use super::*;
use crate::source_test_utils::{FixtureRecords, ResidentSource, pending, query_memory};
use crate::{DocumentSource, Header, QueryIndexes, SourceIdentity, TextResidency};
use kasumi_types::{
    CollectionState, Document, IndexDefinition, IndexField, Limits, QueryRequest, ScalarType,
    TextIndex,
};
use serde_json::json;
use std::convert::Infallible;

fn definition(analyzer: Analyzer, paths: &[&str]) -> CollectionDefinition {
    CollectionDefinition {
        name: "docs".into(),
        write_mode: kasumi_types::CollectionWriteMode::Mutable,
        retention_class: kasumi_types::CollectionRetentionClass::Operational,
        schema: json!({"type":"object"}),
        indexes: vec![IndexDefinition {
            name: "text".into(),
            fields: paths
                .iter()
                .map(|path| IndexField {
                    path: (*path).into(),
                    kind: ScalarType::String,
                })
                .collect(),
            unique: false,
            text: Some(TextIndex { analyzer }),
        }],
        strict_read_audit: false,
    }
}

fn definition_with(analyzer: Analyzer) -> CollectionDefinition {
    definition(analyzer, &["/title"])
}

fn collection(definition: &CollectionDefinition, bodies: &[Value]) -> CollectionState {
    CollectionState {
        definition: Arc::new(definition.clone()),
        data_epoch: 0,
        documents: bodies
            .iter()
            .enumerate()
            .map(|(i, body)| {
                let id = format!("{i:03}");
                (
                    id.clone(),
                    pending(Document {
                        id,
                        version: 1,
                        body: body.clone(),
                    }),
                )
            })
            .collect(),
        archived_documents: Default::default(),
        archived_document_bytes: 0,
    }
}

/// Opened shards with descriptor statistics, as a storage owner keeps them.
struct Shards {
    layout: TextShardLayout,
    shards: Vec<TextShard>,
    documents: u64,
    tokens: Vec<u64>,
    current: BTreeMap<String, u64>,
}
impl Shards {
    fn new(layout: &TextShardLayout) -> Self {
        Self {
            layout: layout.clone(),
            shards: Vec::new(),
            documents: 0,
            tokens: vec![0; layout.field_count()],
            current: BTreeMap::new(),
        }
    }
    fn push(&mut self, built: BuiltTextShard) {
        self.documents += u64::from(built.documents);
        for (total, tokens) in self.tokens.iter_mut().zip(&built.tokens) {
            *total += tokens;
        }
        let shard = TextShard::open(&self.layout, built.files, built.documents).unwrap();
        self.shards.push(shard);
    }
    fn build(&mut self, rows: &[(&str, u64, Value)]) {
        let mut writer = TextShardWriter::new(&self.layout).unwrap();
        for (id, version, body) in rows {
            writer.add(id, *version, body).unwrap();
            self.current.insert((*id).into(), *version);
        }
        self.push(writer.finish().unwrap().unwrap());
    }
}
impl TextShardSet for Shards {
    fn layout(&self) -> &TextShardLayout {
        &self.layout
    }
    fn shard_count(&self) -> usize {
        self.shards.len()
    }
    fn with_shard(
        &self,
        shard: usize,
        visit: &mut dyn FnMut(&TextShard) -> Result<()>,
    ) -> Result<()> {
        visit(&self.shards[shard])
    }
    fn indexed_documents(&self) -> u64 {
        self.documents
    }
    fn total_tokens(&self, field: usize) -> u64 {
        self.tokens[field]
    }
    fn current(&self, id: &str, version: u64) -> Result<bool> {
        Ok(self.current.get(id) == Some(&version))
    }
}

fn search(shards: &Shards, request: &TextSearch) -> Result<BTreeMap<String, f32>> {
    search_shards(shards, request, 100, &QueryCancellation::default())
}

fn corpus() -> Vec<Value> {
    let words = [
        "kitten", "puppy", "running", "runner", "shipping", "harbor", "library", "valley",
    ];
    (0..30)
        .map(|i: usize| {
            json!({
                "title": format!("{} {} {}", words[i % 8], words[(i * 3) % 8], words[(i / 4) % 8]),
                "body": format!("the {} near the {} {}", words[(i + 5) % 8], words[(i * 7) % 8], i),
            })
        })
        .collect()
}

#[test]
fn sharded_search_ranks_exactly_as_one_resident_index() {
    for analyzer in [Analyzer::UnicodeV1, Analyzer::EnglishV1] {
        let definition = definition(analyzer, &["/title", "/body"]);
        let bodies = corpus();
        let state = collection(&definition, &bodies);
        let resident = TextSnapshot::build(&FixtureRecords { collection: &state })
            .map_err(crate::ReadFailure::into_query_error)
            .unwrap()
            .unwrap();
        let layout = TextShardLayout::for_definition(&definition).unwrap();
        let mut shards = Shards::new(&layout);
        for chunk in [0..7, 7..19, 19..30] {
            let rows: Vec<_> = chunk
                .map(|i| (format!("{i:03}"), bodies[i].clone()))
                .collect();
            let rows: Vec<_> = rows
                .iter()
                .map(|(id, body)| (id.as_str(), 1, body.clone()))
                .collect();
            shards.build(&rows);
        }
        assert_eq!(shards.indexed_documents(), 30);
        for request in [
            TextSearch::new("text", "kitten"),
            TextSearch::new("text", "running harbor"),
            TextSearch::new("text", "near the").mode(TextMode::Phrase),
            TextSearch::new("text", "ship").mode(TextMode::Prefix),
            TextSearch::new("text", "kiten pupy").mode(TextMode::Fuzzy),
        ] {
            let expected = resident
                .search(&request, 100, &QueryCancellation::default())
                .unwrap();
            assert!(
                !expected.is_empty(),
                "{analyzer:?} {request:?} found nothing"
            );
            // Identical totals, frequencies and norms: bit-identical scores.
            assert_eq!(search(&shards, &request).unwrap(), expected);
        }
        // Budgets apply to the whole directory, not to one shard.
        let error = search_shards(
            &shards,
            &TextSearch::new("text", "the"),
            2,
            &QueryCancellation::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceExhausted);
    }
}

#[test]
fn superseded_rows_never_match_and_merges_drop_them() {
    let definition = definition(Analyzer::UnicodeV1, &["/title"]);
    let layout = TextShardLayout::for_definition(&definition).unwrap();
    let mut shards = Shards::new(&layout);
    shards.build(&[
        ("a", 1, json!({"title":"alpha shared"})),
        ("b", 1, json!({"title":"beta shared"})),
    ]);
    shards.build(&[("a", 2, json!({"title":"gamma shared"}))]);
    let hits = |shards: &Shards, query: &str| -> Vec<String> {
        search(shards, &TextSearch::new("text", query))
            .unwrap()
            .into_keys()
            .collect()
    };
    assert!(hits(&shards, "alpha").is_empty());
    assert_eq!(hits(&shards, "gamma"), ["a"]);
    assert_eq!(hits(&shards, "shared"), ["a", "b"]);
    // A deleted document has no current version at all.
    shards.current.remove("b");
    assert_eq!(hits(&shards, "shared"), ["a"]);

    let current = shards.current.clone();
    let merged = merge_text_shards(
        &layout,
        &shards.shards.iter().collect::<Vec<_>>(),
        |id, version| Ok(current.get(id) == Some(&version)),
    )
    .unwrap()
    .unwrap();
    assert_eq!(merged.documents, 1);
    let mut compacted = Shards::new(&layout);
    compacted.current = current;
    compacted.push(merged);
    let mut rows = Vec::new();
    compacted.shards[0]
        .visit_rows(|id, version| {
            rows.push((id.to_owned(), version));
            Ok(true)
        })
        .unwrap();
    assert_eq!(rows, [("a".to_owned(), 2)]);
    assert_eq!(hits(&compacted, "shared"), ["a"]);
    assert!(hits(&compacted, "alpha").is_empty());
    assert!(
        merge_text_shards(
            &layout,
            &compacted.shards.iter().collect::<Vec<_>>(),
            |_, _| { Ok(false) }
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn opening_rejects_another_layout_row_count_or_file_name() {
    let definition = definition(Analyzer::UnicodeV1, &["/title"]);
    let layout = TextShardLayout::for_definition(&definition).unwrap();
    let mut writer = TextShardWriter::new(&layout).unwrap();
    writer.add("a", 1, &json!({"title":"alpha"})).unwrap();
    let built = writer.finish().unwrap().unwrap();
    assert!(built.bytes() <= MAX_SHARD_BYTES);
    assert!(built.files.iter().any(|(name, _)| name == "meta.json"));
    assert!(TextShard::open(&layout, built.files.clone(), 2).is_err());
    let other = TextShardLayout::for_definition(&definition_with(Analyzer::EnglishV1)).unwrap();
    assert_ne!(other.sha256(), layout.sha256());
    assert!(TextShard::open(&other, built.files.clone(), 1).is_err());
    let mut renamed = built.files.clone();
    renamed[0].0 = "../escape".into();
    assert!(TextShard::open(&layout, renamed, 1).is_err());
    let mut missing = built.files.clone();
    missing.retain(|(name, _)| name != "meta.json");
    assert!(TextShard::open(&layout, missing, 1).is_err());
    assert!(TextShard::open(&layout, built.files, 1).is_ok());
    assert!(
        TextShardWriter::new(&layout)
            .unwrap()
            .finish()
            .unwrap()
            .is_none()
    );
}

/// A resident fixture source that also lends a persisted shard directory.
struct ShardedSource<'a> {
    inner: ResidentSource<'a>,
    shards: Option<&'a Shards>,
}
impl crate::CollectionRecords for ShardedSource<'_> {
    type Failure = Infallible;
    fn identity(&self) -> SourceIdentity<'_> {
        self.inner.identity()
    }
    fn definition(&self) -> &CollectionDefinition {
        self.inner.definition()
    }
    fn visit_records(
        &self,
        lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        self.inner.visit_records(lend)
    }
}
impl DocumentSource for ShardedSource<'_> {
    fn indexes(&self) -> &QueryIndexes {
        self.inner.indexes()
    }
    fn with_text_shards<T>(
        &self,
        search: impl FnOnce(&dyn TextShardSet) -> Result<T>,
    ) -> ReadResult<Option<T>, Self::Failure> {
        Ok(self
            .shards
            .map(|shards| search(shards as &dyn TextShardSet))
            .transpose()?)
    }
    fn with_record<T>(
        &self,
        id: &str,
        expected_version: Option<u64>,
        cancellation: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Record<'a>>) -> Result<T>,
    ) -> ReadResult<T, Self::Failure> {
        self.inner
            .with_record(id, expected_version, cancellation, lend)
    }
    fn header_after<T>(
        &self,
        after: Option<&str>,
        cancellation: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Header<'a>>) -> Result<T>,
    ) -> ReadResult<T, Self::Failure> {
        self.inner.header_after(after, cancellation, lend)
    }
}

#[test]
fn directory_indexes_build_no_resident_text_and_search_borrowed_shards() {
    let definition = definition(Analyzer::UnicodeV1, &["/title"]);
    let bodies = vec![json!({"title":"alpha one"}), json!({"title":"beta one"})];
    let state = collection(&definition, &bodies);
    let resident = QueryIndexes::build(std::iter::once(FixtureRecords { collection: &state }))
        .map_err(crate::ReadFailure::into_query_error)
        .unwrap();
    assert_eq!(resident.text_residency(), TextResidency::Resident);
    let directory = QueryIndexes::build_with_residency(
        std::iter::once(FixtureRecords { collection: &state }),
        TextResidency::Directory,
    )
    .map_err(crate::ReadFailure::into_query_error)
    .unwrap();
    assert_eq!(directory.text_residency(), TextResidency::Directory);
    assert!(directory.collections["docs"].text.is_none());
    assert!(resident.collections["docs"].text.is_some());

    let layout = TextShardLayout::for_definition(&definition).unwrap();
    let mut shards = Shards::new(&layout);
    shards.build(&[("000", 1, bodies[0].clone()), ("001", 1, bodies[1].clone())]);
    let request = QueryRequest::new("docs").search(TextSearch::new("text", "one"));
    let run = |indexes: &QueryIndexes, shards: Option<&Shards>| {
        indexes
            .execute(
                &ShardedSource {
                    inner: ResidentSource {
                        collection: &state,
                        indexes,
                    },
                    shards,
                },
                &request,
                &Limits::default(),
                &mut query_memory(),
            )
            .map_err(crate::ReadFailure::into_query_error)
    };
    let expected = run(&resident, None).unwrap();
    assert_eq!(run(&directory, Some(&shards)).unwrap(), expected);
    assert_eq!(expected.rows.len(), 2);
    // A directory generation never falls back to resident text.
    let error = run(&directory, None).unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);

    // Moving to a directory drops resident text; returning is refused.
    let moved = resident
        .update_with_residency(
            std::iter::once(crate::IndexUpdate::<FixtureRecords<'_>, NoChanges>::Unchanged("docs")),
            TextResidency::Directory,
        )
        .map_err(crate::ReadFailure::into_query_error)
        .unwrap();
    assert!(moved.collections["docs"].text.is_none());
    assert!(
        moved
            .update_with_residency(
                std::iter::once(
                    crate::IndexUpdate::<FixtureRecords<'_>, NoChanges>::Unchanged("docs",)
                ),
                TextResidency::Resident,
            )
            .is_err()
    );
}

/// A change source type for actions that carry no delta.
struct NoChanges;
impl DocumentChanges for NoChanges {
    type Failure = Infallible;
    fn old_identity(&self) -> SourceIdentity<'_> {
        unreachable!()
    }
    fn new_identity(&self) -> SourceIdentity<'_> {
        unreachable!()
    }
    fn old_definition(&self) -> &CollectionDefinition {
        unreachable!()
    }
    fn new_definition(&self) -> &CollectionDefinition {
        unreachable!()
    }
    fn indexes(&self) -> &QueryIndexes {
        unreachable!()
    }
    fn visit_changes(
        &self,
        _lend: impl for<'a> FnMut(crate::DocumentDelta<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        unreachable!()
    }
}

#[test]
fn shard_writer_counts_normalized_utf8_bytes_across_indexed_values() {
    let layout =
        TextShardLayout::for_definition(&definition(Analyzer::UnicodeV1, &["/title", "/alias"]))
            .unwrap();
    let body =
        json!({"title": ["㍿", "Ａ", "e\u{301}", null, 5], "alias": "é", "unindexed": "ignored"});
    let expected = "株式会社Aéé".len() as u64;
    let mut writer = TextShardWriter::new(&layout).unwrap();
    writer.add("first", 1, &body).unwrap();
    assert_eq!(writer.text_bytes(), expected);
    assert_eq!(layout.text_bytes(&body), expected);

    let second = json!({"title": "㍿㍿"});
    writer.add("second", 2, &second).unwrap();
    assert_eq!(
        writer.text_bytes(),
        expected + "株式会社株式会社".len() as u64
    );
    assert_eq!(writer.finish().unwrap().unwrap().documents, 2);
}
