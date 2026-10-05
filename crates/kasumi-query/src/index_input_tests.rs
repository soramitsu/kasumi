use super::*;
use std::cell::Cell;

#[derive(Debug)]
struct SourceError(Arc<()>);
impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original index input failure")
    }
}
impl std::error::Error for SourceError {}
#[derive(Clone)]
enum Encoded {
    Live(String),
    Archived(String),
}
enum Decoded {
    Live(Document),
    Archived(ArchivedDocument),
}
impl Encoded {
    fn decode(&self) -> Decoded {
        match self {
            Self::Live(bytes) => Decoded::Live(serde_json::from_str(bytes).unwrap()),
            Self::Archived(bytes) => Decoded::Archived(serde_json::from_str(bytes).unwrap()),
        }
    }
}
impl Decoded {
    fn record(&self) -> Record<'_> {
        match self {
            Self::Live(row) => Record::Live(row),
            Self::Archived(row) => Record::Archived(row),
        }
    }
}
struct Rows {
    definition: CollectionDefinition,
    other_definition: CollectionDefinition,
    switched: Cell<bool>,
    switch_after_pass: bool,
    rows: Vec<(String, Encoded)>,
    owner: Box<u8>,
    active: Cell<bool>,
}
impl Rows {
    fn new(name: &str, rows: &[(&str, Value)], unique: bool, text: bool) -> Self {
        let definition = CollectionDefinition {
            name: name.to_owned(),
            write_mode: CollectionWriteMode::Mutable,
            retention_class: CollectionRetentionClass::Operational,
            schema: serde_json::json!({"type":"object"}),
            strict_read_audit: false,
            indexes: if unique {
                vec![IndexDefinition {
                    name: "unique".to_owned(),
                    fields: vec![IndexField {
                        path: "/key".to_owned(),
                        kind: ScalarType::Number,
                    }],
                    unique: true,
                    text: None,
                }]
            } else if text {
                vec![IndexDefinition {
                    name: "text".to_owned(),
                    fields: vec![IndexField {
                        path: "/text".to_owned(),
                        kind: ScalarType::String,
                    }],
                    unique: false,
                    text: Some(TextIndex {
                        analyzer: Analyzer::UnicodeV1,
                    }),
                }]
            } else {
                vec![]
            },
        };
        let mut other_definition = definition.clone();
        other_definition.schema = serde_json::json!({"type":"object","required":["different"]});
        let rows = rows
            .iter()
            .map(|(id, body)| {
                (
                    (*id).to_owned(),
                    Encoded::Live(
                        serde_json::to_string(&Document {
                            id: (*id).to_owned(),
                            version: 7,
                            body: body.clone(),
                        })
                        .unwrap(),
                    ),
                )
            })
            .collect();
        Self {
            definition,
            other_definition,
            switched: Cell::new(false),
            switch_after_pass: false,
            rows,
            owner: Box::new(1),
            active: Cell::new(false),
        }
    }
    fn definition(&self) -> &CollectionDefinition {
        if self.switched.get() {
            &self.other_definition
        } else {
            &self.definition
        }
    }
    fn identity(&self) -> SourceIdentity<'_> {
        SourceIdentity::new(
            self.owner.as_ref(),
            "tenant",
            "incarnation",
            &self.definition.name,
        )
    }
    fn get(&self, id: &str) -> Option<Decoded> {
        self.rows
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, row)| row.decode())
    }
}
struct Active<'a>(&'a Cell<bool>);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        assert!(self.0.replace(false));
    }
}
impl CollectionRecords for &Rows {
    type Failure = SourceError;
    fn identity(&self) -> SourceIdentity<'_> {
        Rows::identity(self)
    }
    fn definition(&self) -> &CollectionDefinition {
        Rows::definition(self)
    }
    fn visit_records(
        &self,
        mut lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        for (id, row) in &self.rows {
            assert!(!self.active.replace(true));
            let _active = Active(&self.active);
            let decoded = row.decode();
            lend(id, decoded.record())?;
        }
        if self.switch_after_pass {
            self.switched.set(true);
        }
        Ok(())
    }
}
struct Changes<'a> {
    old: &'a Rows,
    new: &'a Rows,
    ids: Vec<String>,
    indexes: &'a QueryIndexes,
    pass: Cell<usize>,
    fail_pass: usize,
    failure: Arc<()>,
    wrong_owner: bool,
    change_replayed_version: bool,
}
impl<'a> Changes<'a> {
    fn new(old: &'a Rows, new: &'a Rows, indexes: &'a QueryIndexes, ids: &[&str]) -> Self {
        Self {
            old,
            new,
            ids: ids.iter().map(|id| (*id).to_owned()).collect(),
            indexes,
            pass: Cell::new(0),
            fail_pass: usize::MAX,
            failure: Arc::new(()),
            wrong_owner: false,
            change_replayed_version: false,
        }
    }
}
impl DocumentChanges for Changes<'_> {
    type Failure = SourceError;
    fn old_identity(&self) -> SourceIdentity<'_> {
        self.old.identity()
    }
    fn new_identity(&self) -> SourceIdentity<'_> {
        if self.wrong_owner {
            SourceIdentity::new(
                self.new.owner.as_ref(),
                "other-tenant",
                "incarnation",
                &self.new.definition.name,
            )
        } else {
            self.new.identity()
        }
    }
    fn old_definition(&self) -> &CollectionDefinition {
        self.old.definition()
    }
    fn new_definition(&self) -> &CollectionDefinition {
        self.new.definition()
    }
    fn indexes(&self) -> &QueryIndexes {
        self.indexes
    }
    fn visit_changes(
        &self,
        mut lend: impl for<'a> FnMut(DocumentDelta<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        let pass = self.pass.get() + 1;
        self.pass.set(pass);
        for id in &self.ids {
            assert!(!self.old.active.replace(true));
            assert!(!self.new.active.replace(true));
            let _old = Active(&self.old.active);
            let _new = Active(&self.new.active);
            let old = self.old.get(id);
            let mut new = self.new.get(id);
            if self.change_replayed_version
                && pass > 1
                && let Some(Decoded::Live(document)) = new.as_mut()
            {
                document.version += 1;
            }
            lend(DocumentDelta {
                id,
                old: old.as_ref().map(Decoded::record),
                new: new.as_ref().map(Decoded::record),
            })?;
            if pass == self.fail_pass {
                return Err(ReadFailure::Source(SourceError(self.failure.clone())));
            }
        }
        Ok(())
    }
}
fn update(indexes: &QueryIndexes, changes: Changes<'_>) -> ReadResult<QueryIndexes, SourceError> {
    indexes.update::<&Rows, _>([IndexUpdate::Delta(changes)])
}
fn unique_entries(indexes: &QueryIndexes, name: &str) -> Vec<(String, String)> {
    indexes.collections[name].structured.unique["unique"]
        .entries
        .iter()
        .map(|(key, id)| (format!("{key:?}"), id.clone()))
        .collect()
}

#[test]
fn paired_delta_loans_allow_atomic_swaps_and_match_full_rebuild() {
    let old = Rows::new(
        "docs",
        &[
            ("a", serde_json::json!({"key":1})),
            ("b", serde_json::json!({"key":2})),
        ],
        true,
        false,
    );
    // One final pair per logical ID represents any number of intermediate puts/deletes.
    let new = Rows::new(
        "docs",
        &[
            ("a", serde_json::json!({"key":2})),
            ("b", serde_json::json!({"key":1})),
        ],
        true,
        false,
    );
    let indexes = QueryIndexes::build([&old]).unwrap();
    let next = update(&indexes, Changes::new(&old, &new, &indexes, &["a", "b"])).unwrap();
    let rebuilt = QueryIndexes::build([&new]).unwrap();
    assert_eq!(
        unique_entries(&next, "docs"),
        unique_entries(&rebuilt, "docs")
    );
    assert_ne!(
        unique_entries(&next, "docs"),
        unique_entries(&indexes, "docs")
    );
    assert!(!old.active.get() && !new.active.get());
}

#[test]
fn archived_rows_preserve_unique_keys_and_logical_ids_during_transition() {
    let old = Rows::new("docs", &[("a", serde_json::json!({"key":1}))], true, false);
    let mut new = Rows::new("docs", &[], true, false);
    let archived = ArchivedDocument {
        version: 7,
        archive_id: "archive".to_owned(),
        chunk_index: 0,
        document_sha256: "digest".to_owned(),
        document_bytes: 10,
        indexed_fields: BTreeMap::from([("/key".to_owned(), serde_json::json!(1))]),
    };
    new.rows.push((
        "a".to_owned(),
        Encoded::Archived(serde_json::to_string(&archived).unwrap()),
    ));
    let indexes = QueryIndexes::build([&old]).unwrap();
    let next = update(&indexes, Changes::new(&old, &new, &indexes, &["a"])).unwrap();
    assert_eq!(
        unique_entries(&next, "docs"),
        unique_entries(&indexes, "docs")
    );
    assert!(next.collections["docs"].structured.ids.contains("a"));
    check_unique(&&new).unwrap();
    new.rows.push((
        "b".to_owned(),
        Encoded::Live(
            serde_json::to_string(&Document {
                id: "b".to_owned(),
                version: 7,
                body: serde_json::json!({"key":1}),
            })
            .unwrap(),
        ),
    ));
    assert!(
        matches!(check_unique(&&new), Err(ReadFailure::Query(error)) if error.code == ErrorCode::Conflict)
    );
}

#[test]
fn second_unique_pass_preserves_original_source_failure_and_published_indexes() {
    let old = Rows::new("docs", &[("a", serde_json::json!({"key":1}))], true, false);
    let new = Rows::new("docs", &[("a", serde_json::json!({"key":2}))], true, false);
    let indexes = QueryIndexes::build([&old]).unwrap();
    let mut changes = Changes::new(&old, &new, &indexes, &["a"]);
    changes.fail_pass = 2;
    let original = changes.failure.clone();
    let error = indexes.validate_unique_changes([changes]).unwrap_err();
    let ReadFailure::Source(SourceError(error)) = error else {
        panic!("flattened source failure")
    };
    assert!(Arc::ptr_eq(&error, &original));
    update(&indexes, Changes::new(&old, &new, &indexes, &["a"])).unwrap();
    assert_eq!(unique_entries(&indexes, "docs")[0].1, "a");
}

#[test]
fn checked_inputs_reject_unordered_ids_cross_scope_and_changed_replay_versions() {
    let old = Rows::new(
        "docs",
        &[
            ("a", serde_json::json!({"key":1})),
            ("b", serde_json::json!({"key":2})),
        ],
        true,
        false,
    );
    let new = Rows::new(
        "docs",
        &[
            ("a", serde_json::json!({"key":3})),
            ("b", serde_json::json!({"key":4})),
        ],
        true,
        false,
    );
    let indexes = QueryIndexes::build([&old]).unwrap();
    for mode in 0..3 {
        let mut changes = Changes::new(
            &old,
            &new,
            &indexes,
            if mode == 0 { &["b", "a"] } else { &["a", "b"] },
        );
        changes.wrong_owner = mode == 1;
        changes.change_replayed_version = mode == 2;
        assert!(
            matches!(update(&indexes, changes), Err(ReadFailure::Query(error)) if error.code == ErrorCode::Corruption)
        );
    }
    let mut duplicate = Rows::new(
        "docs",
        &[("a", serde_json::json!({})), ("a", serde_json::json!({}))],
        false,
        false,
    );
    assert!(
        matches!(QueryIndexes::build([&duplicate]), Err(ReadFailure::Query(error)) if error.code == ErrorCode::Corruption)
    );
    duplicate.rows.pop();
    duplicate.switch_after_pass = true;
    assert!(
        matches!(QueryIndexes::build([&duplicate]), Err(ReadFailure::Query(error)) if error.code == ErrorCode::Corruption)
    );
}

#[test]
fn later_collection_rejection_never_advances_an_earlier_shared_text_writer() {
    let old_text = Rows::new(
        "a",
        &[("x", serde_json::json!({"text":"before"}))],
        false,
        true,
    );
    let new_text = Rows::new(
        "a",
        &[("x", serde_json::json!({"text":"after"}))],
        false,
        true,
    );
    let old_unique = Rows::new(
        "b",
        &[
            ("x", serde_json::json!({"key":1})),
            ("y", serde_json::json!({"key":2})),
        ],
        true,
        false,
    );
    for invalid_document in [false, true] {
        let new_unique = Rows::new(
            "b",
            &[
                (
                    "x",
                    if invalid_document {
                        serde_json::json!({"key":"invalid"})
                    } else {
                        serde_json::json!({"key":2})
                    },
                ),
                ("y", serde_json::json!({"key":2})),
            ],
            true,
            false,
        );
        let indexes = QueryIndexes::build([&old_text, &old_unique]).unwrap();
        let error = indexes
            .update::<&Rows, _>([
                IndexUpdate::Delta(Changes::new(&old_text, &new_text, &indexes, &["x"])),
                IndexUpdate::Delta(Changes::new(&old_unique, &new_unique, &indexes, &["x"])),
            ])
            .unwrap_err();
        assert!(matches!(error, ReadFailure::Query(_)));
        // An advanced/poisoned writer would reject this as a stale generation.
        let next = update(
            &indexes,
            Changes::new(&old_text, &new_text, &indexes, &["x"]),
        )
        .unwrap();
        let request = TextSearch::new("text", "after");
        assert!(
            indexes.collections["a"]
                .text
                .as_ref()
                .unwrap()
                .search(&request, 10, &QueryCancellation::default())
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            next.collections["a"]
                .text
                .as_ref()
                .unwrap()
                .search(&request, 10, &QueryCancellation::default())
                .unwrap()
                .len(),
            1
        );
    }
}
