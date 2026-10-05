use super::*;
use crate::TenantEngine;
use kasumi_types::{
    Action, ArchivedDocument, CollectionRetentionClass, CollectionWriteMode, Document, Grant,
    IndexDefinition, IndexField, Limits, Policy, ScalarType,
};
use serde_json::json;
use std::sync::Arc;

fn document(id: &str, version: u64, value: &str) -> Arc<Document> {
    Arc::new(Document {
        id: id.into(),
        version,
        body: json!({"value": value}),
    })
}

fn archived(version: u64, value: &str) -> Arc<ArchivedDocument> {
    Arc::new(ArchivedDocument {
        version,
        archive_id: "archive".into(),
        chunk_index: 0,
        document_sha256: "12".repeat(32),
        document_bytes: 128,
        indexed_fields: BTreeMap::from([("/value".into(), json!(value))]),
    })
}

fn state() -> TenantState {
    let engine = TenantEngine::new(
        "tenant".into(),
        "incarnation".into(),
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: [Action::Admin].into_iter().collect(),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )
    .unwrap();
    let mut state = engine.generation().unwrap().state.clone();
    state.revision = 3;
    state.collections.insert("docs".into(), CollectionState {
        definition: CollectionDefinition {
            name: "docs".into(),
            write_mode: CollectionWriteMode::Mutable,
            retention_class: CollectionRetentionClass::Operational,
            schema: json!({"type":"object", "required":["value"], "properties":{"value":{"type":"string"}}}),
            indexes: vec![IndexDefinition {
                name: "value".into(), fields: vec![IndexField { path: "/value".into(), kind: ScalarType::String }],
                unique: true, text: None,
            }],
            strict_read_audit: false,
        },
        data_epoch: 3,
        documents: [
            ("a".to_owned(), document("a", 1, "alpha")),
            ("c".to_owned(), document("c", 3, "charlie")),
        ].into_iter().collect(),
        archived_documents: Default::default(), archived_document_bytes: 0,
    });
    state
}

fn changed(ids: &[&str]) -> BTreeMap<String, BTreeSet<String>> {
    BTreeMap::from([(
        "docs".into(),
        ids.iter().map(|id| (*id).to_owned()).collect(),
    )])
}

#[test]
fn collection_records_merge_hydration_once_without_cloning_bodies() {
    let mut state = state();
    let collection = state.collections.get_mut("docs").unwrap();
    collection
        .archived_documents
        .insert("b".into(), archived(2, "bravo"));
    collection
        .archived_documents
        .insert("c".into(), archived(3, "charlie"));
    let collection = &state.collections["docs"];
    let source = StateCollection::new(&state, "docs", collection);
    let count = Arc::strong_count(&collection.documents["c"]);
    let mut rows = Vec::new();
    source
        .visit_records(|id, record| {
            if id == "c" {
                let Record::Live(document) = record else {
                    panic!("hydration must win")
                };
                assert!(std::ptr::eq(document, collection.documents["c"].as_ref()));
                assert_eq!(Arc::strong_count(&collection.documents["c"]), count);
            }
            rows.push((id.to_owned(), record.version()));
            Ok(())
        })
        .unwrap();
    assert_eq!(rows, [("a".into(), 1), ("b".into(), 2), ("c".into(), 3)]);
    assert_eq!(
        build(&state)
            .unwrap()
            .document_ids_after("docs", None, 10)
            .unwrap(),
        ["a", "b", "c"]
    );
}

#[test]
fn delta_replays_one_sorted_old_final_pair_for_repeated_mutations() {
    let old = state();
    let indexes = build(&old).unwrap();
    let mut new = old.clone();
    new.revision = 4;
    let docs = &mut new.collections.get_mut("docs").unwrap().documents;
    docs.insert("a".into(), document("a", 4, "intermediate"));
    docs.remove("a");
    docs.insert("a".into(), document("a", 4, "final"));
    docs.insert("b".into(), document("b", 4, "temporary"));
    docs.remove("b");
    docs.remove("c");
    let ids = BTreeSet::from(["c".into(), "a".into(), "b".into()]);
    let source = changes_for(&indexes, &old, &new, "docs", &ids).unwrap();
    assert!(std::ptr::eq(source.indexes(), &indexes));
    assert_ne!(source.old_identity(), source.new_identity());
    for _ in 0..3 {
        let mut rows = Vec::new();
        source
            .visit_changes(|delta| {
                rows.push((
                    delta.id.to_owned(),
                    delta.old.map(|r| r.version()),
                    delta.new.map(|r| r.version()),
                ));
                if delta.id == "a" {
                    let Some(Record::Live(document)) = delta.new else {
                        panic!("final body missing")
                    };
                    assert_eq!(document.body["value"], "final");
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(
            rows,
            [
                ("a".into(), Some(1), Some(4)),
                ("b".into(), None, None),
                ("c".into(), Some(3), None)
            ]
        );
    }
    let journal = changed(&["a", "b", "c"]);
    validate_changes(&indexes, &old, &new, &journal).unwrap();
    let updated = update(&indexes, &old, &new, &journal).unwrap();
    assert_eq!(updated.document_ids_after("docs", None, 10).unwrap(), ["a"]);
    assert_eq!(
        indexes.document_ids_after("docs", None, 10).unwrap(),
        ["a", "c"]
    );
}

#[test]
fn zero_version_live_and_archive_inputs_build_and_apply_exact_deltas() {
    let mut old = state();
    let collection = old.collections.get_mut("docs").unwrap();
    collection
        .documents
        .insert("a".into(), document("a", 0, "alpha"));
    collection
        .archived_documents
        .insert("b".into(), archived(0, "bravo"));
    let indexes = build(&old).unwrap();
    assert_eq!(
        indexes.document_ids_after("docs", None, 10).unwrap(),
        ["a", "b", "c"]
    );

    let mut new = old.clone();
    new.revision = 4;
    let collection = new.collections.get_mut("docs").unwrap();
    collection.data_epoch = 4;
    collection
        .documents
        .insert("a".into(), document("a", 4, "updated"));
    collection.archived_documents.remove("b");
    let ids = changed(&["a", "b"]);
    validate_changes(&indexes, &old, &new, &ids).unwrap();
    let updated = update(&indexes, &old, &new, &ids).unwrap();
    assert_eq!(
        updated.document_ids_after("docs", None, 10).unwrap(),
        ["a", "c"]
    );
    assert_eq!(
        indexes.document_ids_after("docs", None, 10).unwrap(),
        ["a", "b", "c"]
    );

    // Accepting the legitimate lower boundary must not weaken source identity
    // or its upper bound for either live documents or archive references.
    for invalid in 0..3 {
        let mut bad = old.clone();
        let collection = bad.collections.get_mut("docs").unwrap();
        match invalid {
            0 => {
                collection
                    .documents
                    .insert("a".into(), document("wrong", 0, "alpha"));
            }
            1 => {
                collection
                    .documents
                    .insert("a".into(), document("a", 4, "alpha"));
            }
            _ => {
                collection
                    .archived_documents
                    .insert("b".into(), archived(4, "bravo"));
            }
        }
        assert_eq!(build(&bad).unwrap_err().code, ErrorCode::Corruption);
    }
}

#[test]
fn unique_swap_uses_final_pairs_and_conflict_is_prevalidated() {
    let old = state();
    let indexes = build(&old).unwrap();
    let mut new = old.clone();
    new.revision = 4;
    let docs = &mut new.collections.get_mut("docs").unwrap().documents;
    docs.insert("a".into(), document("a", 4, "charlie"));
    docs.insert("c".into(), document("c", 4, "alpha"));
    let journal = changed(&["a", "c"]);
    validate_changes(&indexes, &old, &new, &journal).unwrap();
    update(&indexes, &old, &new, &journal).unwrap();
    new.collections
        .get_mut("docs")
        .unwrap()
        .documents
        .insert("c".into(), document("c", 4, "charlie"));
    assert_eq!(
        validate_changes(&indexes, &old, &new, &journal)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        indexes.document_ids_after("docs", None, 10).unwrap(),
        ["a", "c"]
    );
}

#[test]
fn unexplained_live_and_archive_roots_fail_without_rebuild_fallback() {
    let old = state();
    let indexes = build(&old).unwrap();
    for archived_change in [false, true] {
        let mut new = old.clone();
        if archived_change {
            new.collections
                .get_mut("docs")
                .unwrap()
                .archived_documents
                .insert("b".into(), archived(2, "bravo"));
        } else {
            new.collections
                .get_mut("docs")
                .unwrap()
                .documents
                .remove("a");
        }
        for journal in [BTreeMap::new(), changed(&[])] {
            assert_eq!(
                update(&indexes, &old, &new, &journal).unwrap_err().code,
                ErrorCode::Corruption
            );
        }
    }
    let mut foreign = old.clone();
    foreign.incarnation = "replacement".into();
    assert_eq!(
        update(&indexes, &old, &foreign, &BTreeMap::new())
            .unwrap_err()
            .code,
        ErrorCode::Corruption
    );
}

#[test]
fn explicit_schema_rebuild_and_removal_do_not_require_document_journals() {
    let old = state();
    let indexes = build(&old).unwrap();
    let mut new = old.clone();
    let mut replacement = new.collections.remove("docs").unwrap();
    replacement.definition.name = "new".into();
    new.collections.insert("new".into(), replacement);
    let updated = update(&indexes, &old, &new, &BTreeMap::new()).unwrap();
    assert_eq!(
        updated
            .document_ids_after("docs", None, 10)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        updated.document_ids_after("new", None, 10).unwrap(),
        ["a", "c"]
    );
    let mut replacement = old.clone();
    replacement
        .collections
        .get_mut("docs")
        .unwrap()
        .definition
        .indexes
        .clear();
    update(&indexes, &old, &replacement, &BTreeMap::new()).unwrap();
}

#[test]
fn schema_candidates_and_empty_snapshot_metadata_have_exact_borrowed_owners() {
    let state = state();
    let collection = &state.collections["docs"];
    let source = StateCollection::new(&state, "docs", collection);
    let mut candidate = collection.clone();
    let proposed = StateCollection::new(&state, "docs", &candidate);
    assert_ne!(source.identity(), proposed.identity());
    assert_eq!(proposed.identity().tenant(), state.tenant);
    assert_eq!(proposed.identity().incarnation(), state.incarnation);
    kasumi_query::validate_collection(&proposed).unwrap();
    crate::state::schema::prepare_collection(
        &state,
        Some(collection),
        &collection.definition,
        false,
    )
    .unwrap();
    candidate.documents.insert(
        "future".into(),
        document("future", state.revision + 1, "future"),
    );
    let invalid = StateCollection::new(&state, "docs", &candidate);
    assert_eq!(
        kasumi_query::validate_collection(&invalid)
            .unwrap_err()
            .into_query_error()
            .code,
        ErrorCode::Corruption
    );
    let mut header = state.clone();
    header.revision = 0;
    header.collections.clear();
    let empty = CollectionState {
        documents: Default::default(),
        archived_documents: Default::default(),
        data_epoch: 0,
        archived_document_bytes: 0,
        definition: collection.definition.clone(),
    };
    let metadata = StateCollection::new(&header, "docs", &empty);
    kasumi_query::validate_collection(&metadata).unwrap();
    QueryIndexes::build([metadata]).unwrap();
}
