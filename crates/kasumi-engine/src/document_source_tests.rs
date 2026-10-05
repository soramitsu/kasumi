use super::*;
use crate::TenantEngine;
use kasumi_query::ReadFailure;
use kasumi_types::{
    Action, ArchivedDocument, CollectionRetentionClass, CollectionWriteMode, Document, Grant,
    Limits, Policy,
};
use serde_json::json;
use std::{cell::Cell, collections::BTreeMap};

fn live(id: &str, version: u64) -> Arc<Document> {
    Arc::new(Document {
        id: id.into(),
        version,
        body: json!({"value": id}),
    })
}

fn archive(version: u64) -> Arc<ArchivedDocument> {
    Arc::new(ArchivedDocument {
        version,
        archive_id: "archive".into(),
        chunk_index: 0,
        document_sha256: "12".repeat(32),
        document_bytes: 128,
        indexed_fields: BTreeMap::new(),
    })
}

fn fixture() -> Arc<Generation> {
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
    let collection = CollectionState {
        definition: CollectionDefinition {
            name: "docs".into(),
            write_mode: CollectionWriteMode::Mutable,
            retention_class: CollectionRetentionClass::Operational,
            schema: json!({"type": "object"}),
            indexes: vec![],
            strict_read_audit: false,
        },
        data_epoch: 7,
        documents: [("a", 1), ("c", 3), ("z", 7)]
            .into_iter()
            .map(|(id, version)| (id.to_owned(), live(id, version)))
            .collect(),
        archived_documents: [("b", 2), ("y", 6)]
            .into_iter()
            .map(|(id, version)| (id.to_owned(), archive(version)))
            .collect(),
        archived_document_bytes: 256,
    };
    let mut other = collection.clone();
    other.definition.name = "other".into();
    let collections = BTreeMap::from([("docs".into(), collection), ("other".into(), other)]);
    let mut generation = engine.generation().unwrap().read_view(collections, vec![]);
    generation.state.revision = 7;
    generation.indexes = Arc::new(crate::index_source::build(&generation.state).unwrap());
    Arc::new(generation)
}

fn token() -> QueryCancellation {
    QueryCancellation::default()
}

fn code<T>(result: ReadResult<T, Infallible>) -> ErrorCode {
    result.err().unwrap().into_query_error().code
}

#[test]
fn identity_retains_actual_generation_collection_and_exact_indexes() {
    let generation = fixture();
    let weak = Arc::downgrade(&generation);
    let source = generation.document_source("docs").unwrap();
    let same = generation.document_source("docs").unwrap();
    let other = generation.document_source("other").unwrap();
    let identity = source.identity();
    assert_eq!(identity, same.identity());
    assert_ne!(identity, other.identity());
    assert_eq!(identity.tenant(), "tenant");
    assert_eq!(identity.incarnation(), "incarnation");
    assert_eq!(identity.collection(), "docs");
    assert_eq!(source.definition().name, "docs");
    assert!(std::ptr::eq(source.indexes(), generation.indexes.as_ref()));
    let overlay = Arc::new(generation.read_view(generation.state.collections.clone(), vec![]));
    let selected_overlay = overlay.document_source("docs").unwrap();
    assert_ne!(source.identity(), selected_overlay.identity());
    assert!(std::ptr::eq(source.indexes(), selected_overlay.indexes()));
    drop((same, other, overlay, selected_overlay, generation));
    assert!(weak.upgrade().is_some());
    source
        .with_record("a", Some(1), &token(), |record| {
            let Some(Record::Live(document)) = record else {
                panic!("expected retained live document");
            };
            assert_eq!(document.body, json!({"value": "a"}));
            Ok(())
        })
        .unwrap();
    drop(source);
    assert!(weak.upgrade().is_none());
}

#[test]
fn later_overlay_cannot_change_the_captured_records_or_indexes() {
    let generation = fixture();
    let source = generation.document_source("docs").unwrap();
    let mut collections = generation.state.collections.clone();
    collections
        .get_mut("docs")
        .unwrap()
        .documents
        .insert("a".into(), live("a", 8));
    let mut newer = generation.read_view(collections, vec![]);
    newer.state.revision = 8;
    newer.indexes = Arc::new(crate::index_source::build(&newer.state).unwrap());
    let newer = Arc::new(newer);
    let current = newer.document_source("docs").unwrap();
    assert_ne!(source.identity(), current.identity());
    assert!(!std::ptr::eq(source.indexes(), current.indexes()));
    for (selected, expected) in [(&source, 1), (&current, 8)] {
        selected
            .with_record("a", Some(expected), &token(), |record| {
                assert_eq!(record.unwrap().version(), expected);
                Ok(())
            })
            .unwrap();
    }
    assert_eq!(
        code(source.with_record("a", Some(8), &token(), |_| Ok(()))),
        ErrorCode::Corruption
    );
}

#[test]
fn headers_merge_live_archive_and_hydrated_rows_once_in_exclusive_order() {
    let generation = fixture();
    let mut collections = generation.state.collections.clone();
    collections
        .get_mut("docs")
        .unwrap()
        .archived_documents
        .insert("c".into(), archive(3));
    let hydrated = Arc::new(generation.read_view(collections, vec![]));
    let source = hydrated.document_source("docs").unwrap();
    let mut found = Vec::new();
    let mut after = None;
    loop {
        let header = source
            .header_after(after.as_deref(), &token(), |header| {
                Ok(header.map(|header| (header.id.to_owned(), header.version, header.kind)))
            })
            .unwrap();
        let Some(header) = header else { break };
        after = Some(header.0.clone());
        found.push(header);
    }
    assert_eq!(
        found,
        vec![
            ("a".into(), 1, RecordKind::Live),
            ("b".into(), 2, RecordKind::Archived),
            ("c".into(), 3, RecordKind::Live),
            ("y".into(), 6, RecordKind::Archived),
            ("z".into(), 7, RecordKind::Live),
        ]
    );
    source
        .header_after(Some("a\0"), &token(), |header| {
            assert_eq!(header.unwrap().id, "b");
            Ok(())
        })
        .unwrap();
    for (id, is_live, version) in [("b", false, 2), ("c", true, 3)] {
        source
            .with_record(id, Some(version), &token(), |record| {
                assert_eq!(matches!(record.unwrap(), Record::Live(_)), is_live);
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn corrupt_ids_versions_and_disagreeing_hydration_never_reach_the_loan() {
    for fault in 0..6 {
        let generation = fixture();
        let mut collections = generation.state.collections.clone();
        let collection = collections.get_mut("docs").unwrap();
        match fault {
            0 => {
                collection.documents.insert("a".into(), live("wrong", 1));
            }
            1 => {
                collection.documents.insert("a".into(), live("a", u64::MAX));
            }
            2 => {
                collection.documents.insert("a".into(), live("a", 8));
            }
            3 => {
                collection.documents.remove("a");
                collection
                    .archived_documents
                    .insert("a".into(), archive(u64::MAX));
            }
            4 => {
                collection.documents.remove("a");
                collection.archived_documents.insert("a".into(), archive(8));
            }
            5 => {
                collection.archived_documents.insert("a".into(), archive(2));
            }
            _ => unreachable!(),
        }
        let corrupted = Arc::new(generation.read_view(collections, vec![]));
        let source = corrupted.document_source("docs").unwrap();
        let lent = Cell::new(false);
        assert_eq!(
            code(source.with_record("a", None, &token(), |_| {
                lent.set(true);
                Ok(())
            })),
            ErrorCode::Corruption,
            "record fault {fault}"
        );
        assert_eq!(
            code(source.header_after(None, &token(), |_| {
                lent.set(true);
                Ok(())
            })),
            ErrorCode::Corruption,
            "header fault {fault}"
        );
        assert!(!lent.get());
    }
}

#[test]
fn zero_version_live_and_archived_records_reach_the_exact_point_and_header_loan() {
    for revision in [0, 7] {
        for kind in [RecordKind::Live, RecordKind::Archived] {
            let generation = fixture();
            let mut collection = generation.state.collections["docs"].clone();
            collection.data_epoch = revision;
            collection.documents.clear();
            collection.archived_documents.clear();
            collection.archived_document_bytes = 0;
            match kind {
                RecordKind::Live => {
                    collection.documents.insert("a".into(), live("a", 0));
                }
                RecordKind::Archived => {
                    collection.archived_documents.insert("a".into(), archive(0));
                    collection.archived_document_bytes = 128;
                }
            }
            let mut restored =
                generation.read_view(BTreeMap::from([("docs".into(), collection)]), vec![]);
            restored.state.revision = revision;
            restored.indexes = Arc::new(crate::index_source::build(&restored.state).unwrap());
            let restored = Arc::new(restored);
            let source = restored.document_source("docs").unwrap();
            source
                .with_record("a", Some(0), &token(), |record| {
                    let record = record.expect("restored zero-version record exists");
                    assert_eq!(record.version(), 0);
                    assert_eq!(
                        match record {
                            Record::Live(_) => RecordKind::Live,
                            Record::Archived(_) => RecordKind::Archived,
                        },
                        kind
                    );
                    Ok(())
                })
                .unwrap();
            source
                .header_after(None, &token(), |header| {
                    let header = header.expect("restored zero-version header exists");
                    assert_eq!(header.id, "a");
                    assert_eq!(header.version, 0);
                    assert_eq!(header.kind, kind);
                    Ok(())
                })
                .unwrap();
        }
    }
}

#[test]
fn absent_records_require_presence_only_when_a_version_is_expected() {
    let generation = fixture();
    let source = generation.document_source("docs").unwrap();
    source
        .with_record("missing", None, &token(), |record| {
            assert!(record.is_none());
            Ok(())
        })
        .unwrap();
    for (id, expected) in [("missing", 1), ("a", 0), ("a", 2)] {
        assert_eq!(
            code(source.with_record::<()>(id, Some(expected), &token(), |_| {
                panic!("mismatched expected version reached the loan")
            })),
            ErrorCode::Corruption
        );
    }
    assert_eq!(
        generation.document_source("absent").err().unwrap().code,
        ErrorCode::NotFound
    );
    let mut collections = generation.state.collections.clone();
    collections.get_mut("docs").unwrap().definition.name = "wrong".into();
    let corrupted = Arc::new(generation.read_view(collections, vec![]));
    assert_eq!(
        corrupted.document_source("docs").err().unwrap().code,
        ErrorCode::Corruption
    );
}

#[test]
fn cancellation_is_checked_before_lending_and_after_the_callback() {
    let generation = fixture();
    let source = generation.document_source("docs").unwrap();
    let cancelled = token();
    cancelled.cancel();
    assert_eq!(
        code(source.with_record::<()>("a", None, &cancelled, |_| {
            panic!("cancelled point read reached its callback")
        })),
        ErrorCode::ResourceExhausted
    );
    assert_eq!(
        code(source.header_after::<()>(None, &cancelled, |_| {
            panic!("cancelled header read reached its callback")
        })),
        ErrorCode::ResourceExhausted
    );
    let point = token();
    assert_eq!(
        code(source.with_record("a", None, &point, |record| {
            assert!(record.is_some());
            point.cancel();
            Ok(())
        })),
        ErrorCode::ResourceExhausted
    );
    let header = token();
    assert_eq!(
        code(source.header_after(None, &header, |record| {
            assert!(record.is_some());
            header.cancel();
            Ok(())
        })),
        ErrorCode::ResourceExhausted
    );
    // A typed callback error is returned intact, without a storage failure
    // wrapper or a fabricated successful loan.
    let result: ReadResult<(), Infallible> = source.with_record("a", None, &token(), |_| {
        Err(Error::new(ErrorCode::Forbidden, "callback rejected"))
    });
    assert!(
        matches!(result, Err(ReadFailure::Query(error)) if error.code == ErrorCode::Forbidden && error.message == "callback rejected")
    );
}
