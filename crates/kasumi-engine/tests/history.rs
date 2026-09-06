mod common;
use kasumi_engine::{Database, SecurityAudit};
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

fn context() -> RequestContext {
    RequestContext {
        tenant: "history".into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "history-test".into(),
    }
}
fn policy() -> Policy {
    Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: context().scopes,
        }],
        strict_read_audit: false,
    }
}
async fn open(path: &std::path::Path, limits: Limits) -> (Arc<Database>, Arc<SecurityAudit>) {
    let node = NodeStore::open(path).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let store = TenantStore::open(
        node,
        "history".into(),
        Arc::new(LocalKeyProvider::new([0xD3; 32])),
    )
    .await
    .unwrap();
    let db = kasumi_engine::open_local(store, policy(), limits, audit.clone())
        .await
        .unwrap();
    (db, audit)
}
async fn collection(db: &Database, name: &str, retention_class: CollectionRetentionClass) {
    db.administer(
        context(),
        Operation::CreateCollection(CollectionDefinition {
            name: name.into(),
            write_mode: if retention_class == CollectionRetentionClass::ArchivableHistory {
                CollectionWriteMode::AppendOnly
            } else {
                CollectionWriteMode::Mutable
            },
            retention_class,
            schema: json!({"type":"object"}),
            indexes: vec![IndexDefinition {
                name: "number".into(),
                fields: vec![IndexField {
                    path: "/n".into(),
                    kind: ScalarType::Number,
                }],
                unique: true,
                text: None,
            }],
            strict_read_audit: true,
        }),
    )
    .await
    .unwrap();
}
fn batch(key: &str, first: u64, count: u64) -> MutationBatch {
    MutationBatch {
        idempotency_key: key.into(),
        read_set: vec![],
        operations: (first..first + count)
            .map(|n| Mutation::Put {
                collection: "docs".into(),
                id: format!("r{n:04}"),
                expected: Precondition::Absent,
                body: serde_json::from_str(&format!(
                    "{{\"n\":{n},\"amount\":90071992547409931234567890.123456789}}"
                ))
                .unwrap(),
            })
            .collect(),
    }
}
fn feed(start: ChangeFeedStart, limit: usize) -> ReadChangeFeed {
    ReadChangeFeed {
        collections: BTreeSet::from(["docs".into()]),
        start,
        limit,
    }
}

#[tokio::test]
async fn change_feed_is_atomic_ordered_resumable_and_detects_retention_gaps() {
    let root = tempfile::tempdir().unwrap();
    let mut limits = Limits::default();
    limits.history.max_feed_events = 4;
    let (db, audit) = open(&root.path().join("node.redb"), limits).await;
    collection(&db, "docs", CollectionRetentionClass::Operational).await;
    let receipt = db.mutate(context(), batch("first", 0, 3)).await.unwrap();
    assert_eq!(
        db.mutate(context(), batch("first", 0, 3)).await.unwrap(),
        receipt
    );
    let first = db
        .read_change_feed(&context(), feed(ChangeFeedStart::Beginning, 2))
        .await
        .unwrap();
    let ChangeFeedPage::Events {
        events,
        next,
        caught_up,
        ..
    } = first
    else {
        panic!("unexpected retention gap")
    };
    assert_eq!(events.len(), 2);
    assert!(!caught_up);
    assert!(
        events
            .iter()
            .all(|event| event.revision == receipt.revision && event.commit_event_count == 3)
    );
    assert_eq!(events[1].ordinal, 1);
    assert_eq!(
        events[1].document.as_ref().unwrap().body["amount"].to_string(),
        "90071992547409931234567890.123456789"
    );
    let next_page = db
        .read_change_feed(
            &context(),
            feed(
                ChangeFeedStart::After {
                    cursor: next.clone(),
                },
                2,
            ),
        )
        .await
        .unwrap();
    let ChangeFeedPage::Events {
        events,
        next: finished,
        caught_up,
        ..
    } = next_page
    else {
        panic!("unexpected gap")
    };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sequence, 3);
    assert!(caught_up);
    assert_eq!(
        db.engine().snapshot_bytes().unwrap(),
        db.engine().snapshot().unwrap().len()
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await;
    drop(db);
    drop(audit);
    let (db, audit) = open(&root.path().join("node.redb"), Limits::default()).await;
    let resumed = db
        .read_change_feed(
            &context(),
            feed(
                ChangeFeedStart::After {
                    cursor: next.clone(),
                },
                2,
            ),
        )
        .await
        .unwrap();
    let ChangeFeedPage::Events { events, .. } = resumed else {
        panic!("unexpected restart gap")
    };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sequence, 3);
    db.mutate(context(), batch("second", 3, 2)).await.unwrap();
    assert!(matches!(
        db.read_change_feed(&context(), feed(ChangeFeedStart::After { cursor: next }, 2))
            .await
            .unwrap(),
        ChangeFeedPage::RetentionGap {
            first_available_sequence: 4,
            head_sequence: 5,
            ..
        }
    ));
    let retained = db
        .read_change_feed(
            &context(),
            feed(ChangeFeedStart::After { cursor: finished }, 2),
        )
        .await
        .unwrap();
    let ChangeFeedPage::Events { events, next, .. } = retained else {
        panic!("unexpected retained gap")
    };
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![4, 5]
    );
    let before = db.engine().generation().unwrap().state.document_count;
    assert_eq!(
        db.mutate(context(), batch("too-large", 10, 5))
            .await
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        db.engine().generation().unwrap().state.document_count,
        before
    );
    assert_eq!(
        db.engine()
            .generation()
            .unwrap()
            .state
            .change_feed
            .next_sequence,
        6
    );
    let mut foreign = next.clone();
    foreign.incarnation = "another-incarnation".into();
    assert_eq!(
        db.read_change_feed(
            &context(),
            feed(ChangeFeedStart::After { cursor: foreign }, 2)
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::CursorExpired
    );
    db.administer(
        context(),
        Operation::SetPolicy(Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: BTreeSet::from([Action::Admin]),
            }],
            strict_read_audit: false,
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        db.read_change_feed(&context(), feed(ChangeFeedStart::After { cursor: next }, 2))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        db.engine().snapshot_bytes().unwrap(),
        db.engine().snapshot().unwrap().len()
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await;
}

#[tokio::test]
async fn archived_prefixes_keep_logical_reads_unique_indexes_and_dedup_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            root.path().join("history-objects"),
            16 << 20,
        )
        .unwrap(),
    );
    let (db, audit) = open(&root.path().join("node.redb"), Limits::default()).await;
    db.install_archive_destination("cold".into(), destination.clone())
        .unwrap();
    collection(&db, "docs", CollectionRetentionClass::ArchivableHistory).await;
    collection(&db, "commands", CollectionRetentionClass::Operational).await;
    let mut cutoff = 0;
    for n in 0..3 {
        cutoff = db
            .mutate(context(), batch(&format!("seed-{n}"), n * 200, 200))
            .await
            .unwrap()
            .revision;
    }
    let before = db.get(&context(), "docs", "r0599").await.unwrap();
    let request = ArchiveHistory {
        archive_id: "period-one".into(),
        collection: "docs".into(),
        cutoff_revision: cutoff,
        destination: "cold".into(),
    };
    let receipt = db
        .archive_history(context(), request.clone())
        .await
        .unwrap();
    assert_eq!(
        db.archive_history(context(), request).await.unwrap(),
        receipt
    );
    let state = db.engine().generation().unwrap();
    assert_eq!(state.state.collections["docs"].documents.len(), 0);
    assert_eq!(
        state.state.collections["docs"].archived_documents.len(),
        600
    );
    assert_eq!(state.state.collections["docs"].data_epoch, cutoff);
    assert_eq!(state.state.document_count, 600);
    assert_eq!(state.state.logical_bytes, 0);
    let head = state.state.change_feed.next_sequence;
    assert_eq!(head, 601, "archival cannot emit logical deletes");
    let archive = state.state.history_archives["period-one"].clone();
    drop(state);
    assert_eq!(db.get(&context(), "docs", "r0599").await.unwrap(), before);
    assert_eq!(
        db.mutate(context(), batch("duplicate-archived-id", 599, 1))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let mut duplicate_index = batch("duplicate-cold-index", 600, 1);
    if let Mutation::Put { body, .. } = &mut duplicate_index.operations[0] {
        body["n"] = json!(0);
    }
    assert_eq!(
        db.mutate(context(), duplicate_index)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    db.mutate(context(), batch("new-hot-segment", 600, 1))
        .await
        .unwrap();
    let snapshot = db
        .read_snapshot(
            &context(),
            ReadSnapshotRequest {
                documents: vec![
                    DocumentKey {
                        collection: "docs".into(),
                        id: "r0599".into(),
                    },
                    DocumentKey {
                        collection: "docs".into(),
                        id: "absent".into(),
                    },
                ],
                queries: vec![],
            },
        )
        .await
        .unwrap();
    assert_eq!(snapshot.documents[0].document.as_ref().unwrap(), &before);
    assert!(snapshot.documents[1].document.is_none());
    db.mutate(
        context(),
        MutationBatch {
            idempotency_key: "guard-archived-receipt".into(),
            read_set: snapshot.read_assertions(),
            operations: vec![Mutation::Put {
                collection: "commands".into(),
                id: "command".into(),
                expected: Precondition::Absent,
                body: json!({"n":1}),
            }],
        },
    )
    .await
    .unwrap();
    assert_eq!(
        db.mutate(
            context(),
            MutationBatch {
                idempotency_key: "false-cold-absence".into(),
                read_set: vec![ReadAssertion::Document {
                    collection: "docs".into(),
                    id: "r0599".into(),
                    expected: ReadPrecondition::Absent
                }],
                operations: vec![Mutation::Put {
                    collection: "commands".into(),
                    id: "must-not-commit".into(),
                    expected: Precondition::Absent,
                    body: json!({"n":2})
                }],
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::Conflict
    );
    let query: QueryRequest = serde_json::from_value(json!({
        "collection":"docs", "limit":10,
        "filter":{"op":"compare","field":"/n","comparison":"gte","value":598},
        "sort":[{"field":"/n","direction":"asc"}]
    }))
    .unwrap();
    let rows = db.query(&context(), query.clone()).await.unwrap();
    assert_eq!(
        rows.rows
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        vec!["r0598", "r0599", "r0600"]
    );
    let snapshot = db
        .read_snapshot(
            &context(),
            ReadSnapshotRequest {
                documents: vec![],
                queries: vec![query.clone()],
            },
        )
        .await
        .unwrap();
    assert_eq!(snapshot.queries[0].rows.len(), 3);
    let lease = db
        .open_snapshot_lease(&context(), OpenSnapshotLease { ttl_ms: 60_000 })
        .await
        .unwrap();
    let mut after_id = None;
    let mut read = 0;
    loop {
        let page = db
            .scan_snapshot_page(
                &context(),
                ScanSnapshotPage {
                    lease_id: lease.lease_id.clone(),
                    collection: "docs".into(),
                    after_id,
                    limit: 97,
                },
            )
            .await
            .unwrap();
        read += page.documents.len();
        match page.next_after_id {
            Some(next) => after_id = Some(next),
            None => break,
        }
    }
    assert_eq!(read, 601);
    db.close_snapshot_lease(&context(), &lease.lease_id)
        .await
        .unwrap();
    assert_eq!(
        db.engine().snapshot_bytes().unwrap(),
        db.engine().snapshot().unwrap().len()
    );
    assert!(
        db.backup(context(), destination.as_ref()).await.is_err(),
        "history subset references cannot silently become a self-contained backup"
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await;
    drop(db);
    drop(audit);
    let (db, audit) = open(&root.path().join("node.redb"), Limits::default()).await;
    assert_eq!(
        db.get(&context(), "docs", "r0599").await.unwrap_err().code,
        ErrorCode::Unavailable
    );
    db.install_archive_destination("cold".into(), destination.clone())
        .unwrap();
    assert_eq!(db.get(&context(), "docs", "r0599").await.unwrap(), before);
    assert_eq!(
        db.query(&context(), query.clone())
            .await
            .unwrap()
            .rows
            .len(),
        3
    );
    let mut duplicate_index = batch("duplicate-cold-index-after-restart", 601, 1);
    if let Mutation::Put { body, .. } = &mut duplicate_index.operations[0] {
        body["n"] = json!(599);
    }
    assert_eq!(
        db.mutate(context(), duplicate_index)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        db.archive_history(
            context(),
            ArchiveHistory {
                archive_id: "not-operational".into(),
                collection: "commands".into(),
                cutoff_revision: db.engine().generation().unwrap().state.revision,
                destination: "cold".into()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::Forbidden
    );
    let path = root
        .path()
        .join("history-objects")
        .join(format!("{}.kasumi", archive.manifest.chunks[0].object_id));
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(
        db.get(&context(), "docs", "r0000").await.unwrap_err().code,
        ErrorCode::Corruption
    );
    assert_eq!(
        db.query(&context(), query).await.unwrap_err().code,
        ErrorCode::Corruption
    );
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        db.get(&context(), "docs", "r0000").await.unwrap_err().code,
        ErrorCode::Unavailable
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await;
}
