use kasumi_engine::test_utils::SnapshotFixture;
mod common;
use kasumi_engine::{Database, SecurityAudit};
use kasumi_store::BackupDestination;
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

fn context() -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
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
    let node = NodeStore::open(path, kasumi_store::ScratchDisk::fixture()).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let store = TenantStore::open_fixture(
        node,
        "history".into(),
        Arc::new(LocalKeyProvider::new([0xD3; 32])),
    )
    .await
    .unwrap();
    let db = kasumi_engine::test_utils::open_fixture(
        kasumi_store::test_utils::with_custody(
            store,
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        policy(),
        limits,
        audit.clone(),
    )
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
        db.engine().snapshot_bytes().unwrap() as u64,
        db.engine().fixture_snapshot().unwrap().len()
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
        db.engine().snapshot_bytes().unwrap() as u64,
        db.engine().fixture_snapshot().unwrap().len()
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
        db.engine().snapshot_bytes().unwrap() as u64,
        db.engine().fixture_snapshot().unwrap().len()
    );
    assert!(
        !db.backup(context(), destination.as_ref(), uuid::Uuid::new_v4())
            .await
            .unwrap()
            .is_nil()
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

#[tokio::test]
async fn chunked_full_backup_restores_cold_history_and_permanent_identity_without_source_objects() {
    let root = tempfile::tempdir().unwrap();
    let cold_path = root.path().join("cold");
    let backup_path = root.path().join("backup");
    let cold =
        Arc::new(kasumi_store::FilesystemBackupDestination::new(&cold_path, 16 << 20).unwrap());
    let backups =
        Arc::new(kasumi_store::FilesystemBackupDestination::new(&backup_path, 16 << 20).unwrap());
    let (db, audit) = open(&root.path().join("source.redb"), Limits::default()).await;
    db.install_archive_destination("cold".into(), cold).unwrap();
    collection(&db, "docs", CollectionRetentionClass::ArchivableHistory).await;
    let chunks: Vec<_> = (0..2)
        .map(|chunk| StagedChunk {
            read_set: vec![],
            operations: (chunk * 6..chunk * 6 + 6)
                .map(|n| Mutation::Put {
                    collection: "docs".into(),
                    id: format!("r{n:04}"),
                    expected: Precondition::Absent,
                    body: json!({"n": n, "payload": "x".repeat(900_000)}),
                })
                .collect(),
        })
        .collect();
    let manifest = StagedManifest::from_chunks(&chunks).unwrap();
    let reference = StagedTransactionRef {
        scope: kasumi_types::StagedTransactionScope {
            tenant: context().tenant,
            principal: context().principal,
            incarnation: db.engine().generation().unwrap().state.incarnation.clone(),
        },
        transaction_id: "permanent-history-command".into(),
        manifest_digest: staged_digest(&manifest).unwrap().0,
    };
    db.begin_staged_transaction(
        context(),
        BeginStagedTransaction {
            scope: kasumi_types::StagedTransactionScope {
                tenant: context().tenant,
                principal: context().principal,
                incarnation: db.engine().generation().unwrap().state.incarnation.clone(),
            },
            transaction_id: reference.transaction_id.clone(),
            manifest,
            ttl_ms: 60_000,
        },
    )
    .await
    .unwrap();
    for (index, chunk) in chunks.into_iter().enumerate() {
        db.append_staged_chunk(
            context(),
            AppendStagedChunk {
                transaction: reference.clone(),
                index,
                chunk,
            },
        )
        .await
        .unwrap();
    }
    let original = db
        .finalize_staged_transaction(context(), reference.clone())
        .await
        .unwrap();
    db.archive_history(
        context(),
        ArchiveHistory {
            archive_id: "large-period".into(),
            collection: "docs".into(),
            cutoff_revision: original.revision,
            destination: "cold".into(),
        },
    )
    .await
    .unwrap();
    let state = db.engine().generation().unwrap();
    let archive = state.state.history_archives["large-period"].clone();
    assert!(
        archive.manifest.chunks.len() >= 2,
        "exercise real multiple-chunk archival"
    );
    assert!(state.state.collections["docs"].documents.is_empty());
    drop(state);
    let checkpoint = db
        .backup_checkpoint(context(), backups.as_ref(), uuid::Uuid::new_v4())
        .await
        .unwrap();
    let backup_id = checkpoint.backup_id();
    let encrypted = backups
        .session_get(
            backup_id,
            kasumi_store::BackupSessionSlot::Object(backup_id),
            8 << 20,
        )
        .await
        .unwrap()
        .unwrap();
    let full = kasumi_store::EncryptedBackup::from_bytes(&encrypted, 4 << 20)
        .unwrap()
        .decrypt_fixture("history", Arc::new(LocalKeyProvider::new([0xD3; 32])))
        .await
        .unwrap();
    let full: serde_json::Value = serde_json::from_slice(&full.snapshot).unwrap();
    assert_eq!(full["kind"], "full_database");
    assert!(
        full["chunk_count"].as_u64().unwrap() >= 2,
        "exercise real multiple-chunk resident export"
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await;
    drop(db);
    drop(audit);
    std::fs::remove_dir_all(&cold_path).unwrap();
    let node = NodeStore::open(
        root.path().join("restored.redb"),
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let restored_audit = common::security_audit(node.clone()).await;
    let target = TenantStore::open_fixture(
        node,
        "history".into(),
        Arc::new(LocalKeyProvider::new([0xD3; 32])),
    )
    .await
    .unwrap();
    let restore_source = kasumi_engine::RestoreSource {
        timeout_ms: 300_000,
        destination_alias: "recovered".into(),
        destination: backups.clone(),
        keys: Arc::new(LocalKeyProvider::new([0xD3; 32])),
    };
    let restored = kasumi_engine::restore_local(
        &restore_source,
        kasumi_store::test_utils::with_custody(
            target,
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        common::local_restore_request(context(), checkpoint.checkpoint(), uuid::Uuid::new_v4()),
        restored_audit.admission().clone(),
        restored_audit.clone(),
    )
    .await
    .unwrap();
    assert!(restored.engine().generation().unwrap().state.suspended);
    let restored_archive = restored
        .engine()
        .generation()
        .unwrap()
        .state
        .history_archives["large-period"]
        .clone();
    assert_eq!(restored_archive.storage_destination, "recovered");
    assert_eq!(
        restored_archive.manifest, archive.manifest,
        "source provenance is immutable"
    );
    restored.complete_restore(context()).await.unwrap();
    restored
        .administer(context(), Operation::Suspend(false))
        .await
        .unwrap();
    assert_eq!(
        restored
            .get(&context(), "docs", "r0011")
            .await
            .unwrap()
            .body["payload"]
            .as_str()
            .unwrap()
            .len(),
        900_000
    );
    assert_eq!(
        restored
            .finalize_staged_transaction(context(), reference)
            .await
            .unwrap(),
        original
    );
    let lease = restored
        .open_snapshot_lease(&context(), OpenSnapshotLease { ttl_ms: 60_000 })
        .await
        .unwrap();
    let page = restored
        .scan_snapshot_page(
            &context(),
            ScanSnapshotPage {
                lease_id: lease.lease_id.clone(),
                collection: "docs".into(),
                after_id: None,
                limit: 12,
            },
        )
        .await
        .unwrap();
    assert!(page.next_after_id.is_some(), "byte bound splits cold pages");
    assert!(
        page.documents
            .iter()
            .all(|doc| doc.version == original.revision)
    );
    restored
        .close_snapshot_lease(&context(), &lease.lease_id)
        .await
        .unwrap();
    restored.shutdown().await.unwrap();
    restored_audit.shutdown().await;
    drop(restored);
    drop(restored_audit);

    // Subsets, unavailable historical keys and corrupt/missing dependencies
    // cannot install either bootstrap or Raft identity.
    let dependency_path = backup_path
        .join("sessions")
        .join(backup_id.to_string())
        .join("objects")
        .join(format!("{}.kasumi", archive.manifest.chunks[1].object_id));
    let valid_dependency = std::fs::read(&dependency_path).unwrap();
    for (suffix, selected_id) in [
        (
            "subset",
            uuid::Uuid::parse_str(&archive.manifest_object_id).unwrap(),
        ),
        ("wrong-keys", backup_id),
        ("corrupt", backup_id),
        ("missing", backup_id),
    ] {
        if suffix == "corrupt" {
            let mut corrupt = valid_dependency.clone();
            let last = corrupt.len() - 1;
            corrupt[last] ^= 1;
            std::fs::write(&dependency_path, corrupt).unwrap();
        } else if suffix == "missing" {
            std::fs::remove_file(&dependency_path).unwrap();
        }
        let node = NodeStore::open(
            root.path().join(format!("{suffix}.redb")),
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let audit = common::security_audit(node.clone()).await;
        let target = TenantStore::open_fixture(
            node,
            "history".into(),
            Arc::new(LocalKeyProvider::new(
                [if suffix == "wrong-keys" { 0xD4 } else { 0xD3 }; 32],
            )),
        )
        .await
        .unwrap();
        assert!(
            kasumi_engine::restore_local(
                &restore_source,
                kasumi_store::test_utils::with_custody(
                    target.clone(),
                    std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32]))
                )
                .await
                .unwrap(),
                common::local_restore_request(
                    context(),
                    &kasumi_types::FullBackupCheckpoint {
                        backup_id: selected_id,
                        ..checkpoint.checkpoint().clone()
                    },
                    uuid::Uuid::new_v4()
                ),
                audit.admission().clone(),
                audit.clone(),
            )
            .await
            .is_err()
        );
        assert!(
            target
                .get("engine.bootstrap", b"manifest")
                .unwrap()
                .is_none()
        );
        assert!(
            kasumi_store::test_utils::with_custody(
                target.clone(),
                Arc::new(LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap()
            .custody()
            .store()
            .get("raft.meta", b"node_id")
            .unwrap()
            .is_none()
        );
        audit.shutdown().await;
        if suffix == "corrupt" {
            std::fs::write(&dependency_path, &valid_dependency).unwrap();
        }
    }
}

struct PendingDestination {
    entered: tokio::sync::Notify,
}

#[tokio::test]
async fn scoped_feed_advances_through_filtered_commit_tail_and_emits_only_real_deletions() {
    let root = tempfile::tempdir().unwrap();
    let (db, audit) = open(&root.path().join("node.redb"), Limits::default()).await;
    collection(&db, "docs", CollectionRetentionClass::Operational).await;
    collection(&db, "other", CollectionRetentionClass::Operational).await;
    let mut write = batch("cross-collection", 0, 1);
    write.operations.push(Mutation::Put {
        collection: "other".into(),
        id: "x".into(),
        expected: Precondition::Absent,
        body: json!({"n": 99}),
    });
    let receipt = db.mutate(context(), write).await.unwrap();
    let ChangeFeedPage::Events {
        events,
        next,
        caught_up,
        ..
    } = db
        .read_change_feed(&context(), feed(ChangeFeedStart::Beginning, 1))
        .await
        .unwrap()
    else {
        panic!("unexpected gap")
    };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].revision, receipt.revision);
    assert_eq!(events[0].commit_event_count, 2);
    assert_eq!(events[0].ordinal, 0);
    assert_eq!(next.after_sequence, 1);
    assert!(!caught_up);
    let ChangeFeedPage::Events {
        events,
        next,
        caught_up,
        ..
    } = db
        .read_change_feed(&context(), feed(ChangeFeedStart::After { cursor: next }, 1))
        .await
        .unwrap()
    else {
        panic!("unexpected gap")
    };
    assert!(events.is_empty());
    assert_eq!(
        next.after_sequence, 2,
        "a scoped consumer can complete the atomic commit"
    );
    assert!(caught_up);
    let deletion = db
        .mutate(
            context(),
            MutationBatch {
                idempotency_key: "delete".into(),
                read_set: vec![],
                operations: vec![
                    Mutation::Delete {
                        collection: "docs".into(),
                        id: "r0000".into(),
                        expected: Precondition::Any,
                    },
                    Mutation::Delete {
                        collection: "docs".into(),
                        id: "never-existed".into(),
                        expected: Precondition::Any,
                    },
                ],
            },
        )
        .await
        .unwrap();
    let ChangeFeedPage::Events { events, next, .. } = db
        .read_change_feed(
            &context(),
            feed(ChangeFeedStart::After { cursor: next }, 10),
        )
        .await
        .unwrap()
    else {
        panic!("unexpected gap")
    };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, "r0000");
    assert_eq!(events[0].revision, deletion.revision);
    assert_eq!(events[0].commit_event_count, 1);
    assert!(events[0].document.is_none());
    assert_eq!(next.after_sequence, 3);
    db.shutdown().await.unwrap();
    audit.shutdown().await;
}

#[async_trait::async_trait]
impl BackupDestination for PendingDestination {
    async fn session_get(
        &self,
        _session: uuid::Uuid,
        _slot: kasumi_store::BackupSessionSlot,
        _limit: usize,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    async fn session_put(
        &self,
        _session: uuid::Uuid,
        _slot: kasumi_store::BackupSessionSlot,
        _bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        self.entered.notify_one();
        std::future::pending().await
    }

    async fn put(&self, _id: uuid::Uuid, _bytes: Vec<u8>) -> anyhow::Result<()> {
        self.entered.notify_one();
        std::future::pending().await
    }
    async fn get(&self, _id: uuid::Uuid, _max_bytes: usize) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("no object was published")
    }
}

#[tokio::test]
async fn shutdown_cancels_pending_archive_upload_and_keeps_source_rows_on_restart() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("node.redb");
    let (db, audit) = open(&path, Limits::default()).await;
    collection(&db, "docs", CollectionRetentionClass::ArchivableHistory).await;
    let cutoff = db
        .mutate(context(), batch("seed", 0, 1))
        .await
        .unwrap()
        .revision;
    let pending = Arc::new(PendingDestination {
        entered: tokio::sync::Notify::new(),
    });
    db.install_archive_destination("pending".into(), pending.clone())
        .unwrap();
    let task = tokio::spawn({
        let db = db.clone();
        async move {
            db.archive_history(
                context(),
                ArchiveHistory {
                    archive_id: "interrupted".into(),
                    collection: "docs".into(),
                    cutoff_revision: cutoff,
                    destination: "pending".into(),
                },
            )
            .await
        }
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        pending.entered.notified(),
    )
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), db.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(task.await.unwrap().is_err());
    audit.shutdown().await;
    drop(db);
    drop(audit);
    let (db, audit) = open(&path, Limits::default()).await;
    assert_eq!(
        db.get(&context(), "docs", "r0000").await.unwrap().version,
        cutoff
    );
    assert!(
        db.engine()
            .generation()
            .unwrap()
            .state
            .history_archives
            .is_empty()
    );
    assert!(
        db.engine().generation().unwrap().state.collections["docs"]
            .archived_documents
            .is_empty()
    );
    let backup = tokio::spawn({
        let db = db.clone();
        let pending = pending.clone();
        async move {
            db.backup(context(), pending.as_ref(), uuid::Uuid::new_v4())
                .await
        }
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        pending.entered.notified(),
    )
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), db.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(backup.await.unwrap().is_err());
    audit.shutdown().await;
}
