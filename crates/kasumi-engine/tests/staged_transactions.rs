use kasumi_engine::test_utils::SnapshotFixture;
mod common;

use kasumi_engine::TenantEngine;
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

fn context() -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: "tenant".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        request_id: "staging-test".into(),
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
fn definition(name: &str, mode: CollectionWriteMode) -> CollectionDefinition {
    CollectionDefinition {
        retention_class: kasumi_types::CollectionRetentionClass::Operational,
        name: name.into(),
        write_mode: mode,
        schema: json!({"type":"object"}),
        indexes: vec![IndexDefinition {
            name: "unique_n".into(),
            fields: vec![IndexField {
                path: "/n".into(),
                kind: ScalarType::Number,
            }],
            unique: true,
            text: None,
        }],
        strict_read_audit: false,
    }
}
fn put(collection: &str, id: &str, value: u64) -> Mutation {
    Mutation::Put {
        collection: collection.into(),
        id: id.into(),
        expected: Precondition::Absent,
        body: json!({"n":value,"amount":"90071992547409931234567890.123456789"}),
    }
}
fn chunks() -> Vec<StagedChunk> {
    (0..4)
        .map(|chunk| StagedChunk {
            read_set: (chunk * 150..(chunk + 1) * 150)
                .map(|n| ReadAssertion::Document {
                    collection: if n % 2 == 0 { "docs" } else { "ledger" }.into(),
                    id: format!("row{n:04}"),
                    expected: ReadPrecondition::Absent,
                })
                .collect(),
            operations: (chunk * 150..(chunk + 1) * 150)
                .map(|n| {
                    put(
                        if n % 2 == 0 { "docs" } else { "ledger" },
                        &format!("row{n:04}"),
                        n,
                    )
                })
                .collect(),
        })
        .collect()
}
fn begin(
    incarnation: &str,
    id: &str,
    chunks: &[StagedChunk],
    ttl_ms: u64,
) -> (BeginStagedTransaction, StagedTransactionRef) {
    let manifest = StagedManifest::from_chunks(chunks).unwrap();
    let reference = StagedTransactionRef {
        scope: kasumi_types::StagedTransactionScope {
            tenant: context().tenant,
            principal: context().principal,
            incarnation: incarnation.into(),
        },
        transaction_id: id.into(),
        manifest_digest: staged_digest(&manifest).unwrap().0,
    };
    (
        BeginStagedTransaction {
            scope: reference.scope.clone(),
            transaction_id: id.into(),
            manifest,
            ttl_ms,
        },
        reference,
    )
}
fn apply(db: &TenantEngine, timestamp_ms: u64, operation: Operation) -> Result<WriteReceipt> {
    let revision = db.generation().unwrap().state.revision + 1;
    let result = db
        .apply_command(
            revision,
            Command {
                context: context(),
                timestamp_ms,
                operation,
            },
        )
        .unwrap();
    assert_eq!(
        db.snapshot_bytes().unwrap() as u64,
        db.fixture_snapshot().unwrap().len(),
        "canonical stage accounting after revision {revision}"
    );
    result
}
fn engine(limits: Limits) -> TenantEngine {
    let db = TenantEngine::new("tenant".into(), "incarnation".into(), policy(), limits).unwrap();
    apply(
        &db,
        1,
        Operation::CreateCollection(definition("docs", CollectionWriteMode::Mutable)),
    )
    .unwrap();
    apply(
        &db,
        1,
        Operation::CreateCollection(definition("ledger", CollectionWriteMode::AppendOnly)),
    )
    .unwrap();
    db
}

#[test]
fn large_transaction_stays_invisible_then_publishes_one_generation_and_permanent_receipt() {
    let db = engine(Limits::default());
    let chunks = chunks();
    let (request, reference) = begin(
        &db.generation().unwrap().state.incarnation,
        "large",
        &chunks,
        1000,
    );
    apply(&db, 2, Operation::BeginStaged(request.clone())).unwrap();
    for index in [3, 1, 0, 2] {
        let upload = AppendStagedChunk {
            transaction: reference.clone(),
            index,
            chunk: chunks[index].clone(),
        };
        apply(&db, 3, Operation::AppendStaged(upload.clone())).unwrap();
        apply(&db, 3, Operation::AppendStaged(upload)).unwrap();
        let generation = db.generation().unwrap();
        assert_eq!(generation.state.document_count, 0);
        assert_eq!(generation.state.collections["docs"].data_epoch, 0);
        assert_eq!(generation.state.collections["ledger"].data_epoch, 0);
    }
    let prior = db.generation().unwrap();
    let receipt = apply(&db, 4, Operation::FinalizeStaged(reference.clone())).unwrap();
    assert!(receipt.versions.is_empty());
    assert_eq!(prior.state.document_count, 0);
    let committed = db.generation().unwrap();
    assert_eq!(committed.state.document_count, 600);
    assert_eq!(
        committed.state.collections["docs"].data_epoch,
        receipt.revision
    );
    assert_eq!(
        committed.state.collections["ledger"].data_epoch,
        receipt.revision
    );
    assert!(
        committed
            .state
            .collections
            .values()
            .flat_map(|collection| collection.documents.values())
            .all(|doc| doc.version == receipt.revision)
    );
    assert!(
        committed
            .state
            .staged_transactions
            .values()
            .all(|stage| stage.chunks.is_empty())
    );
    let recovered = TenantEngine::new(
        "tenant".into(),
        "incarnation".into(),
        policy(),
        Limits::default(),
    )
    .unwrap();
    recovered
        .fixture_restore(&db.fixture_snapshot().unwrap())
        .unwrap();
    assert_eq!(
        apply(
            &recovered,
            172_800_004,
            Operation::FinalizeStaged(reference.clone())
        )
        .unwrap(),
        receipt
    );
    assert_eq!(
        apply(&recovered, 172_800_005, Operation::BeginStaged(request)).unwrap(),
        receipt
    );
    assert_eq!(recovered.generation().unwrap().state.document_count, 600);
    assert_eq!(
        recovered.generation().unwrap().state.collections["ledger"].data_epoch,
        receipt.revision
    );
}

#[test]
fn complete_large_read_set_and_append_only_rules_reject_all_effects_atomically() {
    let db = engine(Limits::default());
    let chunks = chunks();
    let (request, reference) = begin(
        &db.generation().unwrap().state.incarnation,
        "stale",
        &chunks,
        1000,
    );
    apply(&db, 2, Operation::BeginStaged(request)).unwrap();
    for (index, chunk) in chunks.into_iter().enumerate() {
        apply(
            &db,
            3,
            Operation::AppendStaged(AppendStagedChunk {
                transaction: reference.clone(),
                index,
                chunk,
            }),
        )
        .unwrap();
    }
    apply(
        &db,
        4,
        Operation::Mutate(MutationBatch {
            idempotency_key: "competitor".into(),
            read_set: vec![],
            operations: vec![put("docs", "row0598", 598)],
        }),
    )
    .unwrap();
    assert_eq!(
        apply(&db, 5, Operation::FinalizeStaged(reference.clone()))
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(db.generation().unwrap().state.document_count, 1);
    assert_eq!(
        apply(&db, 172_800_000, Operation::FinalizeStaged(reference))
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );

    apply(
        &db,
        6,
        Operation::Mutate(MutationBatch {
            idempotency_key: "immutable".into(),
            read_set: vec![],
            operations: vec![put("ledger", "retained", 900)],
        }),
    )
    .unwrap();
    let invalid = vec![StagedChunk {
        read_set: vec![],
        operations: vec![
            put("docs", "new", 901),
            Mutation::Delete {
                collection: "ledger".into(),
                id: "retained".into(),
                expected: Precondition::Any,
            },
        ],
    }];
    let (request, reference) = begin(
        &db.generation().unwrap().state.incarnation,
        "immutable-stage",
        &invalid,
        1000,
    );
    apply(&db, 7, Operation::BeginStaged(request)).unwrap();
    apply(
        &db,
        8,
        Operation::AppendStaged(AppendStagedChunk {
            transaction: reference.clone(),
            index: 0,
            chunk: invalid[0].clone(),
        }),
    )
    .unwrap();
    assert_eq!(
        apply(&db, 9, Operation::FinalizeStaged(reference))
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert!(
        !db.generation().unwrap().state.collections["docs"]
            .documents
            .contains_key("new")
    );
    assert!(
        db.generation().unwrap().state.collections["ledger"]
            .documents
            .contains_key("retained")
    );
}

#[test]
fn staged_identity_capacity_is_reserved_before_payload_and_expiry_never_reuses_identity() {
    let mut limits = Limits::default();
    limits.atomic.max_active_transactions = 1;
    let db = engine(limits);
    let chunks = chunks();
    let (a, ar) = begin(
        &db.generation().unwrap().state.incarnation,
        "a",
        &chunks,
        10,
    );
    apply(&db, 2, Operation::BeginStaged(a)).unwrap();
    let mut mismatched = chunks[0].clone();
    mismatched.operations[0] = put("docs", "wrong", 999);
    assert_eq!(
        apply(
            &db,
            3,
            Operation::AppendStaged(AppendStagedChunk {
                transaction: ar.clone(),
                index: 0,
                chunk: mismatched
            })
        )
        .unwrap_err()
        .code,
        ErrorCode::Conflict
    );
    apply(
        &db,
        3,
        Operation::AppendStaged(AppendStagedChunk {
            transaction: ar.clone(),
            index: 0,
            chunk: chunks[0].clone(),
        }),
    )
    .unwrap();
    assert_eq!(
        apply(&db, 3, Operation::FinalizeStaged(ar.clone()))
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(
        db.generation()
            .unwrap()
            .state
            .staged_transactions
            .values()
            .any(StagedTransaction::is_active)
    );
    let (b, br) = begin(
        &db.generation().unwrap().state.incarnation,
        "b",
        &chunks,
        10,
    );
    assert_eq!(
        apply(&db, 4, Operation::BeginStaged(b.clone()))
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    apply(&db, 12, Operation::BeginStaged(b.clone())).unwrap();
    let state = &db.generation().unwrap().state;
    let mut limits = state.limits.clone();
    limits.atomic.max_permanent_staged_bytes =
        state.permanent_staged_bytes + state.reserved_staged_terminal_bytes;
    apply(&db, 12, Operation::SetLimits(limits)).unwrap();
    assert_eq!(
        apply(&db, 13, Operation::FinalizeStaged(ar))
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let (c, cr) = begin(
        &db.generation().unwrap().state.incarnation,
        "c",
        &chunks,
        10,
    );
    assert_eq!(
        apply(&db, 13, Operation::BeginStaged(c)).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        apply(
            &db,
            13,
            Operation::AppendStaged(AppendStagedChunk {
                transaction: cr,
                index: 0,
                chunk: chunks[0].clone()
            })
        )
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
    assert_eq!(db.generation().unwrap().state.staged_transactions.len(), 2);
    assert!(
        db.generation()
            .unwrap()
            .state
            .staged_transactions
            .values()
            .all(|stage| stage.chunks.is_empty())
    );
    let generation = db.generation().unwrap();
    let stop = StopStagedTransaction {
        original: b,
        admission: vec![
            ReadAssertion::Snapshot {
                incarnation: generation.state.incarnation.clone(),
                policy_epoch: generation.state.policy_epoch,
                schema_epoch: generation.state.schema_epoch,
            },
            ReadAssertion::Before { not_after_ms: 1000 },
        ],
    };
    drop(generation);
    apply(&db, 14, Operation::StopStaged(stop.clone())).unwrap();
    let key = staged_digest(&(context().principal, br.transaction_id))
        .unwrap()
        .0;
    let aborted = db.generation().unwrap().state.staged_transactions[&key]
        .outcome
        .clone();
    apply(&db, 15, Operation::StopStaged(stop)).unwrap();
    assert_eq!(
        db.generation().unwrap().state.staged_transactions[&key].outcome,
        aborted
    );
    assert!(
        db.generation()
            .unwrap()
            .state
            .active_staged_transactions
            .is_empty()
    );
    assert_eq!(db.generation().unwrap().state.document_count, 0);
}

#[test]
fn changed_limits_preserve_historic_outcomes_and_keep_active_snapshots_recoverable() {
    let db = engine(Limits::default());
    let chunks = chunks();
    let (request, reference) = begin(
        &db.generation().unwrap().state.incarnation,
        "limits",
        &chunks,
        1000,
    );
    apply(&db, 2, Operation::BeginStaged(request.clone())).unwrap();
    apply(
        &db,
        3,
        Operation::AppendStaged(AppendStagedChunk {
            transaction: reference.clone(),
            index: 0,
            chunk: chunks[0].clone(),
        }),
    )
    .unwrap();
    let mut limits = db.generation().unwrap().state.limits.clone();
    limits.max_batch_operations = 100;
    assert_eq!(
        apply(&db, 4, Operation::SetLimits(limits))
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    let snapshot = db.fixture_snapshot().unwrap();
    let recovered = engine(Limits::default());
    recovered.fixture_restore(&snapshot).unwrap();
    assert_eq!(recovered.generation().unwrap().state.document_count, 0);
    let mut corrupt = kasumi_engine::test_utils::decode_snapshot_candidate(&snapshot).unwrap();
    let key = corrupt.active_staged_transactions.first().unwrap().clone();
    corrupt
        .staged_transactions
        .get_mut(&key)
        .unwrap()
        .uploaded_payload_bytes += 1;
    assert!(
        recovered
            .fixture_restore(
                &kasumi_engine::test_utils::encode_snapshot_candidate(&corrupt, 64 << 20).unwrap()
            )
            .is_err()
    );
    assert_eq!(recovered.fixture_snapshot().unwrap(), snapshot);
    for (index, chunk) in chunks.into_iter().enumerate().skip(1) {
        apply(
            &recovered,
            5,
            Operation::AppendStaged(AppendStagedChunk {
                transaction: reference.clone(),
                index,
                chunk,
            }),
        )
        .unwrap();
    }
    let receipt = apply(&recovered, 6, Operation::FinalizeStaged(reference.clone())).unwrap();
    let mut limits = recovered.generation().unwrap().state.limits.clone();
    limits.atomic.max_operations = 100;
    apply(&recovered, 7, Operation::SetLimits(limits)).unwrap();
    let final_snapshot = recovered.fixture_snapshot().unwrap();
    let restarted = engine(Limits::default());
    restarted.fixture_restore(&final_snapshot).unwrap();
    assert_eq!(
        apply(&restarted, 8, Operation::FinalizeStaged(reference)).unwrap(),
        receipt
    );
    assert_eq!(
        apply(&restarted, 9, Operation::BeginStaged(request)).unwrap(),
        receipt
    );
}

async fn open(
    path: &std::path::Path,
) -> (
    Arc<kasumi_engine::Database>,
    Arc<kasumi_engine::SecurityAudit>,
) {
    let node = NodeStore::open(path, kasumi_store::ScratchDisk::fixture()).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let store = TenantStore::open_fixture(
        node,
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([0xB3; 32])),
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
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    (db, audit)
}

#[test]
fn staged_crash_worker() {
    let Ok(directory) = std::env::var("KASUMI_STAGED_CRASH_DIRECTORY") else {
        return;
    };
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let directory = std::path::Path::new(&directory);
            let (db, _audit) = open(&directory.join("node.redb")).await;
            for name in ["docs", "ledger"] {
                db.administer(
                    context(),
                    Operation::CreateCollection(definition(name, CollectionWriteMode::Mutable)),
                )
                .await
                .unwrap();
            }
            let chunks = chunks();
            let (request, reference) = begin(
                &db.engine().generation().unwrap().state.incarnation,
                "crashed",
                &chunks,
                60_000,
            );
            db.begin_staged_transaction(context(), request)
                .await
                .unwrap();
            for (index, chunk) in chunks.into_iter().take(2).enumerate() {
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
            std::fs::write(directory.join("uploaded"), b"two acknowledged chunks").unwrap();
            std::future::pending::<()>().await;
        });
}

#[tokio::test]
async fn killed_upload_recovers_encrypted_invisible_chunks_and_finishes_exactly_once() {
    let directory = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "staged_crash_worker", "--nocapture"])
        .env("KASUMI_STAGED_CRASH_DIRECTORY", directory.path())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !directory.path().join("uploaded").exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "upload child exited before durable marker"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "upload child did not reach marker"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    child.kill().unwrap();
    child.wait().unwrap();
    let raw = std::fs::read(directory.path().join("node.redb")).unwrap();
    let amount = b"90071992547409931234567890.123456789";
    assert!(
        !raw.windows(amount.len()).any(|bytes| bytes == amount),
        "invisible staging payload must still be encrypted on disk"
    );
    drop(raw);
    let (db, audit) = open(&directory.path().join("node.redb")).await;
    let chunks = chunks();
    let (_, reference) = begin(
        &db.engine().generation().unwrap().state.incarnation,
        "crashed",
        &chunks,
        60_000,
    );
    let status = db
        .staged_transaction_status(&context(), &reference)
        .await
        .unwrap();
    assert_eq!(status.received_chunks, vec![0, 1]);
    assert_eq!(db.engine().generation().unwrap().state.document_count, 0);
    for (index, chunk) in chunks.into_iter().enumerate().skip(2) {
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
    let receipt = db
        .finalize_staged_transaction(context(), reference.clone())
        .await
        .unwrap();
    db.shutdown().await.unwrap();
    audit.shutdown().await;
    drop(db);
    drop(audit);
    let (db, audit) = open(&directory.path().join("node.redb")).await;
    assert_eq!(
        db.finalize_staged_transaction(context(), reference.clone())
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(db.engine().generation().unwrap().state.document_count, 600);
    assert!(matches!(
        db.staged_transaction_status(&context(), &reference)
            .await
            .unwrap()
            .outcome,
        StagedOutcome::Finished { outcome: Ok(_) }
    ));
    db.shutdown().await.unwrap();
    audit.shutdown().await;
}

#[tokio::test]
async fn coherent_lease_pages_cover_large_dependencies_and_scans_with_live_writes() {
    let directory = tempfile::tempdir().unwrap();
    let (db, audit) = open(&directory.path().join("node.redb")).await;
    for name in ["docs", "ledger"] {
        db.administer(
            context(),
            Operation::CreateCollection(definition(name, CollectionWriteMode::Mutable)),
        )
        .await
        .unwrap();
    }
    let chunks = chunks();
    let (request, reference) = begin(
        &db.engine().generation().unwrap().state.incarnation,
        "lease-seed",
        &chunks,
        60_000,
    );
    db.begin_staged_transaction(context(), request)
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
    db.finalize_staged_transaction(context(), reference)
        .await
        .unwrap();
    let mut strict = policy();
    strict.strict_read_audit = true;
    db.administer(context(), Operation::SetPolicy(strict.clone()))
        .await
        .unwrap();
    let lease = db
        .open_snapshot_lease(&context(), OpenSnapshotLease { ttl_ms: 60_000 })
        .await
        .unwrap();
    db.mutate(
        context(),
        MutationBatch {
            idempotency_key: "after-lease".into(),
            read_set: vec![],
            operations: vec![
                Mutation::Put {
                    collection: "docs".into(),
                    id: "row0000".into(),
                    expected: Precondition::Any,
                    body: json!({"n":10000}),
                },
                put("docs", "row9999", 9999),
            ],
        },
    )
    .await
    .unwrap();
    for start in [0, 150, 300, 450] {
        let keys = (start..start + 150)
            .map(|n| DocumentKey {
                collection: if n % 2 == 0 { "docs" } else { "ledger" }.into(),
                id: format!("row{n:04}"),
            })
            .collect();
        let page = db
            .read_snapshot_page(
                &context(),
                ReadSnapshotPage {
                    lease_id: lease.lease_id.clone(),
                    documents: keys,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.revision, lease.revision);
        for (offset, document) in page.documents.iter().enumerate() {
            assert_eq!(
                document.document.as_ref().unwrap().body["n"],
                start + offset
            );
            assert_eq!(
                document.document.as_ref().unwrap().body["amount"],
                "90071992547409931234567890.123456789"
            );
        }
        assert_eq!(page.read_assertions().len(), 151);
    }
    let mut after = None;
    let mut scanned = vec![];
    loop {
        let page = db
            .scan_snapshot_page(
                &context(),
                ScanSnapshotPage {
                    lease_id: lease.lease_id.clone(),
                    collection: "docs".into(),
                    after_id: after,
                    limit: 37,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.snapshot.revision, lease.revision);
        scanned.extend(page.documents);
        after = page.next_after_id;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(scanned.len(), 300);
    assert!(scanned.windows(2).all(|pair| pair[0].id < pair[1].id));
    assert_eq!(scanned[0].body["n"], 0);
    assert!(!scanned.iter().any(|document| document.id == "row9999"));
    assert!(
        db.engine()
            .generation()
            .unwrap()
            .state
            .audits
            .iter()
            .any(|event| event.data_revision == Some(lease.revision) && event.action == "read")
    );
    db.close_snapshot_lease(&context(), &lease.lease_id)
        .await
        .unwrap();
    let point = |lease_id: String| ReadSnapshotPage {
        lease_id,
        documents: vec![DocumentKey {
            collection: "docs".into(),
            id: "row0000".into(),
        }],
    };
    assert_eq!(
        db.read_snapshot_page(&context(), point(lease.lease_id))
            .await
            .unwrap_err()
            .code,
        ErrorCode::CursorExpired
    );
    let lease = db
        .open_snapshot_lease(&context(), OpenSnapshotLease { ttl_ms: 60_000 })
        .await
        .unwrap();
    let mut revoked = strict.clone();
    revoked.grants[0].actions.remove(&Action::Read);
    db.administer(context(), Operation::SetPolicy(revoked))
        .await
        .unwrap();
    assert_eq!(
        db.read_snapshot_page(&context(), point(lease.lease_id.clone()))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    db.administer(context(), Operation::SetPolicy(strict))
        .await
        .unwrap();
    assert_eq!(
        db.read_snapshot_page(&context(), point(lease.lease_id.clone()))
            .await
            .unwrap_err()
            .code,
        ErrorCode::CursorExpired
    );
    db.close_snapshot_lease(&context(), &lease.lease_id)
        .await
        .unwrap();
    let mut limits = db.engine().generation().unwrap().state.limits.clone();
    limits.atomic.max_snapshot_leases = 1;
    db.administer(context(), Operation::SetLimits(limits))
        .await
        .unwrap();
    let lease = db
        .open_snapshot_lease(&context(), OpenSnapshotLease { ttl_ms: 1000 })
        .await
        .unwrap();
    assert_eq!(
        db.open_snapshot_lease(&context(), OpenSnapshotLease { ttl_ms: 1000 })
            .await
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(
        db.read_snapshot_page(&context(), point(lease.lease_id))
            .await
            .unwrap_err()
            .code,
        ErrorCode::CursorExpired
    );
    let next = db
        .open_snapshot_lease(&context(), OpenSnapshotLease { ttl_ms: 60_000 })
        .await
        .unwrap();
    db.close_snapshot_lease(&context(), &next.lease_id)
        .await
        .unwrap();
    db.shutdown().await.unwrap();
    audit.shutdown().await;
}

#[tokio::test]
async fn small_lease_budget_shares_large_roots_and_expires_on_retained_version_pressure() {
    let directory = tempfile::tempdir().unwrap();
    let (db, audit) = open(&directory.path().join("lease-delta.redb")).await;
    db.administer(
        context(),
        Operation::CreateCollection(definition("docs", CollectionWriteMode::Mutable)),
    )
    .await
    .unwrap();
    db.mutate(
        context(),
        MutationBatch {
            idempotency_key: "large-root".into(),
            read_set: vec![],
            operations: vec![Mutation::Put {
                collection: "docs".into(),
                id: "large".into(),
                expected: Precondition::Absent,
                body: json!({"n":1,"body":"a".repeat(256 << 10)}),
            }],
        },
    )
    .await
    .unwrap();
    let mut limits = db.engine().generation().unwrap().state.limits.clone();
    limits.atomic.max_snapshot_lease_bytes = 32 << 10;
    db.administer(context(), Operation::SetLimits(limits))
        .await
        .unwrap();
    let lease = db
        .open_snapshot_lease(&context(), OpenSnapshotLease { ttl_ms: 60_000 })
        .await
        .unwrap();
    let point = ReadSnapshotPage {
        lease_id: lease.lease_id.clone(),
        documents: vec![DocumentKey {
            collection: "docs".into(),
            id: "large".into(),
        }],
    };
    let mut point_fence = db.response_fence(&context()).unwrap();
    point_fence
        .bind_snapshot_lease(&lease.lease_id)
        .await
        .unwrap();
    let page = db
        .read_snapshot_page(&context(), point.clone())
        .await
        .unwrap();
    let encoded = serde_json::to_vec(&page).unwrap();
    let mut scan_fence = db.response_fence(&context()).unwrap();
    scan_fence
        .bind_snapshot_lease(&lease.lease_id)
        .await
        .unwrap();
    point_fence.check().unwrap();
    scan_fence.check().unwrap();
    db.mutate(
        context(),
        MutationBatch {
            idempotency_key: "replace-root".into(),
            read_set: vec![],
            operations: vec![Mutation::Put {
                collection: "docs".into(),
                id: "large".into(),
                expected: Precondition::Any,
                body: json!({"n":1,"body":"b".repeat(256 << 10)}),
            }],
        },
    )
    .await
    .unwrap();
    // The same bound fences used by native adapters retain only header
    // metadata. Both encoded/in-flight pages are expired by this publication.
    assert_eq!(
        point_fence.check().unwrap_err().code,
        ErrorCode::CursorExpired
    );
    assert_eq!(
        scan_fence.check().unwrap_err().code,
        ErrorCode::CursorExpired
    );
    assert_eq!(
        serde_json::from_slice::<SnapshotReadResponse>(&encoded)
            .unwrap()
            .revision,
        lease.revision
    );
    assert_eq!(
        db.read_snapshot_page(&context(), point)
            .await
            .unwrap_err()
            .code,
        ErrorCode::CursorExpired
    );
    assert_eq!(
        db.engine().generation().unwrap().state.collections["docs"].documents["large"].body["body"]
            .as_str()
            .unwrap()
            .as_bytes()[0],
        b'b'
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await;
}

#[test]
fn ordered_foreign_scope_rejection_cannot_expire_or_rebind_an_original_upload() {
    let db = engine(Limits::default());
    let mut replacement = context();
    replacement.principal = "replacement".into();
    let mut policy = policy();
    policy.grants.push(Grant {
        principal: replacement.principal.clone(),
        collection: None,
        actions: replacement.scopes.clone(),
    });
    apply(&db, 1, Operation::SetPolicy(policy)).unwrap();
    let payloads = chunks();
    let (original, reference) = begin("incarnation", "scope-before-expiry", &payloads, 10);
    apply(&db, 2, Operation::BeginStaged(original.clone())).unwrap();
    let state = db.generation().unwrap();
    let stop = StopStagedTransaction {
        original: original.clone(),
        admission: vec![
            ReadAssertion::Snapshot {
                incarnation: state.state.incarnation.clone(),
                policy_epoch: state.state.policy_epoch,
                schema_epoch: state.state.schema_epoch,
            },
            ReadAssertion::Before { not_after_ms: 2000 },
        ],
    };
    drop(state);
    for operation in [
        Operation::BeginStaged(original),
        Operation::AppendStaged(AppendStagedChunk {
            transaction: reference.clone(),
            index: 0,
            chunk: payloads[0].clone(),
        }),
        Operation::FinalizeStaged(reference),
        Operation::StopStaged(stop),
    ] {
        let result = db
            .apply_command(
                db.generation().unwrap().state.revision + 1,
                Command {
                    context: replacement.clone(),
                    timestamp_ms: 1000,
                    operation,
                },
            )
            .unwrap();
        assert_eq!(result.unwrap_err().code, ErrorCode::Forbidden);
        let generation = db.generation().unwrap();
        assert_eq!(generation.state.staged_transactions.len(), 1);
        assert_eq!(generation.state.active_staged_transactions.len(), 1);
        assert!(matches!(
            generation
                .state
                .staged_transactions
                .values()
                .next()
                .unwrap()
                .outcome,
            StagedOutcome::Uploading
        ));
    }
}

#[test]
fn permanent_staged_byte_exhaustion_preserves_success_failure_and_restored_exact_replays() {
    let db = engine(Limits::default());
    let chunk = StagedChunk {
        read_set: vec![],
        operations: vec![put("docs", "once", 42)],
    };
    let (first, reference) = begin("incarnation", "first", std::slice::from_ref(&chunk), 1000);
    apply(&db, 2, Operation::BeginStaged(first.clone())).unwrap();
    apply(
        &db,
        3,
        Operation::AppendStaged(AppendStagedChunk {
            transaction: reference.clone(),
            index: 0,
            chunk: chunk.clone(),
        }),
    )
    .unwrap();
    let current = db.generation().unwrap();
    let mut limits = current.state.limits.clone();
    limits.atomic.max_permanent_staged_bytes =
        current.state.permanent_staged_bytes + current.state.reserved_staged_terminal_bytes;
    drop(current);
    apply(&db, 3, Operation::SetLimits(limits.clone())).unwrap();
    limits.atomic.max_permanent_staged_bytes -= 1;
    assert_eq!(
        apply(&db, 3, Operation::SetLimits(limits))
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    let committed = apply(&db, 4, Operation::FinalizeStaged(reference.clone())).unwrap();
    let (second, second_reference) =
        begin("incarnation", "second", std::slice::from_ref(&chunk), 1000);
    assert_eq!(
        apply(&db, 5, Operation::BeginStaged(second.clone()))
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        apply(&db, 6, Operation::BeginStaged(first.clone())).unwrap(),
        committed
    );
    assert_eq!(
        apply(&db, 7, Operation::FinalizeStaged(reference.clone())).unwrap(),
        committed
    );
    let mut limits = db.generation().unwrap().state.limits.clone();
    limits.atomic.max_permanent_staged_bytes = 3 << 30;
    apply(&db, 8, Operation::SetLimits(limits)).unwrap();
    apply(&db, 9, Operation::BeginStaged(second.clone())).unwrap();
    apply(
        &db,
        10,
        Operation::AppendStaged(AppendStagedChunk {
            transaction: second_reference.clone(),
            index: 0,
            chunk,
        }),
    )
    .unwrap();
    let current = db.generation().unwrap();
    let mut limits = current.state.limits.clone();
    limits.atomic.max_permanent_staged_bytes =
        current.state.permanent_staged_bytes + current.state.reserved_staged_terminal_bytes;
    drop(current);
    apply(&db, 11, Operation::SetLimits(limits)).unwrap();
    let failure = apply(&db, 12, Operation::FinalizeStaged(second_reference.clone())).unwrap_err();
    assert_eq!(failure.code, ErrorCode::Conflict);
    let current = db.generation().unwrap();
    assert_eq!(current.state.reserved_staged_terminal_bytes, 0);
    assert_eq!(current.state.document_count, 1);
    assert!(
        current
            .state
            .staged_transactions
            .values()
            .all(|s| s.chunks.is_empty())
    );
    let mut limits = current.state.limits.clone();
    limits.atomic.max_permanent_staged_bytes = current.state.permanent_staged_bytes;
    let used = current.state.permanent_staged_bytes;
    drop(current);
    apply(&db, 13, Operation::SetLimits(limits)).unwrap();
    let image = db.fixture_snapshot().unwrap();
    let recovered = TenantEngine::new(
        "tenant".into(),
        "incarnation".into(),
        policy(),
        Limits::default(),
    )
    .unwrap();
    recovered.fixture_restore(&image).unwrap();
    assert_eq!(
        apply(
            &recovered,
            172_800_004,
            Operation::FinalizeStaged(reference)
        )
        .unwrap(),
        committed
    );
    assert_eq!(
        apply(&recovered, 172_800_005, Operation::BeginStaged(first)).unwrap(),
        committed
    );
    assert_eq!(
        apply(
            &recovered,
            172_800_006,
            Operation::FinalizeStaged(second_reference)
        )
        .unwrap_err(),
        failure
    );
    assert_eq!(
        apply(&recovered, 172_800_007, Operation::BeginStaged(second)).unwrap_err(),
        failure
    );
    assert_eq!(
        recovered.generation().unwrap().state.permanent_staged_bytes,
        used
    );
    assert_eq!(recovered.generation().unwrap().state.document_count, 1);
}

#[test]
fn permanent_staged_snapshot_rejection_spends_original_terminal_reservation_atomically() {
    let db = engine(Limits::default());
    let chunk = StagedChunk {
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: "too-large".into(),
            body: json!({"n": 1, "body": "x".repeat(64 << 10)}),
            expected: Precondition::Absent,
        }],
    };
    let (original, reference) = begin("incarnation", "bounded", std::slice::from_ref(&chunk), 1000);
    apply(&db, 2, Operation::BeginStaged(original.clone())).unwrap();
    apply(
        &db,
        3,
        Operation::AppendStaged(AppendStagedChunk {
            transaction: reference.clone(),
            index: 0,
            chunk,
        }),
    )
    .unwrap();
    let state = &db.generation().unwrap().state;
    let mut limits = state.limits.clone();
    limits.atomic.max_permanent_staged_bytes =
        state.permanent_staged_bytes + state.reserved_staged_terminal_bytes;
    // Finalization would add both the document and its change-feed copy. This
    // bound admits existing chunks plus terminal/audit metadata, not those effects.
    limits.max_snapshot_bytes =
        db.snapshot_bytes().unwrap() as u64 + state.reserved_staged_terminal_bytes + 4096;
    apply(&db, 4, Operation::SetLimits(limits)).unwrap();
    let failure = apply(&db, 5, Operation::FinalizeStaged(reference.clone())).unwrap_err();
    assert_eq!(failure.code, ErrorCode::QuotaExceeded);
    let state = &db.generation().unwrap().state;
    assert_eq!(state.document_count, 0);
    assert_eq!(state.change_feed.event_count, 0);
    assert_eq!(state.reserved_staged_terminal_bytes, 0);
    assert!(state.active_staged_transactions.is_empty());
    let key = staged_digest(&(context().principal, &reference.transaction_id))
        .unwrap()
        .0;
    assert_eq!(
        state.staged_transactions[&key].outcome,
        StagedOutcome::Finished {
            outcome: Err(failure.clone())
        }
    );
    assert!(state.staged_transactions[&key].chunks.is_empty());
    let recovered = TenantEngine::new(
        "tenant".into(),
        "incarnation".into(),
        policy(),
        Limits::default(),
    )
    .unwrap();
    recovered
        .fixture_restore(&db.fixture_snapshot().unwrap())
        .unwrap();
    assert_eq!(
        apply(
            &recovered,
            172_800_000,
            Operation::FinalizeStaged(reference)
        )
        .unwrap_err(),
        failure
    );
    assert_eq!(
        apply(&recovered, 172_800_001, Operation::BeginStaged(original)).unwrap_err(),
        failure
    );
    assert_eq!(recovered.generation().unwrap().state.document_count, 0);
}
