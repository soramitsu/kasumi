//! Guarded stop behavior against actual encrypted Kasumi execution and restart.
use kasumi_engine::test_utils::SnapshotFixture;
mod common;
use kasumi_engine::{Database, SecurityAudit};
use kasumi_store::{NodeStore, TenantStorageSet, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, path::Path, sync::Arc};

fn context() -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        tenant: "guarded".into(),
        principal: "owner".into(),
        request_id: "guarded-stop".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
    }
}
async fn open(path: &Path, limits: Limits) -> (Arc<Database>, Arc<SecurityAudit>) {
    let node = NodeStore::open(path, kasumi_store::ScratchDisk::fixture()).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let stores = TenantStorageSet::open_fixture(
        node,
        context().tenant,
        Arc::new(LocalKeyProvider::new([0x95; 32])),
        Arc::new(LocalKeyProvider::new([0x96; 32])),
    )
    .await
    .unwrap();
    let db = kasumi_engine::test_utils::open_fixture(
        stores,
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: context().scopes,
            }],
            strict_read_audit: false,
        },
        limits,
        audit.clone(),
    )
    .await
    .unwrap();
    if db
        .engine()
        .generation()
        .unwrap()
        .state
        .collections
        .is_empty()
    {
        for name in ["authority", "docs", "receipts"] {
            db.administer(
                context(),
                Operation::CreateCollection(CollectionDefinition {
                    name: name.into(),
                    schema: json!({"type":"object"}),
                    indexes: vec![],
                    strict_read_audit: false,
                    retention_class: CollectionRetentionClass::Operational,
                    write_mode: if name == "receipts" {
                        CollectionWriteMode::AppendOnly
                    } else {
                        CollectionWriteMode::Mutable
                    },
                }),
            )
            .await
            .unwrap();
        }
        set_authority(&db, "initial", true).await;
    }
    (db, audit)
}
async fn close(db: Arc<Database>, audit: Arc<SecurityAudit>) {
    db.shutdown().await.unwrap();
    audit.shutdown().await;
}
async fn set_authority(db: &Database, id: &str, enabled: bool) {
    db.mutate(
        context(),
        MutationBatch {
            idempotency_key: id.into(),
            read_set: vec![],
            operations: vec![Mutation::Put {
                collection: "authority".into(),
                id: "session".into(),
                body: json!({"enabled":enabled}),
                expected: Precondition::Any,
            }],
        },
    )
    .await
    .unwrap();
}
fn admission(db: &Database, name: &str) -> Vec<ReadAssertion> {
    let current = db.engine().generation().unwrap();
    vec![
        ReadAssertion::Snapshot {
            incarnation: current.state.incarnation.clone(),
            policy_epoch: current.state.policy_epoch,
            schema_epoch: current.state.schema_epoch,
        },
        ReadAssertion::Before {
            not_after_ms: kasumi_clock::EpochClock::system()
                .unwrap()
                .now_ms()
                .unwrap()
                + 60_000,
        },
        ReadAssertion::Document {
            collection: "authority".into(),
            id: "session".into(),
            expected: ReadPrecondition::Version(
                current.state.collections["authority"].documents["session"].version,
            ),
        },
        ReadAssertion::Document {
            collection: "receipts".into(),
            id: name.into(),
            expected: ReadPrecondition::Absent,
        },
    ]
}
fn original(db: &Database, name: &str) -> (BeginStagedTransaction, StagedChunk) {
    let chunk = StagedChunk {
        read_set: admission(db, name),
        operations: ["docs", "receipts"]
            .into_iter()
            .map(|collection| Mutation::Put {
                collection: collection.into(),
                id: name.into(),
                body: json!({"exact_minor_units":"100"}),
                expected: Precondition::Absent,
            })
            .collect(),
    };
    let begin = BeginStagedTransaction {
        transaction_id: name.into(),
        manifest: StagedManifest::from_chunks(std::slice::from_ref(&chunk)).unwrap(),
        ttl_ms: 60_000,
    };
    (begin, chunk)
}
fn stop(db: &Database, original: &BeginStagedTransaction) -> StopStagedTransaction {
    StopStagedTransaction {
        original: original.clone(),
        admission: admission(db, &original.transaction_id),
    }
}
async fn upload(db: &Database, original: &BeginStagedTransaction, chunk: &StagedChunk) {
    db.begin_staged_transaction(context(), original.clone())
        .await
        .unwrap();
    db.append_staged_chunk(
        context(),
        AppendStagedChunk {
            transaction: original.reference().unwrap(),
            index: 0,
            chunk: chunk.clone(),
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn missing_stop_has_no_upload_lease_and_defeats_delayed_begin_after_encrypted_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("node.redb");
    let (db, audit) = open(&path, Limits::default()).await;
    let (original, chunk) = original(&db, "missing");
    let saved = db
        .stop_staged_transaction(context(), stop(&db, &original))
        .await
        .unwrap();
    assert!(matches!(saved.outcome, StagedOutcome::Aborted { .. }));
    assert_eq!(saved.expires_at_ms, None);
    assert!(saved.received_chunks.is_empty());
    let mut invalid_wire = serde_json::to_value(&saved).unwrap();
    invalid_wire
        .as_object_mut()
        .unwrap()
        .remove("expires_at_ms");
    assert!(serde_json::from_value::<StagedTransactionStatus>(invalid_wire).is_err());
    close(db, audit).await;
    let (db, audit) = open(&path, Limits::default()).await;
    set_authority(&db, "fresh-current-authority", true).await;
    let recovered = db
        .stop_staged_transaction(context(), stop(&db, &original))
        .await
        .unwrap();
    assert_eq!(saved.outcome, recovered.outcome);
    assert!(
        db.begin_staged_transaction(context(), original.clone())
            .await
            .is_err()
    );
    assert!(
        db.append_staged_chunk(
            context(),
            AppendStagedChunk {
                transaction: original.reference().unwrap(),
                index: 0,
                chunk
            }
        )
        .await
        .is_err()
    );
    assert!(
        db.finalize_staged_transaction(context(), original.reference().unwrap())
            .await
            .is_err()
    );
    let mut changed = original.clone();
    changed.ttl_ms += 1;
    assert_eq!(
        db.stop_staged_transaction(context(), stop(&db, &changed))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(db.get(&context(), "docs", "missing").await.is_err());
    close(db, audit).await;
}

#[tokio::test]
async fn upload_stop_clears_payload_and_permanent_capacity_is_checked_without_active_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let mut limits = Limits::default();
    limits.atomic.max_active_transactions = 1;
    limits.atomic.max_transaction_records = 2;
    let (db, audit) = open(&directory.path().join("node.redb"), limits).await;
    let (first, chunk) = original(&db, "uploading");
    upload(&db, &first, &chunk).await;
    let (never, _) = original(&db, "never-started");
    let absent = db
        .stop_staged_transaction(context(), stop(&db, &never))
        .await
        .unwrap();
    assert_eq!(absent.expires_at_ms, None);
    assert_eq!(
        db.engine()
            .generation()
            .unwrap()
            .state
            .active_staged_transactions
            .len(),
        1
    );
    let stopped = db
        .stop_staged_transaction(context(), stop(&db, &first))
        .await
        .unwrap();
    assert!(stopped.expires_at_ms.is_some());
    assert!(stopped.received_chunks.is_empty());
    let current = db.engine().generation().unwrap();
    assert!(current.state.active_staged_transactions.is_empty());
    assert!(
        current
            .state
            .staged_transactions
            .values()
            .all(|s| s.chunks.is_empty() && s.uploaded_payload_bytes == 0)
    );
    drop(current);
    let (third, _) = original(&db, "quota-denied");
    assert_eq!(
        db.stop_staged_transaction(context(), stop(&db, &third))
            .await
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        db.engine()
            .generation()
            .unwrap()
            .state
            .staged_transactions
            .len(),
        2
    );
    close(db, audit).await;
}

#[tokio::test]
async fn committed_original_survives_receipt_absence_admission_failure_and_fresh_resolution() {
    let directory = tempfile::tempdir().unwrap();
    let (db, audit) = open(&directory.path().join("node.redb"), Limits::default()).await;
    let (original, chunk) = original(&db, "committed");
    upload(&db, &original, &chunk).await;
    let before = stop(&db, &original);
    let committed = db
        .finalize_staged_transaction(context(), original.reference().unwrap())
        .await
        .unwrap();
    assert_eq!(
        db.stop_staged_transaction(context(), before)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let receipt = db.get(&context(), "receipts", "committed").await.unwrap();
    let mut current = stop(&db, &original);
    current.admission.retain(
        |a| !matches!(a, ReadAssertion::Document { collection, .. } if collection == "receipts"),
    );
    current.admission.push(ReadAssertion::Document {
        collection: "receipts".into(),
        id: "committed".into(),
        expected: ReadPrecondition::Version(receipt.version),
    });
    let status = db
        .stop_staged_transaction(context(), current)
        .await
        .unwrap();
    assert_eq!(
        status.outcome,
        StagedOutcome::Finished {
            outcome: Ok(committed)
        }
    );
    assert_eq!(
        db.get(&context(), "docs", "committed").await.unwrap().body["exact_minor_units"],
        "100"
    );
    close(db, audit).await;
}

#[tokio::test]
async fn stale_authority_cannot_create_stop_and_retained_terminal_release_checks_exact_read_scope()
{
    let directory = tempfile::tempdir().unwrap();
    let (db, audit) = open(&directory.path().join("node.redb"), Limits::default()).await;
    let (original, _) = original(&db, "authority");
    let stale = stop(&db, &original);
    set_authority(&db, "revoked", false).await;
    assert_eq!(
        db.stop_staged_transaction(context(), stale)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(
        db.staged_transaction_status(&context(), &original.reference().unwrap())
            .await
            .is_err()
    );
    let current = stop(&db, &original);
    let stopped = db
        .stop_staged_transaction(context(), current.clone())
        .await
        .unwrap();
    let mut read_only = context();
    read_only.scopes.remove(&Action::Write);
    assert_eq!(
        db.stop_staged_transaction(read_only, current.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    let mut write_only = context();
    write_only.scopes.remove(&Action::Read);
    assert_eq!(
        db.stop_staged_transaction(write_only, current)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert!(matches!(stopped.outcome, StagedOutcome::Aborted { .. }));
    close(db, audit).await;
}

#[tokio::test]
async fn final_response_fence_rechecks_authority_and_preserves_accepted_stop() {
    let directory = tempfile::tempdir().unwrap();
    let (db, audit) = open(&directory.path().join("node.redb"), Limits::default()).await;
    let (original, _) = original(&db, "release");
    let request = stop(&db, &original);
    let context = context();
    let fence = db.staged_stop_response_fence(&context, &request).unwrap();
    let accepted = db
        .stop_staged_transaction(context.clone(), request)
        .await
        .unwrap();
    let encoded = serde_json::to_vec(&accepted).unwrap();
    set_authority(&db, "changed-before-encoded-release", false).await;
    assert_eq!(fence.check().unwrap_err().code, ErrorCode::Conflict);
    drop(encoded);
    drop(fence);
    let recovered = db
        .stop_staged_transaction(context, stop(&db, &original))
        .await
        .unwrap();
    assert_eq!(recovered.outcome, accepted.outcome);
    close(db, audit).await;
}

#[tokio::test]
async fn concurrent_original_and_stop_keep_exactly_one_permanent_outcome() {
    let directory = tempfile::tempdir().unwrap();
    let (db, audit) = open(&directory.path().join("node.redb"), Limits::default()).await;
    for iteration in 0..4 {
        let name = format!("race-{iteration}");
        let (original, chunk) = original(&db, &name);
        upload(&db, &original, &chunk).await;
        let (finished, _stop_attempt) = tokio::join!(
            db.finalize_staged_transaction(context(), original.reference().unwrap()),
            db.stop_staged_transaction(context(), stop(&db, &original))
        );
        let status = db
            .staged_transaction_status(&context(), &original.reference().unwrap())
            .await
            .unwrap();
        match status.outcome {
            StagedOutcome::Finished {
                outcome: Ok(receipt),
            } => {
                assert_eq!(finished.unwrap(), receipt);
                assert!(db.get(&context(), "receipts", &name).await.is_ok());
            }
            StagedOutcome::Aborted { .. } => {
                assert!(finished.is_err());
                assert!(db.get(&context(), "receipts", &name).await.is_err());
            }
            other => panic!("unexpected terminal outcome: {other:?}"),
        }
    }
    close(db, audit).await;
}

#[tokio::test]
async fn malformed_fresh_admission_and_changed_manifest_cannot_accept_or_rebind_identity() {
    let directory = tempfile::tempdir().unwrap();
    let (db, audit) = open(&directory.path().join("node.redb"), Limits::default()).await;
    let (original, chunk) = original(&db, "closed-input");
    let valid = stop(&db, &original);
    let mut missing_snapshot = valid.clone();
    missing_snapshot
        .admission
        .retain(|assertion| !matches!(assertion, ReadAssertion::Snapshot { .. }));
    let mut missing_deadline = valid.clone();
    missing_deadline
        .admission
        .retain(|assertion| !matches!(assertion, ReadAssertion::Before { .. }));
    let mut duplicate = valid.clone();
    duplicate.admission.push(duplicate.admission[0].clone());
    for request in [missing_snapshot, missing_deadline, duplicate] {
        assert_eq!(
            db.stop_staged_transaction(context(), request)
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert!(
            db.engine()
                .generation()
                .unwrap()
                .state
                .staged_transactions
                .is_empty()
        );
    }
    let accepted = db
        .stop_staged_transaction(context(), valid.clone())
        .await
        .unwrap();
    let mut changed = valid;
    let mut changed_chunk = chunk;
    if let Mutation::Put { body, .. } = &mut changed_chunk.operations[0] {
        *body = json!({"substituted":true});
    }
    changed.original.manifest = StagedManifest::from_chunks(&[changed_chunk]).unwrap();
    assert_eq!(
        db.stop_staged_transaction(context(), changed)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        db.stop_staged_transaction(context(), stop(&db, &original))
            .await
            .unwrap()
            .outcome,
        accepted.outcome
    );
    close(db, audit).await;
}

#[tokio::test]
async fn stopped_resolution_preserves_original_failed_finalize() {
    let directory = tempfile::tempdir().unwrap();
    let (db, audit) = open(&directory.path().join("node.redb"), Limits::default()).await;
    let (original, chunk) = original(&db, "failed-finalize");
    upload(&db, &original, &chunk).await;
    set_authority(&db, "authority-changed", false).await;
    let failure = db
        .finalize_staged_transaction(context(), original.reference().unwrap())
        .await
        .unwrap_err();
    assert_eq!(failure.code, ErrorCode::Conflict);
    let original_status = db
        .staged_transaction_status(&context(), &original.reference().unwrap())
        .await
        .unwrap();
    assert!(matches!(
        original_status.outcome,
        StagedOutcome::Finished { outcome: Err(_) }
    ));
    let resolved = db
        .stop_staged_transaction(context(), stop(&db, &original))
        .await
        .unwrap();
    assert_eq!(resolved.outcome, original_status.outcome);
    assert!(
        db.get(&context(), "receipts", "failed-finalize")
            .await
            .is_err()
    );
    close(db, audit).await;
}

#[tokio::test]
async fn retained_snapshot_quota_rejects_missing_stop_without_leaving_partial_identity() {
    let directory = tempfile::tempdir().unwrap();
    let (db, audit) = open(&directory.path().join("node.redb"), Limits::default()).await;
    let mut limits = db.engine().generation().unwrap().state.limits.clone();
    limits.max_snapshot_bytes = db.engine().snapshot_bytes().unwrap() as u64 + 8192;
    db.administer(context(), Operation::SetLimits(limits))
        .await
        .unwrap();
    let (_, chunk) = original(&db, "bounded");
    let original = BeginStagedTransaction {
        transaction_id: "snapshot-full".into(),
        ttl_ms: 60_000,
        manifest: StagedManifest::from_chunks(&vec![chunk; 512]).unwrap(),
    };
    assert_eq!(
        db.stop_staged_transaction(context(), stop(&db, &original))
            .await
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    let generation = db.engine().generation().unwrap();
    assert!(generation.state.staged_transactions.is_empty());
    assert!(generation.state.active_staged_transactions.is_empty());
    assert_eq!(
        db.engine().snapshot_bytes().unwrap() as u64,
        db.engine().fixture_snapshot().unwrap().len()
    );
    drop(generation);
    close(db, audit).await;
}

#[tokio::test]
async fn guarded_stop_orders_more_than_one_small_batch_of_authority_dependencies() {
    let directory = tempfile::tempdir().unwrap();
    let (db, audit) = open(&directory.path().join("node.redb"), Limits::default()).await;
    for batch in 0..3 {
        db.mutate(
            context(),
            MutationBatch {
                idempotency_key: format!("authority-{batch}"),
                read_set: vec![],
                operations: (batch * 200..(batch + 1) * 200)
                    .map(|index| Mutation::Put {
                        collection: "authority".into(),
                        id: format!("dependency-{index}"),
                        expected: Precondition::Absent,
                        body: json!({"active":true}),
                    })
                    .collect(),
            },
        )
        .await
        .unwrap();
    }
    let (original, _) = original(&db, "large-authority");
    let mut request = stop(&db, &original);
    let generation = db.engine().generation().unwrap();
    request.admission.extend((0..600).map(|index| {
        let id = format!("dependency-{index}");
        ReadAssertion::Document {
            collection: "authority".into(),
            expected: ReadPrecondition::Version(
                generation.state.collections["authority"].documents[&id].version,
            ),
            id,
        }
    }));
    drop(generation);
    assert_eq!(request.admission.len(), 604);
    db.mutate(
        context(),
        MutationBatch {
            idempotency_key: "last-dependency-revoked".into(),
            read_set: vec![],
            operations: vec![Mutation::Put {
                collection: "authority".into(),
                id: "dependency-599".into(),
                expected: Precondition::Any,
                body: json!({"active":false}),
            }],
        },
    )
    .await
    .unwrap();
    assert_eq!(
        db.stop_staged_transaction(context(), request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(
        db.engine()
            .generation()
            .unwrap()
            .state
            .staged_transactions
            .is_empty()
    );
    *request.admission.last_mut().unwrap() = ReadAssertion::Document {
        collection: "authority".into(), id: "dependency-599".into(),
        expected: ReadPrecondition::Version(db.engine().generation().unwrap().state.collections["authority"].documents["dependency-599"].version),
    };
    assert!(matches!(
        db.stop_staged_transaction(context(), request)
            .await
            .unwrap()
            .outcome,
        StagedOutcome::Aborted { .. }
    ));
    close(db, audit).await;
}
