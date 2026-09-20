//! Planned retirement and durable stop tests against actual encrypted storage.
mod common;
use kasumi_engine::{Database, SecurityAudit};
use kasumi_store::{
    FilesystemBackupDestination, NodeStore, TenantStore, test_utils::LocalKeyProvider,
};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

fn context() -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        tenant: "retirement".into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "retirement-test".into(),
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

async fn reopen_custody(
    node: Arc<NodeStore>,
    audit: Arc<SecurityAudit>,
) -> Arc<kasumi_engine::RetiredCustody> {
    let store = kasumi_store::CustodyStore::open(
        node,
        context().tenant,
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await
    .unwrap();
    let control = kasumi_raft::ControlLog::installed(store.clone())
        .unwrap()
        .unwrap();
    let id = control.node_id();
    let group = control.group().to_owned();
    let router = Arc::new(kasumi_raft::InProcessRouter::default());
    let custody = kasumi_engine::RetiredCustody::open_replicated(
        store,
        id,
        group.clone(),
        router.clone(),
        kasumi_raft::CustodyRaftConfig::default(),
        audit.admission().clone(),
        audit,
    )
    .await
    .unwrap();
    let raft = custody.raft_group().unwrap().raft();
    router.register(group, id, raft.clone());
    raft.wait(Some(std::time::Duration::from_secs(10)))
        .current_leader(id, "existing custody voter")
        .await
        .unwrap();
    custody
}
struct Fixture {
    directory: tempfile::TempDir,
    db: Arc<Database>,
    audit: Arc<SecurityAudit>,
    store: Arc<TenantStore>,
    destination: Arc<FilesystemBackupDestination>,
}
impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let node = NodeStore::create_new(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let audit = common::security_audit(node.clone()).await;
        let store = TenantStore::initialize_catalog_fixture(
            node,
            context().tenant,
            Arc::new(LocalKeyProvider::new([0xe1; 32])),
        )
        .await
        .unwrap();
        let db = kasumi_engine::test_utils::open_fixture(
            kasumi_store::test_utils::initialize_custody_fixture(
                store.clone(),
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
        db.install_admission(
            kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
        )
        .unwrap();
        db.administer(
            context(),
            Operation::CreateCollection(CollectionDefinition {
                name: "journal".into(),
                write_mode: CollectionWriteMode::AppendOnly,
                retention_class: CollectionRetentionClass::ArchivableHistory,
                schema: json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
        let destination = Arc::new(
            FilesystemBackupDestination::new(directory.path().join("backups"), 16 << 20).unwrap(),
        );
        db.install_archive_destination("approved".into(), destination.clone())
            .unwrap();
        Self {
            directory,
            db,
            audit,
            store,
            destination,
        }
    }
    async fn write(&self, id: &str) -> WriteReceipt {
        self.db
            .mutate(
                context(),
                MutationBatch {
                    idempotency_key: id.into(),
                    read_set: vec![],
                    operations: vec![Mutation::Put {
                        collection: "journal".into(),
                        id: id.into(),
                        body: json!({"amount":"90071992547409931234567890"}),
                        expected: Precondition::Absent,
                    }],
                },
            )
            .await
            .unwrap()
    }
    async fn request(&self, id: &str) -> RetireSourceRequest {
        let checkpoint = self
            .db
            .backup_checkpoint_named(context(), "approved", uuid::Uuid::new_v4())
            .await
            .unwrap();
        RetireSourceRequest {
            retirement_id: id.into(),
            expected_source_incarnation: checkpoint.source_incarnation().into(),
            target_incarnation: uuid::Uuid::new_v4().to_string(),
            checkpoint: checkpoint.checkpoint().clone(),
            destination: "approved".into(),
            not_after_ms: u64::MAX,
        }
    }
    async fn close(self) {
        self.db.shutdown().await.unwrap();
        self.audit.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn actual_retirement_seed_reopens_through_control_domain_without_loading_source_payload() {
    let fixture = Fixture::new().await;
    fixture.write("private-journal-entry").await;
    let request = fixture.request("custody-seed").await;
    let proof = fixture
        .db
        .retire_source(context(), request.clone())
        .await
        .unwrap();
    let revision_base = fixture
        .db
        .engine()
        .generation()
        .unwrap()
        .state
        .revision_base;
    let index = proof.revision() - revision_base;
    let group = format!(
        "{}/{}",
        context().tenant,
        request.expected_source_incarnation
    );
    let control = kasumi_raft::ControlLog::open(
        fixture.db.raft_group().storage_domains().custody().clone(),
        1,
        group.clone(),
    )
    .unwrap();
    let stored = control.retirement_seed(index).unwrap().unwrap();
    assert_eq!(stored.seed().request(), &request);
    assert_eq!(stored.log_id().index + revision_base, proof.revision());
    let original = stored.seed().encoded().unwrap();
    drop(stored);
    drop(control);
    fixture.db.shutdown().await.unwrap();
    fixture.audit.shutdown().await.unwrap();
    let Fixture {
        directory,
        db,
        audit,
        store,
        destination,
    } = fixture;
    drop(db);
    drop(audit);
    drop(store);
    drop(destination);
    // The custody opener has no application provider or Database parameter.
    // This observation is recovery input; it is not a fresh Admin proof.
    let custody = kasumi_store::CustodyStore::open(
        NodeStore::open_existing(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap(),
        context().tenant,
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await
    .unwrap();
    let reopened = kasumi_raft::ControlLog::open(custody.clone(), 1, group).unwrap();
    assert_eq!(
        reopened
            .retirement_seed(index)
            .unwrap()
            .unwrap()
            .seed()
            .encoded()
            .unwrap(),
        original
    );
    custody.store().shutdown().await.unwrap();
}

#[tokio::test]
async fn exact_retirement_seals_source_once_and_retains_proof_after_encrypted_restart() {
    let fixture = Fixture::new().await;
    let row = fixture.write("one").await;
    fixture
        .db
        .archive_history(
            context(),
            ArchiveHistory {
                archive_id: "history".into(),
                collection: "journal".into(),
                cutoff_revision: row.revision,
                destination: "approved".into(),
            },
        )
        .await
        .unwrap();
    let request = fixture.request("move-one").await;
    let reference = request.reference().unwrap();
    // These intrinsic audited operations may advance Raft revisions after the
    // exact checkpoint without changing application closure.
    fixture
        .db
        .verify_backup_checkpoint_named(context(), "approved", request.checkpoint.backup_id)
        .await
        .unwrap();
    let proof = fixture
        .db
        .retire_source(context(), request.clone())
        .await
        .unwrap();
    assert_eq!(proof.checkpoint(), &request.checkpoint);
    assert_eq!(
        proof.source_incarnation(),
        request.expected_source_incarnation
    );
    assert_eq!(proof.target_incarnation(), request.target_incarnation);
    let receipt = proof.receipt().clone();
    let resolved = fixture
        .db
        .abort_retirement(context(), request.clone())
        .await
        .unwrap();
    let kasumi_engine::VerifiedRetirementResolution::Retired(resolved) = resolved else {
        panic!("committed retirement cannot become stopped")
    };
    assert_eq!(resolved.receipt(), &receipt);
    let epoch = proof.policy_epoch();
    assert_eq!(
        fixture
            .db
            .retire_source(context(), request.clone())
            .await
            .unwrap()
            .receipt(),
        &receipt
    );
    assert_eq!(
        fixture.db.engine().generation().unwrap().state.policy_epoch,
        epoch
    );
    assert_eq!(
        fixture
            .db
            .get(&context(), "journal", "one")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Sealed
    );
    let mut wrong = request.clone();
    wrong.target_incarnation = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        fixture
            .db
            .retire_source(context(), wrong)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        fixture
            .db
            .retirement_status(&context(), &reference)
            .await
            .unwrap()
            .unwrap()
            .outcome
            .unwrap(),
        receipt
    );
    let mut unauthorized = context();
    unauthorized.scopes.remove(&Action::Admin);
    assert_eq!(
        fixture
            .db
            .verify_retirement_receipt(unauthorized, &reference)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    let path = fixture.directory.path().join("node.redb");
    fixture.db.shutdown().await.unwrap();
    fixture.audit.shutdown().await.unwrap();
    let Fixture {
        directory,
        db,
        audit,
        store,
        destination,
    } = fixture;
    drop(db);
    drop(audit);
    drop(store);
    drop(destination);
    let node = NodeStore::open_existing(
        path,
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let audit = common::existing_security_audit(node.clone()).await;
    let db = reopen_custody(node, audit.clone()).await;
    // Permanent recovery does not need backup objects to be read again, and the
    // original action deadline does not expire immutable retirement evidence.
    assert_eq!(
        db.verify_retirement_receipt(context(), &reference)
            .await
            .unwrap()
            .receipt(),
        &receipt
    );
    assert_eq!(
        db.verify_retirement_receipt(context(), &reference)
            .await
            .unwrap()
            .receipt(),
        &receipt
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
    drop(directory);
}

#[tokio::test]
async fn post_checkpoint_payload_or_rejected_mutation_identity_blocks_retirement() {
    for rejected_identity_only in [false, true] {
        let fixture = Fixture::new().await;
        fixture.write("one").await;
        let request = fixture.request("move-drift").await;
        let before =
            fixture.db.engine().generation().unwrap().state.collections["journal"].data_epoch;
        if rejected_identity_only {
            let result = fixture
                .db
                .mutate(
                    context(),
                    MutationBatch {
                        idempotency_key: "rejected-after-backup".into(),
                        read_set: vec![],
                        operations: vec![Mutation::Put {
                            collection: "journal".into(),
                            id: "one".into(),
                            body: json!({"amount":0}),
                            expected: Precondition::Absent,
                        }],
                    },
                )
                .await;
            assert!(result.is_err());
            assert_eq!(
                fixture.db.engine().generation().unwrap().state.collections["journal"].data_epoch,
                before
            );
        } else {
            fixture.write("two").await;
        }
        let reference = request.reference().unwrap();
        assert_eq!(
            fixture
                .db
                .retire_source(context(), request.clone())
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        let status = fixture
            .db
            .retirement_status(&context(), &reference)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.outcome.unwrap_err().code, ErrorCode::Conflict);
        assert!(!fixture.db.engine().generation().unwrap().state.retired);
        assert_eq!(
            fixture
                .db
                .retire_source(context(), request)
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        fixture.close().await;
    }
}

#[tokio::test]
async fn caller_checkpoint_observation_is_not_backup_authority() {
    let fixture = Fixture::new().await;
    fixture.write("one").await;
    let mut request = fixture.request("fake-backup").await;
    request.checkpoint.resident_sha256 = "00".repeat(32);
    let reference = request.reference().unwrap();
    assert_eq!(
        fixture
            .db
            .retire_source(context(), request)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(
        fixture
            .db
            .retirement_status(&context(), &reference)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!fixture.db.engine().generation().unwrap().state.retired);
    fixture.close().await;
}

#[tokio::test]
async fn retired_source_rotates_custody_without_reopening_data_or_rewriting_original_actor() {
    let fixture = Fixture::new().await;
    fixture.write("one").await;
    let request = fixture.request("custody").await;
    let reference = request.reference().unwrap();
    let proof = fixture
        .db
        .retire_source(context(), request.clone())
        .await
        .unwrap();
    let original = proof.receipt().clone();
    let fence = fixture
        .db
        .retirement_response_fence(&context(), &proof)
        .unwrap();
    let closed = fixture.db.retired_custody().unwrap();
    let rotate = CustodyRequest {
        retirement: reference.clone(),
        command_id: "rotate-custody".into(),
        expected_policy_epoch: 1,
        not_after_ms: u64::MAX,
        action: CustodyAction::ReplaceAdministrators(BTreeSet::from(["custodian".into()])),
    };
    assert_eq!(
        closed
            .execute(context(), rotate.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::UnknownOutcome
    );
    assert_eq!(fence.check().unwrap_err().code, ErrorCode::Forbidden);
    drop(fence);
    for result in [
        fixture
            .db
            .verify_retirement_receipt(context(), &reference)
            .await,
        fixture.db.retire_source(context(), request.clone()).await,
    ] {
        assert_eq!(result.unwrap_err().code, ErrorCode::Forbidden);
    }
    assert_eq!(
        fixture
            .db
            .retirement_status(&context(), &reference)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    let custodian = RequestContext {
        principal: "custodian".into(),
        ..context()
    };
    let replay = closed.execute(custodian.clone(), rotate).await.unwrap();
    assert_eq!(replay.principal, "owner");
    replay.outcome.unwrap();
    assert_eq!(
        fixture
            .db
            .verify_retirement_receipt(custodian.clone(), &reference)
            .await
            .unwrap()
            .receipt(),
        &original
    );
    assert_eq!(
        fixture
            .db
            .retire_source(custodian.clone(), request)
            .await
            .unwrap()
            .receipt(),
        &original
    );
    assert_eq!(
        fixture
            .db
            .retirement_status(&custodian, &reference)
            .await
            .unwrap()
            .unwrap()
            .principal,
        "owner"
    );
    assert_eq!(
        fixture
            .db
            .administer(custodian.clone(), Operation::Suspend(false))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        fixture
            .db
            .get(&custodian, "journal", "one")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    let result = fixture
        .db
        .mutate(
            custodian,
            MutationBatch {
                idempotency_key: "cannot-reopen".into(),
                read_set: vec![],
                operations: vec![Mutation::Put {
                    collection: "journal".into(),
                    id: "two".into(),
                    body: json!({"amount":0}),
                    expected: Precondition::Absent,
                }],
            },
        )
        .await;
    assert!(matches!(
        result.unwrap_err().code,
        ErrorCode::Sealed | ErrorCode::Forbidden
    ));
    assert_eq!(
        fixture
            .db
            .engine()
            .generation()
            .unwrap()
            .state
            .retirements
            .len(),
        1
    );
    fixture.close().await;
}

struct CountedDestination {
    inner: Arc<FilesystemBackupDestination>,
    reads: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl kasumi_store::BackupDestination for CountedDestination {
    async fn session_put(
        &self,
        session: uuid::Uuid,
        slot: kasumi_store::BackupSessionSlot,
        bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        kasumi_store::BackupDestination::session_put(self.inner.as_ref(), session, slot, bytes)
            .await
    }
    async fn session_get(
        &self,
        session: uuid::Uuid,
        slot: kasumi_store::BackupSessionSlot,
        limit: usize,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        if matches!(slot, kasumi_store::BackupSessionSlot::Object(_)) {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        kasumi_store::BackupDestination::session_get(self.inner.as_ref(), session, slot, limit)
            .await
    }

    async fn put(&self, id: uuid::Uuid, bytes: Vec<u8>) -> anyhow::Result<()> {
        kasumi_store::BackupDestination::put(self.inner.as_ref(), id, bytes).await
    }
    async fn get(&self, id: uuid::Uuid, max: usize) -> anyhow::Result<Vec<u8>> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        kasumi_store::BackupDestination::get(self.inner.as_ref(), id, max).await
    }
}

#[tokio::test]
async fn permanent_retirement_quota_fails_before_backup_io_and_exact_failure_replays() {
    let fixture = Fixture::new().await;
    let counted = Arc::new(CountedDestination {
        inner: fixture.destination.clone(),
        reads: Default::default(),
    });
    fixture
        .db
        .install_archive_destination("counted".into(), counted.clone())
        .unwrap();
    let mut request = fixture.request("expired").await;
    request.destination = "counted".into();
    request.not_after_ms = 1;
    assert_eq!(
        fixture
            .db
            .retire_source(context(), request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(counted.reads.swap(0, std::sync::atomic::Ordering::SeqCst) > 0);
    let used = fixture
        .db
        .engine()
        .generation()
        .unwrap()
        .state
        .retirement_bytes;
    fixture
        .db
        .administer(
            context(),
            Operation::SetLimits(Limits {
                max_retirement_bytes: used,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        fixture
            .db
            .retire_source(context(), request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(counted.reads.load(std::sync::atomic::Ordering::SeqCst), 0);
    let kasumi_engine::VerifiedRetirementResolution::Stopped(stopped) = fixture
        .db
        .abort_retirement(context(), request.clone())
        .await
        .unwrap()
    else {
        panic!("deadline failure must be definitive")
    };
    assert_eq!(stopped.reference(), &request.reference().unwrap());
    assert_eq!(counted.reads.load(std::sync::atomic::Ordering::SeqCst), 0);
    request.retirement_id = "another".into();
    assert_eq!(
        fixture
            .db
            .retire_source(context(), request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(counted.reads.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(!fixture.db.engine().generation().unwrap().state.retired);
    assert_eq!(
        fixture
            .db
            .engine()
            .generation()
            .unwrap()
            .state
            .retirement_bytes,
        used
    );
    fixture
        .db
        .administer(
            context(),
            Operation::SetLimits(Limits {
                max_retirement_bytes: 3 << 30,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    // The new identity is now admitted, while its already expired action still
    // records a permanent failure instead of fencing the source.
    assert_eq!(
        fixture
            .db
            .retire_source(context(), request)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(counted.reads.load(std::sync::atomic::Ordering::SeqCst) > 0);
    assert_eq!(
        fixture
            .db
            .engine()
            .generation()
            .unwrap()
            .state
            .retirements
            .len(),
        2
    );
    fixture.close().await;
}

struct PausedRetirementDestination {
    inner: Arc<FilesystemBackupDestination>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    pause: std::sync::atomic::AtomicBool,
}
#[async_trait::async_trait]
impl kasumi_store::BackupDestination for PausedRetirementDestination {
    async fn session_put(
        &self,
        session: uuid::Uuid,
        slot: kasumi_store::BackupSessionSlot,
        bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        kasumi_store::BackupDestination::session_put(self.inner.as_ref(), session, slot, bytes)
            .await
    }
    async fn session_get(
        &self,
        session: uuid::Uuid,
        slot: kasumi_store::BackupSessionSlot,
        limit: usize,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        if matches!(slot, kasumi_store::BackupSessionSlot::Object(_))
            && self.pause.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.entered.notify_one();
            self.release.notified().await;
        }
        kasumi_store::BackupDestination::session_get(self.inner.as_ref(), session, slot, limit)
            .await
    }

    async fn put(&self, id: uuid::Uuid, bytes: Vec<u8>) -> anyhow::Result<()> {
        kasumi_store::BackupDestination::put(self.inner.as_ref(), id, bytes).await
    }
    async fn get(&self, id: uuid::Uuid, max: usize) -> anyhow::Result<Vec<u8>> {
        if self.pause.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        kasumi_store::BackupDestination::get(self.inner.as_ref(), id, max).await
    }
}

#[tokio::test]
async fn durable_retirement_stop_defeats_inflight_backup_verification_and_survives_restart() {
    let fixture = Fixture::new().await;
    fixture.write("one").await;
    let mut request = fixture.request("stopped-inflight").await;
    request.destination = "paused".into();
    let paused = Arc::new(PausedRetirementDestination {
        inner: fixture.destination.clone(),
        entered: Default::default(),
        release: Default::default(),
        pause: std::sync::atomic::AtomicBool::new(true),
    });
    fixture
        .db
        .install_archive_destination("paused".into(), paused.clone())
        .unwrap();
    let pending = tokio::spawn({
        let db = fixture.db.clone();
        let request = request.clone();
        async move { db.retire_source(context(), request).await }
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        paused.entered.notified(),
    )
    .await
    .unwrap();
    assert!(
        fixture
            .db
            .retirement_status(&context(), &request.reference().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    let stopped = fixture
        .db
        .abort_retirement(context(), request.clone())
        .await
        .unwrap();
    let kasumi_engine::VerifiedRetirementResolution::Stopped(stopped) = stopped else {
        panic!("stop must win before retirement admission")
    };
    assert_eq!(stopped.tenant(), context().tenant);
    assert_eq!(stopped.reference(), &request.reference().unwrap());
    let stable = stopped.status().clone();
    paused.release.notify_one();
    assert_eq!(
        pending.await.unwrap().unwrap_err().code,
        ErrorCode::Conflict
    );
    assert!(!fixture.db.engine().generation().unwrap().state.retired);
    assert_eq!(
        fixture
            .db
            .retire_source(context(), request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    drop(paused);
    let path = fixture.directory.path().join("node.redb");
    fixture.db.shutdown().await.unwrap();
    fixture.audit.shutdown().await.unwrap();
    let Fixture {
        directory,
        db,
        audit,
        store,
        destination,
    } = fixture;
    drop(db);
    drop(audit);
    drop(store);
    drop(destination);
    let node = NodeStore::open_existing(
        path,
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let audit = common::existing_security_audit(node.clone()).await;
    let store = TenantStore::open_existing_fixture(
        node,
        context().tenant,
        Arc::new(LocalKeyProvider::new([0xe1; 32])),
    )
    .await
    .unwrap();
    let db = kasumi_engine::test_utils::open_fixture(
        kasumi_store::test_utils::open_existing_custody_fixture(
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
    let kasumi_engine::VerifiedRetirementResolution::Stopped(replayed) = db
        .abort_retirement(context(), request.clone())
        .await
        .unwrap()
    else {
        panic!("stop must survive restart")
    };
    assert_eq!(replayed.status(), &stable);
    assert_eq!(
        db.retire_source(context(), request).await.unwrap_err().code,
        ErrorCode::Conflict
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
    drop(directory);
}

#[tokio::test]
async fn invisible_staged_identity_after_checkpoint_is_not_lost_by_retirement() {
    let fixture = Fixture::new().await;
    let request = fixture.request("stage-drift").await;
    let manifest = StagedManifest::from_chunks(&[StagedChunk {
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "journal".into(),
            id: "invisible".into(),
            body: json!({"amount":1}),
            expected: Precondition::Absent,
        }],
    }])
    .unwrap();
    fixture
        .db
        .begin_staged_transaction(
            context(),
            BeginStagedTransaction {
                scope: kasumi_types::StagedTransactionScope {
                    tenant: context().tenant,
                    principal: context().principal,
                    incarnation: fixture
                        .db
                        .engine()
                        .generation()
                        .unwrap()
                        .state
                        .incarnation
                        .clone(),
                },
                transaction_id: "invisible".into(),
                manifest,
                ttl_ms: 30_000,
            },
        )
        .await
        .unwrap();
    assert!(
        fixture.db.engine().generation().unwrap().state.collections["journal"]
            .documents
            .is_empty()
    );
    assert_eq!(
        fixture
            .db
            .retire_source(context(), request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let kasumi_engine::VerifiedRetirementResolution::Stopped(proof) = fixture
        .db
        .abort_retirement(context(), request)
        .await
        .unwrap()
    else {
        panic!("drift failure must stop the exact attempt")
    };
    assert_eq!(proof.failure().code, ErrorCode::Conflict);
    fixture.close().await;
}

#[path = "common/retirement_snapshot.rs"]
mod retirement_snapshot;
