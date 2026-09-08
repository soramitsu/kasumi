mod common;
use kasumi_engine::{Database, SecurityAudit};
use kasumi_store::{
    BackupDestination, FilesystemBackupDestination, NodeStore, TenantStore,
    test_utils::LocalKeyProvider,
};
use kasumi_types::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Arc};

fn context() -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        tenant: "checkpoint".into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "backup-proof-test".into(),
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
        let node = NodeStore::open(directory.path().join("node.redb")).unwrap();
        let audit = common::security_audit(node.clone()).await;
        let store = TenantStore::open_fixture(
            node,
            "checkpoint".into(),
            Arc::new(LocalKeyProvider::new([0xD8; 32])),
        )
        .await
        .unwrap();
        let db = kasumi_engine::open_local(
            kasumi_store::test_utils::with_custody(
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
        // Each fixture models a separate node, with its own unchanged admission budget.
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
                        body: serde_json::from_str(
                            r#"{"amount":90071992547409931234567890.123456789}"#,
                        )
                        .unwrap(),
                        expected: Precondition::Absent,
                    }],
                },
            )
            .await
            .unwrap()
    }
    async fn close(&self) {
        self.db.shutdown().await.unwrap();
        self.audit.shutdown().await;
    }
}

#[tokio::test]
async fn checkpoint_binds_actual_generation_complete_graph_keys_and_encrypted_restart() {
    let fixture = Fixture::new().await;
    let first = fixture.write("first").await;
    fixture
        .db
        .archive_history(
            context(),
            ArchiveHistory {
                archive_id: "period-one".into(),
                collection: "journal".into(),
                cutoff_revision: first.revision,
                destination: "approved".into(),
            },
        )
        .await
        .unwrap();
    let first_proof = fixture
        .db
        .backup_checkpoint(
            context(),
            fixture.destination.as_ref(),
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap();
    fixture.store.rotate_data_key().await.unwrap();
    let second = fixture.write("second").await;
    let snapshot = fixture.db.engine().snapshot().unwrap();
    let state = fixture.db.engine().generation().unwrap();
    let revision = state.state.revision;
    let incarnation = state.state.incarnation.clone();
    drop(state);
    let proof = fixture
        .db
        .backup_checkpoint_named(context(), "approved", uuid::Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(proof.tenant(), "checkpoint");
    assert_eq!(proof.source_incarnation(), incarnation);
    assert_eq!(proof.revision(), revision);
    assert!(proof.revision() >= second.revision);
    assert_eq!(proof.resident_sha256(), snapshot.sha256());
    let bytes = fixture
        .destination
        .session_get(
            proof.backup_id(),
            kasumi_store::BackupSessionSlot::Object(proof.backup_id()),
            8 << 20,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        proof.manifest_ciphertext_sha256(),
        hex::encode(Sha256::digest(&bytes))
    );
    assert_ne!(
        first_proof.key_lineage_digest(),
        proof.key_lineage_digest(),
        "rotation changes actual wrapped-key dependencies"
    );
    let verified = fixture
        .db
        .verify_backup_checkpoint_named(context(), "approved", proof.backup_id())
        .await
        .unwrap();
    assert_eq!(verified.checkpoint(), proof.checkpoint());
    // Mutating live state never changes the identity of an already published backup.
    fixture.write("third").await;
    assert_eq!(
        fixture
            .db
            .verify_backup_checkpoint(context(), fixture.destination.as_ref(), proof.backup_id())
            .await
            .unwrap()
            .checkpoint(),
        proof.checkpoint()
    );
    let path = fixture.directory.path().join("node.redb");
    let destination = fixture.destination.clone();
    fixture.close().await;
    let Fixture {
        directory,
        db,
        audit,
        store,
        ..
    } = fixture;
    drop(db);
    drop(audit);
    drop(store);
    let node = NodeStore::open(&path).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let store = TenantStore::open_fixture(
        node,
        "checkpoint".into(),
        Arc::new(LocalKeyProvider::new([0xD8; 32])),
    )
    .await
    .unwrap();
    let db = kasumi_engine::open_local(
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
    assert_eq!(
        db.verify_backup_checkpoint(context(), destination.as_ref(), proof.backup_id())
            .await
            .unwrap()
            .checkpoint(),
        proof.checkpoint()
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await;
    drop(db);
    drop(audit);
    drop(directory);
}

#[tokio::test]
async fn missing_corrupt_resident_or_cold_dependency_and_history_subset_never_yield_proof() {
    let fixture = Fixture::new().await;
    let receipt = fixture.write("cold").await;
    fixture
        .db
        .archive_history(
            context(),
            ArchiveHistory {
                archive_id: "period".into(),
                collection: "journal".into(),
                cutoff_revision: receipt.revision,
                destination: "approved".into(),
            },
        )
        .await
        .unwrap();
    let archive = fixture
        .db
        .engine()
        .generation()
        .unwrap()
        .state
        .history_archives["period"]
        .clone();
    let proof = fixture
        .db
        .backup_checkpoint(
            context(),
            fixture.destination.as_ref(),
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_eq!(
        fixture
            .db
            .verify_backup_checkpoint(
                context(),
                fixture.destination.as_ref(),
                uuid::Uuid::parse_str(&archive.manifest_object_id).unwrap()
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    let manifest = fixture
        .destination
        .session_get(
            proof.backup_id(),
            kasumi_store::BackupSessionSlot::Object(proof.backup_id()),
            8 << 20,
        )
        .await
        .unwrap();
    let manifest = manifest.unwrap();
    let contents = fixture
        .store
        .decrypt_backup_object(&manifest, proof.backup_id(), 4 << 20)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&contents.snapshot).unwrap();
    let page_id = uuid::Uuid::parse_str(value["last_page"]["object_id"].as_str().unwrap()).unwrap();
    let encrypted_page = fixture
        .destination
        .session_get(
            proof.backup_id(),
            kasumi_store::BackupSessionSlot::Object(page_id),
            8 << 20,
        )
        .await
        .unwrap()
        .unwrap();
    let page = fixture
        .store
        .decrypt_backup_object(&encrypted_page, page_id, 4 << 20)
        .await
        .unwrap();
    let page: serde_json::Value = serde_json::from_slice(&page.snapshot).unwrap();
    let resident = page["chunks"][0]["object_id"].as_str().unwrap();
    for object in [resident, archive.manifest.chunks[0].object_id.as_str()] {
        let path = fixture
            .directory
            .path()
            .join("backups/sessions")
            .join(proof.backup_id().to_string())
            .join("objects")
            .join(format!("{object}.kasumi"));
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            fixture
                .db
                .verify_backup_checkpoint(
                    context(),
                    fixture.destination.as_ref(),
                    proof.backup_id()
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unavailable
        );
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(&path, corrupt).unwrap();
        assert_eq!(
            fixture
                .db
                .verify_backup_checkpoint(
                    context(),
                    fixture.destination.as_ref(),
                    proof.backup_id()
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::Corruption
        );
        std::fs::write(&path, bytes).unwrap();
    }
    assert_eq!(
        fixture
            .db
            .verify_backup_checkpoint(context(), fixture.destination.as_ref(), proof.backup_id())
            .await
            .unwrap()
            .checkpoint(),
        proof.checkpoint()
    );
    fixture.close().await;
}

struct PausedRead {
    destination: Arc<FilesystemBackupDestination>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl BackupDestination for PausedRead {
    async fn session_put(
        &self,
        session: uuid::Uuid,
        slot: kasumi_store::BackupSessionSlot,
        bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        kasumi_store::BackupDestination::session_put(
            self.destination.as_ref(),
            session,
            slot,
            bytes,
        )
        .await
    }
    async fn session_get(
        &self,
        session: uuid::Uuid,
        slot: kasumi_store::BackupSessionSlot,
        limit: usize,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        if matches!(slot, kasumi_store::BackupSessionSlot::Object(_)) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        kasumi_store::BackupDestination::session_get(
            self.destination.as_ref(),
            session,
            slot,
            limit,
        )
        .await
    }

    async fn put(&self, id: uuid::Uuid, bytes: Vec<u8>) -> anyhow::Result<()> {
        self.destination.put(id, bytes).await
    }
    async fn get(&self, id: uuid::Uuid, limit: usize) -> anyhow::Result<Vec<u8>> {
        self.entered.notify_one();
        self.release.notified().await;
        self.destination.get(id, limit).await
    }
}
#[tokio::test]
async fn verification_requires_current_global_admin_and_rechecks_policy_during_readback() {
    let fixture = Fixture::new().await;
    let proof = fixture
        .db
        .backup_checkpoint(
            context(),
            fixture.destination.as_ref(),
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap();
    let mut read_only = context();
    read_only.scopes = BTreeSet::from([Action::Read]);
    assert_eq!(
        fixture
            .db
            .verify_backup_checkpoint(read_only, fixture.destination.as_ref(), proof.backup_id())
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    let fence = fixture
        .db
        .backup_checkpoint_response_fence(&context(), &proof)
        .unwrap();
    let paused = Arc::new(PausedRead {
        destination: fixture.destination.clone(),
        entered: Default::default(),
        release: Default::default(),
    });
    let task = tokio::spawn({
        let db = fixture.db.clone();
        let paused = paused.clone();
        async move {
            db.verify_backup_checkpoint(context(), paused.as_ref(), proof.backup_id())
                .await
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), paused.entered.notified())
        .await
        .unwrap();
    fixture
        .db
        .administer(
            context(),
            Operation::SetPolicy(Policy {
                grants: vec![Grant {
                    principal: "replacement".into(),
                    collection: None,
                    actions: BTreeSet::from([Action::Admin]),
                }],
                strict_read_audit: true,
            }),
        )
        .await
        .unwrap();
    assert_eq!(fence.check().unwrap_err().code, ErrorCode::Conflict);
    drop(fence);
    paused.release.notify_one();
    assert!(matches!(
        task.await.unwrap().unwrap_err().code,
        ErrorCode::Conflict | ErrorCode::Forbidden
    ));
    fixture.close().await;
}

#[tokio::test]
async fn shutdown_cancels_pending_checkpoint_read_and_releases_database_work() {
    let fixture = Fixture::new().await;
    let proof = fixture
        .db
        .backup_checkpoint(
            context(),
            fixture.destination.as_ref(),
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap();
    let paused = Arc::new(PausedRead {
        destination: fixture.destination.clone(),
        entered: Default::default(),
        release: Default::default(),
    });
    let task = tokio::spawn({
        let db = fixture.db.clone();
        let paused = paused.clone();
        async move {
            db.verify_backup_checkpoint(context(), paused.as_ref(), proof.backup_id())
                .await
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), paused.entered.notified())
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), fixture.db.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(task.await.unwrap().is_err());
    fixture.audit.shutdown().await;
}

struct SessionFault {
    inner: Arc<FilesystemBackupDestination>,
    fail_objects: bool,
    fail_outcome: bool,
    lose_outcome_ack: bool,
}
#[async_trait::async_trait]
impl BackupDestination for SessionFault {
    async fn put(&self, id: uuid::Uuid, bytes: Vec<u8>) -> anyhow::Result<()> {
        self.inner.put(id, bytes).await
    }
    async fn get(&self, id: uuid::Uuid, limit: usize) -> anyhow::Result<Vec<u8>> {
        self.inner.get(id, limit).await
    }
    async fn session_get(
        &self,
        session: uuid::Uuid,
        slot: kasumi_store::BackupSessionSlot,
        limit: usize,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.inner.session_get(session, slot, limit).await
    }
    async fn session_put(
        &self,
        session: uuid::Uuid,
        slot: kasumi_store::BackupSessionSlot,
        bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        if (self.fail_objects && matches!(slot, kasumi_store::BackupSessionSlot::Object(_)))
            || (self.fail_outcome && matches!(slot, kasumi_store::BackupSessionSlot::Outcome))
        {
            anyhow::bail!("injected publication failure");
        }
        self.inner.session_put(session, slot, bytes).await?;
        if self.lose_outcome_ack && matches!(slot, kasumi_store::BackupSessionSlot::Outcome) {
            anyhow::bail!("completion committed but acknowledgement lost");
        }
        Ok(())
    }
}

#[tokio::test]
async fn durable_session_resolves_lost_ack_and_never_reclaims_completed_graph() {
    let fixture = Fixture::new().await;
    fixture.write("before-backup").await;
    let session = uuid::Uuid::new_v4();
    let fault = SessionFault {
        inner: fixture.destination.clone(),
        fail_objects: false,
        fail_outcome: false,
        lose_outcome_ack: true,
    };
    let proof = fixture
        .db
        .backup_checkpoint(context(), &fault, session)
        .await
        .unwrap();
    fixture.write("after-backup").await;
    let retry = fixture
        .db
        .backup_checkpoint_named(context(), "approved", session)
        .await
        .unwrap();
    assert_eq!(proof.checkpoint(), retry.checkpoint());
    let status = fixture
        .db
        .abort_backup_session(
            context(),
            AbortBackupSession {
                destination: "approved".into(),
                session_id: session,
                reason: "operator reconciliation".into(),
            },
        )
        .await
        .unwrap();
    assert!(
        matches!(status.outcome, Some(BackupSessionOutcome::Complete { checkpoint, .. }) if checkpoint == *proof.checkpoint())
    );
    let error = fixture
        .db
        .cleanup_backup_session(
            context(),
            CleanupBackupSession {
                destination: "approved".into(),
                session_id: session,
                max_objects: 1,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    fixture
        .db
        .verify_backup_checkpoint_named(context(), "approved", session)
        .await
        .unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn aborted_session_cleanup_is_bounded_and_catches_late_uploads() {
    let fixture = Fixture::new().await;
    let session = uuid::Uuid::new_v4();
    let fault = SessionFault {
        inner: fixture.destination.clone(),
        fail_objects: true,
        fail_outcome: false,
        lose_outcome_ack: false,
    };
    let error = fixture
        .db
        .backup_checkpoint(context(), &fault, session)
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::UnknownOutcome);
    let status = fixture
        .db
        .abort_backup_session(
            context(),
            AbortBackupSession {
                destination: "approved".into(),
                session_id: session,
                reason: "failed upload".into(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        status.outcome,
        Some(BackupSessionOutcome::Aborted { .. })
    ));
    for _ in 0..3 {
        fixture
            .destination
            .session_put(
                session,
                kasumi_store::BackupSessionSlot::Object(uuid::Uuid::new_v4()),
                vec![12; 100],
            )
            .await
            .unwrap();
    }
    let request = CleanupBackupSession {
        destination: "approved".into(),
        session_id: session,
        max_objects: 2,
    };
    let first = fixture
        .db
        .cleanup_backup_session(context(), request.clone())
        .await
        .unwrap();
    assert_eq!(first.deleted_objects, 2);
    assert!(first.more_objects_observed);
    assert_eq!(
        fixture
            .db
            .cleanup_backup_session(context(), request.clone())
            .await
            .unwrap()
            .deleted_objects,
        1
    );
    fixture
        .destination
        .session_put(
            session,
            kasumi_store::BackupSessionSlot::Object(uuid::Uuid::new_v4()),
            vec![13; 100],
        )
        .await
        .unwrap();
    assert_eq!(
        fixture
            .db
            .cleanup_backup_session(context(), request.clone())
            .await
            .unwrap()
            .deleted_objects,
        1
    );
    assert_eq!(
        fixture
            .db
            .cleanup_backup_session(context(), request)
            .await
            .unwrap()
            .deleted_objects,
        0
    );
    let status = fixture
        .db
        .backup_session_status(
            context(),
            BackupSessionRequest {
                destination: "approved".into(),
                session_id: session,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        status.outcome,
        Some(BackupSessionOutcome::Aborted { .. })
    ));
    assert_eq!(
        fixture
            .db
            .backup_checkpoint_named(context(), "approved", session)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    fixture.close().await;
}

#[tokio::test]
async fn abort_resolves_published_root_before_considering_cleanup() {
    let fixture = Fixture::new().await;
    let session = uuid::Uuid::new_v4();
    let fault = SessionFault {
        inner: fixture.destination.clone(),
        fail_objects: false,
        fail_outcome: true,
        lose_outcome_ack: false,
    };
    assert_eq!(
        fixture
            .db
            .backup_checkpoint(context(), &fault, session)
            .await
            .unwrap_err()
            .code,
        ErrorCode::UnknownOutcome
    );
    assert_eq!(
        fixture
            .db
            .verify_backup_checkpoint_named(context(), "approved", session)
            .await
            .unwrap_err()
            .code,
        ErrorCode::UnknownOutcome
    );
    let status = fixture
        .db
        .abort_backup_session(
            context(),
            AbortBackupSession {
                destination: "approved".into(),
                session_id: session,
                reason: "resolve interrupted completion".into(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        status.outcome,
        Some(BackupSessionOutcome::Complete { .. })
    ));
    fixture
        .db
        .verify_backup_checkpoint_named(context(), "approved", session)
        .await
        .unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn local_restore_binds_exact_source_purpose_even_without_cold_archives() {
    let fixture = Fixture::new().await;
    let proof = fixture
        .db
        .backup_checkpoint_named(context(), "approved", uuid::Uuid::new_v4())
        .await
        .unwrap();
    let node = NodeStore::open(fixture.directory.path().join("restore.redb")).unwrap();
    let target = TenantStore::open_fixture(
        node,
        "checkpoint".into(),
        Arc::new(LocalKeyProvider::new([0xD8; 32])),
    )
    .await
    .unwrap();
    let domains =
        kasumi_store::test_utils::with_custody(target, Arc::new(LocalKeyProvider::new([241; 32])))
            .await
            .unwrap();
    let source = kasumi_engine::RestoreSource {
        destination_alias: "approved".into(),
        destination: fixture.destination.clone(),
        keys: Arc::new(LocalKeyProvider::new([0xD8; 32])),
        timeout_ms: 60_000,
    };
    let request =
        common::local_restore_request(context(), proof.checkpoint(), uuid::Uuid::new_v4());
    let mut wrong =
        common::local_restore_request(context(), proof.checkpoint(), request.target_incarnation);
    wrong.source_purpose = kasumi_store::StoragePurpose::Standalone {
        installation_id: uuid::Uuid::new_v4(),
        tenant: "checkpoint".into(),
        incarnation: uuid::Uuid::parse_str(proof.source_incarnation()).unwrap(),
    };
    let error = kasumi_engine::restore_local(
        &source,
        domains.clone(),
        wrong,
        kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
        fixture.audit.clone(),
    )
    .await
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("local backup source purpose differs"));
    let restored = kasumi_engine::restore_local(
        &source,
        domains,
        request,
        kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
        fixture.audit.clone(),
    )
    .await
    .unwrap();
    restored.shutdown().await.unwrap();
    fixture.close().await;
}
