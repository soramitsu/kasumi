use kasumi_engine::test_utils::SnapshotFixture;
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captured_and_historical_backup_verification_fit_fixed_production_workspace() {
    let maximum = 384 << 20;
    let fixture = Fixture::with_admission(
        Limits {
            max_batch_bytes: 1 << 20,
            max_result_bytes: 1 << 20,
            ..Limits::default()
        },
        kasumi_engine::admission::AdmissionConfig {
            max_inflight_bytes: Some(maximum),
            ..Default::default()
        },
        true,
    )
    .await;
    for index in 0..40 {
        let id = format!("large-{index}");
        fixture
            .db
            .mutate(
                context(),
                MutationBatch {
                    idempotency_key: id.clone(),
                    read_set: vec![],
                    operations: vec![Mutation::Put {
                        collection: "journal".into(),
                        id,
                        body: json!({"payload": "x".repeat(768 << 10)}),
                        expected: Precondition::Absent,
                    }],
                },
            )
            .await
            .unwrap();
    }
    let resident = fixture.db.engine().fixture_snapshot().unwrap().len();
    // Both production archival lanes and the service ledger are installed.
    // The former proportional verifier cannot fit alongside those same reserves.
    assert!(fixture.db.audit_maintenance_status().is_some());
    assert!(resident * 3 + (256 << 20) > maximum);
    let proof = fixture
        .db
        .backup_checkpoint_named(context(), "approved", uuid::Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(proof.checkpoint().tenant, "checkpoint");
    let independently_verified = fixture
        .db
        .verify_backup_checkpoint_named(context(), "approved", proof.checkpoint().backup_id)
        .await
        .unwrap();
    assert_eq!(independently_verified.checkpoint(), proof.checkpoint());
    assert_eq!(
        fixture.audit.admission().snapshot().reserved_bytes,
        3 * AuditRetentionBudget::MAINTENANCE_BYTES
    );
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_hands_off_verified_workspace_with_production_and_destination_reserves() {
    let fixture = Fixture::with_admission(
        Limits::default(),
        kasumi_engine::admission::AdmissionConfig {
            max_inflight_bytes: Some(512 << 20),
            ..Default::default()
        },
        true,
    )
    .await;
    fixture.write("retained").await;
    let checkpoint = fixture
        .db
        .backup_checkpoint_named(context(), "approved", uuid::Uuid::new_v4())
        .await
        .unwrap()
        .checkpoint()
        .clone();
    let admission = fixture.audit.admission().clone();
    assert!(fixture.db.audit_maintenance_status().is_some());
    assert_eq!(admission.snapshot().reserved_bytes, 192 << 20);
    // Keep the real service/tenant maintenance pools plus the native destination
    // charge installed throughout verification, materialization and publication.
    let destination_workspace = admission.reserve(128 << 20, None).unwrap();
    let previous_verification = admission.reserve(128 << 20, None).unwrap();
    assert!(
        admission.reserve((64 << 20) + 1, None).is_err(),
        "the previous additive materialization strategy must not fit"
    );
    drop(previous_verification);
    let node = NodeStore::create_new(
        fixture.directory.path().join("restore-budget.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        fixture.store.scratch_disk().clone(),
    )
    .unwrap();
    let target = TenantStore::initialize_catalog_fixture(
        node,
        "checkpoint".into(),
        Arc::new(LocalKeyProvider::new([0xD8; 32])),
    )
    .await
    .unwrap();
    let domains = kasumi_store::test_utils::initialize_custody_fixture(
        target.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await
    .unwrap();
    let source = kasumi_engine::RestoreSource {
        destination_alias: "approved".into(),
        destination: fixture.destination.clone(),
        keys: Arc::new(LocalKeyProvider::new([0xD8; 32])),
        timeout_ms: 60_000,
    };
    let restored = kasumi_engine::restore_local(
        &source,
        domains.clone(),
        common::local_restore_request(context(), &checkpoint, uuid::Uuid::new_v4()),
        admission.clone(),
        fixture.audit.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        restored.engine().generation().unwrap().state.document_count,
        1
    );
    assert_eq!(admission.snapshot().reserved_bytes, 320 << 20);
    restored.shutdown().await.unwrap();
    drop(restored);
    drop(domains);
    drop(target);
    let node = NodeStore::open_existing(
        fixture.directory.path().join("restore-budget.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        fixture.store.scratch_disk().clone(),
    )
    .unwrap();
    let target = TenantStore::initialize_catalog_fixture(
        node,
        "checkpoint".into(),
        Arc::new(LocalKeyProvider::new([0xD8; 32])),
    )
    .await
    .unwrap();
    let domains = kasumi_store::test_utils::initialize_custody_fixture(
        target,
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await
    .unwrap();
    let reopened =
        kasumi_engine::open_local(domains, policy(), Limits::default(), fixture.audit.clone())
            .await
            .unwrap();
    assert_eq!(
        reopened.engine().generation().unwrap().state.document_count,
        1
    );
    assert_eq!(admission.snapshot().reserved_bytes, 320 << 20);
    reopened.shutdown().await.unwrap();
    drop(destination_workspace);
    assert_eq!(admission.snapshot().reserved_bytes, 192 << 20);
    fixture.close().await;
}

#[tokio::test]
async fn cancelled_restore_publication_keeps_storage_and_workspace_until_write_drains() {
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };
    type Pause = (
        tokio::sync::oneshot::Sender<()>,
        std::sync::mpsc::Receiver<()>,
    );
    #[derive(Clone, Debug)]
    struct PausedBackend {
        inner: kasumi_store::test_utils::FaultBackend,
        pause: Arc<Mutex<Option<Pause>>>,
        blocked: Arc<AtomicBool>,
    }
    impl redb::StorageBackend for PausedBackend {
        fn len(&self) -> std::io::Result<u64> {
            self.inner.len()
        }
        fn read(&self, offset: u64, bytes: &mut [u8]) -> std::io::Result<()> {
            self.inner.read(offset, bytes)
        }
        fn set_len(&self, length: u64) -> std::io::Result<()> {
            self.inner.set_len(length)
        }
        fn sync_data(&self) -> std::io::Result<()> {
            self.inner.sync_data()
        }
        fn write(&self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
            let pause = self.pause.lock().unwrap().take();
            if let Some((started, release)) = pause {
                self.blocked.store(true, Ordering::SeqCst);
                let _ = started.send(());
                // A regression to synchronous runtime I/O must fail instead of
                // hanging the test process indefinitely.
                let result = release.recv_timeout(std::time::Duration::from_secs(5));
                self.blocked.store(false, Ordering::SeqCst);
                result.map_err(std::io::Error::other)?;
            }
            self.inner.write(offset, bytes)
        }
    }
    let fixture = Fixture::with_admission(Limits::default(), Default::default(), true).await;
    fixture.write("retained").await;
    let checkpoint = fixture
        .db
        .backup_checkpoint_named(context(), "approved", uuid::Uuid::new_v4())
        .await
        .unwrap()
        .checkpoint()
        .clone();
    let admission = fixture.audit.admission().clone();
    assert_eq!(admission.snapshot().reserved_bytes, 192 << 20);
    let backend = PausedBackend {
        inner: kasumi_store::test_utils::FaultBackend::new(),
        pause: Arc::new(Mutex::new(None)),
        blocked: Arc::new(AtomicBool::new(false)),
    };
    let node = NodeStore::open_with_backend(backend.clone(), fixture.store.scratch_disk().clone())
        .unwrap();
    let target = TenantStore::initialize_catalog_fixture(
        node,
        "checkpoint".into(),
        Arc::new(LocalKeyProvider::new([0xD8; 32])),
    )
    .await
    .unwrap();
    let weak = Arc::downgrade(&target);
    let domains = kasumi_store::test_utils::initialize_custody_fixture(
        target,
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await
    .unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *backend.pause.lock().unwrap() = Some((started_tx, release_rx));
    let source = kasumi_engine::RestoreSource {
        destination_alias: "approved".into(),
        destination: fixture.destination.clone(),
        keys: Arc::new(LocalKeyProvider::new([0xD8; 32])),
        timeout_ms: 30_000,
    };
    let audit = fixture.audit.clone();
    let owned_admission = admission.clone();
    let request = common::local_restore_request(context(), &checkpoint, uuid::Uuid::new_v4());
    let task = tokio::spawn(async move {
        kasumi_engine::restore_local(&source, domains, request, owned_admission, audit).await
    });
    started_rx.await.unwrap();
    assert!(
        backend.blocked.load(Ordering::SeqCst),
        "publication blocked the async executor"
    );
    // This is a single-thread runtime; this timer can run only if the storage
    // write belongs to a separate owned worker.
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(backend.blocked.load(Ordering::SeqCst));
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert!(weak.upgrade().is_some());
    assert!(admission.snapshot().reserved_bytes > 192 << 20);
    release_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while weak.upgrade().is_some() || admission.snapshot().reserved_bytes != 192 << 20 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Cancellation before the final manifest cannot publish a partial genesis.
    let node = NodeStore::open_with_backend(backend, fixture.store.scratch_disk().clone()).unwrap();
    let reopened = TenantStore::open_existing_fixture(
        node,
        "checkpoint".into(),
        Arc::new(LocalKeyProvider::new([0xD8; 32])),
    )
    .await
    .unwrap();
    assert!(
        reopened
            .get("engine.bootstrap", b"manifest")
            .unwrap()
            .is_none()
    );
    reopened.shutdown().await.unwrap();
    fixture.close().await;
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
        Self::with_limits(Limits::default()).await
    }
    async fn with_limits(limits: Limits) -> Self {
        Self::with_admission(limits, Default::default(), false).await
    }
    async fn with_admission(
        limits: Limits,
        config: kasumi_engine::admission::AdmissionConfig,
        production: bool,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let node = NodeStore::create_new(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let admission = kasumi_engine::admission::NodeAdmission::new(config).unwrap();
        let audit = common::security_audit_with_admission(node.clone(), admission.clone()).await;
        let store = TenantStore::initialize_catalog_fixture(
            node,
            "checkpoint".into(),
            Arc::new(LocalKeyProvider::new([0xD8; 32])),
        )
        .await
        .unwrap();
        let stores = kasumi_store::test_utils::initialize_custody_fixture(
            store.clone(),
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap();
        let db = if production {
            kasumi_engine::open_local(stores, policy(), limits, audit.clone())
                .await
                .unwrap()
        } else {
            kasumi_engine::test_utils::open_fixture(stores, policy(), limits, audit.clone())
                .await
                .unwrap()
        };
        // Each fixture models a separate node, with its own unchanged admission budget.
        db.install_admission(admission).unwrap();
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
        self.audit.shutdown().await.unwrap();
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
    let snapshot = fixture.db.engine().fixture_snapshot().unwrap();
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
    let node = NodeStore::open_existing(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let audit = common::existing_security_audit(node.clone()).await;
    let store = TenantStore::open_existing_fixture(
        node,
        "checkpoint".into(),
        Arc::new(LocalKeyProvider::new([0xD8; 32])),
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
    assert_eq!(
        db.verify_backup_checkpoint(context(), destination.as_ref(), proof.backup_id())
            .await
            .unwrap()
            .checkpoint(),
        proof.checkpoint()
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
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
    fixture.audit.shutdown().await.unwrap();
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
    let node = NodeStore::create_new(
        fixture.directory.path().join("restore.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let target = TenantStore::initialize_catalog_fixture(
        node,
        "checkpoint".into(),
        Arc::new(LocalKeyProvider::new([0xD8; 32])),
    )
    .await
    .unwrap();
    let domains = kasumi_store::test_utils::initialize_custody_fixture(
        target,
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
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
        fixture.audit.admission().clone(),
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
        fixture.audit.admission().clone(),
        fixture.audit.clone(),
    )
    .await
    .unwrap();
    restored.shutdown().await.unwrap();
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archived_audit_backup_is_self_contained_and_source_unavailable_restore_preserves_exact_chain()
 {
    let fixture = Fixture::with_limits(Limits {
        audit_retention: AuditRetentionBudget {
            hot_bytes: 128 << 10,
            archive_bytes: 8 << 20,
        },
        ..Limits::default()
    })
    .await;
    for round in 0..2 {
        while {
            let generation = fixture.db.engine().generation().unwrap();
            generation.state.audit_retention.hot_bytes
                < generation.state.limits.audit_retention.starts_at()
        } {
            let revision = fixture.db.engine().generation().unwrap().state.revision;
            let command = Command {
                context: context(),
                timestamp_ms: 1_000,
                operation: Operation::Audit(AuditEvent {
                    event_id: format!("{round}/{revision}/{}", "x".repeat(2_000)),
                    principal: "owner".into(),
                    action: "read".into(),
                    request_id: context().request_id,
                    timestamp_ms: 1_000,
                    data_revision: Some(revision),
                    outcome: "authorized_release".into(),
                    collection: None,
                }),
            };
            let result = fixture
                .db
                .raft_group()
                .write(serde_json::to_vec(&command).unwrap())
                .await
                .unwrap();
            serde_json::from_slice::<Result<WriteReceipt>>(&result)
                .unwrap()
                .unwrap();
        }
        let engine = fixture.db.engine().clone();
        let command = tokio::task::spawn_blocking(move || engine.prepare_audit_prune())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let result = fixture.db.raft_group().write(command).await.unwrap();
        serde_json::from_slice::<Result<()>>(&result)
            .unwrap()
            .unwrap();
    }
    let retained = fixture
        .db
        .engine()
        .generation()
        .unwrap()
        .state
        .audit_retention
        .clone();
    assert_eq!(retained.archive_segments, 2);
    let proof = fixture
        .db
        .backup_checkpoint_named(context(), "approved", uuid::Uuid::new_v4())
        .await
        .unwrap();
    let head = retained.archive_head.as_ref().unwrap();
    let objects =
        kasumi_store::BackupSessionObjects::new(fixture.destination.as_ref(), proof.backup_id())
            .unwrap();
    let ciphertext = objects
        .get(head.object.object_id, MAX_AUDIT_SEGMENT_BYTES)
        .await
        .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&ciphertext)),
        head.object.ciphertext_sha256
    );
    let dependency_path = fixture
        .directory
        .path()
        .join("backups")
        .join("sessions")
        .join(proof.backup_id().to_string())
        .join("objects")
        .join(format!("{}.kasumi", head.object.object_id));
    std::fs::remove_file(&dependency_path).unwrap();
    assert!(
        fixture
            .db
            .verify_backup_checkpoint_named(context(), "approved", proof.backup_id())
            .await
            .is_err()
    );
    // Restore must neither consult a live source quorum nor its local cache.
    fixture.close().await;
    let target_directory = tempfile::tempdir().unwrap();
    let node = NodeStore::create_new(
        target_directory.path().join("target.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let target_audit = common::security_audit(node.clone()).await;
    let target = TenantStore::initialize_catalog_fixture(
        node,
        "checkpoint".into(),
        Arc::new(LocalKeyProvider::new([0xD8; 32])),
    )
    .await
    .unwrap();
    let domains = kasumi_store::test_utils::initialize_custody_fixture(
        target.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await
    .unwrap();
    let source = kasumi_engine::RestoreSource {
        destination_alias: "approved".into(),
        destination: fixture.destination.clone(),
        keys: Arc::new(LocalKeyProvider::new([0xD8; 32])),
        timeout_ms: 60_000,
    };
    let target_incarnation = uuid::Uuid::new_v4();
    assert!(
        kasumi_engine::restore_local(
            &source,
            domains.clone(),
            common::local_restore_request(context(), proof.checkpoint(), target_incarnation),
            target_audit.admission().clone(),
            target_audit.clone()
        )
        .await
        .is_err()
    );
    assert!(target.scan("engine.bootstrap").unwrap().is_empty());
    // A valid immutable re-publication resolves the missing dependency; it does
    // not alter the permanent completed outcome or original source purpose.
    let mut corrupt = ciphertext.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    objects.put(head.object.object_id, corrupt).await.unwrap();
    assert!(
        kasumi_engine::restore_local(
            &source,
            domains.clone(),
            common::local_restore_request(context(), proof.checkpoint(), target_incarnation),
            target_audit.admission().clone(),
            target_audit.clone(),
        )
        .await
        .is_err()
    );
    assert!(target.scan("engine.bootstrap").unwrap().is_empty());
    std::fs::remove_file(&dependency_path).unwrap();
    objects
        .put(head.object.object_id, ciphertext.clone())
        .await
        .unwrap();
    // Source verification alone is insufficient: an independently installed
    // target provider must also retain every original historical archive key.
    let wrong_directory = tempfile::tempdir().unwrap();
    let wrong_node = NodeStore::create_new(
        wrong_directory.path().join("wrong.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let wrong_audit = common::security_audit(wrong_node.clone()).await;
    let wrong_store = TenantStore::initialize_catalog_fixture(
        wrong_node,
        "checkpoint".into(),
        Arc::new(LocalKeyProvider::new([0x47; 32])),
    )
    .await
    .unwrap();
    let wrong_domains = kasumi_store::test_utils::initialize_custody_fixture(
        wrong_store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await
    .unwrap();
    assert!(
        kasumi_engine::restore_local(
            &source,
            wrong_domains,
            common::local_restore_request(context(), proof.checkpoint(), uuid::Uuid::new_v4()),
            wrong_audit.admission().clone(),
            wrong_audit.clone(),
        )
        .await
        .is_err()
    );
    assert!(wrong_store.scan("engine.bootstrap").unwrap().is_empty());
    wrong_store.shutdown().await.unwrap();
    wrong_audit.shutdown().await.unwrap();
    let restored = kasumi_engine::restore_local(
        &source,
        domains,
        common::local_restore_request(context(), proof.checkpoint(), target_incarnation),
        target_audit.admission().clone(),
        target_audit.clone(),
    )
    .await
    .unwrap();
    let after = restored
        .engine()
        .generation()
        .unwrap()
        .state
        .audit_retention
        .clone();
    assert_eq!(after.archive_head, retained.archive_head);
    assert_eq!(after.archive_segments, retained.archive_segments);
    assert_eq!(
        target
            .tenant_audit_archive()
            .unwrap()
            .cache()
            .read_blocking(&head.object)
            .unwrap(),
        ciphertext
    );
    let copied = restored
        .backup_checkpoint_named(context(), "approved", uuid::Uuid::new_v4())
        .await
        .unwrap();
    restored
        .verify_backup_checkpoint_named(context(), "approved", copied.backup_id())
        .await
        .unwrap();
    restored.shutdown().await.unwrap();
    target_audit.shutdown().await.unwrap();
    drop(restored);
    drop(target);
    drop(target_audit);
    let cache_path = target_directory
        .path()
        .join("tenant-audit-archives")
        .join(format!("{}.audit", head.object.object_id));
    std::fs::remove_file(&cache_path).unwrap();
    let node = NodeStore::open_existing(
        target_directory.path().join("target.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let reopened_audit = common::existing_security_audit(node.clone()).await;
    let reopened_store = TenantStore::open_existing_fixture(
        node,
        "checkpoint".into(),
        Arc::new(LocalKeyProvider::new([0xD8; 32])),
    )
    .await
    .unwrap();
    let reopened_domains = kasumi_store::test_utils::open_existing_custody_fixture(
        reopened_store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await
    .unwrap();
    assert!(
        kasumi_engine::open_local(
            reopened_domains.clone(),
            policy(),
            Limits::default(),
            reopened_audit.clone()
        )
        .await
        .is_err(),
        "missing original bootstrap dependency must prevent serving after restart"
    );
    reopened_store
        .tenant_audit_archive()
        .unwrap()
        .cache()
        .publish_blocking(&kasumi_store::PreparedAuditSegment {
            reference: head.clone(),
            ciphertext,
        })
        .unwrap();
    let reopened = kasumi_engine::open_local(
        reopened_domains,
        policy(),
        Limits::default(),
        reopened_audit.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        reopened
            .engine()
            .generation()
            .unwrap()
            .state
            .audit_retention
            .archive_head,
        retained.archive_head
    );
    let portable = reopened
        .engine()
        .snapshot(
            kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
            60_000,
        )
        .await
        .unwrap();
    let prepared = reopened
        .engine()
        .prepare_snapshot_restore(
            portable,
            kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
            60_000,
        )
        .await
        .unwrap();
    assert_eq!(prepared.incarnation(), target_incarnation.to_string());
    reopened.shutdown().await.unwrap();
    reopened_audit.shutdown().await.unwrap();
}
