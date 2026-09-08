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
        .backup_checkpoint(context(), fixture.destination.as_ref())
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
        .backup_checkpoint_named(context(), "approved")
        .await
        .unwrap();
    assert_eq!(proof.tenant(), "checkpoint");
    assert_eq!(proof.source_incarnation(), incarnation);
    assert_eq!(proof.revision(), revision);
    assert!(proof.revision() >= second.revision);
    assert_eq!(
        proof.resident_sha256(),
        hex::encode(Sha256::digest(&snapshot))
    );
    let bytes = fixture
        .destination
        .get(proof.backup_id(), 8 << 20)
        .await
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
        .backup_checkpoint(context(), fixture.destination.as_ref())
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
        ErrorCode::Corruption
    );
    let manifest = fixture
        .destination
        .get(proof.backup_id(), 8 << 20)
        .await
        .unwrap();
    let contents = fixture
        .store
        .decrypt_backup_object(&manifest, proof.backup_id(), 4 << 20)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&contents.snapshot).unwrap();
    let page_id = uuid::Uuid::parse_str(value["last_page"]["object_id"].as_str().unwrap()).unwrap();
    let encrypted_page = fixture.destination.get(page_id, 8 << 20).await.unwrap();
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
            .join("backups")
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
        .backup_checkpoint(context(), fixture.destination.as_ref())
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
        .backup_checkpoint(context(), fixture.destination.as_ref())
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
