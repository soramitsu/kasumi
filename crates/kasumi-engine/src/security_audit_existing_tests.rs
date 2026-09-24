//! Existing-only audit admission using actual private file keyrings and node files.
use super::*;
use crate::admission::NodeAdmission;
use kasumi_store::{FileKeyProvider, StorageAccess, private_files};
use std::path::PathBuf;
use uuid::Uuid;

struct Installation {
    path: PathBuf,
    keys: PathBuf,
    id: Uuid,
    storage: crate::test_utils::FixtureStorage,
    metadata_bytes: u64,
    admission: Arc<NodeAdmission>,
    _directory: tempfile::TempDir,
}
impl Installation {
    fn new() -> Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let private = directory.path().join("installation");
        private_files::create_directory(&private)?;
        let keys = private.join("audit-keys.json");
        FileKeyProvider::initialize(&keys, "service-audit")?;
        let (persistent_config, scratch_config) =
            crate::test_utils::fixture_disk_configs(directory.path())?;
        // The original fixed 2 GiB source resolves Default to a 256 MiB total.
        // Add only the new physical metadata; do not resolve against host RAM.
        let config = crate::admission::AdmissionConfig {
            max_inflight_bytes: Some(
                (256_u64 << 20)
                    .checked_add(crate::test_utils::isolated_disk_metadata_bytes(
                        &persistent_config,
                        &scratch_config,
                    )?)
                    .ok_or_else(|| anyhow::anyhow!("fixture metadata budget overflow"))?,
            ),
            ..Default::default()
        };
        let admission = crate::admission::NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
        let storage = crate::test_utils::FixtureStorage::with_admission(
            &persistent_config,
            &scratch_config,
            admission.clone(),
        )?;
        let metadata_bytes =
            crate::test_utils::isolated_disk_metadata_bytes(&persistent_config, &scratch_config)?;
        Ok(Self {
            path: directory.path().join("persistent/node.redb"),
            _directory: directory,
            keys,
            id: Uuid::new_v4(),
            storage,
            metadata_bytes,
            admission,
        })
    }
    async fn store(&self, create: bool) -> Result<Arc<TenantStore>> {
        let node = if create {
            self.storage.create_new(&self.path, self.id)?
        } else {
            self.storage.open_existing(&self.path, self.id)?
        };
        let provider = Arc::new(FileKeyProvider::open(&self.keys)?);
        if create {
            TenantStore::initialize_catalog(
                node,
                SECURITY_TENANT.into(),
                provider,
                StorageAccess::security_audit(),
            )
            .await
        } else {
            TenantStore::open_existing(
                node,
                SECURITY_TENANT.into(),
                provider,
                StorageAccess::security_audit(),
            )
            .await
        }
    }
    fn initialize(&self, store: Arc<TenantStore>) -> Result<Arc<SecurityAudit>> {
        SecurityAudit::initialize(store, Default::default(), self.admission.clone())
    }
    fn open(&self, store: Arc<TenantStore>) -> Result<Arc<SecurityAudit>> {
        SecurityAudit::open(store, Default::default(), self.admission.clone())
    }
}
fn event() -> SecurityEvent {
    SecurityEvent {
        kind: SecurityEventKind::NodeStarted,
        principal: None,
        tenant: None,
        request_id: "strict-audit-reopen".into(),
        outcome: SecurityOutcome::Succeeded,
    }
}
type LogicalRecords = Vec<(Vec<u8>, Vec<u8>)>;

fn retained(store: &TenantStore) -> Result<Vec<LogicalRecords>> {
    [
        "security.audit.meta",
        "security.audit",
        "security.audit.archives",
    ]
    .into_iter()
    .map(|namespace| store.scan(namespace))
    .collect()
}
async fn close(audit: Arc<SecurityAudit>, store: Arc<TenantStore>) {
    audit.shutdown().await.unwrap();
    store.shutdown().await.unwrap();
    drop(audit);
    drop(store);
}

#[tokio::test]
async fn explicit_audit_creation_drains_and_strict_reopen_preserves_stream_and_sequence()
-> Result<()> {
    let installation = Installation::new()?;
    let store = installation.store(true).await?;
    let before = retained(&store)?;
    assert!(installation.open(store.clone()).is_err());
    assert_eq!(retained(&store)?, before);
    assert_eq!(
        crate::test_utils::reserved_payload_bytes(&installation.admission),
        installation.metadata_bytes
    );
    let audit = installation.initialize(store.clone())?;
    let stream = audit.status()?.position.stream_id;
    assert!(!stream.is_nil());
    assert!(installation.initialize(store.clone()).is_err());
    audit.record(event()).await?;
    let position = audit.status()?.position;
    assert_eq!(position.next_sequence, 1);
    close(audit, store).await;
    assert_eq!(
        crate::test_utils::reserved_payload_bytes(&installation.admission),
        installation.metadata_bytes
    );

    // No sleeps or retries hide retained locks, key monitors or audit workers.
    let store = installation.store(false).await?;
    let before = retained(&store)?;
    assert!(installation.initialize(store.clone()).is_err());
    assert_eq!(retained(&store)?, before);
    let audit = installation.open(store.clone())?;
    assert_eq!(audit.status()?.position, position);
    audit.record(event()).await?;
    assert_eq!(audit.status()?.position.stream_id, stream);
    assert_eq!(audit.status()?.position.next_sequence, 2);
    close(audit, store).await;
    Ok(())
}

#[tokio::test]
async fn missing_empty_or_nonempty_audit_head_never_recreates_a_stream() -> Result<()> {
    for has_event in [false, true] {
        let installation = Installation::new()?;
        let store = installation.store(true).await?;
        let audit = installation.initialize(store.clone())?;
        if has_event {
            audit.record(event()).await?;
        }
        close(audit, store).await;
        let store = installation.store(false).await?;
        store.write_batch(&[WriteOp::delete("security.audit.meta", b"head")])?;
        let before = retained(&store)?;
        for _ in 0..2 {
            assert!(installation.open(store.clone()).is_err());
            assert_eq!(retained(&store)?, before);
            assert_eq!(
                crate::test_utils::reserved_payload_bytes(&installation.admission),
                installation.metadata_bytes
            );
        }
        store.shutdown().await.unwrap();
    }
    Ok(())
}

#[tokio::test]
async fn corrupt_audit_head_hot_gap_and_pending_pair_fail_without_logical_mutation() -> Result<()> {
    for corruption in 0..6 {
        let installation = Installation::new()?;
        let store = installation.store(true).await?;
        let audit = installation.initialize(store.clone())?;
        audit.record(event()).await?;
        close(audit, store).await;
        let store = installation.store(false).await?;
        let head = store.get("security.audit.meta", b"head")?.unwrap();
        let mut changed: serde_json::Value = serde_json::from_slice(&head)?;
        let operation = match corruption {
            0 => WriteOp::put("security.audit.meta", b"head", b"invalid"),
            1 => {
                changed["format"] = 2.into();
                WriteOp::put(
                    "security.audit.meta",
                    b"head",
                    serde_json::to_vec(&changed)?,
                )
            }
            2 => {
                changed["position"]["hot_bytes"] =
                    (changed["position"]["hot_bytes"].as_u64().unwrap() + 1).into();
                WriteOp::put(
                    "security.audit.meta",
                    b"head",
                    serde_json::to_vec(&changed)?,
                )
            }
            3 => WriteOp::delete("security.audit", 0u64.to_be_bytes()),
            4 => WriteOp::put("security.audit.meta", b"pending-ciphertext", b"orphan"),
            5 => {
                let bytes = store.get("security.audit", &0u64.to_be_bytes())?.unwrap();
                let mut record: serde_json::Value = serde_json::from_slice(&bytes)?;
                record["sequence"] = 1.into();
                WriteOp::put(
                    "security.audit",
                    0u64.to_be_bytes(),
                    serde_json::to_vec(&record)?,
                )
            }
            _ => unreachable!(),
        };
        store.write_batch(&[operation])?;
        let before = retained(&store)?;
        assert!(
            installation.open(store.clone()).is_err(),
            "corruption {corruption}"
        );
        assert_eq!(retained(&store)?, before);
        assert_eq!(
            crate::test_utils::reserved_payload_bytes(&installation.admission),
            installation.metadata_bytes
        );
        store.shutdown().await.unwrap();
    }
    Ok(())
}

#[tokio::test]
async fn live_audit_reopen_rejects_deleted_head_instead_of_reusing_cached_writer() -> Result<()> {
    let installation = Installation::new()?;
    let store = installation.store(true).await?;
    let audit = installation.initialize(store.clone())?;
    store.write_batch(&[WriteOp::delete("security.audit.meta", b"head")])?;
    let before = retained(&store)?;
    assert!(installation.open(store.clone()).is_err());
    assert_eq!(retained(&store)?, before);
    close(audit, store).await;
    Ok(())
}
