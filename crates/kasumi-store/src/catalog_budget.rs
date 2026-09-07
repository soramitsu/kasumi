use super::*;
use crate::test_utils::{LocalKeyProvider, ManualClock};
use async_trait::async_trait;
use std::sync::atomic::AtomicUsize;

struct WideReferences {
    inner: LocalKeyProvider,
    padding: AtomicUsize,
}
impl WideReferences {
    fn pad(&self, wrapped: &mut WrappedKey) {
        wrapped.key_ref = "x".repeat(self.padding.load(Ordering::SeqCst));
    }
}
#[async_trait]
impl KeyProvider for WideReferences {
    async fn generate_key(&self, tenant: &str) -> Result<GeneratedKey> {
        let mut generated = self.inner.generate_key(tenant).await?;
        self.pad(&mut generated.wrapped);
        Ok(generated)
    }
    async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        let mut inner = wrapped.clone();
        inner.key_ref = self.inner.key_ref().into();
        self.inner.unwrap_key(tenant, &inner).await
    }
    async fn rewrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<WrappedKey> {
        let mut inner = wrapped.clone();
        inner.key_ref = self.inner.key_ref().into();
        let mut wrapped = self.inner.rewrap_key(tenant, &inner).await?;
        self.pad(&mut wrapped);
        Ok(wrapped)
    }
}

#[tokio::test]
async fn catalog_byte_quota_rejects_initialization_rotation_and_rewrap_before_persistence() {
    let directory = tempfile::tempdir().unwrap();
    let node = NodeStore::open(directory.path().join("catalog.redb")).unwrap();
    let provider = Arc::new(WideReferences {
        inner: LocalKeyProvider::new([33; 32]),
        padding: AtomicUsize::new(MAX_KEY_CATALOG_BYTES),
    });
    let clock = Arc::new(ManualClock::new());
    assert!(
        TenantStore::open_with_clock(
            node.clone(),
            "tenant".into(),
            provider.clone(),
            clock.clone()
        )
        .await
        .is_err()
    );
    assert!(node.catalog("tenant").unwrap().is_none());
    provider.padding.store(0, Ordering::SeqCst);
    let store = TenantStore::open_with_clock(
        node.clone(),
        "tenant".into(),
        provider.clone(),
        clock.clone(),
    )
    .await
    .unwrap();
    store
        .write_batch(&[WriteOp::put("documents", b"id", b"before")])
        .unwrap();
    // A legal large wrapper still fits a backup; a further key change cannot
    // silently consume the header allowance reserved for that backup.
    provider
        .padding
        .store(MAX_KEY_CATALOG_BYTES / 2, Ordering::SeqCst);
    store.rotate_data_key().await.unwrap();
    let before = serde_json::to_vec(&store.catalog.read().clone()).unwrap();
    provider
        .padding
        .store(MAX_KEY_CATALOG_BYTES, Ordering::SeqCst);
    assert!(store.rotate_data_key().await.is_err());
    assert!(store.rewrap_keys().await.is_err());
    assert_eq!(
        serde_json::to_vec(&store.catalog.read().clone()).unwrap(),
        before
    );
    assert_eq!(
        serde_json::to_vec(&node.catalog("tenant").unwrap().unwrap()).unwrap(),
        before
    );
    let backup = store.encrypt_backup(7, b"snapshot").unwrap();
    let bytes = backup.to_bytes().unwrap();
    let restored = EncryptedBackup::from_bytes(&bytes, 1024)
        .unwrap()
        .decrypt("tenant", provider)
        .await
        .unwrap();
    assert_eq!(restored.snapshot.as_slice(), b"snapshot");
    assert_eq!(store.get("documents", b"id").unwrap().unwrap(), b"before");
}

#[tokio::test]
async fn exact_catalog_boundary_leaves_room_for_worst_case_manifest_tenant_encoding() {
    let directory = tempfile::tempdir().unwrap();
    let node = NodeStore::open(directory.path().join("boundary.redb")).unwrap();
    let tenant = "\u{0001}".repeat(1024);
    let provider = Arc::new(LocalKeyProvider::new([62; 32]));
    let store = TenantStore::open_with_clock(
        node.clone(),
        tenant.clone(),
        provider,
        Arc::new(ManualClock::new()),
    )
    .await
    .unwrap();
    let mut catalog = store.catalog.read().clone();
    catalog.keys.get_mut(INDEX_KEY).unwrap().key_ref.clear();
    let size = serde_json::to_vec(&catalog).unwrap().len();
    catalog.keys.get_mut(INDEX_KEY).unwrap().key_ref = "x".repeat(MAX_KEY_CATALOG_BYTES - size);
    assert_eq!(
        serde_json::to_vec(&catalog).unwrap().len(),
        MAX_KEY_CATALOG_BYTES
    );
    catalog.validate(&tenant).unwrap();
    node.save_catalog(&tenant, &catalog).unwrap();
    *store.catalog.write() = catalog.clone();
    let backup = store
        .encrypt_backup(u64::MAX, b"snapshot")
        .unwrap()
        .to_bytes()
        .unwrap();
    assert!(backup.len() < backup::HEADER_LIMIT + 1024);
    EncryptedBackup::from_bytes(&backup, 1024).unwrap();
    catalog.keys.get_mut(INDEX_KEY).unwrap().key_ref.push('x');
    assert!(catalog.validate(&tenant).is_err());
    assert!(node.save_catalog(&tenant, &catalog).is_err());
    // Untrusted/old on-disk metadata is checked before parsing or contacting KMS.
    let oversized = serde_json::to_vec(&catalog).unwrap();
    let mut tx = node.db.begin_write().unwrap();
    tx.set_durability(Durability::Immediate).unwrap();
    tx.set_two_phase_commit(true);
    tx.open_table(CATALOG)
        .unwrap()
        .insert(tenant_hash(&tenant).as_slice(), oversized.as_slice())
        .unwrap();
    tx.commit().unwrap();
    assert!(node.catalog(&tenant).is_err());
}
