use super::*;
use crate::test_utils::{LocalKeyProvider, ManualClock};
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicUsize};

#[tokio::test]
async fn production_catalog_typed_owner_retains_installed_memory_until_drop() -> Result<()> {
    let directory = crate::test_utils::private_tempdir()?;
    let path = directory.path().join("typed-catalog-owner.kv");
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let disk = crate::test_utils::retry_disk_registry(|| {
        crate::NodeDisk::fixture_for_path(&path, memory.clone())
    })?;
    let scratch_directory = crate::test_utils::private_tempdir()?;
    let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, crate::test_utils::NODE_STORE_ID, disk, scratch)?;
    let wrapped = WrappedKey {
        provider: "fixture".into(),
        key_ref: "catalog".into(),
        ciphertext: "opaque".into(),
        version: 1,
        context: None,
    };
    let catalog = KeyCatalog {
        format: 1,
        catalog_id: Uuid::from_u128(1),
        tenant: "tenant".into(),
        purpose: StoragePurpose::LocalFixture,
        active: "current".into(),
        keys: BTreeMap::from([
            ("index".into(), wrapped.clone()),
            ("current".into(), wrapped),
        ]),
    };
    node.save_catalog("tenant", &catalog)?;
    drop(node.catalog("tenant")?); // warm the native read path
    let before = memory.snapshot();
    let decoded = node.catalog("tenant")?.expect("installed catalog");
    assert!(decoded == catalog);
    let held = memory.snapshot();
    assert_eq!(held.live_reservations, before.live_reservations + 1);
    assert!(held.used_bytes > before.used_bytes);
    drop(decoded);
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn production_catalog_typed_admission_denial_precedes_serde_allocation() -> Result<()> {
    let directory = crate::test_utils::private_tempdir()?;
    let path = directory.path().join("typed-catalog-denial.kv");
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let disk = crate::test_utils::retry_disk_registry(|| {
        crate::NodeDisk::fixture_for_path(&path, memory.clone())
    })?;
    let scratch_directory = crate::test_utils::private_tempdir()?;
    let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, crate::test_utils::NODE_STORE_ID, disk, scratch)?;
    let wrapped = WrappedKey {
        provider: "fixture".into(),
        key_ref: "catalog".into(),
        ciphertext: "opaque".into(),
        version: 1,
        context: None,
    };
    let catalog = KeyCatalog {
        format: 1,
        catalog_id: Uuid::from_u128(1),
        tenant: "tenant".into(),
        purpose: StoragePurpose::LocalFixture,
        active: "current".into(),
        keys: BTreeMap::from([
            ("index".into(), wrapped.clone()),
            ("current".into(), wrapped),
        ]),
    };
    node.save_catalog("tenant", &catalog)?;
    drop(node.catalog("tenant")?);
    let before = memory.snapshot();
    // Leave the existing maximum raw-copy reservation and a small native-read
    // margin. The typed budget for two keys is larger than that margin.
    let raw = crate::disk_memory::allocation::<u8>(MAX_KEY_CATALOG_BYTES as u64)?;
    let available = raw + (32 << 10);
    let filler = (256 << 20)
        - before.bookkeeping_bytes
        - before.used_bytes
        - available
        - crate::test_utils::TestDiskMemory::required_reservation_bytes(0)?;
    let held = memory.clone().reserve_installed(filler)?;
    let error = node
        .catalog("tenant")
        .err()
        .expect("typed admission must fail");
    assert!(format!("{error:#}").contains("key catalog typed allocation admission denied"));
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    drop(held);
    node.shutdown().await?;
    Ok(())
}

struct ObservedRefreshProvider {
    inner: LocalKeyProvider,
    memory: Arc<crate::test_utils::TestDiskMemory>,
    capture: AtomicBool,
    minimum_live: AtomicUsize,
    unwraps: AtomicUsize,
}

#[async_trait]
impl KeyProvider for ObservedRefreshProvider {
    async fn generate_key(&self, tenant: &str) -> Result<GeneratedKey> {
        self.inner.generate_key(tenant).await
    }
    async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        self.unwraps.fetch_add(1, Ordering::SeqCst);
        if self.capture.load(Ordering::SeqCst) {
            self.minimum_live
                .fetch_min(self.memory.snapshot().live_reservations, Ordering::SeqCst);
        }
        self.inner.unwrap_key(tenant, wrapped).await
    }
    async fn rewrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<WrappedKey> {
        self.inner.rewrap_key(tenant, wrapped).await
    }
}

#[tokio::test]
async fn production_refresh_catalog_clone_denies_low_headroom_and_keeps_charge_until_probe_end()
-> Result<()> {
    let directory = crate::test_utils::private_tempdir()?;
    let path = directory.path().join("refresh-catalog-clone.kv");
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let disk = crate::test_utils::retry_disk_registry(|| {
        crate::NodeDisk::fixture_for_path(&path, memory.clone())
    })?;
    let scratch_directory = crate::test_utils::private_tempdir()?;
    let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, crate::test_utils::NODE_STORE_ID, disk, scratch)?;
    let provider = Arc::new(ObservedRefreshProvider {
        inner: LocalKeyProvider::new([87; 32]),
        memory: memory.clone(),
        capture: AtomicBool::new(false),
        minimum_live: AtomicUsize::new(usize::MAX),
        unwraps: AtomicUsize::new(0),
    });
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        node.clone(),
        "tenant".into(),
        provider.clone(),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let before = memory.snapshot();
    let remaining = 64 << 10;
    let filler = (256 << 20)
        - before.bookkeeping_bytes
        - before.used_bytes
        - remaining
        - crate::test_utils::TestDiskMemory::required_reservation_bytes(0)?;
    let held = memory.clone().reserve_installed(filler)?;
    let low_headroom = memory.snapshot();
    let probes_before = provider.unwraps.load(Ordering::SeqCst);
    let error = store
        .refresh_lease()
        .await
        .expect_err("typed clone admission must fail");
    assert!(format!("{error:#}").contains("key catalog refresh clone admission denied"));
    assert_eq!(provider.unwraps.load(Ordering::SeqCst), probes_before);
    assert_eq!(memory.snapshot().used_bytes, low_headroom.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        low_headroom.live_reservations
    );
    store.check_access()?;
    drop(held);
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);

    provider.capture.store(true, Ordering::SeqCst);
    store.refresh_lease().await?;
    assert!(provider.minimum_live.load(Ordering::SeqCst) > before.live_reservations);
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        before.live_reservations
    );
    store.shutdown().await?;
    drop(store);
    node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn production_catalog_mutation_clones_deny_low_headroom_and_keep_one_resident_charge()
-> Result<()> {
    let directory = crate::test_utils::private_tempdir()?;
    let path = directory.path().join("mutation-catalog-clones.kv");
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let disk = crate::test_utils::retry_disk_registry(|| {
        crate::NodeDisk::fixture_for_path(&path, memory.clone())
    })?;
    let scratch_directory = crate::test_utils::private_tempdir()?;
    let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, crate::test_utils::NODE_STORE_ID, disk, scratch)?;
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        node.clone(),
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([89; 32])),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let original = store.catalog.read().clone();
    let before = memory.snapshot();
    let remaining = 3 << 20;
    let filler = (256 << 20)
        - before.bookkeeping_bytes
        - before.used_bytes
        - remaining
        - crate::test_utils::TestDiskMemory::required_reservation_bytes(0)?;
    let held = memory.clone().reserve_installed(filler)?;
    let low = memory.snapshot();
    let rotation = store
        .rotate_data_key()
        .await
        .expect_err("rotation clone admission must fail");
    assert!(
        format!("{rotation:#}").contains("key catalog mutation clone admission denied"),
        "unexpected rotation refusal: {rotation:#}"
    );
    assert!(*store.catalog.read() == original);
    assert_eq!(memory.snapshot().used_bytes, low.used_bytes);
    assert_eq!(memory.snapshot().live_reservations, low.live_reservations);
    let rewrap = store
        .rewrap_keys()
        .await
        .expect_err("rewrap clone admission must fail");
    assert!(
        format!("{rewrap:#}").contains("key catalog mutation clone admission denied"),
        "unexpected rewrap refusal: {rewrap:#}"
    );
    assert!(*store.catalog.read() == original);
    assert_eq!(memory.snapshot().used_bytes, low.used_bytes);
    assert_eq!(memory.snapshot().live_reservations, low.live_reservations);
    drop(held);
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);

    store.rotate_data_key().await?;
    let rotated = memory.snapshot();
    assert!(rotated.live_reservations > before.live_reservations);
    assert!(rotated.used_bytes > before.used_bytes);
    store.rewrap_keys().await?;
    let rewrapped = memory.snapshot();
    assert_eq!(rewrapped.live_reservations, rotated.live_reservations);
    assert_eq!(rewrapped.used_bytes, rotated.used_bytes);
    store.shutdown().await?;
    drop(store);
    node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn production_backup_catalog_clone_denies_low_headroom_and_lives_with_backup() -> Result<()> {
    let directory = crate::test_utils::private_tempdir()?;
    let path = directory.path().join("backup-catalog-clone.kv");
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let disk = crate::test_utils::retry_disk_registry(|| {
        crate::NodeDisk::fixture_for_path(&path, memory.clone())
    })?;
    let scratch_directory = crate::test_utils::private_tempdir()?;
    let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, crate::test_utils::NODE_STORE_ID, disk, scratch)?;
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        node.clone(),
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([91; 32])),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let before = memory.snapshot();
    let remaining = 64 << 10;
    let filler = (256 << 20)
        - before.bookkeeping_bytes
        - before.used_bytes
        - remaining
        - crate::test_utils::TestDiskMemory::required_reservation_bytes(0)?;
    let held = memory.clone().reserve_installed(filler)?;
    let low = memory.snapshot();
    let error = store
        .encrypt_backup_with_id(Uuid::from_u128(9), 1, b"tiny")
        .err()
        .expect("backup catalog clone admission must fail");
    assert!(format!("{error:#}").contains("key catalog backup clone admission denied"));
    assert_eq!(memory.snapshot().used_bytes, low.used_bytes);
    assert_eq!(memory.snapshot().live_reservations, low.live_reservations);
    store.check_access()?;
    drop(held);
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);

    let backup = store.encrypt_backup_with_id(Uuid::from_u128(10), 1, b"tiny")?;
    let retained = memory.snapshot();
    assert!(retained.live_reservations > before.live_reservations);
    assert!(retained.used_bytes > before.used_bytes);
    drop(backup);
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        before.live_reservations
    );
    store.shutdown().await?;
    drop(store);
    node.shutdown().await?;
    Ok(())
}

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
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = crate::test_utils::private_tempdir().unwrap();
    let node = NodeStore::create_new_fixture(
        directory.path().join("catalog.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )
    .unwrap();
    let provider = Arc::new(WideReferences {
        inner: LocalKeyProvider::new([33; 32]),
        padding: AtomicUsize::new(MAX_KEY_CATALOG_BYTES),
    });
    let clock = Arc::new(ManualClock::new());
    assert!(
        TenantStore::initialize_catalog_fixture_with_clock(
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
    let store = TenantStore::initialize_catalog_fixture_with_clock(
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
    let restored = EncryptedBackup::from_bytes(&bytes, 1024, &store)
        .unwrap()
        .decrypt_fixture("tenant", provider, &store)
        .await
        .unwrap();
    assert_eq!(restored.snapshot.as_slice(), b"snapshot");
    assert_eq!(store.get("documents", b"id").unwrap().unwrap(), b"before");
}

#[tokio::test]
async fn exact_catalog_boundary_leaves_room_for_worst_case_manifest_tenant_encoding() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = crate::test_utils::private_tempdir().unwrap();
    let node = NodeStore::create_new_fixture(
        directory.path().join("boundary.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )
    .unwrap();
    let tenant = "\u{0001}".repeat(1024);
    let provider = Arc::new(LocalKeyProvider::new([62; 32]));
    let store = TenantStore::initialize_catalog_fixture_with_clock(
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
    EncryptedBackup::from_bytes(&backup, 1024, &store).unwrap();
    catalog.keys.get_mut(INDEX_KEY).unwrap().key_ref.push('x');
    assert!(catalog.validate(&tenant).is_err());
    assert!(node.save_catalog(&tenant, &catalog).is_err());
    // Untrusted/old on-disk metadata is checked before parsing or contacting KMS.
    let oversized = serde_json::to_vec(&catalog).unwrap();
    let tx = node.db.begin_write().unwrap();
    tx.open_table(CATALOG)
        .unwrap()
        .insert(tenant_hash(&tenant).as_slice(), oversized.as_slice())
        .unwrap();
    tx.commit().unwrap();
    assert!(node.catalog(&tenant).is_err());
}
