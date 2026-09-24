//! Real authenticated wrapping for tests only. Never selectable in production config.
use std::{
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};

use anyhow::{Result, ensure};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{GeneratedKey, KeyProvider, SecretKey, WrappedKey, decrypt, encrypt};
use kasumi_clock::LeaseClock;

/// Explicit fixture identity; production callers must retain their own installed
/// UUID. Tests of identity mismatch select distinct UUIDs directly.
pub const NODE_STORE_ID: uuid::Uuid =
    uuid::Uuid::from_u128(0x5c8c_7c42_e708_452c_b92f_510a_4673_4f2b);

/// A fixture installation starts private; production constructors never repair
/// permissions on a supplied directory.
pub fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

/// Explicit fixture setup retry. Production and isolated single-attempt disk
/// constructors never retry; only their typed registry-contention result may
/// be retried here. Provider errors and filesystem ownership failures remain
/// visible even when their underlying OS kind is WouldBlock.
pub fn retry_disk_registry<T>(
    mut open: impl FnMut() -> std::result::Result<T, crate::DiskOpenError>,
) -> std::result::Result<T, crate::DiskOpenError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match open() {
            Err(crate::DiskOpenError::RegistryBusy) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => return result,
        }
    }
}

/// Explicit bounded memory owner for physical-disk fixtures. It performs the
/// same mandatory resident acquisition and owns every accepted lease until Drop;
/// no production constructor selects this governor implicitly.
pub struct TestDiskMemory {
    storage_census: crate::StorageCensus,
    max_bytes: u64,
    max_reservations: usize,
    state: std::sync::Mutex<TestDiskMemorySnapshot>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TestDiskMemorySnapshot {
    /// Fixed provider and census backing, admitted before their allocations.
    pub bookkeeping_bytes: u64,
    /// Bytes held by live resident leases, additional to bookkeeping.
    pub used_bytes: u64,
    pub live_reservations: usize,
    pub attempts: u64,
}
struct TestDiskLease {
    owner: std::sync::Arc<TestDiskMemory>,
    bytes: u64,
}
impl TestDiskMemory {
    pub fn new(max_bytes: u64, max_reservations: usize) -> std::sync::Arc<Self> {
        assert!(max_bytes > 0 && max_reservations > 0);
        let base_bytes = Self::required_bookkeeping_bytes(max_reservations).unwrap();
        assert!(
            base_bytes <= max_bytes,
            "fixture bookkeeping admission denied"
        );
        let storage_census = crate::StorageCensus::allocate(max_reservations).unwrap();
        let owner = std::sync::Arc::new(Self {
            storage_census,
            max_bytes,
            max_reservations,
            state: std::sync::Mutex::new(TestDiskMemorySnapshot {
                bookkeeping_bytes: base_bytes,
                ..Default::default()
            }),
        });
        drop(owner.state.lock().unwrap());
        let provider: std::sync::Arc<dyn crate::NodeDiskMemoryAdmission> = owner.clone();
        owner.storage_census.bind_provider(&provider).unwrap();
        owner
    }
    pub fn required_bookkeeping_bytes(max_reservations: usize) -> std::io::Result<u64> {
        crate::disk_memory::add(
            crate::disk_memory::arc::<Self>()?,
            crate::StorageCensus::required_bytes(max_reservations)?,
        )
    }
    pub fn required_reservation_bytes(bytes: u64) -> std::io::Result<u64> {
        crate::disk_memory::add(bytes, crate::disk_memory::allocation::<TestDiskLease>(1)?)
    }
    pub fn snapshot(&self) -> TestDiskMemorySnapshot {
        *self.state.lock().unwrap()
    }
}
impl crate::NodeDiskMemoryAdmission for TestDiskMemory {
    fn storage_census(&self) -> &crate::StorageCensus {
        &self.storage_census
    }
    fn reserve_installed(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> std::io::Result<crate::DiskMemoryLease> {
        let bytes = Self::required_reservation_bytes(bytes)?;
        let mut state = self.state.lock().map_err(|_| std::io::ErrorKind::Other)?;
        state.attempts = state
            .attempts
            .checked_add(1)
            .ok_or(std::io::ErrorKind::Other)?;
        let next = state
            .used_bytes
            .checked_add(bytes)
            .ok_or(std::io::ErrorKind::OutOfMemory)?;
        if next
            .checked_add(state.bookkeeping_bytes)
            .is_none_or(|total| total > self.max_bytes)
            || state.live_reservations >= self.max_reservations
        {
            return Err(std::io::ErrorKind::OutOfMemory.into());
        }
        state.used_bytes = next;
        state.live_reservations += 1;
        drop(state);
        Ok(crate::DiskMemoryLease::new(TestDiskLease {
            owner: self,
            bytes,
        }))
    }
}
impl Drop for TestDiskLease {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock().unwrap();
        state.used_bytes = state
            .used_bytes
            .checked_sub(self.bytes)
            .expect("owned fixture bytes");
        state.live_reservations = state
            .live_reservations
            .checked_sub(1)
            .expect("owned fixture slot");
    }
}

impl crate::NodeStore {
    /// Synthetic redb I/O with an explicit admitted physical owner for engine
    /// fixtures. This does not claim the backend itself is a physical file.
    /// The exact persistent/scratch core is checked before redb can touch it.
    pub fn open_fixture_backend_on_disk(
        backend: impl redb::StorageBackend,
        redb_admission: std::sync::Arc<dyn redb::StorageAdmission>,
        persistent: std::sync::Arc<crate::NodeDisk>,
        scratch: std::sync::Arc<crate::ScratchDisk>,
    ) -> Result<std::sync::Arc<Self>> {
        ensure!(
            std::sync::Arc::ptr_eq(persistent.memory(), scratch.memory()),
            "persistent and scratch disks require the same installed memory admission"
        );
        let db = redb::Database::builder(redb_admission).create_with_backend(backend)?;
        Self::initialize_tables(&db)?;
        Ok(Self::installed(db, None, Some(persistent), scratch))
    }

    pub fn create_new_fixture(
        path: impl AsRef<std::path::Path>,
        id: uuid::Uuid,
        memory: std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>,
        scratch: std::sync::Arc<crate::ScratchDisk>,
    ) -> Result<std::sync::Arc<Self>> {
        let disk = retry_disk_registry(|| {
            crate::NodeDisk::fixture_for_path(path.as_ref(), memory.clone())
        })?;
        Self::create_new(path, id, disk, scratch)
    }

    pub fn open_existing_fixture(
        path: impl AsRef<std::path::Path>,
        id: uuid::Uuid,
        memory: std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>,
        scratch: std::sync::Arc<crate::ScratchDisk>,
    ) -> Result<std::sync::Arc<Self>> {
        let disk = retry_disk_registry(|| {
            crate::NodeDisk::fixture_for_path(path.as_ref(), memory.clone())
        })?;
        Self::open_existing(path, id, disk, scratch)
    }

    pub fn initialize_owned_empty_fixture(
        path: impl AsRef<std::path::Path>,
        identity: &crate::private_files::FileIdentity,
        id: uuid::Uuid,
        memory: std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>,
        scratch: std::sync::Arc<crate::ScratchDisk>,
    ) -> Result<std::sync::Arc<Self>> {
        let disk = retry_disk_registry(|| {
            crate::NodeDisk::fixture_for_path(path.as_ref(), memory.clone())
        })?;
        Self::initialize_owned_empty(path, identity, id, disk, scratch)
    }

    pub fn claim_cleanup_fixture(
        path: impl AsRef<std::path::Path>,
        id: uuid::Uuid,
        memory: std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>,
    ) -> Result<crate::NodeFileCleanup> {
        let disk = retry_disk_registry(|| {
            crate::NodeDisk::fixture_for_path(path.as_ref(), memory.clone())
        })?;
        Self::claim_cleanup(path, id, disk)
    }
}

/// Bounded synthetic owner for the in-memory crash/fault backends used only by
/// tests. Physical-file tests use NodeDisk instead. Failure remains latched in
/// this exact owner; a restarted crash image needs an explicitly new fixture.
#[derive(Debug, Default)]
struct FixtureStorageAdmission {
    failed: AtomicBool,
    reserved: AtomicU64,
}

impl redb::StorageAdmission for FixtureStorageAdmission {
    fn check_owner(&self) -> std::result::Result<(), redb::OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            Err(redb::OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_growth(
        &self,
        current: u64,
        requested: u64,
    ) -> std::result::Result<(), redb::AdmissionError> {
        self.check_owner()
            .map_err(|_| redb::AdmissionError::OwnerFailed)?;
        if requested < current || requested > 256 << 30 {
            return Err(redb::AdmissionError::CapacityDenied);
        }
        self.reserved.fetch_max(requested, Ordering::AcqRel);
        Ok(())
    }
    fn settle_growth(&self, actual: u64) -> std::result::Result<(), redb::OwnerFailed> {
        self.check_owner()?;
        if actual > 256 << 30 {
            self.owner_failed();
            return Err(redb::OwnerFailed);
        }
        self.reserved.store(actual, Ordering::Release);
        Ok(())
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }
}

pub fn storage_admission() -> std::sync::Arc<dyn redb::StorageAdmission> {
    std::sync::Arc::new(FixtureStorageAdmission::default())
}

/// Explicitly install an independent custody provider for a trusted test store.
/// Production configuration must supply both providers through TenantStorageSet.
pub async fn initialize_custody_fixture(
    application: std::sync::Arc<crate::TenantStore>,
    custody_provider: std::sync::Arc<dyn KeyProvider>,
) -> Result<std::sync::Arc<crate::TenantStorageSet>> {
    let control = crate::TenantStore::initialize_catalog_fixture_with_access(
        application.node.clone(),
        crate::CustodyStore::catalog_name(application.tenant()),
        custody_provider,
        crate::StorageAccess::custody(application.tenant()),
    )
    .await?;
    let result = crate::TenantStorageSet::install(application, control.clone());
    match result {
        Ok(stores) => Ok(stores),
        Err(error) => Err(match control.shutdown().await {
            Ok(()) => error,
            Err(failure) => error.context(failure),
        }),
    }
}

/// Reopen the exact authenticated pair surrounding a borrowed test application.
/// Missing custody or bindings are errors, including a partially created pair.
pub async fn open_existing_custody_fixture(
    application: std::sync::Arc<crate::TenantStore>,
    custody_provider: std::sync::Arc<dyn KeyProvider>,
) -> Result<std::sync::Arc<crate::TenantStorageSet>> {
    crate::TenantStorageSet::open_existing(
        application.node.clone(),
        application.tenant.clone(),
        application.provider.clone(),
        custody_provider,
        application.access.clone(),
    )
    .await
}

/// Assemble explicitly clocked test domains. This helper is unavailable in
/// production; production callers use initialize_catalogs or open_existing.
pub fn with_domains(
    application: std::sync::Arc<crate::TenantStore>,
    custody: std::sync::Arc<crate::TenantStore>,
) -> Result<std::sync::Arc<crate::TenantStorageSet>> {
    crate::TenantStorageSet::install(application, custody)
}

pub struct LocalKeyProvider {
    key: SecretKey,
    key_ref: String,
    allowed: AtomicBool,
    version: AtomicU64,
    minimum: AtomicU64,
    probes: AtomicU64,
}

impl LocalKeyProvider {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key: SecretKey::from_bytes(key),
            key_ref: format!("test-only/{}", hex::encode(Sha256::digest(key))),
            allowed: AtomicBool::new(true),
            version: AtomicU64::new(1),
            minimum: AtomicU64::new(1),
            probes: AtomicU64::new(0),
        }
    }
    pub fn revoke(&self) {
        self.allowed.store(false, Ordering::SeqCst);
    }
    pub fn allow(&self) {
        self.allowed.store(true, Ordering::SeqCst);
    }
    pub fn rotate(&self) -> u64 {
        self.version.fetch_add(1, Ordering::SeqCst) + 1
    }
    pub fn set_minimum_version(&self, version: u64) {
        self.minimum.store(version, Ordering::SeqCst);
    }
    pub fn probe_count(&self) -> u64 {
        self.probes.load(Ordering::SeqCst)
    }
    pub fn key_ref(&self) -> &str {
        &self.key_ref
    }
    fn check(&self) -> Result<()> {
        ensure!(self.allowed.load(Ordering::SeqCst), "test key revoked");
        Ok(())
    }
    fn aad(tenant: &str, version: u64) -> Vec<u8> {
        format!("kasumi.test-key/{tenant}/{version}").into_bytes()
    }
    fn wrap(&self, tenant: &str, plaintext: &SecretKey) -> Result<WrappedKey> {
        self.check()?;
        let version = self.version.load(Ordering::SeqCst);
        Ok(WrappedKey {
            provider: "test-only".into(),
            key_ref: self.key_ref.clone(),
            version,
            ciphertext: STANDARD.encode(encrypt(
                &self.key,
                plaintext.as_bytes(),
                &Self::aad(tenant, version),
            )?),
            context: Some(tenant.to_owned()),
        })
    }
}

#[async_trait]
impl KeyProvider for LocalKeyProvider {
    async fn generate_key(&self, tenant: &str) -> Result<GeneratedKey> {
        let plaintext = SecretKey::random()?;
        Ok(GeneratedKey {
            wrapped: self.wrap(tenant, &plaintext)?,
            plaintext,
        })
    }
    async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        self.probes.fetch_add(1, Ordering::SeqCst);
        self.check()?;
        ensure!(
            wrapped.provider == "test-only"
                && wrapped.key_ref == self.key_ref
                && wrapped.context.as_deref() == Some(tenant),
            "test key tenant mismatch"
        );
        ensure!(
            wrapped.version >= self.minimum.load(Ordering::SeqCst),
            "test key version revoked"
        );
        let bytes = STANDARD.decode(&wrapped.ciphertext)?;
        let key = Zeroizing::new(decrypt(
            &self.key,
            &bytes,
            &Self::aad(tenant, wrapped.version),
        )?);
        ensure!(key.len() == 32, "invalid test key");
        let mut fixed = Zeroizing::new([0u8; 32]);
        fixed.copy_from_slice(&key);
        Ok(SecretKey::from_bytes(*fixed))
    }
    async fn rewrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<WrappedKey> {
        self.wrap(tenant, &self.unwrap_key(tenant, wrapped).await?)
    }
}

#[derive(Default, Debug)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn advance(&self, elapsed: Duration) {
        self.0.fetch_add(
            u64::try_from(elapsed.as_nanos()).expect("test clock overflow"),
            Ordering::SeqCst,
        );
    }
}

impl LeaseClock for ManualClock {
    fn now(&self) -> Duration {
        Duration::from_nanos(self.0.load(Ordering::SeqCst))
    }
}

/// Reopenable storage whose synchronized image models what survives power loss.
/// Mutations after `fail_after` operations fail, including fsync, until disarmed.
/// Only the synchronized image is installed by `crash`, without running redb cleanup.
#[derive(Clone, Debug, Default)]
pub struct FaultBackend(std::sync::Arc<parking_lot::Mutex<FaultState>>);

#[derive(Debug, Default)]
struct FaultState {
    volatile: Vec<u8>,
    durable: Vec<u8>,
    remaining: Option<usize>,
    operations: usize,
    syncs: usize,
    advance_on_sync: Option<(std::sync::Arc<ManualClock>, Duration)>,
}

impl FaultBackend {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn fail_after(&self, mutations: usize) {
        self.0.lock().remaining = Some(mutations);
    }
    pub fn disarm(&self) {
        self.0.lock().remaining = None;
    }
    pub fn operations(&self) -> usize {
        self.0.lock().operations
    }
    pub fn syncs(&self) -> usize {
        self.0.lock().syncs
    }
    pub fn advance_clock_on_next_sync(
        &self,
        clock: std::sync::Arc<ManualClock>,
        elapsed: Duration,
    ) {
        self.0.lock().advance_on_sync = Some((clock, elapsed));
    }
    /// Returns a new independent backend, so dropping the old redb database cannot
    /// synchronize anything into the simulated post-crash disk.
    pub fn crash(&self) -> Self {
        let durable = self.0.lock().durable.clone();
        Self(std::sync::Arc::new(parking_lot::Mutex::new(FaultState {
            volatile: durable.clone(),
            durable,
            ..FaultState::default()
        })))
    }
}

impl FaultState {
    fn mutate(&mut self) -> std::io::Result<()> {
        if let Some(remaining) = &mut self.remaining {
            if *remaining == 0 {
                return Err(std::io::Error::other("injected storage failure"));
            }
            *remaining -= 1;
        }
        self.operations += 1;
        Ok(())
    }
}

impl redb::StorageBackend for FaultBackend {
    fn len(&self) -> std::io::Result<u64> {
        Ok(self.0.lock().volatile.len() as u64)
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
        let state = self.0.lock();
        let offset = usize::try_from(offset).map_err(std::io::Error::other)?;
        let end = offset
            .checked_add(out.len())
            .ok_or_else(|| std::io::Error::other("read overflow"))?;
        let bytes = state.volatile.get(offset..end).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "read outside storage")
        })?;
        out.copy_from_slice(bytes);
        Ok(())
    }
    fn set_len(&self, len: u64) -> std::io::Result<()> {
        let mut state = self.0.lock();
        state.mutate()?;
        state
            .volatile
            .resize(usize::try_from(len).map_err(std::io::Error::other)?, 0);
        Ok(())
    }
    fn sync_data(&self) -> std::io::Result<()> {
        let mut state = self.0.lock();
        state.mutate()?;
        if let Some((clock, elapsed)) = state.advance_on_sync.take() {
            clock.advance(elapsed);
        }
        state.syncs += 1;
        state.durable = state.volatile.clone();
        Ok(())
    }
    fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        let mut state = self.0.lock();
        state.mutate()?;
        let offset = usize::try_from(offset).map_err(std::io::Error::other)?;
        let end = offset
            .checked_add(data.len())
            .ok_or_else(|| std::io::Error::other("write overflow"))?;
        let target = state
            .volatile
            .get_mut(offset..end)
            .ok_or_else(|| std::io::Error::other("write outside storage"))?;
        target.copy_from_slice(data);
        Ok(())
    }
}

impl crate::FilesystemAuditArchive {
    pub fn open_fixture(
        root: impl AsRef<std::path::Path>,
        memory: std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>,
    ) -> anyhow::Result<Self> {
        let root = root.as_ref();
        if !root.exists() {
            crate::private_files::create_directory(root)?;
        }
        let disk = retry_disk_registry(|| {
            crate::NodeDisk::fixture_for_path(
                root.join("archive-accounting-anchor"),
                memory.clone(),
            )
        })?;
        Self::open(root, disk)
    }
}

impl crate::FilesystemBackupDestination {
    pub fn new_fixture(
        root: impl AsRef<std::path::Path>,
        max_bytes: usize,
        memory: std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>,
    ) -> anyhow::Result<Self> {
        let root = root.as_ref();
        if !root.exists() {
            crate::private_files::create_directory(root)?;
        }
        let disk = retry_disk_registry(|| {
            crate::NodeDisk::fixture_for_path(root.join("backup-accounting-anchor"), memory.clone())
        })?;
        Self::new(root, max_bytes, disk)
    }
}

#[cfg(test)]
mod registry_retry_tests {
    use super::*;
    #[test]
    fn fixture_retry_distinguishes_registry_busy_from_provider_would_block() {
        let mut attempts = 0;
        let value = retry_disk_registry(|| {
            attempts += 1;
            if attempts < 3 {
                Err(crate::DiskOpenError::RegistryBusy)
            } else {
                Ok(71)
            }
        })
        .unwrap();
        assert_eq!(value, 71);
        assert_eq!(attempts, 3);
        attempts = 0;
        let result: std::result::Result<(), _> = retry_disk_registry(|| {
            attempts += 1;
            Err(crate::DiskOpenError::Failed(
                std::io::Error::from(std::io::ErrorKind::WouldBlock).into(),
            ))
        });
        assert!(matches!(result, Err(crate::DiskOpenError::Failed(_))));
        assert_eq!(attempts, 1);
    }
}

#[cfg(test)]
mod admitted_backend_tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Debug)]
    struct UntouchedBackend;
    impl redb::StorageBackend for UntouchedBackend {
        fn len(&self) -> std::io::Result<u64> {
            panic!("foreign-core backend was queried")
        }
        fn read(&self, _: u64, _: &mut [u8]) -> std::io::Result<()> {
            panic!("foreign-core backend was read")
        }
        fn set_len(&self, _: u64) -> std::io::Result<()> {
            panic!("foreign-core backend was resized")
        }
        fn sync_data(&self) -> std::io::Result<()> {
            panic!("foreign-core backend was synchronized")
        }
        fn write(&self, _: u64, _: &[u8]) -> std::io::Result<()> {
            panic!("foreign-core backend was written")
        }
        fn close(&self) -> std::io::Result<()> {
            panic!("foreign-core backend was acquired")
        }
    }

    #[tokio::test]
    async fn admitted_backend_rejects_foreign_memory_before_io_and_retains_exact_owner() {
        let persistent_directory = private_tempdir().unwrap();
        let scratch_directory = private_tempdir().unwrap();
        let foreign_directory = private_tempdir().unwrap();
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let foreign_memory = TestDiskMemory::new(256 << 20, 4096);
        let persistent = retry_disk_registry(|| {
            crate::NodeDisk::fixture_for_path(
                persistent_directory.path().join("node.redb"),
                memory.clone(),
            )
        })
        .unwrap();
        let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
        let foreign = crate::ScratchDisk::fixture(foreign_directory.path(), foreign_memory.clone());
        let before = memory.snapshot();
        let foreign_before = foreign_memory.snapshot();
        let error = crate::NodeStore::open_fixture_backend_on_disk(
            UntouchedBackend,
            storage_admission(),
            persistent.clone(),
            foreign,
        )
        .err()
        .expect("foreign core must be rejected before backend I/O");
        assert!(
            error
                .to_string()
                .contains("same installed memory admission")
        );
        assert_eq!(memory.snapshot(), before);
        assert_eq!(foreign_memory.snapshot(), foreign_before);
        assert!(!persistent_directory.path().join("node.redb").exists());

        let backend = FaultBackend::new();
        let node = crate::NodeStore::open_fixture_backend_on_disk(
            backend.clone(),
            storage_admission(),
            persistent.clone(),
            scratch.clone(),
        )
        .unwrap();
        assert!(
            backend.operations() > 0,
            "accepted backend was not initialized"
        );
        assert!(Arc::ptr_eq(node.persistent_disk(), &persistent));
        assert!(Arc::ptr_eq(node.scratch_disk(), &scratch));
        assert_eq!(
            memory.snapshot(),
            before,
            "opening a synthetic backend invented a second disk owner"
        );
        node.shutdown().await.unwrap();
        assert!(!persistent_directory.path().join("node.redb").exists());
    }
}
