//! Real authenticated wrapping for tests only. Never selectable in production config.
#[cfg(test)]
#[path = "source_quote_observer.rs"]
pub(crate) mod source_quote_observer;

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

use kasumi_kv as cache_types;
#[cfg(test)]
#[path = "test_cache_memory.rs"]
pub(crate) mod cache_memory;
#[path = "../../kasumi-kv/src/cache_test.rs"]
pub(crate) mod cache_test;

/// Explicit fixture identity; production callers must retain their own installed
/// UUID. Tests of identity mismatch select distinct UUIDs directly.
pub const NODE_STORE_ID: uuid::Uuid =
    uuid::Uuid::from_u128(0x5c8c_7c42_e708_452c_b92f_510a_4673_4f2b);

/// Explicit deterministic fixture shares. Residency behavior has dedicated KV
/// tests; these unrelated store fixtures keep request-owned output uncached.
pub fn node_storage_config() -> crate::NodeStorageConfig {
    crate::NodeStorageConfig {
        cache: kasumi_kv::CacheConfig { byte_limit: 0 },
        cached_files: 8,
    }
}

/// A fixture installation starts private; production constructors never repair
/// permissions on a supplied directory.
pub fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

/// Enumerate the actual regular files in a test node group without following
/// symlinks or silently skipping unexpected physical entries.
#[cfg(test)]
pub(crate) fn node_group_files(path: &std::path::Path) -> Vec<std::path::PathBuf> {
    assert!(std::fs::symlink_metadata(path).unwrap().is_dir());
    let mut pending = vec![path.to_owned()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                pending.push(path);
            } else {
                assert!(
                    metadata.is_file(),
                    "unexpected node entry: {}",
                    path.display()
                );
                files.push(path);
            }
        }
    }
    files.sort();
    assert!(files.contains(&path.join(kasumi_kv::ROOT_FILE_NAME)));
    files
}

/// A test-only physical fault: publish authenticated rows from both encrypted
/// domains in one native transaction below TenantStore's write-once facade.
/// The caller can therefore model an offline replacement of a complete disk
/// generation, or deliberately tear just one installed identity row.
pub fn inject_authenticated_rows_below_facade(
    stores: &crate::TenantStorageSet,
    application_ops: &[crate::WriteOp],
    custody_ops: &[crate::WriteOp],
) -> Result<()> {
    let tx = stores.application().node.db.begin_write()?;
    for (store, operations) in [
        (stores.application(), application_ops),
        (stores.custody().store(), custody_ops),
    ] {
        let state = store.state.read();
        store.require_access(&state)?;
        let index = state
            .keys
            .get(crate::INDEX_KEY)
            .ok_or_else(|| anyhow::anyhow!("index key missing"))?;
        let catalog = store.catalog.read();
        let mut table = tx.open_table(crate::RECORDS)?;
        for operation in operations {
            match operation {
                crate::WriteOp::Put {
                    namespace,
                    key,
                    value,
                } => {
                    let disk_key = crate::record_key(&store.tenant, namespace, key, index);
                    let data = state
                        .keys
                        .get(&catalog.active)
                        .ok_or_else(|| anyhow::anyhow!("active data key missing"))?;
                    let plaintext =
                        Zeroizing::new(crate::encode_plain_record(namespace, key, value)?);
                    let mut envelope = Vec::new();
                    crate::append_bytes(&mut envelope, catalog.active.as_bytes())?;
                    envelope.extend(encrypt(
                        data,
                        &plaintext,
                        &crate::record_aad(&store.tenant, &disk_key),
                    )?);
                    table.insert(disk_key.as_slice(), envelope.as_slice())?;
                }
                crate::WriteOp::Delete { namespace, key } => {
                    let disk_key = crate::record_key(&store.tenant, namespace, key, index);
                    table.remove(disk_key.as_slice())?;
                }
            }
        }
        store.require_access(&state)?;
    }
    tx.commit()?;
    Ok(())
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

/// The installed device registry binds each filesystem device to the first
/// memory admission registered for it, for the life of the process. Tests that
/// open installed owners share this one admission. A test that makes one of
/// their registrations uncertain affects every installed owner on that device.
#[cfg(test)]
pub(crate) fn installed_device_memory() -> std::sync::Arc<TestDiskMemory> {
    static MEMORY: std::sync::OnceLock<std::sync::Arc<TestDiskMemory>> = std::sync::OnceLock::new();
    MEMORY
        .get_or_init(|| TestDiskMemory::new(256 << 20, 4096))
        .clone()
}

/// Explicit bounded memory owner for physical-disk fixtures. It performs the
/// same mandatory resident acquisition and owns every accepted lease until Drop;
/// no production constructor selects this governor implicitly.
pub struct TestDiskMemory {
    storage_census: crate::StorageCensus,
    max_bytes: u64,
    max_reservations: usize,
    state: std::sync::Mutex<TestDiskMemorySnapshot>,
    #[cfg(test)]
    point_drop_panic: std::sync::Mutex<Option<(u64, Box<dyn std::any::Any + Send>)>>,
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
    // The real lease carries its acquisition identity in test-utils builds too.
    // required_reservation_bytes includes this field before allocation.
    id: u64,
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
            #[cfg(test)]
            point_drop_panic: std::sync::Mutex::new(None),
            max_bytes,
            max_reservations,
            state: std::sync::Mutex::new(TestDiskMemorySnapshot {
                bookkeeping_bytes: base_bytes,
                ..Default::default()
            }),
        });
        drop(owner.state.lock().unwrap());
        // macOS initializes std mutex backing on first lock. Construct the
        // test-only fault hook here, before any allocation-free retirement.
        #[cfg(test)]
        drop(owner.point_drop_panic.lock().unwrap());
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
    // Scalar observation only; called after releasing the admission ledger.
    // No shadow owner registry or replacement lease is constructed.
    fn observe_lease(
        &self,
        event: &'static str,
        id: u64,
        before: u64,
        after: u64,
        snapshot: TestDiskMemorySnapshot,
    ) {
        if std::env::var_os("KASUMI_TEST_METADATA_LEASE_TRACE").as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return;
        }
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr().lock(),
            "fixture_lease event={event} owner={:p} id={id} before_bytes={before} after_bytes={after} used_bytes={} live_reservations={} attempts={}",
            self,
            snapshot.used_bytes,
            snapshot.live_reservations,
            snapshot.attempts,
        );
    }
}
impl kasumi_kv::SourceMemoryProvider for TestDiskMemory {}
impl crate::NodeDiskMemoryAdmission for TestDiskMemory {
    fn quote_installed(&self, bytes: u64) -> std::io::Result<u64> {
        Self::required_reservation_bytes(bytes)
    }
    fn storage_census(&self) -> &crate::StorageCensus {
        &self.storage_census
    }
    fn reserve_installed(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> std::io::Result<crate::DiskMemoryLease> {
        let requested_bytes = bytes;
        let bytes = Self::required_reservation_bytes(bytes)?;
        let mut state = self.state.lock().map_err(|_| std::io::ErrorKind::Other)?;
        state.attempts = state
            .attempts
            .checked_add(1)
            .ok_or(std::io::ErrorKind::Other)?;
        #[cfg(test)]
        if binding_staging_refuses(std::sync::Arc::as_ptr(&self) as usize, requested_bytes) {
            return Err(std::io::ErrorKind::OutOfMemory.into());
        }
        let next = state
            .used_bytes
            .checked_add(bytes)
            .ok_or(std::io::ErrorKind::OutOfMemory)?;
        if next
            .checked_add(state.bookkeeping_bytes)
            .is_none_or(|total| total > self.max_bytes)
            || state.live_reservations >= self.max_reservations
        {
            let error = std::io::Error::from(std::io::ErrorKind::OutOfMemory);
            let refused = *state;
            drop(state);
            use std::io::Write as _;
            let _ = writeln!(
                std::io::stderr().lock(),
                "TestDiskMemory::reserve_installed denied: provider={:p} requested_bytes={requested_bytes} charged_bytes={bytes} bookkeeping_bytes={} used_bytes={} next_used_bytes={next} max_bytes={} live_reservations={} max_reservations={} attempts={} error={error:?}",
                std::sync::Arc::as_ptr(&self),
                refused.bookkeeping_bytes,
                refused.used_bytes,
                self.max_bytes,
                refused.live_reservations,
                self.max_reservations,
                refused.attempts,
            );
            return Err(error);
        }
        state.used_bytes = next;
        state.live_reservations += 1;
        #[cfg(test)]
        source_quote_observer::record(
            std::sync::Arc::as_ptr(&self) as usize,
            bytes,
            state.used_bytes,
            state.live_reservations,
        );
        let id = state.attempts;
        let observed = *state;
        drop(state);
        self.observe_lease("installed", id, 0, bytes, observed);
        Ok(crate::DiskMemoryLease::new(TestDiskLease {
            id,
            owner: self,
            bytes,
        }))
    }

    fn quote_cache_memory(&self, bytes: u64) -> std::io::Result<kasumi_kv::CacheMemoryQuote> {
        kasumi_kv::CacheMemoryQuote::new(bytes, Self::required_reservation_bytes(0)?)
            .ok_or_else(|| std::io::ErrorKind::OutOfMemory.into())
    }

    fn reserve_cache_memory(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> std::io::Result<kasumi_kv::CacheMemoryLease> {
        let quote = self.quote_cache_memory(bytes)?;
        let mut state = self.state.lock().map_err(|_| std::io::ErrorKind::Other)?;
        state.attempts = state
            .attempts
            .checked_add(1)
            .ok_or(std::io::ErrorKind::Other)?;
        let next = state
            .used_bytes
            .checked_add(quote.charged_bytes())
            .ok_or(std::io::ErrorKind::OutOfMemory)?;
        if !self.cache_headroom_fits(&state, next, 1) {
            return Err(std::io::ErrorKind::OutOfMemory.into());
        }
        state.used_bytes = next;
        state.live_reservations += 1;
        let id = state.attempts;
        let observed = *state;
        drop(state);
        self.observe_lease("cache", id, 0, quote.charged_bytes(), observed);
        Ok(kasumi_kv::CacheMemoryLease::new(
            quote,
            TestDiskLease {
                id,
                owner: self,
                bytes: quote.charged_bytes(),
            },
        ))
    }
}

impl TestDiskMemory {
    fn cache_headroom_fits(
        &self,
        state: &TestDiskMemorySnapshot,
        used: u64,
        additional_slots: usize,
    ) -> bool {
        let bytes = (self.max_bytes / 4).min(64 << 20);
        let slots = (self.max_reservations / 4).clamp(1, 64);
        used.checked_add(state.bookkeeping_bytes)
            .and_then(|used| used.checked_add(bytes))
            .is_some_and(|total| total <= self.max_bytes)
            && state
                .live_reservations
                .checked_add(additional_slots)
                .and_then(|used| used.checked_add(slots))
                .is_some_and(|total| total <= self.max_reservations)
    }
}

impl kasumi_kv::CacheMemoryReservation for TestDiskLease {
    fn try_grow(&mut self, bytes: u64) -> Result<(), kasumi_kv::AdmissionError> {
        let mut state = self
            .owner
            .state
            .lock()
            .map_err(|_| kasumi_kv::AdmissionError::OwnerFailed)?;
        state.attempts = state
            .attempts
            .checked_add(1)
            .ok_or(kasumi_kv::AdmissionError::OwnerFailed)?;
        let used = state
            .used_bytes
            .checked_add(bytes)
            .ok_or(kasumi_kv::AdmissionError::CapacityDenied)?;
        let charged = self
            .bytes
            .checked_add(bytes)
            .ok_or(kasumi_kv::AdmissionError::CapacityDenied)?;
        if !self.owner.cache_headroom_fits(&state, used, 0) {
            return Err(kasumi_kv::AdmissionError::CapacityDenied);
        }
        state.used_bytes = used;
        let previous = self.bytes;
        self.bytes = charged;
        let observed = *state;
        drop(state);
        self.owner
            .observe_lease("grow", self.id, previous, charged, observed);
        Ok(())
    }

    fn retain_charge(&mut self, bytes: u64) {
        let mut state = self
            .owner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.used_bytes -= self.bytes - bytes;
        let previous = self.bytes;
        self.bytes = bytes;
        let observed = *state;
        drop(state);
        self.owner
            .observe_lease("retain", self.id, previous, bytes, observed);
    }
}
impl Drop for TestDiskLease {
    fn drop(&mut self) {
        let mut state = self
            .owner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.used_bytes = state
            .used_bytes
            .checked_sub(self.bytes)
            .expect("owned fixture bytes");
        state.live_reservations = state
            .live_reservations
            .checked_sub(1)
            .expect("owned fixture slot");
        let observed = *state;
        drop(state);
        self.owner
            .observe_lease("drop", self.id, self.bytes, 0, observed);
        #[cfg(test)]
        {
            let mut pending = self.owner.point_drop_panic.lock().unwrap();
            let payload = if pending.as_ref().is_some_and(|(id, _)| *id == self.id) {
                pending.take().map(|(_, payload)| payload)
            } else {
                None
            };
            drop(pending);
            if let Some(payload) = payload {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

impl crate::NodeStore {
    /// Synthetic KV I/O with an explicit admitted physical owner for engine
    /// fixtures. This does not claim the backend itself is a physical file.
    /// The exact persistent/scratch core is checked before the engine can touch it.
    pub fn create_fixture_backend_on_disk(
        backend: impl kasumi_kv::SegmentGroupBackend + 'static,
        storage_admission: std::sync::Arc<dyn kasumi_kv::StorageAdmission>,
        persistent: std::sync::Arc<crate::NodeDisk>,
        scratch: std::sync::Arc<crate::ScratchDisk>,
    ) -> Result<std::sync::Arc<Self>> {
        ensure!(
            std::sync::Arc::ptr_eq(persistent.memory(), scratch.memory()),
            "persistent and scratch disks require the same installed memory admission"
        );
        let db = kasumi_kv::Database::builder(
            storage_admission,
            *NODE_STORE_ID.as_bytes(),
            node_storage_config().cache,
        )
        .create_with_backend(backend)?;
        let db = Self::finish_setup(db, Self::initialize_tables)?;
        Ok(Self::installed(db, None, Some(persistent), scratch))
    }

    pub fn open_fixture_backend_on_disk(
        backend: impl kasumi_kv::SegmentGroupBackend + 'static,
        storage_admission: std::sync::Arc<dyn kasumi_kv::StorageAdmission>,
        persistent: std::sync::Arc<crate::NodeDisk>,
        scratch: std::sync::Arc<crate::ScratchDisk>,
    ) -> Result<std::sync::Arc<Self>> {
        ensure!(
            std::sync::Arc::ptr_eq(persistent.memory(), scratch.memory()),
            "persistent and scratch disks require the same installed memory admission"
        );
        let db = kasumi_kv::Database::builder(
            storage_admission,
            *NODE_STORE_ID.as_bytes(),
            node_storage_config().cache,
        )
        .open_with_backend(backend)?;
        let db = Self::finish_setup(db, |database| {
            let tx = database.begin_read()?;
            tx.open_table(crate::CATALOG)?;
            tx.open_table(crate::RECORDS)?;
            Ok(())
        })?;
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
        Self::create_new_fixture_direct(path.as_ref(), id, disk, scratch)
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
        Self::open_existing_fixture_direct(path.as_ref(), id, disk, scratch)
    }

    pub fn initialize_owned_empty_fixture(
        path: impl AsRef<std::path::Path>,
        identity: &crate::NodeGroupIdentity,
        id: uuid::Uuid,
        memory: std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>,
        scratch: std::sync::Arc<crate::ScratchDisk>,
    ) -> Result<std::sync::Arc<Self>> {
        let disk = retry_disk_registry(|| {
            crate::NodeDisk::fixture_for_path(path.as_ref(), memory.clone())
        })?;
        Self::initialize_owned_empty_fixture_direct(path.as_ref(), identity, id, disk, scratch)
    }

    pub fn claim_cleanup_fixture(
        path: impl AsRef<std::path::Path>,
        id: uuid::Uuid,
        memory: std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>,
    ) -> Result<crate::NodeSegmentGroupCleanup> {
        let disk = retry_disk_registry(|| {
            crate::NodeDisk::fixture_for_path(path.as_ref(), memory.clone())
        })?;
        Self::claim_cleanup(path, id, disk, node_storage_config())
    }
}

/// Bounded synthetic owner for the in-memory crash/fault backends used only by
/// tests. Physical-file tests use NodeDisk instead. Failure remains latched in
/// this exact owner; a restarted crash image needs an explicitly new fixture.
#[derive(Debug, Default)]
struct FixtureStorageAdmission {
    cache_bytes: AtomicU64,
    failed: AtomicBool,
    reserved: AtomicU64,
}

impl kasumi_kv::StorageAdmission for FixtureStorageAdmission {
    fn reserve_workspace(
        &self,
        _bytes: u64,
    ) -> core::result::Result<Box<dyn kasumi_kv::ResidentLease>, kasumi_kv::AdmissionError> {
        self.check_owner()
            .map_err(|_| kasumi_kv::AdmissionError::OwnerFailed)?;
        Ok(Box::new(()))
    }
    fn check_owner(&self) -> std::result::Result<(), kasumi_kv::OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            Err(kasumi_kv::OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_growth(
        &self,
        current: u64,
        requested: u64,
    ) -> std::result::Result<(), kasumi_kv::AdmissionError> {
        self.check_owner()
            .map_err(|_| kasumi_kv::AdmissionError::OwnerFailed)?;
        if requested < current || requested > 256 << 30 {
            return Err(kasumi_kv::AdmissionError::CapacityDenied);
        }
        self.reserved.fetch_max(requested, Ordering::AcqRel);
        Ok(())
    }
    fn settle_growth(&self, actual: u64) -> std::result::Result<(), kasumi_kv::OwnerFailed> {
        self.check_owner()?;
        if actual > 256 << 30 {
            self.owner_failed();
            return Err(kasumi_kv::OwnerFailed);
        }
        self.reserved.store(actual, Ordering::Release);
        Ok(())
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }

    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryQuote, kasumi_kv::AdmissionError> {
        crate::test_utils::cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryLease, kasumi_kv::AdmissionError> {
        crate::test_utils::cache_test::reserve(self, bytes)
    }
}
impl crate::test_utils::cache_test::Provider for FixtureStorageAdmission {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), kasumi_kv::AdmissionError> {
        let _ = first;
        self.cache_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|total| *total <= 256 << 20)
            })
            .map_err(|_| kasumi_kv::AdmissionError::CapacityDenied)?;
        Ok(())
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        let _ = (bytes, last);
        self.cache_bytes.fetch_sub(bytes, Ordering::AcqRel);
    }
}

pub fn storage_admission() -> std::sync::Arc<dyn kasumi_kv::StorageAdmission> {
    std::sync::Arc::new(FixtureStorageAdmission::default())
}

/// Install the explicit local-replica-only tenant audit placement that a
/// production installer selects from configuration before replay. Fixture
/// storage uses the fixture placement; a fixture-assembled Control store keeps
/// its production purpose and opts in through the installed API. A placement
/// already installed on this store is kept and a different persisted placement
/// is rejected, never replaced. Every other purpose, and synthetic backends
/// without a durable directory, install nothing here.
pub fn install_fixture_audit_placement(store: &crate::TenantStore) -> Result<()> {
    if store.durable_directory().is_err() || store.audit_placement.lock().is_some() {
        return Ok(());
    }
    match store.storage_access().purpose() {
        crate::StoragePurpose::LocalFixture => {
            store.install_fixture_tenant_audit_archive()?;
        }
        crate::StoragePurpose::NodeControl => {
            let cache = std::sync::Arc::new(crate::FilesystemAuditArchive::open(
                store.durable_directory()?.join("tenant-audit-archives"),
                store.persistent_disk().clone(),
            )?);
            store.install_tenant_audit_archive(cache.clone(), cache)?;
        }
        _ => {}
    }
    Ok(())
}

/// Explicitly install an independent custody provider for a trusted test store,
/// and its fixture tenant audit placement (see install_fixture_audit_placement).
/// Production configuration must supply both providers through TenantStorageSet.
pub async fn initialize_custody_fixture(
    application: std::sync::Arc<crate::TenantStore>,
    custody_provider: std::sync::Arc<dyn KeyProvider>,
) -> Result<std::sync::Arc<crate::TenantStorageSet>> {
    install_fixture_audit_placement(&application)?;
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
/// The reopened application reinstalls the fixture tenant audit placement; a
/// different persisted placement fails instead of being replaced.
pub async fn open_existing_custody_fixture(
    application: std::sync::Arc<crate::TenantStore>,
    custody_provider: std::sync::Arc<dyn KeyProvider>,
) -> Result<std::sync::Arc<crate::TenantStorageSet>> {
    let stores = crate::TenantStorageSet::open_existing(
        application.node.clone(),
        application.tenant.clone(),
        application.provider.clone(),
        custody_provider,
        application.access.clone(),
    )
    .await?;
    match install_fixture_audit_placement(stores.application()) {
        Ok(()) => Ok(stores),
        Err(error) => Err(match stores.shutdown().await {
            Ok(()) => error,
            Err(failure) => error.context(failure),
        }),
    }
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
/// Only the synchronized image is installed by `crash`, without running database cleanup.
#[derive(Clone)]
pub struct FaultBackend {
    backend: kasumi_kv::backends::InMemoryGroup,
    state: std::sync::Arc<parking_lot::Mutex<FaultState>>,
}
impl std::fmt::Debug for FaultBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FaultBackend")
            .finish_non_exhaustive()
    }
}
impl Default for FaultBackend {
    fn default() -> Self {
        Self {
            backend: kasumi_kv::backends::InMemoryGroup::new(),
            state: Default::default(),
        }
    }
}
#[derive(Debug, Default)]
struct FaultState {
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
        self.state.lock().remaining = Some(mutations);
    }
    pub fn disarm(&self) {
        self.state.lock().remaining = None;
    }
    pub fn operations(&self) -> usize {
        self.state.lock().operations
    }
    pub fn syncs(&self) -> usize {
        self.state.lock().syncs
    }
    /// Expire after root publication, not after a prepared data/page fsync.
    pub fn advance_clock_on_next_sync(
        &self,
        clock: std::sync::Arc<ManualClock>,
        elapsed: Duration,
    ) {
        self.state.lock().advance_on_sync = Some((clock, elapsed));
    }
    pub fn crash(&self) -> Self {
        Self {
            backend: self.backend.crash(),
            state: Default::default(),
        }
    }
    fn mutate(&self) -> std::io::Result<()> {
        let mut state = self.state.lock();
        if let Some(remaining) = &mut state.remaining {
            if *remaining == 0 {
                return Err(std::io::Error::other("injected storage failure"));
            }
            *remaining -= 1;
        }
        state.operations += 1;
        Ok(())
    }
}
impl kasumi_kv::SegmentGroupBackend for FaultBackend {
    fn reserve_transaction(
        &self,
        plan: &kasumi_kv::TransactionSpacePlan,
    ) -> std::result::Result<(), kasumi_kv::TransactionReserveError> {
        self.backend.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.backend.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.backend.cancel_transaction(group_id, batch_seq)
    }

    fn read_root(
        &self,
        slot: kasumi_kv::RootSlot,
        out: &mut [u8; kasumi_kv::ROOT_SLOT_BYTES],
    ) -> std::io::Result<()> {
        self.backend.read_root(slot, out)
    }
    fn write_root(
        &self,
        slot: kasumi_kv::RootSlot,
        bytes: &[u8; kasumi_kv::ROOT_SLOT_BYTES],
    ) -> std::io::Result<()> {
        self.mutate()?;
        self.backend.write_root(slot, bytes)
    }
    fn sync_root(&self) -> std::io::Result<()> {
        self.mutate()?;
        self.backend.sync_root()?;
        let mut state = self.state.lock();
        state.syncs += 1;
        if let Some((clock, elapsed)) = state.advance_on_sync.take() {
            clock.advance(elapsed);
        }
        Ok(())
    }
    fn visit_entries(
        &self,
        visitor: &mut dyn FnMut(&std::ffi::OsStr) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        self.backend.visit_entries(visitor)
    }
    fn exists(&self, file: kasumi_kv::GroupFile) -> std::io::Result<bool> {
        self.backend.exists(file)
    }
    fn create(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
        self.mutate()?;
        self.backend.create(file)
    }
    fn len(&self, file: kasumi_kv::GroupFile) -> std::io::Result<u64> {
        self.backend.len(file)
    }
    fn read(&self, file: kasumi_kv::GroupFile, at: u64, out: &mut [u8]) -> std::io::Result<()> {
        self.backend.read(file, at, out)
    }
    fn write(&self, file: kasumi_kv::GroupFile, at: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.mutate()?;
        self.backend.write(file, at, bytes)
    }
    fn set_len(&self, file: kasumi_kv::GroupFile, length: u64) -> std::io::Result<()> {
        self.mutate()?;
        self.backend.set_len(file, length)
    }
    fn sync(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
        self.mutate()?;
        self.backend.sync(file)?;
        self.state.lock().syncs += 1;
        Ok(())
    }
    fn unlink(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
        self.mutate()?;
        self.backend.unlink(file)
    }
    fn sync_names(&self) -> std::io::Result<()> {
        self.mutate()?;
        self.backend.sync_names()
    }
    fn close(&self) -> kasumi_kv::BackendCloseOutcome {
        self.backend.close()
    }
}

// An absent destination must be created beneath an already installed owner.
// Select that owner using the destination as a prospective leaf; for an existing
// directory, retain the original fixture root selection via a child anchor.
// Consumer constructors then perform exact managed open_or_create acquisition.
fn fixture_directory_owner(
    root: &std::path::Path,
    memory: std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>,
) -> anyhow::Result<std::sync::Arc<crate::NodeDisk>> {
    let anchor = root.join("directory-accounting-anchor");
    if let Some(owner) =
        retry_disk_registry(|| crate::NodeDisk::fixture_registered_for_path(&anchor, &memory))?
    {
        return Ok(owner);
    }
    let selection = if root.try_exists()? {
        anchor
    } else {
        root.to_owned()
    };
    retry_disk_registry(|| crate::NodeDisk::fixture_for_path(&selection, memory.clone()))
        .map_err(Into::into)
}

impl crate::FilesystemAuditArchive {
    pub fn open_fixture(
        root: impl AsRef<std::path::Path>,
        memory: std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>,
    ) -> anyhow::Result<Self> {
        let root = root.as_ref();
        let disk = fixture_directory_owner(root, memory)?;
        Self::open(root, disk)
    }
}

/// Fixture owner marked into test backup roots. It is never an installed
/// identity; production roots are marked only by `enroll`.
pub const BACKUP_DESTINATION_OWNER: kasumi_types::TrustVerifierIdentity =
    kasumi_types::TrustVerifierIdentity {
        installation_id: uuid::Uuid::from_u128(0x7d3e_61a0_52c4_4f19_9b1e_0c55_28d6_a3f4),
        node_id: 1,
    };

impl crate::FilesystemBackupDestination {
    /// The former raw constructor, now a fixture only: it creates or adopts the
    /// root and marks an unmarked one with `BACKUP_DESTINATION_OWNER`, so every
    /// operation still runs through the enrolled verification path.
    pub fn new(
        root: impl AsRef<std::path::Path>,
        max_bytes: usize,
        disk: std::sync::Arc<crate::NodeDisk>,
    ) -> anyhow::Result<Self> {
        ensure!(max_bytes > 0, "backup byte limit must be positive");
        let root = crate::backup_sessions::filesystem::EnrolledRoot::fixture(
            root.as_ref(),
            disk,
            &BACKUP_DESTINATION_OWNER,
        )?;
        Ok(Self::from_enrolled(root, max_bytes))
    }

    pub fn new_fixture(
        root: impl AsRef<std::path::Path>,
        max_bytes: usize,
        memory: std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>,
    ) -> anyhow::Result<Self> {
        let root = root.as_ref();
        let disk = fixture_directory_owner(root, memory)?;
        Self::new(root, max_bytes, disk)
    }
}

#[cfg(test)]
mod fixture_directory_tests {
    use super::*;

    #[test]
    fn consumer_fixture_creation_uses_the_installed_owner_with_a_live_file() {
        let root = private_tempdir().unwrap();
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk = retry_disk_registry(|| {
            crate::NodeDisk::fixture_for_path(root.path().join("owned"), memory.clone())
        })
        .unwrap();
        let file = disk
            .create_file(
                "fixture",
                std::path::Path::new("owned"),
                crate::DiskWork::Foreground,
            )
            .unwrap();
        let before = disk.snapshot();
        let archive = crate::FilesystemAuditArchive::open_fixture(
            root.path().join("archive"),
            memory.clone(),
        )
        .unwrap();
        let backup = crate::FilesystemBackupDestination::new_fixture(
            root.path().join("backup"),
            64 << 20,
            memory.clone(),
        )
        .unwrap();
        let after = disk.snapshot();
        assert_eq!(after.phase, crate::NodeDiskPhase::Open);
        assert_eq!(after.open_files, before.open_files);
        // The backup root is enrolled with its fixed marker file.
        assert_eq!(after.persistent_files, before.persistent_files + 1);
        assert_eq!(
            after.persistent_directories,
            before.persistent_directories + 2
        );
        assert_eq!(file.observed_len().unwrap(), 0);
        drop((archive, backup, file));
        disk.reconcile(&crate::CensusCancellation::default())
            .unwrap();
        assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
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
    impl kasumi_kv::SegmentGroupBackend for UntouchedBackend {
        fn reserve_transaction(
            &self,
            _plan: &kasumi_kv::TransactionSpacePlan,
        ) -> std::result::Result<(), kasumi_kv::TransactionReserveError> {
            panic!("foreign-core backend was touched")
        }
        fn finish_transaction(&self, _group_id: [u8; 16], _batch_seq: u64) -> std::io::Result<()> {
            panic!("foreign-core backend was touched")
        }
        fn cancel_transaction(&self, _group_id: [u8; 16], _batch_seq: u64) -> std::io::Result<()> {
            panic!("foreign-core backend was touched")
        }

        fn read_root(
            &self,
            _slot: kasumi_kv::RootSlot,
            _out: &mut [u8; kasumi_kv::ROOT_SLOT_BYTES],
        ) -> std::io::Result<()> {
            panic!("foreign-core backend was touched")
        }
        fn write_root(
            &self,
            _slot: kasumi_kv::RootSlot,
            _bytes: &[u8; kasumi_kv::ROOT_SLOT_BYTES],
        ) -> std::io::Result<()> {
            panic!("foreign-core backend was touched")
        }
        fn sync_root(&self) -> std::io::Result<()> {
            panic!("foreign-core backend was touched")
        }
        fn visit_entries(
            &self,
            _visitor: &mut dyn FnMut(&std::ffi::OsStr) -> std::io::Result<()>,
        ) -> std::io::Result<()> {
            panic!("foreign-core backend was touched")
        }
        fn exists(&self, _file: kasumi_kv::GroupFile) -> std::io::Result<bool> {
            panic!("foreign-core backend was touched")
        }
        fn create(&self, _file: kasumi_kv::GroupFile) -> std::io::Result<()> {
            panic!("foreign-core backend was touched")
        }
        fn len(&self, _file: kasumi_kv::GroupFile) -> std::io::Result<u64> {
            panic!("foreign-core backend was touched")
        }
        fn read(
            &self,
            _file: kasumi_kv::GroupFile,
            _at: u64,
            _out: &mut [u8],
        ) -> std::io::Result<()> {
            panic!("foreign-core backend was touched")
        }
        fn write(
            &self,
            _file: kasumi_kv::GroupFile,
            _at: u64,
            _bytes: &[u8],
        ) -> std::io::Result<()> {
            panic!("foreign-core backend was touched")
        }
        fn set_len(&self, _file: kasumi_kv::GroupFile, _length: u64) -> std::io::Result<()> {
            panic!("foreign-core backend was touched")
        }
        fn sync(&self, _file: kasumi_kv::GroupFile) -> std::io::Result<()> {
            panic!("foreign-core backend was touched")
        }
        fn unlink(&self, _file: kasumi_kv::GroupFile) -> std::io::Result<()> {
            panic!("foreign-core backend was touched")
        }
        fn sync_names(&self) -> std::io::Result<()> {
            panic!("foreign-core backend was touched")
        }
        fn close(&self) -> kasumi_kv::BackendCloseOutcome {
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
                persistent_directory.path().join("node.kv"),
                memory.clone(),
            )
        })
        .unwrap();
        let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
        let foreign = crate::ScratchDisk::fixture(foreign_directory.path(), foreign_memory.clone());
        let before = memory.snapshot();
        let foreign_before = foreign_memory.snapshot();
        let error = crate::NodeStore::create_fixture_backend_on_disk(
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
        assert!(!persistent_directory.path().join("node.kv").exists());

        let backend = FaultBackend::new();
        let node = crate::NodeStore::create_fixture_backend_on_disk(
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
        assert!(!persistent_directory.path().join("node.kv").exists());
    }
}

// Diagnostic-only renderings preserve the exact typed observations and never
// acknowledge a retained operation. Used only when an existing assertion fails.
#[cfg(test)]
pub(crate) fn observation_diagnostic<E: std::fmt::Debug>(
    observation: kasumi_kv::TerminalObservation<'_, E>,
) -> String {
    match observation {
        kasumi_kv::TerminalObservation::NotEntered => "NotEntered".into(),
        kasumi_kv::TerminalObservation::Entered => "Entered".into(),
        kasumi_kv::TerminalObservation::Returned(result) => format!("{result:?}"),
        kasumi_kv::TerminalObservation::Panicked(payload) => format!(
            "Panicked(str={:?}, u64={:?})",
            payload.downcast_ref::<&str>(),
            payload.downcast_ref::<u64>()
        ),
    }
}
#[cfg(test)]
pub(crate) fn native_write_diagnostic<E: std::fmt::Debug>(
    phase: crate::NodeWriterPhase,
    begin: kasumi_kv::TerminalObservation<'_, kasumi_kv::TransactionError>,
    body: kasumi_kv::TerminalObservation<'_, E>,
    outer: kasumi_kv::TerminalObservation<'_, std::convert::Infallible>,
    terminal: Option<kasumi_kv::WriteTerminalReport<'_>>,
) -> String {
    let native = terminal.map(|report| {
        format!(
            "operation={:?}, settlement={:?}, terminal={}, rollback={}, disposal={}",
            report.operation(),
            report.settlement(),
            observation_diagnostic(report.terminal()),
            observation_diagnostic(report.rollback()),
            observation_diagnostic(report.disposal())
        )
    });
    format!(
        "phase={phase:?}, begin={}, body={}, outer={}, native={native:?}",
        observation_diagnostic(begin),
        observation_diagnostic(body),
        observation_diagnostic(outer)
    )
}

// One fixed, thread-local fault slot, scoped to the actual binding insert and
// exact installed provider. Its backing is charged by the arm before use.
#[cfg(test)]
#[derive(Clone, Copy)]
struct BindingStagingFault {
    provider: usize,
    depth: usize,
    entries: usize,
    denials: usize,
    requests: [u64; 2],
}
#[cfg(test)]
std::thread_local! {
    static BINDING_STAGING_FAULT: std::cell::Cell<Option<BindingStagingFault>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(crate) struct BindingStagingDenial<'a> {
    memory: &'a std::sync::Arc<TestDiskMemory>,
    previous: Option<BindingStagingFault>,
    charge: Option<crate::DiskMemoryLease>,
    // Arm and scope guards must be destroyed on their originating thread.
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
#[cfg(test)]
impl TestDiskMemory {
    pub(crate) fn deny_binding_staging(
        self: &std::sync::Arc<Self>,
    ) -> std::io::Result<BindingStagingDenial<'_>> {
        use crate::NodeDiskMemoryAdmission;
        // No heap TLS or request log: one fixed slot and two stack guards.
        let bytes = (std::mem::size_of::<std::cell::Cell<Option<BindingStagingFault>>>()
            + std::mem::size_of::<BindingStagingDenial<'_>>()
            + std::mem::size_of::<BindingStagingScope>()) as u64;
        let charge = self.clone().reserve_installed(bytes)?;
        let fault = BindingStagingFault {
            provider: std::sync::Arc::as_ptr(self) as usize,
            depth: 0,
            entries: 0,
            denials: 0,
            requests: [0; 2],
        };
        let previous = BINDING_STAGING_FAULT.with(|slot| slot.replace(Some(fault)));
        Ok(BindingStagingDenial {
            memory: self,
            previous,
            charge: Some(charge),
            _thread: std::marker::PhantomData,
        })
    }
}
#[cfg(test)]
impl BindingStagingDenial<'_> {
    pub(crate) fn assert_refused_chunk_and_fallback(&self) {
        let fault = BINDING_STAGING_FAULT.with(|slot| slot.get()).unwrap();
        assert_eq!(fault.provider, std::sync::Arc::as_ptr(self.memory) as usize);
        assert_eq!(fault.depth, 0, "binding insert scope did not unwind");
        assert_eq!(fault.entries, 1, "expected one actual binding insert");
        assert_eq!(
            fault.denials, 2,
            "chunk and exact fallback must both be denied"
        );
        // Native staging first requests its 64 KiB chunk plus lease/wrapper
        // backing, then the smaller exact row deficit plus that same backing.
        assert!(fault.requests[0] > 64 << 10, "{:?}", fault.requests);
        assert!(
            fault.requests[1] > 0 && fault.requests[1] < fault.requests[0],
            "{:?}",
            fault.requests
        );
    }
}
#[cfg(test)]
impl Drop for BindingStagingDenial<'_> {
    fn drop(&mut self) {
        BINDING_STAGING_FAULT.with(|slot| slot.set(self.previous));
        // Uninstall TLS observations before refunding their backing, including
        // on unwind or after a nested arm restores its predecessor.
        drop(self.charge.take());
    }
}

#[cfg(test)]
pub(crate) struct BindingStagingScope {
    previous_depth: Option<usize>,
    provider: usize,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
#[cfg(test)]
impl BindingStagingScope {
    pub(crate) fn enter(provider: &std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>) -> Self {
        let provider = std::sync::Arc::as_ptr(provider) as *const () as usize;
        let previous_depth = BINDING_STAGING_FAULT.with(|slot| {
            let mut fault = slot.get()?;
            if fault.provider != provider {
                return None;
            }
            let previous = fault.depth;
            fault.depth = fault.depth.checked_add(1).unwrap();
            fault.entries = fault.entries.checked_add(1).unwrap();
            slot.set(Some(fault));
            Some(previous)
        });
        Self {
            previous_depth,
            provider,
            _thread: std::marker::PhantomData,
        }
    }
}
#[cfg(test)]
impl Drop for BindingStagingScope {
    fn drop(&mut self) {
        if let Some(previous_depth) = self.previous_depth {
            BINDING_STAGING_FAULT.with(|slot| {
                if let Some(mut fault) = slot.get().filter(|fault| fault.provider == self.provider)
                {
                    fault.depth = previous_depth;
                    slot.set(Some(fault));
                }
            });
        }
    }
}
#[cfg(test)]
fn binding_staging_refuses(provider: usize, bytes: u64) -> bool {
    BINDING_STAGING_FAULT.with(|slot| {
        let Some(mut fault) = slot.get() else {
            return false;
        };
        if fault.provider != provider || fault.depth == 0 {
            return false;
        }
        assert!(
            fault.denials < fault.requests.len(),
            "unexpected additional staging grant"
        );
        fault.requests[fault.denials] = bytes;
        fault.denials += 1;
        slot.set(Some(fault));
        true
    })
}

#[cfg(test)]
impl TestDiskMemory {
    /// Arm the exact most recently admitted actual lease, after construction.
    /// Injection runs only after its real accounting release and mutex unlock.
    pub(crate) fn panic_on_last_point_lease_drop(&self, payload: Box<dyn std::any::Any + Send>) {
        let id = self.state.lock().unwrap().attempts;
        let mut pending = self.point_drop_panic.lock().unwrap();
        assert!(pending.is_none());
        *pending = Some((id, payload));
    }
}
