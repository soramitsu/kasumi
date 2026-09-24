//! Encrypted durable records for both local execution and Raft persistence.
//!
//! Only wrapped keys and opaque tenant identifiers are stored in control metadata.
//! Record namespaces, keys and values are authenticated and encrypted before redb.
//! redb's immediate, two-phase commits persist each batch atomically. Host filesystem,
//! kernel, device durability and the embedding process are trusted. A successful
//! store call can return owned plaintext to its caller; that copy is not revocable.

mod archive_objects;
mod audit_archive;
pub use audit_archive::{
    AuditArchiveDestination, AuditArchivePublicationObserver, AuditSegmentBuilder,
    FilesystemAuditArchive, HistoricalAuditVerifier, InspectedAuditDependency,
    PreparedAuditSegment, S3AuditArchive, TenantAuditPlacement, VerifiedAuditSegment,
};
mod backup;
mod backup_sessions;
pub use backup_sessions::{
    BackupSessionObject, BackupSessionObjectPage, BackupSessionObjects, BackupSessionSlot,
    MAX_SESSION_GC_OBJECTS, MAX_SESSION_RECORD_BYTES, VerifiedBackupAbort, VerifiedBackupSession,
    verify_backup_session,
};
#[cfg(test)]
mod allocation_tests;
mod device_disk;
mod disk_memory;
pub use disk_memory::{
    DiskMemoryLease, DiskMemoryRequirements, DiskOpenError, NodeDiskMemoryAdmission,
};
mod keys;
mod node_database;
mod node_disk;
mod node_file;
pub use node_file::NodeFileCleanup;
pub mod node_store_ids;
mod read_view;
pub use node_disk::{
    CensusCancellation, DirectoryPolicy, DiskWork, NodeDisk, NodeDiskConfig, NodeDiskDirectory,
    NodeDiskFile, NodeDiskPhase, NodeDiskSnapshot,
};
mod scratch_disk;
mod scratch_table;
pub use scratch_disk::{ScratchDisk, ScratchDiskConfig, ScratchDiskSnapshot};
mod serving_access;
mod spool;
pub use read_view::TenantReadView;
pub use scratch_table::EncryptedTable;
mod storage_domains;
pub use serving_access::{StorageAccess, StoragePurpose};
mod file_keys;
mod live_trust;
pub mod private_files;
pub use file_keys::FileKeyProvider;
pub use spool::{EncryptedSpool, SnapshotImage, SnapshotReader};
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use backup::{
    BackupContents, BackupDestination, EncryptedBackup, FilesystemBackupDestination,
    S3BackupConfig, S3BackupDestination,
};
pub use backup::{MAX_BACKUP_BUNDLE_BYTES, MAX_BACKUP_OBJECT_BYTES};
use kasumi_clock::{LeaseClock, SystemLeaseClock};
use kasumi_types::drain::{DrainReport, DrainResult};
pub use keys::{
    GeneratedKey, KeyProvider, SecretKey, TransitConfig, TransitKeyProvider, WrappedKey,
};
pub use storage_domains::{CustodyStore, StorageBinding, TenantStorageSet};

use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hmac::{Hmac, Mac};
use parking_lot::{Mutex, RwLock};
use redb::{Database, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as AsyncMutex, watch};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const CATALOG: TableDefinition<&[u8], &[u8]> = TableDefinition::new("wrapped_keys_v1");
const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("encrypted_records_v1");
pub const MAX_KEY_LEASE: Duration = Duration::from_secs(60);
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RECORD: usize = 32 * 1024 * 1024;
const MAX_BATCH: usize = 64 * 1024 * 1024;
const INDEX_KEY: &str = "index";
// A manifest repeats the tenant (at most 1024 UTF-8 bytes, or 6144 JSON
// escape bytes) and adds a UUID, fixed field names and bounded integers.
// Keep that framing available before accepting any wrapping-key change.
const MAX_KEY_CATALOG_BYTES: usize = backup::HEADER_LIMIT - (16 << 10);

#[derive(Clone, Debug)]
pub enum WriteOp {
    Put {
        namespace: String,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        namespace: String,
        key: Vec<u8>,
    },
}

impl WriteOp {
    pub fn put(
        namespace: impl Into<String>,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Self {
        Self::Put {
            namespace: namespace.into(),
            key: key.into(),
            value: value.into(),
        }
    }
    pub fn delete(namespace: impl Into<String>, key: impl Into<Vec<u8>>) -> Self {
        Self::Delete {
            namespace: namespace.into(),
            key: key.into(),
        }
    }
}

#[derive(Default)]
struct InitializerRegistry {
    handles: Vec<tokio::task::JoinHandle<Result<()>>>,
    // A joined failure is still unreported while a cancelled drain has more
    // owners to await. Keep that outcome with the surviving task registry.
    failure: Option<anyhow::Error>,
}
impl InitializerRegistry {
    async fn reap_finished(&mut self) -> Result<()> {
        while let Some(index) = self
            .handles
            .iter()
            .position(tokio::task::JoinHandle::is_finished)
        {
            let result = (&mut self.handles[index]).await;
            drop(self.handles.swap_remove(index));
            if let Err(error) = result
                .context("catalog initializer task join failed")
                .and_then(|outcome| outcome)
            {
                self.failure.get_or_insert(error);
            }
        }
        self.take_failure()
    }
    fn take_failure(&mut self) -> Result<()> {
        self.failure.take().map_or(Ok(()), |error| {
            Err(error.context("catalog initializer task failed"))
        })
    }
}

pub struct NodeStore {
    db: node_database::NodeDatabase,
    persistent_disk: Option<Arc<NodeDisk>>,
    scratch_disk: Arc<ScratchDisk>,
    path: Option<PathBuf>,
    tenants: AsyncMutex<HashMap<String, Arc<AsyncMutex<Weak<TenantStore>>>>>,
    // Retain initialization tasks through rejected/cancelled result delivery.
    initializers: AsyncMutex<InitializerRegistry>,
    shutdown_report: AsyncMutex<DrainReport>,
}

impl NodeStore {
    /// Claim an exact recognized Prepared or Ready inode for independently
    /// authorized cleanup. No redb open, initialization or repair takes place.
    /// This physical guard grants no authority to stop or delete a generation.
    pub fn claim_cleanup(
        path: impl AsRef<Path>,
        expected_id: Uuid,
        persistent_disk: Arc<NodeDisk>,
    ) -> Result<NodeFileCleanup> {
        node_file::NodeFile::claim_cleanup(path.as_ref(), expected_id, persistent_disk)
    }

    /// Initialize a new, exclusively created inode. Its parent must exist.
    /// The caller durably chooses `node_store_id` before creating the file and
    /// retains responsibility for exact partial/uncertain initialization cleanup.
    pub fn create_new(
        path: impl AsRef<Path>,
        node_store_id: Uuid,
        persistent_disk: Arc<NodeDisk>,
        scratch_disk: Arc<ScratchDisk>,
    ) -> Result<Arc<Self>> {
        ensure!(
            Arc::ptr_eq(persistent_disk.memory(), scratch_disk.memory()),
            "persistent and scratch disks require the same installed memory admission"
        );
        Self::initialize(
            node_file::NodeFile::create_new(path.as_ref(), node_store_id, persistent_disk)?,
            scratch_disk,
        )
    }

    /// Initialize the exact empty inode already durably owned by an installation
    /// or recovery journal. A populated/partial file is never adopted or reset.
    pub fn initialize_owned_empty(
        path: impl AsRef<Path>,
        expected_file: &private_files::FileIdentity,
        node_store_id: Uuid,
        persistent_disk: Arc<NodeDisk>,
        scratch_disk: Arc<ScratchDisk>,
    ) -> Result<Arc<Self>> {
        ensure!(
            Arc::ptr_eq(persistent_disk.memory(), scratch_disk.memory()),
            "persistent and scratch disks require the same installed memory admission"
        );
        Self::initialize(
            node_file::NodeFile::initialize_owned_empty(
                path.as_ref(),
                expected_file,
                node_store_id,
                persistent_disk,
            )?,
            scratch_disk,
        )
    }

    fn initialize(
        file: Arc<node_file::NodeFile>,
        scratch_disk: Arc<ScratchDisk>,
    ) -> Result<Arc<Self>> {
        let db = Database::builder(file.clone()).create_with_backend(file.backend())?;
        Self::initialize_tables(&db)?;
        file.publish_ready()?;
        Ok(Self::installed(
            db,
            Some(file.path().to_owned()),
            Some(file.disk().clone()),
            scratch_disk,
        ))
    }

    /// Reject unknown/partial files and a different installed UUID before redb
    /// can write. The exact locked descriptor survives validation and recovery.
    /// A recognized owned payload may need redb recovery bookkeeping even if a
    /// later table, tenant, or bootstrap check rejects its logical contents.
    pub fn open_existing(
        path: impl AsRef<Path>,
        expected_id: Uuid,
        persistent_disk: Arc<NodeDisk>,
        scratch_disk: Arc<ScratchDisk>,
    ) -> Result<Arc<Self>> {
        ensure!(
            Arc::ptr_eq(persistent_disk.memory(), scratch_disk.memory()),
            "persistent and scratch disks require the same installed memory admission"
        );
        let file = node_file::NodeFile::open_existing(path.as_ref(), expected_id, persistent_disk)?;
        let db = Database::builder(file.clone()).create_with_backend(file.backend())?;
        {
            let tx = db.begin_read()?;
            tx.open_table(CATALOG)?;
            tx.open_table(RECORDS)?;
        }
        Ok(Self::installed(
            db,
            Some(file.path().to_owned()),
            Some(file.disk().clone()),
            scratch_disk,
        ))
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn open_with_backend(
        backend: impl redb::StorageBackend,
        admission: Arc<dyn redb::StorageAdmission>,
        scratch_disk: Arc<ScratchDisk>,
    ) -> Result<Arc<Self>> {
        let db = Database::builder(admission).create_with_backend(backend)?;
        Self::initialize_tables(&db)?;
        Ok(Self::installed(db, None, None, scratch_disk))
    }

    /// Every production node has one mandatory installed physical owner.
    pub fn persistent_disk(&self) -> &Arc<NodeDisk> {
        self.persistent_disk
            .as_ref()
            .expect("synthetic backend fixture has no installed physical disk")
    }

    /// Stop new database work, join retained initializers, then explicitly close
    /// redb. The caller first drains its tenant and Raft workers. Busy retains
    /// the exact database and all physical charges for a later shutdown retry.
    pub async fn shutdown(&self) -> DrainResult {
        self.db.stop();
        let mut report = self.shutdown_report.lock().await;
        if let Err(error) = self.drain_initializers().await {
            report.record("node catalog initialization", 0, error);
        }
        match self.db.close() {
            Ok(()) => report.complete(),
            Err(failure)
                if failure.completion() == kasumi_types::drain::DrainCompletion::Retained =>
            {
                report.outcome(Some(failure))
            }
            Err(failure) => {
                report.merge(&failure);
                report.complete()
            }
        }
    }

    /// Every temporary image/table on this node shares this explicit owner.
    pub fn scratch_disk(&self) -> &Arc<ScratchDisk> {
        &self.scratch_disk
    }

    fn initialize_tables(db: &Database) -> Result<()> {
        let tx = db.begin_write()?;
        {
            tx.open_table(CATALOG)?;
            tx.open_table(RECORDS)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn installed(
        db: Database,
        path: Option<PathBuf>,
        persistent_disk: Option<Arc<NodeDisk>>,
        scratch_disk: Arc<ScratchDisk>,
    ) -> Arc<Self> {
        Arc::new(Self {
            db: node_database::NodeDatabase::new(db, "node database"),
            persistent_disk,
            scratch_disk,
            path,
            tenants: AsyncMutex::new(HashMap::new()),
            initializers: AsyncMutex::new(InitializerRegistry::default()),
            shutdown_report: AsyncMutex::new(DrainReport::default()),
        })
    }

    fn catalog(&self, tenant: &str) -> Result<Option<KeyCatalog>> {
        Self::catalog_at(&self.db.begin_read()?, tenant)
    }

    fn catalog_at(tx: &redb::ReadTransaction, tenant: &str) -> Result<Option<KeyCatalog>> {
        let table = tx.open_table(CATALOG)?;
        table
            .get(tenant_hash(tenant).as_slice())?
            .map(|v| {
                ensure!(
                    v.value().len() <= MAX_KEY_CATALOG_BYTES,
                    "key catalog byte quota exceeded"
                );
                let catalog: KeyCatalog =
                    serde_json::from_slice(v.value()).context("invalid key catalog")?;
                catalog.validate(tenant)?;
                Ok(catalog)
            })
            .transpose()
    }

    fn save_catalog(&self, tenant: &str, catalog: &KeyCatalog) -> Result<()> {
        catalog.validate(tenant)?;
        let bytes = serde_json::to_vec(catalog)?;
        let tx = self.db.begin_write()?;
        {
            tx.open_table(CATALOG)?
                .insert(tenant_hash(tenant).as_slice(), bytes.as_slice())?;
        }
        tx.commit().context("committing wrapped-key catalog")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyCatalog {
    format: u32,
    catalog_id: Uuid,
    tenant: String,
    purpose: StoragePurpose,
    active: String,
    keys: BTreeMap<String, WrappedKey>,
}

impl KeyCatalog {
    fn validate(&self, tenant: &str) -> Result<()> {
        ensure!(
            !tenant.is_empty() && tenant.len() <= 1024,
            "invalid catalog tenant"
        );
        ensure!(
            self.format == 1 && !self.catalog_id.is_nil() && self.tenant == tenant,
            "key catalog tenant/format mismatch"
        );
        ensure!(
            self.active != INDEX_KEY
                && self.keys.contains_key(&self.active)
                && self.keys.contains_key(INDEX_KEY),
            "invalid key catalog"
        );
        ensure!(self.keys.len() <= 1024, "too many retained data keys");
        // Count exact serialized bytes without building a second catalog buffer.
        // Stop at the limit even for a malformed or oversized provider response.
        struct Budget(usize);
        impl std::io::Write for Budget {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_add(bytes.len())
                    .filter(|size| *size <= MAX_KEY_CATALOG_BYTES)
                    .ok_or_else(|| std::io::Error::other("key catalog byte quota exceeded"))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(Budget(0), self).context("key catalog byte quota exceeded")?;
        Ok(())
    }
}

struct KeyState {
    keys: BTreeMap<String, SecretKey>,
    deadline: Duration,
    sealed: bool,
}

#[derive(Zeroize, zeroize::ZeroizeOnDrop)]
struct DecodedRecord {
    namespace: String,
    key: Vec<u8>,
    value: Vec<u8>,
}

/// A tenant's per-replica key cache. All keys are zeroized when the cache is sealed.
/// Consumers holding resident documents must also discard their own copies on the
/// `seal_notifications()` signal and gate response emission with `check_access()`.
pub struct TenantStore {
    node: Arc<NodeStore>,
    tenant: String,
    access: StorageAccess,
    provider: Arc<dyn KeyProvider>,
    catalog: RwLock<KeyCatalog>,
    state: RwLock<KeyState>,
    mutations: Mutex<()>,
    refresh: AsyncMutex<()>,
    clock: Arc<dyn LeaseClock>,
    seal_notifier: watch::Sender<u64>,
    // Low bit closes admission; the remaining bits invalidate in-flight probes.
    access_epoch: AtomicU64,
    shutdown_requested: AtomicBool,
    shutdown_signal: watch::Sender<bool>,
    background: AsyncMutex<BackgroundTasks>,
    audit_placement: Mutex<Option<Arc<TenantAuditPlacement>>>,
    live_trust: Mutex<
        BTreeMap<
            String,
            (
                Weak<kasumi_serving::LiveSignerTrust>,
                kasumi_serving::BackgroundWorkScope,
            ),
        >,
    >,
}

#[derive(Default)]
struct BackgroundTasks {
    started: bool,
    handles: Vec<tokio::task::JoinHandle<()>>,
    report: DrainReport,
}

mod single_catalog;

impl Drop for TenantStore {
    fn drop(&mut self) {
        for task in &self.background.get_mut().handles {
            task.abort();
        }
    }
}

/// Release any expired cached keys after method-local key guards have dropped,
/// including early-return/error paths and cancellation of asynchronous probes.
struct AccessGuard<'a>(&'a TenantStore);
impl Drop for AccessGuard<'_> {
    fn drop(&mut self) {
        let _ = self.0.check_access();
    }
}

impl TenantStore {
    pub fn persistent_disk(&self) -> &Arc<NodeDisk> {
        self.node.persistent_disk()
    }

    pub fn scratch_disk(&self) -> &Arc<ScratchDisk> {
        self.node.scratch_disk()
    }

    /// Construct an unpublished owner. The caller retains its open gate until
    /// either publication or completed shutdown of this exact new owner.
    fn unpublished(
        node: Arc<NodeStore>,
        tenant: String,
        provider: Arc<dyn KeyProvider>,
        access: StorageAccess,
        clock: Arc<dyn LeaseClock>,
        catalog: KeyCatalog,
    ) -> Arc<Self> {
        let (seal_notifier, _) = watch::channel(0);
        let (shutdown_signal, _) = watch::channel(false);
        Arc::new(Self {
            node: node.clone(),
            tenant: tenant.clone(),
            access,
            provider,
            catalog: RwLock::new(catalog),
            state: RwLock::new(KeyState {
                keys: BTreeMap::new(),
                deadline: Duration::ZERO,
                sealed: true,
            }),
            mutations: Mutex::new(()),
            refresh: AsyncMutex::new(()),
            clock,
            seal_notifier,
            access_epoch: AtomicU64::new(1),
            shutdown_requested: AtomicBool::new(false),
            shutdown_signal,
            background: AsyncMutex::new(BackgroundTasks::default()),
            audit_placement: Mutex::new(None),
            live_trust: Mutex::new(BTreeMap::new()),
        })
    }

    async fn generate_catalog(
        tenant: &str,
        provider: &Arc<dyn KeyProvider>,
        access: &StorageAccess,
    ) -> Result<KeyCatalog> {
        access.check()?;
        let root = tokio::time::timeout(PROVIDER_TIMEOUT, provider.generate_key(tenant))
            .await
            .context("key generation timed out")??;
        access.check()?;
        let data = tokio::time::timeout(PROVIDER_TIMEOUT, provider.generate_key(tenant))
            .await
            .context("key generation timed out")??;
        access.check()?;
        let active = Uuid::new_v4().to_string();
        let catalog = KeyCatalog {
            format: 1,
            catalog_id: Uuid::new_v4(),
            tenant: tenant.to_owned(),
            purpose: access.purpose().clone(),
            active: active.clone(),
            keys: BTreeMap::from([(INDEX_KEY.to_owned(), root.wrapped), (active, data.wrapped)]),
        };
        catalog.validate(tenant)?;
        Ok(catalog)
    }

    #[cfg(test)]
    async fn start_renewal(store: &Arc<Self>) {
        let (ready, receive) = watch::channel(true);
        Self::prepare_renewal(store, receive).await;
        drop(ready);
    }

    /// Register dormant workers before a prepared owner becomes visible. Their
    /// first key probe cannot run before the synchronous handoff commits.
    async fn prepare_renewal(store: &Arc<Self>, ready: watch::Receiver<bool>) {
        let mut background = store.background.lock().await;
        if background.started || store.shutdown_requested.load(Ordering::Acquire) {
            return;
        }
        background.started = true;
        let weak = Arc::downgrade(store);
        let mut checking_ready = ready.clone();
        let mut stopping = store.shutdown_signal.subscribe();
        background.handles.push(tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = stopping.wait_for(|stopped| *stopped) => return,
                ready = checking_ready.wait_for(|ready| *ready) => if ready.is_err() { return; },
            }
            loop {
                tokio::select! {
                    biased;
                    _ = stopping.wait_for(|stopped| *stopped) => return,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                }
                let Some(store) = weak.upgrade() else { return };
                if store.check_access().is_err() {
                    return;
                }
            }
        }));
        let weak = Arc::downgrade(store);
        let mut refreshing_ready = ready;
        let mut stopping = store.shutdown_signal.subscribe();
        background.handles.push(tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = stopping.wait_for(|stopped| *stopped) => return,
                ready = refreshing_ready.wait_for(|ready| *ready) => if ready.is_err() { return; },
            }
            let interval = Duration::from_secs(20);
            let mut schedule =
                tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            // Start-to-start cadence, without adding each provider's latency or
            // issuing a burst of catch-up decrypt requests after a delayed poll.
            schedule.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = stopping.wait_for(|stopped| *stopped) => return,
                    _ = schedule.tick() => {},
                }
                let Some(store) = weak.upgrade() else { return };
                // Sealing requires explicit recovery; a timer never silently unseals.
                if store.check_access().is_err() {
                    return;
                }
                tokio::select! {
                    biased;
                    _ = stopping.wait_for(|stopped| *stopped) => return,
                    refreshed = store.refresh_lease() => if refreshed.is_err() { return; },
                }
            }
        }));
    }

    /// Permanently close access, discard owned keys, and stop both lease tasks.
    ///
    /// Completion guarantees that background probes no longer retain this store
    /// or its node. Callers must also finish their own operations and drop all
    /// store/node handles before reopening the database file. Concurrent calls
    /// are safe; canceling this future leaves task handles available for a later
    /// call to finish waiting. A shutdown store cannot be refreshed or restarted.
    pub async fn shutdown(&self) -> DrainResult {
        self.shutdown_requested.store(true, Ordering::Release);
        self.shutdown_signal.send_replace(true);
        self.seal();
        let mut background = self.background.lock().await;
        // Cooperative stop returns normally. Any JoinError, including an abort
        // requested elsewhere before shutdown, is an actual terminal failure.
        // Await in place: dropping a shutdown future must not detach a task. Pop
        // each completed handle before awaiting another, because a completed
        // JoinHandle must never be polled twice by a subsequent shutdown caller.
        while let Some(task) = background.handles.last_mut() {
            let result = task.await;
            let index = background.handles.len() - 1;
            if let Err(error) = result {
                background
                    .report
                    .record("store worker", index, error.into());
            }
            background.handles.pop();
        }
        background.report.complete()
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    /// Archive defaults share the durable installation root. Test-only memory
    /// backends must supply an explicit archive destination instead.
    pub fn durable_directory(&self) -> Result<&Path> {
        self.node
            .path
            .as_deref()
            .and_then(Path::parent)
            .context("storage backend has no durable directory")
    }
    pub fn storage_access(&self) -> &StorageAccess {
        &self.access
    }
    pub fn generation(&self) -> u64 {
        self.access_epoch.load(Ordering::Acquire) >> 1
    }
    pub fn seal_notifications(&self) -> watch::Receiver<u64> {
        self.seal_notifier.subscribe()
    }

    pub fn seal(&self) {
        // Signal and close admission before waiting for any in-progress disk I/O
        // holding a shared key lock. Its release check observes revocation too.
        let previous = self
            .access_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                Some(epoch.wrapping_add(2) | 1)
            })
            .expect("unconditional epoch update");
        if previous & 1 == 0 {
            self.seal_notifier
                .send_replace(previous.wrapping_add(2) >> 1);
        }
        let mut state = self.state.write();
        if !state.sealed || !state.keys.is_empty() {
            state.sealed = true;
            state.keys.clear();
            state.deadline = Duration::ZERO;
        }
    }

    pub fn check_access(&self) -> Result<()> {
        if self.valid(&self.state.read()) {
            return Ok(());
        }
        self.seal();
        bail!("tenant is sealed: key-access lease unavailable or expired")
    }

    fn valid(&self, state: &KeyState) -> bool {
        self.access.check().is_ok()
            && !self.shutdown_requested.load(Ordering::Acquire)
            && self.access_epoch.load(Ordering::Acquire) & 1 == 0
            && !state.sealed
            && !state.keys.is_empty()
            && self.clock.now() < state.deadline
    }

    fn require_access(&self, state: &KeyState) -> Result<()> {
        ensure!(
            self.valid(state),
            "tenant is sealed: key-access lease unavailable or expired"
        );
        Ok(())
    }

    /// Each retained wrapping-key version is live-decrypted. No cached plaintext
    /// constitutes a lease probe; a late completion cannot lengthen the deadline.
    pub async fn refresh_lease(&self) -> Result<()> {
        let _access = AccessGuard(self);
        let _refresh = self.refresh.lock().await;
        self.access.check()?;
        ensure!(
            !self.shutdown_requested.load(Ordering::Acquire),
            "tenant store has shut down"
        );
        let start = self.clock.now();
        let epoch = self.access_epoch.load(Ordering::Acquire);
        let catalog = self.catalog.read().clone();
        let refresh = async {
            let mut keys = BTreeMap::new();
            for (id, wrapped) in &catalog.keys {
                self.access.check()?;
                keys.insert(
                    id.clone(),
                    self.provider.unwrap_key(&self.tenant, wrapped).await?,
                );
                self.access.check()?;
            }
            Ok::<_, anyhow::Error>(keys)
        };
        let result = tokio::time::timeout(PROVIDER_TIMEOUT, refresh).await;
        let keys = match result {
            Ok(Ok(keys)) => keys,
            Ok(Err(error)) => {
                self.seal();
                return Err(error.context("key-access probe failed"));
            }
            Err(_) => {
                self.seal();
                bail!("key-access probe timed out");
            }
        };
        let deadline = start
            .checked_add(MAX_KEY_LEASE)
            .context("key-access lease overflow")?;
        let mut state = self.state.write();
        self.access.check()?;
        ensure!(
            !self.shutdown_requested.load(Ordering::Acquire),
            "tenant store has shut down"
        );
        ensure!(
            self.clock.now() < deadline,
            "key-access probe completed after lease expiry"
        );
        self.access_epoch
            .compare_exchange(epoch, epoch & !1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| anyhow::anyhow!("tenant generation changed during key-access probe"))?;
        state.keys = keys;
        state.deadline = deadline;
        state.sealed = false;
        Ok(())
    }

    pub fn get(&self, namespace: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get_bounded(namespace, key, MAX_RECORD)
    }

    /// Reject an oversized encrypted record before allocating its plaintext.
    /// The exact value bound is checked again after authenticated decoding.
    pub fn get_bounded(
        &self,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<Vec<u8>>> {
        ensure!(
            max_value_bytes <= MAX_RECORD,
            "record read budget exceeds storage limit"
        );
        let _access = AccessGuard(self);
        validate_record(namespace, key, 0)?;
        self.check_access()?;
        let state = self.state.read();
        self.require_access(&state)?;
        let disk_key = record_key(
            &self.tenant,
            namespace,
            key,
            state.keys.get(INDEX_KEY).context("index key missing")?,
        );
        let tx = self.node.db.begin_read()?;
        let table = tx.open_table(RECORDS)?;
        let mut result = match table.get(disk_key.as_slice())? {
            Some(v) => {
                check_encrypted_record_budget(
                    v.value(),
                    namespace.len(),
                    key.len(),
                    max_value_bytes,
                )?;
                let record = self.decode_record(&disk_key, v.value(), &state)?;
                ensure!(
                    record.value.len() <= max_value_bytes,
                    "record value exceeds read budget"
                );
                ensure!(
                    record.namespace == namespace && record.key == key,
                    "record identity mismatch"
                );
                Some(record)
            }
            None => None,
        };
        self.require_access(&state)?;
        Ok(result
            .as_mut()
            .map(|record| std::mem::take(&mut record.value)))
    }

    /// Visits one authenticated record at a time without retaining a namespace's
    /// values. The callback runs synchronously under the current key lease and
    /// must bound its own accumulated result. It cannot perform async I/O.
    pub fn visit(
        &self,
        namespace: &str,
        max_value_bytes: usize,
        mut visitor: impl FnMut(&[u8], &[u8]) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            max_value_bytes <= MAX_RECORD,
            "record visit budget exceeds storage limit"
        );
        let _access = AccessGuard(self);
        validate_record(namespace, &[], 0)?;
        self.check_access()?;
        let state = self.state.read();
        self.require_access(&state)?;
        let prefix = namespace_prefix(
            &self.tenant,
            namespace,
            state.keys.get(INDEX_KEY).context("index key missing")?,
        );
        let tx = self.node.db.begin_read()?;
        let table = tx.open_table(RECORDS)?;
        for entry in table.range(prefix.as_slice()..)? {
            let (key, value) = entry?;
            if !key.value().starts_with(&prefix) {
                break;
            }
            self.require_access(&state)?;
            check_encrypted_record_budget(value.value(), namespace.len(), 4096, max_value_bytes)?;
            let record = self.decode_record(key.value(), value.value(), &state)?;
            ensure!(
                record.value.len() <= max_value_bytes,
                "record value exceeds visit budget"
            );
            ensure!(record.namespace == namespace, "record namespace mismatch");
            visitor(&record.key, &record.value)?;
        }
        self.require_access(&state)
    }

    pub fn scan(&self, namespace: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let _access = AccessGuard(self);
        validate_record(namespace, &[], 0)?;
        self.check_access()?;
        let state = self.state.read();
        self.require_access(&state)?;
        let prefix = namespace_prefix(
            &self.tenant,
            namespace,
            state.keys.get(INDEX_KEY).context("index key missing")?,
        );
        let tx = self.node.db.begin_read()?;
        let table = tx.open_table(RECORDS)?;
        let mut records = Vec::new();
        for entry in table.range(prefix.as_slice()..)? {
            let (key, value) = entry?;
            if !key.value().starts_with(&prefix) {
                break;
            }
            self.require_access(&state)?;
            let record = self.decode_record(key.value(), value.value(), &state)?;
            ensure!(record.namespace == namespace, "record namespace mismatch");
            records.push(record);
        }
        records.sort_by(|a, b| a.key.cmp(&b.key));
        self.require_access(&state)?;
        Ok(records
            .into_iter()
            .map(|mut record| {
                (
                    std::mem::take(&mut record.key),
                    std::mem::take(&mut record.value),
                )
            })
            .collect())
    }

    pub fn write_batch(&self, operations: &[WriteOp]) -> Result<()> {
        let _access = AccessGuard(self);
        validate_batch(&[operations])?;
        self.check_access()?;
        let _mutation = self.mutations.lock();
        let state = self.state.read();
        self.require_access(&state)?;
        let catalog = self.catalog.read();
        let tx = self.node.db.begin_write()?;
        write_domain(&tx, self, &state, &catalog, operations)?;
        self.require_access(&state)?;
        tx.commit()
            .context("durable encrypted batch commit failed; outcome may be unknown")?;
        // Expiry during fsync is an unknown-outcome write, never a false rollback claim.
        self.require_access(&state).context(
            "batch committed but key access was lost before acknowledgment; outcome unknown",
        )
    }

    pub async fn rotate_data_key(&self) -> Result<()> {
        let _access = AccessGuard(self);
        let _refresh = self.refresh.lock().await;
        self.check_access()?;
        let generated =
            tokio::time::timeout(PROVIDER_TIMEOUT, self.provider.generate_key(&self.tenant))
                .await??;
        let key = tokio::time::timeout(
            PROVIDER_TIMEOUT,
            self.provider.unwrap_key(&self.tenant, &generated.wrapped),
        )
        .await??;
        let _mutation = self.mutations.lock();
        let mut state = self.state.write();
        self.require_access(&state)?;
        let mut catalog = self.catalog.read().clone();
        ensure!(catalog.keys.len() < 1024, "too many retained data keys");
        let id = Uuid::new_v4().to_string();
        catalog.keys.insert(id.clone(), generated.wrapped);
        catalog.active = id.clone();
        self.node.save_catalog(&self.tenant, &catalog)?;
        state.keys.insert(id, key);
        *self.catalog.write() = catalog;
        self.require_access(&state).context(
            "key rotation committed but access expired before acknowledgment; outcome unknown",
        )
    }

    /// Rewrap all retained DEKs under the current version of the same Transit KEK.
    /// Historical encrypted backup files have their own wrappers and are not rewritten.
    pub async fn rewrap_keys(&self) -> Result<()> {
        let _access = AccessGuard(self);
        let _refresh = self.refresh.lock().await;
        self.check_access()?;
        let mut catalog = self.catalog.read().clone();
        for (id, wrapped) in &mut catalog.keys {
            *wrapped = tokio::time::timeout(
                PROVIDER_TIMEOUT,
                self.provider.rewrap_key(&self.tenant, wrapped),
            )
            .await??;
            let probe = tokio::time::timeout(
                PROVIDER_TIMEOUT,
                self.provider.unwrap_key(&self.tenant, wrapped),
            )
            .await??;
            let state = self.state.read();
            self.require_access(&state)?;
            let original = state.keys.get(id).context("rewrap key missing")?;
            ensure!(
                same_key(original, &probe),
                "rewrap changed data key material"
            );
        }
        let _mutation = self.mutations.lock();
        let state = self.state.read();
        self.require_access(&state)?;
        self.node.save_catalog(&self.tenant, &catalog)?;
        *self.catalog.write() = catalog;
        self.require_access(&state).context(
            "key rewrap committed but access expired before acknowledgment; outcome unknown",
        )
    }

    fn decode_record(
        &self,
        disk_key: &[u8],
        envelope: &[u8],
        state: &KeyState,
    ) -> Result<DecodedRecord> {
        let mut input = envelope;
        let id = std::str::from_utf8(take_bytes(&mut input)?)
            .context("invalid encrypted record key id")?;
        let data_key = state
            .keys
            .get(id)
            .context("encrypted record references an unavailable key")?;
        let plaintext = Zeroizing::new(decrypt(
            data_key,
            input,
            &record_aad(&self.tenant, disk_key),
        )?);
        let mut input = plaintext.as_slice();
        let mut record = DecodedRecord {
            namespace: String::new(),
            key: Vec::new(),
            value: Vec::new(),
        };
        record.namespace = std::str::from_utf8(take_bytes(&mut input)?)
            .context("invalid record namespace")?
            .to_owned();
        record.key = take_bytes(&mut input)?.to_vec();
        record.value = take_bytes(&mut input)?.to_vec();
        ensure!(input.is_empty(), "trailing encrypted record data");
        let expected = record_key(
            &self.tenant,
            &record.namespace,
            &record.key,
            state.keys.get(INDEX_KEY).context("index key missing")?,
        );
        ensure!(expected == disk_key, "encrypted record identity mismatch");
        Ok(record)
    }
}

fn validate_batch(domains: &[&[WriteOp]]) -> Result<()> {
    let mut bytes = 0usize;
    let mut count = 0usize;
    for operations in domains {
        count = count
            .checked_add(operations.len())
            .context("too many batch operations")?;
        ensure!(count <= 65536, "too many batch operations");
        for op in *operations {
            let (namespace, key, value_len) = match op {
                WriteOp::Put {
                    namespace,
                    key,
                    value,
                } => (namespace, key, value.len()),
                WriteOp::Delete { namespace, key } => (namespace, key, 0),
            };
            validate_record(namespace, key, value_len)?;
            bytes = bytes
                .checked_add(namespace.len() + key.len() + value_len)
                .context("batch too large")?;
            ensure!(bytes <= MAX_BATCH, "batch exceeds 64 MiB");
        }
    }
    Ok(())
}

fn write_domain(
    tx: &redb::WriteTransaction,
    store: &TenantStore,
    state: &KeyState,
    catalog: &KeyCatalog,
    operations: &[WriteOp],
) -> Result<()> {
    let index = state.keys.get(INDEX_KEY).context("index key missing")?;
    let data = state
        .keys
        .get(&catalog.active)
        .context("active data key missing")?;
    let mut table = tx.open_table(RECORDS)?;
    for op in operations {
        store.require_access(state)?;
        match op {
            WriteOp::Put {
                namespace,
                key,
                value,
            } => {
                let disk_key = record_key(&store.tenant, namespace, key, index);
                let plaintext = Zeroizing::new(encode_plain_record(namespace, key, value)?);
                let aad = record_aad(&store.tenant, &disk_key);
                let mut envelope = Vec::new();
                append_bytes(&mut envelope, catalog.active.as_bytes())?;
                envelope.extend(encrypt(data, &plaintext, &aad)?);
                table.insert(disk_key.as_slice(), envelope.as_slice())?;
            }
            WriteOp::Delete { namespace, key } => {
                let disk_key = record_key(&store.tenant, namespace, key, index);
                table.remove(disk_key.as_slice())?;
            }
        }
    }
    Ok(())
}

fn same_key(left: &SecretKey, right: &SecretKey) -> bool {
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

fn tenant_hash(tenant: &str) -> [u8; 32] {
    Sha256::digest(tenant.as_bytes()).into()
}

fn keyed_hash(key: &SecretKey, parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes()).expect("HMAC key size");
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn namespace_prefix(tenant: &str, namespace: &str, index: &SecretKey) -> Vec<u8> {
    let mut result = tenant_hash(tenant).to_vec();
    result.extend(keyed_hash(
        index,
        &[
            b"kasumi.namespace.v1",
            tenant.as_bytes(),
            namespace.as_bytes(),
        ],
    ));
    result
}

fn record_key(tenant: &str, namespace: &str, key: &[u8], index: &SecretKey) -> Vec<u8> {
    let mut result = namespace_prefix(tenant, namespace, index);
    result.extend(keyed_hash(
        index,
        &[
            b"kasumi.record.v1",
            tenant.as_bytes(),
            namespace.as_bytes(),
            key,
        ],
    ));
    result
}

fn record_aad(tenant: &str, key: &[u8]) -> Vec<u8> {
    let mut aad = b"kasumi.encrypted-record.v1".to_vec();
    aad.extend((tenant.len() as u64).to_be_bytes());
    aad.extend(tenant.as_bytes());
    // The physical key is an HMAC commitment to the exact namespace and user key.
    aad.extend(key);
    aad
}

fn validate_record(namespace: &str, key: &[u8], value_len: usize) -> Result<()> {
    ensure!(
        !namespace.is_empty() && namespace.len() <= 1024,
        "invalid record namespace"
    );
    ensure!(key.len() <= 4096, "record key exceeds 4096 bytes");
    ensure!(value_len <= MAX_RECORD, "record exceeds 32 MiB");
    Ok(())
}

fn append_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    out.extend(
        u32::try_from(value.len())
            .context("field too large")?
            .to_be_bytes(),
    );
    out.extend(value);
    Ok(())
}

fn take_bytes<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    ensure!(input.len() >= 4, "truncated record field");
    let len = u32::from_be_bytes(input[..4].try_into()?) as usize;
    *input = &input[4..];
    ensure!(input.len() >= len, "truncated record data");
    let result = &input[..len];
    *input = &input[len..];
    Ok(result)
}

fn check_encrypted_record_budget(
    envelope: &[u8],
    namespace_bytes: usize,
    key_bytes: usize,
    max_value_bytes: usize,
) -> Result<()> {
    let mut ciphertext = envelope;
    // Key ID is borrowed; no plaintext/decryption allocation occurs here.
    take_bytes(&mut ciphertext)?;
    let max_ciphertext = max_value_bytes
        .checked_add(namespace_bytes)
        .and_then(|value| value.checked_add(key_bytes))
        .and_then(|value| value.checked_add(12 + 40))
        .context("record read budget overflow")?;
    ensure!(
        ciphertext.len() <= max_ciphertext,
        "encrypted record exceeds read budget"
    );
    Ok(())
}

fn encode_plain_record(namespace: &str, key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::with_capacity(12 + namespace.len() + key.len() + value.len());
    append_bytes(&mut result, namespace.as_bytes())?;
    append_bytes(&mut result, key)?;
    append_bytes(&mut result, value)?;
    Ok(result)
}

fn encrypt(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid encryption key"))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("record encryption failed"))?;
    let mut result = Vec::with_capacity(24 + ciphertext.len());
    result.extend(nonce);
    result.extend(ciphertext);
    Ok(result)
}

fn decrypt(key: &SecretKey, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    ensure!(ciphertext.len() >= 40, "truncated encrypted record");
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid encryption key"))?;
    cipher
        .decrypt(
            XNonce::from_slice(&ciphertext[..24]),
            Payload {
                msg: &ciphertext[24..],
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypted record authentication failed"))
}

#[cfg(test)]
mod catalog_budget;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tls_fixture;
