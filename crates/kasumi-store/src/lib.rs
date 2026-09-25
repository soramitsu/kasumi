//! Encrypted durable records for both local execution and Raft persistence.
//!
//! Only wrapped keys and opaque tenant identifiers are stored in control metadata.
//! Record namespaces, keys and values are authenticated and encrypted before Kasumi KV.
//! Kasumi KV synchronizes each transaction before publishing its commit header.
//! Host filesystem,
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
mod backup_destination_index;
pub use backup_destination_index::{ExactBackupDestinationIndex, MAX_EXACT_BACKUP_DESTINATIONS};
mod backup_marker;
mod backup_sessions;
mod catalog_read_budget;
pub use backup_sessions::{
    BackupSessionObject, BackupSessionObjectPage, BackupSessionObjects, BackupSessionSlot,
    MAX_SESSION_GC_OBJECTS, MAX_SESSION_RECORD_BYTES, VerifiedBackupAbort, VerifiedBackupSession,
    verify_backup_session,
};
use catalog_read_budget::AdmittedKeyCatalog;
#[cfg(test)]
mod allocation_tests;
mod device_disk;
mod disk_memory;
mod storage_census;
mod storage_opening;
pub use disk_memory::{
    DiskMemoryLease, DiskMemoryRequirements, DiskOpenError, NodeDiskMemoryAdmission,
};
pub use storage_census::{
    StorageCensus, StorageCensusDisposition, StorageCensusObservation, StorageCensusPanicPhase,
    StorageCensusSnapshot, StorageOwnerId, StorageOwnerKind,
};
pub use storage_opening::{
    AdmittedReadBytes, BindingInstallBodyError, FailedOpeningAcknowledgement,
    FailedOpeningRecovery, NodeBindingWriteReport, NodeCatalogPutBodyError, NodeCatalogWriteReport,
    NodeOpeningMode, NodeOpeningPhase, NodeOpeningReport, NodeReadAccessError, NodeReadPhase,
    NodeReadReport, NodeReadTablesError, NodeStartupFailureCustody, NodeStartupPhase,
    NodeTablesBodyError, NodeTablesReport, NodeWriterPhase, OwnedEncryptedRow,
    RegisteredBindingPut, RegisteredCatalogPut, RegisteredNodeOpening, RegisteredNodeRead,
    RegisteredNodeStartup, RegisteredNodeTables,
};
mod keys;
mod node_database;
mod node_disk;
mod node_file;
pub use node_file::NodeFileCleanup;
pub mod node_store_ids;
mod read_view;
mod registered_read_scope;
pub use node_disk::{
    CensusCancellation, DirectoryPolicy, DiskWork, NodeDisk, NodeDiskConfig, NodeDiskDirectory,
    NodeDiskDirectoryCloseError, NodeDiskDirectoryCursor, NodeDiskDirectoryEntry,
    NodeDiskDirectoryFailure, NodeDiskDirectoryOperation, NodeDiskDirectoryOperationKind,
    NodeDiskDirectoryOperationStep, NodeDiskEntryKind, NodeDiskFile, NodeDiskPhase,
    NodeDiskSnapshot,
};
mod scratch_disk;
mod scratch_table;
pub use scratch_disk::{ScratchDisk, ScratchDiskConfig, ScratchDiskSnapshot};
mod serving_access;
mod spool;
pub use read_view::TenantReadView;
pub use registered_read_scope::{NodeScopedReadFailure, NodeScopedReadRetirement};
pub use scratch_table::{EncryptedTable, EncryptedTableBatch};
mod storage_domains;
pub use serving_access::{StorageAccess, StoragePurpose};
mod file_keys;
mod live_trust;
pub mod private_files;
pub use file_keys::FileKeyProvider;
pub use spool::{EncryptedSpool, RetainedSpool, SnapshotImage, SnapshotReader, SpoolClosePhase};
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use backup::{
    AdmittedBackupBundle, BackupBundleAdmissionError, BackupContents, BackupDestination,
    BackupUpload, EncryptedBackup, FilesystemBackupDestination, S3BackupConfig,
    S3BackupDestination,
};
pub use backup::{MAX_BACKUP_BUNDLE_BYTES, MAX_BACKUP_OBJECT_BYTES};
use kasumi_clock::{LeaseClock, SystemLeaseClock};
use kasumi_types::drain::{DrainReport, DrainResult};
pub use keys::{
    GeneratedKey, HistoricalKeyResolver, HistoricalKeySource, HistoricalSourceSecurityDescriptor,
    KeyProvider, SecretKey, TransitConfig, TransitKeyProvider, WrappedKey, WrappingIdentity,
};
pub use storage_domains::{
    AdmittedDeploymentBinding, BindingInstallWriteFailure, BindingInstallWriteRetirement,
    CustodyStore, StorageBinding, TenantStorageReadView, TenantStorageSet,
};

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
    aead::{Aead, AeadInPlace, Payload},
};
use hmac::{Hmac, Mac};
use kasumi_kv::TableDefinition;
#[cfg(any(test, feature = "test-utils"))]
use kasumi_kv::{
    BackendNativeDisposition, Database, DatabaseCloseReport, DatabaseCloseSettlement,
    RetainedDatabase,
};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(any(test, feature = "test-utils"))]
use std::{
    any::Any,
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
};
use tokio::sync::{Mutex as AsyncMutex, watch};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const CATALOG: TableDefinition<&[u8], &[u8]> = TableDefinition::new("wrapped_keys_v1");
const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("encrypted_records_v1");
pub const MAX_KEY_LEASE: Duration = Duration::from_secs(60);
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RECORD: usize = 32 * 1024 * 1024;
const MAX_BATCH: usize = 64 * 1024 * 1024;
/// A paired deployment writer fits two namespace/key/value triples in one batch.
/// Readers must accept every byte sequence the current writer can publish.
pub const MAX_DEPLOYMENT_BINDING_BYTES: usize =
    MAX_BATCH / 2 - ("engine.deployment".len() + b"mode".len());
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

#[cfg(any(test, feature = "test-utils"))]
enum NodeStoreSetupCause {
    Error(anyhow::Error),
    Panicked(Mutex<Box<dyn Any + Send>>),
}

/// A failed node setup retains its original error or panic and the exact
/// database close observation. An unproved native owner is never dropped into
/// an implicit backend close.
#[must_use]
#[cfg(any(test, feature = "test-utils"))]
pub struct NodeStoreSetupFailure {
    cause: NodeStoreSetupCause,
    owner: Mutex<Option<RetainedDatabase>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl NodeStoreSetupFailure {
    fn new(database: Database, cause: NodeStoreSetupCause) -> Self {
        let mut owner = database.retain();
        owner.close();
        Self {
            cause,
            owner: Mutex::new(Some(owner)),
        }
    }

    pub fn original_error(&self) -> Option<&anyhow::Error> {
        match &self.cause {
            NodeStoreSetupCause::Error(error) => Some(error),
            NodeStoreSetupCause::Panicked(_) => None,
        }
    }

    pub fn with_panic_payload<R>(&self, inspect: impl FnOnce(&(dyn Any + Send)) -> R) -> Option<R> {
        match &self.cause {
            NodeStoreSetupCause::Panicked(payload) => Some(inspect(payload.lock().as_ref())),
            NodeStoreSetupCause::Error(_) => None,
        }
    }

    pub fn with_close_report<R>(&self, inspect: impl FnOnce(DatabaseCloseReport<'_>) -> R) -> R {
        let guard = self.owner.lock();
        inspect(
            guard
                .as_ref()
                .expect("original setup owner retained")
                .report(),
        )
    }

    /// Only a close that stopped before native entry can advance here. Entered
    /// results and panics remain the first, terminal observation.
    pub fn retry_close(&self) -> DatabaseCloseSettlement {
        let mut guard = self.owner.lock();
        guard
            .as_mut()
            .expect("original setup owner retained")
            .close()
            .settlement()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl fmt::Debug for NodeStoreSetupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeStoreSetupFailure")
            .field("cause", &self.to_string())
            .field(
                "settlement",
                &self.with_close_report(|report| report.settlement()),
            )
            .finish()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl fmt::Display for NodeStoreSetupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.cause {
            NodeStoreSetupCause::Error(error) => write!(formatter, "node setup failed: {error}"),
            NodeStoreSetupCause::Panicked(_) => formatter.write_str("node setup panicked"),
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl std::error::Error for NodeStoreSetupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original_error().map(|error| error.as_ref())
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Drop for NodeStoreSetupFailure {
    fn drop(&mut self) {
        let Some(owner) = self.owner.get_mut().take() else {
            return;
        };
        if owner.report().native_disposition() != BackendNativeDisposition::Drained {
            // The caller discarded the failure while native drain was unproved.
            // Forget the exact owner instead of triggering an implicit close.
            std::mem::forget(owner);
        }
    }
}

/// A failed installed node startup keeps the same registered physical owner,
/// child census handle and original opening reports available to the caller.
/// Dropping this facade does not delete the independent storage-census cell.
pub struct NodeStoreOpeningFailure {
    custody: NodeStartupFailureCustody,
    close_error: Option<std::io::Error>,
}
impl NodeStoreOpeningFailure {
    pub fn opening_id(&self) -> StorageOwnerId {
        self.custody.opening().id()
    }
    pub fn custody(&self) -> &NodeStartupFailureCustody {
        &self.custody
    }
    pub fn close_error(&self) -> Option<&std::io::Error> {
        self.close_error.as_ref()
    }
    pub fn into_custody(self) -> NodeStartupFailureCustody {
        self.custody
    }
}
impl std::fmt::Debug for NodeStoreOpeningFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeStoreOpeningFailure")
            .field("opening_id", &self.opening_id())
            .field("phase", &self.custody.phase())
            .field("child_id", &self.custody.child_id())
            .field("child_disposition", &self.custody.child_disposition())
            .field("close_error", &self.close_error)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for NodeStoreOpeningFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "node startup {:?} retained registered opening {:?}",
            self.custody.phase(),
            self.opening_id()
        )
    }
}
impl std::error::Error for NodeStoreOpeningFailure {}

/// A failed fixed catalog read keeps its exact registered child and original
/// read/close observations. Dropping this facade leaves the census cell intact.
pub struct NodeCatalogReadFailure {
    reader: RegisteredNodeRead,
    stage: &'static str,
    access: Option<NodeReadAccessError>,
    validation_error: Option<anyhow::Error>,
}
impl NodeCatalogReadFailure {
    pub fn reader(&self) -> &RegisteredNodeRead {
        &self.reader
    }
    pub fn into_reader(self) -> RegisteredNodeRead {
        self.reader
    }
    pub fn stage(&self) -> &'static str {
        self.stage
    }
    pub fn validation_error(&self) -> Option<&anyhow::Error> {
        self.validation_error.as_ref()
    }
}
impl std::fmt::Debug for NodeCatalogReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCatalogReadFailure")
            .field("reader_id", &self.reader.id())
            .field("stage", &self.stage)
            .field("reader_phase", &self.reader.phase())
            .field("access", &self.access)
            .field("validation_error", &self.validation_error)
            .finish()
    }
}
impl std::fmt::Display for NodeCatalogReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "registered catalog read {:?} failed at {}",
            self.reader.id(),
            self.stage
        )
    }
}
impl std::error::Error for NodeCatalogReadFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.access
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| {
                self.validation_error
                    .as_ref()
                    .map(|error| error.as_ref() as _)
            })
    }
}

/// Retirement is separate from closing the child transaction. Keep the exact
/// provider/ID when census disposal is still pending after a clean read.
pub struct NodeCatalogReadRetirement {
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    id: StorageOwnerId,
    disposition: StorageCensusDisposition,
    validation_error: Option<anyhow::Error>,
}
impl NodeCatalogReadRetirement {
    pub fn id(&self) -> StorageOwnerId {
        self.id
    }
    pub fn disposition(&self) -> StorageCensusDisposition {
        self.disposition
    }
    pub fn validation_error(&self) -> Option<&anyhow::Error> {
        self.validation_error.as_ref()
    }
    pub fn retry_retirement(&self) -> StorageCensusDisposition {
        self.provider.storage_census().drain_owner(self.id)
    }
}
impl std::fmt::Debug for NodeCatalogReadRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCatalogReadRetirement")
            .field("id", &self.id)
            .field("disposition", &self.disposition)
            .field("validation_error", &self.validation_error)
            .finish()
    }
}
impl std::fmt::Display for NodeCatalogReadRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "registered catalog reader {:?} retirement {:?}",
            self.id, self.disposition
        )
    }
}
impl std::error::Error for NodeCatalogReadRetirement {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.validation_error.as_ref().map(|error| error.as_ref())
    }
}

/// A catalog mutation that did not prove a committed and disposed native
/// writer retains its exact child, admitted input, and original observations.
pub struct NodeCatalogWriteFailure {
    writer: RegisteredCatalogPut,
}
impl NodeCatalogWriteFailure {
    pub fn writer(&self) -> &RegisteredCatalogPut {
        &self.writer
    }
    pub fn into_writer(self) -> RegisteredCatalogPut {
        self.writer
    }
}
impl std::fmt::Debug for NodeCatalogWriteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCatalogWriteFailure")
            .field("writer_id", &self.writer.id())
            .field("phase", &self.writer.report().phase())
            .finish()
    }
}
impl std::fmt::Display for NodeCatalogWriteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "registered catalog write {:?} has an unproved outcome",
            self.writer.id()
        )
    }
}
impl std::error::Error for NodeCatalogWriteFailure {}

/// A clean catalog commit keeps its exact census identity if retirement waits.
pub struct NodeCatalogWriteRetirement {
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    id: StorageOwnerId,
    disposition: StorageCensusDisposition,
}
impl NodeCatalogWriteRetirement {
    pub fn id(&self) -> StorageOwnerId {
        self.id
    }
    pub fn disposition(&self) -> StorageCensusDisposition {
        self.disposition
    }
    pub fn retry_retirement(&self) -> StorageCensusDisposition {
        if let Some(writer) = RegisteredCatalogPut::retained(self.provider.clone(), self.id) {
            // The first retirement may have met a busy report mutex before it
            // could release a clean outcome. Re-enter that same child to make
            // the acknowledgement, without replaying its native terminal.
            writer.retire()
        } else {
            self.provider.storage_census().drain_owner(self.id)
        }
    }
}
impl std::fmt::Debug for NodeCatalogWriteRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCatalogWriteRetirement")
            .field("id", &self.id)
            .field("disposition", &self.disposition)
            .finish()
    }
}
impl std::fmt::Display for NodeCatalogWriteRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "registered catalog writer {:?} retirement {:?}",
            self.id, self.disposition
        )
    }
}
impl std::error::Error for NodeCatalogWriteRetirement {}

/// A failed point read keeps its exact registered child and original read or
/// close observation. The census retains it after this facade is dropped.
pub struct TenantPointReadFailure {
    reader: RegisteredNodeRead,
    stage: &'static str,
    access: Option<NodeReadAccessError>,
    validation_error: Option<anyhow::Error>,
}
impl TenantPointReadFailure {
    pub fn reader(&self) -> &RegisteredNodeRead {
        &self.reader
    }
    pub fn into_reader(self) -> RegisteredNodeRead {
        self.reader
    }
    pub fn stage(&self) -> &'static str {
        self.stage
    }
    pub fn validation_error(&self) -> Option<&anyhow::Error> {
        self.validation_error.as_ref()
    }
}
impl std::fmt::Debug for TenantPointReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantPointReadFailure")
            .field("reader_id", &self.reader.id())
            .field("stage", &self.stage)
            .field("reader_phase", &self.reader.phase())
            .field("access", &self.access)
            .field("validation_error", &self.validation_error)
            .finish()
    }
}
impl std::fmt::Display for TenantPointReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "registered tenant point read {:?} failed at {}",
            self.reader.id(),
            self.stage
        )
    }
}
impl std::error::Error for TenantPointReadFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.access
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| {
                self.validation_error
                    .as_ref()
                    .map(|error| error.as_ref() as _)
            })
    }
}

/// Closing a point reader and retiring its census child are distinct steps.
pub struct TenantPointReadRetirement {
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    id: StorageOwnerId,
    disposition: StorageCensusDisposition,
    validation_error: Option<anyhow::Error>,
}
impl TenantPointReadRetirement {
    pub fn id(&self) -> StorageOwnerId {
        self.id
    }
    pub fn disposition(&self) -> StorageCensusDisposition {
        self.disposition
    }
    pub fn validation_error(&self) -> Option<&anyhow::Error> {
        self.validation_error.as_ref()
    }
    pub fn retry_retirement(&self) -> StorageCensusDisposition {
        self.provider.storage_census().drain_owner(self.id)
    }
}
impl std::fmt::Debug for TenantPointReadRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantPointReadRetirement")
            .field("id", &self.id)
            .field("disposition", &self.disposition)
            .field("validation_error", &self.validation_error)
            .finish()
    }
}
impl std::fmt::Display for TenantPointReadRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "registered tenant point reader {:?} retirement {:?}",
            self.id, self.disposition
        )
    }
}
impl std::error::Error for TenantPointReadRetirement {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.validation_error.as_ref().map(|error| error.as_ref())
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
    /// authorized cleanup. No database open, initialization or repair takes place.
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
        Self::start_registered(
            path.as_ref(),
            node_store_id,
            persistent_disk,
            scratch_disk,
            NodeOpeningMode::Create,
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
        Self::start_registered(
            path.as_ref(),
            node_store_id,
            persistent_disk,
            scratch_disk,
            NodeOpeningMode::OwnedEmpty(expected_file.clone()),
        )
    }

    /// Reopen only the exact recognized installed payload through the same
    /// registered owner used for table verification and later close.
    pub fn open_existing(
        path: impl AsRef<Path>,
        expected_id: Uuid,
        persistent_disk: Arc<NodeDisk>,
        scratch_disk: Arc<ScratchDisk>,
    ) -> Result<Arc<Self>> {
        Self::start_registered(
            path.as_ref(),
            expected_id,
            persistent_disk,
            scratch_disk,
            NodeOpeningMode::Existing,
        )
    }

    fn start_registered(
        path: &Path,
        id: Uuid,
        persistent_disk: Arc<NodeDisk>,
        scratch_disk: Arc<ScratchDisk>,
        mode: NodeOpeningMode,
    ) -> Result<Arc<Self>> {
        ensure!(
            Arc::ptr_eq(persistent_disk.memory(), scratch_disk.memory()),
            "persistent and scratch disks require the same installed memory admission"
        );
        let provider = persistent_disk.memory().clone();
        let mut startup = RegisteredNodeStartup::prepare(path, id, persistent_disk.clone(), mode)?;
        if startup.advance() != NodeStartupPhase::Ready {
            let close_error = startup.close_failed().err();
            let custody = startup.into_failed_custody().map_err(|_| {
                anyhow::anyhow!("failed startup did not retain exact closing custody")
            })?;
            return Err(NodeStoreOpeningFailure {
                custody,
                close_error,
            }
            .into());
        }
        let opening = startup
            .into_opening()
            .map_err(|_| anyhow::anyhow!("ready registered startup lost its opening"))?;
        Ok(Arc::new(Self {
            db: node_database::NodeDatabase::new_registered(opening, provider, "node database"),
            persistent_disk: Some(persistent_disk),
            scratch_disk,
            path: Some(path.to_owned()),
            tenants: AsyncMutex::new(HashMap::new()),
            initializers: AsyncMutex::new(InitializerRegistry::default()),
            shutdown_report: AsyncMutex::new(DrainReport::default()),
        }))
    }

    /// Synthetic fixtures keep their direct, test-only owner so unrelated
    /// suites can model an implicit process-exit drop. Installed production
    /// constructors above always use the registered opening and explicit close.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn create_new_fixture_direct(
        path: &Path,
        id: Uuid,
        persistent_disk: Arc<NodeDisk>,
        scratch_disk: Arc<ScratchDisk>,
    ) -> Result<Arc<Self>> {
        ensure!(
            Arc::ptr_eq(persistent_disk.memory(), scratch_disk.memory()),
            "persistent and scratch disks require the same installed memory admission"
        );
        Self::initialize_fixture(
            node_file::NodeFile::create_new(path, id, persistent_disk)?,
            scratch_disk,
        )
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn initialize_owned_empty_fixture_direct(
        path: &Path,
        expected_file: &private_files::FileIdentity,
        id: Uuid,
        persistent_disk: Arc<NodeDisk>,
        scratch_disk: Arc<ScratchDisk>,
    ) -> Result<Arc<Self>> {
        ensure!(
            Arc::ptr_eq(persistent_disk.memory(), scratch_disk.memory()),
            "persistent and scratch disks require the same installed memory admission"
        );
        Self::initialize_fixture(
            node_file::NodeFile::initialize_owned_empty(path, expected_file, id, persistent_disk)?,
            scratch_disk,
        )
    }

    #[cfg(any(test, feature = "test-utils"))]
    fn initialize_fixture(
        file: Arc<node_file::NodeFile>,
        scratch_disk: Arc<ScratchDisk>,
    ) -> Result<Arc<Self>> {
        let db = Database::builder(file.clone()).create_with_backend(file.backend())?;
        let db = Self::finish_setup(db, |db| {
            Self::initialize_tables(db)?;
            file.publish_ready()?;
            Ok(())
        })?;
        Ok(Self::installed(
            db,
            Some(file.path().to_owned()),
            Some(file.disk().clone()),
            scratch_disk,
        ))
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn open_existing_fixture_direct(
        path: &Path,
        expected_id: Uuid,
        persistent_disk: Arc<NodeDisk>,
        scratch_disk: Arc<ScratchDisk>,
    ) -> Result<Arc<Self>> {
        ensure!(
            Arc::ptr_eq(persistent_disk.memory(), scratch_disk.memory()),
            "persistent and scratch disks require the same installed memory admission"
        );
        let file = node_file::NodeFile::open_existing(path, expected_id, persistent_disk)?;
        let db = Database::builder(file.clone()).create_with_backend(file.backend())?;
        let db = Self::finish_setup(db, |db| {
            let tx = db.begin_read()?;
            tx.open_table(CATALOG)?;
            tx.open_table(RECORDS)?;
            Ok(())
        })?;
        Ok(Self::installed(
            db,
            Some(file.path().to_owned()),
            Some(file.disk().clone()),
            scratch_disk,
        ))
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn open_with_backend(
        backend: impl kasumi_kv::StorageBackend + 'static,
        admission: Arc<dyn kasumi_kv::StorageAdmission>,
        scratch_disk: Arc<ScratchDisk>,
    ) -> Result<Arc<Self>> {
        let db = Database::builder(admission).create_with_backend(backend)?;
        let db = Self::finish_setup(db, Self::initialize_tables)?;
        Ok(Self::installed(db, None, None, scratch_disk))
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn finish_setup(
        database: Database,
        setup: impl FnOnce(&Database) -> Result<()>,
    ) -> Result<Database> {
        match catch_unwind(AssertUnwindSafe(|| setup(&database))) {
            Ok(Ok(())) => Ok(database),
            Ok(Err(error)) => {
                Err(NodeStoreSetupFailure::new(database, NodeStoreSetupCause::Error(error)).into())
            }
            Err(payload) => Err(NodeStoreSetupFailure::new(
                database,
                NodeStoreSetupCause::Panicked(Mutex::new(payload)),
            )
            .into()),
        }
    }

    /// Exact installed census owner for this node's database and close report.
    /// A retained close can be inspected through `RegisteredNodeOpening::retained`
    /// on the same installed memory provider and this ID.
    pub fn registered_opening_id(&self) -> Option<StorageOwnerId> {
        self.db.registered_opening_id()
    }

    /// Every production node has one mandatory installed physical owner.
    pub fn persistent_disk(&self) -> &Arc<NodeDisk> {
        self.persistent_disk
            .as_ref()
            .expect("synthetic backend fixture has no installed physical disk")
    }

    /// Stop new database work, join retained initializers, then explicitly close
    /// the database. The caller first drains its tenant and Raft workers. Busy retains
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

    #[cfg(any(test, feature = "test-utils"))]
    fn initialize_tables(db: &Database) -> Result<()> {
        let tx = db.begin_write()?;
        {
            tx.open_table(CATALOG)?;
            tx.open_table(RECORDS)?;
        }
        tx.commit()?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-utils"))]
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

    fn catalog(&self, tenant: &str) -> Result<Option<AdmittedKeyCatalog>> {
        // Synthetic process-exit fixtures intentionally have a direct backend;
        // an installed production node always has a registered opening.
        #[cfg(any(test, feature = "test-utils"))]
        if self.db.has_fixture_direct_database() {
            return Self::catalog_at(&self.db.begin_read()?, tenant)
                .map(|catalog| catalog.map(AdmittedKeyCatalog::unadmitted));
        }

        let reader = self.db.queue_registered_read()?;
        if reader.begin() != NodeReadPhase::Active {
            return Err(NodeCatalogReadFailure {
                reader,
                stage: "begin",
                access: None,
                validation_error: None,
            }
            .into());
        }
        let bytes = match reader.catalog_bytes(tenant_hash(tenant), MAX_KEY_CATALOG_BYTES) {
            Ok(bytes) => bytes,
            Err(access) => {
                return Err(NodeCatalogReadFailure {
                    reader,
                    stage: "catalog bytes",
                    access: Some(access),
                    validation_error: None,
                }
                .into());
            }
        };
        let decoded = bytes
            .as_ref()
            .map(|bytes| {
                AdmittedKeyCatalog::decode(
                    bytes.as_bytes(),
                    tenant,
                    self.persistent_disk().memory().clone(),
                )
            })
            .transpose();
        drop(bytes);
        if reader.finish() != NodeReadPhase::Finished {
            return Err(NodeCatalogReadFailure {
                reader,
                stage: "finish",
                access: None,
                validation_error: decoded.err(),
            }
            .into());
        }
        let id = reader.id();
        let disposition = reader.retire();
        if disposition != StorageCensusDisposition::Retired {
            return Err(NodeCatalogReadRetirement {
                provider: self.persistent_disk().memory().clone(),
                id,
                disposition,
                validation_error: decoded.err(),
            }
            .into());
        }
        decoded
    }

    #[cfg(any(test, feature = "test-utils"))]
    fn catalog_at(tx: &kasumi_kv::ReadTransaction, tenant: &str) -> Result<Option<KeyCatalog>> {
        let table = tx.open_table(CATALOG)?;
        table
            .get(tenant_hash(tenant).as_slice())?
            .map(|v| Self::catalog_from_bytes(v.value(), tenant))
            .transpose()
    }

    fn catalog_from_bytes(bytes: &[u8], tenant: &str) -> Result<KeyCatalog> {
        ensure!(
            bytes.len() <= MAX_KEY_CATALOG_BYTES,
            "key catalog byte quota exceeded"
        );
        let catalog: KeyCatalog = serde_json::from_slice(bytes).context("invalid key catalog")?;
        catalog.validate(tenant)?;
        // Compare the current writer's exact bytes without retaining a second,
        // potentially 2 MiB copy of wrapped-key metadata.
        struct Exact<'a> {
            original: &'a [u8],
            offset: usize,
        }
        impl std::io::Write for Exact<'_> {
            fn write(&mut self, encoded: &[u8]) -> std::io::Result<usize> {
                let end = self
                    .offset
                    .checked_add(encoded.len())
                    .ok_or_else(|| std::io::Error::other("noncanonical key catalog"))?;
                if self.original.get(self.offset..end) != Some(encoded) {
                    return Err(std::io::Error::other("noncanonical key catalog"));
                }
                self.offset = end;
                Ok(encoded.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut exact = Exact {
            original: bytes,
            offset: 0,
        };
        serde_json::to_writer(&mut exact, &catalog).context("noncanonical key catalog")?;
        ensure!(exact.offset == bytes.len(), "noncanonical key catalog");
        Ok(catalog)
    }

    fn save_catalog(&self, tenant: &str, catalog: &KeyCatalog) -> Result<()> {
        // Only synthetic process-exit fixtures own a direct database. An
        // installed node always registers its exact write before native begin.
        #[cfg(any(test, feature = "test-utils"))]
        if self.db.has_fixture_direct_database() {
            catalog.validate(tenant)?;
            let bytes = serde_json::to_vec(catalog)?;
            let tx = self.db.begin_write()?;
            tx.open_table(CATALOG)?
                .insert(tenant_hash(tenant).as_slice(), bytes.as_slice())?;
            return tx.commit().context("committing wrapped-key catalog");
        }

        let provider = self.persistent_disk().memory().clone();
        let plan = storage_opening::write_plan::AdmittedCatalogPut::prepare(
            tenant,
            catalog,
            provider.clone(),
        )?;
        let writer = self.db.queue_registered_catalog_put(plan)?;
        let _ = writer.run();
        let committed = writer.report().committed_and_disposed();
        if !committed {
            return Err(NodeCatalogWriteFailure { writer }.into());
        }
        let id = writer.id();
        let disposition = writer.retire();
        if disposition != StorageCensusDisposition::Retired {
            return Err(NodeCatalogWriteRetirement {
                provider,
                id,
                disposition,
            }
            .into());
        }
        Ok(())
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
    // The current catalog's derived allocations remain charged through each
    // replacement and for the exact lifetime of this owner.
    catalog_charge: Mutex<Option<DiskMemoryLease>>,
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

    fn clone_catalog_for_mutation(&self) -> Result<AdmittedKeyCatalog> {
        let current = self.catalog.read();
        AdmittedKeyCatalog::clone_for_mutation(&current, self.scratch_disk().memory().clone())
    }

    fn replace_catalog(&self, admitted: AdmittedKeyCatalog) {
        let (catalog, charge) = admitted.into_parts();
        // Drop the previous catalog before retiring its charge. The new clone
        // keeps its local lease until the replacement charge is installed.
        *self.catalog.write() = catalog;
        *self.catalog_charge.lock() = charge;
    }

    /// Construct an unpublished owner. The caller retains its open gate until
    /// either publication or completed shutdown of this exact new owner.
    fn unpublished(
        node: Arc<NodeStore>,
        tenant: String,
        provider: Arc<dyn KeyProvider>,
        access: StorageAccess,
        clock: Arc<dyn LeaseClock>,
        catalog: impl Into<AdmittedKeyCatalog>,
    ) -> Arc<Self> {
        let (seal_notifier, _) = watch::channel(0);
        let (shutdown_signal, _) = watch::channel(false);
        let (catalog, catalog_read_charge) = catalog.into().into_parts();
        Arc::new(Self {
            node: node.clone(),
            tenant: tenant.clone(),
            access,
            provider,
            catalog: RwLock::new(catalog),
            catalog_charge: Mutex::new(catalog_read_charge),
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
        // The installed scratch and persistent owners share one mandatory
        // memory core. Fund this independent typed clone before it allocates.
        let catalog = {
            let current = self.catalog.read();
            AdmittedKeyCatalog::clone_for_refresh(&current, self.scratch_disk().memory().clone())?
        };
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
        // The probe future is complete (or cancelled by timeout). Destroy the
        // cloned strings/map before the exact admission lease can retire.
        drop(catalog);
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
        #[cfg(any(test, feature = "test-utils"))]
        let mut result = if self.node.db.has_fixture_direct_database() {
            let tx = self.node.db.begin_read()?;
            let table = tx.open_table(RECORDS)?;
            table
                .get(disk_key.as_slice())?
                .map(|value| {
                    self.decode_bounded_record(
                        &disk_key,
                        value.value(),
                        namespace,
                        key,
                        max_value_bytes,
                        &state,
                    )
                })
                .transpose()?
        } else {
            self.get_bounded_registered(&disk_key, namespace, key, max_value_bytes, &state)?
        };
        #[cfg(not(any(test, feature = "test-utils")))]
        let mut result =
            self.get_bounded_registered(&disk_key, namespace, key, max_value_bytes, &state)?;
        self.require_access(&state)?;
        Ok(result
            .as_mut()
            .map(|record| std::mem::take(&mut record.value)))
    }

    fn get_bounded_registered(
        &self,
        disk_key: &[u8],
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
        state: &KeyState,
    ) -> Result<Option<DecodedRecord>> {
        // A valid envelope contains a retained key ID, three length fields,
        // a nonce and an authentication tag. Bound the *owned ciphertext copy*
        // before reading; the existing plaintext budget is checked again below.
        let encrypted_limit =
            encrypted_record_limit(namespace.len(), key.len(), max_value_bytes, state)?;

        let reader = self.node.db.queue_registered_read()?;
        if reader.begin() != NodeReadPhase::Active {
            return Err(TenantPointReadFailure {
                reader,
                stage: "begin",
                access: None,
                validation_error: None,
            }
            .into());
        }
        let encrypted = match reader.record_bytes(disk_key, encrypted_limit) {
            Ok(bytes) => bytes,
            Err(access) => {
                return Err(TenantPointReadFailure {
                    reader,
                    stage: "record bytes",
                    access: Some(access),
                    validation_error: None,
                }
                .into());
            }
        };
        let decoded = encrypted
            .as_ref()
            .map(|bytes| {
                self.decode_bounded_record(
                    disk_key,
                    bytes.as_bytes(),
                    namespace,
                    key,
                    max_value_bytes,
                    state,
                )
            })
            .transpose()
            .and_then(|record| {
                self.require_access(state)?;
                Ok(record)
            });
        drop(encrypted);
        if reader.finish() != NodeReadPhase::Finished {
            return Err(TenantPointReadFailure {
                reader,
                stage: "finish",
                access: None,
                validation_error: decoded.err(),
            }
            .into());
        }
        let id = reader.id();
        let disposition = reader.retire();
        if disposition != StorageCensusDisposition::Retired {
            return Err(TenantPointReadRetirement {
                provider: self.node.persistent_disk().memory().clone(),
                id,
                disposition,
                validation_error: decoded.err(),
            }
            .into());
        }
        decoded
    }

    fn decode_bounded_record(
        &self,
        disk_key: &[u8],
        envelope: &[u8],
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
        state: &KeyState,
    ) -> Result<DecodedRecord> {
        check_encrypted_record_budget(envelope, namespace.len(), key.len(), max_value_bytes)?;
        let record = self.decode_record(disk_key, envelope, state)?;
        ensure!(
            record.value.len() <= max_value_bytes,
            "record value exceeds read budget"
        );
        ensure!(
            record.namespace == namespace && record.key == key,
            "record identity mismatch"
        );
        Ok(record)
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
        #[cfg(any(test, feature = "test-utils"))]
        if self.node.db.has_fixture_direct_database() {
            let tx = self.node.db.begin_read()?;
            let table = tx.open_table(RECORDS)?;
            for entry in table.range(prefix.as_slice()..)? {
                let (key, value) = entry?;
                if !key.value().starts_with(&prefix) {
                    break;
                }
                self.require_access(&state)?;
                check_encrypted_record_budget(
                    value.value(),
                    namespace.len(),
                    4096,
                    max_value_bytes,
                )?;
                let record = self.decode_record(key.value(), value.value(), &state)?;
                ensure!(
                    record.value.len() <= max_value_bytes,
                    "record value exceeds visit budget"
                );
                ensure!(record.namespace == namespace, "record namespace mismatch");
                visitor(&record.key, &record.value)?;
            }
            return self.require_access(&state);
        }
        let encrypted_limit =
            encrypted_record_limit(namespace.len(), 4096, max_value_bytes, &state)?;
        self.node.with_registered_read(|reader| {
            let mut cursor: Option<AdmittedReadBytes> = None;
            while let Some(row) = reader.next_record(
                &prefix,
                cursor.as_ref().map(AdmittedReadBytes::as_bytes),
                encrypted_limit,
            )? {
                self.require_access(&state)?;
                check_encrypted_record_budget(row.value(), namespace.len(), 4096, max_value_bytes)?;
                let record = self.decode_record(row.key(), row.value(), &state)?;
                ensure!(
                    record.value.len() <= max_value_bytes,
                    "record value exceeds visit budget"
                );
                ensure!(record.namespace == namespace, "record namespace mismatch");
                visitor(&record.key, &record.value)?;
                cursor = Some(row.into_key());
            }
            self.require_access(&state)
        })
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
        #[cfg(any(test, feature = "test-utils"))]
        if self.node.db.has_fixture_direct_database() {
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
            return self.sorted_scan_records(&state, records);
        }
        let encrypted_limit = encrypted_record_limit(namespace.len(), 4096, MAX_RECORD, &state)?;
        let records = self.node.with_registered_read(|reader| {
            let mut records = Vec::new();
            let mut cursor: Option<AdmittedReadBytes> = None;
            while let Some(row) = reader.next_record(
                &prefix,
                cursor.as_ref().map(AdmittedReadBytes::as_bytes),
                encrypted_limit,
            )? {
                self.require_access(&state)?;
                let record = self.decode_record(row.key(), row.value(), &state)?;
                ensure!(record.namespace == namespace, "record namespace mismatch");
                records.push(record);
                cursor = Some(row.into_key());
            }
            Ok(records)
        })?;
        self.sorted_scan_records(&state, records)
    }

    fn sorted_scan_records(
        &self,
        state: &KeyState,
        mut records: Vec<DecodedRecord>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        records.sort_by(|a, b| a.key.cmp(&b.key));
        self.require_access(state)?;
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
        reject_unpaired_identity_ops(operations)?;
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
        let mut catalog = self.clone_catalog_for_mutation()?;
        ensure!(catalog.keys.len() < 1024, "too many retained data keys");
        let id = Uuid::new_v4().to_string();
        catalog.keys.insert(id.clone(), generated.wrapped);
        catalog.active = id.clone();
        self.node.save_catalog(&self.tenant, &catalog)?;
        state.keys.insert(id, key);
        self.replace_catalog(catalog);
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
        let mut catalog = self.clone_catalog_for_mutation()?;
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
        self.replace_catalog(catalog);
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

/// The initial bootstrap rows are immutable even when a caller holds a
/// writable TenantStore. A repeated, byte-identical first-install write is a
/// no-op so interrupted chunk publication can resume after an unknown commit.
pub(crate) fn is_write_once_identity(namespace: &str, key: &[u8]) -> bool {
    namespace == "engine.bootstrap"
        || (namespace == "engine.deployment" && key == b"mode")
        || (namespace == "raft.meta"
            && matches!(key, b"application_bootstrap_sha256" | b"node_id" | b"group"))
}

pub(crate) fn is_initial_identity_namespace(namespace: &str) -> bool {
    matches!(
        namespace,
        "engine.bootstrap" | "engine.deployment" | "raft.meta"
    )
}

pub(crate) fn is_paired_identity(namespace: &str, key: &[u8]) -> bool {
    (namespace == "engine.deployment" && key == b"mode")
        || (namespace == "engine.bootstrap" && key == b"manifest")
        || (namespace == "raft.meta"
            && matches!(key, b"application_bootstrap_sha256" | b"node_id" | b"group"))
}

pub(crate) fn reject_unpaired_identity_ops(operations: &[WriteOp]) -> Result<()> {
    for operation in operations {
        let (namespace, key) = match operation {
            WriteOp::Put { namespace, key, .. } | WriteOp::Delete { namespace, key } => {
                (namespace, key)
            }
        };
        ensure!(
            !is_paired_identity(namespace, key),
            "initial bootstrap identity requires paired domain publication"
        );
    }
    Ok(())
}

fn write_domain(
    tx: &kasumi_kv::WriteTransaction,
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
                let disk_key = inline_record_key(&store.tenant, namespace, key, index);
                if is_write_once_identity(namespace, key)
                    && let Some(existing) = table.get(disk_key.as_slice())?
                {
                    check_encrypted_record_budget(
                        existing.value(),
                        namespace.len(),
                        key.len(),
                        MAX_RECORD,
                    )?;
                    // Native KV admits the encrypted value. Fund both the
                    // decrypted buffer and DecodedRecord's owned fields
                    // before decrypting a potentially large old chunk.
                    let workspace = u64::try_from(existing.value().len())?
                        .checked_mul(2)
                        .and_then(|bytes| bytes.checked_add(8192))
                        .context("initial identity decode workspace overflow")?;
                    let _plaintext = store
                        .scratch_disk()
                        .memory()
                        .clone()
                        .reserve_installed(workspace)
                        .context("initial identity decode admission denied")?;
                    let record = store.decode_record(&disk_key, existing.value(), state)?;
                    ensure!(
                        record.namespace == namespace.as_str()
                            && record.key.as_slice() == key.as_slice()
                            && record.value.as_slice() == value.as_slice(),
                        "initial bootstrap identity is write-once"
                    );
                    store.require_access(state)?;
                    continue;
                }
                let admitted = AdmittedRecordPut::prepare(
                    store,
                    state,
                    namespace,
                    key,
                    value,
                    &disk_key,
                    &catalog.active,
                    data,
                )?;
                table.insert(disk_key.as_slice(), admitted.bytes())?;
            }
            WriteOp::Delete { namespace, key } => {
                ensure!(
                    !is_write_once_identity(namespace, key),
                    "initial bootstrap identity is write-once"
                );
                let disk_key = record_key(&store.tenant, namespace, key, index);
                table.delete_key(disk_key.as_slice())?;
            }
        }
    }
    Ok(())
}

/// The one encrypted-record buffer owns its exact installed resident charge
/// through native insertion. Its zeroizing allocation drops before the lease.
struct AdmittedRecordPut {
    envelope: Zeroizing<Vec<u8>>,
    _charge: DiskMemoryLease,
}
impl AdmittedRecordPut {
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        store: &TenantStore,
        state: &KeyState,
        namespace: &str,
        key: &[u8],
        value: &[u8],
        disk_key: &[u8; 96],
        active: &str,
        data: &SecretKey,
    ) -> Result<Self> {
        let active_bytes = active.as_bytes();
        let active_len = u32::try_from(active_bytes.len())?;
        let plain_len = 12usize
            .checked_add(namespace.len())
            .and_then(|size| size.checked_add(key.len()))
            .and_then(|size| size.checked_add(value.len()))
            .context("encrypted record plaintext length overflow")?;
        let header_len = 4usize
            .checked_add(active_bytes.len())
            .context("encrypted record key ID overflow")?;
        let plain_start = header_len
            .checked_add(24)
            .context("encrypted record nonce overflow")?;
        let plain_end = plain_start
            .checked_add(plain_len)
            .context("encrypted record body overflow")?;
        let envelope_len = plain_end
            .checked_add(16)
            .context("encrypted record tag overflow")?;
        ensure!(
            envelope_len <= MAX_BATCH,
            "encrypted record exceeds batch limit"
        );
        let requested = u64::try_from(envelope_len)?;
        let admitted = disk_memory::allocation::<u8>(requested)?;
        #[cfg(any(test, feature = "test-utils"))]
        let provider = if store.node.db.has_fixture_direct_database() {
            // A synthetic direct database has no persistent NodeDisk, but its
            // fixture scratch owner still installs mandatory resident credit.
            store.node.scratch_disk().memory().clone()
        } else {
            store.node.persistent_disk().memory().clone()
        };
        #[cfg(not(any(test, feature = "test-utils")))]
        let provider = store.node.persistent_disk().memory().clone();
        let charge = provider
            .reserve_installed(admitted)
            .context("encrypted record output admission denied")?;

        let tenant = store.tenant.as_bytes();
        ensure!(tenant.len() <= 1024, "invalid encrypted record tenant");
        const AAD_PREFIX: &[u8] = b"kasumi.encrypted-record.v1";
        const AAD_MAX: usize = AAD_PREFIX.len() + 8 + 1024 + 96;
        let mut aad = Zeroizing::new([0u8; AAD_MAX]);
        let aad_len = AAD_PREFIX.len() + 8 + tenant.len() + disk_key.len();
        aad[..AAD_PREFIX.len()].copy_from_slice(AAD_PREFIX);
        aad[AAD_PREFIX.len()..AAD_PREFIX.len() + 8]
            .copy_from_slice(&(tenant.len() as u64).to_be_bytes());
        aad[AAD_PREFIX.len() + 8..AAD_PREFIX.len() + 8 + tenant.len()].copy_from_slice(tenant);
        aad[AAD_PREFIX.len() + 8 + tenant.len()..aad_len].copy_from_slice(disk_key);

        let mut envelope = Zeroizing::new(Vec::new());
        envelope
            .try_reserve_exact(envelope_len)
            .context("encrypted record output allocation failed")?;
        ensure!(
            u64::try_from(envelope.capacity())? <= admitted,
            "encrypted record output allocation exceeded admission"
        );
        envelope.resize(envelope_len, 0);
        envelope[..4].copy_from_slice(&active_len.to_be_bytes());
        envelope[4..header_len].copy_from_slice(active_bytes);
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
        envelope[header_len..plain_start].copy_from_slice(&nonce);
        let mut at = plain_start;
        for part in [namespace.as_bytes(), key, value] {
            let len = u32::try_from(part.len())?;
            envelope[at..at + 4].copy_from_slice(&len.to_be_bytes());
            at += 4;
            envelope[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        debug_assert_eq!(at, plain_end);
        let cipher = XChaCha20Poly1305::new_from_slice(data.as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid encryption key"))?;
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(&nonce),
                &aad[..aad_len],
                &mut envelope[plain_start..plain_end],
            )
            .map_err(|_| anyhow::anyhow!("record encryption failed"))?;
        envelope[plain_end..].copy_from_slice(&tag);
        store.require_access(state)?;
        Ok(Self {
            envelope,
            _charge: charge,
        })
    }

    fn bytes(&self) -> &[u8] {
        &self.envelope
    }
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

fn inline_record_key(tenant: &str, namespace: &str, key: &[u8], index: &SecretKey) -> [u8; 96] {
    let mut result = [0u8; 96];
    result[..32].copy_from_slice(&tenant_hash(tenant));
    result[32..64].copy_from_slice(&keyed_hash(
        index,
        &[
            b"kasumi.namespace.v1",
            tenant.as_bytes(),
            namespace.as_bytes(),
        ],
    ));
    result[64..].copy_from_slice(&keyed_hash(
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

#[cfg(any(test, feature = "test-utils"))]
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

fn encrypted_record_limit(
    namespace_bytes: usize,
    key_bytes: usize,
    max_value_bytes: usize,
    state: &KeyState,
) -> Result<usize> {
    let longest_key_id = state.keys.keys().map(String::len).max().unwrap_or(0);
    let limit = max_value_bytes
        .checked_add(namespace_bytes)
        .and_then(|bytes| bytes.checked_add(key_bytes))
        .and_then(|bytes| bytes.checked_add(longest_key_id))
        .and_then(|bytes| bytes.checked_add(4 + 12 + 24 + 16))
        .context("record read budget overflow")?;
    ensure!(
        limit <= MAX_BATCH,
        "encrypted record read budget exceeds storage limit"
    );
    Ok(limit)
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

#[cfg(any(test, feature = "test-utils"))]
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
