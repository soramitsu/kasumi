//! Concrete custody boundary for physical opening and fixed NodeTables work.
//!
//! The census and listed fixed backing are bounded here. The engine holds
//! registered ownership through opening, transactions, and close.
use crate::{
    NativeConstructorFailure, NodeDisk, NodeDiskMemoryAdmission, StorageCensusDisposition,
    StorageOwnerId,
    node_file::segment_group::{GroupFailedWitness, NodeSegmentGroup},
    private_files::{DirectoryIdentity, FileIdentity},
    storage_census::{StorageOwnerKind, StoragePayload, StorageRegistration},
};
use kasumi_kv::{
    DatabaseOpenMode, DatabaseOpenSettlement, RetainedDatabaseOpening, RetainedWriteTransaction,
    TerminalObservation, WriteTerminalOperation, WriteTerminalSettlement,
};
use parking_lot::{Mutex, MutexGuard};
use std::{
    any::Any,
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

// Fund the private engine proxy before register invokes any allocation-only
// constructor. The public plan includes its Arc header and payload alignment;
// disk_memory adds the same existing allocator allowance used by other owners.
fn opening_backing_bytes(path: &Path, config: NodeStorageConfig, node: bool) -> io::Result<u64> {
    let layout = kasumi_kv::Builder::retained_opening_allocation_layout()
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    let allocation = crate::disk_memory::allocation::<u8>(
        u64::try_from(layout.size()).map_err(|_| io::ErrorKind::InvalidInput)?,
    )?;
    let native = crate::disk_memory::add(
        NodeSegmentGroup::prepared_backing_bytes(path, config.cached_files)?,
        crate::disk_memory::add(
            allocation,
            crate::disk_memory::allocation::<Arc<NodeSegmentGroup>>(1)?,
        )?,
    )?;
    if node {
        crate::disk_memory::add(
            native,
            crate::disk_memory::allocation::<u8>(
                u64::try_from(path.as_os_str().as_encoded_bytes().len())
                    .map_err(|_| io::ErrorKind::InvalidInput)?,
            )?,
        )
    } else {
        Ok(native)
    }
}

#[cfg(any(test, feature = "test-utils"))]
fn fixture_backing_bytes<B>() -> io::Result<u64> {
    let native_layout = kasumi_kv::Builder::retained_opening_allocation_layout()
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    crate::disk_memory::add(
        crate::disk_memory::allocation::<u8>(
            u64::try_from(native_layout.size()).map_err(|_| io::ErrorKind::InvalidInput)?,
        )?,
        crate::disk_memory::allocation::<B>(1)?,
    )
}

/// Explicit per-database shares selected by the installed memory owner.
/// Cache bytes include retained output guards and metadata; cached files bound
/// data descriptors independently of the group's permanently owned root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(from = "NodeStorageConfigWire", into = "NodeStorageConfigWire")]
pub struct NodeStorageConfig {
    pub cache: kasumi_kv::CacheConfig,
    pub cached_files: usize,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeStorageConfigWire {
    byte_limit: u64,
    cached_files: usize,
}
impl From<NodeStorageConfigWire> for NodeStorageConfig {
    fn from(wire: NodeStorageConfigWire) -> Self {
        Self {
            cache: kasumi_kv::CacheConfig {
                byte_limit: wire.byte_limit,
            },
            cached_files: wire.cached_files,
        }
    }
}
impl From<NodeStorageConfig> for NodeStorageConfigWire {
    fn from(config: NodeStorageConfig) -> Self {
        Self {
            byte_limit: config.cache.byte_limit,
            cached_files: config.cached_files,
        }
    }
}
impl NodeStorageConfig {
    pub const fn new(byte_limit: u64, cached_files: usize) -> Self {
        Self {
            cache: kasumi_kv::CacheConfig { byte_limit },
            cached_files,
        }
    }

    pub fn validate_within(&self, installed: Self) -> io::Result<()> {
        self.validate()?;
        installed.validate()?;
        if self.cache.byte_limit > installed.cache.byte_limit
            || self.cached_files > installed.cached_files
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.cached_files == 0
            || self.cached_files > crate::node_file::segment_group::MAX_CACHED_FILES
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
}

/// Exact physical identities of one installed group and its root file.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeGroupIdentity {
    pub directory: DirectoryIdentity,
    pub root: FileIdentity,
}

impl NodeGroupIdentity {
    /// A physical observation, not ownership authority. Opening and cleanup
    /// must still verify the acquired installed descriptors before effects.
    pub fn read(path: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            directory: crate::private_files::directory_identity(path)?,
            root: crate::private_files::file_identity(&path.join(kasumi_kv::ROOT_FILE_NAME))?,
        })
    }
}

pub enum NodeOpeningMode {
    Create,
    OwnedEmpty(NodeGroupIdentity),
    Existing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeOpeningPhase {
    Prepared,
    FileAcquisition,
    EngineOpening,
    Open,
    Closing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeWriterPhase {
    Queued,
    Begin,
    Body,
    Terminal,
    PostCommit,
    Disposal,
    Finished,
    Cancelled,
}

enum Observation<E> {
    NotEntered,
    Entered,
    Returned(Result<(), E>),
    Panicked(Box<dyn Any + Send>),
}
impl<E> Observation<E> {
    fn success(&self) -> bool {
        matches!(self, Self::Returned(Ok(())))
    }
    fn borrow(&self) -> TerminalObservation<'_, E> {
        match self {
            Self::NotEntered => TerminalObservation::NotEntered,
            Self::Entered => TerminalObservation::Entered,
            Self::Returned(Ok(())) => TerminalObservation::Returned(Ok(())),
            Self::Returned(Err(error)) => TerminalObservation::Returned(Err(error)),
            Self::Panicked(payload) => TerminalObservation::Panicked(payload.as_ref()),
        }
    }
}
// Synthetic backends are an explicit test-only construction purpose. They
// have no acquired physical file and cannot produce a physical identity or
// failed-file transfer witness. Both purposes own the same registered payload.
enum OpeningFile {
    Physical(Arc<NodeSegmentGroup>),
    #[cfg(any(test, feature = "test-utils"))]
    Synthetic {
        config: NodeStorageConfig,
    },
}
impl OpeningFile {
    fn physical(&self) -> io::Result<&Arc<NodeSegmentGroup>> {
        match self {
            Self::Physical(file) => Ok(file),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Synthetic { .. } => Err(io::ErrorKind::Unsupported.into()),
        }
    }
    fn cache_limit(&self) -> u64 {
        match self {
            Self::Physical(file) => file.disk().native_storage_config().cache.byte_limit,
            #[cfg(any(test, feature = "test-utils"))]
            Self::Synthetic { config } => config.cache.byte_limit,
        }
    }
    fn publish_ready(&self) -> anyhow::Result<()> {
        match self {
            Self::Physical(file) => file.publish_ready(),
            // This branch records only the already-proved table publication.
            // It performs no file operation and supplies no physical witness.
            #[cfg(any(test, feature = "test-utils"))]
            Self::Synthetic { .. } => Ok(()),
        }
    }
}
struct OpeningState {
    mode: NodeOpeningMode,
    file: OpeningFile,
    engine: RetainedDatabaseOpening,
    phase: NodeOpeningPhase,
    // The first accepted table request owns the only create publication proof.
    // A failed registration may release its reservation before any request exists,
    // and a settled capacity denial releases it after that request published nothing.
    tables_reserved: bool,
    tables_request: Option<StorageOwnerId>,
    existing_tables_verified: bool,
    ready_publication: Observation<anyhow::Error>,
    acquisition: Observation<anyhow::Error>,
    opening_outer: Observation<std::convert::Infallible>,
    outcomes_released: bool,
    failed_transferred: bool,
    pending_transfer: Option<GroupFailedWitness>,
    #[cfg(test)]
    after_failed_disposal: Option<Box<dyn FnOnce() + Send>>,
    #[cfg(test)]
    before_close_locked: Option<Box<dyn FnOnce() + Send>>,
    #[cfg(test)]
    before_retry_close_locked: Option<Box<dyn FnOnce() + Send>>,
    failed_recovery: Observation<io::Error>,
}
fn observed_failure<E>(observation: TerminalObservation<'_, E>) -> bool {
    matches!(
        observation,
        TerminalObservation::Entered
            | TerminalObservation::Returned(Err(_))
            | TerminalObservation::Panicked(_)
    )
}
fn transaction_failure(report: &kasumi_kv::WriteTerminalReport<'_>) -> bool {
    observed_failure(report.terminal())
        || observed_failure(report.rollback())
        || observed_failure(report.disposal())
}
/// A writer refused for capacity before publication, while staging (its body
/// failed with a denial and aborted) or at commit. The native writer was
/// rolled back whole, its gate was released and disposed, and the opening
/// stays open; the caller may acknowledge the child and return the denial.
fn settled_capacity_denial<E>(
    phase: NodeWriterPhase,
    begin: &Observation<kasumi_kv::TransactionError>,
    body: &Observation<E>,
    outer: &Observation<std::convert::Infallible>,
    terminal: Option<kasumi_kv::WriteTerminalReport<'_>>,
    body_denied: impl Fn(&E) -> bool,
) -> bool {
    let Some(terminal) = terminal else {
        return false;
    };
    let staged = matches!(body, Observation::Returned(Err(error)) if body_denied(error))
        && terminal.operation() == Some(WriteTerminalOperation::Abort)
        && matches!(terminal.terminal(), TerminalObservation::Returned(Ok(())));
    let committed = body.success() && terminal.is_capacity_denied();
    phase == NodeWriterPhase::Finished
        && begin.success()
        && outer.success()
        && terminal.disposal_complete()
        && (staged || committed)
}
impl OpeningState {
    fn transfer_failed(&mut self) -> FailedOpeningRecovery {
        if self.failed_transferred {
            return FailedOpeningRecovery::AwaitingDiskCensus;
        }
        if self.engine.report().settlement() != DatabaseOpenSettlement::FailedDisposed
            || !matches!(self.failed_recovery, Observation::NotEntered)
        {
            return FailedOpeningRecovery::Retained;
        }
        let Some(witness) = self.pending_transfer.as_ref() else {
            return FailedOpeningRecovery::Retained;
        };
        self.failed_recovery = Observation::Entered;
        match catch_unwind(AssertUnwindSafe(|| {
            self.file.physical()?.transfer_failed(witness)
        })) {
            Ok(Ok(true)) => {
                self.failed_transferred = true;
                self.pending_transfer = None;
                self.failed_recovery = Observation::Returned(Ok(()));
                self.outcomes_released = true;
                FailedOpeningRecovery::AwaitingDiskCensus
            }
            Ok(Ok(false)) => {
                // Contention produces no new original failure. Earlier group
                // members may already have transferred; keep their receipts
                // and the exact prior ack for only the remaining owners. A
                // later nonblocking attempt never repeats engine disposal.
                self.failed_recovery = Observation::NotEntered;
                FailedOpeningRecovery::PendingTransfer
            }
            Ok(Err(error)) => {
                self.failed_recovery = Observation::Returned(Err(error));
                FailedOpeningRecovery::Retained
            }
            Err(payload) => {
                self.failed_recovery = Observation::Panicked(payload);
                FailedOpeningRecovery::Retained
            }
        }
    }
    fn has_failures(&self) -> bool {
        let report = self.engine.report();
        let disposal = report.disposal();
        observed_failure(self.acquisition.borrow())
            || observed_failure(self.ready_publication.borrow())
            || observed_failure(self.opening_outer.borrow())
            || observed_failure(report.opening())
            || report.with_partial_close_observation(observed_failure)
            || observed_failure(report.failed_disposal())
            || observed_failure(self.failed_recovery.borrow())
            || report.database_close().is_some_and(|close| {
                observed_failure(close.shutdown())
                    || observed_failure(close.backend())
                    || observed_failure(close.failed_disposal())
            })
            || (0..disposal.observation_count())
                .any(|index| disposal.with_observation(index, observed_failure))
            || report.fence().with_observation(observed_failure)
    }
}
struct DatabaseOwner {
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    census_id: StorageOwnerId,
    stopped: AtomicBool,
    serial: Mutex<()>,
    state: Mutex<OpeningState>,
    node: Option<crate::RegisteredNodeBody>,
}
impl DatabaseOwner {
    fn dispose_write(
        &self,
        transaction: &mut RetainedWriteTransaction,
        wait_for_settled: bool,
    ) -> bool {
        // A settled commit or abort has released its native writer gate. The
        // synchronous worker can wait for a concurrent opening-state reader
        // without losing a clean terminal to transient try_lock contention.
        // A retained terminal can still own that gate, so drain and retained
        // failures must continue to use a nonblocking state attempt.
        let database = if wait_for_settled
            && matches!(
                transaction.report().settlement(),
                WriteTerminalSettlement::Settled | WriteTerminalSettlement::HoldingWriter
            ) {
            Some(self.state.lock())
        } else {
            self.state.try_lock()
        };
        let Some(database) = database else {
            return false;
        };
        let Some(witness) = database.engine.retained_database() else {
            return false;
        };
        if transaction.report().operation().is_none() {
            let _ = transaction.abort();
        }
        transaction.dispose_settled(witness).disposal_complete()
    }

    // Both explicit close and census drain enter the same retained operation.
    // An entered close is never replayed; only a busy transaction wait can
    // advance when its actual owner drains.
    fn close_locked(state: &mut OpeningState) -> DatabaseOpenSettlement {
        #[cfg(test)]
        if let Some(before_close) = state.before_close_locked.take() {
            before_close();
        }
        state.phase = NodeOpeningPhase::Closing;
        if state.pending_transfer.is_some() {
            let _ = state.transfer_failed();
        }
        let settlement = state.engine.report().settlement();
        if !state.failed_transferred
            && !matches!(
                settlement,
                DatabaseOpenSettlement::Closed
                    | DatabaseOpenSettlement::Disposed
                    | DatabaseOpenSettlement::DrainedWithFailure
                    | DatabaseOpenSettlement::FailedDisposed
            )
        {
            // Close can produce a new original shutdown or backend outcome.
            // A previously released report cannot acknowledge that future work.
            state.outcomes_released = false;
            let _ = state.engine.close();
        }
        state.engine.report().settlement()
    }
}
impl StoragePayload for DatabaseOwner {
    const KIND: StorageOwnerKind = StorageOwnerKind::Database;
    fn drive(&self) -> bool {
        if self
            .node
            .as_ref()
            .is_some_and(|node| !node.lifecycle.permits_drive())
        {
            return false;
        }
        self.stopped.store(true, Ordering::Release);
        reads::drain_source_owners(&self.provider, self.census_id);
        RegisteredNodeOpening::drain_released_clean_writers(&self.provider, self.census_id);
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        let mut settlement = Self::close_locked(&mut state);
        // A failed Ready attempt may leave visible but unproved header bytes.
        // A report acknowledgement cannot retire this physical owner.
        if observed_failure(state.ready_publication.borrow()) {
            return false;
        }
        if state.failed_transferred {
            return settlement == DatabaseOpenSettlement::FailedDisposed
                && state.failed_recovery.success()
                && state.outcomes_released
                && state
                    .file
                    .physical()
                    .is_ok_and(|file| file.failed_transfer_accepted());
        }
        if matches!(
            settlement,
            DatabaseOpenSettlement::DrainedWithFailure | DatabaseOpenSettlement::FailedDisposed
        ) {
            // Ordinary retirement cannot acknowledge a failed close or turn
            // operational disposal into a disk-census acceptance receipt.
            return false;
        }
        if settlement == DatabaseOpenSettlement::Closed {
            // Native close and actual owner disposal have independent original
            // observations. Census retirement needs both positive witnesses.
            settlement = state.engine.dispose().settlement();
        }
        settlement == DatabaseOpenSettlement::Disposed
            && state.engine.report().disposal().complete()
            && (state.outcomes_released || !state.has_failures())
    }
}
/// Every facade is secondary to the actual installed census owner.
pub(crate) enum OpeningLookup {
    Active(RegisteredNodeOpening),
    Busy,
    Missing,
}

pub struct RegisteredNodeOpening {
    registration: StorageRegistration<DatabaseOwner>,
}
impl RegisteredNodeOpening {
    /// Borrow the same retained owner after the original facade disappeared.
    /// This never creates, reopens or retries a physical resource.
    pub fn retained(
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
    ) -> Option<Self> {
        let registration = provider.storage_census().retained(provider.clone(), id)?;
        Some(Self { registration })
    }
    pub fn prepare(
        path: &Path,
        id: Uuid,
        disk: Arc<NodeDisk>,
        mode: NodeOpeningMode,
        config: NodeStorageConfig,
    ) -> Result<Self, NativeConstructorFailure> {
        Self::prepare_inner(path, id, disk, mode, config, None)
    }

    pub(crate) fn prepare_node(
        path: &Path,
        id: Uuid,
        disk: Arc<NodeDisk>,
        scratch: Arc<crate::ScratchDisk>,
        mode: NodeOpeningMode,
        config: NodeStorageConfig,
    ) -> Result<Self, NativeConstructorFailure> {
        Self::prepare_inner(path, id, disk, mode, config, Some(scratch))
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn prepare_fixture<B: kasumi_kv::SegmentGroupBackend + 'static>(
        inputs: &mut Option<crate::NodeFixtureInputs<B>>,
        id: Uuid,
        existing: bool,
        config: NodeStorageConfig,
    ) -> Result<Self, NativeConstructorFailure> {
        let supplied = inputs.as_ref().expect("preowned fixture inputs");
        if id.is_nil() {
            return Err(NativeConstructorFailure::Preclaim(
                io::ErrorKind::InvalidInput.into(),
            ));
        }
        config
            .validate()
            .map_err(NativeConstructorFailure::Preclaim)?;
        if let Some(disk) = &supplied.persistent {
            if !Arc::ptr_eq(disk.memory(), supplied.scratch.memory()) {
                return Err(NativeConstructorFailure::Preclaim(
                    io::ErrorKind::InvalidInput.into(),
                ));
            }
            config
                .validate_within(disk.native_storage_config())
                .map_err(NativeConstructorFailure::Preclaim)?;
        }
        let provider = supplied.scratch.memory().clone();
        let backing = fixture_backing_bytes::<B>().map_err(NativeConstructorFailure::Preclaim)?;
        let registration =
            provider
                .storage_census()
                .register_native(provider.clone(), backing, |census_id| {
                    // The original concrete backend stays in `inputs` until the same
                    // constructor grant is installed. No backend call occurs here.
                    let supplied = inputs.take().expect("one admitted fixture construction");
                    let mode = if existing {
                        NodeOpeningMode::Existing
                    } else {
                        NodeOpeningMode::Create
                    };
                    let engine_mode = if existing {
                        DatabaseOpenMode::Existing
                    } else {
                        DatabaseOpenMode::Create
                    };
                    let engine = kasumi_kv::Database::builder(
                        supplied.admission,
                        *id.as_bytes(),
                        config.cache,
                    )
                    .retain_backend(Box::new(supplied.backend), engine_mode);
                    let node = crate::RegisteredNodeBody::prepare(
                        None,
                        supplied.persistent,
                        supplied.scratch,
                        provider.clone(),
                        census_id,
                    );
                    let owner = DatabaseOwner {
                        node: Some(node),
                        provider: provider.clone(),
                        census_id,
                        stopped: AtomicBool::new(false),
                        serial: Mutex::new(()),
                        state: Mutex::new(OpeningState {
                            mode,
                            file: OpeningFile::Synthetic { config },
                            engine,
                            phase: NodeOpeningPhase::Prepared,
                            tables_reserved: false,
                            tables_request: None,
                            existing_tables_verified: false,
                            ready_publication: Observation::NotEntered,
                            acquisition: Observation::NotEntered,
                            opening_outer: Observation::NotEntered,
                            outcomes_released: false,
                            failed_transferred: false,
                            pending_transfer: None,
                            #[cfg(test)]
                            after_failed_disposal: None,
                            #[cfg(test)]
                            before_close_locked: None,
                            #[cfg(test)]
                            before_retry_close_locked: None,
                            failed_recovery: Observation::NotEntered,
                        }),
                    };
                    #[cfg(test)]
                    tests::observe_owner_identity_before_publication(&owner);
                    owner
                })?;
        Ok(Self { registration })
    }

    fn prepare_inner(
        path: &Path,
        id: Uuid,
        disk: Arc<NodeDisk>,
        mode: NodeOpeningMode,
        config: NodeStorageConfig,
        scratch: Option<Arc<crate::ScratchDisk>>,
    ) -> Result<Self, NativeConstructorFailure> {
        if id.is_nil() {
            return Err(NativeConstructorFailure::Preclaim(
                io::ErrorKind::InvalidInput.into(),
            ));
        }
        config
            .validate_within(disk.native_storage_config())
            .map_err(NativeConstructorFailure::Preclaim)?;
        let provider = disk.memory().clone();
        let known_backing = opening_backing_bytes(path, config, scratch.is_some())
            .map_err(NativeConstructorFailure::Preclaim)?;
        let registration = provider.storage_census().register_native(
            provider.clone(),
            known_backing,
            |census_id| {
                let node = scratch.map(|scratch| {
                    crate::RegisteredNodeBody::prepare(
                        Some(path),
                        Some(disk.clone()),
                        scratch,
                        provider.clone(),
                        census_id,
                    )
                });
                let file = NodeSegmentGroup::retained_prepared(path, id, disk, config.cached_files);
                let engine_mode = if matches!(mode, NodeOpeningMode::Existing) {
                    DatabaseOpenMode::Existing
                } else {
                    DatabaseOpenMode::Create
                };
                let engine =
                    kasumi_kv::Database::builder(file.clone(), *id.as_bytes(), config.cache)
                        .retain_backend(Box::new(file.clone()), engine_mode);
                let owner = DatabaseOwner {
                    node,
                    provider: provider.clone(),
                    census_id,
                    stopped: AtomicBool::new(false),
                    serial: Mutex::new(()),
                    state: Mutex::new(OpeningState {
                        mode,
                        file: OpeningFile::Physical(file),
                        engine,
                        phase: NodeOpeningPhase::Prepared,
                        tables_reserved: false,
                        tables_request: None,
                        existing_tables_verified: false,
                        ready_publication: Observation::NotEntered,
                        acquisition: Observation::NotEntered,
                        opening_outer: Observation::NotEntered,
                        outcomes_released: false,
                        failed_transferred: false,
                        pending_transfer: None,
                        #[cfg(test)]
                        after_failed_disposal: None,
                        #[cfg(test)]
                        before_close_locked: None,
                        #[cfg(test)]
                        before_retry_close_locked: None,
                        failed_recovery: Observation::NotEntered,
                    }),
                };
                #[cfg(test)]
                tests::observe_owner_identity_before_publication(&owner);
                owner
            },
        )?;
        Ok(Self { registration })
    }
    pub fn id(&self) -> StorageOwnerId {
        self.registration.id()
    }
    pub(crate) fn clone_facade(&self) -> Self {
        Self {
            registration: self.registration.clone(),
        }
    }
    pub(crate) fn provider(&self) -> &Arc<dyn NodeDiskMemoryAdmission> {
        self.registration.provider()
    }
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        self.registration.same_owner(&other.registration)
    }
    /// Node shutdown has its independent live-resource gate. Consuming a node
    /// facade cannot seal a native database still in use by another facade.
    pub(crate) fn release_node_facade(self) -> StorageCensusDisposition {
        self.registration.retire()
    }
    pub(crate) fn has_node_body(&self) -> bool {
        self.registration.owner().node.is_some()
    }
    pub(crate) fn node_body(&self) -> &crate::RegisteredNodeBody {
        self.registration
            .owner()
            .node
            .as_ref()
            .expect("composite node purpose")
    }
    #[cfg(test)]
    pub(crate) fn node_request_bytes(path: &Path, config: NodeStorageConfig) -> io::Result<u64> {
        crate::StorageCensus::registration_request_bytes::<DatabaseOwner>(opening_backing_bytes(
            path, config, true,
        )?)
    }
    #[cfg(test)]
    pub(crate) fn fixture_request_bytes<B>() -> io::Result<u64> {
        crate::StorageCensus::registration_request_bytes::<DatabaseOwner>(
            fixture_backing_bytes::<B>()?,
        )
    }
    #[cfg(test)]
    pub(crate) fn allocation_address(&self) -> usize {
        // The same pinned Arc header/alignment formula used by the prospective
        // registration quote. The test must observe this exact System.dealloc
        // address; a wrong layout cannot produce the asserted positive witness.
        let (_, offset) = std::alloc::Layout::new::<[usize; 2]>()
            .extend(std::alloc::Layout::new::<DatabaseOwner>())
            .unwrap();
        (std::ptr::from_ref(self.registration.owner()) as usize) - offset
    }
    pub(crate) fn try_retained(
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
    ) -> OpeningLookup {
        use crate::storage_census::TypedOwnerLookup;
        match provider.storage_census().try_retained(provider.clone(), id) {
            TypedOwnerLookup::Active(registration) => OpeningLookup::Active(Self { registration }),
            TypedOwnerLookup::Busy => OpeningLookup::Busy,
            TypedOwnerLookup::Missing => OpeningLookup::Missing,
        }
    }
    /// Dispose actual native owner, keeping the composite node allocation live.
    pub(crate) fn dispose_native(&self) -> io::Result<DatabaseOpenSettlement> {
        let owner = self.registration.owner();
        let Some(mut state) = owner.state.try_lock() else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        let settlement = state.engine.report().settlement();
        if !matches!(
            settlement,
            DatabaseOpenSettlement::Closed | DatabaseOpenSettlement::Disposed
        ) {
            return Ok(settlement);
        }
        let settlement = state.engine.dispose().settlement();
        Ok(settlement)
    }
    pub fn open(&self) -> NodeOpeningPhase {
        let owner = self.registration.owner();
        let mut state = owner.state.lock();
        if state.phase != NodeOpeningPhase::Prepared || owner.stopped.load(Ordering::Acquire) {
            return state.phase;
        }
        let file = match &state.file {
            OpeningFile::Physical(file) => Some(file.clone()),
            #[cfg(any(test, feature = "test-utils"))]
            OpeningFile::Synthetic { .. } => None,
        };
        if let Some(file) = file {
            state.phase = NodeOpeningPhase::FileAcquisition;
            state.acquisition = Observation::Entered;
            let result = catch_unwind(AssertUnwindSafe(|| file.acquire_prepared(&state.mode)));
            state.acquisition = match result {
                Ok(result) => Observation::Returned(result),
                Err(payload) => Observation::Panicked(payload),
            };
            if !state.acquisition.success() {
                return state.phase;
            }
        }
        state.phase = NodeOpeningPhase::EngineOpening;
        state.opening_outer = Observation::Entered;
        match catch_unwind(AssertUnwindSafe(|| state.engine.open().settlement())) {
            Ok(settlement) => {
                state.opening_outer = Observation::Returned(Ok(()));
                if settlement == DatabaseOpenSettlement::Ready {
                    state.phase = NodeOpeningPhase::Open;
                }
            }
            Err(payload) => {
                state.opening_outer = Observation::Panicked(payload);
                owner.stopped.store(true, Ordering::Release);
            }
        }
        state.phase
    }
    pub fn report(&self) -> NodeOpeningReport<'_> {
        NodeOpeningReport {
            registration: &self.registration,
            state: self.registration.owner().state.lock(),
        }
    }
    /// Seal new work and attempt close without consuming the original owner or
    /// its report. WouldBlock means an active operation owns the state lock;
    /// WaitingForTransactions means an admitted reader or writer must drain.
    /// Both may be retried on this same registered opening. An entered close
    /// error, panic or uncertain native disposition is retained and never
    /// re-entered; inspect the original observations with `report()`.
    pub fn close(&self) -> io::Result<DatabaseOpenSettlement> {
        let owner = self.registration.owner();
        owner.stopped.store(true, Ordering::Release);
        // A recoverable read error may have lost its last facade while this
        // opening lock was busy. Revisit only this opening's released routine
        // readers before asking the native database to close its transactions.
        let provider = {
            let Some(_state) = owner.state.try_lock() else {
                return Err(io::ErrorKind::WouldBlock.into());
            };
            owner.provider.clone()
        };
        reads::drain_source_owners(&provider, self.registration.id());
        Self::drain_released_routine_readers(&provider, self.registration.id());
        Self::drain_released_clean_writers(&provider, self.registration.id());
        let Some(mut state) = owner.state.try_lock() else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        let settlement = DatabaseOwner::close_locked(&mut state);
        drop(state);
        if settlement == DatabaseOpenSettlement::WaitingForTransactions {
            // A last error facade can drop while close held the opening lock,
            // after the pre-close pass. Give only this opening's routine readers
            // a post-close pass and retry the existing busy close once.
            reads::drain_source_owners(&provider, self.registration.id());
            Self::drain_released_routine_readers(&provider, self.registration.id());
            Self::drain_released_clean_writers(&provider, self.registration.id());
            let Some(mut state) = owner.state.try_lock() else {
                return Err(io::ErrorKind::WouldBlock.into());
            };
            #[cfg(test)]
            if let Some(before_retry) = state.before_retry_close_locked.take() {
                before_retry();
            }
            let settlement = DatabaseOwner::close_locked(&mut state);
            return Ok(if settlement == DatabaseOpenSettlement::Disposed {
                DatabaseOpenSettlement::Closed
            } else {
                settlement
            });
        }
        // This public operation reports the preserved native close result.
        // Census drive independently checks the actual Disposed witness.
        Ok(if settlement == DatabaseOpenSettlement::Disposed {
            DatabaseOpenSettlement::Closed
        } else {
            settlement
        })
    }
    // Stop future dispatch through this exact installed opening.
    pub(crate) fn seal_store_transactions(&self) {
        self.registration
            .owner()
            .stopped
            .store(true, Ordering::Release);
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn begin_store_read(
        &self,
    ) -> Result<kasumi_kv::ReadTransaction, kasumi_kv::TransactionError> {
        let owner = self.registration.owner();
        if owner.stopped.load(Ordering::Acquire) {
            return Err(kasumi_kv::StorageError::DatabaseClosed.into());
        }
        let admission = {
            let state = owner.state.lock();
            if owner.stopped.load(Ordering::Acquire) || state.phase != NodeOpeningPhase::Open {
                return Err(kasumi_kv::StorageError::DatabaseClosed.into());
            }
            state
                .engine
                .database()
                .ok_or(kasumi_kv::StorageError::DatabaseClosed)?
                .transaction_admission()
        };
        admission.begin_read()
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn begin_store_write(
        &self,
    ) -> Result<kasumi_kv::WriteTransaction, kasumi_kv::TransactionError> {
        let owner = self.registration.owner();
        if owner.stopped.load(Ordering::Acquire) {
            return Err(kasumi_kv::StorageError::DatabaseClosed.into());
        }
        let admission = {
            let state = owner.state.lock();
            if owner.stopped.load(Ordering::Acquire) || state.phase != NodeOpeningPhase::Open {
                return Err(kasumi_kv::StorageError::DatabaseClosed.into());
            }
            state
                .engine
                .database()
                .ok_or(kasumi_kv::StorageError::DatabaseClosed)?
                .transaction_admission()
        };
        admission.begin_write()
    }

    pub fn physical_identity(&self) -> anyhow::Result<NodeGroupIdentity> {
        let owner = self.registration.owner();
        let state = owner.state.lock();
        if owner.stopped.load(Ordering::Acquire) || state.phase != NodeOpeningPhase::Open {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe).into());
        }
        state.file.physical()?.identity()
    }

    pub fn configure_cache(
        &self,
        config: kasumi_kv::CacheConfig,
    ) -> Result<(), kasumi_kv::StorageError> {
        let owner = self.registration.owner();
        let state = owner.state.lock();
        if owner.stopped.load(Ordering::Acquire) || state.phase != NodeOpeningPhase::Open {
            return Err(kasumi_kv::StorageError::DatabaseClosed);
        }
        if config.byte_limit > state.file.cache_limit() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        state
            .engine
            .database()
            .ok_or(kasumi_kv::StorageError::DatabaseClosed)?
            .configure_cache(config)
    }

    pub fn cache_stats(&self) -> Result<kasumi_kv::CacheStats, kasumi_kv::StorageError> {
        let owner = self.registration.owner();
        let state = owner.state.lock();
        if owner.stopped.load(Ordering::Acquire) || state.phase != NodeOpeningPhase::Open {
            return Err(kasumi_kv::StorageError::DatabaseClosed);
        }
        state
            .engine
            .database()
            .ok_or(kasumi_kv::StorageError::DatabaseClosed)?
            .cache_stats()
    }

    pub fn warm_cache(
        &self,
        work_limit: usize,
    ) -> Result<kasumi_kv::CacheWarmup, kasumi_kv::StorageError> {
        let owner = self.registration.owner();
        let state = owner.state.lock();
        if owner.stopped.load(Ordering::Acquire) || state.phase != NodeOpeningPhase::Open {
            return Err(kasumi_kv::StorageError::DatabaseClosed);
        }
        state
            .engine
            .database()
            .ok_or(kasumi_kv::StorageError::DatabaseClosed)?
            .warm_cache(work_limit)
    }

    pub fn warm_cache_if_needed(
        &self,
        work_limit: usize,
    ) -> Result<kasumi_kv::CacheWarmup, kasumi_kv::StorageError> {
        let owner = self.registration.owner();
        let state = owner.state.lock();
        if owner.stopped.load(Ordering::Acquire) || state.phase != NodeOpeningPhase::Open {
            return Err(kasumi_kv::StorageError::DatabaseClosed);
        }
        state
            .engine
            .database()
            .ok_or(kasumi_kv::StorageError::DatabaseClosed)?
            .warm_cache_if_needed(work_limit)
    }

    pub fn cache_warmup_status(
        &self,
    ) -> Result<kasumi_kv::CacheWarmupStatus, kasumi_kv::StorageError> {
        let owner = self.registration.owner();
        let state = owner.state.lock();
        if owner.stopped.load(Ordering::Acquire) || state.phase != NodeOpeningPhase::Open {
            return Err(kasumi_kv::StorageError::DatabaseClosed);
        }
        state
            .engine
            .database()
            .ok_or(kasumi_kv::StorageError::DatabaseClosed)?
            .cache_warmup_status()
    }

    pub fn request_cache_warm_retry(&self) -> Result<(), kasumi_kv::StorageError> {
        let owner = self.registration.owner();
        let state = owner.state.lock();
        if owner.stopped.load(Ordering::Acquire) || state.phase != NodeOpeningPhase::Open {
            return Err(kasumi_kv::StorageError::DatabaseClosed);
        }
        state
            .engine
            .database()
            .ok_or(kasumi_kv::StorageError::DatabaseClosed)?
            .request_cache_warm_retry()
    }

    /// Fixed, closed operation shape with no user callback or raw transaction
    /// escape. The actual queued request is registered before any serial wait.
    /// Once registration succeeds, even a concurrent close returns the exact
    /// cancelled child facade so its ID, report, and retirement remain owned.
    pub fn queue_node_tables(&self) -> io::Result<RegisteredNodeTables> {
        if self.registration.owner().stopped.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut state = self.registration.owner().state.lock();
        if matches!(state.mode, NodeOpeningMode::Existing)
            || state.phase != NodeOpeningPhase::Open
            || state.tables_reserved
            || self.registration.owner().stopped.load(Ordering::Acquire)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        state.tables_reserved = true;
        let provider = self.registration.provider().clone();
        drop(state);
        let database = self.registration.clone();
        let registration = provider.storage_census().register_child(
            provider.clone(),
            0,
            &self.registration,
            || NodeTablesRequest {
                database,
                state: Mutex::new(WriterState {
                    phase: NodeWriterPhase::Queued,
                    transaction: None,
                    begin: Observation::NotEntered,
                    body: Observation::NotEntered,
                    outer: Observation::NotEntered,
                    outcomes_released: false,
                    #[cfg(test)]
                    fail_owner_before_terminal: false,
                }),
            },
        );
        let mut state = self.registration.owner().state.lock();
        let registration = match registration {
            Ok(registration) => registration,
            Err(error) => {
                state.tables_reserved = false;
                return Err(error);
            }
        };
        if self.registration.owner().stopped.load(Ordering::Acquire)
            || state.phase != NodeOpeningPhase::Open
        {
            // Close may have sealed and physically settled the database while
            // registration waited for a census slot. The child is already a
            // real census owner: return it cancelled, never retire and discard
            // an exact ID or a retained original report inside this method.
            drop(state);
            registration.owner().state.lock().phase = NodeWriterPhase::Cancelled;
            return Ok(RegisteredNodeTables { registration });
        }
        state.tables_request = Some(registration.id());
        Ok(RegisteredNodeTables { registration })
    }
    fn startup_child_constructor(
        &self,
        id: StorageOwnerId,
        purpose: crate::storage_census::NativeStartupChildPurpose,
    ) -> Option<NativeConstructorFailure> {
        let provider = self.registration.owner().provider.clone();
        match purpose {
            crate::storage_census::NativeStartupChildPurpose::Tables => {
                RegisteredNodeTables::retained_constructor(provider, id)
            }
            crate::storage_census::NativeStartupChildPurpose::Verification => {
                RegisteredNodeRead::retained_constructor(provider, id)
            }
        }
    }
    /// The startup-only child claim is nonblocking and retains its exact
    /// constructor failure. It cannot fall back to ordinary child admission.
    fn queue_startup_tables(&self) -> Result<RegisteredNodeTables, NativeConstructorFailure> {
        let owner = self.registration.owner();
        let Some(mut state) = owner.state.try_lock() else {
            return Err(NativeConstructorFailure::Preclaim(
                io::ErrorKind::WouldBlock.into(),
            ));
        };
        if matches!(state.mode, NodeOpeningMode::Existing)
            || state.phase != NodeOpeningPhase::Open
            || state.tables_reserved
            || owner.stopped.load(Ordering::Acquire)
        {
            return Err(NativeConstructorFailure::Preclaim(
                io::ErrorKind::InvalidInput.into(),
            ));
        }
        state.tables_reserved = true;
        let provider = owner.provider.clone();
        drop(state);
        let database = self.registration.clone();
        let result = provider.storage_census().register_native_startup_child(
            provider.clone(),
            &self.registration,
            |id| {
                let mut state = owner.state.try_lock().ok_or(io::ErrorKind::WouldBlock)?;
                state.tables_request = Some(id);
                Ok(())
            },
            |_| NodeTablesRequest {
                database,
                state: Mutex::new(WriterState {
                    phase: NodeWriterPhase::Queued,
                    transaction: None,
                    begin: Observation::NotEntered,
                    body: Observation::NotEntered,
                    outer: Observation::NotEntered,
                    outcomes_released: false,
                    #[cfg(test)]
                    fail_owner_before_terminal: false,
                }),
            },
        );
        match result {
            Ok(registration) => Ok(RegisteredNodeTables { registration }),
            Err(error) => {
                // A retained child forbids a replacement request. Preclaim
                // refusal has no child; reset only while the same state is free.
                if matches!(error, NativeConstructorFailure::Preclaim(_))
                    && let Some(mut state) = owner.state.try_lock()
                {
                    state.tables_reserved = false;
                }
                Err(error)
            }
        }
    }
    /// The matching first table request must have returned a successful Commit
    /// and positively disposed its actual transaction. A publication enters
    /// once: a write or sync error can leave visible but unproved Ready bytes,
    /// so the same file is never retried or adopted through this method.
    pub fn publish_ready_after_tables(&self, tables: &RegisteredNodeTables) -> io::Result<()> {
        let owner = self.registration.owner();
        let request = tables.registration.owner();
        if !std::ptr::eq(request.database.owner(), owner) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Writer run takes this lock before the database state lock. A busy
        // worker therefore produces WouldBlock without reversing lock order.
        let Some(writer) = request.state.try_lock() else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        let Some(mut state) = owner.state.try_lock() else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        let terminal_proved = writer.transaction.as_ref().is_some_and(|transaction| {
            let report = transaction.report();
            report.operation() == Some(WriteTerminalOperation::Commit)
                && matches!(report.terminal(), TerminalObservation::Returned(Ok(())))
                && report.disposal_complete()
        });
        if owner.stopped.load(Ordering::Acquire)
            || state.phase != NodeOpeningPhase::Open
            || matches!(state.mode, NodeOpeningMode::Existing)
            || state.tables_request != Some(tables.id())
            || !matches!(state.ready_publication, Observation::NotEntered)
            || writer.phase != NodeWriterPhase::Finished
            || !writer.begin.success()
            || !writer.body.success()
            || !writer.outer.success()
            || !terminal_proved
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        state.ready_publication = Observation::Entered;
        state.ready_publication =
            match catch_unwind(AssertUnwindSafe(|| state.file.publish_ready())) {
                Ok(result) => Observation::Returned(result),
                Err(payload) => Observation::Panicked(payload),
            };
        if state.ready_publication.success() {
            Ok(())
        } else {
            owner.stopped.store(true, Ordering::Release);
            // The original error or panic remains borrowed from report().
            Err(io::ErrorKind::Other.into())
        }
    }
    /// Explicitly retire failed operational backing and transfer its exact
    /// already-drained FileOwner into installed custody. A later accepted disk
    /// census is required before storage-census retirement can release reports.
    pub fn recover_failed_close(
        &self,
        acknowledgement: FailedOpeningAcknowledgement,
    ) -> io::Result<FailedOpeningRecovery> {
        if !std::ptr::eq(acknowledgement.owner.owner(), self.registration.owner()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let owner = self.registration.owner();
        let Some(mut state) = owner.state.try_lock() else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        if state.engine.report().settlement() != DatabaseOpenSettlement::DrainedWithFailure
            || !matches!(state.failed_recovery, Observation::NotEntered)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Revalidate the exact file generation and all original report guards
        // before operational disposal or any acknowledgement mutation.
        state
            .file
            .physical()?
            .with_failed_close_reports(&acknowledgement.file, |_| ())?;
        owner.stopped.store(true, Ordering::Release);
        state.outcomes_released = false;
        state.pending_transfer = Some(acknowledgement.file);
        // Any disposal error/panic is a new outcome, never covered by the
        // earlier acknowledgement. The actual engine report owner stays installed.
        if state.engine.dispose().settlement() != DatabaseOpenSettlement::FailedDisposed {
            return Ok(FailedOpeningRecovery::Retained);
        }
        #[cfg(test)]
        if let Some(hook) = state.after_failed_disposal.take() {
            hook();
        }
        Ok(state.transfer_failed())
    }
    /// Resume only an already acknowledged, operationally disposed owner.
    /// Contention never replays disposal or acknowledges a newly produced error.
    pub fn resume_failed_recovery(&self) -> io::Result<FailedOpeningRecovery> {
        let owner = self.registration.owner();
        let Some(mut state) = owner.state.try_lock() else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        if state.pending_transfer.is_none() && !state.failed_transferred {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(state.transfer_failed())
    }
    /// Relinquish this caller's outcomes after inspection. Physical uncertainty
    /// still prevents retirement; other real facades still retain the owner.
    pub fn retire(self) -> StorageCensusDisposition {
        let owner = self.registration.owner();
        owner.stopped.store(true, Ordering::Release);
        if let Some(mut state) = owner.state.try_lock()
            && matches!(
                state.engine.report().settlement(),
                DatabaseOpenSettlement::Closed | DatabaseOpenSettlement::Disposed
            )
        {
            state.outcomes_released = true;
        }
        self.registration.retire()
    }
}
/// A caller's explicit acknowledgement of one already-terminal failed owner.
/// Private, non-Clone fields retain the actual registration, preventing address
/// reuse and cross-memory-core substitution even when public IDs coincide.
pub struct FailedOpeningAcknowledgement {
    // Release the private identity before the registration that funds it.
    file: GroupFailedWitness,
    owner: StorageRegistration<DatabaseOwner>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailedOpeningRecovery {
    PendingTransfer,
    AwaitingDiskCensus,
    Retained,
}
pub struct NodeOpeningReport<'a> {
    registration: &'a StorageRegistration<DatabaseOwner>,
    state: MutexGuard<'a, OpeningState>,
}
impl NodeOpeningReport<'_> {
    /// Explicitly acknowledge the terminal engine report and inspect the actual
    /// FileOwner logical errors. The callback borrows the original objects;
    /// returning projections or telemetry never constitutes this witness.
    /// Unknown native close, unfinished work and disposal are ineligible.
    pub fn acknowledge_failed_close(
        &self,
        mut inspect_file_error: impl FnMut(&io::Error),
    ) -> io::Result<FailedOpeningAcknowledgement> {
        if self.state.engine.report().settlement() != DatabaseOpenSettlement::DrainedWithFailure
            || !matches!(self.state.failed_recovery, Observation::NotEntered)
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let physical = self.state.file.physical()?;
        let file = physical.failed_close_witness()?;
        physical.with_failed_close_reports(&file, |report| {
            report.visit_errors(&mut inspect_file_error);
        })?;
        Ok(FailedOpeningAcknowledgement {
            owner: self.registration.clone(),
            file,
        })
    }
    pub fn failed_recovery(&self) -> TerminalObservation<'_, io::Error> {
        self.state.failed_recovery.borrow()
    }

    pub fn acquisition(&self) -> TerminalObservation<'_, anyhow::Error> {
        self.state.acquisition.borrow()
    }
    pub fn opening_outer(&self) -> TerminalObservation<'_, std::convert::Infallible> {
        self.state.opening_outer.borrow()
    }
    pub fn ready_publication(&self) -> TerminalObservation<'_, anyhow::Error> {
        self.state.ready_publication.borrow()
    }
    pub fn existing_tables_verified(&self) -> bool {
        self.state.existing_tables_verified
    }
    pub fn engine(&self) -> kasumi_kv::DatabaseOpenReport<'_> {
        self.state.engine.report()
    }
}

#[derive(Debug)]
pub enum NodeTablesBodyError {
    Catalog(kasumi_kv::TableError),
    Records(kasumi_kv::TableError),
}
struct WriterState {
    phase: NodeWriterPhase,
    transaction: Option<RetainedWriteTransaction>,
    begin: Observation<kasumi_kv::TransactionError>,
    body: Observation<NodeTablesBodyError>,
    outer: Observation<std::convert::Infallible>,
    outcomes_released: bool,
    #[cfg(test)]
    fail_owner_before_terminal: bool,
}
impl WriterState {
    fn has_failures(&self) -> bool {
        observed_failure(self.begin.borrow())
            || observed_failure(self.body.borrow())
            || observed_failure(self.outer.borrow())
            || self
                .transaction
                .as_ref()
                .is_some_and(|transaction| transaction_failure(&transaction.report()))
    }
    fn capacity_denied(&self) -> bool {
        settled_capacity_denial(
            self.phase,
            &self.begin,
            &self.body,
            &self.outer,
            self.transaction
                .as_ref()
                .map(RetainedWriteTransaction::report),
            |error| {
                matches!(
                    error,
                    NodeTablesBodyError::Catalog(error) | NodeTablesBodyError::Records(error)
                        if error.is_capacity_denied()
                )
            },
        )
    }
}
struct NodeTablesRequest {
    database: StorageRegistration<DatabaseOwner>,
    state: Mutex<WriterState>,
}
impl crate::storage_census::NativeStartupChild for NodeTablesRequest {
    const PURPOSE: crate::storage_census::NativeStartupChildPurpose =
        crate::storage_census::NativeStartupChildPurpose::Tables;
    fn report_bytes() -> io::Result<u64> {
        Ok(0)
    }
    fn abandon_delivery(&self) {}
}
impl NodeTablesRequest {
    fn dispose(&self, state: &mut WriterState, wait_for_settled: bool) -> bool {
        let Some(transaction) = state.transaction.as_mut() else {
            return !matches!(state.outer, Observation::Panicked(_))
                && !matches!(state.begin, Observation::Entered);
        };
        if transaction.report().disposal_complete() {
            // This actual disposal proof remains valid after the matching
            // database becomes Closed and its borrowed witness is gated away.
            return true;
        }
        // Abort/disposal can create a new original outcome. An earlier report
        // release never acknowledges that future operation.
        state.outcomes_released = false;
        self.database
            .owner()
            .dispose_write(transaction, wait_for_settled)
    }
    fn execute(&self, state: &mut WriterState) {
        let owner = self.database.owner();
        // This gate is separate from both the census and the database's state.
        // close seals admission and uses try_lock even while this worker waits.
        let _serial = owner.serial.lock();
        if owner.stopped.load(Ordering::Acquire) {
            state.phase = NodeWriterPhase::Cancelled;
            return;
        }
        state.phase = NodeWriterPhase::Begin;
        state.begin = Observation::Entered;
        let database = owner.state.lock();
        let Some(db) = database.engine.database() else {
            state.begin =
                Observation::Returned(Err(kasumi_kv::StorageError::DatabaseClosed.into()));
            return;
        };
        // This admitted handle keeps close aware of the pending writer while
        // the opening lock is released before the native writer-gate wait.
        let admission = db.transaction_admission();
        drop(database);
        match admission.begin_write() {
            Ok(transaction) => {
                state.transaction = Some(transaction.retain());
                state.begin = Observation::Returned(Ok(()));
            }
            Err(error) => {
                state.begin = Observation::Returned(Err(error));
                return;
            }
        }
        state.phase = NodeWriterPhase::Body;
        state.body = Observation::Entered;
        let body = catch_unwind(AssertUnwindSafe(|| {
            let transaction = state.transaction.as_ref().unwrap().transaction().unwrap();
            transaction
                .open_table(crate::CATALOG)
                .map_err(NodeTablesBodyError::Catalog)?;
            transaction
                .open_table(crate::RECORDS)
                .map_err(NodeTablesBodyError::Records)?;
            Ok(())
        }));
        state.body = match body {
            Ok(result) => Observation::Returned(result),
            Err(payload) => Observation::Panicked(payload),
        };
        state.phase = NodeWriterPhase::Terminal;
        #[cfg(test)]
        if state.fail_owner_before_terminal {
            owner
                .state
                .lock()
                .file
                .physical()
                .expect("physical test fixture")
                .disk()
                .fail();
        }
        let transaction = state.transaction.as_mut().unwrap();
        if state.body.success() {
            let _ = transaction.commit();
        } else {
            let _ = transaction.abort();
        }
        state.phase = NodeWriterPhase::Disposal;
        if self.dispose(state, true) {
            state.phase = NodeWriterPhase::Finished;
        }
        if state.phase != NodeWriterPhase::Finished {
            owner.stopped.store(true, Ordering::Release);
        }
    }
}
impl StoragePayload for NodeTablesRequest {
    const KIND: StorageOwnerKind = StorageOwnerKind::Writer;
    fn drive(&self) -> bool {
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        if state.phase == NodeWriterPhase::Queued {
            state.phase = NodeWriterPhase::Cancelled;
        }
        self.dispose(&mut state, false) && (state.outcomes_released || !state.has_failures())
    }
}
pub struct RegisteredNodeTables {
    registration: StorageRegistration<NodeTablesRequest>,
}
impl RegisteredNodeTables {
    /// Recover the exact failed closed startup child constructor, including
    /// before a native request facade could be delivered. No work is replayed.
    pub fn retained_constructor(
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
    ) -> Option<NativeConstructorFailure> {
        provider
            .storage_census()
            .retained_native_constructor::<NodeTablesRequest>(provider.clone(), id)
    }
    /// Observe the exact request after its worker/facade was cancelled. The
    /// census retained the request, inputs, transaction and original outcomes.
    pub fn retained(
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
    ) -> Option<Self> {
        let registration = provider.storage_census().retained(provider.clone(), id)?;
        Some(Self { registration })
    }
    pub fn run(&self) -> NodeWriterPhase {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if state.phase != NodeWriterPhase::Queued {
            return state.phase;
        }
        state.outcomes_released = false;
        state.outer = Observation::Entered;
        match catch_unwind(AssertUnwindSafe(|| request.execute(&mut state))) {
            Ok(()) => state.outer = Observation::Returned(Ok(())),
            Err(payload) => {
                state.outer = Observation::Panicked(payload);
                request
                    .database
                    .owner()
                    .stopped
                    .store(true, Ordering::Release);
            }
        }
        if state.capacity_denied() {
            // The whole batch rolled back before publication and the writer
            // was disposed. Release this request's create reservation so the
            // open database can queue table creation again. The denied request
            // itself can never publish Ready: that proof needs its own commit.
            // Writer then database is the same lock order as execute.
            let mut database = request.database.owner().state.lock();
            if database.tables_request == Some(self.id()) {
                database.tables_reserved = false;
                database.tables_request = None;
            }
        }
        state.phase
    }
    pub fn id(&self) -> StorageOwnerId {
        self.registration.id()
    }
    pub fn report(&self) -> NodeTablesReport<'_> {
        NodeTablesReport {
            state: self.registration.owner().state.lock(),
        }
    }
    /// Relinquish this caller's outcomes after inspection. Physical uncertainty
    /// still prevents retirement; other real facades still retain the owner.
    pub fn retire(self) -> StorageCensusDisposition {
        let owner = self.registration.owner();
        if let Some(mut state) = owner.state.try_lock() {
            // A second facade may still call run. Seal this queued request
            // before acknowledging it; never acknowledge an active worker.
            if state.phase == NodeWriterPhase::Queued {
                state.phase = NodeWriterPhase::Cancelled;
            }
            state.outcomes_released = true;
        }
        self.registration.retire()
    }
}
pub struct NodeTablesReport<'a> {
    state: MutexGuard<'a, WriterState>,
}
impl NodeTablesReport<'_> {
    pub fn begin(&self) -> TerminalObservation<'_, kasumi_kv::TransactionError> {
        self.state.begin.borrow()
    }
    pub fn body(&self) -> TerminalObservation<'_, NodeTablesBodyError> {
        self.state.body.borrow()
    }
    pub fn outer(&self) -> TerminalObservation<'_, std::convert::Infallible> {
        self.state.outer.borrow()
    }
    pub fn terminal(&self) -> Option<kasumi_kv::WriteTerminalReport<'_>> {
        self.state
            .transaction
            .as_ref()
            .map(RetainedWriteTransaction::report)
    }
    /// The table creation was refused for capacity before publication. The
    /// writer was rolled back whole and disposed; the opening stays open and
    /// a Create-mode opening may queue table creation again.
    pub fn is_capacity_denied(&self) -> bool {
        self.state.capacity_denied()
    }
}

mod reads;
pub(crate) use reads::AdmittedReadReport;
pub use reads::{
    AdmittedReadBytes, NodeReadAccessError, NodeReadPhase, NodeReadReport, NodeReadTablesError,
    OwnedEncryptedRow, RegisteredNodeRead, SourceHistoryAbort, SourceHistoryRefusal,
};
#[cfg(any(test, feature = "test-utils"))]
pub use reads::{RegisteredSourceFundingFixture, SourceCompletionFault, SourceReadDiagnostic};

mod catalog_put;
pub use catalog_put::{NodeCatalogPutBodyError, NodeCatalogWriteReport, RegisteredCatalogPut};
mod scoped_write;
pub use scoped_write::{NodeWriteReport, RegisteredNodeWrite};

mod binding_put;
pub use binding_put::{BindingInstallBodyError, NodeBindingWriteReport, RegisteredBindingPut};

pub(crate) mod write_plan;

#[cfg(test)]
#[path = "storage_opening_tests.rs"]
mod tests;

mod startup;
pub use startup::{NodeStartupFailureCustody, NodeStartupPhase, RegisteredNodeStartup};

#[cfg(any(test, feature = "test-utils"))]
#[path = "native_source_funding_fixture.rs"]
mod native_source_funding_fixture;
#[cfg(any(test, feature = "test-utils"))]
pub use native_source_funding_fixture::{
    NativeSlotBlockers, NativeSourceFixtureError, NativeSourceFundingFixture,
};

pub use reads::{
    PreparedRegisteredSource, RegisteredSourceCapacity, SourceCapacityClose, SourceCapacityFailure,
    SourceCapacityReport, SourceCapacityRetirement, SourcePoolPhase,
};
