//! Concrete custody boundary for physical opening and fixed NodeTables work.
//!
//! The census and listed fixed backing are bounded here. The engine holds
//! registered ownership through opening, transactions, and close.
use crate::{
    NodeDisk, NodeDiskMemoryAdmission, StorageCensusDisposition, StorageOwnerId,
    node_file::{FailedFileTransfer, FailedFileWitness, NodeFile},
    private_files::FileIdentity,
    storage_census::{StorageOwnerKind, StoragePayload, StorageRegistration},
};
use kasumi_kv::{
    DatabaseOpenMode, DatabaseOpenSettlement, RetainedDatabaseOpening, RetainedWriteTransaction,
    TerminalObservation, WriteTerminalOperation,
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
fn opening_backing_bytes(path: &Path) -> io::Result<u64> {
    let layout = kasumi_kv::Builder::retained_opening_allocation_layout()
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    let allocation = crate::disk_memory::allocation::<u8>(
        u64::try_from(layout.size()).map_err(|_| io::ErrorKind::InvalidInput)?,
    )?;
    crate::disk_memory::add(NodeFile::prepared_backing_bytes(path)?, allocation)
}

pub enum NodeOpeningMode {
    Create,
    OwnedEmpty(FileIdentity),
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
struct OpeningState {
    mode: NodeOpeningMode,
    file: Arc<NodeFile>,
    engine: RetainedDatabaseOpening,
    phase: NodeOpeningPhase,
    // The first accepted table request owns the only create publication proof.
    // A failed registration may release its reservation before any request exists.
    tables_reserved: bool,
    tables_request: Option<StorageOwnerId>,
    existing_tables_verified: bool,
    ready_publication: Observation<anyhow::Error>,
    acquisition: Observation<anyhow::Error>,
    opening_outer: Observation<std::convert::Infallible>,
    outcomes_released: bool,
    failed_transfer: Option<FailedFileTransfer>,
    pending_transfer: Option<FailedFileWitness>,
    #[cfg(test)]
    after_failed_disposal: Option<Box<dyn FnOnce() + Send>>,
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
impl OpeningState {
    fn transfer_failed(&mut self) -> FailedOpeningRecovery {
        if self.failed_transfer.is_some() {
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
        match catch_unwind(AssertUnwindSafe(|| self.file.transfer_failed(witness))) {
            Ok(Ok(Some(transfer))) => {
                self.failed_transfer = Some(transfer);
                self.pending_transfer = None;
                self.failed_recovery = Observation::Returned(Ok(()));
                self.outcomes_released = true;
                FailedOpeningRecovery::AwaitingDiskCensus
            }
            Ok(Ok(None)) => {
                // Typed pre-effect contention enters no transfer operation and
                // produces no new original failure. Keep the exact prior ack;
                // a later nonblocking attempt never repeats engine disposal.
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
        observed_failure(self.acquisition.borrow())
            || observed_failure(self.ready_publication.borrow())
            || observed_failure(self.opening_outer.borrow())
            || observed_failure(report.opening())
            || observed_failure(report.partial_close())
            || observed_failure(report.failed_disposal())
            || observed_failure(self.failed_recovery.borrow())
            || report.bootstrap().as_ref().is_some_and(transaction_failure)
            || report.database_close().is_some_and(|close| {
                observed_failure(close.shutdown())
                    || observed_failure(close.backend())
                    || observed_failure(close.failed_disposal())
            })
            || report.fence().observation().is_none_or(observed_failure)
    }
}
struct DatabaseOwner {
    stopped: AtomicBool,
    serial: Mutex<()>,
    state: Mutex<OpeningState>,
}
impl DatabaseOwner {
    // Both explicit close and census drain enter the same retained operation.
    // An entered close is never replayed; only a busy transaction wait can
    // advance when its actual owner drains.
    fn close_locked(state: &mut OpeningState) -> DatabaseOpenSettlement {
        state.phase = NodeOpeningPhase::Closing;
        if state.pending_transfer.is_some() {
            let _ = state.transfer_failed();
        }
        let settlement = state.engine.report().settlement();
        if state.failed_transfer.is_none()
            && !matches!(
                settlement,
                DatabaseOpenSettlement::Closed
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
        self.stopped.store(true, Ordering::Release);
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        let settlement = Self::close_locked(&mut state);
        // A failed Ready attempt may leave visible but unproved header bytes.
        // A report acknowledgement cannot retire this physical owner.
        if observed_failure(state.ready_publication.borrow()) {
            return false;
        }
        if let Some(transfer) = &state.failed_transfer {
            return settlement == DatabaseOpenSettlement::FailedDisposed
                && state.failed_recovery.success()
                && state.outcomes_released
                && state.file.disk().accepted_failure_transfer(transfer);
        }
        if matches!(
            settlement,
            DatabaseOpenSettlement::DrainedWithFailure | DatabaseOpenSettlement::FailedDisposed
        ) {
            // Ordinary retirement cannot acknowledge a failed close or turn
            // operational disposal into a disk-census acceptance receipt.
            return false;
        }
        settlement == DatabaseOpenSettlement::Closed
            && (state.outcomes_released || !state.has_failures())
    }
}
/// Every facade is secondary to the actual installed census owner.
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
    ) -> io::Result<Self> {
        if id.is_nil() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let provider = disk.memory().clone();
        let known_backing = opening_backing_bytes(path)?;
        let registration =
            provider
                .storage_census()
                .register(provider.clone(), known_backing, || {
                    let file = NodeFile::retained_prepared(path, id, disk);
                    let engine_mode = if matches!(mode, NodeOpeningMode::Existing) {
                        DatabaseOpenMode::Existing
                    } else {
                        DatabaseOpenMode::Create
                    };
                    let engine = kasumi_kv::Database::builder(file.clone())
                        .retain_backend(Box::new(file.backend()), engine_mode);
                    DatabaseOwner {
                        stopped: AtomicBool::new(false),
                        serial: Mutex::new(()),
                        state: Mutex::new(OpeningState {
                            mode,
                            file,
                            engine,
                            phase: NodeOpeningPhase::Prepared,
                            tables_reserved: false,
                            tables_request: None,
                            existing_tables_verified: false,
                            ready_publication: Observation::NotEntered,
                            acquisition: Observation::NotEntered,
                            opening_outer: Observation::NotEntered,
                            outcomes_released: false,
                            failed_transfer: None,
                            pending_transfer: None,
                            #[cfg(test)]
                            after_failed_disposal: None,
                            failed_recovery: Observation::NotEntered,
                        }),
                    }
                })?;
        Ok(Self { registration })
    }
    pub fn id(&self) -> StorageOwnerId {
        self.registration.id()
    }
    pub fn open(&self) -> NodeOpeningPhase {
        let owner = self.registration.owner();
        let mut state = owner.state.lock();
        if state.phase != NodeOpeningPhase::Prepared || owner.stopped.load(Ordering::Acquire) {
            return state.phase;
        }
        state.phase = NodeOpeningPhase::FileAcquisition;
        state.acquisition = Observation::Entered;
        let result = catch_unwind(AssertUnwindSafe(|| {
            state.file.acquire_prepared(&state.mode)
        }));
        state.acquisition = match result {
            Ok(result) => Observation::Returned(result),
            Err(payload) => Observation::Panicked(payload),
        };
        if !state.acquisition.success() {
            return state.phase;
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
        let Some(mut state) = owner.state.try_lock() else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        Ok(DatabaseOwner::close_locked(&mut state))
    }
    /// Fixed, closed operation shape with no user callback or raw transaction
    /// escape. The actual queued request is registered before any serial wait.
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
        let provider = state.file.disk().memory().clone();
        drop(state);
        let database = self.registration.clone();
        let registration =
            provider
                .storage_census()
                .register(provider.clone(), 0, || NodeTablesRequest {
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
                });
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
            // this request was waiting for a census slot. No facade has been
            // returned yet, so cancel and retire this exact registered owner.
            drop(state);
            registration.owner().state.lock().phase = NodeWriterPhase::Cancelled;
            let _ = registration.retire();
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        state.tables_request = Some(registration.id());
        Ok(RegisteredNodeTables { registration })
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
            .with_failed_close_report(&acknowledgement.file, |_| ())?;
        owner.stopped.store(true, Ordering::Release);
        state.outcomes_released = false;
        state.pending_transfer = Some(acknowledgement.file);
        // Any disposal error/panic is a new outcome, never covered by the
        // earlier acknowledgement. The actual engine report owner stays installed.
        if state.engine.dispose_failed().settlement() != DatabaseOpenSettlement::FailedDisposed {
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
        if state.pending_transfer.is_none() && state.failed_transfer.is_none() {
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
            && state.engine.report().settlement() == DatabaseOpenSettlement::Closed
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
    owner: StorageRegistration<DatabaseOwner>,
    file: FailedFileWitness,
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
        let file = self.state.file.failed_close_witness()?;
        self.state.file.with_failed_close_report(&file, |report| {
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
}
struct NodeTablesRequest {
    database: StorageRegistration<DatabaseOwner>,
    state: Mutex<WriterState>,
}
impl NodeTablesRequest {
    fn dispose(&self, state: &mut WriterState) -> bool {
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
        let Some(database) = self.database.owner().state.try_lock() else {
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
        match db.begin_write() {
            Ok(transaction) => {
                state.transaction = Some(transaction.retain());
                state.begin = Observation::Returned(Ok(()));
            }
            Err(error) => {
                state.begin = Observation::Returned(Err(error));
                return;
            }
        }
        drop(database);
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
            owner.state.lock().file.disk().fail();
        }
        let transaction = state.transaction.as_mut().unwrap();
        if state.body.success() {
            let _ = transaction.commit();
        } else {
            let _ = transaction.abort();
        }
        state.phase = NodeWriterPhase::Disposal;
        if self.dispose(state) {
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
        self.dispose(&mut state) && (state.outcomes_released || !state.has_failures())
    }
}
pub struct RegisteredNodeTables {
    registration: StorageRegistration<NodeTablesRequest>,
}
impl RegisteredNodeTables {
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
}

mod reads;
pub use reads::{
    AdmittedReadBytes, NodeReadAccessError, NodeReadPhase, NodeReadReport, NodeReadTablesError,
    OwnedEncryptedRow, RegisteredNodeRead,
};

// This fixed input plan is dormant until a retained, typed write request can
// own the plan and its original terminal result without raw transaction escape.
#[allow(dead_code)]
pub(crate) mod write_plan;

#[cfg(test)]
#[path = "storage_opening_tests.rs"]
mod tests;
