//! Concrete custody boundary for physical opening and fixed NodeTables work.
//!
//! Adoption prerequisite: the census and listed fixed backing are bounded here.
//! Complete redb workspace/diagnostic plans and all twelve consumer replacements
//! remain mandatory before this boundary can be the production NodeDatabase.
use crate::{
    NodeDisk, NodeDiskMemoryAdmission, StorageCensusDisposition, StorageOwnerId,
    node_file::NodeFile,
    private_files::FileIdentity,
    storage_census::{StorageOwnerKind, StoragePayload, StorageRegistration},
};
use parking_lot::{Mutex, MutexGuard};
use redb::{
    DatabaseOpenMode, DatabaseOpenSettlement, ReadableDatabase, RetainedDatabaseOpening,
    RetainedWriteTransaction, TerminalObservation,
};
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

pub enum NodeOpeningMode {
    Create,
    OwnedEmpty(FileIdentity),
    Existing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeOpeningPhase {
    Prepared,
    FileAcquisition,
    RedbOpening,
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
    redb: RetainedDatabaseOpening,
    phase: NodeOpeningPhase,
    acquisition: Observation<anyhow::Error>,
    opening_outer: Observation<std::convert::Infallible>,
}
fn observed_failure<E>(observation: TerminalObservation<'_, E>) -> bool {
    matches!(
        observation,
        TerminalObservation::Entered
            | TerminalObservation::Returned(Err(_))
            | TerminalObservation::Panicked(_)
    )
}
fn transaction_failure(report: &redb::WriteTerminalReport<'_>) -> bool {
    observed_failure(report.terminal())
        || observed_failure(report.rollback())
        || observed_failure(report.disposal())
}
impl OpeningState {
    fn has_failures(&self) -> bool {
        let report = self.redb.report();
        observed_failure(self.acquisition.borrow())
            || observed_failure(self.opening_outer.borrow())
            || observed_failure(report.opening())
            || observed_failure(report.partial_close())
            || report.bootstrap().as_ref().is_some_and(transaction_failure)
            || report.database_close().is_some_and(|close| {
                observed_failure(close.shutdown()) || observed_failure(close.backend())
            })
            || report.fence().observation().is_none_or(observed_failure)
    }
}
struct DatabaseOwner {
    stopped: AtomicBool,
    outcomes_released: AtomicBool,
    serial: Mutex<()>,
    state: Mutex<OpeningState>,
}
impl StoragePayload for DatabaseOwner {
    const KIND: StorageOwnerKind = StorageOwnerKind::Database;
    fn drive(&self) -> bool {
        self.stopped.store(true, Ordering::Release);
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        state.phase = NodeOpeningPhase::Closing;
        let closed = state.redb.close().settlement() == DatabaseOpenSettlement::Closed;
        closed && (self.outcomes_released.load(Ordering::Acquire) || !state.has_failures())
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
        let known_backing = NodeFile::prepared_backing_bytes(path)?;
        let registration =
            provider
                .storage_census()
                .register(provider.clone(), known_backing, || {
                    let file = NodeFile::retained_prepared(path, id, disk);
                    let redb_mode = if matches!(mode, NodeOpeningMode::Existing) {
                        DatabaseOpenMode::Existing
                    } else {
                        DatabaseOpenMode::Create
                    };
                    let redb = redb::Database::builder(file.clone())
                        .retain_backend(Box::new(file.backend()), redb_mode);
                    DatabaseOwner {
                        stopped: AtomicBool::new(false),
                        outcomes_released: AtomicBool::new(false),
                        serial: Mutex::new(()),
                        state: Mutex::new(OpeningState {
                            mode,
                            file,
                            redb,
                            phase: NodeOpeningPhase::Prepared,
                            acquisition: Observation::NotEntered,
                            opening_outer: Observation::NotEntered,
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
        state.phase = NodeOpeningPhase::RedbOpening;
        state.opening_outer = Observation::Entered;
        match catch_unwind(AssertUnwindSafe(|| state.redb.open().settlement())) {
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
            state: self.registration.owner().state.lock(),
        }
    }
    /// Fixed, closed operation shape with no user callback or raw transaction
    /// escape. The actual queued request is registered before any serial wait.
    pub fn queue_node_tables(&self) -> io::Result<RegisteredNodeTables> {
        if self.registration.owner().stopped.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let state = self.registration.owner().state.lock();
        if matches!(state.mode, NodeOpeningMode::Existing) || state.phase != NodeOpeningPhase::Open
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let provider = state.file.disk().memory().clone();
        drop(state);
        let database = self.registration.clone();
        let registration = provider
            .storage_census()
            .register(provider.clone(), 0, || NodeTablesRequest {
                database,
                outcomes_released: AtomicBool::new(false),
                state: Mutex::new(WriterState {
                    phase: NodeWriterPhase::Queued,
                    transaction: None,
                    begin: Observation::NotEntered,
                    body: Observation::NotEntered,
                    outer: Observation::NotEntered,
                    #[cfg(test)]
                    fail_owner_before_terminal: false,
                }),
            })?;
        Ok(RegisteredNodeTables { registration })
    }
    /// Relinquish this caller's outcomes after inspection. Physical uncertainty
    /// still prevents retirement; other real facades still retain the owner.
    pub fn retire(self) -> StorageCensusDisposition {
        self.registration
            .owner()
            .outcomes_released
            .store(true, Ordering::Release);
        self.registration.retire()
    }
}
pub struct NodeOpeningReport<'a> {
    state: MutexGuard<'a, OpeningState>,
}
impl NodeOpeningReport<'_> {
    pub fn acquisition(&self) -> TerminalObservation<'_, anyhow::Error> {
        self.state.acquisition.borrow()
    }
    pub fn opening_outer(&self) -> TerminalObservation<'_, std::convert::Infallible> {
        self.state.opening_outer.borrow()
    }
    pub fn redb(&self) -> redb::DatabaseOpenReport<'_> {
        self.state.redb.report()
    }
}

#[derive(Debug)]
pub enum NodeTablesBodyError {
    Catalog(redb::TableError),
    Records(redb::TableError),
}
struct WriterState {
    phase: NodeWriterPhase,
    transaction: Option<RetainedWriteTransaction>,
    begin: Observation<redb::TransactionError>,
    body: Observation<NodeTablesBodyError>,
    outer: Observation<std::convert::Infallible>,
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
    outcomes_released: AtomicBool,
    state: Mutex<WriterState>,
}
impl NodeTablesRequest {
    fn dispose(&self, state: &mut WriterState) -> bool {
        let Some(transaction) = state.transaction.as_mut() else {
            return !matches!(state.outer, Observation::Panicked(_))
                && !matches!(state.begin, Observation::Entered);
        };
        let Some(database) = self.database.owner().state.try_lock() else {
            return false;
        };
        let Some(witness) = database.redb.retained_database() else {
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
        let Some(db) = database.redb.database() else {
            state.begin = Observation::Returned(Err(redb::StorageError::DatabaseClosed.into()));
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
        self.dispose(&mut state)
            && (self.outcomes_released.load(Ordering::Acquire) || !state.has_failures())
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
        self.registration
            .owner()
            .outcomes_released
            .store(true, Ordering::Release);
        self.registration.retire()
    }
}
pub struct NodeTablesReport<'a> {
    state: MutexGuard<'a, WriterState>,
}
impl NodeTablesReport<'_> {
    pub fn begin(&self) -> TerminalObservation<'_, redb::TransactionError> {
        self.state.begin.borrow()
    }
    pub fn body(&self) -> TerminalObservation<'_, NodeTablesBodyError> {
        self.state.body.borrow()
    }
    pub fn outer(&self) -> TerminalObservation<'_, std::convert::Infallible> {
        self.state.outer.borrow()
    }
    pub fn terminal(&self) -> Option<redb::WriteTerminalReport<'_>> {
        self.state
            .transaction
            .as_ref()
            .map(RetainedWriteTransaction::report)
    }
}

#[cfg(test)]
#[path = "storage_opening_tests.rs"]
mod tests;
