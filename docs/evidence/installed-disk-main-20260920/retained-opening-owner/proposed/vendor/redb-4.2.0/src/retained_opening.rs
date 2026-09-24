//! Borrowed custody from the raw backend through bootstrap and physical close.
//! The embedding caller must install this exact value in charged, durable
//! ownership before `open`. It is a primitive, not a census or workspace bound.
use super::{Builder, Database, RepairSession, RetainedDatabase};
use crate::transaction_tracker::TransactionTracker;
use crate::tree_store::{BtreeHeader, TransactionalMemory, TransactionalMemoryOpening};
use crate::{
    DatabaseCloseReport, DatabaseCloseSettlement, DatabaseError, RetainedWriteTransaction,
    SavepointError, StorageBackend, StorageError, TerminalObservation, WriteTerminalReport,
    WriteTerminalSettlement,
};
use std::{
    any::Any,
    convert::Infallible,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex, MutexGuard, OnceLock, atomic::{AtomicBool, Ordering}},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseOpenMode {
    /// Initialize only an empty backend; existing contents must be canonical.
    Create,
    /// Require an existing, nonempty canonical database.
    Existing,
}

/// The last entered phase, recorded before its effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseOpenPhase {
    Prepared,
    MemoryInitialization,
    WinningRootVerification,
    AllocatorRestoration,
    BeginWritable,
    DatabaseConstruction,
    BootstrapBegin,
    BootstrapBody,
    BootstrapTerminal,
    BootstrapDisposal,
    Ready,
    Closing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseOpenSettlement {
    Prepared,
    /// The original opening attempt failed or unwound. No retry is permitted.
    Retained,
    /// Bootstrap completed and was actually disposed; database access is allowed.
    Ready,
    /// Admission is sealed, but existing read/write owners must still drain.
    WaitingForTransactions,
    /// Physical release returned successfully. Diagnostics and allocations remain.
    Closed,
}

enum Observation<E> {
    NotEntered,
    Entered,
    Returned(Result<(), E>),
    Panicked(Box<dyn Any + Send>),
}
impl<E> Observation<E> {
    fn observe(&mut self, operation: impl FnOnce() -> Result<(), E>) {
        debug_assert!(matches!(self, Self::NotEntered));
        *self = Self::Entered;
        *self = match catch_unwind(AssertUnwindSafe(operation)) {
            Ok(result) => Self::Returned(result),
            Err(payload) => Self::Panicked(payload),
        };
    }
    fn borrow(&self) -> TerminalObservation<'_, E> {
        match self {
            Self::NotEntered => TerminalObservation::NotEntered,
            Self::Entered => TerminalObservation::Entered,
            Self::Returned(result) => TerminalObservation::Returned(result.as_ref().copied()),
            Self::Panicked(payload) => TerminalObservation::Panicked(payload.as_ref()),
        }
    }
    fn succeeded(&self) -> bool {
        matches!(self, Self::Returned(Ok(())))
    }
}

enum FenceOutcome {
    Returned,
    Panicked(Mutex<Box<dyn Any + Send>>),
}

// Every path forwards to the same retained physical admission object. The
// distinct proxy's inline fence is latched before invoking that object's hook.
// Catching here is essential: CheckedBackend::io still owns its original I/O
// error on the stack while owner_failed runs. This hook must return normally so
// that actual error reaches the separately registered opening/transaction owner.
struct OpeningAdmission {
    inner: Arc<dyn crate::StorageAdmission>,
    failed: AtomicBool,
    outcome: OnceLock<FenceOutcome>,
}
impl std::fmt::Debug for OpeningAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpeningAdmission").field("failed", &self.failed.load(Ordering::Acquire)).finish()
    }
}
impl crate::StorageAdmission for OpeningAdmission {
    fn check_owner(&self) -> Result<(), crate::OwnerFailed> {
        if self.failed.load(Ordering::Acquire) { return Err(crate::OwnerFailed); }
        self.inner.check_owner()
    }
    fn reserve_growth(&self, current: u64, requested: u64) -> Result<(), crate::AdmissionError> {
        if self.failed.load(Ordering::Acquire) { return Err(crate::AdmissionError::OwnerFailed); }
        self.inner.reserve_growth(current, requested)
    }
    fn settle_growth(&self, actual: u64) -> Result<(), crate::OwnerFailed> {
        if self.failed.load(Ordering::Acquire) { return Err(crate::OwnerFailed); }
        self.inner.settle_growth(actual)
    }
    fn owner_failed(&self) {
        if self.failed.swap(true, Ordering::AcqRel) { return; }
        let outcome = match catch_unwind(AssertUnwindSafe(|| self.inner.owner_failed())) {
            Ok(()) => FenceOutcome::Returned,
            Err(payload) => FenceOutcome::Panicked(Mutex::new(payload)),
        };
        // Only the winner above writes the slot. No observer waits for it: a
        // reentrant or concurrent observation sees Entered while it is running.
        assert!(self.outcome.set(outcome).is_ok());
    }
}

/// An original admission-hook panic is borrowed under its own mutex so even
/// a Send-only payload remains safe. Acquiring this report never waits for the
/// callback to return; `Entered` reports an actual in-flight callback.
pub struct OpeningFenceReport<'a> {
    view: FenceView<'a>,
}
enum FenceView<'a> {
    NotEntered,
    Entered,
    Returned,
    Panicked(MutexGuard<'a, Box<dyn Any + Send>>),
    /// Another diagnostic borrower currently holds the exact payload.
    Borrowed,
}
impl OpeningFenceReport<'_> {
    pub fn observation(&self) -> Option<TerminalObservation<'_, Infallible>> {
        match &self.view {
            FenceView::NotEntered => Some(TerminalObservation::NotEntered),
            FenceView::Entered => Some(TerminalObservation::Entered),
            FenceView::Returned => Some(TerminalObservation::Returned(Ok(()))),
            FenceView::Panicked(payload) => Some(TerminalObservation::Panicked(payload.as_ref())),
            FenceView::Borrowed => None,
        }
    }
}
impl OpeningAdmission {
    fn report(&self) -> OpeningFenceReport<'_> {
        let view = match self.outcome.get() {
            Some(FenceOutcome::Returned) => FenceView::Returned,
            Some(FenceOutcome::Panicked(payload)) => match payload.try_lock() {
                Ok(guard) => FenceView::Panicked(guard),
                Err(std::sync::TryLockError::Poisoned(error)) => FenceView::Panicked(error.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => FenceView::Borrowed,
            },
            None if self.failed.load(Ordering::Acquire) => FenceView::Entered,
            None => FenceView::NotEntered,
        };
        OpeningFenceReport { view }
    }
}

/// Owns the original backend, cache/memory, Database and bootstrap transaction
/// at each construction phase. Errors and panic payloads are never cloned or
/// replaced with a synthetic summary. `open` and every terminal phase enter once.
///
/// Construct and register this owner before the first redb storage effect. The
/// provided backend's own creation/locking must already have caller-owned custody.
/// No storage call occurs in `Builder::retain_backend`; its callback and backend
/// are moved into retained fields. The once-only admission proxy allocates one
/// Arc; it and all pre-existing callback/backend allocations require admission.
///
/// An uncertain owner must remain in the embedding census. Dropping it is not a
/// cleanup operation or proof that opaque panic/error backing was bounded. The
/// caller must also retain accepted users/readers/writers through their outcomes.
#[must_use = "register and retain the actual opening owner before storage effects"]
pub struct RetainedDatabaseOpening {
    builder: Builder,
    admission: Arc<OpeningAdmission>,
    mode: DatabaseOpenMode,
    partial: TransactionalMemoryOpening,
    memory: Option<Arc<TransactionalMemory>>,
    database: Option<RetainedDatabase>,
    bootstrap: Option<RetainedWriteTransaction>,
    repaired_roots: Option<[Option<BtreeHeader>; 2]>,
    phase: DatabaseOpenPhase,
    opening_phase: DatabaseOpenPhase,
    settlement: DatabaseOpenSettlement,
    opening: Observation<DatabaseError>,
    partial_close: Observation<StorageError>,
}

#[must_use = "inspect the opening, bootstrap, disposal and close observations"]
pub struct DatabaseOpenReport<'a> {
    owner: &'a RetainedDatabaseOpening,
}
impl DatabaseOpenReport<'_> {
    pub fn phase(&self) -> DatabaseOpenPhase {
        self.owner.phase
    }
    /// The opening failure/success phase survives later close attempts.
    pub fn opening_phase(&self) -> DatabaseOpenPhase {
        self.owner.opening_phase
    }
    pub fn settlement(&self) -> DatabaseOpenSettlement {
        self.owner.settlement
    }
    /// Construction and bootstrap body, excluding the separately observed terminal.
    pub fn opening(&self) -> TerminalObservation<'_, DatabaseError> {
        self.owner.opening.borrow()
    }
    pub fn bootstrap(&self) -> Option<WriteTerminalReport<'_>> {
        self.owner.bootstrap.as_ref().map(RetainedWriteTransaction::report)
    }
    pub fn database_close(&self) -> Option<DatabaseCloseReport<'_>> {
        self.owner.database.as_ref().map(RetainedDatabase::report)
    }
    /// Used only before a Database exists; it never checkpoints partial state.
    pub fn partial_close(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.partial_close.borrow()
    }
    /// The separate non-allocating admission-fence callback, including its unwind.
    pub fn fence(&self) -> OpeningFenceReport<'_> {
        self.owner.admission.report()
    }
}

impl Builder {
    /// Move existing resources into pre-effect opening custody. Register this
    /// owner before calling `open`; no backend operation runs here. The proxy's
    /// Arc allocation/control block must be admitted before this constructor.
    pub fn retain_backend(
        mut self,
        backend: Box<dyn StorageBackend>,
        mode: DatabaseOpenMode,
    ) -> RetainedDatabaseOpening {
        let admission = Arc::new(OpeningAdmission {
            inner: self.admission.clone(),
            failed: AtomicBool::new(false),
            outcome: OnceLock::new(),
        });
        self.admission = admission.clone();
        RetainedDatabaseOpening {
            builder: self,
            admission,
            mode,
            partial: TransactionalMemoryOpening::new(backend),
            memory: None,
            database: None,
            bootstrap: None,
            repaired_roots: None,
            phase: DatabaseOpenPhase::Prepared,
            opening_phase: DatabaseOpenPhase::Prepared,
            settlement: DatabaseOpenSettlement::Prepared,
            opening: Observation::NotEntered,
            partial_close: Observation::NotEntered,
        }
    }
}

impl RetainedDatabaseOpening {
    pub fn report(&self) -> DatabaseOpenReport<'_> {
        DatabaseOpenReport { owner: self }
    }
    /// Only the complete successful attempt exposes database access. This borrow
    /// does not erase the opening/terminal diagnostics or transfer close custody.
    pub fn database(&self) -> Option<&Database> {
        if self.settlement != DatabaseOpenSettlement::Ready {
            return None;
        }
        self.database.as_ref().and_then(RetainedDatabase::database)
    }
    /// Matching owner witness for actual disposal of user transactions. New
    /// borrows remain governed by `database`; waiting close can still dispose
    /// transactions that were accepted earlier.
    pub fn retained_database(&self) -> Option<&RetainedDatabase> {
        if matches!(self.settlement, DatabaseOpenSettlement::Ready | DatabaseOpenSettlement::WaitingForTransactions) {
            self.database.as_ref()
        } else {
            None
        }
    }
    /// Enter exactly one opening attempt while all successive resources remain
    /// installed in this owner. Later calls return the same borrowed observations.
    pub fn open(&mut self) -> DatabaseOpenReport<'_> {
        if self.settlement != DatabaseOpenSettlement::Prepared {
            return self.report();
        }
        self.settlement = DatabaseOpenSettlement::Retained;
        self.opening = Observation::Entered;
        self.opening = match catch_unwind(AssertUnwindSafe(|| self.open_body())) {
            Ok(result) => Observation::Returned(result),
            Err(payload) => Observation::Panicked(payload),
        };
        self.opening_phase = self.phase;
        if matches!(self.opening, Observation::Panicked(_)) {
            // A backend/callback unwind can occur before CheckedBackend sees a
            // Result. Store the original payload before latching that uncertainty.
            self.builder.admission.owner_failed();
        }
        if !self.opening.succeeded() {
            return self.report();
        }
        self.phase = DatabaseOpenPhase::BootstrapTerminal;
        let bootstrap = self.bootstrap.as_mut().expect("bootstrap installed before body");
        let report = if self.repaired_roots.is_some() {
            bootstrap.commit()
        } else {
            bootstrap.abort()
        };
        // A refused commit whose rollback succeeded is settled, but opening did
        // not succeed. Preserve that exact terminal error without manufacturing
        // a second DatabaseError or publishing an unusable database.
        let terminal_succeeded = matches!(report.terminal(), TerminalObservation::Returned(Ok(())));
        self.phase = DatabaseOpenPhase::BootstrapDisposal;
        let database = self.database.as_ref().expect("database installed before bootstrap");
        let report = bootstrap.dispose_settled(database);
        if terminal_succeeded && report.disposal_complete() {
            self.phase = DatabaseOpenPhase::Ready;
            self.settlement = DatabaseOpenSettlement::Ready;
        }
        self.opening_phase = self.phase;
        self.report()
    }

    fn open_body(&mut self) -> Result<(), DatabaseError> {
        self.phase = DatabaseOpenPhase::MemoryInitialization;
        self.memory = Some(Arc::new(self.partial.initialize(
            self.builder.admission.clone(),
            self.mode == DatabaseOpenMode::Create,
            self.builder.page_size,
            match self.mode {
                DatabaseOpenMode::Create => self.builder.region_size,
                DatabaseOpenMode::Existing => None,
            },
            self.builder.cache_size,
        )?));
        self.phase = DatabaseOpenPhase::WinningRootVerification;
        let memory = self.memory.as_mut().expect("memory installed before verification");
        if memory.opened_unclean() && !Database::primary_verifies(memory)? {
            return Err(StorageError::Corrupted(
                "Unclean database has a corrupted winning root".to_string(),
            ).into());
        }
        self.phase = DatabaseOpenPhase::AllocatorRestoration;
        self.repaired_roots = if let Some(tree) = Database::get_allocator_state_table(memory)? {
            memory.load_allocator_state(&tree)?;
            #[cfg(debug_assertions)]
            Database::mark_allocated_page_for_debug(memory)?;
            None
        } else {
            let mut handle = RepairSession::new(0.0);
            (self.builder.repair_callback)(&mut handle);
            if handle.aborted() {
                return Err(DatabaseError::RepairAborted);
            }
            Some(Database::do_repair(memory, &self.builder.repair_callback)?)
        };
        self.phase = DatabaseOpenPhase::BeginWritable;
        memory.begin_writable()?;
        let next_transaction_id = memory.get_last_committed_transaction_id()?.next();
        self.phase = DatabaseOpenPhase::DatabaseConstruction;
        let tracker = Arc::new(TransactionTracker::new(next_transaction_id));
        self.database = Some(Database {
            mem: self.memory.take().expect("memory transferred once"),
            transaction_tracker: tracker,
        }.retain());
        self.phase = DatabaseOpenPhase::BootstrapBegin;
        let database = self.database.as_ref().unwrap().database().unwrap();
        self.bootstrap = Some(database.begin_write().map_err(|error| error.into_storage_error())?.retain());
        self.phase = DatabaseOpenPhase::BootstrapBody;
        let transaction = self.bootstrap.as_mut().unwrap().transaction_mut().unwrap();
        if let Some(roots) = self.repaired_roots {
            transaction.set_repaired_roots(roots);
        }
        if let Some(next_id) = transaction.next_persistent_savepoint_id()? {
            database.transaction_tracker.restore_savepoint_counter_state(next_id);
        }
        for id in transaction.list_persistent_savepoints()? {
            let savepoint = match transaction.get_persistent_savepoint(id) {
                Ok(savepoint) => savepoint,
                Err(SavepointError::InvalidSavepoint) => unreachable!(),
                Err(SavepointError::Storage(error)) => return Err(error.into()),
            };
            database.transaction_tracker.register_persistent_savepoint(&savepoint);
        }
        Ok(())
    }

    /// Seal access, observe bootstrap abort/disposal if necessary, then release
    /// the actual database or partial backend. No terminal operation is replayed.
    /// Busy database close may be re-observed after actual external handles drain.
    pub fn close(&mut self) -> DatabaseOpenReport<'_> {
        self.phase = DatabaseOpenPhase::Closing;
        if self.settlement == DatabaseOpenSettlement::Closed {
            return self.report();
        }
        self.settlement = DatabaseOpenSettlement::Retained;
        if let Some(bootstrap) = self.bootstrap.as_mut() {
            if bootstrap.report().settlement() == WriteTerminalSettlement::Unstarted {
                bootstrap.abort();
            }
            let report = bootstrap.dispose_settled(self.database.as_ref().unwrap());
            if !report.disposal_complete() {
                // Its writer guard and exact transaction remain live. Attempting
                // a checkpoint or releasing the backend would violate custody.
                return self.report();
            }
        }
        if let Some(database) = self.database.as_mut() {
            self.settlement = match database.close().settlement() {
                DatabaseCloseSettlement::Settled => DatabaseOpenSettlement::Closed,
                DatabaseCloseSettlement::WaitingForTransactions => DatabaseOpenSettlement::WaitingForTransactions,
                DatabaseCloseSettlement::Open | DatabaseCloseSettlement::Retained => DatabaseOpenSettlement::Retained,
            };
        } else if matches!(self.partial_close, Observation::NotEntered) {
            let memory = &self.memory;
            let partial = &self.partial;
            self.partial_close.observe(|| match memory {
                Some(memory) => memory.abandon(),
                None => partial.abandon(),
            });
            if self.partial_close.succeeded() {
                self.settlement = DatabaseOpenSettlement::Closed;
            } else {
                // Preserve the close outcome first. A faulty admission callback
                // cannot overwrite its original I/O error or panic payload.
                self.builder.admission.owner_failed();
            }
        }
        self.report()
    }
}

#[cfg(test)]
#[path = "retained_opening_tests.rs"]
mod tests;
