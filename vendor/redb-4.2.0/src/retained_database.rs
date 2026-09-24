//! A non-consuming close attempt retaining the exact database and both phases.
use super::{Database, TransactionTracker, TransactionalMemory};
use crate::{StorageError, TerminalObservation};
use std::{
    any::Any,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

/// Knowledge established by the actual database close attempts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseCloseSettlement {
    Open,
    /// New borrows are fenced; existing transaction owners must drain first.
    WaitingForTransactions,
    /// Both phases returned and the backend positively reported successful close.
    /// Original shutdown errors and database allocations still belong to this owner.
    Settled,
    /// Native resources drained, but the backend returned its original error.
    /// Operational allocations and all original outcomes are still retained.
    DrainedWithFailure,
    /// Explicit failed disposal retired operational allocations. Original close
    /// outcomes remain here until the embedding owner accepts acknowledgement.
    FailedDisposed,
    /// A phase unwound or backend close failed. Preserve this exact owner.
    Retained,
}

enum Observation {
    NotEntered,
    Entered,
    Returned(Result<(), StorageError>),
    Panicked(Box<dyn Any + Send>),
}
impl Observation {
    fn observe(&mut self, operation: impl FnOnce() -> Result<(), StorageError>) {
        debug_assert!(matches!(self, Self::NotEntered));
        *self = Self::Entered;
        *self = match catch_unwind(AssertUnwindSafe(operation)) {
            Ok(outcome) => Self::Returned(outcome),
            Err(payload) => Self::Panicked(payload),
        };
    }
    fn borrow(&self) -> TerminalObservation<'_, StorageError> {
        match self {
            Self::NotEntered => TerminalObservation::NotEntered,
            Self::Entered => TerminalObservation::Entered,
            Self::Returned(result) => TerminalObservation::Returned(result.as_ref().copied()),
            Self::Panicked(payload) => TerminalObservation::Panicked(payload.as_ref()),
        }
    }
}

/// Install this value in admitted caller-owned custody before attempting close.
///
/// A busy result may be retried after actual transactions drain. Once shutdown
/// or backend close enters, neither phase can be replayed, even after unwind.
/// An interrupted phase never consumes the Database; all actual backing and
/// original diagnostics remain here. This is not a self-retaining census or
/// an estimate of arbitrary diagnostic/panic backing. Do not drop a Retained
/// owner and treat its destructor as proof of cleanup.
#[must_use = "retain the exact database while physical close is unproved"]
pub struct RetainedDatabase {
    database: Option<Database>,
    shutdown: Observation,
    backend: Observation,
    native: crate::BackendNativeDisposition,
    disposal: Observation,
    settlement: DatabaseCloseSettlement,
}

/// Borrowed views of the original shutdown and backend-close outcomes.
#[must_use = "inspect both phase outcomes and the physical settlement"]
pub struct DatabaseCloseReport<'a> {
    owner: &'a RetainedDatabase,
}
impl DatabaseCloseReport<'_> {
    pub fn settlement(&self) -> DatabaseCloseSettlement {
        self.owner.settlement
    }
    pub fn shutdown(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.shutdown.borrow()
    }
    pub fn native_disposition(&self) -> crate::BackendNativeDisposition {
        self.owner.native
    }
    pub fn failed_disposal(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.disposal.borrow()
    }
    pub fn backend(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.backend.borrow()
    }
}

impl Database {
    /// Transfer the exact database to inline close custody, before effects.
    pub fn retain(self) -> RetainedDatabase {
        RetainedDatabase {
            database: Some(self),
            shutdown: Observation::NotEntered,
            backend: Observation::NotEntered,
            native: crate::BackendNativeDisposition::Retained,
            disposal: Observation::NotEntered,
            settlement: DatabaseCloseSettlement::Open,
        }
    }
}

impl RetainedDatabase {
    /// Access is available only before the first close request. Existing
    /// transactions already own their handles and remain independently tracked.
    pub fn database(&self) -> Option<&Database> {
        (self.settlement == DatabaseCloseSettlement::Open)
            .then_some(self.database.as_ref())
            .flatten()
    }
    pub fn report(&self) -> DatabaseCloseReport<'_> {
        DatabaseCloseReport { owner: self }
    }
    // A shared borrow keeps the actual Database alive throughout transaction
    // disposal, including while close waits for that transaction. This exposes
    // neither a fresh transaction borrow nor a count-based liveness assumption.
    pub(crate) fn owns_transaction(
        &self,
        tracker: &Arc<TransactionTracker>,
        mem: &Arc<TransactionalMemory>,
    ) -> bool {
        matches!(
            self.settlement,
            DatabaseCloseSettlement::Open | DatabaseCloseSettlement::WaitingForTransactions
        ) && self.database.as_ref().is_some_and(|database| {
            Arc::ptr_eq(&database.transaction_tracker, tracker) && Arc::ptr_eq(&database.mem, mem)
        })
    }
    pub fn close(&mut self) -> DatabaseCloseReport<'_> {
        if matches!(
            self.settlement,
            DatabaseCloseSettlement::Open | DatabaseCloseSettlement::WaitingForTransactions
        ) {
            self.settlement = DatabaseCloseSettlement::WaitingForTransactions;
            let database = self
                .database
                .as_ref()
                .expect("operational database before close");
            if Arc::strong_count(&database.transaction_tracker) != 1 {
                return self.report();
            }
            self.settlement = DatabaseCloseSettlement::Retained;
            self.shutdown.observe(|| database.mem.prepare_close());
            // Backend release is attempted separately even after a shutdown
            // failure. Never combine these outcomes with Result::and: it drops
            // the secondary original error. Both calls borrow the exact owner.
            let native = &mut self.native;
            self.backend.observe(|| {
                let (result, disposition) = database.mem.abandon();
                *native = disposition;
                result
            });
            if matches!(self.shutdown, Observation::Returned(_))
                && self.native == crate::BackendNativeDisposition::Drained
                && matches!(self.backend, Observation::Returned(_))
            {
                self.settlement = if matches!(self.backend, Observation::Returned(Ok(()))) {
                    DatabaseCloseSettlement::Settled
                } else {
                    DatabaseCloseSettlement::DrainedWithFailure
                };
            }
        }
        self.report()
    }
    /// Explicitly retire operational backing after a known-drained failed close.
    /// This does not acknowledge or drop either original close outcome. It may
    /// enter only once; any disposal unwind remains in this same report owner.
    pub fn dispose_failed(&mut self) -> DatabaseCloseReport<'_> {
        if self.settlement == DatabaseCloseSettlement::DrainedWithFailure
            && matches!(self.disposal, Observation::NotEntered)
        {
            self.settlement = DatabaseCloseSettlement::Retained;
            self.disposal.observe(|| {
                drop(self.database.take());
                Ok(())
            });
            if matches!(self.disposal, Observation::Returned(Ok(()))) {
                self.settlement = DatabaseCloseSettlement::FailedDisposed;
            }
        }
        self.report()
    }
}

#[cfg(test)]
#[path = "retained_database_tests.rs"]
mod tests;
