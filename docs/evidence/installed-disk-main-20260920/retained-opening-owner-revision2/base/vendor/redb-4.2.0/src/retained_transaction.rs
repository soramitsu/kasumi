//! A terminal attempt borrows its transaction and retains every original outcome.
//! This is a transaction boundary, not proof of database/backend close or a
//! bound on transaction, diagnostic, or opaque panic backing.
use super::{AllocatorStateLatch, WriteTransaction};
use crate::{CommitError, RetainedDatabase, StorageError};
use core::{any::Any, convert::Infallible};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// The first terminal operation accepted by a retained write transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteTerminalOperation {
    Commit,
    Abort,
}

/// Knowledge established by the actual transaction terminal call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteTerminalSettlement {
    /// No commit or abort has entered; the original transaction is still usable.
    Unstarted,
    /// Commit or rollback returned successfully. This does not dispose of the
    /// transaction or establish database/backend close or diagnostic release.
    Settled,
    /// The original transaction and diagnostic backing must remain owned.
    /// Neither terminal replay nor an assumption of rollback is permitted.
    Retained,
}

/// The first actual error returned by the requested terminal operation.
#[derive(Debug)]
pub enum WriteTerminalError {
    Commit(CommitError),
    Abort(StorageError),
}

/// A borrowed observation of one original call, with no cloned error allocation.
pub enum TerminalObservation<'a, E> {
    NotEntered,
    /// The phase was recorded before effects, but no result has been recorded.
    Entered,
    Returned(Result<(), &'a E>),
    /// The exact original unwind payload; its backing is not assumed bounded.
    Panicked(&'a (dyn Any + Send)),
}

enum Observation<E> {
    NotEntered,
    Entered,
    Returned(Result<(), E>),
    Panicked(Box<dyn Any + Send>),
}
impl<E> Observation<E> {
    fn borrow(&self) -> TerminalObservation<'_, E> {
        match self {
            Self::NotEntered => TerminalObservation::NotEntered,
            Self::Entered => TerminalObservation::Entered,
            Self::Returned(result) => TerminalObservation::Returned(result.as_ref().copied()),
            Self::Panicked(payload) => TerminalObservation::Panicked(payload.as_ref()),
        }
    }
    fn observe(&mut self, operation: impl FnOnce() -> Result<(), E>) {
        debug_assert!(matches!(self, Self::NotEntered));
        *self = Self::Entered;
        // Preserve this phase's first result or original unwind payload. Each
        // phase separately establishes which actual backing must stay owned.
        *self = match catch_unwind(AssertUnwindSafe(operation)) {
            Ok(result) => Self::Returned(result),
            Err(payload) => Self::Panicked(payload),
        };
    }
    fn succeeded(&self) -> bool {
        matches!(self, Self::Returned(Ok(())))
    }
}

/// A write transaction retained through its first terminal operation.
///
/// Install this value in the caller's admitted ownership census before terminal
/// execution. The transaction is never moved into a fallible commit/abort call.
/// No terminal attempt, including a failed automatic rollback, is replayed.
/// All later commit/abort calls observe the same first operation and outcomes.
///
/// Keep this owner while settlement is [`WriteTerminalSettlement::Retained`].
/// Dropping it is not cleanup evidence; it may destroy unproved transaction
/// state and cannot replace an explicit caller-owned cleanup/drain protocol.
/// Even `Settled` requires `dispose_settled` and separate database/backend
/// close before the caller can release their charges or report complete drain.
/// This type does not establish a transaction-memory or panic-payload bound.
#[must_use = "retain this exact transaction owner until its cleanup is independently established"]
pub struct RetainedWriteTransaction {
    transaction: Option<WriteTransaction>,
    operation: Option<WriteTerminalOperation>,
    terminal: Observation<WriteTerminalError>,
    rollback: Observation<StorageError>,
    disposal: Observation<Infallible>,
    settlement: WriteTerminalSettlement,
}

/// Borrowed original outcomes; only the actual owner can construct this view.
#[must_use = "inspect settlement, disposal, and the original terminal and rollback outcomes"]
pub struct WriteTerminalReport<'a> {
    owner: &'a RetainedWriteTransaction,
}
impl WriteTerminalReport<'_> {
    pub fn operation(&self) -> Option<WriteTerminalOperation> {
        self.owner.operation
    }
    pub fn settlement(&self) -> WriteTerminalSettlement {
        self.owner.settlement
    }
    pub fn terminal(&self) -> TerminalObservation<'_, WriteTerminalError> {
        self.owner.terminal.borrow()
    }
    /// Actual disposal is separate from commit/abort settlement. A panic keeps
    /// its original payload here and can never become a successful disposal.
    pub fn disposal(&self) -> TerminalObservation<'_, Infallible> {
        self.owner.disposal.borrow()
    }
    pub fn disposal_complete(&self) -> bool {
        self.owner.disposal.succeeded()
    }
    pub fn rollback(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.rollback.borrow()
    }
}

impl WriteTransaction {
    /// Transfer this exact transaction into a retained terminal owner.
    /// This constructs only inline state; the caller must admit and register
    /// the owner's backing before dispatch. The API requires std unwinding.
    pub fn retain(self) -> RetainedWriteTransaction {
        RetainedWriteTransaction {
            transaction: Some(self),
            operation: None,
            terminal: Observation::NotEntered,
            rollback: Observation::NotEntered,
            disposal: Observation::NotEntered,
            settlement: WriteTerminalSettlement::Unstarted,
        }
    }
}
impl RetainedWriteTransaction {
    /// Borrow the original transaction only before terminal entry. Table guards
    /// borrow this owner and therefore must close before a mutable terminal call.
    pub fn transaction(&self) -> Option<&WriteTransaction> {
        self.transaction
            .as_ref()
            .filter(|_| self.operation.is_none())
    }
    pub fn report(&self) -> WriteTerminalReport<'_> {
        WriteTerminalReport { owner: self }
    }
    /// Dispose of an actually settled transaction without discarding its original
    /// terminal and rollback observations. Unstarted/uncertain transactions are
    /// untouched. This never replays commit, abort or an interrupted disposal.
    ///
    /// A matching actual database owner must remain borrowed for this entire
    /// operation. Open and waiting-for-transactions owners qualify; a different
    /// database leaves this transaction and its observations untouched. This
    /// prevents a deferred backend close from running inside transaction Drop.
    /// Physical close belongs to the separately observed database owner.
    ///
    /// The transaction owner remains in its admitted census until these retained
    /// diagnostic allocations are independently retired. Successful disposal
    /// releases the actual writer slot; it is not database/backend close or
    /// census retirement. A caught internal destructor panic does not establish
    /// complete disposal and cannot be retried.
    pub fn dispose_settled(&mut self, database: &RetainedDatabase) -> WriteTerminalReport<'_> {
        if self.settlement == WriteTerminalSettlement::Settled
            && matches!(self.disposal, Observation::NotEntered)
            && self.transaction.as_ref().is_some_and(|transaction| {
                database.owns_transaction(&transaction.transaction_tracker, &transaction.mem)
            })
        {
            self.disposal.observe(|| {
                drop(self.transaction.take());
                Ok(())
            });
        }
        self.report()
    }
    /// Enter one immediate-durable commit. Any later call only observes its
    /// original outcome, even if that later call requests abort instead.
    pub fn commit(&mut self) -> WriteTerminalReport<'_> {
        if self.operation.is_none() {
            self.operation = Some(WriteTerminalOperation::Commit);
            self.settlement = WriteTerminalSettlement::Retained;
            // Prevent WriteTransaction::drop from replaying terminal work. This
            // flag alone is never interpreted as evidence of settled ownership.
            let transaction = self
                .transaction
                .as_mut()
                .expect("unstarted transaction retained");
            transaction.completed = true;
            let latch = AllocatorStateLatch::arm(transaction.mem.clone());
            self.terminal.observe(|| {
                if let Some(error) = transaction.mem.capacity_error() {
                    return Err(WriteTerminalError::Commit(error.into()));
                }
                if transaction.is_poisoned() {
                    return Err(WriteTerminalError::Commit(CommitError::TransactionPoisoned));
                }
                // The helper performs the original durable protocol. Its parent
                // consuming API combines rollback errors; this owner must keep
                // the primary refusal and actual rollback outcome separately.
                transaction
                    .commit_inner_helper()
                    .map_err(WriteTerminalError::Commit)
            });
            if matches!(
                self.terminal,
                Observation::Returned(Err(WriteTerminalError::Commit(
                    CommitError::Storage(
                        StorageError::CapacityDenied | StorageError::CacheCapacityDenied
                    ) | CommitError::TransactionPoisoned
                )))
            ) {
                self.rollback.observe(|| transaction.abort_inner());
                if self.rollback.succeeded() {
                    self.settlement = WriteTerminalSettlement::Settled;
                    latch.disarm();
                }
            } else if self.terminal.succeeded() {
                self.settlement = WriteTerminalSettlement::Settled;
                latch.disarm();
            }
            // Every other return or unwind leaves the allocator fence armed.
            // The exact transaction and all original diagnostics stay here.
        }
        self.report()
    }
    /// Enter one abort, or observe an already entered terminal operation.
    pub fn abort(&mut self) -> WriteTerminalReport<'_> {
        if self.operation.is_none() {
            self.operation = Some(WriteTerminalOperation::Abort);
            self.settlement = WriteTerminalSettlement::Retained;
            let transaction = self
                .transaction
                .as_mut()
                .expect("unstarted transaction retained");
            transaction.completed = true;
            let latch = AllocatorStateLatch::arm(transaction.mem.clone());
            self.terminal
                .observe(|| transaction.abort_inner().map_err(WriteTerminalError::Abort));
            if self.terminal.succeeded() {
                self.settlement = WriteTerminalSettlement::Settled;
                latch.disarm();
            }
        }
        self.report()
    }
}

#[cfg(test)]
#[path = "retained_transaction_tests.rs"]
mod tests;
