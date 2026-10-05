//! Explicit custody for opening, transactions, and physical close.
//!
//! These owners keep the first result of every operation. A failed commit or
//! close is never retried merely because a caller asks for another report.

use crate::core::{
    AdmissionError, AdmittedValue, BackendCloseEntry, BackendCloseOutcome,
    BackendNativeDisposition, CoreError, CorePanic, NativeDisposal, NativeDisposalReport,
    OpeningCustody, OwnerFailed, ResidentLease, StorageAdmission,
};
use crate::group::{GroupFile, SegmentGroupBackend};
use crate::root::{ROOT_SLOT_BYTES, RootSlot};
use crate::tables::{
    Builder, CommitError, Database, DatabaseError, ReadTransaction, StorageError, TableDefinition,
    TableError, TransactionError, WriteTransaction,
};
use std::alloc::{Layout, LayoutError};
use std::any::Any;
use std::convert::Infallible;
use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

/// A view of the first attempted call. The original error or unwind payload
/// remains owned by its retained operation.
pub enum TerminalObservation<'a, E> {
    NotEntered,
    Entered,
    Returned(Result<(), &'a E>),
    Panicked(&'a (dyn Any + Send)),
}

enum Attempt<E> {
    Pending,
    Running,
    Done(Result<(), E>),
    Unwound(Box<dyn Any + Send>),
}

impl<E> Attempt<E> {
    fn view(&self) -> TerminalObservation<'_, E> {
        match self {
            Self::Pending => TerminalObservation::NotEntered,
            Self::Running => TerminalObservation::Entered,
            Self::Done(Ok(())) => TerminalObservation::Returned(Ok(())),
            Self::Done(Err(error)) => TerminalObservation::Returned(Err(error)),
            Self::Unwound(payload) => TerminalObservation::Panicked(payload.as_ref()),
        }
    }

    fn run(&mut self, body: impl FnOnce() -> Result<(), E>) {
        if !matches!(self, Self::Pending) {
            return;
        }
        *self = Self::Running;
        *self = match catch_unwind(AssertUnwindSafe(body)) {
            Ok(result) => Self::Done(result),
            Err(payload) => Self::Unwound(payload),
        };
    }

    fn view_is_panic(&self) -> bool {
        matches!(self, Self::Unwound(_))
    }

    fn succeeded(&self) -> bool {
        matches!(self, Self::Done(Ok(())))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteTerminalOperation {
    Commit,
    Abort,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteTerminalSettlement {
    Unstarted,
    /// A positively successful commit still owns its original writer token.
    /// Capture must finish before matching-database disposal releases it.
    HoldingWriter,
    Settled,
    Retained,
}

#[derive(Debug)]
pub enum WriteTerminalError {
    Commit(CommitError),
    Abort(StorageError),
}

/// The transaction and its first terminal outcome stay together until an
/// explicit matching-database disposal releases the writer slot.
#[must_use]
pub struct RetainedWriteTransaction {
    transaction: Option<WriteTransaction>,
    operation: Option<WriteTerminalOperation>,
    terminal: Attempt<WriteTerminalError>,
    rollback: Attempt<StorageError>,
    disposal: Attempt<Infallible>,
    settlement: WriteTerminalSettlement,
}

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
        self.owner.terminal.view()
    }

    pub fn rollback(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.rollback.view()
    }

    pub fn disposal(&self) -> TerminalObservation<'_, Infallible> {
        self.owner.disposal.view()
    }

    pub fn disposal_complete(&self) -> bool {
        self.owner.disposal.succeeded()
    }

    /// The original error of a commit that settled without any effect. The
    /// batch was rejected or proved rolled back whole before publication and the
    /// writer gate was released. A retained or uncertain failure, or an
    /// unwind, is never reported here.
    pub fn rejected_no_effect(&self) -> Option<&StorageError> {
        match &self.owner.terminal {
            Attempt::Done(Err(WriteTerminalError::Commit(CommitError(error))))
                if self.owner.settlement == WriteTerminalSettlement::Settled =>
            {
                Some(error)
            }
            _ => None,
        }
    }

    /// A settled commit refused for capacity with no published changes.
    pub fn is_capacity_denied(&self) -> bool {
        self.rejected_no_effect()
            .is_some_and(StorageError::is_capacity_denied)
    }
}

impl WriteTransaction {
    pub fn retain(self) -> RetainedWriteTransaction {
        RetainedWriteTransaction {
            transaction: Some(self),
            operation: None,
            terminal: Attempt::Pending,
            rollback: Attempt::Pending,
            disposal: Attempt::Pending,
            settlement: WriteTerminalSettlement::Unstarted,
        }
    }
}

impl RetainedWriteTransaction {
    pub fn transaction(&self) -> Option<&WriteTransaction> {
        self.operation
            .is_none()
            .then_some(self.transaction.as_ref())
            .flatten()
    }

    pub fn report(&self) -> WriteTerminalReport<'_> {
        WriteTerminalReport { owner: self }
    }

    pub fn commit(&mut self) -> WriteTerminalReport<'_> {
        self.commit_with_writer(false)
    }

    /// Publish once and retain the original successful writer token through
    /// preowned source capture. Every refusal, unknown result and panic retains
    /// the same original terminal observation; none can mint HoldingWriter.
    pub fn commit_holding_writer(&mut self) -> WriteTerminalReport<'_> {
        self.commit_with_writer(true)
    }

    fn commit_with_writer(&mut self, hold_success: bool) -> WriteTerminalReport<'_> {
        if self.operation.is_none() {
            self.operation = Some(WriteTerminalOperation::Commit);
            self.settlement = WriteTerminalSettlement::Retained;
            let transaction = self.transaction.as_mut().expect("retained writer");
            self.terminal.run(|| {
                transaction
                    .commit_inner_with_writer(hold_success)
                    .map_err(|error| WriteTerminalError::Commit(error.into()))
            });
            self.settle_returned();
            if hold_success
                && self.terminal.succeeded()
                && self
                    .transaction
                    .as_ref()
                    .is_some_and(WriteTransaction::holds_writer)
            {
                self.settlement = WriteTerminalSettlement::HoldingWriter;
            }
        }
        self.report()
    }

    pub fn abort(&mut self) -> WriteTerminalReport<'_> {
        if self.operation.is_none() {
            self.operation = Some(WriteTerminalOperation::Abort);
            self.settlement = WriteTerminalSettlement::Retained;
            let transaction = self.transaction.as_mut().expect("retained writer");
            self.terminal.run(|| {
                transaction
                    .abort_inner()
                    .map_err(|error| WriteTerminalError::Abort(error.into()))
            });
            self.settle_returned();
        }
        self.report()
    }

    /// A terminal that returned with the writer gate released has settled:
    /// it published, or rejection/rollback proved no published changes. A terminal that
    /// kept the gate, or unwound, stays retained with its transaction.
    fn settle_returned(&mut self) {
        if matches!(self.terminal, Attempt::Done(_))
            && self
                .transaction
                .as_ref()
                .is_some_and(|transaction| !transaction.holds_writer())
        {
            self.settlement = WriteTerminalSettlement::Settled;
        }
    }

    pub fn dispose_settled(&mut self, database: &RetainedDatabase) -> WriteTerminalReport<'_> {
        if matches!(
            self.settlement,
            WriteTerminalSettlement::Settled | WriteTerminalSettlement::HoldingWriter
        ) && matches!(self.disposal, Attempt::Pending)
            && self
                .transaction
                .as_ref()
                .is_some_and(|transaction| database.owns_writer(transaction))
        {
            self.disposal.run(|| {
                drop(self.transaction.take());
                Ok(())
            });
            if self.settlement == WriteTerminalSettlement::HoldingWriter {
                self.settlement = if self.disposal.succeeded() {
                    WriteTerminalSettlement::Settled
                } else {
                    WriteTerminalSettlement::Retained
                };
            }
        }
        self.report()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadCloseSettlement {
    Open,
    WaitingForGuards,
    Settled,
    Disposed,
    DisposalUncertain,
    Retained,
}

#[derive(Debug)]
pub enum BoundedReadError {
    Closed,
    BoundExceeded,
    Table(TableError),
    Storage(StorageError),
}

impl fmt::Display for BoundedReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("retained read is closed"),
            Self::BoundExceeded => formatter.write_str("read bound exceeded"),
            Self::Table(error) => error.fmt(formatter),
            Self::Storage(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for BoundedReadError {}

pub struct BoundedReadRow {
    pub key: AdmittedValue,
    pub value: AdmittedValue,
}

#[must_use]
pub struct RetainedReadTransaction {
    retirement_observer: Option<crate::tables::source_read::ReadRetirementObserver>,
    native_retirement: Attempt<StorageError>,
    transaction: Option<ReadTransaction>,
    release: Attempt<StorageError>,
    disposal: Attempt<Infallible>,
    settlement: ReadCloseSettlement,
}

pub struct ReadCloseReport<'a> {
    owner: &'a RetainedReadTransaction,
}

impl ReadCloseReport<'_> {
    pub fn native_retirement(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.native_retirement.view()
    }
    pub fn retains_database(&self) -> bool {
        self.owner.transaction.is_some() || self.owner.retirement_observer.is_some()
    }

    pub fn settlement(&self) -> ReadCloseSettlement {
        self.owner.settlement
    }

    pub fn release(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.release.view()
    }

    pub fn disposal(&self) -> TerminalObservation<'_, Infallible> {
        self.owner.disposal.view()
    }

    pub fn retains_transaction(&self) -> bool {
        self.owner.transaction.is_some()
    }
}

impl ReadTransaction {
    pub fn retain(self) -> RetainedReadTransaction {
        RetainedReadTransaction {
            retirement_observer: None,
            native_retirement: Attempt::Pending,
            transaction: Some(self),
            release: Attempt::Pending,
            disposal: Attempt::Pending,
            settlement: ReadCloseSettlement::Open,
        }
    }
}

/// The exact native acquisition error and its terminal acquisition disposition.
/// A clean capacity refusal means no transaction/pin was published by this
/// attempt and all provisional backing was destroyed before the call returned.
/// It is not a synthesized successful release or disposal of a transaction.
#[derive(Debug)]
pub struct ReadAcquisitionFailure {
    original: TransactionError,
    clean_capacity_refusal: bool,
}
impl ReadAcquisitionFailure {
    pub fn original(&self) -> &TransactionError {
        &self.original
    }
    pub fn is_clean_capacity_refusal(&self) -> bool {
        self.clean_capacity_refusal
    }
    fn unproven(original: TransactionError) -> Self {
        Self {
            original,
            clean_capacity_refusal: false,
        }
    }
    // Only the canonical retained begin/fork calls may mint this disposition,
    // after their full native call returns. SnapshotHandle admits before pin
    // acquisition/clone; pin backing/slot denial precedes slot publication.
    // Returning here also proves provisional destructors completed. A panic,
    // owner failure, closed owner or post-acquisition check cannot qualify.
    fn after_native_return(original: TransactionError) -> Self {
        let clean_capacity_refusal = matches!(&(original), TransactionError(StorageError::Core(native_error)) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)));
        Self {
            original,
            clean_capacity_refusal,
        }
    }
}
impl fmt::Display for ReadAcquisitionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.original, formatter)
    }
}
impl std::error::Error for ReadAcquisitionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

impl Database {
    pub fn begin_read_retained(&self) -> Result<RetainedReadTransaction, ReadAcquisitionFailure> {
        self.begin_read()
            .map(ReadTransaction::retain)
            .map_err(ReadAcquisitionFailure::after_native_return)
    }
}

impl RetainedReadTransaction {
    #[cfg(test)]
    pub(crate) fn corrupt_final_release_for_test(&self, poison: bool) {
        self.transaction
            .as_ref()
            .unwrap()
            .retirement_observer()
            .corrupt_for_test(poison);
    }

    /// Fork only an open selected reader, with independent release/disposal
    /// state and snapshot descendants. The shared borrow cannot overlap this
    /// owner's mutable close; an enclosing registered reader must preserve
    /// that serialization while installing its child before invoking fork.
    pub fn fork(&self) -> Result<Self, ReadAcquisitionFailure> {
        if self.settlement != ReadCloseSettlement::Open {
            return Err(ReadAcquisitionFailure::unproven(
                StorageError::DatabaseClosed.into(),
            ));
        }
        self.transaction
            .as_ref()
            .ok_or_else(|| ReadAcquisitionFailure::unproven(StorageError::DatabaseClosed.into()))?
            .fork()
            .map(ReadTransaction::retain)
            .map_err(ReadAcquisitionFailure::after_native_return)
    }

    fn readable(&self) -> Result<&ReadTransaction, BoundedReadError> {
        if self.settlement != ReadCloseSettlement::Open {
            return Err(BoundedReadError::Closed);
        }
        self.transaction.as_ref().ok_or(BoundedReadError::Closed)
    }

    fn table_name(
        definition: TableDefinition<&[u8], &[u8]>,
    ) -> Result<&'static str, BoundedReadError> {
        let name = definition.name();
        if name.len() > 128 {
            Err(BoundedReadError::BoundExceeded)
        } else {
            Ok(name)
        }
    }

    pub fn check_bytes_table(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
    ) -> Result<(), BoundedReadError> {
        Self::table_name(definition)?;
        self.readable()?
            .open_table(definition)
            .map_err(BoundedReadError::Table)?;
        Ok(())
    }

    pub fn check_bytes_table_prepared(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        workspace: &mut crate::PreparedPointRead,
    ) -> Result<(), BoundedReadError> {
        Self::table_name(definition)?;
        self.readable()?
            .check_bytes_table_prepared(definition, workspace)
            .map_err(BoundedReadError::Table)
    }

    /// The returned value retains its resident admission until it is dropped.
    pub fn get_bytes(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<AdmittedValue>, BoundedReadError> {
        let table = Self::table_name(definition)?;
        if key.len() > 8192 || max_value_bytes > 64 << 20 {
            return Err(BoundedReadError::BoundExceeded);
        }
        self.readable()?
            .get_bytes(table, key, max_value_bytes)
            .map_err(|error| match error {
                error
                    if matches!(
                        error.rejected_cause(),
                        Some(crate::CoreErrorCause::InvalidInput(_))
                    ) =>
                {
                    BoundedReadError::BoundExceeded
                }
                other => BoundedReadError::Storage(other.into()),
            })
    }

    pub fn prepare_point_read(
        &self,
        max_value_bytes: usize,
    ) -> Result<crate::PreparedPointRead, BoundedReadError> {
        self.readable()?
            .prepare_point_read(max_value_bytes)
            .map_err(|error| BoundedReadError::Storage(error.into()))
    }

    pub fn point_length_prepared(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
        workspace: &mut crate::PreparedPointRead,
    ) -> Result<Option<usize>, BoundedReadError> {
        let table = Self::table_name(definition)?;
        if key.len() > 8192 {
            return Err(BoundedReadError::BoundExceeded);
        }
        self.readable()?
            .point_length_prepared(table, key, workspace)
            .map_err(|error| BoundedReadError::Storage(error.into()))
    }

    pub fn get_bytes_prepared<'workspace>(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
        max_value_bytes: usize,
        workspace: &'workspace mut crate::PreparedPointRead,
    ) -> Result<Option<&'workspace [u8]>, BoundedReadError> {
        let table = Self::table_name(definition)?;
        if key.len() > 8192 || max_value_bytes > 64 << 20 {
            return Err(BoundedReadError::BoundExceeded);
        }
        self.readable()?
            .get_bytes_prepared(table, key, max_value_bytes, workspace)
            .map_err(|error| match error {
                error
                    if matches!(
                        error.rejected_cause(),
                        Some(crate::CoreErrorCause::InvalidInput(_))
                    ) =>
                {
                    BoundedReadError::BoundExceeded
                }
                other => BoundedReadError::Storage(other.into()),
            })
    }

    /// Consult the pinned disk root without materializing a value or exposing a
    /// table guard outside this retained transaction.
    pub fn key_exists(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
    ) -> Result<bool, BoundedReadError> {
        let table = Self::table_name(definition)?;
        if key.len() > 8192 {
            return Err(BoundedReadError::BoundExceeded);
        }
        self.readable()?
            .key_exists(table, key)
            .map_err(|error| BoundedReadError::Storage(error.into()))
    }

    pub fn prefix_exists(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        prefix: &[u8],
    ) -> Result<bool, BoundedReadError> {
        let table = Self::table_name(definition)?;
        if prefix.len() > 8192 {
            return Err(BoundedReadError::BoundExceeded);
        }
        self.readable()?
            .prefix_exists(table, prefix)
            .map_err(|error| BoundedReadError::Storage(error.into()))
    }

    /// Both returned byte strings retain their resident admissions.
    pub fn next_bytes(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        prefix: &[u8],
        after: Option<&[u8]>,
        max_value_bytes: usize,
    ) -> Result<Option<BoundedReadRow>, BoundedReadError> {
        let table = Self::table_name(definition)?;
        if prefix.len() > 8192
            || after.is_some_and(|key| key.len() > 8192 || !key.starts_with(prefix))
            || max_value_bytes > 64 << 20
        {
            return Err(BoundedReadError::BoundExceeded);
        }
        self.readable()?
            .next_bytes(table, prefix, after, max_value_bytes)
            .map(|row| row.map(|(key, value)| BoundedReadRow { key, value }))
            .map_err(|error| match error {
                error
                    if matches!(
                        error.rejected_cause(),
                        Some(crate::CoreErrorCause::InvalidInput(_))
                    ) =>
                {
                    BoundedReadError::BoundExceeded
                }
                other => BoundedReadError::Storage(other.into()),
            })
    }

    pub fn report(&self) -> ReadCloseReport<'_> {
        ReadCloseReport { owner: self }
    }

    pub fn close(&mut self, database: &RetainedDatabase) -> ReadCloseReport<'_> {
        if matches!(
            self.settlement,
            ReadCloseSettlement::Open | ReadCloseSettlement::WaitingForGuards
        ) && self
            .transaction
            .as_ref()
            .is_some_and(|transaction| database.owns_reader(transaction))
        {
            // A table, range or access guard can outlive the transaction
            // facade. Its exact snapshot is still a native reader; the
            // release attempt has not entered while that owner survives.
            if self
                .transaction
                .as_ref()
                .is_some_and(ReadTransaction::has_snapshot_descendants)
            {
                self.settlement = ReadCloseSettlement::WaitingForGuards;
            } else {
                self.release.run(|| Ok(()));
                self.settlement = if self.release.succeeded() {
                    ReadCloseSettlement::Settled
                } else {
                    ReadCloseSettlement::Retained
                };
            }
        }
        self.report()
    }

    pub fn dispose_settled(&mut self, database: &RetainedDatabase) -> ReadCloseReport<'_> {
        if self.settlement == ReadCloseSettlement::Settled
            && self
                .transaction
                .as_ref()
                .is_some_and(|transaction| database.owns_reader(transaction))
        {
            // Recheck the exact snapshot at the disposal boundary. A future
            // caller that can hold a descendant between close and disposal
            // must not turn this owner's pending guard into a clean report.
            if self
                .transaction
                .as_ref()
                .is_some_and(ReadTransaction::has_snapshot_descendants)
            {
                self.settlement = ReadCloseSettlement::WaitingForGuards;
            } else {
                // Install the actual registry/Database observer before destroying
                // the last snapshot. This performs no allocation or callback.
                self.retirement_observer = self
                    .transaction
                    .as_ref()
                    .map(ReadTransaction::retirement_observer);
                self.disposal.run(|| {
                    drop(self.transaction.take());
                    Ok(())
                });
                let observer = self
                    .retirement_observer
                    .as_ref()
                    .expect("retained retirement observer");
                if self.disposal.succeeded() {
                    self.native_retirement
                        .run(|| observer.check().map_err(StorageError::from));
                    if self.native_retirement.succeeded() {
                        self.retirement_observer.take();
                        self.settlement = ReadCloseSettlement::Disposed;
                    } else {
                        observer.fence();
                        self.settlement = ReadCloseSettlement::Retained;
                    }
                } else {
                    observer.fence();
                    self.settlement = ReadCloseSettlement::DisposalUncertain;
                }
            }
        }
        self.report()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseCloseSettlement {
    Open,
    WaitingForTransactions,
    Settled,
    Retained,
    DrainedWithFailure,
    FailedDisposed,
    Disposed,
}

/// The database stays installed even after native closure so diagnostics keep
/// borrowing the original outcome until its enclosing owner is retired.
#[must_use]
pub struct RetainedDatabase {
    database: Option<Database>,
    disposal: NativeDisposal,
    first_not_entered: Option<BackendCloseOutcome>,
    retry_not_entered: Option<BackendCloseOutcome>,
    pending_close: Option<BackendCloseOutcome>,
    admission: Arc<dyn StorageAdmission>,
    shutdown: Attempt<StorageError>,
    backend: Attempt<StorageError>,
    failed_disposal: Attempt<StorageError>,
    native: BackendNativeDisposition,
    settlement: DatabaseCloseSettlement,
}

pub struct DatabaseCloseReport<'a> {
    owner: &'a RetainedDatabase,
}

impl DatabaseCloseReport<'_> {
    pub fn settlement(&self) -> DatabaseCloseSettlement {
        self.owner.settlement
    }

    pub fn shutdown(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.shutdown.view()
    }

    pub fn backend(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.backend.view()
    }

    pub fn failed_disposal(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.failed_disposal.view()
    }

    pub fn native_disposition(&self) -> BackendNativeDisposition {
        self.owner.native
    }
    pub fn disposal(&self) -> NativeDisposalReport<'_> {
        self.owner.disposal.report()
    }
    pub fn first_not_entered_outcome(&self) -> Option<&BackendCloseOutcome> {
        self.owner.first_not_entered.as_ref()
    }
    pub fn retry_not_entered_outcome(&self) -> Option<&BackendCloseOutcome> {
        self.owner.retry_not_entered.as_ref()
    }
}

impl RetainedDatabase {
    fn new(database: Database, admission: Arc<dyn StorageAdmission>) -> Self {
        Self {
            database: Some(database),
            disposal: NativeDisposal::default(),
            first_not_entered: None,
            retry_not_entered: None,
            pending_close: None,
            admission,
            shutdown: Attempt::Pending,
            backend: Attempt::Pending,
            failed_disposal: Attempt::Pending,
            native: BackendNativeDisposition::Retained,
            settlement: DatabaseCloseSettlement::Open,
        }
    }

    pub fn database(&self) -> Option<&Database> {
        (self.settlement == DatabaseCloseSettlement::Open)
            .then_some(self.database.as_ref())
            .flatten()
    }

    fn owns_writer(&self, transaction: &WriteTransaction) -> bool {
        self.database
            .as_ref()
            .is_some_and(|database| transaction.belongs_to(database))
    }

    fn owns_reader(&self, transaction: &ReadTransaction) -> bool {
        self.database
            .as_ref()
            .is_some_and(|database| transaction.belongs_to(database))
    }

    pub fn report(&self) -> DatabaseCloseReport<'_> {
        DatabaseCloseReport { owner: self }
    }

    /// Waiting for an accepted transaction is a pre-effect condition and may
    /// be revisited. Any native close result or unwind is terminal here.
    pub fn close(&mut self) -> DatabaseCloseReport<'_> {
        if !matches!(
            self.settlement,
            DatabaseCloseSettlement::Open | DatabaseCloseSettlement::WaitingForTransactions
        ) {
            return self.report();
        }
        self.shutdown.run(|| {
            self.admission
                .check_owner()
                .map_err(|_| StorageError::from(CoreError::new(crate::CoreErrorCause::OwnerFailed)))
        });
        let Some(database) = self.database.as_ref() else {
            self.settlement = DatabaseCloseSettlement::Retained;
            return self.report();
        };
        let result = catch_unwind(AssertUnwindSafe(|| database.close_native()));
        match result {
            Ok(outcome) => {
                self.native = outcome.native_disposition();
                if outcome.entry() == BackendCloseEntry::NotEntered {
                    self.pending_close = Some(outcome);
                    if self.first_not_entered.is_none() {
                        self.first_not_entered = self.pending_close.take();
                    } else {
                        if self.retry_not_entered.is_some() {
                            self.disposal.retry_diagnostic_disposal =
                                crate::native_backend::DisposalObservation::NotEntered;
                            let prior = self.retry_not_entered.take();
                            self.disposal.retry_diagnostic_disposal.run(|| drop(prior));
                            if !self.disposal.retry_diagnostic_disposal.returned() {
                                self.settlement = DatabaseCloseSettlement::Retained;
                                return self.report();
                            }
                        }
                        self.retry_not_entered = self.pending_close.take();
                    }
                    self.settlement = DatabaseCloseSettlement::WaitingForTransactions;
                    return self.report();
                }
                self.backend = Attempt::Done(outcome.into_result().map_err(StorageError::Io));
                self.settlement = match (&self.backend, self.native) {
                    (Attempt::Done(Ok(())), BackendNativeDisposition::Drained)
                        if self.shutdown.succeeded() =>
                    {
                        DatabaseCloseSettlement::Settled
                    }
                    (Attempt::Done(Ok(())), BackendNativeDisposition::Drained) => {
                        DatabaseCloseSettlement::DrainedWithFailure
                    }
                    (Attempt::Done(Err(_)), BackendNativeDisposition::Drained) => {
                        DatabaseCloseSettlement::DrainedWithFailure
                    }
                    _ => DatabaseCloseSettlement::Retained,
                };
            }
            Err(payload) => {
                self.backend = Attempt::Unwound(payload);
                self.settlement = DatabaseCloseSettlement::Retained;
            }
        }
        self.report()
    }

    /// Native closure and positive owned-resource disposal are independent.
    pub fn dispose(&mut self) -> DatabaseCloseReport<'_> {
        let failed = self.settlement == DatabaseCloseSettlement::DrainedWithFailure;
        if !matches!(
            self.settlement,
            DatabaseCloseSettlement::Settled | DatabaseCloseSettlement::DrainedWithFailure
        ) {
            return self.report();
        }
        if let Some(database) = self.database.take() {
            self.disposal.adopt_database(database);
        }
        self.disposal.mark_native_drained();
        if self.disposal.dispose() {
            self.failed_disposal = Attempt::Done(Ok(()));
            self.settlement = if failed {
                DatabaseCloseSettlement::FailedDisposed
            } else {
                DatabaseCloseSettlement::Disposed
            };
        }
        self.report()
    }
}

impl Database {
    pub fn retain(self) -> RetainedDatabase {
        let admission = self.admission();
        RetainedDatabase::new(self, admission)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseOpenMode {
    Create,
    Existing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseOpenPhase {
    Prepared,
    Opening,
    Ready,
    Closing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseOpenSettlement {
    Prepared,
    Retained,
    Ready,
    WaitingForTransactions,
    Closed,
    DrainedWithFailure,
    FailedDisposed,
    Disposed,
}

struct SharedBackend(crate::native_owned_arc::NativeOwnedArc<Box<dyn SegmentGroupBackend>>);

impl fmt::Debug for SharedBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharedBackend")
    }
}

impl Clone for SharedBackend {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl SegmentGroupBackend for SharedBackend {
    fn reserve_transaction(
        &self,
        plan: &crate::TransactionSpacePlan,
    ) -> std::result::Result<(), crate::TransactionReserveError> {
        self.0.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.0.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.0.cancel_transaction(group_id, batch_seq)
    }

    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.0.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.0.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.0.sync_root()
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.0.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.0.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.0.create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.0.len(file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.0.write(file, at, bytes)
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.0.set_len(file, length)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.0.sync(file)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.0.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.0.sync_names()
    }
    fn close(&self) -> BackendCloseOutcome {
        self.0.close()
    }
}

enum FenceOutcome {
    Returned,
    Unwound(CorePanic),
}

struct OpeningAdmission {
    inner: Arc<dyn StorageAdmission>,
    failed: AtomicBool,
    fence: OnceLock<FenceOutcome>,
}

impl fmt::Debug for OpeningAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpeningAdmission")
            .field("failed", &self.failed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl StorageAdmission for OpeningAdmission {
    fn install_source_pool(
        self: Arc<Self>,
        install: &mut crate::SourcePoolInstall<'_>,
    ) -> io::Result<()> {
        self.check_owner()
            .map_err(|_| io::Error::from(io::ErrorKind::Other))?;
        self.inner.clone().install_source_pool(install)?;
        self.check_owner().map_err(|_| io::ErrorKind::Other.into())
    }

    fn check_owner(&self) -> Result<(), OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            return Err(OwnerFailed);
        }
        self.inner.check_owner()
    }

    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(AdmissionError::OwnerFailed);
        }
        self.inner.reserve_workspace(bytes)
    }

    fn quote_cache_memory(
        &self,
        credit_bytes: u64,
    ) -> Result<crate::CacheMemoryQuote, AdmissionError> {
        self.inner.quote_cache_memory(credit_bytes)
    }

    fn reserve_cache_memory(
        self: Arc<Self>,
        credit_bytes: u64,
    ) -> Result<crate::CacheMemoryLease, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let lease = self.inner.clone().reserve_cache_memory(credit_bytes)?;
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        Ok(lease)
    }

    fn reserve_growth(&self, current: u64, requested: u64) -> Result<(), AdmissionError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(AdmissionError::OwnerFailed);
        }
        self.inner.reserve_growth(current, requested)
    }

    fn settle_growth(&self, actual: u64) -> Result<(), OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            return Err(OwnerFailed);
        }
        self.inner.settle_growth(actual)
    }

    fn owner_failed(&self) {
        if self.failed.swap(true, Ordering::AcqRel) {
            return;
        }
        let outcome = match catch_unwind(AssertUnwindSafe(|| self.inner.owner_failed())) {
            Ok(()) => FenceOutcome::Returned,
            Err(payload) => FenceOutcome::Unwound(CorePanic::new(payload)),
        };
        let _ = self.fence.set(outcome);
    }
}

pub struct OpeningFenceReport<'a> {
    owner: &'a OpeningAdmission,
}

impl OpeningFenceReport<'_> {
    pub fn with_observation<R>(
        &self,
        inspect: impl FnOnce(TerminalObservation<'_, Infallible>) -> R,
    ) -> R {
        match self.owner.fence.get() {
            None if self.owner.failed.load(Ordering::Acquire) => {
                inspect(TerminalObservation::Entered)
            }
            None => inspect(TerminalObservation::NotEntered),
            Some(FenceOutcome::Returned) => inspect(TerminalObservation::Returned(Ok(()))),
            Some(FenceOutcome::Unwound(original)) => {
                original.with_payload(|payload| inspect(TerminalObservation::Panicked(payload)))
            }
        }
    }
}

#[must_use]
pub struct RetainedDatabaseOpening {
    builder: Option<Builder>,
    backend: Option<SharedBackend>,
    failed_opening: Option<OpeningCustody<SharedBackend>>,
    prepared_disposal: NativeDisposal,
    prepared_close: crate::core::opening::CloseObservation,
    admission: Arc<OpeningAdmission>,
    mode: DatabaseOpenMode,
    database: Option<RetainedDatabase>,
    phase: DatabaseOpenPhase,
    opening_phase: DatabaseOpenPhase,
    settlement: DatabaseOpenSettlement,
    opening: Attempt<DatabaseError>,
    partial_native: BackendNativeDisposition,
    failed_disposal: Attempt<StorageError>,
}

pub struct DatabaseOpenReport<'a> {
    owner: &'a RetainedDatabaseOpening,
}

impl DatabaseOpenReport<'_> {
    pub fn phase(&self) -> DatabaseOpenPhase {
        self.owner.phase
    }

    pub fn opening_phase(&self) -> DatabaseOpenPhase {
        self.owner.opening_phase
    }

    pub fn settlement(&self) -> DatabaseOpenSettlement {
        self.owner.settlement
    }

    pub fn opening(&self) -> TerminalObservation<'_, DatabaseError> {
        self.owner.opening.view()
    }

    pub fn database_close(&self) -> Option<DatabaseCloseReport<'_>> {
        self.owner.database.as_ref().map(RetainedDatabase::report)
    }

    pub fn native_disposition(&self) -> BackendNativeDisposition {
        self.owner
            .database
            .as_ref()
            .map_or(self.owner.partial_native, |database| database.native)
    }

    pub fn with_partial_close_observation<R>(
        &self,
        inspect: impl FnOnce(TerminalObservation<'_, io::Error>) -> R,
    ) -> R {
        match self.owner.failed_opening.as_ref() {
            Some(custody) => custody.with_close_observation(inspect),
            None => self.owner.prepared_close.with_observation(inspect),
        }
    }
    pub fn partial_close_outcome(&self) -> Option<&BackendCloseOutcome> {
        self.owner
            .failed_opening
            .as_ref()
            .and_then(OpeningCustody::first_close_outcome)
            .or_else(|| self.owner.prepared_close.outcome())
    }
    pub fn partial_close_retry_outcome(&self) -> Option<&BackendCloseOutcome> {
        self.owner
            .failed_opening
            .as_ref()
            .and_then(OpeningCustody::retry_close_outcome)
    }
    pub fn disposal(&self) -> NativeDisposalReport<'_> {
        if let Some(database) = self.owner.database.as_ref() {
            return database.disposal.report();
        }
        if let Some(custody) = self.owner.failed_opening.as_ref() {
            return custody.admitted.report();
        }
        self.owner.prepared_disposal.report()
    }

    pub fn failed_disposal(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.failed_disposal.view()
    }

    pub fn fence(&self) -> OpeningFenceReport<'_> {
        OpeningFenceReport {
            owner: &self.owner.admission,
        }
    }
}

impl Builder {
    /// Fixed backing for the admission and backend custody Arc allocations.
    pub fn retained_opening_allocation_layout() -> Result<Layout, LayoutError> {
        let (admission, _) =
            Layout::new::<[AtomicUsize; 2]>().extend(Layout::new::<OpeningAdmission>())?;
        let (backend, _) = Layout::new::<[AtomicUsize; 2]>()
            .extend(Layout::new::<Box<dyn SegmentGroupBackend>>())?;
        let (combined, _) = admission.pad_to_align().extend(backend.pad_to_align())?;
        // The caller turns this layout into one conservative byte reservation
        // for two separate allocations and their allocator metadata.
        Layout::from_size_align(
            combined.size() + 4 * std::mem::size_of::<usize>(),
            combined.align(),
        )
    }

    pub fn retain_backend(
        self,
        backend: Box<dyn SegmentGroupBackend>,
        mode: DatabaseOpenMode,
    ) -> RetainedDatabaseOpening {
        let admission = Arc::new(OpeningAdmission {
            inner: self.admission(),
            failed: AtomicBool::new(false),
            fence: OnceLock::new(),
        });
        RetainedDatabaseOpening {
            builder: Some(self.with_admission(admission.clone())),
            backend: Some(SharedBackend(crate::native_owned_arc::NativeOwnedArc::new(
                backend,
            ))),
            failed_opening: None,
            prepared_disposal: NativeDisposal::default(),
            prepared_close: crate::core::opening::CloseObservation::NotEntered,
            admission,
            mode,
            database: None,
            phase: DatabaseOpenPhase::Prepared,
            opening_phase: DatabaseOpenPhase::Prepared,
            settlement: DatabaseOpenSettlement::Prepared,
            opening: Attempt::Pending,
            partial_native: BackendNativeDisposition::Retained,
            failed_disposal: Attempt::Pending,
        }
    }
}

impl RetainedDatabaseOpening {
    pub fn report(&self) -> DatabaseOpenReport<'_> {
        DatabaseOpenReport { owner: self }
    }

    pub fn database(&self) -> Option<&Database> {
        if self.settlement == DatabaseOpenSettlement::Ready {
            self.database.as_ref().and_then(RetainedDatabase::database)
        } else {
            None
        }
    }

    pub fn retained_database(&self) -> Option<&RetainedDatabase> {
        matches!(
            self.settlement,
            DatabaseOpenSettlement::Ready | DatabaseOpenSettlement::WaitingForTransactions
        )
        .then_some(self.database.as_ref())
        .flatten()
    }

    pub fn open(&mut self) -> DatabaseOpenReport<'_> {
        if self.settlement != DatabaseOpenSettlement::Prepared {
            return self.report();
        }
        self.phase = DatabaseOpenPhase::Opening;
        self.opening_phase = self.phase;
        self.settlement = DatabaseOpenSettlement::Retained;
        self.opening = Attempt::Running;
        let builder = self.builder.take().expect("first opening attempt");
        // Move the exact prepaid owner. No extra retained alias survives the
        // opening and no raw backend erasure is allocated before admission.
        let backend = self.backend.take().expect("exact prepared backend");
        let opened = match self.mode {
            DatabaseOpenMode::Create => builder.create_with_backend_retained(backend),
            DatabaseOpenMode::Existing => builder.open_with_backend_retained(backend),
        };
        match opened {
            Ok(database) => {
                self.opening = Attempt::Done(Ok(()));
                self.database = Some(RetainedDatabase::new(database, self.admission.clone()));
                self.phase = DatabaseOpenPhase::Ready;
                self.opening_phase = self.phase;
                self.settlement = DatabaseOpenSettlement::Ready;
            }
            Err(failure) => {
                let binding: Arc<dyn StorageAdmission> = self.admission.clone();
                match failure.install(&binding, &mut self.failed_opening) {
                    Ok(Some(original)) => {
                        self.opening = Attempt::Done(Err(DatabaseError::from(original)));
                    }
                    Ok(None) => {
                        self.opening = Attempt::Done(Ok(()));
                    }
                    Err(original) => {
                        // A mismatched witness does not release actual custody.
                        // This branch cannot occur with the exact Builder above.
                        std::mem::forget(original);
                    }
                }
                if self.opening.view_is_panic()
                    || matches!(&self.opening, Attempt::Done(Err(DatabaseError(StorageError::Core(original) | StorageError::UnknownCommit(original)))) if original.panic().is_some())
                {
                    self.admission.owner_failed();
                }
            }
        }
        self.report()
    }

    pub fn close(&mut self) -> DatabaseOpenReport<'_> {
        if matches!(
            self.settlement,
            DatabaseOpenSettlement::Closed
                | DatabaseOpenSettlement::DrainedWithFailure
                | DatabaseOpenSettlement::FailedDisposed
                | DatabaseOpenSettlement::Disposed
        ) {
            return self.report();
        }
        self.phase = DatabaseOpenPhase::Closing;
        if let Some(database) = self.database.as_mut() {
            self.settlement = match database.close().settlement() {
                DatabaseCloseSettlement::Settled => DatabaseOpenSettlement::Closed,
                DatabaseCloseSettlement::WaitingForTransactions => {
                    DatabaseOpenSettlement::WaitingForTransactions
                }
                DatabaseCloseSettlement::DrainedWithFailure => {
                    DatabaseOpenSettlement::DrainedWithFailure
                }
                DatabaseCloseSettlement::FailedDisposed => DatabaseOpenSettlement::FailedDisposed,
                DatabaseCloseSettlement::Disposed => DatabaseOpenSettlement::Disposed,
                DatabaseCloseSettlement::Open | DatabaseCloseSettlement::Retained => {
                    DatabaseOpenSettlement::Retained
                }
            };
        } else if let Some(custody) = self.failed_opening.as_mut() {
            if matches!(
                custody.first_close,
                crate::core::opening::CloseObservation::NotEntered
            ) {
                custody.close();
            } else {
                custody.retry_close();
            }
            self.partial_native = custody.native_disposition();
            self.settlement = custody.with_close_observation(|observation| {
                match (observation, self.partial_native) {
                    (TerminalObservation::Returned(Ok(())), BackendNativeDisposition::Drained) => {
                        DatabaseOpenSettlement::Closed
                    }
                    (TerminalObservation::Returned(Err(_)), BackendNativeDisposition::Drained) => {
                        DatabaseOpenSettlement::DrainedWithFailure
                    }
                    (TerminalObservation::Returned(_), _) if custody.close_may_retry() => {
                        DatabaseOpenSettlement::WaitingForTransactions
                    }
                    _ => DatabaseOpenSettlement::Retained,
                }
            });
        } else if let Some(backend) = self.backend.take() {
            let binding: Arc<dyn StorageAdmission> = self.admission.clone();
            self.failed_opening = Some(OpeningCustody::prepared(backend, binding));
            return self.close();
        }

        if matches!(
            self.settlement,
            DatabaseOpenSettlement::Retained | DatabaseOpenSettlement::DrainedWithFailure
        ) {
            self.admission.owner_failed();
        }
        self.report()
    }

    pub fn dispose(&mut self) -> DatabaseOpenReport<'_> {
        let failed = self.settlement == DatabaseOpenSettlement::DrainedWithFailure;
        if !matches!(
            self.settlement,
            DatabaseOpenSettlement::Closed | DatabaseOpenSettlement::DrainedWithFailure
        ) {
            return self.report();
        }
        let complete = if let Some(database) = self.database.as_mut() {
            matches!(
                database.dispose().settlement(),
                DatabaseCloseSettlement::Disposed | DatabaseCloseSettlement::FailedDisposed
            ) && database.disposal.complete()
        } else if let Some(custody) = self.failed_opening.as_mut() {
            custody.dispose()
        } else {
            self.prepared_disposal.mark_native_drained();
            self.prepared_disposal.dispose_inline(&mut self.backend)
        };
        if complete {
            self.failed_disposal = Attempt::Done(Ok(()));
            self.settlement = if failed {
                DatabaseOpenSettlement::FailedDisposed
            } else {
                DatabaseOpenSettlement::Disposed
            };
        }
        self.report()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheConfig;
    use crate::group::InMemoryGroup;

    struct Permit;

    impl StorageAdmission for Permit {
        fn check_owner(&self) -> Result<(), OwnerFailed> {
            Ok(())
        }

        fn reserve_workspace(&self, _: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
            Ok(Box::new(()))
        }

        fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
            Ok(())
        }

        fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
            Ok(())
        }

        fn owner_failed(&self) {}

        fn quote_cache_memory(
            &self,
            bytes: u64,
        ) -> Result<crate::CacheMemoryQuote, crate::AdmissionError> {
            crate::cache_test::quote::<Self>(bytes)
        }
        fn reserve_cache_memory(
            self: std::sync::Arc<Self>,
            bytes: u64,
        ) -> Result<crate::CacheMemoryLease, crate::AdmissionError> {
            crate::cache_test::reserve(self, bytes)
        }
    }
    impl crate::cache_test::Provider for Permit {
        fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
            let _ = first;
            let _ = bytes;
            Ok(())
        }
        fn release_cache(&self, bytes: u64, last: bool) {
            let _ = (bytes, last);
        }
    }

    fn builder() -> Builder {
        Database::builder(Arc::new(Permit), [61; 16], CacheConfig::default())
    }

    #[test]
    fn retained_index_existence_observes_exact_snapshot_and_tombstones() {
        let rows: TableDefinition<&[u8], &[u8]> = TableDefinition::new("index-only-rows");
        let mut opening =
            builder().retain_backend(Box::new(InMemoryGroup::new()), DatabaseOpenMode::Create);
        assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
        let writer = opening.database().unwrap().begin_write().unwrap();
        writer
            .open_table(rows)
            .unwrap()
            .insert(b"app/old".as_slice(), b"opaque".as_slice())
            .unwrap();
        writer.commit().unwrap();
        let mut old = opening.database().unwrap().begin_read_retained().unwrap();
        assert!(old.key_exists(rows, b"app/old").unwrap());
        assert!(old.prefix_exists(rows, b"app/").unwrap());
        assert!(!old.prefix_exists(rows, b"peer/").unwrap());

        let writer = opening.database().unwrap().begin_write().unwrap();
        let mut table = writer.open_table(rows).unwrap();
        table.remove(b"app/old".as_slice()).unwrap();
        table
            .insert(b"peer/new".as_slice(), b"opaque".as_slice())
            .unwrap();
        drop(table);
        writer.commit().unwrap();
        let mut fresh = opening.database().unwrap().begin_read_retained().unwrap();
        assert!(old.key_exists(rows, b"app/old").unwrap());
        assert!(old.prefix_exists(rows, b"app/").unwrap());
        assert!(!fresh.key_exists(rows, b"app/old").unwrap());
        assert!(!fresh.prefix_exists(rows, b"app/").unwrap());
        assert!(fresh.prefix_exists(rows, b"peer/").unwrap());

        assert_eq!(
            opening.close().settlement(),
            DatabaseOpenSettlement::WaitingForTransactions
        );
        let database = opening.retained_database().unwrap();
        for reader in [&mut old, &mut fresh] {
            assert_eq!(
                reader.close(database).settlement(),
                ReadCloseSettlement::Settled
            );
            assert_eq!(
                reader.dispose_settled(database).settlement(),
                ReadCloseSettlement::Disposed
            );
        }
        assert_eq!(opening.close().settlement(), DatabaseOpenSettlement::Closed);
    }

    struct ReopenableBackend {
        inner: InMemoryGroup,
        closes: Arc<AtomicUsize>,
    }

    impl SegmentGroupBackend for ReopenableBackend {
        fn reserve_transaction(
            &self,
            plan: &crate::TransactionSpacePlan,
        ) -> std::result::Result<(), crate::TransactionReserveError> {
            self.inner.reserve_transaction(plan)
        }
        fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.inner.finish_transaction(group_id, batch_seq)
        }
        fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.inner.cancel_transaction(group_id, batch_seq)
        }

        fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
            self.inner.read_root(slot, out)
        }
        fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
            self.inner.write_root(slot, bytes)
        }
        fn sync_root(&self) -> io::Result<()> {
            self.inner.sync_root()
        }
        fn visit_entries(
            &self,
            visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>,
        ) -> io::Result<()> {
            self.inner.visit_entries(visitor)
        }
        fn exists(&self, file: GroupFile) -> io::Result<bool> {
            self.inner.exists(file)
        }
        fn create(&self, file: GroupFile) -> io::Result<()> {
            self.inner.create(file)
        }
        fn len(&self, file: GroupFile) -> io::Result<u64> {
            self.inner.len(file)
        }
        fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.inner.read(file, at, out)
        }
        fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
            self.inner.write(file, at, bytes)
        }
        fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
            self.inner.set_len(file, length)
        }
        fn sync(&self, file: GroupFile) -> io::Result<()> {
            self.inner.sync(file)
        }
        fn unlink(&self, file: GroupFile) -> io::Result<()> {
            self.inner.unlink(file)
        }
        fn sync_names(&self) -> io::Result<()> {
            self.inner.sync_names()
        }
        fn close(&self) -> BackendCloseOutcome {
            self.closes.fetch_add(1, Ordering::AcqRel);
            self.inner.close()
        }
    }

    #[test]
    fn retained_reader_waits_for_exact_table_range_and_guards_before_restart() {
        let group = InMemoryGroup::new();
        let closes = Arc::new(AtomicUsize::new(0));
        let backend = || ReopenableBackend {
            inner: group.clone(),
            closes: closes.clone(),
        };
        let rows: TableDefinition<&[u8], &[u8]> = TableDefinition::new("held-rows");
        let mut opening = builder().retain_backend(Box::new(backend()), DatabaseOpenMode::Create);
        assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
        let writer = opening.database().unwrap().begin_write().unwrap();
        writer
            .open_table(rows)
            .unwrap()
            .insert(b"key".as_slice(), b"value".as_slice())
            .unwrap();
        writer.commit().unwrap();

        let mut reader = opening.database().unwrap().begin_read_retained().unwrap();
        let table = reader
            .transaction
            .as_ref()
            .unwrap()
            .open_table(rows)
            .unwrap();
        let point = table.get(b"key".as_slice()).unwrap().unwrap();
        assert_eq!(point.value(), b"value");
        let mut range = table.iter().unwrap();
        let (key, value) = range.next().unwrap().unwrap();
        assert_eq!(key.value(), b"key");
        assert_eq!(value.value(), b"value");
        assert_eq!(
            opening.close().settlement(),
            DatabaseOpenSettlement::WaitingForTransactions
        );
        assert_eq!(closes.load(Ordering::Acquire), 0);
        let database = opening.retained_database().unwrap();
        assert_eq!(
            reader.close(database).settlement(),
            ReadCloseSettlement::WaitingForGuards
        );
        assert!(matches!(
            reader.report().release(),
            TerminalObservation::NotEntered
        ));
        assert_eq!(
            reader.dispose_settled(database).settlement(),
            ReadCloseSettlement::WaitingForGuards
        );
        drop(table);
        assert_eq!(
            reader.close(database).settlement(),
            ReadCloseSettlement::WaitingForGuards
        );
        drop(range);
        assert_eq!(
            reader.close(database).settlement(),
            ReadCloseSettlement::WaitingForGuards
        );
        drop(key);
        assert_eq!(
            reader.close(database).settlement(),
            ReadCloseSettlement::WaitingForGuards
        );
        drop(value);
        assert_eq!(
            reader.close(database).settlement(),
            ReadCloseSettlement::WaitingForGuards
        );
        drop(point);
        assert_eq!(
            reader.close(database).settlement(),
            ReadCloseSettlement::Settled
        );
        assert_eq!(
            reader.dispose_settled(database).settlement(),
            ReadCloseSettlement::Disposed
        );
        assert_eq!(opening.close().settlement(), DatabaseOpenSettlement::Closed);
        assert_eq!(closes.load(Ordering::Acquire), 1);

        let mut restarted = builder().retain_backend(
            Box::new(ReopenableBackend {
                inner: group.crash(),
                closes: closes.clone(),
            }),
            DatabaseOpenMode::Existing,
        );
        assert_eq!(restarted.open().settlement(), DatabaseOpenSettlement::Ready);
        let snapshot = restarted.database().unwrap().begin_read().unwrap();
        let table = snapshot.open_table(rows).unwrap();
        assert_eq!(
            table.get(b"key".as_slice()).unwrap().unwrap().value(),
            b"value"
        );
        drop(table);
        drop(snapshot);
        assert_eq!(
            restarted.close().settlement(),
            DatabaseOpenSettlement::Closed
        );
        assert_eq!(closes.load(Ordering::Acquire), 2);
    }

    #[test]
    fn retained_reader_guard_wait_is_per_snapshot_not_database_wide() {
        let mut opening =
            builder().retain_backend(Box::new(InMemoryGroup::new()), DatabaseOpenMode::Create);
        assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
        let rows: TableDefinition<&[u8], &[u8]> = TableDefinition::new("held-rows");
        let writer = opening.database().unwrap().begin_write().unwrap();
        writer.open_table(rows).unwrap();
        writer.commit().unwrap();

        let mut held = opening.database().unwrap().begin_read_retained().unwrap();
        let table = held.transaction.as_ref().unwrap().open_table(rows).unwrap();
        let mut independent = opening.database().unwrap().begin_read_retained().unwrap();
        let database = opening.retained_database().unwrap();
        assert_eq!(
            independent.close(database).settlement(),
            ReadCloseSettlement::Settled
        );
        assert_eq!(
            independent.dispose_settled(database).settlement(),
            ReadCloseSettlement::Disposed
        );
        assert_eq!(
            held.close(database).settlement(),
            ReadCloseSettlement::WaitingForGuards
        );
        drop(table);
        assert_eq!(
            held.close(database).settlement(),
            ReadCloseSettlement::Settled
        );
        assert_eq!(
            held.dispose_settled(database).settlement(),
            ReadCloseSettlement::Disposed
        );
        assert_eq!(opening.close().settlement(), DatabaseOpenSettlement::Closed);
    }

    #[test]
    fn retained_read_disposal_rechecks_a_late_snapshot_descendant() {
        let mut opening =
            builder().retain_backend(Box::new(InMemoryGroup::new()), DatabaseOpenMode::Create);
        assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
        let rows: TableDefinition<&[u8], &[u8]> = TableDefinition::new("held-rows");
        let writer = opening.database().unwrap().begin_write().unwrap();
        writer.open_table(rows).unwrap();
        writer.commit().unwrap();

        let mut reader = opening.database().unwrap().begin_read_retained().unwrap();
        let database = opening.retained_database().unwrap();
        assert_eq!(
            reader.close(database).settlement(),
            ReadCloseSettlement::Settled
        );
        // Private test access simulates a future caller admitting a descendant
        // between the two public retained-operation steps.
        let table = reader
            .transaction
            .as_ref()
            .unwrap()
            .open_table(rows)
            .unwrap();
        assert_eq!(
            reader.dispose_settled(database).settlement(),
            ReadCloseSettlement::WaitingForGuards
        );
        assert!(reader.report().retains_transaction());
        drop(table);
        assert_eq!(
            reader.close(database).settlement(),
            ReadCloseSettlement::Settled
        );
        assert_eq!(
            reader.dispose_settled(database).settlement(),
            ReadCloseSettlement::Disposed
        );
        assert_eq!(opening.close().settlement(), DatabaseOpenSettlement::Closed);
    }

    struct CountedBackend {
        inner: InMemoryGroup,
        closes: Arc<AtomicUsize>,
        native_uncertain: bool,
        entered_would_block: bool,
    }

    impl SegmentGroupBackend for CountedBackend {
        fn reserve_transaction(
            &self,
            plan: &crate::TransactionSpacePlan,
        ) -> std::result::Result<(), crate::TransactionReserveError> {
            self.inner.reserve_transaction(plan)
        }
        fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.inner.finish_transaction(group_id, batch_seq)
        }
        fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.inner.cancel_transaction(group_id, batch_seq)
        }

        fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
            self.inner.read_root(slot, out)
        }
        fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
            self.inner.write_root(slot, bytes)
        }
        fn sync_root(&self) -> io::Result<()> {
            self.inner.sync_root()
        }
        fn visit_entries(
            &self,
            visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>,
        ) -> io::Result<()> {
            self.inner.visit_entries(visitor)
        }
        fn exists(&self, file: GroupFile) -> io::Result<bool> {
            self.inner.exists(file)
        }
        fn create(&self, file: GroupFile) -> io::Result<()> {
            self.inner.create(file)
        }
        fn len(&self, file: GroupFile) -> io::Result<u64> {
            self.inner.len(file)
        }
        fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.inner.read(file, at, out)
        }
        fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
            self.inner.write(file, at, bytes)
        }
        fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
            self.inner.set_len(file, length)
        }
        fn sync(&self, file: GroupFile) -> io::Result<()> {
            self.inner.sync(file)
        }
        fn unlink(&self, file: GroupFile) -> io::Result<()> {
            self.inner.unlink(file)
        }
        fn sync_names(&self) -> io::Result<()> {
            self.inner.sync_names()
        }
        fn close(&self) -> BackendCloseOutcome {
            self.closes.fetch_add(1, Ordering::SeqCst);
            if self.entered_would_block {
                return BackendCloseOutcome::retained(io::ErrorKind::WouldBlock.into());
            }
            if self.native_uncertain {
                BackendCloseOutcome::retained_result(Ok(()))
            } else {
                self.inner.close()
            }
        }
    }

    #[test]
    fn opening_waits_for_the_exact_retained_reader_before_native_close() {
        let mut opening =
            builder().retain_backend(Box::new(InMemoryGroup::new()), DatabaseOpenMode::Create);
        assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
        let mut reader = opening.database().unwrap().begin_read_retained().unwrap();
        assert_eq!(
            opening.close().settlement(),
            DatabaseOpenSettlement::WaitingForTransactions
        );
        let owner = opening.retained_database().unwrap();
        assert_eq!(
            reader.close(owner).settlement(),
            ReadCloseSettlement::Settled
        );
        assert_eq!(
            reader.dispose_settled(owner).settlement(),
            ReadCloseSettlement::Disposed
        );
        assert_eq!(opening.close().settlement(), DatabaseOpenSettlement::Closed);
    }

    #[test]
    fn entered_uncertain_native_close_is_reported_once() {
        let closes = Arc::new(AtomicUsize::new(0));
        let mut opening = builder().retain_backend(
            Box::new(CountedBackend {
                inner: InMemoryGroup::new(),
                closes: closes.clone(),
                native_uncertain: true,
                entered_would_block: false,
            }),
            DatabaseOpenMode::Create,
        );
        assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
        assert_eq!(
            opening.close().settlement(),
            DatabaseOpenSettlement::Retained
        );
        assert_eq!(
            opening.close().settlement(),
            DatabaseOpenSettlement::Retained
        );
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        let report = opening.report();
        let close = report.database_close().unwrap();
        assert!(matches!(
            close.backend(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert_eq!(
            close.native_disposition(),
            BackendNativeDisposition::Retained
        );
    }

    #[test]
    fn entered_would_block_is_terminal_for_retained_and_consuming_close() {
        let retained_calls = Arc::new(AtomicUsize::new(0));
        let mut opening = builder().retain_backend(
            Box::new(CountedBackend {
                inner: InMemoryGroup::new(),
                closes: retained_calls.clone(),
                native_uncertain: false,
                entered_would_block: true,
            }),
            DatabaseOpenMode::Create,
        );
        assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
        assert_eq!(
            opening.close().settlement(),
            DatabaseOpenSettlement::Retained
        );
        let first = match opening.report().database_close().unwrap().backend() {
            TerminalObservation::Returned(Err(StorageError::Io(error))) => {
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                std::ptr::from_ref(error)
            }
            _ => panic!("entered WouldBlock must retain its original outcome"),
        };
        assert_eq!(
            opening.close().settlement(),
            DatabaseOpenSettlement::Retained
        );
        let repeated = match opening.report().database_close().unwrap().backend() {
            TerminalObservation::Returned(Err(StorageError::Io(error))) => {
                std::ptr::from_ref(error)
            }
            _ => panic!("entered WouldBlock outcome was lost"),
        };
        assert_eq!(first, repeated);
        assert_eq!(retained_calls.load(Ordering::SeqCst), 1);

        let consuming_calls = Arc::new(AtomicUsize::new(0));
        let database = builder()
            .create_with_backend(CountedBackend {
                inner: InMemoryGroup::new(),
                closes: consuming_calls.clone(),
                native_uncertain: false,
                entered_would_block: true,
            })
            .unwrap();
        assert!(matches!(
            database.close(),
            Err(crate::tables::CloseError::Storage(_))
        ));
        assert_eq!(consuming_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_construction_still_owns_and_closes_its_original_backend() {
        let closes = Arc::new(AtomicUsize::new(0));
        let backend = InMemoryGroup::new();
        backend
            .write_root(RootSlot::A, &[7; ROOT_SLOT_BYTES])
            .unwrap();
        let mut opening = builder().retain_backend(
            Box::new(CountedBackend {
                inner: backend,
                closes: closes.clone(),
                native_uncertain: false,
                entered_would_block: false,
            }),
            DatabaseOpenMode::Create,
        );
        assert_eq!(
            opening.open().settlement(),
            DatabaseOpenSettlement::Retained
        );
        assert!(matches!(
            opening.report().opening(),
            TerminalObservation::Returned(Err(_))
        ));
        assert_eq!(opening.close().settlement(), DatabaseOpenSettlement::Closed);
        assert_eq!(opening.close().settlement(), DatabaseOpenSettlement::Closed);
        assert_eq!(closes.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
#[path = "transaction_claim_activation_tests.rs"]
mod transaction_claim_activation_tests;

#[path = "retained_source_read.rs"]
mod source_read;
pub use source_read::*;

#[path = "source_funding.rs"]
mod source_funding;
pub use source_funding::*;
