//! Explicit custody for opening, transactions, and physical close.
//!
//! These owners keep the first result of every operation. A failed commit or
//! close is never retried merely because a caller asks for another report.

use crate::core::{
    AdmissionError, AdmittedValue, BackendCloseEntry, BackendCloseOutcome,
    BackendNativeDisposition, CoreError, OwnerFailed, ResidentLease, StorageAdmission,
    StorageBackend,
};
use crate::tables::{
    Builder, CommitError, Database, DatabaseError, ReadTransaction, StorageError, TableDefinition,
    TableError, TransactionError, WriteTransaction,
};
use std::alloc::{Layout, LayoutError};
use std::any::Any;
use std::convert::Infallible;
use std::fmt;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

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
        if self.operation.is_none() {
            self.operation = Some(WriteTerminalOperation::Commit);
            self.settlement = WriteTerminalSettlement::Retained;
            let transaction = self.transaction.as_mut().expect("retained writer");
            self.terminal.run(|| {
                transaction
                    .commit_inner()
                    .map_err(|error| WriteTerminalError::Commit(error.into()))
            });
            if self.terminal.succeeded() {
                self.settlement = WriteTerminalSettlement::Settled;
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
            if self.terminal.succeeded() {
                self.settlement = WriteTerminalSettlement::Settled;
            }
        }
        self.report()
    }

    pub fn dispose_settled(&mut self, database: &RetainedDatabase) -> WriteTerminalReport<'_> {
        if self.settlement == WriteTerminalSettlement::Settled
            && matches!(self.disposal, Attempt::Pending)
            && self
                .transaction
                .as_ref()
                .is_some_and(|transaction| database.owns_writer(transaction))
        {
            self.disposal.run(|| {
                drop(self.transaction.take());
                Ok(())
            });
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
    transaction: Option<ReadTransaction>,
    release: Attempt<StorageError>,
    disposal: Attempt<Infallible>,
    settlement: ReadCloseSettlement,
}

pub struct ReadCloseReport<'a> {
    owner: &'a RetainedReadTransaction,
}

impl ReadCloseReport<'_> {
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
            transaction: Some(self),
            release: Attempt::Pending,
            disposal: Attempt::Pending,
            settlement: ReadCloseSettlement::Open,
        }
    }
}

impl Database {
    pub fn begin_read_retained(&self) -> Result<RetainedReadTransaction, TransactionError> {
        self.begin_read().map(ReadTransaction::retain)
    }
}

impl RetainedReadTransaction {
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
                CoreError::InvalidInput(_) => BoundedReadError::BoundExceeded,
                other => BoundedReadError::Storage(other.into()),
            })
    }

    /// Consult the pinned index without materializing a value or exposing a
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
                CoreError::InvalidInput(_) => BoundedReadError::BoundExceeded,
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
                self.disposal.run(|| {
                    drop(self.transaction.take());
                    Ok(())
                });
                self.settlement = if self.disposal.succeeded() {
                    ReadCloseSettlement::Disposed
                } else {
                    ReadCloseSettlement::DisposalUncertain
                };
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
}

/// The database stays installed even after native closure so diagnostics keep
/// borrowing the original outcome until its enclosing owner is retired.
#[must_use]
pub struct RetainedDatabase {
    database: Option<Database>,
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
}

impl RetainedDatabase {
    fn new(database: Database, admission: Arc<dyn StorageAdmission>) -> Self {
        Self {
            database: Some(database),
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
                .map_err(|_| StorageError::from(CoreError::OwnerFailed))
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

    pub fn dispose_failed(&mut self) -> DatabaseCloseReport<'_> {
        if self.settlement == DatabaseCloseSettlement::DrainedWithFailure {
            self.failed_disposal.run(|| {
                drop(self.database.take());
                Ok(())
            });
            if self.failed_disposal.succeeded() {
                self.settlement = DatabaseCloseSettlement::FailedDisposed;
            } else {
                self.settlement = DatabaseCloseSettlement::Retained;
            }
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
}

struct SharedBackend(Arc<Box<dyn StorageBackend>>);

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

impl StorageBackend for SharedBackend {
    fn len(&self) -> io::Result<u64> {
        self.0.len()
    }

    fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read(at, out)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.0.set_len(len)
    }

    fn sync_data(&self) -> io::Result<()> {
        self.0.sync_data()
    }

    fn write(&self, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.0.write(at, bytes)
    }

    fn close(&self) -> BackendCloseOutcome {
        self.0.close()
    }
}

enum FenceOutcome {
    Returned,
    Unwound(Mutex<Box<dyn Any + Send>>),
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
            Err(payload) => FenceOutcome::Unwound(Mutex::new(payload)),
        };
        let _ = self.fence.set(outcome);
    }
}

pub struct OpeningFenceReport<'a> {
    owner: &'a OpeningAdmission,
}

impl OpeningFenceReport<'_> {
    pub fn observation(&self) -> Option<TerminalObservation<'_, Infallible>> {
        Some(match self.owner.fence.get() {
            None if self.owner.failed.load(Ordering::Acquire) => TerminalObservation::Entered,
            None => TerminalObservation::NotEntered,
            Some(FenceOutcome::Returned) => TerminalObservation::Returned(Ok(())),
            Some(FenceOutcome::Unwound(payload)) => TerminalObservation::Panicked(payload),
        })
    }
}

#[must_use]
pub struct RetainedDatabaseOpening {
    builder: Option<Builder>,
    backend: SharedBackend,
    admission: Arc<OpeningAdmission>,
    mode: DatabaseOpenMode,
    database: Option<RetainedDatabase>,
    phase: DatabaseOpenPhase,
    opening_phase: DatabaseOpenPhase,
    settlement: DatabaseOpenSettlement,
    opening: Attempt<DatabaseError>,
    partial_close: Attempt<StorageError>,
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

    pub fn bootstrap(&self) -> Option<WriteTerminalReport<'_>> {
        None
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

    pub fn partial_close(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.partial_close.view()
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
        let (backend, _) =
            Layout::new::<[AtomicUsize; 2]>().extend(Layout::new::<Box<dyn StorageBackend>>())?;
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
        backend: Box<dyn StorageBackend>,
        mode: DatabaseOpenMode,
    ) -> RetainedDatabaseOpening {
        let admission = Arc::new(OpeningAdmission {
            inner: self.admission(),
            failed: AtomicBool::new(false),
            fence: OnceLock::new(),
        });
        RetainedDatabaseOpening {
            builder: Some(self.with_admission(admission.clone())),
            backend: SharedBackend(Arc::new(backend)),
            admission,
            mode,
            database: None,
            phase: DatabaseOpenPhase::Prepared,
            opening_phase: DatabaseOpenPhase::Prepared,
            settlement: DatabaseOpenSettlement::Prepared,
            opening: Attempt::Pending,
            partial_close: Attempt::Pending,
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
        let builder = self.builder.take().expect("first opening attempt");
        let backend = self.backend.clone();
        let mode = self.mode;
        let mut opened = None;
        self.opening.run(|| {
            let database = match mode {
                // This owner already holds the exact SharedBackend and records
                // its one-shot close. The direct Builder path closes failures
                // itself; doing that here would re-enter the same backend.
                DatabaseOpenMode::Create => builder.create_strict_with_backend_retained(backend),
                DatabaseOpenMode::Existing => builder.open_with_backend_retained(backend),
            }?;
            opened = Some(database);
            Ok(())
        });
        if self.opening.succeeded() {
            self.database =
                opened.map(|database| RetainedDatabase::new(database, self.admission.clone()));
            self.phase = DatabaseOpenPhase::Ready;
            self.opening_phase = self.phase;
            self.settlement = DatabaseOpenSettlement::Ready;
        } else if matches!(self.opening, Attempt::Unwound(_)) {
            self.admission.owner_failed();
        }
        self.report()
    }

    pub fn close(&mut self) -> DatabaseOpenReport<'_> {
        if matches!(
            self.settlement,
            DatabaseOpenSettlement::Closed
                | DatabaseOpenSettlement::DrainedWithFailure
                | DatabaseOpenSettlement::FailedDisposed
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
                DatabaseCloseSettlement::Open | DatabaseCloseSettlement::Retained => {
                    DatabaseOpenSettlement::Retained
                }
            };
        } else if matches!(self.partial_close, Attempt::Pending) {
            let outcome = catch_unwind(AssertUnwindSafe(|| self.backend.close()));
            match outcome {
                Ok(outcome) => {
                    self.partial_native = outcome.native_disposition();
                    if outcome.entry() == BackendCloseEntry::NotEntered {
                        self.settlement = DatabaseOpenSettlement::WaitingForTransactions;
                        return self.report();
                    }
                    self.partial_close =
                        Attempt::Done(outcome.into_result().map_err(StorageError::Io));
                    self.settlement = match (&self.partial_close, self.partial_native) {
                        (Attempt::Done(Ok(())), BackendNativeDisposition::Drained) => {
                            DatabaseOpenSettlement::Closed
                        }
                        (Attempt::Done(Err(_)), BackendNativeDisposition::Drained) => {
                            DatabaseOpenSettlement::DrainedWithFailure
                        }
                        _ => DatabaseOpenSettlement::Retained,
                    };
                }
                Err(payload) => {
                    self.partial_close = Attempt::Unwound(payload);
                    self.settlement = DatabaseOpenSettlement::Retained;
                }
            }
        }
        if matches!(
            self.settlement,
            DatabaseOpenSettlement::Retained | DatabaseOpenSettlement::DrainedWithFailure
        ) {
            self.admission.owner_failed();
        }
        self.report()
    }

    pub fn dispose_failed(&mut self) -> DatabaseOpenReport<'_> {
        if self.settlement != DatabaseOpenSettlement::DrainedWithFailure {
            return self.report();
        }
        self.settlement = DatabaseOpenSettlement::Retained;
        if let Some(database) = self.database.as_mut()
            && database.dispose_failed().settlement() != DatabaseCloseSettlement::FailedDisposed
        {
            return self.report();
        }
        self.failed_disposal.run(|| Ok(()));
        if self.failed_disposal.succeeded() {
            self.settlement = DatabaseOpenSettlement::FailedDisposed;
        }
        self.report()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::InMemoryBackend;

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
    }

    fn builder() -> Builder {
        Database::builder(Arc::new(Permit))
    }

    #[test]
    fn retained_index_existence_observes_exact_snapshot_and_tombstones() {
        let rows: TableDefinition<&[u8], &[u8]> = TableDefinition::new("index-only-rows");
        let mut opening =
            builder().retain_backend(Box::new(InMemoryBackend::new()), DatabaseOpenMode::Create);
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
        bytes: Arc<Mutex<Vec<u8>>>,
        closes: Arc<AtomicUsize>,
    }

    impl StorageBackend for ReopenableBackend {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.lock().unwrap().len() as u64)
        }

        fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let bytes = self.bytes.lock().unwrap();
            let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
            let end = start
                .checked_add(out.len())
                .ok_or(io::ErrorKind::InvalidInput)?;
            out.copy_from_slice(bytes.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
            Ok(())
        }

        fn write(&self, at: u64, input: &[u8]) -> io::Result<()> {
            let mut bytes = self.bytes.lock().unwrap();
            let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
            let end = start
                .checked_add(input.len())
                .ok_or(io::ErrorKind::InvalidInput)?;
            bytes
                .get_mut(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?
                .copy_from_slice(input);
            Ok(())
        }

        fn set_len(&self, length: u64) -> io::Result<()> {
            self.bytes.lock().unwrap().resize(
                usize::try_from(length).map_err(|_| io::ErrorKind::InvalidInput)?,
                0,
            );
            Ok(())
        }

        fn sync_data(&self) -> io::Result<()> {
            Ok(())
        }

        fn close(&self) -> BackendCloseOutcome {
            self.closes.fetch_add(1, Ordering::AcqRel);
            BackendCloseOutcome::drained(Ok(()))
        }
    }

    #[test]
    fn retained_reader_waits_for_exact_table_range_and_guards_before_restart() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let closes = Arc::new(AtomicUsize::new(0));
        let backend = || ReopenableBackend {
            bytes: bytes.clone(),
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

        let mut restarted =
            builder().retain_backend(Box::new(backend()), DatabaseOpenMode::Existing);
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
            builder().retain_backend(Box::new(InMemoryBackend::new()), DatabaseOpenMode::Create);
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
            builder().retain_backend(Box::new(InMemoryBackend::new()), DatabaseOpenMode::Create);
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
        inner: InMemoryBackend,
        closes: Arc<AtomicUsize>,
        native_uncertain: bool,
        entered_would_block: bool,
    }

    impl StorageBackend for CountedBackend {
        fn len(&self) -> io::Result<u64> {
            self.inner.len()
        }

        fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.inner.read(at, out)
        }

        fn set_len(&self, len: u64) -> io::Result<()> {
            self.inner.set_len(len)
        }

        fn sync_data(&self) -> io::Result<()> {
            self.inner.sync_data()
        }

        fn write(&self, at: u64, bytes: &[u8]) -> io::Result<()> {
            self.inner.write(at, bytes)
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
            builder().retain_backend(Box::new(InMemoryBackend::new()), DatabaseOpenMode::Create);
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
                inner: InMemoryBackend::new(),
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
                inner: InMemoryBackend::new(),
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
                inner: InMemoryBackend::new(),
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
        let backend = InMemoryBackend::new();
        backend.set_len(1).unwrap();
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
