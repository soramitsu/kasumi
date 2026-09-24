use crate::io;
use crate::sync::PoisonError;
use crate::tree_store::{FILE_FORMAT_VERSION4, MAX_VALUE_LENGTH};
use crate::{ReadTransaction, TypeName};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use core::fmt::{Display, Formatter};
use core::panic;

/// General errors directly from the storage layer
#[derive(Debug)]
#[non_exhaustive]
pub enum StorageError {
    /// The installed owner denied growth before any physical mutation.
    CapacityDenied,
    /// Cache entry capacity was exhausted before creating a new cached page.
    CacheCapacityDenied,
    /// A page-list record does not have the canonical writer shape or count.
    InvalidPageList,
    /// The canonical system namespace contains an explicitly forbidden old table.
    ObsoleteSystemTable,
    /// Physical ownership or I/O is uncertain; drain and census before reopening.
    OwnerFailed,
    /// The Database is corrupted
    Corrupted(String),
    /// The value being inserted exceeds the maximum of 3GiB
    ValueTooLarge(usize),
    /// The key does not sort strictly between the entries adjacent to the cursor
    #[cfg(feature = "experimental_cursor")]
    UnorderedKey,
    Io(io::Error),
    PreviousIo,
    DatabaseClosed,
    LockPoisoned(&'static panic::Location<'static>),
}

impl<T> From<PoisonError<T>> for StorageError {
    fn from(_: PoisonError<T>) -> StorageError {
        StorageError::LockPoisoned(panic::Location::caller())
    }
}

impl From<io::Error> for StorageError {
    fn from(err: io::Error) -> StorageError {
        StorageError::Io(err)
    }
}

impl From<StorageError> for Error {
    fn from(err: StorageError) -> Error {
        match err {
            StorageError::CapacityDenied => Error::CapacityDenied,
            StorageError::CacheCapacityDenied => Error::CacheCapacityDenied,
            StorageError::InvalidPageList => Error::InvalidPageList,
            StorageError::ObsoleteSystemTable => Error::ObsoleteSystemTable,
            StorageError::OwnerFailed => Error::OwnerFailed,
            StorageError::Corrupted(msg) => Error::Corrupted(msg),
            StorageError::ValueTooLarge(x) => Error::ValueTooLarge(x),
            #[cfg(feature = "experimental_cursor")]
            StorageError::UnorderedKey => Error::UnorderedKey,
            StorageError::Io(x) => Error::Io(x),
            StorageError::PreviousIo => Error::PreviousIo,
            StorageError::DatabaseClosed => Error::DatabaseClosed,
            StorageError::LockPoisoned(location) => Error::LockPoisoned(location),
        }
    }
}

impl Display for StorageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            StorageError::CapacityDenied => write!(f, "installed storage capacity denied"),
            StorageError::CacheCapacityDenied => write!(f, "cache entry capacity denied"),
            StorageError::InvalidPageList => write!(f, "invalid canonical page-list record"),
            StorageError::ObsoleteSystemTable => write!(f, "obsolete system table is forbidden"),
            StorageError::OwnerFailed => write!(f, "installed storage owner failed"),
            StorageError::Corrupted(msg) => {
                write!(f, "DB corrupted: {msg}")
            }
            StorageError::ValueTooLarge(len) => {
                write!(
                    f,
                    "The value (length={len}) being inserted exceeds the maximum of {}GiB",
                    MAX_VALUE_LENGTH / 1024 / 1024 / 1024
                )
            }
            #[cfg(feature = "experimental_cursor")]
            StorageError::UnorderedKey => {
                write!(
                    f,
                    "The key does not sort strictly between the entries adjacent to the cursor"
                )
            }
            StorageError::Io(err) => {
                write!(f, "I/O error: {err}")
            }
            StorageError::DatabaseClosed => {
                write!(f, "Database has been closed")
            }
            StorageError::PreviousIo => {
                write!(
                    f,
                    "Previous I/O error occurred. Please close and re-open the database."
                )
            }
            StorageError::LockPoisoned(location) => {
                write!(f, "Poisoned internal lock: {location}")
            }
        }
    }
}

impl core::error::Error for StorageError {}

/// Errors related to opening tables
#[derive(Debug)]
#[non_exhaustive]
pub enum TableError {
    /// Table types didn't match.
    TableTypeMismatch {
        table: String,
        key: TypeName,
        value: TypeName,
    },
    /// The table is a multimap table
    TableIsMultimap(String),
    /// The table is not a multimap table
    TableIsNotMultimap(String),
    TypeDefinitionChanged {
        name: TypeName,
        alignment: usize,
        width: Option<usize>,
    },
    /// Table name does not match any table in database
    TableDoesNotExist(String),
    /// Table name already exists in the database
    TableExists(String),
    // Tables cannot be opened for writing multiple times, since they could retrieve immutable &
    // mutable references to the same dirty pages, or multiple mutable references via insert_reserve()
    TableAlreadyOpen(String, &'static panic::Location<'static>),
    /// Error from underlying storage
    Storage(StorageError),
}

impl TableError {
    pub(crate) fn into_storage_error_or_corrupted(self, msg: &str) -> StorageError {
        match self {
            TableError::TableTypeMismatch { .. }
            | TableError::TableIsMultimap(_)
            | TableError::TableIsNotMultimap(_)
            | TableError::TypeDefinitionChanged { .. }
            | TableError::TableDoesNotExist(_)
            | TableError::TableExists(_)
            | TableError::TableAlreadyOpen(_, _) => {
                StorageError::Corrupted(format!("{msg}: {self}"))
            }
            TableError::Storage(storage) => storage,
        }
    }
}

impl From<TableError> for Error {
    fn from(err: TableError) -> Error {
        match err {
            TableError::TypeDefinitionChanged {
                name,
                alignment,
                width,
            } => Error::TypeDefinitionChanged {
                name,
                alignment,
                width,
            },
            TableError::TableTypeMismatch { table, key, value } => {
                Error::TableTypeMismatch { table, key, value }
            }
            TableError::TableIsMultimap(table) => Error::TableIsMultimap(table),
            TableError::TableIsNotMultimap(table) => Error::TableIsNotMultimap(table),
            TableError::TableDoesNotExist(table) => Error::TableDoesNotExist(table),
            TableError::TableExists(table) => Error::TableExists(table),
            TableError::TableAlreadyOpen(name, location) => Error::TableAlreadyOpen(name, location),
            TableError::Storage(storage) => storage.into(),
        }
    }
}

impl From<StorageError> for TableError {
    fn from(err: StorageError) -> TableError {
        TableError::Storage(err)
    }
}

impl Display for TableError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            TableError::TypeDefinitionChanged {
                name,
                alignment,
                width,
            } => {
                write!(
                    f,
                    "Current definition of {} does not match stored definition (width={:?}, alignment={})",
                    name.name(),
                    width,
                    alignment,
                )
            }
            TableError::TableTypeMismatch { table, key, value } => {
                write!(
                    f,
                    "{table} is of type Table<{}, {}>",
                    key.name(),
                    value.name(),
                )
            }
            TableError::TableIsMultimap(table) => {
                write!(f, "{table} is a multimap table")
            }
            TableError::TableIsNotMultimap(table) => {
                write!(f, "{table} is not a multimap table")
            }
            TableError::TableDoesNotExist(table) => {
                write!(f, "Table '{table}' does not exist")
            }
            TableError::TableExists(table) => {
                write!(f, "Table '{table}' already exists")
            }
            TableError::TableAlreadyOpen(name, location) => {
                write!(f, "Table '{name}' already opened at: {location}")
            }
            TableError::Storage(storage) => storage.fmt(f),
        }
    }
}

impl core::error::Error for TableError {}

/// Errors related to opening a database
#[derive(Debug)]
#[non_exhaustive]
pub enum DatabaseError {
    /// The Database is already open. Cannot acquire lock.
    DatabaseAlreadyOpen,
    /// [`crate::RepairSession::abort`] was called or repair was aborted for another reason (such as the database being read-only).
    RepairAborted,
    /// The database file does not use this build's sole canonical format
    UnsupportedFileFormat(u8),
    /// A transaction is still in-progress
    TransactionInProgress,
    /// Error from underlying storage
    Storage(StorageError),
}

impl From<DatabaseError> for Error {
    fn from(err: DatabaseError) -> Error {
        match err {
            DatabaseError::DatabaseAlreadyOpen => Error::DatabaseAlreadyOpen,
            DatabaseError::RepairAborted => Error::RepairAborted,
            DatabaseError::UnsupportedFileFormat(x) => Error::UnsupportedFileFormat(x),
            DatabaseError::TransactionInProgress => Error::TransactionInProgress,
            DatabaseError::Storage(storage) => storage.into(),
        }
    }
}

impl From<io::Error> for DatabaseError {
    fn from(err: io::Error) -> DatabaseError {
        DatabaseError::Storage(StorageError::Io(err))
    }
}

impl From<StorageError> for DatabaseError {
    fn from(err: StorageError) -> DatabaseError {
        DatabaseError::Storage(err)
    }
}

impl Display for DatabaseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            DatabaseError::UnsupportedFileFormat(actual) => {
                write!(
                    f,
                    "Unsupported file format {actual}; this build requires canonical format {FILE_FORMAT_VERSION4}"
                )
            }
            DatabaseError::RepairAborted => {
                write!(f, "Database repair aborted.")
            }
            DatabaseError::DatabaseAlreadyOpen => {
                write!(f, "Database already open. Cannot acquire lock.")
            }
            DatabaseError::TransactionInProgress => {
                write!(
                    f,
                    "A transaction is still in progress. Operation cannot be performed."
                )
            }
            DatabaseError::Storage(storage) => storage.fmt(f),
        }
    }
}

impl core::error::Error for DatabaseError {}

/// Errors related to savepoints
#[derive(Debug)]
#[non_exhaustive]
pub enum SavepointError {
    /// This savepoint is invalid or cannot be created.
    ///
    /// Savepoints become invalid when an older savepoint is restored after it was created,
    /// and savepoints cannot be created if the transaction is "dirty" (any tables have been opened)
    InvalidSavepoint,
    /// Error from underlying storage
    Storage(StorageError),
}

impl From<SavepointError> for Error {
    fn from(err: SavepointError) -> Error {
        match err {
            SavepointError::InvalidSavepoint => Error::InvalidSavepoint,
            SavepointError::Storage(storage) => storage.into(),
        }
    }
}

impl From<StorageError> for SavepointError {
    fn from(err: StorageError) -> SavepointError {
        SavepointError::Storage(err)
    }
}

impl Display for SavepointError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            SavepointError::InvalidSavepoint => {
                write!(f, "Savepoint is invalid or cannot be created.")
            }
            SavepointError::Storage(storage) => storage.fmt(f),
        }
    }
}

impl core::error::Error for SavepointError {}

/// Errors related to compaction
#[derive(Debug)]
#[non_exhaustive]
pub enum CompactionError {
    /// A persistent savepoint exists
    PersistentSavepointExists,
    /// A ephemeral savepoint exists
    EphemeralSavepointExists,
    /// A transaction is still in-progress
    TransactionInProgress,
    /// Error from underlying storage
    Storage(StorageError),
}

impl From<CompactionError> for Error {
    fn from(err: CompactionError) -> Error {
        match err {
            CompactionError::PersistentSavepointExists => Error::PersistentSavepointExists,
            CompactionError::EphemeralSavepointExists => Error::EphemeralSavepointExists,
            CompactionError::TransactionInProgress => Error::TransactionInProgress,
            CompactionError::Storage(storage) => storage.into(),
        }
    }
}

impl From<StorageError> for CompactionError {
    fn from(err: StorageError) -> CompactionError {
        CompactionError::Storage(err)
    }
}

impl Display for CompactionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            CompactionError::PersistentSavepointExists => {
                write!(
                    f,
                    "Persistent savepoint exists. Operation cannot be performed."
                )
            }
            CompactionError::EphemeralSavepointExists => {
                write!(
                    f,
                    "Ephemeral savepoint exists. Operation cannot be performed."
                )
            }
            CompactionError::TransactionInProgress => {
                write!(
                    f,
                    "A transaction is still in progress. Operation cannot be performed."
                )
            }
            CompactionError::Storage(storage) => storage.fmt(f),
        }
    }
}

impl core::error::Error for CompactionError {}

/// Errors related to transactions
#[derive(Debug)]
#[non_exhaustive]
pub enum TransactionError {
    /// Error from underlying storage
    Storage(StorageError),
    /// The transaction is still referenced by a table or other object
    ReadTransactionStillInUse(Box<ReadTransaction>),
}

impl TransactionError {
    pub(crate) fn into_storage_error(self) -> StorageError {
        match self {
            TransactionError::Storage(storage) => storage,
            _ => unreachable!(),
        }
    }
}

impl From<TransactionError> for Error {
    fn from(err: TransactionError) -> Error {
        match err {
            TransactionError::Storage(storage) => storage.into(),
            TransactionError::ReadTransactionStillInUse(txn) => {
                Error::ReadTransactionStillInUse(txn)
            }
        }
    }
}

impl From<StorageError> for TransactionError {
    fn from(err: StorageError) -> TransactionError {
        TransactionError::Storage(err)
    }
}

impl Display for TransactionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            TransactionError::Storage(storage) => storage.fmt(f),
            TransactionError::ReadTransactionStillInUse(_) => {
                write!(f, "Transaction still in use")
            }
        }
    }
}

impl core::error::Error for TransactionError {}

/// Errors related to committing transactions
#[derive(Debug)]
#[non_exhaustive]
pub enum CommitError {
    /// Error from underlying storage
    Storage(StorageError),
    /// The transaction was poisoned by a panic and can no longer be committed
    TransactionPoisoned,
}

impl CommitError {
    pub(crate) fn into_storage_error(self) -> StorageError {
        match self {
            CommitError::Storage(storage) => storage,
            CommitError::TransactionPoisoned => unreachable!(),
        }
    }
}

impl From<CommitError> for Error {
    fn from(err: CommitError) -> Error {
        match err {
            CommitError::Storage(storage) => storage.into(),
            CommitError::TransactionPoisoned => Error::TransactionPoisoned,
        }
    }
}

impl From<StorageError> for CommitError {
    fn from(err: StorageError) -> CommitError {
        CommitError::Storage(err)
    }
}

impl Display for CommitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            CommitError::Storage(storage) => storage.fmt(f),
            CommitError::TransactionPoisoned => {
                write!(f, "Transaction was poisoned by a panic")
            }
        }
    }
}

impl core::error::Error for CommitError {}

/// Superset of all other errors that can occur. Convenience enum so that users can convert all errors into a single type
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A page-list record does not have the canonical writer shape or count.
    InvalidPageList,
    /// The canonical system namespace contains an explicitly forbidden old table.
    ObsoleteSystemTable,
    CapacityDenied,
    /// Cache entry capacity was exhausted before creating a new cached page.
    CacheCapacityDenied,
    OwnerFailed,
    /// The Database is already open. Cannot acquire lock.
    DatabaseAlreadyOpen,
    /// This savepoint is invalid or cannot be created.
    ///
    /// Savepoints become invalid when an older savepoint is restored after it was created,
    /// and savepoints cannot be created if the transaction is "dirty" (any tables have been opened)
    InvalidSavepoint,
    /// [`crate::RepairSession::abort`] was called.
    RepairAborted,
    /// A persistent savepoint exists
    PersistentSavepointExists,
    /// An Ephemeral savepoint exists
    EphemeralSavepointExists,
    /// A transaction is still in-progress
    TransactionInProgress,
    /// The transaction was poisoned by a panic and can no longer be committed
    TransactionPoisoned,
    /// The Database is corrupted
    Corrupted(String),
    /// The database file does not use this build's sole canonical format
    UnsupportedFileFormat(u8),
    /// The value being inserted exceeds the maximum of 3GiB
    ValueTooLarge(usize),
    /// The key does not sort strictly between the entries adjacent to the cursor
    #[cfg(feature = "experimental_cursor")]
    UnorderedKey,
    /// Table types didn't match.
    TableTypeMismatch {
        table: String,
        key: TypeName,
        value: TypeName,
    },
    /// The table is a multimap table
    TableIsMultimap(String),
    /// The table is not a multimap table
    TableIsNotMultimap(String),
    TypeDefinitionChanged {
        name: TypeName,
        alignment: usize,
        width: Option<usize>,
    },
    /// Table name does not match any table in database
    TableDoesNotExist(String),
    /// Table name already exists in the database
    TableExists(String),
    // Tables cannot be opened for writing multiple times, since they could retrieve immutable &
    // mutable references to the same dirty pages, or multiple mutable references via insert_reserve()
    TableAlreadyOpen(String, &'static panic::Location<'static>),
    Io(io::Error),
    DatabaseClosed,
    /// A previous IO error occurred. The database must be closed and re-opened
    PreviousIo,
    LockPoisoned(&'static panic::Location<'static>),
    /// The transaction is still referenced by a table or other object
    ReadTransactionStillInUse(Box<ReadTransaction>),
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Error {
        Error::LockPoisoned(panic::Location::caller())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::CapacityDenied => write!(f, "installed storage capacity denied"),
            Error::CacheCapacityDenied => write!(f, "cache entry capacity denied"),
            Error::InvalidPageList => write!(f, "invalid canonical page-list record"),
            Error::ObsoleteSystemTable => write!(f, "obsolete system table is forbidden"),
            Error::OwnerFailed => write!(f, "installed storage owner failed"),
            Error::Corrupted(msg) => {
                write!(f, "DB corrupted: {msg}")
            }
            Error::UnsupportedFileFormat(actual) => {
                write!(
                    f,
                    "Unsupported file format {actual}; this build requires canonical format {FILE_FORMAT_VERSION4}"
                )
            }
            Error::ValueTooLarge(len) => {
                write!(
                    f,
                    "The value (length={len}) being inserted exceeds the maximum of {}GiB",
                    MAX_VALUE_LENGTH / 1024 / 1024 / 1024
                )
            }
            #[cfg(feature = "experimental_cursor")]
            Error::UnorderedKey => {
                write!(
                    f,
                    "The key does not sort strictly between the entries adjacent to the cursor"
                )
            }
            Error::TypeDefinitionChanged {
                name,
                alignment,
                width,
            } => {
                write!(
                    f,
                    "Current definition of {} does not match stored definition (width={:?}, alignment={})",
                    name.name(),
                    width,
                    alignment,
                )
            }
            Error::TableTypeMismatch { table, key, value } => {
                write!(
                    f,
                    "{table} is of type Table<{}, {}>",
                    key.name(),
                    value.name(),
                )
            }
            Error::TableIsMultimap(table) => {
                write!(f, "{table} is a multimap table")
            }
            Error::TableIsNotMultimap(table) => {
                write!(f, "{table} is not a multimap table")
            }
            Error::TableDoesNotExist(table) => {
                write!(f, "Table '{table}' does not exist")
            }
            Error::TableExists(table) => {
                write!(f, "Table '{table}' already exists")
            }
            Error::TableAlreadyOpen(name, location) => {
                write!(f, "Table '{name}' already opened at: {location}")
            }
            Error::Io(err) => {
                write!(f, "I/O error: {err}")
            }
            Error::DatabaseClosed => {
                write!(f, "Database has been closed")
            }
            Error::PreviousIo => {
                write!(
                    f,
                    "Previous I/O error occurred. Please close and re-open the database."
                )
            }
            Error::LockPoisoned(location) => {
                write!(f, "Poisoned internal lock: {location}")
            }
            Error::DatabaseAlreadyOpen => {
                write!(f, "Database already open. Cannot acquire lock.")
            }
            Error::RepairAborted => {
                write!(f, "Database repair aborted.")
            }
            Error::PersistentSavepointExists => {
                write!(
                    f,
                    "Persistent savepoint exists. Operation cannot be performed."
                )
            }
            Error::EphemeralSavepointExists => {
                write!(
                    f,
                    "Ephemeral savepoint exists. Operation cannot be performed."
                )
            }
            Error::TransactionInProgress => {
                write!(
                    f,
                    "A transaction is still in progress. Operation cannot be performed."
                )
            }
            Error::TransactionPoisoned => {
                write!(f, "Transaction was poisoned by a panic")
            }
            Error::InvalidSavepoint => {
                write!(f, "Savepoint is invalid or cannot be created.")
            }
            Error::ReadTransactionStillInUse(_) => {
                write!(f, "Transaction still in use")
            }
        }
    }
}

impl core::error::Error for Error {}

impl From<crate::OwnerFailed> for StorageError {
    fn from(_: crate::OwnerFailed) -> Self {
        Self::OwnerFailed
    }
}
impl From<crate::AdmissionError> for StorageError {
    fn from(error: crate::AdmissionError) -> Self {
        match error {
            crate::AdmissionError::CapacityDenied => Self::CapacityDenied,
            crate::AdmissionError::OwnerFailed => Self::OwnerFailed,
        }
    }
}

#[derive(Debug)]
pub enum CloseError<T> {
    Busy(T),
    Storage(StorageError),
}
impl<T> Display for CloseError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Busy(_) => write!(f, "database transactions are still live"),
            Self::Storage(error) => error.fmt(f),
        }
    }
}
impl<T: core::fmt::Debug> core::error::Error for CloseError<T> {}
