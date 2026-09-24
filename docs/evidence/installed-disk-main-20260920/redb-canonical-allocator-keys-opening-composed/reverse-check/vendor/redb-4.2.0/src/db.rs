#[cfg(all(not(redb_no_std), panic = "unwind"))]
#[path = "retained_opening.rs"]
mod retained_opening;
#[cfg(all(not(redb_no_std), panic = "unwind"))]
pub use retained_opening::{
    DatabaseOpenMode, DatabaseOpenPhase, DatabaseOpenReport, DatabaseOpenSettlement,
    OpeningFenceReport, RetainedDatabaseOpening,
};

#[cfg(all(not(redb_no_std), panic = "unwind"))]
#[path = "retained_database.rs"]
mod retained_database;
#[cfg(all(not(redb_no_std), panic = "unwind"))]
pub use retained_database::{DatabaseCloseReport, DatabaseCloseSettlement, RetainedDatabase};

use crate::io;
use crate::transaction_tracker::{TransactionId, TransactionTracker};
#[cfg(not(redb_no_std))]
use crate::tree_store::ReadOnlyBackend;
use crate::tree_store::{
    AllocationPolicy, BtreeHeader, InternalTableDefinition, PAGE_SIZE, PageHint, PageNumber,
    PageResolver, ShrinkPolicy, TableTree, TableType, TransactionalMemory,
};
use crate::types::{Key, Value};
use crate::{
    CompactionError, DatabaseError, ReadOnlyTable, ReadableTable, SavepointError, StorageError,
    TableError,
};
use crate::{ReadTransaction, Result, WriteTransaction};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use core::fmt::{Debug, Display, Formatter};

use alloc::sync::Arc;
use core::marker::PhantomData;
#[cfg(not(redb_no_std))]
use std::fs::{File, OpenOptions};
#[cfg(not(redb_no_std))]
use std::path::Path;

use crate::error::TransactionError;
use crate::sealed::{Sealed, SealedInApi5};
use crate::transactions::{
    ALLOCATOR_STATE_TABLE_NAME, AllocatorStateKey, AllocatorStateTree, DATA_ALLOCATED_TABLE,
    DATA_FREED_TABLE, OBSOLETE_SYSTEM_FREED_TABLE_NAME, PageList, TransactionIdWithPagination,
};
#[cfg(not(redb_no_std))]
use crate::tree_store::file_backend::FileBackend;
#[cfg(feature = "logging")]
use log::{debug, warn};

#[allow(clippy::len_without_is_empty)]
/// Implements persistent storage for a database.
///
/// Failures are reported as [`io::Error`], which is [`std::io::Error`] whenever std is available.
/// `write`, `sync_data`, `len`, shrinking `set_len`, and `close` can run after a
/// winning header or during destruction and must not allocate. Their failures
/// fence the installed physical owner. `close` is called exactly once.
pub trait StorageBackend: 'static + Debug + Send + Sync {
    /// Gets the current length of the storage.
    fn len(&self) -> core::result::Result<u64, io::Error>;

    /// Reads the specified array of bytes from the storage.
    ///
    /// If `out.len()` + `offset` exceeds the length of the storage an appropriate `Error` must be returned.
    fn read(&self, offset: u64, out: &mut [u8]) -> core::result::Result<(), io::Error>;

    /// Sets the length of the storage.
    ///
    /// New positions in the storage must be initialized to zero.
    fn set_len(&self, len: u64) -> core::result::Result<(), io::Error>;

    /// Syncs all buffered data with the persistent storage.
    fn sync_data(&self) -> core::result::Result<(), io::Error>;

    /// Writes the specified array to the storage.
    fn write(&self, offset: u64, data: &[u8]) -> core::result::Result<(), io::Error>;

    /// Release any resources held by the backend
    ///
    /// Note: redb will not access the backend after calling this method and will call it exactly
    /// once: when the [`Database`] is dropped, or, if a [`WriteTransaction`] was live at that
    /// point, when that transaction completes, or if opening the database fails
    fn close(&self) -> core::result::Result<(), io::Error> {
        Ok(())
    }
}

pub trait TableHandle: Sealed {
    // Returns the name of the table
    fn name(&self) -> &str;
}

#[derive(Clone)]
pub struct UntypedTableHandle {
    name: String,
}

impl UntypedTableHandle {
    pub(crate) fn new(name: String) -> Self {
        Self { name }
    }
}

impl TableHandle for UntypedTableHandle {
    fn name(&self) -> &str {
        &self.name
    }
}

impl Sealed for UntypedTableHandle {}

pub trait MultimapTableHandle: Sealed {
    // Returns the name of the multimap table
    fn name(&self) -> &str;
}

#[derive(Clone)]
pub struct UntypedMultimapTableHandle {
    name: String,
}

impl UntypedMultimapTableHandle {
    pub(crate) fn new(name: String) -> Self {
        Self { name }
    }
}

impl MultimapTableHandle for UntypedMultimapTableHandle {
    fn name(&self) -> &str {
        &self.name
    }
}

impl Sealed for UntypedMultimapTableHandle {}

/// Defines the name and types of a table
///
/// A [`TableDefinition`] should be opened for use by calling [`ReadTransaction::open_table`] or [`WriteTransaction::open_table`]
///
/// Note that the lifetime of the `K` and `V` type parameters does not impact the lifetimes of the data
/// that is stored or retreived from the table
pub struct TableDefinition<'a, K: Key + 'static, V: Value + 'static> {
    name: &'a str,
    _key_type: PhantomData<K>,
    _value_type: PhantomData<V>,
}

impl<'a, K: Key + 'static, V: Value + 'static> TableDefinition<'a, K, V> {
    /// Construct a new table with given `name`
    ///
    /// # Panics
    ///
    /// Panics if `name` is empty. When `name` is a non-empty string literal
    /// this is checked at compile time, but callers that build the name at
    /// runtime are responsible for ensuring it is non-empty.
    pub const fn new(name: &'a str) -> Self {
        assert!(!name.is_empty());
        Self {
            name,
            _key_type: PhantomData,
            _value_type: PhantomData,
        }
    }
}

impl<K: Key + 'static, V: Value + 'static> TableHandle for TableDefinition<'_, K, V> {
    fn name(&self) -> &str {
        self.name
    }
}

impl<K: Key, V: Value> Sealed for TableDefinition<'_, K, V> {}

impl<K: Key + 'static, V: Value + 'static> Clone for TableDefinition<'_, K, V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: Key + 'static, V: Value + 'static> Copy for TableDefinition<'_, K, V> {}

impl<K: Key + 'static, V: Value + 'static> Display for TableDefinition<'_, K, V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}<{}, {}>",
            self.name,
            K::type_name().name(),
            V::type_name().name()
        )
    }
}

/// Defines the name and types of a multimap table
///
/// A [`MultimapTableDefinition`] should be opened for use by calling [`ReadTransaction::open_multimap_table`] or [`WriteTransaction::open_multimap_table`]
///
/// [Multimap tables](https://en.wikipedia.org/wiki/Multimap) may have multiple values associated with each key
///
/// Note that the lifetime of the `K` and `V` type parameters does not impact the lifetimes of the data
/// that is stored or retreived from the table
pub struct MultimapTableDefinition<'a, K: Key + 'static, V: Key + 'static> {
    name: &'a str,
    _key_type: PhantomData<K>,
    _value_type: PhantomData<V>,
}

impl<'a, K: Key + 'static, V: Key + 'static> MultimapTableDefinition<'a, K, V> {
    /// Construct a new multimap table with given `name`
    ///
    /// # Panics
    ///
    /// Panics if `name` is empty. When `name` is a non-empty string literal
    /// this is checked at compile time, but callers that build the name at
    /// runtime are responsible for ensuring it is non-empty.
    pub const fn new(name: &'a str) -> Self {
        assert!(!name.is_empty());
        Self {
            name,
            _key_type: PhantomData,
            _value_type: PhantomData,
        }
    }
}

impl<K: Key + 'static, V: Key + 'static> MultimapTableHandle for MultimapTableDefinition<'_, K, V> {
    fn name(&self) -> &str {
        self.name
    }
}

impl<K: Key, V: Key> Sealed for MultimapTableDefinition<'_, K, V> {}

impl<K: Key + 'static, V: Key + 'static> Clone for MultimapTableDefinition<'_, K, V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: Key + 'static, V: Key + 'static> Copy for MultimapTableDefinition<'_, K, V> {}

impl<K: Key + 'static, V: Key + 'static> Display for MultimapTableDefinition<'_, K, V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}<{}, {}>",
            self.name,
            K::type_name().name(),
            V::type_name().name()
        )
    }
}

/// Information regarding the usage of the in-memory cache
///
/// Note: these metrics are only collected when the "`cache_metrics`" feature is enabled
#[derive(Debug)]
pub struct CacheStats {
    pub(crate) evictions: u64,
    pub(crate) read_hits: u64,
    pub(crate) read_misses: u64,
    pub(crate) write_hits: u64,
    pub(crate) write_misses: u64,
    pub(crate) used_bytes: usize,
}

impl CacheStats {
    /// Number of times that data has been evicted, due to the cache being full
    ///
    /// To increase the cache size use [`Builder::set_cache_size`]
    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    /// Number of times that unmodified data has been read from the cache
    pub fn read_hits(&self) -> u64 {
        self.read_hits
    }

    /// Number of times that unmodified data was not in the cache and was read from storage
    pub fn read_misses(&self) -> u64 {
        self.read_misses
    }

    /// Number of times that data modified in a transaction has been read from the cache
    pub fn write_hits(&self) -> u64 {
        self.write_hits
    }

    /// Number of times that data modified in a transaction was not in the cache and was read from storage
    pub fn write_misses(&self) -> u64 {
        self.write_misses
    }

    /// Number of bytes in the cache
    pub fn used_bytes(&self) -> usize {
        self.used_bytes
    }
}

pub(crate) enum TransactionGuard {
    Read {
        tracker: Arc<TransactionTracker>,
        transaction_id: TransactionId,
    },
    Write {
        tracker: Arc<TransactionTracker>,
        transaction_id: TransactionId,
    },
    // Used for internal accesses that happen outside of any tracked transaction,
    // such as opening the database, repairing it, and running integrity checks.
    Untracked,
}

impl TransactionGuard {
    pub(crate) fn new_read(
        transaction_id: TransactionId,
        tracker: Arc<TransactionTracker>,
    ) -> Self {
        Self::Read {
            tracker,
            transaction_id,
        }
    }

    pub(crate) fn allocate_read(
        tracker: Arc<TransactionTracker>,
        mem: &TransactionalMemory,
    ) -> Result<Self> {
        mem.check_io_errors()?;
        let id = tracker.register_read_transaction(mem)?;
        Ok(Self::new_read(id, tracker))
    }

    pub(crate) fn new_write(
        transaction_id: TransactionId,
        tracker: Arc<TransactionTracker>,
    ) -> Self {
        Self::Write {
            tracker,
            transaction_id,
        }
    }

    pub(crate) fn untracked() -> Self {
        Self::Untracked
    }

    pub(crate) fn id(&self) -> TransactionId {
        match self {
            Self::Read { transaction_id, .. } | Self::Write { transaction_id, .. } => {
                *transaction_id
            }
            Self::Untracked => {
                panic!("TransactionGuard::id() called on an untracked guard")
            }
        }
    }
}

impl Drop for TransactionGuard {
    fn drop(&mut self) {
        match self {
            Self::Read {
                tracker,
                transaction_id,
            } => tracker.deallocate_read_transaction(*transaction_id),
            Self::Write {
                tracker,
                transaction_id,
            } => {
                if let Some(mem) = tracker.end_write_transaction(*transaction_id) {
                    // The Database was dropped while this transaction was live, deferring
                    // the database close to the end of this transaction
                    close_database(tracker, &mem);
                }
            }
            Self::Untracked => {}
        }
    }
}

pub trait ReadableDatabase: SealedInApi5 {
    /// Begins a read transaction
    ///
    /// Captures a snapshot of the database, so that only data committed before calling this method
    /// is visible in the transaction
    ///
    /// Returns a [`ReadTransaction`] which may be used to read from the database. Read transactions
    /// may exist concurrently with writes
    fn begin_read(&self) -> Result<ReadTransaction, TransactionError>;

    /// Information regarding the usage of the in-memory cache
    ///
    /// Note: these metrics are only collected when the "`cache_metrics`" feature is enabled
    fn cache_stats(&self) -> CacheStats;
}

// Unavailable without std: every route to one goes through a path, and the file-backed API is
// gated out below.
/// A redb database opened in read-only mode
///
/// Use [`Self::begin_read`] to get a [`ReadTransaction`] object that can be used to read from the database
///
/// Multiple processes may open a [`ReadOnlyDatabase`], but it may not be opened concurrently
/// with a [`Database`].
///
/// # Examples
///
/// Basic usage:
///
/// ```rust
/// use redb::*;
/// # use tempfile::NamedTempFile;
/// const TABLE: TableDefinition<u64, u64> = TableDefinition::new("my_data");
///
/// # fn example(admission: std::sync::Arc<dyn redb::StorageAdmission>) -> Result<(), Error> {
/// # #[cfg(not(target_os = "wasi"))]
/// # let tmpfile = NamedTempFile::new().unwrap();
/// # #[cfg(target_os = "wasi")]
/// # let tmpfile = NamedTempFile::new_in("/tmp").unwrap();
/// # let filename = tmpfile.path();
/// let db = Database::create(filename, admission.clone())?;
/// let txn = db.begin_write()?;
/// {
///     let mut table = txn.open_table(TABLE)?;
///     table.insert(&0, &0)?;
/// }
/// txn.commit()?;
/// drop(db);
///
/// let db = ReadOnlyDatabase::open(filename, admission.clone())?;
/// let txn = db.begin_read()?;
/// {
///     let mut table = txn.open_table(TABLE)?;
///     println!("{}", table.get(&0)?.unwrap().value());
/// }
/// # Ok(())
/// # }
/// ```
#[cfg(not(redb_no_std))]
pub struct ReadOnlyDatabase {
    mem: Arc<TransactionalMemory>,
    transaction_tracker: Arc<TransactionTracker>,
}

#[cfg(not(redb_no_std))]
impl Sealed for ReadOnlyDatabase {}

#[cfg(not(redb_no_std))]
impl ReadableDatabase for ReadOnlyDatabase {
    fn begin_read(&self) -> Result<ReadTransaction, TransactionError> {
        self.mem.check_io_errors()?;
        let id = self
            .transaction_tracker
            .register_read_transaction(&self.mem)?;
        #[cfg(feature = "logging")]
        debug!("Beginning read transaction id={id:?}");

        let guard = TransactionGuard::new_read(id, self.transaction_tracker.clone());

        ReadTransaction::new(self.mem.clone(), guard)
    }

    fn cache_stats(&self) -> CacheStats {
        self.mem.cache_stats()
    }
}

#[cfg(not(redb_no_std))]
impl Debug for ReadOnlyDatabase {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("ReadOnlyDatabase")
    }
}

#[cfg(not(redb_no_std))]
impl ReadOnlyDatabase {
    /// Release the backend explicitly after all read handles drain.
    pub fn close(self) -> core::result::Result<(), crate::CloseError<Self>> {
        if Arc::strong_count(&self.transaction_tracker) != 1 {
            return Err(crate::CloseError::Busy(self));
        }
        self.mem.abandon().map_err(crate::CloseError::Storage)
    }

    /// Opens an existing redb database.
    #[cfg(not(redb_no_std))]
    pub fn open(
        path: impl AsRef<Path>,
        admission: Arc<dyn crate::StorageAdmission>,
    ) -> Result<ReadOnlyDatabase, DatabaseError> {
        Builder::new(admission).open_read_only(path)
    }

    fn new(
        file: Box<dyn StorageBackend>,
        admission: Arc<dyn crate::StorageAdmission>,
        page_size: usize,
        region_size: Option<u64>,
        cache_size: usize,
    ) -> Result<Self, DatabaseError> {
        #[cfg(feature = "logging")]
        let file_path = format!("{file:?}");
        #[cfg(feature = "logging")]
        debug!("Opening database in read-only {file_path:?}");
        let mem = TransactionalMemory::new(
            Box::new(ReadOnlyBackend::new(file)),
            admission,
            false,
            page_size,
            region_size,
            cache_size,
        )?;
        let mem = Arc::new(mem);
        Database::require_canonical_system_tables(&mem)?;
        if mem.opened_unclean() {
            return Err(DatabaseError::RepairAborted);
        }
        // Load the allocator snapshot for this winner, or rebuild it if absent or stale.
        if let Some(tree) = Database::get_allocator_state_table(&mem)? {
            mem.load_allocator_state(&tree)?;
        } else {
            #[cfg(feature = "logging")]
            warn!("Database {file_path:?} not shutdown cleanly. Repair required");
            return Err(DatabaseError::RepairAborted);
        }

        let next_transaction_id = mem.get_last_committed_transaction_id()?.next();
        let db = Self {
            mem,
            transaction_tracker: Arc::new(TransactionTracker::new(next_transaction_id)),
        };

        Ok(db)
    }
}

/// Opened redb database file
///
/// Use [`Self::begin_read`] to get a [`ReadTransaction`] object that can be used to read from the database
/// Use [`Self::begin_write`] to get a [`WriteTransaction`] object that can be used to read or write to the database
///
/// Multiple reads may be performed concurrently, with each other, and with writes. Only a single write
/// may be in progress at a time.
///
/// # Close semantics
///
/// [`Database::close`] performs a fallible clean close after all user handles drain.
/// Dropping the database releases the file lock without a checkpoint, allocation,
/// or trim. Outstanding read transactions return [`StorageError::DatabaseClosed`].
///
/// A live [`WriteTransaction`] keeps the database open, however: if one exists when the
/// [`Database`] is dropped, the transaction remains fully usable and backend release
/// is deferred until the transaction commits, aborts, or is dropped. Until then the database
/// file remains locked, so re-opening it fails with [`DatabaseError::DatabaseAlreadyOpen`].
///
/// # Examples
///
/// Basic usage:
///
/// ```rust
/// use redb::*;
/// # use tempfile::NamedTempFile;
/// const TABLE: TableDefinition<u64, u64> = TableDefinition::new("my_data");
///
/// # fn example(admission: std::sync::Arc<dyn redb::StorageAdmission>) -> Result<(), Error> {
/// # #[cfg(not(target_os = "wasi"))]
/// # let tmpfile = NamedTempFile::new().unwrap();
/// # #[cfg(target_os = "wasi")]
/// # let tmpfile = NamedTempFile::new_in("/tmp").unwrap();
/// # let filename = tmpfile.path();
/// let db = Database::create(filename, admission.clone())?;
/// let write_txn = db.begin_write()?;
/// {
///     let mut table = write_txn.open_table(TABLE)?;
///     table.insert(&0, &0)?;
/// }
/// write_txn.commit()?;
/// # Ok(())
/// # }
/// ```
pub struct Database {
    mem: Arc<TransactionalMemory>,
    transaction_tracker: Arc<TransactionTracker>,
}

impl Sealed for Database {}

impl ReadableDatabase for Database {
    fn begin_read(&self) -> Result<ReadTransaction, TransactionError> {
        let guard = TransactionGuard::allocate_read(self.transaction_tracker.clone(), &self.mem)?;
        #[cfg(feature = "logging")]
        debug!("Beginning read transaction id={:?}", guard.id());
        ReadTransaction::new(self.get_memory(), guard)
    }

    fn cache_stats(&self) -> CacheStats {
        self.mem.cache_stats()
    }
}

impl Database {
    /// Opens the specified file as a redb database.
    /// * if the file does not exist, or is an empty file, a new database will be initialized in it
    /// * if the file is a valid redb database, it will be opened
    /// * otherwise this function will return an error
    #[cfg(not(redb_no_std))]
    pub fn create(
        path: impl AsRef<Path>,
        admission: Arc<dyn crate::StorageAdmission>,
    ) -> Result<Database, DatabaseError> {
        Self::builder(admission).create(path)
    }

    /// Opens an existing redb database.
    #[cfg(not(redb_no_std))]
    pub fn open(
        path: impl AsRef<Path>,
        admission: Arc<dyn crate::StorageAdmission>,
    ) -> Result<Database, DatabaseError> {
        Self::builder(admission).open(path)
    }

    /// Close explicitly after every transaction and savepoint has drained.
    /// A busy result retains this exact database for a later retry.
    pub fn close(self) -> core::result::Result<(), crate::CloseError<Self>> {
        if Arc::strong_count(&self.transaction_tracker) != 1 {
            return Err(crate::CloseError::Busy(self));
        }
        self.mem.close().map_err(crate::CloseError::Storage)
    }

    pub(crate) fn get_memory(&self) -> Arc<TransactionalMemory> {
        self.mem.clone()
    }

    pub(crate) fn require_canonical_system_tables(mem: &Arc<TransactionalMemory>) -> Result {
        let tree = TableTree::new(
            mem.get_system_root(),
            PageHint::None,
            Arc::new(TransactionGuard::untracked()),
            PageResolver::new(mem.clone()),
        )?;
        if tree.contains_table_name(OBSOLETE_SYSTEM_FREED_TABLE_NAME)? {
            return Err(StorageError::ObsoleteSystemTable);
        }
        Ok(())
    }

    pub(crate) fn verify_primary_checksums(mem: Arc<TransactionalMemory>) -> Result<bool> {
        Self::require_canonical_system_tables(&mem)?;
        let data_root = mem.get_data_root();
        let system_root = mem.get_system_root();
        Self::verify_checksums(mem, data_root, system_root)
    }

    // Verifies the checksums reachable from the given data and system roots, reading pages through
    // `mem` (i.e. from disk if its cache was invalidated first).
    fn verify_checksums(
        mem: Arc<TransactionalMemory>,
        data_root: Option<BtreeHeader>,
        system_root: Option<BtreeHeader>,
    ) -> Result<bool> {
        let resolver = PageResolver::new(mem.clone());
        let table_tree = TableTree::new(
            data_root,
            PageHint::None,
            Arc::new(TransactionGuard::untracked()),
            resolver.clone(),
        )?;
        if !table_tree.verify_checksums()? {
            return Ok(false);
        }
        let system_table_tree = TableTree::new(
            system_root,
            PageHint::None,
            Arc::new(TransactionGuard::untracked()),
            resolver,
        )?;
        if !system_table_tree.verify_checksums()? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Force a check of the integrity of the database file, and repair it if possible.
    ///
    /// Note: Calling this function is unnecessary during normal operation. redb will automatically
    /// detect and recover from crashes, power loss, and other unclean shutdowns. This function is
    /// quite slow and should only be used when you suspect the database file may have been modified
    /// externally to redb, or that a redb bug may have left the database in a corrupted state.
    ///
    /// Returns `Ok(true)` if the database passed integrity checks; `Ok(false)` if it failed but was repaired,
    /// and `Err(Corrupted)` if the check failed and the file could not be repaired.
    ///
    /// Returns [`DatabaseError::TransactionInProgress`] if any read or write transaction, or an
    /// ephemeral [`Savepoint`](crate::Savepoint), is still alive when this method is called.
    ///
    pub fn check_integrity(&mut self) -> Result<bool, DatabaseError> {
        if Arc::get_mut(&mut self.mem).is_none() {
            return Err(DatabaseError::TransactionInProgress);
        }
        // Borrowed savepoints must drain before rebuilding their allocator state.
        if self.transaction_tracker.any_ephemeral_savepoint_exists() {
            return Err(DatabaseError::TransactionInProgress);
        }

        // Report a latched I/O failure as such, not as the discarded allocator state it also causes
        self.mem.check_io_errors()?;
        // Once the allocator state has been discarded (by a failed commit or integrity check),
        // the database must be reopened to rebuild it; this check requires one to compare against
        if !self.mem.allocator_state_loaded() {
            return Err(StorageError::Corrupted(
                "Allocator state was discarded by a failed integrity check or commit; reopen the database to repair it".to_string(),
            )
            .into());
        }

        // Repairing rebuilds the allocator state, so a failure part way through leaves one that
        // describes neither the file nor anything else. Holding an allocator state must continue
        // to mean it describes the file.
        let result = self.check_integrity_inner();
        if result.is_err() {
            self.mem.invalidate_allocator_state();
        }
        result
    }

    fn check_integrity_inner(&mut self) -> Result<bool, DatabaseError> {
        let allocator_hash = self.mem.allocator_hash();
        let mem = Arc::get_mut(&mut self.mem).unwrap();
        let mut was_clean = mem.clear_cache_and_reload()?;

        let old_roots = [self.mem.get_data_root(), self.mem.get_system_root()];

        let new_roots = Self::do_repair(&mut self.mem, &|_| {}).map_err(|err| match err {
            DatabaseError::Storage(storage_err) => storage_err,
            _ => unreachable!(),
        })?;

        if old_roots != new_roots || allocator_hash != self.mem.allocator_hash() {
            was_clean = false;
        }

        self.mem.begin_writable()?;
        if !was_clean {
            let mut transaction = self
                .begin_write()
                .map_err(|error| error.into_storage_error())?;
            transaction.set_repaired_roots(new_roots);
            transaction
                .commit()
                .map_err(|error| error.into_storage_error())?;
        }

        Ok(was_clean)
    }

    /// Relocates at most 64 candidate paths within the supplied old/new page-buffer
    /// byte allowance, then reclaims obsolete generations and trims unused extents.
    /// Returns true if relocation moved pages or bounded maintenance observed
    /// DATA or allocation-history debt beyond its batch. A concurrent reader release can require one
    /// extra observation; false never hides unselected reclaim debt.
    /// Candidate discovery still scans the database; callers must separately admit that work.
    pub fn compact(
        &mut self,
        max_relocation_bytes: core::num::NonZeroUsize,
    ) -> Result<bool, CompactionError> {
        // These checks must run before begin_write(): the caller may legally hold an open
        // WriteTransaction (it is not lifetime-bound to the Database), and if that transaction
        // created a savepoint, blocking in begin_write() below would deadlock. Savepoints must
        // be diagnosed before read references, because every live savepoint also holds a read
        // reference. The tracker covers persistent savepoints created by previous Database
        // instances, because they are re-registered when the database is opened.
        if self.transaction_tracker.any_persistent_savepoint_exists() {
            return Err(CompactionError::PersistentSavepointExists);
        }
        if self.transaction_tracker.any_savepoint_exists() {
            return Err(CompactionError::EphemeralSavepointExists);
        }
        if self.transaction_tracker.any_user_read_reference_exists() {
            return Err(CompactionError::TransactionInProgress);
        }
        let txn = self.begin_write().map_err(|e| e.into_storage_error())?;
        // Re-check inside the write transaction: a concurrent writer may have created a
        // savepoint between the checks above and the start of this transaction.
        if txn.list_persistent_savepoints()?.next().is_some() {
            return Err(CompactionError::PersistentSavepointExists);
        }
        if self.transaction_tracker.any_savepoint_exists() {
            return Err(CompactionError::EphemeralSavepointExists);
        }
        if self.transaction_tracker.any_user_read_reference_exists() {
            return Err(CompactionError::TransactionInProgress);
        }
        txn.abort()?;
        // Commit to free up any pending free pages
        self.drain_pending_free_pages(ShrinkPolicy::Maximum)?;

        // One bounded page relocation batch per call. Repair metadata is
        // prepared by its own immediate commit, and cannot recurse into an
        // unbounded series of cleanup commits.
        let mut txn = begin_write_with_allocation_policy(
            &self.transaction_tracker,
            &self.mem,
            AllocationPolicy::Lowest,
        )
        .map_err(|e| e.into_storage_error())?;
        let progress = txn.compact_pages(max_relocation_bytes)?;
        if progress {
            txn.commit().map_err(|e| e.into_storage_error())?;
        } else {
            txn.abort()?;
        }
        let reclaim_pending = self.drain_pending_free_pages(ShrinkPolicy::Maximum)?;
        Ok(progress || reclaim_pending)
    }

    fn drain_pending_free_pages(&self, shrink_policy: ShrinkPolicy) -> Result<bool> {
        // Two commits remain a fixed per-call maintenance allowance. Current
        // system frees are excluded directly, so this does not generate a new
        // historical system tail. Report either retained metadata prefix.
        let mut remaining = false;
        for _ in 0..2 {
            let mut txn = begin_write_with_allocation_policy(
                &self.transaction_tracker,
                &self.mem,
                AllocationPolicy::Lowest,
            )
            .map_err(|e| e.into_storage_error())?;
            txn.set_shrink_policy(shrink_policy);
            // No user mutation occurs between this bounded selection and this
            // empty maintenance commit; the real writer guard excludes others.
            remaining = txn.reclaim_backlog_after_batch()?;
            txn.commit().map_err(|e| e.into_storage_error())?;
        }
        Ok(remaining)
    }

    #[cfg_attr(not(debug_assertions), expect(dead_code))]
    fn check_repaired_allocated_pages_table(
        system_root: Option<BtreeHeader>,
        mem: Arc<TransactionalMemory>,
    ) -> Result {
        let resolver = PageResolver::new(mem.clone());
        let table_tree = TableTree::new(
            system_root,
            PageHint::None,
            Arc::new(TransactionGuard::untracked()),
            resolver.clone(),
        )?;
        if let Some(table_def) = table_tree
            .get_table::<TransactionIdWithPagination, PageList>(
                DATA_ALLOCATED_TABLE.name(),
                TableType::Normal,
            )
            .map_err(|e| e.into_storage_error_or_corrupted("Allocated pages table corrupted"))?
        {
            let InternalTableDefinition::Normal { table_root, .. } = table_def else {
                unreachable!()
            };
            let table: ReadOnlyTable<TransactionIdWithPagination, PageList> = ReadOnlyTable::new(
                DATA_ALLOCATED_TABLE.name().to_string(),
                table_root,
                PageHint::None,
                Arc::new(TransactionGuard::untracked()),
                resolver,
            )?;
            for result in ReadableTable::iter(&table)? {
                let (_, pages) = result?;
                let pages = pages.value().checked()?;
                for i in 0..pages.len() {
                    assert!(mem.is_allocated(pages.get(i)));
                }
            }
        }

        Ok(())
    }

    fn visit_pending_data_pages<F>(
        system_root: Option<BtreeHeader>,
        mem: Arc<TransactionalMemory>,
        mut visitor: F,
    ) -> Result
    where
        F: FnMut(PageNumber) -> Result,
    {
        let untracked_guard = Arc::new(TransactionGuard::untracked());
        let resolver = PageResolver::new(mem.clone());
        let system_tree = TableTree::new(
            system_root,
            PageHint::None,
            untracked_guard,
            resolver.clone(),
        )?;
        let table_name = DATA_FREED_TABLE.name();
        let result = match system_tree
            .get_table::<TransactionIdWithPagination, PageList>(table_name, TableType::Normal)
        {
            Ok(result) => result,
            Err(TableError::Storage(err)) => {
                return Err(err);
            }
            Err(TableError::TableDoesNotExist(_)) => {
                return Ok(());
            }
            Err(_) => {
                return Err(StorageError::Corrupted(format!(
                    "Unable to open {table_name}"
                )));
            }
        };

        if let Some(definition) = result {
            let table_root = match definition {
                InternalTableDefinition::Normal { table_root, .. } => table_root,
                InternalTableDefinition::Multimap { .. } => unreachable!(),
            };
            let table: ReadOnlyTable<TransactionIdWithPagination, PageList<'static>> =
                ReadOnlyTable::new(
                    table_name.to_string(),
                    table_root,
                    PageHint::None,
                    Arc::new(TransactionGuard::untracked()),
                    resolver,
                )?;
            for result in ReadableTable::iter(&table)? {
                let (_, page_list) = result?;
                let pages = page_list.value().checked()?;
                for i in 0..pages.len() {
                    visitor(pages.get(i))?;
                }
            }
        }

        Ok(())
    }

    #[cfg(debug_assertions)]
    fn mark_allocated_page_for_debug(
        mem: &mut Arc<TransactionalMemory>, // Only &mut to ensure exclusivity
    ) -> Result {
        let data_root = mem.get_data_root();
        {
            let untracked = Arc::new(TransactionGuard::untracked());
            let tables = TableTree::new(
                data_root,
                PageHint::None,
                untracked,
                PageResolver::new(mem.clone()),
            )?;
            tables.visit_all_pages(|path| {
                mem.mark_debug_allocated_page(path.page_number());
                Ok(())
            })?;
        }

        let system_root = mem.get_system_root();
        {
            let untracked = Arc::new(TransactionGuard::untracked());
            let system_tables = TableTree::new(
                system_root,
                PageHint::None,
                untracked,
                PageResolver::new(mem.clone()),
            )?;
            system_tables.visit_all_pages(|path| {
                mem.mark_debug_allocated_page(path.page_number());
                Ok(())
            })?;
        }

        Self::visit_pending_data_pages(system_root, mem.clone(), |page| {
            mem.mark_debug_allocated_page(page);
            Ok(())
        })?;

        Ok(())
    }

    // Collapse checksum and malformed-page failures into a failed winner validation.
    // Physical owner failures retain their distinct typed result.
    fn primary_verifies(mem: &Arc<TransactionalMemory>) -> Result<bool> {
        match Self::verify_primary_checksums(mem.clone()) {
            Ok(verified) => Ok(verified),
            Err(StorageError::Corrupted(_)) => Ok(false),
            Err(err) => Err(err),
        }
    }

    fn do_repair(
        mem: &mut Arc<TransactionalMemory>, // Only &mut to ensure exclusivity
        repair_callback: &(dyn Fn(&mut RepairSession) + 'static),
    ) -> Result<[Option<BtreeHeader>; 2], DatabaseError> {
        if !Self::primary_verifies(mem)? {
            return Err(DatabaseError::Storage(StorageError::Corrupted(
                "Winning root is corrupted".to_string(),
            )));
        }
        // 0.6 because the repair takes 3 full scans and the second is done now
        let mut handle = RepairSession::new(0.6);
        repair_callback(&mut handle);
        if handle.aborted() {
            return Err(DatabaseError::RepairAborted);
        }

        let [data_root, system_root] = Self::rebuild_allocator_state(mem, repair_callback)?;

        mem.clear_recovery_required()?;

        // We need to invalidate the userspace cache, because we're about to implicitly free the freed table
        // by storing an empty root during the below commit()
        mem.clear_read_cache();

        Ok([data_root, system_root])
    }

    // Rebuilds the in-memory allocator state by marking every page reachable from the current
    // roots (including the pages referenced by the freed-page tables) as allocated. Operates
    // purely on in-memory state and does not modify the file.
    //
    // The returned roots carry table counts recounted from the trees that were walked. These
    // counts are stored in the commit slot rather than in a page, so no page checksum covers
    // them; recounting here is what lets the rest of the codebase trust them.
    fn rebuild_allocator_state(
        mem: &mut Arc<TransactionalMemory>, // Only &mut to ensure exclusivity
        repair_callback: &(dyn Fn(&mut RepairSession) + 'static),
    ) -> Result<[Option<BtreeHeader>; 2], DatabaseError> {
        Self::require_canonical_system_tables(mem)?;
        mem.reset_allocator_state()?;

        let data_root = {
            let root = mem.get_data_root();
            let untracked = Arc::new(TransactionGuard::untracked());
            let tables = TableTree::new(
                root,
                PageHint::None,
                untracked,
                PageResolver::new(mem.clone()),
            )?;
            tables.visit_all_pages(|path| mem.mark_page_allocated(path.page_number()))?;
            Self::with_recounted_length(root, tables.count_tables()?)
        };

        // 0.9 because the repair takes 3 full scans and the third is done now. There is just some system tables left
        let mut handle = RepairSession::new(0.9);
        repair_callback(&mut handle);
        if handle.aborted() {
            return Err(DatabaseError::RepairAborted);
        }

        let system_root = {
            let root = mem.get_system_root();
            let untracked = Arc::new(TransactionGuard::untracked());
            let system_tables = TableTree::new(
                root,
                PageHint::None,
                untracked,
                PageResolver::new(mem.clone()),
            )?;
            system_tables.visit_all_pages(|path| mem.mark_page_allocated(path.page_number()))?;
            Self::with_recounted_length(root, system_tables.count_tables()?)
        };

        Self::visit_pending_data_pages(system_root, mem.clone(), |page| {
            mem.mark_page_allocated(page)
        })?;
        #[cfg(debug_assertions)]
        {
            Self::check_repaired_allocated_pages_table(system_root, mem.clone())?;
        }

        Ok([data_root, system_root])
    }

    fn with_recounted_length(root: Option<BtreeHeader>, length: u64) -> Option<BtreeHeader> {
        root.map(|header| BtreeHeader::new(header.root, header.checksum, length))
    }

    fn new(
        file: Box<dyn StorageBackend>,
        admission: Arc<dyn crate::StorageAdmission>,
        allow_initialize: bool,
        page_size: usize,
        region_size: Option<u64>,
        cache_size: usize,
        repair_callback: &(dyn Fn(&mut RepairSession) + 'static),
    ) -> Result<Self, DatabaseError> {
        #[cfg(feature = "logging")]
        let file_path = format!("{file:?}");
        #[cfg(feature = "logging")]
        debug!("Opening database {file_path:?}");
        let mem = TransactionalMemory::new(
            file,
            admission,
            allow_initialize,
            page_size,
            region_size,
            cache_size,
        )?;
        let mut mem = Arc::new(mem);
        // An allocator snapshot proves page ownership, not payload integrity. An
        // unclean reopen must verify the winning root before trusting that snapshot.
        if mem.opened_unclean() && !Self::primary_verifies(&mem)? {
            return Err(StorageError::Corrupted(
                "Unclean database has a corrupted winning root".to_string(),
            )
            .into());
        }
        // Load the allocator snapshot for this winner, or rebuild it if absent or stale.
        let repaired_roots = if let Some(tree) = Self::get_allocator_state_table(&mem)? {
            #[cfg(feature = "logging")]
            debug!("Found valid allocator state, full repair not needed");
            mem.load_allocator_state(&tree)?;
            #[cfg(debug_assertions)]
            Self::mark_allocated_page_for_debug(&mut mem)?;
            None
        } else {
            #[cfg(feature = "logging")]
            warn!("Database {file_path:?} not shutdown cleanly. Repairing");
            let mut handle = RepairSession::new(0.0);
            repair_callback(&mut handle);
            if handle.aborted() {
                return Err(DatabaseError::RepairAborted);
            }
            Some(Self::do_repair(&mut mem, repair_callback)?)
        };

        mem.begin_writable()?;
        let next_transaction_id = mem.get_last_committed_transaction_id()?.next();

        let db = Database {
            mem,
            transaction_tracker: Arc::new(TransactionTracker::new(next_transaction_id)),
        };

        // Restore the tracker state for any persistent savepoints
        let mut txn = db.begin_write().map_err(|e| e.into_storage_error())?;
        if let Some(roots) = repaired_roots {
            txn.set_repaired_roots(roots);
        }
        if let Some(next_id) = txn.next_persistent_savepoint_id()? {
            db.transaction_tracker
                .restore_savepoint_counter_state(next_id);
        }
        for id in txn.list_persistent_savepoints()? {
            let savepoint = match txn.get_persistent_savepoint(id) {
                Ok(savepoint) => savepoint,
                Err(err) => match err {
                    SavepointError::InvalidSavepoint => unreachable!(),
                    SavepointError::Storage(storage) => {
                        return Err(storage.into());
                    }
                },
            };
            db.transaction_tracker
                .register_persistent_savepoint(&savepoint);
        }
        if repaired_roots.is_some() {
            txn.commit().map_err(|error| error.into_storage_error())?;
        } else {
            txn.abort()?;
        }

        Ok(db)
    }

    fn get_allocator_state_table(
        mem: &Arc<TransactionalMemory>,
    ) -> Result<Option<AllocatorStateTree>> {
        Self::require_canonical_system_tables(mem)?;
        // See if it's present in the system table tree
        let resolver = PageResolver::new(mem.clone());
        let system_table_tree = TableTree::new(
            mem.get_system_root(),
            PageHint::None,
            Arc::new(TransactionGuard::untracked()),
            resolver.clone(),
        )?;
        let Some(allocator_state_table) = system_table_tree
            .get_table::<AllocatorStateKey, &[u8]>(ALLOCATOR_STATE_TABLE_NAME, TableType::Normal)
            .map_err(|e| e.into_storage_error_or_corrupted("Unexpected TableError"))?
        else {
            return Ok(None);
        };

        // Load the allocator state table
        let InternalTableDefinition::Normal { table_root, .. } = allocator_state_table else {
            unreachable!();
        };
        let tree = AllocatorStateTree::new(
            table_root,
            PageHint::None,
            Arc::new(TransactionGuard::untracked()),
            resolver,
        )?;

        // Make sure this isn't stale allocator state left over from a previous transaction
        if !mem.is_valid_allocator_state(&tree)? {
            return Ok(None);
        }

        Ok(Some(tree))
    }

    /// Convenience method for [`Builder::new`]
    pub fn builder(admission: Arc<dyn crate::StorageAdmission>) -> Builder {
        Builder::new(admission)
    }

    /// Begins a write transaction
    ///
    /// Returns a [`WriteTransaction`] which may be used to read/write to the database. Only a single
    /// write may be in progress at a time. If a write is in progress, this function will block
    /// until it completes.
    ///
    /// The returned transaction is not lifetime-bound to this [`Database`] and keeps the
    /// database open: if the [`Database`] is dropped while the transaction is live, the
    /// transaction remains usable and the database closes when the transaction completes.
    pub fn begin_write(&self) -> Result<WriteTransaction, TransactionError> {
        begin_write_with_allocation_policy(
            &self.transaction_tracker,
            &self.mem,
            AllocationPolicy::Default,
        )
    }
}

// The allocation policy is fixed for the lifetime of the transaction; every page allocation
// this transaction makes goes through it.
fn begin_write_with_allocation_policy(
    transaction_tracker: &Arc<TransactionTracker>,
    mem: &Arc<TransactionalMemory>,
    allocation_policy: AllocationPolicy,
) -> Result<WriteTransaction, TransactionError> {
    // Fail early if there has been an I/O error -- nothing can be committed in that case
    mem.check_io_errors()?;
    let guard = TransactionGuard::new_write(
        transaction_tracker.start_write_transaction(),
        transaction_tracker.clone(),
    );
    // Re-checked after acquiring the write slot: the writer this call blocked on can fail its
    // commit, latching an I/O error and discarding the allocator state. The I/O check comes
    // first so a backend failure is not misreported as corruption. Returning drops the guard,
    // releasing the slot.
    mem.check_io_errors()?;
    if !mem.allocator_state_loaded() {
        return Err(StorageError::Corrupted(
            "Allocator state was discarded by a failed integrity check or commit; reopen the database to repair it".to_string(),
        )
        .into());
    }
    mem.begin_transaction();
    WriteTransaction::new(
        guard,
        transaction_tracker.clone(),
        mem.clone(),
        allocation_policy,
    )
    .map_err(|e| e.into())
}

// Release the backend once, immediately or when a live write transaction ends.
fn close_database(_transaction_tracker: &Arc<TransactionTracker>, mem: &Arc<TransactionalMemory>) {
    // A destructor cannot publish an allocating checkpoint or report its failure.
    // Durable commits already contain their repair metadata. Preserve the dirty
    // recovery flag and release only the retained backend owner.
    let _ = mem.abandon();
}

impl Drop for Database {
    fn drop(&mut self) {
        if self
            .transaction_tracker
            .defer_close_if_write_transaction_live(&self.mem)
        {
            // The write transaction holds the memory and tracker alive, so it remains fully
            // usable; TransactionGuard::drop performs the deferred close when it ends
            return;
        }

        close_database(&self.transaction_tracker, &self.mem);
    }
}

pub struct RepairSession {
    progress: f64,
    aborted: bool,
}

impl RepairSession {
    pub(crate) fn new(progress: f64) -> Self {
        Self {
            progress,
            aborted: false,
        }
    }

    pub(crate) fn aborted(&self) -> bool {
        self.aborted
    }

    /// Abort the repair process. The coorresponding call to [`Builder::open`] or [`Builder::create`] will return an error
    pub fn abort(&mut self) {
        self.aborted = true;
    }

    /// Returns an estimate of the repair progress in the range [0.0, 1.0). At 1.0 the repair is complete.
    pub fn progress(&self) -> f64 {
        self.progress
    }
}

/// Configuration builder of a redb [Database].
pub struct Builder {
    admission: Arc<dyn crate::StorageAdmission>,
    page_size: usize,
    region_size: Option<u64>,
    cache_size: usize,
    repair_callback: Box<dyn Fn(&mut RepairSession) + Send + Sync>,
}

impl Builder {
    /// Construct a new [Builder] with sensible defaults.
    ///
    /// ## Defaults
    ///
    /// - `cache_size_bytes`: 1GiB
    #[allow(clippy::new_without_default)]
    pub fn new(admission: Arc<dyn crate::StorageAdmission>) -> Self {
        Self {
            admission,
            // Default to 4k pages. Benchmarking showed that this was a good default on all platforms,
            // including MacOS with 16k pages. Therefore, users are not allowed to configure it at the moment.
            // It is part of the file format, so can be enabled in the future.
            page_size: PAGE_SIZE,
            region_size: None,
            cache_size: 1024 * 1024 * 1024,
            repair_callback: Box::new(|_| {}),
        }
    }

    /// Set a callback which will be invoked periodically in the event that the database file needs
    /// to be repaired.
    ///
    /// The [`RepairSession`] argument can be used to control the repair process.
    ///
    /// If the database file needs repair, the callback will be invoked at least once.
    /// There is no upper limit on the number of times it may be called.
    pub fn set_repair_callback(
        &mut self,
        callback: impl Fn(&mut RepairSession) + Send + Sync + 'static,
    ) -> &mut Self {
        self.repair_callback = Box::new(callback);
        self
    }

    /// Set the internal page size of the database
    ///
    /// Valid values are powers of two, greater than or equal to 512
    ///
    /// ## Defaults
    ///
    /// Default to 4 Kib pages.
    #[cfg(any(fuzzing, test))]
    pub fn set_page_size(&mut self, size: usize) -> &mut Self {
        assert!(size.is_power_of_two());
        self.page_size = core::cmp::max(size, 512);
        self
    }

    /// Set the amount of memory (in bytes) used for caching data
    pub fn set_cache_size(&mut self, bytes: usize) -> &mut Self {
        self.cache_size = bytes;
        self
    }

    #[cfg(any(test, fuzzing))]
    pub fn set_region_size(&mut self, size: u64) -> &mut Self {
        assert!(size.is_power_of_two());
        self.region_size = Some(size);
        self
    }

    /// Opens the specified file as a redb database.
    /// * if the file does not exist, or is an empty file, a new database will be initialized in it
    /// * if the file is a valid redb database, it will be opened
    /// * otherwise this function will return an error
    #[cfg(not(redb_no_std))]
    pub fn create(&self, path: impl AsRef<Path>) -> Result<Database, DatabaseError> {
        self.admission.check_owner().map_err(StorageError::from)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        Database::new(
            Box::new(FileBackend::new(file)?),
            self.admission.clone(),
            true,
            self.page_size,
            self.region_size,
            self.cache_size,
            &self.repair_callback,
        )
    }

    /// Opens an existing redb database.
    #[cfg(not(redb_no_std))]
    pub fn open(&self, path: impl AsRef<Path>) -> Result<Database, DatabaseError> {
        self.admission.check_owner().map_err(StorageError::from)?;
        let file = OpenOptions::new().read(true).write(true).open(path)?;

        Database::new(
            Box::new(FileBackend::new(file)?),
            self.admission.clone(),
            false,
            self.page_size,
            None,
            self.cache_size,
            &self.repair_callback,
        )
    }

    /// Opens an existing redb database.
    ///
    /// If the file has been opened for writing (i.e. as a [`Database`]) [`DatabaseError::DatabaseAlreadyOpen`]
    /// will be returned on platforms which support file locks (macOS, Windows, Linux). On other platforms,
    /// the caller MUST avoid calling this method when the database is open for writing.
    #[cfg(not(redb_no_std))]
    pub fn open_read_only(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<ReadOnlyDatabase, DatabaseError> {
        self.admission.check_owner().map_err(StorageError::from)?;
        let file = OpenOptions::new().read(true).open(path)?;

        ReadOnlyDatabase::new(
            Box::new(FileBackend::new_internal(file, true)?),
            self.admission.clone(),
            self.page_size,
            None,
            self.cache_size,
        )
    }

    /// Open an existing or create a new database in the given `file`.
    ///
    /// The file must be empty or contain a valid database.
    #[cfg(not(redb_no_std))]
    pub fn create_file(&self, file: File) -> Result<Database, DatabaseError> {
        Database::new(
            Box::new(FileBackend::new(file)?),
            self.admission.clone(),
            true,
            self.page_size,
            self.region_size,
            self.cache_size,
            &self.repair_callback,
        )
    }

    /// Open an existing or create a new database with the given backend.
    pub fn create_with_backend(
        &self,
        backend: impl StorageBackend,
    ) -> Result<Database, DatabaseError> {
        Database::new(
            Box::new(backend),
            self.admission.clone(),
            true,
            self.page_size,
            self.region_size,
            self.cache_size,
            &self.repair_callback,
        )
    }
}

impl core::fmt::Debug for Database {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Database").finish()
    }
}

#[cfg(test)]
mod test {
    use crate::backends::FileBackend;
    use crate::{
        CommitError, Database, DatabaseError, ReadableTable, StorageBackend, StorageError,
        TableDefinition, TransactionError,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::fs::File;
    use std::io::{ErrorKind, Read, Seek, SeekFrom};

    #[derive(Debug)]
    struct FailingBackend {
        inner: FileBackend,
        countdown: Arc<AtomicU64>,
    }

    impl FailingBackend {
        fn new(backend: FileBackend, countdown: u64) -> Self {
            Self {
                inner: backend,
                countdown: Arc::new(AtomicU64::new(countdown)),
            }
        }

        fn check_countdown(&self) -> Result<(), std::io::Error> {
            if self.countdown.load(Ordering::SeqCst) == 0 {
                return Err(std::io::Error::from(ErrorKind::Other));
            }

            Ok(())
        }

        fn decrement_countdown(&self) -> Result<(), std::io::Error> {
            if self
                .countdown
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| {
                    if x > 0 { Some(x - 1) } else { None }
                })
                .is_err()
            {
                return Err(std::io::Error::from(ErrorKind::Other));
            }

            Ok(())
        }
    }

    impl StorageBackend for FailingBackend {
        fn len(&self) -> Result<u64, std::io::Error> {
            self.inner.len()
        }

        fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
            self.check_countdown()?;
            self.inner.read(offset, out)
        }

        fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
            self.inner.set_len(len)
        }

        fn sync_data(&self) -> Result<(), std::io::Error> {
            self.check_countdown()?;
            self.inner.sync_data()
        }

        fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
            self.decrement_countdown()?;
            self.inner.write(offset, data)
        }
    }

    #[test]
    fn crash_regression4() {
        let tmpfile = crate::create_tempfile();
        let (file, path) = tmpfile.into_parts();

        let backend = FailingBackend::new(FileBackend::new(file).unwrap(), u64::MAX);
        let countdown = backend.countdown.clone();
        let db = Database::builder(crate::test_admission())
            .set_cache_size(12686)
            .set_page_size(8 * 1024)
            .set_region_size(32 * 4096)
            .create_with_backend(backend)
            .unwrap();

        let table_def: TableDefinition<u64, &[u8]> = TableDefinition::new("x");

        let tx = db.begin_write().unwrap();
        let _savepoint = tx.ephemeral_savepoint().unwrap();
        let _persistent_savepoint = tx.persistent_savepoint().unwrap();
        tx.commit().unwrap();
        let tx = db.begin_write().unwrap();
        {
            let mut table = tx.open_table(table_def).unwrap();
            let _ = table.insert_reserve(118821, 360).unwrap();
        }
        countdown.store(1, Ordering::SeqCst);
        let result = tx.commit();
        assert!(result.is_err());

        drop(db);
        Database::builder(crate::test_admission())
            .set_cache_size(1024 * 1024)
            .set_page_size(8 * 1024)
            .set_region_size(32 * 4096)
            .create(&path)
            .unwrap();
    }

    #[test]
    fn transient_io_error() {
        let tmpfile = crate::create_tempfile();
        let (file, path) = tmpfile.into_parts();

        let backend = FailingBackend::new(FileBackend::new(file).unwrap(), u64::MAX);
        let countdown = backend.countdown.clone();
        let db = Database::builder(crate::test_admission())
            .set_cache_size(0)
            .create_with_backend(backend)
            .unwrap();

        let table_def: TableDefinition<u64, u64> = TableDefinition::new("x");

        // Create some garbage
        let tx = db.begin_write().unwrap();
        {
            let mut table = tx.open_table(table_def).unwrap();
            table.insert(0, 0).unwrap();
        }
        tx.commit().unwrap();
        let tx = db.begin_write().unwrap();
        {
            let mut table = tx.open_table(table_def).unwrap();
            table.insert(0, 1).unwrap();
        }
        tx.commit().unwrap();

        let tx = db.begin_write().unwrap();
        // Cause an error in the commit
        countdown.store(0, Ordering::SeqCst);
        let result = tx.commit().err().unwrap();
        assert!(matches!(
            result,
            CommitError::Storage(StorageError::Io(error)) if error.kind() == ErrorKind::Other
        ));
        let result = db.begin_write().err().unwrap();
        assert!(matches!(
            result,
            TransactionError::Storage(StorageError::OwnerFailed)
        ));
        // Simulate a transient error
        countdown.store(u64::MAX, Ordering::SeqCst);
        drop(db);

        // Check that recovery flag is set, even though the error has "cleared"
        let mut file = File::open(&path).unwrap();
        file.seek(SeekFrom::Start(9)).unwrap();
        let mut god_byte = vec![0u8];
        assert_eq!(file.read(&mut god_byte).unwrap(), 1);
        assert_ne!(god_byte[0] & 2, 0);
    }

    #[test]
    fn small_pages() {
        let tmpfile = crate::create_tempfile();

        let db = Database::builder(crate::test_admission())
            .set_page_size(512)
            .create(tmpfile.path())
            .unwrap();

        let table_definition: TableDefinition<u64, &[u8]> = TableDefinition::new("x");
        let txn = db.begin_write().unwrap();
        {
            txn.open_table(table_definition).unwrap();
        }
        txn.commit().unwrap();
    }

    #[test]
    fn small_pages2() {
        let tmpfile = crate::create_tempfile();

        let db = Database::builder(crate::test_admission())
            .set_page_size(512)
            .create(tmpfile.path())
            .unwrap();

        let table_def: TableDefinition<u64, &[u8]> = TableDefinition::new("x");

        let tx = db.begin_write().unwrap();

        let savepoint0 = tx.ephemeral_savepoint().unwrap();
        {
            tx.open_table(table_def).unwrap();
        }
        tx.commit().unwrap();

        let mut tx = db.begin_write().unwrap();

        let savepoint1 = tx.ephemeral_savepoint().unwrap();
        tx.restore_savepoint(&savepoint0).unwrap();

        {
            let mut t = tx.open_table(table_def).unwrap();
            t.insert_reserve(&660503, 489).unwrap().as_mut().fill(0xFF);
            assert!(t.remove(&291295).unwrap().is_none());
        }
        tx.commit().unwrap();

        let mut tx = db.begin_write().unwrap();

        tx.restore_savepoint(&savepoint0).unwrap();
        {
            tx.open_table(table_def).unwrap();
        }
        tx.commit().unwrap();

        let mut tx = db.begin_write().unwrap();

        let savepoint2 = tx.ephemeral_savepoint().unwrap();
        drop(savepoint0);
        tx.restore_savepoint(&savepoint2).unwrap();
        {
            let mut t = tx.open_table(table_def).unwrap();
            assert!(t.get(&2059).unwrap().is_none());
            assert!(t.remove(&145227).unwrap().is_none());
            assert!(t.remove(&145227).unwrap().is_none());
        }
        tx.commit().unwrap();

        let mut tx = db.begin_write().unwrap();

        let savepoint3 = tx.ephemeral_savepoint().unwrap();
        drop(savepoint1);
        tx.restore_savepoint(&savepoint3).unwrap();
        {
            tx.open_table(table_def).unwrap();
        }
        tx.commit().unwrap();

        let mut tx = db.begin_write().unwrap();

        let savepoint4 = tx.ephemeral_savepoint().unwrap();
        drop(savepoint2);
        tx.restore_savepoint(&savepoint3).unwrap();

        {
            let mut t = tx.open_table(table_def).unwrap();
            assert!(t.remove(&207936).unwrap().is_none());
        }
        tx.abort().unwrap();

        let mut tx = db.begin_write().unwrap();

        let _savepoint5 = tx.ephemeral_savepoint().unwrap();
        drop(savepoint3);
        // savepoint4 was invalidated by the restore_savepoint(savepoint3) call
        // above, but that transaction was aborted, so the invalidation is
        // reversed and savepoint4 is valid again. Restoring it here invalidates
        // savepoint5 (which is newer), so the next transaction restores
        // savepoint4 again rather than savepoint5.
        tx.restore_savepoint(&savepoint4).unwrap();
        {
            tx.open_table(table_def).unwrap();
        }
        tx.commit().unwrap();

        let mut tx = db.begin_write().unwrap();

        tx.restore_savepoint(&savepoint4).unwrap();

        {
            tx.open_table(table_def).unwrap();
        }
        tx.commit().unwrap();
    }

    #[test]
    fn small_pages3() {
        let tmpfile = crate::create_tempfile();

        let db = Database::builder(crate::test_admission())
            .set_page_size(1024)
            .create(tmpfile.path())
            .unwrap();

        let table_def: TableDefinition<u64, &[u8]> = TableDefinition::new("x");

        let tx = db.begin_write().unwrap();
        let _savepoint0 = tx.ephemeral_savepoint().unwrap();

        {
            let mut t = tx.open_table(table_def).unwrap();
            let value = vec![0; 306];
            t.insert(&539717, value.as_slice()).unwrap();
        }
        tx.abort().unwrap();

        let mut tx = db.begin_write().unwrap();
        let savepoint1 = tx.ephemeral_savepoint().unwrap();
        tx.restore_savepoint(&savepoint1).unwrap();

        {
            let mut t = tx.open_table(table_def).unwrap();
            let value = vec![0; 2008];
            t.insert(&784384, value.as_slice()).unwrap();
        }
        tx.abort().unwrap();
    }

    #[test]
    fn small_pages4() {
        let tmpfile = crate::create_tempfile();

        let db = Database::builder(crate::test_admission())
            .set_cache_size(1024 * 1024)
            .set_page_size(1024)
            .create(tmpfile.path())
            .unwrap();

        let table_def: TableDefinition<u64, &[u8]> = TableDefinition::new("x");

        let tx = db.begin_write().unwrap();
        {
            tx.open_table(table_def).unwrap();
        }
        tx.commit().unwrap();

        let tx = db.begin_write().unwrap();
        {
            let mut t = tx.open_table(table_def).unwrap();
            assert!(t.get(&131072).unwrap().is_none());
            let value = vec![0xFF; 1130];
            t.insert(&42394, value.as_slice()).unwrap();
            t.insert_reserve(&744037, 3645).unwrap().as_mut().fill(0xFF);
            assert!(t.get(&0).unwrap().is_none());
        }
        tx.abort().unwrap();

        let tx = db.begin_write().unwrap();
        {
            let mut t = tx.open_table(table_def).unwrap();
            t.insert_reserve(&118749, 734).unwrap().as_mut().fill(0xFF);
        }
        tx.abort().unwrap();
    }

    #[test]
    fn dynamic_shrink() {
        let tmpfile = crate::create_tempfile();
        let table_definition: TableDefinition<u64, &[u8]> = TableDefinition::new("x");
        let big_value = vec![0u8; 1024];

        let mut db = Database::builder(crate::test_admission())
            .set_region_size(1024 * 1024)
            .create(tmpfile.path())
            .unwrap();

        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(table_definition).unwrap();
            for i in 0..2048 {
                table.insert(&i, big_value.as_slice()).unwrap();
            }
        }
        txn.commit().unwrap();

        let file_size = tmpfile.as_file().metadata().unwrap().len();

        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(table_definition).unwrap();
            for i in 0..2048 {
                table.remove(&i).unwrap();
            }
        }
        txn.commit().unwrap();

        // Perform a couple more commits to be sure the database has a chance to compact
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(table_definition).unwrap();
            table.insert(0, [].as_slice()).unwrap();
        }
        txn.commit().unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(table_definition).unwrap();
            table.remove(0).unwrap();
        }
        txn.commit().unwrap();
        let txn = db.begin_write().unwrap();
        txn.commit().unwrap();

        // Repair snapshots retain their own pages; physical shrinking is an
        // explicitly admitted maintenance operation.
        for _ in 0..8 {
            db.compact(core::num::NonZeroUsize::new(1 << 20).unwrap())
                .unwrap();
        }
        let final_file_size = tmpfile.as_file().metadata().unwrap().len();
        assert!(final_file_size < file_size);
    }

    #[test]
    fn create_new_db_in_empty_file() {
        let tmpfile = crate::create_tempfile();

        let _db = Database::builder(crate::test_admission())
            .create_file(tmpfile.into_file())
            .unwrap();
    }

    #[test]
    fn open_missing_file() {
        let tmpfile = crate::create_tempfile();

        let err = Database::builder(crate::test_admission())
            .open(tmpfile.path().with_extension("missing"))
            .unwrap_err();

        match err {
            DatabaseError::Storage(StorageError::Io(err)) if err.kind() == ErrorKind::NotFound => {}
            err => panic!("Unexpected error for empty file: {err}"),
        }
    }

    #[test]
    fn open_empty_file() {
        let tmpfile = crate::create_tempfile();

        let err = Database::builder(crate::test_admission())
            .open(tmpfile.path())
            .unwrap_err();

        match err {
            DatabaseError::Storage(StorageError::Io(err))
                if err.kind() == ErrorKind::InvalidData => {}
            err => panic!("Unexpected error for empty file: {err}"),
        }
    }
}
