//! Typed table and transaction surface for Kasumi's storage engine.
//!
//! Values are read from the backend on demand. Read transactions pin only the
//! immutable key index; a writer stages its bounded changes until one durable
//! core commit publishes them together. The first capacity denial rolls a
//! writer back whole and releases its writer gate; an owner failure keeps the
//! writer, its staged batch and the gate for retained custody.

use crate::core::{
    AdmittedValue, BackendCloseEntry, BackendCloseOutcome, BackendNativeDisposition, Core,
    CoreError, MAX_BATCH_BYTES, MAX_KEY_BYTES, MAX_VALUE_BYTES, Operation, ReadSnapshot,
    ResidentLease, StorageAdmission, StorageBackend,
};
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::{Bound, RangeFrom};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

const TABLE_TYPES: &str = "__kasumi_kv_table_types";
const MAX_TABLE_VALUE_BYTES: usize = MAX_VALUE_BYTES;
/// One staged row occupies a key and a value slot in its table's B-tree.
const STAGED_ROW_SLOT: usize = size_of::<Vec<u8>>() + size_of::<Option<Vec<u8>>>();
/// A B-tree node holds at most eleven rows and every node except the root
/// keeps at least five, so a row's share of leaf and internal nodes stays
/// below three slots. The key and value are charged at their exact lengths.
const STAGED_ROW_OVERHEAD: usize = 4 * STAGED_ROW_SLOT;
/// A table's first staged row also admits that table's root nodes and its
/// slot in the per-table map. The shared name is charged at its length.
const STAGED_TABLE_OVERHEAD: usize = 2048;
/// Staged rows draw on admitted chunks rather than one owner reservation per
/// row. A smaller exact reservation is tried when a whole chunk is denied.
const STAGING_CHUNK: usize = 64 << 10;
/// Each chunk also admits its slot in the lease vector, whose capacity may
/// double, before that vector grows.
const STAGING_LEASE_SLOT: usize = 2 * size_of::<Box<dyn ResidentLease>>();

pub struct RetainedBackendOwner(Option<Arc<dyn std::any::Any + Send + Sync>>);

impl Drop for RetainedBackendOwner {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            // An entered close did not prove native drain. Dropping the last
            // owner here could invoke an unobserved destructor close.
            std::mem::forget(owner);
        }
    }
}

/// Errors visible to storage callers. A retained owner stays in this error
/// when the backend cannot prove that native resources were drained.
pub enum StorageError {
    DatabaseClosed,
    Io(io::Error),
    UnknownCommit(io::Error),
    Core(CoreError),
    RetainedOwner {
        error: io::Error,
        _owner: RetainedBackendOwner,
    },
}

impl fmt::Debug for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseClosed => f.write_str("DatabaseClosed"),
            Self::Io(error) => f.debug_tuple("Io").field(error).finish(),
            Self::UnknownCommit(error) => f.debug_tuple("UnknownCommit").field(error).finish(),
            Self::Core(error) => f.debug_tuple("Core").field(error).finish(),
            Self::RetainedOwner { error, .. } => f
                .debug_struct("RetainedOwner")
                .field("error", error)
                .finish(),
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseClosed => f.write_str("database is closed"),
            Self::Io(error) => error.fmt(f),
            Self::UnknownCommit(error) => write!(f, "commit outcome is unknown: {error}"),
            Self::Core(error) => error.fmt(f),
            Self::RetainedOwner { error, .. } => {
                write!(f, "database backend remains retained: {error}")
            }
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DatabaseClosed => None,
            Self::Io(error) | Self::UnknownCommit(error) | Self::RetainedOwner { error, .. } => {
                Some(error)
            }
            Self::Core(error) => Some(error),
        }
    }
}

impl StorageError {
    /// A capacity denial decided before any backend effect. A writer that
    /// returns one has been rolled back whole and released its writer gate.
    pub fn is_capacity_denied(&self) -> bool {
        matches!(self, Self::Core(CoreError::CapacityDenied))
    }

    /// Errors that leave the physical owner or a backend effect uncertain.
    fn fences_owner(&self) -> bool {
        match self {
            Self::Io(_) | Self::UnknownCommit(_) | Self::RetainedOwner { .. } => true,
            Self::Core(error) => error.fences_owner(),
            Self::DatabaseClosed => false,
        }
    }
}

impl From<CoreError> for StorageError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::Io(error) => Self::Io(error),
            CoreError::UnknownCommit(error) => Self::UnknownCommit(error),
            CoreError::Closed => Self::DatabaseClosed,
            other => Self::Core(other),
        }
    }
}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

macro_rules! storage_wrapper {
    ($name:ident) => {
        #[derive(Debug)]
        pub struct $name(pub StorageError);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::error::Error for $name {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        impl From<StorageError> for $name {
            fn from(error: StorageError) -> Self {
                Self(error)
            }
        }

        impl From<CoreError> for $name {
            fn from(error: CoreError) -> Self {
                Self(error.into())
            }
        }
    };
}

storage_wrapper!(DatabaseError);
storage_wrapper!(TransactionError);
storage_wrapper!(CommitError);

#[derive(Debug)]
pub enum TableError {
    DoesNotExist(String),
    TypeMismatch(String),
    InvalidEncoding,
    Storage(StorageError),
}

impl fmt::Display for TableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DoesNotExist(name) => write!(f, "table does not exist: {name}"),
            Self::TypeMismatch(name) => write!(f, "table type differs: {name}"),
            Self::InvalidEncoding => f.write_str("table value encoding is invalid"),
            Self::Storage(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for TableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            _ => None,
        }
    }
}

impl TableError {
    /// A capacity denial decided before any backend effect. See
    /// [`StorageError::is_capacity_denied`].
    pub fn is_capacity_denied(&self) -> bool {
        matches!(self, Self::Storage(error) if error.is_capacity_denied())
    }
}

impl From<CoreError> for TableError {
    fn from(error: CoreError) -> Self {
        Self::Storage(error.into())
    }
}

impl From<StorageError> for TableError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

pub enum CloseError<T> {
    Busy(T),
    Storage(StorageError),
}

impl<T> fmt::Debug for CloseError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy(_) => f.write_str("Busy"),
            Self::Storage(error) => f.debug_tuple("Storage").field(error).finish(),
        }
    }
}

impl<T> fmt::Display for CloseError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy(_) => f.write_str("database still has active users"),
            Self::Storage(error) => error.fmt(f),
        }
    }
}

impl<T: Send + Sync + 'static> std::error::Error for CloseError<T> {}

/// The table codec determines an on-disk type tag and how keys and values are
/// passed to the table methods. Only the byte tables used in production and the
/// integer tables used by type-mismatch tests are supported.
pub trait TableCodec {
    type Input<'a>: Copy;
    type Owned;
    type View<'a>;

    const TAG: u8;
    fn encoded_len(input: Self::Input<'_>) -> usize;
    fn encoded_owned_len(value: &Self::Owned) -> usize;
    fn encode(input: Self::Input<'_>) -> Vec<u8>;
    fn encode_owned(value: &Self::Owned) -> Vec<u8>;
    fn decode(bytes: Vec<u8>) -> Result<Self::Owned, TableError>;
    fn view<'a>(value: &'a Self::Owned) -> Self::View<'a>;
}

impl TableCodec for &[u8] {
    type Input<'a> = &'a [u8];
    type Owned = Vec<u8>;
    type View<'a> = &'a [u8];
    const TAG: u8 = 1;

    fn encoded_len(input: Self::Input<'_>) -> usize {
        input.len()
    }

    fn encoded_owned_len(value: &Self::Owned) -> usize {
        value.len()
    }

    fn encode(input: Self::Input<'_>) -> Vec<u8> {
        input.to_vec()
    }

    fn encode_owned(value: &Self::Owned) -> Vec<u8> {
        value.clone()
    }

    fn decode(bytes: Vec<u8>) -> Result<Self::Owned, TableError> {
        Ok(bytes)
    }

    fn view<'a>(value: &'a Self::Owned) -> Self::View<'a> {
        value
    }
}

impl TableCodec for u64 {
    type Input<'a> = u64;
    type Owned = u64;
    type View<'a> = u64;
    const TAG: u8 = 2;

    fn encoded_len(_input: Self::Input<'_>) -> usize {
        8
    }

    fn encoded_owned_len(_value: &Self::Owned) -> usize {
        8
    }

    fn encode(input: Self::Input<'_>) -> Vec<u8> {
        input.to_be_bytes().to_vec()
    }

    fn encode_owned(value: &Self::Owned) -> Vec<u8> {
        value.to_be_bytes().to_vec()
    }

    fn decode(bytes: Vec<u8>) -> Result<Self::Owned, TableError> {
        let array: [u8; 8] = bytes.try_into().map_err(|_| TableError::InvalidEncoding)?;
        Ok(u64::from_be_bytes(array))
    }

    fn view<'a>(value: &'a Self::Owned) -> Self::View<'a> {
        *value
    }
}

pub struct TableDefinition<K: TableCodec, V: TableCodec> {
    name: &'static str,
    _codec: PhantomData<fn() -> (K, V)>,
}

impl<K: TableCodec, V: TableCodec> Copy for TableDefinition<K, V> {}

impl<K: TableCodec, V: TableCodec> Clone for TableDefinition<K, V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: TableCodec, V: TableCodec> TableDefinition<K, V> {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            _codec: PhantomData,
        }
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    fn tags(&self) -> [u8; 2] {
        [K::TAG, V::TAG]
    }
}

pub struct AccessGuard<T: TableCodec> {
    value: T::Owned,
    _lease: Box<dyn ResidentLease>,
    // The guard may outlive its table and transaction facade. Keep the exact
    // snapshot live until both its owned value and resident lease are gone.
    _snapshot: Arc<ReadSnapshot>,
}

impl<T: TableCodec> AccessGuard<T> {
    fn decode_parts(
        (bytes, lease): LeasedBytes,
        snapshot: &Arc<ReadSnapshot>,
    ) -> Result<Self, TableError> {
        Ok(Self {
            value: T::decode(bytes)?,
            _lease: lease,
            _snapshot: snapshot.clone(),
        })
    }

    fn decode_admitted(
        value: AdmittedValue,
        snapshot: &Arc<ReadSnapshot>,
    ) -> Result<Self, TableError> {
        Self::decode_parts(value.into_parts(), snapshot)
    }

    pub fn value(&self) -> T::View<'_> {
        T::view(&self.value)
    }
}

type LeasedBytes = (Vec<u8>, Box<dyn ResidentLease>);
pub type OwnedByteRow = (AdmittedValue, AdmittedValue);
pub type TableRow<K, V> = (AccessGuard<K>, AccessGuard<V>);

fn check_key_bound<K: TableCodec>(key: K::Input<'_>) -> Result<(), TableError> {
    if K::encoded_len(key) > MAX_KEY_BYTES {
        return Err(CoreError::InvalidInput("table key exceeds storage limit").into());
    }
    Ok(())
}

fn admit_clone(core: &Core, bytes: &[u8]) -> Result<LeasedBytes, TableError> {
    let charge = bytes.len().saturating_add(128);
    let lease = core.reserve_workspace(charge as u64)?;
    Ok((bytes.to_vec(), lease))
}

/// Checked staging charge of one row: its exact key and value bytes plus
/// its share of the staged B-tree.
fn staged_row_charge(key_len: usize, value_len: usize) -> Result<usize, TableError> {
    key_len
        .checked_add(value_len)
        .and_then(|bytes| bytes.checked_add(STAGED_ROW_OVERHEAD))
        .ok_or_else(|| CoreError::CapacityDenied.into())
}

/// Commit workspace beyond the rows, which move from staging uncopied: the
/// operation vector, the shared type-table name, and each created table's
/// type row.
fn materialization_charge(
    operations: usize,
    created: &BTreeMap<Arc<str>, [u8; 2]>,
) -> Result<u64, CoreError> {
    let mut bytes = operations.checked_mul(size_of::<Operation>());
    if !created.is_empty() {
        bytes = bytes.and_then(|bytes| bytes.checked_add(shared_name_charge(TABLE_TYPES.len())));
        for name in created.keys() {
            bytes = bytes
                .and_then(|bytes| bytes.checked_add(name.len()))
                .and_then(|bytes| bytes.checked_add(size_of::<[u8; 2]>()));
        }
    }
    bytes
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(CoreError::CapacityDenied)
}

/// An `Arc<str>` allocation: its two reference counts and the name bytes.
const fn shared_name_charge(len: usize) -> usize {
    2 * size_of::<AtomicUsize>() + len
}

fn lock(staged: &Mutex<Pending>) -> MutexGuard<'_, Pending> {
    staged
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Run one staging step of a writer and settle its failure: the first
/// capacity denial rolls the whole transaction back, and an owner failure
/// keeps it retained. The discarded batch drops after the lock is released.
fn staged_step<T>(
    core: &Core,
    staged: &Mutex<Pending>,
    step: impl FnOnce() -> Result<T, TableError>,
) -> Result<T, TableError> {
    let result = step();
    if let Err(error) = &result {
        let discarded = lock(staged).settle(core, error);
        drop(discarded);
    }
    result
}

pub struct Builder {
    admission: Arc<dyn StorageAdmission>,
}

impl Builder {
    pub fn admission(&self) -> Arc<dyn StorageAdmission> {
        self.admission.clone()
    }

    pub fn with_admission(mut self, admission: Arc<dyn StorageAdmission>) -> Self {
        self.admission = admission;
        self
    }

    pub fn create_with_backend(
        self,
        backend: impl StorageBackend + 'static,
    ) -> Result<Database, DatabaseError> {
        let admission = self.admission.clone();
        Ok(Database::from_core(
            Core::create_with_backend(backend, self.admission)?,
            admission,
        ))
    }

    pub fn create_strict_with_backend(
        self,
        backend: impl StorageBackend + 'static,
    ) -> Result<Database, DatabaseError> {
        let admission = self.admission.clone();
        Ok(Database::from_core(
            Core::create_strict_with_backend(backend, self.admission)?,
            admission,
        ))
    }

    pub(crate) fn create_strict_with_backend_retained(
        self,
        backend: impl StorageBackend + 'static,
    ) -> Result<Database, DatabaseError> {
        let admission = self.admission.clone();
        Ok(Database::from_core(
            Core::create_strict_with_backend_retained(backend, self.admission)?,
            admission,
        ))
    }

    pub fn open_with_backend(
        self,
        backend: impl StorageBackend + 'static,
    ) -> Result<Database, DatabaseError> {
        let admission = self.admission.clone();
        Ok(Database::from_core(
            Core::open_with_backend(backend, self.admission)?,
            admission,
        ))
    }

    pub(crate) fn open_with_backend_retained(
        self,
        backend: impl StorageBackend + 'static,
    ) -> Result<Database, DatabaseError> {
        let admission = self.admission.clone();
        Ok(Database::from_core(
            Core::open_with_backend_retained(backend, self.admission)?,
            admission,
        ))
    }
}

struct WriterGate {
    held: Mutex<bool>,
    changed: Condvar,
}

impl WriterGate {
    fn enter(self: &Arc<Self>, closing: &AtomicBool) -> Result<WriterLease, TransactionError> {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *held {
            if closing.load(Ordering::Acquire) {
                return Err(StorageError::DatabaseClosed.into());
            }
            held = self
                .changed
                .wait(held)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        if closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed.into());
        }
        *held = true;
        Ok(WriterLease { gate: self.clone() })
    }
}

struct WriterLease {
    gate: Arc<WriterGate>,
}

impl Drop for WriterLease {
    fn drop(&mut self) {
        let mut held = self
            .gate
            .held
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *held = false;
        self.gate.changed.notify_one();
    }
}

struct DatabaseInner {
    core: Arc<Core>,
    admission: Arc<dyn StorageAdmission>,
    gate: Arc<WriterGate>,
    closing: AtomicBool,
}

pub struct Database {
    inner: Arc<DatabaseInner>,
}

/// A borrowed transaction admission kept alive independently of a database
/// owner's close mutex. A pending writer counts as live work; sealing the
/// database wakes it before physical close can proceed.
pub struct DatabaseTransactionAdmission {
    inner: Arc<DatabaseInner>,
}

impl DatabaseTransactionAdmission {
    pub fn begin_read(&self) -> Result<ReadTransaction, TransactionError> {
        Database {
            inner: self.inner.clone(),
        }
        .begin_read()
    }

    pub fn begin_write(&self) -> Result<WriteTransaction, TransactionError> {
        Database {
            inner: self.inner.clone(),
        }
        .begin_write()
    }
}

impl Database {
    pub fn builder(admission: Arc<dyn StorageAdmission>) -> Builder {
        Builder { admission }
    }

    pub(crate) fn from_core(core: Core, admission: Arc<dyn StorageAdmission>) -> Self {
        Self {
            inner: Arc::new(DatabaseInner {
                core: Arc::new(core),
                admission,
                gate: Arc::new(WriterGate {
                    held: Mutex::new(false),
                    changed: Condvar::new(),
                }),
                closing: AtomicBool::new(false),
            }),
        }
    }

    pub(crate) fn admission(&self) -> Arc<dyn StorageAdmission> {
        self.inner.admission.clone()
    }

    pub fn transaction_admission(&self) -> DatabaseTransactionAdmission {
        DatabaseTransactionAdmission {
            inner: self.inner.clone(),
        }
    }

    pub fn active_transactions(&self) -> usize {
        Arc::strong_count(&self.inner).saturating_sub(1)
    }

    fn seal(&self) {
        // Share the waiter's mutex while changing its predicate. Otherwise a
        // close between its check and condvar wait can lose the wakeup.
        let _held = self
            .inner
            .gate
            .held
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.inner.closing.store(true, Ordering::Release);
        self.inner.gate.changed.notify_all();
    }

    pub fn begin_read(&self) -> Result<ReadTransaction, TransactionError> {
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed.into());
        }
        let snapshot = Arc::new(self.inner.core.snapshot()?);
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed.into());
        }
        Ok(ReadTransaction {
            inner: self.inner.clone(),
            snapshot,
        })
    }

    pub fn begin_write(&self) -> Result<WriteTransaction, TransactionError> {
        let lease = self.inner.gate.enter(&self.inner.closing)?;
        self.inner.core.prepare_write()?;
        let snapshot = Arc::new(self.inner.core.snapshot()?);
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed.into());
        }
        Ok(WriteTransaction {
            inner: self.inner.clone(),
            snapshot,
            staged: Arc::new(Mutex::new(Pending::new(lease))),
            terminal: false,
        })
    }

    /// Seal admission before inspecting live handles. A retained outcome is
    /// reported without invoking the physical backend while a handle survives.
    pub fn close_native(&self) -> BackendCloseOutcome {
        self.seal();
        if self.active_transactions() != 0 {
            return BackendCloseOutcome::not_entered(io::Error::from(io::ErrorKind::WouldBlock));
        }
        self.inner.core.close()
    }

    pub fn close(self) -> Result<(), CloseError<Self>> {
        self.seal();
        if self.active_transactions() != 0 {
            return Err(CloseError::Busy(self));
        }
        let outcome = match catch_unwind(AssertUnwindSafe(|| self.inner.core.close())) {
            Ok(outcome) => outcome,
            Err(payload) => {
                // There is no evidence that native close drained. The outer
                // owner records the panic; this engine owner must remain live.
                std::mem::forget(self);
                resume_unwind(payload);
            }
        };
        let entry = outcome.entry();
        let disposition = outcome.native_disposition();
        match outcome.into_result() {
            Err(_) if entry == BackendCloseEntry::NotEntered => Err(CloseError::Busy(self)),
            Ok(()) if disposition == BackendNativeDisposition::Drained => Ok(()),
            Err(error) if disposition == BackendNativeDisposition::Drained => {
                Err(CloseError::Storage(StorageError::Io(error)))
            }
            result => {
                let error = result.err().unwrap_or_else(|| {
                    io::Error::other("backend close did not prove native drain")
                });
                Err(CloseError::Storage(StorageError::RetainedOwner {
                    error,
                    _owner: RetainedBackendOwner(Some(self.inner.clone())),
                }))
            }
        }
    }
}

/// Kept for APIs that require a readable database bound. `Database` supplies
/// the inherent operation so callers need no trait import.
pub trait ReadableDatabase {
    fn begin_read(&self) -> Result<ReadTransaction, TransactionError>;
}

impl ReadableDatabase for Database {
    fn begin_read(&self) -> Result<ReadTransaction, TransactionError> {
        Database::begin_read(self)
    }
}

fn check_table_type<K: TableCodec, V: TableCodec>(
    core: &Core,
    snapshot: &ReadSnapshot,
    definition: TableDefinition<K, V>,
) -> Result<(), TableError> {
    let name = definition.name();
    if name == TABLE_TYPES || name.is_empty() || name.len() > 128 {
        return Err(TableError::TypeMismatch(name.to_owned()));
    }
    if !snapshot.table_exists(name)? {
        return Err(TableError::DoesNotExist(name.to_owned()));
    }
    if !snapshot.table_exists(TABLE_TYPES)? {
        return Err(TableError::TypeMismatch(name.to_owned()));
    }
    let actual = core
        .get_admitted(snapshot, TABLE_TYPES, name.as_bytes(), 2)?
        .map(AdmittedValue::into_parts);
    if actual.as_ref().map(|(bytes, _lease)| bytes.as_slice()) != Some(definition.tags().as_slice())
    {
        return Err(TableError::TypeMismatch(name.to_owned()));
    }
    Ok(())
}

pub struct ReadTransaction {
    inner: Arc<DatabaseInner>,
    snapshot: Arc<ReadSnapshot>,
}

impl ReadTransaction {
    pub fn belongs_to(&self, database: &Database) -> bool {
        Arc::ptr_eq(&self.inner, &database.inner)
    }

    /// Tables, ranges and admitted access guards all carry this exact Arc.
    /// A count of one cannot race a new descendant without another owner of
    /// this same snapshot from which to clone it.
    pub(crate) fn has_snapshot_descendants(&self) -> bool {
        Arc::strong_count(&self.snapshot) != 1
    }

    pub fn open_table<K: TableCodec, V: TableCodec>(
        &self,
        definition: TableDefinition<K, V>,
    ) -> Result<ReadOnlyTable<K, V>, TableError> {
        check_table_type(&self.inner.core, &self.snapshot, definition)?;
        Ok(ReadOnlyTable {
            inner: self.inner.clone(),
            snapshot: self.snapshot.clone(),
            name: Arc::from(definition.name()),
            _codec: PhantomData,
        })
    }

    /// Point read through the pinned index. The returned value retains its
    /// resident admission until the caller drops it.
    pub fn get_bytes(
        &self,
        table: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<AdmittedValue>, CoreError> {
        self.inner
            .core
            .get_admitted(&self.snapshot, table, key, max_value_bytes)
    }

    pub fn key_exists(&self, table: &str, key: &[u8]) -> Result<bool, CoreError> {
        self.inner.core.key_exists(&self.snapshot, table, key)
    }

    pub fn prefix_exists(&self, table: &str, prefix: &[u8]) -> Result<bool, CoreError> {
        self.inner.core.prefix_exists(&self.snapshot, table, prefix)
    }

    pub fn next_bytes(
        &self,
        table: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        max_value_bytes: usize,
    ) -> Result<Option<OwnedByteRow>, CoreError> {
        self.inner
            .core
            .next_admitted(&self.snapshot, table, prefix, after, max_value_bytes)
    }
}

/// Staged rows by table. A `None` value is a tombstone.
type StagedRows = BTreeMap<Arc<str>, BTreeMap<Vec<u8>, Option<Vec<u8>>>>;

/// Where a writer's staged batch stands. Only a capacity denial settles a
/// writer before publication; an uncertain owner keeps it retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Staging {
    Active,
    /// The first capacity denial dropped the whole batch, its leases and the
    /// writer gate. Every later call repeats that denial without an effect.
    RolledBack,
    /// An owner failure or uncertain I/O fenced the core. The batch, its
    /// leases and the writer gate stay with the transaction.
    Failed,
    /// Commit, abort or drop has taken the batch.
    Terminal,
}

/// Admitted staging memory. Rows consume logical credit from chunks, and
/// every chunk stays leased until the whole batch leaves the transaction.
#[derive(Default)]
struct StagingCredit {
    leases: Vec<Box<dyn ResidentLease>>,
    reserved: usize,
    used: usize,
}

/// A batch taken out of its transaction. Fields drop in order: the staged
/// rows before the credit that admitted them, and the writer gate last.
struct Discarded {
    _created: BTreeMap<Arc<str>, [u8; 2]>,
    _writes: StagedRows,
    _credit: StagingCredit,
    _writer: Option<WriterLease>,
}

struct Pending {
    created: BTreeMap<Arc<str>, [u8; 2]>,
    writes: StagedRows,
    credit: StagingCredit,
    // The writer gate is held here rather than by the transaction facade, so
    // a rollback from any table handle releases it immediately.
    writer: Option<WriterLease>,
    staging: Staging,
}

impl Pending {
    fn new(writer: WriterLease) -> Self {
        Self {
            created: BTreeMap::new(),
            writes: BTreeMap::new(),
            credit: StagingCredit::default(),
            writer: Some(writer),
            staging: Staging::Active,
        }
    }

    fn ensure_active(&self) -> Result<(), TableError> {
        match self.staging {
            Staging::Active => Ok(()),
            Staging::RolledBack => Err(CoreError::CapacityDenied.into()),
            Staging::Failed => Err(CoreError::OwnerFailed.into()),
            Staging::Terminal => Err(TableError::Storage(StorageError::DatabaseClosed)),
        }
    }

    /// Admit `bytes` more staged memory. The staged batch as a whole stays
    /// within the physical batch bound.
    fn reserve(&mut self, core: &Core, bytes: usize) -> Result<(), TableError> {
        let used = self
            .credit
            .used
            .checked_add(bytes)
            .filter(|used| *used <= MAX_BATCH_BYTES)
            .ok_or(CoreError::CapacityDenied)?;
        if used > self.credit.reserved {
            let deficit = used - self.credit.reserved;
            let desired = deficit.max(STAGING_CHUNK);
            let (credit, lease) =
                match core.reserve_workspace((desired + STAGING_LEASE_SLOT) as u64) {
                    Ok(lease) => (desired, lease),
                    Err(CoreError::CapacityDenied) if desired > deficit => (
                        deficit,
                        core.reserve_workspace((deficit + STAGING_LEASE_SLOT) as u64)?,
                    ),
                    Err(error) => return Err(error.into()),
                };
            self.credit
                .leases
                .try_reserve(1)
                .map_err(|_| CoreError::CapacityDenied)?;
            self.credit.leases.push(lease);
            self.credit.reserved += credit;
        }
        self.credit.used = used;
        Ok(())
    }

    /// Admit one staged row, and on a table's first row that table's own
    /// staging structure and shared name.
    fn reserve_row(&mut self, core: &Core, table: &str, row: usize) -> Result<(), TableError> {
        let charge = if self.writes.contains_key(table) {
            Some(row)
        } else {
            row.checked_add(STAGED_TABLE_OVERHEAD)
                .and_then(|bytes| bytes.checked_add(shared_name_charge(table.len())))
        };
        self.reserve(core, charge.ok_or(CoreError::CapacityDenied)?)
    }

    fn stage(&mut self, table: &Arc<str>, key: Vec<u8>, value: Option<Vec<u8>>) {
        self.writes
            .entry(table.clone())
            .or_default()
            .insert(key, value);
    }

    fn discard(&mut self) -> Discarded {
        Discarded {
            _created: std::mem::take(&mut self.created),
            _writes: std::mem::take(&mut self.writes),
            _credit: std::mem::take(&mut self.credit),
            _writer: self.writer.take(),
        }
    }

    /// Settle a failed staging step of an active writer. An owner failure or
    /// uncertain I/O fences the core and keeps the batch and writer gate. The
    /// first capacity denial otherwise rolls the whole batch back before any
    /// effect and releases the gate. Other errors leave the writer active.
    fn settle(&mut self, core: &Core, error: &TableError) -> Option<Discarded> {
        if self.staging != Staging::Active {
            return None;
        }
        let fences = matches!(error, TableError::Storage(error) if error.fences_owner());
        if core.is_fenced() || fences {
            core.fence();
            self.staging = Staging::Failed;
            None
        } else if error.is_capacity_denied() {
            self.staging = Staging::RolledBack;
            Some(self.discard())
        } else {
            None
        }
    }
}

pub struct WriteTransaction {
    inner: Arc<DatabaseInner>,
    snapshot: Arc<ReadSnapshot>,
    staged: Arc<Mutex<Pending>>,
    terminal: bool,
}

impl WriteTransaction {
    pub fn belongs_to(&self, database: &Database) -> bool {
        Arc::ptr_eq(&self.inner, &database.inner)
    }

    /// Whether this transaction still holds the database's writer gate. A
    /// terminal that released it has settled: it published, or it was
    /// rejected before any effect.
    pub(crate) fn holds_writer(&self) -> bool {
        lock(&self.staged).writer.is_some()
    }

    pub fn open_table<K: TableCodec, V: TableCodec>(
        &self,
        definition: TableDefinition<K, V>,
    ) -> Result<Table<K, V>, TableError> {
        let name = definition.name();
        if name == TABLE_TYPES || name.is_empty() || name.len() > 128 {
            return Err(TableError::TypeMismatch(name.to_owned()));
        }
        let name: Arc<str> = Arc::from(name);
        staged_step(&self.inner.core, &self.staged, || {
            let mut pending = lock(&self.staged);
            pending.ensure_active()?;
            self.inner.core.check_read_owner()?;
            if let Some(tags) = pending.created.get(&*name) {
                if *tags != definition.tags() {
                    return Err(TableError::TypeMismatch(name.to_string()));
                }
            } else if self.snapshot.table_exists(&name)? {
                check_table_type(&self.inner.core, &self.snapshot, definition)?;
            } else {
                pending.reserve(&self.inner.core, name.len().saturating_add(512))?;
                pending.created.insert(name.clone(), definition.tags());
            }
            Ok(())
        })?;
        Ok(Table {
            inner: self.inner.clone(),
            snapshot: self.snapshot.clone(),
            staged: self.staged.clone(),
            name,
            _codec: PhantomData,
        })
    }

    /// Mark terminal before entering the durable commit. A failed or panicked
    /// retained call cannot replay the same batch. A rejection decided while
    /// the core stays unfenced had no effect and releases the writer gate; an
    /// owner failure or unknown outcome keeps the gate with this transaction.
    pub(crate) fn commit_inner(&mut self) -> Result<(), CoreError> {
        if self.terminal {
            return Err(CoreError::Closed);
        }
        self.terminal = true;
        let mut pending = lock(&self.staged);
        match pending.staging {
            Staging::Active => {}
            // Rolled back before publication: repeat the original denial.
            Staging::RolledBack => return Err(CoreError::CapacityDenied),
            Staging::Failed => return Err(CoreError::OwnerFailed),
            Staging::Terminal => return Err(CoreError::Closed),
        }
        pending.staging = Staging::Terminal;
        let created = std::mem::take(&mut pending.created);
        let writes = std::mem::take(&mut pending.writes);
        let credit = std::mem::take(&mut pending.credit);
        drop(pending);

        let result = self.publish(created, writes);
        // Every staged row has dropped with its operation by now.
        drop(credit);
        let uncertain = result
            .as_ref()
            .is_err_and(|error| self.inner.core.is_fenced() || error.fences_owner());
        if uncertain {
            self.inner.core.fence();
        } else {
            let writer = lock(&self.staged).writer.take();
            drop(writer);
        }
        result
    }

    /// Materialize the staged batch as one admitted operation vector and
    /// commit it. Rows move into their operations without copying, and each
    /// table's name is shared by its rows. The vector is admitted before it
    /// is allocated and drops before its lease; a denial has no effect.
    fn publish(
        &self,
        created: BTreeMap<Arc<str>, [u8; 2]>,
        writes: StagedRows,
    ) -> Result<(), CoreError> {
        let create_types = !created.is_empty() && !self.snapshot.table_exists(TABLE_TYPES)?;
        let rows = writes
            .values()
            .try_fold(0usize, |rows, table| rows.checked_add(table.len()))
            .ok_or(CoreError::CapacityDenied)?;
        let count = created
            .len()
            .checked_mul(2)
            .and_then(|count| count.checked_add(rows))
            .and_then(|count| count.checked_add(usize::from(create_types)))
            .ok_or(CoreError::CapacityDenied)?;
        if count == 0 {
            return self.inner.core.check_owner();
        }
        let _workspace = self
            .inner
            .core
            .reserve_workspace(materialization_charge(count, &created)?)?;
        let mut operations = Vec::new();
        operations
            .try_reserve_exact(count)
            .map_err(|_| CoreError::CapacityDenied)?;
        if !created.is_empty() {
            let types: Arc<str> = Arc::from(TABLE_TYPES);
            if create_types {
                operations.push(Operation::CreateTable {
                    table: types.clone(),
                });
            }
            for (name, tags) in created {
                let key = name.as_bytes().to_vec();
                operations.push(Operation::CreateTable { table: name });
                operations.push(Operation::Put {
                    table: types.clone(),
                    key,
                    value: tags.to_vec(),
                });
            }
        }
        for (table, rows) in writes {
            for (key, value) in rows {
                operations.push(match value {
                    Some(value) => Operation::Put {
                        table: table.clone(),
                        key,
                        value,
                    },
                    None => Operation::Delete {
                        table: table.clone(),
                        key,
                    },
                });
            }
        }
        debug_assert_eq!(operations.len(), count);
        let result = self.inner.core.commit(&operations);
        drop(operations);
        result
    }

    pub(crate) fn abort_inner(&mut self) -> Result<(), CoreError> {
        if self.terminal {
            return Err(CoreError::Closed);
        }
        self.terminal = true;
        let mut pending = lock(&self.staged);
        match pending.staging {
            Staging::Active => {}
            // The first capacity denial already discarded the batch and
            // released the writer gate; there is nothing left to abort.
            Staging::RolledBack => return Ok(()),
            Staging::Failed => return Err(CoreError::OwnerFailed),
            Staging::Terminal => return Err(CoreError::Closed),
        }
        pending.staging = Staging::Terminal;
        drop(pending);
        // A failed physical owner makes even a requested abort uncertain. The
        // retained transaction keeps its writer lease and original staging.
        self.inner.core.check_owner()?;
        let discarded = lock(&self.staged).discard();
        drop(discarded);
        Ok(())
    }

    pub fn commit(mut self) -> Result<(), CommitError> {
        self.commit_inner().map_err(Into::into)
    }

    pub fn abort(mut self) -> Result<(), StorageError> {
        self.abort_inner().map_err(Into::into)
    }
}

impl Drop for WriteTransaction {
    /// The writer gate never outlives its transaction, even while a table
    /// handle keeps the staged batch reachable. An unfinished batch is
    /// discarded with it and never published.
    fn drop(&mut self) {
        let mut pending = lock(&self.staged);
        if pending.staging == Staging::Active {
            pending.staging = Staging::Terminal;
        }
        let discarded = pending.discard();
        drop(pending);
        drop(discarded);
    }
}

fn current_bytes(
    inner: &DatabaseInner,
    snapshot: &ReadSnapshot,
    staged: &Mutex<Pending>,
    table: &str,
    key: &[u8],
) -> Result<Option<LeasedBytes>, TableError> {
    let pending = lock(staged);
    pending.ensure_active()?;
    inner.core.check_read_owner()?;
    if let Some(entry) = pending
        .writes
        .get(table)
        .and_then(|entries| entries.get(key))
    {
        return entry
            .as_deref()
            .map(|value| admit_clone(&inner.core, value))
            .transpose();
    }
    let newly_created = pending.created.contains_key(table);
    drop(pending);
    if newly_created {
        Ok(None)
    } else {
        inner
            .core
            .get_admitted(snapshot, table, key, MAX_TABLE_VALUE_BYTES)
            .map(|value| value.map(AdmittedValue::into_parts))
            .map_err(Into::into)
    }
}

/// A writable table owns only handles to its transaction's staged changes.
/// Dropping it never publishes a write.
pub struct Table<K: TableCodec, V: TableCodec> {
    inner: Arc<DatabaseInner>,
    snapshot: Arc<ReadSnapshot>,
    staged: Arc<Mutex<Pending>>,
    name: Arc<str>,
    _codec: PhantomData<fn() -> (K, V)>,
}

impl<K: TableCodec, V: TableCodec> Table<K, V> {
    fn step<T>(&self, step: impl FnOnce() -> Result<T, TableError>) -> Result<T, TableError> {
        staged_step(&self.inner.core, &self.staged, step)
    }

    pub fn get(&self, key: K::Input<'_>) -> Result<Option<AccessGuard<V>>, TableError> {
        check_key_bound::<K>(key)?;
        self.step(|| {
            current_bytes(
                &self.inner,
                &self.snapshot,
                &self.staged,
                &self.name,
                &K::encode(key),
            )?
            .map(|parts| AccessGuard::decode_parts(parts, &self.snapshot))
            .transpose()
        })
    }

    pub fn insert(
        &mut self,
        key: K::Input<'_>,
        value: V::Input<'_>,
    ) -> Result<Option<AccessGuard<V>>, TableError> {
        self.step(|| {
            let charge = staged_row_charge(K::encoded_len(key), V::encoded_len(value))?;
            {
                let mut pending = lock(&self.staged);
                pending.ensure_active()?;
                pending.reserve_row(&self.inner.core, &self.name, charge)?;
            }
            let key = K::encode(key);
            let old = current_bytes(&self.inner, &self.snapshot, &self.staged, &self.name, &key)?
                .map(|parts| AccessGuard::decode_parts(parts, &self.snapshot))
                .transpose()?;
            let mut pending = lock(&self.staged);
            pending.ensure_active()?;
            pending.stage(&self.name, key, Some(V::encode(value)));
            Ok(old)
        })
    }

    pub fn remove(&mut self, key: K::Input<'_>) -> Result<Option<AccessGuard<V>>, TableError> {
        self.step(|| {
            let charge = staged_row_charge(K::encoded_len(key), 0)?;
            {
                let mut pending = lock(&self.staged);
                pending.ensure_active()?;
                pending.reserve_row(&self.inner.core, &self.name, charge)?;
            }
            let key = K::encode(key);
            let old = current_bytes(&self.inner, &self.snapshot, &self.staged, &self.name, &key)?
                .map(|parts| AccessGuard::decode_parts(parts, &self.snapshot))
                .transpose()?;
            let mut pending = lock(&self.staged);
            pending.ensure_active()?;
            pending.stage(&self.name, key, None);
            Ok(old)
        })
    }

    /// Stage a tombstone without reading or admitting the prior value. This
    /// is idempotent for an absent key; the caller does not receive old bytes.
    pub fn delete_key(&mut self, key: K::Input<'_>) -> Result<(), TableError> {
        check_key_bound::<K>(key)?;
        self.step(|| {
            let charge = staged_row_charge(K::encoded_len(key), 0)?;
            self.inner.core.check_read_owner()?;
            let mut pending = lock(&self.staged);
            pending.ensure_active()?;
            pending.reserve_row(&self.inner.core, &self.name, charge)?;
            pending.stage(&self.name, K::encode(key), None);
            Ok(())
        })
    }

    pub fn range(&self, range: RangeFrom<K::Input<'_>>) -> Result<TableRange<K, V>, TableError> {
        check_key_bound::<K>(range.start)?;
        self.step(|| {
            lock(&self.staged).ensure_active()?;
            TableRange::new(
                self.inner.clone(),
                self.snapshot.clone(),
                Some(self.staged.clone()),
                self.name.clone(),
                K::encode(range.start),
            )
        })
    }

    pub fn iter(&self) -> Result<TableRange<K, V>, TableError> {
        self.step(|| {
            lock(&self.staged).ensure_active()?;
            TableRange::new(
                self.inner.clone(),
                self.snapshot.clone(),
                Some(self.staged.clone()),
                self.name.clone(),
                Vec::new(),
            )
        })
    }

    pub fn retain_in(
        &mut self,
        range: RangeFrom<K::Input<'_>>,
        mut keep: impl FnMut(K::View<'_>, V::View<'_>) -> bool,
    ) -> Result<(), TableError> {
        for entry in self.range(range)? {
            let (key, value) = entry?;
            if !keep(key.value(), value.value()) {
                self.step(|| {
                    let charge = staged_row_charge(K::encoded_owned_len(&key.value), 0)?;
                    let mut pending = lock(&self.staged);
                    pending.ensure_active()?;
                    pending.reserve_row(&self.inner.core, &self.name, charge)?;
                    pending.stage(&self.name, K::encode_owned(&key.value), None);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }
}

pub struct ReadOnlyTable<K: TableCodec, V: TableCodec> {
    inner: Arc<DatabaseInner>,
    snapshot: Arc<ReadSnapshot>,
    name: Arc<str>,
    _codec: PhantomData<fn() -> (K, V)>,
}

impl<K: TableCodec, V: TableCodec> ReadOnlyTable<K, V> {
    pub fn get(&self, key: K::Input<'_>) -> Result<Option<AccessGuard<V>>, TableError> {
        check_key_bound::<K>(key)?;
        self.inner
            .core
            .get_admitted(
                &self.snapshot,
                &self.name,
                &K::encode(key),
                MAX_TABLE_VALUE_BYTES,
            )?
            .map(|value| AccessGuard::decode_admitted(value, &self.snapshot))
            .transpose()
    }

    pub fn range(&self, range: RangeFrom<K::Input<'_>>) -> Result<TableRange<K, V>, TableError> {
        check_key_bound::<K>(range.start)?;
        TableRange::new(
            self.inner.clone(),
            self.snapshot.clone(),
            None,
            self.name.clone(),
            K::encode(range.start),
        )
    }

    pub fn iter(&self) -> Result<TableRange<K, V>, TableError> {
        TableRange::new(
            self.inner.clone(),
            self.snapshot.clone(),
            None,
            self.name.clone(),
            Vec::new(),
        )
    }
}

pub trait ReadableTable<K: TableCodec, V: TableCodec> {}
impl<K: TableCodec, V: TableCodec> ReadableTable<K, V> for Table<K, V> {}
impl<K: TableCodec, V: TableCodec> ReadableTable<K, V> for ReadOnlyTable<K, V> {}

/// Ordered iterator over one immutable snapshot plus a writer's staged overlay.
/// One value at a time is materialized from the backend.
pub struct TableRange<K: TableCodec, V: TableCodec> {
    inner: Arc<DatabaseInner>,
    snapshot: Arc<ReadSnapshot>,
    staged: Option<Arc<Mutex<Pending>>>,
    table: Arc<str>,
    start: Vec<u8>,
    after: Option<Vec<u8>>,
    _range_lease: Box<dyn ResidentLease>,
    cursor_lease: Option<Box<dyn ResidentLease>>,
    done: bool,
    _codec: PhantomData<fn() -> (K, V)>,
}

impl<K: TableCodec, V: TableCodec> TableRange<K, V> {
    fn new(
        inner: Arc<DatabaseInner>,
        snapshot: Arc<ReadSnapshot>,
        staged: Option<Arc<Mutex<Pending>>>,
        table: Arc<str>,
        start: Vec<u8>,
    ) -> Result<Self, TableError> {
        inner.core.check_read_owner()?;
        let charge = start.len().saturating_add(table.len()).saturating_add(256);
        let lease = inner.core.reserve_workspace(charge as u64)?;
        Ok(Self {
            inner,
            snapshot,
            staged,
            table,
            start,
            after: None,
            _range_lease: lease,
            cursor_lease: None,
            done: false,
            _codec: PhantomData,
        })
    }

    fn next_entry(&mut self) -> Result<Option<TableRow<K, V>>, TableError> {
        loop {
            self.inner.core.check_read_owner()?;
            let new_table = self
                .staged
                .as_ref()
                .is_some_and(|staged| lock(staged).created.contains_key(&*self.table));
            let base_key = if new_table {
                None
            } else {
                self.snapshot
                    .next_key_admitted(&self.table, &self.start, self.after.as_deref())?
                    .map(AdmittedValue::into_parts)
            };
            let (staged_key, staged_value) = if let Some(staged) = &self.staged {
                let pending = lock(staged);
                pending.ensure_active()?;
                let start = match self.after.as_deref() {
                    Some(after) if after >= self.start.as_slice() => Bound::Excluded(after),
                    _ => Bound::Included(self.start.as_slice()),
                };
                pending
                    .writes
                    .get(&*self.table)
                    .and_then(|writes| writes.range::<[u8], _>((start, Bound::Unbounded)).next())
                    .map(|(key, value)| -> Result<_, TableError> {
                        let key = admit_clone(&self.inner.core, key)?;
                        let value = value
                            .as_deref()
                            .map(|value| admit_clone(&self.inner.core, value))
                            .transpose()?;
                        Ok((Some(key), Some(value)))
                    })
                    .transpose()?
                    .unwrap_or((None, None))
            } else {
                (None, None)
            };
            let (key, staged_for_key) = match (base_key, staged_key) {
                (None, None) => return Ok(None),
                (Some(key), None) => (key, None),
                (None, Some(key)) => (key, staged_value),
                (Some(base), Some(staged)) if base.0 < staged.0 => (base, None),
                (Some(base), Some(staged)) if base.0 == staged.0 => (base, staged_value),
                (Some(_), Some(staged)) => (staged, staged_value),
            };
            let (cursor, cursor_lease) = admit_clone(&self.inner.core, &key.0)?;
            self.after = Some(cursor);
            self.cursor_lease = Some(cursor_lease);
            let value = match staged_for_key {
                Some(value) => value,
                _ => self
                    .inner
                    .core
                    .get_admitted(&self.snapshot, &self.table, &key.0, MAX_TABLE_VALUE_BYTES)?
                    .map(AdmittedValue::into_parts),
            };
            let Some(value) = value else { continue };
            return Ok(Some((
                AccessGuard::decode_parts(key, &self.snapshot)?,
                AccessGuard::decode_parts(value, &self.snapshot)?,
            )));
        }
    }
}

impl<K: TableCodec, V: TableCodec> Iterator for TableRange<K, V> {
    type Item = Result<(AccessGuard<K>, AccessGuard<V>), TableError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.next_entry() {
            Ok(Some(row)) => Some(Ok(row)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(error) => {
                // A writer's overlay range settles its transaction like any
                // other staging step; a snapshot range has no writer.
                if let Some(staged) = &self.staged {
                    let discarded = lock(staged).settle(&self.inner.core, &error);
                    drop(discarded);
                }
                self.done = true;
                Some(Err(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize};

    const BYTES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("records");
    const INTEGERS: TableDefinition<u64, u64> = TableDefinition::new("records");

    #[derive(Clone, Default)]
    struct MemoryBackend(Arc<Mutex<Vec<u8>>>);

    impl StorageBackend for MemoryBackend {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.lock().unwrap().len() as u64)
        }

        fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let bytes = self.0.lock().unwrap();
            let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
            let end = start
                .checked_add(out.len())
                .ok_or(io::ErrorKind::InvalidInput)?;
            out.copy_from_slice(bytes.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
            Ok(())
        }

        fn write(&self, at: u64, data: &[u8]) -> io::Result<()> {
            let mut bytes = self.0.lock().unwrap();
            let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
            let end = start
                .checked_add(data.len())
                .ok_or(io::ErrorKind::InvalidInput)?;
            bytes
                .get_mut(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?
                .copy_from_slice(data);
            Ok(())
        }

        fn set_len(&self, length: u64) -> io::Result<()> {
            self.0.lock().unwrap().resize(
                usize::try_from(length).map_err(|_| io::ErrorKind::InvalidInput)?,
                0,
            );
            Ok(())
        }

        fn sync_data(&self) -> io::Result<()> {
            Ok(())
        }

        fn close(&self) -> BackendCloseOutcome {
            BackendCloseOutcome::drained(Ok(()))
        }
    }

    #[derive(Clone, Default)]
    struct CrashBackend(Arc<Mutex<CrashBytes>>);

    #[derive(Default)]
    struct CrashBytes {
        working: Vec<u8>,
        durable: Vec<u8>,
        fail_sync: Option<(usize, bool)>,
    }

    impl CrashBackend {
        fn fail_sync(&self, call: usize, after_persist: bool) {
            self.0.lock().unwrap().fail_sync = Some((call, after_persist));
        }

        fn crash(&self) -> Self {
            let durable = self.0.lock().unwrap().durable.clone();
            Self(Arc::new(Mutex::new(CrashBytes {
                working: durable.clone(),
                durable,
                fail_sync: None,
            })))
        }
    }

    impl StorageBackend for CrashBackend {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.lock().unwrap().working.len() as u64)
        }

        fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let state = self.0.lock().unwrap();
            let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
            let end = start
                .checked_add(out.len())
                .ok_or(io::ErrorKind::InvalidInput)?;
            out.copy_from_slice(
                state
                    .working
                    .get(start..end)
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }

        fn write(&self, at: u64, data: &[u8]) -> io::Result<()> {
            let mut state = self.0.lock().unwrap();
            let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
            let end = start
                .checked_add(data.len())
                .ok_or(io::ErrorKind::InvalidInput)?;
            state
                .working
                .get_mut(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?
                .copy_from_slice(data);
            Ok(())
        }

        fn set_len(&self, length: u64) -> io::Result<()> {
            self.0.lock().unwrap().working.resize(
                usize::try_from(length).map_err(|_| io::ErrorKind::InvalidInput)?,
                0,
            );
            Ok(())
        }

        fn sync_data(&self) -> io::Result<()> {
            let mut state = self.0.lock().unwrap();
            if let Some((remaining, after_persist)) = state.fail_sync {
                if remaining == 1 {
                    state.fail_sync = None;
                    if after_persist {
                        state.durable = state.working.clone();
                    }
                    return Err(io::ErrorKind::Other.into());
                }
                state.fail_sync = Some((remaining - 1, after_persist));
            }
            state.durable = state.working.clone();
            Ok(())
        }

        fn close(&self) -> BackendCloseOutcome {
            BackendCloseOutcome::drained(Ok(()))
        }
    }

    struct UnprovedCloseBackend {
        inner: MemoryBackend,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for UnprovedCloseBackend {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }

    impl StorageBackend for UnprovedCloseBackend {
        fn len(&self) -> io::Result<u64> {
            self.inner.len()
        }
        fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.inner.read(at, out)
        }
        fn write(&self, at: u64, data: &[u8]) -> io::Result<()> {
            self.inner.write(at, data)
        }
        fn set_len(&self, length: u64) -> io::Result<()> {
            self.inner.set_len(length)
        }
        fn sync_data(&self) -> io::Result<()> {
            self.inner.sync_data()
        }
        fn close(&self) -> BackendCloseOutcome {
            BackendCloseOutcome::retained_result(Ok(()))
        }
    }

    #[test]
    fn unproved_consuming_close_never_drops_its_backend_implicitly() {
        let drops = Arc::new(AtomicUsize::new(0));
        let database = Database::builder(Arc::new(AllowAll))
            .create_with_backend(UnprovedCloseBackend {
                inner: MemoryBackend::default(),
                drops: drops.clone(),
            })
            .unwrap();
        let error = database.close().expect_err("native drain is unproved");
        assert!(matches!(
            &error,
            CloseError::Storage(StorageError::RetainedOwner { .. })
        ));
        drop(error);
        assert_eq!(drops.load(Ordering::Acquire), 0);
    }

    #[derive(Default)]
    struct FailableAdmission {
        failed: AtomicBool,
    }

    impl StorageAdmission for FailableAdmission {
        fn check_owner(&self) -> Result<(), crate::core::OwnerFailed> {
            if self.failed.load(Ordering::Acquire) {
                Err(crate::core::OwnerFailed)
            } else {
                Ok(())
            }
        }

        fn reserve_workspace(
            &self,
            _bytes: u64,
        ) -> Result<Box<dyn ResidentLease>, crate::core::AdmissionError> {
            self.check_owner()
                .map_err(|_| crate::core::AdmissionError::OwnerFailed)?;
            Ok(Box::new(()))
        }

        fn reserve_growth(
            &self,
            _current: u64,
            _requested: u64,
        ) -> Result<(), crate::core::AdmissionError> {
            self.check_owner()
                .map_err(|_| crate::core::AdmissionError::OwnerFailed)
        }

        fn settle_growth(&self, _actual: u64) -> Result<(), crate::core::OwnerFailed> {
            self.check_owner()
        }

        fn owner_failed(&self) {
            self.failed.store(true, Ordering::Release);
        }
    }

    struct AllowAll;

    impl StorageAdmission for AllowAll {
        fn check_owner(&self) -> Result<(), crate::core::OwnerFailed> {
            Ok(())
        }

        fn reserve_workspace(
            &self,
            _bytes: u64,
        ) -> Result<Box<dyn ResidentLease>, crate::core::AdmissionError> {
            Ok(Box::new(()))
        }

        fn reserve_growth(
            &self,
            _current: u64,
            _requested: u64,
        ) -> Result<(), crate::core::AdmissionError> {
            Ok(())
        }

        fn settle_growth(&self, _actual: u64) -> Result<(), crate::core::OwnerFailed> {
            Ok(())
        }

        fn owner_failed(&self) {}
    }

    struct WorkspaceCeiling {
        limit: AtomicU64,
    }

    impl WorkspaceCeiling {
        fn new() -> Self {
            Self {
                limit: AtomicU64::new(u64::MAX),
            }
        }
    }

    impl StorageAdmission for WorkspaceCeiling {
        fn check_owner(&self) -> Result<(), crate::core::OwnerFailed> {
            Ok(())
        }

        fn reserve_workspace(
            &self,
            bytes: u64,
        ) -> Result<Box<dyn ResidentLease>, crate::core::AdmissionError> {
            if bytes > self.limit.load(Ordering::Acquire) {
                return Err(crate::core::AdmissionError::CapacityDenied);
            }
            Ok(Box::new(()))
        }

        fn reserve_growth(
            &self,
            _current: u64,
            _requested: u64,
        ) -> Result<(), crate::core::AdmissionError> {
            Ok(())
        }

        fn settle_growth(&self, _actual: u64) -> Result<(), crate::core::OwnerFailed> {
            Ok(())
        }

        fn owner_failed(&self) {}
    }

    fn database(backend: MemoryBackend) -> Database {
        Database::builder(Arc::new(AllowAll))
            .create_with_backend(backend)
            .unwrap()
    }

    #[test]
    fn key_only_delete_needs_no_old_value_headroom_and_preserves_pinned_reader() {
        let admission = Arc::new(WorkspaceCeiling::new());
        let backend = MemoryBackend::default();
        let database = Database::builder(admission.clone())
            .create_with_backend(backend.clone())
            .unwrap();
        let value = vec![0xa5; 8 << 20];
        let write = database.begin_write().unwrap();
        write
            .open_table(BYTES)
            .unwrap()
            .insert(b"large", value.as_slice())
            .unwrap();
        write.commit().unwrap();
        let old = database.begin_read().unwrap();
        admission.limit.store(4096, Ordering::Release);
        let write = database.begin_write().unwrap();
        let mut table = write.open_table(BYTES).unwrap();
        table.delete_key(b"large").unwrap();
        assert!(table.get(b"large").unwrap().is_none());
        drop(table);
        write.commit().unwrap();
        let current = database.begin_read().unwrap();
        assert!(
            current
                .open_table(BYTES)
                .unwrap()
                .get(b"large")
                .unwrap()
                .is_none()
        );
        drop(current);
        admission.limit.store(u64::MAX, Ordering::Release);
        assert_eq!(
            old.open_table(BYTES)
                .unwrap()
                .get(b"large")
                .unwrap()
                .unwrap()
                .value(),
            value.as_slice()
        );
        drop(old);
        database.close().unwrap();
        let reopened = Database::builder(admission)
            .open_with_backend(backend)
            .unwrap();
        let read = reopened.begin_read().unwrap();
        assert!(
            read.open_table(BYTES)
                .unwrap()
                .get(b"large")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn key_only_delete_denied_pre_effect_does_not_stage_a_tombstone() {
        let admission = Arc::new(WorkspaceCeiling::new());
        let database = Database::builder(admission.clone())
            .create_with_backend(MemoryBackend::default())
            .unwrap();
        let write = database.begin_write().unwrap();
        write
            .open_table(BYTES)
            .unwrap()
            .insert(b"key", b"value")
            .unwrap();
        write.commit().unwrap();

        let write = database.begin_write().unwrap();
        let mut table = write.open_table(BYTES).unwrap();
        admission.limit.store(0, Ordering::Release);
        assert!(matches!(
            table.delete_key(b"key"),
            Err(TableError::Storage(StorageError::Core(
                CoreError::CapacityDenied
            )))
        ));
        admission.limit.store(u64::MAX, Ordering::Release);
        // The denial rolled the whole writer back: later calls repeat it and
        // the commit publishes nothing, even with capacity available again.
        assert!(
            table
                .get(b"key")
                .is_err_and(|error| error.is_capacity_denied())
        );
        drop(table);
        assert!(
            write
                .commit()
                .is_err_and(|error| error.0.is_capacity_denied())
        );
        let read = database.begin_read().unwrap();
        assert_eq!(
            read.open_table(BYTES)
                .unwrap()
                .get(b"key")
                .unwrap()
                .unwrap()
                .value(),
            b"value"
        );
    }

    #[test]
    fn key_only_delete_validates_key_and_obeys_staged_order() {
        let database = database(MemoryBackend::default());
        let write = database.begin_write().unwrap();
        let mut table = write.open_table(BYTES).unwrap();
        let oversized = vec![0x44; MAX_KEY_BYTES + 1];
        assert!(matches!(
            table.delete_key(oversized.as_slice()),
            Err(TableError::Storage(StorageError::Core(
                CoreError::InvalidInput(_)
            )))
        ));
        table.delete_key(b"missing").unwrap();
        table.insert(b"key", b"first").unwrap();
        table.delete_key(b"key").unwrap();
        assert!(table.get(b"key").unwrap().is_none());
        table.delete_key(b"key").unwrap();
        table.insert(b"key", b"second").unwrap();
        assert_eq!(table.get(b"key").unwrap().unwrap().value(), b"second");
        drop(table);
        write.commit().unwrap();
        let read = database.begin_read().unwrap();
        let table = read.open_table(BYTES).unwrap();
        assert!(table.get(b"missing").unwrap().is_none());
        assert_eq!(table.get(b"key").unwrap().unwrap().value(), b"second");
    }

    #[test]
    fn key_only_delete_crash_replay_is_atomic_after_sync_failure() {
        for (failed_sync, persisted, deleted) in [
            (1, false, false),
            (2, false, false),
            (3, false, true),
            (3, true, true),
        ] {
            let backend = CrashBackend::default();
            let database = Database::builder(Arc::new(AllowAll))
                .create_with_backend(backend.clone())
                .unwrap();
            let write = database.begin_write().unwrap();
            write
                .open_table(BYTES)
                .unwrap()
                .insert(b"old", b"before")
                .unwrap();
            write.commit().unwrap();

            let write = database.begin_write().unwrap();
            let mut table = write.open_table(BYTES).unwrap();
            table.delete_key(b"old").unwrap();
            table.insert(b"new", b"after").unwrap();
            drop(table);
            backend.fail_sync(failed_sync, persisted);
            assert!(matches!(
                write.commit(),
                Err(CommitError(StorageError::UnknownCommit(_)))
            ));
            let reopened = Database::builder(Arc::new(AllowAll))
                .open_with_backend(backend.crash())
                .unwrap();
            let read = reopened.begin_read().unwrap();
            let table = read.open_table(BYTES).unwrap();
            assert_eq!(table.get(b"old").unwrap().is_none(), deleted);
            assert_eq!(table.get(b"new").unwrap().is_some(), deleted);
            if deleted {
                assert_eq!(table.get(b"new").unwrap().unwrap().value(), b"after");
            } else {
                assert_eq!(table.get(b"old").unwrap().unwrap().value(), b"before");
            }
        }
    }

    #[test]
    fn reader_keeps_prior_committed_values_while_writer_publishes_new_generation() {
        let database = database(MemoryBackend::default());
        let write = database.begin_write().unwrap();
        write
            .open_table(BYTES)
            .unwrap()
            .insert(b"k", b"before")
            .unwrap();
        write.commit().unwrap();

        let old = database.begin_read().unwrap();
        let write = database.begin_write().unwrap();
        write
            .open_table(BYTES)
            .unwrap()
            .insert(b"k", b"after")
            .unwrap();
        write.commit().unwrap();

        assert_eq!(
            old.open_table(BYTES)
                .unwrap()
                .get(b"k")
                .unwrap()
                .unwrap()
                .value(),
            b"before"
        );
        let current = database.begin_read().unwrap();
        assert_eq!(
            current
                .open_table(BYTES)
                .unwrap()
                .get(b"k")
                .unwrap()
                .unwrap()
                .value(),
            b"after"
        );
        drop(old);
        drop(current);
        database.close().unwrap();
    }

    #[test]
    fn staged_table_reads_and_open_fail_after_owner_failure() {
        let admission = Arc::new(FailableAdmission::default());
        let database = Database::builder(admission.clone())
            .create_with_backend(MemoryBackend::default())
            .unwrap();
        let write = database.begin_write().unwrap();
        let mut table = write.open_table(BYTES).unwrap();
        table.insert(b"staged", b"value").unwrap();
        let mut prior_range = table.range(&b""[..]..).unwrap();

        admission.owner_failed();
        assert!(matches!(
            write.open_table(BYTES),
            Err(TableError::Storage(StorageError::Core(
                CoreError::OwnerFailed
            )))
        ));
        assert!(matches!(
            table.get(b"staged"),
            Err(TableError::Storage(StorageError::Core(
                CoreError::OwnerFailed
            )))
        ));
        assert!(matches!(
            table.get(b"absent"),
            Err(TableError::Storage(StorageError::Core(
                CoreError::OwnerFailed
            )))
        ));
        assert!(matches!(
            table.range(&b""[..]..),
            Err(TableError::Storage(StorageError::Core(
                CoreError::OwnerFailed
            )))
        ));
        assert!(matches!(
            prior_range.next(),
            Some(Err(TableError::Storage(StorageError::Core(
                CoreError::OwnerFailed
            ))))
        ));
    }

    #[test]
    fn table_type_and_rows_survive_reopen() {
        let backend = MemoryBackend::default();
        let first = database(backend.clone());
        let write = first.begin_write().unwrap();
        write.open_table(INTEGERS).unwrap().insert(1, 41).unwrap();
        write.commit().unwrap();
        first.close().unwrap();

        let reopened = database(backend);
        let read = reopened.begin_read().unwrap();
        assert!(matches!(
            read.open_table(BYTES),
            Err(TableError::TypeMismatch(_))
        ));
        assert_eq!(
            read.open_table(INTEGERS)
                .unwrap()
                .get(1)
                .unwrap()
                .unwrap()
                .value(),
            41
        );
    }

    #[test]
    fn range_sees_sorted_overlay_and_abort_discards_it() {
        let database = database(MemoryBackend::default());
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(BYTES).unwrap();
            table.insert(b"b", b"3").unwrap();
            table.insert(b"aa", b"1").unwrap();
            table.insert(b"ab", b"2").unwrap();
            let rows = table
                .range(&b"aa"[..]..)
                .unwrap()
                .map(|row| row.map(|(key, value)| (key.value().to_vec(), value.value().to_vec())))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(
                rows,
                vec![
                    (b"aa".to_vec(), b"1".to_vec()),
                    (b"ab".to_vec(), b"2".to_vec()),
                    (b"b".to_vec(), b"3".to_vec())
                ]
            );
        }
        write.abort().unwrap();
        let read = database.begin_read().unwrap();
        assert!(matches!(
            read.open_table(BYTES),
            Err(TableError::DoesNotExist(_))
        ));
    }

    #[test]
    fn table_reads_reject_oversized_keys_before_encoding() {
        let database = database(MemoryBackend::default());
        let oversized = vec![0; MAX_KEY_BYTES + 1];
        let write = database.begin_write().unwrap();
        {
            let table = write.open_table(BYTES).unwrap();
            assert!(matches!(
                table.get(&oversized),
                Err(TableError::Storage(StorageError::Core(
                    CoreError::InvalidInput(_)
                )))
            ));
            assert!(matches!(
                table.range(oversized.as_slice()..),
                Err(TableError::Storage(StorageError::Core(
                    CoreError::InvalidInput(_)
                )))
            ));
        }
        write.commit().unwrap();

        let read = database.begin_read().unwrap();
        let table = read.open_table(BYTES).unwrap();
        assert!(matches!(
            table.get(&oversized),
            Err(TableError::Storage(StorageError::Core(
                CoreError::InvalidInput(_)
            )))
        ));
        assert!(matches!(
            table.range(oversized.as_slice()..),
            Err(TableError::Storage(StorageError::Core(
                CoreError::InvalidInput(_)
            )))
        ));
    }

    #[test]
    fn closing_wakes_a_writer_waiting_behind_an_active_writer() {
        let database = Arc::new(database(MemoryBackend::default()));
        let first = database.begin_write().unwrap();
        let queued = database.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = queued.begin_write().map(|writer| writer.abort().unwrap());
            result_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        let close = database.close_native();
        assert_eq!(
            close.native_disposition(),
            BackendNativeDisposition::Retained
        );
        first.abort().unwrap();
        let result = result_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(matches!(
            result,
            Err(TransactionError(StorageError::DatabaseClosed))
        ));
        worker.join().unwrap();
    }
}
