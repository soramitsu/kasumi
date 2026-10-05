//! Typed table and transaction surface for Kasumi's storage engine.
//!
//! Values are read from the backend on demand. Read transactions pin only the
//! immutable disk root; a writer stages its bounded changes until one durable
//! core commit publishes them together. The first capacity denial rolls a
//! writer back whole and releases its writer gate; an owner failure keeps the
//! writer, its staged batch and the gate for retained custody.

use crate::cache::{CacheConfig, CacheStats};
#[cfg(test)]
use crate::core::ResidentLease;
use crate::core::{
    AdmittedValue, BackendCloseEntry, BackendCloseOutcome, BackendNativeDisposition, Core,
    CoreError, MAX_BATCH_BYTES, MAX_KEY_BYTES, MAX_VALUE_BYTES, NativeResidentLease, Operation,
    ReadSnapshot, StorageAdmission,
};
use crate::core::{CacheWarmup, CacheWarmupStatus};
use crate::group::SegmentGroupBackend;
use crate::native_owned_arc::NativeOwnedArc;
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::{Bound, RangeFrom};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};

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
/// Each chunk admits its own concrete lease node before allocation. There is
/// no separately growing vector or backing retained after the grants retire.
const STAGING_LEASE_NODE: usize = size_of::<StagingLease>() + 64;

pub struct RetainedBackendOwner(Option<NativeOwnedArc<DatabaseInner>>);

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
    UnknownCommit(CoreError),
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
            Self::UnknownCommit(error) => error.fmt(f),
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
            Self::Io(error) | Self::RetainedOwner { error, .. } => Some(error),
            Self::Core(error) | Self::UnknownCommit(error) => Some(error),
        }
    }
}

impl StorageError {
    /// A capacity denial with no published transaction changes. Any private
    /// writes were proved aborted; the writer releases its complete batch and
    /// writer gate before returning the denial.
    pub fn is_capacity_denied(&self) -> bool {
        matches!(self, Self::Core(original) if original.is_capacity_denied())
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
        if error.is_unknown_commit() {
            return Self::UnknownCommit(error);
        }
        if matches!(error.rejected_cause(), Some(crate::CoreErrorCause::Closed)) {
            return Self::DatabaseClosed;
        }
        match error.into_io() {
            Ok(original) => Self::Io(original),
            Err(original) => Self::Core(original),
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
    /// A capacity denial with no published transaction changes. See
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

mod codec_sealed {
    pub trait Sealed {}
    impl Sealed for &[u8] {}
    impl Sealed for u64 {}
}

/// The table codec determines the on-disk type tag and owned/borrowed views.
/// The supported types are byte slices and big-endian `u64`; the sealed boundary
/// makes their bounded encoding and allocation behavior part of native storage.
pub trait TableCodec: codec_sealed::Sealed {
    type Input<'a>: Copy;
    type Owned;
    type View<'a>;

    const TAG: u8;
    fn encoded_len(input: Self::Input<'_>) -> usize;
    fn encoded_owned_len(value: &Self::Owned) -> usize;
    fn encode(input: Self::Input<'_>) -> Vec<u8>;
    fn encode_owned(value: &Self::Owned) -> Vec<u8>;
    #[doc(hidden)]
    fn with_encoded<R>(input: Self::Input<'_>, operation: impl FnOnce(&[u8]) -> R) -> R;
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
    fn with_encoded<R>(input: Self::Input<'_>, operation: impl FnOnce(&[u8]) -> R) -> R {
        operation(input)
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
    fn with_encoded<R>(input: Self::Input<'_>, operation: impl FnOnce(&[u8]) -> R) -> R {
        operation(&input.to_be_bytes())
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
    _lease: NativeResidentLease,
    // The guard may outlive its table and transaction facade. Keep the exact
    // snapshot live until both its owned value and resident lease are gone.
    _snapshot: SnapshotHandle,
}

impl<T: TableCodec> AccessGuard<T> {
    fn decode_parts(
        (bytes, lease): LeasedBytes,
        snapshot: &SnapshotHandle,
    ) -> Result<Self, TableError> {
        Ok(Self {
            value: T::decode(bytes)?,
            _lease: lease,
            _snapshot: snapshot.clone(),
        })
    }

    fn decode_admitted(
        value: AdmittedValue,
        snapshot: &SnapshotHandle,
    ) -> Result<Self, TableError> {
        Self::decode_parts(value.into_parts(), snapshot)
    }

    pub fn value(&self) -> T::View<'_> {
        T::view(&self.value)
    }
}

type LeasedBytes = (Vec<u8>, NativeResidentLease);
pub type OwnedByteRow = (AdmittedValue, AdmittedValue);
pub type TableRow<K, V> = (AccessGuard<K>, AccessGuard<V>);

fn check_key_bound<K: TableCodec>(key: K::Input<'_>) -> Result<(), TableError> {
    if K::encoded_len(key) > MAX_KEY_BYTES {
        return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
            "table key exceeds storage limit",
        ))
        .into());
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
        .ok_or_else(|| CoreError::new(crate::CoreErrorCause::CapacityDenied).into())
}

/// Commit workspace beyond the rows, which move from staging uncopied: the
/// operation vector, the shared type-table name, and each created table's
/// type row.
fn materialization_charge(
    operations: usize,
    created: &BTreeMap<SharedTableName, [u8; 2]>,
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
        .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))
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
    group_id: [u8; 16],
    cache: CacheConfig,
}

impl Builder {
    pub fn admission(&self) -> Arc<dyn StorageAdmission> {
        self.admission.clone()
    }

    pub fn with_admission(mut self, admission: Arc<dyn StorageAdmission>) -> Self {
        self.admission = admission;
        self
    }

    /// Create a new group. The generic failure owns the exact sized backend.
    #[allow(
        clippy::result_large_err,
        reason = "The failure owns the exact sized backend and cleanup without an error-path allocation."
    )]
    pub fn create_with_backend<B: SegmentGroupBackend + 'static>(
        self,
        backend: B,
    ) -> Result<Database, crate::NativeOpenFailure<B>> {
        self.assemble_backend(backend, true, true)
    }
    #[allow(
        clippy::result_large_err,
        reason = "The failure owns the exact sized backend and cleanup without an error-path allocation."
    )]
    pub fn open_with_backend<B: SegmentGroupBackend + 'static>(
        self,
        backend: B,
    ) -> Result<Database, crate::NativeOpenFailure<B>> {
        self.assemble_backend(backend, false, true)
    }
    #[allow(
        clippy::result_large_err,
        reason = "The failure owns the exact sized backend and cleanup without an error-path allocation."
    )]
    pub(crate) fn create_with_backend_retained<B: SegmentGroupBackend + 'static>(
        self,
        backend: B,
    ) -> Result<Database, crate::NativeOpenFailure<B>> {
        self.assemble_backend(backend, true, false)
    }
    #[allow(
        clippy::result_large_err,
        reason = "The failure owns the exact sized backend and cleanup without an error-path allocation."
    )]
    pub(crate) fn open_with_backend_retained<B: SegmentGroupBackend + 'static>(
        self,
        backend: B,
    ) -> Result<Database, crate::NativeOpenFailure<B>> {
        self.assemble_backend(backend, false, false)
    }
    #[allow(
        clippy::result_large_err,
        reason = "The failure owns the exact sized backend and cleanup without an error-path allocation."
    )]
    fn assemble_backend<B: SegmentGroupBackend + 'static>(
        self,
        backend: B,
        create: bool,
        close_on_failure: bool,
    ) -> Result<Database, crate::NativeOpenFailure<B>> {
        crate::core::opening::assemble(
            backend,
            self.admission,
            self.group_id,
            self.cache,
            create,
            close_on_failure,
            true,
        )
        .map(|opened| opened.into_database())
    }
}

struct WriterGate {
    held: Mutex<bool>,
    changed: Condvar,
    // A surviving writer lease keeps the same native admission alive through
    // the final gate allocation and its synchronization controls, even after
    // the database facade is dropped. Dispose these controls before Core.
    _core: NativeOwnedArc<Core>,
}

impl WriterGate {
    fn enter(
        this: &NativeOwnedArc<Self>,
        closing: &AtomicBool,
    ) -> Result<WriterLease, TransactionError> {
        let mut held = this
            .held
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *held {
            if closing.load(Ordering::Acquire) {
                return Err(StorageError::DatabaseClosed.into());
            }
            held = this
                .changed
                .wait(held)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        if closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed.into());
        }
        *held = true;
        Ok(WriterLease { gate: this.clone() })
    }
}

struct WriterLease {
    gate: NativeOwnedArc<WriterGate>,
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

// Quoted by Core before allocating any of these three enclosing controls.
// Each private owner retires its own control before disposing its payload.
pub(crate) const fn facade_heap_bytes() -> usize {
    size_of::<Core>()
        + size_of::<DatabaseInner>()
        + size_of::<WriterGate>()
        + 6 * size_of::<usize>()
        + 3 * 64
        + crate::native_sync::mutex_backing_bytes()
        + crate::native_sync::condvar_backing_bytes()
}
struct DatabaseInner {
    core: NativeOwnedArc<Core>,
    admission: Arc<dyn StorageAdmission>,
    gate: NativeOwnedArc<WriterGate>,
    closing: AtomicBool,
}

pub struct Database {
    inner: NativeOwnedArc<DatabaseInner>,
}

/// A borrowed transaction admission kept alive independently of a database
/// owner's close mutex. A pending writer counts as live work; sealing the
/// database wakes it before physical close can proceed.
pub struct DatabaseTransactionAdmission {
    inner: NativeOwnedArc<DatabaseInner>,
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
    pub fn configure_cache(&self, config: CacheConfig) -> Result<(), StorageError> {
        Database {
            inner: self.inner.clone(),
        }
        .configure_cache(config)
    }
    pub fn cache_stats(&self) -> Result<CacheStats, StorageError> {
        Database {
            inner: self.inner.clone(),
        }
        .cache_stats()
    }
    pub fn warm_cache(&self, work_limit: usize) -> Result<CacheWarmup, StorageError> {
        Database {
            inner: self.inner.clone(),
        }
        .warm_cache(work_limit)
    }
    pub fn warm_cache_if_needed(&self, work_limit: usize) -> Result<CacheWarmup, StorageError> {
        Database {
            inner: self.inner.clone(),
        }
        .warm_cache_if_needed(work_limit)
    }
    pub fn cache_warmup_status(&self) -> Result<CacheWarmupStatus, StorageError> {
        Database {
            inner: self.inner.clone(),
        }
        .cache_warmup_status()
    }
    pub fn request_cache_warm_retry(&self) -> Result<(), StorageError> {
        Database {
            inner: self.inner.clone(),
        }
        .request_cache_warm_retry()
    }
}

/// Facade construction and teardown use the same preowned staging slots.
/// Synchronization controls initialize while the original Core grant is live.
pub(crate) struct FacadeOpening {
    core: Option<NativeOwnedArc<Core>>,
    held: Option<Mutex<bool>>,
    changed: Option<Condvar>,
    gate: Option<NativeOwnedArc<WriterGate>>,
    database: Option<Database>,
    steps: [crate::native_backend::DisposalObservation; 6],
}
impl Default for FacadeOpening {
    fn default() -> Self {
        Self {
            core: None,
            held: None,
            changed: None,
            gate: None,
            database: None,
            steps: std::array::from_fn(|_| crate::native_backend::DisposalObservation::default()),
        }
    }
}
impl FacadeOpening {
    pub(crate) fn build(&mut self, core: Core, admission: Arc<dyn StorageAdmission>) {
        self.core = Some(NativeOwnedArc::new(core));
        let core = self.core.as_ref().expect("staged original Core");
        self.held = Some(crate::native_sync::mutex(false, core.shell_lease()));
        self.changed = Some(crate::native_sync::condvar(core.shell_lease()));
        self.gate = Some(NativeOwnedArc::new(WriterGate {
            held: self.held.take().expect("staged writer mutex"),
            changed: self.changed.take().expect("staged writer condvar"),
            _core: core.clone(),
        }));
        self.database = Some(Database {
            inner: NativeOwnedArc::new(DatabaseInner {
                core: self.core.take().expect("staged Core facade"),
                admission,
                gate: self.gate.take().expect("staged gate"),
                closing: AtomicBool::new(false),
            }),
        });
    }
    pub(crate) fn adopt(&mut self, database: Database) {
        assert!(self.database.is_none() && self.core.is_none());
        self.database = Some(database);
    }
    pub(crate) fn core(&self) -> Option<&Core> {
        self.database
            .as_ref()
            .map(|database| database.inner.core.as_ref())
            .or(self.core.as_deref())
            .or_else(|| self.gate.as_ref().map(|gate| gate._core.as_ref()))
    }
    pub(crate) fn take_completed(&mut self) -> Option<Database> {
        self.database.take()
    }
    pub(crate) fn observation_count(&self) -> usize {
        self.steps.len()
    }
    pub(crate) fn with_observation<R>(
        &self,
        index: usize,
        inspect: impl FnOnce(crate::retained::TerminalObservation<'_, std::convert::Infallible>) -> R,
    ) -> R {
        self.steps[index].with_observation(inspect)
    }
    pub(crate) fn complete(&self) -> bool {
        self.core.is_none()
            && self.held.is_none()
            && self.changed.is_none()
            && self.gate.is_none()
            && self.database.is_none()
            && self.steps.iter().all(|step| {
                matches!(
                    step,
                    crate::native_backend::DisposalObservation::NotEntered
                        | crate::native_backend::DisposalObservation::Returned
                )
            })
    }
    pub(crate) fn dispose(&mut self, output: &mut Option<Core>) -> bool {
        use crate::native_backend::{DisposalObservation, dispose_slot};
        if let Some(database) = self.database.as_mut() {
            if database.inner.get_mut().is_none() {
                return false;
            }
            let Database { inner } = self.database.take().expect("original database facade");
            let inner = match inner.try_unwrap() {
                Ok(inner) => inner,
                Err(inner) => {
                    self.database = Some(Database { inner });
                    return false;
                }
            };
            self.core = Some(inner.core);
            self.gate = Some(inner.gate);
            self.steps[0] = DisposalObservation::Returned;
            // The original Core remains staged during provider alias disposal.
            self.steps[1].run(|| drop(inner.admission));
            if !self.steps[1].returned() {
                return false;
            }
        }
        if let Some(gate) = self.gate.as_mut() {
            if gate.get_mut().is_none() {
                return false;
            }
            let gate = self.gate.take().expect("original writer gate");
            let gate = match gate.try_unwrap() {
                Ok(gate) => gate,
                Err(gate) => {
                    self.gate = Some(gate);
                    return false;
                }
            };
            self.held = Some(gate.held);
            self.changed = Some(gate.changed);
            self.steps[2] = DisposalObservation::Returned;
            self.steps[3].run(|| drop(gate._core));
            if !self.steps[3].returned() {
                return false;
            }
        }
        if !dispose_slot(&mut self.held, &mut self.steps[4])
            || !dispose_slot(&mut self.changed, &mut self.steps[5])
        {
            return false;
        }
        if let Some(core) = self.core.as_mut() {
            if core.get_mut().is_none() {
                return false;
            }
            let core = self.core.take().expect("original Core facade control");
            *output = match core.try_unwrap() {
                Ok(core) => Some(core),
                Err(core) => {
                    self.core = Some(core);
                    return false;
                }
            };
        }
        self.complete()
    }
}
impl Drop for FacadeOpening {
    fn drop(&mut self) {
        if self.complete() {
            return;
        }
        if let Some(owner) = self.core.take() {
            std::mem::forget(owner);
        }
        if let Some(owner) = self.database.take() {
            std::mem::forget(owner);
        }
        if let Some(owner) = self.gate.take() {
            std::mem::forget(owner);
        }
        if let Some(owner) = self.held.take() {
            std::mem::forget(owner);
        }
        if let Some(owner) = self.changed.take() {
            std::mem::forget(owner);
        }
        std::mem::forget(std::mem::replace(
            &mut self.steps,
            std::array::from_fn(|_| crate::native_backend::DisposalObservation::default()),
        ));
    }
}

impl Database {
    pub fn builder(
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        cache: CacheConfig,
    ) -> Builder {
        Builder {
            admission,
            group_id,
            cache,
        }
    }

    pub(crate) fn native_is_drained(&self) -> bool {
        self.inner.core.native_is_drained()
    }
    /// Own actual disposal separately from the prior native close outcome.
    pub fn into_disposal(self) -> crate::NativeOwnedDisposal {
        crate::NativeOwnedDisposal::from_database(self)
    }

    pub(crate) fn admission(&self) -> Arc<dyn StorageAdmission> {
        self.inner.admission.clone()
    }

    /// Set the shared directory-page/value cache budget, including metadata
    /// and retained versions, within the embedding owner's memory budget.
    pub fn configure_cache(&self, config: CacheConfig) -> Result<(), StorageError> {
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed);
        }
        self.inner.core.configure_cache(config).map_err(Into::into)
    }

    pub fn cache_stats(&self) -> Result<CacheStats, StorageError> {
        self.inner.core.cache_stats().map_err(Into::into)
    }

    /// Reconcile and refill the current and pinned roots without materializing
    /// all keys. Work counts cache slots, directory successors and root/phase
    /// transitions; it is neither a byte nor a wall-clock bound.
    pub fn warm_cache(&self, work_limit: usize) -> Result<CacheWarmup, StorageError> {
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed);
        }
        let result = self.inner.core.warm_cache(work_limit)?;
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed);
        }
        Ok(result)
    }

    pub fn warm_cache_if_needed(&self, work_limit: usize) -> Result<CacheWarmup, StorageError> {
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed);
        }
        let result = self.inner.core.warm_cache_if_needed(work_limit)?;
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed);
        }
        Ok(result)
    }

    pub fn cache_warmup_status(&self) -> Result<CacheWarmupStatus, StorageError> {
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed);
        }
        let result = self.inner.core.cache_warmup_status()?;
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed);
        }
        Ok(result)
    }

    pub fn request_cache_warm_retry(&self) -> Result<(), StorageError> {
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed);
        }
        self.inner.core.request_cache_warm_retry()?;
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed);
        }
        Ok(())
    }

    pub fn transaction_admission(&self) -> DatabaseTransactionAdmission {
        DatabaseTransactionAdmission {
            inner: self.inner.clone(),
        }
    }

    pub fn active_transactions(&self) -> usize {
        self.inner.strong_count().saturating_sub(1)
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
        let snapshot = SnapshotHandle::capture(&self.inner.core)?;
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed.into());
        }
        Ok(ReadTransaction {
            inner: self.inner.clone(),
            snapshot,
        })
    }

    pub fn begin_write(&self) -> Result<WriteTransaction, TransactionError> {
        let lease = WriterGate::enter(&self.inner.gate, &self.inner.closing)?;
        self.inner.core.prepare_write()?;
        let snapshot = SnapshotHandle::capture(&self.inner.core)?;
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed.into());
        }
        let staged = SharedPending::new(&self.inner.core, lease)?;
        Ok(WriteTransaction {
            inner: self.inner.clone(),
            snapshot: Some(snapshot),
            staged,
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

// Each transaction has an independently admitted snapshot backing. Tables,
// ranges and access guards alias that backing; a fork creates another backing
// around an allocation-free clone of the same actual native pin.
struct SnapshotBacking {
    snapshot: OnceLock<ReadSnapshot>,
    charge: SnapshotCharge,
}

struct SnapshotCharge(Option<NativeResidentLease>);
impl Drop for SnapshotCharge {
    fn drop(&mut self) {
        if let Some(lease) = self.0.take() {
            lease.retire();
        }
    }
}

struct SnapshotHandle(Option<Arc<SnapshotBacking>>);

pub(crate) const fn snapshot_backing_request_bytes() -> u64 {
    SnapshotHandle::CHARGE_BYTES
}

/// Both table-name allocations and the original opaque grant backing.
pub(crate) fn table_name_backing_bytes(name_bytes: usize) -> Result<u64, CoreError> {
    if name_bytes > 128 {
        return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
            "table name quote exceeds format limit",
        )));
    }
    Ok(
        (name_bytes + 2 * size_of::<usize>()).next_power_of_two() as u64
            + 64
            + (size_of::<TableNameBacking>() + 2 * size_of::<usize>()).next_power_of_two() as u64
            + 64
            + 128,
    )
}

struct TableNameBacking {
    name: Arc<str>,
    charge: SnapshotCharge,
}

// No Weak or raw Arc escapes. Every retained table/range/staged-map alias uses
// this wrapper, so the final control and string backing retire before refund.
struct SharedTableName(Option<Arc<TableNameBacking>>);
impl SharedTableName {
    fn new(core: &Core, name: &str) -> Result<Self, CoreError> {
        let charge = SnapshotCharge(Some(
            core.reserve_workspace(table_name_backing_bytes(name.len())?)?,
        ));
        let name = Arc::from(name);
        Ok(Self(Some(Arc::new(TableNameBacking { name, charge }))))
    }
    // Publication borrows the original maps throughout Core::commit and drops
    // every operation alias before either map's name owner can release credit.
    fn operation_name(&self) -> Arc<str> {
        self.0.as_ref().expect("live table name").name.clone()
    }
}
impl Clone for SharedTableName {
    fn clone(&self) -> Self {
        Self(Some(self.0.as_ref().expect("live table name").clone()))
    }
}
impl std::ops::Deref for SharedTableName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0.as_ref().expect("live table name").name
    }
}
impl std::borrow::Borrow<str> for SharedTableName {
    fn borrow(&self) -> &str {
        self
    }
}
impl PartialEq for SharedTableName {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}
impl Eq for SharedTableName {}
impl PartialOrd for SharedTableName {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SharedTableName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (**self).cmp(&**other)
    }
}
impl Drop for SharedTableName {
    fn drop(&mut self) {
        if let Some(TableNameBacking { name, charge }) =
            Arc::into_inner(self.0.take().expect("live table name"))
        {
            drop(name);
            drop(charge);
        }
    }
}
impl SnapshotHandle {
    // Arc counters, allocator rounding/slack, and the existing native lease
    // allowance. A custom provider must fund excess token backing itself.
    const CHARGE_BYTES: u64 = (size_of::<SnapshotBacking>() + 2 * size_of::<usize>())
        .next_power_of_two() as u64
        + 64
        + 128;

    fn create(
        core: &Core,
        capture: impl FnOnce() -> Result<ReadSnapshot, CoreError>,
    ) -> Result<Self, CoreError> {
        let charge = SnapshotCharge(Some(core.reserve_workspace(Self::CHARGE_BYTES)?));
        // Admission precedes both a fresh pin and a fork's snapshot-count
        // increment. No new backing or pin survives a refused reservation.
        let snapshot = capture()?;
        core.check_read_owner()?;
        Ok(Self(Some(Arc::new(SnapshotBacking {
            snapshot: OnceLock::from(snapshot),
            charge,
        }))))
    }

    fn capture(core: &Core) -> Result<Self, CoreError> {
        Self::create(core, || core.snapshot())
    }

    fn fork(&self, core: &Core) -> Result<Self, CoreError> {
        Self::create(core, || Ok(std::ops::Deref::deref(self).clone()))
    }

    fn has_descendants(&self) -> bool {
        Arc::strong_count(self.0.as_ref().expect("live snapshot handle")) != 1
    }
}
impl Clone for SnapshotHandle {
    fn clone(&self) -> Self {
        Self(Some(self.0.as_ref().expect("live snapshot handle").clone()))
    }
}
impl std::ops::Deref for SnapshotHandle {
    type Target = ReadSnapshot;
    fn deref(&self) -> &Self::Target {
        self.0
            .as_ref()
            .expect("live snapshot handle")
            .snapshot
            .get()
            .expect("initialized snapshot backing")
    }
}
impl Drop for SnapshotHandle {
    fn drop(&mut self) {
        let allocation = self.0.take().expect("live snapshot handle");
        // All strong aliases use this destructor and no Weak/raw Arc escapes.
        // Exactly one concurrent final drop receives the payload. into_inner
        // releases the Arc allocation before its snapshot and lease retire.
        if let Some(SnapshotBacking { snapshot, charge }) = Arc::into_inner(allocation) {
            drop(snapshot.into_inner());
            drop(charge);
        }
    }
}

pub struct ReadTransaction {
    inner: NativeOwnedArc<DatabaseInner>,
    snapshot: SnapshotHandle,
}

impl ReadTransaction {
    /// Independently own this exact selected native snapshot. This never
    /// captures the current root and never consumes another root-pin slot.
    /// The new backing is admitted through this database's actual provider;
    /// its descendants have independent close accounting from the parent.
    pub fn fork(&self) -> Result<Self, TransactionError> {
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed.into());
        }
        let snapshot = self.snapshot.fork(&self.inner.core)?;
        // The borrowed parent keeps the physical owner alive across admission.
        // This check linearizes success before a concurrent database seal.
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseClosed.into());
        }
        Ok(Self {
            inner: self.inner.clone(),
            snapshot,
        })
    }

    pub fn belongs_to(&self, database: &Database) -> bool {
        NativeOwnedArc::ptr_eq(&self.inner, &database.inner)
    }

    /// Tables, ranges and admitted access guards all carry this exact backing.
    /// A count of one cannot race a new descendant without another owner of
    /// this same snapshot from which to clone it.
    pub(crate) fn has_snapshot_descendants(&self) -> bool {
        self.snapshot.has_descendants()
    }

    pub fn open_table<K: TableCodec, V: TableCodec>(
        &self,
        definition: TableDefinition<K, V>,
    ) -> Result<ReadOnlyTable<K, V>, TableError> {
        check_table_type(&self.inner.core, &self.snapshot, definition)?;
        Ok(ReadOnlyTable {
            inner: self.inner.clone(),
            snapshot: self.snapshot.clone(),
            name: SharedTableName::new(&self.inner.core, definition.name())?,
            _codec: PhantomData,
        })
    }

    /// Validate the same canonical table tags using already admitted point
    /// backing. No table guard/name allocation or new read grant is created.
    pub fn check_bytes_table_prepared(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        workspace: &mut crate::PreparedPointRead,
    ) -> Result<(), TableError> {
        let name = definition.name();
        if name == TABLE_TYPES || name.is_empty() || name.len() > 128 {
            return Err(TableError::TypeMismatch(name.to_owned()));
        }
        if !self
            .inner
            .core
            .table_exists_prepared(&self.snapshot, name, workspace)?
        {
            return Err(TableError::DoesNotExist(name.to_owned()));
        }
        if !self
            .inner
            .core
            .table_exists_prepared(&self.snapshot, TABLE_TYPES, workspace)?
        {
            return Err(TableError::TypeMismatch(name.to_owned()));
        }
        let actual = self.inner.core.get_prepared(
            &self.snapshot,
            TABLE_TYPES,
            name.as_bytes(),
            2,
            workspace,
        )?;
        if actual != Some(definition.tags().as_slice()) {
            return Err(TableError::TypeMismatch(name.to_owned()));
        }
        Ok(())
    }

    /// Point read through the pinned disk root. The returned value retains its
    /// resident admission until the caller drops it.
    pub fn prepare_point_read(
        &self,
        max_value_bytes: usize,
    ) -> Result<crate::PreparedPointRead, CoreError> {
        self.inner.core.prepare_point_read(max_value_bytes)
    }

    pub fn point_length_prepared(
        &self,
        table: &str,
        key: &[u8],
        workspace: &mut crate::PreparedPointRead,
    ) -> Result<Option<usize>, CoreError> {
        self.inner
            .core
            .point_length_prepared(&self.snapshot, table, key, workspace)
    }

    pub fn get_bytes_prepared<'workspace>(
        &self,
        table: &str,
        key: &[u8],
        max_value_bytes: usize,
        workspace: &'workspace mut crate::PreparedPointRead,
    ) -> Result<Option<&'workspace [u8]>, CoreError> {
        self.inner
            .core
            .get_prepared(&self.snapshot, table, key, max_value_bytes, workspace)
    }

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
type StagedRows = BTreeMap<SharedTableName, BTreeMap<Vec<u8>, Option<Vec<u8>>>>;

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
    leases: Option<Vec<StagingLease>>,
    reserved: usize,
    used: usize,
}

struct StagingLease {
    lease: NativeResidentLease,
    next: Option<Vec<StagingLease>>,
}

impl StagingCredit {
    fn push(&mut self, lease: NativeResidentLease) -> Result<(), CoreError> {
        // The admitted concrete node owns a single fallibly allocated slot.
        // Default Global reports the requested layout as capacity; reject any
        // other capacity before moving the original tail into this backing.
        let mut allocation = Vec::new();
        if allocation.try_reserve_exact(1).is_err() || allocation.capacity() != 1 {
            // Retire any empty backing before refunding the new prospective
            // grant. A callback panic leaves the original tail untouched.
            drop(allocation);
            lease.retire();
            return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
        }
        allocation.push(StagingLease {
            lease,
            next: self.leases.take(),
        });
        self.leases = Some(allocation);
        Ok(())
    }
}

impl Drop for StagingCredit {
    fn drop(&mut self) {
        // Do not enter a new provider callback during an existing unwind.
        // The exact unentered nodes and their original grants stay retained.
        if std::thread::panicking() {
            std::mem::forget(self.leases.take());
            return;
        }
        while let Some(mut allocation) = self.leases.take() {
            let StagingLease { lease, next } = allocation
                .pop()
                .expect("staging lease backing has exactly one node");
            // The now-empty actual node backing retires before its grant.
            // The opaque lease separately retires its Box before refunding.
            drop(allocation);
            self.leases = next;
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| lease.retire())) {
                // No clean retirement was observed. Avoid recursively dropping
                // or entering another callback; preserve the original panic.
                std::mem::forget(self.leases.take());
                resume_unwind(payload);
            }
        }
    }
}

/// A batch taken out of its transaction. Fields drop in order: the staged
/// rows before the credit that admitted them, and the writer gate last.
struct Discarded {
    _created: BTreeMap<SharedTableName, [u8; 2]>,
    _writes: StagedRows,
    _credit: StagingCredit,
    _writer: Option<WriterLease>,
}

struct Pending {
    created: BTreeMap<SharedTableName, [u8; 2]>,
    writes: StagedRows,
    credit: StagingCredit,
    // The writer gate is held here rather than by the transaction facade, so
    // a rollback from any table handle releases it immediately.
    writer: Option<WriterLease>,
    staging: Staging,
}

// No Weak or raw Arc escapes. Every transaction, table and range clone owns
// this closed wrapper, so one final into_inner retires the actual Arc/control
// allocation before its resident grant is returned, including concurrent drops.
struct PendingBacking {
    pending: Mutex<Pending>,
    charge: SnapshotCharge,
}
struct SharedPending(Option<Arc<PendingBacking>>);
impl SharedPending {
    const CHARGE_BYTES: u64 = (size_of::<PendingBacking>() + 2 * size_of::<usize>())
        .next_power_of_two() as u64
        + 64
        + 128
        + crate::native_sync::mutex_backing_bytes() as u64;
    fn new(core: &Core, writer: WriterLease) -> Result<Self, CoreError> {
        let charge = SnapshotCharge(Some(core.reserve_workspace(Self::CHARGE_BYTES)?));
        Ok(Self(Some(Arc::new(PendingBacking {
            pending: crate::native_sync::mutex(
                Pending::new(writer),
                charge.0.as_ref().expect("original staging control grant"),
            ),
            charge,
        }))))
    }
}
impl Clone for SharedPending {
    fn clone(&self) -> Self {
        Self(Some(self.0.as_ref().expect("live staged owner").clone()))
    }
}
impl std::ops::Deref for SharedPending {
    type Target = Mutex<Pending>;
    fn deref(&self) -> &Self::Target {
        &self.0.as_ref().expect("live staged owner").pending
    }
}
impl Drop for SharedPending {
    fn drop(&mut self) {
        if let Some(PendingBacking { pending, charge }) =
            Arc::into_inner(self.0.take().expect("live staged owner"))
        {
            drop(pending);
            drop(charge);
        }
    }
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
            Staging::RolledBack => {
                Err(CoreError::new(crate::CoreErrorCause::CapacityDenied).into())
            }
            Staging::Failed => Err(CoreError::new(crate::CoreErrorCause::OwnerFailed).into()),
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
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        if used > self.credit.reserved {
            let deficit = used - self.credit.reserved;
            let desired = deficit.max(STAGING_CHUNK);
            let (credit, lease) =
                match core.reserve_workspace((desired + STAGING_LEASE_NODE) as u64) {
                    Ok(lease) => (desired, lease),
                    Err(error) if error.is_capacity_denied() && desired > deficit => (
                        deficit,
                        core.reserve_workspace((deficit + STAGING_LEASE_NODE) as u64)?,
                    ),
                    Err(error) => return Err(error.into()),
                };
            self.credit.push(lease)?;
            self.credit.reserved += credit;
        }
        self.credit.used = used;
        Ok(())
    }

    /// Admit one staged row, and on a table's first row that table's own
    /// staging structure. Its shared name already owns a separate admission.
    fn reserve_row(&mut self, core: &Core, table: &str, row: usize) -> Result<(), TableError> {
        let charge = if self.writes.contains_key(table) {
            Some(row)
        } else {
            row.checked_add(STAGED_TABLE_OVERHEAD)
        };
        self.reserve(
            core,
            charge.ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?,
        )
    }

    fn stage(&mut self, table: &SharedTableName, key: Vec<u8>, value: Option<Vec<u8>>) {
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
    inner: NativeOwnedArc<DatabaseInner>,
    snapshot: Option<SnapshotHandle>,
    staged: SharedPending,
    terminal: bool,
}

/// A successful durable commit whose original writer token remains held.
/// The actual transaction is consumed into this inline owner: no allocation,
/// admission, replay or mutable transaction capability is introduced. Dropping
/// it releases the same writer token after the caller captures a preowned root.
#[must_use = "keep the committed writer guard through the exact source capture"]
#[repr(transparent)]
pub struct CommittedWrite {
    _transaction: WriteTransaction,
}

impl WriteTransaction {
    /// Exact native policy quote for the separate shared staging control.
    /// This allocation coexists with the writer snapshot and staged row grants.
    pub const fn staging_backing_request_bytes() -> u64 {
        SharedPending::CHARGE_BYTES
    }
    pub fn belongs_to(&self, database: &Database) -> bool {
        NativeOwnedArc::ptr_eq(&self.inner, &database.inner)
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
        let (snapshot, name) = staged_step(&self.inner.core, &self.staged, || {
            let mut pending = lock(&self.staged);
            pending.ensure_active()?;
            let snapshot = self
                .snapshot
                .as_ref()
                .ok_or(CoreError::new(crate::CoreErrorCause::Closed))?;
            self.inner.core.check_read_owner()?;
            let create = if let Some(tags) = pending.created.get(name) {
                if *tags != definition.tags() {
                    return Err(TableError::TypeMismatch(name.to_string()));
                }
                false
            } else if snapshot.table_exists(name)? {
                check_table_type(&self.inner.core, snapshot, definition)?;
                false
            } else {
                pending.reserve(&self.inner.core, name.len().saturating_add(512))?;
                true
            };
            let name = SharedTableName::new(&self.inner.core, name)?;
            if create {
                pending.created.insert(name.clone(), definition.tags());
            }
            Ok((snapshot.clone(), name))
        })?;
        Ok(Table {
            inner: self.inner.clone(),
            snapshot,
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
        self.commit_inner_with_writer(false)
    }

    pub(crate) fn commit_inner_with_writer(&mut self, hold_success: bool) -> Result<(), CoreError> {
        if self.terminal {
            return Err(CoreError::new(crate::CoreErrorCause::Closed));
        }
        self.terminal = true;
        let mut pending = lock(&self.staged);
        match pending.staging {
            Staging::Active => {}
            // Rolled back before publication: repeat the original denial.
            Staging::RolledBack => {
                return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
            }
            Staging::Failed => return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed)),
            Staging::Terminal => return Err(CoreError::new(crate::CoreErrorCause::Closed)),
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
        } else if !hold_success || result.is_err() {
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
        &mut self,
        created: BTreeMap<SharedTableName, [u8; 2]>,
        mut writes: StagedRows,
    ) -> Result<(), CoreError> {
        let create_types = !created.is_empty()
            && !self
                .snapshot
                .as_ref()
                .ok_or(CoreError::new(crate::CoreErrorCause::Closed))?
                .table_exists(TABLE_TYPES)?;
        let rows = writes
            .values()
            .try_fold(0usize, |rows, table| rows.checked_add(table.len()))
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        let count = created
            .len()
            .checked_mul(2)
            .and_then(|count| count.checked_add(rows))
            .and_then(|count| count.checked_add(usize::from(create_types)))
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        if count == 0 {
            drop(self.snapshot.take());
            return self.inner.core.check_owner();
        }
        let _workspace = self
            .inner
            .core
            .reserve_workspace(materialization_charge(count, &created)?)?;
        let mut operations = Vec::new();
        operations
            .try_reserve_exact(count)
            .map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        if !created.is_empty() {
            let types: Arc<str> = Arc::from(TABLE_TYPES);
            if create_types {
                operations.push(Operation::CreateTable {
                    table: types.clone(),
                });
            }
            for (name, tags) in &created {
                let key = name.as_bytes().to_vec();
                operations.push(Operation::CreateTable {
                    table: name.operation_name(),
                });
                operations.push(Operation::Put {
                    table: types.clone(),
                    key,
                    value: tags.to_vec(),
                });
            }
        }
        for (table, rows) in &mut writes {
            for (key, value) in std::mem::take(rows) {
                operations.push(match value {
                    Some(value) => Operation::Put {
                        table: table.operation_name(),
                        key,
                        value,
                    },
                    None => Operation::Delete {
                        table: table.operation_name(),
                        key,
                    },
                });
            }
        }
        debug_assert_eq!(operations.len(), count);
        // Terminal publication no longer reads this writer's snapshot. Retire
        // only its Arc before Core decides which old versions can be pruned;
        // surviving tables, ranges and returned values keep their own pins.
        drop(self.snapshot.take());
        let result = self.inner.core.commit(&operations);
        drop(operations);
        result
    }

    pub(crate) fn abort_inner(&mut self) -> Result<(), CoreError> {
        if self.terminal {
            return Err(CoreError::new(crate::CoreErrorCause::Closed));
        }
        self.terminal = true;
        let mut pending = lock(&self.staged);
        match pending.staging {
            Staging::Active => {}
            // The first capacity denial already discarded the batch and
            // released the writer gate; there is nothing left to abort.
            Staging::RolledBack => return Ok(()),
            Staging::Failed => return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed)),
            Staging::Terminal => return Err(CoreError::new(crate::CoreErrorCause::Closed)),
        }
        pending.staging = Staging::Terminal;
        drop(pending);
        // A failed physical owner makes even a requested abort uncertain. The
        // retained transaction keeps its writer lease and original staging.
        self.inner.core.check_owner()?;
        let discarded = lock(&self.staged).discard();
        drop(discarded);
        drop(self.snapshot.take());
        Ok(())
    }

    /// Commit once, retaining the already owned writer token only on success.
    /// It protects capture from writers using any facade for this native node.
    /// Every failed/unknown commit follows the unchanged terminal path and
    /// returns its original error; no success guard is minted for it.
    pub fn commit_holding_writer(mut self) -> Result<CommittedWrite, CommitError> {
        self.commit_inner_with_writer(true)?;
        Ok(CommittedWrite { _transaction: self })
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
    inner: NativeOwnedArc<DatabaseInner>,
    snapshot: SnapshotHandle,
    staged: SharedPending,
    name: SharedTableName,
    _codec: PhantomData<fn() -> (K, V)>,
}

impl<K: TableCodec, V: TableCodec> Table<K, V> {
    fn step<T>(&self, step: impl FnOnce() -> Result<T, TableError>) -> Result<T, TableError> {
        staged_step(&self.inner.core, &self.staged, step)
    }

    pub fn get(&self, key: K::Input<'_>) -> Result<Option<AccessGuard<V>>, TableError> {
        check_key_bound::<K>(key)?;
        self.step(|| {
            K::with_encoded(key, |key| {
                current_bytes(&self.inner, &self.snapshot, &self.staged, &self.name, key)
            })?
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
            K::with_encoded(range.start, |start| {
                TableRange::new(
                    self.inner.clone(),
                    self.snapshot.clone(),
                    Some(self.staged.clone()),
                    self.name.clone(),
                    start,
                )
            })
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
                &[],
            )
        })
    }

    /// Retain rows whose encoded keys start with `prefix` according to `keep`.
    /// Values outside the prefix are never read or admitted.
    pub fn retain_prefix(
        &mut self,
        prefix: K::Input<'_>,
        mut keep: impl FnMut(K::View<'_>, V::View<'_>) -> bool,
    ) -> Result<(), TableError> {
        let mut rows = self.range(prefix..)?;
        rows.prefix_only = true;
        for entry in rows {
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
    inner: NativeOwnedArc<DatabaseInner>,
    snapshot: SnapshotHandle,
    name: SharedTableName,
    _codec: PhantomData<fn() -> (K, V)>,
}

impl<K: TableCodec, V: TableCodec> ReadOnlyTable<K, V> {
    pub fn get(&self, key: K::Input<'_>) -> Result<Option<AccessGuard<V>>, TableError> {
        check_key_bound::<K>(key)?;
        K::with_encoded(key, |key| {
            self.inner
                .core
                .get_admitted(&self.snapshot, &self.name, key, MAX_TABLE_VALUE_BYTES)
        })?
        .map(|value| AccessGuard::decode_admitted(value, &self.snapshot))
        .transpose()
    }

    pub fn range(&self, range: RangeFrom<K::Input<'_>>) -> Result<TableRange<K, V>, TableError> {
        check_key_bound::<K>(range.start)?;
        K::with_encoded(range.start, |start| {
            TableRange::new(
                self.inner.clone(),
                self.snapshot.clone(),
                None,
                self.name.clone(),
                start,
            )
        })
    }

    pub fn iter(&self) -> Result<TableRange<K, V>, TableError> {
        TableRange::new(
            self.inner.clone(),
            self.snapshot.clone(),
            None,
            self.name.clone(),
            &[],
        )
    }
}

pub trait ReadableTable<K: TableCodec, V: TableCodec> {}
impl<K: TableCodec, V: TableCodec> ReadableTable<K, V> for Table<K, V> {}
impl<K: TableCodec, V: TableCodec> ReadableTable<K, V> for ReadOnlyTable<K, V> {}

/// Ordered iterator over one immutable snapshot plus a writer's staged overlay.
/// One value at a time is materialized from the backend.
pub struct TableRange<K: TableCodec, V: TableCodec> {
    inner: NativeOwnedArc<DatabaseInner>,
    snapshot: SnapshotHandle,
    staged: Option<SharedPending>,
    table: SharedTableName,
    start: OwnedKeyBytes,
    prefix_only: bool,
    after: Option<OwnedKeyBytes>,
    done: bool,
    _codec: PhantomData<fn() -> (K, V)>,
}

// Continuations own only their admitted bytes and original opaque grant. Vec
// backing drops first; SnapshotCharge retires the lease Box before its refund.
struct OwnedKeyBytes {
    bytes: Vec<u8>,
    _charge: SnapshotCharge,
}
impl OwnedKeyBytes {
    fn copy(core: &Core, input: &[u8], request: u64) -> Result<Self, TableError> {
        let charge = SnapshotCharge(Some(core.reserve_workspace(request)?));
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(input.len())
            .map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        if bytes.capacity() != input.len() {
            return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied).into());
        }
        bytes.extend_from_slice(input);
        Ok(Self {
            bytes,
            _charge: charge,
        })
    }
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<K: TableCodec, V: TableCodec> TableRange<K, V> {
    fn new(
        inner: NativeOwnedArc<DatabaseInner>,
        snapshot: SnapshotHandle,
        staged: Option<SharedPending>,
        table: SharedTableName,
        start: &[u8],
    ) -> Result<Self, TableError> {
        inner.core.check_read_owner()?;
        let charge = start.len().saturating_add(table.len()).saturating_add(256);
        let start = OwnedKeyBytes::copy(&inner.core, start, charge as u64)?;
        Ok(Self {
            inner,
            snapshot,
            staged,
            table,
            start,
            prefix_only: false,
            after: None,
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
                    .next_key_admitted(
                        &self.table,
                        self.start.as_bytes(),
                        self.after.as_ref().map(OwnedKeyBytes::as_bytes),
                    )?
                    .map(AdmittedValue::into_parts)
                    .filter(|(key, _)| !self.prefix_only || key.starts_with(self.start.as_bytes()))
            };
            let (staged_key, staged_value) = if let Some(staged) = &self.staged {
                let pending = lock(staged);
                pending.ensure_active()?;
                let start = match self.after.as_ref().map(OwnedKeyBytes::as_bytes) {
                    Some(after) if after >= self.start.as_bytes() => Bound::Excluded(after),
                    _ => Bound::Included(self.start.as_bytes()),
                };
                pending
                    .writes
                    .get(&*self.table)
                    .and_then(|writes| writes.range::<[u8], _>((start, Bound::Unbounded)).next())
                    .filter(|(key, _)| !self.prefix_only || key.starts_with(self.start.as_bytes()))
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
            let cursor = OwnedKeyBytes::copy(
                &self.inner.core,
                &key.0,
                key.0.len().saturating_add(128) as u64,
            )?;
            self.after = Some(cursor);
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
    use crate::group::{FaultTiming, GroupFile, GroupOp, InMemoryGroup};
    use crate::root::{ROOT_SLOT_BYTES, RootSlot};
    use std::ffi::OsStr;
    use std::sync::atomic::{AtomicU64, AtomicUsize};

    const GROUP: [u8; 16] = [53; 16];

    const BYTES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("records");
    const INTEGERS: TableDefinition<u64, u64> = TableDefinition::new("records");

    struct UnprovedCloseBackend {
        inner: InMemoryGroup,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for UnprovedCloseBackend {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }

    impl SegmentGroupBackend for UnprovedCloseBackend {
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
            BackendCloseOutcome::retained_result(Ok(()))
        }
    }

    #[test]
    fn unproved_consuming_close_never_drops_its_backend_implicitly() {
        let drops = Arc::new(AtomicUsize::new(0));
        let database = Database::builder(Arc::new(AllowAll), GROUP, CacheConfig::default())
            .create_with_backend(UnprovedCloseBackend {
                inner: InMemoryGroup::new(),
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
    impl crate::cache_test::Provider for FailableAdmission {
        fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
            let _ = first;
            let _ = bytes;
            Ok(())
        }
        fn release_cache(&self, bytes: u64, last: bool) {
            let _ = (bytes, last);
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
    impl crate::cache_test::Provider for AllowAll {
        fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
            let _ = first;
            let _ = bytes;
            Ok(())
        }
        fn release_cache(&self, bytes: u64, last: bool) {
            let _ = (bytes, last);
        }
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
    impl crate::cache_test::Provider for WorkspaceCeiling {
        fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
            let _ = first;
            if bytes > self.limit.load(Ordering::Acquire) {
                Err(crate::AdmissionError::CapacityDenied)
            } else {
                Ok(())
            }
        }
        fn release_cache(&self, bytes: u64, last: bool) {
            let _ = (bytes, last);
        }
    }

    fn database(backend: InMemoryGroup) -> Database {
        Database::builder(Arc::new(AllowAll), GROUP, CacheConfig::default())
            .create_with_backend(backend)
            .unwrap()
    }

    #[test]
    fn prepared_table_validation_preserves_types_snapshot_and_owner_under_denial() {
        const NUMBERS: TableDefinition<u64, u64> = TableDefinition::new("numbers");
        const NUMBERS_AS_BYTES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("numbers");
        const LATER: TableDefinition<&[u8], &[u8]> = TableDefinition::new("later");
        let admission = Arc::new(WorkspaceCeiling::new());
        let database = Database::builder(admission.clone(), GROUP, CacheConfig::default())
            .create_with_backend(InMemoryGroup::new())
            .unwrap();
        let other = Database::builder(admission.clone(), [54; 16], CacheConfig::default())
            .create_with_backend(InMemoryGroup::new())
            .unwrap();
        let write = database.begin_write().unwrap();
        write
            .open_table(BYTES)
            .unwrap()
            .insert(b"key", b"value")
            .unwrap();
        write.open_table(NUMBERS).unwrap().insert(1, 2).unwrap();
        write.commit().unwrap();
        let old = database.begin_read().unwrap();
        let mut workspace = old.prepare_point_read(128).unwrap();
        let write = database.begin_write().unwrap();
        write
            .open_table(LATER)
            .unwrap()
            .insert(b"key", b"later")
            .unwrap();
        write.commit().unwrap();
        let current = database.begin_read().unwrap();
        let foreign = other.begin_read().unwrap();
        let address = workspace.output.bytes.as_ptr();
        admission.limit.store(0, Ordering::Release);

        // This is genuine ordinary workspace refusal, while canonical tag
        // reads use the preowned native backing at the selected snapshot.
        assert!(
            matches!(&(old.open_table(BYTES)), Err(TableError::Storage(StorageError::Core(
                native_error
            ))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
        );
        old.check_bytes_table_prepared(BYTES, &mut workspace)
            .unwrap();
        current
            .check_bytes_table_prepared(BYTES, &mut workspace)
            .unwrap();
        assert!(matches!(
            old.check_bytes_table_prepared(NUMBERS_AS_BYTES, &mut workspace),
            Err(TableError::TypeMismatch(name)) if name == "numbers"
        ));
        assert!(matches!(
            old.check_bytes_table_prepared(LATER, &mut workspace),
            Err(TableError::DoesNotExist(name)) if name == "later"
        ));
        current
            .check_bytes_table_prepared(LATER, &mut workspace)
            .unwrap();
        for name in ["", TABLE_TYPES] {
            assert!(matches!(
                old.check_bytes_table_prepared(TableDefinition::new(name), &mut workspace),
                Err(TableError::TypeMismatch(actual)) if actual == name
            ));
        }
        assert!(
            matches!(&(foreign.check_bytes_table_prepared(BYTES, &mut workspace)), Err(TableError::Storage(StorageError::Core(
                native_error
            ))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        // Failed validation cannot replace the old root or corrupt reusable
        // output; valid loans still use the same allocation afterward.
        old.check_bytes_table_prepared(BYTES, &mut workspace)
            .unwrap();
        assert_eq!(
            old.get_bytes_prepared("records", b"key", 128, &mut workspace)
                .unwrap(),
            Some(b"value".as_slice())
        );
        assert_eq!(workspace.output.bytes.as_ptr(), address);
        admission.limit.store(u64::MAX, Ordering::Release);
        drop((workspace, old, current, foreign));
        database.close().unwrap();
        other.close().unwrap();
    }

    #[test]
    fn prepared_points_reuse_backing_under_total_workspace_refusal_and_bind_exact_owner() {
        let admission = Arc::new(WorkspaceCeiling::new());
        let database = Database::builder(admission.clone(), GROUP, CacheConfig::default())
            .create_with_backend(InMemoryGroup::new())
            .unwrap();
        let other = Database::builder(admission.clone(), [54; 16], CacheConfig::default())
            .create_with_backend(InMemoryGroup::new())
            .unwrap();
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(BYTES).unwrap();
            for row in 0u32..600 {
                table.insert(row.to_be_bytes().as_slice(), b"old").unwrap();
            }
        }
        write.commit().unwrap();
        let old = database.begin_read().unwrap();
        let mut workspace = old.prepare_point_read(128).unwrap();
        let write = database.begin_write().unwrap();
        write
            .open_table(BYTES)
            .unwrap()
            .insert(599u32.to_be_bytes().as_slice(), b"new")
            .unwrap();
        write.commit().unwrap();
        let current = database.begin_read().unwrap();
        let foreign = other.begin_read().unwrap();
        let address = workspace.output.bytes.as_ptr();
        admission.limit.store(0, Ordering::Release);
        for _ in 0..3 {
            assert_eq!(
                old.get_bytes_prepared("records", &599u32.to_be_bytes(), 128, &mut workspace)
                    .unwrap(),
                Some(b"old".as_slice())
            );
            assert_eq!(
                current
                    .get_bytes_prepared("records", &599u32.to_be_bytes(), 128, &mut workspace)
                    .unwrap(),
                Some(b"new".as_slice())
            );
            assert!(
                old.get_bytes_prepared("records", b"missing", 128, &mut workspace)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(workspace.output.bytes.as_ptr(), address);
        }
        assert!(
            matches!(&(foreign.get_bytes_prepared("records", b"key", 128, &mut workspace)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        assert!(
            matches!(&(old.get_bytes_prepared("records", &599u32.to_be_bytes(), 2, &mut workspace)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        assert_eq!(
            old.get_bytes_prepared("records", &599u32.to_be_bytes(), 128, &mut workspace)
                .unwrap(),
            Some(b"old".as_slice())
        );
        assert_eq!(database.cache_stats().unwrap().entries, 0);
        admission.limit.store(u64::MAX, Ordering::Release);
        drop((workspace, old, current, foreign));
        database.close().unwrap();
        other.close().unwrap();
    }

    #[test]
    fn key_only_delete_needs_no_old_value_headroom_and_preserves_pinned_reader() {
        let admission = Arc::new(WorkspaceCeiling::new());
        let backend = InMemoryGroup::new();
        let database = Database::builder(admission.clone(), GROUP, CacheConfig::default())
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
        // Directory/replay workspace fits; copying the 8 MiB old value does not.
        admission.limit.store(4 << 20, Ordering::Release);
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
        let reopened = Database::builder(admission, GROUP, CacheConfig::default())
            .open_with_backend(backend.crash())
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
        let database = Database::builder(admission.clone(), GROUP, CacheConfig::default())
            .create_with_backend(InMemoryGroup::new())
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
        assert!(
            matches!(&(table.delete_key(b"key")), Err(TableError::Storage(StorageError::Core(
                native_error
            ))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
        );
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
        let database = database(InMemoryGroup::new());
        let write = database.begin_write().unwrap();
        let mut table = write.open_table(BYTES).unwrap();
        let oversized = vec![0x44; MAX_KEY_BYTES + 1];
        assert!(
            matches!(&(table.delete_key(oversized.as_slice())), Err(TableError::Storage(StorageError::Core(
                native_error
            ))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
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
        for hold_writer in [false, true] {
            for (operation, nth, timing, deleted) in [
                // Prepared operation bytes and private directory pages cannot
                // publish either row without the final durable commit record.
                (GroupOp::Sync, 1, FaultTiming::BeforeEffect, false),
                (GroupOp::Sync, 1, FaultTiming::AfterEffect, false),
                (GroupOp::Sync, 2, FaultTiming::AfterEffect, false),
                (GroupOp::Sync, 3, FaultTiming::BeforeEffect, false),
                (GroupOp::Sync, 3, FaultTiming::AfterEffect, false),
                (GroupOp::Sync, 4, FaultTiming::BeforeEffect, false),
                (GroupOp::Sync, 4, FaultTiming::AfterEffect, true),
                // The durable log commit is authoritative even when installing
                // its root fails. Strict reopen must recover both changes.
                (GroupOp::RootSync, 1, FaultTiming::BeforeEffect, true),
                (GroupOp::RootSync, 1, FaultTiming::AfterEffect, true),
            ] {
                let backend = InMemoryGroup::new();
                let database = Database::builder(Arc::new(AllowAll), GROUP, CacheConfig::default())
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
                backend.fail(operation, nth, timing);
                let error = if hold_writer {
                    write
                        .commit_holding_writer()
                        .err()
                        .expect("no guard for injected durability failure")
                } else {
                    write.commit().expect_err("injected durability failure")
                };
                assert!(
                    error.0.fences_owner(),
                    "{operation:?} {nth} {timing:?}: {error:?}"
                );
                assert!(database.inner.core.is_fenced());
                let reopened = Database::builder(Arc::new(AllowAll), GROUP, CacheConfig::default())
                    .open_with_backend(backend.crash())
                    .unwrap();
                let read = reopened.begin_read().unwrap();
                let table = read.open_table(BYTES).unwrap();
                assert_eq!(
                    table.get(b"old").unwrap().is_none(),
                    deleted,
                    "{operation:?} {nth} {timing:?}"
                );
                assert_eq!(
                    table.get(b"new").unwrap().is_some(),
                    deleted,
                    "{operation:?} {nth} {timing:?}"
                );
                if deleted {
                    assert_eq!(table.get(b"new").unwrap().unwrap().value(), b"after");
                } else {
                    assert_eq!(table.get(b"old").unwrap().unwrap().value(), b"before");
                }
            }
        }
    }

    #[test]
    fn reader_keeps_prior_committed_values_while_writer_publishes_new_generation() {
        let database = database(InMemoryGroup::new());
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
        let database = Database::builder(admission.clone(), GROUP, CacheConfig::default())
            .create_with_backend(InMemoryGroup::new())
            .unwrap();
        let write = database.begin_write().unwrap();
        let mut table = write.open_table(BYTES).unwrap();
        table.insert(b"staged", b"value").unwrap();
        let mut prior_range = table.range(&b""[..]..).unwrap();

        admission.owner_failed();
        assert!(
            matches!(&(write.open_table(BYTES)), Err(TableError::Storage(StorageError::Core(
                native_error
            ))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert!(
            matches!(&(table.get(b"staged")), Err(TableError::Storage(StorageError::Core(
                native_error
            ))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert!(
            matches!(&(table.get(b"absent")), Err(TableError::Storage(StorageError::Core(
                native_error
            ))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert!(
            matches!(&(table.range(&b""[..]..)), Err(TableError::Storage(StorageError::Core(
                native_error
            ))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert!(
            matches!(&(prior_range.next()), Some(Err(TableError::Storage(StorageError::Core(
                native_error
            )))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
    }

    #[test]
    fn table_type_and_rows_survive_reopen() {
        let backend = InMemoryGroup::new();
        let first = database(backend.clone());
        let write = first.begin_write().unwrap();
        write.open_table(INTEGERS).unwrap().insert(1, 41).unwrap();
        write.commit().unwrap();
        first.close().unwrap();

        let reopened = Database::builder(Arc::new(AllowAll), GROUP, CacheConfig::default())
            .open_with_backend(backend.crash())
            .unwrap();
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
        let database = database(InMemoryGroup::new());
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
        let database = database(InMemoryGroup::new());
        let oversized = vec![0; MAX_KEY_BYTES + 1];
        let write = database.begin_write().unwrap();
        {
            let table = write.open_table(BYTES).unwrap();
            assert!(
                matches!(&(table.get(&oversized)), Err(TableError::Storage(StorageError::Core(
                    native_error
                ))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
            );
            assert!(
                matches!(&(table.range(oversized.as_slice()..)), Err(TableError::Storage(StorageError::Core(
                    native_error
                ))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
            );
        }
        write.commit().unwrap();

        let read = database.begin_read().unwrap();
        let table = read.open_table(BYTES).unwrap();
        assert!(
            matches!(&(table.get(&oversized)), Err(TableError::Storage(StorageError::Core(
                native_error
            ))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        assert!(
            matches!(&(table.range(oversized.as_slice()..)), Err(TableError::Storage(StorageError::Core(
                native_error
            ))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
    }

    #[test]
    fn retain_prefix_does_not_read_large_committed_or_staged_neighbors() {
        for staged_neighbor in [false, true] {
            let admission = Arc::new(WorkspaceCeiling::new());
            let database = Database::builder(admission.clone(), GROUP, CacheConfig::default())
                .create_with_backend(InMemoryGroup::new())
                .unwrap();
            let write = database.begin_write().unwrap();
            {
                let mut table = write.open_table(BYTES).unwrap();
                table.insert(b"app/1", b"one").unwrap();
                table.insert(b"app/2", b"two").unwrap();
                if !staged_neighbor {
                    table
                        .insert(b"peer/large", vec![0x3c; 8 << 20].as_slice())
                        .unwrap();
                }
            }
            write.commit().unwrap();
            let write = database.begin_write().unwrap();
            {
                let mut table = write.open_table(BYTES).unwrap();
                if staged_neighbor {
                    table
                        .insert(b"peer/large", vec![0x3c; 8 << 20].as_slice())
                        .unwrap();
                }
                // Prefix rows fit; admitting the neighboring value from
                // either the snapshot or the overlay would deny the batch.
                admission.limit.store(4 << 20, Ordering::Release);
                let mut visited = 0;
                table
                    .retain_prefix(b"app/", |key, _| {
                        assert!(key.starts_with(b"app/"));
                        visited += 1;
                        false
                    })
                    .unwrap();
                assert_eq!(visited, 2);
            }
            write.commit().unwrap();
            admission.limit.store(u64::MAX, Ordering::Release);
            let read = database.begin_read().unwrap();
            let table = read.open_table(BYTES).unwrap();
            assert!(table.get(b"app/1").unwrap().is_none());
            assert!(table.get(b"app/2").unwrap().is_none());
            assert_eq!(
                table.get(b"peer/large").unwrap().unwrap().value().len(),
                8 << 20
            );
        }
    }

    #[test]
    fn retain_prefix_merges_staged_values_tombstones_and_inserts() {
        let database = database(InMemoryGroup::new());
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(BYTES).unwrap();
            table.insert(b"aaa/outside", b"before").unwrap();
            table.insert(b"app/1", b"one").unwrap();
            table.insert(b"app/2", b"two").unwrap();
            table.insert(b"app/3", b"three").unwrap();
            table.insert(b"peer/outside", b"after").unwrap();
        }
        write.commit().unwrap();
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(BYTES).unwrap();
            table.insert(b"app/1", b"updated").unwrap();
            table.delete_key(b"app/2").unwrap();
            table.insert(b"app/new", b"new").unwrap();
            let mut visited = Vec::new();
            table
                .retain_prefix(b"app/", |key, value| {
                    visited.push((key.to_vec(), value.to_vec()));
                    key == b"app/1" || value == b"new"
                })
                .unwrap();
            assert_eq!(
                visited,
                vec![
                    (b"app/1".to_vec(), b"updated".to_vec()),
                    (b"app/3".to_vec(), b"three".to_vec()),
                    (b"app/new".to_vec(), b"new".to_vec()),
                ]
            );
        }
        write.commit().unwrap();
        let read = database.begin_read().unwrap();
        let table = read.open_table(BYTES).unwrap();
        let rows = table
            .range(&b"aaa/"[..]..)
            .unwrap()
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.value().to_vec(), value.value().to_vec())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            rows,
            vec![
                (b"aaa/outside".to_vec(), b"before".to_vec()),
                (b"app/1".to_vec(), b"updated".to_vec()),
                (b"app/new".to_vec(), b"new".to_vec()),
                (b"peer/outside".to_vec(), b"after".to_vec()),
            ]
        );
    }

    #[test]
    fn retain_prefix_handles_empty_and_all_ff_prefixes() {
        let database = database(InMemoryGroup::new());
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(BYTES).unwrap();
            for key in [b"".as_slice(), b"before", b"\xff", b"\xff\x00", b"\xff\xff"] {
                table.insert(key, b"value").unwrap();
            }
        }
        write.commit().unwrap();
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(BYTES).unwrap();
            table.insert(b"\xff\x01", b"staged").unwrap();
            table
                .retain_prefix(b"\xff", |key, _| key == b"\xff\x00")
                .unwrap();
        }
        write.commit().unwrap();
        {
            let read = database.begin_read().unwrap();
            let table = read.open_table(BYTES).unwrap();
            let keys = table
                .iter()
                .unwrap()
                .map(|entry| entry.unwrap().0.value().to_vec())
                .collect::<Vec<_>>();
            assert_eq!(
                keys,
                vec![b"".to_vec(), b"before".to_vec(), b"\xff\x00".to_vec()]
            );
        }
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(BYTES).unwrap();
            table.retain_prefix(b"", |key, _| key == b"before").unwrap();
        }
        write.commit().unwrap();
        let read = database.begin_read().unwrap();
        let table = read.open_table(BYTES).unwrap();
        let keys = table
            .iter()
            .unwrap()
            .map(|entry| entry.unwrap().0.value().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![b"before".to_vec()]);
    }

    #[test]
    fn sealed_facade_rejects_cache_work_while_native_reader_is_live() {
        let database = database(InMemoryGroup::new());
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(BYTES).unwrap();
            table.insert(b"a", b"first").unwrap();
            table.insert(b"b", b"second").unwrap();
        }
        write.commit().unwrap();
        // Enable caching only after publication so part of the durable data
        // remains cold when the facade seals.
        database
            .configure_cache(CacheConfig {
                byte_limit: 64 << 10,
            })
            .unwrap();
        loop {
            let progress = database.warm_cache(1).unwrap();
            if database.cache_stats().unwrap().entries != 0 {
                assert!(!progress.complete);
                break;
            }
            assert!(!progress.complete);
        }
        let before = database.cache_stats().unwrap();
        let reader = database.begin_read().unwrap();
        let close = database.close_native();
        assert_eq!(
            close.native_disposition(),
            BackendNativeDisposition::Retained
        );

        // The live reader prevents Core::close from running. The facade must
        // reject both mutations itself, without clearing or filling its cache.
        assert!(matches!(
            database.configure_cache(CacheConfig { byte_limit: 0 }),
            Err(StorageError::DatabaseClosed)
        ));
        assert_eq!(database.cache_stats().unwrap(), before);
        assert!(matches!(
            database.warm_cache(100),
            Err(StorageError::DatabaseClosed)
        ));
        assert!(matches!(
            database.warm_cache_if_needed(100),
            Err(StorageError::DatabaseClosed)
        ));
        assert!(matches!(
            database.cache_warmup_status(),
            Err(StorageError::DatabaseClosed)
        ));
        assert!(matches!(
            database.request_cache_warm_retry(),
            Err(StorageError::DatabaseClosed)
        ));
        assert_eq!(database.cache_stats().unwrap(), before);
        assert_eq!(
            reader
                .open_table(BYTES)
                .unwrap()
                .get(b"b")
                .unwrap()
                .unwrap()
                .value(),
            b"second"
        );
        drop(reader);
        assert_eq!(
            database.close_native().native_disposition(),
            BackendNativeDisposition::Drained
        );
    }

    #[test]
    fn cache_table_writes_retire_only_their_own_snapshot_before_replacement() {
        let database = database(InMemoryGroup::new());
        database
            .configure_cache(CacheConfig {
                byte_limit: 128 << 10,
            })
            .unwrap();
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(BYTES).unwrap();
            for id in 0..32_u64 {
                table
                    .insert(&id.to_be_bytes(), &vec![id as u8; 256])
                    .unwrap();
            }
        }
        write.commit().unwrap();
        let bound = database.cache_stats().unwrap().resident_bytes;
        database
            .configure_cache(CacheConfig { byte_limit: bound })
            .unwrap();
        let write = database.begin_write().unwrap();
        {
            let mut table = write.open_table(BYTES).unwrap();
            table.insert(&0_u64.to_be_bytes(), &vec![255; 256]).unwrap();
        }
        write.commit().unwrap();
        let publication_evictions = database.cache_stats().unwrap().evictions;
        let mut fully_resident = false;
        for _ in 0..512 {
            let progress = database.warm_cache(8).unwrap();
            assert!(progress.work <= 8);
            if progress.complete {
                fully_resident = progress.fully_resident;
                break;
            }
        }
        // The old and replacement leaf together exceed the exact cache
        // bound. A leaked writer snapshot would keep both roots live and
        // prevent this reconciliation from retaining the complete data set.
        assert!(fully_resident);
        assert_eq!(
            database.cache_stats().unwrap().evictions,
            publication_evictions
        );
        let before = database.cache_stats().unwrap();
        let read = database.begin_read().unwrap();
        let table = read.open_table(BYTES).unwrap();
        for id in 0..32_u64 {
            assert_eq!(
                table.get(&id.to_be_bytes()).unwrap().unwrap().value(),
                vec![if id == 0 { 255 } else { id as u8 }; 256]
            );
        }
        let after = database.cache_stats().unwrap();
        assert_eq!(after.misses, before.misses);
        assert_eq!(after.evictions, before.evictions);
    }

    #[test]
    fn closing_wakes_a_writer_waiting_behind_an_active_writer() {
        let database = Arc::new(database(InMemoryGroup::new()));
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

#[cfg(test)]
#[path = "staging_credit_tests.rs"]
pub(crate) mod staging_credit_tests;

#[cfg(test)]
#[path = "native_owned_arc_tests.rs"]
pub(crate) mod native_owned_arc_tests;

#[cfg(test)]
#[path = "read_fork_tests.rs"]
pub(crate) mod read_fork_tests;

#[path = "source_read_backing.rs"]
pub(crate) mod source_read;
