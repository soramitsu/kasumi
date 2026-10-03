//! Transactional storage over a durable segmented log and immutable disk directory.
//!
//! The byte-bounded cache retains all fitting values and pages. Disk remains
//! authoritative; snapshots pin immutable roots, and uncertain effects fence
//! the exact owner until an observed close and strict reopen.

use crate::cache::{CacheConfig, CacheStats};
use crate::disk_state::DiskState;
use crate::group::SegmentGroupBackend;
use crate::snapshot_pins::SnapshotPin;
use std::any::Any;
use std::fmt;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError};

pub const MAX_VALUE_BYTES: usize = 40 << 20;
pub const MAX_BATCH_BYTES: usize = 96 << 20;
pub const MAX_KEY_BYTES: usize = 4096;
pub const MAX_TABLE_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendNativeDisposition {
    Drained,
    Retained,
}

/// Whether a backend has entered its one-shot close operation. A retry is
/// allowed only when the backend explicitly proves that close was not entered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendCloseEntry {
    NotEntered,
    Entered,
}

#[derive(Debug)]
pub struct BackendCloseOutcome {
    entry: BackendCloseEntry,
    native: BackendNativeDisposition,
    result: io::Result<()>,
}
impl BackendCloseOutcome {
    pub fn not_entered(error: io::Error) -> Self {
        Self {
            entry: BackendCloseEntry::NotEntered,
            native: BackendNativeDisposition::Retained,
            result: Err(error),
        }
    }
    pub fn drained(result: io::Result<()>) -> Self {
        Self {
            entry: BackendCloseEntry::Entered,
            native: BackendNativeDisposition::Drained,
            result,
        }
    }
    pub fn retained(error: io::Error) -> Self {
        Self::retained_result(Err(error))
    }
    pub fn retained_result(result: io::Result<()>) -> Self {
        Self {
            entry: BackendCloseEntry::Entered,
            native: BackendNativeDisposition::Retained,
            result,
        }
    }
    pub fn entry(&self) -> BackendCloseEntry {
        self.entry
    }
    pub fn native_disposition(&self) -> BackendNativeDisposition {
        self.native
    }
    pub fn into_result(self) -> io::Result<()> {
        self.result
    }
    pub fn into_parts(self) -> (io::Result<()>, BackendNativeDisposition) {
        (self.result, self.native)
    }
}

/// A repeat close reports the first terminal disposition and errno without
/// moving or replacing the original error returned to its retained caller.
#[derive(Clone, Copy)]
enum CloseErrorProjection {
    Os(i32),
    Kind(io::ErrorKind),
}

impl CloseErrorProjection {
    fn capture(error: &io::Error) -> Self {
        error
            .raw_os_error()
            .map_or_else(|| Self::Kind(error.kind()), Self::Os)
    }

    fn report(self) -> io::Error {
        match self {
            Self::Os(errno) => io::Error::from_raw_os_error(errno),
            Self::Kind(kind) => kind.into(),
        }
    }
}

#[derive(Clone, Copy)]
struct CoreCloseReport {
    native: BackendNativeDisposition,
    error: Option<CloseErrorProjection>,
}

impl CoreCloseReport {
    fn capture(outcome: &BackendCloseOutcome) -> Self {
        debug_assert_eq!(outcome.entry, BackendCloseEntry::Entered);
        Self {
            native: outcome.native,
            error: outcome
                .result
                .as_ref()
                .err()
                .map(CloseErrorProjection::capture),
        }
    }

    fn report(self) -> BackendCloseOutcome {
        BackendCloseOutcome {
            entry: BackendCloseEntry::Entered,
            native: self.native,
            result: self.error.map_or(Ok(()), |error| Err(error.report())),
        }
    }
}

pub trait ResidentLease: Send + Sync {
    /// Retire this lease's actual Box before dropping its reservation token.
    fn retire(self: Box<Self>);
}
impl<T: Send + Sync> ResidentLease for T {
    fn retire(self: Box<Self>) {
        let reservation = {
            let allocation = self;
            *allocation
        };
        drop(reservation);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerFailed;
impl fmt::Display for OwnerFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("storage owner failed")
    }
}
impl std::error::Error for OwnerFailed {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    CapacityDenied,
    OwnerFailed,
}
impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityDenied => f.write_str("storage capacity denied"),
            Self::OwnerFailed => f.write_str("storage owner failed"),
        }
    }
}
impl std::error::Error for AdmissionError {}

/// Physical-owner admission. An `OwnerFailed` from any call, including
/// `check_owner`, fences the core, which then calls `owner_failed` exactly
/// once. `CapacityDenied` proves no published effect and never fences; private work
/// may have been durably rolled back.
pub trait StorageAdmission: Send + Sync {
    /// Purpose-bound native source funding through this actual installed owner.
    fn install_source_pool(
        self: Arc<Self>,
        _install: &mut crate::SourcePoolInstall<'_>,
    ) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn check_owner(&self) -> Result<(), OwnerFailed>;
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError>;
    /// Pure charge planning; this neither admits memory nor checks owner health.
    fn quote_cache_memory(
        &self,
        credit_bytes: u64,
    ) -> Result<crate::CacheMemoryQuote, AdmissionError>;
    /// Optional cache credit, including temporary rehash custody. This must
    /// preserve mandatory-work headroom and never consume maintenance escrow.
    fn reserve_cache_memory(
        self: Arc<Self>,
        credit_bytes: u64,
    ) -> Result<crate::CacheMemoryLease, AdmissionError>;
    fn reserve_growth(&self, current: u64, requested: u64) -> Result<(), AdmissionError>;
    fn settle_growth(&self, actual: u64) -> Result<(), OwnerFailed>;
    fn owner_failed(&self);
}

#[derive(Debug)]
pub enum CoreError {
    Io(io::Error),
    Corrupt(&'static str),
    CapacityDenied,
    OwnerFailed,
    Closed,
    InvalidInput(&'static str),
    MissingTable,
    UnknownCommit(io::Error),
    Panicked(Box<CorePanic>),
    OpeningFailure(Box<CoreOpenFailure>),
}
impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "storage I/O: {error}"),
            Self::Corrupt(reason) => write!(f, "corrupt committed storage: {reason}"),
            Self::CapacityDenied => f.write_str("storage capacity denied"),
            Self::OwnerFailed => f.write_str("storage owner failed"),
            Self::Closed => f.write_str("database closed"),
            Self::InvalidInput(reason) => write!(f, "invalid storage input: {reason}"),
            Self::MissingTable => f.write_str("table does not exist"),
            Self::UnknownCommit(error) => write!(f, "commit outcome unknown: {error}"),
            Self::Panicked(panic) => panic.fmt(f),
            Self::OpeningFailure(failure) => failure.fmt(f),
        }
    }
}
impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) | Self::UnknownCommit(error) => Some(error),
            Self::Panicked(panic) => Some(panic),
            Self::OpeningFailure(failure) => Some(failure),
            _ => None,
        }
    }
}
impl CoreError {
    /// An unwinding commit may have entered any backend effect. The payload
    /// stays inspectable as the `CorePanic` source of the unknown outcome.
    fn unknown_commit(panic: CorePanic) -> Self {
        Self::UnknownCommit(io::Error::other(panic))
    }

    fn panicked(panic: CorePanic) -> Self {
        Self::Panicked(Box::new(panic))
    }

    /// Errors that leave the physical owner or a backend effect uncertain.
    /// Capacity, input, table and close errors are decided before any effect.
    pub(crate) fn fences_owner(&self) -> bool {
        matches!(
            self,
            Self::Io(_)
                | Self::Corrupt(_)
                | Self::OwnerFailed
                | Self::UnknownCommit(_)
                | Self::Panicked(_)
        )
    }
}

/// Original unwind payload from a storage operation or opening. The payload
/// remains owned and inspectable without requiring it to implement `Sync`.
pub struct CorePanic(Mutex<Box<dyn Any + Send>>);

impl CorePanic {
    pub(crate) fn new(payload: Box<dyn Any + Send>) -> Self {
        Self(Mutex::new(payload))
    }

    pub fn with_payload<R>(&self, inspect: impl FnOnce(&(dyn Any + Send)) -> R) -> R {
        let payload = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inspect(payload.as_ref())
    }
}

impl fmt::Debug for CorePanic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CorePanic(original payload retained)")
    }
}

impl fmt::Display for CorePanic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("storage operation panicked; original payload retained")
    }
}

impl std::error::Error for CorePanic {}

fn run_open<T>(
    close_on_failure: bool,
    work: impl FnOnce() -> Result<T, CoreError>,
) -> Result<T, CoreError> {
    if close_on_failure {
        match catch_unwind(AssertUnwindSafe(work)) {
            Ok(result) => result,
            Err(payload) => Err(CoreError::Panicked(Box::new(CorePanic::new(payload)))),
        }
    } else {
        // RetainedDatabaseOpening owns the exact SharedBackend and catches its
        // own unwind before recording the original terminal observation.
        work()
    }
}

struct FailedOpenOwner(Arc<dyn SegmentGroupBackend>);

impl FailedOpenOwner {
    fn close(&self) -> BackendCloseOutcome {
        self.0.close()
    }
}

/// A constructor failure whose close did not prove clean native drain. The
/// original opening error and first close observation remain available, and a
/// pre-effect busy close may be retried on this exact owner.
#[must_use]
pub struct CoreOpenFailure {
    original: CoreError,
    owner: Option<FailedOpenOwner>,
    close: BackendCloseOutcome,
    close_panic: Option<CorePanic>,
}

impl CoreOpenFailure {
    pub fn original_error(&self) -> &CoreError {
        &self.original
    }

    pub fn close_report(&self) -> &BackendCloseOutcome {
        &self.close
    }

    pub fn close_panic(&self) -> Option<&CorePanic> {
        self.close_panic.as_ref()
    }

    pub fn retry_close(&mut self) -> &BackendCloseOutcome {
        if self.close.entry() == BackendCloseEntry::NotEntered
            && let Some(owner) = self.owner.as_ref()
        {
            self.close = match catch_unwind(AssertUnwindSafe(|| owner.close())) {
                Ok(close) => close,
                Err(payload) => {
                    self.close_panic = Some(CorePanic::new(payload));
                    BackendCloseOutcome::retained(io::Error::other("backend close panicked"))
                }
            };
            if self.close.native_disposition() == BackendNativeDisposition::Drained {
                self.owner.take();
            }
        }
        &self.close
    }
}

impl fmt::Debug for CoreOpenFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreOpenFailure")
            .field("original", &self.original)
            .field("close", &self.close)
            .field("close_panic", &self.close_panic)
            .field("owner_retained", &self.owner.is_some())
            .finish()
    }
}

impl fmt::Display for CoreOpenFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "opening failed: {}; native close: ", self.original)?;
        match self.close.result.as_ref() {
            Ok(()) => f.write_str("drained"),
            Err(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for CoreOpenFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

impl Drop for CoreOpenFailure {
    fn drop(&mut self) {
        // A caller who discards the report cannot silently perform an
        // unobserved native close of an unproved owner.
        if let Some(owner) = self.owner.take() {
            std::mem::forget(owner);
        }
    }
}

fn failed_open(owner: FailedOpenOwner, original: CoreError, close_on_failure: bool) -> CoreError {
    if !close_on_failure {
        // Used only by the retained opening, which already holds the exact
        // SharedBackend and records its own terminal close attempt.
        return original;
    }
    let (close, close_panic) = match catch_unwind(AssertUnwindSafe(|| owner.close())) {
        Ok(close) => (close, None),
        Err(payload) => (
            BackendCloseOutcome::retained(io::Error::other("backend close panicked")),
            Some(CorePanic::new(payload)),
        ),
    };
    if close.native_disposition() == BackendNativeDisposition::Drained && close.result.is_ok() {
        return original;
    }
    let owner = if close.native_disposition() == BackendNativeDisposition::Drained {
        None
    } else {
        Some(owner)
    };
    CoreError::OpeningFailure(Box::new(CoreOpenFailure {
        original,
        owner,
        close,
        close_panic,
    }))
}
impl From<io::Error> for CoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<AdmissionError> for CoreError {
    fn from(error: AdmissionError) -> Self {
        match error {
            AdmissionError::CapacityDenied => Self::CapacityDenied,
            AdmissionError::OwnerFailed => Self::OwnerFailed,
        }
    }
}

pub enum Operation {
    CreateTable {
        table: Arc<str>,
    },
    Put {
        table: Arc<str>,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        table: Arc<str>,
        key: Vec<u8>,
    },
}
impl Operation {
    pub fn create_table(table: impl Into<Arc<str>>) -> Self {
        Self::CreateTable {
            table: table.into(),
        }
    }
    pub fn put(
        table: impl Into<Arc<str>>,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Self {
        Self::Put {
            table: table.into(),
            key: key.into(),
            value: value.into(),
        }
    }
    pub fn delete(table: impl Into<Arc<str>>, key: impl Into<Vec<u8>>) -> Self {
        Self::Delete {
            table: table.into(),
            key: key.into(),
        }
    }
}

struct State {
    backend: Arc<dyn SegmentGroupBackend>,
    disk: Option<DiskState>,
    close_entered: bool,
    close_report: Option<CoreCloseReport>,
    closed: bool,
    maintenance_active: bool,
    maintenance_position: Option<CommittedPosition>,
}
impl State {
    fn disk(&mut self) -> Result<&mut DiskState, CoreError> {
        self.disk.as_mut().ok_or(CoreError::Closed)
    }
}
struct Shared {
    state: Mutex<State>,
    admission: Arc<dyn StorageAdmission>,
    stopped: AtomicBool,
    fenced: AtomicBool,
    fence_panic: OnceLock<CorePanic>,
    snapshots: AtomicUsize,
    _lease: Box<dyn ResidentLease>,
}
impl Shared {
    /// Latch owner failure. The admission owner is told exactly once; an
    /// unwinding callback cannot unlatch the fence and its payload is kept.
    fn fence(&self) {
        if self.fenced.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| self.admission.owner_failed())) {
            let _ = self.fence_panic.set(CorePanic::new(payload));
        }
    }

    /// A poisoned state lock means an earlier holder unwound with an
    /// unknown effect. It is an owner failure, never a retryable busy state.
    fn lock_state(&self) -> Result<MutexGuard<'_, State>, CoreError> {
        self.state.lock().map_err(|_| {
            self.fence();
            CoreError::OwnerFailed
        })
    }

    fn check_owner(&self) -> Result<(), CoreError> {
        if self.fenced.load(Ordering::Acquire) {
            return Err(CoreError::OwnerFailed);
        }
        self.admission.check_owner().map_err(|_| {
            self.fence();
            CoreError::OwnerFailed
        })
    }

    fn check_open(&self, state: &State) -> Result<(), CoreError> {
        if state.closed || self.stopped.load(Ordering::Acquire) {
            return Err(CoreError::Closed);
        }
        self.check_owner()
    }

    /// Run one installed operation under the state lock. An owner-failure
    /// error or an unwind from a backend or admission callback fences before
    /// the lock is released, so no later caller can act on an uncertain
    /// owner. An error returned while unfenced had no committed effect.
    fn run<T>(
        &self,
        unwound: fn(CorePanic) -> CoreError,
        work: impl FnOnce(&mut State) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        let mut state = self.lock_state()?;
        let result = catch_unwind(AssertUnwindSafe(|| work(&mut state)))
            .unwrap_or_else(|payload| Err(unwound(CorePanic::new(payload))));
        if result.as_ref().is_err_and(CoreError::fences_owner) {
            self.fence();
        }
        result
    }
}
pub struct Core {
    shared: Arc<Shared>,
}

pub struct ReadSnapshot {
    shared: Arc<Shared>,
    pin: SnapshotPin,
}

/// One bounded reconciliation pass over cache slots and reachable directory
/// entries. Complete does not imply resident when the configured budget is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheWarmup {
    pub work: usize,
    pub complete: bool,
    pub fully_resident: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheWarmupState {
    Pending,
    Running,
    Resident,
    CapacityLimited,
    Disabled,
}

/// Owner-checked automatic scheduling state. Fatal failures remain errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheWarmupStatus {
    pub state: CacheWarmupState,
    /// Whether the latest attempt examined its whole selected/pinned union.
    /// Required workspace denial can park an incomplete attempt.
    pub complete: bool,
    /// Required workspace or maintenance provider admission prevented work.
    /// Retry the incomplete cursor with backoff. A completed local-budget-only
    /// attempt remains parked until its retention eligibility changes.
    pub provider_limited: bool,
    /// Examined work units, including pressure-refused items, saturating.
    pub cumulative_work: u64,
    pub attempt_generation: Option<u64>,
    pub byte_limit: u64,
}

/// Published commit boundary; offsets from different segments are not comparable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedPosition {
    pub segment_id: u64,
    pub offset: u64,
}

/// Owned output bytes whose allocation remains admitted until the consumer drops it.
pub struct AdmittedValue {
    pub(crate) bytes: Vec<u8>,
    pub(crate) lease: Box<dyn ResidentLease>,
}
impl AdmittedValue {
    pub(crate) fn request_bytes(len: usize) -> Result<u64, CoreError> {
        let bytes = len
            .checked_add(std::mem::size_of::<Self>() + 192)
            .ok_or(CoreError::CapacityDenied)?;
        u64::try_from(bytes).map_err(|_| CoreError::CapacityDenied)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn into_parts(self) -> (Vec<u8>, Box<dyn ResidentLease>) {
        (self.bytes, self.lease)
    }
    pub(crate) fn allocate(
        admission: &Arc<dyn StorageAdmission>,
        len: usize,
    ) -> Result<Self, CoreError> {
        // Include the output handle, allocator allowance and retained lease.
        let lease = admission.reserve_workspace(Self::request_bytes(len)?)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| CoreError::CapacityDenied)?;
        if bytes.capacity() != len {
            return Err(CoreError::CapacityDenied);
        }
        bytes.resize(len, 0);
        Ok(Self { bytes, lease })
    }
    pub(crate) fn copy(
        admission: &Arc<dyn StorageAdmission>,
        value: &[u8],
    ) -> Result<Self, CoreError> {
        let mut result = Self::allocate(admission, value.len())?;
        result.bytes.copy_from_slice(value);
        Ok(result)
    }
}

/// Reusable point-read backing admitted by one exact native owner. Directory
/// pages and output coexist; capacity remains charged across short/absent reads.
/// The output never escapes independently of this exclusive workspace borrow.
pub struct PreparedPointRead {
    pub(crate) directory: crate::directory::DirectoryReadWorkspace,
    pub(crate) output: AdmittedValue,
    owner: Arc<Shared>,
    _charge: Box<dyn ResidentLease>,
}
impl PreparedPointRead {
    /// Request for the fixed workspace shell; directory and output are separate.
    pub const fn shell_request_bytes() -> u64 {
        (std::mem::size_of::<Self>() + 192) as u64
    }
    /// Exact reusable directory traversal and page request in one actual grant.
    pub const fn directory_request_bytes() -> u64 {
        crate::directory::DirectoryReadWorkspace::request_bytes()
    }
    pub fn capacity(&self) -> usize {
        self.output.bytes.len()
    }
}

impl Clone for ReadSnapshot {
    fn clone(&self) -> Self {
        self.shared.snapshots.fetch_add(1, Ordering::AcqRel);
        Self {
            shared: self.shared.clone(),
            pin: self.pin.clone(),
        }
    }
}
impl Drop for ReadSnapshot {
    fn drop(&mut self) {
        self.shared.snapshots.fetch_sub(1, Ordering::AcqRel);
    }
}
impl ReadSnapshot {
    pub fn generation(&self) -> u64 {
        self.pin.root().generation
    }
    pub fn table_exists(&self, table: &str) -> Result<bool, CoreError> {
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state.disk()?.table_exists(&self.pin, table)
        })
    }
    pub fn next_key_admitted(
        &self,
        table: &str,
        start: &[u8],
        after: Option<&[u8]>,
    ) -> Result<Option<AdmittedValue>, CoreError> {
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state
                .disk()?
                .next_key_admitted(&self.pin, table, start, after)
        })
    }
}

impl Core {
    /// Strictly initialize an empty group using the installed owner's explicit
    /// incarnation and cache budget. Existing groups require `open_with_backend`.
    pub fn create_with_backend(
        backend: impl SegmentGroupBackend + 'static,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        cache: CacheConfig,
    ) -> Result<Self, CoreError> {
        Self::assemble(Arc::new(backend), admission, group_id, cache, true, true)
    }
    pub fn open_with_backend(
        backend: impl SegmentGroupBackend + 'static,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        cache: CacheConfig,
    ) -> Result<Self, CoreError> {
        Self::assemble(Arc::new(backend), admission, group_id, cache, false, true)
    }
    pub(crate) fn create_with_backend_retained(
        backend: impl SegmentGroupBackend + 'static,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        cache: CacheConfig,
    ) -> Result<Self, CoreError> {
        Self::assemble(Arc::new(backend), admission, group_id, cache, true, false)
    }
    pub(crate) fn open_with_backend_retained(
        backend: impl SegmentGroupBackend + 'static,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        cache: CacheConfig,
    ) -> Result<Self, CoreError> {
        Self::assemble(Arc::new(backend), admission, group_id, cache, false, false)
    }
    fn assemble(
        backend: Arc<dyn SegmentGroupBackend>,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        cache: CacheConfig,
        create: bool,
        close_on_failure: bool,
    ) -> Result<Self, CoreError> {
        let result = run_open(close_on_failure, || {
            admission
                .check_owner()
                .map_err(|_| CoreError::OwnerFailed)?;
            let lease =
                admission.reserve_workspace((std::mem::size_of::<Shared>() + 256) as u64)?;
            let disk = if create {
                DiskState::create(backend.clone(), admission.clone(), group_id, cache)?
            } else {
                DiskState::open(backend.clone(), admission.clone(), group_id, cache)?
            };
            let position = disk.committed_position()?;
            Ok(Self {
                shared: Arc::new(Shared {
                    state: Mutex::new(State {
                        backend: backend.clone(),
                        disk: Some(disk),
                        close_entered: false,
                        close_report: None,
                        closed: false,
                        maintenance_active: false,
                        maintenance_position: position,
                    }),
                    admission: admission.clone(),
                    stopped: AtomicBool::new(false),
                    fenced: AtomicBool::new(false),
                    fence_panic: OnceLock::new(),
                    snapshots: AtomicUsize::new(0),
                    _lease: lease,
                }),
            })
        });
        result.map_err(|error| failed_open(FailedOpenOwner(backend), error, close_on_failure))
    }
    pub fn snapshot(&self) -> Result<ReadSnapshot, CoreError> {
        if self.shared.stopped.load(Ordering::Acquire) {
            return Err(CoreError::Closed);
        }
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            let pin = state.disk()?.snapshot()?;
            self.shared.snapshots.fetch_add(1, Ordering::AcqRel);
            Ok(ReadSnapshot {
                shared: self.shared.clone(),
                pin,
            })
        })
    }
    pub(crate) fn check_read_owner(&self) -> Result<(), CoreError> {
        self.shared
            .run(CoreError::panicked, |state| self.shared.check_open(state))
    }
    pub fn is_fenced(&self) -> bool {
        self.shared.fenced.load(Ordering::Acquire)
    }
    pub fn fence_panic(&self) -> Option<&CorePanic> {
        self.shared.fence_panic.get()
    }
    pub(crate) fn fence(&self) {
        self.shared.fence();
    }
    pub(crate) fn check_owner(&self) -> Result<(), CoreError> {
        self.shared
            .run(CoreError::panicked, |_| self.shared.check_owner())
    }
    pub(crate) fn reserve_workspace(
        &self,
        bytes: u64,
    ) -> Result<Box<dyn ResidentLease>, CoreError> {
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            self.shared
                .admission
                .reserve_workspace(bytes)
                .map_err(Into::into)
        })
    }
    pub fn generation(&self) -> Result<u64, CoreError> {
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state.disk()?.generation()
        })
    }
    pub fn committed_position(&self) -> Result<Option<CommittedPosition>, CoreError> {
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state.disk()?.committed_position()
        })
    }
    pub fn configure_cache(&self, config: CacheConfig) -> Result<(), CoreError> {
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state.disk()?.configure_cache(config)
        })
    }
    pub fn cache_stats(&self) -> Result<CacheStats, CoreError> {
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state.disk()?.cache_stats()
        })
    }
    /// Advance an explicit bounded pass, restarting a completed pass on demand.
    /// Admission refusal, including a metadata shrink, returns CapacityDenied
    /// with its continuation preserved for retry. Periodic drivers should use
    /// warm_cache_if_needed, which reports provider pressure without an error.
    pub fn warm_cache(&self, work_limit: usize) -> Result<CacheWarmup, CoreError> {
        if work_limit == 0 {
            return Err(CoreError::InvalidInput(
                "cache warm-up step must be nonzero",
            ));
        }
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state.disk()?.warm(work_limit)
        })
    }

    /// Advance automatic warm-up only when local eligibility has changed.
    /// Completed oversized attempts park without data I/O or new admission.
    /// Provider refusal retains the incomplete cursor for bounded retry; an
    /// automatic driver must apply backoff to provider-limited attempts.
    pub fn warm_cache_if_needed(&self, work_limit: usize) -> Result<CacheWarmup, CoreError> {
        if work_limit == 0 {
            return Err(CoreError::InvalidInput(
                "cache warm-up step must be nonzero",
            ));
        }
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state.disk()?.warm_if_needed(work_limit)
        })
    }

    pub fn cache_warmup_status(&self) -> Result<CacheWarmupStatus, CoreError> {
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state.disk()?.warm_status()
        })
    }

    /// Explicit policy-driven restart, discarding the current continuation.
    /// Periodic drivers should use warm_cache_if_needed with provider backoff
    /// instead; headroom samples are not a reason to discard bounded progress.
    pub fn request_cache_warm_retry(&self) -> Result<(), CoreError> {
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state.disk()?.request_warm_retry()
        })
    }
    /// Finish one compaction cycle. Individual steps use bounded workspace;
    /// explicit full compaction may still take time proportional to the dataset.
    pub fn compact(&self) -> Result<(), CoreError> {
        self.shared.run(CoreError::unknown_commit, |state| {
            self.shared.check_open(state)?;
            while !state.disk()?.compact_step(64)?.complete {}
            state.maintenance_active = false;
            state.maintenance_position = state.disk()?.committed_position()?;
            Ok(())
        })
    }
    /// Advance at most one maintenance work unit once append growth reaches a
    /// MiB. Work uses the same durable publication and snapshot ownership rules.
    pub(crate) fn prepare_write(&self) -> Result<(), CoreError> {
        self.shared.run(CoreError::unknown_commit, |state| {
            self.shared.check_open(state)?;
            let now = state.disk()?.committed_position()?;
            let grew = match (state.maintenance_position, now) {
                (Some(old), Some(now)) if old.segment_id == now.segment_id => {
                    now.offset.saturating_sub(old.offset) >= 1 << 20
                }
                (None, None) => false,
                (None, Some(now)) => now.segment_id > 1 || now.offset >= 1 << 20,
                _ => true,
            };
            if grew || state.maintenance_active {
                state.maintenance_active = !state.disk()?.compact_step(1)?.complete;
                if !state.maintenance_active {
                    state.maintenance_position = state.disk()?.committed_position()?;
                }
            }
            Ok(())
        })
    }
    fn check_snapshot(&self, snapshot: &ReadSnapshot) -> Result<(), CoreError> {
        if !Arc::ptr_eq(&self.shared, &snapshot.shared) {
            return Err(CoreError::InvalidInput(
                "snapshot belongs to another database owner",
            ));
        }
        Ok(())
    }
    pub fn prepare_point_read(
        &self,
        max_value_bytes: usize,
    ) -> Result<PreparedPointRead, CoreError> {
        if max_value_bytes > MAX_VALUE_BYTES {
            return Err(CoreError::InvalidInput(
                "prepared point bound exceeds native value limit",
            ));
        }
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            let charge = self
                .shared
                .admission
                .reserve_workspace(PreparedPointRead::shell_request_bytes())?;
            let directory = crate::directory::DirectoryReadWorkspace::new(&self.shared.admission)?;
            let output = AdmittedValue::allocate(&self.shared.admission, max_value_bytes)?;
            self.shared.check_open(state)?;
            Ok(PreparedPointRead {
                directory,
                output,
                owner: self.shared.clone(),
                _charge: charge,
            })
        })
    }

    pub fn table_exists_prepared(
        &self,
        snapshot: &ReadSnapshot,
        table: &str,
        workspace: &mut PreparedPointRead,
    ) -> Result<bool, CoreError> {
        self.check_snapshot(snapshot)?;
        if !Arc::ptr_eq(&self.shared, &workspace.owner) {
            return Err(CoreError::InvalidInput("prepared point owner differs"));
        }
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state
                .disk()?
                .table_exists_prepared(&snapshot.pin, table, workspace)
        })
    }

    /// Inspect the exact pinned directory's value extent using already-owned
    /// traversal pages. This does not read or authenticate the value bytes.
    pub fn point_length_prepared(
        &self,
        snapshot: &ReadSnapshot,
        table: &str,
        key: &[u8],
        workspace: &mut PreparedPointRead,
    ) -> Result<Option<usize>, CoreError> {
        self.check_snapshot(snapshot)?;
        if !Arc::ptr_eq(&self.shared, &workspace.owner) {
            return Err(CoreError::InvalidInput("prepared point owner differs"));
        }
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state
                .disk()?
                .point_length_prepared(&snapshot.pin, table, key, workspace)
        })
    }

    pub fn get_prepared<'workspace>(
        &self,
        snapshot: &ReadSnapshot,
        table: &str,
        key: &[u8],
        max_value_bytes: usize,
        workspace: &'workspace mut PreparedPointRead,
    ) -> Result<Option<&'workspace [u8]>, CoreError> {
        self.check_snapshot(snapshot)?;
        if !Arc::ptr_eq(&self.shared, &workspace.owner) || max_value_bytes > workspace.capacity() {
            return Err(CoreError::InvalidInput(
                "prepared point owner or bound differs",
            ));
        }
        let length = self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state
                .disk()?
                .get_prepared(&snapshot.pin, table, key, max_value_bytes, workspace)
        })?;
        Ok(length.map(|length| &workspace.output.bytes[..length]))
    }

    pub fn get_admitted(
        &self,
        snapshot: &ReadSnapshot,
        table: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<AdmittedValue>, CoreError> {
        self.check_snapshot(snapshot)?;
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state
                .disk()?
                .get_admitted(&snapshot.pin, table, key, max_value_bytes)
        })
    }
    pub fn key_exists(
        &self,
        snapshot: &ReadSnapshot,
        table: &str,
        key: &[u8],
    ) -> Result<bool, CoreError> {
        self.check_snapshot(snapshot)?;
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state.disk()?.key_exists(&snapshot.pin, table, key)
        })
    }
    pub fn prefix_exists(
        &self,
        snapshot: &ReadSnapshot,
        table: &str,
        prefix: &[u8],
    ) -> Result<bool, CoreError> {
        self.check_snapshot(snapshot)?;
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            Ok(state
                .disk()?
                .next(&snapshot.pin, table, prefix, None)?
                .is_some())
        })
    }
    pub fn next_admitted(
        &self,
        snapshot: &ReadSnapshot,
        table: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        max_value_bytes: usize,
    ) -> Result<Option<(AdmittedValue, AdmittedValue)>, CoreError> {
        self.check_snapshot(snapshot)?;
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            state
                .disk()?
                .next_admitted(&snapshot.pin, table, prefix, after, max_value_bytes)
        })
    }
    pub fn commit(&self, operations: &[Operation]) -> Result<(), CoreError> {
        self.shared.run(CoreError::unknown_commit, |state| {
            self.shared.check_open(state)?;
            if operations.is_empty() {
                return Ok(());
            }
            state.disk()?.commit(operations)
        })
    }
    /// Stop new snapshots and writes. A pre-effect busy result is retryable;
    /// once the backend close is entered, its native effect is never replayed.
    /// Later calls project the first terminal result without moving its error.
    pub fn close(&self) -> BackendCloseOutcome {
        self.shared.stopped.store(true, Ordering::Release);
        if self.shared.snapshots.load(Ordering::Acquire) != 0 {
            return BackendCloseOutcome::not_entered(io::ErrorKind::WouldBlock.into());
        }
        let mut state = match self.shared.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => {
                return BackendCloseOutcome::not_entered(io::ErrorKind::WouldBlock.into());
            }
            Err(TryLockError::Poisoned(poisoned)) => {
                // The unwound holder fenced this owner, but a fenced owner
                // must still drain. The close fields below are written only
                // here, so an unwound close stays entered and is not replayed.
                self.shared.fence();
                poisoned.into_inner()
            }
        };
        // A snapshot may have passed its open check while holding this mutex
        // before close stopped admission. Its pin and counter are now visible.
        if self.shared.snapshots.load(Ordering::Acquire) != 0 {
            return BackendCloseOutcome::not_entered(io::ErrorKind::WouldBlock.into());
        }
        if let Some(report) = state.close_report {
            return report.report();
        }
        if state.close_entered {
            return BackendCloseOutcome::retained(io::ErrorKind::BrokenPipe.into());
        }
        state.close_entered = true;
        let outcome = state.backend.close();
        if outcome.entry() == BackendCloseEntry::NotEntered {
            // The backend attests that it made no one-shot close attempt. The
            // stopped Core retains the same owner and may retry after contention.
            state.close_entered = false;
        } else {
            state.close_report = Some(CoreCloseReport::capture(&outcome));
            if outcome.native_disposition() == BackendNativeDisposition::Drained {
                state.closed = true;
                state.disk.take();
            }
        }
        outcome
    }

    pub fn admission(&self) -> Arc<dyn StorageAdmission> {
        self.shared.admission.clone()
    }
}
#[cfg(test)]
#[path = "core_tests.rs"]
mod tests;

#[path = "core_source_read.rs"]
mod source_read;
pub(crate) use source_read::SourceReadContext;
