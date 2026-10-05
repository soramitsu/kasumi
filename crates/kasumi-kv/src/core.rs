//! Transactional storage over a durable segmented log and immutable disk directory.
//!
//! The byte-bounded cache retains all fitting values and pages. Disk remains
//! authoritative; snapshots pin immutable roots, and uncertain effects fence
//! the exact owner until an observed close and strict reopen.

use crate::cache::{CacheConfig, CacheStats};
use crate::disk_state::DiskState;
use crate::group::SegmentGroupBackend;
use crate::native_owned_arc::NativeOwnedArc;
pub(crate) use crate::native_resident_lease::NativeResidentLease;
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

/// Native commit disposition recorded alongside the original failure. Unknown
/// outcomes never prove abort. Rejected alone does not prove native drain;
/// retained transactions expose their actual terminal and disposal observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreErrorDisposition {
    Rejected,
    UnknownCommit,
}

/// Original inline failure. I/O errors and panic payloads retain their existing
/// owners; changing commit disposition adds no diagnostic allocation.
#[derive(Debug)]
pub enum CoreErrorCause {
    Io(io::Error),
    /// A prospectively admitted allocation refused before a native effect.
    /// Keep its actual error separate from uncertain physical I/O.
    AllocationRefused(io::Error),
    Corrupt(&'static str),
    CapacityDenied,
    OwnerFailed,
    Closed,
    InvalidInput(&'static str),
    MissingTable,
    Panicked(CorePanic),
}
#[derive(Debug)]
pub struct CoreError {
    disposition: CoreErrorDisposition,
    cause: CoreErrorCause,
}
impl CoreError {
    pub fn new(cause: CoreErrorCause) -> Self {
        Self {
            disposition: CoreErrorDisposition::Rejected,
            cause,
        }
    }
    pub fn disposition(&self) -> CoreErrorDisposition {
        self.disposition
    }
    pub fn cause(&self) -> &CoreErrorCause {
        &self.cause
    }
    /// Borrow a failure only when no unknown commit disposition was recorded.
    pub fn rejected_cause(&self) -> Option<&CoreErrorCause> {
        (!self.is_unknown_commit()).then_some(&self.cause)
    }
    pub fn is_unknown_commit(&self) -> bool {
        self.disposition == CoreErrorDisposition::UnknownCommit
    }
    pub fn is_capacity_denied(&self) -> bool {
        matches!(self.rejected_cause(), Some(CoreErrorCause::CapacityDenied))
            || matches!(self.rejected_cause(), Some(CoreErrorCause::AllocationRefused(original))
                if original.kind() == io::ErrorKind::OutOfMemory)
    }
    pub fn io_error(&self) -> Option<&io::Error> {
        match &self.cause {
            CoreErrorCause::Io(original) | CoreErrorCause::AllocationRefused(original) => {
                Some(original)
            }
            _ => None,
        }
    }
    pub fn panic(&self) -> Option<&CorePanic> {
        match &self.cause {
            CoreErrorCause::Panicked(original) => Some(original),
            _ => None,
        }
    }
    pub(crate) fn into_unknown_commit(mut self) -> Self {
        self.disposition = CoreErrorDisposition::UnknownCommit;
        self
    }
    /// Preserve the established ordinary I/O conversion without cloning an
    /// original error. Unknown outcomes and all other causes remain in this
    /// exact error owner.
    pub(crate) fn into_io(self) -> Result<io::Error, Self> {
        if self.is_unknown_commit() {
            return Err(self);
        }
        match self.cause {
            CoreErrorCause::Io(original) => Ok(original),
            cause => Err(Self {
                disposition: self.disposition,
                cause,
            }),
        }
    }
    pub(crate) fn unknown_io(original: io::Error) -> Self {
        Self::new(CoreErrorCause::Io(original)).into_unknown_commit()
    }
    pub(crate) fn unknown_commit(original: CorePanic) -> Self {
        Self::panicked(original).into_unknown_commit()
    }
    pub(crate) fn panicked(original: CorePanic) -> Self {
        Self::new(CoreErrorCause::Panicked(original))
    }
    pub(crate) fn fences_owner(&self) -> bool {
        self.is_unknown_commit()
            || matches!(
                self.cause,
                CoreErrorCause::Io(_)
                    | CoreErrorCause::Corrupt(_)
                    | CoreErrorCause::OwnerFailed
                    | CoreErrorCause::Panicked(_)
            )
    }
}
impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_unknown_commit() {
            f.write_str("commit outcome unknown: ")?;
        }
        match &self.cause {
            CoreErrorCause::Io(original) => write!(f, "storage I/O: {original}"),
            CoreErrorCause::AllocationRefused(original) => {
                write!(f, "native allocation refused: {original}")
            }
            CoreErrorCause::Corrupt(reason) => write!(f, "corrupt committed storage: {reason}"),
            CoreErrorCause::CapacityDenied => f.write_str("storage capacity denied"),
            CoreErrorCause::OwnerFailed => f.write_str("storage owner failed"),
            CoreErrorCause::Closed => f.write_str("database closed"),
            CoreErrorCause::InvalidInput(reason) => write!(f, "invalid storage input: {reason}"),
            CoreErrorCause::MissingTable => f.write_str("table does not exist"),
            CoreErrorCause::Panicked(original) => original.fmt(f),
        }
    }
}
impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            CoreErrorCause::Io(original) | CoreErrorCause::AllocationRefused(original) => {
                Some(original)
            }
            CoreErrorCause::Panicked(original) => Some(original),
            _ => None,
        }
    }
}

/// Original unwind payload from a storage operation or opening. The payload
/// remains owned and inspectable without requiring it to implement `Sync`.
pub struct CorePanic {
    payload: std::cell::UnsafeCell<Box<dyn Any + Send>>,
    inspecting: AtomicBool,
}

// The original payload is Send but need not be Sync. Every borrowed access is
// serialized by the inline flag; no payload reference escapes with_payload.
unsafe impl Sync for CorePanic {}

struct PanicInspection<'a>(&'a AtomicBool);

impl Drop for PanicInspection<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl CorePanic {
    pub(crate) fn new(payload: Box<dyn Any + Send>) -> Self {
        Self {
            payload: std::cell::UnsafeCell::new(payload),
            inspecting: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    pub(crate) fn into_payload_for_test(self) -> Box<dyn Any + Send> {
        self.payload.into_inner()
    }

    pub fn with_payload<R>(&self, inspect: impl FnOnce(&(dyn Any + Send)) -> R) -> R {
        // Diagnostics must remain inspectable after admission or cleanup has
        // failed. The inline gate avoids a lazy platform Mutex allocation on
        // the first inspection. Yield while another synchronous inspection is
        // active; the guard also releases the gate if its callback unwinds.
        while self
            .inspecting
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::hint::spin_loop();
            std::thread::yield_now();
        }
        let _inspection = PanicInspection(&self.inspecting);
        // SAFETY: the acquired gate serializes every access to this payload.
        // The callback's output is independent of the borrowed input lifetime.
        inspect(unsafe { (&*self.payload.get()).as_ref() })
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

#[path = "core_opening.rs"]
pub(crate) mod opening;
pub use opening::{
    CoreOpenCleanup, CoreOpenFailure, NativeDisposalReport, NativeOpenFailure, NativeOwnedDisposal,
};
pub(crate) use opening::{NativeDisposal, OpeningCustody};

impl From<io::Error> for CoreError {
    fn from(error: io::Error) -> Self {
        Self::new(CoreErrorCause::Io(error))
    }
}
impl From<AdmissionError> for CoreError {
    fn from(error: AdmissionError) -> Self {
        match error {
            AdmissionError::CapacityDenied => Self::new(CoreErrorCause::CapacityDenied),
            AdmissionError::OwnerFailed => Self::new(CoreErrorCause::OwnerFailed),
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
    backend: crate::native_backend::BackendRef,
    disk: Option<DiskState>,
    close_entered: bool,
    close_report: Option<CoreCloseReport>,
    closed: bool,
    maintenance_active: bool,
    maintenance_position: Option<CommittedPosition>,
}
impl State {
    fn disk(&mut self) -> Result<&mut DiskState, CoreError> {
        self.disk
            .as_mut()
            .ok_or(CoreError::new(crate::CoreErrorCause::Closed))
    }
}
struct Shared {
    state: Option<Mutex<State>>,
    admission: std::mem::ManuallyDrop<Arc<dyn StorageAdmission>>,
    stopped: AtomicBool,
    fenced: AtomicBool,
    fence_panic: OnceLock<CorePanic>,
    snapshots: AtomicUsize,
    _authority: Option<crate::native_backend::BackendOwner>,
}
impl Drop for Shared {
    fn drop(&mut self) {
        // Explicit teardown takes every owned field first. An abandoned
        // authority keeps its original state and funding without replaying
        // close or pretending an unobserved destructor established drain.
        if let Some(state) = self.state.take() {
            std::mem::forget(state);
        }
        if let Some(authority) = self._authority.take() {
            std::mem::forget(authority);
        }
        if let Some(original) = self.fence_panic.take() {
            std::mem::forget(original);
        }
    }
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
        self.state
            .as_ref()
            .expect("live native state")
            .lock()
            .map_err(|_| {
                self.fence();
                CoreError::new(crate::CoreErrorCause::OwnerFailed)
            })
    }

    fn check_owner(&self) -> Result<(), CoreError> {
        if self.fenced.load(Ordering::Acquire) {
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        self.admission.check_owner().map_err(|_| {
            self.fence();
            CoreError::new(crate::CoreErrorCause::OwnerFailed)
        })
    }

    fn check_open(&self, state: &State) -> Result<(), CoreError> {
        if state.closed || self.stopped.load(Ordering::Acquire) {
            return Err(CoreError::new(crate::CoreErrorCause::Closed));
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
    shared: NativeOwnedArc<Shared>,
}

pub struct ReadSnapshot {
    shared: NativeOwnedArc<Shared>,
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
    pub(crate) lease: NativeResidentLease,
}
impl AdmittedValue {
    pub(crate) fn request_bytes(len: usize) -> Result<u64, CoreError> {
        let bytes = len
            .checked_add(std::mem::size_of::<Self>() + 192)
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        u64::try_from(bytes).map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn into_parts(self) -> (Vec<u8>, NativeResidentLease) {
        (self.bytes, self.lease)
    }
    pub(crate) fn allocate(
        admission: &Arc<dyn StorageAdmission>,
        len: usize,
    ) -> Result<Self, CoreError> {
        // Include the output handle, allocator allowance and retained lease.
        let lease = admission
            .reserve_workspace(Self::request_bytes(len)?)
            .map(NativeResidentLease::new)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        if bytes.capacity() != len {
            return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
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
    owner: NativeOwnedArc<Shared>,
    _charge: NativeResidentLease,
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
    #[cfg(test)]
    pub(crate) fn owner_allocation_addresses_for_test(&self) -> [usize; 7] {
        let state = self
            .shared
            .state
            .as_ref()
            .expect("live native state")
            .lock()
            .unwrap();
        let [root, root_grant, arena, arena_grant, roll] = state
            .disk
            .as_ref()
            .expect("live test native owner")
            .owner_allocation_addresses_for_test();
        [
            self.shared.as_ref() as *const Shared as usize,
            self.shared
                ._authority
                .as_ref()
                .expect("native authority")
                .grant()
                .allocation_address_for_test(),
            root,
            root_grant,
            arena,
            arena_grant,
            roll,
        ]
    }
    #[cfg(test)]
    pub(crate) fn backend_allocation_addresses_for_test(&self) -> [usize; 2] {
        self.shared
            ._authority
            .as_ref()
            .expect("native authority")
            .backing_addresses_for_test()
    }
    pub(crate) fn native_is_drained(&self) -> bool {
        self.shared
            .state
            .as_ref()
            .expect("live native state")
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .closed
    }
    /// One original native shell grant funds the sized backend body, its
    /// authoritative cell, Shared, and every database facade control.
    pub(crate) fn shell_request_bytes<B>() -> io::Result<u64> {
        let fixed = (std::mem::size_of::<Shared>()
            + 2 * std::mem::size_of::<usize>()
            + 64
            + 128
            + crate::native_sync::mutex_backing_bytes()
            + crate::tables::facade_heap_bytes()) as u64;
        fixed
            .checked_add(crate::native_backend::BackendOwner::allocation_request_bytes::<B>()?)
            .ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }
    pub(crate) fn shell_lease(&self) -> &NativeResidentLease {
        self.shared
            ._authority
            .as_ref()
            .expect("native authority")
            .grant()
    }
    #[allow(
        clippy::result_large_err,
        reason = "The failure owns the exact sized backend and cleanup without an error-path allocation."
    )]
    pub fn create_with_backend<B: SegmentGroupBackend + 'static>(
        backend: B,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        cache: CacheConfig,
    ) -> Result<Self, NativeOpenFailure<B>> {
        opening::assemble(backend, admission, group_id, cache, true, true, false)
            .map(|opened| opened.into_core())
    }
    #[allow(
        clippy::result_large_err,
        reason = "The failure owns the exact sized backend and cleanup without an error-path allocation."
    )]
    pub fn open_with_backend<B: SegmentGroupBackend + 'static>(
        backend: B,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        cache: CacheConfig,
    ) -> Result<Self, NativeOpenFailure<B>> {
        opening::assemble(backend, admission, group_id, cache, false, true, false)
            .map(|opened| opened.into_core())
    }
    pub fn snapshot(&self) -> Result<ReadSnapshot, CoreError> {
        if self.shared.stopped.load(Ordering::Acquire) {
            return Err(CoreError::new(crate::CoreErrorCause::Closed));
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
    pub(crate) fn reserve_workspace(&self, bytes: u64) -> Result<NativeResidentLease, CoreError> {
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            self.shared
                .admission
                .reserve_workspace(bytes)
                .map(NativeResidentLease::new)
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
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "cache warm-up step must be nonzero",
            )));
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
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "cache warm-up step must be nonzero",
            )));
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
        if !NativeOwnedArc::ptr_eq(&self.shared, &snapshot.shared) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot belongs to another database owner",
            )));
        }
        Ok(())
    }
    pub fn prepare_point_read(
        &self,
        max_value_bytes: usize,
    ) -> Result<PreparedPointRead, CoreError> {
        if max_value_bytes > MAX_VALUE_BYTES {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "prepared point bound exceeds native value limit",
            )));
        }
        self.shared.run(CoreError::panicked, |state| {
            self.shared.check_open(state)?;
            let charge = self
                .shared
                .admission
                .reserve_workspace(PreparedPointRead::shell_request_bytes())
                .map(NativeResidentLease::new)?;
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
        if !NativeOwnedArc::ptr_eq(&self.shared, &workspace.owner) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "prepared point owner differs",
            )));
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
        if !NativeOwnedArc::ptr_eq(&self.shared, &workspace.owner) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "prepared point owner differs",
            )));
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
        if !NativeOwnedArc::ptr_eq(&self.shared, &workspace.owner)
            || max_value_bytes > workspace.capacity()
        {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "prepared point owner or bound differs",
            )));
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
        let mut state = match self
            .shared
            .state
            .as_ref()
            .expect("live native state")
            .try_lock()
        {
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
                // Keep the original disk owner until explicit observed disposal.
            }
        }
        outcome
    }

    pub fn admission(&self) -> Arc<dyn StorageAdmission> {
        Arc::clone(&self.shared.admission)
    }
}
#[cfg(test)]
#[path = "core_tests.rs"]
mod tests;

#[path = "core_source_read.rs"]
mod source_read;
pub(crate) use source_read::SourceReadContext;
