//! Append-only transactional storage with two checksummed commit headers.
//!
//! A commit writes and synchronizes its complete frame before publishing its
//! alternate header. A failed I/O operation fences the instance; reopening
//! chooses the newest intact header and validates every committed frame. Values
//! remain on the backend. The resident ordered index contains keys and value
//! offsets only, and every index node is admitted before allocation.

use std::any::Any;
#[cfg(test)]
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
#[cfg(test)]
use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, TryLockError};

// The public tenant API caps plaintext at 32 MiB. This physical limit leaves
// room for authenticated envelopes and metadata around that plaintext.
pub const MAX_VALUE_BYTES: usize = 40 << 20;
// Store plaintext batches are capped at 64 MiB. The persisted envelope also
// contains encrypted record headers, table names, keys, and operation framing.
pub const MAX_BATCH_BYTES: usize = 96 << 20;
pub const MAX_KEY_BYTES: usize = 4096;
pub const MAX_TABLE_BYTES: usize = 1024;
const MAX_OPERATIONS: usize = 65_536;
const HEADER_BYTES: usize = 4096;
const LOG_START: u64 = (HEADER_BYTES * 2) as u64;
const HEADER_MAGIC: [u8; 16] = *b"KASUMI-KV-000001";
const FRAME_MAGIC: [u8; 8] = *b"KASUMITX";
const FRAME_BYTES: usize = 40;
const OP_BYTES: usize = 13;
const FORMAT_VERSION: u32 = 2;
const INDEX_ENTRY_CHARGE: u64 = 256;
const TABLE_CHARGE: u64 = 512;
const INDEX_POOL_CHUNK: u64 = 64 << 10;
const COMPACTION_CHECK_BYTES: u64 = 1 << 20;
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

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

/// Exact-offset backing. Implementations must never return short successful
/// reads or writes, and `sync_data` must include prior length and data writes.
/// `set_len` must preserve every byte below the requested length even when it
/// returns an error; the final compaction truncate relies on that prefix.
pub trait StorageBackend: Send + Sync {
    fn len(&self) -> io::Result<u64>;
    fn is_empty(&self) -> io::Result<bool> {
        self.len().map(|length| length == 0)
    }
    fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()>;
    fn write(&self, at: u64, bytes: &[u8]) -> io::Result<()>;
    fn set_len(&self, length: u64) -> io::Result<()>;
    fn sync_data(&self) -> io::Result<()>;
    fn close(&self) -> BackendCloseOutcome;
}
impl<T: StorageBackend + ?Sized> StorageBackend for Box<T> {
    fn len(&self) -> io::Result<u64> {
        (**self).len()
    }
    fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        (**self).read(at, out)
    }
    fn write(&self, at: u64, bytes: &[u8]) -> io::Result<()> {
        (**self).write(at, bytes)
    }
    fn set_len(&self, length: u64) -> io::Result<()> {
        (**self).set_len(length)
    }
    fn sync_data(&self) -> io::Result<()> {
        (**self).sync_data()
    }
    fn close(&self) -> BackendCloseOutcome {
        (**self).close()
    }
}
impl<T: StorageBackend + ?Sized> StorageBackend for Arc<T> {
    fn len(&self) -> io::Result<u64> {
        (**self).len()
    }
    fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        (**self).read(at, out)
    }
    fn write(&self, at: u64, bytes: &[u8]) -> io::Result<()> {
        (**self).write(at, bytes)
    }
    fn set_len(&self, length: u64) -> io::Result<()> {
        (**self).set_len(length)
    }
    fn sync_data(&self) -> io::Result<()> {
        (**self).sync_data()
    }
    fn close(&self) -> BackendCloseOutcome {
        (**self).close()
    }
}

/// Admission leases are held by their actual table/key/version owner.
pub trait ResidentLease: Send + Sync {}
impl<T: Send + Sync> ResidentLease for T {}

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

pub trait StorageAdmission: Send + Sync {
    fn check_owner(&self) -> Result<(), OwnerFailed>;
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError>;
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

/// Original unwind payload from a direct storage opening. The payload remains
/// owned and inspectable without requiring it to implement `Sync`.
pub struct CorePanic(Mutex<Box<dyn Any + Send>>);

impl CorePanic {
    fn new(payload: Box<dyn Any + Send>) -> Self {
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
        f.write_str("storage opening panicked; original payload retained")
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

enum FailedOpenOwner {
    Backend(Box<dyn StorageBackend>),
    Installed(Core),
}

impl FailedOpenOwner {
    fn close(&self) -> BackendCloseOutcome {
        match self {
            Self::Backend(backend) => backend.close(),
            Self::Installed(core) => core.close(),
        }
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

/// A simple file-backed implementation for standalone use. Production callers
/// can supply their already-owned envelope backend instead.
pub struct FileBackend {
    state: Mutex<FileBackendState>,
}

/// The exact native file previously owned by a named backend. Record this
/// while the original descriptor is live and supply it on every reopen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamedFileIdentity {
    device: u64,
    inode: u64,
}

impl NamedFileIdentity {
    pub fn from_file(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

enum FileBackendState {
    Open {
        file: File,
        parent: Option<File>,
        parent_sync_pending: bool,
    },
    ParentOnly(File),
    Drained(Option<io::Error>),
    UnknownClose {
        // Consumed numbers are diagnostic only. Never rebuild a File or retry them.
        _data_descriptor: Option<i32>,
        _parent_descriptor: Option<i32>,
        original_error: io::Error,
        _other_close_error: Option<io::Error>,
        _prior_sync_error: Option<io::Error>,
    },
}

/// A named-file acquisition failure keeps its already-open parent directory
/// until the caller observes an explicit one-shot close outcome.
#[must_use]
pub struct FileBackendOpenError {
    original_error: io::Error,
    owner: Option<FileBackend>,
    close_report: Option<BackendCloseOutcome>,
}

impl FileBackendOpenError {
    fn without_owner(original_error: io::Error) -> Self {
        Self {
            original_error,
            owner: None,
            close_report: None,
        }
    }

    fn with_parent(original_error: io::Error, parent: File) -> Self {
        let mut failure = Self {
            original_error,
            owner: Some(FileBackend {
                state: Mutex::new(FileBackendState::ParentOnly(parent)),
            }),
            close_report: None,
        };
        failure.retry_close();
        failure
    }

    fn with_open(original_error: io::Error, file: File, parent: File) -> Self {
        let mut failure = Self {
            original_error,
            owner: Some(FileBackend {
                state: Mutex::new(FileBackendState::Open {
                    file,
                    parent: Some(parent),
                    parent_sync_pending: false,
                }),
            }),
            close_report: None,
        };
        failure.retry_close();
        failure
    }

    pub fn original_error(&self) -> &io::Error {
        &self.original_error
    }

    pub fn kind(&self) -> io::ErrorKind {
        self.original_error.kind()
    }

    pub fn raw_os_error(&self) -> Option<i32> {
        self.original_error.raw_os_error()
    }

    pub fn close_report(&self) -> Option<&BackendCloseOutcome> {
        self.close_report.as_ref()
    }

    pub fn retry_close(&mut self) -> Option<&BackendCloseOutcome> {
        if self
            .close_report
            .as_ref()
            .is_none_or(|report| report.entry() == BackendCloseEntry::NotEntered)
            && let Some(owner) = self.owner.as_ref()
        {
            let outcome = owner.close();
            if outcome.native_disposition() == BackendNativeDisposition::Drained {
                self.owner.take();
            }
            self.close_report = Some(outcome);
        }
        self.close_report.as_ref()
    }
}

impl fmt::Debug for FileBackendOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileBackendOpenError")
            .field("original_error", &self.original_error)
            .field("opened_resources_retained", &self.owner.is_some())
            .field("close_report", &self.close_report)
            .finish()
    }
}

impl fmt::Display for FileBackendOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.original_error.fmt(f)
    }
}

impl std::error::Error for FileBackendOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original_error)
    }
}

impl Drop for FileBackendOpenError {
    fn drop(&mut self) {
        // Never let an unreported parent descriptor close implicitly.
        if let Some(owner) = self.owner.take() {
            std::mem::forget(owner);
        }
    }
}

fn project_file_error(error: &io::Error) -> io::Error {
    error
        .raw_os_error()
        .map_or_else(|| error.kind().into(), io::Error::from_raw_os_error)
}

#[cfg(test)]
std::thread_local! {
    static FILE_CLOSE_FAILURE: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    static FILE_SYNC_FAILURE: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    static FILE_CLOSE_ATTEMPTS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static FILE_PARENT_SYNC_FAILURE: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    static FILE_PARENT_SYNC_ATTEMPTS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static FILE_PARENT_CLOSE_FAILURE: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    static FILE_PARENT_CLOSE_ATTEMPTS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static FILE_AFTER_PREDATA_SYNC: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn open_in_parent(parent: &File, path: &Path, create: bool) -> io::Result<File> {
    let name = path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?;
    let mut flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    if create {
        flags |= libc::O_CREAT | libc::O_EXCL;
    }
    // SAFETY: name is NUL terminated and parent remains open for the call.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor owned solely by this File.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn sync_parent(parent: &File) -> io::Result<()> {
    #[cfg(test)]
    {
        FILE_PARENT_SYNC_ATTEMPTS.with(|count| count.set(count.get() + 1));
        if let Some(errno) = FILE_PARENT_SYNC_FAILURE.with(std::cell::Cell::take) {
            return Err(io::Error::from_raw_os_error(errno));
        }
    }
    parent.sync_all()
}

fn sync_file_and_parent(
    file: &File,
    parent: Option<&File>,
    parent_sync_pending: &mut bool,
) -> io::Result<()> {
    file.sync_data()?;
    if *parent_sync_pending {
        let parent = parent.expect("pending named file has a parent descriptor");
        sync_parent(parent)?;
        *parent_sync_pending = false;
    }
    Ok(())
}

fn close_file_descriptor(file: File, parent: bool) -> (i32, Option<io::Error>) {
    let descriptor = file.into_raw_fd();
    // SAFETY: into_raw_fd consumed the sole File owner. Never reconstruct it.
    let result = unsafe { libc::close(descriptor) };
    let error = (result != 0).then(io::Error::last_os_error);
    #[cfg(test)]
    let error = if parent {
        FILE_PARENT_CLOSE_ATTEMPTS.with(|count| count.set(count.get() + 1));
        error.or_else(|| {
            FILE_PARENT_CLOSE_FAILURE
                .with(std::cell::Cell::take)
                .map(io::Error::from_raw_os_error)
        })
    } else {
        FILE_CLOSE_ATTEMPTS.with(|count| count.set(count.get() + 1));
        error.or_else(|| {
            FILE_CLOSE_FAILURE
                .with(std::cell::Cell::take)
                .map(io::Error::from_raw_os_error)
        })
    };
    #[cfg(not(test))]
    let _ = parent;
    (descriptor, error)
}

impl FileBackend {
    pub fn from_file(file: File) -> Self {
        Self {
            state: Mutex::new(FileBackendState::Open {
                file,
                parent: None,
                parent_sync_pending: false,
            }),
        }
    }
    pub fn identity(&self) -> io::Result<NamedFileIdentity> {
        self.with(|file, _, _| NamedFileIdentity::from_file(file))
    }
    pub fn create_new(path: impl AsRef<Path>) -> Result<Self, FileBackendOpenError> {
        let path = path.as_ref();
        let parent =
            File::open(parent_directory(path)).map_err(FileBackendOpenError::without_owner)?;
        // Resolve parent durability before acquiring the data descriptor. The
        // same held directory is synced again after a newly created file's
        // first durable header, then closed with an observed native result.
        if let Err(error) = sync_parent(&parent) {
            return Err(FileBackendOpenError::with_parent(error, parent));
        }
        #[cfg(test)]
        FILE_AFTER_PREDATA_SYNC.with(|slot| {
            let action = slot.borrow_mut().take();
            if let Some(action) = action {
                action();
            }
        });
        // A new named owner must not adopt a file inserted while the parent
        // was being synchronized. The caller must resolve EEXIST against its
        // separately retained, exact existing-file identity.
        let file = match open_in_parent(&parent, path, true) {
            Ok(file) => file,
            Err(error) => return Err(FileBackendOpenError::with_parent(error, parent)),
        };
        Ok(Self {
            state: Mutex::new(FileBackendState::Open {
                file,
                parent: Some(parent),
                parent_sync_pending: true,
            }),
        })
    }
    pub fn open_existing(
        path: impl AsRef<Path>,
        expected: NamedFileIdentity,
    ) -> Result<Self, FileBackendOpenError> {
        let path = path.as_ref();
        let parent =
            File::open(parent_directory(path)).map_err(FileBackendOpenError::without_owner)?;
        // A prior create may have failed after writing valid headers but before
        // syncing the name. Reopening cannot turn that uncertainty into success.
        if let Err(error) = sync_parent(&parent) {
            return Err(FileBackendOpenError::with_parent(error, parent));
        }
        Self::open_existing_with_parent(path, expected, parent)
    }
    fn open_existing_with_parent(
        path: &Path,
        expected: NamedFileIdentity,
        parent: File,
    ) -> Result<Self, FileBackendOpenError> {
        let file = match open_in_parent(&parent, path, false) {
            Ok(file) => file,
            Err(error) => return Err(FileBackendOpenError::with_parent(error, parent)),
        };
        match NamedFileIdentity::from_file(&file) {
            Ok(observed) if observed == expected => {}
            Ok(_) => {
                return Err(FileBackendOpenError::with_open(
                    io::ErrorKind::InvalidData.into(),
                    file,
                    parent,
                ));
            }
            Err(error) => return Err(FileBackendOpenError::with_open(error, file, parent)),
        }
        Ok(Self {
            state: Mutex::new(FileBackendState::Open {
                file,
                parent: Some(parent),
                parent_sync_pending: false,
            }),
        })
    }
    fn with<T>(
        &self,
        work: impl FnOnce(&mut File, Option<&File>, &mut bool) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut guard = self.state.lock().map_err(|_| io::ErrorKind::Other)?;
        match &mut *guard {
            FileBackendState::Open {
                file,
                parent,
                parent_sync_pending,
            } => work(file, parent.as_ref(), parent_sync_pending),
            FileBackendState::ParentOnly(_)
            | FileBackendState::Drained(_)
            | FileBackendState::UnknownClose { .. } => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
}
impl StorageBackend for FileBackend {
    fn len(&self) -> io::Result<u64> {
        self.with(|file, _, _| Ok(file.metadata()?.len()))
    }
    fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.with(|file, _, _| {
            file.seek(SeekFrom::Start(at))?;
            file.read_exact(out)
        })
    }
    fn write(&self, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.with(|file, _, _| {
            file.seek(SeekFrom::Start(at))?;
            file.write_all(bytes)
        })
    }
    fn set_len(&self, length: u64) -> io::Result<()> {
        self.with(|file, _, _| file.set_len(length))
    }
    fn sync_data(&self) -> io::Result<()> {
        self.with(|file, parent, pending| sync_file_and_parent(file, parent, pending))
    }
    fn close(&self) -> BackendCloseOutcome {
        let mut guard = match self.state.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                return BackendCloseOutcome::not_entered(io::ErrorKind::WouldBlock.into());
            }
            Err(TryLockError::Poisoned(_)) => {
                return BackendCloseOutcome::retained(io::ErrorKind::Other.into());
            }
        };
        match &*guard {
            FileBackendState::Drained(sync_error) => {
                let result = sync_error
                    .as_ref()
                    .map_or(Ok(()), |error| Err(project_file_error(error)));
                return BackendCloseOutcome::drained(result);
            }
            FileBackendState::UnknownClose { original_error, .. } => {
                return BackendCloseOutcome::retained(project_file_error(original_error));
            }
            FileBackendState::Open { .. } | FileBackendState::ParentOnly(_) => {}
        }
        let previous = std::mem::replace(&mut *guard, FileBackendState::Drained(None));
        let (file, parent, mut parent_sync_pending) = match previous {
            FileBackendState::Open {
                file,
                parent,
                parent_sync_pending,
            } => (Some(file), parent, parent_sync_pending),
            FileBackendState::ParentOnly(parent) => (None, Some(parent), false),
            _ => unreachable!("the open arm was checked under the mutex"),
        };
        let sync_error = file.as_ref().and_then(|file| {
            sync_file_and_parent(file, parent.as_ref(), &mut parent_sync_pending).err()
        });
        #[cfg(test)]
        let sync_error = {
            let injected = FILE_SYNC_FAILURE.with(std::cell::Cell::take);
            sync_error.or_else(|| injected.map(io::Error::from_raw_os_error))
        };
        let (data_descriptor, data_error) = file
            .map(|file| close_file_descriptor(file, false))
            .map_or((None, None), |(descriptor, error)| {
                (Some(descriptor), error)
            });
        let (parent_descriptor, parent_error) = parent
            .map(|parent| close_file_descriptor(parent, true))
            .map_or((None, None), |(descriptor, error)| {
                (Some(descriptor), error)
            });
        let (original_close_error, other_close_error) = match (data_error, parent_error) {
            (Some(data), parent) => (Some(data), parent),
            (None, parent) => (parent, None),
        };
        if let Some(original_error) = original_close_error {
            let returned = project_file_error(&original_error);
            *guard = FileBackendState::UnknownClose {
                _data_descriptor: data_descriptor,
                _parent_descriptor: parent_descriptor,
                original_error,
                _other_close_error: other_close_error,
                _prior_sync_error: sync_error,
            };
            BackendCloseOutcome::retained(returned)
        } else {
            let result = sync_error
                .as_ref()
                .map_or(Ok(()), |error| Err(project_file_error(error)));
            *guard = FileBackendState::Drained(sync_error);
            BackendCloseOutcome::drained(result)
        }
    }
}

/// An exact-offset volatile backend used by component tests and embeddings.
#[derive(Debug)]
pub struct InMemoryBackend {
    bytes: Mutex<Option<Vec<u8>>>,
}
impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}
impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            bytes: Mutex::new(Some(Vec::new())),
        }
    }
    fn with<T>(&self, work: impl FnOnce(&mut Vec<u8>) -> io::Result<T>) -> io::Result<T> {
        let mut guard = self.bytes.lock().map_err(|_| io::ErrorKind::Other)?;
        work(guard.as_mut().ok_or(io::ErrorKind::BrokenPipe)?)
    }
}
impl StorageBackend for InMemoryBackend {
    fn len(&self) -> io::Result<u64> {
        self.with(|bytes| Ok(bytes.len() as u64))
    }
    fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.with(|bytes| {
            let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
            let end = start
                .checked_add(out.len())
                .ok_or(io::ErrorKind::InvalidInput)?;
            let source = bytes.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?;
            out.copy_from_slice(source);
            Ok(())
        })
    }
    fn write(&self, at: u64, input: &[u8]) -> io::Result<()> {
        self.with(|bytes| {
            let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
            let end = start
                .checked_add(input.len())
                .ok_or(io::ErrorKind::InvalidInput)?;
            let target = bytes
                .get_mut(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            target.copy_from_slice(input);
            Ok(())
        })
    }
    fn set_len(&self, length: u64) -> io::Result<()> {
        self.with(|bytes| {
            let length = usize::try_from(length).map_err(|_| io::ErrorKind::InvalidInput)?;
            if length > bytes.len() {
                bytes
                    .try_reserve_exact(length - bytes.len())
                    .map_err(|_| io::ErrorKind::OutOfMemory)?;
            }
            bytes.resize(length, 0);
            Ok(())
        })
    }
    fn sync_data(&self) -> io::Result<()> {
        self.with(|_| Ok(()))
    }
    fn close(&self) -> BackendCloseOutcome {
        let mut guard = match self.bytes.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                return BackendCloseOutcome::not_entered(io::ErrorKind::WouldBlock.into());
            }
            Err(TryLockError::Poisoned(_)) => {
                return BackendCloseOutcome::retained(io::ErrorKind::Other.into());
            }
        };
        guard.take();
        BackendCloseOutcome::drained(Ok(()))
    }
}

#[derive(Clone, Debug)]
pub enum Operation {
    CreateTable {
        table: String,
    },
    Put {
        table: String,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        table: String,
        key: Vec<u8>,
    },
}
impl Operation {
    pub fn create_table(table: impl Into<String>) -> Self {
        Self::CreateTable {
            table: table.into(),
        }
    }
    pub fn put(
        table: impl Into<String>,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Self {
        Self::Put {
            table: table.into(),
            key: key.into(),
            value: value.into(),
        }
    }
    pub fn delete(table: impl Into<String>, key: impl Into<Vec<u8>>) -> Self {
        Self::Delete {
            table: table.into(),
            key: key.into(),
        }
    }
    fn table(&self) -> &str {
        match self {
            Self::CreateTable { table } | Self::Put { table, .. } | Self::Delete { table, .. } => {
                table
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ValueRef {
    at: u64,
    len: u32,
    crc: u32,
}
struct VersionNode {
    generation: u64,
    value: Option<ValueRef>,
    previous: Option<Box<VersionNode>>,
    _lease: Box<dyn ResidentLease>,
}
struct Entry {
    head: Option<Box<VersionNode>>,
    _lease: Box<dyn ResidentLease>,
}
struct Table {
    birth_generation: u64,
    rows: BTreeMap<Vec<u8>, Entry>,
    _lease: Box<dyn ResidentLease>,
}
struct Index {
    tables: BTreeMap<String, Table>,
}
impl Index {
    fn new() -> Self {
        Self {
            tables: BTreeMap::new(),
        }
    }
}

struct State {
    backend: Box<dyn StorageBackend>,
    index: Index,
    generation: u64,
    base: u64,
    first_generation: u64,
    committed_end: u64,
    compaction_check_end: u64,
    slot: usize,
    fenced: bool,
    close_entered: bool,
    close_report: Option<CoreCloseReport>,
    closed: bool,
    needs_gc: bool,
}
struct Shared {
    state: Mutex<State>,
    admission: Arc<dyn StorageAdmission>,
    index_pool: Arc<IndexChargePool>,
    stopped: AtomicBool,
    snapshots: AtomicUsize,
    owner_id: u64,
}
impl Shared {
    fn check_read_owner(&self, state: &State) -> Result<(), CoreError> {
        if state.closed || self.stopped.load(Ordering::Acquire) {
            return Err(CoreError::Closed);
        }
        if state.fenced {
            return Err(CoreError::OwnerFailed);
        }
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)
    }
}
pub struct Core {
    shared: Arc<Shared>,
}

pub struct ReadSnapshot {
    shared: Arc<Shared>,
    generation: u64,
}

/// Owned backend bytes with the exact output allocation kept admitted until
/// the last consumer drops them.
pub struct AdmittedValue {
    bytes: Vec<u8>,
    lease: Box<dyn ResidentLease>,
}
impl AdmittedValue {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn into_parts(self) -> (Vec<u8>, Box<dyn ResidentLease>) {
        (self.bytes, self.lease)
    }
}
impl Clone for ReadSnapshot {
    fn clone(&self) -> Self {
        self.shared.snapshots.fetch_add(1, Ordering::AcqRel);
        Self {
            shared: self.shared.clone(),
            generation: self.generation,
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
        self.generation
    }
    pub fn table_exists(&self, table: &str) -> Result<bool, CoreError> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| CoreError::OwnerFailed)?;
        self.shared.check_read_owner(&state)?;
        Ok(state
            .index
            .tables
            .get(table)
            .is_some_and(|table| table.birth_generation <= self.generation))
    }
    #[cfg(test)]
    fn next_key(
        &self,
        table: &str,
        start: &[u8],
        after: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| CoreError::OwnerFailed)?;
        self.shared.check_read_owner(&state)?;
        let Some(table) = state.index.tables.get(table) else {
            return Ok(None);
        };
        if table.birth_generation > self.generation {
            return Ok(None);
        }
        let rows = &table.rows;
        let lower = match after {
            Some(after) if after >= start => Excluded(after),
            _ => Included(start),
        };
        Ok(rows
            .range::<[u8], _>((lower, Unbounded))
            .find_map(|(key, entry)| {
                visible(&entry.head, self.generation)
                    .flatten()
                    .map(|_| key.clone())
            }))
    }
    pub fn next_key_admitted(
        &self,
        table: &str,
        start: &[u8],
        after: Option<&[u8]>,
    ) -> Result<Option<AdmittedValue>, CoreError> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| CoreError::OwnerFailed)?;
        self.shared.check_read_owner(&state)?;
        let table = state
            .index
            .tables
            .get(table)
            .ok_or(CoreError::MissingTable)?;
        if table.birth_generation > self.generation {
            return Err(CoreError::MissingTable);
        }
        let lower = match after {
            Some(after) if after >= start => Excluded(after),
            _ => Included(start),
        };
        let key = table
            .rows
            .range::<[u8], _>((lower, Unbounded))
            .find_map(|(key, entry)| visible(&entry.head, self.generation).flatten().map(|_| key));
        match key {
            None => Ok(None),
            Some(key) => {
                let lease = reserve(&self.shared.admission, key.len() as u64)?;
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(key.len())
                    .map_err(|_| CoreError::CapacityDenied)?;
                bytes.extend_from_slice(key);
                Ok(Some(AdmittedValue { bytes, lease }))
            }
        }
    }
}

fn visible(head: &Option<Box<VersionNode>>, generation: u64) -> Option<Option<ValueRef>> {
    let mut node = head.as_deref();
    while let Some(version) = node {
        if version.generation <= generation {
            return Some(version.value);
        }
        node = version.previous.as_deref();
    }
    None
}

fn reserve(
    admission: &Arc<dyn StorageAdmission>,
    bytes: u64,
) -> Result<Box<dyn ResidentLease>, CoreError> {
    admission.reserve_workspace(bytes).map_err(Into::into)
}

/// Resident index nodes consume exact logical credit from admitted chunks.
/// This avoids one physical-owner reservation per key while keeping every
/// node's charge live until that node is actually dropped.
struct IndexChargePool {
    admission: Arc<dyn StorageAdmission>,
    state: Mutex<IndexPoolState>,
}
struct IndexPoolState {
    used: u64,
    reserved: u64,
    leases: Vec<(u64, Box<dyn ResidentLease>)>,
}
struct IndexNodeCharge {
    pool: Arc<IndexChargePool>,
    bytes: u64,
}
impl IndexChargePool {
    fn new(admission: Arc<dyn StorageAdmission>) -> Arc<Self> {
        Arc::new(Self {
            admission,
            state: Mutex::new(IndexPoolState {
                used: 0,
                reserved: 0,
                leases: Vec::new(),
            }),
        })
    }
    fn claim(self: &Arc<Self>, bytes: u64) -> Result<Box<dyn ResidentLease>, CoreError> {
        let mut state = self.state.lock().map_err(|_| CoreError::OwnerFailed)?;
        let next_used = state
            .used
            .checked_add(bytes)
            .ok_or(CoreError::CapacityDenied)?;
        if next_used > state.reserved {
            let deficit = next_used - state.reserved;
            let desired = deficit.max(INDEX_POOL_CHUNK);
            state
                .leases
                .try_reserve(1)
                .map_err(|_| CoreError::CapacityDenied)?;
            let (charge, lease) = match reserve(&self.admission, desired) {
                Ok(lease) => (desired, lease),
                Err(CoreError::CapacityDenied) if desired > deficit => {
                    (deficit, reserve(&self.admission, deficit)?)
                }
                Err(error) => return Err(error),
            };
            state.reserved = state
                .reserved
                .checked_add(charge)
                .ok_or(CoreError::CapacityDenied)?;
            state.leases.push((charge, lease));
        }
        state.used = next_used;
        Ok(Box::new(IndexNodeCharge {
            pool: self.clone(),
            bytes,
        }))
    }
}
impl Drop for IndexNodeCharge {
    fn drop(&mut self) {
        {
            let mut state = self.pool.state.lock().unwrap_or_else(|p| p.into_inner());
            debug_assert!(state.used >= self.bytes);
            state.used -= self.bytes;
        }
        loop {
            let retired = {
                let mut state = self.pool.state.lock().unwrap_or_else(|p| p.into_inner());
                let free = state.reserved - state.used;
                if state.leases.last().is_some_and(|(bytes, _)| *bytes <= free) {
                    let (bytes, lease) = state.leases.pop().expect("admitted index chunk");
                    state.reserved -= bytes;
                    Some(lease)
                } else {
                    None
                }
            };
            if retired.is_none() {
                break;
            }
            drop(retired);
        }
    }
}
fn entry_charge(key_len: usize) -> Result<u64, CoreError> {
    INDEX_ENTRY_CHARGE
        .checked_add(key_len as u64)
        .ok_or(CoreError::InvalidInput("index charge overflow"))
}
fn table_charge(name_len: usize) -> Result<u64, CoreError> {
    TABLE_CHARGE
        .checked_add(name_len as u64)
        .ok_or(CoreError::InvalidInput("table charge overflow"))
}

#[derive(Clone, Copy)]
struct CommitHeader {
    generation: u64,
    base: u64,
    first_generation: u64,
    end: u64,
    slot: usize,
}

fn put_u16(dst: &mut [u8], value: u16) {
    dst.copy_from_slice(&value.to_le_bytes());
}
fn put_u32(dst: &mut [u8], value: u32) {
    dst.copy_from_slice(&value.to_le_bytes());
}
fn put_u64(dst: &mut [u8], value: u64) {
    dst.copy_from_slice(&value.to_le_bytes());
}
fn get_u16(src: &[u8]) -> u16 {
    u16::from_le_bytes(src.try_into().expect("two bytes"))
}
fn get_u32(src: &[u8]) -> u32 {
    u32::from_le_bytes(src.try_into().expect("four bytes"))
}
fn get_u64(src: &[u8]) -> u64 {
    u64::from_le_bytes(src.try_into().expect("eight bytes"))
}

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut value = i as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 == 1 {
                (value >> 1) ^ 0x82f6_3b78
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[i] = value;
        i += 1;
    }
    table
}
const CRC_TABLE: [u32; 256] = crc_table();
struct Crc32c(u32);
impl Crc32c {
    fn new() -> Self {
        Self(!0)
    }
    fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = CRC_TABLE[((self.0 as u8) ^ byte) as usize] ^ (self.0 >> 8);
        }
    }
    fn finish(self) -> u32 {
        !self.0
    }
}
fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(bytes);
    crc.finish()
}

fn header_bytes(generation: u64, base: u64, first_generation: u64, end: u64) -> [u8; HEADER_BYTES] {
    let mut bytes = [0u8; HEADER_BYTES];
    bytes[..16].copy_from_slice(&HEADER_MAGIC);
    put_u32(&mut bytes[16..20], FORMAT_VERSION);
    put_u64(&mut bytes[24..32], generation);
    put_u64(&mut bytes[32..40], end);
    put_u64(&mut bytes[40..48], base);
    put_u64(&mut bytes[48..56], first_generation);
    let checksum = crc32c(&bytes[..HEADER_BYTES - 4]);
    put_u32(&mut bytes[HEADER_BYTES - 4..], checksum);
    bytes
}
fn decode_header(bytes: &[u8; HEADER_BYTES], slot: usize) -> Option<CommitHeader> {
    if bytes[..16] != HEADER_MAGIC
        || get_u32(&bytes[16..20]) != FORMAT_VERSION
        || bytes[20..24].iter().any(|&byte| byte != 0)
        || bytes[56..HEADER_BYTES - 4].iter().any(|&byte| byte != 0)
        || get_u32(&bytes[HEADER_BYTES - 4..]) != crc32c(&bytes[..HEADER_BYTES - 4])
    {
        return None;
    }
    let end = get_u64(&bytes[32..40]);
    let base = get_u64(&bytes[40..48]);
    let first_generation = get_u64(&bytes[48..56]);
    let generation = get_u64(&bytes[24..32]);
    if base < LOG_START
        || base > end
        || first_generation == 0
        || first_generation > generation.saturating_add(1)
        || (base == end && generation.saturating_add(1) != first_generation)
        || (base < end && first_generation > generation)
    {
        return None;
    }
    Some(CommitHeader {
        generation,
        base,
        first_generation,
        end,
        slot,
    })
}
fn read_header(
    backend: &dyn StorageBackend,
    slot: usize,
) -> Result<Option<CommitHeader>, CoreError> {
    let mut bytes = [0u8; HEADER_BYTES];
    backend.read((slot * HEADER_BYTES) as u64, &mut bytes)?;
    Ok(decode_header(&bytes, slot))
}
fn chosen_header(backend: &dyn StorageBackend, length: u64) -> Result<CommitHeader, CoreError> {
    if length < LOG_START {
        return Err(CoreError::Corrupt(
            "node payload is shorter than commit headers",
        ));
    }
    let left = read_header(backend, 0)?;
    let right = read_header(backend, 1)?;
    let chosen = match (left, right) {
        (Some(left), Some(right)) if left.generation == right.generation => {
            if left.end != right.end
                || left.base != right.base
                || left.first_generation != right.first_generation
            {
                return Err(CoreError::Corrupt(
                    "commit headers disagree at one generation",
                ));
            }
            left
        }
        (Some(left), Some(right)) => {
            if left.generation > right.generation {
                left
            } else {
                right
            }
        }
        (Some(header), None) | (None, Some(header)) => header,
        (None, None) => return Err(CoreError::Corrupt("no valid commit header")),
    };
    if chosen.end > length {
        return Err(CoreError::Corrupt("committed end exceeds backend length"));
    }
    if chosen.generation == 0 && (chosen.end != LOG_START || chosen.base != LOG_START) {
        return Err(CoreError::Corrupt("empty generation has a nonempty log"));
    }
    Ok(chosen)
}

fn validate_table_name(name: &str) -> Result<(), CoreError> {
    if name.is_empty() || name.len() > MAX_TABLE_BYTES {
        return Err(CoreError::InvalidInput("table name is empty or too long"));
    }
    Ok(())
}
fn validate_operations(
    index: &Index,
    operations: &[Operation],
    admission: &Arc<dyn StorageAdmission>,
) -> Result<u32, CoreError> {
    if operations.is_empty() || operations.len() > MAX_OPERATIONS {
        return Err(CoreError::InvalidInput("empty or oversized transaction"));
    }
    let creates = operations
        .iter()
        .filter(|operation| matches!(operation, Operation::CreateTable { .. }))
        .count();
    let _created_lease = if creates == 0 {
        None
    } else {
        Some(reserve(
            admission,
            (creates as u64)
                .checked_mul(128)
                .ok_or(CoreError::InvalidInput("table validation overflow"))?,
        )?)
    };
    let mut created = BTreeSet::new();
    let mut length = 0usize;
    for operation in operations {
        let table = operation.table();
        validate_table_name(table)?;
        let known = index.tables.contains_key(table) || created.contains(table);
        let (key_len, value_len) = match operation {
            Operation::CreateTable { .. } => (0, 0),
            Operation::Put { key, value, .. } => {
                if !known {
                    return Err(CoreError::MissingTable);
                }
                (key.len(), value.len())
            }
            Operation::Delete { key, .. } => {
                if !known {
                    return Err(CoreError::MissingTable);
                }
                (key.len(), 0)
            }
        };
        if key_len > MAX_KEY_BYTES || value_len > MAX_VALUE_BYTES {
            return Err(CoreError::InvalidInput(
                "key or value exceeds storage limit",
            ));
        }
        length = length
            .checked_add(OP_BYTES)
            .and_then(|n| n.checked_add(table.len()))
            .and_then(|n| n.checked_add(key_len))
            .and_then(|n| n.checked_add(value_len))
            .ok_or(CoreError::InvalidInput("transaction length overflow"))?;
        if length > MAX_BATCH_BYTES {
            return Err(CoreError::InvalidInput(
                "transaction exceeds 96 MiB physical limit",
            ));
        }
        if matches!(operation, Operation::CreateTable { .. }) {
            created.insert(table);
        }
    }
    u32::try_from(length).map_err(|_| CoreError::InvalidInput("transaction length overflow"))
}
fn op_header(operation: &Operation) -> [u8; OP_BYTES] {
    let mut bytes = [0u8; OP_BYTES];
    bytes[0] = match operation {
        Operation::CreateTable { .. } => 1,
        Operation::Put { .. } => 2,
        Operation::Delete { .. } => 3,
    };
    put_u16(&mut bytes[1..3], operation.table().len() as u16);
    match operation {
        Operation::Put { key, value, .. } => {
            put_u16(&mut bytes[3..5], key.len() as u16);
            put_u32(&mut bytes[5..9], value.len() as u32);
            put_u32(&mut bytes[9..13], crc32c(value));
        }
        Operation::Delete { key, .. } => {
            put_u16(&mut bytes[3..5], key.len() as u16);
        }
        Operation::CreateTable { .. } => {}
    }
    bytes
}
fn operation_parts(operation: &Operation) -> (&[u8], &[u8], &[u8]) {
    match operation {
        Operation::CreateTable { table } => (table.as_bytes(), &[], &[]),
        Operation::Put { table, key, value } => (table.as_bytes(), key, value),
        Operation::Delete { table, key } => (table.as_bytes(), key, &[]),
    }
}
fn payload_checksum(operations: &[Operation]) -> u32 {
    let mut checksum = Crc32c::new();
    for operation in operations {
        let header = op_header(operation);
        let (table, key, value) = operation_parts(operation);
        checksum.update(&header);
        checksum.update(table);
        checksum.update(key);
        checksum.update(value);
    }
    checksum.finish()
}
fn frame_header(
    generation: u64,
    previous_end: u64,
    payload_len: u32,
    count: u32,
    payload_crc: u32,
) -> [u8; FRAME_BYTES] {
    let mut bytes = [0u8; FRAME_BYTES];
    bytes[..8].copy_from_slice(&FRAME_MAGIC);
    put_u64(&mut bytes[8..16], generation);
    put_u64(&mut bytes[16..24], previous_end);
    put_u32(&mut bytes[24..28], payload_len);
    put_u32(&mut bytes[28..32], count);
    put_u32(&mut bytes[32..36], payload_crc);
    let checksum = crc32c(&bytes[..36]);
    put_u32(&mut bytes[36..40], checksum);
    bytes
}

impl Core {
    /// Create a new payload when empty, otherwise recover an existing one.
    /// This form supports crash-image backends whose reopen uses the same call.
    pub fn create_with_backend(
        backend: impl StorageBackend + 'static,
        admission: Arc<dyn StorageAdmission>,
    ) -> Result<Self, CoreError> {
        let backend: Box<dyn StorageBackend> = Box::new(backend);
        let length = match run_open(true, || backend.len().map_err(CoreError::from)) {
            Ok(length) => length,
            Err(error) => {
                return Err(failed_open(FailedOpenOwner::Backend(backend), error, true));
            }
        };
        if length == 0 {
            Self::create_strict_boxed(backend, admission, true)
        } else {
            Self::open_boxed(backend, admission, true)
        }
    }

    pub fn create_strict_with_backend(
        backend: impl StorageBackend + 'static,
        admission: Arc<dyn StorageAdmission>,
    ) -> Result<Self, CoreError> {
        Self::create_strict_boxed(Box::new(backend), admission, true)
    }

    pub(crate) fn create_strict_with_backend_retained(
        backend: impl StorageBackend + 'static,
        admission: Arc<dyn StorageAdmission>,
    ) -> Result<Self, CoreError> {
        Self::create_strict_boxed(Box::new(backend), admission, false)
    }

    fn create_strict_boxed(
        backend: Box<dyn StorageBackend>,
        admission: Arc<dyn StorageAdmission>,
        close_on_failure: bool,
    ) -> Result<Self, CoreError> {
        let result = run_open(close_on_failure, || -> Result<(), CoreError> {
            admission
                .check_owner()
                .map_err(|_| CoreError::OwnerFailed)?;
            if backend.len()? != 0 {
                return Err(CoreError::InvalidInput("new backend is not empty"));
            }
            admission.reserve_growth(0, LOG_START)?;
            backend.set_len(LOG_START)?;
            admission
                .settle_growth(LOG_START)
                .map_err(|_| CoreError::OwnerFailed)?;
            let header = header_bytes(0, LOG_START, 1, LOG_START);
            backend.write(0, &header)?;
            backend.write(HEADER_BYTES as u64, &header)?;
            backend.sync_data()?;
            Ok(())
        });
        if let Err(error) = result {
            return Err(failed_open(
                FailedOpenOwner::Backend(backend),
                error,
                close_on_failure,
            ));
        }
        let index_pool = IndexChargePool::new(admission.clone());
        Ok(Self::installed(
            backend,
            admission,
            index_pool,
            Index::new(),
            CommitHeader {
                generation: 0,
                base: LOG_START,
                first_generation: 1,
                end: LOG_START,
                slot: 0,
            },
        ))
    }

    /// Open only an existing payload. A valid newest header whose committed
    /// frame is corrupt is an error; recovery never falls back to older data.
    pub fn open_with_backend(
        backend: impl StorageBackend + 'static,
        admission: Arc<dyn StorageAdmission>,
    ) -> Result<Self, CoreError> {
        Self::open_boxed(Box::new(backend), admission, true)
    }

    pub(crate) fn open_with_backend_retained(
        backend: impl StorageBackend + 'static,
        admission: Arc<dyn StorageAdmission>,
    ) -> Result<Self, CoreError> {
        Self::open_boxed(Box::new(backend), admission, false)
    }

    fn open_boxed(
        backend: Box<dyn StorageBackend>,
        admission: Arc<dyn StorageAdmission>,
        close_on_failure: bool,
    ) -> Result<Self, CoreError> {
        let result = run_open(
            close_on_failure,
            || -> Result<(Index, Arc<IndexChargePool>, CommitHeader), CoreError> {
                admission
                    .check_owner()
                    .map_err(|_| CoreError::OwnerFailed)?;
                let length = backend.len()?;
                let header = chosen_header(&*backend, length)?;
                let mut index = Index::new();
                let index_pool = IndexChargePool::new(admission.clone());
                let mut cursor = header.base;
                let mut generation = header.first_generation - 1;
                while cursor < header.end {
                    let frame = read_frame(&*backend, cursor, header.end, generation)?;
                    scan_payload(&*backend, &frame)?;
                    replay_payload(&*backend, &frame, &mut index, &index_pool)?;
                    cursor = frame.end;
                    generation = frame.generation;
                }
                if cursor != header.end || generation != header.generation {
                    return Err(CoreError::Corrupt(
                        "commit chain does not reach selected header",
                    ));
                }
                // Bytes beyond the selected header belong to an uncommitted attempt.
                // Recovery validates every committed byte before reclaiming that tail.
                if length > header.end {
                    backend.set_len(header.end)?;
                }
                // Persist a fully validated page-cache generation before resolving
                // an uncertain same-host commit for the caller.
                backend.sync_data()?;
                if length > header.end {
                    admission
                        .settle_growth(header.end)
                        .map_err(|_| CoreError::OwnerFailed)?;
                }
                Ok((index, index_pool, header))
            },
        );
        let (index, index_pool, header) = match result {
            Ok(result) => result,
            Err(error) => {
                return Err(failed_open(
                    FailedOpenOwner::Backend(backend),
                    error,
                    close_on_failure,
                ));
            }
        };
        let core = Self::installed(backend, admission, index_pool, index, header);
        if header.base != LOG_START {
            // Recovery finishes a published shadow relocation before exposing
            // an instance that may accept another user commit.
            if let Err(error) = run_open(close_on_failure, || core.compact()) {
                return Err(failed_open(
                    FailedOpenOwner::Installed(core),
                    error,
                    close_on_failure,
                ));
            }
        }
        Ok(core)
    }

    fn installed(
        backend: Box<dyn StorageBackend>,
        admission: Arc<dyn StorageAdmission>,
        index_pool: Arc<IndexChargePool>,
        index: Index,
        header: CommitHeader,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    backend,
                    index,
                    generation: header.generation,
                    base: header.base,
                    first_generation: header.first_generation,
                    committed_end: header.end,
                    compaction_check_end: header.end,
                    slot: header.slot,
                    fenced: false,
                    close_entered: false,
                    close_report: None,
                    closed: false,
                    needs_gc: false,
                }),
                admission,
                index_pool,
                stopped: AtomicBool::new(false),
                snapshots: AtomicUsize::new(0),
                owner_id: NEXT_OWNER.fetch_add(1, Ordering::Relaxed),
            }),
        }
    }

    pub fn snapshot(&self) -> Result<ReadSnapshot, CoreError> {
        if self.shared.stopped.load(Ordering::Acquire) {
            return Err(CoreError::Closed);
        }
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| CoreError::OwnerFailed)?;
        self.shared.check_read_owner(&state)?;
        self.shared.snapshots.fetch_add(1, Ordering::AcqRel);
        Ok(ReadSnapshot {
            shared: self.shared.clone(),
            generation: state.generation,
        })
    }

    pub(crate) fn check_read_owner(&self) -> Result<(), CoreError> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| CoreError::OwnerFailed)?;
        self.shared.check_read_owner(&state)
    }

    pub fn generation(&self) -> Result<u64, CoreError> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| CoreError::OwnerFailed)?;
        self.shared.check_read_owner(&state)?;
        Ok(state.generation)
    }

    pub fn committed_end(&self) -> Result<u64, CoreError> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| CoreError::OwnerFailed)?;
        self.shared.check_read_owner(&state)?;
        Ok(state.committed_end)
    }

    /// Reclaim obsolete log records while preserving the selected committed
    /// header through every crash point. Active snapshots defer compaction.
    /// A front log first moves to a durable shadow log, then moves back to
    /// the front; reopening completes a published shadow relocation.
    pub fn compact(&self) -> Result<(), CoreError> {
        if self.shared.stopped.load(Ordering::Acquire) {
            return Err(CoreError::Closed);
        }
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| CoreError::OwnerFailed)?;
        if state.closed || state.fenced || self.shared.stopped.load(Ordering::Acquire) {
            return Err(CoreError::Closed);
        }
        self.shared
            .admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        self.compact_locked(&mut state)
    }

    /// Run bounded maintenance before a write transaction pins its read
    /// snapshot. The table facade invokes this while holding its writer gate.
    pub fn prepare_write(&self) -> Result<(), CoreError> {
        if self.shared.stopped.load(Ordering::Acquire) {
            return Err(CoreError::Closed);
        }
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| CoreError::OwnerFailed)?;
        if state.closed || state.fenced || self.shared.stopped.load(Ordering::Acquire) {
            return Err(CoreError::Closed);
        }
        self.shared
            .admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        self.maybe_compact_locked(&mut state)
    }

    fn maybe_compact_locked(&self, state: &mut State) -> Result<(), CoreError> {
        if state.base != LOG_START {
            self.compact_locked(state)?;
            if state.base != LOG_START {
                return Err(CoreError::Corrupt("shadow relocation did not finish"));
            }
        }
        if self.shared.snapshots.load(Ordering::Acquire) == 0
            && state
                .committed_end
                .saturating_sub(state.compaction_check_end)
                >= COMPACTION_CHECK_BYTES
        {
            state.compaction_check_end = state.committed_end;
            let layout = compact_layout(&state.index)?;
            let active_bytes = state.committed_end - state.base;
            if layout.frames != 0 && active_bytes >= layout.bytes.saturating_mul(2) {
                match self.compact_locked(state) {
                    Ok(()) | Err(CoreError::CapacityDenied) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    fn compact_locked(&self, state: &mut State) -> Result<(), CoreError> {
        self.compact_locked_with_lease(state, None)
    }

    fn compact_locked_with_lease(
        &self,
        state: &mut State,
        held_copy_lease: Option<&dyn ResidentLease>,
    ) -> Result<(), CoreError> {
        if self.shared.snapshots.load(Ordering::Acquire) != 0 {
            return Err(CoreError::InvalidInput(
                "active snapshots prevent compaction",
            ));
        }
        if state.needs_gc {
            prune_all(&mut state.index);
            state.needs_gc = false;
        }
        let layout = compact_layout(&state.index)?;
        if layout.frames == 0 {
            return Ok(());
        }
        let front = state.base == LOG_START;
        if front && layout.bytes >= state.committed_end - LOG_START {
            return Ok(());
        }
        let copies = if front { 2 } else { 1 };
        let generations = layout
            .frames
            .checked_mul(copies)
            .ok_or(CoreError::InvalidInput("generation overflow"))?;
        state
            .generation
            .checked_add(generations)
            .ok_or(CoreError::InvalidInput("generation overflow"))?;
        let own_copy_lease = if held_copy_lease.is_none() {
            Some(reserve(&self.shared.admission, 8192)?)
        } else {
            None
        };
        let copy_lease = held_copy_lease
            .or(own_copy_lease.as_deref())
            .expect("compaction workspace is admitted");
        let first_generation = state.generation + 1;
        let target = if front {
            state.committed_end.max(
                LOG_START
                    .checked_add(layout.bytes)
                    .ok_or(CoreError::InvalidInput("compaction length overflow"))?,
            )
        } else {
            LOG_START
        };
        let target_end = target
            .checked_add(layout.bytes)
            .ok_or(CoreError::InvalidInput("compaction length overflow"))?;
        if target_end > i64::MAX as u64 {
            return Err(CoreError::InvalidInput(
                "backend length exceeds platform bound",
            ));
        }
        if !front && target_end > state.base {
            return Err(CoreError::Corrupt("shadow relocation overlaps its source"));
        }
        let physical_len = state.backend.len().map_err(|error| {
            state.fenced = true;
            self.shared.admission.owner_failed();
            CoreError::Io(error)
        })?;
        if front {
            self.shared
                .admission
                .reserve_growth(physical_len, target_end)?;
        }
        let next_slot = 1 - state.slot;
        let result = (|| -> Result<u64, CoreError> {
            if front {
                state.backend.set_len(target_end)?;
            }
            let (written_end, generation) = write_compact_snapshot(state, target, layout)?;
            debug_assert_eq!(written_end, target_end);
            state.backend.sync_data()?;
            if front {
                self.shared
                    .admission
                    .settle_growth(target_end)
                    .map_err(|_| CoreError::OwnerFailed)?;
            }
            let header = header_bytes(generation, target, first_generation, target_end);
            state
                .backend
                .write((next_slot * HEADER_BYTES) as u64, &header)?;
            state.backend.sync_data()?;
            Ok(generation)
        })();
        let generation = match result {
            Ok(generation) => generation,
            Err(error) => {
                state.fenced = true;
                self.shared.admission.owner_failed();
                return Err(error);
            }
        };
        state.generation = generation;
        state.base = target;
        state.first_generation = first_generation;
        state.committed_end = target_end;
        state.slot = next_slot;
        if front {
            // The shadow header now protects every live value; the old front
            // extent can be overwritten. A crash before the next header sync
            // recovers from shadow and retries this exact phase.
            self.compact_locked_with_lease(state, Some(copy_lease))
        } else {
            // The new front header is durable before discarding the shadow.
            // A failed truncate leaves a valid front header for reopen.
            if let Err(error) = state
                .backend
                .set_len(target_end)
                .and_then(|()| state.backend.sync_data())
            {
                state.fenced = true;
                self.shared.admission.owner_failed();
                return Err(CoreError::Io(error));
            }
            if self.shared.admission.settle_growth(target_end).is_err() {
                state.fenced = true;
                self.shared.admission.owner_failed();
                return Err(CoreError::OwnerFailed);
            }
            state.compaction_check_end = target_end;
            Ok(())
        }
    }

    #[cfg(test)]
    fn get(
        &self,
        snapshot: &ReadSnapshot,
        table: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        self.get_admitted(snapshot, table, key, max_value_bytes)
            .map(|value| value.map(|value| value.into_parts().0))
    }

    pub fn get_admitted(
        &self,
        snapshot: &ReadSnapshot,
        table: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<AdmittedValue>, CoreError> {
        self.check_snapshot(snapshot)?;
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| CoreError::OwnerFailed)?;
        self.shared.check_read_owner(&state)?;
        let Some(table) = state.index.tables.get(table) else {
            return Err(CoreError::MissingTable);
        };
        if table.birth_generation > snapshot.generation {
            return Err(CoreError::MissingTable);
        }
        let reference = table
            .rows
            .get(key)
            .and_then(|entry| visible(&entry.head, snapshot.generation))
            .flatten();
        match reference {
            None => Ok(None),
            Some(reference) => self
                .read_value_admitted(&mut state, reference, max_value_bytes)
                .map(Some),
        }
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
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| CoreError::OwnerFailed)?;
        self.shared.check_read_owner(&state)?;
        let Some(table) = state.index.tables.get(table) else {
            return Err(CoreError::MissingTable);
        };
        if table.birth_generation > snapshot.generation {
            return Err(CoreError::MissingTable);
        }
        let lower = match after {
            Some(after) if after >= prefix => Excluded(after),
            _ => Included(prefix),
        };
        let mut found = None;
        for (key, entry) in table.rows.range::<[u8], _>((lower, Unbounded)) {
            if !key.starts_with(prefix) {
                break;
            }
            if let Some(reference) = visible(&entry.head, snapshot.generation).flatten() {
                let key_lease = reserve(&self.shared.admission, key.len() as u64)?;
                let mut key_bytes = Vec::new();
                key_bytes
                    .try_reserve_exact(key.len())
                    .map_err(|_| CoreError::CapacityDenied)?;
                key_bytes.extend_from_slice(key);
                found = Some((
                    AdmittedValue {
                        bytes: key_bytes,
                        lease: key_lease,
                    },
                    reference,
                ));
                break;
            }
        }
        match found {
            None => Ok(None),
            Some((key, reference)) => Ok(Some((
                key,
                self.read_value_admitted(&mut state, reference, max_value_bytes)?,
            ))),
        }
    }

    fn check_snapshot(&self, snapshot: &ReadSnapshot) -> Result<(), CoreError> {
        if self.shared.owner_id != snapshot.shared.owner_id
            || !Arc::ptr_eq(&self.shared, &snapshot.shared)
        {
            return Err(CoreError::InvalidInput(
                "snapshot belongs to another database",
            ));
        }
        Ok(())
    }

    fn read_value_admitted(
        &self,
        state: &mut State,
        reference: ValueRef,
        max_value_bytes: usize,
    ) -> Result<AdmittedValue, CoreError> {
        let len = reference.len as usize;
        if len > max_value_bytes {
            return Err(CoreError::InvalidInput("stored value exceeds read bound"));
        }
        self.shared
            .admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        let lease = reserve(&self.shared.admission, len as u64)?;
        let mut value = Vec::new();
        value
            .try_reserve_exact(len)
            .map_err(|_| CoreError::CapacityDenied)?;
        value.resize(len, 0);
        if let Err(error) = state.backend.read(reference.at, &mut value) {
            state.fenced = true;
            self.shared.admission.owner_failed();
            return Err(CoreError::Io(error));
        }
        if crc32c(&value) != reference.crc {
            state.fenced = true;
            self.shared.admission.owner_failed();
            return Err(CoreError::Corrupt("committed value checksum differs"));
        }
        Ok(AdmittedValue {
            bytes: value,
            lease,
        })
    }

    /// Commit a complete batch. A capacity denial before the first backend
    /// effect rolls back provisional index versions. Any I/O failure fences the
    /// instance so the caller must reopen to learn the durable outcome.
    pub fn commit(&self, operations: &[Operation]) -> Result<(), CoreError> {
        if self.shared.stopped.load(Ordering::Acquire) {
            return Err(CoreError::Closed);
        }
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| CoreError::OwnerFailed)?;
        if state.closed || state.fenced || self.shared.stopped.load(Ordering::Acquire) {
            return Err(CoreError::Closed);
        }
        self.shared
            .admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        let payload_len = validate_operations(&state.index, operations, &self.shared.admission)?;
        // A published shadow must return to the front before any user append.
        // If this pre-effect relocation is denied, the shadow remains intact
        // and this commit has made no backend change.
        // Direct Core callers may commit without using the table facade.
        // Facade callers already ran this before pinning their snapshot.
        self.maybe_compact_locked(&mut state)?;
        let next_generation = state
            .generation
            .checked_add(1)
            .ok_or(CoreError::InvalidInput("generation overflow"))?;
        let frame_start = state.committed_end;
        let frame_end = frame_start
            .checked_add(FRAME_BYTES as u64)
            .and_then(|end| end.checked_add(payload_len as u64))
            .ok_or(CoreError::InvalidInput("backend length overflow"))?;
        if frame_end > i64::MAX as u64 {
            return Err(CoreError::InvalidInput(
                "backend length exceeds platform bound",
            ));
        }
        let undo_bytes = (operations.len() as u64)
            .checked_mul(std::mem::size_of::<Undo>() as u64)
            .ok_or(CoreError::InvalidInput("undo workspace overflow"))?;
        let _undo_lease = reserve(&self.shared.admission, undo_bytes)?;
        let mut undo = Vec::new();
        undo.try_reserve_exact(operations.len())
            .map_err(|_| CoreError::CapacityDenied)?;
        let mut value_cursor = frame_start + FRAME_BYTES as u64;
        for operation in operations {
            let (table, key, value) = operation_parts(operation);
            let value_at = value_cursor + OP_BYTES as u64 + table.len() as u64 + key.len() as u64;
            let reference = match operation {
                Operation::Put { .. } => Some(ValueRef {
                    at: value_at,
                    len: value.len() as u32,
                    crc: crc32c(value),
                }),
                _ => None,
            };
            match apply_provisional(
                &mut state.index,
                operation,
                next_generation,
                reference,
                &self.shared.index_pool,
            ) {
                Ok(change) => undo.push(change),
                Err(error) => {
                    rollback(&mut state.index, operations, &undo);
                    if matches!(error, CoreError::OwnerFailed) {
                        state.fenced = true;
                    }
                    return Err(error);
                }
            }
            value_cursor = value_at
                .checked_add(value.len() as u64)
                .ok_or(CoreError::InvalidInput("backend length overflow"))?;
        }
        debug_assert_eq!(value_cursor, frame_end);
        let physical_len = match state.backend.len() {
            Ok(length) => length,
            Err(error) => {
                state.fenced = true;
                self.shared.admission.owner_failed();
                return Err(CoreError::Io(error));
            }
        };
        if let Err(error) = self
            .shared
            .admission
            .reserve_growth(physical_len, frame_end)
        {
            rollback(&mut state.index, operations, &undo);
            if error == AdmissionError::OwnerFailed {
                state.fenced = true;
            }
            return Err(error.into());
        }
        let payload_crc = payload_checksum(operations);
        let header = frame_header(
            next_generation,
            frame_start,
            payload_len,
            operations.len() as u32,
            payload_crc,
        );
        let result = (|| -> io::Result<()> {
            state.backend.set_len(frame_end)?;
            state.backend.write(frame_start, &header)?;
            let mut at = frame_start + FRAME_BYTES as u64;
            for operation in operations {
                let op = op_header(operation);
                let (table, key, value) = operation_parts(operation);
                for part in [&op[..], table, key, value] {
                    state.backend.write(at, part)?;
                    at += part.len() as u64;
                }
            }
            debug_assert_eq!(at, frame_end);
            state.backend.sync_data()?;
            Ok(())
        })();
        if let Err(error) = result {
            state.fenced = true;
            self.shared.admission.owner_failed();
            return Err(CoreError::UnknownCommit(error));
        }
        if self.shared.admission.settle_growth(frame_end).is_err() {
            state.fenced = true;
            self.shared.admission.owner_failed();
            return Err(CoreError::OwnerFailed);
        }
        let next_slot = 1 - state.slot;
        let commit_header = header_bytes(
            next_generation,
            state.base,
            state.first_generation,
            frame_end,
        );
        if let Err(error) = state
            .backend
            .write((next_slot * HEADER_BYTES) as u64, &commit_header)
            .and_then(|()| state.backend.sync_data())
        {
            state.fenced = true;
            self.shared.admission.owner_failed();
            return Err(CoreError::UnknownCommit(error));
        }
        state.generation = next_generation;
        state.committed_end = frame_end;
        state.slot = next_slot;
        if self.shared.snapshots.load(Ordering::Acquire) == 0 {
            if state.needs_gc {
                prune_all(&mut state.index);
                state.needs_gc = false;
            } else {
                prune_touched(&mut state.index, operations);
            }
        } else {
            state.needs_gc = true;
        }
        Ok(())
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
            Err(TryLockError::Poisoned(_)) => {
                return BackendCloseOutcome::retained(io::ErrorKind::Other.into());
            }
        };
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
            }
        }
        outcome
    }

    pub fn admission(&self) -> Arc<dyn StorageAdmission> {
        self.shared.admission.clone()
    }
}

#[derive(Clone, Copy)]
enum Undo {
    Noop,
    CreatedTable,
    InsertedKey,
    AddedVersion,
}

fn apply_provisional(
    index: &mut Index,
    operation: &Operation,
    generation: u64,
    reference: Option<ValueRef>,
    pool: &Arc<IndexChargePool>,
) -> Result<Undo, CoreError> {
    let table_name = operation.table();
    if let Operation::CreateTable { .. } = operation {
        if index.tables.contains_key(table_name) {
            return Ok(Undo::Noop);
        }
        let lease = pool.claim(table_charge(table_name.len())?)?;
        index.tables.insert(
            table_name.to_owned(),
            Table {
                birth_generation: generation,
                rows: BTreeMap::new(),
                _lease: lease,
            },
        );
        return Ok(Undo::CreatedTable);
    }
    let table = index
        .tables
        .get_mut(table_name)
        .ok_or(CoreError::MissingTable)?;
    let key = match operation {
        Operation::Put { key, .. } | Operation::Delete { key, .. } => key,
        _ => unreachable!(),
    };
    if let Some(entry) = table.rows.get_mut(key.as_slice()) {
        let version_lease = pool.claim(INDEX_ENTRY_CHARGE)?;
        let previous = entry.head.take();
        entry.head = Some(Box::new(VersionNode {
            generation,
            value: reference,
            previous,
            _lease: version_lease,
        }));
        return Ok(Undo::AddedVersion);
    }
    if matches!(operation, Operation::Delete { .. }) {
        return Ok(Undo::Noop);
    }
    let key_lease = pool.claim(entry_charge(key.len())?)?;
    let version_lease = pool.claim(INDEX_ENTRY_CHARGE)?;
    table.rows.insert(
        key.clone(),
        Entry {
            head: Some(Box::new(VersionNode {
                generation,
                value: reference,
                previous: None,
                _lease: version_lease,
            })),
            _lease: key_lease,
        },
    );
    Ok(Undo::InsertedKey)
}

fn rollback(index: &mut Index, operations: &[Operation], undo: &[Undo]) {
    for (operation, change) in operations.iter().zip(undo).rev() {
        let table_name = operation.table();
        match change {
            Undo::Noop => {}
            Undo::CreatedTable => {
                index.tables.remove(table_name);
            }
            Undo::InsertedKey => {
                let key = match operation {
                    Operation::Put { key, .. } => key,
                    _ => unreachable!(),
                };
                if let Some(table) = index.tables.get_mut(table_name) {
                    table.rows.remove(key.as_slice());
                }
            }
            Undo::AddedVersion => {
                let key = match operation {
                    Operation::Put { key, .. } | Operation::Delete { key, .. } => key,
                    _ => unreachable!(),
                };
                if let Some(entry) = index
                    .tables
                    .get_mut(table_name)
                    .and_then(|table| table.rows.get_mut(key.as_slice()))
                {
                    let head = entry.head.take().expect("provisional version");
                    entry.head = head.previous;
                }
            }
        }
    }
}

fn prune_entry(entry: &mut Entry) -> bool {
    let Some(head) = entry.head.as_mut() else {
        return true;
    };
    head.previous = None;
    head.value.is_none()
}
fn prune_touched(index: &mut Index, operations: &[Operation]) {
    for operation in operations {
        let key = match operation {
            Operation::Put { key, .. } | Operation::Delete { key, .. } => key,
            _ => continue,
        };
        let Some(table) = index.tables.get_mut(operation.table()) else {
            continue;
        };
        let remove = table.rows.get_mut(key.as_slice()).is_some_and(prune_entry);
        if remove {
            table.rows.remove(key.as_slice());
        }
    }
}
fn prune_all(index: &mut Index) {
    for table in index.tables.values_mut() {
        table.rows.retain(|_, entry| !prune_entry(entry));
    }
}

#[derive(Clone, Copy)]
struct CompactLayout {
    bytes: u64,
    frames: u64,
}

/// Compute the exact physical size before asking the backend to grow. Each
/// operation fits in one bounded frame; a live database can use many frames.
fn compact_layout(index: &Index) -> Result<CompactLayout, CoreError> {
    let mut bytes = 0u64;
    let mut frames = 0u64;
    let mut payload = 0usize;
    let mut count = 0usize;
    let mut add = |item: usize| -> Result<(), CoreError> {
        if item > MAX_BATCH_BYTES {
            return Err(CoreError::Corrupt("live record exceeds frame bound"));
        }
        if count == 0 || count == MAX_OPERATIONS || payload + item > MAX_BATCH_BYTES {
            bytes = bytes
                .checked_add(FRAME_BYTES as u64)
                .ok_or(CoreError::InvalidInput("compaction length overflow"))?;
            frames += 1;
            payload = 0;
            count = 0;
        }
        bytes = bytes
            .checked_add(item as u64)
            .ok_or(CoreError::InvalidInput("compaction length overflow"))?;
        payload += item;
        count += 1;
        Ok(())
    };
    for (name, table) in &index.tables {
        add(OP_BYTES + name.len())?;
        for (key, entry) in &table.rows {
            let Some(reference) = entry.head.as_ref().and_then(|head| head.value) else {
                continue;
            };
            add(OP_BYTES + name.len() + key.len() + reference.len as usize)?;
        }
    }
    Ok(CompactLayout { bytes, frames })
}

/// Writes a compact snapshot without ever allocating an owned value buffer.
/// The caller guarantees that the source and destination extents do not
/// overlap. Frame headers are written after their payload is complete.
struct CompactWriter<'a> {
    backend: &'a dyn StorageBackend,
    frame_at: u64,
    cursor: u64,
    payload: u32,
    count: u32,
    checksum: Crc32c,
    generation: u64,
    frames: u64,
}
impl<'a> CompactWriter<'a> {
    fn new(backend: &'a dyn StorageBackend, at: u64, prior_generation: u64) -> Self {
        Self {
            backend,
            frame_at: at,
            cursor: at + FRAME_BYTES as u64,
            payload: 0,
            count: 0,
            checksum: Crc32c::new(),
            generation: prior_generation,
            frames: 0,
        }
    }
    fn begin_item(&mut self, len: usize) -> Result<(), CoreError> {
        if len > MAX_BATCH_BYTES {
            return Err(CoreError::Corrupt("live record exceeds frame bound"));
        }
        if self.count != 0
            && (self.count as usize == MAX_OPERATIONS
                || self.payload as usize + len > MAX_BATCH_BYTES)
        {
            self.finish_frame(true)?;
        }
        self.payload += len as u32;
        self.count += 1;
        Ok(())
    }
    fn write_part(&mut self, bytes: &[u8]) -> Result<(), CoreError> {
        if !bytes.is_empty() {
            self.backend.write(self.cursor, bytes)?;
            self.cursor += bytes.len() as u64;
            self.checksum.update(bytes);
        }
        Ok(())
    }
    fn finish_frame(&mut self, next: bool) -> Result<(), CoreError> {
        if self.count == 0 {
            return Ok(());
        }
        if self.cursor != self.frame_at + FRAME_BYTES as u64 + self.payload as u64 {
            return Err(CoreError::Corrupt("compaction frame length disagrees"));
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(CoreError::InvalidInput("generation overflow"))?;
        let header = frame_header(
            generation,
            self.frame_at,
            self.payload,
            self.count,
            std::mem::replace(&mut self.checksum, Crc32c::new()).finish(),
        );
        self.backend.write(self.frame_at, &header)?;
        self.generation = generation;
        self.frames += 1;
        if next {
            self.frame_at = self.cursor;
            self.cursor += FRAME_BYTES as u64;
            self.payload = 0;
            self.count = 0;
        }
        Ok(())
    }
    fn finish(mut self) -> Result<(u64, u64, u64), CoreError> {
        self.finish_frame(false)?;
        Ok((self.cursor, self.generation, self.frames))
    }
}

fn write_compact_snapshot(
    state: &mut State,
    at: u64,
    layout: CompactLayout,
) -> Result<(u64, u64), CoreError> {
    let mut writer = CompactWriter::new(&*state.backend, at, state.generation);
    let mut chunk = [0u8; 8192];
    for (name, table) in &mut state.index.tables {
        writer.begin_item(OP_BYTES + name.len())?;
        let mut header = [0u8; OP_BYTES];
        header[0] = 1;
        put_u16(&mut header[1..3], name.len() as u16);
        writer.write_part(&header)?;
        writer.write_part(name.as_bytes())?;
        for (key, entry) in &mut table.rows {
            let Some(head) = entry.head.as_mut() else {
                continue;
            };
            let Some(source) = head.value else {
                continue;
            };
            writer.begin_item(OP_BYTES + name.len() + key.len() + source.len as usize)?;
            let mut header = [0u8; OP_BYTES];
            header[0] = 2;
            put_u16(&mut header[1..3], name.len() as u16);
            put_u16(&mut header[3..5], key.len() as u16);
            put_u32(&mut header[5..9], source.len);
            put_u32(&mut header[9..13], source.crc);
            writer.write_part(&header)?;
            writer.write_part(name.as_bytes())?;
            writer.write_part(key)?;
            let value_at = writer.cursor;
            let mut remaining = source.len as usize;
            let mut source_at = source.at;
            let mut value_crc = Crc32c::new();
            while remaining != 0 {
                let take = remaining.min(chunk.len());
                writer.backend.read(source_at, &mut chunk[..take])?;
                value_crc.update(&chunk[..take]);
                writer.write_part(&chunk[..take])?;
                source_at += take as u64;
                remaining -= take;
            }
            if value_crc.finish() != source.crc {
                return Err(CoreError::Corrupt("committed value checksum differs"));
            }
            head.value = Some(ValueRef {
                at: value_at,
                len: source.len,
                crc: source.crc,
            });
        }
    }
    let (end, generation, frames) = writer.finish()?;
    if end != at + layout.bytes || frames != layout.frames {
        return Err(CoreError::Corrupt("compaction layout disagrees"));
    }
    Ok((end, generation))
}

struct Frame {
    generation: u64,
    payload_at: u64,
    payload_end: u64,
    end: u64,
    count: u32,
    checksum: u32,
}

fn read_frame(
    backend: &dyn StorageBackend,
    at: u64,
    committed_end: u64,
    prior_generation: u64,
) -> Result<Frame, CoreError> {
    if at
        .checked_add(FRAME_BYTES as u64)
        .is_none_or(|end| end > committed_end)
    {
        return Err(CoreError::Corrupt("truncated committed transaction header"));
    }
    let mut bytes = [0u8; FRAME_BYTES];
    backend.read(at, &mut bytes)?;
    if bytes[..8] != FRAME_MAGIC || get_u32(&bytes[36..40]) != crc32c(&bytes[..36]) {
        return Err(CoreError::Corrupt("transaction header checksum differs"));
    }
    let generation = get_u64(&bytes[8..16]);
    if generation
        != prior_generation
            .checked_add(1)
            .ok_or(CoreError::Corrupt("generation overflow"))?
        || get_u64(&bytes[16..24]) != at
    {
        return Err(CoreError::Corrupt("transaction chain is discontinuous"));
    }
    let payload_len = get_u32(&bytes[24..28]) as u64;
    let count = get_u32(&bytes[28..32]);
    if payload_len == 0
        || payload_len > MAX_BATCH_BYTES as u64
        || count == 0
        || count as usize > MAX_OPERATIONS
    {
        return Err(CoreError::Corrupt("transaction bound is invalid"));
    }
    let payload_at = at + FRAME_BYTES as u64;
    let end = payload_at
        .checked_add(payload_len)
        .ok_or(CoreError::Corrupt("transaction length overflow"))?;
    if end > committed_end {
        return Err(CoreError::Corrupt("committed transaction is truncated"));
    }
    Ok(Frame {
        generation,
        payload_at,
        payload_end: end,
        end,
        count,
        checksum: get_u32(&bytes[32..36]),
    })
}

#[derive(Clone, Copy)]
struct DiskOp {
    tag: u8,
    table_len: usize,
    key_len: usize,
    value_len: usize,
    value_crc: u32,
}
fn decode_disk_op(bytes: &[u8; OP_BYTES]) -> Result<DiskOp, CoreError> {
    let tag = bytes[0];
    let table_len = get_u16(&bytes[1..3]) as usize;
    let key_len = get_u16(&bytes[3..5]) as usize;
    let value_len = get_u32(&bytes[5..9]) as usize;
    let value_crc = get_u32(&bytes[9..13]);
    if table_len == 0
        || table_len > MAX_TABLE_BYTES
        || key_len > MAX_KEY_BYTES
        || value_len > MAX_VALUE_BYTES
        || !matches!(tag, 1..=3)
        || (tag == 1 && (key_len != 0 || value_len != 0 || value_crc != 0))
        || (tag == 3 && (value_len != 0 || value_crc != 0))
    {
        return Err(CoreError::Corrupt(
            "transaction operation has invalid lengths or tag",
        ));
    }
    Ok(DiskOp {
        tag,
        table_len,
        key_len,
        value_len,
        value_crc,
    })
}
fn bounded_read(
    backend: &dyn StorageBackend,
    at: &mut u64,
    end: u64,
    out: &mut [u8],
) -> Result<(), CoreError> {
    let next = at
        .checked_add(out.len() as u64)
        .ok_or(CoreError::Corrupt("transaction offset overflow"))?;
    if next > end {
        return Err(CoreError::Corrupt("transaction payload is truncated"));
    }
    backend.read(*at, out)?;
    *at = next;
    Ok(())
}

/// First pass verifies the complete committed payload before any index state is
/// exposed. Fixed stack buffers bound recovery even for a 32 MiB value.
fn scan_payload(backend: &dyn StorageBackend, frame: &Frame) -> Result<(), CoreError> {
    let mut at = frame.payload_at;
    let mut checksum = Crc32c::new();
    let mut table = [0u8; MAX_TABLE_BYTES];
    let mut key = [0u8; MAX_KEY_BYTES];
    let mut chunk = [0u8; 8192];
    for _ in 0..frame.count {
        let mut header = [0u8; OP_BYTES];
        bounded_read(backend, &mut at, frame.payload_end, &mut header)?;
        let op = decode_disk_op(&header)?;
        checksum.update(&header);
        bounded_read(
            backend,
            &mut at,
            frame.payload_end,
            &mut table[..op.table_len],
        )?;
        if std::str::from_utf8(&table[..op.table_len]).is_err() {
            return Err(CoreError::Corrupt("transaction table name is not UTF-8"));
        }
        checksum.update(&table[..op.table_len]);
        bounded_read(backend, &mut at, frame.payload_end, &mut key[..op.key_len])?;
        checksum.update(&key[..op.key_len]);
        let mut value_crc = Crc32c::new();
        let mut left = op.value_len;
        while left != 0 {
            let count = left.min(chunk.len());
            bounded_read(backend, &mut at, frame.payload_end, &mut chunk[..count])?;
            checksum.update(&chunk[..count]);
            value_crc.update(&chunk[..count]);
            left -= count;
        }
        if value_crc.finish() != op.value_crc {
            return Err(CoreError::Corrupt("committed value checksum differs"));
        }
    }
    if at != frame.payload_end || checksum.finish() != frame.checksum {
        return Err(CoreError::Corrupt("committed transaction checksum differs"));
    }
    Ok(())
}

/// Second pass builds only the ordered key-to-offset index. The scan above has
/// already authenticated the complete frame; value bytes are never allocated.
fn replay_payload(
    backend: &dyn StorageBackend,
    frame: &Frame,
    index: &mut Index,
    pool: &Arc<IndexChargePool>,
) -> Result<(), CoreError> {
    let mut at = frame.payload_at;
    let mut table_buf = [0u8; MAX_TABLE_BYTES];
    let mut key_buf = [0u8; MAX_KEY_BYTES];
    for _ in 0..frame.count {
        let mut header = [0u8; OP_BYTES];
        bounded_read(backend, &mut at, frame.payload_end, &mut header)?;
        let op = decode_disk_op(&header)?;
        bounded_read(
            backend,
            &mut at,
            frame.payload_end,
            &mut table_buf[..op.table_len],
        )?;
        bounded_read(
            backend,
            &mut at,
            frame.payload_end,
            &mut key_buf[..op.key_len],
        )?;
        let table_name = std::str::from_utf8(&table_buf[..op.table_len])
            .map_err(|_| CoreError::Corrupt("transaction table name is not UTF-8"))?;
        let key = &key_buf[..op.key_len];
        let value_at = at;
        at = at
            .checked_add(op.value_len as u64)
            .ok_or(CoreError::Corrupt("transaction offset overflow"))?;
        if at > frame.payload_end {
            return Err(CoreError::Corrupt("transaction value is truncated"));
        }
        match op.tag {
            1 => {
                if !index.tables.contains_key(table_name) {
                    let lease = pool.claim(table_charge(table_name.len())?)?;
                    index.tables.insert(
                        table_name.to_owned(),
                        Table {
                            birth_generation: frame.generation,
                            rows: BTreeMap::new(),
                            _lease: lease,
                        },
                    );
                }
            }
            2 => {
                let table = index
                    .tables
                    .get_mut(table_name)
                    .ok_or(CoreError::Corrupt("put precedes table creation"))?;
                let reference = ValueRef {
                    at: value_at,
                    len: op.value_len as u32,
                    crc: op.value_crc,
                };
                if let Some(entry) = table.rows.get_mut(key) {
                    let version = entry.head.as_mut().expect("recovered key has version");
                    version.generation = frame.generation;
                    version.value = Some(reference);
                } else {
                    let key_lease = pool.claim(entry_charge(key.len())?)?;
                    let version_lease = pool.claim(INDEX_ENTRY_CHARGE)?;
                    table.rows.insert(
                        key.to_vec(),
                        Entry {
                            head: Some(Box::new(VersionNode {
                                generation: frame.generation,
                                value: Some(reference),
                                previous: None,
                                _lease: version_lease,
                            })),
                            _lease: key_lease,
                        },
                    );
                }
            }
            3 => {
                let table = index
                    .tables
                    .get_mut(table_name)
                    .ok_or(CoreError::Corrupt("delete precedes table creation"))?;
                table.rows.remove(key);
            }
            _ => unreachable!(),
        }
    }
    if at != frame.payload_end {
        return Err(CoreError::Corrupt("replay did not consume transaction"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestAdmission {
        used: Arc<AtomicU64>,
        limit: AtomicU64,
        growth_limit: AtomicU64,
        copy_reservations: AtomicUsize,
        deny_copy_at: AtomicUsize,
        failed: AtomicBool,
    }
    struct TestLease {
        used: Arc<AtomicU64>,
        bytes: u64,
    }
    impl Drop for TestLease {
        fn drop(&mut self) {
            self.used.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
    impl TestAdmission {
        fn unlimited() -> Arc<Self> {
            Arc::new(Self {
                limit: AtomicU64::new(u64::MAX),
                growth_limit: AtomicU64::new(u64::MAX),
                deny_copy_at: AtomicUsize::new(usize::MAX),
                ..Self::default()
            })
        }
        fn limited(limit: u64) -> Arc<Self> {
            Arc::new(Self {
                limit: AtomicU64::new(limit),
                growth_limit: AtomicU64::new(u64::MAX),
                deny_copy_at: AtomicUsize::new(usize::MAX),
                ..Self::default()
            })
        }
    }
    impl StorageAdmission for TestAdmission {
        fn check_owner(&self) -> Result<(), OwnerFailed> {
            if self.failed.load(Ordering::Acquire) {
                Err(OwnerFailed)
            } else {
                Ok(())
            }
        }
        fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
            self.check_owner()
                .map_err(|_| AdmissionError::OwnerFailed)?;
            if bytes == 8192
                && self.copy_reservations.fetch_add(1, Ordering::AcqRel) + 1
                    == self.deny_copy_at.load(Ordering::Acquire)
            {
                return Err(AdmissionError::CapacityDenied);
            }
            let mut observed = self.used.load(Ordering::Acquire);
            loop {
                let next = observed
                    .checked_add(bytes)
                    .ok_or(AdmissionError::CapacityDenied)?;
                if next > self.limit.load(Ordering::Acquire) {
                    return Err(AdmissionError::CapacityDenied);
                }
                match self.used.compare_exchange(
                    observed,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(actual) => observed = actual,
                }
            }
            Ok(Box::new(TestLease {
                used: self.used.clone(),
                bytes,
            }))
        }
        fn reserve_growth(&self, _current: u64, requested: u64) -> Result<(), AdmissionError> {
            self.check_owner()
                .map_err(|_| AdmissionError::OwnerFailed)?;
            if requested > self.growth_limit.load(Ordering::Acquire) {
                return Err(AdmissionError::CapacityDenied);
            }
            Ok(())
        }
        fn settle_growth(&self, _actual: u64) -> Result<(), OwnerFailed> {
            self.check_owner()
        }
        fn owner_failed(&self) {
            self.failed.store(true, Ordering::Release);
        }
    }

    struct CrashState {
        volatile: Vec<u8>,
        durable: Vec<u8>,
        sync_fault: Option<(usize, bool)>,
        fail_next_read: bool,
        fail_next_len: bool,
        panic_next_len: bool,
        close_not_entered: bool,
        panic_close: bool,
        close_attempts: usize,
        close_error: Option<io::Error>,
    }
    #[derive(Clone)]
    struct CrashBackend(Arc<Mutex<CrashState>>);
    impl CrashBackend {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(CrashState {
                volatile: Vec::new(),
                durable: Vec::new(),
                sync_fault: None,
                fail_next_read: false,
                fail_next_len: false,
                panic_next_len: false,
                close_not_entered: false,
                panic_close: false,
                close_attempts: 0,
                close_error: None,
            })))
        }
        fn crash(&self) -> Self {
            let durable = self.0.lock().unwrap().durable.clone();
            Self(Arc::new(Mutex::new(CrashState {
                volatile: durable.clone(),
                durable,
                sync_fault: None,
                fail_next_read: false,
                fail_next_len: false,
                panic_next_len: false,
                close_not_entered: false,
                panic_close: false,
                close_attempts: 0,
                close_error: None,
            })))
        }
        fn fail_sync(&self, ordinal: usize, after_persist: bool) {
            self.0.lock().unwrap().sync_fault = Some((ordinal, after_persist));
        }
        fn fail_next_read(&self) {
            self.0.lock().unwrap().fail_next_read = true;
        }
        fn fail_next_len(&self) {
            self.0.lock().unwrap().fail_next_len = true;
        }
        fn panic_next_len(&self) {
            self.0.lock().unwrap().panic_next_len = true;
        }
        fn panic_close(&self) {
            self.0.lock().unwrap().panic_close = true;
        }
        fn close_not_entered_once(&self) {
            self.0.lock().unwrap().close_not_entered = true;
        }
        fn close_attempts(&self) -> usize {
            self.0.lock().unwrap().close_attempts
        }
        fn fail_close_with(&self, error: io::Error) {
            self.0.lock().unwrap().close_error = Some(error);
        }
        fn corrupt_durable(&self, needle: &[u8]) {
            let mut state = self.0.lock().unwrap();
            let at = state
                .durable
                .windows(needle.len())
                .position(|window| window == needle)
                .unwrap();
            state.durable[at] ^= 0x80;
        }
        fn corrupt_header(&self, slot: usize) {
            let mut state = self.0.lock().unwrap();
            state.durable[slot * HEADER_BYTES + 24] ^= 0x80;
        }
    }
    impl StorageBackend for CrashBackend {
        fn len(&self) -> io::Result<u64> {
            let mut state = self.0.lock().unwrap();
            if std::mem::take(&mut state.panic_next_len) {
                drop(state);
                panic!("injected length panic");
            }
            if std::mem::take(&mut state.fail_next_len) {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(state.volatile.len() as u64)
        }
        fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let mut state = self.0.lock().unwrap();
            if state.fail_next_read {
                state.fail_next_read = false;
                return Err(io::Error::other("injected value read failure"));
            }
            let at = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
            let end = at
                .checked_add(out.len())
                .ok_or(io::ErrorKind::InvalidInput)?;
            out.copy_from_slice(
                state
                    .volatile
                    .get(at..end)
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write(&self, at: u64, input: &[u8]) -> io::Result<()> {
            let mut state = self.0.lock().unwrap();
            let at = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
            let end = at
                .checked_add(input.len())
                .ok_or(io::ErrorKind::InvalidInput)?;
            state
                .volatile
                .get_mut(at..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?
                .copy_from_slice(input);
            Ok(())
        }
        fn set_len(&self, length: u64) -> io::Result<()> {
            self.0.lock().unwrap().volatile.resize(
                usize::try_from(length).map_err(|_| io::ErrorKind::InvalidInput)?,
                0,
            );
            Ok(())
        }
        fn sync_data(&self) -> io::Result<()> {
            let mut state = self.0.lock().unwrap();
            if let Some((remaining, after)) = state.sync_fault {
                if remaining == 1 {
                    state.sync_fault = None;
                    if after {
                        state.durable = state.volatile.clone();
                    }
                    return Err(io::Error::other("injected sync failure"));
                }
                state.sync_fault = Some((remaining - 1, after));
            }
            state.durable = state.volatile.clone();
            Ok(())
        }
        fn close(&self) -> BackendCloseOutcome {
            let mut state = self.0.lock().unwrap();
            state.close_attempts += 1;
            if std::mem::take(&mut state.close_not_entered) {
                return BackendCloseOutcome::not_entered(io::ErrorKind::WouldBlock.into());
            }
            if std::mem::take(&mut state.panic_close) {
                drop(state);
                panic!("injected close panic");
            }
            BackendCloseOutcome::drained(state.close_error.take().map_or(Ok(()), Err))
        }
    }

    fn new_core() -> (Core, CrashBackend) {
        let backend = CrashBackend::new();
        let core = Core::create_with_backend(backend.clone(), TestAdmission::unlimited()).unwrap();
        (core, backend)
    }

    #[test]
    fn failed_direct_create_len_check_closes_the_exact_backend_once() {
        let backend = CrashBackend::new();
        backend.fail_next_len();
        let error = Core::create_with_backend(backend.clone(), TestAdmission::unlimited())
            .err()
            .expect("injected length failure must reject creation");
        assert!(matches!(
            error,
            CoreError::Io(ref error) if error.raw_os_error() == Some(libc::EIO)
        ));
        assert_eq!(backend.close_attempts(), 1);
    }

    #[test]
    fn failed_direct_open_retains_the_open_and_close_errors() {
        let backend = CrashBackend::new();
        backend.fail_close_with(io::Error::from_raw_os_error(libc::ENOSPC));
        let mut error = Core::open_with_backend(backend.clone(), TestAdmission::unlimited())
            .err()
            .expect("an empty backend is not an existing database");
        let CoreError::OpeningFailure(failure) = &mut error else {
            panic!("the failed close must accompany the original open failure");
        };
        assert!(matches!(failure.original_error(), CoreError::Corrupt(_)));
        assert_eq!(failure.close_report().entry(), BackendCloseEntry::Entered);
        assert_eq!(
            failure.close_report().native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert_eq!(
            failure
                .close_report()
                .result
                .as_ref()
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOSPC)
        );
        let _ = failure.retry_close();
        assert_eq!(backend.close_attempts(), 1);
    }

    #[test]
    fn direct_constructor_panic_keeps_its_payload_and_closes() {
        let backend = CrashBackend::new();
        backend.panic_next_len();
        let error = Core::create_with_backend(backend.clone(), TestAdmission::unlimited())
            .err()
            .expect("injected length panic must become a retained failure");
        let CoreError::Panicked(panic) = error else {
            panic!("original opening panic must remain inspectable");
        };
        assert_eq!(
            panic.with_payload(|payload| payload.downcast_ref::<&str>().copied()),
            Some("injected length panic")
        );
        assert_eq!(backend.close_attempts(), 1);
    }

    #[test]
    fn direct_constructor_close_panic_is_terminal_and_keeps_both_causes() {
        let backend = CrashBackend::new();
        backend.fail_next_len();
        backend.panic_close();
        let mut error = Core::create_with_backend(backend.clone(), TestAdmission::unlimited())
            .err()
            .expect("injected length failure and close panic must both be reported");
        let CoreError::OpeningFailure(failure) = &mut error else {
            panic!("close panic must retain the failed opening owner");
        };
        assert!(matches!(
            failure.original_error(),
            CoreError::Io(error) if error.raw_os_error() == Some(libc::EIO)
        ));
        assert_eq!(failure.close_report().entry(), BackendCloseEntry::Entered);
        assert_eq!(
            failure.close_report().native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert_eq!(
            failure
                .close_panic()
                .unwrap()
                .with_payload(|payload| payload.downcast_ref::<&str>().copied()),
            Some("injected close panic")
        );
        let _ = failure.retry_close();
        assert_eq!(backend.close_attempts(), 1);
    }

    #[test]
    fn retrying_a_pre_effect_close_keeps_its_later_panic_and_original_error() {
        let backend = CrashBackend::new();
        backend.fail_next_len();
        backend.close_not_entered_once();
        backend.panic_close();
        let Err(mut error) = Core::create_with_backend(backend.clone(), TestAdmission::unlimited())
        else {
            panic!("injected length error must reject creation");
        };
        let CoreError::OpeningFailure(failure) = &mut error else {
            panic!("pre-effect close must retain the original owner");
        };
        assert_eq!(
            failure.close_report().entry(),
            BackendCloseEntry::NotEntered
        );
        assert_eq!(backend.close_attempts(), 1);
        assert_eq!(failure.retry_close().entry(), BackendCloseEntry::Entered);
        assert!(matches!(
            failure.original_error(),
            CoreError::Io(error) if error.raw_os_error() == Some(libc::EIO)
        ));
        assert_eq!(
            failure
                .close_panic()
                .unwrap()
                .with_payload(|payload| payload.downcast_ref::<&str>().copied()),
            Some("injected close panic")
        );
        let _ = failure.retry_close();
        assert_eq!(backend.close_attempts(), 2);
    }

    #[test]
    fn failed_value_read_fences_every_snapshot_fact() {
        let backend = CrashBackend::new();
        let admission = TestAdmission::unlimited();
        let core = Core::create_with_backend(backend.clone(), admission.clone()).unwrap();
        core.commit(&[
            Operation::create_table("items"),
            Operation::put("items", b"present", b"value"),
        ])
        .unwrap();
        let snapshot = core.snapshot().unwrap();
        backend.fail_next_read();
        assert!(matches!(
            core.get_admitted(&snapshot, "items", b"present", 16),
            Err(CoreError::Io(_))
        ));
        assert!(admission.failed.load(Ordering::Acquire));
        assert!(matches!(
            snapshot.table_exists("items"),
            Err(CoreError::OwnerFailed)
        ));
        assert!(matches!(
            snapshot.table_exists("missing"),
            Err(CoreError::OwnerFailed)
        ));
        assert!(matches!(
            core.get_admitted(&snapshot, "items", b"present", 16),
            Err(CoreError::OwnerFailed)
        ));
        assert!(matches!(
            core.get_admitted(&snapshot, "items", b"absent", 16),
            Err(CoreError::OwnerFailed)
        ));
        assert!(matches!(
            core.next_admitted(&snapshot, "items", b"present", None, 16),
            Err(CoreError::OwnerFailed)
        ));
        assert!(matches!(
            core.next_admitted(&snapshot, "items", b"empty-prefix", None, 16),
            Err(CoreError::OwnerFailed)
        ));
        assert!(matches!(
            snapshot.next_key_admitted("items", b"present", None),
            Err(CoreError::OwnerFailed)
        ));
        assert!(matches!(
            snapshot.next_key_admitted("items", b"empty-prefix", None),
            Err(CoreError::OwnerFailed)
        ));
        assert!(matches!(core.generation(), Err(CoreError::OwnerFailed)));
        assert!(matches!(core.committed_end(), Err(CoreError::OwnerFailed)));
    }

    #[test]
    fn external_owner_failure_cannot_report_absence_without_a_backend_read() {
        let backend = CrashBackend::new();
        let admission = TestAdmission::unlimited();
        let core = Core::create_with_backend(backend, admission.clone()).unwrap();
        core.commit(&[Operation::create_table("items")]).unwrap();
        let snapshot = core.snapshot().unwrap();
        admission.failed.store(true, Ordering::Release);
        assert!(matches!(
            snapshot.table_exists("missing"),
            Err(CoreError::OwnerFailed)
        ));
        assert!(matches!(
            core.get_admitted(&snapshot, "items", b"absent", 16),
            Err(CoreError::OwnerFailed)
        ));
        assert!(matches!(
            core.next_admitted(&snapshot, "items", b"empty", None, 16),
            Err(CoreError::OwnerFailed)
        ));
        assert!(matches!(
            snapshot.next_key_admitted("items", b"empty", None),
            Err(CoreError::OwnerFailed)
        ));
    }

    fn file_backend_for_close_test() -> FileBackend {
        static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(0);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "kasumi-kv-close-{}-{nonce}-{}",
            std::process::id(),
            NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        FileBackend::from_file(file)
    }

    fn parent_sync_test_path() -> std::path::PathBuf {
        static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "kasumi-kv-parent-sync-{}-{}",
            std::process::id(),
            NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn new_named_file_syncs_parent_before_successful_create_and_reopens() {
        let path = parent_sync_test_path();
        let before = FILE_PARENT_SYNC_ATTEMPTS.with(std::cell::Cell::get);
        let closes = FILE_PARENT_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        let backend = FileBackend::create_new(&path).unwrap();
        let identity = backend.identity().unwrap();
        assert_eq!(
            FILE_PARENT_SYNC_ATTEMPTS.with(std::cell::Cell::get),
            before + 1
        );

        let core = Core::create_strict_with_backend(backend, TestAdmission::unlimited()).unwrap();
        assert_eq!(
            FILE_PARENT_SYNC_ATTEMPTS.with(std::cell::Cell::get),
            before + 2
        );
        core.commit(&[
            Operation::create_table("items"),
            Operation::put("items", b"key", b"durable"),
        ])
        .unwrap();
        assert_eq!(
            FILE_PARENT_SYNC_ATTEMPTS.with(std::cell::Cell::get),
            before + 2
        );
        assert_eq!(
            core.close().native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert_eq!(
            FILE_PARENT_CLOSE_ATTEMPTS.with(std::cell::Cell::get),
            closes + 1
        );

        let reopened = Core::open_with_backend(
            FileBackend::open_existing(&path, identity).unwrap(),
            TestAdmission::unlimited(),
        )
        .unwrap();
        assert_eq!(
            FILE_PARENT_SYNC_ATTEMPTS.with(std::cell::Cell::get),
            before + 3
        );
        let snapshot = reopened.snapshot().unwrap();
        assert_eq!(
            reopened.get(&snapshot, "items", b"key", 16).unwrap(),
            Some(b"durable".to_vec())
        );
        drop(snapshot);
        assert_eq!(
            reopened.close().native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert_eq!(
            FILE_PARENT_CLOSE_ATTEMPTS.with(std::cell::Cell::get),
            closes + 2
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn named_create_does_not_adopt_file_inserted_after_parent_sync() {
        let path = parent_sync_test_path();
        let inserted = path.clone();
        let data_closes = FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        let parent_closes = FILE_PARENT_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        FILE_AFTER_PREDATA_SYNC.with(|slot| {
            assert!(
                slot.borrow_mut()
                    .replace(Box::new(move || {
                        std::fs::write(&inserted, b"other owner").unwrap();
                    }))
                    .is_none()
            );
        });
        let error = FileBackend::create_new(&path).err().unwrap();
        assert_eq!(error.raw_os_error(), Some(libc::EEXIST));
        assert_eq!(
            error.close_report().unwrap().native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert_eq!(FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get), data_closes);
        assert_eq!(
            FILE_PARENT_CLOSE_ATTEMPTS.with(std::cell::Cell::get),
            parent_closes + 1
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"other owner");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn named_reopen_rejects_substituted_valid_file_and_closes_both_descriptors() {
        let path = parent_sync_test_path();
        let replacement = path.with_extension("replacement");
        let original = FileBackend::create_new(&path).unwrap();
        let identity = original.identity().unwrap();
        let original =
            Core::create_strict_with_backend(original, TestAdmission::unlimited()).unwrap();
        assert_eq!(
            original.close().native_disposition(),
            BackendNativeDisposition::Drained
        );
        let other = FileBackend::create_new(&replacement).unwrap();
        assert_ne!(other.identity().unwrap(), identity);
        let other = Core::create_strict_with_backend(other, TestAdmission::unlimited()).unwrap();
        assert_eq!(
            other.close().native_disposition(),
            BackendNativeDisposition::Drained
        );
        std::fs::rename(&replacement, &path).unwrap();

        let data_closes = FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        let parent_closes = FILE_PARENT_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        let error = FileBackend::open_existing(&path, identity).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let close = error.close_report().unwrap();
        assert_eq!(close.entry(), BackendCloseEntry::Entered);
        assert_eq!(close.native_disposition(), BackendNativeDisposition::Drained);
        assert_eq!(FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get), data_closes + 1);
        assert_eq!(
            FILE_PARENT_CLOSE_ATTEMPTS.with(std::cell::Cell::get),
            parent_closes + 1
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_parent_sync_makes_create_uncertain_until_same_path_reopens() {
        let path = parent_sync_test_path();
        let backend = FileBackend::create_new(&path).unwrap();
        let identity = backend.identity().unwrap();
        let before = FILE_PARENT_SYNC_ATTEMPTS.with(std::cell::Cell::get);
        FILE_PARENT_SYNC_FAILURE
            .with(|failure| assert!(failure.replace(Some(libc::EIO)).is_none()));
        let error = Core::create_strict_with_backend(backend, TestAdmission::unlimited())
            .err()
            .expect("directory sync failure must not publish a successful create");
        assert!(
            matches!(error, CoreError::Io(ref error) if error.raw_os_error() == Some(libc::EIO))
        );
        assert_eq!(
            FILE_PARENT_SYNC_ATTEMPTS.with(std::cell::Cell::get),
            before + 2
        );

        FILE_PARENT_SYNC_FAILURE
            .with(|failure| assert!(failure.replace(Some(libc::EIO)).is_none()));
        let retry = FileBackend::open_existing(&path, identity).err().unwrap();
        assert_eq!(retry.raw_os_error(), Some(libc::EIO));
        assert_eq!(
            retry.close_report().unwrap().native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert_eq!(
            FILE_PARENT_SYNC_ATTEMPTS.with(std::cell::Cell::get),
            before + 3
        );

        let reopened = Core::open_with_backend(
            FileBackend::open_existing(&path, identity).unwrap(),
            TestAdmission::unlimited(),
        )
        .unwrap();
        assert_eq!(
            FILE_PARENT_SYNC_ATTEMPTS.with(std::cell::Cell::get),
            before + 4
        );
        assert_eq!(reopened.generation().unwrap(), 0);
        assert_eq!(
            reopened.close().native_disposition(),
            BackendNativeDisposition::Drained
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn predata_parent_sync_failure_retains_original_and_observes_close_once() {
        let path = parent_sync_test_path();
        let parent_closes = FILE_PARENT_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        let data_closes = FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        FILE_PARENT_SYNC_FAILURE
            .with(|failure| assert!(failure.replace(Some(libc::EIO)).is_none()));
        FILE_PARENT_CLOSE_FAILURE
            .with(|failure| assert!(failure.replace(Some(libc::EINTR)).is_none()));
        let mut error = FileBackend::create_new(&path).err().unwrap();
        assert_eq!(error.original_error().raw_os_error(), Some(libc::EIO));
        assert!(!path.exists(), "data descriptor was never acquired");
        let report = error.close_report().unwrap();
        assert_eq!(report.entry(), BackendCloseEntry::Entered);
        assert_eq!(
            report.native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert_eq!(
            report.result.as_ref().unwrap_err().raw_os_error(),
            Some(libc::EINTR)
        );
        assert_eq!(
            FILE_PARENT_CLOSE_ATTEMPTS.with(std::cell::Cell::get),
            parent_closes + 1
        );
        assert_eq!(FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get), data_closes);
        let _ = error.retry_close();
        assert_eq!(
            FILE_PARENT_CLOSE_ATTEMPTS.with(std::cell::Cell::get),
            parent_closes + 1
        );
    }

    #[test]
    fn failed_create_preserves_open_error_and_uncertain_parent_close_report() {
        let path = parent_sync_test_path();
        let backend = FileBackend::create_new(&path).unwrap();
        let parent_closes = FILE_PARENT_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        let data_closes = FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        FILE_PARENT_SYNC_FAILURE
            .with(|failure| assert!(failure.replace(Some(libc::EIO)).is_none()));
        FILE_PARENT_CLOSE_FAILURE
            .with(|failure| assert!(failure.replace(Some(libc::EINTR)).is_none()));
        let mut error = Core::create_strict_with_backend(backend, TestAdmission::unlimited())
            .err()
            .unwrap();
        let CoreError::OpeningFailure(failure) = &mut error else {
            panic!("uncertain close must retain the original opening error");
        };
        assert!(
            matches!(failure.original_error(), CoreError::Io(error) if error.raw_os_error() == Some(libc::EIO))
        );
        assert_eq!(failure.close_report().entry(), BackendCloseEntry::Entered);
        assert_eq!(
            failure.close_report().native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert_eq!(
            failure
                .close_report()
                .result
                .as_ref()
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINTR)
        );
        assert_eq!(
            FILE_PARENT_CLOSE_ATTEMPTS.with(std::cell::Cell::get),
            parent_closes + 1
        );
        assert_eq!(
            FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get),
            data_closes + 1
        );
        let _ = failure.retry_close();
        assert_eq!(
            FILE_PARENT_CLOSE_ATTEMPTS.with(std::cell::Cell::get),
            parent_closes + 1
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn named_backend_rejects_final_symlink_without_opening_target() {
        let target = parent_sync_test_path();
        let link = target.with_extension("link");
        std::fs::write(&target, b"target bytes").unwrap();
        let identity = NamedFileIdentity::from_file(&File::open(&target).unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = FileBackend::open_existing(&link, identity).err().unwrap();
        assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
        assert_eq!(
            error.close_report().unwrap().native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"target bytes");
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(target).unwrap();
    }

    #[test]
    fn file_backend_close_waits_for_lock_before_native_attempt() {
        let backend = file_backend_for_close_test();
        let attempts = FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        let guard = backend.state.lock().unwrap();
        let busy = backend.close();
        assert_eq!(busy.entry(), BackendCloseEntry::NotEntered);
        assert_eq!(
            busy.native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert_eq!(
            busy.into_result().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get), attempts);
        drop(guard);
        assert_eq!(backend.close().entry(), BackendCloseEntry::Entered);
        assert_eq!(
            backend.close().native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert_eq!(FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get), attempts + 1);
    }

    #[test]
    fn file_backend_uncertain_close_retains_original_error_without_retry() {
        let backend = file_backend_for_close_test();
        let attempts = FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        FILE_CLOSE_FAILURE.with(|failure| assert!(failure.replace(Some(libc::EINTR)).is_none()));
        let first = backend.close();
        assert_eq!(first.entry(), BackendCloseEntry::Entered);
        assert_eq!(
            first.native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert_eq!(
            first.into_result().unwrap_err().raw_os_error(),
            Some(libc::EINTR)
        );
        assert_eq!(FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get), attempts + 1);
        let consumed_descriptor = match &*backend.state.lock().unwrap() {
            FileBackendState::UnknownClose {
                _data_descriptor,
                original_error,
                _prior_sync_error,
                ..
            } => {
                assert_eq!(original_error.raw_os_error(), Some(libc::EINTR));
                assert!(_prior_sync_error.is_none());
                _data_descriptor.expect("data descriptor was consumed")
            }
            _ => panic!("uncertain close must retain original native evidence"),
        };
        assert!(consumed_descriptor >= 0);
        let other_owner = file_backend_for_close_test();
        let second = backend.close();
        assert_eq!(second.entry(), BackendCloseEntry::Entered);
        assert_eq!(
            second.native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert_eq!(
            second.into_result().unwrap_err().raw_os_error(),
            Some(libc::EINTR)
        );
        assert_eq!(FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get), attempts + 1);
        assert_eq!(other_owner.len().unwrap(), 0);
        assert_eq!(
            other_owner.close().native_disposition(),
            BackendNativeDisposition::Drained
        );
    }

    #[test]
    fn file_backend_sync_error_with_successful_native_close_is_drained() {
        let backend = file_backend_for_close_test();
        let attempts = FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        FILE_SYNC_FAILURE.with(|failure| assert!(failure.replace(Some(libc::EIO)).is_none()));
        let first = backend.close();
        assert_eq!(first.entry(), BackendCloseEntry::Entered);
        assert_eq!(
            first.native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert_eq!(
            first.into_result().unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
        assert_eq!(FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get), attempts + 1);
        let second = backend.close();
        assert_eq!(
            second.native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert_eq!(
            second.into_result().unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
        assert_eq!(FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get), attempts + 1);
    }

    #[test]
    fn file_backend_native_error_retains_prior_sync_error() {
        let backend = file_backend_for_close_test();
        let attempts = FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        FILE_SYNC_FAILURE.with(|failure| assert!(failure.replace(Some(libc::EIO)).is_none()));
        FILE_CLOSE_FAILURE.with(|failure| assert!(failure.replace(Some(libc::EINTR)).is_none()));
        let outcome = backend.close();
        assert_eq!(
            outcome.native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert_eq!(
            outcome.into_result().unwrap_err().raw_os_error(),
            Some(libc::EINTR)
        );
        assert_eq!(FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get), attempts + 1);
        match &*backend.state.lock().unwrap() {
            FileBackendState::UnknownClose {
                original_error,
                _prior_sync_error,
                ..
            } => {
                assert_eq!(original_error.raw_os_error(), Some(libc::EINTR));
                assert_eq!(
                    _prior_sync_error.as_ref().unwrap().raw_os_error(),
                    Some(libc::EIO)
                );
            }
            _ => panic!("native uncertainty must retain both original errors"),
        }
    }

    #[test]
    fn core_file_backend_never_retries_entered_native_close() {
        let core =
            Core::create_with_backend(file_backend_for_close_test(), TestAdmission::unlimited())
                .unwrap();
        let attempts = FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        FILE_CLOSE_FAILURE.with(|failure| assert!(failure.replace(Some(libc::EINTR)).is_none()));
        let first = core.close();
        assert_eq!(first.entry(), BackendCloseEntry::Entered);
        assert_eq!(
            first.native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert_eq!(
            first.into_result().unwrap_err().raw_os_error(),
            Some(libc::EINTR)
        );
        let second = core.close();
        assert_eq!(second.entry(), BackendCloseEntry::Entered);
        assert_eq!(
            second.native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert_eq!(
            second.into_result().unwrap_err().raw_os_error(),
            Some(libc::EINTR)
        );
        assert_eq!(FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get), attempts + 1);
    }

    #[test]
    fn core_file_backend_sync_error_stays_failed_after_native_drain() {
        let core =
            Core::create_with_backend(file_backend_for_close_test(), TestAdmission::unlimited())
                .unwrap();
        let attempts = FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get);
        FILE_SYNC_FAILURE.with(|failure| assert!(failure.replace(Some(libc::EIO)).is_none()));
        let first = core.close();
        assert_eq!(first.entry(), BackendCloseEntry::Entered);
        assert_eq!(
            first.native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert_eq!(
            first.into_result().unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
        let second = core.close();
        assert_eq!(second.entry(), BackendCloseEntry::Entered);
        assert_eq!(
            second.native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert_eq!(
            second.into_result().unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
        assert_eq!(FILE_CLOSE_ATTEMPTS.with(std::cell::Cell::get), attempts + 1);
    }

    #[test]
    fn core_first_close_keeps_original_error_source() {
        #[derive(Debug)]
        struct CloseMarker(Arc<()>);
        impl fmt::Display for CloseMarker {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("original close marker")
            }
        }
        impl std::error::Error for CloseMarker {}

        let identity = Arc::new(());
        let backend = CrashBackend::new();
        let core = Core::create_with_backend(backend.clone(), TestAdmission::unlimited()).unwrap();
        backend.fail_close_with(io::Error::other(CloseMarker(identity.clone())));
        let first = core.close();
        assert_eq!(
            first.native_disposition(),
            BackendNativeDisposition::Drained
        );
        let first_error = first.into_result().unwrap_err();
        let source = first_error
            .get_ref()
            .unwrap()
            .downcast_ref::<CloseMarker>()
            .unwrap();
        assert!(Arc::ptr_eq(&source.0, &identity));
        let second = core.close();
        assert_eq!(
            second.native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert_eq!(
            second.into_result().unwrap_err().kind(),
            io::ErrorKind::Other
        );
    }

    #[test]
    fn durable_batches_reopen_with_ordered_snapshot_values() {
        let (core, backend) = new_core();
        core.commit(&[
            Operation::create_table("docs"),
            Operation::put("docs", b"b", b"one"),
        ])
        .unwrap();
        let first = core.snapshot().unwrap();
        core.commit(&[
            Operation::put("docs", b"b", b"two"),
            Operation::put("docs", b"c", b"three"),
        ])
        .unwrap();
        let second = core.snapshot().unwrap();
        assert_eq!(
            core.get(&first, "docs", b"b", 8).unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(core.get(&first, "docs", b"c", 8).unwrap(), None);
        assert_eq!(
            core.get(&second, "docs", b"b", 8).unwrap(),
            Some(b"two".to_vec())
        );
        assert_eq!(
            second.next_key("docs", b"b", None).unwrap(),
            Some(b"b".to_vec())
        );
        assert_eq!(
            second.next_key("docs", b"b", Some(b"b")).unwrap(),
            Some(b"c".to_vec())
        );
        assert_eq!(
            core.close().native_disposition(),
            BackendNativeDisposition::Retained
        );
        drop(first);
        drop(second);
        assert_eq!(
            core.close().native_disposition(),
            BackendNativeDisposition::Drained
        );
        let reopened =
            Core::open_with_backend(backend.crash(), TestAdmission::unlimited()).unwrap();
        let view = reopened.snapshot().unwrap();
        assert_eq!(
            reopened.get(&view, "docs", b"b", 8).unwrap(),
            Some(b"two".to_vec())
        );
    }

    #[test]
    fn table_birth_and_deletion_respect_older_snapshots() {
        let (core, _) = new_core();
        core.commit(&[
            Operation::create_table("old"),
            Operation::put("old", b"k", b"v"),
        ])
        .unwrap();
        let old = core.snapshot().unwrap();
        core.commit(&[
            Operation::create_table("new"),
            Operation::delete("old", b"k"),
        ])
        .unwrap();
        let current = core.snapshot().unwrap();
        assert!(!old.table_exists("new").unwrap());
        assert!(current.table_exists("new").unwrap());
        assert_eq!(core.get(&old, "old", b"k", 1).unwrap(), Some(b"v".to_vec()));
        assert_eq!(core.get(&current, "old", b"k", 1).unwrap(), None);
        drop(old);
        drop(current);
        core.commit(&[Operation::put("old", b"again", b"x")])
            .unwrap();
        assert!(!core.shared.state.lock().unwrap().needs_gc);
    }

    #[test]
    fn failed_header_sync_has_unknown_outcome_and_reopen_decides() {
        for after_persist in [false, true] {
            let (core, backend) = new_core();
            core.commit(&[
                Operation::create_table("data"),
                Operation::put("data", b"key", b"before"),
            ])
            .unwrap();
            backend.fail_sync(2, after_persist);
            assert!(matches!(
                core.commit(&[Operation::put("data", b"key", b"after")]),
                Err(CoreError::UnknownCommit(_))
            ));
            assert!(core.snapshot().is_err());
            let reopened =
                Core::open_with_backend(backend.crash(), TestAdmission::unlimited()).unwrap();
            let view = reopened.snapshot().unwrap();
            let expected = if after_persist {
                b"after".to_vec()
            } else {
                b"before".to_vec()
            };
            assert_eq!(
                reopened.get(&view, "data", b"key", 16).unwrap(),
                Some(expected)
            );
        }
    }

    #[test]
    fn same_host_reopen_persists_validated_volatile_generation() {
        let (core, backend) = new_core();
        core.commit(&[
            Operation::create_table("data"),
            Operation::put("data", b"key", b"before"),
        ])
        .unwrap();

        // The frame sync succeeds, but the header sync fails before the
        // volatile new header becomes durable.
        backend.fail_sync(2, false);
        assert!(matches!(
            core.commit(&[Operation::put("data", b"key", b"after")]),
            Err(CoreError::UnknownCommit(_))
        ));

        let previous_crash =
            Core::open_with_backend(backend.crash(), TestAdmission::unlimited()).unwrap();
        let previous = previous_crash.snapshot().unwrap();
        assert_eq!(
            previous_crash.get(&previous, "data", b"key", 16).unwrap(),
            Some(b"before".to_vec())
        );

        backend.fail_sync(1, false);
        assert!(matches!(
            Core::open_with_backend(backend.clone(), TestAdmission::unlimited()),
            Err(CoreError::Io(_))
        ));

        let resolved =
            Core::open_with_backend(backend.clone(), TestAdmission::unlimited()).unwrap();
        let view = resolved.snapshot().unwrap();
        assert_eq!(
            resolved.get(&view, "data", b"key", 16).unwrap(),
            Some(b"after".to_vec())
        );
        drop(view);

        // Once open has returned the new generation as committed, another
        // crash must still recover it.
        let after_crash =
            Core::open_with_backend(backend.crash(), TestAdmission::unlimited()).unwrap();
        let view = after_crash.snapshot().unwrap();
        assert_eq!(
            after_crash.get(&view, "data", b"key", 16).unwrap(),
            Some(b"after".to_vec())
        );
    }

    #[test]
    fn committed_corruption_fails_closed_even_with_older_header() {
        let (core, backend) = new_core();
        core.commit(&[
            Operation::create_table("data"),
            Operation::put("data", b"k", b"unique_payload"),
        ])
        .unwrap();
        backend.corrupt_durable(b"unique_payload");
        assert!(matches!(
            Core::open_with_backend(backend.crash(), TestAdmission::unlimited()),
            Err(CoreError::Corrupt(_))
        ));
    }

    #[test]
    fn torn_newer_header_uses_prior_complete_generation() {
        let (core, backend) = new_core();
        core.commit(&[
            Operation::create_table("data"),
            Operation::put("data", b"k", b"before"),
        ])
        .unwrap();
        core.commit(&[Operation::put("data", b"k", b"after")])
            .unwrap();
        backend.corrupt_header(0);
        let reopened =
            Core::open_with_backend(backend.crash(), TestAdmission::unlimited()).unwrap();
        let view = reopened.snapshot().unwrap();
        assert_eq!(
            reopened.get(&view, "data", b"k", 16).unwrap(),
            Some(b"before".to_vec())
        );
        assert_eq!(reopened.generation().unwrap(), 1);
    }

    #[test]
    fn denied_index_reservation_keeps_old_generation_and_backend_end() {
        let backend = CrashBackend::new();
        let admission = TestAdmission::limited(700);
        let core = Core::create_with_backend(backend, admission.clone()).unwrap();
        core.commit(&[Operation::create_table("t")]).unwrap();
        let end = core.committed_end().unwrap();
        assert!(matches!(
            core.commit(&[Operation::put("t", b"k", b"v")]),
            Err(CoreError::CapacityDenied)
        ));
        assert_eq!(core.generation().unwrap(), 1);
        assert_eq!(core.committed_end().unwrap(), end);
        assert_eq!(
            admission.used.load(Ordering::Acquire),
            table_charge(1).unwrap()
        );
    }

    #[test]
    fn encrypted_value_headroom_exceeds_plaintext_limit_but_stays_bounded() {
        let (core, _) = new_core();
        core.commit(&[Operation::create_table("records")]).unwrap();
        let envelope = vec![0x5a; (32 << 20) + 128];
        core.commit(&[Operation::put("records", b"k", envelope.clone())])
            .unwrap();
        let snapshot = core.snapshot().unwrap();
        let read = core
            .get_admitted(&snapshot, "records", b"k", envelope.len())
            .unwrap()
            .unwrap();
        assert_eq!(read.as_bytes(), envelope);
        assert!(matches!(
            core.commit(&[Operation::put(
                "records",
                b"too-large",
                vec![0; MAX_VALUE_BYTES + 1]
            )]),
            Err(CoreError::InvalidInput(_))
        ));
    }

    #[test]
    fn compaction_spans_multiple_bounded_frames() {
        let backend = Arc::new(InMemoryBackend::new());
        let core = Core::create_with_backend(backend.clone(), TestAdmission::unlimited()).unwrap();
        core.commit(&[
            Operation::create_table("large"),
            Operation::put("large", b"a", vec![0; 4 << 20]),
        ])
        .unwrap();
        for (key, len, fill) in [
            (b"a".as_slice(), 39 << 20, 1u8),
            (b"b".as_slice(), 39 << 20, 2u8),
            (b"c".as_slice(), 20 << 20, 3u8),
        ] {
            core.commit(&[Operation::put("large", key, vec![fill; len])])
                .unwrap();
        }
        let layout = compact_layout(&core.shared.state.lock().unwrap().index).unwrap();
        assert!(layout.bytes > MAX_BATCH_BYTES as u64);
        assert!(layout.frames >= 2);
        let before = backend.len().unwrap();
        core.compact().unwrap();
        assert!(backend.len().unwrap() < before);
        let reopened = Core::open_with_backend(backend, TestAdmission::unlimited()).unwrap();
        let view = reopened.snapshot().unwrap();
        for (key, len, fill) in [
            (b"a".as_slice(), 39 << 20, 1u8),
            (b"b".as_slice(), 39 << 20, 2u8),
            (b"c".as_slice(), 20 << 20, 3u8),
        ] {
            let value = reopened
                .get_admitted(&view, "large", key, MAX_VALUE_BYTES)
                .unwrap()
                .unwrap();
            assert_eq!(value.as_bytes().len(), len);
            assert!(value.as_bytes().iter().all(|byte| *byte == fill));
        }
    }

    #[test]
    fn denied_shadow_headroom_leaves_committed_data_readable() {
        let backend = CrashBackend::new();
        let admission = TestAdmission::unlimited();
        let core = Core::create_with_backend(backend.clone(), admission.clone()).unwrap();
        core.commit(&[
            Operation::create_table("data"),
            Operation::put("data", b"k", b"old"),
        ])
        .unwrap();
        core.commit(&[Operation::put("data", b"k", b"new")])
            .unwrap();
        let before = backend.len().unwrap();
        let live = compact_layout(&core.shared.state.lock().unwrap().index)
            .unwrap()
            .bytes;
        admission
            .growth_limit
            .store(before + live - 1, Ordering::Release);
        assert!(matches!(core.compact(), Err(CoreError::CapacityDenied)));
        assert_eq!(backend.len().unwrap(), before);
        let view = core.snapshot().unwrap();
        assert_eq!(
            core.get(&view, "data", b"k", 8).unwrap(),
            Some(b"new".to_vec())
        );
        drop(view);
        admission.growth_limit.store(u64::MAX, Ordering::Release);
        core.compact().unwrap();
        let reopened =
            Core::open_with_backend(backend.crash(), TestAdmission::unlimited()).unwrap();
        let view = reopened.snapshot().unwrap();
        assert_eq!(
            reopened.get(&view, "data", b"k", 8).unwrap(),
            Some(b"new".to_vec())
        );
    }

    #[test]
    fn repeated_overwrites_trigger_precommit_reclamation() {
        let (core, backend) = new_core();
        core.commit(&[Operation::create_table("data")]).unwrap();
        for value in 0..20u8 {
            core.commit(&[Operation::put("data", b"k", vec![value; 256 << 10])])
                .unwrap();
        }
        assert!(backend.len().unwrap() < 3 << 20);
        let reopened =
            Core::open_with_backend(backend.crash(), TestAdmission::unlimited()).unwrap();
        let view = reopened.snapshot().unwrap();
        let value = reopened
            .get_admitted(&view, "data", b"k", 256 << 10)
            .unwrap()
            .unwrap();
        assert!(value.as_bytes().iter().all(|byte| *byte == 19));
    }

    #[test]
    fn phase_two_uses_the_same_workspace_reservation() {
        let backend = CrashBackend::new();
        let admission = TestAdmission::unlimited();
        admission.deny_copy_at.store(2, Ordering::Release);
        let core = Core::create_with_backend(backend.clone(), admission.clone()).unwrap();
        core.commit(&[
            Operation::create_table("data"),
            Operation::put("data", b"k", b"old"),
        ])
        .unwrap();
        core.commit(&[Operation::put("data", b"k", b"new")])
            .unwrap();
        core.compact().unwrap();
        assert_eq!(admission.copy_reservations.load(Ordering::Acquire), 1);
        let reopened =
            Core::open_with_backend(backend.crash(), TestAdmission::unlimited()).unwrap();
        let view = reopened.snapshot().unwrap();
        assert_eq!(
            reopened.get(&view, "data", b"k", 8).unwrap(),
            Some(b"new".to_vec())
        );
    }

    #[test]
    fn denied_recovery_of_published_shadow_can_retry_without_data_loss() {
        let (core, backend) = new_core();
        core.commit(&[
            Operation::create_table("data"),
            Operation::put("data", b"k", b"old"),
        ])
        .unwrap();
        core.commit(&[Operation::put("data", b"k", b"new")])
            .unwrap();
        backend.fail_sync(3, false);
        assert!(core.compact().is_err());
        let recovered_backend = backend.crash();
        let denied = TestAdmission::unlimited();
        denied.deny_copy_at.store(1, Ordering::Release);
        assert!(matches!(
            Core::open_with_backend(recovered_backend.clone(), denied),
            Err(CoreError::CapacityDenied)
        ));
        assert_eq!(recovered_backend.close_attempts(), 1);
        let reopened =
            Core::open_with_backend(recovered_backend, TestAdmission::unlimited()).unwrap();
        let view = reopened.snapshot().unwrap();
        assert_eq!(
            reopened.get(&view, "data", b"k", 8).unwrap(),
            Some(b"new".to_vec())
        );
    }
}
