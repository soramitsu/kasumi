use super::{
    AccountedDirectory, AccountedFile, AccountedInode, CensusCancellation, Identity,
    NamespaceBinding, NodeDiskConfig, extent,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::{File, Metadata, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::PathBuf,
};

pub(super) struct Root {
    pub(super) path: PathBuf,
    // Prepared before the owner is published. std path conversion may allocate
    // for long paths and cannot be used after redb's winning commit header.
    path_c: CString,
    pub(super) file: File,
    pub(super) identity: Identity,
}

impl Root {
    pub(super) fn verify_nonallocating(&self) -> io::Result<()> {
        // lstat observes the preallocated rooted name without acquiring a
        // temporary descriptor whose close could become an untracked outcome.
        let mut observed: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::lstat(self.path_c.as_ptr(), &mut observed) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if observed.st_mode & libc::S_IFMT != libc::S_IFDIR
            || observed.st_mode & 0o077 != 0
            || observed.st_uid != unsafe { libc::geteuid() }
            || Identity(observed.st_dev as u64, observed.st_ino as u64) != self.identity
            || Identity::of(&self.file.metadata()?) != self.identity
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
    pub(super) fn verify(&self) -> Result<()> {
        let metadata = std::fs::symlink_metadata(&self.path)?;
        directory(&metadata)?;
        ensure!(
            Identity::of(&metadata) == self.identity,
            "persistent root was replaced"
        );
        ensure!(
            Identity::of(&self.file.metadata()?) == self.identity,
            "persistent root descriptor changed"
        );
        Ok(())
    }
}

pub(super) fn directory(metadata: &Metadata) -> Result<()> {
    ensure!(metadata.is_dir(), "persistent root is not a directory");
    private(metadata)
}

fn private(metadata: &Metadata) -> Result<()> {
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
        "persistent storage must be private and owned"
    );
    Ok(())
}

pub(super) fn regular(metadata: &Metadata, device: u64) -> Result<()> {
    ensure!(
        metadata.is_file() && metadata.nlink() == 1 && metadata.dev() == device,
        "persistent file is special, hard-linked or on another filesystem"
    );
    private(metadata)
}

pub(super) fn directory_nonallocating(metadata: &Metadata) -> io::Result<()> {
    if !metadata.is_dir() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    private_nonallocating(metadata)
}

pub(super) fn regular_nonallocating(metadata: &Metadata, device: u64) -> io::Result<()> {
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.dev() != device {
        return Err(io::ErrorKind::InvalidData.into());
    }
    private_nonallocating(metadata)
}

fn private_nonallocating(metadata: &Metadata) -> io::Result<()> {
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

pub(super) fn open_roots(config: &NodeDiskConfig) -> Result<BTreeMap<String, Root>> {
    let mut roots = BTreeMap::new();
    let mut device = None;
    for (name, path) in &config.roots {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        directory(&metadata)?;
        let identity = Identity::of(&metadata);
        ensure!(
            device.is_none_or(|device| device == identity.0),
            "one persistent owner requires one filesystem"
        );
        device = Some(identity.0);
        ensure!(
            !roots.values().any(|root: &Root| root.identity == identity),
            "duplicate physical persistent root"
        );
        roots.insert(
            name.clone(),
            Root {
                path: path.clone(),
                path_c: {
                    use std::os::unix::ffi::OsStrExt;
                    CString::new(path.as_os_str().as_bytes())?
                },
                file,
                identity,
            },
        );
    }
    Ok(roots)
}

// Shared ancestor locks conflict with another owner's exclusive root lock in
// either enrollment order. Directory flock support is required, with no fallback.
pub(super) fn lock_roots(roots: &BTreeMap<String, Root>, max_depth: u32) -> Result<Vec<File>> {
    let mut ancestors = Vec::new();
    let parent_name = CString::new("..").unwrap();
    for root in roots.values() {
        let mut current = root.file.try_clone()?;
        let mut reached_root = false;
        for _ in 0..max_depth {
            let parent = open_at(&current, &parent_name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let identity = Identity::of(&parent.metadata()?);
            if identity == Identity::of(&current.metadata()?) {
                reached_root = true;
                break;
            }
            ensure!(
                !roots.values().any(|root| root.identity == identity),
                "persistent roots overlap"
            );
            lock(&parent, libc::LOCK_SH)?;
            current = parent.try_clone()?;
            ancestors.push(parent);
        }
        ensure!(reached_root, "persistent ancestor lock depth exhausted");
    }
    for root in roots.values() {
        lock(&root.file, libc::LOCK_EX)?;
    }
    Ok(ancestors)
}

pub(super) fn lock(file: &File, kind: libc::c_int) -> Result<()> {
    lock_nonallocating(file, kind).context("persistent storage ownership unavailable")
}

pub(super) fn lock_nonallocating(file: &File, kind: libc::c_int) -> io::Result<()> {
    // SAFETY: flock borrows a live descriptor. The owning File retains the lock.
    if unsafe { libc::flock(file.as_raw_fd(), kind | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn open_at(parent: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: parent and name remain live; successful openat creates one owned fd.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Native stream custody remains inside the caller's State/initial-open guard.
/// Cells are used only by this synchronous scan and its stack unwinding; neither
/// a Cell reference nor a native cursor crosses a thread or await boundary.
#[derive(Default)]
pub(super) struct Streams {
    outstanding: std::cell::Cell<u32>,
    first_close_errno: std::cell::Cell<Option<i32>>,
    #[cfg(test)]
    fail_next_close: std::cell::Cell<bool>,
}
impl Streams {
    pub(super) fn outstanding(&self) -> u32 {
        self.outstanding.get()
    }
    pub(super) fn close_errno(&self) -> Option<i32> {
        self.first_close_errno.get()
    }
    pub(super) fn close_error(&self) -> Option<io::Error> {
        self.close_errno().map(io::Error::from_raw_os_error)
    }
}

pub(super) struct Cursor<'a> {
    identity: Identity,
    binding: NamespaceBinding,
    file: File,
    entries: Option<std::ptr::NonNull<libc::DIR>>,
    streams: &'a Streams,
}

impl<'a> Cursor<'a> {
    fn open(
        file: File,
        binding: NamespaceBinding,
        streams: &'a Streams,
        maximum: u32,
    ) -> Result<Self> {
        let next = streams
            .outstanding()
            .checked_add(1)
            .context("census stream count overflow")?;
        ensure!(next <= maximum, "census stream budget exhausted");
        ensure!(
            streams.close_errno().is_none(),
            "uncertain census stream requires process restart"
        );
        let identity = Identity::of(&file.metadata()?);
        // A dup shares offsets. This independent file description is retained
        // until exactly one closedir invocation consumes its native owner.
        let fd = open_at(&file, c".", libc::O_RDONLY | libc::O_DIRECTORY)?.into_raw_fd();
        // SAFETY: fdopendir takes ownership only on success.
        let pointer = unsafe { libc::fdopendir(fd) };
        let Some(entries) = std::ptr::NonNull::new(pointer) else {
            let error = io::Error::last_os_error();
            drop(unsafe { File::from_raw_fd(fd) });
            return Err(error.into());
        };
        // No fallible handoff follows native acquisition before registration.
        streams.outstanding.set(next);
        Ok(Self {
            identity,
            binding,
            file,
            entries: Some(entries),
            streams,
        })
    }

    fn next(&mut self, max_name_bytes: u32) -> Result<Option<CString>> {
        // SAFETY: this cursor alone owns DIR and clears errno to distinguish EOF.
        unsafe { set_errno(0) };
        let item = unsafe { libc::readdir(self.entries.expect("live census stream").as_ptr()) };
        if item.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error.into());
            }
            return Ok(None);
        }
        let name = unsafe { CStr::from_ptr((*item).d_name.as_ptr()) };
        ensure!(
            name.to_bytes().len() <= max_name_bytes as usize,
            "census name budget exhausted"
        );
        Ok(Some(name.to_owned()))
    }

    fn close(&mut self) -> io::Result<()> {
        let Some(pointer) = self.entries.take() else {
            return Ok(());
        };
        // SAFETY: the sole native owner is consumed exactly once, even when
        // closedir reports an uncertain outcome. Never retry this pointer.
        let result = unsafe { libc::closedir(pointer.as_ptr()) };
        let error = (result != 0).then(io::Error::last_os_error);
        #[cfg(test)]
        let error = if self.streams.fail_next_close.replace(false) {
            Some(io::Error::from_raw_os_error(libc::EIO))
        } else {
            error
        };
        if let Some(error) = error {
            // Capture the actual native errno before any other field retires.
            // Every failed close keeps its slot; the first outcome is retained
            // independently of any preceding cancellation/read/identity error.
            if self.streams.close_errno().is_none() {
                self.streams.first_close_errno.set(error.raw_os_error());
            }
            return Err(error);
        }
        self.streams.outstanding.set(self.streams.outstanding() - 1);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
unsafe fn set_errno(value: libc::c_int) {
    unsafe { *libc::__errno_location() = value };
}
#[cfg(target_os = "macos")]
unsafe fn set_errno(value: libc::c_int) {
    unsafe { *libc::__error() = value };
}
impl Drop for Cursor<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[derive(Debug, Default)]
pub(super) struct Totals {
    pub(super) bytes: u64,
    pub(super) pending: u64,
    pub(super) files: u64,
    pub(super) directory_bytes: u64,
    pub(super) directories: u64,
}
struct Scan<'a> {
    counters: Totals,
    accounted: &'a mut super::fixed_map::Map<AccountedInode>,
}
impl std::ops::Deref for Scan<'_> {
    type Target = Totals;
    fn deref(&self) -> &Totals {
        &self.counters
    }
}
impl std::ops::DerefMut for Scan<'_> {
    fn deref_mut(&mut self) -> &mut Totals {
        &mut self.counters
    }
}

/// Typed secondary-close context; the original primary cause remains in the
/// anyhow chain, while this independent native errno remains downcastable.
#[derive(Debug)]
pub(super) struct CensusCloseFailure {
    pub(super) errno: i32,
}
impl std::fmt::Display for CensusCloseFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "census stream close also failed: {}",
            io::Error::from_raw_os_error(self.errno)
        )
    }
}
impl std::error::Error for CensusCloseFailure {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Progress {
    Pending,
    Complete,
    Failed,
}

/// One scan owns one inactive bank and its actual DFS streams across every
/// Pending result. State/registry serialization is retained by the synchronous
/// caller, so no runtime file mutation, bank rebuild or other census overlaps.
struct CensusSession<'a> {
    roots: std::collections::btree_map::Values<'a, String, Root>,
    current_root: Option<&'a Root>,
    stack: Vec<Cursor<'a>>,
    scan: Scan<'a>,
    config: &'a NodeDiskConfig,
    unit: u64,
    cancel: &'a CensusCancellation,
    streams: &'a Streams,
    work: u64,
    whole_work: u64,
    subdirectories: u64,
    progress: Progress,
    failure: Option<anyhow::Error>,
}
impl<'a> CensusSession<'a> {
    fn new(
        roots: &'a BTreeMap<String, Root>,
        config: &'a NodeDiskConfig,
        unit: u64,
        cancel: &'a CensusCancellation,
        accounted: &'a mut super::fixed_map::Map<AccountedInode>,
        streams: &'a Streams,
    ) -> Result<Self> {
        ensure!(
            streams.outstanding() == 0 && streams.close_errno().is_none(),
            "uncertain census streams require process restart"
        );
        ensure!(
            config.census_work_per_step > 0,
            "census step budget is zero"
        );
        let whole_work = config.census_work_bound()?;
        // All stack backing is prepared before the first fdopendir. No stack
        // growth or scan restart occurs when a step exhausts its work budget.
        let mut stack = Vec::new();
        stack.try_reserve_exact(config.max_depth as usize)?;
        Ok(Self {
            roots: roots.values(),
            current_root: None,
            stack,
            scan: Scan {
                counters: Totals::default(),
                accounted,
            },
            config,
            unit,
            cancel,
            streams,
            work: 0,
            whole_work,
            subdirectories: 0,
            progress: Progress::Pending,
            failure: None,
        })
    }
    fn advance(&mut self) -> Progress {
        if self.progress != Progress::Pending {
            return self.progress;
        }
        match self.advance_inner() {
            Ok(progress) => self.progress = progress,
            Err(error) => {
                self.failure = Some(error);
                self.progress = Progress::Failed;
                self.close_all();
                self.scan.accounted.reset();
            }
        }
        self.progress
    }
    fn advance_inner(&mut self) -> Result<Progress> {
        for _ in 0..self.config.census_work_per_step {
            self.cancel.check()?;
            if self.current_root.is_none() {
                let Some(root) = self.roots.next() else {
                    return Ok(Progress::Complete);
                };
                root.verify()?;
                enroll_directory(
                    &mut self.scan,
                    &root.file,
                    NamespaceBinding::root(root.identity),
                    None,
                    self.config.directory_policy,
                )?;
                self.stack.push(Cursor::open(
                    root.file.try_clone()?,
                    NamespaceBinding::root(root.identity),
                    self.streams,
                    self.config.max_depth,
                )?);
                self.current_root = Some(root);
            }
            let root = self.current_root.expect("active census root");
            ensure!(
                self.work < self.whole_work,
                "persistent census geometry work exhausted"
            );
            self.work += 1; // checked whole-job bound includes dots and EOF.
            let current = self.stack.last_mut().expect("active census stack");
            let Some(name) = current.next(self.config.max_name_bytes)? else {
                current.file.sync_all()?;
                verify_enrolled_directory(&self.scan, current)?;
                current.close()?;
                self.stack.pop();
                if self.stack.is_empty() {
                    root.verify()?;
                    self.current_root = None;
                    if self.roots.len() == 0 {
                        self.cancel.check()?;
                        return Ok(Progress::Complete);
                    }
                }
                continue;
            };
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            let parent = current.identity;
            let enrolled = self
                .scan
                .accounted
                .get_mut(&parent)
                .and_then(AccountedInode::directory_mut)
                .expect("enrolled census directory");
            enrolled.children = enrolled
                .children
                .checked_add(1)
                .context("directory child count overflow")?;
            let binding = current.binding.child(&name);
            // Nonblocking open prevents a substituted FIFO from stalling census.
            let child = open_at(&current.file, &name, libc::O_RDONLY | libc::O_NONBLOCK)?;
            let metadata = child.metadata()?;
            ensure!(
                metadata.dev() == root.identity.0,
                "census crossed filesystem"
            );
            if metadata.is_dir() {
                directory(&metadata)?;
                ensure!(
                    self.subdirectories < self.config.max_persistent_subdirectories,
                    "persistent subdirectory cardinality exhausted"
                );
                ensure!(
                    self.stack.len() < self.config.max_depth as usize,
                    "census depth exhausted"
                );
                enroll_directory(
                    &mut self.scan,
                    &child,
                    binding,
                    Some(parent),
                    self.config.directory_policy,
                )?;
                self.subdirectories += 1;
                self.stack.push(Cursor::open(
                    child,
                    binding,
                    self.streams,
                    self.config.max_depth,
                )?);
            } else {
                regular(&metadata, root.identity.0)?;
                ensure!(
                    self.scan.files < self.config.max_persistent_files,
                    "persistent file cardinality exhausted"
                );
                lock(&child, libc::LOCK_EX)?;
                child.sync_all()?;
                let verified = child.metadata()?;
                regular(&verified, root.identity.0)?;
                ensure!(
                    Identity::of(&verified) == Identity::of(&metadata),
                    "census inode changed"
                );
                let (bytes, pending) = extent(&verified, self.unit)?;
                self.scan
                    .accounted
                    .try_reserve(1)
                    .context("reserving census inode metadata")?;
                ensure!(
                    self.scan
                        .accounted
                        .insert(
                            Identity::of(&verified),
                            AccountedInode::File(AccountedFile::durable(
                                binding,
                                bytes,
                                pending,
                                verified.len()
                            ))
                        )
                        .is_none(),
                    "persistent census repeated an enrolled physical inode"
                );
                self.scan.bytes = self
                    .scan
                    .bytes
                    .checked_add(bytes)
                    .context("census extent overflow")?;
                self.scan.pending = self
                    .scan
                    .pending
                    .checked_add(pending)
                    .context("census pending overflow")?;
                self.scan.files = self
                    .scan
                    .files
                    .checked_add(1)
                    .context("census file count overflow")?;
            }
        }
        Ok(Progress::Pending)
    }
    fn close_all(&mut self) {
        while let Some(mut cursor) = self.stack.pop() {
            let _ = cursor.close();
        }
    }
    fn finish(mut self) -> Result<Totals> {
        self.close_all();
        if self.progress == Progress::Pending {
            self.progress = Progress::Failed;
            self.failure = Some(anyhow::anyhow!("persistent census is incomplete"));
        }
        match (self.failure.take(), self.streams.close_error()) {
            (Some(error), Some(close)) => Err(error.context(CensusCloseFailure {
                errno: close.raw_os_error().expect("native close errno"),
            })),
            (Some(error), None) => Err(error),
            (None, Some(close)) => {
                self.progress = Progress::Failed;
                Err(close.into())
            }
            (None, None) => Ok(std::mem::take(&mut self.scan.counters)),
        }
    }
}
impl Drop for CensusSession<'_> {
    fn drop(&mut self) {
        self.close_all();
        // Error/cancellation/unwind never leaves a partial candidate available
        // for publication. This does not retire either bank's funded backing.
        if self.progress != Progress::Complete {
            self.scan.accounted.reset();
        }
    }
}

pub(super) fn census(
    roots: &BTreeMap<String, Root>,
    config: &NodeDiskConfig,
    unit: u64,
    cancel: &CensusCancellation,
    accounted: &mut super::fixed_map::Map<AccountedInode>,
    streams: &Streams,
) -> Result<Totals> {
    let mut session = CensusSession::new(roots, config, unit, cancel, accounted, streams)?;
    while session.advance() == Progress::Pending {
        // Internal synchronous progress only. Guards and native streams remain
        // owned here; yielding does not promise an async scheduler/cancellation API.
        std::thread::yield_now();
    }
    session.finish()
}

// Directories are not sparse regular files: st_size is a namespace value, not
// an admitted logical byte reservation. Charge observed allocation exactly.
pub(super) fn directory_extent(metadata: &Metadata) -> io::Result<u64> {
    metadata
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| io::ErrorKind::InvalidData.into())
}

fn enroll_directory(
    totals: &mut Scan<'_>,
    file: &File,
    binding: NamespaceBinding,
    parent: Option<Identity>,
    policy: super::DirectoryPolicy,
) -> Result<()> {
    let metadata = file.metadata()?;
    directory(&metadata)?;
    let identity = Identity::of(&metadata);
    let observed = directory_extent(&metadata)?;
    let bytes = policy.extent_bytes.max(observed);
    let pending = bytes - observed;
    let next_bytes = totals
        .bytes
        .checked_add(bytes)
        .context("directory extent overflow")?;
    let next_directories = totals
        .directory_bytes
        .checked_add(observed)
        .context("directory extent overflow")?;
    totals
        .accounted
        .try_reserve(1)
        .context("reserving census directory metadata")?;
    ensure!(
        totals
            .accounted
            .insert(
                identity,
                AccountedInode::Directory(AccountedDirectory {
                    binding,
                    parent,
                    bytes,
                    pending,
                    settled: true,
                    len: metadata.len(),
                    children: 0,
                    live_handles: 0,
                })
            )
            .is_none(),
        "persistent census repeated an enrolled directory"
    );
    totals.directories = totals
        .directories
        .checked_add(1)
        .context("census directory count overflow")?;
    totals.pending = totals
        .pending
        .checked_add(pending)
        .context("directory promises overflow")?;
    totals.bytes = next_bytes;
    totals.directory_bytes = next_directories;
    Ok(())
}

fn verify_enrolled_directory(totals: &Scan<'_>, cursor: &Cursor<'_>) -> Result<()> {
    let metadata = cursor.file.metadata()?;
    directory(&metadata)?;
    let enrolled = totals
        .accounted
        .get(&cursor.identity)
        .and_then(AccountedInode::directory)
        .context("census directory missing")?;
    ensure!(
        Identity::of(&metadata) == cursor.identity
            && metadata.len() == enrolled.len
            && directory_extent(&metadata)?
                == enrolled
                    .bytes
                    .checked_sub(enrolled.pending)
                    .context("invalid directory promise")?,
        "directory changed during persistent census"
    );
    Ok(())
}

#[cfg(test)]
#[path = "census/tests.rs"]
mod tests;
