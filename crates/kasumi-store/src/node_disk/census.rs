use super::{
    AccountedDirectory, AccountedFile, AccountedInode, CensusCancellation, Identity,
    MAX_FILESYSTEMS, NamespaceBinding, NodeDiskConfig, file_extent,
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
    // for long paths and cannot be used after the KV engine's winning commit header.
    path_c: CString,
    pub(super) file: File,
    pub(super) identity: Identity,
    /// Index of the filesystem charged for every promise beneath this root.
    pub(super) filesystem: usize,
    pub(super) btrfs_sector: u32,
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

/// Open every configured root and group the roots by filesystem. Each
/// filesystem is one promise and free-space account; the returned devices are
/// in filesystem index order. `assigned` replaces each named root's device
/// number for that grouping only, so fixtures can place roots that share one
/// physical filesystem on distinct accounted devices. The census and every
/// descriptor check still compare the actual device numbers.
pub(super) fn open_roots(
    config: &NodeDiskConfig,
    assigned: Option<&BTreeMap<String, u64>>,
) -> Result<(BTreeMap<String, Root>, Vec<u64>)> {
    let mut roots: BTreeMap<String, Root> = BTreeMap::new();
    let mut devices: Vec<u64> = Vec::new();
    for (name, path) in &config.roots {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("opening persistent root {name} ({})", path.display()))?;
        let metadata = file.metadata()?;
        directory(&metadata)
            .with_context(|| format!("persistent root {name} ({})", path.display()))?;
        let identity = Identity::of(&metadata);
        if let Some((other, _)) = roots.iter().find(|(_, root)| root.identity == identity) {
            anyhow::bail!(
                "persistent roots {other} and {name} ({}) are the same directory",
                path.display()
            );
        }
        let device = match assigned {
            Some(assigned) => *assigned
                .get(name)
                .with_context(|| format!("fixture assigns no device to root {name}"))?,
            None => identity.0,
        };
        let filesystem = match devices.iter().position(|known| *known == device) {
            Some(index) => index,
            None => {
                ensure!(
                    devices.len() < MAX_FILESYSTEMS,
                    "persistent roots span more than {MAX_FILESYSTEMS} filesystems; \
                     root {name} ({}) would add another",
                    path.display()
                );
                devices.push(device);
                devices.len() - 1
            }
        };
        roots.insert(
            name.clone(),
            Root {
                path: path.clone(),
                path_c: {
                    use std::os::unix::ffi::OsStrExt;
                    CString::new(path.as_os_str().as_bytes())?
                },
                btrfs_sector: btrfs_sector(&file)?,
                file,
                identity,
                filesystem,
            },
        );
    }
    Ok((roots, devices))
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
            if let Some(outer) = roots.values().find(|outer| outer.identity == identity) {
                anyhow::bail!(
                    "persistent root {} is inside persistent root {}; roots may not nest, even \
                     across a mount point. Mount another filesystem outside every persistent \
                     root and install that directory as its own root",
                    root.path.display(),
                    outer.path.display()
                );
            }
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
    namespace_times: [i64; 4],
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
        let metadata = file.metadata()?;
        let identity = Identity::of(&metadata);
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
            namespace_times: namespace_times(&metadata),
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
    /// `pending` split by the filesystem of each enrolled inode's root.
    pub(super) filesystem_pending: [u64; MAX_FILESYSTEMS],
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
                    root.btrfs_sector,
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
                settle_directory(
                    &mut self.scan,
                    current,
                    self.config.directory_policy,
                    root.filesystem,
                )?;
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
                "persistent root {} holds {:?} on another filesystem (device {}, root device {}); \
                 a root is one filesystem. Mount the other filesystem outside every persistent \
                 root and install that directory as its own root",
                root.path.display(),
                name,
                metadata.dev(),
                root.identity.0
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
                    root.btrfs_sector,
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
                let (bytes, pending) =
                    file_extent(&verified, self.unit, self.config.file_allocation_policy)?;
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
                let filesystem = &mut self.scan.filesystem_pending[root.filesystem];
                *filesystem = filesystem
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

// Btrfs can report one sector for a synchronized directory and zero after
// inode-cache reclaim without changing its namespace. The sector cannot
// retire any of the filesystem promise: its disappearance is asynchronous.
#[cfg(target_os = "linux")]
fn btrfs_sector(file: &File) -> io::Result<u32> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs initializes the structure on success and borrows the FD.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    if stat.f_type != libc::BTRFS_SUPER_MAGIC {
        return Ok(0);
    }
    u32::try_from(stat.f_bsize)
        .ok()
        .filter(|size| size.is_power_of_two())
        .ok_or_else(|| io::ErrorKind::InvalidData.into())
}

#[cfg(not(target_os = "linux"))]
fn btrfs_sector(_file: &File) -> io::Result<u32> {
    Ok(0)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct DirectoryAllocation {
    pub(super) reported: u64,
    pub(super) btrfs_sector: u32,
    changed_seconds: i64,
    changed_nanos: u32,
}

impl DirectoryAllocation {
    pub(super) fn observe(metadata: &Metadata, btrfs_sector: u32) -> io::Result<Self> {
        let mut observation = Self {
            reported: directory_extent(metadata)?,
            btrfs_sector,
            ..Self::default()
        };
        if btrfs_sector != 0 {
            observation.changed_seconds = metadata.ctime();
            observation.changed_nanos =
                u32::try_from(metadata.ctime_nsec()).map_err(|_| io::ErrorKind::InvalidData)?;
        }
        Ok(observation)
    }

    pub(super) fn backed(self) -> u64 {
        if self.reported == u64::from(self.btrfs_sector) {
            0
        } else {
            self.reported
        }
    }

    pub(super) fn matches(self, metadata: &Metadata, charged: u64) -> io::Result<bool> {
        Ok(self.accepts(Self::observe(metadata, self.btrfs_sector)?, charged))
    }

    fn accepts(self, current: Self, charged: u64) -> bool {
        current.btrfs_sector == self.btrfs_sector
            && self.changed_seconds == current.changed_seconds
            && self.changed_nanos == current.changed_nanos
            && current.reported <= charged
            && current.backed() == self.backed()
    }
}

#[cfg(test)]
pub(super) fn backed_directory_bytes(path: &std::path::Path) -> u64 {
    let directory = File::open(path).unwrap();
    let observed = directory.metadata().unwrap().blocks() * 512;
    if observed == u64::from(btrfs_sector(&directory).unwrap()) {
        0
    } else {
        observed
    }
}

fn namespace_times(metadata: &Metadata) -> [i64; 4] {
    [
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    ]
}

fn enroll_directory(
    totals: &mut Scan<'_>,
    file: &File,
    binding: NamespaceBinding,
    parent: Option<Identity>,
    btrfs_sector: u32,
) -> Result<()> {
    let metadata = file.metadata()?;
    directory(&metadata)?;
    let identity = Identity::of(&metadata);
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
                    bytes: 0,
                    pending: 0,
                    allocation: DirectoryAllocation::observe(&metadata, btrfs_sector)?,
                    settled: false,
                    len: metadata.len(),
                    children: 0,
                    live_handles: 0,
                    transaction_children: 0,
                    transaction_claimed: false,
                    membership_generation: 0,
                })
            )
            .is_none(),
        "persistent census repeated an enrolled directory"
    );
    totals.directories = totals
        .directories
        .checked_add(1)
        .context("census directory count overflow")?;
    Ok(())
}

// Enumeration and fsync can settle directory blocks even when no entry
// changes (including an empty Btrfs directory). Charge the final descriptor
// metadata once, before the scan can publish its inactive accounting bank.
fn settle_directory(
    totals: &mut Scan<'_>,
    cursor: &Cursor<'_>,
    policy: super::DirectoryPolicy,
    filesystem: usize,
) -> Result<()> {
    let metadata = cursor.file.metadata()?;
    directory(&metadata)?;
    let enrolled = totals
        .accounted
        .get_mut(&cursor.identity)
        .and_then(AccountedInode::directory_mut)
        .context("census directory missing")?;
    ensure!(
        Identity::of(&metadata) == cursor.identity
            && metadata.len() == enrolled.len
            && namespace_times(&metadata) == cursor.namespace_times,
        "directory changed during persistent census"
    );
    enrolled.allocation =
        DirectoryAllocation::observe(&metadata, enrolled.allocation.btrfs_sector)?;
    let observed = enrolled.allocation.reported;
    let bytes = policy.extent_bytes.max(observed);
    let pending = bytes - enrolled.allocation.backed();
    enrolled.bytes = bytes;
    enrolled.pending = pending;
    enrolled.settled = true;
    let next_bytes = totals
        .bytes
        .checked_add(bytes)
        .context("directory extent overflow")?;
    let next_directories = totals
        .directory_bytes
        .checked_add(observed)
        .context("directory extent overflow")?;
    totals.pending = totals
        .pending
        .checked_add(pending)
        .context("directory promises overflow")?;
    let promised = &mut totals.filesystem_pending[filesystem];
    *promised = promised
        .checked_add(pending)
        .context("directory promises overflow")?;
    totals.bytes = next_bytes;
    totals.directory_bytes = next_directories;
    Ok(())
}

#[cfg(test)]
#[path = "census/tests.rs"]
mod tests;
