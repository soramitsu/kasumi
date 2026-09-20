use super::{
    AccountedFile, CensusCancellation, Identity, NamespaceBinding, NodeDiskConfig, extent,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, HashMap},
    ffi::{CStr, CString},
    fs::{File, Metadata, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
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
        // SAFETY: the prepared NUL-terminated path remains live; ownership of a
        // successful descriptor transfers immediately into File.
        let fd = unsafe {
            libc::open(
                self.path_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let observed = unsafe { File::from_raw_fd(fd) };
        let metadata = observed.metadata()?;
        directory_nonallocating(&metadata)?;
        if Identity::of(&metadata) != self.identity
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

pub(super) fn parent(
    root: &Root,
    relative: &Path,
    config: &NodeDiskConfig,
) -> Result<(File, CString, NamespaceBinding)> {
    root.verify()?;
    let mut components = relative.components().peekable();
    let mut directory_fd = root.file.try_clone()?;
    let mut depth = 0_u32;
    let mut binding = NamespaceBinding::root(root.identity);
    while let Some(component) = components.next() {
        depth = depth
            .checked_add(1)
            .context("persistent path depth overflow")?;
        ensure!(depth <= config.max_depth, "persistent path depth exhausted");
        let Component::Normal(name) = component else {
            anyhow::bail!("persistent paths must be relative normal components");
        };
        use std::os::unix::ffi::OsStrExt;
        ensure!(
            name.len() <= config.max_name_bytes as usize,
            "persistent name exceeds budget"
        );
        let name = CString::new(name.as_bytes())?;
        binding = binding.child(&name);
        if components.peek().is_none() {
            return Ok((directory_fd, name, binding));
        }
        let child = open_at(&directory_fd, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let metadata = child.metadata()?;
        directory(&metadata)?;
        ensure!(
            metadata.dev() == root.identity.0,
            "persistent directory crossed filesystem"
        );
        directory_fd = child;
    }
    anyhow::bail!("persistent file path is empty")
}

struct Cursor {
    binding: NamespaceBinding,
    file: File,
    entries: *mut libc::DIR,
}

impl Cursor {
    fn open(file: File, binding: NamespaceBinding) -> Result<Self> {
        // A dup shares the directory offset and would make a later census start
        // at EOF. Open a new file description anchored to this descriptor.
        let fd = open_at(&file, c".", libc::O_RDONLY | libc::O_DIRECTORY)?.into_raw_fd();
        // SAFETY: fdopendir takes ownership only on success.
        let entries = unsafe { libc::fdopendir(fd) };
        if entries.is_null() {
            let error = io::Error::last_os_error();
            drop(unsafe { File::from_raw_fd(fd) });
            return Err(error.into());
        }
        Ok(Self {
            file,
            entries,
            binding,
        })
    }

    fn next(&mut self, max_name_bytes: u32) -> Result<Option<CString>> {
        // SAFETY: this cursor alone owns DIR and clears errno to distinguish EOF.
        unsafe { set_errno(0) };
        let item = unsafe { libc::readdir(self.entries) };
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
}

#[cfg(target_os = "linux")]
unsafe fn set_errno(value: libc::c_int) {
    unsafe { *libc::__errno_location() = value };
}
#[cfg(target_os = "macos")]
unsafe fn set_errno(value: libc::c_int) {
    unsafe { *libc::__error() = value };
}

impl Drop for Cursor {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.entries) };
    }
}

#[derive(Default)]
pub(super) struct Totals {
    pub(super) bytes: u64,
    pub(super) pending: u64,
    pub(super) files: u64,
    pub(super) accounted: HashMap<Identity, AccountedFile>,
}

pub(super) fn census(
    roots: &BTreeMap<String, Root>,
    config: &NodeDiskConfig,
    unit: u64,
    cancel: &CensusCancellation,
) -> Result<Totals> {
    let mut totals = Totals::default();
    let mut work = 0_u64;
    for root in roots.values() {
        root.verify()?;
        let mut stack = vec![Cursor::open(
            root.file.try_clone()?,
            NamespaceBinding::root(root.identity),
        )?];
        while !stack.is_empty() {
            cancel.check()?;
            let current = stack.last_mut().expect("nonempty census stack");
            let Some(name) = current.next(config.max_name_bytes)? else {
                current.file.sync_all()?;
                stack.pop();
                continue;
            };
            work = work.checked_add(1).context("census work overflow")?;
            ensure!(
                work <= config.max_census_entries,
                "persistent census work exhausted"
            );
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            let binding = current.binding.child(&name);
            // Open nonblocking so a substituted FIFO cannot stall a bounded census.
            let child = open_at(&current.file, &name, libc::O_RDONLY | libc::O_NONBLOCK)?;
            let metadata = child.metadata()?;
            ensure!(
                metadata.dev() == root.identity.0,
                "census crossed filesystem"
            );
            if metadata.is_dir() {
                directory(&metadata)?;
                ensure!(
                    stack.len() < config.max_depth as usize,
                    "census depth exhausted"
                );
                stack.push(Cursor::open(child, binding)?);
            } else {
                regular(&metadata, root.identity.0)?;
                lock(&child, libc::LOCK_EX)?;
                child.sync_all()?;
                let verified = child.metadata()?;
                regular(&verified, root.identity.0)?;
                ensure!(
                    Identity::of(&verified) == Identity::of(&metadata),
                    "census inode changed"
                );
                let (bytes, pending) = extent(&verified, unit)?;
                totals
                    .accounted
                    .try_reserve(1)
                    .context("reserving census inode metadata")?;
                ensure!(
                    totals
                        .accounted
                        .insert(
                            Identity::of(&verified),
                            AccountedFile::durable(binding, bytes, pending, verified.len()),
                        )
                        .is_none(),
                    "persistent census repeated an enrolled physical inode"
                );
                totals.bytes = totals
                    .bytes
                    .checked_add(bytes)
                    .context("census extent overflow")?;
                totals.pending = totals
                    .pending
                    .checked_add(pending)
                    .context("census pending overflow")?;
                totals.files = totals
                    .files
                    .checked_add(1)
                    .context("census file count overflow")?;
            }
        }
        root.verify()?;
    }
    cancel.check()?;
    Ok(totals)
}
