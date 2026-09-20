use super::{
    AccountedFile, DiskWork, Identity, NamespaceBinding, NodeDisk, NodeDiskPhase, State, census,
    extent, rounded,
};
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

struct Budget {
    file: Option<File>,
    bytes: u64,
    pending: u64,
    reserved_len: u64,
    actual_len: u64,
    settled: bool,
}

impl Budget {
    fn accounted(&self, binding: NamespaceBinding) -> AccountedFile {
        AccountedFile {
            binding,
            bytes: self.bytes,
            pending: self.pending,
            actual_len: self.actual_len,
            reserved_len: self.reserved_len,
            settled: self.settled,
        }
    }
}

pub(super) struct FileOwner {
    disk: Arc<NodeDisk>,
    root: String,
    relative: PathBuf,
    // Parent path names are validated and allocated once during acquisition.
    // I/O verifies every current ancestor using these original names.
    parent_names: Box<[CString]>,
    parent: File,
    name: CString,
    identity: Identity,
    binding: NamespaceBinding,
    budget: Mutex<Budget>,
}

#[cfg(test)]
pub(super) struct ClosePause {
    pub(super) entered: std::sync::mpsc::Sender<()>,
    pub(super) release: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ShrinkFailure {
    Truncate,
    FileSync,
    DirectorySync,
}

/// An opaque descriptor owner. There is no raw File/fd escape: every clone keeps
/// the registration live, and mutation validates the physical path binding.
#[derive(Clone)]
pub struct NodeDiskFile(Arc<FileOwner>);

impl std::fmt::Debug for NodeDiskFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeDiskFile")
            .field("root", &self.0.root)
            .field("relative", &self.0.relative)
            .field("identity", &self.0.identity)
            .finish_non_exhaustive()
    }
}

// Preparation owns all heap storage before a file can become visible. The Arc
// remains uninitialized on error, so provisional cleanup cannot run the live
// owner's registration destructor while the state mutex is held.
pub(super) struct PreparedFile<'a> {
    disk: &'a Arc<NodeDisk>,
    state: std::sync::MutexGuard<'a, State>,
    allocation: Arc<std::mem::MaybeUninit<FileOwner>>,
    root: String,
    relative: PathBuf,
    parent_names: Box<[CString]>,
    parent: File,
    name: CString,
    device: u64,
    binding: NamespaceBinding,
    create: bool,
    budget: Mutex<Budget>,
}

impl PreparedFile<'_> {
    pub(super) fn execute(mut self) -> io::Result<NodeDiskFile> {
        if self.create {
            let result = verify_parent(
                &self.disk.roots[&self.root],
                &self.parent_names,
                &self.parent,
            )
            .and_then(|()| {
                require_unenrolled_target(
                    &self.state,
                    self.binding,
                    &self.parent,
                    &self.name,
                    self.device,
                    self.disk.unit,
                )
            });
            if let Err(error) = result {
                if error.kind() != io::ErrorKind::AlreadyExists {
                    self.disk.fail_locked(&mut self.state);
                }
                return Err(error);
            }
        }
        let flags = libc::O_RDWR
            | libc::O_NONBLOCK
            | if self.create {
                libc::O_CREAT | libc::O_EXCL
            } else {
                0
            };
        let file = match census::open_at(&self.parent, &self.name, flags) {
            Ok(file) => file,
            Err(error) => {
                // An absent final leaf is harmless only if its complete name
                // was never enrolled and the prepared parent is still rooted.
                if !self.create
                    && error.kind() == io::ErrorKind::NotFound
                    && !self
                        .state
                        .accounted
                        .values()
                        .any(|entry| entry.binding == self.binding)
                {
                    if let Err(error) = verify_parent(
                        &self.disk.roots[&self.root],
                        &self.parent_names,
                        &self.parent,
                    ) {
                        self.disk.fail_locked(&mut self.state);
                        return Err(error);
                    }
                    return Err(error);
                }
                // A create-only conflict did not mutate the existing object.
                if !self.create || error.kind() != io::ErrorKind::AlreadyExists {
                    self.disk.fail_locked(&mut self.state);
                }
                return Err(error);
            }
        };
        let mut already_owned = false;
        let inspected = (|| -> io::Result<(Identity, AccountedFile)> {
            let metadata = file.metadata()?;
            census::regular_nonallocating(&metadata, self.device)?;
            let identity = Identity::of(&metadata);
            // A live inode under a different enrolled name is substitution,
            // never a harmless second open of its retained descriptor.
            if !self.create
                && self
                    .state
                    .accounted
                    .get(&identity)
                    .is_some_and(|entry| entry.binding != self.binding)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if self
                .state
                .live
                .get(&identity)
                .is_some_and(|owner| owner.strong_count() != 0)
            {
                // This is an exclusive open, never an implicit owner clone.
                already_owned = true;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            census::lock_nonallocating(&file, libc::LOCK_EX)?;
            let metadata = file.metadata()?;
            census::regular_nonallocating(&metadata, self.device)?;
            if Identity::of(&metadata) != identity {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let (bytes, pending) = extent(&metadata, self.disk.unit)?;
            Ok((
                identity,
                AccountedFile::durable(self.binding, bytes, pending, metadata.len()),
            ))
        })();
        let (identity, enrolled) = match inspected {
            Ok(value) => value,
            Err(error) => {
                // A still-live registered owner makes an attempted second open
                // harmless; all physical verification failures seal admission.
                if !already_owned || self.create {
                    self.disk.fail_locked(&mut self.state);
                }
                return Err(error);
            }
        };
        if self.create {
            if self.state.accounted.contains_key(&identity) || enrolled.bytes != 0 {
                self.disk.fail_locked(&mut self.state);
                return Err(io::ErrorKind::InvalidData.into());
            }
            let Some(files) = self.state.files.checked_add(1) else {
                self.disk.fail_locked(&mut self.state);
                return Err(io::ErrorKind::InvalidData.into());
            };
            // Both tables have reserved capacity. Even this provisional inode
            // survives a failed durability step in the retained census ledger.
            self.state.accounted.insert(
                identity,
                AccountedFile {
                    settled: false,
                    ..enrolled
                },
            );
            self.state.files = files;
            let durable = (|| -> io::Result<()> {
                #[cfg(test)]
                self.disk
                    .namespace_checkpoint(NamespaceFailure::CreateFileSync)?;
                file.sync_all()?;
                #[cfg(test)]
                self.disk
                    .namespace_checkpoint(NamespaceFailure::CreateParentSync)?;
                self.parent.sync_all()
            })();
            if let Err(error) = durable {
                self.disk.fail_locked(&mut self.state);
                return Err(error);
            }
            *self
                .state
                .accounted
                .get_mut(&identity)
                .expect("new enrolled inode") = enrolled;
        } else if self.state.accounted.get(&identity) != Some(&enrolled) {
            self.disk.fail_locked(&mut self.state);
            return Err(io::ErrorKind::InvalidData.into());
        }
        *self.budget.get_mut().expect("unpublished budget") = Budget {
            file: Some(file),
            bytes: enrolled.bytes,
            pending: enrolled.pending,
            reserved_len: enrolled.reserved_len,
            actual_len: enrolled.actual_len,
            settled: true,
        };
        Arc::get_mut(&mut self.allocation)
            .expect("unpublished owner allocation")
            .write(FileOwner {
                disk: self.disk.clone(),
                root: self.root,
                relative: self.relative,
                parent_names: self.parent_names,
                parent: self.parent,
                name: self.name,
                identity,
                binding: self.binding,
                budget: self.budget,
            });
        // SAFETY: the sole allocation was initialized exactly once above. No
        // fallible work remains between initialization and live registration.
        let owner = unsafe { self.allocation.assume_init() };
        self.state.open_files += 1;
        self.state.live.insert(identity, Arc::downgrade(&owner));
        Ok(NodeDiskFile(owner))
    }
}

// Keep the state guard before the registered Arc: abandoning prepared work must
// unlock the registry before FileOwner::drop can retire the actual descriptor.
pub(super) struct PreparedPublication<'a> {
    disk: &'a Arc<NodeDisk>,
    state: std::sync::MutexGuard<'a, State>,
    retained: Arc<FileOwner>,
    parent: File,
    name: CString,
    root: String,
    relative: PathBuf,
    parent_names: Box<[CString]>,
    binding: NamespaceBinding,
}

impl PreparedPublication<'_> {
    pub(super) fn execute(self) -> io::Result<NodeDiskFile> {
        let Self {
            disk,
            mut state,
            mut retained,
            parent,
            name,
            root,
            relative,
            parent_names,
            binding,
        } = self;
        let mut renamed = false;
        let result = (|| -> io::Result<()> {
            let owner = Arc::get_mut(&mut retained).expect("sole prepared publication owner");
            if state.phase != NodeDiskPhase::Open || !disk.device.lock().admission_ready() {
                return Err(io::ErrorKind::Other.into());
            }
            {
                let budget = owner
                    .budget
                    .lock()
                    .map_err(|_| io::ErrorKind::InvalidData)?;
                owner.check_enrollment(&mut state, &budget)?;
                if !budget.settled {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let actual = budget.file.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
                owner.verify(actual)?;
                let metadata = actual.metadata()?;
                let (bytes, pending) = extent(&metadata, disk.unit)?;
                if AccountedFile::durable(owner.binding, bytes, pending, metadata.len())
                    != budget.accounted(owner.binding)
                {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                actual.sync_all()?;
            }
            verify_parent(&disk.roots[&root], &parent_names, &parent)?;
            require_unenrolled_target(
                &state,
                binding,
                &parent,
                &name,
                owner.identity.0,
                disk.unit,
            )?;
            #[cfg(target_os = "linux")]
            let status = unsafe {
                libc::renameat2(
                    owner.parent.as_raw_fd(),
                    owner.name.as_ptr(),
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            #[cfg(target_os = "macos")]
            let status = unsafe {
                libc::renameatx_np(
                    owner.parent.as_raw_fd(),
                    owner.name.as_ptr(),
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            if status != 0 {
                return Err(io::Error::last_os_error());
            }
            renamed = true;
            let old_parent = std::mem::replace(&mut owner.parent, parent);
            owner.root = root;
            owner.relative = relative;
            owner.parent_names = parent_names;
            owner.name = name;
            owner.binding = binding;
            // The source name stopped owning this inode at the rename. Update
            // the retained slot before any fallible durability step.
            state
                .accounted
                .get_mut(&owner.identity)
                .expect("validated publication enrollment")
                .binding = binding;
            // The descriptor now belongs to the new name even if durability or
            // post-publication verification fails. Every error remains inline.
            #[cfg(test)]
            disk.namespace_checkpoint(NamespaceFailure::PublishSourceSync)?;
            old_parent.sync_all()?;
            #[cfg(test)]
            disk.namespace_checkpoint(NamespaceFailure::PublishDestinationSync)?;
            owner.parent.sync_all()?;
            #[cfg(test)]
            disk.namespace_checkpoint(NamespaceFailure::PublishVerify)?;
            let budget = owner
                .budget
                .lock()
                .expect("exclusive verified publication budget");
            let actual = budget.file.as_ref().expect("live publication descriptor");
            owner.verify(actual)?;
            let metadata = actual.metadata()?;
            let (bytes, pending) = extent(&metadata, disk.unit)?;
            if AccountedFile::durable(owner.binding, bytes, pending, metadata.len())
                != budget.accounted(owner.binding)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(())
        })();
        if let Err(error) = result {
            if renamed || error.kind() != io::ErrorKind::AlreadyExists {
                disk.fail_locked(&mut state);
            }
            drop(state);
            drop(retained);
            return Err(error);
        }
        *state
            .live
            .get_mut(&retained.identity)
            .expect("retained publication slot") = Arc::downgrade(&retained);
        drop(state);
        Ok(NodeDiskFile(retained))
    }
}

#[cfg(test)]
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub(super) enum NamespaceFailure {
    CreateFileSync = 1,
    CreateParentSync,
    PublishSourceSync,
    PublishDestinationSync,
    PublishVerify,
    ReclaimFileSync,
    ReclaimParentSync,
}

impl NodeDisk {
    #[cfg(test)]
    fn namespace_checkpoint(&self, stage: NamespaceFailure) -> io::Result<()> {
        use std::sync::atomic::Ordering;
        if self
            .namespace_failure
            .compare_exchange(stage as u8, 0, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Err(io::ErrorKind::Other.into());
        }
        Ok(())
    }

    pub fn open_file(self: &Arc<Self>, root: &str, relative: &Path) -> io::Result<NodeDiskFile> {
        self.prepare_file(root, relative, None)?.execute()
    }

    pub fn create_file(
        self: &Arc<Self>,
        root: &str,
        relative: &Path,
        work: DiskWork,
    ) -> io::Result<NodeDiskFile> {
        self.prepare_file(root, relative, Some(work))?.execute()
    }

    pub(super) fn prepare_file<'a>(
        self: &'a Arc<Self>,
        root: &str,
        relative: &Path,
        create: Option<DiskWork>,
    ) -> io::Result<PreparedFile<'a>> {
        let mut state = self.lock_state();
        if state.phase != NodeDiskPhase::Open {
            return Err(io::ErrorKind::Other.into());
        }
        state.live.retain(|_, owner| owner.strong_count() != 0);
        if state.open_files >= self.config.max_open_files {
            return Err(io::ErrorKind::StorageFull.into());
        }
        if let Some(work) = create {
            if state.accounted.len() as u64 >= self.config.max_census_entries {
                return Err(io::ErrorKind::StorageFull.into());
            }
            self.reserve(&mut state, 0, work)?;
            state
                .accounted
                .try_reserve(1)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
        }
        state
            .live
            .try_reserve(1)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let selected = self.roots.get(root).ok_or(io::ErrorKind::InvalidInput)?;
        let parent_names = prepare_parent_names(relative, &self.config)?;
        let (parent, name, binding) =
            census::parent(selected, relative, &self.config).map_err(|error| {
                self.fail_locked(&mut state);
                // Path preparation precedes every physical create/publication.
                io::Error::other(error)
            })?;
        let budget = Mutex::new(Budget {
            file: None,
            bytes: 0,
            pending: 0,
            reserved_len: 0,
            actual_len: 0,
            settled: false,
        });
        // Darwin's native mutex may allocate on first lock. Preparation includes
        // this initialization even when the first real operation is measured.
        drop(budget.lock().expect("unpublished budget"));
        Ok(PreparedFile {
            disk: self,
            state,
            allocation: Arc::<FileOwner>::new_uninit(),
            root: root.to_owned(),
            relative: relative.to_owned(),
            parent_names,
            parent,
            name,
            device: selected.identity.0,
            binding,
            create: create.is_some(),
            budget,
        })
    }

    /// Consume the sole descriptor owner, then unlink and synchronize its exact
    /// parent. An uncertain result keeps all bytes charged and seals admission.
    pub fn delete_file(&self, file: NodeDiskFile) -> io::Result<()> {
        self.reclaim(file, None)
    }

    /// Explicit physical shrink after owner drain. Logical deletion/handle Drop
    /// never invokes this operation and never releases its reservation.
    pub fn shrink_file(&self, file: NodeDiskFile, len: u64) -> io::Result<()> {
        self.reclaim(file, Some(len))
    }

    /// Publish the original inode under an immutable, create-only name. All
    /// allocation precedes rename; errors after publication remain inline.
    pub fn publish_file(
        self: &Arc<Self>,
        file: NodeDiskFile,
        root: &str,
        relative: &Path,
    ) -> io::Result<NodeDiskFile> {
        self.prepare_publication(file, root, relative)?.execute()
    }

    pub(super) fn prepare_publication<'a>(
        self: &'a Arc<Self>,
        file: NodeDiskFile,
        root: &str,
        relative: &Path,
    ) -> io::Result<PreparedPublication<'a>> {
        if !Arc::ptr_eq(self, &file.0.disk) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let selected = self.roots.get(root).ok_or(io::ErrorKind::InvalidInput)?;
        // Hold admission through physical path validation. On preparation
        // failure this local guard drops before the input descriptor owner.
        let mut state = self.lock_state();
        let parent_names = prepare_parent_names(relative, &self.config)?;
        let (parent, name, binding) =
            census::parent(selected, relative, &self.config).map_err(|error| {
                self.fail_locked(&mut state);
                io::Error::other(error)
            })?;
        let root = root.to_owned();
        let relative = relative.to_owned();
        let owner = match Arc::try_unwrap(file.0) {
            Ok(owner) => owner,
            Err(owner) => {
                drop(state);
                drop(owner);
                return Err(io::ErrorKind::WouldBlock.into());
            }
        };
        // The old weak slot stays registered under this mutex; moving its value
        // after rename does not allocate or admit an intervening reopen.
        let retained = Arc::new(owner);
        Ok(PreparedPublication {
            disk: self,
            state,
            retained,
            parent,
            name,
            root,
            relative,
            parent_names,
            binding,
        })
    }

    fn reclaim(&self, file: NodeDiskFile, len: Option<u64>) -> io::Result<()> {
        if !std::ptr::eq(self, Arc::as_ptr(&file.0.disk)) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut state = self.lock_state();
        let owner = match Arc::try_unwrap(file.0) {
            Ok(owner) => owner,
            Err(owner) => {
                drop(state);
                drop(owner);
                return Err(io::ErrorKind::WouldBlock.into());
            }
        };
        if owner.budget.is_poisoned()
            || state.phase == NodeDiskPhase::Failed
            || !self.device.lock().admission_ready()
        {
            self.fail_locked(&mut state);
            drop(state);
            drop(owner);
            return Err(io::ErrorKind::Other.into());
        }
        let mut budget = owner
            .budget
            .lock()
            .expect("exclusive unpoisoned file owner");
        if let Err(error) = owner.check_enrollment(&mut state, &budget) {
            drop(budget);
            drop(state);
            drop(owner);
            return Err(error);
        }
        budget.settled = false;
        owner.record_enrollment(&mut state, &budget);
        let actual = budget.file.take().expect("live persistent descriptor");
        let result = (|| -> io::Result<(u64, u64)> {
            owner.verify(&actual)?;
            let current = actual.metadata()?.len();
            if current != budget.actual_len {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if let Some(len) = len {
                if len > current {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                actual.set_len(len)?;
                #[cfg(test)]
                self.namespace_checkpoint(NamespaceFailure::ReclaimFileSync)?;
                actual.sync_all()?;
                owner.verify(&actual)?;
                if actual.metadata()?.len() != len {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                #[cfg(test)]
                self.namespace_checkpoint(NamespaceFailure::ReclaimParentSync)?;
                owner.parent.sync_all()?;
                extent(&actual.metadata()?, self.unit)
            } else {
                actual.sync_all()?;
                if unsafe { libc::unlinkat(owner.parent.as_raw_fd(), owner.name.as_ptr(), 0) } != 0
                {
                    return Err(io::Error::last_os_error());
                }
                #[cfg(test)]
                self.namespace_checkpoint(NamespaceFailure::ReclaimParentSync)?;
                owner.parent.sync_all()?;
                Ok((0, 0))
            }
        })();
        // Close before advertising ownership drain or credit. Even failed
        // reclamation retains its ledger entry and original capacity charge.
        drop(actual);
        state.open_files -= 1;
        state.live.remove(&owner.identity);
        let outcome = match result {
            Ok((bytes, pending)) if bytes <= budget.bytes => {
                let mut promises = self.device.lock();
                let next = promises
                    .checked_sub(budget.pending)
                    .and_then(|n| n.checked_add(pending));
                let own_next = state
                    .pending
                    .checked_sub(budget.pending)
                    .and_then(|n| n.checked_add(pending));
                let owned = state
                    .bytes
                    .checked_sub(budget.bytes)
                    .and_then(|n| n.checked_add(bytes));
                let files = if len.is_none() {
                    state.files.checked_sub(1)
                } else {
                    Some(state.files)
                };
                match (next, own_next, owned, files) {
                    (Some(next), Some(own_next), Some(owned), Some(files)) => {
                        match promises.set_pending(next) {
                            Ok(()) => {
                                state.pending = own_next;
                                state.bytes = owned;
                                state.files = files;
                                if let Some(len) = len {
                                    *state
                                        .accounted
                                        .get_mut(&owner.identity)
                                        .expect("validated reclaimed inode") =
                                        AccountedFile::durable(owner.binding, bytes, pending, len);
                                } else {
                                    state.accounted.remove(&owner.identity);
                                }
                                Ok(())
                            }
                            Err(error) => {
                                state.phase = NodeDiskPhase::Failed;
                                Err(error)
                            }
                        }
                    }
                    _ => {
                        state.phase = NodeDiskPhase::Failed;
                        promises.fail_owner();
                        Err(io::ErrorKind::InvalidData.into())
                    }
                }
            }
            Ok(_) => {
                self.fail_locked(&mut state);
                Err(io::ErrorKind::InvalidData.into())
            }
            Err(error) => {
                self.fail_locked(&mut state);
                Err(error)
            }
        };
        drop(budget);
        drop(owner);
        outcome
    }
}

// Return a conflict only after proving that the retained target still names
// its enrolled inode. A disappeared or substituted target must fence its owner.
fn require_unenrolled_target(
    state: &State,
    binding: NamespaceBinding,
    parent: &File,
    name: &std::ffi::CStr,
    device: u64,
    unit: u64,
) -> io::Result<()> {
    let Some((identity, enrolled)) = state
        .accounted
        .iter()
        .find(|(_, entry)| entry.binding == binding)
    else {
        return Ok(());
    };
    let observed = census::open_at(parent, name, libc::O_RDONLY | libc::O_NONBLOCK)?;
    let metadata = observed.metadata()?;
    census::regular_nonallocating(&metadata, device)?;
    let (bytes, pending) = extent(&metadata, unit)?;
    if Identity::of(&metadata) != *identity
        || metadata.len() != enrolled.actual_len
        || enrolled.actual_len > enrolled.reserved_len
        || bytes > enrolled.bytes
        || (enrolled.settled
            && *enrolled != AccountedFile::durable(binding, bytes, pending, metadata.len()))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // An unsettled live target can retain unused growth promises or contain
    // admitted writes not yet reflected in pending physical materialization.
    // Verify its exact known EOF and full allowance without releasing credit.
    Err(io::ErrorKind::AlreadyExists.into())
}

fn verify_parent(root: &census::Root, names: &[CString], retained: &File) -> io::Result<()> {
    root.verify_nonallocating()?;
    let mut current = root.file.try_clone()?;
    for name in names {
        let child = census::open_at(&current, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let metadata = child.metadata()?;
        census::directory_nonallocating(&metadata)?;
        if metadata.dev() != root.identity.0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        current = child;
    }
    if Identity::of(&current.metadata()?) != Identity::of(&retained.metadata()?) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

fn prepare_parent_names(
    relative: &Path,
    config: &super::NodeDiskConfig,
) -> io::Result<Box<[CString]>> {
    use std::os::unix::ffi::OsStrExt;
    let mut names = Vec::new();
    for component in relative
        .parent()
        .ok_or(io::ErrorKind::InvalidInput)?
        .components()
    {
        if names.len() + 1 >= config.max_depth as usize {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let std::path::Component::Normal(name) = component else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        if name.len() > config.max_name_bytes as usize {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        names.push(CString::new(name.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?);
    }
    Ok(names.into_boxed_slice())
}

impl FileOwner {
    fn check_enrollment(&self, state: &mut State, budget: &Budget) -> io::Result<()> {
        if state.accounted.get(&self.identity) != Some(&budget.accounted(self.binding)) {
            self.disk.fail_locked(state);
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }

    fn record_enrollment(&self, state: &mut State, budget: &Budget) {
        // Every caller validated this existing slot while holding the state
        // mutex, before any physical mutation. Updating it cannot allocate.
        *state
            .accounted
            .get_mut(&self.identity)
            .expect("validated enrolled inode") = budget.accounted(self.binding);
    }

    #[cfg(test)]
    fn shrink_checkpoint(&self, stage: ShrinkFailure) -> io::Result<()> {
        let mut fault = self.disk.shrink_failure.lock().unwrap();
        if *fault == Some(stage) {
            fault.take();
            return Err(io::ErrorKind::Other.into());
        }
        Ok(())
    }

    fn lock_budget(&self) -> io::Result<std::sync::MutexGuard<'_, Budget>> {
        self.budget.lock().map_err(|_| {
            self.disk.fail();
            io::Error::from(io::ErrorKind::InvalidData)
        })
    }
    fn verify(&self, file: &File) -> io::Result<()> {
        verify_parent(
            &self.disk.roots[&self.root],
            &self.parent_names,
            &self.parent,
        )?;
        let observed =
            census::open_at(&self.parent, &self.name, libc::O_RDONLY | libc::O_NONBLOCK)?;
        let metadata = observed.metadata()?;
        census::regular_nonallocating(&metadata, self.identity.0)?;
        if Identity::of(&metadata) != self.identity
            || Identity::of(&file.metadata()?) != self.identity
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }

    fn check(&self, file: &File) -> io::Result<()> {
        self.verify(file).inspect_err(|_| {
            self.disk.fail();
        })
    }

    fn observe(&self, budget: &mut Budget) -> io::Result<()> {
        let file = budget.file.as_ref().expect("live persistent descriptor");
        self.check(file)?;
        let metadata = file.metadata().inspect_err(|_| self.disk.fail())?;
        let (observed, _) = extent(&metadata, self.disk.unit).inspect_err(|_| self.disk.fail())?;
        let extra = observed.saturating_sub(budget.bytes);
        let bytes = budget.bytes.max(observed);
        let allocated = metadata
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        let pending = bytes - allocated;
        let mut state = self.disk.lock_state();
        self.check_enrollment(&mut state, budget)?;
        if state.phase == NodeDiskPhase::Failed || !self.disk.device.lock().admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        let changed_length = metadata.len() != budget.actual_len;
        let mut promises = self.disk.device.lock();
        let Some(next) = promises
            .checked_sub(budget.pending)
            .and_then(|n| n.checked_add(pending))
        else {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        };
        let Some(own_next) = state
            .pending
            .checked_sub(budget.pending)
            .and_then(|n| n.checked_add(pending))
        else {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        };
        let Some(owned) = state.bytes.checked_add(extra) else {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        };
        promises
            .set_pending(next)
            .inspect_err(|_| state.phase = NodeDiskPhase::Failed)?;
        state.pending = own_next;
        state.bytes = owned;
        budget.bytes = bytes;
        budget.pending = pending;
        // Sync cannot convert an unused reservation into a physically present
        // extent. Closing it still requires a stopped, exclusive reconciliation.
        budget.settled = metadata.len() == budget.reserved_len && !changed_length;
        budget.actual_len = metadata.len();
        self.record_enrollment(&mut state, budget);
        if extra != 0 || metadata.len() > budget.reserved_len || changed_length {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        Ok(())
    }
}

impl NodeDiskFile {
    /// The installed redb adapter uses this before every physical operation.
    /// Failure is represented without allocating an error payload.
    pub fn check_owner(&self) -> io::Result<()> {
        let budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
        self.0.check(file)?;
        let mut state = self.0.disk.lock_state();
        self.0.check_enrollment(&mut state, &budget)?;
        if file
            .metadata()
            .inspect_err(|_| self.0.disk.fail_locked(&mut state))?
            .len()
            != budget.actual_len
        {
            self.0.disk.fail_locked(&mut state);
            return Err(io::ErrorKind::InvalidData.into());
        }
        if state.phase == NodeDiskPhase::Failed || !self.0.disk.device.lock().admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        Ok(())
    }

    /// Latch uncertain backend activity without allocating or forgetting extent
    /// charges. Only a complete census after actual owner drain may reopen it.
    pub fn owner_failed(&self) {
        self.0.disk.fail();
    }

    /// Settle unused pre-I/O promises after a commit or aborted transaction.
    /// Sync and verify the exact descriptor before crediting only the difference
    /// between its retained reservation and its actual durable extent. This is
    /// valid with live redb readers because no physical byte is removed.
    pub fn settle_growth(&self, actual_len: u64) -> io::Result<()> {
        let mut budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
        let mut state = self.0.disk.lock_state();
        if state.phase == NodeDiskPhase::Failed || !self.0.disk.device.lock().admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        self.0.check_enrollment(&mut state, &budget)?;
        // Serialize the owner seal through physical verification and sync. A
        // previously failed owner must not initiate another backend operation.
        let outcome = (|| -> io::Result<(u64, u64)> {
            self.0.verify(file)?;
            file.sync_all()?;
            self.0.verify(file)?;
            let metadata = file.metadata()?;
            let (bytes, pending) = extent(&metadata, self.0.disk.unit)?;
            if metadata.len() != actual_len
                || actual_len != budget.actual_len
                || actual_len > budget.reserved_len
                || bytes > budget.bytes
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok((bytes, pending))
        })();
        let (bytes, pending) = outcome.inspect_err(|_| self.0.disk.fail_locked(&mut state))?;
        let mut promises = self.0.disk.device.lock();
        let next = promises
            .checked_sub(budget.pending)
            .and_then(|n| n.checked_add(pending));
        let own_next = state
            .pending
            .checked_sub(budget.pending)
            .and_then(|n| n.checked_add(pending));
        let owned = state
            .bytes
            .checked_sub(budget.bytes)
            .and_then(|n| n.checked_add(bytes));
        let (Some(next), Some(own_next), Some(owned)) = (next, own_next, owned) else {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(io::ErrorKind::InvalidData.into());
        };
        if !promises.admission_ready() {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(io::ErrorKind::Other.into());
        }
        promises
            .set_pending(next)
            .inspect_err(|_| state.phase = NodeDiskPhase::Failed)?;
        state.bytes = owned;
        state.pending = own_next;
        budget.bytes = bytes;
        budget.pending = pending;
        budget.reserved_len = actual_len;
        budget.actual_len = actual_len;
        budget.settled = true;
        self.0.record_enrollment(&mut state, &budget);
        Ok(())
    }

    /// Inspect the same physical identity used by installation/cleanup journals.
    /// The value grants no descriptor access or ownership; this handle retains
    /// the exclusive lock, and every observation verifies the installed binding.
    pub fn identity(&self) -> io::Result<crate::private_files::FileIdentity> {
        let budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().expect("live persistent descriptor");
        self.0.check(file)?;
        let identity = crate::private_files::descriptor_identity(file).map_err(|error| {
            self.0.disk.fail();
            io::Error::other(error)
        })?;
        self.0.check(file)?;
        Ok(identity)
    }

    /// Truncate a settled file while retaining its exact descriptor and lock.
    /// The mutable handle must be the sole owner: all cloned readers/backends
    /// must have drained first. Unused or unsynchronized growth cannot be
    /// reclaimed by this operation. Only verified durable shrink credits bytes;
    /// uncertainty retains all prior charges and seals shared device admission.
    pub fn shrink(&mut self, len: u64) -> io::Result<()> {
        let owner = &self.0;
        let mut state = owner.disk.lock_state();
        if Arc::strong_count(owner) != 1 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        if state.phase == NodeDiskPhase::Failed || !owner.disk.device.lock().admission_ready() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        // Exclusive &mut plus the sole Arc and registration mutex guarantee
        // that no other file operation can wait for this budget while holding
        // an older reference. General file I/O takes budget before disk state.
        let mut budget = match owner.budget.lock() {
            Ok(budget) => budget,
            Err(_) => {
                owner.disk.fail_locked(&mut state);
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
        };
        owner.check_enrollment(&mut state, &budget)?;
        if !budget.settled {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let file = budget.file.as_ref().expect("live persistent descriptor");
        let current = match owner.verify(file).and_then(|()| Ok(file.metadata()?.len())) {
            Ok(current) => current,
            Err(error) => {
                budget.settled = false;
                owner.record_enrollment(&mut state, &budget);
                owner.disk.fail_locked(&mut state);
                return Err(error);
            }
        };
        if current != budget.reserved_len || current != budget.actual_len {
            budget.settled = false;
            owner.record_enrollment(&mut state, &budget);
            owner.disk.fail_locked(&mut state);
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        if len > current {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        // From the first physical operation onward every error is uncertain.
        // Keep the previous budget until both syncs and exact observations pass.
        budget.settled = false;
        owner.record_enrollment(&mut state, &budget);
        let outcome = (|| -> io::Result<(u64, u64)> {
            let file = budget.file.as_ref().expect("live persistent descriptor");
            #[cfg(test)]
            owner.shrink_checkpoint(ShrinkFailure::Truncate)?;
            file.set_len(len)?;
            #[cfg(test)]
            owner.shrink_checkpoint(ShrinkFailure::FileSync)?;
            file.sync_all()?;
            owner.verify(file)?;
            if file.metadata()?.len() != len {
                return Err(io::ErrorKind::InvalidData.into());
            }
            #[cfg(test)]
            owner.shrink_checkpoint(ShrinkFailure::DirectorySync)?;
            owner.parent.sync_all()?;
            // A new path observation after directory sync must still identify
            // the same physical file before any capacity is released.
            owner.verify(file)?;
            let metadata = file.metadata()?;
            if metadata.len() != len {
                return Err(io::ErrorKind::InvalidData.into());
            }
            extent(&metadata, owner.disk.unit)
        })();
        let (bytes, pending) = match outcome {
            Ok((bytes, pending)) if bytes <= budget.bytes => (bytes, pending),
            Ok(_) => {
                owner.disk.fail_locked(&mut state);
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            Err(error) => {
                owner.disk.fail_locked(&mut state);
                return Err(error);
            }
        };
        let mut promises = owner.disk.device.lock();
        let next = promises
            .checked_sub(budget.pending)
            .and_then(|n| n.checked_add(pending));
        let own_next = state
            .pending
            .checked_sub(budget.pending)
            .and_then(|n| n.checked_add(pending));
        let owned = state
            .bytes
            .checked_sub(budget.bytes)
            .and_then(|n| n.checked_add(bytes));
        let (Some(next), Some(own_next), Some(owned)) = (next, own_next, owned) else {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        };
        if !promises.admission_ready() {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        if let Err(error) = promises.set_pending(next) {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(error);
        }
        state.bytes = owned;
        state.pending = own_next;
        budget.bytes = bytes;
        budget.pending = pending;
        budget.reserved_len = len;
        budget.actual_len = len;
        budget.settled = true;
        owner.record_enrollment(&mut state, &budget);
        Ok(())
    }

    pub fn observed_len(&self) -> io::Result<u64> {
        let budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().expect("live persistent descriptor");
        self.0.check(file)?;
        Ok(file.metadata().inspect_err(|_| self.0.disk.fail())?.len())
    }

    /// A synchronous, pre-I/O exact growth reservation. Failure never resizes.
    /// Caller must retain this owner through all backend activity and final sync.
    pub fn reserve_growth(
        &self,
        current_len: u64,
        requested_len: u64,
        work: DiskWork,
    ) -> io::Result<()> {
        let mut budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().expect("live persistent descriptor");
        self.0.check(file)?;
        let actual = file.metadata().inspect_err(|_| self.0.disk.fail())?;
        if actual.len() != current_len
            || current_len != budget.actual_len
            || requested_len < current_len
        {
            self.0.disk.fail();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let bytes = rounded(requested_len, self.0.disk.unit)?;
        let delta = bytes.saturating_sub(budget.bytes);
        let mut state = self.0.disk.lock_state();
        self.0.check_enrollment(&mut state, &budget)?;
        self.0.disk.reserve(&mut state, delta, work)?;
        budget.bytes += delta;
        budget.pending += delta;
        budget.reserved_len = budget.reserved_len.max(requested_len);
        budget.settled = false;
        self.0.record_enrollment(&mut state, &budget);
        Ok(())
    }

    /// Execute an already admitted extension. Shrink uses the drained-owner API.
    pub fn grow_reserved(&self, len: u64) -> io::Result<()> {
        let mut budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().expect("live persistent descriptor");
        self.0.check(file)?;
        let current = file.metadata().inspect_err(|_| self.0.disk.fail())?.len();
        let mut state = self.0.disk.lock_state();
        if state.phase == NodeDiskPhase::Failed
            || !self.0.disk.device.lock().admission_ready()
            || len < current
            || len > budget.reserved_len
        {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.0.check_enrollment(&mut state, &budget)?;
        if current != budget.actual_len {
            self.0.disk.fail_locked(&mut state);
            return Err(io::ErrorKind::InvalidData.into());
        }
        // Keep the admission seal serialized through the backend call and
        // retain uncertainty even if set_len changes the file before failing.
        budget.settled = false;
        self.0.record_enrollment(&mut state, &budget);
        if let Err(error) = budget.file.as_ref().expect("live descriptor").set_len(len) {
            self.0.disk.fail_locked(&mut state);
            return Err(error);
        }
        budget.actual_len = len;
        budget.settled = false;
        self.0.record_enrollment(&mut state, &budget);
        Ok(())
    }

    pub fn write_all_at(&self, data: &[u8], offset: u64) -> io::Result<()> {
        let mut budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().expect("live persistent descriptor");
        self.0.check(file)?;
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        let mut state = self.0.disk.lock_state();
        if state.phase == NodeDiskPhase::Failed
            || !self.0.disk.device.lock().admission_ready()
            || end > budget.reserved_len
        {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.0.check_enrollment(&mut state, &budget)?;
        if file
            .metadata()
            .inspect_err(|_| self.0.disk.fail_locked(&mut state))?
            .len()
            != budget.actual_len
        {
            self.0.disk.fail_locked(&mut state);
            return Err(io::ErrorKind::InvalidData.into());
        }
        budget.settled = false;
        self.0.record_enrollment(&mut state, &budget);
        if let Err(error) = budget
            .file
            .as_ref()
            .expect("live descriptor")
            .write_all_at(data, offset)
        {
            self.0.disk.fail_locked(&mut state);
            return Err(error);
        }
        if !data.is_empty() {
            budget.actual_len = budget.actual_len.max(end);
        }
        self.0.record_enrollment(&mut state, &budget);
        Ok(())
    }

    pub fn read_exact_at(&self, out: &mut [u8], offset: u64) -> io::Result<()> {
        let budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().expect("live persistent descriptor");
        let mut state = self.0.disk.lock_state();
        if state.phase == NodeDiskPhase::Failed || !self.0.disk.device.lock().admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        self.0.check_enrollment(&mut state, &budget)?;
        let outcome = (|| -> io::Result<()> {
            self.0.verify(file)?;
            if file.metadata()?.len() != budget.actual_len {
                return Err(io::ErrorKind::InvalidData.into());
            }
            file.read_exact_at(out, offset)?;
            self.0.verify(file)
        })();
        outcome.inspect_err(|_| self.0.disk.fail_locked(&mut state))
    }

    /// Verified materialization retires only pending filesystem promises; the
    /// complete persistent extent charge remains after this owner closes.
    pub fn sync_all(&self) -> io::Result<()> {
        let mut budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().expect("live persistent descriptor");
        let mut state = self.0.disk.lock_state();
        if state.phase == NodeDiskPhase::Failed || !self.0.disk.device.lock().admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        self.0.check_enrollment(&mut state, &budget)?;
        let outcome = (|| -> io::Result<()> {
            self.0.verify(file)?;
            if file.metadata()?.len() != budget.actual_len {
                return Err(io::ErrorKind::InvalidData.into());
            }
            file.sync_all()?;
            self.0.verify(file)
        })();
        outcome.inspect_err(|_| self.0.disk.fail_locked(&mut state))?;
        drop(state);
        self.0.observe(&mut budget)
    }

    /// Durably publish an initialized envelope without releasing or reopening
    /// its descriptor. Growth promises settle only after the file, its held
    /// parent and the exact installed binding have all been verified. Failure
    /// keeps existing charges and fences admission until an exclusive census.
    pub fn sync_all_and_parent(&self) -> io::Result<()> {
        let mut budget = self.0.lock_budget()?;
        let mut state = self.0.disk.lock_state();
        if state.phase == NodeDiskPhase::Failed || !self.0.disk.device.lock().admission_ready() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.0.check_enrollment(&mut state, &budget)?;
        budget.settled = false;
        self.0.record_enrollment(&mut state, &budget);
        let file = budget.file.as_ref().expect("live persistent descriptor");
        let outcome = (|| -> io::Result<()> {
            self.0.verify(file)?;
            if file.metadata()?.len() != budget.actual_len {
                return Err(io::ErrorKind::InvalidData.into());
            }
            file.sync_all()?;
            #[cfg(test)]
            if self
                .0
                .disk
                .parent_sync_failure
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return Err(io::ErrorKind::Other.into());
            }
            self.0.parent.sync_all()?;
            self.0.verify(file)
        })();
        if let Err(error) = outcome {
            self.0.disk.fail_locked(&mut state);
            return Err(error);
        }
        drop(state);
        self.0.observe(&mut budget)
    }
}

impl Drop for FileOwner {
    fn drop(&mut self) {
        let this = self as *const Self;
        let budget = self.budget.get_mut().unwrap_or_else(|p| {
            let budget = p.into_inner();
            budget.settled = false;
            budget
        });
        if let Some(file) = budget.file.take() {
            if !budget.settled {
                // Seal before closing the descriptor: a concurrent reopen must
                // not bind a fresh budget while this owner is still uncertain.
                self.disk.fail();
            }
            drop(file);
            #[cfg(test)]
            {
                let pause = self.disk.after_file_close.lock().unwrap().take();
                if let Some(pause) = pause {
                    let _ = pause.entered.send(());
                    pause
                        .release
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .expect("release closed-file fixture");
                }
            }
            let mut state = self.disk.lock_state();
            // This decrement follows actual fd close, not Weak::strong_count.
            state.open_files -= 1;
            if state
                .live
                .get(&self.identity)
                .is_some_and(|entry| entry.as_ptr() == this)
            {
                state.live.remove(&self.identity);
            }
            if !budget.settled {
                if let Some(enrolled) = state.accounted.get_mut(&self.identity) {
                    enrolled.settled = false;
                }
                self.disk.fail_locked(&mut state);
            }
        }
    }
}
