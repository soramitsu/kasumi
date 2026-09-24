//! One admitted, State-retained directory namespace effect.
use super::{DirectoryOwner, NodeDiskDirectory};
use crate::node_disk::{
    AccountedDirectory, AccountedInode, DiskWork, Identity, NamespaceBinding, NodeDisk,
    NodeDiskPhase, State, census,
    namespace::{self, ParentTransition, RetainedParent},
};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io,
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, IntoRawFd},
        unix::fs::MetadataExt,
    },
    sync::Arc,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeDiskDirectoryOperationKind {
    Open,
    Create,
    Remove,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeDiskDirectoryOperationStep {
    Prepared,
    Mkdir,
    OpenChild,
    ObserveChild,
    SyncChild,
    SyncParent,
    Verify,
    Settle,
    Unlink,
    CloseChild,
    CloseParent,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeDiskDirectoryFailure {
    pub step: NodeDiskDirectoryOperationStep,
    pub kind: io::ErrorKind,
    pub errno: Option<i32>,
}
impl NodeDiskDirectoryFailure {
    fn new(step: NodeDiskDirectoryOperationStep, error: &io::Error) -> Self {
        Self {
            step,
            kind: error.kind(),
            errno: error.raw_os_error(),
        }
    }
    fn error(self) -> io::Error {
        self.errno
            .map_or_else(|| self.kind.into(), io::Error::from_raw_os_error)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeDiskDirectoryOperation {
    pub kind: NodeDiskDirectoryOperationKind,
    pub step: NodeDiskDirectoryOperationStep,
    pub failure: Option<NodeDiskDirectoryFailure>,
    pub close_failure: Option<NodeDiskDirectoryFailure>,
    /// Diagnostic only. An uncertain close is never retried using this number.
    pub uncertain_close_descriptor: Option<i32>,
}

// This is inline in State. Its dynamic resources fit the one extra admitted
// directory-owner envelope; no Arc<NodeDisk> cycle or failure-time allocation.
pub(in crate::node_disk) struct PendingDirectory {
    observation: NodeDiskDirectoryOperation,
    root: String,
    names: Box<[CString]>,
    binding: NamespaceBinding,
    parent: RetainedParent,
    child: Option<File>,
    walk_current: Option<File>,
    walk_next: Option<File>,
    identity: Option<Identity>,
    allocation: Option<Arc<MaybeUninit<DirectoryOwner>>>,
    plan: Option<ParentTransition>,
}
impl PendingDirectory {
    pub(in crate::node_disk) fn observed(&self) -> NodeDiskDirectoryOperation {
        self.observation
    }
    fn step(&mut self, step: NodeDiskDirectoryOperationStep) {
        self.observation.step = step;
    }
    fn name(&self) -> &CStr {
        self.names.last().expect("prepared child component")
    }
    fn verify_parent(
        &mut self,
        disk: &NodeDisk,
        ledger: Option<&crate::node_disk::fixed_map::Banks<AccountedInode>>,
    ) -> io::Result<()> {
        let root = &disk.roots[&self.root];
        root.verify_nonallocating()?;
        if let Some(ledger) = ledger {
            verify_enrolled(ledger, root.identity, &root.file.metadata()?)?;
        }
        if self.parent.ancestors().len() != self.names.len()
            || self.parent.ancestors()[0] != root.identity
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        for index in 0..self.names.len() - 1 {
            let current = self.walk_current.as_ref().unwrap_or(&root.file);
            self.walk_next = Some(census::open_at(
                current,
                &self.names[index],
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?);
            let metadata = self
                .walk_next
                .as_ref()
                .expect("retained walk descriptor")
                .metadata()?;
            census::directory_nonallocating(&metadata)?;
            if let Some(ledger) = ledger {
                verify_enrolled(ledger, Identity::of(&metadata), &metadata)?;
            }
            if Identity::of(&metadata) != self.parent.ancestors()[index + 1] {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Self::close_owned(
                self.walk_current.take(),
                NodeDiskDirectoryOperationStep::Verify,
                &mut self.observation,
            )?;
            self.walk_current = self.walk_next.take();
        }
        let current = self.walk_current.as_ref().unwrap_or(&root.file);
        let retained = self.parent.file().metadata()?;
        census::directory_nonallocating(&retained)?;
        if let Some(ledger) = ledger {
            verify_enrolled(ledger, self.parent.identity(), &retained)?;
        }
        if Identity::of(&current.metadata()?) != self.parent.identity()
            || Identity::of(&retained) != self.parent.identity()
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Self::close_owned(
            self.walk_current.take(),
            NodeDiskDirectoryOperationStep::Verify,
            &mut self.observation,
        )
    }
    fn verify_child(&mut self, disk: &NodeDisk) -> io::Result<()> {
        self.verify_parent(disk, None)?;
        let mut observed: libc::stat = unsafe { std::mem::zeroed() };
        // No temporary child FD: inspect the one exact component without
        // following a replacement symlink, then compare the retained owner.
        if unsafe {
            libc::fstatat(
                self.parent.file().as_raw_fd(),
                self.name().as_ptr(),
                &mut observed,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let metadata = self.child.as_ref().expect("retained child").metadata()?;
        census::directory_nonallocating(&metadata)?;
        if observed.st_mode & libc::S_IFMT != libc::S_IFDIR
            || observed.st_mode & 0o077 != 0
            || observed.st_uid != unsafe { libc::geteuid() }
            || Some(Identity(observed.st_dev as u64, observed.st_ino as u64)) != self.identity
            || Some(Identity::of(&metadata)) != self.identity
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
    pub(in crate::node_disk) fn close_resources(&mut self) -> io::Result<()> {
        if let Some(error) = self.observation.close_failure {
            return Err(error.error());
        }
        Self::close_owned(
            self.walk_next.take(),
            NodeDiskDirectoryOperationStep::Verify,
            &mut self.observation,
        )?;
        Self::close_owned(
            self.walk_current.take(),
            NodeDiskDirectoryOperationStep::Verify,
            &mut self.observation,
        )?;
        self.close_one(true)?;
        self.close_one(false)
    }
    fn close_one(&mut self, child: bool) -> io::Result<()> {
        let (file, step) = if child {
            (
                self.child.take(),
                NodeDiskDirectoryOperationStep::CloseChild,
            )
        } else {
            (
                self.parent.take_descriptor(),
                NodeDiskDirectoryOperationStep::CloseParent,
            )
        };
        Self::close_owned(file, step, &mut self.observation)
    }
    fn close_owned(
        file: Option<File>,
        step: NodeDiskDirectoryOperationStep,
        observation: &mut NodeDiskDirectoryOperation,
    ) -> io::Result<()> {
        let Some(file) = file else { return Ok(()) };
        let fd = file.into_raw_fd();
        // Exactly one close consumes the descriptor. A nonzero result is not
        // permission to retry a possibly recycled descriptor or release credit.
        let result = unsafe { libc::close(fd) };
        let result = if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        };
        #[cfg(test)]
        let result = result.and_then(|()| injected(step));
        if let Err(error) = result {
            observation.close_failure = Some(NodeDiskDirectoryFailure::new(step, &error));
            observation.uncertain_close_descriptor = Some(fd);
            return Err(error);
        }
        Ok(())
    }
}

struct Effect<'a> {
    disk: &'a NodeDisk,
    state: &'a mut State,
}
impl std::ops::Deref for Effect<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        self.state
    }
}
impl std::ops::DerefMut for Effect<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.state
    }
}
impl Drop for Effect<'_> {
    fn drop(&mut self) {
        // Also runs on unwind while the operation remains under State custody.
        if self.state.pending_directory.is_some() {
            self.disk.fail_locked(self.state);
        }
    }
}
fn step(state: &mut State, step: NodeDiskDirectoryOperationStep) -> io::Result<()> {
    state
        .pending_directory
        .as_mut()
        .expect("retained operation")
        .step(step);
    #[cfg(test)]
    injected(step)?;
    Ok(())
}
fn record_failure(disk: &NodeDisk, state: &mut State, error: &io::Error) {
    let operation = state
        .pending_directory
        .as_mut()
        .expect("retained operation");
    if operation.observation.failure.is_none() {
        operation.observation.failure = Some(NodeDiskDirectoryFailure::new(
            operation.observation.step,
            error,
        ));
    }
    disk.fail_locked(state);
}
fn ready(disk: &NodeDisk, state: &State) -> io::Result<()> {
    if state.phase != NodeDiskPhase::Open
        || state.pending_directory.is_some()
        || !disk.device.lock().admission_ready()
    {
        return Err(io::ErrorKind::Other.into());
    }
    Ok(())
}
fn child_names(owner: &DirectoryOwner, name: &CStr) -> io::Result<Box<[CString]>> {
    let bytes = name.to_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.len() > owner.disk.config.max_name_bytes as usize
        || owner.names.len() + 2 > owner.disk.config.max_depth as usize
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut names = Vec::new();
    names
        .try_reserve_exact(owner.names.len() + 1)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    names.extend(owner.names.iter().cloned());
    names.push(name.to_owned());
    Ok(names.into_boxed_slice())
}

impl NodeDiskDirectory {
    /// Open an exact enrolled child. An unknown final absence is healthy; an
    /// unaccounted existing object or changed ancestry fences this owner.
    pub fn open_child(&self, name: &CStr) -> io::Result<Self> {
        let owner = self.owner();
        let disk = &owner.disk;
        let mut state = disk.lock_state();
        prepare_child(owner, name, &mut state, None)?;
        let mut effect = Effect {
            disk,
            state: &mut state,
        };
        let result: io::Result<Self> = (|| {
            acquire_parent(owner, &mut effect)?;
            step(&mut effect, NodeDiskDirectoryOperationStep::OpenChild)?;
            let operation = effect
                .pending_directory
                .as_mut()
                .expect("retained operation");
            operation.child = Some(census::open_at(
                operation.parent.file(),
                operation.name(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?);
            let metadata = operation
                .child
                .as_ref()
                .expect("retained child")
                .metadata()?;
            let identity = Identity::of(&metadata);
            let binding = operation.binding;
            let parent = operation.parent.identity();
            verify_enrolled(&effect.accounted, identity, &metadata)?;
            let entry = effect
                .accounted
                .get_mut(&identity)
                .and_then(AccountedInode::directory_mut)
                .expect("verified child");
            if entry.binding != binding || entry.parent != Some(parent) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let handles = entry
                .live_handles
                .checked_add(1)
                .ok_or(io::ErrorKind::InvalidData)?;
            entry.live_handles = handles;
            effect
                .pending_directory
                .as_mut()
                .expect("retained operation")
                .identity = Some(identity);
            Ok(publish_child(disk, &mut effect))
        })();
        if let Err(error) = &result {
            // A verified parent's unknown final absence is the only healthy
            // failed acquisition. Close every actual descriptor and backing
            // before returning its prepared slot; close uncertainty stays owned.
            let operation = effect
                .pending_directory
                .as_ref()
                .expect("retained operation");
            let absent = error.kind() == io::ErrorKind::NotFound
                && operation.observation.step == NodeDiskDirectoryOperationStep::OpenChild
                && !effect
                    .accounted
                    .values()
                    .any(|entry| entry.binding() == operation.binding);
            if absent {
                let operation = effect.pending_directory.as_mut().expect("retained absence");
                operation.observation.failure = Some(NodeDiskDirectoryFailure::new(
                    operation.observation.step,
                    error,
                ));
                operation_absent(&mut effect)
                    .inspect_err(|close| record_failure(disk, &mut effect, close))?;
            } else {
                record_failure(disk, &mut effect, error);
            }
        }
        result
    }

    /// Create exactly one absent child with its full policy allowance prepared
    /// before the first descriptor acquisition. This does not admit a multipart
    /// caller operation.
    pub fn create_child(&self, name: &CStr, work: DiskWork) -> io::Result<Self> {
        let owner = self.owner();
        let disk = &owner.disk;
        let mut state = disk.lock_state();
        prepare_child(owner, name, &mut state, Some(work))?;
        let mut effect = Effect {
            disk,
            state: &mut state,
        };
        let result = (|| {
            acquire_parent(owner, &mut effect)?;
            effect
                .pending_directory
                .as_ref()
                .expect("retained operation")
                .plan
                .expect("create plan")
                .activate(&mut effect);
            create_effect(disk, &mut effect)
        })();
        if let Err(error) = &result {
            record_failure(disk, &mut effect, error);
        }
        result
    }

    /// Remove an empty non-root directory, consuming the sole handle. Other
    /// independent owners, child owners and cloned handles reject before unlink.
    pub fn remove_if_empty(mut self) -> io::Result<()> {
        use NodeDiskDirectoryOperationStep as Step;
        let disk = self.owner().disk.clone();
        let mut state = disk.lock_state();
        ready(&disk, &state)?;
        if self.owner().names.is_empty() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if Arc::strong_count(self.0.as_ref().expect("live directory")) != 1 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let entry = *state
            .accounted
            .get(&self.owner().identity)
            .and_then(AccountedInode::directory)
            .ok_or(io::ErrorKind::InvalidData)?;
        if !entry.settled {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if entry.children != 0 {
            return Err(io::ErrorKind::DirectoryNotEmpty.into());
        }
        if entry.live_handles != 1 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let parent_identity = self
            .owner()
            .parent
            .as_ref()
            .expect("nonroot parent")
            .identity();
        let plan =
            ParentTransition::preflight(&disk, &mut state, (parent_identity, -1), None, None)?;
        // No Arc or Weak can be acquired after this private sole-owner check.
        // into_inner deallocates control backing before moving actual custody.
        let mut owner =
            Arc::into_inner(self.0.take().expect("live directory")).expect("sole directory owner");
        owner.registered = false;
        let identity = owner.identity;
        state.pending_directory = Some(PendingDirectory {
            observation: NodeDiskDirectoryOperation {
                kind: NodeDiskDirectoryOperationKind::Remove,
                step: Step::Prepared,
                failure: None,
                close_failure: None,
                uncertain_close_descriptor: None,
            },
            root: std::mem::take(&mut owner.root),
            names: std::mem::replace(&mut owner.names, Box::new([])),
            binding: entry.binding,
            parent: owner.parent.take().expect("nonroot parent"),
            child: owner.file.take(),
            walk_current: None,
            walk_next: None,
            identity: Some(identity),
            allocation: None,
            plan: Some(plan),
        });
        drop(owner);
        let mut effect = Effect {
            disk: &disk,
            state: &mut state,
        };
        let result = (|| {
            verify_preflight(&disk, &mut effect)?;
            effect
                .pending_directory
                .as_mut()
                .expect("retained operation")
                .verify_child(&disk)?;
            let metadata = effect
                .pending_directory
                .as_ref()
                .expect("retained operation")
                .child
                .as_ref()
                .expect("retained child")
                .metadata()?;
            verify_enrolled(&effect.accounted, identity, &metadata)?;
            plan.activate(&mut effect);
            effect
                .accounted
                .get_mut(&identity)
                .and_then(AccountedInode::directory_mut)
                .expect("retained child")
                .settled = false;
            remove_effect(&disk, &mut effect, entry)
        })();
        if let Err(error) = &result {
            record_failure(&disk, &mut effect, error);
        }
        result
    }
}

fn verify_enrolled(
    ledger: &crate::node_disk::fixed_map::Banks<AccountedInode>,
    identity: Identity,
    metadata: &std::fs::Metadata,
) -> io::Result<()> {
    census::directory_nonallocating(metadata)?;
    let entry = ledger
        .get(&identity)
        .and_then(AccountedInode::directory)
        .ok_or(io::ErrorKind::InvalidData)?;
    if !entry.settled
        || entry.len != metadata.len()
        || entry.bytes.checked_sub(entry.pending) != Some(census::directory_extent(metadata)?)
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}
fn verify_preflight(disk: &NodeDisk, state: &mut State) -> io::Result<()> {
    let State {
        pending_directory,
        accounted,
        ..
    } = state;
    pending_directory
        .as_mut()
        .expect("retained operation")
        .verify_parent(disk, Some(accounted))
}
fn acquire_parent(owner: &DirectoryOwner, state: &mut State) -> io::Result<()> {
    let operation = state
        .pending_directory
        .as_mut()
        .expect("retained operation");
    operation
        .parent
        .set_descriptor(owner.file.as_ref().expect("live directory").try_clone()?);
    verify_preflight(&owner.disk, state)
}
fn prepare_child(
    owner: &DirectoryOwner,
    name: &CStr,
    state: &mut State,
    work: Option<DiskWork>,
) -> io::Result<()> {
    let disk = &owner.disk;
    ready(disk, state)?;
    if state.open_directories >= disk.config.max_open_directories {
        return Err(io::ErrorKind::StorageFull.into());
    }
    let roots = u64::try_from(disk.roots.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    if work.is_some()
        && state
            .directories
            .checked_sub(roots)
            .is_none_or(|n| n >= disk.config.max_persistent_subdirectories)
    {
        return Err(io::ErrorKind::StorageFull.into());
    }
    if work.is_some() {
        state.accounted.try_reserve(1)?;
    }
    let names = child_names(owner, name)?;
    let parent_entry = *state
        .accounted
        .get(&owner.identity)
        .and_then(AccountedInode::directory)
        .ok_or(io::ErrorKind::InvalidData)?;
    let binding = parent_entry.binding.child(name);
    if work.is_some()
        && state
            .accounted
            .values()
            .any(|entry| entry.binding() == binding)
    {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    parent_entry
        .live_handles
        .checked_add(1)
        .ok_or(io::ErrorKind::InvalidData)?;
    let directories = if work.is_some() {
        state
            .directories
            .checked_add(1)
            .ok_or(io::ErrorKind::StorageFull)?
    } else {
        state.directories
    };
    let plan = if let Some(work) = work {
        Some(ParentTransition::preflight(
            disk,
            state,
            (owner.identity, 1),
            None,
            Some(work),
        )?)
    } else {
        None
    };
    let mut ancestors = Vec::new();
    ancestors
        .try_reserve_exact(owner.names.len() + 1)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    if let Some(parent) = &owner.parent {
        ancestors.extend_from_slice(parent.ancestors());
    }
    ancestors.push(owner.identity);
    if ancestors.len() != owner.names.len() + 1 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut parent = RetainedParent::prepared(owner.identity, ancestors.into_boxed_slice());
    let allocation = Arc::<DirectoryOwner>::new_uninit();
    let root = owner.root.clone();
    if let Some(work) = work {
        disk.reserve(state, disk.config.directory_policy.extent_bytes, work)?;
    }
    parent
        .register(disk, state)
        .expect("preflighted parent registration");
    state.open_directories += 1;
    state.directories = directories;
    state.pending_directory = Some(PendingDirectory {
        observation: NodeDiskDirectoryOperation {
            kind: if work.is_some() {
                NodeDiskDirectoryOperationKind::Create
            } else {
                NodeDiskDirectoryOperationKind::Open
            },
            step: NodeDiskDirectoryOperationStep::Prepared,
            failure: None,
            close_failure: None,
            uncertain_close_descriptor: None,
        },
        root,
        names,
        binding,
        parent,
        child: None,
        walk_current: None,
        walk_next: None,
        identity: None,
        allocation: Some(allocation),
        plan,
    });
    Ok(())
}
fn operation_absent(state: &mut State) -> io::Result<()> {
    let operation = state.pending_directory.as_mut().expect("retained absence");
    let parent = operation.parent.identity();
    operation.close_resources()?;
    if !namespace::can_retire_parent(state, parent) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let owners = state
        .open_directories
        .checked_sub(1)
        .ok_or(io::ErrorKind::InvalidData)?;
    drop(state.pending_directory.take());
    namespace::retire_parent(state, parent);
    state.open_directories = owners;
    Ok(())
}

fn create_effect(disk: &Arc<NodeDisk>, state: &mut State) -> io::Result<NodeDiskDirectory> {
    use NodeDiskDirectoryOperationStep as Step;
    step(state, Step::Mkdir)?;
    let operation = state
        .pending_directory
        .as_ref()
        .expect("retained operation");
    // SAFETY: both the retained parent FD and one-component C name are live.
    if unsafe {
        libc::mkdirat(
            operation.parent.file().as_raw_fd(),
            operation.name().as_ptr(),
            0o700,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    step(state, Step::OpenChild)?;
    let operation = state
        .pending_directory
        .as_mut()
        .expect("retained operation");
    operation.child = Some(census::open_at(
        operation.parent.file(),
        operation.name(),
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?);
    step(state, Step::ObserveChild)?;
    record_child(disk, state)?;
    step(state, Step::SyncChild)?;
    state
        .pending_directory
        .as_ref()
        .expect("retained operation")
        .child
        .as_ref()
        .expect("opened child")
        .sync_all()?;
    step(state, Step::SyncParent)?;
    state
        .pending_directory
        .as_ref()
        .expect("retained operation")
        .parent
        .file()
        .sync_all()?;
    step(state, Step::Verify)?;
    state
        .pending_directory
        .as_mut()
        .expect("retained operation")
        .verify_child(disk)?;
    let operation = state
        .pending_directory
        .as_ref()
        .expect("retained operation");
    let metadata = operation
        .child
        .as_ref()
        .expect("retained child")
        .metadata()?;
    let entry = state.accounted[&operation.identity.expect("recorded child")]
        .directory()
        .expect("recorded child");
    if metadata.len() != entry.len
        || census::directory_extent(&metadata)? != entry.bytes - entry.pending
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    settle_parent(disk, state)?;
    let identity = state
        .pending_directory
        .as_ref()
        .expect("retained operation")
        .identity
        .expect("observed child");
    state
        .accounted
        .get_mut(&identity)
        .and_then(AccountedInode::directory_mut)
        .expect("observed child")
        .settled = true;
    Ok(publish_child(disk, state))
}
fn publish_child(disk: &Arc<NodeDisk>, state: &mut State) -> NodeDiskDirectory {
    let mut operation = state.pending_directory.take().expect("settled operation");
    assert!(operation.walk_current.is_none() && operation.walk_next.is_none());
    let mut allocation = operation.allocation.take().expect("preallocated owner");
    Arc::get_mut(&mut allocation)
        .expect("private owner allocation")
        .write(DirectoryOwner {
            disk: disk.clone(),
            root: operation.root,
            names: operation.names,
            identity: operation.identity.expect("observed child"),
            file: operation.child,
            parent: Some(operation.parent),
            registered: true,
            #[cfg(test)]
            after_close: None,
        });
    // SAFETY: the sole admitted allocation is fully initialized above.
    NodeDiskDirectory(Some(unsafe { allocation.assume_init() }))
}

fn record_child(disk: &NodeDisk, state: &mut State) -> io::Result<()> {
    let operation = state
        .pending_directory
        .as_ref()
        .expect("retained operation");
    let metadata = operation.child.as_ref().expect("opened child").metadata()?;
    census::directory_nonallocating(&metadata)?;
    let identity = Identity::of(&metadata);
    if identity.0 != disk.roots[&operation.root].identity.0
        || state.accounted.contains_key(&identity)
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let observed = census::directory_extent(&metadata)?;
    let reserved = disk.config.directory_policy.extent_bytes;
    let charged = reserved.max(observed);
    let pending = charged - observed;
    let bytes = state
        .bytes
        .checked_sub(reserved)
        .and_then(|v| v.checked_add(charged))
        .ok_or(io::ErrorKind::InvalidData)?;
    let next_pending = state
        .pending
        .checked_sub(reserved)
        .and_then(|v| v.checked_add(pending))
        .ok_or(io::ErrorKind::InvalidData)?;
    let directory_bytes = state
        .directory_bytes
        .checked_add(observed)
        .ok_or(io::ErrorKind::InvalidData)?;
    let mut promises = disk.device.lock();
    let shared = promises
        .checked_sub(reserved)
        .and_then(|v| v.checked_add(pending))
        .ok_or(io::ErrorKind::InvalidData)?;
    promises.set_pending(shared)?;
    state.bytes = bytes;
    state.pending = next_pending;
    state.directory_bytes = directory_bytes;
    let entry = AccountedDirectory {
        binding: operation.binding,
        parent: Some(operation.parent.identity()),
        bytes: charged,
        pending,
        settled: false,
        len: metadata.len(),
        children: 0,
        live_handles: 1,
    };
    assert!(
        state
            .accounted
            .insert(identity, AccountedInode::Directory(entry))
            .is_none()
    );
    state
        .pending_directory
        .as_mut()
        .expect("retained operation")
        .identity = Some(identity);
    if observed > reserved {
        state.phase = NodeDiskPhase::Failed;
        promises.fail_owner();
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}
fn settle_parent(disk: &NodeDisk, state: &mut State) -> io::Result<()> {
    step(state, NodeDiskDirectoryOperationStep::Settle)?;
    let operation = state
        .pending_directory
        .as_ref()
        .expect("retained operation");
    let observation = (
        operation.parent.identity(),
        operation.parent.file().metadata()?,
    );
    operation
        .plan
        .expect("mutation plan")
        .settle_observed(disk, state, [Some(observation), None])
}
fn remove_effect(disk: &NodeDisk, state: &mut State, entry: AccountedDirectory) -> io::Result<()> {
    use NodeDiskDirectoryOperationStep as Step;
    step(state, Step::Unlink)?;
    let operation = state
        .pending_directory
        .as_ref()
        .expect("retained operation");
    // SAFETY: exact verified empty child and retained parent remain owned.
    if unsafe {
        libc::unlinkat(
            operation.parent.file().as_raw_fd(),
            operation.name().as_ptr(),
            libc::AT_REMOVEDIR,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    step(state, Step::SyncParent)?;
    state
        .pending_directory
        .as_ref()
        .expect("retained operation")
        .parent
        .file()
        .sync_all()?;
    step(state, Step::Verify)?;
    let operation = state
        .pending_directory
        .as_mut()
        .expect("retained operation");
    operation.verify_parent(disk, None)?;
    let metadata = operation
        .child
        .as_ref()
        .expect("retained child")
        .metadata()?;
    if Some(Identity::of(&metadata)) != operation.identity {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // Darwin may retain the original directory nlink value after rmdir. Verify
    // the exact bound name is absent; the actual old inode remains in custody
    // until its explicit close below, before any physical credit is returned.
    let mut absent: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            operation.parent.file().as_raw_fd(),
            operation.name().as_ptr(),
            &mut absent,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let absence = io::Error::last_os_error();
    if absence.kind() != io::ErrorKind::NotFound {
        return Err(absence);
    }
    settle_parent(disk, state)?;
    let bytes = state
        .bytes
        .checked_sub(entry.bytes)
        .ok_or(io::ErrorKind::InvalidData)?;
    let pending = state
        .pending
        .checked_sub(entry.pending)
        .ok_or(io::ErrorKind::InvalidData)?;
    let directory_bytes = state
        .directory_bytes
        .checked_sub(entry.bytes - entry.pending)
        .ok_or(io::ErrorKind::InvalidData)?;
    let directories = state
        .directories
        .checked_sub(1)
        .ok_or(io::ErrorKind::InvalidData)?;
    let open_directories = state
        .open_directories
        .checked_sub(1)
        .ok_or(io::ErrorKind::InvalidData)?;
    let operation = state
        .pending_directory
        .as_mut()
        .expect("retained operation");
    let parent_identity = operation.parent.identity();
    let identity = operation.identity.expect("retained identity");
    operation.close_resources()?;
    if !namespace::can_retire_parent(state, parent_identity) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut promises = disk.device.lock();
    let shared = promises
        .checked_sub(entry.pending)
        .ok_or(io::ErrorKind::InvalidData)?;
    // Close and all fallible checks precede credit. Names, ancestor backing and
    // the prepared control allocation die before the slot becomes reusable.
    promises.set_pending(shared)?;
    drop(state.pending_directory.take());
    state
        .accounted
        .remove(&identity)
        .expect("retained child entry");
    namespace::retire_parent(state, parent_identity);
    state.bytes = bytes;
    state.pending = pending;
    state.directory_bytes = directory_bytes;
    state.directories = directories;
    state.open_directories = open_directories;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FAILURE: std::cell::Cell<Option<NodeDiskDirectoryOperationStep>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn injected(step: NodeDiskDirectoryOperationStep) -> io::Result<()> {
    if FAILURE.with(|failure| {
        if failure.get() == Some(step) {
            failure.set(None);
            true
        } else {
            false
        }
    }) {
        Err(io::Error::from_raw_os_error(libc::EIO))
    } else {
        Ok(())
    }
}
#[cfg(test)]
mod tests;
