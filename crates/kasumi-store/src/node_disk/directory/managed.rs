//! One admitted, State-retained directory namespace effect.
use super::{DirectoryOwner, NodeDiskDirectory};
use crate::node_disk::{
    AccountedDirectory, AccountedInode, DiskWork, Identity, NamespaceBinding, NodeDisk,
    NodeDiskPhase, State, census,
    namespace::{self, ParentTransition, RetainedParent},
    native_file::{self, CloseOutcome},
};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io,
    mem::MaybeUninit,
    os::fd::AsRawFd,
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
    // Fixed custody is initialized in State before every descriptor/effect.
    child_close: Option<CloseOutcome>,
    walk_current_close: Option<CloseOutcome>,
    walk_next_close: Option<CloseOutcome>,
    original_error: Option<io::Error>,
    original_panic: Option<Box<dyn std::any::Any + Send>>,
    retirement: Retirement,
    retirement_panic: Option<Box<dyn std::any::Any + Send>>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Retirement {
    NotEntered,
    Entered,
    DiagnosticsReturned,
    Returned,
    Panicked,
}

/// Borrow the actual originals without closing or retiring their custody.
/// This holds the existing metadata gate until the borrowed view is dropped.
pub struct NodeDiskDirectoryOriginals<'a> {
    state: std::sync::MutexGuard<'a, State>,
}
impl NodeDiskDirectoryOriginals<'_> {
    fn operation(&self) -> &PendingDirectory {
        self.state
            .pending_directory
            .as_ref()
            .expect("borrowed pending operation")
    }
    pub fn error(&self) -> Option<&io::Error> {
        self.operation().original_error.as_ref()
    }
    pub fn panic(&self) -> Option<&(dyn std::any::Any + Send)> {
        self.operation().original_panic.as_deref()
    }
    pub fn retirement_panic(&self) -> Option<&(dyn std::any::Any + Send)> {
        self.operation().retirement_panic.as_deref()
    }
    pub fn retirement_entered(&self) -> bool {
        self.operation().retirement != Retirement::NotEntered
    }
    pub fn retirement_completed(&self) -> bool {
        let operation = self.operation();
        operation.retirement == Retirement::Returned
            && operation.original_error.is_none()
            && operation.original_panic.is_none()
    }
    /// Fixed child/current/next/parent/parent-current/parent-next originals.
    /// Empty slots carry no allocation or claim of a native close attempt.
    pub fn close_errors(&mut self) -> [Option<(i32, &io::Error)>; 6] {
        let operation = self
            .state
            .pending_directory
            .as_mut()
            .expect("borrowed pending operation");
        let [parent, parent_current, parent_next] = operation.parent.directory_close_errors();
        let [child, current, next] = [
            &operation.child_close,
            &operation.walk_current_close,
            &operation.walk_next_close,
        ]
        .map(|outcome| {
            outcome
                .as_ref()
                .map(|outcome| (outcome.descriptor, &outcome.error))
        });
        [child, current, next, parent, parent_current, parent_next]
    }
}
// One actual original at a time crosses the metadata lock boundary; another
// diagnostic remains in its receiver until the previous destructor returned.
enum OriginalDiagnostic {
    Error(io::Error),
    Panic(Box<dyn std::any::Any + Send>),
}
impl NodeDisk {
    pub(in crate::node_disk) fn retire_pending_directory_diagnostics(&self) -> io::Result<()> {
        let mut owns_retirement = false;
        loop {
            let mut state = self.lock_state();
            if state.pending_directory.is_none() {
                return Ok(());
            }
            if !owns_retirement {
                if state.namespace_witnesses() != 0 || !state.external_owners_drained() {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let operation = state.pending_directory.as_mut().expect("pending receiver");
                match operation.retirement {
                    Retirement::DiagnosticsReturned | Retirement::Returned => return Ok(()),
                    Retirement::Entered => return Err(io::ErrorKind::WouldBlock.into()),
                    Retirement::Panicked => return Err(io::ErrorKind::Other.into()),
                    Retirement::NotEntered => {}
                }
                if let Err(error) = operation.close_resources() {
                    self.fail_locked(&mut state);
                    return Err(error);
                }
                operation.retirement = Retirement::Entered;
                owns_retirement = true;
            }
            let operation = state
                .pending_directory
                .as_mut()
                .expect("owned pending retirement");
            assert!(operation.retirement == Retirement::Entered);
            let original = operation
                .parent
                .take_directory_failure()
                .map(OriginalDiagnostic::Error)
                .or_else(|| {
                    operation
                        .original_error
                        .take()
                        .map(OriginalDiagnostic::Error)
                })
                .or_else(|| {
                    operation
                        .original_panic
                        .take()
                        .map(OriginalDiagnostic::Panic)
                });
            let Some(original) = original else {
                operation.retirement = Retirement::DiagnosticsReturned;
                return Ok(());
            };
            // No State, device, or registry lock may be held by this explicit
            // cleanup caller during an opaque original's destructor.
            drop(state);
            let retired =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match original {
                    OriginalDiagnostic::Error(error) => drop(error),
                    OriginalDiagnostic::Panic(payload) => drop(payload),
                }));
            if let Err(payload) = retired {
                let mut state = self.lock_state();
                let operation = state
                    .pending_directory
                    .as_mut()
                    .expect("retirement remains installed");
                assert!(
                    operation.retirement == Retirement::Entered
                        && operation.retirement_panic.is_none()
                );
                operation.retirement_panic = Some(payload);
                operation.retirement = Retirement::Panicked;
                self.fail_locked(&mut state);
                return Err(io::ErrorKind::Other.into());
            }
        }
    }
    pub fn pending_directory_originals(&self) -> io::Result<NodeDiskDirectoryOriginals<'_>> {
        let state = self.lock_state();
        if state.pending_directory.is_none() {
            return Err(io::ErrorKind::NotFound.into());
        }
        Ok(NodeDiskDirectoryOriginals { state })
    }
}
impl PendingDirectory {
    pub(in crate::node_disk) fn retain_publication_error(&mut self, error: io::Error) -> io::Error {
        let returned = native_file::projection(&error);
        assert!(
            self.original_error.is_none(),
            "original publication outcome slot"
        );
        self.original_error = Some(error);
        returned
    }
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
                &mut self.walk_current,
                &mut self.walk_current_close,
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
            &mut self.walk_current,
            &mut self.walk_current_close,
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
        if matches!(self.retirement, Retirement::Entered | Retirement::Panicked)
            || (self.retirement == Retirement::Returned
                && (self.original_error.is_some() || self.original_panic.is_some()))
        {
            return Err(io::ErrorKind::Other.into());
        }
        // Attempt every independent descriptor once. A saved Unknown never
        // retries a consumed, potentially recycled descriptor number.
        let next = Self::close_owned(
            &mut self.walk_next,
            &mut self.walk_next_close,
            NodeDiskDirectoryOperationStep::Verify,
            &mut self.observation,
        );
        let current = Self::close_owned(
            &mut self.walk_current,
            &mut self.walk_current_close,
            NodeDiskDirectoryOperationStep::Verify,
            &mut self.observation,
        );
        let child = Self::close_owned(
            &mut self.child,
            &mut self.child_close,
            NodeDiskDirectoryOperationStep::CloseChild,
            &mut self.observation,
        );
        #[cfg(test)]
        let descriptor = self.parent.descriptor_for_test();
        let parent = self.parent.close_resources();
        #[cfg(test)]
        let parent = parent.and_then(|()| {
            if let Some(descriptor) = descriptor {
                match injected(NodeDiskDirectoryOperationStep::CloseParent) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        let returned = native_file::projection(&error);
                        self.parent
                            .record_closed_descriptor_for_test(descriptor, error);
                        Err(returned)
                    }
                }
            } else {
                Ok(())
            }
        });
        if let Err(error) = &parent {
            self.observation.close_failure.get_or_insert_with(|| {
                NodeDiskDirectoryFailure::new(NodeDiskDirectoryOperationStep::CloseParent, error)
            });
            if let Some((descriptor, _)) = self.parent.close_diagnostic() {
                self.observation
                    .uncertain_close_descriptor
                    .get_or_insert(descriptor);
            }
        }
        next.and(current).and(child).and(parent)?;
        if !self.drained() {
            return Err(io::ErrorKind::Other.into());
        }
        Ok(())
    }
    fn close_owned(
        file: &mut Option<File>,
        outcome: &mut Option<CloseOutcome>,
        step: NodeDiskDirectoryOperationStep,
        observation: &mut NodeDiskDirectoryOperation,
    ) -> io::Result<()> {
        #[cfg(test)]
        let descriptor = file.as_ref().map(AsRawFd::as_raw_fd);
        let result = native_file::close(file, outcome);
        #[cfg(test)]
        let result = result.and_then(|()| {
            if let Some(descriptor) = descriptor {
                match injected(step) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        let returned = native_file::projection(&error);
                        *outcome = Some(CloseOutcome { descriptor, error });
                        Err(returned)
                    }
                }
            } else {
                Ok(())
            }
        });
        if let Some(outcome) = outcome {
            observation
                .close_failure
                .get_or_insert_with(|| NodeDiskDirectoryFailure::new(step, &outcome.error));
            observation
                .uncertain_close_descriptor
                .get_or_insert(outcome.descriptor);
        }
        result
    }
    fn drained(&self) -> bool {
        self.child.is_none()
            && self.child_close.is_none()
            && self.walk_current.is_none()
            && self.walk_current_close.is_none()
            && self.walk_next.is_none()
            && self.walk_next_close.is_none()
            && self.parent.known_drained()
    }
    pub(in crate::node_disk) fn retire_before_release(&mut self) -> io::Result<()> {
        if self.retirement == Retirement::Returned {
            return if self.original_error.is_none() && self.original_panic.is_none() {
                Ok(())
            } else {
                Err(io::ErrorKind::Other.into())
            };
        }
        if !matches!(
            self.retirement,
            Retirement::NotEntered | Retirement::DiagnosticsReturned
        ) || !self.drained()
            || self.original_error.is_some()
            || self.original_panic.is_some()
            || self.parent.has_directory_failure()
        {
            return Err(io::ErrorKind::Other.into());
        }
        // Keep the receiver installed throughout original diagnostic/backing
        // retirement. An entered destructor cannot replay or return credit.
        self.retirement = Retirement::Entered;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(std::mem::take(&mut self.root));
            drop(std::mem::replace(&mut self.names, Box::new([])));
            drop(self.allocation.take());
            self.parent.retire_directory_backing();
        })) {
            Ok(()) => {
                self.retirement = Retirement::Returned;
                Ok(())
            }
            Err(payload) => {
                self.retirement_panic = Some(payload);
                self.retirement = Retirement::Panicked;
                Err(io::ErrorKind::Other.into())
            }
        }
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
fn record_failure(disk: &NodeDisk, state: &mut State, error: io::Error) -> io::Error {
    let returned = native_file::projection(&error);
    let operation = state
        .pending_directory
        .as_mut()
        .expect("retained operation");
    if operation.observation.failure.is_none() {
        operation.observation.failure = Some(NodeDiskDirectoryFailure::new(
            operation.observation.step,
            &error,
        ));
    }
    if operation.original_error.is_none() {
        operation.original_error = Some(error);
    }
    disk.fail_locked(state);
    returned
}
fn catch_effect<'state, T>(
    effect: &mut Effect<'state>,
    body: impl FnOnce(&mut Effect<'state>) -> io::Result<T>,
) -> io::Result<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(effect))) {
        Ok(result) => result,
        Err(payload) => {
            let operation = effect
                .pending_directory
                .as_mut()
                .expect("pending operation during native unwind");
            assert!(
                operation.original_panic.is_none(),
                "one original native operation panic"
            );
            operation.original_panic = Some(payload);
            let returned = io::Error::from(io::ErrorKind::Other);
            operation.observation.failure.get_or_insert_with(|| {
                NodeDiskDirectoryFailure::new(operation.observation.step, &returned)
            });
            effect.disk.fail_locked(effect.state);
            Err(returned)
        }
    }
}
fn finish_result<T>(disk: &NodeDisk, state: &mut State, result: io::Result<T>) -> io::Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(record_failure(disk, state, error)),
    }
}
fn finish_open(
    disk: &NodeDisk,
    state: &mut State,
    result: io::Result<NodeDiskDirectory>,
) -> io::Result<NodeDiskDirectory> {
    let Err(error) = result else {
        return result;
    };
    let operation = state
        .pending_directory
        .as_ref()
        .expect("retained open operation");
    let absent = error.kind() == io::ErrorKind::NotFound
        && operation.observation.step == NodeDiskDirectoryOperationStep::OpenChild
        && !state
            .accounted
            .values()
            .any(|entry| entry.binding() == operation.binding);
    if !absent {
        return Err(record_failure(disk, state, error));
    }
    let operation = state.pending_directory.as_mut().expect("retained absence");
    operation.observation.failure = Some(NodeDiskDirectoryFailure::new(
        operation.observation.step,
        &error,
    ));
    match operation_absent(state) {
        Ok(()) => Err(error),
        Err(close) => {
            state
                .pending_directory
                .as_mut()
                .expect("retained uncertain absence")
                .original_error = Some(error);
            Err(record_failure(disk, state, close))
        }
    }
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
    /// Claim descendant namespace work without allocating names or opening FDs.
    /// Caller components may live on its stack. The retained directory and its
    /// installed names supply the prefix; physical verification follows under
    /// the claim in the ordinary tracked operation protocol.
    pub(crate) fn claim_descendants(
        &self,
        names: &[&CStr],
    ) -> io::Result<super::super::batch::NamespaceClaim> {
        let owner = self.owner();
        let disk = &owner.disk;
        let mut state = disk.lock_state();
        if names.is_empty()
            || owner
                .names
                .len()
                .checked_add(names.len())
                .is_none_or(|depth| depth >= disk.config.max_depth as usize)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let root = disk
            .roots
            .get(&owner.root)
            .ok_or(io::ErrorKind::InvalidData)?;
        let prefix = owner
            .names
            .iter()
            .fold(NamespaceBinding::root(root.identity), |binding, name| {
                binding.child(name)
            });
        let Some(AccountedInode::Directory(entry)) = state.accounted.get(&owner.identity) else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        if entry.binding != prefix || !entry.settled {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut binding = prefix;
        for name in names {
            let bytes = name.to_bytes();
            if bytes.is_empty()
                || bytes == b"."
                || bytes == b".."
                || bytes.contains(&b'/')
                || bytes.len() > disk.config.max_name_bytes as usize
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            binding = binding.child(name);
        }
        disk.claim_binding_namespace(&mut state, binding)
    }

    /// Open an exact enrolled child. An unknown final absence is healthy; an
    /// unaccounted existing object or changed ancestry fences this owner.
    pub fn open_child(&self, name: &CStr) -> io::Result<Self> {
        let owner = self.owner();
        let disk = &owner.disk;
        let mut state = disk.lock_state();
        prepare_child(owner, name, &mut state, None, None)?;
        let mut effect = Effect {
            disk,
            state: &mut state,
        };
        let result: io::Result<Self> = catch_effect(&mut effect, |effect| {
            acquire_parent(owner, effect)?;
            step(effect, NodeDiskDirectoryOperationStep::OpenChild)?;
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
            Ok(publish_child(disk, effect))
        });
        finish_open(disk, &mut effect, result)
    }

    /// Create exactly one absent child with its full policy allowance prepared
    /// before the first descriptor acquisition. This does not admit a multipart
    /// caller operation.
    pub fn create_child(&self, name: &CStr, work: DiskWork) -> io::Result<Self> {
        self.create_child_with_admission(name, work, None)
    }

    pub(crate) fn create_admitted_child(
        &self,
        name: &CStr,
        admission: &mut super::super::batch::NamespaceAdmission,
    ) -> io::Result<Self> {
        if !admission.same_disk(&self.owner().disk) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let work = admission.work(&self.owner().disk.lock_state())?;
        let result = self.create_child_with_admission(name, work, Some(admission));
        if result.is_err() {
            self.owner().disk.fail();
        }
        result
    }

    fn create_child_with_admission(
        &self,
        name: &CStr,
        work: DiskWork,
        admission: Option<&mut super::super::batch::NamespaceAdmission>,
    ) -> io::Result<Self> {
        let owner = self.owner();
        let disk = &owner.disk;
        let mut state = disk.lock_state();
        let allocation = if let Some(admission) = admission {
            let parent_binding = state
                .accounted
                .get(&owner.identity)
                .and_then(AccountedInode::directory)
                .ok_or(io::ErrorKind::InvalidData)?
                .binding;
            Some(admission.take_directory(&mut state, &owner.root, parent_binding.child(name))?)
        } else {
            None
        };
        prepare_child(owner, name, &mut state, Some(work), allocation)?;
        let mut effect = Effect {
            disk,
            state: &mut state,
        };
        let result = catch_effect(&mut effect, |effect| {
            acquire_parent(owner, effect)?;
            effect
                .pending_directory
                .as_ref()
                .expect("retained operation")
                .plan
                .expect("create plan")
                .activate(effect);
            create_effect(disk, effect)
        });
        finish_result(disk, &mut effect, result)
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
        // Even a zero-file claim retains this exact parent until explicit
        // settlement. Its scalar witness need not keep a directory handle.
        if entry.transaction_claimed {
            return Err(io::ErrorKind::WouldBlock.into());
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
            child_close: None,
            walk_current_close: None,
            walk_next_close: None,
            original_error: None,
            original_panic: None,
            retirement: Retirement::NotEntered,
            retirement_panic: None,
        });
        drop(owner);
        let mut effect = Effect {
            disk: &disk,
            state: &mut state,
        };
        let result = catch_effect(&mut effect, |effect| {
            verify_preflight(&disk, effect)?;
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
            plan.activate(effect);
            effect
                .accounted
                .get_mut(&identity)
                .and_then(AccountedInode::directory_mut)
                .expect("retained child")
                .settled = false;
            remove_effect(&disk, effect, entry)
        });
        finish_result(&disk, &mut effect, result)
    }
}

/// Generic non-root opens use the same operation slot from their first native
/// descriptor acquisition. The bounded ancestry array is allocated first and
/// populated only from verified descriptor/ledger pairs during descent.
pub(super) fn open_existing(
    disk: &Arc<NodeDisk>,
    state: &mut State,
    root: String,
    names: Box<[CString]>,
) -> io::Result<NodeDiskDirectory> {
    ready(disk, state)?;
    if names.is_empty()
        || state
            .open_directories
            .checked_add(super::super::batch::reserved_directories(state))
            .is_none_or(|n| n >= disk.config.max_open_directories)
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let root_identity = disk.roots[&root].identity;
    let binding = names
        .iter()
        .fold(NamespaceBinding::root(root_identity), |binding, name| {
            binding.child(name)
        });
    let mut ancestors = Vec::new();
    ancestors
        .try_reserve_exact(names.len())
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    ancestors.resize(names.len(), Identity(0, 0));
    ancestors[0] = root_identity;
    let allocation = Arc::<DirectoryOwner>::new_uninit();
    state.open_directories += 1;
    state.pending_directory = Some(PendingDirectory {
        observation: NodeDiskDirectoryOperation {
            kind: NodeDiskDirectoryOperationKind::Open,
            step: NodeDiskDirectoryOperationStep::Prepared,
            failure: None,
            close_failure: None,
            uncertain_close_descriptor: None,
        },
        root,
        names,
        binding,
        parent: RetainedParent::prepared(root_identity, ancestors.into_boxed_slice()),
        child: None,
        walk_current: None,
        walk_next: None,
        identity: None,
        allocation: Some(allocation),
        plan: None,
        child_close: None,
        walk_current_close: None,
        walk_next_close: None,
        original_error: None,
        original_panic: None,
        retirement: Retirement::NotEntered,
        retirement_panic: None,
    });
    let mut effect = Effect { disk, state };
    let result: io::Result<NodeDiskDirectory> = catch_effect(&mut effect, |effect| {
        acquire_rooted_parent(disk, effect)?;
        step(effect, NodeDiskDirectoryOperationStep::OpenChild)?;
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
        let parent = operation.parent.identity();
        verify_enrolled(&effect.accounted, identity, &metadata)?;
        let entry = effect
            .accounted
            .get_mut(&identity)
            .and_then(AccountedInode::directory_mut)
            .expect("verified directory");
        if entry.binding != binding || entry.parent != Some(parent) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        entry.live_handles = entry
            .live_handles
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        effect
            .pending_directory
            .as_mut()
            .expect("retained operation")
            .identity = Some(identity);
        Ok(publish_child(disk, effect))
    });
    finish_open(disk, &mut effect, result)
}
fn acquire_rooted_parent(disk: &NodeDisk, state: &mut State) -> io::Result<()> {
    let State {
        accounted,
        pending_directory,
        ..
    } = state;
    let operation = pending_directory.as_mut().expect("retained operation");
    let root = &disk.roots[&operation.root];
    root.verify_nonallocating()?;
    verify_enrolled(accounted, root.identity, &root.file.metadata()?)?;
    let mut binding = NamespaceBinding::root(root.identity);
    let mut parent_identity = root.identity;
    for index in 0..operation.names.len() - 1 {
        let current = operation.walk_current.as_ref().unwrap_or(&root.file);
        operation.walk_next = Some(census::open_at(
            current,
            &operation.names[index],
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?);
        let metadata = operation
            .walk_next
            .as_ref()
            .expect("retained walk descriptor")
            .metadata()?;
        let identity = Identity::of(&metadata);
        verify_enrolled(accounted, identity, &metadata)?;
        binding = binding.child(&operation.names[index]);
        let entry = accounted[&identity]
            .directory()
            .expect("verified directory");
        if entry.binding != binding || entry.parent != Some(parent_identity) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        operation.parent.observe_ancestor(index + 1, identity);
        PendingDirectory::close_owned(
            &mut operation.walk_current,
            &mut operation.walk_current_close,
            NodeDiskDirectoryOperationStep::Verify,
            &mut operation.observation,
        )?;
        operation.walk_current = operation.walk_next.take();
        parent_identity = identity;
    }
    let file = match operation.walk_current.take() {
        Some(file) => file,
        None => root.file.try_clone()?,
    };
    operation.parent.finish_prepared(parent_identity, file);
    operation.parent.register_in(accounted)
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
    admitted: Option<Arc<std::mem::MaybeUninit<DirectoryOwner>>>,
) -> io::Result<()> {
    let disk = &owner.disk;
    ready(disk, state)?;
    if state
        .open_directories
        .checked_add(super::super::batch::reserved_directories(state))
        .is_none_or(|n| n >= disk.config.max_open_directories)
    {
        return Err(io::ErrorKind::StorageFull.into());
    }
    let roots = u64::try_from(disk.roots.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    if work.is_some()
        && state
            .directories
            .checked_sub(roots)
            .and_then(|n| {
                n.checked_add(u64::from(super::super::batch::reserved_directories(state)))
            })
            .is_none_or(|n| n >= disk.config.max_persistent_subdirectories)
    {
        return Err(io::ErrorKind::StorageFull.into());
    }
    if work.is_some() {
        state
            .accounted
            .try_reserve(1 + super::super::batch::reserved_entries(state))?;
    }
    let names = child_names(owner, name)?;
    let parent_entry = *state
        .accounted
        .get(&owner.identity)
        .and_then(AccountedInode::directory)
        .ok_or(io::ErrorKind::InvalidData)?;
    let binding = parent_entry.binding.child(name);
    if work.is_some() && super::super::batch::reserved_binding(state, binding) {
        return Err(io::ErrorKind::WouldBlock.into());
    }
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
    let precharged = admitted.is_some();
    let allocation = admitted.unwrap_or_else(Arc::<DirectoryOwner>::new_uninit);
    let root = owner.root.clone();
    if let Some(work) = work
        && !precharged
    {
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
        child_close: None,
        walk_current_close: None,
        walk_next_close: None,
        original_error: None,
        original_panic: None,
        retirement: Retirement::NotEntered,
        retirement_panic: None,
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
    state
        .pending_directory
        .as_mut()
        .expect("retained absence")
        .retire_before_release()?;
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
    assert!(
        operation.walk_current.is_none()
            && operation.walk_next.is_none()
            && operation.walk_current_close.is_none()
            && operation.walk_next_close.is_none()
            && operation.child_close.is_none()
            && operation.original_error.is_none()
            && operation.original_panic.is_none()
            && operation.retirement == Retirement::NotEntered
    );
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
        transaction_children: 0,
        transaction_claimed: false,
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
    state
        .pending_directory
        .as_mut()
        .expect("retained removal")
        .retire_before_release()?;
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
    static ORIGINAL_FAILURE: std::cell::RefCell<Option<(NodeDiskDirectoryOperationStep, io::Error)>> = const { std::cell::RefCell::new(None) };
    static ORIGINAL_PANIC: std::cell::RefCell<Option<(NodeDiskDirectoryOperationStep, Box<dyn std::any::Any + Send>)>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn injected(step: NodeDiskDirectoryOperationStep) -> io::Result<()> {
    if let Some(payload) = ORIGINAL_PANIC.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(at, _)| *at == step) {
            slot.take().map(|(_, payload)| payload)
        } else {
            None
        }
    }) {
        std::panic::resume_unwind(payload);
    }
    if let Some(error) = ORIGINAL_FAILURE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(at, _)| *at == step) {
            slot.take().map(|(_, error)| error)
        } else {
            None
        }
    }) {
        return Err(error);
    }
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
mod custody_tests;
#[cfg(test)]
mod tests;
