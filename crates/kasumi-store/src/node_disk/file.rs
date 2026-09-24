use super::{
    AccountedFile, AccountedInode, DiskWork, Identity, NamespaceBinding, NodeDisk, NodeDiskPhase,
    State, census, extent,
    namespace::{self, ParentTransition, RetainedParent},
    rounded,
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
    close_outcome: Option<super::native_file::CloseOutcome>,
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum CloseAttempt {
    Unattempted,
    Executing,
    Failed(u64),
}

/// A terminal, positively drained attempt on one exact installed file owner.
/// It contains no fabricated native status and cannot be cloned or constructed
/// by a caller. Keeping it does not acknowledge any original outcome.
pub(crate) struct FailedFileWitness {
    disk: Arc<NodeDisk>,
    registration: usize,
    slot: usize,
    attempt: u64,
    identity: Identity,
}

/// Receipt of a transfer into the already admitted fixed custody bank. Transfer
/// releases no registration, physical extent, original outcome or memory charge.
pub(crate) struct FailedFileTransfer {
    disk: Arc<NodeDisk>,
    registration: usize,
    slot: usize,
    attempt: u64,
    after_census: u64,
}

impl PartialEq for FailedFileWitness {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.disk, &other.disk)
            && self.registration == other.registration
            && self.slot == other.slot
            && self.attempt == other.attempt
            && self.identity == other.identity
    }
}
impl Eq for FailedFileWitness {}
impl std::fmt::Debug for FailedFileWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailedFileWitness")
            .field("disk", &Arc::as_ptr(&self.disk))
            .field("registration", &self.registration)
            .field("slot", &self.slot)
            .field("attempt", &self.attempt)
            .field("identity", &self.identity)
            .finish()
    }
}
impl std::fmt::Debug for FailedFileTransfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailedFileTransfer")
            .field("disk", &Arc::as_ptr(&self.disk))
            .field("registration", &self.registration)
            .field("slot", &self.slot)
            .field("attempt", &self.attempt)
            .field("after_census", &self.after_census)
            .finish()
    }
}

/// Original logical outcomes, borrowed only while the terminal file stays live.
/// Native close outcomes must be absent for a known-drained witness.
pub(crate) struct FailedCloseReport<'a> {
    original: std::sync::MutexGuard<'a, Option<io::Error>>,
    parent: Option<namespace::ParentFailureReport<'a>>,
    retiring_parent: Option<namespace::ParentFailureReport<'a>>,
}
impl FailedCloseReport<'_> {
    pub(crate) fn visit_errors(&self, mut visit: impl FnMut(&io::Error)) {
        if let Some(error) = self.original.as_ref() {
            visit(error);
        }
        for parent in [&self.parent, &self.retiring_parent].into_iter().flatten() {
            parent.visit_errors(&mut visit);
        }
    }
}

impl NodeDiskFile {
    fn failed_witness_locked(&self, state: &State) -> io::Result<FailedFileWitness> {
        let owner = self.0.0.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
        let CloseAttempt::Failed(attempt) = owner.close_attempt else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        if state.phase != NodeDiskPhase::Failed
            || owner.registration == 0
            || !state
                .live
                .get(&owner.identity)
                .is_some_and(|entry| entry.as_ptr() as usize == owner.registration)
            || Arc::strong_count(owner) != 1
            || Arc::weak_count(owner) != 1
            || !state.file_custody.reserved_empty(owner.custody_slot)
            || !owner.resources.completed_native_drain()
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(FailedFileWitness {
            disk: owner.disk.clone(),
            registration: owner.registration,
            slot: owner.custody_slot,
            attempt,
            identity: owner.identity,
        })
    }

    pub(crate) fn failed_close_witness(&self) -> io::Result<FailedFileWitness> {
        let owner = self.0.0.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
        let state = owner
            .disk
            .state
            .try_lock()
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        self.failed_witness_locked(&state)
    }

    pub(crate) fn with_failed_close_report<R>(
        &self,
        witness: &FailedFileWitness,
        observe: impl FnOnce(&FailedCloseReport<'_>) -> R,
    ) -> io::Result<R> {
        if &self.failed_close_witness()? != witness {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // No State guard crosses the callback. The enclosing NodeFile read
        // guard prevents transfer; originals cannot change on a sealed attempt.
        let owner = self.0.0.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
        let original = owner
            .original_error
            .as_ref()
            .ok_or(io::ErrorKind::InvalidData)?
            .try_lock()
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        let parent = owner
            .parent
            .as_ref()
            .map(RetainedParent::failure_report)
            .transpose()?;
        let retiring_parent = owner
            .retiring_parent
            .as_ref()
            .map(RetainedParent::failure_report)
            .transpose()?;
        Ok(observe(&FailedCloseReport {
            original,
            parent,
            retiring_parent,
        }))
    }

    pub(crate) fn transfer_failed(
        &mut self,
        witness: &FailedFileWitness,
    ) -> io::Result<Option<FailedFileTransfer>> {
        let disk = self
            .0
            .0
            .as_ref()
            .ok_or(io::ErrorKind::BrokenPipe)?
            .disk
            .clone();
        let mut state = match disk.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(io::ErrorKind::Other.into()),
        };
        if &self.failed_witness_locked(&state)? != witness {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        state
            .accepted_census_generation
            .checked_add(1)
            .ok_or(io::ErrorKind::Other)?;
        let transfer = FailedFileTransfer {
            disk: witness.disk.clone(),
            registration: witness.registration,
            slot: witness.slot,
            attempt: witness.attempt,
            after_census: state.accepted_census_generation,
        };
        drop(std::mem::replace(
            state
                .live
                .get_mut(&witness.identity)
                .expect("validated registration"),
            std::sync::Weak::new(),
        ));
        let mut guarded = ExplicitClose {
            owner: &mut self.0,
            state,
            identity: witness.identity,
            executing: true,
        };
        let owner = Arc::get_mut(&mut *guarded.owner).expect("sole terminal owner");
        let resources = std::mem::replace(&mut owner.resources, FileResources::empty());
        // This entry was validated under the same State guard; the move neither
        // allocates nor drops any original diagnostic or admitted backing.
        guarded.state.file_custody.retain(resources);
        *guarded
            .state
            .live
            .get_mut(&witness.identity)
            .expect("occupied registration") = Arc::downgrade(guarded.owner);
        // The original Weak retains the original Arc allocation until census.
        drop(guarded.owner.0.take());
        guarded.executing = false;
        Ok(Some(transfer))
    }
}

impl NodeDisk {
    pub(crate) fn accepted_failure_transfer(&self, transfer: &FailedFileTransfer) -> bool {
        if !std::ptr::eq(self, Arc::as_ptr(&transfer.disk)) {
            return false;
        }
        let Ok(state) = self.state.try_lock() else {
            return false;
        };
        // Every accepted generation retires all entries installed before its
        // State-held start. No new transfer can interleave with that census.
        state.accepted_census_generation > transfer.after_census
            && transfer.registration != 0
            && transfer.slot != usize::MAX
            && transfer.attempt != 0
    }
}

pub(super) struct FileOwner {
    disk: Arc<NodeDisk>,
    resources: FileResources,
}

// No Arc<NodeDisk> is retained here: failed custody belongs to the installed
// owner without creating a cycle back to itself.
pub(super) struct FileResources {
    root: String,
    relative: PathBuf,
    // Parent path names are validated and allocated once during acquisition.
    // I/O verifies every current ancestor using these original names.
    parent_names: Box<[CString]>,
    parent: Option<RetainedParent>,
    // Publication keeps both real descriptors until durability settles. Only
    // one registration is active, transferred after the old FD actually closes.
    retiring_parent: Option<RetainedParent>,
    retired_parent: Option<Identity>,
    name: Option<CString>,
    identity: Identity,
    binding: NamespaceBinding,
    budget: Option<Mutex<Budget>>,
    registration: usize,
    custody_slot: usize,
    allocation: Option<Arc<std::mem::MaybeUninit<FileOwner>>>,
    provisional_file: Option<File>,
    provisional_close: Option<super::native_file::CloseOutcome>,
    original_error: Option<Mutex<Option<io::Error>>>,
    close_attempt: CloseAttempt,
}
impl std::ops::Deref for FileOwner {
    type Target = FileResources;
    fn deref(&self) -> &FileResources {
        &self.resources
    }
}
impl std::ops::DerefMut for FileOwner {
    fn deref_mut(&mut self) -> &mut FileResources {
        &mut self.resources
    }
}
#[path = "file/custody.rs"]
mod custody;
pub(super) use custody::CustodySlots;

#[cfg(test)]
pub(super) struct ClosePause {
    pub(super) stage: CloseStage,
    pub(super) entered: std::sync::mpsc::Sender<()>,
    pub(super) release: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CloseStage {
    DataClosed,
    ResourcesClosed,
    ResourcesRetained,
}

#[cfg(test)]
std::thread_local! {
    static PARENT_CLOSE_FAILURE: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
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
pub struct NodeDiskFile(OwnedFileArc);

/// Every private strong reference uses this retirement protocol. In particular,
/// publication abandonment and failed exclusive unwrap must not let a raw Arc
/// run FileOwner::drop while its backing allocation is still held implicitly.
#[derive(Clone)]
struct OwnedFileArc(Option<Arc<FileOwner>>);
impl OwnedFileArc {
    fn new(owner: Arc<FileOwner>) -> Self {
        Self(Some(owner))
    }
    fn try_unwrap(mut self) -> Result<FileOwner, Self> {
        Arc::try_unwrap(self.0.take().expect("live file custody")).map_err(Self::new)
    }
}
impl std::ops::Deref for OwnedFileArc {
    type Target = Arc<FileOwner>;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("live file custody")
    }
}
impl std::ops::DerefMut for OwnedFileArc {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().expect("live file custody")
    }
}
impl Drop for OwnedFileArc {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take().and_then(Arc::into_inner) {
            drop(owner);
        }
    }
}

impl std::fmt::Debug for NodeDiskFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.0.is_none() {
            return f
                .debug_struct("NodeDiskFile")
                .field("closed", &true)
                .finish_non_exhaustive();
        }
        f.debug_struct("NodeDiskFile")
            .field("root", &self.0.root)
            .field("relative", &self.0.relative)
            .field("identity", &self.0.identity)
            .finish_non_exhaustive()
    }
}

// One serialized preparation owns its preallocated payload and custody slot
// before the first descriptor. A failed or unwound operation transfers that
// payload into State; it cannot unwind a raw File outside installed custody.
struct FilePreparation<'a> {
    disk: &'a Arc<NodeDisk>,
    resources: Option<FileResources>,
    state: Option<std::sync::MutexGuard<'a, State>>,
    executing: bool,
}
impl FilePreparation<'_> {
    fn acquire_parent(&mut self) -> io::Result<()> {
        let resources = self.resources.as_mut().expect("prepared resources");
        let state = self.state.as_mut().expect("prepared serialization");
        let result = resources.parent.as_mut().expect("prepared parent").acquire(
            self.disk,
            state,
            &resources.root,
            &resources.parent_names,
        );
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                self.disk.fail_locked(state);
                Err(resources.record_error(error))
            }
        }
    }
    fn error(&mut self, error: io::Error) -> io::Error {
        self.executing = false;
        let resources = self.resources.as_ref().expect("prepared resources");
        if self.state.as_ref().expect("prepared serialization").phase == NodeDiskPhase::Failed
            || resources.has_failure()
        {
            resources.record_error(error)
        } else {
            error
        }
    }
}
impl Drop for FilePreparation<'_> {
    fn drop(&mut self) {
        let Some(mut resources) = self.resources.take() else {
            return;
        };
        let state = self.state.as_mut().expect("custody retains serialization");
        let retain =
            self.executing || resources.has_failure() || state.phase == NodeDiskPhase::Failed;
        let closed = resources.close_descriptors();
        if retain || closed.is_err() {
            self.disk.fail_locked(state);
            state.file_custody.retain(resources);
        } else {
            let slot = resources.custody_slot;
            // No native handle or owned backing remains when admission returns.
            drop(resources);
            state.file_custody.release(slot);
        }
    }
}

pub(super) struct PreparedFile<'a> {
    prepared: FilePreparation<'a>,
    device: u64,
    create: bool,
    work: Option<DiskWork>,
    admitted_growth: Option<(u64, u64)>,
}
impl PreparedFile<'_> {
    #[cfg(test)]
    pub(super) fn parent_descriptor(&self) -> std::os::fd::RawFd {
        self.prepared
            .resources
            .as_ref()
            .expect("prepared resources")
            .parent
            .as_ref()
            .expect("prepared parent")
            .file()
            .as_raw_fd()
    }
    pub(super) fn execute(mut self) -> io::Result<NodeDiskFile> {
        self.prepared.executing = true;
        let result = execute_prepared(
            self.prepared.disk,
            self.prepared
                .state
                .as_mut()
                .expect("prepared serialization"),
            self.prepared
                .resources
                .as_mut()
                .expect("prepared resources"),
            self.create,
            self.work,
            self.device,
            self.admitted_growth,
        );
        let identity = match result {
            Ok(identity) => identity,
            Err(error) => return Err(self.prepared.error(error)),
        };
        let mut resources = self.prepared.resources.take().expect("prepared resources");
        let mut allocation = resources
            .allocation
            .take()
            .expect("prepared owner allocation");
        resources.identity = identity;
        Arc::get_mut(&mut allocation)
            .expect("unpublished owner allocation")
            .write(FileOwner {
                disk: self.prepared.disk.clone(),
                resources,
            });
        // SAFETY: the sole allocation is fully initialized; registration is infallible.
        let mut owner = unsafe { allocation.assume_init() };
        let registration = Arc::as_ptr(&owner) as usize;
        Arc::get_mut(&mut owner)
            .expect("unregistered owner")
            .registration = registration;
        let state = self
            .prepared
            .state
            .as_mut()
            .expect("prepared serialization");
        state.open_files += 1;
        state.live.insert(identity, Arc::downgrade(&owner));
        Ok(NodeDiskFile(OwnedFileArc::new(owner)))
    }
}
fn execute_prepared(
    disk: &Arc<NodeDisk>,
    state: &mut State,
    resources: &mut FileResources,
    create: bool,
    work: Option<DiskWork>,
    device: u64,
    admitted_growth: Option<(u64, u64)>,
) -> io::Result<Identity> {
    verify_parent(
        &disk.roots[&resources.root],
        &resources.parent_names,
        resources.parent.as_ref().expect("prepared parent"),
    )
    .inspect_err(|_| disk.fail_locked(state))?;
    if create {
        let result = verify_parent(
            &disk.roots[&resources.root],
            &resources.parent_names,
            resources.parent.as_ref().expect("prepared parent"),
        )
        .and_then(|()| {
            require_unenrolled_target(
                state,
                resources.binding,
                resources.parent.as_ref().expect("prepared parent").file(),
                resources.name.as_ref().expect("prepared name"),
                device,
                disk.unit,
            )
        });
        if let Err(error) = result {
            if error.kind() != io::ErrorKind::AlreadyExists {
                disk.fail_locked(state);
            }
            return Err(error);
        }
    }
    let mut transition = if create {
        Some(ParentTransition::prepare(
            disk,
            state,
            (
                resources
                    .parent
                    .as_ref()
                    .expect("prepared parent")
                    .identity(),
                1,
            ),
            None,
            work,
        )?)
    } else {
        None
    };
    let flags = libc::O_RDWR
        | libc::O_NONBLOCK
        | if create {
            libc::O_CREAT | libc::O_EXCL
        } else {
            0
        };
    resources.provisional_file = Some(
        match census::open_at(
            resources.parent.as_ref().expect("prepared parent").file(),
            resources.name.as_ref().expect("prepared name"),
            flags,
        ) {
            Ok(file) => file,
            Err(error) => {
                if create
                    && error.kind() == io::ErrorKind::AlreadyExists
                    && let Err(rollback) = transition
                        .take()
                        .expect("prepared creation parent")
                        .unchanged(
                            disk,
                            state,
                            &[resources.parent.as_ref().expect("prepared parent")],
                        )
                {
                    disk.fail_locked(state);
                    return Err(rollback);
                }
                // An absent final leaf is harmless only if its complete name
                // was never enrolled and the prepared parent is still rooted.
                if !create
                    && error.kind() == io::ErrorKind::NotFound
                    && !state
                        .accounted
                        .values()
                        .filter_map(AccountedInode::file)
                        .any(|entry| entry.binding == resources.binding)
                {
                    if let Err(error) = verify_parent(
                        &disk.roots[&resources.root],
                        &resources.parent_names,
                        resources.parent.as_ref().expect("prepared parent"),
                    ) {
                        disk.fail_locked(state);
                        return Err(error);
                    }
                    return Err(error);
                }
                // A create-only conflict did not mutate the existing object.
                if !create || error.kind() != io::ErrorKind::AlreadyExists {
                    disk.fail_locked(state);
                }
                return Err(error);
            }
        },
    );
    let file = resources
        .provisional_file
        .as_ref()
        .expect("retained acquired file");
    let mut already_owned = false;
    let inspected = (|| -> io::Result<(Identity, AccountedFile)> {
        let metadata = file.metadata()?;
        census::regular_nonallocating(&metadata, device)?;
        let identity = Identity::of(&metadata);
        // A live inode under a different enrolled name is substitution,
        // never a harmless second open of its retained descriptor.
        if !create
            && state
                .accounted
                .get(&identity)
                .is_some_and(|entry| entry.binding() != resources.binding)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if state.live.contains_key(&identity) {
            // This is an exclusive open, never an implicit owner clone.
            already_owned = true;
            return Err(io::ErrorKind::WouldBlock.into());
        }
        census::lock_nonallocating(file, libc::LOCK_EX)?;
        let metadata = file.metadata()?;
        census::regular_nonallocating(&metadata, device)?;
        if Identity::of(&metadata) != identity {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let (bytes, pending) = extent(&metadata, disk.unit)?;
        Ok((
            identity,
            AccountedFile::durable(resources.binding, bytes, pending, metadata.len()),
        ))
    })();
    let (identity, mut enrolled) = match inspected {
        Ok(value) => value,
        Err(error) => {
            // A still-live registered owner makes an attempted second open
            // harmless; all physical verification failures seal admission.
            if !already_owned || create {
                disk.fail_locked(state);
            }
            return Err(error);
        }
    };
    if create {
        if state.accounted.contains_key(&identity) || enrolled.bytes != 0 {
            disk.fail_locked(state);
            return Err(io::ErrorKind::InvalidData.into());
        }
        let Some(files) = state.files.checked_add(1) else {
            disk.fail_locked(state);
            return Err(io::ErrorKind::InvalidData.into());
        };
        // Both tables have reserved capacity. Even this provisional inode
        // survives a failed durability step in the retained census ledger.
        state.accounted.insert(
            identity,
            AccountedInode::File(AccountedFile {
                settled: false,
                ..enrolled
            }),
        );
        state.files = files;
        let durable = (|| -> io::Result<()> {
            #[cfg(test)]
            disk.namespace_checkpoint(NamespaceFailure::CreateFileSync)?;
            file.sync_all()?;
            #[cfg(test)]
            disk.namespace_checkpoint(NamespaceFailure::CreateParentSync)?;
            resources
                .parent
                .as_ref()
                .expect("prepared parent")
                .file()
                .sync_all()?;
            verify_parent(
                &disk.roots[&resources.root],
                &resources.parent_names,
                resources.parent.as_ref().expect("prepared parent"),
            )?;
            transition.take().expect("prepared creation parent").settle(
                disk,
                state,
                &[resources.parent.as_ref().expect("prepared parent")],
            )
        })();
        if let Err(error) = durable {
            disk.fail_locked(state);
            return Err(error);
        }
        *state
            .accounted
            .get_mut(&identity)
            .and_then(AccountedInode::file_mut)
            .expect("new enrolled inode") = enrolled;
    } else if state
        .accounted
        .get(&identity)
        .and_then(AccountedInode::file)
        != Some(&enrolled)
    {
        disk.fail_locked(state);
        return Err(io::ErrorKind::InvalidData.into());
    }
    if let Some((bytes, length)) = admitted_growth {
        // The batch already charged this exact future file. Transfer its
        // full promise into the inode ledger/budget without a second reserve.
        enrolled.bytes = bytes;
        enrolled.pending = bytes;
        enrolled.reserved_len = length;
        enrolled.settled = length == 0;
        *state
            .accounted
            .get_mut(&identity)
            .and_then(AccountedInode::file_mut)
            .expect("admitted new inode") = enrolled;
    }
    resources
        .parent
        .as_mut()
        .expect("prepared parent")
        .register(disk, state)
        .inspect_err(|_| disk.fail_locked(state))?;
    *resources
        .budget
        .as_mut()
        .expect("prepared budget")
        .get_mut()
        .expect("unpublished budget") = Budget {
        file: resources.provisional_file.take(),
        bytes: enrolled.bytes,
        pending: enrolled.pending,
        reserved_len: enrolled.reserved_len,
        actual_len: enrolled.actual_len,
        settled: enrolled.settled,
        close_outcome: None,
    };
    Ok(identity)
}

// Destination preparation unlocks before the source owner's recursive Drop.
pub(super) struct PreparedPublication<'a> {
    prepared: Option<FilePreparation<'a>>,
    retained: Option<FileOwner>,
}
impl Drop for PreparedPublication<'_> {
    fn drop(&mut self) {
        drop(self.prepared.take());
        drop(self.retained.take());
    }
}
impl PreparedPublication<'_> {
    #[cfg(test)]
    pub(super) fn parent_descriptor(&self) -> std::os::fd::RawFd {
        self.prepared
            .as_ref()
            .expect("prepared destination")
            .resources
            .as_ref()
            .expect("prepared resources")
            .parent
            .as_ref()
            .expect("prepared parent")
            .file()
            .as_raw_fd()
    }
    pub(super) fn execute(mut self) -> io::Result<NodeDiskFile> {
        let prepared = self.prepared.as_mut().expect("prepared destination");
        prepared.executing = true;
        let result = execute_publication(
            prepared.disk,
            prepared.state.as_mut().expect("prepared serialization"),
            prepared.resources.as_mut().expect("prepared resources"),
            self.retained.as_mut().expect("retained publication owner"),
        );
        if let Err(error) = result {
            return Err(prepared.error(error));
        }
        prepared.executing = false;
        let target = prepared.resources.as_mut().expect("prepared resources");
        let mut allocation = target.allocation.take().expect("prepared owner allocation");
        Arc::get_mut(&mut allocation)
            .expect("unpublished publication allocation")
            .write(self.retained.take().expect("retained publication owner"));
        // SAFETY: initialized exactly once above; only infallible registration follows.
        let mut retained = OwnedFileArc::new(unsafe { allocation.assume_init() });
        let registration = Arc::as_ptr(&retained) as usize;
        Arc::get_mut(&mut retained)
            .expect("unregistered publication Arc")
            .registration = registration;
        *prepared
            .state
            .as_mut()
            .expect("prepared serialization")
            .live
            .get_mut(&retained.identity)
            .expect("retained publication slot") = Arc::downgrade(&retained);
        Ok(NodeDiskFile(retained))
    }
}
fn execute_publication(
    disk: &Arc<NodeDisk>,
    state: &mut State,
    target: &mut FileResources,
    retained: &mut FileOwner,
) -> io::Result<()> {
    let mut renamed = false;
    let mut transition = None;
    let result = (|| -> io::Result<()> {
        let owner = &mut *retained;
        if state.phase != NodeDiskPhase::Open || !disk.device.lock().admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        {
            let budget = owner
                .budget()
                .lock()
                .map_err(|_| io::ErrorKind::InvalidData)?;
            owner.check_enrollment(state, &budget)?;
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
        verify_parent(
            &disk.roots[&target.root],
            &target.parent_names,
            target.parent.as_ref().expect("prepared destination parent"),
        )?;
        require_unenrolled_target(
            state,
            target.binding,
            target
                .parent
                .as_ref()
                .expect("prepared destination parent")
                .file(),
            target.name.as_ref().expect("prepared destination name"),
            owner.identity.0,
            disk.unit,
        )?;
        transition = Some(ParentTransition::prepare(
            disk,
            state,
            (owner.parent_custody().identity(), -1),
            Some((
                target
                    .parent
                    .as_ref()
                    .expect("prepared destination parent")
                    .identity(),
                1,
            )),
            Some(DiskWork::Maintenance),
        )?);
        #[cfg(target_os = "linux")]
        let status = unsafe {
            libc::renameat2(
                owner.parent().as_raw_fd(),
                owner.name().as_ptr(),
                target
                    .parent
                    .as_ref()
                    .expect("prepared destination parent")
                    .file()
                    .as_raw_fd(),
                target
                    .name
                    .as_ref()
                    .expect("prepared destination name")
                    .as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        let status = unsafe {
            libc::renameatx_np(
                owner.parent().as_raw_fd(),
                owner.name().as_ptr(),
                target
                    .parent
                    .as_ref()
                    .expect("prepared destination parent")
                    .file()
                    .as_raw_fd(),
                target
                    .name
                    .as_ref()
                    .expect("prepared destination name")
                    .as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if status != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::AlreadyExists {
                transition
                    .take()
                    .expect("prepared publication parents")
                    .unchanged(
                        disk,
                        state,
                        &[
                            owner.parent_custody(),
                            target.parent.as_ref().expect("prepared destination parent"),
                        ],
                    )?;
            }
            return Err(error);
        }
        renamed = true;
        assert!(
            owner.retiring_parent.is_none(),
            "one prepared parent transfer"
        );
        owner.retiring_parent = owner
            .parent
            .replace(target.parent.take().expect("prepared destination parent"));
        let old_root = std::mem::replace(&mut owner.root, std::mem::take(&mut target.root));
        owner.relative = std::mem::take(&mut target.relative);
        let old_parent_names = std::mem::replace(
            &mut owner.parent_names,
            std::mem::replace(&mut target.parent_names, Box::new([])),
        );
        owner.name = target.name.take();
        owner.binding = target.binding;
        // The source name stopped owning this inode at the rename. Update
        // the retained slot before any fallible durability step.
        state
            .accounted
            .get_mut(&owner.identity)
            .and_then(AccountedInode::file_mut)
            .expect("validated publication enrollment")
            .binding = target.binding;
        // The descriptor now belongs to the new name even if durability or
        // post-publication verification fails. Every error remains inline.
        #[cfg(test)]
        disk.namespace_checkpoint(NamespaceFailure::PublishSourceSync)?;
        owner
            .retiring_parent
            .as_ref()
            .expect("retained source parent")
            .file()
            .sync_all()?;
        #[cfg(test)]
        disk.namespace_checkpoint(NamespaceFailure::PublishDestinationSync)?;
        owner.parent().sync_all()?;
        verify_parent(
            &disk.roots[&old_root],
            &old_parent_names,
            owner
                .retiring_parent
                .as_ref()
                .expect("retained source parent"),
        )?;
        #[cfg(test)]
        disk.namespace_checkpoint(NamespaceFailure::PublishVerify)?;
        let budget = owner
            .budget()
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
        drop(budget);
        transition
            .take()
            .expect("prepared publication parents")
            .settle(
                disk,
                state,
                &[
                    owner
                        .retiring_parent
                        .as_ref()
                        .expect("retained source parent"),
                    owner.parent_custody(),
                ],
            )?;
        owner
            .retiring_parent
            .as_mut()
            .expect("retained source parent")
            .close_resources()?;
        let old = owner
            .retiring_parent
            .take()
            .expect("retained source parent")
            .retire_drained()
            .expect("registered source parent");
        if !namespace::can_retire_parent(state, old) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        namespace::retire_parent(state, old);
        owner
            .parent
            .as_mut()
            .expect("retained destination parent")
            .register(disk, state)?;
        Ok(())
    })();
    if let Err(error) = result {
        if renamed || error.kind() != io::ErrorKind::AlreadyExists {
            disk.fail_locked(state);
            return Err(retained.record_error(error));
        }
        return Err(error);
    }
    Ok(())
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
        self.prepare_file_with_admission(root, relative, create, None)
    }

    pub(crate) fn create_admitted_file(
        self: &Arc<Self>,
        admission: &mut super::batch::NamespaceAdmission,
        root: &str,
        relative: &Path,
    ) -> io::Result<NodeDiskFile> {
        if !admission.same_disk(self) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let work = admission.work(&self.lock_state())?;
        let result = self
            .prepare_file_with_admission(root, relative, Some(work), Some(admission))
            .and_then(PreparedFile::execute);
        if result.is_err() {
            self.fail();
        }
        result
    }

    fn prepare_file_with_admission<'a>(
        self: &'a Arc<Self>,
        root: &str,
        relative: &Path,
        create: Option<DiskWork>,
        mut admission: Option<&mut super::batch::NamespaceAdmission>,
    ) -> io::Result<PreparedFile<'a>> {
        let mut state = self.lock_state();
        if state.phase != NodeDiskPhase::Open {
            return Err(io::ErrorKind::Other.into());
        }
        let admitted = if let Some(admission) = admission.as_mut() {
            // Compute the exact bound name without opening a descriptor, then
            // transfer under the State guard held through the create operation.
            let selected = self.roots.get(root).ok_or(io::ErrorKind::InvalidInput)?;
            let names = super::directory::names(
                relative,
                self.config.max_depth,
                self.config.max_name_bytes,
            )?;
            if names.is_empty() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let binding = names
                .iter()
                .fold(NamespaceBinding::root(selected.identity), |b, name| {
                    b.child(name)
                });
            Some(admission.take_file(&mut state, root, binding)?)
        } else {
            None
        };
        // Retiring registrations remain exclusive until BOTH descriptors and
        // their metadata backing are gone; strong_count == 0 is not drain.
        if state
            .open_files
            .checked_add(super::batch::reserved_files(&state))
            .is_none_or(|n| n >= self.config.max_open_files)
        {
            return Err(io::ErrorKind::StorageFull.into());
        }
        if let Some(work) = create {
            if state
                .files
                .checked_add(u64::from(super::batch::reserved_files(&state)))
                .is_none_or(|n| n >= self.config.max_persistent_files)
            {
                return Err(io::ErrorKind::StorageFull.into());
            }
            self.reserve(&mut state, 0, work)?;
            let required = 1 + super::batch::reserved_entries(&state);
            state
                .accounted
                .try_reserve(required)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
        }
        let required = 1 + super::batch::reserved_files(&state) as usize;
        state
            .live
            .try_reserve(required)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let selected = self.roots.get(root).ok_or(io::ErrorKind::InvalidInput)?;
        let (name, parent_names, binding) =
            prepare_file_names(selected.identity, relative, &self.config)?;
        if create.is_some() && super::batch::reserved_binding(&state, binding) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let parent = RetainedParent::prepare_storage(self, root, &parent_names)?;
        let budget = Mutex::new(Budget {
            file: None,
            bytes: 0,
            pending: 0,
            reserved_len: 0,
            actual_len: 0,
            settled: false,
            close_outcome: None,
        });
        drop(budget.lock().expect("unpublished budget"));
        let original_error = Mutex::new(None);
        drop(original_error.lock().expect("unpublished original outcome"));
        let (allocation, admitted_growth) = match admitted {
            Some((allocation, bytes, length)) => (allocation, Some((bytes, length))),
            None => (Arc::<FileOwner>::new_uninit(), None),
        };
        let mut resources = FileResources {
            root: root.to_owned(),
            relative: relative.to_owned(),
            parent_names,
            parent: Some(parent),
            retiring_parent: None,
            retired_parent: None,
            name: Some(name),
            identity: Identity(0, 0),
            binding,
            budget: Some(budget),
            registration: 0,
            custody_slot: usize::MAX,
            allocation: Some(allocation),
            provisional_file: None,
            provisional_close: None,
            original_error: Some(original_error),
            close_attempt: CloseAttempt::Unattempted,
        };
        resources.custody_slot = state.file_custody.reserve()?;
        let mut prepared = FilePreparation {
            disk: self,
            resources: Some(resources),
            state: Some(state),
            executing: false,
        };
        prepared.acquire_parent()?;
        Ok(PreparedFile {
            prepared,
            device: selected.identity.0,
            create: create.is_some(),
            work: create,
            admitted_growth,
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
        file.ensure_open()?;
        if !Arc::ptr_eq(self, &file.0.disk) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Hold the same serialization through all charged preparation and acquisition.
        let mut state = self.lock_state();
        if state.phase != NodeDiskPhase::Open || !self.device.lock().admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        let selected = self.roots.get(root).ok_or(io::ErrorKind::InvalidInput)?;
        let (name, parent_names, binding) =
            prepare_file_names(selected.identity, relative, &self.config)?;
        if super::batch::reserved_binding(&state, binding) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let parent = RetainedParent::prepare_storage(self, root, &parent_names)?;
        let original_error = Mutex::new(None);
        drop(original_error.lock().expect("unpublished original outcome"));
        let mut resources = FileResources {
            root: root.to_owned(),
            relative: relative.to_owned(),
            parent_names,
            parent: Some(parent),
            retiring_parent: None,
            retired_parent: None,
            name: Some(name),
            identity: Identity(0, 0),
            binding,
            budget: None,
            registration: 0,
            custody_slot: usize::MAX,
            allocation: Some(Arc::<FileOwner>::new_uninit()),
            provisional_file: None,
            provisional_close: None,
            original_error: Some(original_error),
            close_attempt: CloseAttempt::Unattempted,
        };
        resources.custody_slot = state.file_custody.reserve()?;
        let prepared = FilePreparation {
            disk: self,
            resources: Some(resources),
            state: Some(state),
            executing: false,
        };
        // Never acquire a destination FD for an owner which cannot transfer.
        let retained = match file.0.try_unwrap() {
            Ok(owner) => owner,
            Err(owner) => {
                drop(prepared);
                drop(owner);
                return Err(io::ErrorKind::WouldBlock.into());
            }
        };
        let mut result = PreparedPublication {
            prepared: Some(prepared),
            retained: Some(retained),
        };
        result
            .prepared
            .as_mut()
            .expect("prepared destination")
            .acquire_parent()?;
        Ok(result)
    }

    fn reclaim(&self, file: NodeDiskFile, len: Option<u64>) -> io::Result<()> {
        file.ensure_open()?;
        if !std::ptr::eq(self, Arc::as_ptr(&file.0.disk)) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut owner;
        let mut state = self.lock_state();
        owner = match file.0.try_unwrap() {
            Ok(owner) => owner,
            Err(owner) => {
                drop(state);
                drop(owner);
                return Err(io::ErrorKind::WouldBlock.into());
            }
        };
        if owner.budget().is_poisoned()
            || state.phase == NodeDiskPhase::Failed
            || !self.device.lock().admission_ready()
        {
            self.fail_locked(&mut state);
            drop(state);
            drop(owner);
            return Err(io::ErrorKind::Other.into());
        }
        let mut budget = owner
            .budget()
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
        let actual = budget.file.as_ref().expect("live persistent descriptor");
        let result = (|| -> io::Result<(u64, u64)> {
            owner.verify(actual)?;
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
                owner.verify(actual)?;
                if actual.metadata()?.len() != len {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                #[cfg(test)]
                self.namespace_checkpoint(NamespaceFailure::ReclaimParentSync)?;
                owner.parent().sync_all()?;
                extent(&actual.metadata()?, self.unit)
            } else {
                actual.sync_all()?;
                let transition = ParentTransition::prepare(
                    self,
                    &mut state,
                    (owner.parent_custody().identity(), -1),
                    None,
                    None,
                )?;
                if unsafe { libc::unlinkat(owner.parent().as_raw_fd(), owner.name().as_ptr(), 0) }
                    != 0
                {
                    return Err(io::Error::last_os_error());
                }
                #[cfg(test)]
                self.namespace_checkpoint(NamespaceFailure::ReclaimParentSync)?;
                owner.parent().sync_all()?;
                verify_parent(
                    &self.roots[&owner.root],
                    &owner.parent_names,
                    owner.parent_custody(),
                )?;
                transition.settle(self, &mut state, &[owner.parent_custody()])?;
                Ok((0, 0))
            }
        })();
        // Every native descriptor stays in the admitted payload through one
        // observed close; failure transfers its original outcome without credit.
        let result = result.map_err(|error| owner.record_error(error));
        let closed = {
            let budget = &mut *budget;
            super::native_file::close(&mut budget.file, &mut budget.close_outcome)
        };
        let old_bytes = budget.bytes;
        let old_pending = budget.pending;
        drop(budget);
        if let Err(error) = closed {
            owner.retain_locked(&mut state);
            return Err(error);
        }
        let result = match result {
            Ok(value) => Ok(value),
            Err(error) => {
                let _closed = owner.resources.close_descriptors();
                #[cfg(test)]
                owner.close_checkpoint(CloseStage::ResourcesRetained);
                owner.retain_locked(&mut state);
                return Err(error);
            }
        };
        if let Err(error) = owner.retire_resources() {
            owner.retain_locked(&mut state);
            return Err(error);
        }
        if !owner.retire_registration(&mut state) {
            owner.retain_locked(&mut state);
            return Err(io::ErrorKind::InvalidData.into());
        }
        let outcome = match result {
            Ok((bytes, pending)) if bytes <= old_bytes => {
                let mut promises = self.device.lock();
                let next = promises
                    .checked_sub(old_pending)
                    .and_then(|n| n.checked_add(pending));
                let own_next = state
                    .pending
                    .checked_sub(old_pending)
                    .and_then(|n| n.checked_add(pending));
                let owned = state
                    .bytes
                    .checked_sub(old_bytes)
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
                                        .and_then(AccountedInode::file_mut)
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
        drop(state);
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
    if super::batch::reserved_binding(state, binding) {
        return Err(io::ErrorKind::WouldBlock.into());
    }

    let Some((identity, enrolled)) = state
        .accounted
        .iter()
        .filter_map(|(identity, entry)| entry.file().map(|file| (identity, file)))
        .find(|(_, entry)| entry.binding == binding)
    else {
        return Ok(());
    };
    let metadata = stat_leaf(parent, name, device)?;
    let length = u64::try_from(metadata.st_size).map_err(|_| io::ErrorKind::InvalidData)?;
    let allocated = u64::try_from(metadata.st_blocks)
        .map_err(|_| io::ErrorKind::InvalidData)?
        .checked_mul(512)
        .ok_or(io::ErrorKind::InvalidData)?;
    let bytes = rounded(length.max(allocated), unit)?;
    let pending = bytes - allocated;
    if metadata.st_ino != identity.1
        || length != enrolled.actual_len
        || enrolled.actual_len > enrolled.reserved_len
        || bytes > enrolled.bytes
        || (enrolled.settled
            && *enrolled != AccountedFile::durable(binding, bytes, pending, length))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // An unsettled live target can retain unused growth promises or contain
    // admitted writes not yet reflected in pending physical materialization.
    // Verify its exact known EOF and full allowance without releasing credit.
    Err(io::ErrorKind::AlreadyExists.into())
}

// A single validated C-string component plus NOFOLLOW never follows an
// intermediate symlink. All ancestors have already been checked by custody.
fn stat_leaf(parent: &File, name: &std::ffi::CStr, device: u64) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent is retained, name is NUL-terminated, and stat is writable.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatat initializes the complete native structure.
    let stat = unsafe { stat.assume_init() };
    let observed_device = u64::try_from(stat.st_dev).map_err(|_| io::ErrorKind::InvalidData)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_nlink != 1
        || observed_device != device
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if stat.st_uid != unsafe { libc::geteuid() } || stat.st_mode & 0o077 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(stat)
}

fn verify_parent(
    root: &census::Root,
    names: &[CString],
    retained: &RetainedParent,
) -> io::Result<()> {
    retained.verify_file(root, names)
}

fn prepare_file_names(
    root: Identity,
    relative: &Path,
    config: &super::NodeDiskConfig,
) -> io::Result<(CString, Box<[CString]>, NamespaceBinding)> {
    use std::os::unix::ffi::OsStrExt;
    let parent_names = prepare_parent_names(relative, config)?;
    let leaf = relative
        .components()
        .next_back()
        .ok_or(io::ErrorKind::InvalidInput)?;
    let std::path::Component::Normal(leaf) = leaf else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    if leaf.len() > config.max_name_bytes as usize
        || parent_names.len() >= config.max_depth as usize
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let name = CString::new(leaf.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?;
    let parent = parent_names
        .iter()
        .fold(NamespaceBinding::root(root), |binding, name| {
            binding.child(name)
        });
    let binding = parent.child(&name);
    Ok((name, parent_names, binding))
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
    fn name(&self) -> &CString {
        self.name.as_ref().expect("live file name")
    }
    fn parent(&self) -> &File {
        self.parent_custody().file()
    }
    fn parent_custody(&self) -> &RetainedParent {
        self.parent.as_ref().expect("live parent custody")
    }
    fn budget(&self) -> &Mutex<Budget> {
        self.budget.as_ref().expect("live file budget")
    }

    fn check_enrollment(&self, state: &mut State, budget: &Budget) -> io::Result<()> {
        if state
            .accounted
            .get(&self.identity)
            .and_then(AccountedInode::file)
            != Some(&budget.accounted(self.binding))
        {
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
            .and_then(AccountedInode::file_mut)
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
        self.budget().lock().map_err(|_| {
            self.disk.fail();
            io::Error::from(io::ErrorKind::InvalidData)
        })
    }
    fn verify(&self, file: &File) -> io::Result<()> {
        let result = (|| {
            verify_parent(
                &self.disk.roots[&self.root],
                &self.parent_names,
                self.parent_custody(),
            )?;
            let metadata = stat_leaf(self.parent(), self.name(), self.identity.0)?;
            if metadata.st_ino != self.identity.1
                || Identity::of(&file.metadata()?) != self.identity
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(())
        })();
        result.map_err(|error| self.record_error(error))
    }

    fn check(&self, file: &File) -> io::Result<()> {
        // Keep the same State gate through the complete temporary-descriptor
        // walk. A sealed owner cannot begin another verification acquisition.
        let mut state = self.disk.lock_state();
        if state.phase == NodeDiskPhase::Failed || !self.disk.device.lock().admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        self.verify(file)
            .inspect_err(|_| self.disk.fail_locked(&mut state))
    }

    fn observe(&self, budget: &mut Budget) -> io::Result<()> {
        let file = budget.file.as_ref().expect("live persistent descriptor");
        self.check(file)?;
        let metadata = file.metadata().map_err(|error| {
            self.disk.fail();
            self.record_error(error)
        })?;
        let (observed, _) = extent(&metadata, self.disk.unit).map_err(|error| {
            self.disk.fail();
            self.record_error(error)
        })?;
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
    fn ensure_open(&self) -> io::Result<()> {
        let owner = self.0.0.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
        let mutex = owner.budget.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
        let budget = mutex.lock().map_err(|_| {
            owner.disk.fail();
            io::Error::from(io::ErrorKind::InvalidData)
        })?;
        if budget.file.is_none() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }

    /// Retire the sole file owner explicitly. A failed attempt leaves this exact
    /// Arc and its original native/owner outcomes retained; the returned error
    /// is only an errno/kind projection. An uncertain native close is never retried.
    /// Success follows descriptor, heap backing, Arc and registration retirement.
    /// A successfully closed handle remains closed and may be closed again.
    pub fn close(&mut self) -> io::Result<()> {
        let Some(owner) = self.0.0.as_ref() else {
            return Ok(());
        };
        let disk = owner.disk.clone();
        if disk.state.is_poisoned() {
            return Err(io::ErrorKind::Other.into());
        }
        let mut state = disk.lock_state();
        let identity = owner.identity;
        let registration = owner.registration;
        if registration == 0
            || !state
                .live
                .get(&identity)
                .is_some_and(|entry| entry.as_ptr() as usize == registration)
        {
            disk.fail_locked(&mut state);
            return Err(owner.record_error(io::ErrorKind::InvalidData.into()));
        }
        // Every registry upgrade holds State. No other strong/weak owner may
        // survive this gate, so the original allocation can be borrowed mutably.
        if Arc::strong_count(owner) != 1 || Arc::weak_count(owner) != 1 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        // Keep the occupied map slot and every credit while releasing its Weak.
        // Replacing the value needs no HashMap insertion or new allocation.
        drop(std::mem::replace(
            state
                .live
                .get_mut(&identity)
                .expect("validated live registration"),
            std::sync::Weak::new(),
        ));
        let mut close = ExplicitClose {
            owner: &mut self.0,
            state,
            identity,
            executing: false,
        };
        let failed =
            close.state.phase == NodeDiskPhase::Failed || !disk.device.lock().admission_ready();
        let owner = Arc::get_mut(&mut *close.owner).expect("exclusive original owner");
        if let CloseAttempt::Failed(_) = owner.close_attempt {
            return Err(owner
                .resources
                .failure_projection()
                .unwrap_or_else(|| io::ErrorKind::Other.into()));
        }
        if matches!(owner.close_attempt, CloseAttempt::Executing) {
            return Err(io::ErrorKind::Other.into());
        }
        if let Some(error) = owner.resources.close_projection() {
            return Err(error);
        }
        if owner.budget.is_none() || owner.original_error.is_none() {
            // A previous retirement unwound after retiring this backing but
            // before credit. Preserve that exact owner without rebuilding an
            // error slot, retrying a descriptor, or fabricating positive close.
            close.executing = true;
            return Err(io::ErrorKind::Other.into());
        }
        let settled = owner.budget.as_mut().is_some_and(|mutex| {
            let poisoned = mutex.is_poisoned();
            let budget = mutex.get_mut().unwrap_or_else(|poison| poison.into_inner());
            !poisoned && budget.settled
        });
        // Re-observing a completed or interrupted attempt consumes no new
        // generation. Check capacity only at a genuinely new effect boundary.
        let attempt = close
            .state
            .file_close_generation
            .checked_add(1)
            .ok_or(io::ErrorKind::Other)?;
        close.executing = true;
        close.state.file_close_generation = attempt;
        owner.close_attempt = CloseAttempt::Executing;
        if failed || !settled || owner.resources.has_failure() {
            if !owner.resources.has_failure() {
                let _projected = owner.record_error(if settled {
                    io::ErrorKind::Other.into()
                } else {
                    io::ErrorKind::InvalidData.into()
                });
            }
            if !settled
                && let Some(enrolled) = close
                    .state
                    .accounted
                    .get_mut(&identity)
                    .and_then(AccountedInode::file_mut)
            {
                enrolled.settled = false;
            }
            let native = owner.resources.close_descriptors();
            owner.close_attempt = CloseAttempt::Failed(attempt);
            return Err(owner
                .resources
                .failure_projection()
                .unwrap_or_else(|| native.err().unwrap_or_else(|| io::ErrorKind::Other.into())));
        }
        // All fallible bookkeeping checks precede descriptor/heap retirement.
        let next = close
            .state
            .open_files
            .checked_sub(1)
            .ok_or_else(|| owner.record_error(io::ErrorKind::InvalidData.into()))?;
        let parent = owner
            .parent
            .as_ref()
            .map(RetainedParent::identity)
            .ok_or_else(|| owner.record_error(io::ErrorKind::InvalidData.into()))?;
        if owner.retiring_parent.is_some()
            || owner.retired_parent.is_some()
            || !namespace::can_retire_parent(&close.state, parent)
            || !close.state.file_custody.reserved_empty(owner.custody_slot)
        {
            return Err(owner.record_error(io::ErrorKind::InvalidData.into()));
        }
        let slot = owner.custody_slot;
        if let Err(projected) = owner.retire_resources() {
            owner.close_attempt = CloseAttempt::Failed(attempt);
            return Err(owner.resources.failure_projection().unwrap_or(projected));
        }
        assert_eq!(
            owner.retired_parent,
            Some(parent),
            "validated parent retirement"
        );
        owner.retired_parent = None;
        owner.registration = 0;
        owner.custody_slot = usize::MAX;
        // FileOwner::drop is now inert. No Weak survives, so this frees the
        // actual original Arc before the counters or custody slot are credited.
        drop(close.owner.0.take());
        drop(close.state.live.remove(&identity));
        namespace::retire_parent(&mut close.state, parent);
        close.state.open_files = next;
        close.state.file_custody.release(slot);
        close.executing = false;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn close_owner_address(&self) -> Option<usize> {
        self.0.0.as_ref().map(|owner| Arc::as_ptr(owner) as usize)
    }
    #[cfg(test)]
    pub(crate) fn close_error_address(&self) -> Option<usize> {
        let owner = self.0.0.as_ref()?;
        if let Some(mutex) = &owner.budget {
            let budget = mutex.lock().unwrap_or_else(|poison| poison.into_inner());
            if let Some(outcome) = &budget.close_outcome {
                return Some(std::ptr::from_ref(&outcome.error) as usize);
            }
        }
        owner.original_error.as_ref().and_then(|mutex| {
            mutex
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .as_ref()
                .map(|error| std::ptr::from_ref(error) as usize)
        })
    }
    #[cfg(test)]
    pub(crate) fn native_close_attempts() -> u64 {
        super::native_file::close_attempts()
    }
    #[cfg(test)]
    pub(super) fn replace_original_close_error(&self, error: io::Error) {
        let owner = self.0.0.as_ref().unwrap();
        assert!(matches!(owner.close_attempt, CloseAttempt::Failed(_)));
        *owner.original_error.as_ref().unwrap().lock().unwrap() = Some(error);
    }
    #[cfg(test)]
    pub(crate) fn fail_next_native_close(errno: i32) {
        super::native_file::fail_next_close(errno);
    }
    #[cfg(test)]
    pub(super) fn fail_parent_close(errno: i32) {
        PARENT_CLOSE_FAILURE.with(|failure| assert!(failure.replace(Some(errno)).is_none()));
    }
    #[cfg(test)]
    pub(crate) fn data_descriptor(&self) -> std::os::fd::RawFd {
        self.0
            .lock_budget()
            .unwrap()
            .file
            .as_ref()
            .unwrap()
            .as_raw_fd()
    }
    #[cfg(test)]
    pub(super) fn parent_descriptor(&self) -> std::os::fd::RawFd {
        self.0.parent().as_raw_fd()
    }

    /// The installed redb adapter uses this before every physical operation.
    /// Failure is represented without allocating an error payload.
    pub fn check_owner(&self) -> io::Result<()> {
        self.ensure_open()?;
        let budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
        self.0.check(file)?;
        let mut state = self.0.disk.lock_state();
        self.0.check_enrollment(&mut state, &budget)?;
        if file
            .metadata()
            .map_err(|error| {
                self.0.disk.fail_locked(&mut state);
                self.0.record_error(error)
            })?
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
        if let Some(owner) = &self.0.0 {
            owner.disk.fail();
        }
    }

    /// Settle unused pre-I/O promises after a commit or aborted transaction.
    /// Sync and verify the exact descriptor before crediting only the difference
    /// between its retained reservation and its actual durable extent. This is
    /// valid with live redb readers because no physical byte is removed.
    pub fn settle_growth(&self, actual_len: u64) -> io::Result<()> {
        self.ensure_open()?;
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
        let (bytes, pending) = outcome.map_err(|error| {
            self.0.disk.fail_locked(&mut state);
            self.0.record_error(error)
        })?;
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
        self.ensure_open()?;
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
        self.ensure_open()?;
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
        let mut budget = match owner.budget().lock() {
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
                return Err(self.0.record_error(error));
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
            owner.parent().sync_all()?;
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
                return Err(self.0.record_error(error));
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
            return Err(self.0.record_error(error));
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
        self.ensure_open()?;
        let budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().expect("live persistent descriptor");
        self.0.check(file)?;
        Ok(file
            .metadata()
            .map_err(|error| {
                self.0.disk.fail();
                self.0.record_error(error)
            })?
            .len())
    }

    /// A synchronous, pre-I/O exact growth reservation. Failure never resizes.
    /// Caller must retain this owner through all backend activity and final sync.
    pub fn reserve_growth(
        &self,
        current_len: u64,
        requested_len: u64,
        work: DiskWork,
    ) -> io::Result<()> {
        self.ensure_open()?;
        let mut budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().expect("live persistent descriptor");
        self.0.check(file)?;
        let actual = file.metadata().map_err(|error| {
            self.0.disk.fail();
            self.0.record_error(error)
        })?;
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
        self.ensure_open()?;
        let mut budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().expect("live persistent descriptor");
        self.0.check(file)?;
        let current = file
            .metadata()
            .map_err(|error| {
                self.0.disk.fail();
                self.0.record_error(error)
            })?
            .len();
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
            return Err(self.0.record_error(error));
        }
        budget.actual_len = len;
        budget.settled = false;
        self.0.record_enrollment(&mut state, &budget);
        Ok(())
    }

    pub fn write_all_at(&self, data: &[u8], offset: u64) -> io::Result<()> {
        self.ensure_open()?;
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
            .map_err(|error| {
                self.0.disk.fail_locked(&mut state);
                self.0.record_error(error)
            })?
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
            return Err(self.0.record_error(error));
        }
        if !data.is_empty() {
            budget.actual_len = budget.actual_len.max(end);
        }
        self.0.record_enrollment(&mut state, &budget);
        Ok(())
    }

    pub fn read_exact_at(&self, out: &mut [u8], offset: u64) -> io::Result<()> {
        self.ensure_open()?;
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
        outcome.map_err(|error| {
            self.0.disk.fail_locked(&mut state);
            self.0.record_error(error)
        })
    }

    /// Verified materialization retires only pending filesystem promises; the
    /// complete persistent extent charge remains after this owner closes.
    pub fn sync_all(&self) -> io::Result<()> {
        self.ensure_open()?;
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
        outcome.map_err(|error| {
            self.0.disk.fail_locked(&mut state);
            self.0.record_error(error)
        })?;
        drop(state);
        self.0.observe(&mut budget)
    }

    /// Durably publish an initialized envelope without releasing or reopening
    /// its descriptor. Growth promises settle only after the file, its held
    /// parent and the exact installed binding have all been verified. Failure
    /// keeps existing charges and fences admission until an exclusive census.
    pub fn sync_all_and_parent(&self) -> io::Result<()> {
        self.ensure_open()?;
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
            self.0.parent().sync_all()?;
            self.0.verify(file)
        })();
        if let Err(error) = outcome {
            self.0.disk.fail_locked(&mut state);
            return Err(self.0.record_error(error));
        }
        drop(state);
        self.0.observe(&mut budget)
    }
}

// State excludes registry upgrades while its occupied slot temporarily holds
// an empty Weak. Failure/unwind restores the original pointer before unlock.
struct ExplicitClose<'a> {
    owner: &'a mut OwnedFileArc,
    state: std::sync::MutexGuard<'a, State>,
    identity: Identity,
    executing: bool,
}
impl Drop for ExplicitClose<'_> {
    fn drop(&mut self) {
        if let Some(owner) = &self.owner.0 {
            *self
                .state
                .live
                .get_mut(&self.identity)
                .expect("retained live registration") = Arc::downgrade(owner);
            if self.executing {
                owner.disk.fail_locked(&mut self.state);
            }
        }
    }
}

impl FileResources {
    fn close_projection(&self) -> Option<io::Error> {
        self.provisional_close
            .as_ref()
            .map(|outcome| super::native_file::projection(&outcome.error))
            .or_else(|| {
                self.budget.as_ref().and_then(|mutex| {
                    mutex
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .close_outcome
                        .as_ref()
                        .map(|outcome| super::native_file::projection(&outcome.error))
                })
            })
            .or_else(|| {
                self.parent
                    .as_ref()
                    .and_then(RetainedParent::close_diagnostic)
                    .map(|(_, errno)| io::Error::from_raw_os_error(errno))
            })
            .or_else(|| {
                self.retiring_parent
                    .as_ref()
                    .and_then(RetainedParent::close_diagnostic)
                    .map(|(_, errno)| io::Error::from_raw_os_error(errno))
            })
    }
    fn failure_projection(&self) -> Option<io::Error> {
        self.close_projection().or_else(|| {
            self.original_error.as_ref().and_then(|mutex| {
                mutex
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .as_ref()
                    .map(super::native_file::projection)
            })
        })
    }
}

impl FileOwner {
    // The caller has exclusive access: Drop moved the value out of its Arc;
    // explicit close borrowed the original allocation under State. Registration
    // credit remains held while descriptors and heap backing retire.
    fn retire_resources(&mut self) -> io::Result<()> {
        if let Some(mutex) = &mut self.resources.budget {
            let budget = mutex.get_mut().unwrap_or_else(|poison| poison.into_inner());
            super::native_file::close(&mut budget.file, &mut budget.close_outcome)?;
        }
        #[cfg(test)]
        self.close_checkpoint(CloseStage::DataClosed);
        #[cfg(test)]
        if let Some(errno) = PARENT_CLOSE_FAILURE.with(std::cell::Cell::take) {
            super::native_file::fail_next_close(errno);
        }
        self.resources.close_descriptors()?;
        if self.resources.has_failure() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        for parent in [
            self.resources.parent.take(),
            self.resources.retiring_parent.take(),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(identity) = parent.retire_drained() {
                assert!(
                    self.resources.retired_parent.replace(identity).is_none(),
                    "one parent registration"
                );
            }
        }
        drop(std::mem::take(&mut self.resources.root));
        drop(std::mem::take(&mut self.resources.relative));
        drop(std::mem::replace(
            &mut self.resources.parent_names,
            Box::new([]),
        ));
        drop(self.resources.name.take());
        drop(self.resources.budget.take());
        drop(self.resources.original_error.take());
        #[cfg(test)]
        self.close_checkpoint(CloseStage::ResourcesClosed);
        Ok(())
    }
    fn retain_locked(&mut self, state: &mut State) {
        let resources = std::mem::replace(&mut self.resources, FileResources::empty());
        self.disk.fail_locked(state);
        state.file_custody.retain(resources);
    }

    #[cfg(test)]
    fn close_checkpoint(&self, stage: CloseStage) {
        let pause = {
            let mut slot = self.disk.after_file_close.lock().unwrap();
            if slot.as_ref().is_some_and(|pause| pause.stage == stage) {
                slot.take()
            } else {
                None
            }
        };
        if let Some(pause) = pause {
            let _ = pause.entered.send(());
            pause
                .release
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("release file retirement fixture");
        }
    }

    fn retire_registration(&mut self, state: &mut State) -> bool {
        if self.registration == 0
            || !state
                .live
                .get(&self.identity)
                .is_some_and(|entry| entry.as_ptr() as usize == self.registration)
        {
            return false;
        }
        let Some(next) = state.open_files.checked_sub(1) else {
            return false;
        };
        let Some(parent) = self.retired_parent else {
            return false;
        };
        if !namespace::can_retire_parent(state, parent) {
            return false;
        }
        // Dropping the exact last Weak frees the original Arc allocation before
        // the slot can fund another handle. No strong/weak reference escapes.
        drop(state.live.remove(&self.identity));
        self.registration = 0;
        namespace::retire_parent(state, parent);
        self.retired_parent = None;
        state.open_files = next;
        state.file_custody.release(self.custody_slot);
        self.custody_slot = usize::MAX;
        true
    }
}

// If a retirement checkpoint or another destructor unwinds, the actual
// unfinished payload moves into its reserved slot before field destruction.
struct Retirement<'a> {
    owner: &'a mut FileOwner,
    armed: bool,
}
impl Drop for Retirement<'_> {
    fn drop(&mut self) {
        if self.armed {
            let disk = self.owner.disk.clone();
            let mut state = disk.lock_state();
            self.owner.retain_locked(&mut state);
        }
    }
}
impl Drop for FileOwner {
    fn drop(&mut self) {
        if self.resources.custody_slot == usize::MAX {
            return;
        }
        let mut retirement = Retirement {
            owner: self,
            armed: true,
        };
        let owner = &mut *retirement.owner;
        let settled = owner.resources.budget.as_mut().is_some_and(|mutex| {
            let poisoned = mutex.is_poisoned();
            let budget = mutex.get_mut().unwrap_or_else(|poison| poison.into_inner());
            !poisoned && budget.settled
        });
        let result = if settled && !owner.resources.has_failure() {
            owner.retire_resources()
        } else {
            let _closed = owner.resources.close_descriptors();
            Err(io::ErrorKind::InvalidData.into())
        };
        let disk = owner.disk.clone();
        let mut state = disk.lock_state();
        if !settled
            && let Some(enrolled) = state
                .accounted
                .get_mut(&owner.identity)
                .and_then(AccountedInode::file_mut)
        {
            enrolled.settled = false;
        }
        if result.is_err() || !owner.retire_registration(&mut state) {
            owner.retain_locked(&mut state);
        }
        retirement.armed = false;
    }
}
