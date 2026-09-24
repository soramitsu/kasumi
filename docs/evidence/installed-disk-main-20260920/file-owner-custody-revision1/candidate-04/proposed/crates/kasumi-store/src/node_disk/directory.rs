//! Enrolled, counted read/sync custody for installed directories.
//!
//! Census establishes exact identities/extents. Prepared child mutations retain
//! affected-parent and unresolved-operation custody under the same State guard.
use super::{
    AccountedDirectory, AccountedInode, Identity, NamespaceBinding, NodeDisk, NodeDiskPhase, State,
    census, namespace,
};
use std::{
    ffi::CString,
    fs::File,
    io,
    path::{Component, Path},
    sync::Arc,
};

pub(super) struct DirectoryOwner {
    disk: Arc<NodeDisk>,
    root: String,
    names: Box<[CString]>,
    identity: Identity,
    file: Option<File>,
    parent: Option<namespace::RetainedParent>,
    registered: bool,
    #[cfg(test)]
    after_close: Option<std::sync::Mutex<Option<ClosePause>>>,
}

/// An operational directory descriptor whose actual close participates in drain.
/// The inner Arc is private: callers can clone custody, not retain an untracked
/// Weak control block after the last physical owner closes.
#[derive(Clone)]
pub struct NodeDiskDirectory(Option<Arc<DirectoryOwner>>);
impl std::fmt::Debug for NodeDiskDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeDiskDirectory")
            .field("identity", &self.owner().identity)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
struct ClosePause {
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

struct LookupFailure {
    error: io::Error,
    fence: bool,
}
impl From<io::Error> for LookupFailure {
    fn from(error: io::Error) -> Self {
        Self { error, fence: true }
    }
}

pub(super) fn checked_entry<'a>(
    state: &'a State,
    file: &File,
    binding: NamespaceBinding,
    parent: Option<Identity>,
) -> io::Result<(Identity, &'a AccountedDirectory)> {
    let metadata = file.metadata()?;
    census::directory_nonallocating(&metadata)?;
    let identity = Identity::of(&metadata);
    let Some(entry) = state
        .accounted
        .get(&identity)
        .and_then(AccountedInode::directory)
    else {
        return Err(io::ErrorKind::InvalidData.into());
    };
    if !entry.settled
        || entry.binding != binding
        || entry.parent != parent
        || entry
            .bytes
            .checked_sub(entry.pending)
            .ok_or(io::ErrorKind::InvalidData)?
            != census::directory_extent(&metadata)?
        || entry.len != metadata.len()
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok((identity, entry))
}

// Each ancestor is compared with the retained ledger, not only the last inode.
// Paths, hash state and descriptor walk require no heap allocation here.
fn walk_observe(
    disk: &NodeDisk,
    state: &State,
    root: &str,
    names: &[CString],
    absent_final: bool,
    mut visited: impl FnMut(Identity),
) -> Result<File, LookupFailure> {
    let root = disk.roots.get(root).ok_or_else(|| LookupFailure {
        error: io::ErrorKind::InvalidInput.into(),
        fence: false,
    })?;
    root.verify_nonallocating()?;
    let mut current = root.file.try_clone()?;
    let mut binding = NamespaceBinding::root(root.identity);
    let (mut parent, _) = checked_entry(state, &current, binding, None)?;
    visited(parent);
    for (index, name) in names.iter().enumerate() {
        binding = binding.child(name);
        let child = match census::open_at(&current, name, libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(child) => child,
            Err(error) => {
                let known = state
                    .accounted
                    .values()
                    .any(|entry| entry.binding() == binding);
                // This is the one healthy absence: an unknown final component
                // below a completely verified enrolled ancestry.
                let fence = !(absent_final
                    && index + 1 == names.len()
                    && !known
                    && error.kind() == io::ErrorKind::NotFound);
                return Err(LookupFailure { error, fence });
            }
        };
        let (identity, _) = checked_entry(state, &child, binding, Some(parent))?;
        visited(identity);
        parent = identity;
        current = child;
    }
    Ok(current)
}

fn walk(
    disk: &NodeDisk,
    state: &State,
    root: &str,
    names: &[CString],
    absent_final: bool,
) -> Result<File, LookupFailure> {
    walk_observe(disk, state, root, names, absent_final, |_| {})
}

pub(super) fn names(relative: &Path, depth: u32, maximum: u32) -> io::Result<Box<[CString]>> {
    use std::os::unix::ffi::OsStrExt;
    let mut names = Vec::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        if names.len() + 1 >= depth as usize || name.len() > maximum as usize {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        names
            .try_reserve(1)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        names.push(CString::new(name.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?);
    }
    Ok(names.into_boxed_slice())
}

impl NodeDisk {
    /// Open only an enrolled directory. Empty relative opens the configured root.
    /// No namespace mutation, raw directory adoption or ancestor fallback occurs.
    pub fn open_directory(
        self: &Arc<Self>,
        root: &str,
        relative: &Path,
    ) -> io::Result<NodeDiskDirectory> {
        let mut state = self.lock_state();
        if state.phase != NodeDiskPhase::Open || !self.device.lock().admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        if state
            .open_directories
            .checked_add(super::batch::reserved_directories(&state))
            .is_none_or(|n| n >= self.config.max_open_directories)
        {
            return Err(io::ErrorKind::StorageFull.into());
        }
        if !self.roots.contains_key(root) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // The installed envelope funds all these allocations and the temporary
        // walk descriptors. No registered destructor exists before publication.
        let names = names(relative, self.config.max_depth, self.config.max_name_bytes)?;
        self.open_directory_names(&mut state, root.to_owned(), names)
    }

    // Caller holds State and has checked the owner quota before any path/Arc
    // allocation. Both rooted and child opens share the same publication path.
    fn open_directory_names(
        self: &Arc<Self>,
        state: &mut State,
        root: String,
        names: Box<[CString]>,
    ) -> io::Result<NodeDiskDirectory> {
        if !names.is_empty() {
            return managed::open_existing(self, state, root, names);
        }
        let mut allocation = Arc::<DirectoryOwner>::new_uninit();
        #[cfg(test)]
        let after_close = {
            let mutex = std::sync::Mutex::new(None);
            drop(mutex.lock().expect("unpublished directory close hook"));
            mutex
        };
        let file = match walk(self, state, &root, &names, true) {
            Ok(file) => file,
            Err(error) => {
                if error.fence {
                    self.fail_locked(state);
                }
                return Err(error.error);
            }
        };
        let identity = match file.metadata() {
            Ok(metadata) => Identity::of(&metadata),
            Err(error) => {
                self.fail_locked(state);
                return Err(error);
            }
        };
        let next = state
            .accounted
            .get(&identity)
            .and_then(AccountedInode::directory)
            .expect("verified root enrollment")
            .live_handles
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        state
            .accounted
            .get_mut(&identity)
            .and_then(AccountedInode::directory_mut)
            .expect("verified root enrollment")
            .live_handles = next;
        state.open_directories += 1;
        Arc::get_mut(&mut allocation)
            .expect("unpublished directory owner")
            .write(DirectoryOwner {
                disk: self.clone(),
                root,
                names,
                identity,
                file: Some(file),
                parent: None,
                registered: true,
                #[cfg(test)]
                after_close: Some(after_close),
            });
        // SAFETY: the sole allocation has just been fully initialized. It is
        // published only after actual FD acquisition and all ledger checks.
        let owner = unsafe { allocation.assume_init() };
        Ok(NodeDiskDirectory(Some(owner)))
    }
}

impl NodeDiskDirectory {
    fn owner(&self) -> &DirectoryOwner {
        self.0.as_deref().expect("live directory custody")
    }
    fn verify(&self, state: &State) -> io::Result<()> {
        let current = walk(
            &self.owner().disk,
            state,
            &self.owner().root,
            &self.owner().names,
            false,
        )
        .map_err(|failure| failure.error)?;
        let retained = self
            .owner()
            .file
            .as_ref()
            .expect("live directory descriptor");
        if Identity::of(&current.metadata()?) != self.owner().identity
            || Identity::of(&retained.metadata()?) != self.owner().identity
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if let Some(parent) = &self.owner().parent {
            // The inherited walk above already checked the complete enrolled
            // ancestry. Checking the retained parent needs no additional FD.
            let metadata = parent.file().metadata()?;
            census::directory_nonallocating(&metadata)?;
            if Identity::of(&metadata) != parent.identity() {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        Ok(())
    }

    pub fn observed_allocated_bytes(&self) -> io::Result<u64> {
        let mut state = self.owner().disk.lock_state();
        if state.phase == NodeDiskPhase::Failed
            || !self.owner().disk.device.lock().admission_ready()
        {
            return Err(io::ErrorKind::Other.into());
        }
        self.verify(&state)
            .inspect_err(|_| self.owner().disk.fail_locked(&mut state))?;
        let entry = state.accounted[&self.owner().identity]
            .directory()
            .expect("verified directory enrollment");
        entry
            .bytes
            .checked_sub(entry.pending)
            .ok_or_else(|| io::ErrorKind::InvalidData.into())
    }

    /// Synchronize an unchanged enrolled directory through its retained FD.
    /// Paused permits existing custody to drain; Failed never advertises success.
    pub fn sync_all(&self) -> io::Result<()> {
        let mut state = self.owner().disk.lock_state();
        if state.phase == NodeDiskPhase::Failed
            || !self.owner().disk.device.lock().admission_ready()
        {
            return Err(io::ErrorKind::Other.into());
        }
        let result = (|| {
            self.verify(&state)?;
            self.owner()
                .file
                .as_ref()
                .expect("live directory descriptor")
                .sync_all()?;
            self.verify(&state)
        })();
        result.inspect_err(|_| self.owner().disk.fail_locked(&mut state))
    }
}

// All strong handles retire through into_inner. Its exactly-one-winner rule
// avoids try_unwrap races where the last Arc would run the owner destructor
// before its allocation was released. No inner Arc or Weak escapes this module.
impl Drop for NodeDiskDirectory {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take().and_then(Arc::into_inner) {
            drop(owner);
        }
    }
}

impl Drop for DirectoryOwner {
    fn drop(&mut self) {
        // Actual close precedes the drain counters. Nothing in this destructor
        // enrolls namespace changes or returns disk extent credit.
        drop(self.file.take());
        let parent = self
            .parent
            .take()
            .and_then(namespace::RetainedParent::retire);
        #[cfg(test)]
        if let Some(mut hook) = self.after_close.take() {
            if let Some(pause) = hook.get_mut().unwrap().take() {
                pause.entered.send(()).unwrap();
                pause
                    .release
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("release directory close fixture");
            }
            drop(hook);
        }
        // These variable allocations must die before another owner may spend
        // this slot. The Arc backing already died in Arc::into_inner above.
        drop(std::mem::take(&mut self.root));
        drop(std::mem::replace(&mut self.names, Box::new([])));
        if !self.registered {
            return;
        }
        let mut state = self.disk.lock_state();
        if parent.is_some_and(|identity| !namespace::can_retire_parent(&state, identity)) {
            self.disk.fail_locked(&mut state);
            return;
        }
        let Some(entry) = state
            .accounted
            .get_mut(&self.identity)
            .and_then(AccountedInode::directory_mut)
        else {
            self.disk.fail_locked(&mut state);
            return;
        };
        let Some(next) = entry.live_handles.checked_sub(1) else {
            self.disk.fail_locked(&mut state);
            return;
        };
        entry.live_handles = next;
        let Some(next) = state.open_directories.checked_sub(1) else {
            self.disk.fail_locked(&mut state);
            return;
        };
        state.open_directories = next;
        if let Some(parent) = parent {
            namespace::retire_parent(&mut state, parent);
        }
        self.registered = false;
    }
}

#[cfg(test)]
mod tests;

mod cursor;
pub use cursor::{
    NodeDiskDirectoryCloseError, NodeDiskDirectoryCursor, NodeDiskDirectoryEntry, NodeDiskEntryKind,
};

mod managed;
pub(super) use managed::PendingDirectory;
pub use managed::{
    NodeDiskDirectoryFailure, NodeDiskDirectoryOperation, NodeDiskDirectoryOperationKind,
    NodeDiskDirectoryOperationStep,
};
