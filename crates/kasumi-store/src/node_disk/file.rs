use super::{DiskWork, Identity, NodeDisk, NodeDiskPhase, census, extent, rounded};
use anyhow::{Context, Result, ensure};
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
    settled: bool,
}

pub(super) struct FileOwner {
    disk: Arc<NodeDisk>,
    root: String,
    relative: PathBuf,
    parent: File,
    name: CString,
    identity: Identity,
    budget: Mutex<Budget>,
}

#[cfg(test)]
pub(super) struct ClosePause {
    pub(super) entered: std::sync::mpsc::Sender<()>,
    pub(super) release: std::sync::mpsc::Receiver<()>,
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

impl NodeDisk {
    pub fn open_file(self: &Arc<Self>, root: &str, relative: &Path) -> Result<NodeDiskFile> {
        self.bind_file(root, relative, None)
    }

    pub fn create_file(
        self: &Arc<Self>,
        root: &str,
        relative: &Path,
        work: DiskWork,
    ) -> Result<NodeDiskFile> {
        self.bind_file(root, relative, Some(work))
    }

    fn bind_file(
        self: &Arc<Self>,
        root: &str,
        relative: &Path,
        create: Option<DiskWork>,
    ) -> Result<NodeDiskFile> {
        let mut state = self.lock_state();
        ensure!(
            state.phase == NodeDiskPhase::Open,
            "persistent admission is closed"
        );
        state.live.retain(|_, owner| owner.strong_count() != 0);
        ensure!(
            state.open_files < self.config.max_open_files,
            "persistent open-file metadata budget exhausted"
        );
        if let Some(work) = create {
            self.reserve(&mut state, 0, work)?;
        }
        let selected = self
            .roots
            .get(root)
            .context("unknown installed persistent root")?;
        let result = (|| -> Result<(File, CString, File)> {
            let (parent, name) = census::parent(selected, relative, &self.config)?;
            let flags = libc::O_RDWR
                | libc::O_NONBLOCK
                | if create.is_some() {
                    libc::O_CREAT | libc::O_EXCL
                } else {
                    0
                };
            let file = census::open_at(&parent, &name, flags)?;
            census::regular(&file.metadata()?, selected.identity.0)?;
            Ok((parent, name, file))
        })();
        let (parent, name, file) = match result {
            Ok(value) => value,
            Err(error) => {
                // A known create conflict does not mutate an existing object.
                if create.is_none()
                    || !error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists)
                {
                    self.fail_locked(&mut state);
                }
                return Err(error);
            }
        };
        let metadata = file
            .metadata()
            .inspect_err(|_| self.fail_locked(&mut state))?;
        let identity = Identity::of(&metadata);
        if let Some(existing) = state.live.get(&identity).and_then(std::sync::Weak::upgrade) {
            ensure!(
                existing.root == root && existing.relative == relative,
                "live persistent file has another name"
            );
            return Ok(NodeDiskFile(existing));
        }
        census::lock(&file, libc::LOCK_EX).inspect_err(|_| self.fail_locked(&mut state))?;
        let (bytes, pending) =
            extent(&metadata, self.unit).inspect_err(|_| self.fail_locked(&mut state))?;
        if create.is_some() {
            // The empty inode is enrolled before any payload operation. If sync
            // is uncertain, keep it counted and require a stopped census.
            state.files = state
                .files
                .checked_add(1)
                .context("persistent file count overflow")?;
            ensure!(bytes == 0, "new persistent file has an unexpected extent");
            if let Err(error) = file.sync_all().and_then(|_| parent.sync_all()) {
                self.fail_locked(&mut state);
                return Err(error.into());
            }
        }
        let owner = Arc::new(FileOwner {
            disk: self.clone(),
            root: root.to_owned(),
            relative: relative.to_owned(),
            parent,
            name,
            identity,
            budget: Mutex::new(Budget {
                file: Some(file),
                bytes,
                pending,
                reserved_len: metadata.len(),
                settled: true,
            }),
        });
        state.open_files += 1;
        state.live.insert(identity, Arc::downgrade(&owner));
        Ok(NodeDiskFile(owner))
    }

    /// Consume the sole descriptor owner, then unlink and synchronize its exact
    /// parent. An uncertain result keeps all bytes charged and seals admission.
    pub fn delete_file(&self, file: NodeDiskFile) -> Result<()> {
        self.reclaim(file, None)
    }

    /// Explicit physical shrink after owner drain. Logical deletion/handle Drop
    /// never invokes this operation and never releases its reservation.
    pub fn shrink_file(&self, file: NodeDiskFile, len: u64) -> Result<()> {
        self.reclaim(file, Some(len))
    }

    fn reclaim(&self, file: NodeDiskFile, len: Option<u64>) -> Result<()> {
        ensure!(
            std::ptr::eq(self, Arc::as_ptr(&file.0.disk)),
            "different persistent owner"
        );
        let mut state = self.lock_state();
        let owner = match Arc::try_unwrap(file.0) {
            Ok(owner) => owner,
            Err(owner) => {
                // A concurrent final clone drop can make this the last Arc. Its
                // destructor must run after releasing the registration mutex.
                drop(state);
                drop(owner);
                anyhow::bail!("persistent file still has readers or backend owners");
            }
        };
        if owner.budget.is_poisoned() {
            self.fail_locked(&mut state);
            drop(state);
            drop(owner);
            anyhow::bail!("poisoned persistent file requires a drained census");
        }
        let mut budget = owner
            .budget
            .lock()
            .expect("exclusive unpoisoned file owner");
        let actual = budget.file.take().expect("live persistent descriptor");
        let result = (|| -> Result<(u64, u64)> {
            owner.verify(&actual)?;
            let current = actual.metadata()?.len();
            if let Some(len) = len {
                ensure!(len <= current, "physical reclaim cannot grow a file");
                actual.set_len(len)?;
                actual.sync_all()?;
                owner.verify(&actual)?;
                ensure!(
                    actual.metadata()?.len() == len,
                    "physical shrink length changed"
                );
                owner.parent.sync_all()?;
                extent(&actual.metadata()?, self.unit).map_err(Into::into)
            } else {
                actual.sync_all()?;
                // SAFETY: exact parent/name were revalidated while holding the
                // registry mutex, so no managed reopen can race owner removal.
                if unsafe { libc::unlinkat(owner.parent.as_raw_fd(), owner.name.as_ptr(), 0) } != 0
                {
                    return Err(io::Error::last_os_error().into());
                }
                owner.parent.sync_all()?;
                Ok((0, 0))
            }
        })();
        // Close the actual descriptor before advertising ownership drain/credit.
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
                match (next, own_next) {
                    (Some(next), Some(own_next)) => match promises.set_pending(next) {
                        Ok(()) => {
                            state.pending = own_next;
                            state.bytes -= budget.bytes - bytes;
                            if len.is_none() {
                                state.files -= 1;
                            }
                            Ok(())
                        }
                        Err(error) => {
                            state.phase = NodeDiskPhase::Failed;
                            Err(error.into())
                        }
                    },
                    _ => {
                        state.phase = NodeDiskPhase::Failed;
                        promises.fail_owner();
                        Err(anyhow::anyhow!("persistent reclaim accounting overflow"))
                    }
                }
            }
            Ok(_) => {
                self.fail_locked(&mut state);
                Err(anyhow::anyhow!(
                    "physical reclaim increased allocated extent"
                ))
            }
            Err(error) => {
                self.fail_locked(&mut state);
                Err(error)
            }
        };
        // FileOwner::drop sees no file and performs no second accounting action.
        drop(budget);
        drop(owner);
        outcome
    }
}

impl FileOwner {
    fn lock_budget(&self) -> io::Result<std::sync::MutexGuard<'_, Budget>> {
        self.budget.lock().map_err(|_| {
            self.disk.fail();
            io::Error::other("persistent file ownership is poisoned")
        })
    }
    fn verify(&self, file: &File) -> Result<()> {
        let root = &self.disk.roots[&self.root];
        let (parent, name) = census::parent(root, &self.relative, &self.disk.config)?;
        ensure!(
            Identity::of(&parent.metadata()?) == Identity::of(&self.parent.metadata()?)
                && name == self.name,
            "persistent file parent was replaced"
        );
        let observed = census::open_at(&parent, &name, libc::O_RDONLY | libc::O_NONBLOCK)?;
        let metadata = observed.metadata()?;
        census::regular(&metadata, self.identity.0)?;
        ensure!(
            Identity::of(&metadata) == self.identity
                && Identity::of(&file.metadata()?) == self.identity,
            "persistent file was replaced"
        );
        Ok(())
    }

    fn check(&self, file: &File) -> io::Result<()> {
        self.verify(file).map_err(|error| {
            self.disk.fail();
            io::Error::other(error)
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
            .ok_or_else(|| io::Error::other("persistent block count overflow"))?;
        let pending = bytes - allocated;
        let mut state = self.disk.lock_state();
        let mut promises = self.disk.device.lock();
        let Some(next) = promises
            .checked_sub(budget.pending)
            .and_then(|n| n.checked_add(pending))
        else {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(io::Error::other("persistent observation promise mismatch"));
        };
        let Some(own_next) = state
            .pending
            .checked_sub(budget.pending)
            .and_then(|n| n.checked_add(pending))
        else {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(io::Error::other("persistent observation owner mismatch"));
        };
        let Some(owned) = state.bytes.checked_add(extra) else {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(io::Error::other("persistent observed extent overflow"));
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
        budget.settled = metadata.len() == budget.reserved_len;
        if extra != 0 || metadata.len() > budget.reserved_len {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(io::Error::other(
                "persistent file exceeded its reserved extent",
            ));
        }
        Ok(())
    }
}

impl NodeDiskFile {
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
        if actual.len() != current_len || requested_len < current_len {
            self.0.disk.fail();
            return Err(io::Error::other(
                "persistent growth does not match the exact current extent",
            ));
        }
        let bytes = rounded(requested_len, self.0.disk.unit)?;
        let delta = bytes.saturating_sub(budget.bytes);
        let mut state = self.0.disk.lock_state();
        self.0.disk.reserve(&mut state, delta, work)?;
        budget.bytes += delta;
        budget.pending += delta;
        budget.reserved_len = budget.reserved_len.max(requested_len);
        budget.settled = false;
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
            return Err(io::Error::other("persistent resize is not admitted"));
        }
        // Keep the admission seal serialized through the backend call.
        if let Err(error) = file.set_len(len) {
            self.0.disk.fail_locked(&mut state);
            return Err(error);
        }
        budget.settled = false;
        Ok(())
    }

    pub fn write_all_at(&self, data: &[u8], offset: u64) -> io::Result<()> {
        let mut budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().expect("live persistent descriptor");
        self.0.check(file)?;
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| io::Error::other("persistent write offset overflow"))?;
        let mut state = self.0.disk.lock_state();
        if state.phase == NodeDiskPhase::Failed
            || !self.0.disk.device.lock().admission_ready()
            || end > budget.reserved_len
        {
            return Err(io::Error::other("persistent write is not admitted"));
        }
        budget.settled = false;
        if let Err(error) = budget
            .file
            .as_ref()
            .expect("live descriptor")
            .write_all_at(data, offset)
        {
            self.0.disk.fail_locked(&mut state);
            return Err(error);
        }
        Ok(())
    }

    pub fn read_exact_at(&self, out: &mut [u8], offset: u64) -> io::Result<()> {
        let budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().expect("live persistent descriptor");
        self.0.check(file)?;
        file.read_exact_at(out, offset)
            .inspect_err(|_| self.0.disk.fail())
    }

    /// Verified materialization retires only pending filesystem promises; the
    /// complete persistent extent charge remains after this owner closes.
    pub fn sync_all(&self) -> io::Result<()> {
        let mut budget = self.0.lock_budget()?;
        let file = budget.file.as_ref().expect("live persistent descriptor");
        self.0.check(file)?;
        file.sync_all().inspect_err(|_| self.0.disk.fail())?;
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
                self.disk.fail_locked(&mut state);
            }
        }
    }
}
