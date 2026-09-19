//! Persistent extent accounting. Production store constructors are not yet wired
//! to this owner; using scratch admission or a raw redb handle does not enroll it.
use crate::device_disk::DeviceDisk;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

mod census;
mod file;
#[cfg(test)]
mod tests;
use census::{Root, census, open_roots};
pub use file::NodeDiskFile;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDiskConfig {
    /// Exact private, non-overlapping persistent roots on one filesystem.
    pub roots: BTreeMap<String, PathBuf>,
    pub max_bytes: u64,
    pub maintenance_reserve_bytes: u64,
    pub min_free_bytes: u64,
    /// Simultaneous file owners. Each owner retains at most two descriptors.
    pub max_open_files: u32,
    /// Bounds traversal work; an incomplete census never opens admission.
    pub max_census_entries: u64,
    /// Bounds traversal stack, ownership ancestor locks and path walk depth.
    pub max_depth: u32,
    /// Bound each directory entry before copying its name.
    pub max_name_bytes: u32,
}

impl NodeDiskConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.roots.is_empty(), "persistent disk roots are empty");
        ensure!(
            self.max_bytes > 0 && self.max_bytes <= i64::MAX as u64,
            "persistent extent budget exceeds supported file offsets"
        );
        ensure!(
            self.maintenance_reserve_bytes < self.max_bytes,
            "maintenance reserve must leave foreground capacity"
        );
        ensure!(self.max_open_files > 0, "open-file metadata budget is zero");
        ensure!(self.max_census_entries > 0, "census work budget is zero");
        ensure!(self.max_depth > 0, "census depth budget is zero");
        ensure!(
            self.max_name_bytes > 0 && self.max_name_bytes <= u16::MAX.into(),
            "directory name budget is invalid"
        );
        ensure!(
            self.roots.len() <= self.max_open_files as usize,
            "root descriptors exceed the installed metadata budget"
        );
        for (name, path) in &self.roots {
            ensure!(
                !name.is_empty()
                    && name.len() <= self.max_name_bytes as usize
                    && path.is_absolute(),
                "invalid persistent root name or path"
            );
        }
        Ok(())
    }

    fn same_policy(&self, other: &Self) -> bool {
        let mut other = other.clone();
        other.roots = self.roots.clone();
        self == &other
    }
}

/// Cancellation affects only unpublished census work; it grants no storage access.
#[derive(Default)]
pub struct CensusCancellation {
    cancelled: AtomicBool,
    #[cfg(test)]
    checkpoints: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    cancel_at: std::sync::atomic::AtomicU64,
}
impl CensusCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    fn check(&self) -> Result<()> {
        #[cfg(test)]
        {
            let at = self.cancel_at.load(Ordering::Relaxed);
            if at != 0 && self.checkpoints.fetch_add(1, Ordering::Relaxed) + 1 >= at {
                self.cancel();
            }
        }
        ensure!(
            !self.cancelled.load(Ordering::Acquire),
            "persistent census cancelled"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskWork {
    Foreground,
    /// Selected by an installed maintenance worker, never a native request field.
    Maintenance,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum NodeDiskPhase {
    Open,
    Paused,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeDiskSnapshot {
    pub phase: NodeDiskPhase,
    pub charged_bytes: u64,
    pub pending_bytes: u64,
    pub persistent_files: u64,
    pub open_files: u32,
    pub max_bytes: u64,
    pub maintenance_reserve_bytes: u64,
    pub filesystem_pending_bytes: u64,
    pub filesystem_min_free_bytes: u64,
    pub filesystem_available_bytes: Option<u64>,
    pub filesystem_admission_ready: bool,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct Identity(u64, u64);
impl Identity {
    fn of(metadata: &std::fs::Metadata) -> Self {
        Self(metadata.dev(), metadata.ino())
    }
}

struct State {
    phase: NodeDiskPhase,
    bytes: u64,
    pending: u64,
    files: u64,
    open_files: u32,
    live: HashMap<Identity, Weak<file::FileOwner>>,
}

/// An installed owner outlives all service/database handles. The strong registry
/// deliberately retains its locks, sparse-file promises and aggregate charges.
/// `pause` and `reconcile` are explicit; dropping an Arc never credits disk space.
pub struct NodeDisk {
    config: NodeDiskConfig,
    roots: BTreeMap<String, Root>,
    _ancestor_locks: Vec<File>,
    device: DeviceDisk,
    unit: u64,
    state: Mutex<State>,
    #[cfg(test)]
    available_override: Mutex<Option<u64>>,
    #[cfg(test)]
    available_error: AtomicBool,
    #[cfg(test)]
    after_file_close: Mutex<Option<file::ClosePause>>,
    #[cfg(test)]
    shrink_failure: Mutex<Option<file::ShrinkFailure>>,
    #[cfg(test)]
    parent_sync_failure: AtomicBool,
}

impl std::fmt::Debug for NodeDisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeDisk")
            .field("config", &self.config)
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

type RootsKey = BTreeMap<String, Identity>;
type RegisteredDisks = Mutex<Vec<(RootsKey, Arc<NodeDisk>)>>;
fn registry() -> &'static RegisteredDisks {
    static REGISTRY: OnceLock<RegisteredDisks> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

impl NodeDisk {
    pub fn open(config: NodeDiskConfig, cancel: &CensusCancellation) -> Result<Arc<Self>> {
        Self::open_inner(
            config,
            cancel,
            #[cfg(test)]
            None,
        )
    }

    fn open_inner(
        config: NodeDiskConfig,
        cancel: &CensusCancellation,
        #[cfg(test)] test_device: Option<DeviceDisk>,
    ) -> Result<Arc<Self>> {
        config.validate()?;
        cancel.check()?;
        let mut installed = registry()
            .lock()
            .map_err(|_| anyhow::anyhow!("persistent ownership registry is poisoned"))?;
        let roots = open_roots(&config)?;
        let key: RootsKey = roots
            .iter()
            .map(|(name, root)| (name.clone(), root.identity))
            .collect();
        for (previous, owner) in installed.iter() {
            if previous == &key {
                ensure!(
                    owner.config.same_policy(&config),
                    "installed persistent owner has different budgets"
                );
                return Ok(owner.clone());
            }
            ensure!(
                !previous
                    .values()
                    .any(|id| key.values().any(|other| id == other)),
                "persistent root is already part of another installed owner"
            );
        }
        let ancestor_locks = census::lock_roots(&roots, config.max_depth)?;
        let root = roots.values().next().expect("validated roots");
        let (_, unit) = filesystem(&root.file)?;
        #[cfg(test)]
        let device = match test_device {
            Some(device) => device,
            None => DeviceDisk::open(root.identity.0, config.min_free_bytes)?,
        };
        #[cfg(not(test))]
        let device = DeviceDisk::open(root.identity.0, config.min_free_bytes)?;
        let totals = census(&roots, &config, unit, cancel)?;
        cancel.check()?;
        let disk = Arc::new(Self {
            config,
            roots,
            _ancestor_locks: ancestor_locks,
            device,
            unit,
            state: Mutex::new(State {
                phase: NodeDiskPhase::Open,
                bytes: totals.bytes,
                pending: totals.pending,
                files: totals.files,
                open_files: 0,
                live: HashMap::new(),
            }),
            #[cfg(test)]
            available_override: Mutex::new(None),
            #[cfg(test)]
            available_error: AtomicBool::new(false),
            #[cfg(test)]
            after_file_close: Mutex::new(None),
            #[cfg(test)]
            shrink_failure: Mutex::new(None),
            #[cfg(test)]
            parent_sync_failure: AtomicBool::new(false),
        });
        let mut promises = disk.device.lock();
        let next = promises
            .checked_add(totals.pending)
            .context("persistent census promises overflow")?;
        // Publish one complete census. Existing over-budget files remain charged;
        // read/cleanup can proceed, while every new reservation checks both limits.
        promises.set_pending(next)?;
        drop(promises);
        installed.push((key, disk.clone()));
        Ok(disk)
    }

    pub fn snapshot(&self) -> NodeDiskSnapshot {
        let state = self.lock_state();
        let promises = self.device.lock();
        NodeDiskSnapshot {
            phase: state.phase,
            charged_bytes: state.bytes,
            pending_bytes: state.pending,
            persistent_files: state.files,
            open_files: state.open_files,
            max_bytes: self.config.max_bytes,
            maintenance_reserve_bytes: self.config.maintenance_reserve_bytes,
            filesystem_pending_bytes: *promises,
            filesystem_min_free_bytes: promises.minimum_free_bytes(),
            filesystem_available_bytes: self.available().ok(),
            filesystem_admission_ready: promises.admission_ready(),
        }
    }

    /// Seal new mutation admission before waiting for file/backend owners to drain.
    /// This never releases physical charges, filesystem promises, or root locks.
    pub fn pause(&self) -> Result<()> {
        let mut state = self.lock_state();
        if state.phase != NodeDiskPhase::Failed {
            state.phase = NodeDiskPhase::Paused;
        }
        ensure!(
            state.open_files == 0,
            "persistent file owners are still live"
        );
        Ok(())
    }

    /// Recount only after every managed file owner has closed under the retained
    /// exclusive root locks. Failure retains the prior accounting and seals access.
    pub fn reconcile(&self, cancel: &CensusCancellation) -> Result<()> {
        ensure!(
            !self.state.is_poisoned(),
            "poisoned persistent ownership requires process restart"
        );
        let mut state = self.lock_state();
        state.phase = NodeDiskPhase::Paused;
        ensure!(
            state.open_files == 0,
            "persistent file owners are still live"
        );
        let result = census(&self.roots, &self.config, self.unit, cancel);
        let totals = match result {
            Ok(totals) => totals,
            Err(error) => {
                state.phase = NodeDiskPhase::Failed;
                self.device.lock().fail_owner();
                return Err(error);
            }
        };
        let mut promises = self.device.lock();
        let Some(next) = promises
            .checked_sub(state.pending)
            .and_then(|n| n.checked_add(totals.pending))
        else {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            anyhow::bail!("persistent census promise accounting overflow");
        };
        promises
            .set_pending(next)
            .inspect_err(|_| state.phase = NodeDiskPhase::Failed)?;
        state.bytes = totals.bytes;
        state.pending = totals.pending;
        state.files = totals.files;
        state.live.clear();
        state.phase = NodeDiskPhase::Open;
        promises.reconcile_owner();
        Ok(())
    }

    fn fail(&self) {
        let mut state = self.lock_state();
        self.fail_locked(&mut state);
    }

    fn fail_locked(&self, state: &mut State) {
        state.phase = NodeDiskPhase::Failed;
        self.device.lock().fail_owner();
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| {
            let mut state = p.into_inner();
            state.phase = NodeDiskPhase::Failed;
            self.device.lock().fail_owner();
            state
        })
    }

    fn available(&self) -> io::Result<u64> {
        #[cfg(test)]
        if self.available_error.load(Ordering::Relaxed) {
            return Err(io::Error::other("injected filesystem observation failure"));
        }
        #[cfg(test)]
        if let Some(value) = *self.available_override.lock().unwrap() {
            return Ok(value);
        }
        filesystem(&self.roots.values().next().expect("installed roots").file).map(|v| v.0)
    }

    fn reserve(&self, state: &mut State, delta: u64, work: DiskWork) -> io::Result<()> {
        if state.phase != NodeDiskPhase::Open {
            return Err(io::Error::other("persistent mutation admission is closed"));
        }
        let maximum = match work {
            DiskWork::Foreground => self.config.max_bytes - self.config.maintenance_reserve_bytes,
            DiskWork::Maintenance => self.config.max_bytes,
        };
        let next = state
            .bytes
            .checked_add(delta)
            .filter(|n| *n <= maximum)
            .ok_or_else(|| exhausted("persistent extent budget exhausted"))?;
        let mut promises = self.device.lock();
        if !promises.admission_ready() {
            return Err(io::Error::other("shared filesystem admission is closed"));
        }
        let next_promises = promises
            .checked_add(delta)
            .ok_or_else(|| exhausted("persistent filesystem promises overflow"))?;
        let required = next_promises
            .checked_add(promises.minimum_free_bytes())
            .ok_or_else(|| exhausted("persistent filesystem floor overflow"))?;
        let available = self.available().inspect_err(|_| {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
        })?;
        if required > available {
            return Err(exhausted("persistent filesystem floor exhausted"));
        }
        let own_pending = state
            .pending
            .checked_add(delta)
            .ok_or_else(|| exhausted("persistent owner promises overflow"))?;
        promises
            .set_pending(next_promises)
            .inspect_err(|_| state.phase = NodeDiskPhase::Failed)?;
        state.bytes = next;
        state.pending = own_pending;
        Ok(())
    }
}

fn exhausted(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::StorageFull, message)
}

fn rounded(len: u64, unit: u64) -> io::Result<u64> {
    len.div_ceil(unit)
        .checked_mul(unit)
        .ok_or_else(|| exhausted("persistent rounded extent overflow"))
}

fn extent(metadata: &std::fs::Metadata, unit: u64) -> io::Result<(u64, u64)> {
    let allocated = metadata
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| io::Error::other("persistent allocated blocks overflow"))?;
    let bytes = rounded(metadata.len().max(allocated), unit)?;
    Ok((bytes, bytes - allocated))
}

pub(crate) fn filesystem(directory: &File) -> io::Result<(u64, u64)> {
    use std::os::fd::AsRawFd;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is live and stat points to initialized writable storage.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let unit = stat.f_frsize as u64;
    if unit == 0 {
        return Err(io::Error::other("filesystem allocation unit unavailable"));
    }
    let available = (stat.f_bavail as u64)
        .checked_mul(unit)
        .ok_or_else(|| io::Error::other("filesystem capacity overflow"))?;
    Ok((available, unit))
}
