//! Installed persistent extent accounting with retained per-inode enrollment.
//! Raw path writes never enroll files or replace an admitted owner's extent.
use crate::DiskOpenError;
use crate::{
    device_disk::{DeviceDisk, DeviceSelection},
    disk_memory::{self, DiskMemoryRequirements, Lease, List, NodeDiskMemoryAdmission},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

mod batch;
mod census;
mod directory;
mod file;
mod fixed_map;
mod ledger;
mod memory;
mod namespace;
mod native_file;
#[cfg(test)]
mod tests;
pub(crate) use batch::{
    MAX_NAMESPACE_PARTS, NamespaceAdmission, NamespaceClaim, NamespacePart, NamespacePartKind,
};
use census::{Root, census, open_roots};
pub use directory::{
    NodeDiskDirectory, NodeDiskDirectoryCloseError, NodeDiskDirectoryCursor,
    NodeDiskDirectoryEntry, NodeDiskDirectoryFailure, NodeDiskDirectoryOperation,
    NodeDiskDirectoryOperationKind, NodeDiskDirectoryOperationStep, NodeDiskEntryKind,
};
pub use file::NodeDiskFile;
pub(crate) use file::{
    FailedCloseReport, FailedFileTransfer, FailedFileWitness, NodeDiskCloseOutcome,
};
use ledger::AccountedInode;

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
    /// Independent operational directory descriptors, separate from file owners.
    pub max_open_directories: u32,
    /// Explicit per-directory namespace admission. No implicit filesystem bound.
    pub directory_policy: DirectoryPolicy,
    /// Independent persistent regular-file cardinality, including closed files.
    pub max_persistent_files: u64,
    /// Persistent subdirectories, excluding the explicitly configured roots.
    pub max_persistent_subdirectories: u64,
    /// Maximum native readdir calls in one retained census step, including
    /// dot entries and EOF. The whole scan bound derives from F + 4D + 3R.
    pub census_work_per_step: u64,
    /// Bounds traversal stack, ownership ancestor locks and path walk depth.
    pub max_depth: u32,
    /// Bound each directory entry before copying its name.
    pub max_name_bytes: u32,
}

/// Required first-release namespace allowance. These scalar bounds are not a
/// filesystem growth qualification; the installed filesystem policy must prove
/// that its namespace operations fit them before production admission is safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPolicy {
    pub extent_bytes: u64,
    pub max_entries: u64,
}
impl DirectoryPolicy {
    pub fn new(extent_bytes: u64, max_entries: u64) -> Result<Self> {
        let policy = Self {
            extent_bytes,
            max_entries,
        };
        policy.validate()?;
        Ok(policy)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.extent_bytes > 0 && self.extent_bytes <= i64::MAX as u64,
            "directory extent allowance is invalid"
        );
        ensure!(self.max_entries > 0, "directory entry allowance is zero");
        Ok(())
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fixture() -> Self {
        Self {
            extent_bytes: 1 << 20,
            max_entries: 32_768,
        }
    }
}

impl NodeDiskConfig {
    pub fn validate(&self) -> Result<()> {
        self.directory_policy.validate()?;
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
        ensure!(
            self.max_open_directories > 0,
            "open-directory metadata budget is zero"
        );
        ensure!(
            self.max_persistent_files > 0,
            "persistent file budget is zero"
        );
        ensure!(self.census_work_per_step > 0, "census step budget is zero");
        self.census_work_bound()?;
        ledger::map_limits(self)?;
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
            ensure!(
                path.components().all(|part| matches!(
                    part,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )),
                "persistent roots require canonical path components"
            );
        }
        Ok(())
    }

    /// A tree with F files, D non-root directories and R configured roots has
    /// F+D child entries, 2(D+R) dot entries and D+R EOF observations. This is
    /// a checked whole-job bound, independent of the scheduling step budget.
    fn census_work_bound(&self) -> io::Result<u64> {
        let roots = u64::try_from(self.roots.len()).map_err(|_| disk_memory::overflow())?;
        self.max_persistent_files
            .checked_add(
                self.max_persistent_subdirectories
                    .checked_mul(4)
                    .ok_or_else(disk_memory::overflow)?,
            )
            .and_then(|n| roots.checked_mul(3).and_then(|r| n.checked_add(r)))
            .ok_or_else(disk_memory::overflow)
    }

    /// Resolve only an explicitly installed accounting root. This performs no
    /// enrollment, filesystem mutation, symlink resolution, or parent fallback.
    pub fn binding<'config, 'path>(
        &'config self,
        path: &'path std::path::Path,
    ) -> Result<(&'config str, &'path std::path::Path)> {
        ensure!(path.is_absolute(), "persistent file path must be absolute");
        let mut selected = None;
        for (name, root) in &self.roots {
            let Ok(relative) = path.strip_prefix(root) else {
                continue;
            };
            ensure!(selected.is_none(), "persistent path has overlapping roots");
            ensure!(
                !relative.as_os_str().is_empty()
                    && relative
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_))),
                "persistent file requires normal components below its root"
            );
            selected = Some((name.as_str(), relative));
        }
        selected.context("persistent file is outside installed accounting roots")
    }
}

/// Cancellation affects bounded directory reads and unpublished census work;
/// it grants no storage access.
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
    pub persistent_directories: u64,
    pub open_directories: u32,
    pub open_directory_cursors: u32,
    pub open_census_streams: u32,
    pub retained_file_attempts: usize,
    pub uncertain_file_close: Option<(i32, i32)>,
    pub census_close_errno: Option<i32>,
    pub observed_directory_bytes: u64,
    pub max_bytes: u64,
    pub maintenance_reserve_bytes: u64,
    pub filesystem_pending_bytes: u64,
    pub filesystem_min_free_bytes: u64,
    pub filesystem_available_bytes: Option<u64>,
    pub filesystem_total_bytes: Option<u64>,
    pub filesystem_used_bytes: Option<u64>,
    pub filesystem_admission_ready: bool,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct Identity(u64, u64);
impl Identity {
    fn of(metadata: &std::fs::Metadata) -> Self {
        Self(metadata.dev(), metadata.ino())
    }
}

/// Fixed retained namespace identity. Component framing and distinct domains
/// prevent ambiguous concatenations; hashing never allocates. This binds a
/// closed inode to its enrolled name without retaining another path allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NamespaceBinding([u8; 32]);

impl NamespaceBinding {
    fn root(identity: Identity) -> Self {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"kasumi-node-disk-root-v1\0");
        hash.update(identity.0.to_le_bytes());
        hash.update(identity.1.to_le_bytes());
        Self(hash.finalize().into())
    }

    fn child(self, name: &std::ffi::CStr) -> Self {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"kasumi-node-disk-child-v1\0");
        hash.update(self.0);
        hash.update((name.to_bytes().len() as u64).to_le_bytes());
        hash.update(name.to_bytes());
        Self(hash.finalize().into())
    }
}

/// The admitted physical identity survives descriptor close. Reservations and
/// observed extents update this existing entry without allocating during I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AccountedFile {
    binding: NamespaceBinding,
    bytes: u64,
    pending: u64,
    actual_len: u64,
    reserved_len: u64,
    settled: bool,
}

impl AccountedFile {
    fn durable(binding: NamespaceBinding, bytes: u64, pending: u64, len: u64) -> Self {
        Self {
            binding,
            bytes,
            pending,
            actual_len: len,
            reserved_len: len,
            settled: true,
        }
    }
}

/// Read-only directory enrollment. Namespace mutation settlement is a separate
/// transition; these entries must never silently adopt an observed change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AccountedDirectory {
    binding: NamespaceBinding,
    parent: Option<Identity>,
    /// Charged total, including the unused admitted namespace promise.
    bytes: u64,
    pending: u64,
    settled: bool,
    len: u64,
    children: u64,
    live_handles: u32,
}

struct State {
    phase: NodeDiskPhase,
    bytes: u64,
    pending: u64,
    files: u64,
    open_files: u32,
    open_directories: u32,
    open_directory_cursors: u32,
    census_streams: census::Streams,
    namespace_generation: u64,
    file_close_generation: u64,
    accepted_census_generation: u64,
    census_retirement_panic: Option<Box<dyn std::any::Any + Send>>,
    pending_directory: Option<directory::PendingDirectory>,
    namespace_batch: Option<batch::BatchRecord>,
    namespace_claim: Option<batch::ClaimRecord>,
    namespace_batch_generation: u64,
    directory_bytes: u64,
    directories: u64,
    live: fixed_map::Banks<Weak<file::FileOwner>>,
    file_custody: file::CustodySlots,
    accounted: fixed_map::Banks<AccountedInode>,
}

/// An installed owner outlives all service/database handles. The strong registry
/// deliberately retains its locks, sparse-file promises and aggregate charges.
/// `pause` and `reconcile` are explicit; dropping an Arc never credits disk space.
pub struct NodeDisk {
    config: NodeDiskConfig,
    memory: Arc<dyn NodeDiskMemoryAdmission>,
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
    // Prepare fixture synchronization as well: Darwin's std mutex creates its
    // native mutex lazily, and these hooks first run inside measured I/O/Drop.
    after_file_close: Mutex<Option<file::ClosePause>>,
    #[cfg(test)]
    shrink_failure: Mutex<Option<file::ShrinkFailure>>,
    #[cfg(test)]
    parent_sync_failure: AtomicBool,
    #[cfg(test)]
    namespace_failure: std::sync::atomic::AtomicU8,
    // Every covered collection/path/descriptor owner is destroyed first.
    _memory_charge: Lease,
}

impl std::fmt::Debug for NodeDisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeDisk")
            .field("config", &self.config)
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

/// The one pre-admitted registry allocation owns either an unfinished initial
/// census or its installed owner. Preparing remains inspectable after an
/// uncertain close, including when the original constructor unwinds.
// Inline preparation deliberately uses the one charged registry node; boxing
// this variant would introduce a separate retention allocation.
#[allow(clippy::large_enum_variant)]
enum Registration {
    Preparing(PreparedResources),
    Installed(Arc<NodeDisk>),
    Transition,
}
struct RegisteredDisk {
    identity: Identity,
    registration: Registration,
    _charge: Lease,
}
impl RegisteredDisk {
    fn config(&self) -> Option<&NodeDiskConfig> {
        match &self.registration {
            Registration::Preparing(prepared) => Some(&prepared.config),
            Registration::Installed(owner) => Some(&owner.config),
            Registration::Transition => None,
        }
    }
    fn roots(&self) -> Option<&BTreeMap<String, Root>> {
        match &self.registration {
            Registration::Preparing(prepared) => Some(&prepared.roots),
            Registration::Installed(owner) => Some(&owner.roots),
            Registration::Transition => None,
        }
    }
    fn owner(&self) -> std::result::Result<&Arc<NodeDisk>, DiskOpenError> {
        match &self.registration {
            Registration::Installed(owner) => Ok(owner),
            Registration::Preparing(prepared) => {
                let error = prepared
                    .streams
                    .close_error()
                    .map(anyhow::Error::from)
                    .unwrap_or_else(|| anyhow::anyhow!("initial census is incomplete"));
                Err(error.context(format!(
                    "initial census retains {} unretired native streams; process restart required",
                    prepared.streams.outstanding())).into())
            }
            Registration::Transition => {
                Err(anyhow::anyhow!("initial census publication is incomplete").into())
            }
        }
    }
}
type RegisteredDisks = parking_lot::Mutex<List<RegisteredDisk>>;
fn registry() -> &'static RegisteredDisks {
    static REGISTRY: RegisteredDisks = parking_lot::Mutex::new(List::new());
    &REGISTRY
}

/// All backing/descriptor owners retire before the owner lease on ordinary
/// failure. The registry's own lease retires after its actual list node.
struct PreparedResources {
    config: NodeDiskConfig,
    memory: Arc<dyn NodeDiskMemoryAdmission>,
    roots: BTreeMap<String, Root>,
    ancestor_locks: Vec<File>,
    accounted: fixed_map::Banks<AccountedInode>,
    live: fixed_map::Banks<Weak<file::FileOwner>>,
    file_custody: file::CustodySlots,
    streams: census::Streams,
    charge: Lease,
}
struct PreparingRegistration<'a> {
    installed: &'a mut List<RegisteredDisk>,
    identity: Identity,
    committed: bool,
}
impl PreparingRegistration<'_> {
    fn entry(&mut self) -> &mut RegisteredDisk {
        self.installed
            .find_mut(|entry| entry.identity == self.identity)
            .expect("registered initial census")
    }
    fn prepared(&mut self) -> &mut PreparedResources {
        match &mut self.entry().registration {
            Registration::Preparing(prepared) => prepared,
            _ => unreachable!("unpublished initial census"),
        }
    }
    fn take(&mut self) -> PreparedResources {
        assert_eq!(
            self.prepared().streams.outstanding(),
            0,
            "unretired initial census stream"
        );
        assert!(
            self.prepared().streams.close_errno().is_none(),
            "uncertain initial census close"
        );
        match std::mem::replace(&mut self.entry().registration, Registration::Transition) {
            Registration::Preparing(prepared) => prepared,
            _ => unreachable!("unpublished initial census"),
        }
    }
    fn commit(&mut self, owner: Arc<NodeDisk>) {
        self.entry().registration = Registration::Installed(owner);
        self.committed = true;
    }
}
impl Drop for PreparingRegistration<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Registration::Preparing(prepared) = &self.entry().registration
            && prepared.streams.outstanding() != 0
        {
            // The pre-effect registry node remains the actual owner of all
            // resource backing, locks, leases AND native close diagnostics.
            // A later constructor reports this retained failure. Never retry
            // a possibly consumed DIR or allocate a detached retention task.
            return;
        }
        // Removing the actual node deallocates its backing before returning
        // the value; ordered fields then retire resources before lease credit.
        drop(
            self.installed
                .remove(|entry| entry.identity == self.identity),
        );
    }
}

/// Private, unique Arc custody until registry publication. On error/unwind the
/// Arc allocation itself retires before its value and resident lease can drop.
struct ProvisionalOwner<T>(Option<Arc<T>>);
impl<T> ProvisionalOwner<T> {
    fn new(value: T) -> Self {
        Self(Some(Arc::new(value)))
    }
}
impl<T> std::ops::Deref for ProvisionalOwner<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0.as_deref().expect("private provisional owner")
    }
}
impl<T> Drop for ProvisionalOwner<T> {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            // No Arc or Weak escapes before publication. into_inner retires
            // the strong/implicit-weak backing before returning the owned T.
            let value = Arc::into_inner(owner).expect("unique provisional Arc");
            drop(value);
        }
    }
}
impl ProvisionalOwner<NodeDisk> {
    fn install(mut self, registration: &mut PreparingRegistration<'_>) -> Arc<NodeDisk> {
        // Keep private custody until the retained registry clone is installed.
        // There is no fallible operation between that installation and take.
        registration.commit(self.0.as_ref().expect("provisional owner").clone());
        self.0.take().expect("registered owner")
    }
}

impl NodeDisk {
    pub(crate) fn binding<'owner, 'path>(
        &'owner self,
        path: &'path std::path::Path,
    ) -> Result<(&'owner str, &'path std::path::Path)> {
        self.config.binding(path)
    }

    pub fn memory(&self) -> &Arc<dyn NodeDiskMemoryAdmission> {
        &self.memory
    }

    pub fn memory_requirements(config: &NodeDiskConfig) -> Result<DiskMemoryRequirements> {
        let (device_bytes, registration_bytes) = DeviceDisk::metadata_requirements()?;
        Ok(DiskMemoryRequirements {
            owner_bytes: Self::required_metadata_bytes(config)?,
            registry_bytes: disk_memory::allocation::<disk_memory::Entry<RegisteredDisk>>(1)?,
            device_bytes,
            registration_bytes,
        })
    }
    pub fn open(
        config: &NodeDiskConfig,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
        cancel: &CensusCancellation,
    ) -> std::result::Result<Arc<Self>, DiskOpenError> {
        Self::open_inner(config, memory, cancel, DeviceSelection::Installed)
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub fn open_fixture(
        config: &NodeDiskConfig,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
        cancel: &CensusCancellation,
    ) -> std::result::Result<Arc<Self>, DiskOpenError> {
        Self::open_inner(config, memory, cancel, DeviceSelection::Isolated)
    }
    fn open_inner(
        config: &NodeDiskConfig,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
        cancel: &CensusCancellation,
        selection: DeviceSelection,
    ) -> std::result::Result<Arc<Self>, DiskOpenError> {
        config.validate()?;
        cancel.check()?;
        let mut installed = registry().try_lock().ok_or(DiskOpenError::RegistryBusy)?;
        if let Some(existing) = installed.find(|entry| {
            entry
                .config()
                .is_some_and(|installed| installed.roots == config.roots)
        }) {
            let owner = existing.owner()?;
            disk_memory::require(
                owner.config == *config,
                "installed persistent owner has different budgets",
            )?;
            disk_memory::require(
                Arc::ptr_eq(&owner.memory, &memory),
                "installed persistent owner has different memory admission",
            )?;
            for root in owner.roots.values() {
                root.verify_nonallocating()?;
            }
            return Ok(owner.clone());
        }
        let requirement = Self::memory_requirements(config)?;
        let charge = memory.clone().reserve_installed(requirement.owner_bytes)?;
        let registry_charge = memory
            .clone()
            .reserve_installed(requirement.registry_bytes)?;
        // The new fixed bank has no failure path after configured-root FD acquisition.
        let file_custody = file::CustodySlots::new(config.max_open_files)?;
        let roots = open_roots(config)?;
        for entry in installed.iter() {
            disk_memory::require(
                entry.roots().is_none_or(|old_roots| {
                    !old_roots
                        .values()
                        .any(|old| roots.values().any(|new| old.identity == new.identity))
                }),
                "persistent root is already part of another registered owner",
            )?;
        }
        let ancestor_locks = census::lock_roots(&roots, config.max_depth)?;
        let root = roots.values().next().expect("validated roots");
        let (_, unit) = filesystem(&root.file)?;
        let (retained_limit, census_limit) = ledger::map_limits(config)?;
        let accounted = fixed_map::Banks::new(retained_limit)?;
        let live = fixed_map::Banks::new(
            usize::try_from(config.max_open_files).map_err(|_| disk_memory::overflow())?,
        )?;
        let identity = roots.values().next().expect("validated roots").identity;
        // Fund and publish actual initial-census custody before fdopendir. A
        // failed/uncertain constructor remains represented in this same node.
        installed.insert(List::prepare(RegisteredDisk {
            identity,
            registration: Registration::Preparing(PreparedResources {
                config: config.clone(),
                memory,
                roots,
                ancestor_locks,
                accounted,
                live,
                file_custody,
                streams: census::Streams::default(),
                charge,
            }),
            _charge: registry_charge,
        }));
        let mut registration = PreparingRegistration {
            installed: &mut installed,
            identity,
            committed: false,
        };
        let prepared = registration.prepared();
        let totals = census(
            &prepared.roots,
            &prepared.config,
            unit,
            cancel,
            prepared.accounted.stage(census_limit)?,
            &prepared.streams,
        )?;
        cancel.check()?;
        prepared.accounted.commit_stage();
        let device = selection.open(identity.0, config.min_free_bytes, prepared.memory.clone())?;
        let PreparedResources {
            config,
            memory,
            roots,
            ancestor_locks,
            accounted,
            live,
            file_custody,
            streams: _,
            charge,
        } = registration.take();
        let disk = ProvisionalOwner::new(Self {
            config,
            memory,
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
                open_directories: 0,
                open_directory_cursors: 0,
                census_streams: census::Streams::default(),
                namespace_generation: 0,
                file_close_generation: 0,
                accepted_census_generation: 0,
                census_retirement_panic: None,
                pending_directory: None,
                namespace_batch: None,
                namespace_claim: None,
                namespace_batch_generation: 0,
                directory_bytes: totals.directory_bytes,
                directories: totals.directories,
                live,
                file_custody,
                accounted,
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
            #[cfg(test)]
            namespace_failure: std::sync::atomic::AtomicU8::new(0),
            _memory_charge: charge,
        });
        drop(disk.state.lock().expect("unpublished node disk state"));
        #[cfg(test)]
        {
            drop(disk.available_override.lock().unwrap());
            // First-use allocation belongs to acquisition, never a publication
            // or descriptor destructor, even for dormant fault-injection hooks.
            drop(disk.after_file_close.lock().unwrap());
            drop(disk.shrink_failure.lock().unwrap());
        }
        let mut promises = disk.device.lock();
        let next = promises
            .checked_add(totals.pending)
            .context("persistent census promises overflow")?;
        // Publish one complete census. Existing over-budget files remain charged;
        // read/cleanup can proceed, while every new reservation checks both limits.
        promises.set_pending(next)?;
        drop(promises);
        Ok(disk.install(&mut registration))
    }

    /// Test installations select their file's parent explicitly. This helper is
    /// absent from production builds and retains the real private-path census,
    /// descriptor identity checks and extent budgets. Its device ledger is
    /// isolated so an intentional fault cannot seal an unrelated fixture.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fixture_for_path(
        path: impl AsRef<std::path::Path>,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> std::result::Result<Arc<Self>, DiskOpenError> {
        if let Some(owner) = Self::fixture_registered_for_path(path.as_ref(), &memory)? {
            return Ok(owner);
        }
        let config = Self::fixture_config(path.as_ref())?;
        Self::open_fixture(&config, memory, &CensusCancellation::default())
    }
    /// Test-only lookup keeps known installed custody authoritative even if a
    /// destination path disappeared. Absence alone permits fresh fixture setup.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn fixture_registered_for_path(
        path: &std::path::Path,
        memory: &Arc<dyn NodeDiskMemoryAdmission>,
    ) -> std::result::Result<Option<Arc<Self>>, DiskOpenError> {
        let existing = {
            let installed = registry().try_lock().ok_or(DiskOpenError::RegistryBusy)?;
            installed
                .find(|entry| {
                    entry
                        .config()
                        .is_some_and(|config| config.binding(path).is_ok())
                })
                .map(|entry| entry.owner().cloned())
                .transpose()?
        };
        if let Some(owner) = existing {
            disk_memory::require(
                Arc::ptr_eq(owner.memory(), memory),
                "fixture persistent owner has different memory admission",
            )?;
            for root in owner.roots.values() {
                root.verify_nonallocating()?;
            }
            let snapshot = owner.snapshot();
            if snapshot.open_files == 0
                && snapshot.open_directories == 0
                && snapshot.open_directory_cursors == 0
                && snapshot.open_census_streams == 0
            {
                owner.reconcile(&CensusCancellation::default())?;
            }
            return Ok(Some(owner));
        }
        Ok(None)
    }
    /// Explicit bounded generic fixture policy. Production installation policy
    /// retains one million files, one million subdirectories and 4096 owners in the server generator.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fixture_config(path: impl AsRef<std::path::Path>) -> Result<NodeDiskConfig> {
        let root = path
            .as_ref()
            .parent()
            .context("fixture file has no parent")?;
        Ok(NodeDiskConfig {
            roots: BTreeMap::from([("fixture".into(), root.to_owned())]),
            max_bytes: 256 << 30,
            maintenance_reserve_bytes: 1 << 30,
            min_free_bytes: 0,
            max_open_files: 256,
            max_open_directories: 256,
            directory_policy: DirectoryPolicy::fixture(),
            max_persistent_files: 16_384,
            max_persistent_subdirectories: 16_384,
            census_work_per_step: 16_384,
            max_depth: 64,
            max_name_bytes: 255,
        })
    }

    pub fn snapshot(&self) -> NodeDiskSnapshot {
        let state = self.lock_state();
        let promises = self.device.lock();
        let physical =
            filesystem_usage(&self.roots.values().next().expect("installed roots").file).ok();
        NodeDiskSnapshot {
            phase: state.phase,
            charged_bytes: state.bytes,
            pending_bytes: state.pending,
            persistent_files: state.files,
            open_files: state.open_files,
            persistent_directories: state.directories,
            open_directories: state.open_directories,
            open_directory_cursors: state.open_directory_cursors,
            open_census_streams: state.census_streams.outstanding(),
            retained_file_attempts: state.file_custody.retained_attempts(),
            uncertain_file_close: state.file_custody.close_diagnostic(),
            census_close_errno: state.census_streams.close_errno(),
            observed_directory_bytes: state.directory_bytes,
            max_bytes: self.config.max_bytes,
            maintenance_reserve_bytes: self.config.maintenance_reserve_bytes,
            filesystem_pending_bytes: *promises,
            filesystem_min_free_bytes: promises.minimum_free_bytes(),
            filesystem_available_bytes: self.available().ok(),
            filesystem_total_bytes: physical.map(|(total, _)| total),
            filesystem_used_bytes: physical.map(|(_, used)| used),
            filesystem_admission_ready: promises.admission_ready(),
        }
    }

    /// Seal new mutation admission before waiting for file/backend/directory owners to drain.
    /// This never releases physical charges, filesystem promises, or root locks.
    pub fn pause(&self) -> Result<()> {
        let mut state = self.lock_state();
        if state.phase != NodeDiskPhase::Failed {
            state.phase = NodeDiskPhase::Paused;
        }
        ensure!(
            state.open_files == 0
                && state.file_custody.retained_attempts() == 0
                && state.open_directories == 0
                && state.open_directory_cursors == 0
                && state.census_streams.outstanding() == 0,
            "persistent file or directory owners are still live"
        );
        Ok(())
    }

    /// Recount only after every managed file and directory owner has closed under the retained
    /// exclusive root locks. Failure retains the prior accounting and seals access.
    pub fn reconcile(&self, cancel: &CensusCancellation) -> Result<()> {
        ensure!(
            !self.state.is_poisoned(),
            "poisoned persistent ownership requires process restart"
        );
        let mut state = self.lock_state();
        ensure!(
            state.census_retirement_panic.is_none(),
            "persistent outcome retirement panicked; original panic remains retained"
        );
        let accepted_generation = state
            .accepted_census_generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("persistent accepted census generation exhausted"))?;
        if state.phase != NodeDiskPhase::Failed {
            state.phase = NodeDiskPhase::Paused;
        }
        ensure!(
            state
                .namespace_batch
                .as_ref()
                .is_none_or(|batch| !batch.witness_live)
                && state
                    .namespace_claim
                    .as_ref()
                    .is_none_or(|claim| !claim.witness_live),
            "persistent namespace admission witness is still live"
        );
        let internal_directories = u32::from(state.pending_directory.is_some());
        let internal_files = state.file_custody.internal_owners();
        ensure!(
            state.open_files == internal_files
                && state.open_directories == internal_directories
                && state.open_directory_cursors == 0
                && state.census_streams.outstanding() == 0,
            "persistent file or directory owners are still live"
        );
        if let Some(operation) = &mut state.pending_directory
            && let Err(error) = operation.close_resources()
        {
            self.fail_locked(&mut state);
            return Err(error.into());
        }
        if let Err(error) = state.file_custody.close_retained() {
            self.fail_locked(&mut state);
            return Err(error.into());
        }
        let (_, census_limit) = ledger::map_limits(&self.config)?;
        let result = {
            // Disjoint borrows keep the actual streams and spare bank under the
            // same State guard for every Pending step and during stack unwind.
            let State {
                accounted,
                census_streams,
                ..
            } = &mut *state;
            census(
                &self.roots,
                &self.config,
                self.unit,
                cancel,
                accounted.stage(census_limit)?,
                census_streams,
            )
        };
        let totals = match result {
            Ok(totals) => totals,
            Err(error) => {
                state.accounted.cancel_stage();
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
            state.accounted.cancel_stage();
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            anyhow::bail!("persistent census promise accounting overflow");
        };
        if let Err(error) = cancel.check() {
            state.accounted.cancel_stage();
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(error);
        }
        if let Err(error) = promises.set_pending(next) {
            state.accounted.cancel_stage();
            state.phase = NodeDiskPhase::Failed;
            return Err(error.into());
        }
        // This is the publication boundary: the complete candidate and shared
        // promises are accepted. Swap fixed backing, then retire old entries.
        state.accounted.commit_stage();
        state.bytes = totals.bytes;
        state.pending = totals.pending;
        state.files = totals.files;
        state.directory_bytes = totals.directory_bytes;
        state.directories = totals.directories;
        let retired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.file_custody.retire_after_census();
            state.live.clear();
            // No registration or operational capacity is published while any
            // old outcome, path, ancestry, Arc or namespace backing remains.
            drop(state.pending_directory.take());
            drop(state.namespace_batch.take());
            state.namespace_claim = None;
        }));
        if let Err(payload) = retired {
            // This inline slot is part of State's preadmitted geometry. The
            // actual opaque panic remains owned; its payload size is not a
            // proved bounded allocator/RSS allowance. Never retry retirement.
            state.census_retirement_panic = Some(payload);
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            anyhow::bail!("persistent original outcome retirement panicked");
        }
        state.open_files = 0;
        state.open_directories = 0;
        promises.reconcile_owner();
        // A receipt is observable only after every required physical/backing
        // retirement and shared promise publication completed under this gate.
        state.accepted_census_generation = accepted_generation;
        state.phase = NodeDiskPhase::Open;
        Ok(())
    }

    /// Original namespace failure and any independent native close failure.
    pub fn pending_directory_operation(&self) -> Option<NodeDiskDirectoryOperation> {
        self.lock_state()
            .pending_directory
            .as_ref()
            .map(|operation| operation.observed())
    }

    #[cfg(test)]
    pub(crate) fn with_state_locked_for_test<R>(&self, work: impl FnOnce() -> R) -> R {
        let _guard = self.lock_state();
        work()
    }

    pub(crate) fn fail(&self) {
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
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        #[cfg(test)]
        if let Some(value) = *self.available_override.lock().unwrap() {
            return Ok(value);
        }
        filesystem(&self.roots.values().next().expect("installed roots").file).map(|v| v.0)
    }

    fn reserve(&self, state: &mut State, delta: u64, work: DiskWork) -> io::Result<()> {
        if state.phase != NodeDiskPhase::Open {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
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
            return Err(io::Error::from(io::ErrorKind::InvalidData));
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

fn exhausted(_message: &'static str) -> io::Error {
    io::ErrorKind::StorageFull.into()
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
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    let bytes = rounded(metadata.len().max(allocated), unit)?;
    Ok((bytes, bytes - allocated))
}

fn filesystem_stat(directory: &File) -> io::Result<libc::statvfs> {
    use std::os::fd::AsRawFd;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is live and stat points to initialized writable storage.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

fn filesystem_usage(directory: &File) -> io::Result<(u64, u64)> {
    let stat = filesystem_stat(directory)?;
    let unit = stat.f_frsize as u64;
    let blocks = stat.f_blocks as u64;
    let free = stat.f_bfree as u64;
    if unit == 0 || blocks == 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let total = blocks
        .checked_mul(unit)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    let used = blocks
        .checked_sub(free)
        .and_then(|used| used.checked_mul(unit))
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok((total, used))
}

pub(crate) fn filesystem(directory: &File) -> io::Result<(u64, u64)> {
    let stat = filesystem_stat(directory)?;
    let unit = stat.f_frsize as u64;
    if unit == 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let available = (stat.f_bavail as u64)
        .checked_mul(unit)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok((available, unit))
}
