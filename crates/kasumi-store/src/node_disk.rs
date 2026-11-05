//! Installed persistent extent accounting with retained per-inode enrollment.
//! Raw path writes never enroll files or replace an admitted owner's extent.
use crate::DiskOpenError;
use crate::{
    ReserveError,
    capacity_refusal::{
        CapacityCheck, CapacityRefusal, CapacityRefusalCount, RefusalLedger, floor_headroom,
    },
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
mod transaction;
pub(crate) use transaction::TransactionSpace;
#[cfg(test)]
mod filesystems_tests;
mod native_file;
#[cfg(test)]
mod reopen_tests;
#[cfg(test)]
mod tests;
pub(crate) use batch::{
    MAX_NAMESPACE_PARTS, NamespaceAdmission, NamespaceClaim, NamespacePart, NamespacePartKind,
};
use census::{Root, census, open_roots};
pub use directory::{
    NodeDiskDirectory, NodeDiskDirectoryCloseError, NodeDiskDirectoryCursor,
    NodeDiskDirectoryEntry, NodeDiskDirectoryFailure, NodeDiskDirectoryOperation,
    NodeDiskDirectoryOperationKind, NodeDiskDirectoryOperationStep, NodeDiskDirectoryOriginals,
    NodeDiskEntryKind,
};
#[cfg(test)]
pub(crate) use file::FailedFileWitness;
pub use file::NodeDiskFile;
pub(crate) use file::{
    FailedCloseReport, FailedFileTransfer, NodeDiskCloseOutcome, sync_ordered_native,
};
use ledger::AccountedInode;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDiskConfig {
    /// Exact private, non-overlapping persistent roots. Each root is one
    /// filesystem, and roots may be on different filesystems: every
    /// filesystem keeps its own promises and `min_free_bytes` floor, and every
    /// reservation is charged to the filesystem of the root it writes in.
    /// `max_bytes` and the namespace limits stay one total for the owner.
    pub roots: BTreeMap<String, PathBuf>,
    pub max_bytes: u64,
    /// Explicit native database cache and descriptor ceilings. Actual live
    /// allocations remain subject to this installed owner's shared admission.
    pub native_storage: crate::NodeStorageConfig,
    pub maintenance_reserve_bytes: u64,
    pub min_free_bytes: u64,
    /// Simultaneous file owners. Each owner retains at most two descriptors.
    pub max_open_files: u32,
    /// Independent operational directory descriptors, separate from file owners.
    pub max_open_directories: u32,
    /// Explicit per-directory namespace admission. No implicit filesystem bound.
    pub directory_policy: DirectoryPolicy,
    /// Standing physical allowance for every regular inode, including closed
    /// files. Installation must qualify the configured filesystem bound.
    pub file_allocation_policy: FileAllocationPolicy,
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

/// Required first-release bound on regular-file allocation above rounded EOF.
/// The allowance is rounded to the installed filesystem unit, charged before
/// creation or growth, and retained through close and census. It is a filesystem
/// qualification assumption, not a portable guarantee supplied by this type.
/// Explicit zero asserts that allocation never exceeds rounded EOF.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileAllocationPolicy {
    pub maximum_extra_extent_bytes: u64,
}
impl FileAllocationPolicy {
    pub fn new(maximum_extra_extent_bytes: u64) -> Result<Self> {
        let policy = Self {
            maximum_extra_extent_bytes,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.maximum_extra_extent_bytes <= i64::MAX as u64,
            "regular-file allocation allowance is invalid"
        );
        Ok(())
    }

    /// Explicit local fixture allowance; not an implicit production policy or
    /// a claim that every filesystem operation fits this amount.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fixture() -> Self {
        Self {
            maximum_extra_extent_bytes: 1 << 20,
        }
    }
}

impl NodeDiskConfig {
    pub fn validate(&self) -> Result<()> {
        self.directory_policy.validate()?;
        self.file_allocation_policy.validate()?;
        self.native_storage.validate()?;
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
    #[cfg(test)]
    pause_at: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    pause: Mutex<Option<CensusPause>>,
}
/// Test-only rendezvous that holds a census at one checkpoint, with every lock
/// its caller owns, until the fixture releases or drops `release`.
#[cfg(test)]
pub(crate) struct CensusPause {
    pub(crate) entered: std::sync::mpsc::Sender<()>,
    pub(crate) release: std::sync::mpsc::Receiver<()>,
}
impl CensusCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    fn check(&self) -> Result<()> {
        #[cfg(test)]
        {
            let at = self.cancel_at.load(Ordering::Relaxed);
            let pause_at = self.pause_at.load(Ordering::Relaxed);
            if at != 0 || pause_at != 0 {
                let checkpoint = self.checkpoints.fetch_add(1, Ordering::Relaxed) + 1;
                if at != 0 && checkpoint >= at {
                    self.cancel();
                }
                if checkpoint == pause_at
                    && let Some(pause) = self.pause.lock().unwrap().take()
                {
                    let _ = pause.entered.send(());
                    let _ = pause.release.recv();
                }
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

/// At most this many filesystems hold one owner's roots.
pub(super) const MAX_FILESYSTEMS: usize = 8;

/// A filesystem holding at least one installed root. Every promise for an
/// inode beneath those roots, and the free-space floor its growth must keep,
/// uses this filesystem's shared device ledger. The extent budget stays one
/// owner total.
struct Filesystem {
    /// The roots' device number, or a fixture-assigned one.
    device: u64,
    promises: DeviceDisk,
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
    /// The margin the floor check of `reserve` compares each request on this
    /// filesystem with, from the same locked sample as the three figures
    /// above: `filesystem_available_bytes - filesystem_pending_bytes -
    /// filesystem_min_free_bytes`. A request of `n` bytes passes the floor
    /// exactly when `n` is at most this; negative once overdrawn.
    pub filesystem_headroom_bytes: Option<i64>,
    pub filesystem_total_bytes: Option<u64>,
    pub filesystem_used_bytes: Option<u64>,
    /// The device number of the filesystem the `filesystem_*` fields describe.
    pub filesystem_device: u64,
    /// Every filesystem's shared admission is ready.
    pub filesystem_admission_ready: bool,
    /// One entry per filesystem when the roots span more than one. The
    /// `filesystem_*` fields above then describe the filesystem with the least
    /// headroom (available bytes beyond its floor and outstanding promises),
    /// so a single readiness check covers them all.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filesystems: Vec<NodeDiskFilesystemSnapshot>,
    /// Refusals of each persistent capacity check since this owner opened.
    pub capacity_refusals: [CapacityRefusalCount; 5],
    /// The most recent refusal, with the figures its check compared.
    pub last_capacity_refusal: Option<CapacityRefusal>,
}

/// One filesystem of a multi-filesystem persistent owner.
#[derive(Clone, Debug, Serialize)]
pub struct NodeDiskFilesystemSnapshot {
    /// The filesystem's device number.
    pub device: u64,
    /// Installed root labels on this filesystem.
    pub roots: Vec<String>,
    /// Outstanding promises of every owner on this filesystem.
    pub pending_bytes: u64,
    /// This owner's part of `pending_bytes`.
    pub owner_pending_bytes: u64,
    pub min_free_bytes: u64,
    pub available_bytes: Option<u64>,
    /// This filesystem's floor margin: available less pending less min-free,
    /// from the same locked sample. A reservation in one of its roots of `n`
    /// bytes passes the floor exactly when `n` is at most this.
    pub headroom_bytes: Option<i64>,
    pub total_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    pub admission_ready: bool,
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
        self.child_bytes(name.to_bytes())
    }

    fn child_bytes(self, name: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"kasumi-node-disk-child-v1\0");
        hash.update(self.0);
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name);
        Self(hash.finalize().into())
    }
}

/// The admitted physical identity survives descriptor close. Reservations and
/// observed extents update this existing entry without allocating during I/O.
/// `bytes` includes the standing regular-file allowance even after close;
/// `pending` records the part not represented by allocated physical blocks.
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

    /// The promise a fresh durable observation of this settled entry adds, or
    /// `None` when it may not be adopted. Binding, EOF and the paid ceiling
    /// must be exact; the filesystem may only have released allocation since
    /// the last post-fsync observation (APFS can count blocks past EOF there
    /// and free them once the descriptor closes). Allocation that grew without
    /// an owner's write stays unexplained, and adopting it would refund credit.
    fn released(&self, observed: &Self) -> Option<u64> {
        let released = observed.pending.checked_sub(self.pending)?;
        (*observed
            == Self {
                pending: observed.pending,
                ..*self
            })
        .then_some(released)
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
    transaction_children: u64,
    transaction_claimed: bool,
    /// Namespace generation of the last settled change to this directory's
    /// entries; zero from census. A listing compares only its own directory.
    membership_generation: u64,
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
    transaction_files: u64,
    transaction_descriptors: u32,
    transaction_witnesses: u32,
    directory_bytes: u64,
    directories: u64,
    refusals: RefusalLedger<5>,
    live: fixed_map::Banks<Weak<file::FileOwner>>,
    file_custody: file::CustodySlots,
    accounted: fixed_map::Banks<AccountedInode>,
}

impl State {
    /// Every holder outside this owner's own custody has retired. Retained
    /// failed-file custody and an unsettled directory operation are internal:
    /// only an accepted census closes and retires them.
    fn external_owners_drained(&self) -> bool {
        self.open_files == self.file_custody.internal_owners()
            && self.open_directories == u32::from(self.pending_directory.is_some())
            && self.open_directory_cursors == 0
            && self.census_streams.outstanding() == 0
            && self.transaction_witnesses == 0
    }

    fn namespace_witnesses(&self) -> u32 {
        u32::from(
            self.namespace_batch
                .as_ref()
                .is_some_and(|batch| batch.witness_live),
        ) + self.transaction_witnesses
            + u32::from(
                self.namespace_claim
                    .as_ref()
                    .is_some_and(|claim| claim.witness_live),
            )
    }

    fn fenced(&self) -> DiskOpenError {
        DiskOpenError::OwnerFenced {
            phase: self.phase,
            open_files: self.open_files,
            open_directories: self.open_directories,
            cursors: self.open_directory_cursors,
            census_streams: self.census_streams.outstanding(),
            namespace_witnesses: self.namespace_witnesses(),
            retained_attempts: self.file_custody.retained_attempts(),
        }
    }
}

/// An installed owner outlives all service/database handles. The strong registry
/// deliberately retains its locks, sparse-file promises and aggregate charges.
/// `pause` and `reconcile` are explicit; dropping an Arc never credits disk space.
pub struct NodeDisk {
    config: NodeDiskConfig,
    memory: Arc<dyn NodeDiskMemoryAdmission>,
    roots: BTreeMap<String, Root>,
    _ancestor_locks: Vec<File>,
    filesystems: Box<[Filesystem]>,
    /// The largest allocation unit among the filesystems. Rounding a smaller
    /// unit's extents up to it only overstates charges and promises.
    unit: u64,
    state: Mutex<State>,
    #[cfg(test)]
    available_override: Mutex<Option<u64>>,
    #[cfg(test)]
    filesystem_available_override: Mutex<[Option<u64>; MAX_FILESYSTEMS]>,
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
    // Physical file synchronizations by owners of this disk: [ordered, full].
    #[cfg(test)]
    synchronizations: [std::sync::atomic::AtomicU64; 2],
    // Pauses the next file synchronization after it released State.
    #[cfg(test)]
    sync_pause: Mutex<Option<file::SyncPause>>,
    // Bytes read through this disk's file owners.
    #[cfg(test)]
    read_bytes: std::sync::atomic::AtomicU64,
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
    /// Accounting device of each filesystem, in filesystem index order.
    devices: Vec<u64>,
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
    pub fn native_storage_config(&self) -> crate::NodeStorageConfig {
        self.config.native_storage
    }

    pub(crate) fn binding<'owner, 'path>(
        &'owner self,
        path: &'path std::path::Path,
    ) -> Result<(&'owner str, &'path std::path::Path)> {
        self.config.binding(path)
    }

    pub fn memory(&self) -> &Arc<dyn NodeDiskMemoryAdmission> {
        &self.memory
    }

    /// Observe the exact installed name's enrolled kind without allocating or
    /// acquiring authority. The caller still verifies its ancestry through the
    /// canonical directory owner before acting on this classification.
    pub(crate) fn enrolled_name_kind(
        &self,
        root: &str,
        relative: &std::path::Path,
    ) -> io::Result<Option<NodeDiskEntryKind>> {
        use std::{os::unix::ffi::OsStrExt, path::Component};
        let mut state = self.lock_state();
        if state.phase != NodeDiskPhase::Open || !self.admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        let installed = self.roots.get(root).ok_or(io::ErrorKind::InvalidInput)?;
        installed
            .verify_nonallocating()
            .inspect_err(|_| self.fail_locked(&mut state))?;
        let mut binding = NamespaceBinding::root(installed.identity);
        let mut depth = 0u32;
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(io::ErrorKind::InvalidInput.into());
            };
            let name = name.as_bytes();
            depth = depth.checked_add(1).ok_or(io::ErrorKind::InvalidInput)?;
            if depth >= self.config.max_depth
                || name.len() > self.config.max_name_bytes as usize
                || name.contains(&0)
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            binding = binding.child_bytes(name);
        }
        Ok(state.accounted.values().find_map(|entry| {
            (entry.binding() == binding).then_some(match entry {
                AccountedInode::File(_) => NodeDiskEntryKind::File,
                AccountedInode::Directory(_) => NodeDiskEntryKind::Directory,
            })
        }))
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
    /// Fixture roots on one physical filesystem, accounted as the assigned
    /// device numbers: each distinct number is a filesystem with its own
    /// isolated promise ledger, floor and free-space observation.
    #[cfg(test)]
    pub(crate) fn open_fixture_filesystems(
        config: &NodeDiskConfig,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
        devices: BTreeMap<String, u64>,
    ) -> std::result::Result<Arc<Self>, DiskOpenError> {
        Self::open_inner(
            config,
            memory,
            &CensusCancellation::default(),
            DeviceSelection::Assigned(devices),
        )
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
            owner.require_installed(config, &memory)?;
            // A fenced owner is never shared: its holders may still observe
            // uncertain I/O. Only reopen_fenced clears it after they drain.
            let state = owner.lock_state();
            if state.phase != NodeDiskPhase::Open {
                return Err(state.fenced());
            }
            drop(state);
            return Ok(owner.clone());
        }
        let requirement = Self::memory_requirements(config)?;
        let charge = memory.clone().reserve_installed(requirement.owner_bytes)?;
        let registry_charge = memory
            .clone()
            .reserve_installed(requirement.registry_bytes)?;
        // The new fixed bank has no failure path after configured-root FD acquisition.
        let file_custody = file::CustodySlots::new(config.max_open_files)?;
        #[cfg(test)]
        let assigned = match &selection {
            DeviceSelection::Assigned(devices) => Some(devices),
            _ => None,
        };
        #[cfg(not(test))]
        let assigned = None;
        let (roots, devices) = open_roots(config, assigned)?;
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
        let mut unit = 0;
        for root in roots.values() {
            unit = unit.max(filesystem(&root.file)?.1);
        }
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
                devices,
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
        let registrations =
            selection.open_each(&prepared.devices, config.min_free_bytes, &prepared.memory)?;
        let PreparedResources {
            config,
            memory,
            roots,
            devices,
            ancestor_locks,
            accounted,
            live,
            file_custody,
            streams: _,
            charge,
        } = registration.take();
        let filesystems = devices
            .into_iter()
            .zip(registrations)
            .map(|(device, promises)| Filesystem { device, promises })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let disk = ProvisionalOwner::new(Self {
            config,
            memory,
            roots,
            _ancestor_locks: ancestor_locks,
            filesystems,
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
                transaction_files: 0,
                transaction_descriptors: 0,
                transaction_witnesses: 0,
                directory_bytes: totals.directory_bytes,
                directories: totals.directories,
                refusals: RefusalLedger::default(),
                live,
                file_custody,
                accounted,
            }),
            #[cfg(test)]
            available_override: Mutex::new(None),
            #[cfg(test)]
            filesystem_available_override: Mutex::new([None; MAX_FILESYSTEMS]),
            #[cfg(test)]
            available_error: AtomicBool::new(false),
            #[cfg(test)]
            after_file_close: Mutex::new(None),
            #[cfg(test)]
            shrink_failure: Mutex::new(None),
            #[cfg(test)]
            parent_sync_failure: AtomicBool::new(false),
            #[cfg(test)]
            synchronizations: Default::default(),
            #[cfg(test)]
            sync_pause: Mutex::new(None),
            #[cfg(test)]
            read_bytes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            namespace_failure: std::sync::atomic::AtomicU8::new(0),
            _memory_charge: charge,
        });
        drop(disk.state.lock().expect("unpublished node disk state"));
        #[cfg(test)]
        {
            drop(disk.available_override.lock().unwrap());
            drop(disk.filesystem_available_override.lock().unwrap());
            // First-use allocation belongs to acquisition, never a publication
            // or descriptor destructor, even for dormant fault-injection hooks.
            drop(disk.after_file_close.lock().unwrap());
            drop(disk.shrink_failure.lock().unwrap());
            drop(disk.sync_pause.lock().unwrap());
        }
        // Publish one complete census, each filesystem's promises on its own
        // device. Existing over-budget files remain charged; read/cleanup can
        // proceed, while every new reservation checks both limits.
        for (filesystem, census) in disk.filesystems.iter().zip(totals.filesystem_pending) {
            let mut promises = filesystem.promises.lock();
            let next = promises
                .checked_add(census)
                .context("persistent census promises overflow")?;
            promises.set_pending(next)?;
        }
        Ok(disk.install(&mut registration))
    }

    /// The single registry path that clears a fenced owner for a new runtime,
    /// operator or store recovery. It applies `open`'s exact budget, memory
    /// admission and root identity checks. Every external file, directory,
    /// cursor, census stream and namespace witness must already have retired:
    /// a live holder returns `OwnerFenced` at once, without waiting or census.
    /// Retained failed-file custody is internal and only the census retires
    /// it, so `pause`'s stricter drain check would make such a fence permanent.
    /// The exact checked owner Arc is retained before releasing the registry
    /// and State guards. Pending-directory original diagnostics retire outside
    /// those guards. The registry is then reacquired and the exact installed
    /// owner, configuration, admission and roots are revalidated. The final
    /// drain check, census and accounting publication hold the registry and
    /// owner's State gate, so concurrent opens return `RegistryBusy` throughout
    /// that census. The same owner returns only after a fresh census is accepted.
    /// Cancellation, a
    /// census failure or shared device poison (restart-only) keep it fenced
    /// with every prior charge and promise; a started census that fails marks
    /// it Failed. An Open owner already reflects its last accepted census and
    /// is shared exactly as `open` would share it.
    pub fn reopen_fenced(
        config: &NodeDiskConfig,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
        cancel: &CensusCancellation,
    ) -> std::result::Result<Arc<Self>, DiskOpenError> {
        config.validate()?;
        cancel.check()?;
        let installed = registry().try_lock().ok_or(DiskOpenError::RegistryBusy)?;
        let owner = installed
            .find(|entry| {
                entry
                    .config()
                    .is_some_and(|installed| installed.roots == config.roots)
            })
            .context("no installed persistent owner to reopen")?
            .owner()?;
        owner.require_installed(config, &memory)?;
        disk_memory::require(
            !owner.state.is_poisoned(),
            "poisoned persistent ownership requires process restart",
        )?;
        let state = owner.lock_state();
        if state.phase == NodeDiskPhase::Open {
            return Ok(owner.clone());
        }
        if state.namespace_witnesses() != 0 || !state.external_owners_drained() {
            return Err(state.fenced());
        }
        disk_memory::require(
            !owner.promises_poisoned(),
            "shared filesystem promises are poisoned; process restart required",
        )?;
        let retained = owner.clone();
        drop(state);
        drop(installed);
        // Opaque original destructors must run outside registry and State.
        // Their retained owner cannot authorize a census until the installed
        // identity and complete drain are checked again under both gates.
        retained.retire_pending_directory_diagnostics()?;
        let installed = registry().try_lock().ok_or(DiskOpenError::RegistryBusy)?;
        let owner = installed
            .find(|entry| {
                entry
                    .config()
                    .is_some_and(|installed| installed.roots == config.roots)
            })
            .context("no installed persistent owner to reopen")?
            .owner()?;
        disk_memory::require(
            Arc::ptr_eq(owner, &retained),
            "installed persistent owner changed during reopen",
        )?;
        owner.require_installed(config, &memory)?;
        disk_memory::require(
            !owner.state.is_poisoned(),
            "poisoned persistent ownership requires process restart",
        )?;
        let mut state = owner.lock_state();
        if state.phase == NodeDiskPhase::Open {
            return Ok(retained);
        }
        if state.namespace_witnesses() != 0 || !state.external_owners_drained() {
            return Err(state.fenced());
        }
        disk_memory::require(
            !owner.promises_poisoned(),
            "shared filesystem promises are poisoned; process restart required",
        )?;
        owner.reconcile_locked(&mut state, cancel)?;
        Ok(retained)
    }

    /// Registered-owner identity shared by `open` and `reopen_fenced`: exact
    /// budgets, the exact memory admission Arc and unsubstituted roots. This
    /// performs no allocation, census or phase transition.
    fn require_installed(
        &self,
        config: &NodeDiskConfig,
        memory: &Arc<dyn NodeDiskMemoryAdmission>,
    ) -> std::result::Result<(), DiskOpenError> {
        disk_memory::require(
            self.config == *config,
            "installed persistent owner has different budgets",
        )?;
        disk_memory::require(
            Arc::ptr_eq(&self.memory, memory),
            "installed persistent owner has different memory admission",
        )?;
        for root in self.roots.values() {
            root.verify_nonallocating()?;
        }
        Ok(())
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
            native_storage: crate::test_utils::node_storage_config(),
            maintenance_reserve_bytes: 1 << 30,
            min_free_bytes: 0,
            max_open_files: 256,
            max_open_directories: 256,
            directory_policy: DirectoryPolicy::fixture(),
            file_allocation_policy: FileAllocationPolicy::fixture(),
            max_persistent_files: 16_384,
            max_persistent_subdirectories: 16_384,
            census_work_per_step: 16_384,
            max_depth: 64,
            max_name_bytes: 255,
        })
    }

    /// Whether no uncertain effect has failed this disk.
    pub(crate) fn is_open(&self) -> bool {
        self.lock_state().phase == NodeDiskPhase::Open
    }

    pub fn snapshot(&self) -> NodeDiskSnapshot {
        let state = self.lock_state();
        let mut tightest = None;
        let mut admission_ready = true;
        let mut filesystems = Vec::new();
        for index in 0..self.filesystems.len() {
            let observed = self.observe_filesystem(index);
            admission_ready &= observed.admission_ready;
            // The floor check's own margin; an unobservable filesystem is
            // the tightest of all.
            let headroom = observed.available_bytes.map_or(i128::MIN, |available| {
                floor_headroom(available, observed.pending_bytes, observed.min_free_bytes)
            });
            if self.filesystems.len() > 1 {
                filesystems.push(observed.clone());
            }
            if tightest
                .as_ref()
                .is_none_or(|(least, _): &(i128, NodeDiskFilesystemSnapshot)| headroom < *least)
            {
                tightest = Some((headroom, observed));
            }
        }
        let (_, tightest) = tightest.expect("installed filesystems");
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
            filesystem_pending_bytes: tightest.pending_bytes,
            filesystem_min_free_bytes: tightest.min_free_bytes,
            filesystem_available_bytes: tightest.available_bytes,
            filesystem_headroom_bytes: tightest.headroom_bytes,
            filesystem_total_bytes: tightest.total_bytes,
            filesystem_used_bytes: tightest.used_bytes,
            filesystem_device: tightest.device,
            filesystem_admission_ready: admission_ready,
            filesystems,
            capacity_refusals: state.refusals.counts(CapacityCheck::PERSISTENT),
            last_capacity_refusal: state.refusals.last(),
        }
    }

    /// The most recent capacity refusal of this owner, for diagnostics that
    /// only received the `StorageFull` kind. Another caller's later refusal
    /// can replace it; the typed `ReserveError` names the caller's own.
    pub(crate) fn last_capacity_refusal(&self) -> Option<CapacityRefusal> {
        self.lock_state().refusals.last()
    }

    /// Count and keep one refusal under the caller's State guard.
    fn refused(state: &mut State, refusal: CapacityRefusal) -> ReserveError {
        ReserveError::Capacity(state.refusals.record(refusal))
    }

    fn observe_filesystem(&self, index: usize) -> NodeDiskFilesystemSnapshot {
        let filesystem = &self.filesystems[index];
        // One locked sample: the same available, promises and floor that a
        // concurrent reservation on this filesystem compares, since it holds
        // this device guard while sampling too.
        let promises = filesystem.promises.lock();
        let physical = filesystem_usage(&self.filesystem_root(index).file).ok();
        let available = self.available(index).ok();
        let min_free = promises.minimum_free_bytes();
        NodeDiskFilesystemSnapshot {
            device: filesystem.device,
            roots: if self.filesystems.len() > 1 {
                self.roots
                    .iter()
                    .filter(|(_, root)| root.filesystem == index)
                    .map(|(label, _)| label.clone())
                    .collect()
            } else {
                Vec::new()
            },
            pending_bytes: *promises,
            owner_pending_bytes: promises.owned(),
            min_free_bytes: min_free,
            available_bytes: available,
            headroom_bytes: available.map(|available| {
                let headroom = floor_headroom(available, *promises, min_free);
                i64::try_from(headroom).unwrap_or(if headroom < 0 { i64::MIN } else { i64::MAX })
            }),
            total_bytes: physical.map(|(total, _)| total),
            used_bytes: physical.map(|(_, used)| used),
            admission_ready: promises.admission_ready(),
        }
    }

    /// The first installed root on filesystem `index`, used for its
    /// free-space and allocation-unit observations.
    fn filesystem_root(&self, index: usize) -> &Root {
        self.roots
            .values()
            .find(|root| root.filesystem == index)
            .expect("every filesystem holds an installed root")
    }

    /// The filesystem charged for every inode beneath an installed root.
    fn root_filesystem(&self, root: &str) -> io::Result<usize> {
        self.roots
            .get(root)
            .map(|root| root.filesystem)
            .ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }

    /// The filesystem of an enrolled directory: the one of the installed root
    /// its retained parent chain ends at. Directories are never renamed, so
    /// the chain is the directory's actual ancestry.
    fn directory_filesystem(&self, state: &State, mut identity: Identity) -> io::Result<usize> {
        for _ in 0..=self.config.max_depth {
            let entry = state
                .accounted
                .get(&identity)
                .and_then(AccountedInode::directory)
                .ok_or(io::ErrorKind::InvalidData)?;
            match entry.parent {
                Some(parent) => identity = parent,
                None => {
                    return self
                        .roots
                        .values()
                        .find(|root| root.identity == identity)
                        .map(|root| root.filesystem)
                        .ok_or_else(|| io::ErrorKind::InvalidData.into());
                }
            }
        }
        Err(io::ErrorKind::InvalidData.into())
    }

    /// Every filesystem's shared admission is ready: no device poison and no
    /// registered owner's uncertainty on any of them.
    fn admission_ready(&self) -> bool {
        self.filesystems
            .iter()
            .all(|filesystem| filesystem.promises.lock().admission_ready())
    }

    fn promises_poisoned(&self) -> bool {
        self.filesystems
            .iter()
            .any(|filesystem| filesystem.promises.lock().poisoned())
    }

    /// The single-filesystem fixture's device ledger.
    #[cfg(test)]
    pub(crate) fn device(&self) -> &DeviceDisk {
        assert_eq!(self.filesystems.len(), 1, "one filesystem");
        &self.filesystems[0].promises
    }

    /// The device ledger of the filesystem holding `root`.
    #[cfg(test)]
    pub(crate) fn root_device(&self, root: &str) -> &DeviceDisk {
        &self.filesystems[self.root_filesystem(root).unwrap()].promises
    }

    /// Report `available` free bytes for the filesystem holding `root`.
    #[cfg(test)]
    pub(crate) fn set_root_available_for_test(&self, root: &str, available: Option<u64>) {
        let index = self.root_filesystem(root).unwrap();
        self.filesystem_available_override.lock().unwrap()[index] = available;
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
        cancel.check()?;
        self.retire_pending_directory_diagnostics()?;
        let mut state = self.lock_state();
        self.reconcile_locked(&mut state, cancel)
    }

    /// The drain check, census and publication run under one State guard, so
    /// no holder can appear between the check and the accepted census.
    fn reconcile_locked(&self, state: &mut State, cancel: &CensusCancellation) -> Result<()> {
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
            state.namespace_witnesses() == 0,
            "persistent namespace admission witness is still live"
        );
        ensure!(
            state.external_owners_drained(),
            "persistent file or directory owners are still live"
        );
        if let Some(operation) = &mut state.pending_directory
            && let Err(error) = operation.close_resources()
        {
            self.fail_locked(state);
            return Err(error.into());
        }
        if let Err(error) = state.file_custody.close_retained() {
            self.fail_locked(state);
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
                self.fail_locked(state);
                return Err(error);
            }
        };
        // Each filesystem replaces exactly this owner's own contribution to
        // its shared aggregate with the census of the roots it holds.
        let republished = |filesystem: &Filesystem, census: u64| {
            let promises = filesystem.promises.lock();
            promises
                .checked_sub(promises.owned())
                .and_then(|n| n.checked_add(census))
        };
        if self
            .filesystems
            .iter()
            .zip(totals.filesystem_pending)
            .any(|(filesystem, census)| republished(filesystem, census).is_none())
        {
            state.accounted.cancel_stage();
            self.fail_locked(state);
            anyhow::bail!("persistent census promise accounting overflow");
        }
        if let Err(error) = cancel.check() {
            state.accounted.cancel_stage();
            self.fail_locked(state);
            return Err(error);
        }
        if let Some(operation) = &mut state.pending_directory
            && let Err(error) = operation.retire_before_release()
        {
            state.accounted.cancel_stage();
            self.fail_locked(state);
            return Err(error.into());
        }
        // A filesystem published before a later one fails keeps its new
        // contribution: the next census replaces exactly that contribution.
        for (filesystem, census) in self.filesystems.iter().zip(totals.filesystem_pending) {
            let mut promises = filesystem.promises.lock();
            let published = promises
                .checked_sub(promises.owned())
                .and_then(|n| n.checked_add(census))
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
                .and_then(|next| promises.set_pending(next));
            if let Err(error) = published {
                drop(promises);
                state.accounted.cancel_stage();
                self.fail_locked(state);
                let error = if let Some(operation) = &mut state.pending_directory {
                    operation.retain_publication_error(error)
                } else {
                    error
                };
                return Err(error.into());
            }
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
            state.transaction_files = 0;
            state.transaction_descriptors = 0;
        }));
        if let Err(payload) = retired {
            // This inline slot is part of State's preadmitted geometry. The
            // actual opaque panic remains owned; its payload size is not a
            // proved bounded allocator/RSS allowance. Never retry retirement.
            state.census_retirement_panic = Some(payload);
            self.fail_locked(state);
            anyhow::bail!("persistent original outcome retirement panicked");
        }
        state.open_files = 0;
        state.open_directories = 0;
        for filesystem in &*self.filesystems {
            filesystem.promises.lock().reconcile_owner();
        }
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

    /// Every physical synchronization that flushes the device's volatile
    /// cache, by an owner of this disk.
    fn synchronized<R>(&self, sync: impl FnOnce() -> io::Result<R>) -> io::Result<R> {
        let result = crate::sync_trace::sync(sync);
        #[cfg(test)]
        if result.is_ok() {
            self.synchronizations[1].fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// An ordering synchronization that reports the level it reached.
    fn synchronized_ordered(
        &self,
        sync: impl FnOnce() -> io::Result<file::Synced>,
    ) -> io::Result<file::Synced> {
        let result = crate::sync_trace::sync(sync);
        #[cfg(test)]
        if let Ok(reached) = &result {
            let full = usize::from(*reached == file::Synced::Durable);
            self.synchronizations[full].fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Hold a file synchronization that already released State until the
    /// test releases it.
    #[cfg(test)]
    fn sync_checkpoint(&self) {
        let pause = self.sync_pause.lock().unwrap().take();
        if let Some(pause) = pause {
            let _ = pause.entered.send(());
            pause
                .release
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("release file synchronization fixture");
        }
    }

    /// Physical file synchronizations issued through this disk's owners, as
    /// (ordered, full). An ordered sync without a barrier counts as full.
    #[cfg(test)]
    pub(crate) fn physical_synchronizations(&self) -> (u64, u64) {
        (
            self.synchronizations[0].load(Ordering::Relaxed),
            self.synchronizations[1].load(Ordering::Relaxed),
        )
    }

    /// Bytes read through this disk's file owners.
    #[cfg(test)]
    pub(crate) fn physical_read_bytes(&self) -> u64 {
        self.read_bytes.load(Ordering::Relaxed)
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

    /// Every filesystem's registration becomes uncertain: none of this
    /// owner's promises can be trusted until a drained census replaces them.
    fn fail_locked(&self, state: &mut State) {
        state.phase = NodeDiskPhase::Failed;
        for filesystem in &*self.filesystems {
            filesystem.promises.lock().fail_owner();
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, State> {
        crate::sync_trace::lock(&self.state, crate::sync_trace::Lock::State).unwrap_or_else(|p| {
            let mut state = p.into_inner();
            state.phase = NodeDiskPhase::Failed;
            for filesystem in &*self.filesystems {
                filesystem.promises.lock().fail_owner();
            }
            state
        })
    }

    fn available(&self, filesystem_index: usize) -> io::Result<u64> {
        #[cfg(test)]
        if self.available_error.load(Ordering::Relaxed) {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        #[cfg(test)]
        if let Some(value) = self.filesystem_available_override.lock().unwrap()[filesystem_index] {
            return Ok(value);
        }
        #[cfg(test)]
        if let Some(value) = *self.available_override.lock().unwrap() {
            return Ok(value);
        }
        filesystem(&self.filesystem_root(filesystem_index).file).map(|v| v.0)
    }

    /// Charge `delta` to the owner's extent budget and to the promises of
    /// filesystem `index`, whose own floor and free space must cover it.
    /// Refusals are typed; `?` in an `io::Result` caller turns them into
    /// `StorageFull` without allocating.
    fn reserve(
        &self,
        state: &mut State,
        index: usize,
        delta: u64,
        work: DiskWork,
    ) -> std::result::Result<(), ReserveError> {
        OnFilesystem {
            config: &self.config,
            device: &self.filesystems[index].promises,
            disk: self,
            index,
        }
        .reserve(state, delta, work)
    }
}

/// One filesystem of an owner, beside the owner's shared extent budget: the
/// device ledger and free space a reservation in one of its roots uses.
struct OnFilesystem<'a> {
    config: &'a NodeDiskConfig,
    device: &'a DeviceDisk,
    disk: &'a NodeDisk,
    index: usize,
}

impl OnFilesystem<'_> {
    fn available(&self) -> io::Result<u64> {
        self.disk.available(self.index)
    }

    /// Charge `delta` bytes of extent and of this filesystem's promise.
    /// Refusals are typed and allocation-free; a floor refusal names this
    /// filesystem's device. Observation failures fail the owner as before.
    fn reserve(
        &self,
        state: &mut State,
        delta: u64,
        work: DiskWork,
    ) -> std::result::Result<(), ReserveError> {
        if state.phase != NodeDiskPhase::Open {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let maximum = match work {
            DiskWork::Foreground => self.config.max_bytes - self.config.maintenance_reserve_bytes,
            DiskWork::Maintenance => self.config.max_bytes,
        };
        let Some(next) = state.bytes.checked_add(delta).filter(|n| *n <= maximum) else {
            let refusal = CapacityRefusal {
                check: CapacityCheck::PersistentExtent,
                requested: delta,
                in_use: state.bytes,
                limit: maximum,
                min_free: 0,
                filesystem: None,
            };
            return Err(NodeDisk::refused(state, refusal));
        };
        let mut promises = self.device.lock();
        if !promises.admission_ready() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let available = self.available().inspect_err(|_| {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
        })?;
        let pending = *promises;
        let min_free = promises.minimum_free_bytes();
        // Passing the floor bounds pending + delta by available, so neither
        // promise sum below can overflow once this check admits the request.
        let floor = CapacityRefusal {
            check: CapacityCheck::PersistentFilesystemFloor,
            requested: delta,
            in_use: pending,
            limit: available,
            min_free,
            filesystem: Some(self.disk.filesystems[self.index].device),
        };
        if i128::from(delta) > floor_headroom(available, pending, min_free) {
            drop(promises);
            return Err(NodeDisk::refused(state, floor));
        }
        let (Some(next_promises), Some(own_pending)) =
            (pending.checked_add(delta), state.pending.checked_add(delta))
        else {
            drop(promises);
            return Err(NodeDisk::refused(state, floor));
        };
        promises
            .set_pending(next_promises)
            .inspect_err(|_| state.phase = NodeDiskPhase::Failed)?;
        state.bytes = next;
        state.pending = own_pending;
        Ok(())
    }
}

impl NodeDisk {
    /// Promise again the allocation a closed settled file released since its
    /// last observation. The paid charge is unchanged and no credit returns.
    /// The caller holds State and matched the observed inode's identity and
    /// binding. A registered owner's budget stays authoritative: its own next
    /// observation adopts the release, so its entry is left untouched.
    fn adopt_released_allocation(
        &self,
        state: &mut State,
        filesystem_index: usize,
        identity: Identity,
        observed: AccountedFile,
    ) -> io::Result<()> {
        let released = state
            .accounted
            .get(&identity)
            .and_then(AccountedInode::file)
            .and_then(|entry| entry.released(&observed))
            .ok_or(io::ErrorKind::InvalidData)?;
        if released == 0 || state.live.contains_key(&identity) {
            return Ok(());
        }
        if state.phase == NodeDiskPhase::Failed || !self.admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        let mut promises = self.filesystems[filesystem_index].promises.lock();
        let (Some(next), Some(own_next)) = (
            promises.checked_add(released),
            state.pending.checked_add(released),
        ) else {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(io::ErrorKind::InvalidData.into());
        };
        promises
            .set_pending(next)
            .inspect_err(|_| state.phase = NodeDiskPhase::Failed)?;
        state.pending = own_next;
        *state
            .accounted
            .get_mut(&identity)
            .and_then(AccountedInode::file_mut)
            .expect("validated enrolled inode") = observed;
        Ok(())
    }
}

/// Extent arithmetic past `u64` cannot be charged; it is not a capacity check.
fn rounded(len: u64, unit: u64) -> io::Result<u64> {
    len.div_ceil(unit)
        .checked_mul(unit)
        .ok_or_else(|| io::ErrorKind::StorageFull.into())
}

/// Raw observed extent, independent of the configured standing allowance. This
/// remains available for recording a physical overrun before owner fencing.
fn extent(metadata: &std::fs::Metadata, unit: u64) -> io::Result<(u64, u64)> {
    let allocated = metadata
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    let bytes = rounded(metadata.len().max(allocated), unit)?;
    Ok((bytes, bytes - allocated))
}

/// Standing charge for an exact logical limit. Live growth uses reserved EOF;
/// durable enrollment and settlement use actual EOF. The extra allowance is
/// not released merely because a descriptor closes or allocation materializes.
fn file_ceiling(logical_len: u64, unit: u64, policy: FileAllocationPolicy) -> io::Result<u64> {
    rounded(logical_len, unit)?
        .checked_add(rounded(policy.maximum_extra_extent_bytes, unit)?)
        .ok_or_else(|| io::ErrorKind::StorageFull.into())
}

/// Canonical durable accounting. Keep this separate from raw `extent`: a live
/// owner must first retain evidence of any allocation beyond its admitted
/// ceiling before fencing, rather than lose it through this rejection path.
fn file_extent(
    metadata: &std::fs::Metadata,
    unit: u64,
    policy: FileAllocationPolicy,
) -> io::Result<(u64, u64)> {
    let allocated = metadata
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    file_extent_from_parts(metadata.len(), allocated, unit, policy)
}

fn file_extent_from_parts(
    logical_len: u64,
    allocated: u64,
    unit: u64,
    policy: FileAllocationPolicy,
) -> io::Result<(u64, u64)> {
    let bytes = file_ceiling(logical_len, unit, policy)?;
    let pending = bytes
        .checked_sub(allocated)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok((bytes, pending))
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
