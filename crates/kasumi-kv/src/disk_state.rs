//! The disk-directory state machine that replaces Core's resident key map.
//!
//! This is the composition boundary: operation locations are prepared first,
//! COW pages are synchronized, the log commit binds the exact directory, and
//! only then does the mirrored root select it. Reopen adopts validated roots
//! from replay without retaining a key map. Core retains the exact backend
//! owner through opening failure and final native close.

#[cfg(test)]
use crate::core::ResidentLease;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::arena::{DirectoryArenaBackend, DirectoryArenaRoll, recover_directory_intent};
#[cfg(test)]
use crate::cache::CachedBytes;
use crate::cache::{CacheConfig, CacheLoadError, CacheStats, NativeCache};
use crate::checked_group::CheckedGroup;
use crate::core::{
    CacheWarmup, CoreError, CorePanic, MAX_KEY_BYTES, MAX_TABLE_BYTES, NativeResidentLease,
    Operation, StorageAdmission,
};
use crate::directory::{
    AppendFloor, DirectoryEdit, DirectoryKey, DirectoryMutator, DirectoryReader, DirectoryRecord,
    DirectoryRoot, DirectoryValue, DirectoryWriteWorkspace, MAX_DIRECTORY_BATCH_EDITS,
};
use crate::group::{GroupFile, SegmentGroupBackend};
use crate::native_backend::BackendRef;
use crate::native_owned_arc::NativeOwnedArc;
use crate::page_cache::{
    CachedDirectoryBackend, NativeIdentity, NativeSharedCache, SupersededIdentities,
};
use crate::root::{
    CompactionCursor, DirectoryCommit, MAX_GARBAGE, RootSelection, Superblock, Unlinked,
    publish_forget, publish_root, repair_mirror, select_root,
};
use crate::segment::{
    self, LogBounds, MAX_BATCH_OPERATIONS, ReplayStart, SealedSegment, SegmentRoll, SegmentWriter,
    ValueLocation, crc32c, replay_roots, validate_directory_anchor,
};
use crate::snapshot_pins::{SnapshotPin, SnapshotPins};

#[path = "disk_public.rs"]
mod public;

#[path = "disk_publish.rs"]
mod publication;

#[path = "disk_maintenance.rs"]
mod maintenance;
use maintenance::Maintenance;
pub use maintenance::{
    MaintenanceBudget, MaintenanceDeferral, MaintenancePolicy, MaintenanceProgress,
    MaintenanceStep, StorageCompactionPhase, StorageMaintenanceStatus,
};
pub(crate) use maintenance::{PublishedMaintenance, published_maintenance_heap_bytes};

#[path = "disk_reclaim.rs"]
mod reclamation;
use reclamation::Reclamation;

#[path = "disk_compact.rs"]
mod compaction;
use compaction::Compaction;

#[path = "disk_warm.rs"]
mod warming;
use warming::Warmup;

#[path = "disk_auto_warm.rs"]
mod auto_warming;
use auto_warming::AutoWarm;

const MAX_PINNED_ROOTS: usize = 256;

const ALLOCATION_ALLOWANCE: usize = 64;
const LEASE_ALLOWANCE: usize = 128;
// Segment staging persists between calls; its largest inline operation and
// replay search window are admitted before entering the unadmitted codec.
const SEGMENT_FIXED_WORKSPACE: usize =
    (64 << 10) + MAX_TABLE_BYTES + MAX_KEY_BYTES + 128 + 3 * crate::root::ROOT_SLOT_BYTES;

struct RootOwner {
    backend: BackendRef,
    admission: Arc<dyn StorageAdmission>,
    root: Mutex<Superblock>,
    group_id: [u8; 16],
    failed: AtomicBool,
    _lease: Option<NativeResidentLease>,
}

impl RootOwner {
    fn check(&self) -> Result<(), CoreError> {
        self.check_live()?;
        if self.admission.check_owner().is_err() {
            self.failed.store(true, Ordering::Release);
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        Ok(())
    }

    /// The in-memory failure latch only. Steps inside one `DiskState::run`
    /// use this: `run` verifies the owner before the operation and again
    /// before any result leaves it, and every physical segment read verifies
    /// its own descriptor. Re-verifying the root between steps of one read
    /// cost a scan up to ten owner checks per record.
    fn check_live(&self) -> Result<(), CoreError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Superblock>, CoreError> {
        self.check()?;
        self.root.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            CoreError::new(crate::CoreErrorCause::OwnerFailed)
        })
    }

    fn publish(&self, current: &mut Superblock, next: Superblock) -> Result<(), CoreError> {
        self.check()?;
        let result = publish_root(self.backend.as_ref(), current, &next);
        if let Err(error) = result {
            self.failed.store(true, Ordering::Release);
            return Err(error);
        }
        self.check()?;
        *current = next;
        Ok(())
    }

    fn bounds(&self) -> Result<LogBounds, CoreError> {
        Ok(self.lock()?.log_bounds())
    }

    /// Install `commit` as the successor of `source`, carrying in-phase
    /// compaction progress. The selected directory must be exactly `source`.
    /// Returns the replaced commit for the reclamation chain.
    fn install(
        &self,
        source: DirectoryRoot,
        commit: DirectoryCommit,
        cursor: Option<(u8, CompactionCursor, u64)>,
    ) -> Result<Option<DirectoryCommit>, CoreError> {
        let mut root = self.lock()?;
        let previous = root.directory();
        if previous.map_or(empty_root(self.group_id), |commit| commit.root) != source {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "directory install does not follow the selected root",
            )));
        }
        let mut next = root.install_directory(commit)?;
        if let Some((level, cursor, remaining)) = cursor {
            next = next.with_compaction_cursor(level, cursor, remaining)?;
        }
        self.publish(&mut root, next)?;
        Ok(previous)
    }

    /// Phase one of a foreground installation: the successor of the selected
    /// root that installs `commit`, which must follow `source`. Nothing is
    /// written; the selected superblock stays in place.
    fn stage_install(
        &self,
        source: DirectoryRoot,
        commit: DirectoryCommit,
    ) -> Result<StagedRoot, CoreError> {
        let root = self.lock()?;
        let replaced = root.directory();
        if replaced.map_or(empty_root(self.group_id), |commit| commit.root) != source {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "directory install does not follow the selected root",
            )));
        }
        let next = root.install_directory(commit)?;
        Ok(StagedRoot {
            previous: root.clone(),
            next,
            replaced,
        })
    }

    /// Phase two: write both root slots and make them durable. Root slots are
    /// read only by publishers, all of which the Core serializes behind the
    /// running commit, and by reopen; this needs neither the state lock nor
    /// the superblock lock, so readers proceed on the selected root. Any
    /// failure fences: the outcome is unknown.
    fn publish_staged(&self, staged: &StagedRoot) -> Result<(), CoreError> {
        let result = self
            .check()
            .and_then(|()| publish_root(self.backend.as_ref(), &staged.previous, &staged.next))
            .and_then(|()| self.check());
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }

    /// Phase three, once `publish_staged` succeeded: adopt the durable
    /// successor. Returns the replaced commit for the reclamation chain.
    fn adopt(&self, staged: StagedRoot) -> Result<Option<DirectoryCommit>, CoreError> {
        let mut root = self.lock()?;
        if *root != staged.previous {
            self.failed.store(true, Ordering::Release);
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                "published root does not follow the selected root",
            )));
        }
        *root = staged.next;
        Ok(staged.replaced)
    }

    /// Drop one recorded garbage file whose unlink `unlinked` proves. Any
    /// failure leaves the owner unable to tell the record's state: fence.
    fn forget(&self, current: &mut Superblock, unlinked: Unlinked) -> Result<(), CoreError> {
        self.check()?;
        match publish_forget(self.backend.as_ref(), current, unlinked) {
            Ok(next) => {
                self.check()?;
                *current = next;
                Ok(())
            }
            Err(error) => {
                self.failed.store(true, Ordering::Release);
                Err(error)
            }
        }
    }
}

/// Minted from the selected root before a transaction builds its successor.
/// Not `Clone`: one witness authorizes exactly one installation.
pub(super) struct SelectionWitness {
    source: DirectoryRoot,
}

/// A foreground commit's successor root between its staging under the state
/// lock and its adoption, back under that lock, once published.
pub(crate) struct StagedRoot {
    previous: Superblock,
    next: Superblock,
    replaced: Option<DirectoryCommit>,
}

/// A foreground commit whose log batch and directory pages are durable and
/// whose successor root is staged but not yet published. The Core publishes
/// it with `publish_root` after releasing its state lock, so readers keep
/// using the selected root meanwhile, then completes it with
/// `DiskState::complete_commit`. Dropping it unpublished leaves the outcome
/// unknown: the caller has fenced, or must.
pub(crate) struct PreparedCommit {
    owner: NativeOwnedArc<RootOwner>,
    witness: SelectionWitness,
    commit: DirectoryCommit,
    root: StagedRoot,
    group_id: [u8; 16],
    batch_seq: u64,
    fresh: AppendFloor,
    shrank: bool,
    publication: Option<publication::PublicationCache>,
    // Dropped before the charge that admitted it.
    values: Vec<Option<ValueLocation>>,
    values_charge: NativeResidentLease,
}

impl PreparedCommit {
    /// Write and synchronize both root slots. This takes no `DiskState`
    /// borrow: the Core runs it without the state lock. Every failure,
    /// including an unwind, fences the owner as an unknown commit.
    pub(crate) fn publish_root(&self) -> Result<(), CoreError> {
        let result = catch_unwind(AssertUnwindSafe(|| self.owner.publish_staged(&self.root)))
            .unwrap_or_else(|panic| {
                self.owner.failed.store(true, Ordering::Release);
                Err(CoreError::unknown_commit(CorePanic::new(panic)))
            })
            .map_err(|error| {
                if error.is_unknown_commit() {
                    error
                } else {
                    error.into_unknown_commit()
                }
            });
        if let Err(error) = &result {
            report_commit_failure("root_publication", error);
        }
        result
    }
}

fn lock_record(
    record: &Mutex<SupersededIdentities>,
) -> Result<MutexGuard<'_, SupersededIdentities>, CoreError> {
    record
        .lock()
        .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))
}

/// Fixed stages and error kinds only. Borrow the original; diagnostics
/// cannot change its disposition, ownership or failure behavior.
fn report_commit_failure(stage: &str, error: &CoreError) {
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr().lock(),
        "Kasumi native commit failed: stage={stage} disposition={:?} io={:?}",
        error.disposition(),
        error.io_error().map(std::io::Error::kind),
    );
}

fn reserve_transaction(
    backend: &dyn SegmentGroupBackend,
    plan: &crate::group::TransactionSpacePlan,
) -> Result<(), CoreError> {
    backend
        .reserve_transaction(plan)
        .map_err(|error| match error {
            crate::group::TransactionReserveError::CapacityDenied => {
                CoreError::new(crate::CoreErrorCause::CapacityDenied)
            }
            crate::group::TransactionReserveError::Failed(original) => {
                CoreError::new(crate::CoreErrorCause::Io(original))
            }
        })
}

impl DirectoryArenaRoll for RootOwner {
    fn reserve(&self) -> Result<u64, CoreError> {
        let mut root = self.lock()?;
        let (next, id) = root.reserve_directory()?;
        self.publish(&mut root, next)?;
        Ok(id)
    }

    fn confirm(&self, id: u64) -> Result<(), CoreError> {
        let mut root = self.lock()?;
        let next = root.confirm_directory(id)?;
        self.publish(&mut root, next)
    }
}

struct Roll(NativeOwnedArc<RootOwner>);
impl SegmentRoll for Roll {
    fn reserve(&mut self, sealed: Option<SealedSegment>) -> Result<u64, CoreError> {
        let mut root = self.0.lock()?;
        let (next, id) = root.reserve_segment(sealed)?;
        self.0.publish(&mut root, next)?;
        Ok(id)
    }

    fn confirm(&mut self, id: u64) -> Result<(), CoreError> {
        let mut root = self.0.lock()?;
        let next = root.confirm_segment(id)?;
        self.0.publish(&mut root, next)
    }
}

/// All data-sized state is on disk or in the one byte-bounded cache. The
/// selected root, writer, one warm-up cursor and allocation owner are bounded.
pub(crate) struct DiskState {
    owner: NativeOwnedArc<RootOwner>,
    arena: NativeOwnedArc<DirectoryArenaBackend>,
    pages: CachedDirectoryBackend<NativeOwnedArc<DirectoryArenaBackend>>,
    cache: NativeSharedCache,
    writer: SegmentWriter,
    selected: DirectoryRoot,
    pins: SnapshotPins,
    reclaim: Reclamation,
    compact: Compaction,
    maintenance: Maintenance,
    warmup: Warmup,
    auto_warm: AutoWarm,
    /// The core's copy of the maintenance status, refreshed at the end of
    /// each step, policy change and request. The core's grant funds it.
    published: Option<Arc<maintenance::PublishedMaintenance>>,
    _lease: Option<NativeResidentLease>,
}

#[path = "disk_opening.rs"]
mod opening;
pub(crate) use opening::DiskOpening;

impl DiskState {
    #[cfg(test)]
    pub(crate) fn owner_allocation_addresses_for_test(&self) -> [usize; 5] {
        [
            self.owner.as_ref() as *const RootOwner as usize,
            self.owner
                ._lease
                .as_ref()
                .expect("original root grant")
                .allocation_address_for_test(),
            self.arena.as_ref() as *const DirectoryArenaBackend as usize,
            self.arena._lease_address_for_test(),
            self.arena.roll_address_for_test(),
        ]
    }
    #[cfg(test)]
    #[allow(
        clippy::result_large_err,
        reason = "The fixture retains the actual opening and cleanup inline until observed disposal."
    )]
    pub(crate) fn create(
        backend: Arc<dyn SegmentGroupBackend>,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        config: CacheConfig,
    ) -> Result<Self, opening::DiskOpeningFailure> {
        opening::fixture(backend, admission, group_id, config, true)
    }
    #[cfg(test)]
    #[allow(
        clippy::result_large_err,
        reason = "The fixture retains the actual opening and cleanup inline until observed disposal."
    )]
    pub(crate) fn open(
        backend: Arc<dyn SegmentGroupBackend>,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        config: CacheConfig,
    ) -> Result<Self, opening::DiskOpeningFailure> {
        opening::fixture(backend, admission, group_id, config, false)
    }

    fn run<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        self.owner.check()?;
        let result = catch_unwind(AssertUnwindSafe(|| {
            let value = operation(self)?;
            self.owner.check()?;
            Ok(value)
        }))
        .unwrap_or_else(|panic| {
            Err(CoreError::new(crate::CoreErrorCause::Panicked(
                CorePanic::new(panic),
            )))
        });
        if self.writer.is_fenced() || result.as_ref().is_err_and(CoreError::fences_owner) {
            self.owner.failed.store(true, Ordering::Release);
        }
        if self.owner.failed.load(Ordering::Acquire)
            && result.as_ref().is_err_and(|error| !error.fences_owner())
        {
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        result
    }

    pub(crate) fn source_pins(&self) -> SnapshotPins {
        self.pins.clone_owner()
    }
    pub(crate) fn install_source_pin(
        &self,
        prepared: &mut crate::snapshot_pins::PreparedProtectedPin,
    ) -> Result<SnapshotPin, CoreError> {
        self.pins.install_protected(prepared, self.selected)
    }
    pub(crate) fn snapshot(&self) -> Result<SnapshotPin, CoreError> {
        self.owner.check()?;
        let result = catch_unwind(AssertUnwindSafe(|| self.pins.acquire(self.selected)))
            .unwrap_or_else(|panic| {
                Err(CoreError::new(crate::CoreErrorCause::Panicked(
                    CorePanic::new(panic),
                )))
            });
        if result.as_ref().is_err_and(CoreError::fences_owner) {
            self.owner.failed.store(true, Ordering::Release);
        }
        result
    }

    #[cfg(test)]
    pub(crate) fn is_fenced(&self) -> bool {
        self.owner.failed.load(Ordering::Acquire)
    }

    /// Test fixture: make every existing file older than the active ones
    /// through the production roll paths, so the next cycle covers them.
    #[cfg(test)]
    pub(crate) fn seal_files_for_test(&mut self) -> Result<(), CoreError> {
        self.arena.force_roll()?;
        self.writer
            .force_roll(self.owner.backend.as_ref(), &mut Roll(self.owner.clone()))
    }

    fn selection_witness(&self) -> SelectionWitness {
        SelectionWitness {
            source: self.selected,
        }
    }

    /// With `adopt_selected`, its split form for foreground commits, the only
    /// post-open writer of `self.selected`. In one owner-lock hold
    /// of this state it checks the witness, installs `commit` with the
    /// in-phase compaction checkpoint (preserving it for foreground writes), selects
    /// it, and advances an active reclamation cohort's certified chain and
    /// stamped pin root. While a cohort is active, a new value below its
    /// segment limit or an active arena below its arena limit invalidates the
    /// cohort before installation; the write itself still proceeds.
    fn install_selected(
        &mut self,
        witness: SelectionWitness,
        commit: DirectoryCommit,
        new_values: &[Option<ValueLocation>],
        cursor: Option<(u8, CompactionCursor, u64)>,
    ) -> Result<(), CoreError> {
        if witness.source != self.selected {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "selection witness is stale",
            )));
        }
        self.certify_install(new_values)?;
        let previous = self.owner.install(witness.source, commit, cursor)?;
        self.selected = commit.root;
        self.observe_install(previous, commit)
    }

    /// `install_selected` for a foreground commit whose staged root
    /// `PreparedCommit::publish_root` already made durable. Its in-memory
    /// effects all happen here, under the state lock: a reader that ran
    /// during the publication saw the state as if the commit had not begun.
    fn adopt_selected(
        &mut self,
        witness: SelectionWitness,
        staged: StagedRoot,
        commit: DirectoryCommit,
        new_values: &[Option<ValueLocation>],
    ) -> Result<(), CoreError> {
        if witness.source != self.selected {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "selection witness is stale",
            )));
        }
        self.certify_install(new_values)?;
        let previous = self.owner.adopt(staged)?;
        self.selected = commit.root;
        self.observe_install(previous, commit)
    }

    /// While a cohort is active, invalidate it before an installation whose
    /// new values or pages fall below its limits.
    fn certify_install(&mut self, new_values: &[Option<ValueLocation>]) -> Result<(), CoreError> {
        if let Some(limits) = self.reclaim.active_limits() {
            let fresh_values = new_values
                .iter()
                .flatten()
                .all(|value| value.segment_id >= limits.segment);
            let fresh_pages = self
                .arena
                .active_arena_id()?
                .is_none_or(|id| id >= limits.arena);
            if !fresh_values || !fresh_pages {
                self.invalidate_for_install()?;
            }
        }
        Ok(())
    }

    fn check_snapshot(&self, pin: &SnapshotPin) -> Result<DirectoryRoot, CoreError> {
        self.owner.check()?;
        let root = self.pins.validate(pin)?;
        root.validate()?;
        if root.group_id != self.owner.group_id || root.generation > self.selected.generation {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot does not belong to this disk state",
            )));
        }
        Ok(root)
    }

    pub(crate) fn table_exists(
        &mut self,
        root: &SnapshotPin,
        table: &str,
    ) -> Result<bool, CoreError> {
        self.run(|state| {
            let root = state.check_snapshot(root)?;
            Ok(
                DirectoryReader::new(&state.pages, state.owner.admission.clone())
                    .get(root, DirectoryKey::table(table))?
                    .is_some(),
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn get(
        &mut self,
        root: &SnapshotPin,
        table: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<CachedBytes>, CoreError> {
        self.run(|state| {
            let root = state.check_snapshot(root)?;
            let reader = DirectoryReader::new(&state.pages, state.owner.admission.clone());
            if reader.get(root, DirectoryKey::table(table))?.is_none() {
                return Err(CoreError::new(crate::CoreErrorCause::MissingTable));
            }
            match reader.get(root, DirectoryKey::row(table, key))? {
                None => Ok(None),
                Some(DirectoryValue::Row { value, .. }) => {
                    state.value(value, table, key, max_value_bytes).map(Some)
                }
                Some(DirectoryValue::Table { .. }) => Err(CoreError::new(
                    crate::CoreErrorCause::Corrupt("row lookup returned a table"),
                )),
            }
        })
    }

    pub(crate) fn next(
        &mut self,
        root: &SnapshotPin,
        table: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
    ) -> Result<Option<DirectoryRecord>, CoreError> {
        self.run(|state| state.next_record(root, table, prefix, after))
    }

    /// The successor step of `next`, for callers already inside `run`.
    pub(crate) fn next_record(
        &self,
        root: &SnapshotPin,
        table: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
    ) -> Result<Option<DirectoryRecord>, CoreError> {
        let root = self.check_snapshot(root)?;
        let reader = DirectoryReader::new(&self.pages, self.owner.admission.clone());
        if reader.get(root, DirectoryKey::table(table))?.is_none() {
            return Err(CoreError::new(crate::CoreErrorCause::MissingTable));
        }
        let (lower, exclusive) = after
            .filter(|after| *after >= prefix)
            .map_or((prefix, false), |after| (after, true));
        let record = reader.next(root, DirectoryKey::row(table, lower), exclusive)?;
        Ok(record.filter(|record| {
            record.key().table == table
                && record.key().row.is_some_and(|key| key.starts_with(prefix))
        }))
    }

    #[cfg(test)]
    fn value(
        &self,
        value: ValueLocation,
        table: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<CachedBytes, CoreError> {
        self.owner.check()?;
        value.validate()?;
        if value.len as usize > max_value_bytes {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "value exceeds the caller's read bound",
            )));
        }
        let identity = NativeIdentity::value(self.owner.group_id, value, table, key)?;
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?;
        let result = cache
            .load(identity, value.len as usize, |out| {
                self.owner.check()?;
                self.owner
                    .backend
                    .read(GroupFile::segment(value.segment_id), value.offset, out)?;
                self.owner.check()?;
                if crc32c(out) != value.crc {
                    return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                        "value checksum differs",
                    )));
                }
                Ok(())
            })
            .map_err(|error| match error {
                CacheLoadError::Admission(error) => error.into(),
                CacheLoadError::Load(error) => error,
            })?;
        self.owner.check()?;
        if result.as_bytes().len() != value.len as usize || crc32c(result.as_bytes()) != value.crc {
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                "cached value identity differs",
            )));
        }
        Ok(result)
    }

    /// The whole commit under one exclusive borrow: `prepare_commit`, the
    /// root publication, then `complete_commit`. The Core runs the same
    /// three steps but releases its state lock around the publication.
    #[cfg(test)]
    pub(crate) fn commit(&mut self, operations: &[Operation]) -> Result<(), CoreError> {
        let prepared = self.prepare_commit(operations)?;
        prepared.publish_root()?;
        self.complete_commit(prepared, operations)
    }

    /// Everything durable except the root: the log batch and the directory
    /// pages it binds, with the successor root staged in memory. Failures
    /// keep their dispositions: refusals before the first effect prove no
    /// effect, a capacity refusal during the mutation rolls back, and later
    /// failures are unknown.
    pub(crate) fn prepare_commit(
        &mut self,
        operations: &[Operation],
    ) -> Result<PreparedCommit, CoreError> {
        self.run(|state| {
            catch_unwind(AssertUnwindSafe(|| {
                let mut stage = "admission";
                state
                    .prepare_staged(operations, &mut stage)
                    .inspect_err(|error| report_commit_failure(stage, error))
            }))
            .unwrap_or_else(|panic| Err(CoreError::unknown_commit(CorePanic::new(panic))))
        })
    }

    /// Adopt and select the root `PreparedCommit::publish_root` made durable,
    /// settle the transaction and publish the caches. The root is durable, so
    /// every failure here is an unknown commit and fences.
    pub(crate) fn complete_commit(
        &mut self,
        prepared: PreparedCommit,
        operations: &[Operation],
    ) -> Result<(), CoreError> {
        self.run(|state| {
            catch_unwind(AssertUnwindSafe(|| {
                let mut stage = "cache_publication_begin";
                state
                    .complete_staged(prepared, operations, &mut stage)
                    .map_err(|error| {
                        if error.is_unknown_commit() {
                            error
                        } else {
                            error.into_unknown_commit()
                        }
                    })
                    .inspect_err(|error| report_commit_failure(stage, error))
            }))
            .unwrap_or_else(|panic| Err(CoreError::unknown_commit(CorePanic::new(panic))))
        })
        .map_err(|error| {
            if error.is_unknown_commit() {
                error
            } else {
                // The owner check around `run` itself refused.
                self.owner.failed.store(true, Ordering::Release);
                error.into_unknown_commit()
            }
        })
    }

    fn prepare_staged(
        &mut self,
        operations: &[Operation],
        stage: &mut &'static str,
    ) -> Result<PreparedCommit, CoreError> {
        // Preflight table existence against the selected tree and earlier
        // creates in this batch. No growing all-table overlay is retained.
        if operations.is_empty() || operations.len() > MAX_BATCH_OPERATIONS {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "empty or oversized transaction",
            )));
        }
        // Abort must never request its first reservation after private effects.
        // Hold its bounded replay workspace until prepare is committed or undone.
        let workspace_bytes = segment::prepared_batch_workspace_bytes(operations)?;
        let values_bytes = (operations.len() * std::mem::size_of::<Option<ValueLocation>>()) as u64;
        let values_charge = self
            .owner
            .admission
            .reserve_workspace(
                values_bytes
                    + std::mem::size_of::<crate::group::TransactionSpacePlan>() as u64
                    + (LEASE_ALLOWANCE + ALLOCATION_ALLOWANCE) as u64,
            )
            .map(NativeResidentLease::new)?;
        // One fixed borrowed edit run is reused below. Charge it and the
        // temporary descriptors before preparing any private log effects.
        let directory_batch_bytes = std::mem::size_of::<
            [DirectoryEdit<'_>; MAX_DIRECTORY_BATCH_EDITS],
        >() + 4 * std::mem::size_of::<DirectoryEdit<'_>>();
        let _workspace = self
            .owner
            .admission
            .reserve_workspace(
                (workspace_bytes - values_bytes)
                    .checked_add(LEASE_ALLOWANCE as u64)
                    .and_then(|bytes| bytes.checked_add(directory_batch_bytes as u64))
                    .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?,
            )
            .map(NativeResidentLease::new)?;
        let mut directory_workspace =
            DirectoryWriteWorkspace::for_edits(self.owner.admission.clone())?;
        let witness = self.selection_witness();
        // All proof buffers, the snapshot capture and the superseded-identity
        // record are admitted before any private disk effect. Nothing marks
        // the cache until the root is durable.
        *stage = "cache_publication_prepare";
        let mut publication = self.prepare_cache_publication(operations.len())?;
        *stage = "directory_preflight";
        let preflight = self.pages.maintenance_private_view();
        // Keep only a borrowed witness for a consecutive table run. Bulk
        // writes should not rescan every earlier operation for each row.
        let mut verified_table = None;
        for (index, operation) in operations.iter().enumerate() {
            let table = match operation {
                Operation::CreateTable { table }
                | Operation::Put { table, .. }
                | Operation::Delete { table, .. } => table.as_ref(),
            };
            if matches!(operation, Operation::CreateTable { .. }) {
                verified_table = Some(table);
                continue;
            }
            if verified_table == Some(table) {
                continue;
            }
            if directory_workspace.get(&preflight, self.selected, DirectoryKey::table(table))?.is_none()
                && !operations[..index].iter().any(|operation| matches!(operation, Operation::CreateTable { table: previous } if previous.as_ref() == table))
            {
                return Err(CoreError::new(crate::CoreErrorCause::MissingTable));
            }
            verified_table = Some(table);
        }
        // Plan against the serialized selected writer before the first private
        // log/root effect. The installed backend atomically owns every physical
        // extent, name and descriptor promise until explicit settlement.
        *stage = "transaction_plan";
        let (plan, first_directory) = {
            let root = self.owner.lock()?;
            if root.pending_segment().is_some() || root.pending_directory().is_some() {
                return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                    "transaction allocation intent outstanding",
                )));
            }
            let first_segment = root.last_segment_id().checked_add(1).ok_or(CoreError::new(
                crate::CoreErrorCause::InvalidInput("segment identifier overflow"),
            ))?;
            let first_directory = root
                .last_directory_id()
                .checked_add(1)
                .ok_or(CoreError::new(crate::CoreErrorCause::InvalidInput(
                    "directory identifier overflow",
                )))?;
            let (segment, new_segments) =
                self.writer.transaction_space(first_segment, operations)?;
            let (directory, new_directories) = self.arena.transaction_space(
                first_directory,
                self.selected.transaction_page_bound(operations.len())?,
            )?;
            let plan = crate::group::TransactionSpacePlan {
                group_id: self.owner.group_id,
                root_generation: root.generation(),
                batch_seq: self.writer.next_batch_sequence(),
                maintenance: false,
                segment,
                directory,
                new_segments,
                new_directories,
            };
            (plan, first_directory)
        };
        *stage = "transaction_reserve";
        reserve_transaction(self.owner.backend.as_ref(), &plan)?;
        *stage = "log_prepare";
        let mut roll = Roll(self.owner.clone());
        let prepared =
            match self
                .writer
                .prepare_batch(self.owner.backend.as_ref(), operations, &mut roll)
            {
                Ok(prepared) => prepared,
                Err(original) if !self.writer.is_fenced() => {
                    // prepare_batch mints this state only before entering operation
                    // writing. A backend must still prove its exact claim pristine.
                    self.owner
                        .backend
                        .cancel_transaction(plan.group_id, plan.batch_seq)?;
                    return Err(original);
                }
                Err(original) => return Err(original),
            };
        self.owner.check()?;
        // Every page this publication appends lies at or above this floor.
        let fresh = self.arena.append_floor();
        *stage = "directory_mutation";
        let generation = prepared.batch_seq();
        let mut shrank = false;
        let (record, mut proof) = match publication.as_mut() {
            Some(publication) => (Some(&publication.superseded), Some(&mut publication.proof)),
            None => (None, None),
        };
        let result = (|| {
            if let Some(record) = record {
                // Without an active arena the first append rolls a fresh
                // one, so every older page is committed.
                lock_record(record)?.set_floor(if fresh == AppendFloor::NONE {
                    AppendFloor::at(first_directory, 0)
                } else {
                    fresh
                });
            }
            // Each call that consumes edits is one recorded step; a table
            // lookup or a refused batch attempt before it shares its route.
            let begin_step = || -> Result<(), CoreError> {
                if let Some(record) = record {
                    lock_record(record)?.begin_step();
                }
                Ok(())
            };
            let end_step = |changed: bool| -> Result<(), CoreError> {
                if let Some(record) = record {
                    lock_record(record)?.end_step(changed);
                }
                Ok(())
            };
            let untracked = self.pages.private_view();
            let recording = record.map(|record| self.pages.recording_private_view(record));
            let private: &dyn crate::directory::DirectoryBackend = match &recording {
                Some(recording) => recording,
                None => &untracked,
            };
            let mut mutator = DirectoryMutator::new(private, &mut directory_workspace)?;
            let mut root = self.selected;
            let mut index = 0;
            while index < operations.len() {
                let first = prepared_directory_edit(
                    &operations[index],
                    prepared.values()[index],
                    generation,
                )?;
                begin_step()?;
                let mut before = root.page;
                if first.key.row.is_none() && mutator.get(root, first.key)?.is_some() {
                    end_step(false)?;
                    index += 1;
                    continue;
                }
                let mut edits = [first; MAX_DIRECTORY_BATCH_EDITS];
                let mut count = 1;
                // Table creation and repeated/descending keys retain their
                // exact original order. Only distinct row edits against one
                // unchanged input root can share prior-value lookups.
                if first.key.row.is_some() {
                    while count < MAX_DIRECTORY_BATCH_EDITS && index + count < operations.len() {
                        let next = prepared_directory_edit(
                            &operations[index + count],
                            prepared.values()[index + count],
                            generation,
                        )?;
                        if next.key.row.is_none() || next.key <= edits[count - 1].key {
                            break;
                        }
                        edits[count] = next;
                        count += 1;
                    }
                }
                for (offset, edit) in edits[..count].iter().enumerate() {
                    // The copied pages of these paths are recorded by the
                    // steps below; this lookup only finds the prior value.
                    if let (Some(record), Some(proof), Some(row)) =
                        (record, proof.as_deref_mut(), edit.key.row)
                        && let Some(DirectoryValue::Row { value: old, .. }) =
                            DirectoryReader::new(&untracked, self.owner.admission.clone())
                                .get_with_workspace(root, edit.key, &mut proof.directory)?
                    {
                        shrank |= match &operations[index + offset] {
                            Operation::Delete { .. } => true,
                            Operation::Put { value, .. } => value.len() < old.len as usize,
                            Operation::CreateTable { .. } => false,
                        };
                        // The run's keys are distinct, so earlier edits in it
                        // cannot replace this key's prior logical value.
                        let identity =
                            NativeIdentity::value(self.owner.group_id, old, edit.key.table, row)?;
                        lock_record(record)?.record_value(identity);
                    }
                }
                let mut applied = 0;
                while applied < count {
                    begin_step()?;
                    let remaining = &edits[applied..count];
                    let batched = if remaining.len() > 1 {
                        mutator.try_set_leaf_batch(root, generation, remaining)?
                    } else {
                        None
                    };
                    if let Some((next, consumed)) = batched {
                        root = next;
                        applied += consumed;
                    } else {
                        // Unsupported shapes append nothing in the batch
                        // helper. Apply the first edit with the ordinary
                        // split/collapse path, then reconsider the remaining
                        // ordered prefix against its new immutable root.
                        let edit = remaining[0];
                        root = mutator.set(root, generation, edit.key, edit.value)?;
                        applied += 1;
                    }
                    end_step(root.page != before)?;
                    before = root.page;
                }
                index += count;
            }
            // A batch of duplicate table creates still advances its commit.
            root.generation = generation;
            mutator.finish(root)
        })();
        drop(directory_workspace);
        let root = match result {
            Ok(root) => root,
            Err(error) if error.is_capacity_denied() => {
                // Private immutable arena pages may remain durable/accounted.
                // Physical settlement releases unused promises, not published
                // data. Only exact prepared-log replay can then prove rollback.
                self.owner
                    .backend
                    .finish_transaction(plan.group_id, plan.batch_seq)?;
                let bounds = self.owner.bounds()?;
                self.writer
                    .abort_prepared(self.owner.backend.as_ref(), prepared, &bounds)?;
                return Err(error);
            }
            Err(error) => {
                // The outstanding token cannot be used after a failed private
                // construction. Only the explicit capacity rollback is retryable.
                self.owner.failed.store(true, Ordering::Release);
                return Err(error);
            }
        };
        *stage = "log_finish";
        let committed =
            self.writer
                .finish_batch(self.owner.backend.as_ref(), prepared, root, &mut roll)?;
        // Abort/replay scratch is no longer live. Return that headroom before
        // retaining fitting data; only the prepared locations remain charged.
        drop(_workspace);
        let commit = DirectoryCommit {
            root: committed.directory_root,
            start: ReplayStart {
                position: committed.end,
                batch_seq: committed.batch_seq,
                chain: committed.chain,
            },
        };
        // The log commit is ordered before the root publication, whose full
        // synchronization makes both durable. Any subsequent failure is
        // indeterminate to this caller and fences; reopen decides from the
        // log and root the device kept.
        *stage = "root_stage";
        let root =
            self.owner
                .stage_install(witness.source, commit)
                .map_err(|error| match error {
                    _ if error.is_unknown_commit() => error,
                    _ => error.into_unknown_commit(),
                })?;
        Ok(PreparedCommit {
            owner: self.owner.clone(),
            witness,
            commit,
            root,
            group_id: plan.group_id,
            batch_seq: plan.batch_seq,
            fresh,
            shrank,
            publication,
            values: committed.values,
            values_charge,
        })
    }

    fn complete_staged(
        &mut self,
        prepared: PreparedCommit,
        operations: &[Operation],
        stage: &mut &'static str,
    ) -> Result<(), CoreError> {
        let PreparedCommit {
            values_charge,
            values,
            owner: _,
            witness,
            commit,
            root,
            group_id,
            batch_seq,
            fresh,
            shrank,
            mut publication,
        } = prepared;
        // Readers may have pinned the selected root during the publication.
        // Include them before that root becomes historical, then mark the
        // record: no reader can load or pin until this state lock is released.
        *stage = "cache_publication_begin";
        self.observe_warm_publication_start()?;
        if let Some(publication) = publication.as_mut() {
            self.begin_cache_publication(publication)?;
        }
        *stage = "root_adoption";
        self.adopt_selected(witness, root, commit, &values)?;
        *stage = "transaction_settle";
        self.owner
            .backend
            .finish_transaction(group_id, batch_seq)
            .map_err(CoreError::unknown_io)?;
        self.warmup = Warmup::default();
        // Publication is durable before pruning or filling. Remove obsolete
        // identities first so old-plus-new overlap cannot displace fitting
        // current/pinned data. Disabled retention needs neither proof nor fill.
        *stage = "cache_publication";
        if let Some(mut publication) = publication {
            self.reconcile_publication(&mut publication)
                .and_then(|()| {
                    self.retain_committed(
                        operations,
                        &values,
                        fresh,
                        &mut publication.proof.directory,
                    )
                })?;
        }
        self.observe_warm_publication(shrank)?;
        drop(values);
        drop(values_charge);
        Ok(())
    }

    fn retain_committed(
        &self,
        operations: &[Operation],
        values: &[Option<ValueLocation>],
        fresh: AppendFloor,
        workspace: &mut crate::directory::DirectoryReadWorkspace,
    ) -> Result<(), CoreError> {
        {
            let warming = self.pages.commit_warm_view();
            let warmer = DirectoryReader::new(&warming, self.owner.admission.clone());
            match warmer.warm_generation_with_workspace(
                self.selected,
                self.selected.generation,
                fresh,
                workspace,
            ) {
                Ok(()) => {}
                Err(error) if error.is_capacity_denied() => {}
                Err(error) => return Err(error),
            }
        }
        // Each supplied value still needs a bounded final-root visibility
        // check: a later put/delete in this batch can supersede its location.
        // These logical reads may use admitted scratch after cache refusal;
        // unlike the optional tree walk, they do not visit unrelated subtrees.
        let published = self.pages.maintenance_view();
        let reader = DirectoryReader::new(&published, self.owner.admission.clone());
        for (operation, location) in operations.iter().zip(values) {
            let Operation::Put {
                table,
                key,
                value: bytes,
            } = operation
            else {
                continue;
            };
            let location = location.ok_or(CoreError::new(crate::CoreErrorCause::Corrupt(
                "committed put has no location",
            )))?;
            let visible =
                reader.get_with_workspace(self.selected, DirectoryKey::row(table, key), workspace);
            let visible = match visible {
                Ok(visible) => visible,
                Err(error) if error.is_capacity_denied() => continue,
                Err(error) => return Err(error),
            };
            if !matches!(visible, Some(DirectoryValue::Row { value, .. }) if value == location) {
                continue;
            }
            self.owner.check()?;
            let identity = NativeIdentity::value(self.owner.group_id, location, table, key)?;
            let loaded = self
                .cache
                .lock()
                .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
                .load_if_fits(identity, bytes.len(), |out| {
                    out.copy_from_slice(bytes);
                    Ok::<_, CoreError>(())
                });
            match loaded {
                Ok(_) | Err(CacheLoadError::Admission(crate::AdmissionError::CapacityDenied)) => {}
                Err(CacheLoadError::Admission(error)) => return Err(error.into()),
                Err(CacheLoadError::Load(error)) => return Err(error),
            }
            self.owner.check()?;
        }
        Ok(())
    }

    pub(crate) fn cache_stats(&self) -> Result<CacheStats, CoreError> {
        self.owner.check()?;
        Ok(self
            .cache
            .lock()
            .map_err(|_| {
                self.owner.failed.store(true, Ordering::Release);
                CoreError::new(crate::CoreErrorCause::OwnerFailed)
            })?
            .stats())
    }

    pub(crate) fn configure_cache(&mut self, config: CacheConfig) -> Result<(), CoreError> {
        self.run(|state| {
            // A denied shrink may already have released lookup ownership
            // while an output guard prevents adopting the smaller limit.
            let result = state.pages.configure(config);
            state.reset_auto_warm();
            result
        })
    }
}

fn prepared_directory_edit(
    operation: &Operation,
    location: Option<ValueLocation>,
    generation: u64,
) -> Result<DirectoryEdit<'_>, CoreError> {
    let (key, value) = match operation {
        Operation::CreateTable { table } => (
            DirectoryKey::table(table),
            Some(DirectoryValue::Table {
                birth_seq: generation,
            }),
        ),
        Operation::Put { table, key, .. } => (
            DirectoryKey::row(table, key),
            Some(DirectoryValue::Row {
                batch_seq: generation,
                value: location.ok_or(CoreError::new(crate::CoreErrorCause::Corrupt(
                    "prepared put has no location",
                )))?,
            }),
        ),
        Operation::Delete { table, key } => (DirectoryKey::row(table, key), None),
    };
    Ok(DirectoryEdit { key, value })
}

fn empty_root(group_id: [u8; 16]) -> DirectoryRoot {
    DirectoryRoot {
        group_id,
        generation: 0,
        page: None,
        height: 0,
        entries: 0,
    }
}

fn fixed_admission(
    admission: &Arc<dyn StorageAdmission>,
) -> Result<NativeResidentLease, CoreError> {
    admission
        .check_owner()
        .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?;
    let bytes = std::mem::size_of::<DiskOpening>()
        + AutoWarm::backing_bytes()
        + std::mem::size_of::<CheckedGroup>()
        + 2 * std::mem::size_of::<usize>()
        + std::mem::size_of::<Mutex<NativeCache<NativeIdentity>>>()
        + 2 * std::mem::size_of::<usize>()
        + crate::native_sync::mutex_backing_bytes()
        // Foreground publication owns only one fixed proof scope/candidate.
        // Its dynamic buffers/roots have separate pre-effect admissions.
        + std::mem::size_of::<publication::PublicationCache>()
        + std::mem::size_of::<crate::cache::CacheCandidate<NativeIdentity>>()
        + SEGMENT_FIXED_WORKSPACE
        // A staged root carries the superblock it follows across the
        // unlocked publication, besides its successor.
        + 3 * std::mem::size_of::<Superblock>()
        + 4 * MAX_GARBAGE * std::mem::size_of::<GroupFile>()
        + 5 * ALLOCATION_ALLOWANCE
        + LEASE_ALLOWANCE;
    admission
        .reserve_workspace(bytes as u64)
        .map(NativeResidentLease::new)
        .map_err(Into::into)
}

#[cfg(test)]
#[path = "disk_state_tests.rs"]
mod tests;
