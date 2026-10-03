//! The disk-directory state machine that replaces Core's resident key map.
//!
//! This is the composition boundary: operation locations are prepared first,
//! COW pages are synchronized, the log commit binds the exact directory, and
//! only then does the mirrored root select it. Reopen adopts validated roots
//! from replay without retaining a key map. Core retains the exact backend
//! owner through opening failure and final native close.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::arena::{DirectoryArenaBackend, DirectoryArenaRoll, recover_directory_intent};
use crate::cache::{CacheConfig, CacheLoadError, CacheStats, CachedBytes, NativeCache};
use crate::checked_group::CheckedGroup;
use crate::core::{
    CacheWarmup, CoreError, CorePanic, MAX_KEY_BYTES, MAX_TABLE_BYTES, Operation, ResidentLease,
    StorageAdmission,
};
use crate::directory::{
    DirectoryEdit, DirectoryKey, DirectoryMutator, DirectoryReader, DirectoryRecord, DirectoryRoot,
    DirectoryValue, DirectoryWriteWorkspace, MAX_DIRECTORY_BATCH_EDITS,
};
use crate::group::{GroupFile, SegmentGroupBackend};
use crate::page_cache::{CachedDirectoryBackend, NativeIdentity, NativeSharedCache};
use crate::root::{
    DirectoryCommit, MAX_GARBAGE, RootSelection, Superblock, publish_root, repair_mirror,
    select_root,
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
    backend: Arc<dyn SegmentGroupBackend>,
    admission: Arc<dyn StorageAdmission>,
    root: Mutex<Superblock>,
    group_id: [u8; 16],
    failed: AtomicBool,
    _lease: Box<dyn ResidentLease>,
}

impl RootOwner {
    fn check(&self) -> Result<(), CoreError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(CoreError::OwnerFailed);
        }
        if self.admission.check_owner().is_err() {
            self.failed.store(true, Ordering::Release);
            return Err(CoreError::OwnerFailed);
        }
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Superblock>, CoreError> {
        self.check()?;
        self.root.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            CoreError::OwnerFailed
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

    fn install(&self, commit: DirectoryCommit) -> Result<(), CoreError> {
        let mut root = self.lock()?;
        let next = root.install_directory(commit)?;
        self.publish(&mut root, next)
    }
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

struct Roll(Arc<RootOwner>);
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
    owner: Arc<RootOwner>,
    arena: Arc<DirectoryArenaBackend>,
    pages: CachedDirectoryBackend<Arc<DirectoryArenaBackend>>,
    cache: NativeSharedCache,
    writer: SegmentWriter,
    selected: DirectoryRoot,
    pins: SnapshotPins,
    reclaim: Reclamation,
    compact: Compaction,
    warmup: Warmup,
    auto_warm: AutoWarm,
    _lease: Box<dyn ResidentLease>,
}

impl DiskState {
    pub(crate) fn create(
        backend: Arc<dyn SegmentGroupBackend>,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        config: CacheConfig,
    ) -> Result<Self, CoreError> {
        let lease = fixed_admission(&admission)?;
        let backend: Arc<dyn SegmentGroupBackend> =
            Arc::new(CheckedGroup::new(backend, admission.clone()));
        if !matches!(select_root(backend.as_ref())?, RootSelection::Empty) {
            return Err(CoreError::InvalidInput("group already contains a root"));
        }
        let genesis = Superblock::genesis(group_id);
        genesis.visit_census(backend.as_ref(), |_| Ok(()))?;
        let root = genesis.initialized()?;
        let state = Self::assemble(
            backend.clone(),
            admission,
            root.clone(),
            SegmentWriter::new(group_id),
            empty_root(group_id),
            config,
            lease,
        )?;
        publish_root(backend.as_ref(), &genesis, &root)?;
        state.owner.check()?;
        Ok(state)
    }

    pub(crate) fn open(
        backend: Arc<dyn SegmentGroupBackend>,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        config: CacheConfig,
    ) -> Result<Self, CoreError> {
        let lease = fixed_admission(&admission)?;
        let backend: Arc<dyn SegmentGroupBackend> =
            Arc::new(CheckedGroup::new(backend, admission.clone()));
        let RootSelection::Selected {
            mut superblock,
            slot,
            mirrored,
        } = select_root(backend.as_ref())?
        else {
            return Err(CoreError::Corrupt("group has no initialized root"));
        };
        if superblock.group_id() != &group_id {
            return Err(CoreError::Corrupt("group incarnation differs from owner"));
        }
        if superblock.checkpoint().is_some() {
            return Err(CoreError::Corrupt("checkpoint-only root is retired"));
        }
        let mut selected = superblock
            .directory()
            .map_or(empty_root(group_id), |commit| commit.root);
        let mut state = Self::assemble(
            backend.clone(),
            admission.clone(),
            superblock.clone(),
            SegmentWriter::new(group_id),
            selected,
            config,
            lease,
        )?;
        superblock.visit_census(backend.as_ref(), |_| Ok(()))?;
        if !mirrored {
            repair_mirror(backend.as_ref(), &superblock, slot)?;
        }
        if let Some(id) = superblock.pending_directory() {
            recover_directory_intent(backend.as_ref(), &admission, group_id, id)?;
            let next = superblock.confirm_directory(id)?;
            publish_root(backend.as_ref(), &superblock, &next)?;
            superblock = next;
        }
        let start = superblock
            .directory()
            .map_or(ReplayStart::GENESIS, |commit| commit.start);
        validate_directory_anchor(backend.as_ref(), group_id, selected, &start)?;
        let _replay_lease = admission
            .reserve_workspace(segment::root_replay_workspace_bytes() + LEASE_ALLOWANCE as u64)?;
        let end = replay_roots(
            backend.as_ref(),
            group_id,
            &start,
            &superblock.log_bounds(),
            |batch| {
                selected = batch.directory_root;
                Ok(())
            },
        )?;
        end.discard_tail(backend.as_ref())?;
        if selected.generation != start.batch_seq {
            let position = end
                .directory_end
                .ok_or(CoreError::Corrupt("replayed directory has no log position"))?;
            let commit = DirectoryCommit {
                root: selected,
                start: ReplayStart {
                    position,
                    batch_seq: end.batch_seq,
                    chain: end.chain,
                },
            };
            validate_directory_anchor(backend.as_ref(), group_id, selected, &commit.start)?;
            let next = superblock.install_directory(commit)?;
            publish_root(backend.as_ref(), &superblock, &next)?;
            superblock = next;
        }
        state.writer = SegmentWriter::resume(group_id, &end);
        drop(_replay_lease);
        state.selected = selected;
        *state.owner.lock()? = superblock;
        state.finish_recorded_garbage()?;
        // Verify the selected root page before reporting an opened database.
        // Subsequent descent validates every child digest and value location.
        let _ = DirectoryReader::new(state.arena.as_ref(), state.owner.admission.clone()).next(
            selected,
            DirectoryKey::table("\0"),
            false,
        )?;
        state.owner.check()?;
        Ok(state)
    }

    fn assemble(
        backend: Arc<dyn SegmentGroupBackend>,
        admission: Arc<dyn StorageAdmission>,
        root: Superblock,
        writer: SegmentWriter,
        selected: DirectoryRoot,
        config: CacheConfig,
        lease: Box<dyn ResidentLease>,
    ) -> Result<Self, CoreError> {
        let owner_lease = admission.reserve_workspace(
            (std::mem::size_of::<RootOwner>()
                + 2 * MAX_GARBAGE * std::mem::size_of::<GroupFile>()
                + LEASE_ALLOWANCE
                + 2 * ALLOCATION_ALLOWANCE) as u64,
        )?;
        let group_id = *root.group_id();
        let owner = Arc::new(RootOwner {
            backend: backend.clone(),
            admission: admission.clone(),
            root: Mutex::new(root),
            group_id,
            failed: AtomicBool::new(false),
            _lease: owner_lease,
        });
        let arena = Arc::new(DirectoryArenaBackend::new(
            backend,
            owner.clone(),
            admission.clone(),
            group_id,
        )?);
        let cache = Arc::new(Mutex::new(NativeCache::new(config, admission.clone())));
        let pins = SnapshotPins::new(admission.clone(), group_id, MAX_PINNED_ROOTS)?;
        let pages = CachedDirectoryBackend::with_shared_cache(
            arena.clone(),
            admission,
            group_id,
            cache.clone(),
        );
        owner.check()?;
        Ok(Self {
            owner,
            arena,
            pages,
            cache,
            writer,
            selected,
            pins,
            reclaim: Reclamation::default(),
            compact: Compaction::default(),
            warmup: Warmup::default(),
            auto_warm: AutoWarm::default(),
            _lease: lease,
        })
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
        .unwrap_or_else(|panic| Err(CoreError::Panicked(Box::new(CorePanic::new(panic)))));
        if self.writer.is_fenced() || result.as_ref().is_err_and(CoreError::fences_owner) {
            self.owner.failed.store(true, Ordering::Release);
        }
        if self.owner.failed.load(Ordering::Acquire)
            && result.as_ref().is_err_and(|error| !error.fences_owner())
        {
            return Err(CoreError::OwnerFailed);
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
            .unwrap_or_else(|panic| Err(CoreError::Panicked(Box::new(CorePanic::new(panic)))));
        if result.as_ref().is_err_and(CoreError::fences_owner) {
            self.owner.failed.store(true, Ordering::Release);
        }
        result
    }

    pub(crate) fn is_fenced(&self) -> bool {
        self.owner.failed.load(Ordering::Acquire)
    }

    fn check_snapshot(&self, pin: &SnapshotPin) -> Result<DirectoryRoot, CoreError> {
        self.owner.check()?;
        let root = self.pins.validate(pin)?;
        root.validate()?;
        if root.group_id != self.owner.group_id || root.generation > self.selected.generation {
            return Err(CoreError::InvalidInput(
                "snapshot does not belong to this disk state",
            ));
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
                return Err(CoreError::MissingTable);
            }
            match reader.get(root, DirectoryKey::row(table, key))? {
                None => Ok(None),
                Some(DirectoryValue::Row { value, .. }) => {
                    state.value(value, table, key, max_value_bytes).map(Some)
                }
                Some(DirectoryValue::Table { .. }) => {
                    Err(CoreError::Corrupt("row lookup returned a table"))
                }
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
        self.run(|state| {
            let root = state.check_snapshot(root)?;
            let reader = DirectoryReader::new(&state.pages, state.owner.admission.clone());
            if reader.get(root, DirectoryKey::table(table))?.is_none() {
                return Err(CoreError::MissingTable);
            }
            let (lower, exclusive) = after
                .filter(|after| *after >= prefix)
                .map_or((prefix, false), |after| (after, true));
            let record = reader.next(root, DirectoryKey::row(table, lower), exclusive)?;
            Ok(record.filter(|record| {
                record.key().table == table
                    && record.key().row.is_some_and(|key| key.starts_with(prefix))
            }))
        })
    }

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
            return Err(CoreError::InvalidInput(
                "value exceeds the caller's read bound",
            ));
        }
        let identity = NativeIdentity::value(self.owner.group_id, value, table, key)?;
        let mut cache = self.cache.lock().map_err(|_| CoreError::OwnerFailed)?;
        let result = cache
            .load(identity, value.len as usize, |out| {
                self.owner.check()?;
                self.owner
                    .backend
                    .read(GroupFile::segment(value.segment_id), value.offset, out)?;
                self.owner.check()?;
                if crc32c(out) != value.crc {
                    return Err(CoreError::Corrupt("value checksum differs"));
                }
                Ok(())
            })
            .map_err(|error| match error {
                CacheLoadError::Admission(error) => error.into(),
                CacheLoadError::Load(error) => error,
            })?;
        self.owner.check()?;
        if result.as_bytes().len() != value.len as usize || crc32c(result.as_bytes()) != value.crc {
            return Err(CoreError::Corrupt("cached value identity differs"));
        }
        Ok(result)
    }

    pub(crate) fn commit(&mut self, operations: &[Operation]) -> Result<(), CoreError> {
        self.run(|state| {
            catch_unwind(AssertUnwindSafe(|| state.commit_inner(operations))).unwrap_or_else(
                |panic| {
                    Err(CoreError::UnknownCommit(std::io::Error::other(
                        CorePanic::new(panic),
                    )))
                },
            )
        })
    }

    fn commit_inner(&mut self, operations: &[Operation]) -> Result<(), CoreError> {
        // Preflight table existence against the selected tree and earlier
        // creates in this batch. No growing all-table overlay is retained.
        if operations.is_empty() || operations.len() > MAX_BATCH_OPERATIONS {
            return Err(CoreError::InvalidInput("empty or oversized transaction"));
        }
        // Abort must never request its first reservation after private effects.
        // Hold its bounded replay workspace until prepare is committed or undone.
        let workspace_bytes = segment::prepared_batch_workspace_bytes(operations)?;
        let values_bytes = (operations.len() * std::mem::size_of::<Option<ValueLocation>>()) as u64;
        let _values = self.owner.admission.reserve_workspace(
            values_bytes
                + std::mem::size_of::<crate::group::TransactionSpacePlan>() as u64
                + (LEASE_ALLOWANCE + ALLOCATION_ALLOWANCE) as u64,
        )?;
        // One fixed borrowed edit run is reused below. Charge it and the
        // temporary descriptors before preparing any private log effects.
        let directory_batch_bytes = std::mem::size_of::<
            [DirectoryEdit<'_>; MAX_DIRECTORY_BATCH_EDITS],
        >() + 4 * std::mem::size_of::<DirectoryEdit<'_>>();
        let _workspace = self.owner.admission.reserve_workspace(
            (workspace_bytes - values_bytes)
                .checked_add(LEASE_ALLOWANCE as u64)
                .and_then(|bytes| bytes.checked_add(directory_batch_bytes as u64))
                .ok_or(CoreError::CapacityDenied)?,
        )?;
        let mut directory_workspace =
            DirectoryWriteWorkspace::for_edits(self.owner.admission.clone())?;
        // All proof buffers and snapshot coverage are acquired before any
        // private disk effect. Marking never changes cache membership/policy.
        self.observe_warm_publication_start()?;
        let mut publication = self.prepare_cache_publication()?;
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
                return Err(CoreError::MissingTable);
            }
            verified_table = Some(table);
        }
        // Plan against the serialized selected writer before the first private
        // log/root effect. The installed backend atomically owns every physical
        // extent, name and descriptor promise until explicit settlement.
        let plan = {
            let root = self.owner.lock()?;
            if root.pending_segment().is_some() || root.pending_directory().is_some() {
                return Err(CoreError::InvalidInput(
                    "transaction allocation intent outstanding",
                ));
            }
            let first_segment = root
                .last_segment_id()
                .checked_add(1)
                .ok_or(CoreError::InvalidInput("segment identifier overflow"))?;
            let first_directory = root
                .last_directory_id()
                .checked_add(1)
                .ok_or(CoreError::InvalidInput("directory identifier overflow"))?;
            let (segment, new_segments) =
                self.writer.transaction_space(first_segment, operations)?;
            let (directory, new_directories) = self.arena.transaction_space(
                first_directory,
                self.selected.transaction_page_bound(operations.len())?,
            )?;
            crate::group::TransactionSpacePlan {
                group_id: self.owner.group_id,
                root_generation: root.generation(),
                batch_seq: self.writer.next_batch_sequence(),
                segment,
                directory,
                new_segments,
                new_directories,
            }
        };
        self.owner
            .backend
            .reserve_transaction(&plan)
            .map_err(|error| match error {
                crate::group::TransactionReserveError::CapacityDenied => CoreError::CapacityDenied,
                crate::group::TransactionReserveError::Failed(original) => CoreError::Io(original),
            })?;
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
        let generation = prepared.batch_seq();
        let mut shrank = false;
        let result = (|| {
            let tracked = self.pages.publication_private_view();
            let untracked = self.pages.private_view();
            let private: &dyn crate::directory::DirectoryBackend = if publication.is_some() {
                &tracked
            } else {
                &untracked
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
                if first.key.row.is_none() && mutator.get(root, first.key)?.is_some() {
                    index += 1;
                    continue;
                }
                let mut edits = [first; MAX_DIRECTORY_BATCH_EDITS];
                let mut count = 1;
                // Table creation and repeated/descending keys retain their
                // exact original order. Only distinct row edits against one
                // unchanged input root can share prior-value cache marking.
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
                    if let (Some(publication), Some(row)) = (publication.as_mut(), edit.key.row)
                        && let Some(DirectoryValue::Row { value: old, .. }) =
                            DirectoryReader::new(private, self.owner.admission.clone())
                                .get_with_workspace(
                                    root,
                                    edit.key,
                                    &mut publication.proof.directory,
                                )?
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
                        self.cache
                            .lock()
                            .map_err(|_| CoreError::OwnerFailed)?
                            .mark_publication_candidate(identity)?;
                    }
                }
                let mut applied = 0;
                while applied < count {
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
            Err(error @ CoreError::CapacityDenied) => {
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
        // The log commit is durable. Any subsequent failure is indeterminate
        // to this caller and fences; reopen decides from that exact commit.
        self.owner.install(commit).map_err(|error| match error {
            CoreError::UnknownCommit(_) => error,
            _ => CoreError::UnknownCommit(std::io::Error::other(error)),
        })?;
        self.owner
            .backend
            .finish_transaction(plan.group_id, plan.batch_seq)
            .map_err(CoreError::UnknownCommit)?;
        self.selected = root;
        self.warmup = Warmup::default();
        // Publication is durable before pruning or filling. Remove obsolete
        // identities first so old-plus-new overlap cannot displace fitting
        // current/pinned data. Disabled retention needs neither proof nor fill.
        if let Some(mut publication) = publication {
            self.reconcile_publication(&mut publication)
                .and_then(|()| {
                    self.retain_committed(
                        operations,
                        &committed.values,
                        &mut publication.proof.directory,
                    )
                })
                .map_err(|error| CoreError::UnknownCommit(std::io::Error::other(error)))?;
        }
        self.observe_warm_publication(shrank)
            .map_err(|error| CoreError::UnknownCommit(std::io::Error::other(error)))?;
        Ok(())
    }

    fn retain_committed(
        &self,
        operations: &[Operation],
        values: &[Option<ValueLocation>],
        workspace: &mut crate::directory::DirectoryReadWorkspace,
    ) -> Result<(), CoreError> {
        {
            let warming = self.pages.commit_warm_view();
            let warmer = DirectoryReader::new(&warming, self.owner.admission.clone());
            match warmer.warm_generation_with_workspace(
                self.selected,
                self.selected.generation,
                workspace,
            ) {
                Ok(()) | Err(CoreError::CapacityDenied) => {}
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
            let location = location.ok_or(CoreError::Corrupt("committed put has no location"))?;
            let visible =
                reader.get_with_workspace(self.selected, DirectoryKey::row(table, key), workspace);
            let visible = match visible {
                Ok(visible) => visible,
                Err(CoreError::CapacityDenied) => continue,
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
                .map_err(|_| CoreError::OwnerFailed)?
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
                CoreError::OwnerFailed
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
                value: location.ok_or(CoreError::Corrupt("prepared put has no location"))?,
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
) -> Result<Box<dyn ResidentLease>, CoreError> {
    admission
        .check_owner()
        .map_err(|_| CoreError::OwnerFailed)?;
    let bytes = std::mem::size_of::<DiskState>()
        + std::mem::size_of::<CheckedGroup>()
        + 2 * std::mem::size_of::<usize>()
        + std::mem::size_of::<Mutex<NativeCache<NativeIdentity>>>()
        // Foreground publication owns only one fixed proof scope/candidate.
        // Its dynamic buffers/roots have separate pre-effect admissions.
        + std::mem::size_of::<publication::PublicationCache>()
        + std::mem::size_of::<crate::cache::CacheCandidate<NativeIdentity>>()
        + SEGMENT_FIXED_WORKSPACE
        + 2 * std::mem::size_of::<Superblock>()
        + 4 * MAX_GARBAGE * std::mem::size_of::<GroupFile>()
        + 5 * ALLOCATION_ALLOWANCE
        + LEASE_ALLOWANCE;
    admission
        .reserve_workspace(bytes as u64)
        .map_err(Into::into)
}

#[cfg(test)]
#[path = "disk_state_tests.rs"]
mod tests;
