//! The persisted compaction cycle: Idle -> Evacuating -> Reclaiming ->
//! Packing -> Idle, one machine per group.
//!
//! Beginning a cycle is one root publication that freezes the cutoffs below
//! the newest confirmed segment and arena; nothing is rolled or created.
//! Evacuation rewrites every leaf that still names a value at or below the
//! segment cutoff or lives in an arena at or below the arena cutoff, with its
//! path. A leaf in a newer arena was written with its whole path after it, so
//! it and its ancestors are fresh; such a leaf without old values is skipped
//! without a data commit. Exact worklist ordinal progress is persisted even
//! for a skip, so restart cannot repeat a long-key prefix indefinitely.
//! Reclaiming runs certified cohorts (`disk_reclaim.rs`), then one bounded
//! density pass packs sparse pages (`disk_density.rs`). Each phase change is
//! its own publication; reopen resumes from the record and never restarts a
//! completed phase, so values are never re-copied by a reopen.

use super::maintenance::{Census, MaintenanceBudget, MaintenanceProgress, Measurement, can_mutate};
use super::*;
use crate::directory::{DirectoryCursor, DirectoryLeaf, MAX_DIRECTORY_LEAF_RECORDS};
use crate::root::{CompactionCursor, CompactionPhase, CompactionRecord};
use crate::segment::{MaintenanceOp, maintenance_operation_bytes};

#[path = "disk_density.rs"]
mod density;
use density::Density;

// A single larger record may exceed this target, up to MAX_VALUE_BYTES.
// Count and encoded transaction bounds are independently enforced by the log.
const COMPACTION_BATCH_BYTES: usize = 1 << 20;
const _: () = assert!(MAX_DIRECTORY_LEAF_RECORDS <= segment::MAX_MAINTENANCE_OPERATIONS);

#[derive(Clone, Copy)]
struct Cutoff {
    segment: u64,
    arena: u64,
}

/// Volatile mirror of the durable record's progress plus the Idle census.
#[derive(Default)]
pub(super) struct Compaction {
    density: Density,
    pub(super) requested: bool,
    census: Option<Census>,
    pub(super) measurement: Option<Measurement>,
    /// Statistics of the most recent step, for diagnostics and tests.
    pub(super) stats: CompactionProgress,
}

/// Internal statistics of one maintenance step; not a public contract.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CompactionProgress {
    pub(crate) entries: usize,
    pub(crate) copied_bytes: u64,
    pub(crate) maintenance_commits: usize,
    pub(crate) skipped_leaves: usize,
    pub(crate) density_pairs: usize,
    pub(crate) density_commits: usize,
    pub(crate) density_truncated_levels: usize,
    pub(crate) census_probes: usize,
    pub(crate) directory_pages_read: u64,
    pub(crate) directory_pages_written: u64,
    pub(crate) directory_syncs: u64,
}

impl Compaction {
    /// Rebuild Packing progress from the selected record. Evacuation reads
    /// its exact durable ordinal directly. Census and measurement start empty.
    pub(super) fn resume(
        record: &CompactionRecord,
        admission: &Arc<dyn StorageAdmission>,
    ) -> Result<Self, CoreError> {
        let mut compaction = Self::default();
        let cursor = record
            .cursor()
            .key()
            .map(|key| DirectoryCursor::from_key(key, admission))
            .transpose()?;
        match record.phase() {
            CompactionPhase::Evacuating => {}
            CompactionPhase::Packing => {
                compaction.density =
                    Density::resume(record.level(), cursor, record.packing_remaining())
            }
            CompactionPhase::Idle | CompactionPhase::Reclaiming => {}
        }
        Ok(compaction)
    }

    /// Files went away since the last census: measure again.
    pub(super) fn remeasure(&mut self) {
        self.measurement = None;
        self.census = None;
    }
}

impl DiskState {
    /// Run phase items until the unit budget is spent or nothing is due.
    pub(super) fn compact_steps(
        &mut self,
        budget: MaintenanceBudget,
        progress: &mut MaintenanceProgress,
    ) -> Result<(), CoreError> {
        self.compact.stats = CompactionProgress::default();
        let before = self.arena.stats()?;
        while progress.units < budget.units {
            let record = *self.owner.lock()?.compaction();
            let advanced = match record.phase() {
                CompactionPhase::Idle => self.idle_step(&record, budget, progress)?,
                CompactionPhase::Evacuating => self.evacuate_step(&record, budget, progress)?,
                CompactionPhase::Reclaiming => self.reclaiming_step(&record, budget, progress)?,
                CompactionPhase::Packing => self.pack_step(budget, progress)?,
            };
            if !advanced {
                break;
            }
        }
        let after = self.arena.stats()?;
        let stats = &mut self.compact.stats;
        stats.directory_pages_read = after.pages_read.saturating_sub(before.pages_read);
        stats.directory_pages_written = after.pages_written.saturating_sub(before.pages_written);
        stats.directory_syncs = after.syncs.saturating_sub(before.syncs);
        Ok(())
    }

    /// Publish one phase transition of the durable record.
    pub(super) fn publish_phase(
        &self,
        transition: impl FnOnce(&Superblock) -> Result<Superblock, CoreError>,
    ) -> Result<(), CoreError> {
        let mut root = self.owner.lock()?;
        let next = transition(&root)?;
        self.owner.publish(&mut root, next)
    }

    fn idle_step(
        &mut self,
        record: &CompactionRecord,
        budget: MaintenanceBudget,
        progress: &mut MaintenanceProgress,
    ) -> Result<bool, CoreError> {
        // An active round finishes first: a cycle begins only on an empty
        // garbage list, and the round frees what pins held without one.
        if self.round_active() {
            return self.round_step(budget, progress);
        }
        // Files kept only for pinned roots are neither in the baseline nor
        // counted against the trigger; Idle's round reclaims them instead.
        let policy = self.maintenance.policy;
        let kept = self.reclaim.totals;
        let due = self.compact.requested
            || self.compact.measurement.is_some_and(|measurement| {
                measurement.bytes().saturating_sub(kept.pin_retained_bytes)
                    >= policy.trigger_bytes(record.baseline_bytes())
                    || measurement.files().saturating_sub(kept.pin_retained_files)
                        >= policy.trigger_files(record.baseline_files())
            });
        if due {
            if !can_mutate(budget, progress) {
                return Ok(false);
            }
            let mut root = self.owner.lock()?;
            let writer_at_newest = self
                .writer
                .position()
                .is_none_or(|position| position.segment_id == root.last_segment_id());
            if root.directory().is_none()
                || root.compaction_cutoffs() == (0, 0)
                || !writer_at_newest
            {
                // Nothing older than the files new writes land in: a cycle
                // could not free anything yet.
                drop(root);
                self.compact.requested = false;
                if self.round_ready()? {
                    return self.round_step(budget, progress);
                }
                progress.idle = true;
                return Ok(false);
            }
            let next = root.begin_compaction()?;
            self.owner.publish(&mut root, next)?;
            drop(root);
            self.drop_owed_round();
            self.compact.requested = false;
            progress.units += 1;
            progress.mutations += 1;
            progress.phase_changed = true;
            return Ok(true);
        }
        if self.round_ready()? {
            return self.round_step(budget, progress);
        }
        let stale = {
            let root = self.owner.lock()?;
            let ids = (root.last_segment_id(), root.last_directory_id());
            let stale = self.compact.measurement.is_none_or(|measurement| {
                (measurement.last_segment_id, measurement.last_directory_id) != ids
            });
            if stale && self.compact.census.is_none() {
                self.compact.census = Some(Census::start(self.reclaim.floor, &root));
            }
            stale
        };
        let Some(census) = self.compact.census.as_mut() else {
            debug_assert!(!stale);
            progress.idle = true;
            return Ok(false);
        };
        let (used, measured) =
            census.step(self.owner.backend.as_ref(), budget.units - progress.units)?;
        progress.units += used;
        self.compact.stats.census_probes += used;
        if let Some(measurement) = measured {
            self.compact.measurement = Some(measurement);
            self.compact.census = None;
        }
        Ok(used != 0 || measured.is_some())
    }

    fn evacuate_step(
        &mut self,
        record: &CompactionRecord,
        budget: MaintenanceBudget,
        progress: &mut MaintenanceProgress,
    ) -> Result<bool, CoreError> {
        let cutoff = Cutoff {
            segment: record.cutoff_segment(),
            arena: record.cutoff_arena(),
        };
        if !can_mutate(budget, progress) {
            return Ok(false);
        }
        // Exact ordinal progress over the immutable worklist. Fresh inserts
        // never add work; removed keys are passed without restoring old data.
        // Its pages cannot retire until the durable Reclaiming transition.
        let source =
            record
                .evacuation_source()
                .ok_or(CoreError::new(crate::CoreErrorCause::Corrupt(
                    "evacuation worklist is absent",
                )))?;
        let position =
            record
                .cursor()
                .ordinal()
                .ok_or(CoreError::new(crate::CoreErrorCause::Corrupt(
                    "evacuation ordinal is absent",
                )))?;
        let leaf = {
            let reader = DirectoryReader::new(self.arena.as_ref(), self.owner.admission.clone());
            match reader.at_ordinal(source, position)? {
                Some(original) => reader.leaf_after(self.selected, original.key(), false)?,
                None => None,
            }
        };
        progress.units += 1;
        let Some(leaf) = leaf else {
            if !can_mutate(budget, progress) {
                return Ok(false);
            }
            self.publish_phase(Superblock::advance_to_reclaiming)?;
            // This root and every later one reference nothing below the
            // limits; only pins of older roots can still reach those files.
            self.reclaim.evacuated = self.selected.generation;
            progress.mutations += 1;
            progress.phase_changed = true;
            return Ok(true);
        };
        let mut plan = LeafWork::new(&leaf, cutoff, &self.owner.admission)?;
        let next = DirectoryReader::new(self.arena.as_ref(), self.owner.admission.clone())
            .ordinal_after(source, plan.cursor.key())?;
        if next <= position || next > source.entries {
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                "evacuation worklist did not advance",
            )));
        }
        let cursor = CompactionCursor::at_ordinal(next);
        if plan.needs_rewrite {
            if !can_mutate(budget, progress) {
                return Ok(false);
            }
            self.maintain_leaf(&leaf, &mut plan, cursor)?;
            progress.mutations += 1;
            progress.relocated_bytes += plan.copied_bytes;
            self.maintenance.relocated_bytes = self
                .maintenance
                .relocated_bytes
                .saturating_add(plan.copied_bytes);
            self.compact.stats.maintenance_commits += 1;
            self.compact.stats.copied_bytes += plan.copied_bytes;
        } else {
            self.publish_phase(|root| root.advance_evacuation_cursor(cursor))?;
            progress.mutations += 1;
            self.compact.stats.skipped_leaves += 1;
        }
        self.compact.stats.entries += plan.visited;
        Ok(true)
    }

    /// Finish Packing: the next cycle is scheduled from the persisted
    /// baseline and a fresh census.
    pub(super) fn finish_cycle(
        &mut self,
        budget: MaintenanceBudget,
        progress: &mut MaintenanceProgress,
    ) -> Result<bool, CoreError> {
        if !can_mutate(budget, progress) {
            return Ok(false);
        }
        self.publish_phase(Superblock::finish_compaction)?;
        self.compact.density = Density::default();
        self.compact.measurement = None;
        self.compact.census = None;
        self.compact.requested = false;
        self.maintenance.cycles_completed = self.maintenance.cycles_completed.saturating_add(1);
        progress.units += 1;
        progress.mutations += 1;
        progress.phase_changed = true;
        Ok(true)
    }

    /// Enter Packing at level zero after Reclaiming published its baseline.
    pub(super) fn start_packing(&mut self) {
        self.compact.density = Density::default();
    }

    fn maintain_leaf(
        &mut self,
        leaf: &DirectoryLeaf,
        plan: &mut LeafWork<'_>,
        cursor: CompactionCursor,
    ) -> Result<(), CoreError> {
        catch_unwind(AssertUnwindSafe(|| self.maintain_inner(leaf, plan, cursor)))
            .unwrap_or_else(|panic| Err(CoreError::unknown_commit(CorePanic::new(panic))))
    }

    /// Reserve the batch's complete space plan like `commit_inner`. A refusal
    /// stops before any effect; the caller settles the returned plan.
    pub(super) fn reserve_maintenance_space(
        &self,
        operations: &[MaintenanceOp<'_>],
        edits: usize,
    ) -> Result<crate::group::TransactionSpacePlan, CoreError> {
        let plan = {
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
            let (segment, new_segments) = self
                .writer
                .maintenance_transaction_space(first_segment, operations)?;
            let (directory, new_directories) = self.arena.transaction_space(
                first_directory,
                self.selected.transaction_page_bound(edits)?,
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
        reserve_transaction(self.owner.backend.as_ref(), &plan)?;
        Ok(plan)
    }

    fn maintain_inner(
        &mut self,
        leaf: &DirectoryLeaf,
        plan: &mut LeafWork<'_>,
        cursor: CompactionCursor,
    ) -> Result<(), CoreError> {
        // Hold abort/read workspace before any private effects. The leaf, key
        // cursor and descriptor vectors already own independent admissions.
        let workspace = self
            .owner
            .admission
            .reserve_workspace(segment::maintenance_workspace_bytes() + LEASE_ALLOWANCE as u64)
            .map(NativeResidentLease::new)?;
        let mut directory_workspace =
            DirectoryWriteWorkspace::for_leaf_rewrite(self.owner.admission.clone())?;
        let witness = self.selection_witness();
        // A leaf rewrite replaces fixed-size locations: one edit's path.
        let space = self.reserve_maintenance_space(&plan.operations, 1)?;
        let mut roll = Roll(self.owner.clone());
        let prepared = match self.writer.prepare_maintenance(
            self.owner.backend.as_ref(),
            &plan.operations,
            &mut roll,
        ) {
            Ok(prepared) => prepared,
            Err(original) if !self.writer.is_fenced() => {
                self.owner
                    .backend
                    .cancel_transaction(space.group_id, space.batch_seq)?;
                return Err(original);
            }
            Err(original) => return Err(original),
        };
        self.owner.check()?;
        if prepared.values().len() != plan.operations.len() {
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                "maintenance location count differs",
            )));
        }
        for (&index, &destination) in plan.indices.iter().zip(prepared.values()) {
            plan.replacements[index] = Some(destination.ok_or(CoreError::new(
                crate::CoreErrorCause::Corrupt("maintenance relocation has no location"),
            ))?);
        }
        let fresh = self.arena.append_floor();
        let private = self.pages.maintenance_private_view();
        let result = (|| {
            let mut mutator = DirectoryMutator::new(&private, &mut directory_workspace)?;
            let root = mutator.rewrite_leaf(
                self.selected,
                prepared.batch_seq(),
                leaf,
                &plan.replacements,
            )?;
            mutator.finish(root)
        })();
        drop(directory_workspace);
        let root = match result {
            Ok(root) => root,
            Err(error) if error.is_capacity_denied() => {
                self.owner
                    .backend
                    .finish_transaction(space.group_id, space.batch_seq)?;
                self.writer.abort_prepared(
                    self.owner.backend.as_ref(),
                    prepared,
                    &self.owner.bounds()?,
                )?;
                return Err(error);
            }
            Err(error) => {
                self.owner.failed.store(true, Ordering::Release);
                return Err(error);
            }
        };
        self.finish_maintenance(witness, prepared, root, workspace, &space, (0, cursor, 0))?;
        let retained = (|| {
            for (operation, &index) in plan.operations.iter().zip(&plan.indices) {
                let MaintenanceOp::Relocate {
                    source, table, key, ..
                } = operation
                else {
                    return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                        "relocation plan operation differs",
                    )));
                };
                let destination = plan.replacements[index].ok_or(CoreError::new(
                    crate::CoreErrorCause::Corrupt("relocation plan destination is missing"),
                ))?;
                let identity =
                    |value| NativeIdentity::value(self.owner.group_id, value, table, key);
                self.cache
                    .lock()
                    .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
                    .copy_relocated(identity(*source)?, identity(destination)?)?;
            }
            self.warm_maintenance_pages(root, fresh)
        })();
        retained.map_err(|error: CoreError| error.into_unknown_commit())?;
        Ok(())
    }

    /// Commit a prepared maintenance batch and install it through the
    /// selection funnel with its in-phase cursor, then settle its space.
    pub(super) fn finish_maintenance(
        &mut self,
        witness: SelectionWitness,
        prepared: segment::PreparedBatch,
        root: DirectoryRoot,
        workspace: NativeResidentLease,
        space: &crate::group::TransactionSpacePlan,
        cursor: (u8, CompactionCursor, u64),
    ) -> Result<(), CoreError> {
        self.observe_warm_publication_start()?;
        let committed = self.writer.finish_batch(
            self.owner.backend.as_ref(),
            prepared,
            root,
            &mut Roll(self.owner.clone()),
        )?;
        let commit = DirectoryCommit {
            root,
            start: ReplayStart {
                position: committed.end,
                batch_seq: committed.batch_seq,
                chain: committed.chain,
            },
        };
        drop(workspace);
        // The log commit is durable; every later failure is indeterminate.
        self.install_selected(witness, commit, &committed.values, Some(cursor))
            .map_err(|error| error.into_unknown_commit())?;
        drop(committed);
        self.owner
            .backend
            .finish_transaction(space.group_id, space.batch_seq)
            .map_err(CoreError::unknown_io)?;
        self.warmup = Warmup::default();
        // Physical page packing/alias retirement can make a previously
        // oversized resident union fit without a logical row-size change.
        self.reset_auto_warm();
        Ok(())
    }

    /// Retain the pages `root`'s publication appended at or above `fresh`.
    pub(super) fn warm_maintenance_pages(
        &self,
        root: DirectoryRoot,
        fresh: AppendFloor,
    ) -> Result<(), CoreError> {
        let warming = self.pages.maintenance_view();
        match DirectoryReader::new(&warming, self.owner.admission.clone()).warm_generation(
            root,
            root.generation,
            fresh,
        ) {
            Ok(()) => Ok(()),
            Err(error) if error.is_capacity_denied() => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Borrow keys from one admitted leaf; only the continuation key is copied.
/// All three vectors reserve exact bounded capacity before preparing a log.
struct LeafWork<'a> {
    operations: Vec<MaintenanceOp<'a>>,
    indices: Vec<usize>,
    replacements: Vec<Option<ValueLocation>>,
    cursor: DirectoryRecord,
    visited: usize,
    copied_bytes: u64,
    needs_rewrite: bool,
    _lease: NativeResidentLease,
}

impl<'a> LeafWork<'a> {
    fn new(
        leaf: &'a DirectoryLeaf,
        cutoff: Cutoff,
        admission: &Arc<dyn StorageAdmission>,
    ) -> Result<Self, CoreError> {
        if leaf.len() == 0
            || leaf.len() > MAX_DIRECTORY_LEAF_RECORDS
            || leaf.first_index() >= leaf.len()
        {
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                "compaction leaf bounds are invalid",
            )));
        }
        let bytes = leaf.len()
            * (std::mem::size_of::<MaintenanceOp<'_>>()
                + std::mem::size_of::<usize>()
                + std::mem::size_of::<Option<ValueLocation>>())
            + std::mem::size_of::<Self>()
            + 3 * ALLOCATION_ALLOWANCE
            + LEASE_ALLOWANCE;
        let lease = admission
            .reserve_workspace(bytes as u64)
            .map(NativeResidentLease::new)?;
        let mut operations = Vec::new();
        let mut indices = Vec::new();
        let mut replacements = Vec::new();
        operations
            .try_reserve_exact(leaf.len())
            .map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        indices
            .try_reserve_exact(leaf.len())
            .map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        replacements
            .try_reserve_exact(leaf.len())
            .map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        if operations.capacity() != leaf.len()
            || indices.capacity() != leaf.len()
            || replacements.capacity() != leaf.len()
        {
            return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
        }
        replacements.resize(leaf.len(), None);
        let mut encoded_bytes = 0usize;
        let mut visited = 0;
        let mut copied_bytes = 0;
        let mut last = leaf.first_index();
        for (index, (key, value)) in leaf.records().enumerate().skip(leaf.first_index()) {
            if let DirectoryValue::Row { batch_seq, value } = value
                && value.segment_id <= cutoff.segment
            {
                let operation = MaintenanceOp::Relocate {
                    table: key.table,
                    key: key.row.expect("validated leaf row"),
                    logical_batch_seq: batch_seq,
                    source: value,
                };
                let bytes = maintenance_operation_bytes(operation)?;
                if !operations.is_empty() && encoded_bytes + bytes > COMPACTION_BATCH_BYTES {
                    break;
                }
                encoded_bytes += bytes;
                copied_bytes += u64::from(value.len);
                operations.push(operation);
                indices.push(index);
            }
            visited += 1;
            last = index;
        }
        let needs_rewrite = !operations.is_empty() || leaf.reference().arena_id <= cutoff.arena;
        if operations.is_empty() && needs_rewrite {
            operations.push(MaintenanceOp::DirectoryOnly);
        }
        // A fresh leaf has fresh ancestors: creating its reference necessarily
        // copied the complete path after the frozen arena cutoff. Such a leaf
        // with no old value addresses can be skipped without writing a root.
        let cursor = leaf.owned_record(last)?;
        admission
            .check_owner()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?;
        Ok(Self {
            operations,
            indices,
            replacements,
            cursor,
            visited,
            copied_bytes,
            needs_rewrite,
            _lease: lease,
        })
    }
}
