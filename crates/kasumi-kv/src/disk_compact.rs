//! Incremental evacuation, directory packing, then reachability GC.
//!
//! Rotate both appenders before scanning. A foreground write can then insert
//! behind the cursor without reintroducing an old physical location. Each step
//! reads the current root under the state owner's exclusive lock. Old snapshots
//! retain their immutable roots and are protected by the reclamation registry.

use super::*;
use crate::directory::{DirectoryLeaf, MAX_DIRECTORY_LEAF_RECORDS};
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

#[derive(Default)]
pub(super) struct Compaction {
    cutoff: Option<Cutoff>,
    segment_rotated: bool,
    arena_rotated: bool,
    after: Option<DirectoryRecord>,
    scan_complete: bool,
    density: Density,
    completed_generation: Option<u64>,
}

#[derive(Default, Debug)]
pub(crate) struct CompactionProgress {
    /// A roll, one bounded leaf batch (possibly a verified skip), or reclamation
    /// work. A batch targets one MiB of encoded records; one oversized value may
    /// still require up to MAX_VALUE_BYTES in this synchronous call.
    pub(crate) work: usize,
    pub(crate) entries: usize,
    pub(crate) copied_bytes: u64,
    pub(crate) maintenance_commits: usize,
    pub(crate) skipped_leaves: usize,
    pub(crate) evacuated: bool,
    pub(crate) density_pairs: usize,
    pub(crate) density_commits: usize,
    pub(crate) density_passes: usize,
    pub(crate) density_restarts: usize,
    pub(crate) density_complete: bool,
    pub(crate) cache_work: usize,
    pub(crate) cache_entries_pruned: usize,
    pub(crate) cache_restarts: usize,
    pub(crate) residency_complete: bool,
    pub(crate) fully_resident: bool,
    pub(crate) directory_pages_read: u64,
    pub(crate) directory_pages_written: u64,
    pub(crate) directory_syncs: u64,
    pub(crate) reclaimed: usize,
    pub(crate) complete: bool,
}

impl DiskState {
    pub(crate) fn compact_step(
        &mut self,
        work_limit: usize,
    ) -> Result<CompactionProgress, CoreError> {
        let result = self.run(|state| {
            let before = state.arena.stats()?;
            let mut progress = state.compact_inner(work_limit)?;
            let after = state.arena.stats()?;
            progress.directory_pages_read = after.pages_read.saturating_sub(before.pages_read);
            progress.directory_pages_written =
                after.pages_written.saturating_sub(before.pages_written);
            progress.directory_syncs = after.syncs.saturating_sub(before.syncs);
            Ok(progress)
        });
        if self.owner.failed.load(Ordering::Acquire) {
            self.compact = Compaction::default();
        }
        result
    }

    fn compact_inner(&mut self, work_limit: usize) -> Result<CompactionProgress, CoreError> {
        let mut progress = CompactionProgress::default();
        if work_limit == 0 {
            return Ok(progress);
        }
        if let Some(generation) = self.compact.completed_generation {
            if generation == self.selected.generation {
                progress.evacuated = true;
                progress.density_complete = true;
                if !self.compact_residency(&mut progress, work_limit)? {
                    return Ok(progress);
                }
                let reclaimed = self.reclaim_step(work_limit - progress.work)?;
                progress.work += reclaimed.work;
                progress.reclaimed = reclaimed.reclaimed;
                progress.complete = reclaimed.complete;
                return Ok(progress);
            }
            self.compact = Compaction::default();
        }
        if self.compact.cutoff.is_none() {
            self.compact.cutoff = Some(Cutoff {
                segment: self.owner.bounds()?.last_segment_id,
                arena: self.owner.lock()?.last_directory_id(),
            });
            if self.selected.entries == 0 {
                self.compact.scan_complete = true;
            }
        }
        while progress.work < work_limit && !self.compact.scan_complete {
            if !self.compact.segment_rotated {
                self.writer
                    .force_roll(self.owner.backend.as_ref(), &mut Roll(self.owner.clone()))?;
                self.compact.segment_rotated = true;
                progress.work += 1;
                continue;
            }
            if !self.compact.arena_rotated {
                self.arena.force_roll()?;
                self.compact.arena_rotated = true;
                progress.work += 1;
                continue;
            }
            let (lower, exclusive) = self
                .compact
                .after
                .as_ref()
                .map_or((DirectoryKey::table("\0"), false), |record| {
                    (record.key(), true)
                });
            // Maintenance reads never admit cold source pages to the cache.
            let next = DirectoryReader::new(self.arena.as_ref(), self.owner.admission.clone())
                .leaf_after(self.selected, lower, exclusive)?;
            progress.work += 1;
            let Some(leaf) = next else {
                self.compact.scan_complete = true;
                self.compact.after = None;
                break;
            };
            let cutoff = self.compact.cutoff.expect("started compaction");
            let mut plan = LeafWork::new(&leaf, cutoff, &self.owner.admission)?;
            if plan.needs_rewrite {
                self.maintain_leaf(&leaf, &mut plan)?;
                progress.maintenance_commits += 1;
            } else {
                progress.skipped_leaves += 1;
            }
            progress.copied_bytes += plan.copied_bytes;
            progress.entries += plan.visited;
            self.compact.after = Some(plan.cursor);
        }
        progress.evacuated = self.compact.scan_complete;
        if self.compact.scan_complete
            && self.density_step(&mut progress, work_limit)?
            && progress.work < work_limit
            && self.compact_residency(&mut progress, work_limit)?
            && progress.work < work_limit
        {
            let reclaimed = self.reclaim_step(work_limit - progress.work)?;
            progress.work += reclaimed.work;
            progress.reclaimed += reclaimed.reclaimed;
            if reclaimed.complete {
                self.compact.completed_generation = Some(self.selected.generation);
                progress.complete = true;
            }
        }
        Ok(progress)
    }

    fn compact_residency(
        &mut self,
        progress: &mut CompactionProgress,
        work_limit: usize,
    ) -> Result<bool, CoreError> {
        let warm = self.warm_inner(work_limit - progress.work, false)?;
        progress.work += warm.work;
        progress.cache_work += warm.work;
        progress.cache_entries_pruned += warm.pruned;
        progress.cache_restarts += warm.restarts;
        progress.residency_complete = warm.complete;
        progress.fully_resident = warm.fully_resident;
        // Synchronous Core::compact drains steps without a timed scheduler.
        // Preserve the refused item but return retryable pressure instead of
        // spinning through the same provider denial under the owner lock.
        if warm.provider_limited {
            return Err(CoreError::CapacityDenied);
        }
        Ok(warm.complete)
    }

    fn maintain_leaf(
        &mut self,
        leaf: &DirectoryLeaf,
        plan: &mut LeafWork<'_>,
    ) -> Result<(), CoreError> {
        catch_unwind(AssertUnwindSafe(|| self.maintain_inner(leaf, plan))).unwrap_or_else(|panic| {
            Err(CoreError::UnknownCommit(std::io::Error::other(
                CorePanic::new(panic),
            )))
        })
    }

    fn maintain_inner(
        &mut self,
        leaf: &DirectoryLeaf,
        plan: &mut LeafWork<'_>,
    ) -> Result<(), CoreError> {
        // Hold abort/read workspace before any private effects. The leaf, key
        // cursor and descriptor vectors already own independent admissions.
        let workspace = self
            .owner
            .admission
            .reserve_workspace(segment::maintenance_workspace_bytes() + LEASE_ALLOWANCE as u64)?;
        let mut directory_workspace =
            DirectoryWriteWorkspace::for_leaf_rewrite(self.owner.admission.clone())?;
        let mut roll = Roll(self.owner.clone());
        let prepared = self.writer.prepare_maintenance(
            self.owner.backend.as_ref(),
            &plan.operations,
            &mut roll,
        )?;
        self.owner.check()?;
        if prepared.values().len() != plan.operations.len() {
            return Err(CoreError::Corrupt("maintenance location count differs"));
        }
        for (&index, &destination) in plan.indices.iter().zip(prepared.values()) {
            plan.replacements[index] = Some(
                destination.ok_or(CoreError::Corrupt("maintenance relocation has no location"))?,
            );
        }
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
            Err(error @ CoreError::CapacityDenied) => {
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
        self.finish_maintenance(prepared, root, workspace)?;
        let retained = (|| {
            for (operation, &index) in plan.operations.iter().zip(&plan.indices) {
                let MaintenanceOp::Relocate {
                    source, table, key, ..
                } = operation
                else {
                    return Err(CoreError::Corrupt("relocation plan operation differs"));
                };
                let destination = plan.replacements[index]
                    .ok_or(CoreError::Corrupt("relocation plan destination is missing"))?;
                let identity =
                    |value| NativeIdentity::value(self.owner.group_id, value, table, key);
                self.cache
                    .lock()
                    .map_err(|_| CoreError::OwnerFailed)?
                    .copy_relocated(identity(*source)?, identity(destination)?)?;
            }
            self.warm_maintenance_pages(root)
        })();
        retained
            .map_err(|error: CoreError| CoreError::UnknownCommit(std::io::Error::other(error)))?;
        Ok(())
    }

    fn finish_maintenance(
        &mut self,
        prepared: segment::PreparedBatch,
        root: DirectoryRoot,
        workspace: Box<dyn ResidentLease>,
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
        drop(committed);
        drop(workspace);
        self.owner
            .install(commit)
            .map_err(|error| CoreError::UnknownCommit(std::io::Error::other(error)))?;
        self.selected = root;
        self.warmup = Warmup::default();
        // Physical page packing/alias retirement can make a previously
        // oversized resident union fit without a logical row-size change.
        self.reset_auto_warm();
        Ok(())
    }

    fn warm_maintenance_pages(&self, root: DirectoryRoot) -> Result<(), CoreError> {
        let warming = self.pages.maintenance_view();
        match DirectoryReader::new(&warming, self.owner.admission.clone())
            .warm_generation(root, root.generation)
        {
            Ok(()) | Err(CoreError::CapacityDenied) => Ok(()),
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
    _lease: Box<dyn ResidentLease>,
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
            return Err(CoreError::Corrupt("compaction leaf bounds are invalid"));
        }
        let bytes = leaf.len()
            * (std::mem::size_of::<MaintenanceOp<'_>>()
                + std::mem::size_of::<usize>()
                + std::mem::size_of::<Option<ValueLocation>>())
            + std::mem::size_of::<Self>()
            + 3 * ALLOCATION_ALLOWANCE
            + LEASE_ALLOWANCE;
        let lease = admission.reserve_workspace(bytes as u64)?;
        let mut operations = Vec::new();
        let mut indices = Vec::new();
        let mut replacements = Vec::new();
        operations
            .try_reserve_exact(leaf.len())
            .map_err(|_| CoreError::CapacityDenied)?;
        indices
            .try_reserve_exact(leaf.len())
            .map_err(|_| CoreError::CapacityDenied)?;
        replacements
            .try_reserve_exact(leaf.len())
            .map_err(|_| CoreError::CapacityDenied)?;
        if operations.capacity() != leaf.len()
            || indices.capacity() != leaf.len()
            || replacements.capacity() != leaf.len()
        {
            return Err(CoreError::CapacityDenied);
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
            .map_err(|_| CoreError::OwnerFailed)?;
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
