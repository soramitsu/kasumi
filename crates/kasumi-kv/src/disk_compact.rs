//! The persisted compaction cycle: Idle -> Evacuating -> Reclaiming ->
//! Packing -> Idle, one machine per group.
//!
//! Beginning a cycle is one root publication that freezes the cutoffs below
//! the newest confirmed segment and arena; nothing is rolled or created.
//! Evacuation first surveys the live value bytes of every old segment in one
//! read-only walk of the immutable cycle-start worklist, and selects the
//! segments to empty (`MaintenancePolicy::retained_garbage_percent`); the
//! rest keep their values in place. The selection depends only on that
//! worklist, the cutoff and the policy, so a reopen surveys again and selects
//! the same segments. Evacuation then rewrites every leaf that still names a
//! value of a selected segment at or below the segment cutoff or lives in an
//! arena at or below the arena cutoff, with its path. A leaf in a newer arena
//! was written with its whole path after it, so it and its ancestors are
//! fresh; such a leaf with nothing to relocate is skipped without a data
//! commit. With no segment selected the cycle rewrites old arenas only, and
//! so does a cycle whose survey was refused admission three times or met
//! more segments than its bound: it keeps every old segment in place.
//! Exact worklist ordinal progress is persisted even for a skip, so restart
//! cannot repeat a long-key prefix indefinitely. Reclaiming runs certified
//! cohorts (`disk_reclaim.rs`), which prove reachability and so keep the
//! segments left in place, then one bounded density pass packs sparse pages
//! (`disk_density.rs`). Each phase change is its own publication; reopen
//! resumes from the record and never restarts a completed phase, so values
//! are never re-copied by a reopen.

use super::maintenance::{Census, MaintenanceBudget, MaintenanceProgress, Measurement, can_mutate};
use super::*;
use crate::directory::{
    DirectoryBackend, DirectoryCursor, DirectoryLeaf, DirectoryWalker, MAX_DIRECTORY_LEAF_RECORDS,
};
use crate::reclaim::WALK_WORK_PER_UNIT;
use crate::root::{CompactionCursor, CompactionPhase, CompactionRecord};
use crate::segment::{MaintenanceOp, VALUE_RECORD_OVERHEAD_BYTES, maintenance_operation_bytes};

#[path = "disk_density.rs"]
mod density;
use density::Density;

// A single larger record may exceed this target, up to MAX_VALUE_BYTES.
// Count and encoded transaction bounds are independently enforced by the log.
const COMPACTION_BATCH_BYTES: usize = 1 << 20;
const _: () = assert!(MAX_DIRECTORY_LEAF_RECORDS <= segment::MAX_MAINTENANCE_OPERATIONS);

/// Refused survey admissions one evacuation takes before it keeps every old
/// segment in place instead: an arena-only cycle.
pub(super) const SURVEY_ATTEMPTS: u32 = 3;
/// The survey's first map capacity, in segments; it doubles as needed.
const SURVEY_INITIAL_SEGMENTS: usize = 64;
/// A survey that would track more segments than this keeps every old segment
/// in place instead.
const SURVEY_MAX_SEGMENTS: usize = 1 << 20;
/// Kept segments may span at most this many identifiers per surveyed
/// segment. Older ones are emptied, so the reclaim floor, and with it every
/// census and cohort probe range, keeps rising.
const KEPT_SPAN_PER_SEGMENT: u64 = 8;

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
    /// The evacuating cycle's segment selection, once surveyed. Reopen
    /// leaves it empty and the next evacuation step surveys again.
    selection: Option<Selection>,
    survey: Option<Survey>,
    /// Refused survey admissions of one cycle: (cycle, count).
    survey_denials: (u64, u32),
    /// The most segments a survey tracks, `SURVEY_MAX_SEGMENTS` unless a
    /// test lowers it.
    survey_segment_bound: Option<usize>,
    /// The latest selection's figures, for the status.
    pub(super) evacuation: EvacuationStats,
    /// Statistics of the most recent step, for diagnostics and tests.
    pub(super) stats: CompactionProgress,
}

/// Figures of the latest evacuation selection, for the status.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct EvacuationStats {
    pub(super) surveyed_segments: u64,
    pub(super) kept_segments: u64,
    pub(super) kept_garbage_bytes: u64,
    /// Process-lifetime count of evacuations that kept every old segment in
    /// place, unsurveyed, because their survey was refused admission or met
    /// more segments than its bound.
    pub(super) survey_fallbacks: u64,
}

/// Sorted (segment, live bytes) pairs in exactly admitted capacity, at most
/// `bound` of them.
struct LiveSegments {
    entries: Vec<(u64, u64)>,
    /// The entry the previous value matched: neighbouring values usually
    /// share a segment.
    last: usize,
    bound: usize,
    admission: Arc<dyn StorageAdmission>,
    _lease: NativeResidentLease,
}

impl LiveSegments {
    fn with_capacity(
        capacity: usize,
        bound: usize,
        admission: &Arc<dyn StorageAdmission>,
    ) -> Result<Self, CoreError> {
        let bytes = capacity * std::mem::size_of::<(u64, u64)>()
            + std::mem::size_of::<Self>()
            + ALLOCATION_ALLOWANCE
            + LEASE_ALLOWANCE;
        let lease = admission
            .reserve_workspace(bytes as u64)
            .map(NativeResidentLease::new)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(capacity)
            .map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        if entries.capacity() != capacity {
            return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
        }
        Ok(Self {
            entries,
            last: 0,
            bound,
            admission: admission.clone(),
            _lease: lease,
        })
    }

    /// Add one value's bytes to its segment; `false`, changing nothing, when
    /// tracking one more segment would exceed the bound.
    fn add(&mut self, segment: u64, bytes: u64) -> Result<bool, CoreError> {
        let index = match self.entries.get(self.last) {
            Some(&(id, _)) if id == segment => Ok(self.last),
            _ => self.entries.binary_search_by_key(&segment, |&(id, _)| id),
        };
        match index {
            Ok(index) => {
                let live = &mut self.entries[index].1;
                *live = live.saturating_add(bytes);
                self.last = index;
            }
            Err(index) => {
                if self.entries.len() >= self.bound {
                    return Ok(false);
                }
                if self.entries.len() == self.entries.capacity() {
                    // Admit the doubled map before the old one is released.
                    let capacity = self.entries.capacity().saturating_mul(2).min(self.bound);
                    let mut grown = Self::with_capacity(capacity, self.bound, &self.admission)?;
                    grown.entries.extend_from_slice(&self.entries);
                    *self = grown;
                }
                self.entries.insert(index, (segment, bytes));
                self.last = index;
            }
        }
        Ok(true)
    }
}

/// One read-only walk of the cycle-start worklist that sums the live value
/// bytes of every segment at or below the cutoff. It publishes nothing; any
/// error poisons the walker and the next attempt starts over.
struct Survey {
    cycle: u64,
    cutoff: u64,
    walker: DirectoryWalker,
    live: LiveSegments,
    complete: bool,
    /// The walk met more segments than the bound and stopped.
    overflowed: bool,
}

impl Survey {
    fn new(
        record: &CompactionRecord,
        source: DirectoryRoot,
        bound: usize,
        admission: &Arc<dyn StorageAdmission>,
    ) -> Result<Self, CoreError> {
        Ok(Self {
            cycle: record.cycle(),
            cutoff: record.cutoff_segment(),
            live: LiveSegments::with_capacity(
                SURVEY_INITIAL_SEGMENTS.min(bound),
                bound,
                admission,
            )?,
            walker: DirectoryWalker::new(source, admission.clone())?,
            complete: false,
            overflowed: false,
        })
    }

    /// Walk within `units`; returns the units charged.
    fn step(&mut self, directory: &dyn DirectoryBackend, units: usize) -> Result<usize, CoreError> {
        let Self {
            cutoff,
            walker,
            live,
            ..
        } = self;
        let mut overflowed = false;
        let walked = walker.step(
            directory,
            units.saturating_mul(WALK_WORK_PER_UNIT),
            |_| Ok(()),
            |value| {
                // Table and key bytes are not counted: a segment of small
                // values looks emptier and is emptied sooner, never later.
                if value.segment_id <= *cutoff
                    && !live.add(
                        value.segment_id,
                        u64::from(value.len) + VALUE_RECORD_OVERHEAD_BYTES,
                    )?
                {
                    // Stop the walk: what it would add is no longer used.
                    overflowed = true;
                    return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
                }
                Ok(())
            },
        );
        if overflowed {
            self.overflowed = true;
            self.complete = true;
            return Ok(units);
        }
        let walked = walked?;
        if walked.complete {
            self.complete = true;
        } else if walked.work == 0 {
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                "directory walker made no progress",
            )));
        }
        // Whole units only. An unfinished walk did at least its limit, so it
        // costs at least one; a walk that finished within less than one unit
        // costs nothing and its step goes on to evacuate, so a small worklist
        // still advances under one-unit steps and a reopen after each.
        Ok((walked.work / WALK_WORK_PER_UNIT).min(units))
    }

    fn select(self, capacity: u64, percent: u32) -> Selection {
        let Self {
            cycle,
            cutoff,
            mut live,
            ..
        } = self;
        let (kept, kept_garbage) = keep_segments(&mut live.entries, capacity, percent, cutoff);
        let surveyed = live.entries.len();
        Selection {
            cycle,
            kept: Kept::Surveyed {
                live,
                from: surveyed - kept,
            },
            stats: EvacuationStats {
                surveyed_segments: surveyed as u64,
                kept_segments: kept as u64,
                kept_garbage_bytes: kept_garbage,
                survey_fallbacks: 0,
            },
        }
    }
}

/// Choose the old segments one evacuation keeps in place from the live
/// value bytes of each (identifiers at or below `cutoff`, in any order).
///
/// Every segment at most half live is emptied. Then, emptiest first and
/// lowest identifier first among equals, more are emptied until the garbage
/// left in the kept ones, `capacity` less their live bytes each, is at most
/// `percent` of all the live bytes. Last, the oldest kept segments are
/// emptied while the kept ones span more than `KEPT_SPAN_PER_SEGMENT`
/// identifiers per surveyed segment. The result depends only on its inputs.
///
/// Returns how many segments it keeps, which are then the trailing entries
/// in identifier order, and the garbage estimated to stay in them.
pub(super) fn keep_segments(
    live: &mut [(u64, u64)],
    capacity: u64,
    percent: u32,
    cutoff: u64,
) -> (usize, u64) {
    let garbage = |bytes: u64| u128::from(capacity.saturating_sub(bytes));
    // Unique identifiers make the unstable order exact.
    live.sort_unstable_by_key(|&(id, bytes)| (bytes, id));
    let total: u128 = live.iter().map(|&(_, bytes)| u128::from(bytes)).sum();
    let allowance = total * u128::from(percent) / 100;
    let mut start = live.partition_point(|&(_, bytes)| bytes.saturating_mul(2) <= capacity);
    let mut kept_garbage: u128 = live[start..].iter().map(|&(_, bytes)| garbage(bytes)).sum();
    while start < live.len() && kept_garbage > allowance {
        kept_garbage -= garbage(live[start].1);
        start += 1;
    }
    live[start..].sort_unstable_by_key(|&(id, _)| id);
    let span = KEPT_SPAN_PER_SEGMENT.saturating_mul(live.len() as u64);
    while let Some(&(oldest, bytes)) = live.get(start)
        && cutoff.saturating_sub(oldest).saturating_add(1) > span
    {
        kept_garbage -= garbage(bytes);
        start += 1;
    }
    (
        live.len() - start,
        u64::try_from(kept_garbage).unwrap_or(u64::MAX),
    )
}

/// What one cycle's evacuation relocates: every value at or below the
/// segment cutoff except those of the kept segments.
struct Selection {
    cycle: u64,
    kept: Kept,
    stats: EvacuationStats,
}

enum Kept {
    /// The legacy policy: every old value is relocated.
    Nothing,
    /// The surveyed segments; those from `from` on are kept, in identifier
    /// order. A segment the survey did not see is relocated.
    Surveyed { live: LiveSegments, from: usize },
    /// No survey could select: every old segment stays, an arena-only cycle.
    Everything,
}

impl Selection {
    fn relocate_all(cycle: u64) -> Self {
        Self {
            cycle,
            kept: Kept::Nothing,
            stats: EvacuationStats::default(),
        }
    }

    fn keep_all(cycle: u64) -> Self {
        Self {
            cycle,
            kept: Kept::Everything,
            stats: EvacuationStats::default(),
        }
    }

    /// Whether evacuation relocates an old value of `segment_id`.
    fn relocates(&self, segment_id: u64) -> bool {
        match &self.kept {
            Kept::Nothing => true,
            Kept::Surveyed { live, from } => live.entries[*from..]
                .binary_search_by_key(&segment_id, |&(id, _)| id)
                .is_err(),
            Kept::Everything => false,
        }
    }
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

/// A selection as the selection tests observe it.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SelectionForTest {
    RelocateAll,
    KeepAll,
    /// The surveyed and the kept segments, both in identifier order.
    Surveyed {
        surveyed: Vec<u64>,
        kept: Vec<u64>,
    },
}

#[cfg(test)]
impl Compaction {
    /// Observation hooks for the selection tests only.
    pub(super) fn selection_for_test(&self) -> Option<(u64, SelectionForTest)> {
        let selection = self.selection.as_ref()?;
        let observed = match &selection.kept {
            Kept::Nothing => SelectionForTest::RelocateAll,
            Kept::Everything => SelectionForTest::KeepAll,
            Kept::Surveyed { live, from } => {
                let kept = live.entries[*from..].iter().map(|&(id, _)| id).collect();
                let mut surveyed: Vec<u64> = live.entries.iter().map(|&(id, _)| id).collect();
                surveyed.sort_unstable();
                SelectionForTest::Surveyed { surveyed, kept }
            }
        };
        Some((selection.cycle, observed))
    }
    pub(super) fn surveying_for_test(&self) -> bool {
        self.survey.is_some()
    }
    /// The segments the survey in progress tracks so far.
    pub(super) fn survey_segments_for_test(&self) -> Option<usize> {
        Some(self.survey.as_ref()?.live.entries.len())
    }
    pub(super) fn bound_survey_for_test(&mut self, segments: usize) {
        assert!(segments > 0);
        self.survey_segment_bound = Some(segments);
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
        // Read-only, so it runs before the publication check: steps without
        // a mutation allowance still advance it.
        if self
            .compact
            .selection
            .as_ref()
            .is_none_or(|selection| selection.cycle != record.cycle())
        {
            return self.survey_step(record, budget, progress);
        }
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
            self.compact.selection = None;
            // This root and every later one reference nothing in the selected
            // segments or the old arenas; only pins of older roots can still
            // reach those files. Kept segments stay referenced, and every
            // cohort's walk keeps what any root references.
            self.reclaim.evacuated = self.selected.generation;
            progress.mutations += 1;
            progress.phase_changed = true;
            return Ok(true);
        };
        let selection = self
            .compact
            .selection
            .as_ref()
            .expect("surveyed evacuation");
        let mut plan = LeafWork::new(&leaf, cutoff, selection, &self.owner.admission)?;
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

    /// Survey the evacuating cycle's worklist within the unit budget and
    /// select its segments once complete. The legacy policy relocates every
    /// old value without a survey; repeatedly refused admission, or more
    /// segments than the bound, keeps every old segment in place.
    fn survey_step(
        &mut self,
        record: &CompactionRecord,
        budget: MaintenanceBudget,
        progress: &mut MaintenanceProgress,
    ) -> Result<bool, CoreError> {
        let cycle = record.cycle();
        if self.maintenance.policy.retained_garbage_percent == 0 {
            self.compact.survey = None;
            self.set_selection(Selection::relocate_all(cycle), false);
            return Ok(true);
        }
        if self.compact.survey_denials.0 == cycle
            && self.compact.survey_denials.1 >= SURVEY_ATTEMPTS
        {
            self.compact.survey = None;
            self.set_selection(Selection::keep_all(cycle), true);
            return Ok(true);
        }
        let result = self.survey_walk(record, budget, progress);
        if let Err(error) = &result {
            self.compact.survey = None;
            if error.is_capacity_denied() {
                let (denied, count) = self.compact.survey_denials;
                self.compact.survey_denials = (cycle, if denied == cycle { count + 1 } else { 1 });
            }
        }
        result
    }

    fn survey_walk(
        &mut self,
        record: &CompactionRecord,
        budget: MaintenanceBudget,
        progress: &mut MaintenanceProgress,
    ) -> Result<bool, CoreError> {
        if self
            .compact
            .survey
            .as_ref()
            .is_none_or(|survey| survey.cycle != record.cycle())
        {
            let source = record.evacuation_source().ok_or(CoreError::new(
                crate::CoreErrorCause::Corrupt("evacuation worklist is absent"),
            ))?;
            let bound = self
                .compact
                .survey_segment_bound
                .unwrap_or(SURVEY_MAX_SEGMENTS);
            self.compact.survey = Some(Survey::new(record, source, bound, &self.owner.admission)?);
        }
        let survey = self.compact.survey.as_mut().expect("started survey");
        progress.units += survey.step(self.arena.as_ref(), budget.units - progress.units)?;
        if !survey.complete {
            return Ok(true);
        }
        let survey = self.compact.survey.take().expect("complete survey");
        if survey.overflowed {
            self.set_selection(Selection::keep_all(survey.cycle), true);
        } else {
            let selection = survey.select(
                self.writer.capacity(),
                self.maintenance.policy.retained_garbage_percent,
            );
            self.set_selection(selection, false);
        }
        Ok(true)
    }

    /// Install a cycle's selection and its status figures; `fallback` counts
    /// an evacuation that keeps every old segment unsurveyed.
    fn set_selection(&mut self, mut selection: Selection, fallback: bool) {
        selection.stats.survey_fallbacks = self
            .compact
            .evacuation
            .survey_fallbacks
            .saturating_add(u64::from(fallback));
        self.compact.evacuation = selection.stats;
        self.compact.selection = Some(selection);
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

    /// Reserve the batch's complete space plan like `prepare_commit`. A refusal
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
                maintenance: true,
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
        // The rewrite replaces the leaf's whole path; record it before any
        // effect. Relocated values need no record: their old locations share
        // the moved payloads and leave with their segment's reclamation.
        let publication = self.prepare_maintenance_publication(1)?;
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
        let untracked = self.pages.maintenance_private_view();
        let recording = publication
            .as_ref()
            .map(|publication| self.pages.recording_private_view(&publication.superseded));
        let private: &dyn DirectoryBackend = match &recording {
            Some(recording) => recording,
            None => &untracked,
        };
        let result = (|| {
            self.begin_maintenance_record(publication.as_ref(), fresh)?;
            let mut mutator = DirectoryMutator::new(private, &mut directory_workspace)?;
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
            // Drop the old path no root reaches before retaining the new one.
            self.reconcile_maintenance(publication)?;
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
        selection: &Selection,
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
                && selection.relocates(value.segment_id)
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
        // with nothing to relocate can be skipped without writing a root,
        // whatever kept segments its values are in. The arena cutoff stays a
        // prefix for this argument.
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
