//! Reclamation inside the Reclaiming phase, as sequential certified cohorts.
//!
//! A cycle freezes its exclusive limits `L` from the persisted cutoffs and the
//! current replay start, measures retained files, then walks candidate
//! identifiers from the reclaim floor to `L` in cohorts of at most
//! `MAX_GARBAGE` present files. Nothing resets on a root generation change:
//! every directory install between cohort start and its seal is certified by
//! the selection funnel (`DiskState::install_selected`), which advances the
//! cohort's chain and the pin registry's stamped root. See `reclaim.rs` for
//! why a sealed proof covers the current root and every live pin.
//!
//! Safety summary:
//! - New pages land in arenas `>= last_directory_id` at cycle begin, which is
//!   above `cutoff_arena`; new values land in segments `>= last_segment_id`
//!   at begin, above `cutoff_segment`. The funnel re-checks both per install.
//! - Builders copy existing references only from the selected root, so the
//!   old files of every chain root are a subset of R0's old files.
//! - Pins taken during a cohort sit at chain roots and carry its stamp;
//!   earlier pins were captured and walked.
//! - R0 and the captured roots stay readable through the drain because
//!   reclamation is the only unlinker and cohorts are sequential.
//! - `L.segment` never exceeds the replay start and the structural guards of
//!   `root_directory.rs` still apply to every retirement.
//! - A cohort is invalidated (never rebound) when any condition fails; files
//!   already recorded are then re-proved by a `RecordedGarbage` cohort, and
//!   reopen re-proves recorded garbage before unlinking any of it.

use super::maintenance::{
    Census, FileFloor, MaintenanceBudget, MaintenanceProgress, Measurement, can_mutate,
};
use super::*;
use crate::reclaim::{Cohort, CohortKind, CohortStage, ReclaimCursor, ReclaimLimits, Seal};
use crate::root::CompactionRecord;

/// Process-lifetime reclamation counters, reported by the status.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ReclaimTotals {
    pub(super) reclaimed_files: u64,
    pub(super) reclaimed_bytes: u64,
    pub(super) invalidations: u64,
    /// Of the last completed cycle: old files kept only for pinned roots.
    pub(super) pin_retained_files: u64,
    pub(super) pin_retained_bytes: u64,
}

#[derive(Default)]
pub(super) struct Reclamation {
    pub(super) floor: FileFloor,
    next_nonce: u64,
    cycle: Option<ReclaimCycle>,
    pub(super) totals: ReclaimTotals,
}

struct ReclaimCycle {
    limits: ReclaimLimits,
    cursor: ReclaimCursor,
    census: Option<Census>,
    measurement: Option<Measurement>,
    reclaimed_files: u64,
    reclaimed_bytes: u64,
    pin_retained_files: u64,
    pin_retained_bytes: u64,
    lowest_segment: Option<u64>,
    lowest_arena: Option<u64>,
    cohort: Option<Cohort>,
}

enum CohortAction {
    Continue,
    Stop,
    Finished,
    Invalidated,
}

fn lowest(slot: &mut Option<u64>, id: Option<u64>) {
    if let Some(id) = id {
        *slot = Some(slot.map_or(id, |current| current.min(id)));
    }
}

impl Reclamation {
    /// The limits a selection witness checks while a cohort is active.
    pub(super) fn active_limits(&self) -> Option<ReclaimLimits> {
        self.cycle.as_ref()?.cohort.as_ref().map(Cohort::limits)
    }

    fn active_cohort(&mut self) -> Option<&mut Cohort> {
        self.cycle.as_mut()?.cohort.as_mut()
    }

    fn next_nonce(&self) -> Result<u64, CoreError> {
        // Exhaustion fails closed: no cohort starts and the step defers.
        self.next_nonce
            .checked_add(1)
            .ok_or(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "reclamation nonce is exhausted",
            )))
    }
}

#[cfg(test)]
impl Reclamation {
    /// Observation hooks for the reclamation tests only.
    pub(super) fn cycle_cursor_for_test(&self) -> Option<(u64, u64)> {
        self.cycle
            .as_ref()
            .map(|cycle| (cycle.cursor.next_segment, cycle.cursor.next_arena))
    }
    pub(super) fn cohort_stage_for_test(&self) -> Option<CohortStage> {
        self.cycle.as_ref()?.cohort.as_ref().map(Cohort::stage)
    }
    /// Fault hook: the next cohort would need a nonce past `u64::MAX`.
    pub(super) fn exhaust_nonces_for_test(&mut self) {
        self.next_nonce = u64::MAX;
    }
    /// Fault hook: as if an install bypassed the selection funnel.
    pub(super) fn break_chain_for_test(&mut self) {
        self.active_cohort()
            .expect("active cohort")
            .chain_mut()
            .break_chain();
    }
}

impl DiskState {
    /// Record one certified installation in the active cohort. Called by the
    /// selection funnel with the commit the owner replaced.
    pub(super) fn observe_install(
        &mut self,
        previous: Option<DirectoryCommit>,
        commit: DirectoryCommit,
    ) -> Result<(), CoreError> {
        let Some(cohort) = self.reclaim.active_cohort() else {
            return Ok(());
        };
        cohort.chain_mut().advance(previous, commit);
        let nonce = cohort.nonce();
        match self.pins.advance_coverage(nonce, commit.root) {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error.rejected_cause(),
                    Some(crate::CoreErrorCause::InvalidInput(_))
                ) =>
            {
                if let Some(cohort) = self.reclaim.active_cohort() {
                    cohort.chain_mut().break_chain();
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Invalidate the active cohort before an uncertified installation.
    pub(super) fn invalidate_for_install(&mut self) -> Result<(), CoreError> {
        if let Some(cohort) = self.reclaim.active_cohort() {
            cohort.chain_mut().break_chain();
            let nonce = cohort.nonce();
            self.pins.end_coverage(nonce)?;
        }
        Ok(())
    }

    /// A local deferral ends an unrecorded cohort and keeps every cursor. A
    /// draining cohort keeps its coverage and resumes after the backoff.
    pub(super) fn local_reclaim_failure(&mut self) -> Result<(), CoreError> {
        let Some(cycle) = self.reclaim.cycle.as_mut() else {
            return Ok(());
        };
        if cycle
            .cohort
            .as_ref()
            .is_some_and(|cohort| cohort.stage() != CohortStage::Draining)
        {
            let cohort = cycle.cohort.take().expect("checked cohort");
            self.pins.end_coverage(cohort.nonce())?;
        }
        Ok(())
    }

    fn start_reclaim_cycle(&mut self, record: &CompactionRecord) -> Result<(), CoreError> {
        let root = self.owner.lock()?;
        let commit = root
            .directory()
            .ok_or(CoreError::new(crate::CoreErrorCause::Corrupt(
                "reclaiming root has no directory",
            )))?;
        let limits = ReclaimLimits {
            segment: record
                .cutoff_segment()
                .saturating_add(1)
                .min(commit.start.position.segment_id),
            arena: record.cutoff_arena().saturating_add(1),
        };
        let floor = self.reclaim.floor;
        let census = Census::start(floor, &root);
        drop(root);
        self.reclaim.cycle = Some(ReclaimCycle {
            limits,
            cursor: ReclaimCursor {
                next_segment: floor.segment,
                next_arena: floor.arena,
            },
            census: Some(census),
            measurement: None,
            reclaimed_files: 0,
            reclaimed_bytes: 0,
            pin_retained_files: 0,
            pin_retained_bytes: 0,
            lowest_segment: None,
            lowest_arena: None,
            cohort: None,
        });
        Ok(())
    }

    /// One bounded Reclaiming item. Completion publishes Reclaiming ->
    /// Packing with the measured baseline.
    pub(super) fn reclaiming_step(
        &mut self,
        record: &CompactionRecord,
        budget: MaintenanceBudget,
        progress: &mut MaintenanceProgress,
    ) -> Result<bool, CoreError> {
        if self.reclaim.cycle.is_none() {
            self.start_reclaim_cycle(record)?;
        }
        let cycle = self.reclaim.cycle.as_mut().expect("started cycle");
        if cycle.measurement.is_none() {
            let census = cycle.census.as_mut().expect("cycle census");
            let (used, measured) =
                census.step(self.owner.backend.as_ref(), budget.units - progress.units)?;
            progress.units += used;
            self.compact.stats.census_probes += used;
            if let Some(measurement) = measured {
                cycle.measurement = Some(measurement);
                cycle.census = None;
            }
            return Ok(used != 0 || measured.is_some());
        }
        if cycle.cohort.is_none() {
            let (cursor, limits) = (cycle.cursor, cycle.limits);
            let root = self.owner.lock()?;
            let recorded = !root.garbage().is_empty();
            if !recorded && cursor.exhausted(limits) {
                drop(root);
                return self.complete_reclaim_cycle(budget, progress);
            }
            let nonce = self.reclaim.next_nonce()?;
            let kind = if recorded {
                CohortKind::RecordedGarbage
            } else {
                CohortKind::Candidates
            };
            let cohort = Cohort::new(
                kind,
                &root,
                &self.pins,
                self.owner.admission.clone(),
                nonce,
                cursor,
                limits,
            )?;
            drop(root);
            self.pins.begin_coverage(nonce, self.selected)?;
            self.reclaim.next_nonce = nonce;
            self.reclaim.cycle.as_mut().expect("started cycle").cohort = Some(cohort);
            return Ok(true);
        }
        let mut cohort = cycle.cohort.take().expect("checked cohort");
        let result = self.cohort_step(&mut cohort, budget, progress);
        let cycle = self.reclaim.cycle.as_mut().expect("started cycle");
        match result {
            Ok(CohortAction::Continue) => {
                cycle.cohort = Some(cohort);
                Ok(true)
            }
            Ok(CohortAction::Stop) => {
                cycle.cohort = Some(cohort);
                Ok(false)
            }
            Ok(CohortAction::Finished) => {
                if cohort.kind() == CohortKind::Candidates {
                    let survivors = cohort.survivors();
                    cycle.cursor = cohort.cursor();
                    cycle.pin_retained_files += survivors.pin_retained_files;
                    cycle.pin_retained_bytes += survivors.pin_retained_bytes;
                    lowest(&mut cycle.lowest_segment, survivors.lowest_segment);
                    lowest(&mut cycle.lowest_arena, survivors.lowest_arena);
                }
                self.pins.end_coverage(cohort.nonce())?;
                Ok(true)
            }
            Ok(CohortAction::Invalidated) => {
                self.reclaim.totals.invalidations += 1;
                self.pins.end_coverage(cohort.nonce())?;
                Ok(true)
            }
            Err(error) => {
                // Keep it for the error boundary: local failures end its
                // coverage there unless it is draining recorded garbage.
                cycle.cohort = Some(cohort);
                Err(error)
            }
        }
    }

    fn cohort_step(
        &mut self,
        cohort: &mut Cohort,
        budget: MaintenanceBudget,
        progress: &mut MaintenanceProgress,
    ) -> Result<CohortAction, CoreError> {
        if cohort.chain_broken() {
            return Ok(CohortAction::Invalidated);
        }
        match cohort.stage() {
            CohortStage::Collecting | CohortStage::Walking => {
                let mut garbage = [GroupFile::segment(0); MAX_GARBAGE];
                let recorded = {
                    let root = self.owner.lock()?;
                    let recorded = root.garbage().len().min(MAX_GARBAGE);
                    garbage[..recorded].copy_from_slice(&root.garbage()[..recorded]);
                    recorded
                };
                let stage = cohort.stage();
                let used = cohort.step(
                    self.owner.backend.as_ref(),
                    self.arena.as_ref(),
                    &garbage[..recorded],
                    budget.units - progress.units,
                )?;
                progress.units += used;
                Ok(if used != 0 || cohort.stage() != stage {
                    CohortAction::Continue
                } else {
                    CohortAction::Stop
                })
            }
            CohortStage::Walked => {
                if !cohort.has_unreferenced() {
                    // Every candidate is still referenced: the range is done.
                    progress.units += 1;
                    return Ok(CohortAction::Finished);
                }
                if !can_mutate(budget, progress) {
                    return Ok(CohortAction::Stop);
                }
                progress.units += 1;
                let mut current = self.owner.lock()?;
                if let Seal::Invalidated(_) = cohort.seal(&self.pins, &current, self.selected)? {
                    return Ok(CohortAction::Invalidated);
                }
                if cohort.kind() == CohortKind::Candidates {
                    let proofs = cohort.mint_proofs(&self.pins, &current, self.selected)?;
                    if proofs.is_empty() {
                        return Ok(CohortAction::Finished);
                    }
                    let next = current.retire_directory_files(proofs)?;
                    self.owner.publish(&mut current, next)?;
                    progress.mutations += 1;
                }
                cohort.begin_drain();
                Ok(CohortAction::Continue)
            }
            CohortStage::Draining => {
                if !can_mutate(budget, progress) {
                    return Ok(CohortAction::Stop);
                }
                progress.units += 1;
                let (file, len) = {
                    let mut current = self.owner.lock()?;
                    let Some(&file) = current.garbage().first() else {
                        return Ok(CohortAction::Finished);
                    };
                    if let Seal::Invalidated(_) =
                        cohort.seal(&self.pins, &current, self.selected)?
                    {
                        return Ok(CohortAction::Invalidated);
                    }
                    // Only files this cohort proved are unlinked; anything
                    // else on the list is re-proved by a new cohort.
                    let Some(len) = cohort.proved_len(file) else {
                        return Ok(CohortAction::Invalidated);
                    };
                    let unlinked = current.unlink_garbage(self.owner.backend.as_ref(), file)?;
                    self.owner.forget(&mut current, unlinked)?;
                    (file, len)
                };
                progress.mutations += 1;
                progress.reclaimed_files += 1;
                progress.reclaimed_bytes += len;
                let totals = &mut self.reclaim.totals;
                totals.reclaimed_files = totals.reclaimed_files.saturating_add(1);
                totals.reclaimed_bytes = totals.reclaimed_bytes.saturating_add(len);
                if let Some(cycle) = self.reclaim.cycle.as_mut() {
                    cycle.reclaimed_files += 1;
                    cycle.reclaimed_bytes = cycle.reclaimed_bytes.saturating_add(len);
                }
                self.prune_reclaimed(file)?;
                Ok(CohortAction::Continue)
            }
        }
    }

    fn complete_reclaim_cycle(
        &mut self,
        budget: MaintenanceBudget,
        progress: &mut MaintenanceProgress,
    ) -> Result<bool, CoreError> {
        if !can_mutate(budget, progress) {
            return Ok(false);
        }
        let cycle = self.reclaim.cycle.as_ref().expect("completed cycle");
        let measurement = cycle.measurement.expect("measured cycle");
        let baseline_bytes = measurement.bytes().saturating_sub(cycle.reclaimed_bytes);
        let baseline_files = measurement.files().saturating_sub(cycle.reclaimed_files);
        self.publish_phase(|root| root.advance_to_packing(baseline_bytes, baseline_files))?;
        let cycle = self.reclaim.cycle.take().expect("completed cycle");
        let floor = &mut self.reclaim.floor;
        floor.segment = floor.segment.max(
            cycle
                .lowest_segment
                .map_or(cycle.limits.segment, |id| id.min(cycle.limits.segment)),
        );
        floor.arena = floor.arena.max(
            cycle
                .lowest_arena
                .map_or(cycle.limits.arena, |id| id.min(cycle.limits.arena)),
        );
        self.reclaim.totals.pin_retained_files = cycle.pin_retained_files;
        self.reclaim.totals.pin_retained_bytes = cycle.pin_retained_bytes;
        self.start_packing();
        progress.units += 1;
        progress.mutations += 1;
        progress.phase_changed = true;
        Ok(true)
    }

    /// An unlinked file's identities can never be served again.
    fn prune_reclaimed(&self, file: GroupFile) -> Result<(), CoreError> {
        let group = self.owner.group_id;
        self.cache
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
            .remove_matching(|key| match key {
                NativeIdentity::Page {
                    group_id, arena_id, ..
                } => group_id == group && file == GroupFile::directory(arena_id),
                NativeIdentity::Value {
                    group_id,
                    segment_id,
                    ..
                } => group_id == group && file == GroupFile::segment(segment_id),
            })?;
        Ok(())
    }

    /// Reopen re-proves an interrupted garbage batch before unlinking any of
    /// it: every selected reference is walked, including child arenas, and
    /// reachable recorded garbage fails closed as corruption. No pins or
    /// foreground installs exist yet, so the cohort cannot be invalidated.
    pub(super) fn finish_recorded_garbage(&mut self) -> Result<(), CoreError> {
        self.run(|state| {
            while !state.owner.lock()?.garbage().is_empty() {
                state.reclaim_recorded_garbage()?;
            }
            Ok(())
        })
    }

    fn reclaim_recorded_garbage(&mut self) -> Result<(), CoreError> {
        let nonce = self.reclaim.next_nonce()?;
        let mut cohort = {
            let root = self.owner.lock()?;
            Cohort::new(
                CohortKind::RecordedGarbage,
                &root,
                &self.pins,
                self.owner.admission.clone(),
                nonce,
                ReclaimCursor {
                    next_segment: 0,
                    next_arena: 0,
                },
                ReclaimLimits {
                    segment: 0,
                    arena: 0,
                },
            )?
        };
        self.pins.begin_coverage(nonce, self.selected)?;
        self.reclaim.next_nonce = nonce;
        let unbounded = MaintenanceBudget {
            units: usize::MAX,
            mutations: usize::MAX,
        };
        let result = (|| {
            loop {
                let mut progress = MaintenanceProgress::default();
                match self.cohort_step(&mut cohort, unbounded, &mut progress)? {
                    CohortAction::Continue => {}
                    CohortAction::Finished => return Ok(()),
                    CohortAction::Stop | CohortAction::Invalidated => {
                        return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                            "recorded garbage proof failed at reopen",
                        )));
                    }
                }
            }
        })();
        self.pins.end_coverage(nonce)?;
        result
    }
}
