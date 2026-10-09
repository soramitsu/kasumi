//! One bounded bottom-up packing pass over the selected directory.
//!
//! Continuations are logical keys, never paths retained across publications,
//! and every install persists the current level and continuation as a lower
//! bound. Foreground changes may leave an already visited range sparse again;
//! the pass does not restart for them, and the next cycle packs it. Each level
//! is capped at the selected entry count at its start plus 64 plans, so a
//! continuously changing tree cannot keep one level alive. Value evacuation
//! and its frozen file cutoffs are never repeated here.

use super::*;
use crate::directory::{DirectoryCursor, DirectoryPackPlan, MAX_HEIGHT};

const LEVEL_SLACK: u64 = 64;

#[derive(Default)]
pub(super) struct Density {
    level: u8,
    next: Option<DirectoryCursor>,
    steps_at_level: u64,
    level_cap: u64,
}

impl Density {
    pub(super) fn resume(level: u8, next: Option<DirectoryCursor>) -> Self {
        Self {
            level,
            next,
            steps_at_level: 0,
            level_cap: 0,
        }
    }

    /// The level and lower bound an install carries. A finished top level is
    /// persisted as the last representable level; repeating it is harmless.
    pub(super) fn persisted(&self) -> Result<(u8, CompactionCursor), CoreError> {
        Ok((
            self.level.min((MAX_HEIGHT - 1) as u8),
            match &self.next {
                Some(next) => CompactionCursor::lower_bound(next.key())?,
                None => CompactionCursor::NONE,
            },
        ))
    }

    fn next_level(&mut self) {
        self.level = self.level.saturating_add(1);
        self.next = None;
        self.steps_at_level = 0;
    }
}

impl DiskState {
    pub(super) fn pack_step(
        &mut self,
        budget: MaintenanceBudget,
        progress: &mut MaintenanceProgress,
    ) -> Result<bool, CoreError> {
        if self.compact.density.level >= self.selected.height {
            return self.finish_cycle(budget, progress);
        }
        let density = &mut self.compact.density;
        if density.steps_at_level == 0 {
            density.level_cap = self.selected.entries.saturating_add(LEVEL_SLACK);
        }
        if density.steps_at_level >= density.level_cap {
            density.next_level();
            self.compact.stats.density_truncated_levels += 1;
            progress.units += 1;
            return Ok(true);
        }
        let level = density.level;
        let lower = density
            .next
            .as_ref()
            .map_or(DirectoryKey::table("\0"), DirectoryCursor::key);
        // Packing must not fill or train the hot cache with a cold sweep.
        let plan = DirectoryReader::new(self.arena.as_ref(), self.owner.admission.clone())
            .pack_after(self.selected, level, lower)?;
        progress.units += 1;
        let Some(plan) = plan else {
            self.compact.density.next_level();
            return Ok(true);
        };
        if plan.references().1.is_some() {
            self.compact.stats.density_pairs += 1;
        }
        if plan.needs_pack() {
            if !can_mutate(budget, progress) {
                return Ok(false);
            }
            let cursor = match plan.next() {
                Some(next) => (level, CompactionCursor::lower_bound(next.key())?),
                None => (
                    level.saturating_add(1).min((MAX_HEIGHT - 1) as u8),
                    CompactionCursor::NONE,
                ),
            };
            self.maintain_pair(&plan, cursor)?;
            progress.mutations += 1;
            self.compact.stats.maintenance_commits += 1;
            self.compact.stats.density_commits += 1;
        }
        let density = &mut self.compact.density;
        density.steps_at_level += 1;
        // The plan admitted this cursor before any preparation. A merged
        // underfull page remains eligible for its next neighbor.
        density.next = plan.into_next();
        if density.next.is_none() {
            density.next_level();
        }
        Ok(true)
    }

    fn maintain_pair(
        &mut self,
        plan: &DirectoryPackPlan,
        cursor: (u8, CompactionCursor),
    ) -> Result<(), CoreError> {
        catch_unwind(AssertUnwindSafe(|| self.maintain_pair_inner(plan, cursor)))
            .unwrap_or_else(|panic| Err(CoreError::unknown_commit(CorePanic::new(panic))))
    }

    fn maintain_pair_inner(
        &mut self,
        plan: &DirectoryPackPlan,
        cursor: (u8, CompactionCursor),
    ) -> Result<(), CoreError> {
        let workspace = self
            .owner
            .admission
            .reserve_workspace(segment::maintenance_workspace_bytes() + LEASE_ALLOWANCE as u64)
            .map(NativeResidentLease::new)?;
        let mut directory_workspace =
            DirectoryWriteWorkspace::for_pack(self.owner.admission.clone())?;
        let witness = self.selection_witness();
        // Packing two neighbors is bounded like two edits of the selected tree.
        let space = self.reserve_maintenance_space(&[MaintenanceOp::DirectoryOnly], 2)?;
        let prepared = match self.writer.prepare_maintenance(
            self.owner.backend.as_ref(),
            &[MaintenanceOp::DirectoryOnly],
            &mut Roll(self.owner.clone()),
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
        let private = self.pages.maintenance_private_view();
        let result = (|| {
            let mut mutator = DirectoryMutator::new(&private, &mut directory_workspace)?;
            let root = mutator.pack_pair(self.selected, prepared.batch_seq(), plan)?;
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
        self.finish_maintenance(witness, prepared, root, workspace, &space, cursor)?;
        self.warm_maintenance_pages(root)
            .map_err(|error| error.into_unknown_commit())
    }
}
