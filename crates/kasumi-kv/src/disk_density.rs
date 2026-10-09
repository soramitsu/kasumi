//! One bounded bottom-up packing pass over the selected directory.
//!
//! Continuations are logical keys, never paths retained across publications,
//! and every step persists the current level and continuation as a lower
//! bound. Foreground changes may leave an already visited range sparse again;
//! the pass does not restart for them, and the next cycle packs it. Each level
//! durably caps its remaining work at the selected entry count at its start
//! plus 64 plans, so a
//! continuously changing tree or repeated reopen cannot keep one level alive. Value evacuation
//! and its frozen file cutoffs are never repeated here.

use super::*;
use crate::directory::{DirectoryCursor, DirectoryPackPlan};

const LEVEL_SLACK: u64 = 64;

#[derive(Default)]
pub(super) struct Density {
    level: u8,
    next: Option<DirectoryCursor>,
    remaining: u64,
}

impl Density {
    pub(super) fn resume(level: u8, next: Option<DirectoryCursor>, remaining: u64) -> Self {
        Self {
            level,
            next,
            remaining,
        }
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
        // Every successful step persists both its cursor and remaining work,
        // including verified skips. A truncated key can repeat after reopen,
        // but cannot reset this finite allowance or starve a later cycle.
        if !can_mutate(budget, progress) {
            return Ok(false);
        }
        let density = &self.compact.density;
        let level = density.level;
        let remaining = if density.remaining == 0 {
            self.selected.entries.saturating_add(LEVEL_SLACK)
        } else {
            density.remaining
        };
        let lower = density
            .next
            .as_ref()
            .map_or(DirectoryKey::table("\0"), DirectoryCursor::key);
        let plan = DirectoryReader::new(self.arena.as_ref(), self.owner.admission.clone())
            .pack_after(self.selected, level, lower)?;
        progress.units += 1;
        let truncated = remaining == 1 && plan.as_ref().is_some_and(|plan| plan.next().is_some());
        let next_level = plan.as_ref().is_none_or(|plan| plan.next().is_none()) || truncated;
        let cursor = if next_level {
            (level + 1, CompactionCursor::NONE, 0)
        } else {
            (
                level,
                CompactionCursor::lower_bound(plan.as_ref().unwrap().next().unwrap().key())?,
                remaining - 1,
            )
        };
        if let Some(plan) = &plan {
            if plan.references().1.is_some() {
                self.compact.stats.density_pairs += 1;
            }
            if plan.needs_pack() {
                self.maintain_pair(plan, cursor)?;
                self.compact.stats.maintenance_commits += 1;
                self.compact.stats.density_commits += 1;
            } else {
                self.publish_phase(|root| {
                    root.advance_packing_cursor(cursor.0, cursor.1, cursor.2)
                })?;
            }
        } else {
            self.publish_phase(|root| root.advance_packing_cursor(cursor.0, cursor.1, cursor.2))?;
        }
        progress.mutations += 1;
        if truncated {
            self.compact.stats.density_truncated_levels += 1;
        }
        self.compact.density = Density {
            level: cursor.0,
            next: if next_level {
                None
            } else {
                plan.and_then(DirectoryPackPlan::into_next)
            },
            remaining: cursor.2,
        };
        Ok(true)
    }

    fn maintain_pair(
        &mut self,
        plan: &DirectoryPackPlan,
        cursor: (u8, CompactionCursor, u64),
    ) -> Result<(), CoreError> {
        catch_unwind(AssertUnwindSafe(|| self.maintain_pair_inner(plan, cursor)))
            .unwrap_or_else(|panic| Err(CoreError::unknown_commit(CorePanic::new(panic))))
    }

    fn maintain_pair_inner(
        &mut self,
        plan: &DirectoryPackPlan,
        cursor: (u8, CompactionCursor, u64),
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
