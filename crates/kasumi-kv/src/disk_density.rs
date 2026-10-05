//! A bounded bottom-up packing pass over the current selected directory.
//!
//! Continuations are logical keys, never paths retained across publications.
//! Foreground changes may make an already visited range sparse again, so only
//! a pass without an intervening foreground publication establishes completion.
//! A retry preserves completed value evacuation and its frozen file cutoffs.

use super::*;
use crate::directory::{DirectoryCursor, DirectoryPackPlan};

#[derive(Default)]
pub(super) struct Density {
    level: u8,
    next: Option<DirectoryCursor>,
    expected_generation: Option<u64>,
    dirty: bool,
    complete: bool,
}

impl DiskState {
    pub(super) fn density_step(
        &mut self,
        progress: &mut CompactionProgress,
        work_limit: usize,
    ) -> Result<bool, CoreError> {
        let generation = self.selected.generation;
        let density = &mut self.compact.density;
        if density.expected_generation.is_none() && progress.work >= work_limit {
            return Ok(false);
        }
        if density
            .expected_generation
            .is_some_and(|old| old != generation)
        {
            if density.complete {
                *density = Density::default();
            } else {
                density.dirty = true;
            }
        }
        density.expected_generation = Some(generation);
        while progress.work < work_limit && !self.compact.density.complete {
            if self.compact.density.level >= self.selected.height {
                progress.work += 1;
                progress.density_passes += 1;
                if self.compact.density.dirty {
                    self.compact.density = Density {
                        expected_generation: Some(self.selected.generation),
                        ..Density::default()
                    };
                    progress.density_restarts += 1;
                    continue;
                }
                self.compact.density.complete = true;
                break;
            }
            let lower = self
                .compact
                .density
                .next
                .as_ref()
                .map_or(DirectoryKey::table("\0"), DirectoryCursor::key);
            // Packing must not fill or train the hot cache with a cold sweep.
            let plan = DirectoryReader::new(self.arena.as_ref(), self.owner.admission.clone())
                .pack_after(self.selected, self.compact.density.level, lower)?;
            progress.work += 1;
            if let Some(plan) = plan {
                if plan.references().1.is_some() {
                    progress.density_pairs += 1;
                }
                if plan.needs_pack() {
                    self.maintain_pair(&plan)?;
                    self.compact.density.expected_generation = Some(self.selected.generation);
                    progress.maintenance_commits += 1;
                    progress.density_commits += 1;
                }
                // The plan admitted this cursor before any preparation. A
                // merged underfull page remains eligible for its next neighbor.
                self.compact.density.next = plan.into_next();
            } else {
                self.compact.density.next = None;
            }
            if self.compact.density.next.is_none() {
                self.compact.density.level += 1;
            }
        }
        progress.density_complete = self.compact.density.complete;
        Ok(progress.density_complete)
    }

    fn maintain_pair(&mut self, plan: &DirectoryPackPlan) -> Result<(), CoreError> {
        catch_unwind(AssertUnwindSafe(|| self.maintain_pair_inner(plan)))
            .unwrap_or_else(|panic| Err(CoreError::unknown_commit(CorePanic::new(panic))))
    }

    fn maintain_pair_inner(&mut self, plan: &DirectoryPackPlan) -> Result<(), CoreError> {
        let workspace = self
            .owner
            .admission
            .reserve_workspace(segment::maintenance_workspace_bytes() + LEASE_ALLOWANCE as u64)
            .map(NativeResidentLease::new)?;
        let mut directory_workspace =
            DirectoryWriteWorkspace::for_pack(self.owner.admission.clone())?;
        let prepared = self.writer.prepare_maintenance(
            self.owner.backend.as_ref(),
            &[MaintenanceOp::DirectoryOnly],
            &mut Roll(self.owner.clone()),
        )?;
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
        self.warm_maintenance_pages(root)
            .map_err(|error| error.into_unknown_commit())
    }
}
