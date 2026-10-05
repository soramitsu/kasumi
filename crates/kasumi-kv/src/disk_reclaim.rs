//! Serialized reclamation owner for the disk state. Scans are incremental;
//! only a complete, still-current proof can enter the durable garbage protocol.

use super::*;
use crate::reclaim::{ReclaimCursor, ReclaimProgress, ReclaimScan, ScanKind};
use crate::root::publish_forget;
use crate::snapshot_pins::SnapshotRoots;

#[derive(Default)]
pub(super) struct Reclamation {
    generation: Option<u64>,
    pin_epoch: Option<u64>,
    cursor: ReclaimCursor,
    scan: Option<ReclaimScan>,
    authorized: Option<SnapshotRoots>,
    cycle_complete: bool,
}

impl DiskState {
    /// Each step probes candidate IDs or visits a bounded number of directory
    /// pages/entries. A completed scan publishes at most MAX_GARBAGE files in
    /// one root transition; each subsequent unit unlinks and forgets one file.
    /// Cache pruning is bounded by cache capacity; optional metadata shrinking
    /// reserves its temporary backing before allocation.
    pub(crate) fn reclaim_step(&mut self, work_limit: usize) -> Result<ReclaimProgress, CoreError> {
        let result = self.run(|state| state.reclaim_inner(work_limit));
        if result.is_err() {
            self.reclaim = Reclamation::default();
        }
        result
    }

    fn reclaim_inner(&mut self, work_limit: usize) -> Result<ReclaimProgress, CoreError> {
        let root = self.owner.lock()?.clone();
        let epoch = self.pins.epoch()?;
        if self.reclaim.generation != Some(root.generation())
            || (self.reclaim.cycle_complete
                && root.garbage().is_empty()
                && self.reclaim.pin_epoch != Some(epoch))
        {
            self.reclaim = Reclamation {
                generation: Some(root.generation()),
                pin_epoch: Some(epoch),
                ..Reclamation::default()
            };
        }
        let mut progress = ReclaimProgress::default();
        if work_limit == 0 {
            return Ok(progress);
        }
        if root.directory().is_none() {
            if !root.garbage().is_empty() {
                return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                    "directory garbage has no committed root",
                )));
            }
            progress.complete = true;
            return Ok(progress);
        }
        if self.reclaim.cycle_complete && root.garbage().is_empty() {
            progress.complete = true;
            return Ok(progress);
        }
        if let Some(capture) = &self.reclaim.authorized {
            self.pins.validate_coverage(capture, self.selected)?;
            while progress.work < work_limit {
                let mut current = self.owner.lock()?;
                let Some(&file) = current.garbage().first() else {
                    break;
                };
                let unlinked = current.unlink_garbage(self.owner.backend.as_ref(), file)?;
                let next = publish_forget(self.owner.backend.as_ref(), &current, unlinked)?;
                self.owner.check()?;
                self.reclaim.generation = Some(next.generation());
                *current = next;
                drop(current);
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
                progress.work += 1;
                progress.reclaimed += 1;
            }
            if self.owner.lock()?.garbage().is_empty() {
                self.reclaim.authorized = None;
                progress.complete = self.reclaim.cycle_complete;
            }
            return Ok(progress);
        }

        let kind = if root.garbage().is_empty() {
            ScanKind::Candidates
        } else {
            ScanKind::RecordedGarbage
        };
        if self.reclaim.scan.is_none() {
            self.reclaim.scan = Some(ReclaimScan::new(
                &root,
                &self.pins,
                self.owner.admission.clone(),
                self.reclaim.cursor,
                kind,
            )?);
        }
        let scan = self.reclaim.scan.as_mut().expect("initialized scan");
        if !scan.matches(&root, &self.pins)? {
            self.reclaim = Reclamation::default();
            return Ok(progress);
        }
        progress = scan.step(self.owner.backend.as_ref(), self.arena.as_ref(), work_limit)?;
        if !progress.complete || progress.work == work_limit {
            progress.complete = false;
            return Ok(progress);
        }
        let proved = self.reclaim.scan.take().expect("completed scan").finish()?;
        self.pins
            .validate_coverage(&proved.capture, self.selected)?;
        if kind == ScanKind::Candidates {
            if !proved.files.is_empty() {
                let mut current = self.owner.lock()?;
                let next = current.retire_directory_files(&proved.files)?;
                self.owner.publish(&mut current, next)?;
                self.reclaim.generation = Some(current.generation());
                self.reclaim.authorized = Some(proved.capture);
            }
            self.reclaim.cursor = proved.cursor;
            self.reclaim.cycle_complete = proved.cycle_complete;
        } else {
            self.reclaim.authorized = Some(proved.capture);
        }
        progress.work += 1;
        progress.complete = self.reclaim.cycle_complete && self.reclaim.authorized.is_none();
        Ok(progress)
    }

    /// Reopen can spend linear I/O on an interrupted garbage batch, but retains
    /// only the same bounded scan buffers. No recorded file is unlinked before
    /// every selected reference has been checked, including child arenas.
    pub(super) fn finish_recorded_garbage(&mut self) -> Result<(), CoreError> {
        while !self.owner.lock()?.garbage().is_empty() {
            self.reclaim_step(256)?;
        }
        Ok(())
    }
}
