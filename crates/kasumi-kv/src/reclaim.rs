//! Bounded reachability proofs for directory-backed file reclamation.
//!
//! Only this module creates production proofs. A proof covers one exact root
//! publication and a captured pin set, never just a caller assertion that a
//! file is unused. The state owner checks that capture again under its write
//! lock before publishing garbage. Reopen re-proves recorded garbage before
//! entering unlink; a checksum-valid garbage list is not a reachability proof.

use std::cell::Cell;
use std::sync::Arc;

use crate::core::{CoreError, ResidentLease, StorageAdmission};
use crate::directory::{DirectoryBackend, DirectoryWalker};
use crate::group::{GroupFile, SegmentGroupBackend};
use crate::root::{DirectoryCommit, MAX_GARBAGE, Superblock};
use crate::snapshot_pins::{SnapshotPins, SnapshotRoots};

/// Opaque evidence consumed by the root transition. Creating a value does not
/// make it available to the root: the private scanner releases these only
/// after visiting the selected tree and every captured pinned tree.
pub(crate) struct ReachabilityProof {
    commit: DirectoryCommit,
    publication_generation: u64,
    file: GroupFile,
}

impl ReachabilityProof {
    pub(crate) fn directory_commit(&self) -> DirectoryCommit {
        self.commit
    }
    pub(crate) fn publication_generation(&self) -> u64 {
        self.publication_generation
    }
    pub(crate) fn file(&self) -> GroupFile {
        self.file
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        commit: DirectoryCommit,
        publication_generation: u64,
        file: GroupFile,
    ) -> Self {
        Self {
            commit,
            publication_generation,
            file,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ReclaimCursor {
    next_segment: u64,
    next_arena: u64,
}

impl Default for ReclaimCursor {
    fn default() -> Self {
        Self {
            next_segment: 1,
            next_arena: 1,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanKind {
    Candidates,
    RecordedGarbage,
}

#[derive(Default, Debug)]
pub(crate) struct ReclaimProgress {
    /// Candidate probes, directory walker work, or one durable root/unlink
    /// transition. Each transition has a fixed bounded number of backend calls.
    pub(crate) work: usize,
    pub(crate) pages: usize,
    pub(crate) entries: usize,
    pub(crate) reclaimed: usize,
    pub(crate) complete: bool,
}

pub(crate) struct ReclaimScan {
    commit: DirectoryCommit,
    generation: u64,
    capture: SnapshotRoots,
    admission: Arc<dyn StorageAdmission>,
    candidates: Vec<ReachabilityProof>,
    referenced: u128,
    cursor: ReclaimCursor,
    arena_end: u64,
    root_arena: Option<u64>,
    kind: ScanKind,
    collecting: bool,
    root_index: usize,
    walker: Option<DirectoryWalker>,
    complete: bool,
    failed: bool,
    _lease: Box<dyn ResidentLease>,
}

pub(crate) struct ReclaimProofs {
    pub(crate) files: Vec<ReachabilityProof>,
    pub(crate) capture: SnapshotRoots,
    pub(crate) cursor: ReclaimCursor,
    pub(crate) cycle_complete: bool,
    _lease: Box<dyn ResidentLease>,
}

impl ReclaimScan {
    pub(crate) fn new(
        root: &Superblock,
        pins: &SnapshotPins,
        admission: Arc<dyn StorageAdmission>,
        cursor: ReclaimCursor,
        kind: ScanKind,
    ) -> Result<Self, CoreError> {
        admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        let commit = root.directory().ok_or(CoreError::InvalidInput(
            "reclamation needs a committed directory",
        ))?;
        let bytes = std::mem::size_of::<Self>()
            + MAX_GARBAGE * std::mem::size_of::<ReachabilityProof>()
            + 256;
        let lease = admission.reserve_workspace(bytes as u64)?;
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(MAX_GARBAGE)
            .map_err(|_| CoreError::CapacityDenied)?;
        if candidates.capacity() != MAX_GARBAGE {
            return Err(CoreError::CapacityDenied);
        }
        let capture = pins.capture()?;
        if kind == ScanKind::RecordedGarbage {
            for &file in root.garbage() {
                candidates.push(ReachabilityProof {
                    commit,
                    publication_generation: root.generation(),
                    file,
                });
            }
        }
        Ok(Self {
            commit,
            generation: root.generation(),
            capture,
            admission,
            candidates,
            referenced: 0,
            cursor,
            arena_end: root.last_directory_id(),
            root_arena: commit.root.page.map(|page| page.arena_id),
            kind,
            collecting: kind == ScanKind::Candidates,
            root_index: 0,
            walker: None,
            complete: false,
            failed: false,
            _lease: lease,
        })
    }

    pub(crate) fn matches(
        &self,
        root: &Superblock,
        pins: &SnapshotPins,
    ) -> Result<bool, CoreError> {
        if root.generation() != self.generation || root.directory() != Some(self.commit) {
            return Ok(false);
        }
        match pins.validate_coverage(&self.capture, self.commit.root) {
            Ok(()) => Ok(true),
            Err(CoreError::InvalidInput(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn exhausted(&self) -> bool {
        self.cursor.next_segment >= self.commit.start.position.segment_id
            && self.cursor.next_arena >= self.arena_end
    }

    pub(crate) fn step(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        directory: &dyn DirectoryBackend,
        work_limit: usize,
    ) -> Result<ReclaimProgress, CoreError> {
        if self.failed {
            return Err(CoreError::OwnerFailed);
        }
        let result = self.step_inner(backend, directory, work_limit);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn step_inner(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        directory: &dyn DirectoryBackend,
        work_limit: usize,
    ) -> Result<ReclaimProgress, CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        let mut progress = ReclaimProgress::default();
        while !self.complete && progress.work < work_limit {
            if self.collecting {
                if self.candidates.len() == MAX_GARBAGE || self.exhausted() {
                    self.collecting = false;
                    if self.candidates.is_empty() {
                        self.complete = true;
                    }
                    continue;
                }
                let file = if self.cursor.next_segment < self.commit.start.position.segment_id {
                    let id = self.cursor.next_segment;
                    self.cursor.next_segment += 1;
                    GroupFile::segment(id)
                } else {
                    let id = self.cursor.next_arena;
                    self.cursor.next_arena += 1;
                    GroupFile::directory(id)
                };
                progress.work += 1;
                if Some(file) == self.root_arena.map(GroupFile::directory) {
                    continue;
                }
                if backend.exists(file)? {
                    self.candidates.push(ReachabilityProof {
                        commit: self.commit,
                        publication_generation: self.generation,
                        file,
                    });
                }
                self.admission
                    .check_owner()
                    .map_err(|_| CoreError::OwnerFailed)?;
                continue;
            }
            if self.walker.is_none() {
                let next_root = if self.root_index == 0 {
                    Some(self.commit.root)
                } else {
                    self.capture.roots().get(self.root_index - 1).copied()
                };
                let Some(root) = next_root else {
                    self.complete = true;
                    continue;
                };
                if self.root_index != 0 && root == self.commit.root {
                    self.root_index += 1;
                    progress.work += 1;
                    continue;
                }
                self.walker = Some(DirectoryWalker::new(root, self.admission.clone())?);
            }
            let referenced = Cell::new(self.referenced);
            let mark = |file| -> Result<(), CoreError> {
                for (index, candidate) in self.candidates.iter().enumerate() {
                    if candidate.file == file {
                        if self.kind == ScanKind::RecordedGarbage {
                            return Err(CoreError::Corrupt(
                                "recorded garbage is reachable from a directory root",
                            ));
                        }
                        referenced.set(referenced.get() | (1u128 << index));
                    }
                }
                Ok(())
            };
            let result = self.walker.as_mut().expect("initialized walker").step(
                directory,
                work_limit - progress.work,
                |page| mark(GroupFile::directory(page.arena_id)),
                |value| mark(GroupFile::segment(value.segment_id)),
            );
            self.referenced = referenced.get();
            let walked = result?;
            progress.work += walked.work;
            progress.pages += walked.pages;
            progress.entries += walked.entries;
            if walked.complete {
                self.walker = None;
                self.root_index += 1;
                // Empty roots and completed cursors still consume bounded work.
                if walked.work == 0 {
                    progress.work += 1;
                }
            } else if walked.work == 0 {
                return Err(CoreError::Corrupt("directory walker made no progress"));
            }
        }
        progress.complete = self.complete;
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        Ok(progress)
    }

    pub(crate) fn finish(mut self) -> Result<ReclaimProofs, CoreError> {
        if !self.complete || self.failed {
            return Err(CoreError::InvalidInput("reclamation scan is incomplete"));
        }
        let mut index = 0;
        self.candidates.retain(|_| {
            let keep = self.referenced & (1u128 << index) == 0;
            index += 1;
            keep
        });
        let cycle_complete = self.exhausted();
        Ok(ReclaimProofs {
            files: self.candidates,
            capture: self.capture,
            cursor: self.cursor,
            cycle_complete,
            _lease: self._lease,
        })
    }
}
