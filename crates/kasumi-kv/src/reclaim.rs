//! Bounded reachability proofs for directory-backed file reclamation.
//!
//! Only this module creates production proofs. A cohort collects at most
//! `MAX_GARBAGE` present candidates below the cycle's frozen limits, walks the
//! directory commit it started from (`R0`) and every root pinned at that
//! moment, and is then sealed under the owner lock. Sealing requires that every
//! later root installation was certified (an unbroken chain whose newest
//! commit is the selected one) and that every live pin is at the current root,
//! at a walked root, or stamped by this cohort's nonce.
//!
//! Why a sealed proof still holds for the current root: during a cohort every
//! builder copies existing references only from the selected root, and every
//! new page or value lands in a file at or above the limits. So the old files
//! referenced by each certified root are a subset of those referenced by R0.
//! A candidate R0 does not reference is referenced by no chain root, and pins
//! taken during the cohort sit at chain roots. Earlier pins were walked. The
//! walked roots stay readable because reclamation is the only unlinker and
//! cohorts are sequential. Reopen re-proves recorded garbage before unlinking
//! it; a checksum-valid garbage list is not a reachability proof.

use crate::core::NativeResidentLease;
use std::cell::Cell;
use std::sync::Arc;

use crate::core::{CoreError, StorageAdmission};
use crate::directory::{DirectoryBackend, DirectoryWalker};
use crate::group::{FileKind, GroupFile, SegmentGroupBackend};
use crate::root::{DirectoryCommit, MAX_GARBAGE, Superblock};
use crate::snapshot_pins::{SnapshotPins, SnapshotRoots};

/// Walker work items charged as one maintenance unit.
pub(crate) const WALK_WORK_PER_UNIT: usize = 256;

/// Opaque evidence consumed by the root transition. Creating a value does not
/// make it available to the root: a sealed cohort mints these only after
/// visiting R0 and every captured pinned tree, bound to the exact current
/// commit and publication generation it then retires against.
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

/// Exclusive identifier limits frozen when a reclamation cycle starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReclaimLimits {
    pub(crate) segment: u64,
    pub(crate) arena: u64,
}

/// The next candidate identifier of each kind; segments are probed first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReclaimCursor {
    pub(crate) next_segment: u64,
    pub(crate) next_arena: u64,
}

impl ReclaimCursor {
    pub(crate) fn exhausted(&self, limits: ReclaimLimits) -> bool {
        self.next_segment >= limits.segment && self.next_arena >= limits.arena
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CohortKind {
    /// Probe present files below the limits from the cycle cursor.
    Candidates,
    /// Re-prove the root's recorded garbage list before unlinking it.
    RecordedGarbage,
}

/// The certified succession of directory commits since R0.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CoverageChain {
    r0: DirectoryCommit,
    latest: DirectoryCommit,
    broken: bool,
}

impl CoverageChain {
    fn new(r0: DirectoryCommit) -> Self {
        Self {
            r0,
            latest: r0,
            broken: false,
        }
    }

    /// Record one installation. A predecessor other than the newest
    /// certified commit breaks the chain permanently.
    pub(crate) fn advance(&mut self, previous: Option<DirectoryCommit>, next: DirectoryCommit) {
        if previous != Some(self.latest) {
            self.broken = true;
        }
        self.latest = next;
    }

    pub(crate) fn break_chain(&mut self) {
        self.broken = true;
    }
}

#[derive(Clone, Copy, Debug)]
struct Candidate {
    file: GroupFile,
    len: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CohortStage {
    Collecting,
    Walking,
    /// The walk is complete; the cohort waits for its seal under the lock.
    Walked,
    /// Its proven files are recorded garbage awaiting unlink and forget.
    Draining,
}

/// Outcome of checking the seal conditions under the owner lock.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Seal {
    Proved,
    Invalidated(&'static str),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CohortSurvivors {
    pub(crate) pin_retained_files: u64,
    pub(crate) pin_retained_bytes: u64,
    pub(crate) lowest_segment: Option<u64>,
    pub(crate) lowest_arena: Option<u64>,
}

pub(crate) struct Cohort {
    kind: CohortKind,
    capture: SnapshotRoots,
    nonce: u64,
    chain: CoverageChain,
    limits: ReclaimLimits,
    cursor: ReclaimCursor,
    admission: Arc<dyn StorageAdmission>,
    candidates: Vec<Candidate>,
    proofs: Vec<ReachabilityProof>,
    recorded: usize,
    /// R0's root-page arena, skipped by collection but never below the floor.
    skipped_root_arena: Option<u64>,
    referenced_current: u128,
    referenced_pinned: u128,
    root_index: usize,
    walker: Option<DirectoryWalker>,
    stage: CohortStage,
    failed: bool,
    _lease: NativeResidentLease,
}

impl Cohort {
    /// Admit every buffer and capture the pinned roots. The caller registers
    /// `nonce` with the pin registry only after this succeeds.
    pub(crate) fn new(
        kind: CohortKind,
        root: &Superblock,
        pins: &SnapshotPins,
        admission: Arc<dyn StorageAdmission>,
        nonce: u64,
        cursor: ReclaimCursor,
        limits: ReclaimLimits,
    ) -> Result<Self, CoreError> {
        admission
            .check_owner()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?;
        let r0 = root
            .directory()
            .ok_or(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "reclamation needs a committed directory",
            )))?;
        if (kind == CohortKind::Candidates) != root.garbage().is_empty() {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "reclamation cohort kind differs from the garbage list",
            )));
        }
        let bytes = std::mem::size_of::<Self>()
            + MAX_GARBAGE
                * (std::mem::size_of::<Candidate>() + std::mem::size_of::<ReachabilityProof>())
            + 256;
        let lease = admission
            .reserve_workspace(bytes as u64)
            .map(NativeResidentLease::new)?;
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(MAX_GARBAGE)
            .map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        let mut proofs = Vec::new();
        proofs
            .try_reserve_exact(MAX_GARBAGE)
            .map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        if candidates.capacity() != MAX_GARBAGE || proofs.capacity() != MAX_GARBAGE {
            return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
        }
        let capture = pins.capture()?;
        Ok(Self {
            kind,
            capture,
            nonce,
            chain: CoverageChain::new(r0),
            limits,
            cursor,
            admission,
            candidates,
            proofs,
            recorded: 0,
            skipped_root_arena: None,
            referenced_current: 0,
            referenced_pinned: 0,
            root_index: 0,
            walker: None,
            stage: CohortStage::Collecting,
            failed: false,
            _lease: lease,
        })
    }

    pub(crate) fn kind(&self) -> CohortKind {
        self.kind
    }
    pub(crate) fn nonce(&self) -> u64 {
        self.nonce
    }
    pub(crate) fn stage(&self) -> CohortStage {
        self.stage
    }
    pub(crate) fn chain_broken(&self) -> bool {
        self.chain.broken
    }
    pub(crate) fn chain_mut(&mut self) -> &mut CoverageChain {
        &mut self.chain
    }
    pub(crate) fn limits(&self) -> ReclaimLimits {
        self.limits
    }
    /// The candidate cursor after this cohort's collection.
    pub(crate) fn cursor(&self) -> ReclaimCursor {
        self.cursor
    }

    fn check_owner(&self) -> Result<(), CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))
    }

    /// Collect or walk within `units`; returns the units charged. Any error
    /// poisons this cohort, which the caller then drops.
    pub(crate) fn step(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        directory: &dyn DirectoryBackend,
        garbage: &[GroupFile],
        units: usize,
    ) -> Result<usize, CoreError> {
        if self.failed {
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        let result = match self.stage {
            CohortStage::Collecting => self.collect(backend, garbage, units),
            CohortStage::Walking => self.walk(directory, units),
            CohortStage::Walked | CohortStage::Draining => Ok(0),
        };
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn collect(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        garbage: &[GroupFile],
        units: usize,
    ) -> Result<usize, CoreError> {
        self.check_owner()?;
        let root_arena = self.chain.r0.root.page.map(|page| page.arena_id);
        let mut used = 0;
        while used < units {
            let file = match self.kind {
                CohortKind::RecordedGarbage => {
                    let Some(&file) = garbage.get(self.recorded) else {
                        self.stage = CohortStage::Walking;
                        break;
                    };
                    if garbage.len() > MAX_GARBAGE || self.candidates.len() == MAX_GARBAGE {
                        return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                            "recorded garbage exceeds its bound",
                        )));
                    }
                    self.recorded += 1;
                    file
                }
                CohortKind::Candidates => {
                    if self.candidates.len() == MAX_GARBAGE || self.cursor.exhausted(self.limits) {
                        self.stage = CohortStage::Walking;
                        break;
                    }
                    if self.cursor.next_segment < self.limits.segment {
                        let id = self.cursor.next_segment;
                        self.cursor.next_segment += 1;
                        GroupFile::segment(id)
                    } else {
                        let id = self.cursor.next_arena;
                        self.cursor.next_arena += 1;
                        GroupFile::directory(id)
                    }
                }
            };
            used += 1;
            if self.kind == CohortKind::Candidates
                && Some(file) == root_arena.map(GroupFile::directory)
            {
                // R0 references its own root page; it survives this cohort.
                self.skipped_root_arena = Some(file.id);
                continue;
            }
            // Recorded garbage may already be unlinked whose forget was lost;
            // it is still re-proved and its record still needs the proof.
            let len = if backend.exists(file)? {
                backend.len(file)?
            } else if self.kind == CohortKind::RecordedGarbage {
                0
            } else {
                self.check_owner()?;
                continue;
            };
            self.candidates.push(Candidate { file, len });
            self.check_owner()?;
        }
        self.check_owner()?;
        Ok(used)
    }

    fn walk(&mut self, directory: &dyn DirectoryBackend, units: usize) -> Result<usize, CoreError> {
        self.check_owner()?;
        let mut used = 0;
        while used < units {
            if self.candidates.is_empty() {
                self.stage = CohortStage::Walked;
                break;
            }
            if self.walker.is_none() {
                let next_root = if self.root_index == 0 {
                    Some(self.chain.r0.root)
                } else {
                    self.capture.roots().get(self.root_index - 1).copied()
                };
                let Some(root) = next_root else {
                    self.stage = CohortStage::Walked;
                    break;
                };
                if self.root_index != 0 && root == self.chain.r0.root {
                    self.root_index += 1;
                    continue;
                }
                self.walker = Some(DirectoryWalker::new(root, self.admission.clone())?);
            }
            let current = self.root_index == 0;
            let kind = self.kind;
            let candidates = &self.candidates;
            let marks = Cell::new(0u128);
            let mark = |file: GroupFile| -> Result<(), CoreError> {
                for (index, candidate) in candidates.iter().enumerate() {
                    if candidate.file == file {
                        if kind == CohortKind::RecordedGarbage {
                            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                                "recorded garbage is reachable from a directory root",
                            )));
                        }
                        marks.set(marks.get() | (1u128 << index));
                    }
                }
                Ok(())
            };
            let budget = (units - used).saturating_mul(WALK_WORK_PER_UNIT);
            let result = self.walker.as_mut().expect("initialized walker").step(
                directory,
                budget,
                |page| mark(GroupFile::directory(page.arena_id)),
                |value| mark(GroupFile::segment(value.segment_id)),
            );
            if current {
                self.referenced_current |= marks.get();
            } else {
                self.referenced_pinned |= marks.get();
            }
            let walked = result?;
            used += walked.work.div_ceil(WALK_WORK_PER_UNIT).max(1);
            if walked.complete {
                self.walker = None;
                self.root_index += 1;
            } else if walked.work == 0 {
                return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                    "directory walker made no progress",
                )));
            }
        }
        self.check_owner()?;
        Ok(used.min(units))
    }

    /// Candidates no walked root references; with no such file nothing needs
    /// a seal and the collected range is complete.
    pub(crate) fn has_unreferenced(&self) -> bool {
        let referenced = self.referenced_current | self.referenced_pinned;
        (0..self.candidates.len()).any(|index| referenced & (1u128 << index) == 0)
    }

    /// Check the seal conditions under the owner lock that selected
    /// `current` and `selected`. Allocates nothing.
    pub(crate) fn seal(
        &self,
        pins: &SnapshotPins,
        current: &Superblock,
        selected: crate::directory::DirectoryRoot,
    ) -> Result<Seal, CoreError> {
        if self.failed || !matches!(self.stage, CohortStage::Walked | CohortStage::Draining) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "reclamation cohort is not walked",
            )));
        }
        if self.chain.broken {
            return Ok(Seal::Invalidated("uncertified root installation"));
        }
        if current.directory() != Some(self.chain.latest) {
            return Ok(Seal::Invalidated(
                "directory changed outside the certified chain",
            ));
        }
        if self.chain.latest.root != selected {
            return Ok(Seal::Invalidated(
                "selected root differs from the certified chain",
            ));
        }
        match pins.validate_cohort_coverage(&self.capture, self.nonce, selected) {
            Ok(()) => Ok(Seal::Proved),
            Err(error) => match error.rejected_cause() {
                Some(crate::CoreErrorCause::InvalidInput(reason)) => Ok(Seal::Invalidated(reason)),
                _ => Err(error),
            },
        }
    }

    /// Mint proofs for every unreferenced, structurally retirable candidate,
    /// bound to `current`. Only a cohort whose seal was just proved under the
    /// same owner lock may call this; the result is a consequence of that
    /// proof, never a general way to rebind an older proof.
    pub(crate) fn mint_proofs(
        &mut self,
        pins: &SnapshotPins,
        current: &Superblock,
        selected: crate::directory::DirectoryRoot,
    ) -> Result<&[ReachabilityProof], CoreError> {
        if self.kind != CohortKind::Candidates
            || self.seal(pins, current, selected)? != Seal::Proved
        {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "reclamation cohort is not sealed",
            )));
        }
        let commit =
            current
                .directory()
                .ok_or(CoreError::new(crate::CoreErrorCause::InvalidInput(
                    "reclamation needs a committed directory",
                )))?;
        let referenced = self.referenced_current | self.referenced_pinned;
        self.proofs.clear();
        for (index, candidate) in self.candidates.iter().enumerate() {
            if referenced & (1u128 << index) == 0 && current.file_is_retirable(candidate.file) {
                self.proofs.push(ReachabilityProof {
                    commit,
                    publication_generation: current.generation(),
                    file: candidate.file,
                });
            }
        }
        Ok(&self.proofs)
    }

    /// After the retirement publication, only the minted files are drained.
    pub(crate) fn begin_drain(&mut self) {
        self.stage = CohortStage::Draining;
    }

    /// Whether this cohort proved `file` unreachable (and so may drain it).
    pub(crate) fn proved_len(&self, file: GroupFile) -> Option<u64> {
        let index = self
            .candidates
            .iter()
            .position(|candidate| candidate.file == file)?;
        let referenced = self.referenced_current | self.referenced_pinned;
        if referenced & (1u128 << index) != 0 {
            return None;
        }
        if self.kind == CohortKind::Candidates
            && !self.proofs.iter().any(|proof| proof.file == file)
        {
            return None;
        }
        Some(self.candidates[index].len)
    }

    /// Candidates this cohort leaves in place: referenced ones, and
    /// unreferenced ones the current root protects structurally.
    pub(crate) fn survivors(&self) -> CohortSurvivors {
        let mut survivors = CohortSurvivors {
            lowest_arena: self.skipped_root_arena,
            ..CohortSurvivors::default()
        };
        if self.kind != CohortKind::Candidates {
            return survivors;
        }
        for (index, candidate) in self.candidates.iter().enumerate() {
            let bit = 1u128 << index;
            let retired = self.proofs.iter().any(|proof| proof.file == candidate.file);
            if retired {
                continue;
            }
            if self.referenced_pinned & bit != 0 && self.referenced_current & bit == 0 {
                survivors.pin_retained_files += 1;
                survivors.pin_retained_bytes += candidate.len;
            }
            let lowest = match candidate.file.kind {
                FileKind::Segment => &mut survivors.lowest_segment,
                FileKind::Directory => &mut survivors.lowest_arena,
                FileKind::Checkpoint => continue,
            };
            *lowest = Some(lowest.map_or(candidate.file.id, |id| id.min(candidate.file.id)));
        }
        survivors
    }
}
