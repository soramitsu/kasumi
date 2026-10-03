//! Directory allocation intents and the selected data root in a superblock.
//!
//! Allocation publications preserve the selected commit. A data publication
//! replaces its directory and replay anchor together, after both the pages
//! and the corresponding log commit are durable. Older roots may still reach
//! older arenas, so allocation alone never makes an arena reclaimable.

use super::{CoreError, GARBAGE_AT, GARBAGE_ENTRY_BYTES, MAX_GARBAGE, Superblock};
use crate::directory::{DIRECTORY_ROOT_BYTES, DirectoryRoot};
use crate::group::{FileKind, GroupFile};
use crate::reclaim::ReachabilityProof;
use crate::segment::{
    COMMIT_RECORD_BYTES, LogPosition, ReplayStart, SEGMENT_BYTES, SEGMENT_HEADER_BYTES, le_u64,
};

pub(super) const DIRECTORY_AT: usize = GARBAGE_AT + MAX_GARBAGE * GARBAGE_ENTRY_BYTES;
pub(super) const DIRECTORY_END: usize = DIRECTORY_AT + 24 + DIRECTORY_ROOT_BYTES + 56;

/// A single durable directory version and the exact committed log boundary
/// it covers. The commit codec must bind these fields into its chain digest;
/// selecting a superblock alone does not prove that an arbitrary page tree
/// was produced by a valid log commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectoryCommit {
    pub(crate) root: DirectoryRoot,
    pub(crate) start: ReplayStart,
}

impl Superblock {
    pub(crate) fn directory(&self) -> Option<DirectoryCommit> {
        self.directory
    }

    /// The newest confirmed arena. It remains protected from retirement even
    /// if a newer arena's creation is pending or no writer currently appends.
    pub(crate) fn last_directory_id(&self) -> u64 {
        self.last_directory_id
    }

    pub(crate) fn pending_directory(&self) -> Option<u64> {
        (self.next_directory_id.checked_sub(self.last_directory_id) == Some(2))
            .then(|| self.next_directory_id - 1)
    }

    /// Publish this successor before creating the arena. Only one creation
    /// can be outstanding; even an empty or abandoned arena consumes its ID.
    pub(crate) fn reserve_directory(&self) -> Result<(Self, u64), CoreError> {
        if self.pending_directory().is_some() {
            return Err(CoreError::InvalidInput("a directory intent is outstanding"));
        }
        let mut next = self.successor()?;
        let id = self.next_directory_id;
        next.next_directory_id = id
            .checked_add(1)
            .filter(|&next| next != u64::MAX)
            .ok_or(CoreError::InvalidInput("directory identifier overflow"))?;
        Ok((next, id))
    }

    /// Publish only after the arena's name and complete identity header have
    /// synchronized. Confirmation does not publish any data pages.
    pub(crate) fn confirm_directory(&self, arena_id: u64) -> Result<Self, CoreError> {
        if self.pending_directory() != Some(arena_id) {
            return Err(CoreError::InvalidInput(
                "directory is not the outstanding intent",
            ));
        }
        let mut next = self.successor()?;
        next.last_directory_id = arena_id;
        Ok(next)
    }

    /// The caller holds the write owner and has synchronized the directory
    /// pages and validated log commit. The root is published as one unit.
    pub(crate) fn install_directory(&self, commit: DirectoryCommit) -> Result<Self, CoreError> {
        if !directory_successor(self.directory, Some(commit)) || self.directory == Some(commit) {
            return Err(CoreError::InvalidInput("directory commit does not advance"));
        }
        let mut next = self.successor()?;
        next.directory = Some(commit);
        if let Some(reason) = next.directory_invariant_violation() {
            return Err(CoreError::InvalidInput(reason));
        }
        Ok(next)
    }

    /// Record one file for retirement under a completed reachability proof.
    /// The proof constructor belongs to the reclaim module; callers cannot
    /// substitute a boolean or a hand-built list of supposedly dead pages.
    pub(crate) fn retire_directory_file(
        &self,
        proof: &ReachabilityProof,
    ) -> Result<Self, CoreError> {
        self.retire_directory_files(std::slice::from_ref(proof))
    }

    /// Publish one bounded garbage batch after the selected root and all pins
    /// have been scanned. Every proof must describe this exact publication,
    /// so allocation/confirmation changes invalidate a proof even when they
    /// preserve the selected DirectoryCommit. Pin epochs are checked under
    /// the DiskState lock by the reclaim owner before this transition.
    pub(crate) fn retire_directory_files(
        &self,
        proofs: &[ReachabilityProof],
    ) -> Result<Self, CoreError> {
        if proofs.is_empty() || proofs.len() > MAX_GARBAGE {
            return Err(CoreError::InvalidInput(
                "directory retirement batch is empty or oversized",
            ));
        }
        let current = self.directory.ok_or(CoreError::InvalidInput(
            "no installed directory covers retirement",
        ))?;
        for (index, proof) in proofs.iter().enumerate() {
            if proof.directory_commit() != current
                || proof.publication_generation() != self.generation
            {
                return Err(CoreError::InvalidInput(
                    "directory reachability proof is stale",
                ));
            }
            let file = proof.file();
            if !self.directory_file_is_retirable(file) {
                return Err(CoreError::InvalidInput(
                    "directory retirement file is protected",
                ));
            }
            if self.garbage.binary_search(&file).is_ok()
                || proofs[..index].iter().any(|earlier| earlier.file() == file)
            {
                return Err(CoreError::InvalidInput(
                    "directory retirement file is duplicated",
                ));
            }
        }
        if proofs.len() > MAX_GARBAGE - self.garbage.len() {
            return Err(CoreError::CapacityDenied);
        }
        let mut next = self.successor()?;
        for proof in proofs {
            next.add_garbage(proof.file())?;
        }
        Ok(next)
    }

    /// Structural guard shared by publication and decoding. Reachability is
    /// deliberately not inferred from these counters: reopen must re-prove
    /// that decoded garbage is unreachable before it can unlink any file.
    pub(super) fn directory_file_is_retirable(&self, file: GroupFile) -> bool {
        let Some(commit) = self.directory else {
            return false;
        };
        if file.id == 0 {
            return false;
        }
        match file.kind {
            FileKind::Segment => {
                file.id < self.last_segment_id
                    && file.id < commit.start.position.segment_id
                    && self.pending_segment() != Some(file.id)
            }
            FileKind::Directory => {
                file.id < self.last_directory_id
                    && self.pending_directory() != Some(file.id)
                    && commit.root.page.is_none_or(|page| page.arena_id != file.id)
            }
            FileKind::Checkpoint => false,
        }
    }

    pub(super) fn directory_invariant_violation(&self) -> Option<&'static str> {
        if self.next_directory_id == 0
            || self.next_directory_id == u64::MAX
            || self.last_directory_id >= self.next_directory_id
            || self.next_directory_id - self.last_directory_id > 2
        {
            return Some("root directory intent is invalid");
        }
        if let Some(commit) = self.directory {
            if self.checkpoint.is_some() {
                return Some("root has two replay authorities");
            }
            if commit.root.validate().is_err()
                || commit.root.group_id != self.group_id
                || commit.root.generation != commit.start.batch_seq
                || commit.start.batch_seq == 0
                || commit.start.batch_seq == u64::MAX
                || commit.start.position.segment_id == 0
                || commit.start.position.segment_id > self.last_segment_id
                || commit.start.position.offset < SEGMENT_HEADER_BYTES + COMMIT_RECORD_BYTES as u64
                || commit.start.position.offset > SEGMENT_BYTES
                || commit
                    .root
                    .page
                    .is_some_and(|page| page.arena_id > self.last_directory_id)
            {
                return Some("root directory commit is invalid");
            }
        }
        None
    }
}

pub(super) fn directory_successor(
    previous: Option<DirectoryCommit>,
    next: Option<DirectoryCommit>,
) -> bool {
    match (previous, next) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(previous), Some(next)) => {
            previous == next
                || (next.start.batch_seq > previous.start.batch_seq
                    && (next.start.position.segment_id, next.start.position.offset)
                        > (
                            previous.start.position.segment_id,
                            previous.start.position.offset,
                        ))
        }
    }
}

pub(super) fn encode_directory(root: &Superblock, bytes: &mut [u8]) {
    bytes.fill(0);
    bytes[..8].copy_from_slice(&root.next_directory_id.to_le_bytes());
    bytes[8..16].copy_from_slice(&root.last_directory_id.to_le_bytes());
    if let Some(commit) = root.directory {
        bytes[16] = 1;
        bytes[24..120].copy_from_slice(&commit.root.encode().expect("validated directory root"));
        bytes[120..128].copy_from_slice(&commit.start.position.segment_id.to_le_bytes());
        bytes[128..136].copy_from_slice(&commit.start.position.offset.to_le_bytes());
        bytes[136..144].copy_from_slice(&commit.start.batch_seq.to_le_bytes());
        bytes[144..176].copy_from_slice(&commit.start.chain);
    }
}

pub(super) fn decode_directory(
    bytes: &[u8],
    group_id: [u8; 16],
) -> Result<(u64, u64, Option<DirectoryCommit>), CoreError> {
    let layout = CoreError::Corrupt("root directory has an unsupported layout");
    if bytes[16] > 1 || bytes[17..24].iter().any(|&byte| byte != 0) {
        return Err(layout);
    }
    let commit = if bytes[16] == 0 {
        if bytes[24..].iter().any(|&byte| byte != 0) {
            return Err(layout);
        }
        None
    } else {
        let root =
            DirectoryRoot::decode(bytes[24..120].try_into().expect("96-byte directory root"))
                .map_err(|error| match error {
                    CoreError::Corrupt("directory root is noncanonical") => layout,
                    _ => CoreError::Corrupt("root directory commit is invalid"),
                })?;
        if root.group_id != group_id {
            return Err(CoreError::Corrupt("root directory commit is invalid"));
        }
        Some(DirectoryCommit {
            root,
            start: ReplayStart {
                position: LogPosition {
                    segment_id: le_u64(&bytes[120..128]),
                    offset: le_u64(&bytes[128..136]),
                },
                batch_seq: le_u64(&bytes[136..144]),
                chain: bytes[144..176].try_into().expect("32 bytes"),
            },
        })
    };
    Ok((le_u64(&bytes[..8]), le_u64(&bytes[8..16]), commit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::DirectoryPageRef;
    use crate::group::{FaultTiming, GroupOp, InMemoryGroup, SegmentGroupBackend};
    use crate::root::{
        CHECKSUM_AT, FileRole, RootSelection, RootSlot, SlotImage, decode_slot, publish_root,
        select_root,
    };
    use crate::segment::crc32c;
    use crate::segment::test_support::{GROUP, corrupt_reason};

    fn allocated() -> Superblock {
        let (root, id) = Superblock::genesis(GROUP).reserve_segment(None).unwrap();
        let root = root.confirm_segment(id).unwrap();
        let (root, id) = root.reserve_directory().unwrap();
        root.confirm_directory(id).unwrap()
    }

    fn commit(sequence: u64) -> DirectoryCommit {
        DirectoryCommit {
            root: DirectoryRoot {
                group_id: GROUP,
                generation: sequence,
                page: Some(DirectoryPageRef {
                    arena_id: 1,
                    page_index: sequence,
                    sha256: [7; 32],
                }),
                height: 1,
                entries: sequence,
            },
            start: ReplayStart {
                position: LogPosition {
                    segment_id: 1,
                    offset: SEGMENT_HEADER_BYTES + sequence * 256,
                },
                batch_seq: sequence,
                chain: [sequence as u8; 32],
            },
        }
    }

    fn retirement_root() -> Superblock {
        let mut root = allocated();
        for _ in 0..2 {
            let sealed = crate::segment::SealedSegment {
                segment_id: root.last_segment_id(),
                len: 4096,
                commit_seq: 0,
            };
            let (next, id) = root.reserve_segment(Some(sealed)).unwrap();
            root = next.confirm_segment(id).unwrap();
        }
        for _ in 0..3 {
            let (next, id) = root.reserve_directory().unwrap();
            root = next.confirm_directory(id).unwrap();
        }
        let mut selected = commit(1);
        selected.root.page.as_mut().unwrap().arena_id = 3;
        selected.start.position.segment_id = 3;
        root = root.install_directory(selected).unwrap();
        let sealed = crate::segment::SealedSegment {
            segment_id: 3,
            len: 4096,
            commit_seq: 1,
        };
        let (root, id) = root.reserve_segment(Some(sealed)).unwrap();
        root.confirm_segment(id).unwrap()
    }

    fn proof(root: &Superblock, file: GroupFile) -> ReachabilityProof {
        ReachabilityProof::for_test(root.directory().unwrap(), root.generation(), file)
    }

    #[test]
    fn directory_retirement_accepts_only_proven_sealed_pre_anchor_files() {
        let root = retirement_root();
        assert_eq!(root.last_directory_id(), 4);
        assert_eq!(root.last_segment_id(), 4);
        let files = [
            GroupFile::segment(1),
            GroupFile::segment(2),
            GroupFile::directory(1),
            GroupFile::directory(2),
        ];
        let proofs: Vec<_> = files.into_iter().map(|file| proof(&root, file)).collect();
        let retired = root.retire_directory_files(&proofs).unwrap();
        assert_eq!(retired.generation(), root.generation() + 1);
        assert_eq!(retired.directory(), root.directory());
        assert_eq!(retired.garbage(), files);
        assert!(root.garbage().is_empty());
        assert_eq!(
            decode_slot(&retired.encode().unwrap()).unwrap(),
            SlotImage::Valid(retired)
        );
        for file in [
            GroupFile::segment(0),
            GroupFile::segment(3),
            GroupFile::segment(4),
            GroupFile::segment(5),
            GroupFile::directory(0),
            GroupFile::directory(3),
            GroupFile::directory(4),
            GroupFile::directory(5),
            GroupFile::checkpoint(1),
        ] {
            assert!(
                matches!(
                    root.retire_directory_file(&proof(&root, file)),
                    Err(CoreError::InvalidInput(
                        "directory retirement file is protected"
                    ))
                ),
                "{file:?}"
            );
        }
        let (pending, id) = root.reserve_directory().unwrap();
        assert!(
            pending
                .retire_directory_file(&proof(&pending, GroupFile::directory(id)))
                .is_err()
        );
        assert!(
            pending
                .retire_directory_file(&proof(&pending, GroupFile::directory(4)))
                .is_err()
        );
        let sealed = crate::segment::SealedSegment {
            segment_id: 4,
            len: 4096,
            commit_seq: 1,
        };
        let (pending, id) = root.reserve_segment(Some(sealed)).unwrap();
        assert!(
            pending
                .retire_directory_file(&proof(&pending, GroupFile::segment(id)))
                .is_err()
        );
    }

    #[test]
    fn directory_retirement_rejects_stale_commit_or_publication_proof() {
        let root = retirement_root();
        let old_proof = proof(&root, GroupFile::directory(1));
        let (new_allocation, _) = root.reserve_directory().unwrap();
        assert_eq!(new_allocation.directory(), root.directory());
        assert!(matches!(
            new_allocation.retire_directory_file(&old_proof),
            Err(CoreError::InvalidInput(
                "directory reachability proof is stale"
            ))
        ));
        let mut other_commit = root.directory().unwrap();
        other_commit.start.chain[0] ^= 1;
        let other_proof =
            ReachabilityProof::for_test(other_commit, root.generation(), GroupFile::directory(1));
        assert!(matches!(
            root.retire_directory_file(&other_proof),
            Err(CoreError::InvalidInput(
                "directory reachability proof is stale"
            ))
        ));
        let mut next_commit = commit(2);
        next_commit.root.page.as_mut().unwrap().arena_id = 3;
        next_commit.start.position.segment_id = 4;
        let advanced = root.install_directory(next_commit).unwrap();
        let forged_generation = ReachabilityProof::for_test(
            root.directory().unwrap(),
            advanced.generation(),
            GroupFile::directory(1),
        );
        assert!(matches!(
            advanced.retire_directory_file(&forged_generation),
            Err(CoreError::InvalidInput(
                "directory reachability proof is stale"
            ))
        ));
    }

    #[test]
    fn directory_retirement_batch_is_atomic_bounded_and_unique() {
        let mut root = retirement_root();
        while root.last_directory_id() < MAX_GARBAGE as u64 + 2 {
            let (next, id) = root.reserve_directory().unwrap();
            root = next.confirm_directory(id).unwrap();
        }
        assert!(matches!(
            root.retire_directory_files(&[]),
            Err(CoreError::InvalidInput(_))
        ));
        let duplicates = [
            proof(&root, GroupFile::directory(1)),
            proof(&root, GroupFile::directory(1)),
        ];
        assert!(matches!(
            root.retire_directory_files(&duplicates),
            Err(CoreError::InvalidInput(
                "directory retirement file is duplicated"
            ))
        ));
        assert!(root.garbage().is_empty());
        let proofs: Vec<_> = (1..root.last_directory_id())
            .filter(|id| *id != 3)
            .map(|id| proof(&root, GroupFile::directory(id)))
            .collect();
        assert_eq!(proofs.len(), MAX_GARBAGE);
        let full = root.retire_directory_files(&proofs).unwrap();
        assert_eq!(full.garbage().len(), MAX_GARBAGE);
        assert!(matches!(
            full.retire_directory_file(&proof(&full, GroupFile::segment(1))),
            Err(CoreError::CapacityDenied)
        ));
        assert_eq!(full.garbage().len(), MAX_GARBAGE);
    }

    #[test]
    fn directory_garbage_uses_existing_mirrored_unlink_and_forget_protocol() {
        let group = InMemoryGroup::new();
        let root = retirement_root();
        for id in 1..=4 {
            group.insert_foreign(GroupFile::segment(id), Vec::new());
            group.insert_foreign(GroupFile::directory(id), Vec::new());
        }
        for slot in [RootSlot::A, RootSlot::B] {
            group.write_root(slot, &root.encode().unwrap()).unwrap();
        }
        group.sync_root().unwrap();
        let file = GroupFile::directory(1);
        let retired = root.retire_directory_file(&proof(&root, file)).unwrap();
        assert!(retired.unlink_garbage(&group, file).is_err());
        assert!(group.exists(file).unwrap());
        publish_root(&group, &root, &retired).unwrap();
        let census = retired.census(&group).unwrap();
        assert_eq!(census.garbage_present, [file]);
        let unlinked = retired.unlink_garbage(&group, file).unwrap();
        assert!(!group.crash().exists(file).unwrap());
        assert_eq!(
            retired.census(&group).unwrap().garbage_unlink_pending,
            [file]
        );
        let forgotten = crate::root::publish_forget(&group, &retired, unlinked).unwrap();
        assert!(forgotten.garbage().is_empty());
        assert!(
            matches!(select_root(&group.crash()).unwrap(), RootSelection::Selected { superblock, mirrored: true, .. } if superblock == forgotten)
        );
    }

    #[test]
    fn decoded_directory_garbage_is_structural_and_still_needs_runtime_proof() {
        let root = retirement_root();
        // An older child arena could still be reachable. The decoder checks
        // only identities/bounds; the reopen reclaimer must walk all roots
        // before unlinking a checksum-valid garbage record like this one.
        let decoded =
            root.with_damaged_garbage(vec![GroupFile::directory(1), GroupFile::directory(2)]);
        assert_eq!(decoded.classify(GroupFile::directory(1)), FileRole::Garbage);
        for file in [
            GroupFile::directory(0),
            GroupFile::directory(3),
            GroupFile::directory(4),
            GroupFile::directory(5),
            GroupFile::segment(3),
        ] {
            let mut invalid = root.clone();
            invalid.garbage = vec![file];
            assert!(
                matches!(
                    invalid.encode(),
                    Err(CoreError::InvalidInput("root garbage list is invalid"))
                ),
                "{file:?}"
            );
        }
    }

    #[test]
    fn directory_root_and_anchor_round_trip_together() {
        let root = allocated().install_directory(commit(1)).unwrap();
        assert_eq!(
            decode_slot(&root.encode().unwrap()).unwrap(),
            SlotImage::Valid(root.clone())
        );
        let mut empty = commit(2);
        empty.root.page = None;
        empty.root.height = 0;
        empty.root.entries = 0;
        let root = root.install_directory(empty).unwrap();
        assert_eq!(
            decode_slot(&root.encode().unwrap()).unwrap(),
            SlotImage::Valid(root)
        );
    }

    #[test]
    fn directory_intents_are_never_reused_or_mistaken_for_orphans() {
        let root = allocated().install_directory(commit(1)).unwrap();
        let (pending, id) = root.reserve_directory().unwrap();
        assert_eq!(id, 2);
        assert_eq!(pending.directory(), root.directory());
        assert!(pending.reserve_directory().is_err());
        assert!(pending.confirm_directory(1).is_err());
        assert_eq!(
            pending.classify(GroupFile::directory(2)),
            FileRole::PendingCreate
        );
        let confirmed = pending.confirm_directory(2).unwrap();
        assert_eq!(confirmed.classify(GroupFile::directory(1)), FileRole::Live);
        assert_eq!(confirmed.classify(GroupFile::directory(2)), FileRole::Live);
        assert_eq!(
            confirmed.classify(GroupFile::directory(3)),
            FileRole::Unexpected
        );
        assert_eq!(
            GroupFile::parse_name("0000000000000002.kvdir"),
            Some(GroupFile::directory(2))
        );
        assert_eq!(
            FileKind::from_tag(FileKind::Directory.tag()),
            Some(FileKind::Directory)
        );
    }

    #[test]
    fn directory_publication_rejects_wrong_scope_versions_and_unconfirmed_arenas() {
        let base = allocated();
        for edit in 0..6 {
            let mut invalid = commit(1);
            match edit {
                0 => invalid.root.group_id = [99; 16],
                1 => invalid.root.generation = 2,
                2 => invalid.root.page.as_mut().unwrap().arena_id = 2,
                3 => invalid.start.position.segment_id = 2,
                4 => invalid.start.position.offset = SEGMENT_HEADER_BYTES,
                _ => invalid.root.page.as_mut().unwrap().page_index = u64::MAX,
            }
            assert!(base.install_directory(invalid).is_err(), "{edit}");
        }
        let root = base.install_directory(commit(2)).unwrap();
        assert!(root.install_directory(commit(1)).is_err());
        assert!(root.install_directory(commit(2)).is_err());
        let mut invalid = commit(3);
        invalid.start.position.offset = commit(1).start.position.offset;
        assert!(root.install_directory(invalid).is_err());
        assert!(!directory_successor(root.directory(), None));
    }

    #[test]
    fn directory_anchor_is_a_representable_commit_boundary() {
        let base = allocated();
        let first_boundary = SEGMENT_HEADER_BYTES + COMMIT_RECORD_BYTES as u64;
        for offset in [first_boundary, SEGMENT_BYTES] {
            let mut candidate = commit(1);
            candidate.start.position.offset = offset;
            assert!(base.install_directory(candidate).is_ok());
        }
        for offset in [
            0,
            SEGMENT_HEADER_BYTES,
            first_boundary - 1,
            SEGMENT_BYTES + 1,
        ] {
            let mut candidate = commit(1);
            candidate.start.position.offset = offset;
            assert!(base.install_directory(candidate).is_err());
        }
        for sequence in [0, u64::MAX] {
            let mut candidate = commit(1);
            candidate.root.generation = sequence;
            candidate.start.batch_seq = sequence;
            assert!(base.install_directory(candidate).is_err());
        }
    }

    #[test]
    fn adjacent_slots_cannot_regress_directory_state_or_allocations() {
        let base = allocated();
        let (base, id) = base.reserve_directory().unwrap();
        let base = base
            .confirm_directory(id)
            .unwrap()
            .install_directory(commit(2))
            .unwrap();
        for change in 0..5 {
            let mut next = base.successor().unwrap();
            match change {
                0 => next.directory = Some(commit(1)),
                1 => next.directory = None,
                2 => {
                    next.directory
                        .as_mut()
                        .unwrap()
                        .root
                        .page
                        .as_mut()
                        .unwrap()
                        .page_index += 1
                }
                3 => {
                    next.next_directory_id -= 1;
                    next.last_directory_id -= 1;
                }
                _ => next.last_directory_id -= 1,
            }
            // Both images are internally valid; their relationship is not.
            let group = InMemoryGroup::new();
            group
                .write_root(
                    RootSlot::for_generation(base.generation),
                    &base.encode().unwrap(),
                )
                .unwrap();
            group
                .write_root(
                    RootSlot::for_generation(next.generation),
                    &next.encode().unwrap(),
                )
                .unwrap();
            group.sync_root().unwrap();
            assert_eq!(
                corrupt_reason(select_root(&group)),
                "root slots are not successive publications",
                "{change}"
            );
        }
    }

    fn damaged(root: &Superblock, edit: impl FnOnce(&mut [u8])) -> &'static str {
        let mut bytes = root.encode().unwrap();
        edit(&mut bytes[DIRECTORY_AT..DIRECTORY_END]);
        let checksum = crc32c(&bytes[..CHECKSUM_AT]);
        bytes[CHECKSUM_AT..].copy_from_slice(&checksum.to_le_bytes());
        corrupt_reason(decode_slot(&bytes))
    }

    #[test]
    fn checksum_valid_directory_fields_must_be_canonical() {
        let allocated = allocated();
        let root = allocated.install_directory(commit(1)).unwrap();
        for at in (17..24).chain(50..56).chain(112..120) {
            assert_eq!(
                damaged(&root, |bytes| bytes[at] = 1),
                "root directory has an unsupported layout",
                "reserved byte {at}"
            );
        }
        assert_eq!(
            damaged(&root, |bytes| bytes[16] = 2),
            "root directory has an unsupported layout"
        );
        for at in 24..40 {
            assert_eq!(
                damaged(&root, |bytes| bytes[at] ^= 1),
                "root directory commit is invalid",
                "foreign group byte {at}"
            );
        }
        for at in 24..176 {
            assert_eq!(
                damaged(&allocated, |bytes| bytes[at] = 1),
                "root directory has an unsupported layout",
                "absent commit byte {at}"
            );
        }
        let mut empty = commit(1);
        empty.root.page = None;
        empty.root.height = 0;
        empty.root.entries = 0;
        let empty = allocated.install_directory(empty).unwrap();
        for at in 64..112 {
            assert_eq!(
                damaged(&empty, |bytes| bytes[at] = 1),
                "root directory has an unsupported layout",
                "absent page byte {at}"
            );
        }
        for (offset, value) in [(0, 0), (0, u64::MAX), (0, 4), (8, 2)] {
            assert_eq!(
                damaged(&root, |bytes| bytes[offset..offset + 8]
                    .copy_from_slice(&value.to_le_bytes())),
                "root directory intent is invalid"
            );
        }
        for (offset, value) in [
            (40, 2u64),
            (56, 0),
            (64, 2),
            (72, u64::MAX),
            (128, SEGMENT_HEADER_BYTES + COMMIT_RECORD_BYTES as u64 - 1),
            (136, u64::MAX),
        ] {
            assert_eq!(
                damaged(&root, |bytes| bytes[offset..offset + 8]
                    .copy_from_slice(&value.to_le_bytes())),
                "root directory commit is invalid",
                "invalid field {offset}"
            );
        }
    }

    #[test]
    fn directory_publication_faults_select_one_complete_commit() {
        for op in [GroupOp::RootWrite, GroupOp::RootSync] {
            for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
                for occurrence in 1..=2 {
                    let group = InMemoryGroup::new();
                    let mut root = Superblock::genesis(GROUP);
                    let (next, id) = root.reserve_segment(None).unwrap();
                    publish_root(&group, &root, &next).unwrap();
                    root = next;
                    let next = root.confirm_segment(id).unwrap();
                    publish_root(&group, &root, &next).unwrap();
                    root = next;
                    let (next, id) = root.reserve_directory().unwrap();
                    publish_root(&group, &root, &next).unwrap();
                    root = next;
                    let next = root.confirm_directory(id).unwrap();
                    publish_root(&group, &root, &next).unwrap();
                    root = next;
                    let next = root.install_directory(commit(1)).unwrap();
                    publish_root(&group, &root, &next).unwrap();
                    root = next;
                    let next = root.install_directory(commit(2)).unwrap();
                    group.fail(op, occurrence, timing);
                    assert!(matches!(
                        publish_root(&group, &root, &next),
                        Err(CoreError::UnknownCommit(_))
                    ));
                    let RootSelection::Selected {
                        superblock: selected,
                        ..
                    } = select_root(&group.crash()).unwrap()
                    else {
                        panic!("lost root")
                    };
                    assert!(selected == root || selected == next);
                    assert!(
                        selected.directory() == Some(commit(1))
                            || selected.directory() == Some(commit(2))
                    );
                }
            }
        }
    }
}
