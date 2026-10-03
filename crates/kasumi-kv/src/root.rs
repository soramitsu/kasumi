//! Root file of a segmented log: two checksummed 4 KiB superblock slots.
//!
//! Generation `g` is first written to its parity slot (A for even, B for odd)
//! and synchronized, then mirrored to the other slot and synchronized again.
//! A publication first requires the slots to select exactly its predecessor
//! (no selection for a new group), so a stale or unknown-outcome caller never
//! overwrites a newer root. Before overwriting its parity slot, it makes sure
//! the other slot holds the previous generation, restoring that copy first
//! when reopen selected the only intact one from the parity slot. So a torn
//! publication always leaves one intact root, and damage to one slot never
//! selects an older root. Reopen synchronizes the root file and then selects
//! the newest intact slot; intact slots must be equal or adjacent generations
//! of one group.
//!
//! A superblock holds the durable segment intent (`next_segment_id`), the
//! newest confirmed segment, and the segment the newest intent sealed with its
//! synchronized length and newest commit. A segment identifier is published as
//! an intent before its create-only file exists and is never reused; at most
//! one intent is outstanding. It also references the newest checkpoint by
//! identifier, length, replay-start segment and SHA-256, and lists garbage
//! files. An unlink cannot be undone, so a garbage file is unlinked only
//! through the root the slots select, after synchronizing the root file and
//! with both slots holding that root, and after its readers have drained; an
//! unpublished or unknown-outcome successor never unlinks a file the durable
//! root still needs. A record leaves the list only through `publish_forget`
//! with an `Unlinked` proof of a confirmed unlink and parent synchronization;
//! a listing that no longer shows the file is no such proof, and
//! `publish_root` refuses a successor that drops a record. Only a segment
//! wholly before the checkpoint's replay start and holding no value that
//! checkpoint references may be retired, so neither checkpoint loading nor
//! replay meets a missing segment. The last identifier of each kind is never
//! allocated, so arithmetic on a decoded root never overflows.

use crate::checkpoint::{CheckpointRef, CheckpointSummary};
use crate::core::CoreError;
use crate::group::{FileKind, GroupFile, ROOT_FILE_NAME, SegmentGroupBackend};
use crate::segment::{
    FORMAT_VERSION, LogBounds, SEGMENT_BYTES, SEGMENT_HEADER_BYTES, SealedSegment, SegmentRoll,
    crc32c, le_u32, le_u64, reject_legacy,
};

#[path = "root_directory.rs"]
mod directory;
pub(crate) use directory::DirectoryCommit;
use directory::{DIRECTORY_AT, DIRECTORY_END, decode_directory, encode_directory};

pub const ROOT_SLOT_BYTES: usize = 4096;
pub(crate) const ROOT_MAGIC: [u8; 16] = *b"KASUMI-KVROOT003";
pub(crate) const MAX_GARBAGE: usize = 128;
const CHECKPOINT_AT: usize = 72;
const SEALED_AT: usize = 128;
const GARBAGE_COUNT_AT: usize = 152;
const GARBAGE_AT: usize = 160;
const GARBAGE_ENTRY_BYTES: usize = 16;
const CHECKSUM_AT: usize = ROOT_SLOT_BYTES - 4;

const _: () = assert!(GARBAGE_AT + MAX_GARBAGE * GARBAGE_ENTRY_BYTES <= CHECKSUM_AT);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootSlot {
    A,
    B,
}

impl RootSlot {
    pub(crate) fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }

    fn for_generation(generation: u64) -> Self {
        if generation.is_multiple_of(2) {
            Self::A
        } else {
            Self::B
        }
    }

    fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// One root generation. The fields are private, so a successor is built only
/// by the transitions below and a garbage record leaves only on proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Superblock {
    generation: u64,
    group_id: [u8; 16],
    next_segment_id: u64,
    /// Newest segment whose file and header are durable; zero for none.
    last_segment_id: u64,
    /// The segment the newest intent sealed; present once one was sealed.
    sealed: Option<SealedSegment>,
    next_checkpoint_id: u64,
    checkpoint: Option<CheckpointRef>,
    next_directory_id: u64,
    last_directory_id: u64,
    directory: Option<DirectoryCommit>,
    /// Sorted, unique files awaiting unlink.
    garbage: Vec<GroupFile>,
}

/// How the root accounts for one present file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileRole {
    Live,
    Garbage,
    /// The outstanding segment intent.
    PendingCreate,
    /// A checkpoint created under an intent but never referenced.
    Orphan,
    /// Not allocated by this root: a substitution that fails closed.
    Unexpected,
}

/// The present files of a group, classified by its selected root. Every
/// garbage file, listed or not, leaves the root only through
/// `Superblock::unlink_garbage` and `publish_forget`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct Census {
    pub(crate) live_segments: Vec<u64>,
    pub(crate) orphans: Vec<GroupFile>,
    /// Recorded garbage still listed; its space is still held.
    pub(crate) garbage_present: Vec<GroupFile>,
    /// Recorded garbage the listing no longer shows. An unlink whose parent
    /// synchronization failed looks the same and may return after power loss,
    /// so its space is not credited and its unlink is still owed.
    pub(crate) garbage_unlink_pending: Vec<GroupFile>,
}

/// One streaming census observation. Missing garbage is still owed an exact
/// unlink and parent synchronization; its absent name does not prove disposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CensusEntry {
    Present(GroupFile, FileRole),
    GarbageUnlinkPending(GroupFile),
}

/// Proof that the unlink of one recorded garbage file, including the parent
/// synchronization, succeeded. Only `Superblock::unlink_garbage` makes one,
/// so no record is dropped on the evidence of a listing alone.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub(crate) struct Unlinked {
    group_id: [u8; 16],
    file: GroupFile,
}

impl Superblock {
    /// The unpublished state of a new group. Its first publication is
    /// generation one.
    pub(crate) fn genesis(group_id: [u8; 16]) -> Self {
        Self {
            generation: 0,
            group_id,
            next_segment_id: 1,
            last_segment_id: 0,
            sealed: None,
            next_checkpoint_id: 1,
            checkpoint: None,
            next_directory_id: 1,
            last_directory_id: 0,
            directory: None,
            garbage: Vec::new(),
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Publish an empty incarnation before any data/arena allocation. The
    /// caller has established an empty owned group and selects no prior root.
    pub(crate) fn initialized(&self) -> Result<Self, CoreError> {
        if self.generation != 0 {
            return Err(CoreError::InvalidInput("group root is already initialized"));
        }
        self.successor()
    }

    pub(crate) fn group_id(&self) -> &[u8; 16] {
        &self.group_id
    }

    pub(crate) fn last_segment_id(&self) -> u64 {
        self.last_segment_id
    }

    pub(crate) fn checkpoint(&self) -> Option<CheckpointRef> {
        self.checkpoint
    }

    pub(crate) fn garbage(&self) -> &[GroupFile] {
        &self.garbage
    }

    pub(crate) fn pending_segment(&self) -> Option<u64> {
        (self.next_segment_id.checked_sub(self.last_segment_id) == Some(2))
            .then(|| self.next_segment_id - 1)
    }

    pub(crate) fn log_bounds(&self) -> LogBounds {
        LogBounds {
            last_segment_id: self.last_segment_id,
            pending_segment: self.pending_segment(),
            sealed: self.sealed,
        }
    }

    fn successor(&self) -> Result<Self, CoreError> {
        let mut next = self.clone();
        next.generation = self
            .generation
            .checked_add(1)
            .ok_or(CoreError::InvalidInput("root generation overflow"))?;
        Ok(next)
    }

    /// Allocate the next segment identifier as a durable intent. `sealed` is
    /// the synchronized newest segment, absent only for the first segment.
    pub(crate) fn reserve_segment(
        &self,
        sealed: Option<SealedSegment>,
    ) -> Result<(Self, u64), CoreError> {
        if self.pending_segment().is_some() {
            return Err(CoreError::InvalidInput("a segment intent is outstanding"));
        }
        let newest = (self.last_segment_id != 0).then_some(self.last_segment_id);
        if sealed.map(|sealed| sealed.segment_id) != newest
            || sealed.is_some_and(|sealed| !sealed_len_is_valid(sealed.len))
        {
            return Err(CoreError::InvalidInput(
                "sealed segment is not the newest segment",
            ));
        }
        let mut next = self.successor()?;
        let id = self.next_segment_id;
        next.next_segment_id = id
            .checked_add(1)
            .filter(|&next| next != u64::MAX)
            .ok_or(CoreError::InvalidInput("segment identifier overflow"))?;
        next.sealed = sealed;
        Ok((next, id))
    }

    pub(crate) fn confirm_segment(&self, segment_id: u64) -> Result<Self, CoreError> {
        if self.pending_segment() != Some(segment_id) {
            return Err(CoreError::InvalidInput(
                "segment is not the outstanding intent",
            ));
        }
        let mut next = self.successor()?;
        next.last_segment_id = segment_id;
        Ok(next)
    }

    pub(crate) fn reserve_checkpoint(&self) -> Result<(Self, u64), CoreError> {
        let mut next = self.successor()?;
        let id = self.next_checkpoint_id;
        next.next_checkpoint_id = id
            .checked_add(1)
            .filter(|&next| next != u64::MAX)
            .ok_or(CoreError::InvalidInput("checkpoint identifier overflow"))?;
        Ok((next, id))
    }

    /// Reference a written, synchronized checkpoint. The replaced checkpoint
    /// becomes garbage in the same publication.
    pub(crate) fn install_checkpoint(&self, reference: CheckpointRef) -> Result<Self, CoreError> {
        if self.directory.is_some() {
            return Err(CoreError::InvalidInput(
                "directory root already owns replay",
            ));
        }
        if reference.id == 0
            || reference.id >= self.next_checkpoint_id
            || self
                .checkpoint
                .is_some_and(|current| reference.id <= current.id)
            || self.garbage.contains(&GroupFile::checkpoint(reference.id))
        {
            return Err(CoreError::InvalidInput(
                "checkpoint was not reserved by this root",
            ));
        }
        // Replay never moves back over segments the previous one let retire.
        if reference.start_segment_id == 0
            || reference.start_segment_id > self.last_segment_id
            || self
                .checkpoint
                .is_some_and(|current| reference.start_segment_id < current.start_segment_id)
        {
            return Err(CoreError::InvalidInput(
                "checkpoint replay start is outside the log",
            ));
        }
        let mut next = self.successor()?;
        if let Some(previous) = next.checkpoint.replace(reference) {
            next.add_garbage(GroupFile::checkpoint(previous.id))?;
        }
        Ok(next)
    }

    /// Record a segment for unlink. It must lie wholly before the installed
    /// checkpoint's replay start, which also keeps the newest segment, and
    /// hold no value that checkpoint references; `checkpoint` is that
    /// checkpoint's summary, bound to the installed reference by identifier,
    /// length, replay start and digest. A full list is a recoverable capacity
    /// denial.
    pub(crate) fn retire_segment(
        &self,
        segment_id: u64,
        checkpoint: &CheckpointSummary,
    ) -> Result<Self, CoreError> {
        if self.directory.is_some() {
            return Err(CoreError::InvalidInput(
                "segment retirement needs directory reachability proof",
            ));
        }
        let Some(current) = self.checkpoint else {
            return Err(CoreError::InvalidInput(
                "no installed checkpoint covers the segment",
            ));
        };
        let header = &checkpoint.header;
        if checkpoint.reference != current
            || header.checkpoint_id != current.id
            || header.start.position.segment_id != current.start_segment_id
        {
            return Err(CoreError::InvalidInput(
                "checkpoint summary is not the installed checkpoint",
            ));
        }
        if segment_id == 0
            || segment_id >= current.start_segment_id
            || checkpoint
                .segment_live_bytes
                .binary_search_by_key(&segment_id, |&(id, _)| id)
                .is_ok()
        {
            return Err(CoreError::InvalidInput(
                "segment is still needed by the installed checkpoint",
            ));
        }
        let mut next = self.successor()?;
        next.add_garbage(GroupFile::segment(segment_id))?;
        Ok(next)
    }

    /// Record an unreferenced checkpoint file, such as an unfinished one, for
    /// unlink. A full list is a recoverable capacity denial.
    pub(crate) fn retire_checkpoint(&self, checkpoint_id: u64) -> Result<Self, CoreError> {
        if checkpoint_id == 0
            || checkpoint_id >= self.next_checkpoint_id
            || self
                .checkpoint
                .is_some_and(|current| current.id == checkpoint_id)
        {
            return Err(CoreError::InvalidInput(
                "checkpoint cannot be retired by this root",
            ));
        }
        let mut next = self.successor()?;
        next.add_garbage(GroupFile::checkpoint(checkpoint_id))?;
        Ok(next)
    }

    /// Unlink one garbage file of this durable root, whether or not the
    /// listing still shows it. The unlink cannot be undone, so `self` must be
    /// the root the slots select once the root file is synchronized, held in
    /// both slots: a successor never published, or one whose publication
    /// had an unknown outcome and reached only one slot, is refused before
    /// any unlink, as is a stale root. A selection held in one slot needs
    /// `repair_mirror` first, so damage to either slot never selects a root
    /// that still needs the file. A failed synchronization is plain I/O. The
    /// backend's unlink is idempotent and synchronizes the parent, so success
    /// proves the name will not return.
    pub(crate) fn unlink_garbage(
        &self,
        backend: &dyn SegmentGroupBackend,
        file: GroupFile,
    ) -> Result<Unlinked, CoreError> {
        if self.garbage.binary_search(&file).is_err() {
            return Err(CoreError::InvalidInput("file is not recorded as garbage"));
        }
        match select_root(backend)? {
            RootSelection::Selected {
                superblock,
                mirrored,
                ..
            } if superblock == *self => {
                if !mirrored {
                    return Err(CoreError::InvalidInput(
                        "garbage unlink waits for both root slots",
                    ));
                }
            }
            RootSelection::Empty | RootSelection::Selected { .. } => {
                return Err(CoreError::InvalidInput(
                    "garbage unlink does not follow the selected root",
                ));
            }
        }
        backend.unlink(file)?;
        Ok(Unlinked {
            group_id: self.group_id,
            file,
        })
    }

    /// Drop a garbage record once its unlink is proven. Only `publish_forget`
    /// publishes the result.
    fn forget(&self, unlinked: Unlinked) -> Result<Self, CoreError> {
        if unlinked.group_id != self.group_id {
            return Err(CoreError::InvalidInput("unlink proof names another group"));
        }
        let mut next = self.successor()?;
        let position = next
            .garbage
            .binary_search(&unlinked.file)
            .map_err(|_| CoreError::InvalidInput("file is not recorded as garbage"))?;
        next.garbage.remove(position);
        Ok(next)
    }

    /// This root as reopen decodes it after media damage replaced its garbage
    /// list with a checksum-valid `garbage`.
    #[cfg(test)]
    pub(crate) fn with_damaged_garbage(&self, garbage: Vec<GroupFile>) -> Self {
        let mut damaged = self.clone();
        damaged.garbage = garbage;
        match decode_slot(&damaged.encode().expect("damage keeps the invariants")) {
            Ok(SlotImage::Valid(decoded)) => decoded,
            other => panic!("damaged root does not decode: {other:?}"),
        }
    }

    fn add_garbage(&mut self, file: GroupFile) -> Result<(), CoreError> {
        let position = match self.garbage.binary_search(&file) {
            Ok(_) => return Err(CoreError::InvalidInput("file is already garbage")),
            Err(position) => position,
        };
        if self.garbage.len() >= MAX_GARBAGE {
            return Err(CoreError::CapacityDenied);
        }
        self.garbage.insert(position, file);
        Ok(())
    }

    pub(crate) fn classify(&self, file: GroupFile) -> FileRole {
        let (next, current) = match file.kind {
            FileKind::Segment => (self.next_segment_id, None),
            FileKind::Checkpoint => (
                self.next_checkpoint_id,
                self.checkpoint.map(|reference| reference.id),
            ),
            FileKind::Directory => (self.next_directory_id, None),
        };
        if file.id == 0 || file.id >= next {
            FileRole::Unexpected
        } else if self.garbage.binary_search(&file).is_ok() {
            FileRole::Garbage
        } else if (file.kind == FileKind::Segment && self.pending_segment() == Some(file.id))
            || (file.kind == FileKind::Directory && self.pending_directory() == Some(file.id))
        {
            FileRole::PendingCreate
        } else if matches!(file.kind, FileKind::Segment | FileKind::Directory)
            || current == Some(file.id)
        {
            FileRole::Live
        } else {
            FileRole::Orphan
        }
    }

    /// Classify every directory entry. An entry that is neither the root nor
    /// a group file, a file this root never allocated, or a missing root or
    /// referenced checkpoint fails closed.
    pub(crate) fn visit_census(
        &self,
        backend: &dyn SegmentGroupBackend,
        mut visit: impl FnMut(CensusEntry) -> Result<(), CoreError>,
    ) -> Result<(), CoreError> {
        #[derive(Debug)]
        struct VisitorStopped;
        impl std::fmt::Display for VisitorStopped {
            fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.write_str("group census visitor stopped")
            }
        }
        impl std::error::Error for VisitorStopped {}

        let mut root = false;
        let mut checkpoint_found = self.checkpoint.is_none();
        let directory = self.directory.and_then(|commit| commit.root.page);
        let mut directory_found = directory.is_none();
        let mut garbage_found = [false; MAX_GARBAGE];
        let mut visit_error = None;
        let result = backend.visit_entries(&mut |entry| {
            let result =
                (|| {
                    if entry == ROOT_FILE_NAME {
                        root = true;
                        return Ok(());
                    }
                    let file = entry.to_str().and_then(GroupFile::parse_name).ok_or(
                        CoreError::Corrupt(
                            "group directory holds an entry that is not a group file",
                        ),
                    )?;
                    let role = self.classify(file);
                    if role == FileRole::Unexpected {
                        return Err(CoreError::Corrupt(
                            "group holds a file its root never allocated",
                        ));
                    }
                    checkpoint_found |= self
                        .checkpoint
                        .is_some_and(|reference| file == GroupFile::checkpoint(reference.id));
                    directory_found |=
                        directory.is_some_and(|page| file == GroupFile::directory(page.arena_id));
                    if let Ok(index) = self.garbage.binary_search(&file) {
                        garbage_found[index] = true;
                    }
                    visit(CensusEntry::Present(file, role))
                })();
            if let Err(error) = result {
                visit_error = Some(error);
                return Err(std::io::Error::other(VisitorStopped));
            }
            Ok(())
        });
        match (result, visit_error) {
            // Only our exact callback sentinel restores its CoreError. The
            // backend may replace it with an independent cursor-close error;
            // that failure must retain precedence and fence the outer owner.
            (Err(error), Some(visit_error))
                if error
                    .get_ref()
                    .is_some_and(|error| error.is::<VisitorStopped>()) =>
            {
                return Err(visit_error);
            }
            (Err(error), _) => return Err(error.into()),
            (Ok(()), Some(error)) => return Err(error),
            (Ok(()), None) => {}
        }
        if !root {
            return Err(CoreError::Corrupt("group root file is missing"));
        }
        if !checkpoint_found {
            return Err(CoreError::Corrupt("referenced checkpoint is missing"));
        }
        if !directory_found {
            return Err(CoreError::Corrupt("referenced directory arena is missing"));
        }
        for (index, file) in self.garbage.iter().enumerate() {
            if !garbage_found[index] {
                visit(CensusEntry::GarbageUnlinkPending(*file))?;
            }
        }
        Ok(())
    }

    /// Test-only materialization for convenient assertions. Production census
    /// retains only the fixed garbage-presence bitmap and a borrowed entry.
    #[cfg(test)]
    pub(crate) fn census(&self, backend: &dyn SegmentGroupBackend) -> Result<Census, CoreError> {
        let mut census = Census::default();
        self.visit_census(backend, |entry| {
            match entry {
                CensusEntry::Present(file, FileRole::Live) if file.kind == FileKind::Segment => {
                    census.live_segments.push(file.id)
                }
                CensusEntry::Present(file, FileRole::Garbage) => census.garbage_present.push(file),
                CensusEntry::Present(file, FileRole::Orphan) => census.orphans.push(file),
                CensusEntry::GarbageUnlinkPending(file) => census.garbage_unlink_pending.push(file),
                CensusEntry::Present(_, _) => {}
            }
            Ok(())
        })?;
        census.live_segments.sort_unstable();
        census.garbage_present.sort_unstable();
        census.orphans.sort_unstable();
        Ok(census)
    }

    fn invariant_violation(&self) -> Option<&'static str> {
        if self.generation == 0 {
            return Some("root generation is zero");
        }
        // The last identifier of each kind stays unallocated, so arithmetic on
        // the next one never overflows.
        if self.next_segment_id == 0
            || self.next_segment_id == u64::MAX
            || self.last_segment_id >= self.next_segment_id
            || self.next_segment_id - self.last_segment_id > 2
        {
            return Some("root segment intent is invalid");
        }
        // Every intent after the first seals the segment two before the next.
        let sealed_id = self.next_segment_id.checked_sub(2).filter(|&id| id != 0);
        if self.sealed.map(|sealed| sealed.segment_id) != sealed_id
            || self
                .sealed
                .is_some_and(|sealed| !sealed_len_is_valid(sealed.len))
        {
            return Some("root sealed segment record is invalid");
        }
        if self.next_checkpoint_id == 0
            || self.next_checkpoint_id == u64::MAX
            || self.checkpoint.is_some_and(|reference| {
                reference.id == 0
                    || reference.id >= self.next_checkpoint_id
                    || reference.len == 0
                    || reference.start_segment_id == 0
                    || reference.start_segment_id > self.last_segment_id
            })
        {
            return Some("root checkpoint reference is invalid");
        }
        if let Some(reason) = self.directory_invariant_violation() {
            return Some(reason);
        }
        let start = self
            .checkpoint
            .map_or(0, |reference| reference.start_segment_id);
        if self.garbage.len() > MAX_GARBAGE
            || self.garbage.windows(2).any(|pair| pair[0] >= pair[1])
            || self.garbage.iter().any(|file| match file.kind {
                FileKind::Segment => {
                    if self.directory.is_some() {
                        !self.directory_file_is_retirable(*file)
                    } else {
                        file.id == 0 || file.id >= start
                    }
                }
                FileKind::Checkpoint => {
                    file.id == 0
                        || file.id >= self.next_checkpoint_id
                        || self.checkpoint.is_some_and(|current| current.id == file.id)
                }
                // These are structural guards only. Runtime recovery checks
                // complete root reachability before unlinking decoded garbage.
                FileKind::Directory => !self.directory_file_is_retirable(*file),
            })
        {
            return Some("root garbage list is invalid");
        }
        None
    }

    pub(crate) fn encode(&self) -> Result<[u8; ROOT_SLOT_BYTES], CoreError> {
        if let Some(reason) = self.invariant_violation() {
            return Err(CoreError::InvalidInput(reason));
        }
        let mut bytes = [0u8; ROOT_SLOT_BYTES];
        bytes[..16].copy_from_slice(&ROOT_MAGIC);
        bytes[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[24..40].copy_from_slice(&self.group_id);
        bytes[40..48].copy_from_slice(&self.generation.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.next_segment_id.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.last_segment_id.to_le_bytes());
        bytes[64..72].copy_from_slice(&self.next_checkpoint_id.to_le_bytes());
        if let Some(reference) = self.checkpoint {
            let at = CHECKPOINT_AT;
            bytes[at..at + 8].copy_from_slice(&reference.id.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&reference.len.to_le_bytes());
            bytes[at + 16..at + 24].copy_from_slice(&reference.start_segment_id.to_le_bytes());
            bytes[at + 24..at + 56].copy_from_slice(&reference.sha256);
        }
        if let Some(sealed) = self.sealed {
            let at = SEALED_AT;
            bytes[at..at + 8].copy_from_slice(&sealed.segment_id.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&sealed.len.to_le_bytes());
            bytes[at + 16..at + 24].copy_from_slice(&sealed.commit_seq.to_le_bytes());
        }
        bytes[GARBAGE_COUNT_AT..GARBAGE_COUNT_AT + 4]
            .copy_from_slice(&(self.garbage.len() as u32).to_le_bytes());
        for (index, file) in self.garbage.iter().enumerate() {
            let at = GARBAGE_AT + index * GARBAGE_ENTRY_BYTES;
            bytes[at] = file.kind.tag();
            bytes[at + 8..at + 16].copy_from_slice(&file.id.to_le_bytes());
        }
        encode_directory(self, &mut bytes[DIRECTORY_AT..DIRECTORY_END]);
        let checksum = crc32c(&bytes[..CHECKSUM_AT]);
        bytes[CHECKSUM_AT..].copy_from_slice(&checksum.to_le_bytes());
        Ok(bytes)
    }
}

fn sealed_len_is_valid(len: u64) -> bool {
    (SEGMENT_HEADER_BYTES..=SEGMENT_BYTES).contains(&len)
}

#[derive(Clone, Debug, PartialEq, Eq)]
// Two fixed-size slot images are read at a time. Keep their bounded metadata
// inline rather than add a fallible, separately admitted allocation per slot.
#[allow(clippy::large_enum_variant)]
enum SlotImage {
    Unwritten,
    /// Torn or damaged: wrong magic or checksum.
    Invalid,
    Valid(Superblock),
}

fn decode_slot(bytes: &[u8; ROOT_SLOT_BYTES]) -> Result<SlotImage, CoreError> {
    reject_legacy(bytes)?;
    if bytes[..16] == *b"KASUMI-KVROOT001" || bytes[..16] == *b"KASUMI-KVROOT002" {
        return Err(CoreError::Corrupt("retired root format is unsupported"));
    }
    if bytes.iter().all(|&byte| byte == 0) {
        return Ok(SlotImage::Unwritten);
    }
    if bytes[..16] != ROOT_MAGIC || le_u32(&bytes[CHECKSUM_AT..]) != crc32c(&bytes[..CHECKSUM_AT]) {
        return Ok(SlotImage::Invalid);
    }
    let layout = CoreError::Corrupt("root slot has an unsupported layout");
    let garbage_count = le_u32(&bytes[GARBAGE_COUNT_AT..GARBAGE_COUNT_AT + 4]) as usize;
    if le_u32(&bytes[16..20]) != FORMAT_VERSION
        || bytes[20..24].iter().any(|&byte| byte != 0)
        || bytes[GARBAGE_COUNT_AT + 4..GARBAGE_AT]
            .iter()
            .any(|&byte| byte != 0)
        || garbage_count > MAX_GARBAGE
        || bytes[GARBAGE_AT + garbage_count * GARBAGE_ENTRY_BYTES..DIRECTORY_AT]
            .iter()
            .any(|&byte| byte != 0)
        || bytes[DIRECTORY_END..CHECKSUM_AT]
            .iter()
            .any(|&byte| byte != 0)
    {
        return Err(layout);
    }
    let checkpoint_id = le_u64(&bytes[CHECKPOINT_AT..CHECKPOINT_AT + 8]);
    let checkpoint = if checkpoint_id == 0 {
        if bytes[CHECKPOINT_AT + 8..SEALED_AT]
            .iter()
            .any(|&byte| byte != 0)
        {
            return Err(layout);
        }
        None
    } else {
        let at = CHECKPOINT_AT;
        Some(CheckpointRef {
            id: checkpoint_id,
            len: le_u64(&bytes[at + 8..at + 16]),
            start_segment_id: le_u64(&bytes[at + 16..at + 24]),
            sha256: bytes[at + 24..at + 56].try_into().expect("32 bytes"),
        })
    };
    let sealed_id = le_u64(&bytes[SEALED_AT..SEALED_AT + 8]);
    let sealed = if sealed_id == 0 {
        if bytes[SEALED_AT + 8..GARBAGE_COUNT_AT]
            .iter()
            .any(|&byte| byte != 0)
        {
            return Err(layout);
        }
        None
    } else {
        Some(SealedSegment {
            segment_id: sealed_id,
            len: le_u64(&bytes[SEALED_AT + 8..SEALED_AT + 16]),
            commit_seq: le_u64(&bytes[SEALED_AT + 16..SEALED_AT + 24]),
        })
    };
    let mut garbage = Vec::with_capacity(garbage_count);
    for index in 0..garbage_count {
        let at = GARBAGE_AT + index * GARBAGE_ENTRY_BYTES;
        let kind = FileKind::from_tag(bytes[at])
            .ok_or(CoreError::Corrupt("root garbage entry has an unknown kind"))?;
        if bytes[at + 1..at + 8].iter().any(|&byte| byte != 0) {
            return Err(CoreError::Corrupt("root slot has an unsupported layout"));
        }
        garbage.push(GroupFile {
            kind,
            id: le_u64(&bytes[at + 8..at + 16]),
        });
    }
    let (next_directory_id, last_directory_id, directory) = decode_directory(
        &bytes[DIRECTORY_AT..DIRECTORY_END],
        bytes[24..40].try_into().expect("16 bytes"),
    )?;
    let superblock = Superblock {
        generation: le_u64(&bytes[40..48]),
        group_id: bytes[24..40].try_into().expect("16 bytes"),
        next_segment_id: le_u64(&bytes[48..56]),
        last_segment_id: le_u64(&bytes[56..64]),
        sealed,
        next_checkpoint_id: le_u64(&bytes[64..72]),
        checkpoint,
        next_directory_id,
        last_directory_id,
        directory,
        garbage,
    };
    if let Some(reason) = superblock.invariant_violation() {
        return Err(CoreError::Corrupt(reason));
    }
    Ok(SlotImage::Valid(superblock))
}

#[derive(Clone, Debug, PartialEq, Eq)]
// Selection holds exactly one bounded root, never a data-sized collection.
// Boxing it would introduce another allocation on the recovery/publication path.
#[allow(clippy::large_enum_variant)]
pub(crate) enum RootSelection {
    /// No publication completed. Valid only for a group with no files.
    Empty,
    Selected {
        superblock: Superblock,
        /// The slot the superblock was read from.
        slot: RootSlot,
        /// Both slots hold the selected generation. Otherwise the next
        /// `publish_root` restores the other copy before it overwrites the
        /// only intact one; `repair_mirror` restores it sooner, and
        /// `Superblock::unlink_garbage` waits for it.
        mirrored: bool,
    },
}

/// Select the durable root at reopen. A restart without power loss can still
/// read slot writes whose synchronization failed, so the root file is
/// synchronized first and the selection survives a later power loss; a
/// failure is plain I/O and the owner fences.
pub(crate) fn select_root(backend: &dyn SegmentGroupBackend) -> Result<RootSelection, CoreError> {
    backend.sync_root()?;
    read_selection(backend)
}

/// The selection the slots hold as this process reads them.
fn read_selection(backend: &dyn SegmentGroupBackend) -> Result<RootSelection, CoreError> {
    let mut a = [0u8; ROOT_SLOT_BYTES];
    let mut b = [0u8; ROOT_SLOT_BYTES];
    backend.read_root(RootSlot::A, &mut a)?;
    backend.read_root(RootSlot::B, &mut b)?;
    select_root_images(&a, &b)
}

/// Apply the canonical mirrored-slot rules to caller-owned images without
/// taking another backend lock or performing a synchronization callback.
fn select_root_images(
    a: &[u8; ROOT_SLOT_BYTES],
    b: &[u8; ROOT_SLOT_BYTES],
) -> Result<RootSelection, CoreError> {
    let a = decode_slot(a)?;
    let b = decode_slot(b)?;
    let selected = |superblock: Superblock, slot, mirrored| {
        Ok(RootSelection::Selected {
            superblock,
            slot,
            mirrored,
        })
    };
    match (a, b) {
        (SlotImage::Valid(a), SlotImage::Valid(b)) => {
            if a.group_id != b.group_id {
                return Err(CoreError::Corrupt("root slots name different groups"));
            }
            if a.generation == b.generation {
                if a != b {
                    return Err(CoreError::Corrupt("root slots disagree at one generation"));
                }
                return selected(a, RootSlot::A, true);
            }
            let (newer, newer_slot, older) = if a.generation > b.generation {
                (a, RootSlot::A, b)
            } else {
                (b, RootSlot::B, a)
            };
            if newer.generation != older.generation + 1
                || RootSlot::for_generation(newer.generation) != newer_slot
            {
                return Err(CoreError::Corrupt(
                    "root slots are not adjacent publications",
                ));
            }
            if !is_successor(&older, &newer) {
                return Err(CoreError::Corrupt(
                    "root slots are not successive publications",
                ));
            }
            selected(newer, newer_slot, false)
        }
        (SlotImage::Valid(valid), SlotImage::Invalid) => selected(valid, RootSlot::A, false),
        (SlotImage::Invalid, SlotImage::Valid(valid)) => selected(valid, RootSlot::B, false),
        // Only the first publication leaves its mirror slot unwritten.
        (SlotImage::Unwritten, SlotImage::Valid(valid)) if valid.generation == 1 => {
            selected(valid, RootSlot::B, false)
        }
        (SlotImage::Valid(_), SlotImage::Unwritten)
        | (SlotImage::Unwritten, SlotImage::Valid(_)) => {
            Err(CoreError::Corrupt("a published root slot was erased"))
        }
        // A torn first publication; its mirror was never written.
        (SlotImage::Unwritten, SlotImage::Unwritten | SlotImage::Invalid) => {
            Ok(RootSelection::Empty)
        }
        (SlotImage::Invalid, SlotImage::Invalid | SlotImage::Unwritten) => {
            Err(CoreError::Corrupt("no intact root slot"))
        }
    }
}

/// Maximum additional heap backing while the pure transaction-space validator
/// decodes both bounded garbage lists. Caller-owned slot images and scalar
/// stack frames are separate. Installed callers preadmit this before decoding.
pub const TRANSACTION_SPACE_ROOTS_HEAP_BYTES: u64 =
    (2 * (MAX_GARBAGE * std::mem::size_of::<GroupFile>() + 128)) as u64;

/// Check a space plan against the canonical selection from two protected root
/// images. This reads no backend and proves no I/O settlement or authorization.
/// The caller preadmits `TRANSACTION_SPACE_ROOTS_HEAP_BYTES`, obtains both images
/// under its actual group owner, and keeps that owner serialized through claim
/// installation. Plan shape/extent/cardinality checks remain mandatory too.
pub fn validate_transaction_space_roots(
    plan: &crate::group::TransactionSpacePlan,
    a: &[u8; ROOT_SLOT_BYTES],
    b: &[u8; ROOT_SLOT_BYTES],
) -> Result<(), CoreError> {
    let RootSelection::Selected {
        superblock: root, ..
    } = select_root_images(a, b)?
    else {
        return Err(CoreError::InvalidInput(
            "transaction space requires an initialized root",
        ));
    };
    if root.group_id != plan.group_id
        || root.generation != plan.root_generation
        || root.pending_segment().is_some()
        || root.pending_directory().is_some()
        || plan.batch_seq == u64::MAX
        || plan.batch_seq <= root.directory.map_or(0, |commit| commit.start.batch_seq)
    {
        return Err(CoreError::InvalidInput(
            "transaction space differs from selected root",
        ));
    }
    // A caller-supplied floor cannot turn a Store envelope plus a truncated
    // native header into a completed physical file. These are canonical native
    // header widths; the installed backend adds its own envelope separately.
    if (plan.new_segments.count != 0
        && plan.new_segments.minimum_len != crate::segment::SEGMENT_HEADER_BYTES)
        || (plan.new_directories.count != 0
            && plan.new_directories.minimum_len != crate::arena::HEADER_BYTES as u64)
        || plan
            .segment
            .is_some_and(|tail| tail.initial_len < crate::segment::SEGMENT_HEADER_BYTES)
        || plan
            .directory
            .is_some_and(|tail| tail.initial_len < crate::arena::HEADER_BYTES as u64)
    {
        return Err(CoreError::InvalidInput(
            "transaction space native header minimum differs",
        ));
    }
    // Reopened directory writers intentionally start a fresh arena. An existing
    // tail, when supplied, must still be this group's newest confirmed file.
    if plan.segment.is_some_and(|tail| {
        tail.file != GroupFile::segment(root.last_segment_id) || root.last_segment_id == 0
    }) || plan.directory.is_some_and(|tail| {
        tail.file != GroupFile::directory(root.last_directory_id) || root.last_directory_id == 0
    }) || (plan.new_segments.count != 0 && plan.new_segments.first_id != root.next_segment_id)
        || (plan.new_directories.count != 0
            && plan.new_directories.first_id != root.next_directory_id)
    {
        return Err(CoreError::InvalidInput(
            "transaction space names a stale file range",
        ));
    }
    Ok(())
}

/// Publish `next` as the successor of the durable root `previous`
/// (generation zero for a new group). Validation failures precede every
/// effect: the slots must select exactly `previous`, or nothing for a new
/// group, so a `previous` the slots do not hold is refused unchanged. A
/// successor keeps every garbage record; only `publish_forget` drops one.
/// Restoring the previous copy is a plain I/O failure; any failure after the
/// first write of `next` is `UnknownCommit`: the caller fences and reopens.
pub(crate) fn publish_root(
    backend: &dyn SegmentGroupBackend,
    previous: &Superblock,
    next: &Superblock,
) -> Result<(), CoreError> {
    if previous
        .garbage
        .iter()
        .any(|file| next.garbage.binary_search(file).is_err())
    {
        return Err(CoreError::InvalidInput(
            "root publication drops garbage without an unlink proof",
        ));
    }
    publish(backend, previous, next)
}

/// Publish the successor of the durable root `previous` without the garbage
/// record whose confirmed unlink `unlinked` proves, and return it. Failures
/// are those of `publish_root`.
pub(crate) fn publish_forget(
    backend: &dyn SegmentGroupBackend,
    previous: &Superblock,
    unlinked: Unlinked,
) -> Result<Superblock, CoreError> {
    let next = previous.forget(unlinked)?;
    publish(backend, previous, &next)?;
    Ok(next)
}

fn publish(
    backend: &dyn SegmentGroupBackend,
    previous: &Superblock,
    next: &Superblock,
) -> Result<(), CoreError> {
    if !is_successor(previous, next) {
        return Err(CoreError::InvalidInput(
            "root publication is not a successor",
        ));
    }
    let bytes = next.encode()?;
    let first = RootSlot::for_generation(next.generation);
    // A caller that kept a stale root, for example after an unknown-outcome
    // publication made a newer generation durable, holds a `previous` the
    // slots no longer select, and a new group must have no root at all.
    let restore = match read_selection(backend)? {
        RootSelection::Empty if previous.generation == 0 => false,
        RootSelection::Selected {
            superblock,
            slot,
            mirrored,
        } if superblock == *previous => {
            // Reopen may have selected the only intact copy from the slot
            // this publication writes first.
            !mirrored && slot == first
        }
        RootSelection::Empty | RootSelection::Selected { .. } => {
            return Err(CoreError::InvalidInput(
                "root publication does not follow the selected root",
            ));
        }
    };
    if restore {
        backend.write_root(first.other(), &previous.encode()?)?;
        backend.sync_root()?;
    }
    for slot in [first, first.other()] {
        backend
            .write_root(slot, &bytes)
            .map_err(CoreError::UnknownCommit)?;
        backend.sync_root().map_err(CoreError::UnknownCommit)?;
    }
    Ok(())
}

/// The next generation of one group that moves no allocation back, never
/// replaces the checkpoint with an older one or moves its replay start back,
/// and changes the sealed record only with a new segment intent.
fn is_successor(previous: &Superblock, next: &Superblock) -> bool {
    let checkpoint_regressed = previous.checkpoint.is_some_and(|current| {
        next.checkpoint.is_none_or(|reference| {
            reference.id < current.id
                || (reference.id == current.id && reference != current)
                || reference.start_segment_id < current.start_segment_id
        })
    });
    previous.generation.checked_add(1) == Some(next.generation)
        && previous.group_id == next.group_id
        && next.next_segment_id >= previous.next_segment_id
        && next.last_segment_id >= previous.last_segment_id
        && next.next_checkpoint_id >= previous.next_checkpoint_id
        && next.next_directory_id >= previous.next_directory_id
        && next.last_directory_id >= previous.last_directory_id
        && directory::directory_successor(previous.directory, next.directory)
        && !checkpoint_regressed
        && (next.next_segment_id != previous.next_segment_id || next.sealed == previous.sealed)
}

/// Rewrite the slot other than `slot` with the selected superblock, never
/// touching the only intact copy. The slots must select `superblock` and
/// `slot` must hold it intact; otherwise nothing is written, so neither a
/// damaged slot nor a stale superblock replaces the intact newest root. A
/// failure leaves the selected slot intact.
pub(crate) fn repair_mirror(
    backend: &dyn SegmentGroupBackend,
    superblock: &Superblock,
    slot: RootSlot,
) -> Result<(), CoreError> {
    match read_selection(backend)? {
        // Unmirrored, only the selected slot holds the root intact.
        RootSelection::Selected {
            superblock: held,
            slot: held_slot,
            mirrored,
        } if held == *superblock && (mirrored || held_slot == slot) => {}
        RootSelection::Empty | RootSelection::Selected { .. } => {
            return Err(CoreError::InvalidInput(
                "mirror repair does not name the selected root slot",
            ));
        }
    }
    let bytes = superblock.encode()?;
    backend.write_root(slot.other(), &bytes)?;
    backend.sync_root()?;
    Ok(())
}

/// Segment allocation through durable root publications.
pub(crate) struct RootRoll<'a> {
    backend: &'a dyn SegmentGroupBackend,
    root: &'a mut Superblock,
}

impl<'a> RootRoll<'a> {
    pub(crate) fn new(backend: &'a dyn SegmentGroupBackend, root: &'a mut Superblock) -> Self {
        Self { backend, root }
    }
}

impl SegmentRoll for RootRoll<'_> {
    fn reserve(&mut self, sealed: Option<SealedSegment>) -> Result<u64, CoreError> {
        let (next, segment_id) = self.root.reserve_segment(sealed)?;
        publish_root(self.backend, self.root, &next)?;
        *self.root = next;
        Ok(segment_id)
    }

    fn confirm(&mut self, segment_id: u64) -> Result<(), CoreError> {
        let next = self.root.confirm_segment(segment_id)?;
        publish_root(self.backend, self.root, &next)?;
        *self.root = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::CheckpointHeader;
    use crate::group::{FaultTiming, GroupOp, InMemoryGroup};
    use crate::segment::test_support::{GROUP, corrupt_reason};
    use crate::segment::{LEGACY_MAGIC, LogPosition, ReplayStart};

    fn published(generations: u64) -> (InMemoryGroup, Superblock) {
        let group = InMemoryGroup::new();
        let mut root = Superblock::genesis(GROUP);
        for _ in 0..generations {
            let (next, _) = root.reserve_checkpoint().unwrap();
            publish_root(&group, &root, &next).unwrap();
            root = next;
        }
        (group, root)
    }

    fn selected(group: &InMemoryGroup) -> (Superblock, RootSlot, bool) {
        match select_root(group).unwrap() {
            RootSelection::Selected {
                superblock,
                slot,
                mirrored,
            } => (superblock, slot, mirrored),
            RootSelection::Empty => panic!("expected a selected root"),
        }
    }

    fn slot_bytes(group: &InMemoryGroup, slot: RootSlot) -> [u8; ROOT_SLOT_BYTES] {
        let mut bytes = [0u8; ROOT_SLOT_BYTES];
        group.read_root(slot, &mut bytes).unwrap();
        bytes
    }

    fn slots(group: &InMemoryGroup) -> ([u8; ROOT_SLOT_BYTES], [u8; ROOT_SLOT_BYTES]) {
        (
            slot_bytes(group, RootSlot::A),
            slot_bytes(group, RootSlot::B),
        )
    }

    fn reseal(bytes: &mut [u8]) {
        let checksum = crc32c(&bytes[..CHECKSUM_AT]);
        bytes[CHECKSUM_AT..].copy_from_slice(&checksum.to_le_bytes());
    }

    /// The newest segment as its successor's intent seals it.
    fn sealing(root: &Superblock) -> Option<SealedSegment> {
        (root.last_segment_id != 0).then_some(SealedSegment {
            segment_id: root.last_segment_id,
            len: 4096,
            commit_seq: root.last_segment_id,
        })
    }

    fn grown(root: &Superblock) -> Superblock {
        let (next, id) = root.reserve_segment(sealing(root)).unwrap();
        next.confirm_segment(id).unwrap()
    }

    fn reference(id: u64, start_segment_id: u64) -> CheckpointRef {
        CheckpointRef {
            id,
            len: 100 * id,
            start_segment_id,
            sha256: [id as u8; 32],
        }
    }

    /// The summary of checkpoint `reference(checkpoint_id, start_segment_id)`,
    /// which references values in `referenced`.
    fn summary(checkpoint_id: u64, start_segment_id: u64, referenced: &[u64]) -> CheckpointSummary {
        CheckpointSummary {
            reference: reference(checkpoint_id, start_segment_id),
            header: CheckpointHeader {
                group_id: GROUP,
                checkpoint_id,
                start: ReplayStart {
                    position: LogPosition {
                        segment_id: start_segment_id,
                        offset: 200,
                    },
                    batch_seq: 7,
                    chain: [7; 32],
                },
            },
            tables: 1,
            rows: referenced.len() as u64,
            live_bytes: 10 * referenced.len() as u64,
            segment_live_bytes: referenced.iter().map(|&id| (id, 10)).collect(),
        }
    }

    /// Four segments, checkpoint 2 replaying from segment 4 with values in
    /// segment 3, and segments 1 and 2 plus checkpoint 1 as garbage.
    fn rich() -> Superblock {
        let mut root = Superblock::genesis(GROUP);
        for _ in 0..4 {
            root = grown(&root);
        }
        let (next, _) = root.reserve_checkpoint().unwrap();
        let (next, _) = next.reserve_checkpoint().unwrap();
        let root = next.install_checkpoint(reference(1, 2)).unwrap();
        let root = root.install_checkpoint(reference(2, 4)).unwrap();
        let current = summary(2, 4, &[3]);
        let root = root.retire_segment(2, &current).unwrap();
        root.retire_segment(1, &current).unwrap()
    }

    #[test]
    fn superblock_round_trips_every_field() {
        let root = rich();
        assert_eq!(
            root.garbage,
            [
                GroupFile::segment(1),
                GroupFile::segment(2),
                GroupFile::checkpoint(1)
            ]
        );
        assert_eq!(root.sealed.map(|sealed| sealed.segment_id), Some(3));
        let bytes = root.encode().unwrap();
        assert_eq!(decode_slot(&bytes).unwrap(), SlotImage::Valid(root.clone()));
        let (next, id) = root.reserve_segment(sealing(&root)).unwrap();
        assert_eq!((id, next.pending_segment()), (5, Some(5)));
        assert_eq!(next.sealed.unwrap().segment_id, 4);
        assert_eq!(
            decode_slot(&next.encode().unwrap()).unwrap(),
            SlotImage::Valid(next)
        );
    }

    #[test]
    fn publication_mirrors_and_selects_the_newest_generation() {
        let (group, root) = published(3);
        let (selected_root, slot, mirrored) = selected(&group);
        assert_eq!(selected_root, root);
        assert_eq!((slot, mirrored), (RootSlot::A, true));
        assert_eq!(
            slot_bytes(&group, RootSlot::A),
            slot_bytes(&group, RootSlot::B)
        );
        assert_eq!(
            select_root(&InMemoryGroup::new()).unwrap(),
            RootSelection::Empty
        );
    }

    #[test]
    fn torn_publication_selects_the_previous_root() {
        let (group, root) = published(2);
        let (next, _) = root.reserve_segment(None).unwrap();
        group.fail(GroupOp::RootSync, 1, FaultTiming::BeforeEffect);
        assert!(matches!(
            publish_root(&group, &root, &next),
            Err(CoreError::UnknownCommit(_))
        ));
        // A one-byte tear rewrites the same magic byte and changes nothing.
        let restarted = group.crash_torn_root(RootSlot::for_generation(3), 1);
        assert_eq!(selected(&restarted), (root.clone(), RootSlot::A, true));
        // Longer tears reach the generation and break the slot checksum.
        for keep in [48, 100, CHECKSUM_AT] {
            let restarted = group.crash_torn_root(RootSlot::for_generation(3), keep);
            let (selected_root, slot, mirrored) = selected(&restarted);
            assert_eq!(selected_root, root, "{keep}");
            assert_eq!((slot, mirrored), (RootSlot::A, false));
            // The next publication overwrites the torn slot.
            publish_root(&restarted, &root, &next).unwrap();
            assert_eq!(
                selected(&restarted.crash()),
                (next.clone(), RootSlot::A, true)
            );
        }
    }

    #[test]
    fn torn_mirror_keeps_the_new_root_and_repair_restores_both_slots() {
        let (group, root) = published(2);
        let (next, _) = root.reserve_segment(None).unwrap();
        group.fail(GroupOp::RootSync, 2, FaultTiming::BeforeEffect);
        publish_root(&group, &root, &next).unwrap_err();
        let restarted = group.crash_torn_root(RootSlot::A, 64);
        let (selected_root, slot, mirrored) = selected(&restarted);
        assert_eq!(selected_root, next);
        assert_eq!((slot, mirrored), (RootSlot::B, false));
        // Naming the torn slot would rewrite the only intact copy.
        let before = slots(&restarted);
        assert!(matches!(
            repair_mirror(&restarted, &selected_root, RootSlot::A),
            Err(CoreError::InvalidInput(
                "mirror repair does not name the selected root slot"
            ))
        ));
        assert_eq!(slots(&restarted), before);
        repair_mirror(&restarted, &selected_root, slot).unwrap();
        assert_eq!(selected(&restarted.crash()), (next, RootSlot::A, true));
    }

    #[test]
    fn unmirrored_new_root_beside_the_previous_generation_is_selected() {
        let (group, root) = published(2);
        let (next, _) = root.reserve_segment(None).unwrap();
        group.fail(GroupOp::RootWrite, 2, FaultTiming::BeforeEffect);
        publish_root(&group, &root, &next).unwrap_err();
        let restarted = group.crash();
        let (selected_root, slot, mirrored) = selected(&restarted);
        assert_eq!(selected_root, next);
        assert_eq!((slot, mirrored), (RootSlot::B, false));
        // Slot A still holds generation 2 intact, but repairing from it would
        // roll the selected generation 3 back; naming A for 3 is the wrong
        // slot. Neither writes anything.
        let before = slots(&restarted);
        for (superblock, slot) in [(&root, RootSlot::A), (&next, RootSlot::A)] {
            assert!(matches!(
                repair_mirror(&restarted, superblock, slot),
                Err(CoreError::InvalidInput(_))
            ));
        }
        assert_eq!(slots(&restarted), before);
        repair_mirror(&restarted, &next, RootSlot::B).unwrap();
        assert_eq!(selected(&restarted.crash()), (next, RootSlot::A, true));
    }

    #[test]
    fn publication_refuses_a_predecessor_the_slots_do_not_select() {
        // A first publication over an established group.
        let (group, root) = published(6);
        let genesis = Superblock::genesis(GROUP);
        let (first, _) = genesis.reserve_segment(None).unwrap();
        let before = slots(&group);
        assert!(matches!(
            publish_root(&group, &genesis, &first),
            Err(CoreError::InvalidInput(
                "root publication does not follow the selected root"
            ))
        ));
        assert_eq!(slots(&group), before);
        assert_eq!(selected(&group.crash()), (root, RootSlot::A, true));

        // An unknown-outcome publication left generation 5 in its first slot,
        // durable or not; the caller still holds generation 4.
        for (op, nth, timing) in [
            (GroupOp::RootWrite, 2, FaultTiming::BeforeEffect),
            (GroupOp::RootSync, 2, FaultTiming::BeforeEffect),
            (GroupOp::RootSync, 1, FaultTiming::AfterEffect),
            (GroupOp::RootSync, 1, FaultTiming::BeforeEffect),
        ] {
            let (group, root) = published(4);
            let (newer, _) = root.reserve_checkpoint().unwrap();
            group.fail(op, nth, timing);
            assert!(matches!(
                publish_root(&group, &root, &newer),
                Err(CoreError::UnknownCommit(_))
            ));
            let before = slots(&group);
            let durable = selected(&group.crash());
            let (other, _) = root.reserve_segment(None).unwrap();
            assert!(
                matches!(
                    publish_root(&group, &root, &other),
                    Err(CoreError::InvalidInput(
                        "root publication does not follow the selected root"
                    ))
                ),
                "{op:?} {nth} {timing:?}"
            );
            assert_eq!(slots(&group), before);
            assert_eq!(selected(&group.crash()), durable);
            // Reopen selects what the slots hold and continues from it.
            let restarted = group.crash();
            let (reopened, _, _) = selected(&restarted);
            let (next, _) = reopened.reserve_segment(None).unwrap();
            publish_root(&restarted, &reopened, &next).unwrap();
            assert_eq!(selected(&restarted.crash()).0, next);
        }
    }

    #[test]
    fn selection_after_a_restart_without_power_loss_survives_power_loss() {
        let (group, root) = published(2);
        let (next, _) = root.reserve_checkpoint().unwrap();
        // Slot B holds generation 3 in the page cache only.
        group.fail(GroupOp::RootSync, 1, FaultTiming::BeforeEffect);
        assert!(matches!(
            publish_root(&group, &root, &next),
            Err(CoreError::UnknownCommit(_))
        ));
        // A failed synchronization at reopen is plain I/O.
        let failing = group.clone();
        failing.fail(GroupOp::RootSync, 1, FaultTiming::BeforeEffect);
        assert!(matches!(select_root(&failing), Err(CoreError::Io(_))));
        assert_eq!(selected(&group.crash()).0, root);
        // The same process restarts and selects generation 3, which must
        // stay selected after a later power loss.
        let served = selected(&group);
        assert_eq!(served, (next, RootSlot::B, false));
        assert_eq!(selected(&group.crash()), served);
    }

    #[test]
    fn publication_from_an_unmirrored_selection_keeps_one_intact_copy() {
        // Generation 4 in both slots, then its parity slot A is damaged, so
        // reopen selects the only intact copy from B: the slot generation 5
        // writes first.
        let (group, root) = published(4);
        let (next, _) = root.reserve_checkpoint().unwrap();
        // The first sync is the restored copy's; the second is slot B's.
        for nth in [1, 2] {
            let damaged = group.crash();
            damaged.with_durable_root(RootSlot::A, |bytes| bytes[100] ^= 1);
            assert_eq!(selected(&damaged), (root.clone(), RootSlot::B, false));
            damaged.fail(GroupOp::RootSync, nth, FaultTiming::BeforeEffect);
            let error = publish_root(&damaged, &root, &next).unwrap_err();
            // Whatever part of either slot write reached the medium, one
            // intact copy of generation 4 remains.
            for (slot, keep) in [RootSlot::A, RootSlot::B]
                .into_iter()
                .flat_map(|slot| [1, 48, 100, CHECKSUM_AT].map(|keep| (slot, keep)))
            {
                let restarted = damaged.crash_torn_root(slot, keep);
                let (selected_root, _, _) = selected(&restarted);
                assert_eq!(selected_root, root, "{nth} {slot:?} {keep}");
            }
            // Restoring the copy publishes nothing, so its failure is known.
            match nth {
                1 => assert!(matches!(error, CoreError::Io(_)), "{error:?}"),
                _ => assert!(matches!(error, CoreError::UnknownCommit(_)), "{error:?}"),
            }
        }
        // Without faults the publication restores the copy and completes.
        let fresh = group.crash();
        fresh.with_durable_root(RootSlot::A, |bytes| bytes[100] ^= 1);
        publish_root(&fresh, &root, &next).unwrap();
        assert_eq!(selected(&fresh.crash()), (next, RootSlot::A, true));
    }

    #[test]
    fn one_damaged_slot_never_rolls_back_and_two_fail_closed() {
        let (group, root) = published(4);
        for at in (0..ROOT_SLOT_BYTES)
            .step_by(7)
            .chain([CHECKSUM_AT, ROOT_SLOT_BYTES - 1])
        {
            for slot in [RootSlot::A, RootSlot::B] {
                let damaged = group.crash();
                damaged.with_durable_root(slot, |bytes| bytes[at] ^= 0x20);
                let (selected_root, selected_slot, _) = selected(&damaged);
                assert_eq!(selected_root, root, "{slot:?} byte {at}");
                assert_eq!(selected_slot, slot.other());
            }
            let damaged = group.crash();
            damaged.with_durable_root(RootSlot::A, |bytes| bytes[at] ^= 0x20);
            damaged.with_durable_root(RootSlot::B, |bytes| bytes[at] ^= 0x20);
            assert_eq!(corrupt_reason(select_root(&damaged)), "no intact root slot");
        }
    }

    #[test]
    fn checksum_valid_field_changes_fail_closed() {
        let bytes = rich().encode().unwrap();
        let entry = |index: usize| GARBAGE_AT + index * GARBAGE_ENTRY_BYTES;
        let cases: [(&str, usize, u8); 18] = [
            (
                "root slot has an unsupported layout",
                16,
                (FORMAT_VERSION + 1) as u8,
            ),
            ("root slot has an unsupported layout", 21, 1),
            (
                "root slot has an unsupported layout",
                GARBAGE_COUNT_AT + 5,
                1,
            ),
            ("root slot has an unsupported layout", CHECKPOINT_AT + 8, 1),
            ("root slot has an unsupported layout", SEALED_AT + 8, 1),
            ("root slot has an unsupported layout", 2000, 1),
            ("root slot has an unsupported layout", entry(0) + 1, 1),
            ("root generation is zero", 40, 0),
            ("root segment intent is invalid", 56, 9),
            ("root segment intent is invalid", 48, 9),
            ("root sealed segment record is invalid", SEALED_AT, 1),
            // A 4096-byte length loses its only nonzero byte.
            ("root sealed segment record is invalid", SEALED_AT + 9, 0),
            ("root checkpoint reference is invalid", CHECKPOINT_AT, 9),
            (
                "root checkpoint reference is invalid",
                CHECKPOINT_AT + 16,
                9,
            ),
            ("root garbage list is invalid", entry(0) + 8, 2),
            // A garbage segment at the checkpoint's replay start.
            ("root garbage list is invalid", entry(1) + 8, 4),
            ("root garbage list is invalid", entry(2) + 8, 2),
            ("root garbage entry has an unknown kind", entry(0), 7),
        ];
        for (reason, at, value) in cases {
            let mut image = bytes;
            if at == CHECKPOINT_AT + 8 {
                // A reference-free root must carry no length or digest.
                image[CHECKPOINT_AT..CHECKPOINT_AT + 8].fill(0);
            }
            if at == SEALED_AT + 8 {
                image[SEALED_AT..SEALED_AT + 8].fill(0);
            }
            image[at] = value;
            reseal(&mut image);
            assert_eq!(corrupt_reason(decode_slot(&image)), reason, "{at}");
        }
    }

    #[test]
    fn slot_pairs_must_be_one_group_and_adjacent_publications() {
        let (group, root) = published(2);
        // Same generation, different content.
        let mut other = root.clone();
        other.next_checkpoint_id += 1;
        let image = other.encode().unwrap();
        let damaged = group.crash();
        damaged.with_durable_root(RootSlot::B, |bytes| bytes.copy_from_slice(&image));
        assert_eq!(
            corrupt_reason(select_root(&damaged)),
            "root slots disagree at one generation"
        );
        // A slot from another group.
        let mut foreign = root.clone();
        foreign.group_id = *b"another-group-01";
        let image = foreign.encode().unwrap();
        let damaged = group.crash();
        damaged.with_durable_root(RootSlot::B, |bytes| bytes.copy_from_slice(&image));
        assert_eq!(
            corrupt_reason(select_root(&damaged)),
            "root slots name different groups"
        );
        // Generations two apart, or a newer root in the wrong slot.
        for generation in [root.generation + 2, root.generation + 1] {
            let mut skipped = root.clone();
            skipped.generation = generation;
            let image = skipped.encode().unwrap();
            let slot = RootSlot::for_generation(generation).other();
            let damaged = group.crash();
            damaged.with_durable_root(slot, |bytes| bytes.copy_from_slice(&image));
            assert_eq!(
                corrupt_reason(select_root(&damaged)),
                "root slots are not adjacent publications"
            );
        }
        // Erasing one slot of an established root.
        let damaged = group.crash();
        damaged.with_durable_root(RootSlot::B, |bytes| bytes.fill(0));
        assert_eq!(
            corrupt_reason(select_root(&damaged)),
            "a published root slot was erased"
        );
    }

    #[test]
    fn torn_first_publication_is_an_empty_group_that_owns_no_files() {
        let group = InMemoryGroup::new();
        let genesis = Superblock::genesis(GROUP);
        let (next, _) = genesis.reserve_segment(None).unwrap();
        group.fail(GroupOp::RootSync, 1, FaultTiming::BeforeEffect);
        publish_root(&group, &genesis, &next).unwrap_err();
        let restarted = group.crash_torn_root(RootSlot::B, 30);
        assert_eq!(select_root(&restarted).unwrap(), RootSelection::Empty);
        assert_eq!(genesis.census(&restarted).unwrap(), Census::default());
        // The group has no root yet, so the first publication may repeat.
        let retried = restarted.crash();
        publish_root(&retried, &genesis, &next).unwrap();
        assert_eq!(selected(&retried.crash()), (next, RootSlot::A, true));
        restarted.insert_foreign(GroupFile::segment(1), Vec::new());
        assert_eq!(
            corrupt_reason(genesis.census(&restarted)),
            "group holds a file its root never allocated"
        );
        // A torn mirror slot without its first publication is damage.
        let damaged = InMemoryGroup::new();
        damaged.with_durable_root(RootSlot::A, |bytes| bytes[0] = 1);
        assert_eq!(corrupt_reason(select_root(&damaged)), "no intact root slot");
    }

    #[test]
    fn retired_root_is_never_treated_as_a_torn_or_missing_publication() {
        let (_, root) = published(1);
        let current = root.encode().unwrap();
        let mut retired = current;
        retired[..16].copy_from_slice(b"KASUMI-KVROOT001");
        reseal(&mut retired);
        for other in [[0; ROOT_SLOT_BYTES], current, retired] {
            for slot in [RootSlot::A, RootSlot::B] {
                let group = InMemoryGroup::new();
                group.write_root(slot, &retired).unwrap();
                group.write_root(slot.other(), &other).unwrap();
                group.sync_root().unwrap();
                assert_eq!(
                    corrupt_reason(select_root(&group)),
                    "retired root format is unsupported"
                );
            }
        }
    }

    #[test]
    fn legacy_single_file_header_is_rejected() {
        let mut legacy = [0u8; ROOT_SLOT_BYTES];
        legacy[..16].copy_from_slice(&LEGACY_MAGIC);
        legacy[16..20].copy_from_slice(&2u32.to_le_bytes());
        reseal(&mut legacy);
        for slot in [RootSlot::A, RootSlot::B] {
            let (group, _) = published(2);
            group.with_durable_root(slot, |bytes| bytes.copy_from_slice(&legacy));
            assert_eq!(
                corrupt_reason(select_root(&group)),
                "unsupported KASUMI-KV-000001 single-file image"
            );
        }
    }

    #[test]
    fn intents_and_census_follow_the_root() {
        let group = InMemoryGroup::new();
        let root = rich();
        let (reserved, _) = root.reserve_segment(sealing(&root)).unwrap();
        assert!(reserved.reserve_segment(sealing(&reserved)).is_err());
        assert!(root.confirm_segment(5).is_err());
        // The intent must record the newest segment as sealed.
        for wrong in [
            None,
            Some(SealedSegment {
                segment_id: 3,
                len: 4096,
                commit_seq: 1,
            }),
            Some(SealedSegment {
                segment_id: 4,
                len: SEGMENT_HEADER_BYTES - 1,
                commit_seq: 1,
            }),
        ] {
            assert!(root.reserve_segment(wrong).is_err(), "{wrong:?}");
        }
        let (next, pending) = root.reserve_segment(sealing(&root)).unwrap();
        let (next, orphan) = next.reserve_checkpoint().unwrap();
        for file in [
            GroupFile::segment(1),
            GroupFile::segment(3),
            GroupFile::segment(4),
            GroupFile::segment(pending),
            GroupFile::checkpoint(2),
            GroupFile::checkpoint(orphan),
        ] {
            group.insert_foreign(file, Vec::new());
        }
        assert_eq!(next.classify(GroupFile::segment(1)), FileRole::Garbage);
        assert_eq!(next.classify(GroupFile::segment(3)), FileRole::Live);
        assert_eq!(
            next.classify(GroupFile::segment(pending)),
            FileRole::PendingCreate
        );
        assert_eq!(
            next.classify(GroupFile::segment(pending + 1)),
            FileRole::Unexpected
        );
        assert_eq!(next.classify(GroupFile::checkpoint(2)), FileRole::Live);
        assert_eq!(
            next.classify(GroupFile::checkpoint(orphan)),
            FileRole::Orphan
        );
        assert_eq!(
            next.classify(GroupFile::checkpoint(0)),
            FileRole::Unexpected
        );
        let census = next.census(&group).unwrap();
        assert_eq!(census.live_segments, [3, 4]);
        assert_eq!(census.orphans, [GroupFile::checkpoint(orphan)]);
        assert_eq!(census.garbage_present, [GroupFile::segment(1)]);
        assert_eq!(
            census.garbage_unlink_pending,
            [GroupFile::segment(2), GroupFile::checkpoint(1)]
        );
        let retired = next.retire_checkpoint(orphan).unwrap();
        assert!(retired.garbage.contains(&GroupFile::checkpoint(orphan)));
        assert!(next.retire_checkpoint(2).is_err());
        assert!(next.retire_checkpoint(orphan + 1).is_err());

        group.remove_foreign(GroupFile::checkpoint(2));
        assert_eq!(
            corrupt_reason(next.census(&group)),
            "referenced checkpoint is missing"
        );
    }

    struct CensusCleanupBackend {
        group: InMemoryGroup,
        replacement: Option<&'static str>,
    }

    impl SegmentGroupBackend for CensusCleanupBackend {
        fn reserve_transaction(
            &self,
            plan: &crate::TransactionSpacePlan,
        ) -> std::result::Result<(), crate::TransactionReserveError> {
            self.group.reserve_transaction(plan)
        }
        fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.group.finish_transaction(group_id, batch_seq)
        }
        fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.group.cancel_transaction(group_id, batch_seq)
        }

        fn read_root(
            &self,
            slot: RootSlot,
            out: &mut [u8; ROOT_SLOT_BYTES],
        ) -> std::io::Result<()> {
            self.group.read_root(slot, out)
        }
        fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> std::io::Result<()> {
            self.group.write_root(slot, bytes)
        }
        fn sync_root(&self) -> std::io::Result<()> {
            self.group.sync_root()
        }
        fn visit_entries(
            &self,
            visitor: &mut dyn FnMut(&std::ffi::OsStr) -> std::io::Result<()>,
        ) -> std::io::Result<()> {
            let result = self.group.visit_entries(visitor);
            if let Some(message) = self.replacement {
                Err(std::io::Error::other(message))
            } else {
                result
            }
        }
        fn exists(&self, file: GroupFile) -> std::io::Result<bool> {
            self.group.exists(file)
        }
        fn create(&self, file: GroupFile) -> std::io::Result<()> {
            self.group.create(file)
        }
        fn len(&self, file: GroupFile) -> std::io::Result<u64> {
            self.group.len(file)
        }
        fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> std::io::Result<()> {
            self.group.read(file, at, out)
        }
        fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> std::io::Result<()> {
            self.group.write(file, at, bytes)
        }
        fn set_len(&self, file: GroupFile, length: u64) -> std::io::Result<()> {
            self.group.set_len(file, length)
        }
        fn sync(&self, file: GroupFile) -> std::io::Result<()> {
            self.group.sync(file)
        }
        fn unlink(&self, file: GroupFile) -> std::io::Result<()> {
            self.group.unlink(file)
        }
        fn sync_names(&self) -> std::io::Result<()> {
            self.group.sync_names()
        }
        fn close(&self) -> crate::core::BackendCloseOutcome {
            self.group.close()
        }
    }

    #[test]
    fn census_preserves_callback_error_only_when_its_sentinel_returns() {
        let group = InMemoryGroup::new();
        let root = grown(&Superblock::genesis(GROUP));
        group.insert_foreign(GroupFile::segment(1), Vec::new());
        let backend = CensusCleanupBackend {
            group,
            replacement: None,
        };
        assert!(matches!(
            root.visit_census(&backend, |_| Err(CoreError::CapacityDenied)),
            Err(CoreError::CapacityDenied)
        ));
        for message in ["cursor close failed", "group census visitor stopped"] {
            let backend = CensusCleanupBackend {
                group: backend.group.clone(),
                replacement: Some(message),
            };
            let error = root
                .visit_census(&backend, |_| Err(CoreError::CapacityDenied))
                .unwrap_err();
            assert!(error.fences_owner());
            assert!(matches!(error, CoreError::Io(ref error) if error.to_string() == message));
        }
    }

    #[test]
    fn empty_initialization_is_mirrored_and_cannot_run_twice() {
        let group = InMemoryGroup::new();
        let genesis = Superblock::genesis(GROUP);
        let initialized = genesis.initialized().unwrap();
        assert_eq!(initialized.generation(), 1);
        assert_eq!(initialized.last_segment_id(), 0);
        assert!(initialized.directory().is_none());
        publish_root(&group, &genesis, &initialized).unwrap();
        assert!(
            matches!(select_root(&group).unwrap(), RootSelection::Selected { superblock, mirrored: true, .. } if superblock == initialized)
        );
        initialized.visit_census(&group, |_| Ok(())).unwrap();
        let before = [
            slot_bytes(&group, RootSlot::A),
            slot_bytes(&group, RootSlot::B),
        ];
        assert!(matches!(
            initialized.initialized(),
            Err(CoreError::InvalidInput(_))
        ));
        assert_eq!(
            before,
            [
                slot_bytes(&group, RootSlot::A),
                slot_bytes(&group, RootSlot::B)
            ]
        );
    }

    #[test]
    fn retired_root_slots_are_rejected_even_beside_current_root() {
        for magic in [b"KASUMI-KVROOT001", b"KASUMI-KVROOT002"] {
            for slot in [RootSlot::A, RootSlot::B] {
                let (group, root) = published(2);
                let mut bytes = root.encode().unwrap();
                bytes[..16].copy_from_slice(magic);
                let checksum = crc32c(&bytes[..CHECKSUM_AT]);
                bytes[CHECKSUM_AT..].copy_from_slice(&checksum.to_le_bytes());
                group.write_root(slot, &bytes).unwrap();
                group.sync_root().unwrap();
                assert_eq!(
                    corrupt_reason(select_root(&group)),
                    "retired root format is unsupported"
                );
            }
        }
    }

    #[test]
    fn census_fails_closed_on_entries_that_are_not_group_files() {
        let root = rich();
        for name in [
            "0000000000000003.kvseg.tmp",
            "0000000000000003.KVSEG",
            "000000000000000A.kvckpt",
            "3.kvseg",
            "notes.txt",
            "root.kvroot~",
        ] {
            let group = InMemoryGroup::new();
            group.insert_foreign(GroupFile::segment(3), Vec::new());
            group.insert_foreign(GroupFile::checkpoint(2), Vec::new());
            root.census(&group).unwrap();
            group.insert_stray(name);
            assert_eq!(
                corrupt_reason(root.census(&group)),
                "group directory holds an entry that is not a group file",
                "{name}"
            );
        }
    }

    #[test]
    fn retirement_needs_a_checkpoint_that_no_longer_uses_the_segment() {
        let mut root = Superblock::genesis(GROUP);
        for _ in 0..4 {
            root = grown(&root);
        }
        let (root, id) = root.reserve_checkpoint().unwrap();
        // Without a checkpoint nothing retires, not even the oldest segment.
        assert!(matches!(
            root.retire_segment(1, &summary(id, 3, &[])),
            Err(CoreError::InvalidInput(_))
        ));
        for start in [0, 5] {
            assert!(root.install_checkpoint(reference(id, start)).is_err());
        }
        let installed = root.install_checkpoint(reference(id, 3)).unwrap();
        let current = summary(id, 3, &[1]);
        // A referenced value, the replay start, the newest segment, and
        // identifiers the root never confirmed all stay.
        for segment_id in [0, 1, 3, 4, 5] {
            assert!(
                matches!(
                    installed.retire_segment(segment_id, &current),
                    Err(CoreError::InvalidInput(_))
                ),
                "{segment_id}"
            );
        }
        // Only the installed checkpoint's own summary is accepted.
        for other in [summary(id, 4, &[]), summary(id + 1, 3, &[])] {
            assert!(installed.retire_segment(2, &other).is_err());
        }
        // A stale or hand-built summary with the right identifier and replay
        // start but another digest or length would free segment 1.
        for forged in [
            CheckpointRef {
                sha256: [0xee; 32],
                ..current.reference
            },
            CheckpointRef {
                len: current.reference.len + 16,
                ..current.reference
            },
        ] {
            let stale = CheckpointSummary {
                reference: forged,
                segment_live_bytes: Vec::new(),
                ..current.clone()
            };
            assert!(matches!(
                installed.retire_segment(1, &stale),
                Err(CoreError::InvalidInput(
                    "checkpoint summary is not the installed checkpoint"
                ))
            ));
        }
        let retired = installed.retire_segment(2, &current).unwrap();
        assert_eq!(retired.garbage, [GroupFile::segment(2)]);
        assert!(retired.retire_segment(2, &current).is_err());
        // A later checkpoint never moves the replay start back.
        let (reserved, later) = retired.reserve_checkpoint().unwrap();
        assert!(reserved.install_checkpoint(reference(later, 2)).is_err());
        let moved = reserved.install_checkpoint(reference(later, 4)).unwrap();
        moved.retire_segment(3, &summary(later, 4, &[1])).unwrap();
    }

    #[test]
    fn full_garbage_list_is_a_recoverable_denial() {
        let group = InMemoryGroup::new();
        let mut root = Superblock::genesis(GROUP);
        for _ in 0..=MAX_GARBAGE + 1 {
            let (next, id) = root.reserve_segment(sealing(&root)).unwrap();
            advance(&group, &mut root, next);
            let next = root.confirm_segment(id).unwrap();
            advance(&group, &mut root, next);
        }
        let (next, id) = root.reserve_checkpoint().unwrap();
        advance(&group, &mut root, next);
        let start = MAX_GARBAGE as u64 + 2;
        let next = root.install_checkpoint(reference(id, start)).unwrap();
        advance(&group, &mut root, next);
        let current = summary(id, start, &[]);
        for segment_id in 1..=MAX_GARBAGE as u64 {
            let next = root.retire_segment(segment_id, &current).unwrap();
            advance(&group, &mut root, next);
        }
        let full = root.encode().unwrap();
        assert_eq!(decode_slot(&full).unwrap(), SlotImage::Valid(root.clone()));
        assert!(matches!(
            root.retire_segment(MAX_GARBAGE as u64 + 1, &current),
            Err(CoreError::CapacityDenied)
        ));
        let unlinked = root.unlink_garbage(&group, GroupFile::segment(1)).unwrap();
        let root = publish_forget(&group, &root, unlinked).unwrap();
        assert_eq!(selected(&group.crash()).0, root);
        root.retire_segment(MAX_GARBAGE as u64 + 1, &current)
            .unwrap();
    }

    fn advance(group: &InMemoryGroup, root: &mut Superblock, next: Superblock) {
        publish_root(group, root, &next).unwrap();
        *root = next;
    }

    /// Four created segments and created checkpoint 1, which replays from
    /// segment 3 and references values in segment 2; every step published.
    fn with_checkpoint() -> (InMemoryGroup, Superblock) {
        let group = InMemoryGroup::new();
        let mut root = Superblock::genesis(GROUP);
        for _ in 0..4 {
            let (next, id) = root.reserve_segment(sealing(&root)).unwrap();
            advance(&group, &mut root, next);
            group.create(GroupFile::segment(id)).unwrap();
            let next = root.confirm_segment(id).unwrap();
            advance(&group, &mut root, next);
        }
        let (next, id) = root.reserve_checkpoint().unwrap();
        advance(&group, &mut root, next);
        group.create(GroupFile::checkpoint(id)).unwrap();
        let next = root.install_checkpoint(reference(id, 3)).unwrap();
        advance(&group, &mut root, next);
        (group, root)
    }

    #[test]
    fn garbage_leaves_the_root_only_after_a_confirmed_unlink() {
        let (group, mut root) = with_checkpoint();
        let next = root.retire_segment(1, &summary(1, 3, &[2])).unwrap();
        advance(&group, &mut root, next);
        let retired = GroupFile::segment(1);

        // The unlink removes the name, but its parent synchronization fails.
        group.fail(GroupOp::Unlink, 1, FaultTiming::AfterEffect);
        assert!(matches!(
            root.unlink_garbage(&group, retired),
            Err(CoreError::Io(_))
        ));
        // The same process no longer lists the file, which proves nothing:
        // after power loss it returns, and only the record keeps it garbage.
        let census = root.census(&group).unwrap();
        assert_eq!(census.garbage_unlink_pending, [retired]);
        assert!(census.garbage_present.is_empty());
        let power_loss = group.crash();
        assert!(power_loss.exists(retired).unwrap());
        assert_eq!(root.census(&power_loss).unwrap().garbage_present, [retired]);
        // Without the record the file would count as live, so no successor
        // may drop it on the evidence of the listing.
        let mut dropped = root.successor().unwrap();
        dropped.garbage.clear();
        assert_eq!(dropped.classify(retired), FileRole::Live);
        assert!(matches!(
            publish_root(&group, &root, &dropped),
            Err(CoreError::InvalidInput(
                "root publication drops garbage without an unlink proof"
            ))
        ));

        // Only the proof a successful unlink returns drops the record.
        let unlinked = root.unlink_garbage(&group, retired).unwrap();
        root = publish_forget(&group, &root, unlinked).unwrap();
        let restarted = group.crash();
        assert!(!restarted.exists(retired).unwrap());
        let (reopened, _, mirrored) = selected(&restarted);
        assert_eq!((&reopened, mirrored), (&root, true));
        let census = reopened.census(&restarted).unwrap();
        assert_eq!(census.live_segments, [2, 3, 4]);
        assert!(census.garbage_unlink_pending.is_empty());
        // Only recorded garbage is unlinked this way.
        assert!(
            reopened
                .unlink_garbage(&restarted, GroupFile::segment(2))
                .is_err()
        );
        assert!(restarted.exists(GroupFile::segment(2)).unwrap());
    }

    #[test]
    fn garbage_unlink_follows_only_the_mirrored_selected_root() {
        let retired = GroupFile::segment(1);
        let current = summary(1, 3, &[2]);

        // A successor that was never published records the file as garbage,
        // but the durable root still counts it live.
        let (group, mut root) = with_checkpoint();
        let unpublished = root.retire_segment(1, &current).unwrap();
        let before = slots(&group);
        assert!(matches!(
            unpublished.unlink_garbage(&group, retired),
            Err(CoreError::InvalidInput(
                "garbage unlink does not follow the selected root"
            ))
        ));
        assert!(group.exists(retired).unwrap());
        assert_eq!(slots(&group), before);
        let restarted = group.crash();
        assert!(restarted.exists(retired).unwrap());
        assert_eq!(selected(&restarted).0, root);
        assert_eq!(root.census(&restarted).unwrap().live_segments, [1, 2, 3, 4]);

        // Once published, a stale copy of that root is refused as well.
        advance(&group, &mut root, unpublished);
        let stale = root.clone();
        let (next, _) = root.reserve_checkpoint().unwrap();
        advance(&group, &mut root, next);
        assert!(matches!(
            stale.unlink_garbage(&group, retired),
            Err(CoreError::InvalidInput(
                "garbage unlink does not follow the selected root"
            ))
        ));
        assert!(group.exists(retired).unwrap());
        let unlinked = root.unlink_garbage(&group, retired).unwrap();
        let root = publish_forget(&group, &root, unlinked).unwrap();
        assert!(!group.crash().exists(retired).unwrap());
        assert_eq!(selected(&group.crash()).0, root);

        // A publication with an unknown outcome: the first slot's
        // synchronization fails, leaving the successor in the page cache
        // only, or the mirror's does. The unlink synchronizes the root file
        // first, so the successor recording the file is durable before any
        // unlink, and only a mirrored one unlinks.
        for (nth, mirrored) in [(1, false), (2, true)] {
            let (group, root) = with_checkpoint();
            let retiring = root.retire_segment(1, &current).unwrap();
            group.fail(GroupOp::RootSync, nth, FaultTiming::BeforeEffect);
            assert!(matches!(
                publish_root(&group, &root, &retiring),
                Err(CoreError::UnknownCommit(_))
            ));
            let result = retiring.unlink_garbage(&group, retired);
            if mirrored {
                drop(result.unwrap());
                assert!(!group.exists(retired).unwrap());
            } else {
                assert!(matches!(
                    result,
                    Err(CoreError::InvalidInput(
                        "garbage unlink waits for both root slots"
                    ))
                ));
                assert!(group.exists(retired).unwrap());
            }
            // After power loss the file is recorded garbage, never a live
            // segment that is missing.
            let restarted = group.crash();
            let (reopened, slot, reopened_mirrored) = selected(&restarted);
            assert_eq!(
                (&reopened, reopened_mirrored),
                (&retiring, mirrored),
                "{nth}"
            );
            let census = reopened.census(&restarted).unwrap();
            assert_eq!(census.live_segments, [2, 3, 4], "{nth}");
            if mirrored {
                assert_eq!(census.garbage_unlink_pending, [retired]);
                assert!(census.garbage_present.is_empty());
            } else {
                assert_eq!(census.garbage_present, [retired]);
                assert!(matches!(
                    reopened.unlink_garbage(&restarted, retired),
                    Err(CoreError::InvalidInput(
                        "garbage unlink waits for both root slots"
                    ))
                ));
                repair_mirror(&restarted, &reopened, slot).unwrap();
            }
            // The reopened owner completes the unlink and drops the record.
            let unlinked = reopened.unlink_garbage(&restarted, retired).unwrap();
            let forgotten = publish_forget(&restarted, &reopened, unlinked).unwrap();
            let again = restarted.crash();
            assert!(!again.exists(retired).unwrap());
            assert_eq!(selected(&again).0, forgotten);
        }

        // A failed synchronization of the root file unlinks nothing.
        let (group, mut root) = with_checkpoint();
        let next = root.retire_segment(1, &current).unwrap();
        advance(&group, &mut root, next);
        group.fail(GroupOp::RootSync, 1, FaultTiming::BeforeEffect);
        assert!(matches!(
            root.unlink_garbage(&group, retired),
            Err(CoreError::Io(_))
        ));
        assert!(group.exists(retired).unwrap());
        assert!(group.crash().exists(retired).unwrap());
        drop(root.unlink_garbage(&group, retired).unwrap());
        assert!(!group.crash().exists(retired).unwrap());
    }

    #[test]
    fn identifier_ceiling_roots_fail_closed_without_overflow() {
        let bytes = rich().encode().unwrap();
        let with = |fields: &[(usize, u64)]| {
            let mut image = bytes;
            for &(at, value) in fields {
                image[at..at + 8].copy_from_slice(&value.to_le_bytes());
            }
            reseal(&mut image);
            image
        };
        // Checksum-valid images whose next identifier is the last one. They
        // used to decode and then overflow in the census and replay bounds.
        let segment_ceiling = with(&[
            (48, u64::MAX),
            (56, u64::MAX - 1),
            (SEALED_AT, u64::MAX - 2),
        ]);
        assert_eq!(
            corrupt_reason(decode_slot(&segment_ceiling)),
            "root segment intent is invalid"
        );
        let checkpoint_ceiling = with(&[(64, u64::MAX)]);
        assert_eq!(
            corrupt_reason(decode_slot(&checkpoint_ceiling)),
            "root checkpoint reference is invalid"
        );

        // Just below the ceiling, with an outstanding intent, every derived
        // value fits.
        let near = with(&[
            (48, u64::MAX - 1),
            (56, u64::MAX - 3),
            (SEALED_AT, u64::MAX - 3),
            (64, u64::MAX - 1),
        ]);
        let SlotImage::Valid(root) = decode_slot(&near).unwrap() else {
            panic!("near-ceiling root does not decode");
        };
        assert_eq!(root.pending_segment(), Some(u64::MAX - 2));
        assert_eq!(root.log_bounds().pending_segment, Some(u64::MAX - 2));
        assert_eq!(
            root.classify(GroupFile::segment(u64::MAX - 2)),
            FileRole::PendingCreate
        );
        for id in [u64::MAX - 1, u64::MAX] {
            assert_eq!(root.classify(GroupFile::segment(id)), FileRole::Unexpected);
            assert_eq!(
                root.classify(GroupFile::checkpoint(id)),
                FileRole::Unexpected
            );
        }
        let group = InMemoryGroup::new();
        for file in [
            GroupFile::segment(3),
            GroupFile::segment(4),
            GroupFile::segment(u64::MAX - 2),
            GroupFile::checkpoint(2),
        ] {
            group.insert_foreign(file, Vec::new());
        }
        assert_eq!(root.census(&group).unwrap().live_segments, [3, 4]);
        // Neither kind allocates the last identifier.
        let confirmed = root.confirm_segment(u64::MAX - 2).unwrap();
        assert_eq!(
            decode_slot(&confirmed.encode().unwrap()).unwrap(),
            SlotImage::Valid(confirmed.clone())
        );
        assert!(matches!(
            confirmed.reserve_segment(sealing(&confirmed)),
            Err(CoreError::InvalidInput("segment identifier overflow"))
        ));
        assert!(matches!(
            confirmed.reserve_checkpoint(),
            Err(CoreError::InvalidInput("checkpoint identifier overflow"))
        ));
    }

    #[test]
    fn publication_refuses_dropped_garbage_and_regressed_state() {
        let group = InMemoryGroup::new();
        let mut root = Superblock::genesis(GROUP);
        for _ in 0..2 {
            let (next, id) = root.reserve_segment(sealing(&root)).unwrap();
            advance(&group, &mut root, next);
            let next = root.confirm_segment(id).unwrap();
            advance(&group, &mut root, next);
        }
        let (next, first) = root.reserve_checkpoint().unwrap();
        advance(&group, &mut root, next);
        let (next, second) = root.reserve_checkpoint().unwrap();
        advance(&group, &mut root, next);
        let next = root.install_checkpoint(reference(first, 1)).unwrap();
        advance(&group, &mut root, next);
        let stale = root.clone();
        let next = root.install_checkpoint(reference(second, 2)).unwrap();
        advance(&group, &mut root, next);
        let recorded = GroupFile::checkpoint(first);
        assert_eq!(root.garbage(), [recorded]);
        let before = slots(&group);

        // A copy with its garbage cleared, and a successor built through the
        // transitions of an older root that never held the record.
        let mut cleared = root.successor().unwrap();
        cleared.garbage.clear();
        let mut derived = stale.clone();
        while derived.generation() <= root.generation() {
            derived = derived.reserve_checkpoint().unwrap().0;
        }
        for candidate in [&cleared, &derived] {
            assert!(
                matches!(
                    publish_root(&group, &root, candidate),
                    Err(CoreError::InvalidInput(
                        "root publication drops garbage without an unlink proof"
                    ))
                ),
                "{candidate:?}"
            );
        }
        // A sealed record changed without a new intent.
        let mut resealed = root.successor().unwrap();
        resealed.sealed = resealed.sealed.map(|sealed| SealedSegment {
            len: sealed.len + 1,
            ..sealed
        });
        assert!(matches!(
            publish_root(&group, &root, &resealed),
            Err(CoreError::InvalidInput(
                "root publication is not a successor"
            ))
        ));
        // A proof from another group's root drops nothing.
        let foreign = Unlinked {
            group_id: *b"another-group-01",
            file: recorded,
        };
        assert!(matches!(
            publish_forget(&group, &root, foreign),
            Err(CoreError::InvalidInput(_))
        ));
        assert_eq!(slots(&group), before);

        let unlinked = root.unlink_garbage(&group, recorded).unwrap();
        root = publish_forget(&group, &root, unlinked).unwrap();
        assert!(root.garbage().is_empty());
        // The older root would now reference the unlinked checkpoint again.
        let mut regressed = stale;
        while regressed.generation() <= root.generation() {
            regressed = regressed.reserve_checkpoint().unwrap().0;
        }
        let before = slots(&group);
        assert!(matches!(
            publish_root(&group, &root, &regressed),
            Err(CoreError::InvalidInput(
                "root publication is not a successor"
            ))
        ));
        assert_eq!(slots(&group), before);
        assert_eq!(selected(&group.crash()).0, root);
    }

    #[test]
    fn non_successor_publication_has_no_effect() {
        let (group, root) = published(2);
        let before = slots(&group);
        let (next, _) = root.reserve_segment(None).unwrap();
        let mut skipped = next.clone();
        skipped.generation += 1;
        let mut regressed = next.clone();
        regressed.next_checkpoint_id = 1;
        let mut foreign = next.clone();
        foreign.group_id = [9; 16];
        for candidate in [skipped, regressed, foreign, root.clone()] {
            assert!(matches!(
                publish_root(&group, &root, &candidate),
                Err(CoreError::InvalidInput(_))
            ));
        }
        // A stale predecessor the slots do not hold is refused as well.
        let mut stale = root.clone();
        stale.next_checkpoint_id += 1;
        let (stale_next, _) = stale.reserve_checkpoint().unwrap();
        assert!(matches!(
            publish_root(&group, &stale, &stale_next),
            Err(CoreError::InvalidInput(_))
        ));
        assert_eq!(slots(&group), before);
    }
}

#[cfg(test)]
#[path = "root_space_tests.rs"]
mod space_tests;
