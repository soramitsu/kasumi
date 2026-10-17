//! The persisted compaction cycle carried by every `KASUMI-KVROOT005` slot.
//!
//! One maintenance machine per group moves through
//! `Idle -> Evacuating -> Reclaiming -> Packing -> Idle`. A phase changes only
//! through its own root publication, so a torn write selects either the old
//! or the new record and an unknown outcome is decided by reopen. Progress
//! inside Evacuating is an exact ordinal in the immutable cycle-start worklist,
//! published with each relocation or skip. Packing keeps a logical lower-bound
//! cursor and remaining per-level work budget, published on every step. A
//! truncated cursor can repeat reads after reopen, but never reset the budget. Allocation,
//! retirement, forget and replay publications clone the record unchanged.
//!
//! The cutoffs are frozen when a cycle begins: every segment and arena with an
//! identifier at or below them predates the cycle, while every value or page
//! written after the beginning lands in the active (or a newer) file, whose
//! identifier is above them. The baseline is the retained size measured when
//! the last cycle finished reclaiming, less the files it kept only for pinned
//! roots; it schedules the next cycle.

use super::directory::DIRECTORY_END;
use super::{CHECKSUM_AT, CoreError, Superblock};
use crate::core::MAX_TABLE_BYTES;
use crate::directory::{DIRECTORY_ROOT_BYTES, DirectoryKey, DirectoryRoot, MAX_HEIGHT};
use crate::segment::{le_u16, le_u64};

pub(super) const COMPACTION_AT: usize = DIRECTORY_END;
const RECORD_HEADER_BYTES: usize = 64;
/// Fixed cursor capacity: a complete table name plus a row-key prefix.
pub(crate) const MAX_CURSOR_BYTES: usize = 1536;
const SOURCE_AT: usize = RECORD_HEADER_BYTES + MAX_CURSOR_BYTES;
pub(super) const COMPACTION_END: usize = COMPACTION_AT + SOURCE_AT + DIRECTORY_ROOT_BYTES;

const _: () = assert!(COMPACTION_END <= CHECKSUM_AT);
// A complete table name always fits beside at least part of a row prefix.
const _: () = assert!(MAX_TABLE_BYTES < MAX_CURSOR_BYTES);
const _: () = assert!(MAX_HEIGHT <= u8::MAX as usize);

const CURSOR_NONE: u8 = 0;
const CURSOR_TABLE: u8 = 1;
const CURSOR_ROW: u8 = 2;
const CURSOR_ORDINAL: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CompactionPhase {
    Idle,
    Evacuating,
    Reclaiming,
    Packing,
}

impl CompactionPhase {
    fn tag(self) -> u8 {
        match self {
            Self::Idle => 0,
            Self::Evacuating => 1,
            Self::Reclaiming => 2,
            Self::Packing => 3,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Idle),
            1 => Some(Self::Evacuating),
            2 => Some(Self::Reclaiming),
            3 => Some(Self::Packing),
            _ => None,
        }
    }
}

/// An exact evacuation ordinal or a Packing inclusive logical lower bound.
/// Only Packing truncates a row key longer than the remaining capacity; under
/// directory-key order that prefix sorts no later than the key, so resuming
/// from it only re-reads entries that were already verified.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompactionCursor {
    kind: u8,
    table_len: u16,
    row_len: u16,
    bytes: [u8; MAX_CURSOR_BYTES],
}

impl CompactionCursor {
    pub(crate) const NONE: Self = Self {
        kind: CURSOR_NONE,
        table_len: 0,
        row_len: 0,
        bytes: [0; MAX_CURSOR_BYTES],
    };

    /// The canonical lower bound of `key`. The caller's key was validated by
    /// the directory codec; an invalid table name is still refused here.
    pub(crate) fn lower_bound(key: DirectoryKey<'_>) -> Result<Self, CoreError> {
        let table = key.table.as_bytes();
        if table.is_empty() || table.len() > MAX_TABLE_BYTES {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "compaction cursor table is invalid",
            )));
        }
        let mut cursor = Self::NONE;
        cursor.bytes[..table.len()].copy_from_slice(table);
        cursor.table_len = table.len() as u16;
        match key.row {
            None => cursor.kind = CURSOR_TABLE,
            Some(row) => {
                let kept = row.len().min(MAX_CURSOR_BYTES - table.len());
                cursor.bytes[table.len()..table.len() + kept].copy_from_slice(&row[..kept]);
                cursor.row_len = kept as u16;
                cursor.kind = CURSOR_ROW;
            }
        }
        Ok(cursor)
    }

    pub(crate) fn at_ordinal(ordinal: u64) -> Self {
        let mut cursor = Self::NONE;
        cursor.kind = CURSOR_ORDINAL;
        cursor.bytes[..8].copy_from_slice(&ordinal.to_le_bytes());
        cursor
    }

    pub(crate) fn ordinal(&self) -> Option<u64> {
        match self.kind {
            CURSOR_NONE => Some(0),
            CURSOR_ORDINAL => Some(le_u64(&self.bytes[..8])),
            _ => None,
        }
    }

    pub(crate) fn is_none(&self) -> bool {
        self.kind == CURSOR_NONE
    }

    /// The decoded Packing lower bound; absent and ordinal cursors yield `None`.
    pub(crate) fn key(&self) -> Option<DirectoryKey<'_>> {
        let table_len = usize::from(self.table_len);
        let table = std::str::from_utf8(&self.bytes[..table_len]).ok()?;
        match self.kind {
            CURSOR_TABLE => Some(DirectoryKey::table(table)),
            CURSOR_ROW => Some(DirectoryKey::row(
                table,
                &self.bytes[table_len..table_len + usize::from(self.row_len)],
            )),
            _ => None,
        }
    }

    fn violation(&self) -> Option<&'static str> {
        let table_len = usize::from(self.table_len);
        let row_len = usize::from(self.row_len);
        let used = if self.kind == CURSOR_ORDINAL {
            8
        } else {
            table_len + row_len
        };
        let shape = match self.kind {
            CURSOR_NONE | CURSOR_ORDINAL => table_len == 0 && row_len == 0,
            CURSOR_TABLE => {
                row_len == 0
                    && (1..=MAX_TABLE_BYTES).contains(&table_len)
                    && std::str::from_utf8(&self.bytes[..table_len]).is_ok()
            }
            CURSOR_ROW => {
                (1..=MAX_TABLE_BYTES).contains(&table_len)
                    && used <= MAX_CURSOR_BYTES
                    && std::str::from_utf8(&self.bytes[..table_len]).is_ok()
            }
            _ => false,
        };
        if !shape || used > MAX_CURSOR_BYTES || self.bytes[used..].iter().any(|&byte| byte != 0) {
            return Some("root compaction cursor is invalid");
        }
        None
    }
}

impl std::fmt::Debug for CompactionCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompactionCursor")
            .field("kind", &self.kind)
            .field("table_len", &self.table_len)
            .field("row_len", &self.row_len)
            .finish_non_exhaustive()
    }
}

/// The durable record. Fields are private; successors are built only by the
/// transitions on `Superblock` below.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompactionRecord {
    cycle: u64,
    phase: CompactionPhase,
    level: u8,
    cutoff_segment: u64,
    cutoff_arena: u64,
    baseline_bytes: u64,
    baseline_files: u64,
    cursor: CompactionCursor,
    /// Remaining bounded work at this Packing level, or zero before its first step.
    packing_remaining: u64,
    /// Immutable cycle-start worklist, retained only while Evacuating.
    evacuation_source: Option<DirectoryRoot>,
}

impl std::fmt::Debug for CompactionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompactionRecord")
            .field("cycle", &self.cycle)
            .field("phase", &self.phase)
            .field("level", &self.level)
            .field("cutoff_segment", &self.cutoff_segment)
            .field("cutoff_arena", &self.cutoff_arena)
            .field("baseline_bytes", &self.baseline_bytes)
            .field("baseline_files", &self.baseline_files)
            .field("packing_remaining", &self.packing_remaining)
            .field("evacuation_source", &self.evacuation_source)
            .field("cursor", &self.cursor)
            .finish()
    }
}

impl CompactionRecord {
    pub(crate) const GENESIS: Self = Self {
        cycle: 0,
        phase: CompactionPhase::Idle,
        level: 0,
        cutoff_segment: 0,
        cutoff_arena: 0,
        baseline_bytes: 0,
        baseline_files: 0,
        cursor: CompactionCursor::NONE,
        packing_remaining: 0,
        evacuation_source: None,
    };

    pub(crate) fn cycle(&self) -> u64 {
        self.cycle
    }
    pub(crate) fn phase(&self) -> CompactionPhase {
        self.phase
    }
    pub(crate) fn level(&self) -> u8 {
        self.level
    }
    pub(crate) fn cutoff_segment(&self) -> u64 {
        self.cutoff_segment
    }
    pub(crate) fn cutoff_arena(&self) -> u64 {
        self.cutoff_arena
    }
    pub(crate) fn baseline_bytes(&self) -> u64 {
        self.baseline_bytes
    }
    pub(crate) fn baseline_files(&self) -> u64 {
        self.baseline_files
    }
    pub(crate) fn cursor(&self) -> &CompactionCursor {
        &self.cursor
    }

    pub(crate) fn packing_remaining(&self) -> u64 {
        self.packing_remaining
    }

    pub(crate) fn evacuation_source(&self) -> Option<DirectoryRoot> {
        self.evacuation_source
    }

    /// The same cycle, phase, cutoffs and baseline; only progress differs.
    fn same_progress_frame(&self, other: &Self) -> bool {
        self.cycle == other.cycle
            && self.phase == other.phase
            && self.cutoff_segment == other.cutoff_segment
            && self.cutoff_arena == other.cutoff_arena
            && self.baseline_bytes == other.baseline_bytes
            && self.baseline_files == other.baseline_files
            && self.evacuation_source == other.evacuation_source
    }

    fn progress_free(&self) -> bool {
        self.level == 0 && self.cursor.is_none() && self.packing_remaining == 0
    }
}

impl Superblock {
    pub(crate) fn compaction(&self) -> &CompactionRecord {
        &self.compaction
    }

    /// The cutoffs a cycle beginning at this root would freeze. Both name
    /// files strictly older than the newest confirmed segment and arena.
    pub(crate) fn compaction_cutoffs(&self) -> (u64, u64) {
        (
            self.last_segment_id.saturating_sub(1),
            self.last_directory_id.saturating_sub(1),
        )
    }

    /// Idle(c) -> Evacuating(c + 1). The cutoffs come from this exact root,
    /// read under the owner lock; no file is rolled or created.
    pub(crate) fn begin_compaction(&self) -> Result<Self, CoreError> {
        let record = &self.compaction;
        if record.phase != CompactionPhase::Idle {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "compaction cycle is already active",
            )));
        }
        if !self.garbage.is_empty() {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "compaction worklist requires drained garbage",
            )));
        }
        if self.directory.is_none() {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "compaction needs a committed directory",
            )));
        }
        let (cutoff_segment, cutoff_arena) = self.compaction_cutoffs();
        if (cutoff_segment, cutoff_arena) == (0, 0) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "compaction has no file older than the newest",
            )));
        }
        let cycle = record.cycle.checked_add(1).ok_or(CoreError::new(
            crate::CoreErrorCause::InvalidInput("compaction cycle overflow"),
        ))?;
        let mut next = self.successor()?;
        next.compaction = CompactionRecord {
            cycle,
            phase: CompactionPhase::Evacuating,
            level: 0,
            cutoff_segment,
            cutoff_arena,
            baseline_bytes: record.baseline_bytes,
            baseline_files: record.baseline_files,
            cursor: CompactionCursor::NONE,
            packing_remaining: 0,
            evacuation_source: self.directory.map(|commit| commit.root),
        };
        Ok(next)
    }

    /// Evacuating -> Reclaiming once no reachable page or value remains at or
    /// below the cutoffs.
    pub(crate) fn advance_to_reclaiming(&self) -> Result<Self, CoreError> {
        self.advance(CompactionPhase::Evacuating, CompactionPhase::Reclaiming)
    }

    /// Reclaiming -> Packing. The only transition that changes the baseline.
    pub(crate) fn advance_to_packing(
        &self,
        baseline_bytes: u64,
        baseline_files: u64,
    ) -> Result<Self, CoreError> {
        let mut next = self.advance(CompactionPhase::Reclaiming, CompactionPhase::Packing)?;
        next.compaction.baseline_bytes = baseline_bytes;
        next.compaction.baseline_files = baseline_files;
        Ok(next)
    }

    /// Packing -> Idle; the cutoffs are cleared, the baseline is kept.
    pub(crate) fn finish_compaction(&self) -> Result<Self, CoreError> {
        let mut next = self.advance(CompactionPhase::Packing, CompactionPhase::Idle)?;
        next.compaction.cutoff_segment = 0;
        next.compaction.cutoff_arena = 0;
        Ok(next)
    }

    fn advance(&self, from: CompactionPhase, to: CompactionPhase) -> Result<Self, CoreError> {
        if self.compaction.phase != from {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "compaction phase transition is out of order",
            )));
        }
        let mut next = self.successor()?;
        next.compaction.phase = to;
        next.compaction.level = 0;
        next.compaction.cursor = CompactionCursor::NONE;
        next.compaction.packing_remaining = 0;
        next.compaction.evacuation_source = None;
        Ok(next)
    }

    /// Attach in-phase progress to an install successor. Only Evacuating
    /// (level zero) and Packing carry a cursor.
    pub(crate) fn with_compaction_cursor(
        mut self,
        level: u8,
        cursor: CompactionCursor,
        packing_remaining: u64,
    ) -> Result<Self, CoreError> {
        let allowed = match self.compaction.phase {
            CompactionPhase::Evacuating => {
                level == 0
                    && cursor.ordinal().is_some_and(|position| {
                        self.compaction
                            .evacuation_source
                            .is_some_and(|source| position <= source.entries)
                            && self
                                .compaction
                                .cursor
                                .ordinal()
                                .is_some_and(|old| position >= old)
                    })
            }
            CompactionPhase::Packing => {
                usize::from(level) <= MAX_HEIGHT && cursor.kind != CURSOR_ORDINAL
            }
            CompactionPhase::Idle | CompactionPhase::Reclaiming => level == 0 && cursor.is_none(),
        };
        if !allowed
            || cursor.violation().is_some()
            || (self.compaction.phase != CompactionPhase::Packing && packing_remaining != 0)
        {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "compaction cursor does not fit the phase",
            )));
        }
        self.compaction.level = level;
        self.compaction.cursor = cursor;
        self.compaction.packing_remaining = packing_remaining;
        Ok(self)
    }

    /// Persist skip-only progress so a crash after every successful step
    /// cannot replay an inclusive or truncated key forever.
    pub(crate) fn advance_evacuation_cursor(
        &self,
        cursor: CompactionCursor,
    ) -> Result<Self, CoreError> {
        if self.compaction.phase != CompactionPhase::Evacuating {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "evacuation is not active",
            )));
        }
        self.successor()?.with_compaction_cursor(0, cursor, 0)
    }

    pub(crate) fn advance_packing_cursor(
        &self,
        level: u8,
        cursor: CompactionCursor,
        remaining: u64,
    ) -> Result<Self, CoreError> {
        if self.compaction.phase != CompactionPhase::Packing {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "packing is not active",
            )));
        }
        self.successor()?
            .with_compaction_cursor(level, cursor, remaining)
    }

    /// Shared by encode (refusal) and decode (corruption).
    pub(super) fn compaction_invariant_violation(&self) -> Option<&'static str> {
        let record = &self.compaction;
        if let Some(reason) = record.cursor.violation() {
            return Some(reason);
        }
        let source_valid = match (record.phase, record.evacuation_source) {
            (CompactionPhase::Evacuating, Some(source)) => {
                source.validate().is_ok()
                    && source.group_id == self.group_id
                    && self
                        .directory
                        .is_some_and(|current| source.generation <= current.root.generation)
                    && source
                        .page
                        .is_none_or(|page| page.arena_id <= self.last_directory_id)
                    && record
                        .cursor
                        .ordinal()
                        .is_some_and(|position| position <= source.entries)
                    && self.garbage.is_empty()
            }
            (CompactionPhase::Evacuating, None) => false,
            (_, source) => source.is_none(),
        };
        if !source_valid
            || (record.phase != CompactionPhase::Packing && record.packing_remaining != 0)
        {
            return Some("root compaction evacuation source is invalid");
        }
        let invalid = match record.phase {
            CompactionPhase::Idle => {
                record.cutoff_segment != 0 || record.cutoff_arena != 0 || !record.progress_free()
            }
            phase => {
                record.cycle == 0
                    || self.directory.is_none()
                    || (record.cutoff_segment != 0 && record.cutoff_segment >= self.last_segment_id)
                    || (record.cutoff_arena != 0 && record.cutoff_arena >= self.last_directory_id)
                    || (record.cutoff_segment, record.cutoff_arena) == (0, 0)
                    || match phase {
                        CompactionPhase::Evacuating => record.level != 0,
                        CompactionPhase::Reclaiming => !record.progress_free(),
                        CompactionPhase::Packing => {
                            usize::from(record.level) > MAX_HEIGHT
                                || record.cursor.kind == CURSOR_ORDINAL
                        }
                        CompactionPhase::Idle => unreachable!("matched above"),
                    }
            }
        };
        invalid.then_some("root compaction record is invalid")
    }
}

/// `next` keeps the record, changes only in-phase progress, or applies
/// exactly one of the four phase transitions to `previous`.
pub(super) fn compaction_successor(previous: &Superblock, next: &Superblock) -> bool {
    let old = &previous.compaction;
    let new = &next.compaction;
    if old == new {
        return true;
    }
    if old.same_progress_frame(new) {
        if old.phase == CompactionPhase::Packing {
            return new.level >= old.level
                && (new.level != old.level
                    || old.packing_remaining == 0
                    || (new.packing_remaining != 0
                        && new.packing_remaining <= old.packing_remaining));
        }
        return old.phase != CompactionPhase::Evacuating
            || old
                .cursor
                .ordinal()
                .zip(new.cursor.ordinal())
                .is_some_and(|(before, after)| after >= before);
    }
    match (old.phase, new.phase) {
        (CompactionPhase::Idle, CompactionPhase::Evacuating) => {
            let (segment, arena) = previous.compaction_cutoffs();
            old.cycle.checked_add(1) == Some(new.cycle)
                && new.cutoff_segment == segment
                && new.cutoff_arena == arena
                && new.baseline_bytes == old.baseline_bytes
                && new.baseline_files == old.baseline_files
                && new.progress_free()
                && new.evacuation_source == previous.directory.map(|commit| commit.root)
                && previous.garbage.is_empty()
        }
        (CompactionPhase::Evacuating, CompactionPhase::Reclaiming) => {
            old.cycle == new.cycle
                && old.cutoff_segment == new.cutoff_segment
                && old.cutoff_arena == new.cutoff_arena
                && old.baseline_bytes == new.baseline_bytes
                && old.baseline_files == new.baseline_files
                && new.progress_free()
                && new.evacuation_source.is_none()
        }
        (CompactionPhase::Reclaiming, CompactionPhase::Packing) => {
            old.cycle == new.cycle
                && old.cutoff_segment == new.cutoff_segment
                && old.cutoff_arena == new.cutoff_arena
                && new.progress_free()
        }
        (CompactionPhase::Packing, CompactionPhase::Idle) => {
            old.cycle == new.cycle
                && old.baseline_bytes == new.baseline_bytes
                && old.baseline_files == new.baseline_files
                && new.progress_free()
        }
        _ => false,
    }
}

pub(super) fn encode_compaction(record: &CompactionRecord, bytes: &mut [u8]) {
    bytes.fill(0);
    bytes[..8].copy_from_slice(&record.cycle.to_le_bytes());
    bytes[8] = record.phase.tag();
    bytes[9] = record.level;
    bytes[10] = record.cursor.kind;
    bytes[16..24].copy_from_slice(&record.cutoff_segment.to_le_bytes());
    bytes[24..32].copy_from_slice(&record.cutoff_arena.to_le_bytes());
    bytes[32..40].copy_from_slice(&record.baseline_bytes.to_le_bytes());
    bytes[40..48].copy_from_slice(&record.baseline_files.to_le_bytes());
    bytes[48..50].copy_from_slice(&record.cursor.table_len.to_le_bytes());
    bytes[50..52].copy_from_slice(&record.cursor.row_len.to_le_bytes());
    bytes[52..60].copy_from_slice(&record.packing_remaining.to_le_bytes());
    bytes[RECORD_HEADER_BYTES..SOURCE_AT].copy_from_slice(&record.cursor.bytes);
    if let Some(source) = record.evacuation_source {
        bytes[SOURCE_AT..].copy_from_slice(&source.encode().expect("validated evacuation source"));
    }
}

/// Layout only; the root invariants are checked with the decoded superblock.
pub(super) fn decode_compaction(bytes: &[u8]) -> Result<CompactionRecord, CoreError> {
    let layout = CoreError::new(crate::CoreErrorCause::Corrupt(
        "root compaction has an unsupported layout",
    ));
    if bytes.len() != SOURCE_AT + DIRECTORY_ROOT_BYTES
        || bytes[11..16].iter().any(|&byte| byte != 0)
        || bytes[60..RECORD_HEADER_BYTES].iter().any(|&byte| byte != 0)
    {
        return Err(layout);
    }
    let phase = CompactionPhase::from_tag(bytes[8]).ok_or(CoreError::new(
        crate::CoreErrorCause::Corrupt("root compaction record is invalid"),
    ))?;
    let table_len = le_u16(&bytes[48..50]);
    let row_len = le_u16(&bytes[50..52]);
    if usize::from(table_len) + usize::from(row_len) > MAX_CURSOR_BYTES {
        return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
            "root compaction cursor is invalid",
        )));
    }
    Ok(CompactionRecord {
        cycle: le_u64(&bytes[..8]),
        phase,
        level: bytes[9],
        cutoff_segment: le_u64(&bytes[16..24]),
        cutoff_arena: le_u64(&bytes[24..32]),
        baseline_bytes: le_u64(&bytes[32..40]),
        baseline_files: le_u64(&bytes[40..48]),
        cursor: CompactionCursor {
            kind: bytes[10],
            table_len,
            row_len,
            bytes: bytes[RECORD_HEADER_BYTES..SOURCE_AT]
                .try_into()
                .expect("fixed cursor bytes"),
        },
        packing_remaining: le_u64(&bytes[52..60]),
        evacuation_source: if bytes[SOURCE_AT..].iter().all(|byte| *byte == 0) {
            None
        } else {
            Some(DirectoryRoot::decode(
                bytes[SOURCE_AT..].try_into().expect("fixed source bytes"),
            )?)
        },
    })
}

#[cfg(test)]
impl CompactionRecord {
    /// A checksum-valid image for codec rejection tests only.
    pub(crate) fn with_fields_for_test(
        cycle: u64,
        phase: CompactionPhase,
        level: u8,
        cutoffs: (u64, u64),
        baseline: (u64, u64),
        cursor: CompactionCursor,
    ) -> Self {
        Self {
            cycle,
            phase,
            level,
            cutoff_segment: cutoffs.0,
            cutoff_arena: cutoffs.1,
            baseline_bytes: baseline.0,
            baseline_files: baseline.1,
            cursor,
            packing_remaining: 0,
            evacuation_source: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{SlotImage, decode_slot, publish_root, select_root};
    use super::*;
    use crate::directory::{DirectoryPageRef, DirectoryRoot};
    use crate::group::InMemoryGroup;
    use crate::root::{DirectoryCommit, RootSelection};
    use crate::segment::test_support::{GROUP, corrupt_reason};
    use crate::segment::{LogPosition, ReplayStart, SEGMENT_HEADER_BYTES, SealedSegment, crc32c};

    fn advance(group: &InMemoryGroup, root: &mut Superblock, next: Superblock) {
        publish_root(group, root, &next).unwrap();
        *root = next;
    }

    fn commit(generation: u64, segment_id: u64, arena_id: u64) -> DirectoryCommit {
        DirectoryCommit {
            root: DirectoryRoot {
                group_id: GROUP,
                generation,
                page: Some(DirectoryPageRef {
                    arena_id,
                    page_index: generation,
                    sha256: [generation as u8; 32],
                }),
                height: 2,
                entries: 9,
            },
            start: ReplayStart {
                position: LogPosition {
                    segment_id,
                    offset: SEGMENT_HEADER_BYTES + 1024 + generation * 256,
                },
                batch_seq: generation,
                chain: [generation as u8; 32],
            },
        }
    }

    /// Three confirmed segments and arenas with a committed directory, every
    /// step published to `group`.
    fn published() -> (InMemoryGroup, Superblock) {
        let group = InMemoryGroup::new();
        let mut root = Superblock::genesis(GROUP);
        for _ in 0..3 {
            let sealed = (root.last_segment_id != 0).then_some(SealedSegment {
                segment_id: root.last_segment_id,
                len: 4096,
                commit_seq: 0,
            });
            let (next, id) = root.reserve_segment(sealed).unwrap();
            advance(&group, &mut root, next);
            let next = root.confirm_segment(id).unwrap();
            advance(&group, &mut root, next);
            let (next, id) = root.reserve_directory().unwrap();
            advance(&group, &mut root, next);
            let next = root.confirm_directory(id).unwrap();
            advance(&group, &mut root, next);
        }
        let next = root.install_directory(commit(5, 3, 3)).unwrap();
        advance(&group, &mut root, next);
        (group, root)
    }

    fn cursor(table: &str, row: Option<&[u8]>) -> CompactionCursor {
        CompactionCursor::lower_bound(match row {
            Some(row) => DirectoryKey::row(table, row),
            None => DirectoryKey::table(table),
        })
        .unwrap()
    }

    fn reseal(bytes: &mut [u8; crate::root::ROOT_SLOT_BYTES]) {
        let checksum = crc32c(&bytes[..CHECKSUM_AT]);
        bytes[CHECKSUM_AT..].copy_from_slice(&checksum.to_le_bytes());
    }

    fn round_trip(root: &Superblock) {
        assert_eq!(
            decode_slot(&root.encode().unwrap()).unwrap(),
            SlotImage::Valid(root.clone())
        );
    }

    #[test]
    fn compaction_record_round_trips_every_phase_level_and_cursor_kind() {
        let (_, root) = published();
        assert_eq!(root.compaction(), &CompactionRecord::GENESIS);
        round_trip(&root);
        let long_table = "t".repeat(MAX_TABLE_BYTES);
        let long_row = vec![0xa5; 512];
        let cursors = [
            CompactionCursor::NONE,
            cursor("accounts", None),
            cursor("accounts", Some(b"")),
            cursor("accounts", Some(b"k\x00\xff")),
            cursor(&long_table, None),
            cursor(&long_table, Some(&long_row)),
        ];
        // A 1024-byte table leaves exactly 512 row bytes.
        assert_eq!(cursors[5].row_len, 512);
        assert_eq!(
            cursors[5].key(),
            Some(DirectoryKey::row(&long_table, &long_row))
        );
        let evacuating = root.begin_compaction().unwrap();
        assert_eq!(evacuating.compaction().phase(), CompactionPhase::Evacuating);
        assert_eq!(evacuating.compaction().cycle(), 1);
        assert_eq!(
            (
                evacuating.compaction().cutoff_segment(),
                evacuating.compaction().cutoff_arena()
            ),
            (2, 2)
        );
        round_trip(&evacuating);
        for cursor in [
            CompactionCursor::NONE,
            CompactionCursor::at_ordinal(1),
            CompactionCursor::at_ordinal(9),
        ] {
            let next = evacuating
                .install_directory(commit(6, 3, 3))
                .unwrap()
                .with_compaction_cursor(0, cursor, 0)
                .unwrap();
            round_trip(&next);
            assert_eq!(next.compaction().cursor(), &cursor);
        }
        let reclaiming = evacuating.advance_to_reclaiming().unwrap();
        round_trip(&reclaiming);
        let packing = reclaiming.advance_to_packing(77 << 20, 31).unwrap();
        assert_eq!(packing.compaction().baseline_bytes(), 77 << 20);
        assert_eq!(packing.compaction().baseline_files(), 31);
        round_trip(&packing);
        for level in [0, 1, 17, (MAX_HEIGHT - 1) as u8] {
            for cursor in cursors {
                let next = packing
                    .install_directory(commit(6, 3, 3))
                    .unwrap()
                    .with_compaction_cursor(level, cursor, 0)
                    .unwrap();
                round_trip(&next);
                assert_eq!(next.compaction().level(), level);
            }
        }
        let idle = packing.finish_compaction().unwrap();
        assert_eq!(idle.compaction().phase(), CompactionPhase::Idle);
        assert_eq!(idle.compaction().cycle(), 1);
        assert_eq!(
            (
                idle.compaction().cutoff_segment(),
                idle.compaction().cutoff_arena()
            ),
            (0, 0)
        );
        assert_eq!(idle.compaction().baseline_bytes(), 77 << 20);
        round_trip(&idle);
        // Allocation and retirement transitions clone the record unchanged.
        let (allocated, _) = reclaiming.reserve_directory().unwrap();
        assert_eq!(allocated.compaction(), reclaiming.compaction());
    }

    /// Re-encode `root` with `record` substituted, checksum-valid.
    fn image_with(
        root: &Superblock,
        record: CompactionRecord,
    ) -> [u8; crate::root::ROOT_SLOT_BYTES] {
        let mut bytes = root.encode().unwrap();
        encode_compaction(&record, &mut bytes[COMPACTION_AT..COMPACTION_END]);
        reseal(&mut bytes);
        bytes
    }

    #[test]
    fn compaction_record_rejects_noncanonical_fields() {
        let (_, root) = published();
        let evacuating = root.begin_compaction().unwrap();
        let record = |phase, level, cutoffs, cursor| {
            CompactionRecord::with_fields_for_test(1, phase, level, cutoffs, (0, 0), cursor)
        };
        let mut invalid_cursor = cursor("accounts", Some(b"k"));
        invalid_cursor.kind = CURSOR_TABLE; // a table cursor carrying a row
        let mut non_utf8 = cursor("accounts", None);
        non_utf8.bytes[0] = 0xff;
        let mut empty_table = CompactionCursor::NONE;
        empty_table.kind = CURSOR_TABLE;
        let mut oversized_table = CompactionCursor::NONE;
        oversized_table.kind = CURSOR_TABLE;
        oversized_table.table_len = (MAX_TABLE_BYTES + 1) as u16;
        oversized_table.bytes[..=MAX_TABLE_BYTES].fill(b'a');
        let mut padded = cursor("accounts", None);
        padded.bytes[MAX_CURSOR_BYTES - 1] = 1;
        let mut lengths_without_kind = CompactionCursor::NONE;
        lengths_without_kind.table_len = 1;
        lengths_without_kind.bytes[0] = b'a';
        let mut unknown_kind = cursor("accounts", None);
        unknown_kind.kind = 4;
        let cases = [
            // Idle carries no cutoff, level or cursor.
            record(CompactionPhase::Idle, 0, (1, 0), CompactionCursor::NONE),
            record(CompactionPhase::Idle, 1, (0, 0), CompactionCursor::NONE),
            record(CompactionPhase::Idle, 0, (0, 0), cursor("accounts", None)),
            // Active phases need real, older cutoffs.
            record(
                CompactionPhase::Evacuating,
                0,
                (0, 0),
                CompactionCursor::NONE,
            ),
            record(
                CompactionPhase::Evacuating,
                0,
                (3, 2),
                CompactionCursor::NONE,
            ),
            record(
                CompactionPhase::Evacuating,
                0,
                (2, 3),
                CompactionCursor::NONE,
            ),
            CompactionRecord::with_fields_for_test(
                0,
                CompactionPhase::Evacuating,
                0,
                (2, 2),
                (0, 0),
                CompactionCursor::NONE,
            ),
            // Evacuation is level zero; Reclaiming has no progress.
            record(
                CompactionPhase::Evacuating,
                1,
                (2, 2),
                CompactionCursor::NONE,
            ),
            record(
                CompactionPhase::Reclaiming,
                0,
                (2, 2),
                cursor("accounts", None),
            ),
            record(
                CompactionPhase::Reclaiming,
                1,
                (2, 2),
                CompactionCursor::NONE,
            ),
            record(
                CompactionPhase::Packing,
                (MAX_HEIGHT + 1) as u8,
                (2, 2),
                CompactionCursor::NONE,
            ),
            // Cursor canon.
            record(CompactionPhase::Evacuating, 0, (2, 2), invalid_cursor),
            record(CompactionPhase::Evacuating, 0, (2, 2), non_utf8),
            record(CompactionPhase::Evacuating, 0, (2, 2), empty_table),
            record(CompactionPhase::Evacuating, 0, (2, 2), oversized_table),
            record(CompactionPhase::Evacuating, 0, (2, 2), padded),
            record(CompactionPhase::Evacuating, 0, (2, 2), lengths_without_kind),
            record(CompactionPhase::Evacuating, 0, (2, 2), unknown_kind),
        ];
        for (index, mut case) in cases.into_iter().enumerate() {
            if case.phase == CompactionPhase::Evacuating {
                case.evacuation_source = evacuating.compaction.evacuation_source;
            }
            let mut refused = evacuating.clone();
            refused.compaction = case;
            assert!(
                matches!(refused.encode(), Err(error) if matches!(error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_)))),
                "encode {index}: {case:?}"
            );
            let reason = corrupt_reason(decode_slot(&image_with(&evacuating, case)));
            assert!(
                reason == "root compaction record is invalid"
                    || reason == "root compaction cursor is invalid",
                "decode {index}: {reason}"
            );
        }
        // A cycle without a committed directory.
        let mut bare = Superblock::genesis(GROUP).initialized().unwrap();
        bare.compaction = record(
            CompactionPhase::Evacuating,
            0,
            (0, 0),
            CompactionCursor::NONE,
        );
        assert!(bare.encode().is_err());
        // Table plus row beyond the fixed capacity.
        let mut image = evacuating.encode().unwrap();
        let at = COMPACTION_AT;
        image[at + 10] = CURSOR_ROW;
        image[at + 48..at + 50].copy_from_slice(&1024u16.to_le_bytes());
        image[at + 50..at + 52].copy_from_slice(&513u16.to_le_bytes());
        reseal(&mut image);
        assert_eq!(
            corrupt_reason(decode_slot(&image)),
            "root compaction cursor is invalid"
        );
        // An unknown phase tag.
        let mut image = evacuating.encode().unwrap();
        image[at + 8] = 4;
        reseal(&mut image);
        assert_eq!(
            corrupt_reason(decode_slot(&image)),
            "root compaction record is invalid"
        );
        // Reserved record bytes and the region after the record.
        for offset in (at + 11..at + 16)
            .chain(at + 60..at + RECORD_HEADER_BYTES)
            .chain([COMPACTION_END, COMPACTION_END + 5, CHECKSUM_AT - 1])
        {
            let mut image = evacuating.encode().unwrap();
            image[offset] = 1;
            reseal(&mut image);
            let reason = corrupt_reason(decode_slot(&image));
            assert!(
                reason == "root compaction has an unsupported layout"
                    || reason == "root slot has an unsupported layout",
                "{offset}: {reason}"
            );
        }
    }

    #[test]
    fn publication_refuses_compaction_regression_skip_or_out_of_phase_change() {
        let (group, mut root) = published();
        let before = root.clone();
        // Out-of-order transitions are refused before any publication.
        for refused in [
            root.advance_to_reclaiming(),
            root.advance_to_packing(1, 1),
            root.finish_compaction(),
        ] {
            assert!(refused.is_err());
        }
        let next = root.begin_compaction().unwrap();
        assert!(next.begin_compaction().is_err());
        advance(&group, &mut root, next);
        // A forged successor: skip a phase, regress the cycle, move cutoffs,
        // change the baseline while evacuating, or go back to Idle.
        let mut forged = Vec::new();
        let mut skipped = root.successor().unwrap();
        skipped.compaction.phase = CompactionPhase::Packing;
        skipped.compaction.evacuation_source = None;
        forged.push(skipped);
        let mut regressed = root.successor().unwrap();
        regressed.compaction = CompactionRecord::GENESIS;
        forged.push(regressed);
        let mut moved = root.successor().unwrap();
        moved.compaction.cutoff_arena = 1;
        forged.push(moved);
        let mut rebased = root.successor().unwrap();
        rebased.compaction.baseline_bytes = 9;
        forged.push(rebased);
        let mut recycled = root.successor().unwrap();
        recycled.compaction.cycle = 7;
        forged.push(recycled);
        for candidate in &forged {
            assert!(
                matches!(publish_root(&group, &root, candidate), Err(error) if matches!(error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_)))),
                "{:?}",
                candidate.compaction()
            );
        }
        // Adjacent slots holding a non-successor record fail closed at reopen.
        for candidate in &forged {
            let damaged = group.crash();
            let image = candidate.encode().unwrap();
            damaged.with_durable_root(
                crate::root::RootSlot::for_generation(candidate.generation()),
                |bytes| bytes.copy_from_slice(&image),
            );
            assert_eq!(
                corrupt_reason(select_root(&damaged)),
                "root slots are not successive publications"
            );
        }
        // The real chain publishes, including cursor-only progress.
        let next = root
            .install_directory(commit(6, 3, 3))
            .unwrap()
            .with_compaction_cursor(0, CompactionCursor::at_ordinal(3), 0)
            .unwrap();
        advance(&group, &mut root, next);
        let next = root.advance_to_reclaiming().unwrap();
        advance(&group, &mut root, next);
        let next = root.advance_to_packing(10, 2).unwrap();
        advance(&group, &mut root, next);
        let next = root.finish_compaction().unwrap();
        advance(&group, &mut root, next);
        assert!(matches!(
            select_root(&group.crash()).unwrap(),
            RootSelection::Selected { superblock, .. } if superblock == root
        ));
        assert_ne!(root, before);
    }

    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    #[test]
    fn frozen_worklist_identity_ordinal_and_retention_are_phase_bound() {
        let (group, mut root) = published();
        let old_file = crate::group::GroupFile {
            kind: crate::group::FileKind::Directory,
            id: 1,
        };
        assert!(root.file_is_retirable(old_file));
        let mut pending = root.clone();
        pending.garbage.push(old_file);
        assert!(pending.begin_compaction().is_err());
        let next = root.begin_compaction().unwrap();
        advance(&group, &mut root, next);
        assert_eq!(
            root.compaction.evacuation_source,
            root.directory.map(|commit| commit.root)
        );
        assert!(!root.file_is_retirable(old_file));
        let next = root
            .advance_evacuation_cursor(CompactionCursor::at_ordinal(3))
            .unwrap();
        advance(&group, &mut root, next);
        assert!(
            root.advance_evacuation_cursor(CompactionCursor::at_ordinal(2))
                .is_err()
        );
        assert!(
            root.advance_evacuation_cursor(CompactionCursor::at_ordinal(10))
                .is_err()
        );
        assert!(
            root.advance_evacuation_cursor(cursor("accounts", Some(b"key")))
                .is_err()
        );
        let mut forged = root.successor().unwrap();
        forged.compaction.cursor = CompactionCursor::at_ordinal(2);
        assert!(publish_root(&group, &root, &forged).is_err());
        let mut substituted = root.successor().unwrap();
        substituted
            .compaction
            .evacuation_source
            .as_mut()
            .unwrap()
            .page
            .as_mut()
            .unwrap()
            .sha256[0] ^= 1;
        assert!(publish_root(&group, &root, &substituted).is_err());
        for mutation in 0..6 {
            let mut bad = root.compaction;
            match mutation {
                0 => bad.evacuation_source = None,
                1 => bad.evacuation_source.as_mut().unwrap().group_id[0] ^= 1,
                2 => bad.evacuation_source.as_mut().unwrap().generation += 1,
                3 => bad.cursor = CompactionCursor::at_ordinal(10),
                4 => bad.cursor.bytes[8] = 1,
                _ => bad.phase = CompactionPhase::Packing,
            }
            assert!(decode_slot(&image_with(&root, bad)).is_err());
        }
        let next = root.advance_to_reclaiming().unwrap();
        advance(&group, &mut root, next);
        assert_eq!(root.compaction.evacuation_source, None);
        assert!(root.file_is_retirable(old_file));
        round_trip(&root);
    }

    #[test]
    fn packing_work_budget_round_trips_and_cannot_reset_within_a_level() {
        let (_, root) = published();
        let packing = root
            .begin_compaction()
            .unwrap()
            .advance_to_reclaiming()
            .unwrap()
            .advance_to_packing(100, 2)
            .unwrap();
        let first = packing
            .advance_packing_cursor(0, cursor("accounts", Some(b"k")), 72)
            .unwrap();
        round_trip(&first);
        assert_eq!(first.compaction().packing_remaining(), 72);
        assert!(compaction_successor(&packing, &first));
        let next = first
            .advance_packing_cursor(0, cursor("accounts", Some(b"k")), 71)
            .unwrap();
        assert!(compaction_successor(&first, &next));
        assert!(!compaction_successor(&next, &first));
        let reset = next
            .advance_packing_cursor(0, CompactionCursor::NONE, 0)
            .unwrap();
        assert!(!compaction_successor(&next, &reset));
        let level = next
            .advance_packing_cursor(1, CompactionCursor::NONE, 0)
            .unwrap();
        assert!(compaction_successor(&next, &level));
        round_trip(&level);
    }

    #[test]
    fn truncated_cursor_is_a_monotone_lower_bound() {
        let mut seed = 0x6b76_6469_7220_3034;
        let tables: Vec<String> = ["a", "b", "ab", "\u{3042}"]
            .iter()
            .map(|prefix| prefix.to_string())
            .chain([
                "t".repeat(MAX_TABLE_BYTES),
                "t".repeat(MAX_TABLE_BYTES - 1),
                "u".repeat(700),
            ])
            .collect();
        let mut keys: Vec<(String, Option<Vec<u8>>)> = Vec::new();
        for _ in 0..600 {
            let table = tables[(splitmix(&mut seed) % tables.len() as u64) as usize].clone();
            let row = match splitmix(&mut seed) % 5 {
                0 => None,
                _ => {
                    // Long shared prefixes stress truncation at the boundary.
                    let len = match splitmix(&mut seed) % 4 {
                        0 => (splitmix(&mut seed) % 8) as usize,
                        1 => MAX_CURSOR_BYTES - table.len() + (splitmix(&mut seed) % 3) as usize,
                        _ => (splitmix(&mut seed) % crate::core::MAX_KEY_BYTES as u64) as usize,
                    }
                    .min(crate::core::MAX_KEY_BYTES);
                    let fill = (splitmix(&mut seed) % 3) as u8;
                    let mut row = vec![fill; len];
                    if len != 0 && splitmix(&mut seed).is_multiple_of(2) {
                        row[len - 1] = (splitmix(&mut seed) % 256) as u8;
                    }
                    Some(row)
                }
            };
            keys.push((table, row));
        }
        fn key((table, row): &(String, Option<Vec<u8>>)) -> DirectoryKey<'_> {
            match row {
                Some(row) => DirectoryKey::row(table, row),
                None => DirectoryKey::table(table),
            }
        }
        for left in &keys {
            let lower = CompactionCursor::lower_bound(key(left)).unwrap();
            let bound = lower.key().unwrap();
            assert!(bound <= key(left));
            // Canonical and idempotent: re-persisting never moves it.
            assert_eq!(CompactionCursor::lower_bound(bound).unwrap(), lower);
            for right in &keys {
                if key(left) <= key(right) {
                    let upper = CompactionCursor::lower_bound(key(right)).unwrap();
                    assert!(bound <= upper.key().unwrap());
                }
            }
        }
    }
}
