//! Segment files of the segmented append-only log.
//!
//! A segment is a create-only file of at most 64 MiB: a 64-byte header, then
//! checksummed records. The largest record (a 40 MiB value with its maximum
//! table and key) fits in one empty segment, so a value never chunks. A batch
//! is its operation records followed by one `BatchCommit` record carrying the
//! batch sequence, operation count, SHA-256 of the operation records, the
//! complete immutable directory root, and a SHA-256 chain over every earlier
//! commit including that root. Operation records may span
//! segments, but a single record never does. Replay exposes a batch only
//! after its commit record validates.
//!
//! Every record header names its batch and the newest commit it follows, and
//! its checksum also covers the group and the record's own position, so a
//! record image copied anywhere else, including into a value, never
//! validates.
//!
//! The writer synchronizes a batch's operation records before appending its
//! directory preparation record, then synchronizes that record before the
//! commit write. The commit is synchronized before acknowledgement. It also
//! synchronizes a segment before creating its successor, and the root intent
//! for that successor records the sealed length and newest commit. A reopened
//! writer finishes an outstanding intent first: its file, if present, must be
//! a prefix of its own header, and its name is synchronized before the root
//! confirms it.
//! Consequently only the newest confirmed segment can have a torn tail, and
//! everything after its last commit is one batch attempt following that
//! commit. Replay synchronizes that segment before reading it, so a batch
//! served after a restart without power loss survives a later power loss.
//! Replay treats damage there as a torn tail only when every checksum-valid
//! record after it belongs to that attempt and no commit header follows it;
//! any other damage fails closed. The bytes where the interrupted write
//! began must be that write, each zero or as written: the pending batch's
//! commit, which replay rebuilds, or an operation record header, whose
//! magic, kind, batch and base are known. A commit write follows the
//! synchronization of its batch's records, so any trace of one after a
//! damaged record fails closed too. So damage to an acknowledged final batch
//! fails closed with its bytes intact, except damage that leaves no
//! recognizable trace of the written commit, such as zeroed bytes or a
//! truncated file, which is indistinguishable from an interrupted write and
//! is discarded as a torn tail. A physical batch has exactly one commit record, so group commit must
//! merge callers into one batch rather than append several commits.

use sha2::{Digest, Sha256};

use crate::core::{
    CoreError, MAX_BATCH_BYTES, MAX_KEY_BYTES, MAX_TABLE_BYTES, MAX_VALUE_BYTES, Operation,
};
use crate::directory::{DIRECTORY_ROOT_BYTES, DirectoryRoot};
use crate::group::{GroupFile, SegmentGroupBackend};

#[path = "segment_maintenance.rs"]
mod maintenance;
pub(crate) use maintenance::{
    MAX_MAINTENANCE_OPERATIONS, MaintenanceOp, maintenance_operation_bytes,
    maintenance_workspace_bytes,
};

#[path = "segment_locator.rs"]
mod locator;
pub(crate) use locator::{CACHED_VALUE_LOCATOR_BYTES, inspect_cached_value_identity};

/// 64 MiB bounds reclaim copy steps while admitting a 40 MiB value whole.
pub(crate) const SEGMENT_BYTES: u64 = 64 << 20;
pub(crate) const SEGMENT_MAGIC: [u8; 16] = *b"KASUMI-KVSEG0004";
/// The single-file image replaced by this format. It has no reader.
pub(crate) const LEGACY_MAGIC: [u8; 16] = *b"KASUMI-KV-000001";
pub(crate) const FORMAT_VERSION: u32 = 4;
pub(crate) const SEGMENT_HEADER_BYTES: u64 = 64;
pub(crate) const MAX_BATCH_OPERATIONS: usize = 65_536;
pub(crate) const RECORD_HEADER_BYTES: usize = 36;
const RECORD_MAGIC: [u8; 4] = *b"KVSR";
const PUT_PREFIX_BYTES: usize = 16;
const RELOCATE_PREFIX_BYTES: usize = PUT_PREFIX_BYTES + 8;
const MAINTENANCE_BODY_BYTES: usize = 8;
const DELETE_PREFIX_BYTES: usize = 4;
const COMMIT_BODY_BYTES: usize = 72 + DIRECTORY_ROOT_BYTES;
const DIRECTORY_RECORD_BYTES: usize = RECORD_HEADER_BYTES + DIRECTORY_ROOT_BYTES;
pub(crate) const COMMIT_RECORD_BYTES: usize = RECORD_HEADER_BYTES + COMMIT_BODY_BYTES;
const MAX_INLINE_BODY: usize = RELOCATE_PREFIX_BYTES + MAX_TABLE_BYTES + MAX_KEY_BYTES;
const MAX_RECORD_BYTES: u64 = (RECORD_HEADER_BYTES + MAX_INLINE_BODY + MAX_VALUE_BYTES) as u64;
const IO_WINDOW: usize = 64 << 10;
const SEARCH_WINDOW: usize = 1 << 20;
const CHAIN_DOMAIN: &[u8] = b"KASUMI-KVSEG0004 batch chain";

const _: () = assert!(MAX_RECORD_BYTES <= SEGMENT_BYTES - SEGMENT_HEADER_BYTES);
const _: () = assert!(SEARCH_WINDOW > RECORD_HEADER_BYTES);

pub(crate) fn le_u16(src: &[u8]) -> u16 {
    u16::from_le_bytes(src.try_into().expect("two bytes"))
}
pub(crate) fn le_u32(src: &[u8]) -> u32 {
    u32::from_le_bytes(src.try_into().expect("four bytes"))
}
pub(crate) fn le_u64(src: &[u8]) -> u64 {
    u64::from_le_bytes(src.try_into().expect("eight bytes"))
}

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut value = i as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 == 1 {
                (value >> 1) ^ 0x82f6_3b78
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[i] = value;
        i += 1;
    }
    table
}
const CRC_TABLE: [u32; 256] = crc_table();

pub(crate) struct Crc32c(u32);
impl Crc32c {
    pub(crate) fn new() -> Self {
        Self(!0)
    }
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = CRC_TABLE[((self.0 as u8) ^ byte) as usize] ^ (self.0 >> 8);
        }
    }
    pub(crate) fn finish(&self) -> u32 {
        !self.0
    }
}
pub(crate) fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(bytes);
    crc.finish()
}

/// Reject the replaced contiguous image before any other decoding.
pub(crate) fn reject_legacy(bytes: &[u8]) -> Result<(), CoreError> {
    if bytes.starts_with(&LEGACY_MAGIC) {
        return Err(CoreError::Corrupt(
            "unsupported KASUMI-KV-000001 single-file image",
        ));
    }
    if bytes.starts_with(b"KASUMI-KVSEG0001") {
        return Err(CoreError::Corrupt(
            "unsupported KASUMI-KVSEG0001 segmented image",
        ));
    }
    if bytes.starts_with(b"KASUMI-KVSEG0002") {
        return Err(CoreError::Corrupt(
            "unsupported KASUMI-KVSEG0002 segmented image",
        ));
    }
    if bytes.starts_with(b"KASUMI-KVSEG0003") {
        return Err(CoreError::Corrupt(
            "unsupported KASUMI-KVSEG0003 segmented image",
        ));
    }
    Ok(())
}

/// A position in the log: a confirmed segment and a byte offset within it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LogPosition {
    pub(crate) segment_id: u64,
    pub(crate) offset: u64,
}

impl LogPosition {
    /// Replay start for a group without a checkpoint.
    pub(crate) const GENESIS: Self = Self {
        segment_id: 1,
        offset: SEGMENT_HEADER_BYTES,
    };
}

/// A segment as its successor's intent sealed it: the synchronized length and
/// the newest commit through it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SealedSegment {
    pub(crate) segment_id: u64,
    pub(crate) len: u64,
    pub(crate) commit_seq: u64,
}

/// The extent of the log as the selected root records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LogBounds {
    /// The newest confirmed segment; zero for none.
    pub(crate) last_segment_id: u64,
    /// The outstanding create intent, if any.
    pub(crate) pending_segment: Option<u64>,
    /// The segment the newest intent sealed.
    pub(crate) sealed: Option<SealedSegment>,
}

/// Exact location and checksum of one value's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ValueLocation {
    pub(crate) segment_id: u64,
    pub(crate) offset: u64,
    pub(crate) len: u32,
    pub(crate) crc: u32,
}

impl ValueLocation {
    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        let end = self.offset.checked_add(u64::from(self.len));
        if self.segment_id == 0
            || self.len as usize > MAX_VALUE_BYTES
            || self.offset < SEGMENT_HEADER_BYTES + (RECORD_HEADER_BYTES + PUT_PREFIX_BYTES) as u64
            || end.is_none_or(|end| end > SEGMENT_BYTES)
        {
            return Err(CoreError::Corrupt("value location is out of bounds"));
        }
        Ok(())
    }

    pub(crate) fn end(&self) -> u64 {
        self.offset + u64::from(self.len)
    }
}

/// Read and verify one value. Allocation failure is a capacity denial.
pub(crate) fn read_value(
    backend: &dyn SegmentGroupBackend,
    location: &ValueLocation,
) -> Result<Vec<u8>, CoreError> {
    location.validate()?;
    let mut value = Vec::new();
    value
        .try_reserve_exact(location.len as usize)
        .map_err(|_| CoreError::CapacityDenied)?;
    value.resize(location.len as usize, 0);
    backend.read(
        GroupFile::segment(location.segment_id),
        location.offset,
        &mut value,
    )?;
    if crc32c(&value) != location.crc {
        return Err(CoreError::Corrupt("value checksum differs"));
    }
    Ok(value)
}

pub(crate) fn chain_digest(
    group_id: &[u8; 16],
    previous: &[u8; 32],
    batch_seq: u64,
    op_count: u32,
    ops_sha256: &[u8; 32],
    directory: &[u8; DIRECTORY_ROOT_BYTES],
) -> [u8; 32] {
    let mut chain = Sha256::new();
    chain.update(CHAIN_DOMAIN);
    chain.update(group_id);
    chain.update(previous);
    chain.update(batch_seq.to_le_bytes());
    chain.update(op_count.to_le_bytes());
    chain.update(ops_sha256);
    chain.update(directory);
    chain.finalize().into()
}

pub(crate) fn segment_header(group_id: &[u8; 16], segment_id: u64) -> [u8; 64] {
    let mut bytes = [0u8; SEGMENT_HEADER_BYTES as usize];
    bytes[..16].copy_from_slice(&SEGMENT_MAGIC);
    bytes[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[24..40].copy_from_slice(group_id);
    bytes[40..48].copy_from_slice(&segment_id.to_le_bytes());
    let checksum = crc32c(&bytes[..60]);
    bytes[60..64].copy_from_slice(&checksum.to_le_bytes());
    bytes
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeaderState {
    Valid,
    /// Zero length or zero-filled.
    Unwritten,
    /// A short or checksum-invalid header.
    Torn,
}

/// Classify a segment header. A checksum-valid header naming another group
/// or segment is a substitution and fails closed. A confirmed segment must be
/// `Valid`; only an unconfirmed intent's file may be otherwise, and then only
/// as a prefix of its own header (`check_pending_segment`).
pub(crate) fn decode_segment_header(
    bytes: &[u8],
    group_id: &[u8; 16],
    segment_id: u64,
) -> Result<HeaderState, CoreError> {
    reject_legacy(bytes)?;
    if bytes.iter().all(|&byte| byte == 0) {
        return Ok(HeaderState::Unwritten);
    }
    if bytes.len() < SEGMENT_HEADER_BYTES as usize
        || bytes[..16] != SEGMENT_MAGIC
        || le_u32(&bytes[60..64]) != crc32c(&bytes[..60])
    {
        return Ok(HeaderState::Torn);
    }
    if le_u32(&bytes[16..20]) != FORMAT_VERSION
        || bytes[20..24].iter().any(|&byte| byte != 0)
        || bytes[48..60].iter().any(|&byte| byte != 0)
    {
        return Err(CoreError::Corrupt(
            "segment header has an unsupported layout",
        ));
    }
    if bytes[24..40] != group_id[..] || le_u64(&bytes[40..48]) != segment_id {
        return Err(CoreError::Corrupt(
            "segment header names another group or segment",
        ));
    }
    Ok(HeaderState::Valid)
}

pub(crate) fn read_segment_header(
    backend: &dyn SegmentGroupBackend,
    group_id: &[u8; 16],
    segment_id: u64,
) -> Result<HeaderState, CoreError> {
    let file = GroupFile::segment(segment_id);
    let len = backend.len(file)?;
    if len > SEGMENT_BYTES {
        return Err(CoreError::Corrupt("segment exceeds its size bound"));
    }
    let mut bytes = [0u8; SEGMENT_HEADER_BYTES as usize];
    let visible = len.min(SEGMENT_HEADER_BYTES) as usize;
    backend.read(file, 0, &mut bytes[..visible])?;
    decode_segment_header(&bytes[..visible], group_id, segment_id)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordKind {
    CreateTable,
    Put,
    Delete,
    Commit,
    Directory,
    Relocate,
    Maintenance,
}

impl RecordKind {
    fn tag(self) -> u8 {
        match self {
            Self::CreateTable => 1,
            Self::Put => 2,
            Self::Delete => 3,
            Self::Commit => 4,
            Self::Directory => 5,
            Self::Relocate => 6,
            Self::Maintenance => 7,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::CreateTable),
            2 => Some(Self::Put),
            3 => Some(Self::Delete),
            4 => Some(Self::Commit),
            5 => Some(Self::Directory),
            6 => Some(Self::Relocate),
            7 => Some(Self::Maintenance),
            _ => None,
        }
    }

    fn body_bounds(self) -> (usize, usize) {
        match self {
            Self::CreateTable => (1, MAX_TABLE_BYTES),
            Self::Put => (PUT_PREFIX_BYTES + 1, MAX_INLINE_BODY + MAX_VALUE_BYTES),
            Self::Delete => (
                DELETE_PREFIX_BYTES + 1,
                DELETE_PREFIX_BYTES + MAX_TABLE_BYTES + MAX_KEY_BYTES,
            ),
            Self::Commit => (COMMIT_BODY_BYTES, COMMIT_BODY_BYTES),
            Self::Directory => (DIRECTORY_ROOT_BYTES, DIRECTORY_ROOT_BYTES),
            Self::Relocate => (RELOCATE_PREFIX_BYTES + 1, MAX_INLINE_BODY + MAX_VALUE_BYTES),
            Self::Maintenance => (MAINTENANCE_BODY_BYTES, MAINTENANCE_BODY_BYTES),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RecordHead {
    kind: RecordKind,
    batch_seq: u64,
    /// The newest committed batch when the record was appended.
    base_seq: u64,
    body_len: u32,
    body_crc: u32,
}

/// The header checksum also covers the group and the record's position, so a
/// record image found anywhere else never validates.
fn header_checksum(group_id: &[u8; 16], at: LogPosition, bytes: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(group_id);
    crc.update(&at.segment_id.to_le_bytes());
    crc.update(&at.offset.to_le_bytes());
    crc.update(bytes);
    crc.finish()
}

fn record_header(
    group_id: &[u8; 16],
    at: LogPosition,
    head: &RecordHead,
) -> [u8; RECORD_HEADER_BYTES] {
    let mut bytes = [0u8; RECORD_HEADER_BYTES];
    bytes[..4].copy_from_slice(&RECORD_MAGIC);
    bytes[4] = head.kind.tag();
    bytes[8..16].copy_from_slice(&head.batch_seq.to_le_bytes());
    bytes[16..24].copy_from_slice(&head.base_seq.to_le_bytes());
    bytes[24..28].copy_from_slice(&head.body_len.to_le_bytes());
    bytes[28..32].copy_from_slice(&head.body_crc.to_le_bytes());
    let checksum = header_checksum(group_id, at, &bytes[..32]);
    bytes[32..36].copy_from_slice(&checksum.to_le_bytes());
    bytes
}

/// `Ok(None)` is damage that an interrupted append can produce, or bytes that
/// are not a record written at `at`. A header whose checksum validates but
/// whose fields break the format fails closed.
fn decode_record_header(
    bytes: &[u8; RECORD_HEADER_BYTES],
    group_id: &[u8; 16],
    at: LogPosition,
) -> Result<Option<RecordHead>, CoreError> {
    if bytes[..4] != RECORD_MAGIC
        || le_u32(&bytes[32..36]) != header_checksum(group_id, at, &bytes[..32])
    {
        return Ok(None);
    }
    let kind = RecordKind::from_tag(bytes[4])
        .ok_or(CoreError::Corrupt("segment record has an unknown kind"))?;
    let batch_seq = le_u64(&bytes[8..16]);
    let base_seq = le_u64(&bytes[16..24]);
    let body_len = le_u32(&bytes[24..28]);
    let (min, max) = kind.body_bounds();
    if bytes[5..8].iter().any(|&byte| byte != 0)
        || base_seq >= batch_seq
        || (body_len as usize) < min
        || body_len as usize > max
    {
        return Err(CoreError::Corrupt("segment record header is invalid"));
    }
    Ok(Some(RecordHead {
        kind,
        batch_seq,
        base_seq,
        body_len,
        body_crc: le_u32(&bytes[28..32]),
    }))
}

/// One operation record's body: its inline bytes (prefix, table and key) and
/// its borrowed value. The header waits for the record's position.
struct EncodedOp<'a> {
    kind: RecordKind,
    inline: Vec<u8>,
    value: &'a [u8],
    body_crc: u32,
    value_crc: u32,
}

impl EncodedOp<'_> {
    fn body_len(&self) -> u32 {
        (self.inline.len() + self.value.len()) as u32
    }

    fn len(&self) -> u64 {
        (RECORD_HEADER_BYTES + self.inline.len() + self.value.len()) as u64
    }
}

fn encode_op(operation: &Operation) -> EncodedOp<'_> {
    let (kind, table, key, value): (_, &[u8], &[u8], &[u8]) = match operation {
        Operation::CreateTable { table } => (RecordKind::CreateTable, table.as_bytes(), &[], &[]),
        Operation::Put { table, key, value } => (RecordKind::Put, table.as_bytes(), key, value),
        Operation::Delete { table, key } => (RecordKind::Delete, table.as_bytes(), key, &[]),
    };
    let value_crc = crc32c(value);
    let mut inline = Vec::with_capacity(PUT_PREFIX_BYTES + table.len() + key.len());
    match kind {
        RecordKind::Put => {
            inline.extend_from_slice(&(table.len() as u16).to_le_bytes());
            inline.extend_from_slice(&(key.len() as u16).to_le_bytes());
            inline.extend_from_slice(&(value.len() as u32).to_le_bytes());
            inline.extend_from_slice(&value_crc.to_le_bytes());
            inline.extend_from_slice(&[0; 4]);
        }
        RecordKind::Delete => {
            inline.extend_from_slice(&(table.len() as u16).to_le_bytes());
            inline.extend_from_slice(&(key.len() as u16).to_le_bytes());
        }
        RecordKind::CreateTable
        | RecordKind::Commit
        | RecordKind::Directory
        | RecordKind::Relocate
        | RecordKind::Maintenance => {}
    }
    inline.extend_from_slice(table);
    inline.extend_from_slice(key);
    let mut body_crc = Crc32c::new();
    body_crc.update(&inline);
    body_crc.update(value);
    EncodedOp {
        kind,
        inline,
        value,
        body_crc: body_crc.finish(),
        value_crc,
    }
}

struct CommitBody {
    op_count: u32,
    ops_sha256: [u8; 32],
    chain_sha256: [u8; 32],
    directory: [u8; DIRECTORY_ROOT_BYTES],
}

fn commit_record(
    group_id: &[u8; 16],
    at: LogPosition,
    batch_seq: u64,
    base_seq: u64,
    commit: &CommitBody,
) -> [u8; COMMIT_RECORD_BYTES] {
    let mut body = [0u8; COMMIT_BODY_BYTES];
    body[..4].copy_from_slice(&commit.op_count.to_le_bytes());
    body[8..40].copy_from_slice(&commit.ops_sha256);
    body[40..72].copy_from_slice(&commit.chain_sha256);
    body[72..].copy_from_slice(&commit.directory);
    let head = RecordHead {
        kind: RecordKind::Commit,
        batch_seq,
        base_seq,
        body_len: COMMIT_BODY_BYTES as u32,
        body_crc: crc32c(&body),
    };
    let mut bytes = [0u8; COMMIT_RECORD_BYTES];
    bytes[..RECORD_HEADER_BYTES].copy_from_slice(&record_header(group_id, at, &head));
    bytes[RECORD_HEADER_BYTES..].copy_from_slice(&body);
    bytes
}

fn decode_commit_body(body: &[u8]) -> Result<CommitBody, CoreError> {
    let op_count = le_u32(&body[..4]);
    if body[4..8].iter().any(|&byte| byte != 0)
        || op_count == 0
        || op_count as usize > MAX_BATCH_OPERATIONS
    {
        return Err(CoreError::Corrupt("batch commit record is invalid"));
    }
    Ok(CommitBody {
        op_count,
        ops_sha256: body[8..40].try_into().expect("32 bytes"),
        chain_sha256: body[40..72].try_into().expect("32 bytes"),
        directory: body[72..].try_into().expect("directory root bytes"),
    })
}

/// Validate the commit immediately preceding an installed directory anchor.
/// This is a bounded read; opening does not rebuild a resident key directory.
/// The caller separately validates reachable directory pages before serving.
pub(crate) fn validate_directory_anchor(
    backend: &dyn SegmentGroupBackend,
    group_id: [u8; 16],
    root: DirectoryRoot,
    start: &ReplayStart,
) -> Result<(), CoreError> {
    let encoded = root.encode()?;
    if root.group_id != group_id || root.generation != start.batch_seq {
        return Err(CoreError::Corrupt(
            "directory anchor names another batch or group",
        ));
    }
    if start.batch_seq == 0 {
        if *start != ReplayStart::GENESIS || root.page.is_some() {
            return Err(CoreError::Corrupt("genesis directory anchor is invalid"));
        }
        return Ok(());
    }
    let offset = start
        .position
        .offset
        .checked_sub(COMMIT_RECORD_BYTES as u64)
        .filter(|offset| *offset >= SEGMENT_HEADER_BYTES)
        .ok_or(CoreError::Corrupt(
            "directory anchor is outside a commit boundary",
        ))?;
    let at = LogPosition {
        segment_id: start.position.segment_id,
        offset,
    };
    if at.segment_id == 0
        || read_segment_header(backend, &group_id, at.segment_id)? != HeaderState::Valid
    {
        return Err(CoreError::Corrupt(
            "directory anchor segment header is invalid",
        ));
    }
    let mut bytes = [0u8; COMMIT_RECORD_BYTES];
    backend.read(GroupFile::segment(at.segment_id), offset, &mut bytes)?;
    let header: &[u8; RECORD_HEADER_BYTES] = bytes[..RECORD_HEADER_BYTES]
        .try_into()
        .expect("header bytes");
    let head = decode_record_header(header, &group_id, at)?
        .filter(|head| head.kind == RecordKind::Commit && head.batch_seq == start.batch_seq)
        .ok_or(CoreError::Corrupt(
            "directory anchor does not follow its commit",
        ))?;
    let body = &bytes[RECORD_HEADER_BYTES..];
    if head.body_crc != crc32c(body) {
        return Err(CoreError::Corrupt(
            "directory anchor commit checksum differs",
        ));
    }
    let commit = decode_commit_body(body)?;
    if commit.directory != encoded || commit.chain_sha256 != start.chain {
        return Err(CoreError::Corrupt(
            "directory anchor differs from committed root",
        ));
    }
    Ok(())
}

/// Pre-effect bounds shared with replay: operation count, and the table, key
/// and value bytes of one batch.
pub(crate) fn validate_batch(operations: &[Operation]) -> Result<(), CoreError> {
    if operations.is_empty() || operations.len() > MAX_BATCH_OPERATIONS {
        return Err(CoreError::InvalidInput("empty or oversized transaction"));
    }
    let mut bytes = 0usize;
    for operation in operations {
        let (table, key, value) = match operation {
            Operation::CreateTable { table } => (table.len(), 0, 0),
            Operation::Put { table, key, value } => (table.len(), key.len(), value.len()),
            Operation::Delete { table, key } => (table.len(), key.len(), 0),
        };
        if table == 0 || table > MAX_TABLE_BYTES {
            return Err(CoreError::InvalidInput("table name is empty or too long"));
        }
        if key > MAX_KEY_BYTES || value > MAX_VALUE_BYTES {
            return Err(CoreError::InvalidInput(
                "key or value exceeds storage limit",
            ));
        }
        bytes = bytes
            .checked_add(table + key + value)
            .filter(|&bytes| bytes <= MAX_BATCH_BYTES)
            .ok_or(CoreError::InvalidInput(
                "transaction exceeds 96 MiB physical limit",
            ))?;
    }
    Ok(())
}

/// Fixed transient reservation for prepare plus a possible abort replay.
/// Reserve before preparing and retain until finish/abort completes. The owner
/// separately retains the writer's 64 KiB staging capacity for its lifetime.
/// Inputs remain caller-owned and are borrowed during encoding. Abort validates
/// and drops one decoded record at a time under the exact prepared count, so
/// neither value payload nor an all-operation replay vector is reserved here.
pub(crate) fn prepared_batch_workspace_bytes(operations: &[Operation]) -> Result<u64, CoreError> {
    validate_batch(operations)?;
    let values = operations.len() as u64 * std::mem::size_of::<Option<ValueLocation>>() as u64;
    Ok(root_replay_workspace_bytes() + values)
}

/// Durable segment allocation supplied by the root owner.
pub(crate) trait SegmentRoll {
    /// Durably publish an intent that allows one new segment identifier,
    /// recording `sealed`, the synchronized newest segment it follows, and
    /// return it. The identifier is never reused.
    fn reserve(&mut self, sealed: Option<SealedSegment>) -> Result<u64, CoreError>;
    /// Durably record that `segment_id` exists with a synchronized header.
    fn confirm(&mut self, segment_id: u64) -> Result<(), CoreError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PreparedIdentity {
    group_id: [u8; 16],
    batch_seq: u64,
    start: ReplayStart,
    end: LogPosition,
    ops_sha256: [u8; 32],
    operation_count: u32,
}

/// A private operation prefix, consumed exactly once by finish or abort.
#[derive(Debug)]
pub(crate) struct PreparedBatch {
    identity: PreparedIdentity,
    values: Vec<Option<ValueLocation>>,
}

impl PreparedBatch {
    pub(crate) fn batch_seq(&self) -> u64 {
        self.identity.batch_seq
    }
    pub(crate) fn values(&self) -> &[Option<ValueLocation>] {
        &self.values
    }
}

/// The durable result of one acknowledged batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommittedBatch {
    pub(crate) batch_seq: u64,
    pub(crate) chain: [u8; 32],
    pub(crate) directory_root: DirectoryRoot,
    /// One entry per operation; `Some` exactly for puts.
    pub(crate) values: Vec<Option<ValueLocation>>,
    pub(crate) end: LogPosition,
}

/// Appends batches to the newest confirmed segment. Any failure after the
/// first effect fences the writer; the owner must reopen through replay.
pub(crate) struct SegmentWriter {
    group_id: [u8; 16],
    active: Option<u64>,
    // Logical end, including staged bytes.
    end: u64,
    capacity: u64,
    stage: Vec<u8>,
    stage_at: u64,
    // An unconfirmed intent left by an interrupted roll. It seals the active
    // segment, so the next append finishes this segment first.
    reserved: Option<u64>,
    last_batch_seq: u64,
    next_batch_seq: u64,
    chain: [u8; 32],
    fenced: bool,
    prepared: Option<PreparedIdentity>,
}

impl SegmentWriter {
    /// A writer for a group with no segment and no committed batch.
    pub(crate) fn new(group_id: [u8; 16]) -> Self {
        Self {
            group_id,
            active: None,
            end: 0,
            capacity: SEGMENT_BYTES,
            stage: Vec::new(),
            stage_at: 0,
            reserved: None,
            last_batch_seq: 0,
            next_batch_seq: 1,
            chain: [0; 32],
            fenced: false,
            prepared: None,
        }
    }

    /// Continue after replay once `ReplayEnd::discard_tail` has succeeded.
    pub(crate) fn resume(group_id: [u8; 16], end: &ReplayEnd) -> Self {
        let mut writer = Self::new(group_id);
        if let Some(resume) = end.resume {
            writer.active = Some(resume.segment_id);
            writer.end = resume.offset;
            writer.stage_at = resume.offset;
        }
        writer.reserved = end.pending_segment;
        writer.last_batch_seq = end.batch_seq;
        writer.next_batch_seq = end.next_batch_seq;
        writer.chain = end.chain;
        writer
    }

    #[cfg(test)]
    pub(crate) fn with_capacity(mut self, capacity: u64) -> Self {
        assert!(capacity > SEGMENT_HEADER_BYTES + COMMIT_RECORD_BYTES as u64);
        assert!(capacity <= SEGMENT_BYTES);
        self.capacity = capacity;
        self
    }

    pub(crate) fn is_fenced(&self) -> bool {
        self.fenced
    }

    pub(crate) fn last_batch_seq(&self) -> u64 {
        self.last_batch_seq
    }

    pub(crate) fn chain(&self) -> [u8; 32] {
        self.chain
    }

    pub(crate) fn position(&self) -> Option<LogPosition> {
        self.active.map(|segment_id| LogPosition {
            segment_id,
            offset: self.end,
        })
    }

    pub(crate) fn next_batch_sequence(&self) -> u64 {
        self.next_batch_seq
    }

    /// Persist operation records and reserve their exact value locations. No
    /// commit can become visible until `finish_batch` binds a synchronized
    /// directory root. While a token is outstanding, a second prepare fails.
    pub(crate) fn prepare_batch(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        operations: &[Operation],
        roll: &mut dyn SegmentRoll,
    ) -> Result<PreparedBatch, CoreError> {
        if self.fenced || self.prepared.is_some() {
            return Err(CoreError::OwnerFailed);
        }
        if self.next_batch_seq == u64::MAX {
            return Err(CoreError::InvalidInput("batch sequence overflow"));
        }
        validate_batch(operations)?;
        // A bounded logical length alone does not bound Vec capacity: a
        // geometric extension near 64 KiB could retain almost 128 KiB. Reserve
        // the exact admitted window before any durable operation effects.
        if self.stage.capacity() < IO_WINDOW {
            self.stage
                .try_reserve_exact(IO_WINDOW - self.stage.len())
                .map_err(|_| CoreError::CapacityDenied)?;
        }
        if self.stage.capacity() > IO_WINDOW {
            self.stage = Vec::new();
            return Err(CoreError::CapacityDenied);
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(operations.len())
            .map_err(|_| CoreError::CapacityDenied)?;
        if values.capacity() != operations.len() {
            return Err(CoreError::CapacityDenied);
        }
        let start = ReplayStart {
            position: self.position().unwrap_or(LogPosition::GENESIS),
            batch_seq: self.last_batch_seq,
            chain: self.chain,
        };
        let result = self.write_operations(backend, operations, roll, values, start);
        match &result {
            Ok(prepared) => self.prepared = Some(prepared.identity),
            Err(_) => self.fenced = true,
        }
        result
    }

    fn write_operations(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        operations: &[Operation],
        roll: &mut dyn SegmentRoll,
        mut values: Vec<Option<ValueLocation>>,
        start: ReplayStart,
    ) -> Result<PreparedBatch, CoreError> {
        let batch_seq = self.next_batch_seq;
        let base_seq = self.last_batch_seq;
        let mut ops = Sha256::new();
        for operation in operations {
            let record = encode_op(operation);
            self.ensure_room(backend, record.len(), roll)?;
            let at = self.position().expect("room ensures an active segment");
            let header = record_header(
                &self.group_id,
                at,
                &RecordHead {
                    kind: record.kind,
                    batch_seq,
                    base_seq,
                    body_len: record.body_len(),
                    body_crc: record.body_crc,
                },
            );
            ops.update(header);
            ops.update(&record.inline);
            ops.update(record.value);
            self.stage(backend, &header)?;
            self.stage(backend, &record.inline)?;
            let value_at = self.end;
            self.stage(backend, record.value)?;
            values.push(
                matches!(operation, Operation::Put { .. }).then_some(ValueLocation {
                    segment_id: at.segment_id,
                    offset: value_at,
                    len: record.value.len() as u32,
                    crc: record.value_crc,
                }),
            );
        }
        let active = self.active.expect("a batch has at least one record");
        self.flush(backend)?;
        backend.sync(GroupFile::segment(active))?;
        Ok(PreparedBatch {
            identity: PreparedIdentity {
                group_id: self.group_id,
                batch_seq,
                start,
                end: self.position().expect("operations have an active segment"),
                ops_sha256: ops.finalize().into(),
                operation_count: operations.len() as u32,
            },
            values,
        })
    }

    /// Bind and acknowledge one batch. The caller must synchronize every page
    /// reachable from `directory_root` before calling this method. A durable
    /// preparation record carries the exact root so replay can reconstruct a
    /// torn commit rather than mistaking arbitrary root damage for a tear.
    /// Failures before the commit write are known uncommitted; failures during
    /// its write or synchronization are `UnknownCommit`. Either fences writer.
    pub(crate) fn finish_batch(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        prepared: PreparedBatch,
        directory_root: DirectoryRoot,
        roll: &mut dyn SegmentRoll,
    ) -> Result<CommittedBatch, CoreError> {
        if self.fenced || self.prepared != Some(prepared.identity) {
            return Err(CoreError::OwnerFailed);
        }
        let result = self.write_commit(backend, prepared, directory_root, roll);
        if result.is_err() {
            self.fenced = true;
        } else {
            self.prepared = None;
        }
        result
    }

    fn write_commit(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        prepared: PreparedBatch,
        directory_root: DirectoryRoot,
        roll: &mut dyn SegmentRoll,
    ) -> Result<CommittedBatch, CoreError> {
        let batch_seq = prepared.identity.batch_seq;
        if directory_root.group_id != self.group_id || directory_root.generation != batch_seq {
            return Err(CoreError::InvalidInput(
                "directory root does not name prepared batch",
            ));
        }
        let directory = directory_root.encode()?;
        self.ensure_room(backend, DIRECTORY_RECORD_BYTES as u64, roll)?;
        let at = self.position().expect("room ensures an active segment");
        let mut record = [0u8; DIRECTORY_RECORD_BYTES];
        record[..RECORD_HEADER_BYTES].copy_from_slice(&record_header(
            &self.group_id,
            at,
            &RecordHead {
                kind: RecordKind::Directory,
                batch_seq,
                base_seq: self.last_batch_seq,
                body_len: DIRECTORY_ROOT_BYTES as u32,
                body_crc: crc32c(&directory),
            },
        ));
        record[RECORD_HEADER_BYTES..].copy_from_slice(&directory);
        let file = GroupFile::segment(at.segment_id);
        backend.write(file, self.end, &record)?;
        backend.sync(file)?;
        self.end += DIRECTORY_RECORD_BYTES as u64;
        self.stage_at = self.end;
        let op_count = prepared.values.len() as u32;
        let chain = chain_digest(
            &self.group_id,
            &self.chain,
            batch_seq,
            op_count,
            &prepared.identity.ops_sha256,
            &directory,
        );
        let body = CommitBody {
            op_count,
            ops_sha256: prepared.identity.ops_sha256,
            chain_sha256: chain,
            directory,
        };
        self.ensure_room(backend, COMMIT_RECORD_BYTES as u64, roll)?;
        let at = self.position().expect("room ensures an active segment");
        let commit = commit_record(&self.group_id, at, batch_seq, self.last_batch_seq, &body);
        let file = GroupFile::segment(at.segment_id);
        backend
            .write(file, self.end, &commit)
            .map_err(CoreError::UnknownCommit)?;
        backend.sync(file).map_err(CoreError::UnknownCommit)?;
        self.end += COMMIT_RECORD_BYTES as u64;
        self.stage_at = self.end;
        self.last_batch_seq = batch_seq;
        self.next_batch_seq = batch_seq + 1;
        self.chain = chain;
        Ok(CommittedBatch {
            batch_seq,
            chain,
            directory_root,
            values: prepared.values,
            end: LogPosition {
                segment_id: at.segment_id,
                offset: self.end,
            },
        })
    }

    /// Release a prepared batch after a known private construction failure,
    /// such as directory capacity denial. Exact replay/discard safeguards
    /// ensure an abort cannot remove committed data. Failed aborts fence.
    pub(crate) fn abort_prepared(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        prepared: PreparedBatch,
        bounds: &LogBounds,
    ) -> Result<(), CoreError> {
        if self.fenced || self.prepared != Some(prepared.identity) {
            return Err(CoreError::OwnerFailed);
        }
        let result = (|| {
            if bounds.last_segment_id != prepared.identity.end.segment_id
                || bounds.pending_segment.is_some()
                || backend.len(GroupFile::segment(prepared.identity.end.segment_id))?
                    != prepared.identity.end.offset
            {
                return Err(CoreError::InvalidInput(
                    "prepared batch tail differs before abort",
                ));
            }
            let mut end = replay_with_policy(
                backend,
                self.group_id,
                &prepared.identity.start,
                bounds,
                ReplayPolicy {
                    max_operations: prepared.identity.operation_count as usize,
                    retain_records: false,
                    prepared: Some(prepared.identity),
                },
                |_| {
                    Err(CoreError::Corrupt(
                        "prepared batch abort encountered a commit",
                    ))
                },
            )?;
            end.discard_tail(backend)?;
            end.next_batch_seq = end.next_batch_seq.max(prepared.batch_seq() + 1);
            let capacity = self.capacity;
            *self = Self::resume(self.group_id, &end);
            self.capacity = capacity;
            Ok(())
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    fn ensure_room(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        len: u64,
        roll: &mut dyn SegmentRoll,
    ) -> Result<(), CoreError> {
        if self.active.is_some() && self.reserved.is_none() && self.end + len <= self.capacity {
            return Ok(());
        }
        if len > self.capacity - SEGMENT_HEADER_BYTES {
            return Err(CoreError::InvalidInput("record exceeds segment capacity"));
        }
        self.roll_segment(backend, roll)
    }

    /// Seal the current segment and establish its successor without changing
    /// the configured segment size. A prepared batch owns the current tail
    /// exclusively and cannot be interrupted by an explicit roll.
    pub(crate) fn force_roll(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        roll: &mut dyn SegmentRoll,
    ) -> Result<(), CoreError> {
        if self.fenced || self.prepared.is_some() {
            return Err(CoreError::OwnerFailed);
        }
        let result = self.roll_segment(backend, roll);
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    fn roll_segment(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        roll: &mut dyn SegmentRoll,
    ) -> Result<(), CoreError> {
        self.flush(backend)?;
        if let Some(active) = self.active {
            // Seal before a successor can exist, so only the newest segment
            // can end in a torn append.
            backend.sync(GroupFile::segment(active))?;
        }
        let segment_id = match self.reserved.take() {
            Some(segment_id) => {
                self.take_over_intent(backend, segment_id)?;
                segment_id
            }
            None => {
                let sealed = self.active.map(|segment_id| SealedSegment {
                    segment_id,
                    len: self.end,
                    commit_seq: self.last_batch_seq,
                });
                let segment_id = roll.reserve(sealed)?;
                // Create-only: a present file at a fresh identifier is not
                // this group's, and the refusal fences the writer.
                backend.create(GroupFile::segment(segment_id))?;
                segment_id
            }
        };
        let file = GroupFile::segment(segment_id);
        backend.write(file, 0, &segment_header(&self.group_id, segment_id))?;
        backend.sync(file)?;
        roll.confirm(segment_id)?;
        self.active = Some(segment_id);
        self.end = SEGMENT_HEADER_BYTES;
        self.stage_at = SEGMENT_HEADER_BYTES;
        Ok(())
    }

    /// Finish the replay-verified intent of an interrupted roll. Its file, if
    /// present, may hold only a torn or complete write of this segment's own
    /// header; anything else fails closed and leaves the file untouched.
    fn take_over_intent(
        &self,
        backend: &dyn SegmentGroupBackend,
        segment_id: u64,
    ) -> Result<(), CoreError> {
        let file = GroupFile::segment(segment_id);
        if !check_pending_segment(backend, &self.group_id, segment_id)? {
            backend.create(file)?;
            return Ok(());
        }
        // The interrupted create may have failed in its parent
        // synchronization, and a restart without power loss still lists the
        // name. It must be durable before the root confirms the segment.
        backend.sync_names()?;
        backend.set_len(file, 0)?;
        Ok(())
    }

    fn stage(&mut self, backend: &dyn SegmentGroupBackend, bytes: &[u8]) -> Result<(), CoreError> {
        if self.stage.len() + bytes.len() > IO_WINDOW {
            self.flush(backend)?;
        }
        if bytes.len() >= IO_WINDOW {
            let file = GroupFile::segment(self.active.expect("staged segment"));
            backend.write(file, self.end, bytes)?;
            self.stage_at = self.end + bytes.len() as u64;
        } else {
            self.stage.extend_from_slice(bytes);
        }
        self.end += bytes.len() as u64;
        Ok(())
    }

    fn flush(&mut self, backend: &dyn SegmentGroupBackend) -> Result<(), CoreError> {
        if !self.stage.is_empty() {
            let file = GroupFile::segment(self.active.expect("staged segment"));
            backend.write(file, self.stage_at, &self.stage)?;
            self.stage.clear();
        }
        self.stage_at = self.end;
        Ok(())
    }
}

/// Sequential reads through one bounded window.
pub(crate) struct FileReader<'a> {
    backend: &'a dyn SegmentGroupBackend,
    file: GroupFile,
    len: u64,
    pos: u64,
    window: Vec<u8>,
    window_at: u64,
}

impl<'a> FileReader<'a> {
    pub(crate) fn new(
        backend: &'a dyn SegmentGroupBackend,
        file: GroupFile,
        len: u64,
        pos: u64,
    ) -> Self {
        Self {
            backend,
            file,
            len,
            pos,
            window: Vec::new(),
            window_at: pos,
        }
    }

    pub(crate) fn pos(&self) -> u64 {
        self.pos
    }

    pub(crate) fn remaining(&self) -> u64 {
        self.len - self.pos
    }

    /// Read exactly `out.len()` bytes; the caller checks `remaining` first.
    pub(crate) fn read_exact(&mut self, out: &mut [u8]) -> Result<(), CoreError> {
        let end = self.pos + out.len() as u64;
        debug_assert!(end <= self.len);
        let window_end = self.window_at + self.window.len() as u64;
        if self.pos >= self.window_at && end <= window_end {
            let start = (self.pos - self.window_at) as usize;
            out.copy_from_slice(&self.window[start..start + out.len()]);
        } else if out.len() >= IO_WINDOW {
            self.backend.read(self.file, self.pos, out)?;
        } else {
            let fill = (self.len - self.pos).min(IO_WINDOW as u64) as usize;
            self.window.resize(fill, 0);
            self.backend.read(self.file, self.pos, &mut self.window)?;
            self.window_at = self.pos;
            out.copy_from_slice(&self.window[..out.len()]);
        }
        self.pos = end;
        Ok(())
    }
}

/// Where replay begins: a commit boundary and the chain state at it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReplayStart {
    pub(crate) position: LogPosition,
    pub(crate) batch_seq: u64,
    pub(crate) chain: [u8; 32],
}

impl ReplayStart {
    pub(crate) const GENESIS: Self = Self {
        position: LogPosition::GENESIS,
        batch_seq: 0,
        chain: [0; 32],
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReplayedRecord {
    CreateTable {
        table: String,
    },
    Put {
        table: String,
        key: Vec<u8>,
        value: ValueLocation,
    },
    Delete {
        table: String,
        key: Vec<u8>,
    },
    Relocate {
        table: String,
        key: Vec<u8>,
        logical_batch_seq: u64,
        value: ValueLocation,
    },
    DirectoryOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplayedBatch {
    pub(crate) end: LogPosition,
    pub(crate) batch_seq: u64,
    pub(crate) chain: [u8; 32],
    pub(crate) directory_root: DirectoryRoot,
    pub(crate) records: Vec<ReplayedRecord>,
}

/// A validated committed root without a retained operation/key collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReplayedRoot {
    pub(crate) end: LogPosition,
    pub(crate) batch_seq: u64,
    pub(crate) chain: [u8; 32],
    pub(crate) directory_root: DirectoryRoot,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplayEnd {
    /// Exact commit boundary for `directory_root`, distinct from append resume
    /// when a later uncommitted attempt rolled into a newer segment.
    pub(crate) directory_end: Option<LogPosition>,
    /// Newest directory root after the supplied start, or none if no batch followed it.
    pub(crate) directory_root: Option<DirectoryRoot>,
    /// The newest committed batch and its chain.
    pub(crate) batch_seq: u64,
    pub(crate) chain: [u8; 32],
    /// Above every sequence seen, including abandoned batches, so a new batch
    /// never merges with abandoned records.
    pub(crate) next_batch_seq: u64,
    /// Append position in the newest confirmed segment: the end of its last
    /// commit, or the replay start or header end when it has none. A newest
    /// segment sealed by an outstanding intent keeps its whole length, since
    /// the root recorded it and the writer rolls into the intent first.
    pub(crate) resume: Option<LogPosition>,
    /// Length of the newest confirmed segment before any discard.
    pub(crate) final_len: u64,
    /// The first bytes after `resume` as replay read them, zero-padded.
    pub(crate) tail_head: [u8; RECORD_HEADER_BYTES],
    /// Offset of damage in the newest segment accepted as a torn tail.
    pub(crate) torn_at: Option<u64>,
    /// Sequence of trailing operation records that have no commit.
    pub(crate) uncommitted_batch: Option<u64>,
    /// An outstanding create intent: absent, or at most a torn header.
    pub(crate) pending_segment: Option<u64>,
}

impl ReplayEnd {
    /// Remove bytes after `resume` from the newest segment and synchronize.
    /// Returns whether the file shrank; the owner settles growth after success.
    ///
    /// The segment must still hold the tail replay read: its length and its
    /// first bytes. A segment that already ends at `resume` is only
    /// synchronized, so a retry after a failed synchronization completes.
    /// Anything else is refused without effect, so a stale `ReplayEnd` never
    /// discards a batch the resumed writer appended. That batch begins with
    /// a whole record header of `next_batch_seq`, and replay counts every
    /// such header in the tail except one whose record is cut short, which
    /// leaves a tail shorter than the appended batch.
    pub(crate) fn discard_tail(
        &self,
        backend: &dyn SegmentGroupBackend,
    ) -> Result<bool, CoreError> {
        let Some(resume) = self.resume else {
            return Ok(false);
        };
        if self.final_len == resume.offset {
            return Ok(false);
        }
        let file = GroupFile::segment(resume.segment_id);
        let len = backend.len(file)?;
        if len != resume.offset {
            let present = (self.final_len - resume.offset).min(RECORD_HEADER_BYTES as u64) as usize;
            let mut head = [0u8; RECORD_HEADER_BYTES];
            if len == self.final_len {
                backend.read(file, resume.offset, &mut head[..present])?;
            }
            if len != self.final_len || head != self.tail_head {
                return Err(CoreError::InvalidInput(
                    "segment tail differs from the replayed tail",
                ));
            }
            backend.set_len(file, resume.offset)?;
        }
        backend.sync(file)?;
        Ok(true)
    }
}

struct PendingBatch {
    batch_seq: u64,
    directory_root: Option<DirectoryRoot>,
    records: Vec<ReplayedRecord>,
    op_count: usize,
    bytes: usize,
    encoded_bytes: usize,
    ops: Sha256,
    kind: Option<BatchKind>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BatchKind {
    User,
    Relocation,
    DirectoryOnly,
}

struct Replay<'a> {
    directory_end: Option<LogPosition>,
    directory_root: Option<DirectoryRoot>,
    backend: &'a dyn SegmentGroupBackend,
    group_id: [u8; 16],
    batch_seq: u64,
    chain: [u8; 32],
    max_seen: u64,
    pending: Option<PendingBatch>,
    // The batch whose records this segment holds after its last commit.
    segment_attempt: Option<u64>,
    max_operations: usize,
    retain_records: bool,
    prepared: Option<PreparedIdentity>,
}

struct ReplayPolicy {
    max_operations: usize,
    retain_records: bool,
    // A synchronized private prefix has a known exact image. It cannot be
    // treated as an interrupted append or silently replaced with a different
    // checksum-valid batch while deriving permission to discard it.
    prepared: Option<PreparedIdentity>,
}

enum Scanned {
    Record,
    Commit,
    Damage,
}

/// Replay committed batches from `start` through the newest confirmed segment
/// the root records in `bounds`. `visit` receives each committed batch in
/// order; on error the caller discards everything built from earlier batches.
///
/// Only the newest confirmed segment and the outstanding intent's file can
/// hold writes whose synchronization failed, and a restart without power loss
/// still reads them. Replay synchronizes both before reading, so what it
/// serves survives a later power loss; a failure is plain I/O and the owner
/// fences.
pub(crate) fn replay(
    backend: &dyn SegmentGroupBackend,
    group_id: [u8; 16],
    start: &ReplayStart,
    bounds: &LogBounds,
    visit: impl FnMut(ReplayedBatch) -> Result<(), CoreError>,
) -> Result<ReplayEnd, CoreError> {
    replay_limited(
        backend,
        group_id,
        start,
        bounds,
        MAX_BATCH_OPERATIONS,
        true,
        visit,
    )
}

/// Reopen the authoritative directory without rebuilding an operation map.
/// Every operation is decoded and checked, then its owned table/key backing
/// is dropped. Record digests, logical versions, operation/byte bounds and
/// torn-tail decisions are identical to full replay.
pub(crate) fn replay_roots(
    backend: &dyn SegmentGroupBackend,
    group_id: [u8; 16],
    start: &ReplayStart,
    bounds: &LogBounds,
    mut visit: impl FnMut(ReplayedRoot) -> Result<(), CoreError>,
) -> Result<ReplayEnd, CoreError> {
    replay_limited(
        backend,
        group_id,
        start,
        bounds,
        MAX_BATCH_OPERATIONS,
        false,
        |batch| {
            visit(ReplayedRoot {
                end: batch.end,
                batch_seq: batch.batch_seq,
                chain: batch.chain,
                directory_root: batch.directory_root,
            })
        },
    )
}

/// Fixed transient charge for root-only replay, including one decoded key,
/// inline/value read windows, torn-tail search and allocation/lease overhead.
pub(crate) fn root_replay_workspace_bytes() -> u64 {
    maintenance_workspace_bytes()
}

/// Every abort admits only its prepared operation count, regardless of
/// the value lengths. The cap is checked before decoding another owned record;
/// malformed private tails cannot turn a large value into unbounded key
/// scratch. Normal reopen retains the public transaction bounds.
fn replay_limited(
    backend: &dyn SegmentGroupBackend,
    group_id: [u8; 16],
    start: &ReplayStart,
    bounds: &LogBounds,
    max_operations: usize,
    retain_records: bool,
    visit: impl FnMut(ReplayedBatch) -> Result<(), CoreError>,
) -> Result<ReplayEnd, CoreError> {
    replay_with_policy(
        backend,
        group_id,
        start,
        bounds,
        ReplayPolicy {
            max_operations,
            retain_records,
            prepared: None,
        },
        visit,
    )
}

fn replay_with_policy(
    backend: &dyn SegmentGroupBackend,
    group_id: [u8; 16],
    start: &ReplayStart,
    bounds: &LogBounds,
    policy: ReplayPolicy,
    mut visit: impl FnMut(ReplayedBatch) -> Result<(), CoreError>,
) -> Result<ReplayEnd, CoreError> {
    if let Some(prepared) = policy.prepared
        && (prepared.group_id != group_id
            || prepared.start != *start
            || prepared.end.segment_id != bounds.last_segment_id
            || bounds.pending_segment.is_some()
            || prepared.operation_count == 0
            || prepared.operation_count as usize != policy.max_operations
            || policy.retain_records)
    {
        return Err(CoreError::InvalidInput("prepared replay token differs"));
    }
    let LogBounds {
        last_segment_id,
        pending_segment,
        sealed,
    } = *bounds;
    if pending_segment.is_some_and(|pending| last_segment_id.checked_add(1) != Some(pending)) {
        return Err(CoreError::Corrupt(
            "segment intent is not the next identifier",
        ));
    }
    if let Some(pending) = pending_segment {
        let file = GroupFile::segment(pending);
        if backend.exists(file)? {
            backend.sync(file)?;
        }
        check_pending_segment(backend, &group_id, pending)?;
    }
    let mut replay = Replay {
        directory_end: None,
        directory_root: None,
        backend,
        group_id,
        batch_seq: start.batch_seq,
        chain: start.chain,
        max_seen: start.batch_seq,
        pending: None,
        segment_attempt: None,
        max_operations: policy.max_operations,
        retain_records: policy.retain_records,
        prepared: policy.prepared,
    };
    let mut end = ReplayEnd {
        directory_end: None,
        directory_root: None,
        batch_seq: start.batch_seq,
        chain: start.chain,
        next_batch_seq: 0,
        resume: None,
        final_len: 0,
        tail_head: [0; RECORD_HEADER_BYTES],
        torn_at: None,
        uncommitted_batch: None,
        pending_segment,
    };
    if last_segment_id == 0 {
        if *start != ReplayStart::GENESIS {
            return Err(CoreError::Corrupt("replay start names a missing segment"));
        }
    } else {
        let first = start.position.segment_id;
        if first == 0 || first > last_segment_id || start.position.offset < SEGMENT_HEADER_BYTES {
            return Err(CoreError::Corrupt("replay start is outside the log"));
        }
        for segment_id in first..=last_segment_id {
            let file = GroupFile::segment(segment_id);
            if !backend.exists(file)? {
                return Err(CoreError::Corrupt("confirmed segment is missing"));
            }
            let newest = segment_id == last_segment_id;
            // Sealed segments were synchronized before their successor's
            // intent was published.
            if newest {
                backend.sync(file)?;
            }
            if read_segment_header(backend, &group_id, segment_id)? != HeaderState::Valid {
                return Err(CoreError::Corrupt("confirmed segment header is damaged"));
            }
            let len = backend.len(file)?;
            if let Some(prepared) = policy.prepared
                && newest
                && len != prepared.end.offset
            {
                return Err(CoreError::Corrupt("prepared batch end differs"));
            }
            let offset = if segment_id == first {
                start.position.offset
            } else {
                SEGMENT_HEADER_BYTES
            };
            if offset > len {
                return Err(CoreError::Corrupt("replay start exceeds segment length"));
            }
            // A segment intent is published only after its predecessor was
            // synchronized, so an outstanding intent seals the newest segment.
            let is_sealed = !newest || pending_segment.is_some();
            replay.segment_attempt = None;
            let mut resume = offset;
            let mut reader = FileReader::new(backend, file, len, offset);
            while reader.remaining() > 0 {
                let at = reader.pos();
                match replay.record(&mut reader, segment_id, &mut visit)? {
                    Scanned::Record => {}
                    Scanned::Commit => resume = reader.pos(),
                    Scanned::Damage if policy.prepared.is_some() => {
                        return Err(CoreError::Corrupt(
                            "synchronized prepared prefix is damaged",
                        ));
                    }
                    Scanned::Damage if is_sealed => {
                        return Err(CoreError::Corrupt("sealed segment record is damaged"));
                    }
                    Scanned::Damage => {
                        replay.check_torn_tail(file, segment_id, at, len)?;
                        end.torn_at = Some(at);
                        break;
                    }
                }
            }
            // Only a sealed segment is recorded. With the commit chain this
            // also finds a commit lost from any earlier sealed segment: a
            // later commit breaks the chain, a later record names the lost
            // commit as its base, and without either the replayed sequence
            // falls short of this record.
            if sealed.is_some_and(|record| record.segment_id == segment_id)
                && sealed
                    != Some(SealedSegment {
                        segment_id,
                        len,
                        commit_seq: replay.batch_seq,
                    })
            {
                return Err(CoreError::Corrupt(
                    "sealed segment differs from its root record",
                ));
            }
            if newest {
                let resume = if is_sealed { len } else { resume };
                let present = (len - resume).min(RECORD_HEADER_BYTES as u64) as usize;
                backend.read(file, resume, &mut end.tail_head[..present])?;
                end.resume = Some(LogPosition {
                    segment_id,
                    offset: resume,
                });
                end.final_len = len;
            }
        }
    }
    if let Some(prepared) = policy.prepared {
        let pending = replay
            .pending
            .as_ref()
            .ok_or(CoreError::Corrupt("prepared operation prefix is missing"))?;
        if pending.batch_seq != prepared.batch_seq
            || pending.op_count != prepared.operation_count as usize
            || pending.directory_root.is_some()
        {
            return Err(CoreError::Corrupt("prepared operation prefix differs"));
        }
        let observed: [u8; 32] = pending.ops.clone().finalize().into();
        if observed != prepared.ops_sha256 {
            return Err(CoreError::Corrupt("prepared operation digest differs"));
        }
    }
    end.directory_end = replay.directory_end;
    end.directory_root = replay.directory_root;
    end.batch_seq = replay.batch_seq;
    end.chain = replay.chain;
    end.uncommitted_batch = replay.pending.as_ref().map(|pending| pending.batch_seq);
    end.next_batch_seq = replay
        .max_seen
        .checked_add(1)
        .ok_or(CoreError::Corrupt("batch sequence overflow"))?;
    Ok(end)
}

/// Check the file of an outstanding segment intent and report whether it is
/// present. The roll creates it empty and then writes this segment's header,
/// so the only valid image is up to 64 bytes, each zero or equal to that
/// header's byte at its offset. Any other image is not this group's roll.
fn check_pending_segment(
    backend: &dyn SegmentGroupBackend,
    group_id: &[u8; 16],
    segment_id: u64,
) -> Result<bool, CoreError> {
    let file = GroupFile::segment(segment_id);
    if !backend.exists(file)? {
        return Ok(false);
    }
    // Records are appended only after the root confirms the segment.
    let len = backend.len(file)?;
    if len > SEGMENT_HEADER_BYTES {
        return Err(CoreError::Corrupt("unconfirmed segment holds records"));
    }
    let mut bytes = [0u8; SEGMENT_HEADER_BYTES as usize];
    let bytes = &mut bytes[..len as usize];
    backend.read(file, 0, bytes)?;
    decode_segment_header(bytes, group_id, segment_id)?;
    let header = segment_header(group_id, segment_id);
    if bytes
        .iter()
        .zip(header)
        .any(|(&byte, expected)| byte != 0 && byte != expected)
    {
        return Err(CoreError::Corrupt(
            "unconfirmed segment holds bytes other than its header",
        ));
    }
    Ok(true)
}

impl Replay<'_> {
    fn record(
        &mut self,
        reader: &mut FileReader<'_>,
        segment_id: u64,
        visit: &mut impl FnMut(ReplayedBatch) -> Result<(), CoreError>,
    ) -> Result<Scanned, CoreError> {
        let at = LogPosition {
            segment_id,
            offset: reader.pos(),
        };
        if reader.remaining() < RECORD_HEADER_BYTES as u64 {
            return Ok(Scanned::Damage);
        }
        let mut header = [0u8; RECORD_HEADER_BYTES];
        reader.read_exact(&mut header)?;
        let Some(head) = decode_record_header(&header, &self.group_id, at)? else {
            return Ok(Scanned::Damage);
        };
        if let Some(prepared) = self.prepared {
            if head.batch_seq != prepared.batch_seq {
                return Err(CoreError::Corrupt("prepared operation batch differs"));
            }
            if matches!(head.kind, RecordKind::Commit | RecordKind::Directory) {
                return Err(CoreError::Corrupt(
                    "prepared prefix contains a publication record",
                ));
            }
        }
        if head.base_seq != self.batch_seq {
            return Err(CoreError::Corrupt(
                "segment record does not follow the newest commit",
            ));
        }
        if u64::from(head.body_len) > reader.remaining() {
            return Ok(Scanned::Damage);
        }
        if head.kind == RecordKind::Commit {
            let mut body = [0u8; COMMIT_BODY_BYTES];
            reader.read_exact(&mut body)?;
            if crc32c(&body) != head.body_crc {
                return Ok(Scanned::Damage);
            }
            self.commit(
                head.batch_seq,
                LogPosition {
                    segment_id,
                    offset: reader.pos(),
                },
                &decode_commit_body(&body)?,
                visit,
            )?;
            self.segment_attempt = None;
            return Ok(Scanned::Commit);
        }
        // Reopen discards an abandoned tail before the next batch, so records
        // between two commits of one segment are one batch attempt.
        if self
            .segment_attempt
            .replace(head.batch_seq)
            .is_some_and(|attempt| attempt != head.batch_seq)
        {
            return Err(CoreError::Corrupt(
                "segment interleaves two uncommitted batches",
            ));
        }
        self.max_seen = self.max_seen.max(head.batch_seq);
        if head.kind == RecordKind::Directory {
            let mut bytes = [0u8; DIRECTORY_ROOT_BYTES];
            reader.read_exact(&mut bytes)?;
            if crc32c(&bytes) != head.body_crc {
                return Ok(Scanned::Damage);
            }
            let directory_root = DirectoryRoot::decode(&bytes)?;
            if directory_root.group_id != self.group_id
                || directory_root.generation != head.batch_seq
            {
                return Err(CoreError::Corrupt("directory root does not name its batch"));
            }
            let pending = self
                .pending
                .as_mut()
                .filter(|pending| pending.batch_seq == head.batch_seq && pending.op_count != 0)
                .ok_or(CoreError::Corrupt("directory root has no matching batch"))?;
            if pending.directory_root.replace(directory_root).is_some() {
                return Err(CoreError::Corrupt("batch has two directory roots"));
            }
            return Ok(Scanned::Record);
        }
        let max_operations = self.max_operations;
        let retain_records = self.retain_records;
        let pending = self.pending_for(head.batch_seq)?;
        if pending.directory_root.is_some() {
            return Err(CoreError::Corrupt(
                "operation follows prepared directory root",
            ));
        }
        let kind = match head.kind {
            RecordKind::Relocate => BatchKind::Relocation,
            RecordKind::Maintenance => BatchKind::DirectoryOnly,
            _ => BatchKind::User,
        };
        if pending.op_count >= max_operations {
            return Err(CoreError::Corrupt("batch exceeds replay operation bound"));
        }
        if pending.kind.is_some_and(|previous| previous != kind)
            || (kind == BatchKind::DirectoryOnly && pending.op_count != 0)
        {
            return Err(CoreError::Corrupt("maintenance batch mixes operations"));
        }
        if kind != BatchKind::User && pending.op_count >= MAX_MAINTENANCE_OPERATIONS {
            return Err(CoreError::Corrupt(
                "maintenance batch exceeds operation bound",
            ));
        }
        pending.encoded_bytes = pending
            .encoded_bytes
            .checked_add(RECORD_HEADER_BYTES + head.body_len as usize)
            .ok_or(CoreError::Corrupt("batch encoded size overflows"))?;
        if kind != BatchKind::User && pending.encoded_bytes > MAX_BATCH_BYTES {
            return Err(CoreError::Corrupt(
                "maintenance batch exceeds encoded byte bound",
            ));
        }
        pending.kind = Some(kind);
        pending.ops.update(header);
        let value_at = reader.pos();
        let body = read_body(reader, &head, &mut pending.ops)?;
        let Some((inline, value_crc)) = body else {
            return Ok(Scanned::Damage);
        };
        let record = decode_operation(head, &inline, value_crc, segment_id, value_at)?;
        let (table, key, value) = match &record {
            ReplayedRecord::CreateTable { table } => (table.len(), 0, 0),
            ReplayedRecord::Put { table, key, value } => {
                (table.len(), key.len(), value.len as usize)
            }
            ReplayedRecord::Relocate {
                table, key, value, ..
            } => (table.len(), key.len(), value.len as usize),
            ReplayedRecord::Delete { table, key } => (table.len(), key.len(), 0),
            ReplayedRecord::DirectoryOnly => (0, 0, 0),
        };
        pending.bytes += table + key + value;
        if pending.op_count >= MAX_BATCH_OPERATIONS || pending.bytes > MAX_BATCH_BYTES {
            return Err(CoreError::Corrupt("batch exceeds its physical bounds"));
        }
        pending.op_count += 1;
        if retain_records {
            pending.records.push(record);
        }
        Ok(Scanned::Record)
    }

    fn pending_for(&mut self, batch_seq: u64) -> Result<&mut PendingBatch, CoreError> {
        match &self.pending {
            Some(pending) if pending.batch_seq == batch_seq => {}
            Some(pending) if pending.batch_seq > batch_seq => {
                return Err(CoreError::Corrupt("batch sequence regressed"));
            }
            // A later sequence abandons trailing records that never committed.
            Some(_) | None => {
                if batch_seq <= self.batch_seq {
                    return Err(CoreError::Corrupt("batch sequence regressed"));
                }
                self.pending = Some(PendingBatch {
                    batch_seq,
                    directory_root: None,
                    records: Vec::new(),
                    op_count: 0,
                    bytes: 0,
                    encoded_bytes: 0,
                    ops: Sha256::new(),
                    kind: None,
                });
            }
        }
        Ok(self.pending.as_mut().expect("pending batch"))
    }

    fn commit(
        &mut self,
        batch_seq: u64,
        end: LogPosition,
        body: &CommitBody,
        visit: &mut impl FnMut(ReplayedBatch) -> Result<(), CoreError>,
    ) -> Result<(), CoreError> {
        let pending = self
            .pending
            .take()
            .filter(|pending| pending.batch_seq == batch_seq)
            .ok_or(CoreError::Corrupt("commit record has no matching batch"))?;
        if pending.op_count != body.op_count as usize {
            return Err(CoreError::Corrupt("commit operation count differs"));
        }
        let ops_sha256: [u8; 32] = pending.ops.finalize().into();
        if ops_sha256 != body.ops_sha256 {
            return Err(CoreError::Corrupt("commit operation digest differs"));
        }
        let directory_root = pending
            .directory_root
            .ok_or(CoreError::Corrupt("commit has no prepared directory root"))?;
        if directory_root.encode()? != body.directory {
            return Err(CoreError::Corrupt("commit directory root differs"));
        }
        let chain = chain_digest(
            &self.group_id,
            &self.chain,
            batch_seq,
            body.op_count,
            &ops_sha256,
            &body.directory,
        );
        if chain != body.chain_sha256 {
            return Err(CoreError::Corrupt("commit chain differs"));
        }
        self.batch_seq = batch_seq;
        self.chain = chain;
        self.directory_root = Some(directory_root);
        self.directory_end = Some(end);
        visit(ReplayedBatch {
            end,
            batch_seq,
            chain,
            directory_root,
            records: pending.records,
        })
    }

    /// Accept damage at `from` in the newest segment as a torn append, or
    /// fail closed. Everything after the segment's last commit is one batch
    /// attempt appended after the newest replayed commit, and a commit is
    /// appended only after its records are synchronized. So a checksum-valid
    /// record after the damage that follows another commit or belongs to
    /// another batch, or any commit header after it, proves the damaged bytes
    /// were synchronized. Headers bind their position, so an image inside a
    /// value never counts. The bytes where the interrupted write began must
    /// also be that write (`check_interrupted_write`).
    fn check_torn_tail(
        &self,
        file: GroupFile,
        segment_id: u64,
        from: u64,
        len: u64,
    ) -> Result<(), CoreError> {
        let mut attempt = self.segment_attempt;
        let mut window = Vec::new();
        let mut at = from;
        while len - at >= RECORD_HEADER_BYTES as u64 {
            let fill = (len - at).min(SEARCH_WINDOW as u64) as usize;
            window.resize(fill, 0);
            self.backend.read(file, at, &mut window)?;
            let complete = at + fill as u64 == len;
            // Windows overlap by one header less a byte, so every candidate
            // header is whole in one of them.
            let scanned = fill - RECORD_HEADER_BYTES + 1;
            for index in 0..scanned {
                let bytes = &window[index..];
                if bytes[..4] != RECORD_MAGIC {
                    continue;
                }
                let header = bytes[..RECORD_HEADER_BYTES]
                    .try_into()
                    .expect("record header");
                let position = LogPosition {
                    segment_id,
                    offset: at + index as u64,
                };
                let Some(head) = decode_record_header(header, &self.group_id, position)? else {
                    continue;
                };
                if head.base_seq != self.batch_seq {
                    return Err(CoreError::Corrupt(
                        "damaged record precedes a record of a later commit",
                    ));
                }
                if *attempt.get_or_insert(head.batch_seq) != head.batch_seq {
                    return Err(CoreError::Corrupt(
                        "damaged record precedes records of another batch",
                    ));
                }
                // Directory preparation follows synchronized operations;
                // commit follows synchronized preparation. Either boundary
                // at `from` itself may be the interrupted write.
                if matches!(head.kind, RecordKind::Directory | RecordKind::Commit)
                    && position.offset != from
                {
                    return Err(CoreError::Corrupt(
                        "record before a synchronized batch boundary is damaged",
                    ));
                }
            }
            if complete {
                break;
            }
            at += scanned as u64;
        }
        self.check_interrupted_write(file, segment_id, from, len, attempt)
    }

    /// Find where the interrupted write began and require its bytes to be
    /// that write. A record from `from` whose header validates and whose body
    /// fits was written whole, and pages persisted out of order may have cut
    /// holes in it, so the walk passes it. The writer appended the record at
    /// the first other position past the synchronized end, where bytes read
    /// as zero, so an interrupted write left each byte zero or as written.
    /// With no damaged record before it, a commit there is the pending
    /// batch's, which replay rebuilds exactly; it is recognized by its kind
    /// or its header checksum. After a damaged record no commit can follow,
    /// since the commit write comes after the records are synchronized, so
    /// only an operation record header can begin there: its magic, kind,
    /// padding, batch and base are known. Any other byte means damage after
    /// the write: replay fails closed and the bytes stay for diagnosis
    /// instead of being discarded as a torn tail. `attempt` is the batch of
    /// the records after the segment's last commit, if any is known.
    fn check_interrupted_write(
        &self,
        file: GroupFile,
        segment_id: u64,
        from: u64,
        len: u64,
        attempt: Option<u64>,
    ) -> Result<(), CoreError> {
        let mut at = from;
        let mut header = [0u8; RECORD_HEADER_BYTES];
        while len - at >= RECORD_HEADER_BYTES as u64 {
            self.backend.read(file, at, &mut header)?;
            let position = LogPosition {
                segment_id,
                offset: at,
            };
            let Some(head) = decode_record_header(&header, &self.group_id, position)? else {
                break;
            };
            let end = at + RECORD_HEADER_BYTES as u64 + u64::from(head.body_len);
            if head.kind == RecordKind::Commit || end > len {
                break;
            }
            at = end;
        }
        let position = LogPosition {
            segment_id,
            offset: at,
        };
        let present = (len - at).min(COMMIT_RECORD_BYTES as u64) as usize;
        let mut bytes = [0u8; COMMIT_RECORD_BYTES];
        let bytes = &mut bytes[..present];
        self.backend.read(file, at, bytes)?;
        let written = if at == from {
            self.pending_commit(position)
        } else {
            None
        };
        if at != from && bytes.get(4) == Some(&RecordKind::Directory.tag()) {
            return Err(CoreError::Corrupt(
                "record before a synchronized batch boundary is damaged",
            ));
        }
        let is_commit = (present > 4 && bytes[4] == RecordKind::Commit.tag())
            || written.is_some_and(|written| {
                present >= RECORD_HEADER_BYTES
                    && bytes[32..36] != [0; 4]
                    && bytes[32..36] == written[32..36]
            });
        if is_commit {
            if at != from {
                return Err(CoreError::Corrupt(
                    "record before a synchronized batch boundary is damaged",
                ));
            }
            let written =
                written.ok_or(CoreError::Corrupt("commit record has no matching batch"))?;
            if bytes
                .iter()
                .zip(written)
                .any(|(&byte, written)| byte != 0 && byte != written)
            {
                return Err(CoreError::Corrupt("written commit record is damaged"));
            }
            return Ok(());
        }
        let batch = attempt.map(u64::to_le_bytes);
        let base = self.batch_seq.to_le_bytes();
        let as_written = |index: usize, byte: u8| match index {
            0..4 => byte == RECORD_MAGIC[index],
            4 => RecordKind::from_tag(byte).is_some_and(|kind| kind != RecordKind::Commit),
            5..8 => false,
            8..16 => batch.is_none_or(|batch| byte == batch[index - 8]),
            16..24 => byte == base[index - 16],
            // Lengths, checksums and bodies are unknown.
            _ => true,
        };
        if bytes
            .iter()
            .enumerate()
            .any(|(index, &byte)| byte != 0 && !as_written(index, byte))
        {
            return Err(CoreError::Corrupt(
                "damaged tail is not an interrupted write",
            ));
        }
        Ok(())
    }

    /// The commit record the writer appends at `at` for the pending batch.
    fn pending_commit(&self, at: LogPosition) -> Option<[u8; COMMIT_RECORD_BYTES]> {
        let pending = self.pending.as_ref()?;
        let directory = pending.directory_root?.encode().ok()?;
        let op_count = pending.op_count as u32;
        let ops_sha256: [u8; 32] = pending.ops.clone().finalize().into();
        let body = CommitBody {
            op_count,
            ops_sha256,
            chain_sha256: chain_digest(
                &self.group_id,
                &self.chain,
                pending.batch_seq,
                op_count,
                &ops_sha256,
                &directory,
            ),
            directory,
        };
        Some(commit_record(
            &self.group_id,
            at,
            pending.batch_seq,
            self.batch_seq,
            &body,
        ))
    }
}

/// Stream one operation body, returning its inline bytes (prefix, table and
/// key) and the checksum of the value remainder. `None` is checksum damage.
fn read_body(
    reader: &mut FileReader<'_>,
    head: &RecordHead,
    ops: &mut Sha256,
) -> Result<Option<(Vec<u8>, u32)>, CoreError> {
    let body_len = head.body_len as usize;
    let inline_len = body_len.min(MAX_INLINE_BODY);
    let mut inline = vec![0u8; inline_len];
    reader.read_exact(&mut inline)?;
    let mut body_crc = Crc32c::new();
    body_crc.update(&inline);
    ops.update(&inline);
    // The value of a well-formed put begins after its declared table and key.
    let value_start = if matches!(head.kind, RecordKind::Put | RecordKind::Relocate) {
        let prefix = if head.kind == RecordKind::Put {
            PUT_PREFIX_BYTES
        } else {
            RELOCATE_PREFIX_BYTES
        };
        (prefix + usize::from(le_u16(&inline[..2])) + usize::from(le_u16(&inline[2..4])))
            .min(inline_len)
    } else {
        inline_len
    };
    let mut value_crc = Crc32c::new();
    value_crc.update(&inline[value_start..]);
    let mut remaining = body_len - inline_len;
    let mut chunk = vec![0u8; remaining.min(IO_WINDOW)];
    while remaining > 0 {
        let take = remaining.min(IO_WINDOW);
        reader.read_exact(&mut chunk[..take])?;
        body_crc.update(&chunk[..take]);
        value_crc.update(&chunk[..take]);
        ops.update(&chunk[..take]);
        remaining -= take;
    }
    if body_crc.finish() != head.body_crc {
        return Ok(None);
    }
    Ok(Some((inline, value_crc.finish())))
}

/// Decode a checksum-valid operation body. Any inconsistency fails closed.
fn decode_operation(
    head: RecordHead,
    inline: &[u8],
    value_crc: u32,
    segment_id: u64,
    body_at: u64,
) -> Result<ReplayedRecord, CoreError> {
    let invalid = CoreError::Corrupt("segment operation record is invalid");
    let text = |bytes: &[u8]| {
        if bytes.is_empty() || bytes.len() > MAX_TABLE_BYTES {
            return Err(CoreError::Corrupt("segment operation record is invalid"));
        }
        String::from_utf8(bytes.to_vec())
            .map_err(|_| CoreError::Corrupt("segment table name is not UTF-8"))
    };
    match head.kind {
        RecordKind::CreateTable => Ok(ReplayedRecord::CreateTable {
            table: text(inline)?,
        }),
        RecordKind::Delete => {
            let table_len = usize::from(le_u16(&inline[..2]));
            let key_len = usize::from(le_u16(&inline[2..4]));
            if DELETE_PREFIX_BYTES + table_len + key_len != inline.len() || key_len > MAX_KEY_BYTES
            {
                return Err(invalid);
            }
            let key_at = DELETE_PREFIX_BYTES + table_len;
            Ok(ReplayedRecord::Delete {
                table: text(&inline[DELETE_PREFIX_BYTES..key_at])?,
                key: inline[key_at..].to_vec(),
            })
        }
        RecordKind::Put | RecordKind::Relocate => {
            let prefix = if head.kind == RecordKind::Put {
                PUT_PREFIX_BYTES
            } else {
                RELOCATE_PREFIX_BYTES
            };
            let table_len = usize::from(le_u16(&inline[..2]));
            let key_len = usize::from(le_u16(&inline[2..4]));
            let value_len = le_u32(&inline[4..8]);
            let key_at = prefix + table_len;
            let value_at = key_at + key_len;
            if key_len > MAX_KEY_BYTES
                || value_len as usize > MAX_VALUE_BYTES
                || value_at > inline.len()
                || value_at + value_len as usize != head.body_len as usize
                || inline[12..16].iter().any(|&byte| byte != 0)
            {
                return Err(invalid);
            }
            if le_u32(&inline[8..12]) != value_crc {
                return Err(CoreError::Corrupt("segment value checksum differs"));
            }
            let value = ValueLocation {
                segment_id,
                offset: body_at + value_at as u64,
                len: value_len,
                crc: value_crc,
            };
            let table = text(&inline[prefix..key_at])?;
            let key = inline[key_at..value_at].to_vec();
            if head.kind == RecordKind::Relocate {
                let logical_batch_seq = le_u64(&inline[PUT_PREFIX_BYTES..RELOCATE_PREFIX_BYTES]);
                if logical_batch_seq == 0 || logical_batch_seq > head.base_seq {
                    return Err(CoreError::Corrupt("relocation logical version is invalid"));
                }
                Ok(ReplayedRecord::Relocate {
                    table,
                    key,
                    logical_batch_seq,
                    value,
                })
            } else {
                Ok(ReplayedRecord::Put { table, key, value })
            }
        }
        RecordKind::Maintenance => {
            if inline.iter().any(|&byte| byte != 0) {
                return Err(CoreError::Corrupt(
                    "directory maintenance record is noncanonical",
                ));
            }
            Ok(ReplayedRecord::DirectoryOnly)
        }
        RecordKind::Commit | RecordKind::Directory => Err(invalid),
    }
}

/// A root-backed log over an in-memory group, shared by format tests.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::group::InMemoryGroup;
    use crate::root::{RootRoll, RootSelection, Superblock, select_root};

    pub(crate) const GROUP: [u8; 16] = *b"kasumi-test-grp1";

    pub(crate) struct Log {
        pub(crate) group: InMemoryGroup,
        pub(crate) root: Superblock,
        pub(crate) writer: SegmentWriter,
    }

    pub(crate) struct Reopened {
        pub(crate) root: Superblock,
        pub(crate) batches: Vec<ReplayedBatch>,
        pub(crate) end: ReplayEnd,
    }

    impl Log {
        pub(crate) fn new(capacity: u64) -> Self {
            Self {
                group: InMemoryGroup::new(),
                root: Superblock::genesis(GROUP),
                writer: SegmentWriter::new(GROUP).with_capacity(capacity),
            }
        }

        pub(crate) fn commit(
            &mut self,
            operations: &[Operation],
        ) -> Result<CommittedBatch, CoreError> {
            let mut roll = RootRoll::new(&self.group, &mut self.root);
            let prepared = self
                .writer
                .prepare_batch(&self.group, operations, &mut roll)?;
            let root = fixture_directory_root(prepared.batch_seq());
            self.writer
                .finish_batch(&self.group, prepared, root, &mut roll)
        }

        /// Discard the replayed tail and continue appending.
        pub(crate) fn resume(group: InMemoryGroup, reopened: &Reopened, capacity: u64) -> Self {
            reopened.end.discard_tail(&group).unwrap();
            Self {
                group,
                root: reopened.root.clone(),
                writer: SegmentWriter::resume(GROUP, &reopened.end).with_capacity(capacity),
            }
        }
    }

    // Segment format tests supply a root fixture; directory/owner tests prove
    // page synchronization and reachability before this boundary is invoked.
    pub(crate) fn fixture_directory_root(generation: u64) -> DirectoryRoot {
        DirectoryRoot {
            group_id: GROUP,
            generation,
            page: None,
            height: 0,
            entries: 0,
        }
    }

    pub(crate) fn selected_root(group: &InMemoryGroup) -> Result<Superblock, CoreError> {
        Ok(match select_root(group)? {
            RootSelection::Empty => Superblock::genesis(GROUP),
            RootSelection::Selected { superblock, .. } => superblock,
        })
    }

    pub(crate) fn reopen_from(
        group: &InMemoryGroup,
        start: &ReplayStart,
    ) -> Result<Reopened, CoreError> {
        let root = selected_root(group)?;
        root.census(group)?;
        let mut batches = Vec::new();
        let end = replay(group, GROUP, start, &root.log_bounds(), |batch| {
            batches.push(batch);
            Ok(())
        })?;
        Ok(Reopened { root, batches, end })
    }

    pub(crate) fn reopen(group: &InMemoryGroup) -> Result<Reopened, CoreError> {
        reopen_from(group, &ReplayStart::GENESIS)
    }

    pub(crate) fn corrupt_reason<T>(result: Result<T, CoreError>) -> &'static str {
        match result {
            Err(CoreError::Corrupt(reason)) => reason,
            Err(other) => panic!("expected corruption, got {other:?}"),
            Ok(_) => panic!("expected corruption, got success"),
        }
    }

    pub(crate) fn put(table: &str, key: &str, value: impl Into<Vec<u8>>) -> Operation {
        Operation::put(table, key.as_bytes().to_vec(), value)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::group::{FaultTiming, GroupOp, InMemoryGroup};
    use crate::root::{RootRoll, Superblock};

    const SMALL: u64 = 1024;

    fn keys(batch: &ReplayedBatch) -> Vec<(String, Vec<u8>)> {
        batch
            .records
            .iter()
            .map(|record| match record {
                ReplayedRecord::CreateTable { table } => (format!("+{table}"), Vec::new()),
                ReplayedRecord::Put { table, key, .. } => (table.clone(), key.clone()),
                ReplayedRecord::Delete { table, key } => (format!("-{table}"), key.clone()),
                ReplayedRecord::Relocate { table, key, .. } => (format!("~{table}"), key.clone()),
                ReplayedRecord::DirectoryOnly => (String::from("~directory"), Vec::new()),
            })
            .collect()
    }

    fn value_at(group: &InMemoryGroup, batch: &ReplayedBatch, index: usize) -> Vec<u8> {
        match &batch.records[index] {
            ReplayedRecord::Put { value, .. } => read_value(group, value).unwrap(),
            other => panic!("not a put: {other:?}"),
        }
    }

    /// Rewrite the checksums of a record in segment 1 after a deliberate
    /// field change.
    fn reseal_record(bytes: &mut [u8], at: usize) {
        let body_len = le_u32(&bytes[at + 24..at + 28]) as usize;
        let body = crc32c(&bytes[at + RECORD_HEADER_BYTES..at + RECORD_HEADER_BYTES + body_len]);
        bytes[at + 28..at + 32].copy_from_slice(&body.to_le_bytes());
        let position = LogPosition {
            segment_id: 1,
            offset: at as u64,
        };
        let header = header_checksum(&GROUP, position, &bytes[at..at + 32]);
        bytes[at + 32..at + 36].copy_from_slice(&header.to_le_bytes());
    }

    fn nonempty_directory_root(generation: u64) -> DirectoryRoot {
        DirectoryRoot {
            group_id: GROUP,
            generation,
            page: Some(crate::directory::DirectoryPageRef {
                arena_id: 7,
                page_index: generation,
                sha256: [generation as u8; 32],
            }),
            height: 1,
            entries: 3,
        }
    }

    #[test]
    fn writer_staging_retains_only_the_fixed_admitted_window() {
        let mut log = Log::new(SEGMENT_BYTES);
        // Without exact reservation these three extensions grow the stage
        // beyond 64 KiB despite keeping its length below 64 KiB throughout.
        let ops: Vec<_> = (0..3)
            .map(|index| put("t", &format!("k{index}"), vec![7; 20_000]))
            .collect();
        log.commit(&ops).unwrap();
        assert_eq!(log.writer.stage.capacity(), IO_WINDOW);
        assert!(log.writer.stage.is_empty());
        log.commit(&[Operation::create_table("u")]).unwrap();
        assert_eq!(log.writer.stage.capacity(), IO_WINDOW);
    }

    #[test]
    fn prepared_workspace_covers_exact_locations_and_streams_maximum_keys() {
        for count in [1, 3, 5, 17, 33, 65] {
            let operations: Vec<_> = (0..count)
                .map(|_| Operation::Delete {
                    table: "t".repeat(MAX_TABLE_BYTES).into(),
                    key: vec![7; MAX_KEY_BYTES],
                })
                .collect();
            let bound = prepared_batch_workspace_bytes(&operations).unwrap();
            let mut log = Log::new(SEGMENT_BYTES);
            let prepared = log
                .writer
                .prepare_batch(
                    &log.group,
                    &operations,
                    &mut RootRoll::new(&log.group, &mut log.root),
                )
                .unwrap();
            assert_eq!(prepared.values.capacity(), count);
            assert_eq!(prepared.identity.operation_count, count as u32);
            assert!(
                bound < 3 << 20,
                "maximum key payload was charged as a replay collection"
            );
            log.writer
                .abort_prepared(&log.group, prepared, &log.root.log_bounds())
                .unwrap();
            assert!(!log.writer.is_fenced());
        }
    }

    #[test]
    fn prepared_workspace_depends_on_location_count_not_borrowed_value_size() {
        let small = [put("t", "k", Vec::new())];
        let large = [put("t", "k", vec![9; 6 << 20])];
        assert_eq!(
            prepared_batch_workspace_bytes(&small).unwrap(),
            prepared_batch_workspace_bytes(&large).unwrap()
        );
        assert!(prepared_batch_workspace_bytes(&large).unwrap() < 3 << 20);
        let many: Vec<_> = (0..MAX_BATCH_OPERATIONS)
            .map(|_| Operation::create_table("t"))
            .collect();
        let bound = prepared_batch_workspace_bytes(&many).unwrap();
        let locations = MAX_BATCH_OPERATIONS * std::mem::size_of::<Option<ValueLocation>>();
        assert!(bound >= locations as u64);
        assert!(bound < 6 << 20);
    }

    #[test]
    fn operation_prepare_is_private_until_full_directory_root_commits() {
        let mut log = Log::new(SEGMENT_BYTES);
        let prepared = log
            .writer
            .prepare_batch(
                &log.group,
                &[put("t", "key", b"value".to_vec())],
                &mut RootRoll::new(&log.group, &mut log.root),
            )
            .unwrap();
        assert_eq!(prepared.batch_seq(), 1);
        assert_eq!(
            read_value(&log.group, &prepared.values()[0].unwrap()).unwrap(),
            b"value"
        );
        assert!(reopen(&log.group.crash()).unwrap().batches.is_empty());
        assert!(matches!(
            log.commit(&[Operation::create_table("later")]),
            Err(CoreError::OwnerFailed)
        ));
        let root = nonempty_directory_root(1);
        let committed = log
            .writer
            .finish_batch(
                &log.group,
                prepared,
                root,
                &mut RootRoll::new(&log.group, &mut log.root),
            )
            .unwrap();
        let replayed = reopen(&log.group.crash()).unwrap();
        assert_eq!(committed.directory_root, root);
        assert_eq!(replayed.batches[0].directory_root, root);
        assert_eq!(replayed.end.directory_root, Some(root));
    }

    #[test]
    fn known_private_failure_can_abort_and_resume_without_reusing_batch_sequence() {
        for capacity in [SMALL, SEGMENT_BYTES] {
            let mut log = Log::new(capacity);
            let first = log.commit(&[Operation::create_table("t")]).unwrap();
            let ops: Vec<_> = (0..8)
                .map(|index| put("t", &format!("k{index}"), vec![1; 300]))
                .collect();
            let prepared = log
                .writer
                .prepare_batch(
                    &log.group,
                    &ops,
                    &mut RootRoll::new(&log.group, &mut log.root),
                )
                .unwrap();
            let abandoned = prepared.batch_seq();
            log.writer
                .abort_prepared(&log.group, prepared, &log.root.log_bounds())
                .unwrap();
            let next = log
                .commit(&[put("t", "new", b"survives".to_vec())])
                .unwrap();
            assert!(next.batch_seq > abandoned);
            let replayed = reopen(&log.group.crash()).unwrap();
            assert_eq!(
                replayed
                    .batches
                    .iter()
                    .map(|batch| batch.batch_seq)
                    .collect::<Vec<_>>(),
                [first.batch_seq, next.batch_seq]
            );
            assert_eq!(value_at(&log.group, &replayed.batches[1], 0), b"survives");
        }
    }

    #[test]
    fn stale_prepared_abort_never_truncates_a_changed_tail() {
        for stale_bounds in [false, true] {
            let mut log = Log::new(SEGMENT_BYTES);
            let prepared = log
                .writer
                .prepare_batch(
                    &log.group,
                    &[Operation::create_table("t")],
                    &mut RootRoll::new(&log.group, &mut log.root),
                )
                .unwrap();
            let mut bounds = log.root.log_bounds();
            if stale_bounds {
                bounds.last_segment_id = 0;
            } else {
                let end = log.writer.position().unwrap();
                log.group
                    .write(GroupFile::segment(end.segment_id), end.offset, &[0xaa])
                    .unwrap();
            }
            let len = log.group.len(GroupFile::segment(1)).unwrap();
            assert!(matches!(
                log.writer.abort_prepared(&log.group, prepared, &bounds),
                Err(CoreError::InvalidInput(_))
            ));
            assert_eq!(log.group.len(GroupFile::segment(1)).unwrap(), len);
            assert!(matches!(
                log.commit(&[Operation::create_table("u")]),
                Err(CoreError::OwnerFailed)
            ));
        }
    }

    #[test]
    fn directory_preparation_failures_are_known_uncommitted() {
        for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
            for operation in [GroupOp::Write, GroupOp::Sync] {
                let mut log = Log::new(SEGMENT_BYTES);
                log.commit(&[Operation::create_table("t")]).unwrap();
                log.group.fail(operation, 2, timing);
                assert!(matches!(
                    log.commit(&[put("t", "lost", vec![1])]),
                    Err(CoreError::Io(_))
                ));
                let replayed = reopen(&log.group.crash()).unwrap();
                assert_eq!(replayed.batches.len(), 1);
                assert_eq!(replayed.end.uncommitted_batch, Some(2));
            }
        }
    }

    #[test]
    fn directory_preparation_proves_prior_operations_were_synchronized() {
        let mut log = Log::new(SEGMENT_BYTES);
        log.commit(&[Operation::create_table("t")]).unwrap();
        let prepared = log
            .writer
            .prepare_batch(
                &log.group,
                &[put("t", "key", b"value".to_vec())],
                &mut RootRoll::new(&log.group, &mut log.root),
            )
            .unwrap();
        let location = prepared.values()[0].unwrap();
        let root = nonempty_directory_root(prepared.batch_seq());
        // Root preparation is durable, but commit writing never starts.
        log.group.fail(GroupOp::Write, 2, FaultTiming::BeforeEffect);
        assert!(matches!(
            log.writer.finish_batch(
                &log.group,
                prepared,
                root,
                &mut RootRoll::new(&log.group, &mut log.root),
            ),
            Err(CoreError::UnknownCommit(_))
        ));
        let group = log.group.crash();
        group.with_durable(GroupFile::segment(location.segment_id), |bytes| {
            bytes[location.offset as usize] ^= 1;
        });
        assert_eq!(
            corrupt_reason(reopen(&group)),
            "record before a synchronized batch boundary is damaged"
        );
    }

    #[test]
    fn finish_rejects_wrong_incarnation_or_generation_before_commit() {
        for wrong_group in [false, true] {
            let mut log = Log::new(SEGMENT_BYTES);
            let prepared = log
                .writer
                .prepare_batch(
                    &log.group,
                    &[Operation::create_table("t")],
                    &mut RootRoll::new(&log.group, &mut log.root),
                )
                .unwrap();
            let mut root = nonempty_directory_root(prepared.batch_seq());
            if wrong_group {
                root.group_id[0] ^= 1;
            } else {
                root.generation += 1;
            }
            assert!(matches!(
                log.writer.finish_batch(
                    &log.group,
                    prepared,
                    root,
                    &mut RootRoll::new(&log.group, &mut log.root),
                ),
                Err(CoreError::InvalidInput(_))
            ));
            assert!(reopen(&log.group.crash()).unwrap().batches.is_empty());
            assert!(matches!(
                log.commit(&[Operation::create_table("u")]),
                Err(CoreError::OwnerFailed)
            ));
        }
    }

    #[test]
    fn commit_root_is_bound_to_preparation_and_chain() {
        let mut log = Log::new(SEGMENT_BYTES);
        let prepared = log
            .writer
            .prepare_batch(
                &log.group,
                &[Operation::create_table("t")],
                &mut RootRoll::new(&log.group, &mut log.root),
            )
            .unwrap();
        let committed = log
            .writer
            .finish_batch(
                &log.group,
                prepared,
                nonempty_directory_root(1),
                &mut RootRoll::new(&log.group, &mut log.root),
            )
            .unwrap();
        let commit_at = committed.end.offset as usize - COMMIT_RECORD_BYTES;
        let directory_at = commit_at - DIRECTORY_RECORD_BYTES;
        for change_preparation in [false, true] {
            let group = log.group.crash();
            group.with_durable(GroupFile::segment(1), |bytes| {
                // Change a page digest byte while keeping canonical root and record CRCs.
                bytes[commit_at + RECORD_HEADER_BYTES + 72 + 56] ^= 1;
                reseal_record(bytes, commit_at);
                if change_preparation {
                    bytes[directory_at + RECORD_HEADER_BYTES + 56] ^= 1;
                    reseal_record(bytes, directory_at);
                }
            });
            assert_eq!(
                corrupt_reason(reopen(&group)),
                if change_preparation {
                    "commit chain differs"
                } else {
                    "commit directory root differs"
                }
            );
        }
    }

    #[test]
    fn replay_keeps_exact_committed_directory_boundary_before_a_later_roll() {
        let mut log = Log::new(SMALL);
        let committed = log.commit(&[Operation::create_table("t")]).unwrap();
        let _prepared = log
            .writer
            .prepare_batch(
                &log.group,
                &[put("t", "big", vec![7; 900])],
                &mut RootRoll::new(&log.group, &mut log.root),
            )
            .unwrap();
        let replayed = reopen(&log.group.crash()).unwrap();
        assert_eq!(replayed.end.directory_end, Some(committed.end));
        assert_ne!(replayed.end.directory_end, replayed.end.resume);
        assert_eq!(replayed.batches[0].end, committed.end);
        validate_directory_anchor(
            &log.group,
            GROUP,
            replayed.end.directory_root.unwrap(),
            &ReplayStart {
                position: replayed.end.directory_end.unwrap(),
                batch_seq: replayed.end.batch_seq,
                chain: replayed.end.chain,
            },
        )
        .unwrap();
    }

    #[test]
    fn directory_anchor_must_match_exact_preceding_commit() {
        let mut log = Log::new(SEGMENT_BYTES);
        let first = log.commit(&[Operation::create_table("t")]).unwrap();
        let second = log.commit(&[put("t", "a", vec![1])]).unwrap();
        let start = ReplayStart {
            position: second.end,
            batch_seq: second.batch_seq,
            chain: second.chain,
        };
        validate_directory_anchor(&log.group, GROUP, second.directory_root, &start).unwrap();
        let mut substituted = first.directory_root;
        substituted.generation = second.batch_seq;
        // Both fixture roots are empty: change the fully canonical root to a different tree.
        substituted = DirectoryRoot {
            generation: substituted.generation,
            ..nonempty_directory_root(1)
        };
        assert_eq!(
            corrupt_reason(validate_directory_anchor(
                &log.group,
                GROUP,
                substituted,
                &start
            )),
            "directory anchor differs from committed root"
        );
        let shifted = ReplayStart {
            position: LogPosition {
                offset: start.position.offset - 1,
                ..start.position
            },
            ..start
        };
        assert!(
            validate_directory_anchor(&log.group, GROUP, second.directory_root, &shifted).is_err()
        );
        let wrong_chain = ReplayStart {
            chain: [9; 32],
            ..start
        };
        assert_eq!(
            corrupt_reason(validate_directory_anchor(
                &log.group,
                GROUP,
                second.directory_root,
                &wrong_chain
            )),
            "directory anchor differs from committed root"
        );
        validate_directory_anchor(
            &log.group,
            GROUP,
            fixture_directory_root(0),
            &ReplayStart::GENESIS,
        )
        .unwrap();
    }

    #[test]
    fn retired_segment_format_is_rejected_without_fallback() {
        let mut bytes = segment_header(&GROUP, 1);
        bytes[..16].copy_from_slice(b"KASUMI-KVSEG0001");
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        let crc = crc32c(&bytes[..60]);
        bytes[60..].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            corrupt_reason(decode_segment_header(&bytes, &GROUP, 1)),
            "unsupported KASUMI-KVSEG0001 segmented image"
        );
    }

    #[test]
    fn batches_round_trip_through_replay() {
        let mut log = Log::new(SEGMENT_BYTES);
        let first = log
            .commit(&[
                Operation::create_table("t"),
                put("t", "a", b"alpha".to_vec()),
                put("t", "empty", Vec::new()),
            ])
            .unwrap();
        let second = log
            .commit(&[
                Operation::delete("t", b"a".to_vec()),
                put("t", "b", vec![7; 70_000]),
            ])
            .unwrap();
        assert_eq!((first.batch_seq, second.batch_seq), (1, 2));
        assert_eq!(first.values[0], None);
        assert_eq!(
            read_value(&log.group, &first.values[1].unwrap()).unwrap(),
            b"alpha"
        );

        let reopened = reopen(&log.group.crash()).unwrap();
        assert_eq!(reopened.batches.len(), 2);
        assert_eq!(
            keys(&reopened.batches[0]),
            [
                ("+t".to_owned(), Vec::new()),
                ("t".to_owned(), b"a".to_vec()),
                ("t".to_owned(), b"empty".to_vec()),
            ]
        );
        assert_eq!(
            keys(&reopened.batches[1]),
            [
                ("-t".to_owned(), b"a".to_vec()),
                ("t".to_owned(), b"b".to_vec())
            ]
        );
        assert_eq!(
            value_at(&log.group, &reopened.batches[1], 1),
            vec![7; 70_000]
        );
        assert_eq!(
            reopened.batches[1].records[1],
            ReplayedRecord::Put {
                table: "t".to_owned(),
                key: b"b".to_vec(),
                value: second.values[1].unwrap(),
            }
        );
        assert_eq!(reopened.batches[1].chain, second.chain);
        assert_eq!(reopened.end.batch_seq, 2);
        assert_eq!(reopened.end.chain, log.writer.chain());
        assert_eq!(reopened.end.next_batch_seq, 3);
        assert_eq!(reopened.end.resume, Some(second.end));
        assert_eq!(reopened.end.torn_at, None);
        assert_eq!(reopened.end.uncommitted_batch, None);
        assert_eq!(reopened.root.last_segment_id(), 1);
    }

    #[test]
    fn invalid_batches_are_rejected_before_any_effect() {
        let mut log = Log::new(SEGMENT_BYTES);
        let long_key = "k".repeat(MAX_KEY_BYTES + 1);
        for operations in [
            Vec::new(),
            vec![Operation::create_table("")],
            vec![put("t", &long_key, Vec::new())],
            vec![put("t", "k", vec![0; MAX_VALUE_BYTES + 1])],
            vec![Operation::delete(
                "t".repeat(MAX_TABLE_BYTES + 1),
                b"k".to_vec(),
            )],
        ] {
            assert!(matches!(
                log.commit(&operations),
                Err(CoreError::InvalidInput(_))
            ));
        }
        assert!(!log.group.exists(GroupFile::segment(1)).unwrap());
        assert_eq!(log.root.generation(), 0);
        log.commit(&[Operation::create_table("t")]).unwrap();
    }

    #[test]
    fn largest_value_is_one_record_in_one_segment() {
        let mut log = Log::new(SEGMENT_BYTES);
        log.commit(&[
            Operation::create_table("t"),
            put("t", "small", vec![1; 4096]),
        ])
        .unwrap();
        let value = vec![0xa5; MAX_VALUE_BYTES];
        let batch = log.commit(&[put("t", "large", value)]).unwrap();
        let location = batch.values[0].unwrap();
        assert_eq!(location.len as usize, MAX_VALUE_BYTES);
        assert_eq!(location.segment_id, 1);
        assert_eq!(log.root.last_segment_id(), 1);
        let reopened = reopen(&log.group.crash()).unwrap();
        assert_eq!(reopened.batches.len(), 2);
        let stored = value_at(&log.group, &reopened.batches[1], 0);
        assert!(stored.len() == MAX_VALUE_BYTES && stored.iter().all(|&byte| byte == 0xa5));
    }

    struct FailingRoll<'a> {
        inner: RootRoll<'a>,
        reserves_left: usize,
    }

    impl SegmentRoll for FailingRoll<'_> {
        fn reserve(&mut self, sealed: Option<SealedSegment>) -> Result<u64, CoreError> {
            if self.reserves_left == 0 {
                return Err(CoreError::Io(std::io::Error::other(
                    "injected intent failure",
                )));
            }
            self.reserves_left -= 1;
            self.inner.reserve(sealed)
        }

        fn confirm(&mut self, segment_id: u64) -> Result<(), CoreError> {
            self.inner.confirm(segment_id)
        }
    }

    #[test]
    fn batch_spans_segments_and_is_visible_only_after_commit() {
        let mut log = Log::new(SMALL);
        log.commit(&[Operation::create_table("t")]).unwrap();
        let spanning: Vec<_> = (0..8)
            .map(|index| put("t", &format!("k{index}"), vec![index as u8; 300]))
            .collect();
        let batch = log.commit(&spanning).unwrap();
        let segments: std::collections::BTreeSet<_> = batch
            .values
            .iter()
            .map(|value| value.unwrap().segment_id)
            .collect();
        assert!(segments.len() >= 3, "{segments:?}");
        assert_eq!(log.root.last_segment_id(), batch.end.segment_id);

        // A second spanning batch stops when its next segment intent fails.
        // Its earlier records are durable in sealed segments without a commit.
        let abandoned: Vec<_> = (0..8)
            .map(|index| put("t", &format!("x{index}"), vec![0xee; 300]))
            .collect();
        let mut roll = FailingRoll {
            inner: RootRoll::new(&log.group, &mut log.root),
            reserves_left: 1,
        };
        let error = log
            .writer
            .prepare_batch(&log.group, &abandoned, &mut roll)
            .unwrap_err();
        assert!(matches!(error, CoreError::Io(_)), "{error:?}");
        assert!(matches!(
            log.commit(&[Operation::create_table("u")]),
            Err(CoreError::OwnerFailed)
        ));

        let group = log.group.crash();
        let reopened = reopen(&group).unwrap();
        assert_eq!(reopened.batches.len(), 2);
        assert_eq!(reopened.batches[1].records.len(), 8);
        assert_eq!(value_at(&group, &reopened.batches[1], 7), vec![7; 300]);
        assert_eq!(reopened.end.uncommitted_batch, Some(3));
        assert_eq!(reopened.end.next_batch_seq, 4);

        let mut resumed = Log::resume(group, &reopened, SMALL);
        let next = resumed.commit(&[put("t", "after", b"v".to_vec())]).unwrap();
        assert_eq!(next.batch_seq, 4);
        let again = reopen(&resumed.group.crash()).unwrap();
        let seqs: Vec<_> = again.batches.iter().map(|batch| batch.batch_seq).collect();
        assert_eq!(seqs, [1, 2, 4]);
        assert_eq!(again.end.uncommitted_batch, None);
    }

    #[test]
    fn failed_commit_write_is_unknown_and_reopen_hides_the_batch() {
        let mut log = Log::new(SEGMENT_BYTES);
        log.commit(&[Operation::create_table("t")]).unwrap();
        // Operation flush, directory preparation, then the commit write.
        log.group.fail(GroupOp::Write, 3, FaultTiming::BeforeEffect);
        let error = log.commit(&[put("t", "k", b"lost".to_vec())]).unwrap_err();
        assert!(matches!(error, CoreError::UnknownCommit(_)), "{error:?}");
        assert!(matches!(
            log.commit(&[put("t", "k", b"v".to_vec())]),
            Err(CoreError::OwnerFailed)
        ));

        let group = log.group.crash();
        let reopened = reopen(&group).unwrap();
        assert_eq!(reopened.batches.len(), 1);
        assert_eq!(reopened.end.uncommitted_batch, Some(2));
        assert_eq!(reopened.end.torn_at, None);
        let resume = reopened.end.resume.unwrap();
        assert!(reopened.end.final_len > resume.offset);

        let mut resumed = Log::resume(group, &reopened, SEGMENT_BYTES);
        assert_eq!(
            resumed.group.len(GroupFile::segment(1)).unwrap(),
            resume.offset
        );
        assert_eq!(
            resumed
                .commit(&[put("t", "k", b"v".to_vec())])
                .unwrap()
                .batch_seq,
            3
        );
        let again = reopen(&resumed.group.crash()).unwrap();
        assert_eq!(again.batches.len(), 2);
        assert_eq!(value_at(&resumed.group, &again.batches[1], 0), b"v");
    }

    #[test]
    fn failed_commit_sync_is_unknown_until_reopen_decides() {
        for (timing, visible) in [
            (FaultTiming::AfterEffect, true),
            (FaultTiming::BeforeEffect, false),
        ] {
            let mut log = Log::new(SEGMENT_BYTES);
            log.commit(&[Operation::create_table("t")]).unwrap();
            // Operation and directory preparation syncs precede the commit sync.
            log.group.fail(GroupOp::Sync, 3, timing);
            let error = log.commit(&[put("t", "k", b"maybe".to_vec())]).unwrap_err();
            assert!(matches!(error, CoreError::UnknownCommit(_)), "{error:?}");
            let reopened = reopen(&log.group.crash()).unwrap();
            assert_eq!(
                reopened.batches.len(),
                1 + usize::from(visible),
                "{timing:?}"
            );
            if !visible {
                // Only the unsynchronized commit record was lost.
                assert_eq!(reopened.end.uncommitted_batch, Some(2));
            }
        }
    }

    #[test]
    fn failed_record_write_is_a_known_rollback() {
        let mut log = Log::new(SEGMENT_BYTES);
        log.commit(&[Operation::create_table("t")]).unwrap();
        log.group.fail(GroupOp::Sync, 1, FaultTiming::AfterEffect);
        let error = log.commit(&[put("t", "k", b"never".to_vec())]).unwrap_err();
        // No commit record was attempted, so the batch cannot become visible.
        assert!(matches!(error, CoreError::Io(_)), "{error:?}");
        let reopened = reopen(&log.group.crash()).unwrap();
        assert_eq!(reopened.batches.len(), 1);
        assert_eq!(reopened.end.uncommitted_batch, Some(2));
    }

    #[test]
    fn torn_tail_is_discarded_and_appends_resume() {
        let mut probe = Log::new(SEGMENT_BYTES);
        probe.commit(&[Operation::create_table("t")]).unwrap();
        let committed = probe.writer.position().unwrap().offset;
        probe
            .commit(&[put("t", "k", vec![3; 200]), put("t", "l", vec![4; 10])])
            .unwrap();
        let full = probe.writer.position().unwrap().offset - committed;
        for keep in [
            1,
            31,
            32,
            33,
            60,
            250,
            full as usize - COMMIT_RECORD_BYTES - DIRECTORY_RECORD_BYTES - 1,
        ] {
            let mut log = Log::new(SEGMENT_BYTES);
            log.commit(&[Operation::create_table("t")]).unwrap();
            // The record sync never happens, so only a torn prefix persists.
            log.group.fail(GroupOp::Sync, 1, FaultTiming::BeforeEffect);
            log.commit(&[put("t", "k", vec![3; 200]), put("t", "l", vec![4; 10])])
                .unwrap_err();
            let group = log.group.crash_torn(GroupFile::segment(1), keep);
            let reopened = reopen(&group).unwrap();
            assert_eq!(reopened.batches.len(), 1, "{keep}");
            assert_eq!(reopened.end.resume.unwrap().offset, committed);
            assert_eq!(reopened.end.final_len, committed + keep as u64);
            let mut resumed = Log::resume(group, &reopened, SEGMENT_BYTES);
            let batch = resumed.commit(&[put("t", "z", b"after".to_vec())]).unwrap();
            assert!(batch.batch_seq >= 2);
            let again = reopen(&resumed.group.crash()).unwrap();
            assert_eq!(again.batches.len(), 2, "{keep}");
            assert_eq!(again.end.torn_at, None);
            assert_eq!(value_at(&resumed.group, &again.batches[1], 0), b"after");
        }
    }

    #[test]
    fn stale_tail_discard_never_removes_a_later_batch() {
        let later = [put("t", "z", b"after".to_vec())];
        let mut probe = Log::new(SEGMENT_BYTES);
        let first = probe.commit(&[Operation::create_table("t")]).unwrap();
        let later_len = probe.commit(&later).unwrap().end.offset - first.end.offset;
        let segment = GroupFile::segment(1);
        // A torn tail exactly as long as the later batch, and a longer one.
        for keep in [later_len, later_len + 40] {
            let mut log = Log::new(SEGMENT_BYTES);
            log.commit(&[Operation::create_table("t")]).unwrap();
            log.group.fail(GroupOp::Sync, 1, FaultTiming::BeforeEffect);
            log.commit(&[put("t", "k", vec![3; 400])]).unwrap_err();
            let group = log.group.crash_torn(segment, keep as usize);
            let reopened = reopen(&group).unwrap();
            let end = &reopened.end;
            assert_eq!(end.final_len - end.resume.unwrap().offset, keep);
            let mut resumed = Log::resume(group, &reopened, SEGMENT_BYTES);
            let acked = resumed.commit(&later).unwrap();
            let len = resumed.group.len(segment).unwrap();
            assert_eq!(len == end.final_len, keep == later_len);
            // Applying the stale end again is refused without effect.
            assert!(matches!(
                end.discard_tail(&resumed.group),
                Err(CoreError::InvalidInput(
                    "segment tail differs from the replayed tail"
                ))
            ));
            assert_eq!(resumed.group.len(segment).unwrap(), len);
            let again = reopen(&resumed.group.crash()).unwrap();
            assert_eq!(again.batches.len(), 2, "{keep}");
            assert_eq!(again.batches[1].batch_seq, acked.batch_seq);
            assert_eq!(value_at(&resumed.group, &again.batches[1], 0), b"after");
        }
    }

    #[test]
    fn interrupted_tail_discard_completes_on_retry() {
        let segment = GroupFile::segment(1);
        for (op, timing) in [
            (GroupOp::SetLen, FaultTiming::BeforeEffect),
            (GroupOp::SetLen, FaultTiming::AfterEffect),
            (GroupOp::Sync, FaultTiming::BeforeEffect),
        ] {
            let mut log = Log::new(SEGMENT_BYTES);
            log.commit(&[Operation::create_table("t")]).unwrap();
            log.group.fail(GroupOp::Sync, 1, FaultTiming::BeforeEffect);
            log.commit(&[put("t", "k", vec![3; 400])]).unwrap_err();
            let group = log.group.crash_torn(segment, 100);
            let reopened = reopen(&group).unwrap();
            let resume = reopened.end.resume.unwrap().offset;
            let final_len = reopened.end.final_len as usize;
            group.fail(op, 1, timing);
            assert!(matches!(
                reopened.end.discard_tail(&group),
                Err(CoreError::Io(_))
            ));
            assert_eq!(group.durable_len(segment), Some(final_len));
            // The retry sees either the replayed tail or a segment already
            // ending at the resume point, and completes.
            assert!(reopened.end.discard_tail(&group).unwrap(), "{op:?}");
            assert_eq!(group.durable_len(segment), Some(resume as usize));
            let mut resumed = Log::resume(group, &reopened, SEGMENT_BYTES);
            let acked = resumed.commit(&[put("t", "z", b"after".to_vec())]).unwrap();
            let again = reopen(&resumed.group.crash()).unwrap();
            assert_eq!(again.batches.len(), 2, "{op:?} {timing:?}");
            assert_eq!(again.batches[1].batch_seq, acked.batch_seq);
        }
    }

    #[test]
    fn sequence_and_identifier_ceilings_never_overflow() {
        let resumed_at = |batch_seq: u64| ReplayEnd {
            directory_end: None,
            directory_root: None,
            batch_seq,
            chain: [0; 32],
            next_batch_seq: batch_seq + 1,
            resume: None,
            final_len: 0,
            tail_head: [0; RECORD_HEADER_BYTES],
            torn_at: None,
            uncommitted_batch: None,
            pending_segment: None,
        };
        let mut log = Log {
            group: InMemoryGroup::new(),
            root: Superblock::genesis(GROUP),
            writer: SegmentWriter::resume(GROUP, &resumed_at(u64::MAX - 2)),
        };
        // The last usable sequence commits; the next is refused before any
        // effect and without fencing the writer.
        let last = log.commit(&[Operation::create_table("t")]).unwrap();
        assert_eq!(last.batch_seq, u64::MAX - 1);
        let generation = log.root.generation();
        let len = log.group.len(GroupFile::segment(1)).unwrap();
        for _ in 0..2 {
            assert!(matches!(
                log.commit(&[put("t", "k", b"v".to_vec())]),
                Err(CoreError::InvalidInput("batch sequence overflow"))
            ));
        }
        assert_eq!(log.root.generation(), generation);
        assert_eq!(log.group.len(GroupFile::segment(1)).unwrap(), len);
        // Replay leaves the same ceiling for the resumed writer.
        let start = ReplayStart {
            batch_seq: u64::MAX - 2,
            ..ReplayStart::GENESIS
        };
        let group = log.group.crash();
        let reopened = reopen_from(&group, &start).unwrap();
        assert_eq!(reopened.batches.len(), 1);
        assert_eq!(reopened.end.next_batch_seq, u64::MAX);
        let mut resumed = Log::resume(group, &reopened, SEGMENT_BYTES);
        assert!(matches!(
            resumed.commit(&[put("t", "k", b"v".to_vec())]),
            Err(CoreError::InvalidInput("batch sequence overflow"))
        ));
        // A replay start at the last sequence leaves no room at all.
        let full = ReplayStart {
            position: last.end,
            batch_seq: u64::MAX,
            chain: last.chain,
        };
        assert_eq!(
            corrupt_reason(reopen_from(&log.group.crash(), &full)),
            "batch sequence overflow"
        );
        // Bounds naming the last segment identifier fail closed.
        let bounds = LogBounds {
            last_segment_id: u64::MAX,
            pending_segment: Some(u64::MAX),
            sealed: None,
        };
        assert_eq!(
            corrupt_reason(replay(
                &log.group,
                GROUP,
                &ReplayStart::GENESIS,
                &bounds,
                |_| Ok(())
            )),
            "segment intent is not the next identifier"
        );
    }

    #[test]
    fn torn_commit_record_leaves_the_batch_invisible() {
        // A tear also lands in the source group's durable image, so each
        // case interrupts a fresh log.
        let interrupted = || {
            let mut log = Log::new(SEGMENT_BYTES);
            log.commit(&[Operation::create_table("t")]).unwrap();
            log.group.fail(GroupOp::Sync, 3, FaultTiming::BeforeEffect);
            log.commit(&[put("t", "k", b"v".to_vec())]).unwrap_err();
            log.group
        };
        let segment = GroupFile::segment(1);
        // Every prefix of the commit write, including one ending inside its
        // header or with the header whole.
        for keep in [5, 30, RECORD_HEADER_BYTES, 60, COMMIT_RECORD_BYTES - 1] {
            let group = interrupted().crash_torn(segment, keep);
            let reopened = reopen(&group).unwrap();
            assert_eq!(reopened.batches.len(), 1, "{keep}");
            assert_eq!(reopened.end.uncommitted_batch, Some(2));
            let torn_at = reopened.end.torn_at.unwrap();
            assert_eq!(reopened.end.final_len - torn_at, keep as u64);
        }
        // Pages persisted out of order: the whole length, with a zero run
        // where a page of the commit never reached the medium.
        let whole = interrupted().crash_torn(segment, COMMIT_RECORD_BYTES);
        let commit_at = whole.durable_len(segment).unwrap() - COMMIT_RECORD_BYTES;
        for zeroed in [
            commit_at + RECORD_HEADER_BYTES..commit_at + COMMIT_RECORD_BYTES,
            commit_at + 50..commit_at + 90,
        ] {
            let group = whole.crash();
            group.with_durable(segment, |bytes| bytes[zeroed.clone()].fill(0));
            let reopened = reopen(&group).unwrap();
            assert_eq!(reopened.batches.len(), 1, "{zeroed:?}");
            assert_eq!(reopened.end.torn_at, Some(commit_at as u64));
        }
    }

    #[test]
    fn commit_image_without_a_pending_batch_fails_closed() {
        let mut log = Log::new(SEGMENT_BYTES);
        let first = log.commit(&[Operation::create_table("t")]).unwrap();
        let segment = GroupFile::segment(1);
        // A commit image at the tail with no records before it, torn in its
        // body or whole but for a zero body.
        let body = CommitBody {
            op_count: 1,
            ops_sha256: [3; 32],
            chain_sha256: [4; 32],
            directory: fixture_directory_root(2).encode().unwrap(),
        };
        let image = commit_record(&GROUP, first.end, 2, 1, &body);
        for tail in [&image[..60], &image[..RECORD_HEADER_BYTES + 1]] {
            let group = log.group.crash();
            group.with_durable(segment, |bytes| bytes.extend_from_slice(tail));
            let len = group.durable_len(segment);
            assert_eq!(
                corrupt_reason(reopen(&group)),
                "commit record has no matching batch"
            );
            assert_eq!(group.durable_len(segment), len);
        }
    }

    #[test]
    fn restart_without_power_loss_keeps_what_replay_served() {
        let mut log = Log::new(SEGMENT_BYTES);
        log.commit(&[Operation::create_table("t")]).unwrap();
        // The commit record is written but its synchronization fails first.
        log.group.fail(GroupOp::Sync, 3, FaultTiming::BeforeEffect);
        let error = log.commit(&[put("t", "k", b"maybe".to_vec())]).unwrap_err();
        assert!(matches!(error, CoreError::UnknownCommit(_)), "{error:?}");
        assert_eq!(reopen(&log.group.crash()).unwrap().batches.len(), 1);
        // Synchronization at reopen fails as plain I/O and serves nothing.
        let same = log.group.clone();
        same.fail(GroupOp::Sync, 1, FaultTiming::BeforeEffect);
        assert!(matches!(reopen(&same), Err(CoreError::Io(_))));
        assert_eq!(reopen(&log.group.crash()).unwrap().batches.len(), 1);

        // The same process restarts, still reading the commit record.
        let served = reopen(&same).unwrap();
        assert_eq!(served.batches.len(), 2);
        assert_eq!(value_at(&same, &served.batches[1], 0), b"maybe");
        // A later power loss keeps what replay served.
        let after_power_loss = reopen(&same.crash()).unwrap();
        assert_eq!(after_power_loss.batches, served.batches);
        assert_eq!(after_power_loss.end, served.end);
    }

    #[test]
    fn restart_without_power_loss_keeps_an_unsynchronized_intent_file() {
        // The roll's header sync fails, so the intent file holds its header
        // in the page cache only.
        let mut log = Log::new(SMALL);
        log.commit(&[Operation::create_table("t")]).unwrap();
        log.group.fail(GroupOp::Sync, 2, FaultTiming::BeforeEffect);
        log.commit(&[put("t", "big", vec![1; 900])]).unwrap_err();
        let intent = GroupFile::segment(2);
        assert_eq!(log.group.durable_len(intent), Some(0));
        let same = log.group.clone();
        let served = reopen(&same).unwrap();
        assert_eq!(served.end.pending_segment, Some(2));
        assert_eq!(
            same.durable_image(intent),
            Some(segment_header(&GROUP, 2).to_vec())
        );
        assert_eq!(reopen(&same.crash()).unwrap().end, served.end);
    }

    #[test]
    fn damage_before_a_durable_commit_fails_closed() {
        let mut log = Log::new(SEGMENT_BYTES);
        let first = log
            .commit(&[Operation::create_table("t"), put("t", "k", vec![9; 100])])
            .unwrap();
        let second = log.commit(&[put("t", "l", vec![8; 100])]).unwrap();
        let first_value = first.values[1].unwrap().offset as usize;
        let second_value = second.values[0].unwrap().offset as usize;
        for at in [first_value, second_value, second_value - 40] {
            let group = log.group.crash();
            group.with_durable(GroupFile::segment(1), |bytes| bytes[at] ^= 0x10);
            assert_eq!(
                corrupt_reason(reopen(&group)),
                "record before a synchronized batch boundary is damaged",
                "{at}"
            );
        }
    }

    #[test]
    fn every_flipped_byte_of_a_sealed_segment_fails_closed() {
        let mut log = Log::new(SMALL);
        log.commit(&[Operation::create_table("t"), put("t", "a", vec![1; 200])])
            .unwrap();
        log.commit(&[
            put("t", "b", vec![2; 200]),
            Operation::delete("t", b"a".to_vec()),
        ])
        .unwrap();
        log.commit(&[put("t", "c", vec![3; 700])]).unwrap();
        assert!(log.root.last_segment_id() >= 2);
        let sealed = GroupFile::segment(1);
        let len = log.group.durable_len(sealed).unwrap();
        for at in 0..len {
            let group = log.group.crash();
            group.with_durable(sealed, |bytes| bytes[at] ^= 0x01);
            assert!(reopen(&group).is_err(), "byte {at} of a sealed segment");
        }
    }

    #[test]
    fn newest_segment_damage_is_torn_only_as_an_interrupted_final_commit() {
        let mut log = Log::new(SEGMENT_BYTES);
        log.commit(&[Operation::create_table("t"), put("t", "a", vec![1; 50])])
            .unwrap();
        let last = log.commit(&[put("t", "b", vec![2; 50])]).unwrap();
        let newest = GroupFile::segment(1);
        let final_commit = last.end.offset as usize - COMMIT_RECORD_BYTES;
        let written = log.group.durable_image(newest).unwrap();
        let mut accepted = 0;
        for at in 0..last.end.offset as usize {
            let group = log.group.crash();
            group.with_durable(newest, |bytes| bytes[at] ^= 0x01);
            let result = reopen(&group);
            if at < final_commit {
                assert!(result.is_err(), "byte {at} precedes the final commit");
            } else if written[at] == 0x01 {
                // Recorded limit: damage that leaves a zero byte cannot be
                // told apart from an interrupted commit write.
                let reopened = result.unwrap();
                assert_eq!(reopened.batches.len(), 1, "{at}");
                assert_eq!(reopened.end.torn_at, Some(final_commit as u64));
                accepted += 1;
            } else {
                // Any other byte, the magic and kind included, was written
                // whole; its bytes stay.
                assert_eq!(
                    corrupt_reason(result),
                    "written commit record is damaged",
                    "{at}"
                );
                assert_eq!(group.durable_len(newest), Some(written.len()));
            }
        }
        assert!(accepted < 8, "{accepted}");
    }

    #[test]
    fn damage_reaching_a_written_commit_is_never_a_torn_tail() {
        let mut log = Log::new(SEGMENT_BYTES);
        log.commit(&[Operation::create_table("t"), put("t", "a", vec![1; 50])])
            .unwrap();
        let last = log.commit(&[put("t", "b", vec![2; 50])]).unwrap();
        let newest = GroupFile::segment(1);
        let commit_at = last.end.offset as usize - COMMIT_RECORD_BYTES;
        let written_len = log.group.durable_len(newest);
        // One damaged sector across the end of the final operation record and
        // the head, header or whole of the acknowledged commit, and a commit
        // whose kind now reads as an operation's.
        let damaged: [(std::ops::Range<usize>, u8); 4] = [
            (commit_at - 8..commit_at + 8, 0x5a),
            (commit_at - 8..commit_at + COMMIT_RECORD_BYTES, 0x5a),
            (commit_at - 1..commit_at + RECORD_HEADER_BYTES, 0x5a),
            (commit_at + 4..commit_at + 5, 0x06),
        ];
        for (range, flip) in damaged {
            let group = log.group.crash();
            group.with_durable(newest, |bytes| {
                bytes[range.clone()]
                    .iter_mut()
                    .for_each(|byte| *byte ^= flip);
            });
            assert!(
                matches!(reopen(&group), Err(CoreError::Corrupt(_))),
                "{range:?}"
            );
            assert_eq!(group.durable_len(newest), written_len, "{range:?}");
        }

        // Pages of an interrupted append persisted out of order: a hole in
        // the first record's value with every later record present is a
        // torn tail, since the commit is written only after the records
        // are synchronized.
        let mut log = Log::new(SEGMENT_BYTES);
        let first = log.commit(&[Operation::create_table("t")]).unwrap();
        log.group.fail(GroupOp::Sync, 1, FaultTiming::BeforeEffect);
        log.commit(&[put("t", "a", vec![1; 5000]), put("t", "b", vec![2; 50])])
            .unwrap_err();
        let hole = first.end.offset as usize + 1000;
        let group = log.group.crash_torn(newest, 1 << 20);
        group.with_durable(newest, |bytes| bytes[hole..hole + 512].fill(0));
        let reopened = reopen(&group).unwrap();
        assert_eq!(reopened.batches.len(), 1);
        assert_eq!(reopened.end.torn_at, Some(first.end.offset));
        // The same hole with a trace of the commit write after the records
        // was damaged after that synchronization.
        for trace in [&RECORD_MAGIC[..], &[b'K', b'V', b'S', b'R', 4], &[9]] {
            let group = log.group.crash();
            group.with_durable(newest, |bytes| {
                bytes[hole..hole + 512].fill(0);
                bytes.extend_from_slice(trace);
            });
            let len = group.durable_len(newest);
            let result = reopen(&group);
            if trace == RECORD_MAGIC {
                // A torn record header's first bytes.
                assert_eq!(result.unwrap().end.torn_at, Some(first.end.offset));
            } else {
                assert!(matches!(result, Err(CoreError::Corrupt(_))), "{trace:?}");
                assert_eq!(group.durable_len(newest), len);
            }
        }
    }

    #[test]
    fn checksum_valid_field_changes_fail_closed() {
        let mut log = Log::new(SEGMENT_BYTES);
        log.commit(&[Operation::create_table("t")]).unwrap();
        let batch = log
            .commit(&[put("t", "k", vec![5; 64]), put("t", "m", vec![6; 8])])
            .unwrap();
        log.commit(&[put("t", "later", b"x".to_vec())]).unwrap();
        let record_at = |index: usize| {
            batch.values[index].unwrap().offset as usize
                - PUT_PREFIX_BYTES
                - 2
                - RECORD_HEADER_BYTES
        };
        let (put_at, second_at) = (record_at(0), record_at(1));
        let prefix = put_at + RECORD_HEADER_BYTES;
        let commit_at = batch.end.offset as usize - COMMIT_RECORD_BYTES;
        let body = commit_at + RECORD_HEADER_BYTES;
        let value_at = batch.values[0].unwrap().offset as usize;
        let cases: [(&str, usize, usize, u8); 14] = [
            ("commit operation count differs", commit_at, body, 3),
            ("commit operation digest differs", commit_at, body + 8, 0),
            ("commit chain differs", commit_at, body + 40, 0),
            ("batch commit record is invalid", commit_at, body + 4, 1),
            (
                "commit record has no matching batch",
                commit_at,
                commit_at + 8,
                9,
            ),
            (
                "segment record does not follow the newest commit",
                put_at,
                put_at + 16,
                0,
            ),
            (
                "segment interleaves two uncommitted batches",
                second_at,
                second_at + 8,
                3,
            ),
            ("segment record has an unknown kind", put_at, put_at + 4, 9),
            ("segment record header is invalid", put_at, put_at + 5, 1),
            // A batch never follows a commit of its own or later sequence.
            ("segment record header is invalid", put_at, put_at + 8, 1),
            ("segment value checksum differs", put_at, prefix + 8, 0),
            ("segment value checksum differs", put_at, value_at, 0),
            (
                "segment operation record is invalid",
                put_at,
                prefix + 12,
                1,
            ),
            ("segment table name is not UTF-8", put_at, prefix + 16, 0xff),
        ];
        for (reason, record_at, field, replacement) in cases {
            let group = log.group.crash();
            group.with_durable(GroupFile::segment(1), |bytes| {
                // Zero requests a bit flip; otherwise the byte is replaced.
                if replacement == 0 {
                    bytes[field] ^= 1;
                } else {
                    bytes[field] = replacement;
                }
                reseal_record(bytes, record_at);
            });
            assert_eq!(corrupt_reason(reopen(&group)), reason, "{field}");
        }
    }

    #[test]
    fn segment_header_substitution_and_legacy_images_fail_closed() {
        let mut log = Log::new(SEGMENT_BYTES);
        log.commit(&[Operation::create_table("t")]).unwrap();
        let segment = GroupFile::segment(1);
        let other = log.group.crash();
        other.with_durable(segment, |bytes| {
            bytes[..64].copy_from_slice(&segment_header(b"another-group-01", 1));
        });
        assert_eq!(
            corrupt_reason(reopen(&other)),
            "segment header names another group or segment"
        );
        let renamed = log.group.crash();
        renamed.with_durable(segment, |bytes| {
            bytes[..64].copy_from_slice(&segment_header(&GROUP, 2));
        });
        assert_eq!(
            corrupt_reason(reopen(&renamed)),
            "segment header names another group or segment"
        );
        let torn = log.group.crash();
        torn.with_durable(segment, |bytes| bytes[50] ^= 1);
        assert_eq!(
            corrupt_reason(reopen(&torn)),
            "confirmed segment header is damaged"
        );

        let mut legacy = [0u8; 64];
        legacy[..16].copy_from_slice(&LEGACY_MAGIC);
        legacy[16..20].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            corrupt_reason(decode_segment_header(&legacy, &GROUP, 1)),
            "unsupported KASUMI-KV-000001 single-file image"
        );
        let old = log.group.crash();
        old.with_durable(segment, |bytes| bytes[..64].copy_from_slice(&legacy));
        assert_eq!(
            corrupt_reason(reopen(&old)),
            "unsupported KASUMI-KV-000001 single-file image"
        );
    }

    #[test]
    fn interrupted_segment_creation_is_finished_under_its_intent() {
        for keep in [None, Some(0), Some(20)] {
            let mut log = Log::new(SMALL);
            log.commit(&[Operation::create_table("t")]).unwrap();
            match keep {
                // The intent is durable but the create never happened.
                None => log
                    .group
                    .fail(GroupOp::Create, 1, FaultTiming::BeforeEffect),
                // The file exists but its header sync did not complete.
                Some(_) => log.group.fail(GroupOp::Sync, 2, FaultTiming::BeforeEffect),
            }
            log.commit(&[put("t", "big", vec![1; 900])]).unwrap_err();
            let group = match keep {
                None => log.group.crash(),
                Some(keep) => log.group.crash_torn(GroupFile::segment(2), keep),
            };
            let reopened = reopen(&group).unwrap();
            assert_eq!(reopened.root.pending_segment(), Some(2));
            assert_eq!(reopened.end.pending_segment, Some(2));
            assert_eq!(group.exists(GroupFile::segment(2)).unwrap(), keep.is_some());
            // The put needed a new segment before its first record.
            assert_eq!(reopened.end.uncommitted_batch, None, "{keep:?}");
            assert_eq!(reopened.end.next_batch_seq, 2);

            let mut resumed = Log::resume(group, &reopened, SMALL);
            let batch = resumed.commit(&[put("t", "big", vec![1; 900])]).unwrap();
            // The outstanding identifier is finished, never skipped. The
            // commit record then needs one more segment.
            assert_eq!(batch.values[0].unwrap().segment_id, 2);
            assert_eq!(batch.end.segment_id, 3);
            assert_eq!(resumed.root.last_segment_id(), 3);
            let again = reopen(&resumed.group.crash()).unwrap();
            assert_eq!(again.batches.len(), 2);
            assert_eq!(value_at(&resumed.group, &again.batches[1], 0), vec![1; 900]);
        }
    }

    #[test]
    fn unconfirmed_segment_with_records_or_missing_segments_fail_closed() {
        let mut log = Log::new(SMALL);
        log.commit(&[Operation::create_table("t")]).unwrap();
        log.group
            .fail(GroupOp::Create, 1, FaultTiming::BeforeEffect);
        log.commit(&[put("t", "big", vec![1; 900])]).unwrap_err();
        let group = log.group.crash();
        let mut image = segment_header(&GROUP, 2).to_vec();
        image.extend_from_slice(&[0; 40]);
        group.insert_foreign(GroupFile::segment(2), image);
        assert_eq!(
            corrupt_reason(reopen(&group)),
            "unconfirmed segment holds records"
        );

        let mut log = Log::new(SMALL);
        log.commit(&[Operation::create_table("t")]).unwrap();
        log.commit(&[put("t", "a", vec![1; 900])]).unwrap();
        log.commit(&[put("t", "b", vec![1; 900])]).unwrap();
        let last = log.root.last_segment_id();
        assert!(last >= 3);
        for missing in [2, last] {
            let group = log.group.crash();
            group.remove_foreign(GroupFile::segment(missing));
            assert_eq!(
                corrupt_reason(reopen(&group)),
                "confirmed segment is missing"
            );
        }
    }

    #[test]
    fn replay_start_must_lie_inside_the_log() {
        let mut log = Log::new(SEGMENT_BYTES);
        let batch = log.commit(&[Operation::create_table("t")]).unwrap();
        let group = log.group.crash();
        for position in [
            LogPosition {
                segment_id: 2,
                offset: SEGMENT_HEADER_BYTES,
            },
            LogPosition {
                segment_id: 1,
                offset: 10,
            },
            LogPosition {
                segment_id: 1,
                offset: batch.end.offset + 1,
            },
        ] {
            let start = ReplayStart {
                position,
                batch_seq: 1,
                chain: batch.chain,
            };
            assert!(reopen_from(&group, &start).is_err(), "{position:?}");
        }
        let empty = InMemoryGroup::new();
        let start = ReplayStart {
            batch_seq: 1,
            ..ReplayStart::GENESIS
        };
        assert_eq!(
            corrupt_reason(reopen_from(&empty, &start)),
            "replay start names a missing segment"
        );
        // A start past a commit only replays what follows it.
        let start = ReplayStart {
            position: batch.end,
            batch_seq: 1,
            chain: batch.chain,
        };
        let reopened = reopen_from(&group, &start).unwrap();
        assert!(reopened.batches.is_empty());
        assert_eq!(reopened.end.batch_seq, 1);
    }

    #[test]
    fn outstanding_intent_seals_the_newest_segment_after_reopen() {
        let mut log = Log::new(SMALL);
        log.commit(&[Operation::create_table("t")]).unwrap();
        // Two records fit in segment 1; the third publishes intent 2 and then
        // its create fails, leaving abandoned records in a sealed segment.
        log.group
            .fail(GroupOp::Create, 1, FaultTiming::BeforeEffect);
        let spanning: Vec<_> = (0..3)
            .map(|index| put("t", &format!("k{index}"), vec![1; 300]))
            .collect();
        log.commit(&spanning).unwrap_err();
        let group = log.group.crash();
        let reopened = reopen(&group).unwrap();
        assert_eq!(reopened.end.pending_segment, Some(2));
        assert_eq!(reopened.end.uncommitted_batch, Some(2));
        // The root recorded the sealed length, so nothing is discarded.
        assert_eq!(reopened.end.resume.unwrap().offset, reopened.end.final_len);

        let mut resumed = Log::resume(group, &reopened, SMALL);
        let segment_one = resumed.group.len(GroupFile::segment(1)).unwrap();
        assert_eq!(segment_one, reopened.end.final_len);
        let small = resumed.commit(&[put("t", "small", b"v".to_vec())]).unwrap();
        // The small batch would fit in segment 1, but the intent sealed it.
        assert_eq!(small.values[0].unwrap().segment_id, 2);
        assert_eq!(
            resumed.group.len(GroupFile::segment(1)).unwrap(),
            segment_one
        );

        // An ordinary torn append in the new newest segment still recovers.
        resumed
            .group
            .fail(GroupOp::Sync, 1, FaultTiming::BeforeEffect);
        resumed
            .commit(&[put("t", "torn", vec![2; 100])])
            .unwrap_err();
        let group = resumed.group.crash_torn(GroupFile::segment(2), 20);
        let again = reopen(&group).unwrap();
        assert_eq!(again.batches.len(), 2);
        assert!(again.end.torn_at.is_some());
        assert_eq!(value_at(&group, &again.batches[1], 0), b"v");
    }

    #[test]
    fn damaged_commit_followed_by_the_next_batch_fails_closed() {
        // Batch 3's records were synchronized after acknowledged commit 2, so
        // damage inside commit 2 cannot be an interrupted append.
        let mut log = Log::new(SEGMENT_BYTES);
        log.commit(&[Operation::create_table("t")]).unwrap();
        let acked = log.commit(&[put("t", "acked", b"v".to_vec())]).unwrap();
        log.group.fail(GroupOp::Write, 3, FaultTiming::BeforeEffect);
        let error = log.commit(&[put("t", "next", vec![9; 50])]).unwrap_err();
        assert!(matches!(error, CoreError::UnknownCommit(_)), "{error:?}");
        let segment = GroupFile::segment(1);
        let commit_at = acked.end.offset as usize - COMMIT_RECORD_BYTES;
        for at in [
            commit_at + 2,
            commit_at + 20,
            commit_at + RECORD_HEADER_BYTES + 50,
        ] {
            let group = log.group.crash();
            group.with_durable(segment, |bytes| bytes[at] ^= 1);
            let len = group.durable_len(segment);
            assert!(matches!(reopen(&group), Err(CoreError::Corrupt(_))), "{at}");
            // The owner never reaches `discard_tail`, so batch 2 survives.
            assert_eq!(group.durable_len(segment), len);
        }

        // The same holds when commit 2 opens the newest segment and its
        // records lie in the sealed one before it.
        let mut log = Log::new(SMALL);
        log.commit(&[Operation::create_table("t")]).unwrap();
        let acked = log.commit(&[put("t", "a", vec![1; 480])]).unwrap();
        assert_eq!(acked.values[0].unwrap().segment_id, 1);
        assert_eq!(acked.end.segment_id, 2);
        log.group.fail(GroupOp::Write, 3, FaultTiming::BeforeEffect);
        log.commit(&[put("t", "b", vec![2; 50])]).unwrap_err();
        let newest = GroupFile::segment(2);
        let group = log.group.crash();
        group.with_durable(newest, |bytes| {
            bytes[acked.end.offset as usize - COMMIT_RECORD_BYTES + 9] ^= 1
        });
        let len = group.durable_len(newest);
        assert_eq!(
            corrupt_reason(reopen(&group)),
            "damaged record precedes a record of a later commit"
        );
        assert_eq!(group.durable_len(newest), len);
    }

    #[test]
    fn present_file_at_a_new_segment_identifier_fails_the_roll_untouched() {
        let mut log = Log::new(SMALL);
        log.commit(&[Operation::create_table("t")]).unwrap();
        let foreign = GroupFile::segment(2);
        let mut image = segment_header(b"another-group-01", 2).to_vec();
        image.extend_from_slice(&[0x77; 500]);
        log.group.insert_foreign(foreign, image.clone());
        let error = log.commit(&[put("t", "big", vec![1; 900])]).unwrap_err();
        assert!(
            matches!(&error, CoreError::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists),
            "{error:?}"
        );
        assert!(matches!(
            log.commit(&[Operation::create_table("u")]),
            Err(CoreError::OwnerFailed)
        ));
        assert_eq!(log.group.durable_image(foreign), Some(image.clone()));
        // The published intent names the file, so reopen fails closed too.
        let group = log.group.crash();
        assert_eq!(
            corrupt_reason(reopen(&group)),
            "unconfirmed segment holds records"
        );
        assert_eq!(group.durable_image(foreign), Some(image));

        // A replay-verified intent is checked again before its file is reused.
        let mut log = Log::new(SMALL);
        log.commit(&[Operation::create_table("t")]).unwrap();
        log.group.fail(GroupOp::Sync, 2, FaultTiming::BeforeEffect);
        log.commit(&[put("t", "big", vec![1; 900])]).unwrap_err();
        let group = log.group.crash_torn(foreign, 20);
        let reopened = reopen(&group).unwrap();
        assert_eq!(reopened.end.pending_segment, Some(2));
        let mut resumed = Log::resume(group, &reopened, SMALL);
        let substitute = segment_header(b"another-group-01", 2).to_vec();
        resumed.group.remove_foreign(foreign);
        resumed.group.insert_foreign(foreign, substitute.clone());
        assert_eq!(
            corrupt_reason(resumed.commit(&[put("t", "big", vec![1; 900])])),
            "segment header names another group or segment"
        );
        assert_eq!(resumed.group.durable_image(foreign), Some(substitute));
        let mut grown = segment_header(&GROUP, 2).to_vec();
        grown.push(0);
        let mut resumed = Log::resume(resumed.group.crash(), &reopened, SMALL);
        resumed.group.remove_foreign(foreign);
        resumed.group.insert_foreign(foreign, grown.clone());
        assert_eq!(
            corrupt_reason(resumed.commit(&[put("t", "big", vec![1; 900])])),
            "unconfirmed segment holds records"
        );
        assert_eq!(resumed.group.durable_image(foreign), Some(grown));
    }

    #[test]
    fn record_images_inside_a_value_never_count_as_records() {
        let mut log = Log::new(SEGMENT_BYTES);
        let first = log.commit(&[Operation::create_table("t")]).unwrap();
        let segment = GroupFile::segment(1);
        let mut copied = [0u8; COMMIT_RECORD_BYTES];
        log.group
            .read(
                segment,
                first.end.offset - COMMIT_RECORD_BYTES as u64,
                &mut copied,
            )
            .unwrap();
        // The put's value follows its header, prefix, table and key.
        let value_at = first.end.offset + (RECORD_HEADER_BYTES + PUT_PREFIX_BYTES + 2) as u64;
        let forged_at = LogPosition {
            segment_id: 1,
            offset: value_at + 4096,
        };
        let body = CommitBody {
            op_count: 1,
            ops_sha256: [0; 32],
            chain_sha256: [0; 32],
            directory: fixture_directory_root(2).encode().unwrap(),
        };
        let torn_with = |forged: [u8; COMMIT_RECORD_BYTES]| {
            let mut log = Log::new(SEGMENT_BYTES);
            log.commit(&[Operation::create_table("t")]).unwrap();
            let mut value = vec![0u8; 8192];
            // A commit image read back from a stored segment, and a forged one.
            value[1024..1024 + COMMIT_RECORD_BYTES].copy_from_slice(&copied);
            value[4096..4096 + COMMIT_RECORD_BYTES].copy_from_slice(&forged);
            log.group.fail(GroupOp::Sync, 1, FaultTiming::BeforeEffect);
            log.commit(&[put("t", "k", value)]).unwrap_err();
            // Pages persisted out of order: all of the append but its header,
            // which reads as zeros.
            let group = log.group.crash_torn(segment, 1 << 20);
            let header_at = first.end.offset as usize;
            group.with_durable(segment, |bytes| {
                bytes[header_at..header_at + RECORD_HEADER_BYTES].fill(0);
            });
            reopen(&group)
        };
        for group_id in [b"another-group-01", &GROUP] {
            let elsewhere = LogPosition {
                offset: forged_at.offset + 1,
                ..forged_at
            };
            let forged = commit_record(group_id, elsewhere, 9, 1, &body);
            let reopened = torn_with(forged).unwrap();
            assert_eq!(reopened.batches.len(), 1);
            assert_eq!(reopened.end.torn_at, Some(first.end.offset));
        }
        let other_group = commit_record(b"another-group-01", forged_at, 9, 1, &body);
        assert_eq!(
            torn_with(other_group).unwrap().end.torn_at,
            Some(first.end.offset)
        );
        // Recorded limit: an image forged with this group's identifier for
        // its exact offset is a record. It fails closed and never hides an
        // acknowledged batch.
        let exact = commit_record(&GROUP, forged_at, 9, 1, &body);
        assert_eq!(
            corrupt_reason(torn_with(exact)),
            "record before a synchronized batch boundary is damaged"
        );
    }

    #[test]
    fn sealed_segment_truncated_at_a_record_boundary_fails_closed() {
        for keep in [0, 40] {
            let mut log = Log::new(SMALL);
            log.commit(&[Operation::create_table("t")]).unwrap();
            let acked = log.commit(&[put("t", "a", vec![1; 190])]).unwrap();
            assert_eq!(acked.end.segment_id, 1);
            // The next batch rolls into segment 2 and is torn there.
            log.group.fail(GroupOp::Sync, 3, FaultTiming::BeforeEffect);
            log.commit(&[put("t", "b", vec![2; 800])]).unwrap_err();
            assert_eq!(log.root.last_segment_id(), 2);
            let group = log.group.crash_torn(GroupFile::segment(2), keep);
            assert_eq!(reopen(&group).unwrap().batches.len(), 2, "{keep}");
            // Media loses acknowledged commit 2 at a record boundary.
            group.with_durable(GroupFile::segment(1), |bytes| {
                bytes.truncate(acked.end.offset as usize - COMMIT_RECORD_BYTES);
            });
            assert_eq!(
                corrupt_reason(reopen(&group)),
                "sealed segment differs from its root record",
                "{keep}"
            );
        }

        // An older sealed segment: a later record names the lost commit.
        let mut log = Log::new(SMALL);
        log.commit(&[Operation::create_table("t")]).unwrap();
        let acked = log.commit(&[put("t", "a", vec![1; 190])]).unwrap();
        // Two headers, two operation flushes and root preparation precede commit.
        log.group.fail(GroupOp::Write, 6, FaultTiming::BeforeEffect);
        let error = log
            .commit(&[put("t", "b", vec![2; 700]), put("t", "c", vec![3; 500])])
            .unwrap_err();
        assert!(matches!(error, CoreError::UnknownCommit(_)), "{error:?}");
        assert_eq!(log.root.last_segment_id(), 3);
        let group = log.group.crash();
        group.with_durable(GroupFile::segment(1), |bytes| {
            bytes.truncate(acked.end.offset as usize - COMMIT_RECORD_BYTES);
        });
        assert_eq!(
            corrupt_reason(reopen(&group)),
            "segment record does not follow the newest commit"
        );
        // Appending bytes to a sealed segment also fails closed.
        let group = log.group.crash();
        group.with_durable(GroupFile::segment(1), |bytes| bytes.push(0));
        assert!(reopen(&group).is_err());
    }

    /// A roll whose create left the name but failed its parent sync, then a
    /// process restart without power loss (the same group, no `crash`).
    fn restarted_with_unsynchronized_intent() -> Log {
        let mut log = Log::new(SMALL);
        log.commit(&[Operation::create_table("t")]).unwrap();
        log.group.fail(GroupOp::Create, 1, FaultTiming::AfterEffect);
        let error = log.commit(&[put("t", "big", vec![1; 900])]).unwrap_err();
        assert!(matches!(error, CoreError::Io(_)), "{error:?}");
        let intent = GroupFile::segment(2);
        assert!(log.group.exists(intent).unwrap());
        assert!(!log.group.durable_exists(intent));
        let group = log.group.clone();
        let reopened = reopen(&group).unwrap();
        assert_eq!(reopened.end.pending_segment, Some(2));
        Log::resume(group, &reopened, SMALL)
    }

    #[test]
    fn take_over_makes_an_unsynchronized_name_durable_before_confirming() {
        let mut resumed = restarted_with_unsynchronized_intent();
        let acked = resumed.commit(&[put("t", "acked", vec![5; 900])]).unwrap();
        assert_eq!(acked.values[0].unwrap().segment_id, 2);
        assert_eq!(acked.end.segment_id, 3);
        // Power loss after the acknowledgement keeps the batch.
        let group = resumed.group.crash();
        let reopened = reopen(&group);
        assert!(
            reopened.is_ok(),
            "acknowledged batch lost: {:?}",
            reopened.as_ref().err()
        );
        let reopened = reopened.unwrap();
        assert_eq!(reopened.batches.len(), 2);
        assert_eq!(reopened.batches[1].batch_seq, acked.batch_seq);
        assert_eq!(value_at(&group, &reopened.batches[1], 0), vec![5; 900]);
        assert!(resumed.group.durable_exists(GroupFile::segment(2)));
    }

    #[test]
    fn failed_name_sync_fences_the_take_over_before_confirming() {
        for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
            let mut resumed = restarted_with_unsynchronized_intent();
            let intent = GroupFile::segment(2);
            resumed.group.fail(GroupOp::SyncNames, 1, timing);
            let error = resumed.commit(&[put("t", "k", vec![5; 900])]).unwrap_err();
            assert!(matches!(error, CoreError::Io(_)), "{timing:?} {error:?}");
            assert!(matches!(
                resumed.commit(&[put("t", "k", vec![5; 900])]),
                Err(CoreError::OwnerFailed)
            ));
            // Nothing was written to the file and the root still holds only
            // the intent.
            assert_eq!(resumed.group.len(intent).unwrap(), 0);
            assert_eq!(resumed.root.pending_segment(), Some(2));
            assert_eq!(
                selected_root(&resumed.group).unwrap().pending_segment(),
                Some(2)
            );

            let group = resumed.group.crash();
            assert_eq!(
                group.exists(intent).unwrap(),
                timing == FaultTiming::AfterEffect
            );
            let reopened = reopen(&group).unwrap();
            assert_eq!(reopened.end.pending_segment, Some(2));
            let mut again = Log::resume(group, &reopened, SMALL);
            let acked = again.commit(&[put("t", "k", vec![6; 900])]).unwrap();
            assert_eq!(acked.values[0].unwrap().segment_id, 2);
            let group = again.group.crash();
            let reopened = reopen(&group).unwrap();
            assert_eq!(reopened.batches.len(), 2, "{timing:?}");
            assert_eq!(value_at(&group, &reopened.batches[1], 0), vec![6; 900]);
        }
    }

    #[test]
    fn intent_file_must_be_a_prefix_of_its_own_header() {
        let intent = GroupFile::segment(2);
        let header = segment_header(&GROUP, 2);
        let mut zero_prefixed = vec![0u8; 40];
        zero_prefixed[39] = 0x5a;
        let foreign = [
            b"operator notes, not a segment".to_vec(),
            segment_header(b"another-group-01", 2)[..40].to_vec(),
            segment_header(&GROUP, 3)[..48].to_vec(),
            zero_prefixed,
        ];
        let reason = "unconfirmed segment holds bytes other than its header";
        for image in foreign {
            // A fresh roll refuses the present name and fences the writer.
            let mut log = Log::new(SMALL);
            log.commit(&[Operation::create_table("t")]).unwrap();
            log.group.insert_foreign(intent, image.clone());
            let error = log.commit(&[put("t", "big", vec![1; 900])]).unwrap_err();
            assert!(
                matches!(&error, CoreError::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists),
                "{error:?}"
            );
            // Reopen under the published intent fails closed.
            let group = log.group.crash();
            assert_eq!(corrupt_reason(reopen(&group)), reason, "{image:?}");
            assert_eq!(group.durable_image(intent), Some(image.clone()));

            // The take-over checks again after reopen accepted a torn header.
            let mut log = Log::new(SMALL);
            log.commit(&[Operation::create_table("t")]).unwrap();
            log.group.fail(GroupOp::Sync, 2, FaultTiming::BeforeEffect);
            log.commit(&[put("t", "big", vec![1; 900])]).unwrap_err();
            let group = log.group.crash_torn(intent, 20);
            let reopened = reopen(&group).unwrap();
            let mut resumed = Log::resume(group, &reopened, SMALL);
            resumed.group.remove_foreign(intent);
            resumed.group.insert_foreign(intent, image.clone());
            assert_eq!(
                corrupt_reason(resumed.commit(&[put("t", "big", vec![1; 900])])),
                reason,
                "{image:?}"
            );
            assert_eq!(resumed.group.durable_image(intent), Some(image));
            assert_eq!(resumed.root.pending_segment(), Some(2));
        }

        // Every image an interrupted header write leaves is finished.
        let mut sparse = header;
        sparse[..16].fill(0);
        for image in [Vec::new(), vec![0; 64], sparse.to_vec(), header.to_vec()] {
            let mut log = Log::new(SMALL);
            log.commit(&[Operation::create_table("t")]).unwrap();
            log.group
                .fail(GroupOp::Create, 1, FaultTiming::BeforeEffect);
            log.commit(&[put("t", "big", vec![1; 900])]).unwrap_err();
            let group = log.group.crash();
            group.insert_foreign(intent, image.clone());
            let reopened = reopen(&group).unwrap();
            let mut resumed = Log::resume(group, &reopened, SMALL);
            let batch = resumed.commit(&[put("t", "big", vec![1; 900])]).unwrap();
            assert_eq!(batch.values[0].unwrap().segment_id, 2, "{image:?}");
            assert_eq!(reopen(&resumed.group.crash()).unwrap().batches.len(), 2);
        }
    }
}

// Transaction-space planning is qualified separately before production activation.
#[path = "segment_space.rs"]
mod space;
