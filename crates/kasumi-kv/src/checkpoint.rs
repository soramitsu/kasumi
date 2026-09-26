//! Index checkpoints of the segmented log.
//!
//! A checkpoint is a create-only file holding the resident index at one
//! commit boundary: a header with the replay start, tables in strictly
//! increasing name order each followed by its rows in strictly increasing key
//! order, an end entry with counts and live value bytes, the live bytes of
//! every referenced segment, and a trailing SHA-256 of all preceding bytes.
//! The root references a checkpoint by identifier, length, replay-start
//! segment and that digest; reopen fails closed on any difference instead of
//! falling back to replay.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::core::{CoreError, MAX_KEY_BYTES, MAX_TABLE_BYTES};
use crate::group::{GroupFile, SegmentGroupBackend};
use crate::root::{FileRole, Superblock};
use crate::segment::{
    FORMAT_VERSION, FileReader, HeaderState, LogPosition, ReplayStart, SEGMENT_HEADER_BYTES,
    ValueLocation, le_u16, le_u32, le_u64, read_segment_header, reject_legacy,
};

pub(crate) const CHECKPOINT_MAGIC: [u8; 16] = *b"KASUMI-KVCKPT001";
const HEADER_BYTES: usize = 128;
const TABLE_ENTRY_BYTES: usize = 16;
const ROW_ENTRY_BYTES: usize = 40;
const END_ENTRY_BYTES: usize = 40;
const SUMMARY_ENTRY_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const TAG_TABLE: u8 = 1;
const TAG_ROW: u8 = 2;
const TAG_END: u8 = 3;
const WRITE_WINDOW: usize = 64 << 10;

/// The root's binding to one checkpoint file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CheckpointRef {
    pub(crate) id: u64,
    pub(crate) len: u64,
    /// The segment replay starts in; the root retires only segments before it.
    pub(crate) start_segment_id: u64,
    pub(crate) sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CheckpointHeader {
    pub(crate) group_id: [u8; 16],
    pub(crate) checkpoint_id: u64,
    /// The commit boundary the checkpoint covers, where replay resumes.
    pub(crate) start: ReplayStart,
}

impl CheckpointHeader {
    fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut bytes = [0u8; HEADER_BYTES];
        bytes[..16].copy_from_slice(&CHECKPOINT_MAGIC);
        bytes[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[24..40].copy_from_slice(&self.group_id);
        bytes[40..48].copy_from_slice(&self.checkpoint_id.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.start.batch_seq.to_le_bytes());
        bytes[56..88].copy_from_slice(&self.start.chain);
        bytes[88..96].copy_from_slice(&self.start.position.segment_id.to_le_bytes());
        bytes[96..104].copy_from_slice(&self.start.position.offset.to_le_bytes());
        bytes
    }

    fn invalid(&self) -> bool {
        self.checkpoint_id == 0
            || self.start.batch_seq == 0
            || self.start.position.segment_id == 0
            || self.start.position.offset < SEGMENT_HEADER_BYTES
    }
}

/// Totals recomputed from the entries, which the end entry must match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CheckpointSummary {
    /// The root reference the checkpoint was written or verified under. Its
    /// digest covers every entry, so only this checkpoint's own summary
    /// matches the reference the root installed.
    pub(crate) reference: CheckpointRef,
    pub(crate) header: CheckpointHeader,
    pub(crate) tables: u64,
    pub(crate) rows: u64,
    pub(crate) live_bytes: u64,
    /// Live value bytes per referenced segment, in segment order.
    pub(crate) segment_live_bytes: Vec<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CheckpointItem<'a> {
    Table {
        name: &'a str,
        birth_seq: u64,
    },
    Row {
        key: &'a [u8],
        batch_seq: u64,
        value: ValueLocation,
    },
}

/// Ordering and bound checks shared by the writer and the reader.
struct EntryOrder {
    header: CheckpointHeader,
    table: Option<(Vec<u8>, u64)>,
    key: Option<Vec<u8>>,
    tables: u64,
    rows: u64,
    live_bytes: u64,
    segments: BTreeMap<u64, u64>,
}

impl EntryOrder {
    fn new(header: CheckpointHeader) -> Self {
        Self {
            header,
            table: None,
            key: None,
            tables: 0,
            rows: 0,
            live_bytes: 0,
            segments: BTreeMap::new(),
        }
    }

    fn table(&mut self, name: &[u8], birth_seq: u64) -> Result<(), &'static str> {
        if name.is_empty() || name.len() > MAX_TABLE_BYTES || std::str::from_utf8(name).is_err() {
            return Err("checkpoint table name is invalid");
        }
        if self
            .table
            .as_ref()
            .is_some_and(|(previous, _)| previous.as_slice() >= name)
        {
            return Err("checkpoint tables are not strictly ordered");
        }
        if birth_seq == 0 || birth_seq > self.header.start.batch_seq {
            return Err("checkpoint table birth is outside the checkpoint");
        }
        self.table = Some((name.to_vec(), birth_seq));
        self.key = None;
        self.tables += 1;
        Ok(())
    }

    fn row(
        &mut self,
        key: &[u8],
        batch_seq: u64,
        value: &ValueLocation,
    ) -> Result<(), &'static str> {
        let Some((_, birth_seq)) = self.table.as_ref() else {
            return Err("checkpoint row precedes its table");
        };
        if key.len() > MAX_KEY_BYTES {
            return Err("checkpoint key exceeds storage limit");
        }
        if self.key.as_deref().is_some_and(|previous| previous >= key) {
            return Err("checkpoint keys are not strictly ordered");
        }
        if batch_seq < *birth_seq || batch_seq > self.header.start.batch_seq {
            return Err("checkpoint row version is outside the checkpoint");
        }
        let start = self.header.start.position;
        if value.validate().is_err()
            || value.segment_id > start.segment_id
            || (value.segment_id == start.segment_id && value.end() > start.offset)
        {
            return Err("checkpoint value is outside the covered log");
        }
        // Both totals are checked before either changes, so a refused row
        // leaves no trace.
        let overflow = "checkpoint live bytes overflow";
        let segment_bytes = self
            .segments
            .get(&value.segment_id)
            .map_or(0, |&bytes| bytes)
            .checked_add(u64::from(value.len))
            .ok_or(overflow)?;
        self.live_bytes = self
            .live_bytes
            .checked_add(u64::from(value.len))
            .ok_or(overflow)?;
        self.segments.insert(value.segment_id, segment_bytes);
        self.key = Some(key.to_vec());
        self.rows += 1;
        Ok(())
    }

    fn summary(self, reference: CheckpointRef) -> CheckpointSummary {
        CheckpointSummary {
            reference,
            header: self.header,
            tables: self.tables,
            rows: self.rows,
            live_bytes: self.live_bytes,
            segment_live_bytes: self.segments.into_iter().collect(),
        }
    }
}

/// Streams one checkpoint into a newly created file. The caller reserved
/// `header.checkpoint_id` in a durable root first; an unfinished file stays an
/// unreferenced orphan. A refused entry has no effect, but after a backend
/// failure the counts and digest no longer describe the file, so every later
/// call fails and the file can only stay an orphan.
pub(crate) struct CheckpointWriter<'a> {
    backend: &'a dyn SegmentGroupBackend,
    file: GroupFile,
    at: u64,
    buffer: Vec<u8>,
    digest: Sha256,
    order: EntryOrder,
    failed: bool,
}

impl<'a> CheckpointWriter<'a> {
    pub(crate) fn create(
        backend: &'a dyn SegmentGroupBackend,
        header: CheckpointHeader,
    ) -> Result<Self, CoreError> {
        if header.invalid() {
            return Err(CoreError::InvalidInput("checkpoint header is invalid"));
        }
        let file = GroupFile::checkpoint(header.checkpoint_id);
        backend.create(file)?;
        let mut writer = Self {
            backend,
            file,
            at: 0,
            buffer: Vec::with_capacity(WRITE_WINDOW),
            digest: Sha256::new(),
            order: EntryOrder::new(header),
            failed: false,
        };
        writer.emit(&header.encode())?;
        Ok(writer)
    }

    fn check_usable(&self) -> Result<(), CoreError> {
        if self.failed {
            return Err(CoreError::OwnerFailed);
        }
        Ok(())
    }

    pub(crate) fn table(&mut self, name: &str, birth_seq: u64) -> Result<(), CoreError> {
        self.check_usable()?;
        self.order
            .table(name.as_bytes(), birth_seq)
            .map_err(CoreError::InvalidInput)?;
        let mut entry = [0u8; TABLE_ENTRY_BYTES];
        entry[0] = TAG_TABLE;
        entry[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
        entry[8..16].copy_from_slice(&birth_seq.to_le_bytes());
        self.emit(&entry)?;
        self.emit(name.as_bytes())
    }

    pub(crate) fn row(
        &mut self,
        key: &[u8],
        batch_seq: u64,
        value: &ValueLocation,
    ) -> Result<(), CoreError> {
        self.check_usable()?;
        self.order
            .row(key, batch_seq, value)
            .map_err(CoreError::InvalidInput)?;
        let mut entry = [0u8; ROW_ENTRY_BYTES];
        entry[0] = TAG_ROW;
        entry[2..4].copy_from_slice(&(key.len() as u16).to_le_bytes());
        entry[4..8].copy_from_slice(&value.len.to_le_bytes());
        entry[8..16].copy_from_slice(&batch_seq.to_le_bytes());
        entry[16..24].copy_from_slice(&value.segment_id.to_le_bytes());
        entry[24..32].copy_from_slice(&value.offset.to_le_bytes());
        entry[32..36].copy_from_slice(&value.crc.to_le_bytes());
        self.emit(&entry)?;
        self.emit(key)
    }

    /// Write the end entry, segment summary and digest, then synchronize.
    pub(crate) fn finish(mut self) -> Result<(CheckpointRef, CheckpointSummary), CoreError> {
        self.check_usable()?;
        let mut end = [0u8; END_ENTRY_BYTES];
        end[0] = TAG_END;
        end[8..16].copy_from_slice(&self.order.tables.to_le_bytes());
        end[16..24].copy_from_slice(&self.order.rows.to_le_bytes());
        end[24..32].copy_from_slice(&self.order.live_bytes.to_le_bytes());
        end[32..40].copy_from_slice(&(self.order.segments.len() as u64).to_le_bytes());
        self.emit(&end)?;
        let segments: Vec<(u64, u64)> = self
            .order
            .segments
            .iter()
            .map(|(&segment_id, &bytes)| (segment_id, bytes))
            .collect();
        for (segment_id, bytes) in segments {
            let mut entry = [0u8; SUMMARY_ENTRY_BYTES];
            entry[..8].copy_from_slice(&segment_id.to_le_bytes());
            entry[8..].copy_from_slice(&bytes.to_le_bytes());
            self.emit(&entry)?;
        }
        let sha256: [u8; 32] = self.digest.finalize_reset().into();
        self.buffer.extend_from_slice(&sha256);
        self.flush()?;
        self.backend.sync(self.file)?;
        let reference = CheckpointRef {
            id: self.order.header.checkpoint_id,
            len: self.at,
            start_segment_id: self.order.header.start.position.segment_id,
            sha256,
        };
        Ok((reference, self.order.summary(reference)))
    }

    fn emit(&mut self, bytes: &[u8]) -> Result<(), CoreError> {
        if self.buffer.len() + bytes.len() > WRITE_WINDOW {
            self.flush()?;
        }
        self.digest.update(bytes);
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), CoreError> {
        if !self.buffer.is_empty() {
            if let Err(error) = self.backend.write(self.file, self.at, &self.buffer) {
                self.failed = true;
                return Err(error.into());
            }
            self.at += self.buffer.len() as u64;
            self.buffer.clear();
        }
        Ok(())
    }
}

/// Hashes every consumed byte.
struct DigestReader<'a> {
    reader: FileReader<'a>,
    digest: Sha256,
}

impl DigestReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> Result<(), CoreError> {
        if (out.len() as u64) > self.reader.remaining() {
            return Err(CoreError::Corrupt("checkpoint entry is truncated"));
        }
        self.reader.read_exact(out)?;
        self.digest.update(&*out);
        Ok(())
    }
}

/// Stream and verify the checkpoint the root references. `visit` sees each
/// entry before the trailing digest is checked, so on any error the caller
/// discards everything it built from this checkpoint.
pub(crate) fn read_checkpoint(
    backend: &dyn SegmentGroupBackend,
    group_id: &[u8; 16],
    reference: &CheckpointRef,
    mut visit: impl FnMut(CheckpointItem<'_>) -> Result<(), CoreError>,
) -> Result<CheckpointSummary, CoreError> {
    let file = GroupFile::checkpoint(reference.id);
    let len = backend.len(file)?;
    if len != reference.len {
        return Err(CoreError::Corrupt(
            "checkpoint length differs from its root",
        ));
    }
    let minimum = (HEADER_BYTES + END_ENTRY_BYTES + DIGEST_BYTES) as u64;
    if len < minimum {
        let mut prefix = vec![0u8; len.min(16) as usize];
        backend.read(file, 0, &mut prefix)?;
        reject_legacy(&prefix)?;
        return Err(CoreError::Corrupt("checkpoint is truncated"));
    }
    let body_len = len - DIGEST_BYTES as u64;
    let mut input = DigestReader {
        reader: FileReader::new(backend, file, body_len, 0),
        digest: Sha256::new(),
    };
    let mut bytes = [0u8; HEADER_BYTES];
    input.read(&mut bytes)?;
    reject_legacy(&bytes)?;
    if bytes[..16] != CHECKPOINT_MAGIC
        || le_u32(&bytes[16..20]) != FORMAT_VERSION
        || bytes[20..24].iter().any(|&byte| byte != 0)
        || bytes[104..].iter().any(|&byte| byte != 0)
    {
        return Err(CoreError::Corrupt("checkpoint header is invalid"));
    }
    let header = CheckpointHeader {
        group_id: bytes[24..40].try_into().expect("16 bytes"),
        checkpoint_id: le_u64(&bytes[40..48]),
        start: ReplayStart {
            batch_seq: le_u64(&bytes[48..56]),
            chain: bytes[56..88].try_into().expect("32 bytes"),
            position: LogPosition {
                segment_id: le_u64(&bytes[88..96]),
                offset: le_u64(&bytes[96..104]),
            },
        },
    };
    if header.invalid() || header.group_id != *group_id || header.checkpoint_id != reference.id {
        return Err(CoreError::Corrupt(
            "checkpoint header names another checkpoint",
        ));
    }
    if header.start.position.segment_id != reference.start_segment_id {
        return Err(CoreError::Corrupt(
            "checkpoint replay start differs from its root",
        ));
    }
    let mut order = EntryOrder::new(header);
    let mut scratch = Vec::new();
    loop {
        let mut tag = [0u8; 8];
        input.read(&mut tag)?;
        match tag[0] {
            TAG_TABLE => {
                let mut rest = [0u8; TABLE_ENTRY_BYTES - 8];
                input.read(&mut rest)?;
                let name_len = usize::from(le_u16(&tag[2..4]));
                if tag[1] != 0
                    || tag[4..8].iter().any(|&byte| byte != 0)
                    || name_len > MAX_TABLE_BYTES
                {
                    return Err(CoreError::Corrupt("checkpoint table entry is invalid"));
                }
                let birth_seq = le_u64(&rest);
                scratch.resize(name_len, 0);
                input.read(&mut scratch)?;
                order
                    .table(&scratch, birth_seq)
                    .map_err(CoreError::Corrupt)?;
                let text = std::str::from_utf8(&scratch).expect("order checked UTF-8");
                visit(CheckpointItem::Table {
                    name: text,
                    birth_seq,
                })?;
            }
            TAG_ROW => {
                let mut rest = [0u8; ROW_ENTRY_BYTES - 8];
                input.read(&mut rest)?;
                let key_len = usize::from(le_u16(&tag[2..4]));
                if tag[1] != 0
                    || rest[28..32].iter().any(|&byte| byte != 0)
                    || key_len > MAX_KEY_BYTES
                {
                    return Err(CoreError::Corrupt("checkpoint row entry is invalid"));
                }
                let batch_seq = le_u64(&rest[..8]);
                let value = ValueLocation {
                    segment_id: le_u64(&rest[8..16]),
                    offset: le_u64(&rest[16..24]),
                    len: le_u32(&tag[4..8]),
                    crc: le_u32(&rest[24..28]),
                };
                scratch.resize(key_len, 0);
                input.read(&mut scratch)?;
                order
                    .row(&scratch, batch_seq, &value)
                    .map_err(CoreError::Corrupt)?;
                visit(CheckpointItem::Row {
                    key: &scratch,
                    batch_seq,
                    value,
                })?;
            }
            TAG_END if tag[1..].iter().all(|&byte| byte == 0) => break,
            _ => return Err(CoreError::Corrupt("checkpoint entry has an unknown kind")),
        }
    }
    let mut end = [0u8; END_ENTRY_BYTES - 8];
    input.read(&mut end)?;
    let segment_count = le_u64(&end[24..32]);
    if input.reader.remaining() != segment_count.saturating_mul(SUMMARY_ENTRY_BYTES as u64)
        || le_u64(&end[..8]) != order.tables
        || le_u64(&end[8..16]) != order.rows
        || le_u64(&end[16..24]) != order.live_bytes
        || segment_count != order.segments.len() as u64
    {
        return Err(CoreError::Corrupt(
            "checkpoint totals differ from its entries",
        ));
    }
    for (&segment_id, &bytes) in &order.segments {
        let mut entry = [0u8; SUMMARY_ENTRY_BYTES];
        input.read(&mut entry)?;
        if le_u64(&entry[..8]) != segment_id || le_u64(&entry[8..]) != bytes {
            return Err(CoreError::Corrupt("checkpoint segment summary differs"));
        }
    }
    let computed: [u8; 32] = input.digest.finalize().into();
    let mut stored = [0u8; DIGEST_BYTES];
    backend.read(file, body_len, &mut stored)?;
    if computed != stored || stored != reference.sha256 {
        return Err(CoreError::Corrupt("checkpoint digest differs"));
    }
    Ok(order.summary(*reference))
}

/// Every segment a loaded checkpoint references, and its replay start, must be
/// a live confirmed segment of the selected root with an intact header.
pub(crate) fn verify_referenced_segments(
    backend: &dyn SegmentGroupBackend,
    root: &Superblock,
    summary: &CheckpointSummary,
) -> Result<(), CoreError> {
    let start = summary.header.start.position.segment_id;
    let referenced = summary
        .segment_live_bytes
        .iter()
        .map(|&(segment_id, _)| segment_id)
        .chain([start]);
    for segment_id in referenced {
        let file = GroupFile::segment(segment_id);
        if segment_id > root.last_segment_id()
            || root.classify(file) != FileRole::Live
            || !backend.exists(file)?
        {
            return Err(CoreError::Corrupt(
                "checkpoint references a retired or missing segment",
            ));
        }
        if read_segment_header(backend, root.group_id(), segment_id)? != HeaderState::Valid {
            return Err(CoreError::Corrupt(
                "checkpoint references a damaged segment",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Operation;
    use crate::group::{FaultTiming, GroupOp, InMemoryGroup};
    use crate::root::{publish_forget, publish_root};
    use crate::segment::test_support::{
        GROUP, Log, corrupt_reason, put, reopen_from, selected_root,
    };
    use crate::segment::{CommittedBatch, LEGACY_MAGIC, SEGMENT_BYTES, read_value};

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Item {
        Table(String, u64),
        Row(Vec<u8>, u64, ValueLocation),
    }

    struct Sample {
        log: Log,
        header: CheckpointHeader,
        items: Vec<Item>,
    }

    /// Two tables and three rows, checkpointed at the writer's position.
    fn sample() -> Sample {
        let mut log = Log::new(SEGMENT_BYTES);
        log.commit(&[Operation::create_table("a"), Operation::create_table("b")])
            .unwrap();
        let rows = log
            .commit(&[
                put("a", "k1", b"one".to_vec()),
                put("a", "k2", b"two".to_vec()),
                put("b", "k1", b"three".to_vec()),
            ])
            .unwrap();
        let (next, checkpoint_id) = log.root.reserve_checkpoint().unwrap();
        publish_root(&log.group, &log.root, &next).unwrap();
        log.root = next;
        let header = CheckpointHeader {
            group_id: GROUP,
            checkpoint_id,
            start: ReplayStart {
                position: log.writer.position().unwrap(),
                batch_seq: log.writer.last_batch_seq(),
                chain: log.writer.chain(),
            },
        };
        let value = |index: usize| rows.values[index].unwrap();
        let items = vec![
            Item::Table("a".to_owned(), 1),
            Item::Row(b"k1".to_vec(), 2, value(0)),
            Item::Row(b"k2".to_vec(), 2, value(1)),
            Item::Table("b".to_owned(), 1),
            Item::Row(b"k1".to_vec(), 2, value(2)),
        ];
        Sample { log, header, items }
    }

    fn write(
        group: &InMemoryGroup,
        header: CheckpointHeader,
        items: &[Item],
    ) -> (CheckpointRef, CheckpointSummary) {
        let mut writer = CheckpointWriter::create(group, header).unwrap();
        for item in items {
            match item {
                Item::Table(name, birth) => writer.table(name, *birth).unwrap(),
                Item::Row(key, seq, value) => writer.row(key, *seq, value).unwrap(),
            }
        }
        writer.finish().unwrap()
    }

    /// Reserve a checkpoint in a published root and write `items`, covering
    /// the log through `batch`.
    fn checkpoint_through(
        log: &mut Log,
        batch: &CommittedBatch,
        items: &[Item],
    ) -> (CheckpointRef, CheckpointSummary) {
        let (next, checkpoint_id) = log.root.reserve_checkpoint().unwrap();
        publish_root(&log.group, &log.root, &next).unwrap();
        log.root = next;
        let header = CheckpointHeader {
            group_id: GROUP,
            checkpoint_id,
            start: ReplayStart {
                position: batch.end,
                batch_seq: batch.batch_seq,
                chain: batch.chain,
            },
        };
        write(&log.group, header, items)
    }

    fn read(
        group: &InMemoryGroup,
        reference: &CheckpointRef,
    ) -> Result<(CheckpointSummary, Vec<Item>), CoreError> {
        let mut items = Vec::new();
        let summary = read_checkpoint(group, &GROUP, reference, |item| {
            items.push(match item {
                CheckpointItem::Table { name, birth_seq } => {
                    Item::Table(name.to_owned(), birth_seq)
                }
                CheckpointItem::Row {
                    key,
                    batch_seq,
                    value,
                } => Item::Row(key.to_vec(), batch_seq, value),
            });
            Ok(())
        })?;
        Ok((summary, items))
    }

    /// Replace the trailing digest after a deliberate edit.
    fn redigest(bytes: &mut [u8]) -> [u8; 32] {
        let body = bytes.len() - DIGEST_BYTES;
        let sha256: [u8; 32] = Sha256::digest(&bytes[..body]).into();
        bytes[body..].copy_from_slice(&sha256);
        sha256
    }

    #[test]
    fn checkpoint_round_trips_sorted_entries_and_live_bytes() {
        let sample = sample();
        let group = &sample.log.group;
        let (reference, written) = write(group, sample.header, &sample.items);
        assert_eq!(
            reference.len,
            group.durable_len(GroupFile::checkpoint(1)).unwrap() as u64
        );
        let (summary, items) = read(&group.crash(), &reference).unwrap();
        assert_eq!(items, sample.items);
        assert_eq!(summary, written);
        // Both summaries carry the reference the root installs, which binds
        // them for segment retirement.
        assert_eq!(written.reference, reference);
        assert_eq!(
            (summary.tables, summary.rows, summary.live_bytes),
            (2, 3, 11)
        );
        assert_eq!(summary.segment_live_bytes, [(1, 11)]);
        assert_eq!(summary.header, sample.header);
        let Item::Row(_, _, location) = &items[4] else {
            panic!("row expected");
        };
        assert_eq!(read_value(group, location).unwrap(), b"three");
    }

    #[test]
    fn every_flipped_byte_fails_closed() {
        let sample = sample();
        let group = &sample.log.group;
        let (reference, _) = write(group, sample.header, &sample.items);
        let file = GroupFile::checkpoint(reference.id);
        for at in 0..reference.len as usize {
            let damaged = group.crash();
            damaged.with_durable(file, |bytes| bytes[at] ^= 0x04);
            assert!(read(&damaged, &reference).is_err(), "byte {at}");
        }
    }

    #[test]
    fn root_reference_binds_length_and_digest() {
        let sample = sample();
        let group = &sample.log.group;
        let (reference, _) = write(group, sample.header, &sample.items);
        let mut wrong_digest = reference;
        wrong_digest.sha256[0] ^= 1;
        assert_eq!(
            corrupt_reason(read(group, &wrong_digest)),
            "checkpoint digest differs"
        );
        let mut wrong_len = reference;
        wrong_len.len += 1;
        assert_eq!(
            corrupt_reason(read(group, &wrong_len)),
            "checkpoint length differs from its root"
        );
        let mut wrong_start = reference;
        wrong_start.start_segment_id += 1;
        assert_eq!(
            corrupt_reason(read(group, &wrong_start)),
            "checkpoint replay start differs from its root"
        );
        // A truncated file that still matches a stale length claim.
        let truncated = group.crash();
        truncated.with_durable(GroupFile::checkpoint(reference.id), |bytes| {
            bytes.truncate(100);
        });
        let short = CheckpointRef {
            len: 100,
            ..reference
        };
        assert_eq!(
            corrupt_reason(read(&truncated, &short)),
            "checkpoint is truncated"
        );
    }

    #[test]
    fn digest_valid_edits_fail_closed_on_structure() {
        let sample = sample();
        let group = &sample.log.group;
        let (reference, _) = write(group, sample.header, &sample.items);
        let len = reference.len as usize;
        let end_at = len - DIGEST_BYTES - SUMMARY_ENTRY_BYTES - END_ENTRY_BYTES;
        let first_table = HEADER_BYTES;
        let first_row = first_table + TABLE_ENTRY_BYTES + 1;
        let cases: [(&str, usize, u8); 10] = [
            ("checkpoint header is invalid", 16, 9),
            ("checkpoint header names another checkpoint", 24, b'x'),
            ("checkpoint header names another checkpoint", 40, 9),
            ("checkpoint entry has an unknown kind", first_table, 9),
            (
                "checkpoint table birth is outside the checkpoint",
                first_table + 8,
                9,
            ),
            (
                "checkpoint row version is outside the checkpoint",
                first_row + 8,
                9,
            ),
            (
                "checkpoint value is outside the covered log",
                first_row + 16,
                2,
            ),
            ("checkpoint totals differ from its entries", end_at + 8, 9),
            ("checkpoint totals differ from its entries", end_at + 24, 9),
            (
                "checkpoint segment summary differs",
                end_at + END_ENTRY_BYTES + 8,
                9,
            ),
        ];
        for (reason, at, value) in cases {
            let damaged = group.crash();
            let mut sha256 = [0; 32];
            damaged.with_durable(GroupFile::checkpoint(reference.id), |bytes| {
                bytes[at] = value;
                sha256 = redigest(bytes);
            });
            let edited = CheckpointRef {
                sha256,
                ..reference
            };
            assert_eq!(corrupt_reason(read(&damaged, &edited)), reason, "{at}");
        }
    }

    #[test]
    fn writer_rejects_unsorted_or_uncovered_entries() {
        let sample = sample();
        let group = &sample.log.group;
        let mut writer = CheckpointWriter::create(group, sample.header).unwrap();
        let Item::Row(_, _, value) = sample.items[1].clone() else {
            panic!("row expected");
        };
        let invalid = |result: Result<(), CoreError>| {
            assert!(
                matches!(result, Err(CoreError::InvalidInput(_))),
                "{result:?}"
            );
        };
        invalid(writer.row(b"k", 2, &value));
        writer.table("m", 1).unwrap();
        invalid(writer.table("m", 1));
        invalid(writer.table("a", 1));
        invalid(writer.table("z", 9));
        invalid(writer.table("", 1));
        writer.row(b"k2", 2, &value).unwrap();
        invalid(writer.row(b"k1", 2, &value));
        invalid(writer.row(b"k3", 9, &value));
        let beyond = ValueLocation {
            offset: sample.header.start.position.offset,
            ..value
        };
        invalid(writer.row(b"k3", 2, &beyond));
        let later_segment = ValueLocation {
            segment_id: 2,
            ..value
        };
        invalid(writer.row(b"k3", 2, &later_segment));
        writer.row(b"k3", 2, &value).unwrap();
        let (reference, summary) = writer.finish().unwrap();
        assert_eq!((summary.tables, summary.rows), (1, 2));
        read(group, &reference).unwrap();

        let mut header = sample.header;
        header.checkpoint_id = 0;
        assert!(matches!(
            CheckpointWriter::create(group, header),
            Err(CoreError::InvalidInput(_))
        ));
    }

    #[test]
    fn checkpoint_files_are_create_only_and_failed_writes_stay_unreferenced() {
        let sample = sample();
        let group = &sample.log.group;
        write(group, sample.header, &sample.items);
        assert!(matches!(
            CheckpointWriter::create(group, sample.header),
            Err(CoreError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        let mut root = sample.log.root.clone();
        let (next, id) = root.reserve_checkpoint().unwrap();
        publish_root(group, &root, &next).unwrap();
        root = next;
        let header = CheckpointHeader {
            checkpoint_id: id,
            ..sample.header
        };
        group.fail(GroupOp::Sync, 1, FaultTiming::BeforeEffect);
        let mut writer = CheckpointWriter::create(group, header).unwrap();
        writer.table("a", 1).unwrap();
        assert!(matches!(writer.finish(), Err(CoreError::Io(_))));
        // The root never referenced it, so reopen classifies it as an orphan.
        let census = root.census(&group.crash()).unwrap();
        assert!(census.orphans.contains(&GroupFile::checkpoint(id)));
    }

    #[test]
    fn failed_write_fences_the_writer_and_leaves_an_orphan() {
        for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
            let sample = sample();
            let group = &sample.log.group;
            let file = GroupFile::checkpoint(sample.header.checkpoint_id);
            let Item::Row(_, _, value) = sample.items[1].clone() else {
                panic!("row expected");
            };
            // Rows of about 4 KiB, so the write window flushes within 17.
            let key = |index: u32| {
                let mut key = vec![b'k'; 4000];
                key.extend_from_slice(&index.to_be_bytes());
                key
            };
            let mut writer = CheckpointWriter::create(group, sample.header).unwrap();
            writer.table("a", 1).unwrap();
            group.fail(GroupOp::Write, 1, timing);
            let mut index = 0;
            let error = loop {
                if let Err(error) = writer.row(&key(index), 2, &value) {
                    break error;
                }
                index += 1;
                assert!(index < 32, "no flush");
            };
            assert!(matches!(error, CoreError::Io(_)), "{error:?}");
            // The failed row is counted and hashed but not in the file, so
            // every later call is refused, even one the order would accept.
            let len = group.len(file).unwrap();
            assert!(matches!(
                writer.row(&key(index + 1), 2, &value),
                Err(CoreError::OwnerFailed)
            ));
            assert!(matches!(writer.table("b", 1), Err(CoreError::OwnerFailed)));
            assert!(matches!(writer.finish(), Err(CoreError::OwnerFailed)));
            assert_eq!(group.len(file).unwrap(), len, "{timing:?}");
            // No reference exists to install, and reopen finds an orphan.
            let census = sample.log.root.census(&group.crash()).unwrap();
            assert_eq!(census.orphans, [file], "{timing:?}");
        }
    }

    #[test]
    fn unpublished_retirement_never_unlinks_a_segment_the_durable_checkpoint_uses() {
        let mut log = Log::new(1024);
        log.commit(&[Operation::create_table("t")]).unwrap();
        let a = log.commit(&[put("t", "a", vec![1; 900])]).unwrap();
        let b = log.commit(&[put("t", "a", vec![2; 900])]).unwrap();
        let (old, new) = (a.values[0].unwrap(), b.values[0].unwrap());
        assert_eq!((old.segment_id, new.segment_id), (2, 4));
        let table = Item::Table("t".to_owned(), 1);
        // Durable checkpoint 1 covers batch 2 and uses the old value.
        let (first, _) = checkpoint_through(
            &mut log,
            &a,
            &[table.clone(), Item::Row(b"a".to_vec(), a.batch_seq, old)],
        );
        let installed = log.root.install_checkpoint(first).unwrap();
        publish_root(&log.group, &log.root, &installed).unwrap();
        log.root = installed;
        // Checkpoint 2 no longer uses segment 2, but neither its
        // installation nor the retirement is published.
        let (_, second) = checkpoint_through(
            &mut log,
            &b,
            &[table, Item::Row(b"a".to_vec(), b.batch_seq, new)],
        );
        let installing = log.root.install_checkpoint(second.reference).unwrap();
        let unpublished = installing.retire_segment(old.segment_id, &second).unwrap();
        let segment = GroupFile::segment(old.segment_id);
        assert!(matches!(
            unpublished.unlink_garbage(&log.group, segment),
            Err(CoreError::InvalidInput(
                "garbage unlink does not follow the selected root"
            ))
        ));
        assert!(log.group.exists(segment).unwrap());

        // After power loss the durable root still loads checkpoint 1 with
        // every segment it uses, and replays batch 3 after it.
        let group = log.group.crash();
        let root = selected_root(&group).unwrap();
        assert_eq!(root, log.root);
        assert_eq!(root.checkpoint(), Some(first));
        let (loaded, _) = read(&group, &first).unwrap();
        verify_referenced_segments(&group, &root, &loaded).unwrap();
        assert_eq!(read_value(&group, &old).unwrap(), vec![1; 900]);
        let reopened = reopen_from(&group, &loaded.header.start).unwrap();
        assert_eq!(reopened.batches.len(), 1);
        assert_eq!(reopened.batches[0].batch_seq, b.batch_seq);

        // Once published, the same retirement unlinks the segment.
        publish_root(&log.group, &log.root, &installing).unwrap();
        publish_root(&log.group, &installing, &unpublished).unwrap();
        log.root = unpublished;
        let unlinked = log.root.unlink_garbage(&log.group, segment).unwrap();
        log.root = publish_forget(&log.group, &log.root, unlinked).unwrap();
        let group = log.group.crash();
        assert!(!group.exists(segment).unwrap());
        let root = selected_root(&group).unwrap();
        let (loaded, _) = read(&group, &root.checkpoint().unwrap()).unwrap();
        verify_referenced_segments(&group, &root, &loaded).unwrap();
        assert_eq!(read_value(&group, &new).unwrap(), vec![2; 900]);
    }

    #[test]
    fn legacy_single_file_images_are_rejected() {
        let group = InMemoryGroup::new();
        for len in [16usize, 4096] {
            let file = GroupFile::checkpoint(len as u64);
            let mut image = vec![0u8; len];
            image[..16].copy_from_slice(&LEGACY_MAGIC);
            group.insert_foreign(file, image);
            let reference = CheckpointRef {
                id: file.id,
                len: len as u64,
                start_segment_id: 1,
                sha256: [0; 32],
            };
            assert_eq!(
                corrupt_reason(read(&group, &reference)),
                "unsupported KASUMI-KV-000001 single-file image"
            );
        }
    }

    #[test]
    fn referenced_segments_must_be_live_and_intact() {
        let mut log = Log::new(1024);
        log.commit(&[Operation::create_table("t")]).unwrap();
        let first = log.commit(&[put("t", "a", vec![1; 600])]).unwrap();
        log.commit(&[put("t", "b", vec![2; 600])]).unwrap();
        let (next, checkpoint_id) = log.root.reserve_checkpoint().unwrap();
        publish_root(&log.group, &log.root, &next).unwrap();
        log.root = next;
        let header = CheckpointHeader {
            group_id: GROUP,
            checkpoint_id,
            start: ReplayStart {
                position: log.writer.position().unwrap(),
                batch_seq: log.writer.last_batch_seq(),
                chain: log.writer.chain(),
            },
        };
        let value = first.values[0].unwrap();
        let items = [
            Item::Table("t".to_owned(), 1),
            Item::Row(b"a".to_vec(), 2, value),
        ];
        let (reference, summary) = write(&log.group, header, &items);
        verify_referenced_segments(&log.group, &log.root, &summary).unwrap();

        let missing = log.group.crash();
        missing.remove_foreign(GroupFile::segment(value.segment_id));
        assert_eq!(
            corrupt_reason(verify_referenced_segments(&missing, &log.root, &summary)),
            "checkpoint references a retired or missing segment"
        );
        // The root refuses to retire a segment the checkpoint still uses, so
        // only a damaged garbage list can name one.
        let installed = log.root.install_checkpoint(reference).unwrap();
        assert!(
            installed
                .retire_segment(value.segment_id, &summary)
                .is_err()
        );
        let retired = installed.with_damaged_garbage(vec![GroupFile::segment(value.segment_id)]);
        assert_eq!(
            corrupt_reason(verify_referenced_segments(&log.group, &retired, &summary)),
            "checkpoint references a retired or missing segment"
        );
        let damaged = log.group.crash();
        damaged.with_durable(GroupFile::segment(value.segment_id), |bytes| bytes[3] ^= 1);
        assert_eq!(
            corrupt_reason(verify_referenced_segments(&damaged, &log.root, &summary)),
            "checkpoint references a damaged segment"
        );
    }

    #[test]
    fn restart_loads_the_checkpoint_and_replays_only_later_batches() {
        let mut sample = sample();
        let (reference, _) = write(&sample.log.group, sample.header, &sample.items);
        let installed = sample.log.root.install_checkpoint(reference).unwrap();
        publish_root(&sample.log.group, &sample.log.root, &installed).unwrap();
        sample.log.root = installed;
        let later = sample
            .log
            .commit(&[
                put("a", "k3", b"four".to_vec()),
                Operation::delete("b", b"k1".to_vec()),
            ])
            .unwrap();

        let group = sample.log.group.crash();
        let root = selected_root(&group).unwrap();
        assert_eq!(root.checkpoint(), Some(reference));
        let (summary, items) = read(&group, &root.checkpoint().unwrap()).unwrap();
        assert_eq!(items, sample.items);
        let reopened = reopen_from(&group, &summary.header.start).unwrap();
        assert_eq!(reopened.batches.len(), 1);
        assert_eq!(reopened.batches[0].batch_seq, later.batch_seq);
        assert_eq!(reopened.end.chain, later.chain);

        // A checkpoint whose chain differs from the log fails closed on the
        // first later commit instead of silently diverging.
        let forged = ReplayStart {
            chain: [7; 32],
            ..summary.header.start
        };
        assert_eq!(
            corrupt_reason(reopen_from(&group, &forged)),
            "commit chain differs"
        );
    }

    #[test]
    fn reclaimed_segment_leaves_the_root_only_after_a_confirmed_unlink() {
        let mut log = Log::new(1024);
        log.commit(&[Operation::create_table("t")]).unwrap();
        let a = log.commit(&[put("t", "a", vec![1; 900])]).unwrap();
        let b = log.commit(&[put("t", "b", vec![2; 900])]).unwrap();
        // Segment 1 holds only the table creation and segment 3 only commit
        // 2; the values live in segments 2 and 4.
        let placed =
            |batch: &CommittedBatch| (batch.values[0].unwrap().segment_id, batch.end.segment_id);
        assert_eq!((placed(&a), placed(&b)), ((2, 3), (4, 5)));
        let items = [
            Item::Table("t".to_owned(), 1),
            Item::Row(b"a".to_vec(), 2, a.values[0].unwrap()),
            Item::Row(b"b".to_vec(), 3, b.values[0].unwrap()),
        ];
        let (reference, summary) = checkpoint_through(&mut log, &b, &items);
        assert_eq!(reference.start_segment_id, 5);
        let installed = log.root.install_checkpoint(reference).unwrap();
        publish_root(&log.group, &log.root, &installed).unwrap();
        log.root = installed;
        for needed in [2, 4, 5] {
            assert!(
                log.root.retire_segment(needed, &summary).is_err(),
                "{needed}"
            );
        }
        let retired = log.root.retire_segment(1, &summary).unwrap();
        publish_root(&log.group, &log.root, &retired).unwrap();
        log.root = retired;

        // The unlink removes the name but its parent synchronization fails.
        let segment = GroupFile::segment(1);
        log.group.fail(GroupOp::Unlink, 1, FaultTiming::AfterEffect);
        assert!(log.root.unlink_garbage(&log.group, segment).is_err());
        let census = log.root.census(&log.group).unwrap();
        assert_eq!(census.garbage_unlink_pending, [segment]);
        // Power loss now brings the file back, still recorded as garbage.
        let early = log.group.crash();
        let early_root = selected_root(&early).unwrap();
        assert_eq!(
            early_root.census(&early).unwrap().garbage_present,
            [segment]
        );
        // Only the proof of that unlink drops the record.
        let unlinked = log.root.unlink_garbage(&log.group, segment).unwrap();
        log.root = publish_forget(&log.group, &log.root, unlinked).unwrap();

        let group = log.group.crash();
        assert!(!group.exists(segment).unwrap());
        let root = selected_root(&group).unwrap();
        assert!(root.garbage().is_empty());
        let (loaded, loaded_items) = read(&group, &root.checkpoint().unwrap()).unwrap();
        assert_eq!(loaded_items, items);
        verify_referenced_segments(&group, &root, &loaded).unwrap();
        let reopened = reopen_from(&group, &loaded.header.start).unwrap();
        assert!(reopened.batches.is_empty());
        assert_eq!(reopened.end.batch_seq, 3);
        assert_eq!(
            read_value(&group, &b.values[0].unwrap()).unwrap(),
            vec![2; 900]
        );
    }
}
