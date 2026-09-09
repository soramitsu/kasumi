//! An unpublished canonical image with a bounded, encrypted point index. Values
//! contain offsets only: source records remain in the immutable encrypted image.
//! This type proves framing and structural references, never application semantics.
use crate::snapshot_codec::{Record, RecordPosition, StreamSummary};
use anyhow::{Result, ensure};
use kasumi_store::{EncryptedTable, SnapshotImage};
use std::io::{Read, Seek, SeekFrom};

type Key = (u8, String, String);
const KINDS: usize = crate::snapshot_codec::RECORD_KINDS as usize;

pub(crate) struct StagedSnapshot {
    image: SnapshotImage,
    index: EncryptedTable,
    counts: [u64; KINDS],
    spans: [Option<(u64, u64)>; KINDS],
    summary: StreamSummary,
}

impl StagedSnapshot {
    pub(crate) fn new(
        image: SnapshotImage,
        max_index_disk_bytes: u64,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        check()?;
        let index = EncryptedTable::new(image.disk(), max_index_disk_bytes)?;
        let mut counts = [0u64; KINDS];
        let mut spans = [None; KINDS];
        let mut previous_change_item = None;
        let mut group: Option<(u8, String, u64, u64, u64)> = None;
        let summary = crate::snapshot_codec::visit(&mut image.reader(), |position, record| {
            check()?;
            let key = record.order();
            match &record {
                Record::Document(collection, _) | Record::Archived(collection, _, _) => {
                    require(&index, &(2, collection.clone(), String::new()))?;
                }
                Record::StageChunk(stage, _, _) | Record::ActiveStage(stage) => {
                    require(&index, &(6, stage.clone(), String::new()))?;
                }
                Record::ChangeItem(sequence, item, _) => {
                    require(&index, &(9, format!("{sequence:020}"), String::new()))?;
                    let expected = match previous_change_item {
                        Some((old, next)) if old == *sequence => next,
                        _ => 0,
                    };
                    ensure!(*item == expected, "change record sequence differs");
                    previous_change_item = Some((
                        *sequence,
                        item.checked_add(1)
                            .ok_or_else(|| anyhow::anyhow!("change item count overflow"))?,
                    ));
                }
                Record::RecoveryPhase(_, record) => {
                    require(
                        &index,
                        &(18, record.operation_id.to_string(), String::new()),
                    )?;
                }
                Record::RecoveryTarget(_, operation) => {
                    require(&index, &(18, operation.to_string(), String::new()))?;
                }
                Record::RecoveryOperation(_, _) => {
                    let header = get_record(&image, &index, &(0, String::new(), String::new()))?;
                    ensure!(
                        matches!(header, Some(Record::Header(head)) if head.tenant == crate::control::CONTROL_TENANT && head.lifecycle_control.is_some()),
                        "recovery coordinator requires installed Control state"
                    );
                }
                Record::Intent(_, _) | Record::ControlChange(_, _) => {
                    // The header is independently point-addressed. Embedded maps
                    // have already been rejected by the canonical decoder.
                    let header = get_record(&image, &index, &(0, String::new(), String::new()))?;
                    ensure!(
                        matches!(header, Some(Record::Header(head)) if head.lifecycle_control.is_some()),
                        "control installation missing"
                    );
                }
                _ => {}
            }
            let kind = usize::from(key.0);
            counts[kind] = counts[kind]
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("snapshot index count overflow"))?;
            let end = position
                .offset
                .checked_add(position.bytes)
                .ok_or_else(|| anyhow::anyhow!("snapshot index offset overflow"))?;
            let first = spans[kind]
                .map(|(first, _)| first)
                .unwrap_or(position.offset - 8);
            spans[kind] = Some((first, end));
            if group
                .as_ref()
                .is_some_and(|(kind, primary, _, _, _)| *kind != key.0 || primary != &key.1)
            {
                write_group(&index, group.take().expect("present group"))?;
            }
            let group = group.get_or_insert((key.0, key.1.clone(), position.offset - 8, end, 0));
            group.3 = end;
            group.4 = group
                .4
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("snapshot group count overflow"))?;
            let mut location = [0u8; 16];
            location[..8].copy_from_slice(&position.offset.to_be_bytes());
            location[8..].copy_from_slice(&position.bytes.to_be_bytes());
            index.insert(&serde_json::to_vec(&key)?, &location)?;
            check()
        })?;
        if let Some(group) = group {
            write_group(&index, group)?;
        }
        ensure!(
            summary.bytes == image.len(),
            "snapshot image length differs"
        );
        check()?;
        Ok(Self {
            image,
            index,
            counts,
            spans,
            summary,
        })
    }

    pub(crate) fn get(&self, kind: u8, primary: &str, secondary: &str) -> Result<Option<Record>> {
        get_record(
            &self.image,
            &self.index,
            &(kind, primary.to_owned(), secondary.to_owned()),
        )
    }

    pub(crate) fn count(&self, kind: u8) -> Result<u64> {
        self.counts
            .get(usize::from(kind))
            .copied()
            .ok_or_else(|| anyhow::anyhow!("unsupported snapshot record kind"))
    }

    /// Exact payload and length-prefix bytes for one canonical record kind.
    pub(crate) fn framed_bytes(&self, kind: u8) -> Result<u64> {
        let span = self
            .spans
            .get(usize::from(kind))
            .ok_or_else(|| anyhow::anyhow!("unsupported snapshot record kind"))?;
        Ok(span.map_or(0, |(start, end)| end - start))
    }

    pub(crate) fn image(&self) -> &SnapshotImage {
        &self.image
    }

    pub(crate) fn summary(&self) -> StreamSummary {
        self.summary
    }

    /// Category ranges refer to the validated physical stream, not a potentially
    /// large in-memory key listing. A callback may perform bounded point reads.
    pub(crate) fn visit(
        &self,
        kind: u8,
        mut visitor: impl FnMut(Record) -> Result<()>,
    ) -> Result<()> {
        for record in self.cursor(kind, None)? {
            visitor(record?)?;
        }
        Ok(())
    }

    pub(crate) fn cursor(&self, kind: u8, primary: Option<&str>) -> Result<RecordCursor> {
        let span = self
            .spans
            .get(usize::from(kind))
            .ok_or_else(|| anyhow::anyhow!("unsupported snapshot record kind"))?;
        let (start, end, count) = if let Some(primary) = primary {
            match self
                .index
                .get(&serde_json::to_vec(&(255u8, kind, primary))?)?
            {
                Some(bytes) => serde_json::from_slice(&bytes)?,
                None => (0, 0, 0),
            }
        } else {
            span.map(|(start, end)| (start, end, self.count(kind).unwrap_or(0)))
                .unwrap_or((0, 0, 0))
        };
        Ok(RecordCursor {
            image: self.image.clone(),
            offset: start,
            end,
            count,
            kind,
            primary: primary.map(str::to_owned),
            failed: false,
        })
    }
}

pub(crate) struct RecordCursor {
    image: SnapshotImage,
    offset: u64,
    end: u64,
    count: u64,
    kind: u8,
    primary: Option<String>,
    failed: bool,
}
impl Iterator for RecordCursor {
    type Item = Result<Record>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || (self.offset == self.end && self.count == 0) {
            return None;
        }
        let result = (|| {
            ensure!(
                self.offset < self.end && self.count > 0,
                "snapshot indexed count differs"
            );
            let mut reader = self.image.reader();
            let offset = self.offset;
            reader.seek(SeekFrom::Start(offset))?;
            let mut length = [0; 8];
            reader.read_exact(&mut length)?;
            let position = RecordPosition {
                offset: offset
                    .checked_add(8)
                    .ok_or_else(|| anyhow::anyhow!("snapshot index offset overflow"))?,
                bytes: u64::from_be_bytes(length),
            };
            self.offset = position
                .offset
                .checked_add(position.bytes)
                .filter(|offset| *offset <= self.end)
                .ok_or_else(|| anyhow::anyhow!("snapshot index span differs"))?;
            let record = read_record(&self.image, position)?;
            let key = record.order();
            ensure!(
                key.0 == self.kind && self.primary.as_ref().is_none_or(|p| p == &key.1),
                "snapshot indexed kind differs"
            );
            self.count -= 1;
            Ok(record)
        })();
        if result.is_err() {
            self.failed = true;
        }
        Some(result)
    }
}

fn write_group(
    index: &EncryptedTable,
    (kind, primary, start, end, count): (u8, String, u64, u64, u64),
) -> Result<()> {
    index.insert(
        &serde_json::to_vec(&(255u8, kind, primary))?,
        &serde_json::to_vec(&(start, end, count))?,
    )
}

fn require(index: &EncryptedTable, key: &Key) -> Result<()> {
    ensure!(
        index.get(&serde_json::to_vec(key)?)?.is_some(),
        "snapshot structural parent missing"
    );
    Ok(())
}

fn get_record(image: &SnapshotImage, index: &EncryptedTable, key: &Key) -> Result<Option<Record>> {
    let Some(bytes) = index.get(&serde_json::to_vec(key)?)? else {
        return Ok(None);
    };
    ensure!(bytes.len() == 16, "snapshot index location differs");
    let position = RecordPosition {
        offset: u64::from_be_bytes(bytes[..8].try_into()?),
        bytes: u64::from_be_bytes(bytes[8..].try_into()?),
    };
    let record = read_record(image, position)?;
    ensure!(&record.order() == key, "snapshot index identity differs");
    Ok(Some(record))
}

fn read_record(image: &SnapshotImage, position: RecordPosition) -> Result<Record> {
    ensure!(
        position.offset >= 16
            && position.bytes > 0
            && position.bytes <= 32 << 20
            && position
                .offset
                .checked_add(position.bytes)
                .is_some_and(|end| end <= image.len()),
        "snapshot index location outside image"
    );
    let mut reader = image.reader();
    reader.seek(SeekFrom::Start(position.offset))?;
    let mut bytes = vec![0u8; usize::try_from(position.bytes)?];
    reader.read_exact(&mut bytes)?;
    // The immutable image was canonically decoded and terminally verified before
    // this index was returned. Every point read still authenticates spool frames.
    Ok(serde_json::from_slice(&bytes)?)
}
