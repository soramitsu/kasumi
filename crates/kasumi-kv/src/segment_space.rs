//! Allocation-free planning of the actual ordinary transaction record layout.
//! The plan is not a quota claim or a native publication/rollback witness.
use super::*;
use crate::group::{ExistingFileSpace, FileSpaceRange};

fn overflow() -> CoreError {
    CoreError::new(crate::CoreErrorCause::InvalidInput(
        "segment transaction-space arithmetic overflow",
    ))
}

// This uses precisely the ordinary wire fields but never creates EncodedOp's
// inline Vec or computes payload checksums during a space-only pass.
fn operation_length(operation: &Operation) -> Result<u64, CoreError> {
    let body = match operation {
        Operation::CreateTable { table } => table.len(),
        Operation::Put { table, key, value } => PUT_PREFIX_BYTES
            .checked_add(table.len())
            .and_then(|n| n.checked_add(key.len()))
            .and_then(|n| n.checked_add(value.len()))
            .ok_or_else(overflow)?,
        Operation::Delete { table, key } => DELETE_PREFIX_BYTES
            .checked_add(table.len())
            .and_then(|n| n.checked_add(key.len()))
            .ok_or_else(overflow)?,
    };
    u64::try_from(body.checked_add(RECORD_HEADER_BYTES).ok_or_else(overflow)?)
        .map_err(|_| overflow())
}

impl SegmentWriter {
    /// Describe the existing tail and every fresh ID needed for ordinary
    /// operations plus the Directory and Commit records, using this writer's
    /// actual capacity. A pending intent must be settled before planning.
    pub(crate) fn transaction_space(
        &self,
        first_fresh: u64,
        operations: &[Operation],
    ) -> Result<(Option<ExistingFileSpace>, FileSpaceRange), CoreError> {
        if self.fenced || self.prepared.is_some() {
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        if self.reserved.is_some() || !self.stage.is_empty() || self.stage_at != self.end {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "segment transaction-space requires a settled tail",
            )));
        }
        if self.next_batch_seq == u64::MAX {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "batch sequence overflow",
            )));
        }
        validate_batch(operations)?;
        if first_fresh == 0
            || first_fresh == u64::MAX
            || self.capacity <= SEGMENT_HEADER_BYTES
            || self.capacity > SEGMENT_BYTES
            || self.active.is_some_and(|id| {
                id == 0
                    || id >= first_fresh
                    || self.end < SEGMENT_HEADER_BYTES
                    || self.end > self.capacity
            })
            || (self.active.is_none() && self.end != 0)
        {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "invalid segment transaction-space start",
            )));
        }
        let mut existing = self.active.map(|id| ExistingFileSpace {
            file: GroupFile::segment(id),
            initial_len: self.end,
            maximum_len: self.end,
        });
        let mut new = FileSpaceRange {
            first_id: 0,
            count: 0,
            full_len: 0,
            minimum_len: 0,
            last_len: 0,
            total_len: 0,
        };
        let mut active = self.active.is_some();
        let mut end = self.end;
        let mut add_record = |length: u64| -> Result<(), CoreError> {
            if length > self.capacity - SEGMENT_HEADER_BYTES {
                return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                    "record exceeds segment capacity",
                )));
            }
            if !active || end.checked_add(length).ok_or_else(overflow)? > self.capacity {
                if new.count != 0 {
                    new.total_len = new.total_len.checked_add(end).ok_or_else(overflow)?;
                } else if let Some(tail) = &mut existing {
                    tail.maximum_len = end;
                }
                let count = new.count.checked_add(1).ok_or_else(overflow)?;
                // Root allocation must leave a representable, non-sentinel next ID.
                first_fresh
                    .checked_add(count)
                    .filter(|next| *next != u64::MAX)
                    .ok_or_else(overflow)?;
                new.count = count;
                new.first_id = first_fresh;
                new.full_len = self.capacity;
                new.minimum_len = SEGMENT_HEADER_BYTES;
                active = true;
                end = SEGMENT_HEADER_BYTES;
            }
            end = end.checked_add(length).ok_or_else(overflow)?;
            Ok(())
        };
        for operation in operations {
            add_record(operation_length(operation)?)?;
        }
        add_record(DIRECTORY_RECORD_BYTES as u64)?;
        add_record(COMMIT_RECORD_BYTES as u64)?;
        if new.count == 0 {
            existing
                .as_mut()
                .expect("records have an existing tail")
                .maximum_len = end;
        } else {
            new.last_len = end;
            new.total_len = new.total_len.checked_add(end).ok_or_else(overflow)?;
        }
        Ok((existing, new))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::test_support::{GROUP, Log, put};

    fn empty_range(range: &FileSpaceRange) {
        assert_eq!(
            (
                range.first_id,
                range.count,
                range.full_len,
                range.minimum_len,
                range.last_len,
                range.total_len
            ),
            (0, 0, 0, 0, 0, 0)
        );
    }

    #[test]
    fn planned_segment_lengths_equal_actual_operations_and_terminal_records() {
        for capacity in [512, 1024, 4096, SEGMENT_BYTES] {
            let mut log = Log::new(capacity);
            for batch in 0..12 {
                let operations = [
                    Operation::CreateTable {
                        table: "rows".into(),
                    },
                    put("rows", "a", vec![1; batch * 13]),
                    Operation::Delete {
                        table: "rows".into(),
                        key: vec![7; batch + 1],
                    },
                    put("rows", "z", vec![2; batch * 9]),
                ];
                let first = log.root.last_segment_id() + 1;
                let old = log.writer.position();
                let (existing, range) = log.writer.transaction_space(first, &operations).unwrap();
                assert_eq!(
                    existing
                        .as_ref()
                        .map(|tail| (tail.file.id, tail.initial_len)),
                    old.map(|at| (at.segment_id, at.offset))
                );
                log.commit(&operations).unwrap();
                if let Some(tail) = existing {
                    assert_eq!(log.group.len(tail.file).unwrap(), tail.maximum_len);
                }
                assert_eq!(log.root.last_segment_id() + 1 - first, range.count);
                if range.count == 0 {
                    empty_range(&range);
                } else {
                    let mut total = 0;
                    for id in range.first_id..range.first_id + range.count {
                        let length = log.group.len(GroupFile::segment(id)).unwrap();
                        assert!(length <= range.full_len);
                        assert!(length >= range.minimum_len);
                        total += length;
                        if id + 1 == range.first_id + range.count {
                            assert_eq!(length, range.last_len);
                        }
                    }
                    assert_eq!(total, range.total_len);
                }
            }
        }
    }

    #[test]
    fn segment_plan_covers_exact_fit_and_terminal_only_rolls_without_padding_charge() {
        let operation = put("t", "k", vec![3; 19]);
        let exact = SEGMENT_HEADER_BYTES
            + operation_length(&operation).unwrap()
            + DIRECTORY_RECORD_BYTES as u64
            + COMMIT_RECORD_BYTES as u64;
        let log = Log::new(exact);
        let (_, fit) = log
            .writer
            .transaction_space(1, std::slice::from_ref(&operation))
            .unwrap();
        assert_eq!(fit.count, 1);
        assert_eq!(fit.total_len, exact);
        let mut log = Log::new(exact - 1);
        let (_, rolled) = log
            .writer
            .transaction_space(1, std::slice::from_ref(&operation))
            .unwrap();
        assert_eq!(rolled.count, 2);
        assert_eq!(rolled.total_len, exact + SEGMENT_HEADER_BYTES);
        assert!(rolled.total_len < rolled.count * rolled.full_len);
        log.commit(&[operation]).unwrap();
        assert_eq!(
            log.group.len(GroupFile::segment(2)).unwrap(),
            rolled.last_len
        );
    }

    #[test]
    fn segment_plan_refuses_uncertain_state_and_id_exhaustion_without_mutation() {
        let operations = [put("t", "k", vec![3])];
        let mut writer = SegmentWriter::new(GROUP);
        assert!(writer.transaction_space(0, &operations).is_err());
        assert!(writer.transaction_space(u64::MAX - 1, &operations).is_err());
        let (_, last) = writer.transaction_space(u64::MAX - 2, &operations).unwrap();
        assert_eq!(last.first_id, u64::MAX - 2);
        writer.reserved = Some(1);
        assert!(writer.transaction_space(2, &operations).is_err());
        assert_eq!(writer.reserved, Some(1));
        writer.reserved = None;
        writer.fenced = true;
        assert!(
            matches!(&(writer.transaction_space(1, &operations)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert!(writer.position().is_none());
    }
}
