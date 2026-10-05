//! Constant-size retained-log inventory over authenticated, uniquely keyed rows.
//! The Store namespace order is HMAC order; no plaintext ordering is assumed.
use super::*;
use std::ops::{Bound, Range, RangeInclusive};

// Preserve the previous scan/get record ceiling. Control consumers may apply
// their own narrower limits, but log inventory must not invent a new one.
pub(crate) const HEADER_BYTES: usize = 32 << 20;
const APPEND_BATCH_BYTES: usize = 48 << 20;
const APPEND_BATCH_OPERATIONS: usize = 65536;
type EntryWrites = (Option<WriteOp>, Vec<WriteOp>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetainedSpan {
    pub(super) first: LogId<u64>,
    pub(super) last: LogId<u64>,
}
impl RetainedSpan {
    pub(super) fn intersect(self, bounds: (Bound<u64>, Bound<u64>)) -> Option<RangeInclusive<u64>> {
        let first = match bounds.0 {
            Bound::Included(value) => value,
            Bound::Excluded(value) => value.checked_add(1)?,
            Bound::Unbounded => 0,
        }
        .max(self.first.index);
        let last = match bounds.1 {
            Bound::Included(value) => value,
            Bound::Excluded(value) => value.checked_sub(1)?,
            Bound::Unbounded => u64::MAX,
        }
        .min(self.last.index);
        (first <= last).then_some(first..=last)
    }
    pub(super) fn check_endpoint(self, id: LogId<u64>) -> Result<()> {
        ensure!(
            (id.index != self.first.index || id == self.first)
                && (id.index != self.last.index || id == self.last),
            "raft retained endpoint log ID mismatch"
        );
        Ok(())
    }
    pub(super) fn including(previous: Option<Self>, entries: &[Entry<TypeConfig>]) -> Result<Self> {
        let first = entries.first().context("empty raft append chunk")?.log_id;
        let last = entries.last().context("empty raft append chunk")?.log_id;
        for pair in entries.windows(2) {
            ensure!(
                pair[0].log_id.index.checked_add(1) == Some(pair[1].log_id.index),
                "raft append contains a hole or repeated index"
            );
        }
        let Some(previous) = previous else {
            return Ok(Self { first, last });
        };
        ensure!(
            first.index as u128 <= previous.last.index as u128 + 1
                && last.index as u128 + 1 >= previous.first.index as u128,
            "raft append would leave a hole"
        );
        Ok(Self {
            first: if first.index <= previous.first.index {
                first
            } else {
                previous.first
            },
            last: if last.index >= previous.last.index {
                last
            } else {
                previous.last
            },
        })
    }
}

#[derive(Default)]
pub(crate) struct HeaderFold {
    span: Option<RetainedSpan>,
    count: u128,
}
impl HeaderFold {
    fn observe(&mut self, index: u64, header: LogHeader) -> Result<()> {
        header.validate()?;
        self.observe_id(index, header.log_id)
    }
    // Shape-only construction uses authenticated key/ID/cardinality without
    // claiming the separate initialization signature/append validation here.
    pub(crate) fn observe_id(&mut self, index: u64, log_id: LogId<u64>) -> Result<()> {
        ensure!(log_id.index == index, "raft key/index mismatch");
        self.count = self
            .count
            .checked_add(1)
            .context("raft header count overflow")?;
        match &mut self.span {
            None => {
                self.span = Some(RetainedSpan {
                    first: log_id,
                    last: log_id,
                })
            }
            Some(span) => {
                if index < span.first.index {
                    span.first = log_id;
                }
                if index > span.last.index {
                    span.last = log_id;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn finish(self) -> Result<Option<RetainedSpan>> {
        if let Some(span) = self.span {
            // Store authentication verifies each plaintext key against its exact
            // physical HMAC key, and its native table has unique keys. Thus each
            // validated index occurs once. Cardinality equals span iff no index
            // is missing, regardless of the order in which rows were visited.
            ensure!(
                self.count == span.last.index as u128 - span.first.index as u128 + 1,
                "raft log contains a hole"
            );
        }
        Ok(self.span)
    }
}

pub(super) fn retained_span(store: &TenantStore) -> Result<Option<RetainedSpan>> {
    let mut fold = HeaderFold::default();
    store.visit(HEADERS, HEADER_BYTES, |key, value| {
        let key: [u8; 8] = key.try_into().context("invalid raft index key")?;
        fold.observe(
            u64::from_be_bytes(key),
            crate::control::decode_canonical(value)?,
        )
    })?;
    fold.finish()
}

pub(super) fn read_header(store: &TenantStore, index: u64) -> Result<LogHeader> {
    let bytes = store
        .get_bounded(HEADERS, &index.to_be_bytes(), HEADER_BYTES)?
        .context("missing retained raft header")?;
    let header: LogHeader = crate::control::decode_canonical(&bytes)?;
    header.validate()?;
    ensure!(header.log_id.index == index, "raft key/index mismatch");
    Ok(header)
}

// Use the existing recovery entry window and append byte window for limited
// reads. These bound a returned prefix, never the size of an individually legal
// entry. Exact try_get_log_entries requests remain unchanged.
const READ_BATCH_ENTRIES: usize = 64;
const READ_BATCH_BYTES: usize = APPEND_BATCH_BYTES;

#[derive(Default)]
pub(super) struct ReadBatch {
    entries: usize,
    bytes: usize,
}
impl ReadBatch {
    pub(super) fn full(&self) -> bool {
        self.entries >= READ_BATCH_ENTRIES || self.bytes >= READ_BATCH_BYTES
    }
    pub(super) fn admit(&mut self, bytes: usize) -> Result<bool> {
        let total = self
            .bytes
            .checked_add(bytes)
            .context("raft read size overflow")?;
        if self.entries != 0 && (self.full() || total > READ_BATCH_BYTES) {
            return Ok(false);
        }
        self.bytes = total;
        self.entries += 1;
        Ok(true)
    }
}

/// The connected overlap/suffix commits first, then each prepended chunk moves
/// the lower endpoint backward. Any successful durable prefix has no hole.
pub(super) struct EntryBatches {
    forward: Range<usize>,
    backward_end: usize,
}
impl EntryBatches {
    pub(super) fn new(
        previous: Option<RetainedSpan>,
        entries: &[Entry<TypeConfig>],
    ) -> Result<Self> {
        if entries.is_empty() {
            return Ok(Self {
                forward: 0..0,
                backward_end: 0,
            });
        }
        RetainedSpan::including(previous, entries)?;
        let pivot = previous.map_or(0, |span| {
            entries.partition_point(|entry| entry.log_id.index < span.first.index)
        });
        Ok(Self {
            forward: pivot..entries.len(),
            backward_end: pivot,
        })
    }
    pub(super) fn next_range(&mut self, writes: &[EntryWrites]) -> Result<Option<Range<usize>>> {
        self.next_with(|index| {
            let (application, custody) = &writes[index];
            let count = usize::from(application.is_some()) + custody.len();
            let bytes =
                application
                    .iter()
                    .chain(custody.iter())
                    .try_fold(0usize, |bytes, op| {
                        let size = match op {
                            WriteOp::Put {
                                namespace,
                                key,
                                value,
                            } => namespace.len() + key.len() + value.len(),
                            WriteOp::Delete { namespace, key } => namespace.len() + key.len(),
                        };
                        bytes.checked_add(size).context("raft append size overflow")
                    })?;
            Ok((bytes, count))
        })
    }
    fn next_with(
        &mut self,
        mut cost: impl FnMut(usize) -> Result<(usize, usize)>,
    ) -> Result<Option<Range<usize>>> {
        let forward = !self.forward.is_empty();
        let (mut start, mut end) = if forward {
            (self.forward.start, self.forward.start)
        } else if self.backward_end != 0 {
            (self.backward_end, self.backward_end)
        } else {
            return Ok(None);
        };
        let mut bytes = 0usize;
        let mut count = 0usize;
        loop {
            let next = if forward {
                if end == self.forward.end {
                    break;
                }
                end
            } else {
                if start == 0 {
                    break;
                }
                start - 1
            };
            let (entry_bytes, entry_count) = cost(next)?;
            let next_bytes = bytes
                .checked_add(entry_bytes)
                .context("raft append size overflow")?;
            let next_count = count
                .checked_add(entry_count)
                .context("raft append operation overflow")?;
            if start != end
                && (next_bytes > APPEND_BATCH_BYTES || next_count > APPEND_BATCH_OPERATIONS)
            {
                break;
            }
            bytes = next_bytes;
            count = next_count;
            if forward {
                end += 1;
            } else {
                start -= 1;
            }
        }
        if forward {
            self.forward.start = end;
        } else {
            self.backward_end = start;
        }
        Ok(Some(start..end))
    }
}

#[cfg(test)]
#[path = "retained_logs_tests.rs"]
mod tests;
