//! Feed cursors address immutable change headers and individual after-images
//! in the selected application directory. A page never decodes a whole commit.
use super::{DurableRecord, KeyBuilder};
use anyhow::{Context, Result, ensure};
use kasumi_store::{
    NodeDiskMemoryAdmission,
    ordered_pages::{Direction, TreeReader},
};
use kasumi_types::{ChangeCommit, ChangeRecord, DocumentSlot, StoredDocument, validate_name};
use std::{ops::Bound, sync::Arc};

#[derive(serde::Deserialize)]
#[serde(tag = "type", content = "value", deny_unknown_fields)]
enum Row {
    Change(ChangeCommit),
    ChangeItem(String, String, Option<StoredDocument>),
}

pub(crate) struct SnapshotFeed<'a, 'view> {
    pub tree: &'a TreeReader<'view>,
    pub memory: &'a Arc<dyn NodeDiskMemoryAdmission>,
    pub end_sequence: u64,
    pub revision: u64,
}

fn number(encoded: &mut &[u8]) -> Result<u64> {
    let mut value = [0; 8];
    for byte in &mut value {
        let (&next, rest) = encoded.split_first().context("short change sequence")?;
        *byte = next;
        *encoded = if next == 0 {
            rest.strip_prefix(&[0xff])
                .context("invalid change sequence escape")?
        } else {
            rest
        };
    }
    *encoded = encoded
        .strip_prefix(&[0, 1])
        .context("invalid change sequence terminator")?;
    Ok(u64::from_be_bytes(value))
}

fn header_sequence(key: &[u8]) -> Result<u64> {
    let mut encoded = key
        .strip_prefix(&[9])
        .context("expected a change header key")?;
    let first = number(&mut encoded)?;
    ensure!(encoded.is_empty(), "invalid change header suffix");
    Ok(first)
}

impl<'a, 'view> SnapshotFeed<'a, 'view> {
    /// The tail of the immutable change-item directory identifies the last
    /// complete commit. A retained snapshot with no events owns no prefix.
    pub(crate) fn open(
        tree: &'a TreeReader<'view>,
        memory: &'a Arc<dyn NodeDiskMemoryAdmission>,
        snapshot_revision: u64,
        state: &kasumi_types::TenantState,
    ) -> Result<Option<Self>> {
        let mut feed = Self {
            tree,
            memory,
            revision: snapshot_revision,
            end_sequence: state.change_feed.next_sequence,
        };
        if snapshot_revision < state.revision {
            let Some(last) = feed.adjacent_header(Bound::Excluded(&[10]), Direction::Reverse)?
            else {
                return Ok(None);
            };
            let mut end = None;
            tree.scan(Bound::Excluded(&[11]), Direction::Reverse, &mut |key, _| {
                let mut encoded = key
                    .strip_prefix(&[10])
                    .context("snapshot change items missing")?;
                let first = number(&mut encoded)?;
                let ordinal = number(&mut encoded)?;
                ensure!(
                    first == last && encoded.is_empty(),
                    "snapshot terminal change item differs"
                );
                end = Some(
                    first
                        .checked_add(ordinal)
                        .and_then(|n| n.checked_add(1))
                        .context("snapshot change sequence overflow")?,
                );
                Ok(false)
            })?;
            feed.end_sequence = end.context("snapshot change tail missing")?;
            ensure!(
                feed.end_sequence <= state.change_feed.next_sequence,
                "snapshot feed exceeds selected head"
            );
        }
        Ok(Some(feed))
    }

    fn adjacent_header(&self, bound: Bound<&[u8]>, direction: Direction) -> Result<Option<u64>> {
        let mut found = None;
        self.tree.scan(bound, direction, &mut |key, _| {
            if key.first() == Some(&9) {
                found = Some(header_sequence(key)?);
            }
            Ok(false)
        })?;
        Ok(found)
    }

    fn with_row<T>(&self, key: &[u8], visit: impl FnOnce(Row) -> Result<T>) -> Result<T> {
        // These rows contain only bounded names, scalar fields and at most one
        // stored descriptor. Body bytes live in the selected document store.
        self.tree.with_value(key, 8 << 10, |bytes| {
            let bytes = bytes.context("selected change feed row is missing")?;
            let work = crate::snapshot_codec::inspect_external_json_work(bytes, &mut || Ok(()))?;
            let _lease = crate::document_restore::ReadAdmissionFailure::reserve(
                self.memory,
                work.checked_add(2 * bytes.len() as u64 + 512)
                    .context("change row workspace overflow")?,
            )?;
            let row: Row = serde_json::from_slice(bytes)?;
            let canonical = match &row {
                Row::Change(commit) => DurableRecord::Change(commit),
                Row::ChangeItem(collection, id, document) => {
                    DurableRecord::ChangeItem(collection, id, document.as_ref())
                }
            };
            ensure!(
                serde_json::to_vec(&canonical)? == bytes,
                "noncanonical change feed row"
            );
            visit(row)
        })
    }

    pub(crate) fn visit(
        &self,
        first_retained: u64,
        mut sequence: u64,
        mut visit: impl FnMut(u64, u64, usize, usize, &ChangeRecord) -> kasumi_types::Result<bool>,
    ) -> kasumi_types::Result<bool> {
        use crate::service::document_load_error;
        let end = self.end_sequence;
        if sequence >= end {
            return Ok(true);
        }
        let start = KeyBuilder::new(9).number(sequence).finish();
        let mut first = self
            .adjacent_header(Bound::Included(&start), Direction::Reverse)
            .and_then(|first| first.context("change cursor has no containing commit"))
            .map_err(document_load_error)?;
        let mut previous_revision = 0;
        while sequence < end {
            let header_key = KeyBuilder::new(9).number(first).finish();
            let next = self
                .adjacent_header(Bound::Excluded(&header_key), Direction::Forward)
                .map_err(document_load_error)?
                .unwrap_or(end);
            let revision = self
                .with_row(&header_key, |row| {
                    let Row::Change(header) = row else {
                        anyhow::bail!("expected change commit")
                    };
                    ensure!(
                        first >= first_retained
                            && first <= sequence
                            && sequence < next
                            && next <= end
                            && header.first_sequence == first
                            && header.records.is_empty()
                            && header.revision > previous_revision
                            && header.revision <= self.revision,
                        "change cursor and selected commit disagree"
                    );
                    Ok(header.revision)
                })
                .map_err(document_load_error)?;
            let count = usize::try_from(next - first).map_err(|e| document_load_error(e.into()))?;
            while sequence < next {
                let ordinal = sequence - first;
                let key = KeyBuilder::new(10).number(first).number(ordinal).finish();
                let keep_going = self
                    .with_row(&key, |row| {
                        let Row::ChangeItem(collection, id, document) = row else {
                            anyhow::bail!("expected change item")
                        };
                        validate_name(&collection)?;
                        validate_name(&id)?;
                        if let Some(descriptor) = &document {
                            descriptor.validate()?;
                            ensure!(
                                descriptor.id == id && descriptor.version == revision,
                                "change after-image identity differs"
                            );
                        }
                        let record = ChangeRecord {
                            collection,
                            id,
                            document: document.map(|v| Arc::new(DocumentSlot::Stored(v))),
                        };
                        Ok(visit(sequence, revision, ordinal as usize, count, &record))
                    })
                    .map_err(document_load_error)??;
                if !keep_going {
                    return Ok(false);
                }
                sequence += 1;
            }
            previous_revision = revision;
            first = next;
        }
        Ok(true)
    }
}
