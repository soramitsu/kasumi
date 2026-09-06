//! Exact canonical JSON length, updated from changed resident entries. Braces
//! live in the fixed frame; these counters contain map/array contents only.
use kasumi_types::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Default)]
pub(crate) struct SnapshotAccounting {
    collection_headers: usize,
    documents: usize,
    receipts: usize,
    audits: usize,
}

pub(crate) fn encoded_len(value: &impl Serialize) -> Result<usize> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("JSON length overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "JSON encoding failed"))?;
    Ok(counter.0)
}
fn commas(count: usize) -> usize {
    count.saturating_sub(1)
}
fn entry(key: &str, value: &impl Serialize) -> Result<usize> {
    let value_bytes = encoded_len(value)?;
    encoded_len(&key)?
        .checked_add(1)
        .and_then(|n| n.checked_add(value_bytes))
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "snapshot accounting overflow"))
}
fn change(total: &mut usize, old: usize, new: usize) -> Result<()> {
    *total = total
        .checked_sub(old)
        .and_then(|n| n.checked_add(new))
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "snapshot accounting mismatch"))?;
    Ok(())
}
fn header(key: &str, collection: &CollectionState) -> Result<usize> {
    #[derive(Serialize)]
    struct EmptyCollection<'a> {
        definition: &'a CollectionDefinition,
        data_epoch: u64,
        documents: BTreeMap<(), ()>,
    }
    entry(
        key,
        &EmptyCollection {
            definition: &collection.definition,
            data_epoch: collection.data_epoch,
            documents: BTreeMap::new(),
        },
    )
}

impl SnapshotAccounting {
    pub fn rebuild(state: &TenantState) -> Result<Self> {
        let mut result = Self {
            collection_headers: commas(state.collections.len()),
            ..Self::default()
        };
        for (key, collection) in &state.collections {
            change(&mut result.collection_headers, 0, header(key, collection)?)?;
            change(&mut result.documents, 0, commas(collection.documents.len()))?;
            for (id, document) in &collection.documents {
                change(&mut result.documents, 0, entry(id, document)?)?;
            }
        }
        result.receipts = commas(state.receipts.len());
        for (key, receipt) in &state.receipts {
            change(&mut result.receipts, 0, entry(key, receipt)?)?;
        }
        result.audits = commas(state.audits.len());
        for audit in &state.audits {
            change(&mut result.audits, 0, encoded_len(audit)?)?;
        }
        Ok(result)
    }
    pub fn updated(
        &self,
        previous: &TenantState,
        next: &TenantState,
        changed_documents: &BTreeMap<String, BTreeSet<String>>,
        changed_receipts: &BTreeSet<String>,
    ) -> Result<Self> {
        let mut result = self.clone();
        change(
            &mut result.collection_headers,
            commas(previous.collections.len()),
            commas(next.collections.len()),
        )?;
        // Definitions have their own bounded metadata quota. Pointer equality is
        // unavailable for this small BTreeMap; compare only serialized definitions
        // when their operation changed the policy/schema epoch or collection count.
        let metadata_changed = previous.policy_epoch != next.policy_epoch
            || previous.collections.len() != next.collections.len();
        if metadata_changed {
            let names: BTreeSet<_> = previous
                .collections
                .keys()
                .chain(next.collections.keys())
                .collect();
            for name in names {
                let old = previous
                    .collections
                    .get(name)
                    .map(|c| header(name, c))
                    .transpose()?
                    .unwrap_or(0);
                let new = next
                    .collections
                    .get(name)
                    .map(|c| header(name, c))
                    .transpose()?
                    .unwrap_or(0);
                change(&mut result.collection_headers, old, new)?;
            }
        }
        for (name, ids) in changed_documents {
            let old = previous
                .collections
                .get(name)
                .ok_or_else(|| Error::new(ErrorCode::Corruption, "previous collection missing"))?;
            let new = next
                .collections
                .get(name)
                .ok_or_else(|| Error::new(ErrorCode::Corruption, "next collection missing"))?;
            if !metadata_changed {
                change(
                    &mut result.collection_headers,
                    header(name, old)?,
                    header(name, new)?,
                )?;
            }
            change(
                &mut result.documents,
                commas(old.documents.len()),
                commas(new.documents.len()),
            )?;
            for id in ids {
                change(
                    &mut result.documents,
                    old.documents
                        .get(id)
                        .map(|d| entry(id, d))
                        .transpose()?
                        .unwrap_or(0),
                    new.documents
                        .get(id)
                        .map(|d| entry(id, d))
                        .transpose()?
                        .unwrap_or(0),
                )?;
            }
        }
        change(
            &mut result.receipts,
            commas(previous.receipts.len()),
            commas(next.receipts.len()),
        )?;
        for key in changed_receipts {
            change(
                &mut result.receipts,
                previous
                    .receipts
                    .get(key)
                    .map(|r| entry(key, r))
                    .transpose()?
                    .unwrap_or(0),
                next.receipts
                    .get(key)
                    .map(|r| entry(key, r))
                    .transpose()?
                    .unwrap_or(0),
            )?;
        }
        if next.audits.len() < previous.audits.len() {
            return Err(Error::new(
                ErrorCode::Corruption,
                "audit removal requires explicit accounting",
            ));
        }
        change(
            &mut result.audits,
            commas(previous.audits.len()),
            commas(next.audits.len()),
        )?;
        for index in previous.audits.len()..next.audits.len() {
            change(&mut result.audits, 0, encoded_len(&next.audits[index])?)?;
        }
        Ok(result)
    }
    pub fn bytes(&self, state: &TenantState) -> Result<usize> {
        #[derive(Serialize)]
        struct Frame<'a> {
            tenant: &'a str,
            incarnation: &'a str,
            revision: u64,
            revision_base: u64,
            policy_epoch: u64,
            schema_epoch: u64,
            suspended: bool,
            retired: bool,
            pending_restore: &'a Option<PendingRestore>,
            document_count: u64,
            logical_bytes: u64,
            policy: &'a Policy,
            limits: &'a Limits,
            collections: BTreeMap<(), ()>,
            receipts: BTreeMap<(), ()>,
            audits: Vec<()>,
        }
        let frame = Frame {
            tenant: &state.tenant,
            incarnation: &state.incarnation,
            revision: state.revision,
            revision_base: state.revision_base,
            policy_epoch: state.policy_epoch,
            schema_epoch: state.schema_epoch,
            suspended: state.suspended,
            retired: state.retired,
            pending_restore: &state.pending_restore,
            document_count: state.document_count,
            logical_bytes: state.logical_bytes,
            policy: &state.policy,
            limits: &state.limits,
            collections: BTreeMap::new(),
            receipts: BTreeMap::new(),
            audits: Vec::new(),
        };
        [
            self.collection_headers,
            self.documents,
            self.receipts,
            self.audits,
        ]
        .into_iter()
        .try_fold(encoded_len(&frame)?, |n, v| {
            n.checked_add(v)
                .ok_or_else(|| Error::new(ErrorCode::Corruption, "snapshot accounting overflow"))
        })
    }
    pub fn fits(&self, state: &TenantState) -> Result<bool> {
        // Even a rejected command advances its revision. Reserve all remaining
        // decimal digits so a full tenant never violates its budget on rejection.
        let headroom = 20 - state.revision.to_string().len();
        Ok(self.bytes(state)?.saturating_add(headroom) <= state.limits.max_snapshot_bytes)
    }
}
