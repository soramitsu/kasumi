//! Exact canonical semantic-record sizes. Only changed document/receipt/stage
//! records are remeasured during ordinary writes; metadata stays bounded.
use crate::snapshot_codec::{Record, metadata};
use kasumi_types::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Default)]
pub(crate) struct SnapshotAccounting {
    documents: usize,
    archived: usize,
    receipts: usize,
    audits: usize,
    staged: usize,
    feed: usize,
    archives: usize,
    activations: usize,
    retirements: usize,
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
fn record(record: &Record) -> Result<usize> {
    let size = encoded_len(record)?;
    if size > (32 << 20) {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "snapshot record exceeds byte limit",
        ));
    }
    size.checked_add(8)
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "snapshot record overflow"))
}
fn change(total: &mut usize, old: usize, new: usize) -> Result<()> {
    *total = total
        .checked_sub(old)
        .and_then(|n| n.checked_add(new))
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "snapshot accounting mismatch"))?;
    Ok(())
}
fn stage(key: &str, value: &StagedTransaction) -> Result<usize> {
    let mut header = value.clone();
    header.chunks.clear();
    let mut size = record(&Record::Stage(key.into(), header))?;
    for (i, chunk) in &value.chunks {
        change(
            &mut size,
            0,
            record(&Record::StageChunk(key.into(), *i, chunk.clone()))?,
        )?;
    }
    Ok(size)
}
fn feed(key: u64, value: &std::sync::Arc<ChangeCommit>) -> Result<usize> {
    let mut header = value.as_ref().clone();
    header.records.clear();
    let mut size = record(&Record::Change(key, std::sync::Arc::new(header)))?;
    for (i, value) in value.records.iter().enumerate() {
        change(
            &mut size,
            0,
            record(&Record::ChangeItem(key, i as u64, value.clone()))?,
        )?;
    }
    Ok(size)
}

fn optional<T>(value: Option<&T>, size: impl FnOnce(&T) -> Result<usize>) -> Result<usize> {
    value.map(size).transpose().map(|size| size.unwrap_or(0))
}
impl SnapshotAccounting {
    pub fn rebuild(state: &TenantState) -> Result<Self> {
        let mut result = Self::default();
        for (name, collection) in &state.collections {
            for document in collection.documents.values() {
                change(
                    &mut result.documents,
                    0,
                    record(&Record::Document(name.clone(), document.clone()))?,
                )?;
            }
            for (id, reference) in &collection.archived_documents {
                change(
                    &mut result.archived,
                    0,
                    record(&Record::Archived(
                        name.clone(),
                        id.clone(),
                        reference.clone(),
                    ))?,
                )?;
            }
        }
        for (key, value) in &state.receipts {
            change(
                &mut result.receipts,
                0,
                record(&Record::Receipt(key.clone(), value.clone()))?,
            )?;
        }
        for (i, event) in state.audits.iter().enumerate() {
            change(
                &mut result.audits,
                0,
                record(&Record::Audit(
                    state
                        .audit_retention
                        .pruned_before
                        .checked_add(i as u64)
                        .ok_or_else(|| {
                            Error::new(ErrorCode::Corruption, "audit sequence overflow")
                        })?,
                    event.clone(),
                ))?,
            )?;
        }
        for (key, value) in &state.staged_transactions {
            change(&mut result.staged, 0, stage(key, value)?)?;
        }
        for (i, commit) in &state.change_feed.commits {
            change(&mut result.feed, 0, feed(*i, commit)?)?;
        }
        result.other(state)?;
        Ok(result)
    }
    fn other(&mut self, state: &TenantState) -> Result<()> {
        self.archives = 0;
        self.activations = 0;
        self.retirements = 0;
        for (key, value) in &state.history_archives {
            change(
                &mut self.archives,
                0,
                record(&Record::Archive(key.clone(), value.clone()))?,
            )?;
        }
        for (key, value) in &state.schema_activations {
            change(
                &mut self.activations,
                0,
                record(&Record::Activation(key.clone(), value.clone()))?,
            )?;
        }
        for (key, value) in &state.retirements {
            change(
                &mut self.retirements,
                0,
                record(&Record::Retirement(key.clone(), Box::new(value.clone())))?,
            )?;
        }
        Ok(())
    }
    pub fn updated(
        &self,
        previous: &TenantState,
        next: &TenantState,
        changed_documents: &BTreeMap<String, BTreeSet<String>>,
        changed_receipts: &BTreeSet<String>,
        changed_stages: &BTreeSet<String>,
    ) -> Result<Self> {
        let mut result = self.clone();
        for (name, ids) in changed_documents {
            let old = previous
                .collections
                .get(name)
                .ok_or_else(|| Error::new(ErrorCode::Corruption, "previous collection missing"))?;
            let new = next
                .collections
                .get(name)
                .ok_or_else(|| Error::new(ErrorCode::Corruption, "next collection missing"))?;
            for id in ids {
                change(
                    &mut result.documents,
                    optional(old.documents.get(id), |d| {
                        record(&Record::Document(name.clone(), d.clone()))
                    })?,
                    optional(new.documents.get(id), |d| {
                        record(&Record::Document(name.clone(), d.clone()))
                    })?,
                )?;
                change(
                    &mut result.archived,
                    optional(old.archived_documents.get(id), |d| {
                        record(&Record::Archived(name.clone(), id.clone(), d.clone()))
                    })?,
                    optional(new.archived_documents.get(id), |d| {
                        record(&Record::Archived(name.clone(), id.clone(), d.clone()))
                    })?,
                )?;
            }
        }
        for key in changed_receipts {
            change(
                &mut result.receipts,
                optional(previous.receipts.get(key), |r| {
                    record(&Record::Receipt(key.clone(), r.clone()))
                })?,
                optional(next.receipts.get(key), |r| {
                    record(&Record::Receipt(key.clone(), r.clone()))
                })?,
            )?;
        }
        for key in changed_stages {
            change(
                &mut result.staged,
                optional(previous.staged_transactions.get(key), |s| stage(key, s))?,
                optional(next.staged_transactions.get(key), |s| stage(key, s))?,
            )?;
        }
        let before = &previous.audit_retention;
        let after = &next.audit_retention;
        if before.stream_id != after.stream_id
            || after.pruned_before < before.pruned_before
            || after.pruned_before > before.next_sequence
            || after.next_sequence < before.next_sequence
            || after.next_sequence.checked_sub(after.pruned_before)
                != Some(next.audits.len() as u64)
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "audit accounting transition differs",
            ));
        }
        let removed = usize::try_from(after.pruned_before - before.pruned_before)
            .map_err(|_| Error::new(ErrorCode::Corruption, "audit prefix exceeds address space"))?;
        for (i, event) in previous.audits.iter().take(removed).enumerate() {
            change(
                &mut result.audits,
                record(&Record::Audit(
                    before.pruned_before.checked_add(i as u64).ok_or_else(|| {
                        Error::new(ErrorCode::Corruption, "audit sequence overflow")
                    })?,
                    event.clone(),
                ))?,
                0,
            )?;
        }
        let retained = usize::try_from(before.next_sequence - after.pruned_before)
            .map_err(|_| Error::new(ErrorCode::Corruption, "audit prefix exceeds address space"))?;
        for i in retained..next.audits.len() {
            change(
                &mut result.audits,
                0,
                record(&Record::Audit(
                    after.pruned_before.checked_add(i as u64).ok_or_else(|| {
                        Error::new(ErrorCode::Corruption, "audit sequence overflow")
                    })?,
                    next.audits[i].clone(),
                ))?,
            )?;
        }
        if !previous
            .change_feed
            .commits
            .ptr_eq(&next.change_feed.commits)
        {
            let first = next.change_feed.commits.get_min().map(|(i, _)| *i);
            for (i, commit) in previous
                .change_feed
                .commits
                .iter()
                .take_while(|(i, _)| first.is_none_or(|first| **i < first))
            {
                change(&mut result.feed, feed(*i, commit)?, 0)?;
            }
            let last = previous.change_feed.commits.get_max().map(|(i, _)| *i);
            for (i, commit) in next
                .change_feed
                .commits
                .iter()
                .rev()
                .take_while(|(i, _)| last.is_none_or(|last| **i > last))
            {
                change(&mut result.feed, 0, feed(*i, commit)?)?;
            }
        }
        if !previous.history_archives.ptr_eq(&next.history_archives)
            || !previous.schema_activations.ptr_eq(&next.schema_activations)
            || !previous.retirements.ptr_eq(&next.retirements)
        {
            result.other(next)?;
        }
        Ok(result)
    }
    pub fn bytes(&self, state: &TenantState) -> Result<usize> {
        // Eight-byte format prefix plus the 56-byte terminal record.
        let mut total = 64usize;
        change(
            &mut total,
            0,
            record(&Record::Header(Box::new(metadata(state))))?,
        )?;
        for (i, link) in state.restore_lineage.iter().enumerate() {
            change(
                &mut total,
                0,
                record(&Record::Lineage(i as u64, link.clone()))?,
            )?;
        }
        for (name, collection) in &state.collections {
            let header = CollectionState {
                definition: collection.definition.clone(),
                data_epoch: collection.data_epoch,
                documents: Default::default(),
                archived_documents: Default::default(),
                archived_document_bytes: collection.archived_document_bytes,
            };
            change(
                &mut total,
                0,
                record(&Record::Collection(name.clone(), header))?,
            )?;
        }
        for key in &state.active_staged_transactions {
            change(&mut total, 0, record(&Record::ActiveStage(key.clone()))?)?;
        }
        if let Some(control) = &state.lifecycle_control {
            for (id, intent) in &control.intents {
                change(&mut total, 0, record(&Record::Intent(*id, intent.clone()))?)?;
            }
            for (id, value) in &control.changes {
                change(
                    &mut total,
                    0,
                    record(&Record::ControlChange(*id, value.clone()))?,
                )?;
            }
        }
        for (key, target) in &state.target_lifecycle {
            change(
                &mut total,
                0,
                record(&Record::Target(key.clone(), Box::new(target.clone())))?,
            )?;
        }
        for size in [
            self.documents,
            self.archived,
            self.receipts,
            self.audits,
            self.staged,
            self.feed,
            self.archives,
            self.activations,
            self.retirements,
        ] {
            change(&mut total, 0, size)?;
        }
        Ok(total)
    }
    pub fn fits(&self, state: &TenantState) -> Result<bool> {
        let headroom = (20 - state.revision.to_string().len()).saturating_add(
            state
                .active_staged_transactions
                .len()
                .saturating_mul(STAGED_OUTCOME_HEADROOM),
        );
        Ok((self.bytes(state)?.saturating_add(headroom) as u64) <= state.limits.max_snapshot_bytes)
    }
}
