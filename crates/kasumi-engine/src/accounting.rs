//! Exact canonical resident semantic-record sizes. Only changed document/stage
//! records are remeasured during ordinary writes; permanent receipt rows have
//! their own checked byte budget and only a fixed head is resident.
use crate::snapshot_codec::{Record, metadata};
use kasumi_types::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Default)]
pub(crate) struct SnapshotAccounting {
    documents: usize,
    archived: usize,
    audits: usize,
    staged: usize,
    feed: usize,
    archives: usize,
    activations: usize,
    retirements: usize,
    recovery_operations: usize,
    recovery_phases: usize,
    recovery_targets: usize,
    recovery_completion_history: usize,
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
    size.checked_add(crate::snapshot_codec::FRAME_HEADER_BYTES)
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "snapshot record overflow"))
}
fn change(total: &mut usize, old: usize, new: usize) -> Result<()> {
    *total = total
        .checked_sub(old)
        .and_then(|n| n.checked_add(new))
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "snapshot accounting mismatch"))?;
    Ok(())
}
pub(crate) fn staged_header(key: &str, value: &StagedTransaction) -> Result<u64> {
    let mut header = value.clone();
    header.chunks.clear();
    Ok(record(&Record::Stage(key.into(), header))? as u64)
}
/// While any stage owns future terminal capacity, reserve the maximum decimal
/// widths of both aggregate counters as well as its record bytes. Moving bytes
/// from reserved to used can never defeat a previously accepted snapshot budget.
pub(crate) fn staged_headroom(state: &TenantState) -> Result<u64> {
    let digits = if state.reserved_staged_terminal_bytes == 0 {
        0
    } else {
        80 - state.permanent_staged_bytes.to_string().len() as u64
            - state.reserved_staged_terminal_bytes.to_string().len() as u64
            - state.staged_terminal_head.count.to_string().len() as u64
            - state.staged_terminal_head.encoded_bytes.to_string().len() as u64
    };
    state
        .reserved_staged_terminal_bytes
        .checked_add(digits)
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "staged snapshot headroom overflow"))
}
pub(crate) fn target_audit_reserve(state: &TenantState) -> u64 {
    let Some(active) = state
        .target_completion_head
        .as_ref()
        .and_then(|head| head.active.as_ref())
    else {
        return 0;
    };
    if state
        .target_lifecycle
        .get(&state.incarnation)
        .is_some_and(|entry| entry.completion.is_some())
    {
        active
            .reserved_audit_bytes
            .saturating_sub(MAX_AUDIT_EVENT_BYTES as u64)
    } else {
        active.reserved_audit_bytes
    }
}
pub(crate) fn target_completion_reserve(state: &TenantState) -> u64 {
    if state
        .target_completion_head
        .as_ref()
        .is_some_and(|head| head.active.is_some())
        && state
            .target_lifecycle
            .get(&state.incarnation)
            .is_some_and(|entry| entry.completion.is_none())
    {
        MAX_TARGET_COMPLETION_RECORD_BYTES
    } else {
        0
    }
}
pub(crate) fn audit_fits(state: &TenantState) -> bool {
    state
        .audit_retention
        .hot_bytes
        .checked_add(target_audit_reserve(state))
        .is_some_and(|bytes| bytes <= state.limits.audit_retention.hot_bytes)
}
pub(crate) fn snapshot_headroom(state: &TenantState) -> Result<u64> {
    staged_headroom(state)?
        .checked_add(target_audit_reserve(state))
        .and_then(|n| n.checked_add(target_completion_reserve(state)))
        // Active metadata is already charged. Reserve bounded future selector
        // and decimal-width growth before its completion can be dispatched.
        .and_then(|n| {
            n.checked_add(if state.target_completion_head.is_some() {
                64 << 10
            } else {
                0
            })
        })
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Corruption,
                "target completion workspace overflow",
            )
        })
}
fn stage(key: &str, value: &StagedTransaction) -> Result<usize> {
    let mut size = usize::try_from(staged_header(key, value)?)
        .map_err(|_| Error::new(ErrorCode::Corruption, "staged header size overflow"))?;
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
fn map_changes<V: Clone + PartialEq>(
    total: &mut usize,
    previous: &imbl::OrdMap<String, V>,
    next: &imbl::OrdMap<String, V>,
    size: impl Fn(&str, &V) -> Result<usize>,
) -> Result<()> {
    for difference in previous.diff(next) {
        use imbl::ordmap::DiffItem;
        match difference {
            DiffItem::Add(key, value) => change(total, 0, size(key, value)?)?,
            DiffItem::Remove(key, value) => change(total, size(key, value)?, 0)?,
            DiffItem::Update {
                old: (old_key, old),
                new: (new_key, new),
            } => {
                change(total, size(old_key, old)?, size(new_key, new)?)?;
            }
        }
    }
    Ok(())
}
fn recovery_operation(key: &str, value: &RecoveryRecord) -> Result<usize> {
    record(&Record::RecoveryOperation(
        key.into(),
        Box::new(value.clone()),
    ))
}
fn recovery_phase(key: &str, value: &RecoveryPhaseRecord) -> Result<usize> {
    record(&Record::RecoveryPhase(key.into(), Box::new(value.clone())))
}
fn recovery_completion_history(key: &str, value: &RecoveryCompletionHistory) -> Result<usize> {
    record(&Record::RecoveryCompletionHistory(
        key.into(),
        Box::new(value.clone()),
    ))
}
fn recovery_target(key: &str, value: &uuid::Uuid) -> Result<usize> {
    record(&Record::RecoveryTarget(key.into(), *value))
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
        map_changes(
            &mut result.recovery_operations,
            &Default::default(),
            &state.recovery_control.operations,
            recovery_operation,
        )?;
        map_changes(
            &mut result.recovery_phases,
            &Default::default(),
            &state.recovery_control.phases,
            recovery_phase,
        )?;
        map_changes(
            &mut result.recovery_completion_history,
            &Default::default(),
            &state.recovery_control.completion_history,
            recovery_completion_history,
        )?;
        map_changes(
            &mut result.recovery_targets,
            &Default::default(),
            &state.recovery_control.targets,
            recovery_target,
        )?;
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
        map_changes(
            &mut result.recovery_operations,
            &previous.recovery_control.operations,
            &next.recovery_control.operations,
            recovery_operation,
        )?;
        map_changes(
            &mut result.recovery_phases,
            &previous.recovery_control.phases,
            &next.recovery_control.phases,
            recovery_phase,
        )?;
        map_changes(
            &mut result.recovery_completion_history,
            &previous.recovery_control.completion_history,
            &next.recovery_control.completion_history,
            recovery_completion_history,
        )?;
        map_changes(
            &mut result.recovery_targets,
            &previous.recovery_control.targets,
            &next.recovery_control.targets,
            recovery_target,
        )?;
        Ok(result)
    }
    pub fn bytes(&self, state: &TenantState) -> Result<usize> {
        // Eight-byte format prefix plus the 56-byte terminal record.
        let mut total = 64usize;
        change(
            &mut total,
            0,
            usize::try_from(state.staged_terminal_head.encoded_bytes).map_err(|_| {
                Error::new(ErrorCode::Corruption, "terminal snapshot byte overflow")
            })?,
        )?;
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
            self.audits,
            self.staged,
            self.feed,
            self.archives,
            self.activations,
            self.retirements,
            self.recovery_operations,
            self.recovery_phases,
            self.recovery_targets,
            self.recovery_completion_history,
        ] {
            change(&mut total, 0, size)?;
        }
        Ok(total)
    }
    pub fn fits(&self, state: &TenantState) -> Result<bool> {
        let headroom = snapshot_headroom(state)?;
        Ok((self.bytes(state)? as u64)
            .checked_add(20 - state.revision.to_string().len() as u64)
            .and_then(|n| n.checked_add(headroom))
            .is_some_and(|n| n <= state.limits.max_snapshot_bytes))
    }
}
