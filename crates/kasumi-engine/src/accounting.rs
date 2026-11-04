//! Exact canonical resident semantic-record sizes. Only changed document/stage
//! records are remeasured during ordinary writes; permanent receipt and Control backup binding rows have
//! their own checked byte budgets and only fixed heads are resident.
use crate::snapshot_codec::{Record, metadata_with_shared};
use kasumi_types::*;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Clone, Default)]
pub(crate) struct SnapshotAccounting {
    shared: Option<SharedAccounting>,
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
/// Metadata totals are inline numbers, not another retained metadata tree or
/// map. Like document/audit accounting, they belong to the paired generation:
/// `updated` compares still-live previous/next owners before remeasuring changes.
#[derive(Clone, Copy, Default)]
struct SharedAccounting {
    policy: usize,
    lineage: usize,
    control_header: Option<usize>,
    control_records: usize,
    collections: usize,
    completion: Option<CompletionSizes>,
}
#[derive(Clone, Copy)]
struct CompletionSizes {
    policy: usize,
    control_header: usize,
    control_records: usize,
    control: usize,
}
#[cfg(test)]
thread_local! { static SHARED_MEASUREMENTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
fn measured<T>(measure: impl FnOnce() -> Result<T>) -> Result<T> {
    #[cfg(test)]
    SHARED_MEASUREMENTS.with(|count| count.set(count.get() + 1));
    measure()
}
fn lineage_bytes(links: &[RestoreLineageLink]) -> Result<usize> {
    measured(|| {
        let mut total = 0;
        for (i, link) in links.iter().enumerate() {
            change(
                &mut total,
                0,
                record(&Record::Lineage(i as u64, link.clone()))?,
            )?;
        }
        Ok(total)
    })
}
fn control_record_bytes(control: &LifecycleControlState) -> Result<usize> {
    measured(|| {
        let mut total = 0;
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
        Ok(total)
    })
}
fn collection_header_bytes(name: &str, collection: &CollectionState) -> Result<usize> {
    measured(|| {
        record(&Record::Collection(
            name.to_owned(),
            CollectionState {
                definition: collection.definition.clone(),
                data_epoch: collection.data_epoch,
                documents: Default::default(),
                archived_documents: Default::default(),
                archived_document_bytes: collection.archived_document_bytes,
            },
        ))
    })
}
impl SharedAccounting {
    fn control(&mut self, control: Option<&Arc<LifecycleControlState>>) -> Result<()> {
        self.control_header = control
            .map(|control| {
                measured(|| encoded_len(&crate::snapshot_codec::control_header(control)))
            })
            .transpose()?;
        self.control_records = control
            .map(|control| control_record_bytes(control))
            .transpose()?
            .unwrap_or(0);
        self.completion = control
            .and_then(|control| control.pending_change.map(|id| (control, id)))
            .map(|(control, id)| {
                // The synthetic completed tree is transient, just as it was in
                // completion_fits. Only these four sizes survive publication.
                let (policy, completed) = crate::state::lifecycle::completed_metadata(control, id)?;
                Ok(CompletionSizes {
                    policy: encoded_len(&policy)?,
                    control_header: encoded_len(&crate::snapshot_codec::control_header(
                        &completed,
                    ))?,
                    control_records: control_record_bytes(&completed)?,
                    control: encoded_len(&completed)?,
                })
            })
            .transpose()?;
        Ok(())
    }
    fn rebuild(state: &TenantState) -> Result<Self> {
        let mut result = Self {
            policy: measured(|| encoded_len(&state.policy))?,
            lineage: lineage_bytes(&state.restore_lineage)?,
            ..Self::default()
        };
        result.control(state.lifecycle_control.as_ref())?;
        for (name, collection) in &state.collections {
            change(
                &mut result.collections,
                0,
                collection_header_bytes(name, collection)?,
            )?;
        }
        Ok(result)
    }
    fn updated(&self, previous: &TenantState, next: &TenantState) -> Result<Self> {
        let mut result = *self;
        if !Arc::ptr_eq(&previous.policy, &next.policy) {
            result.policy = measured(|| encoded_len(&next.policy))?;
        }
        if !Arc::ptr_eq(&previous.restore_lineage, &next.restore_lineage) {
            result.lineage = lineage_bytes(&next.restore_lineage)?;
        }
        let same_control = match (&previous.lifecycle_control, &next.lifecycle_control) {
            (Some(old), Some(new)) => Arc::ptr_eq(old, new),
            (None, None) => true,
            _ => false,
        };
        if !same_control {
            result.control(next.lifecycle_control.as_ref())?;
        }
        for (name, old) in &previous.collections {
            match next.collections.get(name) {
                Some(new) if Arc::ptr_eq(&old.definition, &new.definition) => {
                    let counters = |collection: &CollectionState| {
                        (collection.data_epoch.max(1).ilog10()
                            + collection.archived_document_bytes.max(1).ilog10()
                            + 2) as usize
                    };
                    let before = counters(old);
                    let after = counters(new);
                    // Only decimal widths change when the schema owner is the
                    // same. At a widening boundary also recheck the row cap.
                    if after > before {
                        collection_header_bytes(name, new)?;
                    }
                    change(&mut result.collections, before, after)?;
                }
                new => change(
                    &mut result.collections,
                    collection_header_bytes(name, old)?,
                    new.map(|new| collection_header_bytes(name, new))
                        .transpose()?
                        .unwrap_or(0),
                )?,
            }
        }
        for (name, new) in &next.collections {
            if !previous.collections.contains_key(name) {
                change(
                    &mut result.collections,
                    0,
                    collection_header_bytes(name, new)?,
                )?;
            }
        }
        Ok(result)
    }
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
    framed_record_bytes(encoded_len(record)?)
}
fn framed_record_bytes(size: usize) -> Result<usize> {
    if size > (32 << 20) {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "snapshot record exceeds byte limit",
        ));
    }
    size.checked_add(crate::snapshot_codec::FRAME_HEADER_BYTES)
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "snapshot record overflow"))
}

fn framing_with_document(base: usize, replacement: u64) -> Result<usize> {
    base.checked_sub(4)
        .and_then(|n| n.checked_add(usize::try_from(replacement).ok()?))
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "document framing size overflow"))
}

/// Count logical full-after-image wire bytes from an authenticated descriptor.
/// The placeholder is JSON null, so counting never faults a cold body into RAM.
pub(crate) fn change_record_bytes(record: &ChangeRecord) -> Result<usize> {
    let header = ChangeRecord {
        collection: record.collection.clone(),
        id: record.id.clone(),
        document: None,
    };
    let bytes = encoded_len(&header)?;
    match &record.document {
        None => Ok(bytes),
        Some(document) => framing_with_document(
            bytes,
            document
                .document_bytes()
                .map_err(|_| Error::new(ErrorCode::Corruption, "document length invalid"))?,
        ),
    }
}

fn document_record(name: &str, document: &DocumentSlot) -> Result<usize> {
    #[derive(Serialize)]
    #[serde(tag = "type", content = "value")]
    enum Framing<'a> {
        Document(&'a str, Option<()>),
    }
    let bytes = framing_with_document(
        encoded_len(&Framing::Document(name, None))?,
        document
            .document_bytes()
            .map_err(|_| Error::new(ErrorCode::Corruption, "document length invalid"))?,
    )?;
    if bytes > (32 << 20) {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "snapshot record exceeds byte limit",
        ));
    }
    bytes
        .checked_add(crate::snapshot_codec::FRAME_HEADER_BYTES)
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
        let header = crate::snapshot_codec::WireChangeRecord {
            collection: value.collection.clone(),
            id: value.id.clone(),
            document: None,
        };
        let mut bytes = record(&Record::ChangeItem(key, i as u64, header))?;
        if let Some(document) = &value.document {
            bytes = framing_with_document(
                bytes,
                document
                    .document_bytes()
                    .map_err(|_| Error::new(ErrorCode::Corruption, "document length invalid"))?,
            )?;
        }
        change(&mut size, 0, bytes)?;
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
    /// Finish the bounded audit/header simulation using cached completion
    /// sizes. Neither this cache nor its clones retain a policy/lifecycle tree.
    pub(crate) fn fits_completion(
        &self,
        state: &TenantState,
        completed: &TenantState,
    ) -> Result<bool> {
        let shared = match self.shared {
            Some(shared) => shared,
            None => SharedAccounting::rebuild(state)?,
        };
        let projection = shared.completion.ok_or_else(|| {
            Error::new(
                ErrorCode::Corruption,
                "pending completion accounting absent",
            )
        })?;
        let control = state
            .lifecycle_control
            .as_ref()
            .expect("pending completion");
        if projection.control > control.installation.max_state_bytes {
            return Ok(false);
        }
        let mut accounting = self.updated(state, completed, &BTreeMap::new(), &BTreeSet::new())?;
        let metadata = accounting.shared.as_mut().expect("updated metadata");
        metadata.policy = projection.policy;
        metadata.control_header = Some(projection.control_header);
        metadata.control_records = projection.control_records;
        // Reconstruct and validate the projected header through bytes(), so
        // its individual record cap remains independent of the total budget.
        accounting.fits(completed)
    }
    pub fn rebuild(state: &TenantState) -> Result<Self> {
        let mut result = Self::default();
        for (name, collection) in &state.collections {
            for document in collection.documents.values() {
                change(&mut result.documents, 0, document_record(name, document)?)?;
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
        result.shared = Some(SharedAccounting::rebuild(state)?);
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
        result.shared = Some(match self.shared {
            Some(shared) => shared.updated(previous, next)?,
            None => SharedAccounting::rebuild(next)?,
        });
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
                    optional(old.documents.get(id), |d| document_record(name, d))?,
                    optional(new.documents.get(id), |d| document_record(name, d))?,
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
        let shared = match self.shared {
            Some(shared) => shared,
            None => SharedAccounting::rebuild(state)?,
        };
        let empty_policy = Arc::new(Policy::default());
        let mut header = encoded_len(&Record::Header(Box::new(metadata_with_shared(
            state,
            empty_policy.clone(),
            None,
        ))))?;
        change(
            &mut header,
            encoded_len(empty_policy.as_ref())?,
            shared.policy,
        )?;
        if let Some(control) = shared.control_header {
            change(&mut header, 4, control)?; // JSON null becomes the header.
        }
        change(&mut total, 0, framed_record_bytes(header)?)?;
        change(&mut total, 0, shared.lineage)?;
        change(&mut total, 0, shared.collections)?;
        for key in &state.active_staged_transactions {
            change(&mut total, 0, record(&Record::ActiveStage(key.clone()))?)?;
        }
        change(&mut total, 0, shared.control_records)?;
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
        self.fits_bytes(state, self.bytes(state)?)
    }
    fn fits_bytes(&self, state: &TenantState, bytes: usize) -> Result<bool> {
        let headroom = snapshot_headroom(state)?;
        Ok((bytes as u64)
            .checked_add(20 - state.revision.to_string().len() as u64)
            .and_then(|n| n.checked_add(headroom))
            .is_some_and(|n| n <= state.limits.max_snapshot_bytes))
    }
}

#[cfg(test)]
mod cold_document_accounting_tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn compact_document_and_feed_charges_match_canonical_wire_without_loading() {
        for body in [
            serde_json::json!(null),
            serde_json::json!({"proof": "ab".repeat(8192), "literal": "\"\\\n日本語"}),
            serde_json::json!({"$serde_json::private::Number": "7", "number": 1.25, "array": [true, false, null]}),
        ] {
            for version in [0, 1, u64::MAX] {
                let document = Arc::new(Document {
                    id: "row".into(),
                    version,
                    body: body.clone(),
                });
                let stored = Arc::new(DocumentSlot::Stored(
                    StoredDocument::from_document(&document, [42; 32], 100, 1 << 20, 4096).unwrap(),
                ));
                let original =
                    Record::Document("docs".into(), OwnedDocument::Pending(document.clone()));
                assert_eq!(
                    document_record("docs", &stored).unwrap(),
                    record(&original).unwrap()
                );
                let event = ChangeRecord {
                    collection: "docs".into(),
                    id: "row".into(),
                    document: Some(stored.clone()),
                };
                let wire = crate::snapshot_codec::WireChangeRecord {
                    collection: "docs".into(),
                    id: "row".into(),
                    document: Some(OwnedDocument::Pending(document)),
                };
                assert_eq!(
                    change_record_bytes(&event).unwrap(),
                    encoded_len(&wire).unwrap()
                );
                let logical = Record::ChangeItem(10, 0, wire);
                let commit = Arc::new(ChangeCommit {
                    revision: 12,
                    first_sequence: 10,
                    records: vec![event],
                    record_bytes: 0,
                });
                let mut header = commit.as_ref().clone();
                header.records.clear();
                assert_eq!(
                    feed(10, &commit).unwrap(),
                    record(&Record::Change(10, Arc::new(header))).unwrap()
                        + record(&logical).unwrap()
                );
            }
        }
    }
}

#[cfg(test)]
mod shared_accounting_tests {
    use super::*;

    fn canonical_bytes(state: &TenantState) -> usize {
        let mut bytes = 64;
        for kind in 0..crate::snapshot_codec::RECORD_KINDS {
            // These external point tables are empty in this metadata fixture.
            if matches!(kind, 21 | 22 | 24) {
                continue;
            }
            for row in crate::snapshot_codec::records(state, kind, None).unwrap() {
                bytes += record(&row.unwrap()).unwrap();
            }
        }
        bytes
    }

    #[test]
    fn completion_checks_the_projected_header_record_cap_before_the_total() {
        let mut state = crate::snapshot_codec::recovery_tests::coordinator();
        state.limits.max_snapshot_bytes = 1 << 30;
        let mut accounting = SnapshotAccounting::rebuild(&state).unwrap();
        let metadata = accounting.shared.as_mut().unwrap();
        // Model a cached completion whose policy makes the header exceed one
        // record while the whole tenant would still fit its 1 GiB budget.
        metadata.completion = Some(CompletionSizes {
            policy: 32 << 20,
            control_header: metadata.control_header.unwrap(),
            control_records: metadata.control_records,
            control: 0,
        });
        assert_eq!(
            accounting.fits_completion(&state, &state).unwrap_err().code,
            ErrorCode::QuotaExceeded
        );
    }

    #[test]
    fn unchanged_large_metadata_is_shared_and_measured_only_once() {
        let mut state = crate::snapshot_codec::recovery_tests::coordinator();
        state.collections.insert(
            "docs".into(),
            CollectionState {
                definition: Arc::new(CollectionDefinition {
                    name: "docs".into(),
                    schema: serde_json::json!({"type":"object", "description":"x".repeat(1 << 20)}),
                    indexes: vec![],
                    retention_class: CollectionRetentionClass::Operational,
                    write_mode: CollectionWriteMode::Mutable,
                    strict_read_audit: false,
                }),
                data_epoch: 9,
                documents: Default::default(),
                archived_documents: Default::default(),
                archived_document_bytes: 0,
            },
        );
        // The cache itself owns no allocation, including for Control's future
        // completion. Publishing it cannot retain an uncharged metadata clone.
        assert!(!std::mem::needs_drop::<SnapshotAccounting>());
        let owners = (
            Arc::strong_count(&state.policy),
            Arc::strong_count(state.lifecycle_control.as_ref().unwrap()),
        );
        let accounting = SnapshotAccounting::rebuild(&state).unwrap();
        assert_eq!(
            owners,
            (
                Arc::strong_count(&state.policy),
                Arc::strong_count(state.lifecycle_control.as_ref().unwrap())
            )
        );
        let mut next = state.clone();
        assert!(Arc::ptr_eq(&state.policy, &next.policy));
        assert!(Arc::ptr_eq(&state.restore_lineage, &next.restore_lineage));
        assert!(Arc::ptr_eq(
            state.lifecycle_control.as_ref().unwrap(),
            next.lifecycle_control.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            &state.collections["docs"].definition,
            &next.collections["docs"].definition
        ));
        next.revision = 12345;
        next.collections.get_mut("docs").unwrap().data_epoch = 8;
        let measured = SHARED_MEASUREMENTS.with(|count| count.get());
        let updated = accounting
            .updated(&state, &next, &BTreeMap::new(), &BTreeSet::new())
            .unwrap();
        assert_eq!(updated.bytes(&next).unwrap(), canonical_bytes(&next));
        updated.fits(&next).unwrap();
        assert_eq!(SHARED_MEASUREMENTS.with(|count| count.get()), measured);

        let before = next.clone();
        Arc::make_mut(&mut next.policy).strict_read_audit = true;
        Arc::make_mut(&mut next.collections.get_mut("docs").unwrap().definition).schema =
            serde_json::json!({"type":"object","title":"changed"});
        Arc::make_mut(next.lifecycle_control.as_mut().unwrap()).retired = true;
        let changed = updated
            .updated(&before, &next, &BTreeMap::new(), &BTreeSet::new())
            .unwrap();
        assert_eq!(changed.bytes(&next).unwrap(), canonical_bytes(&next));
        assert_ne!(
            updated.bytes(&before).unwrap(),
            changed.bytes(&next).unwrap()
        );
        assert!(!state.policy.strict_read_audit);
        assert_eq!(
            state.collections["docs"].definition.schema["description"]
                .as_str()
                .unwrap()
                .len(),
            1 << 20
        );
        // Arc serialization still emits the original value, with no wrapper.
        let encoded = serde_json::to_vec(&next).unwrap();
        let decoded: TenantState = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), encoded);
    }
}
