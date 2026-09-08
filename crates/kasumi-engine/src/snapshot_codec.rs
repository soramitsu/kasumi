//! Canonical tenant snapshots consist of independently bounded semantic records.
//! The decoder builds unpublished state one record at a time and accepts it only
//! after checking strict record ordering, counts, byte totals, digest, and EOF.
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    sync::Arc,
};

const MAGIC: &[u8; 8] = b"KASUMIT2";
const MAX_RECORD: usize = 32 << 20;

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "value", deny_unknown_fields)]
pub(crate) enum Record {
    Header(Box<TenantState>),
    Lineage(u64, RestoreLineageLink),
    Collection(String, CollectionState),
    Document(String, Arc<Document>),
    Archived(String, String, ArchivedDocument),
    Receipt(String, StoredReceipt),
    Stage(String, StagedTransaction),
    StageChunk(String, usize, Arc<StagedChunk>),
    ActiveStage(String),
    Change(u64, Arc<ChangeCommit>),
    ChangeItem(u64, u64, ChangeRecord),
    Archive(String, RetainedHistoryArchive),
    Activation(String, StoredSchemaActivation),
    Retirement(String, Box<StoredRetirement>),
    Audit(u64, AuditEvent),
    Intent(uuid::Uuid, LifecycleIntent),
    ControlChange(uuid::Uuid, ControlPolicyChange),
}
impl Record {
    fn order(&self) -> (u8, String, String) {
        match self {
            Self::Header(_) => (0, String::new(), String::new()),
            Self::Lineage(i, _) => (1, format!("{i:020}"), String::new()),
            Self::Collection(k, _) => (2, k.clone(), String::new()),
            Self::Document(k, d) => (3, k.clone(), d.id.clone()),
            Self::Archived(k, id, _) => (4, k.clone(), id.clone()),
            Self::Receipt(k, _) => (5, k.clone(), String::new()),
            Self::Stage(k, _) => (6, k.clone(), String::new()),
            Self::StageChunk(k, i, _) => (7, k.clone(), format!("{i:020}")),
            Self::ActiveStage(k) => (8, k.clone(), String::new()),
            Self::Change(i, _) => (9, format!("{i:020}"), String::new()),
            Self::ChangeItem(i, j, _) => (10, format!("{i:020}"), format!("{j:020}")),
            Self::Archive(k, _) => (11, k.clone(), String::new()),
            Self::Activation(k, _) => (12, k.clone(), String::new()),
            Self::Retirement(k, _) => (13, k.clone(), String::new()),
            Self::Audit(i, _) => (14, format!("{i:020}"), String::new()),
            Self::Intent(k, _) => (15, k.to_string(), String::new()),
            Self::ControlChange(k, _) => (16, k.to_string(), String::new()),
        }
    }
}

pub(crate) fn metadata(state: &TenantState) -> TenantState {
    TenantState {
        tenant: state.tenant.clone(),
        incarnation: state.incarnation.clone(),
        revision: state.revision,
        revision_base: state.revision_base,
        policy_epoch: state.policy_epoch,
        schema_epoch: state.schema_epoch,
        suspended: state.suspended,
        retired: state.retired,
        pending_restore: state.pending_restore.clone(),
        restored_from: state.restored_from.clone(),
        restore_lineage: Vec::new(),
        lifecycle_control: state
            .lifecycle_control
            .as_ref()
            .map(|c| LifecycleControlState {
                installation: c.installation.clone(),
                installation_command_id: c.installation_command_id,
                installation_revision: c.installation_revision,
                installation_policy_epoch: c.installation_policy_epoch,
                installation_policy: c.installation_policy.clone(),
                retired: c.retired,
                pending_change: c.pending_change,
                intents: Default::default(),
                changes: Default::default(),
            }),
        document_count: state.document_count,
        logical_bytes: state.logical_bytes,
        policy: state.policy.clone(),
        limits: state.limits.clone(),
        collections: Default::default(),
        receipts: Default::default(),
        staged_transactions: Default::default(),
        active_staged_transactions: Default::default(),
        change_feed: ChangeFeedState {
            next_sequence: state.change_feed.next_sequence,
            event_count: state.change_feed.event_count,
            encoded_commit_bytes: state.change_feed.encoded_commit_bytes,
            commits: Default::default(),
        },
        history_archives: Default::default(),
        history_archive_bytes: state.history_archive_bytes,
        schema_activations: Default::default(),
        schema_activation_bytes: state.schema_activation_bytes,
        retirements: Default::default(),
        retirement_bytes: state.retirement_bytes,
        audits: Default::default(),
    }
}
fn empty_records(state: &TenantState) -> bool {
    state.collections.is_empty()
        && state.receipts.is_empty()
        && state.staged_transactions.is_empty()
        && state.active_staged_transactions.is_empty()
        && state.change_feed.commits.is_empty()
        && state.history_archives.is_empty()
        && state.schema_activations.is_empty()
        && state.retirements.is_empty()
        && state.audits.is_empty()
        && state.restore_lineage.is_empty()
        && state
            .lifecycle_control
            .as_ref()
            .is_none_or(|c| c.intents.is_empty() && c.changes.is_empty())
}
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > MAX_RECORD)
        {
            return Err(std::io::Error::other("snapshot record exceeds byte limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn write(state: &TenantState, writer: &mut dyn Write) -> anyhow::Result<()> {
    writer.write_all(MAGIC)?;
    let mut digest = Sha256::new();
    digest.update(MAGIC);
    let mut count = 0u64;
    let mut total = 8u64;
    let mut emit = |record: Record| -> anyhow::Result<()> {
        let mut buffer = Bounded(Vec::new());
        serde_json::to_writer(&mut buffer, &record)?;
        let length = (buffer.0.len() as u64).to_be_bytes();
        writer.write_all(&length)?;
        writer.write_all(&buffer.0)?;
        digest.update(length);
        digest.update(&buffer.0);
        count = count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("snapshot record count overflow"))?;
        total = total
            .checked_add(8)
            .and_then(|n| n.checked_add(buffer.0.len() as u64))
            .ok_or_else(|| anyhow::anyhow!("snapshot byte overflow"))?;
        Ok(())
    };
    emit(Record::Header(Box::new(metadata(state))))?;
    for (i, item) in state.restore_lineage.iter().enumerate() {
        emit(Record::Lineage(i as u64, item.clone()))?;
    }
    for (key, collection) in &state.collections {
        emit(Record::Collection(
            key.clone(),
            CollectionState {
                definition: collection.definition.clone(),
                data_epoch: collection.data_epoch,
                documents: Default::default(),
                archived_documents: Default::default(),
                archived_document_bytes: collection.archived_document_bytes,
            },
        ))?;
    }
    for (key, collection) in &state.collections {
        for document in collection.documents.values() {
            emit(Record::Document(key.clone(), document.clone()))?;
        }
    }
    for (key, collection) in &state.collections {
        for (id, reference) in &collection.archived_documents {
            emit(Record::Archived(key.clone(), id.clone(), reference.clone()))?;
        }
    }
    for (key, receipt) in &state.receipts {
        emit(Record::Receipt(key.clone(), receipt.clone()))?;
    }
    for (key, stage) in &state.staged_transactions {
        let mut header = stage.clone();
        header.chunks.clear();
        emit(Record::Stage(key.clone(), header))?;
    }
    for (key, stage) in &state.staged_transactions {
        for (i, chunk) in &stage.chunks {
            emit(Record::StageChunk(key.clone(), *i, chunk.clone()))?;
        }
    }
    for key in &state.active_staged_transactions {
        emit(Record::ActiveStage(key.clone()))?;
    }
    for (key, commit) in &state.change_feed.commits {
        let mut header = commit.as_ref().clone();
        header.records.clear();
        emit(Record::Change(*key, Arc::new(header)))?;
    }
    for (key, commit) in &state.change_feed.commits {
        for (index, change) in commit.records.iter().enumerate() {
            emit(Record::ChangeItem(*key, index as u64, change.clone()))?;
        }
    }
    for (key, archive) in &state.history_archives {
        emit(Record::Archive(key.clone(), archive.clone()))?;
    }
    for (key, activation) in &state.schema_activations {
        emit(Record::Activation(key.clone(), activation.clone()))?;
    }
    for (key, retirement) in &state.retirements {
        emit(Record::Retirement(
            key.clone(),
            Box::new(retirement.clone()),
        ))?;
    }
    for (i, audit) in state.audits.iter().enumerate() {
        emit(Record::Audit(i as u64, audit.clone()))?;
    }
    if let Some(control) = &state.lifecycle_control {
        for (id, intent) in &control.intents {
            emit(Record::Intent(*id, intent.clone()))?;
        }
        for (id, change) in &control.changes {
            emit(Record::ControlChange(*id, change.clone()))?;
        }
    }
    writer.write_all(&0u64.to_be_bytes())?;
    writer.write_all(&count.to_be_bytes())?;
    writer.write_all(&total.to_be_bytes())?;
    writer.write_all(&digest.finalize())?;
    Ok(())
}

pub(crate) fn read(reader: &mut dyn Read) -> anyhow::Result<TenantState> {
    let mut magic = [0; 8];
    reader.read_exact(&mut magic)?;
    anyhow::ensure!(&magic == MAGIC, "unsupported tenant snapshot format");
    let mut digest = Sha256::new();
    digest.update(magic);
    let mut count = 0u64;
    let mut total = 8u64;
    let mut state: Option<TenantState> = None;
    let mut previous = None;
    loop {
        let mut length = [0; 8];
        reader.read_exact(&mut length)?;
        let size = u64::from_be_bytes(length);
        if size == 0 {
            let mut footer = [0; 48];
            reader.read_exact(&mut footer)?;
            anyhow::ensure!(
                count > 0
                    && u64::from_be_bytes(footer[..8].try_into()?) == count
                    && u64::from_be_bytes(footer[8..16].try_into()?) == total
                    && digest.finalize().as_slice() == &footer[16..],
                "snapshot terminal authentication differs"
            );
            anyhow::ensure!(reader.read(&mut [0])? == 0, "trailing snapshot data");
            return state.ok_or_else(|| anyhow::anyhow!("snapshot metadata absent"));
        }
        anyhow::ensure!(
            size <= MAX_RECORD as u64,
            "snapshot record exceeds byte limit"
        );
        let mut bytes = vec![0; size as usize];
        reader.read_exact(&mut bytes)?;
        digest.update(length);
        digest.update(&bytes);
        total = total
            .checked_add(8)
            .and_then(|n| n.checked_add(size))
            .ok_or_else(|| anyhow::anyhow!("snapshot byte overflow"))?;
        count = count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("snapshot record count overflow"))?;
        let record: Record = serde_json::from_slice(&bytes)?;
        let mut canonical = Bounded(Vec::new());
        serde_json::to_writer(&mut canonical, &record)?;
        anyhow::ensure!(canonical.0 == bytes, "noncanonical snapshot record");
        let order = record.order();
        anyhow::ensure!(
            previous.as_ref().is_none_or(|p| p < &order),
            "snapshot records duplicated or unordered"
        );
        previous = Some(order);
        if let Record::Header(header) = record {
            anyhow::ensure!(
                state.is_none() && empty_records(&header),
                "snapshot header contains embedded records"
            );
            state = Some(*header);
            continue;
        }
        let state = state
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("snapshot metadata must be first"))?;
        match record {
            Record::Header(_) => unreachable!(),
            Record::Lineage(i, link) => {
                anyhow::ensure!(
                    i == state.restore_lineage.len() as u64,
                    "lineage sequence differs"
                );
                state.restore_lineage.push(link);
            }
            Record::Collection(k, collection) => {
                anyhow::ensure!(
                    collection.documents.is_empty() && collection.archived_documents.is_empty(),
                    "collection contains embedded documents"
                );
                state.collections.insert(k, collection);
            }
            Record::Document(k, document) => {
                state
                    .collections
                    .get_mut(&k)
                    .ok_or_else(|| anyhow::anyhow!("document collection missing"))?
                    .documents
                    .insert(document.id.clone(), document);
            }
            Record::Archived(k, id, reference) => {
                state
                    .collections
                    .get_mut(&k)
                    .ok_or_else(|| anyhow::anyhow!("archive collection missing"))?
                    .archived_documents
                    .insert(id, reference);
            }
            Record::Receipt(k, receipt) => {
                state.receipts.insert(k, receipt);
            }
            Record::Stage(k, stage) => {
                anyhow::ensure!(stage.chunks.is_empty(), "stage contains embedded chunks");
                state.staged_transactions.insert(k, stage);
            }
            Record::StageChunk(k, i, chunk) => {
                state
                    .staged_transactions
                    .get_mut(&k)
                    .ok_or_else(|| anyhow::anyhow!("stage missing"))?
                    .chunks
                    .insert(i, chunk);
            }
            Record::ActiveStage(k) => {
                state.active_staged_transactions.insert(k);
            }
            Record::Change(i, commit) => {
                anyhow::ensure!(
                    commit.records.is_empty(),
                    "change commit contains embedded records"
                );
                state.change_feed.commits.insert(i, commit);
            }
            Record::ChangeItem(i, index, change) => {
                let commit = state
                    .change_feed
                    .commits
                    .get_mut(&i)
                    .ok_or_else(|| anyhow::anyhow!("change commit missing"))?;
                let commit = Arc::make_mut(commit);
                anyhow::ensure!(
                    index == commit.records.len() as u64,
                    "change record sequence differs"
                );
                commit.records.push(change);
            }
            Record::Archive(k, archive) => {
                state.history_archives.insert(k, archive);
            }
            Record::Activation(k, activation) => {
                state.schema_activations.insert(k, activation);
            }
            Record::Retirement(k, retirement) => {
                state.retirements.insert(k, *retirement);
            }
            Record::Audit(i, event) => {
                anyhow::ensure!(i == state.audits.len() as u64, "audit sequence differs");
                state.audits.push_back(event);
            }
            Record::Intent(id, intent) => {
                state
                    .lifecycle_control
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("control installation missing"))?
                    .intents
                    .insert(id, intent);
            }
            Record::ControlChange(id, change) => {
                state
                    .lifecycle_control
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("control installation missing"))?
                    .changes
                    .insert(id, change);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> TenantState {
        crate::TenantEngine::new(
            "tenant".into(),
            "generation".into(),
            Policy {
                grants: vec![Grant {
                    principal: "owner".into(),
                    collection: None,
                    actions: [Action::Admin].into_iter().collect(),
                }],
                strict_read_audit: false,
            },
            Limits::default(),
        )
        .unwrap()
        .generation()
        .unwrap()
        .state
        .clone()
    }
    #[test]
    fn canonical_stream_requires_terminal_counts_digest_and_exact_eof() {
        let state = state();
        let mut bytes = Vec::new();
        write(&state, &mut bytes).unwrap();
        let decoded = read(&mut bytes.as_slice()).unwrap();
        assert_eq!(
            serde_json::to_vec(&state).unwrap(),
            serde_json::to_vec(&decoded).unwrap()
        );
        for index in [
            0,
            7,
            8,
            15,
            bytes.len() - 57,
            bytes.len() - 49,
            bytes.len() - 33,
            bytes.len() - 1,
        ] {
            assert!(
                read(&mut &bytes[..index]).is_err(),
                "accepted truncation at {index}"
            );
            let mut corrupt = bytes.clone();
            corrupt[index] ^= 1;
            assert!(
                read(&mut corrupt.as_slice()).is_err(),
                "accepted corruption at {index}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(read(&mut trailing.as_slice()).is_err());
        assert!(
            read(&mut serde_json::to_vec(&state).unwrap().as_slice()).is_err(),
            "legacy JSON snapshots are forbidden"
        );
    }
    #[test]
    fn oversized_record_is_rejected_before_payload_read_or_allocation() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&((MAX_RECORD as u64) + 1).to_be_bytes());
        let error = read(&mut bytes.as_slice()).unwrap_err().to_string();
        assert!(error.contains("record exceeds"));
    }
    #[test]
    fn authenticated_duplicate_header_is_rejected() {
        let state = state();
        let record = serde_json::to_vec(&Record::Header(Box::new(state))).unwrap();
        let mut bytes = MAGIC.to_vec();
        for _ in 0..2 {
            bytes.extend_from_slice(&(record.len() as u64).to_be_bytes());
            bytes.extend_from_slice(&record);
        }
        let total = bytes.len() as u64;
        let digest = Sha256::digest(&bytes);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&2u64.to_be_bytes());
        bytes.extend_from_slice(&total.to_be_bytes());
        bytes.extend_from_slice(&digest);
        assert!(
            read(&mut bytes.as_slice())
                .unwrap_err()
                .to_string()
                .contains("unordered")
        );
    }
}
