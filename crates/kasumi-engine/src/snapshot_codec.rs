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

const MAGIC: &[u8; 8] = b"KASUMIT5";
const MAX_RECORD: usize = 32 << 20;
pub(crate) const RECORD_KINDS: u8 = 23;
pub(crate) const FRAME_HEADER_BYTES: usize = 9;
#[path = "snapshot_record_work.rs"]
mod record_work;

pub(crate) fn record_limit(kind: u8) -> anyhow::Result<u64> {
    Ok(match kind {
        0..=20 => MAX_RECORD as u64,
        21 => crate::staged_terminal::MAX_SNAPSHOT_RECORD_BYTES as u64,
        22 => crate::target_resolution::MAX_SNAPSHOT_RECORD_BYTES as u64,
        _ => anyhow::bail!("unsupported snapshot record kind"),
    })
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "value", deny_unknown_fields)]
pub(crate) enum Record {
    Header(Box<TenantState>),
    Lineage(u64, RestoreLineageLink),
    Collection(String, CollectionState),
    Document(String, Arc<Document>),
    Archived(String, String, Arc<ArchivedDocument>),
    Receipt(String, StoredReceipt),
    Stage(String, StagedTransaction),
    StageChunk(String, usize, Arc<StagedChunk>),
    ActiveStage(String),
    Change(u64, Arc<ChangeCommit>),
    ChangeItem(u64, u64, ChangeRecord),
    Archive(String, Arc<RetainedHistoryArchive>),
    Activation(String, StoredSchemaActivation),
    Retirement(String, Box<StoredRetirement>),
    Audit(u64, AuditEvent),
    Intent(uuid::Uuid, LifecycleIntent),
    ControlChange(uuid::Uuid, ControlPolicyChange),
    Target(String, Box<TargetExecutionState>),
    RecoveryOperation(String, Box<RecoveryRecord>),
    RecoveryPhase(String, Box<RecoveryPhaseRecord>),
    RecoveryTarget(String, uuid::Uuid),
    Terminal(Box<crate::staged_terminal::Row>),
    TargetResolution(Box<crate::target_resolution::Row>),
}
impl Record {
    pub(crate) fn order(&self) -> (u8, String, String) {
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
            Self::Target(k, _) => (17, k.clone(), String::new()),
            Self::RecoveryOperation(k, _) => (18, k.clone(), String::new()),
            Self::RecoveryPhase(k, _) => (19, k.clone(), String::new()),
            Self::RecoveryTarget(k, _) => (20, k.clone(), String::new()),
            Self::Terminal(row) => (21, format!("{:020}", row.ordinal), String::new()),
            Self::TargetResolution(row) => (22, format!("{:020}", row.ordinal), String::new()),
        }
    }
}

/// Borrow resident persistent roots, emitting one bounded record at a time. The
/// same semantic record projection is used by portable snapshots and closures.
pub(crate) fn records<'a>(
    state: &'a TenantState,
    kind: u8,
    primary: Option<&str>,
) -> anyhow::Result<Box<dyn Iterator<Item = anyhow::Result<Record>> + Send + 'a>> {
    if kind == 14 {
        let primary = primary.map(str::to_owned);
        return Ok(Box::new(
            state
                .audits
                .iter()
                .enumerate()
                .map(move |(i, event)| {
                    let sequence = state
                        .audit_retention
                        .pruned_before
                        .checked_add(i as u64)
                        .ok_or_else(|| anyhow::anyhow!("audit sequence overflow"))?;
                    Ok(Record::Audit(sequence, event.clone()))
                })
                .filter(move |record| {
                    record.as_ref().map_or(true, |record| {
                        primary.as_ref().is_none_or(|p| &record.order().1 == p)
                    })
                }),
        ));
    }
    let collections: Box<dyn Iterator<Item = (&'a String, &'a CollectionState)> + Send + 'a> =
        match primary {
            Some(name) => Box::new(state.collections.get_key_value(name).into_iter()),
            None => Box::new(state.collections.iter()),
        };
    let primary = primary.map(str::to_owned);
    let records: Box<dyn Iterator<Item = Record> + Send + 'a> =
        match kind {
            0 => Box::new(std::iter::once(Record::Header(Box::new(metadata(state))))),
            1 => Box::new(
                state
                    .restore_lineage
                    .iter()
                    .enumerate()
                    .map(|(i, link)| Record::Lineage(i as u64, link.clone())),
            ),
            2 => Box::new(collections.map(|(name, collection)| {
                Record::Collection(
                    name.clone(),
                    CollectionState {
                        definition: collection.definition.clone(),
                        data_epoch: collection.data_epoch,
                        documents: Default::default(),
                        archived_documents: Default::default(),
                        archived_document_bytes: collection.archived_document_bytes,
                    },
                )
            })),
            3 => Box::new(collections.flat_map(|(name, collection)| {
                collection
                    .documents
                    .values()
                    .map(move |document| Record::Document(name.clone(), document.clone()))
            })),
            4 => Box::new(collections.flat_map(|(name, collection)| {
                collection
                    .archived_documents
                    .iter()
                    .map(move |(id, reference)| {
                        Record::Archived(name.clone(), id.clone(), reference.clone())
                    })
            })),
            5 => Box::new(
                state
                    .receipts
                    .iter()
                    .map(|(key, value)| Record::Receipt(key.clone(), value.clone())),
            ),
            6 => Box::new(state.staged_transactions.iter().map(|(key, value)| {
                let mut header = value.clone();
                header.chunks.clear();
                Record::Stage(key.clone(), header)
            })),
            7 => Box::new(state.staged_transactions.iter().flat_map(|(key, value)| {
                value
                    .chunks
                    .iter()
                    .map(move |(i, chunk)| Record::StageChunk(key.clone(), *i, chunk.clone()))
            })),
            8 => Box::new(
                state
                    .active_staged_transactions
                    .iter()
                    .map(|key| Record::ActiveStage(key.clone())),
            ),
            9 => Box::new(state.change_feed.commits.iter().map(|(i, value)| {
                let mut header = value.as_ref().clone();
                header.records.clear();
                Record::Change(*i, Arc::new(header))
            })),
            10 => Box::new(
                state
                    .change_feed
                    .commits
                    .iter()
                    .flat_map(|(sequence, commit)| {
                        commit.records.iter().enumerate().map(move |(i, record)| {
                            Record::ChangeItem(*sequence, i as u64, record.clone())
                        })
                    }),
            ),
            11 => Box::new(
                state
                    .history_archives
                    .iter()
                    .map(|(key, value)| Record::Archive(key.clone(), value.clone())),
            ),
            12 => Box::new(
                state
                    .schema_activations
                    .iter()
                    .map(|(key, value)| Record::Activation(key.clone(), value.clone())),
            ),
            13 => Box::new(
                state
                    .retirements
                    .iter()
                    .map(|(key, value)| Record::Retirement(key.clone(), Box::new(value.clone()))),
            ),
            15 => Box::new(state.lifecycle_control.iter().flat_map(|state| {
                state
                    .intents
                    .iter()
                    .map(|(key, value)| Record::Intent(*key, value.clone()))
            })),
            16 => Box::new(state.lifecycle_control.iter().flat_map(|state| {
                state
                    .changes
                    .iter()
                    .map(|(key, value)| Record::ControlChange(*key, value.clone()))
            })),
            17 => Box::new(
                state
                    .target_lifecycle
                    .iter()
                    .map(|(key, value)| Record::Target(key.clone(), Box::new(value.clone()))),
            ),
            18 => Box::new(
                state
                    .recovery_control
                    .operations
                    .iter()
                    .map(|(key, value)| {
                        Record::RecoveryOperation(key.clone(), Box::new(value.clone()))
                    }),
            ),
            19 => {
                Box::new(state.recovery_control.phases.iter().map(|(key, value)| {
                    Record::RecoveryPhase(key.clone(), Box::new(value.clone()))
                }))
            }
            20 => Box::new(
                state
                    .recovery_control
                    .targets
                    .iter()
                    .map(|(key, value)| Record::RecoveryTarget(key.clone(), *value)),
            ),
            _ => anyhow::bail!("unsupported snapshot record kind"),
        };
    Ok(Box::new(
        records
            .filter(move |record| primary.as_ref().is_none_or(|p| &record.order().1 == p))
            .map(Ok),
    ))
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
        target_lifecycle: Default::default(),
        recovery_control: Default::default(),
        document_count: state.document_count,
        logical_bytes: state.logical_bytes,
        policy: state.policy.clone(),
        limits: state.limits.clone(),
        collections: Default::default(),
        receipts: Default::default(),
        staged_transactions: Default::default(),
        active_staged_transactions: Default::default(),
        permanent_staged_bytes: state.permanent_staged_bytes,
        reserved_staged_terminal_bytes: state.reserved_staged_terminal_bytes,
        staged_terminal_head: state.staged_terminal_head.clone(),
        target_resolution_head: state.target_resolution_head.clone(),
        target_completion_head: state.target_completion_head.clone(),
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
        audit_retention: state.audit_retention.clone(),
        audits: Default::default(),
    }
}
fn empty_records(state: &TenantState) -> bool {
    state.target_lifecycle.is_empty()
        && state.recovery_control.is_empty()
        && state.collections.is_empty()
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

pub(crate) struct Encoder<'a> {
    writer: &'a mut dyn Write,
    digest: Sha256,
    count: u64,
    total: u64,
    previous: Option<(u8, String, String)>,
}
impl<'a> Encoder<'a> {
    pub(crate) fn new(writer: &'a mut dyn Write) -> anyhow::Result<Self> {
        writer.write_all(MAGIC)?;
        let mut digest = Sha256::new();
        digest.update(MAGIC);
        Ok(Self {
            writer,
            digest,
            count: 0,
            total: 8,
            previous: None,
        })
    }
    pub(crate) fn record(&mut self, record: Record) -> anyhow::Result<()> {
        let key = record.order();
        let kind = key.0;
        anyhow::ensure!(
            self.previous
                .as_ref()
                .is_none_or(|previous| previous < &key),
            "snapshot records duplicated or unordered"
        );
        self.previous = Some(key);
        let mut buffer = Bounded(Vec::new());
        serde_json::to_writer(&mut buffer, &record)?;
        anyhow::ensure!(
            buffer.0.len() as u64 <= record_limit(kind)?,
            "snapshot typed record exceeds byte limit"
        );
        let length = (buffer.0.len() as u64).to_be_bytes();
        self.writer.write_all(&length)?;
        self.writer.write_all(&[kind])?;
        self.writer.write_all(&buffer.0)?;
        self.digest.update(length);
        self.digest.update([kind]);
        self.digest.update(&buffer.0);
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("snapshot record count overflow"))?;
        self.total = self
            .total
            .checked_add(FRAME_HEADER_BYTES as u64)
            .and_then(|n| n.checked_add(buffer.0.len() as u64))
            .ok_or_else(|| anyhow::anyhow!("snapshot byte overflow"))?;
        Ok(())
    }
    pub(crate) fn finish(self) -> anyhow::Result<()> {
        self.writer.write_all(&0u64.to_be_bytes())?;
        self.writer.write_all(&self.count.to_be_bytes())?;
        self.writer.write_all(&self.total.to_be_bytes())?;
        self.writer.write_all(&self.digest.finalize())?;
        Ok(())
    }
}
pub(crate) fn write(
    state: &TenantState,
    terminals: &crate::staged_terminal::View,
    target_resolutions: &crate::target_resolution::View,
    writer: &mut dyn Write,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        terminals.head() == &state.staged_terminal_head,
        "snapshot terminal owner differs"
    );
    terminals.check_head(&state.tenant)?;
    target_resolutions.validate_state(state)?;
    let mut encoder = Encoder::new(writer)?;
    for kind in 0..21 {
        for record in records(state, kind, None)? {
            encoder.record(record?)?;
        }
    }
    for row in terminals.records() {
        encoder.record(Record::Terminal(Box::new(row?)))?;
    }
    for row in target_resolutions.records() {
        encoder.record(Record::TargetResolution(Box::new(row?)))?;
    }
    encoder.finish()
}

/// Positions address payload bytes in the immutable, authenticated image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecordPosition {
    pub offset: u64,
    pub bytes: u64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct KindLayout {
    pub records: u64,
    pub framed_bytes: u64,
    pub maximum_payload_bytes: u64,
    pub maximum_decode_work: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StreamSummary {
    pub records: u64,
    pub bytes: u64,
    pub kinds: [KindLayout; RECORD_KINDS as usize],
}
impl StreamSummary {
    fn empty() -> Self {
        Self {
            records: 0,
            bytes: 8,
            kinds: [KindLayout::default(); RECORD_KINDS as usize],
        }
    }
    fn add(&mut self, kind: u8, payload: u64) -> anyhow::Result<()> {
        anyhow::ensure!(
            payload > 0 && payload <= record_limit(kind)?,
            "snapshot typed record exceeds byte limit"
        );
        let framed = payload
            .checked_add(FRAME_HEADER_BYTES as u64)
            .ok_or_else(|| anyhow::anyhow!("snapshot framing overflow"))?;
        let selected = &mut self.kinds[usize::from(kind)];
        selected.records = selected
            .records
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("snapshot kind count overflow"))?;
        selected.framed_bytes = selected
            .framed_bytes
            .checked_add(framed)
            .ok_or_else(|| anyhow::anyhow!("snapshot kind bytes overflow"))?;
        selected.maximum_payload_bytes = selected.maximum_payload_bytes.max(payload);
        self.records = self
            .records
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("snapshot record count overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(framed)
            .ok_or_else(|| anyhow::anyhow!("snapshot byte overflow"))?;
        Ok(())
    }
    fn record_work(&mut self, kind: u8, work: u64) -> anyhow::Result<()> {
        let selected = self
            .kinds
            .get_mut(usize::from(kind))
            .ok_or_else(|| anyhow::anyhow!("unsupported snapshot record kind"))?;
        selected.maximum_decode_work = selected.maximum_decode_work.max(work);
        Ok(())
    }
    /// Resident semantic records and fixed stream framing, excluding encrypted
    /// permanent point rows. This is not an allocator or hard-RSS measurement.
    pub(crate) fn resident_bytes(&self) -> anyhow::Result<u64> {
        self.kinds[..21].iter().try_fold(64u64, |total, kind| {
            total
                .checked_add(kind.framed_bytes)
                .ok_or_else(|| anyhow::anyhow!("resident snapshot byte overflow"))
        })
    }
    /// Two bounded encrypted indexes and metadata retain their existing cache
    /// floor. Add peak structural decode work before inspecting semantic DTOs.
    pub(crate) fn index_workspace(&self) -> anyhow::Result<u64> {
        (128u64 << 20)
            .checked_add(self.maximum_decode_work())
            .ok_or_else(|| anyhow::anyhow!("snapshot index workspace overflow"))
    }
    fn maximum_decode_work(&self) -> u64 {
        self.kinds
            .iter()
            .map(|kind| kind.maximum_decode_work)
            .max()
            .unwrap_or(0)
    }
    /// Resident/index estimate plus structurally accounted peak typed decode
    /// work. Permanent table length consumes scratch, never this RAM estimate.
    /// See `record_work` for the explicit model; neither term measures hard RSS.
    pub(crate) fn materialization_workspace(&self) -> anyhow::Result<u64> {
        let record = self.maximum_decode_work();
        self.resident_bytes()?
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(record))
            .and_then(|bytes| bytes.checked_add(64 << 20))
            .ok_or_else(|| anyhow::anyhow!("snapshot materialization workspace overflow"))
    }
}

fn finish_summary(
    reader: &mut dyn Read,
    digest: Sha256,
    mut summary: StreamSummary,
) -> anyhow::Result<StreamSummary> {
    let mut footer = [0; 48];
    reader.read_exact(&mut footer)?;
    anyhow::ensure!(
        summary.records > 0
            && u64::from_be_bytes(footer[..8].try_into()?) == summary.records
            && u64::from_be_bytes(footer[8..16].try_into()?) == summary.bytes
            && digest.finalize().as_slice() == &footer[16..],
        "snapshot terminal authentication differs"
    );
    anyhow::ensure!(reader.read(&mut [0])? == 0, "trailing snapshot data");
    summary.bytes = summary
        .bytes
        .checked_add(56)
        .ok_or_else(|| anyhow::anyhow!("snapshot byte overflow"))?;
    Ok(summary)
}

/// Authenticate typed framing with fixed scratch before allocating any JSON
/// record. Kind hints determine admission only; `visit` must independently bind
/// every hint to its actual decoded enum before forwarding a semantic record.
pub(crate) fn inspect(reader: &mut dyn Read) -> anyhow::Result<StreamSummary> {
    let mut magic = [0; 8];
    reader.read_exact(&mut magic)?;
    anyhow::ensure!(&magic == MAGIC, "unsupported tenant snapshot format");
    let mut hash = Sha256::new();
    hash.update(magic);
    let mut summary = StreamSummary::empty();
    let mut previous = 0;
    let mut buffer = [0; 64 << 10];
    loop {
        let mut length = [0; 8];
        reader.read_exact(&mut length)?;
        let bytes = u64::from_be_bytes(length);
        if bytes == 0 {
            return finish_summary(reader, hash, summary);
        }
        let mut kind = [0];
        reader.read_exact(&mut kind)?;
        anyhow::ensure!(
            (summary.records == 0 && kind[0] == 0)
                || (summary.records > 0 && kind[0] > 0 && kind[0] >= previous),
            "snapshot typed frames duplicated or unordered"
        );
        summary.add(kind[0], bytes)?;
        previous = kind[0];
        hash.update(length);
        hash.update(kind);
        let mut remaining = bytes;
        let mut work = record_work::Meter::default();
        while remaining != 0 {
            let take = usize::try_from(remaining.min(buffer.len() as u64))?;
            reader.read_exact(&mut buffer[..take])?;
            hash.update(&buffer[..take]);
            work.consume(&buffer[..take])?;
            remaining -= take as u64;
        }
        summary.record_work(kind[0], work.finish()?)?;
    }
}

/// Visit canonical records without retaining preceding records. Successful return
/// proves framing, canonical encoding, strict order, terminal authentication and
/// contiguous lineage/audit sequences. Cross-record semantic checks belong to the
/// caller; observing a record before the terminal proof never authorizes publish.
pub(crate) fn visit(
    reader: &mut dyn Read,
    mut visitor: impl FnMut(RecordPosition, Record) -> anyhow::Result<()>,
) -> anyhow::Result<StreamSummary> {
    let mut magic = [0; 8];
    reader.read_exact(&mut magic)?;
    anyhow::ensure!(&magic == MAGIC, "unsupported tenant snapshot format");
    let mut digest = Sha256::new();
    digest.update(magic);
    let mut summary = StreamSummary::empty();
    let mut previous = None;
    let mut lineage = 0u64;
    let mut audit = None;
    let mut audit_next = 0u64;
    loop {
        let mut length = [0; 8];
        reader.read_exact(&mut length)?;
        let size = u64::from_be_bytes(length);
        if size == 0 {
            anyhow::ensure!(audit == Some(audit_next), "audit final sequence differs");
            return finish_summary(reader, digest, summary);
        }
        let mut kind = [0];
        reader.read_exact(&mut kind)?;
        anyhow::ensure!(
            size <= record_limit(kind[0])?,
            "snapshot typed record exceeds byte limit"
        );
        let position = RecordPosition {
            offset: summary
                .bytes
                .checked_add(FRAME_HEADER_BYTES as u64)
                .ok_or_else(|| anyhow::anyhow!("snapshot offset overflow"))?,
            bytes: size,
        };
        let mut bytes = vec![0; size as usize];
        reader.read_exact(&mut bytes)?;
        digest.update(length);
        digest.update(kind);
        digest.update(&bytes);
        let work = record_work::measure(&bytes)?;
        let record = decode_record(&bytes)?;
        let order = record.order();
        anyhow::ensure!(
            order.0 == kind[0],
            "snapshot frame kind differs from decoded record"
        );
        // Only a matching typed payload can spend its declared class's budget
        // or reach a caller that builds resident state / permanent tables.
        summary.add(kind[0], size)?;
        summary.record_work(kind[0], work)?;
        anyhow::ensure!(
            previous.as_ref().is_none_or(|p| p < &order),
            "snapshot records duplicated or unordered"
        );
        previous = Some(order);
        match &record {
            Record::Header(header) => {
                anyhow::ensure!(
                    summary.records == 1 && empty_records(header),
                    "snapshot header contains embedded records"
                );
                header.audit_retention.validate()?;
                audit = Some(header.audit_retention.pruned_before);
                audit_next = header.audit_retention.next_sequence;
            }
            _ if audit.is_none() => anyhow::bail!("snapshot metadata must be first"),
            Record::Lineage(i, _) => {
                anyhow::ensure!(*i == lineage, "lineage sequence differs");
                lineage = lineage
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("lineage sequence overflow"))?;
            }
            Record::Audit(i, _) => {
                anyhow::ensure!(Some(*i) == audit, "audit sequence differs");
                audit = Some(
                    i.checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("audit sequence overflow"))?,
                );
            }
            Record::Collection(_, collection) => anyhow::ensure!(
                collection.documents.is_empty() && collection.archived_documents.is_empty(),
                "collection contains embedded documents"
            ),
            Record::Stage(_, stage) => {
                anyhow::ensure!(stage.chunks.is_empty(), "stage contains embedded chunks")
            }
            Record::Terminal(row) => anyhow::ensure!(
                row.ordinal > 0 && !row.stage.is_active() && row.stage.chunks.is_empty(),
                "invalid terminal staged record"
            ),
            Record::TargetResolution(row) => {
                row.record.validate()?;
                row.framed_bytes()?;
            }
            Record::Change(_, commit) => anyhow::ensure!(
                commit.records.is_empty(),
                "change commit contains embedded records"
            ),
            Record::RecoveryOperation(key, value) => {
                value.validate()?;
                anyhow::ensure!(
                    *key == value.request.operation_id.to_string(),
                    "recovery operation key differs"
                );
            }
            Record::RecoveryPhase(key, value) => {
                value.validate()?;
                anyhow::ensure!(
                    *key == value.phase_id.to_string(),
                    "recovery phase key differs"
                );
            }
            Record::RecoveryTarget(key, operation) => {
                let id = uuid::Uuid::parse_str(key)?;
                anyhow::ensure!(
                    !id.is_nil() && id.to_string() == *key && !operation.is_nil(),
                    "recovery target key differs"
                );
            }
            _ => {}
        }
        // The raw bytes are no longer retained while semantic/index consumers run.
        drop(bytes);
        visitor(position, record)?;
    }
}

/// Compare canonical encoding as it is emitted, without a second record buffer.
fn decode_record(bytes: &[u8]) -> anyhow::Result<Record> {
    struct Compare<'a>(&'a [u8]);
    impl Write for Compare<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.0.starts_with(bytes) {
                return Err(std::io::Error::other("noncanonical snapshot record"));
            }
            self.0 = &self.0[bytes.len()..];
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let record: Record = serde_json::from_slice(bytes)?;
    let mut canonical = Compare(bytes);
    serde_json::to_writer(&mut canonical, &record)?;
    anyhow::ensure!(canonical.0.is_empty(), "noncanonical snapshot record");
    Ok(record)
}

#[derive(Clone)]
pub(crate) struct Decoded {
    pub(crate) state: TenantState,
    pub(crate) summary: StreamSummary,
    pub(crate) terminals: crate::staged_terminal::View,
    pub(crate) target_resolutions: crate::target_resolution::View,
}
pub(crate) fn read(
    disk: &Arc<kasumi_store::ScratchDisk>,
    reader: &mut dyn Read,
) -> anyhow::Result<Decoded> {
    let mut state: Option<TenantState> = None;
    let mut terminals: Option<crate::staged_terminal::Builder> = None;
    let mut target_resolutions: Option<crate::target_resolution::Builder> = None;
    let summary = visit(reader, |_, record| {
        if let Record::Header(header) = record {
            anyhow::ensure!(
                state.is_none() && empty_records(&header),
                "snapshot header contains embedded records"
            );
            if header.target_resolution_head.count > 0 {
                target_resolutions = Some(crate::target_resolution::Builder::new(
                    disk,
                    crate::target_resolution::scratch_limit(
                        header.limits.max_target_resolution_bytes,
                    )?,
                    &header.tenant,
                    &header.target_resolution_head.origin_incarnation,
                )?);
            }
            if header.staged_terminal_head.count > 0 {
                terminals = Some(crate::staged_terminal::Builder::new(
                    disk,
                    crate::staged_terminal::scratch_limit(header.limits.max_snapshot_bytes)?,
                    &header.tenant,
                    &header.staged_terminal_head.origin_incarnation,
                )?);
            }
            state = Some(*header);
            return Ok(());
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
                anyhow::ensure!(
                    stage.is_active() && stage.chunks.is_empty(),
                    "resident stage must be an active upload header"
                );
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
                anyhow::ensure!(
                    Some(i)
                        == state
                            .audit_retention
                            .pruned_before
                            .checked_add(state.audits.len() as u64),
                    "audit sequence differs"
                );
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
            Record::Target(key, target) => {
                state.target_lifecycle.insert(key, *target);
            }
            Record::RecoveryOperation(key, record) => {
                anyhow::ensure!(
                    state.tenant == crate::control::CONTROL_TENANT
                        && state.lifecycle_control.is_some(),
                    "recovery coordinator requires installed Control state"
                );
                state.recovery_control.operations.insert(key, *record);
            }
            Record::RecoveryPhase(key, record) => {
                anyhow::ensure!(
                    state
                        .recovery_control
                        .operations
                        .contains_key(&record.operation_id.to_string()),
                    "recovery phase operation missing"
                );
                state.recovery_control.phases.insert(key, *record);
            }
            Record::RecoveryTarget(key, operation) => {
                anyhow::ensure!(
                    state
                        .recovery_control
                        .operations
                        .contains_key(&operation.to_string()),
                    "recovery target operation missing"
                );
                state.recovery_control.targets.insert(key, operation);
            }
            Record::Terminal(row) => {
                anyhow::ensure!(
                    !state.staged_transactions.contains_key(&row.key),
                    "staged identity is both active and terminal"
                );
                terminals
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("terminal stream header missing"))?
                    .push(&row, state)?;
            }
            Record::TargetResolution(row) => {
                target_resolutions
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("target resolution rows without header"))?
                    .push(&row, state)?;
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
        Ok(())
    })?;
    let state = state.ok_or_else(|| anyhow::anyhow!("snapshot metadata absent"))?;
    let terminals = match terminals {
        Some(builder) => builder.finish(&state.staged_terminal_head)?,
        None => {
            let empty = crate::staged_terminal::View::empty(
                &state.tenant,
                &state.staged_terminal_head.origin_incarnation,
            )?;
            anyhow::ensure!(
                empty.head() == &state.staged_terminal_head,
                "empty terminal descriptor differs"
            );
            empty
        }
    };
    let target_resolutions = match target_resolutions {
        Some(builder) => builder.finish(&state)?,
        None => {
            let empty = crate::target_resolution::View::empty(
                &state.tenant,
                &state.target_resolution_head.origin_incarnation,
            )?;
            anyhow::ensure!(
                empty.head() == &state.target_resolution_head,
                "empty target terminal descriptor differs"
            );
            empty
        }
    };
    Ok(Decoded {
        state,
        summary,
        terminals,
        target_resolutions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn write(state: &TenantState, writer: &mut dyn Write) -> anyhow::Result<()> {
        super::write(
            state,
            &crate::staged_terminal::View::empty(&state.tenant, &state.incarnation)?,
            &crate::target_resolution::View::empty(&state.tenant, &state.incarnation)?,
            writer,
        )
    }
    fn read(reader: &mut dyn Read) -> anyhow::Result<TenantState> {
        Ok(super::read(&kasumi_store::ScratchDisk::fixture(), reader)?.state)
    }
    pub(super) fn state() -> TenantState {
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
        bytes.push(0);
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
            bytes.push(0);
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
    #[test]
    fn archived_audit_prefix_preserves_absolute_sequences_and_head() {
        let mut state = state();
        let stream_id = state.audit_retention.stream_id;
        let head = AuditArchiveReference {
            stream_id,
            object: AuditArchiveLink {
                object_id: uuid::Uuid::new_v4(),
                first_sequence: 0,
                next_sequence: 23,
                ciphertext_sha256: "a".repeat(64),
            },
            previous: None,
            record_count: 23,
            plaintext_bytes: 100,
            ciphertext_bytes: 300,
            key: AuditArchiveKeyDependency {
                provider: "file".into(),
                key_ref: "audit-key".into(),
                version: 1,
                wrapped_key_sha256: "b".repeat(64),
            },
        };
        state.audit_retention.next_sequence = 23;
        state.audit_retention.pruned_before = 23;
        state.audit_retention.archive_bytes = head.ciphertext_bytes;
        state.audit_retention.archive_segments = 1;
        state.audit_retention.archive_head = Some(head.clone());
        crate::state::append_audit(
            &mut state,
            AuditEvent {
                event_id: "after-archive".into(),
                principal: "owner".into(),
                action: "read".into(),
                request_id: "req".into(),
                timestamp_ms: 123,
                data_revision: None,
                outcome: "success".into(),
                collection: None,
            },
        )
        .unwrap();
        let mut bytes = Vec::new();
        write(&state, &mut bytes).unwrap();
        assert_eq!(
            crate::accounting::SnapshotAccounting::rebuild(&state)
                .unwrap()
                .bytes(&state)
                .unwrap(),
            bytes.len()
        );
        let restored = read(&mut bytes.as_slice()).unwrap();
        assert_eq!(restored.audit_retention.next_sequence, 24);
        assert_eq!(restored.audit_retention.pruned_before, 23);
        assert_eq!(restored.audit_retention.archive_head, Some(head));
        assert_eq!(restored.audits.len(), 1);
        state.audit_retention.next_sequence = 25;
        bytes.clear();
        write(&state, &mut bytes).unwrap();
        assert!(read(&mut bytes.as_slice()).is_err());
    }
}

#[cfg(test)]
#[path = "snapshot_recovery_tests.rs"]
mod recovery_tests;

#[cfg(test)]
#[path = "snapshot_literal_tests.rs"]
mod literal_tests;

#[cfg(test)]
#[path = "snapshot_frame_tests.rs"]
mod frame_tests;
