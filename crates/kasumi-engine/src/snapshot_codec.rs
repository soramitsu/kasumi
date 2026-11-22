//! Canonical tenant snapshots consist of independently bounded semantic records.
//! The decoder builds unpublished state one record at a time and accepts it only
//! after checking strict record ordering, counts, byte totals, digest, and EOF.
use crate::state::snapshot_validation::VerifiedRecords;
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    sync::Arc,
};

const MAGIC: &[u8; 8] = b"KASUMIT8";
const MAX_RECORD: usize = 32 << 20;
pub(crate) const RECORD_KINDS: u8 = 26;
pub(crate) const FRAME_HEADER_BYTES: usize = 9;
#[path = "snapshot_record_work.rs"]
mod record_work;

/// Reuse the same structural model for external authenticated history bodies.
/// Check the original operation between bounded slices before allocating DTOs.
pub(crate) fn inspect_external_json_work(
    bytes: &[u8],
    check: &mut dyn FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<u64> {
    let mut meter = record_work::Meter::default();
    for chunk in bytes.chunks(64 << 10) {
        check()?;
        meter.consume(chunk)?;
    }
    check()?;
    meter.finish()
}

/// Count owned typed metadata through the same structural model without a JSON
/// buffer. Callers borrow the input until this check admits its later clones.
pub(crate) fn inspect_typed_json_work(value: &impl Serialize) -> anyhow::Result<u64> {
    Ok(measure_typed_json(value, |_| {})?.1)
}

/// Measure exact canonical byte length and structural work in one streaming
/// pass. An observer can hash the same bytes without serializing the input again.
pub(crate) fn measure_typed_json(
    value: &impl Serialize,
    observe: impl FnMut(&[u8]),
) -> anyhow::Result<(u64, u64)> {
    measure_with_meter(value, observe, record_work::Meter::default())
}

/// The structural charge is additive in sites, scalar bytes and wire bytes.
/// Replace the exact charge and length of a null body in the real DTO with
/// those of the measured body. Preserve the depth consumed by the DTO itself.
pub(crate) fn measure_document_json(
    document: &Document,
    observe_body: impl FnMut(&[u8]),
) -> anyhow::Result<((u64, u64), (u64, u64))> {
    let body = measure_with_meter(
        &CanonicalJsonValue(&document.body),
        observe_body,
        record_work::Meter::document_body(),
    )?;
    // A short body costs less to revisit than a second DTO with a null
    // placeholder. Both routes use the same serializer and structural meter.
    if body.0 <= 64 {
        return Ok((body, measure_typed_json(document, |_| {})?));
    }
    validate_name(&document.id)?;
    let frame = Document {
        id: document.id.clone(),
        version: document.version,
        body: serde_json::Value::Null,
    };
    let (frame_bytes, frame_work) = measure_typed_json(&frame, |_| {})?;
    let replace = |frame: u64, placeholder, actual| {
        frame
            .checked_sub(placeholder)
            .and_then(|n| n.checked_add(actual))
            .ok_or_else(|| anyhow::anyhow!("document measurement overflow"))
    };
    let bytes = replace(frame_bytes, 4, body.0)?;
    let work = replace(frame_work, record_work::measure(b"null")?, body.1)?;
    Ok((body, (bytes, work)))
}

fn measure_with_meter(
    value: &impl Serialize,
    observe: impl FnMut(&[u8]),
    meter: record_work::Meter,
) -> anyhow::Result<(u64, u64)> {
    struct Writer<F> {
        meter: record_work::Meter,
        observe: F,
    }
    impl<F: FnMut(&[u8])> Write for Writer<F> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.meter.consume(bytes).map_err(std::io::Error::other)?;
            (self.observe)(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer { meter, observe };
    serde_json::to_writer(&mut writer, value)?;
    let bytes = writer.meter.wire_bytes();
    Ok((bytes, writer.meter.finish()?))
}

pub(crate) fn record_limit(kind: u8) -> anyhow::Result<u64> {
    Ok(match kind {
        5 => crate::mutation_receipt::MAX_SNAPSHOT_RECORD_BYTES as u64,
        0..=20 | 23 => MAX_RECORD as u64,
        21 => crate::staged_terminal::MAX_SNAPSHOT_RECORD_BYTES as u64,
        22 => crate::target_resolution::MAX_SNAPSHOT_RECORD_BYTES as u64,
        24 => crate::backup_binding::MAX_SNAPSHOT_RECORD_BYTES as u64,
        25 => crate::backup_binding::intents::MAX_ROW as u64 + 256,
        _ => anyhow::bail!("unsupported snapshot record kind"),
    })
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "value", deny_unknown_fields)]
pub(crate) enum Record {
    Header(Box<TenantState>),
    Lineage(u64, RestoreLineageLink),
    Collection(String, CollectionState),
    Document(String, OwnedDocument),
    Archived(String, String, Arc<ArchivedDocument>),
    Receipt(Box<crate::mutation_receipt::Row>),
    Stage(String, StagedTransaction),
    StageChunk(String, usize, Arc<StagedChunk>),
    ActiveStage(String),
    Change(u64, Arc<ChangeCommit>),
    ChangeItem(u64, u64, WireChangeRecord),
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
    RecoveryCompletionHistory(String, Box<RecoveryCompletionHistory>),
    BackupBinding(Box<crate::backup_binding::Row>),
    LifecycleIntentHistory(Box<LifecycleIntentRow>),
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct WireChangeRecord {
    pub collection: String,
    pub id: String,
    pub document: Option<OwnedDocument>,
}
impl WireChangeRecord {
    pub(crate) fn from_record(
        record: &ChangeRecord,
        resolver: Option<&dyn DocumentResolver>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            collection: record.collection.clone(),
            id: record.id.clone(),
            document: record
                .document
                .as_ref()
                .map(|slot| slot.load_owned(resolver))
                .transpose()?,
        })
    }
}
impl Record {
    pub(crate) fn order(&self) -> (u8, String, String) {
        match self {
            Self::Header(_) => (0, String::new(), String::new()),
            Self::Lineage(i, _) => (1, format!("{i:020}"), String::new()),
            Self::Collection(k, _) => (2, k.clone(), String::new()),
            Self::Document(k, d) => (3, k.clone(), d.id.clone()),
            Self::Archived(k, id, _) => (4, k.clone(), id.clone()),
            Self::Receipt(row) => (5, format!("{:020}", row.ordinal), String::new()),
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
            Self::RecoveryCompletionHistory(k, _) => (23, k.clone(), String::new()),
            Self::LifecycleIntentHistory(row) => {
                (25, format!("{:020}", row.ordinal), String::new())
            }
            Self::BackupBinding(row) => (24, format!("{:020}", row.ordinal), String::new()),
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
    records_with_resolver(state, kind, primary, None)
}
pub(crate) fn records_with_resolver<'a>(
    state: &'a TenantState,
    kind: u8,
    primary: Option<&str>,
    resolver: Option<&'a dyn DocumentResolver>,
) -> anyhow::Result<Box<dyn Iterator<Item = anyhow::Result<Record>> + Send + 'a>> {
    if kind == 3 {
        let primary = primary.map(str::to_owned);
        return Ok(Box::new(
            state
                .collections
                .iter()
                .filter(move |(name, _)| primary.as_ref().is_none_or(|p| p == *name))
                .flat_map(move |(name, collection)| {
                    collection.documents.values().map(move |slot| {
                        Ok(Record::Document(name.clone(), slot.load_owned(resolver)?))
                    })
                }),
        ));
    }
    if kind == 10 {
        let primary = primary.map(str::to_owned);
        return Ok(Box::new(
            state
                .change_feed
                .commits
                .iter()
                .filter(move |(sequence, _)| {
                    primary
                        .as_ref()
                        .is_none_or(|p| p == &format!("{sequence:020}"))
                })
                .flat_map(move |(sequence, commit)| {
                    commit.records.iter().enumerate().map(move |(i, record)| {
                        Ok(Record::ChangeItem(
                            *sequence,
                            i as u64,
                            WireChangeRecord::from_record(record, resolver)?,
                        ))
                    })
                }),
        ));
    }
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
            3 => unreachable!("document loans handled above"),
            4 => Box::new(collections.flat_map(|(name, collection)| {
                collection
                    .archived_documents
                    .iter()
                    .map(move |(id, reference)| {
                        Record::Archived(name.clone(), id.clone(), reference.clone())
                    })
            })),
            5 | 24 | 25 => Box::new(std::iter::empty()), // Permanent rows require their selected owner.
            6 => Box::new(
                state
                    .staged_transactions
                    .iter()
                    .map(|(key, value)| Record::Stage(key.clone(), stage_header(value))),
            ),
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
                let header = change_header(value);
                Record::Change(*i, Arc::new(header))
            })),
            10 => unreachable!("change-feed loans handled above"),
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
            23 => Box::new(
                state
                    .recovery_control
                    .completion_history
                    .iter()
                    .map(|(key, value)| {
                        Record::RecoveryCompletionHistory(key.clone(), Box::new(value.clone()))
                    }),
            ),
            _ => anyhow::bail!("unsupported snapshot record kind"),
        };
    Ok(Box::new(
        records
            .filter(move |record| primary.as_ref().is_none_or(|p| &record.order().1 == p))
            .map(Ok),
    ))
}

/// Project a feed commit without retaining any of its separately emitted events.
pub(crate) fn change_header(commit: &ChangeCommit) -> ChangeCommit {
    ChangeCommit {
        revision: commit.revision,
        first_sequence: commit.first_sequence,
        records: Vec::new(),
        record_bytes: commit.record_bytes,
    }
}

/// Chunks are emitted independently. Project the header without copying the chunk map.
pub(crate) fn stage_header(value: &StagedTransaction) -> StagedTransaction {
    StagedTransaction {
        scope: value.scope.clone(),
        transaction_id: value.transaction_id.clone(),
        manifest_digest: value.manifest_digest.clone(),
        manifest: value.manifest.clone(),
        chunks: Default::default(),
        stored_chunk_bytes: value.stored_chunk_bytes,
        uploaded_payload_bytes: value.uploaded_payload_bytes,
        uploaded_operations: value.uploaded_operations,
        uploaded_read_assertions: value.uploaded_read_assertions,
        expires_at_ms: value.expires_at_ms,
        ttl_ms: value.ttl_ms,
        outcome: value.outcome.clone(),
    }
}

/// The header's copy of the Control state; intents and changes are records.
pub(crate) fn control_header(control: &LifecycleControlState) -> LifecycleControlState {
    LifecycleControlState {
        installation: control.installation.clone(),
        installation_command_id: control.installation_command_id,
        installation_revision: control.installation_revision,
        installation_policy_epoch: control.installation_policy_epoch,
        installation_policy: control.installation_policy.clone(),
        retired: control.retired,
        pending_change: control.pending_change,
        intent_head: control.intent_head.clone(),
        intent_source: Default::default(),
        pending_intent: None,
        intents: Default::default(),
        changes: Default::default(),
    }
}
pub(crate) fn metadata(state: &TenantState) -> TenantState {
    metadata_with_shared(
        state,
        state.policy.clone(),
        state
            .lifecycle_control
            .as_ref()
            .map(|c| Arc::new(control_header(c))),
    )
}

/// Accounting substitutes small placeholders for independently cached values.
/// Keeping the projection shared with the writer prevents format drift.
pub(crate) fn metadata_with_shared(
    state: &TenantState,
    policy: Arc<Policy>,
    lifecycle_control: Option<Arc<LifecycleControlState>>,
) -> TenantState {
    let mut metadata = query_metadata(state, policy);
    metadata.pending_restore = state.pending_restore.clone();
    metadata.restored_from = state.restored_from.clone();
    metadata.lifecycle_control = lifecycle_control;
    metadata.audit_retention = state.audit_retention.clone();
    metadata.key_retirements = state.key_retirements.clone();
    metadata.target_journal_retirements = state.target_journal_retirements.clone();
    metadata.target_journal_writers = state.target_journal_writers.clone();
    metadata
}

/// The state fields used by a page worker and its selected source readers.
/// Recovery records, audit manifests and key retirement histories can grow
/// independently of a page and are read by the enclosing service.
pub(crate) fn query_metadata(state: &TenantState, policy: Arc<Policy>) -> TenantState {
    TenantState {
        tenant: state.tenant.clone(),
        incarnation: state.incarnation.clone(),
        revision: state.revision,
        revision_base: state.revision_base,
        policy_epoch: state.policy_epoch,
        schema_epoch: state.schema_epoch,
        suspended: state.suspended,
        retired: state.retired,
        pending_restore: None,
        restored_from: None,
        restore_lineage: Default::default(),
        lifecycle_control: None,
        target_lifecycle: Default::default(),
        recovery_control: Default::default(),
        document_count: state.document_count,
        logical_bytes: state.logical_bytes,
        policy,
        limits: state.limits.clone(),
        collections: Default::default(),
        mutation_receipt_head: state.mutation_receipt_head.clone(),
        backup_binding_head: state.backup_binding_head.clone(),
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
        audit_retention: kasumi_types::AuditRetentionState::empty(state.audit_retention.stream_id),
        key_retirements: Default::default(),
        target_journal_retirements: Default::default(),
        target_journal_writers: Vec::new(),
        audits: Default::default(),
    }
}
fn empty_records(state: &TenantState) -> bool {
    state.target_lifecycle.is_empty()
        && state.recovery_control.is_empty()
        && state.collections.is_empty()
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

enum EncodedPosition {
    Record((u8, String, String)),
    EndOfKind(u8),
}

impl EncodedPosition {
    fn precedes(&self, next: &(u8, String, String)) -> bool {
        match self {
            Self::Record(previous) => previous < next,
            Self::EndOfKind(previous) => *previous < next.0,
        }
    }
}

pub(crate) struct Encoder<'a> {
    writer: &'a mut dyn Write,
    digest: Sha256,
    count: u64,
    total: u64,
    previous: Option<EncodedPosition>,
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
                .is_none_or(|previous| previous.precedes(&key)),
            "snapshot records duplicated or unordered"
        );
        self.previous = Some(EncodedPosition::Record(key));
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
    /// Copy a whole ordered class from the same immutable image whose typed
    /// records built this target. Rebinding changes neither live documents
    /// nor feed items. Both the source AEAD and the new stream digest cover
    /// every copied byte, including the record lengths and kind tags.
    fn verified_documents(&mut self, source: &VerifiedRecords, kind: u8) -> anyhow::Result<()> {
        use std::io::{Seek, SeekFrom};

        anyhow::ensure!(matches!(kind, 3 | 10), "unexpected verified document class");
        let layout = source.summary().kinds[usize::from(kind)];
        if layout.records == 0 {
            anyhow::ensure!(
                layout.framed_bytes == 0,
                "empty verified document class has bytes"
            );
            return Ok(());
        }
        anyhow::ensure!(
            self.previous
                .as_ref()
                .is_none_or(|previous| match previous {
                    EncodedPosition::Record((last, _, _)) | EncodedPosition::EndOfKind(last) =>
                        *last < kind,
                }),
            "verified snapshot class is out of order"
        );
        let offset = source.summary().kinds[..usize::from(kind)]
            .iter()
            .try_fold(MAGIC.len() as u64, |offset, row| {
                offset
                    .checked_add(row.framed_bytes)
                    .ok_or_else(|| anyhow::anyhow!("verified snapshot offset overflow"))
            })?;
        let mut reader = source.image().reader();
        reader.seek(SeekFrom::Start(offset))?;
        let mut remaining = layout.framed_bytes;
        let mut buffer = zeroize::Zeroizing::new(vec![0u8; 64 << 10]);
        while remaining > 0 {
            let take = remaining.min(buffer.len() as u64) as usize;
            let chunk = &mut buffer[..take];
            reader.read_exact(chunk)?;
            // The materialization writer checks the original deadline and
            // access before each bounded output block.
            self.writer.write_all(chunk)?;
            self.digest.update(chunk);
            remaining -= take as u64;
        }
        self.count = self
            .count
            .checked_add(layout.records)
            .ok_or_else(|| anyhow::anyhow!("snapshot record count overflow"))?;
        self.total = self
            .total
            .checked_add(layout.framed_bytes)
            .ok_or_else(|| anyhow::anyhow!("snapshot framing overflow"))?;
        self.previous = Some(EncodedPosition::EndOfKind(kind));
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
#[cfg(test)]
pub(crate) fn write(
    state: &TenantState,
    receipts: &crate::mutation_receipt::View,
    backup_bindings: &crate::backup_binding::View,
    terminals: &crate::staged_terminal::View,
    target_resolutions: &crate::target_resolution::View,
    writer: &mut dyn Write,
) -> anyhow::Result<()> {
    write_with_resolver(
        state,
        receipts,
        backup_bindings,
        terminals,
        target_resolutions,
        None,
        writer,
    )
}
pub(crate) fn write_with_resolver(
    state: &TenantState,
    receipts: &crate::mutation_receipt::View,
    backup_bindings: &crate::backup_binding::View,
    terminals: &crate::staged_terminal::View,
    target_resolutions: &crate::target_resolution::View,
    resolver: Option<&dyn DocumentResolver>,
    writer: &mut dyn Write,
) -> anyhow::Result<()> {
    write_records(
        state,
        receipts,
        backup_bindings,
        terminals,
        target_resolutions,
        DocumentFrames::Resolve(resolver),
        writer,
    )
}

/// Only the freshly rebound target may reuse these bytes. Subsequent
/// generations always use their own selected resolver.
pub(crate) fn write_verified_genesis(
    generation: &crate::Generation,
    source: &VerifiedRecords,
    writer: &mut dyn Write,
) -> anyhow::Result<()> {
    write_records(
        &generation.state,
        &generation.receipts,
        &generation.backup_bindings,
        &generation.terminals,
        &generation.target_resolutions,
        DocumentFrames::Verified(source),
        writer,
    )
}

enum DocumentFrames<'a> {
    Resolve(Option<&'a dyn DocumentResolver>),
    Verified(&'a VerifiedRecords),
}

fn write_records(
    state: &TenantState,
    receipts: &crate::mutation_receipt::View,
    backup_bindings: &crate::backup_binding::View,
    terminals: &crate::staged_terminal::View,
    target_resolutions: &crate::target_resolution::View,
    documents: DocumentFrames<'_>,
    writer: &mut dyn Write,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        terminals.head() == &state.staged_terminal_head,
        "snapshot terminal owner differs"
    );
    receipts.validate_state(state)?;
    backup_bindings.validate_state(state)?;
    // The ordered scan validates the physical head in its one selected root.
    terminals.check_head_metadata(&state.tenant)?;
    target_resolutions.validate_state(state)?;
    let mut encoder = Encoder::new(writer)?;
    for kind in 0..21 {
        if kind == 5 {
            for row in receipts.records() {
                encoder.record(Record::Receipt(Box::new(row?)))?;
            }
        } else {
            let resolver = match documents {
                DocumentFrames::Verified(source) if matches!(kind, 3 | 10) => {
                    encoder.verified_documents(source, kind)?;
                    continue;
                }
                DocumentFrames::Resolve(resolver) => resolver,
                DocumentFrames::Verified(_) => None,
            };
            for record in records_with_resolver(state, kind, None, resolver)? {
                encoder.record(record?)?;
            }
        }
    }
    for row in terminals.records() {
        encoder.record(Record::Terminal(Box::new(row?)))?;
    }
    for row in target_resolutions.records() {
        encoder.record(Record::TargetResolution(Box::new(row?)))?;
    }
    for record in records(state, 23, None)? {
        encoder.record(record?)?;
    }
    for row in backup_bindings.records() {
        encoder.record(Record::BackupBinding(Box::new(row?)))?;
    }
    write_lifecycle_history(&mut encoder, state)?;
    encoder.finish()
}
pub(crate) fn write_lifecycle_history(
    encoder: &mut Encoder<'_>,
    state: &TenantState,
) -> anyhow::Result<()> {
    if let Some(control) = &state.lifecycle_control
        && let Some(head) = &control.intent_head
    {
        let reader = control.intent_storage()?;
        for index in 1..=head.count {
            let original = reader.row(head, index, control.installation.max_state_bytes)?;
            encoder.record(Record::LifecycleIntentHistory(original.row))?;
        }
    }
    Ok(())
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
        let selected = self
            .kinds
            .get_mut(usize::from(kind))
            .ok_or_else(|| anyhow::anyhow!("snapshot kind is outside the layout roster"))?;
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
    /// Compact descriptor/maps and other semantic metadata. Document and feed
    /// payload bytes live in encrypted tables; their typed decode is charged by
    /// the separate one-record maximum. This estimate is not measured RSS.
    pub(crate) fn resident_bytes(&self) -> anyhow::Result<u64> {
        self.kinds
            .iter()
            .enumerate()
            .filter(|(kind, _)| !matches!(*kind, 5 | 21 | 22 | 24 | 25))
            .try_fold(64u64, |total, (number, kind)| {
                // Names are bounded at validation; include duplicated map keys,
                // Arc/descriptor control and conservative tree/vector capacity.
                let bytes = match number {
                    3 => kind.records.checked_mul(4096),
                    10 => kind.records.checked_mul(8192),
                    _ => Some(kind.framed_bytes),
                }
                .ok_or_else(|| anyhow::anyhow!("compact snapshot size overflow"))?;
                total
                    .checked_add(bytes)
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
    pub(crate) fn materialization_base_workspace(&self) -> anyhow::Result<u64> {
        let record = self.maximum_decode_work();
        self.resident_bytes()?
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(record))
            .and_then(|bytes| bytes.checked_add(64 << 20))
            .ok_or_else(|| anyhow::anyhow!("snapshot materialization workspace overflow"))
    }

    pub(crate) fn document_workspace(&self) -> anyhow::Result<u64> {
        crate::document_restore::workspace(
            self.kinds[3]
                .maximum_payload_bytes
                .max(self.kinds[10].maximum_payload_bytes),
            self.kinds[3]
                .maximum_decode_work
                .max(self.kinds[10].maximum_decode_work),
        )
    }

    pub(crate) fn materialization_workspace(&self) -> anyhow::Result<u64> {
        let documents = self.document_workspace()?;
        self.materialization_base_workspace()?
            .checked_add(documents)
            .and_then(|bytes| {
                bytes.checked_add(if documents == 0 {
                    0
                } else {
                    crate::admission::DocumentReadBudget::CONTROL_BYTES
                })
            })
            .ok_or_else(|| anyhow::anyhow!("snapshot document workspace overflow"))
    }
}

pub(crate) fn bounded_json_work(wire_bytes: u64, sites: u64) -> anyhow::Result<u64> {
    record_work::bounded_work(wire_bytes, sites)
}

fn authenticated_summary(
    digest: Sha256,
    mut summary: StreamSummary,
    footer: &[u8; 48],
) -> anyhow::Result<StreamSummary> {
    anyhow::ensure!(
        summary.records > 0
            && u64::from_be_bytes(footer[..8].try_into()?) == summary.records
            && u64::from_be_bytes(footer[8..16].try_into()?) == summary.bytes
            && digest.finalize().as_slice() == &footer[16..],
        "snapshot terminal authentication differs"
    );
    summary.bytes = summary
        .bytes
        .checked_add(56)
        .ok_or_else(|| anyhow::anyhow!("snapshot byte overflow"))?;
    Ok(summary)
}

fn finish_summary(
    reader: &mut dyn Read,
    digest: Sha256,
    summary: StreamSummary,
    verified: Option<&VerifiedRecords>,
) -> anyhow::Result<StreamSummary> {
    let mut footer = [0; 48];
    reader.read_exact(&mut footer)?;
    if let Some(source) = verified {
        let mut whole_image = digest.clone();
        whole_image.update(0u64.to_be_bytes());
        whole_image.update(footer);
        anyhow::ensure!(
            hex::encode(whole_image.finalize()) == source.image().sha256(),
            "materialized snapshot image changed"
        );
    }
    let summary = authenticated_summary(digest, summary, &footer)?;
    if let Some(source) = verified {
        anyhow::ensure!(
            &summary == source.summary(),
            "materialized snapshot layout changed"
        );
    }
    anyhow::ensure!(reader.read(&mut [0])? == 0, "trailing snapshot data");
    Ok(summary)
}

#[path = "snapshot_inspection.rs"]
mod inspection;
pub(crate) use inspection::{StreamInspector, inspect};

/// Visit canonical records without retaining preceding records. Successful return
/// proves framing, canonical encoding, strict order, terminal authentication and
/// contiguous lineage/audit sequences. Cross-record semantic checks belong to the
/// caller; observing a record before the terminal proof never authorizes publish.
pub(crate) fn visit<E: From<anyhow::Error>>(
    reader: &mut dyn Read,
    visitor: impl FnMut(RecordPosition, Record) -> std::result::Result<(), E>,
) -> std::result::Result<StreamSummary, E> {
    visit_image(reader, None, visitor)
}

fn visit_image<E: From<anyhow::Error>>(
    reader: &mut dyn Read,
    verified: Option<&VerifiedRecords>,
    mut visitor: impl FnMut(RecordPosition, Record) -> std::result::Result<(), E>,
) -> std::result::Result<StreamSummary, E> {
    let mut magic = [0; 8];
    (|| -> anyhow::Result<()> {
        reader.read_exact(&mut magic)?;
        anyhow::ensure!(&magic == MAGIC, "unsupported tenant snapshot format");
        Ok(())
    })()
    .map_err(E::from)?;
    let mut digest = Sha256::new();
    digest.update(magic);
    let mut summary = StreamSummary::empty();
    let mut previous = None;
    let mut lineage = 0u64;
    let mut audit = None;
    let mut audit_next = 0u64;
    let mut intent_record_limit = 0u64;
    loop {
        let mut length = [0; 8];
        let size = (|| -> anyhow::Result<u64> {
            reader.read_exact(&mut length)?;
            Ok(u64::from_be_bytes(length))
        })()
        .map_err(E::from)?;
        if size == 0 {
            return (|| -> anyhow::Result<StreamSummary> {
                anyhow::ensure!(audit == Some(audit_next), "audit final sequence differs");
                finish_summary(reader, digest, summary, verified)
            })()
            .map_err(E::from);
        }
        let (position, record) = (|| -> anyhow::Result<(RecordPosition, Record)> {
            let mut kind = [0];
            reader.read_exact(&mut kind)?;
            anyhow::ensure!(
                size <= record_limit(kind[0])?,
                "snapshot typed record exceeds byte limit"
            );
            if kind[0] == 25 {
                anyhow::ensure!(
                    size <= intent_record_limit,
                    "lifecycle snapshot row exceeds selected byte allowance"
                );
            }
            // A replay reads from the same frozen, authenticated spool. Keep the
            // original per-kind admission before allocating any payload.
            let measured = verified.map(|source| &source.summary().kinds[usize::from(kind[0])]);
            if let Some(bound) = measured {
                anyhow::ensure!(
                    size <= bound.maximum_payload_bytes,
                    "snapshot replay exceeds the verified record size"
                );
            }
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
            // The initial structural visit compared canonical bytes and measured
            // decode work. Only verified immutable replay can reuse those facts.
            let (record, work) = match measured {
                Some(bound) => (serde_json::from_slice(&bytes)?, bound.maximum_decode_work),
                None => {
                    let work = record_work::measure(&bytes)?;
                    (decode_record(&bytes)?, work)
                }
            };
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
                    if let Some(control) = &header.lifecycle_control
                        && let Some(head) = &control.intent_head
                    {
                        anyhow::ensure!(
                            head.encoded_bytes <= header.limits.max_lifecycle_intent_bytes,
                            "lifecycle snapshot prefix exceeds installed byte budget"
                        );
                        let installed = crate::backup_binding::intents::installed_row_limit(
                            control.installation.max_state_bytes,
                        ) as u64;
                        intent_record_limit = installed.saturating_add(256).min(head.encoded_bytes);
                    }
                    header.audit_retention.validate()?;
                    header.validate_key_retirement_scopes(crate::control::CONTROL_TENANT)?;
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
                Record::LifecycleIntentHistory(row) => {
                    row.intent.request.validate()?;
                    anyhow::ensure!(
                        row.intent.request_sha256 == staged_digest(&row.intent.request)?.0
                            && row.ordinal > 0,
                        "invalid retained lifecycle commitment"
                    );
                }
                Record::BackupBinding(row) => {
                    row.framed_bytes()?;
                }
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
                Record::RecoveryCompletionHistory(key, value) => {
                    value.validate()?;
                    anyhow::ensure!(
                        *key == value.scope.intent.to_string(),
                        "closed completion key differs"
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
            Ok((position, record))
        })()
        .map_err(E::from)?;
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
    pub(crate) receipts: crate::mutation_receipt::View,
    pub(crate) backup_bindings: crate::backup_binding::View,
    pub(crate) terminals: crate::staged_terminal::View,
    pub(crate) target_resolutions: crate::target_resolution::View,
    pub(crate) documents: crate::document_restore::StagedDocuments,
    /// Every receipt row was compared with the reopening replica's durable
    /// checkpoint rows while decoding, so `receipts` already is those rows.
    pub(crate) receipts_verified: bool,
    /// Built from the same typed live records that produced the staged bodies.
    pub(crate) document_indexes: Option<kasumi_query::SnapshotIndexBuilder>,
}
/// A reopening replica's own checkpoint: decoding compares rows with what it
/// already published under `checkpoint_sha256` instead of staging them.
pub(crate) struct ReopenRows<'a> {
    pub(crate) store: &'a Arc<kasumi_store::TenantStore>,
    pub(crate) checkpoint_sha256: &'a str,
    /// Compare document objects with the store's published rows too. Only a
    /// restore that publishes a store-backed document resolver may: its
    /// objects are then never read from this decode after publication.
    pub(crate) documents: bool,
}
enum ReceiptSink {
    Staged(crate::mutation_receipt::Builder),
    Durable(crate::mutation_receipt::DurableReopen),
}
pub(crate) fn read(
    disk: &Arc<kasumi_store::ScratchDisk>,
    reader: &mut dyn Read,
) -> std::result::Result<Decoded, kasumi_store::ScratchOperationFailure> {
    read_reopening(disk, reader, None)
}
pub(crate) fn read_reopening(
    disk: &Arc<kasumi_store::ScratchDisk>,
    reader: &mut dyn Read,
    reopen: Option<&ReopenRows<'_>>,
) -> std::result::Result<Decoded, kasumi_store::ScratchOperationFailure> {
    read_placed(disk, SnapshotInput::Local { reader, reopen })
}

pub(crate) fn read_verified_target(
    records: &VerifiedRecords,
    tenant: &str,
    incarnation: &str,
    check: &dyn Fn() -> anyhow::Result<()>,
) -> std::result::Result<Decoded, kasumi_store::ScratchOperationFailure> {
    read_placed(
        records.image().disk(),
        SnapshotInput::VerifiedTarget {
            records,
            tenant,
            incarnation,
            check,
        },
    )
}

enum SnapshotInput<'a> {
    Local {
        reader: &'a mut dyn Read,
        reopen: Option<&'a ReopenRows<'a>>,
    },
    VerifiedTarget {
        records: &'a VerifiedRecords,
        tenant: &'a str,
        incarnation: &'a str,
        check: &'a dyn Fn() -> anyhow::Result<()>,
    },
}

fn read_placed(
    disk: &Arc<kasumi_store::ScratchDisk>,
    input: SnapshotInput<'_>,
) -> std::result::Result<Decoded, kasumi_store::ScratchOperationFailure> {
    let (reopen, target) = match &input {
        SnapshotInput::Local { reopen, .. } => (*reopen, None),
        SnapshotInput::VerifiedTarget {
            tenant,
            incarnation,
            ..
        } => (None, Some((*tenant, *incarnation))),
    };
    let mut document_indexes = match &input {
        SnapshotInput::VerifiedTarget { records, .. }
            if records.summary().kinds[4].records == 0 =>
        {
            Some(kasumi_query::SnapshotIndexBuilder::for_installed_rows())
        }
        _ => None,
    };
    let mut state: Option<TenantState> = None;
    let mut receipts: Option<ReceiptSink> = None;
    let mut backup_bindings: Option<crate::backup_binding::Builder> = None;
    let mut terminals: Option<crate::staged_terminal::Builder> = None;
    let mut target_resolutions: Option<crate::target_resolution::Builder> = None;
    let mut documents: Option<crate::document_restore::Builder> = None;
    let mut document_table_limit = None;
    let accept = |_, record| {
        if let Record::Header(header) = record {
            kasumi_store::ScratchOperationFailure::ordinary(|| {
                if let Some((tenant, incarnation)) = target {
                    anyhow::ensure!(header.tenant == tenant, "restore document tenant differs");
                    kasumi_types::validate_name(incarnation)?;
                }
                anyhow::ensure!(
                    state.is_none() && empty_records(&header),
                    "snapshot header contains embedded records"
                );
                Ok(())
            })?;
            let intent_bytes = header
                .lifecycle_control
                .as_ref()
                .and_then(|control| control.intent_head.as_ref())
                .map_or(0, |head| head.encoded_bytes);
            if intent_bytes > header.limits.max_lifecycle_intent_bytes {
                return Err(
                    anyhow::anyhow!("snapshot intent prefix exceeds installed budget").into(),
                );
            }
            let backup_bytes = header.backup_binding_head.encoded_bytes;
            if backup_bytes > header.limits.max_backup_binding_bytes {
                return Err(anyhow::anyhow!(
                    "snapshot backup binding prefix exceeds installed budget"
                )
                .into());
            }
            if header.backup_binding_head.count > 0 || intent_bytes > 0 {
                backup_bindings = Some(crate::backup_binding::Builder::new(
                    disk,
                    crate::backup_binding::scratch_limit(
                        backup_bytes.checked_add(intent_bytes).ok_or_else(|| {
                            anyhow::anyhow!("Control permanent scratch bound overflow")
                        })?,
                    )?,
                    &header.backup_binding_head.origin_incarnation,
                )?);
            }
            if header.mutation_receipt_head.count > 0 {
                let durable = reopen
                    .map(|rows| {
                        kasumi_store::ScratchOperationFailure::ordinary(|| {
                            crate::mutation_receipt::DurableReopen::open(
                                rows.store,
                                rows.checkpoint_sha256,
                                &header.tenant,
                                &header.incarnation,
                                &header.mutation_receipt_head.origin_incarnation,
                            )
                        })
                    })
                    .transpose()?
                    .flatten();
                receipts = Some(match durable {
                    Some(durable) => ReceiptSink::Durable(durable),
                    None => ReceiptSink::Staged(crate::mutation_receipt::Builder::new(
                        disk,
                        crate::mutation_receipt::scratch_limit(
                            header.limits.max_mutation_receipt_bytes,
                        )?,
                        &header.tenant,
                        &header.mutation_receipt_head.origin_incarnation,
                    )?),
                });
            }
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
            document_table_limit = Some(kasumi_store::ScratchOperationFailure::ordinary(|| {
                kasumi_types::validate_name(&header.incarnation)?;
                crate::document_store::Scope::new(&header.tenant, &header.incarnation)?;
                header
                    .limits
                    .max_snapshot_bytes
                    .checked_mul(8)
                    .and_then(|v| v.checked_add(64 << 20))
                    .ok_or_else(|| anyhow::anyhow!("document staging budget overflow"))
            })?);
            state = Some(*header);
            return Ok(());
        }
        // Native acquisition stays outside `ordinary`: a refused or failed
        // constructor must retain its exact typed cleanup owner. Empty
        // snapshots never acquire the two scratch databases at all.
        if documents.is_none()
            && (matches!(&record, Record::Document(..))
                || matches!(&record, Record::ChangeItem(_, _, change) if change.document.is_some()))
        {
            let state = state
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("snapshot metadata must be first"))?;
            documents = Some(crate::document_restore::Builder::new(
                disk,
                document_table_limit
                    .ok_or_else(|| anyhow::anyhow!("document staging budget absent"))?,
                &state.tenant,
                target.map_or(state.incarnation.as_str(), |(_, incarnation)| incarnation),
            )?);
            if let Some(rows) = reopen.filter(|rows| rows.documents) {
                kasumi_store::ScratchOperationFailure::ordinary(|| {
                    documents
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("document builder absent"))?
                        .compare_published(rows.store, &state.tenant, &state.incarnation)
                })?;
            }
        }
        kasumi_store::ScratchOperationFailure::ordinary(|| {
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
                    Arc::make_mut(&mut state.restore_lineage).push(link);
                }
                Record::Collection(k, collection) => {
                    anyhow::ensure!(
                        collection.documents.is_empty() && collection.archived_documents.is_empty(),
                        "collection contains embedded documents"
                    );
                    if !collection.definition.indexes.is_empty() {
                        // Every collection header precedes the first document.
                        document_indexes = None;
                    }
                    if let Some(building) = &mut document_indexes {
                        building.add_collection(&collection.definition)?;
                    }
                    state.collections.insert(k, collection);
                }
                Record::Document(k, document) => {
                    let descriptor = documents
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("document builder absent"))?
                        .push(&document)?;
                    if let Some(building) = &mut document_indexes {
                        building.add_document(&k, &document)?;
                    }
                    state
                        .collections
                        .get_mut(&k)
                        .ok_or_else(|| anyhow::anyhow!("document collection missing"))?
                        .documents
                        .insert(
                            document.id.clone(),
                            Arc::new(DocumentSlot::Stored(descriptor)),
                        );
                }
                Record::Archived(k, id, reference) => {
                    state
                        .collections
                        .get_mut(&k)
                        .ok_or_else(|| anyhow::anyhow!("archive collection missing"))?
                        .archived_documents
                        .insert(id, reference);
                }
                Record::LifecycleIntentHistory(row) => {
                    let control = state.lifecycle_control.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("lifecycle intent row outside installed Control")
                    })?;
                    backup_bindings
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("unexpected lifecycle history row"))?
                        .push_intent(&row, control, state.limits.max_lifecycle_intent_bytes)?;
                }
                Record::BackupBinding(row) => {
                    backup_bindings
                        .as_mut()
                        .ok_or_else(|| {
                            anyhow::anyhow!("backup binding row without authenticated prefix")
                        })?
                        .push(&row, state)?;
                }
                Record::Receipt(row) => {
                    match receipts.as_mut().ok_or_else(|| {
                        anyhow::anyhow!("receipt row without authenticated prefix")
                    })? {
                        ReceiptSink::Staged(builder) => builder.push(&row, state)?,
                        ReceiptSink::Durable(durable) => durable.push(&row, state)?,
                    }
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
                    let document = change
                        .document
                        .as_ref()
                        .map(|document| {
                            documents
                                .as_mut()
                                .ok_or_else(|| anyhow::anyhow!("document builder absent"))?
                                .push(document)
                                .map(|descriptor| Arc::new(DocumentSlot::Stored(descriptor)))
                        })
                        .transpose()?;
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
                    commit.records.push(ChangeRecord {
                        collection: change.collection,
                        id: change.id,
                        document,
                    });
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
                        .map(Arc::make_mut)
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
                Record::RecoveryCompletionHistory(key, history) => {
                    anyhow::ensure!(
                        state
                            .recovery_control
                            .operations
                            .contains_key(&history.operation_id.to_string()),
                        "closed completion operation missing"
                    );
                    state
                        .recovery_control
                        .completion_history
                        .insert(key, *history);
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
                        .map(Arc::make_mut)
                        .ok_or_else(|| anyhow::anyhow!("control installation missing"))?
                        .changes
                        .insert(id, change);
                }
            }
            Ok(())
        })
    };
    let summary = match input {
        SnapshotInput::Local { reader, .. } => visit(reader, accept)?,
        SnapshotInput::VerifiedTarget { records, check, .. } => {
            visit_image(&mut records.reader(check), Some(records), accept)?
        }
    };
    kasumi_store::ScratchOperationFailure::ordinary(|| {
        let mut state = state.ok_or_else(|| anyhow::anyhow!("snapshot metadata absent"))?;
        anyhow::ensure!(
            state
                .lifecycle_control
                .as_ref()
                .and_then(|control| control.intent_head.as_ref())
                == backup_bindings
                    .as_ref()
                    .and_then(|builder| builder.intent_head.as_ref()),
            "snapshot lifecycle prefix count, bytes or digest differs"
        );
        let backup_bindings = match backup_bindings {
            Some(builder) => builder.finish(&state.backup_binding_head)?,
            None => {
                let empty = crate::backup_binding::View::empty(
                    &state.backup_binding_head.origin_incarnation,
                )?;
                anyhow::ensure!(
                    empty.head() == &state.backup_binding_head,
                    "backup binding history missing from snapshot"
                );
                empty
            }
        };
        backup_bindings.bind_intents(&mut state);
        crate::state::lifecycle::validate_restored_intents(&state)?;
        let receipts_verified = matches!(receipts, Some(ReceiptSink::Durable(_)));
        let receipts = match receipts {
            Some(ReceiptSink::Staged(builder)) => builder.finish(&state.mutation_receipt_head)?,
            Some(ReceiptSink::Durable(durable)) => durable.finish(&state.mutation_receipt_head)?,
            None => {
                let empty = crate::mutation_receipt::View::empty(
                    &state.tenant,
                    &state.mutation_receipt_head.origin_incarnation,
                )?;
                anyhow::ensure!(
                    empty.head() == &state.mutation_receipt_head,
                    "receipt history missing from snapshot"
                );
                empty
            }
        };
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
        let documents = match documents {
            Some(builder) => builder.finish()?,
            None => crate::document_restore::StagedDocuments::empty(
                disk,
                &state.tenant,
                target.map_or(state.incarnation.as_str(), |(_, incarnation)| incarnation),
            )?,
        };
        Ok(Decoded {
            state,
            receipts,
            backup_bindings,
            summary,
            terminals,
            target_resolutions,
            documents,
            receipts_verified,
            document_indexes,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn write(state: &TenantState, writer: &mut dyn Write) -> anyhow::Result<()> {
        super::write(
            state,
            &crate::mutation_receipt::View::empty(&state.tenant, &state.incarnation)?,
            &crate::backup_binding::View::empty(&state.incarnation)?,
            &crate::staged_terminal::View::empty(&state.tenant, &state.incarnation)?,
            &crate::target_resolution::View::empty(&state.tenant, &state.incarnation)?,
            writer,
        )
    }
    fn read(
        disk: &Arc<kasumi_store::ScratchDisk>,
        reader: &mut dyn Read,
    ) -> std::result::Result<TenantState, kasumi_store::ScratchOperationFailure> {
        Ok(super::read(disk, reader)?.state)
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
    fn verified_replay_rejects_an_independently_valid_image_with_equal_layout() {
        let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 256);
        let scratch = crate::codec_fixture::ScratchScope::new(memory).unwrap();
        let mut state = state();
        let mut bytes = Vec::new();
        write(&state, &mut bytes).unwrap();
        let image = kasumi_store::SnapshotImage::from_bytes(&scratch.disk, &bytes).unwrap();
        let source = crate::state::snapshot_validation::ValidatedApplicationSnapshot::validate(
            image,
            128 << 20,
            || Ok(()),
        )
        .unwrap()
        .into_records();
        let decoded =
            super::read_verified_target(&source, &state.tenant, "restored", &|| Ok(())).unwrap();
        assert_eq!(decoded.summary, *source.summary());
        assert!(decoded.document_indexes.is_some());
        assert!(
            super::read(&scratch.disk, &mut bytes.as_slice())
                .unwrap()
                .document_indexes
                .is_none()
        );
        drop(decoded);

        Arc::make_mut(&mut state.policy).grants[0].principal = "other".into();
        let mut substituted = Vec::new();
        write(&state, &mut substituted).unwrap();
        assert_ne!(bytes, substituted);
        let layout = visit::<anyhow::Error>(&mut substituted.as_slice(), |_, _| Ok(())).unwrap();
        assert_eq!(&layout, source.summary());
        let error =
            visit_image::<anyhow::Error>(&mut substituted.as_slice(), Some(&source), |_, _| Ok(()))
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("materialized snapshot image changed"),
            "{error:#}"
        );
    }

    #[test]
    fn authenticated_fieldless_restore_binds_the_staged_document_headers() {
        let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 256);
        let scratch = crate::codec_fixture::ScratchScope::new(memory).unwrap();
        let mut source = state();
        let documents = ["a", "b", "c"]
            .into_iter()
            .map(|id| {
                let document = Document {
                    id: id.into(),
                    version: 0,
                    body: serde_json::json!({"id": id}),
                };
                (
                    id.to_owned(),
                    Arc::new(DocumentSlot::Pending(Arc::new(document))),
                )
            })
            .collect();
        source.collections.insert(
            "docs".into(),
            CollectionState {
                definition: Arc::new(CollectionDefinition {
                    name: "docs".into(),
                    schema: serde_json::json!({"type":"object"}),
                    indexes: vec![],
                    strict_read_audit: false,
                    retention_class: CollectionRetentionClass::Operational,
                    write_mode: CollectionWriteMode::Mutable,
                }),
                data_epoch: 0,
                documents,
                archived_documents: Default::default(),
                archived_document_bytes: 0,
            },
        );
        let mut bytes = Vec::new();
        write(&source, &mut bytes).unwrap();
        let image = kasumi_store::SnapshotImage::from_bytes(&scratch.disk, &bytes).unwrap();
        let records = crate::state::snapshot_validation::ValidatedApplicationSnapshot::validate(
            image,
            128 << 20,
            || Ok(()),
        )
        .unwrap()
        .into_records();
        let decoded =
            super::read_verified_target(&records, &source.tenant, "restored", &|| Ok(())).unwrap();
        for (id, slot) in &decoded.state.collections["docs"].documents {
            let DocumentSlot::Stored(descriptor) = slot.as_ref() else {
                panic!("authenticated restore retained a pending body");
            };
            let document =
                kasumi_types::DocumentResolver::load(&decoded.documents, descriptor).unwrap();
            assert_eq!(document.body, serde_json::json!({"id":id}));
        }
        let indexes = decoded
            .document_indexes
            .unwrap()
            .finish_installed(
                kasumi_query::TextResidency::Directory,
                &decoded.state.collections,
                || Ok::<_, anyhow::Error>(()),
            )
            .unwrap();
        assert_eq!(
            indexes.document_ids_after("docs", Some("a"), 2).unwrap(),
            ["b", "c"]
        );
    }

    #[test]
    fn empty_decoded_snapshots_retain_scope_without_scratch_databases() {
        let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 256);
        let scratch = crate::codec_fixture::ScratchScope::new(memory.clone()).unwrap();
        let state = state();
        let mut bytes = Vec::new();
        write(&state, &mut bytes).unwrap();
        let before = memory.snapshot();
        let files = scratch.disk.snapshot().live_files;
        let decoded: Vec<_> = (0..129)
            .map(|_| super::read(&scratch.disk, &mut bytes.as_slice()).unwrap())
            .collect();
        assert_eq!(scratch.disk.snapshot().live_files, files);
        assert_eq!(
            memory.snapshot().live_reservations,
            before.live_reservations + 129
        );
        for value in &decoded {
            assert_eq!(value.documents.object_counts().unwrap(), (0, 0));
            assert_eq!(value.state.tenant, state.tenant);
            assert_eq!(value.state.incarnation, state.incarnation);
        }
        drop(decoded);
        assert_eq!(
            memory.snapshot().live_reservations,
            before.live_reservations
        );
        assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    }

    #[test]
    fn first_document_creation_failure_preserves_typed_native_custody() {
        use std::os::unix::fs::PermissionsExt;

        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let path = directory.path().join("scratch");
        let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64);
        let disk = kasumi_store::ScratchDisk::fixture(&path, memory.clone());
        let mut state = state();
        let document = Document {
            id: "one".into(),
            version: 1,
            body: serde_json::json!({"value": 1}),
        };
        state.collections.insert(
            "docs".into(),
            CollectionState {
                definition: Arc::new(CollectionDefinition {
                    name: "docs".into(),
                    schema: serde_json::json!({"type": "object"}),
                    indexes: vec![],
                    strict_read_audit: false,
                    retention_class: CollectionRetentionClass::Operational,
                    write_mode: CollectionWriteMode::Mutable,
                }),
                data_epoch: 0,
                documents: [(
                    document.id.clone(),
                    Arc::new(DocumentSlot::Pending(Arc::new(document))),
                )]
                .into_iter()
                .collect(),
                archived_documents: Default::default(),
                archived_document_bytes: 0,
            },
        );
        let mut bytes = Vec::new();
        write(&state, &mut bytes).unwrap();
        let baseline = memory.snapshot();
        let permissions = std::fs::metadata(&path).unwrap().permissions();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = match super::read(&disk, &mut bytes.as_slice()) {
            Err(error) => error,
            Ok(_) => panic!("first document must acquire native scratch ownership"),
        };
        std::fs::set_permissions(&path, permissions).unwrap();
        let kasumi_store::ScratchOperationFailure::Creation(original) = error else {
            panic!("first document constructor failure was erased");
        };
        assert!(original.owner_id().is_some());
        assert!(memory.snapshot().live_reservations > baseline.live_reservations);
        assert_eq!(
            original.retire().disposition(),
            kasumi_store::StorageCensusDisposition::Retired
        );
        assert_eq!(
            memory.snapshot().live_reservations,
            baseline.live_reservations
        );
        assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    }

    #[test]
    fn canonical_stream_requires_terminal_counts_digest_and_exact_eof() {
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let disk = &scratch.disk;
        let state = state();
        let mut bytes = Vec::new();
        write(&state, &mut bytes).unwrap();
        let decoded = read(disk, &mut bytes.as_slice()).unwrap();
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
                read(disk, &mut &bytes[..index]).is_err(),
                "accepted truncation at {index}"
            );
            let mut corrupt = bytes.clone();
            corrupt[index] ^= 1;
            assert!(
                read(disk, &mut corrupt.as_slice()).is_err(),
                "accepted corruption at {index}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(read(disk, &mut trailing.as_slice()).is_err());
        assert!(
            read(disk, &mut serde_json::to_vec(&state).unwrap().as_slice()).is_err(),
            "legacy JSON snapshots are forbidden"
        );
    }
    #[test]
    fn oversized_record_is_rejected_before_payload_read_or_allocation() {
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let disk = &scratch.disk;
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&((MAX_RECORD as u64) + 1).to_be_bytes());
        bytes.push(0);
        let error = read(disk, &mut bytes.as_slice()).unwrap_err().to_string();
        assert!(error.contains("record exceeds"));
    }
    #[test]
    fn authenticated_duplicate_header_is_rejected() {
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let disk = &scratch.disk;
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
            read(disk, &mut bytes.as_slice())
                .unwrap_err()
                .to_string()
                .contains("unordered")
        );
    }
    #[test]
    fn archived_audit_prefix_preserves_absolute_sequences_and_head() {
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let disk = &scratch.disk;
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
        let restored = read(disk, &mut bytes.as_slice()).unwrap();
        assert_eq!(restored.audit_retention.next_sequence, 24);
        assert_eq!(restored.audit_retention.pruned_before, 23);
        assert_eq!(restored.audit_retention.archive_head, Some(head));
        assert_eq!(restored.audits.len(), 1);
        state.audit_retention.next_sequence = 25;
        bytes.clear();
        write(&state, &mut bytes).unwrap();
        assert!(read(disk, &mut bytes.as_slice()).is_err());
    }
}

#[cfg(test)]
#[path = "snapshot_recovery_tests.rs"]
pub(crate) mod recovery_tests;

#[cfg(test)]
#[path = "snapshot_literal_tests.rs"]
mod literal_tests;

#[cfg(test)]
#[path = "snapshot_frame_tests.rs"]
mod frame_tests;
