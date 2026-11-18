//! Canonical ordered application records. Each document and change after-image
//! carries its stored descriptor. The encrypted body stays in its own namespace.
//! The permanent row catalogs contribute their exact snapshot bindings.
use anyhow::{Context, Result};
use kasumi_types::*;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Order-preserving tuple encoding: each component escapes 0x00 as 0x00 0xFF
/// and ends with 0x00 0x01, so a shorter component sorts before its extensions.
struct KeyBuilder(Vec<u8>);
impl KeyBuilder {
    fn new(kind: u8) -> Self {
        Self(vec![kind])
    }
    fn part(mut self, bytes: &[u8]) -> Self {
        for byte in bytes {
            self.0.push(*byte);
            if *byte == 0 {
                self.0.push(0xff);
            }
        }
        self.0.extend_from_slice(&[0, 1]);
        self
    }
    fn text(self, text: &str) -> Self {
        self.part(text.as_bytes())
    }
    fn number(self, number: u64) -> Self {
        self.part(&number.to_be_bytes())
    }
    fn finish(self) -> Vec<u8> {
        self.0
    }
}

const HEADER: &[u8] = b"\x00header";
const POLICY: &[u8] = b"\x01policy";
const CONTROL: &[u8] = b"\x02control";
const BINDING: &str = "\x03binding/";

#[derive(Serialize)]
#[serde(tag = "type", content = "value")]
enum DurableRecord<'a> {
    Header(&'a TenantState),
    Policy(&'a Policy),
    Control(&'a LifecycleControlState),
    /// Exact UTF-8 bytes of the authenticated permanent-row checkpoint binding.
    Binding(&'a str),
    Lineage(&'a RestoreLineageLink),
    Collection(&'a CollectionDefinition, u64, usize),
    Document(&'a StoredDocument),
    Archived(&'a ArchivedDocument),
    Stage(&'a StagedTransaction),
    StageChunk(&'a StagedChunk),
    ActiveStage,
    Change(&'a ChangeCommit),
    ChangeItem(&'a str, &'a str, Option<&'a StoredDocument>),
    Archive(&'a RetainedHistoryArchive),
    Activation(&'a StoredSchemaActivation),
    Retirement(&'a StoredRetirement),
    Audit(&'a AuditEvent),
    Intent(&'a LifecycleIntent),
    ControlChange(&'a ControlPolicyChange),
    Target(&'a TargetExecutionState),
    RecoveryOperation(&'a RecoveryRecord),
    RecoveryPhase(&'a RecoveryPhaseRecord),
    RecoveryTarget(uuid::Uuid),
    RecoveryCompletionHistory(&'a RecoveryCompletionHistory),
}

fn stored(slot: &DocumentSlot) -> Result<&StoredDocument> {
    match slot {
        DocumentSlot::Stored(descriptor) => Ok(descriptor),
        DocumentSlot::Pending(_) => anyhow::bail!("snapshot descriptor has an unstored document"),
    }
}

type RecordVisitor<'a> = dyn FnMut(Vec<u8>, DurableRecord<'_>) -> Result<()> + 'a;

/// Each value borrows the selected generation until its bounded write completes.
pub(crate) fn visit_all(
    state: &TenantState,
    bindings: &BTreeMap<&'static str, &[u8]>,
    memory: &Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
    mut emit: impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    // Header projections and tuple key framing use a bounded per-visit workspace.
    let _framing = memory.clone().reserve_installed(64 << 10)?;
    let mut visit = |key: Vec<u8>, record: DurableRecord<'_>| {
        let (length, _) = crate::snapshot_codec::measure_typed_json(&record, |_| {})?;
        let length = usize::try_from(length)?;
        anyhow::ensure!(
            length <= kasumi_store::ordered_pages::MAX_VALUE_BYTES,
            "application record exceeds storage bound"
        );
        let _lease = memory.clone().reserve_installed(length as u64)?;
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(length)?;
        serde_json::to_writer(&mut encoded, &record)?;
        anyhow::ensure!(encoded.len() == length, "application record length changed");
        emit(&key, &encoded)
    };
    let zero = |sub: &[u8]| KeyBuilder::new(0).part(sub).finish();
    let header =
        crate::snapshot_codec::metadata_with_shared(state, Arc::new(Policy::default()), None);
    visit(zero(HEADER), DurableRecord::Header(&header))?;
    visit(zero(POLICY), DurableRecord::Policy(&state.policy))?;
    if let Some(control) = &state.lifecycle_control {
        visit(
            zero(CONTROL),
            DurableRecord::Control(&crate::snapshot_codec::control_header(control)),
        )?;
    }
    for (name, binding) in bindings {
        visit(
            zero(format!("{BINDING}{name}").as_bytes()),
            DurableRecord::Binding(std::str::from_utf8(binding)?),
        )?;
    }
    for (index, link) in state.restore_lineage.iter().enumerate() {
        visit(
            KeyBuilder::new(1).number(index as u64).finish(),
            DurableRecord::Lineage(link),
        )?;
    }
    for (name, collection) in &state.collections {
        visit(
            KeyBuilder::new(2).text(name).finish(),
            DurableRecord::Collection(
                &collection.definition,
                collection.data_epoch,
                collection.archived_document_bytes,
            ),
        )?;
    }
    for (name, collection) in &state.collections {
        for (id, slot) in &collection.documents {
            visit(
                KeyBuilder::new(3).text(name).text(id).finish(),
                DurableRecord::Document(stored(slot)?),
            )?;
        }
    }
    for (name, collection) in &state.collections {
        for (id, archived) in &collection.archived_documents {
            visit(
                KeyBuilder::new(4).text(name).text(id).finish(),
                DurableRecord::Archived(archived),
            )?;
        }
    }
    for (key, stage) in &state.staged_transactions {
        visit(
            KeyBuilder::new(6).text(key).finish(),
            DurableRecord::Stage(&crate::snapshot_codec::stage_header(stage)),
        )?;
    }
    for (key, stage) in &state.staged_transactions {
        for (index, chunk) in &stage.chunks {
            visit(
                KeyBuilder::new(7).text(key).number(*index as u64).finish(),
                DurableRecord::StageChunk(chunk),
            )?;
        }
    }
    for key in &state.active_staged_transactions {
        visit(
            KeyBuilder::new(8).text(key).finish(),
            DurableRecord::ActiveStage,
        )?;
    }
    for (sequence, commit) in &state.change_feed.commits {
        let header = crate::snapshot_codec::change_header(commit);
        visit(
            KeyBuilder::new(9).number(*sequence).finish(),
            DurableRecord::Change(&header),
        )?;
    }
    for (sequence, commit) in &state.change_feed.commits {
        for (index, record) in commit.records.iter().enumerate() {
            visit(
                KeyBuilder::new(10)
                    .number(*sequence)
                    .number(index as u64)
                    .finish(),
                DurableRecord::ChangeItem(
                    &record.collection,
                    &record.id,
                    record.document.as_deref().map(stored).transpose()?,
                ),
            )?;
        }
    }
    visit_map(
        11,
        &state.history_archives,
        |v| DurableRecord::Archive(v),
        &mut visit,
    )?;
    visit_map(
        12,
        &state.schema_activations,
        DurableRecord::Activation,
        &mut visit,
    )?;
    visit_map(
        13,
        &state.retirements,
        DurableRecord::Retirement,
        &mut visit,
    )?;
    for (index, event) in state.audits.iter().enumerate() {
        let sequence = state
            .audit_retention
            .pruned_before
            .checked_add(index as u64)
            .context("audit sequence overflow")?;
        visit(
            KeyBuilder::new(14).number(sequence).finish(),
            DurableRecord::Audit(event),
        )?;
    }
    if let Some(control) = &state.lifecycle_control {
        for (id, intent) in &control.intents {
            visit(
                KeyBuilder::new(15).part(id.as_bytes()).finish(),
                DurableRecord::Intent(intent),
            )?;
        }
        for (id, change) in &control.changes {
            visit(
                KeyBuilder::new(16).part(id.as_bytes()).finish(),
                DurableRecord::ControlChange(change),
            )?;
        }
    }
    visit_map(
        17,
        &state.target_lifecycle,
        DurableRecord::Target,
        &mut visit,
    )?;
    let recovery = &state.recovery_control;
    visit_map(
        18,
        &recovery.operations,
        DurableRecord::RecoveryOperation,
        &mut visit,
    )?;
    visit_map(
        19,
        &recovery.phases,
        DurableRecord::RecoveryPhase,
        &mut visit,
    )?;
    visit_map(
        20,
        &recovery.targets,
        |v| DurableRecord::RecoveryTarget(*v),
        &mut visit,
    )?;
    visit_map(
        23,
        &recovery.completion_history,
        DurableRecord::RecoveryCompletionHistory,
        &mut visit,
    )
}

fn visit_map<'a, V: Clone>(
    kind: u8,
    map: &'a imbl::OrdMap<String, V>,
    record: impl Fn(&'a V) -> DurableRecord<'a>,
    visit: &mut RecordVisitor<'_>,
) -> Result<()> {
    for (key, value) in map {
        visit(KeyBuilder::new(kind).text(key).finish(), record(value))?;
    }
    Ok(())
}
