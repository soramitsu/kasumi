//! Canonical ordered application records. Each document and change after-image
//! carries its stored descriptor. The encrypted body stays in its own namespace.
//! The permanent row catalogs contribute their exact snapshot bindings.
use anyhow::{Context, Result, ensure};
use kasumi_types::*;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

#[path = "application_feed_records.rs"]
mod feed;
#[path = "application_field_values.rs"]
mod field_values;
pub(crate) use feed::SnapshotFeed;
pub(crate) use field_values::visit_value_ids;

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

pub(crate) fn document_key(collection: &str, id: &str) -> Vec<u8> {
    KeyBuilder::new(3).text(collection).text(id).finish()
}

fn header_prefix(collection: &str) -> Vec<u8> {
    KeyBuilder::new(26).text(collection).finish()
}

pub(crate) fn visit_snapshot_headers(
    tree: &kasumi_store::ordered_pages::TreeReader<'_>,
    collection: &str,
    after: Option<&str>,
    revision: u64,
    mut visit: impl FnMut(&str, u64, kasumi_query::RecordKind) -> Result<bool>,
) -> Result<()> {
    use kasumi_store::ordered_pages::{Direction, ValueRef};
    use std::ops::Bound;

    let prefix = header_prefix(collection);
    let mut start = prefix.clone();
    let bound = if let Some(after) = after {
        // A stored ID occupies at most 256 bytes. Its equality with even a
        // truncated longer bound is excluded, so the seek stays bounded.
        start.extend_from_slice(&after.as_bytes()[..after.len().min(256)]);
        Bound::Excluded(start.as_slice())
    } else {
        Bound::Included(start.as_slice())
    };
    tree.scan(bound, Direction::Forward, &mut |key, value| {
        if let Some(id) = key.strip_prefix(prefix.as_slice()) {
            let id = std::str::from_utf8(id)?;
            validate_name(id)?;
            let ValueRef::Inline(bytes) = value else {
                anyhow::bail!("overflow document header")
            };
            ensure!(bytes.len() == 9, "invalid document header length");
            let kind = match bytes[0] {
                0 => kasumi_query::RecordKind::Live,
                1 => kasumi_query::RecordKind::Archived,
                _ => anyhow::bail!("unknown document header kind"),
            };
            let version = u64::from_be_bytes(bytes[1..].try_into()?);
            ensure!(
                version <= revision,
                "document header exceeds selected revision"
            );
            return visit(id, version, kind);
        }
        Ok(false)
    })
}

/// Document identifiers cannot contain control characters, so their UTF-8
/// suffix sorts in document order and needs no additional tuple escaping.
fn presence_prefix(collection: &str, field: usize, present: bool) -> Vec<u8> {
    let mut key = KeyBuilder::new(24).text(collection).finish();
    key.extend_from_slice(&(field as u64).to_be_bytes());
    key.push(u8::from(present));
    key
}

pub(crate) fn visit_field_presence(
    reader: &kasumi_store::ordered_pages::TreeReader<'_>,
    collection: &str,
    field: usize,
    present: bool,
    mut visit: impl FnMut(&str) -> Result<bool>,
) -> Result<()> {
    use kasumi_store::ordered_pages::Direction;
    let prefix = presence_prefix(collection, field, present);
    reader.scan(
        std::ops::Bound::Included(&prefix),
        Direction::Forward,
        &mut |key, value| {
            let Some(id) = key.strip_prefix(prefix.as_slice()) else {
                return Ok(false);
            };
            anyhow::ensure!(value.is_empty(), "field presence row carries a payload");
            let id = std::str::from_utf8(id)?;
            validate_name(id)?;
            visit(id)
        },
    )
}

fn archive_key(collection: &str, id: &str) -> Vec<u8> {
    KeyBuilder::new(4).text(collection).text(id).finish()
}

/// Read at most one page from each primary namespace. Only keys are visited,
/// so an archived document's overflow payload stays on disk.
pub(crate) fn snapshot_ids_after(
    reader: &kasumi_store::ordered_pages::TreeReader<'_>,
    collection: &str,
    after: Option<&str>,
    limit: usize,
    mut check: impl FnMut() -> Result<()>,
) -> Result<Vec<String>> {
    use kasumi_store::ordered_pages::Direction;
    use std::ops::Bound;

    let mut page = |kind| -> Result<Vec<String>> {
        let prefix = KeyBuilder::new(kind).text(collection).finish();
        let start = after.map(|id| KeyBuilder::new(kind).text(collection).text(id).finish());
        let bound = start
            .as_deref()
            .map_or(Bound::Included(prefix.as_slice()), Bound::Excluded);
        let mut ids = Vec::with_capacity(limit);
        reader.scan(bound, Direction::Forward, &mut |key, _| {
            check()?;
            let Some(suffix) = key.strip_prefix(prefix.as_slice()) else {
                return Ok(false);
            };
            let encoded = suffix
                .strip_suffix(&[0, 1])
                .context("invalid primary ID terminator")?;
            let id = std::str::from_utf8(encoded)?;
            validate_name(id)?;
            ids.push(id.to_owned());
            Ok(ids.len() < limit)
        })?;
        Ok(ids)
    };
    let live = page(3)?;
    let archived = page(4)?;
    Ok(
        crate::index_source::ordered_union(live.into_iter(), archived.into_iter())
            .take(limit)
            .collect(),
    )
}

pub(crate) enum PrimaryPoint {
    Live(Arc<DocumentSlot>),
    Archived(Arc<ArchivedDocument>),
    Missing,
}

impl PrimaryPoint {
    pub(crate) fn resident(
        collection: &CollectionState,
        id: &str,
        revision: u64,
    ) -> kasumi_types::Result<Self> {
        crate::index_source::header(collection, id, revision)?;
        Ok(if let Some(slot) = collection.documents.get(id) {
            Self::Live(slot.clone())
        } else if let Some(reference) = collection.archived_documents.get(id) {
            Self::Archived(reference.clone())
        } else {
            Self::Missing
        })
    }
}

/// Resolve both possible records from a single authenticated root. A miss is
/// authoritative for that snapshot. The body or history chunk is read later.
pub(crate) fn snapshot_point(
    reader: &kasumi_store::ordered_pages::TreeReader<'_>,
    collection: &str,
    id: &str,
    revision: u64,
    mut admit: impl FnMut(&[u8]) -> Result<()>,
) -> Result<PrimaryPoint> {
    #[derive(serde::Deserialize)]
    #[serde(tag = "type", content = "value", deny_unknown_fields)]
    enum Point {
        Document(StoredDocument),
        Archived(ArchivedDocument),
    }
    if validate_name(id).is_err() {
        return Ok(PrimaryPoint::Missing);
    }
    let live = reader.with_value(
        &document_key(collection, id),
        8 << 10,
        |value| -> Result<_> {
            let Some(bytes) = value else {
                return Ok(None);
            };
            admit(bytes)?;
            let Point::Document(descriptor) = serde_json::from_slice(bytes)? else {
                anyhow::bail!("wrong live document record kind")
            };
            descriptor.validate()?;
            anyhow::ensure!(
                descriptor.id == id && descriptor.version <= revision,
                "snapshot point has another document identity or version"
            );
            anyhow::ensure!(
                serde_json::to_vec(&DurableRecord::Document(&descriptor))? == bytes,
                "noncanonical snapshot document"
            );
            Ok(Some(descriptor))
        },
    )?;
    let archived = reader.with_value(
        &archive_key(collection, id),
        kasumi_store::ordered_pages::MAX_VALUE_BYTES,
        |value| -> Result<_> {
            let Some(bytes) = value else {
                return Ok(None);
            };
            admit(bytes)?;
            let Point::Archived(reference) = serde_json::from_slice(bytes)? else {
                anyhow::bail!("wrong archived document record kind")
            };
            anyhow::ensure!(
                reference.version <= revision
                    && live.as_ref().is_none_or(|d| d.version == reference.version),
                "snapshot archived version differs"
            );
            anyhow::ensure!(
                serde_json::to_vec(&DurableRecord::Archived(&reference))? == bytes,
                "noncanonical archived document"
            );
            Ok(Some(reference))
        },
    )?;
    Ok(match (live, archived) {
        (Some(descriptor), _) => PrimaryPoint::Live(Arc::new(DocumentSlot::Stored(descriptor))),
        (None, Some(reference)) => PrimaryPoint::Archived(Arc::new(reference)),
        (None, None) => PrimaryPoint::Missing,
    })
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
    generation: &crate::Generation,
    layout: u32,
    bindings: &BTreeMap<&'static str, &[u8]>,
    memory: &Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
    mut emit: impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    let state = &generation.state;
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
                document_key(name, id),
                DurableRecord::Document(stored(slot)?),
            )?;
        }
    }
    for (name, collection) in &state.collections {
        for (id, archived) in &collection.archived_documents {
            visit(archive_key(name, id), DurableRecord::Archived(archived))?;
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
    )?;
    if layout >= kasumi_store::application_manifest::FIELD_POSTINGS_LAYOUT {
        generation
            .indexes
            .visit_field_presence(|collection, field, present, id| {
                let mut key = presence_prefix(collection, field, present);
                key.extend_from_slice(id.as_bytes());
                emit(&key, &[])
            })?;
    }
    if layout >= kasumi_store::application_manifest::FIELD_VALUES_LAYOUT {
        field_values::publish(&generation.indexes, &mut emit)?;
    }
    if layout >= kasumi_store::application_manifest::DOCUMENT_HEADERS_LAYOUT {
        for (name, collection) in &state.collections {
            let mut key = header_prefix(name);
            let prefix_bytes = key.len();
            for id in crate::index_source::resident_ids_after(collection, None) {
                let header = crate::index_source::header(collection, id, state.revision)?
                    .context("document lost its selected header")?;
                key.truncate(prefix_bytes);
                key.extend_from_slice(id.as_bytes());
                let mut value = [0; 9];
                value[0] = u8::from(header.kind == kasumi_query::RecordKind::Archived);
                value[1..].copy_from_slice(&header.version.to_be_bytes());
                emit(&key, &value)?;
            }
        }
    }
    Ok(())
}

/// One primary row value with the lease that funds its encoding.
struct PrimaryValue {
    bytes: Vec<u8>,
    _lease: kasumi_store::DiskMemoryLease,
}

fn encode_primary(
    record: &DurableRecord<'_>,
    memory: &Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
) -> Result<PrimaryValue> {
    let (length, _) = crate::snapshot_codec::measure_typed_json(record, |_| {})?;
    let length = usize::try_from(length)?;
    ensure!(
        length <= kasumi_store::ordered_pages::MAX_VALUE_BYTES,
        "primary record exceeds storage bound"
    );
    let lease = memory.clone().reserve_installed(length as u64)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    serde_json::to_writer(&mut bytes, record)?;
    ensure!(bytes.len() == length, "primary record length changed");
    Ok(PrimaryValue {
        bytes,
        _lease: lease,
    })
}

fn header_value(header: &kasumi_query::Header<'_>) -> [u8; 9] {
    let mut value = [0; 9];
    value[0] = u8::from(header.kind == kasumi_query::RecordKind::Archived);
    value[1..].copy_from_slice(&header.version.to_be_bytes());
    value
}

/// Every primary row of `state` in key order: live descriptors, archived
/// references, then the header directory. These are exactly the rows of the
/// same keys in a snapshot tree, so the same readers serve both.
pub(crate) fn visit_primary(
    state: &TenantState,
    memory: &Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
    mut emit: impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    let _framing = memory.clone().reserve_installed(64 << 10)?;
    for (name, collection) in &state.collections {
        for (id, slot) in &collection.documents {
            let value = encode_primary(&DurableRecord::Document(stored(slot)?), memory)?;
            emit(&document_key(name, id), &value.bytes)?;
        }
    }
    for (name, collection) in &state.collections {
        for (id, archived) in &collection.archived_documents {
            let value = encode_primary(&DurableRecord::Archived(archived), memory)?;
            emit(&archive_key(name, id), &value.bytes)?;
        }
    }
    for (name, collection) in &state.collections {
        let mut key = header_prefix(name);
        let prefix_bytes = key.len();
        for id in crate::index_source::resident_ids_after(collection, None) {
            let header = crate::index_source::header(collection, id, state.revision)?
                .context("document lost its selected header")?;
            key.truncate(prefix_bytes);
            key.extend_from_slice(id.as_bytes());
            emit(&key, &header_value(&header))?;
        }
    }
    Ok(())
}

/// The three primary rows of one document at `revision`: each key with its
/// value, or `None` where the row must be absent. Returns the bytes added.
pub(crate) fn primary_rows(
    name: &str,
    collection: Option<&CollectionState>,
    id: &str,
    revision: u64,
    memory: &Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
    rows: &mut BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    leases: &mut Vec<kasumi_store::DiskMemoryLease>,
) -> Result<usize> {
    let mut added = 0usize;
    let mut insert = |key: Vec<u8>, value: Option<Vec<u8>>| {
        added = added
            .saturating_add(key.len())
            .saturating_add(value.as_ref().map_or(0, Vec::len));
        rows.insert(key, value);
    };
    let mut encode = |record: DurableRecord<'_>| -> Result<Vec<u8>> {
        let PrimaryValue { bytes, _lease } = encode_primary(&record, memory)?;
        leases.push(_lease);
        Ok(bytes)
    };
    let live = collection
        .and_then(|collection| collection.documents.get(id))
        .map(|slot| -> Result<Vec<u8>> { encode(DurableRecord::Document(stored(slot)?)) })
        .transpose()?;
    insert(document_key(name, id), live);
    let archived = collection
        .and_then(|collection| collection.archived_documents.get(id))
        .map(|archived| encode(DurableRecord::Archived(archived)))
        .transpose()?;
    insert(archive_key(name, id), archived);
    let header = collection
        .map(|collection| crate::index_source::header(collection, id, revision))
        .transpose()?
        .flatten()
        .map(|header| header_value(&header).to_vec());
    let mut key = header_prefix(name);
    key.extend_from_slice(id.as_bytes());
    insert(key, header);
    Ok(added)
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
