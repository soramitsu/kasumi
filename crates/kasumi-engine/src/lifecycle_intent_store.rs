//! Control intent history shares the selected encrypted Control binding namespace.
//! Its key prefixes, hash domain, byte budget and selected head are independent.
use super::{Builder, Source, View};
use anyhow::{Context, Result, ensure};
use kasumi_store::WriteOp;
use kasumi_types::{
    Error, LifecycleControlState, LifecycleIntentHead, LifecycleIntentRow, LifecycleIntentRowLoan,
    LifecycleIntentRows, LifecycleIntentSource, TenantState, staged_digest,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

// Preserve the full admitted legacy intent size. Each encrypted physical value
// fits a scratch batch and a namespace-stage batch independently.
pub(crate) const MAX_ROW: usize = kasumi_types::MAX_LIFECYCLE_STATE_BYTES + 4096;
pub(crate) fn installed_row_limit(max_intent_bytes: usize) -> usize {
    max_intent_bytes.min(kasumi_types::MAX_LIFECYCLE_STATE_BYTES) + 4096
}
const CHUNK: usize = 256 << 10;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Point {
    ordinal: u64,
    bytes: usize,
    sha256: String,
}
fn chunk_key(id: Uuid, part: usize) -> Vec<u8> {
    [
        b"lifecycle/chunk/".as_slice(),
        id.as_bytes(),
        &(part as u64).to_be_bytes(),
    ]
    .concat()
}
fn physical_records(
    row: &LifecycleIntentRow,
    mut visit: impl FnMut(Vec<u8>, &[u8]) -> Result<()>,
) -> Result<()> {
    use sha2::Digest;
    let (payload, ordinal) = encoded(row)?;
    let id = row.intent.request.command_id;
    let point = Point {
        ordinal: row.ordinal,
        bytes: payload.len(),
        sha256: hex::encode(sha2::Sha256::digest(&payload)),
    };
    visit(point_key(id), &serde_json::to_vec(&point)?)?;
    visit(ordinal_key(row.ordinal), &ordinal)?;
    for (i, bytes) in payload.chunks(CHUNK).enumerate() {
        visit(chunk_key(id, i), bytes)?;
    }
    Ok(())
}

fn point_key(id: Uuid) -> Vec<u8> {
    [b"lifecycle/id/".as_slice(), id.as_bytes()].concat()
}
fn ordinal_key(index: u64) -> Vec<u8> {
    [b"lifecycle/ordinal/".as_slice(), &index.to_be_bytes()].concat()
}
#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
struct Ordinal {
    id: Uuid,
    sha256: String,
}

fn descriptor(row: &LifecycleIntentRow) -> Result<Ordinal> {
    Ok(Ordinal {
        id: row.intent.request.command_id,
        sha256: staged_digest(&("kasumi.lifecycle-intent-row.v1", row))?.0,
    })
}

pub(crate) fn row_sha256(row: &LifecycleIntentRow) -> Result<String> {
    Ok(descriptor(row)?.sha256)
}

fn encoded(row: &LifecycleIntentRow) -> Result<(Vec<u8>, Vec<u8>)> {
    let size = crate::accounting::encoded_len(row)?;
    ensure!(size <= MAX_ROW, "lifecycle intent exceeds record bound");
    let mut bytes = Vec::with_capacity(size);
    serde_json::to_writer(&mut bytes, row)?;
    let index = serde_json::to_vec(&descriptor(row)?)?;
    Ok((bytes, index))
}

pub(crate) fn advance(
    previous: &LifecycleIntentHead,
    row: &LifecycleIntentRow,
) -> Result<LifecycleIntentHead> {
    let mut size = 128u64;
    physical_records(row, |key, value| {
        size = size
            .checked_add(u64::try_from(key.len() + value.len() + 32)?)
            .context("lifecycle intent record charge overflow")?;
        Ok(())
    })?;
    ensure!(
        row.ordinal
            == previous
                .count
                .checked_add(1)
                .context("lifecycle intent count overflow")?
            && row.previous_sha256 == previous.sha256
            && row.intent.revision > previous.revision
            && super::digest(&row.command_sha256),
        "lifecycle intent does not extend the selected prefix"
    );
    Ok(LifecycleIntentHead {
        count: row.ordinal,
        encoded_bytes: previous
            .encoded_bytes
            .checked_add(size)
            .context("lifecycle history byte count overflow")?,
        revision: row.intent.revision,
        sha256: descriptor(row)?.sha256,
    })
}

pub(crate) fn take_candidate(
    state: &mut TenantState,
    command_sha256: &str,
) -> Result<Option<(LifecycleIntentRow, LifecycleIntentHead)>> {
    let Some(control) = &mut state.lifecycle_control else {
        return Ok(None);
    };
    if control.pending_intent.is_none() {
        return Ok(None);
    }
    let control = Arc::make_mut(control);
    let intent = control
        .pending_intent
        .take()
        .expect("checked original lifecycle intent");
    let previous = match &control.intent_head {
        None => LifecycleIntentHead::empty(control.installation.root.control_incarnation)?,
        Some(head) => head.clone(),
    };
    let row = LifecycleIntentRow {
        ordinal: previous
            .count
            .checked_add(1)
            .context("lifecycle intent count overflow")?,
        previous_sha256: previous.sha256.clone(),
        command_sha256: command_sha256.to_owned(),
        intent: *intent,
    };
    let head = advance(&previous, &row)?;
    Ok(Some((row, head)))
}

impl Source {
    fn intent_value(
        &self,
        key: &[u8],
        maximum: usize,
    ) -> Result<Option<crate::materialization_row::MaterializationRow>> {
        use crate::materialization_row::MaterializationRow;
        Ok(match self {
            Self::Durable(rows) => rows
                .store
                .get_bounded(&rows.binding.namespace(), key, maximum)?
                .map(MaterializationRow::Stored),
            Self::Staged(table, _) => table.get(key)?.map(MaterializationRow::Staged),
        })
    }
    fn intent_index(&self, ordinal: u64) -> Result<Ordinal> {
        let raw = self
            .intent_value(&ordinal_key(ordinal), 512)?
            .context("selected lifecycle intent ordinal is absent")?;
        ensure!(
            raw.len() <= 512,
            "lifecycle intent ordinal exceeds its encoding bound"
        );
        let index: Ordinal = serde_json::from_slice(&raw)?;
        crate::current_json::require_current_writer_bytes(
            &raw,
            &index,
            "lifecycle intent ordinal",
        )?;
        ensure!(
            !index.id.is_nil() && super::digest(&index.sha256),
            "invalid lifecycle intent ordinal"
        );
        Ok(index)
    }
    fn intent_point(
        &self,
        head: &LifecycleIntentHead,
        id: Uuid,
        max_intent_bytes: usize,
    ) -> Result<Option<LifecycleIntentRowLoan>> {
        ensure!(
            head.count > 0 && self.intent_index(head.count)?.sha256 == head.sha256,
            "selected lifecycle intent prefix is missing or changed"
        );
        let Some(raw) = self.intent_value(&point_key(id), 512)? else {
            ensure!(
                self.intent_value(&chunk_key(id, 0), CHUNK)?.is_none(),
                "lifecycle intent payload lost its identity descriptor"
            );
            return Ok(None);
        };
        ensure!(
            raw.len() <= 512,
            "lifecycle point descriptor exceeds its encoding bound"
        );
        let point: Point = serde_json::from_slice(&raw)?;
        crate::current_json::require_current_writer_bytes(
            &raw,
            &point,
            "lifecycle point descriptor",
        )?;
        ensure!(
            point.ordinal > 0
                && point.bytes > 0
                && point.bytes <= installed_row_limit(max_intent_bytes)
                && super::digest(&point.sha256),
            "invalid lifecycle point descriptor"
        );
        if point.ordinal > head.count {
            ensure!(
                self.intent_index(point.ordinal)?.id == id,
                "unselected lifecycle point differs from its ordinal"
            );
            return Ok(None);
        }
        ensure!(
            point.bytes as u64 <= head.encoded_bytes,
            "lifecycle point exceeds selected byte budget"
        );
        let memory = match self {
            Self::Durable(rows) => rows.store.plaintext_memory_owner(),
            Self::Staged(_, memory) => memory,
        };
        let input_lease = memory.clone().reserve_installed(
            u64::try_from(point.bytes)?
                .checked_add(1024)
                .context("lifecycle encoded row allocation overflow")?,
        )?;
        let mut bytes = Vec::with_capacity(point.bytes);
        for i in 0..point.bytes.div_ceil(CHUNK) {
            let required = usize::min(CHUNK, point.bytes - bytes.len());
            let chunk = self
                .intent_value(&chunk_key(id, i), required)?
                .context("selected lifecycle intent chunk missing")?;
            ensure!(
                chunk.len() == required,
                "lifecycle history chunk has another length"
            );
            bytes.extend_from_slice(&chunk);
        }
        use sha2::Digest;
        ensure!(
            hex::encode(sha2::Sha256::digest(&bytes)) == point.sha256,
            "selected lifecycle intent ciphertext payload changed"
        );
        let work = crate::snapshot_codec::inspect_external_json_work(&bytes, &mut || Ok(()))?;
        let quoted = work
            .checked_mul(2)
            .context("lifecycle typed record copy overflow")?
            .checked_add(
                (bytes.len() as u64)
                    .checked_mul(3)
                    .context("intent writer/comparison bound overflow")?,
            )
            .and_then(|n| n.checked_add(8192))
            .context("intent decode allocation overflow")?;
        let retained = memory.clone().reserve_installed(quoted)?;
        let row: LifecycleIntentRow = serde_json::from_slice(&bytes)?;
        ensure!(
            crate::accounting::encoded_len(&row.intent)? <= max_intent_bytes,
            "selected lifecycle intent exceeds installed record budget"
        );
        crate::current_json::require_current_writer_bytes(&bytes, &row, "lifecycle intent point")?;
        ensure!(
            row.ordinal == point.ordinal && row.intent.request.command_id == id,
            "invalid lifecycle intent point identity"
        );

        ensure!(
            row.intent.revision <= head.revision
                && self.intent_index(row.ordinal)? == descriptor(&row)?,
            "lifecycle intent differs from selected ordinal or head"
        );
        let previous = if row.ordinal == 1 {
            LifecycleIntentHead::empty(row.intent.control_incarnation)?.sha256
        } else {
            self.intent_index(row.ordinal - 1)?.sha256
        };
        ensure!(
            row.previous_sha256 == previous,
            "lifecycle intent parent commitment differs"
        );
        drop(bytes);
        drop(input_lease);
        Ok(Some(LifecycleIntentRowLoan::new(row, Box::new(retained))))
    }
}
impl LifecycleIntentRows for Source {
    fn point(
        &self,
        head: &LifecycleIntentHead,
        id: Uuid,
        max_intent_bytes: usize,
    ) -> kasumi_types::Result<Option<LifecycleIntentRowLoan>> {
        self.intent_point(head, id, max_intent_bytes)
            .map_err(Error::from_physical_source)
    }
    fn row(
        &self,
        head: &LifecycleIntentHead,
        ordinal: u64,
        max_intent_bytes: usize,
    ) -> kasumi_types::Result<LifecycleIntentRowLoan> {
        (|| {
            ensure!(
                ordinal > 0 && ordinal <= head.count,
                "lifecycle ordinal outside selected prefix"
            );
            let key = self.intent_index(ordinal)?;
            let row = self
                .intent_point(head, key.id, max_intent_bytes)?
                .context("selected lifecycle intent row missing")?;
            ensure!(row.ordinal == ordinal, "redirected lifecycle ordinal");
            Ok(row)
        })()
        .map_err(Error::from_physical_source)
    }
}

impl View {
    pub(crate) fn bind_intents(&self, state: &mut TenantState) {
        if let Some(control) = state.lifecycle_control.as_mut() {
            let source = self
                .source
                .clone()
                .map(|source| source as Arc<dyn LifecycleIntentRows>);
            Arc::make_mut(control).intent_source = LifecycleIntentSource(source);
        }
    }
    pub(crate) fn persist_intent(&self, row: &LifecycleIntentRow) -> Result<()> {
        let source = self
            .source
            .as_ref()
            .context("lifecycle history has no installed physical owner")?;
        let Source::Durable(rows) = source.as_ref() else {
            anyhow::bail!("unpublished lifecycle intent storage")
        };
        let namespace = rows.binding.namespace();
        let mut existing = 0;
        let mut writes = Vec::new();
        physical_records(row, |key, payload| {
            if let Some(current) = source.intent_value(&key, payload.len())? {
                ensure!(
                    &*current == payload,
                    "previously staged lifecycle intent differs from exact ordered replay"
                );
                existing += 1;
            } else {
                writes.push(WriteOp::put(&namespace, key, payload));
            }
            Ok(())
        })?;
        ensure!(
            writes.is_empty() || existing == 0,
            "partially published lifecycle intent"
        );
        if !writes.is_empty() {
            rows.store.write_batch(&writes)?;
        }
        Ok(())
    }
    pub(crate) fn verify_restored_intents(&self, state: &TenantState) -> Result<()> {
        let Some(control) = &state.lifecycle_control else {
            return Ok(());
        };
        let Some(expected) = &control.intent_head else {
            return Ok(());
        };
        let source = self
            .source
            .as_ref()
            .context("restored lifecycle intent source missing")?;
        let original = control.intent_storage()?;
        let mut inferred =
            LifecycleIntentHead::empty(control.installation.root.control_incarnation)?;
        for ordinal in 1..=expected.count {
            let found = source.row(expected, ordinal, control.installation.max_state_bytes)?;
            ensure!(
                found.row
                    == original
                        .row(expected, ordinal, control.installation.max_state_bytes)?
                        .row,
                "selected durable lifecycle intent differs from snapshot"
            );
            inferred = advance(&inferred, &found)?;
        }
        ensure!(
            inferred == *expected,
            "restored lifecycle count, bytes or root differs"
        );
        Ok(())
    }
}

impl Builder {
    pub(crate) fn push_intent(
        &mut self,
        row: &LifecycleIntentRow,
        control: &LifecycleControlState,
        limit: u64,
    ) -> Result<()> {
        let selected = control
            .intent_head
            .as_ref()
            .context("intent row lacks its selected prefix")?;
        ensure!(
            selected.encoded_bytes <= limit && row.ordinal <= selected.count,
            "lifecycle stream exceeds its selected count or installed byte budget"
        );
        let previous = match self.intent_head.take() {
            Some(head) => head,
            None => {
                ensure!(
                    control
                        .intents
                        .values()
                        .all(|legacy| legacy.revision < row.intent.revision),
                    "selected lifecycle prefix precedes a legacy command"
                );
                LifecycleIntentHead::empty(control.installation.root.control_incarnation)?
            }
        };
        let key = point_key(row.intent.request.command_id);
        ensure!(
            self.table.get(&key)?.is_none()
                && !control.intents.contains_key(&row.intent.request.command_id),
            "duplicate historical lifecycle command"
        );
        let next = advance(&previous, row)?;
        ensure!(
            next.encoded_bytes <= selected.encoded_bytes,
            "lifecycle history exceeds its selected byte budget"
        );
        physical_records(row, |key, payload| self.table.insert(&key, payload))?;
        self.intent_head = Some(next);
        Ok(())
    }
}
