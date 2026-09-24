//! Permanent ordinary mutation outcomes, selected by one applied generation.
//! No expiry or resident lifetime map exists. Point reads use short transactions;
//! a row beyond the selected ordinal cannot prove that its command was applied.
use crate::staged_terminal::AppliedIdentity;
#[cfg(any(test, feature = "test-utils"))]
use crate::staged_terminal::AppliedOrigin;
use anyhow::{Context, Result, ensure};
use kasumi_store::{EncryptedTable, ScratchDisk, TenantStore, WriteOp};
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// A single admitted batch has at most 256 bounded names/IDs and contains no
// document Value in its receipt. This is a per-record format bound, not a lifetime cap.
const MAX_ROW_BYTES: usize = 2 << 20;
pub(crate) const MAX_SNAPSHOT_RECORD_BYTES: usize = MAX_ROW_BYTES;
const CATALOG: &str = "mutation-receipt-catalog";
pub(crate) fn scratch_limit(canonical_bytes: u64) -> Result<u64> {
    canonical_bytes
        .checked_mul(8)
        .and_then(|n| n.checked_add(64 << 20))
        .context("receipt scratch table budget overflow")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Row {
    pub ordinal: u64,
    pub key: String,
    pub previous_sha256: String,
    pub applied: AppliedIdentity,
    pub receipt: StoredReceipt,
}
impl Row {
    pub(crate) fn sha256(&self) -> Result<String> {
        Ok(staged_digest(&("kasumi.mutation-receipt-row.v1", self))?.0)
    }
    pub(crate) fn framed_bytes(&self) -> Result<u64> {
        let bytes = crate::accounting::encoded_len(&crate::snapshot_codec::Record::Receipt(
            Box::new(self.clone()),
        ))?;
        ensure!(
            bytes <= MAX_ROW_BYTES,
            "receipt exceeds canonical per-record budget"
        );
        (bytes as u64)
            .checked_add(crate::snapshot_codec::FRAME_HEADER_BYTES as u64)
            .context("receipt canonical length overflow")
    }
    pub(crate) fn validate(&self, state: &TenantState) -> Result<()> {
        ensure!(
            self.ordinal > 0 && digest(&self.key) && digest(&self.previous_sha256),
            "receipt chain identity differs"
        );
        let (genesis, maximum) = self.applied.validate_original_position(state)?;
        self.receipt
            .validate_identity(&self.key, &state.tenant, genesis, maximum)?;
        ensure!(
            self.receipt.scope.incarnation == self.applied.incarnation
                && self.receipt.recorded_revision == self.applied.revision,
            "receipt original scope differs from its applying command"
        );
        ensure!(
            !self.receipt.collections.is_empty() && self.receipt.collections.len() <= 256,
            "receipt collection count exceeds per-operation bound"
        );
        let mut previous: Option<&str> = None;
        for collection in &self.receipt.collections {
            validate_name(collection)?;
            ensure!(
                previous.is_none_or(|old| old < collection.as_str()),
                "receipt collections are not canonical"
            );
            previous = Some(collection);
        }
        if let Ok(outcome) = &self.receipt.outcome {
            ensure!(
                !outcome.versions.is_empty() && outcome.versions.len() <= 256,
                "receipt version count exceeds per-operation bound"
            );
            let mut collections = std::collections::BTreeSet::new();
            for (key, version) in &outcome.versions {
                ensure!(
                    key.len() <= 1026 && *version == self.applied.revision,
                    "receipt document version differs"
                );
                let path = key
                    .strip_prefix('/')
                    .context("receipt path lacks root slash")?;
                let (collection, id) = path
                    .split_once('/')
                    .context("receipt path lacks document segment")?;
                let collection = decode_path_segment(collection)?;
                let _id = decode_path_segment(id)?;
                collections.insert(collection);
            }
            ensure!(
                collections.iter().eq(self.receipt.collections.iter()),
                "receipt versions and authorized collection set differ"
            );
        }

        self.framed_bytes()?;
        Ok(())
    }
}
fn decode_path_segment(segment: &str) -> Result<String> {
    let mut decoded = String::with_capacity(segment.len());
    let mut chars = segment.chars();
    while let Some(ch) = chars.next() {
        decoded.push(match ch {
            '/' => anyhow::bail!("receipt path has an extra segment"),
            '~' => match chars.next() {
                Some('0') => '~',
                Some('1') => '/',
                _ => anyhow::bail!("receipt path escape is not canonical"),
            },
            ch => ch,
        });
    }
    validate_name(&decoded)?;
    Ok(decoded)
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn id_key(key: &str) -> Vec<u8> {
    [b"id/".as_slice(), key.as_bytes()].concat()
}
fn ordinal_key(ordinal: u64) -> Vec<u8> {
    [b"ordinal/".as_slice(), &ordinal.to_be_bytes()].concat()
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Ordinal {
    key: String,
    sha256: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamespaceBinding {
    namespace: uuid::Uuid,
    tenant: String,
    incarnation: String,
    checkpoint_sha256: String,
    checkpoint_head: MutationReceiptHead,
}
impl NamespaceBinding {
    fn namespace(&self) -> String {
        format!("mutation-receipt-{}", self.namespace)
    }
}
struct DurableRows {
    store: Arc<TenantStore>,
    binding: NamespaceBinding,
}
enum Source {
    Durable(DurableRows),
    Staged(Arc<EncryptedTable>),
}
impl Source {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let result = match self {
            Self::Durable(rows) => {
                rows.store
                    .get_bounded(&rows.binding.namespace(), key, MAX_ROW_BYTES)?
            }
            Self::Staged(table) => table.get(key)?,
        };
        ensure!(
            result
                .as_ref()
                .is_none_or(|value| value.len() <= MAX_ROW_BYTES),
            "receipt physical row exceeds bound"
        );
        Ok(result)
    }
}
/// This owner retains immutable rows, not an open KV read transaction. The
/// selected count/root remain unchanged while new rows append to the namespace.
#[derive(Clone)]
pub(crate) struct View {
    source: Option<Arc<Source>>,
    head: MutationReceiptHead,
}
impl std::fmt::Debug for View {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutationReceiptView")
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}
impl View {
    pub(crate) fn empty(tenant: &str, incarnation: &str) -> Result<Self> {
        Ok(Self {
            source: None,
            head: MutationReceiptHead::empty(tenant, incarnation)?,
        })
    }
    pub(crate) fn head(&self) -> &MutationReceiptHead {
        &self.head
    }
    fn bytes(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.source
            .as_ref()
            .map(|s| s.get(key))
            .transpose()
            .map(Option::flatten)
    }
    fn index(&self, ordinal: u64) -> Result<Ordinal> {
        ensure!(
            ordinal > 0 && ordinal <= self.head.count,
            "receipt ordinal is outside selected generation"
        );
        let bytes = self
            .bytes(&ordinal_key(ordinal))?
            .context("receipt ordinal missing")?;
        let entry: Ordinal = serde_json::from_slice(&bytes)?;
        crate::current_json::require_current_writer_bytes(&bytes, &entry, "receipt ordinal")?;
        ensure!(
            digest(&entry.key) && digest(&entry.sha256),
            "invalid receipt ordinal index"
        );
        Ok(entry)
    }
    pub(crate) fn check_head(&self, tenant: &str) -> Result<()> {
        validate_name(&self.head.origin_incarnation)?;
        ensure!(digest(&self.head.sha256), "invalid receipt head digest");
        if self.head.count == 0 {
            ensure!(
                self.head == MutationReceiptHead::empty(tenant, &self.head.origin_incarnation)?,
                "nonempty receipt accounting without rows"
            );
        } else {
            ensure!(
                self.head.encoded_bytes > 0
                    && self.head.last_applied_revision > 0
                    && self.index(self.head.count)?.sha256 == self.head.sha256,
                "receipt physical prefix differs from selected root"
            );
        }
        Ok(())
    }
    pub(crate) fn validate_state(&self, state: &TenantState) -> Result<()> {
        self.check_head(&state.tenant)?;
        ensure!(
            self.head == state.mutation_receipt_head
                && self.head.last_applied_revision <= state.revision
                && (self.head.origin_incarnation == state.incarnation
                    || state
                        .restore_lineage
                        .iter()
                        .any(|link| link.checkpoint.source_incarnation
                            == self.head.origin_incarnation)),
            "receipt history origin is outside retained lineage"
        );
        Ok(())
    }
    pub(crate) fn get(&self, key: &str) -> Result<Option<Row>> {
        self.get_charged(key, |_| Ok(()))
    }
    pub(crate) fn get_charged(
        &self,
        key: &str,
        reserve_decoded: impl FnOnce(&[u8]) -> Result<()>,
    ) -> Result<Option<Row>> {
        ensure!(digest(key), "invalid mutation receipt point identity");
        let Some(bytes) = self.bytes(&id_key(key))? else {
            return Ok(None);
        };
        reserve_decoded(&bytes)?;
        let row: Row = serde_json::from_slice(&bytes)?;
        // A commit may have persisted a row before its applied cursor. It remains
        // invisible until exact replay advances this logical view's prefix.
        if row.ordinal > self.head.count {
            return Ok(None);
        }
        crate::current_json::require_current_writer_bytes(&bytes, &row, "receipt point")?;
        ensure!(
            row.key == key && row.ordinal > 0,
            "receipt point identity differs"
        );
        if row.ordinal == self.head.count {
            ensure!(
                row.applied.revision == self.head.last_applied_revision,
                "receipt last applied position differs from selected head"
            );
        }
        let index = self.index(row.ordinal)?;
        ensure!(
            index.key == key && index.sha256 == row.sha256()?,
            "receipt row differs from ordinal commitment"
        );
        if row.ordinal == 1 {
            ensure!(
                row.previous_sha256
                    == MutationReceiptHead::empty(
                        &row.receipt.scope.tenant,
                        &self.head.origin_incarnation
                    )?
                    .sha256,
                "receipt initial root differs"
            );
        } else {
            ensure!(
                row.previous_sha256 == self.index(row.ordinal - 1)?.sha256,
                "receipt parent root differs"
            );
        }
        ensure!(
            self.index(self.head.count)?.sha256 == self.head.sha256,
            "receipt selected root differs"
        );
        Ok(Some(row))
    }
    pub(crate) fn row(&self, ordinal: u64) -> Result<Row> {
        let key = self.index(ordinal)?.key;
        let row = self.get(&key)?.context("receipt indexed row missing")?;
        ensure!(row.ordinal == ordinal, "receipt ordinal redirected");
        Ok(row)
    }
    pub(crate) fn records(&self) -> impl Iterator<Item = Result<Row>> + Send + '_ {
        (1..=self.head.count).map(|ordinal| self.row(ordinal))
    }
}

/// An encrypted unpublished table is populated in canonical ordinal order. The
/// authenticated final head must match before this can become a restore input.
pub(crate) struct Builder {
    table: Arc<EncryptedTable>,
    head: MutationReceiptHead,
}
impl Builder {
    pub(crate) fn new(
        disk: &Arc<ScratchDisk>,
        limit: u64,
        tenant: &str,
        origin: &str,
    ) -> Result<Self> {
        Ok(Self {
            table: Arc::new(EncryptedTable::new(disk, limit)?),
            head: MutationReceiptHead::empty(tenant, origin)?,
        })
    }
    pub(crate) fn push(&mut self, row: &Row, state: &TenantState) -> Result<()> {
        row.validate(state)?;
        ensure!(
            self.table.get(&id_key(&row.key))?.is_none(),
            "duplicate immutable receipt identity"
        );
        advance(&mut self.head, row)?;
        let index = Ordinal {
            key: row.key.clone(),
            sha256: row.sha256()?,
        };
        self.table
            .insert(&id_key(&row.key), &serde_json::to_vec(row)?)?;
        self.table
            .insert(&ordinal_key(row.ordinal), &serde_json::to_vec(&index)?)?;
        Ok(())
    }
    pub(crate) fn finish(self, expected: &MutationReceiptHead) -> Result<View> {
        ensure!(
            &self.head == expected,
            "receipt stream final root/count/bytes differ"
        );
        Ok(View {
            source: Some(Arc::new(Source::Staged(self.table))),
            head: self.head,
        })
    }
}
pub(crate) fn advance(head: &mut MutationReceiptHead, row: &Row) -> Result<()> {
    ensure!(
        row.ordinal
            == head
                .count
                .checked_add(1)
                .context("receipt ordinal exhausted")?
            && row.previous_sha256 == head.sha256
            && row.applied.revision > head.last_applied_revision,
        "receipt row is not the next committed prefix"
    );
    head.encoded_bytes = head
        .encoded_bytes
        .checked_add(row.framed_bytes()?)
        .context("receipt permanent byte overflow")?;
    head.count = row.ordinal;
    head.last_applied_revision = row.applied.revision;
    head.sha256 = row.sha256()?;
    Ok(())
}

/// Prepared namespace activation. The coordinator commits replacements and
/// catalog writes with the enclosing checkpoint/applied cursor before publishing
/// `view`. Dropping this object leaves only encrypted temporary staging.
pub(crate) struct Installation {
    replacement: Option<Arc<EncryptedTable>>,
    namespace: String,
    writes: Vec<WriteOp>,
    pub(crate) view: View,
}
impl Installation {
    pub(crate) fn replacements(&self) -> Vec<(&str, &EncryptedTable)> {
        self.replacement
            .as_ref()
            .map(|table| vec![(self.namespace.as_str(), table.as_ref())])
            .unwrap_or_default()
    }
    pub(crate) fn writes(&self) -> &[WriteOp] {
        &self.writes
    }
}
impl View {
    pub(crate) fn checkpoint_exists(store: &TenantStore, checkpoint_sha256: &str) -> Result<bool> {
        ensure!(
            digest(checkpoint_sha256),
            "invalid receipt checkpoint digest"
        );
        Ok(store
            .get_bounded(CATALOG, checkpoint_sha256.as_bytes(), 64 << 10)?
            .is_some())
    }
    pub(crate) fn prepare_install(
        &self,
        store: &Arc<TenantStore>,
        state: &TenantState,
        checkpoint_sha256: &str,
        reopen: bool,
    ) -> Result<Installation> {
        ensure!(
            digest(checkpoint_sha256)
                && store.tenant() == state.tenant
                && self.head == state.mutation_receipt_head,
            "receipt installation identity differs"
        );
        self.check_head(&state.tenant)?;
        let selected = store
            .get_bounded(CATALOG, checkpoint_sha256.as_bytes(), 64 << 10)?
            .map(|bytes| {
                let binding: NamespaceBinding = serde_json::from_slice(&bytes)?;
                ensure!(
                    serde_json::to_vec(&binding)? == bytes,
                    "noncanonical receipt checkpoint binding"
                );
                Ok::<NamespaceBinding, anyhow::Error>(binding)
            })
            .transpose()?;
        if reopen {
            let binding = selected.context("authoritative receipt checkpoint binding missing")?;
            ensure!(
                binding.tenant == state.tenant
                    && binding.incarnation == state.incarnation
                    && binding.checkpoint_sha256 == checkpoint_sha256
                    && binding.checkpoint_head == self.head
                    && !binding.namespace.is_nil(),
                "receipt checkpoint binding differs"
            );
            let view = View {
                source: Some(Arc::new(Source::Durable(DurableRows {
                    store: store.clone(),
                    binding: binding.clone(),
                }))),
                head: self.head.clone(),
            };
            view.check_head(&state.tenant)?;
            // Validate against the authenticated snapshot prefix, while leaving
            // rows from later applications invisible for exact ordered replay.
            for row in self.records() {
                let row = row?;
                let actual = view
                    .get(&row.key)?
                    .context("checkpoint receipt row missing")?;
                ensure!(
                    actual.sha256()? == row.sha256()?,
                    "checkpoint receipt physical row differs"
                );
            }
            return Ok(Installation {
                replacement: None,
                namespace: binding.namespace(),
                writes: vec![],
                view,
            });
        }
        let replacement = match self.source.as_deref() {
            Some(Source::Staged(table)) => table.clone(),
            None if self.head.count == 0 => Arc::new(EncryptedTable::new(
                store.scratch_disk(),
                scratch_limit(state.limits.max_mutation_receipt_bytes)?,
            )?),
            _ => anyhow::bail!("namespace installation requires verified staged rows"),
        };
        let binding = NamespaceBinding {
            namespace: uuid::Uuid::new_v4(),
            tenant: state.tenant.clone(),
            incarnation: state.incarnation.clone(),
            checkpoint_sha256: checkpoint_sha256.into(),
            checkpoint_head: self.head.clone(),
        };
        let writes = vec![WriteOp::put(
            CATALOG,
            checkpoint_sha256.as_bytes(),
            serde_json::to_vec(&binding)?,
        )];
        let namespace = binding.namespace();
        let view = View {
            source: Some(Arc::new(Source::Durable(DurableRows {
                store: store.clone(),
                binding,
            }))),
            head: self.head.clone(),
        };
        Ok(Installation {
            replacement: Some(replacement),
            namespace,
            writes,
            view,
        })
    }
    /// Capture records a new checkpoint binding to this exact immutable prefix.
    /// These writes join the Raft snapshot publication transaction, including
    /// when later commands have already appended additional physical rows.
    pub(crate) fn checkpoint_writes(
        &self,
        state: &TenantState,
        checkpoint_sha256: &str,
    ) -> Result<Vec<WriteOp>> {
        ensure!(
            digest(checkpoint_sha256) && self.head == state.mutation_receipt_head,
            "receipt capture checkpoint differs"
        );
        let Some(Source::Durable(rows)) = self.source.as_deref() else {
            anyhow::bail!("receipt snapshot capture requires installed durable ownership");
        };
        rows.store.check_access()?;
        self.check_head(&state.tenant)?;
        let mut binding = rows.binding.clone();
        binding.checkpoint_sha256 = checkpoint_sha256.into();
        binding.checkpoint_head = self.head.clone();
        Ok(vec![WriteOp::put(
            CATALOG,
            checkpoint_sha256.as_bytes(),
            serde_json::to_vec(&binding)?,
        )])
    }
}

/// At most one finalized ordinary receipt can arise from one ordered mutation.
pub(crate) struct Pending {
    previous: View,
    head: MutationReceiptHead,
    rows: Vec<Row>,
}
impl Pending {
    pub(crate) fn prepare(
        previous: &View,
        state: &TenantState,
        receipt: Option<StoredReceipt>,
        applied: &AppliedIdentity,
    ) -> Result<Self> {
        ensure!(
            previous.head == state.mutation_receipt_head,
            "receipt starting prefix differs"
        );
        let mut head = previous.head.clone();
        let mut rows = Vec::new();
        if let Some(receipt) = receipt {
            let key = staged_digest(&(&receipt.scope.principal, &receipt.idempotency_key))?.0;
            ensure!(
                previous.get(&key)?.is_none(),
                "cannot rewrite permanent receipt"
            );
            let row = Row {
                ordinal: head
                    .count
                    .checked_add(1)
                    .context("receipt ordinal overflow")?,
                key,
                previous_sha256: head.sha256.clone(),
                applied: applied.clone(),
                receipt,
            };
            row.validate(state)?;
            advance(&mut head, &row)?;
            ensure!(
                head.encoded_bytes <= state.limits.max_mutation_receipt_bytes,
                "receipt byte admission was not reserved"
            );
            rows.push(row);
        }
        Ok(Self {
            previous: previous.clone(),
            head,
            rows,
        })
    }
    pub(crate) fn head(&self) -> &MutationReceiptHead {
        &self.head
    }
    pub(crate) fn persist(self) -> Result<View> {
        if self.rows.is_empty() {
            return Ok(self.previous);
        }
        let Some(source) = &self.previous.source else {
            anyhow::bail!("receipt append storage is not installed");
        };
        match source.as_ref() {
            Source::Durable(storage) => {
                let namespace = storage.binding.namespace();
                for row in &self.rows {
                    let id = id_key(&row.key);
                    let ordinal = ordinal_key(row.ordinal);
                    let bytes = serde_json::to_vec(row)?;
                    let index = serde_json::to_vec(&Ordinal {
                        key: row.key.clone(),
                        sha256: row.sha256()?,
                    })?;
                    let old_row = source.get(&id)?;
                    let old_index = source.get(&ordinal)?;
                    match (old_row, old_index) {
                        (Some(old_row), Some(old_index)) => {
                            ensure!(
                                old_row == bytes && old_index == index,
                                "future receipt row differs from exact original command replay"
                            );
                        }
                        (None, None) => {
                            // A failure can leave an exact prefix of this bounded
                            // overlay durable. No Generation is published until
                            // every row succeeds. Replay reconciles each pair.
                            storage.store.write_batch(&[
                                WriteOp::put(&namespace, id, bytes),
                                WriteOp::put(&namespace, ordinal, index),
                            ])?;
                        }
                        _ => anyhow::bail!("partially published receipt row/index"),
                    }
                }
            }
            #[cfg(any(test, feature = "test-utils"))]
            Source::Staged(table)
                if self
                    .rows
                    .iter()
                    .all(|row| matches!(row.applied.origin, AppliedOrigin::Fixture)) =>
            {
                for row in &self.rows {
                    table.insert(&id_key(&row.key), &serde_json::to_vec(row)?)?;
                    table.insert(
                        &ordinal_key(row.ordinal),
                        &serde_json::to_vec(&Ordinal {
                            key: row.key.clone(),
                            sha256: row.sha256()?,
                        })?,
                    )?;
                }
            }
            Source::Staged(_) => {
                anyhow::bail!("unpublished restore staging cannot serve receipt writes")
            }
        }
        let view = View {
            source: self.previous.source,
            head: self.head,
        };
        view.check_head(&self.rows[0].receipt.scope.tenant)?;
        Ok(view)
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl View {
    pub(crate) fn fixture_owner(
        &self,
        disk: &Arc<ScratchDisk>,
        state: &TenantState,
    ) -> Result<Self> {
        if self.source.is_some() {
            return Ok(self.clone());
        }
        ensure!(self.head.count == 0, "fixture receipt prefix has no owner");
        let table = Arc::new(EncryptedTable::new(
            disk,
            scratch_limit(state.limits.max_mutation_receipt_bytes)?,
        )?);
        Ok(Self {
            source: Some(Arc::new(Source::Staged(table))),
            head: self.head.clone(),
        })
    }
}

#[cfg(test)]
#[path = "mutation_receipt_tests.rs"]
mod tests;
