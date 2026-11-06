//! Permanent ordinary mutation outcomes, selected by one applied generation.
//! No expiry or resident lifetime map exists. Point reads use short transactions;
//! a row beyond the selected ordinal cannot prove that its command was applied.
use crate::namespace_installation::PreparedRows;
use crate::staged_terminal::AppliedIdentity;
#[cfg(any(test, feature = "test-utils"))]
use crate::staged_terminal::AppliedOrigin;
use anyhow::{Context, Result, ensure};
use kasumi_store::{EncryptedTable, EncryptedTableBatch, ScratchDisk, TenantStore, WriteOp};
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// A single admitted batch has at most 256 bounded names/IDs and contains no
// document Value in its receipt. This is a per-record format bound, not a lifetime cap.
const MAX_ROW_BYTES: usize = 2 << 20;
pub(crate) const MAX_SNAPSHOT_RECORD_BYTES: usize = MAX_ROW_BYTES;
const CATALOG: &str = "mutation-receipt-catalog";
pub(crate) fn scratch_limit(canonical_bytes: u64) -> Result<u64> {
    // Bound temporary working copies, indexes and commit overhead separately
    // from the canonical receipt quota; some histories can still exhaust it.
    canonical_bytes
        .checked_mul(16)
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
        // Record::Receipt's exact encoding, borrowed: measuring a row never
        // copies its collection and version lists.
        #[derive(Serialize)]
        #[serde(tag = "type", content = "value")]
        enum Framing<'a> {
            Receipt(&'a Row),
        }
        let bytes = crate::accounting::encoded_len(&Framing::Receipt(self))?;
        ensure!(
            bytes <= MAX_ROW_BYTES,
            "receipt exceeds canonical per-record budget"
        );
        (bytes as u64)
            .checked_add(crate::snapshot_codec::FRAME_HEADER_BYTES as u64)
            .context("receipt canonical length overflow")
    }
    /// Returns the row's framed snapshot bytes, which validation measures.
    pub(crate) fn validate(&self, state: &TenantState) -> Result<u64> {
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

        self.framed_bytes()
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
    fn get(&self, key: &[u8]) -> Result<Option<crate::materialization_row::MaterializationRow>> {
        let result = match self {
            Self::Durable(rows) => rows
                .store
                .get_bounded(&rows.binding.namespace(), key, MAX_ROW_BYTES)?
                .map(crate::materialization_row::MaterializationRow::Stored),
            Self::Staged(table) => table
                .get(key)?
                .map(crate::materialization_row::MaterializationRow::Staged),
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
pub(crate) enum Lookup {
    Found(Box<Row>),
    Absent(Absent),
}
/// One view found no row for `key` at `head`. A view at the same head shows
/// the same rows, so an append there needs no second point read.
pub(crate) struct Absent {
    key: String,
    head: MutationReceiptHead,
}

/// This owner retains immutable rows, not an open KV read transaction. The
/// selected count/root remain unchanged while new rows append to the namespace.
#[derive(Clone)]
pub(crate) struct View {
    source: Option<Arc<Source>>,
    head: MutationReceiptHead,
}
impl View {
    /// Whether this view's next receipt pair joins its publication, as
    /// `Pending::prepare_publication` would choose for a row of at most
    /// `PreparedPublication::MAX_ROW` bytes.
    pub(crate) fn joins_publication(&self) -> Result<bool> {
        Ok(match self.source.as_deref() {
            Some(Source::Durable(storage)) => {
                storage.store.record_encryption_overhead()?
                    <= PreparedPublication::MAX_ENCRYPTION_OVERHEAD
            }
            _ => false,
        })
    }
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
    fn bytes(&self, key: &[u8]) -> Result<Option<crate::materialization_row::MaterializationRow>> {
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
    fn check_head_metadata(&self, tenant: &str) -> Result<()> {
        validate_name(&self.head.origin_incarnation)?;
        ensure!(digest(&self.head.sha256), "invalid receipt head digest");
        if self.head.count == 0 {
            ensure!(
                self.head == MutationReceiptHead::empty(tenant, &self.head.origin_incarnation)?,
                "nonempty receipt accounting without rows"
            );
        } else {
            ensure!(
                self.head.encoded_bytes > 0 && self.head.last_applied_revision > 0,
                "receipt physical prefix differs from selected root"
            );
        }
        Ok(())
    }
    pub(crate) fn check_head(&self, tenant: &str) -> Result<()> {
        self.check_head_metadata(tenant)?;
        if self.head.count > 0 {
            ensure!(
                self.index(self.head.count)?.sha256 == self.head.sha256,
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
    /// A miss also proves the identity is free to append at this exact head.
    pub(crate) fn lookup(&self, key: &str) -> Result<Lookup> {
        Ok(match self.get(key)? {
            Some(row) => Lookup::Found(Box::new(row)),
            None => Lookup::Absent(Absent {
                key: key.to_owned(),
                head: self.head.clone(),
            }),
        })
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
    batch: Option<EncryptedTableBatch>,
    batch_bytes: usize,
    batch_rows: usize,
    head: MutationReceiptHead,
    failed: bool,
}
// Fixed phase labels correlate real receipt work with the fixture lease log.
#[cfg(any(test, feature = "test-utils"))]
fn observe_staging(phase: &'static str, ordinal: Option<u64>, succeeded: Option<bool>) {
    if std::env::var_os("KASUMI_TEST_METADATA_LEASE_TRACE").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return;
    }
    use std::io::Write as _;
    let _ = writeln!(
        std::io::stderr().lock(),
        "receipt_staging phase={phase} ordinal={ordinal:?} succeeded={succeeded:?}",
    );
}
impl Builder {
    // Bound unpublished work independently of the stream's permanent history.
    const BATCH_BYTES: usize = EncryptedTableBatch::MAX_BYTES;
    const BATCH_ROWS: usize = EncryptedTableBatch::MAX_ENTRIES / 2;

    pub(crate) fn new(
        disk: &Arc<ScratchDisk>,
        limit: u64,
        tenant: &str,
        origin: &str,
    ) -> std::result::Result<Self, kasumi_store::ScratchOperationFailure> {
        #[cfg(any(test, feature = "test-utils"))]
        observe_staging("setup_entered", None, None);
        let table = EncryptedTable::new(disk, limit, disk.native_cache_config());
        #[cfg(any(test, feature = "test-utils"))]
        observe_staging("setup_returned", None, Some(table.is_ok()));
        let table = Arc::new(table?);
        let batch = table
            .begin_batch()
            .map_err(kasumi_store::ScratchOperationFailure::Operation)?;
        Ok(Self {
            table,
            batch: Some(batch),
            batch_bytes: 0,
            batch_rows: 0,
            head: MutationReceiptHead::empty(tenant, origin).map_err(|original| {
                kasumi_store::ScratchOperationFailure::Operation(original.into())
            })?,
            failed: false,
        })
    }
    pub(crate) fn push(&mut self, row: &Row, state: &TenantState) -> Result<()> {
        ensure!(!self.failed, "receipt staging builder previously failed");
        // Neither a partial row/index pair nor an advanced private head can
        // become a verified view after any failed or unwinding push.
        self.failed = true;
        #[cfg(any(test, feature = "test-utils"))]
        observe_staging("row_entered", Some(row.ordinal), None);
        let framed_bytes = row.validate(state)?;
        advance_framed(&mut self.head, row, framed_bytes)?;
        let index = Ordinal {
            key: row.key.clone(),
            sha256: row.sha256()?,
        };
        let id = id_key(&row.key);
        let ordinal = ordinal_key(row.ordinal);
        let encoded_row = serde_json::to_vec(row)?;
        let encoded_index = serde_json::to_vec(&index)?;
        let bytes = id
            .len()
            .checked_add(ordinal.len())
            .and_then(|n| n.checked_add(encoded_row.len()))
            .and_then(|n| n.checked_add(encoded_index.len()))
            .context("receipt staging batch byte overflow")?;
        ensure!(
            bytes <= Self::BATCH_BYTES,
            "receipt row exceeds staging batch"
        );
        if self.batch_rows == Self::BATCH_ROWS
            || self
                .batch_bytes
                .checked_add(bytes)
                .is_none_or(|total| total > Self::BATCH_BYTES)
        {
            self.batch
                .take()
                .context("receipt staging batch missing")?
                .commit()
                .with_context(|| {
                    format!(
                        "receipt staging batch commit failed before ordinal {} (rows={}, bytes={})",
                        row.ordinal, self.batch_rows, self.batch_bytes
                    )
                })?;
            self.batch = Some(self.table.begin_batch()?);
            self.batch_bytes = 0;
            self.batch_rows = 0;
        }
        let batch = self
            .batch
            .as_mut()
            .context("receipt staging batch missing")?;
        #[cfg(any(test, feature = "test-utils"))]
        observe_staging("point_write_entered", Some(row.ordinal), None);
        batch.insert(&id, &encoded_row)?;
        #[cfg(any(test, feature = "test-utils"))]
        observe_staging("ordinal_write_entered", Some(row.ordinal), None);
        batch.insert(&ordinal, &encoded_index)?;
        self.batch_bytes += bytes;
        self.batch_rows += 1;
        self.failed = false;
        #[cfg(any(test, feature = "test-utils"))]
        observe_staging("row_returned", Some(row.ordinal), Some(true));
        Ok(())
    }
    pub(crate) fn finish(self, expected: &MutationReceiptHead) -> Result<View> {
        ensure!(!self.failed, "receipt staging builder previously failed");
        ensure!(
            &self.head == expected,
            "receipt stream final root/count/bytes differ"
        );
        self.batch
            .context("receipt staging batch missing")?
            .commit()
            .with_context(|| {
                format!(
                    "receipt staging final batch commit failed at ordinal {} (rows={}, bytes={})",
                    self.head.count, self.batch_rows, self.batch_bytes
                )
            })?;
        Ok(View {
            source: Some(Arc::new(Source::Staged(self.table))),
            head: self.head,
        })
    }
}
pub(crate) fn advance(head: &mut MutationReceiptHead, row: &Row) -> Result<()> {
    advance_framed(head, row, row.framed_bytes()?)
}
fn advance_framed(head: &mut MutationReceiptHead, row: &Row, framed_bytes: u64) -> Result<()> {
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
        .checked_add(framed_bytes)
        .context("receipt permanent byte overflow")?;
    head.count = row.ordinal;
    head.last_applied_revision = row.applied.revision;
    head.sha256 = row.sha256()?;
    Ok(())
}

fn checkpoint_binding(
    store: &TenantStore,
    checkpoint_sha256: &str,
) -> Result<Option<NamespaceBinding>> {
    store
        .get_bounded(CATALOG, checkpoint_sha256.as_bytes(), 64 << 10)?
        .map(|bytes| {
            let binding: NamespaceBinding = serde_json::from_slice(&bytes)?;
            ensure!(
                serde_json::to_vec(&binding)? == bytes,
                "noncanonical receipt checkpoint binding"
            );
            Ok::<NamespaceBinding, anyhow::Error>(binding)
        })
        .transpose()
}

/// A reopening replica decodes its own snapshot, whose receipt rows are
/// already durable under the snapshot's checkpoint binding. Each decoded row
/// is validated, chained, and compared with its durable point and ordinal rows
/// through one read view. Staging every row in scratch, re-reading it for
/// validation and comparing it again at installation took minutes on a
/// standalone node's reopen.
pub(crate) struct DurableReopen {
    store: Arc<TenantStore>,
    binding: NamespaceBinding,
    namespace: String,
    reader: kasumi_store::TenantReadView,
    head: MutationReceiptHead,
    failed: bool,
}
impl DurableReopen {
    /// `None` when the store holds no binding for this checkpoint: the caller
    /// stages instead, and installation reports the missing binding.
    pub(crate) fn open(
        store: &Arc<TenantStore>,
        checkpoint_sha256: &str,
        tenant: &str,
        incarnation: &str,
        origin: &str,
    ) -> Result<Option<Self>> {
        ensure!(
            digest(checkpoint_sha256) && store.tenant() == tenant,
            "receipt reopen identity differs"
        );
        let Some(binding) = checkpoint_binding(store, checkpoint_sha256)? else {
            return Ok(None);
        };
        ensure!(
            binding.tenant == tenant
                && binding.incarnation == incarnation
                && binding.checkpoint_sha256 == checkpoint_sha256
                && binding.checkpoint_head.origin_incarnation == origin
                && !binding.namespace.is_nil(),
            "receipt checkpoint binding differs"
        );
        Ok(Some(Self {
            namespace: binding.namespace(),
            reader: store.read_view()?,
            store: store.clone(),
            binding,
            head: MutationReceiptHead::empty(tenant, origin)?,
            failed: false,
        }))
    }
    /// The checks `Builder::push` makes, then the durable point row must be
    /// this exact row and its ordinal commitment must name it. The parent
    /// link follows from the decoded chain and the previous ordinal checked
    /// here; `finish` checks the selected root.
    pub(crate) fn push(&mut self, row: &Row, state: &TenantState) -> Result<()> {
        ensure!(
            !self.failed,
            "receipt reopen verification previously failed"
        );
        self.failed = true;
        let framed_bytes = row.validate(state)?;
        advance_framed(&mut self.head, row, framed_bytes)?;
        let point = self
            .reader
            .get(&self.namespace, &id_key(&row.key), MAX_ROW_BYTES)?
            .context("checkpoint receipt row missing")?;
        let durable: Row = serde_json::from_slice(point.as_bytes())?;
        crate::current_json::require_current_writer_bytes(
            point.as_bytes(),
            &durable,
            "receipt point",
        )?;
        ensure!(
            durable.key == row.key && durable.sha256()? == self.head.sha256,
            "checkpoint receipt physical row differs"
        );
        let ordinal = self
            .reader
            .get(&self.namespace, &ordinal_key(row.ordinal), MAX_ROW_BYTES)?
            .context("checkpoint receipt ordinal missing")?;
        let entry: Ordinal = serde_json::from_slice(ordinal.as_bytes())?;
        crate::current_json::require_current_writer_bytes(
            ordinal.as_bytes(),
            &entry,
            "receipt ordinal",
        )?;
        ensure!(
            entry.key == row.key && entry.sha256 == self.head.sha256,
            "checkpoint receipt ordinal differs"
        );
        self.failed = false;
        Ok(())
    }
    /// The durable view at the checkpoint, exactly as reopen installation
    /// selects it, once the stream's final head matches the binding.
    pub(crate) fn finish(self, expected: &MutationReceiptHead) -> Result<View> {
        ensure!(
            !self.failed,
            "receipt reopen verification previously failed"
        );
        ensure!(
            &self.head == expected,
            "receipt stream final root/count/bytes differ"
        );
        ensure!(
            self.binding.checkpoint_head == self.head,
            "receipt checkpoint binding differs"
        );
        self.reader.close()?;
        let tenant = self.binding.tenant.clone();
        let view = View {
            source: Some(Arc::new(Source::Durable(DurableRows {
                store: self.store,
                binding: self.binding,
            }))),
            head: self.head,
        };
        view.check_head(&tenant)?;
        Ok(view)
    }
}

/// Prepared namespace activation. The coordinator commits replacements and
/// catalog writes with the enclosing checkpoint/applied cursor before publishing
/// `view`. Dropping this object leaves only encrypted temporary staging.
pub(crate) struct Installation {
    replacement: Option<PreparedRows>,
    namespace: String,
    writes: Vec<WriteOp>,
    pub(crate) view: View,
}
impl Installation {
    pub(crate) fn replacements(&self) -> Vec<kasumi_store::NamespaceReplacement<'_>> {
        self.replacement
            .as_ref()
            .map(|rows| vec![rows.replacement(&self.namespace)])
            .unwrap_or_default()
    }
    pub(crate) fn writes(&self) -> &[WriteOp] {
        &self.writes
    }
}
impl View {
    /// Whether this view reads exactly `binding`'s rows in `store`.
    fn is_durable(&self, store: &Arc<TenantStore>, binding: &NamespaceBinding) -> bool {
        matches!(self.source.as_deref(), Some(Source::Durable(rows))
            if Arc::ptr_eq(&rows.store, store) && &rows.binding == binding)
    }
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
        let selected = checkpoint_binding(store, checkpoint_sha256)?;
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
            // A view decoded by `DurableReopen` already compared every row
            // with exactly these durable rows.
            if !self.is_durable(store, &binding) {
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
            }
            return Ok(Installation {
                replacement: None,
                namespace: binding.namespace(),
                writes: vec![],
                view,
            });
        }
        let replacement = match self.source.as_deref() {
            Some(Source::Staged(table)) => PreparedRows::Staged(table.clone()),
            None if self.head.count == 0 => PreparedRows::Empty,
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

/// Private prospective immutable receipt writes. The selected View has only
/// its ordinary namespace/head; these bytes and their credit stay with apply.
/// The exact pair joins custody publication or uses the original staging path.
pub(crate) struct PreparedPublication {
    writes: Vec<WriteOp>,
    source: Arc<Source>,
    head: MutationReceiptHead,
    tenant: String,
    // Last: all encoded row/key/vector backing retires before its real credit.
    _workspace: crate::admission::DocumentWorkspace,
}
impl PreparedPublication {
    const MAX_ROW: usize = 64 << 10;
    const MAX_ENCRYPTION_OVERHEAD: usize = 512;
    // At most 320 KiB of private preparation, then 192 KiB retained alongside
    // one <=64 KiB encrypted row, its small index, native staging chunks and
    // one transient encryption output. Commit moves staged values uncopied.
    // The common planner/capture work remains in the existing base escrow.
    pub(crate) const MAX_WORKSPACE: u64 = 1 << 20;

    pub(crate) fn require_view(&self, view: &View) -> Result<()> {
        ensure!(
            view.head == self.head
                && view
                    .source
                    .as_ref()
                    .is_some_and(|source| Arc::ptr_eq(source, &self.source)),
            "private receipt publication differs from candidate"
        );
        Ok(())
    }

    /// A deliberately bounded optimization, not a new acceptance limit.
    /// In this ordinary-entry shape custody adds only its <=2 MiB applied row.
    /// 32 body puts + 2 receipt puts + 1 cursor put stay below 64 MiB logical
    /// and 96 MiB physical even for the <2 MiB active IDs allowed by catalogs.
    pub(crate) fn can_join(
        position: &kasumi_raft::AppliedEntryContext,
        documents: &[WriteOp],
    ) -> bool {
        if position.retirement_seed.is_some()
            || *position.membership.log_id() == Some(position.log_id)
            || documents.len() > 32
        {
            return false;
        }
        let bytes = documents.iter().try_fold(0usize, |bytes, operation| {
            let WriteOp::Put {
                namespace,
                key,
                value,
            } = operation
            else {
                return None;
            };
            // Only the actual immutable body producer may use this bound.
            if !matches!(
                namespace.as_str(),
                crate::document_store::BODIES | crate::document_store::BLOBS
            ) {
                return None;
            }
            bytes
                .checked_add(namespace.len())?
                .checked_add(key.len())?
                .checked_add(value.len())
        });
        bytes.is_some_and(|bytes| bytes <= 1 << 20)
    }

    pub(crate) fn append_to(&mut self, writes: &mut Vec<WriteOp>) -> Result<()> {
        // The <=32-entry destination's reallocation/shell overlap is covered
        // by this owner's 64 KiB floor. Payloads move once, never clone.
        writes.try_reserve_exact(self.writes.len())?;
        writes.append(&mut self.writes);
        Ok(())
    }

    pub(crate) fn stage_separately(self) -> Result<()> {
        let Source::Durable(storage) = self.source.as_ref() else {
            anyhow::bail!("private receipt publication lacks durable storage");
        };
        storage.store.write_batch(&self.writes)?;
        View {
            source: Some(self.source.clone()),
            head: self.head.clone(),
        }
        .check_head(&self.tenant)
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
        receipt: Option<(StoredReceipt, &Absent)>,
        applied: &AppliedIdentity,
    ) -> Result<Self> {
        ensure!(
            previous.head == state.mutation_receipt_head,
            "receipt starting prefix differs"
        );
        let mut head = previous.head.clone();
        let mut rows = Vec::new();
        if let Some((receipt, absent)) = receipt {
            let key = staged_digest(&(&receipt.scope.principal, &receipt.idempotency_key))?.0;
            ensure!(
                absent.key == key && absent.head == previous.head,
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
            let framed_bytes = row.validate(state)?;
            advance_framed(&mut head, &row, framed_bytes)?;
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
    /// Prepare a small pair without writing it. The only returned prospective
    /// View remains private to the command/accepted apply until its bound pair
    /// crosses the same publisher as the selected applied cursor.
    pub(crate) fn prepare_publication(
        self,
        roots: &crate::application_sources::SourceRootsRef,
    ) -> Result<(View, Option<PreparedPublication>)> {
        use crate::admission::RetainedWorkspace as _;
        if self.rows.is_empty() {
            return Ok((self.previous, None));
        }
        ensure!(
            self.rows.len() == 1,
            "ordinary receipt publication has multiple rows"
        );
        let Some(Source::Durable(storage)) = self.previous.source.as_deref() else {
            return Ok((self.stage()?, None));
        };
        ensure!(
            Arc::ptr_eq(&storage.store, roots.primary_installation().0.application()),
            "receipt publication belongs to another application store"
        );
        // A large imported key identifier is repeated in every ciphertext.
        // Keep its native staging overlap on the original separate-commit path.
        if storage.store.record_encryption_overhead()?
            > PreparedPublication::MAX_ENCRYPTION_OVERHEAD
        {
            return Ok((self.stage()?, None));
        }
        let row = &self.rows[0];
        let length = crate::accounting::encoded_len(row)?;
        if length > PreparedPublication::MAX_ROW {
            return Ok((self.stage()?, None));
        }
        let mut workspace = crate::admission::DocumentWorkspace::new(
            roots.primary_installation().1,
            4 * length as u64 + (64 << 10),
        )?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length)?;
        ensure!(
            bytes.capacity() <= 2 * length + 4096,
            "receipt allocation exceeds admission"
        );
        serde_json::to_writer(&mut bytes, row)?;
        ensure!(bytes.len() == length, "receipt encoded length changed");
        let index = serde_json::to_vec(&Ordinal {
            key: row.key.clone(),
            sha256: row.sha256()?,
        })?;
        let id = id_key(&row.key);
        let ordinal = ordinal_key(row.ordinal);
        let source = self
            .previous
            .source
            .as_ref()
            .expect("checked durable receipt source");
        // Preserve the old ahead-pair reconciliation exactly, including corrupt
        // oversized values and a half pair. Never overwrite or ignore either.
        match (source.get(&id)?, source.get(&ordinal)?) {
            (Some(old_row), Some(old_index)) => {
                ensure!(
                    old_row == bytes && old_index == index,
                    "future receipt row differs from exact original command replay"
                );
                let view = View {
                    source: self.previous.source,
                    head: self.head,
                };
                view.check_head(&row.receipt.scope.tenant)?;
                return Ok((view, None));
            }
            (None, None) => {}
            _ => anyhow::bail!("partially published receipt row/index"),
        }
        ensure!(
            row.ordinal == self.head.count && row.sha256()? == self.head.sha256,
            "prospective receipt head differs from immutable pair"
        );
        let tenant = row.receipt.scope.tenant.clone();
        let namespace = storage.binding.namespace();
        let writes = vec![
            WriteOp::put(namespace.clone(), id, bytes),
            WriteOp::put(namespace, ordinal, index),
        ];
        workspace.retain(2 * length as u64 + (64 << 10));
        let publication = PreparedPublication {
            writes,
            source: source.clone(),
            head: self.head.clone(),
            tenant,
            _workspace: workspace,
        };
        let view = View {
            source: self.previous.source,
            head: self.head,
        };
        view.check_head_metadata(&publication.tenant)?;
        publication.require_view(&view)?;
        Ok((view, Some(publication)))
    }

    /// Preserve immutable row/index pairs before selecting the returned view.
    /// An exact replay may reuse this durable prefix after publication fails.
    pub(crate) fn stage(self) -> Result<View> {
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
                    let id = id_key(&row.key);
                    let ordinal = ordinal_key(row.ordinal);
                    let bytes = serde_json::to_vec(row)?;
                    let index = serde_json::to_vec(&Ordinal {
                        key: row.key.clone(),
                        sha256: row.sha256()?,
                    })?;
                    match (source.get(&id)?, source.get(&ordinal)?) {
                        (Some(old_row), Some(old_index)) => ensure!(
                            old_row == bytes && old_index == index,
                            "future receipt row differs from exact original command replay"
                        ),
                        (None, None) => {
                            let mut pair = table.begin_batch()?;
                            pair.insert(&id, &bytes)?;
                            pair.insert(&ordinal, &index)?;
                            pair.commit()?;
                        }
                        _ => anyhow::bail!("partially published receipt row/index"),
                    }
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
    ) -> std::result::Result<Self, kasumi_store::ScratchOperationFailure> {
        if self.source.is_some() {
            return Ok(self.clone());
        }
        kasumi_store::ScratchOperationFailure::ordinary(|| {
            ensure!(self.head.count == 0, "fixture receipt prefix has no owner");
            Ok(())
        })?;
        let table = Arc::new(EncryptedTable::new(
            disk,
            scratch_limit(state.limits.max_mutation_receipt_bytes)
                .map_err(kasumi_store::ScratchOperationFailure::Operation)?,
            disk.native_cache_config(),
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
