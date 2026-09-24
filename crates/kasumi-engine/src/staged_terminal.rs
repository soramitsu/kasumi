//! Immutable terminal transaction rows. A logical view selects a prefix; durable
//! rows beyond that prefix are never evidence that their command was applied.
//! Reads open short point transactions and do not pin unrelated redb pages.
use anyhow::{Context, Result, ensure};
use kasumi_store::{EncryptedTable, EncryptedTableBatch, ScratchDisk, TenantStore, WriteOp};
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const MAX_ROW_BYTES: usize = 2 << 20;
pub(crate) const MAX_SNAPSHOT_RECORD_BYTES: usize = MAX_ROW_BYTES;
const CATALOG: &str = "staged-terminal-catalog";
pub(crate) fn scratch_limit(canonical_bytes: u64) -> Result<u64> {
    canonical_bytes
        .checked_mul(8)
        .and_then(|n| n.checked_add(64 << 20))
        .context("terminal scratch table budget overflow")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum AppliedOrigin {
    Raft {
        term: u64,
        leader: u64,
        index: u64,
        context_sha256: String,
    },
    #[cfg(any(test, feature = "test-utils"))]
    Fixture,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AppliedIdentity {
    pub incarnation: String,
    pub revision: u64,
    pub timestamp_ms: u64,
    pub command_sha256: String,
    pub origin: AppliedOrigin,
}
impl AppliedIdentity {
    pub(crate) fn ordered(
        incarnation: &str,
        revision: u64,
        timestamp_ms: u64,
        position: &kasumi_raft::AppliedEntryContext,
    ) -> Result<Self> {
        let result = Self {
            incarnation: incarnation.into(),
            revision,
            timestamp_ms,
            command_sha256: position.command_sha256.clone(),
            origin: AppliedOrigin::Raft {
                term: position.log_id.leader_id.term,
                leader: position.log_id.leader_id.node_id,
                index: position.log_id.index,
                context_sha256: staged_digest(&(
                    "kasumi.staged-terminal-applied.v1",
                    &position.log_id,
                    &position.previous,
                    &position.membership,
                    &position.command_sha256,
                ))?
                .0,
            },
        };
        result.validate()?;
        Ok(result)
    }
    /// Validate an immutable applied position against the retained original
    /// incarnation, including the strict post-genesis lower bound after restore.
    pub(crate) fn validate_original_position(&self, state: &TenantState) -> Result<(u64, u64)> {
        self.validate()?;
        let (genesis_revision, bound) = if self.incarnation == state.incarnation {
            (state.revision_base, state.revision)
        } else {
            let bound = state
                .restore_lineage
                .iter()
                .find(|link| link.checkpoint.source_incarnation == self.incarnation)
                .context("terminal applied incarnation is outside retained lineage")?
                .checkpoint
                .revision;
            let genesis = state
                .restore_lineage
                .iter()
                .find(|link| link.target_incarnation == self.incarnation)
                .map(|link| {
                    link.checkpoint
                        .revision
                        .checked_add(1)
                        .context("terminal applied genesis revision overflow")
                })
                .transpose()?
                .unwrap_or(0);
            (genesis, bound)
        };
        ensure!(
            self.revision > genesis_revision && self.revision <= bound,
            "terminal applied revision is outside its original incarnation"
        );
        match &self.origin {
            AppliedOrigin::Raft { index, .. } => {
                ensure!(
                    genesis_revision.checked_add(*index) == Some(self.revision),
                    "terminal Raft position differs from original incarnation revision"
                );
            }
            #[cfg(any(test, feature = "test-utils"))]
            AppliedOrigin::Fixture => {}
        }
        Ok((genesis_revision, bound))
    }

    fn validate(&self) -> Result<()> {
        validate_name(&self.incarnation)?;
        ensure!(
            self.revision > 0 && digest(&self.command_sha256),
            "invalid terminal applied identity"
        );
        match &self.origin {
            AppliedOrigin::Raft {
                index,
                context_sha256,
                ..
            } => {
                ensure!(
                    *index > 0 && *index <= self.revision && digest(context_sha256),
                    "invalid terminal Raft binding"
                );
            }
            #[cfg(any(test, feature = "test-utils"))]
            AppliedOrigin::Fixture => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Row {
    pub ordinal: u64,
    pub key: String,
    pub previous_sha256: String,
    pub applied: AppliedIdentity,
    pub stage: StagedTransaction,
}
impl Row {
    pub(crate) fn sha256(&self) -> Result<String> {
        Ok(staged_digest(&("kasumi.staged-terminal-row.v1", self))?.0)
    }
    pub(crate) fn framed_bytes(&self) -> Result<u64> {
        let size = crate::accounting::encoded_len(&crate::snapshot_codec::Record::Terminal(
            Box::new(self.clone()),
        ))?;
        ensure!(
            size <= MAX_ROW_BYTES,
            "terminal row exceeds canonical record budget"
        );
        u64::try_from(size)?
            .checked_add(crate::snapshot_codec::FRAME_HEADER_BYTES as u64)
            .context("terminal row length overflow")
    }
    pub(crate) fn validate(&self, state: &TenantState) -> Result<()> {
        ensure!(
            self.ordinal > 0 && digest(&self.key) && digest(&self.previous_sha256),
            "invalid terminal chain identity"
        );
        self.applied.validate()?;
        ensure!(
            !self.stage.is_active()
                && self.stage.chunks.is_empty()
                && !crate::state::staging::validate_snapshot_record(
                    &self.key,
                    &self.stage,
                    state,
                    &Default::default(),
                )?,
            "terminal row contains a live upload"
        );
        self.applied.validate_original_position(state)?;
        let receipt = match &self.stage.outcome {
            StagedOutcome::Finished {
                outcome: Ok(receipt),
            }
            | StagedOutcome::Aborted { receipt }
            | StagedOutcome::Expired { receipt } => Some(receipt),
            _ => None,
        };
        if let Some(receipt) = receipt {
            ensure!(
                receipt.revision == self.applied.revision,
                "terminal receipt differs from original applying revision"
            );
        }
        self.framed_bytes()?;
        Ok(())
    }
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
    checkpoint_head: StagedTerminalHead,
}
impl NamespaceBinding {
    fn namespace(&self) -> String {
        format!("staged-terminal-{}", self.namespace)
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
            "terminal physical row exceeds bound"
        );
        Ok(result)
    }
}
/// This owner retains immutable rows, not an open redb read transaction. The
/// selected count/root remain unchanged while new rows append to the namespace.
#[derive(Clone)]
pub(crate) struct View {
    source: Option<Arc<Source>>,
    head: StagedTerminalHead,
}
impl std::fmt::Debug for View {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalView")
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}
impl View {
    pub(crate) fn empty(tenant: &str, incarnation: &str) -> Result<Self> {
        Ok(Self {
            source: None,
            head: StagedTerminalHead::empty(tenant, incarnation)?,
        })
    }
    pub(crate) fn head(&self) -> &StagedTerminalHead {
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
            "terminal ordinal is outside selected generation"
        );
        let bytes = self
            .bytes(&ordinal_key(ordinal))?
            .context("terminal ordinal missing")?;
        let entry: Ordinal = serde_json::from_slice(&bytes)?;
        crate::current_json::require_current_writer_bytes(
            &bytes,
            &entry,
            "staged terminal ordinal",
        )?;
        ensure!(
            digest(&entry.key) && digest(&entry.sha256),
            "invalid terminal ordinal index"
        );
        Ok(entry)
    }
    pub(crate) fn check_head(&self, tenant: &str) -> Result<()> {
        validate_name(&self.head.origin_incarnation)?;
        ensure!(digest(&self.head.sha256), "invalid terminal head digest");
        if self.head.count == 0 {
            ensure!(
                self.head == StagedTerminalHead::empty(tenant, &self.head.origin_incarnation)?,
                "nonempty terminal accounting without rows"
            );
        } else {
            ensure!(
                self.head.encoded_bytes > 0
                    && self.index(self.head.count)?.sha256 == self.head.sha256,
                "terminal physical prefix differs from selected root"
            );
        }
        Ok(())
    }
    pub(crate) fn validate_state(&self, state: &TenantState) -> Result<()> {
        self.check_head(&state.tenant)?;
        ensure!(
            self.head == state.staged_terminal_head
                && (self.head.origin_incarnation == state.incarnation
                    || state
                        .restore_lineage
                        .iter()
                        .any(|link| link.checkpoint.source_incarnation
                            == self.head.origin_incarnation)),
            "terminal history origin is outside retained lineage"
        );
        Ok(())
    }
    pub(crate) fn get(&self, key: &str) -> Result<Option<Row>> {
        self.get_charged(key, |_| Ok(()))
    }
    pub(crate) fn get_charged(
        &self,
        key: &str,
        reserve_decoded: impl FnOnce(usize) -> Result<()>,
    ) -> Result<Option<Row>> {
        ensure!(digest(key), "invalid staged point identity");
        let Some(bytes) = self.bytes(&id_key(key))? else {
            return Ok(None);
        };
        reserve_decoded(bytes.len())?;
        let row: Row = serde_json::from_slice(&bytes)?;
        // A commit may have persisted a row before its applied cursor. It remains
        // invisible until exact replay advances this logical view's prefix.
        if row.ordinal > self.head.count {
            return Ok(None);
        }
        crate::current_json::require_current_writer_bytes(&bytes, &row, "staged terminal point")?;
        ensure!(
            row.key == key && row.ordinal > 0,
            "terminal point identity differs"
        );
        let index = self.index(row.ordinal)?;
        ensure!(
            index.key == key && index.sha256 == row.sha256()?,
            "terminal row differs from ordinal commitment"
        );
        if row.ordinal == 1 {
            ensure!(
                row.previous_sha256
                    == StagedTerminalHead::empty(
                        &row.stage.scope.tenant,
                        &self.head.origin_incarnation
                    )?
                    .sha256,
                "terminal initial root differs"
            );
        } else {
            ensure!(
                row.previous_sha256 == self.index(row.ordinal - 1)?.sha256,
                "terminal parent root differs"
            );
        }
        ensure!(
            self.index(self.head.count)?.sha256 == self.head.sha256,
            "terminal selected root differs"
        );
        Ok(Some(row))
    }
    pub(crate) fn row(&self, ordinal: u64) -> Result<Row> {
        let key = self.index(ordinal)?.key;
        let row = self.get(&key)?.context("terminal indexed row missing")?;
        ensure!(row.ordinal == ordinal, "terminal ordinal redirected");
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
    head: StagedTerminalHead,
    failed: bool,
}
impl Builder {
    // Keep uncommitted scratch work bounded independently of the full stream.
    // The table itself has an admitted disk owner and an 8 MiB redb page cache.
    const BATCH_BYTES: usize = EncryptedTableBatch::MAX_BYTES;
    const BATCH_ROWS: usize = EncryptedTableBatch::MAX_ENTRIES / 2;

    pub(crate) fn new(
        disk: &Arc<ScratchDisk>,
        limit: u64,
        tenant: &str,
        origin: &str,
    ) -> Result<Self> {
        let table = Arc::new(EncryptedTable::new(disk, limit)?);
        let batch = table.begin_batch()?;
        Ok(Self {
            table,
            batch: Some(batch),
            batch_bytes: 0,
            batch_rows: 0,
            head: StagedTerminalHead::empty(tenant, origin)?,
            failed: false,
        })
    }
    pub(crate) fn push(&mut self, row: &Row, state: &TenantState) -> Result<()> {
        ensure!(!self.failed, "terminal staging builder previously failed");
        // A failed or unwinding push may already have changed the private head
        // or persisted the identity without its ordinal. Neither can be exposed
        // as a verified view, even if the requested final head happens to match.
        self.failed = true;
        row.validate(state)?;
        advance(&mut self.head, row)?;
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
            .context("terminal staging batch byte overflow")?;
        ensure!(
            bytes <= Self::BATCH_BYTES,
            "terminal row exceeds staging batch"
        );
        if self.batch_rows == Self::BATCH_ROWS
            || self
                .batch_bytes
                .checked_add(bytes)
                .is_none_or(|total| total > Self::BATCH_BYTES)
        {
            self.batch
                .take()
                .context("terminal staging batch missing")?
                .commit()?;
            self.batch = Some(self.table.begin_batch()?);
            self.batch_bytes = 0;
            self.batch_rows = 0;
        }
        let batch = self
            .batch
            .as_mut()
            .context("terminal staging batch missing")?;
        batch.insert(&id, &encoded_row)?;
        batch.insert(&ordinal, &encoded_index)?;
        self.batch_bytes += bytes;
        self.batch_rows += 1;
        self.failed = false;
        Ok(())
    }
    pub(crate) fn finish(self, expected: &StagedTerminalHead) -> Result<View> {
        ensure!(!self.failed, "terminal staging builder previously failed");
        ensure!(
            &self.head == expected,
            "terminal stream final root/count/bytes differ"
        );
        self.batch
            .context("terminal staging batch missing")?
            .commit()?;
        Ok(View {
            source: Some(Arc::new(Source::Staged(self.table))),
            head: self.head,
        })
    }
}
pub(crate) fn advance(head: &mut StagedTerminalHead, row: &Row) -> Result<()> {
    ensure!(
        row.ordinal
            == head
                .count
                .checked_add(1)
                .context("terminal ordinal exhausted")?
            && row.previous_sha256 == head.sha256,
        "terminal row is not the next committed prefix"
    );
    head.encoded_bytes = head
        .encoded_bytes
        .checked_add(row.framed_bytes()?)
        .context("terminal permanent byte overflow")?;
    head.count = row.ordinal;
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
            "invalid terminal checkpoint digest"
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
                && self.head == state.staged_terminal_head,
            "terminal installation identity differs"
        );
        self.check_head(&state.tenant)?;
        let selected = store
            .get_bounded(CATALOG, checkpoint_sha256.as_bytes(), 64 << 10)?
            .map(|bytes| {
                let binding: NamespaceBinding = serde_json::from_slice(&bytes)?;
                ensure!(
                    serde_json::to_vec(&binding)? == bytes,
                    "noncanonical terminal checkpoint binding"
                );
                Ok::<NamespaceBinding, anyhow::Error>(binding)
            })
            .transpose()?;
        if reopen {
            let binding = selected.context("authoritative terminal checkpoint binding missing")?;
            ensure!(
                binding.tenant == state.tenant
                    && binding.incarnation == state.incarnation
                    && binding.checkpoint_sha256 == checkpoint_sha256
                    && binding.checkpoint_head == self.head
                    && !binding.namespace.is_nil(),
                "terminal checkpoint binding differs"
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
                    .context("checkpoint terminal row missing")?;
                ensure!(
                    actual.sha256()? == row.sha256()?,
                    "checkpoint terminal physical row differs"
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
                scratch_limit(state.limits.max_snapshot_bytes)?,
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
            digest(checkpoint_sha256) && self.head == state.staged_terminal_head,
            "terminal capture checkpoint differs"
        );
        let Some(Source::Durable(rows)) = self.source.as_deref() else {
            anyhow::bail!("terminal snapshot capture requires installed durable ownership");
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

/// At most the bounded active set and the current command can become terminal
/// during one apply. Existing permanent rows are never cloned into a history map.
pub(crate) struct Pending {
    previous: View,
    head: StagedTerminalHead,
    rows: Vec<Row>,
}
impl Pending {
    pub(crate) fn prepare(
        previous: &View,
        previous_state: &TenantState,
        next: &mut TenantState,
        applied: &AppliedIdentity,
    ) -> Result<Self> {
        ensure!(
            previous.head == previous_state.staged_terminal_head
                && next.staged_terminal_head == previous.head,
            "terminal starting prefix differs"
        );
        let mut head = previous.head.clone();
        let mut rows = Vec::new();
        let keys: Vec<_> = next
            .staged_transactions
            .iter()
            .filter(|(_, stage)| !stage.is_active())
            .map(|(key, _)| key.clone())
            .collect();
        ensure!(
            keys.len() <= 65,
            "terminal apply overlay exceeds bounded active set"
        );
        for key in keys {
            let stage = next
                .staged_transactions
                .remove(&key)
                .context("terminal overlay row missing")?;
            if let Some(existing) = previous.get(&key)? {
                ensure!(
                    staged_digest(&existing.stage)? == staged_digest(&stage)?,
                    "permanent terminal outcome changed"
                );
                continue;
            }
            let header_bytes = crate::accounting::staged_header(&key, &stage)?;
            let row = Row {
                ordinal: head
                    .count
                    .checked_add(1)
                    .context("terminal ordinal exhausted")?,
                key: key.clone(),
                previous_sha256: head.sha256.clone(),
                applied: applied.clone(),
                stage,
            };
            row.validate(next)?;
            let row_bytes = row.framed_bytes()?;
            if let Some(active) = previous_state.staged_transactions.get(&key) {
                let (used, reserved) = crate::state::staging::permanent_charge(&key, active)?;
                ensure!(
                    active.is_active()
                        && used
                            .checked_add(reserved)
                            .is_some_and(|capacity| row_bytes <= capacity),
                    "terminal envelope exceeds its original Begin reservation"
                );
            }
            next.permanent_staged_bytes = next
                .permanent_staged_bytes
                .checked_sub(header_bytes)
                .and_then(|n| n.checked_add(row_bytes))
                .context("terminal row accounting overflow")?;
            advance(&mut head, &row)?;
            rows.push(row);
        }
        next.staged_terminal_head = head.clone();
        Ok(Self {
            previous: previous.clone(),
            head,
            rows,
        })
    }
    pub(crate) fn get(&self, key: &str) -> Result<Option<StagedTransaction>> {
        if let Some(row) = self.rows.iter().find(|row| row.key == key) {
            return Ok(Some(row.stage.clone()));
        }
        Ok(self.previous.get(key)?.map(|row| row.stage))
    }
    pub(crate) fn persist(self) -> Result<View> {
        if self.rows.is_empty() {
            return Ok(self.previous);
        }
        let Some(source) = &self.previous.source else {
            anyhow::bail!("terminal append storage is not installed");
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
                                "future terminal row differs from exact original command replay"
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
                        _ => anyhow::bail!("partially published terminal row/index"),
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
                anyhow::bail!("unpublished restore staging cannot serve terminal writes")
            }
        }
        let view = View {
            source: self.previous.source,
            head: self.head,
        };
        view.check_head(&self.rows[0].stage.scope.tenant)?;
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
        ensure!(self.head.count == 0, "fixture terminal prefix has no owner");
        let table = Arc::new(EncryptedTable::new(
            disk,
            scratch_limit(state.limits.max_snapshot_bytes)?,
        )?);
        Ok(Self {
            source: Some(Arc::new(Source::Staged(table))),
            head: self.head.clone(),
        })
    }
}

#[cfg(test)]
#[path = "staged_terminal_tests.rs"]
mod tests;
