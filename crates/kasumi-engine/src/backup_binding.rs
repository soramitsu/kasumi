//! Permanent Control backup bindings. A generation selects an authenticated
//! prefix of encrypted point rows; rows persisted ahead of the applied cursor
//! cannot prove that a claim committed.
#[path = "lifecycle_intent_store.rs"]
pub(crate) mod intents;
use crate::namespace_installation::PreparedRows;
use anyhow::{Context, Result, ensure};
use kasumi_store::{EncryptedTable, ScratchDisk, TenantStore, WriteOp};
use kasumi_types::{BackupBindingHead, BackupBindingRecord, TenantState, staged_digest};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const MAX_ROW_BYTES: usize = 2 << 20;
pub(crate) const MAX_SNAPSHOT_RECORD_BYTES: usize = MAX_ROW_BYTES + 256;
pub(crate) const CATALOG: &str = "backup-binding-catalog";

pub(crate) fn scratch_limit(canonical_bytes: u64) -> Result<u64> {
    // Bound temporary working copies, indexes and commit overhead separately
    // from the canonical binding quota; some histories can still exhaust it.
    canonical_bytes
        .checked_mul(16)
        .and_then(|n| n.checked_add(64 << 20))
        .context("backup binding scratch budget overflow")
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn point_key(session: uuid::Uuid, terminal: bool) -> String {
    if terminal {
        format!("terminal/{session}")
    } else {
        session.to_string()
    }
}

fn id_key(key: &str) -> Vec<u8> {
    [b"id/".as_slice(), key.as_bytes()].concat()
}
fn ordinal_key(ordinal: u64) -> Vec<u8> {
    [b"ordinal/".as_slice(), &ordinal.to_be_bytes()].concat()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Row {
    pub ordinal: u64,
    pub key: String,
    pub previous_sha256: String,
    pub applied: crate::staged_terminal::AppliedIdentity,
    pub record: BackupBindingRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<kasumi_types::BackupBindingTerminal>,
}
impl Row {
    pub(crate) fn sha256(&self) -> Result<String> {
        Ok(staged_digest(&("kasumi.backup-binding-row.v1", self))?.0)
    }
    pub(crate) fn framed_bytes(&self) -> Result<u64> {
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_ROW_BYTES,
            "backup binding row exceeds per-record limit"
        );
        let index = serde_json::to_vec(&Ordinal {
            key: self.key.clone(),
            sha256: self.sha256()?,
        })?;
        let charge = [
            bytes.len(),
            index.len(),
            id_key(&self.key).len(),
            ordinal_key(self.ordinal).len(),
            32,
        ]
        .into_iter()
        .try_fold(0u64, |total, item| {
            total
                .checked_add(u64::try_from(item)?)
                .context("backup binding charge overflow")
        })?;
        let snapshot_bytes = crate::accounting::encoded_len(
            &crate::snapshot_codec::Record::BackupBinding(Box::new(self.clone())),
        )?
        .checked_add(crate::snapshot_codec::FRAME_HEADER_BYTES)
        .context("backup binding snapshot frame overflow")?;
        ensure!(
            u64::try_from(snapshot_bytes)? <= charge,
            "backup binding table charge does not cover snapshot frame"
        );
        Ok(charge)
    }
    pub(crate) fn validate(&self, state: &TenantState) -> Result<()> {
        self.validate_position()?;
        ensure!(
            state.tenant == crate::control::CONTROL_TENANT
                && self.ordinal > 0
                && self.key == point_key(self.record.claim.session_id, self.terminal.is_some())
                && digest(&self.previous_sha256)
                && self.applied.incarnation == state.incarnation
                && self.applied.revision > state.revision_base
                && self.applied.revision <= state.revision,
            "backup binding row is outside installed Control position"
        );
        self.applied.validate_original_position(state)?;
        self.framed_bytes()?;
        Ok(())
    }
    fn validate_position(&self) -> Result<()> {
        self.record.validate()?;
        ensure!(
            self.key == point_key(self.record.claim.session_id, self.terminal.is_some()),
            "backup binding kind or session differs"
        );
        if let Some(decision) = &self.terminal {
            decision.validate(&self.record.claim)?;
            ensure!(
                matches!(self.applied.origin, crate::staged_terminal::AppliedOrigin::Raft { index, term, .. }
                if index > self.record.position.index && term >= self.record.position.term),
                "terminal precedes its claimed position"
            );
            return Ok(());
        }
        ensure!(
            self.record.position.command_sha256 == self.applied.command_sha256
                && matches!(
                    &self.applied.origin,
                    crate::staged_terminal::AppliedOrigin::Raft { term, index, .. }
                        if *term == self.record.position.term
                            && *index == self.record.position.index
                ),
            "backup binding committed Control position differs"
        );
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Ordinal {
    key: String,
    sha256: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NamespaceBinding {
    namespace: uuid::Uuid,
    tenant: String,
    incarnation: String,
    checkpoint_sha256: String,
    checkpoint_head: BackupBindingHead,
}
impl NamespaceBinding {
    fn namespace(&self) -> String {
        format!("backup-binding-{}", self.namespace)
    }
}
struct DurableRows {
    store: Arc<TenantStore>,
    binding: NamespaceBinding,
}
enum Source {
    Durable(DurableRows),
    Staged(
        Arc<EncryptedTable>,
        Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
    ),
}
impl Source {
    fn get(&self, key: &[u8]) -> Result<Option<crate::materialization_row::MaterializationRow>> {
        let result = match self {
            Self::Durable(rows) => rows
                .store
                .get_bounded(&rows.binding.namespace(), key, MAX_ROW_BYTES)?
                .map(crate::materialization_row::MaterializationRow::Stored),
            Self::Staged(table, _) => table
                .get(key)?
                .map(crate::materialization_row::MaterializationRow::Staged),
        };
        ensure!(
            result.as_ref().is_none_or(|v| v.len() <= MAX_ROW_BYTES),
            "backup binding physical row exceeds limit"
        );
        Ok(result)
    }
}
/// Outcomes in this locally applied Control binding ledger. Destination-only
/// sessions that predate Control binding have no entry here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ControlBackupSessions {
    pub claimed_without_terminal: u64,
    pub completed: u64,
    pub aborted: u64,
    pub last_binding_revision: u64,
}

impl ControlBackupSessions {
    fn advanced(mut self, row: &Row) -> Result<Self> {
        let count = match row.terminal.as_ref().map(|terminal| &terminal.outcome) {
            None => &mut self.claimed_without_terminal,
            Some(outcome) => {
                self.claimed_without_terminal = self
                    .claimed_without_terminal
                    .checked_sub(1)
                    .context("backup terminal without an outstanding claim")?;
                match outcome {
                    kasumi_types::BackupSessionOutcome::Complete { .. } => &mut self.completed,
                    kasumi_types::BackupSessionOutcome::Aborted { .. } => &mut self.aborted,
                }
            }
        };
        *count = count
            .checked_add(1)
            .context("Control backup session count overflow")?;
        self.last_binding_revision = row.applied.revision;
        Ok(self)
    }
}

impl crate::Generation {
    pub fn control_backup_sessions(&self) -> Option<ControlBackupSessions> {
        (self.tenant() == crate::control::CONTROL_TENANT).then_some(self.backup_bindings.sessions)
    }
}

#[derive(Clone)]
pub(crate) struct View {
    sessions: ControlBackupSessions,
    source: Option<Arc<Source>>,
    head: BackupBindingHead,
}
impl std::fmt::Debug for View {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupBindingView")
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}
impl View {
    pub(crate) fn empty(incarnation: &str) -> Result<Self> {
        Ok(Self {
            sessions: ControlBackupSessions::default(),
            source: None,
            head: BackupBindingHead::empty(incarnation)?,
        })
    }
    pub(crate) fn head(&self) -> &BackupBindingHead {
        &self.head
    }
    fn bytes(&self, key: &[u8]) -> Result<Option<crate::materialization_row::MaterializationRow>> {
        self.source
            .as_ref()
            .map(|source| source.get(key))
            .transpose()
            .map(Option::flatten)
    }
    fn index(&self, ordinal: u64) -> Result<Ordinal> {
        ensure!(
            ordinal > 0 && ordinal <= self.head.count,
            "backup binding ordinal exceeds selected generation"
        );
        let bytes = self
            .bytes(&ordinal_key(ordinal))?
            .context("backup binding ordinal missing")?;
        let index: Ordinal = serde_json::from_slice(&bytes)?;
        crate::current_json::require_current_writer_bytes(
            &bytes,
            &index,
            "backup binding ordinal",
        )?;
        ensure!(
            digest(&index.sha256)
                && uuid::Uuid::parse_str(index.key.strip_prefix("terminal/").unwrap_or(&index.key))
                    .ok()
                    .is_some_and(|id| !id.is_nil()
                        && point_key(id, index.key.starts_with("terminal/")) == index.key),
            "backup binding ordinal identity invalid"
        );
        Ok(index)
    }
    pub(crate) fn check_head(&self) -> Result<()> {
        ensure!(
            digest(&self.head.sha256),
            "invalid backup binding head digest"
        );
        ensure!(
            self.sessions
                .completed
                .checked_add(self.sessions.aborted)
                .and_then(|n| n.checked_mul(2))
                .and_then(|n| n.checked_add(self.sessions.claimed_without_terminal))
                == Some(self.head.count)
                && self.sessions.last_binding_revision == self.head.last_applied_revision,
            "Control backup session counts differ from selected prefix"
        );
        if self.head.count == 0 {
            ensure!(
                self.head == BackupBindingHead::empty(&self.head.origin_incarnation)?,
                "empty backup binding head differs"
            );
        } else {
            ensure!(
                self.head.encoded_bytes > 0
                    && self.head.last_applied_revision > 0
                    && self.index(self.head.count)?.sha256 == self.head.sha256,
                "backup binding physical prefix differs from selected head"
            );
        }
        Ok(())
    }
    pub(crate) fn validate_state(&self, state: &TenantState) -> Result<()> {
        self.check_head()?;
        ensure!(
            self.head.origin_incarnation == state.incarnation
                || state.restore_lineage.iter().any(|link| {
                    link.checkpoint.source_incarnation == self.head.origin_incarnation
                }),
            "backup binding origin is outside retained lineage"
        );
        ensure!(
            self.head == state.backup_binding_head
                && (self.head.count == 0
                    || (state.tenant == crate::control::CONTROL_TENANT
                        && self.head.origin_incarnation == state.incarnation))
                && (state.tenant == crate::control::CONTROL_TENANT
                    || (self.head.count == 0 && self.source.is_none()))
                && self.head.encoded_bytes <= state.limits.max_backup_binding_bytes
                && self.head.last_applied_revision <= state.revision,
            "backup binding head differs from installed Control state"
        );
        Ok(())
    }
    pub(crate) fn get(&self, session: uuid::Uuid) -> Result<Option<Row>> {
        ensure!(!session.is_nil(), "nil backup binding point identity");
        self.point(&point_key(session, false))
    }
    pub(crate) fn terminal(&self, session: uuid::Uuid) -> Result<Option<Row>> {
        let row = self.point(&point_key(session, true))?;
        if let Some(terminal) = &row {
            ensure!(
                self.get(session)?.is_some_and(
                    |claim| claim.record == terminal.record && claim.ordinal < terminal.ordinal
                ),
                "terminal backup decision differs from its original claim"
            );
        }
        Ok(row)
    }
    fn point(&self, key: &str) -> Result<Option<Row>> {
        let Some(bytes) = self.bytes(&id_key(key))? else {
            return Ok(None);
        };
        let row: Row = serde_json::from_slice(&bytes)?;
        // A durable row from a write ahead of the applied cursor is not evidence.
        if row.ordinal > self.head.count {
            return Ok(None);
        }
        crate::current_json::require_current_writer_bytes(&bytes, &row, "backup binding point")?;
        ensure!(
            row.key == key && row.ordinal > 0,
            "backup binding point identity differs"
        );
        let index = self.index(row.ordinal)?;
        ensure!(
            index.key == key && index.sha256 == row.sha256()?,
            "backup binding point differs from ordinal commitment"
        );
        if row.ordinal == 1 {
            ensure!(
                row.previous_sha256
                    == BackupBindingHead::empty(&self.head.origin_incarnation)?.sha256,
                "backup binding initial root differs"
            );
        } else {
            ensure!(
                row.previous_sha256 == self.index(row.ordinal - 1)?.sha256,
                "backup binding parent root differs"
            );
        }
        ensure!(
            self.index(self.head.count)?.sha256 == self.head.sha256,
            "backup binding selected root differs"
        );
        row.validate_position()?;
        Ok(Some(row))
    }
    pub(crate) fn row(&self, ordinal: u64) -> Result<Row> {
        let key = self.index(ordinal)?.key;
        let row = self
            .point(&key)?
            .context("backup binding indexed point missing")?;
        ensure!(row.ordinal == ordinal, "backup binding ordinal redirected");
        Ok(row)
    }
    pub(crate) fn records(&self) -> impl Iterator<Item = Result<Row>> + Send + '_ {
        (1..=self.head.count).map(|ordinal| self.row(ordinal))
    }
    pub(crate) fn checkpoint_exists(store: &TenantStore, sha256: &str) -> Result<bool> {
        ensure!(digest(sha256), "invalid backup binding checkpoint digest");
        Ok(store
            .get_bounded(CATALOG, sha256.as_bytes(), 64 << 10)?
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
                && self.head == state.backup_binding_head,
            "backup binding installation identity differs"
        );
        self.validate_state(state)?;
        let selected = store
            .get_bounded(CATALOG, checkpoint_sha256.as_bytes(), 64 << 10)?
            .map(|bytes| {
                let binding: NamespaceBinding = serde_json::from_slice(&bytes)?;
                ensure!(
                    serde_json::to_vec(&binding)? == bytes,
                    "noncanonical backup binding checkpoint binding"
                );
                Ok::<NamespaceBinding, anyhow::Error>(binding)
            })
            .transpose()?;
        if state.tenant != crate::control::CONTROL_TENANT {
            ensure!(
                self.source.is_none() && selected.is_none() && self.head.count == 0,
                "application tenant cannot own a Control backup binding table"
            );
            return Ok(Installation {
                rows: None,
                staging: None,
                writes: vec![],
                view: self.clone(),
            });
        }
        if reopen {
            let binding = selected.context("authoritative backup binding checkpoint missing")?;
            ensure!(
                binding.tenant == state.tenant
                    && binding.incarnation == state.incarnation
                    && binding.checkpoint_sha256 == checkpoint_sha256
                    && binding.checkpoint_head == self.head
                    && !binding.namespace.is_nil(),
                "backup binding checkpoint identity differs"
            );
            let view = View {
                source: Some(Arc::new(Source::Durable(DurableRows {
                    store: store.clone(),
                    binding: binding.clone(),
                }))),
                sessions: self.sessions,
                head: self.head.clone(),
            };
            view.validate_state(state)?;
            view.verify_restored_intents(state)?;
            for old in self.records() {
                let old = old?;
                let actual = view
                    .point(&old.key)?
                    .context("backup binding checkpoint row missing")?;
                ensure!(
                    actual.sha256()? == old.sha256()?,
                    "backup binding checkpoint physical row differs"
                );
            }
            return Ok(Installation {
                rows: None,
                staging: None,
                writes: vec![],
                view,
            });
        }
        ensure!(
            selected.is_none(),
            "backup binding checkpoint is already installed"
        );
        let rows = match self.source.as_deref() {
            Some(Source::Staged(table, _)) => PreparedRows::Staged(table.clone()),
            None if self.head.count == 0 => PreparedRows::Empty,
            _ => anyhow::bail!("backup binding installation requires verified staged rows"),
        };
        let binding = NamespaceBinding {
            namespace: uuid::Uuid::new_v4(),
            tenant: state.tenant.clone(),
            incarnation: state.incarnation.clone(),
            checkpoint_sha256: checkpoint_sha256.into(),
            checkpoint_head: self.head.clone(),
        };
        let namespace = binding.namespace();
        let mut writes = vec![WriteOp::put(
            CATALOG,
            checkpoint_sha256.as_bytes(),
            serde_json::to_vec(&binding)?,
        )];
        let staging = kasumi_store::NamespaceStage::begin(store, &namespace)?;
        writes.push(staging.publication_write());
        let view = View {
            source: Some(Arc::new(Source::Durable(DurableRows {
                store: store.clone(),
                binding,
            }))),
            sessions: self.sessions,
            head: self.head.clone(),
        };
        Ok(Installation {
            rows: Some(rows),
            staging: Some(staging),
            writes,
            view,
        })
    }
    pub(crate) fn checkpoint_writes(
        &self,
        state: &TenantState,
        checkpoint_sha256: &str,
    ) -> Result<Vec<WriteOp>> {
        ensure!(
            digest(checkpoint_sha256) && self.head == state.backup_binding_head,
            "backup binding snapshot head differs"
        );
        if state.tenant != crate::control::CONTROL_TENANT {
            ensure!(
                self.source.is_none() && self.head.count == 0,
                "application tenant cannot capture a Control backup binding table"
            );
            return Ok(vec![]);
        }
        let Some(Source::Durable(rows)) = self.source.as_deref() else {
            anyhow::bail!("backup binding snapshot requires durable point ownership");
        };
        rows.store.check_access()?;
        self.validate_state(state)?;
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

pub(crate) struct Builder {
    memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
    pub(crate) intent_head: Option<kasumi_types::LifecycleIntentHead>,
    sessions: ControlBackupSessions,
    table: Arc<EncryptedTable>,
    head: BackupBindingHead,
}
impl Builder {
    pub(crate) fn new(
        disk: &Arc<ScratchDisk>,
        limit: u64,
        incarnation: &str,
    ) -> std::result::Result<Self, kasumi_store::ScratchOperationFailure> {
        Ok(Self {
            sessions: ControlBackupSessions::default(),
            intent_head: None,
            memory: disk.memory().clone(),
            table: Arc::new(EncryptedTable::new(
                disk,
                limit,
                disk.native_cache_config(),
            )?),
            head: BackupBindingHead::empty(incarnation).map_err(|original| {
                kasumi_store::ScratchOperationFailure::Operation(original.into())
            })?,
        })
    }
    pub(crate) fn push(&mut self, row: &Row, state: &TenantState) -> Result<()> {
        row.validate(state)?;
        ensure!(
            self.table.get(&id_key(&row.key))?.is_none(),
            "duplicate permanent backup binding identity"
        );
        if row.terminal.is_some() {
            let claim = self
                .table
                .get(&id_key(&row.record.claim.session_id.to_string()))?
                .context("backup terminal is missing its original claim")?;
            let original: Row = serde_json::from_slice(&claim)?;
            ensure!(
                original.terminal.is_none() && original.record == row.record,
                "backup terminal claim differs"
            );
        }
        advance(&mut self.head, row)?;
        self.sessions = self.sessions.advanced(row)?;
        self.table
            .insert(&id_key(&row.key), &serde_json::to_vec(row)?)?;
        self.table.insert(
            &ordinal_key(row.ordinal),
            &serde_json::to_vec(&Ordinal {
                key: row.key.clone(),
                sha256: row.sha256()?,
            })?,
        )?;
        Ok(())
    }
    pub(crate) fn finish(self, expected: &BackupBindingHead) -> Result<View> {
        ensure!(
            &self.head == expected,
            "backup binding stream final root/count/bytes differ"
        );
        Ok(View {
            sessions: self.sessions,
            source: Some(Arc::new(Source::Staged(self.table, self.memory))),
            head: self.head,
        })
    }
}
pub(crate) fn advance(head: &mut BackupBindingHead, row: &Row) -> Result<()> {
    ensure!(
        row.ordinal
            == head
                .count
                .checked_add(1)
                .context("backup binding count overflow")?
            && row.previous_sha256 == head.sha256
            && row.applied.revision > head.last_applied_revision,
        "backup binding row is not the next committed prefix"
    );
    head.encoded_bytes = head
        .encoded_bytes
        .checked_add(row.framed_bytes()?)
        .context("backup binding table budget overflow")?;
    head.count = row.ordinal;
    head.last_applied_revision = row.applied.revision;
    head.sha256 = row.sha256()?;
    Ok(())
}
pub(crate) struct Installation {
    rows: Option<PreparedRows>,
    writes: Vec<WriteOp>,
    pub(crate) view: View,
    // Last: selection-write buffers retire before the stage's descriptor credit.
    staging: Option<kasumi_store::NamespaceStage>,
}
impl Installation {
    pub(crate) fn stage(&self) -> Result<()> {
        if let Some(rows) = &self.rows {
            rows.stage(self.staging.as_ref().context("namespace stage absent")?)?;
        }
        Ok(())
    }
    pub(crate) fn writes(&self) -> &[WriteOp] {
        &self.writes
    }
}

pub(crate) struct Pending {
    sessions: ControlBackupSessions,
    previous: View,
    head: BackupBindingHead,
    row: Row,
}
impl Pending {
    pub(crate) fn prepare(previous: &View, state: &TenantState, row: Row) -> Result<Self> {
        ensure!(
            previous.head == state.backup_binding_head,
            "backup binding starting prefix differs"
        );
        ensure!(
            previous.point(&row.key)?.is_none(),
            "cannot rewrite permanent backup binding"
        );
        row.validate(state)?;
        if row.terminal.is_some() {
            ensure!(
                previous
                    .get(row.record.claim.session_id)?
                    .is_some_and(|r| r.record == row.record),
                "backup terminal requires the exact committed claim"
            );
        }
        let mut head = previous.head.clone();
        advance(&mut head, &row)?;
        ensure!(
            head.encoded_bytes <= state.limits.max_backup_binding_bytes,
            "backup binding table budget exhausted"
        );
        Ok(Self {
            sessions: previous.sessions.advanced(&row)?,
            previous: previous.clone(),
            head,
            row,
        })
    }
    pub(crate) fn head(&self) -> &BackupBindingHead {
        &self.head
    }
    pub(crate) fn persist(self) -> Result<View> {
        let Some(source) = &self.previous.source else {
            anyhow::bail!("backup binding point storage is not installed");
        };
        match source.as_ref() {
            Source::Durable(rows) => {
                let namespace = rows.binding.namespace();
                let id = id_key(&self.row.key);
                let ordinal = ordinal_key(self.row.ordinal);
                let bytes = serde_json::to_vec(&self.row)?;
                let index = serde_json::to_vec(&Ordinal {
                    key: self.row.key.clone(),
                    sha256: self.row.sha256()?,
                })?;
                match (source.get(&id)?, source.get(&ordinal)?) {
                    (Some(old_row), Some(old_index)) => ensure!(
                        old_row == bytes && old_index == index,
                        "future backup binding differs from exact command replay"
                    ),
                    (None, None) => rows.store.write_batch(&[
                        WriteOp::put(&namespace, id, bytes),
                        WriteOp::put(&namespace, ordinal, index),
                    ])?,
                    _ => anyhow::bail!("partially published backup binding row/index"),
                }
            }
            Source::Staged(_, _) => {
                anyhow::bail!("unpublished backup binding staging cannot serve writes")
            }
        }
        let view = View {
            sessions: self.sessions,
            source: self.previous.source,
            head: self.head,
        };
        view.check_head()?;
        Ok(view)
    }
}

#[cfg(test)]
#[path = "backup_binding_tests.rs"]
pub(crate) mod tests;
