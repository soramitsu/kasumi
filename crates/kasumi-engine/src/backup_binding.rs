//! Permanent Control backup bindings. A generation selects an authenticated
//! prefix of encrypted point rows; rows persisted ahead of the applied cursor
//! cannot prove that a claim committed.
use anyhow::{Context, Result, ensure};
use kasumi_store::{EncryptedTable, ScratchDisk, TenantStore, WriteOp};
use kasumi_types::{BackupBindingHead, BackupBindingRecord, TenantState, staged_digest};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const MAX_ROW_BYTES: usize = 2 << 20;
pub(crate) const MAX_SNAPSHOT_RECORD_BYTES: usize = MAX_ROW_BYTES + 256;
const CATALOG: &str = "backup-binding-catalog";

pub(crate) fn scratch_limit(canonical_bytes: u64) -> Result<u64> {
    canonical_bytes
        .checked_mul(8)
        .and_then(|n| n.checked_add(64 << 20))
        .context("backup binding scratch budget overflow")
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Row {
    pub ordinal: u64,
    pub key: String,
    pub previous_sha256: String,
    pub applied: crate::staged_terminal::AppliedIdentity,
    pub record: BackupBindingRecord,
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
                && state.lifecycle_control.is_some()
                && self.ordinal > 0
                && self.key == self.record.claim.session_id.to_string()
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
            result.as_ref().is_none_or(|v| v.len() <= MAX_ROW_BYTES),
            "backup binding physical row exceeds limit"
        );
        Ok(result)
    }
}
#[derive(Clone)]
pub(crate) struct View {
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
            source: None,
            head: BackupBindingHead::empty(incarnation)?,
        })
    }
    pub(crate) fn head(&self) -> &BackupBindingHead {
        &self.head
    }
    fn bytes(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
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
                && uuid::Uuid::parse_str(&index.key)
                    .ok()
                    .is_some_and(|id| !id.is_nil() && id.to_string() == index.key),
            "backup binding ordinal identity invalid"
        );
        Ok(index)
    }
    pub(crate) fn check_head(&self) -> Result<()> {
        ensure!(
            digest(&self.head.sha256),
            "invalid backup binding head digest"
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
                        && state.lifecycle_control.is_some()
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
        let key = session.to_string();
        let Some(bytes) = self.bytes(&id_key(&key))? else {
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
        let id = uuid::Uuid::parse_str(&self.index(ordinal)?.key)?;
        let row = self
            .get(id)?
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
                replacement: None,
                namespace: String::new(),
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
                head: self.head.clone(),
            };
            view.validate_state(state)?;
            for old in self.records() {
                let old = old?;
                let actual = view
                    .get(old.record.claim.session_id)?
                    .context("backup binding checkpoint row missing")?;
                ensure!(
                    actual.sha256()? == old.sha256()?,
                    "backup binding checkpoint physical row differs"
                );
            }
            return Ok(Installation {
                replacement: None,
                namespace: binding.namespace(),
                writes: vec![],
                view,
            });
        }
        ensure!(
            selected.is_none(),
            "backup binding checkpoint is already installed"
        );
        let replacement = match self.source.as_deref() {
            Some(Source::Staged(table)) => table.clone(),
            None if self.head.count == 0 => Arc::new(EncryptedTable::new(
                store.scratch_disk(),
                scratch_limit(state.limits.max_backup_binding_bytes)?,
            )?),
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
        let writes = vec![WriteOp::put(
            CATALOG,
            checkpoint_sha256.as_bytes(),
            serde_json::to_vec(&binding)?,
        )];
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
    table: Arc<EncryptedTable>,
    head: BackupBindingHead,
}
impl Builder {
    pub(crate) fn new(disk: &Arc<ScratchDisk>, limit: u64, incarnation: &str) -> Result<Self> {
        Ok(Self {
            table: Arc::new(EncryptedTable::new(disk, limit)?),
            head: BackupBindingHead::empty(incarnation)?,
        })
    }
    pub(crate) fn push(&mut self, row: &Row, state: &TenantState) -> Result<()> {
        row.validate(state)?;
        ensure!(
            self.table.get(&id_key(&row.key))?.is_none(),
            "duplicate permanent backup binding identity"
        );
        advance(&mut self.head, row)?;
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
            source: Some(Arc::new(Source::Staged(self.table))),
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

#[cfg(test)]
pub(crate) struct Pending {
    previous: View,
    head: BackupBindingHead,
    row: Row,
}
#[cfg(test)]
impl Pending {
    pub(crate) fn prepare(previous: &View, state: &TenantState, row: Row) -> Result<Self> {
        ensure!(
            previous.head == state.backup_binding_head,
            "backup binding starting prefix differs"
        );
        ensure!(
            previous.get(row.record.claim.session_id)?.is_none(),
            "cannot rewrite permanent backup binding"
        );
        row.validate(state)?;
        let mut head = previous.head.clone();
        advance(&mut head, &row)?;
        ensure!(
            head.encoded_bytes <= state.limits.max_backup_binding_bytes,
            "backup binding table budget exhausted"
        );
        Ok(Self {
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
            Source::Staged(_) => {
                anyhow::bail!("unpublished backup binding staging cannot serve writes")
            }
        }
        let view = View {
            source: self.previous.source,
            head: self.head,
        };
        view.check_head()?;
        Ok(view)
    }
}

#[cfg(test)]
#[path = "backup_binding_tests.rs"]
mod tests;
