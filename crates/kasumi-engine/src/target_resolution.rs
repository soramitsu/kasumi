//! Immutable target completion and budget facts, selected by a causal prefix.
//! Physical rows written beyond the selected head are not committed observations.
use anyhow::{Context, Result, ensure};
use kasumi_store::{EncryptedTable, ScratchDisk, TenantStore, WriteOp};
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const MAX_ROW_BYTES: usize = MAX_TARGET_COMPLETION_RECORD_BYTES as usize + (64 << 10);
pub(crate) const MAX_SNAPSHOT_RECORD_BYTES: usize = MAX_ROW_BYTES + 64;
const CATALOG: &str = "target-resolution-catalog";
pub(crate) fn scratch_limit(table_budget: u64) -> Result<u64> {
    table_budget
        .checked_mul(8)
        .and_then(|n| n.checked_add(64 << 20))
        .context("target terminal staging budget overflow")
}
/// Resident application, ordinary receipts and permanent target records have independent configured
/// budgets. The snapshot spool admits their checked aggregate on the same disk.
pub(crate) fn snapshot_limit(state: &TenantState) -> Result<u64> {
    ensure!(
        state.target_resolution_head.encoded_bytes <= state.limits.max_target_resolution_bytes
            && state.mutation_receipt_head.encoded_bytes <= state.limits.max_mutation_receipt_bytes,
        "selected permanent bytes exceed configured table budget"
    );
    state
        .limits
        .max_snapshot_bytes
        .checked_add(state.target_resolution_head.encoded_bytes)
        .and_then(|bytes| bytes.checked_add(state.mutation_receipt_head.encoded_bytes))
        .context("combined permanent snapshot budget overflow")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Row {
    pub ordinal: u64,
    pub key: String,
    pub previous_sha256: String,
    pub command_sha256: String,
    pub applying_context_sha256: String,
    pub record: TargetResolutionRecord,
}
impl Row {
    pub(crate) fn ordered(
        previous: &TargetResolutionPrefixHead,
        record: TargetResolutionRecord,
        applied: &kasumi_raft::AppliedEntryContext,
    ) -> Result<Self> {
        let position = record.position();
        ensure!(
            position.term == applied.log_id.leader_id.term
                && position.leader_node_id == applied.log_id.leader_id.node_id
                && position.index == applied.log_id.index
                && position.command_sha256 == applied.command_sha256,
            "target terminal fact differs from actual applying position"
        );
        let row = Self {
            ordinal: previous
                .count
                .checked_add(1)
                .context("target terminal ordinal exhausted")?,
            key: record.key(),
            previous_sha256: previous.sha256.clone(),
            command_sha256: applied.command_sha256.clone(),
            applying_context_sha256: staged_digest(&(
                "kasumi.target-resolution-apply.v1",
                &applied.log_id,
                &applied.previous,
                &applied.membership,
                &applied.command_sha256,
            ))?
            .0,
            record,
        };
        row.framed_bytes()?;
        Ok(row)
    }
    pub(crate) fn sha256(&self) -> Result<String> {
        Ok(staged_digest(&("kasumi.target-resolution-row.v1", self))?.0)
    }
    /// Logical durable-table cost includes both point/ordinal records, keys and
    /// length framing. It is not an assertion about provider or node disk usage.
    pub(crate) fn framed_bytes(&self) -> Result<u64> {
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_ROW_BYTES,
            "target terminal row exceeds per-record bound"
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
        .try_fold(0u64, |total, n| {
            total
                .checked_add(u64::try_from(n)?)
                .context("target terminal framing overflow")
        })?;
        let snapshot_bytes = crate::accounting::encoded_len(
            &crate::snapshot_codec::Record::TargetResolution(Box::new(self.clone())),
        )?
        .checked_add(crate::snapshot_codec::FRAME_HEADER_BYTES)
        .context("target terminal snapshot framing overflow")?;
        ensure!(
            u64::try_from(snapshot_bytes)? <= charge,
            "target terminal table charge does not cover canonical snapshot framing"
        );
        Ok(charge)
    }
    pub(crate) fn validate(&self, state: &TenantState) -> Result<()> {
        self.record.validate()?;
        ensure!(
            self.ordinal > 0
                && self.key == self.record.key()
                && digest(&self.previous_sha256)
                && digest(&self.command_sha256)
                && self.command_sha256 == self.record.position().command_sha256
                && digest(&self.applying_context_sha256),
            "invalid target terminal row identity"
        );
        let origin = self.record.origin();
        let incarnation = origin.input.target_incarnation.to_string();
        ensure!(
            origin.materialization.request.tenant == state.tenant,
            "target terminal tenant differs"
        );
        let target = state
            .target_lifecycle
            .get(&incarnation)
            .context("target terminal origin absent from retained lifecycle")?;
        ensure!(
            target.origin == *origin,
            "target terminal physical origin changed"
        );
        let maximum = if incarnation == state.incarnation {
            state.revision
        } else {
            state
                .restore_lineage
                .iter()
                .find(|link| link.checkpoint.source_incarnation == incarnation)
                .context("target terminal applying incarnation absent from lineage")?
                .checkpoint
                .revision
        };
        // The typed fact itself verifies genesis(checkpoint+1)+log index equals
        // its revision. The retained checkpoint also supplies an upper bound.
        ensure!(
            self.record.revision() <= maximum,
            "target terminal exceeds retained checkpoint"
        );
        self.framed_bytes()?;
        Ok(())
    }
}
fn valid_key(key: &str) -> bool {
    let fields: Vec<_> = key.split('/').collect();
    fields.len() == 3
        && matches!(fields[0], "completion" | "budget")
        && fields[1..].iter().all(|id| {
            uuid::Uuid::parse_str(id)
                .is_ok_and(|parsed| !parsed.is_nil() && parsed.to_string() == *id)
        })
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
    checkpoint_head: TargetResolutionPrefixHead,
}
impl NamespaceBinding {
    fn namespace(&self) -> String {
        format!("target-resolution-{}", self.namespace)
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
    head: TargetResolutionPrefixHead,
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
            head: TargetResolutionPrefixHead::empty(tenant, incarnation)?,
        })
    }
    pub(crate) fn head(&self) -> &TargetResolutionPrefixHead {
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
        ensure!(
            valid_key(&entry.key) && digest(&entry.sha256),
            "invalid terminal ordinal index"
        );
        Ok(entry)
    }
    pub(crate) fn check_head(&self, tenant: &str) -> Result<()> {
        validate_name(&self.head.origin_incarnation)?;
        ensure!(digest(&self.head.sha256), "invalid terminal head digest");
        if self.head.count == 0 {
            ensure!(
                self.head
                    == TargetResolutionPrefixHead::empty(tenant, &self.head.origin_incarnation)?,
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
            self.head == state.target_resolution_head
                && (self.head.origin_incarnation == state.incarnation
                    || state
                        .restore_lineage
                        .iter()
                        .any(|link| link.checkpoint.source_incarnation
                            == self.head.origin_incarnation)),
            "terminal history origin is outside retained lineage"
        );
        validate_current(state, |key| self.get(key))?;
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
        ensure!(valid_key(key), "invalid target terminal point identity");
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
                    == TargetResolutionPrefixHead::empty(
                        &row.record.origin().materialization.request.tenant,
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
    pub(crate) fn terminal_fact(
        &self,
        state: &TenantState,
        original_command_id: uuid::Uuid,
    ) -> Result<Option<Box<TargetCompletionResolutionFact>>> {
        ensure!(
            self.head == state.target_resolution_head,
            "terminal status prefix differs"
        );
        let Some(row) = self.get(&format!(
            "completion/{}/{original_command_id}",
            state.incarnation
        ))?
        else {
            return Ok(None);
        };
        row.validate(state)?;
        let TargetResolutionRecord::Completion(fact) = row.record else {
            anyhow::bail!("terminal status point kind differs");
        };
        Ok(Some(fact))
    }
    /// Positive original reservation only. Unpublished physical rows remain
    /// invisible, and absence carries no negative or successor authority.
    pub(crate) fn prepared_attempt(
        &self,
        state: &TenantState,
        command_id: uuid::Uuid,
    ) -> Result<Option<Box<TargetCompletionAttempt>>> {
        ensure!(
            self.head == state.target_resolution_head,
            "preparation status prefix differs"
        );
        let key = format!("completion/{}/{command_id}", state.incarnation);
        if let Some(row) = self.get(&key)? {
            row.validate(state)?;
            let TargetResolutionRecord::Completion(fact) = row.record else {
                anyhow::bail!("preparation status terminal kind differs");
            };
            return Ok(Some(fact.input.attempt));
        }
        let Some(head) = &state.target_completion_head else {
            return Ok(None);
        };
        let origin = &state
            .target_lifecycle
            .get(&state.incarnation)
            .context("preparation status current physical origin absent")?
            .origin;
        head.validate(origin)?;
        Ok(head
            .active
            .as_ref()
            .filter(|attempt| attempt.intent.request.command_id == command_id)
            .cloned())
    }
}

pub(crate) fn validate_current(
    state: &TenantState,
    mut lookup: impl FnMut(&str) -> Result<Option<Row>>,
) -> Result<()> {
    state.target_resolution_head.validate(&state.tenant)?;
    snapshot_limit(state)?;
    let current = state.target_lifecycle.get(&state.incarnation);
    let Some(head) = &state.target_completion_head else {
        ensure!(
            current.is_none(),
            "current target lacks its canonical completion head"
        );
        return Ok(());
    };
    let current = current.context("completion head has no current target origin")?;
    head.validate(&current.origin)?;
    if let Some(id) = head.budget_operation_id {
        let row = lookup(&format!("budget/{}/{id}", state.incarnation))?
            .context("current target budget outcome is outside selected prefix")?;
        row.validate(state)?;
        let TargetResolutionRecord::Budget(fact) = row.record else {
            anyhow::bail!("target budget selector names another record kind");
        };
        ensure!(
            fact.input.maximum_bytes == state.limits.max_target_resolution_bytes,
            "current target budget differs from its permanent maintenance outcome"
        );
    } else {
        ensure!(
            head.initial_budget_bytes == state.limits.max_target_resolution_bytes,
            "target budget changed without typed maintenance"
        );
    }
    if let Some(predecessor) = &head.predecessor {
        let key = format!(
            "completion/{}/{}",
            current.origin.input.target_incarnation, predecessor.original_command_id
        );
        let row = lookup(&key)?.context("completion predecessor is outside selected prefix")?;
        row.validate(state)?;
        let TargetResolutionRecord::Completion(fact) = row.record else {
            anyhow::bail!("completion predecessor redirected to budget record");
        };
        ensure!(
            fact.sealed_reference()? == *predecessor,
            "completion predecessor differs from exact selected seal"
        );
    }
    if let Some(active) = &head.active {
        ensure!(
            active.revision <= state.revision
                && state
                    .target_resolution_head
                    .encoded_bytes
                    .checked_add(active.reserved_terminal_bytes)
                    .is_some_and(|bytes| bytes <= state.limits.max_target_resolution_bytes),
            "active target completion exceeds revision or retained table reserve"
        );
        let key = format!(
            "completion/{}/{}",
            current.origin.input.target_incarnation, active.intent.request.command_id
        );
        ensure!(
            lookup(&key)?.is_none(),
            "active completion already has a selected terminal outcome"
        );
        if let Some(completion) = &current.completion {
            ensure!(
                completion.completion_intent == active.intent
                    && completion.predecessor == active.input.predecessor
                    && completion.materialized == active.input.quorum.materialized,
                "active completed attempt differs from original completion"
            );
        }
    } else if let Some(completed) = &current.completion {
        let row = lookup(&format!(
            "completion/{}/{}",
            state.incarnation, completed.completion_intent.request.command_id
        ))?
        .context("completed target lost its active attempt or positive terminal outcome")?;
        let TargetResolutionRecord::Completion(fact) = row.record else {
            anyhow::bail!("completed target terminal kind differs");
        };
        ensure!(
            matches!(fact.terminal, TargetCompletionTerminal::Committed(ref value) if value.as_ref() == completed),
            "completed target differs from selected positive terminal outcome"
        );
    }
    Ok(())
}

/// Restore validation stores this bounded cursor per physical origin in an
/// encrypted point index; it never builds a resident map of permanent facts.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CausalHead {
    completion: Option<String>,
    budget: Option<String>,
    revision: u64,
    term: u64,
}
pub(crate) fn validate_causal(
    state: &TenantState,
    row: &Row,
    head: &mut CausalHead,
    mut lookup: impl FnMut(&str) -> Result<Option<Row>>,
) -> Result<()> {
    ensure!(
        row.record.revision() > head.revision && row.record.position().term >= head.term,
        "target terminal actual applying order regressed"
    );
    let earlier = |key: &str, lookup: &mut dyn FnMut(&str) -> Result<Option<Row>>| -> Result<Row> {
        let previous = lookup(key)?.context("target terminal causal predecessor absent")?;
        ensure!(
            previous.ordinal < row.ordinal && previous.record.origin() == row.record.origin(),
            "target terminal predecessor changed physical origin or order"
        );
        Ok(previous)
    };
    match &row.record {
        TargetResolutionRecord::Completion(fact) => {
            match &head.completion {
                None => ensure!(
                    fact.input.attempt.input.predecessor.is_none(),
                    "target terminal references a missing first predecessor"
                ),
                Some(key) => {
                    let previous = earlier(key, &mut lookup)?;
                    let TargetResolutionRecord::Completion(previous) = previous.record else {
                        anyhow::bail!("target completion chain changed record kind");
                    };
                    ensure!(
                        fact.input.attempt.input.predecessor.as_ref()
                            == Some(&previous.sealed_reference()?)
                            && fact.input.attempt.revision > previous.revision
                            && fact.input.attempt.position.term >= previous.position.term,
                        "target terminal did not preserve exact ordered sealed predecessor"
                    );
                }
            }
            head.completion = Some(row.key.clone());
        }
        TargetResolutionRecord::Budget(fact) => {
            if let Some(key) = &head.budget {
                let previous = earlier(key, &mut lookup)?;
                let TargetResolutionRecord::Budget(previous) = previous.record else {
                    anyhow::bail!("target budget chain changed record kind");
                };
                ensure!(
                    fact.input.expected_bytes == previous.input.maximum_bytes
                        && fact.revision > previous.revision
                        && fact.position.term >= previous.position.term
                        && fact.intent.revision > previous.intent.revision,
                    "target budget compare-and-set or Control order changed"
                );
            } else if fact.origin.input.target_incarnation.to_string() == state.incarnation {
                ensure!(
                    state
                        .target_completion_head
                        .as_ref()
                        .is_some_and(
                            |current| current.initial_budget_bytes == fact.input.expected_bytes
                        ),
                    "target first budget effect changed its installed initial budget"
                );
            }
            head.budget = Some(row.key.clone());
        }
    }
    head.revision = row.record.revision();
    head.term = row.record.position().term;
    Ok(())
}
pub(crate) fn validate_causal_current(
    state: &TenantState,
    causal: &CausalHead,
    mut lookup: impl FnMut(&str) -> Result<Option<Row>>,
) -> Result<()> {
    let Some(head) = &state.target_completion_head else {
        return Ok(());
    };
    ensure!(
        causal.budget
            == head
                .budget_operation_id
                .map(|id| format!("budget/{}/{id}", state.incarnation)),
        "current target budget selector omitted a later committed maintenance effect"
    );
    let expected_predecessor = match &causal.completion {
        None => None,
        Some(key) => {
            let row = lookup(key)?.context("current completion chain head absent")?;
            let TargetResolutionRecord::Completion(fact) = row.record else {
                anyhow::bail!("current completion chain redirected");
            };
            match fact.terminal {
                TargetCompletionTerminal::Sealed => Some(fact.sealed_reference()?),
                TargetCompletionTerminal::Committed(_) => fact.input.attempt.input.predecessor,
            }
        }
    };
    ensure!(
        head.predecessor == expected_predecessor,
        "current target seal selector omitted a later committed completion"
    );
    Ok(())
}

/// An encrypted unpublished table is populated in canonical ordinal order. The
/// authenticated final head must match before this can become a restore input.
pub(crate) struct Builder {
    table: Arc<EncryptedTable>,
    causal: EncryptedTable,
    head: TargetResolutionPrefixHead,
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
            causal: EncryptedTable::new(disk, limit)?,
            head: TargetResolutionPrefixHead::empty(tenant, origin)?,
        })
    }
    pub(crate) fn push(&mut self, row: &Row, state: &TenantState) -> Result<()> {
        row.validate(state)?;
        ensure!(
            self.table.get(&id_key(&row.key))?.is_none(),
            "duplicate target terminal point identity"
        );
        let origin = row.record.origin().input.target_incarnation.to_string();
        let mut causal: CausalHead = self
            .causal
            .get(origin.as_bytes())?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?
            .unwrap_or_default();
        validate_causal(state, row, &mut causal, |key| {
            self.table
                .get(&id_key(key))?
                .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
                .transpose()
        })?;
        advance(&mut self.head, row)?;
        let index = Ordinal {
            key: row.key.clone(),
            sha256: row.sha256()?,
        };
        self.table
            .insert(&id_key(&row.key), &serde_json::to_vec(row)?)?;
        self.table
            .insert(&ordinal_key(row.ordinal), &serde_json::to_vec(&index)?)?;
        self.causal
            .insert(origin.as_bytes(), &serde_json::to_vec(&causal)?)?;
        Ok(())
    }
    fn validate_current(&self, state: &TenantState) -> Result<()> {
        let causal: CausalHead = self
            .causal
            .get(state.incarnation.as_bytes())?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?
            .unwrap_or_default();
        validate_causal_current(state, &causal, |key| {
            self.table
                .get(&id_key(key))?
                .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
                .transpose()
        })
    }
    pub(crate) fn finish(self, state: &TenantState) -> Result<View> {
        self.validate_current(state)?;
        ensure!(
            self.head == state.target_resolution_head,
            "terminal stream final root/count/bytes differ"
        );
        Ok(View {
            source: Some(Arc::new(Source::Staged(self.table))),
            head: self.head,
        })
    }
}

#[cfg(test)]
#[path = "target_resolution_tests.rs"]
mod tests;
pub(crate) fn advance(head: &mut TargetResolutionPrefixHead, row: &Row) -> Result<()> {
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
                && self.head == state.target_resolution_head,
            "terminal installation identity differs"
        );
        self.check_head(&state.tenant)?;
        let selected = store
            .get_bounded(CATALOG, checkpoint_sha256.as_bytes(), 64 << 10)?
            .map(|bytes| serde_json::from_slice::<NamespaceBinding>(&bytes))
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
                scratch_limit(state.limits.max_target_resolution_bytes)?,
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
            digest(checkpoint_sha256) && self.head == state.target_resolution_head,
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

/// One ordered target command appends at most one permanent fact. The pair may
/// reach disk before the generation; exact replay reconciles it without treating
/// unselected bytes as an outcome or borrowing capacity from another attempt.
pub(crate) struct Pending {
    previous: View,
    head: TargetResolutionPrefixHead,
    row: Option<Row>,
}
impl Pending {
    pub(crate) fn prepare(
        previous: &View,
        state: &mut TenantState,
        record: TargetResolutionRecord,
        applied: &kasumi_raft::AppliedEntryContext,
        reserved_bytes: u64,
    ) -> Result<Self> {
        ensure!(
            previous.head == state.target_resolution_head,
            "target terminal selector changed"
        );
        if let Some(existing) = previous.get(&record.key())? {
            ensure!(
                existing.record == record,
                "target terminal first outcome changed"
            );
            return Ok(Self {
                previous: previous.clone(),
                head: previous.head.clone(),
                row: None,
            });
        }
        let row = Row::ordered(&previous.head, record, applied)?;
        row.validate(state)?;
        let charge = row.framed_bytes()?;
        ensure!(
            charge <= reserved_bytes,
            "target terminal row exceeded its original reservation"
        );
        let mut head = previous.head.clone();
        advance(&mut head, &row)?;
        ensure!(
            head.encoded_bytes <= state.limits.max_target_resolution_bytes,
            "target terminal table budget exhausted"
        );
        state.target_resolution_head = head.clone();
        Ok(Self {
            previous: previous.clone(),
            head,
            row: Some(row),
        })
    }
    pub(crate) fn persist(self) -> Result<View> {
        let Some(row) = self.row else {
            return Ok(self.previous);
        };
        let Some(Source::Durable(storage)) = self.previous.source.as_deref() else {
            anyhow::bail!("target terminal writes require installed durable ownership");
        };
        let source = self
            .previous
            .source
            .as_ref()
            .expect("checked durable source");
        let bytes = serde_json::to_vec(&row)?;
        let index = serde_json::to_vec(&Ordinal {
            key: row.key.clone(),
            sha256: row.sha256()?,
        })?;
        let id = id_key(&row.key);
        let ordinal = ordinal_key(row.ordinal);
        match (source.get(&id)?, source.get(&ordinal)?) {
            (Some(old), Some(old_index)) => ensure!(
                old == bytes && old_index == index,
                "unselected target terminal differs from exact original apply replay"
            ),
            (None, None) => storage.store.write_batch(&[
                WriteOp::put(storage.binding.namespace(), id, bytes),
                WriteOp::put(storage.binding.namespace(), ordinal, index),
            ])?,
            _ => anyhow::bail!("partial target terminal row/index pair"),
        }
        let view = View {
            source: self.previous.source,
            head: self.head,
        };
        view.check_head(&row.record.origin().materialization.request.tenant)?;
        Ok(view)
    }
}
