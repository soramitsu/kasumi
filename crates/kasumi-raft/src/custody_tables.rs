//! Permanent custody identities use encrypted point records. The applied cursor,
//! small policy head, new receipt and audit entry publish in one transaction.
//! Snapshot transport still materializes the bounded logical capsule; this module
//! removes history-sized reads, clones and writes from ordinary custody commands.
use crate::custody_state::{CustodyAudit, CustodyState};
use anyhow::{Context, Result, ensure};
use kasumi_store::{TenantStore, WriteOp};
use kasumi_types::{CustodyReceipt, CustodyRequest, Error, ErrorCode, RequestContext};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

pub(crate) const HEAD: &[u8] = b"custody_point_tables";
pub(crate) const COMMANDS: &str = "raft.custody-commands";
pub(crate) const AUDIT: &str = "raft.custody-audit";
// A policy can contain two independently bounded 1,024-member administrator
// sets (current and immutable origin). Keep the existing control-record bound.
pub(crate) const HEAD_BYTES: usize = 2 << 20;
pub(crate) const RECORD_BYTES: usize = 64 << 10;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyHead {
    version: u32,
    pub(crate) policy: CustodyState,
    pub(crate) commands: u64,
    pub(crate) audit: u64,
    pub(crate) history_bytes: u64,
}

fn policy(state: &CustodyState) -> CustodyState {
    CustodyState {
        origin: state.origin.clone(),
        revision: state.revision,
        policy_epoch: state.policy_epoch,
        administrators: state.administrators.clone(),
        limits: state.limits.clone(),
        commands: BTreeMap::new(),
        audit: Vec::new(),
    }
}

fn encoding_error() -> Error {
    Error::new(
        ErrorCode::Corruption,
        "custody point record encoding failed",
    )
}
fn quota_error() -> Error {
    Error::new(ErrorCode::QuotaExceeded, "custody history budget exhausted")
}
fn encoded_len(value: &impl Serialize) -> kasumi_types::Result<u64> {
    struct Counter(u64);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| std::io::Error::other("custody byte overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).map_err(|_| encoding_error())?;
    Ok(counter.0)
}
pub(crate) fn command_bytes(receipt: &CustodyReceipt) -> kasumi_types::Result<u64> {
    encoded_len(&BTreeMap::from([(&receipt.command_id, receipt)]))?
        .checked_sub(2)
        .ok_or_else(encoding_error)
}

impl CustodyHead {
    pub(crate) fn from_state(state: &CustodyState) -> kasumi_types::Result<Self> {
        state.validate()?;
        let mut history_bytes = 0u64;
        for receipt in state.commands.values() {
            history_bytes = history_bytes
                .checked_add(command_bytes(receipt)?)
                .ok_or_else(quota_error)?;
        }
        for event in &state.audit {
            history_bytes = history_bytes
                .checked_add(encoded_len(event)?)
                .ok_or_else(quota_error)?;
        }
        let commands = u64::try_from(state.commands.len()).map_err(|_| quota_error())?;
        let audit = u64::try_from(state.audit.len()).map_err(|_| quota_error())?;
        history_bytes = history_bytes
            .checked_add(commands.saturating_sub(1))
            .and_then(|value| value.checked_add(audit.saturating_sub(1)))
            .ok_or_else(quota_error)?;
        let head = Self {
            version: 1,
            policy: policy(state),
            commands,
            audit,
            history_bytes,
        };
        head.validate()?;
        Ok(head)
    }

    pub(crate) fn validate(&self) -> kasumi_types::Result<()> {
        if self.version != 1
            || !self.policy.commands.is_empty()
            || !self.policy.audit.is_empty()
            || self.commands > self.audit
            || (self.audit == 0) != (self.commands == 0)
            || (self.commands == 0) != (self.history_bytes == 0)
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "unsupported custody point table head",
            ));
        }
        self.policy.validate()?;
        let total = encoded_len(&self.policy)?
            .checked_add(self.history_bytes)
            .ok_or_else(quota_error)?;
        if self.commands > self.policy.limits.max_commands as u64
            || self.audit > self.policy.limits.max_audit_records as u64
            || total > self.policy.limits.max_state_bytes as u64
        {
            return Err(quota_error());
        }
        Ok(())
    }

    /// Reuse the closed reducer on only the referenced receipt. Accounting below
    /// checks its candidate against all retained records before any write escapes.
    pub(crate) fn apply(
        &self,
        prior: Option<CustodyReceipt>,
        context: &RequestContext,
        request: &CustodyRequest,
        admitted_at_ms: u64,
        revision: u64,
    ) -> kasumi_types::Result<(Self, CustodyReceipt, CustodyAudit)> {
        self.validate()?;
        let fresh = prior.is_none();
        let mut selected = self.policy.clone();
        if let Some(prior) = prior {
            prior.validate()?;
            if prior.command_id != request.command_id
                || prior.revision > self.policy.revision
                || prior.policy_epoch > self.policy.policy_epoch
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "custody point receipt differs",
                ));
            }
            selected.commands.insert(prior.command_id.clone(), prior);
        }
        let (mut candidate, receipt) =
            selected.apply(context, request, admitted_at_ms, revision)?;
        let event = candidate.audit.pop().ok_or_else(encoding_error)?;
        let mut history_bytes = self
            .history_bytes
            .checked_add(encoded_len(&event)?)
            .and_then(|n| n.checked_add(u64::from(self.audit != 0)))
            .ok_or_else(quota_error)?;
        if fresh {
            history_bytes = history_bytes
                .checked_add(command_bytes(&receipt)?)
                .and_then(|n| n.checked_add(u64::from(self.commands != 0)))
                .ok_or_else(quota_error)?;
        }
        let next = Self {
            version: 1,
            policy: policy(&candidate),
            commands: self
                .commands
                .checked_add(u64::from(fresh))
                .ok_or_else(quota_error)?,
            audit: self.audit.checked_add(1).ok_or_else(quota_error)?,
            history_bytes,
        };
        next.validate()?;
        Ok((next, receipt, event))
    }

    pub(crate) fn write(&self) -> Result<WriteOp> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= HEAD_BYTES,
            "custody policy head exceeds record bound"
        );
        Ok(WriteOp::put(crate::control::META, HEAD, bytes))
    }
}

pub(crate) fn load(store: &TenantStore) -> Result<CustodyHead> {
    let bytes = store
        .get_bounded(crate::control::META, HEAD, HEAD_BYTES)?
        .context("custody point table head absent; unsupported custody storage format")?;
    let head: CustodyHead = serde_json::from_slice(&bytes)?;
    head.validate()?;
    Ok(head)
}

pub(crate) fn receipt(store: &TenantStore, identity: &str) -> Result<Option<CustodyReceipt>> {
    store
        .get_bounded(COMMANDS, identity.as_bytes(), RECORD_BYTES)?
        .map(|bytes| serde_json::from_slice(&bytes).context("invalid custody receipt record"))
        .transpose()
}

pub(crate) fn transition_writes(
    head: &CustodyHead,
    receipt: &CustodyReceipt,
    event: &CustodyAudit,
) -> Result<Vec<WriteOp>> {
    ensure!(
        head.audit != 0 && event.revision == head.policy.revision,
        "custody audit publication position differs"
    );
    let encoded_event = serde_json::to_vec(event)?;
    let encoded_receipt = serde_json::to_vec(receipt)?;
    ensure!(
        encoded_event.len() <= RECORD_BYTES && encoded_receipt.len() <= RECORD_BYTES,
        "custody point record exceeds bound"
    );
    let mut writes = vec![
        head.write()?,
        WriteOp::put(AUDIT, (head.audit - 1).to_be_bytes(), encoded_event),
    ];
    if !event.replay {
        writes.push(WriteOp::put(
            COMMANDS,
            receipt.command_id.as_bytes(),
            encoded_receipt,
        ));
    }
    Ok(writes)
}

/// Snapshot capture uses one encrypted database root, including its exact head.
/// The aggregate materialization here remains a release gap until the custody
/// snapshot transport is replaced by typed streaming records.
#[cfg(test)]
pub(crate) fn snapshot(store: &Arc<TenantStore>) -> Result<CustodyState> {
    let view = store.read_view()?;
    let head: CustodyHead = serde_json::from_slice(
        &view
            .get(crate::control::META, HEAD, HEAD_BYTES)?
            .context("custody point table head absent")?,
    )?;
    head.validate()?;
    let mut state = head.policy.clone();
    let mut count = 0u64;
    view.visit(COMMANDS, RECORD_BYTES, |key, bytes| {
        let receipt: CustodyReceipt = serde_json::from_slice(bytes)?;
        ensure!(
            key == receipt.command_id.as_bytes(),
            "custody receipt key differs"
        );
        count = count
            .checked_add(1)
            .context("custody record count overflow")?;
        ensure!(count <= head.commands, "unexpected custody receipt record");
        ensure!(
            state
                .commands
                .insert(receipt.command_id.clone(), receipt)
                .is_none(),
            "duplicate custody receipt"
        );
        Ok(())
    })?;
    ensure!(count == head.commands, "custody receipt record missing");
    for index in 0..head.audit {
        let event = view
            .get(AUDIT, &index.to_be_bytes(), RECORD_BYTES)?
            .context("custody audit sequence missing")?;
        state.audit.push(serde_json::from_slice(&event)?);
    }
    let mut count = 0u64;
    view.visit(AUDIT, RECORD_BYTES, |key, _| {
        let index = u64::from_be_bytes(key.try_into().context("invalid custody audit key")?);
        ensure!(index < head.audit, "unexpected custody audit record");
        count = count
            .checked_add(1)
            .context("custody record count overflow")?;
        Ok(())
    })?;
    ensure!(count == head.audit, "custody audit count differs");
    state.validate()?;
    ensure!(
        CustodyHead::from_state(&state)? == head,
        "custody point table accounting differs"
    );
    Ok(state)
}

pub(crate) fn prepare_replacement(
    store: &TenantStore,
    replacement: Arc<crate::custody_records::Records>,
) -> Result<Arc<crate::custody_records::Records>> {
    // A newer snapshot cannot discard or substitute a committed permanent
    // identity. The publication gate is held while this installed prefix is read.
    let previous = store
        .get_bounded(crate::control::META, HEAD, HEAD_BYTES)?
        .map(|bytes| serde_json::from_slice::<CustodyHead>(&bytes))
        .transpose()?;
    if let Some(previous) = &previous {
        previous.validate()?;
    }
    for ((namespace, incoming), expected) in replacement.namespaces().into_iter().zip([
        previous.as_ref().map_or(0, |head| head.commands),
        previous.as_ref().map_or(0, |head| head.audit),
    ]) {
        let mut count = 0u64;
        store.visit(namespace, RECORD_BYTES, |key, bytes| {
            count = count
                .checked_add(1)
                .context("custody record count overflow")?;
            ensure!(count <= expected, "unowned custody point record");
            ensure!(
                incoming.get(key)?.as_deref() == Some(bytes),
                "snapshot would erase or replace permanent custody history"
            );
            Ok(())
        })?;
        ensure!(
            count == expected,
            "custody replacement source record missing"
        );
    }
    Ok(replacement)
}
