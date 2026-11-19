//! A claim joins the Control log before a source can publish an external intent.
//! Permanent rows may be staged first. Only the selected prefix proves custody.
use super::*;
use crate::backup_binding::{Pending, Row};
use crate::staged_terminal::AppliedIdentity;
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};

pub(crate) const PREFIX: &[u8] = b"KASUMI_BACKUP_CLAIM_V1\0";
const MAX_COMMAND: usize = 2 << 20;

/// Test-only observer of one claim (`false`) or terminal (`true`) row for a
/// session. It runs after the row is durable and before the selecting
/// generation and the proposer's response publish, so the write is still
/// outstanding. A crash fixture may block here until its process is killed.
#[cfg(test)]
pub(crate) type OutstandingWriteHook = Box<dyn Fn(uuid::Uuid, bool) + Send + Sync>;
#[cfg(test)]
pub(crate) static OUTSTANDING_WRITE_HOOK: std::sync::Mutex<Option<OutstandingWriteHook>> =
    std::sync::Mutex::new(None);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimCommand {
    pub context: RequestContext,
    pub epoch: u64,
    pub timestamp_ms: u64,
    pub claim: BackupBindingClaim,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<BackupBindingTerminal>,
}

impl ClaimCommand {
    pub(crate) fn encode(&self) -> anyhow::Result<Vec<u8>> {
        self.claim.validate()?;
        if let Some(terminal) = &self.terminal {
            terminal.validate(&self.claim)?;
        }
        let mut bytes = PREFIX.to_vec();
        serde_json::to_writer(&mut bytes, self)?;
        ensure!(
            bytes.len() <= MAX_COMMAND,
            "backup claim command exceeds bound"
        );
        Ok(bytes)
    }
}

impl TenantEngine {
    pub(crate) fn apply_backup_claim(
        &self,
        position: &kasumi_raft::AppliedEntryContext,
        bytes: &[u8],
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
    ) -> anyhow::Result<()> {
        ensure!(
            bytes.len() <= MAX_COMMAND && position.retirement_seed.is_none(),
            "invalid backup claim frame"
        );
        let command: ClaimCommand = super::decode_canonical_json(&bytes[PREFIX.len()..])?;
        command.claim.validate()?;
        if let Some(terminal) = &command.terminal {
            terminal.validate(&command.claim)?;
        }
        let is_terminal = command.terminal.is_some();
        #[cfg(test)]
        let observed = (command.claim.session_id, is_terminal);
        ensure!(
            hex::encode(Sha256::digest(bytes)) == position.command_sha256,
            "Control claim differs from applied command identity"
        );
        let apply = ApplyOwner::lock(self, || {
            anyhow::anyhow!("Control apply ownership unavailable")
        })?;
        let previous = apply.current();
        ensure!(
            previous.state.tenant == crate::control::CONTROL_TENANT,
            "backup claim applied outside Control"
        );
        let mut state = previous.state.clone();
        state.revision = self
            .revision_base
            .checked_add(position.log_id.index)
            .context("backup claim revision exhausted")?;
        ensure!(
            state.revision > previous.state.revision,
            "backup claim did not advance"
        );
        let mut outcome: Result<()> = command
            .context
            .authorization
            .require_control(&state.incarnation)
            .and_then(|()| authorize_state(&state, &command.context, None, Action::Admin));
        if state.policy_epoch != command.epoch
            || state.suspended
            || state.retired
            || state
                .lifecycle_control
                .as_ref()
                .is_some_and(|control| control.retired || control.pending_change.is_some())
        {
            outcome = Err(Error::new(
                ErrorCode::Conflict,
                "Control authority changed during backup claim",
            ));
        }
        let mut pending = None;
        if outcome.is_ok() {
            let session = command.claim.session_id;
            let claim = previous.backup_bindings.get(session)?;
            let existing = if is_terminal {
                previous.backup_bindings.terminal(session)?
            } else {
                claim.clone()
            };
            if is_terminal
                && !claim
                    .as_ref()
                    .is_some_and(|old| old.record.claim == command.claim)
            {
                outcome = Err(Error::new(
                    ErrorCode::Conflict,
                    "terminal decision lacks its original backup claim",
                ));
            } else if let Some(old) = existing {
                if old.record.claim != command.claim || old.terminal != command.terminal {
                    outcome = Err(Error::new(
                        ErrorCode::Conflict,
                        "backup session already has an immutable decision",
                    ));
                }
            } else {
                let record = match claim {
                    Some(claim) => claim.record,
                    None => BackupBindingRecord {
                        claim: command.claim,
                        position: BackupBindingPosition {
                            term: position.log_id.leader_id.term,
                            index: position.log_id.index,
                            command_sha256: position.command_sha256.clone(),
                        },
                    },
                };
                let row = Row {
                    key: if is_terminal {
                        format!("terminal/{session}")
                    } else {
                        session.to_string()
                    },
                    record,
                    terminal: command.terminal,
                    ordinal: state
                        .backup_binding_head
                        .count
                        .checked_add(1)
                        .context("backup claim ordinal exhausted")?,
                    previous_sha256: state.backup_binding_head.sha256.clone(),
                    applied: AppliedIdentity::ordered(
                        &state.incarnation,
                        state.revision,
                        command.timestamp_ms,
                        position,
                    )?,
                };
                if state
                    .backup_binding_head
                    .encoded_bytes
                    .checked_add(row.framed_bytes()?)
                    .is_none_or(|n| n > state.limits.max_backup_binding_bytes)
                {
                    outcome = Err(Error::new(
                        ErrorCode::ResourceExhausted,
                        "Control backup binding capacity exhausted",
                    ));
                } else {
                    let next = Pending::prepare(&previous.backup_bindings, &state, row)?;
                    state.backup_binding_head = next.head().clone();
                    pending = Some(next);
                }
            }
        }
        let event = AuditEvent {
            event_id: format!("{}:{}", state.incarnation, state.revision),
            principal: command.context.principal,
            action: if is_terminal {
                "backup_session_terminal"
            } else {
                "backup_session_claim"
            }
            .into(),
            request_id: command.context.request_id,
            timestamp_ms: command.timestamp_ms,
            data_revision: Some(state.revision),
            outcome: if outcome.is_ok() {
                "committed"
            } else {
                "rejected"
            }
            .into(),
            collection: None,
        };
        append_audit(&mut state, event)?;
        let changed = ChangedIds::new();
        let mut accounting = previous.snapshot_accounting.updated(
            &previous.state,
            &state,
            &changed,
            &BTreeSet::new(),
        )?;
        if !crate::accounting::audit_fits(&state)
            || !accounting.fits(&state)?
            || !lifecycle::completion_fits(&state, &accounting)?
        {
            let revision = state.revision;
            state = previous.state.clone();
            state.revision = revision;
            accounting = previous.snapshot_accounting.clone();
            pending = None;
            outcome = Err(Error::new(
                ErrorCode::ResourceExhausted,
                "Control backup claim or audit exceeds capacity",
            ));
        }
        let bindings = match pending {
            Some(row) => {
                let persisted = row.persist()?;
                #[cfg(test)]
                if let Some(hook) = OUTSTANDING_WRITE_HOOK
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .as_ref()
                {
                    hook(observed.0, observed.1);
                }
                persisted
            }
            None => previous.backup_bindings.clone(),
        };
        let generation = Arc::new(Generation {
            state,
            snapshot_accounting: accounting,
            backup_bindings: bindings,
            indexes: previous.indexes.clone(),
            receipts: previous.receipts.clone(),
            terminals: previous.terminals.clone(),
            target_resolutions: previous.target_resolutions.clone(),
            staged_documents: previous.staged_documents.clone(),
            application_selection: Default::default(),
            document_sources: Default::default(),
            _read_reservations: vec![],
        });
        let response = kasumi_raft::AppliedResponse::application(serde_json::to_vec(&outcome)?);
        self.publish_prepared_generation(
            apply.accept(generation, changed)?,
            response,
            Some(position),
            publisher,
        )
    }
}
