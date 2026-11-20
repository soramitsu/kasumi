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

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Delegation {
    pub confirmation: kasumi_types::RemoteBackupConfirmation,
    pub topology_version: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimCommand {
    pub context: RequestContext,
    pub epoch: u64,
    pub timestamp_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_source: Option<Box<Delegation>>,
    pub claim: BackupBindingClaim,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<BackupBindingTerminal>,
}

/// Only the dedicated backup command uses this reserved grant. Ordinary
/// document writes to Control metadata keep their administrative requirement.
pub(crate) fn authorize_delegation(state: &TenantState, actor: &RequestContext) -> Result<()> {
    let denied = || Error::new(ErrorCode::Forbidden, "dedicated backup grant required");
    actor
        .authorization
        .resource()
        .ok_or_else(denied)?
        .require_control(&state.incarnation)?;
    if state.tenant != crate::control::CONTROL_TENANT
        || actor.tenant != state.tenant
        || state.retired
        || state.suspended
        || actor.scopes.len() != 1
        || !actor.scopes.contains(&Action::Write)
        || !state.policy.grants.iter().any(|g| {
            g.principal == actor.principal
                && g.collection.as_deref() == Some(BACKUP_DELEGATION_COLLECTION)
                && g.actions.contains(&Action::Write)
        })
    {
        return Err(denied());
    }
    Ok(())
}

/// Inspect only the named route and issuing node in this authenticated
/// generation. The stored document loan owns the bounded physical read. A
/// storage failure must stop apply, never create a divergent logical refusal.
pub(crate) fn route_version(
    generation: &Generation,
    observed: &RemoteBackupConfirmation,
) -> anyhow::Result<Option<u64>> {
    let state = &generation.state;
    let source = &observed.original.reference;
    ensure!(
        state.tenant == crate::control::CONTROL_TENANT,
        "backup route requires Control"
    );
    let collection = state
        .collections
        .get("topology")
        .context("Control topology collection absent")?;
    ensure!(
        *collection.definition == crate::control::ControlPlane::topology_definition(),
        "Control topology schema differs"
    );
    let slot = collection
        .documents
        .get("current")
        .context("current Control topology absent")?;
    let document = generation.load_document(slot)?;
    let route = document
        .body
        .get("tenants")
        .and_then(|t| t.get(&source.tenant));
    let node = document
        .body
        .get("nodes")
        .and_then(|n| n.get(source.source_node.to_string()));
    let Some(voters) = route
        .and_then(|r| r.get("voters"))
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(None);
    };
    let Some(pins) = node
        .and_then(|n| n.get("certificate_pins"))
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(None);
    };
    let matched = route
        .and_then(|r| r.get("incarnation"))
        .and_then(serde_json::Value::as_str)
        == Some(source.source_incarnation.as_str())
        && route
            .and_then(|r| r.get("mode"))
            .and_then(serde_json::Value::as_str)
            == Some("replicated")
        && voters.len() == observed.voters.len()
        && observed
            .voters
            .iter()
            .all(|id| voters.iter().any(|v| v.as_u64() == Some(*id)))
        && (1..=2).contains(&pins.len())
        && pins
            .iter()
            .any(|p| p.as_str() == Some(observed.source_certificate_sha256.as_str()));
    Ok(matched.then_some(document.version))
}

impl ClaimCommand {
    pub(crate) fn encode(&self) -> anyhow::Result<Vec<u8>> {
        self.claim.validate()?;
        if let Some(terminal) = &self.terminal {
            terminal.validate(&self.claim)?;
        }
        if let Some(source) = &self.remote_source {
            source.confirmation.validate()?;
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
            .and_then(|()| {
                if command.remote_source.is_some() {
                    command
                        .context
                        .authorization
                        .check_admitted_at(command.timestamp_ms)
                        .and_then(|()| authorize_delegation(&state, &command.context))
                } else {
                    authorize_state(&state, &command.context, None, Action::Admin)
                }
            });
        if let Some(source) = &command.remote_source {
            source.confirmation.validate()?;
            let observed = &source.confirmation;
            let original = &observed.original.reference;
            let action = match &command.terminal {
                Some(terminal) => kasumi_types::RemoteBackupAction::Decide {
                    claim: command.claim.clone(),
                    terminal: Box::new(terminal.clone()),
                },
                None => kasumi_types::RemoteBackupAction::Claim {
                    claim: command.claim.clone(),
                },
            };
            let version = route_version(previous, observed)?;
            if original.action_sha256 != kasumi_types::staged_digest(&action)?.0
                || original.session != command.claim.session_id
                || original.tenant != command.claim.tenant
                || original.source_incarnation != command.claim.source_incarnation
                || original.control_incarnation.to_string() != state.incarnation
                || version != Some(source.topology_version)
                || state
                    .lifecycle_control
                    .as_ref()
                    .is_none_or(|state| state.retired || state.pending_change.is_some())
            {
                outcome = Err(Error::new(
                    ErrorCode::Conflict,
                    "dedicated backup source route changed",
                ));
            }
        }
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
