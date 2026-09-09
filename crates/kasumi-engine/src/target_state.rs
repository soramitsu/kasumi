//! Closed target execution envelope. It is disjoint from ordinary tenant
//! commands; deterministic replay verifies the original signed phase and the
//! actual consensus leader/membership rather than constructing Data authority.
use super::*;
use crate::target_invocation::PreparedTargetAuthorization;
use serde::{Deserialize, Serialize};
#[path = "target_completion_receiver.rs"]
pub(super) mod receiver;

pub(crate) const PREFIX: &[u8] = b"KASUMI_TARGET_V2\0";
pub(crate) const MAX_COMMAND_BYTES: usize = 256 << 10;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum TargetCommand {
    PrepareComplete {
        authorization: PreparedTargetAuthorization,
        input: TargetCompletionInput,
    },
    ResolveComplete {
        authorization: PreparedTargetAuthorization,
        input: Box<TargetCompletionResolutionInput>,
    },
    MaintainBudget {
        authorization: PreparedTargetAuthorization,
        input: TargetResolutionBudgetInput,
    },
    Activate {
        authorization: PreparedTargetAuthorization,
        activation: Box<kasumi_serving::SignedAuthorityReceipt>,
    },
    Complete {
        authorization: PreparedTargetAuthorization,
        input: TargetCompletionInput,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum TargetOutcome {
    Prepared(Box<TargetCompletionAttempt>),
    Resolved(Box<TargetCompletionResolutionFact>),
    Budget(Box<TargetResolutionBudgetFact>),
    Completed(Box<TargetCompletionFact>),
    Activated(Box<TargetActivationFact>),
}
impl TargetCommand {
    fn authorization(&self) -> &PreparedTargetAuthorization {
        match self {
            Self::PrepareComplete { authorization, .. }
            | Self::ResolveComplete { authorization, .. }
            | Self::MaintainBudget { authorization, .. }
            | Self::Complete { authorization, .. }
            | Self::Activate { authorization, .. } => authorization,
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = PREFIX.to_vec();
        serde_json::to_writer(&mut bytes, self)
            .map_err(|_| error(ErrorCode::InvalidArgument, "target command encoding failed"))?;
        if bytes.len() > MAX_COMMAND_BYTES {
            return Err(error(
                ErrorCode::ResourceExhausted,
                "target command too large",
            ));
        }
        Ok(bytes)
    }
}
impl TenantEngine {
    pub(crate) fn apply_target(
        &self,
        position: &kasumi_raft::AppliedEntryContext,
        bytes: &[u8],
    ) -> anyhow::Result<kasumi_raft::AppliedResponse> {
        anyhow::ensure!(
            bytes.len() <= MAX_COMMAND_BYTES && position.retirement_seed.is_none(),
            "invalid target command size or custody seed"
        );
        let command: TargetCommand = serde_json::from_slice(&bytes[PREFIX.len()..])?;
        let _guard = self
            .apply_lock
            .lock()
            .map_err(|_| error(ErrorCode::Unavailable, "target apply lock poisoned"))?;
        let previous = self.generation()?;
        let revision = self
            .revision_base
            .checked_add(position.log_id.index)
            .ok_or_else(|| error(ErrorCode::Corruption, "target revision exhausted"))?;
        anyhow::ensure!(
            revision > previous.state.revision,
            "target revision did not advance"
        );
        let authorization = command.authorization();
        let mut next = previous.state.clone();
        next.revision = revision;
        let outcome = match &command {
            TargetCommand::PrepareComplete {
                authorization,
                input,
            } => receiver::prepare(
                &mut next,
                &previous.target_resolutions,
                position,
                authorization,
                input,
                self,
            )
            .map(|value| TargetOutcome::Prepared(Box::new(value))),
            TargetCommand::ResolveComplete {
                authorization,
                input,
            } => receiver::resolve(
                &mut next,
                &previous.target_resolutions,
                position,
                authorization,
                input,
                self,
            )
            .map(|value| TargetOutcome::Resolved(Box::new(value))),
            TargetCommand::MaintainBudget {
                authorization,
                input,
            } => receiver::maintain(
                &mut next,
                &previous.target_resolutions,
                position,
                authorization,
                input,
                self,
            )
            .map(|value| TargetOutcome::Budget(Box::new(value))),
            TargetCommand::Complete {
                authorization,
                input,
            } => complete(
                &mut next,
                &previous.target_resolutions,
                position,
                authorization,
                input,
                self,
            )
            .map(|fact| TargetOutcome::Completed(Box::new(fact))),
            TargetCommand::Activate {
                authorization,
                activation,
            } => activate(&mut next, position, authorization, activation, self)
                .map(|fact| TargetOutcome::Activated(Box::new(fact))),
        };
        if outcome.is_err() {
            next = previous.state.clone();
            next.revision = revision;
        }
        let mut outcome = outcome;
        let pending = match &outcome {
            Ok(TargetOutcome::Resolved(fact)) => Some(crate::target_resolution::Pending::prepare(
                &previous.target_resolutions,
                &mut next,
                TargetResolutionRecord::Completion(fact.clone()),
                position,
                fact.input.attempt.reserved_terminal_bytes,
            )?),
            Ok(TargetOutcome::Budget(fact)) => Some(crate::target_resolution::Pending::prepare(
                &previous.target_resolutions,
                &mut next,
                TargetResolutionRecord::Budget(fact.clone()),
                position,
                MAX_TARGET_COMPLETION_RECORD_BYTES + (64 << 10),
            )?),
            _ => None,
        };
        {
            let event_id = format!("{}:{revision}", next.incarnation);
            super::append_audit(
                &mut next,
                AuditEvent {
                    event_id,
                    principal: authorization.context.principal.clone(),
                    action: match &command {
                        TargetCommand::PrepareComplete { .. } => "target_prepare_complete",
                        TargetCommand::ResolveComplete { .. } => "target_resolve_complete",
                        TargetCommand::MaintainBudget { .. } => "target_resolution_budget",
                        TargetCommand::Complete { .. } => "target_complete",
                        TargetCommand::Activate { .. } => "target_activate",
                    }
                    .into(),
                    request_id: authorization.context.request_id.clone(),
                    timestamp_ms: authorization.admitted_at_ms,
                    data_revision: Some(revision),
                    outcome: if outcome.is_ok() {
                        "committed"
                    } else {
                        "rejected"
                    }
                    .into(),
                    collection: None,
                },
            )?;
        }
        let mut accounting = SnapshotAccounting::rebuild(&next)?;
        if !crate::accounting::audit_fits(&next) {
            next = previous.state.clone();
            next.revision = revision;
            accounting = previous.snapshot_accounting.clone();
            outcome = Err(error(
                ErrorCode::AuditUnavailable,
                "target hot audit byte budget exhausted",
            ));
        } else if !accounting.fits(&next)?
            || validate_target_history(&next).is_err()
            || !receiver::history_reserve_fits(&next)?
        {
            next = previous.state.clone();
            next.revision = revision;
            accounting = previous.snapshot_accounting.clone();
            outcome = Err(error(
                ErrorCode::ResourceExhausted,
                "target retained state budget exhausted",
            ));
        }
        let target_resolutions = if outcome.is_ok() {
            match pending {
                Some(pending) => pending.persist()?,
                None => previous.target_resolutions.clone(),
            }
        } else {
            previous.target_resolutions.clone()
        };
        target_resolutions.validate_state(&next)?;
        self.publish_generation(Some(Arc::new(Generation {
            terminals: previous.terminals.clone(),
            target_resolutions,
            state: next,
            indexes: previous.indexes.clone(),
            receipt_expiry: previous.receipt_expiry.clone(),
            snapshot_accounting: accounting,
            _read_reservations: vec![],
        })));
        Ok(kasumi_raft::AppliedResponse::application(
            serde_json::to_vec(&outcome)?,
        ))
    }
}
fn complete(
    state: &mut TenantState,
    terminals: &crate::target_resolution::View,
    position: &kasumi_raft::AppliedEntryContext,
    authorization: &PreparedTargetAuthorization,
    input: &TargetCompletionInput,
    engine: &TenantEngine,
) -> Result<TargetCompletionFact> {
    let entry = state
        .target_lifecycle
        .get(&state.incarnation)
        .ok_or_else(|| error(ErrorCode::Forbidden, "closed native target origin required"))?;
    let origin = entry.origin.clone();
    let access = engine.access.get().ok_or_else(|| {
        error(
            ErrorCode::Forbidden,
            "installed target storage authority required",
        )
    })?;
    let serving = access
        .serving_gate()
        .ok_or_else(|| error(ErrorCode::Forbidden, "installed target issuer required"))?;
    let trust = serving
        .authority()
        .map_err(|_| error(ErrorCode::Sealed, "target issuer unavailable"))?;
    authorization.verify(
        &trust,
        &origin,
        LifecyclePhase::Complete,
        &input.digest()?,
        position.log_id.leader_id.node_id,
    )?;
    if input.quorum.origin_sha256 != origin.digest()? {
        return Err(error(
            ErrorCode::Conflict,
            "target completion origin changed",
        ));
    }
    let bootstrap =
        kasumi_serving::verify_target_materializations(&origin, &input.quorum.materialized)
            .map_err(|_| {
                error(
                    ErrorCode::Forbidden,
                    "exact native target materialization proofs required",
                )
            })?;
    let membership = position.membership.membership();
    let voters: BTreeSet<_> = origin.input.voters.keys().copied().collect();
    if membership.get_joint_config() != &vec![voters]
        || membership.nodes().count() != origin.input.voters.len()
        || membership.nodes().any(|(id, node)| {
            origin
                .input
                .voters
                .get(id)
                .is_none_or(|peer| node.addr != peer.endpoint)
        })
    {
        return Err(error(
            ErrorCode::Conflict,
            "actual target quorum differs from committed placement",
        ));
    }
    if let Some(existing) = &entry.completion {
        if existing.completion_intent == authorization.grant.claims.commitment.intent
            && existing.materialized == input.quorum.materialized
            && existing.predecessor == input.predecessor
        {
            return Ok(existing.clone());
        }
        return Err(error(
            ErrorCode::Conflict,
            "target already completed under another permanent identity",
        ));
    }
    receiver::require_active(state, terminals, authorization, input)?;
    if !state.suspended
        || state.retired
        || state
            .pending_restore
            .as_ref()
            .map(|marker| marker.backup_id.as_str())
            != Some(origin.input.backup_id.to_string().as_str())
    {
        return Err(error(
            ErrorCode::Conflict,
            "target is not the pending suspended image",
        ));
    }
    let fact = TargetCompletionFact {
        origin,
        materialized: input.quorum.materialized.clone(),
        predecessor: input.predecessor.clone(),
        completion_intent: authorization.grant.claims.commitment.intent.clone(),
        admitted_at_ms: authorization.admitted_at_ms,
        revision: state.revision,
        term: position.log_id.leader_id.term,
        leader_node_id: position.log_id.leader_id.node_id,
        bootstrap_sha256: bootstrap,
    };
    fact.validate()?;
    state.pending_restore = None;
    state
        .target_lifecycle
        .get_mut(&state.incarnation)
        .expect("checked target")
        .completion = Some(fact.clone());
    Ok(fact)
}
fn error(code: ErrorCode, message: &str) -> Error {
    Error::new(code, message)
}

fn activate(
    state: &mut TenantState,
    position: &kasumi_raft::AppliedEntryContext,
    authorization: &PreparedTargetAuthorization,
    signed: &kasumi_serving::SignedAuthorityReceipt,
    engine: &TenantEngine,
) -> Result<TargetActivationFact> {
    let entry = state
        .target_lifecycle
        .get(&state.incarnation)
        .ok_or_else(|| error(ErrorCode::Forbidden, "closed target origin required"))?;
    let origin = entry.origin.clone();
    let completed = entry
        .completion
        .as_ref()
        .ok_or_else(|| error(ErrorCode::Conflict, "target completion is not committed"))?;
    let serving = engine
        .access
        .get()
        .and_then(|access| access.serving_gate())
        .ok_or_else(|| error(ErrorCode::Forbidden, "installed target issuer required"))?;
    let trust = serving
        .authority()
        .map_err(|_| error(ErrorCode::Sealed, "target issuer unavailable"))?;
    let membership = position.membership.membership();
    if membership.get_joint_config() != &vec![origin.input.voters.keys().copied().collect()]
        || membership.nodes().count() != origin.input.voters.len()
        || membership.nodes().any(|(id, node)| {
            origin
                .input
                .voters
                .get(id)
                .is_none_or(|peer| node.addr != peer.endpoint)
        })
    {
        return Err(error(
            ErrorCode::Conflict,
            "actual activation quorum differs from committed placement",
        ));
    }
    trust.verify_activation(signed.clone()).map_err(|_| {
        error(
            ErrorCode::Forbidden,
            "actual issuer activation proof required",
        )
    })?;
    let kasumi_serving::AuthorityAction::ActivateCommitted {
        fence_id,
        fence_digest,
        target,
        control,
    } = &signed.receipt.command.action
    else {
        return Err(error(
            ErrorCode::Forbidden,
            "closed committed issuer activation required",
        ));
    };
    let input = kasumi_serving::ActivateTargetInput {
        fence_id: *fence_id,
        fence_digest: fence_digest.clone(),
        target: target.clone(),
        completion_sha256: completed.digest()?,
    };
    authorization.verify(
        &trust,
        &origin,
        LifecyclePhase::Activate,
        &input
            .digest()
            .map_err(|_| error(ErrorCode::Conflict, "invalid target activation input"))?,
        position.log_id.leader_id.node_id,
    )?;
    if control.completion.fact() != completed
        || signed.receipt.command.tenant != state.tenant
        || target.incarnation.to_string() != state.incarnation
        || target.checkpoint != origin.materialization.request.checkpoint
        || !matches!(&signed.receipt.outcome, kasumi_serving::AuthorityOutcome::Activated { target: accepted, authority_epoch }
            if accepted == target && Some(*authority_epoch) == origin.materialization.request.source_authority_epoch.checked_add(1))
    {
        return Err(error(
            ErrorCode::Conflict,
            "issuer winner differs from exact completed target",
        ));
    }
    let digest = signed
        .receipt
        .digest()
        .map_err(|_| error(ErrorCode::Corruption, "activation proof digest failed"))?;
    if let Some(accepted) = &entry.activation {
        if accepted.issuer_receipt_sha256 == digest
            && accepted.completion_sha256 == completed.digest()?
        {
            return Ok(accepted.clone());
        }
        return Err(error(
            ErrorCode::Conflict,
            "target already activated under another issuer winner",
        ));
    }
    if state.retired || state.pending_restore.is_some() || !state.suspended {
        return Err(error(
            ErrorCode::Conflict,
            "target activation state differs",
        ));
    }
    let fact = TargetActivationFact {
        position: TargetCommitPosition {
            index: position.log_id.index,
            term: position.log_id.leader_id.term,
            leader_node_id: position.log_id.leader_id.node_id,
            command_sha256: position.command_sha256.clone(),
        },
        intent: authorization.grant.claims.commitment.intent.clone(),
        issuer_receipt_sha256: digest,
        completion_sha256: completed.digest()?,
        admitted_at_ms: authorization.admitted_at_ms,
        revision: state.revision,
    };
    state
        .target_lifecycle
        .get_mut(&state.incarnation)
        .expect("checked target")
        .activation = Some(fact.clone());
    state.suspended = false;
    Ok(fact)
}
