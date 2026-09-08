//! Closed replicated recovery journal. Ordinary document commands cannot write
//! these records. Every remote effect has an exact durable phase before dispatch.
use super::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[path = "recovery_quorum.rs"]
mod quorum;
pub(crate) use quorum::{completion_route_retry, quorum_input, started_for};

#[path = "recovery_source.rs"]
mod source;
pub(crate) use source::{issuer_action, retirement_request};
#[path = "recovery_activation.rs"]
pub(crate) mod activation;
#[path = "recovery_completion.rs"]
pub(crate) mod completion;
#[path = "recovery_route.rs"]
pub(crate) mod route;

pub(crate) const PREFIX: &[u8] = b"KASUMI_RECOVERY_V1\0";
pub(crate) const MAX_COMMAND_BYTES: usize = (2 << 20) + 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryAuthorization {
    pub context: RequestContext,
    pub policy_epoch: u64,
    pub admitted_at_ms: u64,
    pub expires_at_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum RecoveryMutation {
    Start(Box<RecoveryStart>),
    Stop {
        operation_id: Uuid,
        command_id: Uuid,
    },
    Prepare {
        operation_id: Uuid,
        phase_id: Uuid,
        expected_sequence: u64,
        expected_pending: Option<Uuid>,
        input: Box<RecoveryDispatch>,
    },
    PublishRoute {
        operation_id: Uuid,
        phase_id: Uuid,
    },
    Resolve {
        operation_id: Uuid,
        phase_id: Uuid,
        outcome: Box<RecoveryDispatchOutcome>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryCommand {
    pub authorization: RecoveryAuthorization,
    pub mutation: RecoveryMutation,
}
impl RecoveryCommand {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if staged_digest(self)?.1 + PREFIX.len() > MAX_COMMAND_BYTES {
            return Err(error(
                ErrorCode::ResourceExhausted,
                "recovery command work limit",
            ));
        }
        let mut bytes = PREFIX.to_vec();
        serde_json::to_writer(&mut bytes, self)
            .map_err(|_| error(ErrorCode::Corruption, "recovery command encoding"))?;
        Ok(bytes)
    }
}
fn error(code: ErrorCode, message: &str) -> Error {
    Error::new(code, message)
}
fn conflict(message: &str) -> Error {
    error(ErrorCode::Conflict, message)
}
fn same<T: Serialize>(left: &T, right: &T) -> Result<bool> {
    Ok(staged_digest(left)? == staged_digest(right)?)
}
// Phase UUIDs occupy one permanent Control-wide namespace.
pub(crate) fn phase_key(_operation: Uuid, phase: Uuid) -> String {
    phase.to_string()
}
pub(crate) fn phase<'a>(
    state: &'a TenantState,
    operation: &RecoveryRecord,
    id: Uuid,
) -> Result<&'a RecoveryPhaseRecord> {
    state
        .recovery_control
        .phases
        .get(&phase_key(operation.request.operation_id, id))
        .filter(|phase| phase.operation_id == operation.request.operation_id)
        .ok_or_else(|| error(ErrorCode::Corruption, "recovery phase reference missing"))
}
pub(crate) fn intent<'a>(
    state: &'a TenantState,
    operation: &RecoveryRecord,
    id: Uuid,
) -> Result<&'a LifecycleIntent> {
    match &phase(state, operation, id)?.outcome {
        Some(RecoveryDispatchOutcome::ControlIntent(value)) => Ok(value),
        _ => Err(error(
            ErrorCode::Corruption,
            "recovery intent reference is not a committed intent",
        )),
    }
}
pub(crate) fn origin(state: &TenantState, operation: &RecoveryRecord) -> Result<TargetOrigin> {
    let original = intent(
        state,
        operation,
        operation
            .materialization_intent
            .ok_or_else(|| conflict("original materialization intent absent"))?,
    )?;
    let partition = partition(state, operation)?;
    let origin = TargetOrigin {
        authority_manifest_sha256: partition.manifest_sha256.clone(),
        materialization: original.clone(),
        input: operation.request.materialization.clone(),
    };
    origin.validate()?;
    Ok(origin)
}
pub(crate) fn dispatch_limit(
    operation: &RecoveryRecord,
    phase: &RecoveryPhaseRecord,
) -> Result<u64> {
    Ok(phase
        .admitted_at_ms
        .checked_add(operation.request.phase_timeout_ms)
        .ok_or_else(|| conflict("recovery phase deadline overflow"))?
        .min(phase.original_credential_expires_at_ms))
}
pub(crate) fn target(request: &RecoveryStart) -> RecoveryTarget {
    RecoveryTarget {
        incarnation: request.target_incarnation,
        checkpoint: request.checkpoint.clone(),
        nodes: request
            .target_nodes
            .values()
            .map(|node| NodeIdentity {
                node_id: node.node_id,
                verifier: node.verifier.clone(),
                principal: node.principal.clone(),
                certificate_sha256: node.certificate_sha256.clone(),
            })
            .collect(),
    }
}
fn partition<'a>(
    state: &'a TenantState,
    operation: &RecoveryRecord,
) -> Result<&'a ControlAuthorityPartition> {
    state
        .lifecycle_control
        .as_ref()
        .and_then(|control| {
            control
                .installation
                .partitions
                .get(&operation.request.authority_partition)
        })
        .ok_or_else(|| conflict("recovery issuer installation absent"))
}
fn authorize(state: &TenantState, authorization: &RecoveryAuthorization) -> Result<()> {
    if state.tenant != "__kasumi_control" || authorization.context.tenant != state.tenant {
        return Err(error(
            ErrorCode::Forbidden,
            "recovery requires installed Control authority",
        ));
    }
    authorization
        .context
        .authorization
        .require_control(&state.incarnation)?;
    authorize_state(state, &authorization.context, None, Action::Admin)?;
    let control = state
        .lifecycle_control
        .as_ref()
        .ok_or_else(|| conflict("recovery needs installed lifecycle Control"))?;
    if control.retired
        || control.pending_change.is_some()
        || state.retired
        || state.suspended
        || authorization.policy_epoch != state.policy_epoch
        || authorization.admitted_at_ms >= authorization.expires_at_ms
        || authorization.context.authorization.expires_at_ms() != Some(authorization.expires_at_ms)
    {
        return Err(error(
            ErrorCode::Unauthorized,
            "recovery admission authority or original deadline differs",
        ));
    }
    Ok(())
}
impl TenantEngine {
    pub(crate) fn apply_recovery(
        &self,
        position: &kasumi_raft::AppliedEntryContext,
        bytes: &[u8],
    ) -> anyhow::Result<kasumi_raft::AppliedResponse> {
        anyhow::ensure!(
            bytes.len() <= MAX_COMMAND_BYTES && position.retirement_seed.is_none(),
            "invalid recovery command work or custody seed"
        );
        let command: RecoveryCommand = serde_json::from_slice(&bytes[PREFIX.len()..])?;
        let _guard = self
            .apply_lock
            .lock()
            .map_err(|_| conflict("recovery apply ownership unavailable"))?;
        let previous = self.generation()?;
        let revision = self
            .revision_base
            .checked_add(position.log_id.index)
            .ok_or_else(|| conflict("recovery revision exhausted"))?;
        anyhow::ensure!(
            revision > previous.state.revision,
            "recovery applied position did not advance"
        );
        let mut next = previous.state.clone();
        next.revision = revision;
        let mut outcome =
            authorize(&next, &command.authorization).and_then(|()| apply(&mut next, &command));
        if outcome.is_err() {
            next = previous.state.clone();
            next.revision = revision;
        }
        let event = AuditEvent {
            event_id: format!("{}:{revision}", next.incarnation),
            principal: command.authorization.context.principal.clone(),
            action: match command.mutation {
                RecoveryMutation::Start(_) => "recovery_start",
                RecoveryMutation::Stop { .. } => "recovery_stop",
                RecoveryMutation::Prepare { .. } => "recovery_phase_prepare",
                RecoveryMutation::Resolve { .. } => "recovery_phase_resolve",
                RecoveryMutation::PublishRoute { .. } => "recovery_route_publish",
            }
            .into(),
            request_id: command.authorization.context.request_id.clone(),
            timestamp_ms: command.authorization.admitted_at_ms,
            data_revision: Some(revision),
            outcome: if outcome.is_ok() {
                "committed"
            } else {
                "rejected"
            }
            .into(),
            collection: None,
        };
        append_audit(&mut next, event)?;
        let changed = if previous
            .state
            .collections
            .get(route::COLLECTION)
            .and_then(|c| c.documents.get(route::DOCUMENT))
            .map(|d| d.version)
            != next
                .collections
                .get(route::COLLECTION)
                .and_then(|c| c.documents.get(route::DOCUMENT))
                .map(|d| d.version)
        {
            BTreeMap::from([(
                route::COLLECTION.to_string(),
                BTreeSet::from([route::DOCUMENT.to_string()]),
            )])
        } else {
            BTreeMap::new()
        };
        if !changed.is_empty()
            && let Err(failure) =
                crate::change_feed_state::append(&previous.state, &mut next, &changed)
        {
            next = previous.state.clone();
            next.revision = revision;
            outcome = Err(failure);
        }
        let changed = if outcome.is_ok() {
            changed
        } else {
            BTreeMap::new()
        };
        let mut accounting = previous.snapshot_accounting.updated(
            &previous.state,
            &next,
            &changed,
            &BTreeSet::new(),
            &BTreeSet::new(),
        )?;
        if next.audit_retention.hot_bytes > next.limits.audit_retention.hot_bytes
            || !accounting.fits(&next)?
            || !lifecycle::completion_fits(&next)?
        {
            next = previous.state.clone();
            next.revision = revision;
            accounting = previous.snapshot_accounting.clone();
            outcome = Err(error(
                ErrorCode::ResourceExhausted,
                "recovery retained state or audit capacity unavailable",
            ));
        }
        let indexes = if outcome.is_ok() && !changed.is_empty() {
            Arc::new(previous.indexes.update(
                &previous.state.collections,
                &next.collections,
                &changed,
            )?)
        } else {
            previous.indexes.clone()
        };
        self.publish_generation(Some(Arc::new(Generation {
            terminals: previous.terminals.clone(),
            state: next,
            indexes,
            receipt_expiry: previous.receipt_expiry.clone(),
            snapshot_accounting: accounting,
            _read_reservations: vec![],
        })));
        Ok(kasumi_raft::AppliedResponse::application(
            serde_json::to_vec(&outcome)?,
        ))
    }
}
fn apply(state: &mut TenantState, command: &RecoveryCommand) -> Result<RecoveryRecord> {
    if let RecoveryMutation::Start(request) = &command.mutation {
        request.validate()?;
        if let Some(existing) = state
            .recovery_control
            .operations
            .get(&request.operation_id.to_string())
        {
            if existing.request != **request {
                return Err(conflict("permanent recovery operation identity differs"));
            }
            return Ok(existing.clone());
        }
        let installation = &state
            .lifecycle_control
            .as_ref()
            .ok_or_else(|| conflict("Control installation absent"))?
            .installation;
        if request.expected_policy_epoch != state.policy_epoch
            || request.installation_sha256 != staged_digest(installation)?.0
            || !installation
                .partitions
                .contains_key(&request.authority_partition)
        {
            return Err(conflict(
                "recovery Control installation or admission epoch differs",
            ));
        }
        if state
            .recovery_control
            .targets
            .contains_key(&request.target_incarnation.to_string())
        {
            return Err(conflict(
                "target incarnation is permanently bound to another recovery",
            ));
        }
        let record = RecoveryRecord {
            request: request.as_ref().clone(),
            request_sha256: request.digest()?,
            original_principal: command.authorization.context.principal.clone(),
            created_revision: state.revision,
            updated_revision: state.revision,
            phase: RecoveryPhase::Prepare,
            next_phase_sequence: 1,
            pending_phase: None,
            last_phase: None,
            current_intent: None,
            materialization_intent: None,
            issuer_preparation: None,
            initialization: None,
            completion_intent: None,
            completion_attempt: None,
            completion: None,
            retirement: None,
            source_fence: None,
            activation_attempt: None,
            activation: None,
            route_publication: None,
            stop_request: None,
            target_stop: None,
            voters: request
                .target_nodes
                .keys()
                .map(|id| (*id, RecoveryVoterProgress::default()))
                .collect(),
        };
        record.validate()?;
        state
            .recovery_control
            .targets
            .insert(request.target_incarnation.to_string(), request.operation_id);
        state
            .recovery_control
            .operations
            .insert(request.operation_id.to_string(), record.clone());
        return Ok(record);
    }
    let operation_id = match command.mutation {
        RecoveryMutation::Stop { operation_id, .. }
        | RecoveryMutation::Prepare { operation_id, .. }
        | RecoveryMutation::Resolve { operation_id, .. }
        | RecoveryMutation::PublishRoute { operation_id, .. } => operation_id,
        RecoveryMutation::Start(_) => unreachable!(),
    };
    let mut operation = state
        .recovery_control
        .operations
        .get(&operation_id.to_string())
        .cloned()
        .ok_or_else(|| error(ErrorCode::NotFound, "recovery operation absent"))?;
    match &command.mutation {
        RecoveryMutation::Stop { command_id, .. } => {
            if command_id.is_nil() {
                return Err(conflict("nil recovery stop identity"));
            }
            if let Some(existing) = operation.stop_request {
                if existing != *command_id {
                    return Err(conflict("permanent recovery stop identity differs"));
                }
                return Ok(operation);
            }
            operation.stop_request = Some(*command_id);
            if operation.activation.is_none() {
                // Pending exact effects remain in the phase chain. Stop seals
                // the target at its issuer before any physical deletion.
                operation.pending_phase = None;
                operation.phase = if operation.activation_attempt.is_some() {
                    RecoveryPhase::StopActivation
                } else {
                    RecoveryPhase::StopTarget
                };
            }
        }
        RecoveryMutation::Prepare {
            phase_id,
            expected_sequence,
            expected_pending,
            input,
            ..
        } => {
            let key = phase_key(operation_id, *phase_id);
            if let Some(existing) = state.recovery_control.phases.get(&key) {
                if existing.operation_id != operation_id
                    || existing.sequence != *expected_sequence
                    || !same(&existing.input, input.as_ref())?
                {
                    return Err(conflict("permanent recovery phase input differs"));
                }
                return Ok(operation);
            }
            if phase_id.is_nil()
                || operation.phase.terminal()
                || operation.next_phase_sequence != *expected_sequence
                || operation.pending_phase != *expected_pending
            {
                return Err(conflict("recovery phase compare-and-set differs"));
            }
            if let Some(pending) = operation.pending_phase {
                let pending = phase(state, &operation, pending)?;
                let expected = match &pending.input {
                    RecoveryDispatch::Target { request, .. }
                        if command.authorization.admitted_at_ms >= request.not_after_ms =>
                    {
                        match request.step {
                            TargetRuntimeStep::Materialize(_)
                            | TargetRuntimeStep::ResumeMaterialization(_) => {
                                Some(LifecyclePhase::ResumeMaterialize)
                            }
                            TargetRuntimeStep::Stop(_) => Some(LifecyclePhase::StopLocal),
                            TargetRuntimeStep::Start(TargetReplicaInput::Quorum(_))
                            | TargetRuntimeStep::Initialize(_)
                                if operation.phase == RecoveryPhase::Initialize =>
                            {
                                Some(LifecyclePhase::Initialize)
                            }
                            TargetRuntimeStep::Start(_)
                            | TargetRuntimeStep::Complete(_)
                            | TargetRuntimeStep::Inspect(_)
                                if operation.phase == RecoveryPhase::Complete =>
                            {
                                Some(LifecyclePhase::InspectTarget)
                            }
                            TargetRuntimeStep::StartActivation { .. }
                            | TargetRuntimeStep::Activate { .. }
                            | TargetRuntimeStep::ConfirmActivation(_)
                                if operation.phase == RecoveryPhase::Confirm =>
                            {
                                Some(LifecyclePhase::Activate)
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                };
                let stop_expired = matches!((&pending.input,input.as_ref()),
                    (RecoveryDispatch::Authority(original),RecoveryDispatch::Authority(stop))
                    if operation.phase==RecoveryPhase::Activate && command.authorization.admitted_at_ms>=original.not_after_ms
                    && matches!(&stop.action,AuthorityAction::StopActivation{original:stopped} if stopped==original));
                let expired_route = matches!(
                    (&pending.input, input.as_ref()),
                    (
                        RecoveryDispatch::PublishRoute(_),
                        RecoveryDispatch::PublishRoute(_)
                    )
                ) && operation.phase == RecoveryPhase::Publish
                    && command.authorization.admitted_at_ms >= dispatch_limit(&operation, pending)?;
                if !completion_route_retry(pending, input, command.authorization.admitted_at_ms)
                    && !expired_route
                    && !stop_expired
                    && !matches!(input.as_ref(), RecoveryDispatch::ControlIntent(request) if Some(request.phase) == expected)
                {
                    return Err(conflict(
                        "resolve the exact pending recovery phase before another dispatch",
                    ));
                }
                if stop_expired {
                    operation.phase = RecoveryPhase::StopActivation;
                }
            }
            validate_input(state, &operation, *phase_id, input, &command.authorization)?;
            if matches!(input.as_ref(), RecoveryDispatch::PublishRoute(_))
                && let Some(old) = operation.pending_phase
            {
                let mut prior = phase(state, &operation, old)?.clone();
                if !matches!(prior.input, RecoveryDispatch::PublishRoute(_))
                    || command.authorization.admitted_at_ms < dispatch_limit(&operation, &prior)?
                {
                    return Err(conflict(
                        "local publication supersession requires its expired original phase",
                    ));
                }
                prior.outcome = Some(RecoveryDispatchOutcome::RouteSuperseded {
                    replacement_phase: *phase_id,
                });
                prior.resolved_revision = Some(state.revision);
                prior.validate()?;
                state
                    .recovery_control
                    .phases
                    .insert(phase_key(operation_id, old), prior);
            }
            let prepared = RecoveryPhaseRecord {
                operation_id,
                phase_id: *phase_id,
                sequence: *expected_sequence,
                phase: operation.phase,
                previous_phase: operation.last_phase,
                input: input.as_ref().clone(),
                input_sha256: staged_digest(input)?.0,
                principal: command.authorization.context.principal.clone(),
                admitted_at_ms: command.authorization.admitted_at_ms,
                original_credential_expires_at_ms: command.authorization.expires_at_ms,
                prepared_revision: state.revision,
                outcome: None,
                resolved_revision: None,
            };
            prepared.validate()?;
            state.recovery_control.phases.insert(key, prepared);
            if matches!(input.as_ref(),RecoveryDispatch::Authority(command) if matches!(command.action,AuthorityAction::ActivateCommitted{..}))
            {
                operation.activation_attempt = Some(*phase_id);
            }
            if matches!(input.as_ref(), RecoveryDispatch::Target { request, .. } if matches!(request.step, TargetRuntimeStep::Complete(_)))
            {
                operation.completion_attempt = Some(*phase_id);
            }
            operation.pending_phase = Some(*phase_id);
            operation.last_phase = Some(*phase_id);
            operation.next_phase_sequence = operation
                .next_phase_sequence
                .checked_add(1)
                .ok_or_else(|| conflict("recovery phase sequence exhausted"))?;
        }
        RecoveryMutation::PublishRoute { phase_id, .. } => {
            let key = phase_key(operation_id, *phase_id);
            let mut prepared = phase(state, &operation, *phase_id)?.clone();
            let RecoveryDispatch::PublishRoute(input) = &prepared.input else {
                return Err(conflict("route publication phase input differs"));
            };
            if prepared.outcome.is_some() {
                return Ok(operation);
            }
            if operation.phase != RecoveryPhase::Publish
                || operation.pending_phase != Some(*phase_id)
                || command.authorization.admitted_at_ms >= dispatch_limit(&operation, &prepared)?
            {
                return Err(conflict("original route publication is no longer eligible"));
            }
            let outcome = route::apply(
                state,
                &operation,
                input,
                command.authorization.admitted_at_ms,
            )?;
            prepared.outcome = Some(outcome.clone());
            prepared.resolved_revision = Some(state.revision);
            route::validate_outcome(&prepared, input, &outcome)?;
            advance(state, &mut operation, &prepared, &outcome)?;
            prepared.validate()?;
            state.recovery_control.phases.insert(key, prepared);
            operation.pending_phase = None;
        }
        RecoveryMutation::Resolve {
            phase_id, outcome, ..
        } => {
            let key = phase_key(operation_id, *phase_id);
            let mut prepared = phase(state, &operation, *phase_id)?.clone();
            if let Some(existing) = &prepared.outcome {
                if !same(existing, outcome.as_ref())? {
                    return Err(conflict("permanent recovery phase outcome differs"));
                }
                return Ok(operation);
            }
            if matches!(prepared.input, RecoveryDispatch::PublishRoute(_)) {
                return Err(conflict(
                    "route outcome must be committed atomically with its topology update",
                ));
            }
            if operation.pending_phase != Some(*phase_id) {
                return Err(conflict(
                    "recovery phase was superseded; retain its original history",
                ));
            }
            validate_outcome(state, &operation, &prepared, outcome)?;
            if let (
                RecoveryDispatch::Authority(command),
                RecoveryDispatchOutcome::Authority(signed),
            ) = (&prepared.input, outcome.as_ref())
                && let AuthorityAction::StopActivation { original } = &command.action
                && matches!(
                    signed.receipt.outcome,
                    AuthorityOutcome::ActivationResolved { .. }
                )
            {
                let original_key = phase_key(operation_id, original.command_id);
                let mut original_phase = phase(state, &operation, original.command_id)?.clone();
                let resolved = RecoveryDispatchOutcome::AuthorityResolution(signed.clone());
                if let Some(existing) = &original_phase.outcome {
                    if activation::original_receipt(existing)?
                        != activation::original_receipt(&resolved)?
                    {
                        return Err(conflict(
                            "activation stop changed permanent original outcome",
                        ));
                    }
                } else {
                    validate_outcome(state, &operation, &original_phase, &resolved)?;
                    original_phase.outcome = Some(resolved);
                    original_phase.resolved_revision = Some(state.revision);
                    original_phase.validate()?;
                    state
                        .recovery_control
                        .phases
                        .insert(original_key, original_phase);
                }
            }
            if matches!((&prepared.input, outcome.as_ref()), (RecoveryDispatch::Target { request, .. }, RecoveryDispatchOutcome::Target(response)) if matches!(request.step, TargetRuntimeStep::Inspect(_)) && matches!(response.outcome, TargetRuntimeOutcome::Inspected(_)))
            {
                prepared.outcome = Some(outcome.as_ref().clone());
                prepared.resolved_revision = Some(state.revision);
                state
                    .recovery_control
                    .phases
                    .insert(key.clone(), prepared.clone());
                completion::resolve_original(state, &operation, prepared.phase_id)?;
            }
            advance(state, &mut operation, &prepared, outcome)?;
            prepared.outcome = Some(outcome.as_ref().clone());
            prepared.resolved_revision = Some(state.revision);
            prepared.validate()?;
            state.recovery_control.phases.insert(key, prepared);
            operation.pending_phase = None;
        }
        RecoveryMutation::Start(_) => unreachable!(),
    }
    operation.updated_revision = state.revision;
    operation.validate()?;
    state
        .recovery_control
        .operations
        .insert(operation_id.to_string(), operation.clone());
    Ok(operation)
}

pub(crate) fn expected_intent(
    state: &TenantState,
    operation: &RecoveryRecord,
    phase_id: Uuid,
    policy_epoch: u64,
    phase: LifecyclePhase,
) -> Result<CommitLifecycleIntent> {
    let original = &operation.request;
    let (phase_input_sha256, resume_origin) = match phase {
        LifecyclePhase::Materialize => (original.materialization.digest()?, None),
        LifecyclePhase::ResumeMaterialize => {
            let origin = origin(state, operation)?;
            (origin.resume_digest()?, Some(Box::new(origin)))
        }
        LifecyclePhase::Initialize => (quorum_input(state, operation)?.digest()?, None),
        LifecyclePhase::Complete => (
            completion::completion_input(state, operation)?.digest()?,
            None,
        ),
        LifecyclePhase::ResolveComplete | LifecyclePhase::MaintainTarget => {
            return Err(conflict(
                "target terminal coordinator phase is not installed",
            ));
        }
        LifecyclePhase::InspectTarget => (
            completion::inspection_input(state, operation)?.digest()?,
            None,
        ),
        LifecyclePhase::Activate => (
            activation::activation_input(state, operation)?
                .digest()
                .map_err(|_| conflict("activation input digest failed"))?,
            None,
        ),
        LifecyclePhase::StopLocal => (
            staged_digest(&(
                "kasumi.stop-local-target-input.v1",
                &stop_reference(state, operation)?,
            ))?
            .0,
            None,
        ),
    };
    Ok(CommitLifecycleIntent {
        command_id: phase_id,
        expected_policy_epoch: policy_epoch,
        installation_sha256: original.installation_sha256.clone(),
        authority_partition: original.authority_partition.clone(),
        tenant: original.tenant.clone(),
        source_incarnation: original.source_incarnation,
        source_authority_epoch: original.source_authority_epoch,
        target_incarnation: original.target_incarnation,
        checkpoint: original.checkpoint.clone(),
        target_nodes: original.target_nodes.clone(),
        phase,
        phase_input_sha256,
        resume_origin,
    })
}
pub(crate) fn stop_reference(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<TargetStopReference> {
    let retained = phase(
        state,
        operation,
        operation
            .target_stop
            .ok_or_else(|| conflict("permanent issuer target stop absent"))?,
    )?;
    let Some(RecoveryDispatchOutcome::Authority(signed)) = &retained.outcome else {
        return Err(conflict("issuer target stop outcome absent"));
    };
    if !matches!(
        signed.receipt.outcome,
        AuthorityOutcome::TargetStopped { .. }
    ) {
        return Err(conflict("issuer did not stop the target"));
    }
    Ok(TargetStopReference {
        tenant: operation.request.tenant.clone(),
        command_id: signed.receipt.command.command_id,
        receipt_digest: signed
            .receipt
            .digest()
            .map_err(|_| conflict("target stop digest failed"))?,
    })
}
fn validate_input(
    state: &TenantState,
    operation: &RecoveryRecord,
    phase_id: Uuid,
    input: &RecoveryDispatch,
    authorization: &RecoveryAuthorization,
) -> Result<()> {
    if staged_digest(input)?.1 > MAX_RECOVERY_RECORD_BYTES / 2 {
        return Err(error(
            ErrorCode::ResourceExhausted,
            "recovery phase input work limit",
        ));
    }
    match (operation.phase, input) {
        (
            RecoveryPhase::Prepare
            | RecoveryPhase::StopTarget
            | RecoveryPhase::FenceSource
            | RecoveryPhase::Activate
            | RecoveryPhase::StopActivation,
            RecoveryDispatch::Authority(command),
        ) => {
            if matches!(
                operation.phase,
                RecoveryPhase::Activate | RecoveryPhase::StopTarget
            ) {
                activation::require_negative_attempt(state, operation)?;
            }
            let action = match operation.phase {
                RecoveryPhase::Activate => activation::current_action(state, operation)?,
                RecoveryPhase::StopActivation => activation::stop_action(state, operation)?,
                _ => issuer_action(operation, operation.phase)?,
            };
            command
                .validate()
                .map_err(|_| conflict("invalid recovery issuer command"))?;
            if command.tenant != operation.request.tenant
                || command.command_id != phase_id
                || command.expected_policy_epoch != operation.request.authority_policy_epoch
                || command.not_after_ms > authorization.expires_at_ms
                || command.not_after_ms
                    > authorization
                        .admitted_at_ms
                        .checked_add(operation.request.phase_timeout_ms)
                        .ok_or_else(|| conflict("phase deadline overflow"))?
                || command.not_after_ms <= authorization.admitted_at_ms
                || command.action != action
                || (operation.phase == RecoveryPhase::Activate
                    && command.not_after_ms
                        > intent(
                            state,
                            operation,
                            operation
                                .current_intent
                                .ok_or_else(|| conflict("activation intent absent"))?,
                        )?
                        .original_credential_expires_at_ms)
            {
                return Err(conflict(
                    "recovery issuer command differs from frozen input or original deadline",
                ));
            }
        }
        (
            RecoveryPhase::Materialize
            | RecoveryPhase::Cleanup
            | RecoveryPhase::Initialize
            | RecoveryPhase::Complete
            | RecoveryPhase::Activate
            | RecoveryPhase::Confirm,
            RecoveryDispatch::ControlIntent(request),
        ) => {
            let phase = if matches!(
                operation.phase,
                RecoveryPhase::Activate | RecoveryPhase::Confirm
            ) {
                LifecyclePhase::Activate
            } else if operation.phase == RecoveryPhase::Initialize {
                LifecyclePhase::Initialize
            } else if operation.phase == RecoveryPhase::Complete {
                if operation.completion_intent.is_some() {
                    LifecyclePhase::InspectTarget
                } else {
                    LifecyclePhase::Complete
                }
            } else if operation.phase == RecoveryPhase::Cleanup {
                LifecyclePhase::StopLocal
            } else if operation.materialization_intent.is_none() {
                LifecyclePhase::Materialize
            } else {
                LifecyclePhase::ResumeMaterialize
            };
            if phase == LifecyclePhase::Complete && operation.completion_intent.is_some() {
                return Err(conflict(
                    "original completion intent must be resolved without replacing its identity",
                ));
            }
            if phase == LifecyclePhase::InspectTarget {
                let current = intent(
                    state,
                    operation,
                    operation
                        .current_intent
                        .ok_or_else(|| conflict("current completion phase absent"))?,
                )?;
                let expired_pending = operation.pending_phase.and_then(|id| self::phase(state, operation, id).ok()).is_some_and(|phase| matches!(&phase.input, RecoveryDispatch::Target { request, .. } if authorization.admitted_at_ms >= request.not_after_ms));
                if authorization.admitted_at_ms < current.original_credential_expires_at_ms
                    && !expired_pending
                {
                    return Err(conflict(
                        "resolve the live original completion phase before fresh inspection",
                    ));
                }
            }
            if phase == LifecyclePhase::ResumeMaterialize {
                let current = intent(
                    state,
                    operation,
                    operation
                        .current_intent
                        .ok_or_else(|| conflict("current materialization phase absent"))?,
                )?;
                let expired_pending = operation.pending_phase.and_then(|id| self::phase(state, operation, id).ok()).is_some_and(|phase| matches!(&phase.input, RecoveryDispatch::Target {request,..} if authorization.admitted_at_ms >= request.not_after_ms));
                if authorization.admitted_at_ms < current.original_credential_expires_at_ms
                    && !expired_pending
                {
                    return Err(conflict(
                        "resolve the original live materialization before a fresh phase",
                    ));
                }
            }
            if **request
                != expected_intent(
                    state,
                    operation,
                    phase_id,
                    authorization.policy_epoch,
                    phase,
                )?
            {
                return Err(conflict(
                    "recovery Control phase differs from its exact frozen origin",
                ));
            }
        }
        (
            RecoveryPhase::Materialize
            | RecoveryPhase::Cleanup
            | RecoveryPhase::Initialize
            | RecoveryPhase::Complete
            | RecoveryPhase::Confirm,
            RecoveryDispatch::Target { node_id, request },
        ) => {
            request
                .validate()
                .map_err(|_| conflict("invalid native target dispatch"))?;
            let voter = operation
                .voters
                .get(node_id)
                .ok_or_else(|| conflict("target is outside the exact recovery voters"))?;
            let current = intent(
                state,
                operation,
                operation
                    .current_intent
                    .ok_or_else(|| conflict("native target needs a committed Control phase"))?,
            )?;
            if request.not_after_ms <= authorization.admitted_at_ms
                || request.not_after_ms > authorization.expires_at_ms
                || request.not_after_ms
                    > authorization
                        .admitted_at_ms
                        .checked_add(operation.request.phase_timeout_ms)
                        .ok_or_else(|| conflict("phase deadline overflow"))?
                || request.not_after_ms > current.original_credential_expires_at_ms
                || authorization.admitted_at_ms >= current.original_credential_expires_at_ms
                || request.command_id != current.request.command_id
                || request.tenant != operation.request.tenant
            {
                return Err(conflict(
                    "native target dispatch differs from current original phase",
                ));
            }
            match (&request.step, operation.phase) {
                (_, RecoveryPhase::Confirm) => activation::validate_step(
                    state,
                    operation,
                    current,
                    *node_id,
                    &request.step,
                    true,
                )?,
                (_, RecoveryPhase::Complete) if completion::is_inspection(&request.step) => {
                    completion::validate_step(
                        state,
                        operation,
                        current,
                        *node_id,
                        &request.step,
                        true,
                    )?
                }
                (_, RecoveryPhase::Initialize | RecoveryPhase::Complete) => {
                    quorum::validate_quorum_step(
                        state,
                        operation,
                        current,
                        *node_id,
                        &request.step,
                        operation.phase,
                        true,
                    )?
                }
                (TargetRuntimeStep::Materialize(input), RecoveryPhase::Materialize)
                    if voter.materialization.is_none() =>
                {
                    input.validate(current)?;
                    if input != &operation.request.materialization {
                        return Err(conflict("target materialization input changed"));
                    }
                }
                (
                    TargetRuntimeStep::ResumeMaterialization(retained),
                    RecoveryPhase::Materialize,
                ) if voter.materialization.is_none() => {
                    if current.request.phase != LifecyclePhase::ResumeMaterialize
                        || current.request.resume_origin.as_deref() != Some(retained.as_ref())
                        || **retained != origin(state, operation)?
                    {
                        return Err(conflict("target readmission origin changed"));
                    }
                }
                (TargetRuntimeStep::Stop(reference), RecoveryPhase::Cleanup)
                    if voter.cleanup.is_none() =>
                {
                    if current.request.phase != LifecyclePhase::StopLocal
                        || *reference != stop_reference(state, operation)?
                    {
                        return Err(conflict("target cleanup stop changed"));
                    }
                }
                _ => {
                    return Err(conflict(
                        "native target step is outside the current recovery phase",
                    ));
                }
            }
        }
        (RecoveryPhase::Publish, RecoveryDispatch::PublishRoute(input)) => {
            route::validate_input(operation, input)?;
            if *input != route::next_input(state, operation)? {
                return Err(conflict("route publication compare-and-set input changed"));
            }
        }
        (RecoveryPhase::RetireSource, RecoveryDispatch::RetireSource(request)) => {
            if *request != retirement_request(operation, request.not_after_ms)?
                || request.not_after_ms <= authorization.admitted_at_ms
                || request.not_after_ms > authorization.expires_at_ms
                || request.not_after_ms
                    > authorization
                        .admitted_at_ms
                        .checked_add(operation.request.phase_timeout_ms)
                        .ok_or_else(|| conflict("retirement phase deadline overflow"))?
            {
                return Err(conflict(
                    "planned retirement input or original phase deadline differs",
                ));
            }
        }
        _ => return Err(conflict("coordinator phase dispatch is not installed")),
    }
    Ok(())
}
fn history(
    partition: &ControlAuthorityPartition,
) -> Result<kasumi_serving::HistoricalSigningTrust> {
    kasumi_serving::HistoricalSigningTrust::install(SigningDomain {
        authority_id: partition.authority_id,
        partition: partition.partition,
        manifest_sha256: partition.manifest_sha256.clone(),
        root_public_key: partition.signing_public_key.clone(),
        retirement_drain_ms: partition.drain_ms,
    })
    .map_err(|_| conflict("invalid installed recovery issuer history trust"))
}
fn validate_outcome(
    state: &TenantState,
    operation: &RecoveryRecord,
    prepared: &RecoveryPhaseRecord,
    outcome: &RecoveryDispatchOutcome,
) -> Result<()> {
    match (&prepared.input, outcome) {
        (RecoveryDispatch::Authority(expected), RecoveryDispatchOutcome::Authority(signed)) => {
            let issuer = partition(state, operation)?;
            let receipt = &signed.receipt;
            history(issuer)?
                .verify("kasumi.authority-proof.v1", receipt, &signed.signature)
                .map_err(|_| {
                    error(
                        ErrorCode::Forbidden,
                        "invalid signed recovery issuer outcome",
                    )
                })?;
            activation::receipt_identity(issuer, expected, receipt)?;
            if matches!(receipt.outcome, AuthorityOutcome::Rejected { .. }) {
                return Ok(());
            }
            if matches!(expected.action, AuthorityAction::ActivateCommitted { .. }) {
                return activation::validate_original(state, operation, expected, receipt);
            }
            if let AuthorityAction::StopActivation { original } = &expected.action {
                return activation::validate_resolution(state, operation, original, signed);
            }
            if receipt.admitted_at_ms >= expected.not_after_ms {
                return Err(conflict("issuer effect exceeds original phase deadline"));
            }
            match (&expected.action, &receipt.outcome) {
                (
                    AuthorityAction::PrepareTarget { target, .. },
                    AuthorityOutcome::TargetPrepared {
                        target: actual,
                        authority_epoch,
                    },
                ) if target == actual
                    && Some(*authority_epoch)
                        == operation.request.source_authority_epoch.checked_add(1) => {}
                (
                    AuthorityAction::StopTarget {
                        source_incarnation,
                        source_epoch,
                        target,
                    },
                    AuthorityOutcome::TargetStopped {
                        source_incarnation: actual_source,
                        source_epoch: actual_epoch,
                        target: actual,
                    },
                ) if source_incarnation == actual_source
                    && source_epoch == actual_epoch
                    && target == actual => {}
                (
                    AuthorityAction::Fence {
                        incarnation,
                        authority_epoch,
                    },
                    AuthorityOutcome::Fenced {
                        incarnation: actual,
                        authority_epoch: epoch,
                    },
                ) if incarnation == actual && authority_epoch == epoch => {}
                _ => return Err(conflict("issuer returned another recovery outcome")),
            }
        }
        (
            RecoveryDispatch::Authority(expected),
            RecoveryDispatchOutcome::AuthorityResolution(signed),
        ) => {
            activation::validate_resolution(state, operation, expected, signed)?;
            let stop = phase(state, operation, signed.receipt.command.command_id)?;
            if stop.sequence <= prepared.sequence
                || !matches!(&stop.input,RecoveryDispatch::Authority(command) if **command==signed.receipt.command)
            {
                return Err(conflict(
                    "activation resolution lacks its permanent ordered stop phase",
                ));
            }
        }
        (
            RecoveryDispatch::ControlIntent(request),
            RecoveryDispatchOutcome::ControlIntent(actual),
        ) => {
            let retained = state
                .lifecycle_control
                .as_ref()
                .and_then(|control| control.intents.get(&request.command_id));
            if actual.request != **request
                || retained != Some(actual.as_ref())
                || actual.original_credential_expires_at_ms > dispatch_limit(operation, prepared)?
                || actual.accepted_at_ms < prepared.admitted_at_ms
                || actual.revision < prepared.prepared_revision
            {
                return Err(conflict(
                    "Control outcome is not the exact replicated phase commitment",
                ));
            }
        }
        (
            RecoveryDispatch::Target { .. },
            RecoveryDispatchOutcome::CompletionResolution { inspection_phase },
        ) => {
            completion::validate_resolution(state, operation, prepared, *inspection_phase)?;
        }
        (
            RecoveryDispatch::Target { node_id, request },
            RecoveryDispatchOutcome::Target(response),
        ) => {
            if response.command_id != request.command_id || response.node_id != *node_id {
                return Err(conflict("target acknowledgement route differs"));
            }
            let current = state
                .lifecycle_control
                .as_ref()
                .and_then(|control| control.intents.get(&request.command_id))
                .ok_or_else(|| conflict("target acknowledgement Control phase absent"))?;
            match (&request.step, &response.outcome) {
                (
                    TargetRuntimeStep::Materialize(_) | TargetRuntimeStep::ResumeMaterialization(_),
                    TargetRuntimeOutcome::Materialized(signed),
                ) => {
                    kasumi_serving::verify_target_materialization(
                        &origin(state, operation)?,
                        *node_id,
                        signed,
                    )
                    .map_err(|_| {
                        error(
                            ErrorCode::Forbidden,
                            "target materialization signature or immutable origin differs",
                        )
                    })?;
                }
                (
                    TargetRuntimeStep::Start(TargetReplicaInput::Quorum(input)),
                    TargetRuntimeOutcome::Started { origin_sha256 },
                )
                | (
                    TargetRuntimeStep::StartActivation { quorum: input, .. },
                    TargetRuntimeOutcome::Started { origin_sha256 },
                )
                | (
                    TargetRuntimeStep::Initialize(input),
                    TargetRuntimeOutcome::Initialized { origin_sha256 },
                ) => {
                    if *origin_sha256 != input.origin_sha256
                        || input != &quorum_input(state, operation)?
                    {
                        return Err(conflict("native target startup origin differs"));
                    }
                }
                (
                    TargetRuntimeStep::Start(TargetReplicaInput::Completion(input)),
                    TargetRuntimeOutcome::Started { origin_sha256 },
                ) => {
                    if *input != completion::completion_input(state, operation)?
                        || *origin_sha256 != input.quorum.origin_sha256
                    {
                        return Err(conflict("completion startup origin differs"));
                    }
                }
                (
                    TargetRuntimeStep::Start(TargetReplicaInput::Inspection(input)),
                    TargetRuntimeOutcome::Started { origin_sha256 },
                ) => {
                    if **input != completion::inspection_input(state, operation)?
                        || *origin_sha256 != input.quorum.origin_sha256
                    {
                        return Err(conflict("inspection startup origin differs"));
                    }
                }
                (TargetRuntimeStep::Inspect(input), TargetRuntimeOutcome::Inspected(signed)) => {
                    if **input != completion::inspection_input(state, operation)? {
                        return Err(conflict("inspection acknowledgement input differs"));
                    }
                    completion::validate_proof(state, operation, current, *node_id, signed)?;
                }
                (TargetRuntimeStep::Complete(input), TargetRuntimeOutcome::Completed(signed)) => {
                    if signed.observation.fact.completion_intent != *current
                        || signed.observation.fact.admitted_at_ms >= request.not_after_ms
                        || signed.observation.observer_node_id != *node_id
                        || input != &completion::completion_input(state, operation)?
                        || signed.observation.fact.predecessor != input.predecessor
                    {
                        return Err(conflict(
                            "target completion differs from exact retained phase or voter",
                        ));
                    }
                    kasumi_serving::verify_target_completion(&origin(state, operation)?, signed)
                        .map_err(|_| {
                            error(
                                ErrorCode::Forbidden,
                                "target completion signature or quorum differs",
                            )
                        })?;
                }
                (TargetRuntimeStep::Activate { .. }, TargetRuntimeOutcome::Activated(signed)) => {
                    activation::validate_local_proof(state, operation, *node_id, signed, true)?;
                }
                (
                    TargetRuntimeStep::ConfirmActivation(expected),
                    TargetRuntimeOutcome::Activated(signed),
                ) => {
                    activation::validate_local_proof(state, operation, *node_id, signed, true)?;
                    if signed.observation.activation != expected.observation.activation
                        || signed.observation.completion != expected.observation.completion
                    {
                        return Err(conflict(
                            "target confirmation changed exact committed activation",
                        ));
                    }
                }
                (TargetRuntimeStep::Stop(reference), TargetRuntimeOutcome::Stopped(signed)) => {
                    kasumi_serving::verify_local_target_cleanup_history(
                        partition(state, operation)?,
                        current,
                        *node_id,
                        reference,
                        signed,
                    )
                    .map_err(|_| {
                        error(
                            ErrorCode::Forbidden,
                            "target cleanup lacks exact issuer drain and physical cleanup evidence",
                        )
                    })?;
                }
                _ => return Err(conflict("target acknowledgement operation differs")),
            }
        }
        (RecoveryDispatch::PublishRoute(input), outcome) => {
            route::validate_outcome(prepared, input, outcome)?;
            if let RecoveryDispatchOutcome::RouteSuperseded { replacement_phase } = outcome {
                let replacement = phase(state, operation, *replacement_phase)?;
                if replacement.previous_phase != Some(prepared.phase_id)
                    || Some(replacement.prepared_revision) != prepared.resolved_revision
                    || replacement.admitted_at_ms < dispatch_limit(operation, prepared)?
                    || !matches!(replacement.input, RecoveryDispatch::PublishRoute(_))
                {
                    return Err(conflict(
                        "local publication supersession lacks its exact fresh phase",
                    ));
                }
            }
        }
        (
            RecoveryDispatch::RetireSource(request),
            RecoveryDispatchOutcome::SourceRetired(receipt),
        ) => {
            source::validate_retirement(operation, request, receipt)?;
        }
        _ => {
            return Err(conflict(
                "recovery outcome kind differs from durable dispatch",
            ));
        }
    }
    Ok(())
}
fn advance(
    state: &TenantState,
    operation: &mut RecoveryRecord,
    prepared: &RecoveryPhaseRecord,
    outcome: &RecoveryDispatchOutcome,
) -> Result<()> {
    match (&prepared.input, outcome) {
        (_, RecoveryDispatchOutcome::Authority(signed))
            if matches!(signed.receipt.outcome, AuthorityOutcome::Rejected { .. }) => {}
        (RecoveryDispatch::Authority(_), RecoveryDispatchOutcome::Authority(_))
            if prepared.phase == RecoveryPhase::Prepare =>
        {
            operation.issuer_preparation = Some(prepared.phase_id);
            operation.phase = RecoveryPhase::Materialize;
        }
        (RecoveryDispatch::Authority(_), RecoveryDispatchOutcome::Authority(_))
            if prepared.phase == RecoveryPhase::StopTarget =>
        {
            operation.target_stop = Some(prepared.phase_id);
            operation.current_intent = None;
            operation.phase = RecoveryPhase::Cleanup;
        }
        (RecoveryDispatch::Authority(_), RecoveryDispatchOutcome::Authority(_))
            if prepared.phase == RecoveryPhase::FenceSource =>
        {
            operation.source_fence = Some(prepared.phase_id);
            operation.current_intent = None;
            operation.phase = RecoveryPhase::Activate;
        }
        (RecoveryDispatch::Authority(command), RecoveryDispatchOutcome::Authority(signed))
            if prepared.phase == RecoveryPhase::Activate =>
        {
            if matches!(signed.receipt.outcome, AuthorityOutcome::Activated { .. }) {
                operation.activation = Some(prepared.phase_id);
                operation.current_intent = None;
                operation.phase = RecoveryPhase::Confirm;
            } else if matches!(command.action, AuthorityAction::ActivateCommitted { .. })
                && matches!(
                    signed.receipt.outcome,
                    AuthorityOutcome::ActivationStopped { .. }
                )
            {
                operation.current_intent = None;
            } else {
                return Err(conflict("unsupported issuer activation progress"));
            }
        }
        (RecoveryDispatch::Authority(command), RecoveryDispatchOutcome::Authority(signed))
            if prepared.phase == RecoveryPhase::StopActivation =>
        {
            let AuthorityAction::StopActivation { original } = &command.action else {
                return Err(conflict("activation stop input differs"));
            };
            let AuthorityOutcome::ActivationResolved { original: resolved } =
                &signed.receipt.outcome
            else {
                return Err(conflict("activation stop did not resolve original command"));
            };
            operation.current_intent = None;
            if matches!(resolved.outcome, AuthorityOutcome::Activated { .. }) {
                operation.activation = Some(original.command_id);
                operation.phase = RecoveryPhase::Confirm;
            } else {
                operation.phase = if operation.stop_request.is_some() {
                    RecoveryPhase::StopTarget
                } else {
                    RecoveryPhase::Activate
                };
            }
        }
        (RecoveryDispatch::PublishRoute(_), RecoveryDispatchOutcome::RoutePublished { .. }) => {
            operation.route_publication = Some(prepared.phase_id);
            operation.phase = RecoveryPhase::Finished;
        }
        (RecoveryDispatch::PublishRoute(_), RecoveryDispatchOutcome::RouteRejected { .. }) => {}
        (RecoveryDispatch::RetireSource(_), RecoveryDispatchOutcome::SourceRetired(_)) => {
            operation.retirement = Some(prepared.phase_id);
            operation.phase = RecoveryPhase::FenceSource;
        }
        (RecoveryDispatch::ControlIntent(request), RecoveryDispatchOutcome::ControlIntent(_)) => {
            operation.current_intent = Some(prepared.phase_id);
            if request.phase == LifecyclePhase::Materialize {
                operation.materialization_intent = Some(prepared.phase_id);
            }
            if request.phase == LifecyclePhase::Complete {
                if operation.completion_intent.is_some() {
                    return Err(conflict(
                        "permanent original completion identity already installed",
                    ));
                }
                operation.completion_intent = Some(prepared.phase_id);
            }
        }
        (RecoveryDispatch::Target { node_id, .. }, RecoveryDispatchOutcome::Target(response)) => {
            let voter = operation
                .voters
                .get_mut(node_id)
                .ok_or_else(|| conflict("target voter missing"))?;
            match response.outcome {
                TargetRuntimeOutcome::Materialized(_) => {
                    voter.materialization = Some(prepared.phase_id);
                    if operation
                        .voters
                        .values()
                        .all(|v| v.materialization.is_some())
                    {
                        let mut facts = BTreeMap::new();
                        for (id, voter) in &operation.voters {
                            let value = if id == node_id {
                                response.as_ref()
                            } else {
                                let retained = phase(
                                    state,
                                    operation,
                                    voter.materialization.expect("checked materialization"),
                                )?;
                                let Some(RecoveryDispatchOutcome::Target(value)) =
                                    &retained.outcome
                                else {
                                    return Err(conflict("retained voter materialization absent"));
                                };
                                value.as_ref()
                            };
                            let TargetRuntimeOutcome::Materialized(signed) = &value.outcome else {
                                return Err(conflict("retained voter materialization differs"));
                            };
                            facts.insert(*id, signed.as_ref().clone());
                        }
                        kasumi_serving::verify_target_materializations(
                            &origin(state, operation)?,
                            &facts,
                        )
                        .map_err(|_| {
                            conflict("target voters disagree about the exact materialized image")
                        })?;
                        operation.current_intent = None;
                        operation.phase = RecoveryPhase::Initialize;
                    }
                }
                TargetRuntimeOutcome::Started { .. } => {
                    voter.started = Some(prepared.phase_id);
                }
                TargetRuntimeOutcome::Initialized { .. } => {
                    operation.initialization = Some(prepared.phase_id);
                    operation.current_intent = None;
                    operation.phase = RecoveryPhase::Complete;
                }
                TargetRuntimeOutcome::Completed(_) | TargetRuntimeOutcome::Inspected(_) => {
                    operation.completion = Some(prepared.phase_id);
                    operation.current_intent = None;
                    operation.phase = if matches!(
                        operation.request.source_mode,
                        RecoverySourceMode::Planned { .. }
                    ) {
                        RecoveryPhase::RetireSource
                    } else {
                        RecoveryPhase::FenceSource
                    };
                }
                TargetRuntimeOutcome::Activated(_) => {
                    voter.confirmation = Some(prepared.phase_id);
                    if operation.voters.values().all(|v| v.confirmation.is_some()) {
                        operation.phase = RecoveryPhase::Publish;
                    }
                }
                TargetRuntimeOutcome::Stopped(_) => {
                    voter.cleanup = Some(prepared.phase_id);
                    if operation.voters.values().all(|v| v.cleanup.is_some()) {
                        operation.phase = RecoveryPhase::Stopped;
                    }
                }
            }
        }
        _ => return Err(conflict("unsupported recovery progress transition")),
    }
    Ok(())
}

pub(crate) fn validate(state: &TenantState) -> Result<()> {
    let recovery = &state.recovery_control;
    if recovery.is_empty() {
        return Ok(());
    }
    if state.tenant != "__kasumi_control" {
        return Err(conflict(
            "application snapshot contains closed recovery authority",
        ));
    }
    let installed = state
        .lifecycle_control
        .as_ref()
        .ok_or_else(|| conflict("recovery history lacks its Control installation"))?;
    let installation_sha256 = staged_digest(&installed.installation)?.0;
    if recovery.targets.len() != recovery.operations.len() {
        return Err(conflict("recovery permanent target index count differs"));
    }
    let mut counts = BTreeMap::<Uuid, u64>::new();
    for record in recovery.phases.values() {
        let count = counts.entry(record.operation_id).or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| conflict("recovery phase count overflow"))?;
    }
    for (key, operation) in &recovery.operations {
        operation.validate()?;
        let materialized = matches!(
            operation.phase,
            RecoveryPhase::Initialize
                | RecoveryPhase::Complete
                | RecoveryPhase::RetireSource
                | RecoveryPhase::FenceSource
                | RecoveryPhase::Activate
                | RecoveryPhase::Confirm
                | RecoveryPhase::Publish
                | RecoveryPhase::Finished
        );
        let initialized = matches!(
            operation.phase,
            RecoveryPhase::Complete
                | RecoveryPhase::RetireSource
                | RecoveryPhase::FenceSource
                | RecoveryPhase::Activate
                | RecoveryPhase::Confirm
                | RecoveryPhase::Publish
                | RecoveryPhase::Finished
        );
        let completed = matches!(
            operation.phase,
            RecoveryPhase::RetireSource
                | RecoveryPhase::FenceSource
                | RecoveryPhase::Activate
                | RecoveryPhase::Confirm
                | RecoveryPhase::Publish
                | RecoveryPhase::Finished
        );
        if ((materialized || operation.phase == RecoveryPhase::Materialize)
            && operation.issuer_preparation.is_none())
            || (materialized
                && !operation
                    .voters
                    .values()
                    .all(|v| v.materialization.is_some()))
            || (initialized && operation.initialization.is_none())
            || (completed
                && (operation.completion.is_none() || operation.completion_intent.is_none()))
            || (matches!(
                operation.phase,
                RecoveryPhase::Cleanup | RecoveryPhase::Stopped
            ) && operation.target_stop.is_none())
        {
            return Err(conflict(
                "recovery progress skipped a required committed predecessor",
            ));
        }

        if *key != operation.request.operation_id.to_string()
            || operation.request.installation_sha256 != installation_sha256
            || operation.updated_revision > state.revision
            || recovery
                .targets
                .get(&operation.request.target_incarnation.to_string())
                != Some(&operation.request.operation_id)
        {
            return Err(conflict(
                "recovery head or permanent target binding differs",
            ));
        }
        partition(state, operation)?;
        let sequence = match operation.last_phase {
            Some(id) => phase(state, operation, id)?
                .sequence
                .checked_add(1)
                .ok_or_else(|| conflict("recovery sequence exhausted"))?,
            None => 1,
        };
        if sequence != operation.next_phase_sequence
            || counts.remove(&operation.request.operation_id).unwrap_or(0) != sequence - 1
        {
            return Err(conflict("recovery phase chain head differs"));
        }
        let mut cursor = operation.last_phase;
        let mut expected = sequence - 1;
        while let Some(id) = cursor {
            let record = phase(state, operation, id)?;
            if record.sequence != expected || expected == 0 {
                return Err(conflict("recovery phase chain forked"));
            }
            expected -= 1;
            cursor = record.previous_phase;
        }
        if expected != 0 {
            return Err(conflict("recovery phase chain is incomplete"));
        }
        if let Some(id) = operation.pending_phase {
            let pending = phase(state, operation, id)?;
            if operation.last_phase != Some(id)
                || pending.outcome.is_some()
                || pending.phase != operation.phase
            {
                return Err(conflict("recovery pending phase differs"));
            }
        }
        for id in [
            operation.current_intent,
            operation.materialization_intent,
            operation.completion_intent,
        ]
        .into_iter()
        .flatten()
        {
            intent(state, operation, id)?;
        }
        if let Some(id) = operation.completion_intent {
            let original = intent(state, operation, id)?;
            origin(state, operation)?.accepts_phase(original, LifecyclePhase::Complete)?;
            if original.request.phase_input_sha256 != quorum_input(state, operation)?.digest()? {
                return Err(conflict("original completion identity input differs"));
            }
        }
        if let Some(id) = operation.completion_attempt {
            let retained = phase(state, operation, id)?;
            let original = intent(
                state,
                operation,
                operation
                    .completion_intent
                    .ok_or_else(|| conflict("original completion identity absent"))?,
            )?;
            if !matches!(&retained.input, RecoveryDispatch::Target { request, .. } if request.command_id == original.request.command_id && matches!(request.step, TargetRuntimeStep::Complete(_)))
                || retained.phase != RecoveryPhase::Complete
            {
                return Err(conflict("original completion attempt reference differs"));
            }
        }
        if operation.materialization_intent.is_some() {
            origin(state, operation)?;
        }
        for (node_id, voter) in &operation.voters {
            for (id, cleanup) in [(voter.materialization, false), (voter.cleanup, true)] {
                if let Some(id) = id {
                    let retained = phase(state, operation, id)?;
                    let Some(RecoveryDispatchOutcome::Target(response)) = &retained.outcome else {
                        return Err(conflict("recovery voter progress lacks a native outcome"));
                    };
                    if response.node_id != *node_id
                        || !matches!(
                            (&response.outcome, cleanup),
                            (TargetRuntimeOutcome::Materialized(_), false)
                                | (TargetRuntimeOutcome::Stopped(_), true)
                        )
                    {
                        return Err(conflict("recovery voter outcome differs"));
                    }
                }
            }
        }
        for id in [
            operation.issuer_preparation,
            operation.initialization,
            operation.completion,
            operation.retirement,
            operation.source_fence,
            operation.activation,
            operation.route_publication,
            operation.target_stop,
        ]
        .into_iter()
        .flatten()
        {
            if phase(state, operation, id)?.outcome.is_none() {
                return Err(conflict("recovery progress reference is unresolved"));
            }
        }
        for (node_id, voter) in &operation.voters {
            if let Some(id) = voter.started {
                let record = phase(state, operation, id)?;
                if !matches!((&record.input,&record.outcome), (RecoveryDispatch::Target {node_id:actual,request},Some(RecoveryDispatchOutcome::Target(response))) if actual==node_id && response.node_id==*node_id && matches!(request.step,TargetRuntimeStep::Start(_)|TargetRuntimeStep::StartActivation{..}) && matches!(response.outcome,TargetRuntimeOutcome::Started{..}))
                {
                    return Err(conflict(
                        "startup progress lacks exact native voter acknowledgement",
                    ));
                }
            }
        }
        if operation.initialization.is_some_and(|id| !matches!(phase(state,operation,id).ok().and_then(|p|p.outcome.as_ref()),Some(RecoveryDispatchOutcome::Target(response)) if matches!(response.outcome,TargetRuntimeOutcome::Initialized{..}))) {return Err(conflict("initialization progress reference differs"));}
        if operation.completion.is_some_and(|id| !matches!(phase(state,operation,id).ok().and_then(|p|p.outcome.as_ref()),Some(RecoveryDispatchOutcome::Target(response)) if matches!(response.outcome,TargetRuntimeOutcome::Completed(_)|TargetRuntimeOutcome::Inspected(_)))) {return Err(conflict("completion progress reference differs"));}
        if operation.issuer_preparation.is_some_and(|id| !matches!(phase(state, operation, id).ok().and_then(|p|p.outcome.as_ref()),Some(RecoveryDispatchOutcome::Authority(s)) if matches!(s.receipt.outcome,AuthorityOutcome::TargetPrepared{..}))) {
            return Err(conflict("recovery preparation reference differs"));
        }
        if let Some(id) = operation.retirement {
            let record = phase(state, operation, id)?;
            let Some(RecoveryDispatchOutcome::SourceRetired(receipt)) = &record.outcome else {
                return Err(conflict("source retirement progress reference differs"));
            };
            let RecoveryDispatch::RetireSource(request) = &record.input else {
                return Err(conflict("source retirement progress input differs"));
            };
            source::validate_retirement(operation, request, receipt)?;
        }
        if let Some(id) = operation.source_fence
            && !matches!(phase(state, operation, id)?.outcome.as_ref(), Some(RecoveryDispatchOutcome::Authority(s)) if matches!(s.receipt.outcome, AuthorityOutcome::Fenced{incarnation,authority_epoch} if incarnation == operation.request.source_incarnation && authority_epoch == operation.request.source_authority_epoch))
        {
            return Err(conflict("source fence progress reference differs"));
        }
        if matches!(
            operation.phase,
            RecoveryPhase::Activate
                | RecoveryPhase::Confirm
                | RecoveryPhase::Publish
                | RecoveryPhase::Finished
        ) && operation.source_fence.is_none()
        {
            return Err(conflict("activation progress lacks exact source fence"));
        }
        if matches!(
            operation.request.source_mode,
            RecoverySourceMode::Planned { .. }
        ) && matches!(
            operation.phase,
            RecoveryPhase::FenceSource
                | RecoveryPhase::Activate
                | RecoveryPhase::Confirm
                | RecoveryPhase::Publish
                | RecoveryPhase::Finished
        ) && operation.retirement.is_none()
        {
            return Err(conflict("planned source fence lacks verified retirement"));
        }
        if let Some(id) = operation.activation_attempt {
            activation::attempt(state, operation)?;
            if let Some(RecoveryDispatchOutcome::AuthorityResolution(signed)) =
                &phase(state, operation, id)?.outcome
            {
                let stop = phase(state, operation, signed.receipt.command.command_id)?;
                if stop.outcome.as_ref()
                    != Some(&RecoveryDispatchOutcome::Authority(signed.clone()))
                {
                    return Err(conflict(
                        "activation resolution differs from permanent stop outcome",
                    ));
                }
            }
        }
        if operation.activation.is_some() {
            if operation.activation != operation.activation_attempt {
                return Err(conflict(
                    "committed winner differs from original activation attempt",
                ));
            }
            activation::winner(state, operation)?;
        }
        if matches!(
            operation.phase,
            RecoveryPhase::StopTarget | RecoveryPhase::Cleanup | RecoveryPhase::Stopped
        ) {
            activation::require_negative_attempt(state, operation)?;
        }
        if matches!(
            operation.phase,
            RecoveryPhase::Confirm | RecoveryPhase::Publish | RecoveryPhase::Finished
        ) && operation.activation.is_none()
        {
            return Err(conflict(
                "target confirmation precedes committed issuer winner",
            ));
        }
        for (node, voter) in &operation.voters {
            if let Some(id) = voter.confirmation {
                let retained = phase(state, operation, id)?;
                let Some(RecoveryDispatchOutcome::Target(response)) = &retained.outcome else {
                    return Err(conflict("target confirmation lacks native outcome"));
                };
                let TargetRuntimeOutcome::Activated(signed) = &response.outcome else {
                    return Err(conflict("target confirmation proof differs"));
                };
                activation::validate_local_proof(state, operation, *node, signed, true)?;
                if let Some(first) = activation::local_proof(state, operation)?
                    && (first.observation.activation != signed.observation.activation
                        || first.observation.completion != signed.observation.completion)
                {
                    return Err(conflict("target confirmations disagree"));
                }
            }
        }
        if matches!(
            operation.phase,
            RecoveryPhase::Publish | RecoveryPhase::Finished
        ) && !operation.voters.values().all(|v| v.confirmation.is_some())
        {
            return Err(conflict(
                "route publication lacks every local activation confirmation",
            ));
        }
        if let Some(id) = operation.route_publication
            && !matches!(
                (
                    &phase(state, operation, id)?.input,
                    &phase(state, operation, id)?.outcome
                ),
                (
                    RecoveryDispatch::PublishRoute(_),
                    Some(RecoveryDispatchOutcome::RoutePublished { .. })
                )
            )
        {
            return Err(conflict("route publication reference differs"));
        }
        if operation.target_stop.is_some() {
            stop_reference(state, operation)?;
        }
    }
    if !counts.is_empty() {
        return Err(conflict("recovery phase belongs to an absent operation"));
    }
    for (key, retained) in &recovery.phases {
        retained.validate()?;
        let operation = recovery
            .operations
            .get(&retained.operation_id.to_string())
            .ok_or_else(|| conflict("recovery phase has no operation"))?;
        if *key != phase_key(retained.operation_id, retained.phase_id)
            || retained.sequence >= operation.next_phase_sequence
            || retained.prepared_revision < operation.created_revision
            || retained.prepared_revision > operation.updated_revision
            || retained
                .resolved_revision
                .is_some_and(|revision| revision > operation.updated_revision)
        {
            return Err(conflict("recovery retained phase identity differs"));
        }
        match retained.previous_phase {
            Some(id) => {
                let previous = phase(state, operation, id)?;
                if previous.sequence.checked_add(1) != Some(retained.sequence)
                    || previous.prepared_revision >= retained.prepared_revision
                {
                    return Err(conflict("recovery phase chain differs"));
                }
            }
            None if retained.sequence == 1 => {}
            _ => return Err(conflict("recovery phase chain origin differs")),
        }
        validate_frozen_input(state, operation, retained)?;
        if let Some(outcome) = &retained.outcome {
            validate_outcome(state, operation, retained, outcome)?;
        }
    }
    Ok(())
}
fn validate_frozen_input(
    state: &TenantState,
    operation: &RecoveryRecord,
    retained: &RecoveryPhaseRecord,
) -> Result<()> {
    match &retained.input {
        RecoveryDispatch::Authority(command) => {
            let expected = activation::retained_action(state, operation, retained, command)?;
            command
                .validate()
                .map_err(|_| conflict("retained issuer command invalid"))?;
            if command.command_id != retained.phase_id
                || command.tenant != operation.request.tenant
                || command.expected_policy_epoch != operation.request.authority_policy_epoch
                || command.action != expected
                || command.not_after_ms > dispatch_limit(operation, retained)?
                || command.not_after_ms <= retained.admitted_at_ms
            {
                return Err(conflict("retained issuer phase input changed"));
            }
        }
        RecoveryDispatch::PublishRoute(input) => {
            route::validate_input(operation, input)?;
            if retained.phase != RecoveryPhase::Publish
                || input.expected_topology_version >= retained.prepared_revision
            {
                return Err(conflict("retained route publication position differs"));
            }
        }
        RecoveryDispatch::RetireSource(request) => {
            if retained.phase != RecoveryPhase::RetireSource
                || *request != retirement_request(operation, request.not_after_ms)?
                || request.not_after_ms <= retained.admitted_at_ms
                || request.not_after_ms > dispatch_limit(operation, retained)?
            {
                return Err(conflict("retained planned retirement input differs"));
            }
        }
        RecoveryDispatch::ControlIntent(request) => {
            request.validate()?;
            if !matches!(
                (retained.phase, request.phase),
                (
                    RecoveryPhase::Materialize,
                    LifecyclePhase::Materialize | LifecyclePhase::ResumeMaterialize
                ) | (RecoveryPhase::Cleanup, LifecyclePhase::StopLocal)
                    | (RecoveryPhase::Initialize, LifecyclePhase::Initialize)
                    | (
                        RecoveryPhase::Complete,
                        LifecyclePhase::Complete | LifecyclePhase::InspectTarget
                    )
                    | (
                        RecoveryPhase::Activate | RecoveryPhase::Confirm,
                        LifecyclePhase::Activate
                    )
            ) || **request
                != expected_intent(
                    state,
                    operation,
                    retained.phase_id,
                    request.expected_policy_epoch,
                    request.phase,
                )?
            {
                return Err(conflict("retained Control phase input changed"));
            }
        }
        RecoveryDispatch::Target { node_id, request } => {
            request
                .validate()
                .map_err(|_| conflict("retained native target request invalid"))?;
            let current = state
                .lifecycle_control
                .as_ref()
                .and_then(|control| control.intents.get(&request.command_id))
                .ok_or_else(|| conflict("retained target dispatch lacks its Control phase"))?;
            if request.tenant != operation.request.tenant
                || !operation.voters.contains_key(node_id)
                || retained.admitted_at_ms >= current.original_credential_expires_at_ms
                || request.not_after_ms <= retained.admitted_at_ms
                || request.not_after_ms > dispatch_limit(operation, retained)?
                || request.not_after_ms > current.original_credential_expires_at_ms
            {
                return Err(conflict("retained target dispatch resource differs"));
            }
            match (&request.step, retained.phase) {
                (_, RecoveryPhase::Confirm) => activation::validate_step(
                    state,
                    operation,
                    current,
                    *node_id,
                    &request.step,
                    false,
                )?,
                (_, RecoveryPhase::Complete) if completion::is_inspection(&request.step) => {
                    completion::validate_step(
                        state,
                        operation,
                        current,
                        *node_id,
                        &request.step,
                        false,
                    )?
                }
                (_, RecoveryPhase::Initialize | RecoveryPhase::Complete) => {
                    quorum::validate_quorum_step(
                        state,
                        operation,
                        current,
                        *node_id,
                        &request.step,
                        retained.phase,
                        false,
                    )?
                }
                (TargetRuntimeStep::Materialize(input), RecoveryPhase::Materialize) => {
                    input.validate(current)?;
                    if input != &operation.request.materialization {
                        return Err(conflict("retained materialization input differs"));
                    }
                }
                (
                    TargetRuntimeStep::ResumeMaterialization(original),
                    RecoveryPhase::Materialize,
                ) => {
                    if current.request.phase != LifecyclePhase::ResumeMaterialize
                        || current.request.resume_origin.as_deref() != Some(original.as_ref())
                        || **original != origin(state, operation)?
                    {
                        return Err(conflict("retained fresh materialization input differs"));
                    }
                }
                (TargetRuntimeStep::Stop(reference), RecoveryPhase::Cleanup) => {
                    if current.request.phase != LifecyclePhase::StopLocal
                        || *reference != stop_reference(state, operation)?
                    {
                        return Err(conflict("retained target stop input differs"));
                    }
                }
                _ => return Err(conflict("retained target dispatch step differs")),
            }
        }
        _ => return Err(conflict("unsupported retained recovery dispatch")),
    }
    Ok(())
}

/// Incoming consensus snapshots may advance unfinished phases, but cannot erase
/// permanent command identities or substitute an already resolved outcome.
pub(crate) fn validate_successor(previous: &TenantState, incoming: &TenantState) -> Result<()> {
    for (key, id) in &previous.recovery_control.targets {
        if incoming.recovery_control.targets.get(key) != Some(id) {
            return Err(conflict(
                "snapshot removed a permanent target recovery binding",
            ));
        }
    }
    for (key, old) in &previous.recovery_control.operations {
        let new = incoming
            .recovery_control
            .operations
            .get(key)
            .ok_or_else(|| conflict("snapshot removed permanent recovery operation"))?;
        if new.request != old.request
            || new.original_principal != old.original_principal
            || new.created_revision != old.created_revision
            || new.updated_revision < old.updated_revision
            || new.next_phase_sequence < old.next_phase_sequence
            || old
                .stop_request
                .is_some_and(|id| new.stop_request != Some(id))
        {
            return Err(conflict("snapshot substituted recovery operation identity"));
        }
        if let Some(old_id) = old.completion_attempt {
            let new_id = new
                .completion_attempt
                .ok_or_else(|| conflict("snapshot removed original completion attempt"))?;
            if phase(incoming, new, new_id)?.sequence < phase(previous, old, old_id)?.sequence {
                return Err(conflict("snapshot regressed original completion attempt"));
            }
        }
        if let Some(old_id) = old.activation_attempt {
            let new_id = new
                .activation_attempt
                .ok_or_else(|| conflict("snapshot removed original activation attempt"))?;
            if phase(incoming, new, new_id)?.sequence < phase(previous, old, old_id)?.sequence {
                return Err(conflict("snapshot regressed original activation attempt"));
            }
        }
        for (old, new) in [
            (old.materialization_intent, new.materialization_intent),
            (old.completion_intent, new.completion_intent),
            (old.issuer_preparation, new.issuer_preparation),
            (old.initialization, new.initialization),
            (old.completion, new.completion),
            (old.retirement, new.retirement),
            (old.source_fence, new.source_fence),
            (old.activation, new.activation),
            (old.route_publication, new.route_publication),
            (old.target_stop, new.target_stop),
        ] {
            if old.is_some() && old != new {
                return Err(conflict("snapshot substituted immutable recovery progress"));
            }
        }
        for (id, old) in &old.voters {
            let new = new
                .voters
                .get(id)
                .ok_or_else(|| conflict("snapshot removed recovery voter"))?;
            if let Some(old_id) = old.started {
                let new_id = new
                    .started
                    .ok_or_else(|| conflict("snapshot removed target startup progress"))?;
                let old_phase = previous
                    .recovery_control
                    .phases
                    .get(&old_id.to_string())
                    .ok_or_else(|| conflict("old startup phase absent"))?;
                let new_phase = incoming
                    .recovery_control
                    .phases
                    .get(&new_id.to_string())
                    .ok_or_else(|| conflict("new startup phase absent"))?;
                if new_phase.sequence < old_phase.sequence {
                    return Err(conflict("snapshot regressed target startup progress"));
                }
            }
            for (old, new) in [
                (old.materialization, new.materialization),
                (old.confirmation, new.confirmation),
                (old.cleanup, new.cleanup),
            ] {
                if old.is_some() && old != new {
                    return Err(conflict("snapshot substituted recovery voter progress"));
                }
            }
        }
    }
    for (key, old) in &previous.recovery_control.phases {
        let new = incoming
            .recovery_control
            .phases
            .get(key)
            .ok_or_else(|| conflict("snapshot removed permanent recovery phase"))?;
        let mut comparison = new.clone();
        comparison.outcome = old.outcome.clone();
        comparison.resolved_revision = old.resolved_revision;
        if !same(old, &comparison)?
            || old.outcome.as_ref().is_some_and(|outcome| {
                new.outcome
                    .as_ref()
                    .is_none_or(|value| same(outcome, value).ok() != Some(true))
            })
            || old
                .resolved_revision
                .is_some_and(|revision| new.resolved_revision != Some(revision))
        {
            return Err(conflict(
                "snapshot substituted permanent recovery phase input or outcome",
            ));
        }
    }
    Ok(())
}
