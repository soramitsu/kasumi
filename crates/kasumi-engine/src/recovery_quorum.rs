//! Recovery quorum inputs are reconstructed from three permanent signed
//! materialization entries. Local startup acknowledgements are scoped to one
//! exact Control intent and never serve as a membership or completion proof.
use super::*;

pub(crate) fn quorum_input(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<TargetQuorumInput> {
    let original = origin(state, operation)?;
    let mut materialized = BTreeMap::new();
    for (node, voter) in &operation.voters {
        let phase = phase(
            state,
            operation,
            voter
                .materialization
                .ok_or_else(|| conflict("target materialization quorum incomplete"))?,
        )?;
        let Some(RecoveryDispatchOutcome::Target(response)) = &phase.outcome else {
            return Err(conflict("target materialization proof absent"));
        };
        let TargetRuntimeOutcome::Materialized(proof) = &response.outcome else {
            return Err(conflict("target materialization proof differs"));
        };
        materialized.insert(*node, proof.as_ref().clone());
    }
    kasumi_serving::verify_target_materializations(&original, &materialized)
        .map_err(|_| conflict("materialized target quorum differs"))?;
    Ok(TargetQuorumInput {
        origin_sha256: original.digest()?,
        materialized,
    })
}
pub(crate) fn started_for(
    state: &TenantState,
    operation: &RecoveryRecord,
    node: u64,
    intent_id: Uuid,
) -> Result<bool> {
    let Some(id) = operation.voters.get(&node).and_then(|v| v.started) else {
        return Ok(false);
    };
    let retained = phase(state, operation, id)?;
    Ok(matches!((&retained.input,&retained.outcome),
        (RecoveryDispatch::Target {node_id,request},Some(RecoveryDispatchOutcome::Target(response)))
        if *node_id==node && request.command_id==intent_id && response.node_id==node && matches!(response.outcome,TargetRuntimeOutcome::Started{..})))
}
pub(crate) fn current_initial_intent_reader(
    state: &TenantState,
    operation: &RecoveryRecord,
    pending: Uuid,
    command: Uuid,
    dispatch_principal: &str,
    sender: (&str, &str),
    now: impl FnOnce() -> Result<u64>,
) -> Result<bool> {
    if operation.phase != RecoveryPhase::Initialize
        || operation.pending_phase != Some(pending)
        || operation.current_intent != Some(command)
        || operation.initialization.is_some()
        || operation.stop_request.is_some()
    {
        return Ok(false);
    }
    let active = phase(state, operation, pending)?;
    let RecoveryDispatch::Target {
        node_id: receiving_node,
        request,
    } = &active.input
    else {
        return Ok(false);
    };
    let (TargetRuntimeStep::Start(TargetReplicaInput::Quorum(quorum))
    | TargetRuntimeStep::Initialize(quorum)) = &request.step
    else {
        return Ok(false);
    };
    let current = intent(state, operation, command)?;
    let Some(control) = &state.lifecycle_control else {
        return Ok(false);
    };
    if control.retired
        || control.pending_change.is_some()
        || control.installation.generation != current.installation_generation
        || control.installation.root.control_incarnation != current.control_incarnation
        || state.policy_epoch != current.request.expected_policy_epoch
        || active.principal != dispatch_principal
        || active.principal != current.original_principal
        || active.phase != RecoveryPhase::Initialize
        || active.outcome.is_some()
        || active
            .effect_attempts
            .get(&RecoveryEffect::TargetCommand)
            .is_none_or(|attempt| attempt.input_sha256 != active.input_sha256)
        || request.command_id != command
        || request.tenant != operation.request.tenant
        || current.request.phase != LifecyclePhase::Initialize
        || current.request.target_incarnation != operation.request.target_incarnation
        || current.request.tenant != request.tenant
        || current.request.target_nodes != operation.request.target_nodes
        || current.request.phase_input_sha256 != quorum.digest()?
    {
        return Ok(false);
    }
    let (principal, certificate_sha256) = sender;
    let Some(reader) =
        current.request.target_nodes.values().find(|node| {
            node.principal == principal && node.certificate_sha256 == certificate_sha256
        })
    else {
        return Ok(false);
    };
    let dispatch_cap =
        effect_dispatch_limit(operation, active)?.min(current.original_credential_expires_at_ms);
    if reader.node_id == *receiving_node
        && matches!(
            &request.step,
            TargetRuntimeStep::Start(TargetReplicaInput::Quorum(_))
        )
    {
        return Ok(now()? < dispatch_cap);
    }
    let Some(started) = operation
        .voters
        .get(&reader.node_id)
        .and_then(|progress| progress.started)
    else {
        return Ok(false);
    };
    let start = phase(state, operation, started)?;
    let (
        RecoveryDispatch::Target {
            node_id,
            request: original,
        },
        Some(RecoveryDispatchOutcome::Target(reply)),
    ) = (&start.input, &start.outcome)
    else {
        return Ok(false);
    };
    let cap = effect_dispatch_limit(operation, start)?.min(dispatch_cap);
    Ok(start.phase == RecoveryPhase::Initialize
        && start.principal == current.original_principal
        && start.resolved_revision.is_some()
        && start
            .effect_attempts
            .get(&RecoveryEffect::TargetCommand)
            .is_some_and(|attempt| attempt.input_sha256 == start.input_sha256)
        && *node_id == reader.node_id
        && original.command_id == command
        && original.tenant == request.tenant
        && matches!(&original.step, TargetRuntimeStep::Start(TargetReplicaInput::Quorum(input)) if input == quorum)
        && reply.command_id == command
        && reply.node_id == reader.node_id
        && matches!(&reply.outcome, TargetRuntimeOutcome::Started {origin_sha256} if origin_sha256 == &quorum.origin_sha256)
        && now()? < cap)
}

pub(crate) fn all_started(
    state: &TenantState,
    operation: &RecoveryRecord,
    intent_id: Uuid,
) -> Result<bool> {
    for node in operation.voters.keys() {
        if !started_for(state, operation, *node, intent_id)? {
            return Ok(false);
        }
    }
    Ok(true)
}
pub(crate) fn validate_quorum_step(
    state: &TenantState,
    operation: &RecoveryRecord,
    current: &LifecycleIntent,
    node_id: u64,
    step: &TargetRuntimeStep,
    phase_kind: RecoveryPhase,
    admission: bool,
) -> Result<()> {
    let expected = match phase_kind {
        RecoveryPhase::Initialize => LifecyclePhase::Initialize,
        RecoveryPhase::Complete => LifecyclePhase::Complete,
        _ => return Err(conflict("quorum recovery phase differs")),
    };
    origin(state, operation)?.accepts_phase(current, expected)?;
    let input = quorum_input(state, operation)?;
    let complete_input = completion::completion_input(state, operation)?;
    let digest = if phase_kind == RecoveryPhase::Complete {
        complete_input.digest()?
    } else {
        input.digest()?
    };
    if current.request.phase_input_sha256 != digest {
        return Err(conflict("committed quorum input differs"));
    }
    match step {
        TargetRuntimeStep::Start(TargetReplicaInput::Quorum(actual))
            if phase_kind == RecoveryPhase::Initialize && actual == &input =>
        {
            if admission && started_for(state, operation, node_id, current.request.command_id)? {
                return Err(conflict(
                    "target already started under this exact Control phase",
                ));
            }
        }
        TargetRuntimeStep::Start(TargetReplicaInput::Completion(actual))
            if phase_kind == RecoveryPhase::Complete && actual == &complete_input =>
        {
            if admission && started_for(state, operation, node_id, current.request.command_id)? {
                return Err(conflict(
                    "target already started under this exact Complete phase",
                ));
            }
        }
        TargetRuntimeStep::Initialize(actual)
            if phase_kind == RecoveryPhase::Initialize
                && actual == &input
                && operation.voters.keys().next() == Some(&node_id) =>
        {
            if admission && operation.initialization_attempt.is_some() {
                return Err(conflict(
                    "Initialize already has its single original dispatch marker",
                ));
            }
            if admission && !all_started(state, operation, current.request.command_id)? {
                return Err(conflict(
                    "initialization requires every target started under this exact phase",
                ));
            }
        }
        TargetRuntimeStep::Complete(actual)
            if phase_kind == RecoveryPhase::Complete && actual == &complete_input =>
        {
            if admission {
                require_initialized_mutation_observer(state, operation, node_id)?;
            }
            receiver::preparation(state, operation)?;
        }
        _ => {
            return Err(conflict(
                "target quorum operation differs from committed input",
            ));
        }
    }
    Ok(())
}
/// Routing a completion to another installed voter retries the same target
/// command and absolute cap. Both phase entries remain permanent, and whichever
/// voter is current leader resolves the single original target completion.
pub(crate) fn completion_route_retry(
    pending: &RecoveryPhaseRecord,
    input: &RecoveryDispatch,
    now: u64,
) -> bool {
    matches!((&pending.input, input),
        (RecoveryDispatch::Target { node_id: old, request: original }, RecoveryDispatch::Target { node_id: new, request: next })
        if matches!(pending.phase, RecoveryPhase::Complete | RecoveryPhase::Confirm) && old != new
            && original == next && now < original.not_after_ms
            && (established_effect(&original.step) || (pending.phase == RecoveryPhase::Complete && established_start(&original.step))
                || matches!(original.step, TargetRuntimeStep::Activate { .. })))
}

/// Exact initialized membership is already retained. Startup acknowledgements
/// select reachable candidates; only an actual target barrier proves quorum.
pub(crate) fn established(state: &TenantState, operation: &RecoveryRecord) -> Result<()> {
    let retained = phase(
        state,
        operation,
        operation
            .initialization
            .ok_or_else(|| conflict("established target initialization is absent"))?,
    )?;
    let (RecoveryDispatch::Target { request, .. }, Some(RecoveryDispatchOutcome::Target(response))) =
        (&retained.input, &retained.outcome)
    else {
        return Err(conflict(
            "established target initialization evidence differs",
        ));
    };
    if matches!(
        response.outcome,
        TargetRuntimeOutcome::InitialMembershipStatus(_)
    ) {
        initial_inspection::validate_outcome(state, operation, retained, response)?;
        let original_id = operation
            .initialization_attempt
            .ok_or_else(|| conflict("observed initialization lacks original attempt"))?;
        let original = phase(state, operation, original_id)?;
        if !matches!(original.outcome, Some(RecoveryDispatchOutcome::InitialMembershipObserved { inspection_phase }) if inspection_phase == retained.phase_id)
        {
            return Err(conflict(
                "observed initialization lacks exact causal original link",
            ));
        }
        return initial_inspection::validate_link(state, operation, original, retained.phase_id);
    }
    let (TargetRuntimeStep::Initialize(input), TargetRuntimeOutcome::Initialized { origin_sha256 }) =
        (&request.step, &response.outcome)
    else {
        return Err(conflict(
            "established target initialization outcome differs",
        ));
    };
    if retained.phase != RecoveryPhase::Initialize
        || input != &quorum_input(state, operation)?
        || origin_sha256 != &input.origin_sha256
    {
        return Err(conflict("established target membership changed"));
    }
    Ok(())
}
pub(crate) fn established_start(step: &TargetRuntimeStep) -> bool {
    matches!(
        step,
        TargetRuntimeStep::Start(
            TargetReplicaInput::Completion(_)
                | TargetReplicaInput::InitialMembershipStatus(_)
                | TargetReplicaInput::CompletionAttemptStatus(_)
                | TargetReplicaInput::CompletionTerminalStatus(_)
                | TargetReplicaInput::CompletionResolution(_)
                | TargetReplicaInput::Inspection(_)
        )
    )
}
pub(crate) fn established_effect(step: &TargetRuntimeStep) -> bool {
    matches!(
        step,
        TargetRuntimeStep::PrepareComplete(_)
            | TargetRuntimeStep::Complete(_)
            | TargetRuntimeStep::InspectCompletionAttempt(_)
            | TargetRuntimeStep::InspectCompletionResolution(_)
            | TargetRuntimeStep::ResolveComplete(_)
            | TargetRuntimeStep::Inspect(_)
    )
}
pub(crate) fn ready_nodes(
    state: &TenantState,
    operation: &RecoveryRecord,
    current: Uuid,
) -> Result<Vec<u64>> {
    established(state, operation)?;
    operation
        .voters
        .keys()
        .copied()
        .filter_map(|node| match started_for(state, operation, node, current) {
            Ok(true) => Some(Ok(node)),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}
/// The boolean requests startup; otherwise the selected observer can attempt
/// the actual quorum read/write. Boot receipts themselves never prove quorum.
pub(crate) fn established_destination(
    state: &TenantState,
    operation: &RecoveryRecord,
    current: Uuid,
) -> Result<(u64, bool)> {
    let ready = ready_nodes(state, operation, current)?;
    if ready.len() > operation.voters.len() / 2 {
        return Ok((ready[0], false));
    }
    let inspecting = matches!(
        intent(state, operation, current)?.request.phase,
        LifecyclePhase::InspectCompletionAttempt
            | LifecyclePhase::InspectCompletionResolution
            | LifecyclePhase::InspectTarget
    );
    let mut next_start = None;
    for (&node, voter) in &operation.voters {
        if ready.contains(&node) {
            continue;
        }
        let previous = voter
            .start_attempt
            .map(|id| phase(state, operation, id))
            .transpose()?;
        if previous.is_some_and(|record| matches!(&record.input,
            RecoveryDispatch::Target { node_id, request }
            if *node_id == node && request.command_id == current && established_start(&request.step))) {
            continue;
        }
        // A fresh read-only inspection can otherwise repeatedly start the same
        // majority and never reach the elected observer at another voter.
        // Earlier attempts only rank startups. Every reply is still scoped to
        // the current intent and only a positive quorum observation resolves it.
        let sequence = previous
            .filter(|_| inspecting)
            .map(|record| record.sequence);
        let rank = (sequence, node);
        if next_start.is_none_or(|best| rank < best) {
            next_start = Some(rank);
        }
    }
    if let Some((_, node)) = next_start {
        return Ok((node, true));
    }
    let after = match operation.last_phase {
        Some(id) => match &phase(state, operation, id)?.input {
            RecoveryDispatch::Target { node_id, .. } => Some(*node_id),
            _ => None,
        },
        None => None,
    };
    let candidate = operation
        .voters
        .keys()
        .copied()
        .filter(|node| !ready.contains(node))
        .find(|node| after.is_none_or(|after| *node > after))
        .or_else(|| {
            operation
                .voters
                .keys()
                .copied()
                .find(|node| !ready.contains(node))
        })
        .ok_or_else(|| conflict("established target startup candidates absent"))?;
    Ok((candidate, true))
}
pub(crate) fn require_eligible_observer(
    state: &TenantState,
    operation: &RecoveryRecord,
    current: Uuid,
    node: u64,
) -> Result<()> {
    let ready = ready_nodes(state, operation, current)?;
    if !ready.contains(&node) {
        return Err(conflict(
            "target observer has no exact current startup acknowledgment",
        ));
    }
    Ok(())
}

/// An exact Complete mutation can open its target replica at the selected
/// voter. Its original initialized membership and all materialization proofs
/// establish the candidate set; a fresh Start reply only ranks reachable
/// candidates and cannot exclude a leader elected at another installed voter.
pub(crate) fn require_initialized_mutation_observer(
    state: &TenantState,
    operation: &RecoveryRecord,
    node: u64,
) -> Result<()> {
    established(state, operation)?;
    if !operation.voters.contains_key(&node)
        || operation
            .voters
            .get(&node)
            .and_then(|voter| voter.materialization)
            .is_none()
    {
        return Err(conflict(
            "target mutation observer lacks original materialization",
        ));
    }
    Ok(())
}
pub(crate) fn retry_destination(
    state: &TenantState,
    operation: &RecoveryRecord,
    current: Uuid,
    old: u64,
    step: &TargetRuntimeStep,
) -> Result<u64> {
    if established_start(step) {
        let (candidate, startup) = established_destination(state, operation, current)?;
        if !startup || candidate == old {
            return Err(conflict("another pending startup route is unavailable"));
        }
        return Ok(candidate);
    }
    if matches!(
        step,
        TargetRuntimeStep::PrepareComplete(_) | TargetRuntimeStep::Complete(_)
    ) {
        established(state, operation)?;
        return operation
            .voters
            .keys()
            .copied()
            .find(|node| *node > old)
            .or_else(|| operation.voters.keys().next().copied())
            .filter(|node| *node != old)
            .ok_or_else(|| conflict("another initialized target voter is unavailable"));
    }
    let ready = ready_nodes(state, operation, current)?;
    ready
        .iter()
        .copied()
        .find(|node| *node > old)
        .or_else(|| ready.first().copied())
        .filter(|node| *node != old)
        .ok_or_else(|| conflict("another eligible target observer is unavailable"))
}
