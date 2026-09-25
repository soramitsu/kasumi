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
fn startup_attempted(
    state: &TenantState,
    operation: &RecoveryRecord,
    node: u64,
    current: Uuid,
) -> Result<bool> {
    let Some(id) = operation.voters.get(&node).and_then(|v| v.start_attempt) else {
        return Ok(false);
    };
    let retained = phase(state, operation, id)?;
    Ok(
        matches!(&retained.input, RecoveryDispatch::Target { node_id, request }
        if *node_id == node && request.command_id == current && established_start(&request.step)),
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
    for node in operation.voters.keys() {
        if !ready.contains(node) && !startup_attempted(state, operation, *node, current)? {
            return Ok((*node, true));
        }
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
