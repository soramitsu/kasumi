//! A fresh read-only phase can resolve one exact possibly dispatched Initialize.
//! Original markers, caps and Start facts remain immutable; absence is unknown.
use super::*;

fn original<'a>(
    state: &'a TenantState,
    operation: &RecoveryRecord,
) -> Result<&'a RecoveryPhaseRecord> {
    phase(
        state,
        operation,
        operation
            .initialization_attempt
            .ok_or_else(|| conflict("original Initialize attempt absent"))?,
    )
}

pub(crate) fn status_input(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<TargetInitialMembershipStatusInput> {
    let retained = original(state, operation)?;
    let RecoveryDispatch::Target { request, .. } = &retained.input else {
        return Err(conflict("original Initialize is not a target dispatch"));
    };
    if retained.phase != RecoveryPhase::Initialize
        || !matches!(request.step, TargetRuntimeStep::Initialize(_))
    {
        return Err(conflict("original Initialize dispatch differs"));
    }
    let original_intent = state
        .lifecycle_control
        .as_ref()
        .and_then(|control| control.intents.get(&request.command_id))
        .ok_or_else(|| conflict("original Initialize Control intent absent"))?
        .clone();
    let starts = operation
        .initialization_starts
        .iter()
        .map(|(node, id)| Ok((*node, phase(state, operation, *id)?.clone())))
        .collect::<Result<BTreeMap<_, _>>>()?;
    // This projection names the originally marked immutable packet. A later
    // causal outcome is verified separately and never changes inspection input.
    let mut initialize = retained.clone();
    initialize.outcome = None;
    initialize.resolved_revision = None;
    let input = TargetInitialMembershipStatusInput {
        original_intent,
        quorum: quorum_input(state, operation)?,
        starts,
        initialize,
    };
    input.digest()?;
    if input.quorum() != &quorum_input(state, operation)? {
        return Err(conflict(
            "initial membership inspection changed materializations",
        ));
    }
    Ok(input)
}

pub(crate) fn fresh_phase(operation: &RecoveryRecord) -> LifecyclePhase {
    if operation.initialization_attempt.is_some() {
        LifecyclePhase::InspectInitialMembership
    } else {
        LifecyclePhase::Initialize
    }
}

/// Only a fresh read-only phase may follow the exact expired Initialize or an
/// expired inspection of that same immutable cause. Neither case repeats the
/// original effect or changes its retained marker and deadline.
pub(crate) fn may_inspect_pending(
    state: &TenantState,
    operation: &RecoveryRecord,
    pending: &RecoveryPhaseRecord,
    now: u64,
) -> Result<bool> {
    if operation.phase != RecoveryPhase::Initialize
        || pending.phase != RecoveryPhase::Initialize
        || pending.operation_id != operation.request.operation_id
        || pending.outcome.is_some()
        || !pending
            .effect_attempts
            .contains_key(&RecoveryEffect::TargetCommand)
    {
        return Ok(false);
    }
    let RecoveryDispatch::Target { node_id, request } = &pending.input else {
        return Ok(false);
    };
    if now < request.not_after_ms {
        return Ok(false);
    }
    pending.validate()?;
    if operation.initialization_attempt == Some(pending.phase_id)
        && matches!(request.step, TargetRuntimeStep::Initialize(_))
    {
        return Ok(status_input(state, operation)?.initialize == *pending);
    }
    if !is_step(&request.step) || original(state, operation)?.outcome.is_some() {
        return Ok(false);
    }
    let current = intent(
        state,
        operation,
        operation
            .current_intent
            .ok_or_else(|| conflict("pending initial inspection Control intent absent"))?,
    )?;
    if current.request.command_id != request.command_id {
        return Ok(false);
    }
    validate_step(state, operation, current, *node_id, request, false)?;
    Ok(true)
}

pub(crate) fn is_step(step: &TargetRuntimeStep) -> bool {
    matches!(
        step,
        TargetRuntimeStep::Start(TargetReplicaInput::InitialMembershipStatus(_))
            | TargetRuntimeStep::InspectInitialMembership(_)
    )
}
fn started_nodes(
    state: &TenantState,
    operation: &RecoveryRecord,
    command: Uuid,
) -> Result<Vec<u64>> {
    operation
        .voters
        .keys()
        .filter_map(|node| match started_for(state, operation, *node, command) {
            Ok(true) => Some(Ok(*node)),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}
fn attempted_start(
    state: &TenantState,
    operation: &RecoveryRecord,
    command: Uuid,
    node: u64,
) -> bool {
    state.recovery_control.phases.values().any(|phase| phase.operation_id == operation.request.operation_id
        && matches!(&phase.input, RecoveryDispatch::Target { node_id, request }
            if *node_id == node && request.command_id == command
            && matches!(request.step, TargetRuntimeStep::Start(TargetReplicaInput::InitialMembershipStatus(_)))))
}
/// Both variants only open/read under a fresh inspection phase. Routing keeps
/// the exact packet and absolute cap and never repeats original Initialize.
pub(crate) fn route_retry(
    pending: &RecoveryPhaseRecord,
    input: &RecoveryDispatch,
    now: u64,
) -> bool {
    matches!((&pending.input, input),
        (RecoveryDispatch::Target { node_id: old, request: original }, RecoveryDispatch::Target { node_id: new, request: next })
        if pending.phase == RecoveryPhase::Initialize && pending.outcome.is_none()
            && old != new && original == next && now < original.not_after_ms && is_step(&original.step))
}
pub(crate) fn retry_destination(
    state: &TenantState,
    operation: &RecoveryRecord,
    pending: &RecoveryPhaseRecord,
    now: u64,
) -> Result<Option<u64>> {
    let RecoveryDispatch::Target { node_id, request } = &pending.input else {
        return Ok(None);
    };
    if pending.phase != RecoveryPhase::Initialize
        || pending.outcome.is_some()
        || now >= request.not_after_ms
        || !is_step(&request.step)
    {
        return Ok(None);
    }
    let current = intent(
        state,
        operation,
        operation
            .current_intent
            .ok_or_else(|| conflict("inspection current intent absent"))?,
    )?;
    if request.command_id != current.request.command_id {
        return Err(conflict("inspection retry is not current"));
    }
    validate_step(state, operation, current, *node_id, request, false)?;
    let candidates = if matches!(request.step, TargetRuntimeStep::Start(_)) {
        operation
            .voters
            .keys()
            .copied()
            .filter(|node| !attempted_start(state, operation, request.command_id, *node))
            .collect()
    } else {
        started_nodes(state, operation, request.command_id)?
    };
    Ok(candidates
        .iter()
        .copied()
        .find(|node| node > node_id)
        .or_else(|| candidates.first().copied())
        .filter(|node| node != node_id))
}
pub(crate) fn validate_frozen_phase(
    state: &TenantState,
    operation: &RecoveryRecord,
    retained: &RecoveryPhaseRecord,
) -> Result<()> {
    let RecoveryDispatch::Target { node_id, request } = &retained.input else {
        return Err(conflict("inspection frozen target absent"));
    };
    let current = state
        .lifecycle_control
        .as_ref()
        .and_then(|control| control.intents.get(&request.command_id))
        .ok_or_else(|| conflict("inspection frozen Control intent absent"))?;
    validate_step(state, operation, current, *node_id, request, false)
}
pub(crate) fn validate_step(
    state: &TenantState,
    operation: &RecoveryRecord,
    current: &LifecycleIntent,
    node: u64,
    request: &TargetRuntimeRequest,
    admission: bool,
) -> Result<()> {
    let input = match &request.step {
        TargetRuntimeStep::Start(TargetReplicaInput::InitialMembershipStatus(input))
        | TargetRuntimeStep::InspectInitialMembership(input) => input.as_ref(),
        _ => return Err(conflict("initial membership inspection step differs")),
    };
    if input != &status_input(state, operation)? {
        return Err(conflict("inspection changed original accepted dispatch"));
    }
    input.validate(&origin(state, operation)?, current)?;
    let original = original(state, operation)?;
    if current.revision
        <= original
            .effect_attempts
            .get(&RecoveryEffect::TargetCommand)
            .ok_or_else(|| conflict("original Initialize marker absent"))?
            .begun_revision
    {
        return Err(conflict("inspection precedes original Initialize marker"));
    }
    if !operation.voters.contains_key(&node) {
        return Err(conflict("inspection route is not an installed voter"));
    }
    if admission {
        if matches!(request.step, TargetRuntimeStep::Start(_)) {
            if started_for(state, operation, node, current.request.command_id)? {
                return Err(conflict(
                    "inspection voter already started under current phase",
                ));
            }
        } else {
            let nodes = started_nodes(state, operation, current.request.command_id)?;
            if nodes.len() < 2 || !nodes.contains(&node) {
                return Err(conflict(
                    "inspection needs two original installed members and a started observer",
                ));
            }
        }
    }
    Ok(())
}
pub(crate) fn next(
    state: &TenantState,
    operation: &RecoveryRecord,
    current: &LifecycleIntent,
    now: u64,
    expires: u64,
) -> Result<RecoveryDispatch> {
    let input = status_input(state, operation)?;
    let nodes = started_nodes(state, operation, current.request.command_id)?;
    let (node_id, step) = if nodes.len() >= 2 {
        (
            nodes[0],
            TargetRuntimeStep::InspectInitialMembership(Box::new(input)),
        )
    } else {
        let node = operation
            .voters
            .keys()
            .copied()
            .find(|node| !attempted_start(state, operation, current.request.command_id, *node))
            .ok_or_else(|| {
                conflict(
                    "inspection has no available original quorum; wait for current phase expiry",
                )
            })?;
        (
            node,
            TargetRuntimeStep::Start(TargetReplicaInput::InitialMembershipStatus(Box::new(input))),
        )
    };
    Ok(RecoveryDispatch::Target {
        node_id,
        request: Box::new(TargetRuntimeRequest {
            tenant: operation.request.tenant.clone(),
            command_id: current.request.command_id,
            not_after_ms: now
                .checked_add(operation.request.phase_timeout_ms)
                .ok_or_else(|| conflict("inspection deadline overflow"))?
                .min(expires)
                .min(current.original_credential_expires_at_ms),
            step,
        }),
    })
}
pub(crate) fn validate_outcome(
    state: &TenantState,
    operation: &RecoveryRecord,
    prepared: &RecoveryPhaseRecord,
    response: &TargetRuntimeResponse,
) -> Result<()> {
    let RecoveryDispatch::Target { node_id, request } = &prepared.input else {
        return Err(conflict("inspection target phase absent"));
    };
    let current = state
        .lifecycle_control
        .as_ref()
        .and_then(|control| control.intents.get(&request.command_id))
        .ok_or_else(|| conflict("inspection Control identity absent"))?;
    validate_step(state, operation, current, *node_id, request, false)?;
    if prepared.phase != RecoveryPhase::Initialize
        || response.command_id != request.command_id
        || response.node_id != *node_id
        || prepared.prepared_revision <= current.revision
    {
        return Err(conflict("inspection response route differs"));
    }
    match (&request.step, &response.outcome) {
        (
            TargetRuntimeStep::Start(TargetReplicaInput::InitialMembershipStatus(input)),
            TargetRuntimeOutcome::Started { origin_sha256 },
        ) if *origin_sha256 == input.quorum().origin_sha256 => {}
        (
            TargetRuntimeStep::InspectInitialMembership(input),
            TargetRuntimeOutcome::InitialMembershipStatus(signed),
        ) => {
            kasumi_serving::verify_target_initial_membership_status(input, signed).map_err(
                |_| conflict("inspection signature or committed original cause differs"),
            )?;
            if signed.observation.status_intent != *current
                || signed.observation.observer_node_id != *node_id
                || prepared.prepared_revision <= original(state, operation)?.prepared_revision
            {
                return Err(conflict(
                    "inspection current identity or original cause order differs",
                ));
            }
            let started = state.recovery_control.phases.values().filter_map(|phase| {
                let (RecoveryDispatch::Target { node_id, request }, Some(RecoveryDispatchOutcome::Target(response))) = (&phase.input, &phase.outcome) else { return None };
                if phase.operation_id == operation.request.operation_id && phase.phase == RecoveryPhase::Initialize
                    && phase.prepared_revision > current.revision
                    && phase.resolved_revision.is_some_and(|revision| revision < prepared.prepared_revision)
                    && request.command_id == current.request.command_id
                    && matches!(&request.step, TargetRuntimeStep::Start(TargetReplicaInput::InitialMembershipStatus(start)) if start.as_ref() == input.as_ref())
                    && response.node_id == *node_id && response.command_id == request.command_id
                    && matches!(&response.outcome, TargetRuntimeOutcome::Started { origin_sha256 } if origin_sha256 == &input.quorum.origin_sha256) {
                    Some(*node_id)
                } else { None }
            }).collect::<std::collections::BTreeSet<_>>();
            if started.len() < 2
                || !started.contains(node_id)
                || !started
                    .iter()
                    .all(|node| operation.voters.contains_key(node))
            {
                return Err(conflict(
                    "initial inspection lacks causally prior current original-quorum starts",
                ));
            }
            let installed = state
                .lifecycle_control
                .as_ref()
                .ok_or_else(|| conflict("Control installation absent"))?;
            if signed.observation.association.association.control_root
                != installed.installation.root
            {
                return Err(conflict(
                    "committed initialization association Control root differs",
                ));
            }
        }
        _ => return Err(conflict("inspection outcome differs")),
    }
    Ok(())
}

pub(crate) fn validate_link(
    state: &TenantState,
    operation: &RecoveryRecord,
    original: &RecoveryPhaseRecord,
    inspection_phase: Uuid,
) -> Result<()> {
    if operation.initialization_attempt != Some(original.phase_id) {
        return Err(conflict(
            "membership observation linked another original Initialize",
        ));
    }
    let observed = phase(state, operation, inspection_phase)?;
    let Some(RecoveryDispatchOutcome::Target(response)) = &observed.outcome else {
        return Err(conflict(
            "membership observation lacks positive native outcome",
        ));
    };
    if !matches!(
        response.outcome,
        TargetRuntimeOutcome::InitialMembershipStatus(_)
    ) || observed.prepared_revision <= original.prepared_revision
        || observed.resolved_revision != original.resolved_revision
    {
        return Err(conflict("membership observation is not causally later"));
    }
    validate_outcome(state, operation, observed, response)
}

pub(crate) fn resolve_original(
    state: &mut TenantState,
    operation: &RecoveryRecord,
    observed: &RecoveryPhaseRecord,
) -> Result<()> {
    let mut prior = original(state, operation)?.clone();
    if prior.outcome.is_some() {
        return Err(conflict(
            "original Initialize already has a permanent outcome",
        ));
    }
    prior.resolved_revision = Some(state.revision);
    validate_link(state, operation, &prior, observed.phase_id)?;
    prior.outcome = Some(RecoveryDispatchOutcome::InitialMembershipObserved {
        inspection_phase: observed.phase_id,
    });
    prior.validate()?;
    state
        .recovery_control
        .phases
        .insert(phase_key(prior.operation_id, prior.phase_id), prior);
    Ok(())
}

pub(crate) fn validate_progress(state: &TenantState, operation: &RecoveryRecord) -> Result<()> {
    if operation.initialization_attempt.is_some() {
        status_input(state, operation)?;
    }
    let mut requests = BTreeMap::new();
    for retained in state
        .recovery_control
        .phases
        .values()
        .filter(|phase| phase.operation_id == operation.request.operation_id)
    {
        let RecoveryDispatch::Target { request, .. } = &retained.input else {
            continue;
        };
        if matches!(request.step, TargetRuntimeStep::InspectInitialMembership(_)) {
            let digest = staged_digest(request)?.0;
            if requests
                .insert(request.command_id, digest.clone())
                .is_some_and(|old| old != digest)
            {
                return Err(conflict(
                    "inspection retry changed original request or absolute cap",
                ));
            }
        }
    }
    Ok(())
}
pub(crate) fn validate_successor(
    _previous: &TenantState,
    incoming: &TenantState,
    _old: &RecoveryRecord,
    new: &RecoveryRecord,
) -> Result<()> {
    validate_progress(incoming, new)
}
