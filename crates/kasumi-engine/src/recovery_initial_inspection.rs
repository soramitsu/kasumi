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
            | TargetRuntimeStep::InspectInitialAssociation(_)
            | TargetRuntimeStep::InspectInitialMembership(_)
    )
}

/// Historical association records remain valid after a fresh Control intent
/// replaces the bounded scheduling head. Each intent admits exactly one.
fn association_record<'a>(
    state: &'a TenantState,
    operation: &RecoveryRecord,
    current: &LifecycleIntent,
) -> Result<(
    &'a RecoveryPhaseRecord,
    &'a SignedTargetInitialMembershipAssociation,
)> {
    let mut result = None;
    for retained in state.recovery_control.phases.values() {
        if retained.operation_id != operation.request.operation_id {
            continue;
        }
        let (
            RecoveryDispatch::Target { node_id, request },
            Some(RecoveryDispatchOutcome::Target(response)),
        ) = (&retained.input, &retained.outcome)
        else {
            continue;
        };
        let (
            TargetRuntimeStep::InspectInitialAssociation(input),
            TargetRuntimeOutcome::InitialMembershipAssociation(signed),
        ) = (&request.step, &response.outcome)
        else {
            continue;
        };
        if request.command_id != current.request.command_id {
            continue;
        }
        if result.is_some()
            || response.command_id != request.command_id
            || response.node_id != *node_id
            || *node_id != input.node_id()?
            || retained.phase != RecoveryPhase::Initialize
            || retained
                .resolved_revision
                .is_none_or(|revision| revision <= retained.prepared_revision)
            || retained.prepared_revision <= current.revision
            || signed.observation.status_intent != *current
            || **input != status_input(state, operation)?
        {
            return Err(conflict(
                "retained initial membership association identity or cardinality differs",
            ));
        }
        kasumi_serving::verify_target_initial_membership_association(input, signed)
            .map_err(|_| conflict("retained initial membership association proof differs"))?;
        result = Some((retained, signed.as_ref()));
    }
    result.ok_or_else(|| conflict("current initial membership association absent"))
}

pub(crate) fn route_retry(
    pending: &RecoveryPhaseRecord,
    input: &RecoveryDispatch,
    now: u64,
) -> bool {
    matches!((&pending.input, input),
        (RecoveryDispatch::Target { node_id: old, request: original }, RecoveryDispatch::Target { node_id: new, request: next })
        if pending.phase == RecoveryPhase::Initialize && pending.outcome.is_none()
            && old != new && original == next && now < original.not_after_ms
            && matches!(original.step, TargetRuntimeStep::InspectInitialMembership(_)))
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
        || !matches!(request.step, TargetRuntimeStep::InspectInitialMembership(_))
    {
        return Ok(None);
    }
    let current = intent(
        state,
        operation,
        operation
            .current_intent
            .ok_or_else(|| conflict("initial inspection current intent absent"))?,
    )?;
    if request.command_id != current.request.command_id {
        return Err(conflict("initial inspection retry is not current"));
    }
    validate_step(state, operation, current, *node_id, request, true)?;
    let next = operation
        .voters
        .keys()
        .copied()
        .find(|node| node > node_id)
        .or_else(|| operation.voters.keys().next().copied())
        .filter(|node| node != node_id)
        .ok_or_else(|| conflict("another started initial membership observer is absent"))?;
    Ok(Some(next))
}

pub(crate) fn validate_frozen_phase(
    state: &TenantState,
    operation: &RecoveryRecord,
    retained: &RecoveryPhaseRecord,
) -> Result<()> {
    let RecoveryDispatch::Target { node_id, request } = &retained.input else {
        return Err(conflict("initial inspection frozen target absent"));
    };
    let current = state
        .lifecycle_control
        .as_ref()
        .and_then(|control| control.intents.get(&request.command_id))
        .ok_or_else(|| conflict("initial inspection frozen Control intent absent"))?;
    validate_step(state, operation, current, *node_id, request, false)?;
    if matches!(request.step, TargetRuntimeStep::InspectInitialMembership(_)) {
        let (association, _) = association_record(state, operation, current)?;
        if association
            .resolved_revision
            .is_none_or(|revision| revision >= retained.prepared_revision)
        {
            return Err(conflict(
                "initial membership read precedes retained association",
            ));
        }
    }
    Ok(())
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
        | TargetRuntimeStep::InspectInitialAssociation(input) => input.as_ref(),
        TargetRuntimeStep::InspectInitialMembership(association) => {
            let (retained, selected) = association_record(state, operation, current)?;
            if selected != association.as_ref()
                || (admission && operation.initialization_association != Some(retained.phase_id))
            {
                return Err(conflict(
                    "initial membership inspection changed retained association",
                ));
            }
            &association.observation.input
        }
        _ => return Err(conflict("initial membership inspection step differs")),
    };
    if input != &status_input(state, operation)? {
        return Err(conflict(
            "initial membership inspection changed original dispatch",
        ));
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
        return Err(conflict(
            "inspection Control phase precedes original Initialize marker",
        ));
    }
    let startup = matches!(request.step, TargetRuntimeStep::Start(_));
    if !operation.voters.contains_key(&node)
        || (matches!(
            request.step,
            TargetRuntimeStep::InspectInitialAssociation(_)
        ) && node != input.node_id()?)
    {
        return Err(conflict(
            "initial membership association or observer route differs",
        ));
    }
    if admission {
        if startup && started_for(state, operation, node, current.request.command_id)? {
            return Err(conflict(
                "inspection voter already started under exact current phase",
            ));
        }
        if !startup && !quorum::all_started(state, operation, current.request.command_id)? {
            return Err(conflict(
                "initial membership inspection requires all three current Start acknowledgements",
            ));
        }
        if matches!(
            request.step,
            TargetRuntimeStep::InspectInitialAssociation(_)
        ) && operation.initialization_association.is_some()
        {
            return Err(conflict(
                "current inspection already retained its original-node association",
            ));
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
    let mut destination = None;
    for node in operation.voters.keys() {
        if !started_for(state, operation, *node, current.request.command_id)? {
            destination = Some(*node);
            break;
        }
    }
    let (node_id, step) = if let Some(node) = destination {
        (
            node,
            TargetRuntimeStep::Start(TargetReplicaInput::InitialMembershipStatus(Box::new(input))),
        )
    } else if operation.initialization_association.is_none() {
        (
            input.node_id()?,
            TargetRuntimeStep::InspectInitialAssociation(Box::new(input)),
        )
    } else {
        let (_, association) = association_record(state, operation, current)?;
        (
            input.node_id()?,
            TargetRuntimeStep::InspectInitialMembership(Box::new(association.clone())),
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
        return Err(conflict(
            "initial membership inspection is not a target phase",
        ));
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
        return Err(conflict(
            "initial membership inspection response route differs",
        ));
    }
    match (&request.step, &response.outcome) {
        (
            TargetRuntimeStep::Start(TargetReplicaInput::InitialMembershipStatus(input)),
            TargetRuntimeOutcome::Started { origin_sha256 },
        ) if *origin_sha256 == input.quorum().origin_sha256 => {}
        (
            TargetRuntimeStep::InspectInitialAssociation(input),
            TargetRuntimeOutcome::InitialMembershipAssociation(signed),
        ) => {
            kasumi_serving::verify_target_initial_membership_association(input, signed).map_err(
                |_| {
                    conflict("initial membership association signature or original history differs")
                },
            )?;
            if signed.observation.status_intent != *current
                || signed.observation.original_node_id != *node_id
            {
                return Err(conflict(
                    "initial membership association current identity differs",
                ));
            }
        }
        (
            TargetRuntimeStep::InspectInitialMembership(association),
            TargetRuntimeOutcome::InitialMembershipStatus(signed),
        ) => {
            let input = &association.observation.input;
            kasumi_serving::verify_target_initial_membership_status(input, signed).map_err(
                |_| conflict("initial membership inspection signature or original history differs"),
            )?;
            let (retained, _) = association_record(state, operation, current)?;
            if signed.observation.association != **association
                || signed.observation.status_intent != *current
                || signed.observation.observer_node_id != *node_id
                || retained
                    .resolved_revision
                    .is_none_or(|revision| revision >= prepared.prepared_revision)
                || prepared.prepared_revision <= original(state, operation)?.prepared_revision
            {
                return Err(conflict(
                    "initial membership inspection current identity or association order differs",
                ));
            }
        }
        _ => return Err(conflict("initial membership inspection outcome differs")),
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
        let input = status_input(state, operation)?;
        for start in input.starts.values() {
            if start
                .resolved_revision
                .is_none_or(|revision| revision >= input.initialize.prepared_revision)
            {
                return Err(conflict(
                    "original Initialize precedes successful Start evidence",
                ));
            }
        }
    }
    let latest = latest_inspection(state, operation)?;
    let mut associations = BTreeMap::new();
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
        if matches!(
            request.step,
            TargetRuntimeStep::InspectInitialAssociation(_)
        ) && matches!(&retained.outcome, Some(RecoveryDispatchOutcome::Target(response))
                if matches!(response.outcome, TargetRuntimeOutcome::InitialMembershipAssociation(_)))
            && associations
                .insert(request.command_id, retained.phase_id)
                .is_some()
        {
            return Err(conflict(
                "inspection intent has more than one retained association",
            ));
        }
        if matches!(request.step, TargetRuntimeStep::InspectInitialMembership(_)) {
            let digest = staged_digest(request)?.0;
            if requests
                .insert(request.command_id, digest.clone())
                .is_some_and(|prior| prior != digest)
            {
                return Err(conflict(
                    "initial inspection route retry changed original request or cap",
                ));
            }
        }
    }
    let expected = latest.and_then(|phase| associations.get(&phase.phase_id).copied());
    if operation.initialization_association != expected {
        return Err(conflict(
            "initial association head differs from latest accepted inspection",
        ));
    }
    if let Some(phase) = latest
        && expected.is_some()
    {
        association_record(state, operation, intent(state, operation, phase.phase_id)?)?;
    }
    Ok(())
}

fn latest_inspection<'a>(
    state: &'a TenantState,
    operation: &RecoveryRecord,
) -> Result<Option<&'a RecoveryPhaseRecord>> {
    let latest = state.recovery_control.phases.values()
        .filter(|phase| phase.operation_id == operation.request.operation_id
            && matches!((&phase.input, &phase.outcome),
                (RecoveryDispatch::ControlIntent(request), Some(RecoveryDispatchOutcome::ControlIntent(_)))
                    if request.phase == LifecyclePhase::InspectInitialMembership))
        .max_by_key(|phase| phase.sequence);
    if let Some(phase) = latest {
        let current = intent(state, operation, phase.phase_id)?;
        status_input(state, operation)?.validate(&origin(state, operation)?, current)?;
    }
    Ok(latest)
}

pub(crate) fn validate_successor(
    previous: &TenantState,
    incoming: &TenantState,
    old: &RecoveryRecord,
    new: &RecoveryRecord,
) -> Result<()> {
    if let Some(old_id) = old.initialization_association
        && new.initialization_association != Some(old_id)
    {
        let old_association = phase(previous, old, old_id)?;
        let newer = latest_inspection(incoming, new)?.ok_or_else(|| {
            conflict("snapshot removed association without a new inspection intent")
        })?;
        if newer.sequence <= old_association.sequence
            || newer.prepared_revision
                <= old_association
                    .resolved_revision
                    .ok_or_else(|| conflict("original association was not resolved"))?
        {
            return Err(conflict(
                "snapshot substituted association without a later accepted inspection",
            ));
        }
        validate_progress(incoming, new)?;
    }
    Ok(())
}
