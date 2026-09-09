//! Fresh observation of the exact original Complete identity. A positive fact
//! may resolve it; absence never becomes a negative outcome or new mutation.
use super::*;

/// The retained Complete identity commits the complete canonical input,
/// including the explicit predecessor field. A quorum-only digest is invalid.
pub(crate) fn validate_original_intent(
    origin: &TargetOrigin,
    expected: &TargetCompletionInput,
    original: &LifecycleIntent,
) -> Result<()> {
    expected
        .validate(origin, original)
        .map_err(|_| conflict("original completion identity input differs"))
}

pub(crate) fn completion_input(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<TargetCompletionInput> {
    Ok(TargetCompletionInput {
        quorum: quorum_input(state, operation)?,
        predecessor: None,
    })
}

pub(crate) fn inspection_input(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<TargetInspectionInput> {
    let original = intent(
        state,
        operation,
        operation
            .completion_intent
            .ok_or_else(|| conflict("original completion intent absent"))?,
    )?;
    origin(state, operation)?.accepts_phase(original, LifecyclePhase::Complete)?;
    Ok(TargetInspectionInput {
        quorum: quorum_input(state, operation)?,
        original_phase: original.clone(),
        predecessor: completion_input(state, operation)?.predecessor,
    })
}
pub(crate) fn is_inspection(step: &TargetRuntimeStep) -> bool {
    matches!(
        step,
        TargetRuntimeStep::Start(TargetReplicaInput::Inspection(_)) | TargetRuntimeStep::Inspect(_)
    )
}
pub(crate) fn validate_step(
    state: &TenantState,
    operation: &RecoveryRecord,
    current: &LifecycleIntent,
    node: u64,
    step: &TargetRuntimeStep,
    admission: bool,
) -> Result<()> {
    let input = inspection_input(state, operation)?;
    input.validate(&origin(state, operation)?, current)?;
    match step {
        TargetRuntimeStep::Start(TargetReplicaInput::Inspection(actual)) if **actual == input => {
            if admission && started_for(state, operation, node, current.request.command_id)? {
                return Err(conflict(
                    "target already started under this exact inspection",
                ));
            }
        }
        TargetRuntimeStep::Inspect(actual) if **actual == input => {
            if admission && !quorum::all_started(state, operation, current.request.command_id)? {
                return Err(conflict(
                    "inspection requires every target started under its exact phase",
                ));
            }
        }
        _ => return Err(conflict("completion inspection input differs")),
    }
    Ok(())
}
pub(crate) fn validate_proof(
    state: &TenantState,
    operation: &RecoveryRecord,
    current: &LifecycleIntent,
    node: u64,
    signed: &SignedTargetInspection,
) -> Result<()> {
    let input = inspection_input(state, operation)?;
    if signed.observation.inspection_intent != *current
        || signed.observation.observer_node_id != node
    {
        return Err(conflict("completion inspection phase or observer differs"));
    }
    kasumi_serving::verify_target_inspection(&input, signed)
        .map_err(|_| conflict("completion inspection lacks its exact positive signature"))?;
    receiver::validate_inspected_terminal(state, operation, &signed.observation.completion)?;
    if let Some(id) = operation.completion_attempt {
        let original = phase(state, operation, id)?;
        let RecoveryDispatch::Target { request, .. } = &original.input else {
            return Err(conflict("original completion dispatch differs"));
        };
        if !matches!(request.step, TargetRuntimeStep::Complete(_))
            || request.command_id != input.original_phase.request.command_id
            || signed.observation.completion.admitted_at_ms >= request.not_after_ms
        {
            return Err(conflict(
                "inspected completion exceeded its unchanged original dispatch cap",
            ));
        }
    }
    Ok(())
}
pub(crate) fn validate_resolution(
    state: &TenantState,
    operation: &RecoveryRecord,
    original: &RecoveryPhaseRecord,
    inspection_phase: Uuid,
) -> Result<()> {
    let inspection = phase(state, operation, inspection_phase)?;
    let (
        RecoveryDispatch::Target { request: old, .. },
        RecoveryDispatch::Target { node_id, request },
        Some(RecoveryDispatchOutcome::Target(response)),
    ) = (&original.input, &inspection.input, &inspection.outcome)
    else {
        return Err(conflict("completion resolution phase references differ"));
    };
    let TargetRuntimeOutcome::Inspected(signed) = &response.outcome else {
        return Err(conflict(
            "completion resolution lacks a retained positive inspection",
        ));
    };
    if !matches!(old.step, TargetRuntimeStep::Complete(_))
        || !matches!(request.step, TargetRuntimeStep::Inspect(_))
        || old.command_id != signed.observation.input.original_phase.request.command_id
        || signed.observation.completion.admitted_at_ms >= old.not_after_ms
        || inspection.prepared_revision <= original.prepared_revision
        || inspection.resolved_revision != original.resolved_revision
        || response.command_id != request.command_id
        || response.node_id != *node_id
    {
        return Err(conflict(
            "resolved completion changed its original command or cap",
        ));
    }
    let current = state
        .lifecycle_control
        .as_ref()
        .and_then(|c| c.intents.get(&request.command_id))
        .ok_or_else(|| conflict("completion inspection Control intent absent"))?;
    validate_proof(state, operation, current, *node_id, signed)
}
pub(crate) fn resolve_original(
    state: &mut TenantState,
    operation: &RecoveryRecord,
    inspection_phase: Uuid,
) -> Result<()> {
    let Some(id) = operation.completion_attempt else {
        return Ok(());
    };
    let mut original = phase(state, operation, id)?.clone();
    if matches!(
        original.outcome,
        Some(RecoveryDispatchOutcome::CompletionTerminal { .. })
    ) {
        // Its exact positive terminal was validated against the inspection above;
        // preserve the earlier permanent terminal reference and resolution time.
        return Ok(());
    }
    if original.outcome.is_some() {
        return Err(conflict(
            "original completion already has a permanent outcome",
        ));
    }
    original.resolved_revision = Some(state.revision);
    validate_resolution(state, operation, &original, inspection_phase)?;
    original.outcome = Some(RecoveryDispatchOutcome::CompletionResolution { inspection_phase });
    original.validate()?;
    state
        .recovery_control
        .phases
        .insert(phase_key(operation.request.operation_id, id), original);
    Ok(())
}
pub(crate) fn next_inspection(
    state: &TenantState,
    operation: &RecoveryRecord,
    current: &LifecycleIntent,
    now: u64,
    expires: u64,
) -> Result<RecoveryDispatch> {
    let input = inspection_input(state, operation)?;
    input.validate(&origin(state, operation)?, current)?;
    let mut missing = None;
    for node in operation.voters.keys() {
        if !started_for(state, operation, *node, current.request.command_id)? {
            missing = Some(*node);
            break;
        }
    }
    let (node_id, step) = if let Some(node) = missing {
        (
            node,
            TargetRuntimeStep::Start(TargetReplicaInput::Inspection(Box::new(input))),
        )
    } else {
        (
            *operation
                .voters
                .keys()
                .next()
                .ok_or_else(|| conflict("inspection voters absent"))?,
            TargetRuntimeStep::Inspect(Box::new(input)),
        )
    };
    Ok(RecoveryDispatch::Target {
        node_id,
        request: Box::new(TargetRuntimeRequest {
            tenant: operation.request.tenant.clone(),
            command_id: current.request.command_id,
            not_after_ms: now
                .checked_add(operation.request.phase_timeout_ms)
                .ok_or_else(|| conflict("inspection dispatch deadline overflow"))?
                .min(expires)
                .min(current.original_credential_expires_at_ms),
            step,
        }),
    })
}

#[cfg(test)]
#[path = "recovery_completion_tests.rs"]
mod tests;
