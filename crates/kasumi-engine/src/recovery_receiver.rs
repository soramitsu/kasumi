//! Positive preparation and terminal resolution are separate durable Control
//! phases. No missing receiver fact authorizes another completion attempt.
use super::*;

fn target_request(record: &RecoveryPhaseRecord) -> Result<(u64, &TargetRuntimeRequest)> {
    let RecoveryDispatch::Target { node_id, request } = &record.input else {
        return Err(conflict(
            "completion receiver reference is not a target dispatch",
        ));
    };
    if record.phase != RecoveryPhase::Complete {
        return Err(conflict("completion receiver reference has another phase"));
    }
    Ok((*node_id, request))
}
fn original<'a>(
    state: &'a TenantState,
    operation: &RecoveryRecord,
) -> Result<&'a RecoveryPhaseRecord> {
    phase(
        state,
        operation,
        operation
            .completion_preparation_attempt
            .ok_or_else(|| conflict("original preparation dispatch is not retained"))?,
    )
}
pub(crate) fn status_input(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<TargetCompletionAttemptStatusInput> {
    let (_, request) = target_request(original(state, operation)?)?;
    let TargetRuntimeStep::PrepareComplete(input) = &request.step else {
        return Err(conflict("original preparation step differs"));
    };
    let original_intent = intent(
        state,
        operation,
        operation
            .completion_intent
            .ok_or_else(|| conflict("original Complete identity absent"))?,
    )?;
    if request.command_id != original_intent.request.command_id
        || input != &completion::completion_input(state, operation)?
    {
        return Err(conflict("original preparation input differs"));
    }
    let result = TargetCompletionAttemptStatusInput {
        original_intent: original_intent.clone(),
        original_input: input.clone(),
        original_dispatch_not_after_ms: request.not_after_ms,
    };
    result.digest()?;
    Ok(result)
}
pub(crate) fn preparation<'a>(
    state: &'a TenantState,
    operation: &RecoveryRecord,
) -> Result<&'a TargetCompletionAttempt> {
    let retained = phase(
        state,
        operation,
        operation
            .completion_preparation
            .ok_or_else(|| conflict("positive preparation evidence absent"))?,
    )?;
    let Some(RecoveryDispatchOutcome::Target(response)) = &retained.outcome else {
        return Err(conflict("preparation evidence is not a native outcome"));
    };
    let attempt = match &response.outcome {
        TargetRuntimeOutcome::PreparedCompletion(signed) => &signed.observation.attempt,
        TargetRuntimeOutcome::CompletionAttemptStatus(signed) => &signed.observation.attempt,
        _ => return Err(conflict("preparation evidence kind differs")),
    };
    status_input(state, operation)?.matches(attempt)?;
    Ok(attempt)
}
pub(crate) fn resolution_input(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<TargetCompletionResolutionInput> {
    Ok(TargetCompletionResolutionInput {
        attempt: Box::new(preparation(state, operation)?.clone()),
    })
}
pub(crate) fn terminal<'a>(
    state: &'a TenantState,
    operation: &RecoveryRecord,
) -> Result<&'a TargetCompletionResolutionFact> {
    let retained = phase(
        state,
        operation,
        operation
            .completion_terminal
            .ok_or_else(|| conflict("terminal completion evidence absent"))?,
    )?;
    let Some(RecoveryDispatchOutcome::Target(response)) = &retained.outcome else {
        return Err(conflict(
            "terminal completion evidence is not a native outcome",
        ));
    };
    let TargetRuntimeOutcome::ResolvedCompletion(signed) = &response.outcome else {
        return Err(conflict("terminal completion evidence kind differs"));
    };
    if signed.observation.fact.input != resolution_input(state, operation)? {
        return Err(conflict("terminal completion changed the prepared attempt"));
    }
    Ok(&signed.observation.fact)
}
pub(crate) fn fresh_phase(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<LifecyclePhase> {
    if operation.completion_terminal.is_some() {
        return match &terminal(state, operation)?.terminal {
            TargetCompletionTerminal::Committed(_) => Ok(LifecyclePhase::InspectTarget),
            TargetCompletionTerminal::Sealed => Err(error(
                ErrorCode::Unavailable,
                "completion is durably sealed; linked successor dispatch is not installed",
            )),
        };
    }
    if operation.completion_resolution_attempt.is_some() {
        return Err(error(
            ErrorCode::Unavailable,
            "original terminal resolution is unresolved; fresh terminal-only observation is not installed",
        ));
    }
    if operation.completion_preparation.is_some() {
        return Ok(LifecyclePhase::ResolveComplete);
    }
    if operation.completion_preparation_attempt.is_some() {
        return Ok(LifecyclePhase::InspectCompletionAttempt);
    }
    // No preparation request was frozen by this coordinator. A fresh positive
    // completion inspection is safe, but absence still cannot advance it.
    Ok(LifecyclePhase::InspectTarget)
}
pub(crate) fn is_step(step: &TargetRuntimeStep) -> bool {
    matches!(
        step,
        TargetRuntimeStep::PrepareComplete(_)
            | TargetRuntimeStep::InspectCompletionAttempt(_)
            | TargetRuntimeStep::ResolveComplete(_)
            | TargetRuntimeStep::Start(TargetReplicaInput::CompletionAttemptStatus(_))
            | TargetRuntimeStep::Start(TargetReplicaInput::CompletionResolution(_))
    )
}
pub(crate) fn validate_step(
    state: &TenantState,
    operation: &RecoveryRecord,
    current: &LifecycleIntent,
    node: u64,
    request: &TargetRuntimeRequest,
    admission: bool,
) -> Result<()> {
    match &request.step {
        TargetRuntimeStep::PrepareComplete(input) => {
            completion::validate_original_intent(
                &origin(state, operation)?,
                &completion::completion_input(state, operation)?,
                current,
            )?;
            if input != &completion::completion_input(state, operation)? {
                return Err(conflict("preparation dispatch canonical input differs"));
            }
            if let Some(id) = operation.completion_preparation_attempt {
                let (_, first) = target_request(phase(state, operation, id)?)?;
                if first != request {
                    return Err(conflict("preparation retry changed its original dispatch"));
                }
            }
        }
        TargetRuntimeStep::Start(TargetReplicaInput::CompletionAttemptStatus(input))
        | TargetRuntimeStep::InspectCompletionAttempt(input) => {
            if **input != status_input(state, operation)? {
                return Err(conflict("preparation status input differs"));
            }
            input.validate(&origin(state, operation)?, current)?;
        }
        TargetRuntimeStep::Start(TargetReplicaInput::CompletionResolution(input))
        | TargetRuntimeStep::ResolveComplete(input) => {
            if **input != resolution_input(state, operation)? {
                return Err(conflict(
                    "terminal resolution lacks the retained exact preparation",
                ));
            }
            input.validate(&origin(state, operation)?, current)?;
            let evidence = phase(state, operation, operation.completion_preparation.unwrap())?;
            if evidence
                .resolved_revision
                .is_none_or(|revision| revision >= current.revision)
            {
                return Err(conflict(
                    "resolution Control intent precedes durable preparation evidence",
                ));
            }
        }
        _ => return Err(conflict("completion receiver operation differs")),
    }
    if admission {
        let startup = matches!(request.step, TargetRuntimeStep::Start(_));
        if startup && started_for(state, operation, node, current.request.command_id)? {
            return Err(conflict(
                "receiver voter already started under this exact phase",
            ));
        }
        if !startup && !quorum::all_started(state, operation, current.request.command_id)? {
            return Err(conflict(
                "receiver operation requires the exact started target quorum",
            ));
        }
    }
    Ok(())
}
pub(crate) fn validate_outcome(
    state: &TenantState,
    operation: &RecoveryRecord,
    prepared: &RecoveryPhaseRecord,
    response: &TargetRuntimeResponse,
) -> Result<()> {
    let (node, request) = target_request(prepared)?;
    let current = state
        .lifecycle_control
        .as_ref()
        .and_then(|c| c.intents.get(&request.command_id))
        .ok_or_else(|| conflict("completion receiver Control identity absent"))?;
    validate_step(state, operation, current, node, request, false)?;
    if response.command_id != request.command_id || response.node_id != node {
        return Err(conflict("completion receiver response route differs"));
    }
    match (&request.step, &response.outcome) {
        (TargetRuntimeStep::Start(input), TargetRuntimeOutcome::Started { origin_sha256 })
            if *origin_sha256 == input.quorum().origin_sha256 => {}
        (
            TargetRuntimeStep::PrepareComplete(input),
            TargetRuntimeOutcome::PreparedCompletion(signed),
        ) => {
            kasumi_serving::verify_target_completion_attempt(&origin(state, operation)?, signed)
                .map_err(|_| conflict("preparation signature or quorum differs"))?;
            if signed.observation.attempt.intent != *current
                || signed.observation.attempt.input != *input
                || signed.observation.observer_node_id != node
                || signed.observation.attempt.dispatch_not_after_ms != request.not_after_ms
            {
                return Err(conflict(
                    "preparation changed the original intent, cap or observer",
                ));
            }
        }
        (
            TargetRuntimeStep::InspectCompletionAttempt(input),
            TargetRuntimeOutcome::CompletionAttemptStatus(signed),
        ) => {
            kasumi_serving::verify_target_completion_attempt_status(input, signed)
                .map_err(|_| conflict("preparation status signature or quorum differs"))?;
            if signed.observation.status_intent != *current
                || signed.observation.observer_node_id != node
            {
                return Err(conflict("preparation status current identity differs"));
            }
            if original(state, operation)?.prepared_revision >= prepared.prepared_revision {
                return Err(conflict(
                    "status precedes its original preparation dispatch",
                ));
            }
        }
        (
            TargetRuntimeStep::ResolveComplete(input),
            TargetRuntimeOutcome::ResolvedCompletion(signed),
        ) => {
            kasumi_serving::verify_target_completion_resolution(&origin(state, operation)?, signed)
                .map_err(|_| conflict("terminal resolution signature or quorum differs"))?;
            if signed.observation.observation_intent != *current
                || signed.observation.fact.input != **input
                || signed.observation.observer_node_id != node
            {
                return Err(conflict("terminal resolution current identity differs"));
            }
            let first = phase(
                state,
                operation,
                operation
                    .completion_resolution_attempt
                    .ok_or_else(|| conflict("original terminal dispatch absent"))?,
            )?;
            let (_, first_request) = target_request(first)?;
            let original_intent = state
                .lifecycle_control
                .as_ref()
                .and_then(|c| c.intents.get(&first_request.command_id))
                .ok_or_else(|| conflict("original terminal Control intent absent"))?;
            if signed.observation.fact.resolution_intent != *original_intent
                || signed.observation.fact.dispatch_not_after_ms != first_request.not_after_ms
            {
                return Err(conflict(
                    "terminal resolution changed its original admitted deadline",
                ));
            }
        }
        _ => return Err(conflict("completion receiver response kind differs")),
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
    let input = match current.request.phase {
        LifecyclePhase::InspectCompletionAttempt => {
            TargetReplicaInput::CompletionAttemptStatus(Box::new(status_input(state, operation)?))
        }
        LifecyclePhase::ResolveComplete => {
            TargetReplicaInput::CompletionResolution(Box::new(resolution_input(state, operation)?))
        }
        _ => return Err(conflict("current receiver phase differs")),
    };
    let mut missing = None;
    for node in operation.voters.keys() {
        if !started_for(state, operation, *node, current.request.command_id)? {
            missing = Some(*node);
            break;
        }
    }
    let (node_id, step) = match missing {
        Some(node) => (node, TargetRuntimeStep::Start(input)),
        None => (
            *operation
                .voters
                .keys()
                .next()
                .ok_or_else(|| conflict("receiver voters absent"))?,
            match input {
                TargetReplicaInput::CompletionAttemptStatus(input) => {
                    TargetRuntimeStep::InspectCompletionAttempt(input)
                }
                TargetReplicaInput::CompletionResolution(input) => {
                    TargetRuntimeStep::ResolveComplete(input)
                }
                _ => unreachable!(),
            },
        ),
    };
    Ok(RecoveryDispatch::Target {
        node_id,
        request: Box::new(TargetRuntimeRequest {
            tenant: operation.request.tenant.clone(),
            command_id: current.request.command_id,
            not_after_ms: now
                .checked_add(operation.request.phase_timeout_ms)
                .ok_or_else(|| conflict("receiver deadline overflow"))?
                .min(expires)
                .min(current.original_credential_expires_at_ms),
            step,
        }),
    })
}

pub(crate) fn validate_link(
    state: &TenantState,
    operation: &RecoveryRecord,
    original: &RecoveryPhaseRecord,
    linked_id: Uuid,
    terminal_link: bool,
) -> Result<()> {
    let linked = phase(state, operation, linked_id)?;
    let (_, old_request) = target_request(original)?;
    let Some(RecoveryDispatchOutcome::Target(response)) = &linked.outcome else {
        return Err(conflict(
            "receiver resolution lacks its retained positive observation",
        ));
    };
    if linked.prepared_revision <= original.prepared_revision
        || linked.resolved_revision != original.resolved_revision
    {
        return Err(conflict("receiver resolution phase is not causally later"));
    }
    validate_outcome(state, operation, linked, response)?;
    match (&old_request.step, &response.outcome, terminal_link) {
        (
            TargetRuntimeStep::PrepareComplete(input),
            TargetRuntimeOutcome::CompletionAttemptStatus(signed),
            false,
        ) if signed.observation.attempt.input == *input
            && signed.observation.attempt.intent.request.command_id == old_request.command_id
            && signed.observation.attempt.dispatch_not_after_ms == old_request.not_after_ms => {}
        (
            TargetRuntimeStep::Complete(input),
            TargetRuntimeOutcome::ResolvedCompletion(signed),
            true,
        ) if signed.observation.fact.input.attempt.input == *input
            && signed
                .observation
                .fact
                .input
                .attempt
                .intent
                .request
                .command_id
                == old_request.command_id
            && signed.observation.fact.input.attempt.dispatch_not_after_ms
                == old_request.not_after_ms => {}
        _ => {
            return Err(conflict(
                "receiver resolution substituted its original dispatch",
            ));
        }
    }
    Ok(())
}
pub(crate) fn resolve_prior(
    state: &mut TenantState,
    operation: &RecoveryRecord,
    observed: &RecoveryPhaseRecord,
    response: &TargetRuntimeResponse,
) -> Result<()> {
    let (id, terminal_link) = match &response.outcome {
        TargetRuntimeOutcome::CompletionAttemptStatus(_) => {
            (operation.completion_preparation_attempt, false)
        }
        TargetRuntimeOutcome::ResolvedCompletion(_) => (operation.completion_attempt, true),
        _ => return Ok(()),
    };
    let Some(id) = id else {
        return Ok(());
    };
    let mut previous = phase(state, operation, id)?.clone();
    if previous.outcome.is_some() {
        return Ok(());
    }
    previous.resolved_revision = Some(state.revision);
    validate_link(
        state,
        operation,
        &previous,
        observed.phase_id,
        terminal_link,
    )?;
    previous.outcome = Some(if terminal_link {
        RecoveryDispatchOutcome::CompletionTerminal {
            resolution_phase: observed.phase_id,
        }
    } else {
        RecoveryDispatchOutcome::PreparationObserved {
            status_phase: observed.phase_id,
        }
    });
    previous.validate()?;
    state
        .recovery_control
        .phases
        .insert(phase_key(operation.request.operation_id, id), previous);
    Ok(())
}
pub(crate) fn validate_progress(state: &TenantState, operation: &RecoveryRecord) -> Result<()> {
    if operation.completion_preparation_attempt.is_some() {
        status_input(state, operation)?;
    }
    if let Some(id) = operation.completion_preparation {
        let evidence = phase(state, operation, id)?;
        if evidence.resolved_revision.is_none()
            || evidence.prepared_revision < original(state, operation)?.prepared_revision
        {
            return Err(conflict(
                "preparation progress precedes its original dispatch",
            ));
        }
        preparation(state, operation)?;
    }
    if let Some(id) = operation.completion_resolution_attempt {
        let retained = phase(state, operation, id)?;
        let (_, request) = target_request(retained)?;
        let TargetRuntimeStep::ResolveComplete(input) = &request.step else {
            return Err(conflict("original terminal resolution step differs"));
        };
        if **input != resolution_input(state, operation)? {
            return Err(conflict("terminal resolution input changed"));
        }
        let evidence = phase(state, operation, operation.completion_preparation.unwrap())?;
        if evidence
            .resolved_revision
            .is_none_or(|revision| revision >= retained.prepared_revision)
        {
            return Err(conflict(
                "terminal dispatch precedes persisted preparation evidence",
            ));
        }
    }
    if operation.completion_terminal.is_some() {
        let terminal = terminal(state, operation)?;
        if matches!(terminal.terminal, TargetCompletionTerminal::Sealed)
            && (operation.completion.is_some()
                || operation.activation_attempt.is_some()
                || operation.activation.is_some())
        {
            return Err(conflict("sealed completion cannot reach activation"));
        }
    }
    if let Some(id) = operation.completion_attempt {
        let (_, request) = target_request(phase(state, operation, id)?)?;
        let first = status_input(state, operation)?;
        if request.not_after_ms != first.original_dispatch_not_after_ms {
            return Err(conflict("Complete changed its preparation dispatch cap"));
        }
        preparation(state, operation)?;
        let evidence = phase(state, operation, operation.completion_preparation.unwrap())?;
        let completion_dispatch = phase(state, operation, id)?;
        if evidence
            .resolved_revision
            .is_none_or(|revision| revision >= completion_dispatch.prepared_revision)
        {
            return Err(conflict(
                "Complete dispatch precedes persisted preparation evidence",
            ));
        }
    }
    Ok(())
}
/// A separately verified positive terminal must match the later activation
/// inspection exactly. A seal can never enter the existing activation path.
pub(crate) fn validate_inspected_terminal(
    state: &TenantState,
    operation: &RecoveryRecord,
    completion: &TargetCompletionFact,
) -> Result<()> {
    if operation.completion_terminal.is_none() {
        return Ok(());
    }
    match &terminal(state, operation)?.terminal {
        TargetCompletionTerminal::Committed(expected) if expected.as_ref() == completion => Ok(()),
        _ => Err(conflict(
            "positive completion inspection disagrees with its permanent terminal",
        )),
    }
}

#[cfg(test)]
#[path = "recovery_receiver_tests.rs"]
mod tests;
