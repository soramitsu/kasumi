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
pub(crate) fn terminal_status_input(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<TargetCompletionTerminalStatusInput> {
    let original = phase(
        state,
        operation,
        operation
            .completion_resolution_attempt
            .ok_or_else(|| conflict("original resolver dispatch absent"))?,
    )?;
    let (_, request) = target_request(original)?;
    let TargetRuntimeStep::ResolveComplete(input) = &request.step else {
        return Err(conflict("original resolver step differs"));
    };
    if **input != resolution_input(state, operation)? {
        return Err(conflict("original resolver input differs"));
    }
    let original_intent = state
        .lifecycle_control
        .as_ref()
        .and_then(|c| c.intents.get(&request.command_id))
        .ok_or_else(|| conflict("original resolver Control identity absent"))?;
    let value = TargetCompletionTerminalStatusInput {
        original_intent: original_intent.clone(),
        original_input: *input.clone(),
        original_dispatch_not_after_ms: request.not_after_ms,
    };
    value.digest()?;
    Ok(value)
}
pub(crate) fn terminal_response(
    response: &TargetRuntimeResponse,
) -> Result<&TargetCompletionResolutionFact> {
    match &response.outcome {
        TargetRuntimeOutcome::ResolvedCompletion(signed) => Ok(&signed.observation.fact),
        TargetRuntimeOutcome::CompletionTerminalStatus(signed) => Ok(&signed.observation.fact),
        _ => Err(conflict("terminal evidence response kind differs")),
    }
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
    let fact = terminal_response(response)?;
    if fact.input != resolution_input(state, operation)? {
        return Err(conflict("terminal completion changed the prepared attempt"));
    }
    Ok(fact)
}
pub(crate) fn fresh_phase(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<LifecyclePhase> {
    if operation.completion_terminal.is_some() {
        return match &terminal(state, operation)?.terminal {
            TargetCompletionTerminal::Committed(_) => Ok(LifecyclePhase::InspectTarget),
            TargetCompletionTerminal::Sealed => Ok(LifecyclePhase::Complete),
        };
    }
    if operation.completion_resolution_attempt.is_some() {
        return Ok(LifecyclePhase::InspectCompletionResolution);
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
pub(crate) fn validate_complete_dispatch(
    state: &TenantState,
    operation: &RecoveryRecord,
    request: &TargetRuntimeRequest,
) -> Result<()> {
    let attempt = preparation(state, operation)?;
    let TargetRuntimeStep::Complete(input) = &request.step else {
        return Err(conflict("original completion dispatch kind differs"));
    };
    if request.command_id != attempt.intent.request.command_id
        || *input != attempt.input
        || request.not_after_ms != attempt.dispatch_not_after_ms
    {
        return Err(conflict(
            "Complete dispatch changed its exact prepared input or original deadline",
        ));
    }
    Ok(())
}
pub(crate) fn is_step(step: &TargetRuntimeStep) -> bool {
    matches!(
        step,
        TargetRuntimeStep::PrepareComplete(_)
            | TargetRuntimeStep::InspectCompletionAttempt(_)
            | TargetRuntimeStep::ResolveComplete(_)
            | TargetRuntimeStep::InspectCompletionResolution(_)
            | TargetRuntimeStep::Start(TargetReplicaInput::CompletionTerminalStatus(_))
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
        TargetRuntimeStep::Start(TargetReplicaInput::CompletionTerminalStatus(input))
        | TargetRuntimeStep::InspectCompletionResolution(input) => {
            if **input != terminal_status_input(state, operation)? {
                return Err(conflict("terminal status changed its original resolver"));
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
        if !startup {
            quorum::require_eligible_observer(state, operation, current.request.command_id, node)?;
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
            TargetRuntimeStep::InspectCompletionResolution(input),
            TargetRuntimeOutcome::CompletionTerminalStatus(signed),
        ) => {
            kasumi_serving::verify_target_completion_terminal_status(input, signed)
                .map_err(|_| conflict("terminal-only status signature or quorum differs"))?;
            if signed.observation.status_intent != *current
                || signed.observation.observer_node_id != node
            {
                return Err(conflict("terminal-only status current identity differs"));
            }
            let original = phase(
                state,
                operation,
                operation.completion_resolution_attempt.unwrap(),
            )?;
            if original.prepared_revision >= prepared.prepared_revision {
                return Err(conflict("terminal-only status precedes original resolver"));
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
        LifecyclePhase::InspectCompletionResolution => {
            TargetReplicaInput::CompletionTerminalStatus(Box::new(terminal_status_input(
                state, operation,
            )?))
        }
        _ => return Err(conflict("current receiver phase differs")),
    };
    let (node_id, startup) =
        quorum::established_destination(state, operation, current.request.command_id)?;
    let step = if startup {
        TargetRuntimeStep::Start(input)
    } else {
        match input {
            TargetReplicaInput::CompletionAttemptStatus(input) => {
                TargetRuntimeStep::InspectCompletionAttempt(input)
            }
            TargetReplicaInput::CompletionResolution(input) => {
                TargetRuntimeStep::ResolveComplete(input)
            }
            TargetReplicaInput::CompletionTerminalStatus(input) => {
                TargetRuntimeStep::InspectCompletionResolution(input)
            }
            _ => unreachable!(),
        }
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
    if terminal_link {
        let TargetRuntimeStep::Complete(input) = &old_request.step else {
            return Err(conflict("terminal link original operation differs"));
        };
        let fact = terminal_response(response)?;
        if fact.input.attempt.input != *input
            || fact.input.attempt.intent.request.command_id != old_request.command_id
            || fact.input.attempt.dispatch_not_after_ms != old_request.not_after_ms
        {
            return Err(conflict("terminal link changed original Complete dispatch"));
        }
    } else {
        let TargetRuntimeStep::PrepareComplete(input) = &old_request.step else {
            return Err(conflict("preparation link original operation differs"));
        };
        let attempt = match &response.outcome {
            TargetRuntimeOutcome::CompletionAttemptStatus(signed) => &signed.observation.attempt,
            TargetRuntimeOutcome::PreparedCompletion(signed) => &signed.observation.attempt,
            _ => {
                return Err(conflict(
                    "preparation link outcome is not positive evidence",
                ));
            }
        };
        if attempt.input != *input
            || attempt.intent.request.command_id != old_request.command_id
            || attempt.dispatch_not_after_ms != old_request.not_after_ms
        {
            return Err(conflict("preparation link changed original dispatch"));
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
        TargetRuntimeOutcome::CompletionAttemptStatus(_)
        | TargetRuntimeOutcome::PreparedCompletion(_) => {
            (operation.completion_preparation_attempt, false)
        }
        TargetRuntimeOutcome::ResolvedCompletion(_)
        | TargetRuntimeOutcome::CompletionTerminalStatus(_) => (operation.completion_attempt, true),
        _ => return Ok(()),
    };
    let Some(id) = id else {
        return Ok(());
    };
    if id == observed.phase_id {
        return Ok(());
    }
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

pub(crate) fn validate_resolver_link(
    state: &TenantState,
    operation: &RecoveryRecord,
    original: &RecoveryPhaseRecord,
    status_phase: Uuid,
) -> Result<()> {
    let linked = phase(state, operation, status_phase)?;
    let (_, request) = target_request(original)?;
    let TargetRuntimeStep::ResolveComplete(input) = &request.step else {
        return Err(conflict("terminal observation original resolver differs"));
    };
    let Some(RecoveryDispatchOutcome::Target(response)) = &linked.outcome else {
        return Err(conflict("positive terminal observation absent"));
    };
    let TargetRuntimeOutcome::CompletionTerminalStatus(signed) = &response.outcome else {
        return Err(conflict("terminal observation kind differs"));
    };
    if linked.prepared_revision <= original.prepared_revision
        || linked.resolved_revision != original.resolved_revision
        || signed.observation.input.original_input != **input
        || signed.observation.input.original_intent.request.command_id != request.command_id
        || signed.observation.input.original_dispatch_not_after_ms != request.not_after_ms
    {
        return Err(conflict(
            "terminal observation changed original resolver or causal order",
        ));
    }
    validate_outcome(state, operation, linked, response)
}
pub(crate) fn resolve_resolver(
    state: &mut TenantState,
    operation: &RecoveryRecord,
    observed: &RecoveryPhaseRecord,
) -> Result<()> {
    let id = operation
        .completion_resolution_attempt
        .ok_or_else(|| conflict("original resolver absent"))?;
    let mut original = phase(state, operation, id)?.clone();
    if original.outcome.is_some() {
        return Ok(());
    }
    original.resolved_revision = Some(state.revision);
    validate_resolver_link(state, operation, &original, observed.phase_id)?;
    original.outcome = Some(RecoveryDispatchOutcome::TerminalObserved {
        status_phase: observed.phase_id,
    });
    original.validate()?;
    state
        .recovery_control
        .phases
        .insert(phase_key(operation.request.operation_id, id), original);
    Ok(())
}

#[cfg(test)]
#[path = "recovery_receiver_tests.rs"]
mod tests;
