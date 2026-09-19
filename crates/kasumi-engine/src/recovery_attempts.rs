//! Bounded current completion cursor and exact historical attempt scopes.
//! Only a positive sealed receiver fact permits a different logical Complete.
use super::*;
use std::borrow::Cow;

pub(crate) fn scope(operation: &RecoveryRecord) -> Option<RecoveryCompletionScope> {
    operation
        .completion_intent
        .map(|intent| RecoveryCompletionScope {
            intent,
            predecessor: operation.completion_predecessor,
        })
}

fn sealed_fact<'a>(
    state: &'a TenantState,
    operation: &RecoveryRecord,
    id: Uuid,
) -> Result<&'a TargetCompletionResolutionFact> {
    let retained = phase(state, operation, id)?;
    let Some(RecoveryDispatchOutcome::Target(response)) = &retained.outcome else {
        return Err(conflict(
            "completion predecessor lacks a positive native outcome",
        ));
    };
    let fact = receiver::terminal_response(response)?;
    let selected = retained
        .completion_scope
        .as_ref()
        .ok_or_else(|| conflict("completion predecessor lacks its exact attempt scope"))?;
    if retained.phase != RecoveryPhase::Complete
        || retained.resolved_revision.is_none()
        || fact.input.attempt.origin != origin(state, operation)?
        || fact.input.attempt.intent.request.command_id != selected.intent
    {
        return Err(conflict(
            "completion predecessor changed target, scope or durable identity",
        ));
    }
    fact.sealed_reference()?;
    Ok(fact)
}

pub(crate) fn predecessor(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<Option<TargetCompletionResolutionReference>> {
    let Some(id) = operation.completion_predecessor else {
        return Ok(None);
    };
    let retained = phase(state, operation, id)?;
    let selected = retained
        .completion_scope
        .as_ref()
        .ok_or_else(|| conflict("completion predecessor scope absent"))?;
    let actual_head = state
        .recovery_control
        .operations
        .get(&operation.request.operation_id.to_string());
    let current = actual_head.is_some_and(|head| {
        scope(head).as_ref() == Some(selected) && head.completion_terminal == Some(id)
    });
    let archived = state
        .recovery_control
        .completion_history
        .get(&selected.intent.to_string())
        .is_some_and(|history| {
            history.operation_id == operation.request.operation_id
                && history.scope == *selected
                && history.terminal == id
        });
    if (!current && !archived) || operation.completion_intent == Some(selected.intent) {
        return Err(conflict(
            "completion predecessor is not the exact closed original cursor",
        ));
    }
    Ok(Some(sealed_fact(state, operation, id)?.sealed_reference()?))
}

pub(crate) fn require_successor(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<TargetCompletionResolutionReference> {
    if operation.phase != RecoveryPhase::Complete
        || operation.completion_intent.is_none()
        || operation.completion.is_some()
    {
        return Err(conflict(
            "completion successor requires an unfinished original attempt",
        ));
    }
    receiver::terminal(state, operation)?.sealed_reference()
}

pub(crate) fn next_input(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<TargetCompletionInput> {
    let predecessor = if operation.completion_intent.is_some() {
        Some(require_successor(state, operation)?)
    } else {
        predecessor(state, operation)?
    };
    Ok(TargetCompletionInput {
        quorum: quorum_input(state, operation)?,
        predecessor,
    })
}

pub(crate) fn prepared_scope(
    state: &TenantState,
    operation: &RecoveryRecord,
    id: Uuid,
    input: &RecoveryDispatch,
) -> Result<Option<RecoveryCompletionScope>> {
    if operation.phase != RecoveryPhase::Complete {
        return Ok(None);
    }
    if matches!(input, RecoveryDispatch::ControlIntent(request) if request.phase == LifecyclePhase::Complete)
    {
        let predecessor = if operation.completion_intent.is_some() {
            require_successor(state, operation)?;
            operation.completion_terminal
        } else {
            operation.completion_predecessor
        };
        Ok(Some(RecoveryCompletionScope {
            intent: id,
            predecessor,
        }))
    } else {
        Ok(Some(scope(operation).ok_or_else(|| {
            conflict("Complete dispatch lacks its original scope")
        })?))
    }
}

fn historical_view(
    operation: &RecoveryRecord,
    history: &RecoveryCompletionHistory,
) -> RecoveryRecord {
    let mut view = operation.clone();
    view.phase = RecoveryPhase::Complete;
    view.pending_phase = None;
    view.current_intent = Some(history.current_intent);
    view.completion_intent = Some(history.scope.intent);
    view.completion_predecessor = history.scope.predecessor;
    view.completion_preparation_attempt = Some(history.preparation_attempt);
    view.completion_preparation = Some(history.preparation);
    view.completion_resolution_attempt = Some(history.resolution_attempt);
    view.completion_terminal = Some(history.terminal);
    view.completion_attempt = history.attempted_completion;
    view.completion = None;
    // Later global activation cannot rewrite a historical sealed context.
    view.retirement = None;
    view.source_fence = None;
    view.activation_attempt = None;
    view.activation = None;
    view.route_publication = None;
    view.target_stop = None;
    view
}

pub(crate) fn for_phase<'a>(
    state: &TenantState,
    operation: &'a RecoveryRecord,
    retained: &RecoveryPhaseRecord,
) -> Result<Cow<'a, RecoveryRecord>> {
    if retained.phase != RecoveryPhase::Complete {
        if retained.completion_scope.is_some() {
            return Err(conflict("non-Complete phase has completion scope"));
        }
        return Ok(Cow::Borrowed(operation));
    }
    let selected = retained
        .completion_scope
        .as_ref()
        .ok_or_else(|| conflict("Complete phase lacks an exact attempt scope"))?;
    selected.validate()?;
    let birth = matches!(&retained.input, RecoveryDispatch::ControlIntent(request) if request.phase == LifecyclePhase::Complete);
    if birth {
        if selected.intent != retained.phase_id {
            return Err(conflict("completion birth substituted its original intent"));
        }
    } else {
        let original = phase(state, operation, selected.intent)?;
        if original.completion_scope.as_ref() != Some(selected)
            || original.sequence >= retained.sequence
            || !matches!((&original.input, &original.outcome),
                (RecoveryDispatch::ControlIntent(request), Some(RecoveryDispatchOutcome::ControlIntent(_)))
                    if request.phase == LifecyclePhase::Complete)
        {
            return Err(conflict(
                "completion phase belongs to another logical original",
            ));
        }
    }
    if scope(operation).as_ref() == Some(selected) {
        return Ok(Cow::Borrowed(operation));
    }
    if let Some(history) = state
        .recovery_control
        .completion_history
        .get(&selected.intent.to_string())
    {
        if history.operation_id != operation.request.operation_id || history.scope != *selected {
            return Err(conflict("historical completion context differs"));
        }
        return Ok(Cow::Owned(historical_view(operation, history)));
    }
    // A prepared birth has no committed Control intent yet. Validate its exact
    // linked input, without installing a new active cursor or refreshing it.
    let stopped = operation.stop_request.is_some()
        && matches!(
            operation.phase,
            RecoveryPhase::StopActivation
                | RecoveryPhase::StopTarget
                | RecoveryPhase::Cleanup
                | RecoveryPhase::Stopped
        );
    if birth
        && retained.outcome.is_none()
        && (operation.pending_phase == Some(retained.phase_id) || stopped)
    {
        // Stop can clear a pending birth before Control commits it. Its input
        // remains historical, with no installed successor and no renewed grant.
        let mut original_context = operation.clone();
        original_context.phase = RecoveryPhase::Complete;
        if prepared_scope(state, &original_context, retained.phase_id, &retained.input)?.as_ref()
            != Some(selected)
        {
            return Err(conflict(
                "prepared completion birth changed its predecessor",
            ));
        }
        let mut view = operation.clone();
        view.completion_intent = None;
        view.completion_predecessor = selected.predecessor;
        view.completion_preparation_attempt = None;
        view.completion_preparation = None;
        view.completion_resolution_attempt = None;
        view.completion_terminal = None;
        view.completion_attempt = None;
        return Ok(Cow::Owned(view));
    }
    Err(conflict(
        "completion phase has no exact active or closed context",
    ))
}

pub(crate) fn install(
    state: &mut TenantState,
    operation: &mut RecoveryRecord,
    prepared: &RecoveryPhaseRecord,
) -> Result<()> {
    let expected = prepared_scope(state, operation, prepared.phase_id, &prepared.input)?
        .ok_or_else(|| conflict("completion birth lacks its scope"))?;
    if prepared.completion_scope.as_ref() != Some(&expected) {
        return Err(conflict(
            "committed completion birth changed its exact predecessor",
        ));
    }
    if let Some(original) = scope(operation) {
        require_successor(state, operation)?;
        let required = |id: Option<Uuid>| {
            id.ok_or_else(|| conflict("sealed completion history is incomplete"))
        };
        let history = RecoveryCompletionHistory {
            operation_id: operation.request.operation_id,
            scope: original,
            current_intent: required(operation.current_intent)?,
            preparation_attempt: required(operation.completion_preparation_attempt)?,
            preparation: required(operation.completion_preparation)?,
            resolution_attempt: required(operation.completion_resolution_attempt)?,
            terminal: required(operation.completion_terminal)?,
            attempted_completion: operation.completion_attempt,
            successor_intent: prepared.phase_id,
        };
        history.validate()?;
        let key = history.scope.intent.to_string();
        if state.recovery_control.completion_history.contains_key(&key) {
            return Err(conflict(
                "sealed completion already has a permanent successor",
            ));
        }
        state
            .recovery_control
            .completion_history
            .insert(key, history);
    }
    operation.current_intent = Some(prepared.phase_id);
    operation.completion_intent = Some(prepared.phase_id);
    operation.completion_predecessor = expected.predecessor;
    operation.completion_preparation_attempt = None;
    operation.completion_preparation = None;
    operation.completion_resolution_attempt = None;
    operation.completion_terminal = None;
    operation.completion_attempt = None;
    Ok(())
}

pub(crate) fn validate_chain_link(
    state: &TenantState,
    operation: &RecoveryRecord,
    retained: &RecoveryPhaseRecord,
    expected: &mut Option<Uuid>,
) -> Result<()> {
    if !matches!((&retained.input, &retained.outcome),
        (RecoveryDispatch::ControlIntent(request), Some(RecoveryDispatchOutcome::ControlIntent(_)))
            if request.phase == LifecyclePhase::Complete)
    {
        return Ok(());
    }
    let selected = retained
        .completion_scope
        .as_ref()
        .ok_or_else(|| conflict("completion chain birth scope absent"))?;
    if *expected != Some(retained.phase_id) || selected.intent != retained.phase_id {
        return Err(conflict(
            "completion attempt chain forked or skipped a committed birth",
        ));
    }
    *expected = selected
        .predecessor
        .map(|id| {
            let previous = phase(state, operation, id)?;
            if previous.sequence >= retained.sequence
                || previous
                    .resolved_revision
                    .is_none_or(|revision| revision >= retained.prepared_revision)
            {
                return Err(conflict("completion birth precedes its sealed original"));
            }
            sealed_fact(state, operation, id)?;
            Ok(previous
                .completion_scope
                .as_ref()
                .ok_or_else(|| conflict("predecessor scope absent"))?
                .intent)
        })
        .transpose()?;
    Ok(())
}

pub(crate) fn validate_history(state: &TenantState) -> Result<()> {
    for (key, history) in &state.recovery_control.completion_history {
        history.validate()?;
        let operation = state
            .recovery_control
            .operations
            .get(&history.operation_id.to_string())
            .ok_or_else(|| conflict("closed completion history has no operation"))?;
        if *key != history.scope.intent.to_string()
            || operation.completion_intent == Some(history.scope.intent)
        {
            return Err(conflict(
                "closed completion history substituted its key or active cursor",
            ));
        }
        let view = historical_view(operation, history);
        let original = phase(state, operation, history.scope.intent)?;
        let next = phase(state, operation, history.successor_intent)?;
        let next_scope = RecoveryCompletionScope {
            intent: history.successor_intent,
            predecessor: Some(history.terminal),
        };
        if next.completion_scope.as_ref() != Some(&next_scope)
            || !matches!((&next.input, &next.outcome),
                (RecoveryDispatch::ControlIntent(request), Some(RecoveryDispatchOutcome::ControlIntent(_)))
                    if request.phase == LifecyclePhase::Complete)
        {
            return Err(conflict(
                "closed completion lacks its exact committed successor",
            ));
        }
        for id in [
            Some(history.scope.intent),
            Some(history.current_intent),
            Some(history.preparation_attempt),
            Some(history.preparation),
            Some(history.resolution_attempt),
            Some(history.terminal),
            history.attempted_completion,
        ]
        .into_iter()
        .flatten()
        {
            let row = phase(state, operation, id)?;
            if row.completion_scope.as_ref() != Some(&history.scope)
                || row.sequence < original.sequence
                || row.sequence >= next.sequence
            {
                return Err(conflict(
                    "closed completion cursor contains a foreign or later phase",
                ));
            }
        }
        completion::validate_original_intent(
            &origin(state, operation)?,
            &completion::completion_input(state, &view)?,
            intent(state, operation, history.scope.intent)?,
        )?;
        receiver::validate_progress(state, &view)?;
        let terminal = receiver::terminal(state, &view)?;
        terminal.sealed_reference()?;
        if next.prepared_revision
            <= phase(state, operation, history.terminal)?
                .resolved_revision
                .ok_or_else(|| conflict("closed completion terminal is unresolved"))?
        {
            return Err(conflict(
                "successor birth predates durable predecessor resolution",
            ));
        }
    }
    Ok(())
}

/// Historical cursors are immutable. A later snapshot may rotate the active
/// cursor only after retaining this exact original's positively sealed closure.
pub(crate) fn cursor_advanced(
    previous: &TenantState,
    incoming: &TenantState,
    old: &RecoveryRecord,
    new: &RecoveryRecord,
) -> Result<bool> {
    if let Some(id) = new.completion_intent {
        if phase(incoming, new, id)?.completion_scope != scope(new) {
            return Err(conflict(
                "snapshot current completion scope differs from its committed birth",
            ));
        }
    }
    if old.completion_intent == new.completion_intent {
        if old.completion_predecessor != new.completion_predecessor {
            return Err(conflict(
                "snapshot substituted original completion predecessor",
            ));
        }
        return Ok(false);
    }
    let Some(original) = old.completion_intent else {
        return Ok(false);
    };
    let next = new
        .completion_intent
        .ok_or_else(|| conflict("snapshot removed current completion intent"))?;
    let archived = incoming
        .recovery_control
        .completion_history
        .get(&original.to_string())
        .ok_or_else(|| conflict("snapshot replaced completion without its sealed history"))?;
    if archived.operation_id != old.request.operation_id
        || Some(archived.scope.clone()) != scope(old)
        || phase(incoming, new, next)?.sequence
            < phase(incoming, new, archived.successor_intent)?.sequence
    {
        return Err(conflict(
            "snapshot completion continuation is not the original sealed chain",
        ));
    }
    for (prior, retained) in [
        (
            old.completion_preparation_attempt,
            archived.preparation_attempt,
        ),
        (old.completion_preparation, archived.preparation),
        (
            old.completion_resolution_attempt,
            archived.resolution_attempt,
        ),
        (old.completion_terminal, archived.terminal),
    ] {
        if prior.is_some_and(|id| id != retained) {
            return Err(conflict(
                "snapshot altered closed original completion progress",
            ));
        }
    }
    if let Some(id) = old.completion_attempt {
        let retained = archived
            .attempted_completion
            .ok_or_else(|| conflict("snapshot erased original Complete dispatch"))?;
        if phase(incoming, new, retained)?.sequence < phase(previous, old, id)?.sequence {
            return Err(conflict(
                "snapshot regressed archived original Complete dispatch",
            ));
        }
    }
    Ok(true)
}

pub(crate) fn history_unchanged(previous: &TenantState, incoming: &TenantState) -> Result<()> {
    for (key, old) in &previous.recovery_control.completion_history {
        if incoming.recovery_control.completion_history.get(key) != Some(old) {
            return Err(conflict(
                "snapshot removed or changed immutable closed completion history",
            ));
        }
    }
    Ok(())
}
