use super::*;
use crate::target_completion_machine::{CompletionMachine, ResolutionApply};
use crate::target_resolution::View;

fn authorize(
    state: &TenantState,
    position: &kasumi_raft::AppliedEntryContext,
    authorization: &PreparedTargetAuthorization,
    phase: LifecyclePhase,
    digest: &str,
    engine: &TenantEngine,
) -> Result<TargetExecutionState> {
    let entry = state
        .target_lifecycle
        .get(&state.incarnation)
        .ok_or_else(|| error(ErrorCode::Forbidden, "installed physical target required"))?;
    let serving = engine
        .access
        .get()
        .and_then(|access| access.serving_gate())
        .ok_or_else(|| error(ErrorCode::Forbidden, "installed target issuer required"))?;
    let trust = serving
        .authority()
        .map_err(|_| error(ErrorCode::Sealed, "target issuer unavailable"))?;
    authorization.verify(
        &trust,
        &entry.origin,
        phase,
        digest,
        position.log_id.leader_id.node_id,
    )?;
    let membership = position.membership.membership();
    if membership.get_joint_config() != &vec![entry.origin.input.voters.keys().copied().collect()]
        || membership.nodes().count() != entry.origin.input.voters.len()
        || membership.nodes().any(|(id, node)| {
            entry
                .origin
                .input
                .voters
                .get(id)
                .is_none_or(|peer| node.addr != peer.endpoint)
        })
    {
        return Err(error(
            ErrorCode::Conflict,
            "actual target quorum differs from original placement",
        ));
    }
    if state.retired {
        return Err(error(
            ErrorCode::Conflict,
            "retired target cannot admit completion maintenance",
        ));
    }
    Ok(entry.clone())
}
fn point(view: &View, key: &str) -> Result<Option<TargetResolutionRecord>> {
    view.get(key)
        .map(|row| row.map(|row| row.record))
        .map_err(|_| error(ErrorCode::Corruption, "target terminal point lookup failed"))
}
fn completion(
    view: &View,
    origin: &TargetOrigin,
    command: uuid::Uuid,
) -> Result<Option<TargetCompletionResolutionFact>> {
    match point(
        view,
        &format!("completion/{}/{command}", origin.input.target_incarnation),
    )? {
        Some(TargetResolutionRecord::Completion(fact)) => Ok(Some(*fact)),
        None => Ok(None),
        _ => Err(error(
            ErrorCode::Corruption,
            "target completion point kind differs",
        )),
    }
}
fn at(position: &kasumi_raft::AppliedEntryContext) -> TargetCommitPosition {
    TargetCommitPosition {
        index: position.log_id.index,
        term: position.log_id.leader_id.term,
        leader_node_id: position.log_id.leader_id.node_id,
        command_sha256: position.command_sha256.clone(),
    }
}
pub(in crate::state) fn history_reserve_fits(state: &TenantState) -> Result<bool> {
    let bytes = crate::accounting::encoded_len(&state.target_lifecycle)? as u64;
    Ok(bytes
        .checked_add(crate::accounting::target_completion_reserve(state))
        .is_some_and(|bytes| bytes <= MAX_TARGET_HISTORY_BYTES as u64))
}
pub(super) fn prepare(
    state: &mut TenantState,
    view: &View,
    position: &kasumi_raft::AppliedEntryContext,
    authorization: &PreparedTargetAuthorization,
    input: &TargetCompletionInput,
    engine: &TenantEngine,
) -> Result<TargetCompletionAttempt> {
    let entry = authorize(
        state,
        position,
        authorization,
        LifecyclePhase::Complete,
        &input.digest()?,
        engine,
    )?;
    kasumi_serving::verify_target_materializations(&entry.origin, &input.quorum.materialized)
        .map_err(|_| {
            error(
                ErrorCode::Forbidden,
                "exact native target materialization proofs required",
            )
        })?;
    let terminal = completion(
        view,
        &entry.origin,
        authorization
            .grant
            .claims
            .commitment
            .intent
            .request
            .command_id,
    )?;
    let predecessor = input
        .predecessor
        .as_ref()
        .map(|reference| completion(view, &entry.origin, reference.original_command_id))
        .transpose()?
        .flatten();
    let attempt = TargetCompletionAttempt {
        origin: entry.origin.clone(),
        intent: authorization.grant.claims.commitment.intent.clone(),
        input: input.clone(),
        dispatch_not_after_ms: authorization.dispatch_not_after_ms,
        admitted_at_ms: authorization.admitted_at_ms,
        revision: state.revision,
        position: at(position),
        reserved_terminal_bytes: TARGET_COMPLETION_RESERVE_BYTES,
        reserved_audit_bytes: TARGET_COMPLETION_AUDIT_RESERVE_BYTES,
    };
    let mut machine = CompletionMachine {
        origin: &entry.origin,
        head: state
            .target_completion_head
            .as_mut()
            .ok_or_else(|| error(ErrorCode::Corruption, "target completion head absent"))?,
        completion: entry.completion.as_ref(),
        terminal_bytes: state.target_resolution_head.encoded_bytes,
        maximum_bytes: state.limits.max_target_resolution_bytes,
    };
    machine.prepare(attempt, predecessor.as_ref(), terminal.as_ref())
}
pub(super) fn require_active(
    state: &TenantState,
    view: &View,
    authorization: &PreparedTargetAuthorization,
    input: &TargetCompletionInput,
) -> Result<()> {
    let entry = state
        .target_lifecycle
        .get(&state.incarnation)
        .ok_or_else(|| error(ErrorCode::Corruption, "target origin absent"))?;
    let terminal = completion(
        view,
        &entry.origin,
        authorization
            .grant
            .claims
            .commitment
            .intent
            .request
            .command_id,
    )?;
    let mut head = state
        .target_completion_head
        .clone()
        .ok_or_else(|| error(ErrorCode::Corruption, "target completion head absent"))?;
    CompletionMachine {
        origin: &entry.origin,
        head: &mut head,
        completion: entry.completion.as_ref(),
        terminal_bytes: state.target_resolution_head.encoded_bytes,
        maximum_bytes: state.limits.max_target_resolution_bytes,
    }
    .require_active(
        &authorization.grant.claims.commitment.intent,
        input,
        authorization.dispatch_not_after_ms,
        terminal.as_ref(),
    )?;
    Ok(())
}
pub(super) fn resolve(
    state: &mut TenantState,
    view: &View,
    position: &kasumi_raft::AppliedEntryContext,
    authorization: &PreparedTargetAuthorization,
    input: &TargetCompletionResolutionInput,
    engine: &TenantEngine,
) -> Result<TargetCompletionResolutionFact> {
    let entry = authorize(
        state,
        position,
        authorization,
        LifecyclePhase::ResolveComplete,
        &input.digest()?,
        engine,
    )?;
    let previous = completion(view, &entry.origin, input.attempt.intent.request.command_id)?;
    CompletionMachine {
        origin: &entry.origin,
        head: state
            .target_completion_head
            .as_mut()
            .ok_or_else(|| error(ErrorCode::Corruption, "target completion head absent"))?,
        completion: entry.completion.as_ref(),
        terminal_bytes: state.target_resolution_head.encoded_bytes,
        maximum_bytes: state.limits.max_target_resolution_bytes,
    }
    .resolve(
        input.clone(),
        ResolutionApply {
            intent: authorization.grant.claims.commitment.intent.clone(),
            admitted_at_ms: authorization.admitted_at_ms,
            dispatch_not_after_ms: authorization.dispatch_not_after_ms,
            revision: state.revision,
            position: at(position),
        },
        previous.as_ref(),
    )
}
pub(super) fn maintain(
    state: &mut TenantState,
    view: &View,
    position: &kasumi_raft::AppliedEntryContext,
    authorization: &PreparedTargetAuthorization,
    input: &TargetResolutionBudgetInput,
    engine: &TenantEngine,
) -> Result<TargetResolutionBudgetFact> {
    let entry = authorize(
        state,
        position,
        authorization,
        LifecyclePhase::MaintainTarget,
        &input.digest()?,
        engine,
    )?;
    let proposed = TargetResolutionBudgetFact {
        origin: entry.origin.clone(),
        input: input.clone(),
        intent: authorization.grant.claims.commitment.intent.clone(),
        admitted_at_ms: authorization.admitted_at_ms,
        dispatch_not_after_ms: authorization.dispatch_not_after_ms,
        revision: state.revision,
        position: at(position),
    };
    let previous = match point(
        view,
        &format!("budget/{}/{}", state.incarnation, input.operation_id),
    )? {
        Some(TargetResolutionRecord::Budget(fact)) => Some(*fact),
        None => None,
        _ => {
            return Err(error(
                ErrorCode::Corruption,
                "budget point record kind differs",
            ));
        }
    };
    let row = crate::target_resolution::Row::ordered(
        &state.target_resolution_head,
        TargetResolutionRecord::Budget(Box::new(proposed.clone())),
        position,
    )
    .map_err(|_| error(ErrorCode::Corruption, "budget ordered row differs"))?;
    let charge = row.framed_bytes().map_err(|_| {
        error(
            ErrorCode::ResourceExhausted,
            "budget row framing exceeds bound",
        )
    })?;
    let head = state
        .target_completion_head
        .as_mut()
        .ok_or_else(|| error(ErrorCode::Corruption, "target completion head absent"))?;
    if previous.is_none()
        && let Some(id) = head.budget_operation_id
    {
        let Some(TargetResolutionRecord::Budget(old)) =
            point(view, &format!("budget/{}/{id}", state.incarnation))?
        else {
            return Err(error(
                ErrorCode::Corruption,
                "selected budget outcome missing",
            ));
        };
        if proposed.intent.revision <= old.intent.revision {
            return Err(error(
                ErrorCode::Conflict,
                "budget maintenance Control order regressed",
            ));
        }
    }
    let transition = CompletionMachine {
        origin: &entry.origin,
        head,
        completion: entry.completion.as_ref(),
        terminal_bytes: state.target_resolution_head.encoded_bytes,
        maximum_bytes: state.limits.max_target_resolution_bytes,
    }
    .maintain_budget(proposed, charge, previous.as_ref())?;
    if transition.changed {
        state.limits.max_target_resolution_bytes = transition.fact.input.maximum_bytes;
        state
            .target_completion_head
            .as_mut()
            .expect("checked head")
            .budget_operation_id = Some(input.operation_id);
    }
    Ok(transition.fact)
}
