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
            if admission && !all_started(state, operation, current.request.command_id)? {
                return Err(conflict(
                    "completion requires every target started under this exact phase",
                ));
            }
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
    matches!((&pending.input,input),
        (RecoveryDispatch::Target {node_id:old,request:original},RecoveryDispatch::Target {node_id:new,request:next})
        if matches!(pending.phase,RecoveryPhase::Complete|RecoveryPhase::Confirm) && old!=new && original==next && now<original.not_after_ms && matches!(original.step,TargetRuntimeStep::Complete(_)|TargetRuntimeStep::Inspect(_)|TargetRuntimeStep::Activate{..}))
}
