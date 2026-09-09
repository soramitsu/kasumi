//! Pure durable-phase fixtures for the coordinator's proof and causal checks.
//! Actual replicated/native dispatch and crash validation are separate gates.
use super::*;
use crate::target_completion_machine::tests as fixture;
use std::collections::BTreeSet;

fn retained(
    state: &mut TenantState,
    operation: &RecoveryRecord,
    id: Uuid,
    input: RecoveryDispatch,
    outcome: Option<RecoveryDispatchOutcome>,
    revision: u64,
) -> RecoveryPhaseRecord {
    let value = RecoveryPhaseRecord {
        operation_id: operation.request.operation_id,
        phase_id: id,
        sequence: revision,
        phase: RecoveryPhase::Complete,
        previous_phase: None,
        input_sha256: staged_digest(&input).unwrap().0,
        input,
        principal: "operator".into(),
        admitted_at_ms: 100,
        original_credential_expires_at_ms: 3000,
        prepared_revision: revision,
        resolved_revision: outcome.as_ref().map(|_| revision + 1),
        outcome,
    };
    value.validate().unwrap();
    state
        .recovery_control
        .phases
        .insert(id.to_string(), value.clone());
    value
}
fn control(state: &mut TenantState, operation: &RecoveryRecord, intent: LifecycleIntent) {
    state
        .lifecycle_control
        .as_mut()
        .unwrap()
        .intents
        .insert(intent.request.command_id, intent.clone());
    retained(
        state,
        operation,
        intent.request.command_id,
        RecoveryDispatch::ControlIntent(Box::new(intent.request.clone())),
        Some(RecoveryDispatchOutcome::ControlIntent(Box::new(
            intent.clone(),
        ))),
        intent.revision - 1,
    );
}
fn fixture_state() -> (TenantState, RecoveryRecord, TargetCompletionAttempt) {
    let origin = fixture::origin();
    let attempt = fixture::attempt(&origin, None, 3, 1, 200, 500);
    let mut state = crate::TenantEngine::new(
        crate::control::CONTROL_TENANT.into(),
        origin.materialization.control_incarnation.to_string(),
        Policy {
            grants: vec![Grant {
                principal: "operator".into(),
                collection: None,
                actions: BTreeSet::from([Action::Admin]),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )
    .unwrap()
    .generation()
    .unwrap()
    .state
    .clone();
    let partition = ControlAuthorityPartition {
        authority_id: Uuid::from_u128(901),
        manifest_sha256: origin.authority_manifest_sha256.clone(),
        partition: 0,
        signing_public_key: "33".repeat(32),
        maximum_lifetime_ms: 1000,
        drain_ms: 1000,
    };
    state.lifecycle_control = Some(LifecycleControlState {
        installation: LifecycleInstallation {
            root: ControlSigningRoot {
                control_incarnation: origin.materialization.control_incarnation,
                public_key: "55".repeat(32),
            },
            generation: 1,
            partitions: BTreeMap::from([(
                origin.materialization.request.authority_partition.clone(),
                partition,
            )]),
            max_intents: 100,
            max_changes: 10,
            max_state_bytes: 8 << 20,
        },
        installation_command_id: Uuid::from_u128(902),
        installation_revision: 1,
        installation_policy_epoch: 1,
        installation_policy: state.policy.clone(),
        retired: false,
        pending_change: None,
        intents: Default::default(),
        changes: Default::default(),
    });
    let r = &origin.materialization.request;
    let request = RecoveryStart {
        operation_id: Uuid::from_u128(600),
        tenant: r.tenant.clone(),
        source_incarnation: r.source_incarnation,
        source_authority_epoch: r.source_authority_epoch,
        target_incarnation: r.target_incarnation,
        checkpoint: r.checkpoint.clone(),
        source_purpose_sha256: origin.input.source_purpose_sha256.clone(),
        source_mode: RecoverySourceMode::SourceUnavailable,
        installation_sha256: r.installation_sha256.clone(),
        expected_policy_epoch: 1,
        authority_policy_epoch: 1,
        authority_partition: r.authority_partition.clone(),
        dispatch_configuration_sha256: "99".repeat(32),
        target_nodes: r.target_nodes.clone(),
        materialization: origin.input.clone(),
        phase_timeout_ms: 1000,
    };
    let mut operation = RecoveryRecord {
        request_sha256: request.digest().unwrap(),
        request,
        original_principal: "operator".into(),
        created_revision: 1,
        updated_revision: 100,
        phase: RecoveryPhase::Complete,
        next_phase_sequence: 100,
        pending_phase: None,
        last_phase: None,
        issuer_preparation: None,
        current_intent: None,
        materialization_intent: Some(r.command_id),
        initialization: None,
        completion_intent: Some(attempt.intent.request.command_id),
        completion_preparation_attempt: Some(Uuid::from_u128(610)),
        completion_preparation: None,
        completion_resolution_attempt: None,
        completion_terminal: None,
        completion_attempt: None,
        completion: None,
        retirement: None,
        source_fence: None,
        activation_attempt: None,
        activation: None,
        route_publication: None,
        stop_request: None,
        target_stop: None,
        voters: (1..=3)
            .map(|node| (node, RecoveryVoterProgress::default()))
            .collect(),
    };
    control(&mut state, &operation, origin.materialization.clone());
    control(&mut state, &operation, attempt.intent.clone());
    for (node, signed) in &attempt.input.quorum.materialized {
        let id = Uuid::from_u128(500 + u128::from(*node));
        retained(
            &mut state,
            &operation,
            id,
            RecoveryDispatch::Target {
                node_id: *node,
                request: Box::new(TargetRuntimeRequest {
                    tenant: r.tenant.clone(),
                    command_id: r.command_id,
                    not_after_ms: 500,
                    step: TargetRuntimeStep::Materialize(origin.input.clone()),
                }),
            },
            Some(RecoveryDispatchOutcome::Target(Box::new(
                TargetRuntimeResponse {
                    node_id: *node,
                    command_id: r.command_id,
                    outcome: TargetRuntimeOutcome::Materialized(Box::new(signed.clone())),
                },
            ))),
            5 + node,
        );
        operation.voters.get_mut(node).unwrap().materialization = Some(id);
    }
    let first = retained(
        &mut state,
        &operation,
        Uuid::from_u128(610),
        RecoveryDispatch::Target {
            node_id: 1,
            request: Box::new(TargetRuntimeRequest {
                tenant: r.tenant.clone(),
                command_id: attempt.intent.request.command_id,
                not_after_ms: 500,
                step: TargetRuntimeStep::PrepareComplete(attempt.input.clone()),
            }),
        },
        None,
        10,
    );
    operation.pending_phase = Some(first.phase_id);
    (state, operation, attempt)
}
fn observe(
    state: &mut TenantState,
    operation: &mut RecoveryRecord,
    attempt: &TargetCompletionAttempt,
) -> RecoveryPhaseRecord {
    let input = status_input(state, operation).unwrap();
    let intent = fixture::intent(
        &attempt.origin,
        LifecyclePhase::InspectCompletionAttempt,
        input.digest().unwrap(),
        20,
        1000,
        2000,
    );
    control(state, operation, intent.clone());
    let observation = TargetCompletionAttemptStatusObservation {
        input: input.clone(),
        status_intent: intent.clone(),
        attempt: attempt.clone(),
        observer_node_id: 1,
        observed_revision: 20,
        observed_term: 1,
    };
    let signed = SignedTargetCompletionAttemptStatus {
        signature: fixture::sign(
            &observation,
            "kasumi.target-completion-attempt-status-observation.v1",
            1,
        ),
        observation,
    };
    let response = TargetRuntimeResponse {
        node_id: 1,
        command_id: intent.request.command_id,
        outcome: TargetRuntimeOutcome::CompletionAttemptStatus(Box::new(signed)),
    };
    let observed = retained(
        state,
        operation,
        Uuid::from_u128(700),
        RecoveryDispatch::Target {
            node_id: 1,
            request: Box::new(TargetRuntimeRequest {
                tenant: operation.request.tenant.clone(),
                command_id: intent.request.command_id,
                not_after_ms: 1500,
                step: TargetRuntimeStep::InspectCompletionAttempt(Box::new(input)),
            }),
        },
        Some(RecoveryDispatchOutcome::Target(Box::new(response.clone()))),
        25,
    );
    validate_outcome(state, operation, &observed, &response).unwrap();
    state.revision = 26;
    resolve_prior(state, operation, &observed, &response).unwrap();
    operation.completion_preparation = Some(observed.phase_id);
    operation.current_intent = Some(intent.request.command_id);
    operation.pending_phase = None;
    observed
}
#[test]
fn lost_prepare_reply_and_expired_phase_require_persisted_positive_status_before_resolution() {
    let (mut state, mut operation, attempt) = fixture_state();
    let original = original(&state, &operation).unwrap().clone();
    assert!(original.outcome.is_none());
    assert!(resolution_input(&state, &operation).is_err());
    assert_eq!(
        fresh_phase(&state, &operation).unwrap(),
        LifecyclePhase::InspectCompletionAttempt
    );
    let observed = observe(&mut state, &mut operation, &attempt);
    assert_eq!(preparation(&state, &operation).unwrap(), &attempt);
    assert_eq!(
        status_input(&state, &operation)
            .unwrap()
            .original_dispatch_not_after_ms,
        500
    );
    let resolved = phase(&state, &operation, original.phase_id).unwrap();
    assert_eq!(resolved.input, original.input);
    assert_eq!(
        resolved.outcome,
        Some(RecoveryDispatchOutcome::PreparationObserved {
            status_phase: observed.phase_id
        })
    );
    assert_eq!(
        fresh_phase(&state, &operation).unwrap(),
        LifecyclePhase::ResolveComplete
    );

    let input = resolution_input(&state, &operation).unwrap();
    let intent = fixture::intent(
        &attempt.origin,
        LifecyclePhase::ResolveComplete,
        input.digest().unwrap(),
        30,
        1100,
        2000,
    );
    let request = TargetRuntimeRequest {
        tenant: operation.request.tenant.clone(),
        command_id: intent.request.command_id,
        not_after_ms: 1900,
        step: TargetRuntimeStep::ResolveComplete(Box::new(input)),
    };
    validate_step(&state, &operation, &intent, 1, &request, false).unwrap();
    let mut changed = state.clone();
    changed
        .recovery_control
        .phases
        .get_mut(&observed.phase_id.to_string())
        .unwrap()
        .resolved_revision = Some(30);
    assert!(validate_step(&changed, &operation, &intent, 1, &request, false).is_err());
    let mut changed = request;
    if let TargetRuntimeStep::ResolveComplete(input) = &mut changed.step {
        input.attempt.position.index += 1;
    }
    assert!(validate_step(&state, &operation, &intent, 1, &changed, false).is_err());
}
#[test]
fn absence_or_substituted_status_cannot_install_preparation_evidence() {
    let (mut state, mut operation, mut attempt) = fixture_state();
    assert!(preparation(&state, &operation).is_err());
    assert!(resolution_input(&state, &operation).is_err());
    let expected = status_input(&state, &operation).unwrap();
    attempt.dispatch_not_after_ms -= 1;
    assert!(expected.matches(&attempt).is_err());
    let (_, _, exact) = fixture_state();
    let observed = observe(&mut state, &mut operation, &exact);
    let mut original = original(&state, &operation).unwrap().clone();
    original.prepared_revision = observed.prepared_revision;
    assert!(validate_link(&state, &operation, &original, observed.phase_id, false).is_err());
}
#[test]
fn sealed_terminal_is_retained_distinctly_and_cannot_enter_activation_inspection() {
    let (mut state, mut operation, attempt) = fixture_state();
    observe(&mut state, &mut operation, &attempt);
    let input = resolution_input(&state, &operation).unwrap();
    let intent = fixture::intent(
        &attempt.origin,
        LifecyclePhase::ResolveComplete,
        input.digest().unwrap(),
        30,
        1100,
        2000,
    );
    control(&mut state, &operation, intent.clone());
    let fact = TargetCompletionResolutionFact {
        input: input.clone(),
        resolution_intent: intent.clone(),
        admitted_at_ms: 1101,
        dispatch_not_after_ms: 1900,
        revision: 14,
        position: TargetCommitPosition {
            index: 3,
            term: 1,
            leader_node_id: 1,
            command_sha256: "44".repeat(32),
        },
        terminal: TargetCompletionTerminal::Sealed,
    };
    fact.validate().unwrap();
    let observation = TargetCompletionResolutionObservation {
        fact,
        observation_intent: intent.clone(),
        observer_node_id: 1,
        observed_revision: 14,
        observed_term: 1,
    };
    let signed = SignedTargetCompletionResolution {
        signature: fixture::sign(
            &observation,
            "kasumi.resolved-target-completion-observation.v1",
            1,
        ),
        observation,
    };
    let response = TargetRuntimeResponse {
        command_id: intent.request.command_id,
        node_id: 1,
        outcome: TargetRuntimeOutcome::ResolvedCompletion(Box::new(signed)),
    };
    let id = Uuid::from_u128(800);
    let record = retained(
        &mut state,
        &operation,
        id,
        RecoveryDispatch::Target {
            node_id: 1,
            request: Box::new(TargetRuntimeRequest {
                tenant: operation.request.tenant.clone(),
                command_id: intent.request.command_id,
                not_after_ms: 1900,
                step: TargetRuntimeStep::ResolveComplete(Box::new(input)),
            }),
        },
        Some(RecoveryDispatchOutcome::Target(Box::new(response.clone()))),
        31,
    );
    operation.completion_resolution_attempt = Some(id);
    validate_outcome(&state, &operation, &record, &response).unwrap();
    operation.completion_terminal = Some(id);
    validate_progress(&state, &operation).unwrap();
    assert!(fresh_phase(&state, &operation).is_err());
    assert!(
        validate_inspected_terminal(&state, &operation, &fixture::completion(&attempt)).is_err()
    );
    operation.activation_attempt = Some(Uuid::from_u128(900));
    assert!(validate_progress(&state, &operation).is_err());
}
