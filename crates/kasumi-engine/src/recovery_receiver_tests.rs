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
    let phase = match &input {
        RecoveryDispatch::ControlIntent(request) => match request.phase {
            LifecyclePhase::Materialize | LifecyclePhase::ResumeMaterialize => {
                RecoveryPhase::Materialize
            }
            LifecyclePhase::Initialize => RecoveryPhase::Initialize,
            _ => RecoveryPhase::Complete,
        },
        RecoveryDispatch::Target { request, .. } => match request.step {
            TargetRuntimeStep::Materialize(_) | TargetRuntimeStep::ResumeMaterialization(_) => {
                RecoveryPhase::Materialize
            }
            TargetRuntimeStep::Initialize(_) => RecoveryPhase::Initialize,
            _ => RecoveryPhase::Complete,
        },
        _ => RecoveryPhase::Complete,
    };
    let completion_scope = if phase != RecoveryPhase::Complete {
        None
    } else if matches!(&input, RecoveryDispatch::ControlIntent(request) if request.phase == LifecyclePhase::Complete && operation.completion_intent == Some(id))
    {
        attempts::scope(operation)
    } else {
        attempts::prepared_scope(state, operation, id, &input).unwrap()
    };
    let command_id = match &input {
        RecoveryDispatch::ControlIntent(request) => request.command_id,
        RecoveryDispatch::Target { request, .. } => request.command_id,
        _ => panic!("receiver fixture requires an installed Control intent"),
    };
    let authority = state
        .lifecycle_control
        .as_ref()
        .unwrap()
        .intents
        .get(&command_id)
        .expect("receiver fixture must retain the exact original Control intent");
    let input_sha256 = staged_digest(&input).unwrap().0;
    let committed_control = matches!(
        (&input, &outcome),
        (
            RecoveryDispatch::ControlIntent(_),
            Some(RecoveryDispatchOutcome::ControlIntent(_))
        )
    );
    let committed_initial_target = matches!(
        (&input, &outcome),
        (
            RecoveryDispatch::Target { request, .. },
            Some(RecoveryDispatchOutcome::Target(_))
        ) if matches!(
            request.step,
            TargetRuntimeStep::Start(TargetReplicaInput::Quorum(_))
                | TargetRuntimeStep::Initialize(_)
        )
    );
    let prepared_revision = if committed_control || committed_initial_target {
        revision.saturating_sub(1).max(1)
    } else {
        revision
    };
    let effect_attempts = if committed_control || committed_initial_target {
        BTreeMap::from([(
            if committed_control {
                RecoveryEffect::ControlIntent
            } else {
                RecoveryEffect::TargetCommand
            },
            RecoveryEffectAttempt {
                attempt_id: Uuid::new_v4(),
                input_sha256: input_sha256.clone(),
                admitted_at_ms: authority.accepted_at_ms,
                begun_revision: revision.max(2),
            },
        )])
    } else {
        BTreeMap::new()
    };
    let value = RecoveryPhaseRecord {
        operation_id: operation.request.operation_id,
        phase_id: id,
        sequence: revision,
        phase,
        completion_scope,
        previous_phase: None,
        input_sha256,
        input,
        principal: "operator".into(),
        admitted_at_ms: authority.accepted_at_ms,
        original_credential_expires_at_ms: authority.original_credential_expires_at_ms,
        prepared_revision,
        effect_attempts,
        activation_acceptance: None,
        resolved_revision: outcome.as_ref().map(|_| (revision + 1).max(3)),
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
    let attempt = fixture::attempt(&origin, None, 12, 1, 200, 500);
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
        completion_predecessor: None,
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
    let initialization = fixture::intent(
        &origin,
        LifecyclePhase::Initialize,
        attempt.input.quorum.digest().unwrap(),
        9,
        150,
        1000,
    );
    control(&mut state, &operation, initialization.clone());
    let initialized_id = Uuid::from_u128(609);
    let mut initialized = retained(
        &mut state,
        &operation,
        initialized_id,
        RecoveryDispatch::Target {
            node_id: 1,
            request: Box::new(TargetRuntimeRequest {
                tenant: r.tenant.clone(),
                command_id: initialization.request.command_id,
                not_after_ms: 500,
                step: TargetRuntimeStep::Initialize(attempt.input.quorum.clone()),
            }),
        },
        Some(RecoveryDispatchOutcome::Target(Box::new(
            TargetRuntimeResponse {
                node_id: 1,
                command_id: initialization.request.command_id,
                outcome: TargetRuntimeOutcome::Initialized {
                    origin_sha256: attempt.input.quorum.origin_sha256.clone(),
                },
            },
        ))),
        10,
    );
    initialized.phase = RecoveryPhase::Initialize;
    state
        .recovery_control
        .phases
        .insert(initialized_id.to_string(), initialized);
    operation.initialization = Some(initialized_id);
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
        16,
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
fn sealed_fixture() -> (TenantState, RecoveryRecord, TargetCompletionAttempt) {
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
    operation.current_intent = Some(intent.request.command_id);
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
    operation.pending_phase = None;
    operation.last_phase = Some(id);
    operation.next_phase_sequence = record.sequence + 1;
    operation.updated_revision = 32;
    state.revision = 32;
    state.recovery_control.operations.insert(
        operation.request.operation_id.to_string(),
        operation.clone(),
    );
    (state, operation, attempt)
}
#[test]
fn sealed_terminal_is_retained_distinctly_and_cannot_enter_activation_inspection() {
    let (state, mut operation, attempt) = sealed_fixture();
    assert_eq!(
        fresh_phase(&state, &operation).unwrap(),
        LifecyclePhase::Complete
    );
    assert_eq!(
        attempts::next_input(&state, &operation)
            .unwrap()
            .predecessor,
        Some(
            terminal(&state, &operation)
                .unwrap()
                .sealed_reference()
                .unwrap()
        )
    );
    assert!(
        validate_inspected_terminal(&state, &operation, &fixture::completion(&attempt)).is_err()
    );
    operation.activation_attempt = Some(Uuid::from_u128(900));
    assert!(validate_progress(&state, &operation).is_err());
}

#[test]
fn expired_unknown_resolver_uses_only_exact_positive_terminal_status() {
    for committed in [false, true] {
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
        let resolver_id = Uuid::from_u128(850);
        let resolver = retained(
            &mut state,
            &operation,
            resolver_id,
            RecoveryDispatch::Target {
                node_id: 1,
                request: Box::new(TargetRuntimeRequest {
                    tenant: operation.request.tenant.clone(),
                    command_id: intent.request.command_id,
                    not_after_ms: 1900,
                    step: TargetRuntimeStep::ResolveComplete(Box::new(input.clone())),
                }),
            },
            None,
            31,
        );
        operation.completion_resolution_attempt = Some(resolver_id);
        operation.current_intent = Some(intent.request.command_id);
        assert_eq!(
            fresh_phase(&state, &operation).unwrap(),
            LifecyclePhase::InspectCompletionResolution
        );
        assert!(terminal(&state, &operation).is_err());
        let status_input = terminal_status_input(&state, &operation).unwrap();
        let status = fixture::intent(
            &attempt.origin,
            LifecyclePhase::InspectCompletionResolution,
            status_input.digest().unwrap(),
            40,
            2500,
            4000,
        );
        control(&mut state, &operation, status.clone());
        let fact = TargetCompletionResolutionFact {
            input,
            resolution_intent: intent,
            admitted_at_ms: 1101,
            dispatch_not_after_ms: 1900,
            revision: 14,
            position: TargetCommitPosition {
                index: 3,
                term: 1,
                leader_node_id: 1,
                command_sha256: "44".repeat(32),
            },
            terminal: if committed {
                TargetCompletionTerminal::Committed(Box::new(fixture::completion(&attempt)))
            } else {
                TargetCompletionTerminal::Sealed
            },
        };
        let observation = TargetCompletionTerminalStatusObservation {
            input: status_input.clone(),
            status_intent: status.clone(),
            fact: fact.clone(),
            observer_node_id: 1,
            observed_revision: 14,
            observed_term: 1,
        };
        let signed = SignedTargetCompletionTerminalStatus {
            signature: fixture::sign(
                &observation,
                "kasumi.target-completion-terminal-status-observation.v1",
                1,
            ),
            observation,
        };
        kasumi_serving::verify_target_completion_terminal_status(&status_input, &signed).unwrap();
        let response = TargetRuntimeResponse {
            command_id: status.request.command_id,
            node_id: 1,
            outcome: TargetRuntimeOutcome::CompletionTerminalStatus(Box::new(signed.clone())),
        };
        let status_id = Uuid::from_u128(860);
        let observed = retained(
            &mut state,
            &operation,
            status_id,
            RecoveryDispatch::Target {
                node_id: 1,
                request: Box::new(TargetRuntimeRequest {
                    tenant: operation.request.tenant.clone(),
                    command_id: status.request.command_id,
                    not_after_ms: 3500,
                    step: TargetRuntimeStep::InspectCompletionResolution(Box::new(
                        status_input.clone(),
                    )),
                }),
            },
            Some(RecoveryDispatchOutcome::Target(Box::new(response.clone()))),
            41,
        );
        validate_outcome(&state, &operation, &observed, &response).unwrap();
        state.revision = 42;
        resolve_resolver(&mut state, &operation, &observed).unwrap();
        let resolved = phase(&state, &operation, resolver_id).unwrap().clone();
        assert_eq!(resolved.input, resolver.input);
        assert_eq!(
            resolved.original_credential_expires_at_ms,
            resolver.original_credential_expires_at_ms
        );
        assert_eq!(
            resolved.outcome,
            Some(RecoveryDispatchOutcome::TerminalObserved {
                status_phase: status_id
            })
        );
        operation.completion_terminal = Some(status_id);
        validate_progress(&state, &operation).unwrap();
        assert_eq!(terminal(&state, &operation).unwrap(), &fact);
        if committed {
            assert_eq!(
                fresh_phase(&state, &operation).unwrap(),
                LifecyclePhase::InspectTarget
            );
            validate_inspected_terminal(&state, &operation, &fixture::completion(&attempt))
                .unwrap();
        } else {
            assert_eq!(
                fresh_phase(&state, &operation).unwrap(),
                LifecyclePhase::Complete
            );
            assert_eq!(
                attempts::next_input(&state, &operation)
                    .unwrap()
                    .predecessor,
                Some(fact.sealed_reference().unwrap())
            );
        }
        let mut changed = signed.clone();
        changed.observation.fact.dispatch_not_after_ms += 1;
        changed.signature = fixture::sign(
            &changed.observation,
            "kasumi.target-completion-terminal-status-observation.v1",
            1,
        );
        assert!(
            kasumi_serving::verify_target_completion_terminal_status(&status_input, &changed)
                .is_err()
        );
        let mut wrong_domain = signed;
        wrong_domain.signature = fixture::sign(
            &wrong_domain.observation,
            "kasumi.resolved-target-completion-observation.v1",
            1,
        );
        assert!(
            kasumi_serving::verify_target_completion_terminal_status(&status_input, &wrong_domain)
                .is_err()
        );
        let mut earlier = observed;
        earlier.prepared_revision = resolver.prepared_revision;
        state
            .recovery_control
            .phases
            .insert(status_id.to_string(), earlier);
        assert!(validate_resolver_link(&state, &operation, &resolved, status_id).is_err());
    }
}

#[test]
fn terminal_status_absence_or_new_resolver_identity_has_no_valid_evidence_form() {
    assert!(
        serde_json::from_value::<SignedTargetCompletionTerminalStatus>(
            serde_json::json!({"absent": true})
        )
        .is_err()
    );
    let (mut state, mut operation, attempt) = fixture_state();
    observe(&mut state, &mut operation, &attempt);
    assert!(terminal_status_input(&state, &operation).is_err());
    assert!(terminal(&state, &operation).is_err());
}

/// The first installed node has no startup response. Its original request stays
/// unknown while the other two installed nodes can start under the same intent.
#[test]
fn established_receiver_routes_around_unknown_start_without_unanimous_reopening() {
    let (mut state, mut operation, attempt) = fixture_state();
    let input = status_input(&state, &operation).unwrap();
    let current = fixture::intent(
        &attempt.origin,
        LifecyclePhase::InspectCompletionAttempt,
        input.digest().unwrap(),
        20,
        1000,
        2000,
    );
    control(&mut state, &operation, current.clone());
    operation.current_intent = Some(current.request.command_id);
    operation.pending_phase = None;
    let first = next(&state, &operation, &current, 1100, 2000).unwrap();
    let RecoveryDispatch::Target { node_id, request } = &first else {
        panic!("startup required");
    };
    assert_eq!(*node_id, 1);
    assert!(matches!(request.step, TargetRuntimeStep::Start(_)));
    let original_request = request.clone();
    let first_phase = retained(
        &mut state,
        &operation,
        Uuid::from_u128(920),
        first,
        None,
        21,
    );
    operation.voters.get_mut(&1).unwrap().start_attempt = Some(first_phase.phase_id);
    operation.last_phase = Some(first_phase.phase_id);
    operation.pending_phase = Some(first_phase.phase_id);
    assert_eq!(
        quorum::retry_destination(
            &state,
            &operation,
            current.request.command_id,
            1,
            &original_request.step
        )
        .unwrap(),
        2
    );
    let retry = RecoveryDispatch::Target {
        node_id: 2,
        request: original_request.clone(),
    };
    assert!(quorum::completion_route_retry(&first_phase, &retry, 1100));
    assert!(!quorum::completion_route_retry(
        &first_phase,
        &retry,
        original_request.not_after_ms
    ));
    for node in [2, 3] {
        let dispatch = if node == 2 {
            retry.clone()
        } else {
            let dispatch = next(&state, &operation, &current, 1100, 2000).unwrap();
            assert!(
                matches!(&dispatch, RecoveryDispatch::Target { node_id: 3, request }
                if matches!(request.step, TargetRuntimeStep::Start(_)))
            );
            dispatch
        };
        let response = TargetRuntimeResponse {
            node_id: node,
            command_id: current.request.command_id,
            outcome: TargetRuntimeOutcome::Started {
                origin_sha256: attempt.input.quorum.origin_sha256.clone(),
            },
        };
        let record = retained(
            &mut state,
            &operation,
            Uuid::from_u128(920 + u128::from(node)),
            dispatch,
            Some(RecoveryDispatchOutcome::Target(Box::new(response.clone()))),
            21 + node,
        );
        validate_outcome(&state, &operation, &record, &response).unwrap();
        let progress = operation.voters.get_mut(&node).unwrap();
        progress.start_attempt = Some(record.phase_id);
        progress.started = Some(record.phase_id);
        operation.last_phase = Some(record.phase_id);
        operation.pending_phase = None;
    }
    assert!(!quorum::all_started(&state, &operation, current.request.command_id).unwrap());
    let RecoveryDispatch::Target { node_id, request } =
        next(&state, &operation, &current, 1100, 2000).unwrap()
    else {
        panic!("positive receiver observation required");
    };
    assert_eq!(node_id, 2);
    assert!(matches!(
        request.step,
        TargetRuntimeStep::InspectCompletionAttempt(_)
    ));
    validate_step(&state, &operation, &current, node_id, &request, true).unwrap();
    assert!(validate_step(&state, &operation, &current, 1, &request, true).is_err());
    assert!(
        phase(&state, &operation, first_phase.phase_id)
            .unwrap()
            .outcome
            .is_none()
    );
    assert_eq!(
        quorum::retry_destination(
            &state,
            &operation,
            current.request.command_id,
            2,
            &request.step
        )
        .unwrap(),
        3
    );
    // Startup replies do not replace the required materialization proof or a
    // signed positive target observation; neither original outcome is invented.
    assert!(preparation(&state, &operation).is_err());
    operation.voters.get_mut(&1).unwrap().materialization = None;
    assert!(next(&state, &operation, &current, 1100, 2000).is_err());
}

#[test]
fn complete_mutation_retry_includes_initialized_leader_without_new_start() {
    let (mut state, mut operation, attempt) = fixture_state();
    let current = attempt.intent.clone();
    let original = TargetRuntimeRequest {
        tenant: operation.request.tenant.clone(),
        command_id: current.request.command_id,
        not_after_ms: attempt.dispatch_not_after_ms,
        step: TargetRuntimeStep::PrepareComplete(attempt.input.clone()),
    };
    for node in [1, 2] {
        let response = TargetRuntimeResponse {
            node_id: node,
            command_id: current.request.command_id,
            outcome: TargetRuntimeOutcome::Started {
                origin_sha256: attempt.input.quorum.origin_sha256.clone(),
            },
        };
        let started = retained(
            &mut state,
            &operation,
            Uuid::from_u128(940 + u128::from(node)),
            RecoveryDispatch::Target {
                node_id: node,
                request: Box::new(TargetRuntimeRequest {
                    step: TargetRuntimeStep::Start(TargetReplicaInput::Completion(
                        attempt.input.clone(),
                    )),
                    ..original.clone()
                }),
            },
            Some(RecoveryDispatchOutcome::Target(Box::new(response))),
            30 + node,
        );
        let progress = operation.voters.get_mut(&node).unwrap();
        progress.start_attempt = Some(started.phase_id);
        progress.started = Some(started.phase_id);
    }
    assert_eq!(
        quorum::ready_nodes(&state, &operation, current.request.command_id).unwrap(),
        vec![1, 2]
    );
    assert_eq!(
        quorum::retry_destination(
            &state,
            &operation,
            current.request.command_id,
            2,
            &original.step,
        )
        .unwrap(),
        3
    );
    validate_step(&state, &operation, &current, 3, &original, true).unwrap();
    assert!(
        quorum::require_eligible_observer(&state, &operation, current.request.command_id, 3)
            .is_err()
    );

    let mut missing_initialization = operation.clone();
    missing_initialization.initialization = None;
    assert!(
        validate_step(
            &state,
            &missing_initialization,
            &current,
            3,
            &original,
            true
        )
        .is_err()
    );
    assert!(
        quorum::retry_destination(
            &state,
            &missing_initialization,
            current.request.command_id,
            2,
            &original.step,
        )
        .is_err()
    );

    let mut missing_materialization = operation.clone();
    missing_materialization
        .voters
        .get_mut(&3)
        .unwrap()
        .materialization = None;
    assert!(
        validate_step(
            &state,
            &missing_materialization,
            &current,
            3,
            &original,
            true
        )
        .is_err()
    );
    let mut different_input = original.clone();
    let TargetRuntimeStep::PrepareComplete(input) = &mut different_input.step else {
        unreachable!()
    };
    input.quorum.origin_sha256 = "00".repeat(32);
    assert!(validate_step(&state, &operation, &current, 3, &different_input, true).is_err());
}

#[test]
fn complete_reducer_rejects_both_original_cap_substitutions_before_inserting_phase() {
    let (mut state, mut operation, attempt) = fixture_state();
    let original_id = operation.completion_preparation_attempt.unwrap();
    let mut original = phase(&state, &operation, original_id).unwrap().clone();
    let observation = TargetCompletionAttemptObservation {
        attempt: attempt.clone(),
        observer_node_id: 1,
        observed_revision: attempt.revision,
        observed_term: attempt.position.term,
    };
    original.outcome = Some(RecoveryDispatchOutcome::Target(Box::new(
        TargetRuntimeResponse {
            command_id: attempt.intent.request.command_id,
            node_id: 1,
            outcome: TargetRuntimeOutcome::PreparedCompletion(Box::new(
                SignedTargetCompletionAttempt {
                    signature: fixture::sign(
                        &observation,
                        "kasumi.prepared-target-completion-observation.v1",
                        1,
                    ),
                    observation,
                },
            )),
        },
    )));
    original.resolved_revision = Some(17);
    state
        .recovery_control
        .phases
        .insert(original_id.to_string(), original);
    operation.completion_preparation = Some(original_id);
    operation.pending_phase = None;
    operation.current_intent = Some(attempt.intent.request.command_id);
    let started = retained(
        &mut state,
        &operation,
        Uuid::from_u128(930),
        RecoveryDispatch::Target {
            node_id: 1,
            request: Box::new(TargetRuntimeRequest {
                tenant: operation.request.tenant.clone(),
                command_id: attempt.intent.request.command_id,
                not_after_ms: 500,
                step: TargetRuntimeStep::Start(TargetReplicaInput::Completion(
                    attempt.input.clone(),
                )),
            }),
        },
        Some(RecoveryDispatchOutcome::Target(Box::new(
            TargetRuntimeResponse {
                node_id: 1,
                command_id: attempt.intent.request.command_id,
                outcome: TargetRuntimeOutcome::Started {
                    origin_sha256: attempt.input.quorum.origin_sha256.clone(),
                },
            },
        ))),
        14,
    );
    operation.voters.get_mut(&1).unwrap().started = Some(started.phase_id);
    operation.voters.get_mut(&1).unwrap().start_attempt = Some(started.phase_id);
    state.revision = 101;
    state.recovery_control.operations.insert(
        operation.request.operation_id.to_string(),
        operation.clone(),
    );
    let context = RequestContext {
        tenant: state.tenant.clone(),
        principal: "operator".into(),
        scopes: BTreeSet::from([Action::Admin]),
        request_id: "cap-admission".into(),
        authorization: RequestAuthorization::service_identity(),
    };
    for cap in [
        attempt.dispatch_not_after_ms - 1,
        attempt.dispatch_not_after_ms + 1,
        attempt.dispatch_not_after_ms,
    ] {
        let mut candidate = state.clone();
        let id = Uuid::new_v4();
        let command = super::super::RecoveryCommand {
            authorization: super::super::RecoveryAuthorization {
                context: context.clone(),
                policy_epoch: state.policy_epoch,
                admitted_at_ms: 300,
                expires_at_ms: 2000,
            },
            mutation: super::super::RecoveryMutation::Prepare {
                operation_id: operation.request.operation_id,
                phase_id: id,
                expected_sequence: operation.next_phase_sequence,
                expected_pending: None,
                input: Box::new(RecoveryDispatch::Target {
                    node_id: 1,
                    request: Box::new(TargetRuntimeRequest {
                        tenant: operation.request.tenant.clone(),
                        command_id: attempt.intent.request.command_id,
                        not_after_ms: cap,
                        step: TargetRuntimeStep::Complete(attempt.input.clone()),
                    }),
                }),
            },
        };
        let applied = super::super::apply(&mut candidate, &command);
        if cap == attempt.dispatch_not_after_ms {
            assert!(applied.is_ok(), "{applied:?}");
            assert!(
                candidate
                    .recovery_control
                    .phases
                    .contains_key(&id.to_string())
            );
        } else {
            let error = applied.unwrap_err();
            assert_eq!(error.code, ErrorCode::Conflict);
            assert!(error.message.contains("original deadline"), "{error}");
            assert_eq!(candidate.recovery_control, state.recovery_control);
        }
    }
}

fn linked_birth(
    state: &mut TenantState,
    operation: &mut RecoveryRecord,
    revision: u64,
    admitted_at_ms: u64,
    cap: u64,
) -> (TargetCompletionAttempt, RecoveryPhaseRecord) {
    let input = attempts::next_input(state, operation).unwrap();
    let index = terminal(state, operation).unwrap().position.index + 1;
    let attempt = fixture::attempt(
        &origin(state, operation).unwrap(),
        input.predecessor.clone(),
        revision,
        index,
        admitted_at_ms,
        cap,
    );
    assert_eq!(attempt.input, input);
    let intent = attempt.intent.clone();
    state
        .lifecycle_control
        .as_mut()
        .unwrap()
        .intents
        .insert(intent.request.command_id, intent.clone());
    let birth = retained(
        state,
        operation,
        intent.request.command_id,
        RecoveryDispatch::ControlIntent(Box::new(intent.request.clone())),
        Some(RecoveryDispatchOutcome::ControlIntent(Box::new(intent))),
        revision - 1,
    );
    attempts::install(state, operation, &birth).unwrap();
    operation.pending_phase = None;
    operation.last_phase = Some(birth.phase_id);
    operation.next_phase_sequence = birth.sequence + 1;
    operation.updated_revision = revision;
    state.revision = revision;
    state.recovery_control.operations.insert(
        operation.request.operation_id.to_string(),
        operation.clone(),
    );
    attempts::validate_history(state).unwrap();
    (attempt, birth)
}
fn linked_preparation(
    state: &mut TenantState,
    operation: &mut RecoveryRecord,
    attempt: &TargetCompletionAttempt,
) {
    let observation = TargetCompletionAttemptObservation {
        attempt: attempt.clone(),
        observer_node_id: 1,
        observed_revision: attempt.revision,
        observed_term: attempt.position.term,
    };
    let response = TargetRuntimeResponse {
        command_id: attempt.intent.request.command_id,
        node_id: 1,
        outcome: TargetRuntimeOutcome::PreparedCompletion(Box::new(
            SignedTargetCompletionAttempt {
                signature: fixture::sign(
                    &observation,
                    "kasumi.prepared-target-completion-observation.v1",
                    1,
                ),
                observation,
            },
        )),
    };
    let record = retained(
        state,
        operation,
        Uuid::from_u128(10_000 + u128::from(attempt.intent.revision)),
        RecoveryDispatch::Target {
            node_id: 1,
            request: Box::new(TargetRuntimeRequest {
                tenant: operation.request.tenant.clone(),
                command_id: attempt.intent.request.command_id,
                not_after_ms: attempt.dispatch_not_after_ms,
                step: TargetRuntimeStep::PrepareComplete(attempt.input.clone()),
            }),
        },
        Some(RecoveryDispatchOutcome::Target(Box::new(response.clone()))),
        attempt.intent.revision + 1,
    );
    operation.completion_preparation_attempt = Some(record.phase_id);
    operation.completion_preparation = Some(record.phase_id);
    validate_outcome(state, operation, &record, &response).unwrap();
    super::super::validate_frozen_input(state, operation, &record).unwrap();
    state.recovery_control.operations.insert(
        operation.request.operation_id.to_string(),
        operation.clone(),
    );
}
fn seal_linked(
    state: &mut TenantState,
    operation: &mut RecoveryRecord,
    attempt: &TargetCompletionAttempt,
    revision: u64,
    admitted_at_ms: u64,
) {
    let input = resolution_input(state, operation).unwrap();
    let intent = fixture::intent(
        &attempt.origin,
        LifecyclePhase::ResolveComplete,
        input.digest().unwrap(),
        revision,
        admitted_at_ms,
        admitted_at_ms + 900,
    );
    control(state, operation, intent.clone());
    operation.current_intent = Some(intent.request.command_id);
    let fact = TargetCompletionResolutionFact {
        input: input.clone(),
        resolution_intent: intent.clone(),
        admitted_at_ms: admitted_at_ms + 1,
        dispatch_not_after_ms: admitted_at_ms + 800,
        revision: attempt.revision + 1,
        position: TargetCommitPosition {
            index: attempt.position.index + 1,
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
        observed_revision: attempt.revision + 1,
        observed_term: 1,
    };
    let response = TargetRuntimeResponse {
        command_id: intent.request.command_id,
        node_id: 1,
        outcome: TargetRuntimeOutcome::ResolvedCompletion(Box::new(
            SignedTargetCompletionResolution {
                signature: fixture::sign(
                    &observation,
                    "kasumi.resolved-target-completion-observation.v1",
                    1,
                ),
                observation,
            },
        )),
    };
    let record = retained(
        state,
        operation,
        Uuid::from_u128(20_000 + u128::from(revision)),
        RecoveryDispatch::Target {
            node_id: 1,
            request: Box::new(TargetRuntimeRequest {
                tenant: operation.request.tenant.clone(),
                command_id: intent.request.command_id,
                not_after_ms: admitted_at_ms + 800,
                step: TargetRuntimeStep::ResolveComplete(Box::new(input)),
            }),
        },
        Some(RecoveryDispatchOutcome::Target(Box::new(response.clone()))),
        revision + 1,
    );
    operation.completion_resolution_attempt = Some(record.phase_id);
    validate_outcome(state, operation, &record, &response).unwrap();
    operation.completion_terminal = Some(record.phase_id);
    operation.last_phase = Some(record.phase_id);
    operation.next_phase_sequence = record.sequence + 1;
    operation.updated_revision = revision + 2;
    state.revision = revision + 2;
    state.recovery_control.operations.insert(
        operation.request.operation_id.to_string(),
        operation.clone(),
    );
    validate_progress(state, operation).unwrap();
}

#[test]
fn sealed_completion_successor_preserves_exact_old_proof_context_and_rejects_replay() {
    let (mut state, mut operation, _) = sealed_fixture();
    let old = operation.clone();
    let before = state.clone();
    let old_phases = state.recovery_control.phases.clone();
    let predecessor = terminal(&state, &operation)
        .unwrap()
        .sealed_reference()
        .unwrap();
    let (next, birth) = linked_birth(&mut state, &mut operation, 100, 2100, 2500);
    assert_ne!(operation.completion_intent, old.completion_intent);
    assert_eq!(next.input.predecessor, Some(predecessor));
    assert_eq!(operation.completion_predecessor, old.completion_terminal);
    assert!(operation.completion_preparation_attempt.is_none());
    assert!(operation.completion_preparation.is_none());
    assert!(operation.completion_resolution_attempt.is_none());
    assert!(operation.completion_terminal.is_none());
    assert!(operation.completion_attempt.is_none());
    for (key, row) in old_phases.iter() {
        assert_eq!(state.recovery_control.phases.get(key), Some(row));
        if row.phase == RecoveryPhase::Complete {
            let view = attempts::for_phase(&state, &operation, row).unwrap();
            assert_eq!(view.completion_intent, old.completion_intent);
            super::super::validate_frozen_input(&state, &view, row).unwrap();
            if let Some(outcome) = &row.outcome {
                super::super::validate_outcome(&state, &view, row, outcome).unwrap();
            }
        }
    }
    super::super::validate_successor(&before, &state).unwrap();
    let immutable = state.recovery_control.clone();
    assert!(attempts::install(&mut state, &mut operation, &birth).is_err());
    assert_eq!(state.recovery_control, immutable);
    // A forged branch from an old in-memory cursor cannot archive it twice.
    let mut stale = old;
    assert!(attempts::install(&mut state, &mut stale, &birth).is_err());
    assert_eq!(state.recovery_control, immutable);
}

#[test]
fn completion_successor_requires_exact_positive_sealed_original_and_origin() {
    let (state, operation, _) = fixture_state();
    assert!(attempts::next_input(&state, &operation).is_err());
    let (state, operation, attempt) = sealed_fixture();
    for mutation in 0..4 {
        let mut changed = state.clone();
        let mut head = operation.clone();
        match mutation {
            0 => head.completion_terminal = None,
            1 => head.completion = head.completion_terminal,
            2 => {
                let row = changed
                    .recovery_control
                    .phases
                    .get_mut(&head.completion_terminal.unwrap().to_string())
                    .unwrap();
                let Some(RecoveryDispatchOutcome::Target(response)) = &mut row.outcome else {
                    panic!()
                };
                let TargetRuntimeOutcome::ResolvedCompletion(signed) = &mut response.outcome else {
                    panic!()
                };
                signed.observation.fact.terminal =
                    TargetCompletionTerminal::Committed(Box::new(fixture::completion(&attempt)));
            }
            3 => head.request.operation_id = Uuid::from_u128(777_777),
            _ => unreachable!(),
        }
        assert!(
            attempts::next_input(&changed, &head).is_err(),
            "mutation {mutation}"
        );
    }
    let (mut changed, mut head, _) = sealed_fixture();
    linked_birth(&mut changed, &mut head, 100, 2100, 2500);
    head.completion_predecessor = head.completion_preparation_attempt;
    // Removing the predecessor changes the original canonical completion digest.
    assert!(
        completion::validate_original_intent(
            &origin(&changed, &head).unwrap(),
            &completion::completion_input(&changed, &head).unwrap(),
            intent(&changed, &head, head.completion_intent.unwrap()).unwrap()
        )
        .is_err()
    );
    head.completion_predecessor = Some(Uuid::from_u128(610));
    assert!(attempts::predecessor(&changed, &head).is_err());
}

#[test]
fn closed_completion_snapshot_rejects_history_deletion_tamper_cursor_regression_and_phase_rewrite()
{
    let (mut state, mut operation, _) = sealed_fixture();
    let before = state.clone();
    let old_intent = operation.completion_intent.unwrap();
    linked_birth(&mut state, &mut operation, 100, 2100, 2500);
    for mutation in 0..5 {
        let mut changed = state.clone();
        match mutation {
            0 => {
                changed
                    .recovery_control
                    .completion_history
                    .remove(&old_intent.to_string());
            }
            1 => {
                changed
                    .recovery_control
                    .completion_history
                    .get_mut(&old_intent.to_string())
                    .unwrap()
                    .terminal = Uuid::from_u128(610);
            }
            2 => {
                changed
                    .recovery_control
                    .operations
                    .get_mut(&operation.request.operation_id.to_string())
                    .unwrap()
                    .completion_intent = Some(old_intent);
            }
            3 => {
                changed
                    .recovery_control
                    .operations
                    .get_mut(&operation.request.operation_id.to_string())
                    .unwrap()
                    .completion_predecessor = None;
            }
            4 => {
                changed
                    .recovery_control
                    .phases
                    .get_mut(&old_intent.to_string())
                    .unwrap()
                    .completion_scope
                    .as_mut()
                    .unwrap()
                    .predecessor = Some(Uuid::from_u128(800));
            }
            _ => unreachable!(),
        }
        assert!(
            super::super::validate_successor(&state, &changed).is_err(),
            "mutation {mutation}"
        );
        if mutation != 2 {
            assert!(
                attempts::validate_history(&changed).is_err()
                    || super::super::validate_successor(&before, &changed).is_err(),
                "mutation {mutation} must also be rejected when advancing from the old original"
            );
        }
    }
    let mut changed = state.clone();
    changed
        .recovery_control
        .completion_history
        .get_mut(&old_intent.to_string())
        .unwrap()
        .successor_intent = old_intent;
    assert!(attempts::validate_history(&changed).is_err());
}

#[test]
fn repeated_sealed_successors_keep_causal_chain_and_all_original_scopes() {
    let (mut state, mut operation, _) = sealed_fixture();
    let first = operation.completion_intent.unwrap();
    let (second, second_birth) = linked_birth(&mut state, &mut operation, 100, 2100, 2500);
    linked_preparation(&mut state, &mut operation, &second);
    seal_linked(&mut state, &mut operation, &second, 110, 3100);
    let before_third = state.clone();
    let (third, third_birth) = linked_birth(&mut state, &mut operation, 300, 5100, 5500);
    assert_eq!(state.recovery_control.completion_history.len(), 2);
    assert_ne!(third.input.predecessor, second.input.predecessor);
    super::super::validate_successor(&before_third, &state).unwrap();
    let mut chain = operation.completion_intent;
    for row in [
        &third_birth,
        &second_birth,
        phase(&state, &operation, first).unwrap(),
    ] {
        attempts::validate_chain_link(&state, &operation, row, &mut chain).unwrap();
    }
    assert_eq!(chain, None);
    let mut forked = operation.completion_intent;
    assert!(attempts::validate_chain_link(&state, &operation, &second_birth, &mut forked).is_err());
    linked_preparation(&mut state, &mut operation, &third);
    let fact = fixture::completion(&third);
    let observation = TargetCompletionObservation {
        observed_revision: fact.revision,
        observed_term: fact.term,
        observer_node_id: 1,
        fact,
    };
    let outcome = RecoveryDispatchOutcome::Target(Box::new(TargetRuntimeResponse {
        command_id: third.intent.request.command_id,
        node_id: 1,
        outcome: TargetRuntimeOutcome::Completed(Box::new(SignedTargetCompletion {
            signature: fixture::sign(&observation, "kasumi.completed-target-observation.v1", 1),
            observation,
        })),
    }));
    let completed = retained(
        &mut state,
        &operation,
        Uuid::from_u128(30_300),
        RecoveryDispatch::Target {
            node_id: 1,
            request: Box::new(TargetRuntimeRequest {
                tenant: operation.request.tenant.clone(),
                command_id: third.intent.request.command_id,
                not_after_ms: third.dispatch_not_after_ms,
                step: TargetRuntimeStep::Complete(third.input.clone()),
            }),
        },
        Some(outcome.clone()),
        303,
    );
    operation.completion_attempt = Some(completed.phase_id);
    super::super::validate_frozen_input(&state, &operation, &completed).unwrap();
    super::super::validate_outcome(&state, &operation, &completed, &outcome).unwrap();
    // Later global progress must not turn either old sealed context into an
    // activation. These point values test context selection, not native success.
    operation.completion = Some(Uuid::from_u128(900_001));
    operation.activation_attempt = Some(Uuid::from_u128(900_002));
    operation.activation = Some(Uuid::from_u128(900_003));
    for history in state.recovery_control.completion_history.values() {
        let row = phase(&state, &operation, history.terminal).unwrap();
        let view = attempts::for_phase(&state, &operation, row).unwrap();
        assert!(
            view.completion.is_none()
                && view.activation_attempt.is_none()
                && view.activation.is_none()
        );
        validate_progress(&state, &view).unwrap();
        super::super::validate_frozen_input(&state, &view, row).unwrap();
        super::super::validate_outcome(&state, &view, row, row.outcome.as_ref().unwrap()).unwrap();
    }
}

#[test]
fn pending_linked_birth_retains_exact_input_when_stop_clears_pending_without_commit() {
    let (mut state, mut operation, attempt) = sealed_fixture();
    let input = attempts::next_input(&state, &operation).unwrap();
    let intent = fixture::intent(
        &attempt.origin,
        LifecyclePhase::Complete,
        input.digest().unwrap(),
        100,
        2100,
        2600,
    );
    state
        .lifecycle_control
        .as_mut()
        .unwrap()
        .intents
        .insert(intent.request.command_id, intent.clone());
    let pending = retained(
        &mut state,
        &operation,
        intent.request.command_id,
        RecoveryDispatch::ControlIntent(Box::new(intent.request.clone())),
        None,
        99,
    );
    // An unresolved dispatch is not a replicated Control commitment.
    state
        .lifecycle_control
        .as_mut()
        .unwrap()
        .intents
        .remove(&intent.request.command_id);
    operation.pending_phase = Some(pending.phase_id);
    for stopped in [false, true] {
        if stopped {
            operation.pending_phase = None;
            operation.stop_request = Some(Uuid::from_u128(404_404));
            operation.phase = RecoveryPhase::StopTarget;
        }
        let view = attempts::for_phase(&state, &operation, &pending).unwrap();
        super::super::validate_frozen_input(&state, &view, &pending).unwrap();
        assert!(view.completion_intent.is_none());
        assert_eq!(view.completion_predecessor, operation.completion_terminal);
        assert!(state.recovery_control.completion_history.is_empty());
        assert_eq!(
            phase(&state, &operation, pending.phase_id).unwrap(),
            &pending
        );
    }
    let mut forged = pending.clone();
    forged.completion_scope.as_mut().unwrap().predecessor = None;
    assert!(attempts::for_phase(&state, &operation, &forged).is_err());
}

#[test]
fn linked_completion_history_roundtrips_in_native_stream_and_incremental_byte_accounting() {
    let scratch = crate::codec_fixture::ScratchScope::new(
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
    )
    .unwrap();
    let disk = &scratch.disk;
    fn image(
        disk: &Arc<kasumi_store::ScratchDisk>,
        state: &TenantState,
    ) -> kasumi_store::SnapshotImage {
        kasumi_store::SnapshotImage::capture(disk, 16 << 20, |writer| {
            crate::snapshot_codec::write(
                state,
                &crate::mutation_receipt::View::empty(&state.tenant, &state.incarnation)?,
                &crate::backup_binding::View::empty(&state.incarnation)?,
                &crate::staged_terminal::View::empty(&state.tenant, &state.incarnation)?,
                &crate::target_resolution::View::empty(&state.tenant, &state.incarnation)?,
                writer,
            )
        })
        .unwrap()
    }
    // These partial signed fixtures qualify codec/accounting and exact history
    // validation. Full coordinator snapshots require the native runtime gate.
    let (mut state, mut operation, _) = sealed_fixture();
    let before = state.clone();
    let old_accounting = crate::accounting::SnapshotAccounting::rebuild(&before).unwrap();
    linked_birth(&mut state, &mut operation, 100, 2100, 2500);
    let accounting = old_accounting
        .updated(&before, &state, &Default::default(), &Default::default())
        .unwrap();
    let source = image(disk, &state);
    assert_eq!(accounting.bytes(&state).unwrap() as u64, source.len());
    assert_eq!(
        accounting.bytes(&state).unwrap(),
        crate::accounting::SnapshotAccounting::rebuild(&state)
            .unwrap()
            .bytes(&state)
            .unwrap()
    );
    let decoded = crate::snapshot_codec::read(source.disk(), &mut source.reader()).unwrap();
    assert_eq!(decoded.state.recovery_control, state.recovery_control);
    attempts::validate_history(&decoded.state).unwrap();
    let indexed = crate::snapshot_index::StagedSnapshot::new(source, 64 << 20, || Ok(())).unwrap();
    assert_eq!(indexed.count(23).unwrap(), 1);
    let history = state
        .recovery_control
        .completion_history
        .values()
        .next()
        .unwrap();
    let Some(crate::snapshot_codec::Record::RecoveryCompletionHistory(key, actual)) = indexed
        .get(23, &history.scope.intent.to_string(), "")
        .unwrap()
    else {
        panic!("closed completion record absent from point index");
    };
    assert_eq!(key, history.scope.intent.to_string());
    assert_eq!(actual.as_ref(), history);
    // Removal is illegal recovery progression, but accounting must still measure
    // the exact changed map so quotas cannot omit or double-charge its bytes.
    let mut removed = state.clone();
    removed.recovery_control.completion_history.clear();
    let smaller = accounting
        .updated(&state, &removed, &Default::default(), &Default::default())
        .unwrap();
    assert_eq!(
        smaller.bytes(&removed).unwrap() as u64,
        image(disk, &removed).len()
    );
    assert!(smaller.bytes(&removed).unwrap() < accounting.bytes(&state).unwrap());
    assert!(super::super::validate_successor(&state, &removed).is_err());
}
