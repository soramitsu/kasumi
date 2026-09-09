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
            assert!(fresh_phase(&state, &operation).is_err());
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
