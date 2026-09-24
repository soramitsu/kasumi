use super::*;
use std::collections::BTreeMap;
use uuid::Uuid;

fn coordinator() -> TenantState {
    let template = super::tests::state();
    // Build every generation-bound native head for the actual Control identity.
    // Relabeling an application fixture leaves its receipt origin outside lineage.
    let mut state = crate::TenantEngine::new(
        crate::control::CONTROL_TENANT.into(),
        Uuid::new_v4().to_string(),
        template.policy,
        template.limits,
    )
    .unwrap()
    .generation()
    .unwrap()
    .state
    .clone();
    state.revision = 3;
    state.policy_epoch = 1;
    let partition = ControlAuthorityPartition {
        authority_id: Uuid::new_v4(),
        manifest_sha256: "12".repeat(32),
        partition: 0,
        signing_public_key: "34".repeat(32),
        maximum_lifetime_ms: 1000,
        drain_ms: 1000,
    };
    let installation = LifecycleInstallation {
        root: ControlSigningRoot {
            control_incarnation: Uuid::parse_str(&state.incarnation).unwrap(),
            public_key: "56".repeat(32),
        },
        generation: 1,
        partitions: BTreeMap::from([(partition.key(), partition.clone())]),
        max_intents: 100,
        max_changes: 10,
        max_state_bytes: 8 << 20,
    };
    installation.validate().unwrap();
    state.lifecycle_control = Some(LifecycleControlState {
        installation: installation.clone(),
        installation_command_id: Uuid::new_v4(),
        installation_revision: 1,
        installation_policy_epoch: 1,
        installation_policy: state.policy.clone(),
        retired: false,
        pending_change: None,
        intents: Default::default(),
        changes: Default::default(),
    });
    let source = Uuid::new_v4();
    let target = Uuid::new_v4();
    let checkpoint = FullBackupCheckpoint {
        tenant: "application".into(),
        source_incarnation: source.to_string(),
        revision: 123,
        resident_sha256: "12".repeat(32),
        backup_id: Uuid::new_v4(),
        manifest_ciphertext_sha256: "34".repeat(32),
        key_lineage_digest: "56".repeat(32),
    };
    let request = RecoveryStart {
        operation_id: Uuid::new_v4(),
        tenant: checkpoint.tenant.clone(),
        source_incarnation: source,
        source_authority_epoch: 1,
        target_incarnation: target,
        checkpoint: checkpoint.clone(),
        source_purpose_sha256: "78".repeat(32),
        source_mode: RecoverySourceMode::SourceUnavailable,
        installation_sha256: staged_digest(&installation).unwrap().0,
        expected_policy_epoch: 1,
        authority_policy_epoch: 1,
        authority_partition: partition.key(),
        dispatch_configuration_sha256: "9a".repeat(32),
        target_nodes: (1..=3)
            .map(|id| {
                (
                    id,
                    LifecycleNode {
                        node_id: id,
                        verifier: kasumi_serving::test_utils::fixture_verifier(id),
                        principal: format!("target-{id}"),
                        certificate_sha256: format!("{id:064x}"),
                        attestation_public_key: format!("{:064x}", id + 100),
                    },
                )
            })
            .collect(),
        materialization: TargetMaterializationInput {
            source_purpose_sha256: "78".repeat(32),
            destination_alias: "backup".into(),
            backup_id: checkpoint.backup_id,
            target_incarnation: target,
            voters: (1..=3)
                .map(|id| {
                    (
                        id,
                        TargetPeer {
                            endpoint: format!("https://target-{id}:7400"),
                            failure_domain: format!("zone-{id}"),
                        },
                    )
                })
                .collect(),
        },
        phase_timeout_ms: 60_000,
    };
    let head = RecoveryRecord {
        request_sha256: request.digest().unwrap(),
        voters: request
            .target_nodes
            .keys()
            .map(|id| (*id, RecoveryVoterProgress::default()))
            .collect(),
        request,
        original_principal: "owner".into(),
        created_revision: 2,
        updated_revision: 3,
        phase: RecoveryPhase::Prepare,
        next_phase_sequence: 1,
        pending_phase: None,
        last_phase: None,
        issuer_preparation: None,
        current_intent: None,
        materialization_intent: None,
        initialization: None,
        completion_intent: None,
        completion_predecessor: None,
        completion_preparation_attempt: None,
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
    };
    head.validate().unwrap();
    let operation = head.request.operation_id;
    state
        .recovery_control
        .operations
        .insert(operation.to_string(), head);
    state
        .recovery_control
        .targets
        .insert(target.to_string(), operation);
    let input = RecoveryDispatch::PublishRoute(RecoveryRouteChange {
        expected_topology_version: 1,
        expected_source_incarnation: source,
        target_incarnation: target,
        target_voters: (1..=3).collect(),
    });
    let phase = RecoveryPhaseRecord {
        operation_id: operation,
        phase_id: Uuid::new_v4(),
        sequence: 1,
        phase: RecoveryPhase::Publish,
        completion_scope: None,
        previous_phase: None,
        input_sha256: staged_digest(&input).unwrap().0,
        input,
        principal: "owner".into(),
        admitted_at_ms: 1000,
        original_credential_expires_at_ms: 2000,
        prepared_revision: 3,
        effect_attempts: BTreeMap::new(),
        activation_acceptance: None,
        outcome: None,
        resolved_revision: None,
    };
    phase.validate().unwrap();
    state
        .recovery_control
        .phases
        .insert(phase.phase_id.to_string(), phase);
    state
}

fn begin_fixture() -> (TenantState, Uuid, Uuid, String) {
    let mut state = coordinator();
    let (id, original) = state.recovery_control.phases.get_min().unwrap();
    let id = (*id).clone();
    let phase_id = Uuid::parse_str(&id).unwrap();
    let mut phase = original.clone();
    let operation_id = phase.operation_id;
    let mut operation = state
        .recovery_control
        .operations
        .get(&operation_id.to_string())
        .unwrap()
        .clone();
    let input = RecoveryDispatch::Authority(Box::new(AuthorityCommand {
        tenant: operation.request.tenant.clone(),
        command_id: phase_id,
        expected_policy_epoch: operation.request.authority_policy_epoch,
        not_after_ms: 1800,
        action: AuthorityAction::PrepareTarget {
            source_incarnation: operation.request.source_incarnation,
            source_epoch: operation.request.source_authority_epoch,
            target: crate::state::recovery::target(&operation.request),
        },
    }));
    phase.phase = RecoveryPhase::Prepare;
    phase.input_sha256 = staged_digest(&input).unwrap().0;
    phase.input = input;
    phase.validate().unwrap();
    operation.phase = RecoveryPhase::Prepare;
    operation.next_phase_sequence = 2;
    operation.pending_phase = Some(phase_id);
    operation.last_phase = Some(phase_id);
    operation.validate().unwrap();
    state
        .recovery_control
        .operations
        .insert(operation_id.to_string(), operation);
    let digest = phase.input_sha256.clone();
    state.recovery_control.phases.insert(id, phase);
    (state, operation_id, phase_id, digest)
}

fn begin_command(
    state: &TenantState,
    operation_id: Uuid,
    phase_id: Uuid,
    digest: String,
    attempt_id: Uuid,
    admitted_at_ms: u64,
) -> crate::state::recovery::RecoveryCommand {
    crate::state::recovery::RecoveryCommand {
        authorization: crate::state::recovery::RecoveryAuthorization {
            context: RequestContext {
                tenant: state.tenant.clone(),
                principal: "owner".into(),
                scopes: [Action::Admin].into_iter().collect(),
                request_id: "begin-effect".into(),
                authorization: RequestAuthorization::service_identity(),
            },
            policy_epoch: state.policy_epoch,
            admitted_at_ms,
            expires_at_ms: 2000,
        },
        mutation: crate::state::recovery::RecoveryMutation::BeginEffect {
            operation_id,
            phase_id,
            effect: RecoveryEffect::AuthorityCommand,
            attempt_id,
            expected_input_sha256: digest,
        },
    }
}

#[test]
fn begin_effect_is_one_way_and_keeps_exact_frozen_identity() {
    let (mut state, operation_id, phase_id, digest) = begin_fixture();
    state.revision = 4;
    let attempt_id = Uuid::new_v4();
    let begin = begin_command(
        &state,
        operation_id,
        phase_id,
        digest.clone(),
        attempt_id,
        1200,
    );
    let committed = crate::state::recovery::apply(&mut state, &begin).unwrap();
    assert_eq!(committed.updated_revision, 4);
    let marker = state.recovery_control.phases[&phase_id.to_string()].effect_attempts
        [&RecoveryEffect::AuthorityCommand]
        .clone();
    assert_eq!(marker.attempt_id, attempt_id);
    assert_eq!(marker.input_sha256, digest);
    assert_eq!(marker.admitted_at_ms, 1200);
    assert_eq!(marker.begun_revision, 4);

    state.revision = 5;
    for replay in [
        begin.clone(),
        begin_command(&state, operation_id, phase_id, digest, Uuid::new_v4(), 1300),
    ] {
        let error = crate::state::recovery::apply(&mut state, &replay).unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        assert_eq!(
            state.recovery_control.phases[&phase_id.to_string()].effect_attempts
                [&RecoveryEffect::AuthorityCommand],
            marker
        );
    }
    let stop = crate::state::recovery::RecoveryCommand {
        authorization: begin.authorization,
        mutation: crate::state::recovery::RecoveryMutation::Stop {
            operation_id,
            command_id: Uuid::new_v4(),
        },
    };
    assert_eq!(
        crate::state::recovery::apply(&mut state, &stop)
            .unwrap_err()
            .code,
        ErrorCode::Conflict,
        "an unresolved issuer effect cannot be stopped into another phase"
    );
    assert_eq!(
        state.recovery_control.phases[&phase_id.to_string()].effect_attempts
            [&RecoveryEffect::AuthorityCommand],
        marker
    );
    assert_eq!(
        state.recovery_control.operations[&operation_id.to_string()].pending_phase,
        Some(phase_id)
    );
}

#[test]
fn source_retirement_marker_blocks_second_begin_and_phase_supersession() {
    let (mut state, operation_id, phase_id, _) = begin_fixture();
    let operation = state.recovery_control.operations[&operation_id.to_string()].clone();
    let request = RetireSourceRequest {
        retirement_id: "recovery-retirement".into(),
        expected_source_incarnation: operation.request.source_incarnation.to_string(),
        target_incarnation: operation.request.target_incarnation.to_string(),
        checkpoint: operation.request.checkpoint.clone(),
        destination: "backup".into(),
        not_after_ms: 1800,
    };
    request.validate().unwrap();
    let mut prepared = state.recovery_control.phases[&phase_id.to_string()].clone();
    prepared.phase = RecoveryPhase::RetireSource;
    prepared.input = RecoveryDispatch::RetireSource(request.clone());
    prepared.input_sha256 = staged_digest(&prepared.input).unwrap().0;
    prepared.validate().unwrap();
    state
        .recovery_control
        .phases
        .insert(phase_id.to_string(), prepared.clone());
    let mut operation = operation;
    operation.phase = RecoveryPhase::RetireSource;
    operation.validate().unwrap();
    state
        .recovery_control
        .operations
        .insert(operation_id.to_string(), operation);
    let mut begin = begin_command(
        &state,
        operation_id,
        phase_id,
        prepared.input_sha256.clone(),
        Uuid::new_v4(),
        1200,
    );
    if let crate::state::recovery::RecoveryMutation::BeginEffect { effect, .. } =
        &mut begin.mutation
    {
        *effect = RecoveryEffect::SourceRetirement;
    }
    let receipt = RetirementReceipt {
        tenant: request.checkpoint.tenant.clone(),
        principal: "source-admin".into(),
        retirement_id: request.retirement_id.clone(),
        request_digest: request.reference().unwrap().request_digest,
        source_incarnation: request.expected_source_incarnation.clone(),
        target_incarnation: request.target_incarnation.clone(),
        revision: 4,
        policy_epoch: 1,
        admitted_at_ms: 1300,
        checkpoint: request.checkpoint.clone(),
        closure_digest: "ab".repeat(32),
    };
    let resolve = crate::state::recovery::RecoveryCommand {
        authorization: begin.authorization.clone(),
        mutation: crate::state::recovery::RecoveryMutation::Resolve {
            operation_id,
            phase_id,
            outcome: Box::new(RecoveryDispatchOutcome::SourceRetired(Box::new(receipt))),
        },
    };
    let before = state.recovery_control.clone();
    state.revision = 4;
    assert_eq!(
        crate::state::recovery::apply(&mut state, &resolve)
            .unwrap_err()
            .code,
        ErrorCode::Conflict,
        "a retirement receipt cannot manufacture an unbegun outcome"
    );
    assert_eq!(state.recovery_control, before);
    assert_eq!(
        crate::state::recovery::apply(&mut state, &begin)
            .unwrap()
            .pending_phase,
        Some(phase_id)
    );
    state.revision = 5;
    assert_eq!(
        crate::state::recovery::apply(&mut state, &begin)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let stop = crate::state::recovery::RecoveryCommand {
        authorization: begin.authorization.clone(),
        mutation: crate::state::recovery::RecoveryMutation::Stop {
            operation_id,
            command_id: Uuid::new_v4(),
        },
    };
    assert_eq!(
        crate::state::recovery::apply(&mut state, &stop)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let replacement = crate::state::recovery::RecoveryCommand {
        authorization: begin.authorization,
        mutation: crate::state::recovery::RecoveryMutation::Prepare {
            operation_id,
            phase_id: Uuid::new_v4(),
            expected_sequence: 2,
            expected_pending: Some(phase_id),
            input: Box::new(RecoveryDispatch::RetireSource(request)),
        },
    };
    assert_eq!(
        crate::state::recovery::apply(&mut state, &replacement)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        state.recovery_control.operations[&operation_id.to_string()].pending_phase,
        Some(phase_id)
    );
}

#[test]
fn begin_effect_rejects_wrong_phase_input_kind_principal_and_original_deadline() {
    let (base, operation_id, phase_id, digest) = begin_fixture();
    let begin = begin_command(&base, operation_id, phase_id, digest, Uuid::new_v4(), 1200);
    let mut cases = Vec::new();
    let mut wrong = begin.clone();
    if let crate::state::recovery::RecoveryMutation::BeginEffect {
        expected_input_sha256,
        ..
    } = &mut wrong.mutation
    {
        *expected_input_sha256 = "00".repeat(32);
    }
    cases.push(wrong);
    let mut wrong = begin.clone();
    if let crate::state::recovery::RecoveryMutation::BeginEffect { phase_id, .. } =
        &mut wrong.mutation
    {
        *phase_id = Uuid::new_v4();
    }
    cases.push(wrong);
    let mut wrong = begin.clone();
    if let crate::state::recovery::RecoveryMutation::BeginEffect { effect, .. } =
        &mut wrong.mutation
    {
        *effect = RecoveryEffect::TargetCommand;
    }
    cases.push(wrong);
    let mut wrong = begin.clone();
    wrong.authorization.context.principal = "another-operator".into();
    cases.push(wrong);
    let mut wrong = begin.clone();
    wrong.authorization.admitted_at_ms = 1800;
    cases.push(wrong);
    for command in cases {
        let mut state = base.clone();
        state.revision = 4;
        let error = crate::state::recovery::apply(&mut state, &command).unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict, "{error}");
        assert_eq!(state.recovery_control, base.recovery_control);
    }
    let mut superseded = base.clone();
    superseded.revision = 4;
    let mut operation = superseded.recovery_control.operations[&operation_id.to_string()].clone();
    operation.pending_phase = None;
    superseded
        .recovery_control
        .operations
        .insert(operation_id.to_string(), operation);
    assert_eq!(
        crate::state::recovery::apply(&mut superseded, &begin)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let mut resolved = base.clone();
    resolved.revision = 4;
    let mut phase = resolved.recovery_control.phases[&phase_id.to_string()].clone();
    phase.outcome = Some(RecoveryDispatchOutcome::RouteRejected {
        observed_topology_version: None,
    });
    phase.resolved_revision = Some(4);
    resolved
        .recovery_control
        .phases
        .insert(phase_id.to_string(), phase);
    assert_eq!(
        crate::state::recovery::apply(&mut resolved, &begin)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
}

#[test]
fn begin_effect_marker_is_required_and_snapshot_monotone() {
    let (mut previous, operation_id, phase_id, digest) = begin_fixture();
    let mut encoded =
        serde_json::to_value(&previous.recovery_control.phases[&phase_id.to_string()]).unwrap();
    encoded.as_object_mut().unwrap().remove("effect_attempts");
    assert!(serde_json::from_value::<RecoveryPhaseRecord>(encoded).is_err());
    let mut encoded =
        serde_json::to_value(&previous.recovery_control.phases[&phase_id.to_string()]).unwrap();
    encoded
        .as_object_mut()
        .unwrap()
        .remove("activation_acceptance");
    assert!(serde_json::from_value::<RecoveryPhaseRecord>(encoded).is_err());
    let mut incoming = previous.clone();
    incoming.revision = 4;
    let begin = begin_command(
        &incoming,
        operation_id,
        phase_id,
        digest,
        Uuid::new_v4(),
        1200,
    );
    crate::state::recovery::apply(&mut incoming, &begin).unwrap();
    crate::state::recovery::validate_successor(&previous, &incoming).unwrap();
    previous = incoming.clone();
    let mut erased = incoming.clone();
    erased.revision += 1;
    let mut phase = erased.recovery_control.phases[&phase_id.to_string()].clone();
    phase.effect_attempts.clear();
    erased
        .recovery_control
        .phases
        .insert(phase_id.to_string(), phase);
    assert_eq!(
        crate::state::recovery::validate_successor(&previous, &erased)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let mut substituted = incoming;
    substituted.revision += 1;
    let mut phase = substituted.recovery_control.phases[&phase_id.to_string()].clone();
    phase
        .effect_attempts
        .get_mut(&RecoveryEffect::AuthorityCommand)
        .unwrap()
        .attempt_id = Uuid::new_v4();
    substituted
        .recovery_control
        .phases
        .insert(phase_id.to_string(), phase);
    assert_eq!(
        crate::state::recovery::validate_successor(&previous, &substituted)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
}

#[test]
fn control_intent_marker_after_original_phase_timeout_is_invalid_history() {
    let (mut incoming, operation_id, phase_id, _) = begin_fixture();
    let mut operation = incoming.recovery_control.operations[&operation_id.to_string()].clone();
    operation.request.phase_timeout_ms = 100;
    operation.request_sha256 = operation.request.digest().unwrap();
    operation.updated_revision = 4;
    operation.validate().unwrap();
    let control = crate::state::recovery::expected_intent(
        &incoming,
        &operation,
        phase_id,
        incoming.policy_epoch,
        LifecyclePhase::Materialize,
    )
    .unwrap();
    let mut phase = incoming.recovery_control.phases[&phase_id.to_string()].clone();
    phase.input = RecoveryDispatch::ControlIntent(Box::new(control));
    phase.input_sha256 = staged_digest(&phase.input).unwrap().0;
    phase.effect_attempts.insert(
        RecoveryEffect::ControlIntent,
        RecoveryEffectAttempt {
            attempt_id: Uuid::new_v4(),
            input_sha256: phase.input_sha256.clone(),
            admitted_at_ms: 1200,
            begun_revision: 4,
        },
    );
    // All record-local limits pass: the missing bound is the operation's
    // original 100 ms phase timeout (1000 + 100), not credential expiry.
    phase.validate().unwrap();
    incoming
        .recovery_control
        .operations
        .insert(operation_id.to_string(), operation);
    incoming
        .recovery_control
        .phases
        .insert(phase_id.to_string(), phase);
    incoming.revision = 4;
    let error = crate::state::recovery::validate(&incoming).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(error.message.contains("original phase timeout"), "{error}");

    let mut previous = incoming.clone();
    previous.revision = 3;
    let mut operation = previous.recovery_control.operations[&operation_id.to_string()].clone();
    operation.updated_revision = 3;
    previous
        .recovery_control
        .operations
        .insert(operation_id.to_string(), operation);
    let mut phase = previous.recovery_control.phases[&phase_id.to_string()].clone();
    phase.effect_attempts.clear();
    previous
        .recovery_control
        .phases
        .insert(phase_id.to_string(), phase);
    let error = crate::state::recovery::validate_successor(&previous, &incoming).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(error.message.contains("original phase timeout"), "{error}");
}

fn image(
    disk: &Arc<kasumi_store::ScratchDisk>,
    state: &TenantState,
) -> kasumi_store::SnapshotImage {
    let mut spool = kasumi_store::EncryptedSpool::new(disk, 16 << 20).unwrap();
    let terminals = crate::staged_terminal::View::empty(&state.tenant, &state.incarnation).unwrap();
    let target_resolutions =
        crate::target_resolution::View::empty(&state.tenant, &state.incarnation).unwrap();
    write(
        state,
        &crate::mutation_receipt::View::empty(&state.tenant, &state.incarnation).unwrap(),
        &crate::backup_binding::View::empty(&state.incarnation).unwrap(),
        &terminals,
        &target_resolutions,
        &mut spool,
    )
    .unwrap();
    kasumi_store::SnapshotImage::freeze(spool).unwrap()
}

#[test]
fn canonical_recovery_records_roundtrip_and_point_accounting_match_stream() {
    let scratch = crate::codec_fixture::ScratchScope::new(
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
    )
    .unwrap();
    let disk = &scratch.disk;
    // This test covers the codec and accounting, not coordinator phase semantics.
    let previous = coordinator();
    let before = crate::accounting::SnapshotAccounting::rebuild(&previous).unwrap();
    let source = image(disk, &previous);
    assert_eq!(before.bytes(&previous).unwrap() as u64, source.len());
    let decoded = read(source.disk(), &mut source.reader()).unwrap();
    assert_eq!(decoded.state.recovery_control, previous.recovery_control);
    let indexed = crate::snapshot_index::StagedSnapshot::new(source, 64 << 20, || Ok(())).unwrap();
    for kind in 18..=20 {
        assert_eq!(indexed.count(kind).unwrap(), 1);
    }
    assert_eq!(indexed.count(21).unwrap(), 0);
    let mut next = previous.clone();
    next.revision += 1;
    let (_, phase) = next.recovery_control.phases.get_min().unwrap();
    let mut phase = phase.clone();
    phase.outcome = Some(RecoveryDispatchOutcome::RoutePublished {
        revision: next.revision,
    });
    phase.resolved_revision = Some(next.revision);
    next.recovery_control
        .phases
        .insert(phase.phase_id.to_string(), phase);
    let accounting = before
        .updated(&previous, &next, &Default::default(), &Default::default())
        .unwrap();
    assert_eq!(
        accounting.bytes(&next).unwrap() as u64,
        image(disk, &next).len()
    );
    assert_eq!(
        accounting.bytes(&next).unwrap(),
        crate::accounting::SnapshotAccounting::rebuild(&next)
            .unwrap()
            .bytes(&next)
            .unwrap()
    );
    next.recovery_control = Default::default();
    let accounting = before
        .updated(&previous, &next, &Default::default(), &Default::default())
        .unwrap();
    assert_eq!(
        accounting.bytes(&next).unwrap() as u64,
        image(disk, &next).len()
    );
}

#[test]
fn application_backup_rejects_control_recovery_and_embedded_or_orphan_records() {
    let scratch = crate::codec_fixture::ScratchScope::new(
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
    )
    .unwrap();
    let disk = &scratch.disk;
    let state = coordinator();
    let error = crate::state::snapshot_validation::ValidatedApplicationSnapshot::validate(
        image(disk, &state),
        64 << 20,
        || Ok(()),
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("Control state"));
    let mut embedded = metadata(&state);
    embedded.recovery_control = state.recovery_control.clone();
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes).unwrap();
    encoder.record(Record::Header(Box::new(embedded))).unwrap();
    encoder.finish().unwrap();
    assert!(read(disk, &mut bytes.as_slice()).is_err());
    let mut orphan = state.clone();
    orphan.recovery_control.operations.clear();
    let orphan = image(disk, &orphan);
    assert!(read(orphan.disk(), &mut orphan.reader()).is_err());
    let mut wrong_key = state;
    let (_, record) = wrong_key.recovery_control.phases.get_min().unwrap();
    let record = record.clone();
    wrong_key.recovery_control.phases.clear();
    wrong_key
        .recovery_control
        .phases
        .insert(Uuid::new_v4().to_string(), record);
    let wrong_key = image(disk, &wrong_key);
    assert!(read(wrong_key.disk(), &mut wrong_key.reader()).is_err());
}

#[test]
fn completion_history_stream_is_resident_and_counts_in_snapshot_admission_and_quota() {
    let scratch = crate::codec_fixture::ScratchScope::new(
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
    )
    .unwrap();
    let disk = &scratch.disk;
    let previous = coordinator();
    let previous_image = image(disk, &previous);
    let before_summary = inspect(&mut previous_image.reader()).unwrap();
    let before = crate::accounting::SnapshotAccounting::rebuild(&previous).unwrap();
    let mut state = previous.clone();
    let operation_id = state
        .recovery_control
        .operations
        .get_min()
        .unwrap()
        .1
        .request
        .operation_id;
    // This is an actual canonical closed-history record belonging to the
    // existing coordinator operation. This codec test does not assert phase
    // protocol validity of the individually non-nil historical point IDs.
    let history = RecoveryCompletionHistory {
        operation_id,
        scope: RecoveryCompletionScope {
            intent: Uuid::new_v4(),
            predecessor: None,
        },
        current_intent: Uuid::new_v4(),
        preparation_attempt: Uuid::new_v4(),
        preparation: Uuid::new_v4(),
        resolution_attempt: Uuid::new_v4(),
        terminal: Uuid::new_v4(),
        attempted_completion: Some(Uuid::new_v4()),
        successor_intent: Uuid::new_v4(),
    };
    history.validate().unwrap();
    let key = history.scope.intent.to_string();
    let framed_bytes = (serde_json::to_vec(&Record::RecoveryCompletionHistory(
        key.clone(),
        Box::new(history.clone()),
    ))
    .unwrap()
    .len()
        + FRAME_HEADER_BYTES) as u64;
    state
        .recovery_control
        .completion_history
        .insert(key.clone(), history.clone());
    let source = image(disk, &state);
    let summary = inspect(&mut source.reader()).unwrap();
    let verified = visit(&mut source.reader(), |_, _| Ok(())).unwrap();
    assert_eq!(summary, verified);
    assert_eq!(summary.kinds[23].records, 1);
    assert_eq!(summary.kinds[23].framed_bytes, framed_bytes);
    assert_eq!(summary.resident_bytes().unwrap(), source.len());
    assert_eq!(
        summary.resident_bytes().unwrap(),
        before_summary.resident_bytes().unwrap() + framed_bytes
    );
    assert_eq!(
        summary.materialization_workspace().unwrap(),
        3 * source.len() + summary.maximum_decode_work() + (64 << 20)
    );
    let decoded = read(source.disk(), &mut source.reader()).unwrap();
    assert_eq!(decoded.state.recovery_control, state.recovery_control);
    assert_eq!(
        decoded.state.recovery_control.completion_history[&key],
        history
    );
    let incremental = before
        .updated(&previous, &state, &Default::default(), &Default::default())
        .unwrap();
    let rebuilt = crate::accounting::SnapshotAccounting::rebuild(&state).unwrap();
    assert_eq!(
        incremental.bytes(&state).unwrap(),
        rebuilt.bytes(&state).unwrap()
    );
    assert_eq!(incremental.bytes(&state).unwrap() as u64, source.len());
    assert_eq!(
        crate::test_utils::snapshot_accounted_bytes(&source).unwrap(),
        incremental.bytes(&state).unwrap() as u64
    );
}

/// A pure reducer fixture with real Control and issuer signatures. The
/// surrounding recovery journal is intentionally minimal; full activation
/// causality and native dispatch are exercised by the replicated tests.
fn signed_activation_acceptance_fixture() -> (
    TenantState,
    Uuid,
    Uuid,
    kasumi_serving::SignedLifecycleAuthorityReceipt,
    kasumi_serving::GenerationSigner,
) {
    use ring::signature::{Ed25519KeyPair, KeyPair};

    let (mut state, operation_id, phase_id, _) = begin_fixture();
    let random = ring::rand::SystemRandom::new();
    let control_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
    let control_key = Ed25519KeyPair::from_pkcs8(control_pkcs8.as_ref()).unwrap();
    let root = ControlSigningRoot {
        control_incarnation: Uuid::parse_str(&state.incarnation).unwrap(),
        public_key: hex::encode(control_key.public_key().as_ref()),
    };
    let issuer_root_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
    let issuer_root = Ed25519KeyPair::from_pkcs8(issuer_root_pkcs8.as_ref()).unwrap();
    let issuer_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
    let issuer_key = Ed25519KeyPair::from_pkcs8(issuer_pkcs8.as_ref()).unwrap();
    let mut installation = state
        .lifecycle_control
        .as_ref()
        .unwrap()
        .installation
        .clone();
    let mut partition = installation.partitions.values().next().unwrap().clone();
    partition.signing_public_key = hex::encode(issuer_root.public_key().as_ref());
    installation.root = root.clone();
    installation.partitions = BTreeMap::from([(partition.key(), partition.clone())]);
    installation.validate().unwrap();
    state.lifecycle_control.as_mut().unwrap().installation = installation.clone();
    let signing_generation = SigningGeneration {
        domain: SigningDomain {
            authority_id: partition.authority_id,
            partition: partition.partition,
            manifest_sha256: partition.manifest_sha256.clone(),
            root_public_key: partition.signing_public_key.clone(),
            retirement_drain_ms: partition.drain_ms,
        },
        generation: 1,
        public_key: hex::encode(issuer_key.public_key().as_ref()),
    };
    let certificate = SigningCertificate {
        root_signature: hex::encode(
            issuer_root
                .sign(
                    &serde_json::to_vec(&("kasumi.signing-certificate.v1", &signing_generation))
                        .unwrap(),
                )
                .as_ref(),
        ),
        identity: signing_generation,
    };
    let issuer_signer =
        kasumi_serving::GenerationSigner::from_pkcs8(certificate, issuer_pkcs8.as_ref()).unwrap();

    let mut operation = state.recovery_control.operations[&operation_id.to_string()].clone();
    operation.request.installation_sha256 = staged_digest(&installation).unwrap().0;
    operation.request_sha256 = operation.request.digest().unwrap();
    operation.phase = RecoveryPhase::Activate;
    operation.activation_attempt = Some(phase_id);
    // The synthetic history must leave a distinct committed revision between
    // Prepare and Resolve for the Control-intent one-use dispatch marker.
    operation.created_revision = 1;
    let control_id = Uuid::new_v4();
    operation.current_intent = Some(control_id);
    operation.next_phase_sequence = 3;
    operation.validate().unwrap();
    state
        .recovery_control
        .operations
        .insert(operation_id.to_string(), operation.clone());
    let control_request = CommitLifecycleIntent {
        command_id: control_id,
        expected_policy_epoch: state.policy_epoch,
        installation_sha256: operation.request.installation_sha256.clone(),
        authority_partition: partition.key(),
        tenant: operation.request.tenant.clone(),
        source_incarnation: operation.request.source_incarnation,
        source_authority_epoch: operation.request.source_authority_epoch,
        target_incarnation: operation.request.target_incarnation,
        checkpoint: operation.request.checkpoint.clone(),
        target_nodes: operation.request.target_nodes.clone(),
        phase: LifecyclePhase::Activate,
        phase_input_sha256: "ee".repeat(32),
        resume_origin: None,
    };
    control_request.validate().unwrap();
    let control_intent = LifecycleIntent {
        request_sha256: staged_digest(&control_request).unwrap().0,
        request: control_request,
        control_incarnation: root.control_incarnation,
        installation_generation: installation.generation,
        original_principal: "owner".into(),
        original_credential_expires_at_ms: 2000,
        accepted_at_ms: 1000,
        revision: 3,
    };
    state
        .lifecycle_control
        .as_mut()
        .unwrap()
        .intents
        .insert(control_id, control_intent.clone());
    // The issuer receipt may name only a Control intent already retained as an
    // exact recovery phase outcome. A lifecycle map entry alone is insufficient.
    let control_input = RecoveryDispatch::ControlIntent(Box::new(control_intent.request.clone()));
    let control_digest = staged_digest(&control_input).unwrap().0;
    let control_phase = RecoveryPhaseRecord {
        operation_id,
        phase_id: control_id,
        sequence: 1,
        phase: RecoveryPhase::Activate,
        completion_scope: None,
        previous_phase: None,
        input_sha256: control_digest.clone(),
        input: control_input,
        principal: "owner".into(),
        admitted_at_ms: 900,
        original_credential_expires_at_ms: 2000,
        prepared_revision: 1,
        effect_attempts: BTreeMap::from([(
            RecoveryEffect::ControlIntent,
            RecoveryEffectAttempt {
                attempt_id: Uuid::new_v4(),
                input_sha256: control_digest,
                admitted_at_ms: 950,
                begun_revision: 2,
            },
        )]),
        activation_acceptance: None,
        outcome: Some(RecoveryDispatchOutcome::ControlIntent(Box::new(
            control_intent.clone(),
        ))),
        resolved_revision: Some(3),
    };
    control_phase.validate().unwrap();
    state
        .recovery_control
        .phases
        .insert(control_id.to_string(), control_phase);
    let observation = ControlIntentCommitment {
        intent: control_intent,
        root: root.clone(),
        authority_partition: partition.clone(),
        partition_set_sha256: staged_digest(&installation.partitions).unwrap().0,
        observed_policy_epoch: state.policy_epoch,
        observed_revision: 3,
        observed_term: 2,
    };
    let signed_control = SignedControlIntent {
        signature: hex::encode(
            control_key
                .sign(
                    &serde_json::to_vec(&("kasumi.committed-control-intent.v1", &observation))
                        .unwrap(),
                )
                .as_ref(),
        ),
        observation,
    };
    kasumi_serving::ControlTrust::install(root)
        .unwrap()
        .verify_intent(&signed_control)
        .unwrap();
    let request = kasumi_serving::LifecycleAuthorityRequest::AcceptIntent(Box::new(signed_control));
    let control = CommittedActivation {
        completion: {
            let origin = crate::target_completion_machine::tests::origin();
            let attempt =
                crate::target_completion_machine::tests::attempt(&origin, None, 12, 1, 200, 500);
            let fact = crate::target_completion_machine::tests::completion(&attempt);
            let observation = TargetCompletionObservation {
                observer_node_id: 1,
                observed_revision: fact.revision,
                observed_term: fact.term,
                fact,
            };
            Box::new(CommittedCompletion::Original(Box::new(
                SignedTargetCompletion {
                    signature: crate::target_completion_machine::tests::sign(
                        &observation,
                        "kasumi.completed-target.v1",
                        1,
                    ),
                    observation,
                },
            )))
        },
        reference: request.reference(),
        intent_sha256: request.digest().unwrap(),
    };
    let input = RecoveryDispatch::Authority(Box::new(AuthorityCommand {
        tenant: operation.request.tenant.clone(),
        command_id: phase_id,
        expected_policy_epoch: operation.request.authority_policy_epoch,
        not_after_ms: 1800,
        action: AuthorityAction::ActivateCommitted {
            fence_id: Uuid::new_v4(),
            fence_digest: "fe".repeat(32),
            target: crate::state::recovery::target(&operation.request),
            control,
        },
    }));
    let mut phase = state.recovery_control.phases[&phase_id.to_string()].clone();
    phase.phase = RecoveryPhase::Activate;
    phase.sequence = 2;
    phase.previous_phase = Some(control_id);
    phase.input_sha256 = staged_digest(&input).unwrap().0;
    phase.input = input;
    phase.validate().unwrap();
    state
        .recovery_control
        .phases
        .insert(phase_id.to_string(), phase);
    let receipt = kasumi_serving::LifecycleAuthorityReceipt {
        authority_id: partition.authority_id,
        authority_manifest_sha256: partition.manifest_sha256,
        partition: partition.partition,
        reference: request.reference(),
        request_sha256: request.digest().unwrap(),
        request,
        // The issuer Admin principal differs from the Control Admin principal.
        original_principal: "issuer-admin".into(),
        accepted_revision: 8,
        accepted_term: 3,
    };
    let signed = kasumi_serving::SignedLifecycleAuthorityReceipt {
        signature: issuer_signer
            .sign("kasumi.issuer-control-receipt.v1", &receipt)
            .unwrap(),
        receipt,
    };
    (state, operation_id, phase_id, signed, issuer_signer)
}

fn activation_effect_command(
    state: &TenantState,
    operation_id: Uuid,
    phase_id: Uuid,
    effect: RecoveryEffect,
    attempt_id: Uuid,
) -> crate::state::recovery::RecoveryCommand {
    let digest = state.recovery_control.phases[&phase_id.to_string()]
        .input_sha256
        .clone();
    let mut command = begin_command(state, operation_id, phase_id, digest, attempt_id, 1200);
    let crate::state::recovery::RecoveryMutation::BeginEffect { effect: kind, .. } =
        &mut command.mutation
    else {
        unreachable!()
    };
    *kind = effect;
    command
}

fn acceptance_commit_command(
    state: &TenantState,
    operation_id: Uuid,
    phase_id: Uuid,
    attempt_id: Uuid,
    signed: kasumi_serving::SignedLifecycleAuthorityReceipt,
) -> crate::state::recovery::RecoveryCommand {
    let mut command = activation_effect_command(
        state,
        operation_id,
        phase_id,
        RecoveryEffect::ActivationIntentAcceptance,
        attempt_id,
    );
    command.mutation = crate::state::recovery::RecoveryMutation::CommitActivationAcceptance {
        operation_id,
        phase_id,
        attempt_id,
        signed_receipt: Box::new(signed),
    };
    command
}

#[test]
fn activation_requires_committed_positive_signed_acceptance_before_issuer_begin() {
    let (mut state, operation_id, phase_id, signed, _) = signed_activation_acceptance_fixture();
    let acceptance_id = Uuid::new_v4();
    let acceptance = activation_effect_command(
        &state,
        operation_id,
        phase_id,
        RecoveryEffect::ActivationIntentAcceptance,
        acceptance_id,
    );
    state.revision = 4;
    crate::state::recovery::apply(&mut state, &acceptance).unwrap();
    state.revision = 5;
    let authority = activation_effect_command(
        &state,
        operation_id,
        phase_id,
        RecoveryEffect::AuthorityCommand,
        Uuid::new_v4(),
    );
    assert_eq!(
        crate::state::recovery::apply(&mut state, &authority)
            .unwrap_err()
            .code,
        ErrorCode::Conflict,
        "marker-only acceptance cannot authorize issuer activation"
    );
    let commit = acceptance_commit_command(&state, operation_id, phase_id, acceptance_id, signed);
    crate::state::recovery::apply(&mut state, &commit).unwrap();
    let retained = &state.recovery_control.phases[&phase_id.to_string()];
    let evidence = retained.activation_acceptance.as_ref().unwrap();
    assert_eq!(evidence.attempt_id, acceptance_id);
    assert_eq!(evidence.committed_revision, 5);
    assert_eq!(retained.effect_attempts.len(), 1);
    assert_eq!(
        crate::state::recovery::apply(&mut state, &commit)
            .unwrap_err()
            .code,
        ErrorCode::Conflict,
        "acceptance commitment is one-way"
    );
    state.revision = 6;
    crate::state::recovery::apply(&mut state, &authority).unwrap();
    assert_eq!(
        state.recovery_control.phases[&phase_id.to_string()]
            .effect_attempts
            .len(),
        2
    );
}

#[test]
fn activation_acceptance_rejects_wrong_attempt_binding_and_forged_signed_evidence() {
    let (mut state, operation_id, phase_id, signed, signer) =
        signed_activation_acceptance_fixture();
    let acceptance_id = Uuid::new_v4();
    state.revision = 4;
    let begin = activation_effect_command(
        &state,
        operation_id,
        phase_id,
        RecoveryEffect::ActivationIntentAcceptance,
        acceptance_id,
    );
    crate::state::recovery::apply(&mut state, &begin).unwrap();
    state.revision = 5;
    let mut wrong_reference = signed.clone();
    wrong_reference.receipt.reference.identity = LifecycleAuthorityIdentity::Intent(Uuid::new_v4());
    wrong_reference.signature = signer
        .sign("kasumi.issuer-control-receipt.v1", &wrong_reference.receipt)
        .unwrap();
    let mut wrong_digest = signed.clone();
    wrong_digest.receipt.request_sha256 = "ab".repeat(32);
    wrong_digest.signature = signer
        .sign("kasumi.issuer-control-receipt.v1", &wrong_digest.receipt)
        .unwrap();
    let mut forged_control = signed.clone();
    let kasumi_serving::LifecycleAuthorityRequest::AcceptIntent(control) =
        &mut forged_control.receipt.request
    else {
        unreachable!()
    };
    control.signature = "00".repeat(64);
    forged_control.signature = signer
        .sign("kasumi.issuer-control-receipt.v1", &forged_control.receipt)
        .unwrap();
    let mut forged_issuer = signed.clone();
    forged_issuer.signature.signature = "00".repeat(64);
    // The exact signed receipt must succeed from the same pre-commit state;
    // otherwise the rejected cases below could all be failing on a bad fixture.
    let valid = acceptance_commit_command(
        &state,
        operation_id,
        phase_id,
        acceptance_id,
        signed.clone(),
    );
    let mut positive = state.clone();
    crate::state::recovery::apply(&mut positive, &valid).unwrap();
    assert!(
        positive.recovery_control.phases[&phase_id.to_string()]
            .activation_acceptance
            .is_some()
    );
    for (label, attempt_id, evidence, expected_code) in [
        (
            "wrong attempt",
            Uuid::new_v4(),
            signed.clone(),
            ErrorCode::Conflict,
        ),
        (
            "wrong reference",
            acceptance_id,
            wrong_reference,
            ErrorCode::Conflict,
        ),
        (
            "wrong digest",
            acceptance_id,
            wrong_digest,
            ErrorCode::Conflict,
        ),
        (
            "forged Control signature",
            acceptance_id,
            forged_control,
            ErrorCode::Forbidden,
        ),
        (
            "forged issuer signature",
            acceptance_id,
            forged_issuer,
            ErrorCode::Forbidden,
        ),
    ] {
        let mut trial = state.clone();
        let command =
            acceptance_commit_command(&trial, operation_id, phase_id, attempt_id, evidence);
        let error = crate::state::recovery::apply(&mut trial, &command).unwrap_err();
        assert_eq!(error.code, expected_code, "{label}: {error}");
        assert_eq!(trial.recovery_control, state.recovery_control, "{label}");
    }
    let mut missing_intent_phase = state.clone();
    let LifecycleAuthorityIdentity::Intent(control_id) = &signed.receipt.reference.identity else {
        unreachable!()
    };
    missing_intent_phase
        .recovery_control
        .phases
        .remove(&control_id.to_string());
    assert_eq!(
        crate::state::recovery::apply(&mut missing_intent_phase, &valid)
            .unwrap_err()
            .code,
        ErrorCode::Corruption,
        "issuer acceptance requires an exact committed recovery Control-intent phase"
    );
}

#[test]
fn signed_activation_acceptance_is_snapshot_monotone_and_requires_explicit_field() {
    let (mut state, operation_id, phase_id, signed, _) = signed_activation_acceptance_fixture();
    let mut encoded =
        serde_json::to_value(&state.recovery_control.phases[&phase_id.to_string()]).unwrap();
    encoded
        .as_object_mut()
        .unwrap()
        .remove("activation_acceptance");
    assert!(serde_json::from_value::<RecoveryPhaseRecord>(encoded).is_err());
    let acceptance_id = Uuid::new_v4();
    state.revision = 4;
    let begin = activation_effect_command(
        &state,
        operation_id,
        phase_id,
        RecoveryEffect::ActivationIntentAcceptance,
        acceptance_id,
    );
    crate::state::recovery::apply(&mut state, &begin).unwrap();
    let before = state.clone();
    state.revision = 5;
    let commit = acceptance_commit_command(&state, operation_id, phase_id, acceptance_id, signed);
    crate::state::recovery::apply(&mut state, &commit).unwrap();
    crate::state::recovery::validate_successor(&before, &state).unwrap();
    let accepted = state.clone();
    let mut erased = accepted.clone();
    erased.revision = 6;
    let mut phase = erased.recovery_control.phases[&phase_id.to_string()].clone();
    phase.activation_acceptance = None;
    erased
        .recovery_control
        .phases
        .insert(phase_id.to_string(), phase);
    assert_eq!(
        crate::state::recovery::validate_successor(&accepted, &erased)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let mut substituted = accepted.clone();
    substituted.revision = 6;
    let mut phase = substituted.recovery_control.phases[&phase_id.to_string()].clone();
    phase
        .activation_acceptance
        .as_mut()
        .unwrap()
        .signed_receipt_sha256 = "ff".repeat(32);
    substituted
        .recovery_control
        .phases
        .insert(phase_id.to_string(), phase);
    assert_eq!(
        crate::state::recovery::validate_successor(&accepted, &substituted)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
}
