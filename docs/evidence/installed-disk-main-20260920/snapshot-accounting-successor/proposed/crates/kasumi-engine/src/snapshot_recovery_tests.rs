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
