//! Actual replicated Control journal tests. Issuer and node signatures below
//! are explicit cryptographic fixtures; encrypted target execution is covered
//! separately by the authority materialization tests.
use super::*;

fn request(f: &Fixture) -> RecoveryStart {
    let intent = f.intent(
        f.nodes[&1]
            .engine()
            .generation()
            .unwrap()
            .state
            .policy_epoch,
    );
    RecoveryStart {
        operation_id: Uuid::new_v4(),
        tenant: intent.tenant.clone(),
        source_incarnation: intent.source_incarnation,
        source_authority_epoch: intent.source_authority_epoch,
        target_incarnation: intent.target_incarnation,
        checkpoint: intent.checkpoint.clone(),
        source_purpose_sha256: "78".repeat(32),
        source_mode: RecoverySourceMode::SourceUnavailable,
        installation_sha256: intent.installation_sha256,
        expected_policy_epoch: intent.expected_policy_epoch,
        authority_policy_epoch: 7,
        authority_partition: intent.authority_partition,
        dispatch_configuration_sha256: "90".repeat(32),
        target_nodes: intent.target_nodes,
        materialization: TargetMaterializationInput {
            destination_alias: "backup".into(),
            backup_id: intent.checkpoint.backup_id,
            source_purpose_sha256: "78".repeat(32),
            target_incarnation: intent.target_incarnation,
            voters: (1..=3)
                .map(|id| {
                    (
                        id,
                        TargetPeer {
                            endpoint: format!("https://target-{id}.example:8443"),
                            failure_domain: format!("zone-{id}"),
                        },
                    )
                })
                .collect(),
        },
        phase_timeout_ms: 60_000,
    }
}
fn prepare_receipt(f: &Fixture, input: &RecoveryDispatch) -> SignedAuthorityReceipt {
    let RecoveryDispatch::Authority(command) = input else {
        panic!("issuer command required")
    };
    let AuthorityAction::PrepareTarget { target, .. } = &command.action else {
        panic!("preparation required")
    };
    let partition = &f.installation.partitions[&f.intent(1).authority_partition];
    let receipt = AuthorityReceipt {
        authority_id: partition.authority_id,
        manifest_digest: partition.manifest_sha256.clone(),
        partition: partition.partition,
        command: command.as_ref().clone(),
        command_digest: command.digest().unwrap(),
        principal: "issuer-admin".into(),
        term: 3,
        revision: 10,
        admitted_at_ms: command.not_after_ms - 1,
        outcome: AuthorityOutcome::TargetPrepared {
            target: target.clone(),
            authority_epoch: 2,
        },
    };
    let signature = f.partition_keys[&partition.key()]
        .sign("kasumi.authority-proof.v1", &receipt)
        .unwrap();
    SignedAuthorityReceipt { receipt, signature }
}
async fn snapshot(db: &Arc<Database>) {
    let mut bytes = Vec::new();
    db.engine()
        .capture_snapshot()
        .unwrap()
        .write(&mut bytes)
        .unwrap();
    db.engine()
        .validate_snapshot(&mut bytes.as_slice())
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_journal_persists_before_dispatch_rejects_substitution_and_recovers_ambiguous_control_commit()
 {
    exercise_completed_recovery(false, None, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_planned_retirement_freezes_its_exact_request_only_after_target_completion() {
    exercise_completed_recovery(true, None, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_uncertain_activation_resolves_original_winner_and_confirms_every_voter_forward() {
    exercise_completed_recovery(false, Some(true), false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_uncertain_activation_requires_permanent_stop_before_target_cleanup() {
    exercise_completed_recovery(false, Some(false), false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_expired_completion_resolves_its_exact_positive_fact_before_activation() {
    exercise_completed_recovery(false, Some(true), true).await;
}
/// Transfer the exact live fixture only after the completion/activation future
/// has returned. Polling route publication inside that large future composes
/// both debug poll frames on the same thread and can exhaust its normal stack.
struct RoutePublicationFixture {
    fixture: Fixture,
    database: Arc<Database>,
    request: RecoveryStart,
}
async fn exercise_completed_recovery(
    planned: bool,
    activation_outcome: Option<bool>,
    inspect_completion: bool,
) {
    let route = {
        let completed = Box::pin(complete_recovery(
            planned,
            activation_outcome,
            inspect_completion,
        ));
        completed.await
    };
    if let Some(RoutePublicationFixture {
        mut fixture,
        database,
        request,
    }) = route
    {
        // The old future and its poll frame are gone; this moves the same
        // storage owners and original request into the next phase. No detached
        // task, replacement authorization or altered deadline is introduced.
        Box::pin(exercise_route_publication(&mut fixture, database, &request)).await;
    }
}
async fn complete_recovery(
    planned: bool,
    activation_outcome: Option<bool>,
    inspect_completion: bool,
) -> Option<RoutePublicationFixture> {
    let mut f = if activation_outcome == Some(true) {
        Fixture::new().await
    } else {
        Fixture::new().await
    };
    let mut request = request(&f);
    let mut attestation = BTreeMap::new();
    for node in request.target_nodes.values_mut() {
        let pair = key();
        node.attestation_public_key = hex::encode(pair.public_key().as_ref());
        attestation.insert(node.node_id, pair);
    }
    if planned {
        request.source_mode = RecoverySourceMode::Planned {
            retirement_id: format!("retirement-{}", request.operation_id),
            source_backup_destination: "source-backup".into(),
        };
    }
    let id = request.operation_id;
    let db = f.leader().await;
    assert!(
        db.recovery_control(
            f.context("intruder"),
            RecoveryControlCommand::Start(Box::new(request.clone()))
        )
        .await
        .is_err()
    );
    let started = db
        .recovery_control(
            f.context("owner"),
            RecoveryControlCommand::Start(Box::new(request.clone())),
        )
        .await
        .unwrap();
    assert_eq!(started.record().phase, RecoveryPhase::Prepare);
    let created = started.record().created_revision;
    drop(started);
    assert_eq!(
        db.recovery_control(
            f.context("owner"),
            RecoveryControlCommand::Start(Box::new(request.clone()))
        )
        .await
        .unwrap()
        .record()
        .created_revision,
        created
    );
    let mut alias = request.clone();
    alias.operation_id = Uuid::new_v4();
    alias.dispatch_configuration_sha256 = "92".repeat(32);
    assert_eq!(
        db.recovery_control(
            f.context("owner"),
            RecoveryControlCommand::Start(Box::new(alias))
        )
        .await
        .err()
        .unwrap()
        .code,
        ErrorCode::Conflict
    );
    let phase_id = Uuid::new_v4();
    let input = db
        .next_recovery_dispatch(&f.context("owner"), id, phase_id)
        .await
        .unwrap()
        .unwrap();
    let prepared = db
        .prepare_recovery_dispatch(f.context("owner"), id, phase_id, 1, None, input.clone())
        .await
        .unwrap();
    assert!(prepared.record().outcome.is_none());
    prepared.admit_dispatch().await.unwrap();
    let prepared_revision = prepared.record().prepared_revision;
    drop(prepared);
    let mut substitution = input.clone();
    let RecoveryDispatch::Authority(command) = &mut substitution else {
        unreachable!()
    };
    command.not_after_ms += 1;
    assert_eq!(
        db.prepare_recovery_dispatch(f.context("owner"), id, phase_id, 1, None, substitution)
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        db.prepare_recovery_dispatch(f.context("owner"), id, phase_id, 1, None, input.clone())
            .await
            .unwrap()
            .record()
            .prepared_revision,
        prepared_revision
    );
    let signed = prepare_receipt(&f, &input);
    let mut forged = signed.clone();
    forged.receipt.command.command_id = Uuid::new_v4();
    assert!(
        db.resolve_recovery_dispatch(
            f.context("owner"),
            id,
            phase_id,
            RecoveryDispatchOutcome::Authority(Box::new(forged))
        )
        .await
        .is_err()
    );
    let materialize = resolve_phase(
        &f,
        id,
        phase_id,
        RecoveryDispatchOutcome::Authority(Box::new(signed)),
    )
    .await;
    assert_eq!(materialize.record().phase, RecoveryPhase::Materialize);
    let sequence = materialize.record().next_phase_sequence;
    drop(materialize);
    let intent_phase = Uuid::new_v4();
    let input = db
        .next_recovery_dispatch(&f.context("owner"), id, intent_phase)
        .await
        .unwrap()
        .unwrap();
    let RecoveryDispatch::ControlIntent(commit) = &input else {
        panic!("materialization Control intent required")
    };
    let invocation = f.context("owner");
    db.prepare_recovery_dispatch(
        invocation.clone(),
        id,
        intent_phase,
        sequence,
        None,
        input.clone(),
    )
    .await
    .unwrap();
    db.lifecycle_control(
        invocation,
        LifecycleControlCommand::CommitIntent(commit.clone()),
    )
    .await
    .unwrap();
    // Crash after actual Control consensus accepts the phase, before the
    // coordinator receives or records that outcome.
    snapshot(&db).await;
    drop(db);
    f.close().await;
    f.open(false).await;
    let db = f.leader().await;
    let status = db.recovery_status(f.context("owner"), id).await.unwrap();
    assert_eq!(status.record().pending_phase, Some(intent_phase));
    drop(status);
    let committed = db
        .engine()
        .generation()
        .unwrap()
        .state
        .lifecycle_control
        .as_ref()
        .unwrap()
        .intents[&intent_phase]
        .clone();
    let state = resolve_phase(
        &f,
        id,
        intent_phase,
        RecoveryDispatchOutcome::ControlIntent(Box::new(committed.clone())),
    )
    .await;
    assert_eq!(state.record().materialization_intent, Some(intent_phase));
    drop(state);
    for node_id in 1..=3 {
        let status = db.recovery_status(f.context("owner"), id).await.unwrap();
        let sequence = status.record().next_phase_sequence;
        drop(status);
        let phase_id = Uuid::new_v4();
        let input = db
            .next_recovery_dispatch(&f.context("owner"), id, phase_id)
            .await
            .unwrap()
            .unwrap();
        let RecoveryDispatch::Target {
            node_id: actual,
            request: target_request,
        } = &input
        else {
            panic!("target dispatch required")
        };
        assert_eq!(*actual, node_id);
        let target_command_id = target_request.command_id;
        let record = db
            .prepare_recovery_dispatch(f.context("owner"), id, phase_id, sequence, None, input)
            .await
            .unwrap();
        let origin = TargetOrigin {
            authority_manifest_sha256: f.installation.partitions[&request.authority_partition]
                .manifest_sha256
                .clone(),
            materialization: committed.clone(),
            input: request.materialization.clone(),
        };
        let fact = TargetMaterializationFact {
            origin,
            node_id,
            bootstrap_sha256: "bc".repeat(32),
            revision_base: request.checkpoint.revision + 1,
        };
        let signature = hex::encode(
            attestation[&node_id]
                .sign(&serde_json::to_vec(&("kasumi.materialized-target.v1", &fact)).unwrap())
                .as_ref(),
        );
        let response = TargetRuntimeResponse {
            command_id: target_command_id,
            node_id,
            outcome: TargetRuntimeOutcome::Materialized(Box::new(SignedTargetMaterialization {
                fact,
                signature,
            })),
        };
        record.admit_dispatch().await.unwrap();
        drop(record);
        resolve_phase(
            &f,
            id,
            phase_id,
            RecoveryDispatchOutcome::Target(Box::new(response)),
        )
        .await;
    }
    let status = db.recovery_status(f.context("owner"), id).await.unwrap();
    assert_eq!(status.record().phase, RecoveryPhase::Initialize);
    assert!(
        status
            .record()
            .voters
            .values()
            .all(|v| v.materialization.is_some())
    );
    drop(status);
    snapshot(&db).await;
    let initialized_under = commit_next_control(&f, &db, id).await;
    assert_eq!(initialized_under.request.phase, LifecyclePhase::Initialize);
    let premature_id = Uuid::new_v4();
    let mut premature = db
        .next_recovery_dispatch(&f.context("owner"), id, premature_id)
        .await
        .unwrap()
        .unwrap();
    let RecoveryDispatch::Target {
        request: target, ..
    } = &mut premature
    else {
        panic!("startup required")
    };
    let TargetRuntimeStep::Start(TargetReplicaInput::Quorum(quorum)) = &target.step else {
        panic!("quorum startup required")
    };
    target.step = TargetRuntimeStep::Initialize(quorum.clone());
    let head = db.recovery_status(f.context("owner"), id).await.unwrap();
    assert!(
        db.prepare_recovery_dispatch(
            f.context("owner"),
            id,
            premature_id,
            head.record().next_phase_sequence,
            None,
            premature
        )
        .await
        .is_err()
    );
    drop(head);

    for node_id in 1..=3 {
        let (phase_id, input) = prepare_next(&f, &db, id).await;
        let RecoveryDispatch::Target {
            node_id: actual,
            request,
        } = input
        else {
            panic!("target startup required")
        };
        assert_eq!(actual, node_id);
        let TargetRuntimeStep::Start(TargetReplicaInput::Quorum(quorum)) = request.step else {
            panic!("exact quorum startup required")
        };
        resolve_phase(
            &f,
            id,
            phase_id,
            RecoveryDispatchOutcome::Target(Box::new(TargetRuntimeResponse {
                command_id: request.command_id,
                node_id,
                outcome: TargetRuntimeOutcome::Started {
                    origin_sha256: quorum.origin_sha256,
                },
            })),
        )
        .await;
    }
    let (phase_id, input) = prepare_next(&f, &db, id).await;
    let RecoveryDispatch::Target {
        node_id,
        request: initialize,
    } = input
    else {
        panic!("initialization required")
    };
    assert_eq!(node_id, 1);
    let TargetRuntimeStep::Initialize(quorum) = initialize.step else {
        panic!("designated initialization required")
    };
    resolve_phase(
        &f,
        id,
        phase_id,
        RecoveryDispatchOutcome::Target(Box::new(TargetRuntimeResponse {
            command_id: initialize.command_id,
            node_id,
            outcome: TargetRuntimeOutcome::Initialized {
                origin_sha256: quorum.origin_sha256,
            },
        })),
    )
    .await;
    snapshot(&db).await;
    let complete_under = commit_next_control_for(
        &f,
        &db,
        id,
        if inspect_completion { 20_000 } else { 60_000 },
    )
    .await;
    assert_eq!(complete_under.request.phase, LifecyclePhase::Complete);
    // A fresh Start sent to the first installed voter has no response. Keep it
    // unknown and retry the unchanged phase on the two other installed voters.
    let (missing_start, missing_dispatch) = prepare_next(&f, &db, id).await;
    assert!(
        matches!(&missing_dispatch, RecoveryDispatch::Target { node_id: 1, request }
        if matches!(request.step, TargetRuntimeStep::Start(TargetReplicaInput::Completion(_))))
    );
    for node_id in 2..=3 {
        let (phase_id, input) = prepare_next(&f, &db, id).await;
        let RecoveryDispatch::Target {
            node_id: actual,
            request,
        } = input
        else {
            panic!("fresh target startup required")
        };
        assert_eq!(actual, node_id);
        let TargetRuntimeStep::Start(TargetReplicaInput::Completion(input)) = request.step else {
            panic!("current completion startup required")
        };
        let quorum = input.quorum;
        assert_eq!(request.command_id, complete_under.request.command_id);
        resolve_phase(
            &f,
            id,
            phase_id,
            RecoveryDispatchOutcome::Target(Box::new(TargetRuntimeResponse {
                command_id: request.command_id,
                node_id,
                outcome: TargetRuntimeOutcome::Started {
                    origin_sha256: quorum.origin_sha256,
                },
            })),
        )
        .await;
    }
    assert!(
        db.recovery_phase(f.context("owner"), id, missing_start)
            .await
            .unwrap()
            .record()
            .outcome
            .is_none()
    );
    let (prepared_phase, prepared_request) = prepare_next(&f, &db, id).await;
    let RecoveryDispatch::Target {
        node_id: prepared_node,
        request: prepared_request,
    } = prepared_request
    else {
        panic!("completion preparation required");
    };
    let TargetRuntimeStep::PrepareComplete(prepared_input) = prepared_request.step else {
        panic!("explicit completion preparation required");
    };
    let prepared_attempt = TargetCompletionAttempt {
        origin: prepared_input.quorum.materialized[&1].fact.origin.clone(),
        input: prepared_input,
        intent: complete_under.clone(),
        dispatch_not_after_ms: prepared_request.not_after_ms,
        admitted_at_ms: complete_under.accepted_at_ms + 1,
        revision: request.checkpoint.revision + 2,
        position: TargetCommitPosition {
            index: 1,
            term: 8,
            leader_node_id: prepared_node,
            command_sha256: "a9".repeat(32),
        },
        reserved_terminal_bytes: TARGET_COMPLETION_RESERVE_BYTES,
        reserved_audit_bytes: TARGET_COMPLETION_AUDIT_RESERVE_BYTES,
    };
    let prepared_observation = TargetCompletionAttemptObservation {
        attempt: prepared_attempt,
        observer_node_id: prepared_node,
        observed_revision: request.checkpoint.revision + 2,
        observed_term: 8,
    };
    let prepared_signature = hex::encode(
        attestation[&prepared_node]
            .sign(
                &serde_json::to_vec(&(
                    "kasumi.prepared-target-completion-observation.v1",
                    &prepared_observation,
                ))
                .unwrap(),
            )
            .as_ref(),
    );
    resolve_phase(
        &f,
        id,
        prepared_phase,
        RecoveryDispatchOutcome::Target(Box::new(TargetRuntimeResponse {
            command_id: prepared_request.command_id,
            node_id: prepared_node,
            outcome: TargetRuntimeOutcome::PreparedCompletion(Box::new(
                SignedTargetCompletionAttempt {
                    observation: prepared_observation,
                    signature: prepared_signature,
                },
            )),
        })),
    )
    .await;
    reject_changed_completion_caps(&f, id).await;
    let (unresolved, original_request) = prepare_next(&f, &db, id).await;
    let (complete_phase, retried) = prepare_next(&f, &db, id).await;
    let RecoveryDispatch::Target {
        node_id: old_node,
        request: old,
    } = original_request
    else {
        panic!("original completion required")
    };
    let RecoveryDispatch::Target {
        node_id,
        request: completion,
    } = retried
    else {
        panic!("completion peer retry required")
    };
    assert_eq!((old_node, node_id), (2, 3));
    assert_eq!(
        old, completion,
        "peer retry must preserve original command and absolute deadline"
    );
    assert!(
        db.recovery_phase(f.context("owner"), id, unresolved)
            .await
            .unwrap()
            .record()
            .outcome
            .is_none()
    );
    let TargetRuntimeStep::Complete(input) = completion.step else {
        panic!("completion required")
    };
    let quorum = input.quorum;
    let completed = TargetCompletionFact {
        origin: quorum.materialized[&1].fact.origin.clone(),
        materialized: quorum.materialized,
        completion_intent: complete_under.clone(),
        predecessor: input.predecessor,
        admitted_at_ms: complete_under.accepted_at_ms + 1,
        revision: request.checkpoint.revision + 3,
        term: 8,
        leader_node_id: node_id,
        bootstrap_sha256: "bc".repeat(32),
    };
    let observation = TargetCompletionObservation {
        fact: completed.clone(),
        observer_node_id: node_id,
        observed_revision: request.checkpoint.revision + 3,
        observed_term: 8,
    };
    let signed = SignedTargetCompletion {
        signature: hex::encode(
            attestation[&node_id]
                .sign(
                    &serde_json::to_vec(&("kasumi.completed-target-observation.v1", &observation))
                        .unwrap(),
                )
                .as_ref(),
        ),
        observation,
    };
    let outcome = RecoveryDispatchOutcome::Target(Box::new(TargetRuntimeResponse {
        command_id: completion.command_id,
        node_id,
        outcome: TargetRuntimeOutcome::Completed(Box::new(signed)),
    }));
    if inspect_completion {
        resolve_expired_completion(&f, &db, id, complete_phase, completed, &attestation).await;
    } else {
        resolve_phase(&f, id, complete_phase, outcome).await;
    }
    let retirement_phase = if planned {
        let status = db.recovery_status(f.context("owner"), id).await.unwrap();
        assert_eq!(status.record().phase, RecoveryPhase::RetireSource);
        drop(status);
        let (phase_id, input) = prepare_next(&f, &db, id).await;
        let RecoveryDispatch::RetireSource(retirement) = input else {
            panic!("planned recovery must prepare its exact source retirement");
        };
        assert_eq!(retirement.destination, "source-backup");
        assert_ne!(
            retirement.destination,
            request.materialization.destination_alias
        );
        assert_eq!(retirement.checkpoint, request.checkpoint);
        assert_eq!(
            retirement.expected_source_incarnation,
            request.source_incarnation.to_string()
        );
        assert_eq!(
            retirement.target_incarnation,
            request.target_incarnation.to_string()
        );
        let phase = db
            .recovery_phase(f.context("owner"), id, phase_id)
            .await
            .unwrap();
        assert!(retirement.not_after_ms > phase.record().admitted_at_ms);
        assert!(retirement.not_after_ms <= phase.dispatch_limit().await.unwrap());
        drop(phase);
        let mut receipt = RetirementReceipt {
            tenant: request.tenant.clone(),
            principal: "independent-source-admin".into(),
            retirement_id: retirement.retirement_id.clone(),
            request_digest: retirement.reference().unwrap().request_digest,
            source_incarnation: request.source_incarnation.to_string(),
            target_incarnation: Uuid::new_v4().to_string(),
            revision: request.checkpoint.revision + 1,
            policy_epoch: 1,
            admitted_at_ms: retirement.not_after_ms - 1,
            checkpoint: request.checkpoint.clone(),
            closure_digest: "e1".repeat(32),
        };
        assert!(
            db.resolve_recovery_dispatch(
                f.context("owner"),
                id,
                phase_id,
                RecoveryDispatchOutcome::SourceRetired(Box::new(receipt.clone()))
            )
            .await
            .is_err()
        );
        receipt.target_incarnation = request.target_incarnation.to_string();
        resolve_phase(
            &f,
            id,
            phase_id,
            RecoveryDispatchOutcome::SourceRetired(Box::new(receipt)),
        )
        .await;
        Some(phase_id)
    } else {
        None
    };

    assert_eq!(
        db.recovery_status(f.context("owner"), id)
            .await
            .unwrap()
            .record()
            .phase,
        RecoveryPhase::FenceSource
    );
    let (fence_phase, input) = prepare_next(&f, &db, id).await;
    let RecoveryDispatch::Authority(command) = &input else {
        panic!("source-unavailable recovery must use its installed issuer");
    };
    assert_eq!(
        command.action,
        AuthorityAction::Fence {
            incarnation: request.source_incarnation,
            authority_epoch: request.source_authority_epoch,
        }
    );
    let partition = &f.installation.partitions[&request.authority_partition];
    let mut receipt = AuthorityReceipt {
        authority_id: partition.authority_id,
        manifest_digest: partition.manifest_sha256.clone(),
        partition: partition.partition,
        command: command.as_ref().clone(),
        command_digest: command.digest().unwrap(),
        principal: "issuer-admin".into(),
        term: 3,
        revision: 11,
        admitted_at_ms: command.not_after_ms - 1,
        outcome: AuthorityOutcome::Fenced {
            incarnation: Uuid::new_v4(),
            authority_epoch: request.source_authority_epoch,
        },
    };
    let sign = |receipt: &AuthorityReceipt| SignedAuthorityReceipt {
        signature: f.partition_keys[&partition.key()]
            .sign("kasumi.authority-proof.v1", receipt)
            .unwrap(),
        receipt: receipt.clone(),
    };
    assert!(
        db.resolve_recovery_dispatch(
            f.context("owner"),
            id,
            fence_phase,
            RecoveryDispatchOutcome::Authority(Box::new(sign(&receipt)))
        )
        .await
        .is_err()
    );
    receipt.outcome = AuthorityOutcome::Fenced {
        incarnation: request.source_incarnation,
        authority_epoch: request.source_authority_epoch,
    };
    let fenced = resolve_phase(
        &f,
        id,
        fence_phase,
        RecoveryDispatchOutcome::Authority(Box::new(sign(&receipt))),
    )
    .await;
    assert_eq!(fenced.record().source_fence, Some(fence_phase));
    assert_eq!(
        fenced.record().retirement,
        retirement_phase,
        "source fencing must preserve the explicitly selected retirement mode"
    );
    assert_eq!(fenced.record().phase, RecoveryPhase::Activate);
    drop(fenced);
    snapshot(&db).await;
    if let Some(activated) = activation_outcome {
        let activate_under = commit_next_intent(&f, &db, id).await;
        assert_eq!(activate_under.request.phase, LifecyclePhase::Activate);
        let (activation_phase, input) = prepare_next(&f, &db, id).await;
        let RecoveryDispatch::Authority(original) = input else {
            panic!("issuer activation command required")
        };
        let AuthorityAction::ActivateCommitted {
            control, target, ..
        } = &original.action
        else {
            panic!("closed committed activation required")
        };
        assert_eq!(
            control.reference.identity,
            LifecycleAuthorityIdentity::Intent(activate_under.request.command_id)
        );
        assert!(original.not_after_ms <= activate_under.original_credential_expires_at_ms);
        let uncertain = db
            .recovery_control(
                f.context("owner"),
                RecoveryControlCommand::Stop {
                    operation_id: id,
                    command_id: Uuid::new_v4(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            uncertain.record().phase,
            RecoveryPhase::StopActivation,
            "unknown activation cannot authorize target cleanup"
        );
        assert_eq!(
            uncertain.record().activation_attempt,
            Some(activation_phase)
        );
        drop(uncertain);
        let (stop_phase, input) = prepare_next(&f, &db, id).await;
        let RecoveryDispatch::Authority(stop) = input else {
            panic!("permanent activation resolution required")
        };
        assert_eq!(
            stop.action,
            AuthorityAction::StopActivation {
                original: original.clone()
            }
        );
        let original_receipt = AuthorityReceipt {
            authority_id: partition.authority_id,
            manifest_digest: partition.manifest_sha256.clone(),
            partition: partition.partition,
            command: *original.clone(),
            command_digest: original.digest().unwrap(),
            principal: "issuer-admin".into(),
            term: 3,
            revision: 12,
            admitted_at_ms: activate_under.accepted_at_ms + 1,
            outcome: if activated {
                AuthorityOutcome::Activated {
                    target: target.clone(),
                    authority_epoch: request.source_authority_epoch + 1,
                }
            } else {
                AuthorityOutcome::ActivationStopped {
                    original_digest: original.digest().unwrap(),
                }
            },
        };
        let stopped = AuthorityReceipt {
            authority_id: partition.authority_id,
            manifest_digest: partition.manifest_sha256.clone(),
            partition: partition.partition,
            command: *stop.clone(),
            command_digest: stop.digest().unwrap(),
            principal: "issuer-admin".into(),
            term: 3,
            revision: 13,
            admitted_at_ms: stop.not_after_ms - 1,
            outcome: AuthorityOutcome::ActivationResolved {
                original: Box::new(original_receipt.clone()),
            },
        };
        let mut wrong = stopped.clone();
        if let AuthorityOutcome::ActivationResolved { original } = &mut wrong.outcome {
            original.command.command_id = Uuid::new_v4();
            original.command_digest = original.command.digest().unwrap();
        }
        assert!(
            db.resolve_recovery_dispatch(
                f.context("owner"),
                id,
                stop_phase,
                RecoveryDispatchOutcome::Authority(Box::new(sign(&wrong)))
            )
            .await
            .is_err()
        );
        let resolved = resolve_phase(
            &f,
            id,
            stop_phase,
            RecoveryDispatchOutcome::Authority(Box::new(sign(&stopped))),
        )
        .await;
        assert_eq!(
            resolved.record().phase,
            if activated {
                RecoveryPhase::Confirm
            } else {
                RecoveryPhase::StopTarget
            }
        );
        assert_eq!(
            resolved.record().activation,
            activated.then_some(activation_phase)
        );
        drop(resolved);
        let old = db
            .recovery_phase(f.context("owner"), id, activation_phase)
            .await
            .unwrap();
        assert!(matches!(
            old.record().outcome,
            Some(RecoveryDispatchOutcome::AuthorityResolution(_))
        ));
        assert_eq!(
            old.record().input,
            RecoveryDispatch::Authority(original.clone()),
            "resolution must retain unchanged original cutoff and identity"
        );
        drop(old);
        snapshot(&db).await;
        if activated {
            let confirm_under = commit_next_intent(&f, &db, id).await;
            assert_ne!(
                confirm_under.request.command_id,
                activate_under.request.command_id
            );
            assert_eq!(
                confirm_under.request.phase_input_sha256,
                activate_under.request.phase_input_sha256
            );
            for node in 1..=3 {
                let (phase, input) = prepare_next(&f, &db, id).await;
                let RecoveryDispatch::Target {
                    node_id,
                    request: started,
                } = input
                else {
                    panic!("fresh activation startup required")
                };
                assert_eq!(node_id, node);
                let TargetRuntimeStep::StartActivation {
                    quorum,
                    issuer_command_id,
                } = started.step
                else {
                    panic!("startup must bind committed issuer winner")
                };
                assert_eq!(issuer_command_id, original.command_id);
                assert_eq!(started.command_id, confirm_under.request.command_id);
                resolve_phase(
                    &f,
                    id,
                    phase,
                    RecoveryDispatchOutcome::Target(Box::new(TargetRuntimeResponse {
                        command_id: started.command_id,
                        node_id: node,
                        outcome: TargetRuntimeOutcome::Started {
                            origin_sha256: quorum.origin_sha256,
                        },
                    })),
                )
                .await;
                assert!(
                    db.recovery_status(f.context("owner"), id)
                        .await
                        .unwrap()
                        .record()
                        .voters
                        .values()
                        .all(|v| v.confirmation.is_none()),
                    "Started is never local activation evidence"
                );
            }
            let (ambiguous, first) = prepare_next(&f, &db, id).await;
            let (local_phase, retried) = prepare_next(&f, &db, id).await;
            let RecoveryDispatch::Target {
                node_id: first_node,
                request: first,
            } = first
            else {
                panic!("local activation required")
            };
            let RecoveryDispatch::Target {
                node_id,
                request: local,
            } = retried
            else {
                panic!("exact peer retry required")
            };
            assert_eq!((first_node, node_id), (1, 2));
            assert_eq!(local, first);
            assert!(
                db.recovery_phase(f.context("owner"), id, ambiguous)
                    .await
                    .unwrap()
                    .record()
                    .outcome
                    .is_none()
            );
            let fact = TargetActivationFact {
                position: TargetCommitPosition {
                    index: 3,
                    term: 9,
                    leader_node_id: node_id,
                    command_sha256: "e2".repeat(32),
                },
                intent: confirm_under.clone(),
                issuer_receipt_sha256: original_receipt.digest().unwrap(),
                completion_sha256: control.completion.fact().digest().unwrap(),
                admitted_at_ms: confirm_under.accepted_at_ms + 1,
                revision: control.completion.fact().revision + 1,
            };
            let proof = |node_id| {
                let observation = TargetActivationObservation {
                    completion: control.completion.fact().clone(),
                    activation: fact.clone(),
                    observer_node_id: node_id,
                    observed_revision: fact.revision,
                    observed_term: 9,
                };
                SignedTargetActivation {
                    signature: hex::encode(
                        attestation[&node_id]
                            .sign(
                                &serde_json::to_vec(&(
                                    "kasumi.activated-target-observation.v1",
                                    &observation,
                                ))
                                .unwrap(),
                            )
                            .as_ref(),
                    ),
                    observation,
                }
            };
            let response = |command_id, node_id| {
                RecoveryDispatchOutcome::Target(Box::new(TargetRuntimeResponse {
                    command_id,
                    node_id,
                    outcome: TargetRuntimeOutcome::Activated(Box::new(proof(node_id))),
                }))
            };
            let mut forged = response(local.command_id, node_id);
            let RecoveryDispatchOutcome::Target(reply) = &mut forged else {
                unreachable!()
            };
            let TargetRuntimeOutcome::Activated(signed) = &mut reply.outcome else {
                unreachable!()
            };
            signed.observation.activation.issuer_receipt_sha256 = "f2".repeat(32);
            signed.signature = hex::encode(
                attestation[&node_id]
                    .sign(
                        &serde_json::to_vec(&(
                            "kasumi.activated-target-observation.v1",
                            &signed.observation,
                        ))
                        .unwrap(),
                    )
                    .as_ref(),
            );
            assert!(
                db.resolve_recovery_dispatch(f.context("owner"), id, local_phase, forged)
                    .await
                    .is_err()
            );
            resolve_phase(&f, id, local_phase, response(local.command_id, node_id)).await;
            for node in [1, 3] {
                let (phase, input) = prepare_next(&f, &db, id).await;
                let RecoveryDispatch::Target {
                    node_id,
                    request: confirm,
                } = input
                else {
                    panic!("every voter must locally confirm activation")
                };
                assert_eq!(node_id, node);
                let TargetRuntimeStep::ConfirmActivation(expected) = confirm.step else {
                    panic!("exact retained activation confirmation required")
                };
                assert_eq!(expected.observation.activation, fact);
                resolve_phase(&f, id, phase, response(confirm.command_id, node)).await;
            }
            let published = db.recovery_status(f.context("owner"), id).await.unwrap();
            assert_eq!(published.record().phase, RecoveryPhase::Publish);
            assert_eq!(published.record().activation, Some(activation_phase));
            assert!(
                published
                    .record()
                    .voters
                    .values()
                    .all(|v| v.confirmation.is_some())
            );
            drop(published);
            snapshot(&db).await;
            return Some(RoutePublicationFixture {
                fixture: f,
                database: db,
                request,
            });
        }
    }
    if activation_outcome.is_none() {
        let stopped = db
            .recovery_control(
                f.context("owner"),
                RecoveryControlCommand::Stop {
                    operation_id: id,
                    command_id: Uuid::new_v4(),
                },
            )
            .await
            .unwrap();
        assert_eq!(stopped.record().phase, RecoveryPhase::StopTarget);
        drop(stopped);
    }
    let (stop_phase, input) = prepare_next(&f, &db, id).await;
    let RecoveryDispatch::Authority(command) = &input else {
        panic!("stop issuer phase required")
    };
    let AuthorityAction::StopTarget {
        source_incarnation,
        source_epoch,
        target,
    } = &command.action
    else {
        panic!("stop target action required")
    };
    let partition = &f.installation.partitions[&request.authority_partition];
    let stop_receipt = AuthorityReceipt {
        authority_id: partition.authority_id,
        manifest_digest: partition.manifest_sha256.clone(),
        partition: partition.partition,
        command: command.as_ref().clone(),
        command_digest: command.digest().unwrap(),
        principal: "issuer-admin".into(),
        term: 3,
        revision: 11,
        admitted_at_ms: command.not_after_ms - 1,
        outcome: AuthorityOutcome::TargetStopped {
            source_incarnation: *source_incarnation,
            source_epoch: *source_epoch,
            target: target.clone(),
        },
    };
    let signed = SignedAuthorityReceipt {
        signature: f.partition_keys[&partition.key()]
            .sign("kasumi.authority-proof.v1", &stop_receipt)
            .unwrap(),
        receipt: stop_receipt.clone(),
    };
    resolve_phase(
        &f,
        id,
        stop_phase,
        RecoveryDispatchOutcome::Authority(Box::new(signed)),
    )
    .await;
    let (cleanup_phase, input) = prepare_next(&f, &db, id).await;
    let RecoveryDispatch::ControlIntent(commit) = input else {
        panic!("cleanup Control phase required")
    };
    let phase = db
        .recovery_phase(f.context("owner"), id, cleanup_phase)
        .await
        .unwrap();
    let mut invocation = f.context("owner");
    invocation.authorization = invocation
        .authorization
        .with_expiry_limit(phase.dispatch_limit().await.unwrap())
        .unwrap();
    drop(phase);
    db.lifecycle_control(invocation, LifecycleControlCommand::CommitIntent(commit))
        .await
        .unwrap();
    let intent = db
        .engine()
        .generation()
        .unwrap()
        .state
        .lifecycle_control
        .as_ref()
        .unwrap()
        .intents[&cleanup_phase]
        .clone();
    resolve_phase(
        &f,
        id,
        cleanup_phase,
        RecoveryDispatchOutcome::ControlIntent(Box::new(intent.clone())),
    )
    .await;
    for node_id in 1..=3 {
        let (phase_id, input) = prepare_next(&f, &db, id).await;
        let RecoveryDispatch::Target {
            request: target_request,
            ..
        } = input
        else {
            panic!("cleanup target phase required")
        };
        let TargetRuntimeStep::Stop(reference) = target_request.step else {
            panic!("target stop reference required")
        };
        let observation = TargetStopObservation {
            reference,
            stop: stop_receipt.clone(),
            observed_term: 3,
            observed_revision: 11,
            drain_ms: partition.drain_ms,
        };
        let response = |observation: TargetStopObservation| {
            let stopped = SignedTargetStop {
                signature: f.partition_keys[&partition.key()]
                    .sign("kasumi.target-stop-drained.v1", &observation)
                    .unwrap(),
                observation,
            };
            let fact = LocalTargetCleanupFact {
                intent: intent.clone(),
                node_id,
                stopped,
                stop_receipt_sha256: stop_receipt.digest().unwrap(),
                observed_at_ms: intent.accepted_at_ms + 1,
            };
            let signature = hex::encode(
                attestation[&node_id]
                    .sign(&serde_json::to_vec(&("kasumi.local-target-cleanup.v1", &fact)).unwrap())
                    .as_ref(),
            );
            RecoveryDispatchOutcome::Target(Box::new(TargetRuntimeResponse {
                command_id: target_request.command_id,
                node_id,
                outcome: TargetRuntimeOutcome::Stopped(Box::new(SignedLocalTargetCleanup {
                    fact,
                    signature,
                })),
            }))
        };
        if node_id == 1 {
            let mut short_drain = observation.clone();
            short_drain.drain_ms -= 1;
            assert!(
                db.resolve_recovery_dispatch(
                    f.context("owner"),
                    id,
                    phase_id,
                    response(short_drain)
                )
                .await
                .is_err()
            );
            let mut wrong_nodes = observation.clone();
            // A correctly signed issuer observation and node attestation still
            // cannot authorize cleanup against another physical verifier set.
            if let AuthorityAction::StopTarget { target, .. } = &mut wrong_nodes.stop.command.action
            {
                let mut node = target.nodes.pop_first().unwrap();
                node.verifier.installation_id = Uuid::new_v4();
                target.nodes.insert(node);
            }
            if let AuthorityOutcome::TargetStopped { target, .. } = &mut wrong_nodes.stop.outcome {
                let AuthorityAction::StopTarget { target: actual, .. } =
                    &wrong_nodes.stop.command.action
                else {
                    unreachable!()
                };
                *target = actual.clone();
            }
            wrong_nodes.stop.command_digest = wrong_nodes.stop.command.digest().unwrap();
            // Update every digest too: rejection must come from exact roster
            // binding, not just an inconsistent receipt hash.
            let mut forged = response(wrong_nodes);
            let RecoveryDispatchOutcome::Target(reply) = &mut forged else {
                unreachable!()
            };
            let TargetRuntimeOutcome::Stopped(signed) = &mut reply.outcome else {
                unreachable!()
            };
            signed.fact.stop_receipt_sha256 =
                signed.fact.stopped.observation.stop.digest().unwrap();
            signed.signature = hex::encode(
                attestation[&node_id]
                    .sign(
                        &serde_json::to_vec(&("kasumi.local-target-cleanup.v1", &signed.fact))
                            .unwrap(),
                    )
                    .as_ref(),
            );
            assert!(
                db.resolve_recovery_dispatch(f.context("owner"), id, phase_id, forged)
                    .await
                    .is_err()
            );
        }
        resolve_phase(&f, id, phase_id, response(observation)).await;
    }
    assert_eq!(
        db.recovery_status(f.context("owner"), id)
            .await
            .unwrap()
            .record()
            .phase,
        RecoveryPhase::Stopped
    );
    snapshot(&db).await;
    drop(db);
    f.close().await;
    f.open(false).await;
    let db = f.leader().await;
    let mut alias = request.clone();
    alias.operation_id = Uuid::new_v4();
    alias.dispatch_configuration_sha256 = "94".repeat(32);
    assert_eq!(
        db.recovery_control(
            f.context("owner"),
            RecoveryControlCommand::Start(Box::new(alias))
        )
        .await
        .err()
        .unwrap()
        .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        db.recovery_status(f.context("owner"), id)
            .await
            .unwrap()
            .record()
            .phase,
        RecoveryPhase::Stopped
    );
    drop(db);
    f.close().await;
    None
}
async fn publish_route(f: &Fixture, operation: Uuid, phase: Uuid) -> RecoveryDispatchOutcome {
    let context = f.context("owner");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let db = f.leader().await;
            match db
                .publish_recovery_route(context.clone(), operation, phase)
                .await
            {
                Ok(observation) => {
                    return observation
                        .record()
                        .outcome
                        .clone()
                        .expect("permanent route outcome missing");
                }
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                    ) => {}
                Err(error) => panic!("atomic route publication failed: {error:?}"),
            }
        }
    })
    .await
    .expect("original route publication did not resolve")
}
// A denied response releases no topology. Retry the same finite read through
// the actual current leader; permanent authorization/corruption errors still fail.
async fn read_topology(f: &Fixture) -> kasumi_engine::control::VersionedTopology {
    let context = f.context("owner");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let plane = kasumi_engine::control::ControlPlane::new(f.leader().await).unwrap();
            match plane.topology(&context).await {
                Ok(Some(topology)) => return topology,
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::UnknownOutcome
                            | ErrorCode::Unavailable
                            | ErrorCode::AuditUnavailable
                    ) => {}
                other => panic!("current topology read did not release: {other:?}"),
            }
        }
    })
    .await
    .expect("original topology read did not acquire its durable release fence")
}
async fn exercise_route_publication(f: &mut Fixture, db: Arc<Database>, request: &RecoveryStart) {
    use kasumi_engine::control::{
        ControlNode, ControlPlane, ControlTopology, DeploymentMode, TenantRoute,
    };
    let plane = ControlPlane::new(db.clone()).unwrap();
    plane.initialize(f.context("owner")).await.unwrap();
    let mut topology = ControlTopology {
        nodes: request
            .target_nodes
            .iter()
            .map(|(node, identity)| {
                (
                    *node,
                    ControlNode {
                        endpoint: request.materialization.voters[node].endpoint.clone(),
                        failure_domain: request.materialization.voters[node].failure_domain.clone(),
                        certificate_pins: BTreeSet::from([identity.certificate_sha256.clone()]),
                    },
                )
            })
            .collect(),
        tenants: BTreeMap::from([(
            request.tenant.clone(),
            TenantRoute {
                incarnation: request.source_incarnation.to_string(),
                mode: DeploymentMode::Replicated,
                voters: request.target_nodes.keys().copied().collect(),
            },
        )]),
    };
    plane
        .replace_topology(
            f.context("owner"),
            topology.clone(),
            Precondition::Absent,
            "recovery-source-topology".into(),
        )
        .await
        .unwrap();
    let (phase, input) = prepare_next(f, &db, request.operation_id).await;
    let RecoveryDispatch::PublishRoute(original) = input else {
        panic!("exact route compare-and-set must be prepared first")
    };
    assert_eq!(
        original.expected_source_incarnation,
        request.source_incarnation
    );
    assert!(
        db.publish_recovery_route(f.context("intruder"), request.operation_id, phase)
            .await
            .is_err()
    );
    assert!(
        db.resolve_recovery_dispatch(
            f.context("owner"),
            request.operation_id,
            phase,
            RecoveryDispatchOutcome::RoutePublished {
                revision: db.engine().generation().unwrap().state.revision + 1
            }
        )
        .await
        .is_err(),
        "ordinary resolution cannot fabricate an atomic topology publication"
    );
    topology.tenants.insert(
        "unrelated".into(),
        TenantRoute {
            incarnation: Uuid::new_v4().to_string(),
            mode: DeploymentMode::Replicated,
            voters: original.target_voters.clone(),
        },
    );
    plane
        .replace_topology(
            f.context("owner"),
            topology.clone(),
            Precondition::Version(original.expected_topology_version),
            "race-recovery-topology".into(),
        )
        .await
        .unwrap();
    let raced = read_topology(f).await;
    let rejected = publish_route(f, request.operation_id, phase).await;
    assert_eq!(
        rejected,
        RecoveryDispatchOutcome::RouteRejected {
            observed_topology_version: Some(raced.version)
        }
    );
    assert_eq!(
        read_topology(f).await.topology,
        topology,
        "a stale prepared phase cannot overwrite concurrent topology"
    );
    let expiring = f.context_for("owner", 3_000);
    let expired = Uuid::new_v4();
    let head = db
        .recovery_status(f.context("owner"), request.operation_id)
        .await
        .unwrap();
    let pending = db
        .next_recovery_dispatch(&expiring, request.operation_id, expired)
        .await
        .unwrap()
        .unwrap();
    let prepared = db
        .prepare_recovery_dispatch(
            expiring,
            request.operation_id,
            expired,
            head.record().next_phase_sequence,
            None,
            pending,
        )
        .await
        .unwrap();
    let original_cutoff = prepared.dispatch_limit().await.unwrap();
    drop(prepared);
    drop(head);
    let now = kasumi_clock::EpochClock::system()
        .unwrap()
        .observe()
        .unwrap()
        .utc_ms();
    tokio::time::sleep(Duration::from_millis(
        original_cutoff.saturating_sub(now) + 20,
    ))
    .await;
    let (fresh, input) = prepare_next(f, &db, request.operation_id).await;
    let old = db
        .recovery_phase(f.context("owner"), request.operation_id, expired)
        .await
        .unwrap();
    assert_eq!(old.dispatch_limit().await.unwrap(), original_cutoff);
    assert_eq!(
        old.record().outcome,
        Some(RecoveryDispatchOutcome::RouteSuperseded {
            replacement_phase: fresh
        })
    );
    drop(old);
    assert_eq!(
        publish_route(f, request.operation_id, expired).await,
        RecoveryDispatchOutcome::RouteSuperseded {
            replacement_phase: fresh
        }
    );
    assert_eq!(
        read_topology(f).await.version,
        raced.version,
        "an expired local phase must remain closed after fresh admission"
    );
    let RecoveryDispatch::PublishRoute(input) = input else {
        panic!("fresh exact route phase required")
    };
    assert_eq!(input.expected_topology_version, raced.version);
    let published = publish_route(f, request.operation_id, fresh).await;
    let RecoveryDispatchOutcome::RoutePublished { revision } = &published else {
        panic!("atomic publication required")
    };
    let active = read_topology(f).await;
    assert_eq!(active.version, *revision);
    assert_eq!(
        active.topology.tenants[&request.tenant].incarnation,
        request.target_incarnation.to_string()
    );
    assert_eq!(
        active.topology.tenants["unrelated"],
        topology.tenants["unrelated"]
    );
    let head = db
        .recovery_status(f.context("owner"), request.operation_id)
        .await
        .unwrap();
    assert_eq!(head.record().phase, RecoveryPhase::Finished);
    assert_eq!(head.record().route_publication, Some(fresh));
    drop(head);
    let mut later = active.topology;
    later.tenants.get_mut("unrelated").unwrap().incarnation = Uuid::new_v4().to_string();
    plane
        .replace_topology(
            f.context("owner"),
            later.clone(),
            Precondition::Version(*revision),
            "later-authorized-topology".into(),
        )
        .await
        .unwrap();
    let later_version = read_topology(f).await.version;
    assert_eq!(
        publish_route(f, request.operation_id, fresh).await,
        published
    );
    assert_eq!(
        publish_route(f, request.operation_id, phase).await,
        rejected
    );
    let current = read_topology(f).await;
    assert_eq!(current.version, later_version);
    assert_eq!(current.topology, later);
    snapshot(&db).await;
    drop(plane);
    drop(db);
    f.close().await;
    f.open(false).await;
    let db = f.leader().await;
    assert_eq!(
        publish_route(f, request.operation_id, fresh).await,
        published
    );
    let current = read_topology(f).await;
    assert_eq!(current.version, later_version);
    assert_eq!(
        current.topology, later,
        "replay after restart must preserve later authorized topology"
    );
    assert_eq!(
        db.recovery_status(f.context("owner"), request.operation_id)
            .await
            .unwrap()
            .record()
            .phase,
        RecoveryPhase::Finished
    );
    snapshot(&db).await;
    drop(db);
    f.close().await;
}
// A phase outcome may commit before the current-quorum response fence closes.
// Resolve that exact retained phase before advancing; all retries preserve its
// input, signed outcome, command identity, and original authorization deadline.
async fn resolve_phase(
    f: &Fixture,
    operation: Uuid,
    phase_id: Uuid,
    outcome: RecoveryDispatchOutcome,
) -> kasumi_engine::VerifiedRecoveryStatus {
    let context = f.context("owner");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let db = f.leader().await;
            let observed = match db
                .recovery_phase(context.clone(), operation, phase_id)
                .await
            {
                Ok(phase) => phase,
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                    ) =>
                {
                    continue;
                }
                Err(error) => panic!("original recovery phase unavailable: {error:?}"),
            };
            let resolved = if let Some(retained) = &observed.record().outcome {
                assert_eq!(retained, &outcome, "permanent phase outcome changed");
                true
            } else {
                false
            };
            drop(observed);
            let result = if resolved {
                db.recovery_status(context.clone(), operation).await
            } else {
                db.resolve_recovery_dispatch(context.clone(), operation, phase_id, outcome.clone())
                    .await
            };
            match result {
                Ok(status) => return status,
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                    ) => {}
                Err(error) => panic!("original recovery outcome rejected: {error:?}"),
            }
        }
    })
    .await
    .expect("original recovery phase outcome did not resolve")
}
async fn commit_next_intent(f: &Fixture, db: &Arc<Database>, operation: Uuid) -> LifecycleIntent {
    let (phase_id, input) = prepare_next(f, db, operation).await;
    let RecoveryDispatch::ControlIntent(command) = input else {
        panic!("committed Control phase required")
    };
    let prepared = db
        .recovery_phase(f.context("owner"), operation, phase_id)
        .await
        .unwrap();
    let mut context = f.context("owner");
    context.authorization = context
        .authorization
        .with_expiry_limit(prepared.dispatch_limit().await.unwrap())
        .unwrap();
    drop(prepared);
    db.lifecycle_control(context, LifecycleControlCommand::CommitIntent(command))
        .await
        .unwrap();
    let intent = db
        .engine()
        .generation()
        .unwrap()
        .state
        .lifecycle_control
        .as_ref()
        .unwrap()
        .intents[&phase_id]
        .clone();
    resolve_phase(
        f,
        operation,
        phase_id,
        RecoveryDispatchOutcome::ControlIntent(Box::new(intent.clone())),
    )
    .await;
    intent
}
async fn prepare_next(
    f: &Fixture,
    _db: &Arc<Database>,
    operation: Uuid,
) -> (Uuid, RecoveryDispatch) {
    let context = f.context("owner");
    let phase = Uuid::new_v4();
    let (sequence, pending, input) = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let current = f.leader().await;
            let head = match current.recovery_status(context.clone(), operation).await {
                Ok(head) => head,
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                    ) =>
                {
                    continue;
                }
                Err(error) => panic!("recovery planning status rejected: {error:?}"),
            };
            match current
                .next_recovery_dispatch(&context, operation, phase)
                .await
            {
                Ok(Some(input)) => {
                    return (
                        head.record().next_phase_sequence,
                        head.record().pending_phase,
                        input,
                    );
                }
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                    ) => {}
                other => panic!("recovery planning dispatch rejected: {other:?}"),
            }
        }
    })
    .await
    .expect("current recovery planning observation did not resolve");
    // Preparing may commit before its response fence closes. Resolve this exact
    // phase before retrying admission; never regenerate its input or deadline.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let current = f.leader().await;
            match current
                .recovery_phase(context.clone(), operation, phase)
                .await
            {
                Ok(retained) => {
                    assert_eq!(retained.record().input, input);
                    assert_eq!(retained.record().sequence, sequence);
                    assert_eq!(
                        retained.record().original_credential_expires_at_ms,
                        context.authorization.expires_at_ms().unwrap()
                    );
                    return;
                }
                Err(error) if error.code == ErrorCode::NotFound => {}
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                    ) =>
                {
                    continue;
                }
                Err(error) => panic!("exact recovery preparation unavailable: {error:?}"),
            }
            match current
                .prepare_recovery_dispatch(
                    context.clone(),
                    operation,
                    phase,
                    sequence,
                    pending,
                    input.clone(),
                )
                .await
            {
                Ok(_) => return,
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                    ) => {}
                Err(error) => panic!("exact recovery preparation rejected: {error:?}"),
            }
        }
    })
    .await
    .expect("exact recovery preparation did not resolve");
    (phase, input)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_expired_target_requires_fresh_control_admission_and_fences_revoked_observations()
{
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Guard(AtomicBool);
    impl kasumi_types::CredentialLiveness for Guard {
        fn check(&self) -> kasumi_types::Result<()> {
            if self.0.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(kasumi_types::Error::new(
                    ErrorCode::Unauthorized,
                    "revoked test credential",
                ))
            }
        }
    }
    let mut f = Fixture::new().await;
    let db = f.leader().await;
    let mut start = request(&f);
    start.phase_timeout_ms = 15_000;
    let operation = start.operation_id;
    db.recovery_control(
        f.context("owner"),
        RecoveryControlCommand::Start(Box::new(start.clone())),
    )
    .await
    .unwrap();
    let (phase, input) = prepare_next(&f, &db, operation).await;
    resolve_phase(
        &f,
        operation,
        phase,
        RecoveryDispatchOutcome::Authority(Box::new(prepare_receipt(&f, &input))),
    )
    .await;
    let (original_id, input) = prepare_next(&f, &db, operation).await;
    let RecoveryDispatch::ControlIntent(request) = input else {
        panic!("Control phase required")
    };
    let original = db
        .recovery_phase(f.context("owner"), operation, original_id)
        .await
        .unwrap();
    let limit = original.dispatch_limit().await.unwrap();
    drop(original);
    let mut fresh = f.context_for("owner", 60_000);
    fresh.authorization = fresh.authorization.with_expiry_limit(limit).unwrap();
    db.lifecycle_control(fresh, LifecycleControlCommand::CommitIntent(request))
        .await
        .unwrap();
    let original = db
        .engine()
        .generation()
        .unwrap()
        .state
        .lifecycle_control
        .as_ref()
        .unwrap()
        .intents[&original_id]
        .clone();
    assert_eq!(original.original_credential_expires_at_ms, limit);
    let outcome = RecoveryDispatchOutcome::ControlIntent(Box::new(original.clone()));
    match db
        .resolve_recovery_dispatch(f.context("owner"), operation, original_id, outcome.clone())
        .await
    {
        Ok(status) => {
            drop(status);
        }
        Err(error) if error.code == ErrorCode::UnknownOutcome => {
            // A release fence can close after consensus. Resolve the exact
            // retained phase, using a fresh invocation; never invent a new ID
            // or extend the prepared Control commitment's expiry.
            let current = f.leader().await;
            let phase = current
                .recovery_phase(f.context("owner"), operation, original_id)
                .await
                .unwrap();
            if let Some(actual) = &phase.record().outcome {
                assert_eq!(actual, &outcome);
            } else {
                current
                    .resolve_recovery_dispatch(f.context("owner"), operation, original_id, outcome)
                    .await
                    .unwrap();
            }
        }
        Err(error) => panic!("Control phase resolution rejected: {error:?}"),
    }
    let pending = Uuid::new_v4();
    let mut input = db
        .next_recovery_dispatch(&f.context("owner"), operation, pending)
        .await
        .unwrap()
        .unwrap();
    let RecoveryDispatch::Target { request, .. } = &mut input else {
        panic!("target dispatch required")
    };
    request.not_after_ms = kasumi_clock::EpochClock::system()
        .unwrap()
        .now_ms()
        .unwrap()
        + 1000;
    let frozen = input.clone();
    let head = db
        .recovery_status(f.context("owner"), operation)
        .await
        .unwrap();
    db.prepare_recovery_dispatch(
        f.context("owner"),
        operation,
        pending,
        head.record().next_phase_sequence,
        None,
        input,
    )
    .await
    .unwrap();
    drop(head);
    let observation = kasumi_clock::EpochClock::system()
        .unwrap()
        .observe()
        .unwrap();
    let guard = Arc::new(Guard(AtomicBool::new(true)));
    let mut guarded = f.context("owner");
    guarded.authorization = RequestAuthorization::from_verified_credential_with_liveness(
        observation.utc_ms() + 60_000,
        &observation,
        CredentialResource::Control {
            incarnation: Uuid::parse_str(&f.bootstrap.incarnation).unwrap(),
        },
        guard.clone(),
    )
    .unwrap();
    let status = db
        .recovery_status(guarded.clone(), operation)
        .await
        .unwrap();
    let dispatch = db
        .recovery_phase(guarded, operation, pending)
        .await
        .unwrap();
    status.release().await.unwrap();
    dispatch.admit_dispatch().await.unwrap();
    guard.0.store(false, Ordering::Release);
    assert!(status.release().await.is_err());
    assert!(dispatch.release().await.is_err());
    assert!(dispatch.admit_dispatch().await.is_err());
    drop(status);
    drop(dispatch);
    tokio::time::sleep(Duration::from_millis(1050)).await;
    let old = db
        .recovery_phase(f.context("owner"), operation, pending)
        .await
        .unwrap();
    old.release().await.unwrap();
    assert!(old.admit_dispatch().await.is_err());
    assert_eq!(old.record().input, frozen);
    assert!(old.record().outcome.is_none());
    drop(old);
    let (resumed, input) = prepare_next(&f, &db, operation).await;
    let RecoveryDispatch::ControlIntent(request) = input else {
        panic!("expired native target needs fresh Control phase")
    };
    assert_eq!(request.phase, LifecyclePhase::ResumeMaterialize);
    assert_eq!(
        request.resume_origin.as_ref().unwrap().materialization,
        original
    );
    let fresh_phase = db
        .recovery_phase(f.context("owner"), operation, resumed)
        .await
        .unwrap();
    let mut context = f.context("owner");
    context.authorization = context
        .authorization
        .with_expiry_limit(fresh_phase.dispatch_limit().await.unwrap())
        .unwrap();
    drop(fresh_phase);
    db.lifecycle_control(context, LifecycleControlCommand::CommitIntent(request))
        .await
        .unwrap();
    let resumed_intent = db
        .engine()
        .generation()
        .unwrap()
        .state
        .lifecycle_control
        .as_ref()
        .unwrap()
        .intents[&resumed]
        .clone();
    assert!(
        resumed_intent.original_credential_expires_at_ms
            > original.original_credential_expires_at_ms
    );
    resolve_phase(
        &f,
        operation,
        resumed,
        RecoveryDispatchOutcome::ControlIntent(Box::new(resumed_intent)),
    )
    .await;
    assert_eq!(
        db.engine()
            .generation()
            .unwrap()
            .state
            .lifecycle_control
            .as_ref()
            .unwrap()
            .intents[&original_id],
        original
    );
    let old = db
        .recovery_phase(f.context("owner"), operation, pending)
        .await
        .unwrap();
    assert_eq!(old.record().input, frozen);
    assert!(old.record().outcome.is_none());
    drop(old);
    snapshot(&db).await;
    drop(db);
    f.close().await;
}

async fn commit_next_control(f: &Fixture, db: &Arc<Database>, operation: Uuid) -> LifecycleIntent {
    commit_next_control_for(f, db, operation, 60_000).await
}
async fn commit_next_control_for(
    f: &Fixture,
    db: &Arc<Database>,
    operation: Uuid,
    duration: u64,
) -> LifecycleIntent {
    let (phase_id, input) = prepare_next(f, db, operation).await;
    let RecoveryDispatch::ControlIntent(command) = input else {
        panic!("Control phase required")
    };
    let phase = db
        .recovery_phase(f.context("owner"), operation, phase_id)
        .await
        .unwrap();
    let mut context = f.context_for("owner", duration);
    context.authorization = context
        .authorization
        .with_expiry_limit(phase.dispatch_limit().await.unwrap())
        .unwrap();
    drop(phase);
    db.lifecycle_control(context, LifecycleControlCommand::CommitIntent(command))
        .await
        .unwrap();
    let intent = db
        .engine()
        .generation()
        .unwrap()
        .state
        .lifecycle_control
        .as_ref()
        .unwrap()
        .intents[&phase_id]
        .clone();
    resolve_phase(
        f,
        operation,
        phase_id,
        RecoveryDispatchOutcome::ControlIntent(Box::new(intent.clone())),
    )
    .await;
    intent
}

async fn resolve_expired_completion(
    f: &Fixture,
    db: &Arc<Database>,
    operation: Uuid,
    original_phase: Uuid,
    fact: TargetCompletionFact,
    keys: &BTreeMap<u64, Ed25519KeyPair>,
) {
    let original = db
        .recovery_phase(f.context("owner"), operation, original_phase)
        .await
        .unwrap()
        .record()
        .clone();
    let old_intent = fact.completion_intent.clone();
    let now = f.context("owner").authorization.expires_at_ms().unwrap() - 60_000;
    tokio::time::sleep(Duration::from_millis(
        old_intent
            .original_credential_expires_at_ms
            .saturating_sub(now)
            + 20,
    ))
    .await;
    assert!(
        db.recovery_phase(f.context("owner"), operation, original_phase)
            .await
            .unwrap()
            .admit_dispatch()
            .await
            .is_err()
    );
    let resolution = commit_next_control(f, db, operation).await;
    assert_eq!(resolution.request.phase, LifecyclePhase::ResolveComplete);
    for node in 1..=2 {
        let (id, dispatch) = prepare_next(f, db, operation).await;
        let RecoveryDispatch::Target { node_id, request } = dispatch else {
            panic!("terminal startup required")
        };
        assert_eq!(node_id, node);
        let TargetRuntimeStep::Start(TargetReplicaInput::CompletionResolution(input)) =
            request.step
        else {
            panic!("terminal startup input required")
        };
        assert_eq!(input.attempt.intent, old_intent);
        resolve_phase(
            f,
            operation,
            id,
            RecoveryDispatchOutcome::Target(Box::new(TargetRuntimeResponse {
                command_id: request.command_id,
                node_id,
                outcome: TargetRuntimeOutcome::Started {
                    origin_sha256: input.attempt.input.quorum.origin_sha256,
                },
            })),
        )
        .await;
    }
    let (resolution_phase, dispatch) = prepare_next(f, db, operation).await;
    let RecoveryDispatch::Target { node_id, request } = dispatch else {
        panic!("terminal resolution required")
    };
    let TargetRuntimeStep::ResolveComplete(input) = request.step else {
        panic!("terminal input required")
    };
    let terminal = TargetCompletionResolutionFact {
        input: *input,
        resolution_intent: resolution.clone(),
        admitted_at_ms: resolution.accepted_at_ms + 1,
        dispatch_not_after_ms: request.not_after_ms,
        revision: fact.revision + 1,
        position: TargetCommitPosition {
            index: fact.revision - fact.origin.materialization.request.checkpoint.revision,
            term: 8,
            leader_node_id: node_id,
            command_sha256: "bb".repeat(32),
        },
        terminal: TargetCompletionTerminal::Committed(Box::new(fact.clone())),
    };
    let terminal_observation = TargetCompletionResolutionObservation {
        fact: terminal,
        observation_intent: resolution,
        observer_node_id: node_id,
        observed_revision: fact.revision + 1,
        observed_term: 8,
    };
    let terminal_signature = hex::encode(
        keys[&node_id]
            .sign(
                &serde_json::to_vec(&(
                    "kasumi.resolved-target-completion-observation.v1",
                    &terminal_observation,
                ))
                .unwrap(),
            )
            .as_ref(),
    );
    resolve_phase(
        f,
        operation,
        resolution_phase,
        RecoveryDispatchOutcome::Target(Box::new(TargetRuntimeResponse {
            command_id: request.command_id,
            node_id,
            outcome: TargetRuntimeOutcome::ResolvedCompletion(Box::new(
                SignedTargetCompletionResolution {
                    observation: terminal_observation,
                    signature: terminal_signature,
                },
            )),
        })),
    )
    .await;
    let inspection = commit_next_control(f, db, operation).await;
    assert_eq!(inspection.request.phase, LifecyclePhase::InspectTarget);
    assert_ne!(inspection.request.command_id, old_intent.request.command_id);
    for node in 1..=2 {
        let (id, dispatch) = prepare_next(f, db, operation).await;
        let RecoveryDispatch::Target { node_id, request } = dispatch else {
            panic!("fresh inspection startup required")
        };
        assert_eq!(node_id, node);
        let TargetRuntimeStep::Start(TargetReplicaInput::Inspection(input)) = request.step else {
            panic!("inspection-only startup required")
        };
        assert_eq!(input.original_phase, old_intent);
        resolve_phase(
            f,
            operation,
            id,
            RecoveryDispatchOutcome::Target(Box::new(TargetRuntimeResponse {
                command_id: request.command_id,
                node_id,
                outcome: TargetRuntimeOutcome::Started {
                    origin_sha256: input.quorum.origin_sha256,
                },
            })),
        )
        .await;
    }
    let (unresolved, first) = prepare_next(f, db, operation).await;
    let (inspection_phase, next) = prepare_next(f, db, operation).await;
    let RecoveryDispatch::Target {
        node_id: first_node,
        request: first,
    } = first
    else {
        panic!("inspection required")
    };
    let RecoveryDispatch::Target { node_id, request } = next else {
        panic!("inspection peer retry required")
    };
    assert_eq!((first_node, node_id), (1, 2));
    assert_eq!(
        first, request,
        "inspection retries preserve their exact finite request"
    );
    assert!(
        db.recovery_phase(f.context("owner"), operation, unresolved)
            .await
            .unwrap()
            .record()
            .outcome
            .is_none()
    );
    let TargetRuntimeStep::Inspect(input) = request.step else {
        panic!("metadata inspection required")
    };
    let observed_revision = fact.revision;
    let observation = TargetInspectionObservation {
        input: *input,
        inspection_intent: inspection,
        completion: fact,
        activation: None,
        observer_node_id: node_id,
        observed_revision,
        observed_term: 8,
    };
    let sign = |observation: TargetInspectionObservation| SignedTargetInspection {
        signature: hex::encode(
            keys[&node_id]
                .sign(
                    &serde_json::to_vec(&("kasumi.inspected-target-observation.v1", &observation))
                        .unwrap(),
                )
                .as_ref(),
        ),
        observation,
    };
    let response = |signed| {
        RecoveryDispatchOutcome::Target(Box::new(TargetRuntimeResponse {
            command_id: request.command_id,
            node_id,
            outcome: TargetRuntimeOutcome::Inspected(Box::new(signed)),
        }))
    };
    let mut wrong = observation.clone();
    wrong.input.original_phase.request.command_id = Uuid::new_v4();
    assert!(
        db.resolve_recovery_dispatch(
            f.context("owner"),
            operation,
            inspection_phase,
            response(sign(wrong))
        )
        .await
        .is_err()
    );
    let mut late = observation.clone();
    late.completion.admitted_at_ms = old_intent.original_credential_expires_at_ms;
    assert!(
        db.resolve_recovery_dispatch(
            f.context("owner"),
            operation,
            inspection_phase,
            response(sign(late))
        )
        .await
        .is_err()
    );
    resolve_phase(f, operation, inspection_phase, response(sign(observation))).await;
    let retained = db
        .recovery_phase(f.context("owner"), operation, original_phase)
        .await
        .unwrap();
    assert_eq!(retained.record().input, original.input);
    assert_eq!(
        retained.record().original_credential_expires_at_ms,
        original.original_credential_expires_at_ms
    );
    assert_eq!(
        retained.record().outcome,
        Some(RecoveryDispatchOutcome::CompletionTerminal { resolution_phase })
    );
    drop(retained);
    let head = db
        .recovery_status(f.context("owner"), operation)
        .await
        .unwrap();
    assert_eq!(head.record().completion, Some(inspection_phase));
    assert_eq!(head.record().completion_attempt, Some(original_phase));
    assert_eq!(
        head.record().completion_intent,
        Some(old_intent.request.command_id)
    );
    assert_eq!(head.record().phase, RecoveryPhase::FenceSource);
    drop(head);
    snapshot(db).await;
}

async fn reject_changed_completion_caps(f: &Fixture, operation: Uuid) {
    for delta in [-1_i64, 1] {
        let db = f.leader().await;
        let context = f.context("owner");
        let id = Uuid::new_v4();
        let head = db
            .recovery_status(context.clone(), operation)
            .await
            .unwrap()
            .record()
            .clone();
        let mut input = db
            .next_recovery_dispatch(&context, operation, id)
            .await
            .unwrap()
            .unwrap();
        let RecoveryDispatch::Target { request, .. } = &mut input else {
            panic!("Complete required");
        };
        assert!(matches!(request.step, TargetRuntimeStep::Complete(_)));
        request.not_after_ms = request.not_after_ms.checked_add_signed(delta).unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let current = f.leader().await;
                match current
                    .prepare_recovery_dispatch(
                        context.clone(),
                        operation,
                        id,
                        head.next_phase_sequence,
                        head.pending_phase,
                        input.clone(),
                    )
                    .await
                {
                    Err(error)
                        if matches!(
                            error.code,
                            ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => {
                        assert_eq!(error.code, ErrorCode::Conflict, "{error}");
                        break;
                    }
                    Ok(_) => panic!("changed original Complete cap was committed"),
                }
            }
        })
        .await
        .expect("exact negative Complete admission did not resolve");
        let current = f.leader().await;
        let error = current
            .recovery_phase(f.context("owner"), operation, id)
            .await
            .err()
            .expect("rejected phase was retained");
        assert_eq!(error.code, ErrorCode::NotFound);
        assert_eq!(
            *current
                .recovery_status(f.context("owner"), operation)
                .await
                .unwrap()
                .record(),
            head
        );
        snapshot(&current).await;
    }
}
