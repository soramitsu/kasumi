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
                            endpoint: format!("target-{id}"),
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
    let mut f = Fixture::new().await;
    let mut request = request(&f);
    let mut attestation = BTreeMap::new();
    for node in request.target_nodes.values_mut() {
        let pair = key();
        node.attestation_public_key = hex::encode(pair.public_key().as_ref());
        attestation.insert(node.node_id, pair);
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
    let materialize = db
        .resolve_recovery_dispatch(
            f.context("owner"),
            id,
            phase_id,
            RecoveryDispatchOutcome::Authority(Box::new(signed)),
        )
        .await
        .unwrap();
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
    f.open().await;
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
    let state = db
        .resolve_recovery_dispatch(
            f.context("owner"),
            id,
            intent_phase,
            RecoveryDispatchOutcome::ControlIntent(Box::new(committed.clone())),
        )
        .await
        .unwrap();
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
        db.resolve_recovery_dispatch(
            f.context("owner"),
            id,
            phase_id,
            RecoveryDispatchOutcome::Target(Box::new(response)),
        )
        .await
        .unwrap();
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
    db.resolve_recovery_dispatch(
        f.context("owner"),
        id,
        stop_phase,
        RecoveryDispatchOutcome::Authority(Box::new(signed)),
    )
    .await
    .unwrap();
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
    db.resolve_recovery_dispatch(
        f.context("owner"),
        id,
        cleanup_phase,
        RecoveryDispatchOutcome::ControlIntent(Box::new(intent.clone())),
    )
    .await
    .unwrap();
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
        db.resolve_recovery_dispatch(f.context("owner"), id, phase_id, response(observation))
            .await
            .unwrap();
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
    f.open().await;
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
}
async fn prepare_next(
    f: &Fixture,
    db: &Arc<Database>,
    operation: Uuid,
) -> (Uuid, RecoveryDispatch) {
    let head = db
        .recovery_status(f.context("owner"), operation)
        .await
        .unwrap();
    let phase = Uuid::new_v4();
    let input = db
        .next_recovery_dispatch(&f.context("owner"), operation, phase)
        .await
        .unwrap()
        .unwrap();
    db.prepare_recovery_dispatch(
        f.context("owner"),
        operation,
        phase,
        head.record().next_phase_sequence,
        head.record().pending_phase,
        input.clone(),
    )
    .await
    .unwrap();
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
    db.resolve_recovery_dispatch(
        f.context("owner"),
        operation,
        phase,
        RecoveryDispatchOutcome::Authority(Box::new(prepare_receipt(&f, &input))),
    )
    .await
    .unwrap();
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
    db.resolve_recovery_dispatch(
        f.context("owner"),
        operation,
        resumed,
        RecoveryDispatchOutcome::ControlIntent(Box::new(resumed_intent)),
    )
    .await
    .unwrap();
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
