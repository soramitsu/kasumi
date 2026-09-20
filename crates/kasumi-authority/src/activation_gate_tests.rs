use super::*;

pub(super) async fn exact_administrative(
    f: &Fixture,
    command: AuthorityCommand,
) -> AuthorityReceipt {
    f.exact_administrative(command).await
}
async fn prepared_target(f: &Fixture) -> RecoveryTarget {
    let source = Uuid::new_v4();
    let enrolled = exact_administrative(
        f,
        f.command(AuthorityAction::Enroll {
            incarnation: source,
            nodes: nodes(),
        }),
    )
    .await;
    assert!(matches!(
        enrolled.outcome,
        AuthorityOutcome::Enrolled { .. }
    ));
    let target = target(source);
    let prepared = exact_administrative(
        f,
        f.command(AuthorityAction::PrepareTarget {
            source_incarnation: source,
            source_epoch: 1,
            target: target.clone(),
        }),
    )
    .await;
    assert!(matches!(
        prepared.outcome,
        AuthorityOutcome::TargetPrepared { .. }
    ));
    target
}
async fn fence_target(f: &Fixture, target: &RecoveryTarget) -> AuthorityReceipt {
    let receipt = exact_administrative(
        f,
        f.command(AuthorityAction::Fence {
            incarnation: Uuid::parse_str(&target.checkpoint.source_incarnation).unwrap(),
            authority_epoch: 1,
        }),
    )
    .await;
    assert!(matches!(receipt.outcome, AuthorityOutcome::Fenced { .. }));
    receipt
}
// Explicit signature fixture for issuer reducer tests only. Actual native
// materialization/completion production signing is separately engine-tested.
fn completion_fixture(
    control: &ControlFixture,
    f: &Fixture,
    target: &RecoveryTarget,
    expiry: u64,
) -> SignedTargetCompletion {
    let mut original = control.intent(f, target, expiry).observation.intent;
    let input = TargetMaterializationInput {
        destination_alias: "fixture".into(),
        backup_id: target.checkpoint.backup_id,
        source_purpose_sha256: digest(&kasumi_store::StoragePurpose::LocalFixture).unwrap(),
        target_incarnation: target.incarnation,
        voters: target
            .nodes
            .iter()
            .map(|n| {
                (
                    n.node_id,
                    TargetPeer {
                        endpoint: format!("fixture-{}", n.node_id),
                        failure_domain: format!("zone-{}", n.node_id),
                    },
                )
            })
            .collect(),
    };
    original.request.phase_input_sha256 = input.digest().unwrap();
    let mut keys = BTreeMap::new();
    for (id, n) in &mut original.request.target_nodes {
        let key = Ed25519KeyPair::from_seed_unchecked(&[*id as u8; 32]).unwrap();
        n.attestation_public_key = hex::encode(key.public_key().as_ref());
        keys.insert(*id, key);
    }
    original.request_sha256 = digest(&original.request).unwrap();
    let origin = TargetOrigin {
        authority_manifest_sha256: f.installation.manifest.digest().unwrap(),
        materialization: original,
        input,
    };
    let materialized: BTreeMap<_, _> = keys
        .iter()
        .map(|(id, key)| {
            let fact = TargetMaterializationFact {
                origin: origin.clone(),
                node_id: *id,
                bootstrap_sha256: "ac".repeat(32),
                revision_base: target.checkpoint.revision + 1,
            };
            let signature = hex::encode(
                key.sign(&serde_json::to_vec(&("kasumi.materialized-target.v1", &fact)).unwrap())
                    .as_ref(),
            );
            (*id, SignedTargetMaterialization { fact, signature })
        })
        .collect();
    let mut completion_intent = origin.materialization.clone();
    completion_intent.request.command_id = Uuid::new_v4();
    completion_intent.request.phase = LifecyclePhase::Complete;
    completion_intent.request.phase_input_sha256 = kasumi_types::TargetCompletionInput {
        quorum: TargetQuorumInput {
            origin_sha256: origin.digest().unwrap(),
            materialized: materialized.clone(),
        },
        predecessor: None,
    }
    .digest()
    .unwrap();
    completion_intent.request_sha256 = digest(&completion_intent.request).unwrap();
    completion_intent.revision += 1;
    let fact = TargetCompletionFact {
        origin,
        materialized,
        completion_intent,
        predecessor: None,
        admitted_at_ms: 1_000_000,
        revision: target.checkpoint.revision + 3,
        term: 1,
        leader_node_id: 1,
        bootstrap_sha256: "ac".repeat(32),
    };
    let observation = TargetCompletionObservation {
        observed_revision: fact.revision,
        observed_term: 1,
        observer_node_id: 1,
        fact,
    };
    let signature = hex::encode(
        keys[&1]
            .sign(
                &serde_json::to_vec(&("kasumi.completed-target-observation.v1", &observation))
                    .unwrap(),
            )
            .as_ref(),
    );
    SignedTargetCompletion {
        observation,
        signature,
    }
}

fn activation_intent(
    control: &ControlFixture,
    f: &Fixture,
    target: &RecoveryTarget,
    fence: &AuthorityReceipt,
    expiry: u64,
) -> (SignedControlIntent, SignedTargetCompletion) {
    let completion = completion_fixture(control, f, target, expiry);
    let mut signed = control.intent(f, target, expiry);
    let request = &mut signed.observation.intent.request;
    request.target_nodes = completion
        .observation
        .fact
        .origin
        .materialization
        .request
        .target_nodes
        .clone();
    request.phase = LifecyclePhase::Activate;
    request.phase_input_sha256 = ActivateTargetInput {
        completion_sha256: completion.observation.fact.digest().unwrap(),
        fence_id: fence.command.command_id,
        fence_digest: fence.digest().unwrap(),
        target: target.clone(),
    }
    .digest()
    .unwrap();
    signed.observation.intent.request_sha256 = digest(&signed.observation.intent.request).unwrap();
    control.sign_intent(&mut signed);
    (signed, completion)
}
fn activation(
    f: &Fixture,
    target: &RecoveryTarget,
    fence: &AuthorityReceipt,
    signed: &SignedControlIntent,
    completion: &SignedTargetCompletion,
) -> AuthorityCommand {
    let accepted = request(signed);
    f.command(AuthorityAction::ActivateCommitted {
        fence_id: fence.command.command_id,
        fence_digest: fence.digest().unwrap(),
        target: target.clone(),
        control: CommittedActivation {
            completion: Box::new(kasumi_types::CommittedCompletion::Original(Box::new(
                completion.clone(),
            ))),
            reference: accepted.reference(),
            intent_sha256: accepted.digest().unwrap(),
        },
    })
}
#[tokio::test]
async fn committed_activation_rejects_raw_bypass_preserves_exact_winner_and_encrypted_recovery() {
    let control = ControlFixture::new();
    let mut f = control.issuer().await;
    let service = f.leader().await;
    let t = prepared_target(&f).await;
    let fence = fence_target(&f, &t).await;
    let raw = f.command(AuthorityAction::Activate {
        fence_id: fence.command.command_id,
        fence_digest: fence.digest().unwrap(),
        target: t.clone(),
    });
    assert!(
        service
            .execute(f.context("operator"), raw.clone())
            .await
            .is_err()
    );
    f.clock.0.store(1000, Ordering::SeqCst);
    let rejected = service.execute(f.context("operator"), raw).await.unwrap().0;
    assert!(matches!(
        rejected.receipt.outcome,
        AuthorityOutcome::Rejected { .. }
    ));
    let (signed, completion) = activation_intent(&control, &f, &t, &fence, 1_050_000);
    service
        .execute_lifecycle(f.context("operator"), request(&signed))
        .await
        .unwrap();
    let command = activation(&f, &t, &fence, &signed, &completion);
    let roundtrip: AuthorityCommand =
        serde_json::from_slice(&serde_json::to_vec(&command).unwrap()).unwrap();
    assert_eq!(roundtrip, command);
    let (a, b) = tokio::join!(
        exact_administrative(&f, command.clone()),
        exact_administrative(&f, command.clone())
    );
    assert_eq!(a, b);
    assert!(matches!(a.outcome, AuthorityOutcome::Activated { .. }));
    let mut snapshot = Vec::new();
    kasumi_raft::StateMachineBackend::snapshot(service.backend.as_ref(), &mut snapshot).unwrap();
    kasumi_raft::StateMachineBackend::validate_snapshot(
        service.backend.as_ref(),
        &mut snapshot.as_slice(),
    )
    .unwrap();
    fn replace_admission(value: &mut serde_json::Value, command: Uuid) {
        if let Some(object) = value.as_object_mut() {
            if object
                .get("command")
                .is_some_and(|v| v["command_id"] == command.to_string())
                && object.contains_key("admitted_at_ms")
            {
                object.insert("admitted_at_ms".into(), serde_json::json!(1_050_000));
            }
            for child in object.values_mut() {
                replace_admission(child, command);
            }
        } else if let Some(array) = value.as_array_mut() {
            for child in array {
                replace_admission(child, command);
            }
        }
    }
    // Substitute all retained copies together; semantic history still rejects
    // execution beyond the immutable original Control cap.
    let substituted = crate::state::snapshot::rewrite_for_test(&snapshot, |value| {
        replace_admission(value, command.command_id)
    });
    assert!(
        kasumi_raft::StateMachineBackend::validate_snapshot(
            service.backend.as_ref(),
            &mut substituted.as_slice()
        )
        .is_err()
    );
    drop(service);
    f.reopen().await;
    let service = f.leader().await;
    f.clock.0.store(60_000, Ordering::SeqCst);
    let retained = service
        .receipt(f.context("operator"), "city", command.command_id)
        .await
        .unwrap()
        .0
        .unwrap();
    assert_eq!(retained.receipt, a);
    let stop_command = f.command(AuthorityAction::StopActivation {
        original: Box::new(command),
    });
    let stop_context = f.context("operator");
    // A leadership transition after restart can lose an acknowledgement. Resolve
    // this exact command with the original credential fence and no new identity.
    let stopped = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let current = f.leader().await;
            match current
                .execute(stop_context.clone(), stop_command.clone())
                .await
            {
                Ok((receipt, fence)) => {
                    fence.release().await.unwrap();
                    break receipt;
                }
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                    ) =>
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("exact stop recovery failed: {error}"),
            }
        }
    })
    .await
    .unwrap();
    assert!(
        matches!(stopped.receipt.outcome,AuthorityOutcome::ActivationResolved{original} if original==Box::new(a))
    );
    drop(service);
    f.close().await;
}
#[tokio::test]
async fn stopped_control_epoch_and_queued_original_expiry_defeat_new_activation_effects() {
    for stop_epoch in [true, false] {
        let control = ControlFixture::new();
        let f = control.issuer().await;
        let service = f.leader().await;
        let t = prepared_target(&f).await;
        let fence = fence_target(&f, &t).await;
        let (signed, completion) = activation_intent(&control, &f, &t, &fence, 1_002_000);
        drop(service);
        let (mut service, _) = accepted_on_current_leader(&f, request(&signed)).await;
        let command = activation(&f, &t, &fence, &signed, &completion);
        let roundtrip: AuthorityCommand =
            serde_json::from_slice(&serde_json::to_vec(&command).unwrap()).unwrap();
        assert_eq!(roundtrip, command);
        assert!(
            service
                .execute(f.context("operator"), command.clone())
                .await
                .is_err()
        );
        f.clock.0.store(1000, Ordering::SeqCst);
        if stop_epoch {
            let (current, _) = accepted_on_current_leader(
                &f,
                LifecycleAuthorityRequest::StopEpoch(Box::new(control.stop(&signed))),
            )
            .await;
            service = current;
        }
        let gate = service.proposal.lock().await;
        let task = {
            let service = service.clone();
            let context = f.context("operator");
            let command = command.clone();
            tokio::spawn(async move { service.execute(context, command).await })
        };
        tokio::task::yield_now().await;
        if !stop_epoch {
            f.clock.0.store(2000, Ordering::SeqCst);
        }
        drop(gate);
        let attempted = task.await.unwrap();
        let result = match attempted {
            Ok((receipt, _)) => receipt.receipt,
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                ) =>
            {
                exact_administrative(&f, command.clone()).await
            }
            Err(error) => panic!("unexpected queued rejection: {error:?}"),
        };
        assert!(matches!(result.outcome, AuthorityOutcome::Rejected { .. }));
        assert_ne!(
            service
                .backend
                .tenant_record("city")
                .unwrap()
                .unwrap()
                .incarnation,
            t.incarnation
        );
        drop(service);
        f.close().await;
    }
}
pub(super) fn original_control(
    f: &Fixture,
    control: &ControlFixture,
    expiry: u64,
) -> RequestContext {
    RequestContext {
        tenant: "__kasumi_control".into(),
        principal: "control-admin".into(),
        request_id: Uuid::new_v4().to_string(),
        scopes: BTreeSet::from([Action::Admin]),
        authorization: RequestAuthorization::from_verified_credential(
            expiry,
            &f.epoch.observe().unwrap(),
            CredentialResource::Control {
                incarnation: control.root.control_incarnation,
            },
        )
        .unwrap(),
    }
}
#[tokio::test]
async fn target_storage_retains_original_phase_and_cannot_install_late_renewal_or_new_gate() {
    let control = ControlFixture::new();
    let f = control.issuer().await;
    let service = f.leader().await;
    let t = prepared_target(&f).await;
    let signed = control.intent(&f, &t, 1_050_000);
    service
        .execute_lifecycle(f.context("operator"), request(&signed))
        .await
        .unwrap();
    let intent = ControlTrust::install(control.root.clone())
        .unwrap()
        .verify_intent(&signed)
        .unwrap();
    let trust = f.trust.clone();
    let identity = ServingIdentity {
        tenant: "city".into(),
        incarnation: t.incarnation,
        authority_epoch: 2,
        node: nodes().first().unwrap().clone(),
    };
    let serving_boot = ServingBoot::with_test_clock(trust.clone(), identity, f.clock.clone())
        .unwrap()
        .for_restore_preparation();
    let attempt = serving_boot.begin_acquisition().unwrap();
    let lease = service
        .acquire(node(&f), attempt.request().clone())
        .await
        .unwrap()
        .0;
    let serving = ServingGate::new(attempt.verify(lease).unwrap()).unwrap();
    assert!(kasumi_store::StorageAccess::serving(serving.clone()).is_err());
    let phase_boot =
        LifecycleBoot::with_clock(trust, nodes().first().unwrap().clone(), f.clock.clone())
            .unwrap();
    let attempt = phase_boot.begin(&intent).unwrap();
    let lease = service
        .acquire_lifecycle(node(&f), attempt.request().clone())
        .await
        .unwrap()
        .0;
    let phase = LifecycleGate::with_test_clock(
        original_control(&f, &control, 1_050_000),
        attempt.verify(lease).unwrap(),
        f.epoch.clone(),
    )
    .unwrap();
    let captured = phase.capture().unwrap();
    let node_store = NodeStore::create_new(
        f._dir.path().join("actual-target.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let provider = Arc::new(LocalKeyProvider::new([91; 32]));
    let access = kasumi_store::StorageAccess::target_phase(serving.clone(), phase.clone()).unwrap();
    let store = kasumi_store::TenantStore::initialize_catalog_fixture_with_access(
        node_store.clone(),
        "city".into(),
        provider.clone(),
        access,
    )
    .await
    .unwrap();
    store
        .write_batch(&[kasumi_store::WriteOp::put(
            "bootstrap",
            b"phase",
            b"original",
        )])
        .unwrap();
    assert!(store.storage_access().check_serving().is_err());
    f.clock.0.store(500, Ordering::SeqCst);
    let attempt = phase_boot.begin(&intent).unwrap();
    let newer = attempt
        .verify(
            service
                .acquire_lifecycle(node(&f), attempt.request().clone())
                .await
                .unwrap()
                .0,
        )
        .unwrap();
    let new_gate = LifecycleGate::with_test_clock(
        original_control(&f, &control, 1_050_000),
        newer.clone(),
        f.epoch.clone(),
    )
    .unwrap();
    assert!(
        kasumi_store::TenantStore::open_existing_fixture_with_access(
            node_store,
            "city".into(),
            provider,
            kasumi_store::StorageAccess::target_phase(serving.clone(), new_gate).unwrap()
        )
        .await
        .is_err()
    );
    // No reader observes old expiry before renewal installation. The previous
    // true deadline still closes the old gate and all captured fences.
    f.clock.0.store(1000, Ordering::SeqCst);
    assert!(phase.renew(newer).is_err());
    assert!(captured.check().is_err());
    assert!(
        store
            .write_batch(&[kasumi_store::WriteOp::put("bootstrap", b"late", b"denied")])
            .is_err()
    );
    store.shutdown().await.unwrap();
    drop(store);
    drop(service);
    f.close().await;
}

#[tokio::test]
async fn resolved_completion_activates_only_with_its_distinct_positive_inspection_signature() {
    let control = ControlFixture::new();
    let mut f = control.issuer().await;
    let t = prepared_target(&f).await;
    let fence = fence_target(&f, &t).await;
    // Establish the issuer drain witness before advancing this fixture's
    // manually controlled lease clock past the original completion lifetime.
    let undrained = f.command(AuthorityAction::Activate {
        fence_id: fence.command.command_id,
        fence_digest: fence.digest().unwrap(),
        target: t.clone(),
    });
    assert!(
        f.leader()
            .await
            .execute(f.context("operator"), undrained)
            .await
            .is_err()
    );
    let original = completion_fixture(&control, &f, &t, 1_002_000);
    assert!(
        serde_json::from_value::<CommittedCompletion>(serde_json::to_value(&original).unwrap())
            .is_err(),
        "untagged original completion format must be rejected"
    );
    let input = TargetInspectionInput {
        quorum: TargetQuorumInput {
            origin_sha256: original.observation.fact.origin.digest().unwrap(),
            materialized: original.observation.fact.materialized.clone(),
        },
        original_phase: original.observation.fact.completion_intent.clone(),
        predecessor: original.observation.fact.predecessor.clone(),
    };
    let mut inspection = input.original_phase.clone();
    inspection.request.command_id = Uuid::new_v4();
    inspection.request.phase = LifecyclePhase::InspectTarget;
    inspection.request.phase_input_sha256 = input.digest().unwrap();
    inspection.request_sha256 = digest(&inspection.request).unwrap();
    inspection.accepted_at_ms = 1_003_000;
    inspection.original_credential_expires_at_ms = 1_050_000;
    inspection.revision += 1;
    let observation = TargetInspectionObservation {
        input,
        inspection_intent: inspection,
        completion: original.observation.fact.clone(),
        activation: None,
        observer_node_id: 1,
        observed_revision: original.observation.fact.revision,
        observed_term: original.observation.observed_term,
    };
    observation.validate().unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
    let resolved = SignedTargetInspection {
        signature: hex::encode(
            key.sign(
                &serde_json::to_vec(&("kasumi.inspected-target-observation.v1", &observation))
                    .unwrap(),
            )
            .as_ref(),
        ),
        observation,
    };
    kasumi_serving::verify_committed_completion(
        &original.observation.fact.origin,
        &CommittedCompletion::Resolved(Box::new(resolved.clone())),
    )
    .unwrap();
    let (mut fresh, _) = activation_intent(&control, &f, &t, &fence, 1_050_000);
    fresh.observation.intent.request.phase_input_sha256 = ActivateTargetInput {
        completion_sha256: original.observation.fact.digest().unwrap(),
        fence_id: fence.command.command_id,
        fence_digest: fence.digest().unwrap(),
        target: t.clone(),
    }
    .digest()
    .unwrap();
    fresh.observation.intent.request_sha256 = digest(&fresh.observation.intent.request).unwrap();
    control.sign_intent(&mut fresh);
    f.clock.0.store(3000, Ordering::SeqCst);
    assert!(
        f.epoch.observe().unwrap().utc_ms()
            >= original
                .observation
                .fact
                .completion_intent
                .original_credential_expires_at_ms
    );
    let (service, _) = accepted_on_current_leader(&f, request(&fresh)).await;
    let mut command = activation(&f, &t, &fence, &fresh, &original);
    if let AuthorityAction::ActivateCommitted { control, .. } = &mut command.action {
        *control.completion = CommittedCompletion::Resolved(Box::new(resolved.clone()));
    }
    let mut wrong_domain = command.clone();
    wrong_domain.command_id = Uuid::new_v4();
    if let AuthorityAction::ActivateCommitted { control, .. } = &mut wrong_domain.action {
        let CommittedCompletion::Resolved(proof) = control.completion.as_mut() else {
            unreachable!()
        };
        proof.signature = original.signature.clone();
    }
    assert!(matches!(
        exact_administrative(&f, wrong_domain).await.outcome,
        AuthorityOutcome::Rejected { .. }
    ));
    let mut changed_original = command.clone();
    changed_original.command_id = Uuid::new_v4();
    if let AuthorityAction::ActivateCommitted { control, .. } = &mut changed_original.action {
        let CommittedCompletion::Resolved(proof) = control.completion.as_mut() else {
            unreachable!()
        };
        let original = &mut proof.observation.input.original_phase;
        original.request.command_id = Uuid::new_v4();
        original.request_sha256 = digest(&original.request).unwrap();
        proof.observation.completion.completion_intent = original.clone();
        let input_sha256 = proof.observation.input.digest().unwrap();
        let inspection = &mut proof.observation.inspection_intent;
        inspection.request.phase_input_sha256 = input_sha256;
        inspection.request_sha256 = digest(&inspection.request).unwrap();
        proof.observation.validate().unwrap();
        proof.signature = hex::encode(
            key.sign(
                &serde_json::to_vec(&(
                    "kasumi.inspected-target-observation.v1",
                    &proof.observation,
                ))
                .unwrap(),
            )
            .as_ref(),
        );
    }
    assert!(matches!(
        exact_administrative(&f, changed_original).await.outcome,
        AuthorityOutcome::Rejected { .. }
    ));
    let accepted = exact_administrative(&f, command.clone()).await;
    assert!(matches!(
        accepted.outcome,
        AuthorityOutcome::Activated { .. }
    ));
    let mut snapshot = Vec::new();
    kasumi_raft::StateMachineBackend::snapshot(service.backend.as_ref(), &mut snapshot).unwrap();
    kasumi_raft::StateMachineBackend::validate_snapshot(
        service.backend.as_ref(),
        &mut snapshot.as_slice(),
    )
    .unwrap();
    drop(service);
    f.reopen().await;
    assert_eq!(exact_administrative(&f, command).await, accepted);
    f.close().await;
}
