use super::*;
use kasumi_raft::StateMachineBackend;

fn receiver(f: &Fixture, request: &ControlSignerRequest) -> AuthenticatedNode {
    AuthenticatedNode {
        context: f.context(&request.directive.node.principal),
        certificate_sha256: request.directive.node.certificate_sha256.clone(),
    }
}

async fn current_observation(
    f: &Fixture,
    request: &ControlSignerRequest,
) -> (ControlSignerObservation, ControlSignerObservationFence) {
    // Only leader availability may retry, with one original credential and request.
    let caller = receiver(f, request);
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let original = AuthenticatedNode {
                context: caller.context.clone(),
                certificate_sha256: caller.certificate_sha256.clone(),
            };
            match f
                .leader()
                .await
                .observe_control_signer(original, request.clone())
                .await
            {
                Ok((reply, fence)) if fence.release().await.is_ok() => return (reply, fence),
                Ok(_) => {}
                Err(error) if error.code == ErrorCode::Unavailable => {}
                Err(error) => panic!("unexpected current receiver rejection: {error:?}"),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn remote_control_directives_bind_physical_receiver_and_forward_winner_across_restart() {
    let control = ControlFixture::new();
    let mut f = control.issuer().await;
    let controls = distinct_nodes();
    let mut enrolled = nodes();
    enrolled.extend(controls.clone());
    for (index, node) in enrolled.iter().enumerate() {
        let response = signing_transition(
            &f,
            AuthorityMaintenanceAction::EnrollSignerVerifier {
                enrollment: SignerVerifierEnrollment {
                    verifier: node.verifier.clone(),
                    endpoint: format!("https://remote-{index}.test/"),
                    certificate_pins: BTreeSet::from([format!("{:064x}", 8000 + index)]),
                },
            },
        )
        .await;
        assert_eq!(
            response.status.unwrap().phase,
            AuthorityMaintenancePhase::Completed
        );
    }
    let response = signing_transition(
        &f,
        AuthorityMaintenanceAction::AdmitControlVerifiers {
            admission: ControlVerifierAdmission {
                root: control.root.clone(),
                partition: f.installation.manifest.control_partition(0).unwrap(),
                nodes: controls.clone(),
            },
        },
    )
    .await;
    assert_eq!(
        response.status.unwrap().phase,
        AuthorityMaintenancePhase::Completed
    );
    let key = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let certificate = f
        .signing_root
        .certify(2, hex::encode(key.public_key().as_ref()))
        .unwrap();
    let stage = signing_transition(
        &f,
        AuthorityMaintenanceAction::StageSignerGeneration {
            certificate: certificate.clone(),
        },
    )
    .await;
    let global_stage = stage.status.unwrap();
    assert_eq!(global_stage.phase, AuthorityMaintenancePhase::Completed);
    let request = ControlSignerRequest {
        observation_id: Uuid::new_v4(),
        directive: ControlSignerDirective {
            root: control.root.clone(),
            node: controls.first().unwrap().clone(),
            domain_sha256: certificate.identity.domain.digest().unwrap(),
            global_stage_operation_id: global_stage.command.operation_id,
            global_activation_operation_id: None,
            command: SignerTrustCommand {
                operation_id: Uuid::new_v4(),
                expected_revision: 0,
                not_after_ms: 1_050_000,
                action: SignerTrustAction::Stage {
                    certificate: certificate.clone(),
                },
            },
        },
    };
    let service = f.leader().await;
    assert!(
        service
            .observe_control_signer(receiver(&f, &request), request.clone())
            .await
            .is_err()
    );
    let permission = signing_transition(
        &f,
        AuthorityMaintenanceAction::AuthorizeControlSigner {
            directive: Box::new(request.directive.clone()),
        },
    )
    .await
    .status
    .unwrap();
    assert_eq!(permission.phase, AuthorityMaintenancePhase::Completed);
    let (observed, original_fence) = current_observation(&f, &request).await;
    observed
        .validate_for(&request, &f.installation.manifest)
        .unwrap();
    assert!(observed.may_apply);
    assert_eq!(observed.authorization, permission);
    let wire = serde_json::to_vec(&observed).unwrap();
    let decoded: ControlSignerObservation = serde_json::from_slice(&wire).unwrap();
    let mut another_observation = request.clone();
    another_observation.observation_id = Uuid::new_v4();
    assert!(
        decoded
            .validate_for(&another_observation, &f.installation.manifest)
            .is_err()
    );
    let mut another_receiver = request.clone();
    another_receiver.directive.node.verifier.installation_id = Uuid::new_v4();
    assert!(
        service
            .observe_control_signer(receiver(&f, &another_receiver), another_receiver)
            .await
            .is_err()
    );
    let mut wrong_tls = receiver(&f, &request);
    wrong_tls.certificate_sha256 = "fa".repeat(32);
    assert_eq!(
        service
            .observe_control_signer(wrong_tls, request.clone())
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Forbidden
    );
    let mut decoded_context = receiver(&f, &request);
    decoded_context.context =
        serde_json::from_slice(&serde_json::to_vec(&decoded_context.context).unwrap()).unwrap();
    assert!(
        service
            .observe_control_signer(decoded_context, request.clone())
            .await
            .is_err()
    );

    let exact_replay = AuthoritySigningRequest {
        observation_id: Uuid::new_v4(),
        domain_sha256: request.directive.domain_sha256.clone(),
        action: AuthoritySigningAction::Start {
            command: permission.command.clone(),
        },
    };
    let (replayed, fence) = service
        .signing_maintenance(f.context("operator"), exact_replay.clone())
        .await
        .unwrap();
    fence.release().await.unwrap();
    assert_eq!(replayed.status.unwrap(), permission);
    let mut conflict = exact_replay;
    let AuthoritySigningAction::Start { command } = &mut conflict.action else {
        unreachable!()
    };
    let AuthorityMaintenanceAction::AuthorizeControlSigner { directive } = &mut command.action
    else {
        unreachable!()
    };
    directive.command.expected_revision = 7;
    assert_eq!(
        service
            .signing_maintenance(f.context("operator"), conflict)
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );

    // A fresh current observation cannot repair a previously expired fence.
    f.clock.0.store(1001, Ordering::SeqCst);
    assert!(original_fence.check().is_err());
    let (_, fresh_fence) = current_observation(&f, &request).await;
    assert!(original_fence.check().is_err());
    fresh_fence.check().unwrap();
    let mut activation = request.clone();
    activation.observation_id = Uuid::new_v4();
    activation.directive.global_activation_operation_id = Some(Uuid::new_v4());
    activation.directive.command = SignerTrustCommand {
        operation_id: Uuid::new_v4(),
        expected_revision: 1,
        not_after_ms: 1_050_000,
        action: SignerTrustAction::Activate {
            staged_operation_id: request.directive.command.operation_id,
            certificate_sha256: certificate.digest().unwrap(),
        },
    };
    assert!(matches!(
        signing_transition(
            &f,
            AuthorityMaintenanceAction::AuthorizeControlSigner {
                directive: Box::new(activation.directive.clone()),
            }
        )
        .await
        .status
        .unwrap()
        .phase,
        AuthorityMaintenancePhase::Rejected { .. }
    ));
    let winner = signing_transition(
        &f,
        AuthorityMaintenanceAction::ActivateSignerGeneration {
            stage_operation_id: global_stage.command.operation_id,
            certificate_sha256: certificate.digest().unwrap(),
        },
    )
    .await;
    let winner_status = winner.status.unwrap();
    assert_eq!(winner_status.phase, AuthorityMaintenancePhase::Completed);
    assert!(fresh_fence.check().is_err());
    // Global activation seals old issuance, but current maintenance remains available.
    assert!(
        service
            .check_issuance_signer(&service.request_signer().unwrap())
            .is_err()
    );
    let (forward_stage, _) = current_observation(&f, &request).await;
    assert_eq!(forward_stage.head.active, certificate);
    activation.directive.command.operation_id = Uuid::new_v4();
    activation.directive.global_activation_operation_id = Some(winner_status.command.operation_id);
    let activated = signing_transition(
        &f,
        AuthorityMaintenanceAction::AuthorizeControlSigner {
            directive: Box::new(activation.directive.clone()),
        },
    )
    .await
    .status
    .unwrap();
    assert_eq!(activated.phase, AuthorityMaintenancePhase::Completed);
    let (before_restart, activation_fence) = current_observation(&f, &activation).await;
    assert_eq!(before_restart.authorization, activated);
    let mut abort = request.clone();
    abort.directive.command.action = SignerTrustAction::StopStage {
        staged_operation_id: request.directive.command.operation_id,
    };
    assert!(abort.digest().is_err());
    let mut retirement = activation.clone();
    retirement.directive.command.action = SignerTrustAction::CompleteRetirement {
        activation_operation_id: activation.directive.command.operation_id,
    };
    assert!(retirement.digest().is_err());

    let mut snapshot = Vec::new();
    service.backend.snapshot(&mut snapshot).unwrap();
    service
        .backend
        .validate_snapshot(&mut snapshot.as_slice())
        .unwrap();
    let changed = crate::state::snapshot::rewrite_for_test(&snapshot, |frame| {
        if frame["type"] == "Entry" && frame["value"][1]["kind"] == "Maintenance" {
            let mut status: AuthorityMaintenanceStatus =
                serde_json::from_value(frame["value"][1]["record"].clone()).unwrap();
            if status.command.operation_id == activated.command.operation_id {
                let AuthorityMaintenanceAction::AuthorizeControlSigner { directive } =
                    &mut status.command.action
                else {
                    unreachable!()
                };
                let SignerTrustAction::Activate {
                    staged_operation_id,
                    ..
                } = &mut directive.command.action
                else {
                    unreachable!()
                };
                *staged_operation_id = Uuid::new_v4();
                status.command_sha256 = status.command.digest().unwrap();
                frame["value"][1]["record"] = serde_json::to_value(status).unwrap();
            }
        }
    });
    assert!(
        service
            .backend
            .validate_snapshot(&mut changed.as_slice())
            .is_err()
    );
    drop(activation_fence);
    drop(original_fence);
    drop(fresh_fence);
    drop(fence);
    drop(service);
    f.reopen().await;
    let (after_restart, fence) = current_observation(&f, &activation).await;
    assert_eq!(after_restart.authorization, before_restart.authorization);
    assert_eq!(after_restart.registration, before_restart.registration);
    assert_eq!(after_restart.admission, before_restart.admission);
    assert_eq!(after_restart.head, before_restart.head);
    fence.release().await.unwrap();
    assert!(after_restart.head.retirement.is_some());
    drop(fence);
    f.close().await;
}
