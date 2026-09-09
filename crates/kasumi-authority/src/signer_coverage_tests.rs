#[tokio::test]
async fn coverage_dispatch_precedes_permission_and_survives_exact_encrypted_restart() {
    use kasumi_raft::StateMachineBackend;
    use ring::signature::KeyPair;
    let mut fixture = Fixture::new().await;
    let authority = fixture.leader().await;
    let context = fixture.context("operator");
    let physical = fixture.settings.installed_members[&authority.local_node_id]
        .verifier
        .clone();
    for member in fixture.bootstrap.membership.members.values() {
        let command = fixture
            .maintenance_command(AuthorityMaintenanceAction::EnrollSignerVerifier {
                enrollment: SignerVerifierEnrollment {
                    verifier: member.verifier.clone(),
                    endpoint: format!("{}/", member.endpoint),
                    certificate_pins: member.certificate_pins.clone(),
                },
            })
            .await;
        assert_eq!(
            fixture
                .maintenance(AuthorityMaintenanceRequest::Start { command })
                .await
                .unwrap()
                .phase,
            AuthorityMaintenancePhase::Completed
        );
    }
    let key =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let certificate = fixture
        .signing_root
        .certify(2, hex::encode(key.public_key().as_ref()))
        .unwrap();
    let domain = certificate.identity.domain.digest().unwrap();
    let global_stage = fixture
        .maintenance_command(AuthorityMaintenanceAction::StageSignerGeneration {
            certificate: certificate.clone(),
        })
        .await;
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Start {
                command: global_stage.clone()
            })
            .await
            .unwrap()
            .phase,
        AuthorityMaintenancePhase::Completed
    );
    let local_stage = SignerTrustCommand {
        operation_id: Uuid::new_v4(),
        expected_revision: 0,
        not_after_ms: 1_050_000,
        action: SignerTrustAction::Stage {
            certificate: certificate.clone(),
        },
    };
    let stage_permission = commit_directive(&authority, &context, &physical, &domain, &local_stage)
        .await
        .unwrap();
    stage_permission.check().unwrap();
    drop(stage_permission);
    let global = fixture
        .maintenance_command(AuthorityMaintenanceAction::ActivateSignerGeneration {
            stage_operation_id: global_stage.operation_id,
            certificate_sha256: certificate.digest().unwrap(),
        })
        .await;
    let (winner, winner_fence) = authority
        .signing_maintenance(
            context.clone(),
            AuthoritySigningRequest {
                observation_id: Uuid::new_v4(),
                domain_sha256: domain.clone(),
                action: AuthoritySigningAction::Start { command: global },
            },
        )
        .await
        .unwrap();
    winner_fence.release().await.unwrap();
    drop(winner_fence);
    let local = SignerTrustCommand {
        operation_id: Uuid::new_v4(),
        expected_revision: 1,
        not_after_ms: local_stage.not_after_ms,
        action: SignerTrustAction::Activate {
            staged_operation_id: local_stage.operation_id,
            certificate_sha256: certificate.digest().unwrap(),
        },
    };
    let command = SignerCoverageCommand {
        operation_id: Uuid::new_v4(),
        expected_policy_epoch: winner.policy_epoch,
        expected_operational_revision: winner.operational_revision,
        not_after_ms: local.not_after_ms,
        publication: SignerPublicationRequest::Issuer {
            observation_id: Uuid::new_v4(),
            directive: Box::new(
                IssuerSignerDirective::from_current_head(
                    physical,
                    domain,
                    local.clone(),
                    &winner.current,
                )
                .unwrap(),
            ),
        },
    };
    let request = SignerCoverageRequest::Start {
        command: command.clone(),
    };
    let (pending, pending_fence) = authority
        .signer_coverage(context.clone(), request.clone())
        .await
        .unwrap();
    pending_fence.release().await.unwrap();
    drop(pending_fence);
    assert!(pending.acknowledgment.is_none());
    assert!(
        authority
            .backend
            .maintenance_status(local.operation_id)
            .unwrap()
            .is_none(),
        "dispatch cannot imply permission or remote publication"
    );
    let (replayed, replay_fence) = authority
        .signer_coverage(context.clone(), request.clone())
        .await
        .unwrap();
    replay_fence.release().await.unwrap();
    drop(replay_fence);
    assert_eq!(replayed, pending);
    let mut changed = command.clone();
    if let SignerPublicationRequest::Issuer { observation_id, .. } = &mut changed.publication {
        *observation_id = Uuid::new_v4();
    }
    assert_eq!(
        authority
            .signer_coverage(
                context.clone(),
                SignerCoverageRequest::Start { command: changed }
            )
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );
    let mut duplicate_physical = command.clone();
    duplicate_physical.operation_id = Uuid::new_v4();
    duplicate_physical.expected_operational_revision = authority
        .backend
        .operational_configuration()
        .unwrap()
        .revision;
    assert_eq!(
        authority
            .signer_coverage(
                context.clone(),
                SignerCoverageRequest::Start {
                    command: duplicate_physical
                }
            )
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );
    assert!(
        authority
            .signer_coverage(
                fixture.context("intruder"),
                SignerCoverageRequest::Status {
                    operation_id: command.operation_id
                }
            )
            .await
            .is_err()
    );
    let mut before_permission = Vec::new();
    authority.backend.snapshot(&mut before_permission).unwrap();
    authority
        .backend
        .validate_snapshot(&mut before_permission.as_slice())
        .unwrap();
    let wire = SignerCoverageResponse {
        request_sha256: request.digest().unwrap(),
        status: pending.clone(),
    };
    wire.validate_for(&request, &fixture.installation.manifest)
        .unwrap();
    let mut another_manifest = fixture.installation.manifest.clone();
    another_manifest.authority_id = Uuid::new_v4();
    assert!(
        wire.validate_for(&request, &another_manifest).is_err(),
        "even pending wire status must retain its installed domain"
    );
    assert!(
        serde_json::from_value::<SignerCoverageRequest>(serde_json::json!({
            "kind": "acknowledge", "operation_id": command.operation_id, "publication": {}
        }))
        .is_err(),
        "no public DTO can mint a current acknowledgment"
    );
    // An absent transport cannot claim publication. Resume must preserve the
    // original dispatch so a later installed transport can resolve the same effect.
    assert!(
        authority
            .signer_coverage(
                context.clone(),
                SignerCoverageRequest::Resume {
                    operation_id: command.operation_id
                }
            )
            .await
            .is_err()
    );
    assert!(
        authority
            .backend
            .maintenance_status(local.operation_id)
            .unwrap()
            .is_none()
    );
    let transport = Arc::new(UnavailableCoverageTransport {
        authority: Arc::downgrade(&authority),
        observed: std::sync::atomic::AtomicBool::new(false),
    });
    authority
        .install_signer_publication_transport(transport.clone())
        .unwrap();
    assert_eq!(
        authority
            .signer_coverage(
                context.clone(),
                SignerCoverageRequest::Resume {
                    operation_id: command.operation_id
                }
            )
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::UnknownOutcome
    );
    assert!(transport.observed.load(Ordering::SeqCst));
    let permission = authority
        .backend
        .maintenance_status(local.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(permission.phase, AuthorityMaintenancePhase::Completed);
    assert!(permission.progress_revision > pending.dispatch.revision);
    assert!(
        authority
            .backend
            .signer_coverage_status(command.operation_id)
            .unwrap()
            .unwrap()
            .acknowledgment
            .is_none()
    );
    // A structurally valid historical DTO is still not a current observation.
    // In particular its source permission must be the exact retained record,
    // not merely a second valid status with the same action and command hash.
    let original_request = pending
        .dispatch
        .command
        .publication
        .issuer_request()
        .unwrap();
    let mut data = SignerPublicationResponse::Issuer(Box::new(SignerVerifierResponse {
        observation_id: original_request.observation_id,
        request_sha256: original_request.digest().unwrap(),
        domain_sha256: original_request.domain_sha256,
        current: LocalSignerTrustRecord {
            format: 1,
            verifier: pending.dispatch.command.publication.verifier().clone(),
            revision: 2,
            active: certificate.clone(),
            staged: None,
            retirement: Some(SignerRetirement {
                operation_id: local.operation_id,
                retired_generation: 1,
                retired_certificate_sha256: fixture
                    .bootstrap
                    .initial_signer_certificate
                    .digest()
                    .unwrap(),
            }),
        },
        receipt: Some(SignerTrustReceipt {
            command: local.clone(),
            command_sha256: local.digest().unwrap(),
            principal: "operator".into(),
            revision: 2,
            active_generation: 2,
            active_certificate_sha256: certificate.digest().unwrap(),
            retirement_pending: true,
        }),
        loaded_certificate: None,
        authorization: Some(permission.clone()),
    }));
    authority
        .backend
        .check_signer_coverage_publication(&pending.dispatch, &data)
        .unwrap();
    assert!(
        authority
            .backend
            .signer_coverage_status(command.operation_id)
            .unwrap()
            .unwrap()
            .acknowledgment
            .is_none()
    );
    if let SignerPublicationResponse::Issuer(reply) = &mut data {
        reply.authorization.as_mut().unwrap().admitted_principal = "intruder".into();
    }
    data.validate_for(
        &pending.dispatch.command.publication,
        &fixture.installation.manifest,
    )
    .unwrap();
    assert!(
        authority
            .backend
            .check_signer_coverage_publication(&pending.dispatch, &data)
            .is_err()
    );
    let mut after_permission = Vec::new();
    authority.backend.snapshot(&mut after_permission).unwrap();
    authority
        .backend
        .validate_snapshot(&mut after_permission.as_slice())
        .unwrap();
    assert!(
        authority
            .backend
            .validate_snapshot(&mut before_permission.as_slice())
            .is_err(),
        "snapshot cannot erase a durable dispatch phase"
    );
    let marker = format!("signer-coverage-permission/{}", command.operation_id);
    let corrupted = crate::state::snapshot::rewrite_for_test(&after_permission, |value| {
        if value["type"] == "Entry" && value["value"][0] == marker {
            value["value"][1]["record"]["permission_sha256"] = serde_json::json!("f".repeat(64));
        }
    });
    assert!(
        authority
            .backend
            .validate_snapshot(&mut corrupted.as_slice())
            .is_err()
    );
    authority.shutdown().await.unwrap();
    drop(authority);
    fixture.reopen().await;
    let reopened = fixture.leader().await;
    let (status, fence) = reopened
        .signer_coverage(
            fixture.context("operator"),
            SignerCoverageRequest::Status {
                operation_id: command.operation_id,
            },
        )
        .await
        .unwrap();
    fence.release().await.unwrap();
    drop(fence);
    assert_eq!(status, pending);
    assert_eq!(
        reopened
            .backend
            .maintenance_status(local.operation_id)
            .unwrap()
            .unwrap(),
        permission
    );
    fixture.clock.0.store(60_000, Ordering::SeqCst);
    // Read-only recovery retains original deadlines rather than extending a
    // pending local effect when a later request presents a fresh credential.
    let (historical, fence) = reopened
        .signer_coverage(
            fixture.context("operator"),
            SignerCoverageRequest::Status {
                operation_id: command.operation_id,
            },
        )
        .await
        .unwrap();
    fence.release().await.unwrap();
    assert_eq!(historical.dispatch.command.not_after_ms, local.not_after_ms);
    assert!(historical.acknowledgment.is_none());
    drop(fence);
    fixture.close().await;
}

// A failed installed transport may exercise dispatch ordering but cannot
// manufacture the SDK's opaque actual-native acknowledgment owner.
struct UnavailableCoverageTransport {
    authority: std::sync::Weak<IndependentAuthority>,
    observed: std::sync::atomic::AtomicBool,
}
#[async_trait::async_trait]
impl SignerPublicationTransport for UnavailableCoverageTransport {
    async fn observe(
        &self,
        dispatch: &SignerCoverageDispatch,
    ) -> anyhow::Result<kasumi_client::CurrentSignerPublication> {
        let authority = self.authority.upgrade().unwrap();
        let permission = authority
            .backend
            .maintenance_status(dispatch.command.publication.command().operation_id)?
            .unwrap();
        anyhow::ensure!(
            permission.phase == AuthorityMaintenancePhase::Completed
                && permission.progress_revision > dispatch.revision,
            "transport dispatched before its durable original permission"
        );
        self.observed.store(true, Ordering::SeqCst);
        anyhow::bail!("injected publication connection failure")
    }
}
