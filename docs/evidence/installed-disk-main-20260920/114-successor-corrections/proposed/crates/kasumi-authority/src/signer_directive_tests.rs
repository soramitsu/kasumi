#[tokio::test]
async fn signer_directive_is_ordered_exact_finite_and_preserved_in_encrypted_snapshots() {
    use kasumi_raft::StateMachineBackend;
    let mut f = Fixture::new().await;
    let service = f.leader().await;
    let verifier = f.settings.installed_members[&service.local_node_id].verifier.clone();
    let domain = f.installation.manifest.signing_domain(0).unwrap().digest().unwrap();
    use ring::signature::KeyPair;
    let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let certificate = f.signing_root.certify(2, hex::encode(key.public_key().as_ref())).unwrap();
    let command = SignerTrustCommand {
        operation_id: Uuid::new_v4(), expected_revision: 0, not_after_ms: 1_050_000,
        action: SignerTrustAction::Stage { certificate: certificate.clone() },
    };
    let context = f.context("operator");
    assert!(commit_directive(&service, &context, &verifier, &domain, &command).await.is_err());
    for member in f.bootstrap.membership.members.values() {
        let enrollment = f.maintenance_command(AuthorityMaintenanceAction::EnrollSignerVerifier { enrollment: SignerVerifierEnrollment {
            verifier: member.verifier.clone(), endpoint: format!("{}/", member.endpoint), certificate_pins: member.certificate_pins.clone(),
        }}).await;
        assert_eq!(f.maintenance(AuthorityMaintenanceRequest::Start { command: enrollment }).await.unwrap().phase, AuthorityMaintenancePhase::Completed);
    }
    let global = f.maintenance_command(AuthorityMaintenanceAction::StageSignerGeneration { certificate }).await;
    assert_eq!(f.maintenance(AuthorityMaintenanceRequest::Start { command: global.clone() }).await.unwrap().phase, AuthorityMaintenancePhase::Completed);
    let mut stop = command.clone();
    stop.operation_id = Uuid::new_v4();
    stop.action = SignerTrustAction::StopStage { staged_operation_id: command.operation_id };
    assert!(commit_directive(&service, &context, &verifier, &domain, &stop).await.is_err());
    assert!(service.backend.maintenance_status(stop.operation_id).unwrap().is_none());
    let accepted = commit_directive(&service, &context, &verifier, &domain, &command).await.unwrap();
    accepted.check().unwrap();
    assert_eq!(accepted.status().phase, AuthorityMaintenancePhase::Completed);
    assert!(matches!(&accepted.status().command.action,
        AuthorityMaintenanceAction::AuthorizeSignerTrust { directive } if directive.command == command && directive.global_stage_operation_id == global.operation_id));
    let mut unbound = serde_json::to_value(&accepted.status().command.action).unwrap();
    let directive = unbound.as_object_mut().unwrap().remove("directive").unwrap();
    for name in ["verifier", "domain_sha256", "command"] {
        unbound[name] = directive[name].clone();
    }
    assert!(serde_json::from_value::<AuthorityMaintenanceAction>(unbound).is_err());
    let mut missing_origin = directive;
    missing_origin.as_object_mut().unwrap().remove("global_activation_operation_id");
    assert!(serde_json::from_value::<IssuerSignerDirective>(missing_origin).is_err());
    // This is permission for dispatch, not an observation of local publication.
    service.request_signer().unwrap().check().unwrap();
    assert_eq!(commit_directive(&service, &context, &verifier, &domain, &command).await.unwrap().status(), accepted.status());
    let mut changed = command.clone();
    changed.not_after_ms -= 1;
    assert!(commit_directive(&service, &context, &verifier, &domain, &changed).await.is_err());
    assert!(read_directive(&service, &f.context("intruder"), &verifier, &domain, command.operation_id).await.is_err());
    // General authority maintenance may retain a structurally valid rejection;
    // its uninstalled physical verifier must not make valid snapshots unrecoverable.
    let mut invalid = command.clone();
    invalid.operation_id = Uuid::new_v4();
    let mut invalid_directive = IssuerSignerDirective::from_current_head(verifier.clone(), domain.clone(), invalid.clone(), &service.backend.signing_head().unwrap()).unwrap();
    invalid_directive.verifier.installation_id = Uuid::new_v4();
    let current = service.backend.operational_configuration().unwrap();
    let invalid_command = AuthorityMaintenanceCommand {
        operation_id: invalid.operation_id, expected_policy_epoch: current.policy_epoch,
        expected_operational_revision: current.revision, not_after_ms: invalid.not_after_ms,
        action: AuthorityMaintenanceAction::AuthorizeSignerTrust { directive: Box::new(invalid_directive) },
    };
    let rejected = f.maintenance(AuthorityMaintenanceRequest::Start { command: invalid_command }).await.unwrap();
    assert!(matches!(rejected.phase, AuthorityMaintenancePhase::Rejected { .. }));
    let activation = SignerTrustCommand {
        operation_id: Uuid::new_v4(),
        expected_revision: 1,
        not_after_ms: command.not_after_ms,
        action: SignerTrustAction::Activate {
            staged_operation_id: command.operation_id,
            certificate_sha256: match &command.action {
                SignerTrustAction::Stage { certificate } => certificate.digest().unwrap(),
                _ => unreachable!(),
            },
        },
    };
    assert!(commit_directive(&service, &context, &verifier, &domain, &activation).await.is_err());
    assert!(service.backend.maintenance_status(activation.operation_id).unwrap().is_none());
    let winner = f.maintenance_command(AuthorityMaintenanceAction::ActivateSignerGeneration {
        stage_operation_id: global.operation_id,
        certificate_sha256: match &activation.action {
            SignerTrustAction::Activate { certificate_sha256, .. } => certificate_sha256.clone(),
            _ => unreachable!(),
        },
    }).await;
    let (won, fence) = service.signing_maintenance(context.clone(), AuthoritySigningRequest {
        observation_id: Uuid::new_v4(), domain_sha256: domain.clone(),
        action: AuthoritySigningAction::Start { command: winner.clone() },
    }).await.unwrap();
    fence.release().await.unwrap();
    assert_eq!(won.status.unwrap().phase, AuthorityMaintenancePhase::Completed);
    accepted.check().unwrap(); // An original stage may finish forward after the global winner.
    assert!(commit_directive(&service, &context, &verifier, &domain, &stop).await.is_err());
    let activated = commit_directive(&service, &context, &verifier, &domain, &activation).await.unwrap();
    activated.check().unwrap();
    assert!(matches!(&activated.status().command.action,
        AuthorityMaintenanceAction::AuthorizeSignerTrust { directive }
        if directive.global_activation_operation_id == Some(winner.operation_id)));
    let mut substituted_activation = activation.clone();
    substituted_activation.operation_id = Uuid::new_v4();
    if let SignerTrustAction::Activate { staged_operation_id, .. } = &mut substituted_activation.action {
        *staged_operation_id = Uuid::new_v4();
    }
    assert!(commit_directive(&service, &context, &verifier, &domain, &substituted_activation).await.is_err());
    let current = f.leader().await;
    let mut snapshot = Vec::new();
    current.backend.snapshot(&mut snapshot).unwrap();
    current.backend.validate_snapshot(&mut snapshot.as_slice()).unwrap();
    let key = format!("maintenance/{}", command.operation_id);
    let corrupted = crate::state::snapshot::rewrite_for_test(&snapshot, |value| {
        if value["type"] == "Entry" && value["value"][0] == key {
            let record = &mut value["value"][1]["record"];
            record["command"]["action"]["directive"]["global_stage_operation_id"] = serde_json::json!(Uuid::new_v4());
            let command: AuthorityMaintenanceCommand = serde_json::from_value(record["command"].clone()).unwrap();
            record["command_sha256"] = serde_json::json!(command.digest().unwrap());
        }
    });
    assert!(current.backend.prepare_restore(&crate::state::restore_test_context(&corrupted), &mut corrupted.as_slice()).is_err());
    let substituted = crate::state::snapshot::rewrite_for_test(&snapshot, |value| {
        if value["type"] == "Entry" && value["value"][0] == key {
            let record = &mut value["value"][1]["record"];
            record["command"]["action"]["directive"]["verifier"]["installation_id"] = serde_json::json!(Uuid::new_v4());
            let command: AuthorityMaintenanceCommand = serde_json::from_value(record["command"].clone()).unwrap();
            record["command_sha256"] = serde_json::json!(command.digest().unwrap());
        }
    });
    assert!(current.backend.prepare_restore(&crate::state::restore_test_context(&substituted), &mut substituted.as_slice()).is_err());

    assert_eq!(read_directive(&current, &context, &verifier, &domain, command.operation_id).await.unwrap().unwrap(), *accepted.status());
    let activation_key = format!("maintenance/{}", activation.operation_id);
    let wrong_winner = crate::state::snapshot::rewrite_for_test(&snapshot, |value| {
        if value["type"] == "Entry" && value["value"][0] == activation_key {
            let record = &mut value["value"][1]["record"];
            record["command"]["action"]["directive"]["global_activation_operation_id"] = serde_json::json!(global.operation_id);
            let command: AuthorityMaintenanceCommand = serde_json::from_value(record["command"].clone()).unwrap();
            record["command_sha256"] = serde_json::json!(command.digest().unwrap());
        }
    });
    assert!(current.backend.prepare_restore(&crate::state::restore_test_context(&wrong_winner), &mut wrong_winner.as_slice()).is_err());
    let exact_permission = activated.status().clone();
    let mut closing = Box::pin(service.shutdown());
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(closing.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    }).await;
    assert!(accepted.check().is_err(), "a closed source owner cannot authorize publication during reopen");
    // Physical ownership cannot reopen while any old response still retains its
    // database handle. Sealing the guard precedes the complete ownership drain.
    drop(accepted);
    drop(activated);
    drop(fence);
    tokio::time::timeout(Duration::from_secs(10), closing).await.unwrap().unwrap();
    drop(current);
    drop(service);
    f.reopen().await;
    let reopened = f.leader().await;
    assert_eq!(read_directive(&reopened, &context, &verifier, &domain, activation.operation_id).await.unwrap().unwrap(), exact_permission);
    assert_eq!(reopened.backend.signing_head().unwrap().retirement.unwrap().activation_operation_id, winner.operation_id);
    // A fresh identity must not first commit after its immutable admission bound.
    f.clock.0.store(60_000, Ordering::SeqCst);
    let mut expired = command.clone();
    expired.operation_id = Uuid::new_v4();
    let current = f.leader().await;
    let current_verifier = f.settings.installed_members[&current.local_node_id].verifier.clone();
    assert!(commit_directive(&current, &context, &current_verifier, &domain, &expired).await.is_err());
    assert!(current.backend.maintenance_status(expired.operation_id).unwrap().is_none());
    f.close().await;
}

#[tokio::test]
async fn issuer_permission_retains_original_policy_while_current_admin_can_read_its_receipt() {
    use ring::signature::KeyPair;
    let f = Fixture::new().await;
    let service = f.leader().await;
    for member in f.bootstrap.membership.members.values() {
        let command = f.maintenance_command(AuthorityMaintenanceAction::EnrollSignerVerifier {
            enrollment: SignerVerifierEnrollment {
                verifier: member.verifier.clone(),
                endpoint: format!("{}/", member.endpoint),
                certificate_pins: member.certificate_pins.clone(),
            },
        }).await;
        assert_eq!(f.maintenance(AuthorityMaintenanceRequest::Start { command }).await.unwrap().phase,
            AuthorityMaintenancePhase::Completed);
    }
    let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let certificate = f.signing_root.certify(2, hex::encode(key.public_key().as_ref())).unwrap();
    let global = f.maintenance_command(AuthorityMaintenanceAction::StageSignerGeneration {
        certificate: certificate.clone(),
    }).await;
    assert_eq!(f.maintenance(AuthorityMaintenanceRequest::Start { command: global }).await.unwrap().phase,
        AuthorityMaintenancePhase::Completed);
    let verifier = f.settings.installed_members[&service.local_node_id].verifier.clone();
    let domain = certificate.identity.domain.digest().unwrap();
    let context = f.context("operator");
    let command = SignerTrustCommand {
        operation_id: Uuid::new_v4(), expected_revision: 0, not_after_ms: 1_050_000,
        action: SignerTrustAction::Stage { certificate },
    };
    let permission = commit_directive(&service, &context, &verifier, &domain, &command).await.unwrap();
    permission.check().unwrap();
    let policy = f.command(AuthorityAction::ReplaceAdministrators {
        administrators: BTreeSet::from(["operator".into(), "successor".into()]),
    });
    f.exact_administrative(policy).await;
    assert!(permission.check().is_err(), "a retained old-policy permission cannot authorize first publication");
    let current = f.leader().await;
    let successor = f.context("successor");
    assert_eq!(read_directive(&current, &successor, &verifier, &domain, command.operation_id).await.unwrap().unwrap(),
        *permission.status());
    // Renewing authorization preserves the original operation and its policy;
    // it cannot convert historical dispatch permission into a new grant.
    let renewed = commit_directive(&service, &successor, &verifier, &domain, &command).await.unwrap();
    assert_eq!(renewed.status(), permission.status());
    assert!(renewed.check().is_err());
    drop(permission);
    drop(renewed);
    f.close().await;
}

#[tokio::test]
async fn signer_replacement_requires_current_authorization_and_exact_live_owner() {
    let fixture = Fixture::new().await;
    let authority = fixture.leader().await;
    let selected = authority.request_signer().unwrap();
    let authorization = authority.authorize_signer_maintenance(fixture.context("operator")).await.unwrap();
    let deadline = authority.clock.observe().unwrap().until(1_050_000).unwrap();
    let physical = selected.verifier_identity().unwrap();
    let copied = fixture.signing.for_verifier(physical).unwrap();
    assert_eq!(selected.certificate(), copied.signer.certificate());
    assert!(authority.replace_operational_signer(authorization.clone(), copied.signer, deadline.clone()).await.is_err());
    assert!(Arc::ptr_eq(&selected, &authority.request_signer().unwrap()));
    authority.replace_operational_signer(authorization.clone(), selected.clone(), deadline.clone()).await.unwrap();
    // The command admission can expire while its original administrator is
    // still live. Reusing that credential cannot extend the publication window.
    let short = authority.clock.observe().unwrap().until(1_000_001).unwrap();
    fixture.clock.0.store(2, Ordering::SeqCst);
    authorization.check().unwrap();
    assert!(authority.replace_operational_signer(authorization.clone(), selected.clone(), short).await.is_err());
    // A new invocation cannot make an expired administrative fence current.
    fixture.clock.0.store(1_000_000, Ordering::SeqCst);
    assert!(authority.replace_operational_signer(authorization, selected.clone(), deadline).await.is_err());
    assert!(Arc::ptr_eq(&selected, &authority.request_signer().unwrap()));
    fixture.close().await;
}

#[tokio::test]
async fn replicated_signer_head_fences_unchanged_local_keys_and_rejects_snapshot_regression() {
    use kasumi_raft::StateMachineBackend;
    let mut fixture = Fixture::new().await;
    let service = fixture.leader().await;
    let context = fixture.context("operator");
    let domain = fixture.installation.manifest.signing_domain(0).unwrap();
    let request = |action| AuthoritySigningRequest {
        observation_id: Uuid::new_v4(), domain_sha256: domain.digest().unwrap(), action,
    };
    for member in fixture.bootstrap.membership.members.values() {
        let command = fixture.maintenance_command(AuthorityMaintenanceAction::EnrollSignerVerifier {enrollment: SignerVerifierEnrollment {
            verifier: member.verifier.clone(), endpoint: format!("{}/", member.endpoint), certificate_pins: member.certificate_pins.clone(),
        }}).await;
        assert_eq!(fixture.maintenance(AuthorityMaintenanceRequest::Start {command}).await.unwrap().phase, AuthorityMaintenancePhase::Completed);
    }
    let (_, retained) = service.maintenance(context.clone(), AuthorityMaintenanceRequest::Configuration).await.unwrap();
    retained.release().await.unwrap();
    let (initial, _) = service.signing_maintenance(context.clone(), request(AuthoritySigningAction::Observe)).await.unwrap();
    let next_key = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let next_key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(next_key.as_ref()).unwrap();
    use ring::signature::KeyPair;
    let next = fixture.signing_root.certify(2, hex::encode(next_key_pair.public_key().as_ref())).unwrap();
    let stage = AuthorityMaintenanceCommand { operation_id: Uuid::new_v4(), expected_policy_epoch: initial.policy_epoch,
        expected_operational_revision: initial.operational_revision, not_after_ms: 1_050_000,
        action: AuthorityMaintenanceAction::StageSignerGeneration { certificate: next.clone() } };
    let stage_request = request(AuthoritySigningAction::Start { command: stage.clone() });
    let (staged, staged_fence) = service.signing_maintenance(context.clone(), stage_request.clone()).await.unwrap();
    assert_eq!(staged.status.as_ref().unwrap().phase, AuthorityMaintenancePhase::Completed);
    assert_eq!(staged.current.active, initial.current.active);
    retained.check().unwrap();
    assert_eq!(service.signing_maintenance(context.clone(), stage_request).await.unwrap().0, staged);
    let activate = AuthorityMaintenanceCommand { operation_id: Uuid::new_v4(), expected_policy_epoch: staged.policy_epoch,
        expected_operational_revision: staged.operational_revision, not_after_ms: stage.not_after_ms,
        action: AuthorityMaintenanceAction::ActivateSignerGeneration { stage_operation_id: stage.operation_id, certificate_sha256: next.digest().unwrap() } };
    let activation_request = request(AuthoritySigningAction::Start { command: activate.clone() });
    let (activated, fresh_fence) = service.signing_maintenance(context.clone(), activation_request.clone()).await.unwrap();
    assert_eq!(activated.current.active, next);
    assert!(activated.current.retirement.is_some());
    // Local trust still accepts the original key; consensus alone seals it.
    service.request_signer().unwrap().check().unwrap();
    assert!(service.check_active_signer(&service.request_signer().unwrap()).is_err());
    assert!(retained.check().is_err());
    assert!(retained.release().await.is_err());
    assert!(staged_fence.check().is_err());
    fresh_fence.release().await.unwrap();
    assert_eq!(service.signing_maintenance(context.clone(), activation_request).await.unwrap().0, activated);
    let mut snapshot = Vec::new();
    service.backend.snapshot(&mut snapshot).unwrap();
    service.backend.validate_snapshot(&mut snapshot.as_slice()).unwrap();
    let rollback = crate::state::snapshot::rewrite_for_test(&snapshot, |value| {
        if value["type"] == "Meta" { value["value"]["signing"] = serde_json::to_value(&initial.current).unwrap(); }
    });
    assert!(service.backend.prepare_restore(&crate::state::restore_test_context(&rollback), &mut rollback.as_slice()).is_err());
    let retired = crate::state::snapshot::rewrite_for_test(&snapshot, |value| {
        if value["type"] == "Meta" { value["value"]["signing"]["retirement"] = serde_json::Value::Null; }
    });
    assert!(service.backend.prepare_restore(&crate::state::restore_test_context(&retired), &mut retired.as_slice()).is_err());
    let mut legacy_head = serde_json::to_value(&activated.current).unwrap();
    legacy_head.as_object_mut().unwrap().remove("initial");
    assert!(serde_json::from_value::<AuthoritySigningHead>(legacy_head).is_err());
    assert_eq!(service.backend.signing_head().unwrap(), activated.current);
    drop(retained);
    drop(staged_fence);
    drop(fresh_fence);
    drop(service);
    fixture.reopen().await;
    let service = fixture.leader().await;
    assert_eq!(service.backend.signing_head().unwrap(), activated.current);
    service.request_signer().unwrap().check().unwrap();
    assert!(service.check_active_signer(&service.request_signer().unwrap()).is_err());
    // An expired first effect cannot use a renewed invocation to advance state.
    fixture.clock.0.store(50_000, Ordering::SeqCst);
    let mut expired = activate;
    expired.operation_id = Uuid::new_v4();
    assert!(service.signing_maintenance(fixture.context("operator"), request(AuthoritySigningAction::Start { command: expired })).await.is_err());
    // The failed new effect can coincide with an election. Read the exact old
    // receipt through the current quorum with one original read invocation.
    let historical_context = fixture.context("operator");
    let service = fixture.leader().await;
    let (historical, _) = service.signing_maintenance(historical_context, request(AuthoritySigningAction::Receipt { operation_id: stage.operation_id })).await.unwrap();
    assert_eq!(historical.status.unwrap().command, stage);
    assert!(historical.current.retirement.is_some());
    fixture.close().await;
}

#[tokio::test]
async fn frozen_signer_roster_cannot_be_bypassed_by_source_unavailable_activation() {
    use kasumi_raft::StateMachineBackend;
    let f = Fixture::new().await;
    let service = f.leader().await;
    let source = f.enroll(&service).await;
    for member in f.bootstrap.membership.members.values() {
        let command = f.maintenance_command(AuthorityMaintenanceAction::EnrollSignerVerifier {enrollment: SignerVerifierEnrollment {
            verifier: member.verifier.clone(), endpoint: format!("{}/", member.endpoint), certificate_pins: member.certificate_pins.clone(),
        }}).await;
        assert_eq!(f.maintenance(AuthorityMaintenanceRequest::Start {command}).await.unwrap().phase, AuthorityMaintenancePhase::Completed);
    }
    use ring::signature::KeyPair;
    let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let certificate = f.signing_root.certify(2, hex::encode(key.public_key().as_ref())).unwrap();
    let stage = f.maintenance_command(AuthorityMaintenanceAction::StageSignerGeneration {certificate}).await;
    assert_eq!(f.maintenance(AuthorityMaintenanceRequest::Start {command: stage}).await.unwrap().phase, AuthorityMaintenancePhase::Completed);
    let fenced = f.exact_administrative(f.command(AuthorityAction::Fence {incarnation: source, authority_epoch: 1})).await;
    let mut unknown = target(source);
    unknown.nodes = nodes().into_iter().map(|mut node| {node.verifier.installation_id = Uuid::new_v4(); node}).collect();
    let activation = f.command(AuthorityAction::Activate {fence_id: fenced.command.command_id, fence_digest: fenced.digest().unwrap(), target: unknown});
    assert_eq!(service.execute(f.context("operator"), activation.clone()).await.err().unwrap().code, ErrorCode::Unavailable);
    f.clock.0.store(1000, Ordering::SeqCst);
    let rejected = f.exact_administrative(activation.clone()).await;
    assert!(matches!(rejected.outcome, AuthorityOutcome::Rejected {code: ErrorCode::Conflict, ..}));
    assert_eq!(f.exact_administrative(activation).await, rejected);
    // Forward recovery onto an already covered physical receiver is still
    // possible. It cannot acquire a new old-generation lease during the stage.
    let known = f.command(AuthorityAction::Activate {fence_id: fenced.command.command_id, fence_digest: fenced.digest().unwrap(), target: target(source)});
    assert!(matches!(f.exact_administrative(known).await.outcome, AuthorityOutcome::Activated { .. }));
    let mut snapshot = Vec::new(); service.backend.snapshot(&mut snapshot).unwrap();
    service.backend.validate_snapshot(&mut snapshot.as_slice()).unwrap();
    f.close().await;
}
