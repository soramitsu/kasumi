#[tokio::test]
async fn signer_directive_is_ordered_exact_finite_and_preserved_in_encrypted_snapshots() {
    use kasumi_raft::StateMachineBackend;
    let f = Fixture::new().await;
    let service = f.leader().await;
    let verifier = f.settings.installed_members[&service.local_node_id].verifier.clone();
    let domain = f.installation.manifest.signing_domain(0).unwrap().digest().unwrap();
    let command = SignerTrustCommand {
        operation_id: Uuid::new_v4(), expected_revision: 0, not_after_ms: 1_050_000,
        action: SignerTrustAction::StopStage { staged_operation_id: Uuid::new_v4() },
    };
    let context = f.context("operator");
    let accepted = service.commit_signer_directive(&context, &verifier, &domain, &command).await.unwrap();
    assert_eq!(accepted.status().phase, AuthorityMaintenancePhase::Completed);
    assert!(matches!(&accepted.status().command.action,
        AuthorityMaintenanceAction::AuthorizeSignerTrust { command: actual, .. } if **actual == command));
    // This is permission for dispatch, not an observation of a local stop.
    service.request_signer().unwrap().check().unwrap();
    assert_eq!(service.commit_signer_directive(&context, &verifier, &domain, &command).await.unwrap().status(), accepted.status());
    let mut changed = command.clone();
    changed.not_after_ms -= 1;
    assert!(service.commit_signer_directive(&context, &verifier, &domain, &changed).await.is_err());
    assert!(service.signer_directive(&f.context("intruder"), &verifier, &domain, command.operation_id).await.is_err());
    // General authority maintenance may retain a structurally valid rejection;
    // its invalid requested domain must not make valid snapshots unrecoverable.
    let mut invalid = command.clone();
    invalid.operation_id = Uuid::new_v4();
    let current = service.backend.operational_configuration().unwrap();
    let invalid_command = AuthorityMaintenanceCommand {
        operation_id: invalid.operation_id, expected_policy_epoch: current.policy_epoch,
        expected_operational_revision: current.revision, not_after_ms: invalid.not_after_ms,
        action: AuthorityMaintenanceAction::AuthorizeSignerTrust { verifier: verifier.clone(), domain_sha256: "00".repeat(32), command: Box::new(invalid) },
    };
    let rejected = f.maintenance(AuthorityMaintenanceRequest::Start { command: invalid_command }).await.unwrap();
    assert!(matches!(rejected.phase, AuthorityMaintenancePhase::Rejected { .. }));
    let current = f.leader().await;
    let mut snapshot = Vec::new();
    current.backend.snapshot(&mut snapshot).unwrap();
    current.backend.validate_snapshot(&mut snapshot.as_slice()).unwrap();
    let key = format!("maintenance/{}", command.operation_id);
    let corrupted = crate::state::snapshot::rewrite_for_test(&snapshot, |value| {
        if value["type"] == "Entry" && value["value"][0] == key {
            let record = &mut value["value"][1]["record"];
            record["command"]["action"]["domain_sha256"] = serde_json::json!("11".repeat(32));
            let command: AuthorityMaintenanceCommand = serde_json::from_value(record["command"].clone()).unwrap();
            record["command_sha256"] = serde_json::json!(command.digest().unwrap());
        }
    });
    assert!(current.backend.restore(&mut corrupted.as_slice()).is_err());
    let substituted = crate::state::snapshot::rewrite_for_test(&snapshot, |value| {
        if value["type"] == "Entry" && value["value"][0] == key {
            let record = &mut value["value"][1]["record"];
            record["command"]["action"]["verifier"]["installation_id"] = serde_json::json!(Uuid::new_v4());
            let command: AuthorityMaintenanceCommand = serde_json::from_value(record["command"].clone()).unwrap();
            record["command_sha256"] = serde_json::json!(command.digest().unwrap());
        }
    });
    assert!(current.backend.restore(&mut substituted.as_slice()).is_err());

    assert_eq!(current.signer_directive(&context, &verifier, &domain, command.operation_id).await.unwrap().unwrap(), *accepted.status());
    // A fresh identity must not first commit after its immutable admission bound.
    f.clock.0.store(60_000, Ordering::SeqCst);
    let mut expired = command.clone();
    expired.operation_id = Uuid::new_v4();
    let current = f.leader().await;
    let current_verifier = f.settings.installed_members[&current.local_node_id].verifier.clone();
    assert!(current.commit_signer_directive(&context, &current_verifier, &domain, &expired).await.is_err());
    assert!(current.backend.maintenance_status(expired.operation_id).unwrap().is_none());
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
    assert!(service.backend.restore(&mut rollback.as_slice()).is_err());
    let retired = crate::state::snapshot::rewrite_for_test(&snapshot, |value| {
        if value["type"] == "Meta" { value["value"]["signing"]["retirement"] = serde_json::Value::Null; }
    });
    assert!(service.backend.restore(&mut retired.as_slice()).is_err());
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
    let (historical, _) = service.signing_maintenance(fixture.context("operator"), request(AuthoritySigningAction::Receipt { operation_id: stage.operation_id })).await.unwrap();
    assert_eq!(historical.status.unwrap().command, stage);
    assert!(historical.current.retirement.is_some());
    fixture.close().await;
}
