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
    let physical = selected.verifier_identity().unwrap();
    let copied = fixture.signing.for_verifier(physical).unwrap();
    assert_eq!(selected.certificate(), copied.signer.certificate());
    assert!(authority.replace_operational_signer(authorization.clone(), copied.signer).await.is_err());
    assert!(Arc::ptr_eq(&selected, &authority.request_signer().unwrap()));
    authority.replace_operational_signer(authorization.clone(), selected.clone()).await.unwrap();
    // A new invocation cannot make an expired administrative fence current.
    fixture.clock.0.store(1_000_000, Ordering::SeqCst);
    assert!(authority.replace_operational_signer(authorization, selected.clone()).await.is_err());
    assert!(Arc::ptr_eq(&selected, &authority.request_signer().unwrap()));
    fixture.close().await;
}
