// The freeze is derived from durable issuer, data, target and Control facts.
async fn signing_transition(
    f: &Fixture,
    action: AuthorityMaintenanceAction,
) -> AuthoritySigningResponse {
    let mut command = f.maintenance_command(action).await;
    command.not_after_ms = 1_050_000;
    if let AuthorityMaintenanceAction::AuthorizeControlSigner { directive } = &command.action {
        command.operation_id = directive.command.operation_id;
        command.not_after_ms = directive.command.not_after_ms;
    }
    let request = AuthoritySigningRequest {
        observation_id: Uuid::new_v4(),
        domain_sha256: f
            .installation
            .manifest
            .signing_domain(0)
            .unwrap()
            .digest()
            .unwrap(),
        action: AuthoritySigningAction::Start { command },
    };
    let context = f.context("operator");
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match f
                .leader()
                .await
                .signing_maintenance(context.clone(), request.clone())
                .await
            {
                Ok((response, fence)) if fence.release().await.is_ok() => return response,
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                    ) => {}
                Err(error) => panic!("unexpected signing transition rejection: {error:?}"),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}
fn distinct_nodes() -> BTreeSet<NodeIdentity> {
    let installation_id = Uuid::new_v4();
    nodes()
        .into_iter()
        .map(|mut node| {
            node.verifier.installation_id = installation_id;
            node
        })
        .collect()
}
#[tokio::test]
async fn signer_roster_covers_control_and_prepared_targets_and_freezes_exact_admissions() {
    use kasumi_raft::StateMachineBackend;
    let control = ControlFixture::new();
    let mut f = control.issuer().await;
    let service = f.leader().await;
    let source = f.enroll(&service).await;
    let mut target = target(source);
    target.nodes = distinct_nodes();
    let preparation = f.command(AuthorityAction::PrepareTarget {
        source_incarnation: source,
        source_epoch: 1,
        target: target.clone(),
    });
    let prepared = f.exact_administrative(preparation.clone()).await;
    assert!(matches!(
        prepared.outcome,
        AuthorityOutcome::TargetPrepared { .. }
    ));
    let mut lifecycle_target = target.clone();
    lifecycle_target.incarnation = Uuid::new_v4();
    lifecycle_target.nodes = distinct_nodes();
    let intent = control.intent(&f, &lifecycle_target, 1_050_000);
    let (_, original) = accepted_on_current_leader(&f, request(&intent)).await;
    let key = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let certificate = f
        .signing_root
        .certify(2, hex::encode(key.public_key().as_ref()))
        .unwrap();
    let stage_action = AuthorityMaintenanceAction::StageSignerGeneration { certificate };
    let omitted = signing_transition(&f, stage_action.clone()).await;
    assert!(matches!(
        omitted.status.unwrap().phase,
        AuthorityMaintenancePhase::Rejected { .. }
    ));
    assert!(omitted.current.staged.is_none());
    let control_nodes = distinct_nodes();
    let mut all_nodes = nodes();
    all_nodes.extend(target.nodes.clone());
    all_nodes.extend(lifecycle_target.nodes.clone());
    all_nodes.extend(control_nodes.clone());
    let mut first_enrollment = None;
    for (index, node) in all_nodes.iter().enumerate() {
        let enrollment = SignerVerifierEnrollment {
            verifier: node.verifier.clone(),
            endpoint: format!("https://verifier-{index}.test/"),
            certificate_pins: BTreeSet::from([format!("{:064x}", 1000 + index)]),
        };
        let response = signing_transition(
            &f,
            AuthorityMaintenanceAction::EnrollSignerVerifier {
                enrollment: enrollment.clone(),
            },
        )
        .await;
        let status = response.status.unwrap();
        assert_eq!(status.phase, AuthorityMaintenancePhase::Completed);
        first_enrollment.get_or_insert((enrollment, status));
    }
    let omitted_control = signing_transition(&f, stage_action.clone()).await;
    assert!(matches!(
        omitted_control.status.unwrap().phase,
        AuthorityMaintenancePhase::Rejected { .. }
    ));
    let admission = ControlVerifierAdmission {
        root: control.root.clone(),
        partition: f.installation.manifest.control_partition(0).unwrap(),
        nodes: control_nodes,
    };
    let mut other_root = admission.clone();
    other_root.root.public_key = "aa".repeat(32);
    assert!(matches!(
        signing_transition(
            &f,
            AuthorityMaintenanceAction::AdmitControlVerifiers {
                admission: other_root
            }
        )
        .await
        .status
        .unwrap()
        .phase,
        AuthorityMaintenancePhase::Rejected { .. }
    ));
    let mut other_partition = admission.clone();
    other_partition.partition.manifest_sha256 = "bb".repeat(32);
    assert!(matches!(
        signing_transition(
            &f,
            AuthorityMaintenanceAction::AdmitControlVerifiers {
                admission: other_partition
            }
        )
        .await
        .status
        .unwrap()
        .phase,
        AuthorityMaintenancePhase::Rejected { .. }
    ));
    assert_eq!(
        signing_transition(
            &f,
            AuthorityMaintenanceAction::AdmitControlVerifiers {
                admission: admission.clone()
            }
        )
        .await
        .status
        .unwrap()
        .phase,
        AuthorityMaintenancePhase::Completed
    );
    let lease_request = LeaseRequest {
        manifest_digest: f.installation.manifest.digest().unwrap(),
        identity: ServingIdentity {
            tenant: "city".into(),
            incarnation: source,
            authority_epoch: 1,
            node: nodes().first().unwrap().clone(),
        },
        boot_id: Uuid::new_v4(),
        attempt_id: Uuid::new_v4(),
        purpose: LeasePurpose::Serving,
    };
    let (_, queued_lease) = f
        .leader()
        .await
        .acquire(node(&f), lease_request.clone())
        .await
        .unwrap();
    queued_lease.release().await.unwrap();
    let frozen = signing_transition(&f, stage_action).await;
    assert_eq!(
        frozen.status.as_ref().unwrap().phase,
        AuthorityMaintenancePhase::Completed
    );
    let roster = &frozen.current.staged.as_ref().unwrap().roster;
    assert_eq!(roster.enrollment_count, 12);
    assert_eq!(roster.control_count, 1);
    let current = f.leader().await;
    current.request_signer().unwrap().check().unwrap();
    assert!(queued_lease.check().is_err());
    assert!(current.acquire(node(&f), lease_request).await.is_err());
    let page_request = |after| AuthoritySigningRequest {
        observation_id: Uuid::new_v4(),
        domain_sha256: f
            .installation
            .manifest
            .signing_domain(0)
            .unwrap()
            .digest()
            .unwrap(),
        action: AuthoritySigningAction::Verifiers {
            expected_operational_revision: frozen.operational_revision,
            after,
            limit: 2,
        },
    };
    let mut after = None;
    let mut paged = BTreeSet::new();
    loop {
        let request = page_request(after);
        let (response, fence) = current
            .signing_maintenance(f.context("operator"), request.clone())
            .await
            .unwrap();
        response
            .validate_for(
                &request,
                &f.installation.manifest.signing_domain(0).unwrap(),
            )
            .unwrap();
        fence.release().await.unwrap();
        let page = response.verifier_page.unwrap();
        for registration in page.registrations {
            assert!(paged.insert(registration.enrollment.verifier));
        }
        after = page.next;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(paged.len(), 12);
    assert!(
        current
            .check_issuance_signer(&current.request_signer().unwrap())
            .is_err()
    );
    // Exact committed identities remain resolvable after the freeze; no new
    // credential or attempted registration may replace their original input.
    let (_, status) = first_enrollment.unwrap();
    let replay = AuthoritySigningRequest {
        observation_id: Uuid::new_v4(),
        domain_sha256: f
            .installation
            .manifest
            .signing_domain(0)
            .unwrap()
            .digest()
            .unwrap(),
        action: AuthoritySigningAction::Start {
            command: status.command.clone(),
        },
    };
    assert_eq!(
        current
            .signing_maintenance(f.context("operator"), replay.clone())
            .await
            .unwrap()
            .0
            .status
            .unwrap(),
        status
    );
    let mut conflict_request = replay;
    let AuthoritySigningAction::Start { command } = &mut conflict_request.action else {
        unreachable!()
    };
    let AuthorityMaintenanceAction::EnrollSignerVerifier { enrollment } = &mut command.action
    else {
        unreachable!()
    };
    enrollment.endpoint = "https://substituted.test/".into();
    assert_eq!(
        current
            .signing_maintenance(f.context("operator"), conflict_request)
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );
    assert!(matches!(
        signing_transition(
            &f,
            AuthorityMaintenanceAction::EnrollSignerVerifier {
                enrollment: SignerVerifierEnrollment {
                    verifier: TrustVerifierIdentity {
                        installation_id: Uuid::new_v4(),
                        node_id: 1
                    },
                    ..first_enrollment_value(&status)
                }
            }
        )
        .await
        .status
        .unwrap()
        .phase,
        AuthorityMaintenancePhase::Rejected { .. }
    ));
    assert!(matches!(
        signing_transition(
            &f,
            AuthorityMaintenanceAction::AdmitControlVerifiers { admission }
        )
        .await
        .status
        .unwrap()
        .phase,
        AuthorityMaintenancePhase::Rejected { .. }
    ));
    assert_eq!(
        current
            .signing_maintenance(f.context("operator"), page_request(None))
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(f.exact_administrative(preparation).await, prepared);
    let rejected = f
        .exact_administrative(f.command(AuthorityAction::Enroll {
            incarnation: Uuid::new_v4(),
            nodes: distinct_nodes(),
        }))
        .await;
    assert!(matches!(
        rejected.outcome,
        AuthorityOutcome::Rejected {
            code: ErrorCode::Conflict,
            ..
        }
    ));
    let another_intent = control.intent(&f, &lifecycle_target, 1_050_000);
    assert_eq!(
        current
            .execute_lifecycle(f.context("operator"), request(&another_intent))
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        current
            .execute_lifecycle(f.context("operator"), request(&intent))
            .await
            .unwrap()
            .0
            .receipt
            .request_sha256,
        original.receipt.request_sha256
    );
    let mut snapshot = Vec::new();
    current.backend.snapshot(&mut snapshot).unwrap();
    current
        .backend
        .validate_snapshot(&mut snapshot.as_slice())
        .unwrap();
    let changed = crate::state::snapshot::rewrite_for_test(&snapshot, |frame| {
        if frame["type"] == "Meta" {
            frame["value"]["signing"]["staged"]["roster"]["sha256"] =
                serde_json::json!("00".repeat(32));
        }
    });
    assert!(current.backend.prepare_restore(&mut changed.as_slice()).is_err());
    let changed = crate::state::snapshot::rewrite_for_test(&snapshot, |frame| {
        if frame["type"] == "Entry" && frame["value"][1]["kind"] == "Verifier" {
            frame["value"][1]["record"]["enrollment"]["endpoint"] =
                serde_json::json!("https://alias.test/");
        }
    });
    assert!(current.backend.prepare_restore(&mut changed.as_slice()).is_err());
    drop(queued_lease);
    drop(current);
    drop(service);
    f.reopen().await;
    let restarted = f.leader().await;
    assert_eq!(restarted.backend.signing_head().unwrap(), frozen.current);
    assert!(
        restarted
            .check_issuance_signer(&restarted.request_signer().unwrap())
            .is_err()
    );
    f.close().await;
}
fn first_enrollment_value(status: &AuthorityMaintenanceStatus) -> SignerVerifierEnrollment {
    match &status.command.action {
        AuthorityMaintenanceAction::EnrollSignerVerifier { enrollment } => enrollment.clone(),
        _ => unreachable!(),
    }
}
