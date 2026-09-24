//! Real mTLS/native coordinator acceptance against separate replicated Control
//! and issuer groups. The target endpoint is deliberately unavailable: a failed
//! target dispatch must retain its exact prepared entry without a fake outcome.
use super::*;
use kasumi_types::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use uuid::Uuid;

pub(super) struct Fixture<'a> {
    pub directory: &'a std::path::Path,
    pub control: Arc<kasumi_engine::Database>,
    pub signer: Arc<kasumi_engine::LifecycleSigner>,
    pub auth: Arc<Authenticator>,
    pub audit: Arc<kasumi_engine::SecurityAudit>,
    pub issuer: Arc<kasumi_authority::IndependentAuthority>,
    pub trust: kasumi_serving::AuthorityTrust,
    pub installation: LifecycleInstallation,
    pub template: CommitLifecycleIntent,
    pub control_admin: &'a str,
    pub wrong_resource: &'a str,
    pub readonly: &'a str,
    pub issuer_admin: &'a str,
}
pub(super) async fn exercise(f: Fixture<'_>) {
    use crate::{
        recovery_runtime::*,
        runtime::{AdminClientConfig, TlsFiles},
        serving_runtime::{AuthorityEndpoint, ServingAuthorityConfig},
    };
    use kasumi_store::private_files;
    use rcgen::*;
    let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key = KeyPair::generate().unwrap();
    let ca = parameters.self_signed(&key).unwrap();
    let issuer = Issuer::new(parameters, key);
    let issue = |name: &str| {
        let mut parameters = CertificateParams::new(vec![name.into()]).unwrap();
        parameters.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate().unwrap();
        let certificate = parameters.signed_by(&key, &issuer).unwrap();
        (certificate.pem(), key.serialize_pem())
    };
    let (server_cert, server_key) = issue("localhost");
    let server =
        kasumi_transport::TlsIdentity::from_pem(server_cert.as_bytes(), server_key.as_bytes())
            .unwrap();
    let (client_cert, client_key) = issue("coordinator");
    let client =
        kasumi_transport::TlsIdentity::from_pem(client_cert.as_bytes(), client_key.as_bytes())
            .unwrap();
    let dir = f.directory.join("native-recovery");
    private_files::create_directory(&dir).unwrap();
    for (name, bytes) in [
        ("client.pem", client_cert.as_bytes()),
        ("client-key.pem", client_key.as_bytes()),
        ("ca.pem", ca.pem().as_bytes()),
        ("issuer.jwt", f.issuer_admin.as_bytes()),
        ("control.jwt", f.control_admin.as_bytes()),
    ] {
        private_files::publish(&dir.join(name), bytes).unwrap();
    }
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://localhost:{}", socket.local_addr().unwrap().port());
    let pin = server.certificate_pin();
    let tls = kasumi_transport::server_config(
        &server,
        kasumi_transport::ClientAuthentication::Required {
            trusted_ca_pem: ca.pem().as_bytes(),
        },
    )
    .unwrap();
    let configured = ServingAuthorityConfig {
        manifest: f.trust.manifest().clone(),
        endpoints: BTreeMap::from([(
            0,
            BTreeMap::from([(
                1,
                AuthorityEndpoint {
                    endpoint: endpoint.clone(),
                    certificate_pins: BTreeSet::from([hex::encode(pin)]),
                },
            )]),
        )]),
        tls: TlsFiles {
            certificate: dir.join("client.pem"),
            private_key: dir.join("client-key.pem"),
        },
        server_ca: dir.join("ca.pem"),
        bearer_files: BTreeMap::from([(0, dir.join("issuer.jwt").display().to_string())]),
        principal: "operator".into(),
    };
    let mut request = RecoveryStart {
        operation_id: Uuid::new_v4(),
        tenant: "recovery-city".into(),
        source_incarnation: Uuid::new_v4(),
        source_authority_epoch: 1,
        target_incarnation: Uuid::new_v4(),
        checkpoint: f.template.checkpoint.clone(),
        source_purpose_sha256: "86".repeat(32),
        source_mode: RecoverySourceMode::SourceUnavailable,
        installation_sha256: kasumi_serving::digest(&f.installation).unwrap(),
        expected_policy_epoch: f.control.engine().generation().unwrap().state.policy_epoch,
        authority_policy_epoch: 1,
        authority_partition: f.template.authority_partition.clone(),
        dispatch_configuration_sha256: "88".repeat(32),
        target_nodes: f.template.target_nodes.clone(),
        materialization: TargetMaterializationInput {
            destination_alias: "backup".into(),
            backup_id: f.template.checkpoint.backup_id,
            source_purpose_sha256: "86".repeat(32),
            target_incarnation: Uuid::nil(),
            voters: (1..=3)
                .map(|id| {
                    (
                        id,
                        TargetPeer {
                            endpoint: format!("https://target-{id}.example:9446"),
                            failure_domain: format!("zone-{id}"),
                        },
                    )
                })
                .collect(),
        },
        phase_timeout_ms: 20_000,
    };
    request.checkpoint.tenant = request.tenant.clone();
    request.checkpoint.source_incarnation = request.source_incarnation.to_string();
    request.materialization.target_incarnation = request.target_incarnation;
    let route = RecoveryRoute {
        tenant: request.tenant.clone(),
        source_incarnation: request.source_incarnation,
        source_purpose_sha256: request.source_purpose_sha256.clone(),
        authority: "issuer".into(),
        issuer_admin_bearer_file: configured.bearer_files[&0].clone(),
        targets: request
            .target_nodes
            .iter()
            .map(|(id, node)| {
                (
                    *id,
                    RecoveryMember {
                        node: node.clone(),
                        replication: request.materialization.voters[id].clone(),
                        client: AdminClientConfig {
                            endpoint: endpoint.clone(),
                            identity: configured.tls.clone(),
                            server_ca: configured.server_ca.clone(),
                            server_certificate_pins: vec![hex::encode(pin)],
                            token_file: dir.join("control.jwt").display().to_string(),
                        },
                    },
                )
            })
            .collect(),
        source: None,
        source_custody: None,
    };
    let frozen_digest = route.digest(&configured).unwrap();
    let mut second_pin = pin;
    second_pin[0] = if pin[0] == 0xab { 0xcd } else { 0xab };
    let second_pin = hex::encode(second_pin);
    let mut third_pin = pin;
    third_pin[0] = if pin[0] == 0xef { 0x12 } else { 0xef };
    let third_pin = hex::encode(third_pin);
    let mut multi_pin_target = route.clone();
    multi_pin_target
        .targets
        .get_mut(&1)
        .unwrap()
        .client
        .server_certificate_pins = vec![hex::encode(pin), second_pin.clone()];
    let multi_pin_digest = multi_pin_target.digest(&configured).unwrap();
    let mut reordered_target = multi_pin_target.clone();
    reordered_target
        .targets
        .get_mut(&1)
        .unwrap()
        .client
        .server_certificate_pins = vec![
        second_pin.to_ascii_uppercase(),
        hex::encode(pin).to_ascii_uppercase(),
        second_pin.clone(),
    ];
    assert_eq!(
        reordered_target.digest(&configured).unwrap(),
        multi_pin_digest
    );
    reordered_target
        .targets
        .get_mut(&1)
        .unwrap()
        .client
        .server_certificate_pins[0] = third_pin.clone();
    assert_ne!(
        reordered_target.digest(&configured).unwrap(),
        multi_pin_digest
    );
    let mut invalid_target_pin = route.clone();
    invalid_target_pin
        .targets
        .get_mut(&1)
        .unwrap()
        .client
        .server_certificate_pins = vec!["zz".repeat(32)];
    assert!(invalid_target_pin.digest(&configured).is_err());
    let mut multi_pin_issuer = configured.clone();
    multi_pin_issuer
        .endpoints
        .get_mut(&0)
        .unwrap()
        .get_mut(&1)
        .unwrap()
        .certificate_pins
        .insert(second_pin.clone());
    let multi_issuer_digest = route.digest(&multi_pin_issuer).unwrap();
    let mut textual_issuer = multi_pin_issuer.clone();
    textual_issuer
        .endpoints
        .get_mut(&0)
        .unwrap()
        .get_mut(&1)
        .unwrap()
        .certificate_pins
        .insert(second_pin.to_ascii_uppercase());
    assert_eq!(route.digest(&textual_issuer).unwrap(), multi_issuer_digest);
    textual_issuer
        .endpoints
        .get_mut(&0)
        .unwrap()
        .get_mut(&1)
        .unwrap()
        .certificate_pins
        .insert(third_pin.clone());
    assert_ne!(route.digest(&textual_issuer).unwrap(), multi_issuer_digest);
    let copied_ca = dir.join("copied-ca.pem");
    private_files::publish(&copied_ca, ca.pem().as_bytes()).unwrap();
    let changed_ca = dir.join("changed-ca.pem");
    private_files::publish(&changed_ca, server_cert.as_bytes()).unwrap();
    let mut replacement = configured.clone();
    replacement.tls = TlsFiles {
        certificate: dir.join("replacement-client.pem"),
        private_key: dir.join("replacement-client-key.pem"),
    };
    replacement
        .bearer_files
        .insert(0, dir.join("replacement-issuer.jwt").display().to_string());
    replacement.principal = "replacement-control-member".into();
    replacement.server_ca = copied_ca.clone();
    let mut replacement_route = route.clone();
    replacement_route.authority = "replacement-local-issuer-alias".into();
    replacement_route.issuer_admin_bearer_file =
        dir.join("replacement-admin.jwt").display().to_string();
    for member in replacement_route.targets.values_mut() {
        member.client.identity = replacement.tls.clone();
        member.client.server_ca = copied_ca.clone();
        member.client.token_file = dir.join("replacement-target.jwt").display().to_string();
    }
    assert_eq!(
        replacement_route.digest(&replacement).unwrap(),
        frozen_digest
    );
    let mut changed_endpoint = replacement_route.clone();
    changed_endpoint
        .targets
        .get_mut(&1)
        .unwrap()
        .client
        .endpoint = "https://other-target.example:9443".into();
    assert_ne!(
        changed_endpoint.digest(&replacement).unwrap(),
        frozen_digest
    );
    let mut changed_target_ca = replacement_route.clone();
    changed_target_ca
        .targets
        .get_mut(&1)
        .unwrap()
        .client
        .server_ca = changed_ca.clone();
    assert_ne!(
        changed_target_ca.digest(&replacement).unwrap(),
        frozen_digest
    );
    let mut changed_issuer = replacement.clone();
    changed_issuer.server_ca = changed_ca.clone();
    assert_ne!(
        replacement_route.digest(&changed_issuer).unwrap(),
        frozen_digest
    );
    let source = RecoverySource {
        members: configured.endpoints[&0].clone(),
        identity: configured.tls.clone(),
        server_ca: configured.server_ca.clone(),
        token_file: dir.join("source-a.jwt").display().to_string(),
    };
    let mut planned = route.clone();
    planned.source = Some(source.clone());
    let mut custody_source = source;
    custody_source.token_file = dir.join("custody-a.jwt").display().to_string();
    planned.source_custody = Some(custody_source);
    let planned_digest = planned.digest(&configured).unwrap();
    for custody in [false, true] {
        let mut multi_pin_source = planned.clone();
        let source = if custody {
            multi_pin_source.source_custody.as_mut().unwrap()
        } else {
            multi_pin_source.source.as_mut().unwrap()
        };
        source
            .members
            .get_mut(&1)
            .unwrap()
            .certificate_pins
            .insert(second_pin.clone());
        let multi_source_digest = multi_pin_source.digest(&configured).unwrap();
        let mut textual_source = multi_pin_source.clone();
        {
            let source = if custody {
                textual_source.source_custody.as_mut().unwrap()
            } else {
                textual_source.source.as_mut().unwrap()
            };
            source
                .members
                .get_mut(&1)
                .unwrap()
                .certificate_pins
                .insert(second_pin.to_ascii_uppercase());
        }
        assert_eq!(
            textual_source.digest(&configured).unwrap(),
            multi_source_digest
        );
        {
            let source = if custody {
                textual_source.source_custody.as_mut().unwrap()
            } else {
                textual_source.source.as_mut().unwrap()
            };
            source
                .members
                .get_mut(&1)
                .unwrap()
                .certificate_pins
                .insert(third_pin.clone());
        }
        assert_ne!(
            textual_source.digest(&configured).unwrap(),
            multi_source_digest
        );
    }
    let mut replacement_planned = planned.clone();
    for (index, source) in [
        replacement_planned.source.as_mut().unwrap(),
        replacement_planned.source_custody.as_mut().unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        source.identity = replacement.tls.clone();
        source.server_ca = copied_ca.clone();
        source.token_file = dir
            .join(format!("replacement-source-{index}.jwt"))
            .display()
            .to_string();
    }
    assert_eq!(
        replacement_planned.digest(&configured).unwrap(),
        planned_digest
    );
    let mut changed_source_endpoint = replacement_planned.clone();
    changed_source_endpoint
        .source
        .as_mut()
        .unwrap()
        .members
        .get_mut(&1)
        .unwrap()
        .endpoint = "https://other-source.example:9443".into();
    assert_ne!(
        changed_source_endpoint.digest(&configured).unwrap(),
        planned_digest
    );
    replacement_planned.source.as_mut().unwrap().server_ca = changed_ca;
    assert_ne!(
        replacement_planned.digest(&configured).unwrap(),
        planned_digest
    );
    request.dispatch_configuration_sha256 = frozen_digest;
    let mut runtime =
        crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
    runtime.control.lifecycle = Some(crate::lifecycle_runtime::LifecycleRuntimeConfig {
        command_id: Uuid::new_v4(),
        installation: f.installation.clone(),
        signing_key: dir.join("control-signer.pk8"),
        recovery: Some(RecoveryRuntimeConfig {
            routes: BTreeMap::from([("city".into(), route)]),
        }),
    });
    runtime.serving_authorities = BTreeMap::from([("issuer".into(), configured)]);
    let coordinator = ControlRecoveryCoordinator::new(
        &runtime,
        f.control.clone(),
        f.signer,
        BTreeMap::from([("issuer".into(), f.trust.clone())]),
    )
    .unwrap();
    let routes = tonic::service::Routes::new(
        NativeRecoveryControl::new(coordinator, f.auth.clone()).service(),
    )
    .add_service(NativeAuthority::new(f.issuer.clone(), f.auth).service())
    .into_axum_router();
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(crate::tls::serve_tls(
        socket,
        tls,
        routes,
        crate::tls::ListenerLimits::default(),
        f.audit,
        stopped,
    ));
    let config = kasumi_client::KasumiClientConfig {
        endpoint,
        identity: client,
        trusted_ca_pem: ca.pem().into_bytes(),
        server_certificate_pins: BTreeSet::from([pin]),
    };
    let mut authority = kasumi_client::KasumiAuthorityClient::connect(&config, f.trust)
        .await
        .unwrap();
    let enrollment = AuthorityCommand {
        tenant: request.tenant.clone(),
        command_id: Uuid::new_v4(),
        expected_policy_epoch: 1,
        not_after_ms: kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            + 30_000,
        action: AuthorityAction::Enroll {
            incarnation: request.source_incarnation,
            nodes: request
                .target_nodes
                .values()
                .map(|node| NodeIdentity {
                    node_id: node.node_id,
                    verifier: node.verifier.clone(),
                    principal: node.principal.clone(),
                    certificate_sha256: node.certificate_sha256.clone(),
                })
                .collect(),
        },
    };
    let enrolled = authority
        .execute(f.issuer_admin, &enrollment)
        .await
        .unwrap();
    assert!(
        !matches!(enrolled.receipt.outcome, AuthorityOutcome::Rejected { .. }),
        "{:?}",
        enrolled.receipt.outcome
    );
    let mut client = kasumi_client::KasumiRecoveryClient::connect(&config)
        .await
        .unwrap();
    assert!(client.start(f.wrong_resource, &request).await.is_err());
    assert!(client.start(f.readonly, &request).await.is_err());
    let started = client.start(f.control_admin, &request).await.unwrap();
    assert_eq!(started.phase, RecoveryPhase::Prepare);
    assert_eq!(
        client
            .start(f.control_admin, &request)
            .await
            .unwrap()
            .created_revision,
        started.created_revision
    );
    let operation = request.operation_id;
    let advance = RecoveryResume {
        operation_id: operation,
        max_steps: 2,
    };
    let materialize = match client.resume(f.control_admin, &advance).await {
        Ok(record) => record,
        Err(kasumi_client::ClientError::Transport(status))
            if serde_json::from_slice::<kasumi_types::Error>(status.details())
                .is_ok_and(|error| error.code == ErrorCode::UnknownOutcome) =>
        {
            // The proposal can outlive its finite response deadline. Resolve
            // the original operation by read-only status; never dispatch a
            // second resume merely because the first reply was uncertain.
            tokio::time::timeout(Duration::from_secs(45), async {
                loop {
                    match client
                        .status(
                            f.control_admin,
                            &RecoveryStatusRequest {
                                operation_id: operation,
                            },
                        )
                        .await
                    {
                        Ok(record) => {
                            assert_eq!(record.request, request);
                            if record.phase == RecoveryPhase::Materialize
                                && record.issuer_preparation.is_some()
                            {
                                break record;
                            }
                            assert!(
                                matches!(
                                    record.phase,
                                    RecoveryPhase::Prepare | RecoveryPhase::Materialize
                                ),
                                "uncertain preparation advanced to an unexpected phase: {record:?}"
                            );
                        }
                        Err(kasumi_client::ClientError::Transport(status))
                            if matches!(
                                status.code(),
                                tonic::Code::Unavailable
                                    | tonic::Code::DeadlineExceeded
                                    | tonic::Code::Unknown
                            ) => {}
                        Err(error) => panic!("exact recovery status was rejected: {error:?}"),
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("uncertain recovery proposal did not become observable")
        }
        Err(error) => panic!("recovery proposal was definitively rejected: {error:?}"),
    };
    assert_eq!(materialize.phase, RecoveryPhase::Materialize);
    let issuer_phase = client
        .read_phase(
            f.control_admin,
            &RecoveryPhaseRequest {
                operation_id: operation,
                phase_id: materialize.issuer_preparation.unwrap(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        issuer_phase.outcome,
        Some(RecoveryDispatchOutcome::Authority(_))
    ));
    let intent = client.resume(f.control_admin, &advance).await.unwrap();
    assert!(intent.current_intent.is_some());
    let prepared = match client
        .resume(
            f.control_admin,
            &RecoveryResume {
                operation_id: operation,
                max_steps: 1,
            },
        )
        .await
    {
        Ok(record) => record,
        Err(kasumi_client::ClientError::Transport(status))
            if serde_json::from_slice::<kasumi_types::Error>(status.details())
                .is_ok_and(|error| error.code == ErrorCode::UnknownOutcome) =>
        {
            // A prepared target phase can commit before its response release.
            // Observe only the original operation; replaying resume here could
            // prepare or dispatch a different phase with a fresh identity.
            tokio::time::timeout(Duration::from_secs(45), async {
                loop {
                    match client
                        .status(
                            f.control_admin,
                            &RecoveryStatusRequest {
                                operation_id: operation,
                            },
                        )
                        .await
                    {
                        Ok(record) => {
                            assert_eq!(record.request, request);
                            assert_eq!(record.phase, RecoveryPhase::Materialize);
                            assert_eq!(record.current_intent, intent.current_intent);
                            if record.pending_phase.is_some() {
                                break record;
                            }
                        }
                        Err(kasumi_client::ClientError::Transport(status))
                            if matches!(
                                status.code(),
                                tonic::Code::Unavailable
                                    | tonic::Code::DeadlineExceeded
                                    | tonic::Code::Unknown
                            ) => {}
                        Err(error) => panic!("exact recovery status was rejected: {error:?}"),
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("uncertain target preparation did not become observable")
        }
        Err(error) => panic!("target preparation was definitively rejected: {error:?}"),
    };
    assert_eq!(prepared.phase, RecoveryPhase::Materialize);
    assert_eq!(prepared.current_intent, intent.current_intent);
    let pending = prepared.pending_phase.unwrap();
    assert!(
        client
            .resume(
                f.control_admin,
                &RecoveryResume {
                    operation_id: operation,
                    max_steps: 1
                }
            )
            .await
            .is_err()
    );
    let after = client
        .status(
            f.control_admin,
            &RecoveryStatusRequest {
                operation_id: operation,
            },
        )
        .await
        .unwrap();
    assert_eq!(after.pending_phase, Some(pending));
    let phase = client
        .read_phase(
            f.control_admin,
            &RecoveryPhaseRequest {
                operation_id: operation,
                phase_id: pending,
            },
        )
        .await
        .unwrap();
    assert!(phase.outcome.is_none());
    assert!(
        client
            .read_phase(
                f.readonly,
                &RecoveryPhaseRequest {
                    operation_id: operation,
                    phase_id: pending
                }
            )
            .await
            .is_err()
    );
    let stop_request = RecoveryStop {
        operation_id: operation,
        command_id: Uuid::new_v4(),
    };
    assert_eq!(
        client
            .stop(f.control_admin, &stop_request)
            .await
            .unwrap()
            .phase,
        RecoveryPhase::StopTarget
    );
    assert_eq!(
        client
            .stop(f.control_admin, &stop_request)
            .await
            .unwrap()
            .stop_request,
        Some(stop_request.command_id)
    );
    let cleanup = client.resume(f.control_admin, &advance).await.unwrap();
    assert_eq!(cleanup.phase, RecoveryPhase::Cleanup);
    let cleanup = client.resume(f.control_admin, &advance).await.unwrap();
    assert!(cleanup.current_intent.is_some());
    assert!(
        client
            .read_phase(
                f.control_admin,
                &RecoveryPhaseRequest {
                    operation_id: operation,
                    phase_id: pending
                }
            )
            .await
            .unwrap()
            .outcome
            .is_none()
    );
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
