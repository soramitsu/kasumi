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
    };
    request.dispatch_configuration_sha256 = route.digest(&configured).unwrap();
    let mut runtime = crate::runtime::example_config();
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
    let materialize = client.resume(f.control_admin, &advance).await.unwrap();
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
    let prepared = client
        .resume(
            f.control_admin,
            &RecoveryResume {
                operation_id: operation,
                max_steps: 1,
            },
        )
        .await
        .unwrap();
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
