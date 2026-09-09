//! This runs after the native lifecycle fixture has completed its original work:
//! global activation deliberately seals that fixture's old issuance generation.
use super::*;
use crate::{
    control_signer_runtime::ControlSignerRuntime,
    runtime::{KeyProviderSettings, TlsFiles, file_secret},
    serving_runtime::{AuthorityEndpoint, ServingAuthorityConfig},
    signer_runtime::{InitializeSignerVerifier, SignerVerifierConfig},
};
use kasumi_client::{KasumiAdminClient, KasumiAuthorityClient, KasumiClientConfig};
use kasumi_serving::*;
use kasumi_store::private_files;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use uuid::Uuid;

pub(super) struct Fixture<'a> {
    pub directory: &'a std::path::Path,
    pub control: Arc<kasumi_engine::Database>,
    pub issuer: Arc<kasumi_authority::IndependentAuthority>,
    pub auth: Arc<Authenticator>,
    pub audit: Arc<kasumi_engine::SecurityAudit>,
    pub installation: kasumi_types::LifecycleInstallation,
    pub manifest: AuthorityManifest,
    pub initial_certificate: SigningCertificate,
    pub root: InstallationSigningRoot,
    pub issuer_admin: &'a str,
    pub receiver_tokens: BTreeMap<u64, String>,
    pub control_admin: &'a str,
    pub wrong_resource: &'a str,
    pub readonly: &'a str,
}

async fn signing(
    client: &mut KasumiAuthorityClient,
    bearer: &str,
    domain: &SigningDomain,
    action: AuthorityMaintenanceAction,
) -> AuthoritySigningResponse {
    let current = client
        .signing_maintenance(
            bearer,
            &AuthoritySigningRequest {
                observation_id: Uuid::new_v4(),
                domain_sha256: domain.digest().unwrap(),
                action: AuthoritySigningAction::Observe,
            },
        )
        .await
        .unwrap();
    let mut command = AuthorityMaintenanceCommand {
        operation_id: Uuid::new_v4(),
        expected_policy_epoch: current.policy_epoch,
        expected_operational_revision: current.operational_revision,
        not_after_ms: kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            + 30_000,
        action,
    };
    if let AuthorityMaintenanceAction::AuthorizeControlSigner { directive } = &command.action {
        command.operation_id = directive.command.operation_id;
        command.not_after_ms = directive.command.not_after_ms;
    }
    let request = AuthoritySigningRequest {
        observation_id: Uuid::new_v4(),
        domain_sha256: domain.digest().unwrap(),
        action: AuthoritySigningAction::Start { command },
    };
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match client.signing_maintenance(bearer, &request).await {
                Ok(response) => return response,
                Err(kasumi_client::ClientError::Transport(status))
                    if matches!(
                        status.code(),
                        tonic::Code::Unknown | tonic::Code::Unavailable
                    ) => {}
                Err(error) => panic!("definitive remote setup rejection: {error:?}"),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

pub(super) async fn exercise(f: Fixture<'_>) {
    use rcgen::*;
    let directory = f.directory.join("remote-control-signer");
    private_files::create_directory(&directory).unwrap();
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
    let (server_certificate, server_key) = issue("localhost");
    let (client_certificate, client_key) = issue("control-receiver");
    for (name, contents) in [
        ("server.pem", server_certificate.as_bytes()),
        ("server-key.pem", server_key.as_bytes()),
        ("client.pem", client_certificate.as_bytes()),
        ("client-key.pem", client_key.as_bytes()),
        ("ca.pem", ca.pem().as_bytes()),
    ] {
        private_files::create(&directory.join(name), contents).unwrap();
    }
    let tls_files = |prefix: &str| TlsFiles {
        certificate: directory.join(format!("{prefix}.pem")),
        private_key: directory.join(format!("{prefix}-key.pem")),
    };
    let server = tls_files("server").load().unwrap();
    let client = tls_files("client").load().unwrap();
    let node_id = f.control.raft_group().raft().metrics().borrow().id;
    let domain = f.manifest.signing_domain(0).unwrap();
    let physical_installation = Uuid::new_v4();
    let physical = TrustVerifierIdentity {
        installation_id: physical_installation,
        node_id,
    };
    let wrapping = directory.join("wrapping.json");
    kasumi_store::FileKeyProvider::initialize(&wrapping, "remote-control-trust").unwrap();
    let initialization = InitializeSignerVerifier {
        scratch_disk: kasumi_store::ScratchDiskConfig {
            directory: directory.join("scratch"),
            max_bytes: 64 << 30,
            min_free_bytes: 256 << 20,
        },
        verifier: SignerVerifierConfig {
            identity: physical.clone(),
            database_path: directory.join("verifier.redb"),
            keys: KeyProviderSettings::File { path: wrapping },
        },
        initial_certificates: vec![f.initial_certificate.clone()],
    };
    initialization.initialize().await.unwrap();
    let scratch = kasumi_store::ScratchDisk::open(initialization.scratch_disk.clone()).unwrap();
    let domains = BTreeMap::from([(domain.digest().unwrap(), domain.clone())]);
    let verifier = initialization
        .verifier
        .open(domains.clone(), Arc::new(file_secret), scratch.clone())
        .await
        .unwrap();
    let trust = verifier.trust(f.manifest.clone()).unwrap();
    let token_path = directory.join("receiver.jwt");
    private_files::create(&token_path, f.receiver_tokens[&node_id].as_bytes()).unwrap();
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://localhost:{}", socket.local_addr().unwrap().port());
    let authority = ServingAuthorityConfig {
        manifest: f.manifest.clone(),
        endpoints: BTreeMap::from([(
            0,
            BTreeMap::from([(
                f.issuer.raft_group().raft().metrics().borrow().id,
                AuthorityEndpoint {
                    endpoint: endpoint.clone(),
                    certificate_pins: BTreeSet::from([hex::encode(server.certificate_pin())]),
                },
            )]),
        )]),
        tls: tls_files("client"),
        server_ca: directory.join("ca.pem"),
        bearer_files: BTreeMap::from([(0, token_path.to_string_lossy().into_owned())]),
        principal: format!("control-{node_id}"),
    };
    let runtime = ControlSignerRuntime::new(
        node_id,
        f.control.clone(),
        verifier.clone(),
        BTreeMap::from([("installed".into(), authority)]),
        BTreeMap::from([("installed".into(), trust.clone())]),
        tls_files("server"),
        Arc::new(file_secret),
    )
    .unwrap();
    let routes = tonic::service::Routes::new(
        NativeAuthority::new(f.issuer.clone(), f.auth.clone()).service(),
    )
    .add_service(
        NativeAdmin::new(DatabaseRegistry::default(), f.auth.clone())
            .with_control_signer(runtime)
            .service(),
    )
    .into_axum_router();
    let tls = kasumi_transport::server_config(
        &server,
        kasumi_transport::ClientAuthentication::Required {
            trusted_ca_pem: ca.pem().as_bytes(),
        },
    )
    .unwrap();
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(crate::tls::serve_tls(
        socket,
        tls,
        routes,
        crate::tls::ListenerLimits::default(),
        f.audit.clone(),
        stopped,
    ));
    let config = KasumiClientConfig {
        endpoint: endpoint.clone(),
        identity: client.clone(),
        trusted_ca_pem: ca.pem().into_bytes(),
        server_certificate_pins: BTreeSet::from([server.certificate_pin()]),
    };
    let mut issuer_client = KasumiAuthorityClient::connect(&config, trust.clone())
        .await
        .unwrap();
    let mut admin_client = KasumiAdminClient::connect(&config).await.unwrap();
    // The existing lifecycle fixture's data/targets share its three issuer
    // identities. The three Control verifier owners form a distinct installation.
    let controls: BTreeSet<_> = (1..=3)
        .map(|id| NodeIdentity {
            node_id: id,
            verifier: TrustVerifierIdentity {
                installation_id: physical_installation,
                node_id: id,
            },
            principal: format!("control-{id}"),
            certificate_sha256: if id == node_id {
                hex::encode(client.certificate_pin())
            } else {
                format!("{:064x}", id + 1100)
            },
        })
        .collect();
    let mut physical_receivers: BTreeSet<_> = (1..=3)
        .map(kasumi_serving::test_utils::fixture_verifier)
        .collect();
    physical_receivers.extend(controls.iter().map(|node| node.verifier.clone()));
    for (index, identity) in physical_receivers.into_iter().enumerate() {
        let local = identity == physical;
        let response = signing(
            &mut issuer_client,
            f.issuer_admin,
            &domain,
            AuthorityMaintenanceAction::EnrollSignerVerifier {
                enrollment: SignerVerifierEnrollment {
                    verifier: identity,
                    endpoint: if local {
                        format!("{endpoint}/")
                    } else {
                        format!("https://registered-{index}.test/")
                    },
                    certificate_pins: BTreeSet::from([if local {
                        hex::encode(server.certificate_pin())
                    } else {
                        format!("{:064x}", index + 2200)
                    }]),
                },
            },
        )
        .await;
        assert_eq!(
            response.status.unwrap().phase,
            AuthorityMaintenancePhase::Completed
        );
    }
    let response = signing(
        &mut issuer_client,
        f.issuer_admin,
        &domain,
        AuthorityMaintenanceAction::AdmitControlVerifiers {
            admission: ControlVerifierAdmission {
                root: f.installation.root.clone(),
                partition: f.manifest.control_partition(0).unwrap(),
                nodes: controls.clone(),
            },
        },
    )
    .await;
    assert_eq!(
        response.status.unwrap().phase,
        AuthorityMaintenancePhase::Completed
    );
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let successor = f
        .root
        .certify(2, hex::encode(key.public_key_raw()))
        .unwrap();
    let staged = signing(
        &mut issuer_client,
        f.issuer_admin,
        &domain,
        AuthorityMaintenanceAction::StageSignerGeneration {
            certificate: successor.clone(),
        },
    )
    .await;
    let global_stage = staged.status.unwrap();
    assert_eq!(global_stage.phase, AuthorityMaintenancePhase::Completed);
    let mut request = ControlSignerRequest {
        observation_id: Uuid::new_v4(),
        directive: ControlSignerDirective {
            root: f.installation.root.clone(),
            node: controls
                .iter()
                .find(|node| node.node_id == node_id)
                .unwrap()
                .clone(),
            domain_sha256: domain.digest().unwrap(),
            global_stage_operation_id: global_stage.command.operation_id,
            global_activation_operation_id: None,
            command: SignerTrustCommand {
                operation_id: Uuid::new_v4(),
                expected_revision: 0,
                not_after_ms: kasumi_clock::EpochClock::system()
                    .unwrap()
                    .now_ms()
                    .unwrap()
                    + 30_000,
                action: SignerTrustAction::Stage {
                    certificate: successor.clone(),
                },
            },
        },
    };
    assert!(
        admin_client
            .control_signer_maintenance(f.control_admin, &request, &f.manifest)
            .await
            .is_err()
    );
    let permission = signing(
        &mut issuer_client,
        f.issuer_admin,
        &domain,
        AuthorityMaintenanceAction::AuthorizeControlSigner {
            directive: Box::new(request.directive.clone()),
        },
    )
    .await;
    assert_eq!(
        permission.status.unwrap().phase,
        AuthorityMaintenancePhase::Completed
    );
    assert!(
        admin_client
            .control_signer_maintenance(f.wrong_resource, &request, &f.manifest)
            .await
            .is_err()
    );
    assert!(
        admin_client
            .control_signer_maintenance(f.readonly, &request, &f.manifest)
            .await
            .is_err()
    );
    let mut other = request.clone();
    other.directive.node.verifier.installation_id = Uuid::new_v4();
    assert!(
        admin_client
            .control_signer_maintenance(f.control_admin, &other, &f.manifest)
            .await
            .is_err()
    );
    let stage_receipt = admin_client
        .control_signer_maintenance(f.control_admin, &request, &f.manifest)
        .await
        .unwrap();
    assert_eq!(stage_receipt.current.revision, 1);
    assert_eq!(stage_receipt.current.active, f.initial_certificate);
    assert_eq!(
        stage_receipt.current.staged.as_ref().unwrap().certificate,
        successor
    );
    request.observation_id = Uuid::new_v4();
    let replay = admin_client
        .control_signer_maintenance(f.control_admin, &request, &f.manifest)
        .await
        .unwrap();
    assert_eq!(replay.receipt, stage_receipt.receipt);
    let mut forged = replay.clone();
    forged.receipt.active_generation = 2;
    assert!(forged.validate_for(&request, &f.manifest).is_err());
    let global_activation = signing(
        &mut issuer_client,
        f.issuer_admin,
        &domain,
        AuthorityMaintenanceAction::ActivateSignerGeneration {
            stage_operation_id: global_stage.command.operation_id,
            certificate_sha256: successor.digest().unwrap(),
        },
    )
    .await
    .status
    .unwrap();
    assert_eq!(
        global_activation.phase,
        AuthorityMaintenancePhase::Completed
    );
    let activation = ControlSignerRequest {
        observation_id: Uuid::new_v4(),
        directive: ControlSignerDirective {
            global_activation_operation_id: Some(global_activation.command.operation_id),
            command: SignerTrustCommand {
                operation_id: Uuid::new_v4(),
                expected_revision: 1,
                not_after_ms: kasumi_clock::EpochClock::system()
                    .unwrap()
                    .now_ms()
                    .unwrap()
                    + 30_000,
                action: SignerTrustAction::Activate {
                    staged_operation_id: request.directive.command.operation_id,
                    certificate_sha256: successor.digest().unwrap(),
                },
            },
            ..request.directive.clone()
        },
    };
    let publication_bearer = directory.join("control-publication.jwt");
    private_files::create(&publication_bearer, f.control_admin.as_bytes()).unwrap();
    let publication = crate::signer_publication_runtime::SignerPublicationConfig {
        receivers: vec![
            crate::signer_publication_runtime::SignerPublicationReceiver {
                verifier: physical.clone(),
                endpoint: format!("{endpoint}/"),
                certificate_pins: BTreeSet::from([hex::encode(server.certificate_pin())]),
                server_ca: directory.join("ca.pem"),
                tls: tls_files("client"),
                bearer_file: publication_bearer,
            },
        ],
    };
    f.issuer
        .install_signer_publication_transport(publication.open(f.manifest.clone()).unwrap())
        .unwrap();
    let current = issuer_client
        .signing_maintenance(
            f.issuer_admin,
            &AuthoritySigningRequest {
                observation_id: Uuid::new_v4(),
                domain_sha256: domain.digest().unwrap(),
                action: AuthoritySigningAction::Observe,
            },
        )
        .await
        .unwrap();
    let dispatch = SignerCoverageCommand {
        operation_id: Uuid::new_v4(),
        expected_policy_epoch: current.policy_epoch,
        expected_operational_revision: current.operational_revision,
        not_after_ms: activation.directive.command.not_after_ms,
        publication: SignerPublicationRequest::Control {
            request: Box::new(activation.clone()),
        },
    };
    let pending = issuer_client
        .signer_coverage(
            f.issuer_admin,
            &SignerCoverageRequest::Start {
                command: dispatch.clone(),
            },
        )
        .await
        .unwrap();
    assert!(pending.status.acknowledgment.is_none());
    let owner = verifier.owner(&domain).unwrap();
    let old = owner.observe().unwrap();
    let resume = SignerCoverageRequest::Resume {
        operation_id: dispatch.operation_id,
    };
    let covered = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match issuer_client.signer_coverage(f.issuer_admin, &resume).await {
                Ok(response) => break response,
                Err(kasumi_client::ClientError::Transport(status))
                    if matches!(
                        status.code(),
                        tonic::Code::Unknown | tonic::Code::Unavailable
                    ) => {}
                Err(error) => panic!("definitive coverage dispatch rejection: {error:?}"),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(covered.status.dispatch, pending.status.dispatch);
    assert_eq!(
        issuer_client
            .signer_coverage(f.issuer_admin, &resume)
            .await
            .unwrap(),
        covered
    );
    let SignerPublicationResponse::Control(activated) =
        &covered.status.acknowledgment.as_ref().unwrap().publication
    else {
        unreachable!()
    };
    assert_eq!(activated.current.active, successor);
    assert!(activated.receipt.retirement_pending);
    assert!(activated.issuer.head.retirement.is_some());
    assert!(old.check().is_err());
    // A serialized or newly authenticated current principal cannot bypass the
    // request-owned Control/issuer scope retained only during the RPC.
    let context = f
        .auth
        .authenticate(&format!("Bearer {}", f.control_admin))
        .await
        .unwrap();
    assert!(
        owner
            .administer(
                &context,
                SignerTrustCommand {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 2,
                    not_after_ms: activation.directive.command.not_after_ms,
                    action: SignerTrustAction::CompleteRetirement {
                        activation_operation_id: activation.directive.command.operation_id
                    },
                }
            )
            .is_err()
    );
    drop(old);
    drop(owner);
    drop(issuer_client);
    drop(admin_client);
    drop(trust);
    stop.send(true).unwrap();
    serving.await.unwrap().unwrap();
    verifier.shutdown().await;
    drop(verifier);
    let reopened = initialization
        .verifier
        .open(domains, Arc::new(file_secret), scratch)
        .await
        .unwrap();
    assert_eq!(
        reopened.owner(&domain).unwrap().current().unwrap(),
        activated.current
    );
    reopened.shutdown().await;
}
