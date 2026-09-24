use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kasumi_authority::{AuthorityInstallation, IndependentAuthority};
use kasumi_client::{KasumiAuthorityClient, KasumiClientConfig};
use kasumi_serving::*;
use kasumi_store::{StorageAccess, TenantStorageSet, TenantStore, test_utils::LocalKeyProvider};
use kasumi_transport::{ClientAuthentication, TlsIdentity};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

pub(super) fn certificates() -> (String, TlsIdentity, Vec<TlsIdentity>) {
    use rcgen::*;
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    let issuer = Issuer::new(params, key);
    let issue = |name: &str| {
        let mut params = CertificateParams::new(vec![name.into()]).unwrap();
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, &issuer).unwrap();
        TlsIdentity::from_pem(certificate.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap()
    };
    (
        certificate.pem(),
        issue("localhost"),
        (1..=3).map(|i| issue(&format!("node-{i}"))).collect(),
    )
}

struct CoverageTransport {
    config: KasumiClientConfig,
    trust: AuthorityTrust,
    bearer_file: std::path::PathBuf,
    expire_first: std::sync::atomic::AtomicBool,
}
#[async_trait::async_trait]
impl kasumi_authority::SignerPublicationTransport for CoverageTransport {
    async fn observe(
        &self,
        dispatch: &SignerCoverageDispatch,
    ) -> anyhow::Result<kasumi_client::CurrentSignerPublication> {
        let bearer = crate::runtime::file_secret(
            self.bearer_file
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("fixture credential path is not UTF-8"))?,
        )?;
        let observation = kasumi_client::CurrentSignerPublication::observe(
            &self.config,
            &bearer,
            self.trust.clone(),
            dispatch,
        )
        .await?;
        if self
            .expire_first
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            // The remote effect already committed. Losing its first finite
            // response must keep coverage pending until the original receipt is
            // observed again through the same pinned native endpoint.
            tokio::time::sleep(Duration::from_millis(
                self.trust.manifest().max_lease_ms + 25,
            ))
            .await;
        }
        Ok(observation)
    }
}

#[tokio::test]
async fn actual_pinned_native_issuer_binds_jwt_peer_attempt_and_current_admin_recovery() {
    let dir = kasumi_store::test_utils::private_tempdir().unwrap();
    let (ca, server_identity, mut identities) = certificates();
    let issuer = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let keys = serde_json::from_value(json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"identity-key","x":URL_SAFE_NO_PAD.encode(issuer.public_key_raw())}]})).unwrap();
    let auth = Authenticator::with_test_keys(
        crate::auth::AuthConfig {
            issuer: "https://identity.example".into(),
            audience: "https://authority.example".into(),
            source: crate::auth::AuthKeySource::ExternalOAuth {
                jwks_uri: "https://identity.example/keys".into(),
                trusted_ca_pem: None,
            },
            algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
            access_token_types: BTreeSet::from(["at+jwt".into()]),
        },
        keys,
    )
    .await;
    kasumi_store::private_files::create_directory(&dir.path().join("audit")).unwrap();
    let audit_physical =
        crate::runtime_storage_fixtures::physical(&dir.path().join("audit"), Default::default())
            .unwrap();
    let audit_node = audit_physical
        .create_new(
            dir.path().join("audit/persistent/audit.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let audit_store = TenantStore::initialize_catalog(
        audit_node.clone(),
        kasumi_engine::SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([88; 32])),
        StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    let audit = kasumi_engine::SecurityAudit::initialize(
        audit_store.clone(),
        kasumi_types::AuditRetentionBudget::default(),
        audit_physical.admission.clone(),
    )
    .unwrap();
    auth.install_audit(audit.clone()).unwrap();
    let signing = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let manifest = AuthorityManifest {
        lifecycle_controls: std::collections::BTreeMap::new(),
        authority_id: uuid::Uuid::new_v4(),
        max_lease_ms: 1000,
        clock_rate_error_ppm: 0,
        partitions: BTreeMap::from([(
            0,
            AuthorityPartition {
                group: "independent-authority".into(),
                public_key: hex::encode(signing.public_key_raw()),
            },
        )]),
    };
    let domain = manifest.signing_domain(0).unwrap();
    let root =
        InstallationSigningRoot::from_pkcs8(domain.clone(), &signing.serialize_der()).unwrap();
    let operational = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let certificate = root
        .certify(1, hex::encode(operational.public_key_raw()))
        .unwrap();
    let next_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let next_certificate = root
        .certify(2, hex::encode(next_key.public_key_raw()))
        .unwrap();
    let signer_directory = dir.path().join("operational-signer");
    kasumi_store::private_files::create_directory(&signer_directory).unwrap();
    let old_key_file = signer_directory.join("generation-1.pk8");
    let next_key_file = signer_directory.join("generation-2.pk8");
    kasumi_store::private_files::create(&old_key_file, &operational.serialize_der()).unwrap();
    kasumi_store::private_files::create(&next_key_file, &next_key.serialize_der()).unwrap();
    let signer_file = signer_directory.join("current.json");
    let publish_source = |certificate: &SigningCertificate, key_file: &std::path::Path| {
        kasumi_store::private_files::replace(
            &signer_file,
            &serde_json::to_vec(&crate::signer_runtime::OperationalSignerConfig {
                certificate: certificate.clone(),
                key_file: key_file.into(),
            })
            .unwrap(),
        )
        .unwrap();
    };
    publish_source(&certificate, &old_key_file);
    let verifier_installation = uuid::Uuid::new_v4();
    let mut verifier_stores = Vec::new();
    let mut physical_nodes = Vec::new();
    let mut installed_verifiers = Vec::new();
    let mut live_owners = Vec::new();
    // Each actual authority process and the client verifier has independently
    // encrypted trust. This callback is a fixture for the current authenticated
    // administrator; it is not a distributed maintenance coordinator.
    for node_id in 1..=4 {
        let verifier = TrustVerifierIdentity {
            installation_id: if node_id == 4 {
                uuid::Uuid::new_v4()
            } else {
                verifier_installation
            },
            node_id: if node_id == 4 { 1 } else { node_id },
        };
        if node_id <= 3 {
            use crate::signer_runtime::{InitializeSignerVerifier, SignerVerifierConfig};
            let directory = dir.path().join(format!("verifier-{node_id}"));
            kasumi_store::private_files::create_directory(&directory).unwrap();
            let keys = directory.join("keys.json");
            kasumi_store::FileKeyProvider::initialize(&keys, "signer-verifier").unwrap();
            let persistent_disk = crate::persistent_disk::fixture_config(&directory.join("data"));
            let config = SignerVerifierConfig {
                max_background_workers: 64,
                identity: verifier,
                database_path: directory.join("data/trust.redb"),
                keys: crate::runtime::KeyProviderSettings::File { path: keys },
            };
            let mut input = InitializeSignerVerifier {
                admission: Default::default(),
                persistent_disk: persistent_disk.clone(),
                scratch_disk: kasumi_store::ScratchDiskConfig {
                    directory: directory.join("scratch"),
                    max_bytes: 64 << 30,
                    min_free_bytes: 256 << 20,
                },
                verifier: config.clone(),
                initial_certificates: vec![certificate.clone()],
            };
            let storage = crate::runtime_memory::RuntimeStorage::isolated_fixture(
                input.admission.clone(),
                &input.persistent_disk,
                &input.scratch_disk,
            )
            .unwrap();
            input.admission = storage.policy().clone();
            input
                .initialize_with_storage(storage.clone())
                .await
                .unwrap();
            let admission = storage.facade(storage.policy()).unwrap();
            let installed = config
                .open(
                    BTreeMap::from([(domain.digest().unwrap(), domain.clone())]),
                    Arc::new(crate::runtime::file_secret),
                    storage.open_persistent(&persistent_disk).unwrap(),
                    storage.open_scratch(&input.scratch_disk).unwrap(),
                    admission,
                )
                .await
                .unwrap();
            live_owners.push(installed.owner(&domain).unwrap());
            installed_verifiers.push(installed);
            continue;
        }
        let verifier_root = dir.path().join(format!("verifier-{node_id}"));
        kasumi_store::private_files::create_directory(&verifier_root).unwrap();
        let physical =
            crate::runtime_storage_fixtures::physical(&verifier_root, Default::default()).unwrap();
        let node = physical
            .create_new(
                verifier_root.join("persistent/verifier.redb"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .unwrap();
        physical_nodes.push(node.clone());
        let store = TenantStore::initialize_catalog(
            node,
            verifier.tenant(),
            Arc::new(LocalKeyProvider::new([node_id as u8 + 100; 32])),
            StorageAccess::live_signer_trust(verifier.clone()).unwrap(),
        )
        .await
        .unwrap();
        let owner = store
            .initialize_live_signer_trust(
                &verifier,
                certificate.clone(),
                Arc::new(CurrentFixtureAdministrator {
                    authority_id: manifest.authority_id,
                }),
                kasumi_serving::BackgroundWorkBudget::new(64, Arc::new(())).unwrap(),
            )
            .unwrap();
        verifier_stores.push(store);
        live_owners.push(owner);
    }
    let installation = AuthorityInstallation {
        manifest: manifest.clone(),
        partition: 0,
    };
    let trust = AuthorityTrust::install(manifest.clone())
        .unwrap()
        .with_live_verifiers(BTreeMap::from([(0, live_owners[3].clone())]))
        .unwrap();
    let router = Arc::new(kasumi_raft::InProcessRouter::default());
    let bootstrap = kasumi_authority::AuthorityBootstrap {
        initial_signer_certificate: certificate.clone(),
        administrators: BTreeSet::from(["operator".into()]),
        capacity: kasumi_serving::AuthorityCapacity {
            max_tenants: 10,
            max_state_bytes: 4 << 20,
            maintenance_reserve_bytes: 1 << 20,
        },
        membership: kasumi_serving::AuthorityMembership {
            voters: BTreeSet::from([1, 2, 3]),
            members: (1..=3)
                .map(|n| {
                    (
                        n,
                        kasumi_serving::AuthorityMember {
                            verifier: kasumi_serving::TrustVerifierIdentity {
                                installation_id: verifier_installation,
                                node_id: n,
                            },
                            endpoint: format!("https://authority-{n}.test"),
                            failure_domain: format!("domain-{n}"),
                            certificate_pins: BTreeSet::from([format!("{n:064x}")]),
                        },
                    )
                })
                .collect(),
        },
    };
    let settings = kasumi_authority::AuthorityNodeSettings {
        resource_budget_bytes: 4 << 20,
        installed_members: (1..=3)
            .map(|n| {
                (
                    n,
                    kasumi_serving::AuthorityMember {
                        verifier: kasumi_serving::TrustVerifierIdentity {
                            installation_id: verifier_installation,
                            node_id: n,
                        },
                        endpoint: format!("https://authority-{n}.test"),
                        failure_domain: format!("domain-{n}"),
                        certificate_pins: BTreeSet::from([format!("{n:064x}")]),
                    },
                )
            })
            .collect(),
    };
    let mut services = Vec::new();
    let mut stores = Vec::new();
    for id in 1..=3 {
        let authority_root = dir.path().join(format!("authority-{id}"));
        kasumi_store::private_files::create_directory(&authority_root).unwrap();
        let physical =
            crate::runtime_storage_fixtures::physical(&authority_root, Default::default()).unwrap();
        let node = physical
            .create_new(
                authority_root.join("persistent/authority.redb"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .unwrap();
        physical_nodes.push(node.clone());
        let storage = TenantStorageSet::initialize_catalogs(
            node,
            installation.tenant(),
            Arc::new(LocalKeyProvider::new([id as u8; 32])),
            Arc::new(LocalKeyProvider::new([id as u8 + 10; 32])),
            StorageAccess::independent_authority(&manifest, 0).unwrap(),
        )
        .await
        .unwrap();
        IndependentAuthority::initialize_storage(
            &storage,
            &installation,
            &bootstrap,
            &settings.installed_members[&id].verifier,
        )
        .unwrap();
        let service = IndependentAuthority::open_existing_replicated(
            storage.clone(),
            installation.clone(),
            Arc::new(AuthoritySigner::new(
                LiveGenerationSigner::install(
                    GenerationSigner::from_pkcs8(certificate.clone(), &operational.serialize_der())
                        .unwrap(),
                    live_owners[id as usize - 1].clone(),
                )
                .unwrap(),
            )),
            id,
            settings.clone(),
            router.clone(),
            kasumi_raft::Config {
                heartbeat_interval: 30,
                election_timeout_min: 100,
                election_timeout_max: 180,
                ..Default::default()
            },
            crate::authority_runtime::request_budget(&physical.admission).unwrap(),
            physical.admission.snapshot_buffer_owner().unwrap(),
        )
        .await
        .unwrap();
        router.register(
            "independent-authority".into(),
            id,
            service.raft_group().raft().clone(),
        );
        services.push(service);
        stores.push(storage);
    }
    services[0].initialize().await.unwrap();
    let leader = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for service in &services {
                let metric = service.raft_group().raft().metrics().borrow().clone();
                if metric.current_leader == Some(metric.id)
                    && matches!(
                        tokio::time::timeout(
                            Duration::from_millis(250),
                            service.raft_group().linearizable_barrier(),
                        )
                        .await,
                        Ok(Ok(_))
                    )
                {
                    return service.clone();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        let progress = services
            .iter()
            .map(|service| {
                let metric = service.raft_group().raft().metrics().borrow().clone();
                format!(
                    "id={} leader={:?} term={} state={:?} applied={:?} running={:?}",
                    metric.id,
                    metric.current_leader,
                    metric.current_term,
                    metric.state,
                    metric.last_applied,
                    metric.running_state,
                )
            })
            .collect::<Vec<_>>();
        panic!("pinned issuer quorum did not become linearizable: {progress:?}")
    });
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://localhost:{}", socket.local_addr().unwrap().port());
    let server_pin = server_identity.certificate_pin();
    let tls = kasumi_transport::server_config(
        &server_identity,
        ClientAuthentication::Required {
            trusted_ca_pem: ca.as_bytes(),
        },
    )
    .unwrap();
    let routes = tonic::service::Routes::new(
        NativeAuthority::new(leader.clone(), auth.clone())
            .with_signer_verifier(
                installed_verifiers[leader.raft_group().raft().metrics().borrow().id as usize - 1]
                    .clone(),
            )
            .with_operational_signer_file(signer_file.clone())
            .service(),
    )
    .into_axum_router();

    // Arm only for the command below. The handler finishes and its response
    // body is consumed before the fixture returns a retryable wire failure.
    let effect_gate_armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let first_effects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let first_response_ready = Arc::new(tokio::sync::Notify::new());
    let release_first_response = Arc::new(tokio::sync::Notify::new());
    let routes = routes.layer(axum::middleware::from_fn({
        let armed = effect_gate_armed.clone();
        let effects = first_effects.clone();
        let ready = first_response_ready.clone();
        let release = release_first_response.clone();
        move |request: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| {
            let armed = armed.clone();
            let effects = effects.clone();
            let ready = ready.clone();
            let release = release.clone();
            async move {
                if request.uri().path() != "/kasumi.v1.KasumiAuthority/Execute" {
                    return next.run(request).await;
                }
                effects.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if !armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    return next.run(request).await;
                }
                let response = next.run(request).await;
                axum::body::to_bytes(response.into_body(), 1 << 20)
                    .await
                    .unwrap();
                ready.notify_one();
                release.notified().await;
                axum::http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .header("grpc-status", "14")
                    .body(axum::body::Body::empty())
                    .unwrap()
            }
        }
    }));
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(crate::tls::serve_tls(
        socket,
        tls,
        routes,
        crate::tls::ListenerLimits::default(),
        audit.clone(),
        stopped,
    ));
    let nodes: BTreeSet<_> = identities
        .iter()
        .enumerate()
        .map(|(index, identity)| NodeIdentity {
            node_id: index as u64 + 1,
            verifier: if index == 0 {
                trust.verifier_identity().unwrap()
            } else {
                kasumi_serving::TrustVerifierIdentity {
                    installation_id: verifier_installation,
                    node_id: index as u64 + 1,
                }
            },
            principal: format!("node-{}", index + 1),
            certificate_sha256: hex::encode(identity.certificate_pin()),
        })
        .collect();
    let config = KasumiClientConfig {
        endpoint: endpoint.clone(),
        identity: identities.remove(0),
        trusted_ca_pem: ca.as_bytes().to_vec(),
        server_certificate_pins: BTreeSet::from([server_pin]),
    };
    let mut client = KasumiAuthorityClient::connect(&config, trust.clone())
        .await
        .unwrap();
    let key = jsonwebtoken::EncodingKey::from_ed_pem(issuer.serialize_pem().as_bytes()).unwrap();
    let token = |principal: &str, scopes: &str| {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some("identity-key".into());
        header.typ = Some("at+jwt".into());
        let now = kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            / 1000;
        jsonwebtoken::encode(&header, &json!({"sub":principal,"tenant":installation.tenant(),"kasumi_resource":{"kind":"authority","authority_id":installation.manifest.authority_id,"partition":installation.partition},"scope":scopes,"iss":"https://identity.example","aud":"https://authority.example","exp":now+300}), &key).unwrap()
    };
    let admin = token("operator", "kasumi:admin");
    use kasumi_serving::{
        AuthorityMaintenancePhase, AuthorityMaintenanceRequest as Maintenance,
        AuthorityMaintenanceResponse as MaintenanceReply,
    };
    let current = client
        .maintenance(&admin, &Maintenance::Configuration)
        .await
        .unwrap();
    let MaintenanceReply::Configuration { configuration } = current else {
        panic!("configuration response expected")
    };
    assert_eq!(configuration.membership.voters, BTreeSet::from([1, 2, 3]));
    let maintenance = kasumi_serving::AuthorityMaintenanceCommand {
        operation_id: uuid::Uuid::new_v4(),
        expected_policy_epoch: configuration.policy_epoch,
        expected_operational_revision: configuration.revision,
        not_after_ms: kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            + 60_000,
        action: kasumi_serving::AuthorityMaintenanceAction::RevokeMember { node_id: 1 },
    };
    let rejected = client
        .maintenance(
            &admin,
            &Maintenance::Start {
                command: maintenance.clone(),
            },
        )
        .await
        .unwrap();
    assert!(
        matches!(&rejected, MaintenanceReply::Operation {status} if matches!(status.phase, AuthorityMaintenancePhase::Rejected { .. }))
    );
    assert_eq!(
        client
            .maintenance(
                &admin,
                &Maintenance::Status {
                    operation_id: maintenance.operation_id
                }
            )
            .await
            .unwrap(),
        rejected
    );
    assert_eq!(
        client
            .maintenance(
                &admin,
                &Maintenance::Resume {
                    operation_id: maintenance.operation_id
                }
            )
            .await
            .unwrap(),
        rejected
    );
    assert!(
        client
            .maintenance(
                &token("intruder", "kasumi:admin"),
                &Maintenance::Configuration
            )
            .await
            .is_err()
    );
    let incarnation = uuid::Uuid::new_v4();
    let command = AuthorityCommand {
        tenant: "city".into(),
        command_id: uuid::Uuid::new_v4(),
        expected_policy_epoch: 1,
        not_after_ms: kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            + 60_000,
        action: AuthorityAction::Enroll {
            incarnation,
            nodes: nodes.clone(),
        },
    };

    // The second installed route reaches the same real authority, but its
    // first receipt read is deliberately one stale/absent observation. This
    // models the interval after an accepted effect and before its receipt is
    // visible at the selected observation point. Absence never permits replay.
    let shadow_socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut shadow_config = config.clone();
    shadow_config.endpoint = format!(
        "https://localhost:{}",
        shadow_socket.local_addr().unwrap().port()
    );
    let shadow_tls = kasumi_transport::server_config(
        &server_identity,
        ClientAuthentication::Required {
            trusted_ca_pem: ca.as_bytes(),
        },
    )
    .unwrap();
    let shadow_absence = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let absent_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let shadow_effects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let shadow_routes = tonic::service::Routes::new(
        NativeAuthority::new(leader.clone(), auth.clone())
            .with_signer_verifier(
                installed_verifiers[leader.raft_group().raft().metrics().borrow().id as usize - 1]
                    .clone(),
            )
            .with_operational_signer_file(signer_file.clone())
            .service(),
    )
    .into_axum_router()
    .layer(axum::middleware::from_fn({
        let stale = shadow_absence.clone();
        let reads = absent_reads.clone();
        let effects = shadow_effects.clone();
        move |request: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| {
            let stale = stale.clone();
            let reads = reads.clone();
            let effects = effects.clone();
            async move {
                let receipt = request.uri().path() == "/kasumi.v1.KasumiAuthority/Receipt";
                let execute = request.uri().path() == "/kasumi.v1.KasumiAuthority/Execute";
                if receipt && stale.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let payload = kasumi_client::proto::AuthorityJsonResponse {
                        response_json: b"null".to_vec(),
                    };
                    let encoded = prost::Message::encode_to_vec(&payload);
                    let mut framed = vec![0u8];
                    framed.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
                    framed.extend_from_slice(&encoded);
                    return axum::http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .header("grpc-status", "0")
                        .body(axum::body::Body::from(framed))
                        .unwrap();
                }
                if execute {
                    effects.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                next.run(request).await
            }
        }
    }));
    let (shadow_stop, shadow_stopped) = tokio::sync::watch::channel(false);
    let shadow_task = tokio::spawn(crate::tls::serve_tls(
        shadow_socket,
        shadow_tls,
        shadow_routes,
        crate::tls::ListenerLimits::default(),
        audit.clone(),
        shadow_stopped,
    ));
    // Verify that the injected gRPC frame really decodes as a missing exact
    // receipt; otherwise a transport error could let an unfixed pool pass.
    let mut shadow_probe = KasumiAuthorityClient::connect(&shadow_config, trust.clone())
        .await
        .unwrap();
    assert!(
        shadow_probe
            .receipt(&admin, &command.tenant, command.command_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(absent_reads.load(std::sync::atomic::Ordering::SeqCst), 1);
    absent_reads.store(0, std::sync::atomic::Ordering::SeqCst);
    shadow_absence.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(shadow_probe);
    let credential = admin.clone();
    let mut effect_pool = kasumi_client::KasumiAuthorityPool::new(
        BTreeMap::from([(1, config.clone()), (2, shadow_config)]),
        trust.clone(),
        Arc::new(move || Ok(zeroize::Zeroizing::new(credential.clone()))),
    )
    .unwrap();
    first_effects.store(0, std::sync::atomic::Ordering::SeqCst);
    effect_gate_armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let original_command = command.clone();
    let pending = tokio::spawn(async move {
        effect_pool
            .execute(&original_command, Duration::from_secs(20))
            .await
    });
    tokio::time::timeout(Duration::from_secs(30), first_response_ready.notified())
        .await
        .expect("the first real authority effect must finish before its response is gated");
    // Once the real handler completed, release a retryable failure promptly.
    // The second member's absent receipt is now reachable inside the original
    // deadline, so the test can require that observation without timing luck.
    release_first_response.notify_one();
    let outcome = tokio::time::timeout(Duration::from_secs(30), pending)
        .await
        .expect("the original invocation must retain its finite deadline")
        .unwrap();
    match outcome {
        Ok(receipt) => assert_eq!(receipt.receipt.command, command),
        Err(kasumi_client::ClientError::Transport(status)) => {
            assert_eq!(status.code(), tonic::Code::Unavailable);
            let detail: kasumi_types::Error = serde_json::from_slice(status.details()).unwrap();
            assert_eq!(detail.code, kasumi_types::ErrorCode::UnknownOutcome);
        }
        Err(other) => panic!("ambiguous effect returned a definite error: {other}"),
    }
    let exact = client
        .receipt(&admin, &command.tenant, command.command_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exact.receipt.command, command);
    assert_eq!(first_effects.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(absent_reads.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        shadow_effects.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an absent exact receipt after ambiguity cannot authorize a second Execute"
    );
    let enrolled = client.execute(&admin, &command).await.unwrap();
    assert!(matches!(
        enrolled.receipt.outcome,
        AuthorityOutcome::Enrolled { .. }
    ));
    let discovery = LeaseDiscovery {
        tenant: "city".into(),
        incarnation,
        node: nodes.first().unwrap().clone(),
        purpose: LeasePurpose::Serving,
    };
    let node_token = token("node-1", "kasumi:read");
    let identity = client
        .discover_lease(&node_token, &discovery)
        .await
        .unwrap();
    let boot = ServingBoot::new(trust.clone(), identity).unwrap();
    let attempt = boot.begin_acquisition().unwrap();
    let lease = client.acquire_lease(&node_token, &attempt).await.unwrap();
    let gate = ServingGate::new(lease).unwrap();
    gate.check_serving().unwrap();
    assert!(
        client
            .acquire_lease(
                &token("node-2", "kasumi:read"),
                &boot.begin_acquisition().unwrap()
            )
            .await
            .is_err()
    );
    let follower = services
        .iter()
        .find(|service| !Arc::ptr_eq(service, &leader))
        .unwrap()
        .clone();
    let follower_socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let follower_endpoint = format!(
        "https://localhost:{}",
        follower_socket.local_addr().unwrap().port()
    );
    let follower_tls = kasumi_transport::server_config(
        &server_identity,
        ClientAuthentication::Required {
            trusted_ca_pem: ca.as_bytes(),
        },
    )
    .unwrap();
    let (follower_stop, follower_stopped) = tokio::sync::watch::channel(false);
    let follower_task = tokio::spawn(crate::tls::serve_tls(
        follower_socket,
        follower_tls,
        tonic::service::Routes::new(
            NativeAuthority::new(follower.clone(), auth.clone())
                .with_signer_verifier(
                    installed_verifiers
                        [follower.raft_group().raft().metrics().borrow().id as usize - 1]
                        .clone(),
                )
                .service(),
        )
        .into_axum_router(),
        crate::tls::ListenerLimits::default(),
        audit.clone(),
        follower_stopped,
    ));
    // An unreachable installed member cannot prevent discovery or acquisition
    // from the approved live member, and no retry regenerates a lease attempt.
    let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let absent_endpoint = format!("https://localhost:{}", unused.local_addr().unwrap().port());
    drop(unused);
    let mut absent = config.clone();
    absent.endpoint = absent_endpoint;
    let mut follower_config = config.clone();
    follower_config.endpoint = follower_endpoint;
    let current_credential = Arc::new(std::sync::RwLock::new(node_token.clone()));
    let source = current_credential.clone();
    let credential_loads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let loads = credential_loads.clone();
    let mut pool = kasumi_client::KasumiAuthorityPool::new(
        BTreeMap::from([(1, follower_config), (2, absent), (3, config.clone())]),
        trust.clone(),
        Arc::new(move || {
            let snapshot = source.read().unwrap().clone();
            if loads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                // A renewal published while failover is in flight must not
                // replace this request's already selected credential.
                *source.write().unwrap() = "invalid-replacement".into();
            }
            Ok(zeroize::Zeroizing::new(snapshot))
        }),
    )
    .unwrap();
    let discovered = pool
        .discover_lease(&discovery, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(&discovered, boot.identity());
    assert_eq!(
        credential_loads.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert!(
        pool.discover_lease(&discovery, Duration::from_secs(2))
            .await
            .is_err()
    );
    assert_eq!(
        credential_loads.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    *current_credential.write().unwrap() = node_token.clone();
    let original = boot.begin_acquisition().unwrap();
    let acquired = pool
        .acquire_lease(&original, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(acquired.remaining().unwrap() <= Duration::from_secs(1));
    *current_credential.write().unwrap() = admin.clone();
    assert_eq!(
        pool.execute(&command, Duration::from_secs(2))
            .await
            .unwrap()
            .receipt
            .command,
        command
    );
    *current_credential.write().unwrap() = "invalid".into();
    assert!(
        pool.discover_lease(&discovery, Duration::from_secs(2))
            .await
            .is_err()
    );
    *current_credential.write().unwrap() = node_token.clone();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        pool.acquire_lease(&original, Duration::from_secs(1))
            .await
            .is_err()
    );
    assert!(acquired.remaining().is_err());

    let other_config = KasumiClientConfig {
        endpoint,
        identity: identities.remove(0),
        trusted_ca_pem: ca.as_bytes().to_vec(),
        server_certificate_pins: BTreeSet::from([server_pin]),
    };
    let mut other = KasumiAuthorityClient::connect(&other_config, trust.clone())
        .await
        .unwrap();
    assert!(other.discover_lease(&node_token, &discovery).await.is_err());
    // This tests actual issuer stop authority. The administrative checkpoint
    // fixture is not a claim that application backup materialization occurred.
    let target = RecoveryTarget {
        incarnation: uuid::Uuid::new_v4(),
        nodes: nodes.clone(),
        checkpoint: kasumi_types::FullBackupCheckpoint {
            tenant: "city".into(),
            source_incarnation: incarnation.to_string(),
            revision: 1,
            resident_sha256: "1".repeat(64),
            backup_id: uuid::Uuid::new_v4(),
            manifest_ciphertext_sha256: "2".repeat(64),
            key_lineage_digest: "3".repeat(64),
        },
    };
    let mut target_stop = command.clone();
    target_stop.command_id = uuid::Uuid::new_v4();
    target_stop.action = AuthorityAction::StopTarget {
        source_incarnation: incarnation,
        source_epoch: 1,
        target: target.clone(),
    };
    let stopped = client.execute(&admin, &target_stop).await.unwrap();
    let stop_ref = TargetStopReference {
        tenant: "city".into(),
        command_id: target_stop.command_id,
        receipt_digest: stopped.receipt.digest().unwrap(),
    };
    assert!(client.verify_target_stop(&admin, &stop_ref).await.is_err());
    assert!(
        client
            .verify_target_stop(&node_token, &stop_ref)
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let proof = client.verify_target_stop(&admin, &stop_ref).await.unwrap();
    assert_eq!(proof.target(), &target);
    let mut wrong_ref = stop_ref.clone();
    wrong_ref.receipt_digest = "0".repeat(64);
    assert!(client.verify_target_stop(&admin, &wrong_ref).await.is_err());
    let mut replacement = command.clone();
    replacement.command_id = uuid::Uuid::new_v4();
    replacement.action = AuthorityAction::ReplaceAdministrators {
        administrators: BTreeSet::from(["custodian".into()]),
    };
    assert!(client.execute(&admin, &replacement).await.is_err());
    assert!(
        client
            .receipt(&admin, "city", replacement.command_id)
            .await
            .is_err()
    );
    let recovered = client
        .receipt(
            &token("custodian", "kasumi:admin"),
            "city",
            replacement.command_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.receipt.command, replacement);
    assert!(matches!(
        recovered.receipt.outcome,
        AuthorityOutcome::AdministratorsReplaced { policy_epoch: 2 }
    ));
    assert!(client.verify_target_stop(&admin, &stop_ref).await.is_err());
    assert_eq!(
        client
            .verify_target_stop(&token("custodian", "kasumi:admin"), &stop_ref)
            .await
            .unwrap()
            .target(),
        &target
    );

    let attempt = boot.begin_acquisition().unwrap();
    let fresh = client.acquire_lease(&node_token, &attempt).await.unwrap();
    let retained = ServingGate::new(fresh).unwrap().capture().unwrap();
    let node_context = auth
        .authenticate(&format!("Bearer {node_token}"))
        .await
        .unwrap();
    let (_, source_response) = leader
        .acquire(
            kasumi_authority::AuthenticatedNode::from_verified_transport(
                node_context,
                boot.identity().node.certificate_sha256.clone(),
            )
            .unwrap(),
            attempt.request().clone(),
        )
        .await
        .unwrap();
    let maintenance_context = auth
        .authenticate(&format!("Bearer {}", token("custodian", "kasumi:admin")))
        .await
        .unwrap();
    let transition = |owner: &Arc<LiveSignerTrust>| {
        let stage = SignerTrustCommand {
            operation_id: uuid::Uuid::new_v4(),
            expected_revision: owner.current().unwrap().revision,
            not_after_ms: u64::MAX,
            action: SignerTrustAction::Stage {
                certificate: next_certificate.clone(),
            },
        };
        owner
            .administer(&maintenance_context, stage.clone())
            .unwrap();
        let activate = SignerTrustCommand {
            operation_id: uuid::Uuid::new_v4(),
            expected_revision: owner.current().unwrap().revision,
            not_after_ms: u64::MAX,
            action: SignerTrustAction::Activate {
                staged_operation_id: stage.operation_id,
                certificate_sha256: next_certificate.digest().unwrap(),
            },
        };
        owner.administer(&maintenance_context, activate).unwrap();
    };
    let local_owner = &live_owners[leader.raft_group().raft().metrics().borrow().id as usize - 1];
    let local_identity = local_owner.current().unwrap().verifier;
    let signer_request = |action| SignerVerifierRequest {
        observation_id: uuid::Uuid::new_v4(),
        verifier: local_identity.clone(),
        domain_sha256: domain.digest().unwrap(),
        action,
    };
    let operator = token("custodian", "kasumi:admin");
    let observe = signer_request(SignerVerifierAction::Observe);
    assert!(client.signer_maintenance(&admin, &observe).await.is_err());
    assert!(
        client
            .signer_maintenance(&node_token, &observe)
            .await
            .is_err()
    );
    let observed = client
        .signer_maintenance(&operator, &observe)
        .await
        .unwrap();
    assert_eq!(observed.current.active.identity.generation, 1);
    assert!(
        observed
            .validate_for(&signer_request(SignerVerifierAction::Observe), &domain)
            .is_err()
    );
    let mut wrong_verifier = observe.clone();
    wrong_verifier.verifier.node_id = 4;
    assert!(
        client
            .signer_maintenance(&operator, &wrong_verifier)
            .await
            .is_err()
    );
    let initial_reload = signer_request(SignerVerifierAction::ReloadOperationalSigner {
        expected_revision: 0,
        certificate_sha256: certificate.digest().unwrap(),
        not_after_ms: kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            + 60_000,
    });
    assert_eq!(
        client
            .signer_maintenance(&operator, &initial_reload)
            .await
            .unwrap()
            .loaded_certificate,
        Some(certificate.clone())
    );
    kasumi_store::private_files::replace(&signer_file, b"{").unwrap();
    assert!(
        client
            .signer_maintenance(&operator, &initial_reload)
            .await
            .is_err()
    );
    source_response.check().unwrap();
    client
        .acquire_lease(&node_token, &boot.begin_acquisition().unwrap())
        .await
        .unwrap();
    publish_source(&certificate, &old_key_file);
    let deadline = kasumi_clock::EpochClock::system()
        .unwrap()
        .now_ms()
        .unwrap()
        + 60_000;
    let global_request = |action| AuthoritySigningRequest {
        observation_id: uuid::Uuid::new_v4(),
        domain_sha256: domain.digest().unwrap(),
        action,
    };
    let mut verifier_set: BTreeSet<_> = settings
        .installed_members
        .values()
        .map(|member| member.verifier.clone())
        .collect();
    verifier_set.extend(nodes.iter().map(|node| node.verifier.clone()));
    for (index, verifier) in verifier_set.into_iter().enumerate() {
        let current = client
            .signing_maintenance(&operator, &global_request(AuthoritySigningAction::Observe))
            .await
            .unwrap();
        let command = AuthorityMaintenanceCommand {
            operation_id: uuid::Uuid::new_v4(),
            expected_policy_epoch: current.policy_epoch,
            expected_operational_revision: current.operational_revision,
            not_after_ms: deadline,
            action: AuthorityMaintenanceAction::EnrollSignerVerifier {
                enrollment: kasumi_serving::SignerVerifierEnrollment {
                    endpoint: if verifier == local_identity {
                        format!("{}/", config.endpoint)
                    } else {
                        format!("https://verifier-admin-{index}.test/")
                    },
                    certificate_pins: if verifier == local_identity {
                        BTreeSet::from([hex::encode(server_pin)])
                    } else {
                        BTreeSet::from([format!("{:064x}", 1000 + index)])
                    },
                    verifier,
                },
            },
        };
        let start = global_request(AuthoritySigningAction::Start {
            command: command.clone(),
        });
        let registered = match client.signing_maintenance(&operator, &start).await {
            Ok(response) => response,
            Err(kasumi_client::ClientError::Transport(status))
                if status.code() == tonic::Code::Unavailable
                    && serde_json::from_slice::<kasumi_types::Error>(status.details())
                        .is_ok_and(|detail| {
                            detail.code == kasumi_types::ErrorCode::UnknownOutcome
                        }) =>
            {
                // Start may have committed even when its acknowledgement was lost.
                // Resolve only this command on the original pinned endpoint.
                loop {
                    let receipt = global_request(AuthoritySigningAction::Receipt {
                        operation_id: command.operation_id,
                    });
                    let resolved = client
                        .signing_maintenance(&operator, &receipt)
                        .await
                        .expect(
                            "the exact enrollment receipt must resolve on the pinned authority",
                        );
                    if resolved.status.is_some() {
                        break resolved;
                    }
                    assert!(
                        kasumi_clock::EpochClock::system()
                            .unwrap()
                            .now_ms()
                            .unwrap()
                            < deadline,
                        "exact enrollment receipt remained absent at the original command deadline"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            Err(error) => panic!("global signer enrollment failed definitively: {error:?}"),
        };
        let status = registered
            .status
            .expect("global signer enrollment has no exact committed receipt");
        assert_eq!(status.command, command, "enrollment receipt changed input");
        assert_eq!(
            status.command_sha256,
            command.digest().unwrap(),
            "enrollment receipt changed command bytes"
        );
        assert_eq!(status.phase, AuthorityMaintenancePhase::Completed);
    }
    let global = client
        .signing_maintenance(&operator, &global_request(AuthoritySigningAction::Observe))
        .await
        .unwrap();
    let global_stage = AuthorityMaintenanceCommand {
        operation_id: uuid::Uuid::new_v4(),
        expected_policy_epoch: global.policy_epoch,
        expected_operational_revision: global.operational_revision,
        not_after_ms: deadline,
        action: AuthorityMaintenanceAction::StageSignerGeneration {
            certificate: next_certificate.clone(),
        },
    };
    let staged_global = client
        .signing_maintenance(
            &operator,
            &global_request(AuthoritySigningAction::Start {
                command: global_stage.clone(),
            }),
        )
        .await
        .unwrap();
    assert_eq!(staged_global.current.active.identity.generation, 1);
    assert_eq!(
        staged_global.status.unwrap().phase,
        AuthorityMaintenancePhase::Completed
    );
    // The operation's immutable admission deadline survives waiting for local
    // metadata ownership and a fresh credential on a later request.
    let queued = signer_request(SignerVerifierAction::Administer {
        command: SignerTrustCommand {
            operation_id: uuid::Uuid::new_v4(),
            expected_revision: 0,
            not_after_ms: kasumi_clock::EpochClock::system()
                .unwrap()
                .now_ms()
                .unwrap()
                + 30,
            action: SignerTrustAction::Stage {
                certificate: next_certificate.clone(),
            },
        },
    });
    let context = auth
        .authenticate(&format!("Bearer {operator}"))
        .await
        .unwrap();
    let held_fence = leader.authorize_signer_maintenance(context).await.unwrap();
    let local_installed = &installed_verifiers[local_identity.node_id as usize - 1];
    let (_, held_scope) = local_installed
        .authorize(&observe, held_fence, &domain)
        .await
        .unwrap();
    let task = {
        let mut client = client.clone();
        let bearer = operator.clone();
        let request = queued.clone();
        tokio::spawn(async move { client.signer_maintenance(&bearer, &request).await })
    };
    tokio::time::sleep(Duration::from_millis(75)).await;
    drop(held_scope);
    assert!(task.await.unwrap().is_err());
    assert!(
        client
            .signer_maintenance(&token("custodian", "kasumi:admin"), &queued)
            .await
            .is_err()
    );
    let SignerVerifierAction::Administer { command: expired } = &queued.action else {
        unreachable!()
    };
    let absent = client
        .signer_maintenance(
            &operator,
            &signer_request(SignerVerifierAction::Receipt {
                operation_id: expired.operation_id,
            }),
        )
        .await
        .unwrap();
    assert!(absent.receipt.is_none() && absent.authorization.is_none());
    assert_eq!(absent.current.revision, 0);
    let stage = SignerTrustCommand {
        operation_id: uuid::Uuid::new_v4(),
        expected_revision: 0,
        not_after_ms: deadline,
        action: SignerTrustAction::Stage {
            certificate: next_certificate.clone(),
        },
    };
    let staged_request = signer_request(SignerVerifierAction::Administer {
        command: stage.clone(),
    });
    let staged = client
        .signer_maintenance(&operator, &staged_request)
        .await
        .unwrap();
    assert_eq!(staged.current.active.identity.generation, 1);
    assert_eq!(
        staged.current.staged.as_ref().unwrap().operation_id,
        stage.operation_id
    );
    assert_eq!(
        client
            .signer_maintenance(&operator, &staged_request)
            .await
            .unwrap()
            .receipt,
        staged.receipt
    );
    // Publishing a root-certified file does not activate it. The rejected
    // reload leaves the live generation-one signer intact. The global stage has
    // independently closed the old source lease response.
    publish_source(&next_certificate, &next_key_file);
    assert!(
        client
            .signer_maintenance(
                &operator,
                &signer_request(SignerVerifierAction::ReloadOperationalSigner {
                    expected_revision: 1,
                    certificate_sha256: next_certificate.digest().unwrap(),
                    not_after_ms: deadline,
                })
            )
            .await
            .is_err()
    );
    assert_eq!(local_owner.current().unwrap().active, certificate);
    assert!(source_response.check().is_err());
    let mut different = stage.clone();
    different.not_after_ms -= 1;
    assert!(
        client
            .signer_maintenance(
                &operator,
                &signer_request(SignerVerifierAction::Administer { command: different })
            )
            .await
            .is_err()
    );
    let activation = SignerTrustCommand {
        operation_id: uuid::Uuid::new_v4(),
        expected_revision: 1,
        not_after_ms: deadline,
        action: SignerTrustAction::Activate {
            staged_operation_id: stage.operation_id,
            certificate_sha256: next_certificate.digest().unwrap(),
        },
    };
    let abort_stage = signer_request(SignerVerifierAction::Administer {
        command: SignerTrustCommand {
            operation_id: uuid::Uuid::new_v4(),
            expected_revision: 1,
            not_after_ms: deadline,
            action: SignerTrustAction::StopStage {
                staged_operation_id: stage.operation_id,
            },
        },
    });
    assert!(
        client
            .signer_maintenance(&operator, &abort_stage)
            .await
            .is_err()
    );
    assert!(
        client
            .signer_maintenance(
                &operator,
                &signer_request(SignerVerifierAction::Administer {
                    command: activation.clone(),
                })
            )
            .await
            .is_err(),
        "local publication cannot precede the committed global winner"
    );
    assert_eq!(local_owner.current().unwrap(), staged.current);
    transition(&live_owners[3]);
    assert!(
        retained.check().is_err(),
        "receiver activation fences retained TLS replies immediately"
    );
    assert!(
        client
            .acquire_lease(&node_token, &boot.begin_acquisition().unwrap())
            .await
            .is_err(),
        "still-running retired issuer cannot mint a fresh live lease"
    );
    let global = client
        .signing_maintenance(&operator, &global_request(AuthoritySigningAction::Observe))
        .await
        .unwrap();
    let global_activation = global_request(AuthoritySigningAction::Start {
        command: AuthorityMaintenanceCommand {
            operation_id: uuid::Uuid::new_v4(),
            expected_policy_epoch: global.policy_epoch,
            expected_operational_revision: global.operational_revision,
            not_after_ms: deadline,
            action: AuthorityMaintenanceAction::ActivateSignerGeneration {
                stage_operation_id: global_stage.operation_id,
                certificate_sha256: next_certificate.digest().unwrap(),
            },
        },
    });
    let global_activated = client
        .signing_maintenance(&operator, &global_activation)
        .await
        .unwrap();
    assert_eq!(global_activated.current.active.identity.generation, 2);
    assert_eq!(local_owner.current().unwrap().active.identity.generation, 1);
    assert!(
        source_response.check().is_err(),
        "consensus seals the unchanged local issuer generation"
    );
    assert_eq!(
        client
            .signing_maintenance(&operator, &global_activation)
            .await
            .unwrap(),
        global_activated
    );
    assert!(
        client
            .signer_maintenance(&operator, &abort_stage)
            .await
            .is_err()
    );
    assert_eq!(
        local_owner.current().unwrap(),
        staged.current,
        "an issuer-local abort cannot undo the committed global winner"
    );
    let publication_bearer = signer_directory.join("publication.bearer");
    kasumi_store::private_files::create(&publication_bearer, operator.as_bytes()).unwrap();
    let publication_transport = Arc::new(CoverageTransport {
        config: config.clone(),
        trust: trust.clone(),
        bearer_file: publication_bearer,
        expire_first: std::sync::atomic::AtomicBool::new(true),
    });
    leader
        .install_signer_publication_transport(publication_transport.clone())
        .unwrap();
    let coverage = SignerCoverageCommand {
        operation_id: uuid::Uuid::new_v4(),
        expected_policy_epoch: global_activated.policy_epoch,
        expected_operational_revision: global_activated.operational_revision,
        not_after_ms: activation.not_after_ms,
        publication: SignerPublicationRequest::Issuer {
            observation_id: uuid::Uuid::new_v4(),
            directive: Box::new(
                IssuerSignerDirective::from_current_head(
                    local_identity.clone(),
                    domain.digest().unwrap(),
                    activation.clone(),
                    &global_activated.current,
                )
                .unwrap(),
            ),
        },
    };
    let started = client
        .signer_coverage(
            &operator,
            &SignerCoverageRequest::Start {
                command: coverage.clone(),
            },
        )
        .await
        .unwrap();
    assert!(started.status.acknowledgment.is_none());
    assert_eq!(local_owner.current().unwrap().active.identity.generation, 1);
    let mut wrong_endpoint = config.clone();
    wrong_endpoint.server_certificate_pins = BTreeSet::from([[7; 32]]);
    assert!(
        kasumi_client::CurrentSignerPublication::observe(
            &wrong_endpoint,
            &operator,
            trust.clone(),
            &started.status.dispatch
        )
        .await
        .is_err()
    );
    let resume = SignerCoverageRequest::Resume {
        operation_id: coverage.operation_id,
    };
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match client.signer_coverage(&operator, &resume).await {
                Err(kasumi_client::ClientError::Transport(status))
                    if matches!(
                        status.code(),
                        tonic::Code::Unknown | tonic::Code::Unavailable
                    ) => {}
                result => panic!(
                    "expected an uncertain response before acknowledging the remote effect: {result:?}"
                ),
            }
            if !publication_transport
                .expire_first
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                break;
            }
            // An earlier connection or finite observation may have failed before
            // reaching the injected expiration. Resolve only this dispatch and
            // its unchanged local command until that boundary was exercised.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(local_owner.current().unwrap().active.identity.generation, 2);
    let uncertain = client
        .signer_coverage(
            &operator,
            &SignerCoverageRequest::Status {
                operation_id: coverage.operation_id,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        uncertain.status, started.status,
        "the immutable dispatch survives lost publication acknowledgment"
    );
    let covered = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match client.signer_coverage(&operator, &resume).await {
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
    let acknowledgment = covered.status.acknowledgment.as_ref().unwrap();
    assert_eq!(
        acknowledgment.publication.receipt().unwrap().command,
        activation
    );
    assert_eq!(covered.status.dispatch, started.status.dispatch);
    assert_eq!(
        client.signer_coverage(&operator, &resume).await.unwrap(),
        covered
    );
    assert!(
        global_activated.current.retirement.is_some(),
        "one physical acknowledgment is not full global retirement"
    );
    let SignerPublicationResponse::Issuer(activated) = &acknowledgment.publication else {
        unreachable!()
    };
    assert_eq!(activated.current.active.identity.generation, 2);
    assert!(activated.current.retirement.is_some());
    assert!(
        source_response.check().is_err(),
        "source release retains its exact signing generation"
    );
    assert!(source_response.release().await.is_err());
    let retirement = SignerTrustCommand {
        operation_id: uuid::Uuid::new_v4(),
        expected_revision: 2,
        not_after_ms: deadline,
        action: SignerTrustAction::CompleteRetirement {
            activation_operation_id: activation.operation_id,
        },
    };
    let retirement_request = signer_request(SignerVerifierAction::Administer {
        command: retirement.clone(),
    });
    // CoverageTransport held the first publication response for the full
    // max-lease interval after the local activation. The configured retirement
    // drain has therefore elapsed before this request reaches the verifier.
    let retired = client
        .signer_maintenance(&operator, &retirement_request)
        .await
        .unwrap();
    assert_eq!(
        client
            .signer_maintenance(&operator, &retirement_request)
            .await
            .unwrap()
            .receipt,
        retired.receipt
    );
    assert!(retired.current.retirement.is_none());
    assert_eq!(retired.current.revision, 3);
    assert!(
        client
            .signing_maintenance(&operator, &global_request(AuthoritySigningAction::Observe))
            .await
            .unwrap()
            .current
            .retirement
            .is_some(),
        "a local retirement receipt cannot complete global retirement"
    );
    let historical = client
        .signer_maintenance(
            &operator,
            &signer_request(SignerVerifierAction::Receipt {
                operation_id: stage.operation_id,
            }),
        )
        .await
        .unwrap();
    assert_eq!(historical.receipt, staged.receipt);
    assert_eq!(historical.current.active.identity.generation, 2);
    // Current quorum policy still governs this channel after the old operational
    // key is sealed. Its old signatures and old administrator JWT cannot reopen it.
    let mut new_admin = command.clone();
    new_admin.command_id = uuid::Uuid::new_v4();
    new_admin.expected_policy_epoch = 2;
    new_admin.action = AuthorityAction::ReplaceAdministrators {
        administrators: BTreeSet::from(["successor".into()]),
    };
    assert!(client.execute(&operator, &new_admin).await.is_err());
    assert!(
        client
            .signer_maintenance(&operator, &observe)
            .await
            .is_err()
    );
    assert_eq!(
        client
            .signer_maintenance(&token("successor", "kasumi:admin"), &observe)
            .await
            .unwrap()
            .current
            .revision,
        3
    );

    // The native adapter reads only its installed descriptor and publishes a
    // currently activated key. Neither malformed files nor a mismatched key
    // replace the old slot or grant live authority to the retired generation.
    let successor = token("successor", "kasumi:admin");
    let reload = signer_request(SignerVerifierAction::ReloadOperationalSigner {
        expected_revision: 3,
        certificate_sha256: next_certificate.digest().unwrap(),
        not_after_ms: deadline,
    });
    kasumi_store::private_files::replace(&signer_file, b"{").unwrap();
    assert!(
        client
            .signer_maintenance(&successor, &reload)
            .await
            .is_err()
    );
    publish_source(&next_certificate, &old_key_file);
    assert!(
        client
            .signer_maintenance(&successor, &reload)
            .await
            .is_err()
    );
    publish_source(&next_certificate, &next_key_file);

    // Waiting for the local serialization slot cannot renew a reload deadline,
    // including when a subsequent invocation presents a renewed credential.
    let expired_reload = signer_request(SignerVerifierAction::ReloadOperationalSigner {
        expected_revision: 3,
        certificate_sha256: next_certificate.digest().unwrap(),
        not_after_ms: kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            + 30,
    });
    let context = auth
        .authenticate(&format!("Bearer {successor}"))
        .await
        .unwrap();
    let held_fence = leader.authorize_signer_maintenance(context).await.unwrap();
    let (_, held_scope) = local_installed
        .authorize(&observe, held_fence, &domain)
        .await
        .unwrap();
    let queued_reload = {
        let mut client = client.clone();
        let bearer = successor.clone();
        let request = expired_reload.clone();
        tokio::spawn(async move { client.signer_maintenance(&bearer, &request).await })
    };
    tokio::time::sleep(Duration::from_millis(75)).await;
    drop(held_scope);
    assert!(queued_reload.await.unwrap().is_err());
    assert!(
        client
            .signer_maintenance(&token("successor", "kasumi:admin"), &expired_reload)
            .await
            .is_err()
    );
    let reloaded = client
        .signer_maintenance(&successor, &reload)
        .await
        .unwrap();
    assert_eq!(reloaded.loaded_certificate, Some(next_certificate.clone()));
    assert!(reloaded.authorization.is_none() && reloaded.receipt.is_none());
    assert_eq!(
        client
            .signer_maintenance(&successor, &reload)
            .await
            .unwrap(),
        reloaded
    );
    // A serialized observation cannot satisfy another request or changed head.
    let mut altered = reload.clone();
    altered.action = SignerVerifierAction::ReloadOperationalSigner {
        expected_revision: 2,
        certificate_sha256: next_certificate.digest().unwrap(),
        not_after_ms: deadline,
    };
    assert!(reloaded.validate_for(&altered, &domain).is_err());
    let mut changed_deadline = reload.clone();
    let SignerVerifierAction::ReloadOperationalSigner { not_after_ms, .. } =
        &mut changed_deadline.action
    else {
        unreachable!()
    };
    *not_after_ms += 1;
    assert!(reloaded.validate_for(&changed_deadline, &domain).is_err());
    assert!(
        client
            .signer_maintenance(&successor, &altered)
            .await
            .is_err()
    );
    assert!(
        source_response.check().is_err(),
        "replacing a key cannot re-sign an already encoded response"
    );
    assert!(source_response.release().await.is_err());
    drop(source_response);
    assert!(retained.check().is_err());
    let fresh_boot = ServingBoot::new(trust.clone(), boot.identity().clone()).unwrap();
    let fresh_attempt = fresh_boot.begin_acquisition().unwrap();
    let fresh_lease = client
        .acquire_lease(&node_token, &fresh_attempt)
        .await
        .unwrap();
    ServingGate::new(fresh_lease)
        .unwrap()
        .check_serving()
        .unwrap();

    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(gate.check_serving().is_err());
    shadow_stop.send_replace(true);
    shadow_task.await.unwrap().unwrap();
    follower_stop.send_replace(true);
    follower_task.await.unwrap().unwrap();
    stop.send_replace(true);
    serving.await.unwrap().unwrap();
    for service in services {
        service.shutdown().await.unwrap();
    }
    for storage in stores {
        storage.shutdown().await.unwrap();
    }
    audit.shutdown().await.unwrap();
    for owner in live_owners {
        owner.close();
    }
    for store in verifier_stores {
        store.shutdown().await.unwrap();
    }
    for installed in installed_verifiers {
        installed.shutdown().await.unwrap();
    }
    audit_node.shutdown().await.unwrap();
    for node in physical_nodes {
        node.shutdown().await.unwrap();
    }
}

struct CurrentFixtureAdministrator {
    authority_id: uuid::Uuid,
}
impl LiveTrustAdministrator for CurrentFixtureAdministrator {
    fn authorize(&self, context: &kasumi_types::RequestContext) -> anyhow::Result<()> {
        context.authorization.check_live()?;
        context
            .authorization
            .require_authority(self.authority_id, 0)?;
        anyhow::ensure!(
            context.principal == "custodian"
                && context.scopes.contains(&kasumi_types::Action::Admin),
            "current fixture administrator required"
        );
        Ok(())
    }
}
