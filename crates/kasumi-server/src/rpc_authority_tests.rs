use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kasumi_authority::{AuthorityInstallation, IndependentAuthority};
use kasumi_client::{KasumiAuthorityClient, KasumiClientConfig};
use kasumi_serving::*;
use kasumi_store::{
    NodeStore, StorageAccess, TenantStorageSet, TenantStore, test_utils::LocalKeyProvider,
};
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

#[tokio::test]
async fn actual_pinned_native_issuer_binds_jwt_peer_attempt_and_current_admin_recovery() {
    let dir = tempfile::tempdir().unwrap();
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
    let audit_node = NodeStore::open(
        dir.path().join("audit.redb"),
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let audit_store = TenantStore::open(
        audit_node,
        kasumi_engine::SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([88; 32])),
        StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    let audit = kasumi_engine::SecurityAudit::open(
        audit_store.clone(),
        kasumi_types::AuditRetentionBudget::default(),
        kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
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
            let config = SignerVerifierConfig {
                identity: verifier,
                database_path: directory.join("trust.redb"),
                keys: crate::runtime::KeyProviderSettings::File { path: keys },
            };
            InitializeSignerVerifier {
                scratch_disk: kasumi_store::ScratchDiskConfig {
                    directory: directory.join("scratch"),
                    max_bytes: 64 << 30,
                    min_free_bytes: 256 << 20,
                },
                verifier: config.clone(),
                initial_certificates: vec![certificate.clone()],
            }
            .initialize()
            .await
            .unwrap();
            let installed = config
                .open(
                    BTreeMap::from([(domain.digest().unwrap(), domain.clone())]),
                    Arc::new(crate::runtime::file_secret),
                    kasumi_store::ScratchDisk::open(kasumi_store::ScratchDiskConfig {
                        directory: directory.join("scratch"),
                        max_bytes: 64 << 30,
                        min_free_bytes: 256 << 20,
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
            live_owners.push(installed.owner(&domain).unwrap());
            installed_verifiers.push(installed);
            continue;
        }
        let store = TenantStore::open(
            NodeStore::open(
                dir.path().join(format!("verifier-{node_id}.redb")),
                kasumi_store::ScratchDisk::fixture(),
            )
            .unwrap(),
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
    let settings = kasumi_authority::AuthorityNodeSettings {
        bootstrap: kasumi_authority::AuthorityBootstrap {
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
        },
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
        let node = NodeStore::open(
            dir.path().join(format!("authority-{id}.redb")),
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let storage = TenantStorageSet::open(
            node,
            installation.tenant(),
            Arc::new(LocalKeyProvider::new([id as u8; 32])),
            Arc::new(LocalKeyProvider::new([id as u8 + 10; 32])),
            StorageAccess::independent_authority(&manifest, 0).unwrap(),
        )
        .await
        .unwrap();
        let service = IndependentAuthority::open_replicated(
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
                    && service.raft_group().linearizable_barrier().await.is_ok()
                {
                    return service.clone();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
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
    let mut pool = kasumi_client::KasumiAuthorityPool::new(
        BTreeMap::from([(1, follower_config), (2, absent), (3, config.clone())]),
        trust.clone(),
        Arc::new(move || Ok(zeroize::Zeroizing::new(source.read().unwrap().clone()))),
    )
    .unwrap();
    let discovered = pool
        .discover_lease(&discovery, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(&discovered, boot.identity());
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
    let deadline = kasumi_clock::EpochClock::system()
        .unwrap()
        .now_ms()
        .unwrap()
        + 60_000;
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
    // reload leaves the live generation-one signer and retained response intact.
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
    source_response.check().unwrap();
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
    let activated = client
        .signer_maintenance(
            &operator,
            &signer_request(SignerVerifierAction::Administer {
                command: activation.clone(),
            }),
        )
        .await
        .unwrap();
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
    assert!(
        client
            .signer_maintenance(&operator, &retirement_request)
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let retired = client
        .signer_maintenance(&operator, &retirement_request)
        .await
        .unwrap();
    assert!(retired.current.retirement.is_none());
    assert_eq!(retired.current.revision, 3);
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
    follower_stop.send_replace(true);
    follower_task.await.unwrap().unwrap();
    stop.send_replace(true);
    serving.await.unwrap().unwrap();
    for service in services {
        service.shutdown().await.unwrap();
    }
    for storage in stores {
        storage.application().shutdown().await;
        storage.custody().store().shutdown().await;
    }
    audit.shutdown().await;
    for owner in live_owners {
        owner.close();
    }
    for store in verifier_stores {
        store.shutdown().await;
    }
    for installed in installed_verifiers {
        installed.shutdown().await;
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
