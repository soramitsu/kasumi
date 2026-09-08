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
    let audit_node = NodeStore::open(dir.path().join("audit.redb")).unwrap();
    let audit_store = TenantStore::open(
        audit_node,
        kasumi_engine::SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([88; 32])),
        StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    let audit = kasumi_engine::SecurityAudit::open(audit_store.clone(), 10_000).unwrap();
    auth.install_audit(audit.clone()).unwrap();
    let signing = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let signer = Arc::new(AuthoritySigner::from_pkcs8(&signing.serialize_der()).unwrap());
    let manifest = AuthorityManifest {
        lifecycle_controls: std::collections::BTreeMap::new(),
        authority_id: uuid::Uuid::new_v4(),
        max_lease_ms: 1000,
        clock_rate_error_ppm: 0,
        partitions: BTreeMap::from([(
            0,
            AuthorityPartition {
                group: "independent-authority".into(),
                public_key: signer.public_key(),
            },
        )]),
    };
    let installation = AuthorityInstallation {
        manifest: manifest.clone(),
        partition: 0,
    };
    let trust = AuthorityTrust::install(manifest.clone()).unwrap();
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
        let node = NodeStore::open(dir.path().join(format!("authority-{id}.redb"))).unwrap();
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
            signer.clone(),
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
    let routes =
        tonic::service::Routes::new(NativeAuthority::new(leader.clone(), auth.clone()).service())
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
        tonic::service::Routes::new(NativeAuthority::new(follower, auth.clone()).service())
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
    let mut other = KasumiAuthorityClient::connect(&other_config, trust)
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
}
