use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kasumi_client::{KasumiClientConfig, KasumiLifecycleClient};
use kasumi_engine::{LifecycleSigner, ReplicaPlacement, ReplicatedBootstrap};
use kasumi_serving::{ControlTrust, digest};
use kasumi_store::{
    NodeStore, StorageAccess, TenantStorageSet, TenantStore, test_utils::LocalKeyProvider,
};
use kasumi_transport::ClientAuthentication;
use kasumi_types::*;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pinned_native_control_signs_actual_quorum_commitments_and_rejects_wrong_resource_and_partition()
 {
    let directory = tempfile::tempdir().unwrap();
    let (ca, server_identity, mut identities) = super::authority_tests::certificates();
    let jwtkey = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let jwks=serde_json::from_value(json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"control-auth","x":URL_SAFE_NO_PAD.encode(jwtkey.public_key_raw())}]})).unwrap();
    let auth = Authenticator::with_test_keys(
        crate::auth::AuthConfig {
            issuer: "https://identity.example".into(),
            audience: "https://control.example".into(),
            source: crate::auth::AuthKeySource::ExternalOAuth {
                jwks_uri: "https://identity.example/keys".into(),
                trusted_ca_pem: None,
            },
            algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
            access_token_types: BTreeSet::from(["at+jwt".into()]),
        },
        jwks,
    )
    .await;
    let audit_store = TenantStore::open(
        NodeStore::open(directory.path().join("audit.redb")).unwrap(),
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
    let incarnation = Uuid::new_v4();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let root = ControlSigningRoot {
        control_incarnation: incarnation,
        public_key: hex::encode(key.public_key_raw()),
    };
    let signer = Arc::new(LifecycleSigner::from_pkcs8(root.clone(), &key.serialize_der()).unwrap());
    let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let issuer_root =
        kasumi_serving::test_utils::FixtureSigningRoot::from_pkcs8(&issuer_key.serialize_der())
            .unwrap();
    let manifest = kasumi_serving::AuthorityManifest {
        authority_id: Uuid::new_v4(),
        lifecycle_controls: BTreeMap::from([(incarnation, root.public_key.clone())]),
        partitions: BTreeMap::from([(
            0,
            kasumi_serving::AuthorityPartition {
                group: "lifecycle-issuer".into(),
                public_key: issuer_root.public_key(),
            },
        )]),
        max_lease_ms: 1000,
        clock_rate_error_ppm: 0,
    };
    let issuer_signing = issuer_root.install(manifest.clone(), 0).unwrap();
    let issuer_signer = issuer_signing.signer;
    let issuer_trust = issuer_signing.trust;
    let partition = manifest.control_partition(0).unwrap();
    let issuer_install = kasumi_authority::AuthorityInstallation {
        manifest: manifest.clone(),
        partition: 0,
    };
    let issuer_router = Arc::new(kasumi_raft::InProcessRouter::default());
    let mut issuers = Vec::new();
    for id in 1..=3 {
        let stores = TenantStorageSet::open(
            NodeStore::open(directory.path().join(format!("issuer-{id}.redb"))).unwrap(),
            issuer_install.tenant(),
            Arc::new(LocalKeyProvider::new([id as u8 + 50; 32])),
            Arc::new(LocalKeyProvider::new([id as u8 + 60; 32])),
            StorageAccess::independent_authority(&manifest, 0).unwrap(),
        )
        .await
        .unwrap();
        let issuer = kasumi_authority::IndependentAuthority::open_replicated(
            stores,
            issuer_install.clone(),
            issuer_signer.clone(),
            id,
            kasumi_authority::AuthorityNodeSettings {
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
            },
            issuer_router.clone(),
            kasumi_raft::Config {
                heartbeat_interval: 30,
                election_timeout_min: 100,
                election_timeout_max: 180,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        issuer_router.register(
            "lifecycle-issuer".into(),
            id,
            issuer.raft_group().raft().clone(),
        );
        issuers.push(issuer);
    }
    issuers[0].initialize().await.unwrap();
    let issuer = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for issuer in &issuers {
                let m = issuer.raft_group().raft().metrics().borrow().clone();
                if m.current_leader == Some(m.id)
                    && issuer.raft_group().linearizable_barrier().await.is_ok()
                {
                    return issuer.clone();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let installation = LifecycleInstallation {
        root: root.clone(),
        generation: 1,
        partitions: BTreeMap::from([(partition.key(), partition.clone())]),
        max_intents: 100,
        max_changes: 10,
        max_state_bytes: 1 << 20,
    };
    let policy = Policy {
        grants: vec![Grant {
            principal: "operator".into(),
            collection: None,
            actions: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        }],
        strict_read_audit: true,
    };
    let bootstrap = ReplicatedBootstrap {
        incarnation: incarnation.to_string(),
        initial_policy: policy.clone(),
        initial_limits: Limits::default(),
        voters: (1..=3)
            .map(|id| {
                (
                    id,
                    ReplicaPlacement {
                        address: format!("control-{id}"),
                        failure_domain: format!("zone-{id}"),
                    },
                )
            })
            .collect(),
    };
    let router = Arc::new(kasumi_raft::InProcessRouter::default());
    let group = format!("__kasumi_control/{incarnation}");
    let mut nodes = Vec::new();
    for id in 1..=3 {
        let stores = TenantStorageSet::open(
            NodeStore::open(directory.path().join(format!("node-{id}.redb"))).unwrap(),
            "__kasumi_control".into(),
            Arc::new(LocalKeyProvider::new([id as u8; 32])),
            Arc::new(LocalKeyProvider::new([id as u8 + 10; 32])),
            StorageAccess::node_control(),
        )
        .await
        .unwrap();
        let db = kasumi_engine::open_replicated(
            id,
            stores,
            &bootstrap,
            router.clone(),
            kasumi_raft::Config {
                heartbeat_interval: 30,
                election_timeout_min: 100,
                election_timeout_max: 180,
                ..Default::default()
            },
            audit.clone(),
        )
        .await
        .unwrap();
        router.register(group.clone(), id, db.raft_group().raft().clone());
        nodes.push(db);
    }
    kasumi_engine::initialize_replicated(&nodes[0], &bootstrap)
        .await
        .unwrap();
    let leader = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for node in &nodes {
                let metric = node.raft_group().raft().metrics().borrow().clone();
                if metric.current_leader == Some(metric.id)
                    && node.raft_group().linearizable_barrier().await.is_ok()
                {
                    return node.clone();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://localhost:{}", socket.local_addr().unwrap().port());
    let pin = server_identity.certificate_pin();
    let tls = kasumi_transport::server_config(
        &server_identity,
        ClientAuthentication::Required {
            trusted_ca_pem: ca.as_bytes(),
        },
    )
    .unwrap();
    let routes = tonic::service::Routes::new(
        NativeLifecycleControl::new(leader.clone(), signer, auth.clone())
            .unwrap()
            .service(),
    )
    .add_service(NativeAuthority::new(issuer.clone(), auth.clone()).service())
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
    let config = KasumiClientConfig {
        endpoint,
        identity: identities.remove(0),
        trusted_ca_pem: ca.as_bytes().to_vec(),
        server_certificate_pins: BTreeSet::from([pin]),
    };
    let mut client =
        KasumiLifecycleClient::connect(&config, ControlTrust::install(root.clone()).unwrap())
            .await
            .unwrap();
    let encoding =
        jsonwebtoken::EncodingKey::from_ed_pem(jwtkey.serialize_pem().as_bytes()).unwrap();
    let token = |resource: serde_json::Value, scope: &str| {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some("control-auth".into());
        header.typ = Some("at+jwt".into());
        let now = kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            / 1000;
        jsonwebtoken::encode(&header,&json!({"sub":"operator","tenant":"__kasumi_control","kasumi_resource":resource,"scope":scope,"iss":"https://identity.example","aud":"https://control.example","exp":now+300}),&encoding).unwrap()
    };
    let admin = token(
        json!({"kind":"control","incarnation":incarnation}),
        "kasumi:admin",
    );
    let data = token(
        json!({"kind":"database","incarnation":incarnation}),
        "kasumi:admin",
    );
    let readonly = token(
        json!({"kind":"control","incarnation":incarnation}),
        "kasumi:read",
    );
    let install = LifecycleControlCommand::Install {
        command_id: Uuid::new_v4(),
        installation: installation.clone(),
    };
    assert!(client.execute(&data, &install).await.is_err());
    assert!(client.execute(&readonly, &install).await.is_err());
    client.execute(&admin, &install).await.unwrap();
    let epoch = leader.engine().generation().unwrap().state.policy_epoch;
    let source = Uuid::new_v4();
    // Shape-only approved checkpoint fixture: this tests the committed native
    // control signature boundary, not physical backup materialization.
    let intent = CommitLifecycleIntent {
        command_id: Uuid::new_v4(),
        expected_policy_epoch: epoch,
        installation_sha256: digest(&installation).unwrap(),
        authority_partition: partition.key(),
        tenant: "city".into(),
        source_incarnation: source,
        source_authority_epoch: 1,
        target_incarnation: Uuid::new_v4(),
        checkpoint: FullBackupCheckpoint {
            tenant: "city".into(),
            source_incarnation: source.to_string(),
            revision: 123,
            resident_sha256: "12".repeat(32),
            backup_id: Uuid::new_v4(),
            manifest_ciphertext_sha256: "34".repeat(32),
            key_lineage_digest: "56".repeat(32),
        },
        target_nodes: (1..=3)
            .map(|id| {
                (
                    id,
                    LifecycleNode {
                        node_id: id,
                        principal: format!("target-{id}"),
                        attestation_public_key: format!("{:064x}", id + 100),
                        certificate_sha256: if id == 1 {
                            hex::encode(config.identity.certificate_pin())
                        } else {
                            format!("{id:064x}")
                        },
                    },
                )
            })
            .collect(),
        phase: LifecyclePhase::Materialize,
        phase_input_sha256: "ab".repeat(32),
    };
    let receipt = client
        .execute(
            &admin,
            &LifecycleControlCommand::CommitIntent(Box::new(intent.clone())),
        )
        .await
        .unwrap();
    let proof = client
        .observe_intent(&admin, intent.command_id)
        .await
        .unwrap();
    assert_eq!(proof.observation().intent.revision, receipt.revision);
    assert_eq!(proof.observation().intent.request, intent);
    assert!(serde_json::to_vec(proof.signed()).unwrap().len() < 4096);
    assert!(
        client
            .observe_intent(&data, intent.command_id)
            .await
            .is_err()
    );
    assert!(
        client
            .observe_intent(&readonly, intent.command_id)
            .await
            .is_err()
    );
    let request = ReadLifecycleStatus {
        command_id: intent.command_id,
        expected_incarnation: incarnation,
    };
    client.read_status(&admin, &request).await.unwrap();
    assert!(client.read_status(&data, &request).await.is_err());
    let issuer_token = |principal: &str, scope: &str| {
        let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        h.kid = Some("control-auth".into());
        h.typ = Some("at+jwt".into());
        let now = kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            / 1000;
        jsonwebtoken::encode(&h,&json!({"sub":principal,"tenant":issuer_install.tenant(),"kasumi_resource":{"kind":"authority","authority_id":manifest.authority_id,"partition":0},"scope":scope,"iss":"https://identity.example","aud":"https://control.example","exp":now+300}),&encoding).unwrap()
    };
    let authority_admin = issuer_token("operator", "kasumi:admin");
    let node_token = issuer_token("target-1", "kasumi:read");
    let mut authority_client =
        kasumi_client::KasumiAuthorityClient::connect(&config, issuer_trust.clone())
            .await
            .unwrap();
    let target = kasumi_serving::RecoveryTarget {
        incarnation: intent.target_incarnation,
        checkpoint: intent.checkpoint.clone(),
        nodes: intent
            .target_nodes
            .values()
            .map(|n| kasumi_serving::NodeIdentity {
                node_id: n.node_id,
                principal: n.principal.clone(),
                certificate_sha256: n.certificate_sha256.clone(),
            })
            .collect(),
    };
    let authority_command = |action| kasumi_serving::AuthorityCommand {
        tenant: "city".into(),
        command_id: Uuid::new_v4(),
        expected_policy_epoch: 1,
        not_after_ms: kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            + 60000,
        action,
    };
    let native_action = authority_client
        .execute(
            &authority_admin,
            &authority_command(kasumi_serving::AuthorityAction::Enroll {
                incarnation: source,
                nodes: target.nodes.clone(),
            }),
        )
        .await
        .unwrap();
    assert!(
        !matches!(
            native_action.receipt.outcome,
            kasumi_serving::AuthorityOutcome::Rejected { .. }
        ),
        "{:?}",
        native_action.receipt.outcome
    );
    let native_action = authority_client
        .execute(
            &authority_admin,
            &authority_command(kasumi_serving::AuthorityAction::PrepareTarget {
                source_incarnation: source,
                source_epoch: 1,
                target: target.clone(),
            }),
        )
        .await
        .unwrap();
    assert!(
        !matches!(
            native_action.receipt.outcome,
            kasumi_serving::AuthorityOutcome::Rejected { .. }
        ),
        "{:?}",
        native_action.receipt.outcome
    );
    let accept =
        kasumi_serving::LifecycleAuthorityRequest::AcceptIntent(Box::new(proof.signed().clone()));
    assert!(
        authority_client
            .execute_lifecycle(&admin, &accept)
            .await
            .is_err()
    );
    let accepted = authority_client
        .execute_lifecycle(&authority_admin, &accept)
        .await
        .unwrap();
    assert_eq!(accepted.receipt.request_sha256, accept.digest().unwrap());
    let boot = kasumi_serving::LifecycleBoot::new(
        issuer_trust.clone(),
        target
            .nodes
            .iter()
            .find(|n| n.node_id == 1)
            .unwrap()
            .clone(),
    )
    .unwrap();
    let attempt = boot.begin(&proof).unwrap();
    let lease = authority_client
        .acquire_lifecycle(&node_token, &attempt)
        .await
        .unwrap();
    lease.check().unwrap();
    assert!(
        authority_client
            .acquire_lifecycle(&authority_admin, &attempt)
            .await
            .is_err()
    );
    let change = BeginControlPolicyChange {
        command_id: Uuid::new_v4(),
        expected_policy_epoch: epoch,
        installation_sha256: digest(&installation).unwrap(),
        candidate: ControlPolicyCandidate {
            policy,
            retire_control: false,
        },
    };
    client
        .execute(
            &admin,
            &LifecycleControlCommand::BeginPolicyChange(change.clone()),
        )
        .await
        .unwrap();
    assert!(
        client
            .observe_intent(&admin, intent.command_id)
            .await
            .is_err()
    );
    let change_proof = client
        .observe_change(&admin, change.command_id, &partition.key())
        .await
        .unwrap();
    assert_eq!(
        change_proof.observation().stop.change_sha256,
        digest(&change).unwrap()
    );
    assert!(
        client
            .observe_change(&admin, change.command_id, "outside/pinned-set")
            .await
            .is_err()
    );
    assert!(
        client
            .execute(
                &admin,
                &LifecycleControlCommand::CompletePolicyChange(CompleteControlPolicyChange {
                    command_id: change.command_id,
                    change_sha256: digest(&change).unwrap(),
                    stops: BTreeMap::new()
                })
            )
            .await
            .is_err()
    );
    let status = client
        .read_status(
            &admin,
            &ReadLifecycleStatus {
                command_id: change.command_id,
                expected_incarnation: incarnation,
            },
        )
        .await
        .unwrap();
    assert!(
        matches!(status.command,Some(LifecycleCommandStatus::PolicyChange(c)) if c.completed_revision.is_none())
    );
    let stop_request = kasumi_serving::LifecycleAuthorityRequest::StopEpoch(Box::new(
        change_proof.signed().clone(),
    ));
    authority_client
        .execute_lifecycle(&authority_admin, &stop_request)
        .await
        .unwrap();
    assert!(
        authority_client
            .acquire_lifecycle(&node_token, &boot.begin(&proof).unwrap())
            .await
            .is_err()
    );
    assert!(
        authority_client
            .verify_control_stop(&authority_admin, &change_proof.observation().stop)
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(lease.check().is_err());
    let stopped_proof = authority_client
        .verify_control_stop(&authority_admin, &change_proof.observation().stop)
        .await
        .unwrap();
    client
        .execute(
            &admin,
            &LifecycleControlCommand::CompletePolicyChange(CompleteControlPolicyChange {
                command_id: change.command_id,
                change_sha256: digest(&change).unwrap(),
                stops: BTreeMap::from([(partition.key(), stopped_proof)]),
            }),
        )
        .await
        .unwrap();
    assert!(
        client
            .observe_intent(&admin, intent.command_id)
            .await
            .is_err()
    );
    let recovered = authority_client
        .read_lifecycle_receipt(&authority_admin, &accept.reference())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        recovered.receipt.accepted_revision,
        accepted.receipt.accepted_revision
    );
    drop(authority_client);
    for issuer in &issuers {
        issuer.shutdown().await.unwrap();
    }
    stop.send(true).unwrap();
    serving.await.unwrap().unwrap();
    drop(client);
    drop(leader);
    for node in &nodes {
        node.shutdown().await.unwrap();
    }
    nodes.clear();
    audit.shutdown().await;
    audit_store.shutdown().await;
}
