use super::*;
use kasumi_authority::{
    AuthorityBootstrap, AuthorityInstallation, AuthorityNodeSettings, IndependentAuthority,
};
use kasumi_serving::*;
use kasumi_store::{NodeStore, StorageAccess, TenantStorageSet, test_utils::LocalKeyProvider};
use kasumi_types::{Action, CredentialResource, RequestAuthorization, RequestContext};
use tokio::{net::TcpListener, sync::watch};
use uuid::Uuid;

// Explicit audit fixture: this test isolates real pinned peer transport and
// encrypted authority state, not the independent audit archive implementation.
struct TestAudit;
#[async_trait]
impl RequestAuditSink for TestAudit {
    async fn record(&self, _: RequestAuditEvent) -> kasumi_types::Result<()> {
        Ok(())
    }
}
#[async_trait]
impl crate::tls::TlsHandshakeAudit for TestAudit {
    async fn record(&self, _: &crate::tls::TlsHandshakeEvent) -> Result<()> {
        Ok(())
    }
}
fn certificates() -> (String, Vec<TlsIdentity>) {
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
    let identities = (1..=4)
        .map(|_| {
            let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            let key = KeyPair::generate().unwrap();
            let certificate = params.signed_by(&key, &issuer).unwrap();
            TlsIdentity::from_pem(certificate.pem().as_bytes(), key.serialize_pem().as_bytes())
                .unwrap()
        })
        .collect();
    (certificate.pem(), identities)
}
async fn leader(services: &[Arc<IndependentAuthority>]) -> Arc<IndependentAuthority> {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            for service in services {
                let metrics = service.raft_group().raft().metrics().borrow().clone();
                if metrics.current_leader == Some(metrics.id)
                    && service.raft_group().linearizable_barrier().await.is_ok()
                {
                    return service.clone();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}
fn context(installation: &AuthorityInstallation) -> RequestContext {
    let clock = kasumi_clock::EpochClock::system().unwrap();
    RequestContext {
        tenant: installation.tenant(),
        principal: "operator".into(),
        request_id: Uuid::new_v4().to_string(),
        scopes: BTreeSet::from([Action::Admin]),
        authorization: RequestAuthorization::from_verified_credential(
            clock.now_ms().unwrap() + 120_000,
            &clock.observe().unwrap(),
            CredentialResource::Authority {
                authority_id: installation.manifest.authority_id,
                partition: 0,
            },
        )
        .unwrap(),
    }
}
async fn start(
    service: &Arc<IndependentAuthority>,
    action: AuthorityMaintenanceAction,
) -> AuthorityMaintenanceStatus {
    let ctx = context(service.installation());
    let (AuthorityMaintenanceResponse::Configuration { configuration }, fence) = service
        .maintenance(ctx.clone(), AuthorityMaintenanceRequest::Configuration)
        .await
        .unwrap()
    else {
        panic!("configuration expected")
    };
    fence.release().await.unwrap();
    let command = AuthorityMaintenanceCommand {
        operation_id: Uuid::new_v4(),
        expected_policy_epoch: configuration.policy_epoch,
        expected_operational_revision: configuration.revision,
        not_after_ms: kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            + 60_000,
        action,
    };
    let (AuthorityMaintenanceResponse::Operation { status }, fence) = service
        .maintenance(ctx, AuthorityMaintenanceRequest::Start { command })
        .await
        .unwrap()
    else {
        panic!("status expected")
    };
    fence.release().await.unwrap();
    status
}

#[tokio::test]
async fn actual_tls_peer_readiness_enrolls_replaces_and_fences_revoked_member() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, identities) = certificates();
    let mut listeners = Vec::new();
    for _ in 0..4 {
        listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    let members: BTreeMap<_, _> = listeners
        .iter()
        .enumerate()
        .map(|(i, listener)| {
            (
                i as u64 + 1,
                AuthorityMember {
                    verifier: kasumi_serving::test_utils::fixture_verifier(i as u64 + 1),
                    endpoint: format!(
                        "https://localhost:{}",
                        listener.local_addr().unwrap().port()
                    ),
                    failure_domain: format!("domain-{i}"),
                    certificate_pins: BTreeSet::from([hex::encode(
                        identities[i].certificate_pin(),
                    )]),
                },
            )
        })
        .collect();
    let signer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let root =
        kasumi_serving::test_utils::FixtureSigningRoot::from_pkcs8(&signer_key.serialize_der())
            .unwrap();
    let installation = AuthorityInstallation {
        partition: 0,
        manifest: AuthorityManifest {
            authority_id: Uuid::new_v4(),
            lifecycle_controls: BTreeMap::new(),
            max_lease_ms: 1000,
            clock_rate_error_ppm: 0,
            partitions: BTreeMap::from([(
                0,
                AuthorityPartition {
                    group: "authority-maintenance".into(),
                    public_key: root.public_key(),
                },
            )]),
        },
    };
    let signing = root.install(installation.manifest.clone(), 0).unwrap();
    let bootstrap = AuthorityBootstrap {
        initial_signer_certificate: signing.signer.certificate().clone(),
        administrators: BTreeSet::from(["operator".into()]),
        capacity: AuthorityCapacity {
            max_tenants: 100,
            max_state_bytes: 4 << 20,
            maintenance_reserve_bytes: 1 << 20,
        },
        membership: AuthorityMembership {
            voters: BTreeSet::from([1, 2, 3]),
            members: members
                .iter()
                .filter(|(id, _)| **id <= 3)
                .map(|(id, m)| (*id, m.clone()))
                .collect(),
        },
    };
    let peers: Vec<_> = members
        .iter()
        .map(|(id, m)| PeerConfig {
            node_id: *id,
            endpoint: m.endpoint.clone(),
            certificate_pins: BTreeSet::from([identities[*id as usize - 1].certificate_pin()]),
        })
        .collect();
    let (shutdown, stopped) = watch::channel(false);
    let mut tasks = Vec::new();
    let mut services = Vec::new();
    let mut networks = Vec::new();
    let mut stores = Vec::new();
    for (i, listener) in listeners.into_iter().enumerate() {
        let id = i as u64 + 1;
        let network = ClusterNetwork::new(
            id,
            &identities[i],
            ca.as_bytes(),
            peers.clone(),
            PeerLimits::default(),
        )
        .unwrap();
        network.install_audit(Arc::new(TestAudit)).unwrap();
        let store = TenantStorageSet::initialize_catalogs(
            NodeStore::create_new(
                dir.path().join(format!("node-{id}.redb")),
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )
            .unwrap(),
            installation.tenant(),
            Arc::new(LocalKeyProvider::new([id as u8; 32])),
            Arc::new(LocalKeyProvider::new([id as u8 + 10; 32])),
            StorageAccess::independent_authority(&installation.manifest, 0).unwrap(),
        )
        .await
        .unwrap();
        IndependentAuthority::initialize_storage(
            &store,
            &installation,
            &bootstrap,
            &members[&id].verifier,
        )
        .unwrap();
        let service = IndependentAuthority::open_existing_replicated(
            store.clone(),
            installation.clone(),
            signing
                .for_verifier(kasumi_serving::test_utils::fixture_verifier(id))
                .unwrap()
                .signer,
            id,
            AuthorityNodeSettings {
                resource_budget_bytes: 64 << 20,
                installed_members: members.clone(),
            },
            network.clone(),
            kasumi_raft::Config {
                heartbeat_interval: 100,
                election_timeout_min: 500,
                election_timeout_max: 1000,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let access = store.clone();
        network
            .register_group_with_bootstrap(
                "authority-maintenance".into(),
                service.raft_group().raft().clone(),
                BTreeSet::from([1, 2, 3, 4]),
                service.bootstrap_digest().into(),
                Arc::new(move || access.check_access()),
            )
            .unwrap();
        let weak = Arc::downgrade(&service);
        network
            .install_group_peer_fence(
                "authority-maintenance",
                Arc::new(move |peer| {
                    weak.upgrade()
                        .context("authority closed")?
                        .peer_allowed(peer)
                }),
            )
            .unwrap();
        network
            .install_authority_maintenance(Arc::downgrade(&service))
            .unwrap();
        service
            .install_maintenance_transport(network.clone())
            .unwrap();
        tasks.push(tokio::spawn(crate::tls::serve_tls(
            listener,
            network.server_tls(),
            network.router(),
            crate::tls::ListenerLimits::default(),
            Arc::new(TestAudit),
            stopped.clone(),
        )));
        services.push(service);
        networks.push(network);
        stores.push(store);
    }
    services[0].initialize().await.unwrap();
    let current = leader(&services).await;
    assert!(networks[0].authorize("authority-maintenance", 4).is_err());
    assert_eq!(
        start(
            &current,
            AuthorityMaintenanceAction::SetCapacity {
                capacity: AuthorityCapacity {
                    max_tenants: 100,
                    max_state_bytes: 8 << 20,
                    maintenance_reserve_bytes: 1 << 20
                }
            }
        )
        .await
        .phase,
        AuthorityMaintenancePhase::Completed
    );
    assert_eq!(
        start(
            &current,
            AuthorityMaintenanceAction::EnrollLearner {
                node_id: 4,
                member: members[&4].clone()
            }
        )
        .await
        .phase,
        AuthorityMaintenancePhase::Completed
    );
    let removed = services
        .iter()
        .map(|s| s.raft_group().raft().metrics().borrow().id)
        .find(|id| *id <= 3 && *id != current.raft_group().raft().metrics().borrow().id)
        .unwrap();
    let voters = BTreeSet::from([1, 2, 3, 4])
        .difference(&BTreeSet::from([removed]))
        .copied()
        .collect();
    assert_eq!(
        start(
            &current,
            AuthorityMaintenanceAction::ReplaceVoters { voters }
        )
        .await
        .phase,
        AuthorityMaintenancePhase::Completed
    );
    let stopped_member = start(
        &current,
        AuthorityMaintenanceAction::RevokeMember { node_id: removed },
    )
    .await;
    assert_eq!(stopped_member.phase, AuthorityMaintenancePhase::Draining);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if networks
                .iter()
                .enumerate()
                .filter(|(i, _)| *i as u64 + 1 != removed)
                .all(|(_, n)| n.authorize("authority-maintenance", removed).is_err())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // Release the watch read guard before awaiting transport on this runtime.
    let current_id = current.raft_group().raft().metrics().borrow().id;
    assert!(
        networks[removed as usize - 1]
            .bootstrap_fingerprint(current_id, "authority-maintenance")
            .await
            .is_err()
    );
    shutdown.send(true).unwrap();
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    for service in services {
        service.shutdown().await.unwrap();
    }
    for store in stores {
        store.shutdown().await.unwrap();
    }
}
