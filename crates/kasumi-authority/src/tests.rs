use super::*;
use kasumi_clock::{EpochClock, LeaseClock, WallClock};
use kasumi_raft::{BasicNode, Config, InProcessRouter};
use kasumi_store::{NodeStore, TenantStorageSet, test_utils::LocalKeyProvider};
use kasumi_types::{ErrorCode, FullBackupCheckpoint, RequestAuthorization, RequestContext};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;
struct Clock(AtomicU64);
impl LeaseClock for Clock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::SeqCst))
    }
}
struct Wall;
impl WallClock for Wall {
    fn now_ms(&self) -> anyhow::Result<u64> {
        Ok(1_000_000)
    }
}
struct Fixture {
    _dir: tempfile::TempDir,
    router: Arc<InProcessRouter>,
    services: Vec<Arc<IndependentAuthority>>,
    stores: Vec<Arc<TenantStorageSet>>,
    clock: Arc<Clock>,
    epoch: Arc<EpochClock>,
    installation: AuthorityInstallation,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_receipt_limit(1000).await
    }
    async fn with_receipt_limit(max_receipts: u64) -> Self {
        Self::with_controls(max_receipts, BTreeMap::new()).await
    }
    async fn with_controls(max_receipts: u64, controls: BTreeMap<Uuid, String>) -> Self {
        Self::with_control_capacity(max_receipts, controls, 4 << 20).await
    }
    async fn with_control_capacity(
        max_receipts: u64,
        controls: BTreeMap<Uuid, String>,
        max_state_bytes: u64,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let router = Arc::new(InProcessRouter::default());
        let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .unwrap();
        let signer = Arc::new(AuthoritySigner::from_pkcs8(key.as_ref()).unwrap());
        let manifest = AuthorityManifest {
            lifecycle_controls: controls,
            authority_id: Uuid::new_v4(),
            max_lease_ms: 1000,
            clock_rate_error_ppm: 0,
            partitions: BTreeMap::from([(
                0,
                AuthorityPartition {
                    group: "independent-control".into(),
                    public_key: signer.public_key(),
                },
            )]),
        };
        let installation = AuthorityInstallation {
            manifest,
            partition: 0,
            administrators: BTreeSet::from(["operator".into()]),
            max_tenants: 100,
            max_receipts,
            max_state_bytes,
        };
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let epoch = Arc::new(EpochClock::new(clock.clone(), Arc::new(Wall)).unwrap());
        let voters: BTreeMap<_, _> = (1..=3)
            .map(|id| (id, BasicNode::new(format!("node-{id}"))))
            .collect();
        let mut services = Vec::new();
        let mut stores = Vec::new();
        for id in 1..=3 {
            let node = NodeStore::open(dir.path().join(format!("authority-{id}.redb"))).unwrap();
            let store = TenantStorageSet::open(
                node,
                installation.tenant(),
                Arc::new(LocalKeyProvider::new([id as u8; 32])),
                Arc::new(LocalKeyProvider::new([id as u8 + 10; 32])),
                kasumi_store::StorageAccess::independent_authority(
                    &installation.manifest,
                    installation.partition,
                )
                .unwrap(),
            )
            .await
            .unwrap();
            let service = IndependentAuthority::open_with_clock(
                store.clone(),
                installation.clone(),
                signer.clone(),
                id,
                voters.clone(),
                router.clone(),
                Config {
                    heartbeat_interval: 30,
                    election_timeout_min: 100,
                    election_timeout_max: 180,
                    ..Config::default()
                },
                epoch.clone(),
            )
            .await
            .unwrap();
            router.register(
                "independent-control".into(),
                id,
                service.raft_group().raft().clone(),
            );
            services.push(service);
            stores.push(store);
        }
        let fixture = Self {
            _dir: dir,
            router,
            services,
            stores,
            clock,
            epoch,
            installation,
        };
        fixture.services[0].initialize().await.unwrap();
        fixture.leader().await;
        fixture
    }
    async fn leader(&self) -> Arc<IndependentAuthority> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                for service in &self.services {
                    let metrics = service.group.raft().metrics().borrow().clone();
                    if metrics.current_leader == Some(metrics.id)
                        && service.group.linearizable_barrier().await.is_ok()
                    {
                        return service.clone();
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|error| {
            panic!(
                "authority leader wait failed: {error}; states: {:?}",
                self.services
                    .iter()
                    .map(|s| format!("{:?}", s.group.raft().metrics().borrow().running_state))
                    .collect::<Vec<_>>()
            )
        })
    }
    fn context(&self, principal: &str) -> RequestContext {
        RequestContext {
            tenant: self.installation.tenant(),
            principal: principal.into(),
            request_id: Uuid::new_v4().to_string(),
            scopes: BTreeSet::from([kasumi_types::Action::Admin, kasumi_types::Action::Read]),
            authorization: RequestAuthorization::from_verified_credential(
                2_000_000,
                &self.epoch.observe().unwrap(),
                kasumi_types::CredentialResource::Authority {
                    authority_id: self.installation.manifest.authority_id,
                    partition: self.installation.partition,
                },
            )
            .unwrap(),
        }
    }
    fn command(&self, action: AuthorityAction) -> AuthorityCommand {
        AuthorityCommand {
            tenant: "city".into(),
            command_id: Uuid::new_v4(),
            expected_policy_epoch: 1,
            not_after_ms: 1_500_000,
            action,
        }
    }
    async fn enroll(&self, service: &Arc<IndependentAuthority>) -> Uuid {
        let incarnation = Uuid::new_v4();
        let receipt = service
            .execute(
                self.context("operator"),
                self.command(AuthorityAction::Enroll {
                    incarnation,
                    nodes: nodes(),
                }),
            )
            .await
            .unwrap()
            .0;
        assert!(matches!(
            receipt.receipt.outcome,
            AuthorityOutcome::Enrolled { .. }
        ));
        incarnation
    }
    async fn close(self) {
        for service in &self.services {
            service.shutdown().await.unwrap();
        }
        for store in &self.stores {
            store.application().shutdown().await;
            store.custody().store().shutdown().await;
        }
    }
    async fn reopen(&mut self) {
        let signer = self.services[0].signer.clone();
        for service in &self.services {
            service.shutdown().await.unwrap();
        }
        for store in &self.stores {
            store.application().shutdown().await;
            store.custody().store().shutdown().await;
        }
        self.services.clear();
        self.stores.clear();
        self.router = Arc::new(InProcessRouter::default());
        let voters: BTreeMap<_, _> = (1..=3)
            .map(|id| (id, BasicNode::new(format!("node-{id}"))))
            .collect();
        for id in 1..=3 {
            let node =
                NodeStore::open(self._dir.path().join(format!("authority-{id}.redb"))).unwrap();
            let stores = TenantStorageSet::open(
                node,
                self.installation.tenant(),
                Arc::new(LocalKeyProvider::new([id as u8; 32])),
                Arc::new(LocalKeyProvider::new([id as u8 + 10; 32])),
                kasumi_store::StorageAccess::independent_authority(
                    &self.installation.manifest,
                    self.installation.partition,
                )
                .unwrap(),
            )
            .await
            .unwrap();
            let service = IndependentAuthority::open_with_clock(
                stores.clone(),
                self.installation.clone(),
                signer.clone(),
                id,
                voters.clone(),
                self.router.clone(),
                Config {
                    heartbeat_interval: 30,
                    election_timeout_min: 100,
                    election_timeout_max: 180,
                    ..Config::default()
                },
                self.epoch.clone(),
            )
            .await
            .unwrap();
            self.router.register(
                "independent-control".into(),
                id,
                service.raft_group().raft().clone(),
            );
            self.services.push(service);
            self.stores.push(stores);
        }
        self.leader().await;
    }
}
fn nodes() -> BTreeSet<NodeIdentity> {
    (1..=3)
        .map(|id| NodeIdentity {
            node_id: id,
            principal: format!("node-{id}"),
            certificate_sha256: format!("{id:064x}"),
        })
        .collect()
}
fn target(source: Uuid) -> RecoveryTarget {
    RecoveryTarget {
        incarnation: Uuid::new_v4(),
        nodes: nodes(),
        checkpoint: FullBackupCheckpoint {
            tenant: "city".into(),
            source_incarnation: source.to_string(),
            revision: 123,
            resident_sha256: "a".repeat(64),
            backup_id: Uuid::new_v4(),
            manifest_ciphertext_sha256: "b".repeat(64),
            key_lineage_digest: "c".repeat(64),
        },
    }
}
fn boot(fixture: &Fixture, incarnation: Uuid, epoch: u64) -> ServingBoot {
    ServingBoot::with_test_clock(
        AuthorityTrust::install(fixture.installation.manifest.clone()).unwrap(),
        ServingIdentity {
            tenant: "city".into(),
            incarnation,
            authority_epoch: epoch,
            node: nodes().first().unwrap().clone(),
        },
        fixture.clock.clone(),
    )
    .unwrap()
}
async fn acquire(
    fixture: &Fixture,
    service: &Arc<IndependentAuthority>,
    boot: &ServingBoot,
) -> VerifiedLease {
    let attempt = boot.begin_acquisition().unwrap();
    let caller = AuthenticatedNode::from_verified_transport(
        fixture.context("node-1"),
        nodes().first().unwrap().certificate_sha256.clone(),
    )
    .unwrap();
    let (wire, fence) = service
        .acquire(caller, attempt.request().clone())
        .await
        .unwrap();
    fence.check().unwrap();
    attempt.verify(wire).unwrap()
}

#[tokio::test]
async fn independent_quorum_fence_drains_original_lease_and_competing_activations_cannot_overlap() {
    let fixture = Fixture::new().await;
    let service = fixture.leader().await;
    let source = fixture.enroll(&service).await;
    let old_boot = boot(&fixture, source, 1);
    let old_gate = ServingGate::new(acquire(&fixture, &service, &old_boot).await).unwrap();
    let fenced = service
        .execute(
            fixture.context("operator"),
            fixture.command(AuthorityAction::Fence {
                incarnation: source,
                authority_epoch: 1,
            }),
        )
        .await
        .unwrap()
        .0
        .receipt;
    let replacement = target(source);
    let activation = fixture.command(AuthorityAction::Activate {
        fence_id: fenced.command.command_id,
        fence_digest: fenced.digest().unwrap(),
        target: replacement.clone(),
    });
    assert_eq!(
        service
            .execute(fixture.context("operator"), activation.clone())
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Unavailable
    );
    old_gate.check().unwrap();
    let attempt = old_boot.begin_acquisition().unwrap();
    let caller = AuthenticatedNode::from_verified_transport(
        fixture.context("node-1"),
        nodes().first().unwrap().certificate_sha256.clone(),
    )
    .unwrap();
    assert_eq!(
        service
            .acquire(caller, attempt.request().clone())
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Forbidden
    );
    fixture.clock.0.store(1000, Ordering::SeqCst);
    assert!(old_gate.check().is_err());
    let other = fixture.command(AuthorityAction::Activate {
        fence_id: fenced.command.command_id,
        fence_digest: fenced.digest().unwrap(),
        target: target(source),
    });
    let (a, b) = tokio::join!(
        service.execute(fixture.context("operator"), activation.clone()),
        service.execute(fixture.context("operator"), other)
    );
    let accepted = [a, b]
        .into_iter()
        .filter_map(|r| r.ok())
        .filter(|r| matches!(r.0.receipt.outcome, AuthorityOutcome::Activated { .. }))
        .collect::<Vec<_>>();
    assert_eq!(accepted.len(), 1);
    let proof = AuthorityTrust::install(fixture.installation.manifest.clone())
        .unwrap()
        .verify_activation(accepted[0].0.clone())
        .unwrap();
    let AuthorityOutcome::Activated {
        target,
        authority_epoch,
    } = &proof.receipt().outcome
    else {
        unreachable!()
    };
    let new_boot = boot(&fixture, target.incarnation, *authority_epoch);
    acquire(&fixture, &service, &new_boot)
        .await
        .check()
        .unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn exact_stop_defeats_delayed_activation_and_committed_activation_wins_resolution() {
    let fixture = Fixture::new().await;
    let service = fixture.leader().await;
    let source = fixture.enroll(&service).await;
    let fence = service
        .execute(
            fixture.context("operator"),
            fixture.command(AuthorityAction::Fence {
                incarnation: source,
                authority_epoch: 1,
            }),
        )
        .await
        .unwrap()
        .0
        .receipt;
    let activate = fixture.command(AuthorityAction::Activate {
        fence_id: fence.command.command_id,
        fence_digest: fence.digest().unwrap(),
        target: target(source),
    });
    let stop = fixture.command(AuthorityAction::StopActivation {
        original: Box::new(activate.clone()),
    });
    let receipt = service
        .execute(fixture.context("operator"), stop.clone())
        .await
        .unwrap()
        .0;
    let AuthorityOutcome::ActivationResolved { original } = receipt.receipt.outcome else {
        panic!("missing stop resolution")
    };
    assert!(matches!(
        original.outcome,
        AuthorityOutcome::ActivationStopped { .. }
    ));
    fixture.clock.0.store(2000, Ordering::SeqCst);
    let delayed = service
        .execute(fixture.context("operator"), activate.clone())
        .await
        .unwrap()
        .0
        .receipt;
    assert_eq!(delayed, *original);
    let mut substituted = activate.clone();
    substituted.not_after_ms -= 1;
    assert_eq!(
        service
            .execute(fixture.context("operator"), substituted)
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );
    // Another explicitly chosen activation must still perform its own full
    // drain, then its accepted outcome remains successful when resolved.
    let mut next = activate;
    next.command_id = Uuid::new_v4();
    assert!(
        service
            .execute(fixture.context("operator"), next.clone())
            .await
            .is_err()
    );
    fixture.clock.0.store(3000, Ordering::SeqCst);
    let committed = service
        .execute(fixture.context("operator"), next.clone())
        .await
        .unwrap()
        .0
        .receipt;
    let resolved = service
        .execute(
            fixture.context("operator"),
            fixture.command(AuthorityAction::StopActivation {
                original: Box::new(next),
            }),
        )
        .await
        .unwrap()
        .0
        .receipt;
    let AuthorityOutcome::ActivationResolved { original } = resolved.outcome else {
        unreachable!()
    };
    assert_eq!(*original, committed);
    fixture.close().await;
}

#[tokio::test]
async fn current_admin_self_revocation_yields_unknown_and_new_custodian_recovers_exact_identity() {
    let fixture = Fixture::new().await;
    let service = fixture.leader().await;
    fixture.enroll(&service).await;
    let change = fixture.command(AuthorityAction::ReplaceAdministrators {
        administrators: BTreeSet::from(["custodian".into()]),
    });
    assert_eq!(
        service
            .execute(fixture.context("operator"), change.clone())
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::UnknownOutcome
    );
    assert_eq!(
        service
            .receipt(fixture.context("operator"), "city", change.command_id)
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Forbidden
    );
    let recovered = service
        .execute(fixture.context("custodian"), change.clone())
        .await
        .unwrap()
        .0;
    assert!(matches!(
        recovered.receipt.outcome,
        AuthorityOutcome::AdministratorsReplaced { policy_epoch: 2 }
    ));
    assert_eq!(
        service
            .receipt(fixture.context("custodian"), "city", change.command_id)
            .await
            .unwrap()
            .0
            .unwrap(),
        recovered
    );
    fixture.close().await;
}

#[tokio::test]
async fn actual_authority_quorum_loss_rejects_lease_and_activation_without_source_fallback() {
    let fixture = Fixture::new().await;
    let service = fixture.leader().await;
    let source = fixture.enroll(&service).await;
    let lease_boot = boot(&fixture, source, 1);
    acquire(&fixture, &service, &lease_boot).await;
    let node_id = service.group.raft().metrics().borrow().id;
    fixture.router.isolate("independent-control", node_id, true);
    let attempt = lease_boot.begin_acquisition().unwrap();
    let caller = AuthenticatedNode::from_verified_transport(
        fixture.context("node-1"),
        nodes().first().unwrap().certificate_sha256.clone(),
    )
    .unwrap();
    assert!(
        service
            .acquire(caller, attempt.request().clone())
            .await
            .is_err()
    );
    assert!(
        service
            .execute(
                fixture.context("operator"),
                fixture.command(AuthorityAction::Fence {
                    incarnation: source,
                    authority_epoch: 1
                })
            )
            .await
            .is_err()
    );
    fixture
        .router
        .isolate("independent-control", node_id, false);
    fixture.close().await;
}

#[tokio::test]
async fn actual_encrypted_source_materialization_is_fenced_but_independent_custody_stays_available()
{
    let fixture = Fixture::new().await;
    let service = fixture.leader().await;
    let source = fixture.enroll(&service).await;
    let lease_boot = boot(&fixture, source, 1);
    let gate = ServingGate::new(acquire(&fixture, &service, &lease_boot).await).unwrap();
    let path = fixture._dir.path().join("separate-municipality.redb");
    let node = NodeStore::open(&path).unwrap();
    let provider = Arc::new(LocalKeyProvider::new([90; 32]));
    let custody_provider = Arc::new(LocalKeyProvider::new([91; 32]));
    let stores = TenantStorageSet::open(
        node.clone(),
        "city".into(),
        provider.clone(),
        custody_provider.clone(),
        kasumi_store::StorageAccess::serving(gate.clone()).unwrap(),
    )
    .await
    .unwrap();
    stores
        .application()
        .write_batch(&[kasumi_store::WriteOp::put(
            "payload",
            b"journal",
            b"municipality-record",
        )])
        .unwrap();
    stores
        .custody()
        .store()
        .write_batch(&[kasumi_store::WriteOp::put(
            "custody-test",
            b"metadata",
            b"closed-control",
        )])
        .unwrap();
    service
        .execute(
            fixture.context("operator"),
            fixture.command(AuthorityAction::Fence {
                incarnation: source,
                authority_epoch: 1,
            }),
        )
        .await
        .unwrap();
    fixture.clock.0.store(1000, Ordering::SeqCst);
    assert!(stores.application().get("payload", b"journal").is_err());
    assert!(
        stores
            .application()
            .write_batch(&[kasumi_store::WriteOp::put("payload", b"late", b"forbidden")])
            .is_err()
    );
    assert!(stores.application().refresh_lease().await.is_err());
    assert_eq!(
        stores
            .custody()
            .store()
            .get("custody-test", b"metadata")
            .unwrap()
            .unwrap(),
        b"closed-control"
    );
    let probes = provider.probe_count();
    assert!(kasumi_store::StorageAccess::serving(gate).is_err());
    assert_eq!(provider.probe_count(), probes);
    stores.application().shutdown().await;
    stores.custody().store().shutdown().await;
    drop(stores);
    drop(node);
    let reopened = NodeStore::open(&path).unwrap();
    let custody =
        kasumi_store::CustodyStore::open(reopened.clone(), "city".into(), custody_provider)
            .await
            .unwrap();
    assert_eq!(
        custody
            .store()
            .get("custody-test", b"metadata")
            .unwrap()
            .unwrap(),
        b"closed-control"
    );
    assert_eq!(provider.probe_count(), probes);
    // Even a fixture-enabled embedding cannot reinterpret a serving catalog as
    // an unleased fixture. The persisted purpose is required, without defaults.
    assert!(
        kasumi_store::TenantStore::open_fixture(reopened, "city".into(), provider.clone())
            .await
            .is_err()
    );
    assert_eq!(provider.probe_count(), probes);
    custody.store().shutdown().await;
    fixture.close().await;
}

#[tokio::test]
async fn exact_target_preparation_cannot_serve_and_needs_a_fresh_active_lease_after_drain() {
    let fixture = Fixture::new().await;
    let service = fixture.leader().await;
    let source = fixture.enroll(&service).await;
    let replacement = target(source);
    let prepared = fixture.command(AuthorityAction::PrepareTarget {
        source_incarnation: source,
        source_epoch: 1,
        target: replacement.clone(),
    });
    service
        .execute(fixture.context("operator"), prepared)
        .await
        .unwrap();
    let prepared_boot = boot(&fixture, replacement.incarnation, 2).for_restore_preparation();
    let gate = ServingGate::new(acquire(&fixture, &service, &prepared_boot).await).unwrap();
    gate.check().unwrap();
    assert!(gate.check_serving().is_err());
    assert!(gate.capture().is_err());
    let active_boot = prepared_boot.clone().for_serving();
    let attempt = active_boot.begin_acquisition().unwrap();
    let caller = AuthenticatedNode::from_verified_transport(
        fixture.context("node-1"),
        nodes().first().unwrap().certificate_sha256.clone(),
    )
    .unwrap();
    assert!(
        service
            .acquire(caller, attempt.request().clone())
            .await
            .is_err()
    );
    let fenced = service
        .execute(
            fixture.context("operator"),
            fixture.command(AuthorityAction::Fence {
                incarnation: source,
                authority_epoch: 1,
            }),
        )
        .await
        .unwrap()
        .0
        .receipt;
    let activate = fixture.command(AuthorityAction::Activate {
        fence_id: fenced.command.command_id,
        fence_digest: fenced.digest().unwrap(),
        target: replacement,
    });
    assert!(
        service
            .execute(fixture.context("operator"), activate.clone())
            .await
            .is_err()
    );
    // Renew preparation before its current lease expires. This still cannot
    // shorten the source drain or grant a serving response fence.
    fixture.clock.0.store(900, Ordering::SeqCst);
    gate.renew(acquire(&fixture, &service, &prepared_boot).await)
        .unwrap();
    fixture.clock.0.store(1000, Ordering::SeqCst);
    let accepted = service
        .execute(fixture.context("operator"), activate)
        .await
        .unwrap()
        .0;
    let proof = AuthorityTrust::install(fixture.installation.manifest.clone())
        .unwrap()
        .verify_activation(accepted)
        .unwrap();
    let lease = acquire(&fixture, &service, &active_boot).await;
    assert_eq!(lease.activation_digest(), proof.digest().unwrap());
    gate.promote_prepared(lease).unwrap();
    gate.capture().unwrap().check().unwrap();
    let attempt = prepared_boot.begin_acquisition().unwrap();
    let caller = AuthenticatedNode::from_verified_transport(
        fixture.context("node-1"),
        nodes().first().unwrap().certificate_sha256.clone(),
    )
    .unwrap();
    assert!(
        service
            .acquire(caller, attempt.request().clone())
            .await
            .is_err()
    );
    fixture.close().await;
}

#[tokio::test]
async fn encrypted_restart_restarts_full_drain_and_never_reuses_an_old_incarnation() {
    let mut fixture = Fixture::new().await;
    let service = fixture.leader().await;
    let source = fixture.enroll(&service).await;
    let old_boot = boot(&fixture, source, 1);
    let old_attempt = old_boot.begin_acquisition().unwrap();
    let caller = || {
        AuthenticatedNode::from_verified_transport(
            fixture.context("node-1"),
            nodes().first().unwrap().certificate_sha256.clone(),
        )
        .unwrap()
    };
    let signed = service
        .acquire(caller(), old_attempt.request().clone())
        .await
        .unwrap()
        .0;
    let discovery = LeaseDiscovery {
        tenant: "city".into(),
        incarnation: source,
        node: nodes().first().unwrap().clone(),
        purpose: LeasePurpose::Serving,
    };
    let observed = service
        .discover(caller(), discovery.clone())
        .await
        .unwrap()
        .0;
    assert_eq!(observed.authority_epoch, 1);
    let fenced = service
        .execute(
            fixture.context("operator"),
            fixture.command(AuthorityAction::Fence {
                incarnation: source,
                authority_epoch: 1,
            }),
        )
        .await
        .unwrap()
        .0
        .receipt;
    let replacement = target(source);
    let activate = fixture.command(AuthorityAction::Activate {
        fence_id: fenced.command.command_id,
        fence_digest: fenced.digest().unwrap(),
        target: replacement.clone(),
    });
    assert_eq!(
        service
            .execute(fixture.context("operator"), activate.clone())
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Unavailable
    );
    fixture.clock.0.store(999, Ordering::SeqCst);
    drop(service);
    fixture.reopen().await;
    let service = fixture.leader().await;
    // A new process cannot inherit the old leader's elapsed drain witness.
    fixture.clock.0.store(1000, Ordering::SeqCst);
    assert!(old_attempt.verify(signed).is_err());
    assert_eq!(
        service
            .execute(fixture.context("operator"), activate.clone())
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Unavailable
    );
    fixture.clock.0.store(1999, Ordering::SeqCst);
    assert_eq!(
        service
            .execute(fixture.context("operator"), activate.clone())
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Unavailable
    );
    fixture.clock.0.store(2000, Ordering::SeqCst);
    let accepted = service
        .execute(fixture.context("operator"), activate.clone())
        .await
        .unwrap()
        .0;
    assert!(matches!(
        accepted.receipt.outcome,
        AuthorityOutcome::Activated {
            authority_epoch: 2,
            ..
        }
    ));
    let caller = AuthenticatedNode::from_verified_transport(
        fixture.context("node-1"),
        discovery.node.certificate_sha256.clone(),
    )
    .unwrap();
    assert_eq!(
        service
            .discover(caller, discovery)
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Forbidden
    );
    // Make a snapshot and reopen the encrypted state before attempting reuse.
    use kasumi_raft::StateMachineBackend;
    let mut snapshot = Vec::new();
    service.backend.snapshot(&mut snapshot).unwrap();
    service
        .backend
        .validate_snapshot(&mut snapshot.as_slice())
        .unwrap();
    drop(service);
    fixture.reopen().await;
    let service = fixture.leader().await;
    assert_eq!(
        service
            .receipt(fixture.context("operator"), "city", activate.command_id)
            .await
            .unwrap()
            .0
            .unwrap(),
        accepted
    );
    let second_fence = service
        .execute(
            fixture.context("operator"),
            fixture.command(AuthorityAction::Fence {
                incarnation: replacement.incarnation,
                authority_epoch: 2,
            }),
        )
        .await
        .unwrap()
        .0
        .receipt;
    let mut reused = target(replacement.incarnation);
    reused.incarnation = source;
    let stale = fixture.command(AuthorityAction::Activate {
        fence_id: second_fence.command.command_id,
        fence_digest: second_fence.digest().unwrap(),
        target: reused,
    });
    assert_eq!(
        service
            .execute(fixture.context("operator"), stale.clone())
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Unavailable
    );
    fixture.clock.0.store(3000, Ordering::SeqCst);
    let rejected = service
        .execute(fixture.context("operator"), stale)
        .await
        .unwrap()
        .0
        .receipt;
    assert!(matches!(
        rejected.outcome,
        AuthorityOutcome::Rejected {
            code: ErrorCode::Conflict,
            ..
        }
    ));
    fixture.close().await;
}

include!("target_stop_tests.rs");

#[path = "issuer_tests.rs"]
mod issuer_tests;
