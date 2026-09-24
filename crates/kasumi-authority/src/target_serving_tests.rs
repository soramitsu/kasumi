//! Existing target owners remain usable through ordinary maintenance. The
//! learner below deliberately has no serving admission; this is not a test of
//! replacement-node enrollment or of a real TLS transport.
use super::*;
use kasumi_engine::{TargetServingReplica, VerifiedTargetServingProjection};

fn journal_path(f: &MaterialFixture, id: u64) -> std::path::PathBuf {
    f.physical[&id].path(format!("serving-journal-{id}.kv"))
}

async fn journal(
    f: &MaterialFixture,
    id: u64,
    path: &std::path::Path,
    create: bool,
) -> (
    Arc<kasumi_engine::TargetJournal>,
    Arc<TenantStore>,
    Arc<NodeStore>,
) {
    let installation = kasumi_engine::TargetJournalInstallation {
        root: f.control.root.clone(),
        node: nodes().into_iter().find(|node| node.node_id == id).unwrap(),
    };
    let file_id = kasumi_store::node_store_ids::target_journal(
        installation.root.control_incarnation,
        &installation.node.verifier,
    )
    .unwrap();
    let node = if create {
        f.physical[&id].create_new(path, file_id)
    } else {
        f.physical[&id].open_existing(path, file_id)
    }
    .unwrap();
    let name = format!("kasumi.target.{}.{id}", f.control.root.control_incarnation);
    let provider = Arc::new(LocalKeyProvider::new([239; 32]));
    let access = StorageAccess::target_journal(&installation.root, &installation.node).unwrap();
    let store = if create {
        TenantStore::initialize_catalog(node.clone(), name, provider, access).await
    } else {
        TenantStore::open_existing(node.clone(), name, provider, access).await
    }
    .unwrap();
    let limits = TargetJournalLimits {
        max_metadata_bytes: 4 << 20,
    };
    let journal = if create {
        kasumi_engine::TargetJournal::create_new(
            store.clone(),
            installation,
            limits,
            f.physical[&id].admission.clone(),
        )
    } else {
        kasumi_engine::TargetJournal::open_existing(
            store.clone(),
            installation,
            limits,
            f.physical[&id].admission.clone(),
        )
    }
    .unwrap();
    (journal, store, node)
}

pub(super) async fn record_follower_projection(
    f: &MaterialFixture,
    follower: &RunningTarget,
    proof: &kasumi_engine::VerifiedTargetActivation,
    input_digest: &str,
) {
    let (journal, store, node) = journal(f, follower.id, &journal_path(f, follower.id), true).await;
    journal.prepare(&follower.operation, input_digest).unwrap();
    let projection = journal
        .record_activation(&follower.operation, proof, &f.signers[&follower.id])
        .await
        .unwrap();
    assert_eq!(
        projection.execution().unwrap().activation.as_ref(),
        Some(proof.fact())
    );
    drop(projection);
    drop(journal);
    store.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

struct Serving {
    id: u64,
    owner: TargetServingReplica,
    stores: Arc<TenantStorageSet>,
    audit: Arc<kasumi_engine::SecurityAudit>,
    projection: Arc<VerifiedTargetServingProjection>,
    gate: Arc<ServingGate>,
    journal: Arc<kasumi_engine::TargetJournal>,
    journal_store: Arc<TenantStore>,
    journal_node: Arc<NodeStore>,
    node: Arc<NodeStore>,
}
impl Serving {
    async fn open(
        f: &MaterialFixture,
        id: u64,
        selected: u64,
        router: &Arc<InProcessRouter>,
    ) -> Self {
        let path = if id == selected {
            f.physical[&id].path("activation-journal.kv")
        } else {
            journal_path(f, id)
        };
        let (journal, journal_store, journal_node) = journal(f, id, &path, false).await;
        let projection = Arc::new(
            journal
                .serving_projection("city", f.target.incarnation)
                .unwrap()
                .unwrap(),
        );
        let identity = nodes().into_iter().find(|node| node.node_id == id).unwrap();
        let boot = ServingBoot::with_test_clock(
            f.issuer.trust_for(id),
            ServingIdentity {
                tenant: "city".into(),
                incarnation: f.target.incarnation,
                authority_epoch: 2,
                node: identity.clone(),
            },
            f.issuer.clock.clone(),
        )
        .unwrap();
        let attempt = boot.begin_acquisition().unwrap();
        let issuer = f.issuer.leader().await;
        let (lease, fence) = issuer
            .acquire(
                AuthenticatedNode::from_verified_transport(
                    f.issuer.context(&identity.principal),
                    identity.certificate_sha256,
                )
                .unwrap(),
                attempt.request().clone(),
            )
            .await
            .unwrap();
        fence.check().unwrap();
        let gate = ServingGate::new(attempt.verify(lease).unwrap()).unwrap();
        f.shutdown_target_node(id).await;
        let node = f.physical[&id]
            .open_existing(
                f.physical[&id].path(format!("target-{id}.kv")),
                kasumi_store::node_store_ids::target_generation(
                    f.control.root.control_incarnation,
                    "city",
                    f.target.incarnation,
                    &identity.verifier,
                )
                .unwrap(),
            )
            .unwrap();
        let audit = audit(node.clone(), f.physical[&id].admission.clone(), true).await;
        let stores = TenantStorageSet::open_existing(
            node.clone(),
            "city".into(),
            Arc::new(LocalKeyProvider::new([61; 32])),
            Arc::new(LocalKeyProvider::new([221; 32])),
            projection.storage_access(gate.clone()).unwrap(),
        )
        .await
        .unwrap();
        let owner = kasumi_engine::open_serving_target(
            projection.clone(),
            stores.clone(),
            TargetReplicaConfig {
                node_id: id,
                raft: Config {
                    heartbeat_interval: 50,
                    election_timeout_min: 250,
                    election_timeout_max: 400,
                    ..Config::default()
                },
                admission: f.physical[&id].admission.clone(),
            },
            router.clone(),
            audit.clone(),
        )
        .await
        .unwrap();
        router.register(
            format!("city/{}", f.target.incarnation),
            id,
            owner.database().unwrap().raft_group().raft().clone(),
        );
        Self {
            id,
            owner,
            stores,
            audit,
            projection,
            gate,
            journal,
            journal_store,
            journal_node,
            node,
        }
    }
    async fn close(mut self, f: &MaterialFixture, router: &InProcessRouter) {
        router.unregister(&format!("city/{}", f.target.incarnation), self.id);
        let original = self.owner.close().await;
        let repeated = self.owner.close().await;
        assert_target_close_outcomes(original, repeated);
        assert!(self.owner.database().is_err());
        assert!(self.stores.application().check_access().is_err());
        assert!(self.stores.custody().store().check_access().is_err());
        drop(self.owner);
        self.stores.custody().store().shutdown().await.unwrap();
        drop(self.stores);
        self.audit.shutdown().await.unwrap();
        drop(self.audit);
        drop(self.projection);
        drop(self.gate);
        drop(self.journal);
        self.journal_store.shutdown().await.unwrap();
        self.node.shutdown().await.unwrap();
        self.journal_node.shutdown().await.unwrap();
    }
}

async fn leader(targets: &BTreeMap<u64, Serving>) -> u64 {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            for (&id, target) in targets {
                let database = target.owner.database().unwrap();
                let group = database.raft_group();
                if group.raft().metrics().borrow().current_leader == Some(id)
                    && group.linearizable_barrier().await.is_ok()
                {
                    return id;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap()
}

fn context() -> RequestContext {
    RequestContext {
        tenant: "city".into(),
        principal: "source-owner".into(),
        request_id: "target-maintenance".into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        authorization: RequestAuthorization::service_identity(),
    }
}

async fn assert_operational(
    targets: &BTreeMap<u64, Serving>,
    fact: &kasumi_types::TargetActivationFact,
    suspended: bool,
    learner: bool,
    changed_peer: u64,
) {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let mut ready = true;
            for target in targets.values() {
                target.owner.check().unwrap();
                let database = target.owner.database().unwrap();
                let state = database.engine().generation().unwrap();
                assert_eq!(
                    state.state.target_lifecycle[&state.state.incarnation]
                        .activation
                        .as_ref(),
                    Some(fact)
                );
                ready &= state.state.suspended == suspended;
                let covered = database
                    .raft_group()
                    .confirm_local_application(&fact.position)
                    .unwrap();
                let membership = covered.membership().membership();
                assert_eq!(
                    membership.voter_ids().collect::<BTreeSet<_>>(),
                    BTreeSet::from([1, 2, 3])
                );
                ready &= membership.nodes().any(|(id, _)| *id == 4) == learner;
                ready &= membership
                    .nodes()
                    .any(|(id, node)| *id == changed_peer && node.addr == "target-maintained");
                assert_eq!(
                    target.owner.bootstrap().voters[&changed_peer].address,
                    format!("target-{changed_peer}")
                );
                database
                    .engine()
                    .authorize(&context(), None, Action::Admin)
                    .unwrap();
                if state.state.suspended {
                    assert!(
                        database
                            .engine()
                            .authorize(&context(), None, Action::Read)
                            .is_err()
                    );
                }
            }
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

pub(super) async fn exercise_serving(
    f: &MaterialFixture,
    router: &Arc<InProcessRouter>,
    selected: u64,
    fact: &kasumi_types::TargetActivationFact,
    maintenance: bool,
) {
    let ids = if maintenance {
        vec![1, 2, 3]
    } else {
        vec![selected]
    };
    let mut targets = BTreeMap::new();
    for &id in &ids {
        targets.insert(id, Serving::open(f, id, selected, router).await);
    }
    for target in targets.values() {
        assert_eq!(
            target.projection.execution().unwrap().activation.as_ref(),
            Some(fact)
        );
        let database = target.owner.database().unwrap();
        let state = database.engine().generation().unwrap();
        assert_eq!(
            state.state.target_lifecycle[&f.target.incarnation.to_string()]
                .activation
                .as_ref(),
            Some(fact)
        );
    }
    if maintenance {
        let id = leader(&targets).await;
        let database = targets[&id].owner.database().unwrap();
        database
            .administer(context(), Operation::Suspend(true))
            .await
            .unwrap();
        // Commit the learner metadata without claiming catch-up or issuing a
        // serving capability to node 4. Three original voters remain a quorum.
        database
            .raft_group()
            .raft()
            .add_learner(4, kasumi_raft::BasicNode::new("learner-4"), false)
            .await
            .unwrap();
        // AddNodes deliberately preserves an existing node's address. This
        // fixture updates the same physical voter's operational metadata; it
        // neither admits a replacement owner nor changes the voter set.
        database
            .raft_group()
            .raft()
            .change_membership(
                openraft::ChangeMembers::SetNodes(BTreeMap::from([(
                    id,
                    kasumi_raft::BasicNode::new("target-maintained"),
                )])),
                true,
            )
            .await
            .unwrap();
        assert_operational(&targets, fact, true, true, id).await;
        drop(database);
        for (_, target) in std::mem::take(&mut targets) {
            target.close(f, router).await;
        }
        // The same physical files and independent projections reopen while
        // suspended and with different current membership metadata. This is a
        // fresh boot for every owner, not a reused old lease or store handle.
        for &node_id in &ids {
            targets.insert(node_id, Serving::open(f, node_id, selected, router).await);
        }
        assert_operational(&targets, fact, true, true, id).await;
        let new_leader = leader(&targets).await;
        let database = targets[&new_leader].owner.database().unwrap();
        database
            .administer(context(), Operation::Suspend(false))
            .await
            .unwrap();
        database.raft_group().remove_learner(4).await.unwrap();
        assert_operational(&targets, fact, false, false, id).await;
    }
    // Original lifetime and permanent closure rules still apply after any
    // maintenance/restart. Historical activation cannot renew a captured gate.
    f.issuer.clock.0.store(2001, Ordering::SeqCst);
    for target in targets.values() {
        assert!(target.owner.database().is_err());
        assert!(
            target
                .projection
                .storage_access(target.gate.clone())
                .is_err()
        );
    }
    for (_, target) in targets {
        target.close(f, router).await;
    }
}
