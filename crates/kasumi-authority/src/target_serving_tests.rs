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
    NodeStore,
) {
    let installation = kasumi_engine::TargetJournalInstallation {
        root: f.control.root.clone(),
        node: nodes().into_iter().find(|node| node.node_id == id).unwrap(),
        audit_placement_bindings: std::collections::BTreeMap::from([(
            "city".into(),
            "ab".repeat(32),
        )]),
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
    journal_node: NodeStore,
    node: NodeStore,
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
        // Reinstall the fixture's live audit placement before serving replay.
        kasumi_engine::test_utils::install_local_replica_audit_placement(stores.application())
            .unwrap();
        let owner = kasumi_engine::open_serving_target(
            projection.clone(),
            stores.clone(),
            TargetReplicaConfig {
                node_id: id,
                raft: fixture_raft_config(),
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
    let mut last_barrier = None;
    tokio::time::timeout(FIXTURE_OBSERVATION_WINDOW, async {
        loop {
            for (&id, target) in targets {
                let database = target.owner.database().unwrap();
                let group = database.raft_group();
                if group.raft().metrics().borrow().current_leader == Some(id) {
                    match group.linearizable_barrier().await {
                        Ok(_) => return id,
                        Err(error) => last_barrier = Some(format!("{error:?}")),
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|elapsed| {
        let states = targets
            .iter()
            .map(|(id, target)| match target.owner.database() {
                Ok(database) => {
                    let metrics = database.raft_group().raft().metrics().borrow().clone();
                    format!(
                        "{id}: {:?} term={} leader={:?} applied={:?} quorum_ack_ms={:?}",
                        metrics.state,
                        metrics.current_term,
                        metrics.current_leader,
                        metrics.last_applied,
                        metrics.millis_since_quorum_ack
                    )
                }
                Err(error) => format!("{id}: database unavailable: {error:?}"),
            })
            .collect::<Vec<_>>();
        panic!("target leader observation failed: {elapsed}; last barrier: {last_barrier:?}; {states:?}")
    })
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

async fn set_suspension(targets: &BTreeMap<u64, Serving>, suspended: bool) -> u64 {
    let initial = leader(targets).await;
    let database = targets[&initial].owner.database().unwrap();
    let generation = database.engine().generation().unwrap();
    assert_ne!(generation.state.suspended, suspended);
    let previous_epoch = generation.state.policy_epoch;
    let expected_epoch = previous_epoch.checked_add(1).unwrap();
    drop(generation);
    drop(database);
    let context = context();
    let operation = Operation::Suspend(suspended);
    let deadline = tokio::time::Instant::now() + FIXTURE_OBSERVATION_WINDOW;
    let mut last_failure = None;
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "suspension did not settle before the setup deadline: {last_failure:?}"
        );
        // Suspend has no permanent receipt and advances policy_epoch even when
        // its value matches. Settle any original background proposal before a
        // fresh barrier can establish whether another dispatch is necessary.
        if targets
            .values()
            .any(|target| target.owner.database().unwrap().fixture_running_proposals() != 0)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        }
        let current = leader(targets).await;
        assert!(
            tokio::time::Instant::now() < deadline,
            "suspension observation exceeded the original setup deadline: {last_failure:?}"
        );
        let database = targets[&current].owner.database().unwrap();
        let generation = database.engine().generation().unwrap();
        if generation.state.suspended == suspended {
            assert_eq!(generation.state.policy_epoch, expected_epoch);
            return current;
        }
        assert_eq!(generation.state.policy_epoch, previous_epoch);
        drop(generation);
        assert!(
            tokio::time::Instant::now() < deadline,
            "suspension has no observed effect before the setup deadline: {last_failure:?}"
        );
        match database
            .administer(context.clone(), operation.clone())
            .await
        {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                ) =>
            {
                last_failure = Some(error);
            }
            Err(error) => panic!("target suspension rejected: {error:?}"),
        }
        // Success and uncertainty both resolve through the same current-state
        // observation; a changed leader never silently becomes a fresh effect.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Membership setup changes are state-idempotent, but leadership can change
/// after its observation. Keep the exact peer identities and one setup
/// deadline while recovering only Raft's explicit transient membership errors.
async fn exact_membership_change(
    targets: &BTreeMap<u64, Serving>,
    fact: &kasumi_types::TargetActivationFact,
    change: openraft::ChangeMembers<u64, kasumi_raft::BasicNode>,
) {
    use openraft::error::{ChangeMembershipError, ClientWriteError, RaftError};
    type MembershipError = RaftError<u64, ClientWriteError<u64, kasumi_raft::BasicNode>>;

    let deadline = tokio::time::Instant::now() + FIXTURE_OBSERVATION_WINDOW;
    let mut last_failure = None;
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "membership setup did not settle: {change:?}; last failure: {last_failure:?}"
        );
        let current = tokio::time::timeout_at(deadline, leader(targets))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "membership leader observation exceeded its original setup deadline: {change:?}; last failure: {last_failure:?}"
                )
            });
        assert!(
            tokio::time::Instant::now() < deadline,
            "membership observation exceeded its original setup deadline: {last_failure:?}"
        );
        let database = targets[&current].owner.database().unwrap();
        let group = database.raft_group();
        let covered = group.confirm_local_application(&fact.position).unwrap();
        let membership = covered.membership().membership();
        assert_eq!(
            membership.voter_ids().collect::<BTreeSet<_>>(),
            BTreeSet::from([1, 2, 3])
        );
        let applied = match &change {
            openraft::ChangeMembers::AddNodes(nodes) | openraft::ChangeMembers::SetNodes(nodes) => {
                nodes.iter().all(|(id, expected)| {
                    membership
                        .nodes()
                        .any(|(actual, node)| actual == id && node == expected)
                })
            }
            openraft::ChangeMembers::RemoveNodes(ids) => ids
                .iter()
                .all(|id| !membership.nodes().any(|(actual, _)| actual == id)),
            _ => panic!("fixture changes metadata only: {change:?}"),
        };
        drop(covered);
        assert!(
            tokio::time::Instant::now() < deadline,
            "applied membership observation exceeded its original setup deadline: {last_failure:?}"
        );
        if applied {
            return;
        }
        // These changes preserve voters and never wait for learner 4 to catch
        // up. A lost acknowledgement is resolved by the next applied-state read.
        let result = tokio::time::timeout_at(deadline, async {
            match &change {
                openraft::ChangeMembers::AddNodes(nodes) => {
                    assert_eq!(nodes.len(), 1);
                    let (&id, node) = nodes.first_key_value().unwrap();
                    group
                        .raft()
                        .add_learner(id, node.clone(), false)
                        .await
                        .map(|_| ())
                        .map_err(anyhow::Error::new)
                }
                openraft::ChangeMembers::RemoveNodes(ids) => {
                    assert_eq!(ids.len(), 1);
                    group.remove_learner(*ids.first().unwrap()).await
                }
                _ => group
                    .raft()
                    .change_membership(change.clone(), true)
                    .await
                    .map(|_| ())
                    .map_err(anyhow::Error::new),
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "membership dispatch exceeded its original setup deadline; outcome remains unresolved: {change:?}; last failure: {last_failure:?}"
            )
        });
        match result {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.downcast_ref::<MembershipError>(),
                    Some(MembershipError::APIError(
                        ClientWriteError::ForwardToLeader(_)
                    )) | Some(MembershipError::APIError(
                        ClientWriteError::ChangeMembershipError(ChangeMembershipError::InProgress(
                            _
                        ),)
                    ))
                ) =>
            {
                last_failure = Some(error)
            }
            Err(error) => panic!("membership setup rejected: {error:?}"),
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn assert_operational(
    targets: &BTreeMap<u64, Serving>,
    fact: &kasumi_types::TargetActivationFact,
    suspended: bool,
    learner: bool,
    changed_peer: u64,
) {
    tokio::time::timeout(FIXTURE_OBSERVATION_WINDOW, async {
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
        let id = set_suspension(&targets, true).await;
        // Commit the learner metadata without claiming catch-up or issuing a
        // serving capability to node 4. Three original voters remain a quorum.
        exact_membership_change(
            &targets,
            fact,
            openraft::ChangeMembers::AddNodes(BTreeMap::from([(
                4,
                kasumi_raft::BasicNode::new("learner-4"),
            )])),
        )
        .await;
        // AddNodes deliberately preserves an existing node's address. This
        // fixture updates the same physical voter's operational metadata; it
        // neither admits a replacement owner nor changes the voter set.
        exact_membership_change(
            &targets,
            fact,
            openraft::ChangeMembers::SetNodes(BTreeMap::from([(
                id,
                kasumi_raft::BasicNode::new("target-maintained"),
            )])),
        )
        .await;
        assert_operational(&targets, fact, true, true, id).await;
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
        set_suspension(&targets, false).await;
        exact_membership_change(
            &targets,
            fact,
            openraft::ChangeMembers::RemoveNodes(BTreeSet::from([4])),
        )
        .await;
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
