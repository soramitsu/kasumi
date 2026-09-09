use super::*;
use kasumi_raft::InProcessRouter;
use kasumi_store::{NodeStore, test_utils::LocalKeyProvider};
use std::time::Duration;

struct Replica {
    directory: tempfile::TempDir,
    node: Arc<NodeStore>,
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
}
impl Replica {
    async fn new() -> anyhow::Result<Self> {
        let directory = tempfile::tempdir()?;
        let node = NodeStore::open(
            directory.path().join("node.redb"),
            kasumi_store::ScratchDisk::fixture(),
        )?;
        let stores = TenantStorageSet::open_fixture(
            node.clone(),
            "replica".into(),
            Arc::new(LocalKeyProvider::new([31; 32])),
            Arc::new(LocalKeyProvider::new([32; 32])),
        )
        .await?;
        let audit = Self::audit(node.clone(), false).await?;
        Ok(Self {
            directory,
            node,
            stores,
            audit,
        })
    }
    async fn existing(directory: tempfile::TempDir) -> anyhow::Result<Self> {
        let node = NodeStore::open_existing(
            directory.path().join("node.redb"),
            kasumi_store::ScratchDisk::fixture(),
        )?;
        let stores = TenantStorageSet::open_existing_fixture(
            node.clone(),
            "replica".into(),
            Arc::new(LocalKeyProvider::new([31; 32])),
            Arc::new(LocalKeyProvider::new([32; 32])),
        )
        .await?;
        let audit = Self::audit(node.clone(), true).await?;
        Ok(Self {
            directory,
            node,
            stores,
            audit,
        })
    }
    async fn audit(node: Arc<NodeStore>, existing: bool) -> anyhow::Result<Arc<SecurityAudit>> {
        let provider = Arc::new(LocalKeyProvider::new([33; 32]));
        let store = if existing {
            TenantStore::open_existing_fixture(node, crate::SECURITY_TENANT.into(), provider)
                .await?
        } else {
            TenantStore::open_fixture(node, crate::SECURITY_TENANT.into(), provider).await?
        };
        SecurityAudit::open(
            store,
            Default::default(),
            crate::admission::NodeAdmission::with_fixed_memory(Default::default(), 2 << 30, 0)?,
        )
    }
    async fn close(self) -> tempfile::TempDir {
        self.stores.application().shutdown().await;
        self.stores.custody().store().shutdown().await;
        self.audit.shutdown().await;
        let Self {
            directory,
            stores,
            audit,
            node,
        } = self;
        drop(stores);
        drop(audit);
        drop(node);
        directory
    }
    fn seed(
        &self,
        installed: &ReplicatedBootstrap,
        actual_incarnation: &str,
    ) -> anyhow::Result<()> {
        bind_deployment(
            &self.stores,
            &serde_json::to_vec(&("replicated", installed))?,
        )?;
        let engine = TenantEngine::new(
            "replica".into(),
            actual_incarnation.into(),
            installed.initial_policy.clone(),
            installed.initial_limits.clone(),
        )?;
        persist_new(
            &self.stores,
            &engine.logical_snapshot(self.node.scratch_disk())?,
        )
    }
    async fn reject(
        &self,
        node_id: u64,
        installed: &ReplicatedBootstrap,
        expected: &str,
    ) -> anyhow::Result<()> {
        let before = retained(&self.stores)?;
        let error = open_existing_replicated(
            node_id,
            self.stores.clone(),
            installed,
            Arc::new(InProcessRouter::default()),
            raft_config(),
            self.audit.clone(),
        )
        .await
        .err()
        .expect("invalid existing replica must fail");
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert_eq!(retained(&self.stores)?, before);
        Ok(())
    }
}

fn bootstrap() -> ReplicatedBootstrap {
    ReplicatedBootstrap {
        incarnation: uuid::Uuid::new_v4().to_string(),
        initial_policy: Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: BTreeSet::from([Action::Admin]),
            }],
            strict_read_audit: false,
        },
        initial_limits: Limits::default(),
        voters: (1..=3)
            .map(|id| {
                (
                    id,
                    ReplicaPlacement {
                        address: format!("replica-{id}"),
                        failure_domain: format!("zone-{id}"),
                    },
                )
            })
            .collect(),
    }
}
fn raft_config() -> Config {
    Config {
        election_timeout_min: 200,
        election_timeout_max: 400,
        heartbeat_interval: 50,
        ..Default::default()
    }
}
fn retained(stores: &TenantStorageSet) -> anyhow::Result<String> {
    let mut digest = Sha256::new();
    for (index, store) in [stores.application(), stores.custody().store()]
        .into_iter()
        .enumerate()
    {
        digest.update((index as u64).to_be_bytes());
        for namespace in [
            NS,
            "engine.deployment",
            "engine.audit.placement",
            "raft.meta",
            "raft.headers",
        ] {
            digest.update(namespace.as_bytes());
            store.visit(namespace, 16 << 20, |key, value| {
                digest.update((key.len() as u64).to_be_bytes());
                digest.update(key);
                digest.update((value.len() as u64).to_be_bytes());
                digest.update(value);
                Ok(())
            })?;
        }
    }
    Ok(hex::encode(digest.finalize()))
}

#[tokio::test]
async fn existing_replica_never_creates_missing_bootstrap_or_consensus_identity()
-> anyhow::Result<()> {
    let fixture = Replica::new().await?;
    let installed = bootstrap();
    fixture
        .reject(1, &installed, "required deployment binding")
        .await?;
    bind_deployment(
        &fixture.stores,
        &serde_json::to_vec(&("replicated", &installed))?,
    )?;
    fixture
        .reject(1, &installed, "replicated bootstrap is not initialized")
        .await?;
    fixture.seed(&installed, &installed.incarnation)?;
    fixture
        .reject(1, &installed, "consensus identity is not initialized")
        .await?;
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[WriteOp::put("raft.meta", b"node_id", b"1")])?;
    fixture
        .reject(1, &installed, "consensus identity is incomplete")
        .await?;
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[WriteOp::put(
            "raft.meta",
            b"group",
            serde_json::to_vec(&format!("replica/{}", installed.incarnation))?,
        )])?;
    fixture
        .reject(2, &installed, "consensus identity differs")
        .await?;
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[WriteOp::put("raft.meta", b"group", b"\"another/group\"")])?;
    fixture
        .reject(1, &installed, "consensus identity differs")
        .await?;
    drop(fixture.close().await);
    Ok(())
}

#[tokio::test]
async fn existing_replica_rejects_corrupt_manifest_body_and_authenticated_incarnation()
-> anyhow::Result<()> {
    let fixture = Replica::new().await?;
    let installed = bootstrap();
    fixture.seed(&installed, &installed.incarnation)?;
    let store = fixture.stores.application();
    let saved = store.get(NS, b"manifest")?.unwrap();
    let mut wrong: Manifest = serde_json::from_slice(&saved)?;
    wrong.format = 99;
    store.write_batch(&[WriteOp::put(NS, b"manifest", serde_json::to_vec(&wrong)?)])?;
    fixture
        .reject(1, &installed, "invalid bootstrap manifest")
        .await?;
    store.write_batch(&[WriteOp::put(NS, b"manifest", b"{")])?;
    fixture.reject(1, &installed, "EOF").await?;
    store.write_batch(&[WriteOp::put(NS, b"manifest", saved)])?;
    let chunk = store.get(NS, &0u64.to_be_bytes())?.unwrap();
    store.write_batch(&[WriteOp::delete(NS, 0u64.to_be_bytes())])?;
    fixture
        .reject(1, &installed, "incomplete bootstrap")
        .await?;
    let mut corrupt = chunk.clone();
    corrupt[0] ^= 1;
    store.write_batch(&[WriteOp::put(NS, 0u64.to_be_bytes(), corrupt)])?;
    fixture
        .reject(1, &installed, "bootstrap digest mismatch")
        .await?;
    store.write_batch(&[WriteOp::put(NS, 0u64.to_be_bytes(), chunk)])?;
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[WriteOp::put(
            "raft.meta",
            b"application_bootstrap_sha256",
            b"\"wrong\"",
        )])?;
    fixture
        .reject(1, &installed, "bootstrap/control identity differs")
        .await?;
    drop(fixture.close().await);
    let fixture = Replica::new().await?;
    fixture.seed(&installed, &uuid::Uuid::new_v4().to_string())?;
    fixture
        .reject(
            1,
            &installed,
            "replicated incarnation differs from bootstrap",
        )
        .await?;
    drop(fixture.close().await);
    Ok(())
}

#[tokio::test]
async fn existing_replica_preserves_immutable_initial_placement_and_configuration()
-> anyhow::Result<()> {
    let fixture = Replica::new().await?;
    let installed = bootstrap();
    fixture.seed(&installed, &installed.incarnation)?;
    for field in 0..6 {
        let mut changed = installed.clone();
        match field {
            0 => changed.incarnation = uuid::Uuid::new_v4().to_string(),
            1 => changed.voters.get_mut(&1).unwrap().address = "substitution".into(),
            2 => changed.voters.get_mut(&1).unwrap().failure_domain = "other-zone".into(),
            3 => {
                let member = changed.voters.remove(&3).unwrap();
                changed.voters.insert(4, member);
            }
            4 => changed.initial_policy.grants[0].principal = "replacement-admin".into(),
            5 => changed.initial_limits.max_document_bytes += 1,
            _ => unreachable!(),
        }
        fixture
            .reject(1, &changed, "required deployment binding")
            .await?;
    }
    let mut nil = installed.clone();
    nil.incarnation = uuid::Uuid::nil().to_string();
    fixture
        .reject(1, &nil, "nil replicated incarnation")
        .await?;
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[WriteOp::delete("engine.deployment", b"mode")])?;
    fixture
        .reject(1, &installed, "required deployment binding")
        .await?;
    drop(fixture.close().await);
    Ok(())
}

async fn leader(nodes: &BTreeMap<u64, Arc<Database>>) -> anyhow::Result<u64> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for (&id, node) in nodes {
                if node.raft_group().raft().metrics().borrow().current_leader == Some(id)
                    && matches!(
                        tokio::time::timeout(
                            Duration::from_millis(200),
                            node.raft_group().linearizable_barrier()
                        )
                        .await,
                        Ok(Ok(_))
                    )
                {
                    return id;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_replicas_replay_committed_state_and_membership_after_full_close()
-> anyhow::Result<()> {
    let installed = bootstrap();
    let group = format!("replica/{}", installed.incarnation);
    let router = Arc::new(InProcessRouter::default());
    let mut fixtures = BTreeMap::new();
    let mut nodes = BTreeMap::new();
    for id in 1..=3 {
        let fixture = Replica::new().await?;
        let database = fixtures::open_fixture_replicated(
            id,
            fixture.stores.clone(),
            &installed,
            router.clone(),
            raft_config(),
            fixture.audit.clone(),
        )
        .await?;
        router.register(group.clone(), id, database.raft_group().raft().clone());
        nodes.insert(id, database);
        fixtures.insert(id, fixture);
    }
    initialize_replicated(&nodes[&1], &installed).await?;
    let first = leader(&nodes).await?;
    nodes[&first]
        .administer(
            RequestContext {
                authorization: RequestAuthorization::service_identity(),
                tenant: "replica".into(),
                principal: "owner".into(),
                scopes: BTreeSet::from([Action::Admin]),
                request_id: "strict-replica".into(),
            },
            Operation::CreateCollection(CollectionDefinition {
                name: "retained".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await?;
    let revision = nodes[&first].engine().generation()?.state.revision;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if nodes.values().all(|node| {
                node.engine()
                    .generation()
                    .is_ok_and(|generation| generation.state.revision == revision)
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    for (&id, node) in &nodes {
        router.unregister(&group, id);
        node.shutdown().await?;
    }
    nodes.clear();
    let mut directories = BTreeMap::new();
    for (id, fixture) in fixtures {
        directories.insert(id, fixture.close().await);
    }
    let mut reopened = BTreeMap::new();
    for (id, directory) in directories {
        let fixture = Replica::existing(directory).await?;
        let database = open_existing_replicated(
            id,
            fixture.stores.clone(),
            &installed,
            router.clone(),
            raft_config(),
            fixture.audit.clone(),
        )
        .await?;
        let generation = database.engine().generation()?;
        assert_eq!(generation.state.incarnation, installed.incarnation);
        assert_eq!(generation.state.revision, revision);
        assert!(generation.state.collections.contains_key("retained"));
        let metrics = database.raft_group().raft().metrics().borrow().clone();
        assert_eq!(
            metrics
                .membership_config
                .membership()
                .voter_ids()
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        router.register(group.clone(), id, database.raft_group().raft().clone());
        nodes.insert(id, database);
        reopened.insert(id, fixture);
    }
    leader(&nodes).await?;
    for (&id, node) in &nodes {
        router.unregister(&group, id);
        node.shutdown().await?;
    }
    nodes.clear();
    for (_, fixture) in reopened {
        drop(fixture.close().await);
    }
    Ok(())
}
