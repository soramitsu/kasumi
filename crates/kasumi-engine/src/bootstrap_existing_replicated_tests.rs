use super::*;
use kasumi_raft::InProcessRouter;
use kasumi_store::{NodeStore, test_utils::LocalKeyProvider};
use std::time::Duration;

const NODE_STORE_ID: uuid::Uuid = uuid::Uuid::from_u128(0xa1f9_93e5_2727_480a_9e7c_6e39_eb51_5f01);

struct Replica {
    storage: crate::test_utils::FixtureStorage,
    node: Arc<NodeStore>,
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
    directory: tempfile::TempDir,
}
impl Replica {
    async fn new() -> anyhow::Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (persistent_config, scratch_config) =
            crate::test_utils::fixture_disk_configs(directory.path())?;
        // The original fixed 2 GiB source resolves Default to a 256 MiB total.
        // Add only the new physical metadata; do not resolve against host RAM.
        let config = crate::admission::AdmissionConfig {
            max_inflight_bytes: Some(
                (256_u64 << 20)
                    .checked_add(crate::test_utils::isolated_disk_metadata_bytes(
                        &persistent_config,
                        &scratch_config,
                    )?)
                    .ok_or_else(|| anyhow::anyhow!("fixture metadata budget overflow"))?,
            ),
            ..Default::default()
        };
        let admission = crate::admission::NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
        let storage = crate::test_utils::FixtureStorage::with_admission(
            &persistent_config,
            &scratch_config,
            admission.clone(),
        )?;
        let node =
            storage.create_new(directory.path().join("persistent/node.kv"), NODE_STORE_ID)?;
        let stores = TenantStorageSet::initialize_catalogs_fixture(
            node.clone(),
            "replica".into(),
            Arc::new(LocalKeyProvider::new([31; 32])),
            Arc::new(LocalKeyProvider::new([32; 32])),
        )
        .await?;
        let audit = Self::audit(node.clone(), false, storage.admission.clone()).await?;
        Ok(Self {
            directory,
            storage,
            node,
            stores,
            audit,
        })
    }
    async fn existing(
        (directory, storage): (tempfile::TempDir, crate::test_utils::FixtureStorage),
    ) -> anyhow::Result<Self> {
        let node =
            storage.open_existing(directory.path().join("persistent/node.kv"), NODE_STORE_ID)?;
        let stores = TenantStorageSet::open_existing_fixture(
            node.clone(),
            "replica".into(),
            Arc::new(LocalKeyProvider::new([31; 32])),
            Arc::new(LocalKeyProvider::new([32; 32])),
        )
        .await?;
        let audit = Self::audit(node.clone(), true, storage.admission.clone()).await?;
        Ok(Self {
            directory,
            storage,
            node,
            stores,
            audit,
        })
    }
    async fn audit(
        node: Arc<NodeStore>,
        existing: bool,
        admission: Arc<crate::admission::NodeAdmission>,
    ) -> anyhow::Result<Arc<SecurityAudit>> {
        let provider = Arc::new(LocalKeyProvider::new([33; 32]));
        let store = if existing {
            TenantStore::open_existing_fixture(node, crate::SECURITY_TENANT.into(), provider)
                .await?
        } else {
            TenantStore::initialize_catalog_fixture(node, crate::SECURITY_TENANT.into(), provider)
                .await?
        };
        if existing {
            SecurityAudit::open(store, Default::default(), admission)
        } else {
            SecurityAudit::initialize(store, Default::default(), admission)
        }
    }
    async fn close(self) -> (tempfile::TempDir, crate::test_utils::FixtureStorage) {
        self.stores.shutdown().await.unwrap();
        self.audit.shutdown().await.unwrap();
        let Self {
            directory,
            storage,
            stores,
            audit,
            node,
        } = self;
        drop(stores);
        drop(audit);
        drop(node);
        (directory, storage)
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
        expected_incarnation: uuid::Uuid,
        expected: &str,
    ) -> anyhow::Result<()> {
        let before = retained(&self.stores)?;
        let error = open_existing_replicated(
            node_id,
            self.stores.clone(),
            expected_incarnation,
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
        genesis: crate::ReplicatedGenesis::Application,
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
        .reject(
            1,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            "required deployment binding",
        )
        .await?;
    bind_deployment(
        &fixture.stores,
        &serde_json::to_vec(&("replicated", &installed))?,
    )?;
    fixture
        .reject(
            1,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            "replicated bootstrap is not initialized",
        )
        .await?;
    fixture.seed(&installed, &installed.incarnation)?;
    fixture
        .reject(
            1,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            "consensus identity is not initialized",
        )
        .await?;
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[WriteOp::put("raft.meta", b"node_id", b"1")])?;
    fixture
        .reject(
            1,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            "consensus identity is incomplete",
        )
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
        .reject(
            2,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            "consensus identity differs",
        )
        .await?;
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[WriteOp::put("raft.meta", b"group", b"\"another/group\"")])?;
    fixture
        .reject(
            1,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            "consensus identity differs",
        )
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
        .reject(
            1,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            "invalid bootstrap manifest",
        )
        .await?;
    store.write_batch(&[WriteOp::put(NS, b"manifest", b"{")])?;
    fixture
        .reject(1, uuid::Uuid::parse_str(&installed.incarnation)?, "EOF")
        .await?;
    store.write_batch(&[WriteOp::put(NS, b"manifest", saved)])?;
    let chunk = store.get(NS, &0u64.to_be_bytes())?.unwrap();
    store.write_batch(&[WriteOp::delete(NS, 0u64.to_be_bytes())])?;
    fixture
        .reject(
            1,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            "incomplete bootstrap",
        )
        .await?;
    let mut corrupt = chunk.clone();
    corrupt[0] ^= 1;
    store.write_batch(&[WriteOp::put(NS, 0u64.to_be_bytes(), corrupt)])?;
    fixture
        .reject(
            1,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            "bootstrap digest mismatch",
        )
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
        .reject(
            1,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            "bootstrap/control identity differs",
        )
        .await?;
    drop(fixture.close().await);
    let fixture = Replica::new().await?;
    fixture.seed(&installed, &uuid::Uuid::new_v4().to_string())?;
    fixture
        .reject(
            1,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            "replicated incarnation differs from bootstrap",
        )
        .await?;
    drop(fixture.close().await);
    Ok(())
}

#[tokio::test]
async fn existing_replica_validates_authenticated_genesis_tag_domains_and_descriptor()
-> anyhow::Result<()> {
    let fixture = Replica::new().await?;
    let installed = bootstrap();
    let expected = uuid::Uuid::parse_str(&installed.incarnation)?;
    fixture.seed(&installed, &installed.incarnation)?;
    fixture
        .reject(1, uuid::Uuid::nil(), "nil expected replicated incarnation")
        .await?;
    fixture
        .reject(1, uuid::Uuid::new_v4(), "differs from expected incarnation")
        .await?;
    let binding = serde_json::to_vec(&("replicated", &installed))?;
    let replace = |bytes: &[u8]| {
        fixture.stores.write_batch(
            &[WriteOp::put("engine.deployment", b"mode", bytes)],
            &[WriteOp::put("engine.deployment", b"mode", bytes)],
        )
    };
    replace(&serde_json::to_vec(&("local", &installed))?)?;
    fixture
        .reject(1, expected, "unsupported replicated deployment tag")
        .await?;
    replace(b"{")?;
    fixture.reject(1, expected, "invalid type").await?;
    let canonical = std::str::from_utf8(&binding)?;
    replace(canonical.replace("\"1\":", "\"01\":").as_bytes())?;
    fixture
        .reject(1, expected, "noncanonical or duplicate object key")
        .await?;

    for field in 0..5 {
        let mut invalid = installed.clone();
        let diagnostic = match field {
            0 => {
                invalid.incarnation = uuid::Uuid::nil().to_string();
                "nil replicated incarnation"
            }
            1 => {
                invalid.voters.remove(&3);
                "exactly three initial voters"
            }
            2 => {
                invalid.voters.get_mut(&2).unwrap().failure_domain = "zone-1".into();
                "independent failure domains"
            }
            3 => {
                invalid.initial_policy.grants.clear();
                "tenant needs an administrator"
            }
            4 => {
                invalid.initial_limits.history.max_feed_events = 0;
                "invalid history resource limits"
            }
            _ => unreachable!(),
        };
        replace(&serde_json::to_vec(&("replicated", &invalid))?)?;
        fixture.reject(1, expected, diagnostic).await?;
    }
    let mut whitespace = binding.clone();
    whitespace.push(b' ');
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&whitespace)?,
        serde_json::from_slice::<serde_json::Value>(&binding)?
    );
    replace(&whitespace)?;
    fixture
        .reject(1, expected, "noncanonical replicated deployment binding")
        .await?;
    replace(&binding)?;
    let restored = installed_replicated_bootstrap(&fixture.stores, expected)?;
    assert_eq!(serde_json::to_vec(&("replicated", &restored))?, binding);
    let mut substituted = installed.clone();
    substituted.voters.get_mut(&1).unwrap().address = "tampered-domain".into();
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[WriteOp::put(
            "engine.deployment",
            b"mode",
            serde_json::to_vec(&("replicated", substituted))?,
        )])?;
    fixture
        .reject(1, expected, "differs across domains")
        .await?;
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[WriteOp::delete("engine.deployment", b"mode")])?;
    fixture
        .reject(1, expected, "required deployment binding")
        .await?;
    drop(fixture.close().await);
    Ok(())
}

#[tokio::test]
async fn target_deployment_requires_bounded_paired_current_writer_bytes() -> anyhow::Result<()> {
    let fixture = Replica::new().await?;
    let installed = bootstrap();
    let binding = serde_json::to_vec(&("replicated", &installed))?;
    bind_deployment(&fixture.stores, &binding)?;
    let custody = fixture
        .stores
        .custody()
        .store()
        .get_bounded("engine.deployment", b"mode", 256 << 10)?
        .expect("installed custody deployment");
    assert_eq!(custody, binding);
    let decoded = decode_current_target_deployment(&fixture.stores, &custody)?;
    assert_eq!(serde_json::to_vec(&("replicated", &decoded))?, binding);

    let mut alternate = binding.clone();
    alternate.push(b' ');
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&alternate)?,
        serde_json::from_slice::<serde_json::Value>(&binding)?
    );
    fixture.stores.application().write_batch(&[WriteOp::put(
        "engine.deployment",
        b"mode",
        alternate.as_slice(),
    )])?;
    let before = retained(&fixture.stores)?;
    let Err(error) = decode_current_target_deployment(&fixture.stores, &custody) else {
        panic!("target reader accepted divergent deployment copies");
    };
    assert!(
        format!("{error:#}").contains("differs across domains"),
        "{error:#}"
    );
    assert_eq!(retained(&fixture.stores)?, before);

    fixture.stores.write_batch(
        &[WriteOp::put(
            "engine.deployment",
            b"mode",
            alternate.as_slice(),
        )],
        &[WriteOp::put(
            "engine.deployment",
            b"mode",
            alternate.as_slice(),
        )],
    )?;
    let altered_custody = fixture
        .stores
        .custody()
        .store()
        .get_bounded("engine.deployment", b"mode", 256 << 10)?
        .expect("installed custody deployment");
    let before = retained(&fixture.stores)?;
    let Err(error) = decode_current_target_deployment(&fixture.stores, &altered_custody) else {
        panic!("target reader accepted equivalent alternate deployment bytes");
    };
    assert!(
        format!("{error:#}").contains("noncanonical replicated deployment binding"),
        "{error:#}"
    );
    assert_eq!(retained(&fixture.stores)?, before);

    fixture.stores.write_batch(
        &[WriteOp::put(
            "engine.deployment",
            b"mode",
            binding.as_slice(),
        )],
        &[WriteOp::put(
            "engine.deployment",
            b"mode",
            binding.as_slice(),
        )],
    )?;
    let restored = decode_current_target_deployment(&fixture.stores, &binding)?;
    assert_eq!(serde_json::to_vec(&("replicated", &restored))?, binding);
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
    for id in 1..=4 {
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
    nodes[&first]
        .raft_group()
        .add_learner(4, BasicNode::new("relocated-4"))
        .await?;
    // Keep the current leader in the replacement voter set, avoiding an
    // intentionally ambiguous leader-removal response in this reopen fixture.
    let removed = (1..=3).find(|id| *id != first).unwrap();
    let voters = (1..=4).filter(|id| *id != removed).collect::<BTreeSet<_>>();
    nodes[&first]
        .raft_group()
        .change_membership(voters.clone())
        .await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if voters.iter().all(|id| {
                let node = &nodes[id];
                node.engine()
                    .generation()
                    .is_ok_and(|generation| generation.state.revision == revision)
                    && node
                        .raft_group()
                        .raft()
                        .metrics()
                        .borrow()
                        .membership_config
                        .membership()
                        .voter_ids()
                        .collect::<BTreeSet<_>>()
                        == voters
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
        if id == removed {
            drop(directory);
            continue;
        }
        let fixture = Replica::existing(directory).await?;
        let opened = open_existing_replicated(
            id,
            fixture.stores.clone(),
            uuid::Uuid::parse_str(&installed.incarnation)?,
            router.clone(),
            raft_config(),
            fixture.audit.clone(),
        )
        .await?;
        assert_eq!(
            serde_json::to_vec(&opened.bootstrap)?,
            serde_json::to_vec(&installed)?
        );
        let binding = serde_json::to_vec(&("replicated", &installed))?;
        require_deployment(&fixture.stores, &binding)?;
        let database = opened.database;
        // This is a no-op for recovered membership, even at an original voter.
        initialize_replicated(&database, &opened.bootstrap).await?;
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
            voters.iter().copied().collect::<Vec<_>>()
        );
        assert_eq!(
            metrics
                .membership_config
                .membership()
                .get_node(&4)
                .unwrap()
                .addr,
            "relocated-4"
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
