use super::*;
use kasumi_store::{NodeStore, StorageAccess, test_utils::LocalKeyProvider};

fn installed() -> ReplicatedBootstrap {
    let nodes = (1..=3)
        .map(|id| {
            (
                id,
                crate::control::ControlNode {
                    endpoint: format!("https://control-{id}.example"),
                    failure_domain: format!("zone-{id}"),
                    certificate_pins: BTreeSet::from([format!("{id:064x}")]),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    ReplicatedBootstrap {
        genesis: ReplicatedGenesis::Control(ControlGenesis {
            topology: ControlTopology {
                nodes: nodes.clone(),
                tenants: BTreeMap::new(),
            },
            lifecycle: ControlLifecycleGenesis::Disabled,
        }),
        incarnation: uuid::Uuid::new_v4().to_string(),
        initial_policy: Policy {
            grants: vec![Grant {
                principal: "operator".into(),
                collection: None,
                actions: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
            }],
            strict_read_audit: true,
        },
        initial_limits: Limits::default(),
        voters: nodes
            .into_iter()
            .map(|(id, node)| {
                (
                    id,
                    ReplicaPlacement {
                        address: node.endpoint,
                        failure_domain: node.failure_domain,
                    },
                )
            })
            .collect(),
    }
}

#[test]
fn replicated_genesis_requires_explicit_tag_payload_and_lifecycle_kind() -> anyhow::Result<()> {
    let original = serde_json::to_value(installed())?;
    for field in ["genesis", "lifecycle"] {
        let mut value = original.clone();
        if field == "genesis" {
            value.as_object_mut().unwrap().remove(field);
        } else {
            value["genesis"]["control"]
                .as_object_mut()
                .unwrap()
                .remove(field);
        }
        assert!(serde_json::from_value::<ReplicatedBootstrap>(value).is_err());
    }
    for genesis in [
        serde_json::Value::Null,
        serde_json::json!({"kind":"old_control"}),
        serde_json::json!({"kind":"control"}),
        serde_json::json!({"kind":"application","control":{}}),
    ] {
        let mut value = original.clone();
        value["genesis"] = genesis;
        assert!(serde_json::from_value::<ReplicatedBootstrap>(value).is_err());
    }
    Ok(())
}

#[test]
fn control_genesis_is_deterministic_bounded_and_part_of_bootstrap_identity() -> anyhow::Result<()> {
    let original = installed();
    original.validate()?;
    let disk = kasumi_store::ScratchDisk::fixture();
    let first = original
        .genesis
        .engine(CONTROL_TENANT, &original)?
        .logical_snapshot(&disk)?;
    let second = original
        .genesis
        .engine(CONTROL_TENANT, &original)?
        .logical_snapshot(&disk)?;
    assert_eq!(first.sha256(), second.sha256());
    let decoded = TenantEngine::from_bootstrap(CONTROL_TENANT, &first)?;
    let generation = decoded.generation()?;
    let state = &generation.state;
    assert_eq!((state.revision, state.revision_base), (1, 1));
    assert_eq!(ControlPlane::applied_topology(state)?.version, 1);
    assert!(state.mutation_receipt_head.count == 0);
    let mut changed = original.clone();
    let ReplicatedGenesis::Control(control) = &mut changed.genesis else {
        unreachable!()
    };
    control.topology.nodes.get_mut(&1).unwrap().certificate_pins =
        BTreeSet::from(["ab".repeat(32)]);
    changed.validate()?;
    let changed_image = changed
        .genesis
        .engine(CONTROL_TENANT, &changed)?
        .logical_snapshot(&disk)?;
    assert_ne!(first.sha256(), changed_image.sha256());
    assert_ne!(staged_digest(&original)?, staged_digest(&changed)?);
    changed.initial_limits.max_document_bytes = 1;
    assert!(changed.genesis.engine(CONTROL_TENANT, &changed).is_err());
    assert!(original.genesis.engine("application", &original).is_err());
    Ok(())
}

#[test]
fn applied_control_requires_exact_schema_and_document_without_resetting_current_routes()
-> anyhow::Result<()> {
    let original = installed();
    let engine = original.genesis.engine(CONTROL_TENANT, &original)?;
    let original_state = engine.generation()?.state.clone();
    let mut state = original_state.clone();
    state.collections.remove("topology");
    assert!(ControlPlane::applied_topology(&state).is_err());
    let mut state = original_state.clone();
    state
        .collections
        .get_mut("topology")
        .unwrap()
        .documents
        .clear();
    assert!(ControlPlane::applied_topology(&state).is_err());
    let mut state = original_state.clone();
    state
        .collections
        .get_mut("topology")
        .unwrap()
        .definition
        .strict_read_audit = false;
    assert!(ControlPlane::applied_topology(&state).is_err());
    let mut state = original_state;
    let mut current = ControlPlane::applied_topology(&state)?.topology;
    current.nodes.get_mut(&1).unwrap().certificate_pins = BTreeSet::from(["cd".repeat(32)]);
    state
        .collections
        .get_mut("topology")
        .unwrap()
        .documents
        .insert(
            "current".into(),
            Arc::new(Document {
                id: "current".into(),
                version: 8,
                body: serde_json::to_value(&current)?,
            }),
        );
    assert_eq!(ControlPlane::applied_topology(&state)?.topology, current);
    assert_eq!(ControlPlane::applied_topology(&state)?.version, 8);
    Ok(())
}

async fn stores(
    node: Arc<NodeStore>,
    access: StorageAccess,
) -> anyhow::Result<Arc<TenantStorageSet>> {
    TenantStorageSet::initialize_catalogs(
        node,
        CONTROL_TENANT.into(),
        Arc::new(LocalKeyProvider::new([91; 32])),
        Arc::new(LocalKeyProvider::new([92; 32])),
        access,
    )
    .await
}
async fn audit(node: Arc<NodeStore>) -> anyhow::Result<Arc<SecurityAudit>> {
    let store = TenantStore::initialize_catalog(
        node,
        crate::SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([93; 32])),
        StorageAccess::security_audit(),
    )
    .await?;
    SecurityAudit::initialize(
        store,
        Default::default(),
        crate::admission::NodeAdmission::with_fixed_memory(Default::default(), 2 << 30, 0)?,
    )
}
fn retained(stores: &TenantStorageSet) -> anyhow::Result<String> {
    let mut digest = Sha256::new();
    for store in [stores.application(), stores.custody().store()] {
        for namespace in ["engine.deployment", NS, "raft.meta"] {
            store.visit(namespace, 8 << 20, |key, value| {
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
async fn control_genesis_rejects_wrong_storage_purpose_before_deployment_publication()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let node = NodeStore::create_new(
        directory.path().join("node.redb"),
        uuid::Uuid::new_v4(),
        kasumi_store::ScratchDisk::fixture(),
    )?;
    let pair = TenantStorageSet::initialize_catalogs_fixture(
        node.clone(),
        CONTROL_TENANT.into(),
        Arc::new(LocalKeyProvider::new([91; 32])),
        Arc::new(LocalKeyProvider::new([92; 32])),
    )
    .await?;
    let first_audit = audit(node.clone()).await?;
    let before = retained(&pair)?;
    assert!(
        open_replicated(
            1,
            pair.clone(),
            &installed(),
            Arc::new(kasumi_raft::InProcessRouter::default()),
            Config::default(),
            first_audit.clone()
        )
        .await
        .is_err()
    );
    assert_eq!(retained(&pair)?, before);
    pair.shutdown().await?;
    node.drain_initializers().await?;
    first_audit.shutdown().await?;
    drop(first_audit);
    drop(pair);
    drop(node);
    let node = NodeStore::create_new(
        directory.path().join("control.redb"),
        uuid::Uuid::new_v4(),
        kasumi_store::ScratchDisk::fixture(),
    )?;
    let pair = stores(node.clone(), StorageAccess::node_control()).await?;
    let second_audit = audit(node.clone()).await?;
    let before = retained(&pair)?;
    let mut wrong = installed();
    wrong.genesis = ReplicatedGenesis::Application;
    assert!(
        open_replicated(
            1,
            pair.clone(),
            &wrong,
            Arc::new(kasumi_raft::InProcessRouter::default()),
            Config::default(),
            second_audit.clone()
        )
        .await
        .is_err()
    );
    assert_eq!(retained(&pair)?, before);
    pair.shutdown().await?;
    node.drain_initializers().await?;
    second_audit.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn strict_control_reopen_rejects_partial_genesis_without_catalog_or_raft_mutation()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let node = NodeStore::create_new(
        directory.path().join("node.redb"),
        uuid::Uuid::new_v4(),
        kasumi_store::ScratchDisk::fixture(),
    )?;
    let pair = stores(node.clone(), StorageAccess::node_control()).await?;
    let audit = audit(node.clone()).await?;
    let installed = installed();
    bind_deployment(&pair, &serde_json::to_vec(&("replicated", &installed))?)?;
    let partial = TenantEngine::new(
        CONTROL_TENANT.into(),
        installed.incarnation.clone(),
        installed.initial_policy.clone(),
        installed.initial_limits.clone(),
    )?
    .logical_snapshot(node.scratch_disk())?;
    persist_new(&pair, &partial)?;
    let before = retained(&pair)?;
    let error = open_existing_replicated(
        1,
        pair.clone(),
        uuid::Uuid::parse_str(&installed.incarnation)?,
        Arc::new(kasumi_raft::InProcessRouter::default()),
        Config::default(),
        audit.clone(),
    )
    .await
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("immutable genesis"));
    assert_eq!(retained(&pair)?, before);
    assert!(kasumi_raft::ControlLog::installed(pair.custody().clone())?.is_none());
    pair.shutdown().await?;
    node.drain_initializers().await?;
    audit.shutdown().await?;
    Ok(())
}
