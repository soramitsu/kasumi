use super::*;
use kasumi_store::{NodeStore, StorageAccess, test_utils::LocalKeyProvider};

struct Installation {
    directory: tempfile::TempDir,
    node: Arc<NodeStore>,
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
    access: StorageAccess,
    incarnation: uuid::Uuid,
}
impl Installation {
    async fn new() -> anyhow::Result<Self> {
        let directory = tempfile::tempdir()?;
        let node = NodeStore::create_new(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )?;
        let incarnation = uuid::Uuid::new_v4();
        let access = StorageAccess::standalone(uuid::Uuid::new_v4(), "tenant", incarnation)?;
        let stores = TenantStorageSet::open(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([21; 32])),
            Arc::new(LocalKeyProvider::new([22; 32])),
            access.clone(),
        )
        .await?;
        let audit_store = TenantStore::open(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([23; 32])),
            StorageAccess::security_audit(),
        )
        .await?;
        let admission =
            crate::admission::NodeAdmission::with_fixed_memory(Default::default(), 2 << 30, 0)?;
        let audit = SecurityAudit::initialize(audit_store, Default::default(), admission)?;
        Ok(Self {
            directory,
            node,
            stores,
            audit,
            access,
            incarnation,
        })
    }
    async fn shutdown(&self) {
        self.stores.application().shutdown().await;
        self.stores.custody().store().shutdown().await;
        self.audit.shutdown().await;
    }
    fn seed_bootstrap(&self) -> anyhow::Result<()> {
        bind_deployment(&self.stores, b"local-v1")?;
        let engine = TenantEngine::new(
            "tenant".into(),
            self.incarnation.to_string(),
            policy(),
            Limits::default(),
        )?;
        persist_new(
            &self.stores,
            &engine.logical_snapshot(self.node.scratch_disk())?,
        )
    }
}

fn policy() -> Policy {
    Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        }],
        strict_read_audit: false,
    }
}

fn retained(stores: &TenantStorageSet) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
    let mut values = Vec::new();
    let first_chunk = 0u64.to_be_bytes();
    for store in [stores.application(), stores.custody().store()] {
        for (namespace, key) in [
            ("engine.deployment", b"mode".as_slice()),
            (NS, b"manifest"),
            (NS, first_chunk.as_slice()),
            ("raft.meta", b"application_bootstrap_sha256"),
            ("raft.meta", b"node_id"),
        ] {
            values.push(store.get(namespace, key)?);
        }
    }
    Ok(values)
}

#[tokio::test]
async fn existing_local_requires_both_local_bindings_and_an_initialized_bootstrap()
-> anyhow::Result<()> {
    let fixture = Installation::new().await?;
    for (app, custody) in [
        (None, None),
        (Some(b"local-v1".as_slice()), None),
        (None, Some(b"local-v1".as_slice())),
        (
            Some(b"local-v1".as_slice()),
            Some(b"replicated-v1".as_slice()),
        ),
        (Some(b"local-v1".as_slice()), Some(b"local-v1".as_slice())),
    ] {
        let op = |value: Option<&[u8]>| match value {
            Some(value) => WriteOp::put("engine.deployment", b"mode", value),
            None => WriteOp::delete("engine.deployment", b"mode"),
        };
        fixture.stores.write_batch(&[op(app)], &[op(custody)])?;
        let before = retained(&fixture.stores)?;
        assert!(
            open_existing_local(
                fixture.stores.clone(),
                fixture.audit.clone(),
                fixture.incarnation
            )
            .await
            .is_err()
        );
        assert_eq!(retained(&fixture.stores)?, before);
        assert!(load(fixture.stores.application())?.is_none());
    }
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn existing_local_rejects_corrupt_manifest_body_and_custody_commitment_without_repair()
-> anyhow::Result<()> {
    let fixture = Installation::new().await?;
    fixture.seed_bootstrap()?;
    let store = fixture.stores.application();
    let saved_manifest = store.get(NS, b"manifest")?.unwrap();
    let mut wrong: Manifest = serde_json::from_slice(&saved_manifest)?;
    wrong.format = 99;
    for malformed in [b"not-json".to_vec(), serde_json::to_vec(&wrong)?] {
        store.write_batch(&[WriteOp::put(NS, b"manifest", malformed)])?;
        let before = retained(&fixture.stores)?;
        assert!(
            open_existing_local(
                fixture.stores.clone(),
                fixture.audit.clone(),
                fixture.incarnation
            )
            .await
            .is_err()
        );
        assert_eq!(retained(&fixture.stores)?, before);
    }
    store.write_batch(&[WriteOp::put(NS, b"manifest", saved_manifest)])?;
    let saved_chunk = store.get(NS, &0u64.to_be_bytes())?.unwrap();
    let mut wrong = saved_chunk.clone();
    wrong[0] ^= 1;
    store.write_batch(&[WriteOp::put(NS, 0u64.to_be_bytes(), wrong)])?;
    let before = retained(&fixture.stores)?;
    assert!(
        open_existing_local(
            fixture.stores.clone(),
            fixture.audit.clone(),
            fixture.incarnation
        )
        .await
        .is_err()
    );
    assert_eq!(retained(&fixture.stores)?, before);
    store.write_batch(&[WriteOp::put(NS, 0u64.to_be_bytes(), saved_chunk)])?;
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[WriteOp::put(
            "raft.meta",
            b"application_bootstrap_sha256",
            b"\"wrong\"",
        )])?;
    let before = retained(&fixture.stores)?;
    assert!(
        open_existing_local(
            fixture.stores.clone(),
            fixture.audit.clone(),
            fixture.incarnation
        )
        .await
        .is_err()
    );
    assert_eq!(retained(&fixture.stores)?, before);
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_bootstrap_cannot_change_the_standalone_catalog_incarnation()
-> anyhow::Result<()> {
    let fixture = Installation::new().await?;
    bind_deployment(&fixture.stores, b"local-v1")?;
    let wrong = TenantEngine::new(
        "tenant".into(),
        uuid::Uuid::new_v4().to_string(),
        policy(),
        Limits::default(),
    )?;
    persist_new(
        &fixture.stores,
        &wrong.logical_snapshot(fixture.node.scratch_disk())?,
    )?;
    let before = retained(&fixture.stores)?;
    assert!(
        open_existing_local(
            fixture.stores.clone(),
            fixture.audit.clone(),
            fixture.incarnation
        )
        .await
        .is_err()
    );
    assert_eq!(retained(&fixture.stores)?, before);
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_local_reopens_the_same_committed_standalone_after_complete_shutdown()
-> anyhow::Result<()> {
    let fixture = Installation::new().await?;
    let database = open_local_with_incarnation(
        fixture.stores.clone(),
        policy(),
        Limits::default(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await?;
    let context = RequestContext {
        authorization: RequestAuthorization::service_identity(),
        tenant: "tenant".into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: "strict-reopen".into(),
    };
    database
        .administer(
            context,
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
    let expected_revision = database.engine().generation()?.state.revision;
    database.shutdown().await?;
    drop(database);
    fixture.shutdown().await;
    let Installation {
        directory,
        node,
        stores,
        audit,
        access,
        incarnation,
    } = fixture;
    drop(stores);
    drop(audit);
    drop(node);
    let node = NodeStore::open_existing(
        directory.path().join("node.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )?;
    let stores = TenantStorageSet::open_existing(
        node.clone(),
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([21; 32])),
        Arc::new(LocalKeyProvider::new([22; 32])),
        access,
    )
    .await?;
    let audit_store = TenantStore::open_existing(
        node,
        crate::SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([23; 32])),
        StorageAccess::security_audit(),
    )
    .await?;
    let audit = SecurityAudit::initialize(
        audit_store,
        Default::default(),
        crate::admission::NodeAdmission::with_fixed_memory(Default::default(), 2 << 30, 0)?,
    )?;
    let reopened = open_existing_local(stores.clone(), audit.clone(), incarnation).await?;
    let generation = reopened.engine().generation()?;
    assert_eq!(generation.state.incarnation, incarnation.to_string());
    assert_eq!(generation.state.revision, expected_revision);
    assert!(generation.state.collections.contains_key("retained"));
    drop(generation);
    reopened.shutdown().await?;
    drop(reopened);
    stores.application().shutdown().await;
    stores.custody().store().shutdown().await;
    audit.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn existing_control_requires_the_non_nil_configured_incarnation_before_startup()
-> anyhow::Result<()> {
    let fixture = Installation::new().await?;
    let stores = TenantStorageSet::open(
        fixture.node.clone(),
        "__kasumi_control".into(),
        Arc::new(LocalKeyProvider::new([24; 32])),
        Arc::new(LocalKeyProvider::new([25; 32])),
        StorageAccess::node_control(),
    )
    .await?;
    let actual = uuid::Uuid::new_v4();
    bind_deployment(&stores, b"local-v1")?;
    let engine = TenantEngine::new(
        "__kasumi_control".into(),
        actual.to_string(),
        policy(),
        Limits::default(),
    )?;
    persist_new(
        &stores,
        &engine.logical_snapshot(fixture.node.scratch_disk())?,
    )?;
    let before = retained(&stores)?;
    for (expected, message) in [
        (uuid::Uuid::nil(), "nil local incarnation"),
        (
            uuid::Uuid::new_v4(),
            "local incarnation differs from installed identity",
        ),
    ] {
        let error = open_existing_local(stores.clone(), fixture.audit.clone(), expected)
            .await
            .err()
            .expect("mismatched Control identity must fail");
        assert!(error.to_string().contains(message));
        assert_eq!(retained(&stores)?, before);
    }
    stores.application().shutdown().await;
    stores.custody().store().shutdown().await;
    fixture.shutdown().await;
    Ok(())
}
