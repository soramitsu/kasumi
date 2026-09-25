use super::*;
use kasumi_store::{
    NodeReadPhase, NodeStore, StorageAccess, StorageCensusDisposition, TenantPointReadFailure,
    test_utils::LocalKeyProvider,
};

struct Installation {
    storage: crate::test_utils::FixtureStorage,
    node: Arc<NodeStore>,
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
    access: StorageAccess,
    incarnation: uuid::Uuid,
    directory: tempfile::TempDir,
}
impl Installation {
    async fn new() -> anyhow::Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (persistent_config, scratch_config) =
            crate::test_utils::fixture_disk_configs(directory.path())?;
        // Keep the 128 MiB ordinary margin available alongside the installed
        // security audit and maintenance owners. Add the physical metadata.
        let config = crate::admission::AdmissionConfig {
            max_inflight_bytes: Some(
                (384_u64 << 20)
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
        let node = storage.create_new(
            directory.path().join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )?;
        let incarnation = uuid::Uuid::new_v4();
        let access = StorageAccess::standalone(uuid::Uuid::new_v4(), "tenant", incarnation)?;
        let stores = TenantStorageSet::initialize_catalogs(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([21; 32])),
            Arc::new(LocalKeyProvider::new([22; 32])),
            access.clone(),
        )
        .await?;
        let audit_store = TenantStore::initialize_catalog(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([23; 32])),
            StorageAccess::security_audit(),
        )
        .await?;
        let audit = SecurityAudit::initialize(audit_store, Default::default(), admission)?;
        Ok(Self {
            directory,
            storage,
            node,
            stores,
            audit,
            access,
            incarnation,
        })
    }
    async fn shutdown(&self) {
        self.stores.shutdown().await.unwrap();
        self.audit.shutdown().await.unwrap();
        self.node.shutdown().await.unwrap();
    }
    fn seed_bootstrap(&self) -> anyhow::Result<()> {
        bind_deployment(&self.stores, b"local-v1")?;
        persist_new(&self.stores, &self.image()?)
    }
    fn image(&self) -> anyhow::Result<SnapshotImage> {
        let engine = TenantEngine::new(
            "tenant".into(),
            self.incarnation.to_string(),
            policy(),
            Limits::default(),
        )?;
        Ok(engine.logical_snapshot(self.node.scratch_disk())?)
    }
    fn first_publish(
        &self,
        image: &SnapshotImage,
        manifest_bytes: Vec<u8>,
        custody_digest: &str,
        first_chunk: Option<Vec<u8>>,
    ) -> anyhow::Result<()> {
        bind_deployment(&self.stores, b"local-v1")?;
        let mut reader = image.reader();
        let chunks = image.len().div_ceil(CHUNK as u64);
        for index in 0..chunks {
            let mut chunk =
                vec![0; (image.len() - index * CHUNK as u64).min(CHUNK as u64) as usize];
            reader.read_exact(&mut chunk)?;
            if index == 0 {
                chunk = first_chunk.clone().unwrap_or(chunk);
            }
            self.stores.application().write_batch(&[WriteOp::put(
                NS,
                index.to_be_bytes(),
                chunk,
            )])?;
        }
        let [node_id, group] = kasumi_raft::initial_storage_identity(
            1,
            &format!(
                "{}/{}",
                self.stores.application().tenant(),
                self.incarnation
            ),
        )?;
        self.stores.write_batch(
            &[WriteOp::put(NS, b"manifest", manifest_bytes)],
            &[
                WriteOp::put(
                    "raft.meta",
                    b"application_bootstrap_sha256",
                    serde_json::to_vec(custody_digest)?,
                ),
                node_id,
                group,
            ],
        )
    }
}

fn manifest_for(image: &SnapshotImage) -> Manifest {
    Manifest {
        format: 2,
        bytes: image.len(),
        chunks: image.len().div_ceil(CHUNK as u64),
        digest: image.sha256().to_owned(),
    }
}

fn assert_bounded_read_failure<T>(result: anyhow::Result<T>) {
    let error = match result {
        Ok(_) => panic!("oversized first publication passed a bounded read"),
        Err(error) => error,
    };
    let failure = error
        .downcast::<TenantPointReadFailure>()
        .expect("bounded read failure must retain its registered child");
    assert_eq!(failure.stage(), "record bytes");
    let reader = failure.into_reader();
    assert_eq!(reader.phase(), NodeReadPhase::Failed);
    assert_eq!(reader.finish(), NodeReadPhase::Finished);
    assert_eq!(reader.retire(), StorageCensusDisposition::Retired);
}

async fn reject_existing_local_without_repair(fixture: &Installation) -> anyhow::Result<()> {
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
    Ok(())
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

fn assert_rejected<T>(result: anyhow::Result<T>) {
    let error = match result {
        Ok(_) => panic!("corrupt bootstrap row was accepted"),
        Err(error) => error,
    };
    if let Ok(failure) = error.downcast::<kasumi_store::TenantPointReadFailure>() {
        assert_eq!(failure.stage(), "record bytes");
        let reader = failure.into_reader();
        assert_eq!(reader.finish(), kasumi_store::NodeReadPhase::Finished);
        assert_eq!(
            reader.retire(),
            kasumi_store::StorageCensusDisposition::Retired
        );
    }
}

#[tokio::test]
async fn bootstrap_manifest_rejects_alternate_and_oversized_rows_without_repair()
-> anyhow::Result<()> {
    let fixture = Installation::new().await?;
    fixture.seed_bootstrap()?;
    let store = fixture.stores.application();
    let canonical = store
        .get_bounded(NS, b"manifest", MAX_BOOTSTRAP_MANIFEST_BYTES)?
        .expect("current bootstrap manifest");
    let manifest = decode_current_manifest(&canonical)?;
    assert_eq!(persisted_bootstrap_digest(store)?, manifest.digest);
    assert!(load(store)?.is_some());
    let expected_workspace = recovery_workspace_bytes(&fixture.stores)?;
    assert!(expected_workspace >= manifest.bytes);
    assert!(load(store)?.is_some());
    assert_eq!(
        recovery_workspace_bytes(&fixture.stores)?,
        expected_workspace
    );
    fixture.shutdown().await;

    let reordered = format!(
        r#"{{"digest":{},"chunks":{},"bytes":{},"format":{}}}"#,
        serde_json::to_string(&manifest.digest)?,
        manifest.chunks,
        manifest.bytes,
        manifest.format
    )
    .into_bytes();
    let mut padded = canonical.clone();
    padded.push(b' ');
    let mut oversized = canonical.clone();
    oversized.resize(MAX_BOOTSTRAP_MANIFEST_BYTES + 1, b' ');
    for altered in [reordered, padded, oversized] {
        let fixture = Installation::new().await?;
        let image = fixture.image()?;
        let store = fixture.stores.application();
        fixture.first_publish(&image, altered.clone(), image.sha256(), None)?;
        if altered.len() > MAX_BOOTSTRAP_MANIFEST_BYTES {
            assert_bounded_read_failure(read_current_manifest(store));
            assert_bounded_read_failure(persisted_bootstrap_digest(store));
            assert_bounded_read_failure(load(store));
            assert_bounded_read_failure(recovery_workspace_bytes(&fixture.stores));
        } else {
            assert_rejected(read_current_manifest(store));
            assert_rejected(persisted_bootstrap_digest(store));
            assert_rejected(load(store));
            assert_rejected(recovery_workspace_bytes(&fixture.stores));
        }
        assert_eq!(store.get(NS, b"manifest")?, Some(altered));
        drop(image);
        fixture.shutdown().await;
    }
    let oversized_fixture = Installation::new().await?;
    let image = oversized_fixture.image()?;
    let oversized_chunk = vec![0; CHUNK + 1];
    oversized_fixture.first_publish(
        &image,
        serde_json::to_vec(&manifest_for(&image))?,
        image.sha256(),
        Some(oversized_chunk.clone()),
    )?;
    let first_chunk = 0u64.to_be_bytes();
    assert_bounded_read_failure(load(oversized_fixture.stores.application()));
    assert_eq!(
        oversized_fixture
            .stores
            .application()
            .get(NS, &first_chunk)?,
        Some(oversized_chunk)
    );
    drop(image);
    oversized_fixture.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn existing_local_requires_both_local_bindings_and_an_initialized_bootstrap()
-> anyhow::Result<()> {
    let fixture = Installation::new().await?;
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
    // A live facade can no longer manufacture one-sided or divergent first
    // installation. These attempts must leave the pristine pair untouched.
    let app = WriteOp::put("engine.deployment", b"mode", b"local-v1");
    let custody = WriteOp::put("engine.deployment", b"mode", b"replicated-v1");
    assert!(
        fixture
            .stores
            .write_batch(std::slice::from_ref(&app), &[])
            .is_err()
    );
    assert!(
        fixture
            .stores
            .write_batch(&[], std::slice::from_ref(&app))
            .is_err()
    );
    assert!(fixture.stores.write_batch(&[app], &[custody]).is_err());
    assert_eq!(retained(&fixture.stores)?, before);
    assert!(load(fixture.stores.application())?.is_none());
    fixture.shutdown().await;

    let fixture = Installation::new().await?;
    bind_deployment(&fixture.stores, b"local-v1")?;
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
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn existing_local_rejects_corrupt_manifest_body_and_custody_commitment_without_repair()
-> anyhow::Result<()> {
    for invalid_format in [false, true] {
        let fixture = Installation::new().await?;
        let image = fixture.image()?;
        let malformed = if invalid_format {
            let mut wrong = manifest_for(&image);
            wrong.format = 99;
            serde_json::to_vec(&wrong)?
        } else {
            b"not-json".to_vec()
        };
        fixture.first_publish(&image, malformed, image.sha256(), None)?;
        reject_existing_local_without_repair(&fixture).await?;
        drop(image);
        fixture.shutdown().await;
    }

    let fixture = Installation::new().await?;
    let image = fixture.image()?;
    let mut reader = image.reader();
    let mut corrupt_chunk = vec![0; image.len().min(CHUNK as u64) as usize];
    reader.read_exact(&mut corrupt_chunk)?;
    corrupt_chunk[0] ^= 1;
    drop(reader);
    fixture.first_publish(
        &image,
        serde_json::to_vec(&manifest_for(&image))?,
        image.sha256(),
        Some(corrupt_chunk),
    )?;
    reject_existing_local_without_repair(&fixture).await?;
    drop(image);
    fixture.shutdown().await;

    let fixture = Installation::new().await?;
    let image = fixture.image()?;
    fixture.first_publish(
        &image,
        serde_json::to_vec(&manifest_for(&image))?,
        "wrong",
        None,
    )?;
    reject_existing_local_without_repair(&fixture).await?;
    drop(image);
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
        storage,
        node,
        stores,
        audit,
        access,
        incarnation,
    } = fixture;
    drop(stores);
    drop(audit);
    drop(node);
    let node = storage.open_existing(
        directory.path().join("persistent/node.kv"),
        kasumi_store::test_utils::NODE_STORE_ID,
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
    let audit = SecurityAudit::open(audit_store, Default::default(), storage.admission.clone())?;
    let reopened = open_existing_local(stores.clone(), audit.clone(), incarnation).await?;
    let generation = reopened.engine().generation()?;
    assert_eq!(generation.state.incarnation, incarnation.to_string());
    assert_eq!(generation.state.revision, expected_revision);
    assert!(generation.state.collections.contains_key("retained"));
    drop(generation);
    reopened.shutdown().await?;
    drop(reopened);
    stores.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn existing_control_requires_the_non_nil_configured_incarnation_before_startup()
-> anyhow::Result<()> {
    let fixture = Installation::new().await?;
    let stores = TenantStorageSet::initialize_catalogs(
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
    stores.shutdown().await.unwrap();
    fixture.shutdown().await;
    Ok(())
}
