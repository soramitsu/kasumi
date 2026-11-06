use super::*;
use kasumi_store::{
    NodeReadPhase, NodeStore, StorageAccess, StorageCensusDisposition, TenantPointReadFailure,
    test_utils::LocalKeyProvider,
};

struct Installation {
    storage: crate::test_utils::FixtureStorage,
    node: NodeStore,
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
    access: StorageAccess,
    incarnation: uuid::Uuid,
    directory: tempfile::TempDir,
}
impl Installation {
    async fn new() -> crate::test_fixture_failure::FixtureResult<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (persistent_config, scratch_config) =
            crate::test_utils::fixture_disk_configs(directory.path())?;
        // The positive installation admits its actual fixed owners and all
        // mandatory floors separately from the declared workload allowance.
        let config = super::existing_replicated_tests::replica_budget::planned_config(
            &persistent_config,
            &scratch_config,
        )?;
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
        // Like a production installer, select the audit placement before any open.
        crate::test_utils::install_local_replica_audit_placement(stores.application())?;
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
    async fn reopen(self) -> crate::test_fixture_failure::FixtureResult<Self> {
        self.shutdown().await;
        let Self {
            directory,
            storage,
            node,
            stores,
            audit,
            access,
            incarnation,
        } = self;
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
            access.clone(),
        )
        .await?;
        crate::test_utils::install_local_replica_audit_placement(stores.application())?;
        let audit_store = TenantStore::open_existing(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([23; 32])),
            StorageAccess::security_audit(),
        )
        .await?;
        let audit =
            SecurityAudit::open(audit_store, Default::default(), storage.admission.clone())?;
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
    #[allow(
        clippy::result_large_err,
        reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
    )]
    fn seed_bootstrap(&self) -> crate::test_fixture_failure::FixtureResult<()> {
        bind_deployment(&self.stores, b"local-v1")?;
        Ok(persist_new(&self.stores, &self.image()?)?)
    }
    #[allow(
        clippy::result_large_err,
        reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
    )]
    fn image(&self) -> crate::test_fixture_failure::FixtureResult<SnapshotImage> {
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
        manifest_bytes: impl AsRef<[u8]>,
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
        let manifest_bytes = manifest_bytes.as_ref();
        let _manifest_copy = self
            .stores
            .application()
            .plaintext_memory_owner()
            .clone()
            .reserve_installed(
                (NS.len() + b"manifest".len() + manifest_bytes.len()) as u64
                    + 3 * kasumi_store::DiskMemoryLease::token_allocation_bytes::<u8>()?,
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

fn manifest_for(image: &SnapshotImage) -> ApplicationBootstrapManifest {
    ApplicationBootstrapManifest {
        format: 2,
        bytes: image.len(),
        chunks: image.len().div_ceil(CHUNK as u64),
        digest: image.sha256().to_owned(),
    }
}

fn assert_bounded_read_failure<T, E: Into<crate::SnapshotFailure>>(
    result: std::result::Result<T, E>,
) {
    let error = match result {
        Ok(_) => panic!("oversized first publication passed a bounded read"),
        Err(error) => error.into(),
    };
    let crate::SnapshotFailure::Source(error) = error else {
        panic!("bounded read lost its original registered ordinary diagnostic: {error:?}")
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

async fn reject_existing_local_without_repair(
    fixture: &Installation,
) -> crate::test_fixture_failure::FixtureResult<()> {
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

fn retained(
    stores: &TenantStorageSet,
) -> anyhow::Result<Vec<Option<kasumi_store::PlaintextValue>>> {
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

fn assert_rejected<T, E: Into<crate::SnapshotFailure>>(result: std::result::Result<T, E>) {
    let error = match result {
        Ok(_) => panic!("corrupt bootstrap row was accepted"),
        Err(error) => error.into(),
    };
    assert!(
        error.creation().is_none(),
        "logical rejection changed to creation failure: {error:?}"
    );
    if let crate::SnapshotFailure::Source(error) = error
        && let Ok(failure) = error.downcast::<kasumi_store::TenantPointReadFailure>()
    {
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn bootstrap_manifest_rejects_alternate_and_oversized_rows_without_repair()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Installation::new().await?;
    fixture.seed_bootstrap()?;
    let store = fixture.stores.application();
    let canonical = store
        .get_bounded(NS, b"manifest", MAX_BOOTSTRAP_MANIFEST_BYTES)?
        .expect("current bootstrap manifest");
    let manifest = ApplicationBootstrapManifest::decode(&canonical)?;
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
    let padded = kasumi_store::test_utils::FixturePlaintextCopy::with_suffix(
        fixture.stores.application(),
        canonical.as_bytes(),
        b" ",
    )?;
    let oversized = kasumi_store::test_utils::FixturePlaintextCopy::resized(
        fixture.stores.application(),
        canonical.as_bytes(),
        MAX_BOOTSTRAP_MANIFEST_BYTES + 1,
        b' ',
    )?;
    for altered in [
        reordered.as_slice(),
        padded.as_bytes(),
        oversized.as_bytes(),
    ] {
        let fixture = Installation::new().await?;
        let image = fixture.image()?;
        let store = fixture.stores.application();
        fixture.first_publish(&image, altered, image.sha256(), None)?;
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
        assert_eq!(store.get(NS, b"manifest")?.as_deref(), Some(altered));
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
            .get(NS, &first_chunk)?
            .as_deref(),
        Some(oversized_chunk.as_slice())
    );
    drop(image);
    oversized_fixture.shutdown().await;
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn existing_local_requires_both_local_bindings_and_an_initialized_bootstrap()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Installation::new().await?;
    let before = retained(&fixture.stores)?;
    let missing = open_existing_local(
        fixture.stores.clone(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await
    .err()
    .expect("missing deployment binding must reject");
    let original = missing
        .operation_error()
        .expect("native-free corruption error");
    assert_eq!(original.code, ErrorCode::Corruption);
    assert_eq!(
        original.message,
        "required deployment binding is absent or differs"
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn existing_local_rejects_corrupt_manifest_body_and_custody_commitment_without_repair()
-> crate::test_fixture_failure::FixtureResult<()> {
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn authenticated_bootstrap_cannot_change_the_standalone_catalog_incarnation()
-> crate::test_fixture_failure::FixtureResult<()> {
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

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn installed_engine_generation_rejects_closed_original_store()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Installation::new().await?;
    let image = fixture.image()?;
    let engine = TenantEngine::from_bootstrap("tenant", &image)?;
    engine.install_storage_access(fixture.stores.application())?;
    assert!(Arc::ptr_eq(
        engine.snapshot_store.get().unwrap(),
        fixture.stores.application()
    ));
    let retained = engine.generation()?;
    assert_eq!(retained.tenant(), "tenant");
    assert_eq!(retained.incarnation(), fixture.incarnation.to_string());
    assert_eq!(retained.revision(), 0);
    assert!(engine.snapshot_bytes()? > 0);

    // No Database or asynchronous seal monitor exists for this Engine. Its
    // independent standalone capability stays valid after the real Store closes.
    fixture.stores.application().seal();
    let denied = fixture.stores.application().check_access().unwrap_err();
    assert!(denied.is::<kasumi_store::KeyAccessDenied>());
    assert_eq!(denied.chain().count(), 1);
    fixture.access.check()?;
    assert_eq!(engine.generation().err().unwrap().code, ErrorCode::Sealed);
    assert_eq!(engine.snapshot_bytes().unwrap_err().code, ErrorCode::Sealed);
    // This acquisition holds apply_lock before checking the original Store.
    // The denied path must return without recursively entering Engine::seal.
    let denied_restore = engine.restore_candidate(&image).unwrap_err();
    assert!(denied_restore.creation().is_none());
    assert!(denied_restore.source_error().is_none());
    assert_eq!(
        denied_restore.operation_error().unwrap().code,
        ErrorCode::Sealed
    );

    drop(retained);
    drop(engine);
    drop(image);
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn empty_local_reopens_without_an_election_noop_or_revision_change()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Installation::new().await?;
    let database = open_local_with_incarnation(
        fixture.stores.clone(),
        policy(),
        Limits::default(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await?;
    let revision = database.engine().generation()?.state.revision;
    assert_eq!(revision, 0);
    assert!(database.raft_group().try_raft().is_none());
    database.shutdown().await?;
    drop(database);
    let fixture = fixture.reopen().await?;
    let database = open_existing_local(
        fixture.stores.clone(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await?;
    assert!(database.raft_group().try_raft().is_none());
    assert_eq!(database.engine().generation()?.state.revision, revision);
    assert!(
        database
            .raft_group()
            .linearizable_barrier()
            .await?
            .is_some()
    );
    database.shutdown().await?;
    drop(database);
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn existing_local_reopens_the_same_committed_standalone_after_complete_shutdown()
-> crate::test_fixture_failure::FixtureResult<()> {
    use anyhow::Context as _;
    let fixture = Installation::new().await?;
    let database = open_local_with_incarnation(
        fixture.stores.clone(),
        policy(),
        Limits::default(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await
    .map_err(
        |original| crate::test_fixture_failure::FixtureFailure::SnapshotContext {
            context: "local reopen fixture: initial Database startup",
            original,
        },
    )?;
    assert!(database.raft_group().is_local());
    assert!(database.raft_group().try_raft().is_none());
    let context = RequestContext {
        authorization: RequestAuthorization::service_identity(),
        tenant: "tenant".into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: "strict-reopen".into(),
    };
    database
        .administer(
            context.clone(),
            Operation::CreateCollection(CollectionDefinition {
                name: "retained".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await
        .context("local reopen fixture: create retained collection")?;
    let mutation =
        MutationBatch::new().upsert("retained", "durable", serde_json::json!({"value": 7}));
    let receipt = database.mutate(context.clone(), mutation.clone()).await?;
    assert_eq!(
        database
            .get(&context, "retained", "durable")
            .await?
            .expect("local journal committed the document")
            .body,
        serde_json::json!({"value": 7})
    );
    let destination = kasumi_store::FilesystemBackupDestination::new(
        fixture.directory.path().join("persistent/backups"),
        32 << 20,
        fixture.storage.persistent.clone(),
    )?;
    let backup = database
        .backup_checkpoint(context.clone(), &destination, uuid::Uuid::new_v4())
        .await?;
    database
        .verify_backup_checkpoint(context.clone(), &destination, backup.backup_id())
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
    crate::test_utils::install_local_replica_audit_placement(stores.application())?;
    let audit_store = TenantStore::open_existing(
        node,
        crate::SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([23; 32])),
        StorageAccess::security_audit(),
    )
    .await?;
    let audit = SecurityAudit::open(audit_store, Default::default(), storage.admission.clone())?;
    let reopened = open_existing_local(stores.clone(), audit.clone(), incarnation)
        .await
        .map_err(
            |original| crate::test_fixture_failure::FixtureFailure::SnapshotContext {
                context: "local reopen fixture: existing Database startup",
                original,
            },
        )?;
    assert!(reopened.raft_group().is_local());
    assert!(reopened.raft_group().try_raft().is_none());
    let generation = reopened.engine().generation()?;
    assert_eq!(generation.state.incarnation, incarnation.to_string());
    assert_eq!(generation.state.revision, expected_revision);
    assert!(generation.state.collections.contains_key("retained"));
    drop(generation);
    assert_eq!(
        reopened
            .get(&context, "retained", "durable")
            .await?
            .expect("local journal replay restored the document")
            .body,
        serde_json::json!({"value": 7})
    );
    assert_eq!(reopened.mutate(context.clone(), mutation).await?, receipt);
    reopened
        .verify_backup_checkpoint(context, &destination, backup.backup_id())
        .await?;
    reopened.shutdown().await?;
    drop(reopened);
    stores.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
    Ok(())
}

/// One audited read event, as a serving tenant records it.
fn audit_command(number: u64, revision: u64) -> Vec<u8> {
    serde_json::to_vec(&Command {
        context: RequestContext {
            authorization: RequestAuthorization::service_identity(),
            tenant: "tenant".into(),
            principal: "owner".into(),
            scopes: BTreeSet::from([Action::Read]),
            request_id: "read".into(),
        },
        timestamp_ms: 1_000,
        operation: Operation::Audit(AuditEvent {
            event_id: format!("{number}:{}", "x".repeat(2_000)),
            principal: "owner".into(),
            action: "read".into(),
            request_id: "read".into(),
            timestamp_ms: 1_000,
            data_revision: Some(revision),
            outcome: "authorized_release".into(),
            collection: None,
        }),
    })
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    clippy::await_holding_lock,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test. The form default is held for the reopen."
)]
async fn standalone_snapshot_over_an_archived_history_reopens_without_copying_the_archive()
-> crate::test_fixture_failure::FixtureResult<()> {
    use anyhow::Context as _;
    let fixture = Installation::new().await?;
    let limits = Limits {
        audit_retention: AuditRetentionBudget {
            hot_bytes: 128 << 10,
            ..Default::default()
        },
        ..Default::default()
    };
    let database = open_local_with_incarnation(
        fixture.stores.clone(),
        policy(),
        limits,
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await?;
    database.engine().fixture_reference_local_snapshots(true);
    let group = database.raft_group().clone();
    assert!(group.is_local());
    let write = |number: u64| {
        let group = group.clone();
        let revision = database.engine().generation().unwrap().state.revision;
        async move {
            let response = group
                .write(kasumi_raft::ApplicationProposal::generated(audit_command(
                    number, revision,
                )))
                .await
                .unwrap();
            serde_json::from_slice::<kasumi_types::Result<WriteReceipt>>(&response)
                .unwrap()
                .unwrap();
        }
    };
    for number in 0..50 {
        write(number).await;
    }
    // The tenant audit worker drains hot history into this node's archive.
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while database
            .engine()
            .generation()
            .unwrap()
            .state
            .audit_retention
            .archive_segments
            == 0
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .context("audit history never reached the archive")?;
    // A periodic standalone snapshot now covers the archived history, and the
    // journal before it is purged: a reopen must start from that snapshot.
    group.fixture_local_snapshot_interval(2).await?;
    let before = group.metrics().snapshot;
    for number in 50..60 {
        write(number).await;
        group.fixture_local_snapshot_settled().await?;
    }
    let metrics = group.metrics();
    assert!(
        metrics.snapshot > before,
        "no periodic snapshot was published"
    );
    assert_eq!(metrics.purged, metrics.snapshot);
    let generation = database.engine().generation()?;
    let retention = generation.state.audit_retention.clone();
    let revision = generation.state.revision;
    drop(generation);
    assert!(retention.archive_segments > 0);
    assert!(retention.archive_head.is_some());
    database.shutdown().await?;
    drop(group);
    drop(database);
    let _default = ArchiveDefault::set(crate::LocalSnapshotArchive::Reference);
    let fixture = fixture.reopen().await?;
    let reopened = open_existing_local(
        fixture.stores.clone(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await
    .map_err(
        |original| crate::test_fixture_failure::FixtureFailure::SnapshotContext {
            context: "archived standalone reopen",
            original,
        },
    )?;
    assert!(reopened.engine().reopened_from_reference_snapshot());
    // An opted-in reopen keeps the by-reference snapshot: nothing is rewritten.
    assert_eq!(reopened.raft_group().local_snapshots_published(), Some(0));
    // The tenant's audit worker (its hot budget is tiny) can commit while the
    // writer shuts down or after the reopen. Nothing is lost, the archive chain
    // only extends, and without such a commit the reopened state is identical.
    let generation = reopened.engine().generation()?;
    assert!(generation.state.revision >= revision);
    let reopened_retention = generation.state.audit_retention.clone();
    assert!(reopened_retention.archive_segments >= retention.archive_segments);
    if generation.state.revision == revision {
        assert_eq!(reopened_retention, retention);
    }
    let revision = generation.state.revision;
    drop(generation);
    // The reopened tenant serves and keeps auditing on the same chain.
    let response = reopened
        .raft_group()
        .write(kasumi_raft::ApplicationProposal::generated(audit_command(
            60, revision,
        )))
        .await?;
    serde_json::from_slice::<kasumi_types::Result<WriteReceipt>>(&response)?
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let after = reopened
        .engine()
        .generation()?
        .state
        .audit_retention
        .clone();
    assert!(after.archive_segments >= reopened_retention.archive_segments);
    if after.archive_segments == retention.archive_segments {
        assert_eq!(after.archive_head, retention.archive_head);
    }
    reopened.shutdown().await?;
    drop(reopened);
    fixture.shutdown().await;
    Ok(())
}

/// Every published document object, by namespace and key.
fn document_objects(
    stores: &TenantStorageSet,
) -> anyhow::Result<BTreeSet<(&'static str, Vec<u8>)>> {
    let mut objects = BTreeSet::new();
    let view = stores.application().read_view()?;
    for namespace in [crate::document_store::BODIES, crate::document_store::BLOBS] {
        view.visit(namespace, 32 << 20, |key, _| {
            objects.insert((namespace, key.to_vec()));
            Ok(())
        })?;
    }
    view.close()?;
    Ok(objects)
}

/// A standalone reopen reads its snapshot's documents from the objects its
/// store already published: each document reads back, and the objects only a
/// replaced version named are swept while every other object stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn a_standalone_reopen_serves_its_snapshot_documents_and_sweeps_replaced_objects()
-> crate::test_fixture_failure::FixtureResult<()> {
    use anyhow::Context as _;
    let fixture = Installation::new().await?;
    // The feed keeps one event, so a snapshot names only current versions.
    let limits = Limits {
        history: kasumi_types::HistoryLimits {
            max_feed_events: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let database = open_local_with_incarnation(
        fixture.stores.clone(),
        policy(),
        limits,
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await?;
    let context = RequestContext {
        authorization: RequestAuthorization::service_identity(),
        tenant: "tenant".into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: "document-reopen".into(),
    };
    database
        .administer(
            context.clone(),
            Operation::CreateCollection(CollectionDefinition {
                name: "docs".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type": "object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await?;
    // Hex proofs this long are stored as separate chunk objects.
    let proof = |seed: u8| {
        hex::encode(
            (0..70_013u32)
                .map(|index| (index % 251) as u8 ^ seed)
                .collect::<Vec<_>>(),
        )
    };
    let put = |id: &str, seed: u8| {
        MutationBatch::new().upsert("docs", id, serde_json::json!({"proof": proof(seed)}))
    };
    database.mutate(context.clone(), put("replaced", 1)).await?;
    let replaced = document_objects(&fixture.stores)?;
    assert!(!replaced.is_empty());
    // A periodic snapshot covers the current versions; anything after it is
    // replayed.
    let group = database.raft_group().clone();
    group.fixture_local_snapshot_interval(2).await?;
    let before = group.metrics().snapshot;
    for (id, seed) in [("replaced", 2), ("kept", 3)] {
        database.mutate(context.clone(), put(id, seed)).await?;
        group.fixture_local_snapshot_settled().await?;
    }
    assert!(
        group.metrics().snapshot > before,
        "no periodic snapshot was published"
    );
    let published = document_objects(&fixture.stores)?;
    database.shutdown().await?;
    drop(group);
    drop(database);

    let fixture = fixture.reopen().await?;
    let reopened = open_existing_local(
        fixture.stores.clone(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await
    .map_err(
        |original| crate::test_fixture_failure::FixtureFailure::SnapshotContext {
            context: "document reopen",
            original,
        },
    )?;
    for (id, seed) in [("replaced", 2), ("kept", 3)] {
        assert_eq!(
            reopened
                .get(&context, "docs", id)
                .await?
                .context("reopen lost a document")?
                .body,
            serde_json::json!({"proof": proof(seed)})
        );
    }
    let kept = document_objects(&fixture.stores)?;
    assert!(kept.is_subset(&published));
    assert_eq!(
        published
            .difference(&kept)
            .cloned()
            .collect::<BTreeSet<_>>(),
        replaced
    );
    reopened.shutdown().await?;
    drop(reopened);
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn existing_control_requires_the_non_nil_configured_incarnation_before_startup()
-> crate::test_fixture_failure::FixtureResult<()> {
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

// ---- A standalone group's own snapshot form: real crashes and rollback ----

static ARCHIVE_DEFAULT: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Holds this process's default snapshot form for a test that reopens with a
/// chosen form. Unguarded tests may observe any default: every form reopens.
struct ArchiveDefault(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);
impl ArchiveDefault {
    fn set(archive: crate::LocalSnapshotArchive) -> Self {
        let guard = ARCHIVE_DEFAULT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::set_local_snapshot_archive(archive);
        Self(guard)
    }
}
impl ArchiveDefault {
    /// Change the default while still holding it.
    fn switch(&self, archive: crate::LocalSnapshotArchive) {
        crate::set_local_snapshot_archive(archive);
    }
}
impl Drop for ArchiveDefault {
    fn drop(&mut self) {
        crate::set_local_snapshot_archive(crate::LocalSnapshotArchive::Embedded);
    }
}

const FORM_STAGE: &str = "KASUMI_SNAPSHOT_FORM_CHILD_STAGE";
const FORM_ROOT: &str = "KASUMI_SNAPSHOT_FORM_CHILD_ROOT";

#[derive(serde::Serialize, serde::Deserialize)]
struct RootedIds {
    installation: uuid::Uuid,
    incarnation: uuid::Uuid,
}

/// The newest write a child acknowledged before it died: its journal entry and
/// the tenant revision after it, both durable before this record is renamed.
#[derive(serde::Serialize, serde::Deserialize)]
struct Acknowledged {
    number: u64,
    revision: u64,
    reference_snapshots: u64,
}

/// An installation at a fixed directory, so a second process can reopen what a
/// killed first process left behind.
struct Rooted {
    storage: crate::test_utils::FixtureStorage,
    node: NodeStore,
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
    incarnation: uuid::Uuid,
}
impl Rooted {
    fn configs(
        root: &std::path::Path,
    ) -> anyhow::Result<(
        kasumi_store::NodeDiskConfig,
        kasumi_store::ScratchDiskConfig,
    )> {
        // Exactly `fixture_disk_configs`, without creating the directory again.
        Ok((
            kasumi_store::NodeDisk::fixture_config(root.join("persistent/node.kv"))?,
            kasumi_store::ScratchDiskConfig {
                directory: root.join("scratch"),
                max_bytes: 256 << 30,
                min_free_bytes: 0,
                file_allocation_policy: kasumi_store::FileAllocationPolicy::new(0).unwrap(),
                native_cache_bytes: 8 << 20,
            },
        ))
    }
    fn storage(
        persistent: &kasumi_store::NodeDiskConfig,
        scratch: &kasumi_store::ScratchDiskConfig,
    ) -> anyhow::Result<crate::test_utils::FixtureStorage> {
        let config =
            super::existing_replicated_tests::replica_budget::planned_config(persistent, scratch)?;
        let admission = crate::admission::NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
        crate::test_utils::FixtureStorage::with_admission(persistent, scratch, admission)
    }
    async fn create(root: &std::path::Path) -> crate::test_fixture_failure::FixtureResult<Self> {
        let (persistent, scratch) = crate::test_utils::fixture_disk_configs(root)?;
        let storage = Self::storage(&persistent, &scratch)?;
        let node = storage.create_new(
            root.join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )?;
        let ids = RootedIds {
            installation: uuid::Uuid::new_v4(),
            incarnation: uuid::Uuid::new_v4(),
        };
        let access = StorageAccess::standalone(ids.installation, "tenant", ids.incarnation)?;
        let stores = TenantStorageSet::initialize_catalogs(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([21; 32])),
            Arc::new(LocalKeyProvider::new([22; 32])),
            access,
        )
        .await?;
        crate::test_utils::install_local_replica_audit_placement(stores.application())?;
        let audit_store = TenantStore::initialize_catalog(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([23; 32])),
            StorageAccess::security_audit(),
        )
        .await?;
        let audit =
            SecurityAudit::initialize(audit_store, Default::default(), storage.admission.clone())?;
        durable_write(&root.join("ids.json"), &serde_json::to_vec(&ids)?)?;
        Ok(Self {
            storage,
            node,
            stores,
            audit,
            incarnation: ids.incarnation,
        })
    }
    /// Open in a process that never opened this root (after a killed writer).
    async fn open(root: &std::path::Path) -> crate::test_fixture_failure::FixtureResult<Self> {
        let (persistent, scratch) = Self::configs(root)?;
        Self::open_on(root, Self::storage(&persistent, &scratch)?).await
    }
    /// Reopen in this process: disk registries keep their first admission, so
    /// the same fixture storage scope must open the installation again.
    async fn open_on(
        root: &std::path::Path,
        storage: crate::test_utils::FixtureStorage,
    ) -> crate::test_fixture_failure::FixtureResult<Self> {
        let ids: RootedIds = serde_json::from_slice(&std::fs::read(root.join("ids.json"))?)?;
        let node = storage.open_existing(
            root.join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )?;
        let access = StorageAccess::standalone(ids.installation, "tenant", ids.incarnation)?;
        let stores = TenantStorageSet::open_existing(
            node.clone(),
            "tenant".into(),
            Arc::new(LocalKeyProvider::new([21; 32])),
            Arc::new(LocalKeyProvider::new([22; 32])),
            access,
        )
        .await?;
        crate::test_utils::install_local_replica_audit_placement(stores.application())?;
        let audit_store = TenantStore::open_existing(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([23; 32])),
            StorageAccess::security_audit(),
        )
        .await?;
        let audit =
            SecurityAudit::open(audit_store, Default::default(), storage.admission.clone())?;
        Ok(Self {
            storage,
            node,
            stores,
            audit,
            incarnation: ids.incarnation,
        })
    }
    async fn shutdown(&self) {
        self.stores.shutdown().await.unwrap();
        self.audit.shutdown().await.unwrap();
        self.node.shutdown().await.unwrap();
    }
    /// Close every store and keep the storage scope for [`Self::open_on`].
    async fn close(self) -> crate::test_utils::FixtureStorage {
        self.shutdown().await;
        let Self {
            storage,
            node,
            stores,
            audit,
            ..
        } = self;
        drop(stores);
        drop(audit);
        drop(node);
        storage
    }
}

/// Write, fsync, rename and fsync the directory: a reader after a crash sees
/// either the previous complete record or this one.
fn durable_write(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;
    let staged = path.with_extension("staged");
    let mut file = std::fs::File::create(&staged)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&staged, path)?;
    std::fs::File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

fn small_hot_audit_limits() -> Limits {
    Limits {
        audit_retention: AuditRetentionBudget {
            hot_bytes: 128 << 10,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// One acknowledged audited write, and the tenant revision after it.
async fn audited_write(database: &Database, number: u64) -> anyhow::Result<u64> {
    let revision = database.engine().generation()?.state.revision;
    let response = database
        .raft_group()
        .write(kasumi_raft::ApplicationProposal::generated(audit_command(
            number, revision,
        )))
        .await?;
    serde_json::from_slice::<kasumi_types::Result<WriteReceipt>>(&response)?
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    Ok(database.engine().generation()?.state.revision)
}

/// Write until the tenant audit worker has drained history into the archive.
async fn archived_history(database: &Database, writes: u64) -> anyhow::Result<()> {
    use anyhow::Context as _;
    for number in 0..writes {
        audited_write(database, number).await?;
    }
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        while database
            .engine()
            .generation()
            .unwrap()
            .state
            .audit_retention
            .archive_segments
            == 0
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .context("audit history never reached the archive")
}

/// Child process: archive history, publish by-reference snapshots, then keep
/// writing (every second entry snapshots) until the parent kills it, recording
/// each acknowledged write durably. With `abort`, the next snapshot task kills
/// this process itself after its capture and before its build.
async fn form_child(
    root: &std::path::Path,
    abort: bool,
) -> crate::test_fixture_failure::FixtureResult<()> {
    // This process opens only this tenant.
    crate::set_local_snapshot_archive(crate::LocalSnapshotArchive::Reference);
    let fixture = Rooted::create(root).await?;
    let database = open_local_with_incarnation(
        fixture.stores.clone(),
        policy(),
        small_hot_audit_limits(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await?;
    assert!(database.engine().stores_reference_local_snapshots());
    archived_history(&database, 50).await?;
    let group = database.raft_group().clone();
    group.fixture_local_snapshot_interval(2).await?;
    let mut number = 50;
    let acknowledge = |number: u64, revision: u64| {
        let snapshots = group.local_snapshots_published().unwrap_or_default();
        durable_write(
            &root.join("acknowledged.json"),
            &serde_json::to_vec(&Acknowledged {
                number,
                revision,
                reference_snapshots: snapshots,
            })
            .unwrap(),
        )
    };
    while group.local_snapshots_published().unwrap_or_default() < 2 {
        let revision = audited_write(&database, number).await?;
        group.fixture_local_snapshot_settled().await?;
        acknowledge(number, revision)?;
        number += 1;
    }
    if abort {
        group.fixture_local_before_snapshot(Box::new(|| std::process::abort()))?;
    }
    durable_write(&root.join("ready"), b"ready")?;
    while number < 100_000 {
        let revision = audited_write(&database, number).await?;
        acknowledge(number, revision)?;
        number += 1;
    }
    Err(anyhow::anyhow!("the parent never stopped this writer").into())
}

fn spawn_form_child(
    root: &std::path::Path,
    test: &str,
    stage: &str,
) -> anyhow::Result<std::process::Child> {
    Ok(std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(FORM_STAGE, stage)
        .env(FORM_ROOT, root)
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(root.join("child.stderr"))?)
        .spawn()?)
}

fn child_log(root: &std::path::Path) -> String {
    std::fs::read_to_string(root.join("child.stderr")).unwrap_or_default()
}

/// Reopen what a dead child left and prove nothing it acknowledged was lost,
/// that the reopen started from a by-reference snapshot over the archived
/// chain, and that the tenant keeps auditing on that chain.
async fn reopen_after_crash(
    root: &std::path::Path,
) -> crate::test_fixture_failure::FixtureResult<()> {
    let acknowledged: Acknowledged =
        serde_json::from_slice(&std::fs::read(root.join("acknowledged.json"))?)?;
    assert!(
        acknowledged.reference_snapshots >= 2,
        "no reference snapshot preceded the crash"
    );
    let fixture = Rooted::open(root).await?;
    let reopened = open_existing_local(
        fixture.stores.clone(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await
    .map_err(
        |original| crate::test_fixture_failure::FixtureFailure::SnapshotContext {
            context: "reopen after a killed writer",
            original,
        },
    )?;
    assert!(reopened.engine().reopened_from_reference_snapshot());
    let generation = reopened.engine().generation()?;
    assert!(
        generation.state.revision >= acknowledged.revision,
        "acknowledged revision {} lost: reopened at {} ({})",
        acknowledged.revision,
        generation.state.revision,
        child_log(root)
    );
    let retention = generation.state.audit_retention.clone();
    drop(generation);
    assert!(retention.archive_segments > 0);
    audited_write(&reopened, 200_000).await?;
    // Background audit maintenance may archive another segment meanwhile; the
    // chain only ever extends from the one the reopen verified.
    let after = reopened
        .engine()
        .generation()?
        .state
        .audit_retention
        .clone();
    assert!(after.archive_segments >= retention.archive_segments);
    if after.archive_segments == retention.archive_segments {
        assert_eq!(after.archive_head, retention.archive_head);
    }
    reopened.shutdown().await?;
    drop(reopened);
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    clippy::await_holding_lock,
    reason = "Whole native failure custody is the fixture result; the form default is held for this test's reopen."
)]
async fn a_killed_writer_reopens_from_its_reference_snapshot_with_every_acknowledged_write()
-> crate::test_fixture_failure::FixtureResult<()> {
    const TEST: &str = "bootstrap::existing_tests::a_killed_writer_reopens_from_its_reference_snapshot_with_every_acknowledged_write";
    if let Ok(stage) = std::env::var(FORM_STAGE) {
        let root = std::path::PathBuf::from(std::env::var(FORM_ROOT).map_err(anyhow::Error::from)?);
        return form_child(&root, stage == "abort").await;
    }
    let _default = ArchiveDefault::set(crate::LocalSnapshotArchive::Reference);
    // Kill points spread over continuous capture, publication and purge.
    for delay_ms in [0u64, 3, 11, 37, 97] {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let root = directory.path();
        let mut child = spawn_form_child(root, TEST, "kill")?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
        while !root.join("ready").exists() {
            if let Some(status) = child.try_wait()? {
                panic!("child exited early with {status}: {}", child_log(root));
            }
            assert!(
                std::time::Instant::now() < deadline,
                "child never became ready"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        // SIGKILL: no shutdown, destructor, flush or drain runs in the writer.
        child.kill()?;
        assert!(!child.wait()?.success());
        reopen_after_crash(root).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    clippy::await_holding_lock,
    reason = "Whole native failure custody is the fixture result; the form default is held for this test's reopen."
)]
async fn a_writer_that_dies_inside_its_next_snapshot_task_reopens_from_the_previous_one()
-> crate::test_fixture_failure::FixtureResult<()> {
    const TEST: &str = "bootstrap::existing_tests::a_writer_that_dies_inside_its_next_snapshot_task_reopens_from_the_previous_one";
    if let Ok(stage) = std::env::var(FORM_STAGE) {
        let root = std::path::PathBuf::from(std::env::var(FORM_ROOT).map_err(anyhow::Error::from)?);
        return form_child(&root, stage == "abort").await;
    }
    let _default = ArchiveDefault::set(crate::LocalSnapshotArchive::Reference);
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let root = directory.path();
    let mut child = spawn_form_child(root, TEST, "abort")?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        assert!(std::time::Instant::now() < deadline, "child never aborted");
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    // Aborted by its own snapshot task, after the ready marker.
    assert!(!status.success());
    assert!(
        root.join("ready").exists(),
        "child failed before its crash point: {}",
        child_log(root)
    );
    reopen_after_crash(root).await
}

/// Find the cached audit archive segments of a closed installation.
fn archive_segments(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    fn walk(directory: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(directory).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path
                .extension()
                .is_some_and(|extension| extension == "audit")
                && path
                    .components()
                    .any(|part| part.as_os_str() == "tenant-audit-archives")
            {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(root, &mut found);
    found.sort();
    found
}

/// One child stage of the missing-segment test; each runs in a fresh process,
/// because a refused open leaves its disk owners for that process to discard.
async fn segment_child(
    root: &std::path::Path,
    stage: &str,
) -> crate::test_fixture_failure::FixtureResult<()> {
    crate::set_local_snapshot_archive(crate::LocalSnapshotArchive::Reference);
    match stage {
        "populate" => {
            let fixture = Rooted::create(root).await?;
            let database = open_local_with_incarnation(
                fixture.stores.clone(),
                policy(),
                small_hot_audit_limits(),
                fixture.audit.clone(),
                fixture.incarnation,
            )
            .await?;
            archived_history(&database, 50).await?;
            let group = database.raft_group().clone();
            group.fixture_local_snapshot_interval(2).await?;
            for number in 50..56 {
                audited_write(&database, number).await?;
                group.fixture_local_snapshot_settled().await?;
            }
            assert!(group.local_snapshots_published().unwrap() > 0);
            let revision = database.engine().generation()?.state.revision;
            durable_write(&root.join("revision"), revision.to_string().as_bytes())?;
            database.shutdown().await?;
            drop(group);
            drop(database);
            drop(fixture.close().await);
        }
        "refused" => {
            let fixture = Rooted::open(root).await?;
            let opened = open_existing_local(
                fixture.stores.clone(),
                fixture.audit.clone(),
                fixture.incarnation,
            )
            .await;
            if let Ok(database) = opened {
                let _ = database.shutdown().await;
                return Err(anyhow::anyhow!(
                    "a by-reference snapshot reopened without its archive segment"
                )
                .into());
            }
            durable_write(&root.join("refused"), b"refused")?;
        }
        "open" => {
            let expected: u64 = std::fs::read_to_string(root.join("revision"))?
                .parse()
                .map_err(anyhow::Error::from)?;
            let fixture = Rooted::open(root).await?;
            let reopened = open_existing_local(
                fixture.stores.clone(),
                fixture.audit.clone(),
                fixture.incarnation,
            )
            .await
            .map_err(|original| {
                crate::test_fixture_failure::FixtureFailure::SnapshotContext {
                    context: "reopen with the archive segment restored",
                    original,
                }
            })?;
            assert!(reopened.engine().reopened_from_reference_snapshot());
            assert!(reopened.engine().generation()?.state.revision >= expected);
            reopened.shutdown().await?;
            drop(reopened);
            drop(fixture.close().await);
        }
        _ => return Err(anyhow::anyhow!("unknown segment child stage").into()),
    }
    Ok(())
}

fn run_segment_child(root: &std::path::Path, test: &str, stage: &str) -> anyhow::Result<()> {
    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(FORM_STAGE, stage)
        .env(FORM_ROOT, root)
        .output()?;
    anyhow::ensure!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "segment child {stage} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "Whole native failure custody is the fixture result."
)]
async fn a_reference_snapshot_never_reopens_over_a_missing_archive_segment()
-> crate::test_fixture_failure::FixtureResult<()> {
    const TEST: &str = "bootstrap::existing_tests::a_reference_snapshot_never_reopens_over_a_missing_archive_segment";
    if let Ok(stage) = std::env::var(FORM_STAGE) {
        let root = std::path::PathBuf::from(std::env::var(FORM_ROOT).map_err(anyhow::Error::from)?);
        return segment_child(&root, &stage).await;
    }
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let root = directory.path();
    run_segment_child(root, TEST, "populate")?;
    let segments = archive_segments(root);
    assert!(!segments.is_empty(), "no cached archive segment found");
    let removed = &segments[0];
    let held = removed.with_extension("held");
    std::fs::rename(removed, &held)?;
    run_segment_child(root, TEST, "refused")?;
    assert!(root.join("refused").exists());
    // The refused reopen rewrote nothing: with the segment back it opens.
    std::fs::rename(&held, removed)?;
    run_segment_child(root, TEST, "open")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    clippy::await_holding_lock,
    reason = "Whole native failure custody is the fixture result; the form default is held for each reopen."
)]
async fn an_embedded_reopen_replaces_a_reference_snapshot_so_an_older_binary_can_reopen()
-> crate::test_fixture_failure::FixtureResult<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let root = directory.path();
    let fixture = Rooted::create(root).await?;
    let database = open_local_with_incarnation(
        fixture.stores.clone(),
        policy(),
        small_hot_audit_limits(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await?;
    // This engine alone opts in; no process default is involved.
    database.engine().fixture_reference_local_snapshots(true);
    archived_history(&database, 50).await?;
    let group = database.raft_group().clone();
    group.fixture_local_snapshot_interval(2).await?;
    for number in 50..56 {
        audited_write(&database, number).await?;
        group.fixture_local_snapshot_settled().await?;
    }
    assert!(group.local_snapshots_published().unwrap() > 0);
    let generation = database.engine().generation()?;
    let (revision, retention) = (
        generation.state.revision,
        generation.state.audit_retention.clone(),
    );
    drop(generation);
    database.shutdown().await?;
    drop(group);
    drop(database);
    let storage = fixture.close().await;
    let reopen = |phase: &'static str, storage| async move {
        let fixture = Rooted::open_on(root, storage).await?;
        let reopened = open_existing_local(
            fixture.stores.clone(),
            fixture.audit.clone(),
            fixture.incarnation,
        )
        .await
        .map_err(|original| {
            crate::test_fixture_failure::FixtureFailure::SnapshotContext {
                context: phase,
                original,
            }
        })?;
        crate::test_fixture_failure::FixtureResult::Ok((fixture, reopened))
    };
    // Rollback step 1: start once without the opt-in.
    let default = ArchiveDefault::set(crate::LocalSnapshotArchive::Embedded);
    let (fixture, reopened) = reopen("embedded reopen of a reference snapshot", storage).await?;
    assert!(!reopened.engine().stores_reference_local_snapshots());
    assert!(reopened.engine().reopened_from_reference_snapshot());
    // The embedded replacement was durably published before the open returned.
    assert_eq!(reopened.raft_group().local_snapshots_published(), Some(1));
    // Background audit maintenance may commit after the open; nothing is lost.
    let generation = reopened.engine().generation()?;
    assert!(generation.state.revision >= revision);
    assert!(generation.state.audit_retention.archive_segments >= retention.archive_segments);
    let revision = generation.state.revision;
    let retention = generation.state.audit_retention.clone();
    drop(generation);
    reopened.shutdown().await?;
    drop(reopened);
    let storage = fixture.close().await;
    // The stored snapshot is now the embedded form, the only one an older
    // binary reads; another reopen finds it and converts nothing.
    let (fixture, reopened) = reopen("reopen after the conversion", storage).await?;
    assert!(!reopened.engine().reopened_from_reference_snapshot());
    assert_eq!(reopened.raft_group().local_snapshots_published(), Some(0));
    let generation = reopened.engine().generation()?;
    assert!(generation.state.revision >= revision);
    assert!(generation.state.audit_retention.archive_segments >= retention.archive_segments);
    drop(generation);
    audited_write(&reopened, 500).await?;
    reopened.shutdown().await?;
    drop(reopened);
    fixture.shutdown().await;
    drop(default);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    clippy::await_holding_lock,
    reason = "Whole native failure custody is the fixture result; the form default is held for this test."
)]
async fn without_the_opt_in_a_standalone_group_stores_the_embedded_form()
-> crate::test_fixture_failure::FixtureResult<()> {
    let _default = ArchiveDefault::set(crate::LocalSnapshotArchive::Embedded);
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let root = directory.path();
    let fixture = Rooted::create(root).await?;
    let database = open_local_with_incarnation(
        fixture.stores.clone(),
        policy(),
        small_hot_audit_limits(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await?;
    assert!(!database.engine().stores_reference_local_snapshots());
    archived_history(&database, 50).await?;
    let group = database.raft_group().clone();
    group.fixture_local_snapshot_interval(2).await?;
    for number in 50..56 {
        audited_write(&database, number).await?;
        group.fixture_local_snapshot_settled().await?;
    }
    assert!(group.local_snapshots_published().unwrap() > 0);
    database.shutdown().await?;
    drop(group);
    drop(database);
    let storage = fixture.close().await;
    let fixture = Rooted::open_on(root, storage).await?;
    let reopened = open_existing_local(
        fixture.stores.clone(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await
    .map_err(
        |original| crate::test_fixture_failure::FixtureFailure::SnapshotContext {
            context: "embedded default reopen",
            original,
        },
    )?;
    assert!(!reopened.engine().reopened_from_reference_snapshot());
    assert_eq!(reopened.raft_group().local_snapshots_published(), Some(0));
    reopened.shutdown().await?;
    drop(reopened);
    fixture.shutdown().await;
    Ok(())
}

/// A store whose engine alone opted in: archived history, then periodic
/// by-reference (KASUMIL1) snapshots. It is closed; the returned storage scope
/// reopens it in this process. Also the tenant revision it closed at.
#[allow(
    clippy::result_large_err,
    reason = "Whole native failure custody is the fixture result."
)]
async fn by_reference_store(
    root: &std::path::Path,
) -> crate::test_fixture_failure::FixtureResult<(crate::test_utils::FixtureStorage, u64)> {
    let fixture = Rooted::create(root).await?;
    let database = open_local_with_incarnation(
        fixture.stores.clone(),
        policy(),
        small_hot_audit_limits(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await?;
    database.engine().fixture_reference_local_snapshots(true);
    archived_history(&database, 50).await?;
    let group = database.raft_group().clone();
    group.fixture_local_snapshot_interval(2).await?;
    for number in 50..56 {
        audited_write(&database, number).await?;
        group.fixture_local_snapshot_settled().await?;
    }
    assert!(group.local_snapshots_published().unwrap() > 0);
    let revision = database.engine().generation()?.state.revision;
    database.shutdown().await?;
    drop(group);
    drop(database);
    Ok((fixture.close().await, revision))
}

/// Reopen in this process under the default the caller holds.
#[allow(
    clippy::result_large_err,
    reason = "Whole native failure custody is the fixture result."
)]
async fn reopen_on(
    root: &std::path::Path,
    storage: crate::test_utils::FixtureStorage,
    context: &'static str,
) -> crate::test_fixture_failure::FixtureResult<(Rooted, Arc<Database>)> {
    let fixture = Rooted::open_on(root, storage).await?;
    let reopened =
        open_existing_local(
            fixture.stores.clone(),
            fixture.audit.clone(),
            fixture.incarnation,
        )
        .await
        .map_err(|original| {
            crate::test_fixture_failure::FixtureFailure::SnapshotContext { context, original }
        })?;
    Ok((fixture, reopened))
}

/// Shut a reopened tenant down and keep the storage scope for the next reopen.
#[allow(
    clippy::result_large_err,
    reason = "Whole native failure custody is the fixture result."
)]
async fn close_reopened(
    fixture: Rooted,
    database: Arc<Database>,
) -> crate::test_fixture_failure::FixtureResult<crate::test_utils::FixtureStorage> {
    database.shutdown().await?;
    drop(database);
    Ok(fixture.close().await)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    clippy::await_holding_lock,
    reason = "Whole native failure custody is the fixture result; the form default is held for each reopen."
)]
async fn an_offline_command_keeps_each_stored_form_and_converts_nothing()
-> crate::test_fixture_failure::FixtureResult<()> {
    // Every kasumid command but `serve` opens its tenants under `Preserve`.
    let _default = ArchiveDefault::set(crate::LocalSnapshotArchive::Preserve);
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let root = directory.path();
    let (storage, revision) = by_reference_store(root).await?;
    // A by-reference tenant is not converted: no archive copy is written.
    let (fixture, reopened) =
        reopen_on(root, storage, "offline reopen of a reference snapshot").await?;
    assert!(reopened.engine().reopened_from_reference_snapshot());
    assert!(reopened.engine().stores_reference_local_snapshots());
    assert_eq!(reopened.raft_group().local_snapshots_published(), Some(0));
    assert!(reopened.engine().generation()?.state.revision >= revision);
    // Its own snapshots stay by reference too.
    let group = reopened.raft_group().clone();
    group.fixture_local_snapshot_interval(2).await?;
    for number in 100..104 {
        audited_write(&reopened, number).await?;
        group.fixture_local_snapshot_settled().await?;
    }
    assert!(group.local_snapshots_published().unwrap() > 0);
    drop(group);
    let storage = close_reopened(fixture, reopened).await?;
    let (fixture, reopened) = reopen_on(root, storage, "second offline reopen").await?;
    assert!(
        reopened.engine().reopened_from_reference_snapshot(),
        "an offline command stored an embedded snapshot"
    );
    assert_eq!(reopened.raft_group().local_snapshots_published(), Some(0));
    drop(close_reopened(fixture, reopened).await?);

    // A store that never opted in stays embedded: an offline command never
    // starts the by-reference form on its own.
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let root = directory.path();
    let fixture = Rooted::create(root).await?;
    let database = open_local_with_incarnation(
        fixture.stores.clone(),
        policy(),
        small_hot_audit_limits(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await?;
    assert!(!database.engine().stores_reference_local_snapshots());
    archived_history(&database, 50).await?;
    let group = database.raft_group().clone();
    group.fixture_local_snapshot_interval(2).await?;
    for number in 50..54 {
        audited_write(&database, number).await?;
        group.fixture_local_snapshot_settled().await?;
    }
    assert!(group.local_snapshots_published().unwrap() > 0);
    drop(group);
    let storage = close_reopened(fixture, database).await?;
    let (fixture, reopened) =
        reopen_on(root, storage, "offline reopen of an embedded snapshot").await?;
    assert!(!reopened.engine().reopened_from_reference_snapshot());
    assert!(!reopened.engine().stores_reference_local_snapshots());
    assert_eq!(reopened.raft_group().local_snapshots_published(), Some(0));
    let group = reopened.raft_group().clone();
    group.fixture_local_snapshot_interval(2).await?;
    for number in 100..104 {
        audited_write(&reopened, number).await?;
        group.fixture_local_snapshot_settled().await?;
    }
    assert!(group.local_snapshots_published().unwrap() > 0);
    drop(group);
    let storage = close_reopened(fixture, reopened).await?;
    let (fixture, reopened) =
        reopen_on(root, storage, "offline reopen after embedded snapshots").await?;
    assert!(!reopened.engine().reopened_from_reference_snapshot());
    reopened.shutdown().await?;
    drop(reopened);
    fixture.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    clippy::await_holding_lock,
    reason = "Whole native failure custody is the fixture result; the form default is held for each reopen."
)]
async fn a_conversion_refused_for_capacity_serves_on_its_reference_snapshot()
-> crate::test_fixture_failure::FixtureResult<()> {
    let default = ArchiveDefault::set(crate::LocalSnapshotArchive::Embedded);
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let root = directory.path();
    let (storage, revision) = by_reference_store(root).await?;
    // The rollback start on a full store: the conversion's Blank entry is refused.
    let fixture = Rooted::open_on(root, storage).await?;
    let reopened = super::open_existing_local_as_stored(
        fixture.stores.clone(),
        fixture.audit.clone(),
        fixture.incarnation,
    )
    .await
    .map_err(
        |original| crate::test_fixture_failure::FixtureFailure::SnapshotContext {
            context: "embedded reopen before its conversion",
            original,
        },
    )?;
    assert!(reopened.engine().reopened_from_reference_snapshot());
    assert!(!reopened.engine().stores_reference_local_snapshots());
    let stored = reopened.raft_group().metrics().snapshot;
    reopened.raft_group().fixture_local_refuse_next_blank()?;
    super::store_embedded_after_reference_reopen(&reopened)
        .await
        .map_err(
            |original| crate::test_fixture_failure::FixtureFailure::SnapshotContext {
                context: "conversion refused for capacity",
                original,
            },
        )?;
    // Nothing reached the journal or the stored snapshot, and the tenant serves.
    assert_eq!(reopened.raft_group().local_snapshots_published(), Some(0));
    assert_eq!(reopened.raft_group().metrics().snapshot, stored);
    assert!(audited_write(&reopened, 300).await? > revision);
    let storage = close_reopened(fixture, reopened).await?;
    default.switch(crate::LocalSnapshotArchive::Preserve);
    let (fixture, reopened) = reopen_on(root, storage, "reopen after a refused conversion").await?;
    assert!(
        reopened.engine().reopened_from_reference_snapshot(),
        "a refused conversion replaced the stored snapshot"
    );
    let storage = close_reopened(fixture, reopened).await?;
    // With capacity back, the next embedded start converts it.
    default.switch(crate::LocalSnapshotArchive::Embedded);
    let (fixture, reopened) = reopen_on(root, storage, "embedded reopen with capacity").await?;
    assert!(reopened.engine().reopened_from_reference_snapshot());
    assert_eq!(reopened.raft_group().local_snapshots_published(), Some(1));
    let storage = close_reopened(fixture, reopened).await?;
    default.switch(crate::LocalSnapshotArchive::Preserve);
    let (fixture, reopened) = reopen_on(root, storage, "reopen after the conversion").await?;
    assert!(!reopened.engine().reopened_from_reference_snapshot());
    reopened.shutdown().await?;
    drop(reopened);
    fixture.shutdown().await;
    drop(default);
    Ok(())
}

// ---- Cross-version rollback harness (writer side; the older release reads) ----

/// A content manifest of every file under `root`: relative path, length, SHA-256.
fn store_manifest(root: &std::path::Path) -> anyhow::Result<Vec<(String, u64, String)>> {
    use sha2::Digest as _;
    fn walk(
        base: &std::path::Path,
        directory: &std::path::Path,
        out: &mut Vec<(String, u64, String)>,
    ) -> anyhow::Result<()> {
        for entry in std::fs::read_dir(directory)? {
            let path = entry?.path();
            let name = path.strip_prefix(base)?.to_string_lossy().into_owned();
            if name.starts_with("manifest-") || name.ends_with("-record.json") {
                continue;
            }
            if path.is_dir() {
                walk(base, &path, out)?;
            } else {
                let bytes = std::fs::read(&path)?;
                out.push((
                    name,
                    bytes.len() as u64,
                    hex::encode(sha2::Sha256::digest(&bytes)),
                ));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort();
    Ok(out)
}

fn write_store_manifest(root: &std::path::Path, label: &str) -> anyhow::Result<()> {
    durable_write(
        &root.join(format!("manifest-{label}.json")),
        &serde_json::to_vec_pretty(&store_manifest(root)?)?,
    )
}

fn state_record(database: &Database) -> anyhow::Result<serde_json::Value> {
    let generation = database.engine().generation()?;
    Ok(serde_json::json!({
        "revision": generation.state.revision,
        "audit_next_sequence": generation.state.audit_retention.next_sequence,
        "audit_retention": serde_json::to_value(&generation.state.audit_retention)?,
    }))
}

/// Writer side of the cross-version rollback check, run explicitly with
/// `KASUMI_ROLLBACK_ROOTS=<converted-root>:<control-root>` (both new, private,
/// absent directories): archived history stored by reference (KASUMIL1) under
/// both roots; the first is then reopened by this release without the opt-in,
/// which converts it back to KASUMID1. The older release's reader harness opens
/// both: it must reopen the converted store with the recorded state and refuse
/// the by-reference control without rewriting it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "cross-version rollback harness; run explicitly with KASUMI_ROLLBACK_ROOTS"]
#[allow(
    clippy::result_large_err,
    clippy::await_holding_lock,
    reason = "Whole native failure custody is the fixture result; the form default is held for the conversion."
)]
async fn cross_version_rollback_harness_writes_a_converted_and_a_by_reference_store()
-> crate::test_fixture_failure::FixtureResult<()> {
    let roots = std::env::var("KASUMI_ROLLBACK_ROOTS").map_err(anyhow::Error::from)?;
    let (converted, control) = roots
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("KASUMI_ROLLBACK_ROOTS is <converted>:<control>"))?;
    // `serve` without the flag: the embedded form, which converts on reopen.
    let _default = ArchiveDefault::set(crate::LocalSnapshotArchive::Embedded);
    for (root, convert) in [
        (std::path::Path::new(converted), true),
        (std::path::Path::new(control), false),
    ] {
        let fixture = Rooted::create(root).await?;
        let database = open_local_with_incarnation(
            fixture.stores.clone(),
            policy(),
            small_hot_audit_limits(),
            fixture.audit.clone(),
            fixture.incarnation,
        )
        .await?;
        database.engine().fixture_reference_local_snapshots(true);
        archived_history(&database, 50).await?;
        let group = database.raft_group().clone();
        group.fixture_local_snapshot_interval(2).await?;
        for number in 50..56 {
            audited_write(&database, number).await?;
            group.fixture_local_snapshot_settled().await?;
        }
        assert!(group.local_snapshots_published().unwrap() > 0);
        let mut record = serde_json::json!({ "by_reference": state_record(&database)? });
        database.shutdown().await?;
        drop(group);
        drop(database);
        let storage = fixture.close().await;
        write_store_manifest(root, "b1-by-reference")?;
        if convert {
            let (fixture, reopened) = reopen_on(root, storage, "embedded conversion").await?;
            assert!(reopened.engine().reopened_from_reference_snapshot());
            assert!(!reopened.engine().stores_reference_local_snapshots());
            assert_eq!(reopened.raft_group().local_snapshots_published(), Some(1));
            record["converted"] = state_record(&reopened)?;
            drop(close_reopened(fixture, reopened).await?);
            write_store_manifest(root, "b2-converted")?;
        } else {
            drop(storage);
        }
        durable_write(
            &root.join("b-record.json"),
            &serde_json::to_vec_pretty(&record)?,
        )?;
    }
    Ok(())
}
