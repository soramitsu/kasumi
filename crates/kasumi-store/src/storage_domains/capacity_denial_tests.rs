//! Settled capacity denials at the store API. A denied catalog or binding
//! write is typed and recoverable: its census child retires, nothing is
//! published or charged, the opening stays open, and the same write succeeds
//! once space is freed. Owner failures are never reported as denials.
use super::*;
use crate::test_utils::{
    LocalKeyProvider, ManualClock, TestDiskMemory, private_tempdir, retry_disk_registry,
};
use kasumi_kv::DatabaseOpenSettlement;
use std::sync::Mutex as StdMutex;

const ID: Uuid = Uuid::from_u128(0x6c1f_0d52_93a4_4e7b_8f35_1a0c_b7d2_e941);
const MEMORY_BYTES: u64 = 256 << 20;
static UNCERTAIN_DIRECTORIES: StdMutex<Vec<tempfile::TempDir>> = StdMutex::new(Vec::new());

/// A persistent disk with a small foreground budget that a test can fill.
fn quota_disk(path: &Path, memory: &Arc<TestDiskMemory>) -> Arc<NodeDisk> {
    let mut config = NodeDisk::fixture_config(path).unwrap();
    config.max_bytes = 64 << 20;
    config.maintenance_reserve_bytes = 1 << 20;
    retry_disk_registry(|| {
        NodeDisk::open_fixture(
            &config,
            memory.clone(),
            &crate::CensusCancellation::default(),
        )
    })
    .unwrap()
}

/// Settle one sparse file over the whole remaining foreground budget, so any
/// further database growth is refused before an effect.
fn fill_disk(disk: &Arc<NodeDisk>) -> crate::NodeDiskFile {
    let filler = disk
        .create_file(
            "fixture",
            Path::new("capacity-filler"),
            crate::DiskWork::Foreground,
        )
        .unwrap();
    let snapshot = disk.snapshot();
    let mut length =
        (snapshot.max_bytes - snapshot.maintenance_reserve_bytes - snapshot.charged_bytes) / 4096
            * 4096;
    while let Err(error) = filler.reserve_growth(0, length, crate::DiskWork::Foreground) {
        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull);
        length -= 4096;
    }
    filler.grow_reserved(length).unwrap();
    filler.sync_all().unwrap();
    filler.settle_growth(length).unwrap();
    filler
}

struct Installed {
    directory: tempfile::TempDir,
    scratch_directory: tempfile::TempDir,
    path: PathBuf,
    memory: Arc<TestDiskMemory>,
    disk: Arc<NodeDisk>,
    scratch: Arc<ScratchDisk>,
    node: Arc<NodeStore>,
}
impl Installed {
    fn new() -> Result<Self> {
        let directory = private_tempdir()?;
        let path = directory.path().join("capacity-denial.kv");
        let memory = TestDiskMemory::new(MEMORY_BYTES, 4096);
        let disk = quota_disk(&path, &memory);
        let scratch_directory = private_tempdir()?;
        let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
        let node = NodeStore::create_new(
            &path,
            ID,
            disk.clone(),
            scratch.clone(),
            crate::test_utils::node_storage_config(),
        )?;
        Ok(Self {
            directory,
            scratch_directory,
            path,
            memory,
            disk,
            scratch,
            node,
        })
    }

    /// Close the node and reopen the same installed file strictly.
    async fn restart(&mut self) -> Result<()> {
        self.node.shutdown().await?;
        assert_eq!(self.memory.storage_census().snapshot().databases, 0);
        self.node = NodeStore::open_existing(
            &self.path,
            ID,
            self.disk.clone(),
            self.scratch.clone(),
            crate::test_utils::node_storage_config(),
        )?;
        Ok(())
    }

    fn writers(&self) -> usize {
        self.memory.storage_census().snapshot().writers
    }

    /// A fenced owner keeps its files; never delete them under the test.
    fn keep_uncertain(self) {
        UNCERTAIN_DIRECTORIES
            .lock()
            .unwrap()
            .extend([self.directory, self.scratch_directory]);
    }
}

fn app_provider() -> Arc<dyn KeyProvider> {
    Arc::new(LocalKeyProvider::new([31; 32]))
}
fn custody_provider() -> Arc<dyn KeyProvider> {
    Arc::new(LocalKeyProvider::new([32; 32]))
}

async fn singleton(node: &Arc<NodeStore>) -> Result<Arc<TenantStore>> {
    TenantStore::initialize_catalog_fixture_with_clock(
        node.clone(),
        "tenant".into(),
        app_provider(),
        Arc::new(ManualClock::new()),
    )
    .await
}

async fn reopen(
    node: &Arc<NodeStore>,
    tenant: String,
    provider: Arc<dyn KeyProvider>,
) -> Result<Arc<TenantStore>> {
    TenantStore::open_existing_fixture_with_clock(
        node.clone(),
        tenant,
        provider,
        Arc::new(ManualClock::new()),
    )
    .await
}

async fn catalogs(node: &Arc<NodeStore>) -> Result<(Arc<TenantStore>, Arc<TenantStore>)> {
    let app = TenantStore::initialize_catalog_fixture_with_clock(
        node.clone(),
        "tenant".into(),
        app_provider(),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let custody = TenantStore::initialize_catalog_fixture_with_clock(
        node.clone(),
        CustodyStore::catalog_name("tenant"),
        custody_provider(),
        Arc::new(ManualClock::new()),
    )
    .await?;
    Ok((app, custody))
}

fn binding_plan(
    app: &TenantStore,
    custody: &TenantStore,
    provider: Arc<dyn NodeDiskMemoryAdmission>,
) -> Result<AdmittedBindingPut> {
    let app_state = app.state.read();
    let custody_state = custody.state.read();
    app.require_access(&app_state)?;
    custody.require_access(&custody_state)?;
    let app_catalog = app.catalog.read();
    let custody_catalog = custody.catalog.read();
    let binding = derive_binding(&app_catalog, &custody_catalog)?;
    AdmittedBindingBytes::prepare(&binding, provider)?.encrypt(
        custody,
        &custody_state,
        &custody_catalog,
    )
}

fn expect_denied(
    error: &anyhow::Error,
    write: CapacityDeniedWrite,
    stage: CapacityDenialStage,
) -> StorageCapacityDenied {
    let denied = *error
        .downcast_ref::<StorageCapacityDenied>()
        .unwrap_or_else(|| {
            let detail = if let Some(failure) = error.downcast_ref::<NodeCatalogWriteFailure>() {
                let report = failure.writer().report();
                crate::test_utils::native_write_diagnostic(
                    report.phase(),
                    report.begin(),
                    report.body(),
                    report.outer(),
                    report.terminal(),
                )
            } else if let Some(failure) = error.downcast_ref::<BindingInstallWriteFailure>() {
                let report = failure.writer().report();
                crate::test_utils::native_write_diagnostic(
                    report.phase(),
                    report.begin(),
                    report.body(),
                    report.outer(),
                    report.terminal(),
                )
            } else if let Some(failure) = error.downcast_ref::<crate::TenantPointReadFailure>() {
                let report = failure.reader().report();
                format!(
                    "phase={:?}, begin={}, tables={}, outer={}, read={}, output={}",
                    report.phase(),
                    crate::test_utils::observation_diagnostic(report.begin()),
                    crate::test_utils::observation_diagnostic(report.tables()),
                    crate::test_utils::observation_diagnostic(report.outer()),
                    crate::test_utils::observation_diagnostic(report.read_failure()),
                    crate::test_utils::observation_diagnostic(report.output_admission())
                )
            } else {
                "unclassified original error".into()
            };
            panic!("expected a typed capacity denial, got {error:#}; {detail}");
        });
    assert_eq!(denied.write(), write);
    assert_eq!(denied.stage(), stage);
    assert!(denied.payload_bytes() > 0);
    assert!(error.downcast_ref::<NodeCatalogWriteFailure>().is_none());
    assert!(error.downcast_ref::<NodeCatalogWriteRetirement>().is_none());
    assert!(error.downcast_ref::<BindingInstallWriteFailure>().is_none());
    assert!(
        error
            .downcast_ref::<BindingInstallWriteRetirement>()
            .is_none()
    );
    denied
}

#[tokio::test]
async fn save_catalog_commit_denial_retires_its_child_and_retries_after_space_is_freed()
-> Result<()> {
    let mut fixture = Installed::new()?;
    let store = singleton(&fixture.node).await?;
    let installed = store.catalog.read().clone();

    let filler = fill_disk(&fixture.disk);
    let charged = fixture.disk.snapshot().charged_bytes;
    let length = std::fs::metadata(&fixture.path)?.len();
    let error = store.rotate_data_key().await.unwrap_err();
    expect_denied(
        &error,
        CapacityDeniedWrite::KeyCatalog,
        CapacityDenialStage::Commit,
    );
    // Nothing was published, charged or leaked, and the opening stays open.
    assert_eq!(fixture.writers(), 0);
    assert_eq!(fixture.disk.snapshot().charged_bytes, charged);
    assert_eq!(std::fs::metadata(&fixture.path)?.len(), length);
    assert!(fixture.node.catalog("tenant")?.unwrap() == installed);
    assert!(*store.catalog.read() == installed);
    // A direct retry while the disk is still full is denied the same way.
    let error = fixture.node.save_catalog("tenant", &installed).unwrap_err();
    expect_denied(
        &error,
        CapacityDeniedWrite::KeyCatalog,
        CapacityDenialStage::Commit,
    );
    assert_eq!(fixture.writers(), 0);

    fixture.disk.delete_file(filler)?;
    store.rotate_data_key().await?;
    let rotated = store.catalog.read().clone();
    assert!(rotated != installed);
    assert!(fixture.node.catalog("tenant")?.unwrap() == rotated);
    assert_eq!(fixture.writers(), 0);
    store.write_batch(&[WriteOp::put("docs", b"key", b"value".to_vec())])?;
    store.shutdown().await?;
    drop(store);

    // Only the retried rotation is durable.
    fixture.restart().await?;
    let store = reopen(&fixture.node, "tenant".into(), app_provider()).await?;
    assert!(*store.catalog.read() == rotated);
    assert_eq!(store.get("docs", b"key")?, Some(b"value".to_vec()));
    store.shutdown().await?;
    fixture.node.shutdown().await?;
    assert_eq!(fixture.memory.storage_census().snapshot().databases, 0);
    Ok(())
}

#[tokio::test]
async fn singleton_initialization_commit_denial_leaves_catalog_absent_and_retries() -> Result<()> {
    let fixture = Installed::new()?;
    let filler = fill_disk(&fixture.disk);
    let Err(error) = singleton(&fixture.node).await else {
        panic!("initialization on a full disk must be denied");
    };
    expect_denied(
        &error,
        CapacityDeniedWrite::KeyCatalog,
        CapacityDenialStage::Commit,
    );
    assert_eq!(fixture.writers(), 0);
    assert!(fixture.node.catalog("tenant")?.is_none());

    fixture.disk.delete_file(filler)?;
    let store = singleton(&fixture.node).await?;
    assert!(fixture.node.catalog("tenant")?.unwrap() == *store.catalog.read());
    assert_eq!(fixture.writers(), 0);
    store.shutdown().await?;
    fixture.node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn binding_install_staging_denial_settles_and_the_same_install_retries() -> Result<()> {
    let fixture = Installed::new()?;
    let (app, custody) = catalogs(&fixture.node).await?;
    let before = fixture.memory.snapshot();
    // Keep the complete install workflow, including its preceding binding
    // point read. Only its actual row-staging allocation is refused.
    let denial = fixture.memory.deny_binding_staging()?;
    let error = TenantStorageSet::install(app.clone(), custody.clone())
        .err()
        .expect("injected row-staging capacity must be denied");
    expect_denied(
        &error,
        CapacityDeniedWrite::DomainBinding,
        CapacityDenialStage::Staging,
    );
    assert_eq!(fixture.writers(), 0);
    denial.assert_refused_chunk_and_fallback();
    drop(denial);
    assert_eq!(fixture.memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(
        fixture.memory.snapshot().live_reservations,
        before.live_reservations
    );
    assert!(custody.get(BINDING_NS, BINDING_KEY)?.is_none());

    let stores = TenantStorageSet::install(app, custody)?;
    assert_eq!(
        stores
            .custody()
            .store()
            .get(BINDING_NS, BINDING_KEY)?
            .unwrap(),
        serde_json::to_vec(stores.custody().binding())?
    );
    assert_eq!(fixture.writers(), 0);
    stores.shutdown().await?;
    fixture.node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn binding_install_commit_denial_publishes_nothing_across_restart_and_retries() -> Result<()>
{
    let mut fixture = Installed::new()?;
    let (app, custody) = catalogs(&fixture.node).await?;
    let filler = fill_disk(&fixture.disk);
    let charged = fixture.disk.snapshot().charged_bytes;
    let length = std::fs::metadata(&fixture.path)?.len();
    let error = TenantStorageSet::install(app.clone(), custody.clone())
        .err()
        .expect("commit on a full disk must be denied");
    let denied = expect_denied(
        &error,
        CapacityDeniedWrite::DomainBinding,
        CapacityDenialStage::Commit,
    );
    assert_eq!(fixture.writers(), 0);
    assert_eq!(fixture.disk.snapshot().charged_bytes, charged);
    assert_eq!(std::fs::metadata(&fixture.path)?.len(), length);
    assert!(custody.get(BINDING_NS, BINDING_KEY)?.is_none());
    // The opening stayed open: a second attempt is denied the same way.
    let error = TenantStorageSet::install(app.clone(), custody.clone())
        .err()
        .expect("still full");
    assert_eq!(
        expect_denied(
            &error,
            CapacityDeniedWrite::DomainBinding,
            CapacityDenialStage::Commit,
        ),
        denied
    );
    assert_eq!(fixture.writers(), 0);

    // Restart before any retry: both catalogs, and no binding, are durable.
    app.shutdown().await?;
    custody.shutdown().await?;
    drop((app, custody));
    fixture.disk.delete_file(filler)?;
    fixture.restart().await?;
    assert!(TenantStorageSet::catalogs_installed(
        &fixture.node,
        "tenant"
    )?);
    let app = reopen(&fixture.node, "tenant".into(), app_provider()).await?;
    let custody = reopen(
        &fixture.node,
        CustodyStore::catalog_name("tenant"),
        custody_provider(),
    )
    .await?;
    assert!(custody.get(BINDING_NS, BINDING_KEY)?.is_none());
    let stores = TenantStorageSet::install(app.clone(), custody.clone())?;
    let binding = stores.custody().binding().clone();
    stores.shutdown().await?;
    drop((stores, app, custody));

    fixture.restart().await?;
    let stores = TenantStorageSet::open_existing_fixture(
        fixture.node.clone(),
        "tenant".into(),
        app_provider(),
        custody_provider(),
    )
    .await?;
    assert_eq!(stores.custody().binding(), &binding);
    stores.shutdown().await?;
    fixture.node.shutdown().await?;
    Ok(())
}

#[test]
fn create_mode_table_denial_releases_the_reservation_and_requeues() -> Result<()> {
    let directory = private_tempdir()?;
    let path = directory.path().join("capacity-denial-tables.kv");
    let memory = TestDiskMemory::new(MEMORY_BYTES, 4096);
    let disk = quota_disk(&path, &memory);
    let opening = RegisteredNodeOpening::prepare(
        &path,
        ID,
        disk.clone(),
        NodeOpeningMode::Create,
        crate::test_utils::node_storage_config(),
    )?;
    assert_eq!(opening.open(), NodeOpeningPhase::Open);

    let filler = fill_disk(&disk);
    let denied = opening.queue_node_tables()?;
    let phase = denied.run();
    assert_eq!(phase, NodeWriterPhase::Finished, "{}", {
        let report = denied.report();
        crate::test_utils::native_write_diagnostic(
            phase,
            report.begin(),
            report.body(),
            report.outer(),
            report.terminal(),
        )
    });
    assert!(denied.report().is_capacity_denied());
    // The denied request never proves Ready, before or after a requeue.
    assert_eq!(
        opening
            .publish_ready_after_tables(&denied)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(
        opening.report().engine().settlement(),
        DatabaseOpenSettlement::Ready
    );
    disk.delete_file(filler)?;

    let tables = opening.queue_node_tables()?;
    assert_eq!(tables.run(), NodeWriterPhase::Finished);
    assert!(!tables.report().is_capacity_denied());
    assert_eq!(
        opening
            .publish_ready_after_tables(&denied)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(denied.retire(), StorageCensusDisposition::Retired);
    opening.publish_ready_after_tables(&tables)?;
    assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
    // A committed request keeps the only create proof.
    assert_eq!(
        opening.queue_node_tables().err().unwrap().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(memory.storage_census().snapshot().writers, 0);
    assert_eq!(opening.close()?, DatabaseOpenSettlement::Closed);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);

    // Restart: the retried tables and Ready header are durable.
    let opening = RegisteredNodeOpening::prepare(
        &path,
        ID,
        disk,
        NodeOpeningMode::Existing,
        crate::test_utils::node_storage_config(),
    )?;
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    {
        let read = opening.begin_store_read()?;
        read.open_table(crate::CATALOG)?;
        read.open_table(crate::RECORDS)?;
    }
    assert_eq!(opening.close()?, DatabaseOpenSettlement::Closed);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
    Ok(())
}

#[test]
fn owner_failure_during_table_creation_keeps_the_create_reservation() -> Result<()> {
    let directory = private_tempdir()?;
    let path = directory.path().join("capacity-denial-tables-fenced.kv");
    let memory = TestDiskMemory::new(MEMORY_BYTES, 4096);
    let disk = quota_disk(&path, &memory);
    let opening = RegisteredNodeOpening::prepare(
        &path,
        ID,
        disk.clone(),
        NodeOpeningMode::Create,
        crate::test_utils::node_storage_config(),
    )?;
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let _filler = fill_disk(&disk);
    disk.fail();
    let tables = opening.queue_node_tables()?;
    let _ = tables.run();
    assert!(!tables.report().is_capacity_denied());
    assert!(opening.queue_node_tables().is_err());
    assert!(opening.publish_ready_after_tables(&tables).is_err());
    UNCERTAIN_DIRECTORIES.lock().unwrap().push(directory);
    Ok(())
}

#[tokio::test]
async fn owner_failure_is_fenced_and_never_reported_as_capacity_denial() -> Result<()> {
    let fixture = Installed::new()?;
    let store = singleton(&fixture.node).await?;
    let catalog = store.catalog.read().clone();
    // The disk is also full, so only the owner failure can classify it.
    let _filler = fill_disk(&fixture.disk);
    fixture.disk.fail();
    let error = fixture.node.save_catalog("tenant", &catalog).unwrap_err();
    assert!(error.downcast_ref::<StorageCapacityDenied>().is_none());
    let failure = error
        .downcast::<NodeCatalogWriteFailure>()
        .expect("owner failure keeps its exact writer");
    assert!(!failure.writer().report().is_capacity_denied());
    assert!(!failure.writer().report().committed_and_disposed());
    // The store did not acknowledge or retire the unproved child.
    assert_eq!(fixture.writers(), 1);
    drop(failure);
    assert_eq!(fixture.writers(), 1);
    // The fence is sticky: a later attempt is refused, never a denial.
    let error = fixture.node.save_catalog("tenant", &catalog).unwrap_err();
    assert!(error.downcast_ref::<StorageCapacityDenied>().is_none());
    assert_eq!(fixture.disk.snapshot().phase, crate::NodeDiskPhase::Failed);
    drop(store);
    fixture.keep_uncertain();
    Ok(())
}

#[tokio::test]
async fn owner_failure_at_binding_commit_is_fenced_and_never_reported_as_capacity_denial()
-> Result<()> {
    let fixture = Installed::new()?;
    let (app, custody) = catalogs(&fixture.node).await?;
    let _filler = fill_disk(&fixture.disk);
    let writer = fixture.node.db.queue_registered_binding_put(
        binding_plan(&app, &custody, fixture.memory.clone())?,
        app.clone(),
        custody.clone(),
    )?;
    writer.fail_owner_before_terminal_for_test();
    let _ = writer.run();
    {
        let report = writer.report();
        assert!(!report.is_capacity_denied());
        assert!(!report.confirmed());
        let terminal = report.terminal().unwrap();
        assert_eq!(
            terminal.operation(),
            Some(kasumi_kv::WriteTerminalOperation::Commit)
        );
        assert!(
            StorageCapacityDenied::settled(
                CapacityDeniedWrite::DomainBinding,
                1,
                report.is_capacity_denied(),
                report.terminal(),
            )
            .is_none()
        );
    }
    assert_eq!(fixture.writers(), 1);
    // The opening is sealed: install cannot retry into a claimed rollback.
    let error = TenantStorageSet::install(app.clone(), custody.clone())
        .err()
        .expect("fenced owner refuses installation");
    assert!(error.downcast_ref::<StorageCapacityDenied>().is_none());
    drop(writer);
    drop((app, custody));
    fixture.keep_uncertain();
    Ok(())
}
