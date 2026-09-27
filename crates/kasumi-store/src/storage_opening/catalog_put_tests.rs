use super::*;
use crate::{
    NodeStore, ScratchDisk,
    storage_opening::write_plan,
    test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry},
};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;

const ID: Uuid = Uuid::from_u128(0x38a5_c9c5_6a88_41f0_a1a3_a723_fe68_4535);

fn disk(path: &Path, memory: &Arc<TestDiskMemory>) -> Arc<NodeDisk> {
    retry_disk_registry(|| NodeDisk::fixture_for_path(path, memory.clone())).unwrap()
}

fn catalog_for_registered_write() -> crate::KeyCatalog {
    let wrapped = crate::WrappedKey {
        provider: "fixture".into(),
        key_ref: "fixed".into(),
        ciphertext: "opaque".into(),
        version: 1,
        context: None,
    };
    crate::KeyCatalog {
        format: 1,
        catalog_id: uuid::Uuid::from_u128(42),
        tenant: "catalog-writer".into(),
        purpose: crate::StoragePurpose::LocalFixture,
        active: "current".into(),
        keys: std::collections::BTreeMap::from([
            ("index".into(), wrapped.clone()),
            ("current".into(), wrapped),
        ]),
    }
}

async fn unpublished_pair(
    node: Arc<NodeStore>,
    application_name: &str,
    custody_name: &str,
) -> (Arc<crate::TenantStore>, Arc<crate::TenantStore>) {
    use crate::test_utils::LocalKeyProvider;

    let application_access = crate::StorageAccess::fixture();
    let custody_access = crate::StorageAccess::custody(application_name);
    let application_provider: Arc<dyn crate::KeyProvider> =
        Arc::new(LocalKeyProvider::new([81; 32]));
    let custody_provider: Arc<dyn crate::KeyProvider> = Arc::new(LocalKeyProvider::new([82; 32]));
    let application_catalog = crate::TenantStore::generate_catalog(
        application_name,
        &application_provider,
        &application_access,
    )
    .await
    .unwrap();
    let custody_catalog =
        crate::TenantStore::generate_catalog(custody_name, &custody_provider, &custody_access)
            .await
            .unwrap();
    (
        crate::TenantStore::unpublished(
            node.clone(),
            application_name.to_owned(),
            application_provider,
            application_access,
            Arc::new(crate::SystemLeaseClock),
            application_catalog,
        ),
        crate::TenantStore::unpublished(
            node,
            custody_name.to_owned(),
            custody_provider,
            custody_access,
            Arc::new(crate::SystemLeaseClock),
            custody_catalog,
        ),
    )
}

fn pair_plan(
    application: &Arc<crate::TenantStore>,
    custody: &Arc<crate::TenantStore>,
    memory: &Arc<TestDiskMemory>,
    swapped: bool,
) -> write_plan::AdmittedCatalogPairPut {
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let application_catalog = application.catalog.read();
    let custody_catalog = custody.catalog.read();
    if swapped {
        write_plan::AdmittedCatalogPairPut::prepare(
            custody.tenant(),
            &custody_catalog,
            application.tenant(),
            &application_catalog,
            provider,
        )
        .unwrap()
    } else {
        write_plan::AdmittedCatalogPairPut::prepare(
            application.tenant(),
            &application_catalog,
            custody.tenant(),
            &custody_catalog,
            provider,
        )
        .unwrap()
    }
}

#[tokio::test]
async fn paired_catalog_rejects_foreign_owner_and_identity_before_registration() {
    let directory = private_tempdir().unwrap();
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let path = directory.path().join("paired-owner.kv");
    let scratch_directory = private_tempdir().unwrap();
    let node = NodeStore::create_new(
        &path,
        ID,
        disk(&path, &memory),
        ScratchDisk::fixture(scratch_directory.path(), memory.clone()),
    )
    .unwrap();
    let foreign_path = directory.path().join("foreign-owner.kv");
    let foreign_scratch_directory = private_tempdir().unwrap();
    let foreign = NodeStore::create_new(
        &foreign_path,
        Uuid::from_u128(0x38a5_c9c5_6a88_41f0_a1a3_a723_fe68_4536),
        disk(&foreign_path, &memory),
        ScratchDisk::fixture(foreign_scratch_directory.path(), memory.clone()),
    )
    .unwrap();
    let custody_name = crate::CustodyStore::catalog_name("catalog-writer");

    let (foreign_application, foreign_custody) =
        unpublished_pair(foreign.clone(), "catalog-writer", &custody_name).await;
    let before = memory.snapshot();
    let foreign_plan = pair_plan(&foreign_application, &foreign_custody, &memory, false);
    assert!(
        node.db
            .queue_registered_catalog_pair_put(foreign_plan, foreign_application, foreign_custody,)
            .is_err(),
        "a foreign NodeStore with the same memory provider must be rejected"
    );
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(memory.storage_census().snapshot().writers, 0);

    let (application, custody) =
        unpublished_pair(node.clone(), "catalog-writer", &custody_name).await;
    let before = memory.snapshot();
    let swapped_plan = pair_plan(&application, &custody, &memory, true);
    assert!(
        node.db
            .queue_registered_catalog_pair_put(swapped_plan, application.clone(), custody.clone())
            .is_err(),
        "ordered plan hashes must match the two stores"
    );
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(memory.storage_census().snapshot().writers, 0);

    let before = memory.snapshot();
    let plan = pair_plan(&application, &custody, &memory, false);
    assert!(
        node.db
            .queue_registered_catalog_pair_put(plan, custody, application)
            .is_err(),
        "swapped store roles must be rejected"
    );
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(memory.storage_census().snapshot().writers, 0);

    let foreign_custody_name = crate::CustodyStore::catalog_name("other-tenant");
    let (application, custody) =
        unpublished_pair(node.clone(), "catalog-writer", &foreign_custody_name).await;
    let before = memory.snapshot();
    let plan = pair_plan(&application, &custody, &memory, false);
    assert!(
        node.db
            .queue_registered_catalog_pair_put(plan, application, custody)
            .is_err(),
        "custody identity must derive from the application tenant"
    );
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(memory.storage_census().snapshot().writers, 0);

    for owner in [&node, &foreign] {
        for tenant in ["catalog-writer", &custody_name, &foreign_custody_name] {
            assert!(owner.catalog(tenant).unwrap().is_none());
        }
    }
    node.shutdown().await.unwrap();
    foreign.shutdown().await.unwrap();
}

#[tokio::test]
async fn production_catalog_save_uses_registered_writer_and_reopens_value() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("registered-catalog-save.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk.clone(), scratch).unwrap();
    let catalog = catalog_for_registered_write();
    let before = memory.snapshot();
    node.save_catalog("catalog-writer", &catalog).unwrap();
    assert_eq!(memory.storage_census().snapshot().writers, 0);
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert!(
        node.catalog("catalog-writer")
            .unwrap()
            .as_ref()
            .is_some_and(|read| read == &catalog)
    );
    node.shutdown().await.unwrap();
    drop(node);

    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let reopened = NodeStore::open_existing(&path, ID, disk, scratch).unwrap();
    assert!(
        reopened
            .catalog("catalog-writer")
            .unwrap()
            .as_ref()
            .is_some_and(|read| read == &catalog)
    );
    reopened.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}

static UNCERTAIN_CATALOG_DIRECTORY: std::sync::Mutex<Option<tempfile::TempDir>> =
    std::sync::Mutex::new(None);
static UNCERTAIN_PAIR_DIRECTORY: std::sync::Mutex<Option<tempfile::TempDir>> =
    std::sync::Mutex::new(None);

#[test]
fn clean_catalog_writer_releases_busy_report_on_exact_retirement_retry() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("catalog-retirement-retry.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening = RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let tables = opening.queue_node_tables().unwrap();
    assert_eq!(tables.run(), NodeWriterPhase::Finished);
    opening.publish_ready_after_tables(&tables).unwrap();
    assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let plan = write_plan::AdmittedCatalogPut::prepare(
        "catalog-writer",
        &catalog_for_registered_write(),
        provider.clone(),
    )
    .unwrap();
    let writer = opening.queue_catalog_put(plan).unwrap();
    assert_eq!(writer.run(), NodeWriterPhase::Finished);
    assert!(writer.report().committed_and_disposed());
    let id = writer.id();
    let observer = RegisteredCatalogPut::retained(provider.clone(), id).unwrap();
    let report = observer.report();
    assert_eq!(writer.retire(), StorageCensusDisposition::Retained);
    drop(report);
    drop(observer);
    let pending = crate::NodeCatalogWriteRetirement {
        provider,
        id,
        disposition: StorageCensusDisposition::Retained,
    };
    assert_eq!(
        pending.retry_retirement(),
        StorageCensusDisposition::Retired
    );
    assert_eq!(memory.storage_census().snapshot().writers, 0);
    assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn catalog_terminal_refusal_keeps_exact_child_and_never_replays_commit() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("catalog-terminal-refusal.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening = RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    *UNCERTAIN_CATALOG_DIRECTORY.lock().unwrap() = Some(directory);
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let tables = opening.queue_node_tables().unwrap();
    assert_eq!(tables.run(), NodeWriterPhase::Finished);
    opening.publish_ready_after_tables(&tables).unwrap();
    assert_eq!(tables.retire(), StorageCensusDisposition::Retired);

    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let plan = write_plan::AdmittedCatalogPut::prepare(
        "catalog-writer",
        &catalog_for_registered_write(),
        provider,
    )
    .unwrap();
    let writer = opening.queue_catalog_put(plan).unwrap();
    writer.fail_owner_before_terminal_for_test();
    let id = writer.id();
    let opening_id = opening.id();
    assert_eq!(writer.run(), NodeWriterPhase::Disposal);
    let original = {
        let report = writer.report();
        assert!(!report.committed_and_disposed());
        let terminal = report.terminal().unwrap();
        assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Commit));
        assert_eq!(
            terminal.settlement(),
            kasumi_kv::WriteTerminalSettlement::Retained
        );
        assert!(!terminal.disposal_complete());
        let TerminalObservation::Returned(Err(error)) = terminal.terminal() else {
            panic!("expected actual commit refusal");
        };
        std::ptr::from_ref(error)
    };
    drop(writer);
    drop(opening);
    let held = memory.snapshot();
    let snapshot = memory.storage_census().drain().unwrap();
    assert_eq!(snapshot.databases, 1);
    assert_eq!(snapshot.writers, 1);
    assert_eq!(memory.snapshot(), held);
    let retained = RegisteredCatalogPut::retained(memory.clone(), id).unwrap();
    assert_eq!(retained.run(), NodeWriterPhase::Disposal);
    {
        let report = retained.report();
        let terminal = report.terminal().unwrap();
        let TerminalObservation::Returned(Err(error)) = terminal.terminal() else {
            panic!("original commit failure lost");
        };
        assert_eq!(std::ptr::from_ref(error), original);
        assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Commit));
    }
    assert_eq!(retained.retire(), StorageCensusDisposition::Retained);
    let opening = RegisteredNodeOpening::retained(memory.clone(), opening_id).unwrap();
    assert!(matches!(
        opening.close().unwrap(),
        DatabaseOpenSettlement::WaitingForTransactions | DatabaseOpenSettlement::DrainedWithFailure
    ));
    assert_eq!(opening.retire(), StorageCensusDisposition::Retained);
}

#[tokio::test]
async fn fresh_catalog_writer_aborts_existing_and_orphan_rows_without_replacing_them() {
    for kind in ["existing", "orphan"] {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join(format!("fresh-catalog-{kind}.kv"));
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk = disk(&path, &memory);
        let scratch_directory = private_tempdir().unwrap();
        let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
        let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
        let catalog = catalog_for_registered_write();
        let hash = crate::tenant_hash(&catalog.tenant);
        if kind == "existing" {
            node.save_catalog(&catalog.tenant, &catalog).unwrap();
        } else {
            let mut orphan_key = hash.to_vec();
            orphan_key.extend_from_slice(b"orphan");
            let tx = node.db.begin_write().unwrap();
            tx.open_table(crate::RECORDS)
                .unwrap()
                .insert(orphan_key.as_slice(), b"untouched ciphertext".as_slice())
                .unwrap();
            tx.commit().unwrap();
        }
        let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
        let plan =
            write_plan::AdmittedCatalogPut::prepare_fresh(&catalog.tenant, &catalog, provider)
                .unwrap();
        let writer = node.db.queue_registered_catalog_put(plan).unwrap();
        assert_eq!(writer.run(), NodeWriterPhase::Finished);
        {
            let report = writer.report();
            assert_eq!(
                report.clean_freshness_rejection(),
                Some(if kind == "existing" {
                    "catalog already initialized"
                } else {
                    "new catalog has orphan physical rows"
                })
            );
            assert_eq!(
                report.terminal().unwrap().operation(),
                Some(WriteTerminalOperation::Abort)
            );
            assert!(report.terminal().unwrap().disposal_complete());
        }
        assert_eq!(writer.retire(), StorageCensusDisposition::Retired);
        assert_eq!(memory.storage_census().snapshot().writers, 0);
        let read = node.db.begin_read().unwrap();
        let stored = read.open_table(crate::CATALOG).unwrap();
        assert_eq!(
            stored.get(hash.as_slice()).unwrap().is_some(),
            kind == "existing"
        );
        if kind == "orphan" {
            let mut orphan_key = hash.to_vec();
            orphan_key.extend_from_slice(b"orphan");
            assert_eq!(
                read.open_table(crate::RECORDS)
                    .unwrap()
                    .get(orphan_key.as_slice())
                    .unwrap()
                    .unwrap()
                    .value(),
                b"untouched ciphertext"
            );
        }
        drop(stored);
        drop(read);
        node.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn paired_catalog_terminal_refusal_retains_one_child_and_original_outcome() {
    use crate::test_utils::LocalKeyProvider;

    let directory = private_tempdir().unwrap();
    let path = directory.path().join("pair-terminal-refusal.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    *UNCERTAIN_PAIR_DIRECTORY.lock().unwrap() = Some(directory);
    let application_name = "catalog-writer".to_owned();
    let custody_name = crate::CustodyStore::catalog_name(&application_name);
    let application_access = crate::StorageAccess::fixture();
    let custody_access = crate::StorageAccess::custody(&application_name);
    let application_provider: Arc<dyn crate::KeyProvider> =
        Arc::new(LocalKeyProvider::new([71; 32]));
    let custody_provider: Arc<dyn crate::KeyProvider> = Arc::new(LocalKeyProvider::new([72; 32]));
    let application_catalog = crate::TenantStore::generate_catalog(
        &application_name,
        &application_provider,
        &application_access,
    )
    .await
    .unwrap();
    let custody_catalog =
        crate::TenantStore::generate_catalog(&custody_name, &custody_provider, &custody_access)
            .await
            .unwrap();
    let application = crate::TenantStore::unpublished(
        node.clone(),
        application_name.clone(),
        application_provider,
        application_access,
        Arc::new(crate::SystemLeaseClock),
        application_catalog,
    );
    let custody = crate::TenantStore::unpublished(
        node.clone(),
        custody_name.clone(),
        custody_provider,
        custody_access,
        Arc::new(crate::SystemLeaseClock),
        custody_catalog,
    );
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let plan = {
        let application_catalog = application.catalog.read();
        let custody_catalog = custody.catalog.read();
        write_plan::AdmittedCatalogPairPut::prepare(
            &application_name,
            &application_catalog,
            &custody_name,
            &custody_catalog,
            provider.clone(),
        )
        .unwrap()
    };
    let writer = node
        .db
        .queue_registered_catalog_pair_put(plan, application, custody)
        .unwrap();
    writer.fail_owner_before_terminal_for_test();
    let id = writer.id();
    assert_eq!(writer.run(), NodeWriterPhase::Disposal);
    let original = {
        let report = writer.report();
        assert!(!report.committed_and_disposed());
        assert!(matches!(
            report.post_commit(),
            TerminalObservation::NotEntered
        ));
        let terminal = report.terminal().unwrap();
        assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Commit));
        assert!(!terminal.disposal_complete());
        let TerminalObservation::Returned(Err(error)) = terminal.terminal() else {
            panic!("expected original native commit refusal");
        };
        std::ptr::from_ref(error)
    };
    let held = memory.snapshot();
    drop(writer);
    assert_eq!(memory.storage_census().snapshot().writers, 1);
    assert_eq!(memory.snapshot(), held);
    let retained = RegisteredCatalogPut::retained(provider, id).unwrap();
    assert_eq!(retained.run(), NodeWriterPhase::Disposal);
    {
        let report = retained.report();
        let terminal = report.terminal().unwrap();
        let TerminalObservation::Returned(Err(error)) = terminal.terminal() else {
            panic!("original native commit refusal was lost");
        };
        assert_eq!(std::ptr::from_ref(error), original);
        assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Commit));
    }
    assert_eq!(retained.retire(), StorageCensusDisposition::Retained);
}

fn catalog_named(tenant: &str, ciphertext: String) -> crate::KeyCatalog {
    let mut catalog = catalog_for_registered_write();
    catalog.tenant = tenant.into();
    for key in catalog.keys.values_mut() {
        key.ciphertext = ciphertext.clone();
    }
    catalog
}

/// Larger than any filesystem allocation unit, so its frame must grow the
/// database file beyond the extent it already owns.
fn replacement_catalog() -> crate::KeyCatalog {
    catalog_named("catalog-writer", "r".repeat(64 << 10))
}

fn second_catalog() -> crate::KeyCatalog {
    catalog_named("second-tenant", "opaque".into())
}

/// A fixture disk whose foreground extent budget is small enough to fill.
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
fn fill_foreground(disk: &Arc<NodeDisk>) -> crate::NodeDiskFile {
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
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        length -= 4096;
    }
    filler.grow_reserved(length).unwrap();
    filler.sync_all().unwrap();
    filler.settle_growth(length).unwrap();
    filler
}

const CAPACITY_CHILD_PATH: &str = "KASUMI_CATALOG_CAPACITY_CHILD_PATH";

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run_capacity_child(path: &Path) {
    let log_path = path.with_extension("capacity-child.log");
    // The log shares the installed root, whose census admits only private
    // regular files.
    let log = std::os::unix::fs::OpenOptionsExt::mode(
        std::fs::OpenOptions::new().write(true).create_new(true),
        0o600,
    )
    .open(&log_path)
    .unwrap();
    let mut child = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage_opening::catalog_put::tests::catalog_capacity_child",
                "--ignored",
                "--nocapture",
            ])
            .env(CAPACITY_CHILD_PATH, path)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        match child.0.try_wait().unwrap() {
            Some(status) => break Some(status),
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            None => break None,
        }
    };
    if status.is_some_and(|status| status.code() == Some(77)) {
        return;
    }
    drop(child);
    panic!(
        "catalog capacity child failed: {status:?}; log={}",
        String::from_utf8_lossy(&std::fs::read(&log_path).unwrap_or_default())
    );
}

/// Installed NodeDisk custody: the old catalog commits, the disk fills, and a
/// replacement is refused for capacity at commit. The refusal settles: the
/// census child retires, charges and file length are unchanged and the
/// opening stays open, so a later put commits once space is freed. The
/// process then exits without closing anything.
#[test]
#[ignore = "subprocess helper; invoked with an owned temporary path"]
fn catalog_capacity_child() {
    let Some(path) = std::env::var_os(CAPACITY_CHILD_PATH) else {
        return;
    };
    let path = PathBuf::from(path);
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = quota_disk(&path, &memory);
    let opening =
        RegisteredNodeOpening::prepare(&path, ID, disk.clone(), NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let tables = opening.queue_node_tables().unwrap();
    assert_eq!(tables.run(), NodeWriterPhase::Finished);
    opening.publish_ready_after_tables(&tables).unwrap();
    assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let put = |catalog: &crate::KeyCatalog| {
        let plan =
            write_plan::AdmittedCatalogPut::prepare(&catalog.tenant, catalog, provider.clone())
                .unwrap();
        let writer = opening.queue_catalog_put(plan).unwrap();
        assert_eq!(writer.run(), NodeWriterPhase::Finished);
        writer
    };
    let writer = put(&catalog_for_registered_write());
    assert!(writer.report().committed_and_disposed());
    assert_eq!(writer.retire(), StorageCensusDisposition::Retired);

    let filler = fill_foreground(&disk);
    let charged = disk.snapshot().charged_bytes;
    let length = std::fs::metadata(&path).unwrap().len();
    let writer = put(&replacement_catalog());
    {
        let report = writer.report();
        assert!(report.is_capacity_denied());
        assert!(!report.committed_and_disposed());
        assert!(matches!(
            report.body(),
            TerminalObservation::Returned(Ok(()))
        ));
        let terminal = report.terminal().unwrap();
        assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Commit));
        assert_eq!(
            terminal.settlement(),
            kasumi_kv::WriteTerminalSettlement::Settled
        );
        assert!(terminal.is_capacity_denied());
        assert!(terminal.disposal_complete());
    }
    assert_eq!(writer.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.storage_census().snapshot().writers, 0);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
    assert_eq!(
        opening.report().engine().settlement(),
        DatabaseOpenSettlement::Ready
    );

    disk.delete_file(filler).unwrap();
    let writer = put(&second_catalog());
    assert!(writer.report().committed_and_disposed());
    assert_eq!(writer.retire(), StorageCensusDisposition::Retired);
    std::process::exit(77);
}

#[test]
fn installed_catalog_capacity_denial_keeps_opening_open_and_reopens_old_catalog() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("catalog-capacity.kv");
    run_capacity_child(&path);

    let memory = TestDiskMemory::new(256 << 20, 4096);
    let opening =
        RegisteredNodeOpening::prepare(&path, ID, disk(&path, &memory), NodeOpeningMode::Existing)
            .unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    {
        let read = opening.begin_store_read().unwrap();
        let catalogs = read.open_table(crate::CATALOG).unwrap();
        for catalog in [catalog_for_registered_write(), second_catalog()] {
            assert_eq!(
                catalogs
                    .get(crate::tenant_hash(&catalog.tenant).as_slice())
                    .unwrap()
                    .unwrap()
                    .value(),
                serde_json::to_vec(&catalog).unwrap().as_slice()
            );
        }
    }
    assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
}
