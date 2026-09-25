use super::*;
use crate::test_utils::{
    LocalKeyProvider, ManualClock, TestDiskMemory, private_tempdir, retry_disk_registry,
};
use kasumi_kv::{TerminalObservation, WriteTerminalOperation, WriteTerminalSettlement};
use std::sync::Mutex as StdMutex;
use std::sync::mpsc;
use std::time::Duration;

const ID: Uuid = Uuid::from_u128(0x38a5_c9c5_6a88_41f0_a1a3_a723_fe68_4535);
static UNCERTAIN_DIRECTORIES: StdMutex<Vec<tempfile::TempDir>> = StdMutex::new(Vec::new());

struct Uninstalled {
    _directory: tempfile::TempDir,
    _scratch_directory: tempfile::TempDir,
    memory: Arc<TestDiskMemory>,
    node: Arc<NodeStore>,
    app: Arc<TenantStore>,
    custody: Arc<TenantStore>,
    app_clock: Arc<ManualClock>,
}
async fn uninstalled() -> Result<Uninstalled> {
    let directory = private_tempdir()?;
    let path = directory.path().join("registered-binding-install.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone()))?;
    let scratch_directory = private_tempdir()?;
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch)?;
    let app_clock = Arc::new(ManualClock::new());
    let app = TenantStore::initialize_catalog_fixture_with_clock(
        node.clone(),
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([11; 32])),
        app_clock.clone(),
    )
    .await?;
    let custody = TenantStore::initialize_catalog_fixture_with_clock(
        node.clone(),
        CustodyStore::catalog_name("tenant"),
        Arc::new(LocalKeyProvider::new([12; 32])),
        Arc::new(ManualClock::new()),
    )
    .await?;
    Ok(Uninstalled {
        _directory: directory,
        _scratch_directory: scratch_directory,
        memory,
        node,
        app,
        custody,
        app_clock,
    })
}

fn plan(pair: &Uninstalled) -> Result<AdmittedBindingPut> {
    let app_state = pair.app.state.read();
    let custody_state = pair.custody.state.read();
    pair.app.require_access(&app_state)?;
    pair.custody.require_access(&custody_state)?;
    let app_catalog = pair.app.catalog.read();
    let custody_catalog = pair.custody.catalog.read();
    let binding = derive_binding(&app_catalog, &custody_catalog)?;
    let provider: Arc<dyn NodeDiskMemoryAdmission> = pair.memory.clone();
    AdmittedBindingBytes::prepare(&binding, provider)?.encrypt(
        &pair.custody,
        &custody_state,
        &custody_catalog,
    )
}

#[tokio::test]
async fn binding_bytes_admission_refusal_precedes_native_writer_registration() -> Result<()> {
    let pair = uninstalled().await?;
    let binding = derive_binding(&pair.app.catalog.read(), &pair.custody.catalog.read())?;
    let limit = TestDiskMemory::required_bookkeeping_bytes(1)? + 1;
    let denied = TestDiskMemory::new(limit, 1);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = denied.clone();
    assert!(AdmittedBindingBytes::prepare(&binding, provider).is_err());
    assert_eq!(denied.snapshot().attempts, 1);
    assert_eq!(denied.snapshot().used_bytes, 0);
    assert_eq!(denied.storage_census().snapshot().writers, 0);
    assert_eq!(pair.memory.storage_census().snapshot().writers, 0);
    pair.node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn installed_missing_binding_uses_registered_writer_and_decodes_exact_record() -> Result<()> {
    let pair = uninstalled().await?;
    let before = pair.memory.snapshot();
    let stores = TenantStorageSet::install(pair.app.clone(), pair.custody.clone())?;
    assert_eq!(pair.memory.storage_census().snapshot().writers, 0);
    assert_eq!(pair.memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(
        stores
            .custody()
            .store()
            .get(BINDING_NS, BINDING_KEY)?
            .unwrap(),
        serde_json::to_vec(stores.custody().binding())?
    );
    stores.shutdown().await?;
    pair.node.shutdown().await?;
    assert_eq!(pair.memory.storage_census().snapshot().databases, 0);
    Ok(())
}

#[tokio::test]
async fn settled_binding_writer_waits_for_busy_opening_before_disposal() -> Result<()> {
    let pair = uninstalled().await?;
    let writer = pair.node.db.queue_registered_binding_put(
        plan(&pair)?,
        pair.app.clone(),
        pair.custody.clone(),
    )?;
    let queued_behind = pair.node.db.queue_registered_binding_put(
        plan(&pair)?,
        pair.app.clone(),
        pair.custody.clone(),
    )?;
    let provider: Arc<dyn NodeDiskMemoryAdmission> = pair.memory.clone();
    let observer = RegisteredBindingPut::retained(provider, writer.id()).unwrap();
    let (start_tx, start_rx) = mpsc::channel::<()>();
    let (held_tx, held_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        start_rx.recv().unwrap();
        observer.hold_database_state_for_test(|| {
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
    });
    writer.before_dispose_for_test(Box::new(move || {
        start_tx.send(()).unwrap();
        held_rx.recv().unwrap();
        ready_tx.send(()).unwrap();
    }));
    let (done_tx, done_rx) = mpsc::channel();
    let runner = std::thread::spawn(move || {
        let phase = writer.run();
        done_tx.send((phase, writer)).unwrap();
    });
    ready_rx.recv_timeout(Duration::from_secs(5))?;
    let (second_tx, second_rx) = mpsc::channel();
    let second_runner = std::thread::spawn(move || {
        let phase = queued_behind.run();
        second_tx.send((phase, queued_behind)).unwrap();
    });
    let premature = done_rx.recv_timeout(Duration::from_millis(150)).ok();
    let second_premature = second_rx.try_recv().ok();
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    let completed_while_busy = premature.is_some();
    let second_completed_while_busy = second_premature.is_some();
    let (phase, writer) = match premature {
        Some(completed) => completed,
        None => done_rx.recv_timeout(Duration::from_secs(5))?,
    };
    runner.join().unwrap();
    let (second_phase, second) = match second_premature {
        Some(completed) => completed,
        None => second_rx.recv_timeout(Duration::from_secs(5))?,
    };
    second_runner.join().unwrap();
    assert!(
        !completed_while_busy,
        "writer left disposal while opening state was held"
    );
    assert!(
        !second_completed_while_busy,
        "later writer bypassed the opening serial gate"
    );
    assert_eq!(phase, NodeWriterPhase::Finished);
    assert_eq!(second_phase, NodeWriterPhase::Finished);
    let report = writer.report();
    assert!(report.confirmed());
    let terminal = report.terminal().unwrap();
    assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Commit));
    assert_eq!(terminal.settlement(), WriteTerminalSettlement::Settled);
    assert!(terminal.disposal_complete());
    drop(report);
    assert!(second.report().confirmed());
    assert_eq!(writer.retire(), StorageCensusDisposition::Retired);
    assert_eq!(second.retire(), StorageCensusDisposition::Retired);
    pair.node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn close_during_settled_binding_disposal_preserves_exact_child() -> Result<()> {
    let pair = uninstalled().await?;
    let writer = pair.node.db.queue_registered_binding_put(
        plan(&pair)?,
        pair.app.clone(),
        pair.custody.clone(),
    )?;
    let provider: Arc<dyn NodeDiskMemoryAdmission> = pair.memory.clone();
    let observer = RegisteredBindingPut::retained(provider.clone(), writer.id()).unwrap();
    let opening =
        RegisteredNodeOpening::retained(provider, pair.node.db.registered_opening_id().unwrap())
            .unwrap();
    let (start_tx, start_rx) = mpsc::channel::<()>();
    let (held_tx, held_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        start_rx.recv().unwrap();
        observer.hold_database_state_for_test(|| {
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
    });
    writer.before_dispose_for_test(Box::new(move || {
        start_tx.send(()).unwrap();
        held_rx.recv().unwrap();
        ready_tx.send(()).unwrap();
    }));
    let (done_tx, done_rx) = mpsc::channel();
    let runner = std::thread::spawn(move || {
        let phase = writer.run();
        done_tx.send((phase, writer)).unwrap();
    });
    ready_rx.recv_timeout(Duration::from_secs(5))?;
    assert_eq!(
        opening.close().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(pair.memory.storage_census().snapshot().writers, 1);
    let premature = done_rx.recv_timeout(Duration::from_millis(150)).ok();
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    let completed_while_busy = premature.is_some();
    let (phase, writer) = match premature {
        Some(completed) => completed,
        None => done_rx.recv_timeout(Duration::from_secs(5))?,
    };
    runner.join().unwrap();
    assert!(
        !completed_while_busy,
        "writer exited while its close witness was busy"
    );
    assert_eq!(phase, NodeWriterPhase::Finished);
    {
        let report = writer.report();
        assert!(report.committed_and_disposed());
        assert_eq!(
            report.terminal().unwrap().settlement(),
            WriteTerminalSettlement::Settled
        );
    }
    assert_eq!(writer.retire(), StorageCensusDisposition::Retired);
    assert_eq!(opening.close()?, kasumi_kv::DatabaseOpenSettlement::Closed);
    drop(opening);
    pair.node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn post_commit_access_failure_remains_on_exact_child_after_facade_drop() -> Result<()> {
    let pair = uninstalled().await?;
    let writer = pair.node.db.queue_registered_binding_put(
        plan(&pair)?,
        pair.app.clone(),
        pair.custody.clone(),
    )?;
    let clock = pair.app_clock.clone();
    writer.after_commit_for_test(Box::new(move || clock.advance(MAX_KEY_LEASE)));
    let id = writer.id();
    assert_eq!(writer.run(), NodeWriterPhase::Finished);
    let original = {
        let report = writer.report();
        assert!(report.committed_and_disposed());
        assert!(!report.confirmed());
        let TerminalObservation::Returned(Err(error)) = report.post_commit() else {
            panic!("expected actual post-commit access refusal");
        };
        std::ptr::from_ref(error)
    };
    let Uninstalled {
        _directory,
        _scratch_directory,
        memory,
        node,
        app,
        custody,
        app_clock: _,
    } = pair;
    UNCERTAIN_DIRECTORIES
        .lock()
        .unwrap()
        .extend([_directory, _scratch_directory]);
    drop(writer);
    drop(app);
    drop(custody);
    drop(node);
    let snapshot = memory.storage_census().drain().unwrap();
    assert_eq!(snapshot.databases, 1);
    assert_eq!(snapshot.writers, 1);
    let retained = RegisteredBindingPut::retained(memory.clone(), id).unwrap();
    assert_eq!(retained.run(), NodeWriterPhase::Finished);
    {
        let report = retained.report();
        let TerminalObservation::Returned(Err(error)) = report.post_commit() else {
            panic!("post-commit access refusal lost");
        };
        assert_eq!(std::ptr::from_ref(error), original);
        let terminal = report.terminal().unwrap();
        assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Commit));
        assert!(terminal.disposal_complete());
    }
    // This explicit report inspection acknowledges a physically disposed
    // writer. The post-commit access failure remained available until now.
    assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
    Ok(())
}

#[tokio::test]
async fn native_commit_refusal_retains_original_terminal_and_never_replays() -> Result<()> {
    let pair = uninstalled().await?;
    let writer = pair.node.db.queue_registered_binding_put(
        plan(&pair)?,
        pair.app.clone(),
        pair.custody.clone(),
    )?;
    writer.fail_owner_before_terminal_for_test();
    let id = writer.id();
    assert_eq!(writer.run(), NodeWriterPhase::Disposal);
    let original = {
        let report = writer.report();
        let terminal = report.terminal().unwrap();
        assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Commit));
        assert_eq!(terminal.settlement(), WriteTerminalSettlement::Retained);
        assert!(!terminal.disposal_complete());
        let TerminalObservation::Returned(Err(error)) = terminal.terminal() else {
            panic!("expected actual native commit refusal");
        };
        std::ptr::from_ref(error)
    };
    let Uninstalled {
        _directory,
        _scratch_directory,
        memory,
        node,
        app,
        custody,
        app_clock: _,
    } = pair;
    UNCERTAIN_DIRECTORIES
        .lock()
        .unwrap()
        .extend([_directory, _scratch_directory]);
    drop(writer);
    drop(app);
    drop(custody);
    drop(node);
    let snapshot = memory.storage_census().drain().unwrap();
    assert_eq!(snapshot.databases, 1);
    assert_eq!(snapshot.writers, 1);
    let retained = RegisteredBindingPut::retained(memory.clone(), id).unwrap();
    assert_eq!(retained.run(), NodeWriterPhase::Disposal);
    {
        let report = retained.report();
        let terminal = report.terminal().unwrap();
        let TerminalObservation::Returned(Err(error)) = terminal.terminal() else {
            panic!("original native commit refusal lost");
        };
        assert_eq!(std::ptr::from_ref(error), original);
        assert_eq!(terminal.operation(), Some(WriteTerminalOperation::Commit));
    }
    assert_eq!(retained.retire(), StorageCensusDisposition::Retained);
    Ok(())
}
