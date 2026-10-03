//! Fenced registered-owner reopen: typed refusal while any holder lives, exact
//! census restoration after drain, and a retained fence on every census failure.
use super::*;
use crate::test_utils::{TestDiskMemory, retry_disk_registry};
use std::{
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::mpsc,
    time::Duration,
};

fn installation() -> (tempfile::TempDir, NodeDiskConfig) {
    let directory = crate::test_utils::private_tempdir().unwrap();
    let root = directory.path().join("owned");
    crate::private_files::create_directory(&root).unwrap();
    let config = NodeDiskConfig {
        native_storage: crate::test_utils::node_storage_config(),
        roots: BTreeMap::from([("data".into(), root)]),
        max_bytes: 16 << 20,
        maintenance_reserve_bytes: 1 << 20,
        min_free_bytes: 0,
        max_open_files: 16,
        max_open_directories: 16,
        directory_policy: DirectoryPolicy::fixture(),
        // Explicit strict policy keeps these failure-boundary fixtures exact.
        file_allocation_policy: FileAllocationPolicy::new(0).unwrap(),
        max_persistent_files: 10_000,
        max_persistent_subdirectories: 10_000,
        census_work_per_step: 10_000,
        max_depth: 32,
        max_name_bytes: 255,
    };
    (directory, config)
}

/// Durable raw contents written before the owner's initial census.
fn seed(config: &NodeDiskConfig, name: &str, byte: u8, len: usize) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(config.roots["data"].join(name))
        .unwrap();
    file.write_all(&vec![byte; len]).unwrap();
    file.sync_all().unwrap();
}

fn fixture() -> (
    tempfile::TempDir,
    NodeDiskConfig,
    Arc<TestDiskMemory>,
    Arc<NodeDisk>,
) {
    let (directory, config) = installation();
    crate::private_files::create_directory(&config.roots["data"].join("nested")).unwrap();
    seed(&config, "one", 0x11, 48 << 10);
    seed(&config, "two", 0x22, 20 << 10);
    seed(&config, "nested/three", 0x33, 12 << 10);
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = retry_disk_registry(|| {
        NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap();
    assert_eq!(disk.snapshot().persistent_files, 3);
    (directory, config, memory, disk)
}

fn open(
    config: &NodeDiskConfig,
    memory: &Arc<TestDiskMemory>,
) -> std::result::Result<Arc<NodeDisk>, DiskOpenError> {
    retry_disk_registry(|| NodeDisk::open(config, memory.clone(), &CensusCancellation::default()))
}

fn reopen(
    config: &NodeDiskConfig,
    memory: &Arc<TestDiskMemory>,
    cancel: &CensusCancellation,
) -> std::result::Result<Arc<NodeDisk>, DiskOpenError> {
    retry_disk_registry(|| {
        // Checkpoint fixtures count from each actual attempt, never from a
        // busy-registry attempt that stopped before acquiring the registry.
        cancel.checkpoints.store(0, Ordering::Relaxed);
        NodeDisk::reopen_fenced(config, memory.clone(), cancel)
    })
}

/// Every census-derived total a fenced reopen must restore exactly.
fn accounting(disk: &NodeDisk) -> [u64; 6] {
    let snapshot = disk.snapshot();
    [
        snapshot.charged_bytes,
        snapshot.pending_bytes,
        snapshot.persistent_files,
        snapshot.persistent_directories,
        snapshot.observed_directory_bytes,
        snapshot.filesystem_pending_bytes,
    ]
}

fn generation(disk: &NodeDisk) -> u64 {
    disk.lock_state().accepted_census_generation
}

/// Latch an uncertain parent sync on an enrolled file. Neither its contents
/// nor any extent changes, so a later census must reproduce the prior totals.
fn fence(disk: &Arc<NodeDisk>, name: &str) -> NodeDiskFile {
    let file = disk.open_file("data", Path::new(name)).unwrap();
    disk.parent_sync_failure.store(true, Ordering::Relaxed);
    assert!(file.sync_all_and_parent().is_err());
    disk.parent_sync_failure.store(false, Ordering::Relaxed);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert!(!disk.snapshot().filesystem_admission_ready);
    file
}

fn contents(disk: &Arc<NodeDisk>, name: &str, len: usize) -> Vec<u8> {
    let file = disk.open_file("data", Path::new(name)).unwrap();
    assert_eq!(file.observed_len().unwrap(), len as u64);
    let mut bytes = vec![0; len];
    file.read_exact_at(&mut bytes, 0).unwrap();
    bytes
}

fn failed(result: std::result::Result<Arc<NodeDisk>, DiskOpenError>) -> String {
    match result {
        Err(DiskOpenError::Failed(error)) => format!("{error:#}"),
        other => panic!("expected an ordinary reopen failure, got {other:?}"),
    }
}

#[test]
fn fenced_owner_is_refused_while_holders_live_then_reopens_exactly_once_drained() {
    let (_directory, config, memory, disk) = fixture();
    let accepted = accounting(&disk);
    let directory = disk.open_directory("data", Path::new("nested")).unwrap();
    let file = fence(&disk, "one");
    let fenced = disk.snapshot();
    let census = generation(&disk);
    let admitted = memory.snapshot();
    assert_eq!(accounting(&disk), accepted, "a fence releases no charge");
    for result in [
        open(&config, &memory),
        reopen(&config, &memory, &CensusCancellation::default()),
    ] {
        let Err(DiskOpenError::OwnerFenced {
            phase,
            open_files,
            open_directories,
            cursors,
            census_streams,
            namespace_witnesses,
            retained_attempts,
        }) = result
        else {
            panic!("a fenced owner with live holders was shared or reopened");
        };
        assert_eq!(
            (
                phase,
                open_files,
                open_directories,
                cursors,
                census_streams,
                namespace_witnesses,
                retained_attempts,
            ),
            (
                NodeDiskPhase::Failed,
                fenced.open_files,
                1,
                0,
                0,
                0,
                fenced.retained_file_attempts,
            )
        );
        assert!(open_files >= 1);
    }
    // Refusal runs no census, moves no charge and acquires no admission.
    assert_eq!(generation(&disk), census);
    assert_eq!(accounting(&disk), accepted);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(memory.snapshot(), admitted);

    drop(directory);
    let Err(DiskOpenError::OwnerFenced {
        open_directories: 0,
        ..
    }) = reopen(&config, &memory, &CensusCancellation::default())
    else {
        panic!("the live file holder alone must keep the owner fenced");
    };
    assert_eq!(generation(&disk), census);

    drop(file);
    let reopened = reopen(&config, &memory, &CensusCancellation::default()).unwrap();
    assert!(Arc::ptr_eq(&reopened, &disk), "the exact owner is reopened");
    assert_eq!(generation(&disk), census + 1);
    let snapshot = reopened.snapshot();
    assert_eq!(snapshot.phase, NodeDiskPhase::Open);
    assert!(snapshot.filesystem_admission_ready);
    assert_eq!(snapshot.open_files, 0);
    assert_eq!(snapshot.retained_file_attempts, 0);
    assert_eq!(accounting(&reopened), accepted);
    assert_eq!(
        memory.snapshot(),
        admitted,
        "reopen acquires no second owner, registry or device charge"
    );
    assert_eq!(contents(&reopened, "one", 48 << 10), vec![0x11; 48 << 10]);
    assert_eq!(contents(&reopened, "two", 20 << 10), vec![0x22; 20 << 10]);
    assert_eq!(
        contents(&reopened, "nested/three", 12 << 10),
        vec![0x33; 12 << 10]
    );

    // An Open owner is shared by both paths without another census, even
    // while a holder is live.
    let holder = reopened.open_file("data", Path::new("two")).unwrap();
    assert!(Arc::ptr_eq(&open(&config, &memory).unwrap(), &disk));
    assert!(Arc::ptr_eq(
        &reopen(&config, &memory, &CensusCancellation::default()).unwrap(),
        &disk
    ));
    assert_eq!(generation(&disk), census + 1);
    drop(holder);
    assert_eq!(memory.snapshot(), admitted);
}

#[test]
fn paused_owner_is_fenced_for_open_and_reopens_only_through_a_census() {
    let (_directory, config, memory, disk) = fixture();
    let accepted = accounting(&disk);
    let census = generation(&disk);
    disk.pause().unwrap();
    let Err(DiskOpenError::OwnerFenced {
        phase: NodeDiskPhase::Paused,
        open_files: 0,
        open_directories: 0,
        ..
    }) = open(&config, &memory)
    else {
        panic!("a paused owner was shared");
    };
    assert_eq!(generation(&disk), census);
    let reopened = reopen(&config, &memory, &CensusCancellation::default()).unwrap();
    assert!(Arc::ptr_eq(&reopened, &disk));
    assert_eq!(generation(&disk), census + 1);
    assert_eq!(reopened.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(accounting(&reopened), accepted);
}

#[test]
fn failed_or_cancelled_reopen_census_keeps_the_fence_and_charges_until_retry() {
    let (_directory, config, memory, disk) = fixture();
    let accepted = accounting(&disk);
    drop(fence(&disk, "one"));
    let census = generation(&disk);
    let fenced = disk.snapshot();
    let assert_still_fenced = || {
        let snapshot = disk.snapshot();
        assert_eq!(snapshot.phase, NodeDiskPhase::Failed);
        assert!(!snapshot.filesystem_admission_ready);
        assert_eq!(snapshot.open_files, fenced.open_files);
        assert_eq!(accounting(&disk), accepted, "prior charges are retained");
        assert_eq!(generation(&disk), census, "no census was accepted");
        let Err(DiskOpenError::OwnerFenced { .. }) = open(&config, &memory) else {
            panic!("an unaccepted census reopened the owner");
        };
    };

    let cancelled = CensusCancellation::default();
    cancelled.cancel();
    assert!(failed(reopen(&config, &memory, &cancelled)).contains("cancelled"));
    assert_still_fenced();

    // Cancellation inside the census publishes nothing.
    let cancel = CensusCancellation::default();
    cancel.cancel_at.store(3, Ordering::Relaxed);
    assert!(failed(reopen(&config, &memory, &cancel)).contains("cancelled"));
    assert_still_fenced();

    // An observed entry the census cannot count fails the whole census.
    let raw = config.roots["data"].join("two");
    std::fs::set_permissions(&raw, std::fs::Permissions::from_mode(0o644)).unwrap();
    for _ in 0..2 {
        assert!(
            failed(reopen(&config, &memory, &CensusCancellation::default()))
                .contains("private and owned")
        );
        assert_still_fenced();
    }

    std::fs::set_permissions(&raw, std::fs::Permissions::from_mode(0o600)).unwrap();
    let reopened = reopen(&config, &memory, &CensusCancellation::default()).unwrap();
    assert!(Arc::ptr_eq(&reopened, &disk));
    assert_eq!(generation(&disk), census + 1);
    assert_eq!(reopened.snapshot().phase, NodeDiskPhase::Open);
    assert!(reopened.snapshot().filesystem_admission_ready);
    assert_eq!(accounting(&reopened), accepted);
    assert_eq!(contents(&reopened, "two", 20 << 10), vec![0x22; 20 << 10]);
}

#[test]
fn concurrent_open_during_the_reopen_census_is_busy_and_never_half_counted() {
    let (_directory, config, memory, disk) = fixture();
    let accepted = accounting(&disk);
    drop(fence(&disk, "one"));
    let census = generation(&disk);
    let cancel = CensusCancellation::default();
    let (entered, paused) = mpsc::channel();
    let (release, resumed) = mpsc::channel();
    *cancel.pause.lock().unwrap() = Some(CensusPause {
        entered,
        release: resumed,
    });
    // Checkpoint 1 precedes the registry; checkpoint 2 is inside the census.
    cancel.pause_at.store(2, Ordering::Relaxed);
    std::thread::scope(|scope| {
        let reopening = scope.spawn(|| reopen(&config, &memory, &cancel));
        paused.recv_timeout(Duration::from_secs(5)).unwrap();
        for _ in 0..2 {
            assert!(matches!(
                NodeDisk::open(&config, memory.clone(), &CensusCancellation::default()),
                Err(DiskOpenError::RegistryBusy)
            ));
            assert!(matches!(
                NodeDisk::reopen_fenced(&config, memory.clone(), &CensusCancellation::default()),
                Err(DiskOpenError::RegistryBusy)
            ));
        }
        // An existing Arc holder waits on the census's State guard and can
        // only observe the complete published result.
        let (observed, observation) = mpsc::channel();
        let observer = disk.clone();
        scope.spawn(move || observed.send(observer.snapshot()).unwrap());
        assert!(
            observation
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
        release.send(()).unwrap();
        let reopened = reopening.join().unwrap().unwrap();
        assert!(Arc::ptr_eq(&reopened, &disk));
        let observed = observation.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(observed.phase, NodeDiskPhase::Open);
        assert_eq!(
            [
                observed.charged_bytes,
                observed.pending_bytes,
                observed.persistent_files,
                observed.persistent_directories,
                observed.observed_directory_bytes,
                observed.filesystem_pending_bytes,
            ],
            accepted
        );
    });
    assert_eq!(generation(&disk), census + 1);
    assert!(Arc::ptr_eq(&open(&config, &memory).unwrap(), &disk));
}

#[test]
fn reopen_rejects_foreign_identity_absent_owners_and_shared_poison_before_census() {
    let (_directory, config, memory, disk) = fixture();
    let accepted = accounting(&disk);
    drop(fence(&disk, "one"));
    let census = generation(&disk);
    let mut budgets = config.clone();
    budgets.max_bytes -= disk.unit;
    assert!(failed(reopen(&budgets, &memory, &CensusCancellation::default())).contains("budgets"));
    let foreign = TestDiskMemory::new(256 << 20, 4096);
    assert!(
        failed(reopen(&config, &foreign, &CensusCancellation::default()))
            .contains("memory admission")
    );
    assert_eq!(foreign.snapshot().attempts, 0);
    let (_other, absent) = installation();
    assert!(
        failed(reopen(&absent, &memory, &CensusCancellation::default()))
            .contains("no installed persistent owner")
    );
    assert_eq!(generation(&disk), census);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);

    // Shared device poison is process-restart-only: no census may run or
    // reopen admission on top of an unprovable aggregate.
    disk.device.poison();
    for _ in 0..2 {
        assert!(
            failed(reopen(&config, &memory, &CensusCancellation::default()))
                .contains("process restart")
        );
    }
    assert_eq!(generation(&disk), census);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(accounting(&disk), accepted);
}

#[test]
fn reopen_never_retries_an_uncertain_native_close() {
    let (_directory, config, memory, disk) = fixture();
    let accepted = accounting(&disk);
    let prepared = disk
        .prepare_file("data", Path::new("absent"), Some(DiskWork::Foreground))
        .unwrap();
    let descriptor = prepared.parent_descriptor();
    native_file::fail_next_close(libc::EIO);
    let attempts = native_file::close_attempts();
    drop(prepared);
    assert_eq!(native_file::close_attempts(), attempts + 1);
    let census = generation(&disk);
    for _ in 0..2 {
        assert!(matches!(
            reopen(&config, &memory, &CensusCancellation::default()),
            Err(DiskOpenError::Failed(_))
        ));
        assert_eq!(
            native_file::close_attempts(),
            attempts + 1,
            "an uncertain descriptor integer is never closed again"
        );
        let snapshot = disk.snapshot();
        assert_eq!(snapshot.phase, NodeDiskPhase::Failed);
        assert_eq!(snapshot.uncertain_file_close, Some((descriptor, libc::EIO)));
        assert_eq!(snapshot.retained_file_attempts, 1);
        assert_eq!(accounting(&disk), accepted);
        assert_eq!(generation(&disk), census);
    }
}
