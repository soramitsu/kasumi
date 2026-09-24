use super::super::{CensusCancellation, NodeDiskConfig};
use super::*;
use crate::test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

fn fixture() -> (tempfile::TempDir, NodeDiskConfig, Arc<TestDiskMemory>) {
    let directory = private_tempdir().unwrap();
    let config = NodeDisk::fixture_config(directory.path().join("unused")).unwrap();
    (directory, config, TestDiskMemory::new(256 << 20, 4096))
}
fn open(config: &NodeDiskConfig, memory: &Arc<TestDiskMemory>) -> Arc<NodeDisk> {
    retry_disk_registry(|| {
        NodeDisk::open_fixture(config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap()
}
fn blocks(path: &Path) -> u64 {
    path.metadata().unwrap().blocks().checked_mul(512).unwrap()
}

#[test]
fn census_charges_directory_ceilings_and_records_actual_blocks_and_remaining_promises() {
    let (directory, config, memory) = fixture();
    let child = directory.path().join("child");
    crate::private_files::create_directory(&child).unwrap();
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(child.join("data"))
        .unwrap();
    file.set_len(8192).unwrap();
    file.sync_all().unwrap();
    let disk = open(&config, &memory);
    let directories = blocks(directory.path()) + blocks(&child);
    let (file_bytes, file_pending) =
        super::super::extent(&file.metadata().unwrap(), disk.unit).unwrap();
    let snapshot = disk.snapshot();
    assert_eq!(snapshot.persistent_directories, 2);
    assert_eq!(snapshot.observed_directory_bytes, directories);
    let directory_charge = config
        .directory_policy
        .extent_bytes
        .max(blocks(directory.path()))
        + config.directory_policy.extent_bytes.max(blocks(&child));
    assert_eq!(snapshot.charged_bytes, directory_charge + file_bytes);
    assert_eq!(
        snapshot.pending_bytes,
        directory_charge - directories + file_pending
    );
    assert_eq!(snapshot.persistent_files, 1);
    let state = disk.lock_state();
    let root = state.accounted[&Identity::of(&directory.path().metadata().unwrap())]
        .directory()
        .unwrap();
    assert_eq!(root.children, 1);
    let child = state.accounted[&Identity::of(&child.metadata().unwrap())]
        .directory()
        .unwrap();
    assert_eq!(child.children, 1);
    assert_eq!(
        child.parent,
        Some(Identity::of(&directory.path().metadata().unwrap()))
    );
}

#[test]
fn directory_quota_denies_before_allocation_and_preserves_file_quota() {
    let (directory, mut config, memory) = fixture();
    config.max_open_directories = 1;
    let original_file_limit = config.max_open_files;
    let disk = open(&config, &memory);
    let handle = disk.open_directory("fixture", Path::new("")).unwrap();
    let clone = handle.clone();
    assert_eq!(disk.snapshot().open_directories, 1);
    let (result, allocations) =
        crate::allocation_tests::measure(|| disk.open_directory("fixture", Path::new("")));
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::StorageFull);
    assert_eq!(allocations, 0);
    assert_eq!(disk.config.max_open_files, original_file_limit);
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(
        disk.snapshot().observed_directory_bytes,
        blocks(directory.path())
    );
    drop(handle);
    assert_eq!(disk.snapshot().open_directories, 1);
    drop(clone);
    assert_eq!(disk.snapshot().open_directories, 0);
}

#[test]
fn admitted_directory_sync_read_and_last_drop_do_not_allocate_or_credit_extent() {
    let (_directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let handle = disk.open_directory("fixture", Path::new("")).unwrap();
    let before = disk.snapshot();
    assert!(disk.pause().is_err());
    let (result, allocations) = crate::allocation_tests::measure(|| -> io::Result<()> {
        assert_eq!(
            handle.observed_allocated_bytes()?,
            before.observed_directory_bytes
        );
        handle.sync_all()?;
        drop(handle);
        Ok(())
    });
    result.unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().open_directories, 0);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    disk.reconcile(&CensusCancellation::default()).unwrap();
}

#[test]
fn operational_drain_is_not_published_until_after_actual_directory_close() {
    let (_directory, mut config, memory) = fixture();
    config.max_open_directories = 1;
    let disk = open(&config, &memory);
    let handle = disk.open_directory("fixture", Path::new("")).unwrap();
    let (entered_tx, entered) = std::sync::mpsc::sync_channel(0);
    let (release, release_rx) = std::sync::mpsc::sync_channel(0);
    *handle.owner().after_close.as_ref().unwrap().lock().unwrap() = Some(ClosePause {
        entered: entered_tx,
        release: release_rx,
    });
    let dropping = std::thread::spawn(move || drop(handle));
    // This checkpoint is executed only after drop(actual File), before counters.
    entered
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert_eq!(disk.snapshot().open_directories, 1);
    assert_eq!(
        disk.open_directory("fixture", Path::new(""))
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    assert!(disk.pause().is_err());
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    release.send(()).unwrap();
    dropping.join().unwrap();
    assert_eq!(disk.snapshot().open_directories, 0);
    disk.reconcile(&CensusCancellation::default()).unwrap();
}

#[test]
fn unknown_final_directory_absence_is_healthy_but_known_disappearance_fences() {
    let (directory, config, memory) = fixture();
    let child = directory.path().join("child");
    crate::private_files::create_directory(&child).unwrap();
    let disk = open(&config, &memory);
    assert_eq!(
        disk.open_directory("fixture", Path::new("missing"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    let handle = disk.open_directory("fixture", Path::new("child")).unwrap();
    let before = disk.snapshot().charged_bytes;
    std::fs::remove_dir(&child).unwrap();
    let (result, allocations) = crate::allocation_tests::measure(|| handle.sync_all());
    assert!(result.is_err());
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().charged_bytes, before);
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    drop(handle);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().persistent_directories, 1);
}

#[test]
fn unchanged_final_directory_inode_does_not_hide_replaced_intermediate_ancestor() {
    let (directory, config, memory) = fixture();
    for relative in ["a", "a/b", "c"] {
        crate::private_files::create_directory(&directory.path().join(relative)).unwrap();
    }
    let disk = open(&config, &memory);
    let handle = disk.open_directory("fixture", Path::new("a/b")).unwrap();
    let retained = handle.owner().identity;
    let root_before = directory.path().metadata().unwrap();
    let outside = private_tempdir().unwrap();
    std::fs::rename(directory.path().join("a"), outside.path().join("swap")).unwrap();
    std::fs::rename(directory.path().join("c"), directory.path().join("a")).unwrap();
    std::fs::rename(outside.path().join("swap"), directory.path().join("c")).unwrap();
    std::fs::rename(directory.path().join("c/b"), directory.path().join("a/b")).unwrap();
    let root_after = directory.path().metadata().unwrap();
    assert_eq!(
        (root_before.len(), root_before.blocks()),
        (root_after.len(), root_after.blocks()),
        "counterexample must preserve root extent"
    );
    assert_eq!(
        retained,
        Identity::of(&directory.path().join("a/b").metadata().unwrap())
    );
    assert!(handle.sync_all().is_err());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert!(disk.open_directory("fixture", Path::new("a/b")).is_err());
}

#[test]
fn failed_directory_census_replacement_retains_previous_entries_and_charge() {
    let (directory, config, memory) = fixture();
    crate::private_files::create_directory(&directory.path().join("child")).unwrap();
    let disk = open(&config, &memory);
    let before = disk.snapshot();
    let original = disk
        .lock_state()
        .accounted
        .iter()
        .map(|(key, entry)| (*key, *entry))
        .collect::<std::collections::BTreeMap<_, _>>();
    let cancel = CensusCancellation::default();
    cancel.cancel();
    assert!(disk.reconcile(&cancel).is_err());
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(
        disk.lock_state()
            .accounted
            .iter()
            .map(|(key, entry)| (*key, *entry))
            .collect::<std::collections::BTreeMap<_, _>>(),
        original
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(
        disk.lock_state()
            .accounted
            .iter()
            .map(|(key, entry)| (*key, *entry))
            .collect::<std::collections::BTreeMap<_, _>>(),
        original
    );
}

#[test]
fn required_directory_limit_is_not_deserialized_from_a_fallback() {
    let (_directory, config, _memory) = fixture();
    let mut value = serde_json::to_value(config).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("max_open_directories");
    assert!(serde_json::from_value::<NodeDiskConfig>(value).is_err());
}

#[test]
fn metadata_denial_precedes_directory_path_access_and_retains_no_partial_owner() {
    let (directory, mut config, _memory) = fixture();
    config
        .roots
        .insert("fixture".into(), directory.path().join("not-created"));
    let memory = TestDiskMemory::new(
        TestDiskMemory::required_bookkeeping_bytes(1).unwrap() + 1,
        1,
    );
    let error = retry_disk_registry(|| {
        NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap_err();
    let crate::DiskOpenError::Failed(error) = error else {
        panic!("fixture registry retry exhausted");
    };
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(memory.snapshot().attempts, 1);
    assert_eq!(memory.snapshot().used_bytes, 0);
    assert_eq!(memory.snapshot().live_reservations, 0);
    assert!(!config.roots["fixture"].exists());
}

#[test]
fn failed_shared_device_rejects_directory_sync_without_releasing_custody_or_bytes() {
    let (_directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let handle = disk.open_directory("fixture", Path::new("")).unwrap();
    let before = disk.snapshot();
    disk.device.lock().fail_owner();
    assert!(handle.sync_all().is_err());
    assert!(handle.observed_allocated_bytes().is_err());
    assert!(disk.open_directory("fixture", Path::new("")).is_err());
    assert_eq!(disk.snapshot().open_directories, 1);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    drop(handle);
    assert_eq!(disk.snapshot().open_directories, 0);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
}

#[test]
fn file_capacity_remains_independent_of_directory_membership() {
    let (directory, mut config, memory) = fixture();
    config.max_persistent_files = 8;
    config.max_persistent_subdirectories = 8;
    config.census_work_per_step = 8;
    crate::private_files::create_directory(&directory.path().join("child")).unwrap();
    let disk = open(&config, &memory);
    // Both directories remain enrolled as each of the original eight file
    // slots is filled. Capping the union at N (+ roots) denies too early.
    for index in 0..8 {
        let relative = std::path::PathBuf::from(format!("file-{index}"));
        let file = disk
            .create_file("fixture", &relative, super::super::DiskWork::Foreground)
            .unwrap();
        file.sync_all().unwrap();
        drop(file);
    }
    let state = disk.lock_state();
    assert_eq!(state.files, 8);
    assert_eq!(state.directories, 2);
    assert_eq!(state.accounted.len(), 10);
    drop(state);
    assert_eq!(
        disk.create_file(
            "fixture",
            std::path::Path::new("overflow"),
            super::super::DiskWork::Foreground
        )
        .unwrap_err()
        .kind(),
        std::io::ErrorKind::StorageFull
    );
    assert!(!directory.path().join("overflow").exists());
    // The same admitted namespace now completes over retained bounded steps.
    let old = disk
        .lock_state()
        .accounted
        .iter()
        .map(|(key, entry)| (*key, *entry))
        .collect::<std::collections::BTreeMap<_, _>>();
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(
        disk.lock_state()
            .accounted
            .iter()
            .map(|(key, entry)| (*key, *entry))
            .collect::<std::collections::BTreeMap<_, _>>(),
        old
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
}
