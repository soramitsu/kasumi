use super::*;
use std::{
    os::unix::fs::{OpenOptionsExt, symlink},
    path::Path,
};

fn installation() -> (tempfile::TempDir, NodeDiskConfig) {
    let directory = crate::test_utils::private_tempdir().unwrap();
    let root = directory.path().join("owned");
    crate::private_files::create_directory(&root).unwrap();
    let config = NodeDiskConfig {
        roots: BTreeMap::from([("data".into(), root)]),
        max_bytes: 16 << 20,
        maintenance_reserve_bytes: 1 << 20,
        min_free_bytes: 0,
        max_open_files: 16,
        max_open_directories: 16,
        max_census_entries: 10_000,
        max_depth: 32,
        max_name_bytes: 255,
    };
    (directory, config)
}

fn open(config: NodeDiskConfig, memory: Arc<dyn NodeDiskMemoryAdmission>) -> Arc<NodeDisk> {
    crate::test_utils::retry_disk_registry(|| {
        NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap()
}

#[test]
fn retained_file_io_settlement_shrink_and_drop_do_not_allocate() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let mut relative = std::path::PathBuf::new();
    for name in ["a".repeat(200), "b".repeat(200), "c".repeat(200)] {
        relative.push(name);
        crate::private_files::create_directory(&config.roots["data"].join(&relative)).unwrap();
    }
    relative.push("file");
    let disk = open(config, fixture_memory.clone());
    let mut file = disk
        .create_file("data", &relative, DiskWork::Foreground)
        .unwrap();
    file.reserve_growth(0, 64 << 10, DiskWork::Foreground)
        .unwrap();
    file.grow_reserved(32 << 10).unwrap();
    let (result, allocations) = crate::allocation_tests::measure(|| -> io::Result<()> {
        file.check_owner()?;
        file.write_all_at(&[31; 64], 0)?;
        file.sync_all()?;
        file.settle_growth(32 << 10)?;
        assert_eq!(file.observed_len()?, 32 << 10);
        let mut bytes = [0; 64];
        file.read_exact_at(&mut bytes, 0)?;
        assert_eq!(bytes, [31; 64]);
        file.shrink(16 << 10)?;
        file.sync_all_and_parent()?;
        Ok(())
    });
    result.unwrap();
    assert_eq!(
        allocations, 0,
        "admitted physical I/O allocated after preparation"
    );
    assert_eq!(disk.snapshot().charged_bytes, 16 << 10);
    let ((), allocations) = crate::allocation_tests::measure(|| drop(file));
    assert_eq!(allocations, 0, "descriptor retirement allocated");
    let file = disk.open_file("data", &relative).unwrap();
    disk.delete_file(file).unwrap();
    disk.pause().unwrap();
}

#[test]
fn identity_failure_and_uncertain_file_drop_fence_without_allocating() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config.clone(), fixture_memory.clone());
    let file = disk
        .create_file("data", Path::new("file"), DiskWork::Foreground)
        .unwrap();
    file.reserve_growth(0, 32 << 10, DiskWork::Foreground)
        .unwrap();
    file.grow_reserved(32 << 10).unwrap();
    file.sync_all().unwrap();
    std::fs::rename(
        config.roots["data"].join("file"),
        config.roots["data"].join("moved"),
    )
    .unwrap();
    seed(&config, "file", 16 << 10);
    let (result, allocations) = crate::allocation_tests::measure(|| file.sync_all());
    assert!(result.is_err());
    assert_eq!(
        allocations, 0,
        "identity failure allocated an error payload"
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    let ((), allocations) = crate::allocation_tests::measure(|| {
        file.owner_failed();
        drop(file);
    });
    assert_eq!(allocations, 0);
    clean(&disk, &["file", "moved"]);
}

#[test]
fn explicit_settlement_returns_only_unused_promises_and_requires_exact_extent() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config, fixture_memory.clone());
    let file = disk
        .create_file("data", Path::new("file"), DiskWork::Foreground)
        .unwrap();
    file.reserve_growth(0, 128 << 10, DiskWork::Foreground)
        .unwrap();
    file.grow_reserved(32 << 10).unwrap();
    file.settle_growth(32 << 10).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 32 << 10);
    assert!(file.grow_reserved(64 << 10).is_err());
    let (result, allocations) = crate::allocation_tests::measure(|| file.settle_growth(0));
    assert!(result.is_err());
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().charged_bytes, 32 << 10);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    drop(file);
    clean(&disk, &["file"]);
}

fn seed(config: &NodeDiskConfig, name: &str, len: u64) {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(config.roots["data"].join(name))
        .unwrap();
    file.set_len(len).unwrap();
    file.sync_all().unwrap();
}

fn clean(disk: &Arc<NodeDisk>, names: &[&str]) {
    assert_eq!(disk.snapshot().open_files, 0);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    for name in names {
        let file = disk.open_file("data", Path::new(name)).unwrap();
        disk.delete_file(file).unwrap();
    }
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().pending_bytes, 0);
    disk.pause().unwrap();
}

#[test]
fn census_counts_closed_files_and_repeated_cursors_start_at_the_beginning() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    seed(&config, "one", 64 << 10);
    seed(&config, "two", 32 << 10);
    let disk = open(config.clone(), fixture_memory.clone());
    let before = disk.snapshot();
    assert_eq!(before.charged_bytes, 96 << 10);
    assert_eq!(before.persistent_files, 2);
    for _ in 0..3 {
        disk.pause().unwrap();
        disk.reconcile(&CensusCancellation::default()).unwrap();
        let after = disk.snapshot();
        assert_eq!(
            (
                after.charged_bytes,
                after.pending_bytes,
                after.persistent_files
            ),
            (
                before.charged_bytes,
                before.pending_bytes,
                before.persistent_files
            )
        );
    }
    let pointer = Arc::as_ptr(&disk);
    drop(disk);
    let reopened = crate::test_utils::retry_disk_registry(|| {
        NodeDisk::open(
            &config,
            fixture_memory.clone(),
            &CensusCancellation::default(),
        )
    })
    .unwrap();
    assert_eq!(Arc::as_ptr(&reopened), pointer);
    assert_eq!(reopened.snapshot().charged_bytes, before.charged_bytes);
    clean(&reopened, &["one", "two"]);
}

#[test]
fn dropped_unmaterialized_growth_is_retained_until_exclusive_reconciliation() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config.clone(), fixture_memory.clone());
    let file = disk
        .create_file("data", Path::new("pending"), DiskWork::Foreground)
        .unwrap();
    file.reserve_growth(0, 64 << 10, DiskWork::Foreground)
        .unwrap();
    let charged = disk.snapshot();
    assert_eq!(charged.charged_bytes, 64 << 10);
    drop(file);
    let stopped = disk.snapshot();
    assert_eq!(stopped.phase, NodeDiskPhase::Failed);
    assert!(!stopped.filesystem_admission_ready);
    assert_eq!(stopped.charged_bytes, charged.charged_bytes);
    assert_eq!(stopped.pending_bytes, charged.pending_bytes);
    let same = crate::test_utils::retry_disk_registry(|| {
        NodeDisk::open(
            &config,
            fixture_memory.clone(),
            &CensusCancellation::default(),
        )
    })
    .unwrap();
    assert!(Arc::ptr_eq(&same, &disk));
    assert_eq!(same.snapshot().charged_bytes, charged.charged_bytes);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert!(disk.snapshot().filesystem_admission_ready);
    clean(&disk, &["pending"]);
}

#[test]
fn pause_seals_new_reservations_but_drains_reserved_io_and_retains_sparse_promises() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config, fixture_memory.clone());
    let file = disk
        .create_file("data", Path::new("sparse"), DiskWork::Foreground)
        .unwrap();
    file.reserve_growth(0, 128 << 10, DiskWork::Foreground)
        .unwrap();
    assert!(disk.pause().is_err());
    assert!(
        file.reserve_growth(0, 256 << 10, DiskWork::Foreground)
            .is_err()
    );
    file.grow_reserved(128 << 10).unwrap();
    file.write_all_at(b"owned ciphertext", 0).unwrap();
    file.sync_all().unwrap();
    let before = disk.snapshot();
    drop(file);
    disk.pause().unwrap();
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    clean(&disk, &["sparse"]);
}

#[test]
fn maintenance_has_reserved_capacity_and_denial_changes_no_extent_or_charge() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, mut config) = installation();
    let root = File::open(&config.roots["data"]).unwrap();
    let (_, unit) = filesystem(&root).unwrap();
    config.max_bytes = 3 * unit;
    config.maintenance_reserve_bytes = unit;
    let disk = open(config.clone(), fixture_memory.clone());
    let file = disk
        .create_file("data", Path::new("data"), DiskWork::Foreground)
        .unwrap();
    file.reserve_growth(0, 2 * unit, DiskWork::Foreground)
        .unwrap();
    let before = disk.snapshot();
    assert_eq!(
        file.reserve_growth(0, 3 * unit, DiskWork::Foreground)
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(
        std::fs::metadata(config.roots["data"].join("data"))
            .unwrap()
            .len(),
        0
    );
    file.reserve_growth(0, 3 * unit, DiskWork::Maintenance)
        .unwrap();
    file.grow_reserved(3 * unit).unwrap();
    file.sync_all().unwrap();
    drop(file);
    clean(&disk, &["data"]);
}

#[test]
fn physical_reclaim_requires_sole_owner_and_releases_only_verified_extent() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    seed(&config, "data", 128 << 10);
    let disk = open(config.clone(), fixture_memory.clone());
    let file = disk.open_file("data", Path::new("data")).unwrap();
    let reader = file.clone();
    assert!(disk.delete_file(file).is_err());
    assert_eq!(disk.snapshot().charged_bytes, 128 << 10);
    assert!(config.roots["data"].join("data").exists());
    disk.shrink_file(reader, 32 << 10).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 32 << 10);
    let file = disk.open_file("data", Path::new("data")).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 32 << 10);
    disk.delete_file(file).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert!(!config.roots["data"].join("data").exists());
    disk.pause().unwrap();
}

#[test]
fn substitution_closes_shared_admission_and_does_not_delete_the_replacement() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    seed(&config, "data", 64 << 10);
    let disk = open(config.clone(), fixture_memory.clone());
    let sibling = disk.device.share(0);
    let file = disk.open_file("data", Path::new("data")).unwrap();
    let root = config.roots["data"].clone();
    std::fs::rename(root.join("data"), root.join("held")).unwrap();
    seed(&config, "data", 7);
    assert!(disk.delete_file(file).is_err());
    assert_eq!(std::fs::metadata(root.join("data")).unwrap().len(), 7);
    assert_eq!(disk.snapshot().charged_bytes, 64 << 10);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert!(!sibling.lock().admission_ready());
    // Repair the fixture's external substitution before its exclusive census.
    std::fs::remove_file(root.join("data")).unwrap();
    std::fs::rename(root.join("held"), root.join("data")).unwrap();
    clean(&disk, &["data"]);
    assert!(sibling.lock().admission_ready());
}

#[test]
fn cancelled_or_work_exhausted_census_publishes_no_partial_owner() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    for name in ["one", "two", "three"] {
        seed(&config, name, 32 << 10);
    }
    let cancel = CensusCancellation::default();
    cancel.cancel_at.store(5, Ordering::Relaxed);
    assert!(
        crate::test_utils::retry_disk_registry(|| NodeDisk::open_fixture(
            &config,
            fixture_memory.clone(),
            &cancel
        ))
        .is_err()
    );
    let mut bounded = config.clone();
    bounded.max_census_entries = 2;
    assert!(
        crate::test_utils::retry_disk_registry(|| NodeDisk::open_fixture(
            &bounded,
            fixture_memory.clone(),
            &CensusCancellation::default()
        ))
        .is_err()
    );
    let disk = open(config, fixture_memory.clone());
    assert_eq!(disk.snapshot().charged_bytes, 96 << 10);
    assert_eq!(disk.snapshot().persistent_files, 3);
    clean(&disk, &["one", "two", "three"]);
}

#[test]
fn symlinks_hardlinks_and_overlapping_roots_cannot_duplicate_census_charge() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    seed(&config, "one", 32 << 10);
    let root = config.roots["data"].clone();
    std::fs::hard_link(root.join("one"), root.join("two")).unwrap();
    assert!(
        crate::test_utils::retry_disk_registry(|| NodeDisk::open(
            &config,
            fixture_memory.clone(),
            &CensusCancellation::default()
        ))
        .is_err()
    );
    std::fs::remove_file(root.join("two")).unwrap();
    symlink("one", root.join("two")).unwrap();
    assert!(
        crate::test_utils::retry_disk_registry(|| NodeDisk::open(
            &config,
            fixture_memory.clone(),
            &CensusCancellation::default()
        ))
        .is_err()
    );
    std::fs::remove_file(root.join("two")).unwrap();
    let nested = root.join("child");
    crate::private_files::create_directory(&nested).unwrap();
    let disk = open(config.clone(), fixture_memory.clone());
    let mut child = config.clone();
    child.roots = BTreeMap::from([("nested".into(), nested)]);
    assert!(
        crate::test_utils::retry_disk_registry(|| NodeDisk::open(
            &child,
            fixture_memory.clone(),
            &CensusCancellation::default()
        ))
        .is_err()
    );
    let mut alias = config;
    alias.roots.insert("alias".into(), root.clone());
    assert!(
        crate::test_utils::retry_disk_registry(|| NodeDisk::open(
            &alias,
            fixture_memory.clone(),
            &CensusCancellation::default()
        ))
        .is_err()
    );
    clean(&disk, &["one"]);
}

#[test]
fn open_file_metadata_budget_is_bounded_and_close_returns_only_metadata_capacity() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, mut config) = installation();
    seed(&config, "one", 32 << 10);
    seed(&config, "two", 32 << 10);
    config.max_open_files = 1;
    let disk = open(config, fixture_memory.clone());
    let one = disk.open_file("data", Path::new("one")).unwrap();
    assert!(disk.open_file("data", Path::new("two")).is_err());
    drop(one);
    assert_eq!(disk.snapshot().charged_bytes, 64 << 10);
    let two = disk.open_file("data", Path::new("two")).unwrap();
    drop(two);
    clean(&disk, &["one", "two"]);
}

#[test]
fn persistent_and_scratch_cannot_spend_the_same_filesystem_promise() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (directory, config) = installation();
    let disk = open(config, fixture_memory.clone());
    let available = 3 * disk.unit;
    *disk.available_override.lock().unwrap() = Some(available);
    let scratch = crate::ScratchDisk::test_with_device(
        directory.path().join("scratch"),
        disk.device.share(0),
        available,
    );
    let file = disk
        .create_file("data", Path::new("pending"), DiskWork::Foreground)
        .unwrap();
    file.reserve_growth(0, 2 * disk.unit, DiskWork::Foreground)
        .unwrap();
    let (scratch_file, mut charge) = scratch.file().unwrap();
    assert_eq!(
        charge.grow(2 * disk.unit).unwrap_err().kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(scratch.snapshot().charged_bytes, 0);
    assert_eq!(scratch.snapshot().filesystem_pending_bytes, 2 * disk.unit);
    drop(file);
    assert!(
        charge.grow(disk.unit).is_err(),
        "unknown pending owner must fence its peers"
    );
    disk.reconcile(&CensusCancellation::default()).unwrap();
    charge.grow(2 * disk.unit).unwrap();
    drop(scratch_file);
    drop(charge);
    clean(&disk, &["pending"]);
}

#[test]
fn poisoned_shared_promises_cannot_be_reopened_by_either_owner() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (directory, config) = installation();
    let path = config.roots["data"].join("file");
    let disk = open(config, fixture_memory.clone());
    let scratch = crate::ScratchDisk::test_with_device(
        directory.path().join("scratch"),
        disk.device.share(0),
        16 << 20,
    );
    let file = disk
        .create_file("data", Path::new("file"), DiskWork::Foreground)
        .unwrap();
    file.reserve_growth(0, disk.unit, DiskWork::Foreground)
        .unwrap();
    file.grow_reserved(disk.unit).unwrap();
    file.sync_all().unwrap();
    let before = disk.snapshot();
    let (scratch_file, mut charge) = scratch.file().unwrap();
    disk.device.poison();
    assert!(
        file.reserve_growth(disk.unit, 2 * disk.unit, DiskWork::Foreground)
            .is_err()
    );
    assert!(charge.grow(disk.unit).is_err());
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(scratch.snapshot().charged_bytes, 0);
    assert!(!scratch.snapshot().filesystem_admission_ready);
    assert!(disk.delete_file(file).is_err());
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(disk.snapshot().persistent_files, 1);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    let raw = std::fs::File::open(&path).unwrap();
    raw.try_lock().unwrap();
    assert_eq!(raw.metadata().unwrap().len(), disk.unit);
    drop(raw);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert!(
        !disk.snapshot().filesystem_admission_ready,
        "owner census cannot cure shared poison"
    );
    assert!(charge.grow(disk.unit).is_err());
    drop(scratch_file);
    drop(charge);
    assert_eq!(scratch.snapshot().live_files, 0);
    assert_eq!(scratch.snapshot().charged_bytes, 0);
    assert!(scratch.file().is_err());
    assert!(
        disk.create_file("data", Path::new("blocked"), DiskWork::Foreground)
            .is_err()
    );
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(disk.snapshot().persistent_files, 1);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert!(!disk.snapshot().filesystem_admission_ready);
    // Shared poison requires process restart. Fixture teardown removes its
    // private tree; managed cleanup must not reopen this owner to erase charges.
}

#[test]
fn a_retiring_predecessor_keeps_exclusive_registration_until_all_resources_close() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    seed(&config, "file", 32 << 10);
    let disk = open(config, fixture_memory.clone());
    let old = disk.open_file("data", Path::new("file")).unwrap();
    let (entered, observation) = std::sync::mpsc::channel();
    let (release, resumed) = std::sync::mpsc::channel();
    *disk.after_file_close.lock().unwrap() = Some(file::ClosePause {
        stage: file::CloseStage::DataClosed,
        entered,
        release: resumed,
    });
    let closing = std::thread::spawn(move || drop(old));
    observation
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert_eq!(
        disk.open_file("data", Path::new("file"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(disk.snapshot().open_files, 1);
    release.send(()).unwrap();
    closing.join().unwrap();
    let current = disk.open_file("data", Path::new("file")).unwrap();
    assert!(disk.open_file("data", Path::new("file")).is_err());
    // A missing/newly unregistered entry would instead reach flock, fail, and
    // poison admission. The new owner must still have its exclusive slot.
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    let same = current.clone();
    assert_eq!(disk.snapshot().open_files, 1);
    assert_eq!(disk.snapshot().charged_bytes, 32 << 10);
    drop(same);
    drop(current);
    clean(&disk, &["file"]);
}

#[test]
fn unknown_filesystem_observation_fences_scratch_until_a_drained_census() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (directory, config) = installation();
    let disk = open(config, fixture_memory.clone());
    let scratch = crate::ScratchDisk::test_with_device(
        directory.path().join("scratch"),
        disk.device.share(0),
        16 << 20,
    );
    let file = disk
        .create_file("data", Path::new("file"), DiskWork::Foreground)
        .unwrap();
    let (scratch_file, mut charge) = scratch.file().unwrap();
    disk.available_error.store(true, Ordering::Relaxed);
    assert!(
        file.reserve_growth(0, disk.unit, DiskWork::Foreground)
            .is_err()
    );
    assert_eq!(file.observed_len().unwrap(), 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert!(charge.grow(disk.unit).is_err());
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    assert!(!scratch.snapshot().filesystem_admission_ready);
    drop(file);
    disk.available_error.store(false, Ordering::Relaxed);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    charge.grow(disk.unit).unwrap();
    drop(scratch_file);
    drop(charge);
    clean(&disk, &["file"]);
}

#[test]
fn duplicate_live_inode_open_requires_explicit_owner_clone() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    seed(&config, "data", 64 << 10);
    let disk = open(config, fixture_memory.clone());
    let file = disk.open_file("data", Path::new("data")).unwrap();
    let before = disk.snapshot();
    assert!(disk.open_file("data", Path::new("data")).is_err());
    let shared = file.clone();
    drop(file);
    assert!(disk.open_file("data", Path::new("data")).is_err());
    assert_eq!(disk.snapshot().open_files, 1);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert!(disk.snapshot().filesystem_admission_ready);
    drop(shared);
    let reopened = disk.open_file("data", Path::new("data")).unwrap();
    assert_eq!(disk.snapshot().open_files, 1);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    drop(reopened);
    clean(&disk, &["data"]);
}

#[test]
fn live_shrink_requires_the_only_mutable_file_owner() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    seed(&config, "data", 128 << 10);
    let disk = open(config, fixture_memory.clone());
    let mut file = disk.open_file("data", Path::new("data")).unwrap();
    file.write_all_at(b"retained encrypted payload", 0).unwrap();
    file.sync_all().unwrap();
    let reader = file.clone();
    let before = disk.snapshot();
    assert!(file.shrink(32 << 10).is_err());
    assert_eq!(file.observed_len().unwrap(), 128 << 10);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    let mut payload = [0; 26];
    reader.read_exact_at(&mut payload, 0).unwrap();
    assert_eq!(&payload, b"retained encrypted payload");
    drop(reader);
    assert!(file.shrink(256 << 10).is_err());
    assert_eq!(file.observed_len().unwrap(), 128 << 10);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    file.shrink(32 << 10).unwrap();
    assert_eq!(file.observed_len().unwrap(), 32 << 10);
    file.read_exact_at(&mut payload, 0).unwrap();
    assert_eq!(&payload, b"retained encrypted payload");
    drop(file);
    clean(&disk, &["data"]);
}

#[test]
fn live_shrink_cannot_release_unmaterialized_or_unsynced_growth() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    seed(&config, "data", 64 << 10);
    let disk = open(config, fixture_memory.clone());
    let mut file = disk.open_file("data", Path::new("data")).unwrap();
    file.reserve_growth(64 << 10, 128 << 10, DiskWork::Foreground)
        .unwrap();
    let before = disk.snapshot();
    assert!(file.shrink(32 << 10).is_err());
    assert_eq!(file.observed_len().unwrap(), 64 << 10);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    // Syncing a short file does not materialize the accepted reservation.
    file.sync_all().unwrap();
    assert!(file.shrink(32 << 10).is_err());
    file.grow_reserved(128 << 10).unwrap();
    assert!(file.shrink(32 << 10).is_err());
    assert_eq!(file.observed_len().unwrap(), 128 << 10);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    file.sync_all().unwrap();
    file.shrink(32 << 10).unwrap();
    assert_eq!(file.observed_len().unwrap(), 32 << 10);
    assert_eq!(disk.snapshot().charged_bytes, 32 << 10);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    drop(file);
    clean(&disk, &["data"]);
}

#[test]
fn live_shrink_retains_identity_and_lock_with_exact_reopen_accounting() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let path = config.roots["data"].join("data");
    seed(&config, "data", 128 << 10);
    seed(&config, "bystander", 32 << 10);
    let identity = crate::private_files::file_identity(&path).unwrap();
    let disk = open(config.clone(), fixture_memory.clone());
    let mut file = disk.open_file("data", Path::new("data")).unwrap();
    file.write_all_at(b"retained encrypted payload", 0).unwrap();
    file.sync_all().unwrap();
    let contender = File::open(&path).unwrap();
    assert!(contender.try_lock().is_err());
    file.shrink(32 << 10).unwrap();
    assert!(contender.try_lock().is_err());
    assert_eq!(
        crate::private_files::file_identity(&path).unwrap(),
        identity
    );
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 32 << 10);
    assert_eq!(disk.snapshot().charged_bytes, 64 << 10);
    assert_eq!(disk.snapshot().open_files, 1);
    assert_eq!(disk.snapshot().persistent_files, 2);
    assert!(disk.open_file("data", Path::new("data")).is_err());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    let shrunk = disk.snapshot();
    drop(file);
    assert_eq!(disk.snapshot().charged_bytes, shrunk.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, shrunk.pending_bytes);
    let reopened = disk.open_file("data", Path::new("data")).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, shrunk.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, shrunk.pending_bytes);
    reopened
        .reserve_growth(32 << 10, 64 << 10, DiskWork::Foreground)
        .unwrap();
    reopened.grow_reserved(64 << 10).unwrap();
    reopened.sync_all().unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 96 << 10);
    let mut payload = [0; 26];
    reopened.read_exact_at(&mut payload, 0).unwrap();
    assert_eq!(&payload, b"retained encrypted payload");
    drop(reopened);
    drop(contender);
    clean(&disk, &["data", "bystander"]);
}

#[test]
fn live_shrink_failure_retains_charges_through_drop_and_fences_shared_device() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    for failure in [
        file::ShrinkFailure::Truncate,
        file::ShrinkFailure::FileSync,
        file::ShrinkFailure::DirectorySync,
    ] {
        let (directory, config) = installation();
        seed(&config, "data", 128 << 10);
        let disk = open(config, fixture_memory.clone());
        let scratch = crate::ScratchDisk::test_with_device(
            directory.path().join("scratch"),
            disk.device.share(0),
            16 << 20,
        );
        let (scratch_file, mut scratch_charge) = scratch.file().unwrap();
        let mut file = disk.open_file("data", Path::new("data")).unwrap();
        file.write_all_at(b"retained encrypted payload", 0).unwrap();
        file.sync_all().unwrap();
        let before = disk.snapshot();
        *disk.shrink_failure.lock().unwrap() = Some(failure);
        let (result, allocations) = crate::allocation_tests::measure(|| file.shrink(32 << 10));
        assert!(result.is_err());
        assert_eq!(allocations, 0, "uncertain shrink allocated: {failure:?}");
        assert_eq!(
            file.observed_len().unwrap(),
            if failure == file::ShrinkFailure::Truncate {
                128 << 10
            } else {
                32 << 10
            }
        );
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
        assert_eq!(
            disk.snapshot().filesystem_pending_bytes,
            before.filesystem_pending_bytes
        );
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
        assert!(!disk.snapshot().filesystem_admission_ready);
        assert!(scratch_charge.grow(4096).is_err());
        assert!(disk.reconcile(&CensusCancellation::default()).is_err());
        assert!(file.shrink(0).is_err());
        let ((), allocations) = crate::allocation_tests::measure(|| drop(file));
        assert_eq!(allocations, 0, "uncertain descriptor drop allocated");
        assert_eq!(disk.snapshot().open_files, 0);
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
        assert_eq!(
            disk.snapshot().filesystem_pending_bytes,
            before.filesystem_pending_bytes
        );
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
        assert!(!scratch.snapshot().filesystem_admission_ready);
        assert!(disk.open_file("data", Path::new("data")).is_err());
        disk.reconcile(&CensusCancellation::default()).unwrap();
        assert_eq!(
            disk.snapshot().charged_bytes,
            if failure == file::ShrinkFailure::Truncate {
                128 << 10
            } else {
                32 << 10
            }
        );
        assert!(scratch.snapshot().filesystem_admission_ready);
        scratch_charge.grow(4096).unwrap();
        drop(scratch_file);
        drop(scratch_charge);
        clean(&disk, &["data"]);
    }

    // Binding uncertainty cannot authorize truncating an unrelated replacement.
    let (_directory, config) = installation();
    seed(&config, "data", 128 << 10);
    let root = config.roots["data"].clone();
    let disk = open(config.clone(), fixture_memory.clone());
    let mut file = disk.open_file("data", Path::new("data")).unwrap();
    let before = disk.snapshot();
    std::fs::rename(root.join("data"), root.join("retained")).unwrap();
    seed(&config, "data", 4096);
    assert!(file.shrink(0).is_err());
    assert_eq!(std::fs::metadata(root.join("data")).unwrap().len(), 4096);
    assert_eq!(
        std::fs::metadata(root.join("retained")).unwrap().len(),
        128 << 10
    );
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    drop(file);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert!(!disk.snapshot().filesystem_admission_ready);
    std::fs::remove_file(root.join("data")).unwrap();
    std::fs::rename(root.join("retained"), root.join("data")).unwrap();
    clean(&disk, &["data"]);
}

#[test]
fn envelope_identity_and_durability_retain_custody_until_the_last_handle_closes() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let path = config.roots["data"].join("node");
    let disk = open(config, fixture_memory.clone());
    let file = disk
        .create_file("data", Path::new("node"), DiskWork::Foreground)
        .unwrap();
    let identity = file.identity().unwrap();
    assert_eq!(
        identity,
        crate::private_files::file_identity(&path).unwrap()
    );
    file.reserve_growth(0, 8192, DiskWork::Foreground).unwrap();
    file.grow_reserved(8192).unwrap();
    file.write_all_at(b"canonical envelope", 0).unwrap();
    file.sync_all_and_parent().unwrap();
    assert_eq!(file.identity().unwrap(), identity);
    assert_eq!(file.observed_len().unwrap(), 8192);
    let retained = file.clone();
    let before = disk.snapshot();
    let contender = File::open(&path).unwrap();
    assert!(contender.try_lock().is_err());
    assert!(disk.open_file("data", Path::new("node")).is_err());
    drop(file);
    assert_eq!(retained.identity().unwrap(), identity);
    assert!(contender.try_lock().is_err());
    assert_eq!(disk.snapshot().open_files, 1);
    drop(retained);
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    contender.try_lock().unwrap();
    drop(contender);
    let reopened = disk.open_file("data", Path::new("node")).unwrap();
    assert_eq!(reopened.identity().unwrap(), identity);
    let mut header = [0; 18];
    reopened.read_exact_at(&mut header, 0).unwrap();
    assert_eq!(&header, b"canonical envelope");
    drop(reopened);
    clean(&disk, &["node"]);
}

#[test]
fn envelope_inspection_and_publication_reject_inode_and_parent_substitution() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    for replace_parent in [false, true] {
        let (_directory, config) = installation();
        let root = config.roots["data"].clone();
        crate::private_files::create_directory(&root.join("parent")).unwrap();
        seed(&config, "parent/node", 8192);
        let disk = open(config.clone(), fixture_memory.clone());
        let file = disk.open_file("data", Path::new("parent/node")).unwrap();
        let identity = file.identity().unwrap();
        let before = disk.snapshot();
        if replace_parent {
            std::fs::rename(root.join("parent"), root.join("retained")).unwrap();
            crate::private_files::create_directory(&root.join("parent")).unwrap();
        } else {
            std::fs::rename(root.join("parent/node"), root.join("retained")).unwrap();
        }
        seed(&config, "parent/node", 4096);
        let replacement = std::fs::read(root.join("parent/node")).unwrap();
        let retained = root.join(if replace_parent {
            "retained/node"
        } else {
            "retained"
        });
        assert_eq!(
            crate::private_files::file_identity(&retained).unwrap(),
            identity
        );
        if replace_parent {
            assert!(file.sync_all_and_parent().is_err());
            assert!(file.identity().is_err());
        } else {
            assert!(file.identity().is_err());
            assert!(file.sync_all_and_parent().is_err());
        }
        assert_eq!(
            std::fs::read(root.join("parent/node")).unwrap(),
            replacement
        );
        assert_eq!(std::fs::metadata(&retained).unwrap().len(), 8192);
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
        drop(file);
        std::fs::remove_file(root.join("parent/node")).unwrap();
        if replace_parent {
            std::fs::remove_dir(root.join("parent")).unwrap();
            std::fs::rename(root.join("retained"), root.join("parent")).unwrap();
        } else {
            std::fs::rename(root.join("retained"), root.join("parent/node")).unwrap();
        }
        clean(&disk, &["parent/node"]);
    }
}

#[test]
fn uncertain_envelope_parent_sync_preserves_charges_through_close_and_census() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config, fixture_memory.clone());
    let file = disk
        .create_file("data", Path::new("node"), DiskWork::Foreground)
        .unwrap();
    file.reserve_growth(0, 64 << 10, DiskWork::Foreground)
        .unwrap();
    file.grow_reserved(64 << 10).unwrap();
    file.write_all_at(&vec![0xa5; 64 << 10], 0).unwrap();
    let identity = file.identity().unwrap();
    let before = disk.snapshot();
    disk.parent_sync_failure.store(true, Ordering::Relaxed);
    assert!(file.sync_all_and_parent().is_err());
    assert_eq!(file.identity().unwrap(), identity);
    assert_eq!(file.observed_len().unwrap(), 64 << 10);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(
        disk.snapshot().filesystem_pending_bytes,
        before.filesystem_pending_bytes
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert!(!disk.snapshot().filesystem_admission_ready);
    disk.parent_sync_failure.store(false, Ordering::Relaxed);
    assert!(file.sync_all_and_parent().is_err());
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    drop(file);
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 64 << 10);
    assert!(disk.snapshot().filesystem_admission_ready);
    let reopened = disk.open_file("data", Path::new("node")).unwrap();
    assert_eq!(reopened.identity().unwrap(), identity);
    reopened.sync_all_and_parent().unwrap();
    drop(reopened);
    clean(&disk, &["node"]);
}

#[test]
fn immutable_publication_preserves_the_inode_and_its_capacity_charge() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config.clone(), fixture_memory.clone());
    let file = disk
        .create_file("data", Path::new("staged"), DiskWork::Maintenance)
        .unwrap();
    file.reserve_growth(0, 4096, DiskWork::Maintenance).unwrap();
    file.grow_reserved(4096).unwrap();
    file.write_all_at(&[41; 4096], 0).unwrap();
    file.sync_all_and_parent().unwrap();
    let identity = file.identity().unwrap();
    let before = disk.snapshot();
    let published = disk
        .publish_file(file, "data", Path::new("published"))
        .unwrap();
    assert_eq!(published.identity().unwrap(), identity);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().persistent_files, 1);
    assert_eq!(disk.snapshot().open_files, 1);
    assert!(!config.roots["data"].join("staged").exists());
    let mut bytes = [0; 4096];
    published.read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(bytes, [41; 4096]);
    disk.delete_file(published).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn publication_conflict_keeps_both_files_and_the_owner_usable() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config.clone(), fixture_memory.clone());
    let first = disk
        .create_file("data", Path::new("first"), DiskWork::Foreground)
        .unwrap();
    let other = disk
        .create_file("data", Path::new("published"), DiskWork::Foreground)
        .unwrap();
    let identity = other.identity().unwrap();
    drop(other);
    assert!(
        disk.publish_file(first, "data", Path::new("published"))
            .is_err()
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().persistent_files, 2);
    assert!(config.roots["data"].join("first").exists());
    let published = disk.open_file("data", Path::new("published")).unwrap();
    assert_eq!(published.identity().unwrap(), identity);
}

#[test]
fn publication_requires_actual_descriptor_clone_drain() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config.clone(), fixture_memory.clone());
    let first = disk
        .create_file("data", Path::new("first"), DiskWork::Foreground)
        .unwrap();
    let retained = first.clone();
    assert!(
        disk.publish_file(first, "data", Path::new("published"))
            .is_err()
    );
    assert_eq!(disk.snapshot().open_files, 1);
    assert!(!config.roots["data"].join("published").exists());
    disk.publish_file(retained, "data", Path::new("published"))
        .unwrap();
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
}

#[test]
fn raw_created_file_is_not_adopted_after_the_installed_census() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config.clone(), fixture_memory.clone());
    let retained = disk
        .create_file("data", Path::new("retained"), DiskWork::Foreground)
        .unwrap();
    seed(&config, "raw", 64 << 10);
    let before = disk.snapshot();
    assert!(disk.open_file("data", Path::new("raw")).is_err());
    let failed = disk.snapshot();
    assert_eq!(failed.phase, NodeDiskPhase::Failed);
    assert_eq!(failed.charged_bytes, before.charged_bytes);
    assert_eq!(failed.persistent_files, 1);
    assert_eq!(failed.open_files, 1);
    assert!(!failed.filesystem_admission_ready);
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    drop(retained);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 64 << 10);
    assert_eq!(disk.snapshot().persistent_files, 2);
    let raw = disk.open_file("data", Path::new("raw")).unwrap();
    disk.delete_file(raw).unwrap();
    let retained = disk.open_file("data", Path::new("retained")).unwrap();
    disk.delete_file(retained).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().persistent_files, 0);
    disk.pause().unwrap();
}

#[test]
fn raw_growth_of_a_closed_censused_inode_fences_without_rebasing_its_charge() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    seed(&config, "file", 32 << 10);
    let disk = open(config.clone(), fixture_memory.clone());
    drop(disk.open_file("data", Path::new("file")).unwrap());
    let raw = std::fs::OpenOptions::new()
        .write(true)
        .open(config.roots["data"].join("file"))
        .unwrap();
    raw.set_len(128 << 10).unwrap();
    raw.sync_all().unwrap();
    drop(raw);
    assert!(disk.open_file("data", Path::new("file")).is_err());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().charged_bytes, 32 << 10);
    assert_eq!(disk.snapshot().persistent_files, 1);
    assert_eq!(disk.snapshot().open_files, 0);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 128 << 10);
    let file = disk.open_file("data", Path::new("file")).unwrap();
    disk.delete_file(file).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().persistent_files, 0);
    disk.pause().unwrap();
}

#[test]
fn enrolled_extents_survive_all_physical_updates_and_descriptor_reopens() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config.clone(), fixture_memory.clone());
    let mut file = disk
        .create_file("data", Path::new("file"), DiskWork::Foreground)
        .unwrap();
    let identity = file.identity().unwrap();
    file.reserve_growth(0, 256 << 10, DiskWork::Foreground)
        .unwrap();
    file.grow_reserved(128 << 10).unwrap();
    file.write_all_at(&[7; 32 << 10], 0).unwrap();
    file.settle_growth(128 << 10).unwrap();
    let after_write = disk.snapshot();
    drop(file);
    for _ in 0..3 {
        file = disk.open_file("data", Path::new("file")).unwrap();
        assert_eq!(file.identity().unwrap(), identity);
        assert_eq!(file.observed_len().unwrap(), 128 << 10);
        assert_eq!(disk.snapshot().charged_bytes, after_write.charged_bytes);
        assert_eq!(disk.snapshot().pending_bytes, after_write.pending_bytes);
        assert_eq!(disk.snapshot().persistent_files, 1);
        drop(file);
    }
    file = disk.open_file("data", Path::new("file")).unwrap();
    file.shrink(64 << 10).unwrap();
    drop(file);
    file = disk.open_file("data", Path::new("file")).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 64 << 10);
    disk.shrink_file(file, 32 << 10).unwrap();
    file = disk.open_file("data", Path::new("file")).unwrap();
    assert_eq!(file.observed_len().unwrap(), 32 << 10);
    file = disk
        .publish_file(file, "data", Path::new("published"))
        .unwrap();
    assert_eq!(file.identity().unwrap(), identity);
    drop(file);
    file = disk.open_file("data", Path::new("published")).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 32 << 10);
    assert_eq!(disk.snapshot().persistent_files, 1);
    disk.delete_file(file).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().pending_bytes, 0);
    assert_eq!(disk.snapshot().persistent_files, 0);
    assert_eq!(disk.state.lock().unwrap().files, 0);
    disk.pause().unwrap();
}

#[test]
fn enrolled_file_metadata_limit_rejects_before_creating_an_untracked_inode() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, mut config) = installation();
    config.max_census_entries = 3;
    let disk = open(config.clone(), fixture_memory.clone());
    for name in ["one", "two", "three"] {
        drop(
            disk.create_file("data", Path::new(name), DiskWork::Foreground)
                .unwrap(),
        );
    }
    assert!(
        disk.create_file("data", Path::new("four"), DiskWork::Foreground)
            .is_err()
    );
    assert!(!config.roots["data"].join("four").exists());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().persistent_files, 3);
    assert_eq!(disk.state.lock().unwrap().files, 3);
    for name in ["one", "two", "three"] {
        let file = disk.open_file("data", Path::new(name)).unwrap();
        disk.delete_file(file).unwrap();
    }
    disk.pause().unwrap();
    disk.reconcile(&CensusCancellation::default()).unwrap();
}

#[test]
fn failed_direct_handles_never_release_bytes_or_restart_sync() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    for fail_shared_device in [false, true] {
        let (_directory, config) = installation();
        let disk = open(config, fixture_memory.clone());
        let file = disk
            .create_file("data", Path::new("file"), DiskWork::Foreground)
            .unwrap();
        file.reserve_growth(0, 4096, DiskWork::Foreground).unwrap();
        file.grow_reserved(4096).unwrap();
        file.write_all_at(&[71; 4096], 0).unwrap();
        file.sync_all_and_parent().unwrap();
        let before = disk.snapshot();
        if fail_shared_device {
            disk.device.lock().fail_owner();
        } else {
            disk.fail();
        }
        let mut out = [93; 32];
        let (outcomes, allocations) = crate::allocation_tests::measure(|| {
            (
                file.read_exact_at(&mut out, 0),
                file.sync_all(),
                file.sync_all_and_parent(),
            )
        });
        assert!(outcomes.0.is_err());
        assert!(outcomes.1.is_err());
        assert!(outcomes.2.is_err());
        assert_eq!(out, [93; 32], "failed owner released file bytes");
        assert_eq!(allocations, 0);
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
        drop(file);
        clean(&disk, &["file"]);
    }
}

#[test]
fn paused_direct_handles_can_finish_only_already_admitted_io() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config, fixture_memory.clone());
    let file = disk
        .create_file("data", Path::new("file"), DiskWork::Foreground)
        .unwrap();
    file.reserve_growth(0, 4096, DiskWork::Foreground).unwrap();
    assert!(disk.pause().is_err());
    file.grow_reserved(4096).unwrap();
    file.write_all_at(&[53; 4096], 0).unwrap();
    file.sync_all().unwrap();
    file.sync_all_and_parent().unwrap();
    let mut out = [0; 32];
    file.read_exact_at(&mut out, 0).unwrap();
    assert_eq!(out, [53; 32]);
    assert!(
        file.reserve_growth(4096, 8192, DiskWork::Foreground)
            .is_err()
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Paused);
    drop(file);
    clean(&disk, &["file"]);
}

#[test]
fn prepared_file_creation_registers_and_retires_without_allocating() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config.clone(), fixture_memory.clone());
    // Cross several hash-table growth boundaries: capacity must be acquired by
    // prepare_file, before O_CREAT makes any of these inode names visible.
    for index in 0..9 {
        let name = format!("prepared-{index}");
        let prepared = disk
            .prepare_file("data", Path::new(&name), Some(DiskWork::Foreground))
            .unwrap();
        assert!(!config.roots["data"].join(&name).exists());
        let (result, allocations) = crate::allocation_tests::measure(|| prepared.execute());
        let file = result.unwrap();
        assert_eq!(allocations, 0, "file creation allocated after preparation");
        let (result, allocations) = crate::allocation_tests::measure(|| file.check_owner());
        result.unwrap();
        assert_eq!(allocations, 0, "new owner's first I/O allocated");
        let ((), allocations) = crate::allocation_tests::measure(|| drop(file));
        assert_eq!(allocations, 0);
        assert_eq!(disk.snapshot().open_files, 0);
        assert_eq!(disk.snapshot().persistent_files, index + 1);
    }
    for index in 0..9 {
        let name = format!("prepared-{index}");
        let file = disk.open_file("data", Path::new(&name)).unwrap();
        disk.delete_file(file).unwrap();
    }
    assert_eq!(disk.snapshot().persistent_files, 0);
}

#[test]
fn failed_creation_retains_provisional_enrollment_without_registered_drop() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    for failure in [
        file::NamespaceFailure::CreateFileSync,
        file::NamespaceFailure::CreateParentSync,
    ] {
        let (_directory, config) = installation();
        let disk = open(config.clone(), fixture_memory.clone());
        let prepared = disk
            .prepare_file("data", Path::new("created"), Some(DiskWork::Foreground))
            .unwrap();
        disk.namespace_failure
            .store(failure as u8, Ordering::Relaxed);
        let (result, allocations) = crate::allocation_tests::measure(|| prepared.execute());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(allocations, 0, "failed creation allocated: {failure:?}");
        let snapshot = disk.snapshot();
        assert_eq!(snapshot.phase, NodeDiskPhase::Failed);
        assert_eq!(snapshot.open_files, 0);
        assert_eq!(snapshot.persistent_files, 1);
        let path = config.roots["data"].join("created");
        let raw = std::fs::File::open(&path).unwrap();
        raw.try_lock().unwrap();
        let identity = Identity::of(&raw.metadata().unwrap());
        assert!(
            !disk.lock_state().accounted[&identity]
                .file()
                .unwrap()
                .settled
        );
        drop(raw);
        clean(&disk, &["created"]);
    }
}

#[test]
fn abandoned_namespace_preparation_releases_registration_without_deadlock() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config.clone(), fixture_memory.clone());
    let prepared = disk
        .prepare_file("data", Path::new("absent"), Some(DiskWork::Foreground))
        .unwrap();
    let ((), allocations) = crate::allocation_tests::measure(|| drop(prepared));
    assert_eq!(allocations, 0);
    assert!(!config.roots["data"].join("absent").exists());
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(disk.snapshot().persistent_files, 0);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);

    let file = disk
        .create_file("data", Path::new("source"), DiskWork::Foreground)
        .unwrap();
    let prepared = disk
        .prepare_publication(file, "data", Path::new("destination"))
        .unwrap();
    let ((), allocations) = crate::allocation_tests::measure(|| drop(prepared));
    assert_eq!(allocations, 0);
    assert!(!config.roots["data"].join("destination").exists());
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(disk.snapshot().persistent_files, 1);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    let file = disk.open_file("data", Path::new("source")).unwrap();
    disk.delete_file(file).unwrap();
}

#[test]
fn prepared_cross_directory_publication_and_physical_reclaim_do_not_allocate() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let source = "s".repeat(200);
    let destination = "d".repeat(200);
    for name in [&source, &destination] {
        crate::private_files::create_directory(&config.roots["data"].join(name)).unwrap();
    }
    let source = Path::new(&source).join("staged");
    let destination = Path::new(&destination).join("published");
    let disk = open(config.clone(), fixture_memory.clone());
    let file = disk
        .create_file("data", &source, DiskWork::Foreground)
        .unwrap();
    file.reserve_growth(0, 32 << 10, DiskWork::Foreground)
        .unwrap();
    file.grow_reserved(32 << 10).unwrap();
    file.write_all_at(&[17; 32 << 10], 0).unwrap();
    file.sync_all_and_parent().unwrap();
    let identity = file.identity().unwrap();
    let prepared = disk
        .prepare_publication(file, "data", &destination)
        .unwrap();
    let (result, allocations) = crate::allocation_tests::measure(|| prepared.execute());
    let file = result.unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(file.identity().unwrap(), identity);
    assert!(!config.roots["data"].join(&source).exists());
    assert_eq!(disk.snapshot().charged_bytes, 32 << 10);
    let (result, allocations) =
        crate::allocation_tests::measure(|| disk.shrink_file(file, 16 << 10));
    result.unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().charged_bytes, 16 << 10);
    assert_eq!(disk.snapshot().open_files, 0);
    let file = disk.open_file("data", &destination).unwrap();
    let (result, allocations) = crate::allocation_tests::measure(|| disk.delete_file(file));
    result.unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().persistent_files, 0);
    assert_eq!(disk.snapshot().open_files, 0);
}

#[test]
fn post_rename_failures_keep_the_charge_and_return_without_allocating() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    for failure in [
        file::NamespaceFailure::PublishSourceSync,
        file::NamespaceFailure::PublishDestinationSync,
        file::NamespaceFailure::PublishVerify,
    ] {
        let (_directory, config) = installation();
        let disk = open(config.clone(), fixture_memory.clone());
        let file = disk
            .create_file("data", Path::new("source"), DiskWork::Foreground)
            .unwrap();
        file.reserve_growth(0, 32 << 10, DiskWork::Foreground)
            .unwrap();
        file.grow_reserved(32 << 10).unwrap();
        file.write_all_at(&[19; 32 << 10], 0).unwrap();
        file.sync_all_and_parent().unwrap();
        let identity = file.identity().unwrap();
        let prepared = disk
            .prepare_publication(file, "data", Path::new("destination"))
            .unwrap();
        disk.namespace_failure
            .store(failure as u8, Ordering::Relaxed);
        let (result, allocations) = crate::allocation_tests::measure(|| prepared.execute());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(allocations, 0, "post-rename error allocated: {failure:?}");
        assert!(!config.roots["data"].join("source").exists());
        assert_eq!(
            crate::private_files::file_identity(&config.roots["data"].join("destination")).unwrap(),
            identity
        );
        let snapshot = disk.snapshot();
        assert_eq!(snapshot.phase, NodeDiskPhase::Failed);
        assert_eq!(snapshot.open_files, 0);
        assert_eq!(snapshot.persistent_files, 1);
        assert_eq!(snapshot.charged_bytes, 32 << 10);
        let binding = NamespaceBinding::root(disk.roots["data"].identity).child(c"destination");
        assert_eq!(
            disk.lock_state()
                .accounted
                .values()
                .filter_map(AccountedInode::file)
                .next()
                .unwrap()
                .binding,
            binding
        );
        assert!(disk.open_file("data", Path::new("destination")).is_err());
        let raw = std::fs::File::open(config.roots["data"].join("destination")).unwrap();
        raw.try_lock().unwrap();
        drop(raw);
        clean(&disk, &["destination"]);
    }
}

#[test]
fn post_reclaim_failures_keep_credit_until_actual_drain_and_census_without_allocating() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    for (length, failure) in [
        (Some(16 << 10), file::NamespaceFailure::ReclaimFileSync),
        (Some(16 << 10), file::NamespaceFailure::ReclaimParentSync),
        (None, file::NamespaceFailure::ReclaimParentSync),
    ] {
        let (_directory, config) = installation();
        let disk = open(config.clone(), fixture_memory.clone());
        let file = disk
            .create_file("data", Path::new("file"), DiskWork::Foreground)
            .unwrap();
        file.reserve_growth(0, 32 << 10, DiskWork::Foreground)
            .unwrap();
        file.grow_reserved(32 << 10).unwrap();
        file.write_all_at(&[23; 32 << 10], 0).unwrap();
        file.sync_all_and_parent().unwrap();
        disk.namespace_failure
            .store(failure as u8, Ordering::Relaxed);
        let (result, allocations) = crate::allocation_tests::measure(|| match length {
            Some(length) => disk.shrink_file(file, length),
            None => disk.delete_file(file),
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(allocations, 0, "post-reclaim error allocated: {failure:?}");
        let snapshot = disk.snapshot();
        assert_eq!(snapshot.phase, NodeDiskPhase::Failed);
        assert_eq!(snapshot.open_files, 0);
        assert_eq!(snapshot.persistent_files, 1);
        assert_eq!(snapshot.charged_bytes, 32 << 10);
        let path = config.roots["data"].join("file");
        if let Some(length) = length {
            let raw = std::fs::File::open(&path).unwrap();
            raw.try_lock().unwrap();
            assert_eq!(raw.metadata().unwrap().len(), length);
            drop(raw);
        } else {
            assert!(!path.exists());
        }
        disk.reconcile(&CensusCancellation::default()).unwrap();
        assert_eq!(disk.snapshot().charged_bytes, length.unwrap_or(0));
        if length.is_some() {
            let file = disk.open_file("data", Path::new("file")).unwrap();
            disk.delete_file(file).unwrap();
        }
        assert_eq!(disk.snapshot().charged_bytes, 0);
        assert_eq!(disk.snapshot().persistent_files, 0);
    }
}

#[test]
fn prepared_publication_conflict_returns_inline_without_fencing_or_replacing() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config.clone(), fixture_memory.clone());
    let first = disk
        .create_file("data", Path::new("first"), DiskWork::Foreground)
        .unwrap();
    let other = disk
        .create_file("data", Path::new("destination"), DiskWork::Foreground)
        .unwrap();
    let identity = other.identity().unwrap();
    drop(other);
    let prepared = disk
        .prepare_publication(first, "data", Path::new("destination"))
        .unwrap();
    let (result, allocations) = crate::allocation_tests::measure(|| prepared.execute());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(disk.snapshot().persistent_files, 2);
    assert!(config.roots["data"].join("first").exists());
    assert_eq!(
        crate::private_files::file_identity(&config.roots["data"].join("destination")).unwrap(),
        identity
    );
    clean(&disk, &["first", "destination"]);
}

#[test]
fn unenrolled_missing_leaf_preserves_admission_without_allocating() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    crate::private_files::create_directory(&config.roots["data"].join("nested")).unwrap();
    seed(&config, "retained", 32 << 10);
    let disk = open(config, fixture_memory.clone());
    let before = disk.snapshot();
    let prepared = disk
        .prepare_file("data", Path::new("nested/absent"), None)
        .unwrap();
    let (result, allocations) = crate::allocation_tests::measure(|| prepared.execute());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().persistent_files, before.persistent_files);
    let created = disk
        .create_file("data", Path::new("nested/absent"), DiskWork::Foreground)
        .unwrap();
    drop(created);
    let created = disk.open_file("data", Path::new("nested/absent")).unwrap();
    disk.delete_file(created).unwrap();
    let retained = disk.open_file("data", Path::new("retained")).unwrap();
    disk.delete_file(retained).unwrap();
}

#[test]
fn disappeared_censused_and_closed_created_names_fence_without_credit() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    for censused in [true, false] {
        let (_directory, config) = installation();
        crate::private_files::create_directory(&config.roots["data"].join("nested")).unwrap();
        if censused {
            seed(&config, "nested/file", 32 << 10);
        }
        let disk = open(config.clone(), fixture_memory.clone());
        if !censused {
            let file = disk
                .create_file("data", Path::new("nested/file"), DiskWork::Foreground)
                .unwrap();
            file.reserve_growth(0, 32 << 10, DiskWork::Foreground)
                .unwrap();
            file.grow_reserved(32 << 10).unwrap();
            file.sync_all_and_parent().unwrap();
            drop(file);
        }
        drop(disk.open_file("data", Path::new("nested/file")).unwrap());
        let before = disk.snapshot();
        std::fs::remove_file(config.roots["data"].join("nested/file")).unwrap();
        let prepared = disk
            .prepare_file("data", Path::new("nested/file"), None)
            .unwrap();
        let (result, allocations) = crate::allocation_tests::measure(|| prepared.execute());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(allocations, 0);
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(disk.snapshot().persistent_files, 1);
        assert_eq!(disk.snapshot().open_files, 0);
        disk.reconcile(&CensusCancellation::default()).unwrap();
        assert_eq!(disk.snapshot().charged_bytes, 0);
        assert_eq!(disk.snapshot().persistent_files, 0);
        disk.pause().unwrap();
    }
}

#[test]
fn raw_rename_fences_both_missing_old_name_and_present_new_name() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    for keep_live in [false, true] {
        for lookup in ["original", "moved"] {
            let (_directory, config) = installation();
            seed(&config, "original", 32 << 10);
            let disk = open(config.clone(), fixture_memory.clone());
            let retained =
                keep_live.then(|| disk.open_file("data", Path::new("original")).unwrap());
            std::fs::rename(
                config.roots["data"].join("original"),
                config.roots["data"].join("moved"),
            )
            .unwrap();
            assert!(disk.open_file("data", Path::new(lookup)).is_err());
            assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
            assert_eq!(disk.snapshot().charged_bytes, 32 << 10);
            assert_eq!(disk.snapshot().persistent_files, 1);
            drop(retained);
            clean(&disk, &["moved"]);
        }
    }
}

#[test]
fn admitted_publication_rebinds_name_and_reclaim_forgets_it() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    crate::private_files::create_directory(&config.roots["data"].join("nested")).unwrap();
    seed(&config, "source", 32 << 10);
    let disk = open(config, fixture_memory.clone());
    let file = disk.open_file("data", Path::new("source")).unwrap();
    let prepared = disk
        .prepare_publication(file, "data", Path::new("nested/published"))
        .unwrap();
    let (result, allocations) = crate::allocation_tests::measure(|| prepared.execute());
    let file = result.unwrap();
    assert_eq!(allocations, 0);
    drop(file);
    assert_eq!(
        disk.open_file("data", Path::new("source"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    let file = disk
        .open_file("data", Path::new("nested/published"))
        .unwrap();
    disk.delete_file(file).unwrap();
    assert_eq!(
        disk.open_file("data", Path::new("nested/published"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().persistent_files, 0);
    let replacement = disk
        .create_file("data", Path::new("nested/published"), DiskWork::Foreground)
        .unwrap();
    disk.delete_file(replacement).unwrap();
}

#[test]
fn missing_enrolled_target_cannot_be_recreated_or_published_over() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    for publish in [false, true] {
        let (_directory, config) = installation();
        seed(&config, "target", 32 << 10);
        let disk = open(config.clone(), fixture_memory.clone());
        let source = publish.then(|| {
            disk.create_file("data", Path::new("source"), DiskWork::Foreground)
                .unwrap()
        });
        let before = disk.snapshot();
        std::fs::remove_file(config.roots["data"].join("target")).unwrap();
        let (result, allocations) = if let Some(source) = source {
            let prepared = disk
                .prepare_publication(source, "data", Path::new("target"))
                .unwrap();
            crate::allocation_tests::measure(|| prepared.execute())
        } else {
            let prepared = disk
                .prepare_file("data", Path::new("target"), Some(DiskWork::Foreground))
                .unwrap();
            crate::allocation_tests::measure(|| prepared.execute())
        };
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(allocations, 0);
        assert!(!config.roots["data"].join("target").exists());
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(disk.snapshot().persistent_files, before.persistent_files);
        assert_eq!(disk.snapshot().open_files, 0);
        if publish {
            clean(&disk, &["source"]);
        } else {
            disk.reconcile(&CensusCancellation::default()).unwrap();
        }
    }
}

#[test]
fn live_enrolled_target_conflicts_remain_healthy_and_preserve_content() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    for publish in [false, true] {
        let (_directory, config) = installation();
        seed(&config, "target", 32 << 10);
        let disk = open(config.clone(), fixture_memory.clone());
        let target = disk.open_file("data", Path::new("target")).unwrap();
        let (result, allocations) = if publish {
            let source = disk
                .create_file("data", Path::new("source"), DiskWork::Foreground)
                .unwrap();
            let prepared = disk
                .prepare_publication(source, "data", Path::new("target"))
                .unwrap();
            crate::allocation_tests::measure(|| prepared.execute())
        } else {
            let prepared = disk
                .prepare_file("data", Path::new("target"), Some(DiskWork::Foreground))
                .unwrap();
            crate::allocation_tests::measure(|| prepared.execute())
        };
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(allocations, 0);
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
        assert_eq!(target.observed_len().unwrap(), 32 << 10);
        disk.delete_file(target).unwrap();
        if publish {
            let source = disk.open_file("data", Path::new("source")).unwrap();
            disk.delete_file(source).unwrap();
        }
    }
}

#[test]
fn prepared_unknown_absence_revalidates_replaced_parent() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let parent = config.roots["data"].join("nested");
    crate::private_files::create_directory(&parent).unwrap();
    let disk = open(config.clone(), fixture_memory.clone());
    let prepared = disk
        .prepare_file("data", Path::new("nested/absent"), None)
        .unwrap();
    std::fs::rename(&parent, config.roots["data"].join("moved")).unwrap();
    crate::private_files::create_directory(&parent).unwrap();
    let (result, allocations) = crate::allocation_tests::measure(|| prepared.execute());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().persistent_files, 0);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    disk.pause().unwrap();
}

#[test]
fn replaced_parent_cannot_hide_enrolled_missing_leaf() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let parent = config.roots["data"].join("nested");
    crate::private_files::create_directory(&parent).unwrap();
    seed(&config, "nested/file", 32 << 10);
    let disk = open(config.clone(), fixture_memory.clone());
    std::fs::rename(&parent, config.roots["data"].join("moved")).unwrap();
    crate::private_files::create_directory(&parent).unwrap();
    assert_eq!(
        disk.open_file("data", Path::new("nested/file"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().charged_bytes, 32 << 10);
    clean(&disk, &["moved/file"]);
}

#[test]
fn publication_preparation_missing_or_symlinked_ancestor_fences() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    for replace_with_symlink in [false, true] {
        let (_directory, config) = installation();
        let parent = config.roots["data"].join("nested");
        let moved = config.roots["data"].join("moved");
        crate::private_files::create_directory(&parent).unwrap();
        seed(&config, "source", 32 << 10);
        let disk = open(config.clone(), fixture_memory.clone());
        let source = disk.open_file("data", Path::new("source")).unwrap();
        std::fs::rename(&parent, &moved).unwrap();
        if replace_with_symlink {
            symlink(&moved, &parent).unwrap();
        }
        assert!(
            disk.prepare_publication(source, "data", Path::new("nested/published"))
                .is_err()
        );
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
        assert_eq!(disk.snapshot().charged_bytes, 32 << 10);
        assert_eq!(disk.snapshot().open_files, 0);
        assert!(!moved.join("published").exists());
        if replace_with_symlink {
            std::fs::remove_file(&parent).unwrap();
        }
        std::fs::rename(&moved, &parent).unwrap();
        clean(&disk, &["source"]);
    }
}

#[test]
fn publication_preparation_replaced_root_fences_before_rename() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (directory, config) = installation();
    seed(&config, "source", 32 << 10);
    let disk = open(config.clone(), fixture_memory.clone());
    let source = disk.open_file("data", Path::new("source")).unwrap();
    let root = &config.roots["data"];
    let moved = directory.path().join("moved-root");
    std::fs::rename(root, &moved).unwrap();
    crate::private_files::create_directory(root).unwrap();
    assert!(
        disk.prepare_publication(source, "data", Path::new("published"))
            .is_err()
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().charged_bytes, 32 << 10);
    assert_eq!(disk.snapshot().open_files, 0);
    assert!(!root.join("published").exists());
    assert!(moved.join("source").exists());
    std::fs::remove_dir(root).unwrap();
    std::fs::rename(&moved, root).unwrap();
    clean(&disk, &["source"]);
}

#[test]
fn publication_replaced_private_source_ancestor_fences_before_rename() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let parent = config.roots["data"].join("nested");
    crate::private_files::create_directory(&parent).unwrap();
    seed(&config, "nested/source", 32 << 10);
    let disk = open(config.clone(), fixture_memory.clone());
    let source = disk.open_file("data", Path::new("nested/source")).unwrap();
    std::fs::rename(&parent, config.roots["data"].join("moved")).unwrap();
    crate::private_files::create_directory(&parent).unwrap();
    let prepared = disk
        .prepare_publication(source, "data", Path::new("nested/published"))
        .unwrap();
    let (result, allocations) = crate::allocation_tests::measure(|| prepared.execute());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().charged_bytes, 32 << 10);
    assert_eq!(disk.snapshot().open_files, 0);
    assert!(!parent.join("published").exists());
    clean(&disk, &["moved/source"]);
}

#[test]
fn enrolled_target_unauthorized_growth_never_becomes_a_healthy_conflict() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    for publish in [false, true] {
        for (reserved, raw_length) in [
            (32 << 10, 48 << 10),
            (64 << 10, 48 << 10),
            (64 << 10, 96 << 10),
        ] {
            let (_directory, config) = installation();
            seed(&config, "target", 32 << 10);
            let disk = open(config.clone(), fixture_memory.clone());
            let target = disk.open_file("data", Path::new("target")).unwrap();
            if reserved > 32 << 10 {
                target
                    .reserve_growth(32 << 10, reserved, DiskWork::Foreground)
                    .unwrap();
            }
            let source = publish.then(|| {
                disk.create_file("data", Path::new("source"), DiskWork::Foreground)
                    .unwrap()
            });
            let before = disk.snapshot();
            let raw = std::fs::OpenOptions::new()
                .write(true)
                .open(config.roots["data"].join("target"))
                .unwrap();
            raw.set_len(raw_length).unwrap();
            raw.sync_all().unwrap();
            drop(raw);
            let (result, allocations) = if let Some(source) = source {
                let prepared = disk
                    .prepare_publication(source, "data", Path::new("target"))
                    .unwrap();
                crate::allocation_tests::measure(|| prepared.execute())
            } else {
                let prepared = disk
                    .prepare_file("data", Path::new("target"), Some(DiskWork::Foreground))
                    .unwrap();
                crate::allocation_tests::measure(|| prepared.execute())
            };
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert_eq!(allocations, 0);
            assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
            assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
            assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
            assert_eq!(disk.snapshot().persistent_files, before.persistent_files);
            drop(target);
            if publish {
                clean(&disk, &["source", "target"]);
            } else {
                clean(&disk, &["target"]);
            }
        }
    }
}

#[test]
fn enrolled_target_conflict_accepts_only_actual_admitted_growth() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    for publish in [false, true] {
        for materialize in [false, true] {
            let (_directory, config) = installation();
            seed(&config, "target", 32 << 10);
            let disk = open(config.clone(), fixture_memory.clone());
            let target = disk.open_file("data", Path::new("target")).unwrap();
            target
                .reserve_growth(32 << 10, 64 << 10, DiskWork::Foreground)
                .unwrap();
            let actual_len = if materialize {
                target.grow_reserved(48 << 10).unwrap();
                target.write_all_at(&[73; 4096], 32 << 10).unwrap();
                48 << 10
            } else {
                32 << 10
            };
            let source = publish.then(|| {
                disk.create_file("data", Path::new("source"), DiskWork::Foreground)
                    .unwrap()
            });
            let before = disk.snapshot();
            let (result, allocations) = if let Some(source) = source {
                let prepared = disk
                    .prepare_publication(source, "data", Path::new("target"))
                    .unwrap();
                crate::allocation_tests::measure(|| prepared.execute())
            } else {
                let prepared = disk
                    .prepare_file("data", Path::new("target"), Some(DiskWork::Foreground))
                    .unwrap();
                crate::allocation_tests::measure(|| prepared.execute())
            };
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
            assert_eq!(allocations, 0);
            assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
            assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
            assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
            assert_eq!(target.observed_len().unwrap(), actual_len);
            target.settle_growth(actual_len).unwrap();
            disk.delete_file(target).unwrap();
            if publish {
                let source = disk.open_file("data", Path::new("source")).unwrap();
                disk.delete_file(source).unwrap();
            }
        }
    }
}

fn installed_metadata_total(required: DiskMemoryRequirements) -> u64 {
    [
        required.owner_bytes,
        required.registry_bytes,
        required.device_bytes,
        required.registration_bytes,
    ]
    .into_iter()
    .map(|bytes| crate::test_utils::TestDiskMemory::required_reservation_bytes(bytes).unwrap())
    .try_fold(0_u64, u64::checked_add)
    .unwrap()
}

#[test]
fn metadata_denial_precedes_root_open_and_retained_census_allocation() {
    let (_directory, mut config) = installation();
    config.roots.get_mut("data").unwrap().push("not-created");
    let required = NodeDisk::memory_requirements(&config).unwrap();
    let cap = crate::test_utils::TestDiskMemory::required_reservation_bytes(required.owner_bytes)
        .unwrap()
        - 1;
    let memory = crate::test_utils::TestDiskMemory::new(cap, 4);
    let crate::DiskOpenError::Failed(error) = crate::test_utils::retry_disk_registry(|| {
        NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap_err() else {
        panic!("expected resident admission denial");
    };
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert!(!config.roots["data"].exists());
    assert_eq!(memory.snapshot().attempts, 1);
    assert_eq!(memory.snapshot().used_bytes, 0);
    assert_eq!(memory.snapshot().live_reservations, 0);
}

#[test]
fn partial_metadata_admission_never_leaves_unfunded_provisional_owners() {
    for slots in [1, 2, 3] {
        let (_directory, config) = installation();
        let total = installed_metadata_total(NodeDisk::memory_requirements(&config).unwrap());
        let memory = crate::test_utils::TestDiskMemory::new(total, slots);
        assert!(
            crate::test_utils::retry_disk_registry(|| NodeDisk::open_fixture(
                &config,
                memory.clone(),
                &CensusCancellation::default()
            ))
            .is_err()
        );
        assert_eq!(memory.snapshot().attempts, slots as u64 + 1);
        assert_eq!(memory.snapshot().used_bytes, 0);
        assert_eq!(memory.snapshot().live_reservations, 0);
        // A failed provisional census also releases actual root descriptors/locks.
        let raw = std::fs::File::open(&config.roots["data"]).unwrap();
        census::lock(&raw, libc::LOCK_EX).unwrap();
    }
}

#[test]
fn installed_metadata_reuse_keeps_one_exact_core_and_one_retained_envelope() {
    let (_directory, config) = installation();
    let total = installed_metadata_total(NodeDisk::memory_requirements(&config).unwrap());
    let memory = crate::test_utils::TestDiskMemory::new(total, 4);
    let disk = crate::test_utils::retry_disk_registry(|| {
        NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap();
    let held = memory.snapshot();
    assert_eq!(held.used_bytes, total);
    assert_eq!(held.live_reservations, 4);
    let same = crate::test_utils::retry_disk_registry(|| {
        NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap();
    assert!(Arc::ptr_eq(&disk, &same));
    assert_eq!(memory.snapshot(), held);
    let foreign = crate::test_utils::TestDiskMemory::new(total, 4);
    assert!(
        crate::test_utils::retry_disk_registry(|| NodeDisk::open_fixture(
            &config,
            foreign.clone(),
            &CensusCancellation::default()
        ))
        .is_err()
    );
    assert_eq!(foreign.snapshot().attempts, 0);
    let mut changed = config.clone();
    changed.max_bytes += 4096;
    assert!(
        crate::test_utils::retry_disk_registry(|| NodeDisk::open_fixture(
            &changed,
            memory.clone(),
            &CensusCancellation::default()
        ))
        .is_err()
    );
    assert_eq!(memory.snapshot(), held);
    disk.pause().unwrap();
    drop(same);
    drop(disk);
    // The process registry deliberately retains census state and root locks.
    // Runtime/facade shutdown cannot return its actual installed metadata charge.
    assert_eq!(memory.snapshot(), held);
}

#[test]
fn census_failure_closes_real_descriptors_before_releasing_metadata() {
    let (_directory, config) = installation();
    symlink("missing", config.roots["data"].join("invalid")).unwrap();
    let total = installed_metadata_total(NodeDisk::memory_requirements(&config).unwrap());
    let memory = crate::test_utils::TestDiskMemory::new(total, 4);
    assert!(
        crate::test_utils::retry_disk_registry(|| NodeDisk::open_fixture(
            &config,
            memory.clone(),
            &CensusCancellation::default()
        ))
        .is_err()
    );
    assert_eq!(memory.snapshot().attempts, 2);
    assert_eq!(memory.snapshot().used_bytes, 0);
    assert_eq!(memory.snapshot().live_reservations, 0);
    let raw = std::fs::File::open(&config.roots["data"]).unwrap();
    census::lock(&raw, libc::LOCK_EX).unwrap();
    drop(raw);
    std::fs::remove_file(config.roots["data"].join("invalid")).unwrap();
    let disk = crate::test_utils::retry_disk_registry(|| {
        NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap();
    assert_eq!(memory.snapshot().used_bytes, total);
    disk.pause().unwrap();
}

#[test]
fn node_store_rejects_different_isolated_memory_before_touching_file() {
    let (_directory, config) = installation();
    seed(&config, "owned-empty", 0);
    let total = installed_metadata_total(NodeDisk::memory_requirements(&config).unwrap());
    let memory = crate::test_utils::TestDiskMemory::new(total, 4);
    let disk = crate::test_utils::retry_disk_registry(|| {
        NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap();
    let other_memory = crate::test_utils::TestDiskMemory::new(1 << 20, 4);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), other_memory.clone());
    let held = memory.snapshot();
    let other_held = other_memory.snapshot();
    let absent = config.roots["data"].join("must-not-exist");
    let empty = config.roots["data"].join("owned-empty");
    let identity = crate::private_files::file_identity(&empty).unwrap();
    assert!(
        crate::NodeStore::create_new(
            &absent,
            crate::test_utils::NODE_STORE_ID,
            disk.clone(),
            scratch.clone()
        )
        .is_err()
    );
    assert!(
        crate::NodeStore::open_existing(
            &empty,
            crate::test_utils::NODE_STORE_ID,
            disk.clone(),
            scratch.clone()
        )
        .is_err()
    );
    assert!(
        crate::NodeStore::initialize_owned_empty(
            &empty,
            &identity,
            crate::test_utils::NODE_STORE_ID,
            disk.clone(),
            scratch.clone()
        )
        .is_err()
    );
    assert!(!absent.exists());
    assert_eq!(std::fs::metadata(&empty).unwrap().len(), 0);
    assert_eq!(memory.snapshot(), held);
    assert_eq!(other_memory.snapshot(), other_held);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().open_files, 0);
    let empty = disk.open_file("data", Path::new("owned-empty")).unwrap();
    disk.delete_file(empty).unwrap();
}

#[test]
fn registry_busy_precedes_memory_acquisition_without_allocating() {
    let (_directory, config) = installation();
    let memory = crate::test_utils::TestDiskMemory::new(1, 1);
    let guard = registry().lock();
    let (result, allocations) = crate::allocation_tests::measure(|| {
        NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
    });
    assert!(matches!(result, Err(crate::DiskOpenError::RegistryBusy)));
    assert_eq!(allocations, 0);
    assert_eq!(memory.snapshot().attempts, 0);
    drop(guard);
}

#[test]
fn metadata_planning_has_no_heap_or_filesystem_effect_and_checks_overflow() {
    let (_directory, mut config) = installation();
    config.roots.get_mut("data").unwrap().push("not-created");
    let (result, allocations) =
        crate::allocation_tests::measure(|| NodeDisk::memory_requirements(&config));
    let required = result.unwrap();
    assert!(required.owner_bytes > 0 && required.registry_bytes > 0);
    assert!(required.device_bytes > 0 && required.registration_bytes > 0);
    assert_eq!(allocations, 0);
    assert!(!config.roots["data"].exists());
    config.max_census_entries = u64::MAX;
    assert!(NodeDisk::memory_requirements(&config).is_err());
    assert!(!config.roots["data"].exists());
}

#[test]
fn retiring_file_cannot_lend_handle_or_metadata_credit_before_parent_and_backing_release() {
    for stage in [
        file::CloseStage::DataClosed,
        file::CloseStage::ResourcesClosed,
    ] {
        let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let (_directory, mut config) = installation();
        config.max_open_files = 1;
        seed(&config, "file", 32 << 10);
        let disk = open(config.clone(), memory.clone());
        let file = disk.open_file("data", Path::new("file")).unwrap();
        let parent = file.parent_descriptor();
        let identity = Identity::of(&std::fs::metadata(config.roots["data"].join("file")).unwrap());
        let before_memory = memory.snapshot();
        let before_disk = disk.snapshot();
        let (entered, observed) = std::sync::mpsc::channel();
        let (release, resumed) = std::sync::mpsc::channel();
        *disk.after_file_close.lock().unwrap() = Some(file::ClosePause {
            stage,
            entered,
            release: resumed,
        });
        let closing = std::thread::spawn(move || drop(file));
        observed
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        if stage == file::CloseStage::DataClosed {
            // The data FD is gone, but the parent's real FD is still live here.
            assert_ne!(unsafe { libc::fcntl(parent, libc::F_GETFD) }, -1);
        } else {
            retired_descriptor_no_longer_names(parent, disk.roots["data"].identity);
        }
        let state = disk.lock_state();
        assert_eq!(state.open_files, 1);
        assert_eq!(state.live[&identity].strong_count(), 0);
        drop(state);
        let (result, allocations) = crate::allocation_tests::measure(|| {
            disk.create_file("data", Path::new("replacement"), DiskWork::Foreground)
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::StorageFull);
        assert_eq!(allocations, 0);
        assert!(!config.roots["data"].join("replacement").exists());
        assert_eq!(memory.snapshot(), before_memory);
        assert_eq!(disk.snapshot().charged_bytes, before_disk.charged_bytes);
        assert!(disk.pause().is_err());
        assert!(disk.reconcile(&CensusCancellation::default()).is_err());
        release.send(()).unwrap();
        closing.join().unwrap();
        assert_eq!(disk.snapshot().open_files, 0);
        assert!(!disk.lock_state().live.contains_key(&identity));
        disk.reconcile(&CensusCancellation::default()).unwrap();
        let current = disk.open_file("data", Path::new("file")).unwrap();
        assert_eq!(disk.snapshot().open_files, 1);
        drop(current);
        clean(&disk, &["file"]);
    }
}

#[test]
fn concurrent_final_file_clones_retire_exactly_one_registration() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    seed(&config, "file", 32 << 10);
    let disk = open(config, memory.clone());
    let original = disk.open_file("data", Path::new("file")).unwrap();
    let start = Arc::new(std::sync::Barrier::new(9));
    let mut closing = Vec::new();
    for _ in 0..8 {
        let file = original.clone();
        let start = start.clone();
        closing.push(std::thread::spawn(move || {
            start.wait();
            drop(file);
        }));
    }
    drop(original);
    let (entered, observed) = std::sync::mpsc::channel();
    let (release, resumed) = std::sync::mpsc::channel();
    *disk.after_file_close.lock().unwrap() = Some(file::ClosePause {
        stage: file::CloseStage::ResourcesClosed,
        entered,
        release: resumed,
    });
    start.wait();
    observed
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert_eq!(disk.snapshot().open_files, 1);
    assert_eq!(
        disk.open_file("data", Path::new("file"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    release.send(()).unwrap();
    for task in closing {
        task.join().unwrap();
    }
    assert_eq!(disk.snapshot().open_files, 0);
    assert!(disk.lock_state().live.is_empty());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    clean(&disk, &["file"]);
}

#[test]
fn reclaim_retires_parent_metadata_and_weak_backing_before_releasing_promises() {
    for fail in [false, true] {
        let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let (_directory, config) = installation();
        seed(&config, "file", 32 << 10);
        let disk = open(config, memory.clone());
        let file = disk.open_file("data", Path::new("file")).unwrap();
        file.reserve_growth(32 << 10, 64 << 10, DiskWork::Foreground)
            .unwrap();
        file.grow_reserved(64 << 10).unwrap();
        file.sync_all().unwrap();
        let before = disk.snapshot();
        if fail {
            disk.namespace_failure.store(
                file::NamespaceFailure::ReclaimParentSync as u8,
                Ordering::Relaxed,
            );
        }
        let (entered, observed) = std::sync::mpsc::channel();
        let (release, resumed) = std::sync::mpsc::channel();
        *disk.after_file_close.lock().unwrap() = Some(file::ClosePause {
            stage: file::CloseStage::ResourcesClosed,
            entered,
            release: resumed,
        });
        let owner = disk.clone();
        let closing = std::thread::spawn(move || owner.delete_file(file));
        observed
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        // Resources are gone, but the exact Weak allocation/registration and
        // device promises still belong to this serialized reclaim transition.
        assert!(disk.state.try_lock().is_err());
        assert_eq!(*disk.device.lock(), before.filesystem_pending_bytes);
        release.send(()).unwrap();
        let result = closing.join().unwrap();
        assert_eq!(result.is_err(), fail);
        let after = disk.snapshot();
        assert_eq!(after.open_files, 0);
        assert!(disk.lock_state().live.is_empty());
        if fail {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
            assert_eq!(after.phase, NodeDiskPhase::Failed);
            assert_eq!(after.charged_bytes, before.charged_bytes);
            assert_eq!(after.pending_bytes, before.pending_bytes);
        } else {
            assert_eq!(after.phase, NodeDiskPhase::Open);
            assert_eq!(after.charged_bytes, 0);
            assert_eq!(after.pending_bytes, 0);
        }
        disk.reconcile(&CensusCancellation::default()).unwrap();
    }
}

#[test]
fn prepared_publication_abandonment_retires_old_weak_registration_once_without_allocation() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    seed(&config, "file", 32 << 10);
    let disk = open(config.clone(), memory.clone());
    let file = disk.open_file("data", Path::new("file")).unwrap();
    let prepared = disk
        .prepare_publication(file, "data", Path::new("destination"))
        .unwrap();
    let ((), allocations) = crate::allocation_tests::measure(|| drop(prepared));
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().open_files, 0);
    assert!(disk.lock_state().live.is_empty());
    assert!(!config.roots["data"].join("destination").exists());
    let file = disk.open_file("data", Path::new("file")).unwrap();
    let prepared = disk
        .prepare_publication(file, "data", Path::new("destination"))
        .unwrap();
    let (result, allocations) = crate::allocation_tests::measure(|| prepared.execute());
    let published = result.unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().open_files, 1);
    drop(published);
    assert!(disk.lock_state().live.is_empty());
    clean(&disk, &["destination"]);
}

// Native stat fields differ in width between the supported Unix targets.
#[allow(clippy::unnecessary_cast)]
fn retired_descriptor_no_longer_names(fd: std::os::fd::RawFd, expected: Identity) {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } == 0 {
        // Parallel tests may reuse the integer after close. They cannot own our
        // unique private root, so an unrelated inode is also proof of retirement.
        assert_ne!(Identity(stat.st_dev as u64, stat.st_ino as u64), expected);
    } else {
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }
}

#[test]
fn abandoned_preparation_closes_target_descriptors_before_the_next_preparation() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config.clone(), memory.clone());
    let root_identity = disk.roots["data"].identity;
    let prepared = disk
        .prepare_file("data", Path::new("uncreated"), Some(DiskWork::Foreground))
        .unwrap();
    let parent = prepared.parent_descriptor();
    assert!(disk.state.try_lock().is_err());
    let ((), allocations) = crate::allocation_tests::measure(|| drop(prepared));
    assert_eq!(allocations, 0);
    retired_descriptor_no_longer_names(parent, root_identity);
    assert!(disk.state.try_lock().is_ok());
    assert!(!config.roots["data"].join("uncreated").exists());
    let file = disk
        .create_file("data", Path::new("created"), DiskWork::Foreground)
        .unwrap();
    let prepared = disk
        .prepare_publication(file, "data", Path::new("unpublished"))
        .unwrap();
    let parent = prepared.parent_descriptor();
    assert!(disk.state.try_lock().is_err());
    let ((), allocations) = crate::allocation_tests::measure(|| drop(prepared));
    assert_eq!(allocations, 0);
    retired_descriptor_no_longer_names(parent, root_identity);
    assert_eq!(disk.snapshot().open_files, 0);
    assert!(disk.lock_state().live.is_empty());
    assert!(!config.roots["data"].join("unpublished").exists());
    clean(&disk, &["created"]);
}
