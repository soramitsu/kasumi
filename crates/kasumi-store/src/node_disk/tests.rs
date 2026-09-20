use super::*;
use std::{
    os::unix::fs::{OpenOptionsExt, symlink},
    path::Path,
};

fn installation() -> (tempfile::TempDir, NodeDiskConfig) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("owned");
    crate::private_files::create_directory(&root).unwrap();
    let config = NodeDiskConfig {
        roots: BTreeMap::from([("data".into(), root)]),
        max_bytes: 16 << 20,
        maintenance_reserve_bytes: 1 << 20,
        min_free_bytes: 0,
        max_open_files: 16,
        max_census_entries: 10_000,
        max_depth: 32,
        max_name_bytes: 255,
    };
    (directory, config)
}

fn open(config: NodeDiskConfig) -> Arc<NodeDisk> {
    NodeDisk::open_inner(
        config,
        &CensusCancellation::default(),
        Some(DeviceDisk::isolated(0)),
    )
    .unwrap()
}

#[test]
fn retained_file_io_settlement_shrink_and_drop_do_not_allocate() {
    let (_directory, config) = installation();
    let mut relative = std::path::PathBuf::new();
    for name in ["a".repeat(200), "b".repeat(200), "c".repeat(200)] {
        relative.push(name);
        crate::private_files::create_directory(&config.roots["data"].join(&relative)).unwrap();
    }
    relative.push("file");
    let disk = open(config);
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
    let (_directory, config) = installation();
    let disk = open(config.clone());
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
    let (_directory, config) = installation();
    let disk = open(config);
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
    let (_directory, config) = installation();
    seed(&config, "one", 64 << 10);
    seed(&config, "two", 32 << 10);
    let disk = open(config.clone());
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
    let reopened = NodeDisk::open(config, &CensusCancellation::default()).unwrap();
    assert_eq!(Arc::as_ptr(&reopened), pointer);
    assert_eq!(reopened.snapshot().charged_bytes, before.charged_bytes);
    clean(&reopened, &["one", "two"]);
}

#[test]
fn dropped_unmaterialized_growth_is_retained_until_exclusive_reconciliation() {
    let (_directory, config) = installation();
    let disk = open(config.clone());
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
    let same = NodeDisk::open(config, &CensusCancellation::default()).unwrap();
    assert!(Arc::ptr_eq(&same, &disk));
    assert_eq!(same.snapshot().charged_bytes, charged.charged_bytes);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert!(disk.snapshot().filesystem_admission_ready);
    clean(&disk, &["pending"]);
}

#[test]
fn pause_seals_new_reservations_but_drains_reserved_io_and_retains_sparse_promises() {
    let (_directory, config) = installation();
    let disk = open(config);
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
    let (_directory, mut config) = installation();
    let root = File::open(&config.roots["data"]).unwrap();
    let (_, unit) = filesystem(&root).unwrap();
    config.max_bytes = 3 * unit;
    config.maintenance_reserve_bytes = unit;
    let disk = open(config.clone());
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
    let (_directory, config) = installation();
    seed(&config, "data", 128 << 10);
    let disk = open(config.clone());
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
    let (_directory, config) = installation();
    seed(&config, "data", 64 << 10);
    let disk = open(config.clone());
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
    let (_directory, config) = installation();
    for name in ["one", "two", "three"] {
        seed(&config, name, 32 << 10);
    }
    let cancel = CensusCancellation::default();
    cancel.cancel_at.store(5, Ordering::Relaxed);
    assert!(NodeDisk::open_inner(config.clone(), &cancel, Some(DeviceDisk::isolated(0))).is_err());
    let mut bounded = config.clone();
    bounded.max_census_entries = 2;
    assert!(
        NodeDisk::open_inner(
            bounded,
            &CensusCancellation::default(),
            Some(DeviceDisk::isolated(0))
        )
        .is_err()
    );
    let disk = open(config);
    assert_eq!(disk.snapshot().charged_bytes, 96 << 10);
    assert_eq!(disk.snapshot().persistent_files, 3);
    clean(&disk, &["one", "two", "three"]);
}

#[test]
fn symlinks_hardlinks_and_overlapping_roots_cannot_duplicate_census_charge() {
    let (_directory, config) = installation();
    seed(&config, "one", 32 << 10);
    let root = config.roots["data"].clone();
    std::fs::hard_link(root.join("one"), root.join("two")).unwrap();
    assert!(NodeDisk::open(config.clone(), &CensusCancellation::default()).is_err());
    std::fs::remove_file(root.join("two")).unwrap();
    symlink("one", root.join("two")).unwrap();
    assert!(NodeDisk::open(config.clone(), &CensusCancellation::default()).is_err());
    std::fs::remove_file(root.join("two")).unwrap();
    let nested = root.join("child");
    crate::private_files::create_directory(&nested).unwrap();
    let disk = open(config.clone());
    let mut child = config.clone();
    child.roots = BTreeMap::from([("nested".into(), nested)]);
    assert!(NodeDisk::open(child, &CensusCancellation::default()).is_err());
    let mut alias = config;
    alias.roots.insert("alias".into(), root.clone());
    assert!(NodeDisk::open(alias, &CensusCancellation::default()).is_err());
    clean(&disk, &["one"]);
}

#[test]
fn open_file_metadata_budget_is_bounded_and_close_returns_only_metadata_capacity() {
    let (_directory, mut config) = installation();
    seed(&config, "one", 32 << 10);
    seed(&config, "two", 32 << 10);
    config.max_open_files = 1;
    let disk = open(config);
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
    let (directory, config) = installation();
    let disk = open(config);
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
    let (directory, config) = installation();
    let disk = open(config);
    let scratch = crate::ScratchDisk::test_with_device(
        directory.path().join("scratch"),
        disk.device.share(0),
        16 << 20,
    );
    let file = disk
        .create_file("data", Path::new("file"), DiskWork::Foreground)
        .unwrap();
    let (scratch_file, mut charge) = scratch.file().unwrap();
    disk.device.poison();
    assert!(
        file.reserve_growth(0, disk.unit, DiskWork::Foreground)
            .is_err()
    );
    assert!(charge.grow(disk.unit).is_err());
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(scratch.snapshot().charged_bytes, 0);
    assert!(!scratch.snapshot().filesystem_admission_ready);
    drop(file);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert!(
        !disk.snapshot().filesystem_admission_ready,
        "owner census cannot cure shared poison"
    );
    assert!(charge.grow(disk.unit).is_err());
    drop(scratch_file);
    drop(charge);
    clean(&disk, &["file"]);
}

#[test]
fn a_closed_predecessor_cannot_unregister_the_new_owner_of_the_same_inode() {
    let (_directory, config) = installation();
    seed(&config, "file", 32 << 10);
    let disk = open(config);
    let old = disk.open_file("data", Path::new("file")).unwrap();
    let (entered, observation) = std::sync::mpsc::channel();
    let (release, resumed) = std::sync::mpsc::channel();
    *disk.after_file_close.lock().unwrap() = Some(file::ClosePause {
        entered,
        release: resumed,
    });
    let closing = std::thread::spawn(move || drop(old));
    observation
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let current = disk.open_file("data", Path::new("file")).unwrap();
    release.send(()).unwrap();
    closing.join().unwrap();
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
    let (directory, config) = installation();
    let disk = open(config);
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
    let (_directory, config) = installation();
    seed(&config, "data", 64 << 10);
    let disk = open(config);
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
    let (_directory, config) = installation();
    seed(&config, "data", 128 << 10);
    let disk = open(config);
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
    let (_directory, config) = installation();
    seed(&config, "data", 64 << 10);
    let disk = open(config);
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
    let (_directory, config) = installation();
    let path = config.roots["data"].join("data");
    seed(&config, "data", 128 << 10);
    seed(&config, "bystander", 32 << 10);
    let identity = crate::private_files::file_identity(&path).unwrap();
    let disk = open(config.clone());
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
    for failure in [
        file::ShrinkFailure::Truncate,
        file::ShrinkFailure::FileSync,
        file::ShrinkFailure::DirectorySync,
    ] {
        let (directory, config) = installation();
        seed(&config, "data", 128 << 10);
        let disk = open(config);
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
    let disk = open(config.clone());
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
    let (_directory, config) = installation();
    let path = config.roots["data"].join("node");
    let disk = open(config);
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
    for replace_parent in [false, true] {
        let (_directory, config) = installation();
        let root = config.roots["data"].clone();
        crate::private_files::create_directory(&root.join("parent")).unwrap();
        seed(&config, "parent/node", 8192);
        let disk = open(config.clone());
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
    let (_directory, config) = installation();
    let disk = open(config);
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
