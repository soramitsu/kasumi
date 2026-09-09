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
    let same = disk.open_file("data", Path::new("file")).unwrap();
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
