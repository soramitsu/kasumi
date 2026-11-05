//! Roots on more than one filesystem. Unit tests cannot mount filesystems, so
//! fixture device numbers place roots that share one physical filesystem on
//! distinct accounted devices; each gets its own isolated promise ledger and
//! free-space observation, as a real second filesystem would.
use super::*;
use std::path::Path;

const DATA_DEVICE: u64 = 1;
const ARCHIVE_DEVICE: u64 = 2;

fn installation() -> (tempfile::TempDir, NodeDiskConfig) {
    let directory = crate::test_utils::private_tempdir().unwrap();
    let mut roots = BTreeMap::new();
    for name in ["data", "archive"] {
        let root = directory.path().join(name);
        crate::private_files::create_directory(&root).unwrap();
        roots.insert(name.to_owned(), root);
    }
    let config = NodeDiskConfig {
        native_storage: crate::test_utils::node_storage_config(),
        roots,
        max_bytes: 64 << 20,
        maintenance_reserve_bytes: 1 << 20,
        min_free_bytes: 1 << 20,
        max_open_files: 16,
        max_open_directories: 16,
        directory_policy: DirectoryPolicy::fixture(),
        file_allocation_policy: FileAllocationPolicy::new(0).unwrap(),
        max_persistent_files: 1_000,
        max_persistent_subdirectories: 1_000,
        census_work_per_step: 1_000,
        max_depth: 16,
        max_name_bytes: 255,
    };
    (directory, config)
}

fn devices() -> BTreeMap<String, u64> {
    BTreeMap::from([
        ("data".into(), DATA_DEVICE),
        ("archive".into(), ARCHIVE_DEVICE),
    ])
}

fn open(config: &NodeDiskConfig) -> Arc<NodeDisk> {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    crate::test_utils::retry_disk_registry(|| {
        NodeDisk::open_fixture_filesystems(config, memory.clone(), devices())
    })
    .unwrap()
}

/// This owner's promises on the filesystem holding `root`.
fn owned(disk: &NodeDisk, root: &str) -> u64 {
    disk.root_device(root).lock().owned()
}

/// Every owner's promises on the filesystem holding `root`.
fn shared(disk: &NodeDisk, root: &str) -> u64 {
    *disk.root_device(root).lock()
}

/// What a census of `root` promises, from the same extent rules: the unused
/// directory allowance of every directory and the unallocated part of every
/// regular file's ceiling.
fn census_promises(disk: &NodeDisk, root: &Path) -> u64 {
    let metadata = std::fs::symlink_metadata(root).unwrap();
    let observed = census::directory_extent(&metadata).unwrap();
    let mut pending = disk.config.directory_policy.extent_bytes.max(observed) - observed;
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
        if metadata.is_dir() {
            pending += census_promises(disk, &entry.path());
        } else {
            pending += file_extent(&metadata, disk.unit, disk.config.file_allocation_policy)
                .unwrap()
                .1;
        }
    }
    pending
}

fn write_file(path: &Path, bytes: usize) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    std::io::Write::write_all(&mut file, &vec![7; bytes]).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn each_filesystem_holds_the_census_promises_of_its_own_roots() {
    let (_directory, config) = installation();
    let archive = &config.roots["archive"];
    crate::private_files::create_directory(&archive.join("tenant-audit-archives")).unwrap();
    write_file(&archive.join("tenant-audit-archives/a.audit"), 10_000);
    write_file(&config.roots["data"].join("node.kv"), 3_000);
    let disk = open(&config);

    let snapshot = disk.snapshot();
    assert_eq!(snapshot.phase, NodeDiskPhase::Open);
    assert_eq!(snapshot.filesystems.len(), 2);
    let by_device = |device| {
        snapshot
            .filesystems
            .iter()
            .find(|filesystem| filesystem.device == device)
            .unwrap()
    };
    assert_eq!(by_device(DATA_DEVICE).roots, ["data"]);
    assert_eq!(by_device(ARCHIVE_DEVICE).roots, ["archive"]);
    assert_eq!(
        owned(&disk, "data"),
        census_promises(&disk, &config.roots["data"])
    );
    assert_eq!(owned(&disk, "archive"), census_promises(&disk, archive));
    assert_eq!(
        owned(&disk, "data") + owned(&disk, "archive"),
        snapshot.pending_bytes
    );
    assert_eq!(
        by_device(DATA_DEVICE).owner_pending_bytes,
        owned(&disk, "data")
    );
    assert_eq!(
        by_device(ARCHIVE_DEVICE).owner_pending_bytes,
        owned(&disk, "archive")
    );
    // One owner total, whichever filesystem holds the inode.
    assert_eq!(snapshot.persistent_files, 2);
    assert_eq!(snapshot.persistent_directories, 3);
    disk.pause().unwrap();
}

#[test]
fn every_reservation_is_charged_to_the_filesystem_of_its_root() {
    let (_directory, config) = installation();
    let disk = open(&config);
    let mut archive = disk
        .create_file("archive", Path::new("segment"), DiskWork::Maintenance)
        .unwrap();
    let mut data = disk
        .create_file("data", Path::new("node.kv"), DiskWork::Foreground)
        .unwrap();
    let (data_before, archive_before) = (owned(&disk, "data"), owned(&disk, "archive"));
    let charged = disk.snapshot().charged_bytes;

    archive
        .reserve_growth(0, 64 << 10, DiskWork::Maintenance)
        .unwrap();
    assert_eq!(owned(&disk, "archive"), archive_before + (64 << 10));
    assert_eq!(owned(&disk, "data"), data_before);
    data.reserve_growth(0, 16 << 10, DiskWork::Foreground)
        .unwrap();
    assert_eq!(owned(&disk, "data"), data_before + (16 << 10));
    assert_eq!(owned(&disk, "archive"), archive_before + (64 << 10));
    // Both charges count against the owner's single extent budget.
    assert_eq!(disk.snapshot().charged_bytes, charged + (80 << 10));

    // Materialized and settled growth retires promises on its own filesystem.
    archive.grow_reserved(64 << 10).unwrap();
    archive.write_all_at(&[3; 64 << 10], 0).unwrap();
    archive.sync_all().unwrap();
    archive.settle_growth(64 << 10).unwrap();
    assert_eq!(owned(&disk, "data"), data_before + (16 << 10));
    assert!(owned(&disk, "archive") < archive_before + (64 << 10));
    assert_eq!(
        owned(&disk, "data") + owned(&disk, "archive"),
        disk.snapshot().pending_bytes
    );
    // Unused growth returns to the filesystem it was promised on.
    data.settle_growth(0).unwrap();
    assert_eq!(owned(&disk, "data"), data_before);
    archive.close().unwrap();
    data.close().unwrap();
    disk.pause().unwrap();
}

#[test]
fn the_free_space_floor_is_enforced_per_filesystem() {
    let (_directory, config) = installation();
    let disk = open(&config);
    let mut archive = disk
        .create_file("archive", Path::new("segment"), DiskWork::Maintenance)
        .unwrap();
    let mut data = disk
        .create_file("data", Path::new("node.kv"), DiskWork::Foreground)
        .unwrap();
    let growth = 64 << 10;
    let required = |root| shared(&disk, root) + config.min_free_bytes + growth;

    // The archive filesystem lacks one byte; the data filesystem is ample.
    disk.set_root_available_for_test("archive", Some(required("archive") - 1));
    disk.set_root_available_for_test("data", Some(1 << 40));
    let before = disk.snapshot();
    assert_eq!(
        archive
            .reserve_growth(0, growth, DiskWork::Maintenance)
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    data.reserve_growth(0, growth, DiskWork::Foreground)
        .unwrap();

    // The tightest filesystem is what the scalar health fields report.
    let snapshot = disk.snapshot();
    assert_eq!(
        snapshot.filesystem_available_bytes,
        Some(required("archive") - 1)
    );
    assert_eq!(snapshot.filesystem_pending_bytes, shared(&disk, "archive"));
    assert!(snapshot.filesystem_admission_ready);

    // Exactly the floor admits; the other filesystem's shortage does not matter.
    disk.set_root_available_for_test("archive", Some(required("archive")));
    disk.set_root_available_for_test("data", Some(0));
    archive
        .reserve_growth(0, growth, DiskWork::Maintenance)
        .unwrap();
    assert_eq!(
        data.reserve_growth(0, 2 * growth, DiskWork::Foreground)
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    disk.set_root_available_for_test("data", None);
    disk.set_root_available_for_test("archive", None);
    archive.settle_growth(0).unwrap();
    data.settle_growth(0).unwrap();
    archive.close().unwrap();
    data.close().unwrap();
    disk.pause().unwrap();
}

#[test]
fn a_census_replaces_only_this_owners_contribution_on_each_filesystem() {
    let (_directory, config) = installation();
    let disk = open(&config);
    // Another registration on the archive filesystem keeps its own promises.
    let sibling = disk.root_device("archive").share(0);
    let base = *sibling.lock();
    sibling.lock().set_pending(base + 4096).unwrap();

    let mut file = disk
        .create_file("archive", Path::new("segment"), DiskWork::Maintenance)
        .unwrap();
    file.reserve_growth(0, 32 << 10, DiskWork::Maintenance)
        .unwrap();
    file.grow_reserved(32 << 10).unwrap();
    file.write_all_at(&[5; 32 << 10], 0).unwrap();
    file.settle_growth(32 << 10).unwrap();
    file.close().unwrap();
    disk.create_file("data", Path::new("node.kv"), DiskWork::Foreground)
        .unwrap()
        .close()
        .unwrap();

    disk.pause().unwrap();
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(
        owned(&disk, "data"),
        census_promises(&disk, &config.roots["data"])
    );
    assert_eq!(
        owned(&disk, "archive"),
        census_promises(&disk, &config.roots["archive"])
    );
    assert_eq!(shared(&disk, "archive"), owned(&disk, "archive") + 4096);
    assert_eq!(shared(&disk, "data"), owned(&disk, "data"));
    assert_eq!(sibling.lock().owned(), 4096);

    let current = *sibling.lock();
    sibling.lock().set_pending(current - 4096).unwrap();
    drop(sibling);
    disk.pause().unwrap();
}

#[test]
fn a_failure_fences_every_filesystem_until_a_drained_census() {
    let (_directory, config) = installation();
    let disk = open(&config);
    disk.fail();
    assert!(!disk.root_device("data").lock().admission_ready());
    assert!(!disk.root_device("archive").lock().admission_ready());
    assert!(!disk.snapshot().filesystem_admission_ready);
    assert!(
        disk.create_file("archive", Path::new("x"), DiskWork::Maintenance)
            .is_err()
    );
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert!(disk.root_device("data").lock().admission_ready());
    assert!(disk.root_device("archive").lock().admission_ready());
    assert!(disk.snapshot().filesystem_admission_ready);
    disk.pause().unwrap();
}

#[test]
fn publication_and_namespace_plans_never_cross_filesystems() {
    let (_directory, config) = installation();
    let disk = open(&config);
    let file = disk
        .create_file("data", Path::new("staged"), DiskWork::Foreground)
        .unwrap();
    file.sync_all().unwrap();
    let before = disk.snapshot();
    assert_eq!(
        disk.publish_file(file, "archive", Path::new("final"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::CrossesDevices
    );
    // Refused before any effect: nothing moved, nothing fenced or charged.
    let after = disk.snapshot();
    assert_eq!(after.phase, NodeDiskPhase::Open);
    assert_eq!(after.charged_bytes, before.charged_bytes);
    assert!(config.roots["data"].join("staged").is_file());
    assert!(!config.roots["archive"].join("final").exists());
    let reopened = disk.open_file("data", Path::new("staged")).unwrap();
    let published = disk
        .publish_file(reopened, "data", Path::new("final"))
        .unwrap();
    drop(published);

    let parts = [
        NamespacePart {
            root: "data",
            relative: Path::new("sessions"),
            kind: NamespacePartKind::Directory,
        },
        NamespacePart {
            root: "archive",
            relative: Path::new("objects"),
            kind: NamespacePartKind::Directory,
        },
    ];
    assert_eq!(
        disk.admit_namespace(&parts, DiskWork::Foreground)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::CrossesDevices
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().charged_bytes, after.charged_bytes);
    disk.pause().unwrap();
}

#[test]
fn roots_on_one_physical_filesystem_share_one_ledger() {
    let (_directory, config) = installation();
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let disk = crate::test_utils::retry_disk_registry(|| {
        NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap();
    let snapshot = disk.snapshot();
    assert!(snapshot.filesystems.is_empty(), "one filesystem");
    assert_eq!(disk.device().lock().owned(), snapshot.pending_bytes);
    assert_eq!(
        disk.root_filesystem("data").unwrap(),
        disk.root_filesystem("archive").unwrap()
    );
    disk.pause().unwrap();
}

#[test]
fn unsupported_root_layouts_name_the_roots_and_the_supported_layout() {
    let (directory, mut config) = installation();
    // A second filesystem mounted inside a root cannot be its own root.
    let nested = config.roots["data"].join("tenant-audit-archives");
    crate::private_files::create_directory(&nested).unwrap();
    config.roots.insert("archive".into(), nested.clone());
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let error = crate::test_utils::retry_disk_registry(|| {
        NodeDisk::open_fixture_filesystems(&config, memory.clone(), devices())
    })
    .err()
    .unwrap();
    let message = format!("{error:#}");
    assert!(message.contains(&nested.display().to_string()), "{message}");
    assert!(
        message.contains(&config.roots["data"].display().to_string()),
        "{message}"
    );
    assert!(message.contains("may not nest"), "{message}");
    assert!(message.contains("its own root"), "{message}");

    // More filesystems than one owner accounts.
    let mut config = installation().1;
    let mut devices = BTreeMap::new();
    config.roots.clear();
    for index in 0..=MAX_FILESYSTEMS as u64 {
        let root = directory.path().join(format!("root-{index}"));
        crate::private_files::create_directory(&root).unwrap();
        config.roots.insert(format!("root-{index}"), root);
        devices.insert(format!("root-{index}"), 100 + index);
    }
    let error = crate::test_utils::retry_disk_registry(|| {
        NodeDisk::open_fixture_filesystems(&config, memory.clone(), devices.clone())
    })
    .err()
    .unwrap();
    assert!(
        format!("{error:#}").contains("more than 8 filesystems"),
        "{error:#}"
    );
}

/// Roots on two real filesystems. Set `KASUMI_SECOND_FILESYSTEM` to a private
/// directory on another mounted filesystem than the temporary directory, and
/// run this test alone: it registers the real devices in this process.
#[test]
#[ignore = "needs KASUMI_SECOND_FILESYSTEM, a directory on a second mounted filesystem"]
fn roots_on_two_real_filesystems_keep_separate_ledgers() {
    use std::os::unix::fs::MetadataExt;
    let second = std::path::PathBuf::from(std::env::var_os("KASUMI_SECOND_FILESYSTEM").unwrap());
    let (_directory, mut config) = installation();
    let archive = tempfile::Builder::new()
        .prefix("kasumi-archive")
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir_in(second)
        .unwrap();
    config
        .roots
        .insert("archive".into(), archive.path().to_owned());
    let device = |root: &str| std::fs::metadata(&config.roots[root]).unwrap().dev();
    assert_ne!(device("data"), device("archive"), "one filesystem");
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let disk = NodeDisk::open(&config, memory, &CensusCancellation::default()).unwrap();

    let snapshot = disk.snapshot();
    assert_eq!(snapshot.filesystems.len(), 2);
    for root in ["data", "archive"] {
        let filesystem = snapshot
            .filesystems
            .iter()
            .find(|filesystem| filesystem.roots == [root])
            .unwrap();
        assert_eq!(filesystem.device, device(root));
        assert!(filesystem.available_bytes.is_some() && filesystem.total_bytes.is_some());
        assert!(filesystem.admission_ready);
    }
    assert_eq!(
        owned(&disk, "data") + owned(&disk, "archive"),
        snapshot.pending_bytes
    );
    let data_before = owned(&disk, "data");
    let file = disk
        .create_file("archive", Path::new("segment"), DiskWork::Maintenance)
        .unwrap();
    let archive_created = owned(&disk, "archive");
    file.reserve_growth(0, 64 << 10, DiskWork::Maintenance)
        .unwrap();
    assert_eq!(owned(&disk, "archive"), archive_created + (64 << 10));
    assert_eq!(owned(&disk, "data"), data_before);
    file.settle_growth(0).unwrap();
    assert_eq!(owned(&disk, "archive"), archive_created);
    file.sync_all().unwrap();
    // The kernel would refuse this rename; Kasumi refuses it first.
    assert_eq!(
        disk.publish_file(file, "data", Path::new("moved"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::CrossesDevices
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    disk.pause().unwrap();
}

/// Another filesystem mounted inside a root. Set `KASUMI_NESTED_MOUNT_ROOT` to
/// a private directory one of whose children is such a mount point.
#[test]
#[ignore = "needs KASUMI_NESTED_MOUNT_ROOT, a directory holding a mount point"]
fn a_mount_inside_a_root_is_refused_with_the_supported_layout() {
    let nested = std::path::PathBuf::from(std::env::var_os("KASUMI_NESTED_MOUNT_ROOT").unwrap());
    let (_directory, mut config) = installation();
    config.roots.insert("archive".into(), nested.clone());
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let error = NodeDisk::open(&config, memory, &CensusCancellation::default())
        .err()
        .unwrap();
    let message = format!("{error:#}");
    assert!(message.contains(&nested.display().to_string()), "{message}");
    assert!(message.contains("on another filesystem"), "{message}");
    assert!(message.contains("as its own root"), "{message}");
}

/// Each filesystem's headroom is exactly the margin its own floor check
/// compares a reservation in one of its roots with, and a refusal names the
/// filesystem whose floor refused. The scalar fields describe the tightest.
#[test]
fn each_filesystem_reports_its_own_floor_margin_and_refusal() {
    let (_directory, config) = installation();
    let disk = open(&config);
    let data = disk.open_directory("data", Path::new("")).unwrap();
    let archive = disk.open_directory("archive", Path::new("")).unwrap();
    let min_free = config.min_free_bytes;
    for (data_margin, archive_margin) in [(4096u64, 1 << 20), (1 << 20, 4096), (0, 0)] {
        disk.set_root_available_for_test(
            "data",
            Some(shared(&disk, "data") + min_free + data_margin),
        );
        disk.set_root_available_for_test(
            "archive",
            Some(shared(&disk, "archive") + min_free + archive_margin),
        );
        let snapshot = disk.snapshot();
        let by_device = |device| {
            snapshot
                .filesystems
                .iter()
                .find(|filesystem| filesystem.device == device)
                .unwrap()
        };
        for (device, margin) in [(DATA_DEVICE, data_margin), (ARCHIVE_DEVICE, archive_margin)] {
            let filesystem = by_device(device);
            assert_eq!(filesystem.headroom_bytes, Some(margin as i64));
            assert_eq!(
                filesystem.headroom_bytes,
                filesystem.available_bytes.map(|available| {
                    available as i64
                        - filesystem.pending_bytes as i64
                        - filesystem.min_free_bytes as i64
                })
            );
        }
        let least = data_margin.min(archive_margin);
        assert_eq!(snapshot.filesystem_headroom_bytes, Some(least as i64));
        if data_margin != archive_margin {
            let tightest = if data_margin < archive_margin {
                DATA_DEVICE
            } else {
                ARCHIVE_DEVICE
            };
            assert_eq!(snapshot.filesystem_device, tightest);
        }
        // Each root's floor admits its own margin and refuses one byte more,
        // naming that filesystem; the other filesystem is untouched.
        for (directory, device, margin) in [
            (&data, DATA_DEVICE, data_margin),
            (&archive, ARCHIVE_DEVICE, archive_margin),
        ] {
            let parent = directory.verified_identity().unwrap();
            match disk.reserve_transaction_space(parent, margin + 1, 0, 1, 0, DiskWork::Foreground)
            {
                Err(ReserveError::Capacity(refusal)) => {
                    assert_eq!(refusal.check, CapacityCheck::PersistentFilesystemFloor);
                    assert_eq!(refusal.filesystem, Some(device));
                    assert_eq!(refusal.headroom(), i128::from(margin));
                    assert!(
                        refusal
                            .to_string()
                            .contains(&format!("filesystem={device} ")),
                        "{refusal}"
                    );
                }
                other => panic!("margin + 1 was not refused: {:?}", other.err()),
            }
            let mut claim = disk
                .reserve_transaction_space(parent, margin, 0, 1, 0, DiskWork::Foreground)
                .unwrap();
            let held = disk.snapshot();
            let filesystem = held
                .filesystems
                .iter()
                .find(|filesystem| filesystem.device == device)
                .unwrap();
            assert_eq!(filesystem.headroom_bytes, Some(0));
            claim.cancel().unwrap();
        }
    }
    disk.set_root_available_for_test("data", None);
    disk.set_root_available_for_test("archive", None);
    drop((data, archive));
    disk.pause().unwrap();
}
