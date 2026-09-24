use super::super::{CensusCancellation, DirectoryPolicy, NodeDiskConfig};
use super::*;
use crate::test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry};
use std::{
    path::Path,
    sync::{Arc, atomic::Ordering},
};

fn fixture() -> (tempfile::TempDir, NodeDiskConfig, Arc<TestDiskMemory>) {
    let root = private_tempdir().unwrap();
    let mut config = NodeDisk::fixture_config(root.path().join("unused")).unwrap();
    config.directory_policy = DirectoryPolicy::new(1 << 20, 32_768).unwrap();
    (root, config, TestDiskMemory::new(256 << 20, 4096))
}
fn open(config: &NodeDiskConfig, memory: &Arc<TestDiskMemory>) -> Arc<NodeDisk> {
    retry_disk_registry(|| {
        NodeDisk::open_fixture(config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap()
}
fn entry(disk: &NodeDisk, path: &Path) -> AccountedDirectory {
    *disk.lock_state().accounted[&Identity::of(&path.metadata().unwrap())]
        .directory()
        .unwrap()
}
fn assert_physical_parents(disk: &NodeDisk, paths: &[(&Path, u64, u32)]) {
    let mut observed = 0;
    let mut charged = 0;
    let mut pending = 0;
    for (path, children, handles) in paths {
        let metadata = path.metadata().unwrap();
        let actual = census::directory_extent(&metadata).unwrap();
        let value = entry(disk, path);
        assert!(value.settled);
        assert_eq!(value.len, metadata.len());
        assert_eq!(value.children, *children);
        assert_eq!(value.live_handles, *handles);
        assert_eq!(
            value.bytes,
            disk.config.directory_policy.extent_bytes.max(actual)
        );
        assert_eq!(value.pending, value.bytes - actual);
        observed += actual;
        charged += value.bytes;
        pending += value.pending;
    }
    let state = disk.lock_state();
    let file_bytes: u64 = state
        .accounted
        .values()
        .filter_map(AccountedInode::file)
        .map(|v| v.bytes)
        .sum();
    let file_pending: u64 = state
        .accounted
        .values()
        .filter_map(AccountedInode::file)
        .map(|v| v.pending)
        .sum();
    assert_eq!(state.directory_bytes, observed);
    assert_eq!(state.bytes, charged + file_bytes);
    assert_eq!(state.pending, pending + file_pending);
    assert_eq!(*disk.device.lock(), state.pending);
}

#[test]
fn create_same_parent_publish_cross_parent_publish_and_unlink_settle_actual_parents() {
    let (root, mut config, memory) = fixture();
    let child = root.path().join("child");
    crate::private_files::create_directory(&child).unwrap();
    config.max_open_directories = 1;
    let disk = open(&config, &memory);
    let independent = disk.open_directory("fixture", Path::new("")).unwrap();
    let file = disk
        .create_file("fixture", Path::new("first"), DiskWork::Foreground)
        .unwrap();
    assert_physical_parents(&disk, &[(root.path(), 2, 2), (&child, 0, 0)]);
    independent.sync_all().unwrap();
    let file = disk
        .publish_file(file, "fixture", Path::new("second"))
        .unwrap();
    assert_physical_parents(&disk, &[(root.path(), 2, 2), (&child, 0, 0)]);
    let file = disk
        .publish_file(file, "fixture", Path::new("child/last"))
        .unwrap();
    assert_physical_parents(&disk, &[(root.path(), 1, 1), (&child, 1, 1)]);
    independent.sync_all().unwrap();
    assert_eq!(disk.snapshot().open_files, 1);
    assert_eq!(disk.snapshot().open_directories, 1);
    disk.delete_file(file).unwrap();
    assert_physical_parents(&disk, &[(root.path(), 1, 1), (&child, 0, 0)]);
    drop(independent);
    assert_physical_parents(&disk, &[(root.path(), 1, 0), (&child, 0, 0)]);
    disk.pause().unwrap();
}

#[test]
fn required_policy_and_entry_limit_reject_before_create_without_reducing_cleanup() {
    let (root, mut config, memory) = fixture();
    let mut missing = serde_json::to_value(&config).unwrap();
    missing.as_object_mut().unwrap().remove("directory_policy");
    assert!(serde_json::from_value::<NodeDiskConfig>(missing).is_err());
    for invalid in [
        DirectoryPolicy {
            extent_bytes: 0,
            max_entries: 1,
        },
        DirectoryPolicy {
            extent_bytes: 1,
            max_entries: 0,
        },
    ] {
        assert!(invalid.validate().is_err());
    }
    config.directory_policy.max_entries = 1;
    let disk = open(&config, &memory);
    let file = disk
        .create_file("fixture", Path::new("one"), DiskWork::Foreground)
        .unwrap();
    let before = disk.snapshot();
    assert_eq!(
        disk.create_file("fixture", Path::new("two"), DiskWork::Foreground)
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    assert!(!root.path().join("two").exists());
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    disk.delete_file(file).unwrap();
    assert_physical_parents(&disk, &[(root.path(), 0, 0)]);
}

#[test]
fn failed_parent_sync_retains_all_promises_and_an_unsettled_parent_until_census() {
    let (root, config, memory) = fixture();
    let disk = open(&config, &memory);
    let before = disk.snapshot();
    disk.namespace_failure.store(
        super::super::file::NamespaceFailure::CreateParentSync as u8,
        Ordering::Relaxed,
    );
    assert!(
        disk.create_file("fixture", Path::new("uncertain"), DiskWork::Foreground)
            .is_err()
    );
    assert!(root.path().join("uncertain").exists());
    assert!(!entry(&disk, root.path()).settled);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(entry(&disk, root.path()).live_handles, 0);
    assert!(disk.open_directory("fixture", Path::new("")).is_err());
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_physical_parents(&disk, &[(root.path(), 1, 0)]);
}

#[test]
fn file_custody_rejects_a_replaced_intermediate_ancestor_even_when_final_inode_survives() {
    let (root, config, memory) = fixture();
    for path in ["a", "a/b", "c"] {
        crate::private_files::create_directory(&root.path().join(path)).unwrap();
    }
    let disk = open(&config, &memory);
    let file = disk
        .create_file("fixture", Path::new("a/b/file"), DiskWork::Foreground)
        .unwrap();
    let original = Identity::of(&root.path().join("a/b").metadata().unwrap());
    let outside = private_tempdir().unwrap();
    std::fs::rename(root.path().join("a"), outside.path().join("swap")).unwrap();
    std::fs::rename(root.path().join("c"), root.path().join("a")).unwrap();
    std::fs::rename(outside.path().join("swap"), root.path().join("c")).unwrap();
    std::fs::rename(root.path().join("c/b"), root.path().join("a/b")).unwrap();
    assert_eq!(
        Identity::of(&root.path().join("a/b").metadata().unwrap()),
        original
    );
    assert!(file.sync_all().is_err());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    drop(file);
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(entry(&disk, &root.path().join("a/b")).live_handles, 0);
}
