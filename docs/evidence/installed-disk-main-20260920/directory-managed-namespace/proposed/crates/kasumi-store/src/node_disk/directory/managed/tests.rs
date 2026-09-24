use super::*;
use crate::test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry};
use crate::{CensusCancellation, NodeDiskConfig};
use std::{os::unix::fs::MetadataExt, path::Path};

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
fn root(disk: &Arc<NodeDisk>) -> NodeDiskDirectory {
    disk.open_directory("fixture", Path::new("")).unwrap()
}

#[test]
fn managed_child_creation_open_and_removal_preserve_exact_enrollment_and_charge() {
    let (directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let parent = root(&disk);
    let before = disk.snapshot();
    let child = parent.create_child(c"child", DiskWork::Foreground).unwrap();
    let identity = Identity::of(&directory.path().join("child").metadata().unwrap());
    assert_eq!(child.owner().identity, identity);
    let child_entry = *disk.lock_state().accounted[&identity].directory().unwrap();
    assert_eq!(child_entry.bytes, config.directory_policy.extent_bytes);
    assert_eq!(child_entry.children, 0);
    assert_eq!(child_entry.live_handles, 1);
    assert!(child_entry.settled);
    assert_eq!(
        disk.snapshot().charged_bytes,
        before.charged_bytes + child_entry.bytes
    );
    assert_eq!(
        disk.snapshot().persistent_directories,
        before.persistent_directories + 1
    );
    assert_eq!(disk.snapshot().open_directories, 2);
    let second = parent.open_child(c"child").unwrap();
    assert_eq!(second.owner().identity, identity);
    assert_eq!(
        disk.lock_state().accounted[&identity]
            .directory()
            .unwrap()
            .live_handles,
        2
    );
    assert_eq!(
        second.remove_if_empty().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(directory.path().join("child").exists());
    child.remove_if_empty().unwrap();
    assert!(!directory.path().join("child").exists());
    assert!(!disk.lock_state().accounted.contains_key(&identity));
    assert_eq!(
        disk.snapshot().persistent_directories,
        before.persistent_directories
    );
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().open_directories, 1);
    assert!(disk.pending_directory_operation().is_none());
    parent.sync_all().unwrap();
    drop(parent);
    disk.reconcile(&CensusCancellation::default()).unwrap();
}

#[test]
fn managed_directory_cardinality_and_owner_capacity_deny_before_allocations_or_effects() {
    for owner_limit in [false, true] {
        let (directory, mut config, memory) = fixture();
        if owner_limit {
            config.max_open_directories = 1;
        } else {
            config.max_persistent_subdirectories = 0;
        }
        let disk = open(&config, &memory);
        let parent = root(&disk);
        let before = disk.snapshot();
        let (result, allocations) = crate::allocation_tests::measure(|| {
            parent.create_child(c"denied", DiskWork::Foreground)
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::StorageFull);
        assert_eq!(allocations, 0);
        assert!(!directory.path().join("denied").exists());
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
        assert!(disk.pending_directory_operation().is_none());
    }
}

#[test]
fn managed_child_names_depth_existing_identity_and_root_removal_are_exact() {
    let (directory, mut config, memory) = fixture();
    config.max_depth = u32::try_from(directory.path().components().count()).unwrap();
    let disk = open(&config, &memory);
    let parent = root(&disk);
    for name in [c"", c".", c"..", c"a/b"] {
        assert_eq!(
            parent
                .create_child(name, DiskWork::Foreground)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    let child = parent.create_child(c"child", DiskWork::Foreground).unwrap();
    let inode = directory.path().join("child").metadata().unwrap().ino();
    assert_eq!(
        parent
            .create_child(c"child", DiskWork::Foreground)
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    let mut chain = vec![child];
    for _ in 2..config.max_depth {
        let next = chain
            .last()
            .unwrap()
            .create_child(c"level", DiskWork::Foreground)
            .unwrap();
        chain.push(next);
    }
    assert_eq!(
        chain
            .last()
            .unwrap()
            .create_child(c"too-deep", DiskWork::Foreground)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        parent.remove_if_empty().unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        directory.path().join("child").metadata().unwrap().ino(),
        inode
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    while let Some(child) = chain.pop() {
        child.remove_if_empty().unwrap();
    }
}

#[test]
fn retained_child_parent_prevents_removal_with_live_descendant_custody() {
    let (directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let parent = root(&disk);
    let child = parent.create_child(c"child", DiskWork::Foreground).unwrap();
    let grandchild = child
        .create_child(c"grandchild", DiskWork::Foreground)
        .unwrap();
    assert_eq!(
        child.remove_if_empty().unwrap_err().kind(),
        io::ErrorKind::DirectoryNotEmpty
    );
    grandchild.remove_if_empty().unwrap();
    let child = parent.open_child(c"child").unwrap();
    let alias = child.clone();
    assert_eq!(
        child.remove_if_empty().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(directory.path().join("child").exists());
    alias.remove_if_empty().unwrap();
}

#[test]
fn post_mkdir_error_retains_original_failure_and_allows_only_complete_census_resolution() {
    let (directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let parent = root(&disk);
    let before = disk.snapshot();
    FAILURE.with(|failure| failure.set(Some(NodeDiskDirectoryOperationStep::OpenChild)));
    assert_eq!(
        parent
            .create_child(c"uncertain", DiskWork::Foreground)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EIO)
    );
    assert!(directory.path().join("uncertain").is_dir());
    let observed = disk.pending_directory_operation().unwrap();
    assert_eq!(observed.kind, NodeDiskDirectoryOperationKind::Create);
    assert_eq!(
        observed.failure.unwrap().step,
        NodeDiskDirectoryOperationStep::OpenChild
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(
        disk.snapshot().charged_bytes,
        before.charged_bytes + config.directory_policy.extent_bytes
    );
    assert_eq!(disk.snapshot().open_directories, 2);
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    drop(parent);
    let cancelled = CensusCancellation::default();
    cancelled.cancel();
    assert!(disk.reconcile(&cancelled).is_err());
    assert_eq!(disk.pending_directory_operation().unwrap(), observed);
    assert_eq!(disk.snapshot().open_directories, 1);
    assert_eq!(
        disk.snapshot().charged_bytes,
        before.charged_bytes + config.directory_policy.extent_bytes
    );
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert!(disk.pending_directory_operation().is_none());
    assert_eq!(disk.snapshot().open_directories, 0);
    assert_eq!(
        disk.snapshot().persistent_directories,
        before.persistent_directories + 1
    );
    root(&disk)
        .open_child(c"uncertain")
        .unwrap()
        .sync_all()
        .unwrap();
}

#[test]
fn post_unlink_error_holds_actual_child_descriptor_and_extent_until_census() {
    let (directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let parent = root(&disk);
    let child = parent.create_child(c"child", DiskWork::Foreground).unwrap();
    let fd = child.owner().file.as_ref().unwrap().as_raw_fd();
    let charged = disk.snapshot().charged_bytes;
    FAILURE.with(|failure| failure.set(Some(NodeDiskDirectoryOperationStep::SyncParent)));
    assert_eq!(
        child.remove_if_empty().unwrap_err().raw_os_error(),
        Some(libc::EIO)
    );
    assert!(!directory.path().join("child").exists());
    assert_ne!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) },
        -1,
        "unlinked FD still actually retained"
    );
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert_eq!(disk.snapshot().open_directories, 2);
    let diagnostic = disk.pending_directory_operation().unwrap();
    assert_eq!(diagnostic.kind, NodeDiskDirectoryOperationKind::Remove);
    assert_eq!(
        diagnostic.failure.unwrap().step,
        NodeDiskDirectoryOperationStep::SyncParent
    );
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    drop(parent);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().persistent_directories, 1);
    assert_eq!(disk.snapshot().open_directories, 0);
    assert_eq!(
        disk.snapshot().charged_bytes,
        config.directory_policy.extent_bytes
    );
    assert!(disk.pending_directory_operation().is_none());
}

#[test]
fn uncertain_native_close_is_sticky_and_preserves_primary_error_and_custody() {
    let (_directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let parent = root(&disk);
    let child = parent.create_child(c"child", DiskWork::Foreground).unwrap();
    FAILURE.with(|failure| failure.set(Some(NodeDiskDirectoryOperationStep::SyncParent)));
    child.remove_if_empty().unwrap_err();
    drop(parent);
    let first = disk.pending_directory_operation().unwrap().failure;
    FAILURE.with(|failure| failure.set(Some(NodeDiskDirectoryOperationStep::CloseChild)));
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    let both = disk.pending_directory_operation().unwrap();
    assert_eq!(both.failure, first);
    assert_eq!(
        both.close_failure.unwrap().step,
        NodeDiskDirectoryOperationStep::CloseChild
    );
    assert!(both.uncertain_close_descriptor.is_some());
    let charged = disk.snapshot().charged_bytes;
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    assert_eq!(disk.pending_directory_operation().unwrap(), both);
    assert_eq!(disk.snapshot().open_directories, 1);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
}

#[test]
fn unknown_child_absence_retires_prepared_backing_and_descriptors_before_slot_reuse() {
    let (_directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let parent = root(&disk);
    let before = disk.snapshot();
    assert_eq!(
        parent.open_child(c"missing").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().open_directories, before.open_directories);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert!(disk.pending_directory_operation().is_none());
    parent
        .create_child(c"after-missing", DiskWork::Foreground)
        .unwrap()
        .remove_if_empty()
        .unwrap();
}

#[test]
fn preflight_ancestry_close_failure_keeps_new_descriptor_custody_before_mkdir() {
    let (directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let parent = root(&disk);
    let child = parent.create_child(c"child", DiskWork::Foreground).unwrap();
    // The child parent walk must close its real temporary descriptor. Inject
    // an uncertain result after that one actual close; no mkdir may occur.
    FAILURE.with(|failure| failure.set(Some(NodeDiskDirectoryOperationStep::Verify)));
    assert_eq!(
        child
            .create_child(c"uncreated", DiskWork::Foreground)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EIO)
    );
    assert!(!directory.path().join("child/uncreated").exists());
    let observed = disk.pending_directory_operation().unwrap();
    assert_eq!(observed.step, NodeDiskDirectoryOperationStep::Prepared);
    assert_eq!(
        observed.close_failure.unwrap().step,
        NodeDiskDirectoryOperationStep::Verify
    );
    assert_eq!(disk.snapshot().open_directories, 3);
    drop(child);
    drop(parent);
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    assert_eq!(disk.snapshot().open_directories, 1);
    assert_eq!(disk.pending_directory_operation().unwrap(), observed);
}

#[test]
fn census_retires_actual_prepared_arc_backing_before_reopening_slot_admission() {
    use crate::allocation_tests::{DeallocationObservation, observe_deallocation};
    let (_directory, config, memory) = fixture();
    let disk = open(&config, &memory);
    let parent = root(&disk);
    FAILURE.with(|failure| failure.set(Some(NodeDiskDirectoryOperationStep::OpenChild)));
    parent
        .create_child(c"pending", DiskWork::Foreground)
        .unwrap_err();
    drop(parent);
    let (layout, offset) = std::alloc::Layout::new::<[usize; 2]>()
        .extend(std::alloc::Layout::new::<MaybeUninit<DirectoryOwner>>())
        .unwrap();
    let address = {
        let state = disk.lock_state();
        let owner = state
            .pending_directory
            .as_ref()
            .unwrap()
            .allocation
            .as_ref()
            .unwrap();
        // Pinned std ArcInner has the same repr(C) header validated by census.
        (unsafe { Arc::as_ptr(owner).cast::<u8>().sub(offset) }) as usize
    };
    let observed = Arc::new(DeallocationObservation::new(true));
    let runner = {
        let disk = disk.clone();
        let observed = observed.clone();
        std::thread::spawn(move || {
            observe_deallocation(address as *const (), &observed, || {
                disk.reconcile(&CensusCancellation::default())
            })
        })
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !observed.entered() {
        assert!(
            std::time::Instant::now() < deadline,
            "actual prepared Arc never reached deallocation"
        );
        std::thread::yield_now();
    }
    assert!(!observed.finished());
    assert!(
        matches!(
            disk.state.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ),
        "admission cannot inspect or reuse the slot before actual backing retires"
    );
    observed.release();
    runner.join().unwrap().unwrap();
    assert!(observed.finished());
    assert_eq!(observed.count(), 1);
    assert_eq!(observed.bytes(), layout.pad_to_align().size());
    assert_eq!(disk.snapshot().open_directories, 0);
    assert!(disk.pending_directory_operation().is_none());
}
