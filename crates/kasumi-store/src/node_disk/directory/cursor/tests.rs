use super::super::super::{DiskWork, NodeDiskConfig};
use super::*;
use crate::test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry};
use std::{os::fd::AsRawFd, path::Path};
fn fixture() -> (tempfile::TempDir, NodeDiskConfig, Arc<TestDiskMemory>) {
    let root = private_tempdir().unwrap();
    let config = NodeDisk::fixture_config(root.path().join("anchor")).unwrap();
    (root, config, TestDiskMemory::new(256 << 20, 4096))
}
fn open(config: &NodeDiskConfig, memory: &Arc<TestDiskMemory>) -> Arc<NodeDisk> {
    retry_disk_registry(|| {
        NodeDisk::open_fixture(config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap()
}
fn cursor(disk: &Arc<NodeDisk>) -> NodeDiskDirectoryCursor {
    disk.open_directory("fixture", Path::new(""))
        .unwrap()
        .cursor(&CensusCancellation::default())
        .unwrap()
}
#[test]
fn repeated_independent_streams_borrow_bounded_names_and_retire_without_allocating() {
    let (root, config, memory) = fixture();
    crate::private_files::create_directory(&root.path().join("nested")).unwrap();
    let disk = open(&config, &memory);
    for name in ["one", "two"] {
        drop(
            disk.create_file("fixture", Path::new(name), DiskWork::Foreground)
                .unwrap(),
        );
    }
    let cancel = CensusCancellation::default();
    for _ in 0..3 {
        let mut cursor = cursor(&disk);
        assert_eq!(disk.snapshot().open_directory_cursors, 1);
        let (result, allocations) = crate::allocation_tests::measure(|| -> io::Result<u8> {
            let mut seen = 0u8;
            while let Some(entry) = cursor.next(&cancel)? {
                let (bit, kind) = match entry.name().to_bytes() {
                    b"one" => (1, NodeDiskEntryKind::File),
                    b"two" => (2, NodeDiskEntryKind::File),
                    b"nested" => (4, NodeDiskEntryKind::Directory),
                    _ => panic!("unexpected enrolled entry"),
                };
                assert_eq!(seen & bit, 0, "duplicate native entry");
                assert_eq!(entry.kind(), kind);
                seen |= bit;
            }
            Ok(seen)
        });
        assert_eq!(result.unwrap(), 7);
        assert_eq!(allocations, 0);
        assert_eq!(disk.snapshot().open_directory_cursors, 0);
        assert_eq!(disk.snapshot().open_directories, 1);
        let ((), allocations) = crate::allocation_tests::measure(|| drop(cursor));
        assert_eq!(allocations, 0);
        assert_eq!(disk.snapshot().open_directories, 0);
    }
}
#[test]
fn alias_denial_and_cancellation_preserve_exact_cursor_and_directory_lifetimes() {
    let (_root, config, memory) = fixture();
    let disk = open(&config, &memory);
    let directory = disk.open_directory("fixture", Path::new("")).unwrap();
    let alias = directory.clone();
    assert_eq!(
        directory
            .cursor(&CensusCancellation::default())
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(disk.snapshot().open_directory_cursors, 0);
    assert_eq!(disk.snapshot().open_directories, 1);
    drop(alias);
    let cancel = CensusCancellation::default();
    cancel.cancel();
    assert_eq!(
        disk.open_directory("fixture", Path::new(""))
            .unwrap()
            .cursor(&cancel)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(disk.snapshot().open_directories, 0);
    let mut reading = cursor(&disk);
    assert_eq!(
        reading.next(&cancel).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(
        reading
            .next(&CensusCancellation::default())
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(disk.snapshot().open_directory_cursors, 0);
    assert_eq!(disk.snapshot().open_directories, 1);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    drop(reading);
    assert_eq!(disk.snapshot().open_directories, 0);
}
#[test]
fn managed_same_extent_rename_invalidates_scan_without_fencing_healthy_storage() {
    let (root, config, memory) = fixture();
    let disk = open(&config, &memory);
    let file = disk
        .create_file("fixture", Path::new("one"), DiskWork::Foreground)
        .unwrap();
    let before = root.path().metadata().unwrap();
    let mut reading = cursor(&disk);
    let file = disk
        .publish_file(file, "fixture", Path::new("two"))
        .unwrap();
    let after = root.path().metadata().unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        (before.len(), before.blocks()),
        (after.len(), after.blocks()),
        "fixture must preserve the old extent observation"
    );
    assert_eq!(
        reading
            .next(&CensusCancellation::default())
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(
        reading
            .next(&CensusCancellation::default())
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    drop(reading);
    disk.delete_file(file).unwrap();
}
#[test]
fn configured_name_boundary_is_read_without_truncation_or_native_name_copy() {
    let (_root, config, memory) = fixture();
    let disk = open(&config, &memory);
    let name = "n".repeat(config.max_name_bytes as usize);
    let file = disk
        .create_file("fixture", Path::new(&name), DiskWork::Foreground)
        .unwrap();
    let mut reading = cursor(&disk);
    assert_eq!(
        reading
            .next(&CensusCancellation::default())
            .unwrap()
            .unwrap()
            .name()
            .to_bytes(),
        name.as_bytes()
    );
    assert!(
        reading
            .next(&CensusCancellation::default())
            .unwrap()
            .is_none()
    );
    drop(reading);
    disk.delete_file(file).unwrap();
}
#[test]
fn census_workspace_cursor_limit_does_not_reduce_independent_directory_handle_limit() {
    let (_root, mut config, memory) = fixture();
    config.max_open_directories = config.max_depth + 1;
    let disk = open(&config, &memory);
    let mut readers = Vec::new();
    for _ in 0..config.max_depth {
        readers.push(cursor(&disk));
    }
    let independent = disk.open_directory("fixture", Path::new("")).unwrap();
    independent.sync_all().unwrap();
    assert_eq!(
        independent
            .cursor(&CensusCancellation::default())
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(disk.snapshot().open_directory_cursors, config.max_depth);
    assert_eq!(disk.snapshot().open_directories, config.max_depth);
    assert!(disk.pause().is_err());
    drop(readers);
    assert_eq!(disk.snapshot().open_directory_cursors, 0);
    assert_eq!(disk.snapshot().open_directories, 0);
    disk.reconcile(&CensusCancellation::default()).unwrap();
}
#[test]
fn an_unenrolled_actual_entry_fences_and_failed_cursor_cannot_report_later_eof() {
    let (root, config, memory) = fixture();
    let disk = open(&config, &memory);
    let mut reading = cursor(&disk);
    crate::private_files::create(&root.path().join("foreign"), b"").unwrap();
    let error = reading
        .next(&CensusCancellation::default())
        .unwrap_err()
        .kind();
    assert_eq!(error, io::ErrorKind::InvalidData);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(
        reading
            .next(&CensusCancellation::default())
            .unwrap_err()
            .kind(),
        error
    );
    drop(reading);
    assert_eq!(disk.snapshot().open_directory_cursors, 0);
    assert_eq!(disk.snapshot().open_directories, 0);
    disk.reconcile(&CensusCancellation::default()).unwrap();
}
fn fd_names_inode(fd: i32, identity: Identity) -> bool {
    let mut result = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, result.as_mut_ptr()) } != 0 {
        return false;
    }
    let result = unsafe { result.assume_init() };
    (result.st_dev as u64, result.st_ino) == (identity.0, identity.1)
}
#[test]
fn stream_fd_and_buffer_close_before_cursor_credit_and_before_directory_owner_drain() {
    let (_root, config, memory) = fixture();
    let disk = open(&config, &memory);
    let (facts_tx, facts) = std::sync::mpsc::sync_channel(0);
    let (entered_tx, entered) = std::sync::mpsc::sync_channel(0);
    let (release, release_rx) = std::sync::mpsc::channel();
    let worker_disk = disk.clone();
    let worker = std::thread::spawn(move || {
        let mut reading = cursor(&worker_disk);
        let parent = reading.directory.as_ref().unwrap().owner();
        let parent_fd = parent.file.as_ref().unwrap().as_raw_fd();
        let identity = parent.identity;
        let stream = reading.stream.as_mut().unwrap();
        let stream_fd = unsafe { libc::dirfd(stream.pointer.unwrap().as_ptr()) };
        stream.after_close = Some(ClosePause {
            entered: entered_tx,
            release: release_rx,
        });
        facts_tx.send((stream_fd, parent_fd, identity)).unwrap();
        drop(reading);
    });
    let (stream_fd, parent_fd, identity) = facts
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    entered
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert_ne!(stream_fd, parent_fd);
    assert!(
        !fd_names_inode(stream_fd, identity),
        "actual stream fd still retains its directory"
    );
    assert!(
        fd_names_inode(parent_fd, identity),
        "directory custody ended before stream retirement"
    );
    assert_eq!(disk.snapshot().open_directory_cursors, 1);
    assert_eq!(disk.snapshot().open_directories, 1);
    assert!(disk.pause().is_err());
    release.send(()).unwrap();
    worker.join().unwrap();
    assert_eq!(disk.snapshot().open_directory_cursors, 0);
    assert_eq!(disk.snapshot().open_directories, 0);
    disk.reconcile(&CensusCancellation::default()).unwrap();
}

#[test]
fn uncertain_stream_close_retains_the_actual_installed_owner_after_all_external_arcs_drop() {
    let (_root, config, memory) = fixture();
    let disk = open(&config, &memory);
    let retained = Arc::downgrade(&disk);
    let mut reading = cursor(&disk);
    // Actual closedir still runs. The injected uncertain return exercises the
    // custody path without invoking closedir on an invalid pointer.
    reading.stream.as_mut().unwrap().force_close_error = true;
    assert_eq!(
        reading
            .next(&CensusCancellation::default())
            .unwrap_err()
            .kind(),
        io::ErrorKind::Other
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().open_directory_cursors, 1);
    drop(reading);
    assert_eq!(disk.snapshot().open_directories, 0);
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    let charged = memory.snapshot();
    drop(disk);
    let retained = retained
        .upgrade()
        .expect("uncertain stream must retain installed owner");
    assert_eq!(retained.snapshot().open_directory_cursors, 1);
    assert_eq!(memory.snapshot(), charged);
    assert!(charged.used_bytes > 0 && charged.live_reservations > 0);
}

#[test]
fn same_length_raw_sparse_materialization_rejects_changed_settled_extent() {
    use std::os::unix::fs::{FileExt, MetadataExt};
    let (root, config, memory) = fixture();
    let path = root.path().join("sparse");
    crate::private_files::create(&path, b"").unwrap();
    let raw = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    raw.set_len(8 << 20).unwrap();
    raw.sync_all().unwrap();
    let disk = open(&config, &memory);
    let mut reading = cursor(&disk);
    let before = raw.metadata().unwrap();
    raw.write_at(b"materialized", 4 << 20).unwrap();
    raw.sync_all().unwrap();
    let after = raw.metadata().unwrap();
    assert_eq!(before.len(), after.len());
    assert_ne!(
        before.blocks(),
        after.blocks(),
        "fixture must actually change allocated extent at stable EOF"
    );
    assert_eq!(
        reading
            .next(&CensusCancellation::default())
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    drop(reading);
    drop(raw);
    disk.reconcile(&CensusCancellation::default()).unwrap();
}
#[test]
fn cancellation_preserves_independent_close_error_and_explicit_close_cannot_report_success() {
    let (_root, config, memory) = fixture();
    let disk = open(&config, &memory);
    let mut reading = cursor(&disk);
    reading.stream.as_mut().unwrap().force_close_error = true;
    let cancel = CensusCancellation::default();
    cancel.cancel();
    assert_eq!(
        reading.next(&cancel).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(
        reading.close_error(),
        Some(NodeDiskDirectoryCloseError {
            kind: io::ErrorKind::Other,
            raw_os_error: None
        })
    );
    assert_eq!(reading.close().unwrap_err().kind(), io::ErrorKind::Other);
    assert_eq!(
        reading
            .next(&CensusCancellation::default())
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().open_directory_cursors, 1);
}

#[test]
fn explicit_failed_partial_page_close_cannot_advertise_later_eof() {
    let (_root, config, memory) = fixture();
    let disk = open(&config, &memory);
    drop(
        disk.create_file("fixture", Path::new("one"), DiskWork::Foreground)
            .unwrap(),
    );
    let mut reading = cursor(&disk);
    assert_eq!(
        reading
            .next(&CensusCancellation::default())
            .unwrap()
            .unwrap()
            .name()
            .to_bytes(),
        b"one"
    );
    reading.stream.as_mut().unwrap().force_close_error = true;
    assert_eq!(reading.close().unwrap_err().kind(), io::ErrorKind::Other);
    assert_eq!(
        reading
            .next(&CensusCancellation::default())
            .unwrap_err()
            .kind(),
        io::ErrorKind::Other
    );
    assert_eq!(reading.close().unwrap_err().kind(), io::ErrorKind::Other);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
}
