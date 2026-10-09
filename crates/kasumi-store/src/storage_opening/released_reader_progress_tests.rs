use super::*;
use crate::{
    NodeStore, ScratchDisk,
    test_utils::{NODE_STORE_ID, TestDiskMemory, private_tempdir, retry_disk_registry},
};
use std::time::{Duration, Instant};

#[tokio::test]
async fn dropped_view_reader_is_revisited_by_normal_next_read_after_metadata_contention() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("released-reader-admission.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(
        &path,
        NODE_STORE_ID,
        disk,
        scratch,
        crate::test_utils::node_storage_config(),
    )
    .unwrap();

    let reader = node.begin_registered_read().unwrap();
    assert!(reader.catalog_bytes([41; 32], 64).unwrap().is_none());
    assert_eq!(reader.finish(), NodeReadPhase::Finished);
    let id = reader.id();
    // Keep a different, actually finished reader facade alive. The normal
    // admission sweep must not retire it while revisiting the detached one.
    let live = node.begin_registered_read().unwrap();
    assert_eq!(live.finish(), NodeReadPhase::Finished);
    let live_id = live.id();
    let worker_node = node.clone();
    let (start, started) = std::sync::mpsc::sync_channel(0);
    let (done, completed) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        started.recv().unwrap();
        crate::read_view::ViewTransaction::Registered(reader).close_on_drop(&worker_node);
        done.send(()).unwrap();
    });
    // Hold the actual reader's census metadata through the real view Drop
    // cleanup. Its return before release distinguishes nonblocking cleanup
    // from the explicit five-second retirement budget.
    let returned = memory
        .storage_census()
        .with_owner_metadata_held_for_test(id, || {
            start.send(()).unwrap();
            completed.recv_timeout(Duration::from_secs(2))
        });
    worker.join().unwrap();
    returned.expect("Drop cleanup must return without waiting for held reader metadata");
    assert_eq!(memory.storage_census().snapshot().readers, 2);

    let next = node.begin_registered_read().unwrap();
    assert!(RegisteredNodeRead::retained(memory.clone(), id).is_none());
    assert_eq!(live.id(), live_id);
    assert_eq!(live.phase(), NodeReadPhase::Finished);
    assert_eq!(memory.storage_census().snapshot().readers, 2);
    assert_eq!(next.finish(), NodeReadPhase::Finished);
    assert_eq!(
        next.retire_until(Instant::now() + crate::NATIVE_READ_TIMEOUT),
        StorageCensusDisposition::Retired
    );
    assert_eq!(
        live.retire_until(Instant::now() + crate::NATIVE_READ_TIMEOUT),
        StorageCensusDisposition::Retired
    );
    node.shutdown().await.unwrap();
    assert!(node.retire().is_retired());
    assert_eq!(memory.storage_census().snapshot().readers, 0);
}

#[tokio::test]
async fn expired_reader_retirement_is_revisited_by_normal_shutdown_after_metadata_contention() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("released-reader-close.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(
        &path,
        NODE_STORE_ID,
        disk,
        scratch,
        crate::test_utils::node_storage_config(),
    )
    .unwrap();
    let reader = node.begin_registered_read().unwrap();
    assert!(reader.catalog_bytes([42; 32], 64).unwrap().is_none());
    assert_eq!(reader.finish(), NodeReadPhase::Finished);
    let id = reader.id();
    let disposition = memory
        .storage_census()
        .with_owner_metadata_held_for_test(id, || reader.retire_until(Instant::now()));
    assert_eq!(disposition, StorageCensusDisposition::Retained);
    assert_eq!(memory.storage_census().snapshot().readers, 1);

    // No manual census drain and no recovered reader facade. Ordinary native
    // shutdown owns the next progress attempt for this exact opening.
    node.shutdown().await.unwrap();
    assert!(RegisteredNodeRead::retained(memory.clone(), id).is_none());
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    assert!(node.retire().is_retired());
}
