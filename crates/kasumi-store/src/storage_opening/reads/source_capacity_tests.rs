use super::*;
use crate::test_utils::{
    TestDiskMemory, node_storage_config, private_tempdir, retry_disk_registry,
};

#[test]
fn source_capacity_unknown_provider_retains_original_control_refusal() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("source-capacity-close.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let opening = RegisteredNodeOpening::prepare(
        &path,
        uuid::Uuid::from_u128(0x7cd6b71f),
        disk,
        NodeOpeningMode::Create,
        node_storage_config(),
    )
    .unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let tables = opening.queue_node_tables().unwrap();
    assert_eq!(tables.run(), NodeWriterPhase::Finished);
    opening.publish_ready_after_tables(&tables).unwrap();
    assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
    let before = memory.snapshot();
    let capacity = opening.queue_source_capacity().unwrap();
    let id = capacity.owner_id();
    assert!(capacity.pool.is_none());
    let original = capacity
        .with_control_observation(|original, _, _| {
            let TerminalObservation::Returned(Err(error)) = original else {
                panic!("unknown provider did not retain its original refusal");
            };
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            error as *const io::Error as usize
        })
        .unwrap();
    let failure = match capacity.install() {
        Ok(_) => panic!("unknown provider acquired protected capacity"),
        Err(failure) => failure,
    };
    assert_eq!(failure.owner_id(), id);
    assert_eq!(failure.phase(), None);
    let SourceCapacityClose::Retained(failure) = failure.capacity.close() else {
        panic!("failed actual source control was reported clean");
    };
    failure
        .with_control_observation(|error, _, cleanup| {
            let TerminalObservation::Returned(Err(error)) = error else {
                panic!("original source control refusal was lost");
            };
            assert_eq!(error as *const io::Error as usize, original);
            assert!(matches!(cleanup, TerminalObservation::Returned(Ok(()))));
        })
        .unwrap();
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    // Explicit test-only release follows assertions of retained original custody.
    memory
        .storage_census()
        .acknowledge_source_control(id)
        .unwrap();
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retired
    );
    drop(failure);
    let after = memory.snapshot();
    assert_eq!(after.used_bytes, before.used_bytes);
    assert_eq!(after.live_reservations, before.live_reservations);
    assert_eq!(memory.storage_census().snapshot().source_pools, 0);
    assert_eq!(
        opening.close().unwrap(),
        kasumi_kv::DatabaseOpenSettlement::Closed
    );
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
}
