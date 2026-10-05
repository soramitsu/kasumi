use super::*;

#[test]
fn scratch_point_result_uses_the_original_native_allocation() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let table = EncryptedTable::new(&disk, 8 << 20, CacheConfig { byte_limit: 0 }).unwrap();
    let bytes = vec![0x53; 128 << 10];
    table.insert(b"key", &bytes).unwrap();
    let baseline = memory.snapshot();

    let (native, native_allocations, native_requested) =
        crate::allocation_tests::measure_requested(|| {
            let transaction = table.owner.database().begin_read().unwrap();
            transaction
                .open_table(TABLE)
                .unwrap()
                .get(b"key")
                .unwrap()
                .unwrap()
        });
    assert_eq!(native.value(), bytes);
    drop(native);
    let (value, allocations, requested) =
        crate::allocation_tests::measure_requested(|| table.get(b"key").unwrap().unwrap());
    assert_eq!(value.as_bytes(), bytes);
    assert_eq!(allocations, native_allocations);
    assert_eq!(requested, native_requested);
    assert!(memory.snapshot().used_bytes > baseline.used_bytes);
    drop(value);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    drop(table);
}

#[test]
fn scratch_point_result_keeps_its_exact_snapshot_and_database_after_table_drop() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let baseline = memory.snapshot();
    let table = EncryptedTable::new(&disk, 8 << 20, CacheConfig { byte_limit: 0 }).unwrap();
    let original = vec![0x61; 128 << 10];
    table.insert(b"key", &original).unwrap();
    let value = table.get(b"key").unwrap().unwrap();
    table.set(b"key", b"replacement").unwrap();
    assert_eq!(
        table.get(b"key").unwrap().unwrap().as_bytes(),
        b"replacement"
    );
    drop(table);
    assert_eq!(value.as_bytes(), original);
    assert!(disk.snapshot().live_files > 0);
    assert!(disk.snapshot().charged_bytes > 0);
    assert!(memory.snapshot().used_bytes > baseline.used_bytes);
    drop(value);
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[test]
fn missing_scratch_point_does_not_keep_a_database_owner_or_native_charge() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let table = EncryptedTable::new(&disk, 8 << 20, CacheConfig { byte_limit: 0 }).unwrap();
    let baseline = memory.snapshot();
    assert!(table.get(b"missing").unwrap().is_none());
    // The public table and its independently funded construction census own
    // the original table; a missing point contributes no additional alias.
    assert_eq!(Arc::strong_count(&table.owner), 2);
    assert!(
        crate::ScratchCreationFailure::retained(memory.clone(), table.owner.retirement.1).is_none()
    );
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    drop(table);
    assert_eq!(disk.snapshot().live_files, 0);
}
