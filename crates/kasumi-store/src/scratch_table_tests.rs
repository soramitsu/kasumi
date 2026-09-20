use super::*;
use crate::allocation_tests::measure;
use kasumi_types::drain::DrainCompletion;

fn owner(disk: &Arc<ScratchDisk>, limit: u64) -> (Arc<Owner>, Backend) {
    let owner = Arc::new(Owner(Mutex::new(Some(
        EncryptedSpool::new(disk, limit).unwrap(),
    ))));
    owner.check_owner().unwrap();
    (owner.clone(), Backend(owner))
}

#[test]
fn exact_backend_publication_io_settlement_shrink_and_close_do_not_allocate() {
    let disk = ScratchDisk::isolated_fixture(8 << 20);
    let (owner, backend) = owner(&disk, 4 << 20);
    let input = vec![37; (128 << 10) + 13];
    let mut output = vec![0; input.len()];
    let (result, allocations) = measure(|| -> io::Result<()> {
        owner.reserve_growth(0, 192 << 10).unwrap();
        backend.set_len(192 << 10)?;
        backend.write(7, &input)?;
        backend.sync_data()?;
        owner.settle_growth(192 << 10).unwrap();
        backend.read(7, &mut output)?;
        backend.set_len(31)?;
        backend.sync_data()?;
        owner.settle_growth(31).unwrap();
        backend.close()
    });
    result.unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(output, input);
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().live_files, 0);
    backend.close().unwrap();
    assert!(owner.check_owner().is_err());
}

#[test]
fn rejected_resize_is_wholly_reserved_before_any_logical_or_physical_change() {
    let disk = ScratchDisk::isolated_fixture(192 << 10);
    let (owner, backend) = owner(&disk, 4 << 20);
    owner.reserve_growth(0, 64 << 10).unwrap();
    backend.set_len(64 << 10).unwrap();
    backend.write(0, b"original").unwrap();
    backend.sync_data().unwrap();
    let before = disk.snapshot().charged_bytes;
    let (error, allocations) = measure(|| backend.set_len(192 << 10).unwrap_err());
    assert_eq!(error.kind(), io::ErrorKind::StorageFull);
    assert_eq!(allocations, 0);
    assert_eq!(backend.len().unwrap(), 64 << 10);
    assert_eq!(disk.snapshot().charged_bytes, before);
    let mut bytes = [0; 8];
    backend.read(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"original");
    owner.check_owner().unwrap();
    assert_eq!(
        owner.reserve_growth(64 << 10, 192 << 10),
        Err(AdmissionError::CapacityDenied)
    );
    backend.close().unwrap();
}

#[test]
fn exact_settlement_mismatch_fences_owner_without_allocating_or_returning_credit() {
    let disk = ScratchDisk::isolated_fixture(8 << 20);
    let (owner, backend) = owner(&disk, 4 << 20);
    owner.reserve_growth(0, 128 << 10).unwrap();
    backend.set_len(64 << 10).unwrap();
    backend.sync_data().unwrap();
    let charged = disk.snapshot().charged_bytes;
    let (outcome, allocations) = measure(|| owner.settle_growth(0));
    assert_eq!(outcome, Err(OwnerFailed));
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert!(owner.check_owner().is_err());
    assert_eq!(
        owner.reserve_growth(64 << 10, 128 << 10),
        Err(AdmissionError::OwnerFailed)
    );
    let (closed, allocations) = measure(|| backend.close());
    assert!(closed.is_err());
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn accepted_transaction_keeps_scratch_close_retained_until_actual_drain() {
    let disk = ScratchDisk::isolated_fixture(16 << 20);
    let table = EncryptedTable::new(&disk, 8 << 20).unwrap();
    table.insert(b"key", b"value").unwrap();
    let read = table.database.begin_read().unwrap();
    let charged = disk.snapshot().charged_bytes;
    let first = table.close().unwrap_err();
    let second = table.close().unwrap_err();
    assert_eq!(first.completion(), DrainCompletion::Retained);
    assert!(Arc::ptr_eq(&first.issues()[0], &second.issues()[0]));
    assert!(table.get(b"key").is_err());
    assert!(table.set(b"key", b"new").is_err());
    assert_eq!(disk.snapshot().charged_bytes, charged);
    drop(read);
    table.close().unwrap();
    table.close().unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().live_files, 0);
}

#[test]
fn explicit_scratch_close_retains_original_physical_failure_on_retry() {
    let disk = ScratchDisk::isolated_fixture(16 << 20);
    let (owner, backend) = owner(&disk, 8 << 20);
    let database = redb::Database::builder(owner.clone())
        .create_with_backend(backend)
        .unwrap();
    let table = EncryptedTable {
        database: crate::node_database::NodeDatabase::new(database, "encrypted scratch table"),
    };
    owner.owner_failed();
    let first = table.close().unwrap_err();
    let second = table.close().unwrap_err();
    assert_eq!(first.completion(), DrainCompletion::Complete);
    assert!(Arc::ptr_eq(&first.issues()[0], &second.issues()[0]));
    assert!(table.get(b"key").is_err());
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().live_files, 0);
}
