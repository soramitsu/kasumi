use super::*;
use crate::allocation_tests::measure;
use kasumi_types::drain::DrainCompletion;
use std::sync::atomic::{AtomicUsize, Ordering};

fn owner(disk: &Arc<ScratchDisk>, limit: u64) -> (Arc<Owner>, Backend) {
    let owner = Arc::new(Owner(Mutex::new(Some(
        EncryptedSpool::new(disk, limit).unwrap(),
    ))));
    owner.check_owner().unwrap();
    (owner.clone(), Backend(owner))
}

#[test]
fn dropping_a_table_observes_native_close_before_returning_scratch_credit() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let table = EncryptedTable::new(&disk, 8 << 20).unwrap();
    table.insert(b"identity", b"value").unwrap();
    assert_eq!(disk.snapshot().live_files, 1);
    drop(table);
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn batch_outliving_table_observes_close_after_its_transaction_ends() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let table = EncryptedTable::new(&disk, 8 << 20).unwrap();
    let mut batch = table.begin_batch().unwrap();
    batch.insert(b"identity", b"value").unwrap();
    drop(table);
    assert_eq!(disk.snapshot().live_files, 1);
    batch.commit().unwrap();
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn failed_bootstrap_closes_the_exact_spool_before_returning() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    // The native header fits, but creating the first table needs another frame.
    let (owner, backend) = owner(&disk, 8 << 10);
    let database = kasumi_kv::Database::builder(owner.clone())
        .create_with_backend(backend)
        .unwrap();
    let error = EncryptedTable::initialize(database).err().unwrap();
    let setup = error.downcast_ref::<ScratchTableSetupFailure>().unwrap();
    assert!(
        setup
            .original
            .downcast_ref::<kasumi_kv::CommitError>()
            .is_some()
    );
    assert!(setup.close.is_ok());
    assert!(owner.0.lock().unwrap().is_none());
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

struct FailSecondSync {
    backend: Backend,
    syncs: Arc<AtomicUsize>,
}

impl StorageBackend for FailSecondSync {
    fn len(&self) -> io::Result<u64> {
        self.backend.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.backend.read(offset, out)
    }
    fn set_len(&self, length: u64) -> io::Result<()> {
        self.backend.set_len(length)
    }
    fn sync_data(&self) -> io::Result<()> {
        if self.syncs.fetch_add(1, Ordering::SeqCst) == 1 {
            return Err(io::Error::other("injected bootstrap sync failure"));
        }
        self.backend.sync_data()
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.backend.write(offset, bytes)
    }
    fn close(&self) -> kasumi_kv::BackendCloseOutcome {
        self.backend.close()
    }
}

#[test]
fn failed_bootstrap_retains_unproved_close_and_original_outcomes() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let (owner, backend) = owner(&disk, 8 << 20);
    let syncs = Arc::new(AtomicUsize::new(0));
    let database = kasumi_kv::Database::builder(owner.clone())
        .create_with_backend(FailSecondSync {
            backend,
            syncs: syncs.clone(),
        })
        .unwrap();
    let error = EncryptedTable::initialize(database).err().unwrap();
    let setup = error.downcast_ref::<ScratchTableSetupFailure>().unwrap();
    assert!(
        setup
            .original
            .downcast_ref::<kasumi_kv::CommitError>()
            .is_some()
    );
    let first = setup.close.as_ref().unwrap_err();
    assert_eq!(first.completion(), DrainCompletion::Retained);
    let second = setup.retry_close().unwrap_err();
    assert!(Arc::ptr_eq(&first.issues()[0], &second.issues()[0]));
    assert_eq!(syncs.load(Ordering::SeqCst), 2);
    let charged = disk.snapshot().charged_bytes;
    assert!(charged > 0);
    assert_eq!(disk.snapshot().live_files, 1);
    drop(error);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert_eq!(disk.snapshot().live_files, 1);
    assert!(owner.0.lock().unwrap().is_some());
    drop(owner);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert_eq!(disk.snapshot().live_files, 1);
}

#[test]
fn unpublished_batch_aborts_on_drop_and_preserves_duplicate_error() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let table = EncryptedTable::new(&disk, 8 << 20).unwrap();
    let mut batch = table.begin_batch().unwrap();
    batch.insert(b"identity", b"first").unwrap();
    assert_eq!(table.get(b"identity").unwrap(), None);
    let error = batch.insert(b"identity", b"second").unwrap_err();
    assert_eq!(error.to_string(), "duplicate staged key");
    assert_eq!(
        batch.commit().unwrap_err().to_string(),
        "staging batch previously failed"
    );
    assert_eq!(table.get(b"identity").unwrap(), None);
    let mut dropped = table.begin_batch().unwrap();
    dropped.insert(b"abandoned", b"value").unwrap();
    drop(dropped);
    assert_eq!(table.get(b"abandoned").unwrap(), None);
    table.insert(b"identity", b"later").unwrap();
    assert_eq!(table.get(b"identity").unwrap(), Some(b"later".to_vec()));
    table.close().unwrap();
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn accepted_batch_keeps_physical_table_until_commit_and_close() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let table = EncryptedTable::new(&disk, 8 << 20).unwrap();
    let mut batch = table.begin_batch().unwrap();
    batch.insert(b"identity", b"value").unwrap();
    let charged = disk.snapshot().charged_bytes;
    let first = table.close().unwrap_err();
    let second = table.close().unwrap_err();
    assert_eq!(first.completion(), DrainCompletion::Retained);
    assert!(Arc::ptr_eq(&first.issues()[0], &second.issues()[0]));
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert_eq!(disk.snapshot().live_files, 1);
    batch.commit().unwrap();
    table.close().unwrap();
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn batch_entry_limit_rejects_before_publication_and_aborts_partial_input() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let table = EncryptedTable::new(&disk, 8 << 20).unwrap();
    let mut batch = table.begin_batch().unwrap();
    for ordinal in 0..EncryptedTableBatch::MAX_ENTRIES {
        batch.insert(&ordinal.to_be_bytes(), b"value").unwrap();
    }
    let error = batch.insert(b"extra", b"value").unwrap_err();
    assert_eq!(error.to_string(), "staging batch capacity exceeded");
    assert!(batch.commit().is_err());
    assert_eq!(table.get(&0usize.to_be_bytes()).unwrap(), None);
    table.close().unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn exact_backend_publication_io_settlement_shrink_and_close_do_not_allocate() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let disk =
        ScratchDisk::isolated_fixture(scratch_directory.path(), 8 << 20, fixture_memory.clone());
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
        let outcome = backend.close();
        assert_eq!(
            outcome.native_disposition(),
            kasumi_kv::BackendNativeDisposition::Drained
        );
        outcome.into_result()
    });
    result.unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(output, input);
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().live_files, 0);
    let (result, native) = backend.close().into_parts();
    assert_eq!(native, kasumi_kv::BackendNativeDisposition::Drained);
    result.unwrap();
    assert!(owner.check_owner().is_err());
}

#[test]
fn rejected_resize_is_wholly_reserved_before_any_logical_or_physical_change() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let disk =
        ScratchDisk::isolated_fixture(scratch_directory.path(), 192 << 10, fixture_memory.clone());
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
    let (result, native) = backend.close().into_parts();
    assert_eq!(native, kasumi_kv::BackendNativeDisposition::Drained);
    result.unwrap();
}

#[test]
fn exact_settlement_mismatch_fences_owner_without_allocating_or_returning_credit() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let disk =
        ScratchDisk::isolated_fixture(scratch_directory.path(), 8 << 20, fixture_memory.clone());
    let (owner, backend) = owner(&disk, 4 << 20);
    owner.reserve_growth(0, 128 << 10).unwrap();
    backend.set_len(64 << 10).unwrap();
    backend.sync_data().unwrap();
    let charged = disk.snapshot().charged_bytes;
    let address = {
        let retained = owner.0.lock().unwrap();
        std::ptr::from_ref(retained.as_ref().unwrap())
    };
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
    assert_eq!(
        closed.native_disposition(),
        kasumi_kv::BackendNativeDisposition::Retained
    );
    let closed = closed.into_result();
    assert!(closed.is_err());
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().live_files, 1);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    for _ in 0..2 {
        let (outcome, allocations) = measure(|| backend.close());
        let (result, native) = outcome.into_parts();
        assert_eq!(native, kasumi_kv::BackendNativeDisposition::Retained);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(allocations, 0);
        let retained = owner.0.lock().unwrap();
        assert_eq!(std::ptr::from_ref(retained.as_ref().unwrap()), address);
        assert_eq!(disk.snapshot().live_files, 1);
        assert_eq!(disk.snapshot().charged_bytes, charged);
    }
    // This deliberately failed owner has no disposal proof. Keep it installed
    // for the process lifetime instead of using Drop as credit evidence.
    static RETAINED: std::sync::Mutex<Option<Arc<Owner>>> = std::sync::Mutex::new(None);
    *RETAINED.lock().unwrap() = Some(owner);
}

#[test]
fn accepted_transaction_keeps_scratch_close_retained_until_actual_drain() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let disk =
        ScratchDisk::isolated_fixture(scratch_directory.path(), 16 << 20, fixture_memory.clone());
    let table = EncryptedTable::new(&disk, 8 << 20).unwrap();
    table.insert(b"key", b"value").unwrap();
    let read = table.owner.database().begin_read().unwrap();
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
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let disk =
        ScratchDisk::isolated_fixture(scratch_directory.path(), 16 << 20, fixture_memory.clone());
    let (owner, backend) = owner(&disk, 8 << 20);
    let database = kasumi_kv::Database::builder(owner.clone())
        .create_with_backend(backend)
        .unwrap();
    let table = EncryptedTable {
        owner: Arc::new(ScratchTableDatabase {
            database: Some(crate::node_database::NodeDatabase::new(
                database,
                "encrypted scratch table",
            )),
        }),
    };
    let before = disk.snapshot();
    let address = {
        let retained = owner.0.lock().unwrap();
        std::ptr::from_ref(retained.as_ref().unwrap())
    };
    owner.owner_failed();
    let first = table.close().unwrap_err();
    let second = table.close().unwrap_err();
    assert_eq!(first.completion(), DrainCompletion::Retained);
    assert!(Arc::ptr_eq(&first.issues()[0], &second.issues()[0]));
    assert!(table.get(b"key").is_err());
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().live_files, before.live_files);
    {
        let retained = owner.0.lock().unwrap();
        assert_eq!(std::ptr::from_ref(retained.as_ref().unwrap()), address);
    }
    // The consuming NodeDatabase still lacks installed failed-owner custody.
    // This test supplies explicit owner custody without claiming that migration.
    static RETAINED: std::sync::Mutex<Option<Arc<Owner>>> = std::sync::Mutex::new(None);
    *RETAINED.lock().unwrap() = Some(owner);
}

#[test]
fn actual_spool_close_reports_native_drain_before_retiring_adapter_owner() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 8 << 20, memory);
    let (owner, backend) = owner(&disk, 4 << 20);
    owner.reserve_growth(0, 128 << 10).unwrap();
    backend.set_len(128 << 10).unwrap();
    backend.write(0, b"actual ciphertext").unwrap();
    assert!(disk.snapshot().charged_bytes > 0);
    let (outcome, allocations) = measure(|| backend.close());
    let (result, native) = outcome.into_parts();
    assert_eq!(native, kasumi_kv::BackendNativeDisposition::Drained);
    result.unwrap();
    assert_eq!(allocations, 0);
    assert!(owner.0.lock().unwrap().is_none());
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
    let (result, native) = backend.close().into_parts();
    assert_eq!(native, kasumi_kv::BackendNativeDisposition::Drained);
    result.unwrap();
}
