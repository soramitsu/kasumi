use super::*;
use crate::allocation_tests::measure;
use crate::{NodeDiskMemoryAdmission, RetainedSpool};
use kasumi_kv::{
    AdmissionError, GroupFile, OwnerFailed, ROOT_SLOT_BYTES, RootSlot, SegmentGroupBackend,
    StorageAdmission,
};
use kasumi_types::drain::DrainCompletion;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
const GROUP: [u8; 16] = [93; 16];
const CACHE: CacheConfig = CacheConfig {
    byte_limit: 8 << 20,
};
const DATA: GroupFile = GroupFile::segment(1);

struct BootstrapAdmission {
    owner: Arc<Owner>,
    deny: AtomicBool,
}
impl StorageAdmission for BootstrapAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.owner.check_owner()
    }
    fn reserve_workspace(
        &self,
        bytes: u64,
    ) -> Result<Box<dyn kasumi_kv::ResidentLease>, AdmissionError> {
        self.owner
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if self.deny.load(Ordering::Acquire) && bytes >= 1 << 20 {
            return Err(AdmissionError::CapacityDenied);
        }
        self.owner.reserve_workspace(bytes)
    }
    fn reserve_growth(&self, current: u64, requested: u64) -> Result<(), AdmissionError> {
        self.owner.reserve_growth(current, requested)
    }
    fn settle_growth(&self, actual: u64) -> Result<(), OwnerFailed> {
        self.owner.settle_growth(actual)
    }
    fn owner_failed(&self) {
        self.owner.owner_failed();
    }

    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryQuote, AdmissionError> {
        crate::test_utils::cache_memory::quote(self, bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryLease, AdmissionError> {
        crate::test_utils::cache_memory::reserve(self, bytes)
    }
}

impl crate::test_utils::cache_memory::Provider for BootstrapAdmission {
    fn inner_quote(&self, bytes: u64) -> Result<kasumi_kv::CacheMemoryQuote, AdmissionError> {
        self.owner.quote_cache_memory(bytes)
    }
    fn inner_reserve(&self, bytes: u64) -> Result<kasumi_kv::CacheMemoryLease, AdmissionError> {
        self.owner.clone().reserve_cache_memory(bytes)
    }
    fn gate(&self, bytes: u64) -> Result<(), AdmissionError> {
        if self.deny.load(Ordering::Acquire) && bytes >= 1 << 20 {
            Err(AdmissionError::CapacityDenied)
        } else {
            Ok(())
        }
    }
}

fn owner(disk: &Arc<ScratchDisk>, limit: u64) -> (Arc<Owner>, Backend) {
    let owner = Owner::new(disk, limit).unwrap();
    owner.check_owner().unwrap();
    (owner.clone(), Backend(owner))
}

#[test]
fn dropping_a_table_observes_native_close_before_returning_scratch_credit() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let table = EncryptedTable::new(&disk, 8 << 20, CACHE).unwrap();
    table.insert(b"identity", b"value").unwrap();
    assert_eq!(disk.snapshot().live_files, 3);
    drop(table);
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn batch_outliving_table_observes_close_after_its_transaction_ends() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let table = EncryptedTable::new(&disk, 8 << 20, CACHE).unwrap();
    let mut batch = table.begin_batch().unwrap();
    batch.insert(b"identity", b"value").unwrap();
    drop(table);
    assert_eq!(disk.snapshot().live_files, 3);
    batch.commit().unwrap();
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn failed_bootstrap_closes_the_exact_spool_before_returning() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    // The created root is healthy. Deny the first commit's bounded abort/replay
    // workspace before it can append any private segment or directory bytes.
    let (owner, backend) = owner(&disk, 8 << 20);
    let admission = Arc::new(BootstrapAdmission {
        owner: owner.clone(),
        deny: AtomicBool::new(false),
    });
    let database = kasumi_kv::Database::builder(admission.clone(), GROUP, CACHE)
        .create_with_backend(backend)
        .unwrap();
    admission.deny.store(true, Ordering::Release);
    let error = EncryptedTable::initialize(database, owner.clone())
        .err()
        .unwrap();
    error.with_diagnostic(|report| {
        let report = report.unwrap();
        let terminal = report.setup_terminal().unwrap();
        assert!(matches!(
            terminal.terminal(),
            kasumi_kv::TerminalObservation::Returned(Err(kasumi_kv::WriteTerminalError::Commit(_)))
        ));
        assert_eq!(
            terminal.settlement(),
            kasumi_kv::WriteTerminalSettlement::Settled
        );
        assert!(terminal.disposal_complete());
        let close = report.setup_close().unwrap();
        assert_eq!(
            close.native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert_eq!(
            close.settlement(),
            kasumi_kv::DatabaseCloseSettlement::Disposed
        );
        assert!(close.disposal().complete());
    });
    assert!(owner.drained());
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(
        error.retire().disposition(),
        crate::StorageCensusDisposition::Retired
    );
}

struct FailSecondSync {
    backend: Backend,
    syncs: Arc<AtomicUsize>,
}

impl SegmentGroupBackend for FailSecondSync {
    fn reserve_transaction(
        &self,
        plan: &kasumi_kv::TransactionSpacePlan,
    ) -> std::result::Result<(), kasumi_kv::TransactionReserveError> {
        self.backend.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.backend.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.backend.cancel_transaction(group_id, batch_seq)
    }

    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.backend.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.backend.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.backend.sync_root()
    }
    fn visit_entries(
        &self,
        visitor: &mut dyn FnMut(&std::ffi::OsStr) -> io::Result<()>,
    ) -> io::Result<()> {
        self.backend.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.backend.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.backend.create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.backend.len(file)
    }
    fn read(&self, file: GroupFile, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.backend.read(file, offset, out)
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.backend.set_len(file, length)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        if self.syncs.fetch_add(1, Ordering::SeqCst) == 1 {
            self.backend.0.owner_failed();
            return Err(io::Error::other("injected bootstrap sync failure"));
        }
        self.backend.sync(file)
    }
    fn write(&self, file: GroupFile, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.backend.write(file, offset, bytes)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.backend.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.backend.sync_names()
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
    let database = kasumi_kv::Database::builder(owner.clone(), GROUP, CACHE)
        .create_with_backend(FailSecondSync {
            backend,
            syncs: syncs.clone(),
        })
        .unwrap();
    let error = EncryptedTable::initialize(database, owner.clone())
        .err()
        .unwrap();
    let original = error.with_diagnostic(|report| {
        let report = report.unwrap();
        let terminal = report.setup_terminal().unwrap();
        assert_eq!(
            terminal.settlement(),
            kasumi_kv::WriteTerminalSettlement::Retained
        );
        let original = match terminal.terminal() {
            kasumi_kv::TerminalObservation::Returned(Err(
                original @ kasumi_kv::WriteTerminalError::Commit(_),
            )) => original,
            _ => panic!("actual failed setup commit missing"),
        };
        let close = report.setup_close().unwrap();
        assert_eq!(
            close.native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert!(!close.disposal().complete());
        std::ptr::from_ref(original) as usize
    });
    let retirement = error.retire();
    assert_eq!(
        retirement.disposition(),
        crate::StorageCensusDisposition::Retained
    );
    assert_eq!(
        retirement.retry(),
        crate::StorageCensusDisposition::Retained
    );
    retirement.with_diagnostic(|report| {
        let report = report.unwrap();
        let terminal = report.setup_terminal().unwrap();
        let second = match terminal.terminal() {
            kasumi_kv::TerminalObservation::Returned(Err(
                original @ kasumi_kv::WriteTerminalError::Commit(_),
            )) => original,
            _ => panic!("original failed setup commit lost on retry"),
        };
        assert_eq!(std::ptr::from_ref(second) as usize, original);
        assert_eq!(
            terminal.settlement(),
            kasumi_kv::WriteTerminalSettlement::Retained
        );
        let close = report.setup_close().unwrap();
        assert_eq!(
            close.native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert!(!close.disposal().complete());
    });
    assert_eq!(syncs.load(Ordering::SeqCst), 2);
    let charged = disk.snapshot().charged_bytes;
    let files = disk.snapshot().live_files;
    assert!(charged > 0);
    assert_eq!(disk.snapshot().live_files, files);
    drop(retirement);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert_eq!(disk.snapshot().live_files, files);
    assert!(!owner.drained());
    drop(owner);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert_eq!(disk.snapshot().live_files, files);
}

#[test]
fn unpublished_batch_aborts_on_drop_and_preserves_duplicate_error() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let table = EncryptedTable::new(&disk, 8 << 20, CACHE).unwrap();
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
    assert_eq!(
        table.get(b"identity").unwrap().as_deref(),
        Some(b"later".as_slice())
    );
    table.close().unwrap();
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn accepted_batch_keeps_physical_table_until_commit_and_close() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let table = EncryptedTable::new(&disk, 8 << 20, CACHE).unwrap();
    let mut batch = table.begin_batch().unwrap();
    batch.insert(b"identity", b"value").unwrap();
    let charged = disk.snapshot().charged_bytes;
    let first = table.close().unwrap_err();
    let second = table.close().unwrap_err();
    assert_eq!(first.completion(), DrainCompletion::Retained);
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &first.issues()[0],
        &second.issues()[0]
    ));
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert_eq!(disk.snapshot().live_files, 3);
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
    let table = EncryptedTable::new(&disk, 8 << 20, CACHE).unwrap();
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
    backend.create(DATA).unwrap();
    let input = vec![37; (128 << 10) + 13];
    let mut output = vec![0; input.len()];
    let (result, allocations) = measure(|| -> io::Result<()> {
        owner.reserve_growth(0, 192 << 10).unwrap();
        backend.set_len(DATA, 192 << 10)?;
        backend.write(DATA, 7, &input)?;
        backend.sync(DATA)?;
        owner.settle_growth(192 << 10).unwrap();
        backend.read(DATA, 7, &mut output)?;
        backend.set_len(DATA, 31)?;
        backend.sync(DATA)?;
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
    backend.create(DATA).unwrap();
    owner.reserve_growth(0, 64 << 10).unwrap();
    backend.set_len(DATA, 64 << 10).unwrap();
    backend.write(DATA, 0, b"original").unwrap();
    backend.sync(DATA).unwrap();
    let before = disk.snapshot().charged_bytes;
    let (error, allocations) = measure(|| backend.set_len(DATA, 192 << 10).unwrap_err());
    assert_eq!(error.kind(), io::ErrorKind::StorageFull);
    assert_eq!(allocations, 0);
    assert_eq!(backend.len(DATA).unwrap(), 64 << 10);
    assert_eq!(disk.snapshot().charged_bytes, before);
    let mut bytes = [0; 8];
    backend.read(DATA, 0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"original");
    owner.check_owner().unwrap();
    owner.reserve_growth(64 << 10, 192 << 10).unwrap();
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
    backend.create(DATA).unwrap();
    owner.reserve_growth(0, 128 << 10).unwrap();
    backend.set_len(DATA, 64 << 10).unwrap();
    backend.sync(DATA).unwrap();
    let charged = disk.snapshot().charged_bytes;
    let address = spool_address(&owner);
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
    assert_eq!(disk.snapshot().live_files, 2);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    for _ in 0..2 {
        let (outcome, allocations) = measure(|| backend.close());
        let (result, native) = outcome.into_parts();
        assert_eq!(native, kasumi_kv::BackendNativeDisposition::Retained);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(allocations, 0);
        assert_eq!(spool_address(&owner), address);
        assert_eq!(disk.snapshot().live_files, 2);
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
    let table = EncryptedTable::new(&disk, 8 << 20, CACHE).unwrap();
    table.insert(b"key", b"value").unwrap();
    let read = table.owner.database().begin_read().unwrap();
    let charged = disk.snapshot().charged_bytes;
    let first = table.close().unwrap_err();
    let second = table.close().unwrap_err();
    assert_eq!(first.completion(), DrainCompletion::Retained);
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &first.issues()[0],
        &second.issues()[0]
    ));
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
    let database = kasumi_kv::Database::builder(owner.clone(), GROUP, CACHE)
        .create_with_backend(backend)
        .unwrap();
    let table = EncryptedTable::initialize(database, owner.clone()).unwrap();
    let before = disk.snapshot();
    let address = spool_address(&owner);
    owner.owner_failed();
    let first = table.close().unwrap_err();
    let second = table.close().unwrap_err();
    assert_eq!(first.completion(), DrainCompletion::Retained);
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &first.issues()[0],
        &second.issues()[0]
    ));
    assert!(table.get(b"key").is_err());
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().live_files, before.live_files);
    {
        assert_eq!(spool_address(&owner), address);
    }
    // Retain this fixture's additional diagnostic Owner alias. The admitted
    // creation request independently keeps the exact failed native owner.
    static RETAINED: std::sync::Mutex<Option<Arc<Owner>>> = std::sync::Mutex::new(None);
    *RETAINED.lock().unwrap() = Some(owner);
}

#[test]
fn strict_create_rejects_a_non_empty_spool_instead_of_adopting_its_frames() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let (owner, backend) = owner(&disk, 8 << 20);
    // Plant a valid committed image whose table and key would be readable if
    // creation fell back to opening an existing extent.
    let planted = kasumi_kv::Database::builder(owner.clone(), GROUP, CACHE)
        .create_with_backend(backend)
        .unwrap();
    let tx = planted.begin_write().unwrap();
    tx.open_table(TABLE)
        .unwrap()
        .insert(b"planted".as_slice(), b"frame".as_slice())
        .unwrap();
    tx.commit().unwrap();
    assert!(!owner.with_root(|root| root.spool().unwrap().is_empty()));
    assert_eq!(disk.snapshot().live_files, 3);
    let error = EncryptedTable::create(owner.clone(), CACHE).err().unwrap();
    error.with_diagnostic(|report| {
        let report = report.unwrap();
        assert!(matches!(
            report.opening_error().unwrap().rejected_cause(),
            Some(kasumi_kv::CoreErrorCause::InvalidInput(
                "group already contains a root"
            ))
        ));
        assert_eq!(
            report.opening_close().unwrap().native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert!(report.opening_disposal().unwrap().complete());
    });
    // The rejected spool is observed closed before the error is returned.
    assert!(owner.drained());
    assert!(owner.check_owner().is_err());
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(
        error.retire().disposition(),
        crate::StorageCensusDisposition::Retired
    );
    drop(planted);
}

struct CountCloses {
    backend: Backend,
    closes: Arc<AtomicUsize>,
}

impl SegmentGroupBackend for CountCloses {
    fn reserve_transaction(
        &self,
        plan: &kasumi_kv::TransactionSpacePlan,
    ) -> std::result::Result<(), kasumi_kv::TransactionReserveError> {
        self.backend.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.backend.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.backend.cancel_transaction(group_id, batch_seq)
    }

    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.backend.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.backend.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.backend.sync_root()
    }
    fn visit_entries(
        &self,
        visitor: &mut dyn FnMut(&std::ffi::OsStr) -> io::Result<()>,
    ) -> io::Result<()> {
        self.backend.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.backend.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.backend.create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.backend.len(file)
    }
    fn read(&self, file: GroupFile, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.backend.read(file, offset, out)
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.backend.set_len(file, length)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.backend.sync(file)
    }
    fn write(&self, file: GroupFile, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.backend.write(file, offset, bytes)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.backend.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.backend.sync_names()
    }
    fn close(&self) -> kasumi_kv::BackendCloseOutcome {
        self.closes.fetch_add(1, Ordering::SeqCst);
        self.backend.close()
    }
}

fn counted_table(disk: &Arc<ScratchDisk>) -> (EncryptedTable, Arc<Owner>, Arc<AtomicUsize>) {
    let (owner, backend) = owner(disk, 8 << 20);
    let closes = Arc::new(AtomicUsize::new(0));
    let database = kasumi_kv::Database::builder(owner.clone(), GROUP, CACHE)
        .create_with_backend(CountCloses {
            backend,
            closes: closes.clone(),
        })
        .unwrap();
    let table = EncryptedTable::initialize(database, owner.clone()).unwrap();
    table.insert(b"identity", b"value").unwrap();
    (table, owner, closes)
}

fn spool_address(owner: &Owner) -> *const RetainedSpool {
    owner.with_root(|root| std::ptr::from_ref(root))
}

#[test]
fn dropping_a_drained_table_closes_natively_once_without_allocating() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let (table, owner, closes) = counted_table(&disk);
    assert_eq!(
        table.get(b"identity").unwrap().as_deref(),
        Some(b"value".as_slice())
    );
    assert!(disk.snapshot().charged_bytes > 0);
    let ((), allocations) = measure(|| drop(table));
    assert_eq!(allocations, 0);
    assert_eq!(closes.load(Ordering::SeqCst), 1);
    assert!(owner.drained());
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn dropping_an_explicitly_closed_table_never_reenters_native_close() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let (table, owner, closes) = counted_table(&disk);
    table.close().unwrap();
    assert_eq!(closes.load(Ordering::SeqCst), 1);
    assert!(owner.drained());
    assert_eq!(disk.snapshot().charged_bytes, 0);
    let ((), allocations) = measure(|| drop(table));
    assert_eq!(allocations, 0);
    assert_eq!(closes.load(Ordering::SeqCst), 1);
    assert_eq!(disk.snapshot().live_files, 0);
}

#[test]
fn dropping_a_failed_table_keeps_spool_and_charge_without_allocating() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let (table, owner, closes) = counted_table(&disk);
    let address = spool_address(&owner);
    let charged = disk.snapshot().charged_bytes;
    assert!(charged > 0);
    // The physical owner fails after acceptance; the destructor's single
    // native close cannot synchronize and therefore cannot prove drain.
    owner.owner_failed();
    let ((), allocations) = measure(|| drop(table));
    assert_eq!(allocations, 0);
    assert_eq!(closes.load(Ordering::SeqCst), 1);
    assert_eq!(spool_address(&owner), address);
    assert_eq!(disk.snapshot().live_files, 3);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    // The forgotten engine still owns the exact spool, so releasing this
    // last test handle cannot run an unobserved descriptor close or credit.
    drop(owner);
    assert_eq!(disk.snapshot().live_files, 3);
    assert_eq!(disk.snapshot().charged_bytes, charged);
}

#[test]
fn failed_explicit_close_keeps_charge_and_drop_never_reenters_close() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let (table, owner, closes) = counted_table(&disk);
    let address = spool_address(&owner);
    let charged = disk.snapshot().charged_bytes;
    owner.owner_failed();
    let first = table.close().unwrap_err();
    let second = table.close().unwrap_err();
    assert_eq!(first.completion(), DrainCompletion::Retained);
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &first.issues()[0],
        &second.issues()[0]
    ));
    assert_eq!(closes.load(Ordering::SeqCst), 1);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    let ((), allocations) = measure(|| drop(table));
    assert_eq!(allocations, 0);
    assert_eq!(closes.load(Ordering::SeqCst), 1);
    assert_eq!(spool_address(&owner), address);
    assert_eq!(disk.snapshot().live_files, 3);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    drop(owner);
    assert_eq!(disk.snapshot().live_files, 3);
    assert_eq!(disk.snapshot().charged_bytes, charged);
}

#[test]
fn dropping_a_table_under_a_live_transaction_never_enters_close_or_returns_credit() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let (table, owner, closes) = counted_table(&disk);
    let address = spool_address(&owner);
    let charged = disk.snapshot().charged_bytes;
    let read = table.owner.database().begin_read().unwrap();
    let ((), allocations) = measure(|| drop(table));
    assert_eq!(allocations, 0);
    assert_eq!(closes.load(Ordering::SeqCst), 0);
    // A handle ending after the last owner is gone cannot revive a close.
    drop(read);
    assert_eq!(closes.load(Ordering::SeqCst), 0);
    assert_eq!(spool_address(&owner), address);
    assert!(owner.check_owner().is_ok());
    assert_eq!(disk.snapshot().live_files, 3);
    assert_eq!(disk.snapshot().charged_bytes, charged);
}

#[test]
fn actual_spool_close_reports_native_drain_before_retiring_adapter_owner() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 8 << 20, memory);
    let (owner, backend) = owner(&disk, 4 << 20);
    backend.create(DATA).unwrap();
    owner.reserve_growth(0, 128 << 10).unwrap();
    backend.set_len(DATA, 128 << 10).unwrap();
    backend.write(DATA, 0, b"actual ciphertext").unwrap();
    assert!(disk.snapshot().charged_bytes > 0);
    let (outcome, allocations) = measure(|| backend.close());
    let (result, native) = outcome.into_parts();
    assert_eq!(native, kasumi_kv::BackendNativeDisposition::Drained);
    result.unwrap();
    assert_eq!(allocations, 0);
    assert!(owner.drained());
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
    let (result, native) = backend.close().into_parts();
    assert_eq!(native, kasumi_kv::BackendNativeDisposition::Drained);
    result.unwrap();
}

#[test]
fn segmented_scratch_streams_rows_larger_than_its_explicit_cache() {
    let memory = crate::test_utils::TestDiskMemory::new(32 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let before = memory.snapshot().used_bytes;
    let table = EncryptedTable::new(
        &disk,
        8 << 20,
        CacheConfig {
            byte_limit: 64 << 10,
        },
    )
    .unwrap();
    for ordinal in 0u32..128 {
        table
            .insert(&ordinal.to_be_bytes(), &vec![ordinal as u8; 4096])
            .unwrap();
    }
    let mut seen = 0u32;
    table
        .visit(|key, value| {
            assert_eq!(key, seen.to_be_bytes());
            assert_eq!(value, vec![seen as u8; 4096]);
            seen += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(seen, 128);
    assert_eq!(
        table.get(&93u32.to_be_bytes()).unwrap().as_deref(),
        Some(vec![93; 4096].as_slice())
    );
    assert_eq!(disk.snapshot().live_files, 3);
    // No recoverable plaintext path or anonymous-file directory survives.
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    table.close().unwrap();
    drop(table);
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(memory.snapshot().used_bytes, before);
}

#[test]
fn segmented_scratch_limits_aggregate_extents_before_mutation_and_reuses_drained_slots() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 8 << 20, memory.clone());
    let baseline = memory.snapshot();
    let (owner, backend) = owner(&disk, 128 << 10);
    let census_id = owner.census_id();
    let other = GroupFile::directory(1);
    backend.create(DATA).unwrap();
    backend.create(other).unwrap();
    backend.set_len(DATA, 64 << 10).unwrap();
    backend.set_len(other, 64 << 10).unwrap();
    let charged = disk.snapshot().charged_bytes;
    assert_eq!(
        backend.write(DATA, 64 << 10, b"x").unwrap_err().kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(backend.len(DATA).unwrap(), 64 << 10);
    assert_eq!(backend.len(other).unwrap(), 64 << 10);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    owner.check_owner().unwrap();
    backend.unlink(other).unwrap();
    backend.unlink(other).unwrap();
    assert!(!backend.exists(other).unwrap());
    backend.write(DATA, 64 << 10, b"x").unwrap();
    backend.create(GroupFile::directory(2)).unwrap();
    let mut entries = Vec::new();
    let (_, allocations) = measure(|| {
        backend
            .visit_entries(&mut |name| {
                // Count outside this callback in the second pass; this pass proves the
                // backend itself needs no allocated string or census collection.
                assert!(!name.is_empty());
                Ok(())
            })
            .unwrap()
    });
    assert_eq!(allocations, 0);
    backend
        .visit_entries(&mut |name| {
            entries.push(name.to_os_string());
            Ok(())
        })
        .unwrap();
    assert_eq!(entries.len(), 3);
    let (closed, native) = backend.close().into_parts();
    assert_eq!(native, BackendNativeDisposition::Drained);
    closed.unwrap();
    assert!(owner.drained());
    drop((backend, owner));
    assert_eq!(
        memory.storage_census().drain_owner(census_id),
        crate::StorageCensusDisposition::Retired
    );
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[test]
fn segmented_scratch_descriptor_ceiling_is_pre_admitted_and_does_not_open_on_denial() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 8 << 20, memory.clone());
    let baseline = memory.snapshot();
    let (owner, backend) = owner(&disk, 4 << 20);
    let census_id = owner.census_id();
    for id in 1..=group::MAX_FILES as u64 {
        backend.create(GroupFile::segment(id)).unwrap();
    }
    let resident = memory.snapshot().used_bytes;
    let files = disk.snapshot().live_files;
    let (_, allocations) = measure(|| {
        assert_eq!(
            backend
                .create(GroupFile::segment(1_000))
                .unwrap_err()
                .kind(),
            io::ErrorKind::StorageFull
        );
    });
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().live_files, files);
    assert_eq!(memory.snapshot().used_bytes, resident);
    owner.check_owner().unwrap();
    backend.unlink(GroupFile::segment(1)).unwrap();
    backend.create(GroupFile::segment(1_000)).unwrap();
    let (closed, native) = backend.close().into_parts();
    assert_eq!(native, BackendNativeDisposition::Drained);
    closed.unwrap();
    assert!(owner.drained());
    drop((backend, owner));
    assert_eq!(
        memory.storage_census().drain_owner(census_id),
        crate::StorageCensusDisposition::Retired
    );
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[test]
fn scratch_group_metadata_denial_opens_no_file_and_census_callback_failure_is_retryable() {
    let memory = crate::test_utils::TestDiskMemory::new(32 << 20, 64);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 8 << 20, memory.clone());
    let mut leases = Vec::new();
    while let Ok(lease) = disk.memory().clone().reserve_installed(0) {
        leases.push(lease);
    }
    let used = memory.snapshot().used_bytes;
    assert_eq!(
        Owner::new(&disk, 4 << 20).unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(memory.snapshot().used_bytes, used);
    assert_eq!(disk.snapshot().live_files, 0);
    drop(leases);
    let (owner, backend) = owner(&disk, 4 << 20);
    backend.create(DATA).unwrap();
    let mut callbacks = 0;
    assert_eq!(
        backend
            .visit_entries(&mut |_| {
                callbacks += 1;
                Err(io::ErrorKind::Interrupted.into())
            })
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(callbacks, 1);
    owner.check_owner().unwrap();
    backend
        .visit_entries(&mut |_| {
            callbacks += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(callbacks, 3);
    backend.close().into_result().unwrap();
}

#[test]
fn scratch_group_census_releases_owner_lock_for_admission_and_read_callbacks() {
    let memory = crate::test_utils::TestDiskMemory::new(32 << 20, 128);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 8 << 20, memory);
    let (owner, backend) = owner(&disk, 4 << 20);
    backend.create(DATA).unwrap();
    backend.write(DATA, 0, b"row").unwrap();
    let worker_owner = owner.clone();
    let worker_backend = backend.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut callbacks = 0;
        let result = worker_backend.visit_entries(&mut |_| {
            worker_owner
                .check_owner()
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            let lease = worker_owner
                .reserve_workspace(128)
                .map_err(|_| io::ErrorKind::Other)?;
            assert!(worker_backend.exists(DATA)?);
            let mut value = [0; 3];
            worker_backend.read(DATA, 0, &mut value)?;
            assert_eq!(&value, b"row");
            drop(lease);
            callbacks += 1;
            Ok(())
        });
        let _ = sender.send(result.map(|()| callbacks));
    });
    assert_eq!(
        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("scratch census callback deadlocked on its owner")
            .unwrap(),
        2
    );
    worker.join().unwrap();
    owner.check_owner().unwrap();
    backend.close().into_result().unwrap();
}

#[test]
fn scratch_group_census_rejects_namespace_mutation_and_same_slot_reuse_without_restart() {
    let memory = crate::test_utils::TestDiskMemory::new(32 << 20, 128);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 8 << 20, memory);
    let (owner, backend) = owner(&disk, 4 << 20);
    backend.create(DATA).unwrap();
    let added = GroupFile::directory(1);
    let mut callbacks = 0;
    let error = backend
        .visit_entries(&mut |_| {
            callbacks += 1;
            backend.create(added)?;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(callbacks, 1, "a changed census must never restart");
    owner.check_owner().unwrap();

    callbacks = 0;
    let error = backend
        .visit_entries(&mut |name| {
            callbacks += 1;
            if name != kasumi_kv::ROOT_FILE_NAME {
                backend.unlink(DATA)?;
                backend.create(DATA)?;
            }
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(
        callbacks, 2,
        "same-name reuse invalidates an in-progress census"
    );
    owner.check_owner().unwrap();

    callbacks = 0;
    backend
        .visit_entries(&mut |_| {
            callbacks += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(callbacks, 3);
    backend.close().into_result().unwrap();
}

#[path = "scratch_table_workspace_tests.rs"]
mod workspace_tests;

#[path = "scratch_table_value_tests.rs"]
mod value_tests;

#[test]
fn batch_reuses_one_real_typed_table_instead_of_repeating_cold_catalog_reads() {
    let memory = crate::test_utils::TestDiskMemory::new(64 << 20, 32);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let table = EncryptedTable::new(&disk, 8 << 20, CacheConfig { byte_limit: 0 }).unwrap();
    let loads = || table.owner.database().cache_stats().unwrap().uncached_loads;

    // Both executions use this exact committed empty root, real native type
    // validation and duplicate lookup, with caching disabled. Aborting the
    // first transaction leaves the same authoritative input for the second.
    let mut batch = table.begin_batch().unwrap();
    let before = loads();
    for index in 0..EncryptedTableBatch::MAX_ENTRIES {
        batch.insert(&index.to_be_bytes(), b"value").unwrap();
    }
    let reused = loads() - before;
    drop(batch);

    let transaction = table.owner.database().begin_write().unwrap();
    let before_open = loads();
    drop(transaction.open_table(TABLE).unwrap());
    let one_open = loads() - before_open;
    assert!(
        one_open > 0,
        "the control must perform real cold type/catalog reads"
    );
    let before = loads();
    for index in 0..EncryptedTableBatch::MAX_ENTRIES {
        let mut reopened = transaction.open_table(TABLE).unwrap();
        assert!(
            reopened
                .insert(index.to_be_bytes().as_slice(), b"value")
                .unwrap()
                .is_none()
        );
    }
    let reopened = loads() - before;
    assert_eq!(
        reopened - reused,
        EncryptedTableBatch::MAX_ENTRIES as u64 * one_open,
        "every extra open repeats the same authenticated catalog work"
    );
    drop(transaction);
    // Including the retained batch's one constructor open still eliminates
    // MAX_ENTRIES - 1 metadata opens over a complete batch.
    assert!(reused + one_open < reopened);
    assert_eq!(table.get(&0usize.to_be_bytes()).unwrap(), None);
    table.close().unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn retained_batch_table_rejects_a_duplicate_committed_by_an_earlier_batch() {
    let memory = crate::test_utils::TestDiskMemory::new(64 << 20, 32);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let table = EncryptedTable::new(&disk, 8 << 20, CACHE).unwrap();
    let mut first = table.begin_batch().unwrap();
    first.insert(b"identity", b"first").unwrap();
    first.commit().unwrap();
    let mut second = table.begin_batch().unwrap();
    second.insert(b"unpublished", b"candidate").unwrap();
    assert_eq!(
        second
            .insert(b"identity", b"replacement")
            .unwrap_err()
            .to_string(),
        "duplicate staged key"
    );
    assert_eq!(
        second.commit().unwrap_err().to_string(),
        "staging batch previously failed"
    );
    assert_eq!(
        table.get(b"identity").unwrap().as_deref(),
        Some(b"first".as_slice())
    );
    assert_eq!(table.get(b"unpublished").unwrap(), None);
    table.close().unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn retained_batch_table_preserves_exact_byte_bound_and_abort_before_publication() {
    let memory = crate::test_utils::TestDiskMemory::new(64 << 20, 32);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let table = EncryptedTable::new(&disk, 8 << 20, CacheConfig { byte_limit: 0 }).unwrap();
    let value = vec![19; EncryptedTableBatch::MAX_BYTES - 1];
    let mut batch = table.begin_batch().unwrap();
    batch.insert(b"k", &value).unwrap();
    assert_eq!(
        batch.insert(b"x", b"").unwrap_err().to_string(),
        "staging batch capacity exceeded"
    );
    assert_eq!(
        batch.commit().unwrap_err().to_string(),
        "staging batch previously failed"
    );
    assert_eq!(table.get(b"k").unwrap(), None);
    let mut retry = table.begin_batch().unwrap();
    retry.insert(b"k", &value).unwrap();
    retry.commit().unwrap();
    assert_eq!(table.get(b"k").unwrap().as_deref(), Some(value.as_slice()));
    table.close().unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn retained_typed_table_checks_the_current_native_owner_on_every_insert() {
    let memory = crate::test_utils::TestDiskMemory::new(64 << 20, 32);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
    let (owner, backend) = owner(&disk, 8 << 20);
    let database = kasumi_kv::Database::builder(owner.clone(), GROUP, CACHE)
        .create_with_backend(backend)
        .unwrap();
    let table = EncryptedTable::initialize(database, owner.clone()).unwrap();
    let mut batch = table.begin_batch().unwrap();
    batch.insert(b"first", b"unpublished").unwrap();
    owner.owner_failed();
    let error = batch.insert(b"later", b"forbidden").unwrap_err();
    assert!(
        error.downcast_ref::<kasumi_kv::TableError>().is_some(),
        "actual native owner refusal: {error:?}"
    );
    assert_eq!(
        batch.commit().unwrap_err().to_string(),
        "staging batch previously failed"
    );
    let close = table.close().unwrap_err();
    assert_eq!(close.completion(), DrainCompletion::Retained);
    let charged = disk.snapshot().charged_bytes;
    let files = disk.snapshot().live_files;
    assert!(charged > 0 && files > 0);
    drop(table);
    drop(owner);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert_eq!(disk.snapshot().live_files, files);
}

// Arm the actual batch grant before opening the native table, whose transient
// type/catalog probes make later reservations. Continue through the production
// constructor so the test retains the same table, snapshot and failure owners.
fn batch_with_retirement_panic(
    table: &EncryptedTable,
    memory: &crate::test_utils::TestDiskMemory,
    payload: u64,
) -> EncryptedTableBatch {
    let transaction = table.owner.database().begin_write().unwrap();
    let lease = table
        .owner
        .admission
        .reserve_workspace(batch_workspace_bytes().unwrap())
        .unwrap();
    memory.panic_on_last_point_lease_drop(Box::new(payload));
    table
        .open_batch(
            transaction,
            BatchMemory {
                link: Some(Box::new(BatchMemoryLink { lease, next: None })),
                owner: table.owner.clone(),
            },
        )
        .unwrap()
}

#[test]
fn independently_failed_live_batches_keep_each_real_table_and_shell_charge() {
    use kasumi_kv::{ProtectedReadRequests, WriteTransaction};
    const SLOTS: usize = 32;
    let memory = crate::test_utils::TestDiskMemory::new(64 << 20, SLOTS);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let table = EncryptedTable::new(&disk, 8 << 20, CacheConfig { byte_limit: 0 }).unwrap();
    let baseline = memory.snapshot();
    let native_charge = |request| {
        memory
            .quote_installed(group::workspace_provider_request_bytes(request).unwrap())
            .unwrap()
    };
    let snapshot_requests = [
        native_charge(ProtectedReadRequests::snapshot_backing_request_bytes()),
        native_charge(ProtectedReadRequests::pin_backing_request_bytes()),
    ];
    let (read, observed_read) = crate::test_utils::source_quote_observer::measure(&memory, || {
        table.owner.database().begin_read().unwrap()
    });
    assert!(!observed_read.overflow);
    assert_eq!(observed_read.refused_count, 0);
    assert_eq!(observed_read.count, snapshot_requests.len());
    assert_eq!(
        &observed_read.requests[..observed_read.count],
        &snapshot_requests
    );
    assert_eq!(
        memory.snapshot().live_reservations - baseline.live_reservations,
        snapshot_requests.len()
    );
    assert_eq!(
        memory.snapshot().used_bytes - baseline.used_bytes,
        snapshot_requests.iter().sum::<u64>()
    );
    drop(read);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);

    // A writer keeps the same two snapshot allocations and the separate
    // admitted SharedPending control. Every request is the actual native quote
    // wrapped by this installed scratch provider, rather than an unknown slot.
    let write_requests = [
        snapshot_requests[0],
        snapshot_requests[1],
        native_charge(WriteTransaction::staging_backing_request_bytes()),
    ];
    let (native_transaction, observed_write) =
        crate::test_utils::source_quote_observer::measure(&memory, || {
            table.owner.database().begin_write().unwrap()
        });
    assert!(!observed_write.overflow);
    assert_eq!(observed_write.refused_count, 0);
    assert_eq!(observed_write.count, write_requests.len());
    assert_eq!(
        &observed_write.requests[..observed_write.count],
        &write_requests
    );
    let native = memory.snapshot();
    assert_eq!(
        native.live_reservations - baseline.live_reservations,
        write_requests.len()
    );
    assert_eq!(
        native.used_bytes - baseline.used_bytes,
        write_requests.iter().sum::<u64>()
    );
    drop(native_transaction);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    let exhaust = || {
        let remaining = SLOTS - memory.snapshot().live_reservations;
        let blockers = (0..remaining)
            .map(|_| memory.clone().reserve_installed(0).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(memory.snapshot().live_reservations, SLOTS);
        blockers
    };
    let shell_charge = native_charge(batch_workspace_bytes().unwrap());
    let name_charge =
        native_charge(ProtectedReadRequests::table_name_backing_bytes(TABLE.name().len()).unwrap());
    let retained_requests = write_requests.len() + 2;
    let retained_bytes = write_requests.iter().sum::<u64>() + shell_charge + name_charge;
    let (mut first, admitted) =
        crate::test_utils::source_quote_observer::measure(&memory, || table.begin_batch().unwrap());
    assert!(!admitted.overflow);
    assert_eq!(admitted.refused_count, 0);
    assert!(admitted.requests[..admitted.count].starts_with(&write_requests));
    assert_eq!(admitted.requests[write_requests.len()], shell_charge);
    assert_eq!(admitted.requests[admitted.count - 1], name_charge);
    assert_eq!(
        memory.snapshot().live_reservations - baseline.live_reservations,
        retained_requests
    );
    assert_eq!(
        memory.snapshot().used_bytes - baseline.used_bytes,
        retained_bytes
    );
    let blockers = exhaust();
    assert!(first.insert(b"first", b"unpublished").is_err());
    drop(blockers);
    let one_failed = memory.snapshot();
    // Native denial has released the writer gate, but this failed batch and
    // its real typed table/snapshot remain owned by the caller.
    let mut second = table.begin_batch().unwrap();
    let blockers = exhaust();
    assert!(second.insert(b"second", b"unpublished").is_err());
    drop(blockers);
    let two_failed = memory.snapshot();
    // Each failed facade still owns those exact snapshot, pending, name and
    // shell grants, even after native denial releases the writer gate.
    assert_eq!(
        one_failed.live_reservations - baseline.live_reservations,
        retained_requests
    );
    assert_eq!(one_failed.used_bytes - baseline.used_bytes, retained_bytes);
    assert_eq!(
        two_failed.live_reservations - one_failed.live_reservations,
        retained_requests
    );
    assert_eq!(
        two_failed.used_bytes - one_failed.used_bytes,
        retained_bytes
    );
    assert!(one_failed.used_bytes - baseline.used_bytes >= batch_workspace_bytes().unwrap());
    drop(first);
    let remaining = memory.snapshot();
    assert_eq!(remaining.live_reservations, one_failed.live_reservations);
    assert_eq!(remaining.used_bytes, one_failed.used_bytes);
    assert_eq!(
        second.commit().unwrap_err().to_string(),
        "staging batch previously failed"
    );
    let retired = memory.snapshot();
    assert_eq!(retired.live_reservations, baseline.live_reservations);
    assert_eq!(retired.used_bytes, baseline.used_bytes);
    table.insert(b"retry", b"committed").unwrap();
    assert_eq!(table.get(b"first").unwrap(), None);
    assert_eq!(table.get(b"second").unwrap(), None);
    assert_eq!(
        table.get(b"retry").unwrap().as_deref(),
        Some(b"committed".as_slice())
    );
    table.close().unwrap();
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn batch_open_retirement_keeps_actual_type_error_and_actual_lease_panic() {
    let memory = crate::test_utils::TestDiskMemory::new(64 << 20, 32);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let (admission, backend) = owner(&disk, 8 << 20);
    let database =
        kasumi_kv::Database::builder(admission.clone(), GROUP, CacheConfig { byte_limit: 0 })
            .create_with_backend(backend)
            .unwrap();
    let transaction = database.begin_write().unwrap();
    transaction
        .open_table(TableDefinition::<u64, u64>::new(TABLE.name()))
        .unwrap();
    transaction.commit().unwrap();
    let table = creation::initialize_without_table_setup(database, admission).unwrap();
    let transaction = table.owner.database().begin_write().unwrap();
    let lease = table
        .owner
        .admission
        .reserve_workspace(batch_workspace_bytes().unwrap())
        .unwrap();
    memory.panic_on_last_point_lease_drop(Box::new(0xbaa1_u64));
    // This is the production constructor continuation, using the exact real
    // grant and transaction. The native table metadata really has wrong types.
    let error = match table.open_batch(
        transaction,
        BatchMemory {
            link: Some(Box::new(BatchMemoryLink { lease, next: None })),
            owner: table.owner.clone(),
        },
    ) {
        Ok(_) => panic!("wrong native table types accepted"),
        Err(error) => error,
    };
    let failure = error
        .downcast_ref::<ScratchBatchRetirementFailure>()
        .unwrap();
    assert!(
        matches!(failure.original.as_ref().unwrap().downcast_ref::<kasumi_kv::TableError>(), Some(kasumi_kv::TableError::TypeMismatch(name)) if name == TABLE.name())
    );
    assert_eq!(
        failure._payload.lock().unwrap().downcast_ref::<u64>(),
        Some(&0xbaa1)
    );
    assert!(Arc::ptr_eq(&failure._owner, &table.owner));
    assert_eq!(
        table.close().unwrap_err().completion(),
        DrainCompletion::Retained
    );
    let charged = disk.snapshot().charged_bytes;
    assert!(charged > 0);
    drop(error);
    drop(table);
    assert_eq!(disk.snapshot().charged_bytes, charged);
}

#[test]
fn batch_commit_retirement_keeps_failed_and_successful_native_outcomes_unknown() {
    for mode in 0..3 {
        let memory = crate::test_utils::TestDiskMemory::new(64 << 20, 32);
        let directory = crate::test_utils::private_tempdir().unwrap();
        let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
        let table = EncryptedTable::new(&disk, 8 << 20, CacheConfig { byte_limit: 0 }).unwrap();
        let mut batch = batch_with_retirement_panic(&table, &memory, 0xbaa2);
        match mode {
            0 => assert!(batch.insert(&[0; 4097], b"invalid").is_err()),
            1 => table.owner.admission.owner_failed(),
            _ => {}
        }
        let error = batch.commit().unwrap_err();
        let failure = error
            .downcast_ref::<ScratchBatchRetirementFailure>()
            .unwrap();
        match mode {
            0 => assert_eq!(
                failure.original.as_ref().unwrap().to_string(),
                "staging batch previously failed"
            ),
            1 => assert!(
                failure
                    .original
                    .as_ref()
                    .unwrap()
                    .downcast_ref::<kasumi_kv::CommitError>()
                    .is_some()
            ),
            _ => assert!(
                failure.original.is_none(),
                "native success cannot be reported as clean retirement"
            ),
        }
        assert_eq!(
            failure._payload.lock().unwrap().downcast_ref::<u64>(),
            Some(&0xbaa2)
        );
        assert!(Arc::ptr_eq(&failure._owner, &table.owner));
        assert_eq!(
            table.close().unwrap_err().completion(),
            DrainCompletion::Retained
        );
        let charged = disk.snapshot().charged_bytes;
        assert!(charged > 0);
        drop(error);
        drop(table);
        assert_eq!(disk.snapshot().charged_bytes, charged);
    }
}

#[test]
fn raw_batch_cancellation_fences_the_actual_owner_before_retirement_unwinds() {
    let memory = crate::test_utils::TestDiskMemory::new(64 << 20, 32);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let table = EncryptedTable::new(&disk, 8 << 20, CacheConfig { byte_limit: 0 }).unwrap();
    let batch = batch_with_retirement_panic(&table, &memory, 0xbaa3);
    drop(table);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(batch))).unwrap_err();
    assert_eq!(panic.downcast_ref::<u64>(), Some(&0xbaa3));
    assert!(disk.snapshot().charged_bytes > 0);
    assert!(disk.snapshot().live_files > 0);
}

#[test]
fn an_existing_unwind_keeps_the_actual_batch_lease_unentered_and_charged() {
    let memory = crate::test_utils::TestDiskMemory::new(64 << 20, 32);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let table = EncryptedTable::new(&disk, 8 << 20, CacheConfig { byte_limit: 0 }).unwrap();
    let baseline = memory.snapshot();
    let batch = batch_with_retirement_panic(&table, &memory, 0xbaa4);
    let lease_address = batch._memory.link.as_ref().unwrap().lease.as_ref()
        as *const dyn kasumi_kv::ResidentLease as *const () as usize;
    let first = Box::new(0xbaa5_u64);
    let first_address = first.as_ref() as *const u64 as usize;
    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _batch = batch;
        std::panic::resume_unwind(first);
    }))
    .unwrap_err();
    assert_eq!(first.downcast_ref::<u64>(), Some(&0xbaa5));
    assert_eq!(
        first.downcast_ref::<u64>().unwrap() as *const u64 as usize,
        first_address
    );
    {
        let retained = table.owner.retained_batches.lock();
        let link = retained
            .as_ref()
            .expect("actual lease linked before callback");
        assert!(link.next.is_none());
        assert_eq!(
            link.lease.as_ref() as *const dyn kasumi_kv::ResidentLease as *const () as usize,
            lease_address
        );
    }
    // The probe releases its real ledger slot BEFORE it panics. This exact
    // still-live slot therefore proves the armed second callback never ran.
    let deferred = memory.snapshot();
    assert_eq!(deferred.live_reservations, baseline.live_reservations + 1);
    assert!(deferred.used_bytes >= baseline.used_bytes + batch_workspace_bytes().unwrap());
    assert!(table.owner.admission.check_owner().is_err());
    assert_eq!(
        table.close().unwrap_err().completion(),
        DrainCompletion::Retained
    );
    let charged = disk.snapshot().charged_bytes;
    assert!(charged > 0);
    drop(table);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert_eq!(
        memory.snapshot().live_reservations,
        deferred.live_reservations
    );
    assert_eq!(memory.snapshot().used_bytes, deferred.used_bytes);
}
