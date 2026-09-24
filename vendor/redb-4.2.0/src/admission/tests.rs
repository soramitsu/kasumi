use super::*;
#[cfg(feature = "experimental-api-5")]
use crate::ReadableTable;
use crate::{
    CloseError, CommitError, Database, DatabaseError, ReadableDatabase, ReadableTableMetadata,
    StorageError, TableDefinition, TransactionError,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("data");

#[derive(Debug)]
struct Owner {
    maximum: AtomicU64,
    failed: AtomicBool,
    failures: AtomicU64,
    settled: AtomicU64,
    reservations: AtomicU64,
    workspace_denied: AtomicBool,
    workspace_calls: AtomicU64,
}
impl Owner {
    fn new(maximum: u64) -> Arc<Self> {
        Arc::new(Self {
            maximum: AtomicU64::new(maximum),
            failed: AtomicBool::new(false),
            failures: AtomicU64::new(0),
            settled: AtomicU64::new(0),
            reservations: AtomicU64::new(0),
            workspace_denied: AtomicBool::new(false),
            workspace_calls: AtomicU64::new(0),
        })
    }
}
impl StorageAdmission for Owner {
    fn reserve_workspace(
        &self,
        _bytes: u64,
    ) -> core::result::Result<Box<dyn crate::ResidentLease>, crate::AdmissionError> {
        self.workspace_calls.fetch_add(1, Ordering::Relaxed);
        if self.workspace_denied.load(Ordering::Acquire) {
            return Err(crate::AdmissionError::CapacityDenied);
        }
        self.check_owner()
            .map_err(|_| crate::AdmissionError::OwnerFailed)?;
        Ok(Box::new(()))
    }
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_growth(&self, current: u64, requested: u64) -> Result<(), AdmissionError> {
        self.reservations.fetch_add(1, Ordering::Relaxed);
        assert!(requested > current);
        if requested > self.maximum.load(Ordering::Relaxed) {
            Err(AdmissionError::CapacityDenied)
        } else {
            Ok(())
        }
    }
    fn settle_growth(&self, actual: u64) -> Result<(), OwnerFailed> {
        self.settled.store(actual, Ordering::Release);
        Ok(())
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
}
fn create(file: &tempfile::NamedTempFile, owner: Arc<Owner>) -> Database {
    Database::builder(owner)
        .set_page_size(512)
        .set_region_size(16 << 10)
        .create(file.path())
        .unwrap()
}
fn open(file: &tempfile::NamedTempFile, owner: Arc<Owner>) -> Database {
    Database::builder(owner)
        .set_page_size(512)
        .set_region_size(16 << 10)
        .open(file.path())
        .unwrap()
}
fn seed(db: &Database) {
    let write = db.begin_write().unwrap();
    write
        .open_table(TABLE)
        .unwrap()
        .insert(0, b"committed".as_slice())
        .unwrap();
    write.commit().unwrap();
}
fn verify(db: &Database) {
    let read = db.begin_read().unwrap();
    let table = read.open_table(TABLE).unwrap();
    assert_eq!(table.get(0).unwrap().unwrap().value(), b"committed");
    assert!(table.get(1).unwrap().is_none());
}
#[test]
fn construction_denial_never_grows_or_fails_owner() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(0);
    assert!(matches!(
        Database::create(file.path(), owner.clone()),
        Err(DatabaseError::Storage(StorageError::CapacityDenied))
    ));
    assert_eq!(file.as_file().metadata().unwrap().len(), 0);
    assert_eq!(owner.failures.load(Ordering::Relaxed), 0);
}
#[test]
fn direct_header_workspace_denial_precedes_create_file_mutation() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(u64::MAX);
    owner.workspace_denied.store(true, Ordering::Release);
    assert!(matches!(
        Database::builder(owner.clone()).create(file.path()),
        Err(DatabaseError::Storage(StorageError::CapacityDenied))
    ));
    assert!(owner.workspace_calls.load(Ordering::Relaxed) >= 1);
    assert_eq!(file.as_file().metadata().unwrap().len(), 0);
    assert_eq!(owner.failures.load(Ordering::Relaxed), 0);
    owner.workspace_denied.store(false, Ordering::Release);
    let db = create(&file, owner.clone());
    seed(&db);
    db.close().unwrap();
    let before = std::fs::read(file.path()).unwrap();
    owner.workspace_denied.store(true, Ordering::Release);
    assert!(matches!(
        Database::builder(owner.clone()).open(file.path()),
        Err(DatabaseError::Storage(StorageError::CapacityDenied))
    ));
    assert_eq!(std::fs::read(file.path()).unwrap(), before);
    assert_eq!(owner.failures.load(Ordering::Relaxed), 0);
}
#[test]
fn caught_capacity_denial_aborts_all_tables_and_keeps_pinned_read_root() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(u64::MAX);
    let db = create(&file, owner.clone());
    seed(&db);
    let pinned = db.begin_read().unwrap();
    owner
        .maximum
        .store(file.as_file().metadata().unwrap().len(), Ordering::Relaxed);
    let write = db.begin_write().unwrap();
    let mut denied = false;
    {
        let mut table = write.open_table(TABLE).unwrap();
        for key in 1..256 {
            match table.insert(key, [17; 4096].as_slice()) {
                Ok(_) => {}
                Err(StorageError::CapacityDenied) => {
                    denied = true;
                    break;
                }
                Err(error) => panic!("unexpected {error:?}"),
            }
        }
    }
    assert!(denied);
    assert!(matches!(
        write.commit(),
        Err(CommitError::Storage(StorageError::CapacityDenied))
    ));
    verify(&db);
    assert_eq!(
        pinned
            .open_table(TABLE)
            .unwrap()
            .get(0)
            .unwrap()
            .unwrap()
            .value(),
        b"committed"
    );
    assert_eq!(owner.failures.load(Ordering::Relaxed), 0);
    assert_eq!(
        owner.settled.load(Ordering::Acquire),
        file.as_file().metadata().unwrap().len()
    );
    drop(pinned);
    db.close().unwrap();
    let reopened = open(&file, owner);
    verify(&reopened);
    reopened.close().unwrap();
}
#[test]
fn explicit_close_returns_busy_owner_and_drop_does_not_reserve_checkpoint_growth() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(u64::MAX);
    let db = create(&file, owner.clone());
    seed(&db);
    let read = db.begin_read().unwrap();
    let db = match db.close() {
        Err(CloseError::Busy(db)) => db,
        other => panic!("{other:?}"),
    };
    drop(read);
    let before = owner.reservations.load(Ordering::Relaxed);
    drop(db);
    assert_eq!(owner.reservations.load(Ordering::Relaxed), before);
    let reopened = open(&file, owner);
    verify(&reopened);
    reopened.close().unwrap();
}
#[test]
fn commit_metadata_denial_rolls_back_before_winning_header() {
    let mut saw_denial = false;
    for entries in [1024, 1536, 1792, 1920, 1984, 2016, 2040] {
        let file = tempfile::NamedTempFile::new().unwrap();
        let owner = Owner::new(u64::MAX);
        let db = create(&file, owner.clone());
        seed(&db);
        let write = db.begin_write().unwrap();
        {
            let mut table = write.open_table(TABLE).unwrap();
            for key in 1..=entries {
                table.insert(key, [31; 350].as_slice()).unwrap();
            }
        }
        owner
            .maximum
            .store(file.as_file().metadata().unwrap().len(), Ordering::Relaxed);
        match write.commit() {
            Err(CommitError::Storage(StorageError::CapacityDenied)) => {
                saw_denial = true;
                verify(&db);
                assert_eq!(owner.failures.load(Ordering::Relaxed), 0);
                db.close().unwrap();
                let reopened = open(&file, owner);
                verify(&reopened);
                reopened.close().unwrap();
                break;
            }
            Ok(()) => db.close().unwrap(),
            Err(error) => panic!("unexpected commit result {error:?}"),
        }
    }
    assert!(
        saw_denial,
        "bounded workload must hit commit-preparation growth"
    );
}

#[derive(Debug, Default)]
struct Faults {
    header_writes: AtomicU64,
    observe_winner: AtomicBool,
    fail_header: AtomicU64,
    syncs: AtomicU64,
    fail_sync: AtomicU64,
    closes: AtomicU64,
    fail_close: AtomicBool,
}
#[derive(Debug)]
struct FaultBackend {
    file: crate::backends::FileBackend,
    faults: Arc<Faults>,
}
impl crate::StorageBackend for FaultBackend {
    fn len(&self) -> std::io::Result<u64> {
        self.file.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
        self.file.read(offset, out)
    }
    fn set_len(&self, len: u64) -> std::io::Result<()> {
        self.file.set_len(len)
    }
    fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        self.file.write(offset, data)?;
        if offset == 0 {
            let count = self.faults.header_writes.fetch_add(1, Ordering::Relaxed) + 1;
            if count == 2 && self.faults.observe_winner.load(Ordering::Relaxed) {
                begin_allocation_observation();
            }
            if count == self.faults.fail_header.load(Ordering::Relaxed) {
                return Err(std::io::Error::from(std::io::ErrorKind::Other));
            }
        }
        Ok(())
    }
    fn sync_data(&self) -> std::io::Result<()> {
        let count = self.faults.syncs.fetch_add(1, Ordering::Relaxed) + 1;
        if count == self.faults.fail_sync.load(Ordering::Relaxed) {
            return Err(std::io::Error::from(std::io::ErrorKind::Other));
        }
        self.file.sync_data()
    }
    fn close(&self) -> crate::BackendCloseOutcome {
        self.faults.closes.fetch_add(1, Ordering::Relaxed);
        let outcome = self.file.close();
        if self.faults.fail_close.load(Ordering::Relaxed)
            && matches!(
                outcome.native_disposition(),
                crate::BackendNativeDisposition::Drained
            )
        {
            let (result, _) = outcome.into_parts();
            return crate::BackendCloseOutcome::drained(
                result.and_then(|()| Err(std::io::ErrorKind::Other.into())),
            );
        }
        outcome
    }
}
fn fault_database(
    file: &tempfile::NamedTempFile,
    owner: Arc<Owner>,
    faults: Arc<Faults>,
) -> Database {
    Database::builder(owner)
        .set_page_size(512)
        .set_region_size(16 << 10)
        .create_with_backend(FaultBackend {
            file: crate::backends::FileBackend::new(file.reopen().unwrap()).unwrap(),
            faults,
        })
        .unwrap()
}
#[test]
fn publication_and_sync_uncertainty_fences_once_and_reopens_an_atomic_root() {
    for (header, sync) in [(1, 0), (2, 0), (0, 1), (0, 2), (0, 3), (0, 4)] {
        let file = tempfile::NamedTempFile::new().unwrap();
        let owner = Owner::new(u64::MAX);
        let faults = Arc::new(Faults::default());
        let db = fault_database(&file, owner.clone(), faults.clone());
        seed(&db);
        let write = db.begin_write().unwrap();
        write
            .open_table(TABLE)
            .unwrap()
            .insert(1, b"replacement".as_slice())
            .unwrap();
        faults.header_writes.store(0, Ordering::Relaxed);
        faults.syncs.store(0, Ordering::Relaxed);
        faults.fail_header.store(header, Ordering::Relaxed);
        faults.fail_sync.store(sync, Ordering::Relaxed);
        assert!(matches!(
            write.commit(),
            Err(CommitError::Storage(StorageError::Io(error)))
                if error.kind() == std::io::ErrorKind::Other
        ));
        assert!(matches!(
            db.begin_write(),
            Err(TransactionError::Storage(StorageError::OwnerFailed))
        ));
        assert!(matches!(
            db.begin_read(),
            Err(TransactionError::Storage(StorageError::OwnerFailed))
        ));
        assert_eq!(owner.failures.load(Ordering::Relaxed), 1);
        drop(db);
        assert_eq!(faults.closes.load(Ordering::Relaxed), 1);
        let reopened = open(&file, Owner::new(u64::MAX));
        let read = reopened.begin_read().unwrap();
        let table = read.open_table(TABLE).unwrap();
        assert_eq!(table.get(0).unwrap().unwrap().value(), b"committed");
        if let Some(value) = table.get(1).unwrap() {
            assert_eq!(value.value(), b"replacement");
        }
        drop(table);
        drop(read);
        reopened.close().unwrap();
    }
}
#[test]
fn explicit_close_propagates_failure_and_never_closes_backend_twice() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(u64::MAX);
    let faults = Arc::new(Faults::default());
    let db = fault_database(&file, owner.clone(), faults.clone());
    seed(&db);
    faults.fail_close.store(true, Ordering::Relaxed);
    assert!(matches!(
        db.close(),
        Err(CloseError::Storage(StorageError::Io(error)))
            if error.kind() == std::io::ErrorKind::Other
    ));
    assert_eq!(faults.closes.load(Ordering::Relaxed), 1);
    assert_eq!(owner.failures.load(Ordering::Relaxed), 1);
}
#[test]
fn both_abort_forms_retain_successful_growth_and_permit_later_writes() {
    for explicit in [false, true] {
        let file = tempfile::NamedTempFile::new().unwrap();
        let owner = Owner::new(u64::MAX);
        let db = create(&file, owner.clone());
        seed(&db);
        let old_extent = file.as_file().metadata().unwrap().len();
        let write = db.begin_write().unwrap();
        {
            let mut table = write.open_table(TABLE).unwrap();
            for key in 1..512 {
                table.insert(key, [77; 4096].as_slice()).unwrap();
            }
        }
        let grown_extent = file.as_file().metadata().unwrap().len();
        assert!(grown_extent > old_extent);
        if explicit {
            write.abort().unwrap();
        } else {
            drop(write);
        }
        assert_eq!(file.as_file().metadata().unwrap().len(), grown_extent);
        assert_eq!(owner.settled.load(Ordering::Acquire), grown_extent);
        assert_eq!(owner.failures.load(Ordering::Relaxed), 0);
        verify(&db);
        let write = db.begin_write().unwrap();
        write
            .open_table(TABLE)
            .unwrap()
            .insert(2, b"subsequent".as_slice())
            .unwrap();
        write.commit().unwrap();
        db.close().unwrap();
    }
}

thread_local! {
    static ALLOCATION_GUARD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
struct ObservedAllocator;
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;
unsafe impl std::alloc::GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        observe_allocation();
        unsafe { std::alloc::System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        observe_allocation();
        unsafe { std::alloc::System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        observe_allocation();
        unsafe { std::alloc::System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }
}
fn observe_allocation() {
    let _ = ALLOCATION_GUARD.try_with(|guard| {
        if guard.get() {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        }
    });
}
pub(super) fn begin_allocation_observation() {
    ALLOCATIONS.with(|count| count.set(0));
    ALLOCATION_GUARD.with(|guard| guard.set(true));
}
pub(super) fn end_allocation_observation() -> usize {
    ALLOCATION_GUARD.with(|guard| guard.set(false));
    ALLOCATIONS.with(std::cell::Cell::get)
}
#[test]
fn winning_header_and_destructor_are_followed_by_no_heap_allocations() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(u64::MAX);
    let faults = Arc::new(Faults::default());
    let db = fault_database(&file, owner.clone(), faults.clone());
    seed(&db);
    let write = db.begin_write().unwrap();
    write
        .open_table(TABLE)
        .unwrap()
        .insert(1, b"new".as_slice())
        .unwrap();
    faults.header_writes.store(0, Ordering::Relaxed);
    faults.observe_winner.store(true, Ordering::Relaxed);
    let outcome = write.commit();
    let publication_allocations = end_allocation_observation();
    outcome.unwrap();
    assert_eq!(publication_allocations, 0);
    begin_allocation_observation();
    drop(db);
    let destructor_allocations = end_allocation_observation();
    assert_eq!(destructor_allocations, 0);
    assert_eq!(owner.failures.load(Ordering::Relaxed), 0);
}

#[test]
fn repeated_reopen_reclaims_deleted_pages_without_leaking_capacity() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(u64::MAX);
    let mut allocated = Vec::new();
    let mut lengths = Vec::new();
    for cycle in 0..12 {
        let db = if cycle == 0 {
            create(&file, owner.clone())
        } else {
            open(&file, owner.clone())
        };
        let write = db.begin_write().unwrap();
        {
            let mut table = write.open_table(TABLE).unwrap();
            for key in 0..128 {
                table.insert(key, [47; 1024].as_slice()).unwrap();
            }
        }
        write.commit().unwrap();
        let write = db.begin_write().unwrap();
        write.delete_table(TABLE).unwrap();
        write.commit().unwrap();
        for _ in 0..3 {
            db.begin_write().unwrap().commit().unwrap();
        }
        let write = db.begin_write().unwrap();
        allocated.push(write.stats().unwrap().allocated_pages());
        write.abort().unwrap();
        db.close().unwrap();
        lengths.push(file.as_file().metadata().unwrap().len());
    }
    assert!(
        allocated[4..]
            .iter()
            .all(|count| *count <= allocated[3] + 2),
        "allocation leak: {allocated:?}"
    );
    assert!(
        lengths[4..].iter().all(|len| *len <= lengths[3]),
        "extent leak: {lengths:?}"
    );
    assert_eq!(owner.failures.load(Ordering::Relaxed), 0);
}

#[test]
fn persistent_savepoints_survive_explicit_close_but_borrowed_handles_block_it() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(u64::MAX);
    let db = create(&file, owner.clone());
    seed(&db);
    let write = db.begin_write().unwrap();
    let saved = write.persistent_savepoint().unwrap();
    write.commit().unwrap();
    db.close().unwrap();
    let db = open(&file, owner);
    let write = db.begin_write().unwrap();
    let handle = write.get_persistent_savepoint(saved).unwrap();
    write.abort().unwrap();
    let db = match db.close() {
        Err(CloseError::Busy(db)) => db,
        result => panic!("unexpected {result:?}"),
    };
    drop(handle);
    db.close().unwrap();
}

#[test]
fn rollback_and_savepoint_publication_do_not_allocate_after_their_fallible_work() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(u64::MAX);
    let faults = Arc::new(Faults::default());
    let db = fault_database(&file, owner.clone(), faults.clone());
    seed(&db);
    let write = db.begin_write().unwrap();
    write
        .open_table(TABLE)
        .unwrap()
        .insert(1, [15; 4096].as_slice())
        .unwrap();
    begin_allocation_observation();
    drop(write);
    let abort_allocations = end_allocation_observation();
    assert_eq!(abort_allocations, 0);
    verify(&db);
    let write = db.begin_write().unwrap();
    let saved = write.persistent_savepoint().unwrap();
    faults.header_writes.store(0, Ordering::Relaxed);
    faults.observe_winner.store(true, Ordering::Relaxed);
    let result = write.commit();
    let allocations = end_allocation_observation();
    result.unwrap();
    assert_eq!(allocations, 0);
    let write = db.begin_write().unwrap();
    write.delete_persistent_savepoint(saved).unwrap();
    faults.header_writes.store(0, Ordering::Relaxed);
    let result = write.commit();
    let allocations = end_allocation_observation();
    result.unwrap();
    assert_eq!(allocations, 0);
    db.close().unwrap();
}

#[test]
fn full_repair_publishes_its_allocator_snapshot_before_returning() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(u64::MAX);
    let db = create(&file, owner.clone());
    seed(&db);
    // Make only the allocator snapshot's generation stale, simulating a
    // recoverable interrupted maintenance state.
    let mem = db.get_memory();
    mem.commit(
        mem.get_data_root(),
        mem.get_system_root(),
        mem.get_last_committed_transaction_id().unwrap().next(),
        crate::tree_store::ShrinkPolicy::Default,
    )
    .unwrap();
    drop(mem);
    drop(db);
    let repaired = open(&file, owner.clone());
    verify(&repaired);
    repaired.close().unwrap();
    let reopened = Database::builder(owner)
        .set_page_size(512)
        .set_region_size(16 << 10)
        .set_repair_callback(|repair| repair.abort())
        .open(file.path())
        .unwrap();
    verify(&reopened);
    reopened.close().unwrap();
}

#[test]
fn read_only_close_retains_busy_database_until_handles_drain() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(u64::MAX);
    let db = Database::create(file.path(), owner.clone()).unwrap();
    seed(&db);
    db.close().unwrap();
    let db = crate::ReadOnlyDatabase::open(file.path(), owner).unwrap();
    let read = db.begin_read().unwrap();
    let db = match db.close() {
        Err(CloseError::Busy(db)) => db,
        result => panic!("unexpected {result:?}"),
    };
    assert_eq!(
        read.open_table(TABLE)
            .unwrap()
            .get(0)
            .unwrap()
            .unwrap()
            .value(),
        b"committed"
    );
    drop(read);
    db.close().unwrap();
}

#[test]
fn uncertain_winning_header_failure_is_nonallocating_and_fences_once() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(u64::MAX);
    let faults = Arc::new(Faults::default());
    let db = fault_database(&file, owner.clone(), faults.clone());
    seed(&db);
    let write = db.begin_write().unwrap();
    write
        .open_table(TABLE)
        .unwrap()
        .insert(1, b"replacement".as_slice())
        .unwrap();
    faults.header_writes.store(0, Ordering::Relaxed);
    faults.fail_header.store(2, Ordering::Relaxed);
    faults.observe_winner.store(true, Ordering::Relaxed);
    let result = write.commit();
    let allocations = end_allocation_observation();
    assert!(matches!(
        result,
        Err(CommitError::Storage(StorageError::Io(error)))
            if error.kind() == std::io::ErrorKind::Other
    ));
    assert_eq!(allocations, 0);
    assert_eq!(owner.failures.load(Ordering::Relaxed), 1);
    begin_allocation_observation();
    drop(db);
    assert_eq!(end_allocation_observation(), 0);
    assert_eq!(faults.closes.load(Ordering::Relaxed), 1);
}

#[test]
fn repair_at_capacity_respects_admission_and_keeps_committed_root() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(u64::MAX);
    let db = create(&file, owner.clone());
    seed(&db);
    let budget = file.as_file().metadata().unwrap().len();
    owner.maximum.store(budget, Ordering::Relaxed);
    let mut committed = 0;
    for batch in 0..256u64 {
        let write = db.begin_write().unwrap();
        let mut denied = false;
        {
            let mut table = write.open_table(TABLE).unwrap();
            for key in batch * 16 + 1..=batch * 16 + 16 {
                match table.insert(key, [19; 350].as_slice()) {
                    Ok(_) => {}
                    Err(StorageError::CapacityDenied) => {
                        denied = true;
                        break;
                    }
                    Err(error) => panic!("unexpected insertion: {error:?}"),
                }
            }
        }
        match write.commit() {
            Ok(()) => committed = batch * 16 + 16,
            Err(CommitError::Storage(StorageError::CapacityDenied)) => break,
            Err(error) => panic!("unexpected commit: {error:?}; prior denial={denied}"),
        }
    }
    assert!(committed > 0);
    let mem = db.get_memory();
    mem.commit(
        mem.get_data_root(),
        mem.get_system_root(),
        mem.get_last_committed_transaction_id().unwrap().next(),
        crate::tree_store::ShrinkPolicy::Default,
    )
    .unwrap();
    drop(mem);
    drop(db);
    let result = Database::builder(owner.clone())
        .set_page_size(512)
        .set_region_size(16 << 10)
        .open(file.path());
    assert!(file.as_file().metadata().unwrap().len() <= budget);
    assert_eq!(owner.failures.load(Ordering::Relaxed), 0);
    let db = match result {
        Ok(db) => db,
        Err(DatabaseError::Storage(StorageError::CapacityDenied)) => {
            owner.maximum.store(u64::MAX, Ordering::Relaxed);
            open(&file, owner)
        }
        Err(error) => panic!("unexpected repair failure: {error:?}"),
    };
    let read = db.begin_read().unwrap();
    let table = read.open_table(TABLE).unwrap();
    assert_eq!(table.get(0).unwrap().unwrap().value(), b"committed");
    assert_eq!(table.get(committed).unwrap().unwrap().value(), [19; 350]);
    assert!(table.get(committed + 1).unwrap().is_none());
    drop(table);
    drop(read);
    db.close().unwrap();
}

#[test]
fn deferred_close_and_empty_transaction_drop_do_not_allocate() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(u64::MAX);
    let db = create(&file, owner);
    let write = db.begin_write().unwrap();
    begin_allocation_observation();
    drop(db);
    drop(write);
    assert_eq!(end_allocation_observation(), 0);
}

#[test]
fn compaction_respects_relocation_allowance_and_retry_physically_shrinks() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let owner = Owner::new(64 << 20);
    let mut db = Database::create(file.path(), owner.clone()).unwrap();
    let value = vec![0x63; 100 << 10];
    let write = db.begin_write().unwrap();
    {
        let mut table = write.open_table(TABLE).unwrap();
        for key in 0..100 {
            table.insert(key, value.as_slice()).unwrap();
        }
    }
    write.commit().unwrap();
    let write = db.begin_write().unwrap();
    {
        let mut table = write.open_table(TABLE).unwrap();
        for key in 0..90 {
            table.remove(key).unwrap();
        }
    }
    write.commit().unwrap();
    db.begin_write().unwrap().commit().unwrap();
    owner
        .maximum
        .store(file.as_file().metadata().unwrap().len(), Ordering::Relaxed);

    // One byte cannot admit either copy of a page. No relocation is attempted.
    assert!(
        !db.compact(core::num::NonZeroUsize::new(1).unwrap())
            .unwrap()
    );
    let before_retry = file.as_file().metadata().unwrap().len();
    assert!(
        db.compact(core::num::NonZeroUsize::new(1 << 20).unwrap())
            .unwrap()
    );
    let after_retry = file.as_file().metadata().unwrap().len();
    assert!(after_retry < before_retry);
    assert_eq!(owner.settled.load(Ordering::Acquire), after_retry);
    assert_eq!(owner.failures.load(Ordering::Relaxed), 0);
    let read = db.begin_read().unwrap();
    let table = read.open_table(TABLE).unwrap();
    assert_eq!(table.len().unwrap(), 10);
    for key in 90..100 {
        assert_eq!(table.get(key).unwrap().unwrap().value(), value.as_slice());
    }
    drop(table);
    drop(read);
    db.close().unwrap();
}
