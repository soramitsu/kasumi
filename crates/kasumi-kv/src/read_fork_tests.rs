//! Real native transaction/fork custody tests. The backend is the existing
//! segmented in-memory disk implementation, not a substitute snapshot model.
#[path = "source_read_tests.rs"]
mod source_reads;
use super::*;
use crate::core::{AdmissionError, OwnerFailed};
use crate::group::InMemoryGroup;
use crate::retained::{
    DatabaseOpenMode, DatabaseOpenSettlement, ReadCloseSettlement, RetainedDatabaseOpening,
    RetainedReadTransaction,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Barrier;
use std::sync::atomic::AtomicU64;

const ROWS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("fork-rows");
const LATE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("later-table");
const BYTE_LIMIT: u64 = 64 << 20;
const SLOT_LIMIT: usize = 64;

// The KV library test binary has no other global allocator. Integration test
// binaries have their own independent allocators. This observer only delegates
// to System and records the one private backing selected by this module.
struct ObservedAllocator;
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;
static WATCH_LOCK: Mutex<()> = Mutex::new(());
static WATCH_BACKING: AtomicUsize = AtomicUsize::new(0);
static WATCH_LEDGER: AtomicUsize = AtomicUsize::new(0);
static WATCH_GRANT: AtomicU64 = AtomicU64::new(0);
static BACKING_FREED: AtomicBool = AtomicBool::new(false);
static WATCH_REFUNDS: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
fn note_allocation() {
    crate::snapshot_pins::allocation_tests::note_allocation();
    let _ = COUNTING.try_with(|enabled| {
        if enabled.get() {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        }
    });
}
fn note_deallocation(pointer: *mut u8, layout: Layout) {
    crate::retained::source_funding_note_deallocation(pointer, layout);
    crate::snapshot_pins::allocation_tests::note_deallocation(pointer, layout);
    let target = WATCH_BACKING.load(Ordering::Acquire);
    let start = pointer as usize;
    if target != 0 && target >= start && target - start < layout.size() {
        BACKING_FREED.store(true, Ordering::Release);
    }
}
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_allocation();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        note_allocation();
        // Snapshot backing is immutable and never reallocated.
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        note_deallocation(pointer, layout);
    }
}
struct AllocationCount;
impl AllocationCount {
    fn start() -> Self {
        ALLOCATIONS.with(|count| count.set(0));
        COUNTING.with(|enabled| assert!(!enabled.replace(true)));
        Self
    }
    fn count(&self) -> usize {
        ALLOCATIONS.with(Cell::get)
    }
}
impl Drop for AllocationCount {
    fn drop(&mut self) {
        COUNTING.with(|enabled| enabled.set(false));
    }
}
struct BackingWatch;
impl BackingWatch {
    fn new(admission: &CountedAdmission, handle: &SnapshotHandle, grant: u64) -> Self {
        BACKING_FREED.store(false, Ordering::Release);
        WATCH_REFUNDS.store(0, Ordering::Release);
        WATCH_GRANT.store(grant, Ordering::Release);
        WATCH_LEDGER.store(Arc::as_ptr(&admission.state) as usize, Ordering::Release);
        WATCH_BACKING.store(
            Arc::as_ptr(handle.0.as_ref().unwrap()) as usize,
            Ordering::Release,
        );
        Self
    }
}
impl Drop for BackingWatch {
    fn drop(&mut self) {
        WATCH_BACKING.store(0, Ordering::Release);
        WATCH_LEDGER.store(0, Ordering::Release);
        WATCH_GRANT.store(0, Ordering::Release);
    }
}

struct Pause {
    admitted: Barrier,
    resume: Barrier,
}
struct Ledger {
    bytes: u64,
    slots: usize,
    max_bytes: u64,
    max_slots: usize,
    next_grant: u64,
    pause: Option<Arc<Pause>>,
    panic_on_drop: Option<u64>,
}
fn ledger_lock(state: &Mutex<Ledger>) -> MutexGuard<'_, Ledger> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct CountedAdmission {
    state: Arc<Mutex<Ledger>>,
    failed: AtomicBool,
}
impl CountedAdmission {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(Mutex::new(Ledger {
                bytes: 0,
                slots: 0,
                max_bytes: BYTE_LIMIT,
                max_slots: SLOT_LIMIT,
                next_grant: 1,
                pause: None,
                panic_on_drop: None,
            })),
            failed: AtomicBool::new(false),
        })
    }
    fn census(&self) -> (u64, usize) {
        let state = ledger_lock(&self.state);
        (state.bytes, state.slots)
    }
    fn limits(&self, bytes: u64, slots: usize) {
        let mut state = ledger_lock(&self.state);
        state.max_bytes = bytes;
        state.max_slots = slots;
    }
    fn last_grant(&self) -> u64 {
        ledger_lock(&self.state).next_grant - 1
    }
}
struct CountedLease {
    state: Arc<Mutex<Ledger>>,
    bytes: u64,
    id: u64,
}
impl Drop for CountedLease {
    fn drop(&mut self) {
        if WATCH_LEDGER.load(Ordering::Acquire) == Arc::as_ptr(&self.state) as usize
            && WATCH_GRANT.load(Ordering::Acquire) == self.id
        {
            assert!(BACKING_FREED.load(Ordering::Acquire));
            WATCH_REFUNDS.fetch_add(1, Ordering::AcqRel);
        }
        let mut state = ledger_lock(&self.state);
        state.bytes = state.bytes.checked_sub(self.bytes).unwrap();
        state.slots = state.slots.checked_sub(1).unwrap();
        let panic = state.panic_on_drop == Some(self.id);
        if panic {
            state.panic_on_drop = None;
        }
        drop(state);
        if panic {
            std::panic::panic_any(0x51ee_u64);
        }
    }
}
impl StorageAdmission for CountedAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let (id, pause) = {
            let mut state = ledger_lock(&self.state);
            let next = state
                .bytes
                .checked_add(bytes)
                .ok_or(AdmissionError::CapacityDenied)?;
            if next > state.max_bytes || state.slots >= state.max_slots {
                return Err(AdmissionError::CapacityDenied);
            }
            state.bytes = next;
            state.slots += 1;
            let id = state.next_grant;
            state.next_grant += 1;
            (id, state.pause.take())
        };
        let lease = Box::new(CountedLease {
            state: self.state.clone(),
            bytes,
            id,
        });
        if let Some(pause) = pause {
            pause.admitted.wait();
            pause.resume.wait();
        }
        Ok(lease)
    }
    fn quote_cache_memory(&self, bytes: u64) -> Result<crate::CacheMemoryQuote, AdmissionError> {
        crate::cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, AdmissionError> {
        crate::cache_test::reserve(self, bytes)
    }
    fn reserve_growth(&self, _current: u64, _requested: u64) -> Result<(), AdmissionError> {
        self.check_owner().map_err(|_| AdmissionError::OwnerFailed)
    }
    fn settle_growth(&self, _actual: u64) -> Result<(), OwnerFailed> {
        self.check_owner()
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }
}
impl crate::cache_test::Provider for CountedAdmission {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let mut state = ledger_lock(&self.state);
        let next = state
            .bytes
            .checked_add(bytes)
            .ok_or(AdmissionError::CapacityDenied)?;
        if next > state.max_bytes || (first && state.slots >= state.max_slots) {
            return Err(AdmissionError::CapacityDenied);
        }
        state.bytes = next;
        state.slots += usize::from(first);
        Ok(())
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        let mut state = ledger_lock(&self.state);
        state.bytes = state.bytes.checked_sub(bytes).unwrap();
        state.slots = state.slots.checked_sub(usize::from(last)).unwrap();
    }
}
fn opening(admission: &Arc<CountedAdmission>) -> RetainedDatabaseOpening {
    let mut opening = Database::builder(admission.clone(), [73; 16], CacheConfig::default())
        .retain_backend(Box::new(InMemoryGroup::new()), DatabaseOpenMode::Create);
    assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
    let writer = opening.database().unwrap().begin_write().unwrap();
    {
        let mut table = writer.open_table(ROWS).unwrap();
        table.insert(b"a".as_slice(), b"old-a".as_slice()).unwrap();
        table.insert(b"b".as_slice(), b"old-b".as_slice()).unwrap();
    }
    writer.commit().unwrap();
    opening
}
fn close_reader(opening: &RetainedDatabaseOpening, reader: &mut RetainedReadTransaction) {
    let owner = opening.retained_database().unwrap();
    assert_eq!(
        reader.close(owner).settlement(),
        ReadCloseSettlement::Settled
    );
    assert_eq!(
        reader.dispose_settled(owner).settlement(),
        ReadCloseSettlement::Disposed
    );
}
fn finish(mut opening: RetainedDatabaseOpening, admission: &CountedAdmission) {
    assert_eq!(opening.close().settlement(), DatabaseOpenSettlement::Closed);
    drop(opening);
    assert_eq!(admission.census(), (0, 0));
}
fn assert_capacity(result: Result<ReadTransaction, TransactionError>) {
    assert!(matches!(
        result,
        Err(TransactionError(StorageError::Core(
            CoreError::CapacityDenied
        )))
    ));
}

#[test]
fn selected_snapshot_fork_keeps_old_root_after_update_delete_and_parent_drop() {
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let database = opening.database().unwrap();
    let parent = database.begin_read().unwrap();
    let old_generation = parent.snapshot.generation();
    let writer = database.begin_write().unwrap();
    {
        let mut rows = writer.open_table(ROWS).unwrap();
        rows.insert(b"a".as_slice(), b"new-a".as_slice()).unwrap();
        rows.delete_key(b"b".as_slice()).unwrap();
        writer.open_table(LATE).unwrap();
    }
    writer.commit().unwrap();
    // Fork AFTER publication. A fresh snapshot here would observe the wrong
    // value, tombstone and table catalog.
    let child = parent.fork().unwrap();
    assert_eq!(child.snapshot.generation(), old_generation);
    assert!(!Arc::ptr_eq(
        parent.snapshot.0.as_ref().unwrap(),
        child.snapshot.0.as_ref().unwrap()
    ));
    assert!(!parent.has_snapshot_descendants());
    assert!(!child.has_snapshot_descendants());
    drop(parent);
    let grandchild = child.fork().unwrap();
    drop(child);
    database.inner.core.compact().unwrap();
    assert_eq!(
        grandchild
            .get_bytes(ROWS.name(), b"a", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"old-a"
    );
    assert_eq!(
        grandchild
            .get_bytes(ROWS.name(), b"b", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"old-b"
    );
    assert!(matches!(
        grandchild.open_table(LATE),
        Err(TableError::DoesNotExist(_))
    ));
    let current = database.begin_read().unwrap();
    assert_eq!(
        current
            .get_bytes(ROWS.name(), b"a", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"new-a"
    );
    assert!(current.get_bytes(ROWS.name(), b"b", 32).unwrap().is_none());
    assert!(current.open_table(LATE).is_ok());
    drop(current);
    drop(grandchild);
    finish(opening, &admission);
}

#[test]
fn selected_snapshot_fork_close_orders_wait_only_for_own_table_range_and_value() {
    for parent_first in [true, false] {
        let admission = CountedAdmission::new();
        let opening = opening(&admission);
        let parent = opening.database().unwrap().begin_read().unwrap();
        let child = parent.fork().unwrap();
        let (guarded, independent) = if parent_first {
            (child, parent)
        } else {
            (parent, child)
        };
        let table = guarded.open_table(ROWS).unwrap();
        let mut range = table.iter().unwrap();
        let value = table.get(b"a".as_slice()).unwrap().unwrap();
        let row = range.next().unwrap().unwrap();
        let mut guarded = guarded.retain();
        let mut independent = independent.retain();
        close_reader(&opening, &mut independent);
        let failure = independent.fork().err().unwrap();
        assert!(matches!(
            failure.original(),
            TransactionError(StorageError::DatabaseClosed)
        ));
        assert!(!failure.is_clean_capacity_refusal());
        let owner = opening.retained_database().unwrap();
        assert_eq!(
            guarded.close(owner).settlement(),
            ReadCloseSettlement::WaitingForGuards
        );
        let failure = guarded.fork().err().unwrap();
        assert!(matches!(
            failure.original(),
            TransactionError(StorageError::DatabaseClosed)
        ));
        assert!(!failure.is_clean_capacity_refusal());
        drop(table);
        assert_eq!(
            guarded.close(owner).settlement(),
            ReadCloseSettlement::WaitingForGuards
        );
        drop(range);
        assert_eq!(
            guarded.close(owner).settlement(),
            ReadCloseSettlement::WaitingForGuards
        );
        drop(row);
        assert_eq!(
            guarded.close(owner).settlement(),
            ReadCloseSettlement::WaitingForGuards
        );
        assert_eq!(value.value(), b"old-a");
        drop(value);
        close_reader(&opening, &mut guarded);
        finish(opening, &admission);
    }
}

#[test]
fn selected_snapshot_fork_byte_and_slot_refusal_leave_parent_and_counts_unchanged() {
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let parent = opening.database().unwrap().begin_read().unwrap();
    let baseline = admission.census();
    let generation = parent.snapshot.generation();
    for byte_refusal in [true, false] {
        admission.limits(
            if byte_refusal {
                baseline.0 + SnapshotHandle::CHARGE_BYTES - 1
            } else {
                BYTE_LIMIT
            },
            if byte_refusal { SLOT_LIMIT } else { baseline.1 },
        );
        let count = AllocationCount::start();
        let refused = parent.fork();
        assert_eq!(count.count(), 0);
        drop(count);
        assert_capacity(refused);
        assert_eq!(admission.census(), baseline);
        assert_eq!(parent.snapshot.generation(), generation);
        assert!(!parent.has_snapshot_descendants());
        admission.limits(BYTE_LIMIT, SLOT_LIMIT);
        assert_eq!(
            parent
                .get_bytes(ROWS.name(), b"a", 32)
                .unwrap()
                .unwrap()
                .as_bytes(),
            b"old-a"
        );
    }
    let child = parent.fork().unwrap();
    assert_eq!(
        admission.census(),
        (baseline.0 + SnapshotHandle::CHARGE_BYTES, baseline.1 + 1)
    );
    drop(child);
    assert_eq!(admission.census(), baseline);
    drop(parent);
    finish(opening, &admission);
}

#[test]
fn selected_snapshot_normal_captures_preclaim_and_rollback_before_pin_creation() {
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let database = opening.database().unwrap();
    let baseline = admission.census();
    admission.limits(baseline.0 + SnapshotHandle::CHARGE_BYTES - 1, SLOT_LIMIT);
    let count = AllocationCount::start();
    let read = database.begin_read();
    let write = database.begin_write();
    assert_eq!(count.count(), 0);
    drop(count);
    assert_capacity(read);
    assert!(matches!(
        write,
        Err(TransactionError(StorageError::Core(
            CoreError::CapacityDenied
        )))
    ));
    assert_eq!(admission.census(), baseline);
    assert_eq!(database.active_transactions(), 0);
    // The backing fits, but the additional fresh root-pin lease does not.
    admission.limits(BYTE_LIMIT, baseline.1 + 1);
    assert_capacity(database.begin_read());
    assert_eq!(admission.census(), baseline);
    admission.limits(BYTE_LIMIT, SLOT_LIMIT);
    let writer = database.begin_write().unwrap();
    drop(writer); // denial did not strand the writer gate
    finish(opening, &admission);
}

#[test]
fn selected_snapshot_fork_racing_database_seal_rolls_back_admitted_child() {
    let admission = CountedAdmission::new();
    let mut opening = opening(&admission);
    let parent = Arc::new(opening.database().unwrap().begin_read().unwrap());
    let baseline = admission.census();
    let pause = Arc::new(Pause {
        admitted: Barrier::new(2),
        resume: Barrier::new(2),
    });
    ledger_lock(&admission.state).pause = Some(pause.clone());
    let worker_parent = parent.clone();
    let worker = std::thread::spawn(move || worker_parent.fork());
    pause.admitted.wait();
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    pause.resume.wait();
    assert!(matches!(
        worker.join().unwrap(),
        Err(TransactionError(StorageError::DatabaseClosed))
    ));
    assert_eq!(admission.census(), baseline);
    assert!(matches!(
        parent.fork(),
        Err(TransactionError(StorageError::DatabaseClosed))
    ));
    drop(parent);
    finish(opening, &admission);
}

#[test]
fn selected_snapshot_fork_owner_failure_after_admission_retires_private_clone() {
    let admission = CountedAdmission::new();
    let mut opening = opening(&admission);
    let parent = Arc::new(opening.database().unwrap().begin_read().unwrap());
    let baseline = admission.census();
    let pause = Arc::new(Pause {
        admitted: Barrier::new(2),
        resume: Barrier::new(2),
    });
    ledger_lock(&admission.state).pause = Some(pause.clone());
    let worker_parent = parent.clone();
    let worker = std::thread::spawn(move || worker_parent.fork());
    pause.admitted.wait();
    assert_eq!(
        admission.census(),
        (baseline.0 + SnapshotHandle::CHARGE_BYTES, baseline.1 + 1)
    );
    admission.failed.store(true, Ordering::Release);
    pause.resume.wait();
    assert!(matches!(
        worker.join().unwrap(),
        Err(TransactionError(StorageError::Core(CoreError::OwnerFailed)))
    ));
    assert_eq!(admission.census(), baseline);
    assert!(!parent.has_snapshot_descendants());
    drop(parent);
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::DrainedWithFailure
    );
    assert_eq!(
        opening.dispose_failed().settlement(),
        DatabaseOpenSettlement::FailedDisposed
    );
    drop(opening);
    assert_eq!(admission.census(), (0, 0));
}

#[test]
fn selected_snapshot_retained_fork_starts_open_and_preserves_owner_failure() {
    let admission = CountedAdmission::new();
    let mut opening = opening(&admission);
    let mut parent = opening.database().unwrap().begin_read_retained().unwrap();
    let mut child = parent.fork().unwrap();
    assert_eq!(parent.report().settlement(), ReadCloseSettlement::Open);
    assert_eq!(child.report().settlement(), ReadCloseSettlement::Open);
    close_reader(&opening, &mut parent);
    assert_eq!(
        child.get_bytes(ROWS, b"a", 32).unwrap().unwrap().as_bytes(),
        b"old-a"
    );
    // A core owner failure is preserved, not replaced by a new current read.
    admission.failed.store(true, Ordering::Release);
    let failure = child.fork().err().unwrap();
    assert!(matches!(
        failure.original(),
        TransactionError(StorageError::Core(CoreError::OwnerFailed))
    ));
    assert!(!failure.is_clean_capacity_refusal());
    close_reader(&opening, &mut child);
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::DrainedWithFailure
    );
    assert_eq!(
        opening.dispose_failed().settlement(),
        DatabaseOpenSettlement::FailedDisposed
    );
    drop(opening);
    assert_eq!(admission.census(), (0, 0));
}

#[test]
fn selected_snapshot_backing_retires_after_last_descendant_and_before_refund() {
    let _serial = WATCH_LOCK.lock().unwrap();
    let admission = CountedAdmission::new();
    let mut opening = opening(&admission);
    let parent = opening.database().unwrap().begin_read().unwrap();
    let child = parent.fork().unwrap();
    let watch = BackingWatch::new(&admission, &child.snapshot, admission.last_grant());
    drop(parent);
    let table = child.open_table(ROWS).unwrap();
    let range = table.iter().unwrap();
    let value = table.get(b"a".as_slice()).unwrap().unwrap();
    drop(child);
    drop(table);
    assert!(!BACKING_FREED.load(Ordering::Acquire));
    drop(range);
    assert!(!BACKING_FREED.load(Ordering::Acquire));
    // Only a value guard's exact snapshot survives: no transaction/table/range
    // holds DatabaseInner. Actual Core close must still wait for that pin.
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    assert_eq!(value.value(), b"old-a");
    drop(value);
    assert!(BACKING_FREED.load(Ordering::Acquire));
    assert_eq!(WATCH_REFUNDS.load(Ordering::Acquire), 1);
    drop(watch);
    finish(opening, &admission);
}

#[test]
fn selected_snapshot_backing_concurrent_final_aliases_retire_one_actual_arc() {
    let _serial = WATCH_LOCK.lock().unwrap();
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let parent = opening.database().unwrap().begin_read().unwrap();
    let child = parent.fork().unwrap();
    let watch = BackingWatch::new(&admission, &child.snapshot, admission.last_grant());
    let first = child.snapshot.clone();
    let second = child.snapshot.clone();
    let barrier = Arc::new(Barrier::new(3));
    let worker_barrier = barrier.clone();
    let first = std::thread::spawn(move || {
        worker_barrier.wait();
        drop(first);
    });
    let worker_barrier = barrier.clone();
    let second = std::thread::spawn(move || {
        worker_barrier.wait();
        drop(second);
    });
    drop(child);
    assert!(!BACKING_FREED.load(Ordering::Acquire));
    barrier.wait();
    first.join().unwrap();
    second.join().unwrap();
    assert!(BACKING_FREED.load(Ordering::Acquire));
    assert_eq!(WATCH_REFUNDS.load(Ordering::Acquire), 1);
    drop(watch);
    drop(parent);
    finish(opening, &admission);
}

#[test]
fn retained_acquisition_capacity_witness_follows_actual_backing_and_pin_refunds() {
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let database = opening.database().unwrap();
    let baseline = admission.census();
    for backing in [true, false] {
        admission.limits(
            if backing {
                baseline.0 + SnapshotHandle::CHARGE_BYTES - 1
            } else {
                BYTE_LIMIT
            },
            if backing { SLOT_LIMIT } else { baseline.1 + 1 },
        );
        let error = database.begin_read_retained().err().unwrap();
        assert!(error.is_clean_capacity_refusal());
        assert!(matches!(
            error.original(),
            TransactionError(StorageError::Core(CoreError::CapacityDenied))
        ));
        assert_eq!(admission.census(), baseline);
        assert_eq!(database.active_transactions(), 0);
    }
    admission.limits(BYTE_LIMIT, SLOT_LIMIT);
    let mut parent = database.begin_read_retained().unwrap();
    let selected = admission.census();
    admission.limits(selected.0 + SnapshotHandle::CHARGE_BYTES - 1, SLOT_LIMIT);
    let error = parent.fork().err().unwrap();
    assert!(error.is_clean_capacity_refusal());
    assert!(matches!(
        error.original(),
        TransactionError(StorageError::Core(CoreError::CapacityDenied))
    ));
    assert_eq!(admission.census(), selected);
    admission.limits(BYTE_LIMIT, SLOT_LIMIT);
    assert_eq!(
        parent
            .get_bytes(ROWS, b"a", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"old-a"
    );
    close_reader(&opening, &mut parent);
    let error = parent.fork().err().unwrap();
    assert!(!error.is_clean_capacity_refusal());
    assert!(matches!(
        error.original(),
        TransactionError(StorageError::DatabaseClosed)
    ));
    finish(opening, &admission);
}

#[test]
fn retained_acquisition_provisional_backing_drop_panic_cannot_mint_clean_witness() {
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let database = opening.database().unwrap();
    let baseline = admission.census();
    // First native grant is real SnapshotCharge; the pin lease then refuses.
    // Its unwinding charge destructor must run before a witness can exist.
    admission.limits(BYTE_LIMIT, baseline.1 + 1);
    {
        let mut ledger = ledger_lock(&admission.state);
        ledger.panic_on_drop = Some(ledger.next_grant);
    }
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        database.begin_read_retained()
    }));
    let payload = match unwind {
        Err(payload) => payload,
        Ok(_) => panic!("provisional destructor did not unwind"),
    };
    assert_eq!(payload.downcast_ref::<u64>(), Some(&0x51ee));
    assert_eq!(admission.census(), baseline);
    assert_eq!(database.active_transactions(), 0);
    admission.limits(BYTE_LIMIT, SLOT_LIMIT);
    finish(opening, &admission);
}

#[test]
fn retained_acquisition_full_native_pin_registry_refunds_both_provisional_grants() {
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let database = opening.database().unwrap();
    let baseline = admission.census();
    // DiskState's fixed registry has 256 slots. This test's bounded provider
    // funds those exact backing+pin pairs plus the refused attempt's two
    // provisional grants; the byte cap remains the existing 64 MiB.
    const PINS: usize = 256;
    admission.limits(BYTE_LIMIT, baseline.1 + 2 * PINS + 2);
    let mut readers: Vec<_> = (0..PINS)
        .map(|_| database.begin_read_retained().unwrap())
        .collect();
    assert_eq!(database.active_transactions(), PINS);
    let full = admission.census();
    let last_grant = admission.last_grant();
    let error = database.begin_read_retained().err().unwrap();
    assert!(error.is_clean_capacity_refusal());
    assert!(matches!(
        error.original(),
        TransactionError(StorageError::Core(CoreError::CapacityDenied))
    ));
    assert_eq!(
        admission.last_grant(),
        last_grant + 2,
        "both provisional grants preceded the actual pin-slot refusal"
    );
    assert_eq!(admission.census(), full);
    assert_eq!(database.active_transactions(), PINS);
    for reader in &mut readers {
        close_reader(&opening, reader);
    }
    assert_eq!(admission.census(), baseline);
    finish(opening, &admission);
}

#[test]
fn retained_reader_disposal_panic_preserves_unknown_even_after_transaction_is_absent() {
    let admission = CountedAdmission::new();
    let mut opening = opening(&admission);
    let database = opening.database().unwrap();
    let backing_grant = admission.last_grant() + 1;
    let mut reader = database.begin_read_retained().unwrap();
    ledger_lock(&admission.state).panic_on_drop = Some(backing_grant);
    let owner = opening.retained_database().unwrap();
    assert_eq!(
        reader.close(owner).settlement(),
        ReadCloseSettlement::Settled
    );
    let report = reader.dispose_settled(owner);
    assert_eq!(report.settlement(), ReadCloseSettlement::DisposalUncertain);
    assert!(!report.retains_transaction());
    assert!(matches!(
        report.release(),
        crate::TerminalObservation::Returned(Ok(()))
    ));
    let crate::TerminalObservation::Panicked(payload) = report.disposal() else {
        panic!("missing original disposal panic")
    };
    assert_eq!(payload.downcast_ref::<u64>(), Some(&0x51ee));
    assert_eq!(
        reader.dispose_settled(owner).settlement(),
        ReadCloseSettlement::DisposalUncertain
    );
    assert!(reader.report().retains_database());
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    drop(reader); // test teardown does not acknowledge uncertain disposal
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::DrainedWithFailure
    );
    assert_eq!(
        opening.dispose_failed().settlement(),
        DatabaseOpenSettlement::FailedDisposed
    );
    drop(opening);
    assert_eq!(admission.census(), (0, 0));
}

#[test]
fn source_quote_constructor_requests_are_pure_and_match_actual_native_capture() {
    use crate::{PointReadRequests, ProtectedReadRequests};
    let counting = AllocationCount::start();
    let backing = ProtectedReadRequests::snapshot_backing_request_bytes();
    let pin = ProtectedReadRequests::pin_backing_request_bytes();
    let rights = ProtectedReadRequests::rights_request_bytes();
    let point = PointReadRequests::new(65_537).unwrap();
    assert!(PointReadRequests::new(usize::MAX).is_err());
    assert_eq!(
        point.output_request_bytes(),
        AdmittedValue::request_bytes(65_537).unwrap()
    );
    assert!(point.bounds_request_bytes() > 0 && point.page_request_bytes() > 16 << 10);
    assert!(rights > 0);
    assert_eq!(counting.count(), 0);
    drop(counting);
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let before = admission.census();
    let read = opening.database().unwrap().begin_read().unwrap();
    let after = admission.census();
    assert_eq!(after.0 - before.0, backing + pin);
    assert_eq!(after.1 - before.1, 2);
    drop(read);
    assert_eq!(admission.census(), before);
    finish(opening, &admission);
}
