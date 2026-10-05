//! Actual native staging grants and allocator-observed retirement.
use super::*;
use crate::group::InMemoryGroup;
use crate::{AdmissionError, CorePanic};
use std::alloc::Layout;
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, AtomicUsize};

static WATCH_LOCK: Mutex<()> = Mutex::new(());
static TARGETS: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
static FREED: [AtomicBool; 3] = [const { AtomicBool::new(false) }; 3];

thread_local! {
    static DENY_NODE: Cell<bool> = const { Cell::new(false) };
    static NODE_DENIALS: Cell<usize> = const { Cell::new(0) };
    static WATCH_BUFFER_BYTES: Cell<usize> = const { Cell::new(0) };
}

// The production node is one Vec slot allocated by the pinned default Global
// allocator. This hook denies that exact layout on the calling test thread.
pub(crate) fn deny_allocation(layout: Layout) -> bool {
    if layout != Layout::new::<StagingLease>() {
        return false;
    }
    DENY_NODE
        .try_with(|armed| {
            if !armed.replace(false) {
                return false;
            }
            NODE_DENIALS.with(|count| count.set(count.get() + 1));
            true
        })
        .unwrap_or(false)
}

struct DenyNode;
impl DenyNode {
    fn arm() -> Self {
        NODE_DENIALS.with(|count| count.set(0));
        DENY_NODE.with(|armed| assert!(!armed.replace(true)));
        Self
    }
    fn assert_denied(&self) {
        NODE_DENIALS.with(|count| assert_eq!(count.get(), 1));
        DENY_NODE.with(|armed| assert!(!armed.get()));
    }
}
impl Drop for DenyNode {
    fn drop(&mut self) {
        DENY_NODE.with(|armed| armed.set(false));
    }
}

pub(crate) fn note_allocation_backing(pointer: *mut u8, layout: Layout) {
    let _ = WATCH_BUFFER_BYTES.try_with(|bytes| {
        if bytes.get() != 0 && bytes.get() == layout.size() && layout.align() == 1 {
            bytes.set(0);
            TARGETS[0].store(pointer as usize, Ordering::Release);
        }
    });
}

pub(crate) fn note_deallocation(pointer: *mut u8, layout: Layout) {
    let start = pointer as usize;
    for (target, freed) in TARGETS.iter().zip(&FREED) {
        let target = target.load(Ordering::Acquire);
        if target != 0 && target >= start && target - start < layout.size() {
            freed.store(true, Ordering::Release);
        }
    }
}

#[derive(Default)]
struct Ledger {
    used: AtomicU64,
    limit: AtomicU64,
    issued: AtomicUsize,
    callbacks: AtomicUsize,
    refunds: AtomicUsize,
    staging_token: AtomicUsize,
    watched_token: AtomicUsize,
    watched_refunds: AtomicUsize,
    watch_next_grant: AtomicBool,
    watch_request_bytes: AtomicU64,
    panic_token: AtomicUsize,
    deny_request_bytes: AtomicU64,
    panic_request_bytes: AtomicU64,
    payload: Mutex<Option<Box<u64>>>,
}
impl Ledger {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            limit: AtomicU64::new(u64::MAX),
            ..Self::default()
        })
    }
    fn grant(self: &Arc<Self>, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        if bytes != 0
            && self
                .panic_request_bytes
                .compare_exchange(bytes, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            let original = self.payload.lock().unwrap().take().unwrap();
            resume_unwind(original);
        }
        if bytes > self.limit.load(Ordering::Acquire)
            || bytes == self.deny_request_bytes.load(Ordering::Acquire)
        {
            return Err(AdmissionError::CapacityDenied);
        }
        self.used.fetch_add(bytes, Ordering::AcqRel);
        let id = self.issued.fetch_add(1, Ordering::AcqRel) + 1;
        if bytes == (STAGING_CHUNK + STAGING_LEASE_NODE) as u64 {
            self.staging_token.store(id, Ordering::Release);
        }
        let token = Box::new(Token {
            ledger: self.clone(),
            bytes,
            id,
        });
        if (self.watch_request_bytes.load(Ordering::Acquire) == 0
            || self.watch_request_bytes.load(Ordering::Acquire) == bytes)
            && self.watch_next_grant.swap(false, Ordering::AcqRel)
        {
            TARGETS[1].store(token.as_ref() as *const Token as usize, Ordering::Release);
            self.watched_token.store(id, Ordering::Release);
        }
        Ok(token)
    }
}
struct Token {
    ledger: Arc<Ledger>,
    bytes: u64,
    id: usize,
}
impl Drop for Token {
    fn drop(&mut self) {
        self.ledger.callbacks.fetch_add(1, Ordering::AcqRel);
        if self.ledger.watched_token.load(Ordering::Acquire) == self.id {
            crate::native_sync::tests::assert_retired_for(TARGETS[1].load(Ordering::Acquire));
            for freed in &FREED {
                assert!(
                    freed.load(Ordering::Acquire),
                    "original staging allocation survived its provider refund"
                );
            }
            self.ledger.watched_refunds.fetch_add(1, Ordering::AcqRel);
        }
        if self.ledger.panic_token.load(Ordering::Acquire) == self.id {
            let payload = self.ledger.payload.lock().unwrap().take().unwrap();
            resume_unwind(payload);
        }
        self.ledger.used.fetch_sub(self.bytes, Ordering::AcqRel);
        self.ledger.refunds.fetch_add(1, Ordering::AcqRel);
    }
}
struct Admission(Arc<Ledger>);
impl StorageAdmission for Admission {
    fn check_owner(&self) -> Result<(), crate::OwnerFailed> {
        Ok(())
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        self.0.grant(bytes)
    }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn settle_growth(&self, _: u64) -> Result<(), crate::OwnerFailed> {
        Ok(())
    }
    fn owner_failed(&self) {}
    fn quote_cache_memory(&self, bytes: u64) -> Result<crate::CacheMemoryQuote, AdmissionError> {
        crate::cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, AdmissionError> {
        crate::cache_test::reserve(self, bytes)
    }
}
impl crate::cache_test::Provider for Admission {
    fn acquire_cache(&self, _: u64, _: bool) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn release_cache(&self, _: u64, _: bool) {}
}

struct Watch;
impl Watch {
    fn native_output(ledger: &Ledger, bytes: usize) -> Self {
        for target in &TARGETS {
            target.store(0, Ordering::Release);
        }
        FREED[0].store(false, Ordering::Release);
        FREED[1].store(false, Ordering::Release);
        FREED[2].store(true, Ordering::Release);
        WATCH_BUFFER_BYTES.with(|value| {
            assert_eq!(value.replace(bytes), 0);
        });
        ledger.watch_request_bytes.store(
            AdmittedValue::request_bytes(bytes).unwrap(),
            Ordering::Release,
        );
        ledger.watch_next_grant.store(true, Ordering::Release);
        Self
    }
    fn assert_native_output_retired(&self, ledger: &Ledger) {
        WATCH_BUFFER_BYTES.with(|bytes| assert_eq!(bytes.get(), 0));
        assert_ne!(TARGETS[0].load(Ordering::Acquire), 0);
        assert_ne!(TARGETS[1].load(Ordering::Acquire), 0);
        assert!(FREED.iter().all(|freed| freed.load(Ordering::Acquire)));
        assert_eq!(ledger.watched_refunds.load(Ordering::Acquire), 1);
    }

    fn staging(transaction: &WriteTransaction, ledger: &Ledger) -> Self {
        TARGETS[2].store(0, Ordering::Release);
        FREED[2].store(true, Ordering::Release);
        let staged = lock(&transaction.staged);
        let allocation = staged.credit.leases.as_ref().unwrap();
        assert_eq!(allocation.len(), 1);
        assert_eq!(allocation.capacity(), 1);
        let node = &allocation[0];
        assert!(node.next.is_none());
        let addresses = [
            node as *const StagingLease as usize,
            node.lease.allocation_address_for_test(),
        ];
        for ((target, freed), address) in TARGETS.iter().zip(&FREED).zip(addresses) {
            freed.store(false, Ordering::Release);
            target.store(address, Ordering::Release);
        }
        let id = ledger.staging_token.load(Ordering::Acquire);
        assert_ne!(id, 0);
        ledger.watched_token.store(id, Ordering::Release);
        Self
    }

    fn failed_next_node(ledger: &Ledger) -> Self {
        // The denied node never gets backing; its prospective token still has
        // an actual Box that must retire before its refund callback runs.
        TARGETS[0].store(0, Ordering::Release);
        FREED[0].store(true, Ordering::Release);
        TARGETS[1].store(0, Ordering::Release);
        FREED[1].store(false, Ordering::Release);
        TARGETS[2].store(0, Ordering::Release);
        FREED[2].store(true, Ordering::Release);
        ledger.watch_next_grant.store(true, Ordering::Release);
        Self
    }
}

fn watch_table_name(name: &SharedTableName) {
    let backing = name.0.as_ref().unwrap();
    FREED[0].store(false, Ordering::Release);
    TARGETS[0].store(Arc::as_ptr(backing) as usize, Ordering::Release);
    FREED[2].store(false, Ordering::Release);
    TARGETS[2].store(backing.name.as_ptr() as usize, Ordering::Release);
}

#[test]
fn native_table_name_prepays_both_actual_arcs_and_concurrent_final_alias_drop() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let ledger = Ledger::new();
    let database = database(&ledger);
    let baseline = ledger.used.load(Ordering::Acquire);
    let request = table_name_backing_bytes(ROWS.name().len()).unwrap();
    let watch = Watch::failed_next_node(&ledger);
    ledger.watch_request_bytes.store(request, Ordering::Release);
    let counting = super::read_fork_tests::AllocationCount::start();
    let name = SharedTableName::new(&database.inner.core, ROWS.name()).unwrap();
    assert_eq!(
        counting.count(),
        3,
        "one grant Box, name Arc and control Arc"
    );
    drop(counting);
    assert_eq!(ledger.used.load(Ordering::Acquire), baseline + request);
    watch_table_name(&name);
    let left = name.clone();
    let right = name.clone();
    drop(name);
    assert_eq!(ledger.watched_refunds.load(Ordering::Acquire), 0);
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        for alias in [left, right] {
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                drop(alias);
            });
        }
    });
    assert!(FREED.iter().all(|freed| freed.load(Ordering::Acquire)));
    assert_eq!(ledger.watched_refunds.load(Ordering::Acquire), 1);
    assert_eq!(ledger.used.load(Ordering::Acquire), baseline);
    drop(watch);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
}

#[test]
fn native_table_name_refusal_precedes_actual_allocations_and_rolls_back_writer() {
    let ledger = Ledger::new();
    let database = database(&ledger);
    let request = table_name_backing_bytes(ROWS.name().len()).unwrap();
    let baseline = ledger.used.load(Ordering::Acquire);
    let issued = ledger.issued.load(Ordering::Acquire);
    ledger.deny_request_bytes.store(request, Ordering::Release);
    let counting = super::read_fork_tests::AllocationCount::start();
    let name = SharedTableName::new(&database.inner.core, ROWS.name());
    assert!(
        matches!(&(name), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    assert_eq!(counting.count(), 0);
    drop(counting);
    assert_eq!(ledger.issued.load(Ordering::Acquire), issued);
    assert_eq!(ledger.used.load(Ordering::Acquire), baseline);
    ledger.deny_request_bytes.store(0, Ordering::Release);
    let writer = database.begin_write().unwrap();
    let mut table = writer.open_table(ROWS).unwrap();
    table.insert(b"never", b"published").unwrap();
    ledger.deny_request_bytes.store(request, Ordering::Release);
    assert!(writer.open_table(ROWS).err().unwrap().is_capacity_denied());
    assert!(!writer.holds_writer());
    let issued = ledger.issued.load(Ordering::Acquire);
    assert!(writer.open_table(ROWS).err().unwrap().is_capacity_denied());
    assert_eq!(ledger.issued.load(Ordering::Acquire), issued);
    drop(table);
    writer.abort().unwrap();
    ledger.deny_request_bytes.store(0, Ordering::Release);
    let reader = database.begin_read().unwrap();
    assert!(
        reader
            .open_table(ROWS)
            .unwrap()
            .get(b"never")
            .unwrap()
            .is_none()
    );
    drop(reader);
    assert_eq!(ledger.used.load(Ordering::Acquire), baseline);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
}

#[test]
fn native_table_and_range_aliases_keep_each_independent_name_admitted() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let ledger = Ledger::new();
    let database = database(&ledger);
    let request = table_name_backing_bytes(ROWS.name().len()).unwrap();
    let reader = database.begin_read().unwrap();
    let baseline = ledger.used.load(Ordering::Acquire);
    let watch = Watch::failed_next_node(&ledger);
    ledger.watch_request_bytes.store(request, Ordering::Release);
    let table = reader.open_table(ROWS).unwrap();
    watch_table_name(&table.name);
    let other = reader.open_table(ROWS).unwrap();
    assert!(!Arc::ptr_eq(
        table.name.0.as_ref().unwrap(),
        other.name.0.as_ref().unwrap()
    ));
    assert_eq!(ledger.used.load(Ordering::Acquire), baseline + 2 * request);
    let range = table.iter().unwrap();
    drop(other);
    drop(table);
    assert_eq!(ledger.watched_refunds.load(Ordering::Acquire), 0);
    drop(reader);
    drop(range);
    assert!(FREED.iter().all(|freed| freed.load(Ordering::Acquire)));
    assert_eq!(ledger.watched_refunds.load(Ordering::Acquire), 1);
    drop(watch);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
    assert_eq!(ledger.used.load(Ordering::Acquire), 0);
}

#[test]
fn native_staged_operation_aliases_retire_before_their_original_table_name_grant() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let ledger = Ledger::new();
    let database = database(&ledger);
    let writer = database.begin_write().unwrap();
    let request = table_name_backing_bytes(ROWS.name().len()).unwrap();
    let watch = Watch::failed_next_node(&ledger);
    ledger.watch_request_bytes.store(request, Ordering::Release);
    let mut table = writer.open_table(ROWS).unwrap();
    watch_table_name(&table.name);
    table.insert(b"key", b"value").unwrap();
    drop(table);
    assert_eq!(ledger.watched_refunds.load(Ordering::Acquire), 0);
    writer.commit().unwrap();
    assert!(FREED.iter().all(|freed| freed.load(Ordering::Acquire)));
    assert_eq!(ledger.watched_refunds.load(Ordering::Acquire), 1);
    drop(watch);
    ledger.watched_token.store(0, Ordering::Release);
    let reader = database.begin_read().unwrap();
    assert_eq!(
        reader
            .open_table(ROWS)
            .unwrap()
            .get(b"key")
            .unwrap()
            .unwrap()
            .value(),
        b"value"
    );
    drop(reader);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
}

#[test]
fn native_table_name_original_retirement_panic_follows_actual_backing_deallocation() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let ledger = Ledger::new();
    let database = database(&ledger);
    let baseline = ledger.used.load(Ordering::Acquire);
    let request = table_name_backing_bytes(ROWS.name().len()).unwrap();
    let watch = Watch::failed_next_node(&ledger);
    ledger.watch_request_bytes.store(request, Ordering::Release);
    let name = SharedTableName::new(&database.inner.core, ROWS.name()).unwrap();
    watch_table_name(&name);
    let payload = Box::new(0x7ab1e_u64);
    let address = std::ptr::from_ref(payload.as_ref()) as usize;
    *ledger.payload.lock().unwrap() = Some(payload);
    ledger.panic_token.store(
        ledger.watched_token.load(Ordering::Acquire),
        Ordering::Release,
    );
    let callbacks = ledger.callbacks.load(Ordering::Acquire);
    let refunds = ledger.refunds.load(Ordering::Acquire);
    let original = catch_unwind(AssertUnwindSafe(|| drop(name))).unwrap_err();
    assert_eq!(
        std::ptr::from_ref(original.downcast_ref::<u64>().unwrap()) as usize,
        address
    );
    assert!(FREED.iter().all(|freed| freed.load(Ordering::Acquire)));
    assert_eq!(ledger.callbacks.load(Ordering::Acquire), callbacks + 1);
    assert_eq!(ledger.refunds.load(Ordering::Acquire), refunds);
    assert_eq!(ledger.used.load(Ordering::Acquire), baseline + request);
    drop(watch);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
    assert_eq!(ledger.used.load(Ordering::Acquire), request);
}

#[test]
fn native_byte_and_integer_point_keys_allocate_no_independent_encoded_buffer() {
    const NUMBERS: TableDefinition<u64, u64> = TableDefinition::new("point-key-numbers");
    let ledger = Ledger::new();
    let database = database(&ledger);
    let writer = database.begin_write().unwrap();
    writer
        .open_table(ROWS)
        .unwrap()
        .insert(b"key", b"value")
        .unwrap();
    writer.open_table(NUMBERS).unwrap().insert(71, 83).unwrap();
    writer.commit().unwrap();
    let reader = database.begin_read().unwrap();
    let bytes = reader.open_table(ROWS).unwrap();
    let integers = reader.open_table(NUMBERS).unwrap();
    let borrowed_key = b"key";
    let counting = super::read_fork_tests::AllocationCount::start();
    let borrowed = <&[u8]>::with_encoded(borrowed_key, |key| {
        assert_eq!(key.as_ptr(), borrowed_key.as_ptr());
        key.len()
    });
    assert_eq!(borrowed, 3);
    <u64>::with_encoded(71, |key| assert_eq!(key, 71u64.to_be_bytes()));
    assert_eq!(counting.count(), 0);
    drop(counting);
    let integer_key = 71u64.to_be_bytes();
    for (name, key) in [
        (ROWS.name(), b"key".as_slice()),
        (NUMBERS.name(), integer_key.as_slice()),
    ] {
        let counting = super::read_fork_tests::AllocationCount::start();
        let native = database
            .inner
            .core
            .get_admitted(&reader.snapshot, name, key, MAX_TABLE_VALUE_BYTES)
            .unwrap()
            .unwrap();
        let native_allocations = counting.count();
        drop(counting);
        drop(native);
        let counting = super::read_fork_tests::AllocationCount::start();
        if name == ROWS.name() {
            let result = bytes.get(b"key").unwrap().unwrap();
            assert_eq!(result.value(), b"value");
            assert_eq!(counting.count(), native_allocations);
            drop(counting);
            drop(result);
        } else {
            let result = integers.get(71).unwrap().unwrap();
            assert_eq!(result.value(), 83);
            assert_eq!(counting.count(), native_allocations);
            drop(counting);
            drop(result);
        }
    }
    drop(bytes);
    drop(integers);
    drop(reader);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
}

#[test]
fn native_owned_range_key_refusal_precedes_copy_and_exact_backing_retires_before_refund() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let ledger = Ledger::new();
    let database = database(&ledger);
    let baseline = ledger.used.load(Ordering::Acquire);
    let request = 512;
    ledger.deny_request_bytes.store(request, Ordering::Release);
    let counting = super::read_fork_tests::AllocationCount::start();
    assert!(
        matches!(&(OwnedKeyBytes::copy(&database.inner.core, b"continuation", request)), Err(TableError::Storage(StorageError::Core(
            native_error
        ))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    assert_eq!(counting.count(), 0);
    drop(counting);
    assert_eq!(ledger.used.load(Ordering::Acquire), baseline);
    ledger.deny_request_bytes.store(0, Ordering::Release);
    let watch = Watch::failed_next_node(&ledger);
    ledger.watch_request_bytes.store(request, Ordering::Release);
    let counting = super::read_fork_tests::AllocationCount::start();
    let key = OwnedKeyBytes::copy(&database.inner.core, b"continuation", request).unwrap();
    assert_eq!(
        counting.count(),
        2,
        "one exact grant Box and continuation Vec"
    );
    drop(counting);
    assert_eq!(key.bytes.capacity(), b"continuation".len());
    assert_eq!(key.as_bytes(), b"continuation");
    FREED[0].store(false, Ordering::Release);
    TARGETS[0].store(key.bytes.as_ptr() as usize, Ordering::Release);
    assert_eq!(ledger.used.load(Ordering::Acquire), baseline + request);
    drop(key);
    assert!(FREED.iter().all(|freed| freed.load(Ordering::Acquire)));
    assert_eq!(ledger.watched_refunds.load(Ordering::Acquire), 1);
    assert_eq!(ledger.used.load(Ordering::Acquire), baseline);
    drop(watch);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
}

#[test]
fn native_range_owns_admitted_start_after_inputs_tables_and_reader_drop() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let ledger = Ledger::new();
    let database = database(&ledger);
    let writer = database.begin_write().unwrap();
    writer
        .open_table(ROWS)
        .unwrap()
        .insert(b"key", b"value")
        .unwrap();
    writer.commit().unwrap();
    let reader = database.begin_read().unwrap();
    let table = reader.open_table(ROWS).unwrap();
    let input = b"key".to_vec();
    let request = (input.len() + ROWS.name().len() + 256) as u64;
    let watch = Watch::failed_next_node(&ledger);
    ledger.watch_request_bytes.store(request, Ordering::Release);
    let mut range = table.range(input.as_slice()..).unwrap();
    FREED[0].store(false, Ordering::Release);
    TARGETS[0].store(range.start.bytes.as_ptr() as usize, Ordering::Release);
    assert_ne!(range.start.bytes.as_ptr(), input.as_ptr());
    drop(input);
    drop(table);
    drop(reader);
    assert_eq!(ledger.watched_refunds.load(Ordering::Acquire), 0);
    let (key, value) = range.next().unwrap().unwrap();
    assert_eq!(key.value(), b"key");
    assert_eq!(value.value(), b"value");
    assert!(range.next().is_none());
    drop(key);
    drop(value);
    drop(range);
    assert!(FREED.iter().all(|freed| freed.load(Ordering::Acquire)));
    assert_eq!(ledger.watched_refunds.load(Ordering::Acquire), 1);
    drop(watch);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
    assert_eq!(ledger.used.load(Ordering::Acquire), 0);
}

#[test]
fn native_closed_lease_uses_existing_box_without_allocation_and_denial_creates_no_owner() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let ledger = Ledger::new();
    let database = database(&ledger);
    let actual = ledger.grant(998).unwrap();
    let address = actual.as_ref() as *const dyn ResidentLease as *const () as usize;
    let issued = ledger.issued.load(Ordering::Acquire);
    let counting = super::read_fork_tests::AllocationCount::start();
    let closed = NativeResidentLease::new(actual);
    assert_eq!(counting.count(), 0);
    drop(counting);
    assert_eq!(closed.allocation_address_for_test(), address);
    assert_eq!(ledger.issued.load(Ordering::Acquire), issued);
    TARGETS[0].store(0, Ordering::Release);
    TARGETS[1].store(address, Ordering::Release);
    TARGETS[2].store(0, Ordering::Release);
    FREED[0].store(true, Ordering::Release);
    FREED[1].store(false, Ordering::Release);
    FREED[2].store(true, Ordering::Release);
    ledger.watched_token.store(issued, Ordering::Release);
    let watch = Watch;
    drop(closed);
    assert!(FREED[1].load(Ordering::Acquire));
    assert_eq!(ledger.watched_refunds.load(Ordering::Acquire), 1);
    drop(watch);

    ledger.deny_request_bytes.store(999, Ordering::Release);
    let issued = ledger.issued.load(Ordering::Acquire);
    let counting = super::read_fork_tests::AllocationCount::start();
    let result = database.inner.core.reserve_workspace(999);
    assert!(
        matches!(&(result), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    assert_eq!(counting.count(), 0);
    drop(counting);
    assert_eq!(ledger.issued.load(Ordering::Acquire), issued);
    assert!(!database.inner.core.is_fenced());
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
    assert_eq!(ledger.used.load(Ordering::Acquire), 0);
}

#[test]
fn native_admitted_output_and_access_guard_retire_actual_buffer_and_token_before_refund() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    for admitted in [false, true] {
        let ledger = Ledger::new();
        let database = database(&ledger);
        let writer = database.begin_write().unwrap();
        writer
            .open_table(ROWS)
            .unwrap()
            .insert(b"key", b"12345678")
            .unwrap();
        writer.commit().unwrap();
        let reader = database.begin_read().unwrap();
        let table = reader.open_table(ROWS).unwrap();
        let watch = Watch::native_output(&ledger, 8);
        if admitted {
            let value = database
                .inner
                .core
                .get_admitted(&table.snapshot, ROWS.name(), b"key", 8)
                .unwrap()
                .unwrap();
            assert_eq!(value.as_bytes(), b"12345678");
            assert_eq!(
                TARGETS[1].load(Ordering::Acquire),
                value.lease.allocation_address_for_test()
            );
            drop(value);
        } else {
            let value = table.get(b"key".as_slice()).unwrap().unwrap();
            assert_eq!(value.value(), b"12345678");
            assert_eq!(
                TARGETS[1].load(Ordering::Acquire),
                value._lease.allocation_address_for_test()
            );
            drop(value);
        }
        watch.assert_native_output_retired(&ledger);
        drop(watch);
        drop(table);
        drop(reader);
        database.close_native().into_result().unwrap();
        assert!(database.into_disposal().dispose().complete());
        assert_eq!(ledger.used.load(Ordering::Acquire), 0);
    }
}

#[test]
fn native_filtered_range_key_retires_exact_bytes_and_original_token_before_refund() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let ledger = Ledger::new();
    let database = database(&ledger);
    let writer = database.begin_write().unwrap();
    writer
        .open_table(ROWS)
        .unwrap()
        .insert(b"zoutside", b"never read")
        .unwrap();
    writer.commit().unwrap();
    let reader = database.begin_read().unwrap();
    let table = reader.open_table(ROWS).unwrap();
    let mut range = table.range(b"x".as_slice()..).unwrap();
    range.prefix_only = true;
    let watch = Watch::native_output(&ledger, 8);
    assert!(range.next().is_none());
    watch.assert_native_output_retired(&ledger);
    drop(watch);
    drop(range);
    drop(table);
    drop(reader);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
    assert_eq!(ledger.used.load(Ordering::Acquire), 0);
}

#[test]
fn native_invalid_integer_decode_retires_exact_bytes_and_original_token_before_refund() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let ledger = Ledger::new();
    let database = database(&ledger);
    let writer = database.begin_write().unwrap();
    writer
        .open_table(ROWS)
        .unwrap()
        .insert(b"key", b"wrong")
        .unwrap();
    writer.commit().unwrap();
    let reader = database.begin_read().unwrap();
    let table = reader.open_table(ROWS).unwrap();
    let watch = Watch::native_output(&ledger, 5);
    let admitted = database
        .inner
        .core
        .get_admitted(&table.snapshot, ROWS.name(), b"key", 5)
        .unwrap()
        .unwrap();
    assert_eq!(
        TARGETS[1].load(Ordering::Acquire),
        admitted.lease.allocation_address_for_test()
    );
    let decoded = AccessGuard::<u64>::decode_admitted(admitted, &table.snapshot);
    assert!(matches!(decoded, Err(TableError::InvalidEncoding)));
    watch.assert_native_output_retired(&ledger);
    drop(watch);
    drop(table);
    drop(reader);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
    assert_eq!(ledger.used.load(Ordering::Acquire), 0);
}

#[test]
fn native_provider_panic_returns_original_inline_core_diagnostic_without_new_allocation() {
    let ledger = Ledger::new();
    let database = database(&ledger);
    // Observe the same original-payload unwind transport independently. The
    // pinned runtime allocates/frees an exception control even for resume_unwind.
    let baseline: Box<dyn std::any::Any + Send> = Box::new(0xc0ad_u64);
    let baseline_address = baseline.as_ref() as *const dyn std::any::Any as *const () as usize;
    let counting = super::read_fork_tests::AllocationCount::start();
    let baseline = catch_unwind(AssertUnwindSafe(|| resume_unwind(baseline))).unwrap_err();
    let transport_allocations = counting.count();
    let transport_layouts = counting.layouts();
    assert!(
        transport_allocations > 0,
        "actual pinned unwind transport was observed"
    );
    assert!(
        counting.all_actual_allocations_retired(),
        "actual pointer/layout deallocation completed before raw catch returned"
    );
    assert!(
        counting.addresses()[..transport_allocations]
            .iter()
            .all(|address| *address != baseline_address)
    );
    drop(counting);
    assert_eq!(
        baseline.as_ref() as *const dyn std::any::Any as *const () as usize,
        baseline_address
    );
    let counting = super::read_fork_tests::AllocationCount::start();
    let inline = crate::CorePanic::new(baseline);
    assert_eq!(counting.count(), 0, "actual inline diagnostic construction");
    inline.with_payload(|payload| {
        assert_eq!(
            payload as *const dyn std::any::Any as *const () as usize,
            baseline_address
        );
    });
    assert_eq!(
        counting.count(),
        0,
        "first original payload inspection allocates no control"
    );
    drop(counting);
    drop(inline);

    let original = Box::new(0xc0ae_u64);
    let address = std::ptr::from_ref(original.as_ref()) as usize;
    *ledger.payload.lock().unwrap() = Some(original);
    ledger.panic_request_bytes.store(999, Ordering::Release);
    let issued = ledger.issued.load(Ordering::Acquire);
    let used = ledger.used.load(Ordering::Acquire);
    let counting = super::read_fork_tests::AllocationCount::start();
    let result = database.inner.core.reserve_workspace(999);
    assert_eq!(
        counting.count(),
        transport_allocations,
        "native diagnostic adds no allocation to actual unwind transport"
    );
    assert_eq!(
        counting.layouts(),
        transport_layouts,
        "native transport allocation layouts match the exact runtime control"
    );
    assert!(
        counting.all_actual_allocations_retired(),
        "actual unwind carrier deallocated before native catch returned"
    );
    assert!(
        counting.addresses()[..transport_allocations]
            .iter()
            .all(|carrier| *carrier != address)
    );
    drop(counting);
    let Err(error) = result else {
        panic!("original native callback panic missing");
    };
    let original = error
        .panic()
        .expect("original native callback panic missing");
    original.with_payload(|original| {
        let original = original.downcast_ref::<u64>().unwrap();
        assert_eq!(*original, 0xc0ae);
        assert_eq!(std::ptr::from_ref(original) as usize, address);
    });
    assert_eq!(ledger.issued.load(Ordering::Acquire), issued);
    assert_eq!(ledger.used.load(Ordering::Acquire), used);
    assert!(database.inner.core.is_fenced());
    drop(error);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
    assert_eq!(ledger.used.load(Ordering::Acquire), 0);
}

#[derive(Debug)]
struct OriginalUnknownIo {
    marker: u64,
}
impl fmt::Display for OriginalUnknownIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("original native publication failure")
    }
}
impl std::error::Error for OriginalUnknownIo {}

struct InspectionPayload {
    active: AtomicUsize,
    visits: AtomicUsize,
    dropped: Arc<AtomicUsize>,
    _not_sync: std::marker::PhantomData<std::cell::Cell<()>>,
}
impl Drop for InspectionPayload {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn native_original_panic_inspection_serializes_non_sync_payload_without_allocation() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let payload = Box::new(InspectionPayload {
        active: AtomicUsize::new(0),
        visits: AtomicUsize::new(0),
        dropped: dropped.clone(),
        _not_sync: std::marker::PhantomData,
    });
    let address = std::ptr::from_ref(payload.as_ref()) as usize;
    let original = Arc::new(CorePanic::new(payload));
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let threads = [0, 1].map(|_| {
        let original = original.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            let counting = super::read_fork_tests::AllocationCount::start();
            for _ in 0..1024 {
                original.with_payload(|payload| {
                    let payload = payload.downcast_ref::<InspectionPayload>().unwrap();
                    assert_eq!(std::ptr::from_ref(payload) as usize, address);
                    assert_eq!(payload.active.fetch_add(1, Ordering::AcqRel), 0);
                    std::thread::yield_now();
                    payload.visits.fetch_add(1, Ordering::AcqRel);
                    assert_eq!(payload.active.fetch_sub(1, Ordering::AcqRel), 1);
                });
            }
            assert_eq!(
                counting.count(),
                0,
                "first and contended inspection allocate no controls"
            );
        })
    });
    for thread in threads {
        thread.join().unwrap();
    }
    original.with_payload(|payload| {
        let payload = payload.downcast_ref::<InspectionPayload>().unwrap();
        assert_eq!(payload.visits.load(Ordering::Acquire), 2048);
        assert_eq!(payload.active.load(Ordering::Acquire), 0);
    });
    assert_eq!(dropped.load(Ordering::Acquire), 0);
    drop(original);
    assert_eq!(dropped.load(Ordering::Acquire), 1);
}

#[test]
fn native_original_panic_inspection_callback_panic_preserves_payload_and_unlocks() {
    let original = Box::new(0xc0b2_u64);
    let original_address = std::ptr::from_ref(original.as_ref()) as usize;
    let original = CorePanic::new(original);
    let secondary: Box<dyn std::any::Any + Send> = Box::new(0xc0b3_u64);
    let secondary_address = secondary.as_ref() as *const dyn std::any::Any as *const () as usize;
    let secondary = catch_unwind(AssertUnwindSafe(|| {
        original.with_payload(|payload| {
            assert_eq!(
                std::ptr::from_ref(payload.downcast_ref::<u64>().unwrap()) as usize,
                original_address
            );
            resume_unwind(secondary)
        });
    }))
    .unwrap_err();
    assert_eq!(
        secondary.as_ref() as *const dyn std::any::Any as *const () as usize,
        secondary_address
    );
    assert_eq!(*secondary.downcast_ref::<u64>().unwrap(), 0xc0b3);
    let counting = super::read_fork_tests::AllocationCount::start();
    original.with_payload(|payload| {
        let payload = payload.downcast_ref::<u64>().unwrap();
        assert_eq!(*payload, 0xc0b2);
        assert_eq!(std::ptr::from_ref(payload) as usize, original_address);
    });
    assert_eq!(
        counting.count(),
        0,
        "inspection after callback panic allocates no control"
    );
}

#[test]
fn native_unknown_io_keeps_original_inline_source_without_diagnostic_allocation() {
    use std::error::Error;
    let original = io::Error::new(
        io::ErrorKind::StorageFull,
        OriginalUnknownIo { marker: 0xc0b0 },
    );
    let address = original.get_ref().unwrap() as *const _ as *const () as usize;
    let counting = super::read_fork_tests::AllocationCount::start();
    let unknown = CoreError::unknown_io(original);
    assert!(unknown.is_unknown_commit());
    assert_eq!(
        unknown.disposition(),
        crate::CoreErrorDisposition::UnknownCommit
    );
    let unknown = unknown
        .into_io()
        .expect_err("unknown disposition must stay owned");
    let storage = StorageError::from(unknown);
    assert_eq!(
        counting.count(),
        0,
        "actual unknown constructor/conversion adds no shell"
    );
    let StorageError::UnknownCommit(original) = &storage else {
        panic!("unknown outcome lost");
    };
    assert!(!storage.is_capacity_denied());
    assert!(original.rejected_cause().is_none());
    for _ in 0..3 {
        let observed = storage
            .source()
            .unwrap()
            .downcast_ref::<CoreError>()
            .unwrap();
        assert!(std::ptr::eq(observed, original));
        let observed_io = observed
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert!(std::ptr::eq(observed_io, original.io_error().unwrap()));
        let marker = observed_io
            .get_ref()
            .unwrap()
            .downcast_ref::<OriginalUnknownIo>()
            .unwrap();
        assert_eq!(marker.marker, 0xc0b0);
        assert_eq!(std::ptr::from_ref(marker) as usize, address);
    }
    assert_eq!(
        counting.count(),
        0,
        "original I/O source traversal allocates no control"
    );
    drop(counting);
}

#[test]
fn native_unknown_panic_keeps_original_inline_source_without_diagnostic_allocation() {
    use std::error::Error;
    let original: Box<dyn std::any::Any + Send> = Box::new(0xc0b1_u64);
    let address = original.as_ref() as *const dyn std::any::Any as *const () as usize;
    let original = catch_unwind(AssertUnwindSafe(|| resume_unwind(original))).unwrap_err();
    let counting = super::read_fork_tests::AllocationCount::start();
    let storage = StorageError::from(CoreError::unknown_commit(CorePanic::new(original)));
    assert_eq!(
        counting.count(),
        0,
        "actual post-catch unknown diagnostic is inline"
    );
    let StorageError::UnknownCommit(original) = &storage else {
        panic!("unknown outcome lost");
    };
    assert!(!storage.is_capacity_denied());
    assert!(original.rejected_cause().is_none());
    for _ in 0..3 {
        let observed = storage
            .source()
            .unwrap()
            .downcast_ref::<CoreError>()
            .unwrap();
        assert!(std::ptr::eq(observed, original));
        let observed_panic = observed
            .source()
            .unwrap()
            .downcast_ref::<CorePanic>()
            .unwrap();
        assert!(std::ptr::eq(observed_panic, original.panic().unwrap()));
        observed_panic.with_payload(|payload| {
            let marker = payload.downcast_ref::<u64>().unwrap();
            assert_eq!(*marker, 0xc0b1);
            assert_eq!(std::ptr::from_ref(marker) as usize, address);
        });
    }
    assert_eq!(
        counting.count(),
        0,
        "source traversal and original panic inspection allocate no control"
    );
    drop(counting);
}

#[test]
fn native_actual_capacity_cause_cannot_erase_unknown_commit_disposition() {
    let ledger = Ledger::new();
    let database = database(&ledger);
    ledger.deny_request_bytes.store(999, Ordering::Release);
    let issued = ledger.issued.load(Ordering::Acquire);
    let used = ledger.used.load(Ordering::Acquire);
    let counting = super::read_fork_tests::AllocationCount::start();
    let actual = match database.inner.core.reserve_workspace(999) {
        Err(actual) => actual,
        Ok(_) => panic!("actual native provider must refuse"),
    };
    assert_eq!(actual.disposition(), crate::CoreErrorDisposition::Rejected);
    assert!(actual.is_capacity_denied());
    assert!(!actual.fences_owner());
    // Exercise the canonical disposition boundary using the actual cause. This
    // is a classification negative control; it does not claim a native commit.
    let unknown = actual.into_unknown_commit();
    assert!(unknown.fences_owner());
    assert!(!unknown.is_capacity_denied());
    assert!(matches!(
        unknown.cause(),
        crate::CoreErrorCause::CapacityDenied
    ));
    assert!(unknown.rejected_cause().is_none());
    let unknown = unknown
        .into_io()
        .expect_err("whole unknown cause remains owned");
    let storage = StorageError::from(unknown);
    assert!(
        matches!(&storage, StorageError::UnknownCommit(original) if original.is_unknown_commit())
    );
    assert!(!storage.is_capacity_denied());
    assert_eq!(counting.count(), 0);
    drop(counting);
    assert_eq!(ledger.issued.load(Ordering::Acquire), issued);
    assert_eq!(ledger.used.load(Ordering::Acquire), used);
    assert!(!database.inner.core.is_fenced());
    drop(storage);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
    assert_eq!(ledger.used.load(Ordering::Acquire), 0);
}
impl Drop for Watch {
    fn drop(&mut self) {
        WATCH_BUFFER_BYTES.with(|bytes| bytes.set(0));
        for target in &TARGETS {
            target.store(0, Ordering::Release);
        }
    }
}

const ROWS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("staging-credit");
fn database(ledger: &Arc<Ledger>) -> Database {
    let database = Database::builder(
        Arc::new(Admission(ledger.clone())),
        [0xcc; 16],
        CacheConfig { byte_limit: 0 },
    )
    .create_with_backend(InMemoryGroup::new())
    .unwrap();
    let transaction = database.begin_write().unwrap();
    transaction.open_table(ROWS).unwrap();
    transaction.commit().unwrap();
    database
}

#[test]
fn native_staging_node_and_lease_retire_before_refund_on_every_terminal() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    for mode in 0..3 {
        let ledger = Ledger::new();
        let database = database(&ledger);
        let baseline = ledger.used.load(Ordering::Acquire);
        let transaction = database.begin_write().unwrap();
        transaction
            .open_table(ROWS)
            .unwrap()
            .insert(b"key", b"value")
            .unwrap();
        let watch = Watch::staging(&transaction, &ledger);
        match mode {
            0 => transaction.commit().unwrap(),
            1 => transaction.abort().unwrap(),
            _ => drop(transaction),
        }
        assert_eq!(ledger.watched_refunds.load(Ordering::Acquire), 1);
        drop(watch);
        ledger.watched_token.store(0, Ordering::Release);
        assert_eq!(ledger.used.load(Ordering::Acquire), baseline);
        let reader = database.begin_read().unwrap();
        assert_eq!(
            reader
                .open_table(ROWS)
                .unwrap()
                .get(b"key")
                .unwrap()
                .is_some(),
            mode == 0
        );
        drop(reader);
        database.close_native().into_result().unwrap();
        assert!(database.into_disposal().dispose().complete());
        assert_eq!(ledger.used.load(Ordering::Acquire), 0);
    }
}

#[test]
fn staging_exact_fallback_funds_its_node_and_denial_preserves_existing_credit() {
    let ledger = Ledger::new();
    let database = database(&ledger);
    let baseline = ledger.used.load(Ordering::Acquire);
    let transaction = database.begin_write().unwrap();
    let mut staged = lock(&transaction.staged);
    let before = ledger.used.load(Ordering::Acquire);
    ledger
        .limit
        .store((17 + STAGING_LEASE_NODE) as u64, Ordering::Release);
    staged.reserve(&database.inner.core, 17).unwrap();
    assert_eq!(
        ledger.used.load(Ordering::Acquire) - before,
        (17 + STAGING_LEASE_NODE) as u64
    );
    assert_eq!(staged.credit.reserved, 17);
    assert!(staged.credit.leases.as_ref().unwrap()[0].next.is_none());
    let retained = ledger.used.load(Ordering::Acquire);
    ledger
        .limit
        .store(STAGING_LEASE_NODE as u64, Ordering::Release);
    assert!(
        staged
            .reserve(&database.inner.core, 1)
            .unwrap_err()
            .is_capacity_denied()
    );
    assert_eq!(ledger.used.load(Ordering::Acquire), retained);
    assert_eq!(staged.credit.reserved, 17);
    assert_eq!(staged.credit.used, 17);
    drop(staged);
    ledger.limit.store(u64::MAX, Ordering::Release);
    transaction.abort().unwrap();
    assert_eq!(ledger.used.load(Ordering::Acquire), baseline);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
    assert_eq!(ledger.used.load(Ordering::Acquire), 0);
}

#[test]
fn staging_node_allocator_denial_refunds_new_grant_and_preserves_original_tail() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let ledger = Ledger::new();
    let database = database(&ledger);
    let transaction = database.begin_write().unwrap();
    let mut staged = lock(&transaction.staged);
    staged.reserve(&database.inner.core, 1).unwrap();
    let original = staged.credit.leases.as_ref().unwrap().as_ptr();
    let used = staged.credit.used;
    let reserved = staged.credit.reserved;
    let charged = ledger.used.load(Ordering::Acquire);
    let refunds = ledger.refunds.load(Ordering::Acquire);
    let watch = Watch::failed_next_node(&ledger);
    let denial = DenyNode::arm();
    assert!(
        staged
            .reserve(&database.inner.core, STAGING_CHUNK)
            .unwrap_err()
            .is_capacity_denied()
    );
    denial.assert_denied();
    assert_eq!(staged.credit.leases.as_ref().unwrap().as_ptr(), original);
    assert_eq!(staged.credit.used, used);
    assert_eq!(staged.credit.reserved, reserved);
    assert_eq!(ledger.used.load(Ordering::Acquire), charged);
    assert_eq!(ledger.refunds.load(Ordering::Acquire), refunds + 1);
    assert_eq!(ledger.watched_refunds.load(Ordering::Acquire), 1);
    drop(denial);
    drop(watch);
    ledger.watched_token.store(0, Ordering::Release);
    drop(staged);
    transaction.abort().unwrap();
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
    assert_eq!(ledger.used.load(Ordering::Acquire), 0);
}

#[test]
fn real_staging_node_allocator_denial_rolls_back_before_publication() {
    let ledger = Ledger::new();
    let database = database(&ledger);
    let transaction = database.begin_write().unwrap();
    let mut table = transaction.open_table(ROWS).unwrap();
    let baseline = ledger.used.load(Ordering::Acquire);
    table.insert(b"first", b"original").unwrap();
    let value = vec![7; STAGING_CHUNK];
    let denial = DenyNode::arm();
    assert!(
        table
            .insert(b"denied", &value)
            .err()
            .unwrap()
            .is_capacity_denied()
    );
    denial.assert_denied();
    drop(denial);
    assert_eq!(ledger.used.load(Ordering::Acquire), baseline);
    assert!(!transaction.holds_writer());
    let reader = database.begin_read().unwrap();
    let rows = reader.open_table(ROWS).unwrap();
    assert!(rows.get(b"first").unwrap().is_none());
    assert!(rows.get(b"denied").unwrap().is_none());
    drop(rows);
    drop(reader);
    assert!(transaction.commit().unwrap_err().0.is_capacity_denied());
    drop(table);
    let fresh = database.begin_write().unwrap();
    fresh
        .open_table(ROWS)
        .unwrap()
        .insert(b"fresh", b"value")
        .unwrap();
    fresh.commit().unwrap();
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
    assert_eq!(ledger.used.load(Ordering::Acquire), 0);
}

#[test]
fn denied_node_refund_panic_preserves_original_tail_credit_and_payload() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let ledger = Ledger::new();
    let database = database(&ledger);
    let transaction = database.begin_write().unwrap();
    let mut staged = lock(&transaction.staged);
    staged.reserve(&database.inner.core, 1).unwrap();
    let original = staged.credit.leases.as_ref().unwrap().as_ptr();
    let used = staged.credit.used;
    let reserved = staged.credit.reserved;
    let charged = ledger.used.load(Ordering::Acquire);
    let callbacks = ledger.callbacks.load(Ordering::Acquire);
    let refunds = ledger.refunds.load(Ordering::Acquire);
    let payload = Box::new(0x0a110c_u64);
    let address = payload.as_ref() as *const u64 as usize;
    *ledger.payload.lock().unwrap() = Some(payload);
    let failed_token = ledger.issued.load(Ordering::Acquire) + 1;
    ledger.panic_token.store(failed_token, Ordering::Release);
    let watch = Watch::failed_next_node(&ledger);
    let denial = DenyNode::arm();
    let panic = catch_unwind(AssertUnwindSafe(|| {
        staged.reserve(&database.inner.core, STAGING_CHUNK)
    }))
    .unwrap_err();
    denial.assert_denied();
    assert_eq!(
        panic.downcast_ref::<u64>().unwrap() as *const u64 as usize,
        address
    );
    assert_eq!(staged.credit.leases.as_ref().unwrap().as_ptr(), original);
    assert_eq!(staged.credit.used, used);
    assert_eq!(staged.credit.reserved, reserved);
    assert_eq!(ledger.callbacks.load(Ordering::Acquire), callbacks + 1);
    assert_eq!(ledger.refunds.load(Ordering::Acquire), refunds);
    assert_eq!(
        ledger.used.load(Ordering::Acquire),
        charged + (STAGING_CHUNK + STAGING_LEASE_NODE) as u64
    );
    // Only the entered failed callback is unreconciled; the exact untouched
    // original tail can still retire without another invocation of it.
    drop(denial);
    drop(watch);
    ledger.watched_token.store(0, Ordering::Release);
    ledger.panic_token.store(0, Ordering::Release);
    drop(staged);
    transaction.abort().unwrap();
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
    assert_eq!(
        ledger.used.load(Ordering::Acquire),
        (STAGING_CHUNK + STAGING_LEASE_NODE) as u64
    );
}

#[test]
fn native_shared_staging_control_prepays_actual_arc_and_concurrent_final_drop() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let ledger = Ledger::new();
    let database = database(&ledger);
    let baseline = ledger.used.load(Ordering::Acquire);
    let callbacks = ledger.callbacks.load(Ordering::Acquire);
    let refunds = ledger.refunds.load(Ordering::Acquire);
    let watch = Watch::failed_next_node(&ledger);
    ledger
        .watch_request_bytes
        .store(SharedPending::CHARGE_BYTES, Ordering::Release);
    let writer = WriterGate::enter(&database.inner.gate, &database.inner.closing).unwrap();
    let sync = crate::native_sync::tests::Watch::new();
    let counting = super::read_fork_tests::AllocationCount::start();
    let shared = SharedPending::new(&database.inner.core, writer).unwrap();
    let mutex_control = usize::from(crate::native_sync::mutex_backing_bytes() != 0);
    assert_eq!(
        counting.count(),
        2 + mutex_control,
        "actual original grant Box, admitted pending mutex, and staging Arc only"
    );
    assert_eq!(counting.addresses()[0], TARGETS[1].load(Ordering::Acquire));
    assert_eq!(sync.count(), mutex_control);
    if mutex_control != 0 {
        let (funding, address, bytes, align, freed) = sync.record(0);
        assert_eq!(funding, TARGETS[1].load(Ordering::Acquire));
        assert_eq!(address, counting.addresses()[1]);
        #[cfg(unix)]
        assert_eq!(
            (bytes, align),
            (
                size_of::<libc::pthread_mutex_t>(),
                std::mem::align_of::<libc::pthread_mutex_t>()
            )
        );
        assert!(!freed);
    }
    let arc_start = counting.addresses()[1 + mutex_control];
    let arc_bytes = counting.layouts()[1 + mutex_control].0;
    let arc_payload = Arc::as_ptr(shared.0.as_ref().unwrap()) as usize;
    assert!(arc_payload >= arc_start && arc_payload - arc_start < arc_bytes);

    drop(counting);
    assert!(
        SharedPending::CHARGE_BYTES
            >= (size_of::<PendingBacking>() + 2 * size_of::<usize>()) as u64
    );
    assert_eq!(
        ledger.used.load(Ordering::Acquire),
        baseline + SharedPending::CHARGE_BYTES
    );
    FREED[0].store(false, Ordering::Release);
    TARGETS[0].store(
        Arc::as_ptr(shared.0.as_ref().unwrap()) as usize,
        Ordering::Release,
    );
    let left = shared.clone();
    let right = shared.clone();
    drop(shared);
    assert_eq!(
        ledger.used.load(Ordering::Acquire),
        baseline + SharedPending::CHARGE_BYTES
    );
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        for alias in [left, right] {
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                drop(alias);
            });
        }
    });
    assert!(FREED.iter().all(|freed| freed.load(Ordering::Acquire)));
    sync.assert_all_retired();
    assert_eq!(ledger.watched_refunds.load(Ordering::Acquire), 1);
    assert_eq!(ledger.callbacks.load(Ordering::Acquire), callbacks + 1);
    assert_eq!(ledger.refunds.load(Ordering::Acquire), refunds + 1);
    assert_eq!(ledger.used.load(Ordering::Acquire), baseline);
    assert!(!*database.inner.gate.held.lock().unwrap());
    drop(watch);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
}

#[test]
fn native_shared_staging_control_refusal_precedes_actual_arc_allocation() {
    let ledger = Ledger::new();
    let database = database(&ledger);
    let baseline = ledger.used.load(Ordering::Acquire);
    let issued = ledger.issued.load(Ordering::Acquire);
    ledger.limit.store(0, Ordering::Release);
    let writer = WriterGate::enter(&database.inner.gate, &database.inner.closing).unwrap();
    let sync = crate::native_sync::tests::Watch::new();
    let counting = super::read_fork_tests::AllocationCount::start();
    let result = SharedPending::new(&database.inner.core, writer);
    assert!(
        matches!(&(result), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    assert_eq!(counting.count(), 0);
    assert_eq!(
        sync.count(),
        0,
        "actual first control denial initializes no synchronization backing"
    );
    drop(counting);
    assert_eq!(ledger.issued.load(Ordering::Acquire), issued);
    assert_eq!(ledger.used.load(Ordering::Acquire), baseline);
    assert!(!*database.inner.gate.held.lock().unwrap());
    ledger.limit.store(u64::MAX, Ordering::Release);
    database.begin_write().unwrap().abort().unwrap();
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
}

#[test]
fn native_shared_staging_control_retirement_panic_keeps_original_without_replay() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let ledger = Ledger::new();
    let database = database(&ledger);
    let baseline = ledger.used.load(Ordering::Acquire);
    let watch = Watch::failed_next_node(&ledger);
    ledger
        .watch_request_bytes
        .store(SharedPending::CHARGE_BYTES, Ordering::Release);
    let writer = WriterGate::enter(&database.inner.gate, &database.inner.closing).unwrap();
    let sync = crate::native_sync::tests::Watch::new();
    let shared = SharedPending::new(&database.inner.core, writer).unwrap();
    FREED[0].store(false, Ordering::Release);
    TARGETS[0].store(
        Arc::as_ptr(shared.0.as_ref().unwrap()) as usize,
        Ordering::Release,
    );
    let payload = Box::new(0x0c07_1701_u64);
    let address = std::ptr::from_ref(payload.as_ref()) as usize;
    *ledger.payload.lock().unwrap() = Some(payload);
    ledger.panic_token.store(
        ledger.watched_token.load(Ordering::Acquire),
        Ordering::Release,
    );
    let callbacks = ledger.callbacks.load(Ordering::Acquire);
    let refunds = ledger.refunds.load(Ordering::Acquire);
    let original = catch_unwind(AssertUnwindSafe(|| drop(shared))).unwrap_err();
    assert_eq!(
        std::ptr::from_ref(original.downcast_ref::<u64>().unwrap()) as usize,
        address
    );
    assert!(FREED.iter().all(|freed| freed.load(Ordering::Acquire)));
    sync.assert_all_retired();
    assert_eq!(ledger.callbacks.load(Ordering::Acquire), callbacks + 1);
    assert_eq!(ledger.refunds.load(Ordering::Acquire), refunds);
    assert_eq!(
        ledger.used.load(Ordering::Acquire),
        baseline + SharedPending::CHARGE_BYTES
    );
    assert!(!*database.inner.gate.held.lock().unwrap());
    drop(watch);
    database.close_native().into_result().unwrap();
    assert!(database.into_disposal().dispose().complete());
    assert_eq!(
        ledger.used.load(Ordering::Acquire),
        SharedPending::CHARGE_BYTES
    );
}

fn credits(ledger: &Arc<Ledger>, count: usize) -> StagingCredit {
    let mut credit = StagingCredit::default();
    for _ in 0..count {
        credit
            .push(NativeResidentLease::new(
                ledger.grant(STAGING_LEASE_NODE as u64).unwrap(),
            ))
            .unwrap();
    }
    credit
}

#[test]
fn first_staging_refund_panic_retains_unentered_tail_and_original_payload() {
    let ledger = Ledger::new();
    let credit = credits(&ledger, 3);
    let payload = Box::new(0xc0ffee_u64);
    let address = payload.as_ref() as *const u64 as usize;
    *ledger.payload.lock().unwrap() = Some(payload);
    ledger.panic_token.store(3, Ordering::Release);
    let panic = catch_unwind(AssertUnwindSafe(|| drop(credit))).unwrap_err();
    assert_eq!(panic.downcast_ref::<u64>(), Some(&0xc0ffee));
    assert_eq!(
        panic.downcast_ref::<u64>().unwrap() as *const u64 as usize,
        address
    );
    assert_eq!(ledger.callbacks.load(Ordering::Acquire), 1);
    assert_eq!(ledger.refunds.load(Ordering::Acquire), 0);
    assert_eq!(
        ledger.used.load(Ordering::Acquire),
        3 * STAGING_LEASE_NODE as u64
    );
}

#[test]
fn existing_unwind_does_not_enter_staging_refunds_or_replace_its_payload() {
    let ledger = Ledger::new();
    let credit = credits(&ledger, 3);
    let payload = Box::new(0xbadcafe_u64);
    let address = payload.as_ref() as *const u64 as usize;
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _credit = credit;
        resume_unwind(payload);
    }))
    .unwrap_err();
    assert_eq!(
        panic.downcast_ref::<u64>().unwrap() as *const u64 as usize,
        address
    );
    assert_eq!(ledger.callbacks.load(Ordering::Acquire), 0);
    assert_eq!(
        ledger.used.load(Ordering::Acquire),
        3 * STAGING_LEASE_NODE as u64
    );
}

#[test]
fn thousands_of_staging_nodes_retire_with_a_bounded_stack() {
    let ledger = Ledger::new();
    let worker_ledger = ledger.clone();
    std::thread::Builder::new()
        .stack_size(64 << 10)
        .spawn(move || drop(credits(&worker_ledger, 4096)))
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(ledger.callbacks.load(Ordering::Acquire), 4096);
    assert_eq!(ledger.refunds.load(Ordering::Acquire), 4096);
    assert_eq!(ledger.used.load(Ordering::Acquire), 0);
}
