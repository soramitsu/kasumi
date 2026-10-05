use super::*;
use std::{
    alloc::{GlobalAlloc, System},
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Barrier, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

struct ObservedSystem;
#[global_allocator]
static ALLOCATOR: ObservedSystem = ObservedSystem;
thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
    static ALLOCATION: Cell<Option<(usize, usize, usize)>> = const { Cell::new(None) };
}
static TEST_LOCK: Mutex<()> = Mutex::new(());
static WATCHED: AtomicUsize = AtomicUsize::new(0);
static CONTROL_FREED: AtomicBool = AtomicBool::new(false);
static CONTROL_RETIREMENTS: AtomicUsize = AtomicUsize::new(0);
static REFUNDS: AtomicUsize = AtomicUsize::new(0);

fn allocated(pointer: *mut u8, layout: Layout) {
    if !pointer.is_null() && COUNTING.try_with(Cell::get).unwrap_or(false) {
        let _ = COUNT.try_with(|count| count.set(count.get() + 1));
        let _ = ALLOCATION.try_with(|allocation| {
            if allocation.get().is_none() {
                allocation.set(Some((pointer as usize, layout.size(), layout.align())));
            }
        });
    }
}
// SAFETY: unchanged allocation contracts forward directly to System. The
// observer records fixed scalar values and never accesses allocated memory.
unsafe impl GlobalAlloc for ObservedSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        allocated(pointer, layout);
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        allocated(pointer, layout);
        pointer
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let pointer = unsafe { System.realloc(pointer, layout, size) };
        allocated(
            pointer,
            Layout::from_size_align(size, layout.align()).unwrap(),
        );
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let watched = pointer as usize == WATCHED.load(Ordering::Acquire);
        unsafe { System.dealloc(pointer, layout) };
        if watched
            && WATCHED
                .compare_exchange(pointer as usize, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            CONTROL_RETIREMENTS.fetch_add(1, Ordering::AcqRel);
            // Positive witness is after actual System deallocation returned.
            CONTROL_FREED.store(true, Ordering::Release);
        }
    }
}

fn measure<T>(body: impl FnOnce() -> T) -> (T, usize, Option<(usize, usize, usize)>) {
    struct CountingGuard;
    impl Drop for CountingGuard {
        fn drop(&mut self) {
            COUNTING.with(|active| active.set(false));
        }
    }
    COUNT.with(|count| count.set(0));
    ALLOCATION.with(|allocation| allocation.set(None));
    COUNTING.with(|active| assert!(!active.replace(true)));
    let guard = CountingGuard;
    let result = body();
    drop(guard);
    (result, COUNT.with(Cell::get), ALLOCATION.with(Cell::get))
}
fn watch(pointer: usize) {
    CONTROL_FREED.store(false, Ordering::Release);
    CONTROL_RETIREMENTS.store(0, Ordering::Release);
    REFUNDS.store(0, Ordering::Release);
    WATCHED.store(pointer, Ordering::Release);
}
fn stop_watch() {
    WATCHED.store(0, Ordering::Release);
}

struct OriginalBudget;
impl Drop for OriginalBudget {
    fn drop(&mut self) {
        assert!(CONTROL_FREED.load(Ordering::Acquire));
        REFUNDS.fetch_add(1, Ordering::AcqRel);
    }
}
#[repr(align(4096))]
struct AlignedBudget {
    _original: OriginalBudget,
}

fn check_layout<T: Send + Sync + 'static>(original: T) {
    let expected = SharedBudgetCharge::allocation_layout::<T>().unwrap();
    let (_, quote_allocations, _) = measure(|| SharedBudgetCharge::required_bytes::<T>().unwrap());
    assert_eq!(quote_allocations, 0);
    let (charge, allocations, allocation) = measure(|| SharedBudgetCharge::new(original));
    assert_eq!(allocations, 1);
    let (pointer, size, align) = allocation.unwrap();
    assert_eq!((size, align), (expected.size(), expected.align()));
    assert!(SharedBudgetCharge::required_bytes::<T>().unwrap() >= size as u64);
    watch(pointer);
    let (alias, allocations, _) = measure(|| charge.clone());
    assert_eq!(allocations, 0);
    assert!(SharedBudgetCharge::ptr_eq(&charge, &alias));
    drop(charge);
    assert!(!CONTROL_FREED.load(Ordering::Acquire));
    assert_eq!(REFUNDS.load(Ordering::Acquire), 0);
    drop(alias);
    assert!(CONTROL_FREED.load(Ordering::Acquire));
    assert_eq!(CONTROL_RETIREMENTS.load(Ordering::Acquire), 1);
    assert_eq!(REFUNDS.load(Ordering::Acquire), 1);
    stop_watch();
}

#[test]
fn shared_budget_actual_zst_and_overaligned_controls_retire_before_original_refund() {
    let _serial = TEST_LOCK.lock().unwrap();
    assert_eq!(
        std::mem::size_of::<SharedBudgetCharge>(),
        2 * std::mem::size_of::<usize>()
    );
    assert_eq!(
        std::mem::align_of::<SharedBudgetCharge>(),
        std::mem::align_of::<Arc<()>>()
    );
    check_layout(OriginalBudget);
    check_layout(AlignedBudget {
        _original: OriginalBudget,
    });
}

#[test]
fn shared_budget_concurrent_final_aliases_retire_actual_control_and_refund_once() {
    let _serial = TEST_LOCK.lock().unwrap();
    let (charge, allocations, allocation) = measure(|| SharedBudgetCharge::new(OriginalBudget));
    assert_eq!(allocations, 1);
    watch(allocation.unwrap().0);
    let alias = charge.clone();
    let start = Barrier::new(3);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            start.wait();
            drop(charge);
        });
        let second = scope.spawn(|| {
            start.wait();
            drop(alias);
        });
        start.wait();
        first.join().unwrap();
        second.join().unwrap();
    });
    assert!(CONTROL_FREED.load(Ordering::Acquire));
    assert_eq!(CONTROL_RETIREMENTS.load(Ordering::Acquire), 1);
    assert_eq!(REFUNDS.load(Ordering::Acquire), 1);
    stop_watch();
}

#[derive(Debug)]
struct OriginalPanic {
    id: u64,
}
struct PanickingBudget {
    original: Option<Box<OriginalPanic>>,
}
impl Drop for PanickingBudget {
    fn drop(&mut self) {
        assert!(CONTROL_FREED.load(Ordering::Acquire));
        REFUNDS.fetch_add(1, Ordering::AcqRel);
        std::panic::resume_unwind(self.original.take().unwrap());
    }
}

#[test]
fn shared_budget_original_payload_panic_occurs_after_actual_control_deallocation() {
    let _serial = TEST_LOCK.lock().unwrap();
    let original = Box::new(OriginalPanic { id: 73 });
    let original_pointer = original.as_ref() as *const OriginalPanic as usize;
    let (charge, allocations, allocation) = measure(|| {
        SharedBudgetCharge::new(PanickingBudget {
            original: Some(original),
        })
    });
    assert_eq!(allocations, 1);
    watch(allocation.unwrap().0);
    let alias = charge.clone();
    drop(charge);
    assert_eq!(REFUNDS.load(Ordering::Acquire), 0);
    let panic = catch_unwind(AssertUnwindSafe(|| drop(alias))).unwrap_err();
    let actual = panic.downcast_ref::<OriginalPanic>().unwrap();
    assert_eq!(actual.id, 73);
    assert_eq!(actual as *const OriginalPanic as usize, original_pointer);
    assert!(CONTROL_FREED.load(Ordering::Acquire));
    assert_eq!(CONTROL_RETIREMENTS.load(Ordering::Acquire), 1);
    assert_eq!(REFUNDS.load(Ordering::Acquire), 1);
    stop_watch();
}
