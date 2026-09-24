//! Thread-local allocation observation for synchronous publication boundaries.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static DEALLOCATION_ADDRESS: Cell<*const ()> = const { Cell::new(std::ptr::null()) };
    static DEALLOCATION_OBSERVER: Cell<*const DeallocationObservation> = const { Cell::new(std::ptr::null()) };
}
struct ObservedSystem;
#[global_allocator]
static ALLOCATOR: ObservedSystem = ObservedSystem;

fn allocated() {
    if ACTIVE.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
    }
}
// SAFETY: every operation forwards its unchanged allocation contract to System.
unsafe impl GlobalAlloc for ObservedSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocated();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocated();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocated();
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let observation = observe_before_deallocation(pointer, layout);
        unsafe { System.dealloc(pointer, layout) };
        if let Some(observation) = observation {
            // SAFETY: observe_deallocation retains its borrowed observer for
            // this entire synchronous allocator call, including a blocked gate.
            unsafe { &*observation }
                .finished
                .store(true, Ordering::Release);
        }
    }
}

pub(crate) fn measure<T>(work: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ACTIVE.with(|active| active.set(false));
        }
    }
    ACTIVE.with(|active| assert!(!active.replace(true), "nested allocation measurement"));
    ALLOCATIONS.with(|n| n.set(0));
    let reset = Reset;
    let result = work();
    drop(reset);
    (result, ALLOCATIONS.with(Cell::get))
}

/// One exact Box allocation's real System.dealloc boundary. The observer never
/// invokes callbacks, formats messages, allocates, or takes application locks.
/// A paused boundary permits another thread to challenge early credit reuse.
pub(crate) struct DeallocationObservation {
    block: bool,
    entered: AtomicBool,
    released: AtomicBool,
    finished: AtomicBool,
    count: AtomicUsize,
    bytes: AtomicUsize,
}
impl DeallocationObservation {
    pub(crate) fn new(block: bool) -> Self {
        Self {
            block,
            entered: AtomicBool::new(false),
            released: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            count: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
        }
    }
    pub(crate) fn entered(&self) -> bool {
        self.entered.load(Ordering::Acquire)
    }
    pub(crate) fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
    pub(crate) fn release(&self) {
        self.released.store(true, Ordering::Release);
    }
    pub(crate) fn count(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }
    pub(crate) fn bytes(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }
}

fn observe_before_deallocation(
    pointer: *mut u8,
    layout: Layout,
) -> Option<*const DeallocationObservation> {
    let observed = DEALLOCATION_ADDRESS
        .try_with(|address| {
            if address.get() == pointer.cast::<()>() {
                address.set(std::ptr::null());
                true
            } else {
                false
            }
        })
        .unwrap_or(false);
    if !observed {
        return None;
    }
    let observer = DEALLOCATION_OBSERVER.try_with(Cell::get).ok()?;
    if observer.is_null() {
        return None;
    }
    // SAFETY: observe_deallocation installs this thread-local pointer from a
    // live borrow and resets it before returning/unwinding. Deallocation and
    // this observer are synchronous on that same thread. No pointer escapes.
    let state = unsafe { &*observer };
    state.count.fetch_add(1, Ordering::AcqRel);
    state.bytes.store(layout.size(), Ordering::Release);
    state.entered.store(true, Ordering::Release);
    while state.block && !state.released.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    Some(observer)
}

pub(crate) fn observe_deallocation<T>(
    address: *const (),
    observation: &DeallocationObservation,
    work: impl FnOnce() -> T,
) -> T {
    assert!(!address.is_null());
    DEALLOCATION_OBSERVER.with(|current| {
        assert!(current.get().is_null(), "nested deallocation observation");
    });
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            DEALLOCATION_ADDRESS.with(|address| address.set(std::ptr::null()));
            DEALLOCATION_OBSERVER.with(|observer| observer.set(std::ptr::null()));
        }
    }
    DEALLOCATION_OBSERVER.with(|current| current.set(std::ptr::from_ref(observation)));
    DEALLOCATION_ADDRESS.with(|current| current.set(address));
    let _reset = Reset;
    work()
}
