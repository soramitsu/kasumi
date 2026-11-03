//! Hooks are forwarded by the existing Engine test global allocator. No second
//! allocator, provider substitute, production hook or borrowed pointer escapes.
use std::{
    alloc::Layout,
    cell::Cell,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Default)]
struct Counts {
    live: i64,
    peak: i64,
    allocations: usize,
}
thread_local! {
    static COUNTS: Cell<Option<Counts>> = const { Cell::new(None) };
}
fn note(delta: i64, allocation: bool) {
    let _ = COUNTS.try_with(|slot| {
        if let Some(mut counts) = slot.get() {
            counts.live += delta;
            counts.peak = counts.peak.max(counts.live);
            counts.allocations += usize::from(allocation);
            slot.set(Some(counts));
        }
    });
}
pub(crate) fn allocated(bytes: usize) {
    note(bytes as i64, true);
}
pub(crate) fn reallocated(old: usize, new: usize) {
    // Model allocate/copy/free overlap, including an in-place realloc.
    note(new as i64, true);
    note(-(old as i64), false);
}
pub(crate) fn before_deallocate(pointer: *mut u8, layout: Layout) -> bool {
    BODY.before(pointer, layout)
}
pub(crate) fn deallocated(bytes: usize, watched: bool) {
    note(-(bytes as i64), false);
    if watched {
        BODY.finished.store(true, Ordering::Release);
    }
}
struct Measurement;
impl Measurement {
    fn begin() -> Self {
        COUNTS.with(|slot| {
            assert!(slot.get().is_none());
            slot.set(Some(Counts::default()));
        });
        Self
    }
    fn finish(self) -> Counts {
        let result = COUNTS.with(|slot| slot.replace(None).unwrap());
        drop(self);
        result
    }
}
impl Drop for Measurement {
    fn drop(&mut self) {
        COUNTS.with(|slot| slot.set(None));
    }
}
/// Counts this thread's allocations until `finish`; disabled on every other
/// thread and outside the guard.
pub(crate) struct AllocationGuard(Measurement);
impl AllocationGuard {
    pub(crate) fn begin() -> Self {
        Self(Measurement::begin())
    }
    pub(crate) fn finish(self) -> usize {
        self.0.finish().allocations
    }
}

struct Watch {
    address: AtomicUsize,
    entered: AtomicBool,
    released: AtomicBool,
    finished: AtomicBool,
    count: AtomicUsize,
}
impl Watch {
    const fn new() -> Self {
        Self {
            address: AtomicUsize::new(0),
            entered: AtomicBool::new(false),
            released: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            count: AtomicUsize::new(0),
        }
    }
    fn arm(&'static self, address: usize) -> Release {
        assert_ne!(address, 0);
        assert_eq!(self.address.load(Ordering::Acquire), 0);
        self.entered.store(false, Ordering::Relaxed);
        self.released.store(false, Ordering::Relaxed);
        self.finished.store(false, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
        self.address.store(address, Ordering::Release);
        Release(self)
    }
    fn before(&self, pointer: *mut u8, layout: Layout) -> bool {
        let address = self.address.load(Ordering::Acquire);
        if address == 0 || address.wrapping_sub(pointer as usize) >= layout.size() {
            return false;
        }
        if self
            .address
            .compare_exchange(address, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        self.count.fetch_add(1, Ordering::AcqRel);
        self.entered.store(true, Ordering::Release);
        while !self.released.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        true
    }
    fn wait(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.entered.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "expected actual deallocation event"
            );
            std::thread::yield_now();
        }
    }
}
struct Release(&'static Watch);
impl Release {
    fn release(&self) {
        self.0.released.store(true, Ordering::Release);
    }
}
impl Drop for Release {
    fn drop(&mut self) {
        self.release();
        self.0.address.store(0, Ordering::Release);
    }
}
static SERIAL: Mutex<()> = Mutex::new(());
static BODY: Watch = Watch::new();

// Reuse the Engine's one allocator for the concrete topology producer. Both
// bridges are test-only; no allocator callback acquires an admission lock.
pub(crate) fn measure_topology_input<T>(work: impl FnOnce() -> T) -> (T, i64, i64, usize) {
    let measurement = Measurement::begin();
    let result = work();
    let counts = measurement.finish();
    (result, counts.live, counts.peak, counts.allocations)
}
pub(crate) fn check_topology_input_drop(
    address: usize,
    dispose: impl FnOnce() + Send + 'static,
    check: impl FnOnce(),
) {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let release = BODY.arm(address);
    let worker = std::thread::spawn(dispose);
    BODY.wait();
    check();
    release.release();
    worker.join().unwrap();
    assert!(BODY.finished.load(Ordering::Acquire));
    assert_eq!(BODY.count.load(Ordering::Acquire), 1);
}

// Drop the real non-Send ApplyOwner on its original thread. A separate
// observer pauses exactly its paid change-tree allocation at System.dealloc,
// checks the original ledger and then permits that same deallocation to return.
pub(crate) fn check_mutation_change_tree_drop(
    address: usize,
    dispose: impl FnOnce(),
    check: impl FnOnce() + Send + 'static,
) {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let release = BODY.arm(address);
    let observer = std::thread::spawn(move || {
        BODY.wait();
        check();
        release.release();
    });
    dispose();
    observer.join().unwrap();
    assert!(BODY.finished.load(Ordering::Acquire));
    assert_eq!(BODY.count.load(Ordering::Acquire), 1);
}
