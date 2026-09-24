//! Observe the production library's private opening allocation through public
//! APIs. The redb dependency is compiled without cfg(test); no fixture-only
//! field or proxy replaces the actual OpeningAdmission allocation.
use redb::{
    AdmissionError, BackendCloseOutcome, Builder, DatabaseOpenMode, DatabaseOpenSettlement,
    OwnerFailed, ResidentLease, StorageAdmission, StorageBackend,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Allocations {
    count: usize,
    first: Option<(usize, usize)>,
}
thread_local! {
    static OBSERVING: Cell<bool> = const { Cell::new(false) };
    static OBSERVED: Cell<Allocations> = const { Cell::new(Allocations { count: 0, first: None }) };
}
struct ObservedAllocator;
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn record(size: usize, alignment: usize) {
    let _ = OBSERVING.try_with(|observing| {
        if observing.get() {
            let _ = OBSERVED.try_with(|observed| {
                let mut value = observed.get();
                if value.count == 0 {
                    value.first = Some((size, alignment));
                }
                value.count += 1;
                observed.set(value);
            });
        }
    });
}
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size(), layout.align());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size(), layout.align());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size, layout.align());
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
struct Observation;
impl Drop for Observation {
    fn drop(&mut self) {
        OBSERVING.with(|observing| observing.set(false));
    }
}
fn measure<T>(operation: impl FnOnce() -> T) -> (T, Allocations) {
    OBSERVED.with(|observed| observed.set(Allocations::default()));
    OBSERVING.with(|observing| assert!(!observing.replace(true)));
    let guard = Observation;
    let value = operation();
    drop(guard);
    (value, OBSERVED.with(Cell::get))
}

#[derive(Debug, Default)]
struct Calls {
    operations: AtomicUsize,
    closes: AtomicUsize,
}
#[derive(Debug)]
struct Backend(Arc<Calls>);
impl Backend {
    fn unexpected<T>(&self) -> io::Result<T> {
        self.0.operations.fetch_add(1, Ordering::SeqCst);
        Err(io::ErrorKind::Other.into())
    }
}
impl StorageBackend for Backend {
    fn len(&self) -> io::Result<u64> {
        self.unexpected()
    }
    fn read(&self, _: u64, _: &mut [u8]) -> io::Result<()> {
        self.unexpected()
    }
    fn set_len(&self, _: u64) -> io::Result<()> {
        self.unexpected()
    }
    fn sync_data(&self) -> io::Result<()> {
        self.unexpected()
    }
    fn write(&self, _: u64, _: &[u8]) -> io::Result<()> {
        self.unexpected()
    }
    fn close(&self) -> BackendCloseOutcome {
        self.0.closes.fetch_add(1, Ordering::SeqCst);
        BackendCloseOutcome::drained(Ok(()))
    }
}
#[derive(Debug)]
struct Admission;
impl StorageAdmission for Admission {
    fn reserve_workspace(&self, _: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        Ok(Box::new(()))
    }
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        Err(AdmissionError::CapacityDenied)
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn owner_failed(&self) {}
}

#[test]
fn production_opening_plan_matches_actual_arc_request_before_backend_effects() {
    let (plan, query_allocations) = measure(Builder::retained_opening_allocation_layout);
    let plan = plan.unwrap();
    assert_eq!(query_allocations, Allocations::default());

    for mode in [DatabaseOpenMode::Create, DatabaseOpenMode::Existing] {
        let calls = Arc::new(Calls::default());
        let builder = Builder::new(Arc::new(Admission));
        let backend = Box::new(Backend(calls.clone()));
        let (mut opening, allocations) = measure(|| builder.retain_backend(backend, mode));
        assert_eq!(allocations.count, 1);
        assert_eq!(allocations.first, Some((plan.size(), plan.align())));
        assert_eq!(calls.operations.load(Ordering::SeqCst), 0);
        assert_eq!(calls.closes.load(Ordering::SeqCst), 0);
        assert_eq!(
            opening.report().settlement(),
            DatabaseOpenSettlement::Prepared
        );
        assert_eq!(opening.close().settlement(), DatabaseOpenSettlement::Closed);
        assert_eq!(calls.operations.load(Ordering::SeqCst), 0);
        assert_eq!(calls.closes.load(Ordering::SeqCst), 1);
    }
}
