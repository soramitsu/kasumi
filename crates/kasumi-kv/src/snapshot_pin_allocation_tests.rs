//! Reuses the KV test binary's actual System allocator observer.
use super::tests::{root, setup};
use super::*;
use std::alloc::Layout;
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, AtomicUsize};

static WATCH_LOCK: Mutex<()> = Mutex::new(());
static LEDGER: AtomicUsize = AtomicUsize::new(0);
static GRANT: AtomicU64 = AtomicU64::new(0);
static TARGETS: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
static FREED: [AtomicBool; 3] = [const { AtomicBool::new(false) }; 3];
static REFUNDS: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    static COUNT: Cell<Option<usize>> = const { Cell::new(None) };
}
pub(crate) fn note_allocation() {
    let _ = COUNT.try_with(|count| {
        if let Some(n) = count.get() {
            count.set(Some(n + 1));
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
pub(super) fn before_refund(ledger: usize, bytes: u64) {
    if LEDGER.load(Ordering::Acquire) == ledger && GRANT.load(Ordering::Acquire) == bytes {
        for (target, freed) in TARGETS.iter().zip(&FREED) {
            if target.load(Ordering::Acquire) != 0 {
                assert!(
                    freed.load(Ordering::Acquire),
                    "native allocation survived its final credit"
                );
            }
        }
        REFUNDS.fetch_add(1, Ordering::AcqRel);
    }
}
pub(crate) struct AllocationCount;
impl AllocationCount {
    pub(crate) fn start() -> Self {
        COUNT.with(|count| assert!(count.replace(Some(0)).is_none()));
        Self
    }
    pub(crate) fn count(&self) -> usize {
        COUNT.with(|count| count.get().unwrap())
    }
}
impl Drop for AllocationCount {
    fn drop(&mut self) {
        COUNT.with(|count| count.set(None));
    }
}

struct Watch;
impl Watch {
    fn new(admission: &super::tests::Admission, grant: u64, targets: [usize; 3]) -> Self {
        for ((target, freed), address) in TARGETS.iter().zip(&FREED).zip(targets) {
            freed.store(false, Ordering::Release);
            target.store(address, Ordering::Release);
        }
        GRANT.store(grant, Ordering::Release);
        REFUNDS.store(0, Ordering::Release);
        LEDGER.store(Arc::as_ptr(&admission.used) as usize, Ordering::Release);
        Self
    }
    fn assert_refunded(&self) {
        assert_eq!(REFUNDS.load(Ordering::Acquire), 1);
    }
}
impl Drop for Watch {
    fn drop(&mut self) {
        LEDGER.store(0, Ordering::Release);
        for target in &TARGETS {
            target.store(0, Ordering::Release);
        }
    }
}

#[test]
fn native_registry_arc_slots_and_lease_box_deallocate_before_credit() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let (admission, pins) = setup(4);
    let targets = [
        Arc::as_ptr(pins.inner.0.as_ref().unwrap()) as usize,
        pins.inner.state.lock().unwrap().slots.as_ptr() as usize,
        admission.last_box.load(Ordering::Acquire),
    ];
    let watch = Watch::new(&admission, admission.used.load(Ordering::Acquire), targets);
    drop(pins);
    watch.assert_refunded();
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn native_capture_vector_and_lease_box_deallocate_before_credit() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let (admission, pins) = setup(4);
    let pin = pins.acquire(root(1)).unwrap();
    let baseline = admission.used.load(Ordering::Acquire);
    let capture = pins.capture().unwrap();
    let watch = Watch::new(
        &admission,
        admission.used.load(Ordering::Acquire) - baseline,
        [
            capture.roots.as_ptr() as usize,
            admission.last_box.load(Ordering::Acquire),
            0,
        ],
    );
    drop(capture);
    watch.assert_refunded();
    assert_eq!(admission.used.load(Ordering::Acquire), baseline);
    drop(pin);
}

#[test]
fn native_rights_arc_and_lease_box_deallocate_before_credit() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let (admission, pins) = setup(4);
    let baseline = admission.used.load(Ordering::Acquire);
    let rights = pins.reserve_source_rights().unwrap();
    let watch = Watch::new(
        &admission,
        admission.used.load(Ordering::Acquire) - baseline,
        [
            Arc::as_ptr(rights.inner.0.as_ref().unwrap()) as usize,
            admission.last_box.load(Ordering::Acquire),
            0,
        ],
    );
    drop(rights);
    watch.assert_refunded();
    assert_eq!(admission.used.load(Ordering::Acquire), baseline);
}

#[test]
fn native_uninstalled_pin_cancel_deallocates_actual_prepared_arc_and_lease_box() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let (admission, pins) = setup(4);
    let rights = pins.reserve_source_rights().unwrap();
    let baseline = admission.used.load(Ordering::Acquire);
    let mut prepared = pins.prepare_protected(&rights).unwrap();
    let watch = Watch::new(
        &admission,
        admission.used.load(Ordering::Acquire) - baseline,
        [
            Arc::as_ptr(prepared.pin.as_ref().unwrap().inner.0.as_ref().unwrap()) as usize,
            admission.last_box.load(Ordering::Acquire),
            0,
        ],
    );
    prepared.cancel().unwrap();
    watch.assert_refunded();
    assert_eq!(admission.used.load(Ordering::Acquire), baseline);
}

#[test]
fn native_protected_pin_concurrent_final_aliases_deallocate_before_credit() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let (admission, pins) = setup(4);
    let rights = pins.reserve_source_rights().unwrap();
    let baseline = admission.used.load(Ordering::Acquire);
    let mut prepared = pins.prepare_protected(&rights).unwrap();
    let pin = pins.install_protected(&mut prepared, root(1)).unwrap();
    let aliases: Vec<_> = (0..8).map(|_| pin.clone()).collect();
    let watch = Watch::new(
        &admission,
        admission.used.load(Ordering::Acquire) - baseline,
        [
            Arc::as_ptr(pin.inner.0.as_ref().unwrap()) as usize,
            admission.last_box.load(Ordering::Acquire),
            0,
        ],
    );
    drop(pin);
    let barrier = std::sync::Barrier::new(aliases.len());
    std::thread::scope(|scope| {
        for pin in aliases {
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                drop(pin);
            });
        }
    });
    watch.assert_refunded();
    assert_eq!(admission.used.load(Ordering::Acquire), baseline);
}
