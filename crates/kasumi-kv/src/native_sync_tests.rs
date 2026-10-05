//! Fixed observations of actual std synchronization allocations and refunds.
use std::alloc::Layout;
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const CAPACITY: usize = 32;
static EXCLUSIVE: Mutex<()> = Mutex::new(());
static COUNT: AtomicUsize = AtomicUsize::new(0);
static FUNDING: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static ADDRESS: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static BYTES: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static ALIGN: [AtomicUsize; CAPACITY] = [const { AtomicUsize::new(0) }; CAPACITY];
static FREED: [AtomicBool; CAPACITY] = [const { AtomicBool::new(false) }; CAPACITY];
thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(false) };
    static CURRENT: Cell<usize> = const { Cell::new(0) };
}

pub(crate) struct Watch(std::sync::MutexGuard<'static, ()>);
impl Watch {
    pub(crate) fn new() -> Self {
        let guard = EXCLUSIVE.lock().unwrap();
        COUNT.store(0, Ordering::Release);
        for i in 0..CAPACITY {
            FUNDING[i].store(0, Ordering::Release);
            ADDRESS[i].store(0, Ordering::Release);
            FREED[i].store(false, Ordering::Release);
        }
        ENABLED.with(|enabled| assert!(!enabled.replace(true)));
        Self(guard)
    }
    pub(crate) fn count(&self) -> usize {
        COUNT.load(Ordering::Acquire)
    }
    pub(crate) fn record(&self, index: usize) -> (usize, usize, usize, usize, bool) {
        assert!(index < self.count());
        (
            FUNDING[index].load(Ordering::Acquire),
            ADDRESS[index].load(Ordering::Acquire),
            BYTES[index].load(Ordering::Acquire),
            ALIGN[index].load(Ordering::Acquire),
            FREED[index].load(Ordering::Acquire),
        )
    }
    pub(crate) fn assert_all_retired(&self) {
        for (i, freed) in FREED.iter().enumerate().take(self.count()) {
            assert!(
                freed.load(Ordering::Acquire),
                "actual std synchronization control {i} is still live"
            );
        }
    }
}
impl Drop for Watch {
    fn drop(&mut self) {
        ENABLED.with(|enabled| enabled.set(false));
        CURRENT.with(|current| current.set(0));
        let _ = &self.0;
    }
}

pub(super) struct Construction;
impl Construction {
    pub(super) fn new(original: usize) -> Self {
        ENABLED.with(|enabled| {
            if enabled.get() {
                CURRENT.with(|current| assert_eq!(current.replace(original), 0));
            }
        });
        Self
    }
}
impl Drop for Construction {
    fn drop(&mut self) {
        let _ = CURRENT.try_with(|current| current.set(0));
    }
}

pub(crate) fn note_allocation(pointer: *mut u8, layout: Layout) {
    let _ = CURRENT.try_with(|current| {
        let original = current.get();
        if original == 0 {
            return;
        }
        let index = COUNT.fetch_add(1, Ordering::AcqRel);
        assert!(index < CAPACITY, "bounded real synchronization observation");
        FUNDING[index].store(original, Ordering::Release);
        ADDRESS[index].store(pointer as usize, Ordering::Release);
        BYTES[index].store(layout.size(), Ordering::Release);
        ALIGN[index].store(layout.align(), Ordering::Release);
    });
}
pub(crate) fn note_deallocation(pointer: *mut u8, layout: Layout) {
    for i in 0..COUNT.load(Ordering::Acquire).min(CAPACITY) {
        if ADDRESS[i].load(Ordering::Acquire) == pointer as usize
            && BYTES[i].load(Ordering::Acquire) == layout.size()
            && ALIGN[i].load(Ordering::Acquire) == layout.align()
        {
            FREED[i].store(true, Ordering::Release);
        }
    }
}
pub(crate) fn assert_retired_for(original: usize) {
    for i in 0..COUNT.load(Ordering::Acquire).min(CAPACITY) {
        if FUNDING[i].load(Ordering::Acquire) == original {
            assert!(
                FREED[i].load(Ordering::Acquire),
                "actual std synchronization allocation survives original grant refund"
            );
        }
    }
}
