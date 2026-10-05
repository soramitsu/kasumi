//! Actual requested heap for the aggregate cache stays admitted through growth,
//! rehash overlap, and cross-thread final retirement. Only cache work is tracked:
//! fixture owners and thread/handoff scaffolding predate the measuring windows.
//! No slack is added to the measured heap bound. Allocator and refund callbacks
//! only update fixed atomics; assertions run after tracking has stopped.

use kasumi_kv::{
    AdmissionError, CacheConfig, CacheMemoryLease, CacheMemoryQuote, CacheMemoryReservation,
    CachedBytes, NativeCache, OwnerFailed, ResidentLease, StorageAdmission,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const ROWS: u64 = 16_513;
const VALUE_BYTES: usize = 32;
const CACHE_BYTES: u64 = 16 << 20;
const PROVIDER_BYTES: i64 = 32 << 20;

struct Counting;

#[global_allocator]
static ALLOCATOR: Counting = Counting;

thread_local! {
    static TRACKED: Cell<bool> = const { Cell::new(false) };
}
static HEAP: AtomicI64 = AtomicI64::new(0);
static ADMITTED: AtomicI64 = AtomicI64::new(0);
static PEAK_HEAP: AtomicI64 = AtomicI64::new(0);
static PEAK_EXCESS: AtomicI64 = AtomicI64::new(0);
static NEGATIVE_HEAP: AtomicBool = AtomicBool::new(false);
static BAD_REFUND: AtomicBool = AtomicBool::new(false);
static ZERO_WITH_HEAP: AtomicBool = AtomicBool::new(false);
static ZERO_REFUNDS: AtomicUsize = AtomicUsize::new(0);

fn sample() {
    let heap = HEAP.load(Ordering::Acquire);
    PEAK_HEAP.fetch_max(heap, Ordering::AcqRel);
    PEAK_EXCESS.fetch_max(heap - ADMITTED.load(Ordering::Acquire), Ordering::AcqRel);
    if heap < 0 {
        NEGATIVE_HEAP.store(true, Ordering::Release);
    }
}

fn note(delta: i64) {
    if TRACKED.try_with(Cell::get).unwrap_or(false) {
        HEAP.fetch_add(delta, Ordering::AcqRel);
        sample();
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            note(layout.size() as i64);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            note(layout.size() as i64);
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, size) };
        if !moved.is_null() {
            note(size as i64 - layout.size() as i64);
        }
        moved
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        note(-(layout.size() as i64));
    }
}

struct Tracking;

impl Tracking {
    fn enter() -> Self {
        TRACKED.with(|tracked| tracked.set(true));
        Self
    }
}

impl Drop for Tracking {
    fn drop(&mut self) {
        TRACKED.with(|tracked| tracked.set(false));
    }
}

#[derive(Default)]
struct Admission {
    slots: AtomicUsize,
    peak_slots: AtomicUsize,
    reservations: AtomicUsize,
    growths: AtomicUsize,
    checks: AtomicUsize,
    workspace_calls: AtomicUsize,
    failed: AtomicBool,
}

struct Token {
    owner: Arc<Admission>,
    charge: i64,
}

fn admit(bytes: i64) -> Result<(), AdmissionError> {
    ADMITTED
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current
                .checked_add(bytes)
                .filter(|&next| next <= PROVIDER_BYTES)
        })
        .map_err(|_| AdmissionError::CapacityDenied)?;
    sample();
    Ok(())
}

fn refund(bytes: i64) {
    let before = ADMITTED.fetch_sub(bytes, Ordering::AcqRel);
    if bytes < 0 || before < bytes {
        BAD_REFUND.store(true, Ordering::Release);
    }
    sample();
    if before == bytes {
        ZERO_REFUNDS.fetch_add(1, Ordering::AcqRel);
        if HEAP.load(Ordering::Acquire) != 0 {
            ZERO_WITH_HEAP.store(true, Ordering::Release);
        }
    }
}

impl CacheMemoryReservation for Token {
    fn try_grow(&mut self, bytes: u64) -> Result<(), AdmissionError> {
        let bytes = i64::try_from(bytes).map_err(|_| AdmissionError::CapacityDenied)?;
        let next = self
            .charge
            .checked_add(bytes)
            .ok_or(AdmissionError::CapacityDenied)?;
        admit(bytes)?;
        self.charge = next;
        self.owner.growths.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn retain_charge(&mut self, bytes: u64) {
        let next = bytes as i64;
        let released = self.charge - next;
        self.charge = next;
        refund(released);
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        self.owner.slots.fetch_sub(1, Ordering::AcqRel);
        // The opaque lease must have deallocated this token's Box before this
        // callback. The fixture's Arc owner is retained outside both windows.
        refund(self.charge);
    }
}

impl StorageAdmission for Admission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.checks.fetch_add(1, Ordering::AcqRel);
        if self.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }

    fn reserve_workspace(&self, _: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        self.workspace_calls.fetch_add(1, Ordering::AcqRel);
        Err(AdmissionError::CapacityDenied)
    }

    fn quote_cache_memory(&self, credit: u64) -> Result<CacheMemoryQuote, AdmissionError> {
        // This allocator measures requested Layout bytes. The concrete Box is
        // the provider's only new allocation; there is no fixture allowance.
        CacheMemoryQuote::new(credit, size_of::<Token>() as u64)
            .ok_or(AdmissionError::CapacityDenied)
    }

    fn reserve_cache_memory(
        self: Arc<Self>,
        credit: u64,
    ) -> Result<CacheMemoryLease, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let quote = self.quote_cache_memory(credit)?;
        let charge =
            i64::try_from(quote.charged_bytes()).map_err(|_| AdmissionError::CapacityDenied)?;
        let slots = self
            .slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |slots| {
                (slots < 2).then_some(slots + 1)
            })
            .map_err(|_| AdmissionError::CapacityDenied)?
            + 1;
        if let Err(error) = admit(charge) {
            self.slots.fetch_sub(1, Ordering::AcqRel);
            return Err(error);
        }
        self.peak_slots.fetch_max(slots, Ordering::AcqRel);
        self.reservations.fetch_add(1, Ordering::AcqRel);
        Ok(CacheMemoryLease::new(
            quote,
            Token {
                owner: self,
                charge,
            },
        ))
    }

    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }
}

#[derive(Default)]
struct Handoff {
    value: Mutex<Option<CachedBytes>>,
    ready: AtomicBool,
    release: AtomicBool,
    had_guard: AtomicBool,
    remaining_heap: AtomicI64,
    remaining_admission: AtomicI64,
}

#[test]
fn aggregate_cache_heap_stays_admitted_until_cross_thread_final_guard_retirement() {
    let admission = Arc::new(Admission::default());
    let handoff = Arc::new(Handoff::default());
    // Initialize synchronization and thread scaffolding before tracking starts.
    drop(handoff.value.lock().unwrap());
    let child_handoff = handoff.clone();
    let child = std::thread::spawn(move || {
        TRACKED.with(|tracked| tracked.set(false));
        child_handoff.ready.store(true, Ordering::Release);
        while !child_handoff.release.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        let value = child_handoff.value.lock().unwrap().take();
        child_handoff
            .had_guard
            .store(value.is_some(), Ordering::Release);
        {
            let _tracking = Tracking::enter();
            drop(value);
        }
        child_handoff
            .remaining_heap
            .store(HEAP.load(Ordering::Acquire), Ordering::Release);
        child_handoff
            .remaining_admission
            .store(ADMITTED.load(Ordering::Acquire), Ordering::Release);
    });
    while !handoff.ready.load(Ordering::Acquire) {
        std::thread::yield_now();
    }

    let mut failures = 0_u64;
    let tracking = Tracking::enter();
    let mut cache = NativeCache::new(
        CacheConfig {
            byte_limit: CACHE_BYTES,
        },
        admission.clone(),
    );
    let mut held = None;
    for key in 0..ROWS {
        match cache.load(key, VALUE_BYTES, |bytes| {
            bytes.fill(key as u8);
            Ok::<_, ()>(())
        }) {
            Ok(value) => {
                if value.as_bytes() != [key as u8; VALUE_BYTES] {
                    failures |= 1;
                }
                if key == 0 {
                    held = Some(value.clone());
                }
            }
            Err(_) => {
                failures |= 2;
                break;
            }
        }
        if admission.slots.load(Ordering::Acquire) != 1 {
            failures |= 4;
        }
    }
    let hot = cache.stats();
    if hot.entries != ROWS as usize || hot.evictions != 0 || hot.uncached_loads != 0 {
        failures |= 8;
    }
    if hot.resident_bytes != ADMITTED.load(Ordering::Acquire) as u64 {
        failures |= 16;
    }
    for key in 0..ROWS {
        match cache.load(key, VALUE_BYTES, |_| Err::<(), _>(())) {
            Ok(value) if value.as_bytes() == [key as u8; VALUE_BYTES] => {}
            _ => failures |= 32,
        }
    }
    let another = held.clone();
    admission.failed.store(true, Ordering::Release);
    let checks_before_cleanup = admission.checks.load(Ordering::Acquire);
    cache.clear();
    let cleared = cache.stats();
    if cleared.entries != 0 || cleared.pinned_bytes == 0 || cleared.cached_bytes != 0 {
        failures |= 64;
    }
    drop(cache);
    drop(held);
    let retained_heap = HEAP.load(Ordering::Acquire);
    let retained_charge = ADMITTED.load(Ordering::Acquire);
    match handoff.value.lock() {
        Ok(mut slot) => *slot = another,
        Err(_) => failures |= 128,
    }
    drop(tracking);
    handoff.release.store(true, Ordering::Release);
    child.join().unwrap();

    assert_eq!(
        failures, 0,
        "tracked cache operations failed: {failures:#x}"
    );
    assert_eq!(
        admission.workspace_calls.load(Ordering::Acquire),
        0,
        "uncached fallback hid a retention failure"
    );
    assert_eq!(
        admission.peak_slots.load(Ordering::Acquire),
        2,
        "rehash overlap was not exercised"
    );
    assert!(
        admission.reservations.load(Ordering::Acquire) > 8,
        "directory growth was not exercised"
    );
    assert!(
        admission.growths.load(Ordering::Acquire) > 1,
        "aggregate growth was not exercised"
    );
    assert!(PEAK_HEAP.load(Ordering::Acquire) > ROWS as i64 * VALUE_BYTES as i64);
    assert_eq!(
        PEAK_EXCESS.load(Ordering::Acquire),
        0,
        "a cache allocation or refund preceded admission custody"
    );
    assert!(!NEGATIVE_HEAP.load(Ordering::Acquire));
    assert!(!BAD_REFUND.load(Ordering::Acquire));
    assert!(
        !ZERO_WITH_HEAP.load(Ordering::Acquire),
        "the last provider refund preceded allocation retirement"
    );
    assert_eq!(ZERO_REFUNDS.load(Ordering::Acquire), 1);
    assert!(retained_heap >= VALUE_BYTES as i64);
    assert!(retained_charge >= retained_heap);
    assert!(handoff.had_guard.load(Ordering::Acquire));
    assert_eq!(handoff.remaining_heap.load(Ordering::Acquire), 0);
    assert_eq!(handoff.remaining_admission.load(Ordering::Acquire), 0);
    assert_eq!(admission.slots.load(Ordering::Acquire), 0);
    assert_eq!(
        admission.checks.load(Ordering::Acquire),
        checks_before_cleanup,
        "cleanup reentered the expired owner"
    );
}
