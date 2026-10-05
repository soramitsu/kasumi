//! Hooks are forwarded by the existing Engine test global allocator. No second
//! allocator, provider substitute, production hook or borrowed pointer escapes.
use super::*;
use std::{
    alloc::Layout,
    cell::Cell,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
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
pub(crate) fn before_deallocate(pointer: *mut u8, layout: Layout) -> u8 {
    u8::from(PAYLOAD.before(pointer, layout))
        | (u8::from(BODY.before(pointer, layout)) << 1)
        | (u8::from(POOL.before(pointer, layout)) << 2)
}
pub(crate) fn deallocated(bytes: usize, watches: u8) {
    note(-(bytes as i64), false);
    for (bit, watch) in [(1, &PAYLOAD), (2, &BODY), (4, &POOL)] {
        if watches & bit != 0 {
            watch.finished.store(true, Ordering::Release);
        }
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
static PAYLOAD: Watch = Watch::new();
static BODY: Watch = Watch::new();
static POOL: Watch = Watch::new();

fn inputs() -> Vec<Document> {
    let mut id = String::with_capacity(65536);
    id.push_str("spare");
    let mut text = String::with_capacity(65536);
    text.push_str("tiny");
    let mut array = Vec::with_capacity(65536);
    array.push(Value::String(text));
    let exact: Value =
        serde_json::from_str("12345678901234567890.123456789012345678901234567890").unwrap();
    let mut empty = serde_json::Map::new();
    empty.insert("removed".into(), Value::Null);
    empty.remove("removed");
    let mut broad = serde_json::Map::new();
    for index in (0..256).rev() {
        broad.insert(format!("field-{index}"), exact.clone());
    }
    vec![
        Document {
            id,
            version: 1,
            body: Value::Array(array),
        },
        Document {
            id: "empty".into(),
            version: 2,
            body: Value::Object(empty),
        },
        Document {
            id: "broad".into(),
            version: 3,
            body: Value::Object(broad),
        },
    ]
}

#[test]
fn document_pool_quotes_allocate_nothing_and_cover_control_and_compact_clones() {
    for source in inputs() {
        let node = tests::node(8 << 20);
        let baseline = node.snapshot();
        let measuring = Measurement::begin();
        let control = DocumentPool::control_bytes().unwrap();
        let quote = DocumentPool::document_bytes(&source.id, &source.body).unwrap();
        let walk = measuring.finish();
        assert_eq!(walk.allocations, 0);
        assert_eq!(walk.live, 0);
        let measuring = Measurement::begin();
        let pool = DocumentPool::new(&node).unwrap();
        let document = pool.clone_document(&source).unwrap();
        let prepared = COUNTS.with(Cell::get).unwrap();
        assert!(prepared.allocations > 0);
        assert!(prepared.peak as u64 <= control + quote);
        assert_eq!(
            node.snapshot().reserved_bytes,
            baseline.reserved_bytes + control + quote
        );
        drop(document);
        drop(pool);
        let drained = measuring.finish();
        assert_eq!(
            drained.live, 0,
            "pool, Arc owner and cloned payload must all retire"
        );
        assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    }
}

#[test]
fn document_pool_empty_control_quote_covers_actual_wait_and_final_retirement() {
    let control = DocumentPool::control_bytes().unwrap();
    let node = tests::node(control);
    let baseline = node.snapshot();
    let entered = Arc::new(AtomicBool::new(false));
    let released = Arc::new(AtomicBool::new(false));

    let measuring = Measurement::begin();
    let pool = DocumentPool::new(&node).unwrap();
    // Eagerly exercise this pool's Mutex initialization independently of any
    // document allocation. Platform backing belongs to this control quote.
    drop(pool.lock());
    let created = measuring.finish();
    assert!(created.allocations > 0);
    assert!(created.peak as u64 <= control);

    // Thread setup, handoff Arcs, and fixture coordination are outside the
    // measured windows. The worker measures only this pool's actual Condvar
    // wait/reacquisition, including lazy platform synchronization backing.
    let worker_pool = pool.clone();
    let worker_entered = entered.clone();
    let worker_released = released.clone();
    let worker = std::thread::spawn(move || {
        let measuring = Measurement::begin();
        let state = worker_pool.lock();
        worker_entered.store(true, Ordering::Release);
        let (state, waited) = worker_pool
            .inner()
            .available
            .wait_timeout_while(state, Duration::from_secs(5), |_| {
                !worker_released.load(Ordering::Acquire)
            })
            .unwrap_or_else(|p| p.into_inner());
        drop(state);
        let counts = measuring.finish();
        (counts, waited.timed_out())
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !entered.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline, "worker must enter pool wait");
        std::thread::yield_now();
    }
    let measuring = Measurement::begin();
    // Acquiring the same mutex after entered proves that the wait released it;
    // the flag+notify cannot skip the actual synchronization path.
    let state = pool.lock();
    released.store(true, Ordering::Release);
    pool.inner().available.notify_all();
    drop(state);
    let signaled = measuring.finish();
    let (waited, timed_out) = worker.join().unwrap();
    assert!(!timed_out, "pool waiter must receive its notification");
    assert!(created.peak + waited.peak + signaled.peak <= control as i64);
    assert_eq!(
        node.snapshot().reserved_bytes,
        baseline.reserved_bytes + control
    );
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations + 1
    );

    let measuring = Measurement::begin();
    drop(pool);
    let retired = measuring.finish();
    assert_eq!(
        created.live + waited.live + signaled.live + retired.live,
        0,
        "control Arc and all initialized Mutex/Condvar backing must retire"
    );
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[test]
fn document_pool_aliasing_is_allocation_free_and_denial_never_clones_large_source() {
    let source = Document {
        id: "source".into(),
        version: 1,
        body: Value::String("x".repeat(1 << 20)),
    };
    let control = DocumentPool::control_bytes().unwrap();
    let quote = DocumentPool::document_bytes(&source.id, &source.body).unwrap();
    let node = tests::node(control + quote);
    let pool = DocumentPool::new(&node).unwrap();
    let document = pool.clone_document(&source).unwrap();
    let before = node.snapshot();
    let measuring = Measurement::begin();
    let alias = document.clone();
    drop(alias);
    let cloned = measuring.finish();
    assert_eq!(cloned.allocations, 0);
    assert_eq!(cloned.live, 0);
    let measuring = Measurement::begin();
    let error = pool.clone_document(&source).unwrap_err();
    drop(error);
    let denial = measuring.finish();
    // Real provider denial allocates its bounded Error message. It must never
    // copy the one-MiB body or allocate the source payload/control Arc.
    assert!(denial.peak < 4096);
    assert_eq!(denial.live, 0);
    assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, before.live_reservations);
}

#[test]
fn document_pool_concurrent_last_drop_frees_payload_and_pool_arcs_before_refund() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let body = Value::String("watched body".repeat(1024));
    let control = DocumentPool::control_bytes().unwrap();
    let quote = DocumentPool::document_bytes("watched", &body).unwrap();
    let node = tests::node(control + quote);
    let baseline = node.snapshot();
    let pool = DocumentPool::new(&node).unwrap();
    let document = pool.clone_parts("watched", 1, &body).unwrap();
    let payload_address = std::ptr::from_ref(document.payload()) as usize;
    let pool_address = std::ptr::from_ref(pool.inner()) as usize;
    let Value::String(text) = &document.body else {
        unreachable!()
    };
    let body_address = text.as_ptr() as usize;
    let rendezvous = Arc::new(std::sync::Barrier::new(9));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let document = document.clone();
            let rendezvous = rendezvous.clone();
            std::thread::spawn(move || {
                rendezvous.wait();
                drop(document);
            })
        })
        .collect();
    let payload_release = PAYLOAD.arm(payload_address);
    let body_release = BODY.arm(body_address);
    let pool_release = POOL.arm(pool_address);
    drop(document);
    drop(pool);
    rendezvous.wait();
    PAYLOAD.wait();
    assert!(!PAYLOAD.finished.load(Ordering::Acquire));
    assert_eq!(
        node.snapshot().reserved_bytes,
        baseline.reserved_bytes + control + quote
    );
    assert!(
        node.reserve(tests::WORK_HEADROOM + 1, None).is_err(),
        "source Arc backing has not retired"
    );
    payload_release.release();
    BODY.wait();
    assert!(PAYLOAD.finished.load(Ordering::Acquire));
    assert!(!BODY.finished.load(Ordering::Acquire));
    assert_eq!(
        node.snapshot().reserved_bytes,
        baseline.reserved_bytes + control + quote
    );
    assert!(
        node.reserve(tests::WORK_HEADROOM + 1, None).is_err(),
        "body allocation has not retired"
    );
    body_release.release();
    POOL.wait();
    assert!(BODY.finished.load(Ordering::Acquire));
    assert!(!POOL.finished.load(Ordering::Acquire));
    assert_eq!(
        node.snapshot().reserved_bytes,
        baseline.reserved_bytes + control
    );
    assert!(
        node.reserve(quote + tests::WORK_HEADROOM + 1, None)
            .is_err(),
        "pool Arc backing has not retired"
    );
    pool_release.release();
    for worker in workers {
        worker.join().unwrap();
    }
    for watch in [&PAYLOAD, &BODY, &POOL] {
        assert!(watch.finished.load(Ordering::Acquire));
        assert_eq!(watch.count.load(Ordering::Acquire), 1);
    }
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}

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
