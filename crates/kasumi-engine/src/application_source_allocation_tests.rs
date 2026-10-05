//! Real source allocations, observed by the crate's one global allocator.
//! These tests prove allocation retirement ordering, not failure-shell closure.
use super::*;
use std::{alloc::Layout, sync::atomic::AtomicU64, time::Duration};

struct Watch {
    address: AtomicUsize,
    blocked: AtomicBool,
    entered: AtomicBool,
    released: AtomicBool,
    finished: AtomicBool,
    count: AtomicUsize,
}
impl Watch {
    const fn new() -> Self {
        Self {
            address: AtomicUsize::new(0),
            blocked: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            released: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            count: AtomicUsize::new(0),
        }
    }
    fn arm(&self, address: usize, blocked: bool) {
        assert_ne!(address, 0);
        assert_eq!(self.address.load(Ordering::Acquire), 0);
        self.blocked.store(blocked, Ordering::Relaxed);
        self.entered.store(false, Ordering::Relaxed);
        self.released.store(false, Ordering::Relaxed);
        self.finished.store(false, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
        self.address.store(address, Ordering::Release);
    }
    fn before(&self, pointer: *mut u8, layout: Layout) -> bool {
        let address = self.address.load(Ordering::Acquire);
        // The witness is an interior payload address, not a guessed Arc header.
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
        while self.blocked.load(Ordering::Acquire) && !self.released.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        true
    }
    async fn wait(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !self.entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("actual source allocation never reached dealloc");
        assert!(!self.finished.load(Ordering::Acquire));
    }
}
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static WATCHES: [Watch; 2] = [const { Watch::new() }; 2];
// This counter gives the observer's post-System.dealloc events an explicit order.
static ORDER: AtomicU64 = AtomicU64::new(0);
static DATA_ORDER: AtomicU64 = AtomicU64::new(0);
static CREDIT_ORDER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn before_deallocate(pointer: *mut u8, layout: Layout) -> u8 {
    let mut matched = 0;
    for (index, watch) in WATCHES.iter().enumerate() {
        if watch.before(pointer, layout) {
            matched |= 1 << index;
        }
    }
    matched
}
pub(crate) fn after_deallocate(matched: u8) {
    for (index, watch) in WATCHES.iter().enumerate() {
        if matched & (1 << index) != 0 {
            let order = ORDER.fetch_add(1, Ordering::AcqRel) + 1;
            if index == 0 {
                DATA_ORDER.store(order, Ordering::Release);
            } else {
                CREDIT_ORDER.store(order, Ordering::Release);
            }
            watch.finished.store(true, Ordering::Release);
        }
    }
}

// Every failure path, including a test assertion or timeout, releases the
// allocator gate and joins all workers before another test can arm a witness.
struct Retiring {
    threads: Vec<std::thread::JoinHandle<()>>,
}
impl Retiring {
    fn one<T: Send + 'static>(owner: T) -> Self {
        Self {
            threads: vec![std::thread::spawn(move || drop(owner))],
        }
    }
    fn concurrent(cell: CellRef) -> Self {
        let rendezvous = Arc::new(std::sync::Barrier::new(9));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let strong = cell.clone();
            let weak = cell.downgrade();
            let rendezvous = rendezvous.clone();
            threads.push(std::thread::spawn(move || {
                rendezvous.wait();
                drop(strong);
                drop(weak);
            }));
        }
        drop(cell);
        rendezvous.wait();
        Self { threads }
    }
    fn failures(errors: Vec<anyhow::Error>) -> Self {
        let rendezvous = Arc::new(std::sync::Barrier::new(errors.len() + 1));
        let threads = errors
            .into_iter()
            .map(|error| {
                let rendezvous = rendezvous.clone();
                std::thread::spawn(move || {
                    rendezvous.wait();
                    drop(error);
                })
            })
            .collect();
        rendezvous.wait();
        Self { threads }
    }
    fn finish(mut self) {
        self.release();
        let mut panicked = false;
        while let Some(thread) = self.threads.pop() {
            panicked |= thread.join().is_err();
        }
        assert!(!panicked, "source drop panicked");
    }
    fn release(&self) {
        for watch in &WATCHES {
            watch.released.store(true, Ordering::Release);
        }
    }
}
impl Drop for Retiring {
    fn drop(&mut self) {
        self.release();
        while let Some(thread) = self.threads.pop() {
            let _ = thread.join();
        }
        for watch in &WATCHES {
            watch.address.store(0, Ordering::Release);
        }
    }
}
fn fill(fixture: &Fixture) -> Result<Reservation> {
    let admission = &fixture.storage.admission;
    Ok(admission.reserve_resident(fixture.budget - admission.snapshot().reserved_bytes)?)
}
fn arm(data: usize, credit: usize, block_credit: bool) {
    ORDER.store(0, Ordering::Release);
    DATA_ORDER.store(0, Ordering::Release);
    CREDIT_ORDER.store(0, Ordering::Release);
    WATCHES[0].arm(data, !block_credit);
    WATCHES[1].arm(credit, block_credit);
}
async fn assert_held(fixture: &Fixture, grant: u64, slots: usize, block_credit: bool) {
    WATCHES[usize::from(block_credit)].wait().await;
    let admission = &fixture.storage.admission;
    assert_eq!(admission.snapshot().reserved_bytes, fixture.budget);
    assert_eq!(admission.snapshot().live_reservations, slots);
    assert!(
        admission.reserve_resident(grant).is_err(),
        "source credit was reused before actual deallocation"
    );
}
fn assert_retired(fixture: &Fixture, grant: u64, slots: usize) -> Result<()> {
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        fixture.budget - grant
    );
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        slots - 1
    );
    for watch in &WATCHES {
        assert_eq!(watch.count.load(Ordering::Acquire), 1);
        assert!(watch.finished.load(Ordering::Acquire));
    }
    assert!(DATA_ORDER.load(Ordering::Acquire) < CREDIT_ORDER.load(Ordering::Acquire));
    drop(fixture.storage.admission.reserve_resident(grant)?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_root_and_credit_arcs_remain_funded_through_actual_deallocation()
-> crate::test_fixture_failure::FixtureResult<()> {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::new().await?;
    for block_credit in [false, true] {
        let before = fixture.storage.admission.snapshot().reserved_bytes;
        let (roots, binding) = SourceRoots::new(
            fixture.stores.clone(),
            fixture.storage.admission.clone(),
            RaftLimits::default(),
        )?;
        drop(binding);
        let grant = fixture.storage.admission.snapshot().reserved_bytes - before;
        let data = std::ptr::from_ref(roots.as_ref()) as usize;
        let credit = roots._reservation.allocation_address();
        let filler = fill(&fixture)?;
        let slots = fixture.storage.admission.snapshot().live_reservations;
        arm(data, credit, block_credit);
        let retiring = Retiring::one(roots);
        assert_held(&fixture, grant, slots, block_credit).await;
        retiring.finish();
        assert_retired(&fixture, grant, slots)?;
        drop(filler);
    }
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_root_weak_retains_shell_credit_after_payload_is_gone()
-> crate::test_fixture_failure::FixtureResult<()> {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::new().await?;
    let before = fixture.storage.admission.snapshot().reserved_bytes;
    let (roots, binding) = SourceRoots::new(
        fixture.stores.clone(),
        fixture.storage.admission.clone(),
        RaftLimits::default(),
    )?;
    let weak = roots.downgrade();
    let data = std::ptr::from_ref(roots.as_ref()) as usize;
    let credit = roots._reservation.allocation_address();
    drop(binding);
    drop(roots);
    assert!(weak.upgrade().is_none());
    let grant = fixture.storage.admission.snapshot().reserved_bytes - before;
    assert!(grant > 0);
    let filler = fill(&fixture)?;
    let slots = fixture.storage.admission.snapshot().live_reservations;
    arm(data, credit, false);
    let retiring = Retiring::one(weak);
    assert_held(&fixture, grant, slots, false).await;
    retiring.finish();
    assert_retired(&fixture, grant, slots)?;
    drop(filler);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_cell_concurrent_strong_and_weak_drops_hold_the_actual_credit_tail()
-> crate::test_fixture_failure::FixtureResult<()> {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::new().await?;
    for block_credit in [false, true] {
        let before = fixture.storage.admission.snapshot().reserved_bytes;
        let preparation = fixture.roots.prepare_kind(false)?;
        let cell = preparation.cell.clone();
        drop(preparation);
        assert!(cell.state.lock().unwrap().closed);
        assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
        assert_eq!(
            fixture.storage.admission.snapshot().reserved_bytes - before,
            cell_bytes()?
        );
        let data = std::ptr::from_ref(cell.as_ref()) as usize;
        let credit = cell._reservation.allocation_address();
        let filler = fill(&fixture)?;
        let slots = fixture.storage.admission.snapshot().live_reservations;
        arm(data, credit, block_credit);
        let retiring = Retiring::concurrent(cell);
        assert_held(&fixture, cell_bytes()?, slots, block_credit).await;
        retiring.finish();
        assert_retired(&fixture, cell_bytes()?, slots)?;
        drop(filler);
    }
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_binding_box_retires_before_its_real_root_credit()
-> crate::test_fixture_failure::FixtureResult<()> {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::new().await?;
    let buffers = fixture.storage.admission.snapshot_buffer_owner()?;
    let before = fixture.storage.admission.snapshot().reserved_bytes;
    let (roots, binding) = SourceRoots::new(
        fixture.stores.clone(),
        fixture.storage.admission.clone(),
        RaftLimits::default(),
    )?;
    let grant = fixture.storage.admission.snapshot().reserved_bytes - before;
    let data = binding.allocation_address();
    let credit = roots._reservation.allocation_address();
    buffers.bind_application_sources(binding)?;
    drop(roots);
    buffers.drain_startup().await?;
    let filler = fill(&fixture)?;
    let slots = fixture.storage.admission.snapshot().live_reservations;
    arm(data, credit, false);
    let retiring = Retiring::one(buffers);
    assert_held(&fixture, grant, slots, false).await;
    retiring.finish();
    for watch in &WATCHES {
        assert_eq!(watch.count.load(Ordering::Acquire), 1);
        assert!(watch.finished.load(Ordering::Acquire));
    }
    assert!(DATA_ORDER.load(Ordering::Acquire) < CREDIT_ORDER.load(Ordering::Acquire));
    // The containing buffer owner's independent grant also retires after hook.
    assert!(fixture.storage.admission.snapshot().reserved_bytes <= fixture.budget - grant);
    drop(fixture.storage.admission.reserve_resident(grant)?);
    drop(filler);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_view_unique_close_holds_cell_credit_while_arc_backing_retires()
-> crate::test_fixture_failure::FixtureResult<()> {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::new().await?;
    let preparation = fixture.roots.prepare_kind(false)?;
    let view = ViewRef::new(
        fixture.stores.read_view()?,
        preparation.cell._reservation.clone(),
    );
    let data = std::ptr::from_ref(view.as_ref()) as usize;
    let credit = preparation.cell._reservation.allocation_address();
    preparation.cell.state.lock().unwrap().view = Some(view);
    let filler = fill(&fixture)?;
    let slots = fixture.storage.admission.snapshot().live_reservations;
    arm(data, credit, false);
    let retiring = Retiring::one(preparation);
    assert_held(&fixture, cell_bytes()?, slots, false).await;
    retiring.finish();
    assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
    for watch in &WATCHES {
        assert_eq!(watch.count.load(Ordering::Acquire), 1);
        assert!(watch.finished.load(Ordering::Acquire));
    }
    assert!(DATA_ORDER.load(Ordering::Acquire) < CREDIT_ORDER.load(Ordering::Acquire));
    // Native close may release additional actual reader grants after the pause.
    assert!(fixture.storage.admission.snapshot().reserved_bytes <= fixture.budget - cell_bytes()?);
    drop(fixture.storage.admission.reserve_resident(cell_bytes()?)?);
    drop(filler);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_view_weak_retains_credit_after_unique_native_close()
-> crate::test_fixture_failure::FixtureResult<()> {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::new().await?;
    let preparation = fixture.roots.prepare_kind(false)?;
    let view = ViewRef::new(
        fixture.stores.read_view()?,
        preparation.cell._reservation.clone(),
    );
    let data = std::ptr::from_ref(view.as_ref()) as usize;
    let credit = preparation.cell._reservation.allocation_address();
    let weak = view.downgrade();
    preparation.cell.state.lock().unwrap().view = Some(view);
    drop(preparation);
    assert!(weak.upgrade().is_none());
    assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
    let filler = fill(&fixture)?;
    let slots = fixture.storage.admission.snapshot().live_reservations;
    arm(data, credit, false);
    let retiring = Retiring::one(weak);
    assert_held(&fixture, cell_bytes()?, slots, false).await;
    retiring.finish();
    assert_retired(&fixture, cell_bytes()?, slots)?;
    drop(filler);
    fixture.close().await
}

#[derive(Debug)]
struct TailOriginal(u64);
impl std::fmt::Display for TailOriginal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original source failure {}", self.0)
    }
}
impl std::error::Error for TailOriginal {}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_failure_actual_error_aliases_hold_credit_through_owner_deallocation()
-> crate::test_fixture_failure::FixtureResult<()> {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::new().await?;
    for block_credit in [false, true] {
        let preparation = fixture.roots.prepare_kind(false)?;
        preparation
            .cell
            .record_failure(TailOriginal(71).into(), false);
        let record = preparation.cell.failure.get().unwrap();
        let data = std::ptr::from_ref(record.owner.as_ref()) as usize;
        let credit = preparation.cell._reservation.allocation_address();
        let original = std::ptr::from_ref(
            record
                .owner
                .original
                .downcast_ref::<TailOriginal>()
                .unwrap(),
        ) as usize;
        // Actual returned SourceFailure anyhow aliases retain the same owner
        // and original error; no synthetic credit/payload destructor substitutes
        // for the real final FailureOwner Arc and SourceCredit Arc observations.
        let errors: Vec<_> = (0..8).map(|_| preparation.cell.error()).collect();
        for error in &errors {
            assert!(FailureRef::ptr_eq(
                &error.downcast_ref::<SourceFailure>().unwrap().owner,
                &record.owner
            ));
            let observed = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<TailOriginal>())
                .unwrap();
            assert_eq!(observed.0, 71);
            assert_eq!(std::ptr::from_ref(observed) as usize, original);
        }
        drop(preparation);
        assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
        let filler = fill(&fixture)?;
        let slots = fixture.storage.admission.snapshot().live_reservations;
        arm(data, credit, block_credit);
        let retiring = Retiring::failures(errors);
        assert_held(&fixture, cell_bytes()?, slots, block_credit).await;
        retiring.finish();
        assert_retired(&fixture, cell_bytes()?, slots)?;
        drop(filler);
    }
    fixture.close().await
}

#[path = "application_source_completion_allocation_tests.rs"]
mod completion_allocations;
