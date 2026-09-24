use super::*;
use crate::admission::{AdmissionConfig, MemorySource};
use std::{
    sync::{
        Condvar,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

struct ZeroRss;
impl MemorySource for ZeroRss {
    fn resident_bytes(&self) -> anyhow::Result<u64> {
        Ok(0)
    }
}
fn admission(capacity: usize) -> Arc<NodeAdmission> {
    NodeAdmission::from_memory(
        MemoryCore::create(
            AdmissionConfig {
                max_inflight_operations: capacity,
                ..Default::default()
            },
            1 << 30,
            Arc::new(ZeroRss),
            Arc::new(kasumi_clock::SystemLeaseClock),
        )
        .unwrap(),
    )
    .unwrap()
}
#[derive(Debug)]
struct OriginalFailure(u64);
impl std::fmt::Display for OriginalFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original failure {}", self.0)
    }
}
impl StdError for OriginalFailure {}
#[derive(Default)]
struct Gate {
    started: AtomicBool,
    released: Mutex<bool>,
    wake: Condvar,
    cleanup_ready: AtomicBool,
    cleanup_calls: AtomicUsize,
    cleanup_wake_pending: AtomicBool,
    discard_wake_pending: AtomicBool,
    output_drops: AtomicUsize,
    allocations: AtomicUsize,
    operation_drops: AtomicUsize,
}
impl Gate {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_one();
    }
    async fn started(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !self.started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
#[derive(Clone, Copy)]
enum Outcome {
    Success,
    Failure,
    Panic,
}
struct Plan {
    core: Arc<MemoryCore>,
    gate: Arc<Gate>,
    outcome: Outcome,
}
struct Operation {
    core: Arc<MemoryCore>,
    gate: Arc<Gate>,
    outcome: Outcome,
    _cancel: QueryCancellation,
    cleanup_failure: Option<OriginalFailure>,
}
impl Drop for Operation {
    fn drop(&mut self) {
        self.gate.operation_drops.fetch_add(1, Ordering::AcqRel);
    }
}
struct Output {
    gate: Arc<Gate>,
    _charge: Reservation,
}
impl Drop for Output {
    fn drop(&mut self) {
        self.gate.output_drops.fetch_add(1, Ordering::AcqRel);
    }
}
impl SnapshotOperation for Operation {
    type Plan = Plan;
    type Output = Output;
    type Failure = OriginalFailure;
    fn validate_memory(plan: &Plan, core: &Arc<MemoryCore>) -> anyhow::Result<()> {
        anyhow::ensure!(
            Arc::ptr_eq(&plan.core, core),
            "foreign fixture memory owner"
        );
        Ok(())
    }
    fn backing_bytes(_: &Plan) -> anyhow::Result<u64> {
        // The owner includes the named Tokio task estimate. The actual fixture
        // operation/error/output are fixed inline; their one shared Gate is the
        // only backing allocation. This is custody, not allocator qualification.
        arc_bytes::<Gate>()
    }
    fn allocate(plan: Plan, cancellation: QueryCancellation) -> Self {
        plan.gate.allocations.fetch_add(1, Ordering::AcqRel);
        Self {
            core: plan.core,
            gate: plan.gate,
            outcome: plan.outcome,
            _cancel: cancellation,
            cleanup_failure: None,
        }
    }
    fn run(&mut self) -> std::result::Result<Output, OriginalFailure> {
        self.gate.started.store(true, Ordering::Release);
        let released = self.gate.released.lock().unwrap();
        drop(
            self.gate
                .wake
                .wait_while(released, |released| !*released)
                .unwrap(),
        );
        match self.outcome {
            Outcome::Success => {
                let charge = self
                    .core
                    .reserve_resident(arc_bytes::<Gate>().unwrap())
                    .map_err(|_| OriginalFailure(812))?;
                Ok(Output {
                    gate: self.gate.clone(),
                    _charge: charge,
                })
            }
            Outcome::Failure => Err(OriginalFailure(731)),
            Outcome::Panic => std::panic::panic_any(OriginalFailure(937)),
        }
    }
    fn poll_cleanup(&mut self, cx: &mut Context<'_>) -> Poll<DrainCompletion> {
        self.gate.cleanup_calls.fetch_add(1, Ordering::AcqRel);
        if self.gate.cleanup_wake_pending.swap(false, Ordering::AcqRel) {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.gate.cleanup_ready.load(Ordering::Acquire) {
            Poll::Ready(DrainCompletion::Complete)
        } else {
            self.cleanup_failure.get_or_insert(OriginalFailure(991));
            Poll::Ready(DrainCompletion::Retained)
        }
    }
    fn poll_discard(output: &mut Output, cx: &mut Context<'_>) -> Poll<DrainCompletion> {
        if output
            .gate
            .discard_wake_pending
            .swap(false, Ordering::AcqRel)
        {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(DrainCompletion::Complete)
    }
    fn visit_diagnostics(&self, visit: &mut dyn FnMut(&(dyn StdError + 'static))) {
        if let Some(error) = &self.cleanup_failure {
            visit(error);
        }
    }
    fn visit_output_diagnostics(_: &Output, _: &mut dyn FnMut(&(dyn StdError + 'static))) {}
}
fn new_gate() -> Arc<Gate> {
    Arc::new(Gate {
        cleanup_ready: AtomicBool::new(true),
        ..Default::default()
    })
}
fn prepare(
    node: &Arc<NodeAdmission>,
    gate: &Arc<Gate>,
    outcome: Outcome,
) -> SnapshotWork<Operation> {
    node.prepare_snapshot_work::<Operation>(Plan {
        core: node.memory().clone(),
        gate: gate.clone(),
        outcome,
    })
    .unwrap()
}
fn original(report: &SnapshotWorkReport) -> (*const OriginalFailure, u64) {
    let mut original = None;
    report.visit(|observation| {
        if let SnapshotObservation::Failure(error) = observation {
            let error = error.downcast_ref::<OriginalFailure>().unwrap();
            original = Some((std::ptr::from_ref(error), error.0));
        }
    });
    original.unwrap()
}
fn cleanup_identity(report: &SnapshotWorkReport) -> (*const OriginalFailure, u64) {
    let mut found = None;
    report.visit(|observation| {
        if let SnapshotObservation::Diagnostic(error) = observation {
            let error = error.downcast_ref::<OriginalFailure>().unwrap();
            found = Some((std::ptr::from_ref(error), error.0));
        }
    });
    found.unwrap()
}
fn panic_identity(report: &SnapshotWorkReport) -> (*const OriginalFailure, u64) {
    let mut original = None;
    report.visit(|observation| {
        if let SnapshotObservation::Panic { phase, payload } = observation {
            assert_eq!(phase, SnapshotPanicPhase::Run);
            let error = payload.downcast_ref::<OriginalFailure>().unwrap();
            original = Some((std::ptr::from_ref(error), error.0));
        }
    });
    original.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_delivery_and_drain_join_the_actual_late_failure() {
    let node = admission(1);
    let core = node.memory().clone();
    let baseline = core.snapshot().reserved_bytes;
    let gate = new_gate();
    let work = prepare(&node, &gate, Outcome::Failure);
    let id = work.id();
    work.start().unwrap();
    gate.started().await;
    let mut waiting = Box::pin(work.ready());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(waiting);
    assert!(
        tokio::time::timeout(Duration::from_millis(1), work.ready())
            .await
            .is_err()
    );
    drop(work);
    let report = core.snapshot_work_at(id.slot).unwrap();
    let charged = core.snapshot().reserved_bytes;
    assert!(charged > baseline);
    assert_eq!(core.snapshot().inflight_operations, 1);
    let mut draining = Box::pin(report.drain());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(draining.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(draining);
    assert_eq!(core.snapshot().reserved_bytes, charged);
    assert_eq!(gate.cleanup_calls.load(Ordering::Acquire), 0);
    let denied = new_gate();
    assert!(
        node.prepare_snapshot_work::<Operation>(Plan {
            core: node.memory().clone(),
            gate: denied.clone(),
            outcome: Outcome::Success
        })
        .is_err()
    );
    assert_eq!(denied.allocations.load(Ordering::Acquire), 0);
    gate.release();
    let completed = report.drain().await;
    assert_eq!(completed.completion(), DrainCompletion::Complete);
    assert!(core.snapshot_work_at(id.slot).is_none());
    let first = original(&completed);
    assert_eq!(first.1, 731);
    let repeated = report.drain().await;
    assert_eq!(repeated.completion(), DrainCompletion::Complete);
    assert_eq!(original(&repeated), first);
    assert_eq!(core.snapshot().reserved_bytes, charged);
    drop(repeated);
    drop(completed);
    drop(report);
    assert_eq!(core.snapshot().reserved_bytes, baseline);
    assert_eq!(core.snapshot().inflight_operations, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_run_panic_retains_original_payload_resource_and_charge_without_cleanup() {
    let node = admission(1);
    let core = node.memory().clone();
    let baseline = core.snapshot().reserved_bytes;
    let gate = new_gate();
    let work = prepare(&node, &gate, Outcome::Panic);
    work.start().unwrap();
    gate.started().await;
    let id = work.id();
    drop(work);
    gate.release();
    let report = core.snapshot_work_at(id.slot).unwrap();
    let first = report.drain().await;
    assert_eq!(first.completion(), DrainCompletion::Retained);
    let identity = panic_identity(&first);
    assert_eq!(identity.1, 937);
    let repeated = report.drain().await;
    assert_eq!(repeated.completion(), DrainCompletion::Retained);
    assert_eq!(panic_identity(&repeated), identity);
    assert_eq!(gate.cleanup_calls.load(Ordering::Acquire), 0);
    assert!(core.snapshot().reserved_bytes > baseline);
    assert!(core.snapshot_work_at(id.slot).is_some());
    // This deliberately unresolved fixture proves retained panic custody; it
    // makes no Complete claim and does not erase or reset the fixed census.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_cleanup_can_resolve_without_losing_the_original_failure() {
    let node = admission(1);
    let core = node.memory().clone();
    let gate = new_gate();
    gate.cleanup_ready.store(false, Ordering::Release);
    let work = prepare(&node, &gate, Outcome::Failure);
    work.start().unwrap();
    gate.started().await;
    gate.release();
    let report = work.report();
    let first = report.drain().await;
    assert_eq!(first.completion(), DrainCompletion::Retained);
    let identity = original(&first);
    let cleanup = cleanup_identity(&first);
    assert_eq!(cleanup.1, 991);
    assert!(core.snapshot_work_at(work.id().slot).is_some());
    gate.cleanup_ready.store(true, Ordering::Release);
    let second = report.drain().await;
    assert_eq!(second.completion(), DrainCompletion::Complete);
    assert_eq!(original(&second), identity);
    assert_eq!(cleanup_identity(&second), cleanup);
    assert!(core.snapshot_work_at(work.id().slot).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_unclaimed_output_stays_owned_until_explicit_drain() {
    let node = admission(1);
    let gate = new_gate();
    let work = prepare(&node, &gate, Outcome::Success);
    work.start().unwrap();
    gate.started().await;
    gate.release();
    let ready = work.ready().await;
    assert_eq!(ready.completion(), DrainCompletion::Retained);
    assert_eq!(gate.output_drops.load(Ordering::Acquire), 0);
    drop(work);
    assert_eq!(gate.output_drops.load(Ordering::Acquire), 0);
    assert_eq!(ready.drain().await.completion(), DrainCompletion::Complete);
    assert_eq!(gate.output_drops.load(Ordering::Acquire), 0);
    assert_eq!(ready.drain().await.completion(), DrainCompletion::Complete);
    assert_eq!(gate.output_drops.load(Ordering::Acquire), 0);
    drop(ready);
    assert_eq!(gate.output_drops.load(Ordering::Acquire), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn synchronous_claim_retires_only_its_generation_and_keeps_transferred_output() {
    let node = admission(2);
    let core = node.memory().clone();
    let first_gate = new_gate();
    let first = prepare(&node, &first_gate, Outcome::Success);
    let old_id = first.id();
    first.start().unwrap();
    first_gate.started().await;
    first_gate.release();
    let report = first.ready().await;
    let output = first.claim().ok().expect("ready output");
    assert_eq!(report.completion(), DrainCompletion::Complete);
    assert!(core.snapshot_work_at(old_id.slot).is_none());
    assert_eq!(first_gate.output_drops.load(Ordering::Acquire), 0);
    // A retained report truthfully keeps the first operation charge. Capacity
    // two admits a successor while that old generation remains observable.
    let successor_gate = new_gate();
    let successor = prepare(&node, &successor_gate, Outcome::Success);
    assert_eq!(successor.id().slot, old_id.slot);
    assert_ne!(successor.id().generation, old_id.generation);
    assert_eq!(report.drain().await.completion(), DrainCompletion::Complete);
    assert_eq!(
        core.snapshot_work_at(old_id.slot).unwrap().id(),
        successor.id()
    );
    let successor_report = successor.report();
    assert_eq!(
        successor_report.drain().await.completion(),
        DrainCompletion::Complete
    );
    assert!(!successor_gate.started.load(Ordering::Acquire));
    drop(output);
    assert_eq!(first_gate.output_drops.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn admission_failure_precedes_inert_builder_and_returns_the_reserved_slot() {
    let node = admission(1);
    let baseline = node.snapshot();
    let held = node.reserve(0, None).unwrap();
    let gate = new_gate();
    assert!(
        node.prepare_snapshot_work::<Operation>(Plan {
            core: node.memory().clone(),
            gate: gate.clone(),
            outcome: Outcome::Success
        })
        .is_err()
    );
    assert_eq!(gate.allocations.load(Ordering::Acquire), 0);
    assert!(node.memory().snapshot_work_at(0).is_none());
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    drop(held);
    let accepted = prepare(&node, &gate, Outcome::Success);
    assert_eq!(gate.allocations.load(Ordering::Acquire), 1);
    // No child starts in preparation. The accepted inert owner remains in its
    // census until a later asynchronous drain; caller Drop cannot discard it.
    assert!(!gate.started.load(Ordering::Acquire));
    drop(accepted);
    let retained = node.memory().snapshot_work_at(0).unwrap();
    assert_eq!(
        retained.drain().await.completion(),
        DrainCompletion::Complete
    );
    drop(retained);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
}

#[tokio::test]
async fn foreign_core_and_one_byte_short_plan_are_denied_before_allocation() {
    let node = admission(2);
    let foreign = admission(2);
    let gate = new_gate();
    let before = node.snapshot().reserved_bytes;
    let foreign_before = foreign.snapshot().reserved_bytes;
    let error = node
        .prepare_snapshot_work::<Operation>(Plan {
            core: foreign.memory().clone(),
            gate: gate.clone(),
            outcome: Outcome::Success,
        })
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(gate.allocations.load(Ordering::Acquire), 0);
    assert_eq!(node.snapshot().reserved_bytes, before);
    assert_eq!(foreign.snapshot().reserved_bytes, foreign_before);
    let plan = Plan {
        core: node.memory().clone(),
        gate: gate.clone(),
        outcome: Outcome::Success,
    };
    let required = Owner::<Operation>::required_bytes(&plan).unwrap();
    let held = node
        .reserve_resident(
            node.memory()
                .data
                .max_bytes
                .checked_sub(before)
                .unwrap()
                .checked_sub(required)
                .unwrap()
                .checked_add(1)
                .unwrap(),
        )
        .unwrap();
    let denied = node.prepare_snapshot_work::<Operation>(plan).err().unwrap();
    assert_eq!(denied.code, ErrorCode::ResourceExhausted);
    assert_eq!(gate.allocations.load(Ordering::Acquire), 0);
    assert!(node.memory().snapshot_work_at(0).is_none());
    drop(held);
    let accepted = prepare(&node, &gate, Outcome::Success);
    let report = accepted.report();
    assert_eq!(report.drain().await.completion(), DrainCompletion::Complete);
    drop(accepted);
    drop(report);
    assert_eq!(node.snapshot().reserved_bytes, before);
}

// Observe the actual global allocator event, rather than a destructor callback
// which runs before Arc backing is freed. Only two exact live allocation ranges
// are armed; unrelated concurrent test/runtime allocations are forwarded intact.
mod deallocation {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};

    pub(super) struct Watch {
        address: AtomicUsize,
        block: AtomicBool,
        entered: AtomicBool,
        released: AtomicBool,
        finished: AtomicBool,
        count: AtomicUsize,
    }
    impl Watch {
        const fn new() -> Self {
            Self {
                address: AtomicUsize::new(0),
                block: AtomicBool::new(false),
                entered: AtomicBool::new(false),
                released: AtomicBool::new(false),
                finished: AtomicBool::new(false),
                count: AtomicUsize::new(0),
            }
        }
        pub(super) fn arm(&'static self, address: usize, block: bool) -> Release {
            assert_ne!(address, 0);
            assert_eq!(self.address.load(Ordering::Acquire), 0);
            self.block.store(block, Ordering::Relaxed);
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
            while self.block.load(Ordering::Acquire) && !self.released.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            true
        }
        pub(super) async fn entered(&self) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while !self.entered.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        pub(super) fn finished(&self) -> bool {
            self.finished.load(Ordering::Acquire)
        }
        pub(super) fn count(&self) -> usize {
            self.count.load(Ordering::Acquire)
        }
    }
    pub(super) struct Release(&'static Watch);
    impl Release {
        pub(super) fn release(&self) {
            self.0.released.store(true, Ordering::Release);
        }
    }
    impl Drop for Release {
        fn drop(&mut self) {
            self.release();
            self.0.address.store(0, Ordering::Release);
        }
    }
    pub(super) static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    pub(super) static OWNER: Watch = Watch::new();
    pub(super) static WAKE: Watch = Watch::new();
    struct ObservedSystem;
    #[global_allocator]
    static ALLOCATOR: ObservedSystem = ObservedSystem;
    // SAFETY: every allocation operation is forwarded unchanged to System. The
    // deallocation observer uses only atomics and yield_now, never allocation,
    // dereference of observed payload pointers, formatting, or user callbacks.
    unsafe impl GlobalAlloc for ObservedSystem {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            unsafe { System.realloc(pointer, layout, size) }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            let owner = OWNER.before(pointer, layout);
            let wake = WAKE.before(pointer, layout);
            unsafe { System.dealloc(pointer, layout) };
            if owner {
                OWNER.finished.store(true, Ordering::Release);
            }
            if wake {
                WAKE.finished.store(true, Ordering::Release);
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ready_failure_retires_census_without_a_redundant_drain() {
    let node = admission(1);
    let baseline = node.snapshot().reserved_bytes;
    let gate = new_gate();
    let work = prepare(&node, &gate, Outcome::Failure);
    work.start().unwrap();
    gate.started().await;
    gate.release();
    let report = work.ready().await;
    assert_eq!(report.completion(), DrainCompletion::Complete);
    assert!(node.memory().snapshot_work_at(work.id().slot).is_none());
    let identity = original(&report);
    let failed_claim = work
        .claim()
        .err()
        .expect("typed failure cannot become output");
    assert_eq!(original(&failed_claim), identity);
    drop(failed_claim);
    drop(report);
    drop(work);
    assert_eq!(node.snapshot().reserved_bytes, baseline);
    assert_eq!(node.snapshot().inflight_operations, 0);
    let successor = prepare(&node, &gate, Outcome::Failure);
    drop(successor.report().drain().await);
    drop(successor);
    assert_eq!(node.snapshot().reserved_bytes, baseline);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_final_reports_cannot_reuse_credit_before_actual_owner_deallocation() {
    let _serial = deallocation::SERIAL.lock().await;
    let node = admission(1);
    let baseline = node.snapshot().reserved_bytes;
    let gate = new_gate();
    let work = prepare(&node, &gate, Outcome::Failure);
    let owner_address = std::ptr::from_ref::<Owner<Operation>>(&work.owner) as usize;
    let wake_address = std::ptr::from_ref::<WorkWake>(&work.owner.wake) as usize;
    work.start().unwrap();
    gate.started().await;
    gate.release();
    let report = work.ready().await;
    let charged = node.snapshot().reserved_bytes;
    let rendezvous = Arc::new(std::sync::Barrier::new(9));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let report = report.clone();
        let rendezvous = rendezvous.clone();
        threads.push(std::thread::spawn(move || {
            rendezvous.wait();
            drop(report);
        }));
    }
    let owner_release = deallocation::OWNER.arm(owner_address, true);
    let _wake_release = deallocation::WAKE.arm(wake_address, false);
    drop(report);
    drop(work);
    rendezvous.wait();
    deallocation::OWNER.entered().await;
    assert!(!deallocation::OWNER.finished());
    assert_eq!(gate.operation_drops.load(Ordering::Acquire), 0);
    assert_eq!(node.snapshot().reserved_bytes, charged);
    assert_eq!(node.snapshot().inflight_operations, 1);
    assert!(
        node.reserve(0, None).is_err(),
        "actual operation backing is still alive"
    );
    owner_release.release();
    for thread in threads {
        thread.join().unwrap();
    }
    assert!(deallocation::OWNER.finished());
    assert!(deallocation::WAKE.finished());
    assert_eq!(deallocation::OWNER.count(), 1);
    assert_eq!(deallocation::WAKE.count(), 1);
    assert_eq!(gate.operation_drops.load(Ordering::Acquire), 1);
    assert_eq!(node.snapshot().reserved_bytes, baseline);
    assert_eq!(node.snapshot().inflight_operations, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_waker_outlives_all_owner_views_and_keeps_credit_until_actual_deallocation() {
    let _serial = deallocation::SERIAL.lock().await;
    let node = admission(1);
    let baseline = node.snapshot().reserved_bytes;
    let gate = new_gate();
    let work = prepare(&node, &gate, Outcome::Failure);
    let owner_address = std::ptr::from_ref::<Owner<Operation>>(&work.owner) as usize;
    let wake_address = std::ptr::from_ref::<WorkWake>(&work.owner.wake) as usize;
    // The identical proxy type handed to cleanup/JoinHandle can remain alive
    // after its registration is removed or while a concurrent wake is running.
    let proxy = work.owner.wake.waker();
    let last_proxy = proxy.clone();
    work.start().unwrap();
    gate.started().await;
    gate.release();
    let report = work.ready().await;
    let charged = node.snapshot().reserved_bytes;
    let _owner_release = deallocation::OWNER.arm(owner_address, false);
    let wake_release = deallocation::WAKE.arm(wake_address, true);
    drop(report);
    drop(work);
    assert!(deallocation::OWNER.finished());
    assert_eq!(gate.operation_drops.load(Ordering::Acquire), 1);
    proxy.wake_by_ref();
    proxy.wake();
    assert_eq!(node.snapshot().reserved_bytes, charged);
    assert_eq!(node.snapshot().inflight_operations, 1);
    let thread = std::thread::spawn(move || last_proxy.wake());
    deallocation::WAKE.entered().await;
    assert!(!deallocation::WAKE.finished());
    assert_eq!(node.snapshot().reserved_bytes, charged);
    assert!(node.reserve(0, None).is_err());
    wake_release.release();
    thread.join().unwrap();
    assert!(deallocation::WAKE.finished());
    assert_eq!(deallocation::OWNER.count(), 1);
    assert_eq!(deallocation::WAKE.count(), 1);
    assert_eq!(node.snapshot().reserved_bytes, baseline);
    assert_eq!(node.snapshot().inflight_operations, 0);
}

struct ReentrantWake {
    wake: OwnedWake,
    wake_calls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    panic_on_wake: bool,
}
impl ReentrantWake {
    fn check_unlocked(&self) {
        match self.wake.state.try_lock() {
            Ok(guard) => drop(guard),
            Err(std::sync::TryLockError::Poisoned(error)) => drop(error.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => panic!("waker callback under waiter lock"),
        }
    }
}
impl std::task::Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
        self.check_unlocked();
        self.wake_calls.fetch_add(1, Ordering::AcqRel);
        assert!(!self.panic_on_wake, "original executor wake panic");
    }
}
impl Drop for ReentrantWake {
    fn drop(&mut self) {
        self.check_unlocked();
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}
fn reentrant_waker(
    wake: &OwnedWake,
    calls: &Arc<AtomicUsize>,
    drops: &Arc<AtomicUsize>,
    panic: bool,
) -> Waker {
    Waker::from(Arc::new(ReentrantWake {
        wake: wake.clone(),
        wake_calls: calls.clone(),
        drops: drops.clone(),
        panic_on_wake: panic,
    }))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_finish_destroys_executor_waiter_after_unlock_and_before_next_poll() {
    let node = admission(1);
    let baseline = node.snapshot().reserved_bytes;
    let gate = new_gate();
    let work = prepare(&node, &gate, Outcome::Failure);
    work.start().unwrap();
    gate.started().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let outer = reentrant_waker(&work.owner.wake, &calls, &drops, false);
    let mut ready = Box::pin(work.ready());
    assert!(
        ready
            .as_mut()
            .poll(&mut Context::from_waker(&outer))
            .is_pending()
    );
    drop(outer);
    assert_eq!(drops.load(Ordering::Acquire), 0);
    drop(ready);
    assert_eq!(drops.load(Ordering::Acquire), 1);
    assert!(work.owner.wake.state.lock().unwrap().waiter.is_none());
    assert_eq!(calls.load(Ordering::Acquire), 0);
    // The next waiter must use the same actual operation; no dropped wrapper
    // may erase its join custody or let another operation consume the slot.
    gate.release();
    drop(work.ready().await);
    drop(work);
    assert_eq!(node.snapshot().reserved_bytes, baseline);
}

#[tokio::test]
async fn proxy_callback_panic_and_poison_preserve_borrowed_and_consumed_count_ownership() {
    let node = admission(1);
    let baseline = node.snapshot().reserved_bytes;
    let gate = new_gate();
    let work = prepare(&node, &gate, Outcome::Failure);
    let wake = work.owner.wake.clone();
    let proxy = wake.waker();
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let report = work.report().drain().await;
    let charged = node.snapshot().reserved_bytes;
    drop(report);
    drop(work);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _locked = wake.state.lock().unwrap();
            panic!("fixture waiter poison");
        }))
        .is_err()
    );
    wake.state.lock().unwrap_or_else(|p| p.into_inner()).waiter =
        Some(reentrant_waker(&wake, &calls, &drops, true));
    assert!(catch_unwind(AssertUnwindSafe(|| proxy.wake_by_ref())).is_err());
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_eq!(drops.load(Ordering::Acquire), 1);
    assert_eq!(
        node.snapshot().reserved_bytes,
        charged,
        "borrowed wake kept its count"
    );
    wake.state.lock().unwrap_or_else(|p| p.into_inner()).waiter =
        Some(reentrant_waker(&wake, &calls, &drops, true));
    drop(wake);
    assert!(catch_unwind(AssertUnwindSafe(|| proxy.wake())).is_err());
    assert_eq!(calls.load(Ordering::Acquire), 2);
    assert_eq!(drops.load(Ordering::Acquire), 2);
    assert_eq!(node.snapshot().reserved_bytes, baseline);
    assert_eq!(node.snapshot().inflight_operations, 0);
}

// This executor deliberately reenters the public report, rather than merely
// checking the proxy's own mutex. The try_lock checks make a regression fail
// promptly instead of deadlocking the test process inside completion().
struct CompletionWake {
    owner: OwnedOwner<Operation>,
    report: SnapshotWorkReport,
    calls: AtomicUsize,
    panic_on_wake: AtomicBool,
}
impl CompletionWake {
    fn inspect(&self) {
        fn require_unlocked<T>(mutex: &Mutex<T>) {
            match mutex.try_lock() {
                Ok(guard) => drop(guard),
                Err(std::sync::TryLockError::Poisoned(error)) => drop(error.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => {
                    panic!("external executor callback under an owner lock")
                }
            }
        }
        require_unlocked(&self.owner.control);
        require_unlocked(&self.owner.resource);
        require_unlocked(&self.owner.wake.state);
        // Execute the actual public path after the deadlock-prevention checks.
        let _completion = self.report.completion();
    }
}
impl std::task::Wake for CompletionWake {
    fn wake(self: Arc<Self>) {
        self.inspect();
        self.calls.fetch_add(1, Ordering::AcqRel);
        assert!(
            !self.panic_on_wake.load(Ordering::Acquire),
            "original deferred executor wake panic"
        );
    }
}
impl Drop for CompletionWake {
    fn drop(&mut self) {
        self.inspect();
    }
}
fn completion_waker(work: &SnapshotWork<Operation>) -> (Arc<CompletionWake>, Waker) {
    let callback = Arc::new(CompletionWake {
        owner: work.owner.clone(),
        report: work.report(),
        calls: AtomicUsize::new(0),
        panic_on_wake: AtomicBool::new(false),
    });
    let waker = Waker::from(callback.clone());
    (callback, waker)
}
async fn join_only(work: &SnapshotWork<Operation>, gate: &Gate) {
    work.start().unwrap();
    gate.started().await;
    gate.release();
    assert!(std::future::poll_fn(|cx| work.owner.poll_join(cx)).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleanup_and_discard_wakes_reenter_actual_completion_only_after_owner_unlock() {
    for outcome in [Outcome::Failure, Outcome::Success] {
        let node = admission(1);
        let baseline = node.snapshot().reserved_bytes;
        let gate = new_gate();
        gate.cleanup_wake_pending.store(true, Ordering::Release);
        gate.discard_wake_pending.store(true, Ordering::Release);
        let work = prepare(&node, &gate, outcome);
        join_only(&work, &gate).await;
        let (callback, outer) = completion_waker(&work);
        let report = work.report();
        let original_failure = match outcome {
            Outcome::Failure => Some(original(&report)),
            _ => None,
        };
        let mut draining = Box::pin(report.drain());
        assert!(
            draining
                .as_mut()
                .poll(&mut Context::from_waker(&outer))
                .is_pending()
        );
        assert_eq!(callback.calls.load(Ordering::Acquire), 1);
        assert_eq!(report.completion(), DrainCompletion::Retained);
        assert_eq!(work.owner.wake.state.lock().unwrap().owner_scopes, 0);
        assert_eq!(node.snapshot().inflight_operations, 1);
        if matches!(outcome, Outcome::Success) {
            assert!(
                draining
                    .as_mut()
                    .poll(&mut Context::from_waker(&outer))
                    .is_pending()
            );
            assert_eq!(callback.calls.load(Ordering::Acquire), 2);
            assert_eq!(report.completion(), DrainCompletion::Retained);
            assert_eq!(gate.output_drops.load(Ordering::Acquire), 0);
        }
        let Poll::Ready(drained) = draining.as_mut().poll(&mut Context::from_waker(&outer)) else {
            panic!("the same operation must complete after its deferred wake");
        };
        assert_eq!(drained.completion(), DrainCompletion::Complete);
        assert!(node.memory().snapshot_work_at(work.id().slot).is_none());
        if let Some(original_failure) = original_failure {
            assert_eq!(original(&drained), original_failure);
        }
        drop(drained);
        drop(draining);
        drop(report);
        drop(outer);
        drop(callback);
        drop(work);
        assert_eq!(gate.operation_drops.load(Ordering::Acquire), 1);
        assert_eq!(
            gate.output_drops.load(Ordering::Acquire),
            usize::from(matches!(outcome, Outcome::Success))
        );
        assert_eq!(node.snapshot().reserved_bytes, baseline);
        assert_eq!(node.snapshot().inflight_operations, 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deferred_callback_panic_then_cancel_preserves_original_outcome_and_retry() {
    let node = admission(1);
    let baseline = node.snapshot().reserved_bytes;
    let gate = new_gate();
    gate.cleanup_wake_pending.store(true, Ordering::Release);
    let work = prepare(&node, &gate, Outcome::Failure);
    join_only(&work, &gate).await;
    let report = work.report();
    let original_failure = original(&report);
    let charged = node.snapshot().reserved_bytes;
    let (callback, outer) = completion_waker(&work);
    callback.panic_on_wake.store(true, Ordering::Release);
    let mut draining = Box::pin(report.drain());
    let Err(panic) = catch_unwind(AssertUnwindSafe(|| {
        draining.as_mut().poll(&mut Context::from_waker(&outer))
    })) else {
        panic!("the external executor panic must leave the owner poll scope");
    };
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"original deferred executor wake panic")
    );
    assert_eq!(callback.calls.load(Ordering::Acquire), 1);
    assert_eq!(original(&report), original_failure);
    assert!(work.owner.resource.lock().unwrap().panic.is_none());
    assert_eq!(work.owner.wake.state.lock().unwrap().owner_scopes, 0);
    assert_eq!(node.snapshot().reserved_bytes, charged);
    assert!(node.memory().snapshot_work_at(work.id().slot).is_some());
    // The failed poll did not finish the future. Cancel that waiter and then
    // retry the same actual child/resources; never repoll the unwound future.
    drop(draining);
    assert!(work.owner.wake.state.lock().unwrap().waiter.is_none());
    let drained = report.drain().await;
    assert_eq!(drained.completion(), DrainCompletion::Complete);
    assert_eq!(original(&drained), original_failure);
    assert!(node.memory().snapshot_work_at(work.id().slot).is_none());
    drop(drained);
    drop(report);
    drop(outer);
    drop(callback);
    drop(work);
    assert_eq!(node.snapshot().reserved_bytes, baseline);
}

#[tokio::test]
async fn nested_owner_scopes_coalesce_wakes_and_unwind_leaves_registration_recoverable() {
    let node = admission(1);
    let baseline = node.snapshot().reserved_bytes;
    let gate = new_gate();
    let work = prepare(&node, &gate, Outcome::Failure);
    let report = work.report().drain().await;
    let (callback, outer) = completion_waker(&work);
    let proxy = work.owner.wake.waker();
    work.owner.wake.register(outer.clone());
    let control_scope = work.owner.wake.defer();
    let control = work.owner.control.lock().unwrap();
    let resource_scope = work.owner.wake.defer();
    let resource = work.owner.resource.lock().unwrap();
    proxy.wake_by_ref();
    proxy.wake_by_ref();
    assert_eq!(callback.calls.load(Ordering::Acquire), 0);
    drop(resource);
    drop(resource_scope);
    assert_eq!(callback.calls.load(Ordering::Acquire), 0);
    drop(control);
    assert_eq!(callback.calls.load(Ordering::Acquire), 0);
    drop(control_scope);
    assert_eq!(callback.calls.load(Ordering::Acquire), 1);
    assert_eq!(report.completion(), DrainCompletion::Complete);
    work.owner.wake.register(outer.clone());
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _scope = work.owner.wake.defer();
            proxy.wake_by_ref();
            panic!("original owner-scope unwind");
        }))
        .is_err()
    );
    assert_eq!(
        callback.calls.load(Ordering::Acquire),
        1,
        "never invoke the executor during an existing unwind"
    );
    {
        let state = work.owner.wake.state.lock().unwrap();
        assert_eq!(state.owner_scopes, 0);
        assert!(state.notified);
        assert!(state.waiter.is_some());
    }
    // A later scope drains the preserved notification after its own locks are
    // released. Its executor really reenters completion, with no lost wake.
    assert_eq!(report.completion(), DrainCompletion::Complete);
    assert_eq!(callback.calls.load(Ordering::Acquire), 2);
    assert!(!work.owner.wake.state.lock().unwrap().notified);
    drop(proxy);
    drop(report);
    drop(outer);
    drop(callback);
    drop(work);
    assert_eq!(node.snapshot().reserved_bytes, baseline);
}
