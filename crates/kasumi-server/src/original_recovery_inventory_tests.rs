use super::*;
use crate::recovery_allocation_watch::{AddressWatch, Watch};
use kasumi_engine::admission::NodeAdmission;
use std::{
    any::Any,
    cell::{Cell, RefCell},
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};

thread_local! {
    static REFUND_EXPECTATION: RefCell<Option<(Arc<NodeAdmission>, usize)>> = const { RefCell::new(None) };
    static REFUND_OBSERVATION: Cell<Option<(bool, u64)>> = const { Cell::new(None) };
}
pub(super) fn before_refund(address: usize) {
    REFUND_EXPECTATION.with(|expected| {
        if let Some((admission, expected_address)) = expected.borrow().as_ref()
            && *expected_address == address
        {
            let all_retired = AddressWatch::all_retired();
            REFUND_OBSERVATION.with(|observed| {
                observed.set(Some((all_retired, admission.snapshot().reserved_bytes)))
            });
        }
    });
}

fn actual_addresses(inventory: &OriginalRecoveries) -> [usize; 8] {
    let state = inventory.state();
    let (_, offset) = std::alloc::Layout::new::<[usize; 2]>()
        .extend(std::alloc::Layout::new::<RecoveryInventoryState>())
        .unwrap();
    let data = Arc::as_ptr(inventory.inner.as_ref().unwrap()) as usize;
    let names = state.participants.as_ref().unwrap();
    assert!(names.len() <= 4);
    let mut addresses = [0; 8];
    addresses[..4].copy_from_slice(&[
        data - offset,
        state.seats.as_ref().unwrap().as_ptr() as usize,
        state.rpc.as_ref().unwrap().as_ptr() as usize,
        names.as_ptr() as usize,
    ]);
    for (index, name) in names.iter().enumerate() {
        if !name.is_empty() {
            addresses[index + 4] = name.as_ptr() as usize;
        }
    }
    addresses
}

static CLAIM_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static PAUSE_INVENTORY: AtomicUsize = AtomicUsize::new(0);
static CLAIM_ENTERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static CLAIM_RELEASE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(super) fn after_rpc_claim(address: usize) {
    if PAUSE_INVENTORY.load(Ordering::SeqCst) == address {
        CLAIM_ENTERED.store(true, Ordering::SeqCst);
        while !CLAIM_RELEASE.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
    }
}

#[test]
fn original_recovery_actual_array_frees_before_same_installed_charge_refund() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let before = admission.snapshot();
    let names = [crate::runtime::CONTROL_TENANT, "tenant"];
    let participants = OriginalRecoveryParticipants::names(&names);
    let capacity = names.len();
    let bytes = OriginalRecoveries::required_bytes(admission.policy(), participants).unwrap();
    let watching = Watch::begin();
    let inventory = OriginalRecoveries::new(&admission, participants).unwrap();
    let addresses = actual_addresses(&inventory);
    let address = addresses[1];
    let allocation = watching.snapshot().allocation(address).unwrap();
    let layout = std::alloc::Layout::array::<tokio::sync::Mutex<RecoverySeat>>(capacity).unwrap();
    assert_eq!(
        (allocation.bytes, allocation.align),
        (layout.size(), layout.align())
    );
    let (control, _) = std::alloc::Layout::new::<[usize; 2]>()
        .extend(std::alloc::Layout::new::<RecoveryInventoryState>())
        .unwrap();
    let control = control.pad_to_align();
    let layouts = [
        control,
        layout,
        std::alloc::Layout::array::<RpcSeat>(capacity * admission.policy().max_inflight_operations)
            .unwrap(),
        std::alloc::Layout::array::<String>(capacity).unwrap(),
        std::alloc::Layout::array::<u8>(names[0].len()).unwrap(),
        std::alloc::Layout::array::<u8>(names[1].len()).unwrap(),
    ];
    for (address, layout) in addresses.into_iter().zip(layouts) {
        let allocation = watching.snapshot().allocation(address).unwrap();
        assert_eq!(
            (allocation.bytes, allocation.align),
            (layout.size(), layout.align())
        );
        assert!(!allocation.freed);
    }
    assert_eq!(
        admission.snapshot().reserved_bytes,
        before.reserved_bytes + bytes
    );
    assert_eq!(
        admission.snapshot().live_reservations,
        before.live_reservations + 1
    );
    let count = watching.snapshot().count;
    let alias = inventory.clone();
    assert_eq!(watching.snapshot().count, count, "closed alias allocated");
    assert_eq!(
        admission.snapshot().live_reservations,
        before.live_reservations + 1
    );
    let address_watch = AddressWatch::begin(addresses);
    drop(inventory);
    assert_eq!(address_watch.counts(), [0; 8]);
    assert_eq!(
        admission.snapshot().reserved_bytes,
        before.reserved_bytes + bytes
    );
    REFUND_EXPECTATION.with(|expected| *expected.borrow_mut() = Some((admission.clone(), address)));
    REFUND_OBSERVATION.with(|observed| observed.set(None));
    drop(alias);
    let observed = REFUND_OBSERVATION.with(Cell::get).unwrap();
    REFUND_EXPECTATION.with(|expected| expected.borrow_mut().take());
    assert_eq!(observed, (true, before.reserved_bytes + bytes));
    assert_eq!(address_watch.counts(), [1, 1, 1, 1, 1, 1, 0, 0]);
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        before.live_reservations
    );
    let observed = watching.finish();
    assert!(!observed.overflow);
    for address in &addresses[..6] {
        assert!(observed.allocation(*address).unwrap().freed);
    }
}

#[test]
fn original_recovery_refusal_creates_no_array_or_new_charge() {
    let config = kasumi_engine::admission::AdmissionConfig::default();
    let total = config.resolved_fixture_total_bytes().unwrap();
    let admission = NodeAdmission::new(config).unwrap();
    let before = admission.snapshot();
    let pressure = admission
        .memory()
        .reserve_resident(total - before.reserved_bytes)
        .unwrap();
    let full = admission.snapshot();
    let capacity = 2;
    let layout = std::alloc::Layout::array::<tokio::sync::Mutex<RecoverySeat>>(capacity).unwrap();
    let watching = Watch::begin();
    let refused = OriginalRecoveries::new(
        &admission,
        OriginalRecoveryParticipants::names(&[crate::runtime::CONTROL_TENANT, "tenant"]),
    );
    assert!(refused.is_err());
    // The ordinary provider refusal may own its original diagnostic backing.
    // This verifies the concrete constructor array never allocated.
    assert!(
        !watching.snapshot().allocations[..watching.snapshot().count]
            .iter()
            .any(|allocation| allocation.bytes == layout.size()
                && allocation.align == layout.align())
    );
    assert_eq!(admission.snapshot().reserved_bytes, full.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        full.live_reservations
    );
    drop(refused);
    assert!(!watching.finish().overflow);
    drop(pressure);
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);
}

struct OpaqueOriginal {
    _lease: kasumi_engine::admission::Reservation,
    drops: Arc<AtomicUsize>,
}
impl std::fmt::Debug for OpaqueOriginal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpaqueOriginal")
    }
}
impl std::fmt::Display for OpaqueOriginal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original source diagnostic")
    }
}
impl std::error::Error for OpaqueOriginal {}
impl Drop for OpaqueOriginal {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn original_recovery_opaque_source_keeps_actual_original_and_charge_after_facade_drop() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let before = admission.snapshot();
    let drops = Arc::new(AtomicUsize::new(0));
    let original = anyhow::Error::new(OpaqueOriginal {
        _lease: admission
            .memory()
            .reserve_resident(std::mem::size_of::<usize>() as u64)
            .unwrap(),
        drops: drops.clone(),
    });
    let original_address = original.downcast_ref::<OpaqueOriginal>().unwrap() as *const _ as usize;
    let charged = admission.snapshot();
    let watching = Watch::begin();
    let inventory =
        OriginalRecoveries::new(&admission, OriginalRecoveryParticipants::one("tenant")).unwrap();
    let address = inventory.state().seats.as_ref().unwrap().as_ptr() as usize;
    let mut seat = inventory.claim(0).await;
    let capture_watch = watching.snapshot().count;
    let marker = seat
        .capture_snapshot(original.into())
        .expect("preheld empty seat");
    assert_eq!(
        watching.snapshot().count,
        capture_watch,
        "paid handoff allocated"
    );
    assert_eq!(marker.index, 0);
    drop(marker);
    assert_eq!(
        seat.with_failure(|failure| failure
            .original()
            .source_error()
            .unwrap()
            .downcast_ref::<OpaqueOriginal>()
            .unwrap() as *const _ as usize),
        Some(original_address)
    );
    drop(seat);
    assert!(inventory.retained().await);
    let retained = admission.snapshot();
    drop(inventory);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(admission.snapshot().reserved_bytes, retained.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        retained.live_reservations
    );
    assert!(retained.reserved_bytes > charged.reserved_bytes);
    assert!(charged.reserved_bytes > before.reserved_bytes);
    let observed = watching.finish();
    assert!(!observed.overflow);
    assert!(!observed.allocation(address).unwrap().freed);
}

#[derive(Debug)]
struct OriginalPanic(u64);
struct ReturnedThenDropPanic {
    original: Option<DrainFailure>,
    drop_panic: Option<Box<dyn Any + Send>>,
}
impl Future for ReturnedThenDropPanic {
    type Output = kasumi_types::drain::DrainResult;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Err(self.original.take().expect("one original poll")))
    }
}
impl Drop for ReturnedThenDropPanic {
    fn drop(&mut self) {
        std::panic::resume_unwind(self.drop_panic.take().expect("one original destructor"));
    }
}
struct PollThenDropPanic {
    poll_panic: Option<Box<dyn Any + Send>>,
    drop_panic: Option<Box<dyn Any + Send>>,
}
impl Future for PollThenDropPanic {
    type Output = kasumi_types::drain::DrainResult;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        std::panic::resume_unwind(self.poll_panic.take().expect("one original poll"));
    }
}
impl Drop for PollThenDropPanic {
    fn drop(&mut self) {
        std::panic::resume_unwind(self.drop_panic.take().expect("one original destructor"));
    }
}
fn panic_address(original: &(dyn Any + Send)) -> usize {
    original.downcast_ref::<OriginalPanic>().unwrap() as *const _ as usize
}

#[tokio::test]
async fn original_recovery_cleanup_keeps_original_return_and_second_original_disposal_panic() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let inventory =
        OriginalRecoveries::new(&admission, OriginalRecoveryParticipants::one("tenant")).unwrap();
    let mut guard = inventory.seat(0).await;
    guard.failure = Some(anyhow::anyhow!("original body").into());
    let mut report = DrainReport::default();
    let issue = report.record(
        "actual cleanup",
        0,
        anyhow::anyhow!("independent returned cleanup"),
    );
    let returned = DrainFailure::retained(issue.clone());
    let original_panic: Box<dyn Any + Send> = Box::new(OriginalPanic(11));
    let address = panic_address(original_panic.as_ref());
    let seat = &mut *guard;
    observe_cleanup(
        &mut seat.retired_observation,
        &mut seat.failure.as_mut().unwrap().retired_cleanup,
        ReturnedThenDropPanic {
            original: Some(returned),
            drop_panic: Some(original_panic),
        },
    )
    .await;
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &issue,
        &seat
            .failure
            .as_ref()
            .unwrap()
            .retired_cleanup
            .as_ref()
            .unwrap()
            .issues()[0]
    ));
    assert_eq!(seat.retired_observation.entry(), CleanupEntry::Returned);
    assert_eq!(
        seat.retired_observation.future_disposal(),
        CleanupEntry::Panicked
    );
    assert_eq!(
        seat.retired_observation.with_disposal_panic(panic_address),
        Some(address)
    );
    assert_eq!(
        seat.retired_observation
            .with_disposal_panic(|original| original.downcast_ref::<OriginalPanic>().unwrap().0),
        Some(11)
    );
    assert!(!seat.native_free_failure());
    drop(guard);
    assert!(inventory.retained().await);
}

#[tokio::test]
async fn original_recovery_cleanup_keeps_both_original_poll_and_disposal_panics_without_replay() {
    let mut observation = CleanupObservation::default();
    let mut returned = None;
    let first: Box<dyn Any + Send> = Box::new(OriginalPanic(21));
    let second: Box<dyn Any + Send> = Box::new(OriginalPanic(22));
    let addresses = (
        panic_address(first.as_ref()),
        panic_address(second.as_ref()),
    );
    observe_cleanup(
        &mut observation,
        &mut returned,
        PollThenDropPanic {
            poll_panic: Some(first),
            drop_panic: Some(second),
        },
    )
    .await;
    assert!(returned.is_none());
    assert_eq!(observation.entry(), CleanupEntry::Panicked);
    assert_eq!(observation.future_disposal(), CleanupEntry::Panicked);
    assert_eq!(observation.with_panic(panic_address), Some(addresses.0));
    assert_eq!(
        observation.with_disposal_panic(panic_address),
        Some(addresses.1)
    );
    let calls = AtomicUsize::new(0);
    observe_cleanup(&mut observation, &mut returned, async {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(observation.with_panic(panic_address), Some(addresses.0));
}

#[tokio::test]
async fn original_recovery_cancelled_cleanup_retains_entered_original_seat_and_same_charge() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let inventory =
        OriginalRecoveries::new(&admission, OriginalRecoveryParticipants::one("tenant")).unwrap();
    let charged = admission.snapshot();
    let mut guard = inventory.seat(0).await;
    guard.failure = Some(anyhow::anyhow!("original before cancellation").into());
    let seat = &mut *guard;
    {
        let mut future = std::pin::pin!(observe_cleanup(
            &mut seat.retired_observation,
            &mut seat.failure.as_mut().unwrap().retired_cleanup,
            std::future::pending()
        ));
        std::future::poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    assert_eq!(seat.retired_observation.entry(), CleanupEntry::Entered);
    assert_eq!(
        seat.retired_observation.future_disposal(),
        CleanupEntry::NotEntered
    );
    assert!(seat.failure.as_ref().unwrap().retired_cleanup.is_none());
    drop(guard);
    assert!(inventory.retained().await);
    drop(inventory);
    assert_eq!(admission.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        charged.live_reservations
    );
}

#[test]
fn original_recovery_concurrent_final_aliases_retire_exact_controls_once_before_refund() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let before = admission.snapshot();
    let watching = Watch::begin();
    let inventory =
        OriginalRecoveries::new(&admission, OriginalRecoveryParticipants::one("tenant")).unwrap();
    let addresses = actual_addresses(&inventory);
    let charged = admission.snapshot().reserved_bytes;
    let address_watch = AddressWatch::begin(addresses);
    let count = watching.snapshot().count;
    let other = inventory.clone();
    assert_eq!(watching.snapshot().count, count);
    let barrier = std::sync::Barrier::new(2);
    let observations = std::thread::scope(|scope| {
        let drop_one = |inventory: OriginalRecoveries| {
            REFUND_EXPECTATION
                .with(|expected| *expected.borrow_mut() = Some((admission.clone(), addresses[1])));
            REFUND_OBSERVATION.with(|observed| observed.set(None));
            barrier.wait();
            drop(inventory);
            let observed = REFUND_OBSERVATION.with(Cell::get);
            REFUND_EXPECTATION.with(|expected| expected.borrow_mut().take());
            observed
        };
        let left = scope.spawn(move || drop_one(inventory));
        let right = scope.spawn(move || drop_one(other));
        [left.join().unwrap(), right.join().unwrap()]
    });
    assert_eq!(
        observations.iter().flatten().count(),
        1,
        "one actual final grant retirement"
    );
    assert_eq!(
        observations.into_iter().flatten().next(),
        Some((true, charged))
    );
    assert_eq!(address_watch.counts(), [1, 1, 1, 1, 1, 0, 0, 0]);
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        before.live_reservations
    );
    assert!(!watching.finish().overflow);
}

#[tokio::test]
async fn original_recovery_rpc_policy_seats_allow_independent_work_and_inline_refusal() {
    use kasumi_store::ScratchAdmissionRefusal;
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let inventory =
        OriginalRecoveries::new(&admission, OriginalRecoveryParticipants::one("tenant")).unwrap();
    let charged = admission.snapshot();
    let count = admission.policy().max_inflight_operations;
    assert_eq!(inventory.state().rpc.as_ref().unwrap().len(), count);
    let mut loans = Vec::with_capacity(count);
    let watching = Watch::begin();
    for index in 0..count {
        let loan = inventory.rpc_claim("tenant").await.unwrap();
        assert_eq!(loan.index, index);
        loans.push(loan);
    }
    let recovery = inventory.claim(0).await;
    assert!(
        recovery.is_empty(),
        "RPC loans do not serialize recovery metadata"
    );
    assert!(matches!(
        inventory.rpc_claim("tenant").await,
        Err(ScratchAdmissionRefusal::Busy)
    ));
    assert!(matches!(
        inventory.rpc_claim("unknown").await,
        Err(ScratchAdmissionRefusal::Busy)
    ));
    let independent = loans.pop().unwrap();
    assert_eq!(
        independent
            .run_snapshot(async { Ok::<_, kasumi_engine::SnapshotFailure>(()) })
            .await
            .ok(),
        Some(())
    );
    let replacement = inventory.rpc_claim("tenant").await.unwrap();
    assert_eq!(replacement.index, count - 1);
    drop(replacement);
    drop(recovery);
    drop(loans);
    inventory.seal();
    assert!(matches!(
        inventory.rpc_claim("tenant").await,
        Err(ScratchAdmissionRefusal::Sealed)
    ));
    let observed = watching.finish();
    assert!(!observed.overflow);
    assert_eq!(
        observed.count, 0,
        "claim, independent success, Busy and Sealed allocate no backing"
    );
    assert!(!inventory.retained().await);
    assert_eq!(admission.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        charged.live_reservations
    );
}

#[tokio::test]
async fn original_recovery_rpc_metadata_contention_never_leaks_unentered_claim() {
    use kasumi_store::ScratchAdmissionRefusal;
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let inventory =
        OriginalRecoveries::new(&admission, OriginalRecoveryParticipants::one("tenant")).unwrap();
    let rpc = inventory.state().rpc.as_ref().unwrap();
    let mut loans = Vec::with_capacity(rpc.len() - 1);
    for _ in 1..rpc.len() {
        loans.push(inventory.rpc_claim("tenant").await.unwrap());
    }
    // The remaining last slot is contended by a real borrowed diagnostic lock.
    let metadata = rpc.last().unwrap().original.lock().await;
    let watching = Watch::begin();
    assert!(matches!(
        inventory.rpc_claim("tenant").await,
        Err(ScratchAdmissionRefusal::Busy)
    ));
    assert!(!rpc.last().unwrap().claimed.load(Ordering::SeqCst));
    assert_eq!(watching.snapshot().count, 0);
    drop(metadata);
    let reused = inventory.rpc_claim("tenant").await.unwrap();
    assert_eq!(reused.index, rpc.len() - 1);
    drop(reused);
    assert_eq!(watching.finish().count, 0);
    drop(loans);
    assert!(!inventory.retained().await);
}

#[test]
fn original_recovery_seal_census_observes_actual_pre_mutex_claim_window() {
    use kasumi_store::ScratchAdmissionRefusal;
    let _serial = CLAIM_TEST_LOCK.lock().unwrap();
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let inventory =
        OriginalRecoveries::new(&admission, OriginalRecoveryParticipants::one("tenant")).unwrap();
    let worker_inventory = inventory.clone();
    CLAIM_ENTERED.store(false, Ordering::SeqCst);
    CLAIM_RELEASE.store(false, Ordering::SeqCst);
    PAUSE_INVENTORY.store(inventory.state() as *const _ as usize, Ordering::SeqCst);
    let calls = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let mut claim = std::pin::pin!(worker_inventory.rpc_claim("tenant"));
            let result = claim
                .as_mut()
                .poll(&mut Context::from_waker(std::task::Waker::noop()));
            if matches!(result, Poll::Ready(Ok(_))) {
                calls.fetch_add(1, Ordering::SeqCst);
            }
            matches!(result, Poll::Ready(Err(ScratchAdmissionRefusal::Sealed)))
        });
        let started = std::time::Instant::now();
        while !CLAIM_ENTERED.load(Ordering::SeqCst) {
            if started.elapsed() > std::time::Duration::from_secs(10) {
                CLAIM_RELEASE.store(true, Ordering::SeqCst);
                panic!("actual claim did not reach the pre-mutex checkpoint");
            }
            std::thread::yield_now();
        }
        inventory.seal();
        // Poll census synchronously: the real claimed reservation must make it
        // Ready(true) without waiting for a mutex or fabricating an original.
        let mut retained = std::pin::pin!(inventory.retained());
        let observed = retained
            .as_mut()
            .poll(&mut Context::from_waker(std::task::Waker::noop()));
        CLAIM_RELEASE.store(true, Ordering::SeqCst);
        assert!(matches!(observed, Poll::Ready(true)));
        assert!(worker.join().unwrap());
    });
    PAUSE_INVENTORY.store(0, Ordering::SeqCst);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "sealed constructor never entered"
    );
    let mut retained = std::pin::pin!(inventory.retained());
    assert!(matches!(
        retained
            .as_mut()
            .poll(&mut Context::from_waker(std::task::Waker::noop())),
        Poll::Ready(false)
    ));
}

struct PendingRpcBody {
    _actual_lease: kasumi_engine::admission::Reservation,
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}
impl Future for PendingRpcBody {
    type Output = Result<(), kasumi_engine::SnapshotFailure>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}
impl Drop for PendingRpcBody {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn original_recovery_cancelled_rpc_body_keeps_entered_custody_and_same_inventory_charge() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let polls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let inventory =
        OriginalRecoveries::new(&admission, OriginalRecoveryParticipants::one("tenant")).unwrap();
    let charged = admission.snapshot();
    let body = PendingRpcBody {
        _actual_lease: admission
            .memory()
            .reserve_resident(std::mem::size_of::<usize>() as u64)
            .unwrap(),
        polls: polls.clone(),
        drops: drops.clone(),
    };
    let guard = inventory.rpc_claim("tenant").await.unwrap();
    let index = guard.index;
    let array = inventory.state().rpc.as_ref().unwrap().as_ptr() as usize;
    let watching = Watch::begin();
    {
        let mut work = std::pin::pin!(guard.run_snapshot(body));
        std::future::poll_fn(|cx| {
            assert!(work.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    inventory
        .with_rpc_report(index, |report| {
            assert!(
                report.original().is_none(),
                "cancellation fabricates no returned original"
            );
            assert_eq!(report.observation().entry(), CleanupEntry::Entered);
            assert_eq!(
                report.observation().future_disposal(),
                CleanupEntry::Returned
            );
        })
        .unwrap();
    let replacement = inventory.rpc_claim("tenant").await.unwrap();
    assert_ne!(
        replacement.index, index,
        "entered unknown seat cannot be reused"
    );
    drop(replacement);
    assert_eq!(watching.finish().count, 0);
    assert!(inventory.retained().await);
    assert_eq!(
        polls.load(Ordering::SeqCst),
        1,
        "entered producer is never replayed"
    );
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "actual future destruction was observed"
    );
    // Its concrete ordinary input credit actually retired. That observation
    // proves no native body settlement, so the original inventory stays held.
    assert_eq!(admission.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        charged.live_reservations
    );
    let address_watch = AddressWatch::begin([array, 0, 0, 0, 0, 0, 0, 0]);
    drop(inventory);
    assert_eq!(
        address_watch.counts(),
        [0; 8],
        "unknown metadata backing remains retained"
    );
    assert_eq!(admission.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        charged.live_reservations
    );
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

struct ReadyRpcThenDropPanic<T> {
    original: Option<T>,
    panic: Option<Box<dyn Any + Send>>,
}
impl<T: Unpin> Future for ReadyRpcThenDropPanic<T> {
    type Output = Result<T, kasumi_engine::SnapshotFailure>;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(self.original.take().expect("one original result")))
    }
}
impl<T> Drop for ReadyRpcThenDropPanic<T> {
    fn drop(&mut self) {
        std::panic::resume_unwind(self.panic.take().expect("one original destructor panic"));
    }
}

#[tokio::test]
async fn original_recovery_rpc_ready_output_keeps_actual_backing_and_original_disposal_panic() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let inventory =
        OriginalRecoveries::new(&admission, OriginalRecoveryParticipants::one("tenant")).unwrap();
    let charged = admission.snapshot();
    // This is preexisting producer output. The inventory quotes its inline
    // custody lane; this control does not certify producer buffer funding.
    let watching = Watch::begin();
    let original = b"exact completed producer output".to_vec();
    let address = original.as_ptr() as usize;
    let original_panic: Box<dyn Any + Send> = Box::new(OriginalPanic(41));
    let panic = panic_address(original_panic.as_ref());
    let guard = inventory.rpc_claim("tenant").await.unwrap();
    let index = guard.index;
    let guard = guard
        .run_snapshot(ReadyRpcThenDropPanic {
            original: Some(original),
            panic: Some(original_panic),
        })
        .await
        .err()
        .expect("retained original output and panic");
    guard.with_report(|report| {
        assert!(report.original().is_none(), "no invented body error");
        match report.output().unwrap() {
            RpcOutput::Encoded(original) => {
                assert_eq!(original.as_ptr() as usize, address);
                assert_eq!(original, b"exact completed producer output");
            }
            _ => panic!("unchanged original encoded result"),
        }
        assert_eq!(report.observation().entry(), CleanupEntry::Returned);
        assert_eq!(
            report.observation().future_disposal(),
            CleanupEntry::Panicked
        );
        assert_eq!(
            report.observation().with_disposal_panic(panic_address),
            Some(panic)
        );
    });
    drop(guard);
    assert!(inventory.retained().await);
    assert!(
        inventory
            .with_rpc_report(index, |report| report.output().is_some())
            .unwrap()
    );
    drop(inventory);
    assert!(!watching.finish().allocation(address).unwrap().freed);
    assert_eq!(admission.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        charged.live_reservations
    );
}

#[tokio::test]
async fn original_recovery_rpc_uuid_output_handoff_and_inline_scalar_error_use_same_paid_lane() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let inventory =
        OriginalRecoveries::new(&admission, OriginalRecoveryParticipants::one("tenant")).unwrap();
    let charged = admission.snapshot();
    let original = uuid::Uuid::from_u128(123);
    let watching = Watch::begin();
    let guard = inventory.rpc_claim("tenant").await.unwrap();
    assert_eq!(
        guard
            .run_snapshot(async { Ok::<_, kasumi_engine::SnapshotFailure>(original) })
            .await
            .ok(),
        Some(original)
    );
    for refusal in [
        kasumi_store::ScratchAdmissionRefusal::Busy,
        kasumi_store::ScratchAdmissionRefusal::Sealed,
    ] {
        let guard = inventory.rpc_claim("tenant").await.unwrap();
        let failure = guard
            .run_snapshot(async {
                Err::<(), _>(kasumi_engine::SnapshotFailure::AdmissionRefused(refusal))
            })
            .await
            .err()
            .unwrap();
        assert_eq!(
            failure.with_original(kasumi_engine::SnapshotFailure::admission_refusal),
            Some(Some(refusal))
        );
        failure.with_report(|report| {
            assert_eq!(report.observation().entry(), CleanupEntry::Returned);
            assert_eq!(
                report.observation().future_disposal(),
                CleanupEntry::Returned
            );
        });
        drop(failure);
    }
    assert_eq!(
        watching.finish().count,
        0,
        "closed output and scalar handoff allocate no diagnostic shell"
    );
    assert!(!inventory.retained().await);
    assert_eq!(admission.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        charged.live_reservations
    );
}

struct NeverPolledRpcDropPanic {
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    original: Option<Box<dyn Any + Send>>,
}
impl Future for NeverPolledRpcDropPanic {
    type Output = Result<(), kasumi_engine::SnapshotFailure>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}
impl Drop for NeverPolledRpcDropPanic {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        std::panic::resume_unwind(self.original.take().unwrap());
    }
}

#[tokio::test]
async fn original_recovery_rpc_pre_first_poll_disposal_keeps_original_panic_without_body_entry() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let inventory =
        OriginalRecoveries::new(&admission, OriginalRecoveryParticipants::one("tenant")).unwrap();
    let charged = admission.snapshot();
    let polls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let original: Box<dyn Any + Send> = Box::new(OriginalPanic(51));
    let address = panic_address(original.as_ref());
    let guard = inventory.rpc_claim("tenant").await.unwrap();
    let index = guard.index;
    let watching = Watch::begin();
    let work = guard.run_snapshot(NeverPolledRpcDropPanic {
        polls: polls.clone(),
        drops: drops.clone(),
        original: Some(original),
    });
    assert_eq!(
        watching.snapshot().count,
        0,
        "inline synchronous custody allocates no wrapper"
    );
    drop(work);
    inventory
        .with_rpc_report(index, |report| {
            assert!(report.original().is_none());
            assert!(report.output().is_none());
            assert_eq!(report.observation().entry(), CleanupEntry::NotEntered);
            assert_eq!(
                report.observation().future_disposal(),
                CleanupEntry::Panicked
            );
            assert_eq!(
                report.observation().with_disposal_panic(panic_address),
                Some(address)
            );
        })
        .unwrap();
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(inventory.retained().await);
    drop(inventory);
    assert_eq!(admission.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        charged.live_reservations
    );
    assert!(!watching.finish().overflow);
}
