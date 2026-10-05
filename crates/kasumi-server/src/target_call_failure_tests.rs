//! Actual producer poll, destruction, cancellation, and output custody.
use super::*;
use crate::{
    recovery_allocation_watch::Watch,
    target_runtime::target_call_jobs::{TargetCallJobs, TestReply},
};
use kasumi_engine::admission::NodeAdmission;
use kasumi_types::drain::DrainCompletion;
use std::{sync::atomic::AtomicUsize, time::Duration};

struct PanicOriginal {
    _charge: Reservation,
    stage: &'static str,
    dropped: Arc<AtomicUsize>,
}
impl Drop for PanicOriginal {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
fn panic_original(
    admission: &Arc<NodeAdmission>,
    stage: &'static str,
    dropped: &Arc<AtomicUsize>,
) -> (Box<dyn std::any::Any + Send>, usize) {
    let original = Box::new(PanicOriginal {
        _charge: admission
            .reserve_resident(std::mem::size_of::<PanicOriginal>() as u64)
            .unwrap(),
        stage,
        dropped: dropped.clone(),
    });
    let address = &*original as *const PanicOriginal as usize;
    (original, address)
}
fn panic_address(original: &(dyn std::any::Any + Send), stage: &str) -> usize {
    let original = original.downcast_ref::<PanicOriginal>().unwrap();
    assert_eq!(original.stage, stage);
    original as *const PanicOriginal as usize
}

struct ActualProducer<T> {
    returned: Option<Result<T, SnapshotFailure>>,
    poll_panic: Option<Box<dyn std::any::Any + Send>>,
    disposal_panic: Option<Box<dyn std::any::Any + Send>>,
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}
impl<T: Unpin> Future for ActualProducer<T> {
    type Output = Result<T, SnapshotFailure>;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if let Some(original) = self.poll_panic.take() {
            std::panic::resume_unwind(original);
        }
        match self.returned.take() {
            Some(original) => Poll::Ready(original),
            None => Poll::Pending,
        }
    }
}
impl<T> Drop for ActualProducer<T> {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        if let Some(original) = self.disposal_panic.take() {
            std::panic::resume_unwind(original);
        }
    }
}
fn producer<T>(
    returned: Option<Result<T, SnapshotFailure>>,
    poll_panic: Option<Box<dyn std::any::Any + Send>>,
    disposal_panic: Option<Box<dyn std::any::Any + Send>>,
) -> (ActualProducer<T>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let polls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    (
        ActualProducer {
            returned,
            poll_panic,
            disposal_panic,
            polls: polls.clone(),
            drops: drops.clone(),
        },
        polls,
        drops,
    )
}
#[derive(Debug)]
struct ContextOwner(Arc<AtomicUsize>);
impl std::fmt::Display for ContextOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("actual original IO context")
    }
}
impl Drop for ContextOwner {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn outer_address(original: &anyhow::Error) -> usize {
    let original: &(dyn std::error::Error + Send + Sync + 'static) = original.as_ref();
    original as *const _ as *const () as usize
}

#[tokio::test]
async fn ready_original_is_staged_before_independent_future_disposal_panic() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let jobs = TargetCallJobs::new(&admission).unwrap();
    let context_drops = Arc::new(AtomicUsize::new(0));
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let io = std::fs::metadata(directory.path().join("absent-actual-original")).unwrap_err();
    let original = anyhow::Error::new(io).context(ContextOwner(context_drops.clone()));
    let address = outer_address(&original);
    let panic_drops = Arc::new(AtomicUsize::new(0));
    let (disposal, disposal_address) = panic_original(&admission, "future", &panic_drops);
    let charged = admission.snapshot().reserved_bytes;
    let seat = jobs.acquire_failure().unwrap();
    seat.accepted();
    let (work, polls, drops) = producer::<()>(
        Some(Err(SnapshotFailure::Source(original))),
        None,
        Some(disposal),
    );
    let failure = seat.begin().unwrap().run(work).await.unwrap_err();
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(failure.marker().code, ErrorCode::UnknownOutcome);
    let inspect = |report: Option<TargetCallReport<'_>>| {
        let report = report.unwrap();
        assert!(report.body_returned());
        assert!(!report.future_disposal_returned());
        assert!(!report.has_output());
        assert!(report.with_body_panic(|_| ()).is_none());
        assert_eq!(
            outer_address(report.original().unwrap().source_error().unwrap()),
            address
        );
        assert_eq!(
            report.with_future_disposal_panic(|original| panic_address(original, "future")),
            Some(disposal_address)
        );
    };
    failure.with_report(inspect);
    assert!(seat.begin().is_err());
    failure.with_report(inspect);
    drop(failure);
    drop(seat);
    let retained = jobs.original_failure(0).unwrap();
    retained.with_report(inspect);
    drop(retained);
    drop(jobs);
    assert_eq!(context_drops.load(Ordering::SeqCst), 0);
    assert_eq!(panic_drops.load(Ordering::SeqCst), 0);
    assert_eq!(admission.snapshot().reserved_bytes, charged);
}

#[tokio::test]
async fn actual_poll_and_future_disposal_panics_keep_both_original_allocations() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let jobs = TargetCallJobs::new(&admission).unwrap();
    let panic_drops = Arc::new(AtomicUsize::new(0));
    let (poll, poll_address) = panic_original(&admission, "poll", &panic_drops);
    let (disposal, disposal_address) = panic_original(&admission, "future", &panic_drops);
    let seat = jobs.acquire_failure().unwrap();
    seat.accepted();
    let (work, polls, drops) = producer::<()>(None, Some(poll), Some(disposal));
    let failure = seat.begin().unwrap().run(work).await.unwrap_err();
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    failure.with_report(|report| {
        let report = report.unwrap();
        assert!(report.body_entered());
        assert!(!report.body_returned());
        assert!(!report.future_disposal_returned());
        assert!(report.original().is_none());
        assert_eq!(
            report.with_body_panic(|original| panic_address(original, "poll")),
            Some(poll_address)
        );
        assert_eq!(
            report.with_future_disposal_panic(|original| panic_address(original, "future")),
            Some(disposal_address)
        );
    });
    assert_eq!(failure.marker().code, ErrorCode::UnknownOutcome);
    assert!(seat.begin().is_err());
    drop(failure);
    drop(seat);
    drop(jobs);
    assert_eq!(panic_drops.load(Ordering::SeqCst), 0);
}

#[test]
fn before_first_poll_disposal_panic_keeps_body_unentered_and_same_loan_sticky() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let jobs = TargetCallJobs::new(&admission).unwrap();
    let panic_drops = Arc::new(AtomicUsize::new(0));
    let (disposal, address) = panic_original(&admission, "future", &panic_drops);
    let seat = jobs.acquire_failure().unwrap();
    let (work, polls, drops) = producer::<()>(None, None, Some(disposal));
    let run = seat.begin().unwrap().run(work);
    drop(run);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    let failure = jobs.original_failure(0).unwrap();
    failure.with_report(|report| {
        let report = report.unwrap();
        assert!(!report.body_entered());
        assert!(!report.body_returned());
        assert!(!report.future_disposal_returned());
        assert!(report.original().is_none());
        assert_eq!(
            report.with_future_disposal_panic(|original| panic_address(original, "future")),
            Some(address)
        );
    });
    assert!(failure.has_observed_panic());
    assert_eq!(failure.marker().code, ErrorCode::UnknownOutcome);
    assert!(seat.begin().is_err());
    drop(failure);
    drop(seat);
    drop(jobs);
    assert_eq!(panic_drops.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pending_cancellation_observes_future_drop_without_claiming_body_completion() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let baseline = admission.snapshot().reserved_bytes;
    let jobs = TargetCallJobs::new(&admission).unwrap();
    let charged = admission.snapshot().reserved_bytes;
    let seat = jobs.acquire_failure().unwrap();
    let identity = seat.identity();
    seat.accepted();
    let (work, polls, drops) = producer::<()>(None, None, None);
    let mut run = Box::pin(seat.begin().unwrap().run(work));
    std::future::poll_fn(|cx| {
        assert!(run.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(run);
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    let failure = jobs.original_failure(0).unwrap();
    failure.with_report(|report| {
        let report = report.unwrap();
        assert!(report.body_entered());
        assert!(!report.body_returned());
        assert!(report.future_disposal_returned());
        assert!(report.original().is_none());
        assert!(report.with_body_panic(|_| ()).is_none());
        assert!(report.with_future_disposal_panic(|_| ()).is_none());
    });
    assert_eq!(failure.marker().code, ErrorCode::UnknownOutcome);
    assert!(seat.begin().is_err());
    drop(failure);
    drop(seat);
    let next = jobs.acquire_failure().unwrap();
    assert_ne!(next.identity(), identity);
    drop(next);
    assert_eq!(admission.snapshot().reserved_bytes, charged);
    drop(jobs);
    assert!(charged > baseline);
    assert_eq!(admission.snapshot().reserved_bytes, charged);
}

#[tokio::test]
async fn ready_output_stays_whole_when_future_disposal_panics() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let jobs = TargetCallJobs::new(&admission).unwrap();
    let capacity = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = capacity.clone().acquire_owned().await.unwrap();
    let output_drops = Arc::new(AtomicUsize::new(0));
    let panic_drops = Arc::new(AtomicUsize::new(0));
    let (disposal, address) = panic_original(&admission, "future", &panic_drops);
    let seat = jobs.acquire_failure().unwrap();
    seat.accepted();
    let (work, _, drops) = producer(
        Some(Ok(TestReply {
            _permit: permit,
            dropped: output_drops.clone(),
            panic: None,
        })),
        None,
        Some(disposal),
    );
    let failure = seat.begin().unwrap().run(work).await.unwrap_err();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    failure.with_report(|report| {
        let report = report.unwrap();
        assert!(report.body_returned());
        assert!(!report.future_disposal_returned());
        assert!(report.has_output());
        assert!(!report.output_disposal_returned());
        assert!(report.original().is_none());
        assert_eq!(
            report.with_future_disposal_panic(|original| panic_address(original, "future")),
            Some(address)
        );
    });
    assert_eq!(failure.marker().code, ErrorCode::UnknownOutcome);
    drop(failure);
    drop(seat);
    drop(jobs);
    assert_eq!(capacity.available_permits(), 0);
    assert_eq!(output_drops.load(Ordering::SeqCst), 0);
    assert_eq!(panic_drops.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn abandoned_output_disposal_panic_is_an_independent_retained_terminal() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let jobs = TargetCallJobs::new(&admission).unwrap();
    let capacity = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = capacity.clone().acquire_owned().await.unwrap();
    let output_drops = Arc::new(AtomicUsize::new(0));
    let panic_drops = Arc::new(AtomicUsize::new(0));
    let (output_panic, address) = panic_original(&admission, "output", &panic_drops);
    let reply = TestReply {
        _permit: permit,
        dropped: output_drops.clone(),
        panic: Some(output_panic),
    };
    let submission = jobs
        .acquire_submission::<TestReply>(
            tokio::time::Instant::now() + Duration::from_secs(5),
            jobs.acquire_failure().unwrap(),
        )
        .await
        .unwrap();
    let receive = submission
        .submit::<SnapshotFailure, _>(async move { Ok(reply) })
        .unwrap();
    drop(receive.await.unwrap());
    let first = tokio::time::timeout(Duration::from_secs(5), jobs.drain())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(first.completion(), DrainCompletion::Retained);
    assert_eq!(output_drops.load(Ordering::SeqCst), 1);
    assert_eq!(capacity.available_permits(), 1);
    let failure = jobs.original_failure(0).unwrap();
    failure.with_report(|report| {
        let report = report.unwrap();
        assert!(report.body_returned());
        assert!(report.future_disposal_returned());
        assert!(!report.output_disposal_returned());
        assert!(!report.has_output());
        assert!(report.original().is_none());
        assert!(report.with_body_panic(|_| ()).is_none());
        assert!(report.with_future_disposal_panic(|_| ()).is_none());
        assert_eq!(
            report.with_output_disposal_panic(|original| panic_address(original, "output")),
            Some(address)
        );
    });
    let again = jobs.drain().await.unwrap_err();
    assert_eq!(again.completion(), DrainCompletion::Retained);
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &first.issues()[0],
        &again.issues()[0]
    ));
    drop(failure);
    drop(jobs);
    assert_eq!(output_drops.load(Ordering::SeqCst), 1);
    assert_eq!(panic_drops.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn contested_output_claim_preserves_original_and_same_seat() {
    contested_output_ticket(false).await;
}

#[tokio::test]
async fn contested_output_disposal_preserves_original_and_same_seat() {
    contested_output_ticket(true).await;
}

async fn contested_output_ticket(dispose: bool) {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let jobs = TargetCallJobs::new(&admission).unwrap();
    let charged = admission.snapshot().reserved_bytes;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let output_drops = Arc::new(AtomicUsize::new(0));
    let reply = TestReply {
        _permit: semaphore.clone().acquire_owned().await.unwrap(),
        dropped: output_drops.clone(),
        panic: None,
    };
    let seat = jobs.acquire_failure().unwrap();
    let identity = seat.identity();
    let ticket = seat
        .begin()
        .unwrap()
        .run(async move { Ok::<_, SnapshotFailure>(reply) })
        .await
        .unwrap();
    let original = jobs.original_failure(0).unwrap();
    let failure = original.with_report(|report| {
        assert!(report.unwrap().has_output());
        if dispose {
            ticket.dispose().unwrap_err()
        } else {
            match ticket.claim() {
                Ok(_) => panic!("a borrowed output report allowed a whole-output claim"),
                Err(original) => original,
            }
        }
    });
    assert!(matches!(
        &failure,
        TargetCallFailure::Retained(original) if original.identity() == identity
    ));
    assert_eq!(failure.marker().code, ErrorCode::UnknownOutcome);
    assert_eq!(output_drops.load(Ordering::SeqCst), 0);
    assert_eq!(semaphore.available_permits(), 0);
    assert_eq!(admission.snapshot().reserved_bytes, charged);
    drop(seat);
    drop(original);
    let original = jobs.original_failure(0).unwrap();
    drop(failure);
    drop(jobs);
    original.with_report(|report| {
        let report = report.unwrap();
        assert!(report.body_returned());
        assert!(report.future_disposal_returned());
        assert!(!report.output_disposal_returned());
        assert!(report.has_output());
        assert!(report.original().is_none());
        assert!(report.dispatch_error().is_none());
        assert!(report.with_body_panic(|_| ()).is_none());
        assert!(report.with_output_disposal_panic(|_| ()).is_none());
    });
    assert_eq!(output_drops.load(Ordering::SeqCst), 0);
    assert_eq!(semaphore.available_permits(), 0);
    assert_eq!(admission.snapshot().reserved_bytes, charged);
    drop(original);
    assert_eq!(output_drops.load(Ordering::SeqCst), 0);
    assert_eq!(admission.snapshot().reserved_bytes, charged);
}

#[tokio::test]
async fn successful_sequential_reuse_requires_actual_output_claim() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let jobs = TargetCallJobs::new(&admission).unwrap();
    let seat = jobs.acquire_failure().unwrap();
    let identity = seat.identity();
    let ticket = seat
        .begin()
        .unwrap()
        .run(async { Ok::<_, SnapshotFailure>(17_u64) })
        .await
        .unwrap();
    assert!(seat.begin().is_err());
    assert_eq!(ticket.claim().unwrap(), 17);
    let second = seat
        .begin()
        .unwrap()
        .run(async { Ok::<_, SnapshotFailure>(23_u64) })
        .await
        .unwrap();
    assert_eq!(second.claim().unwrap(), 23);
    drop(seat);
    let reused = jobs.acquire_failure().unwrap();
    assert_eq!(reused.identity(), identity);
    drop(reused);
    jobs.drain().await.unwrap();
}

#[tokio::test]
async fn final_success_ticket_retires_actual_controls_and_charge_only_after_claim() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let baseline = admission.snapshot().reserved_bytes;
    let watching = Watch::begin();
    let jobs = TargetCallJobs::new(&admission).unwrap();
    let charged = admission.snapshot().reserved_bytes;
    let seat = jobs.acquire_failure().unwrap();
    let state = Arc::as_ptr(&seat.0.state) as usize;
    let outcome = Arc::as_ptr(&seat.0.state.outcome) as usize;
    let observed = watching.snapshot();
    let control = |data| {
        observed.allocations[..observed.count]
            .iter()
            .copied()
            .find(|allocation| {
                allocation.address <= data && data < allocation.address + allocation.bytes
            })
            .unwrap()
    };
    let state = control(state);
    let outcome = control(outcome);
    let ticket = seat
        .begin()
        .unwrap()
        .run(async { Ok::<_, SnapshotFailure>(29_u64) })
        .await
        .unwrap();
    drop(seat);
    drop(jobs);
    assert_eq!(admission.snapshot().reserved_bytes, charged);
    assert!(!watching.snapshot().allocation(state.address).unwrap().freed);
    assert!(
        !watching
            .snapshot()
            .allocation(outcome.address)
            .unwrap()
            .freed
    );
    assert_eq!(ticket.claim().unwrap(), 29);
    let observed = watching.finish();
    assert!(!observed.overflow);
    assert!(observed.allocation(state.address).unwrap().freed);
    assert!(observed.allocation(outcome.address).unwrap().freed);
    assert_eq!(admission.snapshot().reserved_bytes, baseline);
}

#[tokio::test]
async fn outcome_guard_holds_same_charge_until_its_actual_control_alias_retires() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let baseline = admission.snapshot().reserved_bytes;
    let watching = Watch::begin();
    let jobs = TargetCallJobs::new(&admission).unwrap();
    let charged = admission.snapshot().reserved_bytes;
    let seat = jobs.acquire_failure().unwrap();
    let state = Arc::as_ptr(&seat.0.state) as usize;
    let outcome = Arc::as_ptr(&seat.0.state.outcome) as usize;
    let state_allocation = watching.snapshot().allocations[..watching.snapshot().count]
        .iter()
        .copied()
        .find(|allocation| {
            allocation.address <= state && state < allocation.address + allocation.bytes
        })
        .unwrap();
    let outcome_allocation = watching.snapshot().allocations[..watching.snapshot().count]
        .iter()
        .copied()
        .find(|allocation| {
            allocation.address <= outcome && outcome < allocation.address + allocation.bytes
        })
        .unwrap();
    assert_eq!(
        state_allocation.bytes,
        arc_layout::<State>().unwrap().size()
    );
    assert_eq!(
        outcome_allocation.bytes,
        arc_layout::<tokio::sync::Mutex<Outcome>>().unwrap().size()
    );
    let loan = seat.begin().unwrap();
    // A contended report returns no diagnosis, and another begin refuses
    // before it can accept a replacement producer or reset the actual loan.
    let report = TargetCallFailure::Retained(seat.clone());
    assert!(report.with_report(|report| report.is_none()));
    assert!(matches!(
        seat.begin(),
        Err(TargetCallFailure::Admission(ScratchAdmissionRefusal::Busy))
    ));
    drop(report);
    drop(seat);
    drop(jobs);
    assert_eq!(admission.snapshot().reserved_bytes, charged);
    drop(loan);
    let observed = watching.finish();
    assert!(!observed.overflow);
    assert!(!observed.allocation(state_allocation.address).unwrap().freed);
    assert!(
        !observed
            .allocation(outcome_allocation.address)
            .unwrap()
            .freed
    );
    assert!(charged > baseline);
    assert_eq!(admission.snapshot().reserved_bytes, charged);
}
