//! Protocol tests use the real admitted slot and real publisher machinery.
//! Native/source effects and canceled workers are exercised by Engine's fixtures.
use super::*;
use crate::{
    ApplyObservationRef as O, CompletionAction, CompletionBinding, CompletionCustody,
    CompletionFinalization, CompletionIdentity, CompletionInvocation, CompletionSettleError,
    CompletionVerdict, RetainedApplyReport,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

struct Control {
    identity: CompletionIdentity,
    settled: AtomicUsize,
    failed: AtomicBool,
    drained: AtomicBool,
    drain_panic: AtomicBool,
}
struct Binding(Arc<Control>);
impl CompletionCustody for Binding {
    fn identity(&self) -> &CompletionIdentity {
        &self.0.identity
    }
    fn settle(
        &self,
        finalization: CompletionFinalization<'_>,
    ) -> Result<(), CompletionSettleError> {
        finalization
            .require_identity(&self.0.identity)
            .map_err(|_| CompletionSettleError::Foreign)?;
        self.0.settled.fetch_add(1, Ordering::SeqCst);
        if finalization.verdict() == CompletionVerdict::Failed {
            self.0.failed.store(true, Ordering::SeqCst);
            return Err(CompletionSettleError::Retained);
        }
        Ok(())
    }
    fn poll_drain(&self, _: &mut Context<'_>) -> Poll<Result<(), CompletionSettleError>> {
        if self.0.drain_panic.load(Ordering::SeqCst) {
            std::panic::panic_any(Arc::clone(&self.0))
        }
        self.0.drained.store(true, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
    fn is_drained(&self) -> bool {
        self.0.drained.load(Ordering::SeqCst)
    }
}
fn owner() -> (crate::apply_failure::ApplyFailureSlot, Arc<Control>) {
    let control = Arc::new(Control {
        identity: CompletionIdentity::new(),
        settled: AtomicUsize::new(0),
        failed: AtomicBool::new(false),
        drained: AtomicBool::new(false),
        drain_panic: AtomicBool::new(false),
    });
    let slot = crate::apply_failure::ApplyFailureSlot::new(Arc::new(()));
    assert!(
        slot.completion()
            .bind(CompletionBinding::new(Binding(control.clone())))
            .is_ok()
    );
    (slot, control)
}
struct SinkCount(usize);
impl PublicationSink for SinkCount {
    fn plain(&mut self, _: &AppliedResponse, _: &[WriteOp]) -> SinkResult<()> {
        self.0 += 1;
        Ok(())
    }
    fn selected<'call>(
        &mut self,
        _: &AppliedResponse,
        _: &[WriteOp],
        _: &mut dyn SelectionPreparer,
        _: PublicationChallenge<'call>,
    ) -> SinkResult<JointPublicationReceipt<'call>> {
        Err(anyhow::anyhow!("plain protocol fixture").into())
    }
}
struct Commit;
impl CompletionAction for Commit {
    fn run(
        &mut self,
        _: &CompletionInvocation<'_>,
        publisher: &mut dyn ApplyPublisher,
    ) -> Result<()> {
        publisher.commit(AppliedResponse::application(vec![7, 9]), &[])?;
        Ok(())
    }
}
fn failed(
    result: std::result::Result<FinishedPublication, FinishFailure>,
) -> crate::apply_failure::RetainedApplyFailure {
    match result {
        Err(FinishFailure::Retained(failure)) => failure,
        _ => panic!("expected retained ordinary failure"),
    }
}
#[test]
fn completion_success_transfers_response_before_reset_and_reuses_real_slot() {
    let (slot, control) = owner();
    let mut sink = SinkCount(0);
    for ordinal in 1..=2 {
        let mut publication = ApplyPublication::new_bound(&mut sink, &slot);
        assert!(
            publication
                .with_completion(&control.identity, &mut Commit)
                .is_ok()
        );
        let finished = match publication.finish_observed(Ok(Ok(())), || {}) {
            Ok(finished) => finished,
            _ => panic!("finish"),
        };
        assert_eq!(finished.response.data, [7, 9]);
        assert!(slot.completion().unsettled());
        assert_eq!(control.settled.load(Ordering::SeqCst), ordinal);
        let FinishedPublication {
            response,
            acknowledgment,
        } = finished;
        let output = response.data;
        acknowledge_publication(acknowledgment);
        assert_eq!(output, [7, 9]);
        assert!(!slot.completion().unsettled());
        assert!(slot.failure().is_none());
    }
    assert_eq!(sink.0, 2);
}
struct Recursive<'a>(&'a CompletionIdentity);
impl CompletionAction for Recursive<'_> {
    fn run(
        &mut self,
        _: &CompletionInvocation<'_>,
        publisher: &mut dyn ApplyPublisher,
    ) -> Result<()> {
        publisher.commit(AppliedResponse::application(vec![11]), &[])?;
        assert_eq!(
            publisher.with_completion(self.0, &mut Commit),
            Err(crate::CompletionCallError::Recorded)
        );
        Ok(())
    }
}
#[test]
fn swallowed_recursive_completion_retains_response_and_sticky_failure() {
    let (slot, control) = owner();
    let mut sink = SinkCount(0);
    let mut publication = ApplyPublication::new_bound(&mut sink, &slot);
    assert_eq!(
        publication.with_completion(&control.identity, &mut Recursive(&control.identity)),
        Err(crate::CompletionCallError::Recorded)
    );
    let failure = failed(publication.finish_observed(Ok(Ok(())), || {}));
    failure
        .try_with_report(|report| {
            let RetainedApplyReport::Ordinary(report) = report else {
                panic!("ordinary")
            };
            assert_eq!(report.violation, Some(crate::CompletionViolation::Repeated));
            assert_eq!(report.response.unwrap().data, [11]);
            assert!(matches!(report.sink, O::Returned));
            assert!(matches!(report.action, O::Returned));
            assert!(matches!(
                report.cleanup,
                O::Refused(CompletionSettleError::Retained)
            ));
        })
        .unwrap();
    assert_eq!(sink.0, 1);
}
#[test]
fn late_completion_after_plain_commit_cannot_acknowledge_or_drop_response() {
    let (slot, control) = owner();
    let mut sink = SinkCount(0);
    let mut publication = ApplyPublication::new_bound(&mut sink, &slot);
    publication
        .commit(AppliedResponse::application(vec![13]), &[])
        .unwrap();
    assert_eq!(
        publication.with_completion(&control.identity, &mut Commit),
        Err(crate::CompletionCallError::Recorded)
    );
    let failure = failed(publication.finish_observed(Ok(Ok(())), || {}));
    failure
        .try_with_report(|report| {
            let RetainedApplyReport::Ordinary(report) = report else {
                panic!("ordinary")
            };
            assert_eq!(report.violation, Some(crate::CompletionViolation::Repeated));
            assert_eq!(report.response.unwrap().data, [13]);
            assert!(matches!(report.action, O::NotEntered));
        })
        .unwrap();
    assert_eq!(sink.0, 1);
}
#[derive(Debug)]
struct Original(u64);
impl std::fmt::Display for Original {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original {}", self.0)
    }
}
impl std::error::Error for Original {}
#[test]
fn backend_error_precedes_finish_panic_and_both_survive_caller_drop() {
    let (slot, control) = owner();
    let mut sink = SinkCount(0);
    let original: anyhow::Error = Original(17).into();
    let pointer = original.downcast_ref::<Original>().unwrap() as *const _;
    let panic = Arc::new(19u64);
    let thrown = panic.clone();
    let mut publication = ApplyPublication::new_bound(&mut sink, &slot);
    publication
        .with_completion(&control.identity, &mut Commit)
        .unwrap();
    let returned =
        failed(publication.finish_observed(Ok(Err(original)), || std::panic::panic_any(thrown)));
    drop(returned);
    slot.failure()
        .unwrap()
        .try_with_report(|report| {
            let RetainedApplyReport::Ordinary(report) = report else {
                panic!("ordinary")
            };
            let O::Error(error) = report.backend else {
                panic!("backend")
            };
            assert_eq!(
                error.downcast_ref::<Original>().unwrap() as *const _,
                pointer
            );
            let O::Unwound(payload) = report.finish else {
                panic!("finish")
            };
            assert!(Arc::ptr_eq(
                payload.downcast_ref::<Arc<u64>>().unwrap(),
                &panic
            ));
            assert!(report.response.is_some());
            assert!(matches!(report.cleanup, O::NotEntered));
        })
        .unwrap();
    assert_eq!(control.settled.load(Ordering::SeqCst), 0);
}
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
#[test]
fn borrowed_report_contention_wakes_drain_and_keeps_single_plus_lifecycle_original() {
    let (slot, control) = owner();
    let original: anyhow::Error = Original(23).into();
    let pointer = original.downcast_ref::<Original>().unwrap() as *const _;
    slot.retain(original).unwrap();
    control.drain_panic.store(true, Ordering::SeqCst);
    let wake = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(wake.clone());
    let mut cx = Context::from_waker(&waker);
    // First create real terminal completion failure from the actual drain callback.
    assert!(slot.completion().poll_drain(&mut cx).is_ready());
    let failure = slot.failure().unwrap();
    failure
        .try_with_report(|report| {
            let RetainedApplyReport::Ordinary(report) = report else {
                panic!("ordinary")
            };
            assert_eq!(
                report.single.unwrap().downcast_ref::<Original>().unwrap() as *const _,
                pointer
            );
            let O::Unwound(payload) = report.drain else {
                panic!("drain panic")
            };
            assert!(Arc::ptr_eq(
                payload.downcast_ref::<Arc<Control>>().unwrap(),
                &control
            ));
        })
        .unwrap();
    // Distinct active owner demonstrates report contention, no synthetic busy flag.
    let (other, other_control) = owner();
    other.completion().begin(&other_control.identity).unwrap();
    other.completion().repeated();
    other
        .failure()
        .unwrap()
        .try_with_report(|_| {
            assert!(other.completion().poll_drain(&mut cx).is_pending());
        })
        .unwrap();
    assert_eq!(wake.0.load(Ordering::SeqCst), 1);
    assert!(other.completion().poll_drain(&mut cx).is_ready());
    assert!(other.completion().drained());
}

struct FailingSink(Option<anyhow::Error>);
impl PublicationSink for FailingSink {
    fn plain(&mut self, response: &AppliedResponse, _: &[WriteOp]) -> SinkResult<()> {
        assert_eq!(response.data, [29]);
        Err(self.0.take().unwrap().into())
    }
    fn selected<'call>(
        &mut self,
        _: &AppliedResponse,
        _: &[WriteOp],
        _: &mut dyn SelectionPreparer,
        _: PublicationChallenge<'call>,
    ) -> SinkResult<JointPublicationReceipt<'call>> {
        unreachable!("plain fixture")
    }
}
struct SwallowThenPanic(Arc<u64>);
impl CompletionAction for SwallowThenPanic {
    fn run(
        &mut self,
        _: &CompletionInvocation<'_>,
        publisher: &mut dyn ApplyPublisher,
    ) -> Result<()> {
        assert_eq!(
            publisher.commit(AppliedResponse::application(vec![29]), &[]),
            Err(PublishCallError::Failed)
        );
        std::panic::panic_any(self.0.clone())
    }
}
#[test]
fn sink_original_and_action_panic_remain_independent_after_swallowed_notification() {
    let (slot, control) = owner();
    let original: anyhow::Error = Original(31).into();
    let pointer = original.downcast_ref::<Original>().unwrap() as *const _;
    let mut sink = FailingSink(Some(original));
    let panic = Arc::new(37u64);
    let mut publication = ApplyPublication::new_bound(&mut sink, &slot);
    assert_eq!(
        publication.with_completion(&control.identity, &mut SwallowThenPanic(panic.clone())),
        Err(crate::CompletionCallError::Recorded)
    );
    let failure = failed(publication.finish_observed(Ok(Ok(())), || {}));
    failure
        .try_with_report(|report| {
            let RetainedApplyReport::Ordinary(report) = report else {
                panic!("ordinary")
            };
            let O::Error(error) = report.sink else {
                panic!("sink")
            };
            assert_eq!(
                error.downcast_ref::<Original>().unwrap() as *const _,
                pointer
            );
            let O::Unwound(payload) = report.action else {
                panic!("action")
            };
            assert!(Arc::ptr_eq(
                payload.downcast_ref::<Arc<u64>>().unwrap(),
                &panic
            ));
            assert_eq!(report.response.unwrap().data, [29]);
            assert!(matches!(report.backend, O::Returned));
        })
        .unwrap();
}

#[test]
fn opaque_sink_error_stays_owned_after_positive_completion_drain() {
    struct Swallow;
    impl CompletionAction for Swallow {
        fn run(
            &mut self,
            _: &CompletionInvocation<'_>,
            publisher: &mut dyn ApplyPublisher,
        ) -> Result<()> {
            assert_eq!(
                publisher.commit(AppliedResponse::application(vec![29]), &[]),
                Err(PublishCallError::Failed)
            );
            Ok(())
        }
    }
    let (slot, control) = owner();
    assert!(!slot.failure_ownership_drained());
    let original: anyhow::Error = Original(41).into();
    let pointer = original.downcast_ref::<Original>().unwrap() as *const _;
    // Identical words in an arbitrary context are never a trusted disposition.
    let original = original.context(
        "domain transaction committed; access expired before acknowledgment; outcome unknown",
    );
    let mut sink = FailingSink(Some(original));
    let mut publication = ApplyPublication::new_bound(&mut sink, &slot);
    assert_eq!(
        publication.with_completion(&control.identity, &mut Swallow),
        Err(crate::CompletionCallError::Recorded)
    );
    let failure = failed(publication.finish_observed(Ok(Ok(())), || {}));
    assert!(!slot.failure_ownership_drained());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(slot.completion().poll_drain(&mut cx).is_ready());
    assert!(slot.completion().drained());
    assert!(slot.completion().failed());
    assert!(slot.completion().unsettled());
    assert!(!slot.failure_ownership_drained());
    failure
        .try_with_report(|report| {
            let RetainedApplyReport::Ordinary(report) = report else {
                panic!("ordinary failure");
            };
            let O::Error(original) = report.sink else {
                panic!("sink original absent");
            };
            assert_eq!(
                original.downcast_ref::<Original>().unwrap() as *const _,
                pointer
            );
            assert!(matches!(report.action, O::Returned));
            assert!(matches!(report.backend, O::Returned));
            assert!(matches!(report.finish, O::Returned));
            assert!(matches!(
                report.cleanup,
                O::Refused(CompletionSettleError::Retained)
            ));
            assert!(matches!(report.drain, O::Returned));
            assert!(report.response.is_some());
        })
        .unwrap();
}
