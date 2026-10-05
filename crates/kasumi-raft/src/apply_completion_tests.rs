//! Protocol tests use the real admitted slot and real publisher machinery.
//! Native/source effects and canceled workers are exercised by Engine's fixtures.
#[path = "apply_preparation_tests.rs"]
mod apply_preparation_tests;
#[path = "planner_refusal_tests.rs"]
mod planner_refusal_tests;
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
    action_proof: std::sync::Mutex<Option<crate::CompletionActionFailureIdentity>>,
    proof_panic: AtomicBool,
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
    fn retired_action_failure(&self) -> Option<crate::CompletionActionFailureIdentity> {
        if self.0.proof_panic.load(Ordering::SeqCst) {
            std::panic::panic_any(Arc::clone(&self.0));
        }
        *self.0.action_proof.lock().unwrap()
    }
}
fn owner() -> (crate::apply_failure::ApplyFailureSlot, Arc<Control>) {
    let control = Arc::new(Control {
        identity: CompletionIdentity::new(),
        settled: AtomicUsize::new(0),
        failed: AtomicBool::new(false),
        drained: AtomicBool::new(false),
        drain_panic: AtomicBool::new(false),
        action_proof: std::sync::Mutex::new(None),
        proof_panic: AtomicBool::new(false),
    });
    let slot =
        crate::apply_failure::ApplyFailureSlot::new(kasumi_types::SharedBudgetCharge::new(()));
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
    ) -> Result<(), kasumi_store::ScratchOperationFailure> {
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
    ) -> Result<(), kasumi_store::ScratchOperationFailure> {
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
    let returned = failed(
        publication.finish_observed(Ok(Err(original.into())), || std::panic::panic_any(thrown)),
    );
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
    ) -> Result<(), kasumi_store::ScratchOperationFailure> {
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
        ) -> Result<(), kasumi_store::ScratchOperationFailure> {
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

struct ReturnedActionError<'a> {
    control: &'a Control,
    original: &'a mut Option<anyhow::Error>,
    capture_identity: bool,
    return_error: bool,
    add_context: bool,
}
impl CompletionAction for ReturnedActionError<'_> {
    fn run(
        &mut self,
        invocation: &CompletionInvocation<'_>,
        publisher: &mut dyn ApplyPublisher,
    ) -> Result<(), kasumi_store::ScratchOperationFailure> {
        if self.capture_identity {
            *self.control.action_proof.lock().unwrap() =
                Some(invocation.action_failure_identity(self.original.as_ref().unwrap()));
        }
        publisher.commit(AppliedResponse::application(vec![53]), &[])?;
        if self.return_error {
            let original = self.original.take().unwrap();
            return Err((if self.add_context {
                original.context("same underlying cause in a different error allocation")
            } else {
                original
            })
            .into());
        }
        Ok(())
    }
}

#[test]
fn action_retirement_proof_requires_exact_allocation_binding_and_current_invocation() {
    for mode in ["exact", "context", "foreign", "old ordinal", "opaque"] {
        let (slot, control) = owner();
        let mut sink = SinkCount(0);
        let mut original: Option<anyhow::Error> = Some(Original(47).into());
        let address = original
            .as_ref()
            .unwrap()
            .downcast_ref::<Original>()
            .unwrap() as *const Original as usize;
        if matches!(mode, "foreign" | "old ordinal") {
            // The same live error allocation is observed in a real successful
            // prior action, then carried into a different binding or ordinal.
            let (other, other_control) = owner();
            let (before, binding) = if mode == "foreign" {
                (&other, &other_control)
            } else {
                (&slot, &control)
            };
            let mut publication = ApplyPublication::new_bound(&mut sink, before);
            publication
                .with_completion(
                    &binding.identity,
                    &mut ReturnedActionError {
                        control: &control,
                        original: &mut original,
                        capture_identity: true,
                        return_error: false,
                        add_context: false,
                    },
                )
                .unwrap();
            let FinishedPublication {
                response,
                acknowledgment,
            } = publication.finish_observed(Ok(Ok(())), || {}).ok().unwrap();
            acknowledge_publication(acknowledgment);
            drop(response);
        }
        let mut publication = ApplyPublication::new_bound(&mut sink, &slot);
        assert_eq!(
            publication.with_completion(
                &control.identity,
                &mut ReturnedActionError {
                    control: &control,
                    original: &mut original,
                    capture_identity: matches!(mode, "exact" | "context"),
                    return_error: true,
                    add_context: mode == "context",
                }
            ),
            Err(crate::CompletionCallError::Recorded)
        );
        let returned = failed(publication.finish_observed(Ok(Ok(())), || {}));
        assert!(original.is_none());
        assert!(!slot.failure_ownership_drained());
        drop(returned);
        assert!(
            slot.completion()
                .poll_drain(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        assert!(slot.completion().drained());
        assert_eq!(slot.failure_ownership_drained(), mode == "exact", "{mode}");
        slot.failure()
            .unwrap()
            .try_with_report(|report| {
                let RetainedApplyReport::Ordinary(report) = report else {
                    panic!("ordinary original");
                };
                let O::Error(original) = report.action else {
                    panic!("unchanged action original");
                };
                assert_eq!(
                    original.downcast_ref::<Original>().unwrap() as *const Original as usize,
                    address,
                    "{mode}"
                );
                assert_eq!(report.response.unwrap().data, [53]);
                assert!(matches!(report.sink, O::Returned));
                assert!(matches!(report.drain, O::Returned));
                assert_eq!(
                    report.custody_guards.action_error_retired,
                    mode == "exact",
                    "{mode}"
                );
            })
            .unwrap();
        assert!(slot.completion().failed() && slot.completion().unsettled());
    }
}

#[test]
fn action_retirement_proof_panic_retains_both_originals_and_never_retries_callback() {
    let (slot, control) = owner();
    control.proof_panic.store(true, Ordering::SeqCst);
    let mut sink = SinkCount(0);
    let mut original: Option<anyhow::Error> = Some(Original(59).into());
    let address = original
        .as_ref()
        .unwrap()
        .downcast_ref::<Original>()
        .unwrap() as *const Original as usize;
    let mut publication = ApplyPublication::new_bound(&mut sink, &slot);
    assert_eq!(
        publication.with_completion(
            &control.identity,
            &mut ReturnedActionError {
                control: &control,
                original: &mut original,
                capture_identity: true,
                return_error: true,
                add_context: false,
            }
        ),
        Err(crate::CompletionCallError::Recorded)
    );
    drop(failed(publication.finish_observed(Ok(Ok(())), || {})));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(slot.completion().poll_drain(&mut cx).is_ready());
    assert!(!slot.completion().drained() && !slot.failure_ownership_drained());
    control.proof_panic.store(false, Ordering::SeqCst);
    assert!(slot.completion().poll_drain(&mut cx).is_ready());
    assert!(!slot.completion().drained() && !slot.failure_ownership_drained());
    slot.failure()
        .unwrap()
        .try_with_report(|report| {
            let RetainedApplyReport::Ordinary(report) = report else {
                panic!("ordinary original");
            };
            let O::Error(original) = report.action else {
                panic!("action original");
            };
            assert_eq!(
                original.downcast_ref::<Original>().unwrap() as *const Original as usize,
                address
            );
            let O::Unwound(panic) = report.drain else {
                panic!("independent proof callback panic");
            };
            assert!(Arc::ptr_eq(
                panic.downcast_ref::<Arc<Control>>().unwrap(),
                &control
            ));
            assert_eq!(report.response.unwrap().data, [53]);
        })
        .unwrap();
}
