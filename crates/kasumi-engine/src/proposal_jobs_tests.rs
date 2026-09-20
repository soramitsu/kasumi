use super::*;
use crate::admission::{AdmissionConfig, WorkFence};
use kasumi_query::QueryCancellation;
use std::{future::Future, task::Poll};

fn admission() -> Arc<NodeAdmission> {
    NodeAdmission::with_fixed_memory(
        AdmissionConfig {
            max_inflight_bytes: Some(128 << 20),
            ..Default::default()
        },
        1 << 30,
        1 << 20,
    )
    .unwrap()
}
async fn until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn registry_is_bounded_and_uses_the_original_node_charge() {
    let admission = admission();
    let jobs = Jobs::default();
    jobs.prepare(&admission).unwrap();
    assert_eq!(
        admission.snapshot().reserved_bytes,
        BackgroundWorkBudget::required_bytes(MAX_PROPOSALS, 1).unwrap()
    );
    assert_eq!(admission.snapshot().inflight_operations, 0);
    let mut releases = Vec::new();
    for _ in 0..MAX_PROPOSALS {
        let (release, waiting) = tokio::sync::oneshot::channel::<()>();
        drop(
            jobs.start_task(async move {
                waiting.await.unwrap();
                Ok(())
            })
            .unwrap(),
        );
        releases.push(release);
    }
    let rejected = jobs.start_task(async { Ok(()) });
    assert_eq!(rejected.err().unwrap().code, ErrorCode::ResourceExhausted);
    assert_eq!(
        jobs.state.lock().unwrap().slots.iter().flatten().count(),
        MAX_PROPOSALS
    );
    for release in releases {
        release.send(()).unwrap();
    }
    jobs.drain().await.unwrap();
    assert_eq!(admission.snapshot().reserved_bytes, 0);
    assert!(jobs.start_task(async { Ok(()) }).is_err());
}

#[tokio::test]
async fn completed_response_retains_command_workspace_and_registration_until_consumed() {
    let admission = admission();
    let jobs = Jobs::default();
    jobs.prepare(&admission).unwrap();
    let metadata = admission.snapshot().reserved_bytes;
    let fence = Arc::new(WorkFence::default());
    let registration = Arc::new(fence.begin(QueryCancellation::default()).unwrap());
    let mut workspace = admission.reserve(1 << 20, None).unwrap();
    let call = jobs
        .start_task(async move {
            workspace.retain_workspace();
            Ok(Response {
                bytes: b"terminal result".to_vec(),
                _reservation: workspace,
                _registration: registration,
            })
        })
        .unwrap();
    let response = call.wait(Duration::from_secs(5)).await.unwrap();
    jobs.check().unwrap();
    assert_eq!(response.bytes, b"terminal result");
    assert_eq!(admission.snapshot().reserved_bytes, metadata + (1 << 20));
    assert_eq!(admission.snapshot().inflight_operations, 0);
    let mut drain = Box::pin(fence.drain());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(response);
    drain.await;
    assert_eq!(admission.snapshot().reserved_bytes, metadata);
    jobs.drain().await.unwrap();
    assert_eq!(admission.snapshot().reserved_bytes, 0);
}

#[tokio::test]
async fn timed_out_call_retains_actual_child_and_cannot_cancel_its_effect() {
    let admission = admission();
    let jobs = Jobs::default();
    jobs.prepare(&admission).unwrap();
    let workspace = admission.reserve(1 << 20, None).unwrap();
    let effect = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let accepted = effect.clone();
    let (release, waiting) = tokio::sync::oneshot::channel();
    let call = jobs
        .start_task(async move {
            waiting.await.unwrap();
            accepted.store(true, std::sync::atomic::Ordering::Release);
            Ok(workspace)
        })
        .unwrap();
    assert_eq!(
        call.wait(Duration::from_millis(1))
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::UnknownOutcome
    );
    assert_eq!(admission.snapshot().inflight_operations, 1);
    assert_eq!(jobs.state.lock().unwrap().slots.iter().flatten().count(), 1);
    let mut drain = Box::pin(jobs.drain());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(drain);
    assert_eq!(admission.snapshot().inflight_operations, 1);
    release.send(()).unwrap();
    jobs.drain().await.unwrap();
    assert!(effect.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(admission.snapshot().reserved_bytes, 0);
}

#[tokio::test]
async fn cancelled_drain_preserves_prior_panic_while_later_child_remains_owned() {
    let admission = admission();
    let jobs = Jobs::default();
    jobs.prepare(&admission).unwrap();
    let (fail, failed) = tokio::sync::oneshot::channel();
    let first = jobs
        .start_task::<()>(async move {
            failed.await.unwrap();
            panic!("original proposal panic");
        })
        .unwrap();
    let first_worker = first.worker.clone();
    drop(first);
    let (release, waiting) = tokio::sync::oneshot::channel::<()>();
    drop(
        jobs.start_task(async move {
            waiting.await.unwrap();
            Ok(())
        })
        .unwrap(),
    );
    fail.send(()).unwrap();
    until(|| first_worker.observed().is_some()).await;
    assert_eq!(jobs.check().unwrap_err().code, ErrorCode::Unavailable);
    assert!(jobs.start_task(async { Ok(()) }).is_err());
    let mut drain = Box::pin(jobs.drain());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(drain);
    let prior = jobs.state.lock().unwrap().report.complete().unwrap_err();
    let original = prior.issues()[0].clone();
    assert!(
        original
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_panic()
    );
    assert_eq!(jobs.state.lock().unwrap().slots.iter().flatten().count(), 1);
    release.send(()).unwrap();
    let finished = jobs.drain().await.unwrap_err();
    assert_eq!(finished.completion(), DrainCompletion::Complete);
    assert!(Arc::ptr_eq(&original, &finished.issues()[0]));
    assert!(Arc::ptr_eq(
        &original,
        &jobs.drain().await.unwrap_err().issues()[0]
    ));
}

#[derive(Debug)]
struct OriginalFailure(Arc<()>);
impl std::fmt::Display for OriginalFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original proposal infrastructure failure")
    }
}
impl std::error::Error for OriginalFailure {}

#[tokio::test]
async fn original_error_and_charge_survive_cancelled_caller_and_registry_drop() {
    let admission = admission();
    let jobs = Jobs::default();
    jobs.prepare(&admission).unwrap();
    let identity = Arc::new(());
    let original = OriginalFailure(identity.clone());
    let (release, waiting) = tokio::sync::oneshot::channel();
    let call = jobs
        .start_task::<()>(async move {
            waiting.await.unwrap();
            Err(original.into())
        })
        .unwrap();
    let worker = Arc::downgrade(&call.worker);
    drop(call);
    drop(jobs);
    assert!(admission.snapshot().reserved_bytes > 0);
    release.send(()).unwrap();
    let recovered = worker
        .upgrade()
        .expect("exact child lost after registry drop");
    let failure = recovered.drain().await.unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    let actual = failure.issues()[0]
        .error()
        .downcast_ref::<OriginalFailure>()
        .unwrap();
    assert!(Arc::ptr_eq(&identity, &actual.0));
    let again = recovered.drain().await.unwrap_err();
    assert!(Arc::ptr_eq(&failure.issues()[0], &again.issues()[0]));
    drop(recovered);
    assert!(worker.upgrade().is_none());
    assert_eq!(admission.snapshot().reserved_bytes, 0);
}

#[tokio::test]
async fn definite_request_rejection_does_not_poison_proposal_custody() {
    let jobs = Jobs::default();
    jobs.prepare(&admission()).unwrap();
    let call = jobs
        .start_task(async {
            Ok(Err::<(), _>(Error::new(
                ErrorCode::Conflict,
                "definite rejection",
            )))
        })
        .unwrap();
    assert_eq!(
        call.wait(Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    jobs.check().unwrap();
    jobs.start_task(async { Ok(()) })
        .unwrap()
        .wait(Duration::from_secs(5))
        .await
        .unwrap();
    jobs.drain().await.unwrap();
}
