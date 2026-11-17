use super::*;
use kasumi_types::drain::{DrainCompletion, DrainIssueRef};
use std::{
    sync::{Arc, mpsc},
    time::Duration,
};

const WAIT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct OriginalFailure(u64);
impl fmt::Display for OriginalFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original child failure {}", self.0)
    }
}
impl std::error::Error for OriginalFailure {}

type Outcome = Result<u64, ChildFailure<anyhow::Error>>;

/// A child that reports it started, then holds until released.
fn held(
    children: &BlockingChildren,
    finish: impl FnOnce() -> Outcome + Send + 'static,
) -> (
    Call<'_, u64, anyhow::Error>,
    tokio::sync::oneshot::Receiver<()>,
    mpsc::Sender<()>,
) {
    let (entered, running) = tokio::sync::oneshot::channel();
    let (release, held) = mpsc::channel::<()>();
    let call = children
        .start(move || {
            let _ = entered.send(());
            let _ = held.recv();
            finish()
        })
        .unwrap();
    (call, running, release)
}

async fn pending_once(drain: &mut Pin<Box<impl Future<Output = DrainResult>>>) {
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn cancelled_caller_and_cancelled_drain_retain_the_later_original_failure() {
    let children = BlockingChildren::new("test child", 1).unwrap();
    let (call, running, release) = held(&children, || {
        Err(ChildFailure::Failed(OriginalFailure(7).into()))
    });
    tokio::time::timeout(WAIT, running).await.unwrap().unwrap();

    // The caller's timeout drops only its claim; the child keeps running.
    assert!(
        tokio::time::timeout(Duration::from_millis(20), call.wait())
            .await
            .is_err()
    );
    assert_eq!(children.running(), 1);

    let mut first = Box::pin(children.drain());
    pending_once(&mut first).await;
    drop(first);
    assert_eq!(children.running(), 1);
    release.send(()).unwrap();

    let failure = tokio::time::timeout(WAIT, children.drain())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(failure.issues().len(), 1);
    let original = &failure.issues()[0];
    assert_eq!(original.component(), "test child");
    assert_eq!(
        original
            .error()
            .downcast_ref::<OriginalFailure>()
            .unwrap()
            .0,
        7
    );
    let repeated = children.drain().await.unwrap_err();
    assert!(DrainIssueRef::ptr_eq(original, &repeated.issues()[0]));
    assert_eq!(children.running(), 0);
    // The evidence keeps its slot: nothing can displace it.
    assert_eq!(
        children.start(|| -> Outcome { Ok(1) }).err(),
        Some(ChildRefused::Full)
    );
}

#[tokio::test]
async fn panic_reaches_a_waiting_caller_as_lost_and_the_drain_as_its_join_error() {
    let children = BlockingChildren::new("test child", 2).unwrap();
    let call = children
        .start(|| -> Outcome { panic!("original child panic") })
        .unwrap();
    assert!(
        tokio::time::timeout(WAIT, call.wait())
            .await
            .unwrap()
            .is_err()
    );
    let failure = tokio::time::timeout(WAIT, children.drain())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    let join = failure.issues()[0]
        .error()
        .downcast_ref::<tokio::task::JoinError>()
        .unwrap();
    assert!(join.is_panic());
    // One slot holds the panic; the other still admits work.
    let next = children.start(|| -> Outcome { Ok(3) }).unwrap();
    assert_eq!(next.wait().await.unwrap().unwrap(), 3);
    let repeated = children.drain().await.unwrap_err();
    assert_eq!(repeated.issues().len(), 1);
    assert!(DrainIssueRef::ptr_eq(
        &failure.issues()[0],
        &repeated.issues()[0]
    ));
}

#[tokio::test]
async fn panic_after_its_caller_left_is_joined_by_the_drain() {
    let children = BlockingChildren::new("test child", 1).unwrap();
    let (call, running, release) = held(&children, || panic!("abandoned child panic"));
    tokio::time::timeout(WAIT, running).await.unwrap().unwrap();
    drop(call);
    release.send(()).unwrap();
    let failure = tokio::time::timeout(WAIT, children.drain())
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        failure.issues()[0]
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_panic()
    );
}

#[tokio::test]
async fn stopped_or_successful_children_nobody_awaits_leave_no_evidence() {
    let children = BlockingChildren::new("test child", 1).unwrap();
    for stopped in [true, false] {
        let (call, running, release) = held(&children, move || {
            if stopped {
                Err(ChildFailure::Stopped(anyhow::anyhow!("deadline expired")))
            } else {
                Ok(5)
            }
        });
        tokio::time::timeout(WAIT, running).await.unwrap().unwrap();
        drop(call);
        release.send(()).unwrap();
        tokio::time::timeout(WAIT, children.drain())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(children.running(), 0);
    }
}

#[tokio::test]
async fn received_failure_is_the_callers_and_frees_its_slot() {
    let children = BlockingChildren::new("test child", 1).unwrap();
    for _ in 0..3 {
        let call = children
            .start(|| -> Outcome { Err(ChildFailure::Failed(OriginalFailure(9).into())) })
            .unwrap();
        let error = tokio::time::timeout(WAIT, call.wait())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.downcast_ref::<OriginalFailure>().unwrap().0, 9);
        tokio::time::timeout(WAIT, children.drain())
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn finished_failure_whose_caller_never_joins_it_becomes_evidence() {
    let children = BlockingChildren::new("test child", 1).unwrap();
    let (finished, done) = tokio::sync::oneshot::channel::<()>();
    let call = children
        .start(move || -> Outcome {
            let _finished = finished;
            Err(ChildFailure::Failed(OriginalFailure(11).into()))
        })
        .unwrap();
    // The child ends while its caller still holds the claim. Only that caller
    // may join it, so a drain waits rather than taking its output.
    let _ = tokio::time::timeout(WAIT, done).await.unwrap();
    let mut drain = Box::pin(children.drain());
    pending_once(&mut drain).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    pending_once(&mut drain).await;
    assert_eq!(children.running(), 1);
    drop(call);
    let failure = tokio::time::timeout(WAIT, drain)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(
        failure.issues()[0]
            .error()
            .downcast_ref::<OriginalFailure>()
            .unwrap()
            .0,
        11
    );
}

#[tokio::test]
async fn caller_that_joins_wakes_a_waiting_drain() {
    let children = BlockingChildren::new("test child", 1).unwrap();
    let (call, running, release) = held(&children, || Ok(8));
    tokio::time::timeout(WAIT, running).await.unwrap().unwrap();
    let mut drain = Box::pin(children.drain());
    pending_once(&mut drain).await;
    release.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, call.wait())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        8
    );
    tokio::time::timeout(WAIT, drain).await.unwrap().unwrap();
}

#[tokio::test]
async fn full_table_starts_nothing_and_admits_again_once_a_child_ends() {
    let children = BlockingChildren::new("test child", 1).unwrap();
    let (call, running, release) = held(&children, || Ok(1));
    tokio::time::timeout(WAIT, running).await.unwrap().unwrap();
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let refused = started.clone();
    assert_eq!(
        children
            .start(move || -> Outcome {
                refused.store(true, std::sync::atomic::Ordering::Release);
                Ok(2)
            })
            .err(),
        Some(ChildRefused::Full)
    );
    release.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, call.wait())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        1
    );
    tokio::time::timeout(WAIT, children.drain())
        .await
        .unwrap()
        .unwrap();
    assert!(!started.load(std::sync::atomic::Ordering::Acquire));
    let next = children.start(|| -> Outcome { Ok(4) }).unwrap();
    assert_eq!(next.wait().await.unwrap().unwrap(), 4);
}

#[tokio::test]
async fn captured_owners_are_destroyed_before_the_caller_resumes() {
    let children = BlockingChildren::new("test child", 1).unwrap();
    let owner = Arc::new(());
    let captured = owner.clone();
    let call = children
        .start(move || -> Outcome {
            let _held = captured;
            Ok(6)
        })
        .unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, call.wait())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        6
    );
    assert_eq!(Arc::strong_count(&owner), 1);
}

/// What a real child's output retains: a charge, a work registration.
type Retaining = Result<Arc<()>, ChildFailure<anyhow::Error>>;

#[tokio::test]
async fn child_whose_caller_left_destroys_its_output_without_waiting_for_a_drain() {
    let children = BlockingChildren::new("test child", 1).unwrap();
    let owner = Arc::new(());
    let captured = owner.clone();
    let (call, running, release) = held_retaining(&children, move || Ok(captured));
    tokio::time::timeout(WAIT, running).await.unwrap().unwrap();
    drop(call);
    release.send(()).unwrap();
    // A work fence waits for what the output retains, and only a drain would
    // join the handle: the child itself must release it.
    tokio::time::timeout(WAIT, async {
        while Arc::strong_count(&owner) > 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(WAIT, children.drain())
        .await
        .unwrap()
        .unwrap();
}

fn held_retaining(
    children: &BlockingChildren,
    finish: impl FnOnce() -> Retaining + Send + 'static,
) -> (
    Call<'_, Arc<()>, anyhow::Error>,
    tokio::sync::oneshot::Receiver<()>,
    mpsc::Sender<()>,
) {
    let (entered, running) = tokio::sync::oneshot::channel();
    let (release, held) = mpsc::channel::<()>();
    let call = children
        .start(move || {
            let _ = entered.send(());
            let _ = held.recv();
            finish()
        })
        .unwrap();
    (call, running, release)
}

#[tokio::test]
async fn delivered_output_is_destroyed_when_its_caller_leaves_before_joining() {
    let children = BlockingChildren::new("test child", 2).unwrap();
    for failed in [false, true] {
        let owner = Arc::new(());
        let captured = owner.clone();
        let (finished, done) = tokio::sync::oneshot::channel::<()>();
        let call = children
            .start(move || -> Retaining {
                let _finished = finished;
                if failed {
                    let _held = captured;
                    Err(ChildFailure::Failed(OriginalFailure(13).into()))
                } else {
                    Ok(captured)
                }
            })
            .unwrap();
        let _ = tokio::time::timeout(WAIT, done).await.unwrap();
        // Wait for the delivery itself: the handle finishes after it.
        while !children.state().slots[call.slot]
            .child
            .as_ref()
            .unwrap()
            .is_finished()
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        drop(call);
        assert_eq!(Arc::strong_count(&owner), 1);
        let drained = tokio::time::timeout(WAIT, children.drain()).await.unwrap();
        if failed {
            let failure = drained.unwrap_err();
            assert_eq!(failure.issues().len(), 1);
            assert_eq!(
                failure.issues()[0]
                    .error()
                    .downcast_ref::<OriginalFailure>()
                    .unwrap()
                    .0,
                13
            );
        } else {
            drained.unwrap();
        }
    }
}

#[tokio::test]
async fn sealed_table_starts_nothing_and_still_drains_its_children() {
    let children = BlockingChildren::new("test child", 2).unwrap();
    let (call, running, release) = held(&children, || Ok(1));
    tokio::time::timeout(WAIT, running).await.unwrap().unwrap();
    drop(call);
    children.seal();
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let refused = started.clone();
    assert_eq!(
        children
            .start(move || -> Outcome {
                refused.store(true, std::sync::atomic::Ordering::Release);
                Ok(2)
            })
            .err(),
        Some(ChildRefused::Sealed)
    );
    // The child accepted before the seal is still the drain's to join.
    let mut drain = Box::pin(children.drain());
    pending_once(&mut drain).await;
    release.send(()).unwrap();
    tokio::time::timeout(WAIT, drain).await.unwrap().unwrap();
    assert!(!started.load(std::sync::atomic::Ordering::Acquire));
}
