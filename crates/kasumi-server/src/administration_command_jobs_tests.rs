use super::*;
use std::{
    future::{Future, poll_fn},
    sync::atomic::Ordering,
    task::Poll,
    time::Duration,
};

#[derive(Debug)]
struct OriginalCommandError(Arc<()>);
impl std::fmt::Display for OriginalCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original accepted membership command failure")
    }
}
impl std::error::Error for OriginalCommandError {}

fn jobs() -> (Arc<NodeAdmission>, Arc<CommandJobs>, u64) {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let baseline = admission.snapshot().reserved_bytes;
    let jobs = Arc::new(CommandJobs::new(&admission).unwrap());
    assert_eq!(
        admission.snapshot().reserved_bytes,
        baseline + metadata_bytes().unwrap()
    );
    assert_eq!(admission.snapshot().inflight_operations, 0);
    (admission, jobs, baseline)
}

async fn registered(jobs: &CommandJobs, count: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while jobs.registered() != count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn canceled_waiter_leaves_original_command_error_for_exact_shutdown_drain() {
    let (admission, jobs, baseline) = jobs();
    let marker = Arc::new(());
    let original = marker.clone();
    let (release, waiting) = oneshot::channel::<()>();
    let owner = jobs.clone();
    let caller = tokio::spawn(async move {
        owner
            .execute(
                tokio::time::Instant::now() + Duration::from_secs(5),
                async move {
                    waiting.await?;
                    Err(OriginalCommandError(original).into())
                },
                "membership command timed out",
            )
            .await
    });
    registered(&jobs, 1).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert_eq!(jobs.registered(), 1);
    release.send(()).unwrap();
    let failure = tokio::time::timeout(Duration::from_secs(5), jobs.drain())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    let issue = failure
        .issues()
        .iter()
        .find(|issue| issue.component() == "membership command")
        .unwrap();
    assert!(Arc::ptr_eq(
        &issue
            .error()
            .downcast_ref::<OriginalCommandError>()
            .unwrap()
            .0,
        &marker
    ));
    let again = jobs.drain().await.unwrap_err();
    assert!(again.issues().iter().any(|value| Arc::ptr_eq(value, issue)));
    assert_eq!(jobs.registered(), 0);
    drop(jobs);
    assert_eq!(admission.snapshot().reserved_bytes, baseline);
}

#[tokio::test]
async fn deadline_returns_unknown_while_success_remains_in_bounded_custody() {
    let (_admission, jobs, _baseline) = jobs();
    let (release, waiting) = oneshot::channel::<()>();
    let error = jobs
        .execute(
            tokio::time::Instant::now() + Duration::from_millis(20),
            async move {
                waiting.await?;
                Ok(())
            },
            "membership command timed out",
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<kasumi_types::Error>().unwrap().code,
        kasumi_types::ErrorCode::UnknownOutcome
    );
    assert_eq!(jobs.registered(), 1);
    release.send(()).unwrap();
    jobs.drain().await.unwrap();
    assert_eq!(jobs.registered(), 0);
}

#[tokio::test]
async fn aborted_drain_retries_with_original_join_error_and_fenced_admission() {
    let (_admission, jobs, _baseline) = jobs();
    let (release, waiting) = oneshot::channel::<()>();
    let (entered, observed_entry) = oneshot::channel::<()>();
    let (panicked, panic_receive) = jobs
        .submit(async move {
            entered.send(()).unwrap();
            waiting.await.unwrap();
            panic!("original membership child panic");
            #[allow(unreachable_code)]
            Ok(())
        })
        .unwrap();
    observed_entry.await.unwrap();
    let mut first = Box::pin(jobs.drain());
    poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(first);
    assert!(panicked.child.observed().is_none());
    release.send(()).unwrap();
    assert!(panic_receive.await.is_err());
    let original = panicked.child.drain().await.unwrap_err();
    assert!(
        original.issues()[0]
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_panic()
    );
    assert!(jobs.closed.load(Ordering::Acquire));
    for _ in 0..128 {
        jobs.observe();
        assert!(jobs.submit(async { Ok(()) }).is_err());
    }
    let failure = jobs.drain().await.unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(failure.issues().len(), 1);
    assert!(
        failure
            .issues()
            .iter()
            .any(|issue| Arc::ptr_eq(issue, &original.issues()[0]))
    );
    let again = jobs.drain().await.unwrap_err();
    assert_eq!(again.issues().len(), 1);
    assert!(
        again
            .issues()
            .iter()
            .any(|issue| Arc::ptr_eq(issue, &original.issues()[0]))
    );
}

#[tokio::test]
async fn original_command_error_finishes_its_turn_and_remains_owned() {
    let (_admission, jobs, _baseline) = jobs();
    let marker = Arc::new(());
    let original = marker.clone();
    let (_first, first_receive) = jobs
        .submit(async move { Err(OriginalCommandError(original).into()) })
        .unwrap();
    drop(first_receive);
    let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = dispatched.clone();
    let (_second, second_receive) = jobs
        .submit(async move {
            observed.store(true, Ordering::Release);
            Ok(())
        })
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), second_receive)
        .await
        .unwrap()
        .unwrap();
    assert!(dispatched.load(Ordering::Acquire));
    let failure = jobs.drain().await.unwrap_err();
    assert!(failure.issues().iter().any(|issue| {
        issue
            .error()
            .downcast_ref::<OriginalCommandError>()
            .is_some_and(|error| Arc::ptr_eq(&error.0, &marker))
    }));
}

#[tokio::test]
async fn predecessor_baton_waits_even_if_successor_is_polled_first() {
    let (first, second_predecessor) = watch::channel(Turn::Pending);
    let mut second = Box::pin(predecessor_completed(Some(second_predecessor)));
    poll_fn(|cx| {
        assert!(second.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(first.send(Turn::Completed).is_ok());
    assert!(
        tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn closed_unpolled_predecessor_sender_blocks_successor() {
    let (first, second_predecessor) = watch::channel(Turn::Pending);
    drop(first);
    assert!(!predecessor_completed(Some(second_predecessor)).await);
}

#[tokio::test]
async fn cancelled_waiter_does_not_let_later_accepted_command_overtake() {
    let (_admission, jobs, _baseline) = jobs();
    let (release, blocked) = oneshot::channel::<()>();
    let order = Arc::new(Mutex::new(Vec::new()));
    let first_order = order.clone();
    let (_first, first_receive) = jobs
        .submit(async move {
            blocked.await?;
            first_order.lock().unwrap().push(1_u8);
            Ok(())
        })
        .unwrap();
    drop(first_receive);
    let second_order = order.clone();
    let (_second, mut second_receive) = jobs
        .submit(async move {
            second_order.lock().unwrap().push(2_u8);
            Ok(())
        })
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut second_receive)
            .await
            .is_err()
    );
    assert!(order.lock().unwrap().is_empty());
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), second_receive)
        .await
        .unwrap()
        .unwrap();
    jobs.drain().await.unwrap();
    assert_eq!(*order.lock().unwrap(), vec![1, 2]);
}

#[tokio::test]
async fn predecessor_panic_fences_an_already_queued_membership_child() {
    let (_admission, jobs, _baseline) = jobs();
    let (started, observed_start) = oneshot::channel::<()>();
    let (release, blocked) = oneshot::channel::<()>();
    let (_first, first_receive) = jobs
        .submit(async move {
            started.send(()).unwrap();
            blocked.await.unwrap();
            panic!("predecessor membership panic");
            #[allow(unreachable_code)]
            Ok(())
        })
        .unwrap();
    observed_start.await.unwrap();
    let dispatched = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let marker = dispatched.clone();
    let (second, second_receive) = jobs
        .submit(async move {
            marker.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
        .unwrap();
    release.send(()).unwrap();
    assert!(first_receive.await.is_err());
    tokio::time::timeout(Duration::from_secs(5), second_receive)
        .await
        .unwrap()
        .unwrap();
    second.child.drain().await.unwrap();
    let error = second.outcome.take().unwrap().unwrap_err();
    assert_eq!(
        error.downcast_ref::<kasumi_types::Error>().unwrap().code,
        kasumi_types::ErrorCode::Unavailable
    );
    assert_eq!(dispatched.load(Ordering::Acquire), 0);
    let failure = jobs.drain().await.unwrap_err();
    assert!(failure.issues().iter().any(|issue| {
        issue
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .is_some()
    }));
}

#[tokio::test]
async fn unclaimed_terminal_outcomes_fill_only_the_precharged_fixed_inventory() {
    let (admission, jobs, baseline) = jobs();
    for _ in 0..COMMAND_SLOTS {
        let (job, receive) = jobs.submit(async { Ok(()) }).unwrap();
        receive.await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while job.child.observed().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    jobs.observe();
    assert_eq!(jobs.registered(), COMMAND_SLOTS);
    let error = match jobs.submit(async { Ok(()) }) {
        Ok(_) => panic!("unclaimed command exceeded fixed child inventory"),
        Err(error) => error,
    };
    assert_eq!(
        error.downcast_ref::<kasumi_types::Error>().unwrap().code,
        kasumi_types::ErrorCode::ResourceExhausted
    );
    assert_eq!(
        admission.snapshot().reserved_bytes,
        baseline + metadata_bytes().unwrap()
    );
    jobs.drain().await.unwrap();
    assert_eq!(jobs.registered(), 0);
    drop(jobs);
    assert_eq!(admission.snapshot().reserved_bytes, baseline);
}

#[tokio::test]
async fn claimed_operation_error_returns_original_and_reclaims_slot() {
    let (_admission, jobs, _baseline) = jobs();
    let marker = Arc::new(());
    let original = marker.clone();
    let error = jobs
        .execute(
            tokio::time::Instant::now() + Duration::from_secs(5),
            async move { Err(OriginalCommandError(original).into()) },
            "membership command timed out",
        )
        .await
        .unwrap_err();
    assert!(Arc::ptr_eq(
        &error.downcast_ref::<OriginalCommandError>().unwrap().0,
        &marker
    ));
    jobs.observe();
    assert_eq!(jobs.registered(), 0);
    jobs.drain().await.unwrap();
}
