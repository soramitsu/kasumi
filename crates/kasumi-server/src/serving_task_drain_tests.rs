use super::ServingTasks;
use kasumi_types::drain::DrainCompletion;
use std::{future::Future, sync::Arc, task::Poll, time::Duration};

#[tokio::test]
async fn cancelled_serving_drain_retains_joined_panic_and_exact_pending_owner() {
    let mut tasks = ServingTasks::new();
    let failed = tasks.maintenance.spawn(async {
        panic!("actual maintenance task panic");
    });
    let failed_id = failed.id();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !failed.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("serving-task.redb");
    let node = kasumi_store::NodeStore::create_new(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let weak = Arc::downgrade(&node);
    let (release, waiting) = tokio::sync::oneshot::channel();
    let pending = tasks.listeners.spawn(async move {
        let _node = node;
        waiting.await?;
        Ok(())
    });
    let pending_id = pending.id();
    let mut first = Box::pin(tasks.shutdown());
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(first);
    assert!(tasks.maintenance.is_empty());
    assert_eq!(tasks.listeners.len(), 1);
    assert!(!pending.is_finished());
    assert!(weak.upgrade().is_some());
    assert!(
        kasumi_store::NodeStore::open_existing(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .is_err()
    );
    let issue = tasks.report.issues()[0].clone();
    let error = issue
        .error()
        .downcast_ref::<tokio::task::JoinError>()
        .unwrap();
    assert!(error.is_panic());
    assert_eq!(error.id(), failed_id);
    assert_ne!(error.id(), pending_id);

    let mut resumed = Box::pin(tasks.shutdown());
    std::future::poll_fn(|cx| {
        assert!(resumed.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    release.send(()).unwrap();
    let failure = tokio::time::timeout(Duration::from_secs(5), resumed)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(failure.issues().len(), 1);
    assert!(Arc::ptr_eq(&issue, &failure.issues()[0]));
    assert!(pending.is_finished());
    assert!(weak.upgrade().is_none());
    assert!(tasks.listeners.is_empty());
    let repeated = tasks.shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(&issue, &repeated.issues()[0]));
    assert_eq!(tasks.failed_tasks.len(), 1);
    let reopened = kasumi_store::NodeStore::open_existing(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    drop(reopened);
}

#[derive(Debug)]
struct ListenerFailure;
impl std::fmt::Display for ListenerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original returned listener error")
    }
}
impl std::error::Error for ListenerFailure {}

#[tokio::test]
async fn serving_drain_keeps_every_panic_abort_and_returned_error() {
    let mut tasks = ServingTasks::new();
    let failed = tasks.maintenance.spawn(async {
        panic!("actual maintenance panic");
    });
    let aborted = tasks.maintenance.spawn(std::future::pending());
    let returned = tasks.listeners.spawn(async { Err(ListenerFailure.into()) });
    let failed_id = failed.id();
    let aborted_id = aborted.id();
    let returned_id = returned.id();
    aborted.abort();
    let failure = tokio::time::timeout(Duration::from_secs(5), tasks.shutdown())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(failure.issues().len(), 3);
    assert_eq!(tasks.failed_tasks.len(), 3);
    let panic = failure
        .issues()
        .iter()
        .find(|issue| {
            issue
                .error()
                .downcast_ref::<tokio::task::JoinError>()
                .is_some_and(|error| error.is_panic())
        })
        .unwrap();
    assert_eq!(
        panic
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .id(),
        failed_id
    );
    let cancelled = failure
        .issues()
        .iter()
        .find(|issue| {
            issue
                .error()
                .downcast_ref::<tokio::task::JoinError>()
                .is_some_and(|error| error.is_cancelled())
        })
        .unwrap();
    assert_eq!(
        cancelled
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .id(),
        aborted_id
    );
    let returned = failure
        .issues()
        .iter()
        .find(|issue| issue.error().is::<ListenerFailure>())
        .unwrap();
    assert_eq!(tasks.failed_tasks[&returned_id], returned.instance());
    let repeated = tasks.shutdown().await.unwrap_err();
    for (first, again) in failure.issues().iter().zip(repeated.issues()) {
        assert!(Arc::ptr_eq(first, again));
    }
    assert_eq!(tasks.failed_tasks.len(), 3);
}
