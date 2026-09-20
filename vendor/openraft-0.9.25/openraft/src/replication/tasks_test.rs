//! Retained registry tests use actual Tokio handles and task IDs, including
//! independent stream/snapshot failures and cancellation at real join awaits.
use std::future::Future;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use tokio::sync::oneshot;

use super::tasks::Registry;
use crate::core::sm::tasks::Task;
use crate::engine::testing::UTConfig;

#[tokio::test]
async fn cancelled_drain_retains_both_original_errors_and_capacity() {
    let registry = Registry::<UTConfig>::new(1);
    let owner = registry.reserve(17).unwrap();
    let (release, waiting) = oneshot::channel();
    let stream = tokio::spawn(async move {
        let _ = waiting.await;
        panic!("original stream panic");
    });
    let stream_id = stream.id();
    *owner.stream.lock().await = Some(Task::Running(stream));
    let (snapshot_release, snapshot_waiting) = oneshot::channel();
    let snapshot = tokio::spawn(async move {
        let _ = snapshot_waiting.await;
        panic!("original snapshot panic");
    });
    let snapshot_id = snapshot.id();
    *owner.snapshot.lock().await = Some(Task::Running(snapshot));
    assert!(registry.reserve(18).is_err());
    let mut drain = Box::pin(registry.shutdown());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(drain);
    release.send(()).unwrap();
    // A joined stream failure must not skip an unresolved snapshot sender.
    assert!(tokio::time::timeout(Duration::from_millis(20), registry.shutdown()).await.is_err());
    assert!(registry.reserve(18).is_err());
    snapshot_release.send(()).unwrap();
    let first = registry.shutdown().await;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].target, 17);
    assert_eq!(first[0].stream.as_ref().unwrap().join_error().unwrap().id(), stream_id);
    assert_eq!(
        first[0].snapshot.as_ref().unwrap().join_error().unwrap().id(),
        snapshot_id
    );
    let stream_error = Arc::downgrade(first[0].stream.as_ref().unwrap().join_error().unwrap());
    let snapshot_error = Arc::downgrade(first[0].snapshot.as_ref().unwrap().join_error().unwrap());
    drop(first);
    let again = registry.shutdown().await;
    assert!(Arc::ptr_eq(
        &stream_error.upgrade().unwrap(),
        again[0].stream.as_ref().unwrap().join_error().unwrap()
    ));
    assert!(Arc::ptr_eq(
        &snapshot_error.upgrade().unwrap(),
        again[0].snapshot.as_ref().unwrap().join_error().unwrap()
    ));
    assert!(
        registry.reserve(18).is_err(),
        "failed owners never evicted for admission"
    );
}

#[tokio::test]
async fn sender_failure_wakes_live_owner_and_preserves_runtime_abort() {
    let registry = Registry::<UTConfig>::new(1);
    let owner = registry.reserve(8).unwrap();
    let (release, waiting) = oneshot::channel();
    *owner.stream.lock().await = Some(Task::Running(tokio::spawn(async move {
        let _ = waiting.await;
        Ok(())
    })));
    let snapshot = tokio::spawn(std::future::pending());
    let id = snapshot.id();
    snapshot.abort();
    *owner.snapshot.lock().await = Some(Task::Running(snapshot));
    let original = tokio::time::timeout(Duration::from_secs(1), registry.changed()).await.unwrap().unwrap_err();
    assert!(original.join_error().unwrap().is_cancelled());
    assert_eq!(original.join_error().unwrap().id(), id);
    release.send(()).unwrap();
    let errors = registry.shutdown().await;
    assert!(errors[0].stream.is_none());
    assert!(Arc::ptr_eq(
        original.join_error().unwrap(),
        errors[0].snapshot.as_ref().unwrap().join_error().unwrap()
    ));
}

#[tokio::test]
async fn joined_success_reuses_one_slot_without_history_growth() {
    let registry = Registry::<UTConfig>::new(1);
    for target in 0..128 {
        let owner = registry.reserve(target).unwrap();
        assert_eq!(owner.id, target);
        *owner.stream.lock().await = Some(Task::Running(tokio::spawn(async { Ok(()) })));
        *owner.snapshot.lock().await = Some(Task::Running(tokio::spawn(async { Ok(()) })));
        registry.changed().await.unwrap();
        registry.available(1).unwrap();
    }
    assert!(registry.shutdown().await.is_empty());
}

#[tokio::test]
async fn unspawned_reservation_is_released_only_after_producer_join() {
    let registry = Registry::<UTConfig>::new(1);
    let _preparation = registry.reserve(1).unwrap();
    assert!(registry.available(1).is_err());
    assert!(registry.shutdown().await.is_empty());
    registry.available(1).unwrap();
}
