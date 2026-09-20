use std::future::Future;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use super::Registry;
use crate::core::sm::tasks::Task;
use crate::engine::testing::UTConfig;
use crate::error::AuxiliaryTaskKind;

#[tokio::test]
async fn cancelled_drain_retains_independent_collector_panics_and_election_capacity() {
    let registry = Registry::<UTConfig>::new(2);
    let read = registry.reserve(AuxiliaryTaskKind::LeadershipRead).unwrap();
    assert!(registry.reserve(AuxiliaryTaskKind::LeadershipRead).is_err());
    let vote = registry.reserve(AuxiliaryTaskKind::VoteRound).unwrap();
    let (release_read, wait_read) = tokio::sync::oneshot::channel();
    let (release_vote, wait_vote) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = wait_read.await;
        panic!("original read collector");
    });
    let read_id = task.id();
    *read.task.lock().await = Some(Task::Running(task));
    let task = tokio::spawn(async move {
        let _ = wait_vote.await;
        panic!("original vote collector");
    });
    let vote_id = task.id();
    *vote.task.lock().await = Some(Task::Running(task));
    let mut drain = Box::pin(registry.shutdown());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(drain);
    release_read.send(()).unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(20), registry.shutdown()).await.is_err());
    release_vote.send(()).unwrap();
    let errors = registry.shutdown().await;
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].kind, AuxiliaryTaskKind::LeadershipRead);
    assert_eq!(errors[1].kind, AuxiliaryTaskKind::VoteRound);
    assert_eq!(errors[0].error.join_error().unwrap().id(), read_id);
    assert_eq!(errors[1].error.join_error().unwrap().id(), vote_id);
    let original = [
        Arc::downgrade(errors[0].error.join_error().unwrap()),
        Arc::downgrade(errors[1].error.join_error().unwrap()),
    ];
    drop(errors);
    let again = registry.shutdown().await;
    for (index, error) in again.iter().enumerate() {
        assert!(Arc::ptr_eq(
            &original[index].upgrade().unwrap(),
            error.error.join_error().unwrap()
        ));
    }
    assert!(registry.reserve(AuxiliaryTaskKind::VoteRound).is_err());
}

#[tokio::test]
async fn actual_abort_wakes_live_core_and_preserves_original_id() {
    let registry = Registry::<UTConfig>::new(2);
    let owner = registry.reserve(AuxiliaryTaskKind::VoteRound).unwrap();
    let task = tokio::spawn(std::future::pending());
    let id = task.id();
    task.abort();
    *owner.task.lock().await = Some(Task::Running(task));
    let error = tokio::time::timeout(Duration::from_secs(1), registry.changed()).await.unwrap().unwrap_err();
    assert!(error.join_error().unwrap().is_cancelled());
    assert_eq!(error.join_error().unwrap().id(), id);
    let again = registry.shutdown().await;
    assert!(Arc::ptr_eq(
        error.join_error().unwrap(),
        again[0].error.join_error().unwrap()
    ));
}

#[tokio::test]
async fn successful_rounds_reuse_fixed_capacity_and_unspawned_reservation_drains() {
    let registry = Registry::<UTConfig>::new(2);
    for sequence in 0..128 {
        let owner = registry.reserve(AuxiliaryTaskKind::LeadershipRead).unwrap();
        assert_eq!(owner.id, sequence);
        *owner.task.lock().await = Some(Task::Running(tokio::spawn(async { Ok(()) })));
        registry.changed().await.unwrap();
    }
    let _unspawned = registry.reserve(AuxiliaryTaskKind::LeadershipRead).unwrap();
    assert!(registry.reserve(AuxiliaryTaskKind::LeadershipRead).is_err());
    assert!(registry.shutdown().await.is_empty());
    registry.reserve(AuxiliaryTaskKind::LeadershipRead).unwrap();
}
