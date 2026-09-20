use std::future::Future;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Poll;
use std::time::Duration;

use anyhow::Result;
use maplit::btreeset;
use openraft::error::ClientWriteError;
use openraft::error::Fatal;
use openraft::testing::log_id;
use openraft::Config;
use openraft::RPCTypes;

use crate::fixtures::init_default_ut_tracing;
use crate::fixtures::RaftRouter;

/// Shutdown cancellation leaves the actual blocked ReplicationCore owned, and
/// its later network panic remains the same runtime error on every retry.
#[async_entry::test(worker_threads = 8, init = "init_default_ut_tracing()", tracing_span = "debug")]
async fn cancelled_shutdown_retains_actual_replication_panic() -> Result<()> {
    let config = Arc::new(
        Config {
            enable_tick: false,
            ..Default::default()
        }
        .validate()?,
    );
    let mut router = RaftRouter::new(config);
    router.new_cluster(btreeset! {0}, btreeset! {1}).await?;
    let leader = router.get_raft_handle(&0)?;
    let (entered, entry) = tokio::sync::oneshot::channel();
    let entered = Mutex::new(Some(entered));
    let (release, waiting) = std::sync::mpsc::channel();
    let waiting = Mutex::new(waiting);
    router.set_rpc_pre_hook(RPCTypes::AppendEntries, move |_, _, from, to| {
        if from == 0 && to == 1 {
            if let Some(entered) = entered.lock().unwrap().take() {
                let _ = entered.send(());
                let _ = waiting.lock().unwrap().recv_timeout(Duration::from_secs(10));
                panic!("actual replication network panic after shutdown cancellation");
            }
        }
        Ok(())
    });
    router.client_request(0, "held", 1).await?;
    tokio::time::timeout(Duration::from_secs(5), entry).await??;
    let mut drain = Box::pin(leader.shutdown());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(drain);
    assert!(tokio::time::timeout(Duration::from_millis(20), leader.shutdown()).await.is_err());
    release.send(())?;
    let first = tokio::time::timeout(Duration::from_secs(5), leader.shutdown()).await?.unwrap_err();
    assert_eq!(first.replications().len(), 1);
    assert_eq!(first.replications()[0].target, 1);
    let original = first.replications()[0].stream.as_ref().unwrap().join_error().unwrap();
    assert!(original.is_panic());
    let again = leader.shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(
        original,
        again.replications()[0].stream.as_ref().unwrap().join_error().unwrap()
    ));
    router.get_raft_handle(&1)?.shutdown().await?;
    Ok(())
}

/// A snapshot sender can panic without delivering its normal callback. The
/// actual sender handle wakes the live core and survives the core's own exit.
#[async_entry::test(worker_threads = 8, init = "init_default_ut_tracing()", tracing_span = "debug")]
async fn actual_snapshot_sender_panic_fences_and_is_retained() -> Result<()> {
    let config = Arc::new(
        Config {
            enable_tick: false,
            max_in_snapshot_log_to_keep: 0,
            purge_batch_size: 1,
            ..Default::default()
        }
        .validate()?,
    );
    let mut router = RaftRouter::new(config);
    let mut index = router.new_cluster(btreeset! {0}, btreeset! {1}).await?;
    let leader = router.get_raft_handle(&0)?;
    router.set_network_error(1, true);
    index += router.client_request_many(0, "snapshot", 10).await?;
    leader.trigger().snapshot().await?;
    leader
        .wait(Some(Duration::from_secs(5)))
        .purged(Some(log_id(1, 0, index)), "snapshot log purged")
        .await?;
    router.set_rpc_pre_hook(RPCTypes::InstallSnapshot, move |_, _, from, to| {
        assert!(!(from == 0 && to == 1), "actual snapshot sender network panic");
        Ok(())
    });
    router.set_network_error(1, false);
    leader.trigger().heartbeat().await?;
    let fatal = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Err(error) = leader.with_raft_state(|_| ()).await {
                break error;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(fatal, Fatal::Panicked);
    let first = leader.shutdown().await.unwrap_err();
    assert_eq!(first.core(), Some(&Fatal::Panicked));
    assert_eq!(first.replications().len(), 1);
    let original = first.replications()[0].snapshot.as_ref().unwrap().join_error().unwrap();
    assert!(original.is_panic());
    let again = leader.shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(
        original,
        again.replications()[0].snapshot.as_ref().unwrap().join_error().unwrap()
    ));
    router.get_raft_handle(&1)?.shutdown().await?;
    Ok(())
}

/// Reject new topology work before appending its entry when replacement custody
/// cannot fit. Existing streams keep replicating and committed writes still apply.
#[async_entry::test(worker_threads = 8, init = "init_default_ut_tracing()", tracing_span = "debug")]
async fn capacity_rejection_preserves_existing_consensus_and_application() -> Result<()> {
    let config = Arc::new(
        Config {
            enable_tick: false,
            max_retained_replication_owners: 2,
            ..Default::default()
        }
        .validate()?,
    );
    let mut router = RaftRouter::new(config);
    let mut index = router.new_cluster(btreeset! {0}, btreeset! {1}).await?;
    let leader = router.get_raft_handle(&0)?;
    let before = leader.with_raft_state(|state| state.membership_state.effective().clone()).await?;
    let error = leader.change_membership([0, 1], false).await.unwrap_err();
    assert!(matches!(
        error.into_api_error().unwrap(),
        ClientWriteError::TaskCapacity(_)
    ));
    let after = leader.with_raft_state(|state| state.membership_state.effective().clone()).await?;
    assert_eq!(before, after, "denied topology must not append a membership entry");
    index += router.client_request_many(0, "still-applied", 16).await?;
    router
        .wait_for_log(
            &btreeset! {0, 1},
            Some(index),
            Some(Duration::from_secs(5)),
            "existing streams still progress",
        )
        .await?;
    for id in [0, 1] {
        router.get_raft_handle(&id)?.shutdown().await?;
    }
    Ok(())
}
