use std::future::Future;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Poll;
use std::time::Duration;

use anyhow::Result;
use maplit::btreeset;
use openraft::error::AuxiliaryTaskKind;
use openraft::error::CheckIsLeaderError;
use openraft::error::RaftError;
use openraft::Config;
use openraft::RPCTypes;

use crate::fixtures::init_default_ut_tracing;
use crate::fixtures::RPCRequest;
use crate::fixtures::RaftRouter;

fn config() -> Arc<Config> {
    Arc::new(
        Config {
            enable_tick: false,
            enable_heartbeat: false,
            heartbeat_interval: 5_000,
            election_timeout_min: 5_001,
            election_timeout_max: 5_002,
            max_retained_auxiliary_owners: 2,
            ..Default::default()
        }
        .validate()
        .unwrap(),
    )
}

#[async_entry::test(
    worker_threads = 8,
    init = "init_default_ut_tracing()",
    tracing_span = "debug"
)]
async fn abandoned_read_and_shutdown_keep_actual_collector_panic() -> Result<()> {
    let mut router = RaftRouter::new(config());
    router.new_cluster(btreeset! {0, 1}, btreeset! {}).await?;
    let leader = router.get_raft_handle(&0)?;
    leader.ensure_linearizable().await?;
    let (entered, entry) = tokio::sync::oneshot::channel();
    let (release, waiting) = tokio::sync::oneshot::channel();
    let channels = Arc::new(Mutex::new(Some((entered, waiting))));
    router.set_rpc_async_pre_hook(RPCTypes::AppendEntries, move |req, from, to| {
        let channels = channels.clone();
        async move {
            if from == 0
                && to == 1
                && matches!(req, RPCRequest::AppendEntries(ref req) if req.entries.is_empty())
            {
                let next = channels.lock().unwrap().take();
                if let Some((entered, waiting)) = next {
                    entered.send(tokio::task::id()).unwrap();
                    waiting.await.unwrap();
                    panic!("actual retained leadership collector panic");
                }
            }
        }
    });
    let calling = leader.clone();
    let caller = tokio::spawn(async move { calling.ensure_linearizable().await });
    let original_id = tokio::time::timeout(Duration::from_secs(2), entry).await??;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    let mut drain = Box::pin(leader.shutdown());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(drain);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), leader.shutdown())
            .await
            .is_err()
    );
    release.send(()).unwrap();
    let first = tokio::time::timeout(Duration::from_secs(2), leader.shutdown())
        .await?
        .unwrap_err();
    assert_eq!(first.auxiliary().len(), 1);
    assert_eq!(first.auxiliary()[0].kind, AuxiliaryTaskKind::LeadershipRead);
    let error = first.auxiliary()[0].error.join_error().unwrap();
    assert!(error.is_panic());
    assert_eq!(error.id(), original_id);
    let again = leader.shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(
        error,
        again.auxiliary()[0].error.join_error().unwrap()
    ));
    router.get_raft_handle(&1)?.shutdown().await?;
    Ok(())
}

#[async_entry::test(
    worker_threads = 8,
    init = "init_default_ut_tracing()",
    tracing_span = "debug"
)]
async fn actual_vote_round_panic_fences_live_core_and_remains_original() -> Result<()> {
    let mut router = RaftRouter::new(config());
    router.new_raft_node(0).await;
    router.new_raft_node(1).await;
    let (entered, entry) = tokio::sync::oneshot::channel();
    let (release, waiting) = tokio::sync::oneshot::channel();
    let channels = Arc::new(Mutex::new(Some((entered, waiting))));
    router.set_rpc_async_pre_hook(RPCTypes::Vote, move |_, from, to| {
        let channels = channels.clone();
        async move {
            if from == 0 && to == 1 {
                let next = channels.lock().unwrap().take();
                if let Some((entered, waiting)) = next {
                    entered.send(tokio::task::id()).unwrap();
                    waiting.await.unwrap();
                    panic!("actual retained vote collector panic");
                }
            }
        }
    });
    let node = router.get_raft_handle(&0)?;
    node.initialize(btreeset! {0, 1}).await?;
    let original_id = tokio::time::timeout(Duration::from_secs(2), entry).await??;
    release.send(()).unwrap();
    let mut metrics = node.metrics();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if metrics.borrow().running_state.is_err() {
                break;
            }
            metrics.changed().await.unwrap();
        }
    })
    .await?;
    let first = node.shutdown().await.unwrap_err();
    assert_eq!(first.auxiliary().len(), 1);
    assert_eq!(first.auxiliary()[0].kind, AuxiliaryTaskKind::VoteRound);
    let error = first.auxiliary()[0].error.join_error().unwrap();
    assert!(error.is_panic());
    assert_eq!(error.id(), original_id);
    let again = node.shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(
        error,
        again.auxiliary()[0].error.join_error().unwrap()
    ));
    router.get_raft_handle(&1)?.shutdown().await?;
    Ok(())
}

#[async_entry::test(
    worker_threads = 8,
    init = "init_default_ut_tracing()",
    tracing_span = "debug"
)]
async fn full_read_capacity_keeps_existing_replication_and_application_running() -> Result<()> {
    let mut router = RaftRouter::new(config());
    router.new_cluster(btreeset! {0, 1}, btreeset! {}).await?;
    let leader = router.get_raft_handle(&0)?;
    leader.ensure_linearizable().await?;
    let (entered, entry) = tokio::sync::oneshot::channel();
    let (release, waiting) = tokio::sync::oneshot::channel();
    let channels = Arc::new(Mutex::new(Some((entered, waiting))));
    router.set_rpc_async_pre_hook(RPCTypes::AppendEntries, move |req, from, to| {
        let channels = channels.clone();
        async move {
            if from == 0
                && to == 1
                && matches!(req, RPCRequest::AppendEntries(ref req) if req.entries.is_empty())
            {
                let next = channels.lock().unwrap().take();
                if let Some((entered, waiting)) = next {
                    entered.send(()).unwrap();
                    waiting.await.unwrap();
                }
            }
        }
    });
    let calling = leader.clone();
    let caller = tokio::spawn(async move { calling.ensure_linearizable().await });
    tokio::time::timeout(Duration::from_secs(2), entry).await??;
    assert!(matches!(
        leader.ensure_linearizable().await,
        Err(RaftError::APIError(CheckIsLeaderError::TaskCapacity(_)))
    ));
    tokio::time::timeout(
        Duration::from_secs(2),
        router.client_request(0, "capacity", 1),
    )
    .await??;
    release.send(()).unwrap();
    caller.await??;
    leader.ensure_linearizable().await?;
    leader.shutdown().await?;
    router.get_raft_handle(&1)?.shutdown().await?;
    Ok(())
}

#[async_entry::test(
    worker_threads = 8,
    init = "init_default_ut_tracing()",
    tracing_span = "debug"
)]
async fn quorum_completion_drops_remaining_inline_peer_future_in_same_actual_task() -> Result<()> {
    struct PeerDrop(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for PeerDrop {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
        }
    }
    let mut router = RaftRouter::new(config());
    router
        .new_cluster(btreeset! {0, 1, 2}, btreeset! {})
        .await?;
    let leader = router.get_raft_handle(&0)?;
    leader.ensure_linearizable().await?;
    let (entered, entry) = tokio::sync::oneshot::channel();
    let (dropped, drop_observation) = tokio::sync::oneshot::channel();
    let first = Arc::new(Mutex::new(Some((entered, dropped))));
    let second = Arc::new(Mutex::new(Some(entry)));
    let identities = Arc::new(Mutex::new(Vec::new()));
    let ids = identities.clone();
    router.set_rpc_async_pre_hook(RPCTypes::AppendEntries, move |req, from, to| {
        let (first, second, ids) = (first.clone(), second.clone(), ids.clone());
        async move {
            if from != 0
                || !matches!(req, RPCRequest::AppendEntries(ref req) if req.entries.is_empty())
            {
                return;
            }
            if to == 1 {
                let next = first.lock().unwrap().take();
                if let Some((entered, dropped)) = next {
                    let guard = PeerDrop(Some(dropped));
                    ids.lock().unwrap().push(tokio::task::id());
                    entered.send(()).unwrap();
                    std::future::pending::<()>().await;
                    drop(guard);
                }
            } else if to == 2 {
                let next = second.lock().unwrap().take();
                if let Some(entry) = next {
                    entry.await.unwrap();
                    ids.lock().unwrap().push(tokio::task::id());
                }
            }
        }
    });
    leader.ensure_linearizable().await?;
    tokio::time::timeout(Duration::from_secs(2), drop_observation).await??;
    let ids = identities.lock().unwrap().clone();
    assert_eq!(ids.len(), 2);
    assert_eq!(
        ids[0], ids[1],
        "all peer futures belong to one actual collector"
    );
    for id in [0, 1, 2] {
        router.get_raft_handle(&id)?.shutdown().await?;
    }
    Ok(())
}
