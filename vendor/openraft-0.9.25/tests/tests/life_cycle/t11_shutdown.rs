use std::sync::Arc;

use anyhow::Result;
use maplit::btreeset;
use openraft::error::Fatal;
use openraft::Config;
use openraft::ServerState;

use crate::fixtures::init_default_ut_tracing;
use crate::fixtures::RaftRouter;

/// Shutdown raft node and check the metrics change.
#[async_entry::test(
    worker_threads = 8,
    init = "init_default_ut_tracing()",
    tracing_span = "debug"
)]
async fn shutdown() -> Result<()> {
    let config = Arc::new(
        Config {
            enable_heartbeat: false,
            ..Default::default()
        }
        .validate()?,
    );

    let mut router = RaftRouter::new(config.clone());
    let _log_index = router.new_cluster(btreeset! {0,1,2}, btreeset! {}).await?;

    tracing::info!("--- performing node shutdowns");
    {
        for i in [0, 1, 2] {
            let (node, _, _) = router.remove_node(i).unwrap();
            node.shutdown().await?;
            node.shutdown().await?;
            let m = node.metrics();
            assert_eq!(
                ServerState::Shutdown,
                m.borrow().state,
                "shutdown node-{}",
                i
            );
        }
    }

    Ok(())
}

/// A panicked RaftCore should also return a proper error the next time accessing the `Raft`.
#[async_entry::test(
    worker_threads = 8,
    init = "init_default_ut_tracing()",
    tracing_span = "debug"
)]
async fn return_error_after_panic() -> Result<()> {
    let config = Arc::new(
        Config {
            enable_heartbeat: false,
            ..Default::default()
        }
        .validate()?,
    );

    let mut router = RaftRouter::new(config.clone());

    tracing::info!("--- initializing cluster");
    let log_index = router.new_cluster(btreeset! {0}, btreeset! {}).await?;
    let _ = log_index; // unused;

    tracing::info!(log_index, "--- panic the RaftCore");
    {
        router.external_request(0, |_s| {
            panic!("foo");
        });
    }

    tracing::info!(
        log_index,
        "--- calls the panicked raft should get a Fatal::Panicked error"
    );
    {
        let res = router.client_request(0, "foo", 2).await;
        let err = res.unwrap_err();
        assert_eq!(Fatal::Panicked, err.into_fatal().unwrap());
    }

    let node = router.get_raft_handle(&0)?;
    let first = node.shutdown().await.unwrap_err();
    assert_eq!(first.core(), Some(&Fatal::Panicked));
    assert!(first.ticker().is_none());
    assert!(first.core_join_error().unwrap().is_panic());
    let again = node.shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(
        first.core_join_error().unwrap(),
        again.core_join_error().unwrap()
    ));

    Ok(())
}

/// Cancellation while the real core is still executing an admitted callback
/// must retain its later panic for both resumed and repeated shutdown calls.
#[async_entry::test(
    worker_threads = 8,
    init = "init_default_ut_tracing()",
    tracing_span = "debug"
)]
async fn cancelled_shutdown_retains_later_core_failure() -> Result<()> {
    use std::future::Future;
    use std::task::Poll;
    use std::time::Duration;

    let config = Arc::new(Config::default().validate()?);
    let mut router = RaftRouter::new(config);
    router.new_cluster(btreeset! {0}, btreeset! {}).await?;
    let node = router.get_raft_handle(&0)?;
    let (entered, entry) = tokio::sync::oneshot::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    node.external_request(move |_| {
        let _ = entered.send(());
        let _ = waiting.recv_timeout(Duration::from_secs(10));
        panic!("injected core panic after shutdown cancellation");
    });
    tokio::time::timeout(Duration::from_secs(5), entry).await??;
    let mut first = Box::pin(node.shutdown());
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(first);
    release.send(())?;
    let error = tokio::time::timeout(Duration::from_secs(5), node.shutdown())
        .await?
        .unwrap_err();
    assert_eq!(error.core(), Some(&Fatal::Panicked));
    assert!(error.ticker().is_none());
    assert!(error.core_join_error().unwrap().is_panic());
    let original = Arc::downgrade(error.core_join_error().unwrap());
    drop(error);
    let again = node.shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(
        &original.upgrade().unwrap(),
        again.core_join_error().unwrap()
    ));
    Ok(())
}

/// A real state machine worker panic stops the core and preserves its exact
/// runtime failure independently of the core's wire classification.
#[async_entry::test(
    worker_threads = 8,
    init = "init_default_ut_tracing()",
    tracing_span = "debug"
)]
async fn return_error_when_sm_worker_dies() -> Result<()> {
    let config = Arc::new(
        Config {
            enable_heartbeat: false,
            ..Default::default()
        }
        .validate()?,
    );

    let mut router = RaftRouter::new(config.clone());

    tracing::info!("--- initializing cluster");
    let _log_index = router.new_cluster(btreeset! {0}, btreeset! {}).await?;

    tracing::info!("--- arm the state machine to panic when it begins receiving a snapshot");
    {
        let (_log_store, sm) = router.get_storage_handle(&0)?;
        sm.storage_mut()
            .await
            .set_panic_on_begin_receiving_snapshot(true);
    }

    tracing::info!("--- the call kills the sm worker; it must return instead of hanging");
    {
        let raft = router.get_raft_handle(&0)?;
        let err = raft.begin_receiving_snapshot().await.unwrap_err();
        assert_eq!(Fatal::Panicked, err.into_fatal().unwrap());
    }

    tracing::info!("--- later calls observe the same worker panic classification");
    {
        let raft = router.get_raft_handle(&0)?;
        let err = raft.get_snapshot().await.unwrap_err();
        assert_eq!(Fatal::Panicked, err.into_fatal().unwrap());
    }

    let node = router.get_raft_handle(&0)?;
    let first = node.shutdown().await.unwrap_err();
    assert_eq!(first.core(), Some(&Fatal::Panicked));
    assert!(
        first.core_join_error().is_none(),
        "the core returned its fatal classification normally"
    );
    let original = first.state_machine().unwrap().join_error().unwrap();
    assert!(original.is_panic());
    let again = node.shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(
        original,
        again.state_machine().unwrap().join_error().unwrap()
    ));

    Ok(())
}

/// After shutdown(), access to Raft should return a Fatal::Stopped error.
#[async_entry::test(
    worker_threads = 8,
    init = "init_default_ut_tracing()",
    tracing_span = "debug"
)]
async fn return_error_after_shutdown() -> Result<()> {
    let config = Arc::new(
        Config {
            enable_heartbeat: false,
            ..Default::default()
        }
        .validate()?,
    );

    let mut router = RaftRouter::new(config.clone());

    tracing::info!("--- initializing cluster");
    let log_index = router.new_cluster(btreeset! {0}, btreeset! {}).await?;
    let _ = log_index; // unused;

    tracing::info!(log_index, "--- shutdown the raft");
    {
        let n = router.get_raft_handle(&0)?;
        n.shutdown().await?;
    }

    tracing::info!(
        log_index,
        "--- calls the panicked raft should get a Fatal::Panicked error"
    );
    {
        let res = router.client_request(0, "foo", 2).await;
        let err = res.unwrap_err();
        assert_eq!(Fatal::Stopped, err.into_fatal().unwrap());
    }

    Ok(())
}

/// Poll the real constructor into a storage await on its own runtime. Runtime
/// task counts establish that abandoning startup has no ticker/core/worker to
/// detach, independently of whether those children would terminate soon later.
#[tokio::test(flavor = "current_thread")]
async fn cancelled_initial_storage_load_has_no_spawned_children() {
    use crate::fixtures::MemRaft;
    use openraft::storage::Adaptor;
    use openraft_memstore::{BlockOperation, MemStore};
    use std::future::Future;
    use std::task::Poll;
    use std::time::Duration;

    let config = Arc::new(Config::default().validate().unwrap());
    let router = RaftRouter::new(config.clone());
    let store = Arc::new(MemStore::new());
    store.set_blocking(BlockOperation::ReadVote, Duration::from_secs(10));
    let (log, machine) = Adaptor::new(store);
    let runtime = tokio::runtime::Handle::current();
    let before = runtime.metrics().num_alive_tasks();
    let mut startup = Box::pin(MemRaft::new(0, config, router, log, machine));
    std::future::poll_fn(|cx| {
        assert!(startup.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(
        runtime.metrics().num_alive_tasks(),
        before,
        "initial storage loading must precede every spawn"
    );
    drop(startup);
    assert_eq!(
        runtime.metrics().num_alive_tasks(),
        before,
        "cancelled startup must own no detached child"
    );
}
