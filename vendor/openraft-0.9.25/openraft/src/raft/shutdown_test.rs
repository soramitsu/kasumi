//! Exercise the real Raft shutdown owner with controlled Tokio child tasks.
//! This does not run a consensus core, transport or storage implementation.
use std::future::Future;
use std::io::Cursor;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::watch;
use tokio::sync::Mutex;

use super::core_state::CoreState;
use super::raft_inner::RaftInner;
use super::Raft;
use crate::config::RuntimeConfig;
use crate::core::TickHandle;
use crate::error::Fatal;
use crate::error::Infallible;
use crate::metrics::RaftDataMetrics;
use crate::metrics::RaftServerMetrics;
use crate::Config;
use crate::RaftMetrics;
use crate::RaftTypeConfig;
use crate::TokioRuntime;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
struct ShutdownConfig;
impl RaftTypeConfig for ShutdownConfig {
    type D = ();
    type R = ();
    type NodeId = u64;
    type Node = ();
    type Entry = crate::Entry<Self>;
    type SnapshotData = Cursor<Vec<u8>>;
    type AsyncRuntime = TokioRuntime;
    type Responder = crate::impls::OneshotResponder<Self>;
}

struct OwnedTask(Arc<AtomicBool>);
impl Drop for OwnedTask {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

enum CoreExit {
    Normal,
    Panic,
    Abort,
}

struct Fixture {
    raft: Raft<ShutdownConfig>,
    release: oneshot::Sender<()>,
    core_dropped: Arc<AtomicBool>,
    ticker_dropped: Arc<AtomicBool>,
    core_task_id: tokio::task::Id,
    ticker_task_id: tokio::task::Id,
}

async fn fixture(core_exit: CoreExit, ticker_panics: bool) -> Fixture {
    let core_dropped = Arc::new(AtomicBool::new(false));
    let core_owner = OwnedTask(core_dropped.clone());
    let abort = matches!(core_exit, CoreExit::Abort);
    let core: tokio::task::JoinHandle<Result<Infallible, Fatal<u64>>> = tokio::spawn(async move {
        let _owner = core_owner;
        match core_exit {
            CoreExit::Normal => Err(Fatal::Stopped),
            CoreExit::Panic => panic!("controlled core panic"),
            CoreExit::Abort => std::future::pending().await,
        }
    });
    let core_task_id = core.id();
    if abort {
        core.abort();
    }
    let ticker_dropped = Arc::new(AtomicBool::new(false));
    let ticker_owner = OwnedTask(ticker_dropped.clone());
    let (entered, observed) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let ticker = tokio::spawn(async move {
        let _owner = ticker_owner;
        let _ = entered.send(());
        let _ = released.await;
        assert!(!ticker_panics, "controlled ticker panic");
    });
    let ticker_task_id = ticker.id();
    let config = Arc::new(Config::default());
    let inner = RaftInner {
        id: 1,
        runtime_config: Arc::new(RuntimeConfig::new(&config)),
        membership_observer: Arc::default(),
        config,
        tick_handle: TickHandle::retain_test_task(ticker),
        state_machine_tasks: crate::core::sm::tasks::Tasks::completed_test_tasks(),
        replication_tasks: Arc::new(crate::replication::tasks::Registry::new(4)),
        auxiliary_tasks: Arc::new(crate::core::auxiliary::Registry::new(2)),
        tx_api: mpsc::unbounded_channel().0,
        tx_notify: mpsc::unbounded_channel().0,
        rx_metrics: watch::channel(RaftMetrics::new_initial(1)).1,
        rx_data_metrics: watch::channel(RaftDataMetrics::default()).1,
        rx_server_metrics: watch::channel(RaftServerMetrics::default()).1,
        tx_shutdown: Mutex::new(None),
        core_state: Mutex::new(CoreState::Running(core)),
        snapshot: Mutex::new(None),
    };
    tokio::time::timeout(Duration::from_secs(5), observed)
        .await
        .unwrap()
        .unwrap();
    Fixture {
        raft: Raft {
            inner: Arc::new(inner),
        },
        release,
        core_dropped,
        ticker_dropped,
        core_task_id,
        ticker_task_id,
    }
}

async fn cancel_after_core_join(raft: &Raft<ShutdownConfig>) {
    let mut closing = Box::pin(raft.shutdown());
    tokio::time::timeout(
        Duration::from_secs(5),
        std::future::poll_fn(|cx| {
            assert!(
                closing.as_mut().poll(cx).is_pending(),
                "ticker must still be owned"
            );
            // The core JoinHandle wakes this waiter if its join was not ready yet.
            // Once shutdown reaches the held ticker, the exact core result is Done.
            if raft
                .inner
                .core_state
                .try_lock()
                .is_ok_and(|state| matches!(*state, CoreState::Done(_)))
            {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .unwrap();
    drop(closing);
}

#[tokio::test]
async fn cancelled_shutdown_after_core_join_retains_ticker_and_both_failures() {
    for core_panics in [false, true] {
        for ticker_panics in [false, true] {
            let Fixture {
                raft,
                release,
                core_dropped,
                ticker_dropped,
                core_task_id,
                ticker_task_id,
            } = fixture(
                if core_panics {
                    CoreExit::Panic
                } else {
                    CoreExit::Normal
                },
                ticker_panics,
            )
            .await;
            cancel_after_core_join(&raft).await;
            assert!(core_dropped.load(Ordering::Acquire));
            assert!(!ticker_dropped.load(Ordering::Acquire));
            // A second caller must still find the same pending ticker.
            cancel_after_core_join(&raft.clone()).await;
            assert!(!ticker_dropped.load(Ordering::Acquire));
            release.send(()).unwrap();
            let result = tokio::time::timeout(Duration::from_secs(5), raft.shutdown())
                .await
                .unwrap();
            if core_panics || ticker_panics {
                let failure = result.unwrap_err();
                assert_eq!(failure.core(), core_panics.then_some(&Fatal::Panicked));
                assert_eq!(failure.core_join_error().is_some(), core_panics);
                assert_eq!(failure.ticker().is_some(), ticker_panics);
                if let Some(error) = failure.core_join_error() {
                    assert!(error.is_panic());
                    assert_eq!(error.id(), core_task_id);
                }
                if let Some(error) = failure.ticker() {
                    assert!(error.is_panic());
                    assert_eq!(error.id(), ticker_task_id);
                }
                if let (Some(core), Some(ticker)) = (failure.core_join_error(), failure.ticker()) {
                    assert!(
                        !Arc::ptr_eq(core, ticker),
                        "independent tasks retain independent errors"
                    );
                }
                // Neither the returned report nor the initiating facade is the
                // custodian: after dropping both, the peer still has the exact errors.
                let core_error = failure.core_join_error().map(Arc::downgrade);
                let ticker_error = failure.ticker().map(Arc::downgrade);
                drop(failure);
                let peer = raft.clone();
                drop(raft);
                let again = peer.shutdown().await.unwrap_err();
                if let Some(original) = core_error {
                    assert!(Arc::ptr_eq(
                        &original.upgrade().unwrap(),
                        again.core_join_error().unwrap()
                    ));
                }
                if let Some(original) = ticker_error {
                    assert!(Arc::ptr_eq(
                        &original.upgrade().unwrap(),
                        again.ticker().unwrap()
                    ));
                }
            } else {
                result.unwrap();
                raft.shutdown().await.unwrap();
            }
            assert!(ticker_dropped.load(Ordering::Acquire));
        }
    }
}

#[tokio::test]
async fn aborted_core_still_drains_ticker_and_retains_distinct_cancellation() {
    let Fixture {
        raft,
        release,
        core_dropped,
        ticker_dropped,
        core_task_id,
        ticker_task_id,
    } = fixture(CoreExit::Abort, true).await;
    cancel_after_core_join(&raft).await;
    assert!(core_dropped.load(Ordering::Acquire));
    assert!(!ticker_dropped.load(Ordering::Acquire));
    release.send(()).unwrap();
    let failure = tokio::time::timeout(Duration::from_secs(5), raft.shutdown())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.core(), Some(&Fatal::Cancelled));
    assert!(failure.core_join_error().unwrap().is_cancelled());
    assert_eq!(failure.core_join_error().unwrap().id(), core_task_id);
    assert!(failure.ticker().unwrap().is_panic());
    assert_eq!(failure.ticker().unwrap().id(), ticker_task_id);
    assert!(ticker_dropped.load(Ordering::Acquire));
    let again = raft.shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(
        failure.core_join_error().unwrap(),
        again.core_join_error().unwrap()
    ));
    assert!(Arc::ptr_eq(
        failure.ticker().unwrap(),
        again.ticker().unwrap()
    ));
}
