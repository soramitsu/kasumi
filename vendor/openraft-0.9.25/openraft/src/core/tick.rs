//! tick emitter emits a `RaftMsg::Tick` event at a certain interval.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use futures::future::Either;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::Mutex as AsyncMutex;
use tracing::Instrument;
use tracing::Level;
use tracing::Span;

use crate::core::notify::Notify;
use crate::type_config::alias::JoinErrorOf;
use crate::type_config::alias::JoinHandleOf;
use crate::type_config::TypeConfigExt;
use crate::RaftTypeConfig;

/// Emit RaftMsg::Tick event at regular `interval`.
pub(crate) struct Tick<C>
where C: RaftTypeConfig
{
    interval: Duration,

    tx: mpsc::UnboundedSender<Notify<C>>,

    /// Emit event or not
    enabled: Arc<AtomicBool>,
}

pub(crate) struct TickHandle<C>
where C: RaftTypeConfig
{
    enabled: Arc<AtomicBool>,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
    task: AsyncMutex<TickState<C>>,
}

enum TickState<C: RaftTypeConfig> {
    Running(JoinHandleOf<C, ()>),
    Done(Result<(), Arc<JoinErrorOf<C>>>),
}

impl<C> Drop for TickHandle<C>
where C: RaftTypeConfig
{
    /// Signal the tick loop to stop, without waiting for it to stop.
    fn drop(&mut self) {
        self.stop();
    }
}

impl<C> Tick<C>
where C: RaftTypeConfig
{
    pub(crate) fn spawn(interval: Duration, tx: mpsc::UnboundedSender<Notify<C>>, enabled: bool) -> TickHandle<C> {
        let enabled = Arc::new(AtomicBool::from(enabled));
        let this = Self {
            interval,
            enabled: enabled.clone(),
            tx,
        };

        let (shutdown, shutdown_rx) = oneshot::channel();

        let shutdown = Mutex::new(Some(shutdown));

        let join_handle = C::spawn(this.tick_loop(shutdown_rx).instrument(tracing::span!(
            parent: &Span::current(),
            Level::DEBUG,
            "tick"
        )));

        TickHandle {
            enabled,
            shutdown,
            task: AsyncMutex::new(TickState::Running(join_handle)),
        }
    }

    pub(crate) async fn tick_loop(self, cancel_rx: oneshot::Receiver<()>) {
        let mut i = 0;

        let mut cancel = std::pin::pin!(cancel_rx);

        loop {
            let at = C::now() + self.interval;
            let sleep_fut = C::sleep_until(at);
            let sleep_fut = std::pin::pin!(sleep_fut);
            let cancel_fut = cancel.as_mut();

            match futures::future::select(cancel_fut, sleep_fut).await {
                Either::Left((_canceled, _)) => {
                    tracing::info!("TickLoop received cancel signal, quit");
                    return;
                }
                Either::Right((_, _)) => {
                    // sleep done
                }
            }

            if !self.enabled.load(Ordering::Relaxed) {
                continue;
            }

            i += 1;

            let send_res = self.tx.send(Notify::Tick { i });
            if let Err(_e) = send_res {
                tracing::info!("Stopping tick_loop(), main loop terminated");
                break;
            } else {
                tracing::debug!("Tick sent: {}", i)
            }
        }
    }
}

impl<C> TickHandle<C>
where C: RaftTypeConfig
{
    /// Controlled actual task ownership for shutdown interleaving regressions.
    #[cfg(test)]
    pub(crate) fn retain_test_task(task: JoinHandleOf<C, ()>) -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(false)),
            shutdown: Mutex::new(None),
            task: AsyncMutex::new(TickState::Running(task)),
        }
    }

    pub(crate) fn enable(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Signal without transferring ownership of the task handle.
    pub(crate) fn stop(&self) {
        if let Some(shutdown) = self.shutdown.lock().unwrap().take() {
            let send_res = shutdown.send(());
            tracing::info!("Timer shutdown signal sent: {send_res:?}");
        }
    }

    /// Join in place so cancellation retains both the handle and its outcome.
    pub(crate) async fn shutdown(&self) -> Result<(), Arc<JoinErrorOf<C>>> {
        self.stop();
        let mut task = self.task.lock().await;
        if let TickState::Running(handle) = &mut *task {
            let outcome = handle.await.map_err(Arc::new);
            // No yield between observing completion and retaining its result.
            *task = TickState::Done(outcome);
        }
        let TickState::Done(outcome) = &*task else {
            unreachable!("ticker task was joined above")
        };
        outcome.clone()
    }
}

#[cfg(all(test, not(feature = "singlethreaded")))]
mod tests {
    use std::future::Future;
    use std::io::Cursor;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::task::Poll;

    use tokio::sync::oneshot;
    use tokio::sync::Mutex as AsyncMutex;
    use tokio::time::Duration;

    use super::TickHandle;
    use super::TickState;
    use crate::core::Tick;
    use crate::type_config::TypeConfigExt;
    use crate::RaftTypeConfig;
    use crate::TokioRuntime;

    #[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    pub(crate) struct TickUTConfig {}
    impl RaftTypeConfig for TickUTConfig {
        type D = ();
        type R = ();
        type NodeId = u64;
        type Node = ();
        type Entry = crate::Entry<TickUTConfig>;
        type SnapshotData = Cursor<Vec<u8>>;
        type AsyncRuntime = TokioRuntime;
        type Responder = crate::impls::OneshotResponder<Self>;
    }

    // AsyncRuntime::spawn is `spawn_local` with singlethreaded enabled.
    // It will result in a panic:
    // `spawn_local` called from outside of a `task::LocalSet`.
    #[cfg(not(feature = "singlethreaded"))]
    #[tokio::test]
    async fn test_shutdown() -> anyhow::Result<()> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let th = Tick::<TickUTConfig>::spawn(Duration::from_millis(100), tx, true);

        TickUTConfig::sleep(Duration::from_millis(500)).await;
        th.shutdown().await?;
        TickUTConfig::sleep(Duration::from_millis(500)).await;

        let mut received = vec![];
        while let Some(x) = rx.recv().await {
            received.push(x);
        }

        assert!(
            received.len() < 10,
            "no more tick will be received after shutdown: {}",
            received.len()
        );

        Ok(())
    }

    /// Real task ownership and failure survive cancellation of both the first
    /// join and a concurrent waiter. No timer or simulated completion is used.
    #[cfg(not(feature = "singlethreaded"))]
    #[tokio::test]
    async fn cancelled_ticker_shutdown_retains_task_and_terminal_outcome() -> anyhow::Result<()> {
        for panic in [false, true] {
            let owner = Arc::new(());
            let retained = owner.clone();
            let (release, waiting) = oneshot::channel();
            let (stop, stopped) = oneshot::channel();
            let handle = tokio::spawn(async move {
                let _retained = retained;
                let _ = stopped.await;
                let _ = waiting.await;
                assert!(!panic, "injected ticker panic after drain cancellation");
            });
            let ticker = TickHandle::<TickUTConfig> {
                enabled: Arc::new(AtomicBool::new(true)),
                shutdown: Mutex::new(Some(stop)),
                task: AsyncMutex::new(TickState::Running(handle)),
            };
            let mut first = Box::pin(ticker.shutdown());
            std::future::poll_fn(|cx| {
                assert!(first.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            let mut concurrent = Box::pin(ticker.shutdown());
            std::future::poll_fn(|cx| {
                assert!(concurrent.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(first);
            drop(concurrent);
            assert_eq!(Arc::strong_count(&owner), 2);
            release.send(()).unwrap();
            let result = tokio::time::timeout(Duration::from_secs(5), ticker.shutdown()).await?;
            assert_eq!(Arc::strong_count(&owner), 1);
            if panic {
                let first = result.unwrap_err();
                assert!(first.is_panic());
                let original = Arc::downgrade(&first);
                drop(first);
                let next = ticker.shutdown().await.unwrap_err();
                assert!(Arc::ptr_eq(
                    &original.upgrade().expect("ticker must retain original error"),
                    &next
                ));
            } else {
                result.unwrap();
                ticker.shutdown().await.unwrap();
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "singlethreaded"))]
    #[tokio::test]
    async fn runtime_cancelled_ticker_is_never_reported_as_normal_shutdown() -> anyhow::Result<()> {
        let (stop, _stopped) = oneshot::channel();
        let handle = tokio::spawn(std::future::pending::<()>());
        let task_id = handle.id();
        handle.abort();
        let ticker = TickHandle::<TickUTConfig> {
            enabled: Arc::new(AtomicBool::new(true)),
            shutdown: Mutex::new(Some(stop)),
            task: AsyncMutex::new(TickState::Running(handle)),
        };
        let first = ticker.shutdown().await.unwrap_err();
        assert!(first.is_cancelled());
        assert_eq!(first.id(), task_id);
        let again = ticker.shutdown().await.unwrap_err();
        assert!(Arc::ptr_eq(&first, &again));
        Ok(())
    }
}
