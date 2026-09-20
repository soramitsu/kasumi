//! Retained listener task inventory. Hyper's HTTP/2 executor uses this same
//! ownership protocol as connections; joining a socket alone is not completion.
use kasumi_types::drain::{DrainReport, DrainResult};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{
    sync::watch,
    task::{Id, JoinSet},
};

struct State {
    tasks: JoinSet<()>,
    sealed: bool,
    maximum: usize,
    report: DrainReport,
    requested_aborts: BTreeSet<Id>,
    aborts: BTreeMap<Id, tokio::task::AbortHandle>,
}
impl State {
    fn observe(&mut self, result: std::result::Result<(Id, ()), tokio::task::JoinError>) {
        let id = match &result {
            Ok((id, ())) => *id,
            Err(error) => error.id(),
        };
        self.aborts.remove(&id);
        let abort_requested = self.requested_aborts.remove(&id);
        if let Err(error) = result
            && !(abort_requested && error.is_cancelled())
        {
            // First failure seals admission. At most the installed concurrent
            // inventory can subsequently fail; successful history is discarded.
            let slot = self.report.issues().len();
            self.report.record("TLS task", slot, error.into());
            self.sealed = true;
        }
    }
    fn try_reap(&mut self) {
        while let Some(outcome) = self.tasks.try_join_next_with_id() {
            self.observe(outcome);
        }
    }
    fn reap_ready(&mut self, cx: &mut Context<'_>) {
        while let Poll::Ready(Some(outcome)) = self.tasks.poll_join_next_with_id(cx) {
            self.observe(outcome);
        }
    }
}

#[derive(Clone)]
pub(crate) struct Tasks {
    state: Arc<Mutex<State>>,
    failed: watch::Sender<bool>,
    draining: Arc<tokio::sync::Mutex<()>>,
}
impl Tasks {
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                tasks: JoinSet::new(),
                sealed: false,
                maximum,
                report: Default::default(),
                requested_aborts: BTreeSet::new(),
                aborts: BTreeMap::new(),
            })),
            failed: watch::channel(false).0,
            draining: Default::default(),
        }
    }
    pub(crate) fn failure(&self) -> watch::Receiver<bool> {
        self.failed.subscribe()
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .tasks
            .is_empty()
    }
    pub(crate) async fn next(&self) {
        std::future::poll_fn(|cx| {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            match state.tasks.poll_join_next_with_id(cx) {
                Poll::Ready(Some(outcome)) => {
                    state.observe(outcome);
                    if state.sealed {
                        self.failed.send_replace(true);
                    }
                    Poll::Ready(())
                }
                Poll::Ready(None) => Poll::Ready(()),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }
    pub(crate) fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.sealed {
            self.failed.send_replace(true);
            return;
        }
        state.try_reap();
        if !state.sealed && state.tasks.len() >= state.maximum {
            state.report.record(
                "TLS task budget",
                0,
                anyhow::anyhow!("TLS executor task budget exhausted"),
            );
            state.sealed = true;
        }
        if state.sealed {
            self.failed.send_replace(true);
            return;
        }
        let abort = state.tasks.spawn(future);
        state.aborts.insert(abort.id(), abort);
    }
    pub(crate) async fn drain(&self, timeout: std::time::Duration) -> DrainResult {
        let _draining = self.draining.lock().await;
        self.state.lock().unwrap_or_else(|p| p.into_inner()).sealed = true;
        if tokio::time::timeout(timeout, self.join()).await.is_err() {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.try_reap();
            // Preserve completed external cancellation/panic before requesting
            // abort of remaining task IDs. There are no exposed production abort
            // handles, and all subsequent joins remain in this retained census.
            state.requested_aborts = state
                .aborts
                .values()
                .filter(|task| !task.is_finished())
                .map(|task| task.id())
                .collect();
            state.tasks.abort_all();
        }
        self.join().await;
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .report
            .complete()
    }
    async fn join(&self) {
        std::future::poll_fn(|cx| {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.reap_ready(cx);
            if state.tasks.is_empty() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
}
impl<F> hyper::rt::Executor<F> for Tasks
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, future: F) {
        self.spawn(future);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};
    struct ObservedWake {
        count: AtomicUsize,
        notice: tokio::sync::Notify,
    }
    impl Wake for ObservedWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.count.fetch_add(1, Ordering::AcqRel);
            self.notice.notify_one();
        }
    }
    #[tokio::test]
    async fn sealed_executor_late_spawn_preserves_the_actual_drain_waker() {
        let tasks = Tasks::new(2);
        let (release, waiting) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            waiting.await.unwrap();
        });
        let wake = Arc::new(ObservedWake {
            count: AtomicUsize::new(0),
            notice: Default::default(),
        });
        let waker = Waker::from(wake.clone());
        let mut drain = Box::pin(tasks.drain(std::time::Duration::from_secs(60)));
        assert!(
            drain
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        // A Hyper callback may attempt execute after its connection was stopped.
        // It must neither dispatch this work nor replace the active join waker.
        tasks.spawn(async {
            panic!("sealed executor dispatched late work");
        });
        let before = wake.count.load(Ordering::Acquire);
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while wake.count.load(Ordering::Acquire) == before {
                wake.notice.notified().await;
            }
        })
        .await
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), drain)
            .await
            .unwrap()
            .unwrap();
        assert!(tasks.is_empty());
    }
}
