//! Startup tasks retain unopened/unpublished runtime resources through cancellation.
//! A successful oneshot send is not transfer: only the recipient's synchronous
//! ticket claim moves the runtime. Every abandoned result is closed and joined.
use anyhow::{Context, Result};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
};
use tokio::sync::{Mutex as AsyncMutex, Notify, oneshot};

type Tasks = AsyncMutex<Vec<tokio::task::JoinHandle<Result<()>>>>;

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Data,
    Authority,
}

fn tasks(kind: Kind) -> &'static Tasks {
    static DATA: OnceLock<Tasks> = OnceLock::new();
    static AUTHORITY: OnceLock<Tasks> = OnceLock::new();
    match kind {
        Kind::Data => &DATA,
        Kind::Authority => &AUTHORITY,
    }
    .get_or_init(Default::default)
}

struct Handoff<T> {
    value: Mutex<Option<T>>,
    decided: Notify,
}
struct Ticket<T>(Arc<Handoff<T>>);
impl<T> Ticket<T> {
    fn claim(self) -> T {
        self.0
            .value
            .lock()
            .expect("startup handoff lock poisoned")
            .take()
            .expect("private startup ticket is consumed only once")
    }
}
impl<T> Drop for Ticket<T> {
    fn drop(&mut self) {
        self.0.decided.notify_one();
    }
}

pub(crate) trait Runtime: Send + 'static {
    fn close(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}

/// A failed drain is never permission to discard its owner. Retry only the
/// same idempotent shutdown; this cannot reacquire credentials or reopen files.
/// The joinable startup task remains live until actual owner drain succeeds.
pub(crate) async fn finish(runtime: &mut impl Runtime) -> Result<()> {
    let mut failure = None;
    let mut delay = std::time::Duration::from_secs(1);
    loop {
        match runtime.close().await {
            Ok(()) => return failure.map_or(Ok(()), Err),
            Err(error) => {
                tracing::error!(error = %error, retry_after_secs = delay.as_secs(), "startup owner drain failed; retaining resources for retry");
                failure.get_or_insert(error);
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(std::time::Duration::from_secs(30));
            }
        }
    }
}

pub(crate) async fn open<T, Opening>(kind: Kind, opening: Opening) -> Result<T>
where
    T: Runtime,
    Opening: Future<Output = Result<T>> + Send + 'static,
{
    let receive = begin(tasks(kind), opening).await?;
    // No await or fallible work between actual receipt and public ownership.
    Ok(receive.await.context("startup owner stopped")??.claim())
}

async fn begin<T, Opening>(
    tasks: &Tasks,
    opening: Opening,
) -> Result<oneshot::Receiver<Result<Ticket<T>>>>
where
    T: Runtime,
    Opening: Future<Output = Result<T>> + Send + 'static,
{
    let (send, receive) = oneshot::channel();
    let mut tasks = tasks.lock().await;
    while let Some(index) = tasks.iter().position(tokio::task::JoinHandle::is_finished) {
        let result = (&mut tasks[index]).await;
        drop(tasks.swap_remove(index));
        result.context("prior startup owner panicked")??;
    }
    tasks.push(tokio::spawn(async move {
        match Box::pin(opening).await {
            Err(error) => match send.send(Err(error)) {
                Ok(()) => Ok(()),
                Err(Err(error)) => Err(error),
                Err(Ok(_)) => unreachable!("startup error delivery cannot contain a runtime"),
            },
            Ok(runtime) => deliver(runtime, send).await,
        }
    }));
    Ok(receive)
}

async fn deliver<T: Runtime>(runtime: T, send: oneshot::Sender<Result<Ticket<T>>>) -> Result<()> {
    let handoff = Arc::new(Handoff {
        value: Mutex::new(Some(runtime)),
        decided: Notify::new(),
    });
    let _ = send.send(Ok(Ticket(handoff.clone())));
    handoff.decided.notified().await;
    let abandoned = handoff
        .value
        .lock()
        .expect("startup handoff lock poisoned")
        .take();
    if let Some(mut runtime) = abandoned {
        finish(&mut runtime).await?;
    }
    Ok(())
}

/// Stop admitting new open calls before this final drain. Cancellation retains
/// every unfinished handle; committed runtimes are never closed by this registry.
pub(crate) async fn drain(kind: Kind) -> Result<()> {
    drain_tasks(tasks(kind)).await
}
async fn drain_tasks(tasks: &Tasks) -> Result<()> {
    let mut tasks = tasks.lock().await;
    let mut failure = None;
    while let Some(task) = tasks.last_mut() {
        let result = task.await;
        tasks.pop();
        if let Err(error) = result
            .context("startup owner panicked")
            .and_then(|result| result)
        {
            failure.get_or_insert(error);
        }
    }
    failure.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        task::Poll,
        time::Duration,
    };

    #[derive(Default)]
    struct Observation {
        attempts: AtomicUsize,
        closed: AtomicBool,
        dropped: AtomicBool,
        entered: Notify,
        release: Notify,
    }
    struct Candidate {
        observation: Arc<Observation>,
        fail_once: bool,
    }
    impl Drop for Candidate {
        fn drop(&mut self) {
            self.observation.dropped.store(true, Ordering::Release);
        }
    }
    impl Runtime for Candidate {
        fn close(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            Box::pin(async move {
                let attempt = self.observation.attempts.fetch_add(1, Ordering::AcqRel);
                self.observation.entered.notify_one();
                if self.fail_once && attempt == 0 {
                    anyhow::bail!("injected drain failure");
                }
                self.observation.release.notified().await;
                self.observation.closed.store(true, Ordering::Release);
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn buffered_startup_ticket_drain_is_joinable_after_result_receiver_cancellation()
    -> Result<()> {
        let observation = Arc::new(Observation::default());
        let candidate = Candidate {
            observation: observation.clone(),
            fail_once: false,
        };
        let (send, receive) = oneshot::channel();
        let delivery = deliver(candidate, send);
        tokio::pin!(delivery);
        std::future::poll_fn(|context| {
            assert!(delivery.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(receive);
        std::future::poll_fn(|context| {
            assert!(delivery.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(observation.attempts.load(Ordering::Acquire), 1);
        assert!(!observation.dropped.load(Ordering::Acquire));
        observation.release.notify_one();
        tokio::time::timeout(Duration::from_secs(5), delivery).await??;
        assert!(observation.closed.load(Ordering::Acquire));
        assert!(observation.dropped.load(Ordering::Acquire));
        Ok(())
    }

    #[tokio::test]
    async fn claimed_startup_runtime_is_never_closed_by_the_initializer_registry() -> Result<()> {
        let tasks = Tasks::default();
        let observation = Arc::new(Observation::default());
        let candidate = Candidate {
            observation: observation.clone(),
            fail_once: false,
        };
        let receive = begin(&tasks, async move { Ok(candidate) }).await?;
        let ticket = tokio::time::timeout(Duration::from_secs(5), receive).await???;
        let mut runtime = ticket.claim();
        tokio::time::timeout(Duration::from_secs(5), drain_tasks(&tasks)).await??;
        assert_eq!(observation.attempts.load(Ordering::Acquire), 0);
        assert!(!observation.dropped.load(Ordering::Acquire));
        observation.release.notify_one();
        runtime.close().await?;
        drop(runtime);
        assert!(observation.dropped.load(Ordering::Acquire));
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_waiter_retains_open_work_and_failed_drain_until_actual_completion()
    -> Result<()> {
        let tasks = Tasks::default();
        let observation = Arc::new(Observation::default());
        let candidate = Candidate {
            observation: observation.clone(),
            fail_once: true,
        };
        let (resume, resumed) = oneshot::channel();
        let receive = begin(&tasks, async move {
            resumed.await?;
            Ok(candidate)
        })
        .await?;
        drop(receive);
        let draining = drain_tasks(&tasks);
        tokio::pin!(draining);
        std::future::poll_fn(|context| {
            assert!(draining.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(!observation.dropped.load(Ordering::Acquire));
        resume.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), observation.entered.notified()).await?;
        assert!(!observation.dropped.load(Ordering::Acquire));
        observation.release.notify_one();
        // The actual retry must drain, and the original failure remains an error.
        let result = tokio::time::timeout(Duration::from_secs(5), draining).await?;
        assert!(result.is_err());
        assert!(observation.attempts.load(Ordering::Acquire) >= 2);
        assert!(observation.closed.load(Ordering::Acquire));
        assert!(observation.dropped.load(Ordering::Acquire));
        assert!(tasks.lock().await.is_empty());
        Ok(())
    }
}
