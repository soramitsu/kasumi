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

#[derive(Default)]
struct Registry {
    handles: Vec<tokio::task::JoinHandle<Result<()>>>,
    // Joined failures must outlive a cancelled drain that is still awaiting
    // another owner. Clear only when returning them to a caller without a yield.
    failure: Option<anyhow::Error>,
}
type Tasks = AsyncMutex<Registry>;

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Data,
    Authority,
    LocalOperator,
    TenantEnrollment,
}

fn tasks(kind: Kind) -> &'static Tasks {
    static DATA: OnceLock<Tasks> = OnceLock::new();
    static AUTHORITY: OnceLock<Tasks> = OnceLock::new();
    static LOCAL_OPERATOR: OnceLock<Tasks> = OnceLock::new();
    static TENANT_ENROLLMENT: OnceLock<Tasks> = OnceLock::new();
    match kind {
        Kind::Data => &DATA,
        Kind::Authority => &AUTHORITY,
        Kind::LocalOperator => &LOCAL_OPERATOR,
        Kind::TenantEnrollment => &TENANT_ENROLLMENT,
    }
    .get_or_init(Default::default)
}

struct Handoff<T> {
    value: Mutex<Option<Result<T>>>,
    decided: Notify,
}
struct Ticket<T>(Arc<Handoff<T>>);
impl<T: Runtime> Ticket<T> {
    fn claim(self) -> Result<T> {
        let mut outcome = self.0.value.lock().expect("startup handoff lock poisoned");
        if let Some(Ok(runtime)) = outcome.as_mut() {
            // A failed publication leaves the actual owner in its ticket, so the
            // retained task joins cleanup even if this error is then abandoned.
            runtime.handoff()?;
        }
        outcome
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
    fn handoff(&mut self) -> Result<()> {
        Ok(())
    }
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
    receive.await.context("startup owner stopped")?.claim()
}

async fn begin<T, Opening>(tasks: &Tasks, opening: Opening) -> Result<oneshot::Receiver<Ticket<T>>>
where
    T: Runtime,
    Opening: Future<Output = Result<T>> + Send + 'static,
{
    let (send, receive) = oneshot::channel();
    let mut tasks = tasks.lock().await;
    while let Some(index) = tasks
        .handles
        .iter()
        .position(tokio::task::JoinHandle::is_finished)
    {
        let result = (&mut tasks.handles[index]).await;
        drop(tasks.handles.swap_remove(index));
        if let Err(error) = result
            .context("prior startup owner panicked")
            .and_then(|value| value)
        {
            tasks.failure.get_or_insert(error);
        }
    }
    if let Some(error) = tasks.failure.take() {
        return Err(error);
    }
    tasks.handles.push(tokio::spawn(async move {
        // An error needs the same acknowledged handoff as a runtime. Sending
        // into a receiver's buffer does not establish that anyone observed it.
        deliver(Box::pin(opening).await, send).await
    }));
    Ok(receive)
}

async fn deliver<T: Runtime>(outcome: Result<T>, send: oneshot::Sender<Ticket<T>>) -> Result<()> {
    let handoff = Arc::new(Handoff {
        value: Mutex::new(Some(outcome)),
        decided: Notify::new(),
    });
    let _ = send.send(Ticket(handoff.clone()));
    handoff.decided.notified().await;
    let abandoned = handoff
        .value
        .lock()
        .expect("startup handoff lock poisoned")
        .take();
    match abandoned {
        Some(Ok(mut runtime)) => finish(&mut runtime).await?,
        Some(Err(error)) => return Err(error),
        None => {}
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
    while let Some(task) = tasks.handles.last_mut() {
        let result = task.await;
        tasks.handles.pop();
        if let Err(error) = result
            .context("startup owner panicked")
            .and_then(|result| result)
        {
            tasks.failure.get_or_insert(error);
        }
    }
    tasks.failure.take().map_or(Ok(()), Err)
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
        let delivery = deliver(Ok(candidate), send);
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
        let ticket = tokio::time::timeout(Duration::from_secs(5), receive).await??;
        let mut runtime = ticket.claim()?;
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
        assert!(tasks.lock().await.handles.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_drain_preserves_joined_failure_before_another_pending_owner() -> Result<()> {
        let tasks = Tasks::default();
        let (release, waiting) = oneshot::channel::<()>();
        let pending = tokio::spawn(async move { waiting.await.map_err(Into::into) });
        let failed = tokio::spawn(async { anyhow::bail!("first owner failed") });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !failed.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        tasks.lock().await.handles.extend([pending, failed]);
        let mut draining = Box::pin(drain_tasks(&tasks));
        std::future::poll_fn(|context| {
            assert!(draining.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        // This actually drops the drain after it consumed the last failed
        // handle, while its await still owns the pending handle in place.
        drop(draining);
        {
            let registry = tasks.lock().await;
            assert_eq!(registry.handles.len(), 1);
            assert_eq!(
                registry.failure.as_ref().unwrap().to_string(),
                "first owner failed"
            );
        }
        release.send(()).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), drain_tasks(&tasks))
            .await?
            .unwrap_err();
        assert_eq!(error.to_string(), "first owner failed");
        let registry = tasks.lock().await;
        assert!(registry.handles.is_empty());
        assert!(registry.failure.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn buffered_failed_open_requires_an_actual_recipient_before_forgetting_its_error()
    -> Result<()> {
        let (send, receive) = oneshot::channel();
        let mut delivery = Box::pin(deliver::<Candidate>(
            Err(anyhow::anyhow!("unobserved failed open")),
            send,
        ));
        std::future::poll_fn(|context| {
            assert!(delivery.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(receive);
        let error = tokio::time::timeout(Duration::from_secs(5), delivery)
            .await?
            .unwrap_err();
        assert_eq!(error.to_string(), "unobserved failed open");

        let tasks = Tasks::default();
        let receive =
            begin::<Candidate, _>(&tasks, async { anyhow::bail!("observed failed open") }).await?;
        let ticket = tokio::time::timeout(Duration::from_secs(5), receive).await??;
        assert_eq!(
            ticket.claim().err().unwrap().to_string(),
            "observed failed open"
        );
        tokio::time::timeout(Duration::from_secs(5), drain_tasks(&tasks)).await??;
        Ok(())
    }

    struct RejectedPublication {
        candidate: Candidate,
        handed: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl Runtime for RejectedPublication {
        fn handoff(&mut self) -> Result<()> {
            self.handed.fetch_add(1, Ordering::AcqRel);
            anyhow::bail!("publication fence rejected the actual recipient")
        }
        fn close(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            self.candidate.close()
        }
    }
    #[tokio::test]
    async fn rejected_actual_recipient_handoff_retains_owner_until_cancelled_drain_is_joined()
    -> Result<()> {
        let tasks = Tasks::default();
        let observation = Arc::new(Observation::default());
        let handed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let candidate = RejectedPublication {
            candidate: Candidate {
                observation: observation.clone(),
                fail_once: false,
            },
            handed: handed.clone(),
        };
        let ticket = begin(&tasks, async move { Ok(candidate) }).await?.await?;
        assert_eq!(handed.load(Ordering::Acquire), 0);
        assert!(ticket.claim().is_err());
        assert_eq!(handed.load(Ordering::Acquire), 1);
        tokio::time::timeout(Duration::from_secs(5), observation.entered.notified()).await?;
        let mut drain = Box::pin(drain_tasks(&tasks));
        std::future::poll_fn(|cx| {
            assert!(drain.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(drain);
        assert!(!observation.dropped.load(Ordering::Acquire));
        observation.release.notify_one();
        tokio::time::timeout(Duration::from_secs(5), drain_tasks(&tasks)).await??;
        assert!(observation.closed.load(Ordering::Acquire));
        assert!(observation.dropped.load(Ordering::Acquire));
        Ok(())
    }
}
