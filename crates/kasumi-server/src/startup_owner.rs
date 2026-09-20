//! Startup tasks retain unopened/unpublished runtime resources through cancellation.
//! A successful oneshot send is not transfer: only the recipient's synchronous
//! ticket claim moves the runtime. Every abandoned result is closed and joined.
use anyhow::{Context, Result};
use kasumi_types::drain::{DrainCompletion, DrainReport, DrainResult};
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
    SignerVerifier,
    TargetJournal,
}

fn tasks(kind: Kind) -> &'static Tasks {
    static DATA: OnceLock<Tasks> = OnceLock::new();
    static AUTHORITY: OnceLock<Tasks> = OnceLock::new();
    static LOCAL_OPERATOR: OnceLock<Tasks> = OnceLock::new();
    static TENANT_ENROLLMENT: OnceLock<Tasks> = OnceLock::new();
    static TARGET_JOURNAL: OnceLock<Tasks> = OnceLock::new();
    static SIGNER_VERIFIER: OnceLock<Tasks> = OnceLock::new();
    match kind {
        Kind::Data => &DATA,
        Kind::Authority => &AUTHORITY,
        Kind::LocalOperator => &LOCAL_OPERATOR,
        Kind::TenantEnrollment => &TENANT_ENROLLMENT,
        Kind::SignerVerifier => &SIGNER_VERIFIER,
        Kind::TargetJournal => &TARGET_JOURNAL,
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
    fn close(&mut self) -> Pin<Box<dyn Future<Output = DrainResult> + Send + '_>>;
}

/// Retry only incomplete ownership. A completed failure still reports the exact
/// errors, but never keeps a fully drained runtime in an endless cleanup loop.
/// Every implementation also retains its report across a cancelled finish call.
pub(crate) async fn finish(runtime: &mut impl Runtime) -> DrainResult {
    let mut report = DrainReport::default();
    let mut delay = std::time::Duration::from_secs(1);
    loop {
        match runtime.close().await {
            Ok(()) => return report.complete(),
            Err(error) => {
                report.merge(&error);
                if error.completion() == DrainCompletion::Complete {
                    return report.complete();
                }
                tracing::error!(error = %error, retry_after_secs = delay.as_secs(), "startup owner drain incomplete; retaining resources for retry");
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
    open_in(tasks(kind), opening).await
}

async fn open_in<T, Opening>(tasks: &Tasks, opening: Opening) -> Result<T>
where
    T: Runtime,
    Opening: Future<Output = Result<T>> + Send + 'static,
{
    let receive = begin(tasks, opening).await?;
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

/// Isolate faulting ownership tests from other process-wide startup kinds while
/// exercising the same publication, acknowledgement and retained-join code.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestRegistry(Tasks);
#[cfg(test)]
impl TestRegistry {
    pub(crate) async fn open<T: Runtime>(
        &self,
        opening: impl Future<Output = Result<T>> + Send + 'static,
    ) -> Result<T> {
        open_in(&self.0, opening).await
    }
    pub(crate) async fn drain(&self) -> Result<()> {
        drain_tasks(&self.0).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_types::drain::DrainFailure;
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
        report: DrainReport,
        observation: Arc<Observation>,
        fail_once: bool,
    }
    impl Drop for Candidate {
        fn drop(&mut self) {
            self.observation.dropped.store(true, Ordering::Release);
        }
    }
    impl Runtime for Candidate {
        fn close(&mut self) -> Pin<Box<dyn Future<Output = DrainResult> + Send + '_>> {
            Box::pin(async move {
                let attempt = self.observation.attempts.fetch_add(1, Ordering::AcqRel);
                self.observation.entered.notify_one();
                if self.fail_once && attempt == 0 {
                    let issue = self.report.record(
                        "candidate",
                        0,
                        anyhow::anyhow!("injected drain failure"),
                    );
                    return Err(DrainFailure::retained(issue));
                }
                self.observation.release.notified().await;
                self.observation.closed.store(true, Ordering::Release);
                self.report.complete()
            })
        }
    }

    #[tokio::test]
    async fn buffered_startup_ticket_drain_is_joinable_after_result_receiver_cancellation()
    -> Result<()> {
        let observation = Arc::new(Observation::default());
        let candidate = Candidate {
            report: DrainReport::default(),
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
            report: DrainReport::default(),
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
            report: DrainReport::default(),
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
        assert_eq!(observation.attempts.load(Ordering::Acquire), 2);
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

    struct JoinedWorkers {
        handles: Vec<tokio::task::JoinHandle<()>>,
        report: DrainReport,
        attempts: usize,
    }
    impl Runtime for JoinedWorkers {
        fn close(&mut self) -> Pin<Box<dyn Future<Output = DrainResult> + Send + '_>> {
            Box::pin(async {
                self.attempts += 1;
                while let Some(handle) = self.handles.last_mut() {
                    let result = handle.await;
                    self.handles.pop();
                    if let Err(error) = result {
                        // Slots remain stable as this owned stack drains.
                        self.report
                            .record("joined worker", self.handles.len(), error.into());
                    }
                }
                self.report.complete()
            })
        }
    }
    async fn panicked_worker() -> Result<tokio::task::JoinHandle<()>> {
        let task = tokio::spawn(async { panic!("injected actual worker panic") });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !task.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(task)
    }
    #[tokio::test]
    async fn completed_worker_panic_reports_original_join_error_without_retry() -> Result<()> {
        let mut workers = JoinedWorkers {
            handles: vec![panicked_worker().await?],
            report: DrainReport::default(),
            attempts: 0,
        };
        let error = tokio::time::timeout(Duration::from_secs(5), finish(&mut workers))
            .await?
            .unwrap_err();
        assert_eq!(workers.attempts, 1);
        assert!(workers.handles.is_empty());
        let failure = &error;
        assert_eq!(failure.completion(), DrainCompletion::Complete);
        let issue = failure.issues()[0].clone();
        assert!(
            issue
                .error()
                .downcast_ref::<tokio::task::JoinError>()
                .unwrap()
                .is_panic()
        );
        let repeated = finish(&mut workers).await.unwrap_err();
        assert_eq!(repeated.completion(), DrainCompletion::Complete);
        assert_eq!(repeated.issues().len(), 1);
        assert!(Arc::ptr_eq(&issue, &repeated.issues()[0]));
        // Preparation and cleanup both failed: retain the typed original child
        // report as context, exactly as the startup callers do.
        let preparation = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let combined = anyhow::Error::new(preparation).context(repeated);
        assert_eq!(
            combined.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let propagated = combined.downcast_ref::<DrainFailure>().unwrap();
        assert_eq!(propagated.completion(), DrainCompletion::Complete);
        assert!(Arc::ptr_eq(&issue, &propagated.issues()[0]));
        drop(workers);
        // Error evidence remains the actual JoinError after resource owner drop.
        assert!(
            issue
                .error()
                .downcast_ref::<tokio::task::JoinError>()
                .unwrap()
                .is_panic()
        );
        Ok(())
    }
    #[tokio::test]
    async fn cancelled_finish_keeps_joined_panic_and_exact_unfinished_worker() -> Result<()> {
        struct Resource(Arc<AtomicBool>);
        impl Drop for Resource {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let resource = Resource(dropped.clone());
        let (release, waiting) = oneshot::channel::<()>();
        let retained = tokio::spawn(async move {
            let _resource = resource;
            waiting.await.unwrap();
        });
        let mut workers = JoinedWorkers {
            handles: vec![retained, panicked_worker().await?],
            report: DrainReport::default(),
            attempts: 0,
        };
        let mut first = Box::pin(finish(&mut workers));
        std::future::poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(first);
        assert_eq!(workers.handles.len(), 1);
        assert!(!dropped.load(Ordering::Acquire));
        let original = workers.report.issues()[0].clone();
        assert!(
            original
                .error()
                .downcast_ref::<tokio::task::JoinError>()
                .unwrap()
                .is_panic()
        );
        let mut retry = Box::pin(finish(&mut workers));
        std::future::poll_fn(|cx| {
            assert!(retry.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(!dropped.load(Ordering::Acquire));
        release.send(()).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), retry)
            .await?
            .unwrap_err();
        assert!(workers.handles.is_empty());
        assert_eq!(workers.attempts, 2);
        assert!(dropped.load(Ordering::Acquire));
        let failure = &error;
        assert_eq!(failure.completion(), DrainCompletion::Complete);
        assert_eq!(failure.issues().len(), 1);
        assert!(Arc::ptr_eq(&original, &failure.issues()[0]));
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
        fn close(&mut self) -> Pin<Box<dyn Future<Output = DrainResult> + Send + '_>> {
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
                report: DrainReport::default(),
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
