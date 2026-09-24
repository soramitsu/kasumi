//! One bounded blocking-child slot per installed database worker. The handle
//! lives in the database owner, outside the cancellable supervisor future.
use kasumi_types::drain::{DrainFailure, DrainReport, DrainResult};
use std::sync::Mutex;

/// Only an unclaimed child result is interpreted here. A caller that receives
/// the result is responsible for handling its ordinary operation error.
pub(super) trait UnclaimedOutcome {
    fn error(self) -> Option<anyhow::Error>;
}
impl UnclaimedOutcome for bool {
    fn error(self) -> Option<anyhow::Error> {
        None
    }
}
impl<T> UnclaimedOutcome for anyhow::Result<T> {
    fn error(self) -> Option<anyhow::Error> {
        self.err()
    }
}

pub(super) struct BlockingChild<T> {
    task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<T>>>,
    report: Mutex<DrainReport>,
    component: &'static str,
}
impl<T: UnclaimedOutcome + Send + 'static> BlockingChild<T> {
    pub(super) fn new(component: &'static str) -> Self {
        Self {
            task: tokio::sync::Mutex::new(None),
            report: Mutex::new(DrainReport::default()),
            component,
        }
    }

    pub(super) async fn run(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> std::result::Result<T, DrainFailure> {
        let mut task = self.task.lock().await;
        {
            let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
            if task.is_some() {
                // An abandoned attempt belongs to drain, never to a new run.
                return Err(DrainFailure::retained(report.record(
                    self.component,
                    1,
                    anyhow::anyhow!("blocking child has an unclaimed prior attempt"),
                )));
            }
            report.complete()?;
        }
        *task = Some(tokio::task::spawn_blocking(work));
        match task.as_mut().expect("installed blocking child").await {
            Ok(result) => {
                task.take();
                Ok(result)
            }
            Err(error) => {
                let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
                report.record(self.component, 0, error.into());
                task.take();
                Err(report
                    .complete()
                    .expect_err("recorded terminal child failure"))
            }
        }
    }

    pub(super) async fn drain(&self) -> DrainResult {
        let mut task = self.task.lock().await;
        if let Some(handle) = task.as_mut() {
            let result = handle.await;
            let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
            match result {
                Ok(unclaimed) => {
                    if let Some(error) = unclaimed.error() {
                        report.record(self.component, 0, error);
                    }
                }
                Err(error) => {
                    report.record(self.component, 0, error.into());
                }
            }
            // A successful unclaimed output may hold a work registration; it
            // was dropped above before the parent attempts its WorkFence census.
            task.take();
        }
        self.report
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .complete()
    }

    #[cfg(test)]
    pub(super) async fn child_finished(&self) -> Option<bool> {
        self.task
            .lock()
            .await
            .as_ref()
            .map(|task| task.is_finished())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_types::drain::DrainCompletion;
    use std::{future::Future, sync::Arc, task::Poll, time::Duration};

    #[derive(Debug)]
    struct PreparationFailure;
    impl std::fmt::Display for PreparationFailure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "original audit preparation failure")
        }
    }
    impl std::error::Error for PreparationFailure {}

    #[tokio::test]
    async fn cancelled_caller_and_drain_waiter_retain_original_preparation_error() {
        let child = Arc::new(BlockingChild::<anyhow::Result<()>>::new(
            "database audit preparation",
        ));
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let caller = tokio::spawn({
            let child = child.clone();
            async move {
                child
                    .run(move || {
                        let _ = entered.send(());
                        blocked.recv().expect("release blocking child");
                        Err(PreparationFailure.into())
                    })
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());

        let mut first = Box::pin(child.drain());
        std::future::poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(first);
        release.send(()).unwrap();

        let failure = tokio::time::timeout(Duration::from_secs(5), child.drain())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(failure.completion(), DrainCompletion::Complete);
        assert_eq!(failure.issues().len(), 1);
        let original = &failure.issues()[0];
        assert!(
            original
                .error()
                .downcast_ref::<PreparationFailure>()
                .is_some()
        );
        let repeated = child.drain().await.unwrap_err();
        assert!(Arc::ptr_eq(original, &repeated.issues()[0]));
        assert_eq!(child.child_finished().await, None);
    }
}
