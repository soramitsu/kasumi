//! One bounded blocking-child slot per installed database worker. The handle
//! lives in the database owner, outside the cancellable supervisor future.
use kasumi_types::drain::{DrainFailure, DrainReport, DrainResult};
use std::sync::Mutex;

pub(super) struct BlockingChild<T> {
    task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<T>>>,
    report: Mutex<DrainReport>,
    component: &'static str,
}
impl<T: Send + 'static> BlockingChild<T> {
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
            if let Err(error) = result {
                report.record(self.component, 0, error.into());
            }
            // Successful unclaimed output may hold a work registration. Drop it
            // here, before the parent attempts its WorkFence census.
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
