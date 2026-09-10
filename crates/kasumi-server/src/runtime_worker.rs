//! Retain the exact background task handle and its stable terminal outcome.
use tokio::sync::Notify;

#[derive(Default)]
pub(crate) struct RuntimeWorker {
    work: std::sync::Arc<kasumi_serving::BackgroundWork>,
    #[cfg(test)]
    pause: std::sync::Mutex<Option<std::sync::Arc<WorkerPause>>>,
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct WorkerPause {
    pub(crate) entered: Notify,
    pub(crate) release: Notify,
}
#[cfg(test)]
impl RuntimeWorker {
    pub(crate) fn pause_next_upgrade(&self) -> std::sync::Arc<WorkerPause> {
        let pause = std::sync::Arc::new(WorkerPause::default());
        *self.pause.lock().unwrap() = Some(pause.clone());
        self.work.wake().notify_one();
        pause
    }
    pub(crate) async fn after_upgrade(&self) {
        let pause = self.pause.lock().unwrap().take();
        if let Some(pause) = pause {
            pause.entered.notify_one();
            pause.release.notified().await;
        }
    }
}
impl RuntimeWorker {
    pub(crate) fn work(&self) -> std::sync::Arc<kasumi_serving::BackgroundWork> {
        self.work.clone()
    }
    pub(crate) fn is_closed(&self) -> bool {
        self.work.is_closed()
    }
    pub(crate) fn close(&self) {
        self.work.close();
    }
    pub(crate) fn wake(&self) -> std::sync::Arc<Notify> {
        self.work.wake()
    }
    pub(crate) fn start(
        &self,
        task: impl std::future::Future<Output = ()> + Send + 'static,
        budget: &kasumi_serving::BackgroundWorkBudget,
    ) -> anyhow::Result<()> {
        self.work.start(task, budget)
    }
    pub(crate) async fn drain(&self) -> kasumi_types::drain::DrainResult {
        self.work.drain().await
    }
}
