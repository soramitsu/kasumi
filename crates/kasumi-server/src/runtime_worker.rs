//! A background task remains owned until its actual future has been dropped.
use tokio::{
    sync::{Mutex, Notify},
    task::JoinHandle,
};

#[derive(Default)]
pub(crate) struct RuntimeWorker {
    task: Mutex<Option<JoinHandle<()>>>,
    wake: std::sync::Arc<Notify>,
    closed: std::sync::atomic::AtomicBool,
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
        self.wake.notify_one();
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
impl kasumi_serving::LiveTrustBackgroundWork for RuntimeWorker {
    fn close(&self) {
        RuntimeWorker::close(self);
    }
    fn drain(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let _ = RuntimeWorker::drain(self).await;
        })
    }
}
impl RuntimeWorker {
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Acquire)
    }
    pub(crate) fn close(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.wake.notify_one();
    }
    pub(crate) fn wake(&self) -> std::sync::Arc<Notify> {
        self.wake.clone()
    }
    pub(crate) fn register(&self, task: JoinHandle<()>) {
        let mut owner = self.task.try_lock().expect("new background worker owner");
        assert!(owner.is_none(), "background worker already registered");
        *owner = Some(task);
    }
    /// The caller closes admission first. Wake idle work, but never abort an
    /// admitted operation. A cancelled waiter leaves this exact handle installed.
    pub(crate) async fn drain(&self) -> Result<(), tokio::task::JoinError> {
        self.close();
        let mut owner = self.task.lock().await;
        let result = match owner.as_mut() {
            Some(task) => task.await,
            None => return Ok(()),
        };
        owner.take();
        result
    }
    /// Best effort when an owner is abandoned without its explicit async drain.
    pub(crate) fn abort(&self) {
        if let Ok(mut owner) = self.task.try_lock()
            && let Some(task) = owner.take()
        {
            task.abort();
        }
    }
}
