//! Process stop and reload signals for installed services.
use crate::tls_reload::RuntimeTlsReload;
use anyhow::Result;
use std::future::Future;
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    sync::watch,
};

pub(crate) struct StopSignals {
    interrupt: Signal,
    terminate: Signal,
}

impl StopSignals {
    pub(crate) fn install() -> std::io::Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    pub(crate) async fn wait(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {},
            _ = self.terminate.recv() => {},
        }
    }
}

pub struct DaemonSignals {
    stop: StopSignals,
    hangup: Signal,
}

impl DaemonSignals {
    /// Install handlers before announcing startup or opening any installed owner.
    pub fn install() -> std::io::Result<Self> {
        Ok(Self {
            stop: StopSignals::install()?,
            hangup: signal(SignalKind::hangup())?,
        })
    }

    /// Dropping the open waiter leaves its original work and any unclaimed
    /// runtime in startup_owner, which the binary joins in process_drain.
    pub async fn open<T>(&mut self, opening: impl Future<Output = Result<T>>) -> Result<Option<T>> {
        tokio::select! {
            biased;
            _ = self.stop.wait() => Ok(None),
            result = opening => result.map(Some),
        }
    }

    pub async fn serve<F>(
        mut self,
        reload: RuntimeTlsReload,
        serving: impl FnOnce(watch::Receiver<bool>) -> F,
    ) -> Result<()>
    where
        F: Future<Output = Result<()>>,
    {
        let (stop, shutdown) = watch::channel(false);
        let mut serving_done = shutdown.clone();
        let mut reload_done = shutdown.clone();
        let runtime = async {
            let result = serving(shutdown).await;
            stop.send_replace(true);
            result
        };
        let termination = async {
            tokio::select! {
                _ = serving_done.changed() => return,
                _ = self.stop.wait() => {},
            }
            stop.send_replace(true);
        };
        // A stop may reach the runtime during a reload. Join the already
        // admitted reload before releasing its handle and returning to main.
        let reloads = async move {
            loop {
                tokio::select! {
                    biased;
                    _ = reload_done.changed() => break,
                    _ = self.hangup.recv() => {
                        if reload.reload().await.is_err() {
                            crate::logging::tls_reload_failed();
                        }
                    }
                }
            }
        };
        tokio::join!(runtime, termination, reloads).0
    }
}
