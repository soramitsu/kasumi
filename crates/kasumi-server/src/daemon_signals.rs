//! Process stop and reload signals for the installed data and authority daemons.
use crate::tls_reload::RuntimeTlsReload;
use anyhow::Result;
use std::future::Future;
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    sync::watch,
};

pub struct DaemonSignals {
    interrupt: Signal,
    terminate: Signal,
    hangup: Signal,
}

impl DaemonSignals {
    /// Install handlers before announcing startup or opening any installed owner.
    pub fn install() -> std::io::Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
        })
    }

    /// Dropping the open waiter leaves its original work and any unclaimed
    /// runtime in startup_owner, which the binary joins in process_drain.
    pub async fn open<T>(&mut self, opening: impl Future<Output = Result<T>>) -> Result<Option<T>> {
        tokio::select! {
            biased;
            _ = self.interrupt.recv() => Ok(None),
            _ = self.terminate.recv() => Ok(None),
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
                _ = self.interrupt.recv() => {},
                _ = self.terminate.recv() => {},
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
