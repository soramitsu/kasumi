//! One owned actor query, retained independently of its diagnostic waiter.
use kasumi_engine::admission::{NodeAdmission, Reservation};
use kasumi_types::drain::{DrainReport, DrainResult};
use std::{future::Future, pin::Pin, sync::Arc};

const PROBE_BYTES: u64 = 128 << 10;
type Probe = Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send>>;
struct Pending {
    future: Option<Probe>,
    // A caught panic may have left an SDK message queued. Keep its charge until
    // positive group shutdown, even after preserving the original panic/error.
    _reservation: Reservation,
}
#[derive(Default)]
struct State {
    pending: Option<Pending>,
    report: DrainReport,
    closed: bool,
}
#[derive(Default)]
pub(crate) struct ProbeSlot(tokio::sync::Mutex<State>);
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Healthy,
    Unhealthy,
    Failed,
}
impl State {
    async fn observe(&mut self) -> Outcome {
        let Some(pending) = self.pending.as_mut() else {
            return Outcome::Unhealthy;
        };
        let Some(future) = pending.future.as_mut() else {
            return Outcome::Failed;
        };
        // Poll the original future by reference. Cancelling this observation
        // leaves that exact future, its resources and its reservation in State.
        match future.await {
            Ok(healthy) => {
                self.pending = None;
                if healthy {
                    Outcome::Healthy
                } else {
                    Outcome::Unhealthy
                }
            }
            Err(error) => {
                self.report.record("readiness actor probe", 0, error);
                pending.future = None;
                Outcome::Failed
            }
        }
    }
}
impl ProbeSlot {
    pub(crate) async fn start(
        &self,
        admission: &Arc<NodeAdmission>,
        future: impl Future<Output = anyhow::Result<bool>> + Send + 'static,
    ) -> anyhow::Result<()> {
        let mut state = self.0.lock().await;
        anyhow::ensure!(
            !state.closed && state.pending.is_none() && state.report.issues().is_empty(),
            "previous readiness actor probe still owns its slot"
        );
        let mut reservation = admission.reserve(PROBE_BYTES, None)?;
        reservation.retain(PROBE_BYTES);
        state.pending = Some(Pending {
            future: Some(Box::pin(crate::startup_preparation::capture(
                "readiness actor probe",
                future,
            ))),
            _reservation: reservation,
        });
        Ok(())
    }
    pub(crate) async fn observe(&self) -> Outcome {
        self.0.lock().await.observe().await
    }
    /// Only after the owning runtime has positively drained every selected
    /// group's SDK core and children. Normal stop does not call this from the
    /// maintenance loop: core shutdown must first close any stalled receiver.
    pub(crate) async fn drain_after_group_shutdown(&self) -> DrainResult {
        let mut state = self.0.lock().await;
        state.closed = true;
        state.observe().await;
        state.pending = None;
        state.report.complete()
    }
}

#[cfg(test)]
#[path = "readiness_probe_tests.rs"]
mod tests;
