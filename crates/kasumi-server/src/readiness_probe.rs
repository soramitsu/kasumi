//! One owned actor query, retained independently of its diagnostic waiter.
use kasumi_engine::admission::{NodeAdmission, Reservation};
use kasumi_types::drain::{DrainReport, DrainResult};
use std::{future::Future, pin::Pin, sync::Arc};

const PROBE_BYTES: u64 = 128 << 10;
type Probe = Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send>>;
struct Pending {
    source: Option<kasumi_store::NodeStoreLocator>,
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
        source: Option<kasumi_store::NodeStoreLocator>,
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
            source,
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
    /// Observe the existing query after this exact target has closed its SDK
    /// core. A stopped actor's ready reply releases the query's database alias
    /// before the target's physical census checks for live facades. A different
    /// node, an active observer, or a still-pending query retains its own slot.
    pub(crate) async fn observe_closed_node(&self, node: &kasumi_store::NodeStoreLocator) {
        let Ok(mut state) = self.0.try_lock() else {
            return;
        };
        if state
            .pending
            .as_ref()
            .and_then(|pending| pending.source.as_ref())
            .is_some_and(|source| source.same_owner(node))
        {
            let _ = tokio::time::timeout(crate::readiness::PROBE_TIMEOUT, state.observe()).await;
        }
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
