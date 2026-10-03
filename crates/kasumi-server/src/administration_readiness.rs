use super::*;
use crate::readiness::{Epoch, FRESHNESS, PROBE_TIMEOUT, Sample};
use std::time::Duration;
use tokio::{sync::watch, time::Instant};

/// Fixed, non-sensitive class of one failed readiness sweep. Attached as error
/// context; the underlying error text is never logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SweepFailure {
    ControlUnavailable,
    EpochUnavailable,
    EpochChanged,
    Stopped,
    AdmissionReserve,
    MemoryPressure,
    RouteInvalid,
    GenerationUnavailable,
    ProbeAdmission,
    ActorProbeFailed,
    ProbeDeadline,
}
impl SweepFailure {
    pub(crate) fn class(self) -> &'static str {
        match self {
            Self::ControlUnavailable => "control_unavailable",
            Self::EpochUnavailable => "epoch_unavailable",
            Self::EpochChanged => "epoch_changed",
            Self::Stopped => "stopped",
            Self::AdmissionReserve => "admission_reserve",
            Self::MemoryPressure => "memory_pressure",
            Self::RouteInvalid => "route_invalid",
            Self::GenerationUnavailable => "generation_unavailable",
            Self::ProbeAdmission => "probe_admission",
            Self::ActorProbeFailed => "actor_probe_failed",
            Self::ProbeDeadline => "probe_deadline",
        }
    }
}
impl std::fmt::Display for SweepFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.class())
    }
}

impl Administration {
    pub(crate) fn readiness_epoch(&self) -> Result<Epoch> {
        self.control
            .check_serving()
            .context(SweepFailure::ControlUnavailable)?;
        let generation = self
            .control
            .engine()
            .generation()
            .context(SweepFailure::ControlUnavailable)?;
        let topology_version = generation
            .local_control_topology_version()
            .context(SweepFailure::ControlUnavailable)?;
        Ok(Epoch {
            topology_version,
            installed_routes: self
                .registry
                .route_epoch()
                .context(SweepFailure::EpochUnavailable)?,
            actual_membership: self
                .registry
                .membership_epoch()
                .context(SweepFailure::EpochUnavailable)?,
        })
    }

    /// The serving task inventory owns this exact future. Probes are awaited
    /// inline; stopping never drops an unobserved spawned probe or reaper.
    pub(crate) async fn probe_readiness(
        self: Arc<Self>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<()> {
        struct Invalidate<'a>(&'a crate::readiness::Coverage);
        impl Drop for Invalidate<'_> {
            fn drop(&mut self) {
                self.0.invalidate();
            }
        }
        let _terminal = Invalidate(&self.readiness);
        loop {
            if *stop.borrow() {
                return Ok(());
            }
            if let Err(error) = self.readiness_sweep(&mut stop).await {
                self.readiness.invalidate();
                let readiness_error_class = error
                    .downcast_ref::<SweepFailure>()
                    .map_or("unclassified", |failure| failure.class());
                tracing::warn!(
                    event = "readiness_probe_failed",
                    readiness_error_class,
                    "complete readiness coverage unavailable"
                );
            }
            if *stop.borrow() {
                return Ok(());
            }
            tokio::select! {
                _ = stop.changed() => return Ok(()),
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    }

    async fn readiness_sweep(&self, stop: &mut watch::Receiver<bool>) -> Result<()> {
        // Retain one immutable topology document, never the complete generation
        // or all database handles. Charge its heap before retaining its Arc.
        let (epoch, document, _reservation) =
            {
                let selection = ControlPlane::select_local(&self.control)
                    .context(SweepFailure::ControlUnavailable)?;
                selection
                    .check_admission(&self.admission)
                    .context(SweepFailure::AdmissionReserve)?;
                let document =
                    selection
                        .topology_document()
                        .map_err(|error| {
                            let class = if error.downcast_ref::<kasumi_types::Error>().is_some_and(
                                |error| error.code == kasumi_types::ErrorCode::ResourceExhausted,
                            ) {
                                SweepFailure::AdmissionReserve
                            } else {
                                SweepFailure::ControlUnavailable
                            };
                            error.context(class)
                        })?
                        .context(SweepFailure::ControlUnavailable)?;
                // Preserve the existing route/probe scratch allowance. The source
                // handle has its own independent current point-read custody.
                let bytes = 128 << 10;
                let mut reservation = self
                    .admission
                    .reserve(bytes, None)
                    .context(SweepFailure::AdmissionReserve)?;
                reservation.retain(bytes);
                let epoch = Epoch {
                    topology_version: document.version,
                    installed_routes: self
                        .registry
                        .route_epoch()
                        .context(SweepFailure::EpochUnavailable)?,
                    actual_membership: self
                        .registry
                        .membership_epoch()
                        .context(SweepFailure::EpochUnavailable)?,
                };
                (epoch, document, reservation)
            };
        let local_id = self.config.replication.as_ref().map_or(1, |r| r.node_id);
        let routes = document
            .body
            .get("tenants")
            .and_then(serde_json::Value::as_object)
            .context(SweepFailure::ControlUnavailable)?;
        let local = |value: &serde_json::Value| -> Result<bool> {
            Ok(value
                .get("voters")
                .and_then(serde_json::Value::as_array)
                .context(SweepFailure::RouteInvalid)?
                .iter()
                .any(|v| v.as_u64() == Some(local_id)))
        };
        let mut expected = 1usize;
        for (index, value) in routes.values().enumerate() {
            if index % 16 == 0 {
                ensure!(!*stop.borrow(), SweepFailure::Stopped);
                tokio::task::yield_now().await;
            }
            expected = expected
                .checked_add(usize::from(local(value)?))
                .context(SweepFailure::RouteInvalid)?;
        }
        ensure!(!*stop.borrow(), SweepFailure::Stopped);
        ensure!(self.readiness_epoch()? == epoch, SweepFailure::EpochChanged);
        let started = Instant::now();
        self.readiness.begin(epoch, expected, started);
        let control_incarnation = self
            .control
            .engine()
            .generation()
            .context(SweepFailure::ControlUnavailable)?
            .incarnation()
            .to_owned();
        self.probe_one(
            crate::runtime::CONTROL_TENANT.to_owned(),
            control_incarnation,
            Some(SelectedTenant::new(self.control.clone())),
            None,
            epoch,
            stop,
        )
        .await?;
        for (index, (tenant, value)) in routes.iter().enumerate() {
            ensure!(!*stop.borrow(), SweepFailure::Stopped);
            ensure!(self.readiness_epoch()? == epoch, SweepFailure::EpochChanged);
            if index % 16 == 0 {
                tokio::task::yield_now().await;
                let memory = self.admission.snapshot();
                ensure!(
                    memory.sample_usable && !memory.pressured,
                    SweepFailure::MemoryPressure
                );
            }
            if !local(value)? {
                continue;
            }
            let route = kasumi_engine::control::TenantRoute::deserialize(value)
                .context(SweepFailure::RouteInvalid)?;
            let managed = self
                .registry
                .installed_generation(tenant, &route.incarnation)
                .context(SweepFailure::GenerationUnavailable)?
                .map(SelectedTenant::new);
            self.probe_one(
                tenant.clone(),
                route.incarnation,
                managed,
                Some(route.voters),
                epoch,
                stop,
            )
            .await?;
        }
        ensure!(!*stop.borrow(), SweepFailure::Stopped);
        ensure!(self.readiness_epoch()? == epoch, SweepFailure::EpochChanged);
        self.readiness.finish(epoch);
        Ok(())
    }

    async fn probe_one(
        &self,
        tenant: String,
        incarnation: String,
        selected: Option<SelectedTenant>,
        expected_voters: Option<BTreeSet<u64>>,
        epoch: Epoch,
        stop: &mut watch::Receiver<bool>,
    ) -> Result<()> {
        let mut quorum = false;
        let mut healthy = false;
        let mut valid_until = Instant::now() + FRESHNESS;
        if let Some(selected) = selected
            && selected.database.check_serving().is_ok()
            && selected.store.check_access().is_ok()
        {
            let local_id = self.config.replication.as_ref().map_or(1, |r| r.node_id);
            ensure!(!*stop.borrow(), SweepFailure::Stopped);
            let database = selected.database.clone();
            self.readiness
                .probe
                .start(&self.admission, async move {
                    database
                        .raft_group()
                        .readiness_probe(local_id, expected_voters)
                        .await
                })
                .await
                .context(SweepFailure::ProbeAdmission)?;
            let observed = tokio::select! {
                biased;
                _ = stop.changed() => anyhow::bail!(SweepFailure::Stopped),
                observed = tokio::time::timeout(PROBE_TIMEOUT, self.readiness.probe.observe()) => observed,
            };
            use crate::readiness_probe::Outcome;
            quorum = match observed {
                Ok(Outcome::Healthy) => true,
                Ok(Outcome::Unhealthy) => false,
                Ok(Outcome::Failed) => anyhow::bail!(SweepFailure::ActorProbeFailed),
                Err(_) => {
                    // A diagnostic timeout does not cancel the actual actor
                    // operation. Revoke the old certificate now and retain the
                    // single charged slot until the actor replies or shutdown
                    // takes over its observation after draining the cores.
                    self.readiness.record(
                        Sample {
                            tenant: tenant.clone(),
                            incarnation: incarnation.clone(),
                            quorum: false,
                        },
                        false,
                        Instant::now(),
                    );
                    tokio::select! {
                        biased;
                        _ = stop.changed() => {},
                        _ = self.readiness.probe.observe() => {},
                    }
                    anyhow::bail!(SweepFailure::ProbeDeadline);
                }
            };
            healthy = quorum
                && selected.database.check_serving().is_ok()
                && selected.store.check_access().is_ok();
            if self.config.mode == crate::runtime::DeploymentMode::Replicated {
                let observed_at = Instant::now();
                match selected
                    .store
                    .storage_access()
                    .serving_gate()
                    .and_then(|g| g.remaining().ok())
                {
                    Some(remaining) if !remaining.is_zero() => {
                        valid_until = valid_until.min(observed_at + remaining)
                    }
                    _ => healthy = false,
                }
            }
        }
        ensure!(self.readiness_epoch()? == epoch, SweepFailure::EpochChanged);
        self.readiness.record(
            Sample {
                tenant,
                incarnation,
                quorum,
            },
            healthy,
            valid_until,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_sweep_classes_survive_context_without_error_text() {
        let reserve: Result<()> = Err(anyhow::anyhow!("private admission detail"));
        let error = reserve.context(SweepFailure::AdmissionReserve).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<SweepFailure>()
                .map(|failure| failure.class()),
            Some("admission_reserve")
        );
        let pressured = (|| -> Result<()> {
            ensure!(false, SweepFailure::MemoryPressure);
            Ok(())
        })()
        .unwrap_err();
        assert_eq!(
            pressured.downcast_ref::<SweepFailure>(),
            Some(&SweepFailure::MemoryPressure)
        );
        let deadline =
            (|| -> Result<()> { anyhow::bail!(SweepFailure::ProbeDeadline) })().unwrap_err();
        assert_eq!(deadline.to_string(), "probe_deadline");
    }
}
