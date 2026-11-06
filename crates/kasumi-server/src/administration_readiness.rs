use super::failure_episodes::{EpisodeReport, EpisodeSummary, FailureEpisodes, utc};
use super::*;
use crate::readiness::{Epoch, PROBE_TIMEOUT, Sample};
use std::time::{Duration, SystemTime};
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

/// A failed sweep is known by its `readiness_error_class` and the control
/// plane's `control_closure_cause`. Sweeps that keep failing with the same
/// pair are one episode, logged by its transitions rather than every second.
type ReadinessFailure = (&'static str, &'static str);
/// A lasting failure episode is logged again at most this often.
const READINESS_REMINDER: Duration = Duration::from_secs(600);

/// Count one completed sweep, `None` when it succeeded, and log what it changed.
fn report_sweep(
    failures: &mut FailureEpisodes<ReadinessFailure>,
    failed: Option<ReadinessFailure>,
    now: Instant,
    wall: SystemTime,
) {
    let Some(failure) = failed else {
        if let Some(ended) = failures.close() {
            let (readiness_error_class, control_closure_cause) = ended.key;
            tracing::info!(
                event = "readiness_probe_recovered",
                readiness_error_class,
                control_closure_cause,
                failed_sweeps = ended.failures,
                first_failure = %utc(ended.first_failure),
                last_failure = %utc(ended.last_failure),
                "complete readiness coverage restored"
            );
        }
        return;
    };
    match failures.failed(failure, now, wall) {
        Some(EpisodeReport::Started {
            key,
            failures: count,
        }) => {
            let (readiness_error_class, control_closure_cause) = key;
            tracing::warn!(
                event = "readiness_probe_failed",
                readiness_error_class,
                control_closure_cause,
                failed_sweeps = count,
                "complete readiness coverage unavailable"
            );
        }
        Some(EpisodeReport::Lasting(lasting)) => readiness_still_failing(&lasting),
        None => {}
    }
}
fn readiness_still_failing(lasting: &EpisodeSummary<ReadinessFailure>) {
    let (readiness_error_class, control_closure_cause) = lasting.key;
    tracing::warn!(
        event = "readiness_probe_still_failing",
        readiness_error_class,
        control_closure_cause,
        failed_sweeps = lasting.failures,
        first_failure = %utc(lasting.first_failure),
        last_failure = %utc(lasting.last_failure),
        "complete readiness coverage still unavailable"
    );
}

impl Administration {
    pub(super) fn readiness_generation(
        &self,
        tenant: &str,
        incarnation: &str,
    ) -> Result<Option<SelectedTenant>> {
        // Original owners can remain installed while their serving route is
        // fenced. Targets have a separate installed runner and enter the route
        // registry. Select exact owners from both inventories; never turn a
        // failed lookup into a synthetic group or reopen a missing owner.
        let original = self
            .generations
            .read()
            .map_err(|_| anyhow::anyhow!("generation registry unavailable"))?
            .get(&(tenant.to_owned(), incarnation.to_owned()))
            .map(|owner| SelectedTenant::new(owner.database.clone()));
        let routed = self
            .registry
            .installed_generation(tenant, incarnation)?
            .map(SelectedTenant::new);
        match (original, routed) {
            (Some(original), Some(routed)) => {
                ensure!(
                    Arc::ptr_eq(&original.database, &routed.database),
                    SweepFailure::GenerationUnavailable
                );
                Ok(Some(original))
            }
            (Some(selected), None) | (None, Some(selected)) => Ok(Some(selected)),
            (None, None) => Ok(None),
        }
    }

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
        let mut failures = FailureEpisodes::new(READINESS_REMINDER);
        loop {
            if *stop.borrow() {
                break;
            }
            let swept = self.readiness_sweep(&mut stop).await;
            // Refresh the point observation scrapes report, here rather than
            // in a scrape: its store read can wait behind maintenance.
            if self.config.mode == crate::runtime::DeploymentMode::Standalone {
                self.observation.set_recovery_pending(
                    crate::local_recovery::runtime_pending(self.audit.store()).ok(),
                );
            }
            match swept {
                Ok(()) => report_sweep(&mut failures, None, Instant::now(), SystemTime::now()),
                Err(error) => {
                    self.readiness.invalidate();
                    let failure = error.downcast_ref::<SweepFailure>();
                    // A sweep cut short by shutdown neither fails nor recovers.
                    if failure != Some(&SweepFailure::Stopped) {
                        let readiness_error_class =
                            failure.map_or("unclassified", |failure| failure.class());
                        let control_closure_cause =
                            self.control_closure().map_or("none", |(cause, _)| cause);
                        report_sweep(
                            &mut failures,
                            Some((readiness_error_class, control_closure_cause)),
                            Instant::now(),
                            SystemTime::now(),
                        );
                    }
                }
            }
            if *stop.borrow() {
                break;
            }
            tokio::select! {
                _ = stop.changed() => break,
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
        if let Some(open) = failures.close() {
            readiness_still_failing(&open);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn test_readiness_sweep(&self) -> Result<(), &'static str> {
        let (_sender, mut stop) = watch::channel(false);
        self.readiness_sweep(&mut stop).await.map_err(|error| {
            error
                .downcast_ref::<SweepFailure>()
                .map_or("unclassified", |failure| failure.class())
        })
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
        let control_incarnation = self
            .control
            .engine()
            .generation()
            .context(SweepFailure::ControlUnavailable)?
            .incarnation()
            .to_owned();
        // The observed roster: Control first, then local routes, bounded by
        // the detail limit. Coverage itself counts every local route.
        let mut roster = Vec::with_capacity(crate::readiness::DETAIL_LIMIT.min(routes.len() + 1));
        roster.push((
            crate::runtime::CONTROL_TENANT.to_owned(),
            control_incarnation.clone(),
        ));
        let mut expected = 1usize;
        for (index, (tenant, value)) in routes.iter().enumerate() {
            if index % 16 == 0 {
                ensure!(!*stop.borrow(), SweepFailure::Stopped);
                tokio::task::yield_now().await;
            }
            let hosted = local(value)?;
            expected = expected
                .checked_add(usize::from(hosted))
                .context(SweepFailure::RouteInvalid)?;
            if hosted && roster.len() < crate::readiness::DETAIL_LIMIT {
                let route = kasumi_engine::control::TenantRoute::deserialize(value)
                    .context(SweepFailure::RouteInvalid)?;
                roster.push((tenant.clone(), route.incarnation));
            }
        }
        ensure!(!*stop.borrow(), SweepFailure::Stopped);
        ensure!(self.readiness_epoch()? == epoch, SweepFailure::EpochChanged);
        let started = Instant::now();
        self.readiness.begin(epoch, expected, started);
        self.readiness.enroll(roster);
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
                .readiness_generation(tenant, &route.incarnation)
                .context(SweepFailure::GenerationUnavailable)?;
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
        let selected = selected.context(SweepFailure::GenerationUnavailable)?;
        // A retained original owner may not have entered data routing yet.
        // Attach the same synchronous membership observer before its first
        // probe; a new attachment changes the epoch and requires a new sweep.
        self.registry
            .observe_membership(&selected.database)
            .context(SweepFailure::EpochUnavailable)?;
        ensure!(self.readiness_epoch()? == epoch, SweepFailure::EpochChanged);
        let mut quorum = false;
        let mut healthy = false;
        // Retain the actual installed handle for either the Raft observation or
        // a fresh negative local state probe. An absent handle cannot certify a
        // probe of a group that has never been opened here.
        if selected.database.check_serving().is_ok() && selected.store.check_access().is_ok() {
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
                    self.readiness.invalidate();
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
                match selected
                    .store
                    .storage_access()
                    .serving_gate()
                    .and_then(|g| g.remaining().ok())
                {
                    Some(remaining) if !remaining.is_zero() => {}
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

    #[test]
    fn an_hour_of_failed_sweeps_logs_its_transitions_not_each_second() {
        use crate::administration::failure_episodes::test_log::Logs;
        let logs = Logs::default();
        let _subscriber = logs.capture();
        let mut failures = FailureEpisodes::new(READINESS_REMINDER);
        let start = Instant::now();
        let first = std::time::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut sweep = |second: u64, failed: Option<ReadinessFailure>| {
            let elapsed = Duration::from_secs(second);
            report_sweep(&mut failures, failed, start + elapsed, first + elapsed);
        };
        // One sweep a second, as the probe runs, for an hour.
        for second in 0..3_600 {
            sweep(second, Some(("control_unavailable", "none")));
        }
        // The control plane closes: a new cause is a new report.
        sweep(3_600, Some(("control_unavailable", "key_lease_sealed")));
        sweep(3_601, None);
        sweep(3_602, None);

        let events = logs.events();
        assert_eq!(
            logs.event_names(),
            [
                "readiness_probe_failed",
                "readiness_probe_still_failing",
                "readiness_probe_still_failing",
                "readiness_probe_still_failing",
                "readiness_probe_still_failing",
                "readiness_probe_still_failing",
                "readiness_probe_failed",
                "readiness_probe_recovered",
            ]
        );
        let started = &events[0]["fields"];
        assert_eq!(started["readiness_error_class"], "control_unavailable");
        assert_eq!(started["control_closure_cause"], "none");
        assert_eq!(started["failed_sweeps"], 1);
        assert_eq!(events[0]["level"], "WARN");
        assert_eq!(events[1]["fields"]["failed_sweeps"], 601);
        assert_eq!(events[1]["fields"]["first_failure"], "2027-01-15T08:00:00Z");
        assert_eq!(
            events[6]["fields"]["control_closure_cause"],
            "key_lease_sealed"
        );
        assert_eq!(events[6]["fields"]["failed_sweeps"], 3_601);
        let recovered = &events[7];
        assert_eq!(recovered["level"], "INFO");
        assert_eq!(recovered["fields"]["failed_sweeps"], 3_601);
        assert_eq!(recovered["fields"]["first_failure"], "2027-01-15T08:00:00Z");
        assert_eq!(recovered["fields"]["last_failure"], "2027-01-15T09:00:00Z");
    }
}
