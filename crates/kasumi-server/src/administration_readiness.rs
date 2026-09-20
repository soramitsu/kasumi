use super::*;
use crate::readiness::{Epoch, FRESHNESS, PROBE_TIMEOUT, Sample};
use std::time::Duration;
use tokio::{sync::watch, time::Instant};

impl Administration {
    pub(crate) fn readiness_epoch(&self) -> Result<Epoch> {
        self.control.check_serving()?;
        let generation = self.control.engine().generation()?;
        let document = generation
            .state
            .collections
            .get("topology")
            .and_then(|c| c.documents.get("current"))
            .context("control topology unavailable")?;
        Ok(Epoch {
            topology_version: document.version,
            installed_routes: self.registry.route_epoch()?,
            actual_membership: self.registry.membership_epoch()?,
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
            if self.readiness_sweep(&mut stop).await.is_err() {
                self.readiness.invalidate();
                tracing::warn!(
                    event = "readiness_probe_failed",
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
        let (epoch, document, _reservation) = {
            let generation = self.control.engine().generation()?;
            let document = generation
                .state
                .collections
                .get("topology")
                .and_then(|c| c.documents.get("current"))
                .context("control topology unavailable")?;
            let bytes = u64::try_from(kasumi_engine::retained_document_bytes(document)?)?
                .checked_add(128 << 10)
                .context("readiness workspace overflow")?;
            let mut reservation = self.admission.reserve(bytes, None)?;
            reservation.retain(bytes);
            let epoch = Epoch {
                topology_version: document.version,
                installed_routes: self.registry.route_epoch()?,
                actual_membership: self.registry.membership_epoch()?,
            };
            (epoch, document.clone(), reservation)
        };
        let local_id = self.config.replication.as_ref().map_or(1, |r| r.node_id);
        let routes = document
            .body
            .get("tenants")
            .and_then(serde_json::Value::as_object)
            .context("control topology routes unavailable")?;
        let local = |value: &serde_json::Value| -> Result<bool> {
            Ok(value
                .get("voters")
                .and_then(serde_json::Value::as_array)
                .context("control topology voters unavailable")?
                .iter()
                .any(|v| v.as_u64() == Some(local_id)))
        };
        let mut expected = 1usize;
        for (index, value) in routes.values().enumerate() {
            if index % 16 == 0 {
                ensure!(!*stop.borrow(), "readiness stopped");
                tokio::task::yield_now().await;
            }
            expected = expected
                .checked_add(usize::from(local(value)?))
                .context("local group count overflow")?;
        }
        ensure!(
            !*stop.borrow() && self.readiness_epoch()? == epoch,
            "readiness membership changed or stopped"
        );
        let started = Instant::now();
        self.readiness.begin(epoch, expected, started);
        let control_incarnation = self
            .control
            .engine()
            .generation()?
            .state
            .incarnation
            .clone();
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
            ensure!(!*stop.borrow(), "readiness stopped");
            ensure!(
                self.readiness_epoch()? == epoch,
                "readiness membership changed"
            );
            if index % 16 == 0 {
                tokio::task::yield_now().await;
                let memory = self.admission.snapshot();
                ensure!(
                    memory.sample_usable && !memory.pressured,
                    "readiness memory pressure"
                );
            }
            if !local(value)? {
                continue;
            }
            let route = kasumi_engine::control::TenantRoute::deserialize(value)?;
            let managed = self
                .registry
                .installed_generation(tenant, &route.incarnation)?
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
        ensure!(
            !*stop.borrow() && self.readiness_epoch()? == epoch,
            "readiness membership changed or stopped"
        );
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
            ensure!(!*stop.borrow(), "readiness stopped");
            let database = selected.database.clone();
            self.readiness
                .probe
                .start(&self.admission, async move {
                    database
                        .raft_group()
                        .readiness_probe(local_id, expected_voters)
                        .await
                })
                .await?;
            let observed = tokio::select! {
                biased;
                _ = stop.changed() => anyhow::bail!("readiness stopped"),
                observed = tokio::time::timeout(PROBE_TIMEOUT, self.readiness.probe.observe()) => observed,
            };
            use crate::readiness_probe::Outcome;
            quorum = match observed {
                Ok(Outcome::Healthy) => true,
                Ok(Outcome::Unhealthy) => false,
                Ok(Outcome::Failed) => anyhow::bail!("readiness actor probe failed"),
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
                    anyhow::bail!("readiness diagnostic deadline exceeded");
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
        ensure!(
            self.readiness_epoch()? == epoch,
            "readiness membership changed"
        );
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
