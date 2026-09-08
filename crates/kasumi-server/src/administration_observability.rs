use super::*;
use crate::observability::{
    CapacityObservation, GroupObservation, LocalObservation, MAX_GROUPS, RetentionObservation,
};

impl Administration {
    pub(crate) async fn local_observation(&self) -> Result<LocalObservation> {
        let local_id = self.config.replication.as_ref().map_or(1, |r| r.node_id);
        let control = self.configured(crate::runtime::CONTROL_TENANT)?;
        let (expected_groups, required) = {
            // Borrow the shared document root and decode one bounded route at a
            // time; a scrape never clones the entire Control topology document.
            self.control.raft_group().check_access()?;
            let generation = self.control.engine().generation()?;
            let document = generation
                .state
                .collections
                .get("topology")
                .and_then(|c| c.documents.get("current"))
                .context("control topology unavailable")?;
            let routes = document
                .body
                .get("tenants")
                .and_then(serde_json::Value::as_object)
                .context("control topology routes unavailable")?;
            let mut expected = 1usize;
            let mut required = Vec::with_capacity(MAX_GROUPS.min(1 + routes.len()));
            required.push((
                crate::runtime::CONTROL_TENANT.to_owned(),
                Some(control),
                true,
            ));
            for (tenant, value) in routes {
                let route = kasumi_engine::control::TenantRoute::deserialize(value)?;
                if !route.voters.contains(&local_id) {
                    continue;
                }
                expected = expected
                    .checked_add(1)
                    .context("local group count overflow")?;
                if required.len() == MAX_GROUPS {
                    continue;
                }
                let managed = self.generation(tenant, &route.incarnation).ok();
                let routed = self
                    .enabled
                    .read()
                    .map_err(|_| anyhow::anyhow!("routing unavailable"))?
                    .contains(tenant)
                    && self
                        .active
                        .read()
                        .map_err(|_| anyhow::anyhow!("routing unavailable"))?
                        .get(tenant)
                        == Some(&route.incarnation);
                required.push((tenant.clone(), managed, routed));
            }
            (expected, required)
        };
        let mut groups = Vec::with_capacity(required.len());
        let mut stores = Vec::with_capacity(required.len());
        // Probe work has one overall budget. A known leader value does not grant
        // readiness, and expiry of this budget leaves later quorum values absent.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        for (tenant, managed, routed) in required {
            let authority_required = self.config.mode == crate::runtime::DeploymentMode::Replicated;
            let mut observation = GroupObservation {
                tenant,
                store_available: false,
                routed,
                quorum: None,
                authority_required,
                authority_remaining_seconds: None,
                retention: None,
                capacity: None,
            };
            if let Some(managed) = managed {
                if let Some(gate) = managed.store.storage_access().serving_gate() {
                    observation.authority_remaining_seconds =
                        gate.remaining().ok().map(|value| value.as_secs_f64());
                }
                if managed.store.check_access().is_ok() {
                    if tokio::time::Instant::now() < deadline {
                        observation.quorum = Some(matches!(
                            tokio::time::timeout_at(
                                deadline.min(
                                    tokio::time::Instant::now() + std::time::Duration::from_secs(1)
                                ),
                                managed.database.raft_group().linearizable_barrier(),
                            )
                            .await,
                            Ok(Ok(_))
                        ));
                    }
                    if managed.store.check_access().is_ok()
                        && let Ok(generation) = managed.database.engine().generation()
                    {
                        let retention = &generation.state.audit_retention;
                        let budget = &generation.state.limits.audit_retention;
                        observation.capacity = Some(CapacityObservation {
                            documents: generation.state.document_count,
                            logical_bytes: generation.state.logical_bytes,
                            logical_budget_bytes: generation.state.limits.max_logical_bytes,
                            snapshot_disk_budget_bytes: generation.state.limits.max_snapshot_bytes,
                        });
                        observation.retention = Some(RetentionObservation {
                            next_sequence: retention.next_sequence,
                            pruned_before: retention.pruned_before,
                            hot_bytes: retention.hot_bytes,
                            archive_bytes: retention.archive_bytes,
                            archive_segments: retention.archive_segments,
                            draining: retention.draining,
                            hot_budget_bytes: budget.hot_bytes,
                            archive_budget_bytes: budget.archive_bytes,
                        });
                        observation.store_available = true;
                        stores.push(managed.store);
                    }
                }
            }
            if !observation.store_available {
                // No remaining-lifetime value is released without the original
                // live store/gate being retained in the response fence.
                observation.authority_remaining_seconds = None;
            }
            groups.push(observation);
        }
        let standalone_recovery_pending =
            if self.config.mode == crate::runtime::DeploymentMode::Standalone {
                Some(crate::local_recovery::runtime_pending(self.audit.store())?)
            } else {
                None
            };
        Ok(LocalObservation {
            admission: self.admission.snapshot(),
            expected_groups,
            groups,
            stores,
            standalone_recovery_pending,
        })
    }
}
