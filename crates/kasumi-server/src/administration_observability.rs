use super::*;
use crate::observability::{
    CapacityObservation, GroupObservation, LocalObservation, RetentionObservation,
};

impl Administration {
    pub(crate) async fn local_observation(&self) -> Result<LocalObservation> {
        let epoch = self.readiness_epoch()?;
        let coverage = self.readiness.snapshot(epoch, tokio::time::Instant::now());
        let mut groups = Vec::with_capacity(coverage.details.len());
        let mut stores = Vec::with_capacity(coverage.details.len());
        // Scrapes consume one bounded diagnostic page. The independently owned
        // worker certifies every required group; this detail limit is never a
        // readiness group-count limit and performs no foreground quorum probes.
        for sample in coverage.details {
            let managed = if sample.tenant == crate::runtime::CONTROL_TENANT {
                (self.control.engine().generation()?.state.incarnation == sample.incarnation)
                    .then(|| SelectedTenant::new(self.control.clone()))
            } else {
                self.registry
                    .installed_generation(&sample.tenant, &sample.incarnation)?
                    .map(SelectedTenant::new)
            };
            let routed = managed.is_some();
            let authority_required = self.config.mode == crate::runtime::DeploymentMode::Replicated;
            let mut observation = GroupObservation {
                tenant: sample.tenant,
                store_available: false,
                routed,
                quorum: coverage.status.fresh.then_some(sample.quorum),
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
                if managed.database.check_serving().is_ok()
                    && managed.store.check_access().is_ok()
                    && let Ok(generation) = managed.database.engine().generation()
                {
                    let retention = &generation.state.audit_retention;
                    let budget = &generation.state.limits.audit_retention;
                    observation.capacity = Some(CapacityObservation {
                        documents: generation.state.document_count,
                        logical_bytes: generation.state.logical_bytes,
                        logical_budget_bytes: generation.state.limits.max_logical_bytes,
                        snapshot_disk_budget_bytes: generation.state.limits.max_snapshot_bytes,
                        permanent_staged_bytes: generation.state.permanent_staged_bytes,
                        reserved_staged_terminal_bytes: generation
                            .state
                            .reserved_staged_terminal_bytes,
                        permanent_staged_budget_bytes: generation
                            .state
                            .limits
                            .atomic
                            .max_permanent_staged_bytes,
                        schema_activation_bytes: generation.state.schema_activation_bytes,
                        schema_activation_budget_bytes: generation
                            .state
                            .limits
                            .max_schema_activation_bytes,
                        retirement_bytes: generation.state.retirement_bytes,
                        retirement_budget_bytes: generation.state.limits.max_retirement_bytes,
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
            persistent_disk: self.node.persistent_disk().snapshot(),
            scratch_disk: self.node.scratch_disk().snapshot(),
            coverage: coverage.status,
            coverage_token: coverage.token,
            groups,
            stores,
            standalone_recovery_pending,
        })
    }
}
