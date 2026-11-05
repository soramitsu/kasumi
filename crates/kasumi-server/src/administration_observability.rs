use super::*;
use crate::observability::{
    CapacityObservation, GroupObservation, LocalObservation, RetentionObservation,
    StorageObservation, archive_backlog_bytes,
};

impl Administration {
    /// One bounded local sample for the protected observation routes. It
    /// lists every group of the readiness roster, whatever state coverage,
    /// stores or maintenance are in, and never waits on a database: storage
    /// figures are the node workers' published copies, the recovery flag is
    /// the readiness worker's, and closed stores report their last figures
    /// with an age instead of disappearing.
    pub(crate) async fn local_observation(&self) -> Result<LocalObservation> {
        let epoch = self.readiness_epoch()?;
        let now = tokio::time::Instant::now();
        let clock = std::time::Instant::now();
        let coverage = self.readiness.snapshot(epoch, now);
        let roster = coverage
            .roster
            .map(|roster| roster.groups)
            .unwrap_or_default();
        self.observation.retain_roster(&roster);
        let authority_required = self.config.mode == crate::runtime::DeploymentMode::Replicated;
        let mut groups = Vec::with_capacity(roster.len());
        let mut stores = Vec::with_capacity(roster.len());
        for (tenant, incarnation) in roster {
            let control = tenant == crate::runtime::CONTROL_TENANT;
            let routed = if control {
                self.control
                    .engine()
                    .generation()
                    .is_ok_and(|generation| generation.incarnation() == incarnation)
            } else {
                self.registry
                    .installed_generation(&tenant, &incarnation)
                    .ok()
                    .flatten()
                    .is_some()
            };
            // A failed lookup describes this group as unavailable; it never
            // withholds the other groups' figures.
            let managed = if control {
                routed.then(|| SelectedTenant::new(self.control.clone()))
            } else {
                self.readiness_generation(&tenant, &incarnation)
                    .ok()
                    .flatten()
            };
            let probe = coverage
                .probes
                .get(&tenant)
                .filter(|probe| probe.incarnation == incarnation);
            let mut observation = GroupObservation {
                tenant,
                store_available: false,
                routed,
                quorum: probe.map(|probe| probe.quorum),
                probe_age_seconds: probe
                    .map(|probe| now.saturating_duration_since(probe.at).as_secs_f64()),
                authority_required,
                authority_remaining_seconds: None,
                figures_age_seconds: None,
                retention: None,
                audit_maintenance: None,
                capacity: None,
                storage_dedicated: None,
                storage: None,
            };
            let mut dedicated_storage = None;
            if let Some(managed) = managed {
                let node = managed.store.node_store();
                let dedicated = !NodeStore::ptr_eq(node, &self.node);
                observation.storage_dedicated = Some(dedicated);
                if dedicated {
                    dedicated_storage = node.published_storage_status();
                    observation.storage = dedicated_storage
                        .as_ref()
                        .map(|published| StorageObservation::published(published, clock));
                }
                if let Some(gate) = managed.store.storage_access().serving_gate() {
                    observation.authority_remaining_seconds =
                        gate.remaining().ok().map(|value| value.as_secs_f64());
                }
                if managed.database.check_serving().is_ok()
                    && managed.store.check_access().is_ok()
                    && let Ok(generation) = managed.database.engine().generation()
                {
                    let retention = generation.audit_retention();
                    let budget = &generation.limits().audit_retention;
                    observation.capacity = Some(CapacityObservation {
                        documents: generation.document_count(),
                        logical_bytes: generation.logical_bytes(),
                        logical_budget_bytes: generation.limits().max_logical_bytes,
                        snapshot_disk_budget_bytes: generation.limits().max_snapshot_bytes,
                        permanent_staged_bytes: generation.permanent_staged_bytes(),
                        reserved_staged_terminal_bytes: generation.reserved_staged_terminal_bytes(),
                        permanent_staged_budget_bytes: generation
                            .limits()
                            .atomic
                            .max_permanent_staged_bytes,
                        schema_activation_bytes: generation.schema_activation_bytes(),
                        schema_activation_budget_bytes: generation
                            .limits()
                            .max_schema_activation_bytes,
                        retirement_bytes: generation.retirement_bytes(),
                        retirement_budget_bytes: generation.limits().max_retirement_bytes,
                    });
                    observation.retention = Some(RetentionObservation {
                        next_sequence: retention.next_sequence,
                        pruned_before: retention.pruned_before,
                        hot_bytes: retention.hot_bytes,
                        archive_bytes: retention.archive_bytes,
                        archive_segments: retention.archive_segments,
                        draining: retention.draining,
                        archive_backlog_bytes: archive_backlog_bytes(
                            retention.hot_bytes,
                            budget,
                            retention.draining,
                            !generation.retired() && generation.pending_restore().is_none(),
                        ),
                        hot_budget_bytes: budget.hot_bytes,
                        archive_budget_bytes: budget.archive_bytes,
                    });
                    observation.audit_maintenance = managed.database.audit_maintenance_status();
                    observation.store_available = true;
                    stores.push(managed.store);
                }
            }
            if !observation.store_available {
                // No remaining-lifetime value is released without the original
                // live store/gate being retained in the response fence.
                observation.authority_remaining_seconds = None;
            }
            self.observation.reconcile(
                &mut observation,
                &incarnation,
                dedicated_storage,
                now,
                clock,
            );
            groups.push(observation);
        }
        let standalone_recovery_pending =
            if self.config.mode == crate::runtime::DeploymentMode::Standalone {
                self.observation.recovery_pending()
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
            storage: self
                .node
                .published_storage_status()
                .map(|published| StorageObservation::published(&published, clock)),
        })
    }
}
