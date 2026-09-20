//! Bounded installed-target restart reconciliation. Only independently retained
//! exact activation plus a freshly acquired Serving lease may construct app keys.
use super::*;
use crate::{api::DatabaseRegistry, serving_runtime::RuntimeLease};
use std::ops::Bound;
impl TargetRecoveryRuntime {
    pub(super) fn start_serving_reconciliation(
        self: &Arc<Self>,
        budget: &kasumi_serving::BackgroundWorkBudget,
    ) -> Result<()> {
        let weak = Arc::downgrade(self);
        let wake = self.serving_monitor.wake();
        let task = async move {
            let mut after = None::<String>;
            loop {
                tokio::select! {
                    _ = wake.notified() => {},
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {},
                }
                let Some(runtime) = weak.upgrade() else {
                    break;
                };
                #[cfg(test)]
                runtime.serving_monitor.after_upgrade().await;
                if runtime.closing.load(Ordering::Acquire) {
                    break;
                }
                runtime.prune_inactive_serving().await;
                // Fixed bounded page over installed templates; historical journal
                // bodies are never gathered into memory or scanned for discovery.
                let lower = after.as_deref().map_or(Bound::Unbounded, Bound::Excluded);
                let names: Vec<_> = runtime
                    .installed
                    .tenants
                    .range::<str, _>((lower, Bound::Unbounded))
                    .take(16)
                    .map(|(name, _)| name.clone())
                    .collect();
                if names.is_empty() {
                    after = None;
                    continue;
                }
                after = names.last().cloned();
                for tenant in names {
                    if runtime.closing.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(_permit) = runtime.calls.clone().try_acquire_owned() else {
                        break;
                    };
                    // Failure remains non-serving and retries the exact retained
                    // candidate. It never downgrades or opens a source provider.
                    let mut stage = RecoveryStage::Projection;
                    match runtime.reconcile_serving(&tenant, &mut stage).await {
                        Ok(()) => runtime.record_recovery(&tenant, None),
                        Err(_) => runtime.record_recovery(&tenant, Some(stage)),
                    }
                }
            }
        };
        self.serving_monitor.start(task, budget)
    }
    async fn prune_inactive_serving(&self) {
        let candidates: Vec<_> = self
            .generations
            .lock()
            .await
            .iter()
            .map(|(key, owner)| (key.clone(), owner.clone()))
            .collect();
        for (key, owner) in candidates {
            let Ok(mut generation) = owner.try_lock() else {
                continue;
            };
            if generation
                .serving
                .as_ref()
                .is_some_and(|serving| serving.check().is_ok())
                || generation
                    .custody
                    .as_ref()
                    .is_some_and(|(_, custody)| custody.identity().is_ok())
                || generation
                    .phase
                    .as_ref()
                    .is_some_and(|phase| phase.scope().invocation().check().is_ok())
            {
                continue;
            }
            if generation
                .close(&self.cluster, &self.registry)
                .await
                .is_err()
            {
                continue;
            }
            drop(generation);
            let mut all = self.generations.lock().await;
            if Arc::strong_count(&owner) == 2
                && all
                    .get(&key)
                    .is_some_and(|current| Arc::ptr_eq(current, &owner))
            {
                all.remove(&key);
            }
        }
    }
    async fn reconcile_serving(&self, tenant: &str, stage: &mut RecoveryStage) -> Result<()> {
        ensure!(
            !self.closing.load(Ordering::Acquire),
            "target runtime closing"
        );
        let Some(incarnation) = self.journal.serving_candidate(tenant)? else {
            return Ok(());
        };
        let key = (tenant.to_owned(), incarnation);
        let template = &self.installed.tenants[tenant];
        *stage = RecoveryStage::Ownership;
        let target = {
            let mut all = self.generations.lock().await;
            if let Some(target) = all.get(&key) {
                target.clone()
            } else {
                ensure!(
                    all.len() < self.installed.limits.max_live_generations as usize,
                    "target live generation capacity exhausted"
                );
                let target = Arc::new(Mutex::new(Generation::default()));
                all.insert(key.clone(), target.clone());
                target
            }
        };
        let Ok(mut g) = target.try_lock() else {
            return Ok(());
        };
        if let Some((_, custody)) = &g.custody {
            if custody.identity().is_ok() {
                return Ok(());
            }
            g.close(&self.cluster, &self.registry).await?;
        }
        if let Some(owner) = &g.serving {
            if owner.check().is_ok() && g.registered_data.is_some() {
                return Ok(());
            }
            g.close(&self.cluster, &self.registry).await?;
        }
        if g.phase
            .as_ref()
            .is_some_and(|phase| !phase.scope().is_idle())
        {
            return Ok(());
        }
        // The same original management request keeps its phase alive through
        // final reply release. Only after every operation/reply drops may this
        // independent startup close that old payload group and its phase.
        g.close(&self.cluster, &self.registry).await?;
        let projection = Arc::new(
            self.journal
                .serving_projection(tenant, incarnation)?
                .context("activation projection unavailable")?,
        );
        let path = self.path(&key)?;
        ensure!(path.is_file(), "activated target file is missing");
        g.node = Some(NodeStore::open_existing(
            path,
            self.journal.materialization_file_id(&key.0, key.1)?,
            self.audit.store().persistent_disk().clone(),
            self.audit.store().scratch_disk().clone(),
        )?);
        self.placement(&projection.execution()?.origin.input)?;
        // Closed retirement recovery consults only independently keyed control
        // storage. It remains available after ordinary serving expires, without
        // constructing a municipality application provider or data authority.
        *stage = RecoveryStage::Custody;
        let custody_provider = template.custody_keys.provider(self.credential.clone())?;
        g.custody_probe = Some(
            kasumi_store::CustodyStore::open(
                g.node.as_ref().unwrap().clone(),
                tenant.into(),
                custody_provider,
            )
            .await?,
        );
        let probe = g.custody_probe.as_ref().unwrap().clone();
        let control = kasumi_raft::ControlLog::installed(probe.clone())?
            .context("target control identity missing")?;
        ensure!(
            control.group() == format!("{tenant}/{incarnation}")
                && control.node_id() == self.installed.node.node_id,
            "target control identity differs"
        );
        control.recover_retired()?;
        if control.is_retired()? {
            self.registry.install_retirement_source(
                kasumi_engine::InstalledRetirementSource::RecoveringControl {
                    tenant: tenant.into(),
                    source_incarnation: incarnation.to_string(),
                },
            )?;
            let custody = crate::runtime::open_retired_source(
                &self.config,
                probe.clone(),
                Some(&self.cluster),
                self.audit.clone(),
                self.admission.clone(),
            )
            .await?;
            ensure!(
                custody.identity()? == (tenant.into(), incarnation.to_string()),
                "retired target custody identity differs"
            );
            g.registered_group = Some(control.group().to_owned());
            self.registry.install_retirement_source(
                kasumi_engine::InstalledRetirementSource::RetiredCustody(custody.clone()),
            )?;
            g.custody = Some((key, custody));
            g.custody_probe = None;
            return Ok(());
        }
        drop(control);
        probe.store().shutdown().await?;
        g.custody_probe = None;
        drop(probe);
        *stage = RecoveryStage::Issuer;
        let authority = &self.config.serving_authorities[&template.authority];
        let lease = RuntimeLease::acquire(
            authority,
            self.authority_trusts
                .get(&template.authority)
                .context("live authority verifier absent")?
                .clone(),
            self.credential.clone(),
            tenant,
            incarnation,
            self.installed.node.node_id,
            LeasePurpose::Serving,
        )
        .await?;
        projection.check(lease.gate())?;
        ensure!(
            !self.closing.load(Ordering::Acquire),
            "target runtime closing"
        );
        // Provider construction follows both independently verified retained
        // metadata and current issuer admission; no old control/data JWT used.
        *stage = RecoveryStage::ApplicationKeys;
        let access = projection.storage_access(lease.gate().clone())?;
        let app = template
            .application_keys
            .provider(self.credential.clone())?;
        let custody = template.custody_keys.provider(self.credential.clone())?;
        projection.check(lease.gate())?;
        g.stores = Some(
            TenantStorageSet::open_existing(
                g.node.as_ref().unwrap().clone(),
                tenant.into(),
                app,
                custody,
                access,
            )
            .await?,
        );
        g.lease = Some(lease);
        let stores = g.stores.as_ref().unwrap().clone();
        self.config
            .install_tenant_audit_archive(stores.application(), None)?;
        *stage = RecoveryStage::LocalReplay;
        let owner = kasumi_engine::open_serving_target(
            projection.clone(),
            stores.clone(),
            kasumi_engine::TargetReplicaConfig {
                node_id: self.installed.node.node_id,
                raft: kasumi_raft::server_config(),
                admission: self.admission.clone(),
            },
            self.cluster.clone(),
            self.audit.clone(),
        )
        .await?;
        g.serving = Some(owner);
        let owner = g.serving.as_ref().context("opened serving owner absent")?;
        let database = owner.database()?;
        for (name, destination) in &self.destinations {
            database.install_archive_destination(name.clone(), destination.clone())?;
        }
        let execution = projection.execution()?;
        let name = format!("{tenant}/{incarnation}");
        let check = stores.clone();
        *stage = RecoveryStage::PeerRegistration;
        self.cluster.register_group_with_bootstrap(
            name.clone(),
            database.raft_group().raft().clone(),
            owner.bootstrap().voters.keys().copied().collect(),
            execution
                .completion
                .as_ref()
                .context("target completion absent")?
                .bootstrap_sha256
                .clone(),
            Arc::new(move || check.check_access()),
        )?;
        g.registered_group = Some(name);
        ensure!(
            !self.closing.load(Ordering::Acquire),
            "target runtime closing"
        );
        projection.check(g.lease.as_ref().unwrap().gate())?;
        *stage = RecoveryStage::DataRegistration;
        self.registry.insert(database.clone())?;
        g.registered_data = Some((key, database));
        g.serving.as_ref().unwrap().check()?;
        Ok(())
    }
}
/// Remove only the exact owned data handle. Independent source recovery keeps
/// a closed installed route, never an expired warm application Database Arc.
pub(super) fn detach_owned_data(
    registry: &DatabaseRegistry,
    key: &GenerationKey,
    database: &Arc<kasumi_engine::Database>,
) -> Result<()> {
    registry.detach_target_generation(&key.0, &key.1.to_string(), database)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecoveryStage {
    Projection,
    Ownership,
    Custody,
    Issuer,
    ApplicationKeys,
    LocalReplay,
    PeerRegistration,
    DataRegistration,
}
struct RecoveryFailure {
    stage: RecoveryStage,
    notified: bool,
    touched: u64,
}
pub(super) struct RecoveryHealth {
    failures: BTreeMap<String, RecoveryFailure>,
    sequence: u64,
    last_log: Option<std::time::Instant>,
}
impl RecoveryHealth {
    pub(super) fn new() -> Self {
        Self {
            failures: BTreeMap::new(),
            sequence: 0,
            last_log: None,
        }
    }
}
impl TargetRecoveryRuntime {
    fn record_recovery(&self, tenant: &str, stage: Option<RecoveryStage>) {
        let Ok(mut health) = self.recovery_health.lock() else {
            return;
        };
        let Some(stage) = stage else {
            if health.failures.remove(tenant).is_some() {
                tracing::info!(tenant, "installed target recovery resumed");
            }
            return;
        };
        health.sequence = health.sequence.saturating_add(1);
        let sequence = health.sequence;
        // Fixed metadata bound; no unbounded error bodies, tokens, paths or
        // per-attempt histories. Evicted failures may be reported conservatively
        // again, under the same process-wide one-warning-per-second ceiling.
        if !health.failures.contains_key(tenant) && health.failures.len() >= 128 {
            let oldest = health
                .failures
                .iter()
                .min_by_key(|(_, failure)| failure.touched)
                .map(|(name, _)| name.clone());
            if let Some(oldest) = oldest {
                health.failures.remove(&oldest);
            }
        }
        let failure = health
            .failures
            .entry(tenant.into())
            .or_insert(RecoveryFailure {
                stage,
                notified: false,
                touched: sequence,
            });
        if failure.stage != stage {
            failure.stage = stage;
            failure.notified = false;
        }
        failure.touched = sequence;
        let pending = !failure.notified;
        if pending
            && health
                .last_log
                .is_none_or(|last| last.elapsed() >= Duration::from_secs(1))
        {
            tracing::warn!(tenant, recovery_stage = ?stage, "installed target remains non-serving; check the configured authority, storage and recovery service for this stage");
            health.last_log = Some(std::time::Instant::now());
            health
                .failures
                .get_mut(tenant)
                .expect("inserted failure")
                .notified = true;
        }
    }
}
