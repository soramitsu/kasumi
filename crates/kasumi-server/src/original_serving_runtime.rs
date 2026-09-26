//! Fresh admission of installed original tenants after a permanently closed
//! serving instance. Old engines, captured replies and storage handles stay shut.
use super::*;
use std::fmt;

/// Fixed, non-sensitive stage at which one fresh original admission attempt
/// stopped. Attached as error context; the underlying cause is never logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoverStage {
    EnrollmentMismatch,
    PreviousLeaseRetained,
    PreviousDetach,
    PreviousShutdownRetained,
    CustodyOpen,
    AccessLease,
    KeyProvider,
    StorageOpen,
    AdmissionReserve,
    EngineOpen,
    RouteRegister,
    SetupRouteChanged,
    Publish,
    Initialize,
}
impl RecoverStage {
    pub(crate) fn class(self) -> &'static str {
        match self {
            Self::EnrollmentMismatch => "enrollment_mismatch",
            Self::PreviousLeaseRetained => "previous_lease_retained",
            Self::PreviousDetach => "previous_detach",
            Self::PreviousShutdownRetained => "previous_shutdown_retained",
            Self::CustodyOpen => "custody_open",
            Self::AccessLease => "access_lease",
            Self::KeyProvider => "key_provider",
            Self::StorageOpen => "storage_open",
            Self::AdmissionReserve => "admission_reserve",
            Self::EngineOpen => "engine_open",
            Self::RouteRegister => "route_register",
            Self::SetupRouteChanged => "setup_route_changed",
            Self::Publish => "publish",
            Self::Initialize => "initialize",
        }
    }
}
impl fmt::Display for RecoverStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class())
    }
}

/// A closed original generation awaiting fresh admission. Its failed owner has
/// drained and left `generations`; this record keeps the retry authorized
/// without retaining that owner, and carries only fixed diagnostic classes.
#[derive(Clone, Debug)]
pub(crate) struct PendingAdmission {
    pub(crate) closure_cause: &'static str,
    pub(crate) key_lease_class: Option<&'static str>,
    pub(crate) drained_with_issues: BTreeSet<&'static str>,
    pub(crate) failed_attempts: u64,
}

/// Owners whose complete drain already recorded their issues. Entries are Weak
/// and pruned when their last handle drops, so this never extends a lifetime.
#[derive(Default)]
pub(crate) struct Superseded {
    databases: std::sync::Mutex<Vec<std::sync::Weak<Database>>>,
    leases: std::sync::Mutex<Vec<std::sync::Weak<crate::serving_runtime::RuntimeLease>>>,
}
fn retain_weak<T>(entries: &std::sync::Mutex<Vec<std::sync::Weak<T>>>, owner: &Arc<T>) {
    let mut entries = entries.lock().unwrap_or_else(|p| p.into_inner());
    entries.retain(|entry| entry.strong_count() > 0);
    if !entries
        .iter()
        .any(|entry| std::ptr::eq(entry.as_ptr(), Arc::as_ptr(owner)))
    {
        entries.push(Arc::downgrade(owner));
    }
}
fn contains_weak<T>(entries: &std::sync::Mutex<Vec<std::sync::Weak<T>>>, owner: &Arc<T>) -> bool {
    entries
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .any(|entry| std::ptr::eq(entry.as_ptr(), Arc::as_ptr(owner)))
}

/// Component names are fixed `&'static str` inventory labels, never errors.
fn component_names(failure: &DrainFailure) -> BTreeSet<&'static str> {
    failure
        .issues()
        .iter()
        .map(|issue| issue.component())
        .collect()
}

fn joined(names: &BTreeSet<&'static str>) -> String {
    names.iter().copied().collect::<Vec<_>>().join(",")
}

impl Administration {
    /// True only for this exact original database handle after its complete
    /// drain was observed and reported by fresh admission.
    pub(crate) fn superseded_database(&self, database: &Arc<Database>) -> bool {
        contains_weak(&self.superseded.databases, database)
    }

    pub(crate) fn superseded_lease(
        &self,
        lease: &Arc<crate::serving_runtime::RuntimeLease>,
    ) -> bool {
        contains_weak(&self.superseded.leases, lease)
    }

    #[cfg(test)]
    pub(crate) fn pending_admission(
        &self,
        tenant: &str,
        incarnation: &str,
    ) -> Option<PendingAdmission> {
        self.pending_admission
            .read()
            .ok()?
            .get(&(tenant.to_owned(), incarnation.to_owned()))
            .cloned()
    }

    /// One failed attempt of an already recorded closure. Returns its cause.
    pub(crate) fn record_failed_admission(&self, tenant: &str, incarnation: &str) -> &'static str {
        let Ok(mut pending) = self.pending_admission.write() else {
            return "unobservable";
        };
        match pending.get_mut(&(tenant.to_owned(), incarnation.to_owned())) {
            Some(record) => {
                record.failed_attempts = record.failed_attempts.saturating_add(1);
                record.closure_cause
            }
            None => "unobservable",
        }
    }

    pub(super) async fn recover_original(&self, tenant: &str, incarnation: &str) -> Result<()> {
        let Some(configured) = self
            .config
            .tenants
            .iter()
            .find(|entry| entry.tenant == tenant)
        else {
            return Ok(());
        };
        if self.config.mode == crate::runtime::DeploymentMode::Replicated {
            let enrolled = crate::node_enrollment::tenant_record(self.audit.store(), tenant)
                .context(RecoverStage::EnrollmentMismatch)?
                .context("routed original tenant has no enrollment")
                .context(RecoverStage::EnrollmentMismatch)?;
            ensure!(
                enrolled.stage == crate::node_enrollment::Stage::Prepared
                    && enrolled.incarnation
                        == Uuid::parse_str(incarnation)
                            .context(RecoverStage::EnrollmentMismatch)?,
                RecoverStage::EnrollmentMismatch
            );
        }
        let context = RequestContext {
            tenant: tenant.to_owned(),
            ..self.control_context.clone()
        };
        if matches!(
            self.registry.retirement_source(&context, incarnation),
            Ok(kasumi_engine::InstalledRetirementSource::RetiredCustody(_))
        ) {
            return Ok(());
        }
        let key = (tenant.to_owned(), incarnation.to_owned());
        let previous = self.generation(tenant, incarnation).ok();
        let pending = self
            .pending_admission
            .read()
            .map_err(|_| anyhow::anyhow!("pending admission registry unavailable"))?
            .contains_key(&key);
        if configured
            .incarnation
            .as_deref()
            .is_some_and(|installed| installed != incarnation)
            || (configured.incarnation.is_none() && previous.is_none() && !pending)
        {
            return Ok(());
        }
        if self
            .custody_generations
            .read()
            .map_err(|_| anyhow::anyhow!("custody registry unavailable"))?
            .contains_key(&key)
        {
            return Ok(());
        }
        if let Some(previous) = &previous {
            if previous.database.check_serving().is_ok() {
                return self
                    .initialize_original_if_ready(tenant, previous)
                    .await
                    .context(RecoverStage::Initialize);
            }
            self.observe_closure(tenant, incarnation, previous)?;
            if let Some(lease) = &previous.lease {
                match lease.shutdown().await {
                    Ok(()) => {}
                    Err(failure) if failure.completion() == DrainCompletion::Complete => {
                        self.record_drain_issues(tenant, incarnation, &failure);
                        retain_weak(&self.superseded.leases, lease);
                    }
                    Err(failure) => {
                        return Err(anyhow::Error::new(failure))
                            .context(RecoverStage::PreviousLeaseRetained);
                    }
                }
            }
            self.registry
                .detach_target_generation(tenant, incarnation, &previous.database)
                .context(RecoverStage::PreviousDetach)?;
            if let Some(network) = &self.cluster {
                network
                    .unregister_group(&format!("{tenant}/{incarnation}"))
                    .context(RecoverStage::PreviousDetach)?;
            }
            // Completion drains proposals, queries, Raft storage and key probes.
            // Retained caller handles still refer to this permanently closed instance.
            // A complete drain that recorded issues is still complete: those
            // issues are the closure's evidence, retained sticky by that owner,
            // not a reason to refuse fresh admission forever. Only an owner whose
            // completion is not established keeps this tenant closed.
            match previous.database.shutdown().await {
                Ok(()) => {}
                Err(failure) if failure.completion() == DrainCompletion::Complete => {
                    self.record_drain_issues(tenant, incarnation, &failure);
                    retain_weak(&self.superseded.databases, &previous.database);
                }
                Err(failure) => {
                    return Err(anyhow::Error::new(failure))
                        .context(RecoverStage::PreviousShutdownRetained);
                }
            }
            // Every owner of this exact failed instance has drained. Remove it
            // so neither retries nor daemon shutdown drain it again; the pending
            // record keeps fresh admission of this incarnation authorized.
            let mut generations = self
                .generations
                .write()
                .map_err(|_| anyhow::anyhow!("generation registry unavailable"))?;
            if generations
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(&current.database, &previous.database))
            {
                generations.remove(&key);
            }
        }
        let custody_provider = configured
            .custody_keys
            .provider(self.credential.clone())
            .context(RecoverStage::KeyProvider)?;
        if kasumi_store::CustodyStore::catalog_installed(&self.node, tenant)
            .context(RecoverStage::CustodyOpen)?
        {
            let custody = kasumi_store::CustodyStore::open(
                self.node.clone(),
                tenant.to_owned(),
                custody_provider.clone(),
            )
            .await
            .context(RecoverStage::CustodyOpen)?;
            if let Some(control) = kasumi_raft::ControlLog::installed(custody.clone())
                .context(RecoverStage::CustodyOpen)?
                && control
                    .recover_retired()
                    .context(RecoverStage::CustodyOpen)?
            {
                let owner = crate::runtime::open_retired_source(
                    &self.config,
                    custody,
                    self.cluster.as_ref(),
                    self.audit.clone(),
                    self.admission.clone(),
                )
                .await
                .context(RecoverStage::CustodyOpen)?;
                self.registry
                    .install_retirement_source(
                        kasumi_engine::InstalledRetirementSource::RetiredCustody(owner.clone()),
                    )
                    .context(RecoverStage::Publish)?;
                self.custody_generations
                    .write()
                    .map_err(|_| anyhow::anyhow!("custody registry unavailable"))
                    .context(RecoverStage::Publish)?
                    .insert(key.clone(), owner);
                // Retired custody never returns to data routing.
                self.registry
                    .set_pending_admission(tenant, incarnation, false)
                    .context(RecoverStage::Publish)?;
                self.finish_pending_admission(tenant, incarnation);
                return Ok(());
            }
        }
        // No application provider is constructed until the exact incarnation is
        // independently admitted again. This never uses a preparation fallback.
        let (access, lease) = crate::serving_runtime::acquire_tenant_access(
            &self.config,
            &self.authority_trusts,
            self.credential.clone(),
            tenant,
            Uuid::parse_str(incarnation)?,
            kasumi_serving::LeasePurpose::Serving,
        )
        .await
        .context(RecoverStage::AccessLease)?;
        let provider = configured
            .keys
            .provider(self.credential.clone())
            .context(RecoverStage::KeyProvider)?;
        let stores = TenantStorageSet::open_existing(
            self.node.clone(),
            tenant.to_owned(),
            provider.clone(),
            custody_provider.clone(),
            access,
        )
        .await
        .context(RecoverStage::StorageOpen)?;
        let group = format!("{tenant}/{incarnation}");
        let mut registered = false;
        let opened = async {
            // Replay requires the configured tenant audit placement, installed on
            // this fresh store exactly as at startup; none is selected by default.
            self.config
                .install_tenant_audit_archive(stores.application(), None)
                .context(RecoverStage::StorageOpen)?;
            let _reservation = self
                .admission
                .reserve(kasumi_engine::recovery_workspace_bytes(&stores)?, None)
                .context(RecoverStage::AdmissionReserve)?;
            let expected_incarnation = Uuid::parse_str(incarnation)?;
            let (database, bootstrap) =
                if self.config.mode == crate::runtime::DeploymentMode::Replicated {
                    let network = self.cluster.as_ref().context("replication unavailable")?;
                    let opened = kasumi_engine::open_existing_replicated(
                        self.config
                            .replication
                            .as_ref()
                            .context("replication unavailable")?
                            .node_id,
                        stores.clone(),
                        expected_incarnation,
                        network.clone(),
                        kasumi_raft::server_config(),
                        self.audit.clone(),
                    )
                    .await
                    .context(RecoverStage::EngineOpen)?;
                    let fingerprint = crate::runtime::opened_replicated_bootstrap_fingerprint(
                        stores.application().tenant(),
                        &opened,
                    )
                    .context(RecoverStage::EngineOpen)?;
                    let kasumi_engine::OpenedReplica {
                        database,
                        bootstrap,
                        ..
                    } = opened;
                    let store = stores.application().clone();
                    if let Err(error) = network.register_group_with_bootstrap(
                        group.clone(),
                        database.raft_group().raft().clone(),
                        self.config
                            .replication
                            .as_ref()
                            .unwrap()
                            .peers
                            .iter()
                            .map(|peer| peer.node_id)
                            .collect(),
                        fingerprint,
                        Arc::new(move || store.check_access()),
                    ) {
                        database.shutdown().await?;
                        return Err(error.context(RecoverStage::RouteRegister));
                    }
                    registered = true;
                    (database, Some(bootstrap))
                } else {
                    let database = kasumi_engine::open_existing_local(
                        stores.clone(),
                        self.audit.clone(),
                        expected_incarnation,
                    )
                    .await
                    .context(RecoverStage::EngineOpen)?;
                    (database, None)
                };
            let setup = (|| {
                for (name, destination) in &self.destinations {
                    database.install_archive_destination(name.clone(), destination.clone())?;
                }
                database.check_serving()?;
                ensure!(
                    self.committed_topology()?
                        .tenants
                        .get(tenant)
                        .is_some_and(|route| route.incarnation == incarnation),
                    "Control route changed during fresh tenant admission"
                );
                Ok::<_, anyhow::Error>(())
            })();
            if let Err(error) = setup {
                database.shutdown().await?;
                return Err(error.context(RecoverStage::SetupRouteChanged));
            }
            Ok(ManagedTenant {
                database,
                store: stores.application().clone(),
                bootstrap,
                lease,
            })
        }
        .await;
        let current = match opened {
            Ok(current) => current,
            Err(error) => {
                if registered && let Some(network) = &self.cluster {
                    network.unregister_group(&group)?;
                }
                return Err(match stores.shutdown().await {
                    Ok(()) => error,
                    Err(failure) => error.context(failure),
                });
            }
        };
        self.generations
            .write()
            .map_err(|_| anyhow::anyhow!("generation registry unavailable"))
            .context(RecoverStage::Publish)?
            .insert(key, current.clone());
        self.registry
            .install_retirement_source(kasumi_engine::InstalledRetirementSource::Serving(
                current.database.clone(),
            ))
            .context(RecoverStage::Publish)?;
        // Routing the fresh generation clears the registry's pending mark.
        self.finish_pending_admission(tenant, incarnation);
        self.initialize_original_if_ready(tenant, &current)
            .await
            .context(RecoverStage::Initialize)
    }

    /// Record the first observation of a closed generation with only fixed
    /// classes. Later attempts for the same incarnation reuse this record.
    fn observe_closure(
        &self,
        tenant: &str,
        incarnation: &str,
        previous: &ManagedTenant,
    ) -> Result<()> {
        let mut pending = self
            .pending_admission
            .write()
            .map_err(|_| anyhow::anyhow!("pending admission registry unavailable"))?;
        let key = (tenant.to_owned(), incarnation.to_owned());
        if pending.contains_key(&key) {
            return Ok(());
        }
        let record = PendingAdmission {
            closure_cause: previous
                .database
                .serving_failure_class()
                .unwrap_or("unclassified"),
            key_lease_class: previous.store.key_lease_failure_class(),
            drained_with_issues: BTreeSet::new(),
            failed_attempts: 0,
        };
        tracing::warn!(
            tenant,
            event = "original_tenant_closed",
            closure_cause = record.closure_cause,
            key_lease_class = record.key_lease_class.unwrap_or("none"),
            "original tenant closed; draining for fresh admission"
        );
        pending.insert(key, record);
        // Native callers bound to this incarnation now see a retryable outage
        // once the closed generation is detached, not an authorization denial.
        self.registry
            .set_pending_admission(tenant, incarnation, true)?;
        Ok(())
    }

    fn record_drain_issues(&self, tenant: &str, incarnation: &str, failure: &DrainFailure) {
        let names = component_names(failure);
        tracing::warn!(
            tenant,
            event = "original_tenant_drain_completed_with_issues",
            components = joined(&names),
            "closed original tenant drained with recorded issues"
        );
        if let Ok(mut pending) = self.pending_admission.write()
            && let Some(record) = pending.get_mut(&(tenant.to_owned(), incarnation.to_owned()))
        {
            record.drained_with_issues.extend(names);
        }
    }

    fn finish_pending_admission(&self, tenant: &str, incarnation: &str) {
        let Some(record) =
            self.pending_admission.write().ok().and_then(|mut pending| {
                pending.remove(&(tenant.to_owned(), incarnation.to_owned()))
            })
        else {
            return;
        };
        tracing::info!(
            tenant,
            event = "original_tenant_reopened",
            closure_cause = record.closure_cause,
            key_lease_class = record.key_lease_class.unwrap_or("none"),
            drained_with_issues = joined(&record.drained_with_issues),
            failed_attempts = record.failed_attempts,
            "original tenant reopened through fresh admission"
        );
    }

    async fn initialize_original_if_ready(
        &self,
        tenant: &str,
        current: &ManagedTenant,
    ) -> Result<()> {
        let Some(bootstrap) = &current.bootstrap else {
            return Ok(());
        };
        if current
            .database
            .raft_group()
            .raft()
            .is_initialized()
            .await?
        {
            return Ok(());
        }
        let local = self
            .config
            .replication
            .as_ref()
            .context("replication unavailable")?
            .node_id;
        if bootstrap.voters.keys().next() != Some(&local) {
            return Ok(());
        }
        let network = self.cluster.as_ref().context("replication unavailable")?;
        let group = format!("{tenant}/{}", bootstrap.incarnation);
        let expected =
            crate::runtime::persisted_replicated_bootstrap_fingerprint(current.database.stores())?;
        for member in bootstrap.voters.keys() {
            ensure!(
                network.bootstrap_fingerprint(*member, &group).await? == expected,
                "original tenant bootstrap differs across voters"
            );
        }
        kasumi_engine::initialize_replicated(&current.database, bootstrap).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recover_stage_is_the_only_logged_class_of_a_failed_attempt() {
        let failed: Result<()> = Err(anyhow::anyhow!("provider https://private.example/key"));
        let error = failed.context(RecoverStage::StorageOpen).unwrap_err();
        let stage = error.downcast_ref::<RecoverStage>().copied();
        assert_eq!(stage, Some(RecoverStage::StorageOpen));
        assert_eq!(stage.unwrap().class(), "storage_open");
        let ensured = (|| -> Result<()> {
            ensure!(false, RecoverStage::EnrollmentMismatch);
            Ok(())
        })()
        .unwrap_err();
        assert_eq!(
            ensured.downcast_ref::<RecoverStage>(),
            Some(&RecoverStage::EnrollmentMismatch)
        );
        // A later drain context keeps the stage observable beneath it.
        let nested = Err::<(), _>(anyhow::anyhow!("private detail"))
            .context(RecoverStage::EngineOpen)
            .context("store shutdown also failed")
            .unwrap_err();
        assert_eq!(
            nested.downcast_ref::<RecoverStage>(),
            Some(&RecoverStage::EngineOpen)
        );
        for stage in [
            RecoverStage::EnrollmentMismatch,
            RecoverStage::PreviousLeaseRetained,
            RecoverStage::PreviousDetach,
            RecoverStage::PreviousShutdownRetained,
            RecoverStage::CustodyOpen,
            RecoverStage::AccessLease,
            RecoverStage::KeyProvider,
            RecoverStage::StorageOpen,
            RecoverStage::AdmissionReserve,
            RecoverStage::EngineOpen,
            RecoverStage::RouteRegister,
            RecoverStage::SetupRouteChanged,
            RecoverStage::Publish,
            RecoverStage::Initialize,
        ] {
            assert!(
                stage
                    .class()
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
        }
    }
}
