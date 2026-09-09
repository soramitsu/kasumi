//! Fresh admission of installed original tenants after a permanently closed
//! serving instance. Old engines, captured replies and storage handles stay shut.
use super::*;

impl Administration {
    pub(super) async fn recover_original(&self, tenant: &str, incarnation: &str) -> Result<()> {
        let Some(configured) = self
            .config
            .tenants
            .iter()
            .find(|entry| entry.tenant == tenant)
        else {
            return Ok(());
        };
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
        let previous = self.generation(tenant, incarnation).ok();
        if configured
            .incarnation
            .as_deref()
            .is_some_and(|installed| installed != incarnation)
            || (configured.incarnation.is_none() && previous.is_none())
        {
            return Ok(());
        }
        if self
            .custody_generations
            .read()
            .map_err(|_| anyhow::anyhow!("custody registry unavailable"))?
            .contains_key(&(tenant.to_owned(), incarnation.to_owned()))
        {
            return Ok(());
        }
        if let Some(previous) = &previous {
            if previous.database.check_serving().is_ok() {
                return self.initialize_original_if_ready(tenant, previous).await;
            }
            if let Some(lease) = &previous.lease {
                lease.shutdown().await?;
            }
            self.registry
                .detach_target_generation(tenant, incarnation, &previous.database)?;
            if let Some(network) = &self.cluster {
                network.unregister_group(&format!("{tenant}/{incarnation}"))?;
            }
            // Completion drains proposals, queries, Raft storage and key probes.
            // Retained caller handles still refer to this permanently closed instance.
            previous.database.shutdown().await?;
        }
        let custody_provider = configured.custody_keys.provider(self.credential.clone())?;
        if kasumi_store::CustodyStore::catalog_installed(&self.node, tenant)? {
            let custody = kasumi_store::CustodyStore::open(
                self.node.clone(),
                tenant.to_owned(),
                custody_provider.clone(),
            )
            .await?;
            if let Some(control) = kasumi_raft::ControlLog::installed(custody.clone())?
                && control.recover_retired()?
            {
                let owner = crate::runtime::open_retired_source(
                    &self.config,
                    custody,
                    self.cluster.as_ref(),
                    self.audit.clone(),
                    self.admission.clone(),
                )
                .await?;
                self.registry.install_retirement_source(
                    kasumi_engine::InstalledRetirementSource::RetiredCustody(owner.clone()),
                )?;
                self.custody_generations
                    .write()
                    .map_err(|_| anyhow::anyhow!("custody registry unavailable"))?
                    .insert((tenant.to_owned(), incarnation.to_owned()), owner);
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
        .await?;
        let provider = configured.keys.provider(self.credential.clone())?;
        let stores = TenantStorageSet::open_existing(
            self.node.clone(),
            tenant.to_owned(),
            provider.clone(),
            custody_provider.clone(),
            access,
        )
        .await?;
        let group = format!("{tenant}/{incarnation}");
        let mut registered = false;
        let opened = async {
            let _reservation = self
                .admission
                .reserve(kasumi_engine::recovery_workspace_bytes(&stores)?, None)?;
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
                    .await?;
                    let kasumi_engine::OpenedReplica {
                        database,
                        bootstrap,
                    } = opened;
                    let fingerprint =
                        crate::runtime::persisted_bootstrap_fingerprint(stores.application())?;
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
                        return Err(error);
                    }
                    registered = true;
                    (database, Some(bootstrap))
                } else {
                    let database = kasumi_engine::open_existing_local(
                        stores.clone(),
                        self.audit.clone(),
                        expected_incarnation,
                    )
                    .await?;
                    (database, None)
                };
            let setup = (|| {
                database.install_admission(self.admission.clone())?;
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
                return Err(error);
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
                stores.application().shutdown().await;
                stores.custody().store().shutdown().await;
                return Err(error);
            }
        };
        self.generations
            .write()
            .map_err(|_| anyhow::anyhow!("generation registry unavailable"))?
            .insert((tenant.to_owned(), incarnation.to_owned()), current.clone());
        self.active
            .write()
            .map_err(|_| anyhow::anyhow!("active registry unavailable"))?
            .insert(tenant.to_owned(), incarnation.to_owned());
        self.registry.install_retirement_source(
            kasumi_engine::InstalledRetirementSource::Serving(current.database.clone()),
        )?;
        self.initialize_original_if_ready(tenant, &current).await
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
        let expected = crate::runtime::persisted_bootstrap_fingerprint(&current.store)?;
        for member in bootstrap.voters.keys() {
            ensure!(
                network.bootstrap_fingerprint(*member, &group).await? == expected,
                "original tenant bootstrap differs across voters"
            );
        }
        kasumi_engine::initialize_replicated(&current.database, bootstrap).await
    }
}
