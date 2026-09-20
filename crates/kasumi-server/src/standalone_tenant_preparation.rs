//! Creation under the already owned standalone installation. This scope grants
//! no authority over another independent copy of the installation.
use super::*;

impl Administration {
    pub(super) async fn prepare_local_enrollment(
        &self,
        prepared: &mut PreparedTenant,
    ) -> Result<()> {
        let proposal = prepared.proposal.clone();
        let tenant = &proposal.tenant;
        ensure!(
            crate::standalone::requires_provisioned(&self.config),
            "standalone enrollment requires an installed production scope"
        );
        ensure!(
            proposal.authority_id.is_none()
                && proposal.route.mode == kasumi_engine::control::DeploymentMode::Local,
            "standalone proposal contains distributed authority"
        );
        node_enrollment::require_complete(
            self.audit.store(),
            self.config.database_id,
            node_enrollment::Kind::Data,
        )?;
        {
            let generations = self
                .generations
                .read()
                .map_err(|_| anyhow::anyhow!("generation registry poisoned"))?;
            ensure!(
                !generations.keys().any(|(name, _)| name == tenant),
                "another configured generation owns this tenant"
            );
            let selected = self
                .config
                .tenants
                .iter()
                .filter(|entry| {
                    entry.tenant == *tenant
                        || generations.keys().any(|(name, _)| name == &entry.tenant)
                })
                .collect::<Vec<_>>();
            self.config.validate_selected_key_domains(&selected)?;
        }
        let configured = self
            .config
            .tenants
            .iter()
            .find(|entry| entry.tenant == *tenant)
            .context("configured template disappeared")?;
        let TenantServingConfig::Standalone { installation_id } = configured.serving else {
            anyhow::bail!("standalone enrollment requires explicit installation identity")
        };
        let incarnation = Uuid::parse_str(&proposal.route.incarnation)?;
        let access = kasumi_store::StorageAccess::standalone(installation_id, tenant, incarnation)?;
        self.check_enrollment(&prepared.invocation)?;
        let existing = node_enrollment::tenant_record(self.audit.store(), tenant)?;
        if let Some(record) = &existing {
            record.require_proposal(&proposal)?;
            ensure!(
                record.stage == Stage::Prepared,
                "original local creation is incomplete; retry cannot recreate it"
            );
        } else {
            let mut record = node_enrollment::dispatch_tenant(
                self.audit.store(),
                proposal.clone(),
                prepared.invocation.context.request_id.clone(),
            )?;
            prepared.resources.borrowed_nodes.push(self.node.clone());
            let stores = TenantStorageSet::initialize_catalogs(
                self.node.clone(),
                tenant.clone(),
                configured.keys.provider(self.credential.clone())?,
                configured.custody_keys.provider(self.credential.clone())?,
                access.clone(),
            )
            .await?;
            prepared.resources.stores.push(stores.application().clone());
            prepared
                .resources
                .stores
                .push(stores.custody().store().clone());
            self.config
                .install_tenant_audit_archive(stores.application(), None)?;
            self.check_enrollment(&prepared.invocation)?;
            let database = kasumi_engine::open_local_with_incarnation(
                stores.clone(),
                proposal.initial_policy.clone(),
                proposal.initial_limits.clone(),
                self.audit.clone(),
                incarnation,
            )
            .await?;
            prepared.resources.databases.push(database.clone());
            let resident = ManagedTenant {
                database,
                store: stores.application().clone(),
                bootstrap: None,
                lease: None,
            };
            self.require_resident_proposal(&resident, &proposal)?;
            let fingerprint =
                crate::runtime::persisted_bootstrap_fingerprint(stores.application())?;
            stores.application().write_batch(&[WriteOp::put(
                "runtime.provisioning",
                b"prepared",
                proposal.digest()?.as_bytes(),
            )])?;
            crate::startup_owner::finish(&mut prepared.resources).await?;
            self.check_enrollment(&prepared.invocation)?;
            let before = record.clone();
            record.stage = Stage::Prepared;
            record.bootstrap_sha256 = Some(fingerprint);
            node_enrollment::update_tenant(self.audit.store(), &before, &record)?;
            self.check_enrollment(&prepared.invocation)?;
            drop(resident);
            drop(stores);
            prepared.resources = Default::default();
        }
        self.check_enrollment(&prepared.invocation)?;
        prepared.resources.borrowed_nodes.push(self.node.clone());
        let stores = TenantStorageSet::open_existing(
            self.node.clone(),
            tenant.clone(),
            configured.keys.provider(self.credential.clone())?,
            configured.custody_keys.provider(self.credential.clone())?,
            access,
        )
        .await?;
        prepared.resources.stores.push(stores.application().clone());
        prepared
            .resources
            .stores
            .push(stores.custody().store().clone());
        self.config
            .install_tenant_audit_archive(stores.application(), None)?;
        let database =
            kasumi_engine::open_existing_local(stores.clone(), self.audit.clone(), incarnation)
                .await?;
        prepared.resources.databases.push(database.clone());
        for (alias, destination) in &self.destinations {
            database.install_archive_destination(alias.clone(), destination.clone())?;
        }
        let record = node_enrollment::tenant_record(self.audit.store(), tenant)?
            .context("prepared enrollment disappeared")?;
        record.require_proposal(&proposal)?;
        ensure!(
            record.stage == Stage::Prepared
                && record.bootstrap_sha256.as_ref()
                    == Some(&crate::runtime::persisted_bootstrap_fingerprint(
                        stores.application()
                    )?),
            "prepared local bootstrap differs from its permanent outcome"
        );
        let resident = ManagedTenant {
            database,
            store: stores.application().clone(),
            bootstrap: None,
            lease: None,
        };
        self.require_resident_proposal(&resident, &proposal)?;
        self.node.drain_initializers().await?;
        prepared.resident = Some(resident);
        prepared.publish = true;
        Ok(())
    }
}
