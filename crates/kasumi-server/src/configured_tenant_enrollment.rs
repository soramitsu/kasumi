//! Explicit live enrollment of a configured template under committed Control
//! approval. The original creation grant is never renewed or recovered on retry.
use super::*;
use crate::{
    node_enrollment::{self, Proposal, Stage},
    serving_runtime::{RuntimeLease, TenantServingConfig},
};

#[derive(Clone)]
pub(super) enum ProvisionSelection {
    Proposal(Proposal),
    Resident(ManagedTenant),
}
impl ProvisionSelection {
    pub(super) fn proposal(&self) -> Result<&Proposal> {
        match self {
            Self::Proposal(value) => Ok(value),
            _ => anyhow::bail!("immutable enrollment proposal was not selected"),
        }
    }
    pub(super) fn resident(&self) -> Result<&ManagedTenant> {
        match self {
            Self::Resident(value) => Ok(value),
            _ => anyhow::bail!("prepared enrollment owner was not selected"),
        }
    }
}
pub(super) fn capture_deadline() -> Result<kasumi_clock::ElapsedDeadline> {
    let observation = kasumi_clock::EpochClock::system()?.observe()?;
    observation.until(
        observation
            .utc_ms()
            .checked_add(60_000)
            .context("enrollment deadline overflow")?,
    )
}
fn api_error(error: anyhow::Error) -> kasumi_types::Error {
    error
        .downcast_ref::<kasumi_types::Error>()
        .cloned()
        .unwrap_or_else(|| {
            kasumi_types::Error::new(kasumi_types::ErrorCode::Unavailable, error.to_string())
        })
}
impl Administration {
    pub(super) fn enrollment_proposal(&self, tenant: &str) -> Result<Proposal> {
        kasumi_types::validate_name(tenant)?;
        ensure!(
            !tenant.starts_with("__kasumi_"),
            "reserved tenant cannot be enrolled"
        );
        let configured = self
            .config
            .tenants
            .iter()
            .find(|entry| entry.tenant == tenant)
            .context("tenant is not operator configured")?;
        let bootstrap = self.config.bootstrap(
            &configured.initial_policy,
            &configured.initial_limits,
            configured.incarnation.as_deref(),
        )?;
        let incarnation = configured
            .incarnation
            .clone()
            .context("enrollment requires an explicit incarnation")?;
        let route = kasumi_engine::control::TenantRoute {
            incarnation,
            mode: if bootstrap.is_some() {
                kasumi_engine::control::DeploymentMode::Replicated
            } else {
                kasumi_engine::control::DeploymentMode::Local
            },
            voters: bootstrap
                .as_ref()
                .map(|value| value.voters.keys().copied().collect())
                .unwrap_or_else(|| BTreeSet::from([1])),
        };
        let configured_nodes = self.configured_nodes()?;
        let approved = self.committed_topology()?;
        let nodes = route
            .voters
            .iter()
            .map(|id| {
                let node = configured_nodes
                    .get(id)
                    .context("configured voter is absent")?;
                ensure!(
                    approved.nodes.get(id) == Some(node),
                    "voter identity/pins are not Control approved"
                );
                Ok((*id, node.clone()))
            })
            .collect::<Result<_>>()?;
        let authority_id = match &configured.serving {
            TenantServingConfig::Independent { authority } => Some(
                self.config
                    .serving_authorities
                    .get(authority)
                    .context("installed enrollment authority is missing")?
                    .manifest
                    .authority_id,
            ),
            TenantServingConfig::Standalone { .. } => None,
            #[cfg(any(test, feature = "test-utils"))]
            TenantServingConfig::LocalFixture => None,
        };
        let proposal = Proposal {
            format: 1,
            tenant: tenant.into(),
            route,
            nodes,
            initial_policy: configured.initial_policy.clone(),
            initial_limits: configured.initial_limits.clone(),
            application_keys: configured.keys.identity_descriptor()?,
            custody_keys: configured.custody_keys.identity_descriptor()?,
            authority_id,
        };
        proposal.digest()?;
        Ok(proposal)
    }
    pub(super) fn require_resident_proposal(
        &self,
        resident: &ManagedTenant,
        proposal: &Proposal,
    ) -> Result<()> {
        let generation = resident.database.engine().generation()?;
        ensure!(
            generation.state.incarnation == proposal.route.incarnation
                && generation.state.restored_from.is_none()
                && generation.state.pending_restore.is_none()
                && !generation.state.retired,
            "enrollment requires its exact fresh resident generation"
        );
        if !self
            .committed_topology()?
            .tenants
            .contains_key(&proposal.tenant)
        {
            ensure!(
                serde_json::to_vec(&generation.state.policy)?
                    == serde_json::to_vec(&proposal.initial_policy)?
                    && serde_json::to_vec(&generation.state.limits)?
                        == serde_json::to_vec(&proposal.initial_limits)?,
                "resident bootstrap policy/limits differ from the approved proposal"
            );
        }
        ensure!(
            self.provision_route(resident)? == proposal.route,
            "resident enrollment placement differs"
        );
        Ok(())
    }
    pub(super) fn approved_enrollment(&self, tenant: &str) -> Result<Proposal> {
        self.control.raft_group().check_access()?;
        let generation = self.control.engine().generation()?;
        let body = &generation
            .state
            .collections
            .get("tenant_enrollments")
            .and_then(|collection| collection.documents.get(tenant))
            .context("tenant has no committed Control enrollment approval")?
            .body;
        let proposal: Proposal = serde_json::from_value(body.clone())?;
        ensure!(
            proposal.tenant == tenant,
            "Control enrollment identity differs"
        );
        proposal.digest()?;
        Ok(proposal)
    }
    pub(super) async fn approve_tenant(
        &self,
        context: &RequestContext,
        tenant: &str,
        proposal: &Proposal,
    ) -> Result<serde_json::Value> {
        self.authorized(&self.current(&self.control_context)?, context, true)
            .await?;
        ensure!(
            proposal.tenant == tenant
                && self.enrollment_proposal(tenant)?.digest()? == proposal.digest()?,
            "selected enrollment proposal changed"
        );
        ensure!(
            !self.committed_topology()?.tenants.contains_key(tenant),
            "tenant already has a serving route"
        );
        let definition = kasumi_types::CollectionDefinition {
            retention_class: kasumi_types::CollectionRetentionClass::Operational,
            write_mode: kasumi_types::CollectionWriteMode::AppendOnly,
            name: "tenant_enrollments".into(),
            schema: serde_json::json!({"type":"object"}),
            indexes: vec![],
            strict_read_audit: true,
        };
        let existing = self
            .control
            .engine()
            .generation()?
            .state
            .collections
            .get("tenant_enrollments")
            .map(|collection| collection.definition.clone());
        match existing {
            Some(existing) => ensure!(
                serde_json::to_vec(&existing)? == serde_json::to_vec(&definition)?,
                "Control enrollment schema differs"
            ),
            None => {
                self.control
                    .administer(context.clone(), Operation::CreateCollection(definition))
                    .await?;
            }
        }
        let existing = self
            .control
            .engine()
            .generation()?
            .state
            .collections
            .get("tenant_enrollments")
            .and_then(|collection| collection.documents.get(tenant))
            .map(|document| document.body.clone());
        if let Some(existing) = existing {
            let approved: Proposal = serde_json::from_value(existing)?;
            ensure!(
                approved.digest()? == proposal.digest()?,
                "tenant already has another immutable approval"
            );
        } else {
            self.control
                .mutate(
                    context.clone(),
                    kasumi_types::MutationBatch {
                        idempotency_key: format!("approve-{}", proposal.digest()?),
                        read_set: vec![],
                        operations: vec![kasumi_types::Mutation::Put {
                            collection: "tenant_enrollments".into(),
                            id: tenant.into(),
                            body: serde_json::to_value(proposal)?,
                            expected: Precondition::Absent,
                        }],
                    },
                )
                .await?;
        }
        self.event(
            context,
            SecurityEventKind::Administration,
            SecurityOutcome::Succeeded,
        )
        .await?;
        Ok(
            serde_json::json!({"approved":true,"tenant":tenant,"bootstrap_sha256":proposal.digest()?}),
        )
    }
    fn check_enrollment(&self, invocation: &ManagementInvocation) -> Result<()> {
        ensure!(
            !*self
                .enrollment_closed
                .lock()
                .map_err(|_| anyhow::anyhow!("enrollment publication lock poisoned"))?,
            "administration is closing"
        );
        invocation
            .enrollment_deadline
            .as_ref()
            .context("original enrollment deadline missing")?
            .check()?;
        invocation.context.authorization.check_live()?;
        invocation.source.store.check_access()?;
        invocation
            .source
            .database
            .engine()
            .authorize(&invocation.context, None, Action::Admin)?;
        self.control
            .engine()
            .authorize(&self.control_context, None, Action::Admin)?;
        Ok(())
    }
    pub(super) async fn prepare_configured_tenant(
        self: Arc<Self>,
        invocation: ManagementInvocation,
    ) -> kasumi_types::Result<serde_json::Value> {
        self.check_enrollment(&invocation).map_err(api_error)?;
        let encoded = serde_json::to_vec(
            invocation
                .provisioning
                .as_ref()
                .context("selected proposal missing")
                .map_err(api_error)?
                .proposal()
                .map_err(api_error)?,
        )
        .map_err(|error| api_error(error.into()))?;
        let bytes = u64::try_from(encoded.len())
            .map_err(|error| api_error(error.into()))?
            .checked_mul(8)
            .and_then(|bytes| bytes.checked_add(64 << 10))
            .ok_or_else(|| api_error(anyhow::anyhow!("enrollment workspace overflow")))?;
        let reservation = self.admission.reserve(bytes, None)?;
        let manager = self.clone();
        let completed = crate::api::mutation_release(
            crate::startup_owner::open(crate::startup_owner::Kind::TenantEnrollment, async move {
                manager.open_enrollment(invocation, reservation).await
            })
            .await
            .map_err(api_error),
        )?;
        Ok(completed.result)
    }
    async fn open_enrollment(
        self: Arc<Self>,
        invocation: ManagementInvocation,
        reservation: kasumi_engine::admission::Reservation,
    ) -> Result<PreparedTenant> {
        let gate = self.gate.enter().await?;
        self.check_enrollment(&invocation)?;
        let proposal = invocation
            .provisioning
            .as_ref()
            .context("selected enrollment proposal missing")?
            .proposal()?
            .clone();
        self.authorized(&invocation.source, &invocation.context, true)
            .await?;
        self.check_enrollment(&invocation)?;
        ensure!(
            self.approved_enrollment(&proposal.tenant)?.digest()? == proposal.digest()?,
            "approved enrollment differs from this replica"
        );
        let mut prepared = PreparedTenant {
            drain_report: Default::default(),
            manager: self.clone(),
            invocation,
            _reservation: reservation,
            proposal,
            _gate: gate,
            resident: None,
            resources: Default::default(),
            lease: None,
            registered: None,
            publish: false,
            committed: false,
            result: serde_json::Value::Null,
        };
        let result = async {
            self.event(
                &prepared.invocation.context,
                SecurityEventKind::Administration,
                SecurityOutcome::Started,
            )
            .await?;
            self.prepare_owned(&mut prepared).await
        }
        .await;
        if let Err(error) = result {
            // Audit availability never decides whether newly owned workers drain.
            let _ = self
                .event(
                    &prepared.invocation.context,
                    SecurityEventKind::Administration,
                    SecurityOutcome::Failed,
                )
                .await;
            let drained = crate::startup_owner::finish(&mut prepared).await;
            return Err(match drained {
                Ok(()) => error,
                Err(drain) => error.context(drain),
            });
        }
        #[cfg(test)]
        tests::pause_ready(self.config.database_id).await;
        Ok(prepared)
    }
    async fn prepare_owned(&self, prepared: &mut PreparedTenant) -> Result<()> {
        let proposal = prepared.proposal.clone();
        let name = &proposal.tenant;
        self.check_enrollment(&prepared.invocation)?;
        let existing_owner = self
            .generations
            .read()
            .map_err(|_| anyhow::anyhow!("generation registry poisoned"))?
            .get(&(name.clone(), proposal.route.incarnation.clone()))
            .cloned();
        if let Some(resident) = existing_owner {
            self.require_resident_proposal(&resident, &proposal)?;
            resident.store.check_access()?;
            resident.store.write_batch(&[WriteOp::put(
                "runtime.provisioning",
                b"prepared",
                proposal.digest()?.as_bytes(),
            )])?;
            prepared.resident = Some(resident); // Explicitly borrowed: never in cleanup resources.
        } else if self.config.mode == crate::runtime::DeploymentMode::Standalone {
            self.prepare_local_enrollment(prepared).await?;
        } else {
            ensure!(
                !self
                    .generations
                    .read()
                    .map_err(|_| anyhow::anyhow!("generation registry poisoned"))?
                    .keys()
                    .any(|(tenant, _)| tenant == name),
                "another configured generation owns this tenant"
            );
            ensure!(
                self.config.mode == crate::runtime::DeploymentMode::Replicated,
                "fresh independent enrollment requires replicated mode"
            );
            node_enrollment::require_complete(
                self.audit.store(),
                self.config.database_id,
                node_enrollment::Kind::Data,
            )?;
            let configured = self
                .config
                .tenants
                .iter()
                .find(|tenant| tenant.tenant == *name)
                .context("configured template disappeared")?;
            let replication = self
                .config
                .replication
                .as_ref()
                .context("replication missing")?;
            let network = self.cluster.as_ref().context("cluster transport missing")?;
            let incarnation = Uuid::parse_str(&proposal.route.incarnation)?;
            let existing = node_enrollment::tenant_record(self.audit.store(), name)?;
            if let Some(record) = &existing {
                record.require_proposal(&proposal)?;
                ensure!(
                    record.stage == Stage::Prepared,
                    "original tenant creation is incomplete; it cannot be recreated by retry"
                );
            } else {
                {
                    let generations = self
                        .generations
                        .read()
                        .map_err(|_| anyhow::anyhow!("generation registry poisoned"))?;
                    let selected = self
                        .config
                        .tenants
                        .iter()
                        .filter(|tenant| {
                            tenant.tenant == *name
                                || generations.keys().any(|(name, _)| name == &tenant.tenant)
                        })
                        .collect::<Vec<_>>();
                    self.config.validate_selected_key_domains(&selected)?;
                }
                let TenantServingConfig::Independent { authority } = &configured.serving else {
                    anyhow::bail!("live HA enrollment requires independent authority")
                };
                let installed = self
                    .config
                    .serving_authorities
                    .get(authority)
                    .context("enrollment authority missing")?;
                let (lease, grant) = RuntimeLease::acquire_for_enrollment(
                    installed,
                    self.authority_trusts
                        .get(authority)
                        .context("live enrollment trust missing")?
                        .clone(),
                    self.credential.clone(),
                    name,
                    incarnation,
                    replication.node_id,
                )
                .await?;
                prepared.lease = Some(lease.clone());
                prepared.resources.borrowed_nodes.push(self.node.clone());
                self.check_enrollment(&prepared.invocation)?;
                ensure!(
                    grant.identity().authority_epoch == 1
                        && lease.gate().recovery_checkpoint()?.is_none(),
                    "restored or retired incarnation cannot enroll"
                );
                grant.check()?;
                let mut record = node_enrollment::dispatch_tenant(
                    self.audit.store(),
                    proposal.clone(),
                    prepared.invocation.context.request_id.clone(),
                )?;
                let before = record.clone();
                record.original_grant = Some(grant.signed().clone());
                node_enrollment::update_tenant(self.audit.store(), &before, &record)?;
                let stores = TenantStorageSet::initialize_catalogs(
                    self.node.clone(),
                    name.clone(),
                    configured.keys.provider(self.credential.clone())?,
                    configured.custody_keys.provider(self.credential.clone())?,
                    lease.access()?,
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
                grant.check()?;
                let bootstrap = self
                    .config
                    .bootstrap(
                        &proposal.initial_policy,
                        &proposal.initial_limits,
                        Some(&proposal.route.incarnation),
                    )?
                    .context("enrollment bootstrap missing")?;
                let database = kasumi_engine::open_replicated(
                    replication.node_id,
                    stores.clone(),
                    &bootstrap,
                    network.clone(),
                    kasumi_raft::server_config(),
                    self.audit.clone(),
                )
                .await?;
                prepared.resources.databases.push(database.clone());
                let resident = ManagedTenant {
                    store: stores.application().clone(),
                    database,
                    bootstrap: Some(bootstrap),
                    lease: Some(lease.clone()),
                };
                self.require_resident_proposal(&resident, &proposal)?;
                let fingerprint =
                    crate::runtime::persisted_bootstrap_fingerprint(stores.application())?;
                stores.application().write_batch(&[WriteOp::put(
                    "runtime.provisioning",
                    b"prepared",
                    proposal.digest()?.as_bytes(),
                )])?;
                // Finish all creation workers before committing its permanent outcome.
                crate::startup_owner::finish(&mut prepared.resources).await?;
                self.check_enrollment(&prepared.invocation)?;
                grant.check()?;
                let before = record.clone();
                record.stage = Stage::Prepared;
                record.bootstrap_sha256 = Some(fingerprint);
                node_enrollment::update_tenant(self.audit.store(), &before, &record)?;
                grant.check()?;
                self.check_enrollment(&prepared.invocation)?;
                lease.shutdown().await?;
                prepared.lease.take();
                drop(resident);
                drop(stores);
                prepared.resources = Default::default();
            }
            // Creation is already durably complete and drained. A fresh serving
            // instance only opens that exact state; it cannot finish partial genesis.
            self.check_enrollment(&prepared.invocation)?;
            let (access, lease) = crate::serving_runtime::acquire_tenant_access(
                &self.config,
                &self.authority_trusts,
                self.credential.clone(),
                name,
                incarnation,
                kasumi_serving::LeasePurpose::Serving,
            )
            .await?;
            prepared.lease = lease.clone();
            prepared.resources.borrowed_nodes.push(self.node.clone());
            let stores = TenantStorageSet::open_existing(
                self.node.clone(),
                name.clone(),
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
            let opened = kasumi_engine::open_existing_replicated(
                replication.node_id,
                stores.clone(),
                incarnation,
                network.clone(),
                kasumi_raft::server_config(),
                self.audit.clone(),
            )
            .await?;
            prepared.resources.databases.push(opened.database.clone());
            for (alias, destination) in &self.destinations {
                opened
                    .database
                    .install_archive_destination(alias.clone(), destination.clone())?;
            }
            let record = node_enrollment::tenant_record(self.audit.store(), name)?
                .context("prepared enrollment disappeared")?;
            record.require_proposal(&proposal)?;
            let fingerprint =
                crate::runtime::persisted_bootstrap_fingerprint(stores.application())?;
            ensure!(
                record.stage == Stage::Prepared
                    && record.bootstrap_sha256.as_ref() == Some(&fingerprint),
                "prepared bootstrap differs from enrollment outcome"
            );
            let resident = ManagedTenant {
                database: opened.database,
                store: stores.application().clone(),
                bootstrap: Some(opened.bootstrap),
                lease,
            };
            self.require_resident_proposal(&resident, &proposal)?;
            self.node.drain_initializers().await?;
            let group = format!("{name}/{incarnation}");
            let store = stores.application().clone();
            network.register_group_with_bootstrap(
                group.clone(),
                resident.database.raft_group().raft().clone(),
                replication.peers.iter().map(|peer| peer.node_id).collect(),
                fingerprint,
                Arc::new(move || store.check_access()),
            )?;
            prepared.registered = Some(group);
            prepared.publish = true;
            prepared.resident = Some(resident);
        }
        self.check_enrollment(&prepared.invocation)?;
        self.event(
            &prepared.invocation.context,
            SecurityEventKind::Administration,
            SecurityOutcome::Succeeded,
        )
        .await?;
        prepared.result = serde_json::json!({"prepared":true,"tenant":name,"bootstrap_sha256":proposal.digest()?,"incarnation":proposal.route.incarnation});
        Ok(())
    }
}
struct PreparedTenant {
    drain_report: kasumi_types::drain::DrainReport,
    _reservation: kasumi_engine::admission::Reservation,
    manager: Arc<Administration>,
    invocation: ManagementInvocation,
    proposal: Proposal,
    _gate: tokio::sync::OwnedMutexGuard<()>,
    resident: Option<ManagedTenant>,
    resources: crate::startup_resources::Resources,
    lease: Option<Arc<RuntimeLease>>,
    registered: Option<String>,
    publish: bool,
    committed: bool,
    result: serde_json::Value,
}
impl crate::startup_owner::Runtime for PreparedTenant {
    fn handoff(&mut self) -> Result<()> {
        self.manager.check_enrollment(&self.invocation)?;
        let resident = self
            .resident
            .as_ref()
            .context("prepared enrollment owner missing")?;
        self.manager
            .require_resident_proposal(resident, &self.proposal)?;
        ensure!(
            self.manager
                .enrollment_proposal(&self.proposal.tenant)?
                .digest()?
                == self.proposal.digest()?,
            "configured key/placement proposal changed during enrollment"
        );
        ensure!(
            self.manager
                .approved_enrollment(&self.proposal.tenant)?
                .digest()?
                == self.proposal.digest()?,
            "Control approval changed before handoff"
        );
        resident.store.check_access()?;
        let closed = self
            .manager
            .enrollment_closed
            .lock()
            .map_err(|_| anyhow::anyhow!("enrollment publication lock poisoned"))?;
        ensure!(!*closed, "administration closed before enrollment handoff");
        let mut response_selection = self
            .invocation
            .prepared_selection
            .lock()
            .map_err(|_| anyhow::anyhow!("enrollment response selection poisoned"))?;
        self.invocation.context.authorization.check_live()?;
        self.invocation
            .enrollment_deadline
            .as_ref()
            .context("original deadline missing")?
            .check()?;
        resident.store.check_access()?;
        let selected = SelectedTenant::new(resident.database.clone());
        if self.publish {
            let mut generations = self
                .manager
                .generations
                .write()
                .map_err(|_| anyhow::anyhow!("generation registry poisoned"))?;
            let key = (
                self.proposal.tenant.clone(),
                self.proposal.route.incarnation.clone(),
            );
            ensure!(
                !generations
                    .keys()
                    .any(|(name, _)| name == &self.proposal.tenant),
                "another tenant owner appeared before enrollment handoff"
            );
            let owner = resident.clone();
            self.invocation.context.authorization.check_live()?;
            self.invocation
                .enrollment_deadline
                .as_ref()
                .context("original deadline missing")?
                .check()?;
            resident.store.check_access()?;
            generations.insert(key, owner);
        }
        *response_selection = Some(selected);
        self.committed = true;
        Ok(())
    }
    fn close(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kasumi_types::drain::DrainResult> + Send + '_>,
    > {
        Box::pin(async {
            use kasumi_types::drain::{DrainCompletion, DrainFailure};
            if self.committed {
                let issue = self.drain_report.record(
                    "enrollment handoff",
                    0,
                    anyhow::anyhow!("claimed enrollment owner belongs to Administration"),
                );
                return Err(DrainFailure::retained(issue));
            }
            let mut retained = None;
            if let Some(lease) = &self.lease {
                lease.close();
            }
            if let Some(group) = &self.registered {
                let unregistered = self
                    .manager
                    .cluster
                    .as_ref()
                    .context("registered cluster is absent")
                    .and_then(|cluster| cluster.unregister_group(group));
                match unregistered {
                    Ok(()) => self.registered = None,
                    Err(error) => {
                        retained = Some(DrainFailure::retained(self.drain_report.record(
                            "enrollment routing",
                            0,
                            error,
                        )));
                    }
                }
            }
            if let Err(error) = self.resources.close().await {
                self.drain_report.merge(&error);
                if error.completion() == DrainCompletion::Retained {
                    retained = Some(error);
                }
            }
            if let Some(lease) = &self.lease {
                match lease.shutdown().await {
                    Ok(()) => {
                        self.lease.take();
                    }
                    Err(error) => {
                        self.drain_report.merge(&error);
                        if error.completion() == DrainCompletion::Retained {
                            retained = Some(error);
                        } else {
                            self.lease.take();
                        }
                    }
                }
            }
            self.drain_report.outcome(retained)
        })
    }
}

#[cfg(test)]
#[path = "configured_tenant_enrollment_tests.rs"]
mod tests;

#[path = "standalone_tenant_preparation.rs"]
mod standalone_preparation;
