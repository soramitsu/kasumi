//! Audited maintenance of the exact installed data route. Recovery is owned by
//! the typed Control coordinator and target runner, never this management API.
use crate::{
    api::DatabaseRegistry,
    cluster::ClusterNetwork,
    runtime::{RuntimeConfig, SecurityAudit, SecurityEvent, SecurityEventKind, SecurityOutcome},
};
use anyhow::{Context, Result, ensure};
use kasumi_engine::{
    Database, ReplicatedBootstrap,
    control::{ControlPlane, ControlTopology},
};
use kasumi_store::{
    BackupDestination, FilesystemBackupDestination, NodeStore, S3BackupConfig, S3BackupDestination,
    TenantStorageSet, TenantStore, WriteOp,
};
use kasumi_types::drain::{DrainCompletion, DrainFailure, DrainReport, DrainResult};
use kasumi_types::{Action, Operation, Precondition, RequestContext};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DestinationConfig {
    Filesystem {
        directory: PathBuf,
        max_bytes: usize,
    },
    S3 {
        endpoint: String,
        region: String,
        bucket: String,
        prefix: String,
        credentials_file: PathBuf,
        ca_certificate: Option<PathBuf>,
        max_bytes: usize,
    },
}
impl DestinationConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Filesystem {
                directory,
                max_bytes,
            } => {
                ensure!(directory.is_absolute(), "backup directory must be absolute");
                bounded(*max_bytes)?;
            }
            Self::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                credentials_file,
                ca_certificate,
                max_bytes,
            } => {
                crate::runtime::origin(endpoint)?;
                for value in [region, bucket] {
                    ensure!(
                        crate::runtime::valid_transit_path(value) && !value.contains('/'),
                        "invalid S3 segment"
                    );
                }
                ensure!(
                    prefix.is_empty() || crate::runtime::valid_transit_path(prefix),
                    "invalid S3 prefix"
                );
                ensure!(
                    credentials_file.is_absolute(),
                    "S3 credential file must be absolute"
                );
                if let Some(path) = ca_certificate {
                    ensure!(path.is_absolute(), "S3 CA path must be absolute");
                }
                bounded(*max_bytes)?;
            }
        }
        Ok(())
    }
    pub(crate) fn open(
        &self,
        persistent_disk: Arc<kasumi_store::NodeDisk>,
    ) -> Result<Arc<dyn BackupDestination>> {
        self.validate()?;
        Ok(match self {
            Self::Filesystem {
                directory,
                max_bytes,
            } => Arc::new(FilesystemBackupDestination::new(
                directory,
                *max_bytes,
                persistent_disk,
            )?),
            Self::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                credentials_file,
                ca_certificate,
                max_bytes,
            } => Arc::new(S3BackupDestination::new(S3BackupConfig {
                endpoint: endpoint.clone(),
                region: region.clone(),
                bucket: bucket.clone(),
                prefix: prefix.clone(),
                credential: Arc::new(kasumi_transport::credentials::FileCredentialSource::new(
                    credentials_file,
                )?),
                ca_pem: ca_certificate
                    .as_ref()
                    .map(|path| crate::runtime::read_bounded(path, 1 << 20))
                    .transpose()?,
                max_bytes: *max_bytes,
            })?),
        })
    }
}
fn bounded(bytes: usize) -> Result<()> {
    ensure!(
        bytes > 0 && bytes <= kasumi_store::MAX_BACKUP_BUNDLE_BYTES,
        "backup destination limit must be within the encrypted bundle format limit"
    );
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagementCommand {
    Backup {
        destination: String,
        session_id: Uuid,
    },
    RotateDataKey,
    RewrapKeys,
    Status {},
    AddLearner {
        node_id: u64,
    },
    ChangeMembership {
        voters: BTreeSet<u64>,
    },
    PublishMembership {
        voters: BTreeSet<u64>,
    },
    /// The verified context must name the reserved control tenant.
    ApprovePeerPool {
        expected_topology_version: u64,
    },
    ApproveTenant {
        tenant: String,
    },
    PrepareTenant {
        tenant: String,
    },
    InitializeTenant {
        tenant: String,
    },
    ActivateTenant {
        tenant: String,
        expected_topology_version: u64,
    },
}
#[derive(Clone)]
pub(crate) struct ManagedTenant {
    pub database: Arc<Database>,
    pub store: Arc<TenantStore>,
    pub bootstrap: Option<ReplicatedBootstrap>,
    pub lease: Option<Arc<crate::serving_runtime::RuntimeLease>>,
}
#[path = "administration_command_jobs.rs"]
mod command_jobs;
#[path = "configured_tenant_enrollment.rs"]
mod configured_tenant_enrollment;
#[path = "administration_observability.rs"]
mod observability;
use command_jobs::CommandJobs;
#[path = "original_serving_runtime.rs"]
mod original_serving_runtime;
#[path = "administration_readiness.rs"]
mod readiness;
use configured_tenant_enrollment::ProvisionSelection;

/// Closure is synchronous; a shutdown waits for the original active command
/// before releasing any generation it could still reach.
#[derive(Default)]
struct ManagementGate {
    closed: AtomicBool,
    active: Arc<tokio::sync::Mutex<()>>,
}
impl ManagementGate {
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
    fn closed_error() -> kasumi_types::Error {
        kasumi_types::Error::new(
            kasumi_types::ErrorCode::Unavailable,
            "administrative command admission is closed",
        )
    }
    async fn enter(&self) -> kasumi_types::Result<tokio::sync::OwnedMutexGuard<()>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Self::closed_error());
        }
        let guard = self.active.clone().lock_owned().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(Self::closed_error());
        }
        Ok(guard)
    }
    async fn drain(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.active.lock().await
    }
}

pub struct Administration {
    pub(crate) config: RuntimeConfig,
    authority_trusts: BTreeMap<String, kasumi_serving::AuthorityTrust>,
    node: Arc<NodeStore>,
    registry: DatabaseRegistry,
    control: Arc<Database>,
    control_context: RequestContext,
    audit: Arc<SecurityAudit>,
    cluster: Option<Arc<ClusterNetwork>>,
    destinations: BTreeMap<String, Arc<dyn BackupDestination>>,
    // Original configured owners only; canonical recovery targets belong to their runner.
    generations: RwLock<BTreeMap<(String, String), ManagedTenant>>,
    custody_generations: RwLock<BTreeMap<(String, String), Arc<kasumi_engine::RetiredCustody>>>,
    gate: ManagementGate,
    // Closure and enrollment publication take this same synchronous boundary.
    enrollment_closed: std::sync::Mutex<bool>,
    // Retain observed failures if a caller cancels while another owner drains.
    shutdown_failure: tokio::sync::Mutex<DrainReport>,
    command_jobs: CommandJobs,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
    credential: crate::serving_runtime::CredentialSource,
    pub(crate) readiness: crate::readiness::Coverage,
}
/// Administrative selection borrows the already installed serving owner. It
/// never constructs providers, starts renewal, reopens storage, or owns shutdown.
#[derive(Clone)]
struct SelectedTenant {
    database: Arc<Database>,
    store: Arc<TenantStore>,
}
impl SelectedTenant {
    fn new(database: Arc<Database>) -> Self {
        let store = database
            .raft_group()
            .storage_domains()
            .application()
            .clone();
        Self { database, store }
    }
}

/// One immutable selection is shared by execution and final response release.
/// Reconciliation cannot redirect an admitted request to a fresh serving owner.
#[derive(Clone)]
pub struct ManagementInvocation {
    manager: Arc<Administration>,
    context: RequestContext,
    command: ManagementCommand,
    source: SelectedTenant,
    provisioning: Option<ProvisionSelection>,
    enrollment_deadline: Option<kasumi_clock::ElapsedDeadline>,
    prepared_selection: Arc<std::sync::Mutex<Option<SelectedTenant>>>,
}
impl ManagementInvocation {
    pub fn response_fence(&self) -> kasumi_types::Result<ManagementResponseFence<'_>> {
        Ok(ManagementResponseFence {
            invocation: self,
            source: self.source.database.response_fence(&self.context)?,
            control: self
                .manager
                .control
                .response_fence(&self.manager.control_context)?,
        })
    }
    pub async fn execute(&self) -> kasumi_types::Result<serde_json::Value> {
        if matches!(self.command, ManagementCommand::PrepareTenant { .. }) {
            return self
                .manager
                .clone()
                .prepare_configured_tenant(self.clone())
                .await;
        }
        self.manager.execute_selected(self).await
    }
}

pub struct ManagementResponseFence<'a> {
    invocation: &'a ManagementInvocation,
    source: kasumi_engine::ResponseFence<'a>,
    control: kasumi_engine::ResponseFence<'a>,
}
impl ManagementResponseFence<'_> {
    pub fn check_release(&self) -> kasumi_types::Result<()> {
        self.source.check()?;
        self.control.check()?;
        let selected = self.invocation;
        selected
            .source
            .database
            .engine()
            .authorize(&selected.context, None, Action::Admin)?;
        if let Some(ProvisionSelection::Resident(target)) = &selected.provisioning {
            target.store.check_access().map_err(|_| {
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Sealed,
                    "provisioned tenant key access expired",
                )
            })?;
        }
        if let Some(target) = selected
            .prepared_selection
            .lock()
            .map_err(|_| {
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Sealed,
                    "enrollment response selection unavailable",
                )
            })?
            .as_ref()
        {
            target.store.check_access().map_err(|_| {
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Sealed,
                    "prepared tenant access expired before response release",
                )
            })?;
        }
        selected.manager.control.engine().authorize(
            &selected.manager.control_context,
            None,
            Action::Admin,
        )?;
        Ok(())
    }
}

impl Administration {
    pub(crate) fn security_audit_workspace(
        &self,
    ) -> kasumi_types::Result<kasumi_engine::admission::Reservation> {
        // Decoded records, their encoded page and transport response coexist.
        // This explicit charge also covers installations with tiny document limits.
        self.admission.reserve(
            (4 * kasumi_types::MAX_SECURITY_AUDIT_PAGE_BYTES) as u64,
            None,
        )
    }

    pub(crate) fn security_audit(&self) -> &Arc<SecurityAudit> {
        &self.audit
    }

    /// Administrative routing is separate from DatabaseRegistry. Reserved control
    /// access still requires its own verified tenant context and current admin
    /// permission; service-security storage is never a database route.
    pub async fn authorized_database(
        &self,
        context: &RequestContext,
    ) -> kasumi_types::Result<Arc<Database>> {
        let result: Result<Arc<Database>> = async {
            if context.tenant == crate::runtime::SECURITY_TENANT {
                return Err(kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Forbidden,
                    "service security store is not an administrative database",
                )
                .into());
            }
            let tenant = self.current(context)?;
            self.authorized(&tenant, context, true).await?;
            Ok(tenant.database)
        }
        .await;
        result.map_err(|error| {
            error
                .downcast_ref::<kasumi_types::Error>()
                .cloned()
                .unwrap_or_else(|| {
                    kasumi_types::Error::new(
                        kasumi_types::ErrorCode::Unavailable,
                        "administrative database unavailable",
                    )
                })
        })
    }
    pub fn prepare(
        self: &Arc<Self>,
        context: RequestContext,
        command: ManagementCommand,
    ) -> kasumi_types::Result<ManagementInvocation> {
        let source = self.current(&context).map_err(|error| {
            error
                .downcast_ref::<kasumi_types::Error>()
                .cloned()
                .unwrap_or_else(|| {
                    kasumi_types::Error::new(
                        kasumi_types::ErrorCode::Unavailable,
                        "administrative database unavailable",
                    )
                })
        })?;
        source
            .database
            .engine()
            .authorize(&context, None, Action::Admin)?;
        let provisioning = provisioning_tenant(&command)
            .map(|name| match &command {
                ManagementCommand::ApproveTenant { .. }
                | ManagementCommand::PrepareTenant { .. } => self
                    .enrollment_proposal(name)
                    .map(ProvisionSelection::Proposal),
                _ => self
                    .provision_target(name)
                    .map(ProvisionSelection::Resident),
            })
            .transpose()
            .map_err(|_| {
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Forbidden,
                    "tenant provisioning denied",
                )
            })?;
        if provisioning.is_some() || matches!(command, ManagementCommand::ApprovePeerPool { .. }) {
            require_control(&context)?;
        }
        let enrollment_deadline = if matches!(command, ManagementCommand::PrepareTenant { .. }) {
            Some(
                configured_tenant_enrollment::capture_deadline().map_err(|error| {
                    kasumi_types::Error::new(
                        kasumi_types::ErrorCode::Unavailable,
                        error.to_string(),
                    )
                })?,
            )
        } else {
            None
        };
        Ok(ManagementInvocation {
            enrollment_deadline,
            prepared_selection: Arc::new(std::sync::Mutex::new(None)),
            manager: self.clone(),
            context,
            command,
            source,
            provisioning,
        })
    }

    #[cfg(test)]
    pub(crate) fn execute_for_test(
        self: &Arc<Self>,
        context: RequestContext,
        command: ManagementCommand,
    ) -> impl std::future::Future<Output = kasumi_types::Result<serde_json::Value>> + '_ {
        // Keep repeated administration futures out of large scenario test frames.
        Box::pin(async move {
            let invocation = self.prepare(context, command)?;
            let fence = invocation.response_fence()?;
            let result = invocation.execute().await?;
            fence.check_release()?;
            Ok(result)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: RuntimeConfig,
        authority_trusts: BTreeMap<String, kasumi_serving::AuthorityTrust>,
        node: Arc<NodeStore>,
        registry: DatabaseRegistry,
        control: Arc<Database>,
        audit: Arc<SecurityAudit>,
        cluster: Option<Arc<ClusterNetwork>>,
        tenants: Vec<ManagedTenant>,
        destinations: BTreeMap<String, Arc<dyn BackupDestination>>,
        admission: Arc<kasumi_engine::admission::NodeAdmission>,
        credential: crate::serving_runtime::CredentialSource,
    ) -> Result<Arc<Self>> {
        if !Arc::ptr_eq(&admission, audit.admission()) {
            return Err(kasumi_types::Error::new(
                kasumi_types::ErrorCode::Conflict,
                "administration admission differs from security audit",
            )
            .into());
        }
        let mut generations = BTreeMap::new();
        for tenant in tenants {
            registry.install_retirement_source(
                kasumi_engine::InstalledRetirementSource::Serving(tenant.database.clone()),
            )?;
            for (alias, destination) in &destinations {
                tenant
                    .database
                    .install_archive_destination(alias.clone(), destination.clone())?;
            }
            let state = tenant.database.engine().generation()?;
            let name = state.state.tenant.clone();
            let incarnation = state.state.incarnation.clone();
            generations.insert((name, incarnation), tenant);
        }
        let control_context = crate::runtime::configured_control_context(&config.control)?;
        registry.observe_membership(&control)?;
        let readiness = crate::readiness::Coverage::new(&admission)?;
        // Reserve the complete membership-child inventory on the installed
        // memory core before this manager can accept an administrative command.
        let command_jobs = CommandJobs::new(&admission)?;
        Ok(Arc::new(Self {
            config,
            authority_trusts,
            node,
            registry,
            control,
            control_context,
            audit,
            cluster,
            destinations,
            generations: RwLock::new(generations),
            custody_generations: RwLock::new(BTreeMap::new()),
            gate: ManagementGate::default(),
            enrollment_closed: std::sync::Mutex::new(false),
            shutdown_failure: tokio::sync::Mutex::new(DrainReport::default()),
            command_jobs,
            admission,
            credential,
            readiness,
        }))
    }
    fn current(&self, context: &RequestContext) -> Result<SelectedTenant> {
        context.authorization.check_live()?;
        if context.tenant == crate::runtime::CONTROL_TENANT {
            return Ok(SelectedTenant::new(self.control.clone()));
        }
        let database = self.registry.database(context)?;
        let generation = database.engine().generation()?;
        let topology = self.committed_topology()?;
        ensure!(
            topology
                .tenants
                .get(&context.tenant)
                .is_some_and(|route| route.incarnation == generation.state.incarnation),
            kasumi_types::Error::new(
                kasumi_types::ErrorCode::Unavailable,
                "registered generation differs from committed control route"
            )
        );
        drop(generation);
        Ok(SelectedTenant::new(database))
    }
    fn configured(&self, tenant: &str) -> Result<ManagedTenant> {
        let generations = self
            .generations
            .read()
            .map_err(|_| anyhow::anyhow!("generation registry unavailable"))?;
        let mut matching = generations.iter().filter(|((name, _), _)| name == tenant);
        let selected = matching
            .next()
            .map(|(_, value)| value.clone())
            .context("tenant has no installed original owner")?;
        ensure!(
            matching.next().is_none(),
            "tenant has multiple original owners"
        );
        Ok(selected)
    }
    #[cfg(test)]
    pub(crate) fn node_for_enrollment_test(&self) -> Arc<NodeStore> {
        self.node.clone()
    }
    #[cfg(test)]
    pub(crate) fn test_generation(&self, tenant: &str, incarnation: &str) -> Arc<Database> {
        self.generation(tenant, incarnation)
            .expect("fixture generation exists")
            .database
    }
    fn generation(&self, tenant: &str, incarnation: &str) -> Result<ManagedTenant> {
        self.generations
            .read()
            .map_err(|_| anyhow::anyhow!("generation registry unavailable"))?
            .get(&(tenant.into(), incarnation.into()))
            .cloned()
            .context("generation is not prepared on this replica")
    }
    fn destination(&self, name: &str) -> Result<&dyn BackupDestination> {
        kasumi_types::validate_name(name)?;
        self.destinations
            .get(name)
            .map(Arc::as_ref)
            .context("backup destination is not configured")
    }
    async fn event(
        &self,
        context: &RequestContext,
        kind: SecurityEventKind,
        outcome: SecurityOutcome,
    ) -> Result<()> {
        self.audit
            .record(SecurityEvent {
                kind,
                principal: Some(context.principal.clone()),
                tenant: Some(context.tenant.clone()),
                request_id: context.request_id.clone(),
                outcome,
            })
            .await
    }
    async fn authorized(
        &self,
        tenant: &SelectedTenant,
        context: &RequestContext,
        barrier: bool,
    ) -> Result<()> {
        tenant.store.check_access()?;
        tenant
            .database
            .engine()
            .authorize(context, None, Action::Admin)?;
        if barrier {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tenant.database.raft_group().linearizable_barrier(),
            )
            .await
            .map_err(|_| {
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Unavailable,
                    "administrative quorum deadline exceeded",
                )
            })??;
        }
        tenant.store.check_access()?;
        tenant
            .database
            .engine()
            .authorize(context, None, Action::Admin)?;
        Ok(())
    }
    async fn execute_selected(
        &self,
        invocation: &ManagementInvocation,
    ) -> kasumi_types::Result<serde_json::Value> {
        let context = &invocation.context;
        let command = &invocation.command;
        let source = &invocation.source;
        let _guard = self.gate.enter().await?;
        let mut admitted = false;
        let mutation = !matches!(command, ManagementCommand::Status { .. });
        let mut result: Result<serde_json::Value> = async {
            self.authorized(source, context, false).await?;
            admitted = true;
            let result = Box::pin(self.execute_inner(
                context,
                command.clone(),
                source,
                invocation.provisioning.as_ref(),
            ))
            .await?;
            self.authorized(source, context, false).await?;
            Ok(result)
        }
        .await;
        if let Err(error) = &mut result
            && let Some(error) = error.downcast_mut::<kasumi_types::Error>()
            && !error.denial_audit_attempted()
            && matches!(
                error.code,
                kasumi_types::ErrorCode::Forbidden
                    | kasumi_types::ErrorCode::Unauthorized
                    | kasumi_types::ErrorCode::Sealed
            )
        {
            let kind = if error.code == kasumi_types::ErrorCode::Sealed {
                SecurityEventKind::TenantSealed
            } else {
                SecurityEventKind::AccessDenied
            };
            // A failed denial audit can never turn the denial into access.
            let _ = self.event(context, kind, SecurityOutcome::Denied).await;
            error.mark_denial_audit_attempted();
        }
        let result = result.map_err(|error| {
            error
                .downcast_ref::<kasumi_types::Error>()
                .cloned()
                .unwrap_or_else(|| {
                    kasumi_types::Error::new(
                        kasumi_types::ErrorCode::Unavailable,
                        "administrative operation failed; inspect status before retrying",
                    )
                })
        });
        if admitted && mutation {
            crate::api::mutation_release(result)
        } else {
            result
        }
    }
    async fn execute_inner(
        &self,
        context: &RequestContext,
        command: ManagementCommand,
        source: &SelectedTenant,
        provisioning: Option<&ProvisionSelection>,
    ) -> Result<serde_json::Value> {
        self.authorized(source, context, false).await?;
        match command {
            ManagementCommand::ApprovePeerPool {
                expected_topology_version,
            } => {
                require_control(context)?;
                self.approve_peer_pool(context, expected_topology_version)
                    .await
            }
            ManagementCommand::ApproveTenant { tenant } => {
                require_control(context)?;
                self.approve_tenant(
                    context,
                    &tenant,
                    provisioning
                        .context("selected provisioning owner absent")?
                        .proposal()?,
                )
                .await
            }
            ManagementCommand::PrepareTenant { .. } => {
                anyhow::bail!("tenant preparation requires its retained enrollment owner")
            }
            ManagementCommand::InitializeTenant { tenant } => {
                require_control(context)?;
                self.initialize_tenant(
                    context,
                    &tenant,
                    provisioning
                        .context("selected provisioning owner absent")?
                        .resident()?,
                )
                .await
            }
            ManagementCommand::ActivateTenant {
                tenant,
                expected_topology_version,
            } => {
                require_control(context)?;
                self.activate_tenant(
                    context,
                    &tenant,
                    provisioning
                        .context("selected provisioning owner absent")?
                        .resident()?,
                    expected_topology_version,
                )
                .await
            }
            ManagementCommand::Status {} => {
                self.authorized(source, context, false).await?;
                self.event(
                    context,
                    SecurityEventKind::Administration,
                    SecurityOutcome::Succeeded,
                )
                .await?;
                let state = source.database.engine().generation()?;
                Ok(
                    serde_json::json!({"incarnation":state.state.incarnation,"revision":state.state.revision,"suspended":state.state.suspended,"pending_restore":state.state.pending_restore,
                    "observation":"local_committed_state","retired":state.state.retired,"node_id":source.database.raft_group().raft().metrics().borrow().id,
                    "leader":source.database.raft_group().raft().metrics().borrow().current_leader,
                    "control_leader":self.control.raft_group().raft().metrics().borrow().current_leader,
                    "control_topology_version": if context.tenant==crate::runtime::CONTROL_TENANT {
                        state.state.collections.get("topology").and_then(|c|c.documents.get("current")).map(|d|d.version)
                    } else { None },
                    "routing":"select the operator-configured endpoint for the reported node ID"}),
                )
            }
            ManagementCommand::Backup {
                destination,
                session_id,
            } => {
                // The engine owns the bounded stream, verification and worker
                // reservations. This layer retains only its response fences
                // and serializes the returned backup UUID, not backup objects.
                let destination = self.destination(&destination)?;
                self.event(context, SecurityEventKind::Backup, SecurityOutcome::Started)
                    .await?;
                let result = source
                    .database
                    .backup(context.clone(), destination, session_id)
                    .await;
                self.event(
                    context,
                    SecurityEventKind::Backup,
                    if result.is_ok() {
                        SecurityOutcome::Succeeded
                    } else {
                        SecurityOutcome::Unknown
                    },
                )
                .await?;
                Ok(serde_json::json!({"backup_id":result?}))
            }
            ManagementCommand::RotateDataKey | ManagementCommand::RewrapKeys => {
                self.authorized(source, context, true).await?;
                let action = if matches!(command, ManagementCommand::RotateDataKey) {
                    "key_rotation"
                } else {
                    "key_rewrap"
                };
                source
                    .database
                    .maintenance_audit(
                        context.clone(),
                        action,
                        "started",
                        source.database.engine().generation()?.state.revision,
                    )
                    .await?;
                self.event(
                    context,
                    SecurityEventKind::KeyAdministration,
                    SecurityOutcome::Started,
                )
                .await?;
                let result = if matches!(command, ManagementCommand::RotateDataKey) {
                    source.store.rotate_data_key().await
                } else {
                    source.store.rewrap_keys().await
                };
                self.event(
                    context,
                    SecurityEventKind::KeyAdministration,
                    if result.is_ok() {
                        SecurityOutcome::Succeeded
                    } else {
                        SecurityOutcome::Unknown
                    },
                )
                .await?;
                source
                    .database
                    .maintenance_audit(
                        context.clone(),
                        action,
                        if result.is_ok() {
                            "completed"
                        } else {
                            "unknown"
                        },
                        source.database.engine().generation()?.state.revision,
                    )
                    .await?;
                result?;
                self.authorized(source, context, true).await?;
                Ok(serde_json::json!({"completed":true,"scope":"this_replica"}))
            }
            ManagementCommand::AddLearner { node_id } => {
                self.authorized(source, context, true).await?;
                let topology = self.committed_topology()?;
                let node = topology
                    .nodes
                    .get(&node_id)
                    .context("learner absent from approved control metadata")?;
                ensure!(
                    self.config
                        .replication
                        .as_ref()
                        .is_some_and(|r| r.peers.iter().any(|p| p.node_id == node_id)),
                    "learner requires configured pinned transport"
                );
                self.event(
                    context,
                    SecurityEventKind::Membership,
                    SecurityOutcome::Started,
                )
                .await?;
                source
                    .database
                    .maintenance_audit(
                        context.clone(),
                        "membership",
                        "started",
                        source.database.engine().generation()?.state.revision,
                    )
                    .await?;
                let selected = source.clone();
                let original_context = context.clone();
                let learner = kasumi_raft::BasicNode::new(node.endpoint.clone());
                self.command_jobs
                    .execute(
                        tokio::time::Instant::now() + std::time::Duration::from_secs(30),
                        async move {
                            // The child may wait behind a prior accepted command
                            // after this caller has disappeared. Recheck original
                            // authority immediately before Raft dispatch.
                            selected.store.check_access()?;
                            selected.database.engine().authorize(
                                &original_context,
                                None,
                                Action::Admin,
                            )?;
                            selected
                                .database
                                .raft_group()
                                .add_learner(node_id, learner)
                                .await
                        },
                        "learner catch-up deadline exceeded; inspect membership",
                    )
                    .await?;
                self.event(
                    context,
                    SecurityEventKind::Membership,
                    SecurityOutcome::Succeeded,
                )
                .await?;
                Ok(serde_json::json!({"caught_up":node_id}))
            }
            ManagementCommand::ChangeMembership { voters } => {
                self.authorized(source, context, true).await?;
                let mut topology = self.committed_topology()?;
                validate_voters(&topology, &voters)?;
                if let Some(route) = topology.tenants.get_mut(&context.tenant) {
                    route.voters = voters.clone();
                }
                topology.validate()?;
                let metrics = source
                    .database
                    .raft_group()
                    .raft()
                    .metrics()
                    .borrow()
                    .clone();
                ensure!(
                    voters.iter().all(|id| metrics
                        .membership_config
                        .nodes()
                        .any(|(node, _)| node == id)),
                    "all voters must be explicitly added and caught up as learners first"
                );
                self.event(
                    context,
                    SecurityEventKind::Membership,
                    SecurityOutcome::Started,
                )
                .await?;
                source
                    .database
                    .maintenance_audit(
                        context.clone(),
                        "membership",
                        "started",
                        source.database.engine().generation()?.state.revision,
                    )
                    .await?;
                let selected = source.clone();
                let original_context = context.clone();
                self.command_jobs
                    .execute(
                        tokio::time::Instant::now() + std::time::Duration::from_secs(30),
                        async move {
                            selected.store.check_access()?;
                            selected.database.engine().authorize(
                                &original_context,
                                None,
                                Action::Admin,
                            )?;
                            selected
                                .database
                                .raft_group()
                                .change_membership(voters)
                                .await
                        },
                        "membership deadline exceeded; inspect committed membership",
                    )
                    .await?;
                self.event(
                    context,
                    SecurityEventKind::Membership,
                    SecurityOutcome::Succeeded,
                )
                .await?;
                Ok(serde_json::json!({"changed":true,"publish_control_route_required":true}))
            }
            ManagementCommand::PublishMembership { voters } => {
                let metrics = source
                    .database
                    .raft_group()
                    .raft()
                    .metrics()
                    .borrow()
                    .clone();
                ensure!(
                    metrics
                        .membership_config
                        .membership()
                        .get_joint_config()
                        .len()
                        == 1
                        && metrics
                            .membership_config
                            .membership()
                            .voter_ids()
                            .collect::<BTreeSet<_>>()
                            == voters,
                    "local committed membership must match final voters"
                );
                ensure!(
                    metrics
                        .membership_config
                        .log_id()
                        .as_ref()
                        .is_none_or(|log| metrics
                            .last_applied
                            .is_some_and(|applied| applied.index >= log.index)),
                    "membership has not applied locally"
                );
                let plane = ControlPlane::new(self.control.clone())?;
                let current = plane
                    .topology(&self.control_context)
                    .await?
                    .context("route missing")?;
                let mut topology = current.topology;
                validate_voters(&topology, &voters)?;
                if let Some(route) = topology.tenants.get_mut(&context.tenant) {
                    route.voters = voters;
                }
                topology.validate()?;
                self.event(
                    context,
                    SecurityEventKind::Membership,
                    SecurityOutcome::Started,
                )
                .await?;
                plane
                    .replace_topology(
                        self.control_context.clone(),
                        topology,
                        Precondition::Version(current.version),
                        format!("membership-{}", context.request_id),
                    )
                    .await?;
                self.event(
                    context,
                    SecurityEventKind::Membership,
                    SecurityOutcome::Succeeded,
                )
                .await?;
                Ok(serde_json::json!({"published":true}))
            }
        }
    }
    fn provision_target(&self, tenant: &str) -> Result<ManagedTenant> {
        kasumi_types::validate_name(tenant)?;
        ensure!(
            !tenant.starts_with("__kasumi_"),
            "reserved tenant cannot be provisioned"
        );
        ensure!(
            self.config.tenants.iter().any(|t| t.tenant == tenant),
            "tenant is not operator configured"
        );
        self.configured(tenant)
    }
    fn configured_nodes(&self) -> Result<BTreeMap<u64, kasumi_engine::control::ControlNode>> {
        if let Some(replication) = &self.config.replication {
            replication.control_nodes()
        } else {
            Ok(self.committed_topology()?.nodes)
        }
    }
    fn provision_route(
        &self,
        target: &ManagedTenant,
    ) -> Result<kasumi_engine::control::TenantRoute> {
        use kasumi_engine::control::{DeploymentMode, TenantRoute};
        Ok(TenantRoute {
            incarnation: target
                .database
                .engine()
                .generation()?
                .state
                .incarnation
                .clone(),
            mode: if target.bootstrap.is_some() {
                DeploymentMode::Replicated
            } else {
                DeploymentMode::Local
            },
            voters: target
                .bootstrap
                .as_ref()
                .map(|b| b.voters.keys().copied().collect())
                .unwrap_or_else(|| BTreeSet::from([1])),
        })
    }
    fn provision_hash(&self, tenant: &str, target: &ManagedTenant) -> Result<String> {
        let proposal = self.enrollment_proposal(tenant)?;
        self.require_resident_proposal(target, &proposal)?;
        proposal.digest()
    }
    fn provision_approval(&self, tenant: &str) -> Result<String> {
        self.approved_enrollment(tenant)?.digest()
    }
    async fn approve_peer_pool(
        &self,
        context: &RequestContext,
        expected: u64,
    ) -> Result<serde_json::Value> {
        self.authorized(&self.current(&self.control_context)?, context, true)
            .await?;
        let plane = ControlPlane::new(self.control.clone())?;
        let current = plane
            .topology(context)
            .await?
            .context("control topology unavailable")?;
        ensure!(
            current.version == expected,
            kasumi_types::Error::new(
                kasumi_types::ErrorCode::Conflict,
                "control topology version changed"
            )
        );
        let nodes = self.configured_nodes()?;
        ensure!(
            current
                .topology
                .nodes
                .iter()
                .all(|(id, node)| nodes.get(id) == Some(node)),
            "existing peer identities cannot be changed or removed"
        );
        let mut topology = current.topology;
        topology.nodes = nodes;
        topology.validate()?;
        self.event(
            context,
            SecurityEventKind::Administration,
            SecurityOutcome::Started,
        )
        .await?;
        plane
            .replace_topology(
                context.clone(),
                topology,
                Precondition::Version(expected),
                format!("approve-peer-pool-{expected}"),
            )
            .await?;
        self.event(
            context,
            SecurityEventKind::Administration,
            SecurityOutcome::Succeeded,
        )
        .await?;
        Ok(serde_json::json!({"approved":true}))
    }
    async fn verify_provision_peers(
        &self,
        tenant: &str,
        target: &ManagedTenant,
        require_initialized: bool,
    ) -> Result<()> {
        use crate::cluster::EnrollmentReadinessProvider;
        let hash = self.provision_hash(tenant, target)?;
        ensure!(
            self.provision_approval(tenant)? == hash,
            "approved bootstrap differs"
        );
        let route = self.provision_route(target)?;
        let group = format!("{tenant}/{}", route.incarnation);
        let fingerprint = target
            .bootstrap
            .as_ref()
            .map(|_| crate::runtime::persisted_bootstrap_fingerprint(&target.store))
            .transpose()?;
        for peer in &route.voters {
            let ready = if let Some(network) = &self.cluster {
                ensure!(
                    Some(network.bootstrap_fingerprint(*peer, &group).await?) == fingerprint,
                    "replica persisted bootstrap differs"
                );
                network.enrollment_readiness(*peer, &group).await?
            } else {
                self.readiness(&group)?
            };
            ensure!(
                ready.bootstrap_sha256 == hash,
                "replica bootstrap or identity/pins differ"
            );
            ensure!(
                !require_initialized || ready.initialized,
                "replica has not applied initialized membership"
            );
        }
        Ok(())
    }
    async fn initialize_tenant(
        &self,
        context: &RequestContext,
        tenant: &str,
        target: &ManagedTenant,
    ) -> Result<serde_json::Value> {
        self.verify_provision_peers(tenant, target, false).await?;
        self.event(
            context,
            SecurityEventKind::Administration,
            SecurityOutcome::Started,
        )
        .await?;
        if let Some(bootstrap) = &target.bootstrap {
            ensure!(
                self.config.replication.as_ref().map(|r| r.node_id)
                    == bootstrap.voters.keys().next().copied(),
                "initialize on the lowest configured voter"
            );
            kasumi_engine::initialize_replicated(&target.database, bootstrap).await?;
        }
        self.event(
            context,
            SecurityEventKind::Administration,
            SecurityOutcome::Succeeded,
        )
        .await?;
        Ok(serde_json::json!({"initialized":true,"tenant":tenant}))
    }
    async fn activate_tenant(
        &self,
        context: &RequestContext,
        tenant: &str,
        target: &ManagedTenant,
        expected: u64,
    ) -> Result<serde_json::Value> {
        self.authorized(&self.current(&self.control_context)?, context, true)
            .await?;
        self.verify_provision_peers(tenant, target, true).await?;
        let plane = ControlPlane::new(self.control.clone())?;
        let current = plane
            .topology(context)
            .await?
            .context("control topology missing")?;
        let route = self.provision_route(target)?;
        if let Some(existing) = current.topology.tenants.get(tenant) {
            ensure!(
                existing == &route,
                "tenant already routes another generation"
            );
        } else {
            ensure!(
                current.version == expected,
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Conflict,
                    "control topology version changed"
                )
            );
            let mut topology = current.topology;
            topology.tenants.insert(tenant.into(), route.clone());
            self.event(
                context,
                SecurityEventKind::Administration,
                SecurityOutcome::Started,
            )
            .await?;
            plane
                .replace_topology(
                    context.clone(),
                    topology,
                    Precondition::Version(expected),
                    format!(
                        "activate-tenant-{}",
                        hex_digest(format!("{tenant}/{}", route.incarnation).as_bytes())
                    ),
                )
                .await?;
        }
        target.store.check_access()?;
        self.event(
            context,
            SecurityEventKind::Administration,
            SecurityOutcome::Succeeded,
        )
        .await?;
        // Reconciliation publishes after this durable route CAS. It runs on all
        // replicas and never requires collocated control/tenant leaders.
        Ok(serde_json::json!({"activated":true,"tenant":tenant,"incarnation":route.incarnation}))
    }
    pub(crate) fn committed_topology(&self) -> Result<ControlTopology> {
        self.control.raft_group().check_access()?;
        let state = self.control.engine().generation()?;
        let document = state
            .state
            .collections
            .get("topology")
            .and_then(|c| c.documents.get("current"))
            .context("control topology unavailable")?;
        let topology: ControlTopology = serde_json::from_value(document.body.clone())?;
        topology.validate()?;
        Ok(topology)
    }
    async fn close_retired_generations(&self) -> Result<()> {
        let generations = self
            .generations
            .read()
            .map_err(|_| anyhow::anyhow!("source registry unavailable"))?
            .iter()
            .map(|(identity, source)| (identity.clone(), source.clone()))
            .collect::<Vec<_>>();
        for ((tenant, incarnation), source) in generations {
            if tenant.starts_with("__kasumi_") {
                continue;
            }
            let context = RequestContext {
                tenant: tenant.clone(),
                ..self.control_context.clone()
            };
            if !matches!(
                self.registry.retirement_source(&context, &incarnation),
                Ok(kasumi_engine::InstalledRetirementSource::Serving(_))
            ) {
                continue;
            }
            let control = kasumi_raft::ControlLog::installed(
                source
                    .database
                    .raft_group()
                    .storage_domains()
                    .custody()
                    .clone(),
            )?;
            let Some(control) = control else {
                continue;
            };
            if !control.is_retired()? {
                continue;
            }
            self.registry
                .detach_target_generation(&tenant, &incarnation, &source.database)?;
            // Publish an explicit closed transition before sealing/draining the
            // old handle. Concurrent native callers can retry unavailable
            // custody; none observes a stale Serving route to a sealed engine.
            self.registry.install_retirement_source(
                kasumi_engine::InstalledRetirementSource::RecoveringControl {
                    tenant: tenant.clone(),
                    source_incarnation: incarnation.clone(),
                },
            )?;
            if let Some(lease) = &source.lease {
                lease.shutdown().await?;
            }
            let store = source.database.detach_retired_custody().await?;
            let group = format!("{tenant}/{incarnation}");
            if let Some(network) = &self.cluster {
                network.unregister_group(&group)?;
            }
            let route = match crate::runtime::open_retired_source(
                &self.config,
                store,
                self.cluster.as_ref(),
                self.audit.clone(),
                self.admission.clone(),
            )
            .await
            {
                Ok(custody) => {
                    self.custody_generations
                        .write()
                        .map_err(|_| anyhow::anyhow!("custody routing unavailable"))?
                        .insert((tenant.clone(), incarnation.clone()), custody.clone());
                    kasumi_engine::InstalledRetirementSource::RetiredCustody(custody)
                }
                Err(_) => kasumi_engine::InstalledRetirementSource::RecoveringControl {
                    tenant,
                    source_incarnation: incarnation,
                },
            };
            self.registry.install_retirement_source(route)?;
        }
        Ok(())
    }

    pub(crate) async fn reconcile(&self) -> Result<()> {
        let _guard = self.gate.enter().await?;
        if self.close_retired_generations().await.is_err() {
            tracing::warn!("retired generation reconciliation remains unavailable");
        }
        let topology = self.committed_topology()?;
        for (tenant, route) in topology.tenants {
            let original = self
                .config
                .tenants
                .iter()
                .find(|entry| entry.tenant == tenant)
                .is_some_and(|entry| {
                    entry
                        .incarnation
                        .as_deref()
                        .is_none_or(|id| id == route.incarnation)
                });
            if original
                && self
                    .recover_original(&tenant, &route.incarnation)
                    .await
                    .is_err()
            {
                tracing::warn!(
                    tenant,
                    "original tenant remains closed pending fresh admission"
                );
                continue;
            }
            // Canonical targets belong exclusively to TargetRecoveryRuntime.
            // Observe their registered handle; never infer a path or reopen one.
            let Some(source) = self
                .generations
                .read()
                .map_err(|_| anyhow::anyhow!("original generation registry unavailable"))?
                .get(&(tenant.clone(), route.incarnation.clone()))
                .cloned()
            else {
                continue;
            };
            if source.database.check_serving().is_err() {
                continue;
            }
            let generation = source.database.engine().generation()?;
            if generation.state.retired || generation.state.pending_restore.is_some() {
                continue;
            }
            drop(generation);
            if self
                .registry
                .installed_generation(&tenant, &route.incarnation)?
                .is_none()
            {
                self.registry.insert(source.database.clone())?;
            }
        }
        Ok(())
    }
    pub(crate) async fn shutdown(&self) -> DrainResult {
        // Close synchronously with command publication before any shutdown
        // await. Join exact membership children before closing their Raft group.
        self.gate.close();
        self.command_jobs.close();
        // Close enrollment before the first await as well. A cancelled shutdown
        // leaves both admission fences closed for its retry.
        let enrollment_poisoned = match self.enrollment_closed.lock() {
            Ok(mut closed) => {
                *closed = true;
                false
            }
            Err(poisoned) => {
                *poisoned.into_inner() = true;
                true
            }
        };
        let mut report = self.shutdown_failure.lock().await;
        let mut retained = None;
        if enrollment_poisoned {
            report.record(
                "enrollment admission",
                0,
                anyhow::anyhow!("enrollment publication lock poisoned"),
            );
        }
        if let Err(error) =
            crate::startup_owner::drain(crate::startup_owner::Kind::TenantEnrollment).await
        {
            // The registry returns only after its retained task inventory joins.
            report.record("tenant enrollment", 0, error);
        }
        if let Err(failure) = self.command_jobs.drain().await {
            report.merge(&failure);
            if failure.completion() == DrainCompletion::Retained {
                return report.outcome(Some(failure));
            }
        }
        // No management execution or reconciliation can still be using an
        // original generation when its Raft/database owner starts closing.
        let _management = self.gate.drain().await;
        let generations = self
            .generations
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for tenant in &generations {
            if let Some(lease) = &tenant.lease {
                lease.close();
            }
        }
        for (index, tenant) in generations.into_iter().enumerate() {
            if let Some(network) = &self.cluster {
                let incarnation = tenant
                    .bootstrap
                    .as_ref()
                    .map(|bootstrap| bootstrap.incarnation.clone())
                    .or_else(|| {
                        tenant
                            .database
                            .engine()
                            .generation()
                            .ok()
                            .map(|state| state.state.incarnation.clone())
                    });
                if let Some(incarnation) = incarnation
                    && let Err(error) = network.unregister_group(&format!(
                        "{}/{}",
                        tenant.store.tenant(),
                        incarnation
                    ))
                {
                    retained = Some(DrainFailure::retained(report.record(
                        "generation route",
                        index,
                        error,
                    )));
                }
            }
            if let Some(lease) = &tenant.lease
                && let Err(error) = lease.shutdown().await
            {
                report.merge(&error);
                if error.completion() == DrainCompletion::Retained {
                    retained = Some(error);
                }
            }
            if let Err(failure) = tenant.database.shutdown().await {
                report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
            }
        }
        let custody = self
            .custody_generations
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for source in custody {
            if let Err(failure) = source.shutdown().await {
                report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
            }
        }
        if let Err(error) = self.node.drain_initializers().await {
            report.record("administration node initializers", 0, error);
        }
        report.outcome(retained)
    }
}
impl crate::cluster::EnrollmentReadinessProvider for Administration {
    fn readiness(&self, group: &str) -> Result<crate::cluster::EnrollmentReadiness> {
        let (tenant, incarnation) = group.rsplit_once('/').context("invalid generation group")?;
        let target = self.generation(tenant, incarnation)?;
        target.store.check_access()?;
        let state = target.database.engine().generation()?;
        let expected = self.provision_hash(tenant, &target)?;
        let approval = self.provision_approval(tenant)?;
        ensure!(
            approval == expected,
            "provisioning approval differs from configured bootstrap"
        );
        let prepared = target
            .store
            .get("runtime.provisioning", b"prepared")?
            .context("tenant is not prepared")?;
        ensure!(
            prepared == expected.as_bytes(),
            "prepared tenant bootstrap differs"
        );
        ensure!(
            state.state.pending_restore.is_none()
                && state.state.restored_from.is_none()
                && !state.state.retired,
            "enrollment readiness requires the original fresh tenant"
        );
        let bootstrap_sha256 = expected;
        Ok(crate::cluster::EnrollmentReadiness {
            bootstrap_sha256,
            initialized: initialized(&target),
            revision: state.state.revision,
        })
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn require_control(context: &RequestContext) -> kasumi_types::Result<()> {
    if context.tenant != crate::runtime::CONTROL_TENANT {
        return Err(kasumi_types::Error::new(
            kasumi_types::ErrorCode::Forbidden,
            "control-group identity required",
        ));
    }
    Ok(())
}
fn provisioning_tenant(command: &ManagementCommand) -> Option<&str> {
    match command {
        ManagementCommand::ApproveTenant { tenant }
        | ManagementCommand::PrepareTenant { tenant }
        | ManagementCommand::InitializeTenant { tenant }
        | ManagementCommand::ActivateTenant { tenant, .. } => Some(tenant),
        _ => None,
    }
}
fn initialized(target: &ManagedTenant) -> bool {
    let metrics = target
        .database
        .raft_group()
        .raft()
        .metrics()
        .borrow()
        .clone();
    let membership = &metrics.membership_config;
    let configs = membership.membership().get_joint_config();
    let expected = target
        .bootstrap
        .as_ref()
        .map(|b| b.voters.keys().copied().collect::<BTreeSet<_>>())
        .unwrap_or_else(|| BTreeSet::from([1]));
    configs.len() == 1
        && configs[0] == expected
        && membership.log_id().is_some()
        && metrics.last_applied >= *membership.log_id()
}

fn validate_voters(topology: &ControlTopology, voters: &BTreeSet<u64>) -> Result<()> {
    ensure!(
        voters.len() == 3,
        "replicated membership requires exactly three voters"
    );
    let domains = voters
        .iter()
        .map(|id| {
            topology
                .nodes
                .get(id)
                .map(|n| n.failure_domain.clone())
                .context("voter absent from approved topology")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        domains.len() == 3,
        "voters require three independent failure domains"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_gate_waits_for_active_management_and_rejects_queued_work() {
        use std::{future::Future, task::Poll, time::Duration};
        let gate = ManagementGate::default();
        let active = gate.enter().await.unwrap();
        let mut queued = Box::pin(gate.enter());
        std::future::poll_fn(|cx| {
            assert!(queued.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        gate.close();
        let mut shutdown = Box::pin(gate.drain());
        std::future::poll_fn(|cx| {
            assert!(shutdown.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(active);
        let queued = tokio::time::timeout(Duration::from_secs(5), queued)
            .await
            .unwrap();
        assert!(matches!(
            queued,
            Err(error) if error.code == kasumi_types::ErrorCode::Unavailable
        ));
        let shutdown = tokio::time::timeout(Duration::from_secs(5), shutdown)
            .await
            .unwrap();
        // A new caller rejects immediately even while shutdown owns the gate.
        let late = tokio::time::timeout(Duration::from_secs(5), gate.enter())
            .await
            .unwrap();
        assert!(matches!(
            late,
            Err(error) if error.code == kasumi_types::ErrorCode::Unavailable
        ));
        drop(shutdown);
    }

    #[test]
    fn management_entry_future_bounds_stack_residency() {
        fn future_size<A, F>(_: impl FnOnce(A) -> F) -> usize {
            std::mem::size_of::<F>()
        }
        let bytes = future_size(
            |(manager, context, command): (
                &'static Arc<Administration>,
                RequestContext,
                ManagementCommand,
            )| manager.execute_for_test(context, command),
        );
        let retirement_bytes = future_size(
            |(database, context, request): (
                &'static kasumi_engine::Database,
                RequestContext,
                kasumi_types::RetireSourceRequest,
            )| database.retire_source(context, request),
        );
        eprintln!("management future {bytes} bytes; retirement future {retirement_bytes} bytes");
        assert!(bytes <= 8 * 1024, "management future retains {bytes} bytes");
        assert!(
            retirement_bytes <= 8 * 1024,
            "retirement future retains {retirement_bytes} bytes"
        );
    }
    #[test]
    fn removed_management_recovery_and_status_selection_have_no_decoder() {
        for operation in [
            "prepare_restore",
            "initialize_restore",
            "complete_restore",
            "retire_source",
            "activate_restore",
        ] {
            let error = serde_json::from_value::<ManagementCommand>(serde_json::json!({
                "operation": operation,
                "destination": "named",
                "backup_id": Uuid::new_v4(),
                "incarnation": Uuid::new_v4(),
                "request": {}
            }))
            .unwrap_err();
            assert!(
                error.to_string().contains("unknown variant"),
                "{operation}: {error}"
            );
        }
        let error = serde_json::from_value::<ManagementCommand>(serde_json::json!({
            "operation": "status", "incarnation": Uuid::new_v4()
        }))
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
        assert!(matches!(
            serde_json::from_value::<ManagementCommand>(serde_json::json!({"operation": "status"}))
                .unwrap(),
            ManagementCommand::Status {}
        ));
    }

    #[test]
    fn closed_commands_reject_path_and_tenant_overrides() {
        assert!(
            serde_json::from_value::<ManagementCommand>(
                serde_json::json!({"operation":"backup","destination":"named","session_id":Uuid::new_v4(),"tenant":"other"})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<ManagementCommand>(
                serde_json::json!({"operation":"prepare_restore","path":"/tmp/target.redb"})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<ManagementCommand>(
                serde_json::json!({"operation":"shell","command":"anything"})
            )
            .is_err()
        );
        let destination = DestinationConfig::Filesystem {
            directory: "relative".into(),
            max_bytes: 100,
        };
        assert!(destination.validate().is_err());
        let destination = DestinationConfig::Filesystem {
            directory: "/tmp/backups".into(),
            max_bytes: 0,
        };
        assert!(destination.validate().is_err());
    }
}
