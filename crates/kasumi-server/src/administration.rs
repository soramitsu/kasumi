//! Audited maintenance and immutable replacement generations. Destination names
//! and all physical paths come from operator configuration, never data requests.
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
    BackupDestination, FilesystemBackupDestination, KeyProvider, NodeStore, S3BackupConfig,
    S3BackupDestination, TenantStore, WriteOp,
};
use kasumi_types::{Action, Operation, Precondition, RequestContext};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};
use uuid::Uuid;
use zeroize::Zeroizing;

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
        access_key_env: String,
        secret_key_env: String,
        session_token_env: Option<String>,
        ca_certificate: Option<PathBuf>,
        max_bytes: usize,
    },
}
impl DestinationConfig {
    fn max_bytes(&self) -> usize {
        match self {
            Self::Filesystem { max_bytes, .. } | Self::S3 { max_bytes, .. } => *max_bytes,
        }
    }
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
                access_key_env,
                secret_key_env,
                session_token_env,
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
                for name in [
                    Some(access_key_env),
                    Some(secret_key_env),
                    session_token_env.as_ref(),
                ]
                .into_iter()
                .flatten()
                {
                    crate::runtime::environment_name(name)?;
                }
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
        credential: &impl Fn(&str) -> Result<Zeroizing<String>>,
    ) -> Result<Arc<dyn BackupDestination>> {
        self.validate()?;
        Ok(match self {
            Self::Filesystem {
                directory,
                max_bytes,
            } => Arc::new(FilesystemBackupDestination::new(directory, *max_bytes)?),
            Self::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                access_key_env,
                secret_key_env,
                session_token_env,
                ca_certificate,
                max_bytes,
            } => Arc::new(S3BackupDestination::new(S3BackupConfig {
                endpoint: endpoint.clone(),
                region: region.clone(),
                bucket: bucket.clone(),
                prefix: prefix.clone(),
                access_key_id: credential(access_key_env)?.to_string(),
                secret_access_key: credential(secret_key_env)?.to_string(),
                session_token: session_token_env
                    .as_ref()
                    .map(|key| credential(key).map(|value| value.to_string()))
                    .transpose()?,
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
    },
    RotateDataKey,
    RewrapKeys,
    Status {
        #[serde(default)]
        incarnation: Option<Uuid>,
    },
    PrepareRestore {
        destination: String,
        backup_id: Uuid,
        incarnation: Uuid,
    },
    InitializeRestore {
        incarnation: Uuid,
    },
    CompleteRestore {
        incarnation: Uuid,
    },
    RetireSource {
        incarnation: Uuid,
    },
    ActivateRestore {
        incarnation: Uuid,
        expected_source: String,
    },
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
    pub provider: Arc<dyn KeyProvider>,
    pub bootstrap: Option<ReplicatedBootstrap>,
    pub descriptor: Option<GenerationDescriptor>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GenerationDescriptor {
    pub format: u32,
    pub tenant: String,
    pub incarnation: Uuid,
    pub backup_id: Uuid,
    pub bootstrap: Option<ReplicatedBootstrap>,
    pub bootstrap_sha256: String,
}

pub struct Administration {
    pub(crate) config: RuntimeConfig,
    registry: DatabaseRegistry,
    control: Arc<Database>,
    control_context: RequestContext,
    audit: Arc<SecurityAudit>,
    cluster: Option<Arc<ClusterNetwork>>,
    destinations: BTreeMap<String, Arc<dyn BackupDestination>>,
    // Includes active and prepared generations, keyed by immutable incarnation.
    generations: RwLock<BTreeMap<(String, String), ManagedTenant>>,
    active: RwLock<BTreeMap<String, String>>,
    enabled: RwLock<BTreeSet<String>>,
    gate: tokio::sync::Mutex<()>,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
}
/// Holds the exact source/target handles across adapter serialization. Activation
/// deliberately retires the source, so its acknowledgement is fenced by the new
/// target and control database instead.
pub struct ManagementResponseFence {
    manager: Arc<Administration>,
    context: RequestContext,
    source: Option<ManagedTenant>,
    target: Option<Uuid>,
    provisioning: Option<ManagedTenant>,
}
impl ManagementResponseFence {
    pub fn check_release(&self) -> kasumi_types::Result<()> {
        let check = |tenant: &ManagedTenant| -> kasumi_types::Result<()> {
            tenant.store.check_access().map_err(|_| {
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Sealed,
                    "tenant key access expired",
                )
            })?;
            tenant
                .database
                .engine()
                .authorize(&self.context, None, Action::Admin)
        };
        if let Some(source) = &self.source {
            check(source)?;
        }
        if let Some(incarnation) = self.target {
            let target = self
                .manager
                .generation(&self.context.tenant, &incarnation.to_string())
                .map_err(|_| {
                    kasumi_types::Error::new(
                        kasumi_types::ErrorCode::Unavailable,
                        "restore generation unavailable",
                    )
                })?;
            check(&target)?;
        }
        if let Some(target) = &self.provisioning {
            target.store.check_access().map_err(|_| {
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Sealed,
                    "provisioned tenant key access expired",
                )
            })?;
        }
        self.manager
            .control
            .raft_group()
            .check_access()
            .map_err(|_| {
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Sealed,
                    "control key access unavailable",
                )
            })?;
        self.manager.control.engine().authorize(
            &self.manager.control_context,
            None,
            Action::Admin,
        )?;
        Ok(())
    }
}

impl Administration {
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
            let tenant = self.current(&context.tenant)?;
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
    pub fn response_fence(
        self: &Arc<Self>,
        context: &RequestContext,
        command: &ManagementCommand,
    ) -> kasumi_types::Result<ManagementResponseFence> {
        let source = self.current(&context.tenant).map_err(|_| {
            kasumi_types::Error::new(kasumi_types::ErrorCode::Forbidden, "tenant access denied")
        })?;
        source
            .database
            .engine()
            .authorize(context, None, Action::Admin)?;
        let target = match command {
            ManagementCommand::Status { incarnation } => *incarnation,
            ManagementCommand::PrepareRestore { incarnation, .. }
            | ManagementCommand::InitializeRestore { incarnation }
            | ManagementCommand::CompleteRestore { incarnation }
            | ManagementCommand::RetireSource { incarnation }
            | ManagementCommand::ActivateRestore { incarnation, .. } => Some(*incarnation),
            _ => None,
        };
        let provisioning = provisioning_tenant(command)
            .map(|name| self.configured(name))
            .transpose()
            .map_err(|_| {
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Forbidden,
                    "tenant provisioning denied",
                )
            })?;
        if provisioning.is_some() || matches!(command, ManagementCommand::ApprovePeerPool { .. }) {
            require_control(context)?;
        }
        Ok(ManagementResponseFence {
            provisioning,
            manager: self.clone(),
            context: context.clone(),
            source: (!matches!(command, ManagementCommand::ActivateRestore { .. }))
                .then_some(source),
            target,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: RuntimeConfig,
        registry: DatabaseRegistry,
        control: Arc<Database>,
        audit: Arc<SecurityAudit>,
        cluster: Option<Arc<ClusterNetwork>>,
        tenants: Vec<ManagedTenant>,
        destinations: BTreeMap<String, Arc<dyn BackupDestination>>,
        admission: Arc<kasumi_engine::admission::NodeAdmission>,
    ) -> Result<Arc<Self>> {
        let mut generations = BTreeMap::new();
        let mut active = BTreeMap::new();
        for tenant in tenants {
            let state = tenant.database.engine().generation()?;
            let name = state.state.tenant.clone();
            let incarnation = state.state.incarnation.clone();
            active.insert(name.clone(), incarnation.clone());
            generations.insert((name, incarnation), tenant);
        }
        let control_context = crate::runtime::configured_control_context(&config.control)?;
        Ok(Arc::new(Self {
            config,
            registry,
            control,
            control_context,
            audit,
            cluster,
            destinations,
            generations: RwLock::new(generations),
            active: RwLock::new(active),
            enabled: RwLock::new(BTreeSet::from([crate::runtime::CONTROL_TENANT.into()])),
            gate: tokio::sync::Mutex::new(()),
            admission,
        }))
    }
    fn current(&self, tenant: &str) -> Result<ManagedTenant> {
        ensure!(
            self.enabled
                .read()
                .map_err(|_| anyhow::anyhow!("routing unavailable"))?
                .contains(tenant),
            kasumi_types::Error::new(kasumi_types::ErrorCode::Forbidden, "tenant access denied")
        );
        self.configured(tenant)
    }
    fn configured(&self, tenant: &str) -> Result<ManagedTenant> {
        let incarnation = self
            .active
            .read()
            .map_err(|_| anyhow::anyhow!("generation registry unavailable"))?
            .get(tenant)
            .cloned()
            .ok_or_else(|| {
                kasumi_types::Error::new(kasumi_types::ErrorCode::Forbidden, "tenant access denied")
            })?;
        self.generation(tenant, &incarnation)
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
        tenant: &ManagedTenant,
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
    pub async fn execute(
        &self,
        context: RequestContext,
        command: ManagementCommand,
    ) -> kasumi_types::Result<serde_json::Value> {
        // No user-provided tenant can bypass this lookup and current RBAC.
        let _guard = self.gate.lock().await;
        let mut result: Result<serde_json::Value> = async {
            let result = self.execute_inner(&context, command).await?;
            let current = self.current(&context.tenant)?;
            self.authorized(&current, &context, false).await?;
            Ok(result)
        }
        .await;
        if let Err(error) = &mut result
            && let Some(error) = error.downcast_mut::<kasumi_types::Error>()
            && !error.denial_audit_attempted()
            && matches!(
                error.code,
                kasumi_types::ErrorCode::Forbidden | kasumi_types::ErrorCode::Sealed
            )
        {
            let kind = if error.code == kasumi_types::ErrorCode::Sealed {
                SecurityEventKind::TenantSealed
            } else {
                SecurityEventKind::AccessDenied
            };
            // A failed denial audit can never turn the denial into access.
            let _ = self.event(&context, kind, SecurityOutcome::Denied).await;
            error.mark_denial_audit_attempted();
        }
        result.map_err(|error| {
            error
                .downcast_ref::<kasumi_types::Error>()
                .cloned()
                .unwrap_or_else(|| {
                    kasumi_types::Error::new(
                        kasumi_types::ErrorCode::Unavailable,
                        "administrative operation failed; inspect status before retrying",
                    )
                })
        })
    }
    async fn execute_inner(
        &self,
        context: &RequestContext,
        command: ManagementCommand,
    ) -> Result<serde_json::Value> {
        let source = self.current(&context.tenant)?;
        self.authorized(&source, context, false).await?;
        let _maintenance = match &command {
            ManagementCommand::Backup { destination }
            | ManagementCommand::PrepareRestore { destination, .. } => {
                let limit = self
                    .config
                    .backup_destinations
                    .get(destination)
                    .context("backup destination not configured")?
                    .max_bytes();
                Some(
                    self.admission
                        .reserve((limit as u64).saturating_mul(4), None)?,
                )
            }
            _ => None,
        };
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
                self.approve_tenant(context, &tenant).await
            }
            ManagementCommand::PrepareTenant { tenant } => {
                require_control(context)?;
                self.prepare_tenant(context, &tenant).await
            }
            ManagementCommand::InitializeTenant { tenant } => {
                require_control(context)?;
                self.initialize_tenant(context, &tenant).await
            }
            ManagementCommand::ActivateTenant {
                tenant,
                expected_topology_version,
            } => {
                require_control(context)?;
                self.activate_tenant(context, &tenant, expected_topology_version)
                    .await
            }
            ManagementCommand::Status { incarnation } => {
                let source = if let Some(incarnation) = incarnation {
                    self.generation(&context.tenant, &incarnation.to_string())?
                } else {
                    source
                };
                self.authorized(&source, context, false).await?;
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
            ManagementCommand::Backup { destination } => {
                self.event(context, SecurityEventKind::Backup, SecurityOutcome::Started)
                    .await?;
                let result = source
                    .database
                    .backup(context.clone(), self.destination(&destination)?)
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
                self.authorized(&source, context, true).await?;
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
                self.authorized(&source, context, true).await?;
                Ok(serde_json::json!({"completed":true,"scope":"this_replica"}))
            }
            ManagementCommand::PrepareRestore {
                destination,
                backup_id,
                incarnation,
            } => {
                ensure!(
                    !incarnation.is_nil()
                        && source.database.engine().generation()?.state.incarnation
                            != incarnation.to_string(),
                    "restore requires a fresh incarnation"
                );
                if generation_path(&self.config.database_path, &context.tenant, incarnation)
                    .is_file()
                    && self
                        .generation(&context.tenant, &incarnation.to_string())
                        .is_err()
                {
                    self.load_generation(&source, &context.tenant, incarnation)
                        .await?;
                }
                ensure!(
                    source.database.engine().generation()?.state.suspended,
                    "source must be suspended before restore"
                );
                if let Ok(existing) = self.generation(&context.tenant, &incarnation.to_string()) {
                    let descriptor = existing.descriptor.context("incarnation already exists")?;
                    ensure!(
                        descriptor.backup_id == backup_id,
                        "incarnation belongs to another backup"
                    );
                    return Ok(serde_json::to_value(descriptor)?);
                }
                self.event(
                    context,
                    SecurityEventKind::Restore,
                    SecurityOutcome::Started,
                )
                .await?;
                let path =
                    generation_path(&self.config.database_path, &context.tenant, incarnation);
                fresh_file(&path)?;
                let node = NodeStore::open(&path)?;
                let store =
                    TenantStore::open(node, context.tenant.clone(), source.provider.clone())
                        .await?;
                let (database, bootstrap, hash) = if let (Some(_bootstrap), Some(network)) =
                    (&source.bootstrap, &self.cluster)
                {
                    let topology = self.committed_topology()?;
                    let route = topology
                        .tenants
                        .get(&context.tenant)
                        .context("tenant route absent")?;
                    let voters = route
                        .voters
                        .iter()
                        .map(|id| {
                            let node = topology.nodes.get(id).context("voter metadata absent")?;
                            Ok((
                                *id,
                                kasumi_engine::ReplicaPlacement {
                                    address: node.endpoint.clone(),
                                    failure_domain: node.failure_domain.clone(),
                                },
                            ))
                        })
                        .collect::<Result<BTreeMap<_, _>>>()?;
                    let prepared = kasumi_engine::prepare_replicated_restore(
                        self.destination(&destination)?,
                        backup_id,
                        source.provider.clone(),
                        store.clone(),
                        context.clone(),
                        kasumi_engine::ReplicaRestoreConfig {
                            node_id: self
                                .config
                                .replication
                                .as_ref()
                                .context("replication missing")?
                                .node_id,
                            incarnation,
                            voters,
                            raft: kasumi_raft::server_config(),
                        },
                        network.clone(),
                        self.audit.clone(),
                    )
                    .await?;
                    let fingerprint = crate::runtime::persisted_bootstrap_fingerprint(&store)?;
                    let bootstrap_store = store.clone();
                    network.register_group_with_bootstrap(
                        format!("{}/{}", context.tenant, incarnation),
                        prepared.database.raft_group().raft().clone(),
                        prepared.bootstrap.voters.keys().copied().collect(),
                        fingerprint,
                        Arc::new(move || bootstrap_store.check_access()),
                    )?;
                    (
                        prepared.database,
                        Some(prepared.bootstrap),
                        prepared.bootstrap_sha256,
                    )
                } else {
                    let db = kasumi_engine::restore_local_with_incarnation_and_admission(
                        self.destination(&destination)?,
                        backup_id,
                        source.provider.clone(),
                        store.clone(),
                        context.clone(),
                        incarnation,
                        self.admission.clone(),
                        self.audit.clone(),
                    )
                    .await?;
                    (db, None, String::new())
                };
                if bootstrap.is_some() {
                    database.install_admission(self.admission.clone())?;
                }
                let descriptor = GenerationDescriptor {
                    format: 1,
                    tenant: context.tenant.clone(),
                    incarnation,
                    backup_id,
                    bootstrap: bootstrap.clone(),
                    bootstrap_sha256: hash,
                };
                store.write_batch(&[WriteOp::put(
                    "runtime.generation",
                    b"descriptor",
                    serde_json::to_vec(&descriptor)?,
                )])?;
                self.generations
                    .write()
                    .map_err(|_| anyhow::anyhow!("generation registry unavailable"))?
                    .insert(
                        (context.tenant.clone(), incarnation.to_string()),
                        ManagedTenant {
                            database,
                            store,
                            provider: source.provider.clone(),
                            bootstrap,
                            descriptor: Some(descriptor.clone()),
                        },
                    );
                self.event(
                    context,
                    SecurityEventKind::Restore,
                    SecurityOutcome::Succeeded,
                )
                .await?;
                Ok(serde_json::to_value(descriptor)?)
            }
            ManagementCommand::InitializeRestore { incarnation } => {
                let target = self.generation(&context.tenant, &incarnation.to_string())?;
                self.authorized(&target, context, false).await?;
                let bootstrap = target
                    .bootstrap
                    .as_ref()
                    .context("local restore already initialized")?;
                ensure!(
                    self.config
                        .replication
                        .as_ref()
                        .is_some_and(|r| Some(&r.node_id) == bootstrap.voters.keys().next()),
                    "initialize on designated lowest voter"
                );
                // Readiness is checked through pinned peer identities before a
                // replacement generation can start consensus.
                self.verify_restore_peers(&target).await?;
                kasumi_engine::initialize_replicated(&target.database, bootstrap).await?;
                Ok(serde_json::json!({"initialized":true}))
            }
            ManagementCommand::CompleteRestore { incarnation } => {
                let target = self.generation(&context.tenant, &incarnation.to_string())?;
                target.database.complete_restore(context.clone()).await?;
                self.event(
                    context,
                    SecurityEventKind::Restore,
                    SecurityOutcome::Succeeded,
                )
                .await?;
                Ok(serde_json::json!({"completed":true,"incarnation":incarnation}))
            }
            ManagementCommand::RetireSource { incarnation } => {
                let target = self.generation(&context.tenant, &incarnation.to_string())?;
                self.authorized(&target, context, false).await?;
                let target_state = target.database.engine().generation()?;
                ensure!(
                    target_state.state.suspended && target_state.state.pending_restore.is_none(),
                    "target restore not complete"
                );
                source
                    .database
                    .administer(context.clone(), Operation::Retire)
                    .await?;
                Ok(serde_json::json!({"retired":true}))
            }
            ManagementCommand::ActivateRestore {
                incarnation,
                expected_source,
            } => {
                let target = self.generation(&context.tenant, &incarnation.to_string())?;
                self.authorized(&target, context, false).await?;
                let source_state = source.database.engine().generation()?;
                if source_state.state.incarnation == incarnation.to_string() {
                    let plane = ControlPlane::new(self.control.clone())?;
                    let topology = plane
                        .topology(&self.control_context)
                        .await?
                        .context("control topology missing")?;
                    ensure!(
                        topology
                            .topology
                            .tenants
                            .get(&context.tenant)
                            .is_some_and(|route| route.incarnation == incarnation.to_string()),
                        "control route changed"
                    );
                    self.event(
                        context,
                        SecurityEventKind::Restore,
                        SecurityOutcome::Succeeded,
                    )
                    .await?;
                    return Ok(
                        serde_json::json!({"active_incarnation":incarnation,"suspended":source_state.state.suspended}),
                    );
                }
                ensure!(
                    source_state.state.incarnation == expected_source && source_state.state.retired,
                    "source must be durably retired"
                );
                let target_state = target.database.engine().generation()?;
                ensure!(
                    target_state.state.suspended && target_state.state.pending_restore.is_none(),
                    "target must be a completed suspended restore"
                );
                let plane = ControlPlane::new(self.control.clone())?;
                let current = plane
                    .topology(&self.control_context)
                    .await?
                    .context("control topology missing")?;
                let mut topology = current.topology;
                let route = topology
                    .tenants
                    .get_mut(&context.tenant)
                    .context("tenant route absent")?;
                ensure!(
                    route.incarnation == expected_source
                        || route.incarnation == incarnation.to_string(),
                    "control route changed"
                );
                let needs_publication = route.incarnation != incarnation.to_string();
                route.incarnation = incarnation.to_string();
                self.event(
                    context,
                    SecurityEventKind::Restore,
                    SecurityOutcome::Started,
                )
                .await?;
                if needs_publication {
                    plane
                        .replace_topology(
                            self.control_context.clone(),
                            topology,
                            Precondition::Version(current.version),
                            format!("activate-{incarnation}"),
                        )
                        .await?;
                }
                self.publish_target(&context.tenant, &expected_source, target)?;
                self.event(
                    context,
                    SecurityEventKind::Restore,
                    SecurityOutcome::Succeeded,
                )
                .await?;
                Ok(serde_json::json!({"active_incarnation":incarnation,"suspended":true}))
            }
            ManagementCommand::AddLearner { node_id } => {
                self.authorized(&source, context, true).await?;
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
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    source
                        .database
                        .raft_group()
                        .add_learner(node_id, kasumi_raft::BasicNode::new(node.endpoint.clone())),
                )
                .await
                .map_err(|_| {
                    kasumi_types::Error::new(
                        kasumi_types::ErrorCode::UnknownOutcome,
                        "learner catch-up deadline exceeded; inspect membership",
                    )
                })??;
                self.event(
                    context,
                    SecurityEventKind::Membership,
                    SecurityOutcome::Succeeded,
                )
                .await?;
                Ok(serde_json::json!({"caught_up":node_id}))
            }
            ManagementCommand::ChangeMembership { voters } => {
                self.authorized(&source, context, true).await?;
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
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    source.database.raft_group().change_membership(voters),
                )
                .await
                .map_err(|_| {
                    kasumi_types::Error::new(
                        kasumi_types::ErrorCode::UnknownOutcome,
                        "membership deadline exceeded; inspect committed membership",
                    )
                })??;
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
            Ok(replication
                .peers
                .iter()
                .map(|peer| {
                    (
                        peer.node_id,
                        kasumi_engine::control::ControlNode {
                            endpoint: crate::runtime::origin(&peer.endpoint)
                                .expect("validated peer")
                                .to_string(),
                            failure_domain: peer.failure_domain.clone(),
                            certificate_pins: peer
                                .certificate_pins
                                .iter()
                                .map(|p| p.to_ascii_lowercase())
                                .collect(),
                        },
                    )
                })
                .collect())
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
        let configuration = self
            .config
            .tenants
            .iter()
            .find(|t| t.tenant == tenant)
            .context("tenant not configured")?;
        let generation = target.database.engine().generation()?;
        // Local reopen deliberately ignores changed bootstrap configuration for
        // existing databases. A staged tenant must therefore prove the proposed
        // policy/limits are the ones actually resident before approval.
        if !self.committed_topology()?.tenants.contains_key(tenant) {
            ensure!(
                serde_json::to_value(&generation.state.policy)?
                    == serde_json::to_value(&configuration.initial_policy)?
                    && serde_json::to_value(&generation.state.limits)?
                        == serde_json::to_value(&configuration.initial_limits)?,
                "staged resident policy/limits differ from configured bootstrap"
            );
        }
        let route = self.provision_route(target)?;
        let configured_nodes = self.configured_nodes()?;
        let approved = self.committed_topology()?;
        let nodes = route
            .voters
            .iter()
            .map(|id| {
                let node = configured_nodes
                    .get(id)
                    .context("configured voter absent")?;
                ensure!(
                    approved.nodes.get(id) == Some(node),
                    "voter identity/pins not approved in control metadata"
                );
                Ok((*id, node.clone()))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut check = approved;
        check.tenants.insert(tenant.into(), route.clone());
        check.validate()?;
        // No credentials, local paths, node-specific token env names, or mutable
        // state enter the fingerprint. All immutable policy/schema limits and
        // voter identities must match, including the configured wrapping key.
        let settings = &configuration.transit;
        let bytes = serde_json::to_vec(&serde_json::json!({
            "format":1,"tenant":tenant,"route":route,"nodes":nodes,
            "initial_policy":configuration.initial_policy,"initial_limits":configuration.initial_limits,
            "transit":{"endpoint":settings.endpoint,"mount":settings.mount,"key_name":settings.key_name,
                "namespace":settings.namespace,"derived":settings.derived}
        }))?;
        Ok(format!("provision-v1-{}", hex_digest(&bytes)))
    }
    fn provision_approval(&self, tenant: &str) -> Result<String> {
        self.control.raft_group().check_access()?;
        let generation = self.control.engine().generation()?;
        let document = generation
            .state
            .collections
            .get("tenant_provisioning")
            .and_then(|c| c.documents.get(tenant))
            .context("tenant has no committed control approval")?;
        document
            .body
            .get("bootstrap_sha256")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .context("invalid provisioning approval")
    }
    async fn approve_peer_pool(
        &self,
        context: &RequestContext,
        expected: u64,
    ) -> Result<serde_json::Value> {
        self.authorized(
            &self.current(crate::runtime::CONTROL_TENANT)?,
            context,
            true,
        )
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
    async fn approve_tenant(
        &self,
        context: &RequestContext,
        tenant: &str,
    ) -> Result<serde_json::Value> {
        self.authorized(
            &self.current(crate::runtime::CONTROL_TENANT)?,
            context,
            true,
        )
        .await?;
        let target = self.provision_target(tenant)?;
        ensure!(
            !self.committed_topology()?.tenants.contains_key(tenant),
            "tenant already has a serving route"
        );
        let hash = self.provision_hash(tenant, &target)?;
        let definition = kasumi_types::CollectionDefinition {
            write_mode: kasumi_types::CollectionWriteMode::Mutable,
            name: "tenant_provisioning".into(),
            schema: serde_json::json!({"type":"object","required":["bootstrap_sha256"],"additionalProperties":false,
                "properties":{"bootstrap_sha256":{"type":"string","pattern":"^provision-v1-[a-f0-9]{64}$"}}}),
            indexes: vec![],
            strict_read_audit: true,
        };
        let existing = self
            .control
            .engine()
            .generation()?
            .state
            .collections
            .get("tenant_provisioning")
            .map(|c| c.definition.clone());
        if let Some(existing) = existing {
            ensure!(
                serde_json::to_value(existing)? == serde_json::to_value(&definition)?,
                "provisioning schema mismatch"
            );
        } else {
            self.control
                .administer(context.clone(), Operation::CreateCollection(definition))
                .await?;
        }
        if let Ok(approved) = self.provision_approval(tenant) {
            ensure!(
                approved == hash,
                "tenant was approved with another immutable bootstrap"
            );
        } else {
            self.control
                .mutate(
                    context.clone(),
                    kasumi_types::MutationBatch {
                        read_set: Vec::new(),
                        idempotency_key: format!(
                            "approve-tenant-{}",
                            hex_digest(format!("{tenant}/{hash}").as_bytes())
                        ),
                        operations: vec![kasumi_types::Mutation::Put {
                            collection: "tenant_provisioning".into(),
                            id: tenant.into(),
                            body: serde_json::json!({"bootstrap_sha256":hash}),
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
        target.store.check_access()?;
        Ok(serde_json::json!({"approved":true,"tenant":tenant,"bootstrap_sha256":hash}))
    }
    async fn prepare_tenant(
        &self,
        context: &RequestContext,
        tenant: &str,
    ) -> Result<serde_json::Value> {
        let target = self.provision_target(tenant)?;
        let hash = self.provision_hash(tenant, &target)?;
        ensure!(
            self.provision_approval(tenant)? == hash,
            "approved bootstrap differs from this replica"
        );
        target.store.check_access()?;
        self.event(
            context,
            SecurityEventKind::Administration,
            SecurityOutcome::Started,
        )
        .await?;
        target.store.write_batch(&[WriteOp::put(
            "runtime.provisioning",
            b"prepared",
            hash.as_bytes(),
        )])?;
        self.event(
            context,
            SecurityEventKind::Administration,
            SecurityOutcome::Succeeded,
        )
        .await?;
        Ok(
            serde_json::json!({"prepared":true,"tenant":tenant,"bootstrap_sha256":hash,
            "incarnation":target.database.engine().generation()?.state.incarnation}),
        )
    }
    async fn verify_provision_peers(
        &self,
        tenant: &str,
        target: &ManagedTenant,
        require_initialized: bool,
    ) -> Result<()> {
        use crate::cluster::RestoreReadinessProvider;
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
                network.restore_readiness(*peer, &group).await?
            } else {
                self.readiness(&group)?
            };
            ensure!(
                ready.bootstrap_sha256 == hash,
                "replica bootstrap or identity/pins differ"
            );
            ensure!(
                !ready.pending_restore && (!require_initialized || ready.initialized),
                "replica has not applied initialized membership"
            );
        }
        Ok(())
    }
    async fn initialize_tenant(
        &self,
        context: &RequestContext,
        tenant: &str,
    ) -> Result<serde_json::Value> {
        let target = self.provision_target(tenant)?;
        self.verify_provision_peers(tenant, &target, false).await?;
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
        expected: u64,
    ) -> Result<serde_json::Value> {
        self.authorized(
            &self.current(crate::runtime::CONTROL_TENANT)?,
            context,
            true,
        )
        .await?;
        let target = self.provision_target(tenant)?;
        self.verify_provision_peers(tenant, &target, true).await?;
        let plane = ControlPlane::new(self.control.clone())?;
        let current = plane
            .topology(context)
            .await?
            .context("control topology missing")?;
        let route = self.provision_route(&target)?;
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
    fn publish_target(&self, tenant: &str, expected: &str, target: ManagedTenant) -> Result<()> {
        let incarnation = target
            .database
            .engine()
            .generation()?
            .state
            .incarnation
            .clone();
        if self
            .registry
            .database(&RequestContext {
                tenant: tenant.into(),
                principal: "runtime".into(),
                scopes: BTreeSet::new(),
                request_id: "runtime".into(),
            })
            .is_ok()
        {
            self.registry
                .replace_generation(expected, target.database.clone())?;
        } else {
            self.registry.insert(target.database.clone())?;
        }
        if let Ok(previous) = self.generation(tenant, expected) {
            previous.database.engine().seal();
            previous.store.seal();
        }
        self.active
            .write()
            .map_err(|_| anyhow::anyhow!("generation registry unavailable"))?
            .insert(tenant.into(), incarnation);
        self.enabled
            .write()
            .map_err(|_| anyhow::anyhow!("routing unavailable"))?
            .insert(tenant.into());
        Ok(())
    }
    async fn verify_restore_peers(&self, target: &ManagedTenant) -> Result<()> {
        let descriptor = target
            .descriptor
            .as_ref()
            .context("restore descriptor missing")?;
        let bootstrap = target
            .bootstrap
            .as_ref()
            .context("restore bootstrap missing")?;
        let network = self
            .cluster
            .as_ref()
            .context("replication transport missing")?;
        let group = format!("{}/{}", descriptor.tenant, descriptor.incarnation);
        let fingerprint = crate::runtime::persisted_bootstrap_fingerprint(&target.store)?;
        for peer in bootstrap.voters.keys() {
            ensure!(
                network.bootstrap_fingerprint(*peer, &group).await? == fingerprint,
                "replicas prepared different bootstrap state or placement"
            );
            let ready = network.restore_readiness(*peer, &group).await?;
            ensure!(
                ready.bootstrap_sha256 == descriptor.bootstrap_sha256,
                "replicas prepared different restored state"
            );
        }
        Ok(())
    }
    async fn load_generation(
        &self,
        source: &ManagedTenant,
        tenant: &str,
        incarnation: Uuid,
    ) -> Result<ManagedTenant> {
        let path = generation_path(&self.config.database_path, tenant, incarnation);
        ensure!(path.is_file(), "durably routed generation file is missing");
        let _reservation = self.admission.reserve(
            source
                .database
                .engine()
                .generation()?
                .state
                .logical_bytes
                .saturating_mul(8)
                .saturating_add(1 << 20),
            None,
        )?;
        let node = NodeStore::open(path)?;
        let store = TenantStore::open(node, tenant.to_owned(), source.provider.clone()).await?;
        let descriptor: GenerationDescriptor = serde_json::from_slice(
            &store
                .get("runtime.generation", b"descriptor")?
                .context("generation descriptor absent")?,
        )?;
        ensure!(
            descriptor.format == 1
                && descriptor.tenant == tenant
                && descriptor.incarnation == incarnation,
            "generation descriptor mismatch"
        );
        let database = if let Some(bootstrap) = &descriptor.bootstrap {
            let network = self
                .cluster
                .as_ref()
                .context("replication transport absent")?;
            let db = kasumi_engine::open_replicated(
                self.config
                    .replication
                    .as_ref()
                    .context("replication absent")?
                    .node_id,
                store.clone(),
                bootstrap,
                network.clone(),
                kasumi_raft::server_config(),
                self.audit.clone(),
            )
            .await?;
            let fingerprint = crate::runtime::persisted_bootstrap_fingerprint(&store)?;
            let bootstrap_store = store.clone();
            network.register_group_with_bootstrap(
                format!("{tenant}/{incarnation}"),
                db.raft_group().raft().clone(),
                bootstrap.voters.keys().copied().collect(),
                fingerprint,
                Arc::new(move || bootstrap_store.check_access()),
            )?;
            db
        } else {
            kasumi_engine::open_local(
                store.clone(),
                self.config
                    .tenants
                    .iter()
                    .find(|t| t.tenant == tenant)
                    .context("unknown tenant")?
                    .initial_policy
                    .clone(),
                kasumi_types::Limits::default(),
                self.audit.clone(),
            )
            .await?
        };
        database.install_admission(self.admission.clone())?;
        let target = ManagedTenant {
            database,
            store,
            provider: source.provider.clone(),
            bootstrap: descriptor.bootstrap.clone(),
            descriptor: Some(descriptor),
        };
        self.generations
            .write()
            .map_err(|_| anyhow::anyhow!("generation registry unavailable"))?
            .insert((tenant.to_owned(), incarnation.to_string()), target.clone());
        Ok(target)
    }
    pub(crate) async fn reconcile(&self) -> Result<()> {
        let _guard = self.gate.lock().await;
        let topology = self.committed_topology()?;
        for (tenant, route) in topology.tenants {
            let source = self.configured(&tenant)?;
            let old = source
                .database
                .engine()
                .generation()?
                .state
                .incarnation
                .clone();
            if old == route.incarnation {
                if !self
                    .enabled
                    .read()
                    .map_err(|_| anyhow::anyhow!("routing unavailable"))?
                    .contains(&tenant)
                {
                    self.registry.insert(source.database.clone())?;
                    self.enabled
                        .write()
                        .map_err(|_| anyhow::anyhow!("routing unavailable"))?
                        .insert(tenant.clone());
                }
                continue;
            }
            let target = match self.generation(&tenant, &route.incarnation) {
                Ok(target) => target,
                Err(_) => {
                    self.load_generation(&source, &tenant, Uuid::parse_str(&route.incarnation)?)
                        .await?
                }
            };
            if target
                .database
                .engine()
                .generation()?
                .state
                .pending_restore
                .is_some()
            {
                continue;
            }
            self.publish_target(&tenant, &old, target)?;
        }
        Ok(())
    }
    pub(crate) async fn shutdown(&self) {
        let generations = self
            .generations
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for tenant in generations {
            let _ = tenant.database.shutdown().await;
        }
    }
}
pub(crate) fn generation_path(base: &Path, tenant: &str, incarnation: Uuid) -> PathBuf {
    let digest = Sha256::digest(tenant.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    base.with_extension("generations")
        .join(digest)
        .join(format!("{incarnation}.redb"))
}
fn fresh_file(path: &Path) -> Result<()> {
    let parent = path.parent().context("generation directory absent")?;
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .context("restore target must be fresh")?;
    file.sync_all()?;
    for directory in parent.ancestors() {
        if !directory.as_os_str().is_empty() {
            std::fs::File::open(directory)?.sync_all()?;
        }
    }
    Ok(())
}

impl crate::cluster::RestoreReadinessProvider for Administration {
    fn readiness(&self, group: &str) -> Result<crate::cluster::RestoreReadiness> {
        let (tenant, incarnation) = group.rsplit_once('/').context("invalid generation group")?;
        let target = self.generation(tenant, incarnation)?;
        target.store.check_access()?;
        let state = target.database.engine().generation()?;
        let bootstrap_sha256 = if let Some(descriptor) = &target.descriptor {
            descriptor.bootstrap_sha256.clone()
        } else {
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
            expected
        };
        Ok(crate::cluster::RestoreReadiness {
            bootstrap_sha256,
            pending_restore: state.state.pending_restore.is_some(),
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
    #[test]
    fn closed_commands_reject_path_and_tenant_overrides() {
        assert!(
            serde_json::from_value::<ManagementCommand>(
                serde_json::json!({"operation":"backup","destination":"named","tenant":"other"})
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
    #[test]
    fn generation_paths_cannot_inherit_tenant_traversal() {
        let base = Path::new("/var/lib/kasumi/node.redb");
        let incarnation = Uuid::new_v4();
        let path = generation_path(base, "../../escape", incarnation);
        assert!(path.starts_with("/var/lib/kasumi/node.generations"));
        assert_eq!(
            path.file_name().unwrap(),
            format!("{incarnation}.redb").as_str()
        );
        assert_eq!(path.components().count(), 7);
    }
}
