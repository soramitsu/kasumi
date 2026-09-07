//! Persisted bootstrap and logical restore, separate from node-bound Raft snapshots.
use crate::{Database, SecurityAudit, TenantEngine};
use kasumi_raft::{BasicNode, Config, RaftGroup, RaftTransport};
use kasumi_store::{
    BackupDestination, EncryptedBackup, KeyProvider, TenantStorageSet, TenantStore, WriteOp,
};
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[path = "backup_restore.rs"]
mod backup_restore;
pub use backup_restore::RestoreSource;

const NS: &str = "engine.bootstrap";
const CHUNK: usize = 4 << 20;
const MAX_BOOTSTRAP: usize = 2 << 30;
// Only bootstraps are serialized here, never data operations. A node owns its
// redb file exclusively; startup must register each returned tenant once.
static BOOTSTRAP_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Operator-approved placement. Transport must authenticate the node independently
/// of this address; a data request cannot choose a network destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaPlacement {
    pub address: String,
    pub failure_domain: String,
}

/// All initial replicas receive exactly the same bootstrap. Subsequent policy
/// and membership changes are tenant commands and never configuration overrides.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicatedBootstrap {
    pub incarnation: String,
    pub initial_policy: Policy,
    pub initial_limits: Limits,
    pub voters: BTreeMap<u64, ReplicaPlacement>,
}

/// Trusted placement for one replica of a new restore generation. Every member
/// uses the same backup UUID, fresh incarnation and three-voter placement.
pub struct ReplicaRestoreConfig {
    pub node_id: u64,
    pub incarnation: uuid::Uuid,
    pub voters: BTreeMap<u64, ReplicaPlacement>,
    pub raft: Config,
    pub admission: Arc<crate::admission::NodeAdmission>,
}

pub struct PreparedReplicaRestore {
    pub database: Arc<Database>,
    pub bootstrap: ReplicatedBootstrap,
    pub backup_id: uuid::Uuid,
    pub source_revision: u64,
    /// Compare across replicas before activating a restored placement.
    pub bootstrap_sha256: String,
}

/// Verify and install an encrypted backup into an EMPTY replica store. This
/// starts no membership and cannot serve data: the pending restore marker is
/// part of its durable bootstrap. Register each peer, initialize three voters,
/// then `Database::complete_restore` must commit before explicit activation.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_replicated_restore(
    source: &RestoreSource,
    backup_id: uuid::Uuid,
    targets: Arc<TenantStorageSet>,
    context: RequestContext,
    replica: ReplicaRestoreConfig,
    transport: Arc<dyn RaftTransport>,
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<PreparedReplicaRestore> {
    let target = targets.application().clone();
    let deadline = source.deadline()?;
    let _gate = deadline.run(BOOTSTRAP_GATE.lock()).await?;
    restore_access(&target, &security_audit, &context).await?;
    anyhow::ensure!(
        target.get(NS, b"manifest")?.is_none()
            && targets
                .custody()
                .store()
                .get("raft.meta", b"node_id")?
                .is_none(),
        "restore target is already initialized"
    );
    anyhow::ensure!(
        replica.node_id > 0
            && replica.voters.contains_key(&replica.node_id)
            && !replica.incarnation.is_nil(),
        "invalid restore replica identity"
    );
    let verified = deadline
        .run(Box::pin(backup_restore::load(
            source,
            backup_id,
            &target,
            &context,
            &security_audit,
            &replica.admission,
            deadline,
        )))
        .await??;
    let source_revision = verified.state.revision;
    let _restore_workspace = verified._reservation.clone();
    let original = &verified.state;
    anyhow::ensure!(
        replica.incarnation.to_string() != original.incarnation,
        "restore requires a fresh incarnation"
    );
    let bootstrap = ReplicatedBootstrap {
        incarnation: replica.incarnation.to_string(),
        initial_policy: original.policy.clone(),
        initial_limits: original.limits.clone(),
        voters: replica.voters,
    };
    bootstrap.validate()?;
    let restored = verified
        .into_genesis(
            deadline,
            target.tenant().into(),
            bootstrap.incarnation.clone(),
        )
        .await?;
    deadline.check()?;
    restore_access(&target, &security_audit, &context).await?;
    bind_deployment(&targets, &serde_json::to_vec(&("replicated", &bootstrap))?)?;
    persist_new(&targets, &restored.bytes)?;
    let engine = restored.engine;
    let group = RaftGroup::open(
        replica.node_id,
        format!("{}/{}", target.tenant(), bootstrap.incarnation),
        targets.clone(),
        engine.clone(),
        transport,
        replica.raft,
    )
    .await?;
    let database =
        Database::new_with_admission(engine, group, target, replica.admission, security_audit);
    database.install_archive_destination(
        source.destination_alias.clone(),
        source.destination.clone(),
    )?;
    Ok(PreparedReplicaRestore {
        database,
        bootstrap,
        backup_id,
        source_revision,
        bootstrap_sha256: restored.sha256,
    })
}

impl ReplicatedBootstrap {
    pub fn validate(&self) -> anyhow::Result<()> {
        uuid::Uuid::parse_str(&self.incarnation)?;
        anyhow::ensure!(
            self.voters.len() == 3,
            "replicated mode requires exactly three initial voters"
        );
        let mut domains = BTreeSet::new();
        for (id, placement) in &self.voters {
            anyhow::ensure!(
                *id > 0 && !placement.address.is_empty() && placement.address.len() <= 2048,
                "invalid replica placement"
            );
            validate_name(&placement.failure_domain)?;
            anyhow::ensure!(
                domains.insert(&placement.failure_domain),
                "replicated voters must occupy independent failure domains"
            );
        }
        Ok(())
    }
}

fn bind_deployment(stores: &TenantStorageSet, binding: &[u8]) -> anyhow::Result<()> {
    let store = stores.application();
    const DEPLOYMENT: &str = "engine.deployment";
    if let Some(existing) = store.get(DEPLOYMENT, b"mode")? {
        anyhow::ensure!(
            existing == binding
                && stores
                    .custody()
                    .store()
                    .get(DEPLOYMENT, b"mode")?
                    .as_deref()
                    == Some(binding),
            "deployment bootstrap differs from persisted configuration"
        );
    } else {
        anyhow::ensure!(
            stores
                .custody()
                .store()
                .get("raft.meta", b"node_id")?
                .is_none(),
            "existing Raft storage lacks a deployment binding"
        );
        stores.write_batch(
            &[WriteOp::put(DEPLOYMENT, b"mode", binding)],
            &[WriteOp::put(DEPLOYMENT, b"mode", binding)],
        )?;
    }
    Ok(())
}

/// Open a replica without changing membership. Register its Raft handle with
/// the authenticated peer transport before calling `initialize_replicated` on
/// the lowest initial voter. Reopening never reduces replication or changes
/// policy. New learners use the same bootstrap and their own approved node ID.
pub async fn open_replicated(
    node_id: u64,
    stores: Arc<TenantStorageSet>,
    bootstrap: &ReplicatedBootstrap,
    transport: Arc<dyn RaftTransport>,
    config: Config,
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<Arc<Database>> {
    let store = stores.application().clone();
    bootstrap.validate()?;
    anyhow::ensure!(node_id > 0, "node ID must be positive");
    let _gate = BOOTSTRAP_GATE.lock().await;
    let binding = serde_json::to_vec(&("replicated", bootstrap))?;
    bind_deployment(&stores, &binding)?;
    let bytes = match load(&store)? {
        Some(bytes) => bytes,
        None => {
            let engine = TenantEngine::new(
                store.tenant().into(),
                bootstrap.incarnation.clone(),
                bootstrap.initial_policy.clone(),
                bootstrap.initial_limits.clone(),
            )?;
            let bytes = engine.snapshot()?;
            persist_new(&stores, &bytes)?;
            bytes
        }
    };
    validate_bootstrap_control(&stores, &bytes)?;
    let engine = Arc::new(TenantEngine::from_bootstrap(store.tenant(), &bytes)?);
    anyhow::ensure!(
        engine.generation()?.state.incarnation == bootstrap.incarnation,
        "replicated incarnation differs from bootstrap"
    );
    let group = RaftGroup::open(
        node_id,
        format!("{}/{}", store.tenant(), bootstrap.incarnation),
        stores.clone(),
        engine.clone(),
        transport,
        config,
    )
    .await?;
    Ok(Database::new(engine, group, store, security_audit))
}

/// Explicit first creation, never a partition fallback. Only the designated
/// bootstrap voter initializes, and an existing membership is left untouched.
pub async fn initialize_replicated(
    database: &Database,
    bootstrap: &ReplicatedBootstrap,
) -> anyhow::Result<()> {
    bootstrap.validate()?;
    let binding = serde_json::to_vec(&("replicated", bootstrap))?;
    anyhow::ensure!(
        database
            .store()
            .get("engine.deployment", b"mode")?
            .as_deref()
            == Some(binding.as_slice()),
        "replicated bootstrap does not match this database"
    );
    let group = database.raft_group();
    if group.raft().is_initialized().await? {
        return Ok(());
    }
    let id = group.raft().metrics().borrow().id;
    anyhow::ensure!(
        Some(&id) == bootstrap.voters.keys().next(),
        "only the designated voter may initialize"
    );
    group
        .initialize(
            bootstrap
                .voters
                .iter()
                .map(|(id, p)| (*id, BasicNode::new(&p.address)))
                .collect(),
        )
        .await
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    bytes: usize,
    chunks: usize,
    digest: String,
}

fn load(store: &TenantStore) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(bytes) = store.get(NS, b"manifest")? else {
        return Ok(None);
    };
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        manifest.format == 1
            && manifest.bytes <= MAX_BOOTSTRAP
            && manifest.chunks == manifest.bytes.div_ceil(CHUNK),
        "invalid bootstrap manifest"
    );
    let mut snapshot = Vec::with_capacity(manifest.bytes);
    for i in 0..manifest.chunks {
        let bytes = store
            .get(NS, &(i as u64).to_be_bytes())?
            .ok_or_else(|| anyhow::anyhow!("incomplete bootstrap"))?;
        anyhow::ensure!(
            bytes.len() == (manifest.bytes - snapshot.len()).min(CHUNK),
            "invalid bootstrap chunk length"
        );
        snapshot.extend(bytes);
    }
    anyhow::ensure!(
        hex::encode(Sha256::digest(&snapshot)) == manifest.digest,
        "bootstrap digest mismatch"
    );
    Ok(Some(snapshot))
}

fn validate_bootstrap_control(stores: &TenantStorageSet, bytes: &[u8]) -> anyhow::Result<()> {
    stores.check_access()?;
    let expected = serde_json::to_vec(&hex::encode(Sha256::digest(bytes)))?;
    anyhow::ensure!(
        stores
            .custody()
            .store()
            .get("raft.meta", b"application_bootstrap_sha256")?
            .as_deref()
            == Some(expected.as_slice()),
        "application bootstrap/control identity differs"
    );
    Ok(())
}

fn persist_new(stores: &TenantStorageSet, bytes: &[u8]) -> anyhow::Result<()> {
    let store = stores.application();
    anyhow::ensure!(bytes.len() <= MAX_BOOTSTRAP, "bootstrap exceeds size limit");
    anyhow::ensure!(
        store.get(NS, b"manifest")?.is_none()
            && stores
                .custody()
                .store()
                .get("raft.meta", b"node_id")?
                .is_none(),
        "target tenant already initialized; restore never overwrites it"
    );
    for (i, chunk) in bytes.chunks(CHUNK).enumerate() {
        store.write_batch(&[WriteOp::put(NS, (i as u64).to_be_bytes(), chunk)])?;
    }
    let manifest = Manifest {
        format: 1,
        bytes: bytes.len(),
        chunks: bytes.len().div_ceil(CHUNK),
        digest: hex::encode(Sha256::digest(bytes)),
    };
    // Only this durable manifest makes the bootstrap eligible to start Raft.
    let encoded = serde_json::to_vec(&manifest)?;
    stores.write_batch(
        &[WriteOp::put(NS, b"manifest", encoded)],
        &[WriteOp::put(
            "raft.meta",
            b"application_bootstrap_sha256",
            serde_json::to_vec(&manifest.digest)?,
        )],
    )?;
    Ok(())
}

/// Open a single-voter tenant. On reopen, its persisted bootstrap is authoritative;
/// caller-supplied creation defaults cannot change existing permissions or limits.
/// The node must own exactly one live Database instance for each TenantStore.
pub async fn open_local(
    stores: Arc<TenantStorageSet>,
    initial_policy: Policy,
    initial_limits: Limits,
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<Arc<Database>> {
    let store = stores.application().clone();
    let _gate = BOOTSTRAP_GATE.lock().await;
    bind_deployment(&stores, b"local-v1")?;
    let bytes = match load(&store)? {
        Some(bytes) => bytes,
        None => {
            let engine = TenantEngine::new(
                store.tenant().into(),
                uuid::Uuid::new_v4().to_string(),
                initial_policy,
                initial_limits,
            )?;
            let bytes = engine.snapshot()?;
            persist_new(&stores, &bytes)?;
            bytes
        }
    };
    start(stores, &bytes, security_audit).await
}

async fn start(
    stores: Arc<TenantStorageSet>,
    bytes: &[u8],
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<Arc<Database>> {
    start_with_optional_admission(stores, bytes, None, security_audit).await
}

async fn start_with_optional_admission(
    stores: Arc<TenantStorageSet>,
    bytes: &[u8],
    admission: Option<Arc<crate::admission::NodeAdmission>>,
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<Arc<Database>> {
    validate_bootstrap_control(&stores, bytes)?;
    let engine = Arc::new(TenantEngine::from_bootstrap(
        stores.application().tenant(),
        bytes,
    )?);
    start_prepared(stores, engine, admission, security_audit).await
}

async fn start_prepared(
    stores: Arc<TenantStorageSet>,
    engine: Arc<TenantEngine>,
    admission: Option<Arc<crate::admission::NodeAdmission>>,
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<Arc<Database>> {
    let store = stores.application().clone();
    let incarnation = engine.generation()?.state.incarnation.clone();
    let group = RaftGroup::local(
        1,
        format!("{}/{incarnation}", store.tenant()),
        stores.clone(),
        engine.clone(),
    )
    .await?;
    Ok(match admission {
        Some(admission) => {
            Database::new_with_admission(engine, group, store, admission, security_audit)
        }
        None => Database::new(engine, group, store, security_audit),
    })
}

/// Restore a verified logical backup into an empty store for the SAME tenant.
/// Old Raft membership/node identities never cross this boundary. The result is
/// suspended and must be explicitly activated through its administrative API.
pub async fn restore_local(
    source: &RestoreSource,
    backup_id: uuid::Uuid,
    targets: Arc<TenantStorageSet>,
    context: RequestContext,
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<Arc<Database>> {
    restore_local_with_incarnation(
        source,
        backup_id,
        targets,
        context,
        uuid::Uuid::new_v4(),
        security_audit,
    )
    .await
}

/// The server chooses a fresh incarnation before creating its isolated restore
/// file. An existing store or the backup's original incarnation is rejected.
pub async fn restore_local_with_incarnation(
    source: &RestoreSource,
    backup_id: uuid::Uuid,
    targets: Arc<TenantStorageSet>,
    context: RequestContext,
    incarnation: uuid::Uuid,
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<Arc<Database>> {
    restore_local_with_incarnation_and_admission(
        source,
        backup_id,
        targets,
        context,
        incarnation,
        crate::admission::NodeAdmission::process_default(),
        security_audit,
    )
    .await
}

/// Install the node's admission governor before the required restore audit.
#[allow(clippy::too_many_arguments)]
pub async fn restore_local_with_incarnation_and_admission(
    source: &RestoreSource,
    backup_id: uuid::Uuid,
    targets: Arc<TenantStorageSet>,
    context: RequestContext,
    incarnation: uuid::Uuid,
    admission: Arc<crate::admission::NodeAdmission>,
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<Arc<Database>> {
    let target = targets.application().clone();
    let deadline = source.deadline()?;
    let _gate = deadline.run(BOOTSTRAP_GATE.lock()).await?;
    restore_access(&target, &security_audit, &context).await?;
    anyhow::ensure!(
        target.get(NS, b"manifest")?.is_none()
            && targets
                .custody()
                .store()
                .get("raft.meta", b"node_id")?
                .is_none(),
        "restore target is already initialized"
    );
    let verified = deadline
        .run(Box::pin(backup_restore::load(
            source,
            backup_id,
            &target,
            &context,
            &security_audit,
            &admission,
            deadline,
        )))
        .await??;
    let source_revision = verified.state.revision;
    let _restore_workspace = verified._reservation.clone();
    let original = &verified.state;
    anyhow::ensure!(
        !incarnation.is_nil() && incarnation.to_string() != original.incarnation,
        "restore requires a fresh database incarnation"
    );
    let restored = verified
        .into_genesis(deadline, target.tenant().into(), incarnation.to_string())
        .await?;
    deadline.check()?;
    restore_access(&target, &security_audit, &context).await?;
    bind_deployment(&targets, b"local-v1")?;
    persist_new(&targets, &restored.bytes)?;
    let database =
        start_prepared(targets, restored.engine, Some(admission), security_audit).await?;
    database.install_archive_destination(
        source.destination_alias.clone(),
        source.destination.clone(),
    )?;
    if let Err(error) = database
        .maintenance_audit(context, "restore", "completed", source_revision)
        .await
    {
        database.shutdown().await?;
        return Err(error.into());
    }
    Ok(database)
}

// Restore authorization runs before a Database exists. Keep those public
// embedded boundaries on the same separately protected denial-audit contract.
async fn restore_denial(audit: &SecurityAudit, context: &RequestContext, code: ErrorCode) -> Error {
    let mut error = Error::new(code, "backup restore access denied");
    let _ = audit
        .record(crate::SecurityEvent {
            kind: if code == ErrorCode::Sealed {
                crate::SecurityEventKind::TenantSealed
            } else {
                crate::SecurityEventKind::AccessDenied
            },
            principal: Some(context.principal.clone()),
            tenant: Some(context.tenant.clone()),
            request_id: context.request_id.clone(),
            outcome: crate::SecurityOutcome::Denied,
        })
        .await;
    error.mark_denial_audit_attempted();
    error
}

async fn restore_access(
    target: &TenantStore,
    audit: &SecurityAudit,
    context: &RequestContext,
) -> anyhow::Result<()> {
    if context.authorization.check_live().is_err() {
        return Err(restore_denial(audit, context, ErrorCode::Unauthorized)
            .await
            .into());
    }
    if context.tenant != target.tenant() || !context.scopes.contains(&Action::Admin) {
        return Err(restore_denial(audit, context, ErrorCode::Forbidden)
            .await
            .into());
    }
    if target.check_access().is_err() {
        return Err(restore_denial(audit, context, ErrorCode::Sealed)
            .await
            .into());
    }
    Ok(())
}
