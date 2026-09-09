use kasumi_store::{EncryptedSpool, SnapshotImage};
use std::io::{Read, Write};
// Persisted bootstrap and logical restore, separate from node-bound Raft snapshots.
use crate::{Database, SecurityAudit, TenantEngine};
use kasumi_raft::{BasicNode, Config, RaftGroup, RaftTransport};
use kasumi_store::{
    BackupDestination, EncryptedBackup, KeyProvider, TenantStorageSet, TenantStore, WriteOp,
};
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[path = "backup_restore.rs"]
mod backup_restore;
pub use backup_restore::RestoreSource;
#[path = "bootstrap_publication.rs"]
mod publication;
#[path = "bootstrap_target.rs"]
mod target;
pub use target::{
    MaterializedTargetReplica, TargetMaterializationConfig, VerifiedTargetMaterialization,
    materialize_target_replica, resume_target_materialization,
};

#[path = "bootstrap_target_quorum.rs"]
mod target_quorum;
pub use target_quorum::{TargetReplica, TargetReplicaConfig, open_target_replica};

const NS: &str = "engine.bootstrap";
const CHUNK: usize = 4 << 20;
// Only bootstraps are serialized here, never data operations. A node owns its
// redb file exclusively; startup must register each returned tenant once.
static BOOTSTRAP_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
#[path = "bootstrap_existing_replicated_tests.rs"]
mod existing_replicated_tests;
#[cfg(test)]
#[path = "bootstrap_existing_tests.rs"]
mod existing_tests;

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
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
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
    security_audit.require_admission(&replica.admission)?;
    let target = targets.application().clone();
    if let Some(gate) = target.storage_access().serving_gate() {
        anyhow::ensure!(
            gate.identity().incarnation == replica.incarnation,
            "restore target incarnation differs from its signed serving authority"
        );
    }
    let deadline = source.deadline()?;
    let cancellation = kasumi_query::QueryCancellation::default();
    let _cancel = crate::admission::CancelOnDrop(cancellation.clone());
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
        .run(Box::pin(backup_restore::load_authorized(
            source,
            backup_id,
            &target,
            backup_restore::RestoreAuthorization::Data(&context),
            &security_audit,
            &replica.admission,
            deadline,
            None,
            Some(cancellation.clone()),
        )))
        .await??;
    let source_revision = verified.state.metadata().revision;
    let original = verified.state.metadata();
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
            replica.admission.clone(),
            target.tenant().into(),
            bootstrap.incarnation.clone(),
            None,
        )
        .await?;
    deadline.check()?;
    restore_access(&target, &security_audit, &context).await?;
    let (restored, _gate) = publication::Publication {
        stores: targets.clone(),
        audit: security_audit.clone(),
        contexts: vec![context.clone()],
        cancellation,
        deadline,
    }
    .persist(
        restored,
        _gate,
        serde_json::to_vec(&("replicated", &bootstrap))?,
    )
    .await?;
    let engine = restored.engine;
    engine.install_storage_access(&target)?;
    engine
        .verify_bootstrap_dependencies_owned(replica.admission.clone())
        .await?;
    engine.install_audit_maintenance(&replica.admission)?;
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
        crate::state::validate_limits(&self.initial_limits)?;
        crate::state::validate_policy(&self.initial_policy, &self.initial_limits)?;
        anyhow::ensure!(
            !uuid::Uuid::parse_str(&self.incarnation)?.is_nil(),
            "nil replicated incarnation"
        );
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

fn require_deployment(stores: &TenantStorageSet, binding: &[u8]) -> anyhow::Result<()> {
    stores.check_access()?;
    for store in [stores.application(), stores.custody().store()] {
        anyhow::ensure!(
            store.get("engine.deployment", b"mode")?.as_deref() == Some(binding),
            "required deployment binding is absent or differs"
        );
    }
    Ok(())
}

/// Open a replica for explicit first enrollment. Register its Raft handle with
/// the authenticated peer transport before calling `initialize_replicated` on
/// the lowest initial voter. New learners receive the original installed
/// bootstrap and their own approved node ID. Existing installations use
/// `open_existing_replicated`, which reads that immutable descriptor itself.
pub async fn open_replicated(
    node_id: u64,
    stores: Arc<TenantStorageSet>,
    bootstrap: &ReplicatedBootstrap,
    transport: Arc<dyn RaftTransport>,
    config: Config,
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<Arc<Database>> {
    let (database, _) = open_replicated_inner(
        node_id,
        stores,
        transport,
        config,
        security_audit,
        ReplicaRuntime::FirstEnrollment(bootstrap),
    )
    .await?;
    Ok(database)
}

/// An existing replica and its authenticated immutable genesis descriptor.
/// Operational membership and addresses are recovered independently by Raft.
/// The descriptor can finish an interrupted first enrollment only when Raft's
/// retained state still permits initialization.
pub struct OpenedReplica {
    pub database: Arc<Database>,
    pub bootstrap: ReplicatedBootstrap,
}

/// Reopen an installed replicated database under an exact non-nil incarnation.
/// Neither initial policy/limits nor initial voters are accepted from current
/// runtime configuration. Both encrypted domains must retain identical typed
/// replicated genesis, and its logical bootstrap and physical Raft identity
/// must match before startup. Missing installation state is never provisioned.
pub async fn open_existing_replicated(
    node_id: u64,
    stores: Arc<TenantStorageSet>,
    expected_incarnation: uuid::Uuid,
    transport: Arc<dyn RaftTransport>,
    config: Config,
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<OpenedReplica> {
    let (database, bootstrap) = open_replicated_inner(
        node_id,
        stores,
        transport,
        config,
        security_audit,
        ReplicaRuntime::Existing(expected_incarnation),
    )
    .await?;
    Ok(OpenedReplica {
        database,
        bootstrap: bootstrap.into_owned(),
    })
}

#[derive(Clone, Copy)]
enum ReplicaRuntime<'a> {
    FirstEnrollment(&'a ReplicatedBootstrap),
    Existing(uuid::Uuid),
    #[cfg(any(test, feature = "test-utils"))]
    FixtureEnrollment(&'a ReplicatedBootstrap),
}
impl ReplicaRuntime<'_> {
    fn maintenance(self) -> bool {
        match self {
            Self::FirstEnrollment(_) | Self::Existing(_) => true,
            #[cfg(any(test, feature = "test-utils"))]
            Self::FixtureEnrollment(_) => false,
        }
    }
}

fn installed_replicated_bootstrap(
    stores: &TenantStorageSet,
    expected_incarnation: uuid::Uuid,
) -> anyhow::Result<ReplicatedBootstrap> {
    anyhow::ensure!(
        !expected_incarnation.is_nil(),
        "nil expected replicated incarnation"
    );
    stores.check_access()?;
    let bytes = stores
        .application()
        .get("engine.deployment", b"mode")?
        .ok_or_else(|| anyhow::anyhow!("required deployment binding is absent"))?;
    anyhow::ensure!(
        stores
            .custody()
            .store()
            .get("engine.deployment", b"mode")?
            .as_deref()
            == Some(bytes.as_slice()),
        "required deployment binding is absent or differs across domains"
    );
    let (tag, bootstrap): (String, ReplicatedBootstrap) = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(tag == "replicated", "unsupported replicated deployment tag");
    bootstrap.validate()?;
    anyhow::ensure!(
        bootstrap.incarnation == expected_incarnation.to_string(),
        "installed replicated genesis differs from expected incarnation"
    );
    Ok(bootstrap)
}

async fn open_replicated_inner<'a>(
    node_id: u64,
    stores: Arc<TenantStorageSet>,
    transport: Arc<dyn RaftTransport>,
    config: Config,
    security_audit: Arc<SecurityAudit>,
    runtime: ReplicaRuntime<'a>,
) -> anyhow::Result<(Arc<Database>, Cow<'a, ReplicatedBootstrap>)> {
    let store = stores.application().clone();
    anyhow::ensure!(
        store.storage_access().lifecycle_gate().is_none(),
        "closed target runner required for lifecycle storage"
    );
    anyhow::ensure!(node_id > 0, "node ID must be positive");
    let _gate = BOOTSTRAP_GATE.lock().await;
    reject_retired_serving_open(&stores)?;
    let bootstrap = match runtime {
        ReplicaRuntime::Existing(expected) => {
            Cow::Owned(installed_replicated_bootstrap(&stores, expected)?)
        }
        ReplicaRuntime::FirstEnrollment(bootstrap) => Cow::Borrowed(bootstrap),
        #[cfg(any(test, feature = "test-utils"))]
        ReplicaRuntime::FixtureEnrollment(bootstrap) => Cow::Borrowed(bootstrap),
    };
    // Existing mode validates its descriptor during the single authenticated
    // decode; enrollment validates the independently supplied initial inputs.
    if !matches!(runtime, ReplicaRuntime::Existing(_)) {
        bootstrap.validate()?;
    }
    if let Some(gate) = store.storage_access().serving_gate() {
        anyhow::ensure!(
            gate.identity().incarnation.to_string() == bootstrap.incarnation
                && gate.identity().node.node_id == node_id,
            "replicated node or incarnation differs from its signed serving authority"
        );
    }
    if !matches!(runtime, ReplicaRuntime::Existing(_)) {
        bind_deployment(
            &stores,
            &serde_json::to_vec(&("replicated", bootstrap.as_ref()))?,
        )?;
    }
    let bytes = match load(&store)? {
        Some(bytes) => bytes,
        None => {
            anyhow::ensure!(
                !matches!(runtime, ReplicaRuntime::Existing(_)),
                "replicated bootstrap is not initialized"
            );
            let engine = TenantEngine::new(
                store.tenant().into(),
                bootstrap.incarnation.clone(),
                bootstrap.initial_policy.clone(),
                bootstrap.initial_limits.clone(),
            )?;
            let bytes = engine.logical_snapshot(store.scratch_disk())?;
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
    if matches!(runtime, ReplicaRuntime::Existing(_)) {
        let installed = kasumi_raft::ControlLog::installed(stores.custody().clone())?
            .ok_or_else(|| anyhow::anyhow!("replicated consensus identity is not initialized"))?;
        anyhow::ensure!(
            installed.node_id() == node_id
                && installed.group() == format!("{}/{}", store.tenant(), bootstrap.incarnation),
            "replicated consensus identity differs from installed configuration"
        );
    }
    engine.install_storage_access(&store)?;
    engine
        .verify_bootstrap_dependencies_owned(security_audit.admission().clone())
        .await?;
    if runtime.maintenance() {
        engine.install_audit_maintenance(security_audit.admission())?;
    }
    let group = RaftGroup::open(
        node_id,
        format!("{}/{}", store.tenant(), bootstrap.incarnation),
        stores.clone(),
        engine.clone(),
        transport,
        config,
    )
    .await?;
    let database = if runtime.maintenance() {
        Database::new_with_admission(
            engine,
            group,
            store,
            security_audit.admission().clone(),
            security_audit,
        )
    } else {
        Database::new(engine, group, store, security_audit)
    };
    Ok((database, bootstrap))
}

/// Explicit first creation, never a partition fallback. Only the designated
/// bootstrap voter initializes, and an existing membership is left untouched.
pub async fn initialize_replicated(
    database: &Database,
    bootstrap: &ReplicatedBootstrap,
) -> anyhow::Result<()> {
    bootstrap.validate()?;
    anyhow::ensure!(
        database.store().storage_access().lifecycle_gate().is_none(),
        "closed target initialization required"
    );
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
    bytes: u64,
    chunks: u64,
    digest: String,
}

fn load(store: &TenantStore) -> anyhow::Result<Option<SnapshotImage>> {
    let Some(bytes) = store.get(NS, b"manifest")? else {
        return Ok(None);
    };
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        manifest.format == 2
            && manifest.bytes > 0
            && manifest.chunks == manifest.bytes.div_ceil(CHUNK as u64),
        "invalid bootstrap manifest"
    );
    let mut spool = EncryptedSpool::new(store.scratch_disk(), manifest.bytes)?;
    for i in 0..manifest.chunks {
        let bytes = store
            .get(NS, &i.to_be_bytes())?
            .ok_or_else(|| anyhow::anyhow!("incomplete bootstrap"))?;
        anyhow::ensure!(
            bytes.len() == (manifest.bytes - spool.len()).min(CHUNK as u64) as usize,
            "invalid bootstrap chunk length"
        );
        spool.write_all(&bytes)?;
    }
    let snapshot = SnapshotImage::freeze(spool)?;
    anyhow::ensure!(
        snapshot.sha256() == manifest.digest,
        "bootstrap digest mismatch"
    );
    Ok(Some(snapshot))
}

fn validate_bootstrap_control(
    stores: &TenantStorageSet,
    bytes: &SnapshotImage,
) -> anyhow::Result<()> {
    stores.check_access()?;
    let expected = serde_json::to_vec(bytes.sha256())?;
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

fn persist_new(stores: &TenantStorageSet, bytes: &SnapshotImage) -> anyhow::Result<()> {
    persist_new_checked(stores, bytes, || stores.check_access())
}

fn persist_new_checked(
    stores: &TenantStorageSet,
    bytes: &SnapshotImage,
    mut check: impl FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    check()?;
    let store = stores.application();
    anyhow::ensure!(
        store.get(NS, b"manifest")?.is_none()
            && stores
                .custody()
                .store()
                .get("raft.meta", b"node_id")?
                .is_none(),
        "target tenant already initialized; restore never overwrites it"
    );
    let mut reader = bytes.reader();
    let chunks = bytes.len().div_ceil(CHUNK as u64);
    for i in 0..chunks {
        check()?;
        let mut chunk = vec![0; (bytes.len() - i * CHUNK as u64).min(CHUNK as u64) as usize];
        reader.read_exact(&mut chunk)?;
        check()?;
        store.write_batch(&[WriteOp::put(NS, i.to_be_bytes(), chunk)])?;
        check()?;
    }
    let manifest = Manifest {
        format: 2,
        bytes: bytes.len(),
        chunks,
        digest: bytes.sha256().to_owned(),
    };
    let encoded = serde_json::to_vec(&manifest)?;
    check()?;
    stores.write_batch(
        &[WriteOp::put(NS, b"manifest", encoded)],
        &[WriteOp::put(
            "raft.meta",
            b"application_bootstrap_sha256",
            serde_json::to_vec(&manifest.digest)?,
        )],
    )?;
    check()
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
    open_local_inner(
        stores,
        initial_policy,
        initial_limits,
        security_audit,
        None,
        LocalRuntime::Production(None),
    )
    .await
}

/// Reopen an initialized local deployment using only its authenticated bootstrap.
/// Missing deployment, bootstrap or custody commitment is corruption, never a
/// request to generate a new incarnation or install default policy and limits.
pub async fn open_existing_local(
    stores: Arc<TenantStorageSet>,
    security_audit: Arc<SecurityAudit>,
    expected_incarnation: uuid::Uuid,
) -> anyhow::Result<Arc<Database>> {
    anyhow::ensure!(!expected_incarnation.is_nil(), "nil local incarnation");
    anyhow::ensure!(
        stores
            .application()
            .storage_access()
            .serving_gate()
            .is_none(),
        "independent serving authority requires replicated storage; local downgrade is forbidden"
    );
    let _gate = BOOTSTRAP_GATE.lock().await;
    reject_retired_serving_open(&stores)?;
    require_deployment(&stores, b"local-v1")?;
    let bytes = load(stores.application())?
        .ok_or_else(|| anyhow::anyhow!("local bootstrap is not initialized"))?;
    start(
        stores,
        &bytes,
        LocalRuntime::Production(None),
        security_audit,
        Some(expected_incarnation),
    )
    .await
}

/// Explicit genesis identity for local control storage and local test fixtures.
/// It never accepts serving-authorized application storage or changes an
/// existing incarnation. Remote production tenants remain replicated only.
pub async fn open_local_with_incarnation(
    stores: Arc<TenantStorageSet>,
    initial_policy: Policy,
    initial_limits: Limits,
    security_audit: Arc<SecurityAudit>,
    incarnation: uuid::Uuid,
) -> anyhow::Result<Arc<Database>> {
    anyhow::ensure!(!incarnation.is_nil(), "nil local incarnation");
    open_local_inner(
        stores,
        initial_policy,
        initial_limits,
        security_audit,
        Some(incarnation),
        LocalRuntime::Production(None),
    )
    .await
}

/// Open only an explicit encrypted application fixture using one paired clock.
/// The supplied epoch also creates the test's original finite credentials; this
/// does not replace their observations or alter any production time source.
#[cfg(any(test, feature = "test-utils"))]
pub async fn open_fixture_with_epoch_clock(
    stores: Arc<TenantStorageSet>,
    initial_policy: Policy,
    initial_limits: Limits,
    security_audit: Arc<SecurityAudit>,
    admission: Arc<crate::admission::NodeAdmission>,
    clock: Arc<kasumi_clock::EpochClock>,
) -> anyhow::Result<Arc<Database>> {
    anyhow::ensure!(
        matches!(
            stores.application().storage_access().purpose(),
            kasumi_store::StoragePurpose::LocalFixture
        ),
        "fixture clock cannot open production storage"
    );
    clock.now_ms()?;
    open_local_inner(
        stores,
        initial_policy,
        initial_limits,
        security_audit,
        None,
        LocalRuntime::Fixture { admission, clock },
    )
    .await
}

#[cfg(any(test, feature = "test-utils"))]
#[path = "bootstrap_fixtures.rs"]
pub(crate) mod fixtures;

enum LocalRuntime {
    Production(Option<Arc<crate::admission::NodeAdmission>>),
    #[cfg(any(test, feature = "test-utils"))]
    FixtureDefault,
    #[cfg(any(test, feature = "test-utils"))]
    Fixture {
        admission: Arc<crate::admission::NodeAdmission>,
        clock: Arc<kasumi_clock::EpochClock>,
    },
}

async fn open_local_inner(
    stores: Arc<TenantStorageSet>,
    initial_policy: Policy,
    initial_limits: Limits,
    security_audit: Arc<SecurityAudit>,
    incarnation: Option<uuid::Uuid>,
    runtime: LocalRuntime,
) -> anyhow::Result<Arc<Database>> {
    let store = stores.application().clone();
    anyhow::ensure!(
        store.storage_access().serving_gate().is_none(),
        "independent serving authority requires replicated storage; local downgrade is forbidden"
    );
    let _gate = BOOTSTRAP_GATE.lock().await;
    reject_retired_serving_open(&stores)?;
    bind_deployment(&stores, b"local-v1")?;
    let bytes = match load(&store)? {
        Some(bytes) => bytes,
        None => {
            let engine = TenantEngine::new(
                store.tenant().into(),
                incarnation.unwrap_or_else(uuid::Uuid::new_v4).to_string(),
                initial_policy,
                initial_limits,
            )?;
            let bytes = engine.logical_snapshot(store.scratch_disk())?;
            persist_new(&stores, &bytes)?;
            bytes
        }
    };
    start(stores, &bytes, runtime, security_audit, incarnation).await
}

async fn start(
    stores: Arc<TenantStorageSet>,
    bytes: &SnapshotImage,
    runtime: LocalRuntime,
    security_audit: Arc<SecurityAudit>,
    expected_incarnation: Option<uuid::Uuid>,
) -> anyhow::Result<Arc<Database>> {
    validate_bootstrap_control(&stores, bytes)?;
    let engine = Arc::new(TenantEngine::from_bootstrap(
        stores.application().tenant(),
        bytes,
    )?);
    if let Some(expected) = expected_incarnation {
        anyhow::ensure!(
            engine.generation()?.state.incarnation == expected.to_string(),
            "local incarnation differs from installed identity"
        );
    }
    if let kasumi_store::StoragePurpose::Standalone {
        tenant,
        incarnation,
        ..
    } = stores.application().storage_access().purpose()
    {
        let generation = engine.generation()?;
        anyhow::ensure!(
            generation.state.tenant == *tenant
                && generation.state.incarnation == incarnation.to_string(),
            "local bootstrap differs from authenticated standalone identity"
        );
    }
    start_prepared(stores, engine, runtime, security_audit).await
}

async fn start_prepared(
    stores: Arc<TenantStorageSet>,
    engine: Arc<TenantEngine>,
    runtime: LocalRuntime,
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<Arc<Database>> {
    let store = stores.application().clone();
    engine.install_storage_access(&store)?;
    let admission = match &runtime {
        LocalRuntime::Production(Some(admission)) => admission.clone(),
        LocalRuntime::Production(None) => security_audit.admission().clone(),
        #[cfg(any(test, feature = "test-utils"))]
        LocalRuntime::FixtureDefault => security_audit.admission().clone(),
        #[cfg(any(test, feature = "test-utils"))]
        LocalRuntime::Fixture { admission, .. } => admission.clone(),
    };
    engine
        .verify_bootstrap_dependencies_owned(admission.clone())
        .await?;
    if matches!(runtime, LocalRuntime::Production(_)) {
        engine.install_audit_maintenance(&admission)?;
    }
    let incarnation = engine.generation()?.state.incarnation.clone();
    let group = RaftGroup::local(
        1,
        format!("{}/{incarnation}", store.tenant()),
        stores.clone(),
        engine.clone(),
    )
    .await?;
    Ok(match runtime {
        LocalRuntime::Production(_) => {
            Database::new_with_admission(engine, group, store, admission, security_audit)
        }
        #[cfg(any(test, feature = "test-utils"))]
        LocalRuntime::FixtureDefault => Database::new(engine, group, store, security_audit),
        #[cfg(any(test, feature = "test-utils"))]
        LocalRuntime::Fixture { admission, clock } => Database::new_fixture_with_epoch_clock(
            engine,
            group,
            store,
            admission,
            security_audit,
            clock,
        )?,
    })
}

/// Exact independently authorized source and target for one local materialization.
/// Callers choose the target incarnation before obtaining its credential. The
/// source purpose is retained for explicit historical archive authorization.
pub struct LocalRestoreRequest {
    pub checkpoint: FullBackupCheckpoint,
    pub target_incarnation: uuid::Uuid,
    pub source_context: RequestContext,
    pub target_context: RequestContext,
    pub source_purpose: kasumi_store::StoragePurpose,
}

/// Verify a complete encrypted graph and publish its bounded staged bootstrap
/// into an empty standalone target. Source and target credentials remain separate
/// throughout verification, persistence, and the target's mandatory audit.
pub async fn restore_local(
    source: &RestoreSource,
    targets: Arc<TenantStorageSet>,
    request: LocalRestoreRequest,
    admission: Arc<crate::admission::NodeAdmission>,
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<Arc<Database>> {
    request.checkpoint.validate()?;
    security_audit.require_admission(&admission)?;
    let incarnation = request.target_incarnation;
    let backup_id = request.checkpoint.backup_id;
    request
        .source_context
        .authorization
        .require_database(&request.checkpoint.source_incarnation)?;
    request
        .target_context
        .authorization
        .require_database(&incarnation.to_string())?;
    anyhow::ensure!(
        !incarnation.is_nil() && incarnation.to_string() != request.checkpoint.source_incarnation,
        "local restore requires a fresh target incarnation"
    );
    let target = targets.application().clone();
    anyhow::ensure!(
        target.storage_access().serving_gate().is_none(),
        "independent restore authority requires replicated storage; local downgrade is forbidden"
    );
    let deadline = source.deadline()?;
    let cancellation = kasumi_query::QueryCancellation::default();
    let _cancel = crate::admission::CancelOnDrop(cancellation.clone());
    let _gate = deadline.run(BOOTSTRAP_GATE.lock()).await?;
    let authorization = backup_restore::RestoreAuthorization::Local(&request);
    authorization.check_access(&target, &security_audit).await?;
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
        .run(Box::pin(backup_restore::load_authorized(
            source,
            backup_id,
            &target,
            authorization,
            &security_audit,
            &admission,
            deadline,
            None,
            Some(cancellation.clone()),
        )))
        .await??;
    anyhow::ensure!(
        verified.checkpoint == request.checkpoint,
        "verified local backup differs from exact checkpoint"
    );
    let source_revision = verified.state.metadata().revision;
    let original = verified.state.metadata();
    anyhow::ensure!(
        !incarnation.is_nil() && incarnation.to_string() != original.incarnation,
        "restore requires a fresh database incarnation"
    );
    let restored = verified
        .into_genesis(
            deadline,
            admission.clone(),
            target.tenant().into(),
            incarnation.to_string(),
            None,
        )
        .await?;
    deadline.check()?;
    backup_restore::RestoreAuthorization::Local(&request)
        .check_access(&target, &security_audit)
        .await?;
    let (restored, _gate) = publication::Publication {
        stores: targets.clone(),
        audit: security_audit.clone(),
        contexts: vec![
            request.source_context.clone(),
            request.target_context.clone(),
        ],
        cancellation,
        deadline,
    }
    .persist(restored, _gate, b"local-v1".to_vec())
    .await?;
    let database = start_prepared(
        targets,
        restored.engine,
        LocalRuntime::Production(Some(admission)),
        security_audit,
    )
    .await?;
    database.install_archive_destination(
        source.destination_alias.clone(),
        source.destination.clone(),
    )?;
    if let Err(error) = database
        .maintenance_audit(
            request.target_context,
            "restore",
            "started",
            source_revision,
        )
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

fn reject_retired_serving_open(stores: &TenantStorageSet) -> anyhow::Result<()> {
    if let Some(control) = kasumi_raft::ControlLog::installed(stores.custody().clone())? {
        anyhow::ensure!(
            !control.is_retired()?,
            "source is retired; use the installed custody-only opener"
        );
    }
    Ok(())
}

/// Admission estimate from bounded authenticated bootstrap/snapshot manifests.
/// It does not deserialize resident application state or authorize serving.
pub fn recovery_workspace_bytes(stores: &TenantStorageSet) -> anyhow::Result<u64> {
    let bytes = stores
        .application()
        .get(NS, b"manifest")?
        .ok_or_else(|| anyhow::anyhow!("bootstrap manifest absent"))?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        manifest.format == 2
            && manifest.bytes > 0
            && manifest.chunks == manifest.bytes.div_ceil(CHUNK as u64),
        "invalid bootstrap resource manifest"
    );
    let snapshot = kasumi_raft::recovery_snapshot_bytes(stores)?;
    Ok(manifest
        .bytes
        .saturating_add(snapshot)
        .saturating_mul(4)
        .saturating_add(4 << 20))
}

#[path = "bootstrap_target_serving.rs"]
pub(crate) mod target_serving;
