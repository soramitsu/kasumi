use kasumi_store::{
    APPLICATION_BOOTSTRAP_CHUNK_BYTES as CHUNK,
    APPLICATION_BOOTSTRAP_MANIFEST_BYTES as MAX_BOOTSTRAP_MANIFEST_BYTES,
    ApplicationBootstrapManifest, EncryptedSpool, LOCAL_ENROLLMENT_GENESIS_KEY, SnapshotImage,
};
use std::io::{Read, Write};
// Persisted bootstrap and logical restore, separate from node-bound Raft snapshots.
use crate::service::construction::DatabaseConstruction;
use crate::{Database, SecurityAudit, TenantEngine};
use kasumi_raft::{BasicNode, Config, RaftTransport};
use kasumi_store::{
    AdmittedDeploymentBinding, BackupDestination, EncryptedBackup, KeyProvider,
    TenantStorageReadView, TenantStorageSet, TenantStore, WriteOp,
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
#[path = "deployment_preflight.rs"]
mod deployment_preflight;
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
pub use target_quorum::{
    TargetReplica, TargetReplicaConfig, TargetReplicaStartup, open_target_replica,
};

#[path = "bootstrap_control_genesis.rs"]
mod control_genesis;
pub use control_genesis::{ControlGenesis, ControlLifecycleGenesis, ReplicatedGenesis};

const NS: &str = "engine.bootstrap";
// Only bootstraps are serialized here, never data operations. A node owns its
// database file exclusively; startup must register each returned tenant once.
static BOOTSTRAP_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
#[path = "bootstrap_cold_file_tests.rs"]
mod cold_file_tests;
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
    pub genesis: ReplicatedGenesis,
    pub incarnation: String,
    pub initial_policy: Policy,
    pub initial_limits: Limits,
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
    pub voters: BTreeMap<u64, ReplicaPlacement>,
}

impl ReplicatedBootstrap {
    pub fn validate(&self) -> anyhow::Result<()> {
        self.genesis.validate(&self.incarnation)?;
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
            if let ReplicatedGenesis::Control(control) = &self.genesis {
                let node =
                    control.topology.nodes.get(id).ok_or_else(|| {
                        anyhow::anyhow!("Control genesis initial voter is missing")
                    })?;
                anyhow::ensure!(
                    url::Url::parse(&placement.address)?
                        .origin()
                        .ascii_serialization()
                        == node.endpoint
                        && placement.failure_domain == node.failure_domain,
                    "Control genesis voter identity differs from replicated placement"
                );
            }
        }
        Ok(())
    }
}

fn bind_deployment(stores: &TenantStorageSet, binding: &[u8]) -> anyhow::Result<()> {
    const DEPLOYMENT: &str = "engine.deployment";
    match stores.deployment_binding()? {
        Some(existing) => anyhow::ensure!(
            existing.as_bytes() == binding,
            "deployment bootstrap differs from persisted configuration"
        ),
        None => {
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
    }
    Ok(())
}

fn require_deployment(stores: &TenantStorageSet, binding: &[u8]) -> anyhow::Result<()> {
    let installed = stores.deployment_binding()?;
    if installed.as_ref().map(|value| value.as_bytes()) != Some(binding) {
        return Err(Error::new(
            ErrorCode::Corruption,
            "required deployment binding is absent or differs",
        )
        .into());
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
) -> std::result::Result<Arc<Database>, crate::SnapshotFailure> {
    let (database, _, _) = open_replicated_inner(
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
    verified_identity: VerifiedInitialBootstrap,
}

struct VerifiedInitialBootstrap {
    // Retain the admitted exact descriptor bytes, not a reconstructed copy.
    binding: AdmittedDeploymentBinding,
    snapshot_sha256: String,
}

impl OpenedReplica {
    pub fn verified_binding(&self) -> &[u8] {
        self.verified_identity.binding.as_bytes()
    }

    pub fn verified_snapshot_sha256(&self) -> &str {
        &self.verified_identity.snapshot_sha256
    }
}

/// Reopen an installed replicated database under an exact non-nil incarnation.
/// Neither initial policy/limits nor initial voters are accepted from current
/// runtime configuration. Both encrypted domains must retain identical typed
/// replicated genesis, and its logical bootstrap and physical Raft identity
/// must match before startup. Missing installation state is never provisioned.
pub async fn open_existing_replicated<'a>(
    node_id: u64,
    stores: Arc<TenantStorageSet>,
    expected_incarnation: impl Into<ExistingIncarnation<'a>>,
    transport: Arc<dyn RaftTransport>,
    config: Config,
    security_audit: Arc<SecurityAudit>,
) -> std::result::Result<OpenedReplica, crate::SnapshotFailure> {
    let (database, bootstrap, verified_identity) = open_replicated_inner(
        node_id,
        stores,
        transport,
        config,
        security_audit,
        ReplicaRuntime::Existing(expected_incarnation.into()),
    )
    .await?;
    Ok(OpenedReplica {
        database,
        bootstrap: bootstrap.into_owned(),
        verified_identity: verified_identity.expect("existing replica has verified identity"),
    })
}

#[derive(Clone, Copy)]
enum ReplicaRuntime<'a> {
    FirstEnrollment(&'a ReplicatedBootstrap),
    Existing(ExistingIncarnation<'a>),
    #[cfg(any(test, feature = "test-utils"))]
    FixtureEnrollment(&'a ReplicatedBootstrap),
    #[cfg(any(test, feature = "test-utils"))]
    FixtureEpochEnrollment(&'a ReplicatedBootstrap, &'a Arc<kasumi_clock::EpochClock>),
}
impl ReplicaRuntime<'_> {
    fn maintenance(self) -> bool {
        match self {
            Self::FirstEnrollment(_) | Self::Existing(_) => true,
            #[cfg(any(test, feature = "test-utils"))]
            Self::FixtureEnrollment(_) | Self::FixtureEpochEnrollment(_, _) => false,
        }
    }
}

fn decode_current_replicated_deployment(bytes: &[u8]) -> anyhow::Result<ReplicatedBootstrap> {
    let _inventory = deployment_preflight::inspect_current_deployment(
        bytes,
        kasumi_store::MAX_DEPLOYMENT_BINDING_BYTES,
    )
    .map_err(anyhow::Error::msg)?;
    let (tag, bootstrap): (String, ReplicatedBootstrap) = serde_json::from_slice(bytes)?;
    anyhow::ensure!(tag == "replicated", "unsupported replicated deployment tag");
    bootstrap.validate()?;
    crate::current_json::require_current_writer_bytes(
        bytes,
        &("replicated", &bootstrap),
        "replicated deployment binding",
    )?;
    Ok(bootstrap)
}

fn decode_current_target_deployment(
    stores: &TenantStorageSet,
) -> anyhow::Result<ReplicatedBootstrap> {
    let binding = stores
        .deployment_binding()?
        .ok_or_else(|| anyhow::anyhow!("required deployment binding is absent"))?;
    decode_current_replicated_deployment(binding.as_bytes())
}

fn installed_replicated_bootstrap(
    view: &TenantStorageReadView,
    expected_incarnation: uuid::Uuid,
) -> anyhow::Result<(ReplicatedBootstrap, AdmittedDeploymentBinding)> {
    anyhow::ensure!(
        !expected_incarnation.is_nil(),
        "nil expected replicated incarnation"
    );
    let bytes = view
        .deployment_binding()?
        .ok_or_else(|| anyhow::anyhow!("required deployment binding is absent"))?;
    let bootstrap = decode_current_replicated_deployment(bytes.as_bytes())?;
    anyhow::ensure!(
        bootstrap.incarnation == expected_incarnation.to_string(),
        "installed replicated genesis differs from expected incarnation"
    );
    Ok((bootstrap, bytes))
}

async fn open_replicated_inner<'a>(
    node_id: u64,
    stores: Arc<TenantStorageSet>,
    transport: Arc<dyn RaftTransport>,
    config: Config,
    security_audit: Arc<SecurityAudit>,
    runtime: ReplicaRuntime<'a>,
) -> std::result::Result<
    (
        Arc<Database>,
        Cow<'a, ReplicatedBootstrap>,
        Option<VerifiedInitialBootstrap>,
    ),
    crate::SnapshotFailure,
> {
    let construction = match runtime {
        #[cfg(any(test, feature = "test-utils"))]
        ReplicaRuntime::FixtureEpochEnrollment(_, clock) => {
            DatabaseConstruction::with_fixture_control_clock(
                stores.clone(),
                security_audit.clone(),
                clock.clone(),
            )
        }
        _ => DatabaseConstruction::new(stores.clone(), security_audit.clone()),
    }?;
    let store = stores.application().clone();
    crate::SnapshotFailure::ordinary(|| {
        anyhow::ensure!(
            store.storage_access().lifecycle_gate().is_none(),
            "closed target runner required for lifecycle storage"
        );
        Ok(())
    })?;
    crate::SnapshotFailure::ordinary(|| {
        anyhow::ensure!(node_id > 0, "node ID must be positive");
        Ok(())
    })?;
    let _gate = BOOTSTRAP_GATE.lock().await;
    reject_retired_serving_open(&stores)?;
    let existing_view = matches!(runtime, ReplicaRuntime::Existing(_))
        .then(|| stores.read_view())
        .transpose()?;
    let (bootstrap, installed_binding) = match runtime {
        ReplicaRuntime::Existing(expected) => {
            let (bootstrap, binding) = installed_replicated_bootstrap(
                existing_view.as_ref().expect("existing read view"),
                expected.incarnation,
            )?;
            (Cow::Owned(bootstrap), Some(binding))
        }
        ReplicaRuntime::FirstEnrollment(bootstrap) => (Cow::Borrowed(bootstrap), None),
        #[cfg(any(test, feature = "test-utils"))]
        ReplicaRuntime::FixtureEnrollment(bootstrap)
        | ReplicaRuntime::FixtureEpochEnrollment(bootstrap, _) => (Cow::Borrowed(bootstrap), None),
    };
    // Existing mode validates its descriptor during the single authenticated
    // decode; enrollment validates the independently supplied initial inputs.
    if !matches!(runtime, ReplicaRuntime::Existing(_)) {
        bootstrap.validate()?;
    }
    bootstrap.genesis.require_domain(&store)?;
    if let Some(gate) = store.storage_access().serving_gate() {
        crate::SnapshotFailure::ordinary(|| {
            anyhow::ensure!(
                gate.identity().incarnation.to_string() == bootstrap.incarnation
                    && gate.identity().node.node_id == node_id,
                "replicated node or incarnation differs from its signed serving authority"
            );
            Ok(())
        })?;
    }
    if !matches!(runtime, ReplicaRuntime::Existing(_)) {
        bind_deployment(
            &stores,
            &serde_json::to_vec(&("replicated", bootstrap.as_ref()))?,
        )?;
    }
    let loaded = match existing_view.as_ref() {
        Some(view) => load_at(view, store.scratch_disk())?,
        None => load(&store)?,
    };
    let bytes = match loaded {
        Some(bytes) => bytes,
        None => {
            crate::SnapshotFailure::ordinary(|| {
                anyhow::ensure!(
                    !matches!(runtime, ReplicaRuntime::Existing(_)),
                    "replicated bootstrap is not initialized"
                );
                Ok(())
            })?;
            let engine = bootstrap.genesis.engine(store.tenant(), &bootstrap)?;
            let bytes = engine.logical_snapshot(store.scratch_disk())?;
            let identity = kasumi_raft::initial_storage_identity(
                node_id,
                &format!("{}/{}", store.tenant(), bootstrap.incarnation),
            )?;
            persist_new_checked(&stores, &bytes, identity, || stores.check_access())?;
            bytes
        }
    };
    bootstrap.genesis.verify_image(&store, &bootstrap, &bytes)?;
    if let Some(view) = existing_view.as_ref() {
        validate_bootstrap_control_at(view, &bytes)?;
    } else {
        validate_bootstrap_control(&stores, &bytes)?;
    }
    let installed_control = existing_view
        .as_ref()
        .map(kasumi_raft::ControlLog::installed_identity_at)
        .transpose()?;
    let verified_identity = installed_binding.map(|binding| VerifiedInitialBootstrap {
        binding,
        // load_at checked the manifest against this frozen image while the
        // descriptor and custody commitment were held by the same view.
        snapshot_sha256: bytes.sha256().to_owned(),
    });
    drop(existing_view);
    let engine = Arc::new(TenantEngine::from_bootstrap(store.tenant(), &bytes)?);
    if let ReplicaRuntime::Existing(ExistingIncarnation {
        recovery: Some(workspace),
        ..
    }) = runtime
    {
        workspace.install(&engine, &store)?;
    }
    let generation = engine.generation()?;
    crate::SnapshotFailure::ordinary(|| {
        anyhow::ensure!(
            generation.state.incarnation == bootstrap.incarnation,
            "replicated incarnation differs from bootstrap"
        );
        Ok(())
    })?;
    crate::SnapshotFailure::ordinary(|| {
        anyhow::ensure!(
            canonical_digest(&generation.state.policy)?
                == canonical_digest(&bootstrap.initial_policy)?,
            "replicated initial policy differs from bootstrap image"
        );
        Ok(())
    })?;
    crate::SnapshotFailure::ordinary(|| {
        anyhow::ensure!(
            canonical_digest(&generation.state.limits)?
                == canonical_digest(&bootstrap.initial_limits)?,
            "replicated initial limits differ from bootstrap image"
        );
        Ok(())
    })?;
    if let Some(installed) = installed_control {
        let (installed_node_id, installed_group) = installed
            .ok_or_else(|| anyhow::anyhow!("replicated consensus identity is not initialized"))?;
        crate::SnapshotFailure::ordinary(|| {
            anyhow::ensure!(
                installed_node_id == node_id
                    && installed_group == format!("{}/{}", store.tenant(), bootstrap.incarnation),
                "replicated consensus identity differs from installed configuration"
            );
            Ok(())
        })?;
    }
    engine.install_storage_access(&store)?;
    engine
        .verify_bootstrap_dependencies_owned(security_audit.admission().clone())
        .await?;
    if runtime.maintenance() {
        engine.install_audit_maintenance(security_audit.admission())?;
    }
    let database = construction
        .start_replicated(
            engine,
            &bytes,
            node_id,
            format!("{}/{}", store.tenant(), bootstrap.incarnation),
            transport,
            kasumi_raft::RaftGroupConfig {
                raft: config,
                limits: kasumi_raft::RaftLimits::default(),
            },
        )
        .await?;
    Ok((database, bootstrap, verified_identity))
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
    let installed = database
        .stores()
        .deployment_binding()?
        .ok_or_else(|| anyhow::anyhow!("replicated deployment binding is absent"))?;
    anyhow::ensure!(
        installed.as_bytes() == binding,
        "replicated bootstrap does not match this database"
    );
    let group = database.raft_group();
    if group.raft().is_initialized().await? {
        return Ok(());
    }
    let id = group.node_id();
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

/// Compare bounded typed genesis fields without materializing another JSON
/// copy while the decoded bootstrap image is resident.
fn canonical_digest<T: Serialize>(value: &T) -> anyhow::Result<[u8; 32]> {
    struct HashWriter(Sha256);
    impl Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter(Sha256::new());
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.0.finalize().into())
}

fn read_current_manifest(
    store: &TenantStore,
) -> anyhow::Result<Option<ApplicationBootstrapManifest>> {
    store
        .get_bounded(NS, b"manifest", MAX_BOOTSTRAP_MANIFEST_BYTES)?
        .map(|bytes| ApplicationBootstrapManifest::decode(&bytes))
        .transpose()
}

fn read_current_manifest_at(
    view: &TenantStorageReadView,
) -> anyhow::Result<Option<ApplicationBootstrapManifest>> {
    view.application_get(NS, b"manifest", MAX_BOOTSTRAP_MANIFEST_BYTES)?
        .map(|bytes| ApplicationBootstrapManifest::decode(&bytes))
        .transpose()
}

/// Decode the immutable manifest from the same native generation as the
/// deployment pair and custody commitment held by this view.
pub fn persisted_bootstrap_digest_at(view: &TenantStorageReadView) -> anyhow::Result<String> {
    read_current_manifest_at(view)?
        .map(|manifest| manifest.digest)
        .ok_or_else(|| anyhow::anyhow!("bootstrap manifest absent"))
}

/// Read the initial snapshot digest from the current immutable bootstrap row.
/// Startup, materialization and server enrollment all use this exact decoder.
pub fn persisted_bootstrap_digest(store: &TenantStore) -> anyhow::Result<String> {
    read_current_manifest(store)?
        .map(|manifest| manifest.digest)
        .ok_or_else(|| anyhow::anyhow!("bootstrap manifest absent"))
}

pub(crate) fn load(store: &TenantStore) -> anyhow::Result<Option<SnapshotImage>> {
    let Some(manifest) = read_current_manifest(store)? else {
        return Ok(None);
    };
    load_chunks(&manifest, store.scratch_disk(), |key| {
        store.get_bounded(NS, key, CHUNK)
    })
    .map(Some)
}

fn load_at(
    view: &TenantStorageReadView,
    scratch_disk: &Arc<kasumi_store::ScratchDisk>,
) -> anyhow::Result<Option<SnapshotImage>> {
    let Some(manifest) = read_current_manifest_at(view)? else {
        return Ok(None);
    };
    load_chunks(&manifest, scratch_disk, |key| {
        view.application_get(NS, key, CHUNK)
    })
    .map(Some)
}

fn load_chunks(
    manifest: &ApplicationBootstrapManifest,
    scratch_disk: &Arc<kasumi_store::ScratchDisk>,
    mut get: impl FnMut(&[u8]) -> anyhow::Result<Option<kasumi_store::PlaintextValue>>,
) -> anyhow::Result<SnapshotImage> {
    // The authenticated extent is known, just as it is for a Raft snapshot.
    // Reserve ciphertext space once before reading the immutable chunks.
    let mut spool = EncryptedSpool::new(scratch_disk, manifest.bytes)?;
    spool.reserve(manifest.bytes)?;
    for i in 0..manifest.chunks {
        let bytes =
            get(&i.to_be_bytes())?.ok_or_else(|| anyhow::anyhow!("incomplete bootstrap"))?;
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
    Ok(snapshot)
}

fn validate_bootstrap_control_at(
    view: &TenantStorageReadView,
    bytes: &SnapshotImage,
) -> anyhow::Result<()> {
    let expected = serde_json::to_vec(bytes.sha256())?;
    anyhow::ensure!(
        view.custody_get("raft.meta", b"application_bootstrap_sha256", 256)?
            .as_deref()
            == Some(expected.as_slice()),
        "application bootstrap/control identity differs"
    );
    Ok(())
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

#[cfg(test)]
fn persist_new(
    stores: &TenantStorageSet,
    bytes: &SnapshotImage,
) -> std::result::Result<(), crate::SnapshotFailure> {
    let engine = TenantEngine::from_bootstrap(stores.application().tenant(), bytes)?;
    let incarnation = engine.generation()?.state.incarnation.clone();
    let identity = kasumi_raft::initial_storage_identity(
        1,
        &format!("{}/{}", stores.application().tenant(), incarnation),
    )?;
    Ok(persist_new_checked(stores, bytes, identity, || {
        stores.check_access()
    })?)
}

fn persist_new_checked(
    stores: &TenantStorageSet,
    bytes: &SnapshotImage,
    identity: impl IntoIterator<Item = WriteOp>,
    mut check: impl FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    check()?;
    let store = stores.application();
    anyhow::ensure!(
        store
            .get_bounded(NS, b"manifest", MAX_BOOTSTRAP_MANIFEST_BYTES)?
            .is_none()
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
    let manifest = ApplicationBootstrapManifest {
        format: 2,
        bytes: bytes.len(),
        chunks,
        digest: bytes.sha256().to_owned(),
    };
    let encoded = serde_json::to_vec(&manifest)?;
    check()?;
    let mut custody_ops = vec![WriteOp::put(
        "raft.meta",
        b"application_bootstrap_sha256",
        serde_json::to_vec(&manifest.digest)?,
    )];
    custody_ops.extend(identity);
    stores.write_batch(&[WriteOp::put(NS, b"manifest", encoded)], &custody_ops)?;
    check()
}

/// Open a local tenant without a Raft runtime. On reopen, its persisted bootstrap is authoritative;
/// caller-supplied creation defaults cannot change existing permissions or limits.
/// The node must own exactly one live Database instance for each TenantStore.
pub async fn open_local(
    stores: Arc<TenantStorageSet>,
    initial_policy: Policy,
    initial_limits: Limits,
    security_audit: Arc<SecurityAudit>,
) -> std::result::Result<Arc<Database>, crate::SnapshotFailure> {
    open_local_inner(
        DatabaseConstruction::new(stores, security_audit)?,
        initial_policy,
        initial_limits,
        None,
        LocalRuntime::Production,
    )
    .await
}

/// The audit facade and its snapshot startup slot travel together until the
/// local group takes ownership. Enrollment can claim the slot before recording
/// its permanent creation intent or initializing either catalog.
pub struct LocalDatabaseStartup {
    audit: Arc<SecurityAudit>,
    buffers: Option<Arc<kasumi_raft::SnapshotBufferOwner>>,
}

impl LocalDatabaseStartup {
    pub fn reserve(audit: Arc<SecurityAudit>) -> anyhow::Result<Self> {
        let buffers = audit.admission().snapshot_buffer_owner()?;
        Ok(Self {
            audit,
            buffers: Some(buffers),
        })
    }

    fn unreserved(audit: Arc<SecurityAudit>) -> Self {
        Self {
            audit,
            buffers: None,
        }
    }

    fn construction(self, stores: Arc<TenantStorageSet>) -> anyhow::Result<DatabaseConstruction> {
        let construction = DatabaseConstruction::new(stores, self.audit)?;
        Ok(match self.buffers {
            Some(buffers) => construction.with_local_buffers(buffers),
            None => construction,
        })
    }

    /// Open the authenticated bootstrap using this startup's snapshot buffers.
    pub async fn reopen<'a>(
        self,
        stores: Arc<TenantStorageSet>,
        expected_incarnation: impl Into<ExistingIncarnation<'a>>,
    ) -> std::result::Result<Arc<Database>, crate::SnapshotFailure> {
        let expected_incarnation = expected_incarnation.into();
        let construction = self.construction(stores)?;
        let stores = construction.stores();
        crate::SnapshotFailure::ordinary(|| {
            anyhow::ensure!(
                !expected_incarnation.incarnation.is_nil(),
                "nil local incarnation"
            );
            anyhow::ensure!(
                stores
                    .application()
                    .storage_access()
                    .serving_gate()
                    .is_none(),
                "independent serving authority requires replicated storage; local downgrade is forbidden"
            );
            Ok(())
        })?;
        let _gate = BOOTSTRAP_GATE.lock().await;
        reject_retired_serving_open(stores)?;
        require_deployment(stores, b"local-v1")?;
        let bytes = load(stores.application())?
            .ok_or_else(|| anyhow::anyhow!("local bootstrap is not initialized"))?;
        start(
            construction,
            &bytes,
            LocalRuntime::Production,
            Some(expected_incarnation),
        )
        .await
    }

    pub async fn initialize(
        self,
        stores: Arc<TenantStorageSet>,
        initial_policy: Policy,
        initial_limits: Limits,
        incarnation: uuid::Uuid,
    ) -> std::result::Result<Arc<Database>, crate::SnapshotFailure> {
        self.initialize_as(
            stores,
            initial_policy,
            initial_limits,
            incarnation,
            LocalRuntime::Production,
        )
        .await
    }

    /// Commit the original standalone creation identity together with both sides
    /// of its fresh genesis, before a fallible database constructor can run.
    pub async fn initialize_enrollment(
        self,
        stores: Arc<TenantStorageSet>,
        initial_policy: Policy,
        initial_limits: Limits,
        incarnation: uuid::Uuid,
        original_dispatch: [u8; 32],
        check_original: impl Fn() -> anyhow::Result<()> + Send + Sync,
    ) -> std::result::Result<Arc<Database>, crate::SnapshotFailure> {
        self.initialize_as(
            stores,
            initial_policy,
            initial_limits,
            incarnation,
            LocalRuntime::Enrollment {
                dispatch: original_dispatch,
                check: &check_original,
            },
        )
        .await
    }

    async fn initialize_as(
        self,
        stores: Arc<TenantStorageSet>,
        initial_policy: Policy,
        initial_limits: Limits,
        incarnation: uuid::Uuid,
        runtime: LocalRuntime<'_>,
    ) -> std::result::Result<Arc<Database>, crate::SnapshotFailure> {
        crate::SnapshotFailure::ordinary(|| {
            anyhow::ensure!(!incarnation.is_nil(), "nil local incarnation");
            Ok(())
        })?;
        open_local_inner(
            self.construction(stores)?,
            initial_policy,
            initial_limits,
            Some(incarnation),
            runtime,
        )
        .await
    }
}

/// Reopen an initialized local deployment using only its authenticated bootstrap.
/// Missing deployment, bootstrap or custody commitment is corruption, never a
/// request to generate a new incarnation or install default policy and limits.
pub async fn open_existing_local<'a>(
    stores: Arc<TenantStorageSet>,
    security_audit: Arc<SecurityAudit>,
    expected_incarnation: impl Into<ExistingIncarnation<'a>>,
) -> std::result::Result<Arc<Database>, crate::SnapshotFailure> {
    LocalDatabaseStartup::unreserved(security_audit)
        .reopen(stores, expected_incarnation)
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
) -> std::result::Result<Arc<Database>, crate::SnapshotFailure> {
    LocalDatabaseStartup::unreserved(security_audit)
        .initialize(stores, initial_policy, initial_limits, incarnation)
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
) -> std::result::Result<Arc<Database>, crate::SnapshotFailure> {
    security_audit.require_admission(&admission)?;
    crate::SnapshotFailure::ordinary(|| {
        anyhow::ensure!(
            matches!(
                stores.application().storage_access().purpose(),
                kasumi_store::StoragePurpose::LocalFixture
            ),
            "fixture clock cannot open production storage"
        );
        Ok(())
    })?;
    let construction = DatabaseConstruction::with_fixture_clock(stores, security_audit, clock)?;
    open_local_inner(
        construction,
        initial_policy,
        initial_limits,
        None,
        LocalRuntime::FixtureDefault,
    )
    .await
}

#[cfg(any(test, feature = "test-utils"))]
#[path = "bootstrap_fixtures.rs"]
pub(crate) mod fixtures;

enum LocalRuntime<'a> {
    Production,
    Enrollment {
        dispatch: [u8; 32],
        check: &'a (dyn Fn() -> anyhow::Result<()> + Send + Sync),
    },
    #[cfg(any(test, feature = "test-utils"))]
    FixtureDefault,
}

fn local_enrollment_commitment(
    stores: &TenantStorageSet,
    dispatch: &[u8; 32],
    bootstrap_digest: &str,
) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(
        matches!(
            stores.application().storage_access().purpose(),
            kasumi_store::StoragePurpose::Standalone { .. }
        ),
        "local enrollment requires an installed standalone pair"
    );
    let pair = stores.custody().binding();
    let mut hash = Sha256::new();
    hash.update(b"kasumi-standalone-enrollment-genesis-v1\0");
    hash.update(dispatch);
    hash.update(pair.application_catalog().as_bytes());
    hash.update(pair.custody_catalog().as_bytes());
    hash.update(bootstrap_digest.as_bytes());
    Ok(hash.finalize().into())
}

/// Check the immutable, original-dispatch receipt from the same read generation
/// as the two deployment rows and the manifest. Existing data without the
/// receipt cannot be adopted by an incomplete security enrollment.
pub fn require_local_enrollment_genesis(
    stores: &TenantStorageSet,
    dispatch: &[u8; 32],
) -> anyhow::Result<()> {
    let view = stores.read_view()?;
    let binding = view
        .deployment_binding()?
        .ok_or_else(|| anyhow::anyhow!("local enrollment deployment pair absent"))?;
    anyhow::ensure!(
        binding.as_bytes() == b"local-v1",
        "local enrollment deployment differs"
    );
    let digest = persisted_bootstrap_digest_at(&view)?;
    anyhow::ensure!(
        view.custody_get("raft.meta", b"application_bootstrap_sha256", 256)?
            .as_deref()
            == Some(serde_json::to_vec(&digest)?.as_slice()),
        "local enrollment custody bootstrap differs"
    );
    let expected = local_enrollment_commitment(stores, dispatch, &digest)?;
    anyhow::ensure!(
        view.custody_get("raft.meta", LOCAL_ENROLLMENT_GENESIS_KEY, 32)?
            .as_deref()
            == Some(expected.as_slice()),
        "original local enrollment genesis receipt is missing or differs"
    );
    Ok(())
}

async fn open_local_inner(
    construction: DatabaseConstruction,
    initial_policy: Policy,
    initial_limits: Limits,
    incarnation: Option<uuid::Uuid>,
    runtime: LocalRuntime<'_>,
) -> std::result::Result<Arc<Database>, crate::SnapshotFailure> {
    let stores = construction.stores().clone();
    let store = stores.application().clone();
    crate::SnapshotFailure::ordinary(|| {
        anyhow::ensure!(
            store.storage_access().serving_gate().is_none(),
            "independent serving authority requires replicated storage; local downgrade is forbidden"
        );
        Ok(())
    })?;
    let _gate = BOOTSTRAP_GATE.lock().await;
    reject_retired_serving_open(&stores)?;
    let check = || -> anyhow::Result<()> {
        stores.check_access()?;
        if let LocalRuntime::Enrollment { check, .. } = &runtime {
            check()?;
        }
        Ok(())
    };
    if matches!(runtime, LocalRuntime::Enrollment { .. }) {
        check()?;
        crate::SnapshotFailure::ordinary(|| {
            anyhow::ensure!(
                stores.deployment_binding()?.is_none()
                    && store
                        .get_bounded(NS, b"manifest", MAX_BOOTSTRAP_MANIFEST_BYTES)?
                        .is_none()
                    && stores
                        .custody()
                        .store()
                        .get_bounded("raft.meta", LOCAL_ENROLLMENT_GENESIS_KEY, 32)?
                        .is_none(),
                "original local enrollment requires fresh catalogs"
            );
            Ok(())
        })?;
    }
    bind_deployment(&stores, b"local-v1")?;
    let bytes = match load(&store)? {
        Some(bytes) => {
            crate::SnapshotFailure::ordinary(|| {
                anyhow::ensure!(
                    !matches!(runtime, LocalRuntime::Enrollment { .. }),
                    "original local enrollment cannot adopt an existing bootstrap"
                );
                Ok(())
            })?;
            bytes
        }
        None => {
            let engine = TenantEngine::new(
                store.tenant().into(),
                incarnation.unwrap_or_else(uuid::Uuid::new_v4).to_string(),
                initial_policy,
                initial_limits,
            )?;
            let bytes = engine.logical_snapshot(store.scratch_disk())?;
            let identity = kasumi_raft::initial_storage_identity(
                1,
                &format!(
                    "{}/{}",
                    store.tenant(),
                    engine.generation()?.state.incarnation
                ),
            )?;
            let receipt = if let LocalRuntime::Enrollment { dispatch, .. } = &runtime {
                let value = local_enrollment_commitment(&stores, dispatch, bytes.sha256())?;
                Some(WriteOp::put(
                    "raft.meta",
                    LOCAL_ENROLLMENT_GENESIS_KEY,
                    value,
                ))
            } else {
                None
            };
            persist_new_checked(&stores, &bytes, identity.into_iter().chain(receipt), check)?;
            bytes
        }
    };
    start(construction, &bytes, runtime, incarnation.map(Into::into)).await
}

async fn start(
    construction: DatabaseConstruction,
    bytes: &SnapshotImage,
    runtime: LocalRuntime<'_>,
    expected_incarnation: Option<ExistingIncarnation<'_>>,
) -> std::result::Result<Arc<Database>, crate::SnapshotFailure> {
    let stores = construction.stores();
    validate_bootstrap_control(stores, bytes)?;
    let engine = Arc::new(TenantEngine::from_bootstrap(
        stores.application().tenant(),
        bytes,
    )?);
    if let Some(expected) = expected_incarnation {
        if let Some(workspace) = expected.recovery {
            workspace.install(&engine, stores.application())?;
        }
        crate::SnapshotFailure::ordinary(|| {
            anyhow::ensure!(
                engine.generation()?.state.incarnation == expected.incarnation.to_string(),
                "local incarnation differs from installed identity"
            );
            Ok(())
        })?;
    }
    if let kasumi_store::StoragePurpose::Standalone {
        tenant,
        incarnation,
        ..
    } = stores.application().storage_access().purpose()
    {
        let generation = engine.generation()?;
        crate::SnapshotFailure::ordinary(|| {
            anyhow::ensure!(
                generation.state.tenant == *tenant
                    && generation.state.incarnation == incarnation.to_string(),
                "local bootstrap differs from authenticated standalone identity"
            );
            Ok(())
        })?;
    }
    start_prepared(construction, engine, bytes, runtime).await
}

async fn start_prepared(
    construction: DatabaseConstruction,
    engine: Arc<TenantEngine>,
    bytes: &SnapshotImage,
    runtime: LocalRuntime<'_>,
) -> std::result::Result<Arc<Database>, crate::SnapshotFailure> {
    let store = construction.stores().application().clone();
    engine.install_storage_access(&store)?;
    let admission = construction.admission().clone();
    engine
        .verify_bootstrap_dependencies_owned(admission.clone())
        .await?;
    if matches!(
        runtime,
        LocalRuntime::Production | LocalRuntime::Enrollment { .. }
    ) {
        engine.install_audit_maintenance(&admission)?;
    }
    let incarnation = engine.generation()?.state.incarnation.clone();
    construction
        .start_local(
            engine,
            bytes,
            1,
            format!("{}/{incarnation}", store.tenant()),
        )
        .await
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
) -> std::result::Result<Arc<Database>, crate::SnapshotFailure> {
    let construction = DatabaseConstruction::new(targets.clone(), security_audit.clone())?;
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
    crate::SnapshotFailure::ordinary(|| {
        anyhow::ensure!(
            !incarnation.is_nil()
                && incarnation.to_string() != request.checkpoint.source_incarnation,
            "local restore requires a fresh target incarnation"
        );
        Ok(())
    })?;
    let target = targets.application().clone();
    crate::SnapshotFailure::ordinary(|| {
        anyhow::ensure!(
            target.storage_access().serving_gate().is_none(),
            "independent restore authority requires replicated storage; local downgrade is forbidden"
        );
        Ok(())
    })?;
    use crate::backup_verify::VerificationPhase;
    let deadline = source.deadline()?;
    let total = VerificationPhase::start("restore.local_total", Some(deadline));
    let cancellation = kasumi_query::QueryCancellation::default();
    let _cancel = crate::admission::CancelOnDrop(cancellation.clone());
    let phase = VerificationPhase::start("restore.bootstrap_gate", Some(deadline));
    let _gate = deadline.run(BOOTSTRAP_GATE.lock()).await?;
    phase.complete();
    let phase = VerificationPhase::start("restore.initial_access", Some(deadline));
    let authorization = backup_restore::RestoreAuthorization::Local(&request);
    authorization.check_access(&target, &security_audit).await?;
    crate::SnapshotFailure::ordinary(|| {
        anyhow::ensure!(
            target
                .get_bounded(NS, b"manifest", MAX_BOOTSTRAP_MANIFEST_BYTES)?
                .is_none()
                && targets
                    .custody()
                    .store()
                    .get("raft.meta", b"node_id")?
                    .is_none(),
            "restore target is already initialized"
        );
        Ok(())
    })?;
    phase.complete();
    // Reserve the target's mandatory audit pool while its store is still empty.
    // Verification and persistence can otherwise fill the shared governor with
    // optional pages before start_prepared installs that very same pool.
    let maintenance = crate::audit_maintenance::NodeAuditMaintenance::install(&admission)?;
    let phase = VerificationPhase::start("restore.load_authorized", Some(deadline));
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
    phase.complete();
    crate::SnapshotFailure::ordinary(|| {
        anyhow::ensure!(
            verified.checkpoint == request.checkpoint,
            "verified local backup differs from exact checkpoint"
        );
        Ok(())
    })?;
    let source_revision = verified.state.metadata().revision;
    let original = verified.state.metadata();
    crate::SnapshotFailure::ordinary(|| {
        anyhow::ensure!(
            !incarnation.is_nil() && incarnation.to_string() != original.incarnation,
            "restore requires a fresh database incarnation"
        );
        Ok(())
    })?;
    let restored = verified
        .into_genesis(
            deadline,
            cancellation.clone(),
            admission.clone(),
            target.tenant().into(),
            incarnation.to_string(),
            None,
        )
        .await?;
    let phase = VerificationPhase::start("restore.publication_access", Some(deadline));
    deadline.check()?;
    backup_restore::RestoreAuthorization::Local(&request)
        .check_access(&target, &security_audit)
        .await?;
    phase.complete();
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
    .persist(
        restored,
        _gate,
        b"local-v1".to_vec(),
        kasumi_raft::initial_storage_identity(1, &format!("{}/{}", target.tenant(), incarnation))?,
    )
    .await?;
    // The started database owns the restored engine. The materialization
    // workspace and verification registration end with this block, before the
    // mandatory audit below admits its proposal workspace and source grant.
    let database = {
        let restored = restored;
        let phase = VerificationPhase::start("restore.start_prepared", Some(deadline));
        let database = start_prepared(
            construction,
            restored.engine,
            &restored.bytes,
            LocalRuntime::Production,
        )
        .await?;
        phase.complete();
        database
    };
    // The serving engine has adopted the pool for this exact MemoryCore.
    drop(maintenance);
    let phase = VerificationPhase::start("restore.maintenance_audit", Some(deadline));
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
    phase.complete();
    total.complete();
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

/// Original-serving reopen owns its admission through bootstrap, snapshot and
/// log replay. When the full wire estimate does not fit, the immutable backend
/// image is metered before any logical record is materialized.
pub struct OriginalRecoveryWorkspace {
    store: std::sync::Weak<TenantStore>,
    _reservation: crate::admission::Reservation,
    metered_image: Option<String>,
}
impl OriginalRecoveryWorkspace {
    pub fn reserve(
        stores: &TenantStorageSet,
        admission: &Arc<crate::admission::NodeAdmission>,
    ) -> std::result::Result<Self, crate::SnapshotFailure> {
        admission
            .memory()
            .require_store_memory(stores.application())?;
        let manifest = read_current_manifest(stores.application())?
            .ok_or_else(|| anyhow::anyhow!("bootstrap manifest absent"))?;
        let bootstrap_bytes = manifest
            .bytes
            .checked_mul(4)
            .and_then(|n| n.checked_add(4 << 20))
            .ok_or_else(|| anyhow::anyhow!("bootstrap workspace overflow"))?;
        let snapshot_bytes = kasumi_raft::recovery_snapshot_bytes(stores)?;
        let full = snapshot_bytes
            .checked_mul(4)
            .and_then(|n| n.checked_add(bootstrap_bytes))
            .ok_or_else(|| anyhow::anyhow!("snapshot workspace overflow"))?;
        let scan = bootstrap_bytes
            .checked_add(Self::SCAN_BYTES)
            .ok_or_else(|| anyhow::anyhow!("snapshot scan workspace overflow"))?;
        let (reservation, metered_image) = match admission.reserve(full, None) {
            Ok(reservation) => (reservation, None),
            Err(error) if error.code == ErrorCode::ResourceExhausted && scan < full => {
                // Pay both passes before constructing the engine or Raft owners.
                // A refusal here can be retried after the fresh store has drained.
                let mut reservation = admission.reserve(scan, None)?;
                let image = kasumi_raft::recovery_snapshot_backend(stores)?;
                let layout = crate::state::snapshot_bundle::inspect_reopening(&mut image.reader())?;
                let restore = layout.materialization_workspace()?;
                let additional = restore
                    .checked_sub(Self::SCAN_BYTES)
                    .ok_or_else(|| anyhow::anyhow!("invalid recovery workspace"))?;
                reservation.reserve_additional(additional)?;
                tracing::info!(
                    event = "original_reopen_snapshot_admitted",
                    snapshot_bytes,
                    bootstrap_workspace_bytes = bootstrap_bytes,
                    snapshot_workspace_bytes = restore
                );
                (reservation, Some(image.sha256().to_owned()))
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            store: Arc::downgrade(stores.application()),
            _reservation: reservation,
            metered_image,
        })
    }

    const SCAN_BYTES: u64 = 64 << 20;

    fn install(&self, engine: &TenantEngine, store: &Arc<TenantStore>) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.store.ptr_eq(&Arc::downgrade(store)),
            "recovery admission belongs to another store"
        );
        if let Some(digest) = &self.metered_image {
            engine
                .original_recovery
                .set(digest.clone())
                .map_err(|_| anyhow::anyhow!("recovery admission already installed"))?;
        }
        Ok(())
    }
}

/// The ordinary opener takes an incarnation; original recovery additionally
/// supplies a reservation bound to the exact application store.
#[derive(Clone, Copy)]
pub struct ExistingIncarnation<'a> {
    incarnation: uuid::Uuid,
    recovery: Option<&'a OriginalRecoveryWorkspace>,
}
impl From<uuid::Uuid> for ExistingIncarnation<'_> {
    fn from(incarnation: uuid::Uuid) -> Self {
        Self {
            incarnation,
            recovery: None,
        }
    }
}
impl<'a> From<(uuid::Uuid, &'a OriginalRecoveryWorkspace)> for ExistingIncarnation<'a> {
    fn from((incarnation, workspace): (uuid::Uuid, &'a OriginalRecoveryWorkspace)) -> Self {
        Self {
            incarnation,
            recovery: Some(workspace),
        }
    }
}

/// Admission estimate from bounded authenticated bootstrap/snapshot manifests.
/// It does not deserialize resident application state or authorize serving.
pub(crate) fn recovery_workspace_bytes(stores: &TenantStorageSet) -> anyhow::Result<u64> {
    let manifest = read_current_manifest(stores.application())?
        .ok_or_else(|| anyhow::anyhow!("bootstrap manifest absent"))?;
    let snapshot = kasumi_raft::recovery_snapshot_bytes(stores)?;
    Ok(manifest
        .bytes
        .saturating_add(snapshot)
        .saturating_mul(4)
        .saturating_add(4 << 20))
}

#[path = "bootstrap_target_serving.rs"]
pub(crate) mod target_serving;

#[cfg(test)]
pub(crate) fn persist_fixture_bootstrap(
    stores: &TenantStorageSet,
    image: &SnapshotImage,
    node_id: u64,
    name: &str,
) -> anyhow::Result<()> {
    persist_new_checked(
        stores,
        image,
        kasumi_raft::initial_storage_identity(node_id, name)?,
        || stores.check_access(),
    )
}
