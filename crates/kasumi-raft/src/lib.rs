//! Durable byte-command replication. Application outcomes are encoded in response bytes;
//! backend errors are fatal materialization failures, never replica-local rejections.

mod command;
mod control;
#[cfg(test)]
mod custody_capacity_tests;
mod custody_command;
mod custody_group;
mod custody_machine;
mod custody_records;
mod custody_snapshot_storage;
mod custody_state;
mod custody_tables;
mod domains;
#[cfg(any(test, feature = "test-utils"))]
pub mod historical_test_utils;
mod lifetime;
mod network;
mod quorum;
mod snapshot_buffer;
mod snapshot_codec;
mod snapshot_custody;
mod snapshot_state;
mod startup_owner;
#[cfg(test)]
mod startup_owner_tests;
#[cfg(any(test, feature = "test-utils"))]
pub mod startup_test_utils;
mod storage;
mod timing;
mod write_errors;

use anyhow::{Context, Result, ensure};
pub use command::{
    MAX_RETIREMENT_SEED_BYTES, RaftCommand, RetirementLogSeed, RetirementReplayState,
};
pub use control::{
    AppliedEntryContext, CommittedRetirementSeed, ControlLog, TARGET_PREBIND_KEY,
    TARGET_PREBIND_NAMESPACE, TargetFirstMembershipHistory, TargetFirstMembershipPrebind,
    initial_storage_identity, read_target_first_membership_history,
    read_target_first_membership_prebind,
};
pub use custody_command::{CustodyCommand, MAX_CUSTODY_COMMAND_BYTES};
pub use custody_group::{CustodyRaftGroup, CustodyView};
use kasumi_store::TenantStorageSet;
use lifetime::StorageDrain;
pub use network::{
    InProcessRouter, RaftTransport, RpcPayloadTooLarge, RpcRequest, RpcResponse, dispatch_rpc,
};
pub use openraft::{
    BasicNode, Config, LogId, MembershipObserver, SnapshotMeta, SnapshotPolicy, StoredMembership,
};
pub use snapshot_buffer::{SNAPSHOT_BUFFER_SLOTS, SnapshotBuffer, SnapshotBufferOwner};
pub use snapshot_state::RetiredSnapshotState;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{
        Arc, LazyLock, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
pub use storage::{LogStore, StateMachine, recovery_snapshot_bytes};
pub use timing::server_config;
pub use write_errors::{is_application_write_capacity_denied, is_application_write_redirect};

#[derive(Clone, Debug)]
pub struct RaftLimits {
    pub max_snapshot_bytes: u64,
}
impl Default for RaftLimits {
    fn default() -> Self {
        Self {
            max_snapshot_bytes: 64 << 30,
        }
    }
}

/// Operational settings and capacity for either a serving or custody group.
#[derive(Clone, Debug, Default)]
pub struct RaftGroupConfig {
    pub raft: Config,
    pub limits: RaftLimits,
}

openraft::declare_raft_types!(
    pub TypeConfig:
        D = RaftCommand,
        R = Vec<u8>,
        NodeId = u64,
        Node = BasicNode,
        SnapshotData = SnapshotBuffer,
);

pub type Raft = openraft::Raft<TypeConfig>;

/// Trusted state-machine output. It has no wire deserializer and does not mint
/// a current administrative proof. The adapter validates terminal metadata
/// against the exact committed seed before recording an immutable boundary.
pub struct AppliedResponse {
    pub data: Vec<u8>,
    pub retirement: Option<kasumi_types::RetirementReceipt>,
}
impl AppliedResponse {
    pub fn application(data: Vec<u8>) -> Self {
        Self {
            data,
            retirement: None,
        }
    }
}

type SnapshotWriter = dyn Fn(&mut dyn std::io::Write) -> Result<()> + Send + Sync;
type CheckpointWrites =
    dyn Fn(&SnapshotRestoreContext) -> Result<Vec<kasumi_store::WriteOp>> + Send + Sync;
/// Immutable logical roots captured at one applied position. Materialization
/// occurs after releasing the applied-state lock and can overlap new commits.
pub struct CapturedSnapshot {
    pub retirement: Option<RetiredSnapshotState>,
    writer: Box<SnapshotWriter>,
    checkpoint_writes: Box<CheckpointWrites>,
}
impl CapturedSnapshot {
    pub fn new(
        retirement: Option<RetiredSnapshotState>,
        writer: impl Fn(&mut dyn std::io::Write) -> Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self {
            retirement,
            writer: Box::new(writer),
            checkpoint_writes: Box::new(|_| Ok(Vec::new())),
        }
    }
    pub fn with_checkpoint_writes(
        mut self,
        writes: impl Fn(&SnapshotRestoreContext) -> Result<Vec<kasumi_store::WriteOp>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.checkpoint_writes = Box::new(writes);
        self
    }
    pub(crate) fn checkpoint_writes(
        &self,
        context: &SnapshotRestoreContext,
    ) -> Result<Vec<kasumi_store::WriteOp>> {
        (self.checkpoint_writes)(context)
    }
    pub fn write(&self, writer: &mut dyn std::io::Write) -> Result<()> {
        (self.writer)(writer)
    }
}

/// Only the Raft adapter may call mutation methods after the group starts.
/// `apply` must publish the complete command atomically; business errors belong in
/// its returned bytes. `restore` must validate before atomically replacing state.
/// Validated backend state held unpublished while Raft durably installs its
/// encrypted tables and the matching snapshot/applied cursor. The borrowed
/// lifetime keeps the backend's mutation lock and tracked storage owner alive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotRestoreMode {
    Reopen,
    Install,
}
/// Authenticated enclosing position supplied by the Raft adapter. Reopen selects
/// an existing checkpoint namespace; installation prepares a new atomic binding.
pub struct SnapshotRestoreContext {
    pub mode: SnapshotRestoreMode,
    pub backend_sha256: String,
    pub meta: openraft::SnapshotMeta<u64, BasicNode>,
}
impl SnapshotRestoreContext {
    pub fn checkpoint_sha256(&self) -> Result<String> {
        use sha2::Digest;
        ensure!(
            self.backend_sha256.len() == 64
                && self
                    .backend_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid backend snapshot digest"
        );
        Ok(hex::encode(sha2::Sha256::digest(serde_json::to_vec(&(
            "kasumi.backend-checkpoint.v1",
            &self.backend_sha256,
            &self.meta.last_log_id,
            &self.meta.last_membership,
        ))?)))
    }
}

pub trait PreparedStateMachineRestore {
    fn retirement(&self) -> Option<RetiredSnapshotState>;
    fn application_replacements(&self) -> Vec<(&str, &kasumi_store::EncryptedTable)>;
    fn application_writes(&self) -> &[kasumi_store::WriteOp];
    /// Called only after durable publication succeeds. A release failure seals
    /// the replica; restart must recover the already committed snapshot exactly.
    fn publish(self: Box<Self>) -> Result<()>;
}

pub trait StateMachineBackend: Send + Sync + 'static {
    fn apply(&self, position: &AppliedEntryContext, command: &[u8]) -> Result<AppliedResponse>;
    fn capture_snapshot(&self) -> Result<CapturedSnapshot>;
    fn snapshot(&self, writer: &mut dyn std::io::Write) -> Result<Option<RetiredSnapshotState>> {
        let captured = self.capture_snapshot()?;
        captured.write(writer)?;
        Ok(captured.retirement)
    }
    /// Validate the complete logical snapshot without modifying published state.
    /// Called before durable installation; malformed snapshots must never replace
    /// the last recoverable durable snapshot.
    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Option<RetiredSnapshotState>>;
    fn prepare_restore<'a>(
        &'a self,
        context: &SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Box<dyn PreparedStateMachineRestore + 'a>>;
    /// Irreversibly evict resident application material before publishing an
    /// installed closed custody snapshot. This cannot grant data access.
    fn close_application(&self);
}

#[derive(Clone)]
pub struct RaftGroup {
    raft: Raft,
    machine_failed: Arc<AtomicBool>,
    storage_drain: StorageDrain,
    snapshot_buffers: Arc<SnapshotBufferOwner>,
    shutdown_report: Arc<tokio::sync::Mutex<kasumi_types::drain::DrainReport>>,
    store: Arc<TenantStorageSet>,
    ownership: Arc<AtomicBool>,
    local_route: Option<(Arc<InProcessRouter>, String, u64)>,
}

// NodeStore holds an exclusive OS file lock and returns one TenantStore per tenant.
// Keep this claim alive in the backend too: dropping a public handle does not
// prove that OpenRaft's background tasks have stopped using its durable store.
static LIVE_GROUPS: LazyLock<Mutex<HashMap<usize, Weak<AtomicBool>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct OwnedBackend {
    inner: Arc<dyn StateMachineBackend>,
    _ownership: Arc<AtomicBool>,
}
impl StateMachineBackend for OwnedBackend {
    fn close_application(&self) {
        self.inner.close_application();
    }
    fn apply(&self, position: &AppliedEntryContext, command: &[u8]) -> Result<AppliedResponse> {
        self.inner.apply(position, command)
    }
    fn capture_snapshot(&self) -> Result<CapturedSnapshot> {
        self.inner.capture_snapshot()
    }
    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Option<RetiredSnapshotState>> {
        self.inner.validate_snapshot(bytes)
    }
    fn prepare_restore<'a>(
        &'a self,
        context: &SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Box<dyn PreparedStateMachineRestore + 'a>> {
        self.inner.prepare_restore(context, bytes)
    }
}

fn claim_store(store: &Arc<TenantStorageSet>) -> Result<Arc<AtomicBool>> {
    claim_custody(store.custody())
}

fn claim_custody(store: &kasumi_store::CustodyStore) -> Result<Arc<AtomicBool>> {
    let mut groups = LIVE_GROUPS
        .lock()
        .map_err(|_| anyhow::anyhow!("group ownership unavailable"))?;
    groups.retain(|_, owner| owner.strong_count() > 0);
    let key = Arc::as_ptr(store.store()) as usize;
    ensure!(
        !groups
            .get(&key)
            .and_then(Weak::upgrade)
            .is_some_and(|owner| owner.load(Ordering::Acquire)),
        "tenant store already has a live Raft group; shut it down before reopening"
    );
    let owner = Arc::new(AtomicBool::new(true));
    groups.insert(key, Arc::downgrade(&owner));
    Ok(owner)
}

async fn failed_startup(
    error: anyhow::Error,
    snapshot_buffers: &Arc<SnapshotBufferOwner>,
    storage_drain: &StorageDrain,
) -> anyhow::Error {
    let startup = snapshot_buffers.record_startup_error(error);
    let failure = snapshot_buffers
        .drain_buffers()
        .await
        .err()
        .unwrap_or(startup);
    storage_drain.wait().await;
    failure.into()
}

impl RaftGroup {
    /// Opens existing durable state without changing membership. `Raft::new`
    /// replays through the persisted committed cursor before returning.
    pub async fn open(
        id: u64,
        group: String,
        store: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
        transport: Arc<dyn RaftTransport>,
        config: RaftGroupConfig,
        snapshot_buffers: Arc<SnapshotBufferOwner>,
    ) -> Result<Self> {
        let owner = snapshot_buffers.clone();
        match owner
            .start(async move {
                Self::open_inner(
                    id,
                    group,
                    store,
                    backend,
                    transport,
                    config,
                    snapshot_buffers,
                    None,
                )
                .await
                .map(startup_owner::StartedGroup::Serving)
            })
            .await?
        {
            startup_owner::StartedGroup::Serving(group) => Ok(group),
            _ => unreachable!("serving startup result"),
        }
    }

    /// The first target startup must supply an expectation freshly derived
    /// from its authenticated journal and signed Control originals. The local
    /// custody row is compared before `Raft::new` can replay or apply entries.
    /// This check grants no child, issuer lease, or historical outcome.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_target_prebound(
        id: u64,
        group: String,
        store: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
        transport: Arc<dyn RaftTransport>,
        config: RaftGroupConfig,
        snapshot_buffers: Arc<SnapshotBufferOwner>,
        expected: TargetFirstMembershipPrebind,
    ) -> Result<Self> {
        let owner = snapshot_buffers.clone();
        match owner
            .start(async move {
                Self::open_inner(
                    id,
                    group,
                    store,
                    backend,
                    transport,
                    config,
                    snapshot_buffers,
                    Some(expected),
                )
                .await
                .map(startup_owner::StartedGroup::Serving)
            })
            .await?
        {
            startup_owner::StartedGroup::Serving(group) => Ok(group),
            _ => unreachable!("serving startup result"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_inner(
        id: u64,
        group: String,
        store: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
        transport: Arc<dyn RaftTransport>,
        config: RaftGroupConfig,
        snapshot_buffers: Arc<SnapshotBufferOwner>,
        target_prebind: Option<TargetFirstMembershipPrebind>,
    ) -> Result<Self> {
        let RaftGroupConfig {
            raft: mut config,
            limits,
        } = config;
        ensure!(
            limits.max_snapshot_bytes > 0,
            "snapshot limit must be positive"
        );
        config.cluster_name = group.clone();
        let config = Arc::new(config.validate()?);
        if let Some(expected) = &target_prebind {
            ensure!(
                expected.node.node_id == id && expected.group == group,
                "target Raft prebind startup node or group differs"
            );
            read_target_first_membership_prebind(&store, expected)?;
        }
        let ownership = claim_store(&store)?;
        let backend = Arc::new(OwnedBackend {
            inner: backend,
            _ownership: ownership.clone(),
        });
        let (storage_drain, lease) = StorageDrain::new();
        let opened = async {
            let log = LogStore::open_tracked(store.clone(), id, lease.clone()).await?;
            log.bind_group(group.clone()).await?;
            let machine = StateMachine::open_tracked(
                store.clone(),
                backend,
                limits,
                lease.clone(),
                snapshot_buffers.clone(),
            )
            .await?;
            let machine_failed = machine.failure_flag();
            let raft = Raft::new(
                id,
                config,
                network::NetworkFactory::new(id, group, transport),
                log,
                machine,
            )
            .await?;
            Ok::<_, anyhow::Error>((raft, machine_failed))
        }
        .await;
        drop(lease);
        let (raft, machine_failed) = match opened {
            Ok(value) => value,
            Err(error) => {
                return Err(failed_startup(error, &snapshot_buffers, &storage_drain).await);
            }
        };
        Ok(Self {
            raft,
            machine_failed,
            storage_drain,
            snapshot_buffers,
            shutdown_report: Default::default(),
            store,
            ownership,
            local_route: None,
        })
    }

    /// Creates/opens a one-voter group. It never rewrites an existing membership.
    pub async fn local(
        id: u64,
        group: String,
        store: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
        snapshot_buffers: Arc<SnapshotBufferOwner>,
    ) -> Result<Self> {
        let owner = snapshot_buffers.clone();
        match owner
            .start(async move {
                Self::local_inner(id, group, store, backend, snapshot_buffers)
                    .await
                    .map(startup_owner::StartedGroup::Serving)
            })
            .await?
        {
            startup_owner::StartedGroup::Serving(group) => Ok(group),
            _ => unreachable!("local startup result"),
        }
    }

    async fn local_inner(
        id: u64,
        group: String,
        store: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
        snapshot_buffers: Arc<SnapshotBufferOwner>,
    ) -> Result<Self> {
        let router = Arc::new(InProcessRouter::default());
        let mut instance = Self::open_inner(
            id,
            group.clone(),
            store,
            backend,
            router.clone(),
            RaftGroupConfig::default(),
            snapshot_buffers,
            None,
        )
        .await?;
        router.register(group.clone(), id, instance.raft.clone());
        instance.local_route = Some((router, group, id));
        let initialized = async {
            #[cfg(any(test, feature = "test-utils"))]
            {
                let gate = instance
                    .snapshot_buffers
                    .local_startup_gate
                    .lock()
                    .unwrap()
                    .take();
                if let Some(gate) = gate {
                    gate.pause(&instance).await?;
                }
            }
            if !instance.raft.is_initialized().await? {
                instance
                    .initialize(BTreeMap::from([(id, BasicNode::new("local"))]))
                    .await?;
            }
            instance
                .raft
                .wait(Some(Duration::from_secs(10)))
                .current_leader(id, "local leader")
                .await?;
            instance.linearizable_barrier().await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = initialized {
            let startup = instance.snapshot_buffers.record_startup_error(error);
            // This is a live group: join its SDK children before draining the
            // buffers and storage leases. The owner retains the startup issue.
            return Err(instance.shutdown().await.err().unwrap_or(startup).into());
        }
        Ok(instance)
    }

    pub fn raft(&self) -> &Raft {
        &self.raft
    }

    /// Attach the installed node's bounded readiness invalidation target before
    /// publishing this group in routing. The same observer may be attached again.
    pub fn install_membership_observer(&self, observer: Arc<dyn MembershipObserver>) -> Result<()> {
        self.raft.install_membership_observer(observer)?;
        Ok(())
    }

    /// One complete readiness operation. The installed caller retains this
    /// future through diagnostic timeouts and stops; there is deliberately no
    /// timeout that abandons a queued SDK actor request or applied-state waiter.
    pub async fn readiness_probe(
        &self,
        local_id: u64,
        expected_voters: Option<BTreeSet<u64>>,
    ) -> Result<bool> {
        use openraft::error::{Fatal, RaftError};
        if self.check_access().is_err() {
            return Ok(false);
        }
        let term = self.raft.metrics().borrow().current_term;
        let applied = match self.raft.ensure_linearizable().await {
            Ok(applied) => applied,
            // These are ordinary observations of a follower, a lost quorum or
            // a stopped group, not infrastructure failures of the probe owner.
            Err(RaftError::APIError(_)) | Err(RaftError::Fatal(Fatal::Stopped)) => {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        if self.check_access().is_err() || self.raft.metrics().borrow().current_term != term {
            return Ok(false);
        }
        let result = self
            .readiness_membership_matches(applied, local_id, expected_voters)
            .await;
        match result {
            Err(error) if matches!(error.downcast_ref::<Fatal<u64>>(), Some(Fatal::Stopped)) => {
                Ok(false)
            }
            Ok(healthy) => Ok(healthy
                && self.check_access().is_ok()
                && self.raft.metrics().borrow().current_term == term),
            Err(error) => Err(error),
        }
    }

    /// An actor-ordered membership observation, never a possibly lagging metrics
    /// watch sample. Callers still establish quorum and check their node epoch.
    async fn readiness_membership_matches(
        &self,
        applied: Option<LogId<u64>>,
        local_id: u64,
        expected_voters: Option<BTreeSet<u64>>,
    ) -> Result<bool> {
        Ok(self
            .raft
            .with_raft_state(move |state| {
                let membership = state.membership_state.effective();
                let configurations = membership.membership().get_joint_config();
                membership
                    .log_id()
                    .as_ref()
                    .is_some_and(|log| applied.as_ref().is_some_and(|applied| applied >= log))
                    && configurations.len() == 1
                    && configurations[0].contains(&local_id)
                    && expected_voters
                        .as_ref()
                        .is_none_or(|expected| &configurations[0] == expected)
            })
            .await?)
    }

    pub fn storage_domains(&self) -> &Arc<TenantStorageSet> {
        &self.store
    }

    pub async fn initialize(&self, members: BTreeMap<u64, BasicNode>) -> Result<()> {
        self.check_proposal()?;
        ensure!(!members.is_empty(), "membership cannot be empty");
        self.raft
            .initialize(members)
            .await
            .context("initialize raft membership")?;
        Ok(())
    }

    /// Success means quorum persistence followed by local atomic application.
    /// Timeout/cancellation does not imply rollback: retry with an application idempotency key.
    pub async fn write(&self, command: Vec<u8>) -> Result<Vec<u8>> {
        self.check_proposal()?;
        let response = self
            .raft
            .client_write(RaftCommand::application(command))
            .await?;
        self.check_access()?;
        Ok(response.data)
    }

    pub async fn write_retirement(
        &self,
        command: Vec<u8>,
        seed: RetirementLogSeed,
    ) -> Result<Vec<u8>> {
        self.check_proposal()?;
        let response = self
            .raft
            .client_write(RaftCommand::retirement(command, seed)?)
            .await?;
        self.check_access()?;
        Ok(response.data)
    }

    pub fn custody_view(&self) -> Result<CustodyView> {
        self.check_access()?;
        Ok(CustodyView(
            control::custody_head(self.store.custody())?.policy,
        ))
    }

    /// Local point lookup only; the caller must establish current quorum and
    /// custody authorization before releasing this historical observation.
    pub fn custody_receipt(
        &self,
        command_id: &str,
    ) -> Result<Option<kasumi_types::CustodyReceipt>> {
        self.check_access()?;
        kasumi_types::validate_name(command_id)?;
        let receipt = crate::custody_tables::receipt(self.store.custody().store(), command_id)?;
        self.check_access()?;
        Ok(receipt)
    }

    pub async fn write_custody(&self, command: CustodyCommand) -> Result<Vec<u8>> {
        self.check_proposal()?;
        let response = self
            .raft
            .client_write(RaftCommand::custody(&command)?)
            .await?;
        Ok(response.data)
    }

    pub async fn linearizable_barrier(&self) -> Result<Option<LogId<u64>>> {
        quorum::barrier(
            &self.raft,
            || self.check_access(),
            self.store.custody().store(),
            Some(self.store.application()),
        )
        .await
    }

    pub async fn add_learner(&self, id: u64, node: BasicNode) -> Result<()> {
        self.check_proposal()?;
        self.raft.add_learner(id, node, true).await?;
        Ok(())
    }

    /// Remove one nonvoting member without changing unrelated learners or voters.
    pub async fn remove_learner(&self, id: u64) -> Result<()> {
        self.check_proposal()?;
        ensure!(
            !self
                .raft
                .metrics()
                .borrow()
                .membership_config
                .voter_ids()
                .any(|voter| voter == id),
            "remove voter through joint consensus before revocation"
        );
        self.raft
            .change_membership(
                openraft::ChangeMembers::RemoveNodes(BTreeSet::from([id])),
                true,
            )
            .await?;
        Ok(())
    }

    pub async fn change_membership(&self, voters: BTreeSet<u64>) -> Result<()> {
        self.check_proposal()?;
        ensure!(!voters.is_empty(), "membership cannot be empty");
        self.raft.change_membership(voters, false).await?;
        Ok(())
    }

    pub async fn snapshot(&self) -> Result<()> {
        self.check_access()?;
        self.raft.trigger().snapshot().await?;
        Ok(())
    }

    fn check_proposal(&self) -> Result<()> {
        self.check_access()?;
        self.store
            .application()
            .storage_access()
            .check_consensus_proposal()
    }
    pub fn check_access(&self) -> Result<()> {
        self.snapshot_buffers.check()?;
        ensure!(
            self.ownership.load(Ordering::Acquire),
            "Raft group has shut down"
        );
        self.store.check_access()?;
        ensure!(
            self.raft.metrics().borrow().running_state.is_ok(),
            "Raft core failed; recovery required"
        );
        ensure!(
            !self.machine_failed.load(Ordering::Acquire),
            "state machine unavailable; recovery required"
        );
        Ok(())
    }

    pub async fn shutdown(&self) -> kasumi_types::drain::DrainResult {
        let mut report = self.shutdown_report.lock().await;
        if let Some((router, group, id)) = &self.local_route {
            router.unregister(group, *id);
        }
        if let Err(error) = self.raft.shutdown().await {
            report.record("OpenRaft runtime", 0, error.into());
        }
        if let Err(failure) = self.snapshot_buffers.drain_buffers().await {
            report.merge(&failure);
        }
        self.storage_drain.wait().await;
        // SDK shutdown has joined every runtime child. Its failed incoming
        // facade is now unusable because the independent buffer owner closed
        // every backing; keep the original errors while establishing completion.
        self.ownership.store(false, Ordering::Release);
        report.complete()
    }
}

mod local_applied;
pub use local_applied::ConfirmedLocalApplication;
