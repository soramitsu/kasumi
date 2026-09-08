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
mod lifetime;
mod network;
mod quorum;
mod snapshot_buffer;
mod snapshot_codec;
mod snapshot_custody;
mod snapshot_state;
mod storage;
mod timing;

use anyhow::{Context, Result, ensure};
pub use command::{
    MAX_RETIREMENT_SEED_BYTES, RaftCommand, RetirementLogSeed, RetirementReplayState,
};
pub use control::{AppliedEntryContext, CommittedRetirementSeed, ControlLog};
pub use custody_command::{CustodyCommand, MAX_CUSTODY_COMMAND_BYTES};
pub use custody_group::{CustodyRaftConfig, CustodyRaftGroup, CustodyView};
use kasumi_store::TenantStorageSet;
use lifetime::StorageDrain;
pub use network::{
    InProcessRouter, RaftTransport, RpcPayloadTooLarge, RpcRequest, RpcResponse, dispatch_rpc,
};
pub use openraft::{BasicNode, Config, LogId, SnapshotPolicy};
pub use snapshot_buffer::SnapshotBuffer;
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
/// Immutable logical roots captured at one applied position. Materialization
/// occurs after releasing the applied-state lock and can overlap new commits.
pub struct CapturedSnapshot {
    pub retirement: Option<RetiredSnapshotState>,
    writer: Box<SnapshotWriter>,
}
impl CapturedSnapshot {
    pub fn new(
        retirement: Option<RetiredSnapshotState>,
        writer: impl Fn(&mut dyn std::io::Write) -> Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self {
            retirement,
            writer: Box::new(writer),
        }
    }
    pub fn write(&self, writer: &mut dyn std::io::Write) -> Result<()> {
        (self.writer)(writer)
    }
}

/// Only the Raft adapter may call mutation methods after the group starts.
/// `apply` must publish the complete command atomically; business errors belong in
/// its returned bytes. `restore` must validate before atomically replacing state.
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
    fn restore(&self, bytes: &mut dyn std::io::Read) -> Result<()>;
    /// Irreversibly evict resident application material before publishing an
    /// installed closed custody snapshot. This cannot grant data access.
    fn close_application(&self);
}

#[derive(Clone)]
pub struct RaftGroup {
    raft: Raft,
    machine_failed: Arc<AtomicBool>,
    storage_drain: StorageDrain,
    store: Arc<TenantStorageSet>,
    ownership: Arc<AtomicBool>,
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
    fn restore(&self, bytes: &mut dyn std::io::Read) -> Result<()> {
        self.inner.restore(bytes)
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

impl RaftGroup {
    /// Opens existing durable state without changing membership. `Raft::new`
    /// replays through the persisted committed cursor before returning.
    pub async fn open(
        id: u64,
        group: String,
        store: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
        transport: Arc<dyn RaftTransport>,
        config: Config,
    ) -> Result<Self> {
        Self::open_with_limits(
            id,
            group,
            store,
            backend,
            transport,
            config,
            RaftLimits::default(),
        )
        .await
    }

    pub async fn open_with_limits(
        id: u64,
        group: String,
        store: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
        transport: Arc<dyn RaftTransport>,
        mut config: Config,
        limits: RaftLimits,
    ) -> Result<Self> {
        ensure!(
            limits.max_snapshot_bytes > 0,
            "snapshot limit must be positive"
        );
        config.cluster_name = group.clone();
        let config = Arc::new(config.validate()?);
        let ownership = claim_store(&store)?;
        let backend = Arc::new(OwnedBackend {
            inner: backend,
            _ownership: ownership.clone(),
        });
        let (storage_drain, lease) = StorageDrain::new();
        let log = LogStore::open_tracked(store.clone(), id, lease.clone()).await?;
        log.bind_group(group.clone()).await?;
        let machine =
            StateMachine::open_tracked(store.clone(), backend, limits, lease.clone()).await?;
        let machine_failed = machine.failure_flag();
        let raft = Raft::new(
            id,
            config,
            network::NetworkFactory::new(id, group, transport),
            log,
            machine,
        )
        .await?;
        drop(lease);
        Ok(Self {
            raft,
            machine_failed,
            storage_drain,
            store,
            ownership,
        })
    }

    /// Creates/opens a one-voter group. It never rewrites an existing membership.
    pub async fn local(
        id: u64,
        group: String,
        store: Arc<TenantStorageSet>,
        backend: Arc<dyn StateMachineBackend>,
    ) -> Result<Self> {
        let router = Arc::new(InProcessRouter::default());
        let instance = Self::open(
            id,
            group.clone(),
            store,
            backend,
            router.clone(),
            Config::default(),
        )
        .await?;
        router.register(group, id, instance.raft.clone());
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
        Ok(instance)
    }

    pub fn raft(&self) -> &Raft {
        &self.raft
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

    pub async fn shutdown(&self) -> Result<()> {
        let result = self.raft.shutdown().await;
        // OpenRaft 0.9.25 joins the core/ticker, but its state-machine,
        // snapshot, and replication workers can still own storage. Do not
        // release the group claim until every such owner and blocking job ends.
        self.storage_drain.wait().await;
        self.ownership.store(false, Ordering::Release);
        result.map_err(Into::into)
    }
}

mod local_applied;
pub use local_applied::ConfirmedLocalApplication;
