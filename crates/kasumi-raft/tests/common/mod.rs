#![allow(dead_code)]

use anyhow::Result;

macro_rules! ensure {
    ($condition:expr, $($message:tt)+) => {
        if !$condition {
            return Err(anyhow::anyhow!($($message)+).into());
        }
    };
}
#[allow(
    unused_imports,
    reason = "The cluster target imports this macro; other independent integration targets share this module."
)]
pub(crate) use ensure;
use kasumi_raft::{Config, SnapshotPolicy, StateMachineBackend};
use kasumi_store::{NodeStore, test_utils::LocalKeyProvider};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// Small deterministic application that detects duplicate/out-of-order replay.
/// Consensus, encrypted persistence, and snapshot transfer are production code.
#[derive(Default)]
pub struct Backend {
    pub data: Mutex<BTreeMap<u64, Vec<u8>>>,
    pub fail_apply: AtomicBool,
    pub fail_snapshot: AtomicBool,
    /// The filesystem refuses the next command's publication transaction.
    pub refuse_publication: AtomicBool,
    /// The next command fails after its publication returned.
    pub fail_after_publication: AtomicBool,
    /// Each command first writes a row of its own to this application store,
    /// ahead of its publication, as an immutable receipt pair is staged.
    pub ahead: Mutex<Option<Arc<kasumi_store::TenantStore>>>,
}

impl Backend {
    pub fn values(&self) -> Vec<Vec<u8>> {
        self.data.lock().unwrap().values().cloned().collect()
    }
}

struct PreparedBackend<'a> {
    backend: &'a Backend,
    restored: BTreeMap<u64, Vec<u8>>,
}
impl kasumi_raft::PreparedStateMachineRestore for PreparedBackend<'_> {
    fn retirement(&self) -> Option<kasumi_raft::RetiredSnapshotState> {
        None
    }
    fn application_replacements(&self) -> Vec<kasumi_store::NamespaceReplacement<'_>> {
        vec![]
    }
    fn application_writes(&self) -> &[kasumi_store::WriteOp] {
        &[]
    }
    fn publish(self: Box<Self>) -> Result<()> {
        *self.backend.data.lock().unwrap() = self.restored;
        Ok(())
    }
}

impl StateMachineBackend for Backend {
    fn close_application(&self) {
        self.data.lock().unwrap().clear();
        self.fail_apply.store(true, Ordering::Release);
    }
    fn apply_with_publisher(
        &self,
        position: &kasumi_raft::AppliedEntryContext,
        input: kasumi_raft::AppliedInput<'_>,
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
    ) -> std::result::Result<(), kasumi_store::ScratchOperationFailure> {
        let kasumi_raft::AppliedInput::Command(command) = input else {
            publisher
                .commit(kasumi_raft::AppliedResponse::application(Vec::new()), &[])
                .map_err(anyhow::Error::from)?;
            return Ok(());
        };
        let index = position.log_id.index;
        ensure!(
            !self.fail_apply.load(Ordering::Acquire),
            "injected application allocation failure"
        );
        let mut data = self.data.lock().unwrap();
        ensure!(
            data.last_key_value()
                .is_none_or(|(&previous, _)| previous < index),
            "reapplied command"
        );
        let mut prepared = data.clone();
        prepared.insert(index, command.to_vec());
        if let Some(store) = self.ahead.lock().unwrap().as_ref() {
            store.write_batch(&[kasumi_store::WriteOp::put(
                "test.ahead",
                index.to_be_bytes(),
                command.to_vec(),
            )])?;
        }
        if self.refuse_publication.swap(false, Ordering::AcqRel) {
            kasumi_store::NodeDisk::fixture_refuse_transactions_on_this_thread(1);
        }
        publisher
            .commit(
                kasumi_raft::AppliedResponse::application(command.to_vec()),
                &[],
            )
            .map_err(anyhow::Error::from)?;
        ensure!(
            !self.fail_after_publication.swap(false, Ordering::AcqRel),
            "injected failure after publication"
        );
        *data = prepared;
        Ok(())
    }
    fn supports_group_apply(&self) -> bool {
        true
    }
    fn apply_group_with_publisher(
        &self,
        positions: &[kasumi_raft::AppliedEntryContext],
        inputs: &[&[u8]],
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
    ) -> std::result::Result<(), kasumi_store::ScratchOperationFailure> {
        ensure!(
            positions.len() == inputs.len() && positions.len() > 1,
            "group positions and inputs differ"
        );
        ensure!(
            !self.fail_apply.load(Ordering::Acquire),
            "injected application allocation failure"
        );
        let mut data = self.data.lock().unwrap();
        let mut prepared = data.clone();
        let mut responses = Vec::new();
        let mut previous = positions[0].previous;
        for (position, command) in positions.iter().zip(inputs) {
            let index = position.log_id.index;
            ensure!(
                position.previous == previous
                    && prepared
                        .last_key_value()
                        .is_none_or(|(&last, _)| last < index),
                "group entry out of order"
            );
            prepared.insert(index, command.to_vec());
            responses.push(command.to_vec());
            previous = Some(position.log_id);
        }
        if self.refuse_publication.swap(false, Ordering::AcqRel) {
            kasumi_store::NodeDisk::fixture_refuse_transactions_on_this_thread(1);
        }
        publisher
            .commit(
                kasumi_raft::AppliedResponse::application(kasumi_raft::encode_group_responses(
                    &responses,
                )?),
                &[],
            )
            .map_err(anyhow::Error::from)?;
        ensure!(
            !self.fail_after_publication.swap(false, Ordering::AcqRel),
            "injected failure after publication"
        );
        *data = prepared;
        Ok(())
    }
    fn capture_snapshot(
        &self,
    ) -> std::result::Result<kasumi_raft::CapturedSnapshot, kasumi_store::ScratchOperationFailure>
    {
        ensure!(
            !self.fail_snapshot.load(Ordering::Acquire),
            "injected snapshot capture failure"
        );
        let data = self.data.lock().unwrap().clone();
        Ok(kasumi_raft::CapturedSnapshot::new(None, move |writer| {
            serde_json::to_writer(writer, &data)?;
            Ok(())
        }))
    }
    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> std::result::Result<
        Option<kasumi_raft::RetiredSnapshotState>,
        kasumi_store::ScratchOperationFailure,
    > {
        serde_json::from_reader::<_, BTreeMap<u64, Vec<u8>>>(bytes)?;
        Ok(None)
    }
    fn prepare_restore<'a>(
        &'a self,
        _context: &kasumi_raft::SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> std::result::Result<
        Box<dyn kasumi_raft::PreparedStateMachineRestore + 'a>,
        kasumi_store::ScratchOperationFailure,
    > {
        let restored = serde_json::from_reader(bytes)?;
        Ok(Box::new(PreparedBackend {
            backend: self,
            restored,
        }))
    }
}

pub async fn store(
    path: &Path,
    create: bool,
    fixture_scratch: Arc<kasumi_store::ScratchDisk>,
    node_id: u64,
    group: &str,
) -> kasumi_raft::test_utils::FixtureResult<Arc<kasumi_store::TenantStorageSet>> {
    let (_, stores) = store_with_node(path, create, fixture_scratch, node_id, group).await?;
    Ok(stores)
}

/// Keep the native owner available for fixtures that require its exact census
/// retirement receipt in addition to the independent worker shutdown result.
pub async fn store_with_node(
    path: &Path,
    create: bool,
    fixture_scratch: Arc<kasumi_store::ScratchDisk>,
    node_id: u64,
    group: &str,
) -> kasumi_raft::test_utils::FixtureResult<(NodeStore, Arc<kasumi_store::TenantStorageSet>)> {
    let node = if create {
        NodeStore::create_new_fixture(
            path,
            kasumi_store::test_utils::NODE_STORE_ID,
            fixture_scratch.memory().clone(),
            fixture_scratch.clone(),
        )?
    } else {
        NodeStore::open_existing_fixture(
            path,
            kasumi_store::test_utils::NODE_STORE_ID,
            fixture_scratch.memory().clone(),
            fixture_scratch.clone(),
        )?
    };
    let stores = if create {
        kasumi_store::TenantStorageSet::initialize_catalogs_fixture(
            node.clone(),
            "tenant-a".into(),
            Arc::new(LocalKeyProvider::new([19; 32])),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?
    } else {
        kasumi_store::TenantStorageSet::open_existing_fixture(
            node.clone(),
            "tenant-a".into(),
            Arc::new(LocalKeyProvider::new([19; 32])),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?
    };
    if create {
        stores.write_batch(&[], &kasumi_raft::initial_storage_identity(node_id, group)?)?;
    }
    Ok((node, stores))
}

pub fn config() -> Config {
    Config {
        election_timeout_min: 200,
        election_timeout_max: 400,
        heartbeat_interval: 50,
        snapshot_policy: SnapshotPolicy::Never,
        max_in_snapshot_log_to_keep: 0,
        purge_batch_size: 1,
        replication_lag_threshold: 10,
        ..Config::default()
    }
}

pub fn snapshot_owner() -> Arc<kasumi_raft::SnapshotBufferOwner> {
    kasumi_raft::SnapshotBufferOwner::new(
        kasumi_raft::SNAPSHOT_BUFFER_SLOTS,
        kasumi_types::SharedBudgetCharge::new(()),
    )
    .unwrap()
}

/// Explicit singleton consensus fixture for tests that exercise Raft internals.
pub async fn singleton_raft(
    id: u64,
    group_name: String,
    stores: Arc<kasumi_store::TenantStorageSet>,
    backend: Arc<dyn StateMachineBackend>,
    owner: Arc<kasumi_raft::SnapshotBufferOwner>,
) -> kasumi_raft::test_utils::FixtureResult<kasumi_raft::RaftGroup> {
    let group = kasumi_raft::RaftGroup::open(
        id,
        group_name,
        stores,
        backend,
        Arc::new(kasumi_raft::InProcessRouter::default()),
        kasumi_raft::RaftGroupConfig::default(),
        owner,
    )
    .await?;
    if !group.raft().is_initialized().await? {
        group
            .initialize(BTreeMap::from([(id, kasumi_raft::BasicNode::new("local"))]))
            .await?;
    }
    group
        .raft()
        .wait(Some(std::time::Duration::from_secs(10)))
        .current_leader(id, "singleton consensus fixture")
        .await?;
    group.linearizable_barrier().await?;
    Ok(group)
}
