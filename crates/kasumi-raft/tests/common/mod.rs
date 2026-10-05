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
        publisher
            .commit(
                kasumi_raft::AppliedResponse::application(command.to_vec()),
                &[],
            )
            .map_err(anyhow::Error::from)?;
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
            node,
            "tenant-a".into(),
            Arc::new(LocalKeyProvider::new([19; 32])),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?
    } else {
        kasumi_store::TenantStorageSet::open_existing_fixture(
            node,
            "tenant-a".into(),
            Arc::new(LocalKeyProvider::new([19; 32])),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?
    };
    if create {
        stores.write_batch(&[], &kasumi_raft::initial_storage_identity(node_id, group)?)?;
    }
    Ok(stores)
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
