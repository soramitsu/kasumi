#![allow(dead_code)]

use anyhow::{Result, ensure};
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

impl StateMachineBackend for Backend {
    fn apply(
        &self,
        position: &kasumi_raft::AppliedEntryContext,
        command: &[u8],
    ) -> Result<kasumi_raft::AppliedResponse> {
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
        data.insert(index, command.to_vec());
        Ok(kasumi_raft::AppliedResponse::application(command.to_vec()))
    }
    fn snapshot(&self) -> Result<Vec<u8>> {
        ensure!(
            !self.fail_snapshot.load(Ordering::Acquire),
            "injected snapshot capture failure"
        );
        Ok(serde_json::to_vec(&*self.data.lock().unwrap())?)
    }
    fn validate_snapshot(&self, bytes: &[u8]) -> Result<()> {
        serde_json::from_slice::<BTreeMap<u64, Vec<u8>>>(bytes)?;
        Ok(())
    }
    fn restore(&self, bytes: &[u8]) -> Result<()> {
        let restored = serde_json::from_slice(bytes)?;
        *self.data.lock().unwrap() = restored;
        Ok(())
    }
}

pub async fn store(path: &Path) -> Result<Arc<kasumi_store::TenantStorageSet>> {
    kasumi_store::TenantStorageSet::open(
        NodeStore::open(path)?,
        "tenant-a".into(),
        Arc::new(LocalKeyProvider::new([19; 32])),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await
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
