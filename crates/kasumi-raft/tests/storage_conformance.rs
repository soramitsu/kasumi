mod common;

use anyhow::Result;
use kasumi_raft::{LogStore, SnapshotBuffer, StateMachine, TypeConfig};
use openraft::{
    Entry, EntryPayload, LogId, RaftLogReader, RaftSnapshotBuilder, StorageError, StorageIOError,
    Vote,
    storage::{RaftLogStorage, RaftLogStorageExt, RaftStateMachine},
    testing::{StoreBuilder, Suite},
};
use std::sync::{Arc, atomic::Ordering};
use tempfile::TempDir;

struct Builder;

impl StoreBuilder<TypeConfig, LogStore, StateMachine, TempDir> for Builder {
    async fn build(&self) -> Result<(TempDir, LogStore, StateMachine), StorageError<u64>> {
        async {
            let dir = tempfile::tempdir()?;
            let store = common::store(&dir.path().join("node.redb"), true).await?;
            let log = LogStore::open(store.clone(), 1).await?;
            let machine = StateMachine::open(store, Arc::new(common::Backend::default())).await?;
            anyhow::Ok((dir, log, machine))
        }
        .await
        .map_err(|error| StorageIOError::write(&std::io::Error::other(error.to_string())).into())
    }
}

#[test]
fn openraft_storage_conformance_suite() -> Result<()> {
    Suite::test_all(Builder)?;
    Ok(())
}

fn entry(index: u64, data: &[u8]) -> Entry<TypeConfig> {
    Entry {
        log_id: LogId::new(openraft::CommittedLeaderId::new(3, 1), index),
        payload: EntryPayload::Normal(kasumi_raft::RaftCommand::application(data.to_vec())),
    }
}

#[tokio::test]
async fn log_vote_and_committed_cursor_survive_full_reopen() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("node.redb");
    {
        let store = common::store(&path, true).await?;
        let mut log = LogStore::open(store, 1).await?;
        log.save_vote(&Vote::new_committed(3, 1)).await?;
        log.blocking_append([entry(0, b"a"), entry(1, b"b"), entry(2, b"uncommitted")])
            .await?;
        log.save_committed(Some(entry(1, b"").log_id)).await?;
    }
    let store = common::store(&path, false).await?;
    let mut log = LogStore::open(store, 1).await?;
    assert_eq!(log.read_vote().await?, Some(Vote::new_committed(3, 1)));
    assert_eq!(log.read_committed().await?, Some(entry(1, b"").log_id));
    assert_eq!(log.try_get_log_entries(..).await?.len(), 3);
    log.truncate(entry(2, b"").log_id).await?;
    assert_eq!(
        log.get_log_state().await?.last_log_id,
        Some(entry(1, b"").log_id)
    );
    Ok(())
}

#[tokio::test]
async fn snapshot_survives_reopen_and_failed_apply_makes_replica_unavailable() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("node.redb");
    let snapshot_meta;
    {
        let store = common::store(&path, true).await?;
        let backend = Arc::new(common::Backend::default());
        let mut machine = StateMachine::open(store, backend.clone()).await?;
        machine.apply([entry(0, b"before")]).await?;
        snapshot_meta = machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await?
            .meta;
        backend.fail_apply.store(true, Ordering::Release);
        assert!(machine.apply([entry(1, b"fail")]).await.is_err());
        assert!(machine.failed());
        backend.fail_apply.store(false, Ordering::Release);
        assert!(machine.apply([entry(2, b"must-not-apply")]).await.is_err());
        assert_eq!(backend.values(), vec![b"before".to_vec()]);
    }
    let store = common::store(&path, false).await?;
    let backend = Arc::new(common::Backend::default());
    let mut machine = StateMachine::open(store, backend.clone()).await?;
    assert!(!machine.failed());
    assert_eq!(machine.applied_state().await?.0, snapshot_meta.last_log_id);
    assert_eq!(backend.values(), vec![b"before".to_vec()]);
    assert_eq!(
        machine.get_current_snapshot().await?.unwrap().meta,
        snapshot_meta
    );
    Ok(())
}

#[tokio::test]
async fn snapshot_buffer_caps_total_size_and_sparse_seeks() -> Result<()> {
    use std::io::SeekFrom;
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    let mut buffer = SnapshotBuffer::new(&kasumi_store::ScratchDisk::fixture(), 16)?;
    buffer.write_all(b"12345678").await?;
    assert!(buffer.seek(SeekFrom::Start(15)).await.is_err());
    buffer.write_all(b"1234567").await?;
    assert!(buffer.write_all(b"xx").await.is_err());
    buffer.write_all(b"x").await?;
    assert_eq!(buffer.len(), 16);
    assert!(buffer.seek(SeekFrom::Start(17)).await.is_err());
    assert!(buffer.seek(SeekFrom::Current(i64::MIN)).await.is_err());
    assert!(
        SnapshotBuffer::from_bytes(&kasumi_store::ScratchDisk::fixture(), vec![0; 17], 16).is_err()
    );
    Ok(())
}

#[tokio::test]
async fn committed_log_replay_survives_every_append_and_commit_io_failure() -> Result<()> {
    use kasumi_store::{
        NodeStore, TenantStore,
        test_utils::{FaultBackend, LocalKeyProvider, ManualClock},
    };
    use openraft::storage::StorageHelper;
    async fn open(disk: FaultBackend) -> Result<Arc<kasumi_store::TenantStorageSet>> {
        let application = TenantStore::open_fixture_with_clock(
            NodeStore::open_with_backend(disk, kasumi_store::ScratchDisk::fixture())?,
            "log-crash".into(),
            Arc::new(LocalKeyProvider::new([4; 32])),
            Arc::new(ManualClock::new()),
        )
        .await?;
        kasumi_store::test_utils::with_custody(
            application,
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await
    }
    async fn append_commit(log: &mut LogStore) -> Result<()> {
        log.blocking_append([entry(1, b"new-a"), entry(2, b"new-b")])
            .await?;
        log.save_committed(Some(entry(2, b"").log_id)).await?;
        Ok(())
    }
    let seed = FaultBackend::new();
    let mut initial = LogStore::open(open(seed.clone()).await?, 1).await?;
    initial.save_vote(&Vote::new_committed(3, 1)).await?;
    initial
        .blocking_append([entry(0, b"already-acknowledged")])
        .await?;
    initial.save_committed(Some(entry(0, b"").log_id)).await?;
    let baseline = seed.crash();
    let mut log = LogStore::open(open(baseline.clone()).await?, 1).await?;
    let start = baseline.operations();
    append_commit(&mut log).await?;
    let operations = baseline.operations() - start;
    assert!(operations > 4);
    for failure in 0..=operations {
        let disk = seed.crash();
        let mut log = LogStore::open(open(disk.clone()).await?, 1).await?;
        disk.fail_after(failure);
        let acknowledged = append_commit(&mut log).await.is_ok();
        let store = open(disk.crash()).await?;
        let backend = Arc::new(common::Backend::default());
        let mut log = LogStore::open(store.clone(), 1).await?;
        let mut machine = StateMachine::open(store, backend.clone()).await?;
        StorageHelper::new(&mut log, &mut machine)
            .get_initial_state()
            .await?;
        let values = backend.values();
        assert_eq!(
            values[0], b"already-acknowledged",
            "previous ACK lost at operation {failure}"
        );
        assert!(
            values.len() == 1
                || values
                    == vec![
                        b"already-acknowledged".to_vec(),
                        b"new-a".to_vec(),
                        b"new-b".to_vec()
                    ]
        );
        if acknowledged {
            assert_eq!(values.len(), 3, "new ACK lost at operation {failure}");
        }
    }
    Ok(())
}
