use super::*;
use kasumi_store::{
    NodeStore,
    test_utils::{FaultBackend, LocalKeyProvider, ManualClock},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_log_future_retains_drain_lease_until_blocking_persistence_finishes() -> Result<()>
{
    use crate::lifetime::StorageDrain;
    use std::{
        future::{Future, poll_fn},
        task::Poll,
        time::Duration,
    };

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("cancelled-persistence.redb");
    let store = TenantStore::open_fixture_with_clock(
        NodeStore::open(&path)?,
        "cancelled-persistence".into(),
        Arc::new(LocalKeyProvider::new([19; 32])),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let (drain, lease) = StorageDrain::new();
    let log = LogStore::open_tracked(
        kasumi_store::test_utils::with_custody(
            store.clone(),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?,
        1,
        lease,
    )
    .await?;
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let operation = tokio::spawn(async move {
        log.mutate(move |store| {
            let _ = entered.send(());
            wait.recv_timeout(Duration::from_secs(10))?;
            store.write_batch(&[put("test", b"committed", b"whole-write".to_vec())])
        })
        .await
    });
    tokio::time::timeout(Duration::from_secs(10), ready).await??;
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    let mut drained = Box::pin(drain.wait());
    assert!(poll_fn(|cx| Poll::Ready(drained.as_mut().poll(cx).is_pending())).await);
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(10), drained).await?;
    let domains = kasumi_store::test_utils::with_custody(
        store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    assert_eq!(
        domains
            .custody()
            .store()
            .get("test", b"committed")?
            .unwrap(),
        b"whole-write"
    );
    domains.custody().store().shutdown().await;
    drop(domains);
    drop(store);
    // An abandoned response does not detach persistence from its drain lease.
    let reopened = NodeStore::open(&path)?;
    drop(reopened);
    Ok(())
}

#[derive(Default)]
struct BytesBackend(Mutex<Vec<u8>>);

impl StateMachineBackend for BytesBackend {
    fn close_application(&self) {
        self.0.lock().unwrap().clear();
    }
    fn apply(
        &self,
        _: &crate::AppliedEntryContext,
        bytes: &[u8],
    ) -> Result<crate::AppliedResponse> {
        *self.0.lock().unwrap() = bytes.to_vec();
        Ok(crate::AppliedResponse::application(bytes.to_vec()))
    }
    fn snapshot(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> Result<Option<crate::RetiredSnapshotState>> {
        writer.write_all(&self.0.lock().unwrap())?;
        Ok(None)
    }
    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Option<crate::RetiredSnapshotState>> {
        let mut captured = Vec::new();
        bytes.read_to_end(&mut captured)?;
        ensure!(captured != b"invalid", "invalid application snapshot");
        Ok(None)
    }
    fn restore(&self, bytes: &mut dyn std::io::Read) -> Result<()> {
        let mut captured = Vec::new();
        bytes.read_to_end(&mut captured)?;
        self.validate_snapshot(&mut captured.as_slice())?;
        *self.0.lock().unwrap() = captured;
        Ok(())
    }
}

async fn fault_store(disk: FaultBackend) -> Result<Arc<TenantStore>> {
    TenantStore::open_fixture_with_clock(
        NodeStore::open_with_backend(disk)?,
        "snapshot-test".into(),
        Arc::new(LocalKeyProvider::new([7; 32])),
        Arc::new(ManualClock::new()),
    )
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn applied_metadata_does_not_block_runtime_while_snapshot_capture_holds_state_lock()
-> Result<()> {
    struct PausedSnapshot {
        entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl StateMachineBackend for PausedSnapshot {
        fn close_application(&self) {
            // This fixture retains no application state.
        }
        fn apply(
            &self,
            _: &crate::AppliedEntryContext,
            bytes: &[u8],
        ) -> Result<crate::AppliedResponse> {
            Ok(crate::AppliedResponse::application(bytes.to_vec()))
        }
        fn snapshot(
            &self,
            writer: &mut dyn std::io::Write,
        ) -> Result<Option<crate::RetiredSnapshotState>> {
            self.entered
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            // Bound a regression's stall instead of hanging the test runtime.
            let _ = self
                .release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(1));
            writer.write_all(b"consistent-snapshot")?;
            Ok(None)
        }
        fn validate_snapshot(
            &self,
            _: &mut dyn std::io::Read,
        ) -> Result<Option<crate::RetiredSnapshotState>> {
            Ok(None)
        }
        fn restore(&self, _: &mut dyn std::io::Read) -> Result<()> {
            Ok(())
        }
    }
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let mut machine = StateMachine::open(
        kasumi_store::test_utils::with_custody(
            fault_store(FaultBackend::new()).await?,
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?,
        Arc::new(PausedSnapshot {
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(wait),
        }),
    )
    .await?;
    let mut capturing = machine.clone();
    let capture = tokio::spawn(async move { capturing.get_snapshot_builder().await });
    ready.await?;
    let start = tokio::time::Instant::now();
    let (metadata, elapsed) = tokio::join!(machine.applied_state(), async {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let elapsed = start.elapsed();
        let _ = release.send(());
        elapsed
    });
    assert!(
        elapsed < std::time::Duration::from_millis(250),
        "metadata lookup blocked the runtime for {elapsed:?}"
    );
    assert_eq!(metadata?.0, None);
    let mut builder = capture.await?;
    let snapshot = builder.build_snapshot().await?;
    let envelope =
        SnapshotEnvelope::decode(&mut snapshot.snapshot.into_image()?.reader(), 64 << 20)?;
    assert_eq!(envelope.backend.read_bounded(1024)?, b"consistent-snapshot");
    assert_eq!(envelope.meta.last_log_id, None);
    Ok(())
}

fn envelope(bytes: Vec<u8>) -> SnapshotEnvelope {
    SnapshotEnvelope {
        version: 1,
        kind: SnapshotKind::Application,
        meta: SnapshotMeta {
            last_log_id: Some(LogId::new(openraft::CommittedLeaderId::new(1, 1), 3)),
            last_membership: StoredMembership::default(),
            snapshot_id: uuid::Uuid::new_v4().to_string(),
        },
        backend: kasumi_store::SnapshotImage::from_bytes(&bytes).unwrap(),
        retirement: None,
    }
}

#[tokio::test]
async fn invalid_backend_snapshot_never_replaces_durable_recoverable_state() -> Result<()> {
    let disk = FaultBackend::new();
    let store = fault_store(disk.clone()).await?;
    let mut machine = StateMachine::open(
        kasumi_store::test_utils::with_custody(
            store.clone(),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?,
        Arc::new(BytesBackend::default()),
    )
    .await?;
    let valid = envelope(b"valid".to_vec());
    machine
        .install_snapshot(
            &valid.meta,
            Box::new(SnapshotBuffer::from_bytes(
                valid.encode(64 << 20)?.read_bounded(64 << 20)?,
                1024,
            )?),
        )
        .await?;
    let invalid = envelope(b"invalid".to_vec());
    assert!(
        machine
            .install_snapshot(
                &invalid.meta,
                Box::new(SnapshotBuffer::from_bytes(
                    invalid.encode(64 << 20)?.read_bounded(64 << 20)?,
                    1024
                )?)
            )
            .await
            .is_err()
    );
    assert_eq!(
        load_snapshot(&store, 1024)?
            .unwrap()
            .backend
            .read_bounded(1024)?,
        b"valid"
    );
    let restored = Arc::new(BytesBackend::default());
    StateMachine::open(
        kasumi_store::test_utils::with_custody(
            fault_store(disk.crash()).await?,
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?,
        restored.clone(),
    )
    .await?;
    assert_eq!(*restored.0.lock().unwrap(), b"valid");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshots_larger_than_store_record_limit_are_chunked_and_recovered() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = TenantStore::open_fixture(
        NodeStore::open(dir.path().join("large.redb"))?,
        "large".into(),
        Arc::new(LocalKeyProvider::new([8; 32])),
    )
    .await?;
    let value = envelope(vec![42; 33 * 1024 * 1024]);
    let bytes = value.encode(64 << 20)?.read_bounded(64 << 20)?;
    let domains = kasumi_store::test_utils::with_custody(
        store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    persist_snapshot(&domains, &bytes, 64 * 1024 * 1024, &value)?;
    assert!(
        load_manifest(&store, b"current", 64 * 1024 * 1024)?
            .unwrap()
            .chunks
            > 8
    );
    assert_eq!(
        load_snapshot(&store, 64 * 1024 * 1024)?
            .unwrap()
            .backend
            .sha256(),
        value.backend.sha256()
    );
    assert!(load_snapshot(&store, 1024).is_err());
    assert!(load_manifest(&store, b"pending", 64 * 1024 * 1024)?.is_none());
    Ok(())
}

#[tokio::test]
async fn snapshot_install_power_loss_at_every_storage_operation_keeps_whole_old_or_new_snapshot()
-> Result<()> {
    let seed = FaultBackend::new();
    let old = envelope(b"old-complete-snapshot".to_vec());
    let mut new = envelope(b"new-complete-snapshot".to_vec());
    new.meta.last_log_id.as_mut().unwrap().index += 1;
    let initial = kasumi_store::test_utils::with_custody(
        fault_store(seed.clone()).await?,
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    persist_snapshot(
        &initial,
        &old.encode(64 << 20)?.read_bounded(64 << 20)?,
        1024,
        &old,
    )?;
    initial.custody().store().shutdown().await;
    drop(initial);
    let bytes = new.encode(64 << 20)?.read_bounded(64 << 20)?;
    let baseline = seed.crash();
    let store = fault_store(baseline.clone()).await?;
    let domains = kasumi_store::test_utils::with_custody(
        store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    let start = baseline.operations();
    persist_snapshot(&domains, &bytes, 1024, &new)?;
    let operations = baseline.operations() - start;
    ensure!(
        operations > 10,
        "fault test must cover chunk, manifest, cleanup writes and syncs"
    );
    for failure in 0..=operations {
        let disk = seed.crash();
        let store = fault_store(disk.clone()).await?;
        let domains = kasumi_store::test_utils::with_custody(
            store.clone(),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?;
        disk.fail_after(failure);
        let written = persist_snapshot(&domains, &bytes, 1024, &new);
        let recovered = fault_store(disk.crash()).await?;
        cleanup_snapshots(&recovered, 1024)?;
        let restored = load_snapshot(&recovered, 1024)?.context("snapshot lost")?;
        let recovered_domains = kasumi_store::test_utils::with_custody(
            recovered.clone(),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?;
        validate_snapshot_coverage(&recovered_domains, &restored, 1024)?;
        assert!(
            restored.backend.sha256() == old.backend.sha256()
                || restored.backend.sha256() == new.backend.sha256(),
            "torn snapshot at storage operation {failure}"
        );
        if written.is_ok() {
            assert_eq!(
                restored.backend.sha256(),
                new.backend.sha256(),
                "acknowledged snapshot lost at operation {failure}"
            );
        }
        assert!(load_manifest(&recovered, b"pending", 1024)?.is_none());
        assert!(load_manifest(&recovered, b"obsolete", 1024)?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn eight_mib_command_uses_compact_log_record_and_replays_after_reopen() -> Result<()> {
    use openraft::storage::{RaftLogStorageExt, StorageHelper};
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("large-command.redb");
    let bytes = vec![171u8; (8 << 20) + (64 << 10)];
    async fn open(path: &std::path::Path) -> Result<Arc<TenantStore>> {
        TenantStore::open_fixture(
            NodeStore::open(path)?,
            "large-command".into(),
            Arc::new(LocalKeyProvider::new([9; 32])),
        )
        .await
    }
    {
        let store = open(&path).await?;
        let mut log = LogStore::open(
            kasumi_store::test_utils::with_custody(
                store.clone(),
                Arc::new(LocalKeyProvider::new([241; 32])),
            )
            .await?,
            1,
        )
        .await?;
        let entry = Entry::<TypeConfig> {
            log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), 0),
            payload: EntryPayload::Normal(crate::RaftCommand::application(bytes.clone())),
        };
        log.blocking_append([entry.clone()]).await?;
        log.save_committed(Some(entry.log_id)).await?;
        let stored = store.get(LOG, &0u64.to_be_bytes())?.unwrap();
        assert!(stored.starts_with(LOG_FORMAT));
        assert!(
            stored.len() < bytes.len() + 128,
            "command must not expand into JSON integer arrays"
        );
    }
    let store = open(&path).await?;
    let mut log = LogStore::open(
        kasumi_store::test_utils::with_custody(
            store.clone(),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?,
        1,
    )
    .await?;
    let backend = Arc::new(BytesBackend::default());
    let mut machine = StateMachine::open(
        kasumi_store::test_utils::with_custody(store, Arc::new(LocalKeyProvider::new([241; 32])))
            .await?,
        backend.clone(),
    )
    .await?;
    StorageHelper::new(&mut log, &mut machine)
        .get_initial_state()
        .await?;
    assert_eq!(*backend.0.lock().unwrap(), bytes);
    Ok(())
}

#[path = "snapshot_custody_tests.rs"]
mod snapshot_custody_tests;
