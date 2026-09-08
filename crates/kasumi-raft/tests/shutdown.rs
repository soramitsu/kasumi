mod common;

use anyhow::{Context, Result};
use kasumi_raft::{RaftGroup, StateMachineBackend};
use kasumi_store::{
    NodeStore, TenantStore,
    test_utils::{LocalKeyProvider, ManualClock},
};
use std::{
    future::{Future, poll_fn},
    sync::{Arc, Mutex, mpsc},
    task::Poll,
    time::Duration,
};

const WAIT: Duration = Duration::from_secs(10);

struct PausedSnapshot {
    inner: common::Backend,
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl StateMachineBackend for PausedSnapshot {
    fn close_application(&self) {
        self.inner.close_application();
    }
    fn apply(
        &self,
        position: &kasumi_raft::AppliedEntryContext,
        command: &[u8],
    ) -> Result<kasumi_raft::AppliedResponse> {
        self.inner.apply(position, command)
    }

    fn capture_snapshot(&self) -> Result<kasumi_raft::CapturedSnapshot> {
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
            self.release.lock().unwrap().recv_timeout(WAIT)?;
        }
        self.inner.capture_snapshot()
    }

    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Option<kasumi_raft::RetiredSnapshotState>> {
        self.inner.validate_snapshot(bytes)
    }

    fn prepare_restore<'a>(&'a self, context: &kasumi_raft::SnapshotRestoreContext, bytes: &mut dyn std::io::Read) -> Result<Box<dyn kasumi_raft::PreparedStateMachineRestore + 'a>> {
        self.inner.prepare_restore(context, bytes)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_drains_snapshot_worker_before_releasing_group_or_file_ownership() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("shutdown.redb");
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = mpsc::channel();
    let store = TenantStore::open_fixture_with_clock(
        NodeStore::open(&path, kasumi_store::ScratchDisk::fixture())?,
        "tenant-a".into(),
        Arc::new(LocalKeyProvider::new([19; 32])),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let group = RaftGroup::local(
        1,
        "tenant-a".into(),
        kasumi_store::test_utils::with_custody(
            store.clone(),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await?,
        Arc::new(PausedSnapshot {
            inner: common::Backend::default(),
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(wait),
        }),
    )
    .await?;
    group.write(b"acknowledged".to_vec()).await?;
    group.snapshot().await?;
    tokio::time::timeout(WAIT, ready).await??;

    // Prove the upstream shutdown boundary directly: it returns while our
    // snapshot callback is still paused. Kasumi must wait beyond that boundary.
    tokio::time::timeout(WAIT, group.raft().shutdown()).await??;
    let mut shutting_down = Box::pin(group.shutdown());
    let pending = poll_fn(|cx| Poll::Ready(shutting_down.as_mut().poll(cx).is_pending())).await;
    assert!(pending, "shutdown returned with a live snapshot worker");
    assert!(
        RaftGroup::local(
            1,
            "tenant-a".into(),
            kasumi_store::test_utils::with_custody(
                store.clone(),
                Arc::new(LocalKeyProvider::new([241; 32]))
            )
            .await?,
            Arc::new(common::Backend::default()),
        )
        .await
        .is_err(),
        "a second Raft group acquired the store before shutdown drained"
    );

    release
        .send(())
        .context("snapshot worker unexpectedly exited")?;
    tokio::time::timeout(WAIT, shutting_down).await??;
    drop(group);
    drop(store);

    // No sleep or retry: shutdown must have released every background owner.
    let recovered = Arc::new(common::Backend::default());
    let group = RaftGroup::local(
        1,
        "tenant-a".into(),
        common::store(&path).await?,
        recovered.clone(),
    )
    .await?;
    assert_eq!(recovered.values(), vec![b"acknowledged".to_vec()]);
    group.shutdown().await
}
