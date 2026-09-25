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

    fn prepare_restore<'a>(
        &'a self,
        context: &kasumi_raft::SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> Result<Box<dyn kasumi_raft::PreparedStateMachineRestore + 'a>> {
        self.inner.prepare_restore(context, bytes)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_drains_snapshot_worker_before_releasing_group_or_file_ownership() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let path = directory.path().join("shutdown.kv");
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = mpsc::channel();
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        NodeStore::create_new_fixture(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            fixture_scratch.memory().clone(),
            fixture_scratch.clone(),
        )?,
        "tenant-a".into(),
        Arc::new(LocalKeyProvider::new([19; 32])),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let stores = kasumi_store::test_utils::initialize_custody_fixture(
        store.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await?;
    stores.write_batch(&[], &kasumi_raft::initial_storage_identity(1, "tenant-a")?)?;
    let group = RaftGroup::local(
        1,
        "tenant-a".into(),
        stores,
        Arc::new(PausedSnapshot {
            inner: common::Backend::default(),
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(wait),
        }),
        common::snapshot_owner(),
    )
    .await?;
    group.write(b"acknowledged".to_vec()).await?;
    group.snapshot().await?;
    tokio::time::timeout(WAIT, ready).await??;

    // The vendored shutdown retains and joins the actual snapshot builder.
    // Cancelling its waiter must leave that same child available to group drain.
    let mut vendor_shutdown = Box::pin(group.raft().shutdown());
    assert!(
        poll_fn(|cx| Poll::Ready(vendor_shutdown.as_mut().poll(cx).is_pending())).await,
        "vendor shutdown returned with a live snapshot worker"
    );
    drop(vendor_shutdown);
    let mut shutting_down = Box::pin(group.shutdown());
    let pending = poll_fn(|cx| Poll::Ready(shutting_down.as_mut().poll(cx).is_pending())).await;
    assert!(pending, "shutdown returned with a live snapshot worker");
    assert!(
        RaftGroup::local(
            1,
            "tenant-a".into(),
            kasumi_store::test_utils::open_existing_custody_fixture(
                store.clone(),
                Arc::new(LocalKeyProvider::new([241; 32]))
            )
            .await?,
            Arc::new(common::Backend::default()),
            common::snapshot_owner()
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
        common::store(&path, false, fixture_scratch.clone(), 1, "tenant-a").await?,
        recovered.clone(),
        common::snapshot_owner(),
    )
    .await?;
    assert_eq!(recovered.values(), vec![b"acknowledged".to_vec()]);
    group.shutdown().await?;
    Ok(())
}
