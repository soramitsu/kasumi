mod common;

use anyhow::Context;
use kasumi_raft::test_utils::FixtureResult;
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
    release: Arc<Mutex<mpsc::Receiver<()>>>,
}

impl StateMachineBackend for PausedSnapshot {
    fn close_application(&self) {
        self.inner.close_application();
    }
    fn apply_with_publisher(
        &self,
        position: &kasumi_raft::AppliedEntryContext,
        input: kasumi_raft::AppliedInput<'_>,
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
    ) -> std::result::Result<(), kasumi_store::ScratchOperationFailure> {
        self.inner.apply_with_publisher(position, input, publisher)
    }
    fn capture_snapshot(
        &self,
    ) -> std::result::Result<kasumi_raft::CapturedSnapshot, kasumi_store::ScratchOperationFailure>
    {
        let captured = self.inner.capture_snapshot()?;
        let entered = Mutex::new(self.entered.lock().unwrap().take());
        let release = self.release.clone();
        Ok(kasumi_raft::CapturedSnapshot::new(None, move |writer| {
            if let Some(entered) = entered.lock().unwrap().take() {
                let _ = entered.send(());
                release
                    .lock()
                    .unwrap()
                    .recv_timeout(WAIT)
                    .map_err(anyhow::Error::from)?;
            }
            captured.write(writer)
        }))
    }

    fn validate_snapshot(
        &self,
        bytes: &mut dyn std::io::Read,
    ) -> std::result::Result<
        Option<kasumi_raft::RetiredSnapshotState>,
        kasumi_store::ScratchOperationFailure,
    > {
        self.inner.validate_snapshot(bytes)
    }

    fn prepare_restore<'a>(
        &'a self,
        context: &kasumi_raft::SnapshotRestoreContext,
        bytes: &mut dyn std::io::Read,
    ) -> std::result::Result<
        Box<dyn kasumi_raft::PreparedStateMachineRestore + 'a>,
        kasumi_store::ScratchOperationFailure,
    > {
        self.inner.prepare_restore(context, bytes)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn shutdown_drains_snapshot_worker_before_releasing_group_or_file_ownership()
-> FixtureResult<()> {
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
        stores.clone(),
        Arc::new(PausedSnapshot {
            inner: common::Backend::default(),
            entered: Mutex::new(Some(entered)),
            release: Arc::new(Mutex::new(wait)),
        }),
        common::snapshot_owner(),
    )
    .await?;
    group
        .write(kasumi_raft::ApplicationProposal::generated(
            b"acknowledged".to_vec(),
        ))
        .await?;
    group.snapshot().await?;
    tokio::time::timeout(WAIT, ready).await??;
    // Materializing the captured snapshot must not stall new local commits.
    tokio::time::timeout(
        WAIT,
        group.write(kasumi_raft::ApplicationProposal::generated(
            b"during-snapshot".to_vec(),
        )),
    )
    .await??;
    tokio::time::timeout(WAIT, group.linearizable_barrier()).await??;

    // Local shutdown retains and joins the actual snapshot worker.
    // Cancelling its waiter must leave that same child available to group drain.
    assert!(group.try_raft().is_none());
    let mut vendor_shutdown = Box::pin(group.shutdown());
    assert!(
        poll_fn(|cx| Poll::Ready(vendor_shutdown.as_mut().poll(cx).is_pending())).await,
        "local shutdown returned with a live snapshot worker"
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
    kasumi_store::test_utils::shutdown_owned_stores_fixture(&stores).await?;
    drop(stores);
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
    assert_eq!(
        recovered.values(),
        vec![b"acknowledged".to_vec(), b"during-snapshot".to_vec()]
    );
    group.shutdown().await?;
    Ok(())
}
