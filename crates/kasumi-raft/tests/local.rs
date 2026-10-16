mod common;

use kasumi_raft::test_utils::FixtureResult;
use kasumi_raft::{ApplicationProposal, RaftGroup};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

const GROUP: &str = "tenant-a";
const WAIT: Duration = Duration::from_secs(10);

fn scratch() -> FixtureResult<(tempfile::TempDir, Arc<kasumi_store::ScratchDisk>)> {
    let memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let disk = kasumi_store::ScratchDisk::fixture(directory.path(), memory);
    Ok((directory, disk))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_recovers_legacy_singleton_snapshot_and_journal() -> FixtureResult<()> {
    let (_scratch_directory, disk) = scratch()?;
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let path = directory.path().join("legacy.kv");
    let stores = common::store(&path, true, disk.clone(), 1, GROUP).await?;
    let backend = Arc::new(common::Backend::default());
    let raft = common::singleton_raft(
        1,
        GROUP.into(),
        stores.clone(),
        backend,
        common::snapshot_owner(),
    )
    .await?;
    raft.write(ApplicationProposal::generated(b"before-snapshot".to_vec()))
        .await?;
    raft.snapshot().await?;
    raft.raft()
        .wait(Some(WAIT))
        .metrics(|metrics| metrics.snapshot.is_some(), "legacy snapshot")
        .await?;
    raft.write(ApplicationProposal::generated(b"after-snapshot".to_vec()))
        .await?;
    raft.shutdown().await?;
    drop(raft);
    let saved_vote = stores
        .custody()
        .store()
        .get("raft.meta", b"vote")?
        .map(|bytes| bytes.to_vec());
    let recovered = Arc::new(common::Backend::default());
    let local = RaftGroup::local(
        1,
        GROUP.into(),
        stores.clone(),
        recovered.clone(),
        common::snapshot_owner(),
    )
    .await?;
    assert!(local.is_local());
    assert!(local.try_raft().is_none());
    assert_eq!(
        recovered.values(),
        [b"before-snapshot".to_vec(), b"after-snapshot".to_vec()]
    );
    local
        .write(ApplicationProposal::generated(b"local-write".to_vec()))
        .await?;
    assert_eq!(
        local.linearizable_barrier().await?,
        local.metrics().last_applied
    );
    assert_eq!(
        saved_vote,
        stores
            .custody()
            .store()
            .get("raft.meta", b"vote")?
            .map(|bytes| bytes.to_vec())
    );
    local.snapshot().await?;
    tokio::time::timeout(WAIT, async {
        while local.metrics().snapshot != local.metrics().last_applied {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(local.metrics().snapshot, local.metrics().last_applied);
    local.shutdown().await?;
    drop(local);
    let recovered_again = Arc::new(common::Backend::default());
    let reopened = RaftGroup::local(
        1,
        GROUP.into(),
        stores,
        recovered_again.clone(),
        common::snapshot_owner(),
    )
    .await?;
    assert_eq!(
        recovered_again.values(),
        [
            b"before-snapshot".to_vec(),
            b"after-snapshot".to_vec(),
            b"local-write".to_vec()
        ]
    );
    reopened.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_rejects_cluster_membership_without_rewriting_it() -> FixtureResult<()> {
    let (_scratch_directory, disk) = scratch()?;
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let stores = common::store(&directory.path().join("cluster.kv"), true, disk, 1, GROUP).await?;
    let raft = RaftGroup::open(
        1,
        GROUP.into(),
        stores.clone(),
        Arc::new(common::Backend::default()),
        Arc::new(kasumi_raft::InProcessRouter::default()),
        kasumi_raft::RaftGroupConfig::default(),
        common::snapshot_owner(),
    )
    .await?;
    raft.initialize(BTreeMap::from([
        (1, kasumi_raft::BasicNode::new("node-1")),
        (2, kasumi_raft::BasicNode::new("node-2")),
        (3, kasumi_raft::BasicNode::new("node-3")),
    ]))
    .await?;
    raft.shutdown().await?;
    drop(raft);
    let result = RaftGroup::local(
        1,
        GROUP.into(),
        stores,
        Arc::new(common::Backend::default()),
        common::snapshot_owner(),
    )
    .await;
    assert!(
        result.is_err(),
        "cluster state must never be downgraded to local authority"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_local_request_finishes_commit_and_remains_ordered() -> FixtureResult<()> {
    let (_scratch_directory, disk) = scratch()?;
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let stores =
        common::store(&directory.path().join("cancelled.kv"), true, disk, 1, GROUP).await?;
    let backend = Arc::new(common::Backend::default());
    let local = RaftGroup::local(
        1,
        GROUP.into(),
        stores,
        backend.clone(),
        common::snapshot_owner(),
    )
    .await?;
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, pause) = std::sync::mpsc::channel();
    local.fixture_local_before_apply(Box::new(move || {
        entered.send(()).unwrap();
        pause.recv_timeout(WAIT).unwrap();
    }))?;
    let writer = local.clone();
    let request = tokio::spawn(async move {
        writer
            .write(ApplicationProposal::generated(b"cancelled-waiter".to_vec()))
            .await
    });
    tokio::time::timeout(WAIT, ready).await??;
    request.abort();
    release.send(())?;
    local
        .write(ApplicationProposal::generated(b"next-write".to_vec()))
        .await?;
    local.observation_barrier().await?;
    assert_eq!(
        backend.values(),
        [b"cancelled-waiter".to_vec(), b"next-write".to_vec()]
    );
    local.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_snapshot_failure_is_fenced_retained_and_drained() -> FixtureResult<()> {
    let (_scratch_directory, disk) = scratch()?;
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let stores = common::store(
        &directory.path().join("snapshot-failed.kv"),
        true,
        disk,
        1,
        GROUP,
    )
    .await?;
    let backend = Arc::new(common::Backend::default());
    let local = RaftGroup::local(
        1,
        GROUP.into(),
        stores.clone(),
        backend.clone(),
        common::snapshot_owner(),
    )
    .await?;
    local
        .write(ApplicationProposal::generated(b"committed".to_vec()))
        .await?;
    backend
        .fail_snapshot
        .store(true, std::sync::atomic::Ordering::Release);
    local.snapshot().await?;
    tokio::time::timeout(WAIT, async {
        while local.check_access().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(local.access_failure_class(), Some("local_executor_failed"));
    let failure = local.shutdown().await.unwrap_err();
    assert_eq!(
        failure.completion(),
        kasumi_types::drain::DrainCompletion::Complete
    );
    let issue = failure
        .issues()
        .iter()
        .find(|issue| issue.component() == "Local snapshot worker")
        .unwrap();
    assert!(
        issue
            .error()
            .to_string()
            .contains("injected snapshot capture failure")
    );
    let repeated = local.shutdown().await.unwrap_err();
    assert!(
        repeated
            .issues()
            .iter()
            .any(|next| kasumi_types::drain::DrainIssueRef::ptr_eq(next, issue))
    );
    let recovered = Arc::new(common::Backend::default());
    let reopened = RaftGroup::local(
        1,
        GROUP.into(),
        stores,
        recovered.clone(),
        common::snapshot_owner(),
    )
    .await?;
    assert_eq!(recovered.values(), [b"committed".to_vec()]);
    reopened.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn installed_local_snapshot_repairs_legacy_missing_commit_cursor() -> FixtureResult<()> {
    let (_scratch_directory, disk) = scratch()?;
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let stores = common::store(
        &directory.path().join("snapshot-cursor.kv"),
        true,
        disk,
        1,
        GROUP,
    )
    .await?;
    let local = RaftGroup::local(
        1,
        GROUP.into(),
        stores.clone(),
        Arc::new(common::Backend::default()),
        common::snapshot_owner(),
    )
    .await?;
    local
        .write(ApplicationProposal::generated(b"snapshot-covered".to_vec()))
        .await?;
    let applied = local.linearizable_barrier().await?;
    local.snapshot().await?;
    tokio::time::timeout(WAIT, async {
        while local.metrics().snapshot != applied {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    local.shutdown().await?;
    // Model the historical snapshot-install crash window: independently
    // committed snapshot coverage exists before the log cursor is repaired.
    stores
        .custody()
        .store()
        .write_batch(&[kasumi_store::WriteOp::put(
            "raft.meta",
            b"committed",
            serde_json::to_vec(&None::<kasumi_raft::LogId<u64>>)?,
        )])?;
    let recovered = Arc::new(common::Backend::default());
    let reopened = RaftGroup::local(
        1,
        GROUP.into(),
        stores,
        recovered.clone(),
        common::snapshot_owner(),
    )
    .await?;
    assert_eq!(reopened.linearizable_barrier().await?, applied);
    assert_eq!(recovered.values(), [b"snapshot-covered".to_vec()]);
    reopened
        .write(ApplicationProposal::generated(b"after-recovery".to_vec()))
        .await?;
    reopened.shutdown().await?;
    Ok(())
}
