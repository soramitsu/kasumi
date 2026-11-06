mod common;

use kasumi_raft::test_utils::FixtureResult;
use kasumi_raft::{ApplicationProposal, RaftGroup};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

const GROUP: &str = "tenant-a";
const WAIT: Duration = Duration::from_secs(10);

#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
fn scratch() -> FixtureResult<(tempfile::TempDir, Arc<kasumi_store::ScratchDisk>)> {
    let memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let disk = kasumi_store::ScratchDisk::fixture(directory.path(), memory);
    Ok((directory, disk))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn retained_local_readiness_probe_does_not_block_shutdown() -> FixtureResult<()> {
    use std::{future::Future, task::Poll};

    let (_scratch_directory, disk) = scratch()?;
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let stores = common::store(
        &directory.path().join("retained-probe.kv"),
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
        stores,
        backend.clone(),
        common::snapshot_owner(),
    )
    .await?;
    let role = || kasumi_raft::ReadinessRole::Voter(Some([1].into()));
    assert!(local.readiness_probe(1, role()).await?);
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, pause) = std::sync::mpsc::channel();
    local.fixture_local_before_apply(Box::new(move || {
        entered.send(()).unwrap();
        pause.recv_timeout(WAIT).unwrap();
    }))?;
    let writer = local.clone();
    let request = tokio::spawn(async move {
        writer
            .write(ApplicationProposal::generated(b"probe-overlap".to_vec()))
            .await
    });
    tokio::time::timeout(WAIT, ready).await??;

    // The installed readiness owner retains its original future after its
    // observation is cancelled, then drains it only after group shutdown.
    let mut probe = Box::pin(local.readiness_probe(1, role()));
    let observation = std::future::poll_fn(|cx| Poll::Ready(probe.as_mut().poll(cx))).await;
    release.send(())?;
    tokio::time::timeout(WAIT, request).await???;
    assert_eq!(backend.values(), [b"probe-overlap".to_vec()]);
    let shutdown = tokio::time::timeout(WAIT, local.shutdown()).await;
    // Never poll the retained probe again. Cleanup also makes a regression
    // failure release the reserved mutex permit before the fixture is removed.
    drop(probe);
    if shutdown.is_err() {
        tokio::time::timeout(WAIT, local.shutdown()).await??;
    }
    assert!(
        shutdown.is_ok(),
        "a retained readiness probe prevented shutdown after its writer finished"
    );
    shutdown.unwrap()?;
    assert!(matches!(observation, Poll::Ready(Ok(false))));
    assert!(!local.readiness_probe(1, role()).await?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
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

fn generated(value: &str) -> ApplicationProposal {
    ApplicationProposal::generated(value.as_bytes().to_vec())
}

fn values(backend: &common::Backend) -> Vec<String> {
    backend
        .values()
        .into_iter()
        .map(|value| String::from_utf8(value).unwrap())
        .collect()
}

#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
fn committed(
    stores: &kasumi_store::TenantStorageSet,
) -> FixtureResult<Option<kasumi_raft::LogId<u64>>> {
    let Some(bytes) = stores.custody().store().get("raft.meta", b"committed")? else {
        return Ok(None);
    };
    Ok(serde_json::from_slice::<Option<kasumi_raft::LogId<u64>>>(
        &bytes,
    )?)
}

#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn open_local(
    stores: &Arc<kasumi_store::TenantStorageSet>,
    backend: &Arc<common::Backend>,
) -> FixtureResult<RaftGroup> {
    Ok(RaftGroup::local(
        1,
        GROUP.into(),
        stores.clone(),
        backend.clone(),
        common::snapshot_owner(),
    )
    .await?)
}

/// A failed apply keeps its store's duplicate-open fence until the process
/// drains it. Shut the stores down and open them again from their file.
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn reopen_failed(
    local: RaftGroup,
    stores: Arc<kasumi_store::TenantStorageSet>,
    path: &std::path::Path,
    disk: &Arc<kasumi_store::ScratchDisk>,
) -> FixtureResult<Arc<kasumi_store::TenantStorageSet>> {
    assert!(local.shutdown().await.is_err());
    drop(local);
    kasumi_store::test_utils::shutdown_owned_stores_fixture(&stores).await?;
    drop(stores);
    common::store(path, false, disk.clone(), 1, GROUP).await
}

/// A reopened journal replays each entry since the last snapshot exactly once
/// and in order: every acknowledged write, joined or not, and nothing else.
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn reopened_values(
    stores: &Arc<kasumi_store::TenantStorageSet>,
) -> FixtureResult<(RaftGroup, Vec<String>)> {
    let backend = Arc::new(common::Backend::default());
    let reopened = open_local(stores, &backend).await?;
    let metrics = reopened.metrics();
    assert_eq!(committed(stores)?, metrics.last_applied);
    assert_eq!(
        metrics.last_log_index,
        metrics.last_applied.map(|id| id.index)
    );
    Ok((reopened, values(&backend)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn joined_writes_commit_their_records_with_their_effects() -> FixtureResult<()> {
    let (_scratch_directory, disk) = scratch()?;
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let stores = common::store(&directory.path().join("joined.kv"), true, disk, 1, GROUP).await?;
    let backend = Arc::new(common::Backend::default());
    let local = open_local(&stores, &backend).await?;
    local.write(generated("appended")).await?;
    for value in ["joined-0", "joined-1", "joined-2"] {
        local.write_joined(generated(value)).await?;
        // The record and the applied position committed together.
        let metrics = local.metrics();
        assert_eq!(committed(&stores)?, metrics.last_applied);
        assert_eq!(
            metrics.last_log_index,
            metrics.last_applied.map(|id| id.index)
        );
    }
    assert_eq!(
        local.fixture_local_joined_appends()?,
        kasumi_raft::JoinedAppendCounts {
            applied: 3,
            ..Default::default()
        }
    );
    assert_eq!(stores.deferred_flushes_for_test(), 0);
    assert_eq!(
        values(&backend),
        ["appended", "joined-0", "joined-1", "joined-2"]
    );
    local.shutdown().await?;
    drop(local);
    let (reopened, replayed) = reopened_values(&stores).await?;
    assert_eq!(replayed, ["appended", "joined-0", "joined-1", "joined-2"]);
    reopened.write_joined(generated("after-reopen")).await?;
    reopened.shutdown().await?;
    drop(reopened);
    let (reopened, replayed) = reopened_values(&stores).await?;
    assert_eq!(
        replayed,
        [
            "appended",
            "joined-0",
            "joined-1",
            "joined-2",
            "after-reopen"
        ]
    );
    reopened.shutdown().await?;
    Ok(())
}

/// A joined write that fails before its publication fences the writer and
/// leaves no record: reopen never sees it, and its index is reused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn joined_write_failing_before_publication_fences_and_leaves_no_record() -> FixtureResult<()>
{
    let (_scratch_directory, disk) = scratch()?;
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let path = directory.path().join("joined-failed.kv");
    let stores = common::store(&path, true, disk.clone(), 1, GROUP).await?;
    let backend = Arc::new(common::Backend::default());
    let local = open_local(&stores, &backend).await?;
    local.write_joined(generated("kept")).await?;
    let kept = local.metrics().last_applied;
    backend
        .fail_apply
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(local.write_joined(generated("lost")).await.is_err());
    assert!(local.write(generated("fenced")).await.is_err());
    assert_eq!(committed(&stores)?, kept);
    let stores = reopen_failed(local, stores, &path, &disk).await?;
    let (reopened, replayed) = reopened_values(&stores).await?;
    assert_eq!(replayed, ["kept"]);
    assert_eq!(reopened.metrics().last_applied, kept);
    reopened.write_joined(generated("next")).await?;
    assert_eq!(
        reopened.metrics().last_applied.map(|id| id.index),
        kept.map(|id| id.index + 1)
    );
    reopened.shutdown().await?;
    Ok(())
}

/// A joined write that fails after its one transaction committed is applied
/// and journaled: the fenced writer reopens with it, replayed exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn joined_write_failing_after_publication_fences_and_reopens_applied() -> FixtureResult<()> {
    let (_scratch_directory, disk) = scratch()?;
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let path = directory.path().join("joined-late.kv");
    let stores = common::store(&path, true, disk.clone(), 1, GROUP).await?;
    let backend = Arc::new(common::Backend::default());
    let local = open_local(&stores, &backend).await?;
    local.write_joined(generated("first")).await?;
    let first = local.metrics().last_applied;
    backend
        .fail_after_publication
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(local.write_joined(generated("published")).await.is_err());
    assert!(local.write(generated("fenced")).await.is_err());
    assert_eq!(
        committed(&stores)?.map(|id| id.index),
        first.map(|id| id.index + 1)
    );
    let stores = reopen_failed(local, stores, &path, &disk).await?;
    let (reopened, replayed) = reopened_values(&stores).await?;
    assert_eq!(replayed, ["first", "published"]);
    reopened.shutdown().await?;
    Ok(())
}

/// Outside an ordinary completion nothing can release a backend's prepared
/// work, so a refused joined publication fails the apply. Its record was in
/// that refused transaction, so reopen does not see the entry either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn joined_publication_refused_outside_ordinary_completion_fences_without_a_record()
-> FixtureResult<()> {
    let (_scratch_directory, disk) = scratch()?;
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let path = directory.path().join("joined-refused.kv");
    let stores = common::store(&path, true, disk.clone(), 1, GROUP).await?;
    let backend = Arc::new(common::Backend::default());
    let local = open_local(&stores, &backend).await?;
    local.write_joined(generated("kept")).await?;
    let kept = local.metrics().last_applied;
    backend
        .refuse_publication
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(local.write_joined(generated("refused")).await.is_err());
    assert!(local.write(generated("fenced")).await.is_err());
    assert_eq!(committed(&stores)?, kept);
    let stores = reopen_failed(local, stores, &path, &disk).await?;
    let (reopened, replayed) = reopened_values(&stores).await?;
    assert_eq!(replayed, ["kept"]);
    reopened.shutdown().await?;
    Ok(())
}

/// A two-commit store can hold a committed entry whose apply never published.
/// Opening replays and applies it before any joined append.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn committed_unapplied_entry_replays_before_joined_appends() -> FixtureResult<()> {
    let (_scratch_directory, disk) = scratch()?;
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let path = directory.path().join("legacy-unapplied.kv");
    let stores = common::store(&path, true, disk.clone(), 1, GROUP).await?;
    let backend = Arc::new(common::Backend::default());
    let local = open_local(&stores, &backend).await?;
    local.write(generated("applied")).await?;
    let applied = local.metrics().last_applied;
    // The two-commit path journals the entry, then fails its apply.
    backend
        .fail_apply
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(local.write(generated("unapplied")).await.is_err());
    assert_eq!(
        committed(&stores)?.map(|id| id.index),
        applied.map(|id| id.index + 1)
    );
    let stores = reopen_failed(local, stores, &path, &disk).await?;
    let (reopened, replayed) = reopened_values(&stores).await?;
    assert_eq!(replayed, ["applied", "unapplied"]);
    reopened.write_joined(generated("joined")).await?;
    reopened.shutdown().await?;
    drop(reopened);
    let (reopened, replayed) = reopened_values(&stores).await?;
    assert_eq!(replayed, ["applied", "unapplied", "joined"]);
    reopened.shutdown().await?;
    Ok(())
}

/// Periodic snapshot builds and their journal purges run beside joined
/// appends, which hold the log's I/O gate from preparing their record until
/// it commits. The retained span always ends at the last applied entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn snapshots_and_purges_run_beside_joined_appends() -> FixtureResult<()> {
    let (_scratch_directory, disk) = scratch()?;
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let stores = common::store(
        &directory.path().join("joined-snapshots.kv"),
        true,
        disk,
        1,
        GROUP,
    )
    .await?;
    let backend = Arc::new(common::Backend::default());
    let local = open_local(&stores, &backend).await?;
    local.fixture_local_snapshot_interval(3).await?;
    let mut written = Vec::new();
    for number in 0..24 {
        let value = format!("joined-{number}");
        local.write_joined(generated(&value)).await?;
        written.push(value);
        let metrics = local.metrics();
        assert_eq!(
            metrics.last_log_index,
            metrics.last_applied.map(|id| id.index)
        );
        assert!(metrics.snapshot <= metrics.last_applied);
    }
    local.fixture_local_snapshot_settled().await?;
    let metrics = local.metrics();
    assert!(metrics.snapshot.is_some(), "no periodic snapshot was built");
    assert!(metrics.purged <= metrics.snapshot);
    assert_eq!(committed(&stores)?, metrics.last_applied);
    assert_eq!(local.fixture_local_joined_appends()?.applied, 24);
    assert_eq!(stores.deferred_flushes_for_test(), 0);
    local.shutdown().await?;
    drop(local);
    let (reopened, replayed) = reopened_values(&stores).await?;
    assert_eq!(replayed, written);
    reopened.shutdown().await?;
    Ok(())
}

/// A write the apply makes ahead of its publication first commits the joined
/// entry's record by itself, so the old order (record, then anything else)
/// holds. A refusal of the publication after that is an ordinary failure, as
/// an apply-commit refusal is today: the entry is journaled with its ahead
/// row, a reopen replays it (see the committed-unapplied test above), and the
/// refused writer stays retained for the process to drain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn ahead_writes_commit_the_joined_record_first() -> FixtureResult<()> {
    let (_scratch_directory, disk) = scratch()?;
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let stores = common::store(
        &directory.path().join("joined-ahead.kv"),
        true,
        disk.clone(),
        1,
        GROUP,
    )
    .await?;
    let backend = Arc::new(common::Backend::default());
    *backend.ahead.lock().unwrap() = Some(stores.application().clone());
    let local = open_local(&stores, &backend).await?;
    local.write_joined(generated("ahead")).await?;
    assert_eq!(stores.deferred_flushes_for_test(), 1);
    let metrics = local.metrics();
    assert_eq!(committed(&stores)?, metrics.last_applied);
    let ahead = metrics.last_applied.unwrap().index;
    let row = |index: u64| -> FixtureResult<Option<Vec<u8>>> {
        Ok(stores
            .application()
            .get("test.ahead", &index.to_be_bytes())?
            .map(|row| row.to_vec()))
    };
    assert_eq!(row(ahead)?, Some(b"ahead".to_vec()));
    backend
        .refuse_publication
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(local.write_joined(generated("refused-late")).await.is_err());
    assert!(local.write(generated("fenced")).await.is_err());
    assert_eq!(stores.deferred_flushes_for_test(), 2);
    assert_eq!(committed(&stores)?.map(|id| id.index), Some(ahead + 1));
    assert_eq!(row(ahead + 1)?, Some(b"refused-late".to_vec()));
    assert_eq!(values(&backend), ["ahead"]);
    backend.ahead.lock().unwrap().take();
    assert!(local.shutdown().await.is_err());
    Ok(())
}
