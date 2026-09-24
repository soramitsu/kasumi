mod common;

use anyhow::{Context, Result, ensure};
use kasumi_raft::{BasicNode, InProcessRouter, RaftGroup};
use openraft::{LogId, ServerState};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use tempfile::TempDir;

const GROUP: &str = "tenant-a";
const WAIT: Duration = Duration::from_secs(10);

struct Node {
    group: RaftGroup,
    backend: Arc<common::Backend>,
}
struct Cluster {
    fixture_scratch: Arc<kasumi_store::ScratchDisk>,
    dir: TempDir,
    router: Arc<InProcessRouter>,
    nodes: BTreeMap<u64, Node>,
    _scratch_directory: TempDir,
}

impl Cluster {
    async fn new() -> Result<Self> {
        let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = kasumi_store::test_utils::private_tempdir()?;
        let fixture_scratch =
            kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
        let mut cluster = Self {
            fixture_scratch,
            _scratch_directory: scratch_directory,
            dir: kasumi_store::test_utils::private_tempdir()?,
            router: Arc::new(InProcessRouter::default()),
            nodes: BTreeMap::new(),
        };
        for id in 1..=3 {
            cluster.open(id, true).await?;
        }
        cluster.nodes[&1]
            .group
            .initialize(
                (1..=3)
                    .map(|id| (id, BasicNode::new(format!("node-{id}"))))
                    .collect(),
            )
            .await?;
        cluster.leader(&[]).await?;
        Ok(cluster)
    }

    async fn open(&mut self, id: u64, create: bool) -> Result<()> {
        let store = common::store(
            &self.dir.path().join(format!("node-{id}.kv")),
            create,
            self.fixture_scratch.clone(),
        )
        .await?;
        let backend = Arc::new(common::Backend::default());
        let group = RaftGroup::open(
            id,
            GROUP.into(),
            store,
            backend.clone(),
            self.router.clone(),
            kasumi_raft::RaftGroupConfig {
                raft: common::config(),
                limits: kasumi_raft::RaftLimits::default(),
            },
            common::snapshot_owner(),
        )
        .await?;
        self.router.register(GROUP.into(), id, group.raft().clone());
        self.nodes.insert(id, Node { group, backend });
        Ok(())
    }

    async fn stop(&mut self, id: u64) -> Result<()> {
        self.router.unregister(GROUP, id);
        self.nodes
            .remove(&id)
            .context("node missing")?
            .group
            .shutdown()
            .await?;
        Ok(())
    }

    async fn stop_all(&mut self) -> Result<()> {
        for id in self.nodes.keys().copied().collect::<Vec<_>>() {
            self.stop(id).await?;
        }
        Ok(())
    }

    async fn leader(&self, excluded: &[u64]) -> Result<u64> {
        tokio::time::timeout(WAIT, async {
            loop {
                for (&id, node) in &self.nodes {
                    if excluded.contains(&id) {
                        continue;
                    }
                    if node.group.raft().metrics().borrow().state == ServerState::Leader
                        && matches!(
                            tokio::time::timeout(
                                Duration::from_millis(250),
                                node.group.linearizable_barrier()
                            )
                            .await,
                            Ok(Ok(_))
                        )
                    {
                        return id;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .context("no quorum-backed leader elected")
    }

    async fn write(&self, id: u64, data: &[u8]) -> Result<LogId<u64>> {
        ensure!(
            tokio::time::timeout(WAIT, self.nodes[&id].group.write(data.to_vec())).await?? == data,
            "wrong application response"
        );
        self.nodes[&id]
            .group
            .linearizable_barrier()
            .await?
            .context("leader missing committed log")
    }

    async fn applied(&self, ids: &[u64], target: LogId<u64>) -> Result<()> {
        for id in ids {
            self.nodes[id]
                .group
                .raft()
                .wait(Some(WAIT))
                .metrics(
                    |metrics| {
                        metrics
                            .last_applied
                            .is_some_and(|last| last.index >= target.index)
                    },
                    "application caught up",
                )
                .await?;
        }
        Ok(())
    }

    fn values(&self, id: u64) -> Vec<Vec<u8>> {
        self.nodes[&id].backend.values()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partition_rejects_minority_reads_and_writes_and_recovers_after_full_restart() -> Result<()>
{
    let mut cluster = Cluster::new().await?;
    let first = cluster.leader(&[]).await?;
    let committed = cluster
        .write(first, b"acknowledged-before-partition")
        .await?;
    cluster.applied(&[1, 2, 3], committed).await?;
    cluster.router.isolate(GROUP, first, true);

    let minority = &cluster.nodes[&first].group;
    assert!(!matches!(
        tokio::time::timeout(Duration::from_millis(600), minority.linearizable_barrier()).await,
        Ok(Ok(_))
    ));
    // A timed-out proposal is genuinely unknown. In this controlled cut, it
    // cannot reach a second voter; the new leader must discard it on healing.
    assert!(!matches!(
        tokio::time::timeout(
            Duration::from_millis(600),
            minority.write(b"uncommitted-minority".to_vec())
        )
        .await,
        Ok(Ok(_))
    ));
    assert_eq!(
        minority
            .raft()
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .count(),
        3
    );

    let second = cluster.leader(&[first]).await?;
    assert_ne!(first, second);
    let committed = cluster.write(second, b"acknowledged-by-majority").await?;
    let majority = (1..=3).filter(|id| *id != first).collect::<Vec<_>>();
    cluster.applied(&majority, committed).await?;
    cluster.router.isolate(GROUP, first, false);
    cluster.applied(&[1, 2, 3], committed).await?;
    let expected = vec![
        b"acknowledged-before-partition".to_vec(),
        b"acknowledged-by-majority".to_vec(),
    ];
    for id in 1..=3 {
        assert_eq!(cluster.values(id), expected);
    }

    // Drop every live Raft/store handle and reopen all three independent KV
    // files. No test-side state is carried into the new application instances.
    cluster.stop_all().await?;
    for id in 1..=3 {
        cluster.open(id, false).await?;
    }
    let leader = cluster.leader(&[]).await?;
    let committed = cluster.nodes[&leader]
        .group
        .linearizable_barrier()
        .await?
        .unwrap();
    cluster.applied(&[1, 2, 3], committed).await?;
    for id in 1..=3 {
        assert_eq!(cluster.values(id), expected);
    }
    cluster.write(leader, b"after-total-restart").await?;
    cluster.stop_all().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_catches_up_partitioned_follower_and_replaces_a_voter() -> Result<()> {
    let mut cluster = Cluster::new().await?;
    let leader = cluster.leader(&[]).await?;
    let lagging = (1..=3).find(|id| *id != leader).unwrap();
    let first = cluster.write(leader, b"initial").await?;
    cluster.applied(&[1, 2, 3], first).await?;
    cluster.router.isolate(GROUP, lagging, true);
    let mut last = first;
    for index in 0..24 {
        last = cluster
            .write(leader, format!("document-{index}").as_bytes())
            .await?;
    }
    // Both possible majority leaders must require snapshot transfer. Healing an
    // isolated voter can advance the term and elect the other up-to-date voter;
    // retaining its logs would legitimately permit log catch-up instead.
    let majority: Vec<_> = (1..=3).filter(|id| *id != lagging).collect();
    cluster.applied(&majority, last).await?;
    for id in majority {
        cluster.nodes[&id].group.snapshot().await?;
        cluster.nodes[&id]
            .group
            .raft()
            .wait(Some(WAIT))
            .snapshot(last, "snapshot published")
            .await?;
        cluster.nodes[&id]
            .group
            .raft()
            .wait(Some(WAIT))
            .purged(Some(last), "covered logs durably purged")
            .await?;
    }
    cluster.router.isolate(GROUP, lagging, false);
    cluster.applied(&[lagging], last).await?;
    assert_eq!(cluster.values(lagging), cluster.values(leader));
    cluster.nodes[&lagging]
        .group
        .raft()
        .wait(Some(WAIT))
        .snapshot(last, "follower installed remote snapshot")
        .await?;

    cluster.open(4, true).await?;
    let leader = cluster.leader(&[]).await?;
    cluster.nodes[&leader]
        .group
        .add_learner(4, BasicNode::new("node-4"))
        .await?;
    let voters = BTreeSet::from_iter((1..=4).filter(|id| *id != lagging));
    cluster.nodes[&leader]
        .group
        .change_membership(voters.clone())
        .await?;
    let last = cluster
        .write(leader, b"replacement-voter-acknowledged")
        .await?;
    cluster
        .applied(&voters.iter().copied().collect::<Vec<_>>(), last)
        .await?;
    for &id in &voters {
        assert_eq!(cluster.values(id), cluster.values(leader));
    }
    assert_eq!(
        cluster.nodes[&leader]
            .group
            .raft()
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .collect::<BTreeSet<_>>(),
        voters
    );
    cluster.stop(lagging).await?;
    cluster.stop(leader).await?;
    let elected = cluster.leader(&[]).await?;
    cluster
        .write(elected, b"survives-leader-process-loss")
        .await?;
    cluster.stop_all().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_voter_acknowledgment_recovers_without_a_snapshot() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let dir = kasumi_store::test_utils::private_tempdir()?;
    let path = dir.path().join("local.kv");
    {
        let backend = Arc::new(common::Backend::default());
        let group = RaftGroup::local(
            1,
            GROUP.into(),
            common::store(&path, true, fixture_scratch.clone()).await?,
            backend.clone(),
            common::snapshot_owner(),
        )
        .await?;
        assert_eq!(
            group.write(b"durable-local".to_vec()).await?,
            b"durable-local"
        );
        assert_eq!(backend.values(), vec![b"durable-local".to_vec()]);
        group.shutdown().await?;
    }
    let backend = Arc::new(common::Backend::default());
    let group = RaftGroup::local(
        1,
        GROUP.into(),
        common::store(&path, false, fixture_scratch.clone()).await?,
        backend.clone(),
        common::snapshot_owner(),
    )
    .await?;
    assert_eq!(backend.values(), vec![b"durable-local".to_vec()]);
    group.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn fatal_snapshot_capture_blocks_even_local_generation_access() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let dir = kasumi_store::test_utils::private_tempdir()?;
    let path = dir.path().join("fatal-snapshot.kv");
    let store = common::store(&path, true, fixture_scratch.clone()).await?;
    let backend = Arc::new(common::Backend::default());
    let group = RaftGroup::local(
        1,
        GROUP.into(),
        store.clone(),
        backend.clone(),
        common::snapshot_owner(),
    )
    .await?;
    group.write(b"committed".to_vec()).await?;
    backend
        .fail_snapshot
        .store(true, std::sync::atomic::Ordering::Release);
    group.snapshot().await?;
    group
        .raft()
        .wait(Some(WAIT))
        .metrics(
            |metrics| metrics.running_state.is_err(),
            "snapshot capture stopped Raft core",
        )
        .await?;
    // Neither store lease nor the already-applied generation failed. The Raft
    // core status must independently fence the embedded local read fast path.
    store.check_access()?;
    assert_eq!(backend.values(), vec![b"committed".to_vec()]);
    assert!(group.check_access().is_err());
    let drain = group.shutdown().await.unwrap_err();
    assert_eq!(
        drain.completion(),
        kasumi_types::drain::DrainCompletion::Complete
    );
    let issue = drain
        .issues()
        .iter()
        .find(|issue| issue.component() == "OpenRaft runtime")
        .context("original OpenRaft failure missing")?;
    let original = issue
        .error()
        .downcast_ref::<openraft::error::ShutdownError<u64, tokio::task::JoinError>>()
        .context("original typed OpenRaft shutdown error missing")?;
    let snapshot_error = original
        .snapshot_builder()
        .and_then(|error| error.storage_error())
        .context("actual snapshot worker error missing")?;
    assert!(
        snapshot_error
            .to_string()
            .contains("injected snapshot capture failure")
    );
    assert!(Arc::ptr_eq(
        snapshot_error,
        original
            .state_machine()
            .and_then(|error| error.storage_error())
            .unwrap()
    ));
    assert!(original.core_join_error().is_none());
    let repeated = group.shutdown().await.unwrap_err();

    assert_eq!(
        repeated.completion(),
        kasumi_types::drain::DrainCompletion::Complete
    );
    assert_eq!(repeated.issues().len(), drain.issues().len());
    assert!(
        repeated
            .issues()
            .iter()
            .any(|next| Arc::ptr_eq(next, issue))
    );
    drop(group);
    drop(store);

    // Complete drain releases actual file owners despite its retained failure.
    // Reopen immediately, with no delay or retry, and replay the acknowledged row.
    let recovered = Arc::new(common::Backend::default());
    let reopened = RaftGroup::local(
        1,
        GROUP.into(),
        common::store(&path, false, fixture_scratch.clone()).await?,
        recovered.clone(),
        common::snapshot_owner(),
    )
    .await?;
    assert_eq!(recovered.values(), vec![b"committed".to_vec()]);
    reopened.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn raft_crash_worker() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let Some(path) = std::env::var_os("KASUMI_RAFT_CRASH_TEST_PATH") else {
        return Ok(());
    };
    let path = std::path::PathBuf::from(path);
    let group = RaftGroup::local(
        1,
        GROUP.into(),
        common::store(&path, true, fixture_scratch.clone()).await?,
        Arc::new(common::Backend::default()),
        common::snapshot_owner(),
    )
    .await?;
    group.write(b"acknowledged-before-sigkill".to_vec()).await?;
    use std::io::Write;
    println!("KASUMI_DURABLE_ACK");
    std::io::stdout().flush()?;
    std::future::pending::<()>().await;
    Ok(())
}

#[tokio::test]
async fn acknowledged_one_voter_write_survives_sigkill_without_graceful_shutdown() -> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    let dir = kasumi_store::test_utils::private_tempdir()?;
    let path = dir.path().join("killed.kv");
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "raft_crash_worker", "--nocapture"])
        .env("KASUMI_RAFT_CRASH_TEST_PATH", &path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut lines = BufReader::new(child.stdout.take().context("child stdout missing")?).lines();
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(line) = lines.next_line().await? {
            if line.contains("KASUMI_DURABLE_ACK") {
                return anyhow::Ok(());
            }
        }
        anyhow::bail!("worker exited before acknowledging")
    })
    .await??;
    child.kill().await?;
    let backend = Arc::new(common::Backend::default());
    let recovered = RaftGroup::local(
        1,
        GROUP.into(),
        common::store(&path, false, fixture_scratch.clone()).await?,
        backend.clone(),
        common::snapshot_owner(),
    )
    .await?;
    assert_eq!(
        backend.values(),
        vec![b"acknowledged-before-sigkill".to_vec()]
    );
    recovered.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_replication_backlog_shrinks_and_catches_up_without_changing_membership()
-> Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    use kasumi_raft::{RaftTransport, RpcPayloadTooLarge, RpcRequest, RpcResponse};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Limited {
        router: Arc<InProcessRouter>,
        rejected: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl RaftTransport for Limited {
        async fn send(
            &self,
            group: &str,
            source: u64,
            target: u64,
            node: &BasicNode,
            request: RpcRequest,
        ) -> Result<RpcResponse> {
            if let RpcRequest::Append(append) = &request
                && append.entries.len() > 2
            {
                self.rejected.fetch_add(1, Ordering::SeqCst);
                return Err(RpcPayloadTooLarge { max_entries: 2 }.into());
            }
            self.router.send(group, source, target, node, request).await
        }
    }
    let dir = kasumi_store::test_utils::private_tempdir()?;
    let router = Arc::new(InProcessRouter::default());
    let transport = Arc::new(Limited {
        router: router.clone(),
        rejected: AtomicUsize::new(0),
    });
    let mut groups = Vec::new();
    let mut backends = Vec::new();
    for id in 1..=3 {
        let backend = Arc::new(common::Backend::default());
        let config = kasumi_raft::Config {
            replication_lag_threshold: 10_000,
            max_payload_entries: 64,
            heartbeat_interval: 200,
            election_timeout_min: 600,
            election_timeout_max: 1_000,
            ..common::config()
        };
        let group = RaftGroup::open(
            id,
            GROUP.into(),
            common::store(
                &dir.path().join(format!("node-{id}.kv")),
                true,
                fixture_scratch.clone(),
            )
            .await?,
            backend.clone(),
            transport.clone(),
            kasumi_raft::RaftGroupConfig {
                raft: config,
                limits: kasumi_raft::RaftLimits::default(),
            },
            common::snapshot_owner(),
        )
        .await?;
        router.register(GROUP.into(), id, group.raft().clone());
        groups.push(group);
        backends.push(backend);
    }
    groups[0]
        .initialize((1..=3).map(|id| (id, BasicNode::new("local"))).collect())
        .await?;
    groups[0]
        .raft()
        .wait(Some(WAIT))
        .current_leader(1, "initial leader")
        .await?;
    for group in &groups {
        group
            .raft()
            .wait(Some(WAIT))
            .metrics(
                |metrics| metrics.last_applied.is_some_and(|id| id.index >= 1),
                "initial voter group committed",
            )
            .await?;
    }
    groups[0].linearizable_barrier().await?;
    router.isolate(GROUP, 3, true);
    for id in 0..24 {
        groups[0]
            .write(format!("backlog-{id}").into_bytes())
            .await?;
    }
    let target = groups[0].linearizable_barrier().await?.unwrap();
    router.isolate(GROUP, 3, false);
    for group in &groups {
        group
            .raft()
            .wait(Some(WAIT))
            .metrics(
                |metrics| {
                    metrics
                        .last_applied
                        .is_some_and(|id| id.index >= target.index)
                },
                "bounded batches caught up",
            )
            .await?;
    }
    assert!(
        transport.rejected.load(Ordering::SeqCst) > 0,
        "test must exercise oversized append retry"
    );
    assert_eq!(backends[0].values(), backends[2].values());
    for (index, group) in groups.iter().enumerate() {
        assert_eq!(
            group
                .raft()
                .metrics()
                .borrow()
                .membership_config
                .membership()
                .voter_ids()
                .count(),
            3
        );
        router.unregister(GROUP, index as u64 + 1);
        group.shutdown().await?;
    }
    Ok(())
}
