mod common;

use anyhow::Result;
use async_trait::async_trait;
use kasumi_raft::{BasicNode, InProcessRouter, RaftGroup, RaftTransport, RpcRequest, RpcResponse};
use kasumi_store::TenantStorageSet;
use openraft::error::{CheckIsLeaderError, RaftError};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;

struct PausedTransport {
    router: InProcessRouter,
    paused_until: Mutex<Instant>,
    probes: AtomicUsize,
}
#[async_trait]
impl RaftTransport for PausedTransport {
    async fn send(
        &self,
        group: &str,
        source: u64,
        target: u64,
        node: &BasicNode,
        request: RpcRequest,
    ) -> Result<RpcResponse> {
        if matches!(&request, RpcRequest::Append(append) if append.entries.is_empty()) {
            self.probes.fetch_add(1, Ordering::SeqCst);
        }
        let until = *self.paused_until.lock().unwrap();
        if Instant::now() < until {
            tokio::time::sleep_until(until).await;
        }
        self.router.send(group, source, target, node, request).await
    }
}
struct Fixture {
    _dir: tempfile::TempDir,
    transport: Arc<PausedTransport>,
    groups: Vec<RaftGroup>,
    stores: Vec<Arc<TenantStorageSet>>,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let dir = kasumi_store::test_utils::private_tempdir()?;
        let transport = Arc::new(PausedTransport {
            router: InProcessRouter::default(),
            paused_until: Mutex::new(Instant::now()),
            probes: AtomicUsize::new(0),
        });
        let mut groups = Vec::new();
        let mut stores = Vec::new();
        for id in 1..=3 {
            let store = common::store(&dir.path().join(format!("{id}.redb")), true).await?;
            let config = kasumi_raft::Config {
                enable_elect: false,
                snapshot_policy: kasumi_raft::SnapshotPolicy::Never,
                ..kasumi_raft::server_config()
            };
            let group = RaftGroup::open(
                id,
                "read-barrier".into(),
                store.clone(),
                Arc::new(common::Backend::default()),
                transport.clone(),
                kasumi_raft::RaftGroupConfig {
                    raft: config,
                    limits: kasumi_raft::RaftLimits::default(),
                },
                common::snapshot_owner(),
            )
            .await?;
            transport
                .router
                .register("read-barrier".into(), id, group.raft().clone());
            groups.push(group);
            stores.push(store);
        }
        groups[0]
            .initialize((1..=3).map(|id| (id, BasicNode::new("test"))).collect())
            .await?;
        groups[0].raft().trigger().elect().await?;
        groups[0]
            .raft()
            .wait(Some(Duration::from_secs(5)))
            .current_leader(1, "chosen test leader")
            .await?;
        groups[0].write(b"committed before pause".to_vec()).await?;
        groups[0].linearizable_barrier().await?;
        Ok(Self {
            _dir: dir,
            transport,
            groups,
            stores,
        })
    }
    fn pause(&self, duration: Duration) {
        *self.transport.paused_until.lock().unwrap() = Instant::now() + duration;
    }
    async fn close(self) -> Result<()> {
        for group in self.groups {
            group.shutdown().await?;
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_quorum_round_recovers_after_a_600ms_stall_within_original_deadline() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.pause(Duration::from_millis(900));
    // Establish the pinned OpenRaft behavior directly, independent of our retry.
    let start = Instant::now();
    let initial = fixture.groups[0].raft().ensure_linearizable().await;
    assert!(matches!(
        initial,
        Err(RaftError::APIError(CheckIsLeaderError::QuorumNotEnough(_)))
    ));
    // Kasumi's network honors OpenRaft's soft TTL (3/4 of its 250 ms hard TTL).
    assert!(start.elapsed() >= Duration::from_millis(150));
    let probes = fixture.transport.probes.load(Ordering::SeqCst);
    let committed = fixture.groups[0].linearizable_barrier().await?.unwrap();
    assert!(
        fixture.transport.probes.load(Ordering::SeqCst) >= probes + 4,
        "must issue multiple fresh quorum rounds"
    );
    assert!(start.elapsed() >= Duration::from_millis(850));
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(
        fixture.groups[0]
            .raft()
            .metrics()
            .borrow()
            .last_applied
            .is_some_and(|applied| applied >= committed)
    );
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permanent_partition_exhausts_five_seconds_without_reducing_membership() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.pause(Duration::from_secs(60));
    let start = Instant::now();
    let error = fixture.groups[0].linearizable_barrier().await.unwrap_err();
    assert!(error.to_string().contains("deadline"));
    assert!(start.elapsed() >= Duration::from_millis(4_900));
    assert!(start.elapsed() < Duration::from_secs(6));
    assert_eq!(
        fixture.groups[0]
            .raft()
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .count(),
        3
    );
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_seal_interrupts_pending_quorum_probe_without_waiting_for_deadline() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.pause(Duration::from_secs(60));
    let start = Instant::now();
    let (barrier, ()) = tokio::join!(fixture.groups[0].linearizable_barrier(), async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        fixture.stores[0].application().seal();
    });
    assert!(barrier.is_err());
    assert!(start.elapsed() < Duration::from_millis(250));
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custody_key_seal_interrupts_pending_probe_and_denies_new_writes() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.pause(Duration::from_secs(60));
    let start = Instant::now();
    let (barrier, ()) = tokio::join!(fixture.groups[0].linearizable_barrier(), async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        fixture.stores[0].custody().store().seal();
    });
    assert!(barrier.is_err());
    assert!(start.elapsed() < Duration::from_millis(250));
    assert!(
        fixture.groups[0]
            .write(b"after custody seal".to_vec())
            .await
            .is_err()
    );
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn higher_term_stops_retry_and_never_releases_a_stale_read() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.pause(Duration::from_secs(60));
    let metrics = fixture.groups[0].raft().metrics().borrow().clone();
    let start = Instant::now();
    let (barrier, vote) = tokio::join!(fixture.groups[0].linearizable_barrier(), async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        fixture.groups[0]
            .raft()
            .append_entries(openraft::raft::AppendEntriesRequest {
                vote: openraft::Vote::new_committed(metrics.current_term + 1, 2),
                prev_log_id: metrics.last_applied,
                entries: vec![],
                leader_commit: metrics.last_applied,
            })
            .await
    });
    vote?;
    assert!(barrier.is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    fixture.close().await
}
