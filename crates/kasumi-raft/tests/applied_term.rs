mod common;

use anyhow::Result;
use async_trait::async_trait;
use kasumi_raft::test_utils::FixtureResult;
use kasumi_raft::{BasicNode, InProcessRouter, RaftGroup, RaftTransport, RpcRequest, RpcResponse};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

/// Drops every RPC sent by `silenced` and every append sent by `muted`.
#[derive(Default)]
struct Filter {
    router: InProcessRouter,
    silenced: AtomicU64,
    muted: AtomicU64,
}
#[async_trait]
impl RaftTransport for Filter {
    async fn send(
        &self,
        group: &str,
        source: u64,
        target: u64,
        node: &BasicNode,
        request: RpcRequest,
    ) -> Result<RpcResponse> {
        let muted =
            matches!(request, RpcRequest::Append(_)) && self.muted.load(Ordering::SeqCst) == source;
        if muted || self.silenced.load(Ordering::SeqCst) == source {
            anyhow::bail!("test transport dropped the RPC");
        }
        self.router.send(group, source, target, node, request).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn new_leader_admits_proposals_only_after_applying_its_own_term() -> FixtureResult<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let dir = kasumi_store::test_utils::private_tempdir()?;
    let transport = Arc::new(Filter::default());
    let mut groups = Vec::new();
    for id in 1..=3 {
        let store = common::store(
            &dir.path().join(format!("{id}.kv")),
            true,
            fixture_scratch.clone(),
            id,
            "applied-term",
        )
        .await?;
        let group = RaftGroup::open(
            id,
            "applied-term".into(),
            store,
            Arc::new(common::Backend::default()),
            transport.clone(),
            kasumi_raft::RaftGroupConfig {
                raft: kasumi_raft::Config {
                    enable_elect: false,
                    ..common::config()
                },
                limits: kasumi_raft::RaftLimits::default(),
            },
            common::snapshot_owner(),
        )
        .await?;
        transport
            .router
            .register("applied-term".into(), id, group.raft().clone());
        groups.push(group);
    }
    groups[0]
        .initialize((1..=3).map(|id| (id, BasicNode::new("test"))).collect())
        .await?;
    groups[0].raft().trigger().elect().await?;
    groups[0]
        .raft()
        .wait(Some(Duration::from_secs(5)))
        .current_leader(1, "first leader")
        .await?;
    groups[0]
        .write(kasumi_raft::ApplicationProposal::generated(
            b"first term".to_vec(),
        ))
        .await?;
    // The established leader applied its own term's first entry.
    let first = groups[0].current_term();
    assert_eq!(
        groups[0].admission_term(Duration::from_secs(5)).await,
        Some(first)
    );
    let applied = groups[0]
        .raft()
        .metrics()
        .borrow()
        .last_applied
        .map(|id| id.index);
    groups[1]
        .raft()
        .wait(Some(Duration::from_secs(5)))
        .applied_index_at_least(applied, "second node holds the first term")
        .await?;

    // Node 2 wins the next term once node 3's lease from node 1 expires, but
    // none of its appends arrive: its first entry never commits or applies.
    transport.silenced.store(1, Ordering::SeqCst);
    transport.muted.store(2, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(
        2 * common::config().election_timeout_max,
    ))
    .await;
    groups[1].raft().trigger().elect().await?;
    groups[1]
        .raft()
        .wait(Some(Duration::from_secs(5)))
        .current_leader(2, "second leader")
        .await?;
    assert_eq!(
        groups[1].admission_term(Duration::from_millis(500)).await,
        None
    );
    // A follower proceeds at once; OpenRaft redirects its write.
    assert_eq!(
        groups[2].admission_term(Duration::from_millis(100)).await,
        Some(groups[2].current_term())
    );

    transport.muted.store(0, Ordering::SeqCst);
    assert_eq!(
        groups[1].admission_term(Duration::from_secs(5)).await,
        Some(groups[1].current_term())
    );
    transport.silenced.store(0, Ordering::SeqCst);
    for group in groups {
        group.shutdown().await?;
    }
    Ok(())
}
