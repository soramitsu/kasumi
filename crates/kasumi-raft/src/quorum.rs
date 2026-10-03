//! Fresh current-term quorum barrier shared by serving and closed custody, and
//! the read-only observation barrier that extends it to followers and learners.
use crate::{LogId, Raft, RaftTransport, ReadIndexResponse, RpcRequest, RpcResponse};
use anyhow::{Context, Result, bail, ensure};
use std::time::Duration;
use tokio::time::Instant;

/// One bound for every probe, backoff and application wait of a barrier.
pub(crate) const BARRIER_DEADLINE: Duration = Duration::from_secs(5);
/// One read-index request to the leader, including its quorum heartbeat round
/// (one 250 ms heartbeat interval in the server profile). A later answer is
/// dropped with its request and can never release an observation.
const READ_INDEX_ROUND: Duration = Duration::from_millis(250);
const TERM_CHANGED: &str = "leadership term changed during read barrier";

/// Key-lease seal notifications. Either interrupts a pending round or wait at
/// once; the caller's access check then reports the exact revoked grant.
struct Seals {
    application: Option<tokio::sync::watch::Receiver<u64>>,
    custody: tokio::sync::watch::Receiver<u64>,
}
impl Seals {
    fn new(
        custody: &kasumi_store::TenantStore,
        application: Option<&kasumi_store::TenantStore>,
    ) -> Self {
        Self {
            application: application.map(kasumi_store::TenantStore::seal_notifications),
            custody: custody.seal_notifications(),
        }
    }
    async fn changed(&mut self) -> &'static str {
        let Self {
            application,
            custody,
        } = self;
        let application = async {
            match application {
                Some(seals) => {
                    let _ = seals.changed().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = application => "key authorization changed during read barrier",
            _ = custody.changed() => "custody key authorization changed during read barrier",
        }
    }
    /// Backoff after an immediate rejection, so a retry never busy-loops.
    async fn backoff(&mut self, delay: Duration, check: &impl Fn() -> Result<()>) -> Result<()> {
        tokio::select! {
            _ = tokio::time::sleep(delay) => Ok(()),
            reason = self.changed() => {
                check()?;
                bail!(reason)
            }
        }
    }
}

pub(crate) async fn barrier(
    raft: &Raft,
    check: impl Fn() -> Result<()>,
    custody: &kasumi_store::TenantStore,
    application: Option<&kasumi_store::TenantStore>,
) -> Result<Option<LogId<u64>>> {
    let deadline = Instant::now() + BARRIER_DEADLINE;
    barrier_until(raft, check, custody, application, deadline).await
}

async fn barrier_until(
    raft: &Raft,
    check: impl Fn() -> Result<()>,
    custody: &kasumi_store::TenantStore,
    application: Option<&kasumi_store::TenantStore>,
    deadline: Instant,
) -> Result<Option<LogId<u64>>> {
    check()?;
    let initial_term = raft.metrics().borrow().current_term;
    let mut seals = Seals::new(custody, application);
    tokio::time::timeout_at(deadline, async {
        loop {
            check()?;
            ensure!(
                raft.metrics().borrow().current_term == initial_term,
                TERM_CHANGED
            );
            // OpenRaft 0.9.25 bounds each leadership probe by one heartbeat
            // interval (250 ms in the server profile). A transient scheduling
            // or storage stall need not consume the whole API deadline.
            // Every round establishes a fresh quorum and waits for local
            // application; failed rounds grant no authority to read.
            let result = tokio::select! {
                result = raft.ensure_linearizable() => result,
                reason = seals.changed() => {
                    check()?;
                    bail!(reason);
                }
            };
            match result {
                Ok(id) => {
                    check()?;
                    ensure!(
                        raft.metrics().borrow().current_term == initial_term,
                        TERM_CHANGED
                    );
                    return Ok(id);
                }
                Err(openraft::error::RaftError::APIError(
                    openraft::error::CheckIsLeaderError::QuorumNotEnough(_),
                )) => {
                    check()?;
                    // Immediate transport rejection must not busy-loop. The
                    // original deadline bounds all probes and backoff together.
                    seals.backoff(Duration::from_millis(10), &check).await?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await
    .context("read quorum deadline exceeded")?
}

/// How a follower or learner reaches its current leader for a read index.
pub(crate) struct ReadIndexRoute<'a> {
    pub(crate) local: u64,
    pub(crate) group: &'a str,
    pub(crate) transport: &'a dyn RaftTransport,
}

/// Read-only observation barrier for any current member. A leader runs the
/// fresh quorum barrier above. A follower or learner asks its current-term
/// leader for a read index, which the leader returns only after confirming
/// its leadership with a fresh quorum round, then waits until local
/// application reaches that index. Every round, the application wait and the
/// release share one deadline and fail closed on a term change, a key seal, a
/// failed access check or a stopped core. It grants no authority to propose.
pub(crate) async fn observation_barrier(
    raft: &Raft,
    route: ReadIndexRoute<'_>,
    check: impl Fn() -> Result<()>,
    custody: &kasumi_store::TenantStore,
    application: Option<&kasumi_store::TenantStore>,
    within: Duration,
) -> Result<Option<LogId<u64>>> {
    check()?;
    let deadline = Instant::now() + within;
    let (initial_term, leader) = {
        let metrics = raft.metrics();
        let metrics = metrics.borrow();
        (metrics.current_term, metrics.current_leader)
    };
    if leader == Some(route.local) {
        return barrier_until(raft, check, custody, application, deadline).await;
    }
    let mut seals = Seals::new(custody, application);
    tokio::time::timeout_at(deadline, async {
        loop {
            check()?;
            let (term, leader) = {
                let metrics = raft.metrics();
                let metrics = metrics.borrow();
                let leader = metrics.current_leader.and_then(|leader| {
                    let node = metrics.membership_config.membership().get_node(&leader);
                    node.map(|node| (leader, node.clone()))
                });
                (metrics.current_term, leader)
            };
            ensure!(term == initial_term, TERM_CHANGED);
            let Some((leader, node)) = leader else {
                // No leader is known in this term yet; an election or the
                // first heartbeat must come first.
                seals.backoff(Duration::from_millis(25), &check).await?;
                continue;
            };
            // A node becomes leader only after its own campaign in this term;
            // the barrier it started as a follower no longer describes it.
            ensure!(
                leader != route.local,
                "local node became leader during observation barrier"
            );
            let request = route.transport.send(
                route.group,
                route.local,
                leader,
                &node,
                RpcRequest::ReadIndex { term },
            );
            let answer = tokio::select! {
                answer = tokio::time::timeout(READ_INDEX_ROUND, request) => answer,
                reason = seals.changed() => {
                    check()?;
                    bail!(reason);
                }
            };
            match answer {
                Ok(Ok(RpcResponse::ReadIndex(Ok(answer)))) => {
                    let read_log_id = answer_in_term(answer, initial_term)?;
                    wait_applied(raft, initial_term, read_log_id, &mut seals, &check).await?;
                    check()?;
                    ensure!(
                        raft.metrics().borrow().current_term == initial_term,
                        TERM_CHANGED
                    );
                    return Ok(read_log_id);
                }
                Ok(Ok(RpcResponse::ReadIndex(Err(_)))) | Ok(Err(_)) | Err(_) => {
                    // Not leader, lost quorum, stopped or unreachable leader,
                    // or no answer within the round. None grants a read; the
                    // original deadline bounds all rounds and backoff.
                    check()?;
                    seals.backoff(Duration::from_millis(25), &check).await?;
                }
                Ok(Ok(_)) => bail!("unexpected read-index response"),
            }
        }
    })
    .await
    .context("observation barrier deadline exceeded")?
}

fn answer_in_term(answer: ReadIndexResponse, term: u64) -> Result<Option<LogId<u64>>> {
    ensure!(
        answer.term == term,
        "read index was confirmed in another leadership term"
    );
    Ok(answer.read_log_id)
}

async fn wait_applied(
    raft: &Raft,
    term: u64,
    read_log_id: Option<LogId<u64>>,
    seals: &mut Seals,
    check: &impl Fn() -> Result<()>,
) -> Result<()> {
    let target = read_log_id.map(|id| id.index);
    let mut metrics = raft.metrics();
    loop {
        {
            let current = metrics.borrow_and_update();
            if let Err(fatal) = &current.running_state {
                return Err(fatal.clone().into());
            }
            ensure!(current.current_term == term, TERM_CHANGED);
            if current.last_applied.map(|id| id.index) >= target {
                return Ok(());
            }
        }
        tokio::select! {
            changed = metrics.changed() => {
                changed.context("Raft core ended during observation barrier")?;
            }
            reason = seals.changed() => {
                check()?;
                bail!(reason);
            }
        }
    }
}
