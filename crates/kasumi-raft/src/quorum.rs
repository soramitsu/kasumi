//! Fresh current-term quorum barrier shared by serving and closed custody.
use crate::{LogId, Raft};
use anyhow::{Context, Result, ensure};
use std::time::Duration;
async fn application_changed(seals: &mut Option<tokio::sync::watch::Receiver<u64>>) {
    match seals {
        Some(seals) => {
            let _ = seals.changed().await;
        }
        None => std::future::pending::<()>().await,
    }
}
pub(crate) async fn barrier(
    raft: &Raft,
    check: impl Fn() -> Result<()>,
    custody: &kasumi_store::TenantStore,
    application: Option<&kasumi_store::TenantStore>,
) -> Result<Option<LogId<u64>>> {
    check()?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let initial_term = raft.metrics().borrow().current_term;
    let mut seals = application.map(kasumi_store::TenantStore::seal_notifications);
    let mut custody_seals = custody.seal_notifications();
    tokio::time::timeout_at(deadline, async {
        loop {
            check()?;
            ensure!(
                raft.metrics().borrow().current_term == initial_term,
                "leadership term changed during read barrier"
            );
            // OpenRaft 0.9.25 bounds each leadership probe by one heartbeat
            // interval (250 ms in the server profile). A transient scheduling
            // or storage stall need not consume the whole API deadline.
            // Every round establishes a fresh quorum and waits for local
            // application; failed rounds grant no authority to read.
            let result = tokio::select! {
                result = raft.ensure_linearizable() => result,
                _ = application_changed(&mut seals) => {
                    check()?;
                    anyhow::bail!("key authorization changed during read barrier");
                }
                _ = custody_seals.changed() => {
                    check()?;
                    anyhow::bail!("custody key authorization changed during read barrier");
                }
            };
            match result {
                Ok(id) => {
                    check()?;
                    ensure!(
                        raft.metrics().borrow().current_term == initial_term,
                        "leadership term changed during read barrier"
                    );
                    return Ok(id);
                }
                Err(openraft::error::RaftError::APIError(
                    openraft::error::CheckIsLeaderError::QuorumNotEnough(_),
                )) => {
                    check()?;
                    // Immediate transport rejection must not busy-loop. The
                    // original deadline bounds all probes and backoff together.
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                        _ = application_changed(&mut seals) => {
                            check()?;
                            anyhow::bail!("key authorization changed during read barrier");
                        }
                        _ = custody_seals.changed() => {
                            check()?;
                            anyhow::bail!("custody key authorization changed during read barrier");
                        }
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await
    .context("read quorum deadline exceeded")?
}
