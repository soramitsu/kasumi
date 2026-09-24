//! Bounded custody for accepted Raft membership commands. The command result
//! stays in this registry until its caller has joined the actual child or the
//! installed Administration drain has observed it.
use anyhow::{Result, ensure};
use kasumi_engine::admission::NodeAdmission;
use kasumi_serving::{BackgroundWork, BackgroundWorkBudget};
use kasumi_types::drain::{DrainCompletion, DrainFailure, DrainReport, DrainResult};
use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Mutex as AsyncMutex, oneshot, watch};

pub(super) const COMMAND_SLOTS: usize = 16;

pub(super) fn metadata_bytes() -> Result<u64> {
    BackgroundWorkBudget::required_bytes(COMMAND_SLOTS, 1)
}

fn unknown(message: &'static str) -> anyhow::Error {
    kasumi_types::Error::new(kasumi_types::ErrorCode::UnknownOutcome, message).into()
}

struct Outcome {
    value: Mutex<Option<Result<()>>>,
    delivered: AtomicBool,
    consumed: AtomicBool,
}
impl Outcome {
    fn new() -> Self {
        Self {
            value: Mutex::new(None),
            delivered: AtomicBool::new(false),
            consumed: AtomicBool::new(false),
        }
    }
    fn take(&self) -> Option<Result<()>> {
        let value = self.value.lock().unwrap_or_else(|p| p.into_inner()).take();
        if value.is_some() {
            self.consumed.store(true, Ordering::Release);
        }
        value
    }
}
struct CommandJob {
    child: Arc<BackgroundWork>,
    outcome: Arc<Outcome>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Turn {
    Pending,
    Completed,
    Blocked,
}

/// A successor waits for the exact preceding accepted child, not for whichever
/// Tokio task happened to poll the mutex first. A closed sender is a failed
/// predecessor, including an abort before its future was ever polled.
async fn predecessor_completed(mut preceding: Option<watch::Receiver<Turn>>) -> bool {
    let Some(preceding) = preceding.as_mut() else {
        return true;
    };
    loop {
        let turn = *preceding.borrow_and_update();
        match turn {
            Turn::Completed => return true,
            Turn::Blocked => return false,
            Turn::Pending => {}
        }
        if preceding.changed().await.is_err() {
            return false;
        }
    }
}

struct Registry {
    jobs: Vec<Option<Arc<CommandJob>>>,
    // Published only after a child starts. Reclaimed slots do not change this
    // predecessor chain; each watch cell retains just one bounded turn state.
    tail: Option<watch::Receiver<Turn>>,
    report: DrainReport,
}
pub(super) struct CommandJobs {
    budget: BackgroundWorkBudget,
    registry: Mutex<Registry>,
    draining: AsyncMutex<()>,
    closed: Arc<AtomicBool>,
}

// A panic or abort fences later command admission and releases successors with
// Blocked. The exact JoinError remains in BackgroundWork custody.
struct ExecutionGuard {
    closed: Arc<AtomicBool>,
    turn: watch::Sender<Turn>,
    returned: bool,
}
impl ExecutionGuard {
    fn finish(&mut self, turn: Turn) {
        if turn == Turn::Blocked {
            self.closed.store(true, Ordering::Release);
        }
        let _ = self.turn.send(turn);
        self.returned = true;
    }
}
impl Drop for ExecutionGuard {
    fn drop(&mut self) {
        if !self.returned {
            self.closed.store(true, Ordering::Release);
            let _ = self.turn.send(Turn::Blocked);
        }
    }
}

impl CommandJobs {
    pub(super) fn new(admission: &Arc<NodeAdmission>) -> Result<Self> {
        // Charge the installed memory core, not the facade: the budget lives in
        // Administration and must not form an admission-facade ownership cycle.
        let charge = admission.memory().reserve_resident(metadata_bytes()?)?;
        let budget = BackgroundWorkBudget::new(COMMAND_SLOTS, Arc::new(charge))?;
        ensure!(
            budget.max_registered() == COMMAND_SLOTS,
            "membership command inventory differs from its admitted budget"
        );
        let mut jobs = Vec::new();
        jobs.try_reserve_exact(COMMAND_SLOTS)?;
        jobs.resize_with(COMMAND_SLOTS, || None);
        Ok(Self {
            budget,
            registry: Mutex::new(Registry {
                jobs,
                tail: None,
                report: DrainReport::default(),
            }),
            draining: AsyncMutex::new(()),
            closed: Arc::new(AtomicBool::new(false)),
        })
    }

    pub(super) fn close(&self) {
        // Publication and closure share this synchronous lock. A shutdown
        // census cannot pass a vacant slot while an accepted child installs it.
        let _registry = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        self.closed.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) fn registered(&self) -> usize {
        self.registry
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .jobs
            .iter()
            .flatten()
            .count()
    }

    // Completed claimed commands reclaim slots. Unclaimed outcomes stay in the
    // fixed inventory until shutdown records the original Result. A failed
    // child also stays installed so its exact JoinError survives retry.
    pub(super) fn observe(&self) {
        let mut registry = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        for index in 0..COMMAND_SLOTS {
            let Some(job) = registry.jobs[index].clone() else {
                continue;
            };
            match job.child.observed() {
                None => {}
                Some(Err(_failure)) => {
                    // Seal admission, but leave the exact terminal issue in its
                    // child until drain merges it once. Repeated probes must
                    // not grow the retained report.
                    self.closed.store(true, Ordering::Release);
                }
                Some(Ok(())) => {
                    if job.outcome.consumed.load(Ordering::Acquire) {
                        registry.jobs[index] = None;
                    } else if !job.outcome.delivered.load(Ordering::Acquire) {
                        // Drain records the missing outcome once, after joining
                        // this exact child. The slot cannot be reclaimed here.
                        self.closed.store(true, Ordering::Release);
                    }
                }
            }
        }
    }

    fn submit(
        &self,
        task: impl Future<Output = Result<()>> + Send + 'static,
    ) -> Result<(Arc<CommandJob>, oneshot::Receiver<()>)> {
        self.observe();
        let mut registry = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            !self.closed.load(Ordering::Acquire),
            kasumi_types::Error::new(
                kasumi_types::ErrorCode::Unavailable,
                "membership command admission is closed"
            )
        );
        let index = registry
            .jobs
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| {
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::ResourceExhausted,
                    "membership command child registry is full",
                )
            })?;
        let child = Arc::new(BackgroundWork::default());
        let outcome = Arc::new(Outcome::new());
        let delivered = outcome.clone();
        let closed = self.closed.clone();
        // The registry lock assigns an exact predecessor at admission. Its tail
        // changes only after start succeeds, so a rejected spawn cannot break
        // the chain of already accepted children.
        let preceding = registry.tail.clone();
        let (turn, tail) = watch::channel(Turn::Pending);
        let (send, receive) = oneshot::channel();
        child.start(
            async move {
                let mut guard = ExecutionGuard {
                    closed: closed.clone(),
                    turn,
                    returned: false,
                };
                if !predecessor_completed(preceding).await || closed.load(Ordering::Acquire) {
                    *delivered.value.lock().unwrap_or_else(|p| p.into_inner()) =
                        Some(Err(kasumi_types::Error::new(
                            kasumi_types::ErrorCode::Unavailable,
                            "membership command was not dispatched after admission closed",
                        )
                        .into()));
                    delivered.delivered.store(true, Ordering::Release);
                    let _ = send.send(());
                    guard.finish(Turn::Blocked);
                    return;
                }
                let result = task.await;
                *delivered.value.lock().unwrap_or_else(|p| p.into_inner()) = Some(result);
                delivered.delivered.store(true, Ordering::Release);
                let _ = send.send(());
                // The next accepted child may dispatch only after the exact
                // preceding task and outcome publication have finished.
                guard.finish(Turn::Completed);
            },
            &self.budget,
        )?;
        let job = Arc::new(CommandJob { child, outcome });
        registry.jobs[index] = Some(job.clone());
        registry.tail = Some(tail);
        Ok((job, receive))
    }

    pub(super) async fn execute(
        &self,
        deadline: tokio::time::Instant,
        task: impl Future<Output = Result<()>> + Send + 'static,
        timeout_message: &'static str,
    ) -> Result<()> {
        if tokio::time::Instant::now() >= deadline {
            return Err(unknown(timeout_message));
        }
        let (job, receive) = self.submit(task)?;
        tokio::time::timeout_at(deadline, async {
            receive
                .await
                .map_err(|_| unknown("membership command child stopped before its outcome"))?;
            if let Err(failure) = job.child.drain().await {
                self.closed.store(true, Ordering::Release);
                return Err(unknown(match failure.completion() {
                    DrainCompletion::Complete => {
                        "membership command child failed; inspect membership"
                    }
                    DrainCompletion::Retained => {
                        "membership command child remains unjoined; inspect membership"
                    }
                }));
            }
            Ok(())
        })
        .await
        .map_err(|_| unknown(timeout_message))??;
        if tokio::time::Instant::now() >= deadline {
            return Err(unknown(timeout_message));
        }
        // There is no await after taking the original error. If shutdown won
        // the race to consume it, that owner reports the original and this
        // caller receives uncertainty instead of an invented operation result.
        job.outcome.take().ok_or_else(|| {
            unknown("membership command result was consumed by shutdown; inspect membership")
        })?
    }

    pub(super) async fn drain(&self) -> DrainResult {
        self.close();
        let _serial = self.draining.lock().await;
        let mut retained = None;
        for index in 0..COMMAND_SLOTS {
            let job = self.registry.lock().unwrap_or_else(|p| p.into_inner()).jobs[index].clone();
            let Some(job) = job else { continue };
            let joined = job.child.drain().await;
            let mut registry = self.registry.lock().unwrap_or_else(|p| p.into_inner());
            if let Err(failure) = &joined {
                registry.report.merge(failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure.clone());
                }
            }
            if matches!(&joined, Err(failure) if failure.completion() == DrainCompletion::Retained)
            {
                continue;
            }
            if let Some(Err(error)) = job.outcome.take() {
                registry.report.record("membership command", index, error);
            }
            if joined.is_ok() && !job.outcome.delivered.load(Ordering::Acquire) {
                retained = Some(DrainFailure::retained(registry.report.record(
                    "membership command outcome",
                    index,
                    anyhow::anyhow!("joined command has no published terminal outcome"),
                )));
                continue;
            }
            if job.child.drained() {
                registry.jobs[index] = None;
            }
        }
        self.registry
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .report
            .outcome(retained)
    }
}

#[cfg(test)]
#[path = "administration_command_jobs_tests.rs"]
mod tests;
