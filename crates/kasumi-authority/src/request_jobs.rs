//! Exact accepted request children remain in bounded custody when their caller
//! disappears. The registry stores no response fence or authority back-reference.
use super::*;
use kasumi_types::drain::{DrainCompletion, DrainFailure, DrainReport, DrainResult};
use std::future::Future;
use tokio::sync::oneshot;

pub const AUTHORITY_REQUEST_SLOTS: usize = 32;

/// Reserve this metadata before opening the authority. The trusted installer
/// supplies the actual retained node-memory charge to BackgroundWorkBudget.
pub fn authority_request_metadata_bytes() -> anyhow::Result<u64> {
    BackgroundWorkBudget::required_bytes(AUTHORITY_REQUEST_SLOTS, 1)
}

type TerminalOutcome = Result<()>;
struct RequestJob {
    child: Arc<BackgroundWork>,
    outcome: Arc<Mutex<Option<TerminalOutcome>>>,
}
struct Registry {
    jobs: Vec<Option<Arc<RequestJob>>>,
    report: DrainReport,
}
pub(super) struct RequestJobs {
    budget: BackgroundWorkBudget,
    registry: Mutex<Registry>,
    draining: tokio::sync::Mutex<()>,
}

/// Fence immediately while the actual worker unwinds. Cancellation is fenced
/// when its exact JoinError is observed. Neither claims resources drained: the
/// original JoinError stays in BackgroundWork custody until actually reported.
struct ExecutionGuard {
    requests: Arc<Semaphore>,
    returned: bool,
}
impl Drop for ExecutionGuard {
    fn drop(&mut self) {
        if !self.returned && std::thread::panicking() {
            self.requests.close();
        }
    }
}

impl RequestJobs {
    pub(super) fn close(&self, requests: &Semaphore) {
        // Serialize closure with handle publication. A shutdown census cannot
        // pass an empty slot while an already admitted caller is installing it.
        let _registry = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        requests.close();
    }

    #[cfg(test)]
    pub(super) fn registered(&self) -> usize {
        self.registry.lock().unwrap().jobs.iter().flatten().count()
    }

    pub(super) fn new(budget: BackgroundWorkBudget) -> anyhow::Result<Self> {
        ensure!(
            budget.max_registered() == AUTHORITY_REQUEST_SLOTS,
            "authority request metadata must reserve its exact complete slot inventory"
        );
        Ok(Self {
            budget,
            registry: Mutex::new(Registry {
                jobs: (0..AUTHORITY_REQUEST_SLOTS).map(|_| None).collect(),
                report: DrainReport::default(),
            }),
            draining: tokio::sync::Mutex::new(()),
        })
    }

    /// Actual nonblocking joins reclaim only normally terminated cells. Panic
    /// diagnostics stay installed, and their original Arc identity survives all
    /// request admission and shutdown retries.
    pub(super) fn observe(&self, requests: &Semaphore) {
        let mut registry = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        for index in 0..registry.jobs.len() {
            let Some(job) = registry.jobs[index].clone() else {
                continue;
            };
            match job.child.observed() {
                None => {}
                Some(Err(failure)) => {
                    requests.close();
                    registry.report.merge(&failure);
                }
                Some(Ok(())) => {
                    // A normal rejection is a completed request outcome, not a
                    // failed resource drain. Its permanent identity is resolved
                    // through the existing authoritative receipt/journal API.
                    let outcome = job.outcome.lock().unwrap_or_else(|p| p.into_inner());
                    if outcome.is_some() {
                        registry.jobs[index] = None;
                    } else {
                        requests.close();
                        registry.report.record(
                            "authority request outcome",
                            index,
                            anyhow::anyhow!("joined request has no terminal operation outcome"),
                        );
                    }
                }
            }
        }
    }

    pub(super) fn submit<T: Send + 'static>(
        &self,
        requests: Arc<Semaphore>,
        task: impl Future<Output = Result<T>> + Send + 'static,
    ) -> Result<(Arc<BackgroundWork>, oneshot::Receiver<Result<T>>)> {
        self.observe(&requests);
        if requests.is_closed() {
            return Err(unavailable("authority request admission is closed"));
        }
        let mut registry = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        if requests.is_closed() {
            return Err(unavailable("authority request admission is closed"));
        }
        let slot = registry
            .jobs
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "authority child registry is full",
                )
            })?;
        let child = Arc::new(BackgroundWork::default());
        let outcome = Arc::new(Mutex::new(None));
        let observed = outcome.clone();
        let (send, receive) = oneshot::channel();
        let mut guard = ExecutionGuard {
            requests,
            returned: false,
        };
        child
            .start(
                async move {
                    let result = task.await;
                    *observed.lock().unwrap_or_else(|p| p.into_inner()) =
                        Some(result.as_ref().map(|_| ()).map_err(Clone::clone));
                    // A dropped receiver destroys the undelivered response here,
                    // including its original request capacity/response fence.
                    // No response or authority Arc is stored in the registry.
                    let _ = send.send(result);
                    guard.returned = true;
                },
                &self.budget,
            )
            .map_err(unavailable)?;
        registry.jobs[slot] = Some(Arc::new(RequestJob {
            child: child.clone(),
            outcome,
        }));
        Ok((child, receive))
    }

    pub(super) async fn drain(&self, requests: &Semaphore) -> DrainResult {
        self.close(requests);
        let _serial = self.draining.lock().await;
        let mut retained = None;
        for index in 0..AUTHORITY_REQUEST_SLOTS {
            let job = self.registry.lock().unwrap_or_else(|p| p.into_inner()).jobs[index].clone();
            let Some(job) = job else { continue };
            // The handle remains in BackgroundWork across cancellation of this
            // await. Publish observed errors before awaiting a different child.
            let outcome = job.child.drain().await;
            let mut registry = self.registry.lock().unwrap_or_else(|p| p.into_inner());
            if let Err(failure) = outcome {
                registry.report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
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

impl IndependentAuthority {
    async fn accepted_request<T: Send + 'static>(
        self: &Arc<Self>,
        deadline: tokio::time::Instant,
        task: impl Future<Output = Result<T>> + Send + 'static,
    ) -> Result<T> {
        if tokio::time::Instant::now() >= deadline {
            return Err(unavailable(
                "authority request deadline expired before dispatch",
            ));
        }
        let (child, receive) = self.request_jobs.submit(self.requests.clone(), task)?;
        tokio::time::timeout_at(deadline, async {
            let result = receive.await;
            // Keep the real JoinError, including its original panic payload, in
            // registry custody even when the response channel closed first.
            if let Err(failure) = child.drain().await {
                self.requests.close();
                return Err(unknown(failure));
            }
            result.map_err(unknown)?
        })
        .await
        .map_err(unknown)?
    }
}
