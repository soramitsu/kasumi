//! Exact proposal children outlive cancelled callers under process-local custody.
//! No join/reaper task exists: callers, subsequent admission and typed drain
//! observe the original BackgroundWork handle directly.
use super::{Command, ProposalWork, Reservation, WorkRegistration};
use crate::admission::NodeAdmission;
use kasumi_serving::{BackgroundWork, BackgroundWorkBudget};
use kasumi_types::{Error, ErrorCode, Result, drain::*};
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

const MAX_PROPOSALS: usize = 32;

#[derive(Default)]
pub(super) struct Jobs {
    state: Mutex<State>,
    // Registration and terminal failure use the same short synchronous gate.
    // A failed child closes it before releasing its final poll, including panic.
    closed: Arc<Mutex<bool>>,
}
#[derive(Default)]
struct State {
    #[cfg(test)]
    admitted: u64,
    slots: [Option<Arc<BackgroundWork>>; MAX_PROPOSALS],
    budget: Option<BackgroundWorkBudget>,
    report: DrainReport,
}

pub(super) struct Response {
    pub(super) bytes: Vec<u8>,
    // Preserve the original owners through response decoding and strict audit.
    _reservation: Reservation,
    _registration: Arc<WorkRegistration>,
}
pub(super) struct Call<T> {
    worker: Arc<BackgroundWork>,
    response: tokio::sync::oneshot::Receiver<T>,
}

struct TerminalFence {
    closed: Arc<Mutex<bool>>,
    completed: bool,
}
impl Drop for TerminalFence {
    fn drop(&mut self) {
        if !self.completed {
            *self.closed.lock().unwrap_or_else(|p| p.into_inner()) = true;
        }
    }
}

impl Jobs {
    fn required_bytes() -> anyhow::Result<u64> {
        BackgroundWorkBudget::required_bytes(MAX_PROPOSALS, 1)
    }

    fn observe_locked(&self, state: &mut State) {
        for slot in &mut state.slots {
            let Some(worker) = slot else { continue };
            match worker.observed() {
                Some(Ok(())) => {
                    *slot = None;
                }
                Some(Err(failure)) => {
                    state.report.merge(&failure);
                    *self.closed.lock().unwrap_or_else(|p| p.into_inner()) = true;
                }
                None => {}
            }
        }
    }

    pub(super) fn check(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.observe_locked(&mut state);
        if *self.closed.lock().unwrap_or_else(|p| p.into_inner()) {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "proposal work is closed; recovery required",
            ));
        }
        Ok(())
    }

    /// Lazily reserve the entire fixed registry before acquiring a command's
    /// operation slot. Custody retains this same real node charge if the public
    /// Database is dropped. No replacement/default governor is introduced.
    pub(super) fn prepare(&self, admission: &Arc<NodeAdmission>) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.observe_locked(&mut state);
        if *self.closed.lock().unwrap_or_else(|p| p.into_inner()) {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "proposal work is closed; recovery required",
            ));
        }
        if state.budget.is_none() {
            let bytes = Self::required_bytes().map_err(|_| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "proposal metadata budget overflow",
                )
            })?;
            let mut charge = admission.reserve(bytes, None)?;
            charge.retain(bytes);
            state.budget = Some(
                BackgroundWorkBudget::new(MAX_PROPOSALS, Arc::new(charge)).map_err(|_| {
                    Error::new(
                        ErrorCode::ResourceExhausted,
                        "proposal metadata budget unavailable",
                    )
                })?,
            );
        }
        Ok(())
    }

    pub(super) fn start(
        &self,
        mut work: ProposalWork,
        command: Command,
        max_bytes: usize,
    ) -> Result<Call<Response>> {
        self.start_task(Box::pin(async move {
            let bytes = work.run(command, max_bytes).await?;
            work._reservation.retain_workspace();
            Ok(Response {
                bytes,
                _reservation: work._reservation,
                _registration: work._registration,
            })
        }))
    }

    fn start_task<T: Send + 'static>(
        &self,
        task: impl Future<Output = anyhow::Result<T>> + Send + 'static,
    ) -> Result<Call<T>> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.observe_locked(&mut state);
        let closed = self.closed.lock().unwrap_or_else(|p| p.into_inner());
        if *closed {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "proposal work is closed; recovery required",
            ));
        }
        let slot = state
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| Error::new(ErrorCode::ResourceExhausted, "proposal registry is full"))?;
        let budget = state.budget.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::Unavailable,
                "proposal registry has no memory reservation",
            )
        })?;
        #[cfg(test)]
        let admitted = state
            .admitted
            .checked_add(1)
            .expect("test admission sequence");
        let worker = Arc::new(BackgroundWork::default());
        let (sender, response) = tokio::sync::oneshot::channel();
        let admission = self.closed.clone();
        worker
            .start_result(
                async move {
                    let mut terminal = TerminalFence {
                        closed: admission,
                        completed: false,
                    };
                    let response = task.await?;
                    // Receiver cancellation discards the result and its original owners
                    // here; it never cancels or replaces the admitted proposal itself.
                    let _ = sender.send(response);
                    terminal.completed = true;
                    Ok(())
                },
                budget,
            )
            .map_err(|_| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "proposal custody admission failed",
                )
            })?;
        state.slots[slot] = Some(worker.clone());
        #[cfg(test)]
        {
            state.admitted = admitted;
        }
        Ok(Call { worker, response })
    }

    /// Drive this request through any asynchronous preflight until this registry
    /// owns its actual child. Tests hold the ordered proposal gate and submit no
    /// other requests concurrently. A prior completed slot cannot satisfy this
    /// boundary, and an initial Pending read is not mistaken for admission.
    #[cfg(test)]
    pub(super) async fn wait_for_admission<F: Future>(&self, mut request: std::pin::Pin<&mut F>) {
        let before = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .admitted;
        std::future::poll_fn(|cx| {
            assert!(
                request.as_mut().poll(cx).is_pending(),
                "request completed before the gated proposal admission boundary"
            );
            if self
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .admitted
                > before
            {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
    }

    pub(super) async fn drain(&self) -> DrainResult {
        let workers = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            *self.closed.lock().unwrap_or_else(|p| p.into_inner()) = true;
            state.slots.clone()
        };
        let mut retained = None;
        for (index, worker) in workers.into_iter().enumerate() {
            let Some(worker) = worker else { continue };
            let outcome = worker.drain().await;
            // Publish each exact terminal outcome before awaiting another child.
            // A cancelled drain leaves pending handles and prior errors owned.
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Err(failure) = outcome {
                state.report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                    continue;
                }
            }
            if state.slots[index]
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &worker))
            {
                state.slots[index] = None;
            }
        }
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if retained.is_none() && state.report.issues().is_empty() {
            state.budget = None;
        }
        state.report.outcome(retained)
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl super::Database {
    /// Exact lazily retained proposal registry charge for fixture accounting.
    pub fn fixture_proposal_metadata_bytes() -> anyhow::Result<u64> {
        Jobs::required_bytes()
    }
}

impl<T> Call<T> {
    pub(super) async fn wait(self, timeout: Duration) -> Result<T> {
        tokio::time::timeout(timeout, async move {
            self.worker.drain().await.map_err(|_| {
                Error::new(
                    ErrorCode::UnknownOutcome,
                    "write task failed; resolve or retry with the same idempotency key",
                )
            })?;
            self.response.await.map_err(|_| {
                Error::new(
                    ErrorCode::UnknownOutcome,
                    "write result unavailable; resolve or retry with the same idempotency key",
                )
            })
        })
        .await
        .map_err(|_| {
            Error::new(
                ErrorCode::UnknownOutcome,
                "write deadline exceeded; resolve or retry with the same idempotency key",
            )
        })?
    }
}

#[cfg(test)]
#[path = "proposal_jobs_tests.rs"]
mod tests;
