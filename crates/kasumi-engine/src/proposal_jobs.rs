//! Exact proposal children outlive cancelled callers under process-local custody.
//! No join/reaper task exists: callers, subsequent admission and typed drain
//! observe the original BackgroundWork handle directly.
use super::{
    ProposalBudget, ProposalWork, Reservation, WorkRegistration, proposal_input::ProposalCommand,
};
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
    // Queue backing retires before State's exact metadata credit on drop.
    // Detached children retain their own shared registry credit until finished.
    queue: Arc<Mutex<std::collections::VecDeque<super::proposal_group::Queued>>>,
    state: Mutex<State>,
    entry_queue: tokio::sync::Mutex<()>,
    changed: tokio::sync::Notify,
    // Registration and terminal failure use the same short synchronous gate.
    // A failed child closes it before releasing its final poll, including panic.
    closed: Arc<Mutex<bool>>,
    #[cfg(test)]
    before_gate: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}
#[derive(Default)]
struct State {
    #[cfg(test)]
    admitted: u64,
    slots: [Option<Arc<BackgroundWork>>; MAX_PROPOSALS],
    reserved: [bool; MAX_PROPOSALS],
    budget: Option<BackgroundWorkBudget>,
    report: DrainReport,
}

/// One already-free registry position; no child has been dispatched. Dropping
/// a cancelled or refused preflight makes the exact position available again.
pub(super) struct Entry<'a> {
    jobs: &'a Jobs,
    slot: usize,
    installed: bool,
}
impl Drop for Entry<'_> {
    fn drop(&mut self) {
        if !self.installed {
            self.jobs
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .reserved[self.slot] = false;
            self.jobs.changed.notify_waiters();
        }
    }
}

pub(super) struct Response {
    pub(super) bytes: Vec<u8>,
    // Preserve the original owners through response decoding and strict audit.
    _registration: Arc<WorkRegistration>,
    // LAST: response/registration backing precedes the same original credit.
    _reservation: ProposalBudget,
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

fn missing_response() -> anyhow::Error {
    anyhow::anyhow!("proposal batch driver failed; its original failure is retained")
}

impl Jobs {
    /// Wait with only the caller's separately charged input, without growing
    /// this fixed registry. The short entry queue orders capacity waiters; it
    /// is released before the command's execution or any network workflow.
    pub(super) async fn entry(&self, admission: &Arc<NodeAdmission>) -> Result<Entry<'_>> {
        let _turn = self.entry_queue.lock().await;
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let workers = {
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                self.observe_locked(&mut state);
                if *self.closed.lock().unwrap_or_else(|p| p.into_inner()) {
                    return Err(Error::new(
                        ErrorCode::Unavailable,
                        "proposal work is closed; recovery required",
                    ));
                }
                if let Some(slot) = state
                    .slots
                    .iter()
                    .enumerate()
                    .position(|(slot, worker)| worker.is_none() && !state.reserved[slot])
                {
                    state.reserved[slot] = true;
                    return Ok(Entry {
                        jobs: self,
                        slot,
                        installed: false,
                    });
                }
                state.slots.clone()
            };
            if let Some(worker) = workers.iter().flatten().next() {
                let count = workers.iter().flatten().count();
                let future_bytes =
                    kasumi_query::vec_bytes::<u8>(std::mem::size_of_val(&worker.drain()))?;
                let bytes = future_bytes
                    .checked_mul(count as u64)
                    // Each pinned Box contains one concrete sized future, so
                    // its Vec element is exactly one pointer, not a trait object.
                    .and_then(|bytes| {
                        bytes.checked_add(kasumi_query::vec_bytes::<usize>(count).ok()?)
                    })
                    .and_then(|bytes| bytes.checked_add(4096))
                    .ok_or_else(|| {
                        Error::new(
                            ErrorCode::ResourceExhausted,
                            "proposal wait workspace overflow",
                        )
                    })?;
                let mut workspace = admission.reserve(bytes, None)?;
                workspace.retain(bytes);
                let mut waits: Vec<_> = workers
                    .iter()
                    .flatten()
                    .map(|worker| Box::pin(worker.drain()))
                    .collect();
                // Await any exact join, not the lowest numbered registry slot.
                // A child notification can precede Tokio's completed handle;
                // these futures are woken by the actual owned JoinHandles.
                // Cancelling the wait preserves every registered child.
                tokio::select! {
                    _ = std::future::poll_fn(|cx| {
                        for wait in &mut waits {
                            if wait.as_mut().poll(cx).is_ready() {
                                return std::task::Poll::Ready(());
                            }
                        }
                        std::task::Poll::Pending
                    }) => {},
                    _ = &mut changed => {},
                }
            } else {
                changed.await;
            }
        }
    }
    fn required_bytes() -> anyhow::Result<u64> {
        BackgroundWorkBudget::required_bytes(MAX_PROPOSALS, 1)?
            .checked_add(
                std::mem::size_of::<super::proposal_group::Queued>() as u64
                    * MAX_PROPOSALS as u64
                    * 2,
            )
            .and_then(|bytes| {
                bytes.checked_add(
                    kasumi_types::SharedBudgetCharge::required_bytes::<Reservation>().ok()?,
                )
            })
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput).into())
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
                BackgroundWorkBudget::new(
                    MAX_PROPOSALS,
                    kasumi_types::SharedBudgetCharge::new(charge),
                )
                .map_err(|_| {
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
        work: ProposalWork,
        command: ProposalCommand,
        max_bytes: usize,
        entry: Option<Entry<'_>>,
    ) -> Result<Call<Response>> {
        let queue = self.queue.clone();
        let gate = work.admission_gate.clone();
        #[cfg(test)]
        let before_gate = self.before_gate.lock().unwrap().take();
        self.start_task_at(
            Box::pin(async move {
                let (send, mut receive) = tokio::sync::oneshot::channel();
                queue.lock().unwrap_or_else(|p| p.into_inner()).push_back(
                    super::proposal_group::Queued {
                        work,
                        command,
                        max_bytes,
                        send,
                    },
                );
                #[cfg(test)]
                if let Some(wait) = before_gate {
                    let _ = wait.await;
                }
                // Caller cancellation never cancels this registered child. A
                // driver owns every dequeued original through its response.
                loop {
                    // A prior driver can finish this original while its worker
                    // waits for the gate. Unrelated later work must not delay
                    // or replace that response.
                    let guard = tokio::select! {
                        biased;
                        response = &mut receive => return response.map_err(|_| missing_response()),
                        guard = gate.clone().lock_owned() => guard,
                    };
                    match receive.try_recv() {
                        Ok(response) => return Ok(response),
                        Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                            return Err(missing_response());
                        }
                        Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
                    }
                    let batch = super::proposal_group::take(
                        &mut queue.lock().unwrap_or_else(|p| p.into_inner()),
                    );
                    super::proposal_group::run(batch).await?;
                    drop(guard);
                    // Queue insertion and gate acquisition can occur in a
                    // different order. This prefix may have answered only
                    // earlier callers: keep driving until our own answer, even
                    // if those earlier callers exit through their ready result.
                }
            }),
            entry,
        )
    }

    pub(super) fn response(work: ProposalWork, bytes: Vec<u8>) -> Response {
        work._reservation.retain_workspace();
        Response {
            bytes,
            _reservation: work._reservation,
            _registration: work._registration,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    fn start_task<T: Send + 'static>(
        &self,
        task: impl Future<Output = anyhow::Result<T>> + Send + 'static,
    ) -> Result<Call<T>> {
        self.start_task_at(task, None)
    }

    fn start_task_at<T: Send + 'static>(
        &self,
        task: impl Future<Output = anyhow::Result<T>> + Send + 'static,
        mut entry: Option<Entry<'_>>,
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
        let slot = if let Some(entry) = &entry {
            if !std::ptr::eq(entry.jobs, self)
                || !state.reserved[entry.slot]
                || state.slots[entry.slot].is_some()
            {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    "proposal entry reservation changed",
                ));
            }
            entry.slot
        } else {
            state
                .slots
                .iter()
                .enumerate()
                .position(|(slot, worker)| worker.is_none() && !state.reserved[slot])
                .ok_or_else(|| {
                    Error::new(ErrorCode::ResourceExhausted, "proposal registry is full")
                })?
        };
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
        if let Some(entry) = &mut entry {
            entry.installed = true;
            state.reserved[slot] = false;
        }
        self.changed.notify_waiters();
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
    pub(super) fn queued_for_test(&self) -> usize {
        self.queue.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    #[cfg(test)]
    pub(super) fn pause_next_before_gate_for_test(&self) -> tokio::sync::oneshot::Sender<()> {
        let (release, wait) = tokio::sync::oneshot::channel();
        assert!(self.before_gate.lock().unwrap().replace(wait).is_none());
        release
    }

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
            self.changed.notify_waiters();
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
            let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
            assert!(
                queue.is_empty(),
                "drained proposal children left queued work"
            );
            *queue = std::collections::VecDeque::new();
            state.budget = None;
        }
        state.report.outcome(retained)
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Jobs {
    fn running(&self) -> usize {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state
            .slots
            .iter()
            .flatten()
            .filter(|worker| worker.observed().is_none())
            .count()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl super::Database {
    /// Exact lazily retained proposal registry charge for fixture accounting.
    pub fn fixture_proposal_metadata_bytes() -> anyhow::Result<u64> {
        Jobs::required_bytes()
    }

    /// Admit one real proposal child that fails after admission, as a failed
    /// consensus write does. The caller receives the documented uncertain
    /// outcome and this registry closes the tenant exactly as in production.
    pub async fn fixture_fail_admitted_proposal(&self) -> Result<()> {
        self.proposals.prepare(&self.admission)?;
        let call = self
            .proposals
            .start_task::<()>(async { anyhow::bail!("fixture proposal child failure") })?;
        call.wait(Duration::from_secs(5)).await
    }

    /// Admitted proposal children without a terminal observation. Fixtures use
    /// this to seal storage beneath an actual in-flight consensus write.
    pub fn fixture_running_proposals(&self) -> usize {
        self.proposals.running()
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
