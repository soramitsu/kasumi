//! The original blocking backup producer is owned outside its cancellable caller.
use super::NodeAdmission;
use kasumi_serving::{BackgroundWork, BackgroundWorkBudget};
use kasumi_types::{Error, ErrorCode, Result, drain::*};
use std::sync::{Arc, Mutex};

// A database admits at most four query slots, including a live producer's slot.
const MAX_PRODUCERS: usize = 4;

#[derive(Default)]
pub(super) struct Jobs {
    state: Mutex<State>,
    closed: Arc<Mutex<bool>>,
}
#[derive(Default)]
struct State {
    slots: [Option<Arc<BackgroundWork>>; MAX_PRODUCERS],
    budget: Option<BackgroundWorkBudget>,
    report: DrainReport,
}

/// A stopped consumer or cancelled request is an ordinary request outcome. A
/// failed producer is retained as a typed drain issue and closes new admission.
pub(super) enum Failure {
    Stopped(Error),
    Failed(Error),
}

pub(super) struct Call<T> {
    worker: Arc<BackgroundWork>,
    response: tokio::sync::oneshot::Receiver<Result<T>>,
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
        BackgroundWorkBudget::required_bytes(MAX_PRODUCERS, 1)
    }

    fn observe_locked(&self, state: &mut State) {
        for slot in &mut state.slots {
            let Some(worker) = slot else { continue };
            match worker.observed() {
                Some(Ok(())) => *slot = None,
                Some(Err(failure)) => {
                    state.report.merge(&failure);
                    *self.closed.lock().unwrap_or_else(|p| p.into_inner()) = true;
                }
                None => {}
            }
        }
    }

    /// Charge the fixed registry from the installed node before publishing a
    /// backup intent. An idle database never reserves producer custody.
    pub(super) fn prepare(&self, admission: &Arc<NodeAdmission>) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.observe_locked(&mut state);
        if *self.closed.lock().unwrap_or_else(|p| p.into_inner()) {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "backup producer custody is closed",
            ));
        }
        if state.slots.iter().all(Option::is_some) {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "backup producer registry is full",
            ));
        }
        if state.budget.is_none() {
            let bytes = Self::required_bytes().map_err(|_| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "backup producer metadata budget overflow",
                )
            })?;
            let charge = admission.reserve_resident(bytes)?;
            state.budget = Some(
                BackgroundWorkBudget::new(MAX_PRODUCERS, Arc::new(charge)).map_err(|_| {
                    Error::new(
                        ErrorCode::ResourceExhausted,
                        "backup producer metadata budget unavailable",
                    )
                })?,
            );
        }
        Ok(())
    }

    /// The closure runs on the exact retained blocking child. Its small reply is
    /// separate from the original handle and cannot become detached custody.
    pub(super) fn start<T: Send + 'static>(
        &self,
        run: impl FnOnce() -> std::result::Result<T, Failure> + Send + 'static,
    ) -> Result<Call<T>> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.observe_locked(&mut state);
        let closed = self.closed.lock().unwrap_or_else(|p| p.into_inner());
        if *closed {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "backup producer custody is closed",
            ));
        }
        let slot = state
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "backup producer registry is full",
                )
            })?;
        let budget = state.budget.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::Unavailable,
                "backup producer registry has no memory reservation",
            )
        })?;
        let worker = Arc::new(BackgroundWork::default());
        let (sender, response) = tokio::sync::oneshot::channel();
        let admission = self.closed.clone();
        worker
            .start_blocking_result(
                move || {
                    let mut terminal = TerminalFence {
                        closed: admission,
                        completed: false,
                    };
                    match run() {
                        Ok(value) => {
                            let _ = sender.send(Ok(value));
                            terminal.completed = true;
                            Ok(())
                        }
                        Err(Failure::Stopped(error)) => {
                            let _ = sender.send(Err(error));
                            terminal.completed = true;
                            Ok(())
                        }
                        Err(Failure::Failed(error)) => {
                            let _ = sender.send(Err(error.clone()));
                            Err(error.into())
                        }
                    }
                },
                budget,
            )
            .map_err(|_| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "backup producer custody admission failed",
                )
            })?;
        state.slots[slot] = Some(worker.clone());
        Ok(Call { worker, response })
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

    #[cfg(test)]
    pub(super) fn test_worker_if_started(&self, index: usize) -> Option<Arc<BackgroundWork>> {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).slots[index].clone()
    }

    #[cfg(test)]
    pub(super) fn test_worker(&self, index: usize) -> Arc<BackgroundWork> {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).slots[index]
            .as_ref()
            .expect("installed producer child")
            .clone()
    }
}

impl<T> Call<T> {
    /// Join the actual producer before accepting its summary into the manifest.
    pub(super) async fn wait(self) -> Result<T> {
        let joined = self.worker.drain().await;
        let reply = self.response.await;
        match (joined, reply) {
            (Ok(()), Ok(result)) => result,
            (Err(_), Ok(Err(error))) => Err(error),
            _ => Err(Error::new(
                ErrorCode::Unavailable,
                "backup producer failed before replying",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, task::Poll};

    #[tokio::test]
    async fn cancelled_caller_and_drain_retain_actual_producer_panic() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let jobs = Jobs::default();
        jobs.prepare(&admission).unwrap();
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let call = jobs
            .start(move || -> std::result::Result<(), Failure> {
                let _ = entered.send(());
                held.recv().unwrap();
                panic!("original producer child panic");
            })
            .unwrap();
        waiting.await.unwrap();
        let caller = tokio::spawn(call.wait());
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let mut first = Box::pin(jobs.drain());
        std::future::poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(first);
        release.send(()).unwrap();
        let failure = jobs.drain().await.unwrap_err();
        assert_eq!(failure.completion(), DrainCompletion::Complete);
        assert!(
            failure.issues()[0]
                .error()
                .downcast_ref::<tokio::task::JoinError>()
                .unwrap()
                .is_panic()
        );
        let repeated = jobs.drain().await.unwrap_err();
        assert!(Arc::ptr_eq(&failure.issues()[0], &repeated.issues()[0]));
    }

    #[tokio::test]
    async fn expected_consumer_stop_does_not_poison_next_producer() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let jobs = Jobs::default();
        jobs.prepare(&admission).unwrap();
        let stopped = Error::new(ErrorCode::Unavailable, "backup consumer stopped");
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let call = jobs
            .start(move || -> std::result::Result<(), Failure> {
                let _ = entered.send(());
                held.recv().unwrap();
                Err(Failure::Stopped(stopped))
            })
            .unwrap();
        waiting.await.unwrap();
        let worker = jobs.state.lock().unwrap().slots[0]
            .as_ref()
            .unwrap()
            .clone();
        let caller = tokio::spawn(call.wait());
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while worker.observed().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(worker.observed().unwrap().is_ok());
        jobs.prepare(&admission).unwrap();
        let next = jobs.start(|| Ok(7u64)).unwrap();
        assert_eq!(next.wait().await.unwrap(), 7);
        jobs.drain().await.unwrap();
    }

    #[tokio::test]
    async fn unexpected_result_retains_original_error_and_closes_admission() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let jobs = Jobs::default();
        jobs.prepare(&admission).unwrap();
        let call = jobs
            .start(|| -> std::result::Result<(), Failure> {
                Err(Failure::Failed(Error::new(
                    ErrorCode::Corruption,
                    "original producer failure",
                )))
            })
            .unwrap();
        assert_eq!(call.wait().await.unwrap_err().code, ErrorCode::Corruption);
        assert!(jobs.prepare(&admission).is_err());
        let first = jobs.drain().await.unwrap_err();
        let original = first.issues()[0].error().downcast_ref::<Error>().unwrap();
        assert_eq!(original.message, "original producer failure");
        let repeated = jobs.drain().await.unwrap_err();
        assert!(Arc::ptr_eq(&first.issues()[0], &repeated.issues()[0]));
    }
}
