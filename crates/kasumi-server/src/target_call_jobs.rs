//! Exact target-call child custody. A permit alone does not retain a JoinError or
//! a response whose caller disappears after the child publishes its result.
use super::{MAX_CALLS, unknown};
use anyhow::{Result, anyhow, ensure};
use kasumi_engine::admission::NodeAdmission;
use kasumi_serving::{BackgroundWork, BackgroundWorkBudget};
use kasumi_types::{
    Error, ErrorCode,
    drain::{DrainCompletion, DrainFailure, DrainReport, DrainResult},
};
use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    sync::{Mutex as AsyncMutex, Notify, oneshot},
    time::Instant,
};

struct Handoff<T> {
    value: Mutex<Option<Result<T>>>,
    decided: Notify,
}

/// Claim is synchronous: there is no cancellation or fallible gap between
/// receiving the private ticket and accepting its exact result.
pub(super) struct Ticket<T>(Arc<Handoff<T>>);
impl<T> Ticket<T> {
    pub(super) fn claim(self) -> Result<T> {
        self.0
            .value
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .expect("target result ticket claimed once")
    }
}
impl<T> Drop for Ticket<T> {
    fn drop(&mut self) {
        self.0.decided.notify_one();
    }
}

enum Terminal {
    Claimed,
    AbandonedSuccess,
    // This is the original anyhow::Error, not a rebuilt message or an error
    // copied from a timeout response. Keep its exact object until owner drain.
    AbandonedFailure(anyhow::Error),
}

struct Job {
    child: Arc<BackgroundWork>,
    terminal: Arc<Mutex<Option<Terminal>>>,
}
struct Registry {
    jobs: Vec<Option<Arc<Job>>>,
    report: DrainReport,
}

/// The fixed MAX_CALLS child/handoff metadata inventory is admitted before
/// target opening. Its charge remains installed through shutdown.
pub(super) struct TargetCallJobs {
    budget: BackgroundWorkBudget,
    closed: AtomicBool,
    registry: AsyncMutex<Registry>,
}
impl TargetCallJobs {
    pub(super) fn new(admission: &Arc<NodeAdmission>) -> Result<Self> {
        let bytes = BackgroundWorkBudget::required_bytes(MAX_CALLS as usize, 1)?;
        let charge = admission.reserve_resident(bytes)?;
        let budget = BackgroundWorkBudget::new(MAX_CALLS as usize, Arc::new(charge))?;
        ensure!(
            budget.max_registered() == MAX_CALLS as usize,
            "target call inventory charge differs from installed capacity"
        );
        let mut jobs = Vec::new();
        jobs.try_reserve_exact(MAX_CALLS as usize)?;
        jobs.resize_with(MAX_CALLS as usize, || None);
        Ok(Self {
            budget,
            closed: AtomicBool::new(false),
            registry: AsyncMutex::new(Registry {
                jobs,
                report: DrainReport::default(),
            }),
        })
    }

    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    pub(super) async fn await_reply<T>(
        &self,
        deadline: Instant,
        receive: oneshot::Receiver<Ticket<T>>,
    ) -> Result<T> {
        // A timeout only loses this waiter. A closed response channel means
        // the child could not publish a ticket, including a panic whose
        // JoinHandle has not yet become observable; seal admission now.
        match tokio::time::timeout_at(deadline, receive).await {
            // timeout_at may poll a ready receiver before testing its timer.
            // A late ticket is abandoned in child custody, not claimed.
            Ok(Ok(ticket)) if Instant::now() < deadline => ticket.claim(),
            Ok(Ok(ticket)) => {
                drop(ticket);
                Err(unknown("target response deadline expired"))
            }
            Ok(Err(error)) => {
                self.close();
                Err(unknown(error))
            }
            Err(error) => Err(unknown(error)),
        }
    }

    /// Reclaim only claimed, positively joined calls. An abandoned result keeps
    /// its bounded slot and exact outcome until the final shutdown census.
    async fn observe_claimed(&self, registry: &mut Registry) {
        for index in 0..registry.jobs.len() {
            let Some(job) = registry.jobs[index].clone() else {
                continue;
            };
            if job.child.observed().is_none() {
                continue;
            }
            if let Err(failure) = job.child.drain().await {
                registry.report.merge(&failure);
                self.close();
            }
            if job.child.drained()
                && matches!(
                    &*job.terminal.lock().unwrap_or_else(|p| p.into_inner()),
                    Some(Terminal::Claimed)
                )
            {
                registry.jobs[index] = None;
            }
        }
    }

    /// Publication and shutdown census share this lock. A cancelled submit
    /// either starts nothing or leaves the real child in an installed slot.
    pub(super) async fn submit<T: Send + 'static>(
        &self,
        deadline: Instant,
        task: impl Future<Output = Result<T>> + Send + 'static,
    ) -> Result<oneshot::Receiver<Ticket<T>>> {
        let mut registry = self.registry.lock().await;
        self.observe_claimed(&mut registry).await;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(ErrorCode::Unavailable, "target call admission closed").into());
        }
        if Instant::now() >= deadline {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "target operation deadline expired before child dispatch",
            )
            .into());
        }
        let index = registry
            .jobs
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "target call child registry exhausted",
                )
            })?;
        let child = Arc::new(BackgroundWork::default());
        let terminal = Arc::new(Mutex::new(None));
        let observed = terminal.clone();
        let (send, receive) = oneshot::channel();
        child.start(
            async move {
                let outcome = task.await;
                let handoff = Arc::new(Handoff {
                    value: Mutex::new(Some(outcome)),
                    decided: Notify::new(),
                });
                // Sending is not acceptance. If the receiver disappeared before
                // or after this send, Ticket::drop wakes the actual child.
                let _ = send.send(Ticket(handoff.clone()));
                handoff.decided.notified().await;
                let abandoned = handoff
                    .value
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take();
                let terminal = match abandoned {
                    None => Terminal::Claimed,
                    Some(Ok(reply)) => {
                        // Explicitly retire the unclaimed response and its call
                        // permit; leave the success marker in bounded custody.
                        drop(reply);
                        Terminal::AbandonedSuccess
                    }
                    Some(Err(error)) => Terminal::AbandonedFailure(error),
                };
                *observed.lock().unwrap_or_else(|p| p.into_inner()) = Some(terminal);
            },
            &self.budget,
        )?;
        registry.jobs[index] = Some(Arc::new(Job { child, terminal }));
        Ok(receive)
    }

    /// Join exact handles before any generation or journal is released. A
    /// cancelled drain leaves its previously joined diagnostics in this owner.
    pub(super) async fn drain(&self) -> DrainResult {
        self.close();
        let mut registry = self.registry.lock().await;
        let mut retained = None;
        for index in 0..registry.jobs.len() {
            let Some(job) = registry.jobs[index].clone() else {
                continue;
            };
            let outcome = job.child.drain().await;
            let joined_failure =
                matches!(&outcome, Err(f) if f.completion() == DrainCompletion::Complete);
            if let Err(failure) = outcome {
                registry.report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
            }
            if !job.child.drained() {
                if retained.is_none() {
                    retained = Some(DrainFailure::retained(registry.report.record(
                        "target call child",
                        index,
                        anyhow!("target child remains owned after drain"),
                    )));
                }
                continue;
            }
            let terminal = job
                .terminal
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take();
            match terminal {
                Some(Terminal::Claimed | Terminal::AbandonedSuccess) => {
                    registry.jobs[index] = None;
                }
                Some(Terminal::AbandonedFailure(error)) => {
                    registry
                        .report
                        .record("abandoned target call", index, error);
                    registry.jobs[index] = None;
                }
                None if joined_failure => {
                    // The child panic itself is the original terminal outcome.
                    registry.jobs[index] = None;
                }
                None => {
                    retained = Some(DrainFailure::retained(registry.report.record(
                        "target call outcome",
                        index,
                        anyhow!("joined target child has no terminal outcome"),
                    )));
                }
            }
        }
        registry.report.outcome(retained)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::Poll,
        time::Duration,
    };

    fn jobs() -> TargetCallJobs {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        TargetCallJobs::new(&admission).unwrap()
    }

    #[test]
    fn fixed_call_inventory_has_one_exact_resident_charge() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let baseline = admission.snapshot().reserved_bytes;
        let bytes = BackgroundWorkBudget::required_bytes(MAX_CALLS as usize, 1).unwrap();
        let jobs = TargetCallJobs::new(&admission).unwrap();
        assert_eq!(admission.snapshot().reserved_bytes, baseline + bytes);
        drop(jobs);
        assert_eq!(admission.snapshot().reserved_bytes, baseline);
    }

    #[tokio::test]
    async fn ready_ticket_after_original_deadline_is_not_claimed() {
        let jobs = jobs();
        let receive = jobs
            .submit(Instant::now() + Duration::from_secs(5), async { Ok(7_u64) })
            .await
            .unwrap();
        let ticket = receive.await.unwrap();
        let (forward, ready) = oneshot::channel();
        assert!(forward.send(ticket).is_ok());
        let expired = Instant::now() - Duration::from_millis(1);
        let error = jobs.await_reply(expired, ready).await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<Error>().unwrap().code,
            ErrorCode::UnknownOutcome
        );
        jobs.drain().await.unwrap();
    }

    #[tokio::test]
    async fn timeout_retires_unclaimed_success_only_after_exact_child_joins() {
        struct Reply {
            _permit: tokio::sync::OwnedSemaphorePermit,
            dropped: Arc<AtomicUsize>,
        }
        impl Drop for Reply {
            fn drop(&mut self) {
                self.dropped.fetch_add(1, Ordering::AcqRel);
            }
        }
        let jobs = self::jobs();
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = capacity.clone().acquire_owned().await.unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let held = dropped.clone();
        let (finish, completed) = oneshot::channel::<()>();
        let receive = jobs
            .submit(Instant::now() + Duration::from_secs(5), async move {
                completed.await?;
                Ok(Reply {
                    _permit: permit,
                    dropped: held,
                })
            })
            .await
            .unwrap();
        let error = match jobs
            .await_reply(Instant::now() + Duration::from_millis(1), receive)
            .await
        {
            Ok(_) => panic!("target timeout unexpectedly released a reply"),
            Err(error) => error,
        };
        assert_eq!(
            error.downcast_ref::<Error>().unwrap().code,
            ErrorCode::UnknownOutcome
        );
        assert_eq!(capacity.available_permits(), 0);
        let mut drain = Box::pin(jobs.drain());
        std::future::poll_fn(|cx| {
            assert!(drain.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(dropped.load(Ordering::Acquire), 0);
        assert_eq!(capacity.available_permits(), 0);
        finish.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), drain)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dropped.load(Ordering::Acquire), 1);
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn abandoned_error_is_original_and_a_claimed_reply_clears_its_slot() {
        let jobs = self::jobs();
        let receive = jobs
            .submit(Instant::now() + Duration::from_secs(5), async {
                Err::<u64, _>(anyhow!("exact target rejection"))
            })
            .await
            .unwrap();
        let ticket = receive.await.unwrap();
        drop(ticket);
        let first = jobs.drain().await.unwrap_err();
        assert_eq!(first.completion(), DrainCompletion::Complete);
        assert_eq!(first.issues().len(), 1);
        assert_eq!(
            first.issues()[0].error().to_string(),
            "exact target rejection"
        );
        let again = jobs.drain().await.unwrap_err();
        assert!(Arc::ptr_eq(&first.issues()[0], &again.issues()[0]));

        let jobs = self::jobs();
        let receive = jobs
            .submit(Instant::now() + Duration::from_secs(5), async { Ok(7_u64) })
            .await
            .unwrap();
        assert_eq!(
            jobs.await_reply(Instant::now() + Duration::from_secs(5), receive)
                .await
                .unwrap(),
            7
        );
        jobs.drain().await.unwrap();

        let jobs = self::jobs();
        let receive = jobs
            .submit(Instant::now() + Duration::from_secs(5), async {
                Err::<u64, _>(Error::new(ErrorCode::Forbidden, "ordered rejection").into())
            })
            .await
            .unwrap();
        let error = jobs
            .await_reply(Instant::now() + Duration::from_secs(5), receive)
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<Error>().unwrap().code,
            ErrorCode::Forbidden
        );
        jobs.drain().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_waiter_and_cancelled_drain_retain_original_child_panic() {
        let jobs = self::jobs();
        let (finish, blocked) = oneshot::channel::<()>();
        let receive = jobs
            .submit(Instant::now() + Duration::from_secs(5), async move {
                blocked.await.unwrap();
                panic!("exact target child panic");
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            })
            .await
            .unwrap();
        drop(receive);
        let mut first = Box::pin(jobs.drain());
        std::future::poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(first);
        finish.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), jobs.drain())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(result.completion(), DrainCompletion::Complete);
        assert!(
            result.issues()[0]
                .error()
                .downcast_ref::<tokio::task::JoinError>()
                .is_some()
        );
        let again = jobs.drain().await.unwrap_err();
        assert!(Arc::ptr_eq(&result.issues()[0], &again.issues()[0]));
    }

    #[tokio::test]
    async fn child_panic_and_aborted_response_channel_map_to_unknown_outcome() {
        let jobs = self::jobs();
        let receive = jobs
            .submit(Instant::now() + Duration::from_secs(5), async {
                panic!("target child failed after dispatch");
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            })
            .await
            .unwrap();
        let error = jobs
            .await_reply(Instant::now() + Duration::from_secs(5), receive)
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<Error>().unwrap().code,
            ErrorCode::UnknownOutcome
        );
        let subsequent = jobs
            .submit(Instant::now() + Duration::from_secs(5), async {
                Ok::<(), anyhow::Error>(())
            })
            .await;
        let subsequent = match subsequent {
            Ok(_) => panic!("panic failed to seal target-call admission"),
            Err(error) => error,
        };
        assert_eq!(
            subsequent.downcast_ref::<Error>().unwrap().code,
            ErrorCode::Unavailable
        );
        let failure = jobs.drain().await.unwrap_err();
        assert_eq!(failure.completion(), DrainCompletion::Complete);
        assert!(
            failure.issues()[0]
                .error()
                .downcast_ref::<tokio::task::JoinError>()
                .is_some()
        );
        let repeated = jobs.drain().await.unwrap_err();
        assert!(Arc::ptr_eq(&failure.issues()[0], &repeated.issues()[0]));

        let channel_jobs = self::jobs();
        let (send, receive) = oneshot::channel::<Ticket<()>>();
        let aborted = tokio::spawn(async move {
            let _send = send;
            std::future::pending::<()>().await;
        });
        aborted.abort();
        assert!(aborted.await.unwrap_err().is_cancelled());
        let error = channel_jobs
            .await_reply(Instant::now() + Duration::from_secs(5), receive)
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<Error>().unwrap().code,
            ErrorCode::UnknownOutcome
        );
        let next = channel_jobs
            .submit(Instant::now() + Duration::from_secs(5), async { Ok(()) })
            .await;
        let next = match next {
            Ok(_) => panic!("closed response channel failed to seal target-call admission"),
            Err(error) => error,
        };
        assert_eq!(
            next.downcast_ref::<Error>().unwrap().code,
            ErrorCode::Unavailable
        );
        channel_jobs.drain().await.unwrap();
    }

    #[tokio::test]
    async fn abandoned_outcomes_fill_only_the_fixed_admitted_inventory() {
        let jobs = self::jobs();
        for value in 0..MAX_CALLS {
            let receive = jobs
                .submit(
                    Instant::now() + Duration::from_secs(5),
                    async move { Ok(value) },
                )
                .await
                .unwrap();
            drop(receive);
        }
        let extra = jobs
            .submit(Instant::now() + Duration::from_secs(5), async { Ok(()) })
            .await;
        let error = match extra {
            Ok(_) => panic!("abandoned target outcomes exceeded the fixed inventory"),
            Err(error) => error,
        };
        assert_eq!(
            error.downcast_ref::<Error>().unwrap().code,
            ErrorCode::ResourceExhausted
        );
        jobs.drain().await.unwrap();
    }
}
