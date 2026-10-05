//! Exact target-call child custody. A permit alone does not retain a JoinError or
//! a response whose caller disappears after the child publishes its result.
#[cfg(test)]
use super::SnapshotFailure;
use super::target_call_failure::{
    TargetFailureInventory, TargetOutput, TargetOutputTicket, TargetProducerFailure,
    TargetProducerLoan,
};
use super::{MAX_CALLS, TargetCallFailure, TargetCallSeat};
use anyhow::{Result, anyhow, ensure};
use kasumi_engine::admission::NodeAdmission;
use kasumi_serving::{BackgroundWork, BackgroundWorkBudget};
use kasumi_types::SharedBudgetCharge;
use kasumi_types::drain::{DrainCompletion, DrainFailure, DrainReport, DrainResult};
#[cfg(test)]
use kasumi_types::{Error, ErrorCode};
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

struct Handoff<T: TargetOutput> {
    value: Mutex<Option<std::result::Result<TargetOutputTicket<T>, TargetCallFailure>>>,
    decided: Notify,
}

/// Claim is synchronous. Report contention returns the same retained owner
/// before taking its output; cancellation cannot split the custody transfer.
pub(super) struct Ticket<T: TargetOutput>(Arc<Handoff<T>>);
impl<T: TargetOutput> Ticket<T> {
    pub(super) fn claim(self) -> std::result::Result<T, TargetCallFailure> {
        self.0
            .value
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .expect("target result ticket claimed once")
            .and_then(TargetOutputTicket::claim)
    }
}
impl<T: TargetOutput> Drop for Ticket<T> {
    fn drop(&mut self) {
        self.0.decided.notify_one();
    }
}

enum Terminal {
    Claimed,
    AbandonedSuccess,
    // The facade lends the whole original from its independent paid cell.
    // A timeout marker never replaces that original.
    AbandonedFailure(TargetCallFailure),
}

struct Job {
    child: Arc<BackgroundWork>,
    terminal: Arc<Mutex<Option<Terminal>>>,
    _seat: TargetCallSeat,
}
struct Registry {
    jobs: Vec<Option<Arc<Job>>>,
    report: DrainReport,
}
#[cfg(test)]
pub(super) struct TestReply {
    pub(super) _permit: tokio::sync::OwnedSemaphorePermit,
    pub(super) dropped: Arc<std::sync::atomic::AtomicUsize>,
    pub(super) panic: Option<Box<dyn std::any::Any + Send>>,
}
#[cfg(test)]
impl Drop for TestReply {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::AcqRel);
        if let Some(original) = self.panic.take() {
            std::panic::resume_unwind(original);
        }
    }
}

/// The fixed MAX_CALLS child/handoff metadata inventory is admitted before
/// target opening. Its charge remains installed through shutdown.
pub(super) struct TargetCallJobs {
    budget: BackgroundWorkBudget,
    closed: AtomicBool,
    registry: AsyncMutex<Registry>,
    failures: TargetFailureInventory,
}
/// A single admitted dispatch. Fixed controls precede the producer loan,
/// whose outcome guard precedes its same charged seat. The borrowed jobs owner
/// also keeps the original parent grant alive through unused-control disposal.
pub(super) struct TargetSubmissionLoan<'jobs, T: TargetOutput> {
    job: Option<Arc<Job>>,
    send: Option<oneshot::Sender<Ticket<T>>>,
    receive: Option<oneshot::Receiver<Ticket<T>>>,
    handoff: Option<Arc<Handoff<T>>>,
    execution: Option<TargetProducerLoan>,
    jobs: &'jobs TargetCallJobs,
    index: usize,
    // Last: vacant-slot reuse follows actual fixed-control destruction.
    registry: tokio::sync::MutexGuard<'jobs, Registry>,
}
impl<T: TargetOutput + Send + 'static> TargetSubmissionLoan<'_, T> {
    pub(super) fn seat(&self) -> &TargetCallSeat {
        &self.job.as_ref().expect("same admitted target job")._seat
    }
    /// The accepted producer is installed before actual dispatch. No queue,
    /// deadline or body-phase refusal occurs after the producer is supplied.
    pub(super) fn submit<
        E: TargetProducerFailure + Send + 'static,
        F: Future<Output = std::result::Result<T, E>> + Send + 'static,
    >(
        mut self,
        work: F,
    ) -> std::result::Result<oneshot::Receiver<Ticket<T>>, TargetCallFailure> {
        let producer = self
            .execution
            .take()
            .expect("one admitted producer")
            .run(work);
        let handoff = self.handoff.take().expect("same prepared handoff");
        let send = self.send.take().expect("same prepared response channel");
        let job = self.job.as_ref().expect("same prepared child");
        let child = job.child.clone();
        let observed = job.terminal.clone();
        let started = child.start(
            async move {
                let outcome = producer.await;
                *handoff.value.lock().unwrap_or_else(|p| p.into_inner()) = Some(outcome);
                // Sending is not acceptance. The actual ticket's Drop wakes
                // this same child if the receiver or its caller disappears.
                let _ = send.send(Ticket(handoff.clone()));
                handoff.decided.notified().await;
                let abandoned = handoff
                    .value
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take();
                let terminal = match abandoned {
                    None => Terminal::Claimed,
                    Some(Ok(reply)) => match reply.dispose() {
                        Ok(()) => Terminal::AbandonedSuccess,
                        Err(original) => Terminal::AbandonedFailure(original),
                    },
                    Some(Err(original)) => Terminal::AbandonedFailure(original),
                };
                *observed.lock().unwrap_or_else(|p| p.into_inner()) = Some(terminal);
            },
            &self.jobs.budget,
        );
        if let Err(original) = started {
            let failure = self.seat().record_dispatch(original);
            self.jobs.fence_panicked_failure(&failure);
            return Err(failure);
        }
        self.registry.jobs[self.index] = self.job.take();
        Ok(self.receive.take().expect("same admitted receiver"))
    }
}

impl TargetCallJobs {
    pub(super) fn new(admission: &Arc<NodeAdmission>) -> Result<Self> {
        let bytes = Self::required_bytes()?;
        let charge = SharedBudgetCharge::new(admission.reserve_resident(bytes)?);
        let failures = TargetFailureInventory::new(MAX_CALLS as usize, charge.clone())?;
        let budget = BackgroundWorkBudget::new(MAX_CALLS as usize, charge)?;
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
            failures,
        })
    }

    pub(super) fn required_bytes() -> Result<u64> {
        BackgroundWorkBudget::required_bytes(MAX_CALLS as usize, 1)?
            .checked_add(TargetFailureInventory::required_bytes(MAX_CALLS as usize)?)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput).into())
    }

    pub(super) fn acquire_failure(&self) -> std::result::Result<TargetCallSeat, TargetCallFailure> {
        self.failures.acquire()
    }
    pub(super) fn original_failure(&self, index: usize) -> Option<TargetCallFailure> {
        self.failures.original_failure(index)
    }

    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.failures.close();
    }

    pub(super) async fn await_reply<T: TargetOutput>(
        &self,
        deadline: Instant,
        receive: oneshot::Receiver<Ticket<T>>,
    ) -> std::result::Result<T, TargetCallFailure> {
        // A timeout only loses this waiter. A closed response channel means
        // the child could not publish a ticket, including a panic whose
        // JoinHandle has not yet become observable; seal admission now.
        match tokio::time::timeout_at(deadline, receive).await {
            // timeout_at may poll a ready receiver before testing its timer.
            // A late ticket is abandoned in child custody, not claimed.
            Ok(Ok(ticket)) if Instant::now() < deadline => {
                let result = ticket.claim();
                if let Err(original) = &result {
                    self.fence_panicked_failure(original);
                }
                result
            }
            Ok(Ok(ticket)) => {
                {
                    let outcome = ticket.0.value.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(Err(original)) = outcome.as_ref() {
                        self.fence_panicked_failure(original);
                    }
                }
                drop(ticket);
                Err(TargetCallFailure::ResponseExpired)
            }
            Ok(Err(_error)) => {
                self.close();
                Err(TargetCallFailure::ResponseLost)
            }
            Err(_error) => Err(TargetCallFailure::ResponseExpired),
        }
    }

    // Poll and disposal panics are separate resident originals. A successful
    // supervisor join never changes their admission consequence or custody.
    fn fence_panicked_failure(&self, original: &TargetCallFailure) {
        if original.has_observed_panic() {
            self.close();
        }
    }

    /// Reclaim only claimed, positively joined calls. An abandoned result keeps
    /// its bounded slot and exact outcome until the final shutdown census.
    async fn observe_claimed(&self, registry: &mut Registry) {
        for index in 0..registry.jobs.len() {
            let Some(job) = registry.jobs[index].clone() else {
                continue;
            };
            self.fence_panicked_failure(&TargetCallFailure::Retained(job._seat.clone()));
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

    /// Complete every queue check before the caller constructs its producer.
    /// The returned nonclone loan holds this exact registry slot and paid cell.
    pub(super) async fn acquire_submission<T: TargetOutput + Send + 'static>(
        &self,
        deadline: Instant,
        seat: TargetCallSeat,
    ) -> std::result::Result<TargetSubmissionLoan<'_, T>, TargetCallFailure> {
        let mut registry = self.registry.lock().await;
        self.observe_claimed(&mut registry).await;
        if self.closed.load(Ordering::Acquire) {
            return Err(TargetCallFailure::Admission(
                kasumi_store::ScratchAdmissionRefusal::Sealed,
            ));
        }
        if Instant::now() >= deadline {
            return Err(TargetCallFailure::ResponseExpired);
        }
        let index =
            registry
                .jobs
                .iter()
                .position(Option::is_none)
                .ok_or(TargetCallFailure::Admission(
                    kasumi_store::ScratchAdmissionRefusal::Busy,
                ))?;
        // These are the same fixed dispatch controls as an installed job. They
        // are prepared under the original budget before a producer can exist.
        let job = Arc::new(Job {
            child: Arc::new(BackgroundWork::default()),
            terminal: Arc::new(Mutex::new(None)),
            _seat: seat.clone(),
        });
        let handoff = Arc::new(Handoff {
            value: Mutex::new(None),
            decided: Notify::new(),
        });
        let (send, receive) = oneshot::channel();
        let execution = seat.begin()?;
        // No await follows the accepted begin. Dropping this unused loan leaves
        // its original body unentered and the same cell conservatively sticky.
        Ok(TargetSubmissionLoan {
            registry,
            job: Some(job),
            send: Some(send),
            receive: Some(receive),
            handoff: Some(handoff),
            execution: Some(execution),
            jobs: self,
            index,
        })
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
            self.fence_panicked_failure(&TargetCallFailure::Retained(job._seat.clone()));
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
                    let issue = registry.report.record(
                        "abandoned target call",
                        index,
                        anyhow!("target failure remains in admitted cell"),
                    );
                    // Retain the facade and exact original cell independently
                    // of the foreign drain marker.
                    *job.terminal.lock().unwrap_or_else(|p| p.into_inner()) =
                        Some(Terminal::AbandonedFailure(error));
                    retained = Some(DrainFailure::retained(issue));
                }
                None if joined_failure => {
                    // A joined panic is not an observation of the accepted
                    // producer or its independently owned output disposal.
                    retained = Some(DrainFailure::retained(registry.report.record(
                        "target call producer",
                        index,
                        anyhow!("joined target panic retains its original producer custody"),
                    )));
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
        if self.failures.retained() && retained.is_none() {
            retained = Some(DrainFailure::retained(registry.report.record(
                "target call failure custody",
                0,
                anyhow!("original target failure remains admitted"),
            )));
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

    // This fixture helper accepts only a scalar deadline and the actual jobs
    // owner. It never accepts or constructs an owning factory or producer.
    async fn submission<T: TargetOutput + Send + 'static>(
        jobs: &TargetCallJobs,
        deadline: Instant,
    ) -> std::result::Result<TargetSubmissionLoan<'_, T>, TargetCallFailure> {
        let seat = jobs.acquire_failure()?;
        jobs.acquire_submission(deadline, seat).await
    }

    struct OwnedProducer {
        drops: Arc<AtomicUsize>,
    }
    impl Future for OwnedProducer {
        type Output = std::result::Result<(), SnapshotFailure>;
        fn poll(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<Self::Output> {
            Poll::Ready(Ok(()))
        }
    }
    impl Drop for OwnedProducer {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn owned_producer(constructed: &AtomicUsize, drops: &Arc<AtomicUsize>) -> OwnedProducer {
        constructed.fetch_add(1, Ordering::SeqCst);
        OwnedProducer {
            drops: drops.clone(),
        }
    }

    #[tokio::test]
    async fn sealed_submission_refuses_before_owned_producer_construction() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let jobs = TargetCallJobs::new(&admission).unwrap();
        let charged = admission.snapshot().reserved_bytes;
        let original_seat = jobs.acquire_failure().unwrap();
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let original = anyhow::Error::new(
            std::fs::metadata(directory.path().join("actual-sealed-original")).unwrap_err(),
        );
        let outer: &(dyn std::error::Error + Send + Sync + 'static) = original.as_ref();
        let address = outer as *const _ as *const () as usize;
        let original_failure = original_seat
            .begin()
            .unwrap()
            .run(async { Err::<(), _>(SnapshotFailure::Source(original)) })
            .await
            .unwrap_err();
        jobs.close();
        let constructed = AtomicUsize::new(0);
        let drops = Arc::new(AtomicUsize::new(0));
        let refused = match submission::<()>(&jobs, Instant::now() + Duration::from_secs(5)).await {
            Ok(loan) => {
                let _ = loan.submit(owned_producer(&constructed, &drops));
                panic!("closed actual jobs admitted another producer");
            }
            Err(original) => original,
        };
        assert!(matches!(
            refused,
            TargetCallFailure::Admission(kasumi_store::ScratchAdmissionRefusal::Sealed)
        ));
        assert_eq!(constructed.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(admission.snapshot().reserved_bytes, charged);
        original_failure.with_original(|original| {
            let outer: &(dyn std::error::Error + Send + Sync + 'static) =
                original.unwrap().source_error().unwrap().as_ref();
            assert_eq!(outer as *const _ as *const () as usize, address);
        });
        assert_eq!(jobs.registry.lock().await.jobs.iter().flatten().count(), 0);
        assert_eq!(
            jobs.drain().await.unwrap_err().completion(),
            DrainCompletion::Retained
        );
        drop(original_seat);
        drop(original_failure);
        drop(jobs);
        assert_eq!(admission.snapshot().reserved_bytes, charged);
    }

    #[tokio::test]
    async fn expired_submission_refuses_before_owned_producer_construction() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let baseline = admission.snapshot().reserved_bytes;
        let jobs = TargetCallJobs::new(&admission).unwrap();
        let charged = admission.snapshot().reserved_bytes;
        let seat = jobs.acquire_failure().unwrap();
        let identity = seat.identity();
        let constructed = AtomicUsize::new(0);
        let drops = Arc::new(AtomicUsize::new(0));
        let refused = match jobs
            .acquire_submission::<()>(Instant::now() - Duration::from_millis(1), seat)
            .await
        {
            Ok(loan) => {
                let _ = loan.submit(owned_producer(&constructed, &drops));
                panic!("the original expired deadline admitted a producer");
            }
            Err(original) => original,
        };
        assert!(matches!(refused, TargetCallFailure::ResponseExpired));
        assert_eq!(constructed.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(admission.snapshot().reserved_bytes, charged);
        assert!(jobs.original_failure(0).is_none());
        let reused = jobs.acquire_failure().unwrap();
        assert_eq!(reused.identity(), identity);
        drop(reused);
        assert_eq!(jobs.registry.lock().await.jobs.iter().flatten().count(), 0);
        jobs.drain().await.unwrap();
        drop(jobs);
        assert_eq!(admission.snapshot().reserved_bytes, baseline);
    }

    #[tokio::test]
    async fn full_actual_queue_refuses_before_owned_producer_and_preserves_original() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let jobs = TargetCallJobs::new(&admission).unwrap();
        let charged = admission.snapshot().reserved_bytes;
        let original_seat = jobs.acquire_failure().unwrap();
        let original_alias = original_seat.clone();
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let original = anyhow::Error::new(
            std::fs::metadata(directory.path().join("actual-full-queue-original")).unwrap_err(),
        );
        let outer: &(dyn std::error::Error + Send + Sync + 'static) = original.as_ref();
        let address = outer as *const _ as *const () as usize;
        let loan = jobs
            .acquire_submission::<()>(Instant::now() + Duration::from_secs(5), original_seat)
            .await
            .unwrap();
        let receive = loan
            .submit(async { Err::<(), _>(SnapshotFailure::Source(original)) })
            .unwrap();
        drop(receive.await.unwrap());
        for _ in 1..MAX_CALLS {
            let loan = submission::<()>(&jobs, Instant::now() + Duration::from_secs(5))
                .await
                .unwrap();
            let receive = loan.submit::<SnapshotFailure, _>(async { Ok(()) }).unwrap();
            drop(receive.await.unwrap());
        }
        assert_eq!(
            jobs.registry.lock().await.jobs.iter().flatten().count(),
            MAX_CALLS as usize
        );
        let constructed = AtomicUsize::new(0);
        let drops = Arc::new(AtomicUsize::new(0));
        // Lend the same existing first job's seat. No sixty-fifth cell or new
        // grant is invented merely to reach the real full registry boundary.
        let refused = match jobs
            .acquire_submission::<()>(
                Instant::now() + Duration::from_secs(5),
                original_alias.clone(),
            )
            .await
        {
            Ok(loan) => {
                let _ = loan.submit(owned_producer(&constructed, &drops));
                panic!("the actual fixed queue admitted a sixty-fifth producer");
            }
            Err(original) => original,
        };
        assert!(matches!(
            refused,
            TargetCallFailure::Admission(kasumi_store::ScratchAdmissionRefusal::Busy)
        ));
        assert_eq!(constructed.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(admission.snapshot().reserved_bytes, charged);
        let original = jobs.original_failure(0).unwrap();
        original.with_original(|original| {
            let outer: &(dyn std::error::Error + Send + Sync + 'static) =
                original.unwrap().source_error().unwrap().as_ref();
            assert_eq!(outer as *const _ as *const () as usize, address);
        });
        assert_eq!(
            jobs.drain().await.unwrap_err().completion(),
            DrainCompletion::Retained
        );
        original.with_original(|original| {
            let outer: &(dyn std::error::Error + Send + Sync + 'static) =
                original.unwrap().source_error().unwrap().as_ref();
            assert_eq!(outer as *const _ as *const () as usize, address);
        });
        drop(original);
        drop(original_alias);
        drop(jobs);
        assert_eq!(admission.snapshot().reserved_bytes, charged);
    }

    #[tokio::test]
    async fn cancelled_pending_submission_never_accepts_a_producer_or_spends_its_seat() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let baseline = admission.snapshot().reserved_bytes;
        let jobs = TargetCallJobs::new(&admission).unwrap();
        let charged = admission.snapshot().reserved_bytes;
        let locked = jobs.registry.lock().await;
        let seat = jobs.acquire_failure().unwrap();
        let identity = seat.identity();
        let mut acquire =
            Box::pin(jobs.acquire_submission::<()>(Instant::now() + Duration::from_secs(5), seat));
        std::future::poll_fn(|cx| {
            assert!(acquire.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(acquire);
        assert!(jobs.original_failure(0).is_none());
        assert_eq!(admission.snapshot().reserved_bytes, charged);
        assert_eq!(locked.jobs.iter().flatten().count(), 0);
        drop(locked);
        let reused = jobs.acquire_failure().unwrap();
        assert_eq!(reused.identity(), identity);
        drop(reused);
        jobs.drain().await.unwrap();
        drop(jobs);
        assert_eq!(admission.snapshot().reserved_bytes, baseline);
    }

    #[tokio::test]
    async fn unused_admitted_submission_disposes_fixed_controls_but_keeps_same_unknown_loan() {
        use crate::recovery_allocation_watch::Watch;
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let jobs = TargetCallJobs::new(&admission).unwrap();
        let charged = admission.snapshot().reserved_bytes;
        let watching = Watch::begin();
        let loan = submission::<()>(&jobs, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        let observed = watching.snapshot();
        let fixed = [
            Arc::as_ptr(loan.job.as_ref().unwrap()) as usize,
            Arc::as_ptr(&loan.job.as_ref().unwrap().child) as usize,
            Arc::as_ptr(&loan.job.as_ref().unwrap().terminal) as usize,
            Arc::as_ptr(loan.handoff.as_ref().unwrap()) as usize,
        ];
        let actual = fixed.map(|data| {
            observed.allocations[..observed.count]
                .iter()
                .copied()
                .find(|allocation| {
                    allocation.address <= data && data < allocation.address + allocation.bytes
                })
                .unwrap()
        });
        let identity = loan.seat().identity();
        drop(loan);
        let observed = watching.finish();
        assert!(!observed.overflow);
        for control in actual {
            assert!(observed.allocation(control.address).unwrap().freed);
        }
        assert_eq!(admission.snapshot().reserved_bytes, charged);
        assert_eq!(jobs.registry.lock().await.jobs.iter().flatten().count(), 0);
        let original = jobs.original_failure(0).unwrap();
        original.with_report(|report| {
            let report = report.unwrap();
            assert!(!report.body_entered());
            assert!(!report.body_returned());
            assert!(!report.future_disposal_returned());
            assert!(!report.output_disposal_returned());
            assert!(!report.has_output());
            assert!(report.original().is_none());
            assert!(report.dispatch_error().is_none());
            assert!(report.with_body_panic(|_| ()).is_none());
            assert!(report.with_future_disposal_panic(|_| ()).is_none());
        });
        assert_eq!(original.marker().code, ErrorCode::UnknownOutcome);
        let reused = jobs.acquire_failure().unwrap();
        assert_ne!(reused.identity(), identity);
        drop(reused);
        assert_eq!(
            jobs.drain().await.unwrap_err().completion(),
            DrainCompletion::Retained
        );
        drop(jobs);
        original.with_report(|report| assert!(!report.unwrap().body_entered()));
        drop(original);
        assert_eq!(admission.snapshot().reserved_bytes, charged);
    }

    #[tokio::test]
    async fn actual_initial_quote_refusal_survives_abandoned_ticket_and_inventory_drop() {
        use kasumi_store::{
            EncryptedTable, NodeDiskMemoryAdmission, ScratchDisk, test_utils::TestDiskMemory,
        };
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let baseline = admission.snapshot().reserved_bytes;
        let jobs = TargetCallJobs::new(&admission).unwrap();
        let charged = admission.snapshot().reserved_bytes;
        assert_eq!(
            charged,
            baseline + TargetCallJobs::required_bytes().unwrap()
        );
        let memory = TestDiskMemory::new(64 << 20, 32);
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
        let mut fillers = Vec::new();
        for _ in memory.snapshot().live_reservations..32 {
            fillers.push(memory.clone().reserve_installed(0).unwrap());
        }
        let before = memory.snapshot();
        let census_before = memory.storage_census().snapshot();
        let native_before = disk.snapshot();
        let effect_disk = disk.clone();
        let receive = submission::<()>(&jobs, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap()
            .submit::<SnapshotFailure, _>(async move {
                let original =
                    EncryptedTable::new(&effect_disk, 8 << 20, effect_disk.native_cache_config())
                        .err()
                        .unwrap();
                assert!(original.owner_id().is_some());
                original.with_diagnostic(|report| {
                    let report = report.unwrap();
                    let constructor = report.constructor_report().unwrap();
                    assert!(constructor.capacity_refused());
                    assert!(!constructor.has_lease());
                    assert!(!constructor.has_payload());
                    assert!(matches!(
                        constructor.construction(),
                        kasumi_store::TerminalObservation::NotEntered
                    ));
                });
                Err(SnapshotFailure::Creation(original))
            })
            .unwrap();
        let ticket = receive.await.unwrap();
        let identity = |original: &TargetCallFailure| {
            original.with_original(|original| {
                let creation = original.unwrap().creation().unwrap();
                let id = creation.owner_id().unwrap();
                let address = creation.with_diagnostic(|report| {
                    let report = report.unwrap();
                    let constructor = report.constructor_report().unwrap();
                    assert!(constructor.capacity_refused());
                    assert!(!constructor.has_lease());
                    assert!(!constructor.has_payload());
                    assert!(matches!(
                        constructor.construction(),
                        kasumi_store::TerminalObservation::NotEntered
                    ));
                    let original = report.admission_error().unwrap();
                    assert_eq!(original.kind(), std::io::ErrorKind::OutOfMemory);
                    assert!(report.opening_error().is_none());
                    original as *const std::io::Error as usize
                });
                (id, address)
            })
        };
        let original = jobs.original_failure(0).unwrap();
        let address = identity(&original);
        drop(original);
        // Cancellation drops only the actual published ticket. The child and
        // its independently installed original failure remain in their seats.
        drop(ticket);
        let first = jobs.drain().await.unwrap_err();
        assert_eq!(first.completion(), DrainCompletion::Retained);
        assert_eq!(memory.snapshot().attempts, before.attempts + 1);
        assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
        assert_eq!(memory.snapshot().live_reservations, 32);
        for _ in 0..3 {
            let original = jobs.original_failure(0).unwrap();
            assert_eq!(identity(&original), address);
            assert_eq!(original.marker().code, ErrorCode::Unavailable);
            drop(original);
        }
        let census_retained = memory.storage_census().snapshot();
        assert_eq!(census_retained.databases, census_before.databases + 1);
        assert_eq!(census_retained.readers, census_before.readers);
        assert_eq!(census_retained.writers, census_before.writers);
        let native_original =
            kasumi_store::ScratchCreationFailure::retained(memory.clone(), address.0).unwrap();
        assert_eq!(native_original.owner_id(), Some(address.0));
        native_original.with_diagnostic(|report| {
            let report = report.unwrap();
            assert!(report.constructor_report().unwrap().capacity_refused());
            assert_eq!(
                report.admission_error().unwrap() as *const std::io::Error as usize,
                address.1
            );
        });
        drop(native_original);
        assert_eq!(native_before.live_files, 0);
        assert_eq!(disk.snapshot().live_files, native_before.live_files);
        assert_eq!(admission.snapshot().reserved_bytes, charged);
        drop(jobs);
        // Neither whole-error disposal nor a native/opaque IO refund witness
        // exists. The original cell and its exact parent charge stay installed.
        assert_eq!(admission.snapshot().reserved_bytes, charged);
        let native_original =
            kasumi_store::ScratchCreationFailure::retained(memory.clone(), address.0).unwrap();
        native_original.with_diagnostic(|report| {
            let report = report.unwrap();
            assert!(report.constructor_report().unwrap().capacity_refused());
            assert_eq!(
                report.admission_error().unwrap() as *const std::io::Error as usize,
                address.1
            );
        });
        assert_eq!(memory.storage_census().snapshot(), census_retained);
        assert_eq!(memory.snapshot().live_reservations, 32);
        drop(native_original);
        drop(fillers);
    }

    #[tokio::test]
    async fn opaque_context_keeps_exact_outer_allocation_after_terminal_projection() {
        #[derive(Debug)]
        struct ContextOwner(Arc<AtomicUsize>);
        impl std::fmt::Display for ContextOwner {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("actual IO context")
            }
        }
        impl Drop for ContextOwner {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let io = std::fs::metadata(directory.path().join("absent-original")).unwrap_err();
        let drops = Arc::new(AtomicUsize::new(0));
        let original = anyhow::Error::new(io).context(ContextOwner(drops.clone()));
        let outer: &(dyn std::error::Error + Send + Sync + 'static) = original.as_ref();
        let address = outer as *const _ as *const () as usize;
        let jobs = jobs();
        let seat = jobs.acquire_failure().unwrap();
        seat.accepted();
        let failure = seat
            .begin()
            .unwrap()
            .run(async { Err::<(), _>(SnapshotFailure::Source(original)) })
            .await
            .unwrap_err();
        assert_eq!(failure.marker().code, ErrorCode::UnknownOutcome);
        failure.with_original(|original| {
            let outer: &(dyn std::error::Error + Send + Sync + 'static) =
                original.unwrap().source_error().unwrap().as_ref();
            assert_eq!(outer as *const _ as *const () as usize, address);
        });
        let entered = AtomicUsize::new(0);
        let repeated = match seat.begin() {
            Ok(_) => panic!("retained original cannot accept another producer"),
            Err(original) => original,
        };
        assert_eq!(entered.load(Ordering::Acquire), 0);
        repeated.with_original(|original| {
            let outer: &(dyn std::error::Error + Send + Sync + 'static) =
                original.unwrap().source_error().unwrap().as_ref();
            assert_eq!(outer as *const _ as *const () as usize, address);
        });
        drop(repeated);
        drop(failure);
        drop(seat);
        let original = jobs.original_failure(0).unwrap();
        original.with_original(|original| {
            let outer: &(dyn std::error::Error + Send + Sync + 'static) =
                original.unwrap().source_error().unwrap().as_ref();
            assert_eq!(outer as *const _ as *const () as usize, address);
        });
        assert_eq!(drops.load(Ordering::Acquire), 0);
        drop(original);
        assert_eq!(
            jobs.drain().await.unwrap_err().completion(),
            DrainCompletion::Retained
        );
        drop(jobs);
        assert_eq!(drops.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn native_free_operation_retires_only_after_its_last_actual_report_alias() {
        let jobs = jobs();
        let seat = jobs.acquire_failure().unwrap();
        let first_state = seat.identity();
        let original = Error::new(ErrorCode::Forbidden, "same original operation");
        let message = original.message.as_ptr();
        let failure = seat
            .begin()
            .unwrap()
            .run(async { Err::<(), _>(SnapshotFailure::Operation(original)) })
            .await
            .unwrap_err();
        assert_eq!(failure.marker().code, ErrorCode::Forbidden);
        failure.with_original(|original| {
            assert_eq!(
                original
                    .unwrap()
                    .operation_error()
                    .unwrap()
                    .message
                    .as_ptr(),
                message
            )
        });
        drop(seat);
        let occupied = jobs.acquire_failure().unwrap();
        assert_ne!(occupied.identity(), first_state);
        drop(occupied);
        drop(failure);
        let reused = jobs.acquire_failure().unwrap();
        assert_eq!(reused.identity(), first_state);
        drop(reused);
        jobs.drain().await.unwrap();
    }

    #[test]
    fn fixed_call_inventory_has_one_exact_resident_charge() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let baseline = admission.snapshot().reserved_bytes;
        let bytes = TargetCallJobs::required_bytes().unwrap();
        let jobs = TargetCallJobs::new(&admission).unwrap();
        assert_eq!(admission.snapshot().reserved_bytes, baseline + bytes);
        drop(jobs);
        assert_eq!(admission.snapshot().reserved_bytes, baseline);
    }

    #[tokio::test]
    async fn ready_ticket_after_original_deadline_is_not_claimed() {
        let jobs = jobs();
        let receive = submission::<_>(&jobs, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap()
            .submit::<anyhow::Error, _>(async { Ok(7_u64) })
            .unwrap();
        let ticket = receive.await.unwrap();
        let (forward, ready) = oneshot::channel();
        assert!(forward.send(ticket).is_ok());
        let expired = Instant::now() - Duration::from_millis(1);
        let error = jobs.await_reply(expired, ready).await.unwrap_err();
        assert_eq!(error.marker().code, ErrorCode::UnknownOutcome);
        jobs.drain().await.unwrap();
    }

    #[tokio::test]
    async fn timeout_retires_unclaimed_success_only_after_exact_child_joins() {
        let jobs = self::jobs();
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = capacity.clone().acquire_owned().await.unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let held = dropped.clone();
        let (finish, completed) = oneshot::channel::<()>();
        let receive = submission::<_>(&jobs, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap()
            .submit::<anyhow::Error, _>(async move {
                completed.await?;
                Ok(TestReply {
                    _permit: permit,
                    dropped: held,
                    panic: None,
                })
            })
            .unwrap();
        let error = match jobs
            .await_reply(Instant::now() + Duration::from_millis(1), receive)
            .await
        {
            Ok(_) => panic!("target timeout unexpectedly released a reply"),
            Err(error) => error,
        };
        assert_eq!(error.marker().code, ErrorCode::UnknownOutcome);
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
        let receive = submission::<_>(&jobs, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap()
            .submit::<anyhow::Error, _>(async { Err::<u64, _>(anyhow!("exact target rejection")) })
            .unwrap();
        let ticket = receive.await.unwrap();
        drop(ticket);
        let first = jobs.drain().await.unwrap_err();
        assert_eq!(first.completion(), DrainCompletion::Retained);
        assert_eq!(first.issues().len(), 1);
        let original = jobs.original_failure(0).unwrap();
        original.with_original(|original| {
            assert_eq!(
                original.unwrap().source_error().unwrap().to_string(),
                "exact target rejection"
            );
        });
        drop(original);
        let again = jobs.drain().await.unwrap_err();
        assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
            &first.issues()[0],
            &again.issues()[0]
        ));

        let jobs = self::jobs();
        let receive = submission::<_>(&jobs, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap()
            .submit::<anyhow::Error, _>(async { Ok(7_u64) })
            .unwrap();
        assert_eq!(
            jobs.await_reply(Instant::now() + Duration::from_secs(5), receive)
                .await
                .unwrap(),
            7
        );
        jobs.drain().await.unwrap();

        let jobs = self::jobs();
        let receive = submission::<_>(&jobs, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap()
            .submit::<anyhow::Error, _>(async {
                Err::<u64, _>(Error::new(ErrorCode::Forbidden, "ordered rejection").into())
            })
            .unwrap();
        let error = jobs
            .await_reply(Instant::now() + Duration::from_secs(5), receive)
            .await
            .unwrap_err();
        assert_eq!(error.marker().code, ErrorCode::Forbidden);
        jobs.drain().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_waiter_and_cancelled_drain_retain_original_child_panic() {
        let jobs = self::jobs();
        let (finish, blocked) = oneshot::channel::<()>();
        let receive = submission::<_>(&jobs, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap()
            .submit::<anyhow::Error, _>(async move {
                blocked.await.unwrap();
                panic!("exact target child panic");
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            })
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
        assert_eq!(result.completion(), DrainCompletion::Retained);
        let original = jobs.original_failure(0).unwrap();
        original.with_report(|report| {
            assert!(report.unwrap().with_body_panic(|_| ()).is_some());
        });
        let again = jobs.drain().await.unwrap_err();
        assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
            &result.issues()[0],
            &again.issues()[0]
        ));
    }

    #[tokio::test]
    async fn child_panic_and_aborted_response_channel_map_to_unknown_outcome() {
        let jobs = self::jobs();
        let receive = submission::<_>(&jobs, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap()
            .submit::<anyhow::Error, _>(async {
                panic!("target child failed after dispatch");
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            })
            .unwrap();
        let error = jobs
            .await_reply(Instant::now() + Duration::from_secs(5), receive)
            .await
            .unwrap_err();
        assert_eq!(error.marker().code, ErrorCode::UnknownOutcome);
        let subsequent = submission::<()>(&jobs, Instant::now() + Duration::from_secs(5)).await;
        let subsequent = match subsequent {
            Ok(_) => panic!("panic failed to seal target-call admission"),
            Err(error) => error,
        };
        assert_eq!(subsequent.marker().code, ErrorCode::Unavailable);
        let failure = jobs.drain().await.unwrap_err();
        assert_eq!(failure.completion(), DrainCompletion::Retained);
        let original = jobs.original_failure(0).unwrap();
        original.with_report(|report| {
            assert!(report.unwrap().with_body_panic(|_| ()).is_some());
        });
        let repeated = jobs.drain().await.unwrap_err();
        assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
            &failure.issues()[0],
            &repeated.issues()[0]
        ));

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
        assert_eq!(error.marker().code, ErrorCode::UnknownOutcome);
        let next = submission::<()>(&channel_jobs, Instant::now() + Duration::from_secs(5)).await;
        let next = match next {
            Ok(_) => panic!("closed response channel failed to seal target-call admission"),
            Err(error) => error,
        };
        assert_eq!(next.marker().code, ErrorCode::Unavailable);
        channel_jobs.drain().await.unwrap();
    }

    #[tokio::test]
    async fn abandoned_outcomes_fill_only_the_fixed_admitted_inventory() {
        let jobs = self::jobs();
        for value in 0..MAX_CALLS {
            let receive = submission::<_>(&jobs, Instant::now() + Duration::from_secs(5))
                .await
                .unwrap()
                .submit::<anyhow::Error, _>(async move { Ok(value) })
                .unwrap();
            drop(receive);
        }
        let extra = submission::<()>(&jobs, Instant::now() + Duration::from_secs(5)).await;
        let error = match extra {
            Ok(_) => panic!("abandoned target outcomes exceeded the fixed inventory"),
            Err(error) => error,
        };
        assert_eq!(error.marker().code, ErrorCode::ResourceExhausted);
        jobs.drain().await.unwrap();
    }

    #[tokio::test]
    async fn actual_abandoned_poll_panic_fences_before_another_producer_is_constructed() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let jobs = TargetCallJobs::new(&admission).unwrap();
        let charged = admission.snapshot().reserved_bytes;
        let loan = submission::<()>(&jobs, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        let original = Box::new("actual abandoned target poll panic");
        let address = &*original as *const &'static str as usize;
        let receive = loan
            .submit::<SnapshotFailure, _>(async move {
                std::panic::resume_unwind(original);
                #[allow(unreachable_code)]
                Ok(())
            })
            .unwrap();
        drop(receive.await.unwrap());
        let failure = jobs.original_failure(0).unwrap();
        let inspect = |report: Option<super::super::target_call_failure::TargetCallReport<'_>>| {
            let report = report.unwrap();
            assert!(report.body_entered());
            assert!(!report.body_returned());
            assert!(report.future_disposal_returned());
            assert_eq!(
                report.with_body_panic(|original| {
                    original.downcast_ref::<&'static str>().unwrap() as *const &'static str as usize
                }),
                Some(address)
            );
        };
        failure.with_report(inspect);
        let constructed = AtomicUsize::new(0);
        let drops = Arc::new(AtomicUsize::new(0));
        let refused = match submission::<()>(&jobs, Instant::now() + Duration::from_secs(5)).await {
            Ok(loan) => {
                let _ = loan.submit(owned_producer(&constructed, &drops));
                panic!("actual retained poll panic failed to fence admission");
            }
            Err(original) => original,
        };
        assert!(matches!(
            refused,
            TargetCallFailure::Admission(kasumi_store::ScratchAdmissionRefusal::Sealed)
        ));
        assert_eq!(constructed.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(failure.marker().code, ErrorCode::UnknownOutcome);
        failure.with_report(inspect);
        assert_eq!(
            jobs.drain().await.unwrap_err().completion(),
            DrainCompletion::Retained
        );
        failure.with_report(inspect);
        drop(failure);
        drop(jobs);
        assert_eq!(admission.snapshot().reserved_bytes, charged);
    }

    #[tokio::test]
    async fn completed_panic_fences_admission_while_original_report_is_borrowed() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let jobs = TargetCallJobs::new(&admission).unwrap();
        let charged = admission.snapshot().reserved_bytes;
        let loan = submission::<()>(&jobs, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        let original = Box::new("actual inspected target poll panic");
        let address = &*original as *const &'static str as usize;
        let receive = loan
            .submit::<SnapshotFailure, _>(async move {
                std::panic::resume_unwind(original);
                #[allow(unreachable_code)]
                Ok(())
            })
            .unwrap();
        let ticket = receive.await.unwrap();
        let original = jobs.original_failure(0).unwrap();
        let (borrowed, report_is_borrowed) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let inspector = std::thread::spawn(move || {
            original.with_report(|report| {
                let report = report.unwrap();
                assert_eq!(
                    report.with_body_panic(|original| {
                        original.downcast_ref::<&'static str>().unwrap() as *const &'static str
                            as usize
                    }),
                    Some(address)
                );
                borrowed.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(5)).unwrap();
            });
            original
        });
        report_is_borrowed
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        let (send, receive) = oneshot::channel();
        assert!(send.send(ticket).is_ok());
        let failure = jobs
            .await_reply(Instant::now() + Duration::from_secs(5), receive)
            .await
            .unwrap_err();
        assert_eq!(failure.marker().code, ErrorCode::UnknownOutcome);
        assert!(jobs.closed.load(Ordering::Acquire));
        let constructed = AtomicUsize::new(0);
        let drops = Arc::new(AtomicUsize::new(0));
        let refused = match submission::<()>(&jobs, Instant::now() + Duration::from_secs(5)).await {
            Ok(loan) => {
                let _ = loan.submit(owned_producer(&constructed, &drops));
                panic!("a borrowed original panic report reopened producer admission");
            }
            Err(original) => original,
        };
        assert!(matches!(
            refused,
            TargetCallFailure::Admission(kasumi_store::ScratchAdmissionRefusal::Sealed)
        ));
        assert_eq!(constructed.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(admission.snapshot().reserved_bytes, charged);
        release.send(()).unwrap();
        let original = inspector.join().unwrap();
        original.with_report(|report| {
            let report = report.unwrap();
            assert_eq!(
                report.with_body_panic(|original| {
                    original.downcast_ref::<&'static str>().unwrap() as *const &'static str as usize
                }),
                Some(address)
            );
            assert!(report.future_disposal_returned());
        });
        assert_eq!(
            jobs.drain().await.unwrap_err().completion(),
            DrainCompletion::Retained
        );
        drop(original);
        drop(failure);
        drop(jobs);
        assert_eq!(admission.snapshot().reserved_bytes, charged);
    }

    #[tokio::test]
    async fn actual_clean_dispatch_refusal_keeps_its_original_and_unentered_observation() {
        struct Unentered {
            polls: Arc<AtomicUsize>,
            drops: Arc<AtomicUsize>,
        }
        impl Future for Unentered {
            type Output = std::result::Result<(), SnapshotFailure>;
            fn poll(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> Poll<Self::Output> {
                self.polls.fetch_add(1, Ordering::SeqCst);
                Poll::Pending
            }
        }
        impl Drop for Unentered {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let jobs = TargetCallJobs::new(&admission).unwrap();
        let charged = admission.snapshot().reserved_bytes;
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let children: [Arc<BackgroundWork>; MAX_CALLS as usize] =
            std::array::from_fn(|_| Arc::new(BackgroundWork::default()));
        for child in &children {
            let gate = gate.clone();
            child
                .start(
                    async move {
                        gate.acquire_owned().await.unwrap().forget();
                    },
                    &jobs.budget,
                )
                .unwrap();
        }
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let submission = submission::<()>(&jobs, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        let work = Unentered {
            polls: polls.clone(),
            drops: drops.clone(),
        };
        let failure = match submission.submit(work) {
            Ok(_) => panic!("the actual original background inventory is full"),
            Err(original) => original,
        };
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(failure.marker().code, ErrorCode::Unavailable);
        assert!(!jobs.closed.load(Ordering::Acquire));
        let address = failure.with_report(|report| {
            let report = report.unwrap();
            assert!(!report.body_entered());
            assert!(!report.body_returned());
            assert!(report.future_disposal_returned());
            assert!(!report.output_disposal_returned());
            assert!(!report.has_output());
            assert!(report.original().is_none());
            assert!(report.with_body_panic(|_| ()).is_none());
            assert!(report.with_future_disposal_panic(|_| ()).is_none());
            assert!(report.with_output_disposal_panic(|_| ()).is_none());
            let original: &(dyn std::error::Error + Send + Sync + 'static) =
                report.dispatch_error().unwrap().as_ref();
            original as *const _ as *const () as usize
        });
        drop(failure);
        let failure = jobs.original_failure(0).unwrap();
        failure.with_report(|report| {
            let report = report.unwrap();
            let original: &(dyn std::error::Error + Send + Sync + 'static) =
                report.dispatch_error().unwrap().as_ref();
            assert_eq!(original as *const _ as *const () as usize, address);
            assert!(report.future_disposal_returned());
        });
        assert_eq!(
            jobs.drain().await.unwrap_err().completion(),
            DrainCompletion::Retained
        );
        gate.add_permits(MAX_CALLS as usize);
        for child in &children {
            tokio::time::timeout(Duration::from_secs(5), child.drain())
                .await
                .unwrap()
                .unwrap();
        }
        drop(failure);
        drop(jobs);
        drop(children);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(admission.snapshot().reserved_bytes, charged);
    }

    #[tokio::test]
    async fn actual_dispatch_original_is_recorded_while_completed_report_is_borrowed() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let jobs = TargetCallJobs::new(&admission).unwrap();
        let charged = admission.snapshot().reserved_bytes;
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let children: [Arc<BackgroundWork>; MAX_CALLS as usize] =
            std::array::from_fn(|_| Arc::new(BackgroundWork::default()));
        for child in &children {
            let gate = gate.clone();
            child
                .start(
                    async move {
                        gate.acquire_owned().await.unwrap().forget();
                    },
                    &jobs.budget,
                )
                .unwrap();
        }
        let constructed = AtomicUsize::new(0);
        let drops = Arc::new(AtomicUsize::new(0));
        let seat = jobs.acquire_failure().unwrap();
        let producer = seat
            .begin()
            .unwrap()
            .run(owned_producer(&constructed, &drops));
        let refused_child = Arc::new(BackgroundWork::default());
        let original = refused_child
            .start(async move { drop(producer.await) }, &jobs.budget)
            .unwrap_err();
        assert_eq!(constructed.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let outer: &(dyn std::error::Error + Send + Sync + 'static) = original.as_ref();
        let address = outer as *const _ as *const () as usize;
        let borrowed = jobs.original_failure(0).unwrap();
        let failure = borrowed.with_report(|report| {
            let report = report.unwrap();
            assert!(!report.body_entered());
            assert!(report.future_disposal_returned());
            assert!(report.dispatch_error().is_none());
            let failure = seat.record_dispatch(original);
            let actual: &(dyn std::error::Error + Send + Sync + 'static) =
                report.dispatch_error().unwrap().as_ref();
            assert_eq!(actual as *const _ as *const () as usize, address);
            failure
        });
        assert_eq!(failure.marker().code, ErrorCode::Unavailable);
        assert_eq!(admission.snapshot().reserved_bytes, charged);
        drop(borrowed);
        drop(seat);
        let original = jobs.original_failure(0).unwrap();
        drop(failure);
        original.with_report(|report| {
            let report = report.unwrap();
            let actual: &(dyn std::error::Error + Send + Sync + 'static) =
                report.dispatch_error().unwrap().as_ref();
            assert_eq!(actual as *const _ as *const () as usize, address);
            assert!(!report.body_entered());
            assert!(report.future_disposal_returned());
        });
        assert_eq!(
            jobs.drain().await.unwrap_err().completion(),
            DrainCompletion::Retained
        );
        gate.add_permits(MAX_CALLS as usize);
        for child in &children {
            tokio::time::timeout(Duration::from_secs(5), child.drain())
                .await
                .unwrap()
                .unwrap();
        }
        drop(refused_child);
        drop(children);
        drop(jobs);
        original.with_report(|report| assert!(report.unwrap().dispatch_error().is_some()));
        drop(original);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(admission.snapshot().reserved_bytes, charged);
    }

    #[tokio::test]
    async fn actual_dispatch_refusal_preserves_independent_unentered_future_disposal_panic() {
        struct DispatchPanic {
            _charge: kasumi_engine::admission::Reservation,
            drops: Arc<AtomicUsize>,
        }
        impl Drop for DispatchPanic {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }
        struct Unentered {
            original: Option<Box<dyn std::any::Any + Send>>,
            polls: Arc<AtomicUsize>,
            drops: Arc<AtomicUsize>,
        }
        impl Future for Unentered {
            type Output = std::result::Result<(), SnapshotFailure>;
            fn poll(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Self::Output> {
                self.polls.fetch_add(1, Ordering::SeqCst);
                Poll::Pending
            }
        }
        impl Drop for Unentered {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                std::panic::resume_unwind(self.original.take().unwrap());
            }
        }
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let jobs = TargetCallJobs::new(&admission).unwrap();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let children: [Arc<BackgroundWork>; MAX_CALLS as usize] =
            std::array::from_fn(|_| Arc::new(BackgroundWork::default()));
        for child in &children {
            let gate = gate.clone();
            child
                .start(
                    async move {
                        gate.acquire_owned().await.unwrap().forget();
                    },
                    &jobs.budget,
                )
                .unwrap();
        }
        let panic_drops = Arc::new(AtomicUsize::new(0));
        let original = Box::new(DispatchPanic {
            _charge: admission
                .reserve_resident(std::mem::size_of::<DispatchPanic>() as u64)
                .unwrap(),
            drops: panic_drops.clone(),
        });
        let panic_address = &*original as *const DispatchPanic as usize;
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let submission = submission::<()>(&jobs, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        let work = Unentered {
            original: Some(original),
            polls: polls.clone(),
            drops: drops.clone(),
        };
        let failure = match submission.submit(work) {
            Ok(_) => panic!("the actual original background inventory is full"),
            Err(original) => original,
        };
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let dispatch_address = failure.with_report(|report| {
            let report = report.unwrap();
            assert!(!report.body_entered());
            assert!(!report.body_returned());
            assert!(!report.future_disposal_returned());
            assert!(report.original().is_none());
            assert_eq!(
                report.with_future_disposal_panic(|original| {
                    original.downcast_ref::<DispatchPanic>().unwrap() as *const DispatchPanic
                        as usize
                }),
                Some(panic_address)
            );
            let original: &(dyn std::error::Error + Send + Sync + 'static) =
                report.dispatch_error().unwrap().as_ref();
            original as *const _ as *const () as usize
        });
        drop(failure);
        let failure = jobs.original_failure(0).unwrap();
        failure.with_report(|report| {
            let report = report.unwrap();
            let original: &(dyn std::error::Error + Send + Sync + 'static) =
                report.dispatch_error().unwrap().as_ref();
            assert_eq!(original as *const _ as *const () as usize, dispatch_address);
            assert_eq!(
                report.with_future_disposal_panic(|original| {
                    original.downcast_ref::<DispatchPanic>().unwrap() as *const DispatchPanic
                        as usize
                }),
                Some(panic_address)
            );
        });
        assert_eq!(failure.marker().code, ErrorCode::UnknownOutcome);
        assert_eq!(
            jobs.drain().await.unwrap_err().completion(),
            DrainCompletion::Retained
        );
        gate.add_permits(MAX_CALLS as usize);
        for child in &children {
            tokio::time::timeout(Duration::from_secs(5), child.drain())
                .await
                .unwrap()
                .unwrap();
        }
        drop(failure);
        drop(jobs);
        drop(children);
        assert_eq!(panic_drops.load(Ordering::SeqCst), 0);
    }
}
