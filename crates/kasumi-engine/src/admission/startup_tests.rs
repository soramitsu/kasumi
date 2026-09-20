use super::*;
use crate::admission::{AdmissionConfig, MemorySource};
use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

struct ZeroRss;
impl MemorySource for ZeroRss {
    fn resident_bytes(&self) -> anyhow::Result<u64> {
        Ok(0)
    }
}
fn core(capacity: usize) -> Arc<MemoryCore> {
    MemoryCore::create(
        AdmissionConfig {
            max_startup_scopes: capacity,
            ..Default::default()
        },
        1 << 30,
        Arc::new(ZeroRss),
        Arc::new(kasumi_clock::SystemLeaseClock),
    )
    .unwrap()
}

#[derive(Debug)]
struct FixedFailure(u64);
impl std::fmt::Display for FixedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fixed child failure {}", self.0)
    }
}
impl StdError for FixedFailure {}
#[derive(Default)]
struct Gate {
    allocated: AtomicBool,
    polled: AtomicBool,
    released: AtomicBool,
    waker: Mutex<Option<Waker>>,
}
impl Gate {
    fn release(&self) {
        let waker = {
            let mut waker = self.waker.lock().unwrap();
            self.released.store(true, Ordering::Release);
            waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}
struct WorkerFuture {
    gate: Arc<Gate>,
    failure: Option<FixedFailure>,
}
impl Future for WorkerFuture {
    type Output = std::result::Result<(), FixedFailure>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let ready = {
            let mut waker = self.gate.waker.lock().unwrap();
            self.gate.polled.store(true, Ordering::Release);
            if self.gate.released.load(Ordering::Acquire) {
                true
            } else {
                *waker = Some(cx.waker().clone());
                false
            }
        };
        if ready {
            Poll::Ready(Err(self.failure.take().unwrap()))
        } else {
            Poll::Pending
        }
    }
}
struct TaskPlan {
    gate: Arc<Gate>,
    failure: u64,
}
struct TaskResource {
    prepared: Option<WorkerFuture>,
    child: Option<tokio::task::JoinHandle<std::result::Result<(), FixedFailure>>>,
    failure: Option<FixedFailure>,
    opaque: Option<tokio::task::JoinError>,
}
impl TaskResource {
    fn start(&mut self) {
        // No await, conversion or fallible application step can intervene between
        // spawning and retaining the original handle in this installed cell.
        self.child = Some(tokio::spawn(self.prepared.take().unwrap()));
    }
}
impl StartupResource for TaskResource {
    type Plan = TaskPlan;
    fn backing_bytes(_: &Self::Plan) -> anyhow::Result<u64> {
        // The actual diagnostic is the fixed inline FixedFailure above. The
        // named existing Tokio slot workspace estimate is separate; these tests
        // qualify custody/accounting mechanics, not allocator-layout guarantees.
        arc_bytes::<Gate>()?
            .checked_add(allocation_bytes::<WorkerFuture>(1)?)
            .and_then(|n| n.checked_add(kasumi_serving::BACKGROUND_WORK_SLOT_BYTES))
            .ok_or_else(|| anyhow::anyhow!("test task workspace overflow"))
    }
    fn allocate(plan: Self::Plan) -> Self {
        plan.gate.allocated.store(true, Ordering::Release);
        Self {
            prepared: Some(WorkerFuture {
                gate: plan.gate,
                failure: Some(FixedFailure(plan.failure)),
            }),
            child: None,
            failure: None,
            opaque: None,
        }
    }
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<DrainCompletion> {
        if self.opaque.is_some() {
            return Poll::Ready(DrainCompletion::Retained);
        }
        self.prepared.take(); // An inert unstarted fixture owns no actual child.
        if let Some(child) = self.child.as_mut() {
            let result = match Pin::new(child).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result,
            };
            self.child.take();
            match result {
                Ok(Ok(())) => {}
                Ok(Err(original)) => self.failure = Some(original),
                Err(original) => {
                    // This adapter has no bounded arbitrary-panic envelope. It
                    // retains the original JoinError, never claiming Complete.
                    self.opaque = Some(original);
                    return Poll::Ready(DrainCompletion::Retained);
                }
            }
        }
        Poll::Ready(DrainCompletion::Complete)
    }
    fn visit_diagnostics(&self, visit: &mut dyn FnMut(&(dyn StdError + 'static))) {
        if let Some(error) = &self.failure {
            visit(error);
        }
        if let Some(error) = &self.opaque {
            visit(error);
        }
    }
}
fn observed(report: &StartupReport) -> Vec<(usize, u64, usize)> {
    let mut values = Vec::new();
    report.visit(|observation| {
        if let StartupObservation::Diagnostic { resource, error } = observation {
            let original = error.downcast_ref::<FixedFailure>().unwrap();
            values.push((resource, original.0, std::ptr::from_ref(original) as usize));
        }
    });
    values
}

#[tokio::test]
async fn actual_children_and_original_errors_survive_cancelled_drain_and_caller_drop() {
    let core = core(1);
    let baseline = core.snapshot();
    let scope = core
        .prepare_startup_scope(StartupSpec { resources: 2 })
        .unwrap();
    let id = scope.id();
    let first = Arc::new(Gate::default());
    let second = Arc::new(Gate::default());
    let a = scope
        .prepare::<TaskResource>(TaskPlan {
            gate: first.clone(),
            failure: 7,
        })
        .unwrap();
    let b = scope
        .prepare::<TaskResource>(TaskPlan {
            gate: second.clone(),
            failure: 11,
        })
        .unwrap();
    a.activate(TaskResource::start).unwrap();
    b.activate(TaskResource::start).unwrap();
    first.release();
    let mut interrupted = Box::pin(scope.drain());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            std::future::poll_fn(|cx| {
                assert!(interrupted.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            if observed(&scope.report()).len() == 1 && second.polled.load(Ordering::Acquire) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(interrupted);
    assert!(scope.wake.waiter.lock().unwrap().is_none());
    let prior = scope.report();
    let first_issue = observed(&prior)[0];
    assert_eq!(prior.completion(), DrainCompletion::Retained);
    let retained_bytes = core.snapshot().reserved_bytes;
    assert!(retained_bytes > baseline.reserved_bytes);
    assert_eq!(
        core.snapshot().inflight_operations,
        baseline.inflight_operations
    );
    drop(a);
    drop(b);
    drop(scope);
    let retained = core.startup_scope_at(id.slot).unwrap();
    assert_eq!(retained.id(), id);
    assert_eq!(observed(&retained.report()), vec![first_issue]);
    assert_eq!(core.snapshot().reserved_bytes, retained_bytes);
    second.release();
    let complete = retained.drain().await;
    assert_eq!(complete.completion(), DrainCompletion::Complete);
    let errors = observed(&complete);
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0], first_issue);
    assert_eq!(errors[1].1, 11);
    assert!(core.startup_scope_at(id.slot).is_none());
    // A fresh lifecycle is allowed; repeated old drain cannot remove its slot.
    let successor = core
        .prepare_startup_scope(StartupSpec { resources: 1 })
        .unwrap();
    assert_eq!(successor.id().slot, id.slot);
    assert_ne!(successor.id().generation, id.generation);
    let repeated = retained.drain().await;
    assert_eq!(observed(&repeated), errors);
    assert!(Arc::ptr_eq(
        &core.startup_scope_at(id.slot).unwrap(),
        &successor
    ));
    drop(successor.drain().await);
    drop(successor);
    drop(retained);
    drop(prior);
    drop(repeated);
    drop(first);
    drop(second);
    let report_clone = complete.clone();
    drop(complete);
    assert_eq!(core.snapshot().reserved_bytes, retained_bytes);
    assert_eq!(observed(&report_clone), errors);
    drop(report_clone);
    assert_eq!(core.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        core.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[tokio::test]
async fn capacity_and_budget_denial_precede_inert_builder_and_preserve_existing_owner() {
    let core = core(1);
    let baseline = core.snapshot();
    let scope = core
        .prepare_startup_scope(StartupSpec { resources: 1 })
        .unwrap();
    let after_scope = core.snapshot();
    assert!(
        core.prepare_startup_scope(StartupSpec { resources: 1 })
            .is_err()
    );
    assert_eq!(core.snapshot().reserved_bytes, after_scope.reserved_bytes);
    let gate = Arc::new(Gate::default());
    let plan = TaskPlan {
        gate: gate.clone(),
        failure: 5,
    };
    let bytes =
        allocation_bytes::<TaskResource>(1).unwrap() + TaskResource::backing_bytes(&plan).unwrap();
    let free = core.data.max_bytes - core.snapshot().reserved_bytes;
    let held = core.reserve_resident(free - bytes + 1).unwrap();
    let charged = core.snapshot();
    assert!(scope.prepare::<TaskResource>(plan).is_err());
    assert!(!gate.allocated.load(Ordering::Acquire));
    assert_eq!(core.snapshot().reserved_bytes, charged.reserved_bytes);
    drop(held);
    let owner = scope
        .prepare::<TaskResource>(TaskPlan {
            gate: gate.clone(),
            failure: 5,
        })
        .unwrap();
    let denied = Arc::new(Gate::default());
    let occupied = core.snapshot();
    assert!(
        scope
            .prepare::<TaskResource>(TaskPlan {
                gate: denied.clone(),
                failure: 6
            })
            .is_err()
    );
    assert!(!denied.allocated.load(Ordering::Acquire));
    assert_eq!(core.snapshot().reserved_bytes, occupied.reserved_bytes);
    let report = scope.drain().await;
    assert_eq!(report.completion(), DrainCompletion::Complete);
    assert!(owner.activate(TaskResource::start).is_err());
    drop(owner);
    drop(scope);
    drop(gate);
    drop(denied);
    drop(report);
    assert_eq!(core.snapshot().reserved_bytes, baseline.reserved_bytes);
}
