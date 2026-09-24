//! Retained actual blocking-child ownership for admitted snapshot operations.
//!
//! This foundation has no adapter for the current snapshot decoder's consuming
//! transaction cleanup. Such an adapter must keep its staging state outside the
//! fallible worker body and return Retained whenever cleanup is not proved.
use super::{MemoryCore, NodeAdmission, Reservation, allocation_bytes, arc_bytes};
use kasumi_query::QueryCancellation;
use kasumi_types::{Error, ErrorCode, Result, drain::DrainCompletion};
use std::{
    any::Any,
    error::Error as StdError,
    future::Future,
    mem::ManuallyDrop,
    ops::Deref,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotWorkId {
    pub slot: usize,
    pub generation: u64,
}
struct CensusSlot {
    generation: u64,
    reserved: bool,
    owner: Option<ErasedOwner>,
}
pub(super) struct Census {
    next: u64,
    slots: Box<[CensusSlot]>,
}
impl Census {
    pub(super) fn required_bytes(capacity: usize) -> anyhow::Result<u64> {
        allocation_bytes::<CensusSlot>(capacity)
    }
    pub(super) fn allocate(capacity: usize) -> anyhow::Result<Self> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(capacity)?;
        slots.resize_with(capacity, || CensusSlot {
            generation: 0,
            reserved: false,
            owner: None,
        });
        Ok(Self {
            next: 0,
            slots: slots.into_boxed_slice(),
        })
    }
}
struct CensusTicket {
    core: Arc<MemoryCore>,
    id: SnapshotWorkId,
    published: bool,
}
impl Drop for CensusTicket {
    fn drop(&mut self) {
        if !self.published {
            let mut census = self
                .core
                .snapshot_work
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let slot = &mut census.slots[self.id.slot];
            if slot.generation == self.id.generation && slot.owner.is_none() {
                slot.reserved = false;
            }
        }
    }
}

/// Trusted concrete operation state, installed before its actual child starts.
///
/// backing_bytes validates the plan and accounts for all operation-owned heap,
/// original diagnostic and output backing beyond Self. The owner separately
/// reserves its concrete layout and the named Tokio slot workspace estimate.
/// allocate is inert; run borrows the retained operation and must not hide an
/// independently owned child in a local variable or detached supervisor.
///
/// poll_cleanup positively drains operation-owned resources. A joined worker is
/// not proof of cleanup. Interrupted consuming close/abort, an opaque run panic,
/// or uncertain ownership must remain Retained. poll_discard does the same for
/// an unclaimed output. Complete permits infallible destruction of that value.
/// A claimed Output must own its backing and leases independently of this owner.
/// Arbitrary anyhow or panic payload sizes are not implicitly a bounded plan.
/// Cleanup/discard may wake their Context synchronously. The owner records that
/// proxy notification and calls the external executor only after its locks exit.
pub trait SnapshotOperation: Send + 'static {
    type Plan;
    type Output: Send + 'static;
    type Failure: StdError + Send + 'static;
    fn validate_memory(plan: &Self::Plan, core: &Arc<MemoryCore>) -> anyhow::Result<()>;
    fn backing_bytes(plan: &Self::Plan) -> anyhow::Result<u64>;
    fn allocate(plan: Self::Plan, cancellation: QueryCancellation) -> Self;
    fn run(&mut self) -> std::result::Result<Self::Output, Self::Failure>;
    fn poll_cleanup(&mut self, cx: &mut Context<'_>) -> Poll<DrainCompletion>;
    fn poll_discard(output: &mut Self::Output, cx: &mut Context<'_>) -> Poll<DrainCompletion>;
    fn visit_diagnostics(&self, visit: &mut dyn FnMut(&(dyn StdError + 'static)));
    fn visit_output_diagnostics(
        output: &Self::Output,
        visit: &mut dyn FnMut(&(dyn StdError + 'static)),
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotPanicPhase {
    Allocate,
    Start,
    Run,
    JoinPoll,
    Cleanup,
    Discard,
}
struct OriginalPanic {
    phase: SnapshotPanicPhase,
    payload: Box<dyn Any + Send>,
}
struct Resource<O: SnapshotOperation> {
    operation: Option<O>,
    output: Option<O::Output>,
    // Positive output cleanup leaves the original fixed output/diagnostic object
    // with the report until its last view drops, without retaining physical work.
    discarded: Option<O::Output>,
    failure: Option<O::Failure>,
    panic: Option<OriginalPanic>,
    cleanup_complete: bool,
}
struct Control {
    started: bool,
    joined: bool,
    closing: bool,
    child: Option<tokio::task::JoinHandle<()>>,
    join_error: Option<tokio::task::JoinError>,
    panic: Option<OriginalPanic>,
}
struct WakeState {
    waiter: Option<Waker>,
    // Nested and concurrent owner scopes share one inline deferral counter.
    // A scope is entered before any owner lock and exits after its guards.
    owner_scopes: usize,
    notified: bool,
}
impl WakeState {
    fn take_notification(&mut self) -> Option<Waker> {
        if self.owner_scopes == 0 && self.notified {
            self.notified = false;
            self.waiter.take()
        } else {
            None
        }
    }
}
// The actual wake allocation can outlive its operation through a registered or
// in-progress proxy Waker. Keep the original complete operation reservation here.
// Every strong release uses into_inner, so this allocation itself is destroyed
// before its final field can return admission credit. No raw Arc or Weak escapes.
struct WorkWake {
    state: Mutex<WakeState>,
    _charge: Reservation,
}
impl WorkWake {
    fn notify(&self) {
        let waiter = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.notified = true;
            state.take_notification()
        };
        // Consume the registration outside the wake-state mutex. An owner
        // callback records its notification until all entered scopes leave;
        // it cannot synchronously reenter the owner through an executor wake.
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
    fn dispatch_pending(&self) {
        if std::thread::panicking() {
            // As in DeferWake, never introduce an executor callback during an
            // existing unwind. Preserve the registration and notification.
            return;
        }
        let waiter = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take_notification();
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
    fn defer(&self) -> DeferWake<'_> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.owner_scopes = state
            .owner_scopes
            .checked_add(1)
            .expect("snapshot wake scope overflow");
        DeferWake(self)
    }
    fn register(&self, incoming: Waker) {
        let replaced = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state
                .waiter
                .as_ref()
                .is_none_or(|old| !old.will_wake(&incoming))
            {
                state.waiter.replace(incoming)
            } else {
                Some(incoming)
            }
        };
        drop(replaced);
    }
}
// Declare this guard before acquiring any Owner mutex. Rust drops the later
// mutex guards first on every return/unwind path. The last nested/concurrent
// scope forwards a queued notification only after releasing its owner locks.
// The counter and flag belong to the already admitted WorkWake allocation.
struct DeferWake<'a>(&'a WorkWake);
impl Drop for DeferWake<'_> {
    fn drop(&mut self) {
        let waiter = {
            let mut state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
            state.owner_scopes -= 1;
            // Do not invoke an arbitrary callback while unwinding an existing
            // panic. Keep its pending notification/registration for a retry;
            // a cancelled finish clears that registration outside all locks.
            if std::thread::panicking() {
                None
            } else {
                state.take_notification()
            }
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
}
struct OwnedWake(Option<Arc<WorkWake>>);
impl OwnedWake {
    fn new(charge: Reservation) -> Self {
        Self(Some(Arc::new(WorkWake {
            state: Mutex::new(WakeState {
                waiter: None,
                owner_scopes: 0,
                notified: false,
            }),
            _charge: charge,
        })))
    }
    fn waker(&self) -> Waker {
        let wake = self.0.as_ref().expect("owned wake").clone();
        let pointer = Arc::into_raw(wake).cast::<()>();
        // SAFETY: the raw pointer transfers exactly one live Arc strong count
        // into this Waker; every vtable operation follows that ownership below.
        unsafe { Waker::from_raw(RawWaker::new(pointer, &WORK_WAKE_VTABLE)) }
    }
}
impl Clone for OwnedWake {
    fn clone(&self) -> Self {
        Self(Some(self.0.as_ref().expect("owned wake").clone()))
    }
}
impl Deref for OwnedWake {
    type Target = WorkWake;
    fn deref(&self) -> &Self::Target {
        self.0.as_deref().expect("owned wake")
    }
}
impl Drop for OwnedWake {
    fn drop(&mut self) {
        if let Some(wake) = self.0.take().and_then(Arc::into_inner) {
            // No Weak exists. Arc::into_inner already retired the real backing.
            drop(wake);
        }
    }
}

// These private callbacks are the only owners of raw WorkWake pointers. A raw
// Waker owns one count, cloning creates one, wake/drop consume one, and
// wake_by_ref only borrows one. Every consumed count goes through OwnedWake;
// even a panicking user wake callback cannot skip the final retirement protocol.
static WORK_WAKE_VTABLE: RawWakerVTable =
    RawWakerVTable::new(clone_work_wake, wake_work, wake_work_by_ref, drop_work_wake);
unsafe fn clone_work_wake(pointer: *const ()) -> RawWaker {
    // SAFETY: the borrowed source Waker keeps this exact Arc allocation alive.
    unsafe { Arc::increment_strong_count(pointer.cast::<WorkWake>()) };
    RawWaker::new(pointer, &WORK_WAKE_VTABLE)
}
unsafe fn wake_work(pointer: *const ()) {
    // SAFETY: wake consumes the source Waker's one strong count exactly once.
    let wake = OwnedWake(Some(unsafe { Arc::from_raw(pointer.cast::<WorkWake>()) }));
    wake.notify();
    // OwnedWake also runs during callback unwinding.
}
unsafe fn wake_work_by_ref(pointer: *const ()) {
    // SAFETY: this is a borrowed count owned by the source Waker. ManuallyDrop
    // prevents decrementing it on return or callback unwind; the source still
    // owns it. No new Arc count is created and no raw Arc is returned.
    let wake = ManuallyDrop::new(unsafe { Arc::from_raw(pointer.cast::<WorkWake>()) });
    wake.notify();
}
unsafe fn drop_work_wake(pointer: *const ()) {
    // SAFETY: drop consumes the source Waker's one strong count exactly once.
    drop(OwnedWake(Some(unsafe {
        Arc::from_raw(pointer.cast::<WorkWake>())
    })));
}
struct ClearWaiter<'a>(&'a WorkWake);
impl Drop for ClearWaiter<'_> {
    fn drop(&mut self) {
        let waiter = self
            .0
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .waiter
            .take();
        drop(waiter);
    }
}

struct Owner<O: SnapshotOperation> {
    id: SnapshotWorkId,
    // The worker may hold resource while blocked. Poll/report paths inspect
    // control first and never take resource until the actual handle is joined.
    control: Mutex<Control>,
    resource: Mutex<Resource<O>>,
    serial: tokio::sync::Mutex<()>,
    cancellation: QueryCancellation,
    core: Arc<MemoryCore>,
    // Last: actual Owner allocation and all fields retire before this count.
    // External proxy wakers may retain the same original charge even longer.
    wake: OwnedWake,
}
// Typed delivery/worker handles and erased report/census handles cannot expose
// their inner Arc. Every final release moves the value out before destroying it,
// rather than releasing a lease from inside the still-allocated Arc payload.
struct OwnedOwner<O: SnapshotOperation>(Option<Arc<Owner<O>>>);
impl<O: SnapshotOperation> OwnedOwner<O> {
    fn erased(&self) -> ErasedOwner {
        ErasedOwner(Some(self.0.as_ref().expect("owned operation").clone()))
    }
}
impl<O: SnapshotOperation> Clone for OwnedOwner<O> {
    fn clone(&self) -> Self {
        Self(Some(self.0.as_ref().expect("owned operation").clone()))
    }
}
impl<O: SnapshotOperation> Deref for OwnedOwner<O> {
    type Target = Owner<O>;
    fn deref(&self) -> &Self::Target {
        self.0.as_deref().expect("owned operation")
    }
}
impl<O: SnapshotOperation> Drop for OwnedOwner<O> {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take().and_then(Arc::into_inner) {
            drop(owner);
        }
    }
}
struct ErasedOwner(Option<Arc<dyn ErasedWork>>);
impl Clone for ErasedOwner {
    fn clone(&self) -> Self {
        Self(Some(self.0.as_ref().expect("owned report").clone()))
    }
}
impl Deref for ErasedOwner {
    type Target = dyn ErasedWork;
    fn deref(&self) -> &Self::Target {
        self.0.as_deref().expect("owned report")
    }
}
impl Drop for ErasedOwner {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            // Dynamic dispatch restores the concrete sized Arc before release.
            owner.retire();
        }
    }
}
impl<O: SnapshotOperation> Owner<O> {
    fn required_bytes(plan: &O::Plan) -> anyhow::Result<u64> {
        let backing = O::backing_bytes(plan)?;
        let cancellation = u64::try_from(QueryCancellation::shared_state_bytes())?
            .checked_add(arc_bytes::<()>()?)
            .ok_or_else(|| anyhow::anyhow!("snapshot cancellation allocation overflow"))?;
        arc_bytes::<Self>()?
            .checked_add(arc_bytes::<WorkWake>()?)
            .and_then(|n| n.checked_add(cancellation))
            .and_then(|n| n.checked_add(kasumi_serving::BACKGROUND_WORK_SLOT_BYTES))
            .and_then(|n| n.checked_add(backing))
            .ok_or_else(|| anyhow::anyhow!("snapshot work allocation overflow or unsupported plan"))
    }
    fn run(&self) {
        let _defer = self.wake.defer();
        let mut resource = self.resource.lock().unwrap_or_else(|p| p.into_inner());
        let operation = resource
            .operation
            .as_mut()
            .expect("inert operation installed");
        match catch_unwind(AssertUnwindSafe(|| operation.run())) {
            Ok(Ok(output)) => resource.output = Some(output),
            Ok(Err(failure)) => resource.failure = Some(failure),
            Err(payload) => {
                resource.panic = Some(OriginalPanic {
                    phase: SnapshotPanicPhase::Run,
                    payload,
                })
            }
        }
        // The Tokio handle, not this wake or callback return, proves termination.
    }
    fn start(owner: &OwnedOwner<O>) -> Result<()> {
        let _defer = owner.wake.defer();
        let mut control = owner.control.lock().unwrap_or_else(|p| p.into_inner());
        if control.closing || control.started || control.panic.is_some() {
            return Err(Error::new(
                ErrorCode::Conflict,
                "snapshot work is closed or already started",
            ));
        }
        if owner
            .resource
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .panic
            .is_some()
        {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "snapshot work allocation panicked",
            ));
        }
        control.started = true;
        let worker = owner.clone();
        // No suspension or application work intervenes between actual spawn and
        // retaining its original handle in the already published owner.
        match catch_unwind(AssertUnwindSafe(|| {
            tokio::task::spawn_blocking(move || worker.run())
        })) {
            Ok(child) => control.child = Some(child),
            Err(payload) => {
                control.panic = Some(OriginalPanic {
                    phase: SnapshotPanicPhase::Start,
                    payload,
                });
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    "snapshot child start panicked; owner retained",
                ));
            }
        }
        Ok(())
    }
    fn poll_join(&self, cx: &mut Context<'_>) -> Poll<bool> {
        let _defer = self.wake.defer();
        let mut control = self.control.lock().unwrap_or_else(|p| p.into_inner());
        if control.panic.is_some() || control.join_error.is_some() {
            return Poll::Ready(false);
        }
        if control.joined {
            return Poll::Ready(true);
        }
        if !control.started {
            if control.closing {
                control.joined = true;
                return Poll::Ready(true);
            }
            return Poll::Ready(false);
        }
        let child = control.child.as_mut().expect("started child retained");
        match catch_unwind(AssertUnwindSafe(|| Pin::new(child).poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(outcome)) => {
                control.child.take();
                control.joined = true;
                match outcome {
                    Ok(()) => Poll::Ready(true),
                    Err(error) => {
                        control.join_error = Some(error);
                        Poll::Ready(false)
                    }
                }
            }
            Err(payload) => {
                // Never poll an actual handle again after an interrupted poll.
                control.panic = Some(OriginalPanic {
                    phase: SnapshotPanicPhase::JoinPoll,
                    payload,
                });
                Poll::Ready(false)
            }
        }
    }
    fn poll_finish(&self, cx: &mut Context<'_>, discard: bool) -> Poll<()> {
        let _defer = self.wake.defer();
        match self.poll_join(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(false) => return Poll::Ready(()),
            Poll::Ready(true) => {}
        }
        let mut resource = self.resource.lock().unwrap_or_else(|p| p.into_inner());
        if resource.panic.is_some() {
            return Poll::Ready(());
        }
        if !resource.cleanup_complete {
            let operation = resource
                .operation
                .as_mut()
                .expect("non-panicked inert operation");
            match catch_unwind(AssertUnwindSafe(|| operation.poll_cleanup(cx))) {
                Ok(Poll::Pending) => return Poll::Pending,
                Ok(Poll::Ready(DrainCompletion::Retained)) => return Poll::Ready(()),
                Ok(Poll::Ready(DrainCompletion::Complete)) => resource.cleanup_complete = true,
                Err(payload) => {
                    resource.panic = Some(OriginalPanic {
                        phase: SnapshotPanicPhase::Cleanup,
                        payload,
                    });
                    return Poll::Ready(());
                }
            }
        }
        if discard && let Some(output) = resource.output.as_mut() {
            match catch_unwind(AssertUnwindSafe(|| O::poll_discard(output, cx))) {
                Ok(Poll::Pending) => return Poll::Pending,
                Ok(Poll::Ready(DrainCompletion::Retained)) => return Poll::Ready(()),
                Ok(Poll::Ready(DrainCompletion::Complete)) => {
                    resource.discarded = resource.output.take();
                }
                Err(payload) => {
                    resource.panic = Some(OriginalPanic {
                        phase: SnapshotPanicPhase::Discard,
                        payload,
                    })
                }
            }
        }
        Poll::Ready(())
    }
}
trait ErasedWork: Send + Sync {
    fn id(&self) -> SnapshotWorkId;
    fn core(&self) -> &Arc<MemoryCore>;
    fn serial(&self) -> &tokio::sync::Mutex<()>;
    fn wake(&self) -> &OwnedWake;
    fn retire(self: Arc<Self>);
    fn close(&self);
    fn poll_finish(&self, cx: &mut Context<'_>, discard: bool) -> Poll<()>;
    fn completion(&self) -> DrainCompletion;
    fn visit(&self, visit: &mut dyn FnMut(SnapshotObservation<'_>));
}
impl<O: SnapshotOperation> ErasedWork for Owner<O> {
    fn id(&self) -> SnapshotWorkId {
        self.id
    }
    fn core(&self) -> &Arc<MemoryCore> {
        &self.core
    }
    fn serial(&self) -> &tokio::sync::Mutex<()> {
        &self.serial
    }
    fn wake(&self) -> &OwnedWake {
        &self.wake
    }
    fn retire(self: Arc<Self>) {
        if let Some(owner) = Arc::into_inner(self) {
            drop(owner);
        }
    }
    fn close(&self) {
        let _defer = self.wake.defer();
        self.control
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .closing = true;
        self.cancellation.cancel();
    }
    fn poll_finish(&self, cx: &mut Context<'_>, discard: bool) -> Poll<()> {
        let _defer = self.wake.defer();
        Owner::poll_finish(self, cx, discard)
    }
    fn completion(&self) -> DrainCompletion {
        let _defer = self.wake.defer();
        let control = self.control.lock().unwrap_or_else(|p| p.into_inner());
        if !control.joined || control.panic.is_some() || control.join_error.is_some() {
            return DrainCompletion::Retained;
        }
        let resource = self.resource.lock().unwrap_or_else(|p| p.into_inner());
        if resource.cleanup_complete && resource.panic.is_none() && resource.output.is_none() {
            DrainCompletion::Complete
        } else {
            DrainCompletion::Retained
        }
    }
    fn visit(&self, visit: &mut dyn FnMut(SnapshotObservation<'_>)) {
        let _defer = self.wake.defer();
        let control = self.control.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(error) = &control.join_error {
            visit(SnapshotObservation::JoinError(error));
        }
        if let Some(panic) = &control.panic {
            visit(SnapshotObservation::Panic {
                phase: panic.phase,
                payload: panic.payload.as_ref(),
            });
        }
        // A report callback must never wait for a running blocking operation.
        if !control.joined {
            return;
        }
        let resource = self.resource.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(error) = &resource.failure {
            visit(SnapshotObservation::Failure(error));
        }
        if let Some(operation) = &resource.operation {
            operation.visit_diagnostics(&mut |error| visit(SnapshotObservation::Diagnostic(error)));
        }
        if let Some(output) = resource.discarded.as_ref().or(resource.output.as_ref()) {
            O::visit_output_diagnostics(output, &mut |error| {
                visit(SnapshotObservation::Diagnostic(error))
            });
        }
        if let Some(panic) = &resource.panic {
            visit(SnapshotObservation::Panic {
                phase: panic.phase,
                payload: panic.payload.as_ref(),
            });
        }
    }
}

/// Caller delivery capability. Dropping it cancels delivery, never the actual
/// handle or result retained in MemoryCore's fixed strong census.
pub struct SnapshotWork<O: SnapshotOperation> {
    owner: OwnedOwner<O>,
}
impl<O: SnapshotOperation> Drop for SnapshotWork<O> {
    fn drop(&mut self) {
        self.owner.cancellation.cancel();
    }
}
impl<O: SnapshotOperation> SnapshotWork<O> {
    pub fn id(&self) -> SnapshotWorkId {
        self.owner.id
    }
    pub fn start(&self) -> Result<()> {
        Owner::start(&self.owner)
    }
    pub fn report(&self) -> SnapshotWorkReport {
        SnapshotWorkReport {
            owner: self.owner.erased(),
        }
    }
    /// Wait for the actual join and operation cleanup without moving its output
    /// into this cancelable future. Claim is a later synchronous transfer.
    pub async fn ready(&self) -> SnapshotWorkReport {
        let report = self.report();
        report.finish(false).await;
        // A joined typed failure with positive cleanup has no pending output.
        // Do not leave an already Complete operation in the strong core cycle.
        report.retire_complete();
        report
    }
    pub fn claim(&self) -> std::result::Result<O::Output, SnapshotWorkReport> {
        // Arbitrary executor callbacks must finish while the output is still
        // in retained custody. They can themselves close/claim this owner, so
        // recheck all eligibility only after dispatch returns.
        self.owner.wake.dispatch_pending();
        let report = self.report();
        // This final section invokes no adapter, Waker or executor callback.
        // In particular, do not add a dispatching DeferWake/Tokio guard here:
        // a callback panic after output.take would destroy an undelivered value
        // without its required poll_discard. Concurrent callbacks can contend
        // for these std mutexes, but this section cannot call back into them.
        let control = self.owner.control.lock().unwrap_or_else(|p| p.into_inner());
        if control.closing
            || !control.joined
            || control.panic.is_some()
            || control.join_error.is_some()
        {
            return Err(report);
        }
        let mut resource = self
            .owner
            .resource
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if !resource.cleanup_complete || resource.panic.is_some() || resource.failure.is_some() {
            return Err(report);
        }
        let Some(output) = resource.output.take() else {
            return Err(report);
        };
        let retired = {
            let mut census = self
                .owner
                .core
                .snapshot_work
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            match census.slots.get_mut(self.owner.id.slot) {
                Some(slot) if slot.generation == self.owner.id.generation => {
                    slot.reserved = false;
                    slot.owner.take()
                }
                _ => None,
            }
        };
        drop(resource);
        drop(control);
        // No completion()/retire_complete() dispatch after the transfer. Both
        // extra owner counts retire outside the locks; borrowed self guarantees
        // that neither can be the final actual Owner/resource destruction.
        drop(retired);
        drop(report);
        Ok(output)
    }
}

/// Original diagnostics are borrowed under the owner locks. Callbacks must not
/// recursively enter the same owner. No report grows or clones a diagnostic Vec.
pub enum SnapshotObservation<'a> {
    Failure(&'a (dyn StdError + 'static)),
    Diagnostic(&'a (dyn StdError + 'static)),
    JoinError(&'a tokio::task::JoinError),
    Panic {
        phase: SnapshotPanicPhase,
        payload: &'a (dyn Any + Send),
    },
}
/// Executor callbacks may inspect completion, but must not synchronously block
/// waiting for another finish/drain of this same owner. Those asynchronous
/// operations share a serial gate protecting the single waiter registration.
#[derive(Clone)]
pub struct SnapshotWorkReport {
    owner: ErasedOwner,
}
impl SnapshotWorkReport {
    pub fn id(&self) -> SnapshotWorkId {
        self.owner.id()
    }
    pub fn completion(&self) -> DrainCompletion {
        self.owner.completion()
    }
    pub fn visit(&self, mut visit: impl FnMut(SnapshotObservation<'_>)) {
        self.owner.visit(&mut visit);
    }
    async fn finish(&self, discard: bool) {
        let _serial = self.owner.serial().lock().await;
        let wake = self.owner.wake();
        let _clear = ClearWaiter(wake);
        let proxy = wake.waker();
        std::future::poll_fn(|cx| {
            // Clone callbacks may run arbitrary executor code; do this before
            // acquiring the waiter lock, and destroy replaced counts after it.
            wake.register(cx.waker().clone());
            self.owner
                .poll_finish(&mut Context::from_waker(&proxy), discard)
        })
        .await;
    }
    /// Synchronously fences this one job before the first suspension. Cancelled
    /// drains leave the exact handle, resource and outcome in the same cell.
    pub async fn drain(&self) -> Self {
        self.owner.close();
        self.finish(true).await;
        self.retire_complete();
        self.clone()
    }
    fn retire_complete(&self) {
        if self.completion() != DrainCompletion::Complete {
            return;
        }
        let retired = {
            let mut census = self
                .owner
                .core()
                .snapshot_work
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let id = self.id();
            let slot = &mut census.slots[id.slot];
            if slot.generation != id.generation {
                return;
            }
            slot.reserved = false;
            slot.owner.take()
        };
        drop(retired);
    }
}
impl NodeAdmission {
    /// Reserve a concrete operation and result owner before constructing its
    /// inert state. Slot count comes from max_inflight_operations, not the
    /// unrelated startup-scope policy. This does not spawn the actual child.
    pub fn prepare_snapshot_work<O: SnapshotOperation>(
        self: &Arc<Self>,
        plan: O::Plan,
    ) -> Result<SnapshotWork<O>> {
        O::validate_memory(&plan, self.memory()).map_err(|_| {
            Error::new(
                ErrorCode::Conflict,
                "snapshot operation and memory owners differ",
            )
        })?;
        let bytes = Owner::<O>::required_bytes(&plan)
            .map_err(|_| Error::new(ErrorCode::ResourceExhausted, "snapshot work plan invalid"))?;
        let mut ticket = {
            let mut census = self
                .core
                .snapshot_work
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let slot = census
                .slots
                .iter()
                .position(|slot| !slot.reserved)
                .ok_or_else(|| {
                    Error::new(ErrorCode::ResourceExhausted, "snapshot work census is full")
                })?;
            let generation = census.next;
            census.next = generation.checked_add(1).ok_or_else(|| {
                Error::new(ErrorCode::Unavailable, "snapshot work identity exhausted")
            })?;
            census.slots[slot].reserved = true;
            census.slots[slot].generation = generation;
            CensusTicket {
                core: self.core.clone(),
                id: SnapshotWorkId { slot, generation },
                published: false,
            }
        };
        // The reservation precedes even the cancellation Arc allocation. Bind
        // its token into that same already charged operation slot before any
        // inert builder or child can run; concurrent pressure is observed here.
        let charge = self.reserve(bytes, None)?;
        let cancellation = QueryCancellation::default();
        {
            let mut state = self
                .core
                .data
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let cancel_now = !state.usable || state.pressured;
            state
                .charge_mut(charge.slot, charge.id)
                .expect("admitted snapshot charge")
                .cancellation = Some(cancellation.clone());
            if cancel_now {
                cancellation.cancel();
            }
        }
        let allocated = catch_unwind(AssertUnwindSafe(|| O::allocate(plan, cancellation.clone())));
        let (operation, panic) = match allocated {
            Ok(operation) => (Some(operation), None),
            Err(payload) => (
                None,
                Some(OriginalPanic {
                    phase: SnapshotPanicPhase::Allocate,
                    payload,
                }),
            ),
        };
        let allocation_panicked = panic.is_some();
        let owner = OwnedOwner(Some(Arc::new(Owner {
            id: ticket.id,
            control: Mutex::new(Control {
                started: false,
                joined: false,
                closing: false,
                child: None,
                join_error: None,
                panic: None,
            }),
            resource: Mutex::new(Resource {
                operation,
                output: None,
                discarded: None,
                failure: None,
                panic,
                cleanup_complete: false,
            }),
            serial: tokio::sync::Mutex::new(()),
            cancellation,
            core: self.core.clone(),
            wake: OwnedWake::new(charge),
        })));
        {
            let mut census = self
                .core
                .snapshot_work
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            census.slots[ticket.id.slot].owner = Some(owner.erased());
            ticket.published = true;
        }
        if allocation_panicked {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "snapshot inert allocation panicked; exact owner retained",
            ));
        }
        Ok(SnapshotWork { owner })
    }
}
impl MemoryCore {
    pub fn snapshot_work_capacity(&self) -> usize {
        self.data.config.max_inflight_operations
    }
    /// Stable per-cell custody lookup. Traversal alone does not assert whole-core
    /// completion while admission/preparation remains open. Runtime adapters must
    /// close their own admission first and retain a preparing census obligation.
    pub fn snapshot_work_at(&self, index: usize) -> Option<SnapshotWorkReport> {
        self.snapshot_work
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .slots
            .get(index)
            .and_then(|slot| slot.owner.clone())
            .map(|owner| SnapshotWorkReport { owner })
    }
}
#[cfg(test)]
#[path = "snapshot_work_tests.rs"]
mod tests;
