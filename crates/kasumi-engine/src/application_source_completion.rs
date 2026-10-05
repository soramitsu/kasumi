//! Actual ordinary source owners retained through the adapter's outer finish.
//! The standing grant funds these fixed shells, not candidate bodies or reads.
use super::*;
use kasumi_raft::{
    CompletionActionFailureIdentity, CompletionBinding, CompletionCustody, CompletionFinalization,
    CompletionIdentity, CompletionInvocation, CompletionSettleError, CompletionVerdict,
};
use std::{
    ops::{Deref, DerefMut},
    sync::{MutexGuard, TryLockError},
};

pub(crate) type CompletionRef = ownership::Strong<OrdinarySourceCompletion>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Idle,
    Entered,
    Captured,
    Retained,
    Settled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cleanup {
    Pending,
    Running,
    Returned,
}
struct State {
    ordinal: u64,
    phase: Phase,
    attempted: bool,
    repeated: bool,
    preparation: Option<RootPreparation>,
    selected: Option<SelectedApplication>,
    witness: Option<CellRef>,
    failed_capture: Option<CapturedFailure>,
    cleanup: Cleanup,
    #[cfg(test)]
    fault: Option<(CompletionCheckpoint, CompletionFault)>,
}
struct CapturedFailure {
    identity: CompletionActionFailureIdentity,
    // Same admitted original diagnostic and credit, independent of Cell Drop.
    original: FailureRef,
    retired: bool,
}
pub(crate) struct OrdinarySourceCompletion {
    identity: CompletionIdentity,
    roots: SourceRootsWeak,
    state: Mutex<State>,
    waiter: Mutex<Option<Waker>>,
    waking: AtomicBool,
    wake_panic: OnceLock<Mutex<Box<dyn std::any::Any + Send>>>,
    sealed: AtomicBool,
    drained: AtomicBool,
}
struct Guard<'a> {
    owner: &'a OrdinarySourceCompletion,
    state: Option<MutexGuard<'a, State>>,
}
impl Deref for Guard<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        self.state.as_deref().expect("completion state")
    }
}
impl DerefMut for Guard<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.state.as_deref_mut().expect("completion state")
    }
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        // Registration precedes try_lock; no wake callback under either mutex.
        drop(self.state.take());
        self.owner.wake();
    }
}
impl OrdinarySourceCompletion {
    pub(super) fn required_bytes() -> Result<u64> {
        let cell = allocated(std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>())?;
        let credit = SourceCredit::required_bytes()?;
        let binding = CompletionBinding::required_bytes::<CompletionRef>()?;
        cell.checked_add(credit)
            .and_then(|n| n.checked_add(binding))
            .context("application completion allocation overflow")
    }
    pub(super) fn new(roots: &SourceRootsRef) -> Result<(CompletionRef, CompletionBinding)> {
        roots
            .admission
            .memory()
            .require_store_memory(roots.stores.application())?;
        roots
            .admission
            .memory()
            .require_store_memory(roots.stores.custody().store())?;
        let credit = SourceCredit::new(
            roots
                .admission
                .reserve_document_source(Self::required_bytes()?)?,
        );
        let owner = CompletionRef::new(
            Self {
                identity: CompletionIdentity::new(),
                roots: roots.downgrade(),
                state: Mutex::new(State {
                    ordinal: 0,
                    phase: Phase::Idle,
                    attempted: false,
                    repeated: false,
                    preparation: None,
                    selected: None,
                    witness: None,
                    failed_capture: None,
                    cleanup: Cleanup::Pending,
                    #[cfg(test)]
                    fault: None,
                }),
                waiter: Mutex::new(None),
                waking: AtomicBool::new(false),
                wake_panic: OnceLock::new(),
                sealed: AtomicBool::new(false),
                drained: AtomicBool::new(false),
            },
            credit,
        );
        let binding = CompletionBinding::new(owner.clone());
        Ok((owner, binding))
    }
    pub(crate) fn identity(&self) -> &CompletionIdentity {
        &self.identity
    }
    fn register(&self, cx: &Context<'_>) {
        if self.wake_panic.get().is_some() {
            return;
        }
        let next = cx.waker().clone();
        let previous = {
            let mut waiter = self.waiter.lock().unwrap_or_else(|p| p.into_inner());
            if self.wake_panic.get().is_some() {
                return;
            }
            waiter.replace(next)
        };
        drop(previous);
    }
    fn wake(&self) {
        if self
            .waking
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        loop {
            if self.wake_panic.get().is_some() {
                break;
            }
            let wake = {
                let mut queued = self.waiter.lock().unwrap_or_else(|p| p.into_inner());
                match queued.take() {
                    Some(wake) => wake,
                    None => {
                        // Registration takes this same lock, closing the gap
                        // between an empty observation and releasing wake duty.
                        self.waking.store(false, Ordering::Release);
                        return;
                    }
                }
            };
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| wake.wake()))
            {
                // Guard::drop may already be unwinding an action. Keep this
                // independent original in its preadmitted inline slot; never
                // replace the first action panic or enter another wake callback.
                assert!(self.wake_panic.set(Mutex::new(payload)).is_ok());
                self.sealed.store(true, Ordering::Release);
                self.drained.store(false, Ordering::Release);
                break;
            }
        }
        self.waking.store(false, Ordering::Release);
    }
    fn wake_result(&self) -> std::result::Result<(), CompletionSettleError> {
        if self.wake_panic.get().is_some() {
            Err(CompletionSettleError::Retained)
        } else {
            Ok(())
        }
    }
    fn try_state(&self) -> std::result::Result<Guard<'_>, CompletionSettleError> {
        self.wake_result()?;
        match self.state.try_lock() {
            Ok(state) => Ok(Guard {
                owner: self,
                state: Some(state),
            }),
            Err(TryLockError::WouldBlock) => Err(CompletionSettleError::Busy),
            // The actual outer adapter catcher retains the original panic.
            // Poison never authorizes replaying a destructive callback.
            Err(TryLockError::Poisoned(_)) => Err(CompletionSettleError::Retained),
        }
    }
    pub(crate) fn enter<'a>(
        &'a self,
        invocation: &'a CompletionInvocation<'a>,
    ) -> Result<CompletionLoan<'a>> {
        invocation.require_identity(&self.identity)?;
        ensure!(
            !self.sealed.load(Ordering::Acquire),
            "application completion sealed"
        );
        let mut state = self
            .try_state()
            .map_err(|e| anyhow::anyhow!("application completion unavailable: {e:?}"))?;
        ensure!(
            matches!(state.phase, Phase::Idle | Phase::Settled)
                && state.preparation.is_none()
                && state.selected.is_none()
                && state.witness.is_none()
                && state.failed_capture.is_none(),
            "application completion is not empty"
        );
        ensure!(
            invocation.ordinal() > state.ordinal,
            "application completion invocation repeated"
        );
        let roots = self
            .roots
            .upgrade()
            .context("application completion roots retired")?;
        state.ordinal = invocation.ordinal();
        state.phase = Phase::Entered;
        state.attempted = false;
        state.repeated = false;
        state.cleanup = Cleanup::Pending;
        Ok(CompletionLoan {
            state,
            roots,
            invocation,
        })
    }
    fn clean(&self, state: &mut Guard<'_>) -> std::result::Result<(), CompletionSettleError> {
        if state.cleanup == Cleanup::Running {
            return Err(CompletionSettleError::Retained);
        }
        if state.cleanup == Cleanup::Pending {
            // Keep exact allocation, native/error identity and credit outside
            // both destructive values before either can unwind. A later drain
            // can inspect this witness again, but cannot replay either Drop.
            state.witness = state
                .preparation
                .as_ref()
                .map(|p| p.cell.clone())
                .or_else(|| state.selected.as_ref().map(|s| s.cell.clone()));
            state.cleanup = Cleanup::Running;
            drop(state.selected.take());
            drop(state.preparation.take());
            state.cleanup = Cleanup::Returned;
        }
        let source_settled = state.witness.as_ref().is_none_or(|cell| {
            let source = cell.state.lock().unwrap_or_else(|p| p.into_inner());
            let legitimate_alias = !cell.capture_failed()
                && cell.alias_failure.get().is_none()
                && cell.close_failure.get().is_none()
                && (cell.handles.load(Ordering::Acquire) != 0 || source.inflight != 0);
            let retired = source.closed
                && source.inflight == 0
                && source.view.is_none()
                && source.protected_view.is_none()
                && !cell.native_retained.load(Ordering::Acquire);
            !source.preparing && !source.closing && (legitimate_alias || retired)
        });
        if !source_settled {
            state.phase = Phase::Retained;
            return Err(CompletionSettleError::Retained);
        }
        // A remaining actual selected/reader alias is a handoff, otherwise the
        // exact source must be positively closed with no view or native work.
        // Capture failure is still an error: its returned SourceFailure retains
        // the original FailureRef and its credit independently of this Cell.
        // Returning from Drop alone never authorizes clearing the witness.
        if let Some(failed) = state.failed_capture.as_ref() {
            let exact_retired_capture = state.witness.as_ref().is_some_and(|cell| {
                cell.failure.get().is_some_and(|record| {
                    std::ptr::eq(record.owner.as_ref(), failed.original.as_ref())
                }) && cell.state.lock().unwrap_or_else(|p| p.into_inner()).closed
                    && !cell.native_retained.load(Ordering::Acquire)
            });
            if !exact_retired_capture {
                state.phase = Phase::Retained;
                return Err(CompletionSettleError::Retained);
            }
            state
                .failed_capture
                .as_mut()
                .expect("exact failed capture")
                .retired = true;
        }
        state.witness = None;
        state.phase = Phase::Settled;
        Ok(())
    }
}
impl CompletionCustody for CompletionRef {
    fn identity(&self) -> &CompletionIdentity {
        &self.identity
    }
    fn settle(
        &self,
        finalization: CompletionFinalization<'_>,
    ) -> std::result::Result<(), CompletionSettleError> {
        finalization
            .require_identity(&self.identity)
            .map_err(|_| CompletionSettleError::Foreign)?;
        let mut state = self.try_state()?;
        if state.ordinal != finalization.ordinal()
            || matches!(state.phase, Phase::Idle | Phase::Settled)
        {
            return Err(CompletionSettleError::Protocol);
        }
        if finalization.verdict() == CompletionVerdict::Failed {
            state.phase = Phase::Retained;
            return Err(CompletionSettleError::Retained);
        }
        let result = self.clean(&mut state);
        drop(state);
        self.wake_result()?;
        result
    }
    fn poll_drain(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), CompletionSettleError>> {
        self.sealed.store(true, Ordering::Release);
        if let Err(error) = self.wake_result() {
            return Poll::Ready(Err(error));
        }
        if self.drained.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }
        self.register(cx);
        let mut state = match self.try_state() {
            Ok(state) => state,
            Err(CompletionSettleError::Busy) => return Poll::Pending,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let result = self.clean(&mut state);
        drop(state);
        if self.wake_result().is_err() {
            return Poll::Ready(Err(CompletionSettleError::Retained));
        }
        if result.is_ok() {
            self.drained.store(true, Ordering::Release);
        }
        Poll::Ready(result)
    }
    fn is_drained(&self) -> bool {
        self.drained.load(Ordering::Acquire) && self.wake_panic.get().is_none()
    }
    fn retired_action_failure(&self) -> Option<CompletionActionFailureIdentity> {
        if !self.sealed.load(Ordering::Acquire) || !self.is_drained() {
            return None;
        }
        let state = self.try_state().ok()?;
        state
            .failed_capture
            .as_ref()
            .filter(|f| f.retired)
            .map(|f| f.identity)
    }
}

pub(crate) struct CompletionLoan<'a> {
    state: Guard<'a>,
    roots: SourceRootsRef,
    invocation: &'a CompletionInvocation<'a>,
}
struct Preparer<'a> {
    roots: &'a SourceRootsRef,
    state: &'a mut State,
}
impl SelectionPreparer for Preparer<'_> {
    fn prepare(
        &mut self,
        plan: &PreparedSelectionPlan,
        points: PreparedTenantPointWorkspace,
    ) -> Result<()> {
        with_incoming_points(points, |points| {
            if self.state.attempted {
                self.state.repeated = true;
                anyhow::bail!("application completion preparation repeated");
            }
            self.state.attempted = true;
            plan.require_stores(&self.roots.stores)?;
            self.state.preparation =
                Some(self.roots.prepare_kind_unqueued(true, Some(plan), points)?);
            #[cfg(test)]
            self.state.checkpoint(CompletionCheckpoint::BeforeQueue)?;
            self.state
                .preparation
                .as_mut()
                .expect("stored source preparation")
                .queue_planned_in_place()?;
            #[cfg(test)]
            self.state.checkpoint(CompletionCheckpoint::Queued)?;
            Ok(())
        })
    }
}
impl CompletionLoan<'_> {
    pub(crate) fn publish_source(
        &mut self,
        position: &kasumi_raft::AppliedEntryContext,
        response: kasumi_raft::AppliedResponse,
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
        frozen: bool,
    ) -> Result<Option<SelectedApplication>> {
        let roots = self.roots.clone();
        let expectation = roots.publication_expectation(position, &[], &response)?;
        let receipt = match publisher.commit_with_selection(
            response,
            &[],
            &mut Preparer {
                roots: &roots,
                state: &mut self.state,
            },
            expectation.challenge()?,
        ) {
            Ok(receipt) => receipt,
            // The real publisher owns the original. Stop this action without
            // allocating an anyhow box for its notification after effects.
            Err(_) => return Ok(None),
        };
        ensure!(
            !self.state.repeated,
            "application completion preparation repeated"
        );
        let plan = self
            .state
            .preparation
            .as_ref()
            .and_then(|p| p.plan.as_ref())
            .context("actual completion publication plan absent")?;
        expectation.consume(receipt, plan)?;
        #[cfg(test)]
        self.state.checkpoint(CompletionCheckpoint::Published)?;
        let captured = self
            .state
            .preparation
            .as_mut()
            .expect("verified preparation")
            .capture_in_place(ApplicationBoundaryRef::Entry(position), frozen);
        let selected = match captured {
            Ok(selected) => selected,
            Err(original) => {
                // Only our canonical capture's exact recorded SourceFailure can
                // carry this identity. Checkpoint errors and panics do not.
                if let Some(failure) = original.downcast_ref::<SourceFailure>() {
                    let exact = self.state.preparation.as_ref().is_some_and(|p| {
                        p.cell.failure.get().is_some_and(|record| {
                            std::ptr::eq(record.owner.as_ref(), failure.owner.as_ref())
                        })
                    });
                    if exact {
                        self.state.failed_capture = Some(CapturedFailure {
                            identity: self.invocation.action_failure_identity(&original),
                            original: failure.owner.clone(),
                            retired: false,
                        });
                    }
                }
                return Err(original);
            }
        };
        self.state.selected = Some(selected);
        self.state.phase = Phase::Captured;
        #[cfg(test)]
        self.state.checkpoint(CompletionCheckpoint::Captured)?;
        Ok(Some(
            self.state
                .selected
                .as_ref()
                .expect("stored selected source")
                .clone(),
        ))
    }
    #[cfg(test)]
    pub(crate) fn checkpoint(&mut self, point: CompletionCheckpoint) -> Result<()> {
        self.state.checkpoint(point)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompletionCheckpoint {
    BeforeQueue,
    Queued,
    Published,
    Captured,
    Installed,
    Visible,
}
#[cfg(test)]
pub(crate) enum CompletionFault {
    Error(anyhow::Error),
    Panic(Box<dyn std::any::Any + Send>),
    Pause(Arc<super::tests::completion_tests::CompletionPause>),
}
#[cfg(test)]
impl State {
    fn checkpoint(&mut self, point: CompletionCheckpoint) -> Result<()> {
        if self.fault.as_ref().is_some_and(|(at, _)| *at == point) {
            match self.fault.take().expect("armed completion fault").1 {
                CompletionFault::Error(error) => return Err(error),
                CompletionFault::Panic(payload) => std::panic::resume_unwind(payload),
                CompletionFault::Pause(gate) => return gate.wait(self.snapshot()),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CompletionSnapshot {
    pub(crate) ordinal: u64,
    pub(crate) phase: Phase,
    pub(crate) preparation_cell: Option<u64>,
    pub(crate) queued_reader: Option<kasumi_store::StorageOwnerId>,
    pub(crate) selected_cell: Option<u64>,
    pub(crate) retirement_witness: Option<u64>,
}
#[cfg(test)]
impl SourceRootsRef {
    pub(crate) fn completion_snapshot_for_test(&self) -> CompletionSnapshot {
        let owner = self.completion().expect("completion installed");
        let state = owner.state.lock().unwrap_or_else(|p| p.into_inner());
        state.snapshot()
    }
    pub(crate) fn arm_completion_fault_for_test(
        &self,
        point: CompletionCheckpoint,
        fault: CompletionFault,
    ) {
        let owner = self.completion().expect("completion installed");
        let mut state = owner.state.lock().unwrap_or_else(|p| p.into_inner());
        assert!(matches!(state.phase, Phase::Idle | Phase::Settled) && state.fault.is_none());
        state.fault = Some((point, fault));
    }
    pub(crate) fn with_completion_state_held_for_test<R>(&self, work: impl FnOnce() -> R) -> R {
        let owner = self.completion().expect("completion installed");
        let _guard = Guard {
            owner,
            state: Some(owner.state.lock().unwrap_or_else(|p| p.into_inner())),
        };
        work()
    }
}
#[cfg(test)]
impl CompletionRef {
    pub(crate) fn allocation_address_for_test(&self) -> usize {
        std::ptr::from_ref(self.as_ref()) as usize
    }
    pub(crate) fn credit_address_for_test(&self) -> usize {
        self.credit_address()
    }
}

#[cfg(test)]
impl State {
    fn snapshot(&self) -> CompletionSnapshot {
        CompletionSnapshot {
            ordinal: self.ordinal,
            phase: self.phase,
            preparation_cell: self.preparation.as_ref().map(|p| p.cell.id),
            queued_reader: self
                .preparation
                .as_ref()
                .and_then(|p| p.queued.as_ref())
                .and_then(PreparedTenantStorageReadView::registered_reader_id),
            selected_cell: self.selected.as_ref().map(|s| s.cell.id),
            retirement_witness: self.witness.as_ref().map(|c| c.id),
        }
    }
}

#[cfg(test)]
impl SourceRootsRef {
    pub(crate) fn with_completion_wake_panic_for_test<T>(
        &self,
        inspect: impl FnOnce(Option<&(dyn std::any::Any + Send)>) -> T,
    ) -> T {
        let owner = self.completion().expect("installed completion");
        let panic = owner
            .wake_panic
            .get()
            .map(|p| p.lock().unwrap_or_else(|p| p.into_inner()));
        inspect(panic.as_ref().map(|p| p.as_ref()))
    }
}
