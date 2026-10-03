//! Fixed, preadmitted per-entry observations. The failure latch is independent
//! of inspection locks used under lifecycle/state-machine serialization.
use crate::AppliedResponse;
use crate::apply_completion::*;
use std::{
    any::Any,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    task::{Context, Poll, Waker},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionViolation {
    Missing,
    Repeated,
    Interrupted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportBusy;

pub enum ApplyObservationRef<'a> {
    NotEntered,
    Running,
    Returned,
    Error(&'a anyhow::Error),
    Unwound(&'a (dyn Any + Send)),
    Refused(CompletionSettleError),
}
pub struct OrdinaryApplyReport<'a> {
    pub ordinal: u64,
    pub single: Option<&'a anyhow::Error>,
    pub violation: Option<CompletionViolation>,
    pub response: Option<&'a AppliedResponse>,
    pub sink: ApplyObservationRef<'a>,
    pub action: ApplyObservationRef<'a>,
    pub backend: ApplyObservationRef<'a>,
    pub finish: ApplyObservationRef<'a>,
    pub cleanup: ApplyObservationRef<'a>,
    pub drain: ApplyObservationRef<'a>,
    pub wake_panic: Option<&'a (dyn Any + Send)>,
}
pub enum RetainedApplyReport<'a> {
    Single(&'a anyhow::Error),
    Ordinary(OrdinaryApplyReport<'a>),
}

pub(crate) enum Observation {
    NotEntered,
    Running,
    Returned,
    Error(anyhow::Error),
    Unwound(Box<dyn Any + Send>),
    Refused(CompletionSettleError),
}
impl Observation {
    fn borrowed(&self) -> ApplyObservationRef<'_> {
        match self {
            Self::NotEntered => ApplyObservationRef::NotEntered,
            Self::Running => ApplyObservationRef::Running,
            Self::Returned => ApplyObservationRef::Returned,
            Self::Error(e) => ApplyObservationRef::Error(e),
            Self::Unwound(p) => ApplyObservationRef::Unwound(p.as_ref()),
            Self::Refused(e) => ApplyObservationRef::Refused(*e),
        }
    }
    fn returned(&self) -> bool {
        matches!(self, Self::Returned)
    }
    fn from_caught(result: std::thread::Result<anyhow::Result<()>>) -> Self {
        match result {
            Ok(Ok(())) => Self::Returned,
            Ok(Err(e)) => Self::Error(e),
            Err(p) => Self::Unwound(p),
        }
    }
}
const IDLE: u8 = 0;
const ENTERED: u8 = 1;
const FINISHING: u8 = 2;
const SETTLED: u8 = 3;
const FAILED: u8 = 4;
struct EntryState {
    ordinal: u64,
    violation: Option<CompletionViolation>,
    response: Option<AppliedResponse>,
    sink: Observation,
    sink_no_native_children: bool,
    action: Observation,
    backend: Observation,
    finish: Observation,
    cleanup: Observation,
    drain: Observation,
}
impl EntryState {
    fn empty(ordinal: u64) -> Self {
        Self {
            ordinal,
            violation: None,
            response: None,
            sink: Observation::NotEntered,
            sink_no_native_children: false,
            action: Observation::NotEntered,
            backend: Observation::NotEntered,
            finish: Observation::NotEntered,
            cleanup: Observation::NotEntered,
            drain: Observation::NotEntered,
        }
    }
    fn borrowed<'a>(&'a self, single: Option<&'a anyhow::Error>) -> RetainedApplyReport<'a> {
        RetainedApplyReport::Ordinary(OrdinaryApplyReport {
            ordinal: self.ordinal,
            single,
            violation: self.violation,
            response: self.response.as_ref(),
            sink: self.sink.borrowed(),
            action: self.action.borrowed(),
            backend: self.backend.borrowed(),
            finish: self.finish.borrowed(),
            cleanup: self.cleanup.borrowed(),
            drain: self.drain.borrowed(),
            wake_panic: None,
        })
    }
}

pub(crate) struct CompletionState {
    binding: OnceLock<CompletionBinding>,
    state: Mutex<EntryState>,
    waiter: Mutex<Option<Waker>>,
    waking: AtomicBool,
    pending_drain: Mutex<Option<Observation>>,
    wake_panic: OnceLock<Mutex<Box<dyn Any + Send>>>,
    phase: AtomicU8,
    failed: AtomicBool,
    repeated: AtomicBool,
    drained: AtomicBool,
    sealed: AtomicBool,
}
impl CompletionState {
    pub(crate) fn new() -> Self {
        Self {
            binding: OnceLock::new(),
            state: Mutex::new(EntryState::empty(0)),
            waiter: Mutex::new(None),
            waking: AtomicBool::new(false),
            pending_drain: Mutex::new(None),
            wake_panic: OnceLock::new(),
            phase: AtomicU8::new(IDLE),
            failed: AtomicBool::new(false),
            repeated: AtomicBool::new(false),
            drained: AtomicBool::new(true),
            sealed: AtomicBool::new(false),
        }
    }
    pub(crate) fn bound(&self) -> bool {
        self.binding.get().is_some()
    }
    pub(crate) fn bind(&self, binding: CompletionBinding) -> Result<(), CompletionBinding> {
        self.drained.store(false, Ordering::Release);
        self.binding.set(binding)
    }
    pub(crate) fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
    pub(crate) fn unsettled(&self) -> bool {
        matches!(
            self.phase.load(Ordering::Acquire),
            ENTERED | FINISHING | FAILED
        )
    }
    /// The failure remains latched and its original remains inspectable. Only
    /// the exact Store disposition plus positive actual cleanup can retire its
    /// native custody; arbitrary errors and every other failed producer cannot.
    pub(crate) fn failure_ownership_drained(&self) -> bool {
        if !self.failed()
            || !self.sealed.load(Ordering::Acquire)
            || !self.drained()
            || self.repeated.load(Ordering::Acquire)
            || self.waking.load(Ordering::Acquire)
            || self.wake_panic.get().is_some()
        {
            return false;
        }
        let state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::Poisoned(_))
            | Err(std::sync::TryLockError::WouldBlock) => return false,
        };
        state.sink_no_native_children
            && state.response.is_some()
            && state.violation.is_none()
            && matches!(state.sink, Observation::Error(_))
            && state.action.returned()
            && state.backend.returned()
            && state.finish.returned()
            && matches!(
                state.cleanup,
                Observation::Returned | Observation::Refused(CompletionSettleError::Retained)
            )
            && state.drain.returned()
    }
    pub(crate) fn drained(&self) -> bool {
        self.drained.load(Ordering::Acquire)
    }
    fn fail(&self) {
        self.failed.store(true, Ordering::Release);
        self.phase.store(FAILED, Ordering::Release);
    }
    pub(crate) fn identity(&self) -> Option<&CompletionIdentity> {
        self.binding.get().map(CompletionCustody::identity)
    }
    pub(crate) fn begin(&self, expected: &CompletionIdentity) -> Result<u64, CompletionCallError> {
        let actual = self.identity().ok_or(CompletionCallError::Unsupported)?;
        if !std::ptr::eq(actual, expected) {
            return Err(CompletionCallError::Foreign);
        }
        if self.failed() || self.sealed.load(Ordering::Acquire) {
            return Err(CompletionCallError::Closed);
        }
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if self.failed() || self.sealed.load(Ordering::Acquire) {
            return Err(CompletionCallError::Closed);
        }
        if !matches!(self.phase.load(Ordering::Acquire), IDLE | SETTLED) {
            state.violation = Some(CompletionViolation::Repeated);
            self.fail();
            return Err(CompletionCallError::Recorded);
        }
        let ordinal = state
            .ordinal
            .checked_add(1)
            .ok_or(CompletionCallError::IdentifierExhausted)?;
        // A successful entry is empty before reset; no old original may retire here.
        assert!(state.response.is_none());
        *state = EntryState::empty(ordinal);
        state.action = Observation::Running;
        self.phase.store(ENTERED, Ordering::Release);
        Ok(ordinal)
    }
    pub(crate) fn repeated(&self) {
        self.repeated.store(true, Ordering::Release);
        self.fail();
    }
    pub(crate) fn adopt_plain(
        &self,
        response: Option<AppliedResponse>,
        error: Option<anyhow::Error>,
        running: bool,
    ) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.response = response;
        state.sink = if let Some(error) = error {
            Observation::Error(error)
        } else if running {
            Observation::Running
        } else {
            Observation::Returned
        };
        state.action = Observation::NotEntered;
        self.repeated();
    }
    pub(crate) fn sink<T>(
        &self,
        ordinal: u64,
        response: AppliedResponse,
        run: impl FnOnce(&AppliedResponse) -> crate::apply_publication::SinkResult<T>,
    ) -> Result<T, crate::PublishCallError> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.ordinal != ordinal || !matches!(state.sink, Observation::NotEntered) {
                state.violation = Some(CompletionViolation::Repeated);
                self.fail();
                return Err(None);
            }
            state.response = Some(response);
            state.sink = Observation::Running;
            match run(state.response.as_ref().expect("stored response")) {
                Ok(value) => Ok(value),
                Err(error) => Err(Some(error)),
            }
        }));
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match result {
            Ok(Ok(value)) => {
                state.sink = Observation::Returned;
                Ok(value)
            }
            Ok(Err(Some(failure))) => {
                let (error, no_native_children) = failure.into_parts();
                state.sink = Observation::Error(error);
                state.sink_no_native_children = no_native_children;
                self.fail();
                Err(crate::PublishCallError::Failed)
            }
            Ok(Err(None)) => Err(crate::PublishCallError::Repeated),
            Err(payload) => {
                state.sink = Observation::Unwound(payload);
                self.fail();
                Err(crate::PublishCallError::Failed)
            }
        }
    }
    pub(crate) fn action(
        &self,
        result: std::thread::Result<anyhow::Result<()>>,
    ) -> Result<(), CompletionCallError> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        assert!(matches!(state.action, Observation::Running));
        state.action = Observation::from_caught(result);
        if !state.action.returned() {
            self.fail();
        }
        if self.failed() {
            Err(CompletionCallError::Recorded)
        } else {
            Ok(())
        }
    }
    pub(crate) fn record_backend(&self, backend: std::thread::Result<anyhow::Result<()>>) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        assert!(matches!(state.backend, Observation::NotEntered));
        state.backend = Observation::from_caught(backend);
        state.finish = Observation::Running;
        if !state.backend.returned() {
            self.fail();
        }
    }
    /// Actual outer finish; original backend has already moved into this owner.
    pub(crate) fn finish(&self, ordinal: u64) -> bool {
        let success = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            assert_eq!(state.ordinal, ordinal);
            if matches!(state.sink, Observation::NotEntered) {
                state.violation = Some(CompletionViolation::Missing);
            }
            if self.repeated.load(Ordering::Acquire) {
                state.violation = Some(CompletionViolation::Repeated)
            }
            let success = !self.failed()
                && state.violation.is_none()
                && state.sink.returned()
                && state.action.returned()
                && state.backend.returned();
            if !success {
                self.fail();
            } else {
                self.phase.store(FINISHING, Ordering::Release);
            }
            state.cleanup = Observation::Running;
            success
        };
        let binding = self.binding.get().expect("entered binding");
        // No mutable report guard across external completion cleanup.
        let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            binding.settle(CompletionFinalization::new(
                binding.identity(),
                ordinal,
                if success {
                    CompletionVerdict::Success
                } else {
                    CompletionVerdict::Failed
                },
            ))
        }));
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.cleanup = match cleanup {
            Ok(Ok(())) => Observation::Returned,
            Ok(Err(e)) => Observation::Refused(e),
            Err(p) => Observation::Unwound(p),
        };
        state.finish = Observation::Returned;
        if !success || !state.cleanup.returned() {
            self.fail();
            false
        } else {
            true
        }
    }
    pub(crate) fn finish_panic(&self, payload: Box<dyn Any + Send>) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.finish = Observation::Unwound(payload);
        self.fail();
    }
    pub(crate) fn take_response(&self, ordinal: u64) -> AppliedResponse {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(state.ordinal, ordinal);
        assert!(!self.failed());
        assert!(state.cleanup.returned());
        state.response.take().expect("successful stored response")
    }
    pub(crate) fn acknowledge(&self, ordinal: u64) {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(state.ordinal, ordinal);
        assert!(state.response.is_none() && !self.failed());
        self.phase.store(SETTLED, Ordering::Release);
    }
    pub(crate) fn try_with_report<R>(
        &self,
        single: Option<&anyhow::Error>,
        inspect: impl for<'a> FnOnce(RetainedApplyReport<'a>) -> R,
    ) -> Result<R, ReportBusy> {
        let state = match self.state.try_lock() {
            Ok(s) => s,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Err(ReportBusy),
        };
        let state = ReportGuard {
            state: Some(state),
            owner: self,
        };
        let pending = self.pending_drain.lock().unwrap_or_else(|p| p.into_inner());
        // Empty staging must remain available to a cleanup callback already
        // running outside the report lock. With Some, no further callback may
        // start until the report lock lends this exact staged terminal outcome.
        let pending = if pending.is_some() {
            Some(pending)
        } else {
            drop(pending);
            None
        };
        let wake = self
            .wake_panic
            .get()
            .map(|p| p.lock().unwrap_or_else(|p| p.into_inner()));
        let mut report = state.borrowed(single);
        if let RetainedApplyReport::Ordinary(view) = &mut report {
            if let Some(pending) = pending.as_ref().and_then(|guard| guard.as_ref()) {
                view.drain = pending.borrowed()
            }
            view.wake_panic = wake.as_ref().map(|p| p.as_ref());
        }
        if let RetainedApplyReport::Ordinary(view) = &mut report
            && self.repeated.load(Ordering::Acquire)
        {
            view.violation = Some(CompletionViolation::Repeated)
        }
        Ok(inspect(report))
    }
    fn register(&self, cx: &Context<'_>) {
        if self.wake_panic.get().is_some() {
            return;
        }
        let next = cx.waker().clone();
        let prior = {
            let mut waiter = self.waiter.lock().unwrap_or_else(|p| p.into_inner());
            if self.wake_panic.get().is_some() {
                return;
            }
            waiter.replace(next)
        };
        drop(prior);
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
            let waiter = {
                let mut queued = self.waiter.lock().unwrap_or_else(|p| p.into_inner());
                match queued.take() {
                    Some(waiter) => waiter,
                    None => {
                        self.waking.store(false, Ordering::Release);
                        return;
                    }
                }
            };
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waiter.wake()))
            {
                // Exactly one wake is entered at a time. On its first panic,
                // retain the exact payload and any subsequently queued waiter;
                // no more wake/registration callbacks are permitted.
                assert!(self.wake_panic.set(Mutex::new(payload)).is_ok());
                self.fail();
                break;
            }
        }
        self.waking.store(false, Ordering::Release);
    }
    /// Only after actual workers have stopped. Register then recheck prevents
    /// an inspector releasing its borrow from losing the pending drain wake.
    pub(crate) fn poll_drain(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.sealed.store(true, Ordering::Release);
        let Some(binding) = self.binding.get() else {
            return Poll::Ready(());
        };
        if self.drained() || self.wake_panic.get().is_some() {
            return Poll::Ready(());
        }
        self.register(cx);
        let state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Poll::Pending,
        };
        let mut state = state;
        let registered = self.waiter.lock().unwrap_or_else(|p| p.into_inner()).take();
        let pending = {
            self.pending_drain
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take()
        };
        if let Some(outcome) = pending {
            let positive = outcome.returned();
            state.drain = outcome;
            if positive {
                self.drained.store(true, Ordering::Release)
            } else {
                self.fail()
            }
            drop(state);
            drop(registered);
            return Poll::Ready(());
        }
        if matches!(
            state.drain,
            Observation::Unwound(_) | Observation::Refused(_)
        ) {
            drop(state);
            drop(registered);
            return Poll::Ready(());
        }
        if self.unsettled() && !self.failed() {
            state.violation = Some(CompletionViolation::Interrupted);
            self.fail()
        }
        state.drain = Observation::Running;
        // No report/metadata guard across external Engine cleanup.
        drop(state);
        drop(registered);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match binding.poll_drain(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(())) if binding.is_drained() => Poll::Ready(Ok(())),
                Poll::Ready(Ok(())) => Poll::Ready(Err(CompletionSettleError::Retained)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            }
        }));
        let outcome = match result {
            Ok(Poll::Pending) => return Poll::Pending,
            Ok(Poll::Ready(Ok(()))) => Observation::Returned,
            Ok(Poll::Ready(Err(error))) => Observation::Refused(error),
            Err(payload) => Observation::Unwound(payload),
        };
        if !outcome.returned() {
            self.fail()
        }
        *self.pending_drain.lock().unwrap_or_else(|p| p.into_inner()) = Some(outcome);
        // The exact outcome remains independently owned if inspection won the
        // report lock or the surrounding drain future is now cancelled.
        self.poll_drain(cx)
    }
}
struct ReportGuard<'a> {
    state: Option<std::sync::MutexGuard<'a, EntryState>>,
    owner: &'a CompletionState,
}
impl std::ops::Deref for ReportGuard<'_> {
    type Target = EntryState;
    fn deref(&self) -> &EntryState {
        self.state.as_ref().expect("report guard")
    }
}
impl std::ops::DerefMut for ReportGuard<'_> {
    fn deref_mut(&mut self) -> &mut EntryState {
        self.state.as_mut().expect("report guard")
    }
}
impl Drop for ReportGuard<'_> {
    fn drop(&mut self) {
        drop(self.state.take());
        self.owner.wake()
    }
}
