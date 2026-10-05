//! Closed failure cells paid by the original target-call inventory.
use kasumi_engine::{SnapshotFailure, admission::Reservation};
use kasumi_store::{ScratchAdmissionRefusal, ScratchAdmissionSlot};
use kasumi_types::{Error, ErrorCode, SharedBudgetCharge};
use std::{
    alloc::Layout,
    future::Future,
    io,
    marker::PhantomData,
    mem::ManuallyDrop,
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

struct State {
    outcome: Arc<tokio::sync::Mutex<Outcome>>,
    // A dispatch refusal can arrive while the completed producer report is
    // borrowed. This original has one writer and never permits cell reuse.
    dispatch: OnceLock<anyhow::Error>,
    phase: AtomicU8,
    users: AtomicUsize,
    accepted: AtomicBool,
    // Published only after the original panic is installed in this paid cell.
    // Admission must not depend on borrowing a concurrently inspected report.
    observed_panic: AtomicBool,
    retired_source: AtomicBool,
    preserve: AtomicBool,
    retained: AtomicBool,
    admission: ScratchAdmissionSlot,
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Entry {
    #[default]
    NotEntered,
    Entered,
    Returned,
    Panicked,
}
#[derive(Default)]
struct Observation {
    entry: Entry,
    panic: Option<Box<dyn std::any::Any + Send>>,
}
#[derive(Default)]
struct Outcome {
    original: Option<Original>,
    output: Option<Output>,
    body: Observation,
    future_disposal: Observation,
    output_disposal: Observation,
}
impl Outcome {
    fn empty(&self) -> bool {
        self.original.is_none()
            && self.output.is_none()
            && self.body.entry == Entry::NotEntered
            && self.future_disposal.entry == Entry::NotEntered
            && self.output_disposal.entry == Entry::NotEntered
    }
    fn returned(&self) -> bool {
        self.body.entry == Entry::Returned && self.future_disposal.entry == Entry::Returned
    }
    fn clearable(&self) -> bool {
        self.returned()
            && self.output.is_none()
            && self.original.as_ref().is_none_or(Original::native_free)
            && matches!(
                self.output_disposal.entry,
                Entry::NotEntered | Entry::Returned
            )
    }
}
/// The closed lane contains only these actual supported producers. Its fixed
/// inline layout is paid by the original inventory; arbitrary producer and
/// output backing allocations remain their producer's responsibility.
#[allow(
    clippy::large_enum_variant,
    reason = "the closed output lane is quoted in the same initial inventory and preserves whole response owners without allocating a later Box"
)]
pub(super) enum Output {
    Unit,
    Prepared(
        (
            kasumi_engine::TargetRequestAdmission,
            tokio::time::Instant,
            tokio::sync::OwnedSemaphorePermit,
        ),
    ),
    Runtime(super::TargetRuntimeReply),
    Membership(super::initial_membership_status::TargetInitialMembershipReply),
    #[cfg(test)]
    U64(u64),
    #[cfg(test)]
    U32(u32),
    #[cfg(test)]
    TestReply(super::target_call_jobs::TestReply),
}
mod sealed {
    pub trait Output {}
    pub trait Failure {}
}
pub(super) trait TargetOutput: sealed::Output {
    fn retain(self) -> Output;
    fn recover(original: Output) -> Self;
}
macro_rules! output {
    ($ty:ty, $variant:ident) => {
        impl sealed::Output for $ty {}
        impl TargetOutput for $ty {
            fn retain(self) -> Output {
                Output::$variant(self)
            }
            fn recover(original: Output) -> Self {
                match original {
                    Output::$variant(original) => original,
                    _ => unreachable!("same closed Target output producer"),
                }
            }
        }
    };
}
impl sealed::Output for () {}
impl TargetOutput for () {
    fn retain(self) -> Output {
        Output::Unit
    }
    fn recover(original: Output) -> Self {
        match original {
            Output::Unit => (),
            _ => unreachable!("same closed Target output producer"),
        }
    }
}
output!(
    (
        kasumi_engine::TargetRequestAdmission,
        tokio::time::Instant,
        tokio::sync::OwnedSemaphorePermit
    ),
    Prepared
);
output!(super::TargetRuntimeReply, Runtime);
output!(
    super::initial_membership_status::TargetInitialMembershipReply,
    Membership
);
#[cfg(test)]
output!(u64, U64);
#[cfg(test)]
output!(u32, U32);
#[cfg(test)]
output!(super::target_call_jobs::TestReply, TestReply);

pub(super) trait TargetProducerFailure: sealed::Failure {
    fn retain(self) -> TargetTaskFailure;
}
macro_rules! producer_failure {
    ($ty:ty) => {
        impl sealed::Failure for $ty {}
        impl TargetProducerFailure for $ty {
            fn retain(self) -> TargetTaskFailure {
                self.into()
            }
        }
    };
}
producer_failure!(SnapshotFailure);
producer_failure!(TargetTaskFailure);
#[cfg(test)]
producer_failure!(anyhow::Error);
#[allow(
    clippy::large_enum_variant,
    reason = "whole native and cleanup originals remain inline in the preadmitted failure cell; error-path boxing would add unadmitted backing"
)]
enum Original {
    Snapshot(SnapshotFailure),
    RetiredSource(crate::runtime::RetiredSourceFailure),
    NodeStartup(kasumi_store::NodeStoreStartFailure),
}
impl Original {
    fn snapshot(&self) -> Option<&SnapshotFailure> {
        match self {
            Self::Snapshot(original) => Some(original),
            Self::RetiredSource(original) => Some(original.original()),
            Self::NodeStartup(_) => None,
        }
    }
    fn native_free(&self) -> bool {
        matches!(
            self,
            Self::Snapshot(SnapshotFailure::Operation(_) | SnapshotFailure::AdmissionRefused(_))
        )
    }
}
/// The two actual owning failures reach the same prepaid cell whole.
/// Captured failures leave `run` as their closed diagnostic facade.
#[allow(
    clippy::large_enum_variant,
    reason = "the typed producer moves whole originals into the already paid closed lane without a fresh diagnostic allocation"
)]
pub(crate) enum TargetTaskFailure {
    Snapshot(SnapshotFailure),
    RetiredSource(crate::runtime::RetiredSourceFailure),
    NodeStartup(kasumi_store::NodeStoreStartFailure),
}
impl std::fmt::Display for TargetTaskFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Snapshot(original) => original.fmt(f),
            Self::RetiredSource(original) => original.original().fmt(f),
            Self::NodeStartup(original) => original.fmt(f),
        }
    }
}
impl From<kasumi_store::NodeStoreStartFailure> for TargetTaskFailure {
    fn from(original: kasumi_store::NodeStoreStartFailure) -> Self {
        Self::NodeStartup(original)
    }
}
impl From<SnapshotFailure> for TargetTaskFailure {
    fn from(original: SnapshotFailure) -> Self {
        Self::Snapshot(original)
    }
}
impl From<crate::runtime::RetiredSourceFailure> for TargetTaskFailure {
    fn from(original: crate::runtime::RetiredSourceFailure) -> Self {
        Self::RetiredSource(original)
    }
}
impl From<Error> for TargetTaskFailure {
    fn from(original: Error) -> Self {
        SnapshotFailure::from(original).into()
    }
}
impl From<anyhow::Error> for TargetTaskFailure {
    fn from(original: anyhow::Error) -> Self {
        SnapshotFailure::from(original).into()
    }
}
impl From<std::io::Error> for TargetTaskFailure {
    fn from(original: std::io::Error) -> Self {
        SnapshotFailure::from(original).into()
    }
}
impl From<serde_json::Error> for TargetTaskFailure {
    fn from(original: serde_json::Error) -> Self {
        SnapshotFailure::from(original).into()
    }
}
impl From<kasumi_types::drain::DrainFailure> for TargetTaskFailure {
    fn from(original: kasumi_types::drain::DrainFailure) -> Self {
        SnapshotFailure::from(original).into()
    }
}
impl From<kasumi_store::ScratchOperationFailure> for TargetTaskFailure {
    fn from(original: kasumi_store::ScratchOperationFailure) -> Self {
        SnapshotFailure::from(original).into()
    }
}

// Actual closed control backing precedes its final original parent credit.
#[derive(Clone)]
struct Cell {
    state: Arc<State>,
    _charge: SharedBudgetCharge,
}
impl Drop for Cell {
    fn drop(&mut self) {
        // Source diagnostics can own arbitrary native custody. Creation has an
        // independent native/disposal report. Neither is settled by facade Drop.
        // Active loans, tickets, and report aliases already retain this same
        // Cell. A temporary alias must not make a successful unclaimed output
        // permanently sticky before its actual claim clears the state.
        if self.state.users.load(Ordering::Acquire) == 0
            && self.state.preserve.load(Ordering::Acquire)
            && !self.state.retained.swap(true, Ordering::AcqRel)
        {
            std::mem::forget(self.clone());
        }
    }
}

pub(super) struct TargetFailureInventory {
    cells: Vec<Cell>,
    closed: AtomicBool,
    _charge: SharedBudgetCharge,
}

/// A private alias retains both the actual failure control and its charge.
pub(crate) struct TargetCallSeat(Cell);
impl Clone for TargetCallSeat {
    fn clone(&self) -> Self {
        self.0
            .state
            .users
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |users| {
                (users != 0 && users < usize::MAX - 1).then(|| users + 1)
            })
            .expect("live bounded target failure seat");
        Self(self.0.clone())
    }
}
impl Drop for TargetCallSeat {
    fn drop(&mut self) {
        let mut users = self.0.state.users.load(Ordering::Acquire);
        loop {
            let next = if users == 1 { usize::MAX } else { users - 1 };
            match self.0.state.users.compare_exchange(
                users,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => users = current,
            }
        }
        if users == 1 && !self.0.state.preserve.load(Ordering::Acquire) {
            // These two inline variants have no native authority or destructor
            // callback. All active report aliases are gone before destruction.
            let mut outcome = self
                .0
                .state
                .outcome
                .try_lock()
                .expect("last target report alias has no borrowed report or running body");
            assert!(
                self.0.state.dispatch.get().is_none() && (outcome.empty() || outcome.clearable()),
                "actual settled native-free Target outcome"
            );
            drop(outcome.original.take());
            *outcome = Outcome::default();
            self.0.state.phase.store(0, Ordering::SeqCst);
            self.0.state.users.store(0, Ordering::SeqCst);
        } else if users == 1 {
            self.0.state.users.store(0, Ordering::SeqCst);
        }
    }
}

pub(crate) enum TargetCallFailure {
    Retained(TargetCallSeat),
    Admission(ScratchAdmissionRefusal),
    ResponseExpired,
    ResponseLost,
}
/// Borrowed whole-custody diagnosis. No owning native failure can escape.
pub struct TargetCallReport<'a> {
    outcome: &'a Outcome,
    dispatch: &'a OnceLock<anyhow::Error>,
}
impl TargetCallReport<'_> {
    pub fn original(&self) -> Option<&SnapshotFailure> {
        self.outcome.original.as_ref().and_then(Original::snapshot)
    }
    pub fn node_startup(&self) -> Option<&kasumi_store::NodeStoreStartFailure> {
        match self.outcome.original.as_ref() {
            Some(Original::NodeStartup(original)) => Some(original),
            _ => None,
        }
    }
    pub fn cleanup(&self) -> Option<&kasumi_types::drain::DrainFailure> {
        match self.outcome.original.as_ref() {
            Some(Original::RetiredSource(original)) => original.cleanup(),
            Some(Original::Snapshot(_) | Original::NodeStartup(_)) | None => None,
        }
    }
    pub fn cleanup_unsettled(&self) -> Option<bool> {
        match self.outcome.original.as_ref() {
            Some(Original::RetiredSource(original)) => {
                Some(original.cleanup_observation().unsettled())
            }
            Some(Original::Snapshot(_) | Original::NodeStartup(_)) | None => None,
        }
    }
    pub fn dispatch_error(&self) -> Option<&anyhow::Error> {
        self.dispatch.get()
    }
    pub fn body_entered(&self) -> bool {
        self.outcome.body.entry != Entry::NotEntered
    }
    pub fn body_returned(&self) -> bool {
        self.outcome.body.entry == Entry::Returned
    }
    pub fn future_disposal_returned(&self) -> bool {
        self.outcome.future_disposal.entry == Entry::Returned
    }
    pub fn output_disposal_returned(&self) -> bool {
        self.outcome.output_disposal.entry == Entry::Returned
    }
    pub fn has_output(&self) -> bool {
        self.outcome.output.is_some()
    }
    pub fn with_body_panic<R>(
        &self,
        inspect: impl FnOnce(&(dyn std::any::Any + Send)) -> R,
    ) -> Option<R> {
        self.outcome.body.panic.as_deref().map(inspect)
    }
    pub fn with_future_disposal_panic<R>(
        &self,
        inspect: impl FnOnce(&(dyn std::any::Any + Send)) -> R,
    ) -> Option<R> {
        self.outcome.future_disposal.panic.as_deref().map(inspect)
    }
    pub fn with_output_disposal_panic<R>(
        &self,
        inspect: impl FnOnce(&(dyn std::any::Any + Send)) -> R,
    ) -> Option<R> {
        self.outcome.output_disposal.panic.as_deref().map(inspect)
    }
}
impl TargetCallFailure {
    pub(super) fn has_observed_panic(&self) -> bool {
        match self {
            Self::Retained(seat) => seat.0.state.observed_panic.load(Ordering::Acquire),
            Self::Admission(_) | Self::ResponseExpired | Self::ResponseLost => false,
        }
    }
    pub(crate) fn unresolved_custody(&self) -> bool {
        match self {
            Self::Retained(seat) => seat.0.state.preserve.load(Ordering::Acquire),
            Self::Admission(_) | Self::ResponseExpired | Self::ResponseLost => false,
        }
    }
    pub(crate) fn with_report<R>(
        &self,
        work: impl for<'a> FnOnce(Option<TargetCallReport<'a>>) -> R,
    ) -> R {
        match self {
            Self::Retained(seat) => match seat.0.state.outcome.try_lock() {
                Ok(outcome) => work(Some(TargetCallReport {
                    outcome: &outcome,
                    dispatch: &seat.0.state.dispatch,
                })),
                Err(_) => work(None),
            },
            Self::Admission(_) | Self::ResponseExpired | Self::ResponseLost => work(None),
        }
    }
    /// The original never escapes its paid cell. A foreign response owns only
    /// a native-free marker; the report remains independently accessible.
    pub(crate) fn with_original<R>(
        &self,
        work: impl for<'a> FnOnce(Option<&'a SnapshotFailure>) -> R,
    ) -> R {
        self.with_report(|report| {
            work(report.and_then(|report| {
                report
                    .outcome
                    .original
                    .as_ref()
                    .and_then(Original::snapshot)
            }))
        })
    }
    pub(crate) fn marker(&self) -> Error {
        match self {
            Self::Retained(seat) => self.with_report(|report| {
                let mut code = ErrorCode::UnknownOutcome;
                if let Some(report) = report {
                    let outcome = report.outcome;
                    let disposal_uncertain = matches!(
                        outcome.output_disposal.entry,
                        Entry::Entered | Entry::Panicked
                    );
                    if !disposal_uncertain
                        && outcome.returned()
                        && report.dispatch_error().is_none()
                    {
                        if !seat.0.state.retired_source.load(Ordering::Acquire)
                            && let Some(SnapshotFailure::Operation(original)) = report.original()
                        {
                            return original.clone();
                        }
                        // This exact native constructor certificate witnesses
                        // the original provider refusal before lease/payload
                        // construction. The owning diagnostic remains resident.
                        if !seat.0.state.accepted.load(Ordering::Acquire)
                            && let Some(Original::Snapshot(SnapshotFailure::Creation(original))) =
                                outcome.original.as_ref()
                            && original.with_diagnostic(|original| {
                                original
                                    .and_then(|original| {
                                        original.constructor_report().map(|report| {
                                            report.capacity_refused()
                                                && !report.has_lease()
                                                && !report.has_payload()
                                        })
                                    })
                                    .unwrap_or(false)
                            })
                        {
                            code = ErrorCode::Unavailable;
                        }
                    } else if !seat.0.state.accepted.load(Ordering::Acquire)
                        && outcome.body.entry == Entry::NotEntered
                        && outcome.future_disposal.entry == Entry::Returned
                        && outcome.output_disposal.entry == Entry::NotEntered
                        && outcome.original.is_none()
                        && outcome.output.is_none()
                        && outcome.body.panic.is_none()
                        && outcome.future_disposal.panic.is_none()
                        && outcome.output_disposal.panic.is_none()
                    {
                        // Only actual clean destruction of an unentered
                        // producer qualifies this pre-dispatch refusal.
                        code = ErrorCode::Unavailable;
                    }
                }
                Error::new(
                    code,
                    "target failure remains in its original admitted custody",
                )
            }),
            Self::Admission(ScratchAdmissionRefusal::Busy) => Error::new(
                ErrorCode::ResourceExhausted,
                "target call custody exhausted",
            ),
            Self::Admission(ScratchAdmissionRefusal::Sealed) => {
                Error::new(ErrorCode::Unavailable, "target call admission closed")
            }
            Self::ResponseExpired | Self::ResponseLost => Error::new(
                ErrorCode::UnknownOutcome,
                "target response unavailable; recover the exact committed identity",
            ),
        }
    }
}
impl std::fmt::Debug for TargetCallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::fmt::Display for TargetCallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retained(_) => self.with_report(|report| {
                let Some(report) = report else {
                    return f.write_str("target original diagnostic unavailable");
                };
                if let Some(original) = report.node_startup() {
                    return original.fmt(f);
                }
                match report.original() {
                    Some(original) => original.fmt(f),
                    None => f.write_str("target original diagnostic unavailable"),
                }
            }),
            Self::Admission(original) => original.fmt(f),
            Self::ResponseExpired => f.write_str("target response deadline expired"),
            Self::ResponseLost => f.write_str("target response channel closed"),
        }
    }
}

fn allocation(layout: Layout) -> io::Result<u64> {
    layout
        .size()
        .checked_next_power_of_two()
        .and_then(|bytes| bytes.checked_add(64))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| io::ErrorKind::InvalidInput.into())
}
fn arc_layout<T>() -> io::Result<Layout> {
    Layout::array::<usize>(2)
        .map_err(|_| io::ErrorKind::InvalidInput)?
        .extend(Layout::new::<T>())
        .map(|(layout, _)| layout.pad_to_align())
        .map_err(|_| io::ErrorKind::InvalidInput.into())
}
impl TargetFailureInventory {
    pub(super) fn required_bytes(capacity: usize) -> io::Result<u64> {
        let retirement = crate::runtime::RetiredSourceFailure::required_bytes()?;
        let cell = allocation(arc_layout::<State>()?)?
            .checked_add(allocation(arc_layout::<tokio::sync::Mutex<Outcome>>()?)?)
            .and_then(|bytes| bytes.checked_add(ScratchAdmissionSlot::required_bytes().ok()?))
            .and_then(|bytes| bytes.checked_add(retirement))
            .ok_or(io::ErrorKind::InvalidInput)?;
        let cells = cell
            .checked_mul(u64::try_from(capacity).map_err(|_| io::ErrorKind::InvalidInput)?)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let handles =
            allocation(Layout::array::<Cell>(capacity).map_err(|_| io::ErrorKind::InvalidInput)?)?;
        let parent = allocation(
            SharedBudgetCharge::allocation_layout::<Reservation>()
                .map_err(|_| io::ErrorKind::InvalidInput)?,
        )?;
        cells
            .checked_add(handles)
            .and_then(|bytes| bytes.checked_add(parent))
            .ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }
    pub(super) fn new(capacity: usize, charge: SharedBudgetCharge) -> io::Result<Self> {
        Self::required_bytes(capacity)?;
        let mut cells = Vec::new();
        cells
            .try_reserve_exact(capacity)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        for _ in 0..capacity {
            cells.push(Cell {
                state: Arc::new(State {
                    outcome: Arc::new(tokio::sync::Mutex::new(Outcome::default())),
                    dispatch: OnceLock::new(),
                    phase: AtomicU8::new(0),
                    users: AtomicUsize::new(0),
                    accepted: AtomicBool::new(false),
                    observed_panic: AtomicBool::new(false),
                    retired_source: AtomicBool::new(false),
                    preserve: AtomicBool::new(false),
                    retained: AtomicBool::new(false),
                    admission: ScratchAdmissionSlot::new(charge.clone()),
                }),
                _charge: charge.clone(),
            });
        }
        Ok(Self {
            cells,
            closed: AtomicBool::new(false),
            _charge: charge,
        })
    }
    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
    pub(super) fn acquire(&self) -> Result<TargetCallSeat, TargetCallFailure> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(TargetCallFailure::Admission(
                ScratchAdmissionRefusal::Sealed,
            ));
        }
        for cell in &self.cells {
            if cell.state.preserve.load(Ordering::Acquire)
                || cell.state.admission.occupied()
                || cell
                    .state
                    .users
                    .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
            {
                continue;
            }
            let seat = TargetCallSeat(cell.clone());
            if self.closed.load(Ordering::SeqCst) {
                drop(seat);
                return Err(TargetCallFailure::Admission(
                    ScratchAdmissionRefusal::Sealed,
                ));
            }
            cell.state.accepted.store(false, Ordering::Release);
            return Ok(seat);
        }
        Err(TargetCallFailure::Admission(ScratchAdmissionRefusal::Busy))
    }
    pub(super) fn retained(&self) -> bool {
        self.cells
            .iter()
            .any(|cell| cell.state.preserve.load(Ordering::Acquire))
    }
    pub(super) fn original_failure(&self, index: usize) -> Option<TargetCallFailure> {
        let cell = self.cells.get(index)?;
        if !cell.state.preserve.load(Ordering::Acquire) {
            return None;
        }
        let mut users = cell.state.users.load(Ordering::Acquire);
        loop {
            if users >= usize::MAX - 1 {
                return None;
            }
            match cell.state.users.compare_exchange(
                users,
                users + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(TargetCallFailure::Retained(TargetCallSeat(cell.clone()))),
                Err(current) => users = current,
            }
        }
    }
}
impl TargetCallSeat {
    #[cfg(test)]
    pub(super) fn identity(&self) -> usize {
        Arc::as_ptr(&self.0.state) as usize
    }
    pub(super) fn accepted(&self) {
        self.0.state.accepted.store(true, Ordering::Release);
    }
    /// Admission precedes construction of the producer. An occupied or
    /// unknown loan cannot accept another future or overwrite an original.
    pub(super) fn begin(&self) -> Result<TargetProducerLoan, TargetCallFailure> {
        let Ok(outcome) = self.0.state.outcome.clone().try_lock_owned() else {
            return Err(TargetCallFailure::Admission(ScratchAdmissionRefusal::Busy));
        };
        if !outcome.empty()
            || self.0.state.dispatch.get().is_some()
            || self.0.state.preserve.load(Ordering::Acquire)
            || self
                .0
                .state
                .phase
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            return Err(TargetCallFailure::Retained(self.clone()));
        }
        self.0.state.preserve.store(true, Ordering::Release);
        Ok(TargetProducerLoan {
            outcome: Some(outcome),
            seat: Some(self.clone()),
        })
    }
    pub(super) fn record_dispatch(&self, original: anyhow::Error) -> TargetCallFailure {
        assert!(
            self.0.state.dispatch.set(original).is_ok(),
            "one actual dispatch observation"
        );
        self.0.state.preserve.store(true, Ordering::Release);
        TargetCallFailure::Retained(self.clone())
    }
}

/// A nonclone capability for one accepted producer. Dropping an unentered
/// loan gives no producer or native disposition proof.
pub(super) struct TargetProducerLoan {
    outcome: Option<tokio::sync::OwnedMutexGuard<Outcome>>,
    seat: Option<TargetCallSeat>,
}
impl TargetProducerLoan {
    pub(super) fn run<T: TargetOutput, E: TargetProducerFailure, F>(
        mut self,
        work: F,
    ) -> TargetRun<F, T, E>
    where
        F: Future<Output = Result<T, E>>,
    {
        TargetRun {
            outcome: self.outcome.take(),
            work: ManuallyDrop::new(work),
            started: false,
            disposed: false,
            seat: self.seat.take(),
            output: PhantomData,
        }
    }
}
pub(super) struct TargetRun<F, T, E> {
    outcome: Option<tokio::sync::OwnedMutexGuard<Outcome>>,
    work: ManuallyDrop<F>,
    started: bool,
    disposed: bool,
    seat: Option<TargetCallSeat>,
    output: PhantomData<fn() -> (T, E)>,
}
impl<F, T, E> TargetRun<F, T, E> {
    fn dispose_work(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        let outcome = self.outcome.as_mut().expect("same original producer guard");
        outcome.future_disposal.entry = Entry::Entered;
        let disposed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            // The exact accepted future is destroyed in place once, including
            // before first poll or during cancellation. No F is moved here.
            ManuallyDrop::drop(&mut self.work);
        }));
        match disposed {
            Ok(()) => outcome.future_disposal.entry = Entry::Returned,
            Err(original) => {
                outcome.future_disposal.panic = Some(original);
                outcome.future_disposal.entry = Entry::Panicked;
                self.seat
                    .as_ref()
                    .expect("same original producer seat")
                    .0
                    .state
                    .observed_panic
                    .store(true, Ordering::Release);
            }
        }
    }
}
impl<F, T: TargetOutput, E: TargetProducerFailure> Future for TargetRun<F, T, E>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = Result<TargetOutputTicket<T>, TargetCallFailure>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Only pinned projection and in-place destruction access work. The
        // original guard and cell survive both independent unwind catches.
        let this = unsafe { self.get_unchecked_mut() };
        let outcome = this
            .outcome
            .as_mut()
            .expect("one original producer terminal");
        let seat = this.seat.as_ref().expect("same accepted producer seat");
        if !this.started {
            this.started = true;
            outcome.body.entry = Entry::Entered;
            seat.0.state.phase.store(2, Ordering::SeqCst);
        }
        let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            Pin::new_unchecked(&mut *this.work).poll(cx)
        }));
        match polled {
            Ok(Poll::Pending) => return Poll::Pending,
            Ok(Poll::Ready(returned)) => {
                match returned {
                    Ok(original) => outcome.output = Some(original.retain()),
                    Err(original) => {
                        let original = match original.retain() {
                            TargetTaskFailure::Snapshot(SnapshotFailure::Creation(original)) => {
                                Original::Snapshot(SnapshotFailure::Creation(
                                    match seat.0.state.admission.capture(original) {
                                        Ok(original) | Err(original) => original,
                                    },
                                ))
                            }
                            TargetTaskFailure::Snapshot(original) => Original::Snapshot(original),
                            TargetTaskFailure::RetiredSource(original) => {
                                Original::RetiredSource(original)
                            }
                            TargetTaskFailure::NodeStartup(original) => {
                                Original::NodeStartup(original)
                            }
                        };
                        seat.0.state.retired_source.store(
                            matches!(&original, Original::RetiredSource(_)),
                            Ordering::Release,
                        );
                        outcome.original = Some(original);
                    }
                }
                outcome.body.entry = Entry::Returned;
            }
            Err(original) => {
                outcome.body.panic = Some(original);
                outcome.body.entry = Entry::Panicked;
                seat.0.state.observed_panic.store(true, Ordering::Release);
            }
        }
        // The whole returned outcome or actual poll panic is installed BEFORE
        // this independently observed future destructor is entered.
        this.dispose_work();
        let outcome = this.outcome.as_ref().expect("same original terminal guard");
        let seat = this.seat.as_ref().expect("same original terminal seat");
        let success = outcome.returned() && outcome.output.is_some();
        if outcome.returned() {
            seat.0.state.phase.store(3, Ordering::SeqCst);
            if outcome.clearable() && seat.0.state.dispatch.get().is_none() {
                seat.0.state.preserve.store(false, Ordering::Release);
            }
        }
        let result = if success {
            Ok(TargetOutputTicket {
                seat: seat.clone(),
                output: PhantomData,
            })
        } else {
            Err(TargetCallFailure::Retained(seat.clone()))
        };
        drop(this.outcome.take());
        Poll::Ready(result)
    }
}
impl<F, T, E> Drop for TargetRun<F, T, E> {
    fn drop(&mut self) {
        self.dispose_work();
    }
}

/// No output is owned by a response channel before its exact claim. Dropping
/// this ticket leaves the whole original output in its paid cell.
pub(super) struct TargetOutputTicket<T: TargetOutput> {
    seat: TargetCallSeat,
    output: PhantomData<fn() -> T>,
}
impl<T: TargetOutput> std::fmt::Debug for TargetOutputTicket<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TargetOutputTicket")
    }
}
impl<T: TargetOutput> TargetOutputTicket<T> {
    pub(super) fn claim(self) -> Result<T, TargetCallFailure> {
        let Ok(mut outcome) = self.seat.0.state.outcome.try_lock() else {
            // A borrowed report is not authority to consume its whole output.
            return Err(TargetCallFailure::Retained(self.seat.clone()));
        };
        assert!(
            outcome.returned()
                && outcome.original.is_none()
                && self.seat.0.state.dispatch.get().is_none()
        );
        let original = outcome.output.take().expect("one exact output claim");
        *outcome = Outcome::default();
        self.seat.0.state.phase.store(0, Ordering::SeqCst);
        self.seat.0.state.preserve.store(false, Ordering::Release);
        Ok(T::recover(original))
    }
    pub(super) fn dispose(self) -> Result<(), TargetCallFailure> {
        let Ok(mut outcome) = self.seat.0.state.outcome.try_lock() else {
            // No output destructor was entered; keep the same paid original.
            return Err(TargetCallFailure::Retained(self.seat.clone()));
        };
        assert!(outcome.returned() && outcome.output_disposal.entry == Entry::NotEntered);
        let original = outcome.output.take().expect("one exact unclaimed output");
        outcome.output_disposal.entry = Entry::Entered;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(original))) {
            Ok(()) => outcome.output_disposal.entry = Entry::Returned,
            Err(original) => {
                outcome.output_disposal.panic = Some(original);
                outcome.output_disposal.entry = Entry::Panicked;
                self.seat
                    .0
                    .state
                    .observed_panic
                    .store(true, Ordering::Release);
            }
        }
        if outcome.clearable() && self.seat.0.state.dispatch.get().is_none() {
            *outcome = Outcome::default();
            self.seat.0.state.phase.store(0, Ordering::SeqCst);
            self.seat.0.state.preserve.store(false, Ordering::Release);
            Ok(())
        } else {
            Err(TargetCallFailure::Retained(self.seat.clone()))
        }
    }
}
impl TargetCallFailure {
    pub(super) async fn close_pending(&self) {
        if let Self::Retained(seat) = self {
            let mut outcome = seat.0.state.outcome.lock().await;
            if let Some(Original::RetiredSource(original)) = outcome.original.as_mut() {
                // The original is already resident before any cleanup await;
                // its independent exact cleanup observations stay with it.
                original.close_pending().await;
            }
        }
    }
}

#[cfg(test)]
#[path = "target_call_failure_tests.rs"]
mod tests;
