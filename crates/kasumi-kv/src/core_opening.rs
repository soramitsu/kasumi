//! Inline opening custody and explicit, observed native owner teardown.
use super::*;
use crate::disk_state::DiskOpening;
use crate::native_backend::{BackendOwner, BackendTransferSlot, DisposalObservation};
use crate::retained::TerminalObservation;
use std::convert::Infallible;
use std::mem::ManuallyDrop;

#[derive(Default)]
pub(crate) enum CloseObservation {
    #[default]
    NotEntered,
    Entered,
    Returned(BackendCloseOutcome),
    Panicked(CorePanic),
}
impl CloseObservation {
    pub(crate) fn outcome(&self) -> Option<&BackendCloseOutcome> {
        match self {
            Self::Returned(original) => Some(original),
            _ => None,
        }
    }
    fn panic(&self) -> Option<&CorePanic> {
        match self {
            Self::Panicked(original) => Some(original),
            _ => None,
        }
    }
    fn may_retry(&self) -> bool {
        matches!(self, Self::Returned(original) if original.entry() == BackendCloseEntry::NotEntered)
    }
    pub(crate) fn with_observation<R>(
        &self,
        inspect: impl FnOnce(TerminalObservation<'_, io::Error>) -> R,
    ) -> R {
        match self {
            Self::NotEntered => inspect(TerminalObservation::NotEntered),
            Self::Entered => inspect(TerminalObservation::Entered),
            Self::Returned(outcome) => inspect(TerminalObservation::Returned(
                outcome.result.as_ref().copied(),
            )),
            Self::Panicked(original) => {
                original.with_payload(|payload| inspect(TerminalObservation::Panicked(payload)))
            }
        }
    }
}

/// This report borrows exact observations stored in the original native owner.
/// A returned Drop or a native Closed disposition alone is not completion.
pub struct NativeDisposalReport<'a> {
    owner: &'a NativeDisposal,
}
impl NativeDisposalReport<'_> {
    pub fn complete(&self) -> bool {
        self.owner.complete()
    }
    pub fn observation_count(&self) -> usize {
        self.owner.observation_count()
    }
    pub fn with_observation<R>(
        &self,
        index: usize,
        inspect: impl FnOnce(TerminalObservation<'_, Infallible>) -> R,
    ) -> R {
        self.owner.with_observation(index, inspect)
    }
}

pub(crate) struct CoreDisposal {
    pub(crate) core: Option<Core>,
    pub(crate) authority: Option<BackendOwner>,
    pub(crate) disk: DiskOpening,
    state: Option<Mutex<State>>,
    admission: Option<Arc<dyn StorageAdmission>>,
    fence_panic: Option<CorePanic>,
    steps: [DisposalObservation; 5],
    native_drained: bool,
}
impl Default for CoreDisposal {
    fn default() -> Self {
        Self {
            core: None,
            authority: None,
            disk: DiskOpening::default(),
            state: None,
            admission: None,
            fence_panic: None,
            steps: std::array::from_fn(|_| DisposalObservation::default()),
            native_drained: false,
        }
    }
}
impl CoreDisposal {
    fn mark_native_drained(&mut self) {
        self.native_drained = true;
        if let Some(authority) = self.authority.as_mut() {
            authority.mark_native_drained();
        }
    }
    fn dispose(&mut self) -> bool {
        if !self.native_drained {
            return false;
        }
        if let Some(core) = self.core.as_mut() {
            // Closed ownership, no Weak or raw aliases: get_mut only gates
            // exclusivity. The actual control retirement follows separately.
            if core.shared.get_mut().is_none() {
                return false;
            }
            let Core { shared } = self.core.take().expect("original Core disposal");
            let mut shared = match shared.try_unwrap() {
                Ok(shared) => shared,
                Err(shared) => {
                    self.core = Some(Core { shared });
                    return false;
                }
            };
            // Stage the exact authority before any owned field can be dropped.
            self.authority = shared._authority.take();
            self.state = shared.state.take();
            self.admission = Some(unsafe { ManuallyDrop::take(&mut shared.admission) });
            self.fence_panic = shared.fence_panic.take();
            if let Some(authority) = self.authority.as_mut() {
                authority.mark_native_drained();
            }
            self.steps[0].run(|| drop(shared));
        }
        if !matches!(
            self.steps[0],
            DisposalObservation::NotEntered | DisposalObservation::Returned
        ) {
            return false;
        }
        if let Some(state) = self.state.take() {
            // into_inner consumes the real synchronization control before its
            // original State is handed back. Stage its owned fields before
            // entering any destructor callback.
            let mut state = state
                .into_inner()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(disk) = state.disk.take() {
                self.disk.adopt(disk);
            }
            let backend = state.backend;
            self.steps[1] = DisposalObservation::Returned;
            self.steps[2].run(|| drop(backend));
        }
        if self.steps.iter().any(|step| {
            matches!(
                step,
                DisposalObservation::Entered | DisposalObservation::Panicked(_)
            )
        }) {
            return false;
        }
        if !self.disk.dispose() {
            return false;
        }
        if matches!(self.steps[3], DisposalObservation::NotEntered) {
            let original = self.fence_panic.take();
            self.steps[3].run(|| drop(original));
        }
        if !self.steps[3].returned() {
            return false;
        }
        if matches!(self.steps[4], DisposalObservation::NotEntered) {
            let admission = self.admission.take();
            self.steps[4].run(|| drop(admission));
        }
        if !self.steps[4].returned() {
            return false;
        }
        self.authority.as_mut().is_none_or(BackendOwner::dispose)
    }
    fn complete(&self) -> bool {
        self.native_drained
            && self.core.is_none()
            && self.state.is_none()
            && self.disk.complete()
            && self.steps[3].returned()
            && self.steps[4].returned()
            && self
                .authority
                .as_ref()
                .is_none_or(|owner| owner.disposal.complete())
            && self.steps.iter().all(|step| {
                matches!(
                    step,
                    DisposalObservation::NotEntered | DisposalObservation::Returned
                )
            })
    }
}
impl Drop for CoreDisposal {
    fn drop(&mut self) {
        // The enclosing report must explicitly drive disposal. An abandoned
        // report cannot manufacture a positive observation by default Drop.
        if self.complete() {
            return;
        }
        if let Some(owner) = self.core.take() {
            std::mem::forget(owner);
        }
        if let Some(owner) = self.authority.take() {
            std::mem::forget(owner);
        }
        if let Some(owner) = self.state.take() {
            std::mem::forget(owner);
        }
        if let Some(owner) = self.admission.take() {
            std::mem::forget(owner);
        }
        if let Some(original) = self.fence_panic.take() {
            std::mem::forget(original);
        }
        std::mem::forget(std::mem::take(&mut self.disk));
        std::mem::forget(std::mem::replace(
            &mut self.steps,
            std::array::from_fn(|_| DisposalObservation::default()),
        ));
    }
}

pub(crate) struct NativeDisposal {
    pub(crate) core: CoreDisposal,
    pub(crate) facade: crate::tables::FacadeOpening,
    inline_body: DisposalObservation,
    pub(crate) retry_diagnostic_disposal: DisposalObservation,
    close_diagnostic_disposal: [DisposalObservation; 3],
}
impl Default for NativeDisposal {
    fn default() -> Self {
        Self {
            core: CoreDisposal::default(),
            facade: crate::tables::FacadeOpening::default(),
            inline_body: DisposalObservation::default(),
            retry_diagnostic_disposal: DisposalObservation::default(),
            close_diagnostic_disposal: std::array::from_fn(|_| DisposalObservation::default()),
        }
    }
}
impl NativeDisposal {
    pub(crate) fn dispose_inline<B>(&mut self, body: &mut Option<B>) -> bool {
        if !self.core.native_drained {
            return false;
        }
        if !crate::native_backend::dispose_slot(body, &mut self.inline_body) {
            return false;
        }
        self.dispose()
    }
    pub(crate) fn report(&self) -> NativeDisposalReport<'_> {
        NativeDisposalReport { owner: self }
    }
    pub(crate) fn core_ref(&self) -> Option<&Core> {
        self.core.core.as_ref().or_else(|| self.facade.core())
    }
    pub(crate) fn mark_native_drained(&mut self) {
        self.core.mark_native_drained();
    }
    pub(crate) fn adopt_database(&mut self, database: crate::Database) {
        self.facade.adopt(database);
    }
    pub(crate) fn dispose(&mut self) -> bool {
        if !self.core.native_drained
            || !matches!(
                self.inline_body,
                DisposalObservation::NotEntered | DisposalObservation::Returned
            )
        {
            return false;
        }
        if !self.facade.dispose(&mut self.core.core) {
            return false;
        }
        self.core.dispose()
    }
    pub(crate) fn complete(&self) -> bool {
        self.facade.complete()
            && self.core.complete()
            && matches!(
                self.retry_diagnostic_disposal,
                DisposalObservation::NotEntered | DisposalObservation::Returned
            )
            && self.close_diagnostic_disposal.iter().all(|step| {
                matches!(
                    step,
                    DisposalObservation::NotEntered | DisposalObservation::Returned
                )
            })
            && matches!(
                self.inline_body,
                DisposalObservation::NotEntered | DisposalObservation::Returned
            )
    }
    fn observation_count(&self) -> usize {
        5 + self.facade.observation_count()
            + self.core.steps.len()
            + self.core.disk.observation_count()
            + 3
    }
    fn with_observation<R>(
        &self,
        mut index: usize,
        inspect: impl FnOnce(TerminalObservation<'_, Infallible>) -> R,
    ) -> R {
        if index == 0 {
            return self.inline_body.with_observation(inspect);
        }
        if index == 1 {
            return self.retry_diagnostic_disposal.with_observation(inspect);
        }
        if index < 5 {
            return self.close_diagnostic_disposal[index - 2].with_observation(inspect);
        }
        index -= 5;
        let count = self.facade.observation_count();
        if index < count {
            return self.facade.with_observation(index, inspect);
        }
        index -= count;
        if index < self.core.steps.len() {
            return self.core.steps[index].with_observation(inspect);
        }
        index -= self.core.steps.len();
        let count = self.core.disk.observation_count();
        if index < count {
            return self.core.disk.with_observation(index, inspect);
        }
        index -= count;
        if let Some(authority) = self.core.authority.as_ref() {
            return match index {
                0 => authority.disposal.body.with_observation(inspect),
                1 => authority.disposal.control.with_observation(inspect),
                2 => authority.disposal.grant.with_observation(inspect),
                _ => panic!("native disposal observation index"),
            };
        }
        assert!(index < 3, "native disposal observation index");
        inspect(TerminalObservation::NotEntered)
    }
}

impl Drop for NativeDisposal {
    fn drop(&mut self) {
        if self.complete() {
            return;
        }
        std::mem::forget(std::mem::take(&mut self.inline_body));
        std::mem::forget(std::mem::take(&mut self.retry_diagnostic_disposal));
        std::mem::forget(std::mem::replace(
            &mut self.close_diagnostic_disposal,
            std::array::from_fn(|_| DisposalObservation::NotEntered),
        ));
    }
}

/// A consumed failure's private authority. It is installed in an already
/// admitted retained report before its original cause is moved to Attempt.
pub(crate) struct OpeningCustody<B> {
    inline: BackendTransferSlot<B>,
    pub(crate) admitted: NativeDisposal,
    binding: Option<Arc<dyn StorageAdmission>>,
    pub(crate) first_close: CloseObservation,
    retry_close: CloseObservation,
}
impl<B: SegmentGroupBackend> OpeningCustody<B> {
    pub(crate) fn prepared(backend: B, binding: Arc<dyn StorageAdmission>) -> Self {
        Self {
            inline: BackendTransferSlot::new(backend),
            admitted: NativeDisposal::default(),
            binding: Some(binding),
            first_close: CloseObservation::NotEntered,
            retry_close: CloseObservation::NotEntered,
        }
    }
    fn retire_close_diagnostics(&mut self) -> bool {
        for index in 0..2 {
            if matches!(
                self.admitted.close_diagnostic_disposal[index],
                DisposalObservation::NotEntered
            ) {
                let original = if index == 0 {
                    std::mem::take(&mut self.first_close)
                } else {
                    std::mem::take(&mut self.retry_close)
                };
                self.admitted.close_diagnostic_disposal[index].run(|| drop(original));
            }
            if !self.admitted.close_diagnostic_disposal[index].returned() {
                return false;
            }
        }
        crate::native_backend::dispose_slot(
            &mut self.binding,
            &mut self.admitted.close_diagnostic_disposal[2],
        )
    }
    fn close_body(&self) -> BackendCloseOutcome {
        if let Some(original) = self.inline.as_ref() {
            return original.close();
        }
        if let Some(core) = self.admitted.core_ref() {
            return core.close();
        }
        if let Some(authority) = self.admitted.core.authority.as_ref() {
            return authority.close();
        }
        panic!("original backend close custody")
    }
    fn latest_close(&self) -> &CloseObservation {
        if matches!(self.retry_close, CloseObservation::NotEntered) {
            &self.first_close
        } else {
            &self.retry_close
        }
    }
    pub(crate) fn native_disposition(&self) -> BackendNativeDisposition {
        if self.admitted.core.native_drained {
            return BackendNativeDisposition::Drained;
        }
        self.latest_close().outcome().map_or(
            BackendNativeDisposition::Retained,
            BackendCloseOutcome::native_disposition,
        )
    }
    pub(crate) fn close(&mut self) {
        if !matches!(self.first_close, CloseObservation::NotEntered) {
            return;
        }
        self.first_close = CloseObservation::Entered;
        self.first_close = match catch_unwind(AssertUnwindSafe(|| self.close_body())) {
            Ok(outcome) => CloseObservation::Returned(outcome),
            Err(original) => CloseObservation::Panicked(CorePanic::new(original)),
        };
        if self.native_disposition() == BackendNativeDisposition::Drained {
            self.admitted.mark_native_drained();
        }
    }
    pub(crate) fn close_may_retry(&self) -> bool {
        self.latest_close().may_retry()
    }
    pub(crate) fn first_close_outcome(&self) -> Option<&BackendCloseOutcome> {
        self.first_close.outcome()
    }
    pub(crate) fn retry_close_outcome(&self) -> Option<&BackendCloseOutcome> {
        self.retry_close.outcome()
    }
    pub(crate) fn retry_close(&mut self) {
        if !self.latest_close().may_retry() {
            return;
        }
        if !matches!(self.retry_close, CloseObservation::NotEntered) {
            if !matches!(
                self.admitted.retry_diagnostic_disposal,
                DisposalObservation::NotEntered | DisposalObservation::Returned
            ) {
                return;
            }
            self.admitted.retry_diagnostic_disposal = DisposalObservation::NotEntered;
            let prior = std::mem::take(&mut self.retry_close);
            self.admitted.retry_diagnostic_disposal.run(|| drop(prior));
            if !self.admitted.retry_diagnostic_disposal.returned() {
                return;
            }
        }
        self.retry_close = CloseObservation::Entered;
        self.retry_close = match catch_unwind(AssertUnwindSafe(|| self.close_body())) {
            Ok(outcome) => CloseObservation::Returned(outcome),
            Err(original) => CloseObservation::Panicked(CorePanic::new(original)),
        };
        if self.native_disposition() == BackendNativeDisposition::Drained {
            self.admitted.mark_native_drained();
        }
    }
    pub(crate) fn with_close_observation<R>(
        &self,
        inspect: impl FnOnce(TerminalObservation<'_, io::Error>) -> R,
    ) -> R {
        self.latest_close().with_observation(inspect)
    }
    pub(crate) fn dispose(&mut self) -> bool {
        if self.native_disposition() != BackendNativeDisposition::Drained {
            return false;
        }
        if self.inline.as_ref().is_some()
            && matches!(self.admitted.inline_body, DisposalObservation::NotEntered)
        {
            self.inline.dispose(&mut self.admitted.inline_body);
            if !self.admitted.inline_body.returned() {
                return false;
            }
        }
        self.admitted.dispose()
    }
}
impl<B> Drop for OpeningCustody<B> {
    fn drop(&mut self) {
        if self.admitted.complete() {
            return;
        }
        if let Some(binding) = self.binding.take() {
            std::mem::forget(binding);
        }
        std::mem::forget(std::mem::take(&mut self.first_close));
        std::mem::forget(std::mem::take(&mut self.retry_close));
        std::mem::forget(std::mem::take(&mut self.admitted.retry_diagnostic_disposal));
        std::mem::forget(std::mem::replace(
            &mut self.admitted.close_diagnostic_disposal,
            std::array::from_fn(|_| DisposalObservation::NotEntered),
        ));
    }
}

/// Generic, inline constructor failure. First admission denial retains the
/// original sized backend without allocating an erasure or diagnostic box.
#[must_use]
pub struct CoreOpenFailure<B> {
    original: ManuallyDrop<CoreError>,
    custody: OpeningCustody<B>,
}
impl<B: SegmentGroupBackend> CoreOpenFailure<B> {
    pub fn original_error(&self) -> &CoreError {
        &self.original
    }
    pub fn backend(&self) -> Option<&B> {
        self.custody.inline.as_ref()
    }
    pub fn close_report(&self) -> Option<&BackendCloseOutcome> {
        self.custody.first_close.outcome()
    }
    pub fn close_panic(&self) -> Option<&CorePanic> {
        self.custody.first_close.panic()
    }
    pub fn native_disposition(&self) -> BackendNativeDisposition {
        self.custody.native_disposition()
    }
    pub fn retry_close(&mut self) -> Option<&BackendCloseOutcome> {
        self.custody.retry_close();
        self.custody.latest_close().outcome()
    }
    pub fn dispose(&mut self) -> NativeDisposalReport<'_> {
        self.custody.dispose();
        self.custody.admitted.report()
    }
    pub fn disposal(&self) -> NativeDisposalReport<'_> {
        self.custody.admitted.report()
    }
    #[allow(
        clippy::result_large_err,
        reason = "Refusal returns the same inline custody without allocating another owner."
    )]
    pub fn into_disposed_error(mut self) -> Result<CoreError, Self> {
        if !self.custody.admitted.complete() || !self.custody.retire_close_diagnostics() {
            return Err(self);
        }
        let mut original = ManuallyDrop::new(self);
        let cause = unsafe { ManuallyDrop::take(&mut original.original) };
        let custody = unsafe { std::ptr::read(&original.custody) };
        drop(custody);
        Ok(cause)
    }
    #[allow(
        clippy::result_large_err,
        reason = "Refusal returns the same inline custody without allocating another owner."
    )]
    pub(crate) fn install(
        self,
        binding: &Arc<dyn StorageAdmission>,
        slot: &mut Option<OpeningCustody<B>>,
    ) -> Result<CoreError, Self> {
        if !self
            .custody
            .binding
            .as_ref()
            .is_some_and(|actual| Arc::ptr_eq(binding, actual))
            || slot.is_some()
        {
            return Err(self);
        }
        let mut original = ManuallyDrop::new(self);
        // SAFETY: consumed owner is not dropped. Its custody is moved once to
        // the exact preowned slot BEFORE its original error is extracted.
        *slot = Some(unsafe { std::ptr::read(&original.custody) });
        Ok(unsafe { ManuallyDrop::take(&mut original.original) })
    }
}
impl<B> fmt::Debug for CoreOpenFailure<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreOpenFailure")
            .field("original", &self.original)
            .finish_non_exhaustive()
    }
}
impl<B> fmt::Display for CoreOpenFailure<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "opening failed: {}", *self.original)
    }
}

impl<B> Drop for CoreOpenFailure<B> {
    fn drop(&mut self) {
        // original remains inline and alive for repeated inspection. A caller
        // abandoning the owner cannot trigger an unobserved diagnostic Drop.
    }
}

/// Opening returned successfully, but its separately staged cleanup did not.
/// This owner keeps that ReturnedOk result and the exact cleanup observations.
#[must_use]
pub struct CoreOpenCleanup<B> {
    custody: OpeningCustody<B>,
}
impl<B> fmt::Debug for CoreOpenCleanup<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CoreOpenCleanup(original successful body; cleanup retained)")
    }
}
impl<B> fmt::Display for CoreOpenCleanup<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("opening body returned; original cleanup retained")
    }
}

/// The one canonical constructor failure: no cleanup panic is normalized into
/// a fabricated opening cause and no generic authority is erased on failure.
#[must_use]
pub enum NativeOpenFailure<B> {
    Body(CoreOpenFailure<B>),
    Cleanup(CoreOpenCleanup<B>),
}
impl<B: SegmentGroupBackend> NativeOpenFailure<B> {
    fn custody(&self) -> &OpeningCustody<B> {
        match self {
            Self::Body(original) => &original.custody,
            Self::Cleanup(original) => &original.custody,
        }
    }
    fn custody_mut(&mut self) -> &mut OpeningCustody<B> {
        match self {
            Self::Body(original) => &mut original.custody,
            Self::Cleanup(original) => &mut original.custody,
        }
    }
    pub fn original_error(&self) -> Option<&CoreError> {
        match self {
            Self::Body(original) => Some(original.original_error()),
            Self::Cleanup(_) => None,
        }
    }
    pub fn opening_returned_ok(&self) -> bool {
        matches!(self, Self::Cleanup(_))
    }
    pub fn backend(&self) -> Option<&B> {
        self.custody().inline.as_ref()
    }
    pub fn close_report(&self) -> Option<&BackendCloseOutcome> {
        self.custody().first_close.outcome()
    }
    pub fn retry_close_report(&self) -> Option<&BackendCloseOutcome> {
        self.custody().retry_close.outcome()
    }
    pub fn close_panic(&self) -> Option<&CorePanic> {
        self.custody().first_close.panic()
    }
    pub fn native_disposition(&self) -> BackendNativeDisposition {
        self.custody().native_disposition()
    }
    pub fn retry_close(&mut self) -> Option<&BackendCloseOutcome> {
        self.custody_mut().retry_close();
        self.custody().latest_close().outcome()
    }
    pub fn dispose(&mut self) -> NativeDisposalReport<'_> {
        self.custody_mut().dispose();
        self.custody().admitted.report()
    }
    pub fn disposal(&self) -> NativeDisposalReport<'_> {
        self.custody().admitted.report()
    }
    #[allow(
        clippy::result_large_err,
        reason = "Refusal returns the same inline custody without allocating another owner."
    )]
    pub fn into_disposed_error(self) -> Result<CoreError, Self> {
        match self {
            Self::Body(original) => original.into_disposed_error().map_err(Self::Body),
            original => Err(original),
        }
    }
    #[allow(
        clippy::result_large_err,
        reason = "Refusal returns the same inline custody without allocating another owner."
    )]
    pub(crate) fn install(
        self,
        binding: &Arc<dyn StorageAdmission>,
        slot: &mut Option<OpeningCustody<B>>,
    ) -> Result<Option<CoreError>, Self> {
        if !self
            .custody()
            .binding
            .as_ref()
            .is_some_and(|actual| Arc::ptr_eq(binding, actual))
            || slot.is_some()
        {
            return Err(self);
        }
        match self {
            Self::Body(original) => original
                .install(binding, slot)
                .map(Some)
                .map_err(Self::Body),
            Self::Cleanup(original) => {
                *slot = Some(original.custody);
                Ok(None)
            }
        }
    }
}
impl<B> fmt::Debug for NativeOpenFailure<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Body(original) => original.fmt(f),
            Self::Cleanup(original) => original.fmt(f),
        }
    }
}
impl<B> fmt::Display for NativeOpenFailure<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Body(original) => original.fmt(f),
            Self::Cleanup(original) => original.fmt(f),
        }
    }
}

#[allow(
    clippy::result_large_err,
    reason = "Constructor failure retains the exact backend and cleanup inline when allocation admission fails."
)]
pub(crate) fn assemble<B: SegmentGroupBackend + 'static>(
    backend: B,
    admission: Arc<dyn StorageAdmission>,
    group_id: [u8; 16],
    cache: CacheConfig,
    create: bool,
    close_on_failure: bool,
    facade: bool,
) -> Result<NativeDisposal, NativeOpenFailure<B>> {
    let mut custody = OpeningCustody::prepared(backend, admission.clone());
    let body = catch_unwind(AssertUnwindSafe(|| -> Result<(), CoreError> {
        admission
            .check_owner()
            .map_err(|_| CoreError::new(CoreErrorCause::OwnerFailed))?;
        let grant = admission
            .reserve_workspace(Core::shell_request_bytes::<B>()?)
            .map(NativeResidentLease::new)?;
        custody.admitted.core.authority = Some(BackendOwner::prepared(grant));
        custody
            .admitted
            .core
            .authority
            .as_mut()
            .expect("original native shell authority")
            .adopt(&mut custody.inline)
            .map_err(|original| CoreError::new(CoreErrorCause::AllocationRefused(original)))?;
        let original = custody
            .admitted
            .core
            .authority
            .as_ref()
            .expect("admitted original backend")
            .original();
        if create {
            custody
                .admitted
                .core
                .disk
                .create(original, admission.clone(), group_id, cache)?;
        } else {
            custody
                .admitted
                .core
                .disk
                .open(original, admission.clone(), group_id, cache)?;
        }
        Ok(())
    }));
    // The original body result is recorded outside transient retirement.
    if let Some(original) = opening_error(body) {
        if close_on_failure {
            custody.close();
        }
        return Err(NativeOpenFailure::Body(CoreOpenFailure {
            original: ManuallyDrop::new(original),
            custody,
        }));
    }
    if !custody.admitted.core.disk.retire_transients() {
        if close_on_failure {
            custody.close();
        }
        return Err(NativeOpenFailure::Cleanup(CoreOpenCleanup { custody }));
    }
    let promotion = catch_unwind(AssertUnwindSafe(|| -> Result<(), CoreError> {
        let position = custody
            .admitted
            .core
            .disk
            .completed()
            .expect("completed disk opening")
            .committed_position()?;
        let authority = custody
            .admitted
            .core
            .authority
            .as_ref()
            .expect("original authority");
        custody.admitted.core.state = Some(crate::native_sync::mutex(
            State {
                backend: authority.reference(),
                disk: None,
                close_entered: false,
                close_report: None,
                closed: false,
                maintenance_active: false,
                maintenance_position: position,
            },
            authority.grant(),
        ));
        let state = custody
            .admitted
            .core
            .state
            .as_ref()
            .expect("admitted state");
        state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .disk = custody.admitted.core.disk.take_completed();
        let shared = Shared {
            state: custody.admitted.core.state.take(),
            admission: ManuallyDrop::new(admission.clone()),
            stopped: AtomicBool::new(false),
            fenced: AtomicBool::new(false),
            fence_panic: OnceLock::new(),
            snapshots: AtomicUsize::new(0),
            _authority: custody.admitted.core.authority.take(),
        };
        custody.admitted.core.core = Some(Core {
            shared: NativeOwnedArc::new(shared),
        });
        if facade {
            custody.admitted.facade.build(
                custody
                    .admitted
                    .core
                    .core
                    .take()
                    .expect("completed original Core"),
                admission.clone(),
            );
        }
        Ok(())
    }));
    if let Some(original) = opening_error(promotion) {
        if close_on_failure {
            custody.close();
        }
        Err(NativeOpenFailure::Body(CoreOpenFailure {
            original: ManuallyDrop::new(original),
            custody,
        }))
    } else {
        // Promotion installed the provider in the live native owner. Release
        // only the constructor binding; the argument and promoted owner keep
        // the provider alive throughout this discharge.
        drop(custody.binding.take());
        Ok(std::mem::take(&mut custody.admitted))
    }
}
fn opening_error(result: Result<Result<(), CoreError>, Box<dyn Any + Send>>) -> Option<CoreError> {
    match result {
        Ok(Ok(())) => None,
        Ok(Err(original)) => Some(original),
        Err(original) => Some(CoreError::panicked(CorePanic::new(original))),
    }
}

impl NativeDisposal {
    pub(crate) fn into_core(mut self) -> Core {
        self.core.core.take().expect("completed Core")
    }
    pub(crate) fn into_database(mut self) -> crate::Database {
        self.facade.take_completed().expect("completed Database")
    }
}

/// Consuming direct-Core disposal custody. The original close outcome remains
/// with the caller; this owner never invokes or replays native close.
#[must_use]
pub struct NativeOwnedDisposal {
    owner: NativeDisposal,
}
impl NativeOwnedDisposal {
    pub(crate) fn from_database(database: crate::Database) -> Self {
        let drained = database.native_is_drained();
        let mut owner = NativeDisposal::default();
        owner.adopt_database(database);
        if drained {
            owner.mark_native_drained();
        }
        Self { owner }
    }
    pub fn report(&self) -> NativeDisposalReport<'_> {
        self.owner.report()
    }
    pub fn dispose(&mut self) -> NativeDisposalReport<'_> {
        self.owner.dispose();
        self.owner.report()
    }
}
impl Core {
    pub fn into_disposal(self) -> NativeOwnedDisposal {
        let drained = self
            .shared
            .state
            .as_ref()
            .expect("live native state")
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .closed;
        let mut owner = NativeDisposal::default();
        owner.core.core = Some(self);
        if drained {
            owner.mark_native_drained();
        }
        NativeOwnedDisposal { owner }
    }
}
