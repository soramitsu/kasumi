//! One original backend body and its prospective native shell grant.
use crate::checked_group::CheckedGroup;
use crate::core::{BackendCloseOutcome, CorePanic, NativeResidentLease};
use crate::group::{GroupFile, SegmentGroupBackend};
use crate::native_owned_arc::{NativeOwnedArc, NativeOwnedArcAllocation};
use crate::root::{ROOT_SLOT_BYTES, RootSlot};
use std::alloc::{Layout, alloc};
use std::ffi::OsStr;
use std::io;
use std::mem::MaybeUninit;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// The constructor's original sized body stays in this closed slot until both
/// admitted control and body placement exist. Its flag permits one in-place move;
/// neither allocation refusal nor an abandoned report drops the original body.
pub(crate) struct BackendTransferSlot<B> {
    body: MaybeUninit<B>,
    initialized: bool,
}
impl<B> BackendTransferSlot<B> {
    pub(crate) fn new(body: B) -> Self {
        Self {
            body: MaybeUninit::new(body),
            initialized: true,
        }
    }
    pub(crate) fn as_ref(&self) -> Option<&B> {
        if self.initialized {
            // SAFETY: only this flag authorizes access to the original B.
            Some(unsafe { self.body.assume_init_ref() })
        } else {
            None
        }
    }
    fn place(&mut self) -> io::Result<Box<B>> {
        assert!(self.initialized, "original backend transfers once");
        let layout = Layout::new::<B>();
        let pointer = if layout.size() == 0 {
            std::ptr::NonNull::<B>::dangling().as_ptr()
        } else {
            // The original native shell grant already covers this exact
            // backing and its alignment/allocator allowance. Null is a real
            // allocation refusal, before any backend move or native effect.
            let pointer = unsafe { alloc(layout) }.cast::<B>();
            if pointer.is_null() {
                return Err(io::ErrorKind::OutOfMemory.into());
            }
            pointer
        };
        // SAFETY: the original B is initialized and exclusively borrowed. The
        // destination is aligned, sized and disjoint (or dangling for a ZST).
        // No callback or fallible operation occurs between this one move,
        // disabling the source, and installing the initialized Box owner.
        unsafe { std::ptr::copy_nonoverlapping(self.body.as_ptr(), pointer, 1) };
        self.initialized = false;
        Ok(unsafe { Box::from_raw(pointer) })
    }
    pub(crate) fn dispose(&mut self, observation: &mut DisposalObservation) {
        if self.initialized && matches!(observation, DisposalObservation::NotEntered) {
            self.initialized = false;
            // The original inline allocation remains outside this callback.
            // A panic is retained by its existing observation, never retried.
            observation.run(|| unsafe { std::ptr::drop_in_place(self.body.as_mut_ptr()) });
        }
    }
}

/// A destructor observation owns its original panic inline. Returned is set
/// only after the consuming operation itself returned.
#[derive(Default)]
pub(crate) enum DisposalObservation {
    #[default]
    NotEntered,
    Entered,
    Returned,
    Panicked(CorePanic),
}
impl DisposalObservation {
    pub(crate) fn returned(&self) -> bool {
        matches!(self, Self::Returned)
    }
    pub(crate) fn with_observation<R>(
        &self,
        inspect: impl FnOnce(crate::retained::TerminalObservation<'_, std::convert::Infallible>) -> R,
    ) -> R {
        use crate::retained::TerminalObservation;
        match self {
            Self::NotEntered => inspect(TerminalObservation::NotEntered),
            Self::Entered => inspect(TerminalObservation::Entered),
            Self::Returned => inspect(TerminalObservation::Returned(Ok(()))),
            Self::Panicked(original) => {
                original.with_payload(|payload| inspect(TerminalObservation::Panicked(payload)))
            }
        }
    }
    pub(crate) fn run(&mut self, dispose: impl FnOnce()) {
        if !matches!(self, Self::NotEntered) {
            return;
        }
        *self = Self::Entered;
        *self = match catch_unwind(AssertUnwindSafe(dispose)) {
            Ok(()) => Self::Returned,
            Err(original) => Self::Panicked(CorePanic::new(original)),
        };
    }
}

pub(crate) struct BackendDisposal {
    pub(crate) body: DisposalObservation,
    pub(crate) control: DisposalObservation,
    pub(crate) grant: DisposalObservation,
    body_initialized: bool,
    control_allocated: bool,
}
impl Default for BackendDisposal {
    fn default() -> Self {
        Self {
            body: DisposalObservation::NotEntered,
            control: DisposalObservation::NotEntered,
            grant: DisposalObservation::NotEntered,
            body_initialized: false,
            control_allocated: false,
        }
    }
}
impl BackendDisposal {
    pub(crate) fn complete(&self) -> bool {
        (if self.body_initialized {
            self.body.returned()
        } else {
            matches!(self.body, DisposalObservation::NotEntered)
        }) && (if self.control_allocated {
            self.control.returned()
        } else {
            matches!(self.control, DisposalObservation::NotEntered)
        }) && self.grant.returned()
    }
}

pub(crate) struct BackendCell {
    body: Option<Box<dyn SegmentGroupBackend>>,
    grant: Option<NativeResidentLease>,
    // A fallback must retain the original diagnostic along with this same
    // already funded cell; it cannot allocate another failure owner.
    retained_disposal: Option<BackendDisposal>,
}
impl Drop for BackendCell {
    fn drop(&mut self) {
        // The sole consuming authority removes these only under observation.
        // A broken or abandoned protocol never silently refunds its funding.
        if let Some(body) = self.body.take() {
            std::mem::forget(body);
        }
        if let Some(grant) = self.grant.take() {
            std::mem::forget(grant);
        }
        if let Some(original) = self.retained_disposal.take() {
            std::mem::forget(original);
        }
    }
}

#[derive(Clone)]
pub(crate) enum OriginalBackend {
    Native(NativeOwnedArc<BackendCell>),
    // Component tests begin with an externally preowned raw fixture. This
    // adapter adds no owner or grant and is absent from production builds.
    #[cfg(test)]
    ComponentFixture(std::sync::Arc<dyn SegmentGroupBackend>),
}
impl OriginalBackend {
    #[cfg(test)]
    pub(crate) fn component_fixture(body: std::sync::Arc<dyn SegmentGroupBackend>) -> Self {
        Self::ComponentFixture(body)
    }
    pub(crate) fn as_ref(&self) -> &dyn SegmentGroupBackend {
        match self {
            Self::Native(cell) => cell.body.as_deref().expect("live original backend body"),
            #[cfg(test)]
            Self::ComponentFixture(body) => body.as_ref(),
        }
    }
}

/// Capabilities alias one body. Checked construction accepts only Original,
/// preventing recursive checked ownership and a second close authority.
#[derive(Clone)]
pub(crate) enum BackendRef {
    Original(OriginalBackend),
    Checked(NativeOwnedArc<CheckedGroup>),
}
impl BackendRef {
    pub(crate) fn as_ref(&self) -> &dyn SegmentGroupBackend {
        match self {
            Self::Original(original) => original.as_ref(),
            Self::Checked(checked) => checked.as_ref(),
        }
    }
}

/// Nonclone authority. Shared stores this last, outside its State mutex.
pub(crate) struct BackendOwner {
    cell: Option<NativeOwnedArc<BackendCell>>,
    uninitialized_cell: Option<NativeOwnedArcAllocation<BackendCell>>,
    staged_grant: Option<NativeResidentLease>,
    native_drained: bool,
    pub(crate) disposal: BackendDisposal,
}
impl BackendOwner {
    pub(crate) fn allocation_request_bytes<B>() -> io::Result<u64> {
        fn backing(layout: Layout) -> io::Result<u64> {
            u64::try_from(layout.size())
                .ok()
                .and_then(|bytes| bytes.checked_add(u64::try_from(layout.align() - 1).ok()?))
                .and_then(|bytes| bytes.checked_add(64))
                .ok_or_else(|| io::ErrorKind::InvalidInput.into())
        }
        backing(Layout::new::<B>())?
            .checked_add(backing(NativeOwnedArc::<BackendCell>::allocation_layout()?)?)
            .ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }
    pub(crate) fn prepared(grant: NativeResidentLease) -> Self {
        // Stage the actual combined grant in the original opening owner before
        // either allocation. Every partial refusal keeps it under observation.
        Self {
            cell: None,
            uninitialized_cell: None,
            staged_grant: Some(grant),
            native_drained: false,
            disposal: BackendDisposal::default(),
        }
    }
    pub(crate) fn adopt<B: SegmentGroupBackend + 'static>(
        &mut self,
        original: &mut BackendTransferSlot<B>,
    ) -> io::Result<()> {
        assert!(self.cell.is_none() && self.uninitialized_cell.is_none());
        self.uninitialized_cell = Some(NativeOwnedArc::try_allocate()?);
        self.disposal.control_allocated = true;
        let body = original.place()?;
        self.disposal.body_initialized = true;
        let grant = self
            .staged_grant
            .take()
            .expect("original native shell grant");
        self.cell = Some(
            self.uninitialized_cell
                .take()
                .expect("actual admitted native control")
                .initialize(BackendCell {
                    body: Some(body),
                    grant: Some(grant),
                    retained_disposal: None,
                }),
        );
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn control_allocation_layout_for_test() -> io::Result<Layout> {
        NativeOwnedArc::<BackendCell>::allocation_layout()
    }
    pub(crate) fn original(&self) -> OriginalBackend {
        OriginalBackend::Native(
            self.cell
                .as_ref()
                .expect("original backend authority")
                .clone(),
        )
    }
    pub(crate) fn reference(&self) -> BackendRef {
        BackendRef::Original(self.original())
    }
    pub(crate) fn grant(&self) -> &NativeResidentLease {
        self.cell
            .as_ref()
            .expect("live authoritative backend cell")
            .grant
            .as_ref()
            .expect("original combined native grant")
    }
    pub(crate) fn close(&self) -> BackendCloseOutcome {
        self.cell
            .as_ref()
            .expect("live authoritative backend cell")
            .body
            .as_deref()
            .expect("backend close before body disposal")
            .close()
    }
    #[cfg(test)]
    pub(crate) fn backing_addresses_for_test(&self) -> [usize; 2] {
        let cell = self.cell.as_ref().expect("original backend authority");
        [
            cell.as_ref() as *const BackendCell as usize,
            cell.body.as_deref().expect("original backend body") as *const dyn SegmentGroupBackend
                as *const () as usize,
        ]
    }
    pub(crate) fn mark_native_drained(&mut self) {
        self.native_drained = true;
    }
    pub(crate) fn dispose(&mut self) -> bool {
        if !self.native_drained {
            return false;
        }
        if self.disposal.body_initialized
            && matches!(self.disposal.body, DisposalObservation::NotEntered)
        {
            let Some(cell) = self.cell.as_mut().and_then(NativeOwnedArc::get_mut) else {
                return false;
            };
            let body = cell.body.take().expect("one original backend disposal");
            // This same live cell and grant stay outside the catch. A body
            // destructor panic cannot retire either or trigger a second Drop.
            self.disposal.body.run(|| drop(body));
        }
        if self.disposal.body_initialized && !self.disposal.body.returned() {
            return false;
        }
        if self.disposal.control_allocated
            && matches!(self.disposal.control, DisposalObservation::NotEntered)
        {
            if let Some(cell) = self.cell.as_mut() {
                let Some(actual) = cell.get_mut() else {
                    return false;
                };
                self.staged_grant = actual.grant.take();
                let control = self.cell.take().expect("original backend control");
                self.disposal.control.run(|| drop(control));
            } else {
                let control = self
                    .uninitialized_cell
                    .take()
                    .expect("original uninitialized native control");
                self.disposal.control.run(|| drop(control));
            }
        }
        if self.disposal.control_allocated && !self.disposal.control.returned() {
            return false;
        }
        if matches!(self.disposal.grant, DisposalObservation::NotEntered) {
            let grant = self
                .staged_grant
                .take()
                .expect("original native grant retirement");
            self.disposal.grant.run(|| grant.retire());
        }
        self.disposal.complete()
    }
}
impl Drop for BackendOwner {
    fn drop(&mut self) {
        // Fallback never closes, retries, or publishes a retirement proof.
        if self.disposal.complete() {
            return;
        }
        let _ = self.dispose();
        if self.disposal.complete() {
            return;
        }
        if let Some(mut cell) = self.cell.take() {
            if let Some(actual) = cell.get_mut() {
                actual.retained_disposal = Some(std::mem::take(&mut self.disposal));
            }
            std::mem::forget(cell);
        }
        if let Some(grant) = self.staged_grant.take() {
            std::mem::forget(grant);
        }
        if let Some(control) = self.uninitialized_cell.take() {
            std::mem::forget(control);
        }
        std::mem::forget(std::mem::take(&mut self.disposal));
    }
}

impl SegmentGroupBackend for BackendRef {
    fn reserve_transaction(
        &self,
        plan: &crate::TransactionSpacePlan,
    ) -> Result<(), crate::TransactionReserveError> {
        self.as_ref().reserve_transaction(plan)
    }
    fn finish_transaction(&self, group: [u8; 16], batch: u64) -> io::Result<()> {
        self.as_ref().finish_transaction(group, batch)
    }
    fn cancel_transaction(&self, group: [u8; 16], batch: u64) -> io::Result<()> {
        self.as_ref().cancel_transaction(group, batch)
    }
    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.as_ref().read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.as_ref().write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.as_ref().sync_root()
    }
    fn visit_entries(&self, visit: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.as_ref().visit_entries(visit)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.as_ref().exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.as_ref().create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.as_ref().len(file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.as_ref().read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.as_ref().write(file, at, bytes)
    }
    fn set_len(&self, file: GroupFile, len: u64) -> io::Result<()> {
        self.as_ref().set_len(file, len)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.as_ref().sync(file)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.as_ref().unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.as_ref().sync_names()
    }
    fn close(&self) -> BackendCloseOutcome {
        self.as_ref().close()
    }
}

/// Consume an already staged original once. Empty stages do not manufacture
/// destructor observations; a refused or panicked observation is never replayed.
pub(crate) fn dispose_slot<T>(slot: &mut Option<T>, observation: &mut DisposalObservation) -> bool {
    match observation {
        DisposalObservation::Returned => true,
        DisposalObservation::Entered | DisposalObservation::Panicked(_) => false,
        DisposalObservation::NotEntered => {
            let Some(original) = slot.take() else {
                return true;
            };
            observation.run(|| drop(original));
            observation.returned()
        }
    }
}
