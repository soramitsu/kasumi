//! A preclaimed, paid receiver for native database constructor admission.
//! The provider grant and every original observation stay here until explicit
//! disposition. Provider callbacks and payload construction never hold metadata.
use super::*;
use crate::source_metadata::MetadataAttempt;
use kasumi_kv::TerminalObservation;
use std::{any::TypeId, convert::Infallible, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeConstructorCallError {
    ForeignProvider,
    AlreadyEntered,
    MissingBinding,
}
#[derive(Clone, Copy)]
enum Binding {
    Fresh,
    Claimed,
    Bound,
    CapacityRefused,
}
struct BindStatus {
    binding: Binding,
    rejected: Option<NativeConstructorCallError>,
}
impl BindStatus {
    const fn new() -> Self {
        Self {
            binding: Binding::Fresh,
            rejected: None,
        }
    }
    fn claim(&mut self, same: bool) -> Result<(), NativeConstructorCallError> {
        let error = self.rejected.or(if !same {
            Some(NativeConstructorCallError::ForeignProvider)
        } else if !matches!(self.binding, Binding::Fresh) {
            Some(NativeConstructorCallError::AlreadyEntered)
        } else {
            None
        });
        if let Some(error) = error {
            self.rejected.get_or_insert(error);
            return Err(error);
        }
        self.binding = Binding::Claimed;
        Ok(())
    }
}
/// Constructor-minted capability. A byte quote alone cannot create one.
/// ```compile_fail
/// let _ = kasumi_store::NativeConstructorInstall {};
/// ```
pub struct NativeConstructorInstall<'a> {
    expected: &'a Arc<dyn NodeDiskMemoryAdmission>,
    bytes: u64,
    status: &'a mut BindStatus,
    lease: &'a mut Option<DiskMemoryLease>,
}
impl NativeConstructorInstall<'_> {
    pub fn try_begin_bind(
        &mut self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<NativeConstructorPermit<'_>, NativeConstructorCallError> {
        self.status.claim(Arc::ptr_eq(self.expected, &provider))?;
        Ok(NativeConstructorPermit {
            bytes: self.bytes,
            status: self.status,
            lease: self.lease,
        })
    }
}
/// One actual provider reservation, including its concrete token allocation.
/// ```compile_fail
/// let _ = kasumi_store::NativeConstructorPermit {};
/// ```
pub struct NativeConstructorPermit<'a> {
    bytes: u64,
    status: &'a mut BindStatus,
    lease: &'a mut Option<DiskMemoryLease>,
}
impl NativeConstructorPermit<'_> {
    pub fn request_bytes(&self) -> u64 {
        self.bytes
    }
    /// Only an actual pre-grant ordinary capacity refusal supplies this witness.
    pub fn refuse_capacity(self, original: io::Error) -> io::Error {
        self.status.binding = Binding::CapacityRefused;
        original
    }
    /// Installs the actual token before the provider can continue or unwind.
    pub fn bind<T: Send + Sync + 'static>(self, token: T) {
        *self.lease = Some(DiskMemoryLease::new(token));
        self.status.binding = Binding::Bound;
    }
}

/// Closed startup child purposes; ordinary read/write requests use their own
/// admission contracts. Only the two concrete opening children implement this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeStartupChildPurpose {
    Tables,
    Verification,
}
pub(crate) trait NativeStartupChild: StoragePayload {
    const PURPOSE: NativeStartupChildPurpose;
    fn report_bytes() -> io::Result<u64>;
    fn abandon_delivery(&self);
}
fn abandon_child_delivery<T: NativeStartupChild>(payload: &dyn ErasedPayload) {
    let original: &dyn Any = payload;
    original
        .downcast_ref::<T>()
        .expect("exact closed child type")
        .abandon_delivery();
}

pub(super) struct NativeConstructorState {
    generation: u64,
    payload_type: Option<TypeId>,
    expected: Option<Arc<dyn NodeDiskMemoryAdmission>>,
    bytes: u64,
    child_purpose: Option<NativeStartupChildPurpose>,
    parent: Option<StorageOwnerId>,
    abandon_delivery: Option<fn(&dyn ErasedPayload)>,
    delivery_abandonment: MetadataAttempt<Infallible>,
    report_bytes: u64,
    report_status: BindStatus,
    report_provider: MetadataAttempt<io::Error>,
    report_lease: Option<DiskMemoryLease>,
    status: BindStatus,
    provider: MetadataAttempt<io::Error>,
    preparation: MetadataAttempt<io::Error>,
    construction: MetadataAttempt<Infallible>,
    lease_cleanup: MetadataAttempt<Infallible>,
    diagnostic_cleanup: MetadataAttempt<Infallible>,
    lease: Option<DiskMemoryLease>,
    payload: Option<Arc<dyn ErasedPayload>>,
    published: bool,
    success_returned: bool,
    retired: bool,
}
impl NativeConstructorState {
    pub(super) const fn new() -> Self {
        Self {
            generation: 0,
            payload_type: None,
            expected: None,
            bytes: 0,
            child_purpose: None,
            parent: None,
            abandon_delivery: None,
            delivery_abandonment: MetadataAttempt::new(),
            report_bytes: 0,
            report_status: BindStatus::new(),
            report_provider: MetadataAttempt::new(),
            report_lease: None,
            status: BindStatus::new(),
            provider: MetadataAttempt::new(),
            preparation: MetadataAttempt::new(),
            construction: MetadataAttempt::new(),
            lease_cleanup: MetadataAttempt::new(),
            diagnostic_cleanup: MetadataAttempt::new(),
            lease: None,
            payload: None,
            published: false,
            success_returned: false,
            retired: false,
        }
    }
    fn protocol(&self) -> Option<NativeConstructorCallError> {
        self.status
            .rejected
            .or(self.report_status.rejected)
            .or_else(|| {
                ((self.provider.succeeded() && !matches!(self.status.binding, Binding::Bound))
                    || (self.report_bytes != 0
                        && self.report_provider.succeeded()
                        && !matches!(self.report_status.binding, Binding::Bound)))
                .then_some(NativeConstructorCallError::MissingBinding)
            })
    }
    fn ready(&self) -> bool {
        self.provider.succeeded()
            && self.protocol().is_none()
            && matches!(self.status.binding, Binding::Bound)
            && self.lease.is_some()
            && (self.report_bytes == 0
                || (self.report_provider.succeeded()
                    && matches!(self.report_status.binding, Binding::Bound)))
    }
    fn run_provider(&mut self) -> bool {
        if !self.provider.pending() || !self.diagnostic_cleanup.pending() {
            return false;
        }
        let expected = self.expected.as_ref().expect("preclaimed exact provider");
        self.provider.run(|| {
            let mut install = NativeConstructorInstall {
                expected,
                bytes: self.bytes,
                status: &mut self.status,
                lease: &mut self.lease,
            };
            expected.clone().install_native_constructor(&mut install)
        });
        if self.provider.succeeded()
            && self.protocol().is_none()
            && self.lease.is_some()
            && self.report_bytes != 0
        {
            self.report_provider.run(|| {
                let mut install = NativeConstructorInstall {
                    expected,
                    bytes: self.report_bytes,
                    status: &mut self.report_status,
                    lease: &mut self.report_lease,
                };
                expected.clone().install_native_constructor(&mut install)
            });
        }
        self.ready()
    }
    fn panicked(&self) -> bool {
        matches!(self.provider, MetadataAttempt::Panicked(_))
            || matches!(self.report_provider, MetadataAttempt::Panicked(_))
            || matches!(self.preparation, MetadataAttempt::Panicked(_))
            || matches!(self.delivery_abandonment, MetadataAttempt::Panicked(_))
            || matches!(self.construction, MetadataAttempt::Panicked(_))
            || matches!(self.lease_cleanup, MetadataAttempt::Panicked(_))
            || matches!(self.diagnostic_cleanup, MetadataAttempt::Panicked(_))
    }
}
/// Borrowed original outcomes; no error, panic, grant, or payload can escape.
pub struct NativeConstructorReport<'a> {
    state: &'a NativeConstructorState,
}
impl NativeConstructorReport<'_> {
    pub fn provider(&self) -> TerminalObservation<'_, io::Error> {
        self.state.provider.view()
    }
    pub fn report_provider(&self) -> TerminalObservation<'_, io::Error> {
        self.state.report_provider.view()
    }
    pub fn parent_id(&self) -> Option<StorageOwnerId> {
        self.state.parent
    }
    pub fn report_request_bytes(&self) -> u64 {
        self.state.report_bytes
    }
    pub fn has_report_lease(&self) -> bool {
        self.state.report_lease.is_some()
    }
    pub fn delivery_abandonment(&self) -> TerminalObservation<'_, Infallible> {
        self.state.delivery_abandonment.view()
    }
    pub fn preparation(&self) -> TerminalObservation<'_, io::Error> {
        self.state.preparation.view()
    }
    pub fn construction(&self) -> TerminalObservation<'_, Infallible> {
        self.state.construction.view()
    }
    pub fn lease_cleanup(&self) -> TerminalObservation<'_, Infallible> {
        self.state.lease_cleanup.view()
    }
    pub fn diagnostic_cleanup(&self) -> TerminalObservation<'_, Infallible> {
        self.state.diagnostic_cleanup.view()
    }
    pub fn protocol(&self) -> Option<NativeConstructorCallError> {
        self.state.protocol()
    }
    pub fn capacity_refused(&self) -> bool {
        self.protocol().is_none()
            && ((matches!(self.state.status.binding, Binding::CapacityRefused)
                && matches!(self.state.provider, MetadataAttempt::Returned(Err(_))))
                || (matches!(self.state.report_status.binding, Binding::CapacityRefused)
                    && matches!(
                        self.state.report_provider,
                        MetadataAttempt::Returned(Err(_))
                    )))
            && self.state.report_lease.is_none()
            && self.state.payload.is_none()
    }
    pub fn request_bytes(&self) -> u64 {
        self.state.bytes
    }
    pub fn has_lease(&self) -> bool {
        self.state.lease.is_some()
    }
    pub fn has_payload(&self) -> bool {
        self.state.payload.is_some()
    }
}
/// A compact exact locator, deliberately excluded from generic error transport.
pub enum NativeConstructorFailure {
    Preclaim(io::Error),
    Retained(NativeConstructorCustody),
}
pub struct NativeConstructorCustody {
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    id: StorageOwnerId,
    payload_type: TypeId,
}
impl fmt::Debug for NativeConstructorFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preclaim(error) => f.debug_tuple("Preclaim").field(error).finish(),
            Self::Retained(custody) => f.debug_tuple("Retained").field(&custody.id).finish(),
        }
    }
}
impl fmt::Display for NativeConstructorFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preclaim(error) => error.fmt(f),
            Self::Retained(custody) => write!(f, "native constructor retained at {:?}", custody.id),
        }
    }
}
impl NativeConstructorFailure {
    pub fn id(&self) -> Option<StorageOwnerId> {
        match self {
            Self::Preclaim(_) => None,
            Self::Retained(custody) => Some(custody.id),
        }
    }
    pub fn with_report<R>(
        &self,
        inspect: impl FnOnce(Option<NativeConstructorReport<'_>>) -> R,
    ) -> R {
        let Self::Retained(custody) = self else {
            return inspect(None);
        };
        let census = custody.provider.storage_census();
        if census.require_provider(&custody.provider).is_err() {
            return inspect(None);
        }
        let Some(slot) = census.slots.get(custody.id.index) else {
            return inspect(None);
        };
        let Some(state) = native_state(slot) else {
            return inspect(None);
        };
        if state.generation != custody.id.generation
            || state.payload_type != Some(custody.payload_type)
        {
            return inspect(None);
        }
        inspect(Some(NativeConstructorReport { state: &state }))
    }
    pub fn is_capacity_denied(&self) -> bool {
        self.with_report(|report| report.is_some_and(|report| report.capacity_refused()))
    }
    /// Explicit acknowledgement/disposition. Dropping a locator never cleans a
    /// registered failure or implicitly credits its actual bound grant.
    pub fn cleanup(&self) -> StorageCensusDisposition {
        match self {
            Self::Preclaim(_) => StorageCensusDisposition::Stale,
            Self::Retained(custody) => custody
                .provider
                .storage_census()
                .cleanup_native_constructor(custody.id, custody.payload_type),
        }
    }
}
fn native_state(slot: &Slot) -> Option<parking_lot::MutexGuard<'_, NativeConstructorState>> {
    slot.native_constructor.try_lock()
}
impl StorageCensus {
    fn preclaim_native<T: StoragePayload>(
        &self,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        bytes: u64,
    ) -> io::Result<StorageOwnerId> {
        if T::KIND != StorageOwnerKind::Database {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.preclaim_native_bound::<T>(provider, bytes, None, None, 0, None)
    }
    fn preclaim_native_bound<T: StoragePayload>(
        &self,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        bytes: u64,
        mut parent: Option<ChildAdmission<'_>>,
        purpose: Option<NativeStartupChildPurpose>,
        report_bytes: u64,
        abandon_delivery: Option<fn(&dyn ErasedPayload)>,
    ) -> io::Result<StorageOwnerId> {
        self.require_provider(provider)?;
        if self.fenced.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        for (index, slot) in self.slots.iter().enumerate() {
            let Ok(mut metadata) = slot.metadata.try_lock() else {
                continue;
            };
            if !matches!(metadata.cell, Cell::Vacant) {
                continue;
            }
            let Some(mut state) = native_state(slot) else {
                continue;
            };
            assert!(
                state.expected.is_none()
                    && state.lease.is_none()
                    && state.report_lease.is_none()
                    && state.payload.is_none()
            );
            let generation = owner_generation()?;
            let parent = parent.take().map(ChildAdmission::publish);
            *state = NativeConstructorState::new();
            state.generation = generation;
            state.payload_type = Some(TypeId::of::<T>());
            state.expected = Some(provider.clone());
            state.bytes = bytes;
            state.child_purpose = purpose;
            state.parent = parent;
            state.abandon_delivery = abandon_delivery;
            state.report_bytes = report_bytes;
            metadata.generation = generation;
            metadata.kind = T::KIND;
            metadata.parent = parent;
            metadata.children_sealed = false;
            assert!(metadata.lease.is_none() && metadata.source.is_none());
            assert_eq!(slot.children.load(Ordering::Acquire), 0);
            slot.pending.store(NONE, Ordering::Release);
            slot.output_generation.store(generation, Ordering::Release);
            slot.output_state.store(NONE, Ordering::Release);
            slot.native_constructor_panicked
                .store(false, Ordering::Release);
            slot.native_constructor_generation
                .store(generation, Ordering::Release);
            slot.native_constructor_delivery_pending
                .store(true, Ordering::Release);
            metadata.cell = Cell::Constructing;
            return Ok(StorageOwnerId { index, generation });
        }
        Err(io::ErrorKind::WouldBlock.into())
    }
    pub(crate) fn register_native<T: StoragePayload>(
        &self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        backing: u64,
        construct: impl FnOnce(StorageOwnerId) -> T,
    ) -> Result<StorageRegistration<T>, NativeConstructorFailure> {
        let bytes = Self::registration_request_bytes::<T>(backing)
            .map_err(NativeConstructorFailure::Preclaim)?;
        let id = self
            .preclaim_native::<T>(&provider, bytes)
            .map_err(NativeConstructorFailure::Preclaim)?;
        self.construct_native(provider, id, |_| Ok(()), |_| construct(id))
    }
    /// Claim the exact child and parent count before provider dispatch. Both
    /// original grants are installed in the paid receiver before construction.
    pub(crate) fn register_native_startup_child<T: NativeStartupChild, P: StoragePayload>(
        &self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        parent: &StorageRegistration<P>,
        claimed: impl FnOnce(StorageOwnerId) -> io::Result<()>,
        construct: impl FnOnce(&mut Option<DiskMemoryLease>) -> T,
    ) -> Result<StorageRegistration<T>, NativeConstructorFailure> {
        let preclaim = || -> io::Result<StorageOwnerId> {
            self.require_provider(&parent.provider)?;
            if !Arc::ptr_eq(&provider, &parent.provider)
                || P::KIND != StorageOwnerKind::Database
                || !matches!(
                    (T::PURPOSE, T::KIND),
                    (NativeStartupChildPurpose::Tables, StorageOwnerKind::Writer)
                        | (
                            NativeStartupChildPurpose::Verification,
                            StorageOwnerKind::Reader
                        )
                )
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let parent_slot = self
                .slots
                .get(parent.id.index)
                .ok_or(io::ErrorKind::InvalidInput)?;
            let parent_metadata = parent_slot
                .metadata
                .try_lock()
                .map_err(|_| io::ErrorKind::WouldBlock)?;
            if parent_metadata.generation != parent.id.generation
                || !matches!(
                    parent_metadata.cell,
                    Cell::Active {
                        servicing: false,
                        ..
                    }
                )
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let child = self.preclaim_child_locked(parent.id, &parent_metadata)?;
            drop(parent_metadata);
            let id = self.preclaim_native_bound::<T>(
                &provider,
                Self::registration_request_bytes::<T>(0)?,
                Some(child),
                Some(T::PURPOSE),
                T::report_bytes()?,
                Some(abandon_child_delivery::<T>),
            )?;
            Ok(id)
        };
        let id = preclaim().map_err(NativeConstructorFailure::Preclaim)?;
        self.construct_native(provider, id, claimed, construct)
    }
    fn construct_native<T: StoragePayload>(
        &self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
        claimed: impl FnOnce(StorageOwnerId) -> io::Result<()>,
        construct: impl FnOnce(&mut Option<DiskMemoryLease>) -> T,
    ) -> Result<StorageRegistration<T>, NativeConstructorFailure> {
        let slot = &self.slots[id.index];
        // The receiver is independent from metadata and was admitted as part
        // of the actual initial Slot array. No late custody allocation occurs.
        let mut state = slot.native_constructor.lock();
        state.preparation.run(|| claimed(id));
        if state.preparation.succeeded() && state.run_provider() {
            state.construction = MetadataAttempt::Entered;
            match catch_unwind(AssertUnwindSafe(|| {
                Arc::new(construct(&mut state.report_lease))
            })) {
                Ok(owner) => {
                    state.payload = Some(owner);
                    state.construction = MetadataAttempt::Returned(Ok(()));
                }
                Err(original) => state.construction = MetadataAttempt::Panicked(original),
            }
        }
        slot.native_constructor_panicked
            .store(state.panicked(), Ordering::Release);
        let published = self.publish_native(slot, id, &mut state);
        if published {
            // Uses only a clone of the already installed actual owner.
            if let Some(owner) = self.retained::<T>(provider.clone(), id) {
                state.success_returned = true;
                slot.native_constructor_delivery_pending
                    .store(false, Ordering::Release);
                drop(state);
                return Ok(owner);
            }
        }
        Err(NativeConstructorFailure::Retained(
            NativeConstructorCustody {
                provider,
                id,
                payload_type: TypeId::of::<T>(),
            },
        ))
    }
    fn publish_native(
        &self,
        slot: &Slot,
        id: StorageOwnerId,
        state: &mut NativeConstructorState,
    ) -> bool {
        if state.published {
            return true;
        }
        if !state.preparation.succeeded()
            || !state.ready()
            || !state.construction.succeeded()
            || state.payload.is_none()
            || state.report_lease.is_some()
        {
            return false;
        }
        let Ok(mut metadata) = slot.metadata.try_lock() else {
            return false;
        };
        if metadata.generation != id.generation || !matches!(metadata.cell, Cell::Constructing) {
            return false;
        }
        metadata.lease = state.lease.take();
        metadata.cell = Cell::Active {
            owner: state.payload.take().unwrap(),
            servicing: false,
        };
        state.published = true;
        drop(metadata);
        // This is never the final provider reference: the current caller and
        // exact facade/locator retain it. No callback executes under metadata.
        drop(state.expected.take());
        true
    }
    pub(crate) fn retained_native_constructor<T: StoragePayload>(
        &self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
    ) -> Option<NativeConstructorFailure> {
        self.require_provider(&provider).ok()?;
        let slot = self.slots.get(id.index)?;
        let metadata = slot.metadata.try_lock().ok()?;
        if metadata.generation != id.generation || matches!(metadata.cell, Cell::Vacant) {
            return None;
        }
        let state = native_state(slot)?;
        if state.generation != id.generation
            || state.payload_type != Some(TypeId::of::<T>())
            || state.retired
            || state.success_returned
            || (state.preparation.pending()
                && state.provider.pending()
                && state.diagnostic_cleanup.pending())
        {
            return None;
        }
        Some(NativeConstructorFailure::Retained(
            NativeConstructorCustody {
                provider,
                id,
                payload_type: TypeId::of::<T>(),
            },
        ))
    }
    fn cleanup_native_constructor(
        &self,
        id: StorageOwnerId,
        payload_type: TypeId,
    ) -> StorageCensusDisposition {
        self.cleanup_native_constructor_after_drain(id, payload_type, || {})
    }
    fn cleanup_native_constructor_after_drain(
        &self,
        id: StorageOwnerId,
        payload_type: TypeId,
        after_drain: impl FnOnce(),
    ) -> StorageCensusDisposition {
        let Some(slot) = self.slots.get(id.index) else {
            return StorageCensusDisposition::Stale;
        };
        // IDs here were minted by this slot's native claim; they cannot be
        // forged through the public custody API. Every reuse requires Vacant,
        // reached only after positive original diagnostic/body/grant retirement.
        // Thus a later native retirement in this same slot also proves this
        // earlier issued generation retired. An arbitrary Stale never does.
        if slot
            .native_constructor_retired_generation
            .load(Ordering::Acquire)
            >= id.generation
        {
            return StorageCensusDisposition::Retired;
        }
        let Some(mut state) = native_state(slot) else {
            return StorageCensusDisposition::Retained;
        };
        if state.generation != id.generation || state.payload_type != Some(payload_type) {
            return StorageCensusDisposition::Stale;
        }
        if state.retired {
            return StorageCensusDisposition::Retired;
        }
        if state.payload.is_some() || state.published {
            if !state.success_returned
                && let Some(abandon) = state.abandon_delivery
            {
                if !state.delivery_abandonment.pending() && !state.delivery_abandonment.succeeded()
                {
                    return StorageCensusDisposition::Retained;
                }
                if state.delivery_abandonment.pending() {
                    // The request reserved a real delivery obligation before
                    // publication. A failed delivery must retire it exactly once,
                    // including when the original Arc is already in metadata.
                    let payload = if let Some(payload) = &state.payload {
                        payload.clone()
                    } else {
                        let Ok(metadata) = slot.metadata.try_lock() else {
                            return StorageCensusDisposition::Retained;
                        };
                        if metadata.generation != id.generation {
                            return StorageCensusDisposition::Stale;
                        }
                        let Cell::Active { owner, .. } = &metadata.cell else {
                            return StorageCensusDisposition::Retained;
                        };
                        owner.clone()
                    };
                    state.delivery_abandonment.run(|| {
                        abandon(payload.as_ref());
                        Ok(())
                    });
                    drop(payload);
                    slot.native_constructor_panicked
                        .store(state.panicked(), Ordering::Release);
                    if !state.delivery_abandonment.succeeded() {
                        self.fenced.store(true, Ordering::Release);
                        return StorageCensusDisposition::Retained;
                    }
                }
            }
            // Publication retry retains the same Arc and grant. Cleanup then
            // uses the ordinary real drive/destruction/lease census pipeline.
            if !self.publish_native(slot, id, &mut state) {
                return StorageCensusDisposition::Retained;
            }
            slot.native_constructor_delivery_pending
                .store(false, Ordering::Release);
            drop(state);
            let mut disposition = self.drain_owner(id);
            if disposition == StorageCensusDisposition::Stale
                && slot
                    .native_constructor_retired_generation
                    .load(Ordering::Acquire)
                    >= id.generation
            {
                disposition = StorageCensusDisposition::Retired;
            }
            if disposition == StorageCensusDisposition::Retired {
                // Metadata is already released: this vacant slot may have
                // been reused and retired again. Never replace that later
                // exact receipt with this delayed, older generation.
                // Production supplies a no-op; tests pause this real tail.
                after_drain();
                slot.native_constructor_retired_generation
                    .fetch_max(id.generation, Ordering::Release);
                if let Some(mut state) = native_state(slot)
                    && state.generation == id.generation
                {
                    state.retired = true;
                }
            }
            return disposition;
        }
        if state.preparation.pending()
            && state.provider.pending()
            && state.diagnostic_cleanup.pending()
        {
            return StorageCensusDisposition::Retained;
        }
        let NativeConstructorState {
            diagnostic_cleanup,
            provider,
            construction,
            report_provider,
            preparation,
            ..
        } = &mut *state;
        diagnostic_cleanup.run(|| {
            drop(std::mem::replace(provider, MetadataAttempt::new()));
            drop(std::mem::replace(construction, MetadataAttempt::new()));
            drop(std::mem::replace(report_provider, MetadataAttempt::new()));
            drop(std::mem::replace(preparation, MetadataAttempt::new()));
            Ok(())
        });
        slot.native_constructor_panicked
            .store(state.panicked(), Ordering::Release);
        if !state.diagnostic_cleanup.succeeded() {
            return StorageCensusDisposition::Retained;
        }
        let NativeConstructorState {
            lease_cleanup,
            lease,
            report_lease,
            ..
        } = &mut *state;
        lease_cleanup.run(|| {
            drop(report_lease.take());
            drop(lease.take());
            Ok(())
        });
        if !state.lease_cleanup.succeeded() {
            self.fenced.store(true, Ordering::Release);
            slot.native_constructor_panicked
                .store(state.panicked(), Ordering::Release);
            return StorageCensusDisposition::Retained;
        }
        let Ok(mut metadata) = slot.metadata.try_lock() else {
            return StorageCensusDisposition::Retained;
        };
        if metadata.generation != id.generation || !matches!(metadata.cell, Cell::Constructing) {
            return StorageCensusDisposition::Stale;
        }
        assert!(state.lease.is_none() && state.report_lease.is_none() && state.payload.is_none());
        metadata.cell = Cell::Vacant;
        slot.native_constructor_delivery_pending
            .store(false, Ordering::Release);
        if let Some(parent) = metadata.parent.take() {
            let previous = self.slots[parent.index]
                .children
                .fetch_sub(1, Ordering::AcqRel);
            assert_ne!(
                previous, 0,
                "exact native child releases parent only after lease retirement"
            );
        }
        state.retired = true;
        slot.native_constructor_retired_generation
            .fetch_max(id.generation, Ordering::Release);
        drop(metadata);
        drop(state.expected.take());
        StorageCensusDisposition::Retired
    }
}

#[cfg(any(test, feature = "test-utils"))]
struct ProbePayload;
#[cfg(any(test, feature = "test-utils"))]
impl StoragePayload for ProbePayload {
    const KIND: StorageOwnerKind = StorageOwnerKind::Database;
    fn drive(&self) -> bool {
        true
    }
}
/// Tests use the actual closed fixed receiver and provider admission path.
#[cfg(any(test, feature = "test-utils"))]
pub struct NativeConstructorProbe {
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    id: StorageOwnerId,
}
#[cfg(any(test, feature = "test-utils"))]
impl NativeConstructorProbe {
    pub fn prepare(provider: Arc<dyn NodeDiskMemoryAdmission>, bytes: u64) -> io::Result<Self> {
        let id = provider
            .storage_census()
            .preclaim_native::<ProbePayload>(&provider, bytes)?;
        Ok(Self { provider, id })
    }
    pub fn run(&self) -> bool {
        let slot = &self.provider.storage_census().slots[self.id.index];
        let mut state = slot.native_constructor.lock();
        if state.generation != self.id.generation
            || state.payload_type != Some(TypeId::of::<ProbePayload>())
            || state.retired
        {
            return false;
        }
        let ready = state.run_provider();
        slot.native_constructor_panicked
            .store(state.panicked(), Ordering::Release);
        ready
    }
    pub fn run_provider_again_for_test(&self) -> bool {
        self.run()
    }
    pub fn with_report<R>(&self, inspect: impl FnOnce(NativeConstructorReport<'_>) -> R) -> R {
        let slot = &self.provider.storage_census().slots[self.id.index];
        let state = slot.native_constructor.lock();
        if state.generation != self.id.generation
            || state.payload_type != Some(TypeId::of::<ProbePayload>())
        {
            drop(state);
            panic!("stale native constructor probe");
        }
        inspect(NativeConstructorReport { state: &state })
    }
    pub fn cleanup(&self) -> StorageCensusDisposition {
        self.provider
            .storage_census()
            .cleanup_native_constructor(self.id, TypeId::of::<ProbePayload>())
    }
}

#[cfg(test)]
#[path = "storage_census_native_constructor_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "native_constructor_receiver_ownership_tests.rs"]
mod receiver_ownership_tests;
