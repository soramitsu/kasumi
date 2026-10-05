//! Fixed custody owned by the exact installed memory provider.
//!
//! Each occupied cell owns its own resident lease, separate from its actual
//! payload. Initial provider bookkeeping admits the complete fixed slot array.
//! Owner backing is not a bound for index versions, transactions, callback workspaces
//! or opaque diagnostics; those need their own concrete workspace plans.
use crate::{DiskMemoryLease, NodeDiskMemoryAdmission, disk_memory};
use std::{
    alloc::Layout,
    any::Any,
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
};
type Panic = Box<dyn Any + Send>;

#[path = "storage_census_source.rs"]
mod source;
pub(crate) use source::{SourceCellClaim, SourceCensusExchange};
use source::{SourceClass, SourceSlot};
#[path = "storage_census_native_constructor.rs"]
mod native_constructor;
#[cfg(any(test, feature = "test-utils"))]
pub use native_constructor::NativeConstructorProbe;
pub use native_constructor::{
    NativeConstructorCallError, NativeConstructorCustody, NativeConstructorFailure,
    NativeConstructorInstall, NativeConstructorPermit, NativeConstructorReport,
};
pub(crate) use native_constructor::{NativeStartupChild, NativeStartupChildPurpose};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageOwnerKind {
    Database,
    Reader,
    Writer,
    /// One multi-file NodeDisk owner of a segmented log: its root, directory
    /// and bounded descriptor cache, including failed-close owners it keeps.
    /// It may be a database's exact child.
    SegmentGroup,
    /// Fixed registered control for the source publication pool.
    SourcePool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageOwnerId {
    index: usize,
    generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageCensusDisposition {
    Retained,
    Retired,
    Stale,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageCensusPanicPhase {
    Construction,
    Drive,
    PayloadDisposal,
    LeaseRetirement,
    SourceHoldRetirement,
    SourceControlRetirement,
    WriteOutputDisposal,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StorageCensusSnapshot {
    pub capacity: usize,
    pub databases: usize,
    pub readers: usize,
    pub writers: usize,
    pub segment_groups: usize,
    pub source_pools: usize,
    pub source_reserved: usize,
    pub source_active: usize,
    pub source_history: usize,
    pub source_replacements: usize,
    pub servicing: usize,
    pub retained_panics: usize,
    pub fenced: bool,
}

/// Only the store's concrete owners implement this contract. Drive uses
/// nonblocking access to actual resources. True witnesses their positive
/// disposal; it does not witness disposal of this owner's backing or diagnostics.
pub(crate) trait StoragePayload: Send + Sync + 'static {
    const KIND: StorageOwnerKind;
    fn drive(&self) -> bool;
}
trait ErasedPayload: Any + Send + Sync {
    fn drive(&self) -> bool;
    fn try_dispose(self: Arc<Self>) -> Disposal;
}
enum Disposal {
    StillOwned(Arc<dyn ErasedPayload>),
    Disposed,
    Panicked(Panic),
}
impl<T: StoragePayload> ErasedPayload for T {
    fn drive(&self) -> bool {
        StoragePayload::drive(self)
    }
    fn try_dispose(self: Arc<Self>) -> Disposal {
        match Arc::try_unwrap(self) {
            Err(owner) => Disposal::StillOwned(owner),
            Ok(payload) => {
                // No Weak or raw Arc capability escapes this census. The
                // actual control block has retired before payload destruction.
                match catch_unwind(AssertUnwindSafe(|| drop(payload))) {
                    Ok(()) => Disposal::Disposed,
                    Err(payload) => Disposal::Panicked(payload),
                }
            }
        }
    }
}
enum Cell {
    Vacant,
    Constructing,
    Active {
        owner: Arc<dyn ErasedPayload>,
        servicing: bool,
    },
    Disposing,
    RetiringLease,
    SourceControl {
        servicing: bool,
    },
    SourceReserved,
    RetiringSourceHold,
    Retained,
}
struct Metadata {
    generation: u64,
    kind: StorageOwnerKind,
    // Survives payload disposal so a parent retry can find this exact child.
    parent: Option<StorageOwnerId>,
    cell: Cell,
    lease: Option<DiskMemoryLease>,
    source: Option<SourceSlot>,
}
struct OriginalPanic {
    generation: u64,
    phase: StorageCensusPanicPhase,
    payload: Mutex<Panic>,
}
// Every effectful stage has a fixed scalar completion slot. A post-effect
// try_lock failure returns Retained without losing its actual owner or result.
const NONE: u8 = 0;
const DRIVE_BUSY: u8 = 1;
const DRIVE_SETTLED: u8 = 2;
const PANICKED: u8 = 3;
const PAYLOAD_DISPOSED: u8 = 4;
const LEASE_RETIRED: u8 = 5;
const UNEXPECTED_SHARED: u8 = 6;
const SOURCE_HOLD_RETIRED: u8 = 7;
const OUTPUT_PENDING: u8 = 1;
const OUTPUT_ENTERED: u8 = 2;
const OUTPUT_DISPOSED: u8 = 3;
const OUTPUT_RELEASED: u8 = 4;
const OUTPUT_HANDED_OFF: u8 = 5;
const OUTPUT_PANICKED: u8 = 6;
struct Slot {
    native_constructor: parking_lot::Mutex<native_constructor::NativeConstructorState>,
    native_constructor_panicked: AtomicBool,
    native_constructor_retired_generation: AtomicU64,
    native_constructor_generation: AtomicU64,
    native_constructor_delivery_pending: AtomicBool,
    metadata: Mutex<Metadata>,
    pending: AtomicU8,
    source_completion: AtomicU8,
    // Published only after actual source Hold/lease/cell retirement and the
    // parent decrement. Per-slot generations increase; later reuse cannot
    // erase an earlier positive outcome still awaited by its unique claim.
    source_retired_generation: AtomicU64,
    source_control: Mutex<source::SourceControlState>,
    // An exact parent's cell cannot retire while any child cell or lease lives.
    children: AtomicUsize,
    // Once installed, an original panic makes the cell permanently retained;
    // successful retirement/reuse therefore never needs to reset this OnceLock.
    panic: OnceLock<OriginalPanic>,
    // Paid in the initial actual slot array. A synchronous writer reserves
    // this second observation before native begin; no failure grant is needed
    // after its payload or original opaque lease has already left the cell.
    output_generation: AtomicU64,
    output_state: AtomicU8,
    output_panic: OnceLock<OriginalPanic>,
    payload_retired_generation: AtomicU64,
    lease_retired_generation: AtomicU64,
    #[cfg(test)]
    after_write_lease_retirement: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    unexpected_shared: OnceLock<Arc<dyn ErasedPayload>>,
}

/// Allocate after admitting required_bytes in provider bookkeeping; bind the
/// exact provider before publishing it. There is no optional or lazy census.
pub struct StorageCensus {
    provider: AtomicPtr<()>,
    fenced: AtomicBool,
    slots: Box<[Slot]>,
}
// An owner ID may cross a foreign transport boundary without its typed facade.
// Mint process-wide generations so a different provider's same-index cell can
// never alias that exact identity. Zero remains the never-installed sentinel.
static NEXT_OWNER_GENERATION: AtomicU64 = AtomicU64::new(0);
fn owner_generation() -> io::Result<u64> {
    NEXT_OWNER_GENERATION
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map(|previous| previous + 1)
        .map_err(|_| io::ErrorKind::Other.into())
}
impl StorageCensus {
    pub fn required_bytes(capacity: usize) -> io::Result<u64> {
        if capacity == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Layout::array::<Slot>(capacity).map_err(|_| disk_memory::overflow())?;
        disk_memory::allocation::<Slot>(
            u64::try_from(capacity).map_err(|_| disk_memory::overflow())?,
        )
    }
    pub fn allocate(capacity: usize) -> io::Result<Self> {
        Self::required_bytes(capacity)?;
        let mut slots = Box::<[Slot]>::new_uninit_slice(capacity);
        for slot in &mut slots {
            let metadata = Mutex::new(Metadata {
                generation: 0,
                kind: StorageOwnerKind::Database,
                parent: None,
                cell: Cell::Vacant,
                lease: None,
                source: None,
            });
            drop(metadata.lock().unwrap());
            slot.write(Slot {
                native_constructor: parking_lot::Mutex::new(
                    native_constructor::NativeConstructorState::new(),
                ),
                native_constructor_panicked: AtomicBool::new(false),
                native_constructor_retired_generation: AtomicU64::new(0),
                native_constructor_generation: AtomicU64::new(0),
                native_constructor_delivery_pending: AtomicBool::new(false),
                metadata,
                pending: AtomicU8::new(NONE),
                source_completion: AtomicU8::new(source::EXCHANGE_NONE),
                source_retired_generation: AtomicU64::new(0),
                source_control: Mutex::new(source::SourceControlState::new()),
                children: AtomicUsize::new(0),
                panic: OnceLock::new(),
                output_generation: AtomicU64::new(0),
                output_state: AtomicU8::new(NONE),
                output_panic: OnceLock::new(),
                payload_retired_generation: AtomicU64::new(0),
                lease_retired_generation: AtomicU64::new(0),
                #[cfg(test)]
                after_write_lease_retirement: Mutex::new(None),
                unexpected_shared: OnceLock::new(),
            });
        }
        // SAFETY: all elements are initialized before assume_init. Each loop
        // iteration uses only fixed inline constructors and an unshared mutex.
        let slots = unsafe { slots.assume_init() };
        Ok(Self {
            provider: AtomicPtr::new(std::ptr::null_mut()),
            fenced: AtomicBool::new(false),
            slots,
        })
    }
    pub fn bind_provider(&self, provider: &Arc<dyn NodeDiskMemoryAdmission>) -> io::Result<()> {
        if !std::ptr::eq(self, provider.storage_census()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let identity = Arc::as_ptr(provider).cast::<()>().cast_mut();
        self.provider
            .compare_exchange(
                std::ptr::null_mut(),
                identity,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| io::Error::from(io::ErrorKind::AlreadyExists))?;
        Ok(())
    }
    fn require_provider(&self, provider: &Arc<dyn NodeDiskMemoryAdmission>) -> io::Result<()> {
        if !std::ptr::eq(self, provider.storage_census())
            || self.provider.load(Ordering::Acquire)
                != Arc::as_ptr(provider).cast::<()>().cast_mut()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
    /// Telemetry only. Drain itself always uses the nonblocking snapshot below.
    /// Original observation guards never own any of these metadata mutexes.
    pub fn snapshot(&self) -> StorageCensusSnapshot {
        let mut snapshot = StorageCensusSnapshot {
            capacity: self.slots.len(),
            ..Default::default()
        };
        for slot in &self.slots {
            let metadata = slot.metadata.lock().unwrap_or_else(|poisoned| {
                self.fenced.store(true, Ordering::Release);
                poisoned.into_inner()
            });
            Self::count(&mut snapshot, slot, &metadata);
        }
        snapshot.fenced = self.fenced.load(Ordering::Acquire);
        snapshot
    }
    pub fn try_snapshot(&self) -> Option<StorageCensusSnapshot> {
        let mut snapshot = StorageCensusSnapshot {
            capacity: self.slots.len(),
            ..Default::default()
        };
        for slot in &self.slots {
            let metadata = slot.metadata.try_lock().ok()?;
            Self::count(&mut snapshot, slot, &metadata);
        }
        snapshot.fenced = self.fenced.load(Ordering::Acquire);
        Some(snapshot)
    }
    fn count(snapshot: &mut StorageCensusSnapshot, slot: &Slot, metadata: &Metadata) {
        if matches!(metadata.cell, Cell::Vacant) {
            return;
        }
        match metadata.kind {
            StorageOwnerKind::Database => snapshot.databases += 1,
            StorageOwnerKind::Reader => snapshot.readers += 1,
            StorageOwnerKind::Writer => snapshot.writers += 1,
            StorageOwnerKind::SegmentGroup => snapshot.segment_groups += 1,
            StorageOwnerKind::SourcePool => snapshot.source_pools += 1,
        }
        if let Some(source) = &metadata.source {
            match source.class {
                SourceClass::ProtectedVacant => snapshot.source_reserved += 1,
                SourceClass::ProtectedActive => snapshot.source_active += 1,
                SourceClass::OrdinaryHistory => snapshot.source_history += 1,
                SourceClass::ReplacementHeld => snapshot.source_replacements += 1,
                SourceClass::Releasing => {}
            }
        }
        let servicing = matches!(
            metadata.cell,
            Cell::Constructing
                | Cell::Disposing
                | Cell::RetiringLease
                | Cell::Active {
                    servicing: true,
                    ..
                }
        );
        let servicing = servicing
            || matches!(
                metadata.cell,
                Cell::RetiringSourceHold | Cell::SourceControl { servicing: true }
            );
        if servicing {
            snapshot.servicing += 1;
        }
        if slot.native_constructor_panicked.load(Ordering::Acquire) {
            snapshot.retained_panics += 1;
        }
        if slot.panic.get().is_some() {
            snapshot.retained_panics += 1;
        }
        if slot.output_panic.get().is_some() {
            snapshot.retained_panics += 1;
        }
    }
    pub fn owner_at(&self, index: usize) -> Option<StorageOwnerId> {
        let metadata = self.slots.get(index)?.metadata.try_lock().ok()?;
        (!matches!(metadata.cell, Cell::Vacant)).then_some(StorageOwnerId {
            index,
            generation: metadata.generation,
        })
    }
    pub(crate) fn capacity(&self) -> usize {
        self.slots.len()
    }

    #[cfg(test)]
    pub(crate) fn child_count_for_test(&self, id: StorageOwnerId) -> Option<usize> {
        let slot = self.slots.get(id.index)?;
        let metadata = slot.metadata.try_lock().ok()?;
        (metadata.generation == id.generation && !matches!(metadata.cell, Cell::Vacant))
            .then(|| slot.children.load(Ordering::Acquire))
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn with_owner_metadata_held_for_test<R>(
        &self,
        id: StorageOwnerId,
        work: impl FnOnce() -> R,
    ) -> R {
        let slot = self.slots.get(id.index).expect("existing owner slot");
        let metadata = slot.metadata.lock().unwrap();
        assert_eq!(metadata.generation, id.generation);
        let result = work();
        drop(metadata);
        result
    }
    /// The original Send-only payload has its own fixed mutex. A retained
    /// observation cannot hold census metadata or prevent another owner draining.
    pub fn observation(&self, id: StorageOwnerId) -> Option<StorageCensusObservation<'_>> {
        let original = self.slots.get(id.index)?.panic.get()?;
        if original.generation != id.generation {
            return None;
        }
        let payload = match original.payload.try_lock() {
            Ok(payload) => payload,
            Err(std::sync::TryLockError::WouldBlock) => return None,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        };
        Some(StorageCensusObservation {
            phase: original.phase,
            payload,
        })
    }
    pub(crate) fn write_output_observation(
        &self,
        id: StorageOwnerId,
    ) -> Option<StorageWriteOutputObservation<'_>> {
        let slot = self.slots.get(id.index)?;
        if slot.output_generation.load(Ordering::Acquire) != id.generation {
            return None;
        }
        let state = slot.output_state.load(Ordering::Acquire);
        let payload = if state == OUTPUT_PANICKED {
            let original = slot.output_panic.get()?;
            if original.generation != id.generation {
                return None;
            }
            Some(
                original
                    .payload
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            )
        } else {
            None
        };
        Some(StorageWriteOutputObservation { state, payload })
    }
    /// Both destructive callbacks returned cleanly for this exact generation.
    /// Neither busy metadata nor a prior drive result supplies this witness.
    pub(crate) fn write_retirement_completed(&self, id: StorageOwnerId) -> bool {
        self.slots.get(id.index).is_some_and(|slot| {
            slot.output_generation.load(Ordering::Acquire) == id.generation
                && slot.payload_retired_generation.load(Ordering::Acquire) == id.generation
                && slot.lease_retired_generation.load(Ordering::Acquire) == id.generation
                && slot.panic.get().is_none()
                && slot.output_panic.get().is_none()
        })
    }
    /// Output handoff is permitted only by the exact positive destruction and
    /// lease-callback witness. The now-clean metadata tail remains retryable.
    pub(crate) fn hand_off_write_output(&self, id: StorageOwnerId) -> bool {
        if !self.write_retirement_completed(id) {
            return false;
        }
        let slot = &self.slots[id.index];
        if slot
            .output_state
            .compare_exchange(
                OUTPUT_PENDING,
                OUTPUT_HANDED_OFF,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        let _ = self.drain_owner(id);
        true
    }
    /// One real synchronous disposal under a preinstalled exact slot. The
    /// original native/lease panic and this second original remain separate.
    pub(crate) fn dispose_write_output<T>(&self, id: StorageOwnerId, output: T) {
        let slot = self
            .slots
            .get(id.index)
            .expect("registered write output slot");
        assert_eq!(
            slot.output_generation.load(Ordering::Acquire),
            id.generation
        );
        assert!(
            slot.output_state
                .compare_exchange(
                    OUTPUT_PENDING,
                    OUTPUT_ENTERED,
                    Ordering::AcqRel,
                    Ordering::Acquire
                )
                .is_ok(),
            "one output disposition per registered write"
        );
        match catch_unwind(AssertUnwindSafe(|| drop(output))) {
            Ok(()) => slot.output_state.store(OUTPUT_DISPOSED, Ordering::Release),
            Err(payload) => {
                assert!(
                    slot.output_panic
                        .set(OriginalPanic {
                            generation: id.generation,
                            phase: StorageCensusPanicPhase::WriteOutputDisposal,
                            payload: Mutex::new(payload),
                        })
                        .is_ok()
                );
                slot.output_state.store(OUTPUT_PANICKED, Ordering::Release);
            }
        }
    }
    pub(crate) fn release_disposed_write_output(&self, id: StorageOwnerId) {
        let Some(slot) = self.slots.get(id.index) else {
            return;
        };
        if slot.output_generation.load(Ordering::Acquire) == id.generation {
            let _ = slot.output_state.compare_exchange(
                OUTPUT_DISPOSED,
                OUTPUT_RELEASED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
    pub(crate) fn release_unentered_write_output(&self, id: StorageOwnerId) {
        let Some(slot) = self.slots.get(id.index) else {
            return;
        };
        if slot.output_generation.load(Ordering::Acquire) == id.generation {
            let _ = slot.output_state.compare_exchange(
                OUTPUT_PENDING,
                OUTPUT_HANDED_OFF,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
    fn record_panic(
        slot: &Slot,
        id: StorageOwnerId,
        phase: StorageCensusPanicPhase,
        payload: Panic,
    ) {
        // This slot has one servicing owner, and every first panic is terminal.
        // No later stage is dispatched after it; observation only calls get.
        let original = OriginalPanic {
            generation: id.generation,
            phase,
            payload: Mutex::new(payload),
        };
        assert!(
            slot.panic.set(original).is_ok(),
            "one terminal original per census slot"
        );
        slot.pending.store(PANICKED, Ordering::Release);
    }
    /// Charge and publish a concrete owner before dispatch. The private store
    /// constructors perform only allocation/inline initialization; no storage,
    /// user callback, writer wait or destructor may occur inside the constructor.
    pub(crate) fn register<T: StoragePayload>(
        &self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        backing_bytes: u64,
        construct: impl FnOnce() -> T,
    ) -> io::Result<StorageRegistration<T>> {
        self.register_inner(provider, backing_bytes, None, false, construct)
    }
    /// A child keeps its exact parent's census generation charged until its
    /// own payload, lease, and cell have all retired. The borrowed registration
    /// prevents parent disposal while the child is being published.
    pub(crate) fn register_child<T: StoragePayload, P: StoragePayload>(
        &self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        backing_bytes: u64,
        parent: &StorageRegistration<P>,
        construct: impl FnOnce() -> T,
    ) -> io::Result<StorageRegistration<T>> {
        self.register_child_inner(provider, backing_bytes, parent, false, construct)
    }
    pub(crate) fn register_write_child<T: StoragePayload, P: StoragePayload>(
        &self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        backing_bytes: u64,
        parent: &StorageRegistration<P>,
        construct: impl FnOnce() -> T,
    ) -> io::Result<StorageRegistration<T>> {
        if T::KIND != StorageOwnerKind::Writer {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.register_child_inner(provider, backing_bytes, parent, true, construct)
    }
    fn register_child_inner<T: StoragePayload, P: StoragePayload>(
        &self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        backing_bytes: u64,
        parent: &StorageRegistration<P>,
        output: bool,
        construct: impl FnOnce() -> T,
    ) -> io::Result<StorageRegistration<T>> {
        self.require_provider(&parent.provider)?;
        if !Arc::ptr_eq(&provider, &parent.provider)
            || P::KIND != StorageOwnerKind::Database
            || T::KIND == StorageOwnerKind::Database
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let slot = self
            .slots
            .get(parent.id.index)
            .ok_or(io::ErrorKind::InvalidInput)?;
        // Registration is pre-effect. Wait for a short census observation or
        // another admission instead of failing an ordinary storage read.
        let metadata = slot.metadata.lock().map_err(|_| {
            self.fenced.store(true, Ordering::Release);
            io::ErrorKind::InvalidData
        })?;
        if metadata.generation != parent.id.generation
            || !matches!(metadata.cell, Cell::Active { .. })
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        drop(metadata);
        self.register_inner(provider, backing_bytes, Some(parent.id), output, construct)
    }
    pub(crate) fn registration_request_bytes<T: StoragePayload>(backing: u64) -> io::Result<u64> {
        disk_memory::add(disk_memory::arc::<T>()?, backing)
    }
    fn register_inner<T: StoragePayload>(
        &self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        backing_bytes: u64,
        parent: Option<StorageOwnerId>,
        output: bool,
        construct: impl FnOnce() -> T,
    ) -> io::Result<StorageRegistration<T>> {
        if matches!(
            T::KIND,
            StorageOwnerKind::SourcePool | StorageOwnerKind::Database
        ) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.require_provider(&provider)?;
        if self.fenced.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let lease = provider
            .clone()
            .reserve_installed(Self::registration_request_bytes::<T>(backing_bytes)?)?;
        for (index, slot) in self.slots.iter().enumerate() {
            let Ok(mut metadata) = slot.metadata.try_lock() else {
                continue;
            };
            if !matches!(metadata.cell, Cell::Vacant) {
                continue;
            }
            assert_eq!(slot.children.load(Ordering::Acquire), 0);
            let generation = owner_generation()?;
            let id = StorageOwnerId { index, generation };
            if let Some(parent) = parent {
                self.slots[parent.index]
                    .children
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                        value.checked_add(1)
                    })
                    .map_err(|_| io::ErrorKind::Other)?;
            }
            metadata.generation = generation;
            metadata.kind = T::KIND;
            metadata.parent = parent;
            slot.output_generation.store(generation, Ordering::Release);
            slot.output_state.store(
                if output { OUTPUT_PENDING } else { NONE },
                Ordering::Release,
            );
            metadata.lease = Some(lease);
            debug_assert!(metadata.source.is_none());
            metadata.cell = Cell::Constructing;
            // Effect-free construction/publication is the only allocation held
            // under this short metadata guard. Storage dispatch happens later.
            match catch_unwind(AssertUnwindSafe(|| Arc::new(construct()))) {
                Ok(owner) => {
                    metadata.cell = Cell::Active {
                        owner: owner.clone(),
                        servicing: false,
                    };
                    drop(metadata);
                    return Ok(StorageRegistration {
                        provider,
                        id,
                        owner,
                    });
                }
                Err(payload) => {
                    Self::record_panic(slot, id, StorageCensusPanicPhase::Construction, payload);
                    metadata.cell = Cell::Retained;
                    return Err(io::ErrorKind::Other.into());
                }
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
    }
    /// Recover only a typed facade to the already-installed exact owner. This
    /// allocates no owner/control block, dispatches no work, and exposes no Weak.
    pub(crate) fn retained<T: StoragePayload>(
        &self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
    ) -> Option<StorageRegistration<T>> {
        match self.try_retained(provider, id) {
            TypedOwnerLookup::Active(owner) => Some(owner),
            TypedOwnerLookup::Busy | TypedOwnerLookup::Missing => None,
        }
    }

    pub(crate) fn try_retained<T: StoragePayload>(
        &self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
    ) -> TypedOwnerLookup<T> {
        if self.require_provider(&provider).is_err() {
            return TypedOwnerLookup::Missing;
        }
        let Some(slot) = self.slots.get(id.index) else {
            return TypedOwnerLookup::Missing;
        };
        let Ok(metadata) = slot.metadata.try_lock() else {
            return TypedOwnerLookup::Busy;
        };
        if metadata.generation != id.generation {
            return TypedOwnerLookup::Missing;
        }
        let Cell::Active { owner, .. } = &metadata.cell else {
            return if matches!(metadata.cell, Cell::Vacant) {
                TypedOwnerLookup::Missing
            } else {
                TypedOwnerLookup::Busy
            };
        };
        let erased: Arc<dyn Any + Send + Sync> = owner.clone();
        let Ok(owner) = Arc::downcast::<T>(erased) else {
            return TypedOwnerLookup::Missing;
        };
        TypedOwnerLookup::Active(StorageRegistration {
            provider,
            id,
            owner,
        })
    }
    /// Advance only exact children whose payload has already left the cell.
    /// Active children keep their facade/report rules; an unavailable metadata
    /// guard simply leaves the parent's outstanding count positive for retry.
    pub(crate) fn drain_disposed_children(&self, parent: StorageOwnerId) {
        for (index, slot) in self.slots.iter().enumerate() {
            let id = {
                let Ok(metadata) = slot.metadata.try_lock() else {
                    continue;
                };
                let payload_disposed =
                    matches!(metadata.cell, Cell::Disposing | Cell::RetiringLease);
                let payload_disposed =
                    payload_disposed || matches!(metadata.cell, Cell::RetiringSourceHold);
                if metadata.parent != Some(parent) || !payload_disposed {
                    continue;
                }
                StorageOwnerId {
                    index,
                    generation: metadata.generation,
                }
            };
            let _ = self.drain_owner(id);
        }
    }
    /// One actual owner; all post-effect bookkeeping uses try_lock. When busy,
    /// the original completion remains in this fixed slot for a later call.
    /// Read-only terminal observation for a token already minted after actual
    /// native completion. This grants no retirement or acknowledgment authority.
    pub(crate) fn retirement_is_terminal(&self, id: StorageOwnerId) -> bool {
        self.fenced.load(Ordering::Acquire)
            || self.slots.get(id.index).is_some_and(|slot| {
                slot.panic
                    .get()
                    .is_some_and(|panic| panic.generation == id.generation)
                    || slot.pending.load(Ordering::Acquire) == UNEXPECTED_SHARED
            })
    }

    pub fn drain_owner(&self, id: StorageOwnerId) -> StorageCensusDisposition {
        let Some(slot) = self.slots.get(id.index) else {
            return StorageCensusDisposition::Stale;
        };
        if slot.children.load(Ordering::Acquire) != 0 {
            // An already disposed child has no typed payload to recover. A
            // parent-only retirement retry must still be able to finish its
            // exact child lease before considering parent disposal.
            self.drain_disposed_children(id);
        }
        // At most drive, payload disposal and lease retirement run in one pass.
        for _ in 0..4 {
            let Ok(mut metadata) = slot.metadata.try_lock() else {
                return StorageCensusDisposition::Retained;
            };
            if metadata.generation != id.generation || matches!(metadata.cell, Cell::Vacant) {
                return StorageCensusDisposition::Stale;
            }
            if slot.native_constructor_generation.load(Ordering::Acquire) == id.generation
                && slot
                    .native_constructor_delivery_pending
                    .load(Ordering::Acquire)
            {
                return StorageCensusDisposition::Retained;
            }
            let pending = slot.pending.load(Ordering::Acquire);
            if source::exchange_blocks(slot, &metadata) {
                return StorageCensusDisposition::Retained;
            }
            if self.fenced.load(Ordering::Acquire)
                || pending == PANICKED
                || pending == UNEXPECTED_SHARED
                || slot.output_state.load(Ordering::Acquire) == OUTPUT_PANICKED
            {
                return StorageCensusDisposition::Retained;
            }
            match &mut metadata.cell {
                Cell::SourceControl { .. } => {
                    drop(metadata);
                    return self.drain_source_control(id);
                }
                Cell::Active { owner, servicing } => {
                    if *servicing {
                        if pending == NONE {
                            return StorageCensusDisposition::Retained;
                        }
                        slot.pending.store(NONE, Ordering::Release);
                        *servicing = false;
                        if pending == DRIVE_BUSY {
                            return StorageCensusDisposition::Retained;
                        }
                        assert_eq!(pending, DRIVE_SETTLED);
                        // Payload disposal can drop its last parent Arc. Keep
                        // the parent cell until even that child's census lease
                        // and slot have gone Vacant.
                        if slot.children.load(Ordering::Acquire) != 0 {
                            return StorageCensusDisposition::Retained;
                        }
                        // With no Weak/raw Arc escape, a count of one cannot
                        // race a new facade clone: there is no other facade.
                        if Arc::strong_count(owner) != 1 {
                            return StorageCensusDisposition::Retained;
                        }
                        let Cell::Active { owner, .. } =
                            std::mem::replace(&mut metadata.cell, Cell::Disposing)
                        else {
                            unreachable!();
                        };
                        drop(metadata);
                        match owner.try_dispose() {
                            Disposal::Disposed => {
                                slot.payload_retired_generation
                                    .store(id.generation, Ordering::Release);
                                slot.pending.store(PAYLOAD_DISPOSED, Ordering::Release)
                            }
                            Disposal::Panicked(payload) => Self::record_panic(
                                slot,
                                id,
                                StorageCensusPanicPhase::PayloadDisposal,
                                payload,
                            ),
                            Disposal::StillOwned(owner) => {
                                assert!(slot.unexpected_shared.set(owner).is_ok());
                                slot.pending.store(UNEXPECTED_SHARED, Ordering::Release);
                                self.fenced.store(true, Ordering::Release);
                            }
                        }
                    } else {
                        *servicing = true;
                        let temporary = owner.clone();
                        drop(metadata);
                        let result = catch_unwind(AssertUnwindSafe(|| temporary.drive()));
                        // The original Arc is still installed throughout this
                        // catch and temporary drop; a drive panic cannot erase it.
                        drop(temporary);
                        match result {
                            Ok(true) => slot.pending.store(DRIVE_SETTLED, Ordering::Release),
                            Ok(false) => slot.pending.store(DRIVE_BUSY, Ordering::Release),
                            Err(payload) => Self::record_panic(
                                slot,
                                id,
                                StorageCensusPanicPhase::Drive,
                                payload,
                            ),
                        }
                    }
                }
                Cell::Disposing => {
                    if pending != PAYLOAD_DISPOSED {
                        return StorageCensusDisposition::Retained;
                    }
                    slot.pending.store(NONE, Ordering::Release);
                    metadata.cell = Cell::RetiringLease;
                    let lease = metadata.lease.take();
                    let actual_lease = lease.is_some();
                    drop(metadata);
                    match catch_unwind(AssertUnwindSafe(|| drop(lease))) {
                        Ok(()) => {
                            if actual_lease {
                                slot.lease_retired_generation
                                    .store(id.generation, Ordering::Release);
                            }
                            slot.pending.store(LEASE_RETIRED, Ordering::Release);
                            #[cfg(test)]
                            if slot.output_state.load(Ordering::Acquire) == OUTPUT_PENDING {
                                let hook = slot.after_write_lease_retirement.lock().unwrap().take();
                                if let Some(hook) = hook {
                                    hook();
                                }
                            }
                        }
                        Err(payload) => {
                            Self::record_panic(
                                slot,
                                id,
                                StorageCensusPanicPhase::LeaseRetirement,
                                payload,
                            );
                            self.fenced.store(true, Ordering::Release);
                        }
                    }
                }
                Cell::RetiringLease => {
                    if pending != LEASE_RETIRED {
                        return StorageCensusDisposition::Retained;
                    }
                    if matches!(
                        slot.output_state.load(Ordering::Acquire),
                        OUTPUT_PENDING | OUTPUT_ENTERED | OUTPUT_DISPOSED
                    ) {
                        return StorageCensusDisposition::Retained;
                    }
                    if metadata.source.is_some() {
                        drop(metadata);
                        return self.finish_source_payload(id);
                    }
                    slot.pending.store(NONE, Ordering::Release);
                    metadata.cell = Cell::Vacant;
                    if let Some(parent) = metadata.parent.take() {
                        let previous = self.slots[parent.index]
                            .children
                            .fetch_sub(1, Ordering::AcqRel);
                        assert_ne!(previous, 0, "child count belongs to live parent generation");
                    }
                    if slot.native_constructor_generation.load(Ordering::Acquire) == id.generation {
                        slot.native_constructor_retired_generation
                            .fetch_max(id.generation, Ordering::Release);
                    }
                    return StorageCensusDisposition::Retired;
                }
                Cell::RetiringSourceHold => {
                    drop(metadata);
                    return self.finish_source_hold(id);
                }
                Cell::SourceReserved => return StorageCensusDisposition::Retained,
                Cell::Constructing | Cell::Retained | Cell::Vacant => {
                    return StorageCensusDisposition::Retained;
                }
            }
        }
        StorageCensusDisposition::Retained
    }
    /// One nonblocking fixed pass. Busy observations or resources never require
    /// a user facade to be reconstructed and cannot force a metadata wait.
    pub fn drain(&self) -> Option<StorageCensusSnapshot> {
        for index in 0..self.slots.len() {
            if let Some(id) = self.owner_at(index) {
                self.drain_owner(id);
            }
        }
        self.try_snapshot()
    }
}

pub struct StorageCensusObservation<'a> {
    phase: StorageCensusPanicPhase,
    payload: MutexGuard<'a, Panic>,
}
pub struct StorageWriteOutputObservation<'a> {
    state: u8,
    payload: Option<MutexGuard<'a, Panic>>,
}
impl StorageWriteOutputObservation<'_> {
    pub fn disposal(&self) -> kasumi_kv::TerminalObservation<'_, std::convert::Infallible> {
        use kasumi_kv::TerminalObservation;
        match self.state {
            OUTPUT_PENDING | NONE | OUTPUT_HANDED_OFF => TerminalObservation::NotEntered,
            OUTPUT_ENTERED => TerminalObservation::Entered,
            OUTPUT_DISPOSED | OUTPUT_RELEASED => TerminalObservation::Returned(Ok(())),
            OUTPUT_PANICKED => {
                TerminalObservation::Panicked(self.payload.as_ref().unwrap().as_ref())
            }
            _ => unreachable!("registered output observation"),
        }
    }
}
impl StorageCensusObservation<'_> {
    pub fn phase(&self) -> StorageCensusPanicPhase {
        self.phase
    }
    pub fn payload(&self) -> &(dyn Any + Send) {
        self.payload.as_ref()
    }
}

/// Private actual-owner facade. Drop never removes the independent census cell.
/// A queued worker may disappear without destroying its actual accepted request.
pub(crate) enum TypedOwnerLookup<T> {
    Active(StorageRegistration<T>),
    Busy,
    Missing,
}

pub(crate) struct StorageRegistration<T> {
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    id: StorageOwnerId,
    owner: Arc<T>,
}
impl<T> Clone for StorageRegistration<T> {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider.clone(),
            id: self.id,
            owner: self.owner.clone(),
        }
    }
}
impl<T> StorageRegistration<T> {
    pub(crate) fn provider(&self) -> &Arc<dyn NodeDiskMemoryAdmission> {
        &self.provider
    }
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        self.id == other.id && Arc::ptr_eq(&self.provider, &other.provider)
    }
    pub(crate) fn owner(&self) -> &T {
        &self.owner
    }
    pub(crate) fn id(&self) -> StorageOwnerId {
        self.id
    }
    /// Another typed facade to this exact installed allocation. No Weak or raw
    /// capability leaves the store, and the census keeps its independent lease.
    pub(crate) fn owner_arc(&self) -> Arc<T> {
        self.owner.clone()
    }
    pub(crate) fn retire(self) -> StorageCensusDisposition {
        let Self {
            provider,
            id,
            owner,
        } = self;
        drop(owner);
        provider.storage_census().drain_owner(id)
    }
}

#[cfg(test)]
#[path = "storage_census_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "storage_census_write_output_tests.rs"]
mod write_output_tests;

#[cfg(test)]
#[path = "storage_census_source_tests.rs"]
mod source_tests;
