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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageOwnerKind {
    Database,
    Reader,
    Writer,
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
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StorageCensusSnapshot {
    pub capacity: usize,
    pub databases: usize,
    pub readers: usize,
    pub writers: usize,
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
    Retained,
}
struct Metadata {
    generation: u64,
    kind: StorageOwnerKind,
    // Survives payload disposal so a parent retry can find this exact child.
    parent: Option<StorageOwnerId>,
    cell: Cell,
    lease: Option<DiskMemoryLease>,
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
struct Slot {
    metadata: Mutex<Metadata>,
    pending: AtomicU8,
    // An exact parent's cell cannot retire while any child cell or lease lives.
    children: AtomicUsize,
    // Once installed, an original panic makes the cell permanently retained;
    // successful retirement/reuse therefore never needs to reset this OnceLock.
    panic: OnceLock<OriginalPanic>,
    unexpected_shared: OnceLock<Arc<dyn ErasedPayload>>,
}

/// Allocate after admitting required_bytes in provider bookkeeping; bind the
/// exact provider before publishing it. There is no optional or lazy census.
pub struct StorageCensus {
    provider: AtomicPtr<()>,
    next_generation: AtomicU64,
    fenced: AtomicBool,
    slots: Box<[Slot]>,
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
            });
            drop(metadata.lock().unwrap());
            slot.write(Slot {
                metadata,
                pending: AtomicU8::new(NONE),
                children: AtomicUsize::new(0),
                panic: OnceLock::new(),
                unexpected_shared: OnceLock::new(),
            });
        }
        // SAFETY: all elements are initialized before assume_init. Each loop
        // iteration uses only fixed inline constructors and an unshared mutex.
        let slots = unsafe { slots.assume_init() };
        Ok(Self {
            provider: AtomicPtr::new(std::ptr::null_mut()),
            next_generation: AtomicU64::new(0),
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
        }
        if matches!(
            metadata.cell,
            Cell::Constructing
                | Cell::Disposing
                | Cell::RetiringLease
                | Cell::Active {
                    servicing: true,
                    ..
                }
        ) {
            snapshot.servicing += 1;
        }
        if slot.panic.get().is_some() {
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
        self.register_inner(provider, backing_bytes, None, construct)
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
        self.register_inner(provider, backing_bytes, Some(parent.id), construct)
    }
    fn register_inner<T: StoragePayload>(
        &self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        backing_bytes: u64,
        parent: Option<StorageOwnerId>,
        construct: impl FnOnce() -> T,
    ) -> io::Result<StorageRegistration<T>> {
        self.require_provider(&provider)?;
        if self.fenced.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let lease = provider
            .clone()
            .reserve_installed(disk_memory::add(disk_memory::arc::<T>()?, backing_bytes)?)?;
        for (index, slot) in self.slots.iter().enumerate() {
            let Ok(mut metadata) = slot.metadata.try_lock() else {
                continue;
            };
            if !matches!(metadata.cell, Cell::Vacant) {
                continue;
            }
            assert_eq!(slot.children.load(Ordering::Acquire), 0);
            let generation = self
                .next_generation
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| io::ErrorKind::Other)?
                + 1;
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
            metadata.lease = Some(lease);
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
        self.require_provider(&provider).ok()?;
        let slot = self.slots.get(id.index)?;
        let metadata = slot.metadata.try_lock().ok()?;
        if metadata.generation != id.generation {
            return None;
        }
        let Cell::Active { owner, .. } = &metadata.cell else {
            return None;
        };
        let erased: Arc<dyn Any + Send + Sync> = owner.clone();
        let owner = Arc::downcast::<T>(erased).ok()?;
        Some(StorageRegistration {
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
                if metadata.parent != Some(parent)
                    || !matches!(metadata.cell, Cell::Disposing | Cell::RetiringLease)
                {
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
            let pending = slot.pending.load(Ordering::Acquire);
            if self.fenced.load(Ordering::Acquire)
                || pending == PANICKED
                || pending == UNEXPECTED_SHARED
            {
                return StorageCensusDisposition::Retained;
            }
            match &mut metadata.cell {
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
                    drop(metadata);
                    match catch_unwind(AssertUnwindSafe(|| drop(lease))) {
                        Ok(()) => slot.pending.store(LEASE_RETIRED, Ordering::Release),
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
                    slot.pending.store(NONE, Ordering::Release);
                    metadata.cell = Cell::Vacant;
                    if let Some(parent) = metadata.parent.take() {
                        let previous = self.slots[parent.index]
                            .children
                            .fetch_sub(1, Ordering::AcqRel);
                        assert_ne!(previous, 0, "child count belongs to live parent generation");
                    }
                    return StorageCensusDisposition::Retired;
                }
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
    pub(crate) fn owner(&self) -> &T {
        &self.owner
    }
    pub(crate) fn id(&self) -> StorageOwnerId {
        self.id
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
