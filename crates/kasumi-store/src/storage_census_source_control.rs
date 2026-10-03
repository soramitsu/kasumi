//! Construction custody exists before its first provider callback. The report
//! mutex is independent of all census metadata/parent-count/exchange locks.
use super::*;
use crate::source_metadata::{MetadataPreparation, SourceMetadataCallError, SourceMetadataPurpose};
use kasumi_kv::TerminalObservation;
use std::convert::Infallible;
const CONTROL_RETURNED: u8 = 8;
const CONTROL_DISPOSED: u8 = 9;

pub(crate) struct SourceControlClaim {
    census: usize,
    id: StorageOwnerId,
}
impl SourceControlClaim {
    pub(crate) fn id(&self) -> StorageOwnerId {
        self.id
    }
}
pub(in super::super) struct SourceControlState {
    generation: u64,
    preparation: Option<MetadataPreparation>,
    cancel: bool,
    acknowledged: bool,
}
impl SourceControlState {
    pub(in super::super) const fn new() -> Self {
        Self {
            generation: 0,
            preparation: None,
            cancel: false,
            acknowledged: false,
        }
    }
}
pub(crate) struct SourceControlObservation<'a> {
    state: MutexGuard<'a, SourceControlState>,
}
impl SourceControlObservation<'_> {
    pub(crate) fn original(&self) -> TerminalObservation<'_, io::Error> {
        self.state.preparation.as_ref().map_or(
            TerminalObservation::NotEntered,
            MetadataPreparation::original,
        )
    }
    pub(crate) fn protocol(&self) -> Option<SourceMetadataCallError> {
        self.state
            .preparation
            .as_ref()
            .and_then(MetadataPreparation::protocol)
    }
    pub(crate) fn cleanup(&self) -> TerminalObservation<'_, Infallible> {
        self.state.preparation.as_ref().map_or(
            TerminalObservation::NotEntered,
            MetadataPreparation::cleanup,
        )
    }
}

impl StorageCensus {
    pub(crate) fn source_control_parent(&self, id: StorageOwnerId) -> Option<StorageOwnerId> {
        let metadata = self.source_lock(id.index).ok()?;
        (metadata.generation == id.generation
            && matches!(metadata.cell, Cell::SourceControl { .. }))
        .then_some(metadata.parent)
        .flatten()
    }
    fn source_control_lock<'a>(
        &self,
        slot: &'a Slot,
    ) -> io::Result<MutexGuard<'a, SourceControlState>> {
        match slot.source_control.try_lock() {
            Ok(state) => Ok(state),
            Err(std::sync::TryLockError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                self.fenced.store(true, Ordering::Release);
                Err(io::ErrorKind::InvalidData.into())
            }
        }
    }
    pub(crate) fn claim_source_control<P: StoragePayload>(
        &self,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        parent: &StorageRegistration<P>,
    ) -> io::Result<SourceControlClaim> {
        self.require_source_available(provider)?;
        if P::KIND != StorageOwnerKind::Database || !Arc::ptr_eq(provider, &parent.provider) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        {
            let metadata = self.source_lock(parent.id.index)?;
            if metadata.generation != parent.id.generation
                || !matches!(metadata.cell, Cell::Active { .. })
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
        }
        for (index, slot) in self.slots.iter().enumerate() {
            let mut metadata = match self.source_lock(index) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            };
            if !matches!(metadata.cell, Cell::Vacant) {
                continue;
            }
            let mut state = match self.source_control_lock(slot) {
                Ok(state) => state,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            };
            // Positive promotion or acknowledged failure must already have
            // retired every preparation field outside the metadata lock.
            if state.preparation.is_some() {
                self.fenced.store(true, Ordering::Release);
                return Err(io::ErrorKind::InvalidData.into());
            }
            let generation = self.source_generation()?;
            self.source_add_child(parent.id)?;
            let id = StorageOwnerId { index, generation };
            state.generation = generation;
            state.preparation = Some(MetadataPreparation::new());
            state.cancel = false;
            state.acknowledged = false;
            metadata.generation = generation;
            metadata.kind = StorageOwnerKind::SourcePool;
            metadata.parent = Some(parent.id);
            metadata.cell = Cell::SourceControl { servicing: false };
            return Ok(SourceControlClaim {
                census: self as *const Self as usize,
                id,
            });
        }
        Err(io::ErrorKind::WouldBlock.into())
    }
    /// Fixed cells and parent count already exist. Provider dispatch runs only
    /// under this owner's independent preparation/report mutex, never under a
    /// census metadata, ordered exchange, bank, account, or native mutex.
    pub(crate) fn register_source_control<T: StoragePayload>(
        &self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        claim: &mut SourceControlClaim,
        construct: impl FnOnce() -> T,
    ) -> io::Result<StorageRegistration<T>> {
        self.require_source_available(&provider)?;
        if T::KIND != StorageOwnerKind::SourcePool || claim.census != self as *const Self as usize {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let bytes = Self::registration_request_bytes::<T>(0)?;
        let slot = self
            .slots
            .get(claim.id.index)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let mut metadata = self.source_lock(claim.id.index)?;
        if metadata.generation != claim.id.generation {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let Cell::SourceControl { servicing } = &mut metadata.cell else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        if *servicing && slot.pending.load(Ordering::Acquire) != CONTROL_RETURNED {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        *servicing = true;
        slot.pending.store(NONE, Ordering::Release);
        drop(metadata);
        let ready = {
            let mut state = self.source_control_lock(slot).inspect_err(|_| {
                slot.pending.store(CONTROL_RETURNED, Ordering::Release);
            })?;
            if state.generation != claim.id.generation || state.cancel {
                slot.pending.store(CONTROL_RETURNED, Ordering::Release);
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let preparation = state
                .preparation
                .as_mut()
                .ok_or(io::ErrorKind::InvalidData)?;
            preparation.acquire(&provider, SourceMetadataPurpose::Control, bytes);
            preparation.ready_for(&provider, SourceMetadataPurpose::Control, bytes)
        };
        slot.pending.store(CONTROL_RETURNED, Ordering::Release);
        if !ready {
            return Err(io::ErrorKind::Other.into());
        }
        // A busy post-provider metadata lock leaves the original and actual
        // grant in the fixed report; a later call never repeats the callback.
        let mut metadata = self.source_lock(claim.id.index)?;
        if metadata.generation != claim.id.generation
            || !matches!(metadata.cell, Cell::SourceControl { servicing: true })
        {
            self.fenced.store(true, Ordering::Release);
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut state = self.source_control_lock(slot)?;
        if state.cancel {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let lease = state
            .preparation
            .as_mut()
            .ok_or(io::ErrorKind::InvalidData)?
            .take_for(&provider, SourceMetadataPurpose::Control, bytes)
            .ok_or(io::ErrorKind::InvalidData)?;
        metadata.lease = Some(lease);
        metadata.cell = Cell::Constructing;
        slot.pending.store(NONE, Ordering::Release);
        match catch_unwind(AssertUnwindSafe(|| Arc::new(construct()))) {
            Ok(owner) => {
                metadata.cell = Cell::Active {
                    owner: owner.clone(),
                    servicing: false,
                };
                let preparation = state.preparation.take();
                drop(state);
                drop(metadata);
                // Retire the fixed preparation's exact provider alias before
                // this cell can ever become vacant. Actual provider and payload
                // owners remain live, so its successful fields have no final
                // funding tail; still retain an unexpected destructor original.
                if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(preparation))) {
                    Self::record_panic(
                        slot,
                        claim.id,
                        StorageCensusPanicPhase::SourceControlRetirement,
                        payload,
                    );
                    self.fenced.store(true, Ordering::Release);
                    return Err(io::ErrorKind::Other.into());
                }
                Ok(StorageRegistration {
                    provider,
                    id: claim.id,
                    owner,
                })
            }
            Err(payload) => {
                Self::record_panic(
                    slot,
                    claim.id,
                    StorageCensusPanicPhase::Construction,
                    payload,
                );
                metadata.cell = Cell::Retained;
                Err(io::ErrorKind::Other.into())
            }
        }
    }
    pub(crate) fn source_control_observation(
        &self,
        id: StorageOwnerId,
    ) -> Option<SourceControlObservation<'_>> {
        let state = self.source_control_lock(self.slots.get(id.index)?).ok()?;
        if state.generation != id.generation || state.preparation.is_none() {
            return None;
        }
        Some(SourceControlObservation { state })
    }
    /// Explicit parent-close intent. A lost authority token alone never
    /// cancels an authorized constructor while ordinary census drain runs.
    pub(crate) fn cancel_source_control(&self, id: StorageOwnerId) -> StorageCensusDisposition {
        let Some(slot) = self.slots.get(id.index) else {
            return StorageCensusDisposition::Stale;
        };
        let Ok(metadata) = self.source_lock(id.index) else {
            return StorageCensusDisposition::Retained;
        };
        if metadata.generation != id.generation
            || !matches!(metadata.cell, Cell::SourceControl { .. })
        {
            return StorageCensusDisposition::Stale;
        }
        let Ok(mut state) = self.source_control_lock(slot) else {
            return StorageCensusDisposition::Retained;
        };
        state.cancel = true;
        drop(state);
        drop(metadata);
        self.drain_source_control(id)
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn acknowledge_source_control(&self, id: StorageOwnerId) -> io::Result<()> {
        let slot = self
            .slots
            .get(id.index)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let metadata = self.source_lock(id.index)?;
        if metadata.generation != id.generation
            || !matches!(metadata.cell, Cell::SourceControl { .. })
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut state = self.source_control_lock(slot)?;
        if !state
            .preparation
            .as_ref()
            .is_some_and(MetadataPreparation::disposed)
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        state.acknowledged = true;
        Ok(())
    }
    pub(in super::super) fn drain_source_control(
        &self,
        id: StorageOwnerId,
    ) -> StorageCensusDisposition {
        let slot = &self.slots[id.index];
        let Ok(mut metadata) = self.source_lock(id.index) else {
            return StorageCensusDisposition::Retained;
        };
        if metadata.generation != id.generation
            || !matches!(metadata.cell, Cell::SourceControl { .. })
        {
            return StorageCensusDisposition::Stale;
        }
        let pending = slot.pending.load(Ordering::Acquire);
        if self.fenced.load(Ordering::Acquire) || pending == PANICKED {
            return StorageCensusDisposition::Retained;
        }
        if pending == CONTROL_DISPOSED {
            metadata.cell = Cell::Vacant;
            slot.pending.store(NONE, Ordering::Release);
            if let Some(parent) = metadata.parent.take() {
                let previous = self.slots[parent.index]
                    .children
                    .fetch_sub(1, Ordering::AcqRel);
                assert_ne!(
                    previous, 0,
                    "control preparation retains exact parent count"
                );
            }
            return StorageCensusDisposition::Retired;
        }
        if matches!(metadata.cell, Cell::SourceControl { servicing: true }) && pending == NONE {
            return StorageCensusDisposition::Retained;
        }
        let Ok(mut state) = self.source_control_lock(slot) else {
            return StorageCensusDisposition::Retained;
        };
        let cancel = state.cancel;
        let acknowledged = state.acknowledged;
        let Some(preparation) = state.preparation.as_mut() else {
            return StorageCensusDisposition::Retained;
        };
        if !cancel && !preparation.failed() {
            return StorageCensusDisposition::Retained;
        }
        metadata.cell = Cell::SourceControl { servicing: true };
        slot.pending.store(NONE, Ordering::Release);
        drop(metadata);
        preparation.dispose(); // Independent owner report guard only.
        if !preparation.disposed() || (preparation.failed() && !acknowledged) {
            slot.pending.store(CONTROL_RETURNED, Ordering::Release);
            return StorageCensusDisposition::Retained;
        }
        // Explicit acknowledgement precedes destruction of an original error.
        // This destruction, too, happens outside all report/metadata guards.
        let preparation = state.preparation.take();
        drop(state);
        match catch_unwind(AssertUnwindSafe(|| drop(preparation))) {
            Ok(()) => slot.pending.store(CONTROL_DISPOSED, Ordering::Release),
            Err(payload) => {
                Self::record_panic(
                    slot,
                    id,
                    StorageCensusPanicPhase::SourceControlRetirement,
                    payload,
                );
                self.fenced.store(true, Ordering::Release);
                return StorageCensusDisposition::Retained;
            }
        }
        self.drain_source_control(id)
    }
}
