//! Fixed physical source rights. Authority tokens do not own the cells: the
//! installed census retains every hold, payload, lease and completion record.
use super::*;
use crate::source_metadata::{
    SourceMetadataBankHold, SourceMetadataRetirement, SourceMetadataWitness, SourcePayloadGrant,
};

pub(super) const EXCHANGE_NONE: u8 = 0;
const CLAIMED: u8 = 1;
const NATIVE_ENTERED: u8 = 2;
const NATIVE_COMMITTED: u8 = 3;
const METADATA_APPLIED: u8 = 4;
const CENSUS_APPLIED: u8 = 5;
const COMMITTED: u8 = 6;
const EXCHANGE_RETAINED: u8 = 7;
const CANCELLING: u8 = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SourceClass {
    ProtectedVacant,
    ProtectedActive,
    OrdinaryHistory,
    ReplacementHeld,
    Releasing,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct ExchangeRecord {
    old: StorageOwnerId,
    replacement: StorageOwnerId,
    pool: StorageOwnerId,
    right: usize,
}
pub(super) struct SourceSlot {
    pool: StorageOwnerId,
    right: usize,
    pub(super) class: SourceClass,
    hold: Option<SourceMetadataBankHold>,
    witness: Option<SourceMetadataWitness>,
    exchange: Option<ExchangeRecord>,
}

/// Noncloneable authority for one protected right. Drop is intentionally inert;
/// its actual owner, including the Database child count, is in the Slot.
pub(crate) struct SourceCellClaim {
    census: usize,
    id: StorageOwnerId,
    pool: StorageOwnerId,
    right: usize,
    released: bool,
}
impl SourceCellClaim {
    pub(crate) fn id(&self) -> StorageOwnerId {
        self.id
    }
}
/// A bounded exchange token. The two Slot records remain authoritative if the
/// report/facade containing this token disappears.
pub(crate) struct SourceCensusExchange {
    census: usize,
    record: ExchangeRecord,
    phase: AtomicU8,
    cancelled: bool,
}
impl SourceCensusExchange {
    pub(crate) fn mark_native_entered(&self, census: &StorageCensus) -> io::Result<()> {
        census.advance_source_exchange(self, CLAIMED, NATIVE_ENTERED)
    }
    pub(crate) fn mark_native_committed(&self, census: &StorageCensus) -> io::Result<()> {
        census.advance_source_exchange(self, NATIVE_ENTERED, NATIVE_COMMITTED)
    }
}

pub(super) fn exchange_blocks(slot: &Slot, metadata: &Metadata) -> bool {
    metadata.source.as_ref().is_some_and(|source| {
        source.exchange.is_some() && slot.source_completion.load(Ordering::Acquire) != COMMITTED
    })
}

impl StorageCensus {
    fn source_generation(&self) -> io::Result<u64> {
        super::owner_generation()
    }
    fn source_lock(&self, index: usize) -> io::Result<MutexGuard<'_, Metadata>> {
        let slot = self.slots.get(index).ok_or(io::ErrorKind::InvalidInput)?;
        match slot.metadata.try_lock() {
            Ok(guard) => Ok(guard),
            Err(std::sync::TryLockError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                self.fenced.store(true, Ordering::Release);
                Err(io::ErrorKind::InvalidData.into())
            }
        }
    }
    fn require_source_available(
        &self,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
    ) -> io::Result<()> {
        self.require_provider(provider)?;
        if self.fenced.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
    fn source_add_child(&self, parent: StorageOwnerId) -> io::Result<()> {
        self.slots[parent.index]
            .children
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| io::ErrorKind::Other)?;
        Ok(())
    }
    fn require_source_parent(
        &self,
        parent: StorageOwnerId,
        pool: StorageOwnerId,
    ) -> io::Result<()> {
        if parent.index == pool.index {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let (first, second) = if parent.index < pool.index {
            (parent, pool)
        } else {
            (pool, parent)
        };
        let low = self.source_lock(first.index)?;
        let high = self.source_lock(second.index)?;
        let (parent_meta, pool_meta) = if parent.index < pool.index {
            (&low, &high)
        } else {
            (&high, &low)
        };
        if parent_meta.generation != parent.generation
            || parent_meta.kind != StorageOwnerKind::Database
            || !matches!(parent_meta.cell, Cell::Active { .. })
            || pool_meta.generation != pool.generation
            || pool_meta.kind != StorageOwnerKind::SourcePool
            || pool_meta.parent != Some(parent)
            || !matches!(pool_meta.cell, Cell::Active { .. })
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
    fn require_claim(&self, claim: &SourceCellClaim, metadata: &Metadata) -> io::Result<()> {
        let source = metadata
            .source
            .as_ref()
            .ok_or(io::ErrorKind::InvalidInput)?;
        if claim.census != self as *const Self as usize
            || claim.released
            || metadata.generation != claim.id.generation
            || source.pool != claim.pool
            || source.right != claim.right
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
    /// The caller retains its actual SourcePool registration throughout entry.
    pub(crate) fn claim_source_right(
        &self,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        parent: StorageOwnerId,
        pool: StorageOwnerId,
        right: usize,
        hold: &mut Option<SourceMetadataBankHold>,
    ) -> io::Result<SourceCellClaim> {
        self.require_source_available(provider)?;
        if right >= 2 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let bank = hold.as_ref().ok_or(io::ErrorKind::InvalidInput)?;
        bank.require_provider(provider)?;
        if !bank.belongs_to_pool(pool) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.require_source_parent(parent, pool)?;
        // The actual pool state serializes its two claims. A duplicate exact
        // logical right is still rejected, including a retained old cell.
        for index in 0..self.slots.len() {
            let metadata = self.source_lock(index)?;
            if metadata.source.as_ref().is_some_and(|source| {
                source.pool == pool
                    && source.right == right
                    && source.class != SourceClass::OrdinaryHistory
            }) {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
        }
        for index in 0..self.slots.len() {
            let mut metadata = match self.source_lock(index) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            };
            if !matches!(metadata.cell, Cell::Vacant) {
                continue;
            }
            let generation = self.source_generation()?;
            self.source_add_child(parent)?;
            let id = StorageOwnerId { index, generation };
            metadata.generation = generation;
            metadata.kind = StorageOwnerKind::Reader;
            metadata.parent = Some(parent);
            metadata.cell = Cell::SourceReserved;
            metadata.source = Some(SourceSlot {
                pool,
                right,
                class: SourceClass::ProtectedVacant,
                hold: hold.take(),
                witness: None,
                exchange: None,
            });
            return Ok(SourceCellClaim {
                census: self as *const Self as usize,
                id,
                pool,
                right,
                released: false,
            });
        }
        Err(io::ErrorKind::WouldBlock.into())
    }
    /// Actual child count is transferred from the reservation. Every rejection
    /// before installation leaves both the claim and grant intact.
    pub(crate) fn register_source_child<T: StoragePayload>(
        &self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        claim: &mut SourceCellClaim,
        grant: &mut Option<SourcePayloadGrant>,
        construct: impl FnOnce() -> T,
    ) -> io::Result<StorageRegistration<T>> {
        self.require_source_available(&provider)?;
        if T::KIND != StorageOwnerKind::Reader {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let offered = grant.as_ref().ok_or(io::ErrorKind::InvalidInput)?;
        offered.require(&provider, Self::registration_request_bytes::<T>(0)?)?;
        let slot = self
            .slots
            .get(claim.id.index)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let mut metadata = self.source_lock(claim.id.index)?;
        self.require_claim(claim, &metadata)?;
        let source = metadata.source.as_ref().expect("validated source");
        if source.class != SourceClass::ProtectedVacant
            || source.exchange.is_some()
            || !matches!(metadata.cell, Cell::SourceReserved)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        offered.require_hold(source.hold.as_ref().ok_or(io::ErrorKind::InvalidData)?)?;
        let generation = self.source_generation()?;
        let (lease, witness) = grant.take().expect("validated payload grant").into_parts();
        metadata.lease = Some(lease);
        metadata.generation = generation;
        metadata.cell = Cell::Constructing;
        let source = metadata.source.as_mut().expect("validated source");
        source.class = SourceClass::ProtectedActive;
        source.witness = Some(witness);
        claim.id.generation = generation;
        let id = claim.id;
        match catch_unwind(AssertUnwindSafe(|| Arc::new(construct()))) {
            Ok(owner) => {
                metadata.cell = Cell::Active {
                    owner: owner.clone(),
                    servicing: false,
                };
                let previous_hold = metadata
                    .source
                    .as_mut()
                    .expect("installed source")
                    .hold
                    .take();
                // Witness remains installed and retains this exact bank. Even
                // this nonfinal old alias retires outside every census lock.
                drop(metadata);
                if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(previous_hold))) {
                    Self::record_panic(
                        slot,
                        id,
                        StorageCensusPanicPhase::SourceHoldRetirement,
                        payload,
                    );
                    self.fenced.store(true, Ordering::Release);
                    return Err(io::ErrorKind::Other.into());
                }
                Ok(StorageRegistration {
                    provider,
                    id,
                    owner,
                })
            }
            Err(payload) => {
                Self::record_panic(slot, id, StorageCensusPanicPhase::Construction, payload);
                metadata.cell = Cell::Retained;
                Err(io::ErrorKind::Other.into())
            }
        }
    }
    /// Refresh a pool's unique claim after its publication payload has actually
    /// retired and the same physical right acquired a fresh generation.
    pub(crate) fn refresh_source_right(&self, claim: &mut SourceCellClaim) -> io::Result<()> {
        if claim.census != self as *const Self as usize || claim.released {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if self.fenced.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if self.slots.get(claim.id.index).is_some_and(|slot| {
            slot.source_retired_generation.load(Ordering::Acquire) >= claim.id.generation
        }) {
            claim.released = true;
            return Ok(());
        }
        let metadata = self.source_lock(claim.id.index)?;
        let source = metadata
            .source
            .as_ref()
            .ok_or(io::ErrorKind::InvalidInput)?;
        if source.pool != claim.pool
            || source.right != claim.right
            || !matches!(
                source.class,
                SourceClass::ProtectedVacant | SourceClass::Releasing
            )
            || source.exchange.is_some()
            || !matches!(
                metadata.cell,
                Cell::SourceReserved | Cell::RetiringSourceHold
            )
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        claim.id.generation = metadata.generation;
        Ok(())
    }
    pub(crate) fn release_source_right(
        &self,
        claim: &mut SourceCellClaim,
    ) -> StorageCensusDisposition {
        if claim.released {
            return StorageCensusDisposition::Retired;
        }
        if self.fenced.load(Ordering::Acquire) {
            return StorageCensusDisposition::Retained;
        }
        if claim.census != self as *const Self as usize {
            return StorageCensusDisposition::Stale;
        }
        if self.slots.get(claim.id.index).is_some_and(|slot| {
            slot.source_retired_generation.load(Ordering::Acquire) >= claim.id.generation
        }) {
            claim.released = true;
            return StorageCensusDisposition::Retired;
        }
        let Ok(mut metadata) = self.source_lock(claim.id.index) else {
            return StorageCensusDisposition::Retained;
        };
        if self.require_claim(claim, &metadata).is_err() {
            return StorageCensusDisposition::Stale;
        }
        let source = metadata.source.as_mut().expect("validated source");
        if source.exchange.is_some()
            || !matches!(
                source.class,
                SourceClass::ProtectedVacant | SourceClass::Releasing
            )
        {
            return StorageCensusDisposition::Retained;
        }
        if source.class == SourceClass::ProtectedVacant {
            source.class = SourceClass::Releasing;
            metadata.cell = Cell::RetiringSourceHold;
        }
        drop(metadata);
        let outcome = self.finish_source_hold(claim.id);
        if outcome == StorageCensusDisposition::Retired {
            claim.released = true;
        }
        outcome
    }
    pub(super) fn finish_source_payload(&self, id: StorageOwnerId) -> StorageCensusDisposition {
        let slot = &self.slots[id.index];
        let Ok(mut metadata) = self.source_lock(id.index) else {
            return StorageCensusDisposition::Retained;
        };
        if metadata.generation != id.generation
            || !matches!(metadata.cell, Cell::RetiringLease)
            || slot.pending.load(Ordering::Acquire) != LEASE_RETIRED
            || exchange_blocks(slot, &metadata)
        {
            return StorageCensusDisposition::Retained;
        }
        let Some(source) = metadata.source.as_mut() else {
            return StorageCensusDisposition::Retained;
        };
        match source.class {
            SourceClass::ProtectedActive => {
                let Some(witness) = source.witness.as_ref() else {
                    self.fenced.store(true, Ordering::Release);
                    return StorageCensusDisposition::Retained;
                };
                match witness.status() {
                    SourceMetadataRetirement::Pending => return StorageCensusDisposition::Retained,
                    SourceMetadataRetirement::Retained => {
                        self.fenced.store(true, Ordering::Release);
                        return StorageCensusDisposition::Retained;
                    }
                    SourceMetadataRetirement::Retired => {}
                }
                let Ok(generation) = self.source_generation() else {
                    self.fenced.store(true, Ordering::Release);
                    return StorageCensusDisposition::Retained;
                };
                source.hold = Some(source.witness.take().expect("observed witness").into_hold());
                source.class = SourceClass::ProtectedVacant;
                source.exchange = None;
                metadata.generation = generation;
                metadata.cell = Cell::SourceReserved;
                slot.pending.store(NONE, Ordering::Release);
                slot.source_completion
                    .store(EXCHANGE_NONE, Ordering::Release);
                // The old reader retired; its protected right still owns the
                // same parent count until explicit pool release.
                StorageCensusDisposition::Retired
            }
            SourceClass::OrdinaryHistory => {
                // Historical report/account tails retain their own credit.
                // A publication watermark says nothing about these tails.
                source.class = SourceClass::Releasing;
                source.exchange = None;
                metadata.cell = Cell::RetiringSourceHold;
                slot.pending.store(NONE, Ordering::Release);
                slot.source_completion
                    .store(EXCHANGE_NONE, Ordering::Release);
                drop(metadata);
                self.finish_source_hold(id)
            }
            _ => StorageCensusDisposition::Retained,
        }
    }
    pub(super) fn finish_source_hold(&self, id: StorageOwnerId) -> StorageCensusDisposition {
        let slot = &self.slots[id.index];
        let Ok(mut metadata) = self.source_lock(id.index) else {
            return StorageCensusDisposition::Retained;
        };
        if metadata.generation != id.generation
            || !matches!(metadata.cell, Cell::RetiringSourceHold)
            || self.fenced.load(Ordering::Acquire)
            || exchange_blocks(slot, &metadata)
        {
            return StorageCensusDisposition::Retained;
        }
        let pending = slot.pending.load(Ordering::Acquire);
        if pending == PANICKED {
            return StorageCensusDisposition::Retained;
        }
        if pending == NONE {
            let source = metadata.source.as_mut().expect("source hold retirement");
            if source.witness.is_some() {
                self.fenced.store(true, Ordering::Release);
                return StorageCensusDisposition::Retained;
            }
            let hold = source.hold.take();
            // NONE with no hold means a prior destructor is in flight.
            let Some(hold) = hold else {
                return StorageCensusDisposition::Retained;
            };
            drop(metadata);
            match catch_unwind(AssertUnwindSafe(|| drop(hold))) {
                Ok(()) => slot.pending.store(SOURCE_HOLD_RETIRED, Ordering::Release),
                Err(payload) => {
                    Self::record_panic(
                        slot,
                        id,
                        StorageCensusPanicPhase::SourceHoldRetirement,
                        payload,
                    );
                    self.fenced.store(true, Ordering::Release);
                    return StorageCensusDisposition::Retained;
                }
            }
            return self.finish_source_hold(id);
        }
        if pending != SOURCE_HOLD_RETIRED {
            return StorageCensusDisposition::Retained;
        }
        let source = metadata.source.as_ref().expect("source retirement");
        if source.hold.is_some()
            || source.witness.is_some()
            || source.class != SourceClass::Releasing
        {
            self.fenced.store(true, Ordering::Release);
            return StorageCensusDisposition::Retained;
        }
        metadata.source = None; // Contains no destructible owner now.
        metadata.cell = Cell::Vacant;
        slot.pending.store(NONE, Ordering::Release);
        slot.source_completion
            .store(EXCHANGE_NONE, Ordering::Release);
        if let Some(parent) = metadata.parent.take() {
            let previous = self.slots[parent.index]
                .children
                .fetch_sub(1, Ordering::AcqRel);
            assert_ne!(previous, 0, "source child belongs to exact live parent");
        }
        slot.source_retired_generation
            .store(id.generation, Ordering::Release);
        StorageCensusDisposition::Retired
    }
}

#[path = "storage_census_exchange.rs"]
mod exchange;

#[path = "storage_census_source_control.rs"]
mod control;
pub(super) use control::SourceControlState;
