use super::*;

impl StorageCensus {
    /// ReaderState already owns the source transition before this call. The
    /// pool guard serializes its exact right. No native work has entered yet.
    pub(crate) fn begin_source_exchange(
        &self,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        claim: &SourceCellClaim,
        replacement_hold: &mut Option<SourceMetadataBankHold>,
    ) -> io::Result<SourceCensusExchange> {
        self.require_source_available(provider)?;
        let hold = replacement_hold
            .as_ref()
            .ok_or(io::ErrorKind::InvalidInput)?;
        hold.require_provider(provider)?;
        if !hold.belongs_to_pool(claim.pool) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        for replacement_index in 0..self.slots.len() {
            if replacement_index == claim.id.index {
                continue;
            }
            let (low_index, high_index) = if claim.id.index < replacement_index {
                (claim.id.index, replacement_index)
            } else {
                (replacement_index, claim.id.index)
            };
            let mut low = match self.source_lock(low_index) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            };
            let mut high = match self.source_lock(high_index) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            };
            let (old, replacement) = if claim.id.index < replacement_index {
                (&mut low, &mut high)
            } else {
                (&mut high, &mut low)
            };
            self.require_claim(claim, old)?;
            let source = old.source.as_ref().expect("validated source");
            if source.class != SourceClass::ProtectedActive
                || source.exchange.is_some()
                || !matches!(
                    old.cell,
                    Cell::Active {
                        servicing: false,
                        ..
                    }
                )
                || self.slots[claim.id.index].pending.load(Ordering::Acquire) != NONE
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            if !source
                .witness
                .as_ref()
                .ok_or(io::ErrorKind::InvalidData)?
                .same_bank(hold)
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            if !matches!(replacement.cell, Cell::Vacant) {
                continue;
            }
            let parent = old.parent.ok_or(io::ErrorKind::InvalidData)?;
            let generation = self.source_generation()?;
            self.source_add_child(parent)?;
            let record = ExchangeRecord {
                old: claim.id,
                replacement: StorageOwnerId {
                    index: replacement_index,
                    generation,
                },
                pool: claim.pool,
                right: claim.right,
            };
            replacement.generation = generation;
            replacement.kind = StorageOwnerKind::Reader;
            replacement.parent = Some(parent);
            replacement.cell = Cell::SourceReserved;
            replacement.source = Some(SourceSlot {
                pool: claim.pool,
                right: claim.right,
                class: SourceClass::ReplacementHeld,
                hold: replacement_hold.take(),
                witness: None,
                exchange: Some(record),
            });
            old.source.as_mut().expect("validated source").exchange = Some(record);
            self.slots[record.old.index]
                .source_completion
                .store(CLAIMED, Ordering::Release);
            self.slots[record.replacement.index]
                .source_completion
                .store(CLAIMED, Ordering::Release);
            return Ok(SourceCensusExchange {
                census: self as *const Self as usize,
                record,
                phase: AtomicU8::new(CLAIMED),
                cancelled: false,
            });
        }
        Err(io::ErrorKind::WouldBlock.into())
    }
    fn source_exchange_guards(
        &self,
        exchange: &SourceCensusExchange,
    ) -> io::Result<(MutexGuard<'_, Metadata>, MutexGuard<'_, Metadata>)> {
        if exchange.census != self as *const Self as usize
            || exchange.cancelled
            || matches!(
                exchange.phase.load(Ordering::Acquire),
                COMMITTED | EXCHANGE_RETAINED
            )
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let record = exchange.record;
        let low = self.source_lock(record.old.index.min(record.replacement.index))?;
        let high = self.source_lock(record.old.index.max(record.replacement.index))?;
        let (old, replacement) = if record.old.index < record.replacement.index {
            (&low, &high)
        } else {
            (&high, &low)
        };
        if old.generation != record.old.generation
            || replacement.generation != record.replacement.generation
            || old.source.as_ref().and_then(|source| source.exchange) != Some(record)
            || replacement
                .source
                .as_ref()
                .and_then(|source| source.exchange)
                != Some(record)
        {
            self.retain_source_exchange(record);
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok((low, high))
    }
    fn retain_source_exchange(&self, record: ExchangeRecord) {
        self.fenced.store(true, Ordering::Release);
        for id in [record.old, record.replacement] {
            if let Some(slot) = self.slots.get(id.index) {
                slot.source_completion
                    .store(EXCHANGE_RETAINED, Ordering::Release);
            }
        }
    }
    pub(super) fn advance_source_exchange(
        &self,
        exchange: &SourceCensusExchange,
        expected: u8,
        next: u8,
    ) -> io::Result<()> {
        let (_low, _high) = self.source_exchange_guards(exchange)?;
        let record = exchange.record;
        if self.fenced.load(Ordering::Acquire)
            || exchange.phase.load(Ordering::Acquire) != expected
            || self.slots[record.old.index]
                .source_completion
                .load(Ordering::Acquire)
                != expected
            || self.slots[record.replacement.index]
                .source_completion
                .load(Ordering::Acquire)
                != expected
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.slots[record.old.index]
            .source_completion
            .store(next, Ordering::Release);
        self.slots[record.replacement.index]
            .source_completion
            .store(next, Ordering::Release);
        exchange.phase.store(next, Ordering::Release);
        Ok(())
    }
    pub(crate) fn try_complete_source_exchange<'a>(
        &'a self,
        exchange: &'a SourceCensusExchange,
        claim: &'a mut SourceCellClaim,
    ) -> io::Result<Option<SourceCensusCompletionGuard<'a>>> {
        let (low, high) = match self.source_exchange_guards(exchange) {
            Ok(guards) => guards,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error),
        };
        let record = exchange.record;
        let (old, replacement) = if record.old.index < record.replacement.index {
            (&low, &high)
        } else {
            (&high, &low)
        };
        self.require_claim(claim, old)?;
        let old_source = old.source.as_ref().expect("validated source");
        let new_source = replacement.source.as_ref().expect("validated source");
        if self.fenced.load(Ordering::Acquire)
            || self.slots[record.old.index]
                .source_completion
                .load(Ordering::Acquire)
                != NATIVE_COMMITTED
            || self.slots[record.replacement.index]
                .source_completion
                .load(Ordering::Acquire)
                != NATIVE_COMMITTED
            || old_source.class != SourceClass::ProtectedActive
            || new_source.class != SourceClass::ReplacementHeld
            || old_source.witness.is_none()
            || old_source.hold.is_some()
            || new_source.hold.is_none()
            || new_source.witness.is_some()
            || old.parent != replacement.parent
            || !matches!(
                old.cell,
                Cell::Active {
                    servicing: false,
                    ..
                }
            )
            || !matches!(replacement.cell, Cell::SourceReserved)
        {
            self.retain_source_exchange(record);
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Some(SourceCensusCompletionGuard {
            census: self,
            exchange,
            record,
            low,
            high,
            claim,
            phase: NATIVE_COMMITTED,
        }))
    }
    /// The private reader caller first positively cancels/disposes its native
    /// provisional history, or closes the entire bound source. The old active
    /// claim is preserved. Once native commit entered, this cannot cancel.
    /// A pending result permits only another cancellation observation. It does
    /// not prove retirement or restore source readability. This must remain
    /// lock-free: the preceding cancellation can be pending on these cells.
    pub(crate) fn source_exchange_can_retry_cancellation(
        &self,
        exchange: &SourceCensusExchange,
    ) -> bool {
        let phase = exchange.phase.load(Ordering::Acquire);
        exchange.census == self as *const Self as usize
            && !exchange.cancelled
            && !self.fenced.load(Ordering::Acquire)
            && matches!(phase, CLAIMED | CANCELLING)
            && [exchange.record.old.index, exchange.record.replacement.index]
                .into_iter()
                .all(|index| {
                    self.slots
                        .get(index)
                        .is_some_and(|slot| slot.source_completion.load(Ordering::Acquire) == phase)
                })
    }
    pub(crate) fn cancel_source_exchange(
        &self,
        exchange: &mut SourceCensusExchange,
    ) -> StorageCensusDisposition {
        if exchange.cancelled {
            return StorageCensusDisposition::Retired;
        }
        if self.fenced.load(Ordering::Acquire) {
            return StorageCensusDisposition::Retained;
        }
        let record = exchange.record;
        let (mut low, mut high) = match self.source_exchange_guards(exchange) {
            Ok(guards) => guards,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return StorageCensusDisposition::Retained;
            }
            Err(_) => return StorageCensusDisposition::Retained,
        };
        let phase = self.slots[record.old.index]
            .source_completion
            .load(Ordering::Acquire);
        if !matches!(phase, CLAIMED | CANCELLING)
            || self.slots[record.replacement.index]
                .source_completion
                .load(Ordering::Acquire)
                != phase
        {
            return StorageCensusDisposition::Retained;
        }
        let replacement = if record.old.index < record.replacement.index {
            &mut high
        } else {
            &mut low
        };
        replacement
            .source
            .as_mut()
            .expect("validated replacement")
            .class = SourceClass::Releasing;
        replacement.cell = Cell::RetiringSourceHold;
        self.slots[record.old.index]
            .source_completion
            .store(CANCELLING, Ordering::Release);
        self.slots[record.replacement.index]
            .source_completion
            .store(CANCELLING, Ordering::Release);
        exchange.phase.store(CANCELLING, Ordering::Release);
        let replacement_slot = &self.slots[record.replacement.index];
        let pending = replacement_slot.pending.load(Ordering::Acquire);
        if pending == NONE {
            let hold = replacement
                .source
                .as_mut()
                .expect("validated replacement")
                .hold
                .take();
            let Some(hold) = hold else {
                return StorageCensusDisposition::Retained;
            };
            drop(high);
            drop(low);
            match catch_unwind(AssertUnwindSafe(|| drop(hold))) {
                Ok(()) => replacement_slot
                    .pending
                    .store(SOURCE_HOLD_RETIRED, Ordering::Release),
                Err(payload) => {
                    Self::record_panic(
                        replacement_slot,
                        record.replacement,
                        StorageCensusPanicPhase::SourceHoldRetirement,
                        payload,
                    );
                    self.retain_source_exchange(record);
                    return StorageCensusDisposition::Retained;
                }
            }
            return self.cancel_source_exchange(exchange);
        }
        if pending != SOURCE_HOLD_RETIRED {
            return StorageCensusDisposition::Retained;
        }
        let (old, replacement) = if record.old.index < record.replacement.index {
            (&mut low, &mut high)
        } else {
            (&mut high, &mut low)
        };
        let source = replacement.source.as_ref().expect("validated replacement");
        if source.hold.is_some() || source.witness.is_some() {
            self.retain_source_exchange(record);
            return StorageCensusDisposition::Retained;
        }
        replacement.source = None;
        replacement.cell = Cell::Vacant;
        if let Some(parent) = replacement.parent.take() {
            let previous = self.slots[parent.index]
                .children
                .fetch_sub(1, Ordering::AcqRel);
            assert_ne!(previous, 0, "held replacement owns exact parent count");
        }
        old.source.as_mut().expect("validated old").exchange = None;
        replacement_slot.pending.store(NONE, Ordering::Release);
        replacement_slot
            .source_completion
            .store(EXCHANGE_NONE, Ordering::Release);
        self.slots[record.old.index]
            .source_completion
            .store(EXCHANGE_NONE, Ordering::Release);
        exchange.cancelled = true;
        StorageCensusDisposition::Retired
    }
}

/// Caller acquires metadata bank/account guards only after this guard. No
/// provider, native operation, allocation or resource destructor is called here.
pub(crate) struct SourceCensusCompletionGuard<'a> {
    census: &'a StorageCensus,
    exchange: &'a SourceCensusExchange,
    record: ExchangeRecord,
    low: MutexGuard<'a, Metadata>,
    high: MutexGuard<'a, Metadata>,
    claim: &'a mut SourceCellClaim,
    phase: u8,
}
impl SourceCensusCompletionGuard<'_> {
    pub(crate) fn mark_metadata_applied(&mut self) {
        assert_eq!(self.phase, NATIVE_COMMITTED);
        self.phase = METADATA_APPLIED;
        self.census.slots[self.record.old.index]
            .source_completion
            .store(METADATA_APPLIED, Ordering::Release);
        self.census.slots[self.record.replacement.index]
            .source_completion
            .store(METADATA_APPLIED, Ordering::Release);
    }
    pub(crate) fn apply_census(&mut self) {
        assert_eq!(self.phase, METADATA_APPLIED);
        let (old, replacement) = if self.record.old.index < self.record.replacement.index {
            (&mut self.low, &mut self.high)
        } else {
            (&mut self.high, &mut self.low)
        };
        let source = old.source.as_mut().expect("prevalidated old source");
        source.hold = Some(
            source
                .witness
                .take()
                .expect("prevalidated witness")
                .into_hold(),
        );
        source.class = SourceClass::OrdinaryHistory;
        replacement
            .source
            .as_mut()
            .expect("prevalidated replacement")
            .class = SourceClass::ProtectedVacant;
        self.claim.id = self.record.replacement;
        self.phase = CENSUS_APPLIED;
        self.census.slots[self.record.old.index]
            .source_completion
            .store(CENSUS_APPLIED, Ordering::Release);
        self.census.slots[self.record.replacement.index]
            .source_completion
            .store(CENSUS_APPLIED, Ordering::Release);
    }
    /// The caller enables its validated metadata lane while all local guards
    /// remain held, then performs this final non-failing linearization store.
    pub(crate) fn final_commit(mut self) {
        assert_eq!(self.phase, CENSUS_APPLIED);
        let replacement = if self.record.old.index < self.record.replacement.index {
            &mut self.high
        } else {
            &mut self.low
        };
        replacement
            .source
            .as_mut()
            .expect("prevalidated replacement")
            .exchange = None;
        self.census.slots[self.record.replacement.index]
            .source_completion
            .store(EXCHANGE_NONE, Ordering::Release);
        self.census.slots[self.record.old.index]
            .source_completion
            .store(COMMITTED, Ordering::Release);
        self.phase = COMMITTED;
        self.exchange.phase.store(COMMITTED, Ordering::Release);
    }
}
impl Drop for SourceCensusCompletionGuard<'_> {
    fn drop(&mut self) {
        if self.phase != COMMITTED && (self.phase != NATIVE_COMMITTED || std::thread::panicking()) {
            self.census.retain_source_exchange(self.record);
            self.exchange
                .phase
                .store(EXCHANGE_RETAINED, Ordering::Release);
        }
    }
}
