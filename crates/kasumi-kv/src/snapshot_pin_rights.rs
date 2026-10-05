//! Private capacity foundation. No Database/Store capture corridor is activated.
//! A prepared pin owns its actual admitted Arc before root selection; installing
//! it uses only the caller's serialized current root and no provider callbacks.
use super::*;
#[path = "snapshot_pin_retained.rs"]
pub(crate) mod retained;

pub(super) type RightsRef = RetiredArc<RightsInner>;
pub(super) struct RightsInner {
    registry: RegistryRef,
    source: u64,
    _lease: LeaseCharge,
}

/// Exactly two lanes in this actual registry. This facade cannot be cloned.
pub(crate) struct SourcePinRights {
    pub(super) inner: RightsRef,
}

/// No root is selected until `install_protected`. Keep this owner in retained
/// native custody across that call; errors borrow it rather than erasing rights.
pub(crate) struct PreparedProtectedPin {
    pub(super) pin: Option<SnapshotPin>,
    lease: LeaseCharge,
    rights: RightsRef,
    lane: SourceLane,
    ticket: u64,
    pending: bool,
}

/// Provisional ordinary capacity, retaining the exact protected pin throughout.
pub(crate) struct HistoryPinRight {
    pin: SnapshotPin,
    held_slot: usize,
    ticket: u64,
    lane: SourceLane,
    pending: bool,
}

pub(super) const fn source_rights_request_bytes() -> u64 {
    (std::mem::size_of::<RightsInner>()
        + std::mem::size_of::<SourcePinRights>()
        + ARC_HEADER_BYTES
        + ALLOCATION_ALLOWANCE
        + LEASE_ALLOWANCE) as u64
}

fn serial(state: &RegistryState) -> Result<u64, CoreError> {
    state
        .serial
        .checked_add(1)
        .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))
}
fn same_pin(slot: &Slot, pin: PinIdentity) -> bool {
    slot.token == pin.token && slot.root == pin.root
}

impl SnapshotPins {
    pub(crate) fn reserve_source_rights(&self) -> Result<SourcePinRights, CoreError> {
        let lease = self.inner.reserve(source_rights_request_bytes())?;
        // The admitted stack owner owns any installed lanes until its Arc is
        // allocated after unlocking. No root is captured by this operation.
        let mut owner = RightsInner {
            registry: self.inner.clone(),
            source: 0,
            _lease: lease,
        };
        let mut state = self.inner.lock()?;
        let mut available = state.slots.iter().enumerate().filter(|(_, e)| e.is_empty());
        let first = available
            .next()
            .map(|(i, _)| i)
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        let second = available
            .next()
            .map(|(i, _)| i)
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        let source = serial(&state)?;
        // No allocation or provider callback while this lock is held. The
        // rights payload is still stack-owned; allocate its Arc after unlocking
        // while the provisional owner already owns both installed idle lanes.
        owner.source = source;
        for (slot, lane) in [(first, 0), (second, 1)] {
            state.slots[slot] = Entry::ProtectedIdle {
                lane: SourceLane { source, lane },
                ticket: None,
            };
        }
        state.serial = source;
        drop(state);
        let rights = SourcePinRights {
            inner: RetiredArc::new(owner),
        };
        self.inner.check()?;
        Ok(rights)
    }

    pub(crate) fn prepare_protected(
        &self,
        rights: &SourcePinRights,
    ) -> Result<PreparedProtectedPin, CoreError> {
        if !RetiredArc::ptr_eq(&self.inner, &rights.inner.registry) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "source pin rights belong to another owner",
            )));
        }
        let lease = self.inner.reserve(Self::pin_backing_request_bytes())?;
        let pin = SnapshotPin {
            inner: RetiredArc::new(PinInner {
                registry: self.inner.clone(),
                identity: OnceLock::new(),
                _rights: Some(rights.inner.clone()),
                _lease: lease,
            }),
        };
        let mut state = self.inner.lock()?;
        // A history swap can move a lane. Never cache its old physical slot.
        let (index, lane) = state
            .slots
            .iter()
            .enumerate()
            .find_map(|(i, entry)| match entry {
                Entry::ProtectedIdle { lane, ticket: None }
                    if lane.source == rights.inner.source =>
                {
                    Some((i, *lane))
                }
                _ => None,
            })
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        let ticket = serial(&state)?;
        state.slots[index] = Entry::ProtectedIdle {
            lane,
            ticket: Some(ticket),
        };
        state.serial = ticket;
        drop(state);
        let prepared = PreparedProtectedPin {
            pin: Some(pin),
            lease: LeaseCharge(None),
            rights: rights.inner.clone(),
            lane,
            ticket,
            pending: true,
        };
        self.inner.check()?;
        Ok(prepared)
    }

    /// Allocation-free local installation only. The enclosing physical owner
    /// must check provider access outside its lock, select its current published
    /// root under that lock, then call this method without exposing the root.
    /// This private foundation is deliberately not a public capture API.
    pub(crate) fn install_protected(
        &self,
        prepared: &mut PreparedProtectedPin,
        root: DirectoryRoot,
    ) -> Result<SnapshotPin, CoreError> {
        if !RetiredArc::ptr_eq(&self.inner, &prepared.rights.registry) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "prepared pin belongs to another owner",
            )));
        }
        if !prepared.pending || prepared.pin.is_none() {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "prepared pin was already settled",
            )));
        }
        if root.group_id != self.inner.group_id {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot root belongs to another group",
            )));
        }
        root.validate()?;
        let pin = prepared.pin.as_ref().expect("checked prepared pin");
        let mut state = self.inner.lock()?;
        let index = state
            .slots
            .iter()
            .position(|entry| {
                matches!(entry,
            Entry::ProtectedIdle { lane, ticket: Some(ticket) }
                if *lane == prepared.lane && *ticket == prepared.ticket)
            })
            .ok_or(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "prepared pin ticket differs",
            )))?;
        let token = self.inner.next_epoch(&state)?;
        // OnceLock::set neither allocates nor invokes provider code.
        if pin
            .inner
            .identity
            .set(PinIdentity {
                slot: index,
                token,
                root,
            })
            .is_err()
        {
            self.inner.failed.store(true, Ordering::Release);
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        state.slots[index] = Entry::Pinned(Slot {
            root,
            token,
            class: PinClass::Protected(prepared.lane),
        });
        state.epoch = token;
        prepared.pending = false;
        drop(state);
        Ok(prepared.pin.take().expect("installed prepared pin"))
    }

    pub(crate) fn reserve_history(&self, pin: &SnapshotPin) -> Result<HistoryPinRight, CoreError> {
        self.inner.check()?;
        if !RetiredArc::ptr_eq(&self.inner, &pin.inner.registry) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "history pin belongs to another owner",
            )));
        }
        let retained = pin.clone(); // Allocation-free; retained before the lock.
        let target = pin.identity();
        let mut state = self.inner.lock()?;
        let lane = match state.slots.get(target.slot).and_then(Entry::pinned) {
            Some(slot) if same_pin(slot, target) => match slot.class {
                PinClass::Protected(lane) => lane,
                PinClass::Ordinary => {
                    return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                        "pin is already ordinary",
                    )));
                }
            },
            _ => {
                return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                    "history target differs",
                )));
            }
        };
        if state.slots.iter().any(
            |entry| matches!(entry, Entry::HistoryHold { target: held, .. } if *held == target),
        ) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "history target already reserved",
            )));
        }
        let held_slot = state
            .slots
            .iter()
            .position(Entry::is_empty)
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        let ticket = serial(&state)?;
        state.slots[held_slot] = Entry::HistoryHold {
            ticket,
            target,
            lane,
        };
        state.serial = ticket;
        drop(state);
        let right = HistoryPinRight {
            pin: retained,
            held_slot,
            ticket,
            lane,
            pending: true,
        };
        self.inner.check()?;
        Ok(right)
    }

    /// Commit only after ordinary history bytes are already owned by the
    /// higher-level handoff. No admission, allocation or root change occurs.
    pub(crate) fn commit_history(&self, history: &mut HistoryPinRight) -> Result<(), CoreError> {
        if !RetiredArc::ptr_eq(&self.inner, &history.pin.inner.registry) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "history right belongs to another owner",
            )));
        }
        if !history.pending {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "history right was already settled",
            )));
        }
        let target = history.pin.identity();
        let mut state = self.inner.lock()?;
        if !matches!(state.slots.get(history.held_slot), Some(Entry::HistoryHold { ticket, target: held, lane })
            if *ticket == history.ticket && *held == target && *lane == history.lane)
        {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "history reservation differs",
            )));
        }
        let slot = state
            .slots
            .get(target.slot)
            .and_then(Entry::pinned)
            .copied()
            .filter(|slot| {
                same_pin(slot, target) && slot.class == PinClass::Protected(history.lane)
            })
            .ok_or(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "history protected pin differs",
            )))?;
        state.slots[target.slot] = Entry::Pinned(Slot {
            class: PinClass::Ordinary,
            ..slot
        });
        state.slots[history.held_slot] = Entry::ProtectedIdle {
            lane: history.lane,
            ticket: None,
        };
        history.pending = false;
        drop(state);
        Ok(())
    }
}

impl PreparedProtectedPin {
    pub(crate) fn cancel(&mut self) -> Result<(), CoreError> {
        if !self.pending {
            return Ok(());
        }
        self.cancel_ticket()?;
        drop(self.pin.take());
        Ok(())
    }

    pub(crate) fn cancel_ticket(&mut self) -> Result<(), CoreError> {
        if !self.pending {
            return Ok(());
        }
        // Cancellation is permitted after owner failure. An Err from this
        // borrowed call leaves ownership with the caller. Drop is best-effort:
        // after a mismatch it fences, then drops fields; it is never proof of
        // successful unknown cancellation for future Store retained custody.
        // Neither destructors nor admission run under the registry lock.
        let registry = &self.rights.registry;
        let mut state = registry.state.lock().unwrap_or_else(|poisoned| {
            registry.failed.store(true, Ordering::Release);
            poisoned.into_inner()
        });
        let Some(index) = state.slots.iter().position(|entry| matches!(entry,
            Entry::ProtectedIdle { lane, ticket: Some(ticket) } if *lane == self.lane && *ticket == self.ticket)) else {
            registry.failed.store(true, Ordering::Release);
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        };
        state.slots[index] = Entry::ProtectedIdle {
            lane: self.lane,
            ticket: None,
        };
        self.pending = false;
        drop(state);
        Ok(())
    }
}
impl Drop for PreparedProtectedPin {
    fn drop(&mut self) {
        let _ = self.cancel();
    }
}

impl HistoryPinRight {
    pub(crate) fn cancel(&mut self) -> Result<(), CoreError> {
        if !self.pending {
            return Ok(());
        }
        let registry = &self.pin.inner.registry;
        let mut state = registry.state.lock().unwrap_or_else(|poisoned| {
            registry.failed.store(true, Ordering::Release);
            poisoned.into_inner()
        });
        if !matches!(state.slots.get(self.held_slot), Some(Entry::HistoryHold { ticket, target, lane })
            if *ticket == self.ticket && *target == self.pin.identity() && *lane == self.lane)
        {
            registry.failed.store(true, Ordering::Release);
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        state.slots[self.held_slot] = Entry::Empty;
        self.pending = false;
        drop(state);
        Ok(())
    }
}
impl Drop for HistoryPinRight {
    fn drop(&mut self) {
        let _ = self.cancel();
    }
}

fn retire_source_lanes(registry: &RegistryRef, source: u64) -> Result<(), CoreError> {
    let mut state = registry.state.lock().map_err(|poisoned| {
        registry.failed.store(true, Ordering::Release);
        drop(poisoned.into_inner());
        CoreError::new(crate::CoreErrorCause::OwnerFailed)
    })?;
    let mut found = [None; 2];
    for (index, entry) in state.slots.iter().enumerate() {
        let lane = match entry {
            Entry::ProtectedIdle { lane, ticket: None } if lane.source == source => *lane,
            Entry::ProtectedIdle { lane, .. }
            | Entry::Pinned(Slot {
                class: PinClass::Protected(lane),
                ..
            }) if lane.source == source => {
                registry.failed.store(true, Ordering::Release);
                return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
            }
            Entry::HistoryHold { lane, .. } if lane.source == source => {
                registry.failed.store(true, Ordering::Release);
                return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
            }
            _ => continue,
        };
        let Some(slot) = found.get_mut(usize::from(lane.lane)) else {
            registry.failed.store(true, Ordering::Release);
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        };
        if slot.replace(index).is_some() {
            registry.failed.store(true, Ordering::Release);
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
    }
    let [Some(first), Some(second)] = found else {
        registry.failed.store(true, Ordering::Release);
        return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
    };
    state.slots[first] = Entry::Empty;
    state.slots[second] = Entry::Empty;
    drop(state);
    Ok(())
}
impl Drop for RightsInner {
    fn drop(&mut self) {
        if self.source != 0 && retire_source_lanes(&self.registry, self.source).is_err() {
            self.registry.failed.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
#[path = "snapshot_pin_rights_tests.rs"]
mod tests;
