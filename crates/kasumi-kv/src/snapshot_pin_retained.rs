//! Incremental assets for retained callers. Every allocation/ticket is installed
//! in the borrowed owner before the next provider observation can fail.
use super::*;

#[derive(Clone, Copy)]
pub(crate) enum RightsRetirement {
    NoLanes,
    OtherHolders,
    LanesRetired,
}

pub(crate) struct PendingSourceRights {
    lease: LeaseCharge,
    rights: Option<SourcePinRights>,
    retiring: Option<RightsInner>,
}
impl PendingSourceRights {
    #[cfg(test)]
    pub(crate) fn remove_lane_for_test(&self) {
        let rights = self.rights.as_ref().unwrap();
        let mut state = rights.inner.registry.state.lock().unwrap();
        let entry = state
            .slots
            .iter_mut()
            .find(|entry| {
                matches!(entry,
            Entry::ProtectedIdle { lane, .. } if lane.source == rights.inner.source)
            })
            .unwrap();
        *entry = Entry::Empty;
    }
    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        let rights = self.rights.as_ref().unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = rights.inner.registry.state.lock().unwrap();
            panic!("test registry poison");
        }));
    }
    pub(crate) fn new() -> Self {
        Self {
            lease: LeaseCharge(None),
            rights: None,
            retiring: None,
        }
    }
    pub(crate) fn rights(&self) -> Option<&SourcePinRights> {
        self.rights.as_ref()
    }
    pub(crate) fn retire_checked(&mut self) -> Result<RightsRetirement, CoreError> {
        if let Some(rights) = self.rights.take() {
            // Elect the real final owner and deallocate its Arc before moving
            // the payload into retained custody. A nonfinal facade only retires
            // its alias; every remaining KV holder has an independent DB alias.
            self.retiring = rights.inner.into_payload();
            if self.retiring.is_none() {
                return Ok(RightsRetirement::OtherHolders);
            }
        }
        let Some(owner) = self.retiring.as_mut() else {
            return Ok(RightsRetirement::NoLanes);
        };
        if owner.source == 0 {
            return Ok(RightsRetirement::NoLanes);
        }
        retire_source_lanes(&owner.registry, owner.source)?;
        owner.source = 0;
        Ok(RightsRetirement::LanesRetired)
    }
    pub(crate) fn prepare(&mut self, pins: &SnapshotPins) -> Result<(), CoreError> {
        if self.rights.is_some() || self.lease.0.is_some() {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "rights preparation already entered",
            )));
        }
        reserve_into(
            &pins.inner,
            &mut self.lease,
            crate::ProtectedReadRequests::rights_request_bytes(),
        )?;
        self.install_prepared_rights(pins)
    }
    pub(crate) fn prepare_funded(
        &mut self,
        pins: &SnapshotPins,
        pool: &mut crate::NativeSourcePool,
    ) -> Result<(), CoreError> {
        if self.rights.is_some() || self.lease.0.is_some() {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "rights preparation already entered",
            )));
        }
        pool.reserve_rights_into(pins, &mut self.lease.0)?;
        self.install_prepared_rights(pins)
    }
    // Both callers own the actual constructor grant before allocating. The
    // funded caller has no route through ordinary registry admission.
    fn install_prepared_rights(&mut self, pins: &SnapshotPins) -> Result<(), CoreError> {
        self.rights = Some(SourcePinRights {
            inner: RetiredArc::new(RightsInner {
                registry: pins.inner.clone(),
                source: 0,
                _lease: LeaseCharge(self.lease.0.take()),
            }),
        });
        let owner = self
            .rights
            .as_mut()
            .expect("owned rights")
            .inner
            .get_mut()
            .expect("unshared rights");
        let mut state = pins.inner.lock()?;
        let mut free = state
            .slots
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.is_empty());
        let first = free
            .next()
            .map(|(i, _)| i)
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        let second = free
            .next()
            .map(|(i, _)| i)
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        let source = serial(&state)?;
        owner.source = source;
        for (slot, lane) in [(first, 0), (second, 1)] {
            state.slots[slot] = Entry::ProtectedIdle {
                lane: SourceLane { source, lane },
                ticket: None,
            };
        }
        state.serial = source;
        drop(state);
        pins.inner.check()
    }
}

// Unlike RegistryInner::reserve, a successful grant is owned before post-check.
fn reserve_into(
    registry: &RegistryRef,
    target: &mut LeaseCharge,
    bytes: u64,
) -> Result<(), CoreError> {
    registry.check()?;
    match registry
        .admission
        .reserve_workspace(bytes)
        .map(NativeResidentLease::new)
    {
        Ok(lease) => target.0 = Some(lease),
        Err(error) => {
            if error == AdmissionError::OwnerFailed {
                registry.failed.store(true, Ordering::Release);
            }
            return Err(error.into());
        }
    }
    registry.check()
}

impl SourcePinRights {
    pub(crate) fn queue_pin(&self) -> PreparedProtectedPin {
        PreparedProtectedPin {
            pin: None,
            lease: LeaseCharge(None),
            rights: self.inner.clone(),
            lane: SourceLane {
                source: self.inner.source,
                lane: 0,
            },
            ticket: 0,
            pending: false,
        }
    }
    pub(crate) fn belongs_to(&self, pins: &SnapshotPins) -> bool {
        RetiredArc::ptr_eq(&self.inner.registry, &pins.inner)
    }
}
impl PreparedProtectedPin {
    #[cfg(test)]
    pub(crate) fn mismatch_ticket_for_test(&mut self) {
        self.ticket += 1;
    }
    pub(crate) fn prepare_retained(&mut self) -> Result<(), CoreError> {
        if self.pin.is_some() || self.lease.0.is_some() || self.pending {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "pin preparation already entered",
            )));
        }
        let registry = &self.rights.registry;
        reserve_into(
            registry,
            &mut self.lease,
            crate::ProtectedReadRequests::pin_backing_request_bytes(),
        )?;
        self.install_prepared_pin()
    }
    pub(crate) fn prepare_retained_funded(
        &mut self,
        funding: &mut crate::NativeSourceFunding,
    ) -> Result<(), CoreError> {
        if self.pin.is_some() || self.lease.0.is_some() || self.pending {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "pin preparation already entered",
            )));
        }
        let pins = SnapshotPins {
            inner: self.rights.registry.clone(),
        };
        funding.reserve_pin_into(&pins, &mut self.lease.0)?;
        self.install_prepared_pin()
    }
    fn install_prepared_pin(&mut self) -> Result<(), CoreError> {
        let registry = &self.rights.registry;
        self.pin = Some(SnapshotPin {
            inner: RetiredArc::new(PinInner {
                registry: registry.clone(),
                identity: OnceLock::new(),
                _rights: Some(self.rights.clone()),
                _lease: LeaseCharge(self.lease.0.take()),
            }),
        });
        let mut state = registry.lock()?;
        let (index, lane) = state
            .slots
            .iter()
            .enumerate()
            .find_map(|(i, entry)| match entry {
                Entry::ProtectedIdle { lane, ticket: None }
                    if lane.source == self.rights.source =>
                {
                    Some((i, *lane))
                }
                _ => None,
            })
            .ok_or(CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        let ticket = serial(&state)?;
        self.lane = lane;
        self.ticket = ticket;
        self.pending = true;
        state.slots[index] = Entry::ProtectedIdle {
            lane,
            ticket: Some(ticket),
        };
        state.serial = ticket;
        drop(state);
        registry.check()
    }
    pub(crate) fn is_pending(&self) -> bool {
        self.pending
    }
}

impl SnapshotPin {
    pub(crate) fn queue_history(&self) -> HistoryPinRight {
        HistoryPinRight {
            pin: self.clone(),
            held_slot: 0,
            ticket: 0,
            lane: SourceLane { source: 0, lane: 0 },
            pending: false,
        }
    }
    pub(crate) fn registry(&self) -> SnapshotPins {
        SnapshotPins {
            inner: self.inner.registry.clone(),
        }
    }
}
impl HistoryPinRight {
    pub(crate) fn retirement_registry(&self) -> SnapshotPins {
        self.pin.registry()
    }

    pub(crate) fn belongs_to(&self, pins: &SnapshotPins) -> bool {
        RetiredArc::ptr_eq(&self.pin.inner.registry, &pins.inner)
    }
    pub(crate) fn prepare_retained(&mut self) -> Result<(), CoreError> {
        if self.pending || self.ticket != 0 {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "history preparation already entered",
            )));
        }
        let registry = &self.pin.inner.registry;
        registry.check()?;
        let target = self.pin.identity();
        let mut state = registry.lock()?;
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
        self.held_slot = held_slot;
        self.ticket = ticket;
        self.lane = lane;
        self.pending = true;
        state.slots[held_slot] = Entry::HistoryHold {
            ticket,
            target,
            lane,
        };
        state.serial = ticket;
        drop(state);
        registry.check()
    }
    pub(crate) fn commit_local(&mut self) -> Result<(), CoreError> {
        let pins = self.pin.registry();
        pins.commit_history(self)
    }
    pub(crate) fn is_pending(&self) -> bool {
        self.pending
    }
}
