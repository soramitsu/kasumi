//! The prepared-source capture corridor has no provider callback while holding
//! the publication mutex. It never receives a caller-selected root.
use super::*;
use crate::snapshot_pins::{PreparedProtectedPin, SnapshotPins};

impl ReadSnapshot {
    pub(crate) fn retirement_registry(&self) -> SnapshotPins {
        self.pin.registry()
    }

    pub(crate) fn source_history(&self) -> crate::snapshot_pins::HistoryPinRight {
        self.pin.queue_history()
    }
}

pub(crate) struct SourceReadContext {
    shared: Arc<Shared>,
    pub(crate) pins: SnapshotPins,
}
impl Core {
    #[cfg(test)]
    pub(crate) fn source_snapshots_for_test(&self) -> usize {
        self.shared.snapshots.load(Ordering::Acquire)
    }
    #[cfg(test)]
    pub(crate) fn source_probe_for_test(&self) -> Box<dyn Fn() -> bool + Send + Sync> {
        let context = self.source_context().expect("test source context");
        Box::new(move || {
            context.shared.state.try_lock().is_ok() && context.pins.source_lock_available_for_test()
        })
    }
    pub(crate) fn source_context(&self) -> Result<SourceReadContext, CoreError> {
        self.shared.check_owner()?;
        let mut state = self.source_lock()?;
        check_local(&self.shared, &state)?;
        let pins = state.disk()?.source_pins();
        drop(state);
        let context = SourceReadContext {
            shared: self.shared.clone(),
            pins,
        };
        context.check()?;
        Ok(context)
    }
    fn source_lock(&self) -> Result<MutexGuard<'_, State>, CoreError> {
        self.shared.state.lock().map_err(|poisoned| {
            drop(poisoned.into_inner());
            // Fence notification is deliberately deferred to the retained owner.
            CoreError::OwnerFailed
        })
    }
}
fn check_local(shared: &Shared, state: &State) -> Result<(), CoreError> {
    if shared.fenced.load(Ordering::Acquire) {
        return Err(CoreError::OwnerFailed);
    }
    if state.closed || shared.stopped.load(Ordering::Acquire) {
        return Err(CoreError::Closed);
    }
    Ok(())
}
impl SourceReadContext {
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }
    pub(crate) fn admission(&self) -> Arc<dyn StorageAdmission> {
        self.shared.admission.clone()
    }
    pub(crate) fn check(&self) -> Result<(), CoreError> {
        self.check_local()?;
        self.shared.check_owner()
    }
    pub(crate) fn check_local(&self) -> Result<(), CoreError> {
        if self.shared.fenced.load(Ordering::Acquire) {
            return Err(CoreError::OwnerFailed);
        }
        if self.shared.stopped.load(Ordering::Acquire) {
            return Err(CoreError::Closed);
        }
        Ok(())
    }
    pub(crate) fn reserve_into(
        &self,
        target: &mut Option<Box<dyn ResidentLease>>,
        bytes: u64,
    ) -> Result<(), CoreError> {
        self.check()?;
        *target = Some(self.shared.admission.reserve_workspace(bytes)?);
        self.check()
    }
    pub(crate) fn capture_into(
        &self,
        prepared: &mut PreparedProtectedPin,
        target: &OnceLock<ReadSnapshot>,
    ) -> Result<(), CoreError> {
        if target.get().is_some() {
            return Err(CoreError::InvalidInput(
                "source snapshot already initialized",
            ));
        }
        let mut state = self.shared.state.lock().map_err(|poisoned| {
            drop(poisoned.into_inner());
            CoreError::OwnerFailed
        })?;
        check_local(&self.shared, &state)?;
        let disk = state.disk()?;
        if !self.pins.same_owner(&disk.source_pins()) {
            return Err(CoreError::InvalidInput("source registry changed"));
        }
        // Check counter room before installing; acquisitions are serialized by
        // this gate. Ordinary snapshot clones can race, hence use checked CAS.
        self.shared
            .snapshots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| CoreError::CapacityDenied)?;
        let pin = match disk.install_source_pin(prepared) {
            Ok(pin) => pin,
            Err(error) => {
                self.shared.snapshots.fetch_sub(1, Ordering::AcqRel);
                return Err(error);
            }
        };
        let snapshot = ReadSnapshot {
            shared: self.shared.clone(),
            pin,
        };
        // Exclusive prepared ownership proved this empty before installation.
        // There are no callbacks or other references capable of filling it.
        assert!(target.set(snapshot).is_ok(), "exclusive source backing");
        drop(state);
        Ok(())
    }
}
