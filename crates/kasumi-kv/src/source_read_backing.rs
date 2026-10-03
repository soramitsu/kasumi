//! Private exact-Database bridge. Prepared backing is never exposed as a
//! SnapshotHandle until it contains the actual installed native snapshot.
use super::*;
use crate::core::SourceReadContext;
use crate::snapshot_pins::{HistoryPinRight, PreparedProtectedPin, SnapshotPins};

pub(crate) struct SourceDatabase(Arc<DatabaseInner>);
impl SourceDatabase {
    pub(crate) fn new(database: &Database) -> Self {
        Self(database.inner.clone())
    }
    pub(crate) fn belongs_to(&self, database: &Database) -> bool {
        Arc::ptr_eq(&self.0, &database.inner)
    }
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn check_local(&self) -> Result<(), CoreError> {
        if self.0.core.is_fenced() {
            return Err(CoreError::OwnerFailed);
        }
        if self.0.closing.load(Ordering::Acquire) {
            return Err(CoreError::Closed);
        }
        Ok(())
    }
    pub(crate) fn context(&self) -> Result<SourceReadContext, CoreError> {
        self.check_local()?;
        self.0.core.source_context()
    }
    pub(crate) fn fence(&self) {
        self.0.core.fence();
    }
    pub(crate) fn reader(&self, backing: &mut SourceBacking) -> Option<ReadTransaction> {
        if !backing.has_snapshot() {
            return None;
        }
        Some(ReadTransaction {
            inner: self.0.clone(),
            snapshot: backing.handle.take().expect("initialized backing"),
        })
    }
}
pub(crate) struct SourceBacking {
    charge: SnapshotCharge,
    handle: Option<SnapshotHandle>,
}
impl SourceBacking {
    #[cfg(test)]
    pub(crate) fn address_for_test(&self) -> usize {
        Arc::as_ptr(
            self.handle
                .as_ref()
                .expect("prepared backing")
                .0
                .as_ref()
                .unwrap(),
        ) as usize
    }
    pub(crate) fn new() -> Self {
        Self {
            charge: SnapshotCharge(None),
            handle: None,
        }
    }
    pub(crate) fn prepare(&mut self, context: &SourceReadContext) -> Result<(), CoreError> {
        if self.handle.is_some() || self.charge.0.is_some() {
            return Err(CoreError::InvalidInput("source backing already prepared"));
        }
        context.reserve_into(
            &mut self.charge.0,
            crate::ProtectedReadRequests::snapshot_backing_request_bytes(),
        )?;
        self.allocate_empty();
        Ok(())
    }
    pub(crate) fn prepare_funded(
        &mut self,
        context: &SourceReadContext,
        funding: &mut crate::NativeSourceFunding,
    ) -> Result<(), CoreError> {
        if self.handle.is_some() || self.charge.0.is_some() {
            return Err(CoreError::InvalidInput("source backing already prepared"));
        }
        funding.reserve_backing_into(context, &mut self.charge.0)?;
        self.allocate_empty();
        Ok(())
    }
    fn allocate_empty(&mut self) {
        self.handle = Some(SnapshotHandle(Some(Arc::new(SnapshotBacking {
            snapshot: OnceLock::new(),
            charge: SnapshotCharge(self.charge.0.take()),
        }))));
    }
    pub(crate) fn capture(
        &self,
        context: &SourceReadContext,
        pin: &mut PreparedProtectedPin,
    ) -> Result<(), CoreError> {
        let backing = self
            .handle
            .as_ref()
            .ok_or(CoreError::InvalidInput("source backing absent"))?
            .0
            .as_ref()
            .expect("live backing");
        context.capture_into(pin, &backing.snapshot)
    }
    pub(crate) fn has_snapshot(&self) -> bool {
        self.handle
            .as_ref()
            .is_some_and(|handle| handle.0.as_ref().unwrap().snapshot.get().is_some())
    }
}
impl ReadTransaction {
    // Scalar observation of this already captured root, with no I/O, provider
    // callback or authority to select/capture another root.
    pub(crate) fn source_generation(&self) -> u64 {
        self.snapshot.generation()
    }
    pub(crate) fn source_history(&self) -> (SourceDatabase, HistoryPinRight) {
        (
            SourceDatabase(self.inner.clone()),
            self.snapshot.source_history(),
        )
    }
}

/// Inline, allocation-free custody outside the destructive retained Attempt.
/// Registry is dropped before Database, so the actual DB keeps it nonfinal.
pub(crate) struct ReadRetirementObserver {
    pins: SnapshotPins,
    binding: SourceDatabase,
}
impl ReadRetirementObserver {
    pub(crate) fn from_registry(binding: &SourceDatabase, pins: SnapshotPins) -> Self {
        Self {
            pins,
            binding: SourceDatabase(binding.0.clone()),
        }
    }

    pub(crate) fn from_context(binding: &SourceDatabase, context: &SourceReadContext) -> Self {
        Self {
            pins: context.pins.clone_owner(),
            binding: SourceDatabase(binding.0.clone()),
        }
    }
    pub(crate) fn check(&self) -> Result<(), CoreError> {
        self.pins.check_retirement()
    }
    pub(crate) fn fence(&self) {
        self.binding.fence();
    }
    #[cfg(test)]
    pub(crate) fn corrupt_for_test(&self, poison: bool) {
        self.pins.corrupt_final_release_for_test(poison);
    }
}
impl ReadTransaction {
    pub(crate) fn retirement_observer(&self) -> ReadRetirementObserver {
        ReadRetirementObserver {
            pins: self.snapshot.retirement_registry(),
            binding: SourceDatabase(self.inner.clone()),
        }
    }
}
