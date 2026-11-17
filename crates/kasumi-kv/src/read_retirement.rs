//! Final-release observation for a retained read. It is installed before the
//! last snapshot is destroyed and never selects or captures a root.
use super::*;
use crate::snapshot_pins::SnapshotPins;

/// Inline, allocation-free custody outside the destructive retained Attempt.
/// Registry is dropped before Database, so the actual DB keeps it nonfinal.
pub(crate) struct ReadRetirementObserver {
    pins: SnapshotPins,
    database: NativeOwnedArc<DatabaseInner>,
}
impl ReadRetirementObserver {
    pub(crate) fn check(&self) -> Result<(), CoreError> {
        self.pins.check_retirement()
    }
    pub(crate) fn fence(&self) {
        self.database.core.fence();
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
            database: self.inner.clone(),
        }
    }
}
