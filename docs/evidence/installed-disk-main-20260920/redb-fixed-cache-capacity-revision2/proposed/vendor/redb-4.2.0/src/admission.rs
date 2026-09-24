//! The physical owner is installed before storage construction and survives all
//! database, transaction and backend handles. There is no unowned default.
use core::fmt::Debug;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// No physical operation occurred and the transaction must roll back.
    CapacityDenied,
    /// Ownership or physical state is uncertain. Further access is fenced.
    OwnerFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerFailed;

/// Admission for the exact physical file supplied to the database builder.
/// Implementations retain physical charges after handles close; only verified
/// physical reclamation or a complete drained census may release those charges.
pub trait StorageAdmission: Debug + Send + Sync + 'static {
    /// Observe the retained owner fence without reserving or allocating.
    fn check_owner(&self) -> Result<(), OwnerFailed>;
    /// Reserve before growing the physical file. Denial must have no effects.
    fn reserve_growth(&self, current_len: u64, requested_len: u64) -> Result<(), AdmissionError>;
    /// Synchronize and settle unused reservation against this exact retained
    /// extent. This must never discard charges for successfully grown storage.
    /// It also runs after the winning header and must not allocate.
    fn settle_growth(&self, actual_len: u64) -> Result<(), OwnerFailed>;
    /// Latch uncertainty. This callback must be idempotent and non-allocating.
    fn owner_failed(&self);
}

#[cfg(test)]
#[derive(Debug)]
struct TestAdmission;
#[cfg(test)]
impl StorageAdmission for TestAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn owner_failed(&self) {}
}
#[cfg(test)]
pub(crate) fn test_admission() -> alloc::sync::Arc<dyn StorageAdmission> {
    alloc::sync::Arc::new(TestAdmission)
}

#[cfg(test)]
mod tests;

#[cfg(all(test, not(redb_no_std), panic = "unwind"))]
#[path = "cache_admission_tests.rs"]
mod cache_admission_tests;

#[cfg(test)]
pub(crate) fn observe_test_allocations<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    tests::begin_allocation_observation();
    let result = operation();
    (result, tests::end_allocation_observation())
}
