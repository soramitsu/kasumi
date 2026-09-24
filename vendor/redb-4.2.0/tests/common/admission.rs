//! Admission fixtures belong to integration test executables, never the library.
use redb::{AdmissionError, OwnerFailed, ResidentLease, StorageAdmission};
use std::sync::Arc;

#[derive(Debug)]
struct TestAdmission;
impl StorageAdmission for TestAdmission {
    fn reserve_workspace(&self, _: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        Ok(Box::new(()))
    }
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
pub fn admission() -> Arc<dyn StorageAdmission> {
    Arc::new(TestAdmission)
}
