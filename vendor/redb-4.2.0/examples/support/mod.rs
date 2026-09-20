//! Finite single-file budget for the standalone API examples. Kasumi uses its
//! installed physical NodeDisk owner, including aggregate and filesystem limits.
use redb::{AdmissionError, OwnerFailed, StorageAdmission};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[derive(Debug)]
struct ExampleBudget {
    failed: AtomicBool,
    maximum: u64,
}
impl StorageAdmission for ExampleBudget {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_growth(&self, _: u64, requested: u64) -> Result<(), AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if requested <= self.maximum {
            Ok(())
        } else {
            Err(AdmissionError::CapacityDenied)
        }
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        self.check_owner()
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }
}
pub fn budget(maximum: u64) -> Arc<dyn StorageAdmission> {
    Arc::new(ExampleBudget {
        failed: AtomicBool::new(false),
        maximum,
    })
}
