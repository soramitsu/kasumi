//! Finite single-file budget for the standalone API examples. Kasumi uses its
//! installed physical NodeDisk owner, including aggregate and filesystem limits.
use redb::{AdmissionError, OwnerFailed, ResidentLease, StorageAdmission};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
#[derive(Debug)]
struct ExampleBudget {
    failed: AtomicBool,
    maximum: u64,
    resident: Arc<AtomicU64>,
}
struct ExampleLease {
    resident: Arc<AtomicU64>,
    bytes: u64,
}
impl Drop for ExampleLease {
    fn drop(&mut self) {
        self.resident.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
impl StorageAdmission for ExampleBudget {
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let lease_bytes = u64::try_from(std::mem::size_of::<ExampleLease>())
            .map_err(|_| AdmissionError::CapacityDenied)?;
        let charged = bytes
            .checked_add(lease_bytes)
            .and_then(|sum| sum.checked_add(4096))
            .ok_or(AdmissionError::CapacityDenied)?;
        self.resident
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                live.checked_add(charged)
                    .filter(|next| *next <= self.maximum)
            })
            .map_err(|_| AdmissionError::CapacityDenied)?;
        Ok(Box::new(ExampleLease {
            resident: self.resident.clone(),
            bytes: charged,
        }))
    }
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
        resident: Arc::new(AtomicU64::new(0)),
    })
}
