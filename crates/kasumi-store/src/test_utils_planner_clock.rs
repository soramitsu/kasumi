//! Deterministic expiry after observing an actual registered planner reader.
use super::TestDiskMemory;
use crate::NodeDiskMemoryAdmission;
use kasumi_clock::LeaseClock;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Advances monotonically after the real reader enters the owning census.
/// It changes no configured lease deadline and creates no native disposition.
pub struct PlannerExpiryClock {
    memory: Arc<TestDiskMemory>,
    armed: AtomicBool,
    observed_reader: AtomicBool,
}
impl PlannerExpiryClock {
    pub fn new(memory: Arc<TestDiskMemory>) -> Self {
        Self {
            memory,
            armed: AtomicBool::new(false),
            observed_reader: AtomicBool::new(false),
        }
    }
    pub fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }
    pub fn observed_reader(&self) -> bool {
        self.observed_reader.load(Ordering::Acquire)
    }
}
impl LeaseClock for PlannerExpiryClock {
    fn now(&self) -> Duration {
        if self.observed_reader()
            || (self.armed.load(Ordering::Acquire)
                && self.memory.storage_census().snapshot().readers != 0)
        {
            self.observed_reader.store(true, Ordering::Release);
            Duration::MAX
        } else {
            Duration::ZERO
        }
    }
}
