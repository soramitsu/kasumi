use super::*;
use crate::{
    allocation_tests::{DeallocationObservation, observe_deallocation},
    test_utils::TestDiskMemory,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

fn allocation_address(lease: &DiskMemoryLease) -> *const () {
    std::ptr::from_ref::<dyn RetireLease>(lease.0.as_deref().expect("live lease")).cast::<()>()
}

// Release before joining even on an assertion panic, so this test cannot leave
// an allocator thread parked or silently detach the actual watched destructor.
struct PausedRetirement {
    observation: Arc<DeallocationObservation>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl PausedRetirement {
    fn start(lease: DiskMemoryLease) -> Self {
        let observation = Arc::new(DeallocationObservation::new(true));
        let worker_observation = observation.clone();
        let worker = std::thread::spawn(move || {
            let address = allocation_address(&lease);
            observe_deallocation(address, &worker_observation, || drop(lease));
        });
        Self {
            observation,
            worker: Some(worker),
        }
    }
    fn entered(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.observation.entered() {
            assert!(
                Instant::now() < deadline,
                "actual deallocation was not observed"
            );
            std::thread::yield_now();
        }
    }
    fn finish(&mut self) {
        self.observation.release();
        self.worker.take().unwrap().join().unwrap();
    }
}
impl Drop for PausedRetirement {
    fn drop(&mut self) {
        self.observation.release();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn installed_lease_cannot_return_bytes_or_slot_before_actual_box_deallocation() {
    let workspace = 1234;
    let required = TestDiskMemory::required_reservation_bytes(workspace).unwrap();
    let memory = TestDiskMemory::new(
        TestDiskMemory::required_bookkeeping_bytes(1).unwrap() + required,
        1,
    );
    let lease = memory.clone().reserve_installed(workspace).unwrap();
    assert_eq!(memory.snapshot().used_bytes, required);
    assert_eq!(memory.snapshot().live_reservations, 1);
    let mut retirement = PausedRetirement::start(lease);
    retirement.entered();
    assert!(!retirement.observation.finished());
    assert_eq!(memory.snapshot().used_bytes, required);
    assert_eq!(memory.snapshot().live_reservations, 1);
    assert!(memory.clone().reserve_installed(workspace).is_err());
    retirement.finish();
    assert!(retirement.observation.finished());
    assert_eq!(retirement.observation.count(), 1);
    assert_eq!(
        u64::try_from(retirement.observation.bytes()).unwrap(),
        required - workspace - ALLOCATION_ALLOWANCE,
        "provider still admits exactly one concrete token allocation"
    );
    assert_eq!(memory.snapshot().used_bytes, 0);
    assert_eq!(memory.snapshot().live_reservations, 0);
    let successor = memory.clone().reserve_installed(workspace).unwrap();
    assert_eq!(memory.snapshot().used_bytes, required);
    drop(successor);
    assert_eq!(memory.snapshot().used_bytes, 0);
}

struct Credit {
    observation: Arc<DeallocationObservation>,
    live: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}
impl Drop for Credit {
    fn drop(&mut self) {
        assert!(
            self.observation.finished(),
            "actual Box backing must be freed before credit destructor"
        );
        assert_eq!(self.live.fetch_sub(1, Ordering::AcqRel), 1);
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}
struct PanickingToken {
    _credit: Credit,
}
impl Drop for PanickingToken {
    fn drop(&mut self) {
        panic!("original token destructor panic");
    }
}

#[test]
fn panicking_token_keeps_single_retirement_and_frees_box_before_field_unwind() {
    let observation = Arc::new(DeallocationObservation::new(false));
    let live = Arc::new(AtomicUsize::new(1));
    let drops = Arc::new(AtomicUsize::new(0));
    let lease = DiskMemoryLease::new(PanickingToken {
        _credit: Credit {
            observation: observation.clone(),
            live: live.clone(),
            drops: drops.clone(),
        },
    });
    let address = allocation_address(&lease);
    let error = catch_unwind(AssertUnwindSafe(|| {
        observe_deallocation(address, &observation, || drop(lease));
    }))
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<&'static str>(),
        Some(&"original token destructor panic")
    );
    assert!(observation.finished());
    assert_eq!(observation.count(), 1);
    assert_eq!(observation.bytes(), std::mem::size_of::<PanickingToken>());
    assert_eq!(live.load(Ordering::Acquire), 0);
    assert_eq!(drops.load(Ordering::Acquire), 1);

    // Unwinding resets the thread-local observer before another independent
    // lease uses the same allocator on this thread.
    let successor_observation = Arc::new(DeallocationObservation::new(false));
    live.store(1, Ordering::Release);
    let successor = DiskMemoryLease::new(Credit {
        observation: successor_observation.clone(),
        live: live.clone(),
        drops: drops.clone(),
    });
    observe_deallocation(
        allocation_address(&successor),
        &successor_observation,
        || drop(successor),
    );
    assert!(successor_observation.finished());
    assert_eq!(successor_observation.count(), 1);
    assert_eq!(live.load(Ordering::Acquire), 0);
    assert_eq!(drops.load(Ordering::Acquire), 2);
}

#[test]
fn mandatory_opaque_lease_preserves_inline_layout_and_provider_denial_accounting() {
    assert_eq!(
        std::mem::size_of::<DiskMemoryLease>(),
        std::mem::size_of::<Box<dyn Send + Sync>>()
    );
    assert_eq!(
        std::mem::align_of::<DiskMemoryLease>(),
        std::mem::align_of::<Box<dyn Send + Sync>>()
    );
    let required = TestDiskMemory::required_reservation_bytes(1234).unwrap();
    let memory = TestDiskMemory::new(
        TestDiskMemory::required_bookkeeping_bytes(1).unwrap() + required - 1,
        1,
    );
    assert!(memory.clone().reserve_installed(1234).is_err());
    let after = memory.snapshot();
    assert_eq!(after.used_bytes, 0);
    assert_eq!(after.live_reservations, 0);
    assert_eq!(after.attempts, 1);
    assert!(TestDiskMemory::required_reservation_bytes(u64::MAX).is_err());
}
