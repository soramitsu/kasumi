use super::*;
use crate::test_utils::TestDiskMemory;
use std::sync::atomic::{AtomicBool, AtomicUsize};

struct ActualOwner {
    ready: Arc<AtomicBool>,
    drops: Arc<AtomicUsize>,
    memory: Arc<TestDiskMemory>,
}
impl StoragePayload for ActualOwner {
    const KIND: StorageOwnerKind = StorageOwnerKind::Writer;
    fn drive(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}
impl Drop for ActualOwner {
    fn drop(&mut self) {
        assert_eq!(self.memory.snapshot().live_reservations, 1);
        assert_eq!(self.memory.storage_census().snapshot().servicing, 1);
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}
fn fixture_memory(capacity: usize) -> Arc<TestDiskMemory> {
    TestDiskMemory::new(1 << 20, capacity)
}

struct ReadyDatabase;
impl StoragePayload for ReadyDatabase {
    const KIND: StorageOwnerKind = StorageOwnerKind::Database;
    fn drive(&self) -> bool {
        true
    }
}
struct ReadyChild;
impl StoragePayload for ReadyChild {
    const KIND: StorageOwnerKind = StorageOwnerKind::Reader;
    fn drive(&self) -> bool {
        true
    }
}

#[test]
fn denied_child_registration_never_increments_parent_count() {
    let memory = fixture_memory(1);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let parent = memory
        .storage_census()
        .register(provider.clone(), 0, || ReadyDatabase)
        .unwrap();
    let constructed = AtomicBool::new(false);
    assert!(
        memory
            .storage_census()
            .register_child(provider, 0, &parent, || {
                constructed.store(true, Ordering::Release);
                ReadyChild
            })
            .is_err()
    );
    assert!(!constructed.load(Ordering::Acquire));
    assert_eq!(parent.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.storage_census().snapshot().databases, 0);
    assert_eq!(memory.snapshot().live_reservations, 0);
}

#[test]
fn child_registration_waits_for_parent_metadata_observation() {
    let memory = fixture_memory(2);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let parent = memory
        .storage_census()
        .register(provider.clone(), 0, || ReadyDatabase)
        .unwrap();
    let metadata = memory.storage_census().slots[parent.id().index]
        .metadata
        .lock()
        .unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
    let (completed_tx, completed_rx) = std::sync::mpsc::channel();
    let worker_memory = memory.clone();
    let worker_parent = parent.clone();
    let worker = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let child =
            worker_memory
                .storage_census()
                .register_child(provider, 0, &worker_parent, || ReadyChild);
        completed_tx.send(()).unwrap();
        child
    });
    started_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert!(matches!(
        completed_rx.recv_timeout(std::time::Duration::from_millis(100)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    drop(metadata);
    completed_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let child = worker.join().unwrap().unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 1);
    assert_eq!(memory.storage_census().snapshot().readers, 1);
    assert_eq!(child.retire(), StorageCensusDisposition::Retired);
    assert_eq!(parent.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.snapshot().live_reservations, 0);
}

#[test]
fn poisoned_parent_metadata_fences_child_registration() {
    let memory = fixture_memory(2);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let parent = memory
        .storage_census()
        .register(provider.clone(), 0, || ReadyDatabase)
        .unwrap();
    let index = parent.id().index;
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _metadata = memory.storage_census().slots[index]
            .metadata
            .lock()
            .unwrap();
        panic!("poison parent census metadata");
    }));
    let constructed = AtomicBool::new(false);
    let error = memory
        .storage_census()
        .register_child(provider, 0, &parent, || {
            constructed.store(true, Ordering::Release);
            ReadyChild
        })
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!constructed.load(Ordering::Acquire));
    assert!(memory.storage_census().fenced.load(Ordering::Acquire));
    assert_eq!(memory.snapshot().live_reservations, 1);
}

#[test]
fn panicked_child_constructor_retains_parent_and_both_leases() {
    let memory = fixture_memory(2);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let parent = memory
        .storage_census()
        .register(provider.clone(), 0, || ReadyDatabase)
        .unwrap();
    assert!(
        memory
            .storage_census()
            .register_child::<ReadyChild, _>(provider, 0, &parent, || {
                std::panic::panic_any(177_u64)
            })
            .is_err()
    );
    assert_eq!(parent.retire(), StorageCensusDisposition::Retained);
    assert_eq!(memory.storage_census().snapshot().databases, 1);
    assert_eq!(memory.storage_census().snapshot().readers, 1);
    assert_eq!(memory.snapshot().live_reservations, 2);
}

#[test]
fn fixed_census_is_precharged_and_bound_to_the_exact_provider() {
    let memory = fixture_memory(2);
    assert_eq!(
        memory.snapshot().bookkeeping_bytes,
        TestDiskMemory::required_bookkeeping_bytes(2).unwrap()
    );
    assert_eq!(memory.snapshot().used_bytes, 0);
    assert_eq!(memory.storage_census().snapshot().capacity, 2);
    let foreign = fixture_memory(2);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = foreign.clone();
    let before = foreign.snapshot();
    let built = AtomicBool::new(false);
    let result = memory
        .storage_census()
        .register::<ActualOwner>(provider.clone(), 0, || {
            built.store(true, Ordering::Release);
            unreachable!()
        });
    assert!(result.is_err());
    assert!(!built.load(Ordering::Acquire));
    assert_eq!(foreign.snapshot(), before);
    assert!(memory.storage_census().bind_provider(&provider).is_err());
    assert!(StorageCensus::required_bytes(0).is_err());
    assert!(StorageCensus::required_bytes(usize::MAX).is_err());
}

#[test]
fn facade_cancellation_preserves_actual_owner_and_census_drives_later_retirement() {
    let memory = fixture_memory(1);
    let base = memory.snapshot();
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let ready = Arc::new(AtomicBool::new(false));
    let drops = Arc::new(AtomicUsize::new(0));
    let registration = memory
        .storage_census()
        .register(provider, 0, || ActualOwner {
            ready: ready.clone(),
            drops: drops.clone(),
            memory: memory.clone(),
        })
        .unwrap();
    let id = registration.id();
    let actual = std::ptr::from_ref(registration.owner());
    let held = memory.snapshot();
    assert!(held.used_bytes > base.used_bytes);
    assert_eq!(held.live_reservations, 1);
    drop(registration);
    assert_eq!(memory.storage_census().drain().unwrap().writers, 1);
    assert_eq!(drops.load(Ordering::Acquire), 0);
    assert_eq!(memory.snapshot(), held);
    {
        let metadata = memory.storage_census().slots[id.index]
            .metadata
            .lock()
            .unwrap();
        let Cell::Active { owner, .. } = &metadata.cell else {
            panic!("actual owner missing");
        };
        assert_eq!(Arc::as_ptr(owner).cast::<()>(), actual.cast::<()>());
    }
    ready.store(true, Ordering::Release);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retired
    );
    assert_eq!(drops.load(Ordering::Acquire), 1);
    assert_eq!(memory.snapshot().used_bytes, base.used_bytes);
    assert_eq!(memory.snapshot().live_reservations, 0);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Stale
    );
}

struct PanicOwner {
    cause: Mutex<Option<Panic>>,
    actual: Box<u64>,
    drops: Arc<AtomicUsize>,
}
impl StoragePayload for PanicOwner {
    const KIND: StorageOwnerKind = StorageOwnerKind::Database;
    fn drive(&self) -> bool {
        std::panic::resume_unwind(self.cause.lock().unwrap().take().unwrap())
    }
}
impl Drop for PanicOwner {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn settlement_unwind_keeps_the_actual_owner_and_exact_original_payload() {
    let memory = fixture_memory(1);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let original = Box::new(717_u64);
    let original_address = std::ptr::from_ref(original.as_ref());
    let drops = Arc::new(AtomicUsize::new(0));
    let registration = memory
        .storage_census()
        .register(provider, 0, || PanicOwner {
            cause: Mutex::new(Some(original)),
            actual: Box::new(919),
            drops: drops.clone(),
        })
        .unwrap();
    let id = registration.id();
    let actual_address = std::ptr::from_ref(registration.owner().actual.as_ref());
    let owner_address = std::ptr::from_ref(registration.owner());
    let held = memory.snapshot();
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_eq!(
        std::ptr::from_ref(registration.owner().actual.as_ref()),
        actual_address
    );
    assert_eq!(*registration.owner().actual, 919);
    drop(registration);
    assert_eq!(memory.snapshot(), held);
    assert_eq!(drops.load(Ordering::Acquire), 0);
    let observation = memory.storage_census().observation(id).unwrap();
    assert_eq!(observation.phase(), StorageCensusPanicPhase::Drive);
    assert_eq!(
        std::ptr::from_ref(observation.payload().downcast_ref::<u64>().unwrap()),
        original_address
    );
    drop(observation);
    {
        let metadata = memory.storage_census().slots[id.index]
            .metadata
            .lock()
            .unwrap();
        let Cell::Active { owner, .. } = &metadata.cell else {
            panic!("actual owner missing");
        };
        assert_eq!(Arc::as_ptr(owner).cast::<()>(), owner_address.cast::<()>());
    }
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_eq!(memory.storage_census().snapshot().retained_panics, 1);
    assert_eq!(drops.load(Ordering::Acquire), 0);
}

struct DestructorPanic {
    drops: Arc<AtomicUsize>,
}
impl StoragePayload for DestructorPanic {
    const KIND: StorageOwnerKind = StorageOwnerKind::Writer;
    fn drive(&self) -> bool {
        true
    }
}
impl Drop for DestructorPanic {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
        std::panic::panic_any(123_u64);
    }
}
#[test]
fn payload_destructor_panic_keeps_original_and_charge_and_never_replays() {
    let memory = fixture_memory(1);
    let drops = Arc::new(AtomicUsize::new(0));
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let registration = memory
        .storage_census()
        .register(provider, 0, || DestructorPanic {
            drops: drops.clone(),
        })
        .unwrap();
    let id = registration.id();
    let held = memory.snapshot();
    assert_eq!(registration.retire(), StorageCensusDisposition::Retained);
    assert_eq!(memory.snapshot(), held);
    let observation = memory.storage_census().observation(id).unwrap();
    assert_eq!(
        observation.phase(),
        StorageCensusPanicPhase::PayloadDisposal
    );
    assert_eq!(observation.payload().downcast_ref::<u64>(), Some(&123));
    drop(observation);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_eq!(drops.load(Ordering::Acquire), 1);
}

#[test]
fn hard_capacity_and_byte_denial_precede_owner_construction() {
    let base = TestDiskMemory::required_bookkeeping_bytes(1).unwrap();
    let owner_bytes = disk_memory::arc::<ActualOwner>().unwrap();
    let required = TestDiskMemory::required_reservation_bytes(owner_bytes).unwrap();
    let memory = TestDiskMemory::new(base + required - 1, 1);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let called = AtomicBool::new(false);
    assert!(
        memory
            .storage_census()
            .register::<ActualOwner>(provider, 0, || {
                called.store(true, Ordering::Release);
                unreachable!()
            })
            .is_err()
    );
    assert!(!called.load(Ordering::Acquire));
    assert_eq!(memory.snapshot().bookkeeping_bytes, base);
    assert_eq!(memory.snapshot().used_bytes, 0);
    assert_eq!(memory.storage_census().snapshot().writers, 0);
}

#[test]
fn constructor_unwind_is_classified_before_dispatch_and_keeps_exact_payload() {
    let memory = fixture_memory(1);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let original = Box::new(181_u64);
    let address = std::ptr::from_ref(original.as_ref());
    assert!(
        memory
            .storage_census()
            .register::<ActualOwner>(provider, 0, || { std::panic::resume_unwind(original) })
            .is_err()
    );
    let census = memory.storage_census();
    let snapshot = census.snapshot();
    assert_eq!(snapshot.writers, 1);
    assert_eq!(snapshot.databases, 0);
    assert_eq!(memory.snapshot().live_reservations, 1);
    let id = census.owner_at(0).unwrap();
    let report = census.observation(id).unwrap();
    assert_eq!(report.phase(), StorageCensusPanicPhase::Construction);
    assert_eq!(
        std::ptr::from_ref(report.payload().downcast_ref::<u64>().unwrap()),
        address
    );
    drop(report);
    assert_eq!(census.drain_owner(id), StorageCensusDisposition::Retained);
}

struct ReadyOwner(Arc<AtomicUsize>);
impl StoragePayload for ReadyOwner {
    const KIND: StorageOwnerKind = StorageOwnerKind::Writer;
    fn drive(&self) -> bool {
        true
    }
}
impl Drop for ReadyOwner {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}
#[test]
fn retained_original_observation_never_holds_metadata_or_stalls_another_owner() {
    let memory = fixture_memory(2);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let bad = memory
        .storage_census()
        .register(provider.clone(), 0, || DestructorPanic {
            drops: Arc::new(AtomicUsize::new(0)),
        })
        .unwrap();
    let id = bad.id();
    assert_eq!(bad.retire(), StorageCensusDisposition::Retained);
    let observation = memory.storage_census().observation(id).unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let good = memory
        .storage_census()
        .register(provider, 0, || ReadyOwner(drops.clone()))
        .unwrap();
    drop(good);
    let snapshot = memory.storage_census().drain().unwrap();
    assert_eq!(snapshot.writers, 1);
    assert_eq!(snapshot.retained_panics, 1);
    assert_eq!(drops.load(Ordering::Acquire), 1);
    assert_eq!(observation.payload().downcast_ref::<u64>(), Some(&123));
}

struct PausedDrive {
    entered: std::sync::mpsc::Sender<()>,
    resume: Mutex<std::sync::mpsc::Receiver<()>>,
    drops: Arc<AtomicUsize>,
}
impl StoragePayload for PausedDrive {
    const KIND: StorageOwnerKind = StorageOwnerKind::Writer;
    fn drive(&self) -> bool {
        self.entered.send(()).unwrap();
        self.resume.lock().unwrap().recv().unwrap();
        true
    }
}
impl Drop for PausedDrive {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}
#[test]
fn post_drive_metadata_contention_keeps_completion_in_fixed_slot_without_waiting() {
    // The synthetic pause positions another thread at the exact post-effect
    // metadata boundary; concrete production drivers use try_lock themselves.
    let memory = fixture_memory(1);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let (entered, observed) = std::sync::mpsc::channel();
    let (resume, receiver) = std::sync::mpsc::channel();
    let drops = Arc::new(AtomicUsize::new(0));
    let registration = memory
        .storage_census()
        .register(provider, 0, || PausedDrive {
            entered,
            resume: Mutex::new(receiver),
            drops: drops.clone(),
        })
        .unwrap();
    let id = registration.id();
    drop(registration);
    let worker_memory = memory.clone();
    let worker = std::thread::spawn(move || worker_memory.storage_census().drain_owner(id));
    observed
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let metadata = memory.storage_census().slots[id.index]
        .metadata
        .lock()
        .unwrap();
    resume.send(()).unwrap();
    assert_eq!(worker.join().unwrap(), StorageCensusDisposition::Retained);
    assert_eq!(
        memory.storage_census().slots[id.index]
            .pending
            .load(Ordering::Acquire),
        DRIVE_SETTLED
    );
    assert!(matches!(
        metadata.cell,
        Cell::Active {
            servicing: true,
            ..
        }
    ));
    assert_eq!(drops.load(Ordering::Acquire), 0);
    assert_eq!(memory.snapshot().live_reservations, 1);
    drop(metadata);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retired
    );
    assert_eq!(drops.load(Ordering::Acquire), 1);
}
