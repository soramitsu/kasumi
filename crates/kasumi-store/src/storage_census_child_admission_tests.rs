use super::*;
use crate::test_utils::TestDiskMemory;
use std::time::Duration;

struct Database;
impl StoragePayload for Database {
    const KIND: StorageOwnerKind = StorageOwnerKind::Database;
    fn drive(&self) -> bool {
        true
    }
}
struct Reader;
impl StoragePayload for Reader {
    const KIND: StorageOwnerKind = StorageOwnerKind::Reader;
    fn drive(&self) -> bool {
        true
    }
}
impl NativeStartupChild for Reader {
    const PURPOSE: NativeStartupChildPurpose = NativeStartupChildPurpose::Verification;
    fn report_bytes() -> io::Result<u64> {
        Ok(0)
    }
    fn abandon_delivery(&self) {}
}

// The hook only parks after a real child count preclaim. Actual provider
// admission and cell construction run unchanged once the schedule is released.
fn held_child_claim_is_counted_through_seal(capacity: usize) {
    let memory = TestDiskMemory::new(1 << 20, capacity);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let parent = memory
        .storage_census()
        .register_native(provider.clone(), 0, |_| Database)
        .unwrap();
    let id = parent.id();
    assert!(
        !memory.storage_census().children_retired(id),
        "zero before seal is not completion"
    );
    let worker_memory = memory.clone();
    let worker_parent = parent.clone();
    let (claimed, claim_seen) = std::sync::mpsc::sync_channel(0);
    let (release, released) = std::sync::mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        CHILD_PRECLAIM_OBSERVER.with(|observer| {
            *observer.borrow_mut() = Some(Box::new(move || {
                claimed.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(5)).unwrap();
            }));
        });
        worker_memory.storage_census().register_child(
            worker_memory.clone(),
            0,
            &worker_parent,
            || Reader,
        )
    });
    claim_seen.recv_timeout(Duration::from_secs(5)).unwrap();
    // Sealing succeeds while the actual provider step is paused: no parent
    // metadata lock escaped into provider/cell work, and the count is already 1.
    memory.storage_census().seal_child_admission(id).unwrap();
    assert_eq!(memory.storage_census().child_count_for_test(id), Some(1));
    assert!(!memory.storage_census().children_retired(id));
    let attempts = memory.snapshot().attempts;
    let denied = memory
        .storage_census()
        .register_child::<Reader, _>(provider.clone(), 0, &parent, || {
            panic!("sealed constructor entered")
        })
        .err()
        .unwrap();
    assert_eq!(denied.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(
        memory.snapshot().attempts,
        attempts,
        "sealed ordinary claim never reaches provider"
    );
    let native = memory
        .storage_census()
        .register_native_startup_child::<Reader, _>(
            provider,
            &parent,
            |_| panic!("sealed native claim published"),
            |_| panic!("sealed native constructor entered"),
        )
        .err()
        .unwrap();
    assert!(native.id().is_none());
    assert_eq!(
        memory.snapshot().attempts,
        attempts,
        "sealed native claim never reaches provider"
    );
    release.send(()).unwrap();
    let result = worker.join().unwrap();
    if capacity == 1 {
        assert!(
            result.is_err(),
            "actual native capacity refuses unpublished child"
        );
    } else {
        let child = result.unwrap();
        assert!(!memory.storage_census().children_retired(id));
        assert_eq!(memory.storage_census().child_count_for_test(id), Some(1));
        assert_eq!(child.retire(), StorageCensusDisposition::Retired);
    }
    assert!(memory.storage_census().children_retired(id));
    assert_eq!(parent.retire(), StorageCensusDisposition::Retired);
    assert!(
        !memory.storage_census().children_retired(id),
        "missing owner is not an exact witness"
    );
    let next = memory
        .storage_census()
        .register_native(memory.clone(), 0, |_| Database)
        .unwrap();
    assert_eq!(next.id().index, id.index);
    assert_ne!(next.id().generation, id.generation);
    assert!(
        !memory.storage_census().children_retired(next.id()),
        "new generation does not inherit seal"
    );
    assert_eq!(
        memory
            .storage_census()
            .seal_child_admission(id)
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    memory
        .storage_census()
        .seal_child_admission(next.id())
        .unwrap();
    assert!(memory.storage_census().children_retired(next.id()));
    assert_eq!(next.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.snapshot().live_reservations, 0);
}

#[test]
fn sealed_parent_waits_for_actual_late_child_publication_and_retirement() {
    held_child_claim_is_counted_through_seal(3);
}
#[test]
fn sealed_parent_waits_for_actual_unpublished_child_capacity_rollback() {
    held_child_claim_is_counted_through_seal(1);
}

struct RetainedReader {
    released: Arc<AtomicBool>,
    original: Arc<u64>,
}
impl StoragePayload for RetainedReader {
    const KIND: StorageOwnerKind = StorageOwnerKind::Reader;
    fn drive(&self) -> bool {
        self.released.load(Ordering::Acquire)
    }
}
#[test]
fn sealed_parent_cannot_complete_while_original_child_is_retained() {
    let memory = TestDiskMemory::new(1 << 20, 3);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let parent = memory
        .storage_census()
        .register_native(provider.clone(), 0, |_| Database)
        .unwrap();
    let original = Arc::new(0xfeed_u64);
    let released = Arc::new(AtomicBool::new(false));
    let child = memory
        .storage_census()
        .register_child(provider, 0, &parent, || RetainedReader {
            released: released.clone(),
            original: original.clone(),
        })
        .unwrap();
    let id = child.id();
    memory
        .storage_census()
        .seal_child_admission(parent.id())
        .unwrap();
    assert_eq!(child.retire(), StorageCensusDisposition::Retained);
    assert!(!memory.storage_census().children_retired(parent.id()));
    let same = memory
        .storage_census()
        .retained::<RetainedReader>(memory.clone(), id)
        .unwrap();
    assert!(Arc::ptr_eq(&same.owner().original, &original));
    assert_eq!(
        memory.storage_census().child_count_for_test(parent.id()),
        Some(1)
    );
    released.store(true, Ordering::Release);
    assert_eq!(same.retire(), StorageCensusDisposition::Retired);
    assert!(memory.storage_census().children_retired(parent.id()));
    assert_eq!(parent.retire(), StorageCensusDisposition::Retired);
}
