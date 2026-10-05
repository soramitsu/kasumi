//! Exact paid slots preserve a second original after destructive retirement.
use super::*;
use crate::test_utils::TestDiskMemory;
use kasumi_kv::TerminalObservation;
use std::sync::atomic::AtomicUsize;

struct Parent;
impl StoragePayload for Parent {
    const KIND: StorageOwnerKind = StorageOwnerKind::Database;
    fn drive(&self) -> bool {
        true
    }
}
struct Writer {
    drops: Arc<AtomicUsize>,
    panic: Option<Box<u64>>,
}
impl StoragePayload for Writer {
    const KIND: StorageOwnerKind = StorageOwnerKind::Writer;
    fn drive(&self) -> bool {
        true
    }
}
impl Drop for Writer {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
        if let Some(original) = self.panic.take() {
            std::panic::resume_unwind(original);
        }
    }
}
struct Output {
    drops: Arc<AtomicUsize>,
    panic: Option<Box<u64>>,
}
impl Drop for Output {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
        if let Some(original) = self.panic.take() {
            std::panic::resume_unwind(original);
        }
    }
}
fn assert_output_panic(census: &StorageCensus, id: StorageOwnerId, address: usize, value: u64) {
    let report = census.write_output_observation(id).unwrap();
    let TerminalObservation::Panicked(original) = report.disposal() else {
        panic!("original output disposal panic absent");
    };
    let original = original.downcast_ref::<u64>().unwrap();
    assert_eq!(*original, value);
    assert_eq!(std::ptr::from_ref(original) as usize, address);
}

#[test]
fn payload_destruction_refusal_preserves_second_output_original_in_same_paid_slot() {
    let memory = TestDiskMemory::new(1 << 20, 2);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let parent = memory
        .storage_census()
        .register_native(provider.clone(), 0, |_| Parent)
        .unwrap();
    let original = Box::new(0x0a11_u64);
    let address = std::ptr::from_ref(original.as_ref()) as usize;
    let writer_drops = Arc::new(AtomicUsize::new(0));
    let writer = memory
        .storage_census()
        .register_write_child(provider, 0, &parent, || Writer {
            drops: writer_drops.clone(),
            panic: Some(original),
        })
        .unwrap();
    let id = writer.id();
    let held = memory.snapshot();
    assert_eq!(writer.retire(), StorageCensusDisposition::Retained);
    assert!(!memory.storage_census().write_retirement_completed(id));
    let original = memory.storage_census().observation(id).unwrap();
    assert_eq!(original.phase(), StorageCensusPanicPhase::PayloadDisposal);
    assert_eq!(
        std::ptr::from_ref(original.payload().downcast_ref::<u64>().unwrap()) as usize,
        address
    );
    drop(original);
    let second = Box::new(0x0b22_u64);
    let second_address = std::ptr::from_ref(second.as_ref()) as usize;
    let output_drops = Arc::new(AtomicUsize::new(0));
    memory.storage_census().dispose_write_output(
        id,
        Output {
            drops: output_drops.clone(),
            panic: Some(second),
        },
    );
    assert_output_panic(memory.storage_census(), id, second_address, 0x0b22);
    assert_eq!(memory.snapshot(), held);
    assert_eq!(memory.storage_census().snapshot().retained_panics, 2);
    assert_eq!(writer_drops.load(Ordering::Acquire), 1);
    assert_eq!(output_drops.load(Ordering::Acquire), 1);
    assert_eq!(parent.retire(), StorageCensusDisposition::Retained);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_output_panic(memory.storage_census(), id, second_address, 0x0b22);
    assert_eq!(memory.snapshot().attempts, held.attempts);
}

#[test]
fn opaque_lease_retirement_refusal_preserves_second_output_original_and_parent_generation() {
    let memory = TestDiskMemory::new(1 << 20, 2);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let parent = memory
        .storage_census()
        .register_native(provider.clone(), 0, |_| Parent)
        .unwrap();
    let parent_id = parent.id();
    let writer_drops = Arc::new(AtomicUsize::new(0));
    let writer = memory
        .storage_census()
        .register_write_child(provider, 0, &parent, || Writer {
            drops: writer_drops.clone(),
            panic: None,
        })
        .unwrap();
    let id = writer.id();
    let first = Box::new(0x1ea5e_u64);
    let first_address = std::ptr::from_ref(first.as_ref()) as usize;
    memory.panic_on_last_point_lease_drop(first);
    let attempts = memory.snapshot().attempts;
    assert_eq!(writer.retire(), StorageCensusDisposition::Retained);
    assert_eq!(writer_drops.load(Ordering::Acquire), 1);
    assert!(!memory.storage_census().write_retirement_completed(id));
    let first = memory.storage_census().observation(id).unwrap();
    assert_eq!(first.phase(), StorageCensusPanicPhase::LeaseRetirement);
    assert_eq!(
        std::ptr::from_ref(first.payload().downcast_ref::<u64>().unwrap()) as usize,
        first_address
    );
    drop(first);
    let second = Box::new(0x007_u64);
    let second_address = std::ptr::from_ref(second.as_ref()) as usize;
    let output_drops = Arc::new(AtomicUsize::new(0));
    memory.storage_census().dispose_write_output(
        id,
        Output {
            drops: output_drops.clone(),
            panic: Some(second),
        },
    );
    assert_output_panic(memory.storage_census(), id, second_address, 0x007);
    assert_eq!(parent.retire(), StorageCensusDisposition::Retained);
    assert_eq!(
        memory.storage_census().owner_at(parent_id.index),
        Some(parent_id)
    );
    assert_eq!(memory.storage_census().snapshot().retained_panics, 2);
    assert_eq!(memory.snapshot().attempts, attempts);
    assert_eq!(output_drops.load(Ordering::Acquire), 1);
}

#[test]
fn held_metadata_completion_tail_accepts_only_both_actual_retirement_callbacks() {
    let memory = TestDiskMemory::new(1 << 20, 2);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let parent = memory
        .storage_census()
        .register_native(provider.clone(), 0, |_| Parent)
        .unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let writer = memory
        .storage_census()
        .register_write_child(provider, 0, &parent, || Writer {
            drops: drops.clone(),
            panic: None,
        })
        .unwrap();
    let id = writer.id();
    assert!(!memory.storage_census().hand_off_write_output(id));
    let (start_tx, start_rx) = std::sync::mpsc::sync_channel(0);
    let (held_tx, held_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let worker_memory = memory.clone();
    let worker = std::thread::spawn(move || {
        start_rx.recv().unwrap();
        worker_memory
            .storage_census()
            .with_owner_metadata_held_for_test(id, || {
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
    });
    *memory.storage_census().slots[id.index]
        .after_write_lease_retirement
        .lock()
        .unwrap() = Some(Box::new(move || {
        start_tx.send(()).unwrap();
        held_rx.recv().unwrap();
    }));
    let attempts = memory.snapshot().attempts;
    assert_eq!(writer.retire(), StorageCensusDisposition::Retained);
    assert_eq!(drops.load(Ordering::Acquire), 1);
    assert_eq!(
        memory.snapshot().live_reservations,
        1,
        "only the exact parent grant remains"
    );
    assert!(memory.storage_census().write_retirement_completed(id));
    assert!(memory.storage_census().hand_off_write_output(id));
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    release_tx.send(()).unwrap();
    worker.join().unwrap();
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retired
    );
    assert_eq!(memory.snapshot().attempts, attempts);
    assert_eq!(parent.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.snapshot().live_reservations, 0);
}
