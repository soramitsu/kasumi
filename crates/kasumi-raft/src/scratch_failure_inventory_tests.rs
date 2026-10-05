use super::*;
use crate::selected_application::allocation_tests::{
    DeallocationObservation, observe_deallocation, observe_last_allocation, require_no_allocations,
};
use kasumi_store::{
    DiskMemoryLease, EncryptedTable, NodeDiskMemoryAdmission, ScratchDisk,
    StorageCensusDisposition, test_utils::TestDiskMemory,
};
use std::sync::atomic::AtomicUsize;

struct RootCharge {
    original: Option<DiskMemoryLease>,
    retired: Arc<AtomicUsize>,
    backing: Arc<DeallocationObservation>,
}
impl Drop for RootCharge {
    fn drop(&mut self) {
        assert!(
            self.backing.finished(),
            "actual inventory backing precedes original refund"
        );
        self.retired.fetch_add(1, Ordering::AcqRel);
        drop(self.original.take());
    }
}

fn root_charge(
    memory: &Arc<TestDiskMemory>,
    capacity: usize,
    retired: Arc<AtomicUsize>,
    backing: Arc<DeallocationObservation>,
) -> (kasumi_types::SharedBudgetCharge, usize) {
    let root_layout = kasumi_types::SharedBudgetCharge::allocation_layout::<RootCharge>().unwrap();
    let bytes = ScratchFailureInventory::required_bytes(capacity)
        .unwrap()
        .checked_add(allocation_bytes(root_layout).unwrap())
        .unwrap();
    let original = memory.clone().reserve_installed(bytes).unwrap();
    let (charge, control, allocations) = observe_last_allocation(|| {
        kasumi_types::SharedBudgetCharge::new(RootCharge {
            original: Some(original),
            retired,
            backing,
        })
    });
    assert_eq!(allocations, 1);
    (charge, control)
}

fn simple_charge(
    memory: &Arc<TestDiskMemory>,
    capacity: usize,
) -> kasumi_types::SharedBudgetCharge {
    let layout = kasumi_types::SharedBudgetCharge::allocation_layout::<DiskMemoryLease>().unwrap();
    let bytes = ScratchFailureInventory::required_bytes(capacity)
        .unwrap()
        .checked_add(allocation_bytes(layout).unwrap())
        .unwrap();
    kasumi_types::SharedBudgetCharge::new(memory.clone().reserve_installed(bytes).unwrap())
}

#[test]
fn prepaid_inventory_actual_controls_and_vec_retire_before_original_root_refund() {
    for observed_backing in 0..3 {
        let memory = TestDiskMemory::new(64 << 20, 32);
        let baseline = memory.snapshot();
        let retired = Arc::new(AtomicUsize::new(0));
        let observer = Arc::new(DeallocationObservation::new(false));
        let (charge, charge_control) = root_charge(&memory, 3, retired.clone(), observer.clone());
        let (inventory, control, allocations) =
            observe_last_allocation(|| ScratchFailureInventory::new(3, charge).unwrap());
        // One actual Vec, three independent Store slot controls and one closed
        // inventory control are all constructed after the original root grant.
        assert_eq!(allocations, 5);
        assert_eq!(inventory.capacity(), 3);
        let quoted = ScratchFailureInventory::required_bytes(3).unwrap();
        let actual = control_layout().unwrap().size() + Layout::array::<Seat>(3).unwrap().size();
        assert!(quoted >= actual as u64 + 3 * ScratchAdmissionSlot::required_bytes().unwrap());
        let address = match observed_backing {
            0 => control,
            1 => inventory.inner().seats.as_ptr() as usize,
            2 => charge_control,
            _ => unreachable!(),
        };
        let alias = require_no_allocations(|| inventory.clone());
        let first = require_no_allocations(|| inventory.acquire().unwrap());
        let second = require_no_allocations(|| alias.acquire().unwrap());
        assert_ne!(first.index(), second.index());
        assert!(inventory.active());
        assert!(inventory.retirement_blocked());
        assert_eq!(retired.load(Ordering::Acquire), 0);
        assert_eq!(
            require_no_allocations(|| first.capture_result(Ok(17))).unwrap(),
            17
        );
        assert_eq!(
            require_no_allocations(|| second.capture_result(Ok(19))).unwrap(),
            19
        );
        assert!(!inventory.retirement_blocked());
        drop(inventory);
        assert_eq!(retired.load(Ordering::Acquire), 0);
        observe_deallocation(address, &observer, || drop(alias));
        assert!(observer.finished());
        assert_eq!(observer.count(), 1);
        assert_eq!(retired.load(Ordering::Acquire), 1);
        assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
        assert_eq!(
            memory.snapshot().live_reservations,
            baseline.live_reservations
        );
    }
}

#[test]
fn full_inventory_refuses_before_constructor_without_allocating_or_acquiring_memory() {
    let memory = TestDiskMemory::new(64 << 20, 32);
    let inventory = ScratchFailureInventory::new(2, simple_charge(&memory, 2)).unwrap();
    let first = require_no_allocations(|| inventory.acquire().unwrap());
    let second = require_no_allocations(|| inventory.acquire().unwrap());
    assert_ne!(first.index(), second.index());
    let before = memory.snapshot();
    assert!(matches!(
        require_no_allocations(|| inventory.acquire()),
        Err(ScratchInventoryRefusal::Busy)
    ));
    assert_eq!(memory.snapshot(), before);
    drop(first);
    let replacement = require_no_allocations(|| inventory.acquire().unwrap());
    assert_ne!(replacement.index(), second.index());
    drop(replacement);
    drop(second);
    assert!(!inventory.retirement_blocked());
}

#[test]
fn sealed_inventory_refuses_new_jobs_while_accepted_guard_retains_original_charge() {
    let memory = TestDiskMemory::new(64 << 20, 32);
    let baseline = memory.snapshot();
    let inventory = ScratchFailureInventory::new(2, simple_charge(&memory, 2)).unwrap();
    let guard = require_no_allocations(|| inventory.acquire().unwrap());
    let admitted = memory.snapshot();
    require_no_allocations(|| inventory.seal());
    assert!(inventory.active());
    assert!(inventory.retirement_blocked());
    assert!(matches!(
        require_no_allocations(|| inventory.acquire()),
        Err(ScratchInventoryRefusal::Sealed)
    ));
    assert_eq!(memory.snapshot(), admitted);
    drop(inventory);
    assert_eq!(memory.snapshot(), admitted);
    assert_eq!(guard.capture_result(Ok(23)).unwrap(), 23);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[test]
fn actual_first_quote_refusal_stays_in_prepaid_seat_after_foreign_result_disappears() {
    let memory = TestDiskMemory::new(64 << 20, 32);
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let inventory = ScratchFailureInventory::new(2, simple_charge(&memory, 2)).unwrap();
    let before_fill = memory.snapshot();
    let mut fillers: [Option<DiskMemoryLease>; 32] = std::array::from_fn(|_| None);
    for slot in fillers.iter_mut().take(32 - before_fill.live_reservations) {
        *slot = Some(memory.clone().reserve_installed(0).unwrap());
    }
    let full = memory.snapshot();
    let disk_before = disk.snapshot();
    let census_before = memory.storage_census().snapshot();
    let guard = require_no_allocations(|| inventory.acquire().unwrap());
    let index = guard.index();
    let original = EncryptedTable::new(&disk, 8 << 20, kasumi_kv::CacheConfig { byte_limit: 0 })
        .err()
        .expect("the original first census quote must remain refused");
    assert_eq!(original.owner_id(), None);
    let returned = require_no_allocations(|| {
        guard.capture_result::<()>(Err(ScratchOperationFailure::Creation(original)))
    })
    .unwrap_err();
    assert!(returned.creation().is_some());
    assert!(inventory.occupied());
    assert!(!inventory.active());
    assert!(inventory.retirement_blocked());
    let address = returned.creation().unwrap().with_diagnostic(|report| {
        let report = report.unwrap();
        let original = report.admission_error().unwrap();
        assert_eq!(original.kind(), io::ErrorKind::OutOfMemory);
        assert!(report.opening_error().is_none());
        std::ptr::from_ref(original) as usize
    });
    drop(returned);
    for _ in 0..3 {
        let facade = require_no_allocations(|| inventory.original_failure(index).unwrap());
        assert_eq!(facade.owner_id(), None);
        assert_eq!(
            facade.with_diagnostic(|report| {
                std::ptr::from_ref(report.unwrap().admission_error().unwrap()) as usize
            }),
            address
        );
        assert_eq!(
            facade.retire().disposition(),
            StorageCensusDisposition::Retained
        );
    }
    let free = require_no_allocations(|| inventory.acquire().unwrap());
    assert_ne!(free.index(), index);
    let Err(ScratchInventoryRefusal::Occupied(original)) =
        require_no_allocations(|| inventory.acquire())
    else {
        panic!("an exhausted inventory must return its same retained original");
    };
    assert_eq!(
        original.with_diagnostic(|report| {
            std::ptr::from_ref(report.unwrap().admission_error().unwrap()) as usize
        }),
        address
    );
    drop(original);
    drop(free);
    let after = memory.snapshot();
    assert_eq!(after.attempts, full.attempts + 1);
    assert_eq!(after.used_bytes, full.used_bytes);
    assert_eq!(after.live_reservations, full.live_reservations);
    assert_eq!(memory.storage_census().snapshot(), census_before);
    assert_eq!(disk.snapshot().live_files, disk_before.live_files);
    assert_eq!(disk.snapshot().charged_bytes, disk_before.charged_bytes);
    drop(fillers);
    let retained = memory.snapshot();
    drop(inventory);
    assert_eq!(memory.snapshot(), retained);
}

#[test]
fn registered_creation_original_passes_through_empty_seat_without_replacement() {
    let memory = TestDiskMemory::new(64 << 20, 32);
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let inventory = ScratchFailureInventory::new(1, simple_charge(&memory, 1)).unwrap();
    let baseline = memory.snapshot();
    let original = EncryptedTable::new(&disk, u64::MAX, kasumi_kv::CacheConfig { byte_limit: 0 })
        .err()
        .expect("actual registered extent acquisition must fail");
    let id = original.owner_id().unwrap();
    let address = original.with_diagnostic(|report| {
        std::ptr::from_ref(report.unwrap().admission_error().unwrap()) as usize
    });
    let guard = require_no_allocations(|| inventory.acquire().unwrap());
    let returned = require_no_allocations(|| {
        guard.capture_result::<()>(Err(ScratchOperationFailure::Creation(original)))
    })
    .unwrap_err();
    let ScratchOperationFailure::Creation(original) = returned else {
        panic!("registered constructor failure must stay typed");
    };
    assert_eq!(original.owner_id(), Some(id));
    assert_eq!(
        original.with_diagnostic(|report| {
            std::ptr::from_ref(report.unwrap().admission_error().unwrap()) as usize
        }),
        address
    );
    assert!(!inventory.retirement_blocked());
    assert!(inventory.original_failure(0).is_none());
    assert_eq!(
        original.retire().disposition(),
        StorageCensusDisposition::Retired
    );
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
}
