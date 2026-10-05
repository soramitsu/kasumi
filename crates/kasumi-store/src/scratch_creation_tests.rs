use super::*;
use crate::{
    DiskMemoryLease, NativeConstructorProbe, NodeDiskMemoryAdmission, test_utils::TestDiskMemory,
};

const CACHE: CacheConfig = CacheConfig { byte_limit: 0 };

// This concrete, native-free test parent uses the real census lease protocol.
// Its extra backing quote funds the actual Slot allocation before Slot::new.
struct AdmissionParent;
impl StoragePayload for AdmissionParent {
    const KIND: StorageOwnerKind = StorageOwnerKind::Database;
    fn drive(&self) -> bool {
        true
    }
}
fn admission_slot(
    memory: &Arc<TestDiskMemory>,
) -> (ScratchAdmissionSlot, StorageRegistration<AdmissionParent>) {
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let parent = memory
        .storage_census()
        .register_native(
            provider,
            ScratchAdmissionSlot::required_bytes()
                .unwrap()
                .checked_add(
                    kasumi_types::SharedBudgetCharge::required_bytes::<Arc<AdmissionParent>>()
                        .unwrap(),
                )
                .unwrap(),
            |_| AdmissionParent,
        )
        .unwrap();
    // The census independently owns the original parent lease; this typed
    // native-free payload only retains that exact parent until slot retirement.
    let charge = kasumi_types::SharedBudgetCharge::new(parent.owner_arc());
    let (slot, allocations) =
        crate::allocation_tests::measure(|| ScratchAdmissionSlot::new(charge));
    assert_eq!(allocations, 1);
    (slot, parent)
}
fn initial_admission_identity(original: &ScratchCreationFailure) -> usize {
    assert_eq!(original.owner_id(), None);
    original.with_diagnostic(|report| {
        let report = report.unwrap();
        let original = report.admission_error().unwrap();
        assert_eq!(original.kind(), io::ErrorKind::WouldBlock);
        assert!(report.constructor_report().is_none());
        assert!(report.opening_error().is_none());
        assert!(report.setup_begin().is_none());
        assert!(report.setup_terminal().is_none());
        assert!(report.panic().is_none());
        original as *const io::Error as usize
    })
}

#[test]
fn empty_admission_slot_retires_actual_control_before_parent_charge() {
    let memory = TestDiskMemory::new(64 << 20, 32);
    let before = memory.snapshot();
    let (slot, parent) = admission_slot(&memory);
    let id = parent.id();
    assert!(!slot.occupied());
    assert!(slot.original_failure().is_none());
    let alias = slot.clone();
    assert_eq!(parent.retire(), StorageCensusDisposition::Retained);
    drop(slot);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    drop(alias);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retired
    );
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        before.live_reservations
    );
}

#[test]
fn prepaid_initial_refusal_survives_worker_cancellation_and_exact_facade_drop() {
    let memory = TestDiskMemory::new(64 << 20, 32);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let before = memory.snapshot();
    let (slot, parent) = admission_slot(&memory);
    let id = parent.id();
    let prepaid = memory.snapshot();
    assert_eq!(prepaid.live_reservations, before.live_reservations + 1);
    let parent_census = memory.storage_census().snapshot();
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let mut receivers: [Option<NativeConstructorProbe>; 32] = std::array::from_fn(|_| None);
    for receiver in receivers
        .iter_mut()
        .take(parent_census.capacity - parent_census.databases)
    {
        *receiver = Some(NativeConstructorProbe::prepare(provider.clone(), 0).unwrap());
    }
    // The constructor's original fixed receivers consume census capacity
    // without entering the provider or creating any native backing.
    assert_eq!(memory.snapshot(), prepaid);
    let mut fillers: [Option<DiskMemoryLease>; 32] = std::array::from_fn(|_| None);
    for filler in fillers.iter_mut().take(32 - prepaid.live_reservations) {
        *filler = Some(memory.clone().reserve_installed(0).unwrap());
    }
    let filled = memory.snapshot();
    assert_eq!(filled.live_reservations, 32);
    let census = memory.storage_census().snapshot();
    assert_eq!(census.databases, census.capacity);
    let disk_before = disk.snapshot();
    let address;
    {
        // This actual worker is refused before the native receiver can claim
        // a seat or call the provider. Its whole original then survives in the
        // separately prepaid admission slot when the worker is cancelled.
        let worker = async {
            let original = EncryptedTable::new(&disk, 8 << 20, CACHE)
                .err()
                .expect("filled provider unexpectedly constructed scratch");
            assert!(matches!(&original.custody, Custody::Admission(_)));
            let (original, allocations) =
                crate::allocation_tests::measure(|| slot.capture(original).unwrap());
            assert_eq!(allocations, 0);
            std::future::pending::<()>().await;
            original
        };
        let mut worker = std::pin::pin!(worker);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(std::future::Future::poll(worker.as_mut(), &mut context).is_pending());
        assert!(slot.occupied());
        address = initial_admission_identity(&slot.original_failure().unwrap());
        assert_eq!(memory.snapshot().attempts, filled.attempts);
    }
    // Cancellation destroyed only the future's facade. The exact error and
    // original backing charge remain available after all returned aliases die.
    let after_cancel = memory.snapshot();
    assert_eq!(Arc::strong_count(&slot.state), 2);
    assert_eq!(after_cancel.used_bytes, filled.used_bytes);
    assert_eq!(after_cancel.live_reservations, filled.live_reservations);
    assert_eq!(memory.storage_census().snapshot(), census);
    assert_eq!(disk.snapshot().live_files, disk_before.live_files);
    assert_eq!(disk.snapshot().charged_bytes, disk_before.charged_bytes);
    for _ in 0..3 {
        let (original, allocations) =
            crate::allocation_tests::measure(|| slot.original_failure().unwrap());
        assert_eq!(allocations, 0);
        assert_eq!(initial_admission_identity(&original), address);
        let retirement = original.retire();
        assert_eq!(retirement.disposition(), StorageCensusDisposition::Retained);
        assert_eq!(retirement.retry(), StorageCensusDisposition::Retained);
        retirement.with_diagnostic(|report| {
            assert_eq!(
                report.unwrap().admission_error().unwrap() as *const io::Error as usize,
                address
            );
        });
        drop(retirement);
        assert_eq!(Arc::strong_count(&slot.state), 2);
        assert_eq!(memory.snapshot(), after_cancel);
    }

    // A second actual preclaim refusal cannot overwrite the occupied seat.
    let second = EncryptedTable::new(&disk, 8 << 20, CACHE)
        .err()
        .expect("occupied refusal control unexpectedly constructed scratch");
    let second = slot.capture(second).unwrap_err();
    assert!(matches!(&second.custody, Custody::Admission(_)));
    initial_admission_identity(&second);
    assert_eq!(
        initial_admission_identity(&slot.original_failure().unwrap()),
        address
    );
    assert_eq!(memory.snapshot().attempts, filled.attempts);
    assert_eq!(memory.storage_census().snapshot(), census);
    drop(second);
    let mut refused_receivers = 0;
    for receiver in receivers.iter_mut().filter_map(Option::take) {
        // Each same receiver enters its actual provider exactly once while
        // grants remain saturated. Its original certified refusal is observed
        // before explicit diagnostic and lease cleanup releases that seat.
        assert!(!receiver.run());
        receiver.with_report(|report| {
            assert!(report.capacity_refused());
            assert_eq!(report.protocol(), None);
            assert!(!report.has_lease());
            assert!(!report.has_payload());
            assert!(matches!(
                report.provider(),
                TerminalObservation::Returned(Err(original))
                    if original.kind() == io::ErrorKind::OutOfMemory
            ));
            assert!(matches!(
                report.construction(),
                TerminalObservation::NotEntered
            ));
        });
        assert_eq!(receiver.cleanup(), StorageCensusDisposition::Retired);
        refused_receivers += 1;
    }
    assert_eq!(refused_receivers, census.capacity - parent_census.databases);
    assert_eq!(
        memory.snapshot().attempts,
        filled.attempts + refused_receivers as u64
    );
    assert_eq!(memory.storage_census().snapshot(), parent_census);
    drop(fillers);
    assert_eq!(memory.snapshot().used_bytes, prepaid.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        prepaid.live_reservations
    );

    // The occupied admission seat also cannot consume a registered failure.
    let registered = EncryptedTable::new(&disk, u64::MAX, CACHE)
        .err()
        .expect("registered passthrough control unexpectedly constructed scratch");
    let registered_id = registered.owner_id().unwrap();
    let registered_address = acquisition_identity(&registered);
    let (registered, allocations) =
        crate::allocation_tests::measure(|| slot.capture(registered).unwrap());
    assert_eq!(allocations, 0);
    assert_eq!(registered.owner_id(), Some(registered_id));
    assert_eq!(acquisition_identity(&registered), registered_address);
    assert_eq!(
        registered.retire().disposition(),
        StorageCensusDisposition::Retired
    );
    assert_eq!(memory.snapshot().used_bytes, prepaid.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        prepaid.live_reservations
    );
    assert_eq!(disk.snapshot().live_files, disk_before.live_files);

    assert_eq!(parent.retire(), StorageCensusDisposition::Retained);
    let observer = slot.clone();
    drop(slot);
    assert_eq!(
        initial_admission_identity(&observer.original_failure().unwrap()),
        address
    );
    drop(observer);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_eq!(memory.snapshot().used_bytes, prepaid.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        prepaid.live_reservations
    );
}

#[test]
fn constructor_quote_refusal_precedes_root_and_native_effects() {
    let memory = TestDiskMemory::new(64 << 20, 32);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let before = memory.snapshot();
    let mut fillers: [Option<DiskMemoryLease>; 32] = std::array::from_fn(|_| None);
    for slot in fillers.iter_mut().take(32 - before.live_reservations) {
        *slot = Some(memory.clone().reserve_installed(0).unwrap());
    }
    let filled = memory.snapshot();
    assert_eq!(filled.live_reservations, 32);
    let census = memory.storage_census().snapshot();
    let disk_before = disk.snapshot();
    let original = EncryptedTable::new(&disk, 8 << 20, CACHE)
        .err()
        .expect("scratch quote refusal unexpectedly constructed a table");
    let id = original
        .owner_id()
        .expect("actual native receiver was claimed");
    let address = original.with_diagnostic(|report| {
        let report = report.unwrap();
        let constructor = report.constructor_report().unwrap();
        assert!(constructor.capacity_refused());
        assert_eq!(constructor.protocol(), None);
        assert!(!constructor.has_lease());
        assert!(!constructor.has_payload());
        assert!(matches!(
            constructor.construction(),
            TerminalObservation::NotEntered
        ));
        assert!(matches!(
            constructor.provider(),
            TerminalObservation::Returned(Err(error))
                if std::ptr::eq(error, report.admission_error().unwrap())
        ));
        assert_eq!(
            report.admission_error().unwrap().kind(),
            io::ErrorKind::OutOfMemory
        );
        assert!(report.opening_error().is_none());
        assert!(report.setup_begin().is_none());
        assert!(report.setup_terminal().is_none());
        assert!(report.panic().is_none());
        std::ptr::from_ref(report.admission_error().unwrap())
    });
    let after = memory.snapshot();
    assert_eq!(after.attempts, filled.attempts + 1);
    assert_eq!(after.used_bytes, filled.used_bytes);
    assert_eq!(after.live_reservations, filled.live_reservations);
    let mut retained_census = census;
    retained_census.databases += 1;
    // Constructing is an occupied prepaid receiver in census telemetry, even
    // when the provider refused before payload or native work could enter.
    retained_census.servicing += 1;
    assert_eq!(memory.storage_census().snapshot(), retained_census);
    let (retained, allocations) = crate::allocation_tests::measure(|| {
        ScratchCreationFailure::retained(memory.clone(), id).unwrap()
    });
    assert_eq!(allocations, 0);
    retained.with_diagnostic(|report| {
        let report = report.unwrap();
        assert_eq!(
            std::ptr::from_ref(report.admission_error().unwrap()),
            address
        );
        assert!(report.constructor_report().unwrap().capacity_refused());
    });
    drop(retained);
    assert_eq!(memory.snapshot(), after);
    assert_eq!(disk.snapshot().live_files, disk_before.live_files);
    assert_eq!(disk.snapshot().charged_bytes, disk_before.charged_bytes);
    assert_eq!(
        original.retire().disposition(),
        StorageCensusDisposition::Retired
    );
    assert_eq!(memory.storage_census().snapshot(), census);
    drop(fillers);
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        before.live_reservations
    );
}

fn acquisition_identity(original: &ScratchCreationFailure) -> usize {
    original.with_diagnostic(|report| {
        let report = report.unwrap();
        let original = report.admission_error().unwrap();
        assert_eq!(original.kind(), io::ErrorKind::InvalidInput);
        assert!(report.opening_error().is_none());
        assert!(report.setup_terminal().is_none());
        original as *const io::Error as usize
    })
}

#[test]
fn transport_lookup_retains_exact_original_and_rejects_foreign_and_reused_ids() {
    let memory = TestDiskMemory::new(64 << 20, 32);
    let other_memory = TestDiskMemory::new(64 << 20, 32);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let other_directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let other_disk =
        ScratchDisk::isolated_fixture(other_directory.path(), 16 << 20, other_memory.clone());
    let before = memory.snapshot();
    let other_before = other_memory.snapshot();
    // This actual extent cannot be represented by the authenticated spool
    // layout. Root acquisition returns its own original after the FILE grant.
    let original = EncryptedTable::new(&disk, u64::MAX, CACHE)
        .err()
        .expect("invalid scratch extent unexpectedly constructed a table");
    let other = EncryptedTable::new(&other_disk, u64::MAX, CACHE)
        .err()
        .expect("foreign invalid scratch extent unexpectedly constructed a table");
    let id = original.owner_id().unwrap();
    let other_id = other.owner_id().unwrap();
    assert_ne!(id, other_id);
    let address = acquisition_identity(&original);
    assert!(original.to_string().contains(&format!("{id:?}")));
    assert!(ScratchCreationFailure::retained(memory.clone(), other_id).is_none());
    assert!(ScratchCreationFailure::retained(other_memory.clone(), id).is_none());
    drop(original);
    let retained = memory.snapshot();
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    for _ in 0..3 {
        let (reborrow, allocations) = crate::allocation_tests::measure(|| {
            ScratchCreationFailure::retained(memory.clone(), id).unwrap()
        });
        assert_eq!(allocations, 0);
        assert_eq!(acquisition_identity(&reborrow), address);
        reborrow.with_diagnostic(|report| {
            let report = report.unwrap();
            report.with_acquisition_disposal(|observation| {
                assert!(matches!(
                    observation,
                    Some(TerminalObservation::Returned(Ok(())))
                ));
            });
            assert_eq!(
                memory.storage_census().drain_owner(id),
                StorageCensusDisposition::Retained
            );
        });
        drop(reborrow);
        assert_eq!(memory.snapshot(), retained);
    }
    let recovered = ScratchCreationFailure::retained(memory.clone(), id).unwrap();
    let alias = ScratchCreationFailure::retained(memory.clone(), id).unwrap();
    let retirement = recovered.with_diagnostic(|report| {
        let report = report.unwrap();
        assert_eq!(
            report.admission_error().unwrap() as *const io::Error as usize,
            address
        );
        let retirement = alias.retire();
        assert_eq!(retirement.disposition(), StorageCensusDisposition::Retained);
        retirement
    });
    // A borrowed report and then this exact facade kept payload disposal
    // unproved; acknowledgment never bypasses either real allocation owner.
    assert_eq!(retirement.retry(), StorageCensusDisposition::Retained);
    drop(recovered);
    assert_eq!(retirement.retry(), StorageCensusDisposition::Retired);
    assert_eq!(
        other.retire().disposition(),
        StorageCensusDisposition::Retired
    );
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        before.live_reservations
    );
    assert_eq!(other_memory.snapshot().used_bytes, other_before.used_bytes);
    assert_eq!(
        other_memory.snapshot().live_reservations,
        other_before.live_reservations
    );
    assert!(ScratchCreationFailure::retained(memory.clone(), id).is_none());
    let replacement = EncryptedTable::new(&disk, u64::MAX, CACHE)
        .err()
        .expect("replacement invalid scratch extent unexpectedly constructed a table");
    assert_ne!(replacement.owner_id(), Some(id));
    assert!(ScratchCreationFailure::retained(memory.clone(), id).is_none());
    assert_eq!(
        replacement.retire().disposition(),
        StorageCensusDisposition::Retired
    );
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        before.live_reservations
    );
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(other_disk.snapshot().live_files, 0);
}

#[test]
fn root_acquisition_refund_panic_preserves_original_and_same_actual_grant_observation() {
    let memory = TestDiskMemory::new(64 << 20, 32);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let before = memory.snapshot();
    let payload = Box::new(0x73_u64);
    let panic_address = (&*payload) as *const u64 as usize;
    memory.panic_on_next_matching_point_lease_drop(super::super::group::FILE_MEMORY_BYTES, payload);
    let original = EncryptedTable::new(&disk, u64::MAX, CACHE)
        .err()
        .expect("scratch refund panic unexpectedly constructed a table");
    let id = original.owner_id().unwrap();
    let address = acquisition_identity(&original);
    let retained = memory.snapshot();
    // Creation and actual group control remain. The real FILE lease has
    // refunded its accounting before its callback unwound with this payload.
    assert_eq!(retained.live_reservations, before.live_reservations + 2);
    original.with_diagnostic(|report| {
        let report = report.unwrap();
        report.with_acquisition_disposal(|observation| {
            let Some(TerminalObservation::Panicked(payload)) = observation else {
                panic!("original refund panic");
            };
            assert_eq!(*payload.downcast_ref::<u64>().unwrap(), 0x73);
            assert_eq!(
                payload.downcast_ref::<u64>().unwrap() as *const u64 as usize,
                panic_address
            );
        });
        assert!(report.opening_error().is_none());
        assert!(report.panic().is_none());
    });
    let retirement = original.retire();
    assert_eq!(retirement.disposition(), StorageCensusDisposition::Retained);
    for _ in 0..3 {
        assert_eq!(retirement.retry(), StorageCensusDisposition::Retained);
        retirement.with_diagnostic(|report| {
            let report = report.unwrap();
            assert_eq!(
                report.admission_error().unwrap() as *const io::Error as usize,
                address
            );
            report.with_acquisition_disposal(|observation| {
                let Some(TerminalObservation::Panicked(payload)) = observation else {
                    panic!("same refund observation");
                };
                assert_eq!(
                    payload.downcast_ref::<u64>().unwrap() as *const u64 as usize,
                    panic_address
                );
            });
        });
        assert_eq!(memory.snapshot(), retained);
        assert_eq!(disk.snapshot().live_files, 0);
        assert_eq!(disk.snapshot().charged_bytes, 0);
    }
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
}

#[test]
fn ordinary_carrier_preserves_whole_original_anyhow_allocation() {
    let original = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
    let original = anyhow::Error::new(original);
    let view: &(dyn std::error::Error + Send + Sync) = original.as_ref();
    let address = view as *const _ as *const () as usize;
    let failure = ScratchOperationFailure::from(original);
    assert!(failure.creation().is_none());
    let view: &(dyn std::error::Error + Send + Sync) = failure.operation_error().unwrap().as_ref();
    assert_eq!(view as *const _ as *const () as usize, address);
    assert!(view.downcast_ref::<serde_json::Error>().is_some());
}
