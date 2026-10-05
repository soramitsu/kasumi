use super::*;
use crate::test_utils::{
    TestDiskMemory, node_storage_config, private_tempdir, retry_disk_registry,
};

const BYTES: u64 = 256 << 20;
const SLOTS: usize = 4096;
const ID: Uuid = Uuid::from_u128(0x671a_1a88_3c2e_4bc0_879a_10a5_c9dd_0061);
const KEY: [u8; 32] = [7; 32];

struct Fixture {
    opening: RegisteredNodeOpening,
    memory: Arc<TestDiskMemory>,
    _directory: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("selected-fork.kv");
        let memory = TestDiskMemory::new(BYTES, SLOTS);
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let opening = RegisteredNodeOpening::prepare(
            &path,
            ID,
            disk,
            NodeOpeningMode::Create,
            node_storage_config(),
        )
        .unwrap();
        assert_eq!(opening.open(), NodeOpeningPhase::Open);
        let tables = opening.queue_node_tables().unwrap();
        assert_eq!(tables.run(), NodeWriterPhase::Finished);
        opening.publish_ready_after_tables(&tables).unwrap();
        assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
        let fixture = Self {
            opening,
            memory,
            _directory: directory,
        };
        fixture.publish(b"old");
        fixture
    }
    fn publish(&self, value: &[u8]) {
        let state = self.opening.registration.owner().state.lock();
        let tx = state.engine.database().unwrap().begin_write().unwrap();
        {
            let mut table = tx.open_table(crate::CATALOG).unwrap();
            table.insert(KEY.as_slice(), value).unwrap();
        }
        tx.commit().unwrap();
    }
    fn reader(&self) -> RegisteredNodeRead {
        let reader = self.opening.queue_read().unwrap();
        assert_eq!(reader.begin(), NodeReadPhase::Active);
        reader
    }
    fn finish(self) {
        assert_eq!(self.memory.storage_census().snapshot().readers, 0);
        assert_eq!(
            self.opening.close().unwrap(),
            DatabaseOpenSettlement::Closed
        );
        assert_eq!(self.opening.retire(), StorageCensusDisposition::Retired);
    }
    fn fill_bytes(&self) -> crate::DiskMemoryLease {
        let snapshot = self.memory.snapshot();
        let available = BYTES - snapshot.bookkeeping_bytes - snapshot.used_bytes;
        self.memory
            .clone()
            .reserve_installed(available - TestDiskMemory::required_reservation_bytes(0).unwrap())
            .unwrap()
    }
    fn fill_slots(&self) -> Vec<crate::DiskMemoryLease> {
        let remaining = SLOTS - self.memory.snapshot().live_reservations;
        (0..remaining)
            .map(|_| self.memory.clone().reserve_installed(0).unwrap())
            .collect()
    }
}
fn value(reader: &RegisteredNodeRead, expected: &[u8]) {
    assert_eq!(
        reader.catalog_bytes(KEY, 64).unwrap().unwrap().as_bytes(),
        expected
    );
}
fn retire(reader: RegisteredNodeRead) {
    assert_eq!(reader.finish(), NodeReadPhase::Finished);
    assert_eq!(reader.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn selected_fork_keeps_old_root_and_closes_independently_in_both_orders() {
    for parent_first in [true, false] {
        let fixture = Fixture::new();
        let parent = fixture.reader();
        fixture.publish(b"new");
        let child = parent.fork().unwrap();
        assert_ne!(child.id(), parent.id());
        assert_eq!(child.phase(), NodeReadPhase::Active);
        assert_eq!(fixture.memory.storage_census().snapshot().readers, 2);
        value(&parent, b"old");
        value(&child, b"old");
        let current = fixture.reader();
        value(&current, b"new");
        retire(current);
        if parent_first {
            retire(parent);
            value(&child, b"old");
            let grandchild = child.fork().unwrap();
            retire(child);
            value(&grandchild, b"old");
            retire(grandchild);
        } else {
            retire(child);
            value(&parent, b"old");
            retire(parent);
        }
        fixture.finish();
    }
}

#[test]
fn selected_fork_recovered_begin_cannot_select_current_root() {
    let fixture = Fixture::new();
    let parent = fixture.reader();
    fixture.publish(b"new");
    // Interpose at the exact published census boundary, before private begin.
    let child = parent.queue_fork().unwrap();
    let recovered = RegisteredNodeRead::retained(fixture.memory.clone(), child.id()).unwrap();
    assert_eq!(recovered.begin(), NodeReadPhase::ForkQueued);
    assert!(matches!(
        recovered.report().begin(),
        TerminalObservation::NotEntered
    ));
    assert_eq!(child.begin_fork(&parent), NodeReadPhase::Active);
    value(&recovered, b"old");
    drop(recovered);
    retire(child);
    retire(parent);
    fixture.finish();
}

#[test]
fn selected_fork_recovered_finish_or_retire_wins_without_installing_transaction() {
    for retire_first in [false, true] {
        let fixture = Fixture::new();
        let parent = fixture.reader();
        let child = parent.queue_fork().unwrap();
        let recovered = RegisteredNodeRead::retained(fixture.memory.clone(), child.id()).unwrap();
        if retire_first {
            assert_eq!(recovered.retire(), StorageCensusDisposition::Retained);
        } else {
            assert_eq!(recovered.finish(), NodeReadPhase::Cancelled);
            drop(recovered);
        }
        let before = fixture.memory.snapshot();
        assert_eq!(child.begin_fork(&parent), NodeReadPhase::Cancelled);
        assert!(
            child
                .registration
                .owner()
                .state
                .lock()
                .transaction
                .is_none()
        );
        assert!(matches!(
            child.report().begin(),
            TerminalObservation::NotEntered
        ));
        assert_eq!(fixture.memory.snapshot(), before);
        assert_eq!(child.retire(), StorageCensusDisposition::Retired);
        value(&parent, b"old");
        retire(parent);
        fixture.finish();
    }
}

#[test]
fn selected_fork_parent_close_before_install_retains_original_begin_failure() {
    let fixture = Fixture::new();
    let parent = fixture.reader();
    let child = parent.queue_fork().unwrap();
    let competing_parent = parent.retain_report_facade();
    let request = parent.registration.owner();
    let mut parent_state = request.state.lock();
    let (entered, received) = std::sync::mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        entered.send(()).unwrap();
        let phase = child.begin_fork(&competing_parent);
        drop(competing_parent);
        (phase, child)
    });
    received.recv().unwrap();
    // The fork cannot pass the held parent lock. Finish the actual selected
    // transaction before releasing it, then observe the competing fork result.
    let closed = request.finish_observed(&mut parent_state);
    drop(parent_state);
    let (phase, child) = worker.join().unwrap();
    assert_eq!(closed, NodeReadPhase::Finished);
    assert_eq!(phase, NodeReadPhase::Failed);
    assert!(matches!(
        child.report().begin(),
        TerminalObservation::Returned(Err(kasumi_kv::TransactionError(
            kasumi_kv::StorageError::DatabaseClosed
        )))
    ));
    assert!(
        child
            .registration
            .owner()
            .state
            .lock()
            .transaction
            .is_none()
    );
    assert!(child.report().acquisition_failure().is_none());
    assert!(
        !child.try_acknowledge_routine(),
        "absent native transaction is not a clean acquisition witness"
    );
    retire(child);
    assert_eq!(parent.retire(), StorageCensusDisposition::Retired);
    fixture.finish();
}

#[test]
fn selected_fork_metadata_and_native_backing_denials_preserve_parent_and_exact_child() {
    for slots in [false, true] {
        let fixture = Fixture::new();
        let parent = fixture.reader();
        let byte_blocker = (!slots).then(|| fixture.fill_bytes());
        let slot_blockers = slots.then(|| fixture.fill_slots());
        let before = fixture.memory.snapshot();
        let census = fixture.memory.storage_census().snapshot();
        let error = match parent.fork() {
            Ok(_) => panic!("fork registered despite exhausted admission"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert_eq!(fixture.memory.storage_census().snapshot(), census);
        let after = fixture.memory.snapshot();
        assert_eq!(after.used_bytes, before.used_bytes);
        assert_eq!(after.live_reservations, before.live_reservations);
        drop((byte_blocker, slot_blockers));

        // The census metadata fits; only the new native backing is refused.
        let child = parent.queue_fork().unwrap();
        let id = child.id();
        let byte_blocker = (!slots).then(|| fixture.fill_bytes());
        let slot_blockers = slots.then(|| fixture.fill_slots());
        let before = fixture.memory.snapshot();
        assert_eq!(child.begin_fork(&parent), NodeReadPhase::Failed);
        assert!(
            matches!(&(child.report().begin()), TerminalObservation::Returned(Err(kasumi_kv::TransactionError(
                kasumi_kv::StorageError::Core(native_error)
            ))) if matches!(native_error.rejected_cause(), Some(kasumi_kv::CoreErrorCause::CapacityDenied)))
        );
        let after = fixture.memory.snapshot();
        assert_eq!(after.used_bytes, before.used_bytes);
        assert_eq!(after.live_reservations, before.live_reservations);
        assert_eq!(parent.phase(), NodeReadPhase::Active);
        assert!(!parent.report().has_failures());
        drop((byte_blocker, slot_blockers));
        let failure =
            crate::NodeScopedReadFailure::from_view(&child, NodeReadAccessError::Reported.into());
        let address = {
            let report = failure.report();
            assert!(
                report
                    .acquisition_failure()
                    .unwrap()
                    .is_clean_capacity_refusal()
            );
            std::ptr::from_ref(report.acquisition_failure().unwrap().original()) as usize
        };
        drop(child);
        let before_cleanup = fixture.memory.snapshot();
        assert_eq!(
            failure.try_retire_routine(),
            StorageCensusDisposition::Retired
        );
        assert_eq!(fixture.memory.snapshot().attempts, before_cleanup.attempts);
        assert!(RegisteredNodeRead::retained(fixture.memory.clone(), id).is_none());
        let report = failure.report();
        assert_eq!(
            std::ptr::from_ref(report.acquisition_failure().unwrap().original()) as usize,
            address
        );
        assert!(report.close().is_none());
        drop(report);
        value(&parent, b"old");
        retire(parent);
        fixture.finish();
        assert_eq!(
            std::ptr::from_ref(failure.report().acquisition_failure().unwrap().original()) as usize,
            address
        );
    }
}

#[test]
fn selected_fork_read_failure_is_local_and_survives_explicit_close() {
    let fixture = Fixture::new();
    let parent = fixture.reader();
    let child = parent.fork().unwrap();
    assert!(matches!(
        child.catalog_bytes(KEY, 1),
        Err(NodeReadAccessError::Reported)
    ));
    assert!(matches!(
        child.report().read_failure(),
        TerminalObservation::Returned(Err(BoundedReadError::BoundExceeded))
    ));
    assert_eq!(child.finish(), NodeReadPhase::Finished);
    assert!(matches!(
        child.report().read_failure(),
        TerminalObservation::Returned(Err(BoundedReadError::BoundExceeded))
    ));
    value(&parent, b"old");
    assert!(!parent.report().has_failures());
    assert_eq!(child.retire(), StorageCensusDisposition::Retired);
    retire(parent);
    fixture.finish();
}

#[test]
fn routine_early_missing_or_wrong_typed_table_stays_retained_after_real_disposal() {
    for wrong_type in [false, true] {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("invalid-required-table.kv");
        let memory = TestDiskMemory::new(BYTES, SLOTS);
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let opening = RegisteredNodeOpening::prepare(
            &path,
            ID,
            disk.clone(),
            NodeOpeningMode::Create,
            node_storage_config(),
        )
        .unwrap();
        assert_eq!(opening.open(), NodeOpeningPhase::Open);
        if wrong_type {
            let state = opening.registration.owner().state.lock();
            let writer = state.engine.database().unwrap().begin_write().unwrap();
            writer
                .open_table(kasumi_kv::TableDefinition::<u64, u64>::new(
                    crate::CATALOG.name(),
                ))
                .unwrap();
            writer.commit().unwrap();
        }
        // Deliberately build a physically ready group with an invalid native
        // table set. Otherwise Existing rejects its Prepared envelope before
        // a reader can observe the missing or wrongly typed catalog.
        opening
            .registration
            .owner()
            .state
            .lock()
            .file
            .publish_ready()
            .unwrap();
        assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
        assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
        let existing = RegisteredNodeOpening::prepare(
            &path,
            ID,
            disk,
            NodeOpeningMode::Existing,
            node_storage_config(),
        )
        .unwrap();
        assert_eq!(existing.open(), NodeOpeningPhase::Open);
        let reader = existing.verify_existing_tables().unwrap();
        assert_eq!(reader.phase(), NodeReadPhase::Failed);
        let id = reader.id();
        let failure =
            crate::NodeScopedReadFailure::from_view(&reader, NodeReadAccessError::Reported.into());
        let address = {
            let report = failure.report();
            assert!(matches!(
                report.begin(),
                TerminalObservation::Returned(Ok(()))
            ));
            let TerminalObservation::Returned(Err(NodeReadTablesError::Catalog(error))) =
                report.tables()
            else {
                panic!("expected actual catalog verification failure")
            };
            if wrong_type {
                assert!(matches!(
                    error,
                    BoundedReadError::Table(kasumi_kv::TableError::TypeMismatch(_))
                ));
            } else {
                assert!(matches!(
                    error,
                    BoundedReadError::Table(kasumi_kv::TableError::DoesNotExist(_))
                ));
            }
            std::ptr::from_ref(error) as usize
        };
        drop(reader);
        assert_eq!(
            failure.try_retire_routine(),
            StorageCensusDisposition::Retained
        );
        assert_eq!(
            failure.report().close().unwrap().settlement(),
            ReadCloseSettlement::Disposed
        );
        drop(failure);
        assert_eq!(
            memory.storage_census().drain_owner(id),
            StorageCensusDisposition::Retained
        );
        let reader = RegisteredNodeRead::retained(memory.clone(), id).unwrap();
        {
            let report = reader.report();
            let TerminalObservation::Returned(Err(NodeReadTablesError::Catalog(error))) =
                report.tables()
            else {
                panic!()
            };
            assert_eq!(std::ptr::from_ref(error) as usize, address);
        }
        assert_eq!(reader.retire(), StorageCensusDisposition::Retired); // explicit fixture acknowledgment
        assert_eq!(existing.close().unwrap(), DatabaseOpenSettlement::Closed);
        assert_eq!(existing.retire(), StorageCensusDisposition::Retired);
    }
}
