//! Actual registered reads, original report identity, and native retirement.
use super::*;

struct Fixture {
    _directory: tempfile::TempDir,
    _scratch: tempfile::TempDir,
    memory: Arc<PausedRegistrationMemory>,
    node: NodeStore,
}
impl Fixture {
    fn new() -> Self {
        let directory = private_tempdir().unwrap();
        let scratch = private_tempdir().unwrap();
        let path = directory.path().join("routine-diagnostics.kv");
        let (memory, _, _) = PausedRegistrationMemory::new();
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let node = NodeStore::create_new(
            &path,
            ID,
            disk,
            ScratchDisk::fixture(scratch.path(), memory.clone()),
            crate::test_utils::node_storage_config(),
        )
        .unwrap();
        Self {
            _directory: directory,
            _scratch: scratch,
            memory,
            node,
        }
    }
    fn write(&self, value: &[u8]) {
        let transaction = self.node.body().db.begin_write().unwrap();
        transaction
            .open_table(crate::CATALOG)
            .unwrap()
            .insert([7u8; 32].as_slice(), value)
            .unwrap();
        transaction
            .open_table(crate::RECORDS)
            .unwrap()
            .insert(b"row".as_slice(), value)
            .unwrap();
        transaction.commit().unwrap();
    }
}
fn bounded_address(failure: &crate::NodeScopedReadFailure) -> usize {
    let report = failure.report();
    match report.read_failure() {
        TerminalObservation::Returned(Err(error)) => std::ptr::from_ref(error) as usize,
        _ => panic!("missing original bounded read error"),
    }
}

#[tokio::test]
async fn routine_read_two_original_aliases_outlive_native_and_database_retirement() {
    let fixture = Fixture::new();
    fixture.write(b"actual encrypted row bytes");
    let reader = fixture.node.begin_registered_read().unwrap();
    let id = reader.id();
    let marker = reader.catalog_bytes([7u8; 32], 1).err().unwrap();
    let failure = crate::NodeScopedReadFailure::from_view(&reader, marker.into());
    let original_address = bounded_address(&failure);
    let body_address = std::ptr::from_ref(
        failure
            .body_error()
            .unwrap()
            .downcast_ref::<NodeReadAccessError>()
            .unwrap(),
    ) as usize;
    let close = fixture
        .node
        .settle_registered_read(reader, Ok(()))
        .unwrap_err()
        .downcast::<crate::NodeScopedReadFailure>()
        .unwrap();
    assert_eq!(close.reader_id(), id);
    assert_eq!(bounded_address(&close), original_address);

    // Holding the public immutable report must never self-deadlock retirement.
    let report = failure.report();
    assert_eq!(
        failure.try_retire_routine(),
        StorageCensusDisposition::Retained
    );
    assert_eq!(report.phase(), NodeReadPhase::Finished);
    drop(report);
    let recovered = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
    let before_retirement = fixture.memory.backing.snapshot();
    fixture.memory.fail_next.store(true, Ordering::Release);
    assert_eq!(
        failure.try_retire_routine(),
        StorageCensusDisposition::Retained
    );
    assert_eq!(
        close.try_retire_routine(),
        StorageCensusDisposition::Retained
    );
    assert!(matches!(
        recovered.catalog_bytes([7u8; 32], 1),
        Err(NodeReadAccessError::Unavailable)
    ));
    drop(recovered);
    assert_eq!(
        failure.try_retire_routine(),
        StorageCensusDisposition::Retired
    );
    assert_eq!(
        close.try_retire_routine(),
        StorageCensusDisposition::Retired
    );
    assert!(
        fixture.memory.fail_next.swap(false, Ordering::AcqRel),
        "cleanup requested new admission"
    );
    assert_eq!(
        fixture.memory.backing.snapshot().attempts,
        before_retirement.attempts
    );
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    fixture.node.shutdown().await.unwrap();
    assert_eq!(fixture.memory.storage_census().snapshot().databases, 0);
    assert_eq!(bounded_address(&failure), original_address);
    assert_eq!(bounded_address(&close), original_address);
    assert_eq!(
        std::ptr::from_ref(
            failure
                .body_error()
                .unwrap()
                .downcast_ref::<NodeReadAccessError>()
                .unwrap()
        ) as usize,
        body_address
    );
    let report = failure.report();
    let native = report.close().unwrap();
    assert!(!native.retains_transaction());
    assert!(matches!(
        native.release(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(matches!(
        native.disposal(),
        TerminalObservation::Returned(Ok(()))
    ));
    drop(report);
    let held = fixture.memory.backing.snapshot();
    drop(failure);
    assert_eq!(
        fixture.memory.backing.snapshot().used_bytes,
        held.used_bytes
    );
    drop(close);
    assert!(fixture.memory.backing.snapshot().used_bytes < held.used_bytes);
}

#[tokio::test]
async fn routine_read_native_and_outer_capacity_keep_exact_errors_without_cleanup_admission() {
    for native in [false, true] {
        let fixture = Fixture::new();
        let value = vec![0x6b; 4096];
        fixture.write(&value);
        let reader = fixture.node.begin_registered_read().unwrap();
        let denied = if native {
            native_output_bytes(value.len())
        } else {
            crate::disk_memory::allocation::<u8>(8192).unwrap()
        };
        fixture.memory.deny_bytes.store(denied, Ordering::Release);
        let marker = if native {
            reader.record_bytes(b"row", 8192).err().unwrap()
        } else {
            reader.catalog_bytes([7u8; 32], 8192).err().unwrap()
        };
        fixture.memory.deny_bytes.store(0, Ordering::Release);
        assert!(matches!(marker, NodeReadAccessError::Reported));
        let failure = fixture
            .node
            .settle_registered_read::<()>(reader, Err(marker.into()))
            .unwrap_err()
            .downcast::<crate::NodeScopedReadFailure>()
            .unwrap();
        let address = {
            let report = failure.report();
            if native {
                match report.read_failure() {
                    TerminalObservation::Returned(Err(
                        error @ kasumi_kv::BoundedReadError::Storage(kasumi_kv::StorageError::Core(
                            original,
                        )),
                    )) if original.is_capacity_denied() => std::ptr::from_ref(error) as usize,
                    _ => panic!("missing original native capacity failure"),
                }
            } else {
                match report.output_admission() {
                    TerminalObservation::Returned(Err(error))
                        if error.kind() == io::ErrorKind::OutOfMemory =>
                    {
                        std::ptr::from_ref(error) as usize
                    }
                    _ => panic!("missing original output capacity failure"),
                }
            }
        };
        let before = fixture.memory.backing.snapshot();
        fixture.memory.fail_next.store(true, Ordering::Release);
        assert_eq!(
            failure.try_retire_routine(),
            StorageCensusDisposition::Retired
        );
        assert!(fixture.memory.fail_next.swap(false, Ordering::AcqRel));
        assert_eq!(fixture.memory.backing.snapshot().attempts, before.attempts);
        fixture.node.shutdown().await.unwrap();
        if native {
            assert_eq!(bounded_address(&failure), address);
        } else {
            let report = failure.report();
            let TerminalObservation::Returned(Err(error)) = report.output_admission() else {
                panic!()
            };
            assert_eq!(std::ptr::from_ref(error) as usize, address);
        }
    }
}

#[tokio::test]
async fn routine_read_unknown_io_and_original_body_panic_keep_native_custody() {
    for body_panic in [false, true] {
        let fixture = Fixture::new();
        let error = fixture
            .node
            .with_registered_read::<()>(|reader| {
                if body_panic {
                    std::panic::panic_any(0xcafe_u64);
                }
                fixture.memory.fail_next.store(true, Ordering::Release);
                reader
                    .catalog_bytes([7u8; 32], 64)
                    .map(|_| ())
                    .map_err(Into::into)
            })
            .unwrap_err();
        let failure = error.downcast::<crate::NodeScopedReadFailure>().unwrap();
        let id = failure.reader_id();
        assert_eq!(
            failure.try_retire_routine(),
            StorageCensusDisposition::Retained
        );
        {
            let report = failure.report();
            if body_panic {
                let TerminalObservation::Panicked(payload) = report.body_panic() else {
                    panic!()
                };
                assert_eq!(payload.downcast_ref::<u64>(), Some(&0xcafe));
            } else {
                assert!(
                    matches!(report.output_admission(), TerminalObservation::Returned(Err(error))
                    if error.kind() == io::ErrorKind::Other)
                );
            }
        }
        drop(failure);
        assert_eq!(
            fixture.memory.storage_census().drain_owner(id),
            StorageCensusDisposition::Retained
        );
        let retained = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
        assert!(retained.report().has_failures());
        // Existing explicit owner acknowledgment is test cleanup only. The
        // narrow production operation above refused both unknown outcomes.
        assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
        fixture.node.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn routine_read_known_clean_retirement_is_positive_after_another_exact_drainer() {
    let fixture = Fixture::new();
    let reader = fixture.node.begin_registered_read().unwrap();
    let id = reader.id();
    let other = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
    let pending = fixture
        .node
        .settle_registered_read(reader, Ok(()))
        .unwrap_err()
        .downcast::<crate::NodeScopedReadRetirement>()
        .unwrap();
    assert_eq!(pending.id(), id);
    assert_eq!(
        pending.retry_retirement(),
        StorageCensusDisposition::Retained
    );
    assert_eq!(other.retire(), StorageCensusDisposition::Retired);
    assert_eq!(
        fixture.memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Stale
    );
    assert_eq!(
        pending.retry_retirement(),
        StorageCensusDisposition::Retired
    );
    assert_eq!(
        pending.retry_retirement(),
        StorageCensusDisposition::Retired
    );
    fixture.node.shutdown().await.unwrap();
}

fn early_error_address(failure: &crate::NodeScopedReadFailure, table: bool) -> usize {
    let report = failure.report();
    if table {
        match report.tables() {
            TerminalObservation::Returned(Err(error)) => std::ptr::from_ref(error) as usize,
            _ => panic!("missing original table error"),
        }
    } else {
        match report.begin() {
            TerminalObservation::Returned(Err(error)) => {
                let native = report.acquisition_failure().unwrap();
                assert!(native.is_clean_capacity_refusal());
                assert!(std::ptr::eq(error, native.original()));
                std::ptr::from_ref(error) as usize
            }
            _ => panic!("missing original native begin refusal"),
        }
    }
}

#[tokio::test]
async fn routine_early_capacity_keeps_original_after_real_native_and_database_retirement() {
    // Begin backing, catalog verification, records verification. The latter
    // skips exactly the first required tag output, not an ordinal provider call.
    for stage in 0..3 {
        let fixture = Fixture::new();
        let reader = fixture.node.body().db.queue_registered_read().unwrap();
        if stage == 0 {
            fixture
                .memory
                .deny_installed_next
                .store(true, Ordering::Release);
        } else {
            fixture
                .memory
                .deny_installed_bytes
                .store(native_output_bytes(2), Ordering::Release);
            fixture
                .memory
                .deny_installed_skip
                .store(stage - 1, Ordering::Release);
        }
        assert_eq!(reader.begin(), NodeReadPhase::Failed);
        fixture
            .memory
            .deny_installed_bytes
            .store(0, Ordering::Release);
        assert_eq!(fixture.memory.capacity_denials.load(Ordering::Acquire), 1);
        let failure =
            crate::NodeScopedReadFailure::from_view(&reader, NodeReadAccessError::Reported.into());
        let id = failure.reader_id();
        let address = early_error_address(&failure, stage != 0);
        {
            let report = failure.report();
            if stage == 0 {
                assert!(report.close().is_none());
                assert!(matches!(report.tables(), TerminalObservation::NotEntered));
            } else {
                assert!(matches!(
                    report.begin(),
                    TerminalObservation::Returned(Ok(()))
                ));
                assert_eq!(
                    report.close().unwrap().settlement(),
                    kasumi_kv::ReadCloseSettlement::Open
                );
                let TerminalObservation::Returned(Err(error)) = report.tables() else {
                    panic!()
                };
                let original = match (stage, error) {
                    (1, NodeReadTablesError::Catalog(error))
                    | (2, NodeReadTablesError::Records(error)) => error,
                    _ => panic!("wrong required table verification failed"),
                };
                assert!(
                    matches!(&(original), kasumi_kv::BoundedReadError::Table(kasumi_kv::TableError::Storage(
                        kasumi_kv::StorageError::Core(native_error)
                    )) if matches!(native_error.rejected_cause(), Some(kasumi_kv::CoreErrorCause::CapacityDenied)))
                );
            }
        }
        if stage != 0 {
            let opening = RegisteredNodeOpening::retained(
                fixture.memory.clone(),
                fixture.node.registered_opening_id().unwrap(),
            )
            .unwrap();
            let opening_state = opening.registration.owner().state.lock();
            assert_eq!(
                failure.try_retire_routine(),
                StorageCensusDisposition::Retained
            );
            assert_eq!(
                failure.report().close().unwrap().settlement(),
                kasumi_kv::ReadCloseSettlement::Open
            );
            drop(opening_state);
            drop(opening);
        }
        drop(reader);
        let held = failure.report();
        assert_eq!(
            failure.try_retire_routine(),
            StorageCensusDisposition::Retained
        );
        drop(held);
        let before = fixture.memory.backing.snapshot();
        fixture.memory.fail_next.store(true, Ordering::Release);
        assert_eq!(
            failure.try_retire_routine(),
            StorageCensusDisposition::Retired
        );
        assert!(
            fixture.memory.fail_next.swap(false, Ordering::AcqRel),
            "cleanup attempted admission"
        );
        assert_eq!(fixture.memory.backing.snapshot().attempts, before.attempts);
        assert!(RegisteredNodeRead::retained(fixture.memory.clone(), id).is_none());
        assert_eq!(early_error_address(&failure, stage != 0), address);
        {
            let report = failure.report();
            assert!(matches!(
                report.finish_outer(),
                TerminalObservation::Returned(Ok(()))
            ));
            if stage == 0 {
                assert!(
                    report.close().is_none(),
                    "acquisition must not synthesize close observations"
                );
            } else {
                let native = report.close().unwrap();
                assert_eq!(
                    native.settlement(),
                    kasumi_kv::ReadCloseSettlement::Disposed
                );
                assert!(!native.retains_transaction());
                assert!(matches!(
                    native.release(),
                    TerminalObservation::Returned(Ok(()))
                ));
                assert!(matches!(
                    native.disposal(),
                    TerminalObservation::Returned(Ok(()))
                ));
            }
        }
        fixture.node.shutdown().await.unwrap();
        assert_eq!(fixture.memory.storage_census().snapshot().databases, 0);
        assert_eq!(early_error_address(&failure, stage != 0), address);
    }
}

#[tokio::test]
async fn routine_early_capacity_last_facade_never_blocks_on_retained_report() {
    for table in [false, true] {
        let fixture = Fixture::new();
        let reader = fixture.node.body().db.queue_registered_read().unwrap();
        if table {
            fixture
                .memory
                .deny_installed_bytes
                .store(native_output_bytes(2), Ordering::Release);
        } else {
            fixture
                .memory
                .deny_installed_next
                .store(true, Ordering::Release);
        }
        assert_eq!(reader.begin(), NodeReadPhase::Failed);
        fixture
            .memory
            .deny_installed_bytes
            .store(0, Ordering::Release);
        let id = reader.id();
        let retained = reader.admitted_report();
        let report = retained.report();
        let original = if table {
            let TerminalObservation::Returned(Err(error)) = report.tables() else {
                panic!()
            };
            std::ptr::from_ref(error) as usize
        } else {
            std::ptr::from_ref(report.acquisition_failure().unwrap().original()) as usize
        };
        // Same-thread drop while the report guard remains live must return.
        drop(reader);
        assert_eq!(fixture.memory.storage_census().snapshot().readers, 1);
        assert_eq!(report.phase(), NodeReadPhase::Failed);
        drop(report);
        fixture.node.shutdown().await.unwrap();
        assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
        assert!(RegisteredNodeRead::retained(fixture.memory.clone(), id).is_none());
        let report = retained.report();
        let after = if table {
            let TerminalObservation::Returned(Err(error)) = report.tables() else {
                panic!()
            };
            std::ptr::from_ref(error) as usize
        } else {
            std::ptr::from_ref(report.acquisition_failure().unwrap().original()) as usize
        };
        assert_eq!(after, original);
    }
}

#[tokio::test]
async fn routine_early_capacity_recovered_unknown_revokes_both_retirement_paths() {
    let fixture = Fixture::new();
    let reader = fixture.node.body().db.queue_registered_read().unwrap();
    fixture
        .memory
        .deny_installed_next
        .store(true, Ordering::Release);
    assert_eq!(reader.begin(), NodeReadPhase::Failed);
    let failure =
        crate::NodeScopedReadFailure::from_view(&reader, NodeReadAccessError::Reported.into());
    let address = early_error_address(&failure, false);
    let id = reader.id();
    let recovered = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
    drop(reader);
    recovered.preserve_body_panic(Box::new(0xecaf_u64));
    assert_eq!(
        failure.try_retire_routine(),
        StorageCensusDisposition::Retained
    );
    drop(failure);
    drop(recovered);
    assert_eq!(
        fixture.memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    let recovered = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
    let report = recovered.report();
    assert_eq!(
        std::ptr::from_ref(report.acquisition_failure().unwrap().original()) as usize,
        address
    );
    let TerminalObservation::Panicked(payload) = report.body_panic() else {
        panic!()
    };
    assert_eq!(payload.downcast_ref::<u64>(), Some(&0xecaf));
    drop(report);
    // Exact explicit acknowledgment is fixture cleanup, never routine success.
    assert_eq!(recovered.retire(), StorageCensusDisposition::Retired);
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn routine_early_unknown_and_native_panic_never_gain_clean_acquisition_permission() {
    for panic in [false, true] {
        let fixture = Fixture::new();
        let reader = fixture.node.body().db.queue_registered_read().unwrap();
        if panic {
            fixture.memory.panic_next.store(true, Ordering::Release);
        } else {
            fixture.memory.fail_next.store(true, Ordering::Release);
        }
        assert_eq!(reader.begin(), NodeReadPhase::Failed);
        let failure =
            crate::NodeScopedReadFailure::from_view(&reader, NodeReadAccessError::Reported.into());
        let id = reader.id();
        let address = {
            let report = failure.report();
            let native = report.acquisition_failure().unwrap();
            assert!(!native.is_clean_capacity_refusal());
            if panic {
                assert!(
                    matches!(&(native.original()), kasumi_kv::TransactionError(kasumi_kv::StorageError::Core(
                        native_error
                    )) if matches!(native_error.rejected_cause(), Some(kasumi_kv::CoreErrorCause::Panicked(_))))
                );
            } else {
                assert!(
                    matches!(&(native.original()), kasumi_kv::TransactionError(kasumi_kv::StorageError::Core(
                        native_error
                    )) if matches!(native_error.rejected_cause(), Some(kasumi_kv::CoreErrorCause::OwnerFailed)))
                );
            }
            assert!(report.close().is_none());
            std::ptr::from_ref(native.original()) as usize
        };
        drop(reader);
        assert_eq!(
            failure.try_retire_routine(),
            StorageCensusDisposition::Retained
        );
        assert_eq!(failure.phase(), NodeReadPhase::Finished);
        drop(failure);
        assert_eq!(
            fixture.memory.storage_census().drain_owner(id),
            StorageCensusDisposition::Retained
        );
        let reader = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
        assert_eq!(
            std::ptr::from_ref(reader.report().acquisition_failure().unwrap().original()) as usize,
            address
        );
        assert_eq!(reader.retire(), StorageCensusDisposition::Retired); // explicit fixture acknowledgment
        assert_eq!(
            fixture.node.shutdown().await.unwrap_err().completion(),
            kasumi_types::drain::DrainCompletion::Retained
        );
    }
}
