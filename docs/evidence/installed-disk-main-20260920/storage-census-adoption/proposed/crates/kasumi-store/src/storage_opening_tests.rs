use super::*;
use crate::{
    NodeDiskMemoryAdmission,
    test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry},
};
use std::time::{Duration, Instant};

fn disk(path: &Path, memory: &Arc<TestDiskMemory>) -> Arc<NodeDisk> {
    retry_disk_registry(|| NodeDisk::fixture_for_path(path, memory.clone())).unwrap()
}
const ID: Uuid = Uuid::from_u128(0x38a5_c9c5_6a88_41f0_a1a3_a723_fe68_4535);

#[test]
fn registered_opening_exists_before_actual_creation_and_abandoned_prepare_has_no_file_effect() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("prepared.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let baseline = memory.snapshot();
    let opening = RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    let id = opening.id();
    assert!(!path.exists());
    assert_eq!(memory.storage_census().snapshot().databases, 1);
    assert!(memory.snapshot().used_bytes > baseline.used_bytes);
    assert!(matches!(
        opening.report().acquisition(),
        TerminalObservation::NotEntered
    ));
    drop(opening);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retired
    );
    assert!(!path.exists());
    assert_eq!(memory.storage_census().snapshot().databases, 0);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
}

#[test]
fn registered_node_tables_retains_actual_transaction_and_reports_through_physical_close() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("initialized.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening = RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    assert!(path.exists());
    assert!(matches!(
        opening.report().opening_outer(),
        TerminalObservation::Returned(Ok(()))
    ));
    let writer = opening.queue_node_tables().unwrap();
    assert_eq!(memory.storage_census().snapshot().writers, 1);
    assert!(matches!(
        writer.report().begin(),
        TerminalObservation::NotEntered
    ));
    assert_eq!(writer.run(), NodeWriterPhase::Finished);
    {
        let report = writer.report();
        assert!(matches!(
            report.begin(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert!(matches!(
            report.body(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert!(matches!(
            report.outer(),
            TerminalObservation::Returned(Ok(()))
        ));
        let terminal = report.terminal().unwrap();
        assert_eq!(
            terminal.operation(),
            Some(redb::WriteTerminalOperation::Commit)
        );
        assert!(terminal.disposal_complete());
        assert!(matches!(
            terminal.terminal(),
            TerminalObservation::Returned(Ok(()))
        ));
    }
    {
        let state = opening.registration.owner().state.lock();
        let read = state.redb.database().unwrap().begin_read().unwrap();
        read.open_table(crate::CATALOG).unwrap();
        read.open_table(crate::RECORDS).unwrap();
    }
    let id = opening.id();
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_eq!(
        opening.report().redb().settlement(),
        DatabaseOpenSettlement::Closed
    );
    // The returned report's real request owner remains charged after physical
    // close. Only its own actual disposal can remove the writer cell.
    assert_eq!(memory.storage_census().snapshot().writers, 1);
    assert!(writer.report().terminal().unwrap().disposal_complete());
    assert_eq!(writer.retire(), StorageCensusDisposition::Retired);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn actual_queued_worker_keeps_request_without_blocking_close_and_cancels_after_seal() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("queued.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening = RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let writer = opening.queue_node_tables().unwrap();
    let id = writer.id();
    let queued = RegisteredNodeTables {
        registration: writer.registration.clone(),
    };
    let serial = opening.registration.owner().serial.lock();
    let worker = std::thread::spawn(move || queued.run());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !writer.registration.owner().state.is_locked() {
        assert!(
            Instant::now() < deadline,
            "worker never reached serial queue"
        );
        std::thread::yield_now();
    }
    let started = Instant::now();
    assert_eq!(
        memory.storage_census().drain_owner(opening.id()),
        StorageCensusDisposition::Retained
    );
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "close waited for queued writer"
    );
    assert_eq!(memory.storage_census().snapshot().writers, 1);
    drop(serial);
    assert_eq!(worker.join().unwrap(), NodeWriterPhase::Cancelled);
    assert!(matches!(
        writer.report().begin(),
        TerminalObservation::NotEntered
    ));
    drop(writer);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retired
    );
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn actual_body_error_is_retained_before_abort_and_disposal_without_replay() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("body-error.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening = RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    {
        // Produce a real incompatible table with the ordinary engine. The
        // NodeTables adapter below takes its actual TableError and abort path.
        let state = opening.registration.owner().state.lock();
        let tx = state.redb.database().unwrap().begin_write().unwrap();
        tx.open_table(redb::TableDefinition::<u64, u64>::new("wrapped_keys_v1"))
            .unwrap();
        tx.commit().unwrap();
    }
    let writer = opening.queue_node_tables().unwrap();
    assert_eq!(writer.run(), NodeWriterPhase::Finished);
    let address = {
        let report = writer.report();
        let TerminalObservation::Returned(Err(NodeTablesBodyError::Catalog(error))) = report.body()
        else {
            panic!("expected actual catalog error");
        };
        assert!(report.terminal().unwrap().disposal_complete());
        assert_eq!(
            report.terminal().unwrap().operation(),
            Some(redb::WriteTerminalOperation::Abort)
        );
        std::ptr::from_ref(error)
    };
    assert_eq!(writer.run(), NodeWriterPhase::Finished);
    memory.storage_census().drain_owner(opening.id());
    {
        let report = writer.report();
        let TerminalObservation::Returned(Err(NodeTablesBodyError::Catalog(error))) = report.body()
        else {
            panic!("original body error lost");
        };
        assert_eq!(std::ptr::from_ref(error), address);
    }
    assert_eq!(writer.retire(), StorageCensusDisposition::Retired);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
}

// An uncertain transaction is deliberately retained by the exact provider's
// fixed census. Keep fixture path custody too, rather than unlinking under it.
static UNCERTAIN_DIRECTORIES: std::sync::Mutex<[Option<tempfile::TempDir>; 2]> =
    std::sync::Mutex::new([None, None]);
#[test]
fn real_commit_and_abort_failures_keep_actual_request_after_all_facades_cancel() {
    for (index, body_error) in [false, true].into_iter().enumerate() {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("terminal-failure.kasumi");
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk = disk(&path, &memory);
        let opening =
            RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
        UNCERTAIN_DIRECTORIES.lock().unwrap()[index] = Some(directory);
        assert_eq!(opening.open(), NodeOpeningPhase::Open);
        if body_error {
            let state = opening.registration.owner().state.lock();
            let tx = state.redb.database().unwrap().begin_write().unwrap();
            tx.open_table(redb::TableDefinition::<u64, u64>::new("wrapped_keys_v1"))
                .unwrap();
            tx.commit().unwrap();
        }
        let writer = opening.queue_node_tables().unwrap();
        writer
            .registration
            .owner()
            .state
            .lock()
            .fail_owner_before_terminal = true;
        let id = writer.id();
        assert_eq!(writer.run(), NodeWriterPhase::Disposal);
        let (original, transaction) = {
            let report = writer.report();
            let terminal = report.terminal().unwrap();
            assert_eq!(
                terminal.operation(),
                Some(if body_error {
                    redb::WriteTerminalOperation::Abort
                } else {
                    redb::WriteTerminalOperation::Commit
                })
            );
            assert_eq!(
                terminal.settlement(),
                redb::WriteTerminalSettlement::Retained
            );
            assert!(!terminal.disposal_complete());
            let TerminalObservation::Returned(Err(error)) = terminal.terminal() else {
                panic!("expected actual terminal refusal");
            };
            (
                std::ptr::from_ref(error),
                std::ptr::from_ref(report.state.transaction.as_ref().unwrap()),
            )
        };
        drop(writer);
        drop(opening);
        let held = memory.snapshot();
        let snapshot = memory.storage_census().drain().unwrap();
        assert_eq!(snapshot.databases, 1);
        assert_eq!(snapshot.writers, 1);
        assert_eq!(memory.snapshot(), held);
        let retained = RegisteredNodeTables::retained(memory.clone(), id).unwrap();
        {
            let report = retained.report();
            let terminal = report.terminal().unwrap();
            let TerminalObservation::Returned(Err(error)) = terminal.terminal() else {
                panic!("original terminal failure lost");
            };
            assert_eq!(std::ptr::from_ref(error), original);
            assert_eq!(
                std::ptr::from_ref(report.state.transaction.as_ref().unwrap()),
                transaction
            );
            assert!(!terminal.disposal_complete());
        }
        assert_eq!(retained.retire(), StorageCensusDisposition::Retained);
        let raw = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        use std::os::fd::AsRawFd;
        // SAFETY: the owned descriptor is live, and nonblocking flock does not
        // mutate its bytes or transfer ownership of the descriptor.
        assert_eq!(
            unsafe { libc::flock(raw.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            -1
        );
        assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
    }
}

#[test]
fn abandoned_failed_open_keeps_original_after_positive_close_until_explicit_report_release() {
    use std::os::unix::fs::OpenOptionsExt;
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("invalid-envelope.kasumi");
    drop(
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap(),
    );
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening =
        RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Existing).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::FileAcquisition);
    let original = {
        let report = opening.report();
        let TerminalObservation::Returned(Err(error)) = report.acquisition() else {
            panic!("expected actual envelope rejection");
        };
        std::ptr::from_ref(error)
    };
    let id = opening.id();
    drop(opening);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_eq!(memory.storage_census().snapshot().databases, 1);
    let retained = RegisteredNodeOpening::retained(memory.clone(), id).unwrap();
    {
        let report = retained.report();
        assert_eq!(report.redb().settlement(), DatabaseOpenSettlement::Closed);
        let TerminalObservation::Returned(Err(error)) = report.acquisition() else {
            panic!("original acquisition error lost");
        };
        assert_eq!(std::ptr::from_ref(error), original);
    }
    assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}
