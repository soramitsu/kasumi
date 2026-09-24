use super::*;
use crate::{
    NodeDiskMemoryAdmission,
    test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry},
};
use std::{
    io::Read,
    time::{Duration, Instant},
};

#[test]
fn retained_reader_keeps_one_snapshot_and_admitted_bytes_through_close() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("retained-reader.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening =
        RegisteredNodeOpening::prepare(&path, ID, disk.clone(), NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let tables = opening.queue_node_tables().unwrap();
    assert_eq!(tables.run(), NodeWriterPhase::Finished);
    opening.publish_ready_after_tables(&tables).unwrap();
    assert_eq!(tables.retire(), StorageCensusDisposition::Retired);

    let reader = opening.queue_read().unwrap();
    assert_eq!(memory.storage_census().snapshot().readers, 1);
    assert_eq!(reader.begin(), NodeReadPhase::Active);
    let hash = [7u8; 32];
    assert!(reader.catalog_bytes(hash, 64).unwrap().is_none());
    {
        let state = opening.registration.owner().state.lock();
        let transaction = state.engine.database().unwrap().begin_write().unwrap();
        {
            let mut catalog = transaction.open_table(crate::CATALOG).unwrap();
            catalog
                .insert(hash.as_slice(), b"ciphertext".as_slice())
                .unwrap();
        }
        transaction.commit().unwrap();
    }
    assert!(reader.catalog_bytes(hash, 64).unwrap().is_none());
    let reader_id = reader.id();
    drop(reader);
    let reader = RegisteredNodeRead::retained(memory.clone(), reader_id).unwrap();
    assert_eq!(reader.phase(), NodeReadPhase::Active);
    assert!(reader.catalog_bytes(hash, 64).unwrap().is_none());

    let later = opening.queue_read().unwrap();
    assert_eq!(later.begin(), NodeReadPhase::Active);
    let value = later.catalog_bytes(hash, 64).unwrap().unwrap();
    assert_eq!(value.as_bytes(), b"ciphertext");
    assert_eq!(
        opening.close().unwrap(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    assert!(opening.queue_read().is_err());
    assert_eq!(
        later.catalog_bytes(hash, 64).unwrap().unwrap().as_bytes(),
        b"ciphertext"
    );
    assert_eq!(reader.finish(), NodeReadPhase::Finished);
    assert_eq!(later.finish(), NodeReadPhase::Finished);
    assert_eq!(reader.retire(), StorageCensusDisposition::Retired);
    assert_eq!(later.retire(), StorageCensusDisposition::Retired);
    drop(value);
    assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);

    let existing =
        RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Existing).unwrap();
    assert_eq!(existing.open(), NodeOpeningPhase::Open);
    let verification = existing.verify_existing_tables().unwrap();
    assert_eq!(verification.phase(), NodeReadPhase::Active);
    assert!(existing.report().existing_tables_verified());
    assert_eq!(verification.finish(), NodeReadPhase::Finished);
    assert_eq!(verification.retire(), StorageCensusDisposition::Retired);
    assert_eq!(existing.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(existing.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn inspected_reader_failure_retires_directly_after_successful_close() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("reader-failures.kasumi");
    let (memory, _, _) = PausedRegistrationMemory::new();
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let opening = RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let tables = opening.queue_node_tables().unwrap();
    assert_eq!(tables.run(), NodeWriterPhase::Finished);
    opening.publish_ready_after_tables(&tables).unwrap();
    assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
    let hash = [9u8; 32];
    {
        let state = opening.registration.owner().state.lock();
        let transaction = state.engine.database().unwrap().begin_write().unwrap();
        {
            let mut catalog = transaction.open_table(crate::CATALOG).unwrap();
            catalog
                .insert(hash.as_slice(), b"ciphertext".as_slice())
                .unwrap();
        }
        transaction.commit().unwrap();
    }

    let failed_read = opening.queue_read().unwrap();
    assert_eq!(failed_read.begin(), NodeReadPhase::Active);
    assert!(matches!(
        failed_read.catalog_bytes(hash, 1),
        Err(NodeReadAccessError::Reported)
    ));
    {
        let report = failed_read.report();
        assert!(matches!(
            report.read_failure(),
            TerminalObservation::Returned(Err(kasumi_kv::BoundedReadError::BoundExceeded))
        ));
    }
    assert_eq!(failed_read.retire(), StorageCensusDisposition::Retired);

    let denied_output = opening.queue_read().unwrap();
    assert_eq!(denied_output.begin(), NodeReadPhase::Active);
    memory.fail_next.store(true, Ordering::Release);
    assert!(matches!(
        denied_output.catalog_bytes(hash, 64),
        Err(NodeReadAccessError::Reported)
    ));
    {
        let report = denied_output.report();
        assert!(matches!(
            report.output_admission(),
            TerminalObservation::Returned(Err(_))
        ));
    }
    assert_eq!(denied_output.retire(), StorageCensusDisposition::Retired);

    let failed_begin = opening.queue_read().unwrap();
    {
        // Test the queued begin failure after its database became unavailable.
        let mut state = opening.registration.owner().state.lock();
        assert_eq!(
            state.engine.close().settlement(),
            DatabaseOpenSettlement::Closed
        );
    }
    assert_eq!(failed_begin.begin(), NodeReadPhase::Failed);
    {
        let report = failed_begin.report();
        assert!(matches!(
            report.begin(),
            TerminalObservation::Returned(Err(_))
        ));
    }
    assert_eq!(failed_begin.retire(), StorageCensusDisposition::Retired);
    assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn owned_reader_point_and_range_bytes_keep_exact_credit_after_close() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("reader-owned-output.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening = RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let tables = opening.queue_node_tables().unwrap();
    assert_eq!(tables.run(), NodeWriterPhase::Finished);
    opening.publish_ready_after_tables(&tables).unwrap();
    assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
    let key = b"tenant/row";
    let value = b"encrypted value";
    {
        let state = opening.registration.owner().state.lock();
        let transaction = state.engine.database().unwrap().begin_write().unwrap();
        {
            let mut records = transaction.open_table(crate::RECORDS).unwrap();
            records.insert(key.as_slice(), value.as_slice()).unwrap();
        }
        transaction.commit().unwrap();
    }

    let reader = opening.queue_read().unwrap();
    assert_eq!(reader.begin(), NodeReadPhase::Active);
    let before = memory.snapshot();
    let point = reader.record_bytes(key, 64).unwrap().unwrap();
    let row = reader.next_record(b"tenant/", None, 64).unwrap().unwrap();
    assert_eq!(point.as_bytes(), value);
    assert_eq!(row.key(), key);
    assert_eq!(row.value(), value);
    let point_charge = TestDiskMemory::required_reservation_bytes(
        crate::disk_memory::allocation::<u8>(64).unwrap(),
    )
    .unwrap();
    let row_charge = TestDiskMemory::required_reservation_bytes(
        crate::disk_memory::add(
            crate::disk_memory::allocation::<u8>(8192).unwrap(),
            crate::disk_memory::allocation::<u8>(64).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let native_charge = |len: usize| {
        TestDiskMemory::required_reservation_bytes(
            crate::disk_memory::add(
                len as u64,
                crate::disk_memory::allocation::<crate::DiskMemoryLease>(1).unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let point_total = point_charge + native_charge(value.len());
    let row_total = row_charge + native_charge(key.len()) + native_charge(value.len());
    let charged = memory.snapshot();
    assert_eq!(
        charged.used_bytes - before.used_bytes,
        point_total + row_total
    );
    assert_eq!(charged.live_reservations - before.live_reservations, 5);

    assert_eq!(reader.finish(), NodeReadPhase::Finished);
    assert_eq!(reader.retire(), StorageCensusDisposition::Retired);
    assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
    let held = memory.snapshot();
    drop(row);
    let after_row = memory.snapshot();
    assert_eq!(held.used_bytes - after_row.used_bytes, row_total);
    assert_eq!(held.live_reservations - after_row.live_reservations, 3);
    drop(point);
    let after_point = memory.snapshot();
    assert_eq!(after_row.used_bytes - after_point.used_bytes, point_total);
    assert_eq!(
        after_row.live_reservations - after_point.live_reservations,
        2
    );
}

#[test]
fn reader_output_admission_panic_is_reported_and_seals_new_work() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("reader-output-panic.kasumi");
    let (memory, _, _) = PausedRegistrationMemory::new();
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let opening = RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let tables = opening.queue_node_tables().unwrap();
    assert_eq!(tables.run(), NodeWriterPhase::Finished);
    opening.publish_ready_after_tables(&tables).unwrap();
    assert_eq!(tables.retire(), StorageCensusDisposition::Retired);

    let reader = opening.queue_read().unwrap();
    assert_eq!(reader.begin(), NodeReadPhase::Active);
    memory.panic_next.store(true, Ordering::Release);
    assert!(matches!(
        reader.catalog_bytes([0; 32], 64),
        Err(NodeReadAccessError::Reported)
    ));
    {
        let report = reader.report();
        let TerminalObservation::Panicked(payload) = report.output_admission() else {
            panic!("original output admission panic was not retained");
        };
        assert_eq!(
            payload.downcast_ref::<&'static str>(),
            Some(&"reader output admission panic")
        );
    }
    assert!(opening.queue_read().is_err());
    assert_eq!(reader.finish(), NodeReadPhase::Finished);
    assert_eq!(reader.retire(), StorageCensusDisposition::Retired);
    assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
}

fn header_state(path: &Path) -> u8 {
    let mut bytes = [0; 33];
    std::fs::File::open(path)
        .unwrap()
        .read_exact(&mut bytes)
        .unwrap();
    bytes[32]
}

fn disk(path: &Path, memory: &Arc<TestDiskMemory>) -> Arc<NodeDisk> {
    retry_disk_registry(|| NodeDisk::fixture_for_path(path, memory.clone())).unwrap()
}
// Every assertion failure releases the actual serial gate and joins the
// worker; the fixture never leaves a detached accepted writer behind.
struct HeldQueue<'a> {
    serial: Option<MutexGuard<'a, ()>>,
    worker: Option<std::thread::JoinHandle<NodeWriterPhase>>,
}
impl<'a> HeldQueue<'a> {
    fn start(opening: &'a RegisteredNodeOpening, queued: RegisteredNodeTables) -> Self {
        let serial = opening.registration.owner().serial.lock();
        let worker = std::thread::spawn(move || queued.run());
        Self {
            serial: Some(serial),
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> NodeWriterPhase {
        drop(self.serial.take());
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for HeldQueue<'_> {
    fn drop(&mut self) {
        drop(self.serial.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

const ID: Uuid = Uuid::from_u128(0x38a5_c9c5_6a88_41f0_a1a3_a723_fe68_4535);

struct PausedRegistrationMemory {
    census: crate::StorageCensus,
    backing: Arc<TestDiskMemory>,
    pause_next: AtomicBool,
    fail_next: AtomicBool,
    panic_next: AtomicBool,
    entered: std::sync::mpsc::Sender<()>,
    resume: Mutex<std::sync::mpsc::Receiver<()>>,
}
impl PausedRegistrationMemory {
    fn new() -> (
        Arc<Self>,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (entered, observe) = std::sync::mpsc::channel();
        let (resume, release) = std::sync::mpsc::channel();
        let owner = Arc::new(Self {
            census: crate::StorageCensus::allocate(16).unwrap(),
            backing: TestDiskMemory::new(256 << 20, 4096),
            pause_next: AtomicBool::new(false),
            fail_next: AtomicBool::new(false),
            panic_next: AtomicBool::new(false),
            entered,
            resume: Mutex::new(release),
        });
        let provider: Arc<dyn NodeDiskMemoryAdmission> = owner.clone();
        owner.census.bind_provider(&provider).unwrap();
        (owner, observe, resume)
    }
}
impl NodeDiskMemoryAdmission for PausedRegistrationMemory {
    fn storage_census(&self) -> &crate::StorageCensus {
        &self.census
    }
    fn reserve_installed(self: Arc<Self>, bytes: u64) -> io::Result<crate::DiskMemoryLease> {
        if self.panic_next.swap(false, Ordering::AcqRel) {
            panic!("reader output admission panic");
        }
        if self.fail_next.swap(false, Ordering::AcqRel) {
            return Err(io::ErrorKind::Other.into());
        }
        if self.pause_next.swap(false, Ordering::AcqRel) {
            self.entered.send(()).unwrap();
            self.resume.lock().recv().unwrap();
        }
        self.backing.clone().reserve_installed(bytes)
    }
}

#[test]
fn close_during_table_registration_returns_the_exact_cancelled_request() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("registration-race.kasumi");
    let (memory, entered, resume) = PausedRegistrationMemory::new();
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let opening =
        Arc::new(RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap());
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    memory.pause_next.store(true, Ordering::Release);
    let queued = opening.clone();
    let worker = std::thread::spawn(move || queued.queue_node_tables());
    let observed = entered.recv_timeout(Duration::from_secs(5));
    let close = opening.close();
    let _ = resume.send(());
    let queued = worker.join().unwrap();
    observed.unwrap();
    assert_eq!(close.unwrap(), DatabaseOpenSettlement::Closed);
    let cancelled = queued.expect("registered child lost when close sealed admission");
    let child_id = cancelled.id();
    assert_eq!(cancelled.run(), NodeWriterPhase::Cancelled);
    assert!(matches!(
        cancelled.report().begin(),
        TerminalObservation::NotEntered
    ));
    assert_eq!(memory.storage_census().snapshot().writers, 1);
    let held = RegisteredNodeTables::retained(memory.clone(), child_id)
        .expect("exact cancelled child must remain addressable");
    assert_eq!(cancelled.retire(), StorageCensusDisposition::Retained);
    assert_eq!(held.id(), child_id);
    assert_eq!(held.run(), NodeWriterPhase::Cancelled);
    assert_eq!(held.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.storage_census().snapshot().writers, 0);
    assert!(matches!(
        opening.report().ready_publication(),
        TerminalObservation::NotEntered
    ));
    let opening = Arc::try_unwrap(opening).ok().unwrap();
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn close_during_read_registration_returns_the_exact_cancelled_request() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("read-registration-race.kasumi");
    let (memory, entered, resume) = PausedRegistrationMemory::new();
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let opening =
        Arc::new(RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap());
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let tables = opening.queue_node_tables().unwrap();
    assert_eq!(tables.run(), NodeWriterPhase::Finished);
    opening.publish_ready_after_tables(&tables).unwrap();
    assert_eq!(tables.retire(), StorageCensusDisposition::Retired);

    memory.pause_next.store(true, Ordering::Release);
    let queued = opening.clone();
    let worker = std::thread::spawn(move || queued.queue_read());
    let observed = entered.recv_timeout(Duration::from_secs(5));
    let close = opening.close();
    let _ = resume.send(());
    let queued = worker.join().unwrap();
    observed.unwrap();
    assert_eq!(close.unwrap(), DatabaseOpenSettlement::Closed);
    let cancelled = queued.expect("registered reader lost when close sealed admission");
    let child_id = cancelled.id();
    assert_eq!(cancelled.phase(), NodeReadPhase::Cancelled);
    assert_eq!(cancelled.begin(), NodeReadPhase::Cancelled);
    assert_eq!(memory.storage_census().snapshot().readers, 1);
    let held = RegisteredNodeRead::retained(memory.clone(), child_id)
        .expect("exact cancelled reader must remain addressable");
    assert_eq!(cancelled.retire(), StorageCensusDisposition::Retained);
    assert_eq!(held.id(), child_id);
    assert_eq!(held.begin(), NodeReadPhase::Cancelled);
    assert_eq!(held.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    let opening = Arc::try_unwrap(opening).ok().unwrap();
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn ready_publication_requires_the_exact_committed_disposed_tables_request_once() {
    let first_directory = private_tempdir().unwrap();
    let second_directory = private_tempdir().unwrap();
    let first_path = first_directory.path().join("first.kasumi");
    let second_path = second_directory.path().join("second.kasumi");
    let first_memory = TestDiskMemory::new(256 << 20, 4096);
    let second_memory = TestDiskMemory::new(256 << 20, 4096);
    let first = RegisteredNodeOpening::prepare(
        &first_path,
        ID,
        disk(&first_path, &first_memory),
        NodeOpeningMode::Create,
    )
    .unwrap();
    let second = RegisteredNodeOpening::prepare(
        &second_path,
        ID,
        disk(&second_path, &second_memory),
        NodeOpeningMode::Create,
    )
    .unwrap();
    assert_eq!(first.open(), NodeOpeningPhase::Open);
    assert_eq!(second.open(), NodeOpeningPhase::Open);
    let tables = first.queue_node_tables().unwrap();
    assert!(first.queue_node_tables().is_err());
    assert!(first.publish_ready_after_tables(&tables).is_err());
    assert_eq!(header_state(&first_path), 1);
    assert_eq!(tables.run(), NodeWriterPhase::Finished);
    assert!(second.publish_ready_after_tables(&tables).is_err());
    assert_eq!(header_state(&second_path), 1);
    assert!(matches!(
        first.report().ready_publication(),
        TerminalObservation::NotEntered
    ));
    first.publish_ready_after_tables(&tables).unwrap();
    assert_eq!(header_state(&first_path), 2);
    assert!(matches!(
        first.report().ready_publication(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(first.publish_ready_after_tables(&tables).is_err());
    assert_eq!(first.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
    assert_eq!(first.retire(), StorageCensusDisposition::Retired);
    assert_eq!(second.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(second.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn aborted_table_body_is_not_a_ready_publication_proof() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("aborted.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let opening =
        RegisteredNodeOpening::prepare(&path, ID, disk(&path, &memory), NodeOpeningMode::Create)
            .unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    {
        let state = opening.registration.owner().state.lock();
        let tx = state.engine.database().unwrap().begin_write().unwrap();
        tx.open_table(kasumi_kv::TableDefinition::<u64, u64>::new(
            "wrapped_keys_v1",
        ))
        .unwrap();
        tx.commit().unwrap();
    }
    let tables = opening.queue_node_tables().unwrap();
    assert_eq!(tables.run(), NodeWriterPhase::Finished);
    assert_eq!(
        tables.report().terminal().unwrap().operation(),
        Some(kasumi_kv::WriteTerminalOperation::Abort)
    );
    assert!(opening.publish_ready_after_tables(&tables).is_err());
    assert!(matches!(
        opening.report().ready_publication(),
        TerminalObservation::NotEntered
    ));
    assert_eq!(header_state(&path), 1);
    assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
}

// A failed physical owner must keep both its descriptor and its directory
// available for the installed census to inspect after this test facade ends.
static FAILED_READY_DIRECTORY: std::sync::Mutex<Option<tempfile::TempDir>> =
    std::sync::Mutex::new(None);
#[test]
fn failed_ready_attempt_is_one_shot_and_keeps_the_original_registered_owner() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("failed-ready.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening =
        RegisteredNodeOpening::prepare(&path, ID, disk.clone(), NodeOpeningMode::Create).unwrap();
    FAILED_READY_DIRECTORY.lock().unwrap().replace(directory);
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let tables = opening.queue_node_tables().unwrap();
    assert_eq!(tables.run(), NodeWriterPhase::Finished);
    disk.fail();
    assert!(opening.publish_ready_after_tables(&tables).is_err());
    let original = {
        let report = opening.report();
        let TerminalObservation::Returned(Err(error)) = report.ready_publication() else {
            panic!("expected original Ready failure");
        };
        std::ptr::from_ref(error)
    };
    assert_eq!(header_state(&path), 1);
    assert!(opening.publish_ready_after_tables(&tables).is_err());
    let id = opening.id();
    drop(tables);
    drop(opening);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    let retained = RegisteredNodeOpening::retained(memory.clone(), id).unwrap();
    let report = retained.report();
    let TerminalObservation::Returned(Err(error)) = report.ready_publication() else {
        panic!("original Ready failure lost");
    };
    assert_eq!(std::ptr::from_ref(error), original);
    assert_eq!(memory.storage_census().snapshot().databases, 1);
}

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
            Some(kasumi_kv::WriteTerminalOperation::Commit)
        );
        assert!(terminal.disposal_complete());
        assert!(matches!(
            terminal.terminal(),
            TerminalObservation::Returned(Ok(()))
        ));
    }
    {
        let state = opening.registration.owner().state.lock();
        let read = state.engine.database().unwrap().begin_read().unwrap();
        read.open_table(crate::CATALOG).unwrap();
        read.open_table(crate::RECORDS).unwrap();
    }
    let id = opening.id();
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_eq!(
        opening.report().engine().settlement(),
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
fn explicit_close_waits_for_the_actual_reader_then_retries_without_consuming_the_facade() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("reader-close.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening = RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let reader = {
        let state = opening.registration.owner().state.lock();
        state.engine.database().unwrap().begin_read().unwrap()
    };
    assert_eq!(
        opening.close().unwrap(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    assert_eq!(opening.report().state.phase, NodeOpeningPhase::Closing);
    assert!(opening.queue_node_tables().is_err());
    assert_eq!(
        opening.close().unwrap(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    drop(reader);
    assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(
        opening.report().engine().settlement(),
        DatabaseOpenSettlement::Closed
    );
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn explicit_close_seals_admission_without_waiting_for_a_held_report() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("held-report-close.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening = RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let report = opening.report();
    assert_eq!(
        opening.close().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(report);
    assert!(opening.queue_node_tables().is_err());
    assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
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
    let paused = HeldQueue::start(&opening, queued);
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
    assert_eq!(paused.finish(), NodeWriterPhase::Cancelled);
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
        let tx = state.engine.database().unwrap().begin_write().unwrap();
        tx.open_table(kasumi_kv::TableDefinition::<u64, u64>::new(
            "wrapped_keys_v1",
        ))
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
            Some(kasumi_kv::WriteTerminalOperation::Abort)
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
            let tx = state.engine.database().unwrap().begin_write().unwrap();
            tx.open_table(kasumi_kv::TableDefinition::<u64, u64>::new(
                "wrapped_keys_v1",
            ))
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
                    kasumi_kv::WriteTerminalOperation::Abort
                } else {
                    kasumi_kv::WriteTerminalOperation::Commit
                })
            );
            assert_eq!(
                terminal.settlement(),
                kasumi_kv::WriteTerminalSettlement::Retained
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
        assert_eq!(report.engine().settlement(), DatabaseOpenSettlement::Closed);
        let TerminalObservation::Returned(Err(error)) = report.acquisition() else {
            panic!("original acquisition error lost");
        };
        assert_eq!(std::ptr::from_ref(error), original);
    }
    assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}

#[test]
fn a_new_close_error_is_not_relinquished_by_the_call_that_first_starts_close() {
    use kasumi_kv::StorageBackend;
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("new-close-error.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening =
        RegisteredNodeOpening::prepare(&path, ID, disk.clone(), NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let id = opening.id();
    let actual = std::ptr::from_ref(opening.registration.owner());
    let file_owner = {
        let state = opening.registration.owner().state.lock();
        assert!(!state.outcomes_released);
        state.file.retained_file_custody().unwrap().0
    };
    let physical = std::fs::read(&path).unwrap();
    let admitted = disk.snapshot();
    // Starting close may produce both a shutdown error and a failed backend
    // outcome. The explicit call keeps both originals in the same owner and
    // neither this call nor a later retirement can preauthorize their release.
    disk.fail();
    assert_eq!(
        opening.close().unwrap(),
        DatabaseOpenSettlement::DrainedWithFailure
    );
    assert_eq!(
        opening.close().unwrap(),
        DatabaseOpenSettlement::DrainedWithFailure
    );
    assert_eq!(opening.retire(), StorageCensusDisposition::Retained);
    let retained = RegisteredNodeOpening::retained(memory.clone(), id).unwrap();
    assert_eq!(std::ptr::from_ref(retained.registration.owner()), actual);
    let (original, backend, native) = {
        let report = retained.report();
        assert!(
            !report.state.outcomes_released,
            "first close must invalidate relinquishment before producing either error"
        );
        let engine = report.engine();
        assert_eq!(
            engine.settlement(),
            DatabaseOpenSettlement::DrainedWithFailure
        );
        let close = engine.database_close().unwrap();
        let TerminalObservation::Returned(Err(shutdown)) = close.shutdown() else {
            panic!("new original shutdown failure absent");
        };
        let TerminalObservation::Returned(Err(backend)) = close.backend() else {
            panic!("failed file owner must not produce positive backend close");
        };
        let (owner, native) = report.state.file.retained_file_custody().unwrap();
        assert_eq!(owner, file_owner);
        assert!(
            native.is_some(),
            "original file-owner error must remain retained"
        );
        (
            std::ptr::from_ref(shutdown),
            std::ptr::from_ref(backend),
            native,
        )
    };
    assert_eq!(disk.snapshot().open_files, 1);
    assert_eq!(disk.snapshot().charged_bytes, admitted.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, admitted.pending_bytes);
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Failed);
    assert!(
        disk.reconcile(&crate::CensusCancellation::default())
            .is_err()
    );
    drop(retained);
    let charged = memory.snapshot();
    for _ in 0..2 {
        assert_eq!(
            memory.storage_census().drain_owner(id),
            StorageCensusDisposition::Retained
        );
        assert_eq!(memory.snapshot(), charged);
        let observed = RegisteredNodeOpening::retained(memory.clone(), id).unwrap();
        assert_eq!(std::ptr::from_ref(observed.registration.owner()), actual);
        assert!(observed.queue_node_tables().is_err());
        {
            let report = observed.report();
            assert!(!report.state.outcomes_released);
            let engine = report.engine();
            assert_eq!(
                engine.settlement(),
                DatabaseOpenSettlement::DrainedWithFailure
            );
            let close = engine.database_close().unwrap();
            let TerminalObservation::Returned(Err(error)) = close.shutdown() else {
                panic!("close original was erased");
            };
            assert_eq!(std::ptr::from_ref(error), original);
            let TerminalObservation::Returned(Err(error)) = close.backend() else {
                panic!("backend close original was erased");
            };
            assert_eq!(std::ptr::from_ref(error), backend);
            assert_eq!(
                report.state.file.retained_file_custody(),
                Some((file_owner, native))
            );
            assert!(report.state.file.backend().len().is_err());
        }
        // Inspecting/relinquishing reports is not proof that the retained
        // physical owner and its error custody have retired.
        assert_eq!(observed.retire(), StorageCensusDisposition::Retained);
        let still_retained = RegisteredNodeOpening::retained(memory.clone(), id).unwrap();
        assert!(
            !still_retained
                .registration
                .owner()
                .state
                .lock()
                .outcomes_released,
            "an unresolved close cannot preserve a blanket future acknowledgement"
        );
        drop(still_retained);
        assert_eq!(memory.snapshot(), charged);
        assert_eq!(disk.snapshot().open_files, 1);
        assert_eq!(disk.snapshot().charged_bytes, admitted.charged_bytes);
        assert_eq!(disk.snapshot().pending_bytes, admitted.pending_bytes);
        assert!(
            disk.reconcile(&crate::CensusCancellation::default())
                .is_err()
        );
        let (root, relative) = disk.binding(&path).unwrap();
        assert!(disk.open_file(root, relative).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), physical);
    }
    // Ordinary retirement never acknowledges the failed-close generation.
    // Without explicit recovery the installed owner remains after all facades
    // disappear, even though native closure is now separately proved.
    assert_eq!(memory.storage_census().snapshot().databases, 1);
    assert_eq!(memory.storage_census().snapshot().writers, 0);
    assert_eq!(disk.snapshot().open_files, 1);
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Failed);
}

#[test]
fn queued_relinquishment_seals_the_request_before_another_facade_can_run() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("sealed-queue.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening = RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let first = opening.queue_node_tables().unwrap();
    let second = RegisteredNodeTables::retained(memory.clone(), first.id()).unwrap();
    assert_eq!(first.retire(), StorageCensusDisposition::Retained);
    assert_eq!(second.run(), NodeWriterPhase::Cancelled);
    assert!(matches!(
        second.report().begin(),
        TerminalObservation::NotEntered
    ));
    assert!(second.report().terminal().is_none());
    assert_eq!(second.retire(), StorageCensusDisposition::Retired);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn busy_worker_cannot_acknowledge_the_body_error_that_it_has_not_produced_yet() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("busy-report-release.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening = RegisteredNodeOpening::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    {
        let state = opening.registration.owner().state.lock();
        let tx = state.engine.database().unwrap().begin_write().unwrap();
        tx.open_table(kasumi_kv::TableDefinition::<u64, u64>::new(
            "wrapped_keys_v1",
        ))
        .unwrap();
        tx.commit().unwrap();
    }
    let first = opening.queue_node_tables().unwrap();
    let id = first.id();
    let observer = RegisteredNodeTables::retained(memory.clone(), id).unwrap();
    let queued = RegisteredNodeTables::retained(memory.clone(), id).unwrap();
    let paused = HeldQueue::start(&opening, queued);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !observer.registration.owner().state.is_locked() {
        assert!(
            Instant::now() < deadline,
            "worker did not enter the real serial queue"
        );
        std::thread::yield_now();
    }
    let started = Instant::now();
    assert_eq!(first.retire(), StorageCensusDisposition::Retained);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "relinquishment waited for an active worker"
    );
    assert_eq!(paused.finish(), NodeWriterPhase::Finished);
    let original = {
        let report = observer.report();
        let TerminalObservation::Returned(Err(NodeTablesBodyError::Catalog(error))) = report.body()
        else {
            panic!("actual body failure absent");
        };
        assert!(report.terminal().unwrap().disposal_complete());
        std::ptr::from_ref(error)
    };
    drop(observer);
    drop(opening);
    let snapshot = memory.storage_census().drain().unwrap();
    assert_eq!(snapshot.writers, 1);
    let retained = RegisteredNodeTables::retained(memory.clone(), id).unwrap();
    {
        let report = retained.report();
        let TerminalObservation::Returned(Err(NodeTablesBodyError::Catalog(error))) = report.body()
        else {
            panic!("unacknowledged original lost");
        };
        assert_eq!(std::ptr::from_ref(error), original);
    }
    assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
    let final_snapshot = memory.storage_census().drain().unwrap();
    assert_eq!(final_snapshot.writers, 0);
    assert_eq!(final_snapshot.databases, 0);
}

#[test]
fn explicit_failed_close_requires_original_acknowledgement_then_accepted_disk_census_before_retirement()
 {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("explicit-failed-recovery.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening =
        RegisteredNodeOpening::prepare(&path, ID, disk.clone(), NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    assert!(
        opening
            .report()
            .acknowledge_failed_close(|_| panic!("no outcome exists"))
            .is_err()
    );
    let id = opening.id();
    let physical = std::fs::read(&path).unwrap();
    disk.fail();
    assert_eq!(opening.retire(), StorageCensusDisposition::Retained);
    let retained = RegisteredNodeOpening::retained(memory.clone(), id).unwrap();
    let (shutdown, backend, original_native, acknowledgement) = {
        let report = retained.report();
        let engine = report.engine();
        let close = engine.database_close().unwrap();
        let TerminalObservation::Returned(Err(shutdown)) = close.shutdown() else {
            panic!("shutdown error absent")
        };
        let TerminalObservation::Returned(Err(backend)) = close.backend() else {
            panic!("backend error absent")
        };
        let (_, native) = report.state.file.retained_file_custody().unwrap();
        let mut seen = None;
        let (ack, allocations) = crate::allocation_tests::measure(|| {
            report.acknowledge_failed_close(|error| {
                assert!(seen.replace(std::ptr::from_ref(error) as usize).is_none());
            })
        });
        let ack = ack.unwrap();
        assert_eq!(allocations, 0);
        assert_eq!(seen, native);
        assert!(!report.state.outcomes_released);
        (
            std::ptr::from_ref(shutdown),
            std::ptr::from_ref(backend),
            native,
            ack,
        )
    };
    assert!(original_native.is_some());
    let before_transfer = disk.snapshot();
    let (recovery, allocations) =
        crate::allocation_tests::measure(|| retained.recover_failed_close(acknowledgement));
    assert_eq!(recovery.unwrap(), FailedOpeningRecovery::AwaitingDiskCensus);
    assert_eq!(allocations, 0);
    assert_eq!(disk.snapshot().charged_bytes, before_transfer.charged_bytes);
    assert_eq!(disk.snapshot().open_files, 1);
    {
        let report = retained.report();
        assert_eq!(
            report.engine().settlement(),
            DatabaseOpenSettlement::FailedDisposed
        );
        let engine = report.engine();
        let close = engine.database_close().unwrap();
        let TerminalObservation::Returned(Err(error)) = close.shutdown() else {
            panic!("original shutdown lost")
        };
        assert_eq!(std::ptr::from_ref(error), shutdown);
        let TerminalObservation::Returned(Err(error)) = close.backend() else {
            panic!("original backend lost")
        };
        assert_eq!(std::ptr::from_ref(error), backend);
        assert!(report.acknowledge_failed_close(|_| ()).is_err());
        assert!(report.state.file.failed_close_witness().is_err());
    }
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    let cancelled = crate::CensusCancellation::default();
    cancelled.cancel();
    assert!(disk.reconcile(&cancelled).is_err());
    assert_eq!(disk.snapshot().open_files, 1);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_eq!(std::fs::read(&path).unwrap(), physical);
    disk.reconcile(&crate::CensusCancellation::default())
        .unwrap();
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, before_transfer.charged_bytes);
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
    // The accepted native/namespace census does not erase higher-level errors.
    // The actual facade still prevents StorageCensus from dropping their owner.
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    {
        let report = retained.report();
        let engine = report.engine();
        let close = engine.database_close().unwrap();
        let TerminalObservation::Returned(Err(error)) = close.backend() else {
            panic!("error released before final facade")
        };
        assert_eq!(std::ptr::from_ref(error), backend);
    }
    assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.storage_census().snapshot().databases, 0);
    assert_eq!(std::fs::read(&path).unwrap(), physical);
}

#[test]
fn failed_acknowledgement_cannot_cross_memory_cores_with_equal_public_owner_ids() {
    let first_dir = private_tempdir().unwrap();
    let second_dir = private_tempdir().unwrap();
    let first_path = first_dir.path().join("first.kasumi");
    let second_path = second_dir.path().join("second.kasumi");
    let first_memory = TestDiskMemory::new(256 << 20, 4096);
    let second_memory = TestDiskMemory::new(256 << 20, 4096);
    let first_disk = disk(&first_path, &first_memory);
    let second_disk = disk(&second_path, &second_memory);
    let first = RegisteredNodeOpening::prepare(
        &first_path,
        ID,
        first_disk.clone(),
        NodeOpeningMode::Create,
    )
    .unwrap();
    let second = RegisteredNodeOpening::prepare(
        &second_path,
        ID,
        second_disk.clone(),
        NodeOpeningMode::Create,
    )
    .unwrap();
    assert_eq!(first.open(), NodeOpeningPhase::Open);
    assert_eq!(second.open(), NodeOpeningPhase::Open);
    assert_eq!(
        first.id(),
        second.id(),
        "regression requires equal per-core public IDs"
    );
    first_disk.fail();
    second_disk.fail();
    let first_id = first.id();
    let second_id = second.id();
    assert_eq!(first.retire(), StorageCensusDisposition::Retained);
    assert_eq!(second.retire(), StorageCensusDisposition::Retained);
    let first = RegisteredNodeOpening::retained(first_memory.clone(), first_id).unwrap();
    let second = RegisteredNodeOpening::retained(second_memory.clone(), second_id).unwrap();
    let wrong = first.report().acknowledge_failed_close(|_| ()).unwrap();
    let second_custody = second.report().state.file.retained_file_custody();
    assert_eq!(
        second.recover_failed_close(wrong).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        second.report().engine().settlement(),
        DatabaseOpenSettlement::DrainedWithFailure
    );
    assert_eq!(
        second.report().state.file.retained_file_custody(),
        second_custody
    );
    for (opening, disk, memory) in [
        (first, first_disk, first_memory),
        (second, second_disk, second_memory),
    ] {
        let acknowledgement = opening.report().acknowledge_failed_close(|_| ()).unwrap();
        assert_eq!(
            opening.recover_failed_close(acknowledgement).unwrap(),
            FailedOpeningRecovery::AwaitingDiskCensus
        );
        disk.reconcile(&crate::CensusCancellation::default())
            .unwrap();
        assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
        assert_eq!(memory.storage_census().snapshot().databases, 0);
    }
}

#[test]
fn disposed_failed_owner_resumes_after_actual_transfer_contention_without_replaying_disposal() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("transfer-contention.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening =
        RegisteredNodeOpening::prepare(&path, ID, disk.clone(), NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let id = opening.id();
    disk.fail();
    assert_eq!(opening.retire(), StorageCensusDisposition::Retained);
    let retained = RegisteredNodeOpening::retained(memory.clone(), id).unwrap();
    let acknowledgement = retained.report().acknowledge_failed_close(|_| ()).unwrap();
    let physical_owner = retained.report().state.file.retained_file_custody();
    let (start_send, start_receive) = std::sync::mpsc::sync_channel(0);
    let (ready_send, ready_receive) = std::sync::mpsc::sync_channel(0);
    let (release_send, release_receive) = std::sync::mpsc::sync_channel(0);
    std::thread::scope(|scope| {
        let holder_disk = disk.clone();
        let holder = scope.spawn(move || {
            start_receive.recv().unwrap();
            holder_disk.with_state_locked_for_test(|| {
                ready_send.send(()).unwrap();
                let _ = release_receive.recv();
            });
        });
        retained
            .registration
            .owner()
            .state
            .lock()
            .after_failed_disposal = Some(Box::new(move || {
            start_send.send(()).unwrap();
            ready_receive.recv().unwrap();
        }));
        assert_eq!(
            retained.recover_failed_close(acknowledgement).unwrap(),
            FailedOpeningRecovery::PendingTransfer
        );
        let originals = {
            let report = retained.report();
            assert_eq!(
                report.engine().settlement(),
                DatabaseOpenSettlement::FailedDisposed
            );
            assert!(matches!(
                report.engine().failed_disposal(),
                TerminalObservation::Returned(Ok(()))
            ));
            let engine = report.engine();
            let close = engine.database_close().unwrap();
            let TerminalObservation::Returned(Err(shutdown)) = close.shutdown() else {
                panic!("shutdown original missing")
            };
            let TerminalObservation::Returned(Err(backend)) = close.backend() else {
                panic!("backend original missing")
            };
            assert!(!report.state.outcomes_released);
            assert!(report.state.pending_transfer.is_some());
            (std::ptr::from_ref(shutdown), std::ptr::from_ref(backend))
        };
        assert_eq!(
            retained.resume_failed_recovery().unwrap(),
            FailedOpeningRecovery::PendingTransfer
        );
        assert_eq!(
            memory.storage_census().drain_owner(id),
            StorageCensusDisposition::Retained
        );
        release_send.send(()).unwrap();
        holder.join().unwrap();
        assert_eq!(
            retained.report().state.file.retained_file_custody(),
            physical_owner
        );
        assert_eq!(
            retained.resume_failed_recovery().unwrap(),
            FailedOpeningRecovery::AwaitingDiskCensus
        );
        let report = retained.report();
        let engine = report.engine();
        let close = engine.database_close().unwrap();
        let TerminalObservation::Returned(Err(shutdown)) = close.shutdown() else {
            panic!("shutdown original changed")
        };
        let TerminalObservation::Returned(Err(backend)) = close.backend() else {
            panic!("backend original changed")
        };
        assert_eq!(
            (std::ptr::from_ref(shutdown), std::ptr::from_ref(backend)),
            originals
        );
        assert!(matches!(
            engine.failed_disposal(),
            TerminalObservation::Returned(Ok(()))
        ));
    });
    disk.reconcile(&crate::CensusCancellation::default())
        .unwrap();
    assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}

#[test]
fn unknown_native_opening_close_vetoes_acknowledgement_and_never_retries_the_handle() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("unknown-native-close.kasumi");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening =
        RegisteredNodeOpening::prepare(&path, ID, disk.clone(), NodeOpeningMode::Create).unwrap();
    assert_eq!(opening.open(), NodeOpeningPhase::Open);
    let id = opening.id();
    let physical = std::fs::read(&path).unwrap();
    // Fence shutdown first so the injected close belongs to backend retirement,
    // rather than a preceding temporary verification walk.
    disk.fail();
    NodeFile::fail_next_native_close(libc::EIO);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retained);
    let attempts = NodeFile::native_close_attempts();
    let retained = RegisteredNodeOpening::retained(memory.clone(), id).unwrap();
    let (backend, native_owner) = {
        let report = retained.report();
        let engine = report.engine();
        assert_eq!(engine.settlement(), DatabaseOpenSettlement::Retained);
        assert_eq!(
            engine.native_disposition(),
            kasumi_kv::BackendNativeDisposition::Retained
        );
        let close = engine.database_close().unwrap();
        let TerminalObservation::Returned(Err(error)) = close.backend() else {
            panic!("original native close error absent")
        };
        assert!(
            report
                .acknowledge_failed_close(|_| panic!("unknown close cannot be acknowledged"))
                .is_err()
        );
        (
            std::ptr::from_ref(error),
            report.state.file.retained_file_custody(),
        )
    };
    let charged = disk.snapshot().charged_bytes;
    for _ in 0..2 {
        assert!(retained.resume_failed_recovery().is_err());
        assert_eq!(
            memory.storage_census().drain_owner(id),
            StorageCensusDisposition::Retained
        );
        assert!(
            disk.reconcile(&crate::CensusCancellation::default())
                .is_err()
        );
        let report = retained.report();
        let engine = report.engine();
        let close = engine.database_close().unwrap();
        let TerminalObservation::Returned(Err(error)) = close.backend() else {
            panic!("original error erased")
        };
        assert_eq!(std::ptr::from_ref(error), backend);
        assert_eq!(report.state.file.retained_file_custody(), native_owner);
        assert!(matches!(
            engine.failed_disposal(),
            TerminalObservation::NotEntered
        ));
        assert!(!report.state.outcomes_released);
        assert_eq!(NodeFile::native_close_attempts(), attempts);
        assert_eq!(disk.snapshot().charged_bytes, charged);
        assert_eq!(std::fs::read(&path).unwrap(), physical);
    }
    drop(retained);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_eq!(disk.snapshot().open_files, 1);
    assert_eq!(NodeFile::native_close_attempts(), attempts);
}

#[test]
fn private_opening_arc_is_admitted_before_any_prepared_owner_allocation() {
    use crate::disk_memory::{add, allocation, arc};
    const MAX_BYTES: u64 = 256 << 20;
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("proxy-admission.kasumi");
    let memory = TestDiskMemory::new(MAX_BYTES, 4096);
    let disk = disk(&path, &memory);
    let baseline = memory.snapshot();
    let former_backing = add(
        arc::<DatabaseOwner>().unwrap(),
        NodeFile::prepared_backing_bytes(&path).unwrap(),
    )
    .unwrap();
    let former_charge = TestDiskMemory::required_reservation_bytes(former_backing).unwrap();
    let layout = kasumi_kv::Builder::retained_opening_allocation_layout().unwrap();
    let proxy_charge = allocation::<u8>(u64::try_from(layout.size()).unwrap()).unwrap();
    let complete_charge =
        TestDiskMemory::required_reservation_bytes(add(former_backing, proxy_charge).unwrap())
            .unwrap();
    assert!(complete_charge > former_charge);
    let fill_charge = MAX_BYTES - baseline.bookkeeping_bytes - baseline.used_bytes - former_charge;
    let held = memory
        .clone()
        .reserve_installed(fill_charge - TestDiskMemory::required_reservation_bytes(0).unwrap())
        .unwrap();
    let full = memory.snapshot();
    let (denied, allocations) = crate::allocation_tests::measure(|| {
        RegisteredNodeOpening::prepare(&path, ID, disk.clone(), NodeOpeningMode::Create)
    });
    assert!(matches!(denied, Err(error) if error.kind() == io::ErrorKind::OutOfMemory));
    assert_eq!(
        allocations, 0,
        "denial precedes NodeFile, path, backend and proxy allocations"
    );
    assert_eq!(memory.snapshot().used_bytes, full.used_bytes);
    assert_eq!(memory.storage_census().snapshot().databases, 0);
    assert_eq!(disk.snapshot().open_files, 0);
    assert!(!path.exists());
    drop(held);
    let opening =
        RegisteredNodeOpening::prepare(&path, ID, disk.clone(), NodeOpeningMode::Create).unwrap();
    let id = opening.id();
    assert_eq!(
        memory.snapshot().used_bytes - baseline.used_bytes,
        complete_charge
    );
    assert!(!path.exists());
    drop(opening);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retired
    );
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(disk.snapshot().open_files, 0);
    assert!(!path.exists());
}
