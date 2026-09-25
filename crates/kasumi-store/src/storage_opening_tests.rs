use super::*;
use crate::{
    CATALOG, NodeDiskMemoryAdmission, NodeStore, NodeStoreOpeningFailure, RECORDS, ScratchDisk,
    test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry},
};
use std::{
    io::{self, Read},
    sync::atomic::AtomicU64,
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
fn queued_store_writer_does_not_hold_opening_lock_against_close() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("queued-store-writer.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let mut startup =
        RegisteredNodeStartup::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    assert_eq!(startup.advance(), NodeStartupPhase::Ready);
    let opening = std::sync::Arc::new(startup.into_opening().ok().unwrap());
    let first = opening.begin_store_write().unwrap();
    let queued = opening.clone();
    let worker = std::thread::spawn(move || match queued.begin_store_write() {
        Err(kasumi_kv::TransactionError(kasumi_kv::StorageError::DatabaseClosed)) => true,
        Ok(writer) => {
            writer.abort().unwrap();
            false
        }
        Err(_) => false,
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let waiting = loop {
        if let Some(state) = opening.registration.owner().state.try_lock()
            && state
                .engine
                .database()
                .is_some_and(|database| database.active_transactions() > 2)
        {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::yield_now();
    };
    let close = opening.close();
    first.abort().unwrap();
    let second_closed = worker.join().unwrap();
    assert!(
        waiting,
        "queued writer never released the opening state lock"
    );
    assert_eq!(
        close.unwrap(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    assert!(
        second_closed,
        "queued writer was admitted after close sealed it"
    );
    assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
    let opening = std::sync::Arc::try_unwrap(opening).ok().unwrap();
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn active_reader_finish_waits_for_opening_lock_before_reporting_completion() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("reader-finish-contention.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let mut startup =
        RegisteredNodeStartup::prepare(&path, ID, disk, NodeOpeningMode::Create).unwrap();
    assert_eq!(startup.advance(), NodeStartupPhase::Ready);
    let opening = startup.into_opening().ok().unwrap();
    let reader = opening.queue_read().unwrap();
    assert_eq!(reader.begin(), NodeReadPhase::Active);
    let opening_guard = opening.registration.owner().state.lock();
    let (started, received) = std::sync::mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        started.send(()).unwrap();
        let phase = reader.finish();
        (phase, reader)
    });
    received.recv().unwrap();
    std::thread::sleep(Duration::from_millis(20));
    assert!(
        !worker.is_finished(),
        "reader reported completion before close"
    );
    drop(opening_guard);
    let (phase, reader) = worker.join().unwrap();
    assert_eq!(phase, NodeReadPhase::Finished);
    assert_eq!(reader.retire(), StorageCensusDisposition::Retired);
    assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
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
    assert_eq!(failed_read.finish(), NodeReadPhase::Finished);
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
    assert_eq!(denied_output.finish(), NodeReadPhase::Finished);
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
    let point_total = native_charge(value.len());
    let row_total = row_charge + native_charge(key.len()) + native_charge(value.len());
    let charged = memory.snapshot();
    assert_eq!(
        charged.used_bytes - before.used_bytes,
        point_total + row_total
    );
    assert_eq!(charged.live_reservations - before.live_reservations, 4);

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
        1
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
    let reader_id = reader.id();
    drop(reader);
    assert_eq!(memory.storage_census().snapshot().readers, 1);
    let reader = RegisteredNodeRead::retained(memory.clone(), reader_id)
        .expect("panicked admission retains its exact report after facade drop");
    assert_eq!(reader.phase(), NodeReadPhase::Failed);
    assert!(matches!(
        reader.report().output_admission(),
        TerminalObservation::Panicked(_)
    ));
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
    deny_bytes: AtomicU64,
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
        Self::with_slots(16)
    }

    fn with_slots(
        slots: usize,
    ) -> (
        Arc<Self>,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (entered, observe) = std::sync::mpsc::channel();
        let (resume, release) = std::sync::mpsc::channel();
        let owner = Arc::new(Self {
            census: crate::StorageCensus::allocate(slots).unwrap(),
            backing: TestDiskMemory::new(256 << 20, 4096),
            pause_next: AtomicBool::new(false),
            fail_next: AtomicBool::new(false),
            deny_bytes: AtomicU64::new(0),
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
        if bytes != 0
            && self
                .deny_bytes
                .compare_exchange(bytes, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
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

#[test]
fn failed_pre_descriptor_acquisition_retires_the_registered_opening() {
    let directory = private_tempdir().unwrap();
    let configured_path = directory.path().join("configured.kv");
    let outside = private_tempdir().unwrap();
    let outside_path = outside.path().join("outside.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&configured_path, &memory);
    let initial_bytes = memory.snapshot().used_bytes;
    let opening =
        RegisteredNodeOpening::prepare(&outside_path, ID, disk.clone(), NodeOpeningMode::Create)
            .unwrap();

    assert_eq!(opening.open(), NodeOpeningPhase::FileAcquisition);
    assert!(matches!(
        opening.report().acquisition(),
        kasumi_kv::TerminalObservation::Returned(Err(_))
    ));
    assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.storage_census().snapshot().databases, 0);
    assert_eq!(memory.snapshot().used_bytes, initial_bytes);
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().open_files, 0);
    assert!(!outside_path.exists());
}

#[test]
fn failed_existing_name_acquisition_retires_the_registered_opening() {
    use std::os::unix::fs::PermissionsExt;
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("existing.kv");
    std::fs::write(&path, b"unowned existing bytes").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let opening =
        RegisteredNodeOpening::prepare(&path, ID, disk.clone(), NodeOpeningMode::Create).unwrap();

    assert_eq!(opening.open(), NodeOpeningPhase::FileAcquisition);
    assert!(matches!(
        opening.report().acquisition(),
        kasumi_kv::TerminalObservation::Returned(Err(_))
    ));
    assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
    assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.storage_census().snapshot().databases, 0);
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(std::fs::read(&path).unwrap(), b"unowned existing bytes");
}

#[tokio::test]
async fn production_node_create_reopen_and_shutdown_use_registered_owner() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-node-cutover.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());

    let node = NodeStore::create_new(&path, ID, disk.clone(), scratch.clone()).unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 1);
    {
        let tx = node.db.begin_read().unwrap();
        tx.open_table(CATALOG).unwrap();
        tx.open_table(RECORDS).unwrap();
    }
    node.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 0);
    drop(node);

    let reopened = NodeStore::open_existing(&path, ID, disk, scratch).unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 1);
    reopened.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}

#[tokio::test]
async fn production_catalog_read_registers_child_and_retains_original_table_failure() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-catalog-reader.kv");
    let (memory, entered, resume) = PausedRegistrationMemory::new();
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk.clone(), scratch).unwrap();
    assert!(node.catalog("tenant").unwrap().is_none());
    assert_eq!(memory.storage_census().snapshot().readers, 0);

    memory.pause_next.store(true, Ordering::Release);
    let worker_node = node.clone();
    let worker = std::thread::spawn(move || {
        worker_node
            .catalog("tenant")
            .err()
            .expect("injected reader admission denial fails catalog read")
    });
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    memory.fail_next.store(true, Ordering::Release);
    resume.send(()).unwrap();
    let failure = worker
        .join()
        .unwrap()
        .downcast::<crate::NodeCatalogReadFailure>()
        .expect("registered catalog failure retains the exact child");
    assert_eq!(failure.stage(), "begin");
    let reader_id = failure.reader().id();
    assert_eq!(memory.storage_census().snapshot().readers, 1);
    assert!(matches!(
        failure.reader().report().tables(),
        TerminalObservation::Returned(Err(_))
    ));
    drop(failure);
    let reader = RegisteredNodeRead::retained(memory.clone(), reader_id)
        .expect("census kept the failed reader after error facade drop");
    assert_eq!(reader.phase(), NodeReadPhase::Failed);
    assert!(matches!(
        reader.report().tables(),
        TerminalObservation::Returned(Err(_))
    ));
    assert_eq!(reader.finish(), NodeReadPhase::Finished);
    assert_eq!(reader.retire(), StorageCensusDisposition::Retired);
    let opening_id = node.registered_opening_id().unwrap();
    let close = node.shutdown().await.unwrap_err();
    assert_eq!(
        close.completion(),
        kasumi_types::drain::DrainCompletion::Retained
    );
    assert_eq!(memory.storage_census().snapshot().databases, 1);
    let opening = RegisteredNodeOpening::retained(memory.clone(), opening_id).unwrap();
    assert_eq!(
        opening.report().engine().settlement(),
        DatabaseOpenSettlement::DrainedWithFailure
    );
}

#[tokio::test]
async fn queued_production_catalog_reader_is_cancelled_with_registered_custody() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-queued-reader.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let reader = node.db.queue_registered_read().unwrap();
    let reader_id = reader.id();
    assert_eq!(memory.storage_census().snapshot().readers, 1);
    node.db.stop();
    assert_eq!(reader.begin(), NodeReadPhase::Cancelled);
    drop(reader);
    let reader = RegisteredNodeRead::retained(memory.clone(), reader_id)
        .expect("queued child survives its original facade");
    assert_eq!(reader.phase(), NodeReadPhase::Cancelled);
    assert!(matches!(
        reader.report().begin(),
        TerminalObservation::NotEntered
    ));
    assert_eq!(reader.retire(), StorageCensusDisposition::Retired);
    node.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}

#[tokio::test]
async fn production_catalog_bounded_failure_retires_when_error_is_dropped() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-catalog-bound.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let oversized = vec![0x5a; crate::MAX_KEY_CATALOG_BYTES + 1];
    let tx = node.db.begin_write().unwrap();
    tx.open_table(CATALOG)
        .unwrap()
        .insert(
            crate::tenant_hash("tenant").as_slice(),
            oversized.as_slice(),
        )
        .unwrap();
    tx.commit().unwrap();

    let error = node
        .catalog("tenant")
        .err()
        .unwrap()
        .downcast::<crate::NodeCatalogReadFailure>()
        .expect("catalog bound error retains its original typed report");
    assert_eq!(error.stage(), "catalog bytes");
    let id = error.reader().id();
    assert!(matches!(
        error.reader().report().read_failure(),
        TerminalObservation::Returned(Err(kasumi_kv::BoundedReadError::BoundExceeded))
    ));
    assert_eq!(memory.storage_census().snapshot().readers, 1);
    drop(error);
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    assert!(RegisteredNodeRead::retained(memory.clone(), id).is_none());
    node.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}

#[tokio::test]
async fn production_catalog_output_capacity_failure_retires_when_error_is_dropped() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-catalog-capacity.kv");
    let (memory, _, _) = PausedRegistrationMemory::new();
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let outer_bound =
        crate::disk_memory::allocation::<u8>(u64::try_from(crate::MAX_KEY_CATALOG_BYTES).unwrap())
            .unwrap();
    memory.deny_bytes.store(outer_bound, Ordering::Release);
    let error = node
        .catalog("tenant")
        .err()
        .unwrap()
        .downcast::<crate::NodeCatalogReadFailure>()
        .expect("catalog capacity error retains its original typed report");
    assert_eq!(memory.deny_bytes.load(Ordering::Acquire), 0);
    assert_eq!(error.stage(), "catalog bytes");
    let id = error.reader().id();
    assert!(matches!(
        error.reader().report().output_admission(),
        TerminalObservation::Returned(Err(error)) if error.kind() == io::ErrorKind::OutOfMemory
    ));
    drop(error);
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    assert!(RegisteredNodeRead::retained(memory.clone(), id).is_none());
    node.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}

#[tokio::test]
async fn production_catalog_decode_failure_retires_its_clean_registered_reader() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-corrupt-catalog.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let wrapped = crate::WrappedKey {
        provider: "fixture".into(),
        key_ref: "catalog".into(),
        ciphertext: "opaque".into(),
        version: 1,
        context: None,
    };
    let catalog = crate::KeyCatalog {
        format: 1,
        catalog_id: Uuid::from_u128(1),
        tenant: "tenant".into(),
        purpose: crate::StoragePurpose::LocalFixture,
        active: "current".into(),
        keys: std::collections::BTreeMap::from([
            ("index".into(), wrapped.clone()),
            ("current".into(), wrapped),
        ]),
    };
    node.save_catalog("tenant", &catalog).unwrap();
    assert!(
        node.catalog("tenant")
            .unwrap()
            .as_ref()
            .is_some_and(|read| read == &catalog)
    );
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    let tx = node.db.begin_write().unwrap();
    tx.open_table(CATALOG)
        .unwrap()
        .insert(crate::tenant_hash("tenant").as_slice(), b"{".as_slice())
        .unwrap();
    tx.commit().unwrap();

    let error = node.catalog("tenant").err().unwrap();
    assert!(format!("{error:#}").contains("invalid key catalog"));
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    node.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}

#[tokio::test]
async fn production_pristine_probe_classifies_large_orphan_without_value_admission() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-pristine-read.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let hash = crate::tenant_hash("__kasumi_security");
    let mut key = hash.to_vec();
    key.push(1);
    let oversized_orphan = vec![0x5a; 8 << 20];
    let tx = node.db.begin_write().unwrap();
    tx.open_table(RECORDS)
        .unwrap()
        .insert(key.as_slice(), oversized_orphan.as_slice())
        .unwrap();
    tx.commit().unwrap();
    drop(oversized_orphan);
    let before = memory.snapshot();
    assert!(
        node.with_registered_read(|reader| {
            assert!(!reader.catalog_exists(hash)?);
            Ok(reader.record_prefix_exists(&hash)?)
        })
        .unwrap()
    );
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    let error = crate::TenantStore::initialize_catalog(
        node.clone(),
        "__kasumi_security".into(),
        Arc::new(crate::test_utils::LocalKeyProvider::new([42; 32])),
        crate::StorageAccess::security_audit(),
    )
    .await
    .err()
    .expect("orphan prevents fresh installation");
    assert!(format!("{error:#}").contains("new catalog has orphan physical rows"));
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn production_long_lived_view_returns_exact_native_report_after_drop() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-long-view-report.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let store = crate::TenantStore::initialize_catalog(
        node.clone(),
        "__kasumi_security".into(),
        Arc::new(crate::test_utils::LocalKeyProvider::new([42; 32])),
        crate::StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    store
        .write_batch(&[crate::WriteOp::put("docs", b"key", vec![0x6b; 4096])])
        .unwrap();
    let view = store.read_view().unwrap();
    let id = view.registered_reader_id().unwrap();
    let error = view.get("docs", b"key", 1).unwrap_err();
    let failure = error.downcast::<crate::NodeScopedReadFailure>().unwrap();
    drop(view);
    assert_eq!(failure.reader().id(), id);
    assert!(matches!(
        failure
            .body_error()
            .and_then(|error| error.downcast_ref::<NodeReadAccessError>()),
        Some(NodeReadAccessError::Reported)
    ));
    assert!(matches!(
        failure.reader().report().read_failure(),
        TerminalObservation::Returned(Err(kasumi_kv::BoundedReadError::BoundExceeded))
    ));
    assert_eq!(memory.storage_census().snapshot().readers, 1);
    drop(failure);
    assert!(RegisteredNodeRead::retained(memory.clone(), id).is_none());

    let view = store.read_view().unwrap();
    let id = view.registered_reader_id().unwrap();
    let error = view.visit("docs", 1, |_, _| Ok(())).unwrap_err();
    let failure = error.downcast::<crate::NodeScopedReadFailure>().unwrap();
    drop(view);
    assert_eq!(failure.reader().id(), id);
    assert!(matches!(
        failure.reader().report().read_failure(),
        TerminalObservation::Returned(Err(kasumi_kv::BoundedReadError::BoundExceeded))
    ));
    drop(failure);
    assert!(RegisteredNodeRead::retained(memory.clone(), id).is_none());

    store.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn production_paired_view_returns_exact_native_report_after_drop() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-paired-view-report.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let stores = crate::TenantStorageSet::initialize_catalogs(
        node.clone(),
        "tenant".into(),
        Arc::new(crate::test_utils::LocalKeyProvider::new([11; 32])),
        Arc::new(crate::test_utils::LocalKeyProvider::new([12; 32])),
        crate::StorageAccess::fixture(),
    )
    .await
    .unwrap();
    stores
        .application()
        .write_batch(&[crate::WriteOp::put("docs", b"key", vec![0x6b; 4096])])
        .unwrap();
    stores
        .custody()
        .store()
        .write_batch(&[crate::WriteOp::put("docs", b"key", vec![0x6b; 4096])])
        .unwrap();
    for custody in [false, true] {
        let view = stores.read_view().unwrap();
        let id = view.registered_reader_id().unwrap();
        let error = if custody {
            view.custody_get("docs", b"key", 1).unwrap_err()
        } else {
            view.application_get("docs", b"key", 1).unwrap_err()
        };
        let failure = error.downcast::<crate::NodeScopedReadFailure>().unwrap();
        drop(view);
        assert_eq!(failure.reader().id(), id);
        assert!(matches!(
            failure.reader().report().read_failure(),
            TerminalObservation::Returned(Err(kasumi_kv::BoundedReadError::BoundExceeded))
        ));
        assert_eq!(memory.storage_census().snapshot().readers, 1);
        drop(failure);
        assert!(RegisteredNodeRead::retained(memory.clone(), id).is_none());
    }
    stores.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn production_read_view_keeps_exact_child_until_explicit_close() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-retained-view.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let store = crate::TenantStore::initialize_catalog(
        node.clone(),
        "__kasumi_security".into(),
        Arc::new(crate::test_utils::LocalKeyProvider::new([42; 32])),
        crate::StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    store
        .write_batch(&[crate::WriteOp::put("docs", b"key", b"value")])
        .unwrap();
    let view = store.read_view().unwrap();
    let id = view.registered_reader_id().unwrap();
    assert_eq!(
        view.get("docs", b"key", 16).unwrap(),
        Some(b"value".to_vec())
    );
    let mut visited = 0;
    view.visit("docs", 16, |key, value| {
        assert_eq!((key, value), (b"key".as_slice(), b"value".as_slice()));
        visited += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(visited, 1);
    assert_eq!(
        store.scan("docs").unwrap(),
        vec![(b"key".to_vec(), b"value".to_vec())]
    );
    assert_eq!(memory.storage_census().snapshot().readers, 1);
    store.shutdown().await.unwrap();
    let busy = node.shutdown().await.unwrap_err();
    assert_eq!(
        busy.completion(),
        kasumi_types::drain::DrainCompletion::Retained
    );
    assert!(RegisteredNodeRead::retained(memory.clone(), id).is_some());
    view.close().unwrap();
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    node.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}

#[tokio::test]
async fn production_delete_needs_no_prior_ciphertext_headroom_and_survives_reopen() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-key-only-delete.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk.clone(), scratch.clone()).unwrap();
    let provider = Arc::new(crate::test_utils::LocalKeyProvider::new([42; 32]));
    let store = crate::TenantStore::initialize_catalog(
        node.clone(),
        "__kasumi_security".into(),
        provider.clone(),
        crate::StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    let large_value = vec![0x6b; 8 << 20];
    store
        .write_batch(&[crate::WriteOp::put("docs", b"large", large_value.clone())])
        .unwrap();
    let view = store.read_view().unwrap();
    assert_eq!(
        view.get("docs", b"large", large_value.len()).unwrap(),
        Some(large_value.clone())
    );

    let before_fill = memory.snapshot();
    let reserve_overhead = TestDiskMemory::required_reservation_bytes(0).unwrap();
    let headroom = 4 << 20;
    let fill_bytes = (256u64 << 20)
        .checked_sub(before_fill.bookkeeping_bytes + before_fill.used_bytes + headroom)
        .and_then(|available| available.checked_sub(reserve_overhead))
        .expect("large row and pinned view leave 4 MiB of headroom");
    let fill = memory.clone().reserve_installed(fill_bytes).unwrap();
    let low_headroom = memory.snapshot();
    assert_eq!(
        (256u64 << 20) - low_headroom.bookkeeping_bytes - low_headroom.used_bytes,
        headroom
    );
    store
        .write_batch(&[crate::WriteOp::delete("docs", b"large")])
        .expect("deleting a key must not admit its prior 8 MiB ciphertext");
    assert_eq!(store.get_bounded("docs", b"large", 0).unwrap(), None);
    drop(fill);

    assert_eq!(
        view.get("docs", b"large", large_value.len()).unwrap(),
        Some(large_value)
    );
    view.close().unwrap();
    store.shutdown().await.unwrap();
    drop(store);
    node.shutdown().await.unwrap();
    drop(node);

    let reopened = NodeStore::open_existing(&path, ID, disk, scratch).unwrap();
    let reopened_store = crate::TenantStore::open_existing(
        reopened.clone(),
        "__kasumi_security".into(),
        provider,
        crate::StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    assert_eq!(
        reopened_store.get_bounded("docs", b"large", 0).unwrap(),
        None
    );
    reopened_store.shutdown().await.unwrap();
    reopened.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}

#[tokio::test]
async fn production_visit_failure_retains_original_registered_report() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-visit-bound.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let store = crate::TenantStore::initialize_catalog(
        node.clone(),
        "__kasumi_security".into(),
        Arc::new(crate::test_utils::LocalKeyProvider::new([42; 32])),
        crate::StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    store
        .write_batch(&[crate::WriteOp::put("docs", b"key", vec![0x6b; 4096])])
        .unwrap();
    let error = store
        .visit("docs", 1, |_, _| Ok(()))
        .err()
        .unwrap()
        .downcast::<crate::NodeScopedReadFailure>()
        .unwrap();
    let id = error.reader().id();
    assert!(matches!(
        error.reader().report().read_failure(),
        TerminalObservation::Returned(Err(kasumi_kv::BoundedReadError::BoundExceeded))
    ));
    assert_eq!(memory.storage_census().snapshot().readers, 1);
    drop(error);
    assert!(RegisteredNodeRead::retained(memory.clone(), id).is_none());
    store.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn production_paired_deployment_reads_one_registered_snapshot() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-deployment-read.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let stores = crate::TenantStorageSet::initialize_catalogs_fixture(
        node.clone(),
        "tenant".into(),
        Arc::new(crate::test_utils::LocalKeyProvider::new([21; 32])),
        Arc::new(crate::test_utils::LocalKeyProvider::new([22; 32])),
    )
    .await
    .unwrap();
    let put = crate::WriteOp::put("engine.deployment", b"mode", b"paired");
    stores
        .write_batch(std::slice::from_ref(&put), std::slice::from_ref(&put))
        .unwrap();
    assert_eq!(
        stores.deployment_binding().unwrap().unwrap().as_bytes(),
        b"paired"
    );
    assert_eq!(
        stores
            .custody()
            .deployment_binding()
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"paired"
    );
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    stores.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn production_paired_view_keeps_one_registered_generation_until_close() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-paired-view.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let stores = crate::TenantStorageSet::initialize_catalogs_fixture(
        node.clone(),
        "tenant".into(),
        Arc::new(crate::test_utils::LocalKeyProvider::new([21; 32])),
        Arc::new(crate::test_utils::LocalKeyProvider::new([22; 32])),
    )
    .await
    .unwrap();
    let old = crate::WriteOp::put("docs", b"key", b"old");
    stores
        .write_batch(std::slice::from_ref(&old), std::slice::from_ref(&old))
        .unwrap();
    let view = stores.read_view().unwrap();
    let id = view.registered_reader_id().unwrap();
    let new = crate::WriteOp::put("docs", b"key", b"new");
    stores
        .write_batch(std::slice::from_ref(&new), std::slice::from_ref(&new))
        .unwrap();
    assert_eq!(
        view.application_get("docs", b"key", 16).unwrap(),
        Some(b"old".to_vec())
    );
    assert_eq!(
        view.custody_get("docs", b"key", 16).unwrap(),
        Some(b"old".to_vec())
    );
    assert_eq!(memory.storage_census().snapshot().readers, 1);
    stores.shutdown().await.unwrap();
    let busy = node.shutdown().await.unwrap_err();
    assert_eq!(
        busy.completion(),
        kasumi_types::drain::DrainCompletion::Retained
    );
    assert!(RegisteredNodeRead::retained(memory.clone(), id).is_some());
    view.close().unwrap();
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn production_scoped_body_panic_cannot_auto_retire() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-scoped-panic.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let error = node
        .with_registered_read::<()>(|_| std::panic::panic_any("scoped body panic"))
        .err()
        .unwrap()
        .downcast::<crate::NodeScopedReadFailure>()
        .unwrap();
    assert_eq!(error.stage(), "body panic");
    let id = error.reader().id();
    let original = {
        let report = error.reader().report();
        let TerminalObservation::Panicked(payload) = report.body_panic() else {
            panic!("original scoped body panic missing");
        };
        assert_eq!(payload.downcast_ref::<&str>(), Some(&"scoped body panic"));
        std::ptr::from_ref(payload)
    };
    assert_eq!(memory.storage_census().snapshot().readers, 1);
    drop(error);
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    let close = node.shutdown().await.unwrap_err();
    assert_eq!(
        close.completion(),
        kasumi_types::drain::DrainCompletion::Retained
    );
    let retained = RegisteredNodeRead::retained(memory.clone(), id).unwrap();
    {
        let report = retained.report();
        let TerminalObservation::Panicked(payload) = report.body_panic() else {
            panic!("retained scoped body panic missing");
        };
        assert_eq!(std::ptr::from_ref(payload), original);
    }
    assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn production_view_drop_during_unwind_keeps_interrupted_child() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-view-unwind.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let store = crate::TenantStore::initialize_catalog(
        node.clone(),
        "__kasumi_security".into(),
        Arc::new(crate::test_utils::LocalKeyProvider::new([42; 32])),
        crate::StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    let view = store.read_view().unwrap();
    let id = view.registered_reader_id().unwrap();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _view = view;
        std::panic::panic_any("external view unwind");
    }));
    assert!(caught.is_err());
    assert_eq!(
        memory.storage_census().drain_owner(id),
        StorageCensusDisposition::Retained
    );
    store.shutdown().await.unwrap();
    let close = node.shutdown().await.unwrap_err();
    assert_eq!(
        close.completion(),
        kasumi_types::drain::DrainCompletion::Retained
    );
    let retained = RegisteredNodeRead::retained(memory.clone(), id).unwrap();
    assert!(matches!(
        retained.report().body_panic(),
        TerminalObservation::Entered
    ));
    assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn production_tenant_get_accepts_maximum_writer_value() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-max-point-read.kv");
    let memory = TestDiskMemory::new(1 << 30, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let store = crate::TenantStore::initialize_catalog(
        node.clone(),
        "__kasumi_security".into(),
        Arc::new(crate::test_utils::LocalKeyProvider::new([42; 32])),
        crate::StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    store
        .write_batch(&[crate::WriteOp::put(
            "docs",
            b"max",
            vec![0x5a; crate::MAX_RECORD],
        )])
        .unwrap();
    let value = store.get("docs", b"max").unwrap().unwrap();
    assert_eq!(value.len(), crate::MAX_RECORD);
    assert!(value.iter().all(|byte| *byte == 0x5a));
    drop(value);
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    store.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}

#[tokio::test]
async fn production_record_writer_refuses_unadmitted_live_envelope_peak() -> anyhow::Result<()> {
    let directory = private_tempdir()?;
    let path = directory.path().join("record-writer-low-headroom.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir()?;
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch)?;
    let store = crate::TenantStore::initialize_catalog(
        node.clone(),
        "__kasumi_security".into(),
        Arc::new(crate::test_utils::LocalKeyProvider::new([42; 32])),
        crate::StorageAccess::security_audit(),
    )
    .await?;
    store.write_batch(&[crate::WriteOp::put("docs", b"sentinel", b"kept")])?;

    let value = vec![0x73u8; 1 << 20];
    let before_fill = memory.snapshot();
    // Native staging can admit its one encrypted copy with this headroom.
    // A second, simultaneous store-owned envelope cannot fit.
    let headroom = (value.len() as u64) + (512 << 10);
    let reserve_overhead = TestDiskMemory::required_reservation_bytes(0)?;
    let fill_bytes = (256u64 << 20)
        .checked_sub(before_fill.bookkeeping_bytes + before_fill.used_bytes + headroom)
        .and_then(|available| available.checked_sub(reserve_overhead))
        .expect("startup leaves capacity for a 1 MiB row");
    let fill = memory.clone().reserve_installed(fill_bytes)?;
    let limited = memory.snapshot();
    assert_eq!(
        (256u64 << 20) - limited.bookkeeping_bytes - limited.used_bytes,
        headroom
    );

    let denied = store.write_batch(&[crate::WriteOp::put("docs", b"large", value.clone())]);
    assert!(
        denied.is_err(),
        "record write published without funding its simultaneous resident envelope"
    );
    let after_denial = memory.snapshot();
    assert_eq!(after_denial.used_bytes, limited.used_bytes);
    assert_eq!(after_denial.live_reservations, limited.live_reservations);
    drop(fill);
    assert_eq!(store.get("docs", b"sentinel")?, Some(b"kept".to_vec()));
    assert!(store.get("docs", b"large")?.is_none());
    store.write_batch(&[crate::WriteOp::put("docs", b"large", value)])?;
    assert_eq!(store.get("docs", b"large")?.unwrap().len(), 1 << 20);
    store.shutdown().await?;
    node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn production_record_writer_denies_before_output_allocation() -> anyhow::Result<()> {
    let directory = private_tempdir()?;
    let path = directory.path().join("record-writer-output-denial.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir()?;
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch)?;
    let store = crate::TenantStore::initialize_catalog(
        node.clone(),
        "__kasumi_security".into(),
        Arc::new(crate::test_utils::LocalKeyProvider::new([42; 32])),
        crate::StorageAccess::security_audit(),
    )
    .await?;
    let value = vec![0x42u8; 1 << 20];
    let before_fill = memory.snapshot();
    let headroom = 512u64 << 10;
    let reserve_overhead = TestDiskMemory::required_reservation_bytes(0)?;
    let fill_bytes = (256u64 << 20)
        .checked_sub(before_fill.bookkeeping_bytes + before_fill.used_bytes + headroom)
        .and_then(|available| available.checked_sub(reserve_overhead))
        .expect("startup leaves capacity for a 512 KiB probe");
    let fill = memory.clone().reserve_installed(fill_bytes)?;
    let limited = memory.snapshot();
    assert_eq!(
        (256u64 << 20) - limited.bookkeeping_bytes - limited.used_bytes,
        headroom
    );

    let error = store
        .write_batch(&[crate::WriteOp::put("docs", b"large", value.clone())])
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("encrypted record output admission denied"),
        "unexpected refusal: {error:#}"
    );
    let after_denial = memory.snapshot();
    assert_eq!(after_denial.used_bytes, limited.used_bytes);
    assert_eq!(after_denial.live_reservations, limited.live_reservations);
    drop(fill);
    assert!(store.get("docs", b"large")?.is_none());
    store.write_batch(&[crate::WriteOp::put("docs", b"large", value)])?;
    assert_eq!(store.get("docs", b"large")?.unwrap().len(), 1 << 20);
    store.shutdown().await?;
    node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn production_tenant_get_missing_and_tiny_rows_fit_low_headroom() {
    let directory = private_tempdir().unwrap();
    let path = directory
        .path()
        .join("production-low-headroom-point-read.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let store = crate::TenantStore::initialize_catalog(
        node.clone(),
        "__kasumi_security".into(),
        Arc::new(crate::test_utils::LocalKeyProvider::new([42; 32])),
        crate::StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    store
        .write_batch(&[
            crate::WriteOp::put("docs", b"key", b"x".to_vec()),
            crate::WriteOp::put("docs", b"empty", Vec::new()),
        ])
        .unwrap();

    let before_fill = memory.snapshot();
    let reserve_overhead = TestDiskMemory::required_reservation_bytes(0).unwrap();
    let fill_bytes = (256u64 << 20)
        .checked_sub(before_fill.bookkeeping_bytes + before_fill.used_bytes + (8 << 20))
        .and_then(|available| available.checked_sub(reserve_overhead))
        .expect("startup leaves at least 8 MiB of headroom");
    let fill = memory.clone().reserve_installed(fill_bytes).unwrap();
    let low_headroom = memory.snapshot();
    assert_eq!(
        (256u64 << 20) - low_headroom.bookkeeping_bytes - low_headroom.used_bytes,
        8 << 20
    );
    assert_eq!(store.get("docs", b"missing").unwrap(), None);
    assert_eq!(store.get("docs", b"key").unwrap(), Some(b"x".to_vec()));
    assert_eq!(store.get_bounded("docs", b"missing", 0).unwrap(), None);
    assert_eq!(
        store.get_bounded("docs", b"empty", 0).unwrap(),
        Some(Vec::new())
    );
    let after_reads = memory.snapshot();
    assert_eq!(after_reads.used_bytes, low_headroom.used_bytes);
    assert_eq!(
        after_reads.live_reservations,
        low_headroom.live_reservations
    );
    assert_eq!(memory.storage_census().snapshot().readers, 0);

    drop(fill);
    store.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}

#[tokio::test]
async fn production_present_point_row_uses_native_credit_without_duplicate_outer_charge() {
    let directory = private_tempdir().unwrap();
    let path = directory
        .path()
        .join("production-native-only-point-read.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let store = crate::TenantStore::initialize_catalog(
        node.clone(),
        "__kasumi_security".into(),
        Arc::new(crate::test_utils::LocalKeyProvider::new([42; 32])),
        crate::StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    let value_len = 1 << 20;
    store
        .write_batch(&[crate::WriteOp::put(
            "docs",
            b"capacity",
            vec![0x6b; value_len],
        )])
        .unwrap();

    let before_probe = memory.snapshot();
    let probe = node.db.queue_registered_read().unwrap();
    assert_eq!(probe.begin(), NodeReadPhase::Active);
    let with_reader = memory.snapshot();
    let reader_charge = with_reader.used_bytes - before_probe.used_bytes;
    assert_eq!(probe.finish(), NodeReadPhase::Finished);
    assert_eq!(probe.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.snapshot().used_bytes, before_probe.used_bytes);

    let envelope_len = 4 + store.catalog.read().active.len() + 24 + 12 + 4 + 8 + value_len + 16;
    let native_charge = TestDiskMemory::required_reservation_bytes(
        crate::disk_memory::add(
            envelope_len as u64,
            crate::disk_memory::allocation::<crate::DiskMemoryLease>(1).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let duplicate_outer_charge = TestDiskMemory::required_reservation_bytes(
        crate::disk_memory::allocation::<u8>(envelope_len as u64).unwrap(),
    )
    .unwrap();
    let headroom = reader_charge + native_charge + duplicate_outer_charge / 2;
    assert!(headroom < reader_charge + native_charge + duplicate_outer_charge);
    let reserve_overhead = TestDiskMemory::required_reservation_bytes(0).unwrap();
    let fill_bytes = (256u64 << 20)
        .checked_sub(before_probe.bookkeeping_bytes + before_probe.used_bytes + headroom)
        .and_then(|available| available.checked_sub(reserve_overhead))
        .expect("startup leaves capacity for the native value and reader");
    let fill = memory.clone().reserve_installed(fill_bytes).unwrap();
    let limited = memory.snapshot();
    assert_eq!(
        (256u64 << 20) - limited.bookkeeping_bytes - limited.used_bytes,
        headroom
    );

    let value = store
        .get_bounded("docs", b"capacity", value_len)
        .unwrap()
        .unwrap();
    assert_eq!(value.len(), value_len);
    assert!(value.iter().all(|byte| *byte == 0x6b));
    drop(value);
    let after_read = memory.snapshot();
    assert_eq!(after_read.used_bytes, limited.used_bytes);
    assert_eq!(after_read.live_reservations, limited.live_reservations);
    assert_eq!(memory.storage_census().snapshot().readers, 0);

    drop(fill);
    store.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}

#[tokio::test]
async fn production_tenant_point_read_retires_routine_failures_and_keeps_cancelled_child() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-point-reader.kv");
    let (memory, entered, resume) = PausedRegistrationMemory::new();
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(&path, ID, disk, scratch).unwrap();
    let store = crate::TenantStore::initialize_catalog(
        node.clone(),
        "__kasumi_security".into(),
        Arc::new(crate::test_utils::LocalKeyProvider::new([42; 32])),
        crate::StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    store
        .write_batch(&[crate::WriteOp::put("docs", b"key", b"payload".to_vec())])
        .unwrap();
    assert_eq!(
        store.get_bounded("docs", b"key", 7).unwrap(),
        Some(b"payload".to_vec())
    );
    assert_eq!(memory.storage_census().snapshot().readers, 0);

    // Deny the native exact-length lease before it allocates ciphertext. The
    // registered child must retain the native failure observation.
    let envelope_len = 4 + store.catalog.read().active.len() + 24 + 12 + 4 + 3 + 7 + 16;
    let native_bytes = crate::disk_memory::add(
        envelope_len as u64,
        crate::disk_memory::allocation::<crate::DiskMemoryLease>(1).unwrap(),
    )
    .unwrap();
    let before_denial = memory.backing.snapshot();
    let probe = node.db.queue_registered_read().unwrap();
    assert_eq!(probe.begin(), NodeReadPhase::Active);
    let active_reader = memory.backing.snapshot();
    assert!(active_reader.used_bytes > before_denial.used_bytes);
    assert_eq!(probe.finish(), NodeReadPhase::Finished);
    assert_eq!(probe.retire(), StorageCensusDisposition::Retired);
    memory.deny_bytes.store(native_bytes, Ordering::Release);
    let denied = store
        .get("docs", b"key")
        .unwrap_err()
        .downcast::<crate::TenantPointReadFailure>()
        .expect("native output denial must return its registered reader");
    assert_eq!(memory.deny_bytes.load(Ordering::Acquire), 0);
    assert_eq!(denied.stage(), "record bytes");
    assert_eq!(denied.reader().phase(), NodeReadPhase::Failed);
    let denied_id = denied.reader().id();
    {
        let report = denied.reader().report();
        assert!(matches!(
            report.read_failure(),
            TerminalObservation::Returned(Err(kasumi_kv::BoundedReadError::Storage(
                kasumi_kv::StorageError::Core(kasumi_kv::CoreError::CapacityDenied)
            )))
        ));
        assert!(matches!(
            report.output_admission(),
            TerminalObservation::NotEntered
        ));
    }
    drop(denied);
    let after_denial = memory.backing.snapshot();
    assert_eq!(after_denial.used_bytes, before_denial.used_bytes);
    assert_eq!(
        after_denial.live_reservations,
        before_denial.live_reservations
    );
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    assert!(RegisteredNodeRead::retained(memory.clone(), denied_id).is_none());

    let failure = store
        .get_bounded("docs", b"key", 6)
        .unwrap_err()
        .downcast::<crate::TenantPointReadFailure>()
        .expect("oversized ciphertext must fail through its registered reader");
    assert_eq!(failure.stage(), "record bytes");
    let failed_id = failure.reader().id();
    assert!(matches!(
        failure.reader().report().read_failure(),
        TerminalObservation::Returned(Err(kasumi_kv::BoundedReadError::BoundExceeded))
    ));
    drop(failure);
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    assert!(RegisteredNodeRead::retained(memory.clone(), failed_id).is_none());

    memory.pause_next.store(true, Ordering::Release);
    let worker_store = store.clone();
    let worker = std::thread::spawn(move || {
        worker_store
            .get_bounded("docs", b"key", 7)
            .expect_err("stopped node cannot fall back to a direct read")
    });
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    node.db.stop();
    resume.send(()).unwrap();
    let cancelled = worker
        .join()
        .unwrap()
        .downcast::<crate::TenantPointReadFailure>()
        .expect("queued point reader retains its exact cancelled child");
    assert_eq!(cancelled.stage(), "begin");
    let cancelled_id = cancelled.reader().id();
    assert_eq!(cancelled.reader().phase(), NodeReadPhase::Cancelled);
    drop(cancelled);
    let cancelled = RegisteredNodeRead::retained(memory.clone(), cancelled_id)
        .expect("cancelled point reader survives facade drop");
    assert!(matches!(
        cancelled.report().begin(),
        TerminalObservation::NotEntered
    ));
    assert_eq!(cancelled.retire(), StorageCensusDisposition::Retired);
    assert_eq!(memory.storage_census().snapshot().readers, 0);
    store.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().databases, 0);
}

#[tokio::test]
async fn production_node_post_open_failure_retains_exact_registered_custody() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-node-table-denied.kv");
    let (memory, _, _) = PausedRegistrationMemory::with_slots(1);
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());

    let error = NodeStore::create_new(&path, ID, disk, scratch)
        .err()
        .expect("child census denial must fail setup")
        .downcast::<NodeStoreOpeningFailure>()
        .expect("production failure retains typed custody");
    assert_eq!(error.custody().phase(), NodeStartupPhase::Failed);
    assert!(error.custody().local_error().is_some());
    assert_eq!(memory.storage_census().snapshot().databases, 1);
    assert_eq!(memory.storage_census().snapshot().writers, 0);
    let opening_id = error.opening_id();
    assert_eq!(
        error.custody().opening().report().engine().settlement(),
        DatabaseOpenSettlement::Closed
    );
    drop(error);
    let retained = RegisteredNodeOpening::retained(memory.clone(), opening_id)
        .expect("the exact post-open owner survives facade drop");
    assert_eq!(
        retained.report().engine().settlement(),
        DatabaseOpenSettlement::Closed
    );
    assert!(matches!(
        retained.report().ready_publication(),
        kasumi_kv::TerminalObservation::NotEntered
    ));
}

#[tokio::test]
async fn production_node_rejects_wrong_identity_with_recoverable_failed_opening_id() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("production-node-wrong-id.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = disk(&path, &memory);
    let scratch_directory = private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());

    let node = NodeStore::create_new(&path, ID, disk.clone(), scratch.clone()).unwrap();
    node.shutdown().await.unwrap();
    drop(node);
    let other_id = Uuid::from_u128(ID.as_u128() + 1);
    let error = NodeStore::open_existing(&path, other_id, disk, scratch)
        .err()
        .unwrap()
        .downcast::<NodeStoreOpeningFailure>()
        .unwrap();
    let opening_id = error.opening_id();
    assert_eq!(memory.storage_census().snapshot().databases, 1);
    assert!(matches!(
        error.custody().opening().report().acquisition(),
        kasumi_kv::TerminalObservation::Returned(Err(_))
    ));
    drop(error);
    let retained = RegisteredNodeOpening::retained(memory.clone(), opening_id)
        .expect("the exact failed opening survives a dropped error facade");
    assert!(matches!(
        retained.report().acquisition(),
        kasumi_kv::TerminalObservation::Returned(Err(_))
    ));
}
