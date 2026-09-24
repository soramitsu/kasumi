use super::*;
#[cfg(feature = "experimental-api-5")]
use crate::ReadableTable;
use crate::{
    AdmissionError, CloseError, Database, OwnerFailed, ReadableDatabase, StorageAdmission,
    StorageBackend, TableDefinition, TransactionError, backends::FileBackend,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
};

const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("retained");

#[derive(Debug)]
struct Marker;
#[derive(Debug)]
struct OriginalIoFailure(Arc<Marker>);
impl core::fmt::Display for OriginalIoFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("original retained terminal I/O failure")
    }
}
impl std::error::Error for OriginalIoFailure {}

#[derive(Debug)]
struct Owner {
    maximum: AtomicU64,
    failed: AtomicBool,
    settle_mode: AtomicU8,
    settlements: AtomicUsize,
    marker: Arc<Marker>,
}
impl StorageAdmission for Owner {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_growth(&self, _: u64, requested: u64) -> Result<(), AdmissionError> {
        if requested > self.maximum.load(Ordering::Relaxed) {
            Err(AdmissionError::CapacityDenied)
        } else {
            Ok(())
        }
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        self.settlements.fetch_add(1, Ordering::SeqCst);
        match self.settle_mode.load(Ordering::SeqCst) {
            1 => Err(OwnerFailed),
            2 => std::panic::panic_any(self.marker.clone()),
            _ => Ok(()),
        }
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }
}

#[derive(Debug)]
struct Control {
    mode: AtomicU8,
    writes: AtomicUsize,
    header_writes: AtomicUsize,
    syncs: AtomicUsize,
    closes: AtomicUsize,
    marker: Arc<Marker>,
}
#[derive(Debug)]
struct Backend {
    file: FileBackend,
    control: Arc<Control>,
}
impl StorageBackend for Backend {
    fn len(&self) -> std::io::Result<u64> {
        self.file.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
        self.file.read(offset, out)
    }
    fn set_len(&self, len: u64) -> std::io::Result<()> {
        self.file.set_len(len)
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.control.writes.fetch_add(1, Ordering::SeqCst);
        if offset == 0 && self.control.mode.load(Ordering::SeqCst) != 0 {
            self.control.header_writes.fetch_add(1, Ordering::SeqCst);
        }
        self.file.write(offset, bytes)
    }
    fn sync_data(&self) -> std::io::Result<()> {
        self.control.syncs.fetch_add(1, Ordering::SeqCst);
        self.file.sync_data()?;
        match self.control.mode.load(Ordering::SeqCst) {
            1 => Err(std::io::Error::other(OriginalIoFailure(
                self.control.marker.clone(),
            ))),
            2 if self.control.header_writes.load(Ordering::SeqCst) == 2 => {
                // The winning header has really been written and synced. A
                // panic after this point cannot authorize terminal replay.
                std::panic::panic_any(self.control.marker.clone());
            }
            _ => Ok(()),
        }
    }
    fn close(&self) -> std::io::Result<()> {
        self.control.closes.fetch_add(1, Ordering::SeqCst);
        self.file.close()?;
        if self.control.mode.load(Ordering::SeqCst) == 3 {
            std::panic::panic_any(self.control.marker.clone());
        }
        Ok(())
    }
}

struct Fixture {
    database: Database,
    owner: Arc<Owner>,
    control: Arc<Control>,
    file: tempfile::NamedTempFile,
}
impl Fixture {
    fn new() -> Self {
        let file = crate::create_tempfile();
        let owner = Arc::new(Owner {
            maximum: AtomicU64::new(u64::MAX),
            failed: AtomicBool::new(false),
            settle_mode: AtomicU8::new(0),
            settlements: AtomicUsize::new(0),
            marker: Arc::new(Marker),
        });
        let control = Arc::new(Control {
            mode: AtomicU8::new(0),
            writes: AtomicUsize::new(0),
            header_writes: AtomicUsize::new(0),
            syncs: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            marker: Arc::new(Marker),
        });
        let database = Database::builder(owner.clone())
            .set_page_size(512)
            .set_region_size(16 << 10)
            .create_with_backend(Backend {
                file: FileBackend::new(file.reopen().unwrap()).unwrap(),
                control: control.clone(),
            })
            .unwrap();
        let transaction = database.begin_write().unwrap();
        transaction
            .open_table(TABLE)
            .unwrap()
            .insert(0, b"original".as_slice())
            .unwrap();
        transaction.commit().unwrap();
        Self {
            database,
            owner,
            control,
            file,
        }
    }
    fn write(&self) -> RetainedWriteTransaction {
        let write = self.database.begin_write().unwrap().retain();
        write
            .transaction()
            .unwrap()
            .open_table(TABLE)
            .unwrap()
            .insert(1, b"pending".as_slice())
            .unwrap();
        write
    }
    fn denied_write(&self) -> RetainedWriteTransaction {
        self.owner.maximum.store(
            self.file.as_file().metadata().unwrap().len(),
            Ordering::Relaxed,
        );
        let write = self.database.begin_write().unwrap().retain();
        let mut denied = false;
        {
            let mut table = write.transaction().unwrap().open_table(TABLE).unwrap();
            for key in 1..256 {
                match table.insert(key, [17; 4096].as_slice()) {
                    Ok(_) => {}
                    Err(StorageError::CapacityDenied) => {
                        denied = true;
                        break;
                    }
                    Err(error) => panic!("unexpected insert failure: {error:?}"),
                }
            }
        }
        assert!(denied, "actual growth was not denied");
        write
    }
    fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.control.writes.load(Ordering::SeqCst),
            self.control.syncs.load(Ordering::SeqCst),
            self.control.closes.load(Ordering::SeqCst),
            self.owner.settlements.load(Ordering::SeqCst),
        )
    }
}

// Unproved failure cleanup is intentionally not exercised by dropping a
// transaction. The test process has five fixed owner slots retaining the real
// transaction, database, file and diagnostics. This is test-only lifetime custody,
// not a production census, memory bound, or successful cleanup observation.
struct FailureCustody {
    write: RetainedWriteTransaction,
    _database: Database,
    _file: tempfile::NamedTempFile,
}
static FAILURES: Mutex<[Option<FailureCustody>; 5]> = Mutex::new([const { None }; 5]);

fn retain_failure(slot: usize, fixture: Fixture, mut write: RetainedWriteTransaction) {
    assert_eq!(
        write.report().settlement(),
        WriteTerminalSettlement::Retained
    );
    let transaction = write.transaction.as_ref().unwrap() as *const WriteTransaction;
    let counts = fixture.counts();
    assert!(matches!(
        write.dispose_settled().disposal(),
        TerminalObservation::NotEntered
    ));
    assert_eq!(
        write.transaction.as_ref().unwrap() as *const WriteTransaction,
        transaction
    );
    assert_eq!(fixture.counts(), counts);
    let database = match fixture.database.close() {
        Err(CloseError::Busy(database)) => database,
        _ => panic!("the exact retained transaction must keep database close busy"),
    };
    assert_eq!(fixture.control.closes.load(Ordering::SeqCst), 0);
    let mut failures = FAILURES.lock().unwrap();
    assert!(failures[slot].is_none());
    failures[slot] = Some(FailureCustody {
        write,
        _database: database,
        _file: fixture.file,
    });
    assert_eq!(
        failures[slot].as_ref().unwrap().write.report().settlement(),
        WriteTerminalSettlement::Retained
    );
}

fn terminal_error(report: &WriteTerminalReport<'_>) -> *const WriteTerminalError {
    let TerminalObservation::Returned(Err(error)) = report.terminal() else {
        panic!("original returned error missing");
    };
    error
}
fn assert_capacity(report: &WriteTerminalReport<'_>) {
    assert!(matches!(
        report.terminal(),
        TerminalObservation::Returned(Err(WriteTerminalError::Commit(CommitError::Storage(
            StorageError::CapacityDenied
        ))))
    ));
}

#[test]
fn successful_terminal_calls_are_never_replayed_and_disposal_precedes_close() {
    let fixture = Fixture::new();
    let mut write = fixture.write();
    assert_eq!(
        write.report().settlement(),
        WriteTerminalSettlement::Unstarted
    );
    assert!(matches!(
        write.report().terminal(),
        TerminalObservation::NotEntered
    ));
    let transaction = write.transaction.as_ref().unwrap() as *const WriteTransaction;
    let report = write.commit();
    assert_eq!(report.operation(), Some(WriteTerminalOperation::Commit));
    assert_eq!(report.settlement(), WriteTerminalSettlement::Settled);
    assert!(matches!(
        report.terminal(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert_eq!(
        write.transaction.as_ref().unwrap() as *const WriteTransaction,
        transaction
    );
    assert!(write.transaction().is_none());
    let counts = fixture.counts();
    assert_eq!(
        write.abort().operation(),
        Some(WriteTerminalOperation::Commit)
    );
    assert_eq!(
        write.commit().settlement(),
        WriteTerminalSettlement::Settled
    );
    assert_eq!(fixture.counts(), counts);
    assert!(write.dispose_settled().disposal_complete());
    assert!(write.transaction.is_none());
    assert!(matches!(
        write.report().terminal(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert_eq!(fixture.counts(), counts);
    assert!(write.dispose_settled().disposal_complete());
    let mut aborted = fixture.write();
    aborted
        .transaction()
        .unwrap()
        .open_table(TABLE)
        .unwrap()
        .insert(2, b"must roll back".as_slice())
        .unwrap();
    assert_eq!(
        aborted.abort().settlement(),
        WriteTerminalSettlement::Settled
    );
    let counts = fixture.counts();
    assert_eq!(
        aborted.commit().operation(),
        Some(WriteTerminalOperation::Abort)
    );
    assert_eq!(fixture.counts(), counts);
    assert!(aborted.dispose_settled().disposal_complete());
    assert!(aborted.transaction.is_none());
    fixture.database.close().unwrap();
    assert!(write.report().disposal_complete());
    assert!(aborted.report().disposal_complete());
    assert_eq!(fixture.control.closes.load(Ordering::SeqCst), 1);
    let reopened = Database::builder(fixture.owner)
        .set_page_size(512)
        .set_region_size(16 << 10)
        .open(fixture.file.path())
        .unwrap();
    assert_eq!(
        reopened
            .begin_read()
            .unwrap()
            .open_table(TABLE)
            .unwrap()
            .get(1)
            .unwrap()
            .unwrap()
            .value(),
        b"pending"
    );
    assert!(
        reopened
            .begin_read()
            .unwrap()
            .open_table(TABLE)
            .unwrap()
            .get(2)
            .unwrap()
            .is_none()
    );
    reopened.close().unwrap();
}

#[test]
fn poisoned_transaction_keeps_refusal_after_actual_callback_panic_and_rollback() {
    let fixture = Fixture::new();
    let mut write = fixture.write();
    let callback = catch_unwind(AssertUnwindSafe(|| {
        write
            .transaction()
            .unwrap()
            .open_table(TABLE)
            .unwrap()
            .retain(|_, _| std::panic::panic_any(fixture.owner.marker.clone()))
            .unwrap();
    }))
    .unwrap_err();
    assert!(Arc::ptr_eq(
        callback.downcast_ref::<Arc<Marker>>().unwrap(),
        &fixture.owner.marker
    ));
    let report = write.commit();
    assert_eq!(report.settlement(), WriteTerminalSettlement::Settled);
    assert!(matches!(
        report.terminal(),
        TerminalObservation::Returned(Err(WriteTerminalError::Commit(
            CommitError::TransactionPoisoned
        )))
    ));
    assert!(matches!(
        report.rollback(),
        TerminalObservation::Returned(Ok(()))
    ));
    let original = terminal_error(&report);
    let counts = fixture.counts();
    assert_eq!(terminal_error(&write.commit()), original);
    assert_eq!(fixture.counts(), counts);
    drop(write);
    assert!(
        fixture
            .database
            .begin_read()
            .unwrap()
            .open_table(TABLE)
            .unwrap()
            .get(1)
            .unwrap()
            .is_none()
    );
    fixture.database.close().unwrap();
}

#[test]
fn actual_capacity_refusal_keeps_primary_error_and_successful_rollback() {
    let fixture = Fixture::new();
    let mut write = fixture.denied_write();
    let report = write.commit();
    assert_capacity(&report);
    assert_eq!(report.settlement(), WriteTerminalSettlement::Settled);
    assert!(matches!(
        report.rollback(),
        TerminalObservation::Returned(Ok(()))
    ));
    let original = terminal_error(&report);
    let counts = fixture.counts();
    assert_eq!(terminal_error(&write.abort()), original);
    assert_eq!(fixture.counts(), counts);
    assert!(!fixture.owner.failed.load(Ordering::Acquire));
    assert!(write.dispose_settled().disposal_complete());
    assert_eq!(terminal_error(&write.report()), original);
    assert!(matches!(
        write.report().rollback(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(write.transaction.is_none());
    assert_eq!(fixture.counts(), counts);
    // The original error remains alive while a new actual transaction acquires
    // and releases the same writer slot. Neither original terminal is replayed.
    fixture.database.begin_write().unwrap().abort().unwrap();
    assert_eq!(terminal_error(&write.report()), original);
    {
        let read = fixture.database.begin_read().unwrap();
        let table = read.open_table(TABLE).unwrap();
        assert_eq!(table.get(0).unwrap().unwrap().value(), b"original");
        assert!(table.get(1).unwrap().is_none());
    }
    fixture.database.close().unwrap();
}

#[test]
fn commit_sync_failure_retains_exact_transaction_and_original_io_object() {
    let fixture = Fixture::new();
    let mut write = fixture.write();
    fixture.control.mode.store(1, Ordering::SeqCst);
    let transaction = write.transaction.as_ref().unwrap() as *const WriteTransaction;
    let report = write.commit();
    let original = terminal_error(&report);
    let TerminalObservation::Returned(Err(WriteTerminalError::Commit(CommitError::Storage(
        StorageError::Io(error),
    )))) = report.terminal()
    else {
        panic!("original commit I/O error missing");
    };
    let marker = &error
        .get_ref()
        .unwrap()
        .downcast_ref::<OriginalIoFailure>()
        .unwrap()
        .0;
    assert!(Arc::ptr_eq(marker, &fixture.control.marker));
    assert!(matches!(report.rollback(), TerminalObservation::NotEntered));
    assert_eq!(
        write.transaction.as_ref().unwrap() as *const WriteTransaction,
        transaction
    );
    assert!(write.transaction().is_none());
    assert!(fixture.owner.failed.load(Ordering::Acquire));
    let counts = fixture.counts();
    assert!(matches!(
        fixture.database.begin_read(),
        Err(TransactionError::Storage(StorageError::OwnerFailed))
    ));
    assert!(matches!(
        fixture.database.begin_write(),
        Err(TransactionError::Storage(StorageError::OwnerFailed))
    ));
    assert_eq!(terminal_error(&write.abort()), original);
    assert_eq!(terminal_error(&write.commit()), original);
    assert_eq!(fixture.counts(), counts);
    retain_failure(0, fixture, write);
}

#[test]
fn failed_abort_settlement_is_retained_and_never_reclassified_as_capacity() {
    let fixture = Fixture::new();
    let mut write = fixture.write();
    fixture.owner.settle_mode.store(1, Ordering::SeqCst);
    let report = write.abort();
    let original = terminal_error(&report);
    assert!(matches!(
        report.terminal(),
        TerminalObservation::Returned(Err(WriteTerminalError::Abort(StorageError::OwnerFailed)))
    ));
    assert!(matches!(report.rollback(), TerminalObservation::NotEntered));
    let counts = fixture.counts();
    assert_eq!(terminal_error(&write.commit()), original);
    assert_eq!(fixture.counts(), counts);
    retain_failure(1, fixture, write);
}

#[test]
fn failed_capacity_rollback_preserves_both_original_outcomes() {
    let fixture = Fixture::new();
    let mut write = fixture.denied_write();
    fixture.owner.settle_mode.store(1, Ordering::SeqCst);
    let report = write.commit();
    assert_capacity(&report);
    let primary = terminal_error(&report);
    let TerminalObservation::Returned(Err(error)) = report.rollback() else {
        panic!("actual rollback failure missing");
    };
    assert!(matches!(error, StorageError::OwnerFailed));
    let rollback = error as *const StorageError;
    let counts = fixture.counts();
    let repeated = write.abort();
    assert_eq!(terminal_error(&repeated), primary);
    let TerminalObservation::Returned(Err(error)) = repeated.rollback() else {
        panic!("original rollback failure was lost");
    };
    assert_eq!(error as *const StorageError, rollback);
    assert_eq!(fixture.counts(), counts);
    retain_failure(2, fixture, write);
}

#[test]
fn panic_after_actual_winning_header_sync_retains_payload_and_never_replays() {
    let fixture = Fixture::new();
    let mut write = fixture.write();
    fixture.control.mode.store(2, Ordering::SeqCst);
    let transaction = write.transaction.as_ref().unwrap() as *const WriteTransaction;
    let report = write.commit();
    assert_eq!(report.settlement(), WriteTerminalSettlement::Retained);
    let TerminalObservation::Panicked(payload) = report.terminal() else {
        panic!("original terminal panic missing");
    };
    assert!(Arc::ptr_eq(
        payload.downcast_ref::<Arc<Marker>>().unwrap(),
        &fixture.control.marker
    ));
    let original = payload as *const (dyn Any + Send);
    assert_eq!(fixture.control.header_writes.load(Ordering::SeqCst), 2);
    assert_eq!(
        write.transaction.as_ref().unwrap() as *const WriteTransaction,
        transaction
    );
    let counts = fixture.counts();
    let repeated = write.abort();
    let TerminalObservation::Panicked(payload) = repeated.terminal() else {
        panic!("original panic was replaced");
    };
    assert!(std::ptr::eq(payload as *const (dyn Any + Send), original));
    assert_eq!(fixture.counts(), counts);
    assert!(write.transaction().is_none());
    // Verify the already-synced bytes through an independent crash-image copy.
    // The uncertain original transaction/database remain retained throughout.
    let image = crate::create_tempfile();
    std::fs::copy(fixture.file.path(), image.path()).unwrap();
    let recovered = Database::builder(crate::test_admission())
        .set_page_size(512)
        .set_region_size(16 << 10)
        .open(image.path())
        .unwrap();
    assert_eq!(
        recovered
            .begin_read()
            .unwrap()
            .open_table(TABLE)
            .unwrap()
            .get(1)
            .unwrap()
            .unwrap()
            .value(),
        b"pending"
    );
    recovered.close().unwrap();
    retain_failure(3, fixture, write);
}

#[test]
fn capacity_rollback_panic_keeps_primary_refusal_and_actual_panic_payload() {
    let fixture = Fixture::new();
    let mut write = fixture.denied_write();
    fixture.owner.settle_mode.store(2, Ordering::SeqCst);
    let report = write.commit();
    assert_capacity(&report);
    let primary = terminal_error(&report);
    let TerminalObservation::Panicked(payload) = report.rollback() else {
        panic!("original rollback panic missing");
    };
    assert!(Arc::ptr_eq(
        payload.downcast_ref::<Arc<Marker>>().unwrap(),
        &fixture.owner.marker
    ));
    let original = payload as *const (dyn Any + Send);
    let counts = fixture.counts();
    let repeated = write.commit();
    assert_eq!(terminal_error(&repeated), primary);
    let TerminalObservation::Panicked(payload) = repeated.rollback() else {
        panic!("original rollback panic was replaced");
    };
    assert!(std::ptr::eq(payload as *const (dyn Any + Send), original));
    assert_eq!(fixture.counts(), counts);
    retain_failure(4, fixture, write);
}

#[test]
fn unstarted_disposal_keeps_actual_transaction_usable_until_positive_abort() {
    let fixture = Fixture::new();
    let mut write = fixture.write();
    let identity = write.transaction().unwrap() as *const WriteTransaction;
    let counts = fixture.counts();
    assert!(matches!(
        write.dispose_settled().disposal(),
        TerminalObservation::NotEntered
    ));
    assert_eq!(
        write.transaction().unwrap() as *const WriteTransaction,
        identity
    );
    assert_eq!(fixture.counts(), counts);
    write
        .transaction()
        .unwrap()
        .open_table(TABLE)
        .unwrap()
        .insert(2, b"abort me".as_slice())
        .unwrap();
    assert_eq!(write.abort().settlement(), WriteTerminalSettlement::Settled);
    assert!(write.dispose_settled().disposal_complete());
    fixture.database.begin_write().unwrap().abort().unwrap();
    assert!(matches!(
        write.commit().terminal(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert_eq!(
        write.report().operation(),
        Some(WriteTerminalOperation::Abort)
    );
    fixture.database.close().unwrap();
}

struct DisposalCustody {
    _write: RetainedWriteTransaction,
    _file: tempfile::NamedTempFile,
}
static DISPOSAL_FAILURE: Mutex<Option<DisposalCustody>> = Mutex::new(None);
#[test]
fn actual_deferred_close_panic_retains_original_disposal_payload_without_replay() {
    let fixture = Fixture::new();
    let mut write = fixture.write();
    assert_eq!(
        write.commit().settlement(),
        WriteTerminalSettlement::Settled
    );
    // Dropping the real Database defers its backend release to this transaction.
    // Its last writer guard invokes the actual FileBackend close before the
    // prefabricated backend then unwinds with its original marker.
    fixture.control.mode.store(3, Ordering::SeqCst);
    drop(fixture.database);
    assert_eq!(fixture.control.closes.load(Ordering::SeqCst), 0);
    let report = write.dispose_settled();
    assert!(!report.disposal_complete());
    assert!(matches!(
        report.terminal(),
        TerminalObservation::Returned(Ok(()))
    ));
    let TerminalObservation::Panicked(payload) = report.disposal() else {
        panic!("original disposal panic missing")
    };
    assert!(Arc::ptr_eq(
        payload.downcast_ref::<Arc<Marker>>().unwrap(),
        &fixture.control.marker
    ));
    let identity = payload as *const (dyn Any + Send);
    assert_eq!(fixture.control.closes.load(Ordering::SeqCst), 1);
    let TerminalObservation::Panicked(repeated) = write.dispose_settled().disposal() else {
        panic!("original disposal panic replaced")
    };
    assert!(std::ptr::eq(repeated, identity));
    assert_eq!(fixture.control.closes.load(Ordering::SeqCst), 1);
    assert!(write.transaction.is_none());
    let mut retained = DISPOSAL_FAILURE.lock().unwrap();
    assert!(retained.is_none());
    *retained = Some(DisposalCustody {
        _write: write,
        _file: fixture.file,
    });
}
