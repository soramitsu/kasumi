//! Retained reader and held-writer custody over a real Database. These reuse
//! the fork tests' actual allocator observer and counted admission ledger.
use super::*;
use crate::TerminalObservation;

// Counts every provider owner check so a local, callback-free retirement can
// prove it made none. All capacity stays in the wrapped ledger.
struct CheckedAdmission {
    inner: Arc<CountedAdmission>,
    checks: AtomicUsize,
}
impl CheckedAdmission {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: CountedAdmission::new(),
            checks: AtomicUsize::new(0),
        })
    }
}
impl StorageAdmission for CheckedAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.checks.fetch_add(1, Ordering::AcqRel);
        self.inner.check_owner()
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        self.inner.reserve_workspace(bytes)
    }
    fn quote_cache_memory(&self, bytes: u64) -> Result<crate::CacheMemoryQuote, AdmissionError> {
        crate::cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, AdmissionError> {
        crate::cache_test::reserve(self, bytes)
    }
    fn reserve_growth(&self, current: u64, requested: u64) -> Result<(), AdmissionError> {
        self.inner.reserve_growth(current, requested)
    }
    fn settle_growth(&self, actual: u64) -> Result<(), OwnerFailed> {
        self.inner.settle_growth(actual)
    }
    fn owner_failed(&self) {
        self.inner.owner_failed();
    }
}
impl crate::cache_test::Provider for CheckedAdmission {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), AdmissionError> {
        self.inner.acquire_cache(bytes, first)
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        self.inner.release_cache(bytes, last);
    }
}
fn checked_opening(admission: &Arc<CheckedAdmission>) -> RetainedDatabaseOpening {
    let mut opening = Database::builder(admission.clone(), [73; 16], CacheConfig::default())
        .retain_backend(Box::new(InMemoryGroup::new()), DatabaseOpenMode::Create);
    assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
    let writer = opening.database().unwrap().begin_write().unwrap();
    writer
        .open_table(ROWS)
        .unwrap()
        .insert(b"a".as_slice(), b"old-a".as_slice())
        .unwrap();
    writer.commit().unwrap();
    opening
}
fn finish_failed(mut opening: RetainedDatabaseOpening, admission: &CountedAdmission) {
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::DrainedWithFailure
    );
    assert_eq!(
        opening.dispose().settlement(),
        DatabaseOpenSettlement::FailedDisposed
    );
    drop(opening);
    assert_eq!(admission.census(), (0, 0));
}
fn native_failure_address(observation: TerminalObservation<'_, StorageError>) -> usize {
    let TerminalObservation::Returned(Err(error @ StorageError::Core(_))) = observation else {
        panic!("original native retirement failure absent");
    };
    assert!(matches!(error, StorageError::Core(original)
        if matches!(original.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed))));
    error as *const _ as usize
}

#[test]
fn retained_reader_and_fork_retain_final_native_mismatch_or_poison() {
    for fork in [false, true] {
        for poison in [false, true] {
            let admission = CheckedAdmission::new();
            let mut opening = checked_opening(&admission);
            let mut reader = opening.database().unwrap().begin_read_retained().unwrap();
            if fork {
                let next = reader.fork().unwrap();
                close_reader(&opening, &mut reader);
                reader = next;
            }
            reader.corrupt_final_release_for_test(poison);
            let checks = admission.checks.load(Ordering::Acquire);
            let grants = admission.inner.last_grant();
            let owner = opening.retained_database().unwrap();
            reader.close(owner);
            let report = reader.dispose_settled(owner);
            assert_eq!(report.settlement(), ReadCloseSettlement::Retained);
            assert!(!report.retains_transaction());
            assert!(report.retains_database());
            assert!(matches!(
                report.disposal(),
                TerminalObservation::Returned(Ok(()))
            ));
            let original = native_failure_address(report.native_retirement());
            assert_eq!(
                admission.checks.load(Ordering::Acquire),
                checks,
                "local retirement called provider check_owner"
            );
            assert_eq!(admission.inner.last_grant(), grants);
            let report = reader.dispose_settled(owner);
            assert_eq!(native_failure_address(report.native_retirement()), original);
            assert_eq!(report.settlement(), ReadCloseSettlement::Retained);
            assert_eq!(
                opening.close().settlement(),
                DatabaseOpenSettlement::WaitingForTransactions
            );
            drop(reader); // test teardown; no clean native disposition is minted
            finish_failed(opening, &admission.inner);
        }
    }
}

#[test]
fn retained_committed_writer_holds_the_writer_until_its_disposal() {
    use std::sync::mpsc;
    use std::time::Duration;
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let database = opening.database().unwrap();
    let write = database.begin_write().unwrap();
    write
        .open_table(ROWS)
        .unwrap()
        .insert(b"a".as_slice(), b"first".as_slice())
        .unwrap();
    let mut committed = write.retain();
    assert_eq!(
        committed.commit_holding_writer().settlement(),
        crate::WriteTerminalSettlement::HoldingWriter
    );
    assert!(*database.inner.gate.held.lock().unwrap());
    let queued = database.transaction_admission();
    let (started, starting) = mpsc::sync_channel(0);
    let (acquired, acquisition) = mpsc::sync_channel(1);
    let next = std::thread::spawn(move || {
        started.send(()).unwrap();
        let writer = queued.begin_write().unwrap();
        acquired.send(()).unwrap();
        writer
            .open_table(ROWS)
            .unwrap()
            .insert(b"a".as_slice(), b"second".as_slice())
            .unwrap();
        writer.commit().unwrap();
    });
    starting.recv().unwrap();
    assert!(matches!(
        acquisition.recv_timeout(Duration::from_millis(20)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    // A reader begun while the writer is held selects the committed root.
    let mut selected = database.begin_read_retained().unwrap();
    assert!(
        committed
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );
    acquisition.recv_timeout(Duration::from_secs(2)).unwrap();
    next.join().unwrap();
    assert_eq!(
        selected
            .get_bytes(ROWS, b"a", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"first"
    );
    let current = database.begin_read().unwrap();
    assert_eq!(
        current
            .get_bytes(ROWS.name(), b"a", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"second"
    );
    drop(current);
    close_reader(&opening, &mut selected);
    finish(opening, &admission);
}

#[test]
fn retained_holding_writer_refuses_foreign_disposal_and_keeps_exact_terminal_once() {
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let foreign_admission = CountedAdmission::new();
    let foreign = super::opening(&foreign_admission);
    let database = opening.database().unwrap();
    let mut writer = database.begin_write().unwrap().retain();
    assert_eq!(
        writer.commit_holding_writer().settlement(),
        crate::WriteTerminalSettlement::HoldingWriter
    );
    assert!(*database.inner.gate.held.lock().unwrap());
    assert!(
        !writer
            .dispose_settled(foreign.retained_database().unwrap())
            .disposal_complete()
    );
    assert_eq!(
        writer.report().settlement(),
        crate::WriteTerminalSettlement::HoldingWriter
    );
    assert!(matches!(
        writer.report().disposal(),
        TerminalObservation::NotEntered
    ));
    assert!(*database.inner.gate.held.lock().unwrap());
    let before = admission.census();
    let grants = admission.last_grant();
    let counting = AllocationCount::start();
    assert_eq!(
        writer.commit().settlement(),
        crate::WriteTerminalSettlement::HoldingWriter
    );
    assert_eq!(
        writer.abort().settlement(),
        crate::WriteTerminalSettlement::HoldingWriter
    );
    assert_eq!(counting.count(), 0);
    drop(counting);
    assert_eq!(admission.last_grant(), grants);
    assert_eq!(admission.census(), before);
    assert!(
        writer
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );
    assert!(!*database.inner.gate.held.lock().unwrap());
    assert!(matches!(
        writer.report().terminal(),
        TerminalObservation::Returned(Ok(()))
    ));
    finish(foreign, &foreign_admission);
    finish(opening, &admission);
}

#[test]
fn committed_empty_writer_is_a_live_owner_until_its_success_guard_retires() {
    let admission = CountedAdmission::new();
    let mut opening = opening(&admission);
    let committed = opening
        .database()
        .unwrap()
        .begin_write()
        .unwrap()
        .commit_holding_writer()
        .unwrap();
    assert!(*opening.database().unwrap().inner.gate.held.lock().unwrap());
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    drop(committed);
    finish(opening, &admission);
}

#[test]
fn held_writer_commit_capacity_refusal_mints_no_guard_and_releases_actual_writer() {
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let database = opening.database().unwrap();
    let write = database.begin_write().unwrap();
    write
        .open_table(ROWS)
        .unwrap()
        .insert(b"a".as_slice(), b"rejected".as_slice())
        .unwrap();
    let full = admission.census();
    admission.limits(full.0, full.1);
    let error = write
        .commit_holding_writer()
        .err()
        .expect("materialization grant must refuse");
    assert!(error.0.is_capacity_denied(), "{error:?}");
    assert!(!*database.inner.gate.held.lock().unwrap());
    assert!(!database.inner.core.is_fenced());
    admission.limits(BYTE_LIMIT, SLOT_LIMIT);
    let next = database.begin_write().unwrap();
    next.abort().unwrap();
    let read = database.begin_read().unwrap();
    assert_eq!(
        read.get_bytes(ROWS.name(), b"a", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"old-a"
    );
    drop(read);
    finish(opening, &admission);
}
