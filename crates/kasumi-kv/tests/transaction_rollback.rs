//! Whole-transaction rollback before publication and settled rejections.
//!
//! A capacity denial while staging or at commit rolls a writer back whole:
//! nothing reaches the backend, every staged lease returns, and the writer
//! gate opens for the next writer at once. An owner failure or an unknown
//! commit outcome keeps the writer, its batch and the gate retained until a
//! strict reopen decides.

use kasumi_kv::{
    AdmissionError, BackendCloseOutcome, CommitError, CoreError, Database, DatabaseOpenMode,
    DatabaseOpenSettlement, OwnerFailed, ResidentLease, StorageAdmission, StorageBackend,
    StorageError, TableDefinition, TableError, TerminalObservation, TransactionError,
    WriteTerminalError, WriteTerminalOperation, WriteTerminalSettlement, WriteTransaction,
};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ROWS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rows");
const FRESH: TableDefinition<&[u8], &[u8]> = TableDefinition::new("fresh");
/// Larger than a staging chunk's slack, so every insert needs its own
/// workspace reservation and a denial lands on exactly that insert.
static VALUE: [u8; 48 << 10] = [0x5a; 48 << 10];

#[derive(Default)]
struct Admission {
    live: Arc<AtomicU64>,
    deny_workspace: AtomicBool,
    fail_workspace: AtomicBool,
    deny_growth: AtomicBool,
    owner_failures: AtomicUsize,
}

struct Lease {
    live: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.live.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

impl Admission {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn live(&self) -> u64 {
        self.live.load(Ordering::Acquire)
    }

    fn set(flag: &AtomicBool, value: bool) {
        flag.store(value, Ordering::Release);
    }
}

impl StorageAdmission for Admission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        if self.fail_workspace.load(Ordering::Acquire) {
            return Err(AdmissionError::OwnerFailed);
        }
        if self.deny_workspace.load(Ordering::Acquire) {
            return Err(AdmissionError::CapacityDenied);
        }
        self.live.fetch_add(bytes, Ordering::AcqRel);
        Ok(Box::new(Lease {
            live: self.live.clone(),
            bytes,
        }))
    }

    fn reserve_growth(&self, _current: u64, _requested: u64) -> Result<(), AdmissionError> {
        if self.deny_growth.load(Ordering::Acquire) {
            Err(AdmissionError::CapacityDenied)
        } else {
            Ok(())
        }
    }

    fn settle_growth(&self, _actual: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn owner_failed(&self) {
        self.owner_failures.fetch_add(1, Ordering::AcqRel);
    }
}

#[derive(Default)]
struct Image {
    volatile: Vec<u8>,
    durable: Vec<u8>,
    effects: usize,
    syncs: usize,
    fail_sync: Option<(usize, bool)>,
}

/// Effects are the mutating calls `set_len`, `write` and `sync_data`. The
/// durable image holds what a crash would keep.
#[derive(Clone, Default)]
struct CrashBackend(Arc<Mutex<Image>>);

impl CrashBackend {
    fn image(&self) -> std::sync::MutexGuard<'_, Image> {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    fn crash(&self) -> Self {
        let bytes = self.image().durable.clone();
        Self(Arc::new(Mutex::new(Image {
            volatile: bytes.clone(),
            durable: bytes,
            ..Image::default()
        })))
    }

    fn effects(&self) -> usize {
        self.image().effects
    }

    fn bytes(&self) -> (Vec<u8>, Vec<u8>) {
        let image = self.image();
        (image.volatile.clone(), image.durable.clone())
    }

    /// Fail the `ordinal`-th sync from now; `persist` makes it reach the
    /// durable image before reporting failure.
    fn fail_sync(&self, ordinal: usize, persist: bool) {
        let mut image = self.image();
        image.syncs = 0;
        image.fail_sync = Some((ordinal, persist));
    }
}

impl StorageBackend for CrashBackend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.image().volatile.len() as u64)
    }

    fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let image = self.image();
        let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::InvalidInput)?;
        out.copy_from_slice(
            image
                .volatile
                .get(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }

    fn write(&self, at: u64, input: &[u8]) -> io::Result<()> {
        let mut image = self.image();
        image.effects += 1;
        let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
        let end = start
            .checked_add(input.len())
            .ok_or(io::ErrorKind::InvalidInput)?;
        image
            .volatile
            .get_mut(start..end)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(input);
        Ok(())
    }

    fn set_len(&self, length: u64) -> io::Result<()> {
        let mut image = self.image();
        image.effects += 1;
        image.volatile.resize(
            usize::try_from(length).map_err(|_| io::ErrorKind::InvalidInput)?,
            0,
        );
        Ok(())
    }

    fn sync_data(&self) -> io::Result<()> {
        let mut image = self.image();
        image.effects += 1;
        image.syncs += 1;
        if let Some((ordinal, persist)) = image.fail_sync
            && image.syncs == ordinal
        {
            image.fail_sync = None;
            if persist {
                image.durable = image.volatile.clone();
            }
            return Err(io::Error::other("injected sync failure"));
        }
        image.durable = image.volatile.clone();
        Ok(())
    }

    fn close(&self) -> BackendCloseOutcome {
        BackendCloseOutcome::drained(Ok(()))
    }
}

fn commit_rows(database: &Database, rows: &[(&[u8], &[u8])]) {
    let write = database.begin_write().unwrap();
    {
        let mut table = write.open_table(ROWS).unwrap();
        for (key, value) in rows {
            table.insert(key, value).unwrap();
        }
    }
    write.commit().unwrap();
}

/// Read every row of `ROWS` from a fresh strict reopen of `backend`.
fn reopened_rows(backend: CrashBackend) -> Vec<Vec<u8>> {
    let database = Database::builder(Admission::new())
        .open_with_backend(backend)
        .unwrap();
    let read = database.begin_read().unwrap();
    let keys = read
        .open_table(ROWS)
        .unwrap()
        .iter()
        .unwrap()
        .map(|row| row.map(|(key, _)| key.value().to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    drop(read);
    database.close().unwrap();
    keys
}

/// Begin a writer on another thread. `None` means it was still waiting for
/// the writer gate when the deadline passed.
fn begin_write_within(
    database: &Arc<Database>,
    deadline: Duration,
) -> Option<Result<WriteTransaction, TransactionError>> {
    let admission = database.transaction_admission();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(admission.begin_write());
    });
    receiver.recv_timeout(deadline).ok()
}

fn is_denied<T>(result: Result<T, TableError>) -> bool {
    result.is_err_and(|error| error.is_capacity_denied())
}

#[test]
fn denied_second_of_three_inserts_rolls_back_the_whole_writer() {
    let admission = Admission::new();
    let backend = CrashBackend::default();
    let database = Arc::new(
        Database::builder(admission.clone())
            .create_with_backend(backend.clone())
            .unwrap(),
    );
    commit_rows(&database, &[(b"stable", b"before")]);
    let image = backend.bytes();
    let effects = backend.effects();
    let baseline = admission.live();

    let write = database.begin_write().unwrap();
    let mut table = write.open_table(ROWS).unwrap();
    table.insert(b"first", &VALUE).unwrap();
    assert!(admission.live() > baseline);
    Admission::set(&admission.deny_workspace, true);
    assert!(is_denied(table.insert(b"second", &VALUE)));
    Admission::set(&admission.deny_workspace, false);

    // The first denial dropped the whole batch and every staged lease. With
    // capacity available again, every later call repeats that denial.
    assert_eq!(admission.live(), baseline);
    assert!(is_denied(table.insert(b"third", &VALUE)));
    assert!(is_denied(table.get(b"first")));
    assert!(is_denied(table.get(b"stable")));
    assert!(is_denied(table.delete_key(b"stable")));
    assert!(is_denied(table.range(&b""[..]..).map(|_| ())));
    assert!(is_denied(write.open_table(ROWS).map(|_| ())));
    assert_eq!(admission.live(), baseline);

    // The writer gate opened at the denial: another writer begins while the
    // rolled-back writer and its table handle are still alive.
    let next = begin_write_within(&database, Duration::from_secs(5));
    next.expect("writer gate stayed held after rollback")
        .unwrap()
        .abort()
        .unwrap();

    // Commit repeats the original denial without any backend effect.
    drop(table);
    let error = write.commit().unwrap_err();
    assert!(matches!(
        error,
        CommitError(StorageError::Core(CoreError::CapacityDenied))
    ));
    assert_eq!(backend.effects(), effects);
    assert_eq!(backend.bytes(), image);
    assert_eq!(admission.live(), baseline);

    commit_rows(&database, &[(b"other", b"after")]);
    let read = database.begin_read().unwrap();
    let rows = read.open_table(ROWS).unwrap();
    for key in [&b"first"[..], b"second", b"third"] {
        assert!(rows.get(key).unwrap().is_none());
    }
    assert_eq!(rows.get(b"stable").unwrap().unwrap().value(), b"before");
    drop(rows);
    drop(read);
    assert_eq!(
        reopened_rows(backend.crash()),
        vec![b"other".to_vec(), b"stable".to_vec()]
    );
}

#[test]
fn denied_table_creation_and_overlay_range_roll_back_their_writers() {
    let admission = Admission::new();
    let backend = CrashBackend::default();
    let database = Database::builder(admission.clone())
        .create_with_backend(backend.clone())
        .unwrap();
    commit_rows(&database, &[(b"stable", b"before")]);
    let effects = backend.effects();
    let baseline = admission.live();

    // A new table's staging reservation.
    let write = database.begin_write().unwrap();
    Admission::set(&admission.deny_workspace, true);
    assert!(is_denied(write.open_table(FRESH).map(|_| ())));
    Admission::set(&admission.deny_workspace, false);
    assert!(is_denied(write.open_table(ROWS).map(|_| ())));
    assert_eq!(admission.live(), baseline);
    assert!(write.commit().unwrap_err().0.is_capacity_denied());

    // An overlay range materializing a staged row.
    let write = database.begin_write().unwrap();
    let mut table = write.open_table(ROWS).unwrap();
    table.insert(b"b", &VALUE).unwrap();
    let mut range = table.range(&b""[..]..).unwrap();
    Admission::set(&admission.deny_workspace, true);
    assert!(
        range
            .next()
            .unwrap()
            .is_err_and(|error| error.is_capacity_denied())
    );
    Admission::set(&admission.deny_workspace, false);
    assert!(range.next().is_none());
    drop(range);
    assert_eq!(admission.live(), baseline);
    assert!(is_denied(table.insert(b"c", b"small")));
    drop(table);
    assert!(write.commit().unwrap_err().0.is_capacity_denied());

    assert_eq!(backend.effects(), effects);
    let read = database.begin_read().unwrap();
    assert!(matches!(
        read.open_table(FRESH),
        Err(TableError::DoesNotExist(_))
    ));
    let rows = read.open_table(ROWS).unwrap();
    assert!(rows.get(b"b").unwrap().is_none());
    assert!(rows.get(b"c").unwrap().is_none());
}

#[test]
fn table_handle_never_keeps_the_writer_gate_after_its_transaction_drops() {
    let database = Arc::new(
        Database::builder(Admission::new())
            .create_with_backend(CrashBackend::default())
            .unwrap(),
    );
    commit_rows(&database, &[(b"stable", b"before")]);
    let write = database.begin_write().unwrap();
    let mut table = write.open_table(ROWS).unwrap();
    table.insert(b"orphan", b"value").unwrap();
    drop(write);
    let next = begin_write_within(&database, Duration::from_secs(5));
    let next = next.expect("dropped writer kept its gate").unwrap();
    assert!(matches!(
        table.insert(b"late", b"value"),
        Err(TableError::Storage(StorageError::DatabaseClosed))
    ));
    drop(table);
    next.commit().unwrap();
    let read = database.begin_read().unwrap();
    assert!(
        read.open_table(ROWS)
            .unwrap()
            .get(b"orphan")
            .unwrap()
            .is_none()
    );
}

#[test]
fn commit_growth_denial_settles_a_retained_writer_and_the_next_writer_commits() {
    let admission = Admission::new();
    let backend = CrashBackend::default();
    let mut opening = Database::builder(admission.clone())
        .retain_backend(Box::new(backend.clone()), DatabaseOpenMode::Create);
    assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
    commit_rows(opening.database().unwrap(), &[(b"stable", b"before")]);
    let image = backend.bytes();
    let effects = backend.effects();
    let baseline = admission.live();

    let mut writer = opening.database().unwrap().begin_write().unwrap().retain();
    writer
        .transaction()
        .unwrap()
        .open_table(ROWS)
        .unwrap()
        .insert(b"denied", b"value")
        .unwrap();
    Admission::set(&admission.deny_growth, true);
    {
        let report = writer.commit();
        assert_eq!(report.operation(), Some(WriteTerminalOperation::Commit));
        assert_eq!(report.settlement(), WriteTerminalSettlement::Settled);
        assert!(matches!(
            report.terminal(),
            TerminalObservation::Returned(Err(WriteTerminalError::Commit(CommitError(
                StorageError::Core(CoreError::CapacityDenied)
            ))))
        ));
        assert!(report.is_capacity_denied());
        assert!(
            report
                .rejected_no_effect()
                .is_some_and(StorageError::is_capacity_denied)
        );
    }
    Admission::set(&admission.deny_growth, false);
    assert_eq!(backend.effects(), effects);
    assert_eq!(backend.bytes(), image);
    assert_eq!(admission.live(), baseline);
    assert_eq!(admission.owner_failures.load(Ordering::Acquire), 0);
    // Crash image of the settled rejection: the prior generation.
    let crash = backend.crash();

    // A repeated terminal never replays the commit.
    assert_eq!(
        writer.commit().settlement(),
        WriteTerminalSettlement::Settled
    );
    assert_eq!(backend.effects(), effects);
    assert!(
        writer
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );

    commit_rows(opening.database().unwrap(), &[(b"after", b"next")]);
    assert_eq!(opening.close().settlement(), DatabaseOpenSettlement::Closed);
    assert_eq!(reopened_rows(crash), vec![b"stable".to_vec()]);
    assert_eq!(
        reopened_rows(backend.crash()),
        vec![b"after".to_vec(), b"stable".to_vec()]
    );
}

#[test]
fn rejected_commit_input_settles_and_releases_the_writer() {
    let backend = CrashBackend::default();
    let mut opening = Database::builder(Admission::new())
        .retain_backend(Box::new(backend.clone()), DatabaseOpenMode::Create);
    assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
    commit_rows(opening.database().unwrap(), &[(b"stable", b"before")]);
    let effects = backend.effects();

    let mut writer = opening.database().unwrap().begin_write().unwrap().retain();
    let oversized = vec![0x33; kasumi_kv::MAX_KEY_BYTES + 1];
    writer
        .transaction()
        .unwrap()
        .open_table(ROWS)
        .unwrap()
        .insert(oversized.as_slice(), b"value")
        .unwrap();
    let report = writer.commit();
    assert_eq!(report.settlement(), WriteTerminalSettlement::Settled);
    assert!(matches!(
        report.rejected_no_effect(),
        Some(StorageError::Core(CoreError::InvalidInput(_)))
    ));
    assert!(!report.is_capacity_denied());
    assert_eq!(backend.effects(), effects);
    assert!(
        writer
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );
    commit_rows(opening.database().unwrap(), &[(b"after", b"next")]);
    assert_eq!(opening.close().settlement(), DatabaseOpenSettlement::Closed);
}

#[test]
fn abort_after_a_staging_rollback_settles_and_disposes() {
    let admission = Admission::new();
    let backend = CrashBackend::default();
    let mut opening = Database::builder(admission.clone())
        .retain_backend(Box::new(backend.clone()), DatabaseOpenMode::Create);
    assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
    commit_rows(opening.database().unwrap(), &[(b"stable", b"before")]);
    let baseline = admission.live();

    let mut writer = opening.database().unwrap().begin_write().unwrap().retain();
    let mut table = writer.transaction().unwrap().open_table(ROWS).unwrap();
    Admission::set(&admission.deny_workspace, true);
    assert!(is_denied(table.insert(b"denied", &VALUE)));
    Admission::set(&admission.deny_workspace, false);
    drop(table);
    let report = writer.abort();
    assert_eq!(report.operation(), Some(WriteTerminalOperation::Abort));
    assert!(matches!(
        report.terminal(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert_eq!(report.settlement(), WriteTerminalSettlement::Settled);
    assert!(
        writer
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );
    assert_eq!(admission.live(), baseline);
    commit_rows(opening.database().unwrap(), &[(b"after", b"next")]);
    assert_eq!(opening.close().settlement(), DatabaseOpenSettlement::Closed);
    assert_eq!(
        reopened_rows(backend.crash()),
        vec![b"after".to_vec(), b"stable".to_vec()]
    );
}

#[test]
fn staging_owner_failure_keeps_the_batch_and_writer_gate_retained() {
    let admission = Admission::new();
    let backend = CrashBackend::default();
    let mut opening = Database::builder(admission.clone())
        .retain_backend(Box::new(backend.clone()), DatabaseOpenMode::Create);
    assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
    commit_rows(opening.database().unwrap(), &[(b"stable", b"before")]);
    let effects = backend.effects();
    let baseline = admission.live();

    let mut writer = opening.database().unwrap().begin_write().unwrap().retain();
    let mut table = writer.transaction().unwrap().open_table(ROWS).unwrap();
    table.insert(b"kept", &VALUE).unwrap();
    Admission::set(&admission.fail_workspace, true);
    let Err(error) = table.insert(b"failed", &VALUE) else {
        panic!("admission owner failure was not reported");
    };
    Admission::set(&admission.fail_workspace, false);
    assert!(!error.is_capacity_denied());
    assert!(matches!(
        error,
        TableError::Storage(StorageError::Core(CoreError::OwnerFailed))
    ));
    // Not a rollback: the staged leases remain and later calls report the
    // sticky owner failure instead of a capacity denial.
    assert!(admission.live() > baseline);
    assert!(matches!(
        table.get(b"kept"),
        Err(TableError::Storage(StorageError::Core(
            CoreError::OwnerFailed
        )))
    ));
    assert_eq!(admission.owner_failures.load(Ordering::Acquire), 1);
    drop(table);

    let report = writer.commit();
    assert_eq!(report.settlement(), WriteTerminalSettlement::Retained);
    assert!(report.rejected_no_effect().is_none());
    assert!(matches!(
        report.terminal(),
        TerminalObservation::Returned(Err(WriteTerminalError::Commit(CommitError(
            StorageError::Core(CoreError::OwnerFailed)
        ))))
    ));
    assert_eq!(backend.effects(), effects);
    assert!(
        !writer
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    assert_eq!(reopened_rows(backend.crash()), vec![b"stable".to_vec()]);
}

#[test]
fn frame_sync_failure_keeps_the_writer_retained_until_reopen_decides() {
    // The first sync of a commit persists its frame; the second publishes
    // the header. Only a durable header makes the batch survive reopen.
    for (sync, persist, published) in [(1, false, false), (2, true, true)] {
        let admission = Admission::new();
        let backend = CrashBackend::default();
        let mut opening = Database::builder(admission.clone())
            .retain_backend(Box::new(backend.clone()), DatabaseOpenMode::Create);
        assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
        commit_rows(opening.database().unwrap(), &[(b"stable", b"before")]);

        let mut writer = opening.database().unwrap().begin_write().unwrap().retain();
        writer
            .transaction()
            .unwrap()
            .open_table(ROWS)
            .unwrap()
            .insert(b"uncertain", b"value")
            .unwrap();
        backend.fail_sync(sync, persist);
        {
            let report = writer.commit();
            assert_eq!(report.settlement(), WriteTerminalSettlement::Retained);
            assert!(report.rejected_no_effect().is_none());
            assert!(!report.is_capacity_denied());
            assert!(matches!(
                report.terminal(),
                TerminalObservation::Returned(Err(WriteTerminalError::Commit(CommitError(
                    StorageError::UnknownCommit(_)
                ))))
            ));
        }
        // The core fenced once and reported its owner failure.
        assert!(matches!(
            opening.report().fence().observation(),
            Some(TerminalObservation::Returned(Ok(())))
        ));
        assert_eq!(admission.owner_failures.load(Ordering::Acquire), 1);
        assert!(matches!(
            opening.database().unwrap().begin_read(),
            Err(TransactionError(StorageError::Core(CoreError::OwnerFailed)))
        ));

        // The retained writer still holds the gate: a queued writer waits
        // until close seals admission and wakes it.
        let database = Arc::new(opening.database().unwrap().transaction_admission());
        let (sender, receiver) = mpsc::channel();
        let queued = std::thread::spawn(move || {
            let _ = sender.send(database.begin_write().map(drop));
        });
        assert!(
            receiver.recv_timeout(Duration::from_millis(200)).is_err(),
            "a retained uncertain writer released its gate"
        );
        assert!(
            !writer
                .dispose_settled(opening.retained_database().unwrap())
                .disposal_complete()
        );
        assert_eq!(
            opening.close().settlement(),
            DatabaseOpenSettlement::WaitingForTransactions
        );
        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
            Err(TransactionError(StorageError::DatabaseClosed))
        ));
        queued.join().unwrap();

        let mut expected = vec![b"stable".to_vec()];
        if published {
            expected.push(b"uncertain".to_vec());
        }
        assert_eq!(reopened_rows(backend.crash()), expected);
    }
}
