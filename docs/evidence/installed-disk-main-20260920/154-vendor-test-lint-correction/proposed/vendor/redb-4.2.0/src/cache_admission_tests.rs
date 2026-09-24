#[cfg(feature = "experimental-api-5")]
use crate::ReadableTable;
use crate::{
    AdmissionError, CloseError, CommitError, Database, DatabaseCloseSettlement, OwnerFailed,
    ReadableDatabase, RetainedWriteTransaction, StorageAdmission, StorageError, TableDefinition,
    TerminalObservation, WriteTerminalError, WriteTerminalSettlement,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};

const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("cache-admission");
#[derive(Debug)]
struct Marker;
#[derive(Debug)]
struct Owner {
    failed: AtomicBool,
    growths: AtomicU64,
    settled: AtomicU64,
    settle_mode: AtomicU8,
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
    fn reserve_growth(&self, current: u64, requested: u64) -> Result<(), AdmissionError> {
        assert!(requested > current);
        self.growths.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn settle_growth(&self, actual: u64) -> Result<(), OwnerFailed> {
        self.settled.store(actual, Ordering::Release);
        match self.settle_mode.load(Ordering::Acquire) {
            1 => Err(OwnerFailed),
            2 => std::panic::panic_any(self.marker.clone()),
            _ => Ok(()),
        }
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }
}
struct Fixture {
    db: Database,
    owner: Arc<Owner>,
    file: tempfile::NamedTempFile,
}
fn fixture() -> Fixture {
    let file = crate::create_tempfile();
    let owner = Arc::new(Owner {
        failed: AtomicBool::new(false),
        growths: AtomicU64::new(0),
        settled: AtomicU64::new(0),
        settle_mode: AtomicU8::new(0),
        marker: Arc::new(Marker),
    });
    let db = Database::builder(owner.clone())
        .set_page_size(512)
        .create(file.path())
        .unwrap();
    let tx = db.begin_write().unwrap();
    tx.open_table(TABLE)
        .unwrap()
        .insert(0, b"committed".as_slice())
        .unwrap();
    tx.commit().unwrap();
    Fixture { db, owner, file }
}

fn deny_after_admitted_growth(f: &Fixture) -> crate::WriteTransaction {
    let tx = f.db.begin_write().unwrap();
    let mut table = tx.open_table(TABLE).unwrap();
    table.insert(1, b"must abort".as_slice()).unwrap();
    let memory = f.db.get_memory();
    let allocated_before = memory.count_allocated_pages().unwrap();
    let growths_before = f.owner.growths.load(Ordering::Acquire);
    let length_before = f.file.as_file().metadata().unwrap().len();
    memory.set_write_entry_capacity_for_test(0);
    // This large leaf requires a real admitted layout expansion before the
    // cache refuses its new buffer. No candidate may remain allocated.
    let value = vec![7u8; usize::try_from(length_before * 2).unwrap()];
    assert!(matches!(
        table.insert(2, value.as_slice()),
        Err(StorageError::CacheCapacityDenied)
    ));
    assert!(f.owner.growths.load(Ordering::Acquire) > growths_before);
    assert!(f.file.as_file().metadata().unwrap().len() > length_before);
    assert_eq!(memory.count_allocated_pages().unwrap(), allocated_before);
    assert!(!f.owner.failed.load(Ordering::Acquire));
    // Clearing the fixture's capacity limit does not clear the transaction's
    // original refusal. Later allocating inserts stop before allocator/cache effects.
    memory.set_write_entry_capacity_for_test(usize::MAX);
    assert!(matches!(
        table.insert(3, value.as_slice()),
        Err(StorageError::CacheCapacityDenied)
    ));
    drop(table);
    tx
}

fn assert_cache_error(report: &crate::WriteTerminalReport<'_>) -> *const WriteTerminalError {
    let TerminalObservation::Returned(Err(error)) = report.terminal() else {
        panic!("missing original cache error")
    };
    assert!(matches!(
        error,
        WriteTerminalError::Commit(CommitError::Storage(StorageError::CacheCapacityDenied))
    ));
    std::ptr::from_ref(error)
}

#[test]
fn selected_page_is_rolled_back_and_admitted_growth_settles_on_abort() {
    let f = fixture();
    let mut tx = deny_after_admitted_growth(&f).retain();
    let mut database = f.db.retain();
    let report = tx.commit();
    let original = assert_cache_error(&report);
    assert_eq!(report.settlement(), WriteTerminalSettlement::Settled);
    assert!(matches!(
        report.rollback(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(!tx.report().disposal_complete());
    let disposed = tx.dispose_settled(&database);
    assert!(disposed.disposal_complete());
    assert_eq!(assert_cache_error(&disposed), original);
    assert_eq!(
        f.owner.settled.load(Ordering::Acquire),
        f.file.as_file().metadata().unwrap().len()
    );
    let read = database.database().unwrap().begin_read().unwrap();
    let table = read.open_table(TABLE).unwrap();
    assert_eq!(table.get(0).unwrap().unwrap().value(), b"committed");
    assert!(table.get(1).unwrap().is_none());
    assert!(table.get(2).unwrap().is_none());
    drop(table);
    drop(read);
    // Reuse the actual writer while the first owner's original refusal stays
    // retained. Settlement alone did not release that writer; disposal did.
    let next = database.database().unwrap().begin_write().unwrap();
    next.open_table(TABLE)
        .unwrap()
        .insert(1, b"retry".as_slice())
        .unwrap();
    let mut next = next.retain();
    assert_eq!(next.commit().settlement(), WriteTerminalSettlement::Settled);
    assert!(next.dispose_settled(&database).disposal_complete());
    assert_eq!(assert_cache_error(&tx.report()), original);
    let close = database.close();
    assert_eq!(close.settlement(), DatabaseCloseSettlement::Settled);
    assert!(matches!(
        close.shutdown(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(matches!(
        close.backend(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert_eq!(assert_cache_error(&tx.report()), original);
}

struct Custody {
    _transaction: RetainedWriteTransaction,
    _database: Database,
    _file: tempfile::NamedTempFile,
}
static RETAINED: Mutex<[Option<Custody>; 2]> = Mutex::new([const { None }; 2]);
#[test]
fn cache_denial_keeps_original_error_and_failed_or_panicked_abort() {
    for mode in [1u8, 2] {
        let f = fixture();
        let mut tx = deny_after_admitted_growth(&f).retain();
        f.owner.settle_mode.store(mode, Ordering::Release);
        let report = tx.commit();
        let original = assert_cache_error(&report);
        assert_eq!(report.settlement(), WriteTerminalSettlement::Retained);
        if mode == 1 {
            assert!(matches!(
                report.rollback(),
                TerminalObservation::Returned(Err(StorageError::OwnerFailed))
            ));
        } else {
            let TerminalObservation::Panicked(payload) = report.rollback() else {
                panic!("missing original abort panic")
            };
            assert!(Arc::ptr_eq(
                payload.downcast_ref::<Arc<Marker>>().unwrap(),
                &f.owner.marker
            ));
        }
        assert_eq!(assert_cache_error(&tx.abort()), original);
        let Err(CloseError::Busy(database)) = f.db.close() else {
            panic!("actual retained tx must keep DB busy")
        };
        let mut custody = RETAINED.lock().unwrap();
        assert!(custody[usize::from(mode - 1)].is_none());
        custody[usize::from(mode - 1)] = Some(Custody {
            _transaction: tx,
            _database: database,
            _file: f.file,
        });
    }
}

#[test]
fn consuming_commit_also_aborts_a_latched_cache_denial() {
    let f = fixture();
    let tx = deny_after_admitted_growth(&f);
    assert!(matches!(
        tx.commit(),
        Err(CommitError::Storage(StorageError::CacheCapacityDenied))
    ));
    let read = f.db.begin_read().unwrap();
    let table = read.open_table(TABLE).unwrap();
    assert!(table.get(1).unwrap().is_none());
    assert!(table.get(2).unwrap().is_none());
    drop(table);
    drop(read);
    let next = f.db.begin_write().unwrap();
    next.abort().unwrap();
    f.db.close().unwrap();
}
