use super::*;
#[cfg(feature = "experimental-api-5")]
use crate::ReadableTable;
use crate::{
    AdmissionError, Database, DatabaseCloseSettlement, OwnerFailed, ReadableDatabase,
    RetainedDatabase, RetainedWriteTransaction, StorageAdmission, StorageBackend,
    TerminalObservation, WriteTerminalSettlement,
};
use std::sync::atomic::{AtomicU8, AtomicU64};

fn record(count: usize) -> Vec<u8> {
    let mut bytes = vec![0xa5; PageList::required_bytes(DATA_PAGE_LIST_CAPACITY)];
    bytes[..2].copy_from_slice(&u16::try_from(count).unwrap().to_le_bytes());
    for index in 0..count.min(DATA_PAGE_LIST_CAPACITY) {
        let offset = 2 + index * PageNumber::serialized_size();
        bytes[offset..offset + 8]
            .copy_from_slice(&PageNumber::new(0, u32::try_from(index).unwrap(), 0).to_le_bytes());
    }
    bytes
}

#[test]
fn canonical_data_page_list_rejects_obsolete_system_shape_without_allocating() {
    for count in [1, DATA_PAGE_LIST_CAPACITY] {
        let bytes = record(count);
        let (checked, allocations) =
            crate::admission::observe_test_allocations(|| PageList { data: &bytes }.checked());
        assert_eq!(allocations, 0);
        let checked = checked.unwrap();
        assert_eq!(checked.len(), count);
        assert_eq!(
            checked.get(count - 1),
            PageNumber::new(0, u32::try_from(count - 1).unwrap(), 0)
        );
    }
    let valid = record(1);
    // 1602 bytes was the obsolete system-row shape. It has no decoder.
    let invalid = [
        Vec::new(),
        vec![1],
        valid[..10].to_vec(),
        valid[..1602].to_vec(),
        record(0),
        record(DATA_PAGE_LIST_CAPACITY + 1),
        record(u16::MAX as usize),
    ];
    for bytes in invalid {
        let (result, allocations) =
            crate::admission::observe_test_allocations(|| PageList { data: &bytes }.checked());
        assert!(matches!(result, Err(StorageError::InvalidPageList)));
        assert_eq!(allocations, 0);
    }
}

#[test]
fn malformed_selected_data_record_is_rejected_before_any_pending_removal() {
    for alias_entry in [None, Some(0), Some(DATA_PAGE_LIST_CAPACITY - 1)] {
        for invalid_first in [true, false] {
            let file = crate::create_tempfile();
            let mut database = Database::builder(crate::test_admission())
                .create(file.path())
                .unwrap()
                .retain();
            let mut tx = database.database().unwrap().begin_write().unwrap();
            let first = TransactionIdWithPagination {
                transaction_id: 10_000,
                pagination_id: 0,
            };
            let second = TransactionIdWithPagination {
                transaction_id: 10_000,
                pagination_id: 1,
            };
            let valid = record(1);
            let malformed = if let Some(index) = alias_entry {
                let mut malformed = record(DATA_PAGE_LIST_CAPACITY);
                malformed[2 + 8 * index + 5] |= 1;
                malformed
            } else {
                record(DATA_PAGE_LIST_CAPACITY + 1)
            };
            let values = if invalid_first {
                [&malformed, &valid]
            } else {
                [&valid, &malformed]
            };
            {
                let mut namespace = tx.system_tables.lock().unwrap();
                let mut data = namespace
                    .open_system_table(&tx.dirty, DATA_FREED_TABLE)
                    .unwrap();
                data.insert(first, PageList { data: values[0] }).unwrap();
                data.insert(second, PageList { data: values[1] }).unwrap();
            }
            assert!(matches!(
                tx.process_pending_pages(TransactionId::new(10_001), u64::MAX),
                Err(StorageError::InvalidPageList)
            ));
            assert!(tx.deferred_reclaim.is_empty());
            assert!(tx.is_poisoned());
            {
                let mut namespace = tx.system_tables.lock().unwrap();
                let data = namespace
                    .open_system_table(&tx.dirty, DATA_FREED_TABLE)
                    .unwrap();
                assert_eq!(data.get(first).unwrap().unwrap().value().data, values[0]);
                assert_eq!(data.get(second).unwrap().unwrap().value().data, values[1]);
            }
            let mut tx = tx.retain();
            assert_eq!(tx.abort().settlement(), WriteTerminalSettlement::Settled);
            assert!(tx.dispose_settled(&database).disposal_complete());
            let check = database.database().unwrap().begin_write().unwrap();
            assert!(
                check
                    .system_tables
                    .lock()
                    .unwrap()
                    .get_system_table_root(DATA_FREED_TABLE)
                    .unwrap()
                    .is_none()
            );
            let mut check = check.retain();
            assert_eq!(check.abort().settlement(), WriteTerminalSettlement::Settled);
            assert!(check.dispose_settled(&database).disposal_complete());
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
        }
    }
}

#[test]
fn fixed_deferred_storage_preserves_exact_capacity_and_never_allocates() {
    let (mut pending, allocations) = crate::admission::observe_test_allocations(|| {
        let mut pending = DeferredReclaim::new();
        for i in 0..DATA_PAGE_LIST_CAPACITY {
            pending
                .push(PageNumber::new(0, u32::try_from(i).unwrap(), 0))
                .unwrap();
        }
        assert!(matches!(
            pending.push(PageNumber::new(0, 401, 0)),
            Err(StorageError::InvalidPageList)
        ));
        pending
    });
    assert_eq!(allocations, 0);
    assert_eq!(pending.as_slice().len(), DATA_PAGE_LIST_CAPACITY);
    for (i, page) in pending.as_slice().iter().enumerate() {
        assert_eq!(*page, PageNumber::new(0, u32::try_from(i).unwrap(), 0));
    }
    pending.clear();
    assert!(pending.is_empty());
}

#[derive(Debug)]
struct Marker;
#[derive(Debug)]
struct OriginalIo(Arc<Marker>);
impl core::fmt::Display for OriginalIo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("original page-list close growth synchronization failure")
    }
}
impl std::error::Error for OriginalIo {}
#[derive(Debug)]
struct Owner {
    failed: AtomicBool,
}
impl StorageAdmission for Owner {
    fn reserve_workspace(
        &self,
        _bytes: u64,
    ) -> core::result::Result<Box<dyn crate::ResidentLease>, crate::AdmissionError> {
        self.check_owner()
            .map_err(|_| crate::AdmissionError::OwnerFailed)?;
        Ok(Box::new(()))
    }
    fn check_owner(&self) -> core::result::Result<(), OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_growth(&self, _: u64, _: u64) -> core::result::Result<(), AdmissionError> {
        Ok(())
    }
    fn settle_growth(&self, _: u64) -> core::result::Result<(), OwnerFailed> {
        Ok(())
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }
}
#[derive(Debug)]
struct Backend {
    file: crate::tree_store::file_backend::FileBackend,
    mode: Arc<AtomicU8>,
    syncs: Arc<AtomicU64>,
    marker: Arc<Marker>,
}
impl StorageBackend for Backend {
    fn len(&self) -> std::io::Result<u64> {
        self.file.len()
    }
    fn read(&self, offset: u64, output: &mut [u8]) -> std::io::Result<()> {
        self.file.read(offset, output)
    }
    fn set_len(&self, len: u64) -> std::io::Result<()> {
        self.file.set_len(len)
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.file.write(offset, bytes)
    }
    fn sync_data(&self) -> std::io::Result<()> {
        self.file.sync_data()?;
        self.syncs.fetch_add(1, Ordering::AcqRel);
        if self.mode.load(Ordering::Acquire) == 1 {
            Err(std::io::Error::other(OriginalIo(self.marker.clone())))
        } else {
            Ok(())
        }
    }
    fn close(&self) -> crate::BackendCloseOutcome {
        self.file.close()
    }
}
struct FailureCustody {
    _error: StorageError,
    _transaction: RetainedWriteTransaction,
    _database: RetainedDatabase,
    _file: tempfile::NamedTempFile,
}
static FAILURE: std::sync::Mutex<Option<FailureCustody>> = std::sync::Mutex::new(None);

#[test]
fn early_extraction_close_failure_keeps_original_error_and_fences_publication() {
    let file = crate::create_tempfile();
    let mode = Arc::new(AtomicU8::new(0));
    let syncs = Arc::new(AtomicU64::new(0));
    let marker = Arc::new(Marker);
    let owner = Arc::new(Owner {
        failed: AtomicBool::new(false),
    });
    let backend = Backend {
        file: crate::tree_store::file_backend::FileBackend::new(file.reopen().unwrap()).unwrap(),
        mode: mode.clone(),
        syncs: syncs.clone(),
        marker: marker.clone(),
    };
    let mut database = Database::builder(owner.clone())
        .set_page_size(4096)
        .set_region_size(128 << 10)
        .create_with_backend(backend)
        .unwrap()
        .retain();
    // Each canonical record retains one real allocated page. This is a
    // valid pending-page tree; test setup never invents dangling page numbers.
    let tx = database.database().unwrap().begin_write().unwrap();
    let seed_transaction_id = tx.transaction_id.raw_id();
    for pagination_id in 0..8 {
        let page = tx
            .page_allocator()
            .allocate(4096, &PageTracker::ignore())
            .unwrap();
        let number = page.get_page_number();
        drop(page);
        let mut bytes = record(1);
        bytes[2..10].copy_from_slice(&number.to_le_bytes());
        tx.system_tables
            .lock()
            .unwrap()
            .open_system_table(&tx.dirty, DATA_FREED_TABLE)
            .unwrap()
            .insert(
                TransactionIdWithPagination {
                    transaction_id: seed_transaction_id,
                    pagination_id,
                },
                PageList { data: &bytes },
            )
            .unwrap();
    }
    let mut tx = tx.retain();
    assert_eq!(tx.commit().settlement(), WriteTerminalSettlement::Settled);
    assert!(tx.dispose_settled(&database).disposal_complete());
    let tx = database.database().unwrap().begin_write().unwrap();
    // Force the close's next COW allocation to grow the actual file, making the
    // injected sync error deterministic instead of relying on cache eviction.
    let free = tx.mem.count_free_pages().unwrap();
    for _ in 0..free {
        drop(
            tx.page_allocator()
                .allocate(4096, &PageTracker::ignore())
                .unwrap(),
        );
    }
    assert_eq!(tx.mem.count_free_pages().unwrap(), 0);
    let before_syncs = syncs.load(Ordering::Acquire);
    let before_len = file.as_file().metadata().unwrap().len();
    let mut namespace = tx.system_tables.lock().unwrap();
    let mut table = namespace
        .open_system_table(&tx.dirty, DATA_FREED_TABLE)
        .unwrap();
    let key = TransactionIdWithPagination {
        transaction_id: seed_transaction_id,
        pagination_id: 0,
    };
    table.validate_page_lists(key..=key).unwrap();
    let mut iter = table.extract_from_if(key..=key, |_, _| true).unwrap();
    let entry = iter.next().unwrap().unwrap();
    assert_eq!(entry.1.value().checked().unwrap().len(), 1);
    drop(entry);
    mode.store(1, Ordering::Release);
    let error =
        WriteTransaction::finish_page_list_extraction(&tx.poisoned, iter, Ok(())).unwrap_err();
    let StorageError::Io(original) = &error else {
        std::panic!("close lost original I/O: {error:?}");
    };
    assert!(Arc::ptr_eq(
        &original
            .get_ref()
            .unwrap()
            .downcast_ref::<OriginalIo>()
            .unwrap()
            .0,
        &marker
    ));
    assert!(syncs.load(Ordering::Acquire) > before_syncs);
    assert!(file.as_file().metadata().unwrap().len() > before_len);
    assert!(tx.is_poisoned());
    assert!(owner.failed.load(Ordering::Acquire));
    drop(table);
    drop(namespace);
    let mut tx = tx.retain();
    let report = tx.abort();
    assert_eq!(report.settlement(), WriteTerminalSettlement::Retained);
    assert!(matches!(
        report.terminal(),
        TerminalObservation::Returned(Err(WriteTerminalError::Abort(StorageError::OwnerFailed)))
    ));
    assert!(!tx.dispose_settled(&database).disposal_complete());
    assert_eq!(
        database.close().settlement(),
        DatabaseCloseSettlement::WaitingForTransactions
    );
    let mut custody = FAILURE.lock().unwrap();
    assert!(custody.is_none());
    *custody = Some(FailureCustody {
        _error: error,
        _transaction: tx,
        _database: database,
        _file: file,
    });
}

fn commit_clean(tx: WriteTransaction, database: &RetainedDatabase) {
    let mut tx = tx.retain();
    let report = tx.commit();
    assert_eq!(report.settlement(), WriteTerminalSettlement::Settled);
    assert!(matches!(
        report.terminal(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(tx.dispose_settled(database).disposal_complete());
}
fn abort_clean(tx: WriteTransaction, database: &RetainedDatabase) {
    let mut tx = tx.retain();
    let report = tx.abort();
    assert_eq!(report.settlement(), WriteTerminalSettlement::Settled);
    assert!(matches!(
        report.terminal(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(tx.dispose_settled(database).disposal_complete());
}
fn close_clean(mut database: RetainedDatabase) {
    let report = database.close();
    assert_eq!(report.settlement(), DatabaseCloseSettlement::Settled);
    assert!(matches!(
        report.shutdown(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(matches!(
        report.backend(),
        TerminalObservation::Returned(Ok(()))
    ));
}
fn seed_pending(database: &RetainedDatabase, counts: &[usize]) -> (u64, Vec<PageNumber>) {
    let tx = database.database().unwrap().begin_write().unwrap();
    let generation = tx.transaction_id.raw_id();
    let mut all = Vec::new();
    for (pagination_id, &count) in counts.iter().enumerate() {
        let mut bytes = record(count);
        for i in 0..count {
            let page = tx
                .page_allocator()
                .allocate(4096, &PageTracker::ignore())
                .unwrap();
            let number = page.get_page_number();
            drop(page);
            bytes[2 + i * 8..10 + i * 8].copy_from_slice(&number.to_le_bytes());
            all.push(number);
        }
        tx.system_tables
            .lock()
            .unwrap()
            .open_system_table(&tx.dirty, DATA_FREED_TABLE)
            .unwrap()
            .insert(
                TransactionIdWithPagination {
                    transaction_id: generation,
                    pagination_id: pagination_id as u64,
                },
                PageList { data: &bytes },
            )
            .unwrap();
    }
    commit_clean(tx, database);
    (generation, all)
}
fn pending_records(database: &RetainedDatabase) -> Vec<(u64, usize)> {
    let tx = database.database().unwrap().begin_write().unwrap();
    let mut result = Vec::new();
    {
        let mut namespace = tx.system_tables.lock().unwrap();
        assert!(
            !namespace
                .table_tree
                .contains_table_name(OBSOLETE_SYSTEM_FREED_TABLE_NAME)
                .unwrap()
        );
        if namespace
            .get_system_table_root(DATA_FREED_TABLE)
            .unwrap()
            .is_some()
        {
            let table = namespace
                .open_system_table(&tx.dirty, DATA_FREED_TABLE)
                .unwrap();
            for entry in table.range::<TransactionIdWithPagination>(..).unwrap() {
                let (key, value) = entry.unwrap();
                result.push((
                    key.value().pagination_id,
                    value.value().checked().unwrap().len(),
                ));
            }
        }
    }
    abort_clean(tx, database);
    result
}

#[test]
fn bounded_data_prefix_leaves_unselected_records_and_reopens_between_batches() {
    let file = crate::create_tempfile();
    let mut database = Database::builder(crate::test_admission())
        .create(file.path())
        .unwrap()
        .retain();
    let (_, pages) = seed_pending(&database, &[400, 400, 17]);
    assert_eq!(pages.len(), 817);
    assert_eq!(
        pending_records(&database),
        vec![(0, 400), (1, 400), (2, 17)]
    );
    for expected in [vec![(1, 400), (2, 17)], vec![(2, 17)], vec![]] {
        let tx = database.database().unwrap().begin_write().unwrap();
        commit_clean(tx, &database);
        assert_eq!(pending_records(&database), expected);
        close_clean(database);
        database = Database::open(file.path(), crate::test_admission())
            .unwrap()
            .retain();
        assert_eq!(pending_records(&database), expected);
    }
    close_clean(database);
}

#[test]
fn maintenance_preview_cannot_hide_debt_when_the_reader_horizon_advances() {
    let file = crate::create_tempfile();
    let database = Database::builder(crate::test_admission())
        .create(file.path())
        .unwrap()
        .retain();
    let read = database.database().unwrap().begin_read().unwrap();
    seed_pending(&database, &[400, 17]);
    let tx = database.database().unwrap().begin_write().unwrap();
    // Nothing is eligible at this preview's pinned horizon. Reporting only
    // eligible rows would return false, even though the ensuing real commit
    // can leave debt when the reader disappears between preview and commit.
    assert!(tx.reclaim_backlog_after_batch().unwrap());
    drop(read);
    commit_clean(tx, &database);
    assert_eq!(pending_records(&database), vec![(1, 17)]);
    let tx = database.database().unwrap().begin_write().unwrap();
    assert!(!tx.reclaim_backlog_after_batch().unwrap());
    commit_clean(tx, &database);
    assert!(pending_records(&database).is_empty());
    close_clean(database);
}

#[cfg(debug_assertions)]
#[test]
fn selected_data_pages_remain_allocated_until_winning_commit_and_abort_restores_records() {
    let file = crate::create_tempfile();
    let database = Database::builder(crate::test_admission())
        .create(file.path())
        .unwrap()
        .retain();
    let (_, pages) = seed_pending(&database, &[400, 17]);
    let mut tx = database.database().unwrap().begin_write().unwrap();
    let horizon = tx.transaction_id;
    tx.process_pending_pages(horizon, u64::MAX).unwrap();
    assert_eq!(tx.deferred_reclaim.as_slice(), &pages[..400]);
    for &page in &pages {
        assert!(tx.mem.is_allocated(page));
    }
    {
        let mut namespace = tx.system_tables.lock().unwrap();
        let table = namespace
            .open_system_table(&tx.dirty, DATA_FREED_TABLE)
            .unwrap();
        let remaining = table
            .range::<TransactionIdWithPagination>(..)
            .unwrap()
            .fold(0, |count, entry| {
                entry.unwrap();
                count + 1
            });
        assert_eq!(remaining, 1);
    }
    abort_clean(tx, &database);
    assert_eq!(pending_records(&database), vec![(0, 400), (1, 17)]);
    close_clean(database);
}

#[test]
fn pinned_user_reader_survives_system_retirement_and_data_reclaim_waits_for_its_horizon() {
    const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("reader-horizon");
    let file = crate::create_tempfile();
    let database = Database::builder(crate::test_admission())
        .create(file.path())
        .unwrap()
        .retain();
    let tx = database.database().unwrap().begin_write().unwrap();
    tx.open_table(TABLE)
        .unwrap()
        .insert(1, b"old".as_slice())
        .unwrap();
    commit_clean(tx, &database);
    let read = database.database().unwrap().begin_read().unwrap();
    let tx = database.database().unwrap().begin_write().unwrap();
    tx.open_table(TABLE)
        .unwrap()
        .insert(1, b"new".as_slice())
        .unwrap();
    commit_clean(tx, &database);
    let retained = pending_records(&database);
    assert!(!retained.is_empty());
    for _ in 0..16 {
        let tx = database.database().unwrap().begin_write().unwrap();
        commit_clean(tx, &database);
        assert_eq!(pending_records(&database), retained);
        assert_eq!(
            read.open_table(TABLE)
                .unwrap()
                .get(1)
                .unwrap()
                .unwrap()
                .value(),
            b"old"
        );
    }
    drop(read);
    let tx = database.database().unwrap().begin_write().unwrap();
    commit_clean(tx, &database);
    assert!(pending_records(&database).is_empty());
    close_clean(database);
    let readonly = crate::ReadOnlyDatabase::open(file.path(), crate::test_admission()).unwrap();
    {
        let read = readonly.begin_read().unwrap();
        assert_eq!(
            read.open_table(TABLE)
                .unwrap()
                .get(1)
                .unwrap()
                .unwrap()
                .value(),
            b"new"
        );
    }
    readonly.close().unwrap();
}

#[test]
fn consuming_compaction_reports_retained_data_backlog_without_chasing_a_system_tail() {
    let file = crate::create_tempfile();
    let database = Database::builder(crate::test_admission())
        .create(file.path())
        .unwrap()
        .retain();
    seed_pending(&database, &[400; 5]);
    close_clean(database);
    // This exercises the existing consuming Database::compact API separately
    // from the retained transaction-custody tests above. One byte cannot move
    // even a single old/new page pair; true must mean pending reclamation.
    let mut database = Database::open(file.path(), crate::test_admission()).unwrap();
    assert!(
        database
            .compact(core::num::NonZeroUsize::new(1).unwrap())
            .unwrap()
    );
    let database = database.retain();
    assert_eq!(pending_records(&database), vec![(4, 400)]);
    close_clean(database);
    let mut database = Database::open(file.path(), crate::test_admission()).unwrap();
    assert!(
        !database
            .compact(core::num::NonZeroUsize::new(1).unwrap())
            .unwrap()
    );
    let database = database.retain();
    assert!(pending_records(&database).is_empty());
    close_clean(database);
}

#[test]
fn obsolete_system_namespace_is_rejected_before_writable_readonly_or_repair_mutation() {
    use crate::DatabaseError;
    let file = crate::create_tempfile();
    let database = Database::builder(crate::test_admission())
        .create(file.path())
        .unwrap();
    let mut tx = database.begin_write().unwrap();
    // Deliberately construct a forbidden on-disk fixture below the canonical
    // transaction entry point. No obsolete PageList value is created/decoded.
    // This is equivalent to the header corruption fixtures' raw offline edit.
    let system_root = {
        let mut namespace = tx.system_tables.lock().unwrap();
        namespace
            .table_tree
            .get_or_create_table::<u64, u64>(OBSOLETE_SYSTEM_FREED_TABLE_NAME, TableType::Normal)
            .unwrap();
        namespace
            .table_tree
            .flush_table_root_updates()
            .unwrap()
            .finalize_dirty_checksums()
            .unwrap()
    };
    tx.mem
        .commit(
            tx.mem.get_data_root(),
            system_root,
            tx.transaction_id,
            ShrinkPolicy::Default,
        )
        .unwrap();
    tx.page_allocator().discard_committed_allocations();
    tx.completed = true;
    drop(tx);
    // abandon does not try to normalize/repair this deliberately invalid root.
    database.get_memory().abandon().0.unwrap();
    drop(database);
    let original = std::fs::read(file.path()).unwrap();
    let callbacks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = callbacks.clone();
    let error = Database::builder(crate::test_admission())
        .set_repair_callback(move |_| {
            observed.fetch_add(1, Ordering::Relaxed);
        })
        .open(file.path())
        .unwrap_err();
    assert!(matches!(
        error,
        DatabaseError::Storage(StorageError::ObsoleteSystemTable)
    ));
    assert_eq!(callbacks.load(Ordering::Relaxed), 0);
    assert_eq!(std::fs::read(file.path()).unwrap(), original);
    let error = Database::builder(crate::test_admission())
        .open_read_only(file.path())
        .unwrap_err();
    assert!(matches!(
        error,
        DatabaseError::Storage(StorageError::ObsoleteSystemTable)
    ));
    assert_eq!(std::fs::read(file.path()).unwrap(), original);
}

fn retained_savepoint(database: &RetainedDatabase) -> crate::Savepoint {
    let tx = database.database().unwrap().begin_write().unwrap();
    let savepoint = tx.ephemeral_savepoint().unwrap();
    abort_clean(tx, database);
    savepoint
}

// These records describe real unreachable physical pages. A held savepoint
// keeps the newly written allocation rows ineligible during fixture creation.
fn seed_allocation_and_pending(database: &RetainedDatabase, counts: &[usize]) -> Vec<PageNumber> {
    let tx = database.database().unwrap().begin_write().unwrap();
    assert!(tx.transaction_tracker.any_savepoint_exists());
    let generation = tx.transaction_id.raw_id();
    let mut pages = Vec::new();
    for (pagination, &count) in counts.iter().enumerate() {
        let mut bytes = record(count);
        for i in 0..count {
            let page = tx
                .page_allocator()
                .allocate(4096, &PageTracker::ignore())
                .unwrap();
            let number = page.get_page_number();
            drop(page);
            bytes[2 + i * 8..10 + i * 8].copy_from_slice(&number.to_le_bytes());
            pages.push(number);
        }
        let key = TransactionIdWithPagination {
            transaction_id: generation,
            pagination_id: pagination as u64,
        };
        let mut namespace = tx.system_tables.lock().unwrap();
        namespace
            .open_system_table(&tx.dirty, DATA_ALLOCATED_TABLE)
            .unwrap()
            .insert(key, PageList { data: &bytes })
            .unwrap();
        namespace
            .open_system_table(&tx.dirty, DATA_FREED_TABLE)
            .unwrap()
            .insert(key, PageList { data: &bytes })
            .unwrap();
    }
    commit_clean(tx, database);
    pages
}

fn allocation_records(database: &RetainedDatabase) -> Vec<(u64, u64, usize)> {
    let tx = database.database().unwrap().begin_write().unwrap();
    let mut result = Vec::new();
    {
        let mut namespace = tx.system_tables.lock().unwrap();
        let table = namespace
            .open_system_table(&tx.dirty, DATA_ALLOCATED_TABLE)
            .unwrap();
        for entry in table.range::<TransactionIdWithPagination>(..).unwrap() {
            let (key, value) = entry.unwrap();
            let pages = value.value().checked().unwrap();
            result.push((
                key.value().transaction_id,
                key.value().pagination_id,
                pages.len(),
            ));
            #[cfg(debug_assertions)]
            for index in 0..pages.len() {
                assert!(
                    tx.mem.is_allocated(pages.get(index)),
                    "retained allocation record names a freed physical page"
                );
            }
        }
    }
    abort_clean(tx, database);
    result
}

#[test]
fn bounded_allocation_debt_blocks_data_free_and_cold_reopens_after_every_batch() {
    let file = crate::create_tempfile();
    let mut database = Database::builder(crate::test_admission())
        .create(file.path())
        .unwrap()
        .retain();
    let savepoint = retained_savepoint(&database);
    let pages = seed_allocation_and_pending(&database, &[400, 400, 17]);
    assert_eq!(pages.len(), 817);
    drop(savepoint);
    for (allocated, freed) in [
        (vec![400, 17], vec![(0, 400), (1, 400), (2, 17)]),
        (vec![17], vec![(0, 400), (1, 400), (2, 17)]),
        (vec![], vec![(1, 400), (2, 17)]),
        (vec![], vec![(2, 17)]),
        (vec![], vec![]),
    ] {
        let tx = database.database().unwrap().begin_write().unwrap();
        let expected_debt = !allocated.is_empty() || !freed.is_empty();
        assert_eq!(tx.reclaim_backlog_after_batch().unwrap(), expected_debt);
        commit_clean(tx, &database);
        assert_eq!(
            allocation_records(&database)
                .iter()
                .map(|(_, _, count)| *count)
                .collect::<Vec<_>>(),
            allocated
        );
        assert_eq!(pending_records(&database), freed);
        close_clean(database);
        database = Database::open(file.path(), crate::test_admission())
            .unwrap()
            .retain();
        assert_eq!(
            allocation_records(&database)
                .iter()
                .map(|(_, _, count)| *count)
                .collect::<Vec<_>>(),
            allocated
        );
        assert_eq!(pending_records(&database), freed);
    }
    close_clean(database);
}

#[test]
fn both_selected_prefixes_are_validated_before_either_namespace_is_removed() {
    for malformed_allocated in [false, true] {
        let file = crate::create_tempfile();
        let database = Database::builder(crate::test_admission())
            .create(file.path())
            .unwrap()
            .retain();
        let mut tx = database.database().unwrap().begin_write().unwrap();
        let key = TransactionIdWithPagination {
            transaction_id: 10_000,
            pagination_id: 0,
        };
        let valid = record(1);
        let invalid = record(401);
        let allocated = if malformed_allocated {
            &invalid
        } else {
            &valid
        };
        let freed = if malformed_allocated {
            &valid
        } else {
            &invalid
        };
        {
            let mut namespace = tx.system_tables.lock().unwrap();
            namespace
                .open_system_table(&tx.dirty, DATA_ALLOCATED_TABLE)
                .unwrap()
                .insert(key, PageList { data: allocated })
                .unwrap();
            namespace
                .open_system_table(&tx.dirty, DATA_FREED_TABLE)
                .unwrap()
                .insert(key, PageList { data: freed })
                .unwrap();
        }
        assert!(matches!(
            tx.process_pending_pages(TransactionId::new(10_001), 10_001),
            Err(StorageError::InvalidPageList)
        ));
        assert!(tx.is_poisoned());
        assert!(tx.deferred_reclaim.is_empty());
        {
            let mut namespace = tx.system_tables.lock().unwrap();
            assert_eq!(
                namespace
                    .open_system_table(&tx.dirty, DATA_ALLOCATED_TABLE)
                    .unwrap()
                    .get(key)
                    .unwrap()
                    .unwrap()
                    .value()
                    .data,
                allocated
            );
            assert_eq!(
                namespace
                    .open_system_table(&tx.dirty, DATA_FREED_TABLE)
                    .unwrap()
                    .get(key)
                    .unwrap()
                    .unwrap()
                    .value()
                    .data,
                freed
            );
        }
        abort_clean(tx, &database);
        close_clean(database);
        let reopened = Database::open(file.path(), crate::test_admission())
            .unwrap()
            .retain();
        assert!(allocation_records(&reopened).is_empty());
        assert!(pending_records(&reopened).is_empty());
        close_clean(reopened);
    }
}

#[test]
fn allocation_preview_retains_debt_across_savepoint_release_before_commit() {
    let file = crate::create_tempfile();
    let database = Database::builder(crate::test_admission())
        .create(file.path())
        .unwrap()
        .retain();
    let savepoint = retained_savepoint(&database);
    seed_allocation_and_pending(&database, &[400, 17]);
    let tx = database.database().unwrap().begin_write().unwrap();
    assert!(tx.reclaim_backlog_after_batch().unwrap());
    drop(savepoint);
    commit_clean(tx, &database);
    assert_eq!(
        allocation_records(&database)
            .iter()
            .map(|(_, _, count)| *count)
            .collect::<Vec<_>>(),
        vec![17]
    );
    assert_eq!(pending_records(&database), vec![(0, 400), (1, 17)]);
    let tx = database.database().unwrap().begin_write().unwrap();
    assert!(tx.reclaim_backlog_after_batch().unwrap());
    commit_clean(tx, &database);
    assert!(allocation_records(&database).is_empty());
    assert_eq!(pending_records(&database), vec![(1, 17)]);
    let tx = database.database().unwrap().begin_write().unwrap();
    assert!(!tx.reclaim_backlog_after_batch().unwrap());
    commit_clean(tx, &database);
    assert!(pending_records(&database).is_empty());
    close_clean(database);
}

#[test]
fn purging_allocation_history_does_not_advance_the_original_user_reader_horizon() {
    let file = crate::create_tempfile();
    let database = Database::builder(crate::test_admission())
        .create(file.path())
        .unwrap()
        .retain();
    let read = database.database().unwrap().begin_read().unwrap();
    let savepoint = retained_savepoint(&database);
    seed_allocation_and_pending(&database, &[400, 17]);
    drop(savepoint);
    for allocated in [vec![17], vec![]] {
        let tx = database.database().unwrap().begin_write().unwrap();
        commit_clean(tx, &database);
        assert_eq!(
            allocation_records(&database)
                .iter()
                .map(|(_, _, count)| *count)
                .collect::<Vec<_>>(),
            allocated
        );
        assert_eq!(pending_records(&database), vec![(0, 400), (1, 17)]);
    }
    drop(read);
    for remaining in [vec![(1, 17)], vec![]] {
        let tx = database.database().unwrap().begin_write().unwrap();
        commit_clean(tx, &database);
        assert_eq!(pending_records(&database), remaining);
    }
    close_clean(database);
}

#[test]
fn persistent_savepoint_restores_original_payload_with_retained_allocation_debt() {
    const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("bounded-allocation-restore");
    let file = crate::create_tempfile();
    let database = Database::builder(crate::test_admission())
        .create(file.path())
        .unwrap()
        .retain();
    let tx = database.database().unwrap().begin_write().unwrap();
    tx.open_table(TABLE)
        .unwrap()
        .insert(1, b"original".as_slice())
        .unwrap();
    commit_clean(tx, &database);
    let tx = database.database().unwrap().begin_write().unwrap();
    let id = tx.persistent_savepoint().unwrap();
    commit_clean(tx, &database);
    let tx = database.database().unwrap().begin_write().unwrap();
    tx.open_table(TABLE)
        .unwrap()
        .insert(1, b"replacement".as_slice())
        .unwrap();
    commit_clean(tx, &database);
    seed_allocation_and_pending(&database, &[400, 400, 17]);
    let before = allocation_records(&database);
    close_clean(database);
    let database = Database::open(file.path(), crate::test_admission())
        .unwrap()
        .retain();
    assert_eq!(allocation_records(&database), before);
    let mut tx = database.database().unwrap().begin_write().unwrap();
    let savepoint = tx.get_persistent_savepoint(id).unwrap();
    tx.restore_savepoint(&savepoint).unwrap();
    drop(savepoint);
    commit_clean(tx, &database);
    {
        let read = database.database().unwrap().begin_read().unwrap();
        assert_eq!(
            read.open_table(TABLE)
                .unwrap()
                .get(1)
                .unwrap()
                .unwrap()
                .value(),
            b"original"
        );
    }
    assert_eq!(allocation_records(&database), before);
    close_clean(database);
    let database = Database::open(file.path(), crate::test_admission())
        .unwrap()
        .retain();
    assert_eq!(allocation_records(&database), before);
    {
        let read = database.database().unwrap().begin_read().unwrap();
        assert_eq!(
            read.open_table(TABLE)
                .unwrap()
                .get(1)
                .unwrap()
                .unwrap()
                .value(),
            b"original"
        );
    }
    // Savepoint deletion makes old allocation rows eligible. It must not
    // publish a DATA free while those rows remain, even on the first commit.
    let tx = database.database().unwrap().begin_write().unwrap();
    assert!(tx.delete_persistent_savepoint(id).unwrap());
    commit_clean(tx, &database);
    assert!(!allocation_records(&database).is_empty());
    close_clean(database);
    let database = Database::open(file.path(), crate::test_admission())
        .unwrap()
        .retain();
    allocation_records(&database); // checks every remaining ID against actual allocator ownership
    close_clean(database);
}

#[test]
fn allocation_prefix_close_failure_retains_actual_transaction_and_original_error() {
    static ALLOCATION_FAILURE: Mutex<Option<FailureCustody>> = Mutex::new(None);
    let file = crate::create_tempfile();
    let mode = Arc::new(AtomicU8::new(0));
    let syncs = Arc::new(AtomicU64::new(0));
    let marker = Arc::new(Marker);
    let owner = Arc::new(Owner {
        failed: AtomicBool::new(false),
    });
    let backend = Backend {
        file: crate::tree_store::file_backend::FileBackend::new(file.reopen().unwrap()).unwrap(),
        mode: mode.clone(),
        syncs: syncs.clone(),
        marker: marker.clone(),
    };
    let mut database = Database::builder(owner.clone())
        .set_page_size(4096)
        .set_region_size(128 << 10)
        .create_with_backend(backend)
        .unwrap()
        .retain();
    // Each canonical record retains one real allocated page. This is a
    // valid pending-page tree; test setup never invents dangling page numbers.
    let tx = database.database().unwrap().begin_write().unwrap();
    // Keep allocation history eligible only after this persisted savepoint
    // releases. This direct extraction test faults before any publication.
    tx.persistent_savepoint().unwrap();
    let seed_transaction_id = tx.transaction_id.raw_id();
    for pagination_id in 0..8 {
        let page = tx
            .page_allocator()
            .allocate(4096, &PageTracker::ignore())
            .unwrap();
        let number = page.get_page_number();
        drop(page);
        let mut bytes = record(1);
        bytes[2..10].copy_from_slice(&number.to_le_bytes());
        tx.system_tables
            .lock()
            .unwrap()
            .open_system_table(&tx.dirty, DATA_ALLOCATED_TABLE)
            .unwrap()
            .insert(
                TransactionIdWithPagination {
                    transaction_id: seed_transaction_id,
                    pagination_id,
                },
                PageList { data: &bytes },
            )
            .unwrap();
    }
    let mut tx = tx.retain();
    assert_eq!(tx.commit().settlement(), WriteTerminalSettlement::Settled);
    assert!(tx.dispose_settled(&database).disposal_complete());
    let tx = database.database().unwrap().begin_write().unwrap();
    // Force the close's next COW allocation to grow the actual file, making the
    // injected sync error deterministic instead of relying on cache eviction.
    let free = tx.mem.count_free_pages().unwrap();
    for _ in 0..free {
        drop(
            tx.page_allocator()
                .allocate(4096, &PageTracker::ignore())
                .unwrap(),
        );
    }
    assert_eq!(tx.mem.count_free_pages().unwrap(), 0);
    let before_syncs = syncs.load(Ordering::Acquire);
    let before_len = file.as_file().metadata().unwrap().len();
    let mut namespace = tx.system_tables.lock().unwrap();
    let mut table = namespace
        .open_system_table(&tx.dirty, DATA_ALLOCATED_TABLE)
        .unwrap();
    let key = TransactionIdWithPagination {
        transaction_id: seed_transaction_id,
        pagination_id: 0,
    };
    table.validate_page_lists(key..=key).unwrap();
    let mut iter = table.extract_from_if(key..=key, |_, _| true).unwrap();
    let entry = iter.next().unwrap().unwrap();
    assert_eq!(entry.1.value().checked().unwrap().len(), 1);
    drop(entry);
    mode.store(1, Ordering::Release);
    let error =
        WriteTransaction::finish_page_list_extraction(&tx.poisoned, iter, Ok(())).unwrap_err();
    let StorageError::Io(original) = &error else {
        std::panic!("close lost original I/O: {error:?}");
    };
    assert!(Arc::ptr_eq(
        &original
            .get_ref()
            .unwrap()
            .downcast_ref::<OriginalIo>()
            .unwrap()
            .0,
        &marker
    ));
    assert!(syncs.load(Ordering::Acquire) > before_syncs);
    assert!(file.as_file().metadata().unwrap().len() > before_len);
    assert!(tx.is_poisoned());
    assert!(owner.failed.load(Ordering::Acquire));
    drop(table);
    drop(namespace);
    let mut tx = tx.retain();
    let report = tx.abort();
    assert_eq!(report.settlement(), WriteTerminalSettlement::Retained);
    assert!(matches!(
        report.terminal(),
        TerminalObservation::Returned(Err(WriteTerminalError::Abort(StorageError::OwnerFailed)))
    ));
    assert!(!tx.dispose_settled(&database).disposal_complete());
    assert_eq!(
        database.close().settlement(),
        DatabaseCloseSettlement::WaitingForTransactions
    );
    let mut custody = ALLOCATION_FAILURE.lock().unwrap();
    assert!(custody.is_none());
    *custody = Some(FailureCustody {
        _error: error,
        _transaction: tx,
        _database: database,
        _file: file,
    });
}
