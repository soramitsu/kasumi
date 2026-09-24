use super::*;
use crate::{
    AdmissionError, Database, DatabaseCloseSettlement, OwnerFailed, RetainedDatabase,
    RetainedWriteTransaction, StorageAdmission, StorageBackend, TerminalObservation,
    WriteTerminalSettlement,
};
use std::sync::atomic::{AtomicU8, AtomicU64};

fn record(kind: PageListKind, count: usize) -> Vec<u8> {
    let mut bytes = vec![0xa5; PageList::required_bytes(kind.capacity())];
    bytes[..2].copy_from_slice(&u16::try_from(count).unwrap().to_le_bytes());
    for index in 0..count.min(kind.capacity()) {
        let offset = 2 + index * PageNumber::serialized_size();
        bytes[offset..offset + 8]
            .copy_from_slice(&PageNumber::new(0, index as u32, 0).to_le_bytes());
    }
    bytes
}

#[test]
fn canonical_page_list_shapes_accept_used_entries_and_reject_other_shapes_without_allocating() {
    for kind in [PageListKind::Data, PageListKind::System] {
        for count in [1, kind.capacity()] {
            let bytes = record(kind, count);
            let (checked, allocations) = crate::admission::observe_test_allocations(|| {
                PageList { data: &bytes }.checked(kind)
            });
            assert_eq!(allocations, 0);
            let checked = checked.unwrap();
            assert_eq!(checked.len(), count);
            assert_eq!(
                checked.get(count - 1),
                PageNumber::new(0, (count - 1) as u32, 0)
            );
        }
        let valid = record(kind, 1);
        let invalid = [
            Vec::new(),
            vec![1],
            valid[..10].to_vec(),
            record(kind, 0),
            record(kind, kind.capacity() + 1),
            record(kind, u16::MAX as usize),
        ];
        for bytes in invalid {
            let (result, allocations) = crate::admission::observe_test_allocations(|| {
                PageList { data: &bytes }.checked(kind)
            });
            assert!(matches!(result, Err(StorageError::InvalidPageList)));
            assert_eq!(allocations, 0);
        }
    }
    let data = record(PageListKind::Data, 1);
    assert!(matches!(
        PageList { data: &data }.checked(PageListKind::System),
        Err(StorageError::InvalidPageList)
    ));
    let system = record(PageListKind::System, 1);
    assert!(matches!(
        PageList { data: &system }.checked(PageListKind::Data),
        Err(StorageError::InvalidPageList)
    ));
}

#[test]
fn malformed_record_in_either_namespace_is_rejected_before_any_pending_removal() {
    for invalid_kind in [PageListKind::Data, PageListKind::System] {
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
        let valid = record(PageListKind::Data, 1);
        let malformed = record(invalid_kind, invalid_kind.capacity() + 1);
        {
            let mut namespace = tx.system_tables.lock().unwrap();
            namespace
                .open_system_table(&tx, DATA_FREED_TABLE)
                .unwrap()
                .insert(first, PageList { data: &valid })
                .unwrap();
            let definition = match invalid_kind {
                PageListKind::Data => DATA_FREED_TABLE,
                PageListKind::System => SYSTEM_FREED_TABLE,
            };
            namespace
                .open_system_table(&tx, definition)
                .unwrap()
                .insert(second, PageList { data: &malformed })
                .unwrap();
        }
        let result = tx.process_freed_pages(TransactionId::new(10_001));
        assert!(matches!(result, Err(StorageError::InvalidPageList)));
        assert!(tx.deferred_reclaim.is_empty());
        assert!(tx.is_poisoned());
        {
            let mut namespace = tx.system_tables.lock().unwrap();
            let data = namespace.open_system_table(&tx, DATA_FREED_TABLE).unwrap();
            assert_eq!(data.get(first).unwrap().unwrap().value().data, valid);
            drop(data);
            let definition = match invalid_kind {
                PageListKind::Data => DATA_FREED_TABLE,
                PageListKind::System => SYSTEM_FREED_TABLE,
            };
            let bad = namespace.open_system_table(&tx, definition).unwrap();
            assert_eq!(bad.get(second).unwrap().unwrap().value().data, malformed);
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
    fn close(&self) -> std::io::Result<()> {
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
        let mut bytes = record(PageListKind::System, 1);
        bytes[2..10].copy_from_slice(&number.to_le_bytes());
        tx.system_tables
            .lock()
            .unwrap()
            .open_system_table(&tx, SYSTEM_FREED_TABLE)
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
        .open_system_table(&tx, SYSTEM_FREED_TABLE)
        .unwrap();
    let key = TransactionIdWithPagination {
        transaction_id: seed_transaction_id,
        pagination_id: 0,
    };
    table
        .validate_page_lists(key..=key, PageListKind::System)
        .unwrap();
    let mut iter = table.extract_from_if(key..=key, |_, _| true).unwrap();
    let entry = iter.next().unwrap().unwrap();
    assert_eq!(
        entry.1.value().checked(PageListKind::System).unwrap().len(),
        1
    );
    drop(entry);
    mode.store(1, Ordering::Release);
    let error = tx.finish_page_list_extraction(iter, Ok(())).unwrap_err();
    let StorageError::Io(original) = &error else {
        panic!("close lost original I/O: {error:?}");
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
