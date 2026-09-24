from pathlib import Path
p=Path('/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/redb-bounded-data-reclaim/proposed/vendor/redb-4.2.0/src/page_list_tests.rs')
s=p.read_text();start=s.index('fn record(');end=s.index('\n#[derive(Debug)]\nstruct Marker;',start)
s=s[:start]+'''fn record(count: usize) -> Vec<u8> {
    let mut bytes = vec![0xa5; PageList::required_bytes(DATA_PAGE_LIST_CAPACITY)];
    bytes[..2].copy_from_slice(&u16::try_from(count).unwrap().to_le_bytes());
    for index in 0..count.min(DATA_PAGE_LIST_CAPACITY) {
        let offset = 2 + index * PageNumber::serialized_size();
        bytes[offset..offset + 8]
            .copy_from_slice(&PageNumber::new(0, index as u32, 0).to_le_bytes());
    }
    bytes
}

#[test]
fn canonical_data_page_list_rejects_obsolete_system_shape_without_allocating() {
    for count in [1, DATA_PAGE_LIST_CAPACITY] {
        let bytes = record(count);
        let (checked, allocations) = crate::admission::observe_test_allocations(|| {
            PageList { data: &bytes }.checked()
        });
        assert_eq!(allocations, 0);
        let checked = checked.unwrap();
        assert_eq!(checked.len(), count);
        assert_eq!(checked.get(count - 1), PageNumber::new(0, (count - 1) as u32, 0));
    }
    let valid = record(1);
    // 1602 bytes was the obsolete system-row shape. It has no decoder.
    let invalid = [Vec::new(), vec![1], valid[..10].to_vec(), valid[..1602].to_vec(),
        record(0), record(DATA_PAGE_LIST_CAPACITY + 1), record(u16::MAX as usize)];
    for bytes in invalid {
        let (result, allocations) = crate::admission::observe_test_allocations(|| {
            PageList { data: &bytes }.checked()
        });
        assert!(matches!(result, Err(StorageError::InvalidPageList)));
        assert_eq!(allocations, 0);
    }
}

#[test]
fn malformed_selected_data_record_is_rejected_before_any_pending_removal() {
    for invalid_first in [true, false] {
        let file = crate::create_tempfile();
        let mut database = Database::builder(crate::test_admission()).create(file.path()).unwrap().retain();
        let mut tx = database.database().unwrap().begin_write().unwrap();
        let first = TransactionIdWithPagination { transaction_id: 10_000, pagination_id: 0 };
        let second = TransactionIdWithPagination { transaction_id: 10_000, pagination_id: 1 };
        let valid = record(1);
        let malformed = record(DATA_PAGE_LIST_CAPACITY + 1);
        let values = if invalid_first { [&malformed, &valid] } else { [&valid, &malformed] };
        {
            let mut namespace = tx.system_tables.lock().unwrap();
            let mut data = namespace.open_system_table(&tx.dirty, DATA_FREED_TABLE).unwrap();
            data.insert(first, PageList { data: values[0] }).unwrap();
            data.insert(second, PageList { data: values[1] }).unwrap();
        }
        assert!(matches!(tx.process_freed_pages(TransactionId::new(10_001)), Err(StorageError::InvalidPageList)));
        assert!(tx.deferred_reclaim.is_empty());
        assert!(tx.is_poisoned());
        {
            let mut namespace = tx.system_tables.lock().unwrap();
            let data = namespace.open_system_table(&tx.dirty, DATA_FREED_TABLE).unwrap();
            assert_eq!(data.get(first).unwrap().unwrap().value().data, values[0]);
            assert_eq!(data.get(second).unwrap().unwrap().value().data, values[1]);
        }
        let mut tx = tx.retain();
        assert_eq!(tx.abort().settlement(), WriteTerminalSettlement::Settled);
        assert!(tx.dispose_settled(&database).disposal_complete());
        let check = database.database().unwrap().begin_write().unwrap();
        assert!(check.system_tables.lock().unwrap().get_system_table_root(DATA_FREED_TABLE).unwrap().is_none());
        let mut check = check.retain();
        assert_eq!(check.abort().settlement(), WriteTerminalSettlement::Settled);
        assert!(check.dispose_settled(&database).disposal_complete());
        let close = database.close();
        assert_eq!(close.settlement(), DatabaseCloseSettlement::Settled);
        assert!(matches!(close.shutdown(), TerminalObservation::Returned(Ok(()))));
        assert!(matches!(close.backend(), TerminalObservation::Returned(Ok(()))));
    }
}

#[test]
fn fixed_deferred_storage_preserves_exact_capacity_and_never_allocates() {
    let (mut pending, allocations) = crate::admission::observe_test_allocations(|| {
        let mut pending = DeferredReclaim::new();
        for i in 0..DATA_PAGE_LIST_CAPACITY {
            pending.push(PageNumber::new(0, i as u32, 0)).unwrap();
        }
        assert!(matches!(pending.push(PageNumber::new(0, 401, 0)), Err(StorageError::InvalidPageList)));
        pending
    });
    assert_eq!(allocations, 0);
    assert_eq!(pending.as_slice().len(), DATA_PAGE_LIST_CAPACITY);
    for (i, page) in pending.as_slice().iter().enumerate() {
        assert_eq!(*page, PageNumber::new(0, i as u32, 0));
    }
    pending.clear();
    assert!(pending.is_empty());
}
'''+s[end:]
s=s.replace('record(PageListKind::System, 1)', 'record(1)').replace('SYSTEM_FREED_TABLE','DATA_FREED_TABLE')
s=s.replace('.open_system_table(&tx,', '.open_system_table(&tx.dirty,')
s=s.replace('.validate_page_lists(key..=key, PageListKind::System)', '.validate_page_lists(key..=key)')
s=s.replace('.checked(PageListKind::System)', '.checked()')
s=s.replace('tx.finish_page_list_extraction(iter, Ok(()))', 'WriteTransaction::finish_page_list_extraction(&tx.poisoned, iter, Ok(()))')
p.write_text(s)
