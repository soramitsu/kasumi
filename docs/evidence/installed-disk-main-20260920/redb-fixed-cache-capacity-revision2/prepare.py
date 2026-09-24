from pathlib import Path
import json, shutil, hashlib
root=Path('/Users/mtakemiya/dev/kasumi')
old=root/'target/installed-disk-validation/redb-fixed-cache-capacity'
new=root/'target/installed-disk-validation/redb-fixed-cache-capacity-revision2'
manifest=json.loads((old/'manifest.json').read_text())
for f in manifest['files']:
 p=f['path']
 proposed=new/'proposed'/p; proposed.parent.mkdir(parents=True,exist_ok=True)
 shutil.copyfile(old/'proposed'/p,proposed)
 actual=root/p
 if actual.exists():
  base=new/'base'/p; base.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(actual,base)
  if p not in ['vendor/redb-4.2.0/src/retained_transaction.rs','vendor/redb-4.2.0/src/transactions.rs']:
   assert hashlib.sha256(actual.read_bytes()).hexdigest()==f['before_sha256'],p
 else: assert f['before_sha256'] is None,p
p='vendor/redb-4.2.0/src/retained_transaction.rs'
s=(root/p).read_text()
s=s.replace('''                if transaction.mem.capacity_denied() {
                    return Err(WriteTerminalError::Commit(
                        StorageError::CapacityDenied.into(),
                    ));
                }''','''                if let Some(error) = transaction.mem.capacity_error() {
                    return Err(WriteTerminalError::Commit(error.into()));
                }''')
s=s.replace('''                    CommitError::Storage(StorageError::CapacityDenied)
                        | CommitError::TransactionPoisoned''','''                    CommitError::Storage(
                        StorageError::CapacityDenied | StorageError::CacheCapacityDenied
                    ) | CommitError::TransactionPoisoned''')
assert 'capacity_denied()' not in s
(new/'proposed'/p).write_text(s)
p='vendor/redb-4.2.0/src/transactions.rs';s=(root/p).read_text()
s=s.replace('''        if self.mem.capacity_denied() {
            self.abort_inner()?;
            return Err(StorageError::CapacityDenied.into());
        }''','''        if let Some(error) = self.mem.capacity_error() {
            self.abort_inner()?;
            return Err(error.into());
        }''')
s=s.replace('''            Err(CommitError::Storage(StorageError::CapacityDenied))''','''            Err(CommitError::Storage(
                StorageError::CapacityDenied | StorageError::CacheCapacityDenied
            ))''')
assert 'capacity_denied()' not in s;(new/'proposed'/p).write_text(s)
p=new/'proposed/vendor/redb-4.2.0/src/tree_store/page_store/lru_cache.rs'
s=p.read_text(); needle='''    pub(crate) fn clear(&mut self) {'''
insert='''    // Two complete queue passes suffice: the first gives each eligible entry
    // its second chance, and the second selects the first eligible entry left.
    // Ineligible entries retain their registration and flag while rotating.
    // There is no removal/reinsertion that could repeatedly select one borrowed
    // entry before an available entry receives its turn.
    pub(crate) fn pop_lowest_priority_if(
        &mut self,
        eligible: impl Fn(&T) -> bool,
    ) -> Option<(u64, T)> {
        let entries = self.lru_queue.len();
        for _ in 0..2 {
            for _ in 0..entries {
                let key = self.lru_queue.pop_front()?;
                if let Some((value, second_chance)) = self.cache.get(&key) {
                    if !eligible(value)
                        || second_chance.swap(false, Ordering::AcqRel)
                    {
                        self.lru_queue.push_back(key);
                    } else {
                        let (value, _) = self.cache.remove(&key).unwrap();
                        return Some((key, value));
                    }
                }
            }
        }
        None
    }

'''
assert s.count(needle)==1;s=s.replace(needle,insert+needle);p.write_text(s)
p=new/'proposed/vendor/redb-4.2.0/src/tree_store/page_store/cached_file.rs'
s=p.read_text();start=s.index('    fn pop_lowest_priority(&mut self) -> Option<(u64, Arc<[u8]>)> {');end=s.index('    fn clear(&mut self)',start)
s=s[:start]+'''    fn pop_lowest_priority(&mut self) -> Option<(u64, Arc<[u8]>)> {
        self.cache
            .pop_lowest_priority_if(Option::is_some)
            .map(|(key, value)| (key, value.unwrap()))
    }

'''+s[end:]
needle='''        self.flush_lowest_priority(cache, 1)?;
        Ok(())'''
assert s.count(needle)==1;s=s.replace(needle,'''        self.flush_lowest_priority(cache, 1)?;
        // Prove that eviction made room rather than inferring it from a
        // successful I/O result: zero bytes may mean no entry was selected.
        if cache.cache.len() >= self.write_entry_capacity() {
            self.cache_capacity_denied.store(true, Ordering::Release);
            return Err(StorageError::CacheCapacityDenied);
        }
        Ok(())''')
needle='''    #[test]
    fn long_same_stripe_traversal_preserves_entry_caps_and_payload()'''
insert='''    #[test]
    fn mixed_borrowed_and_second_chance_entries_make_real_room_before_insert() {
        let page_size = 128u64;
        let stride = page_size * PagedCachedFile::lock_stripes();
        let (backend, writes) = CountingBackend::new(stride * 3);
        let cache =
            PagedCachedFile::new(Box::new(backend), crate::test_admission(), page_size, 4096)
                .unwrap();
        cache.set_write_entry_capacity_for_test(2);
        let mut borrowed = cache.write(0, page_size as usize, true).unwrap();
        borrowed.mem_mut().fill(11);
        // With only A borrowed, an attempted flush cannot select a page. The
        // former remove/reinsert selector left A's flag false in this state.
        assert_eq!(cache.flush_buffered_pages(1).unwrap(), 0);
        let mut available = cache.write(stride, page_size as usize, true).unwrap();
        available.mem_mut().fill(22);
        drop(available); // Returning B gives it a second chance.
        let before = cache.write_buffer_bytes.load(Ordering::Acquire);
        let mut new_page = cache.write(stride * 2, page_size as usize, true).unwrap();
        new_page.mem_mut().fill(33);
        assert_eq!(writes.load(Ordering::Acquire), 1);
        assert_eq!(cache.write_buffer_stripe(0).lock().unwrap().cache.len(), 2);
        assert_eq!(cache.write_buffer_bytes.load(Ordering::Acquire), before);
        assert!(cache.capacity_error().is_none());
        assert!(borrowed.mem().iter().all(|byte| *byte == 11));
        drop(new_page);
        drop(borrowed);
        cache.flush().unwrap();
        for (offset, byte) in [(0, 11), (stride, 22), (stride * 2, 33)] {
            let value = cache.read(offset, page_size as usize, PageHint::Clean).unwrap();
            assert!(value.iter().all(|actual| *actual == byte));
        }
        assert_eq!(cache.write_buffer_bytes.load(Ordering::Acquire), 0);
    }

'''
assert s.count(needle)==1;s=s.replace(needle,insert+needle);p.write_text(s)
p=new/'proposed/vendor/redb-4.2.0/src/cache_admission_tests.rs'
s=p.read_text().replace('AdmissionError, CloseError, CommitError, Database, OwnerFailed, ReadableDatabase,','AdmissionError, CloseError, CommitError, Database, DatabaseCloseSettlement, OwnerFailed, ReadableDatabase,')
s=s.replace('''    let report = tx.commit();
    assert_cache_error(&report);''','''    let mut database = f.db.retain();
    let report = tx.commit();
    let original = assert_cache_error(&report);''',1)
s=s.replace('''    drop(tx);
    assert_eq!(''','''    assert!(!tx.report().disposal_complete());
    let disposed = tx.dispose_settled(&database);
    assert!(disposed.disposal_complete());
    assert_eq!(assert_cache_error(&disposed), original);
    assert_eq!(''',1)
s=s.replace('''    let read = f.db.begin_read().unwrap();''','''    let read = database.database().unwrap().begin_read().unwrap();''',1)
s=s.replace('''    let tx = f.db.begin_write().unwrap();
    tx.open_table(TABLE)
        .unwrap()
        .insert(1, b"retry".as_slice())
        .unwrap();
    tx.commit().unwrap();
    f.db.close().unwrap();''','''    // Reuse the actual writer while the first owner's original refusal stays
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
    assert_eq!(database.close().settlement(), DatabaseCloseSettlement::Settled);
    assert_eq!(assert_cache_error(&tx.report()), original);''',1)
p.write_text(s)
(new/'revision1.json').write_text(json.dumps({'package':str(old.relative_to(root)), 'patch_sha256':manifest['patch_sha256'], 'manifest_sha256':hashlib.sha256((old/'manifest.json').read_bytes()).hexdigest(), 'actual_disposal_dependency':'2933c5a6b379bf61146a9a88b01f912f4ec5018d7182346307a341009f6bb434'},indent=2)+'\n')
print(new)
