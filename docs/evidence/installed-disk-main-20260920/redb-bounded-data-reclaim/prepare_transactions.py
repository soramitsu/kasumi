from pathlib import Path
p=Path('/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/redb-bounded-data-reclaim/proposed/vendor/redb-4.2.0/src/transactions.rs')
s=p.read_text()
a=s.index('// Pages in the system tree that are in the pending free state:');b=s.index('// The allocator state table',a)
s=s[:a]+'''// Presence is rejected before repair, allocator loading or mutation. There is
// deliberately no key/value definition or decoder for this obsolete table.
pub(crate) const OBSOLETE_SYSTEM_FREED_TABLE_NAME: &str = "system_pages_unreachable";
'''+s[b:]
s=s.replace("pub(crate) type SystemFreedTree = BtreeMut<TransactionIdWithPagination, PageList<'static>>;\n",'')
a=s.index('#[derive(Clone, Copy)]\npub(crate) enum PageListKind');b=s.index('pub(crate) struct CheckedPageList',a)
s=s[:a]+'''pub(crate) const DATA_PAGE_LIST_CAPACITY: usize = 400;

struct ValidatedPageListPrefix {
    free_until: TransactionId,
    root: Option<BtreeHeader>,
    last: Option<TransactionIdWithPagination>,
    records: usize,
    pages: usize,
    remaining: bool,
}

// One original canonical data record's page count is the per-commit historical
// reclamation allowance. Native PageNumber layout, not encoded payload length,
// determines this transaction-resident storage. It never allocates or grows.
struct DeferredReclaim {
    pages: [PageNumber; DATA_PAGE_LIST_CAPACITY],
    len: usize,
}
impl DeferredReclaim {
    fn new() -> Self {
        Self {
            pages: [PageNumber { region: 0, page_index: 0, page_order: 0 }; DATA_PAGE_LIST_CAPACITY],
            len: 0,
        }
    }
    fn is_empty(&self) -> bool { self.len == 0 }
    fn as_slice(&self) -> &[PageNumber] { &self.pages[..self.len] }
    fn push(&mut self, page: PageNumber) -> Result {
        let slot = self.pages.get_mut(self.len).ok_or(StorageError::InvalidPageList)?;
        *slot = page;
        self.len += 1;
        Ok(())
    }
    fn clear(&mut self) { self.len = 0; }
}

'''+s[b:]
s=s.replace('pub(crate) fn checked(self, kind: PageListKind)', 'pub(crate) fn checked(self)')
s=s.replace('let capacity = kind.capacity();','let capacity = DATA_PAGE_LIST_CAPACITY;')
s=s.replace('PageListKind::Data.capacity()', 'DATA_PAGE_LIST_CAPACITY').replace('.checked(PageListKind::Data)', '.checked()')
s=s.replace('        kind: PageListKind,\n','').replace('pages.value().checked(kind)?;', 'pages.value().checked()?;')
s=s.replace('.validate_page_lists(lower.., PageListKind::Data)', '.validate_page_lists(lower..)').replace('.validate_page_lists(..key, PageListKind::Data)', '.validate_page_lists(..key)')
s=s.replace('        transaction: &WriteTransaction,\n', '        dirty: &AtomicBool,\n')
s=s.replace('        transaction.dirty.store(true, Ordering::Release);','        dirty.store(true, Ordering::Release);')
s=s.replace('.open_system_table(self,', '.open_system_table(&self.dirty,')
s=s.replace('    deferred_reclaim: Vec<PageNumber>,','    deferred_reclaim: DeferredReclaim,').replace('            deferred_reclaim: Vec::new(),','            deferred_reclaim: DeferredReclaim::new(),')
s=s.replace('        let transaction_id = guard.id();\n','        crate::Database::require_canonical_system_tables(&mem)?;\n        let transaction_id = guard.id();\n',1)
# Remove the debug-only system deferred decoder as well.
a=s.index('            let system_freed_table =') if '            let system_freed_table =' in s else -1
if a<0:
 a=s.rfind('        {',0,s.index('.open_system_table(&self.dirty, SYSTEM_FREED_TABLE)'))
 b=s.index('\n        }',s.index('.open_system_table(&self.dirty, SYSTEM_FREED_TABLE)'))+len('\n        }')
 s=s[:a]+s[b:]
else:raise AssertionError('inspect debug block before removing')
# Original extraction finish remains reusable for allocated-data/savepoint maintenance.
s=s.replace('self.finish_page_list_extraction(iter, result)?;', 'Self::finish_page_list_extraction(&self.poisoned, iter, result)?;')
# Reject internal attempts to reintroduce an obsolete namespace before commit work.
needle='    fn commit_inner_helper(&mut self) -> Result<(), CommitError> {\n'
s=s.replace(needle,needle+'''        if self.system_tables.lock().unwrap().table_tree
            .contains_table_name(OBSOLETE_SYSTEM_FREED_TABLE_NAME)? {
            return Err(StorageError::ObsoleteSystemTable.into());
        }
''')
# Prepared allocator consumes existing slices, never physical free before winner.
a=s.index('                            // The allocator snapshot must match the committed system root.');b=s.index('                                return Ok(());',a)
s=s[:a]+'''                            // Every obsolete current-system page is writer-private. Keep
                            // its actual allocation until the winning header, but exclude
                            // it directly from that header's prepared allocator. The
                            // existing vector remains the sole owner of this collection.
                            let current_system = system_freed_pages.lock().unwrap();
                            if self.mem.try_save_allocator_state(
                                tree,
                                num_regions,
                                self.deferred_reclaim.as_slice(),
                                &current_system,
                            )? {
'''+s[b:]
# Guard must unlock before a retry can free/allocate table pages.
needle='''                                return Ok(());
                            }

                            // Clear out the table before retrying'''
assert needle in s
s=s.replace(needle,'''                                return Ok(());
                            }
                            drop(current_system);

                            // Clear out the table before retrying''',1)
s=s.replace('''        for page in self.deferred_reclaim.drain(..) {
            page_allocator.free(page, &PageTracker::ignore());
        }''','''        for &page in self.deferred_reclaim.as_slice() {
            page_allocator.free(page, &PageTracker::ignore());
        }
        self.deferred_reclaim.clear();''')
a=s.index('    // NOTE: must be called before store_system_freed_pages()');b=s.index('    // Explicit close remains mandatory',a)
s=s[:a]+'''    // Selection reads at most 400 nonempty canonical records plus one bounded
    // lookahead. Every selected record is checked before any tree mutation.
    fn select_data_reclaim(
        system_tables: &mut SystemNamespace,
        dirty: &AtomicBool,
        free_until: TransactionId,
    ) -> Result<ValidatedPageListPrefix> {
        let root = system_tables.get_system_table_root(DATA_FREED_TABLE)?;
        let mut plan = ValidatedPageListPrefix {
            free_until, root, last: None, records: 0, pages: 0, remaining: false,
        };
        if root.is_none() { return Ok(plan); }
        let table = system_tables.open_system_table(dirty, DATA_FREED_TABLE)?;
        let horizon = TransactionIdWithPagination {
            transaction_id: free_until.raw_id(), pagination_id: 0,
        };
        for entry in table.range(..horizon)? {
            let (key, value) = entry?;
            let pages = value.value().checked()?;
            if pages.len() > DATA_PAGE_LIST_CAPACITY - plan.pages {
                plan.remaining = true;
                break;
            }
            plan.pages += pages.len();
            plan.records += 1;
            plan.last = Some(key.value());
        }
        Ok(plan)
    }

    fn process_freed_pages(&mut self, free_until: TransactionId) -> Result {
        let mut system_tables = self.system_tables.lock().unwrap();
        let result = (|| {
            if !self.deferred_reclaim.is_empty() {
                return Err(StorageError::InvalidPageList);
            }
            let plan = Self::select_data_reclaim(&mut system_tables, &self.dirty, free_until)?;
            Self::extract_data_reclaim(
                &mut system_tables, &self.dirty, &self.poisoned,
                &mut self.deferred_reclaim, plan,
            )
        })();
        if result.is_err() { self.poisoned.store(true, Ordering::Release); }
        result
    }

    fn extract_data_reclaim(
        system_tables: &mut SystemNamespace,
        dirty: &AtomicBool,
        poisoned: &AtomicBool,
        deferred: &mut DeferredReclaim,
        plan: ValidatedPageListPrefix,
    ) -> Result {
        if system_tables.get_system_table_root(DATA_FREED_TABLE)? != plan.root {
            return Err(StorageError::InvalidPageList);
        }
        let Some(last) = plan.last else { return Ok(()); };
        if last.transaction_id >= plan.free_until.raw_id() {
            return Err(StorageError::InvalidPageList);
        }
        let mut freed = system_tables.open_system_table(dirty, DATA_FREED_TABLE)?;
        let mut iter = freed.extract_from_if(..=last, |_, _| true)?;
        let result = (|| {
            let mut records = 0;
            let mut pages = 0;
            for entry in &mut iter {
                let (_, page_list) = entry?;
                let page_list = page_list.value().checked()?;
                for i in 0..page_list.len() {
                    deferred.push(page_list.get(i))?;
                    pages += 1;
                }
                records += 1;
            }
            if records != plan.records || pages != plan.pages {
                return Err(StorageError::InvalidPageList);
            }
            Ok(())
        })();
        Self::finish_page_list_extraction(poisoned, iter, result)
    }

    // Only the explicit maintenance path calls this before its otherwise empty
    // commit. The writer guard keeps selection/root/horizon stable; that commit
    // can add system metadata frees but creates no new DATA pending rows.
    pub(crate) fn data_reclaim_backlog_after_batch(&self) -> Result<bool> {
        let free_until = self.transaction_tracker.oldest_live_read_transaction()
            .map_or(self.transaction_id, |id| id.next());
        let mut system_tables = self.system_tables.lock().unwrap();
        Ok(Self::select_data_reclaim(&mut system_tables, &self.dirty, free_until)?.remaining)
    }

'''+s[b:]
s=s.replace('''    fn finish_page_list_extraction<F>(
        &self,''','''    fn finish_page_list_extraction<F>(
        poisoned: &AtomicBool,''')
s=s.replace('''        if result.is_err() {
            self.poison();
        }
        result
    }

    fn store_system_freed_pages(''','''        if result.is_err() {
            poisoned.store(true, Ordering::Release);
        }
        result
    }

    fn store_system_freed_pages(''')
a=s.index('    fn store_system_freed_pages(')
# Both obsolete writer and pagination helper occupy the end of this impl.
b=s.index('\n}',a)
s=s[:a]+s[b:]
assert 'SYSTEM_FREED_TABLE' not in s.replace('OBSOLETE_SYSTEM_FREED_TABLE_NAME','')
assert 'PageListKind' not in s
p.write_text(s)
