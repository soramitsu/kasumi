from pathlib import Path
p=Path(__file__).parent/'proposed/vendor/redb-4.2.0/src'
f=p/'transactions.rs';s=f.read_text()
s=s.replace('''struct ValidatedPageListPrefix {
    free_until: TransactionId,''','''#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingPageList {
    Allocated,
    Freed,
}
impl PendingPageList {
    fn definition(self) -> SystemTableDefinition<'static, TransactionIdWithPagination, PageList<'static>> {
        match self {
            Self::Allocated => DATA_ALLOCATED_TABLE,
            Self::Freed => DATA_FREED_TABLE,
        }
    }
}

struct ValidatedPageListPrefix {
    table: PendingPageList,
    free_until: TransactionId,''')
s=s.replace('''    pages: usize,
    remaining: bool,
}''','''    pages: usize,
    remaining: bool,
    eligible_remaining: bool,
}''',1)
s=s.replace('''    // Keep allocation records only while a surviving savepoint can use them.
    // Deferred reclamation is represented in the prepared allocator snapshot.
    fn flush_data_allocated_pages(&self, data_allocated_pages: Vec<PageNumber>) -> Result<u64> {''','''    // Record current allocation history and freeze its post-commit savepoint
    // horizon. Removal is a separately prevalidated bounded prefix.
    fn record_data_allocations(&self, data_allocated_pages: Vec<PageNumber>) -> Result<u64> {''')
old='''        let key = TransactionIdWithPagination {
            transaction_id: oldest,
            pagination_id: 0,
        };
        allocated_table.validate_page_lists(..key)?;
        let mut iter = allocated_table.extract_from_if(..key, |_, _| true)?;
        let result = (|| {
            for entry in &mut iter {
                entry?;
            }
            Ok(())
        })();
        Self::finish_page_list_extraction(&self.poisoned, iter, result)?;

        Ok(oldest)'''
assert old in s;s=s.replace(old,'        Ok(oldest)')
old='''        self.process_freed_pages(free_until_transaction)?;
        // Prepare allocation records before constructing the repair snapshot.
        self.flush_data_allocated_pages(allocated_pages)?;'''
new='''        // Freeze the DATA read horizon before any savepoint can disappear.
        // A later release may make more work eligible, but cannot widen this
        // commit's selected prefix after its allocation metadata was checked.
        let allocation_horizon = self.record_data_allocations(allocated_pages)?;
        self.process_pending_pages(free_until_transaction, allocation_horizon)?;'''
assert old in s;s=s.replace(old,new)
s=s.replace('''    fn select_data_reclaim(
        system_tables: &mut SystemNamespace,
        dirty: &AtomicBool,
        free_until: TransactionId,
    ) -> Result<ValidatedPageListPrefix> {
        let root = system_tables.get_system_table_root(DATA_FREED_TABLE)?;
        let mut plan = ValidatedPageListPrefix {
            free_until,''','''    fn select_page_list_prefix(
        system_tables: &mut SystemNamespace,
        dirty: &AtomicBool,
        table: PendingPageList,
        free_until: TransactionId,
    ) -> Result<ValidatedPageListPrefix> {
        let root = system_tables.get_system_table_root(table.definition())?;
        let mut plan = ValidatedPageListPrefix {
            table,
            free_until,''')
s=s.replace('''            remaining: false,
        };
        if root.is_none()''','''            remaining: false,
            eligible_remaining: false,
        };
        if root.is_none()''',1)
s=s.replace('''        let table = system_tables.open_system_table(dirty, DATA_FREED_TABLE)?;
        let horizon''','''        let table = system_tables.open_system_table(dirty, table.definition())?;
        let horizon''',1)
s=s.replace('''            if pages.len() > DATA_PAGE_LIST_CAPACITY - plan.pages {
                plan.remaining = true;
                break;''','''            if pages.len() > DATA_PAGE_LIST_CAPACITY - plan.pages {
                plan.remaining = true;
                plan.eligible_remaining = true;
                break;''',1)
start=s.index('    fn process_freed_pages(')
end=s.index('    // Explicit close remains mandatory',start)
s=s[:start]+'''    fn process_pending_pages(&mut self, free_until: TransactionId, allocation_horizon: u64) -> Result {
        let mut system_tables = self.system_tables.lock().unwrap();
        let result = (|| {
            if !self.deferred_reclaim.is_empty() {
                return Err(StorageError::InvalidPageList);
            }
            let allocated = Self::select_page_list_prefix(
                &mut system_tables,
                &self.dirty,
                PendingPageList::Allocated,
                TransactionId::new(allocation_horizon),
            )?;
            // Retained eligible allocation rows may still reference historical
            // DATA pages. Purge them in bounded commits before freeing any DATA.
            // If this commit can reclaim DATA, validate that prefix as well
            // before removing anything from either namespace.
            let freed = if allocated.eligible_remaining {
                None
            } else {
                Some(Self::select_page_list_prefix(
                    &mut system_tables,
                    &self.dirty,
                    PendingPageList::Freed,
                    free_until,
                )?)
            };
            Self::extract_allocated_prefix(
                &mut system_tables,
                &self.dirty,
                &self.poisoned,
                allocated,
            )?;
            if let Some(freed) = freed {
                Self::extract_data_reclaim(
                    &mut system_tables,
                    &self.dirty,
                    &self.poisoned,
                    &mut self.deferred_reclaim,
                    freed,
                )?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }

    fn extract_allocated_prefix(
        system_tables: &mut SystemNamespace,
        dirty: &AtomicBool,
        poisoned: &AtomicBool,
        plan: ValidatedPageListPrefix,
    ) -> Result {
        if plan.table != PendingPageList::Allocated
            || system_tables.get_system_table_root(DATA_ALLOCATED_TABLE)? != plan.root
        {
            return Err(StorageError::InvalidPageList);
        }
        let Some(last) = plan.last else {
            return Ok(());
        };
        if last.transaction_id >= plan.free_until.raw_id() {
            return Err(StorageError::InvalidPageList);
        }
        let mut allocated = system_tables.open_system_table(dirty, DATA_ALLOCATED_TABLE)?;
        let mut iter = allocated.extract_from_if(..=last, |_, _| true)?;
        let result = (|| {
            let mut records = 0;
            let mut pages = 0;
            for entry in &mut iter {
                let (_, page_list) = entry?;
                pages += page_list.value().checked()?.len();
                records += 1;
            }
            if records != plan.records || pages != plan.pages {
                return Err(StorageError::InvalidPageList);
            }
            Ok(())
        })();
        Self::finish_page_list_extraction(poisoned, iter, result)
    }

    fn extract_data_reclaim(
        system_tables: &mut SystemNamespace,
        dirty: &AtomicBool,
        poisoned: &AtomicBool,
        deferred: &mut DeferredReclaim,
        plan: ValidatedPageListPrefix,
    ) -> Result {
        if plan.table != PendingPageList::Freed
            || system_tables.get_system_table_root(DATA_FREED_TABLE)? != plan.root
        {
            return Err(StorageError::InvalidPageList);
        }
        let Some(last) = plan.last else {
            return Ok(());
        };
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
        if let Err(error) = Self::finish_page_list_extraction(poisoned, iter, result) {
            return Err(error);
        }
        Ok(())
    }

    // Only explicit maintenance calls this before its otherwise empty commit.
    // The writer guard keeps both roots stable; read/savepoint horizons may
    // advance as owners release. Count ineligible rows as retained debt too.
    // A blocked DATA phase leaves even a small DATA prefix for a later commit.
    pub(crate) fn reclaim_backlog_after_batch(&self) -> Result<bool> {
        let free_until = self
            .transaction_tracker
            .oldest_live_read_transaction()
            .map_or(self.transaction_id, |id| id.next());
        let deleted_savepoints = self.savepoint_state.lock().unwrap().pending_deleted_ids();
        let oldest = self.transaction_tracker.oldest_savepoint_excluding(&deleted_savepoints)
            .map_or(u64::MAX, |(_, id)| id.raw_id());
        let mut system_tables = self.system_tables.lock().unwrap();
        let allocated = Self::select_page_list_prefix(
            &mut system_tables,
            &self.dirty,
            PendingPageList::Allocated,
            TransactionId::new(oldest),
        )?;
        let freed = Self::select_page_list_prefix(
            &mut system_tables,
            &self.dirty,
            PendingPageList::Freed,
            free_until,
        )?;
        Ok(allocated.remaining || freed.remaining
            || (allocated.eligible_remaining && freed.last.is_some()))
    }

'''+s[end:]
# Keep existing direct extraction return idiom, no needless manual propagation.
s=s.replace('''        if let Err(error) = Self::finish_page_list_extraction(poisoned, iter, result) {
            return Err(error);
        }
        Ok(())''','''        Self::finish_page_list_extraction(poisoned, iter, result)''')
s=s.replace('            // No need to process the system freed table, because it only rolls forward','            // Current system pages are writer-private and only roll forward.')
f.write_text(s)
f=p/'db.rs';s=f.read_text().replace('DATA debt beyond its batch','DATA or allocation-history debt beyond its batch').replace('unselected DATA reclaim debt','unselected reclaim debt').replace('historical system tail. Report any DATA prefix left for the caller.','historical system tail. Report either retained metadata prefix.').replace('txn.data_reclaim_backlog_after_batch()?','txn.reclaim_backlog_after_batch()?');f.write_text(s)
f=p/'page_list_tests.rs';s=f.read_text().replace('tx.process_freed_pages(TransactionId::new(10_001))','tx.process_pending_pages(TransactionId::new(10_001), u64::MAX)').replace('tx.process_freed_pages(horizon)','tx.process_pending_pages(horizon, u64::MAX)').replace('tx.data_reclaim_backlog_after_batch()','tx.reclaim_backlog_after_batch()');f.write_text(s)
