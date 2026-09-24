from pathlib import Path
import re
r=Path('/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/redb-bounded-data-reclaim/proposed/vendor/redb-4.2.0/src')
p=r/'db.rs';s=p.read_text()
s=s.replace('DATA_FREED_TABLE, PageList, PageListKind, SYSTEM_FREED_TABLE, SystemTableDefinition,','DATA_FREED_TABLE, OBSOLETE_SYSTEM_FREED_TABLE_NAME, PageList,')
s=s.replace('.checked(PageListKind::Data)', '.checked()')
s=s.replace('''    fn visit_freed_tree<K: Key, V: Value, F>(
        system_root: Option<BtreeHeader>,
        table_def: SystemTableDefinition<K, V>,
        kind: PageListKind,''','''    fn visit_pending_data_pages<F>(
        system_root: Option<BtreeHeader>,''')
s=s.replace('        let table_name = table_def.name();\n        let result = match system_tree.get_table::<K, V>(table_name, TableType::Normal) {','        let table_name = DATA_FREED_TABLE.name();\n        let result = match system_tree.get_table::<TransactionIdWithPagination, PageList>(table_name, TableType::Normal) {')
s=s.replace('.checked(kind)', '.checked()')
pat=r'        Self::visit_freed_tree\(\n            system_root,\n            SYSTEM_FREED_TABLE,\n            PageListKind::System,\n            mem.clone\(\),\n            \|page\| (?:\{[\s\S]*?\}|mem.mark_page_allocated\(page\)),\n        \)\?;\n'
s,n=re.subn(pat,'',s);assert n==2,n
s=s.replace('''        Self::visit_freed_tree(
            system_root,
            DATA_FREED_TABLE,
            PageListKind::Data,''','''        Self::visit_pending_data_pages(
            system_root,''')
# Private construction/repair helper: detect the name without touching an obsolete value.
needle='    pub(crate) fn verify_primary_checksums(mem: Arc<TransactionalMemory>) -> Result<bool> {\n'
assert needle in s
s=s.replace(needle,'''    pub(crate) fn require_canonical_system_tables(mem: &Arc<TransactionalMemory>) -> Result {
        let tree = TableTree::new(
            mem.get_system_root(), PageHint::None,
            Arc::new(TransactionGuard::untracked()), PageResolver::new(mem.clone()),
        )?;
        if tree.contains_table_name(OBSOLETE_SYSTEM_FREED_TABLE_NAME)? {
            return Err(StorageError::ObsoleteSystemTable);
        }
        Ok(())
    }

'''+needle+'        Self::require_canonical_system_tables(&mem)?;\n')
needle='''    fn get_allocator_state_table(
        mem: &Arc<TransactionalMemory>,
    ) -> Result<Option<AllocatorStateTree>> {
''';assert needle in s;s=s.replace(needle,needle+'        Self::require_canonical_system_tables(mem)?;\n')
needle='''    fn rebuild_allocator_state(
        mem: &mut Arc<TransactionalMemory>, // Only &mut to ensure exclusivity
        repair_callback: &(dyn Fn(&mut RepairSession) + 'static),
    ) -> Result<[Option<BtreeHeader>; 2], DatabaseError> {
''';assert needle in s;s=s.replace(needle,needle+'        Self::require_canonical_system_tables(mem)?;\n')
# Keep the established bounded number of maintenance commits; report eligible
# data backlog as work remaining instead of false compaction completion.
s=s.replace('''    /// Returns whether this bounded relocation batch moved any pages. Candidate
    /// discovery still scans the database; callers must separately admit that work.''','''    /// Returns true if relocation moved pages or a bounded maintenance batch
    /// leaves pending DATA reclamation. False never hides eligible reclaim debt.
    /// Candidate discovery still scans the database; callers must separately admit that work.''')
s=s.replace('''        self.drain_pending_free_pages(ShrinkPolicy::Maximum)?;
        Ok(progress)
    }

    fn drain_pending_free_pages(&self, shrink_policy: ShrinkPolicy) -> Result {''','''        let reclaim_pending = self.drain_pending_free_pages(ShrinkPolicy::Maximum)?;
        Ok(progress || reclaim_pending)
    }

    fn drain_pending_free_pages(&self, shrink_policy: ShrinkPolicy) -> Result<bool> {''')
s=s.replace('''        // A commit's repair snapshot is itself retained bookkeeping. Bound
        // maintenance to two generations rather than chasing its own tail.
        for _ in 0..2 {''','''        // Two commits remain a fixed per-call maintenance allowance. Current
        // system frees are excluded directly, so this does not generate a new
        // historical system tail. Report any DATA prefix left for the caller.
        let mut remaining = false;
        for _ in 0..2 {''')
needle='''            txn.set_shrink_policy(shrink_policy);
            txn.commit().map_err(|e| e.into_storage_error())?;
        }
        Ok(())
    }
''';assert needle in s
s=s.replace(needle,'''            txn.set_shrink_policy(shrink_policy);
            // No user mutation occurs between this bounded selection and this
            // empty maintenance commit; the real writer guard excludes others.
            remaining = txn.data_reclaim_backlog_after_batch()?;
            txn.commit().map_err(|e| e.into_storage_error())?;
        }
        Ok(remaining)
    }
''',1)
assert 'PageListKind' not in s
assert 'SYSTEM_FREED_TABLE' not in s.replace('OBSOLETE_SYSTEM_FREED_TABLE_NAME','')
p.write_text(s)
p=r/'tree_store/page_store/page_manager.rs';s=p.read_text();needle='''        deferred_reclaim: &[PageNumber],
    ) -> Result<bool> {''';assert needle in s;s=s.replace(needle,'''        deferred_reclaim: &[PageNumber],
        current_system_reclaim: &[PageNumber],
    ) -> Result<bool> {''')
s=s.replace('''        for page in deferred_reclaim {
            let order = allocators.region_allocators[page.region as usize]''','''        // Neither slice is returned to the live allocator here. Current system
        // pages are writer-private, and the caller guarantees no system-tree
        // allocation/free after this snapshot completes. The winning header
        // therefore names this prepared allocator; failure preserves old-root
        // ownership and the existing retained transaction collections.
        for page in deferred_reclaim.iter().chain(current_system_reclaim) {
            let order = allocators.region_allocators[page.region as usize]''')
p.write_text(s)
