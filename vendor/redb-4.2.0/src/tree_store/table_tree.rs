use crate::db::TransactionGuard;
use crate::error::TableError;
use crate::sync::Mutex;
use crate::tree_store::btree::{PagePath, UntypedBtreeMut, btree_stats};
use crate::tree_store::btree_base::BtreeHeader;
use crate::tree_store::multimap_btree::{
    finalize_tree_and_subtree_checksums, verify_tree_and_subtree_checksums,
};
use crate::tree_store::{
    Btree, BtreeCursorRange, BtreeMut, InternalTableDefinition, PageAllocator, PageHint,
    PageNumber, PageNumberHashMap, PageNumberHashSet, PageResolver, PageTracker, RawBtree,
    RawTableDefinition, TableType, multimap_btree_stats,
};
use crate::types::{Key, Value};
use crate::{DatabaseStats, Result};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::max;
use core::mem;
use core::mem::size_of;
use core::ops::RangeFull;

#[derive(Debug)]
#[repr(transparent)]
pub(crate) struct PageListMut {
    data: [u8],
}

impl PageListMut {
    pub(crate) fn push_back(&mut self, value: PageNumber) {
        let len = u16::from_le_bytes(self.data[..size_of::<u16>()].try_into().unwrap());
        self.data[..size_of::<u16>()].copy_from_slice(&(len + 1).to_le_bytes());
        let len: usize = len.into();
        let start = size_of::<u16>() + PageNumber::serialized_size() * len;
        self.data[start..(start + PageNumber::serialized_size())]
            .copy_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn clear(&mut self) {
        self.data[..size_of::<u16>()].fill(0);
    }
}

pub struct TableNameIter {
    inner: BtreeCursorRange<&'static str, RawTableDefinition<'static>>,
    table_type: TableType,
}

impl Iterator for TableNameIter {
    type Item = Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        for entry in self.inner.by_ref() {
            match entry {
                Ok(entry) => {
                    if match entry.value().checked() {
                        Ok(definition) => definition.get_type(),
                        Err(error) => return Some(Err(error)),
                    } == self.table_type
                    {
                        return Some(Ok(entry.key().to_string()));
                    }
                }
                Err(err) => {
                    return Some(Err(err));
                }
            }
        }
        None
    }
}

pub(crate) struct TableTree {
    tree: Btree<&'static str, RawTableDefinition<'static>>,
    mem: PageResolver,
}

impl TableTree {
    pub(crate) fn new(
        master_root: Option<BtreeHeader>,
        page_hint: PageHint,
        guard: Arc<TransactionGuard>,
        mem: PageResolver,
    ) -> Result<Self> {
        Ok(Self {
            tree: Btree::new(master_root, page_hint, guard, mem.clone())?,
            mem,
        })
    }

    pub(crate) fn transaction_guard(&self) -> &Arc<TransactionGuard> {
        self.tree.transaction_guard()
    }

    pub(crate) fn verify_checksums(&self) -> Result<bool> {
        if !self.tree.verify_checksum()? {
            return Ok(false);
        }

        for entry in self.tree.range::<RangeFull, &str>(&(..))? {
            let entry = entry?;
            let definition = entry.value().checked()?;
            match definition {
                InternalTableDefinition::Normal {
                    table_root,
                    fixed_key_size,
                    fixed_value_size,
                    ..
                } => {
                    if let Some(header) = table_root
                        && !RawBtree::new(
                            Some(header),
                            fixed_key_size,
                            fixed_value_size,
                            self.mem.clone(),
                            self.tree.hint(),
                        )
                        .verify_checksum()?
                    {
                        return Ok(false);
                    }
                }
                InternalTableDefinition::Multimap {
                    table_root,
                    fixed_key_size,
                    fixed_value_size,
                    ..
                } => {
                    if !verify_tree_and_subtree_checksums(
                        table_root,
                        fixed_key_size,
                        fixed_value_size,
                        self.mem.clone(),
                        self.tree.hint(),
                    )? {
                        return Ok(false);
                    }
                }
            }
        }

        Ok(true)
    }

    // Counts the tables present, rather than returning the count stored in the tree's header
    pub(crate) fn count_tables(&self) -> Result<u64> {
        let mut count = 0;
        for entry in self.tree.range::<RangeFull, &str>(&(..))? {
            entry?;
            count += 1;
        }
        Ok(count)
    }

    // root_page: the root of the master table
    pub(crate) fn list_tables(&self, table_type: TableType) -> Result<Vec<String>> {
        let iter = self.tree.range::<RangeFull, &str>(&(..))?;
        let iter = TableNameIter {
            inner: iter,
            table_type,
        };
        let mut result = vec![];
        for table in iter {
            result.push(table?);
        }
        Ok(result)
    }

    pub(crate) fn contains_table_name(&self, name: &str) -> Result<bool> {
        Ok(self.tree.get(&name)?.is_some())
    }

    pub(crate) fn get_table_untyped(
        &self,
        name: &str,
        table_type: TableType,
    ) -> Result<Option<InternalTableDefinition>, TableError> {
        if let Some(guard) = self.tree.get(&name)? {
            let definition = guard.value().checked()?;
            definition.check_match_untyped(table_type, name)?;
            Ok(Some(definition))
        } else {
            Ok(None)
        }
    }

    // root_page: the root of the master table
    pub(crate) fn get_table<K: Key, V: Value>(
        &self,
        name: &str,
        table_type: TableType,
    ) -> Result<Option<InternalTableDefinition>, TableError> {
        Ok(
            if let Some(definition) = self.get_table_untyped(name, table_type)? {
                // Do additional checks on the types to be sure they match
                definition.check_match::<K, V>(table_type, name)?;
                Some(definition)
            } else {
                None
            },
        )
    }

    pub(crate) fn visit_all_pages<F>(&self, mut visitor: F) -> Result
    where
        F: FnMut(&PagePath) -> Result,
    {
        // Metadata roots remain raw until every definition in this walk passes.
        for entry in self.tree.range::<RangeFull, &str>(&(..))? {
            entry?.value().checked()?;
        }
        // All the pages in the table tree itself
        self.tree.visit_all_pages(&mut visitor)?;

        // All the normal tables
        for entry in self.list_tables(TableType::Normal)? {
            let definition = self
                .get_table_untyped(&entry, TableType::Normal)
                .map_err(|e| e.into_storage_error_or_corrupted("Internal corruption"))?
                .unwrap();
            definition.visit_all_pages(self.mem.clone(), self.tree.hint(), |path| visitor(path))?;
        }

        for entry in self.list_tables(TableType::Multimap)? {
            let definition = self
                .get_table_untyped(&entry, TableType::Multimap)
                .map_err(|e| e.into_storage_error_or_corrupted("Internal corruption"))?
                .unwrap();
            definition.visit_all_pages(self.mem.clone(), self.tree.hint(), |path| visitor(path))?;
        }

        Ok(())
    }
}

pub(crate) struct TableTreeMut {
    tree: BtreeMut<&'static str, RawTableDefinition<'static>>,
    guard: Arc<TransactionGuard>,
    page_allocator: PageAllocator,
    // Cached updates from tables that have been closed. These must be flushed to the btree.
    // The bool indicates whether the root has dirty (DEFERRED) checksums that need finalization.
    // Never contains an entry for an open table -- the update is taken out on open and re-staged
    // on close -- so entries cannot reference pages that an open handle frees.
    // Ordered so that commits flush table roots in a deterministic order, keeping the pages a
    // commit allocates -- and therefore the resulting file bytes -- reproducible.
    pending_table_updates: BTreeMap<String, (Option<BtreeHeader>, u64, bool)>,
    freed_pages: Arc<Mutex<Vec<PageNumber>>>,
    allocated_pages: Arc<PageTracker>,
}

impl TableTreeMut {
    pub(crate) fn new(
        master_root: Option<BtreeHeader>,
        guard: Arc<TransactionGuard>,
        page_allocator: PageAllocator,
        freed_pages: Arc<Mutex<Vec<PageNumber>>>,
        allocated_pages: Arc<PageTracker>,
    ) -> Self {
        Self {
            tree: BtreeMut::new(
                master_root,
                guard.clone(),
                page_allocator.clone(),
                freed_pages.clone(),
                allocated_pages.clone(),
            ),
            guard,
            page_allocator,
            pending_table_updates: BTreeMap::new(),
            freed_pages,
            allocated_pages,
        }
    }

    pub(crate) fn page_allocator(&self) -> &PageAllocator {
        &self.page_allocator
    }

    pub(crate) fn set_root(&mut self, root: Option<BtreeHeader>) {
        self.tree.set_root(root);
        // Pending updates were staged for the old root and are invalid for the new one
        self.pending_table_updates.clear();
    }

    #[cfg_attr(any(not(debug_assertions), redb_no_std), expect(dead_code))]
    pub(crate) fn visit_all_pages<F>(&self, mut visitor: F) -> Result
    where
        F: FnMut(&PagePath) -> Result,
    {
        // Validate every raw definition before the first visitor callback.
        for entry in self.tree.range::<RangeFull, &str>(&(..))? {
            entry?.value().checked()?;
        }
        // All the pages in the table tree itself
        self.tree.visit_all_pages(&mut visitor)?;

        // All the normal tables
        for entry in self.list_tables(TableType::Normal)? {
            let definition = self
                .get_table_untyped(&entry, TableType::Normal)
                .map_err(|e| e.into_storage_error_or_corrupted("Internal corruption"))?
                .unwrap();
            definition.visit_all_pages(self.page_allocator.resolver(), PageHint::None, |path| {
                visitor(path)
            })?;
        }

        for entry in self.list_tables(TableType::Multimap)? {
            let definition = self
                .get_table_untyped(&entry, TableType::Multimap)
                .map_err(|e| e.into_storage_error_or_corrupted("Internal corruption"))?
                .unwrap();
            definition.visit_all_pages(self.page_allocator.resolver(), PageHint::None, |path| {
                visitor(path)
            })?;
        }

        Ok(())
    }

    // Queues an update to the table root
    pub(crate) fn stage_update_table_root(
        &mut self,
        name: &str,
        table_root: Option<BtreeHeader>,
        length: u64,
    ) {
        let dirty = table_root
            .as_ref()
            .is_some_and(|header| self.page_allocator.uncommitted(header.root));
        self.pending_table_updates
            .insert(name.to_string(), (table_root, length, dirty));
    }

    pub(crate) fn discard_root_updates(&mut self) {
        self.pending_table_updates.clear();
    }

    pub(crate) fn clear_root_updates_and_close(&mut self) {
        self.pending_table_updates.clear();
        // This returns no error, so a poisoned tracker panics here as it did when the caller
        // locked it directly
        self.allocated_pages.close().unwrap();
    }

    pub(crate) fn flush_and_close(
        &mut self,
    ) -> Result<(Option<BtreeHeader>, PageNumberHashSet, Vec<PageNumber>)> {
        match self.flush_inner() {
            Ok(header) => {
                let allocated = self.allocated_pages.close()?;
                let mut old = vec![];
                let mut freed_pages = self.freed_pages.lock()?;
                mem::swap(freed_pages.as_mut(), &mut old);
                Ok((header, allocated, old))
            }
            Err(err) => {
                // Ensure that the allocated pages get clear. Otherwise it will cause a panic
                // when they are dropped
                self.allocated_pages.close()?;
                Err(err)
            }
        }
    }

    fn flush_inner(&mut self) -> Result<Option<BtreeHeader>> {
        self.flush_table_root_updates()?.finalize_dirty_checksums()
    }

    pub(crate) fn flush_table_root_updates(&mut self) -> Result<&mut Self> {
        for name in self.pending_table_updates.keys() {
            self.tree.get(&name.as_str())?.unwrap().value().checked()?;
        }
        for (name, (new_root, new_length, dirty)) in
            core::mem::take(&mut self.pending_table_updates)
        {
            // Bypass .get_table() since the table types are dynamic
            let mut definition = self.tree.get(&name.as_str())?.unwrap().value().checked()?;
            // No-op if the root has not changed and checksums are already finalized
            if !dirty {
                match definition {
                    InternalTableDefinition::Normal { table_root, .. }
                    | InternalTableDefinition::Multimap { table_root, .. } => {
                        if table_root == new_root {
                            continue;
                        }
                    }
                }
            }
            // Finalize any dirty checksums
            match definition {
                InternalTableDefinition::Normal {
                    ref mut table_root,
                    ref mut table_length,
                    fixed_key_size,
                    fixed_value_size,
                    ..
                } => {
                    let mut tree = UntypedBtreeMut::new(
                        new_root,
                        self.page_allocator.clone(),
                        self.freed_pages.clone(),
                        fixed_key_size,
                        fixed_value_size,
                    );
                    *table_root = tree.finalize_dirty_checksums()?;
                    *table_length = new_length;
                }
                InternalTableDefinition::Multimap {
                    ref mut table_root,
                    ref mut table_length,
                    fixed_key_size,
                    fixed_value_size,
                    ..
                } => {
                    *table_root = finalize_tree_and_subtree_checksums(
                        new_root,
                        fixed_key_size,
                        fixed_value_size,
                        self.page_allocator.clone(),
                    )?;
                    *table_length = new_length;
                }
            }
            self.tree.insert(&name.as_str(), &definition.as_raw())?;
        }
        Ok(self)
    }

    // Creates a new table, calls the provided closure to insert entries into it, and then
    // flushes the table root. The flush is done using insert_inplace(), so it's guaranteed
    // that no pages will be allocated or freed after the closure returns
    pub(crate) fn create_table_and_flush_table_root<K: Key + 'static, V: Value + 'static>(
        &mut self,
        name: &str,
        f: impl FnOnce(&mut Self, &mut BtreeMut<K, V>) -> Result,
    ) -> Result {
        assert!(self.pending_table_updates.is_empty());
        assert!(self.tree.get(&name)?.is_none());

        // Reserve space in the table tree
        self.tree.insert(
            &name,
            &InternalTableDefinition::new::<K, V>(TableType::Normal, None, 0).as_raw(),
        )?;

        // Create an empty table and call the provided closure on it
        let mut tree: BtreeMut<K, V> = BtreeMut::new(
            None,
            self.guard.clone(),
            self.page_allocator.clone(),
            self.freed_pages.clone(),
            self.allocated_pages.clone(),
        );
        f(self, &mut tree)?;

        // Finalize the table's checksums
        let table_root = tree.finalize_dirty_checksums()?;
        let table_length = tree.get_root().map(|x| x.length).unwrap_or_default();

        // Flush the root to the table tree, without allocating
        self.tree.insert_inplace(
            &name,
            &InternalTableDefinition::new::<K, V>(TableType::Normal, table_root, table_length)
                .as_raw(),
        )?;

        Ok(())
    }

    pub(crate) fn finalize_dirty_checksums(&mut self) -> Result<Option<BtreeHeader>> {
        self.tree.finalize_dirty_checksums()
    }

    // root_page: the root of the master table
    pub(crate) fn list_tables(&self, table_type: TableType) -> Result<Vec<String>> {
        let tree = TableTree::new(
            self.tree.get_root(),
            PageHint::None,
            self.guard.clone(),
            self.page_allocator.resolver(),
        )?;
        tree.list_tables(table_type)
    }

    pub(crate) fn contains_table_name(&self, name: &str) -> Result<bool> {
        Ok(self.tree.get(&name)?.is_some())
    }

    pub(crate) fn get_table_untyped(
        &self,
        name: &str,
        table_type: TableType,
    ) -> Result<Option<InternalTableDefinition>, TableError> {
        let tree = TableTree::new(
            self.tree.get_root(),
            PageHint::None,
            self.guard.clone(),
            self.page_allocator.resolver(),
        )?;
        let mut result = tree.get_table_untyped(name, table_type);

        if let Ok(Some(definition)) = result.as_mut()
            && let Some((updated_root, updated_length, _)) = self.pending_table_updates.get(name)
        {
            definition.set_header(*updated_root, *updated_length);
        }

        result
    }

    // root_page: the root of the master table
    pub(crate) fn get_table<K: Key, V: Value>(
        &self,
        name: &str,
        table_type: TableType,
    ) -> Result<Option<InternalTableDefinition>, TableError> {
        let tree = TableTree::new(
            self.tree.get_root(),
            PageHint::None,
            self.guard.clone(),
            self.page_allocator.resolver(),
        )?;
        let mut result = tree.get_table::<K, V>(name, table_type);

        if let Ok(Some(definition)) = result.as_mut()
            && let Some((updated_root, updated_length, _)) = self.pending_table_updates.get(name)
        {
            definition.set_header(*updated_root, *updated_length);
        }

        result
    }

    pub(crate) fn rename_table(
        &mut self,
        name: &str,
        new_name: &str,
        table_type: TableType,
    ) -> Result<(), TableError> {
        // Move the definition as stored, not the pending update: staged roots must stay out
        // of the master tree, since reopening the table can free their pages (see stats())
        let stored_definition = if let Some(guard) = self.tree.get(&name)? {
            let definition = guard.value().checked()?;
            definition.check_match_untyped(table_type, name)?;
            Some(definition)
        } else {
            None
        };
        if let Some(definition) = stored_definition {
            if self.get_table_untyped(new_name, table_type)?.is_some() {
                return Err(TableError::TableExists(new_name.to_string()));
            }
            if let Some(update) = self.pending_table_updates.remove(name) {
                self.pending_table_updates
                    .insert(new_name.to_string(), update);
            }
            assert!(self.tree.remove(&name)?.is_some());
            assert!(self.tree.insert(&new_name, &definition.as_raw())?.is_none());
        } else {
            return Err(TableError::TableDoesNotExist(name.to_string()));
        }

        Ok(())
    }

    pub(crate) fn delete_table(
        &mut self,
        name: &str,
        table_type: TableType,
    ) -> Result<bool, TableError> {
        if let Some(definition) = self.get_table_untyped(name, table_type)? {
            // Collect all pages first, then free them. The walk reads each page to discover
            // its children, so we must not invalidate any page before the walk completes.
            let mut pages = vec![];
            definition.visit_all_pages(self.page_allocator.resolver(), PageHint::None, |path| {
                pages.push(path.page_number());
                Ok(())
            })?;
            let mut freed_pages = self.freed_pages.lock().unwrap();
            for page in pages {
                if !self
                    .page_allocator
                    .free_if_uncommitted(page, &self.allocated_pages)
                {
                    freed_pages.push(page);
                }
            }
            drop(freed_pages);

            self.pending_table_updates.remove(name);

            let found = self.tree.remove(&name)?.is_some();
            return Ok(found);
        }

        Ok(false)
    }

    // Takes the staged update for `name`. Called when the table is opened: while it is open
    // the live root is in the handle, and it is re-staged on close
    pub(crate) fn clear_pending_table_update(&mut self, name: &str) {
        self.pending_table_updates.remove(name);
    }

    pub(crate) fn get_or_create_table<K: Key, V: Value>(
        &mut self,
        name: &str,
        table_type: TableType,
    ) -> Result<(Option<BtreeHeader>, u64), TableError> {
        let table = if let Some(found) = self.get_table::<K, V>(name, table_type)? {
            found
        } else {
            let table = InternalTableDefinition::new::<K, V>(table_type, None, 0);
            self.tree.insert(&name, &table.as_raw())?;
            table
        };

        match table {
            InternalTableDefinition::Normal {
                table_root,
                table_length,
                ..
            }
            | InternalTableDefinition::Multimap {
                table_root,
                table_length,
                ..
            } => Ok((table_root, table_length)),
        }
    }

    // Returns the paths to the n pages that are closest to the end of the database
    // The return value is sorted, according to path.page_number()'s Ord
    pub(crate) fn highest_index_pages(
        &self,
        n: usize,
        output: &mut BTreeMap<PageNumber, PagePath>,
    ) -> Result {
        // A later invalid definition must not leave an earlier path in output.
        for entry in self.tree.range::<RangeFull, &str>(&(..))? {
            entry?.value().checked()?;
        }
        for entry in self.tree.range::<RangeFull, &str>(&(..))? {
            let entry = entry?;
            let mut definition = entry.value().checked()?;
            if let Some((updated_root, updated_length, _)) =
                self.pending_table_updates.get(entry.key())
            {
                definition.set_header(*updated_root, *updated_length);
            }

            definition.visit_all_pages(self.page_allocator.resolver(), PageHint::None, |path| {
                output.insert(path.page_number(), path.clone());
                while output.len() > n {
                    output.pop_first();
                }
                Ok(())
            })?;
        }

        self.tree.visit_all_pages(|path| {
            output.insert(path.page_number(), path.clone());
            while output.len() > n {
                output.pop_first();
            }
            Ok(())
        })?;

        Ok(())
    }

    pub(crate) fn relocate_tables(
        &mut self,
        relocation_map: &PageNumberHashMap<PageNumber>,
    ) -> Result {
        for entry in self.tree.range::<RangeFull, &str>(&(..))? {
            entry?.value().checked()?;
        }
        for entry in self.tree.range::<RangeFull, &str>(&(..))? {
            let entry = entry?;
            let mut definition = entry.value().checked()?;
            if let Some((updated_root, updated_length, _)) =
                self.pending_table_updates.get(entry.key())
            {
                definition.set_header(*updated_root, *updated_length);
            }

            if let Some(new_root) = definition.relocate_tree(
                self.page_allocator.clone(),
                self.freed_pages.clone(),
                relocation_map,
            )? {
                // Relocated roots have already-finalized checksums
                self.pending_table_updates.insert(
                    entry.key().to_string(),
                    (Some(new_root), definition.get_length(), false),
                );
            }
        }

        self.tree.relocate(relocation_map)?;

        Ok(())
    }

    pub fn stats(&self) -> Result<DatabaseStats> {
        let master_tree_stats = self.tree.stats()?;
        let mut max_subtree_height = 0;
        let mut total_stored_bytes = 0;
        // Count the master tree leaf pages as branches, since they point to the data trees
        let mut branch_pages = master_tree_stats.branch_pages + master_tree_stats.leaf_pages;
        let mut leaf_pages = 0;
        // Include the master table in the overhead
        let mut total_metadata_bytes =
            master_tree_stats.metadata_bytes + master_tree_stats.stored_leaf_bytes;
        let mut total_fragmented = master_tree_stats.fragmented_bytes;

        let resolver = self.page_allocator.resolver();
        for entry in self.tree.range::<RangeFull, &str>(&(..))? {
            let entry = entry?;
            let mut definition = entry.value().checked()?;
            if let Some((updated_root, length, _)) = self.pending_table_updates.get(entry.key()) {
                definition.set_header(*updated_root, *length);
            }
            match definition {
                InternalTableDefinition::Normal {
                    table_root,
                    fixed_key_size,
                    fixed_value_size,
                    ..
                } => {
                    let subtree_stats = btree_stats(
                        table_root.map(|x| x.root),
                        &resolver,
                        fixed_key_size,
                        fixed_value_size,
                        PageHint::None,
                    )?;
                    max_subtree_height = max(max_subtree_height, subtree_stats.tree_height);
                    total_stored_bytes += subtree_stats.stored_leaf_bytes;
                    total_metadata_bytes += subtree_stats.metadata_bytes;
                    total_fragmented += subtree_stats.fragmented_bytes;
                    branch_pages += subtree_stats.branch_pages;
                    leaf_pages += subtree_stats.leaf_pages;
                }
                InternalTableDefinition::Multimap {
                    table_root,
                    fixed_key_size,
                    fixed_value_size,
                    ..
                } => {
                    let subtree_stats = multimap_btree_stats(
                        table_root.map(|x| x.root),
                        &resolver,
                        fixed_key_size,
                        fixed_value_size,
                        PageHint::None,
                    )?;
                    max_subtree_height = max(max_subtree_height, subtree_stats.tree_height);
                    total_stored_bytes += subtree_stats.stored_leaf_bytes;
                    total_metadata_bytes += subtree_stats.metadata_bytes;
                    total_fragmented += subtree_stats.fragmented_bytes;
                    branch_pages += subtree_stats.branch_pages;
                    leaf_pages += subtree_stats.leaf_pages;
                }
            }
        }
        Ok(DatabaseStats {
            tree_height: master_tree_stats.tree_height + max_subtree_height,
            allocated_pages: resolver.count_allocated_pages()?,
            leaf_pages,
            branch_pages,
            stored_leaf_bytes: total_stored_bytes,
            metadata_bytes: total_metadata_bytes,
            fragmented_bytes: total_fragmented,
            page_size: self.page_allocator.get_page_size(),
        })
    }
}

impl Drop for TableTreeMut {
    fn drop(&mut self) {
        if crate::panicking() {
            return;
        }
        assert!(self.allocated_pages.is_empty());
    }
}

#[cfg(test)]
mod test {
    use crate::tree_store::table_tree_base::InternalTableDefinition;
    use crate::types::TypeName;

    #[test]
    fn round_trip() {
        let x = InternalTableDefinition::Multimap {
            table_root: None,
            table_length: 0,
            fixed_key_size: None,
            fixed_value_size: Some(5),
            key_alignment: 6,
            value_alignment: 7,
            key_type: TypeName::new("test::Key"),
            value_type: TypeName::new("test::Value"),
        };
        let y = InternalTableDefinition::checked(InternalTableDefinition::as_bytes(&x).as_ref())
            .unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn every_master_table_entry_point_rejects_raw_root_before_visitation_or_mutation() {
        use super::*;
        use crate::tree_store::btree_base::{LeafBuilder, leaf_checksum};
        use crate::tree_store::{AllocationPolicy, InMemoryBackend, Page, TransactionalMemory};
        for table_type in [TableType::Normal, TableType::Multimap] {
            for alias in [0, 1] {
                let mem = Arc::new(
                    TransactionalMemory::new(
                        Box::new(InMemoryBackend::new()),
                        crate::test_admission(),
                        true,
                        4096,
                        None,
                        0,
                    )
                    .unwrap(),
                );
                mem.reset_allocator_state().unwrap();
                let allocator = PageAllocator::new(mem.clone(), AllocationPolicy::Default);
                let tracker = Arc::new(PageTracker::ignore());
                let freed = Arc::new(Mutex::new(vec![]));
                let guard = Arc::new(TransactionGuard::untracked());
                let pair = 1_u64.to_le_bytes();
                let mut builder = LeafBuilder::new(&allocator, &tracker, 1, Some(8), Some(8));
                builder.push(&pair, &pair);
                let page = builder.build().unwrap();
                let leaf = BtreeHeader::new(
                    page.get_page_number(),
                    leaf_checksum(&page, Some(8), Some(8)).unwrap(),
                    1,
                );
                drop(page);
                let good =
                    InternalTableDefinition::new::<u64, u64>(TableType::Normal, Some(leaf), 1);
                let mut bad =
                    InternalTableDefinition::new::<u64, u64>(table_type, Some(leaf), 1).as_bytes();
                let raw = u64::from_le_bytes(bad[10..18].try_into().unwrap());
                let alias = if alias == 0 {
                    raw | (1_u64 << 40)
                } else {
                    (raw & !(0x1f_u64 << 59)) | (4_u64 << 59) | (1_u64 << 19)
                };
                bad[10..18].copy_from_slice(&alias.to_le_bytes());
                let mut tables = TableTreeMut::new(
                    None,
                    guard.clone(),
                    allocator.clone(),
                    freed.clone(),
                    tracker.clone(),
                );
                tables.tree.insert(&"a", &good.as_raw()).unwrap();
                tables
                    .tree
                    .insert(&"z", &RawTableDefinition::from_bytes(&bad))
                    .unwrap();
                let root = tables.tree.finalize_dirty_checksums().unwrap();
                let readonly =
                    TableTree::new(root, PageHint::None, guard.clone(), allocator.resolver())
                        .unwrap();
                let mut visits = 0;
                assert!(matches!(
                    readonly.visit_all_pages(|_| {
                        visits += 1;
                        Ok(())
                    }),
                    Err(crate::StorageError::Corrupted(_))
                ));
                assert_eq!(visits, 0);
                let mut mutable_visits = 0;
                assert!(matches!(
                    tables.visit_all_pages(|_| {
                        mutable_visits += 1;
                        Ok(())
                    }),
                    Err(crate::StorageError::Corrupted(_))
                ));
                assert_eq!(mutable_visits, 0);
                let mut highest = BTreeMap::new();
                assert!(matches!(
                    tables.highest_index_pages(2, &mut highest),
                    Err(crate::StorageError::Corrupted(_))
                ));
                assert!(highest.is_empty());
                assert!(matches!(
                    readonly.get_table_untyped("z", table_type),
                    Err(TableError::Storage(crate::StorageError::Corrupted(_)))
                ));
                assert!(matches!(
                    readonly.list_tables(table_type),
                    Err(crate::StorageError::Corrupted(_))
                ));
                assert!(matches!(
                    readonly.verify_checksums(),
                    Err(crate::StorageError::Corrupted(_))
                ));
                drop(readonly);
                let mut target = allocator.allocate(4096, &tracker).unwrap();
                target.memory_mut().fill(0xa5);
                let target_number = target.get_page_number();
                drop(target);
                let pages = [root.unwrap().root, leaf.root, target_number];
                let before: Vec<_> = pages
                    .iter()
                    .map(|number| {
                        allocator
                            .get_page(*number, PageHint::None)
                            .unwrap()
                            .memory()
                            .to_vec()
                    })
                    .collect();
                let allocated = mem.count_allocated_pages().unwrap();
                let original_root = tables.tree.get_root();
                assert!(matches!(
                    tables.rename_table("z", "renamed", table_type),
                    Err(TableError::Storage(crate::StorageError::Corrupted(_)))
                ));
                assert!(matches!(
                    tables.delete_table("z", table_type),
                    Err(TableError::Storage(crate::StorageError::Corrupted(_)))
                ));
                assert!(matches!(
                    tables.get_or_create_table::<u64, u64>("z", table_type),
                    Err(TableError::Storage(crate::StorageError::Corrupted(_)))
                ));
                let mut map = PageNumberHashMap::default();
                map.insert(leaf.root, target_number);
                assert!(matches!(
                    tables.relocate_tables(&map),
                    Err(crate::StorageError::Corrupted(_))
                ));
                tables
                    .pending_table_updates
                    .insert("a".to_string(), (Some(leaf), 1, true));
                tables
                    .pending_table_updates
                    .insert("z".to_string(), (Some(leaf), 1, true));
                assert!(matches!(
                    tables.flush_table_root_updates(),
                    Err(crate::StorageError::Corrupted(_))
                ));
                assert_eq!(tables.pending_table_updates.len(), 2);
                assert_eq!(tables.tree.get_root(), original_root);
                assert!(freed.lock().unwrap().is_empty());
                assert_eq!(mem.count_allocated_pages().unwrap(), allocated);
                assert_eq!(
                    RawTableDefinition::as_bytes(&tables.tree.get(&"z").unwrap().unwrap().value()),
                    bad
                );
                for (index, page) in pages.iter().enumerate() {
                    assert_eq!(
                        allocator.get_page(*page, PageHint::None).unwrap().memory(),
                        before[index]
                    );
                }
            }
        }
    }
}
