use crate::Result;
use crate::sync::Mutex;
use crate::tree_store::btree::{PagePath, UntypedBtree, UntypedBtreeMut, btree_stats};
use crate::tree_store::btree_base::{
    BRANCH, BranchAccessor, BranchMutator, Checksum, DEFERRED, LEAF, LeafAccessor, LeafPageMut,
};
use crate::tree_store::multimap_btree::DynamicCollectionType::{Inline, SubtreeV2};
use crate::tree_store::{
    AllPageNumbersBtreeIter, BtreeHeader, BtreeStats, Page, PageAllocator, PageHint, PageNumber,
    PageNumberHashMap, PageResolver, PageTracker, RawBtree,
};
use crate::types::{Key, TypeName, Value};
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::max;
use core::marker::PhantomData;
use core::ops::Range;

pub(crate) fn multimap_btree_stats(
    root: Option<PageNumber>,
    mem: &PageResolver,
    fixed_key_size: Option<usize>,
    fixed_value_size: Option<usize>,
    hint: PageHint,
) -> Result<BtreeStats> {
    if let Some(root) = root {
        multimap_stats_helper(root, mem, fixed_key_size, fixed_value_size, hint)
    } else {
        Ok(BtreeStats {
            tree_height: 0,
            leaf_pages: 0,
            branch_pages: 0,
            stored_leaf_bytes: 0,
            metadata_bytes: 0,
            fragmented_bytes: 0,
        })
    }
}

fn multimap_stats_helper(
    page_number: PageNumber,
    mem: &PageResolver,
    fixed_key_size: Option<usize>,
    fixed_value_size: Option<usize>,
    hint: PageHint,
) -> Result<BtreeStats> {
    let page = mem.get_page(page_number, hint)?;
    let node_mem = page.memory();
    match node_mem[0] {
        LEAF => {
            let accessor = LeafAccessor::new(
                page.memory(),
                fixed_key_size,
                DynamicCollection::<()>::fixed_width_with(fixed_value_size),
            );
            let mut leaf_bytes = 0u64;
            let mut is_branch = false;
            for i in 0..accessor.num_pairs() {
                let entry = accessor.entry(i).unwrap();
                let collection: &UntypedDynamicCollection =
                    UntypedDynamicCollection::new(entry.value());
                match collection.collection_type() {
                    Inline => {
                        let inline_accessor = LeafAccessor::new(
                            collection.as_inline(),
                            fixed_value_size,
                            <() as Value>::fixed_width(),
                        );
                        leaf_bytes +=
                            inline_accessor.length_of_pairs(0, inline_accessor.num_pairs()) as u64;
                    }
                    SubtreeV2 => {
                        is_branch = true;
                    }
                }
            }
            let mut overhead_bytes = (accessor.total_length() as u64) - leaf_bytes;
            let mut fragmented_bytes = (page.memory().len() - accessor.total_length()) as u64;
            let mut max_child_height = 0;
            let (mut leaf_pages, mut branch_pages) = if is_branch { (0, 1) } else { (1, 0) };

            for i in 0..accessor.num_pairs() {
                let entry = accessor.entry(i).unwrap();
                let collection: &UntypedDynamicCollection =
                    UntypedDynamicCollection::new(entry.value());
                match collection.collection_type() {
                    Inline => {
                        // data is inline, so it was already counted above
                    }
                    SubtreeV2 => {
                        // this is a sub-tree, so traverse it
                        let stats = btree_stats(
                            Some(collection.as_subtree()?.root),
                            mem,
                            fixed_value_size,
                            <() as Value>::fixed_width(),
                            hint,
                        )?;
                        max_child_height = max(max_child_height, stats.tree_height);
                        branch_pages += stats.branch_pages;
                        leaf_pages += stats.leaf_pages;
                        fragmented_bytes += stats.fragmented_bytes;
                        overhead_bytes += stats.metadata_bytes;
                        leaf_bytes += stats.stored_leaf_bytes;
                    }
                }
            }

            Ok(BtreeStats {
                tree_height: max_child_height + 1,
                leaf_pages,
                branch_pages,
                stored_leaf_bytes: leaf_bytes,
                metadata_bytes: overhead_bytes,
                fragmented_bytes,
            })
        }
        BRANCH => {
            let accessor = BranchAccessor::new(&page, fixed_key_size)?;
            let mut max_child_height = 0;
            let mut leaf_pages = 0;
            let mut branch_pages = 1;
            let mut stored_leaf_bytes = 0;
            let mut metadata_bytes = accessor.total_length() as u64;
            let mut fragmented_bytes = (page.memory().len() - accessor.total_length()) as u64;
            for i in 0..accessor.count_children() {
                if let Some(child) = accessor.child_page(i) {
                    let stats =
                        multimap_stats_helper(child, mem, fixed_key_size, fixed_value_size, hint)?;
                    max_child_height = max(max_child_height, stats.tree_height);
                    leaf_pages += stats.leaf_pages;
                    branch_pages += stats.branch_pages;
                    stored_leaf_bytes += stats.stored_leaf_bytes;
                    metadata_bytes += stats.metadata_bytes;
                    fragmented_bytes += stats.fragmented_bytes;
                }
            }

            Ok(BtreeStats {
                tree_height: max_child_height + 1,
                leaf_pages,
                branch_pages,
                stored_leaf_bytes,
                metadata_bytes,
                fragmented_bytes,
            })
        }
        _ => unreachable!(),
    }
}

// Verify all the checksums in the tree, including any Dynamic collection subtrees
pub(super) fn verify_tree_and_subtree_checksums(
    root: Option<BtreeHeader>,
    key_size: Option<usize>,
    value_size: Option<usize>,
    mem: PageResolver,
    hint: PageHint,
) -> Result<bool> {
    if let Some(header) = root {
        if !RawBtree::new(
            Some(header),
            key_size,
            DynamicCollection::<()>::fixed_width_with(value_size),
            mem.clone(),
            hint,
        )
        .verify_checksum()?
        {
            return Ok(false);
        }

        let table_pages_iter =
            AllPageNumbersBtreeIter::new(header.root, key_size, mem.clone(), hint);
        for table_page in table_pages_iter {
            let page = mem.get_page(table_page?, hint)?;
            let subtree_roots = parse_subtree_roots(&page, key_size, value_size)?;
            for header in subtree_roots {
                if !RawBtree::new(
                    Some(header),
                    value_size,
                    <()>::fixed_width(),
                    mem.clone(),
                    hint,
                )
                .verify_checksum()?
                {
                    return Ok(false);
                }
            }
        }
    }

    Ok(true)
}

fn preflight_multimap_relocation(
    number: PageNumber,
    widths: (Option<usize>, Option<usize>),
    allocator: &PageAllocator,
    freed: &Arc<Mutex<Vec<PageNumber>>>,
    map: &PageNumberHashMap<PageNumber>,
    path: &mut [Option<PageNumber>; crate::tree_store::btree_base::MAX_BTREE_DEPTH],
    depth: usize,
) -> Result {
    let (key_size, value_size) = widths;
    if !map.contains_key(&number) {
        return Ok(());
    }
    if depth >= path.len() || path[..depth].contains(&Some(number)) {
        return Err(crate::StorageError::Corrupted(
            "Invalid multimap relocation path".to_string(),
        ));
    }
    path[depth] = Some(number);
    let page = allocator.get_page(number, PageHint::None)?;
    if page.memory()[0] == BRANCH {
        let accessor = BranchAccessor::new(&page, key_size)?;
        for index in 0..accessor.count_children() {
            preflight_multimap_relocation(
                accessor.child_page(index).unwrap(),
                widths,
                allocator,
                freed,
                map,
                path,
                depth + 1,
            )?;
        }
    } else {
        // Validate every stored subtree root before preflighting any subtree.
        let roots = parse_subtree_roots(&page, key_size, value_size)?;
        for header in roots {
            let tree = UntypedBtreeMut::new(
                Some(header),
                allocator.clone(),
                freed.clone(),
                value_size,
                <()>::fixed_width(),
            );
            tree.preflight_relocation(
                header.root,
                map,
                &mut [None; crate::tree_store::btree_base::MAX_BTREE_DEPTH],
                0,
            )?;
        }
    }
    Ok(())
}

pub(super) fn relocate_subtrees(
    root: (PageNumber, Checksum),
    key_size: Option<usize>,
    value_size: Option<usize>,
    page_allocator: PageAllocator,
    freed_pages: Arc<Mutex<Vec<PageNumber>>>,
    relocation_map: &PageNumberHashMap<PageNumber>,
) -> Result<(PageNumber, Checksum)> {
    preflight_multimap_relocation(
        root.0,
        (key_size, value_size),
        &page_allocator,
        &freed_pages,
        relocation_map,
        &mut [None; crate::tree_store::btree_base::MAX_BTREE_DEPTH],
        0,
    )?;
    relocate_subtrees_inner(
        root,
        key_size,
        value_size,
        page_allocator,
        freed_pages,
        relocation_map,
    )
}

// Relocate all subtrees to lower index pages, if possible
fn relocate_subtrees_inner(
    root: (PageNumber, Checksum),
    key_size: Option<usize>,
    value_size: Option<usize>,
    page_allocator: PageAllocator,
    freed_pages: Arc<Mutex<Vec<PageNumber>>>,
    relocation_map: &PageNumberHashMap<PageNumber>,
) -> Result<(PageNumber, Checksum)> {
    let Some(new_page_number) = relocation_map.get(&root.0) else {
        return Ok(root);
    };
    let old_page = page_allocator.get_page(root.0, PageHint::None)?;
    if old_page.memory()[0] == BRANCH {
        BranchAccessor::new(&old_page, key_size)?;
    }
    parse_subtree_roots(&old_page, key_size, value_size)?;
    let mut new_page = page_allocator.get_page_mut(*new_page_number)?;
    let new_page_number = new_page.get_page_number();
    new_page.memory_mut().copy_from_slice(old_page.memory());

    match old_page.memory()[0] {
        LEAF => {
            let mut leaf_page = LeafPageMut::new(
                new_page,
                key_size,
                UntypedDynamicCollection::fixed_width_with(value_size),
            );
            let accessor = LeafAccessor::new(
                old_page.memory(),
                key_size,
                UntypedDynamicCollection::fixed_width_with(value_size),
            );
            for i in 0..accessor.num_pairs() {
                let entry = accessor.entry(i).unwrap();
                let collection = UntypedDynamicCollection::from_bytes(entry.value());
                if matches!(collection.collection_type(), SubtreeV2) {
                    let sub_root = collection.as_subtree()?;
                    let mut tree = UntypedBtreeMut::new(
                        Some(sub_root),
                        page_allocator.clone(),
                        freed_pages.clone(),
                        value_size,
                        <() as Value>::fixed_width(),
                    );
                    tree.relocate(relocation_map)?;
                    if sub_root != tree.get_root().unwrap() {
                        let new_collection =
                            UntypedDynamicCollection::make_subtree_data(tree.get_root().unwrap());
                        leaf_page.replace_value(i, &new_collection);
                    }
                }
            }
        }
        BRANCH => {
            let accessor = BranchAccessor::new(&old_page, key_size)?;
            let mut mutator = BranchMutator::new(new_page.memory_mut())?;
            for i in 0..accessor.count_children() {
                if let Some(child) = accessor.child_page(i) {
                    let child_checksum = accessor.child_checksum(i).unwrap();
                    let (new_child, new_checksum) = relocate_subtrees_inner(
                        (child, child_checksum),
                        key_size,
                        value_size,
                        page_allocator.clone(),
                        freed_pages.clone(),
                        relocation_map,
                    )?;
                    mutator.write_child_page(i, new_child, new_checksum);
                }
            }
        }
        _ => unreachable!(),
    }

    let old_page_number = old_page.get_page_number();
    drop(old_page);
    // No need to track allocations, because this method is only called during compaction when
    // there can't be any savepoints
    let ignore = PageTracker::ignore();
    if !page_allocator.free_if_uncommitted(old_page_number, &ignore) {
        freed_pages.lock().unwrap().push(old_page_number);
    }
    Ok((new_page_number, DEFERRED))
}

// Finalize all the checksums in the tree, including any Dynamic collection subtrees
// Returns the root checksum
pub(super) fn finalize_tree_and_subtree_checksums(
    root: Option<BtreeHeader>,
    key_size: Option<usize>,
    value_size: Option<usize>,
    page_allocator: PageAllocator,
) -> Result<Option<BtreeHeader>> {
    let freed_pages = Arc::new(Mutex::new(vec![]));
    let mut tree = UntypedBtreeMut::new(
        root,
        page_allocator.clone(),
        freed_pages.clone(),
        key_size,
        DynamicCollection::<()>::fixed_width_with(value_size),
    );
    tree.dirty_leaf_visitor(|mut leaf_page| {
        let mut sub_root_updates = vec![];
        let accessor = leaf_page.accessor();
        for i in 0..accessor.num_pairs() {
            let entry = accessor.entry(i).unwrap();
            let collection = <&DynamicCollection<()>>::from_bytes(entry.value());
            if matches!(collection.collection_type(), SubtreeV2) {
                collection.as_subtree()?;
            }
        }
        for i in 0..accessor.num_pairs() {
            let entry = accessor.entry(i).unwrap();
            let collection = <&DynamicCollection<()>>::from_bytes(entry.value());
            if matches!(collection.collection_type(), SubtreeV2) {
                let sub_root = collection.as_subtree()?;
                if page_allocator.uncommitted(sub_root.root) {
                    let mut subtree = UntypedBtreeMut::new(
                        Some(sub_root),
                        page_allocator.clone(),
                        freed_pages.clone(),
                        value_size,
                        <()>::fixed_width(),
                    );
                    let subtree_root = subtree.finalize_dirty_checksums()?.unwrap();
                    sub_root_updates.push((i, subtree_root));
                }
            }
        }
        for (i, sub_root) in sub_root_updates {
            let collection = DynamicCollection::<()>::make_subtree_data(sub_root);
            leaf_page.replace_value(i, &collection);
        }

        Ok(())
    })?;

    let root = tree.finalize_dirty_checksums()?;
    // No pages should have been freed by this operation
    assert!(freed_pages.lock().unwrap().is_empty());
    Ok(root)
}

fn parse_subtree_roots<T: Page>(
    page: &T,
    fixed_key_size: Option<usize>,
    fixed_value_size: Option<usize>,
) -> Result<Vec<BtreeHeader>> {
    Ok(match page.memory()[0] {
        BRANCH => {
            vec![]
        }
        LEAF => {
            let mut result = vec![];
            let accessor = LeafAccessor::new(
                page.memory(),
                fixed_key_size,
                DynamicCollection::<()>::fixed_width_with(fixed_value_size),
            );
            for i in 0..accessor.num_pairs() {
                let entry = accessor.entry(i).unwrap();
                let collection = <&DynamicCollection<()>>::from_bytes(entry.value());
                if matches!(collection.collection_type(), SubtreeV2) {
                    result.push(collection.as_subtree()?);
                }
            }

            result
        }
        _ => unreachable!(),
    })
}

pub(super) struct UntypedMultiBtree {
    mem: PageResolver,
    root: Option<BtreeHeader>,
    hint: PageHint,
    key_width: Option<usize>,
    value_width: Option<usize>,
}

impl UntypedMultiBtree {
    pub(super) fn new(
        root: Option<BtreeHeader>,
        mem: PageResolver,
        hint: PageHint,
        key_width: Option<usize>,
        value_width: Option<usize>,
    ) -> Self {
        Self {
            mem,
            root,
            hint,
            key_width,
            value_width,
        }
    }

    // Applies visitor to pages in the tree
    pub(super) fn visit_all_pages<F>(&self, mut visitor: F) -> Result
    where
        F: FnMut(&PagePath) -> Result,
    {
        let tree = UntypedBtree::new(
            self.root,
            self.mem.clone(),
            self.hint,
            self.key_width,
            UntypedDynamicCollection::fixed_width_with(self.value_width),
        );
        tree.visit_all_pages(|path| {
            visitor(path)?;
            let page = self.mem.get_page(path.page_number(), self.hint)?;
            match page.memory()[0] {
                LEAF => {
                    for header in parse_subtree_roots(&page, self.key_width, self.value_width)? {
                        let subtree = UntypedBtree::new(
                            Some(header),
                            self.mem.clone(),
                            self.hint,
                            self.value_width,
                            <() as Value>::fixed_width(),
                        );
                        subtree.visit_all_pages(|subpath| {
                            let full_path = path.with_subpath(subpath);
                            visitor(&full_path)
                        })?;
                    }
                }
                BRANCH => {
                    // No-op. The tree.visit_pages() call will process this sub-tree
                }
                _ => unreachable!(),
            }
            Ok(())
        })?;

        Ok(())
    }
}

pub(crate) enum DynamicCollectionType {
    Inline,
    // Was used in file format version 1
    // Subtree,
    SubtreeV2,
}

impl From<u8> for DynamicCollectionType {
    fn from(value: u8) -> Self {
        match value {
            LEAF => Inline,
            // 2 => Subtree,
            3 => SubtreeV2,
            _ => unreachable!(),
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<u8> for DynamicCollectionType {
    fn into(self) -> u8 {
        match self {
            // Reuse the LEAF type id, so that we can cast this directly into the format used by
            // LeafAccessor
            Inline => LEAF,
            // Subtree => 2,
            SubtreeV2 => 3,
        }
    }
}

/// Layout:
/// type (1 byte):
/// * 1 = inline data
/// * 2 = sub tree
///
/// (when type = 1) data (n bytes): inlined leaf node
///
/// (when type = 2) root (8 bytes): sub tree root page number
/// (when type = 2) checksum (16 bytes): sub tree checksum
///
/// NOTE: Even though the [`PhantomData`] is zero-sized, the inner data DST must be placed last.
/// See [Exotically Sized Types](https://doc.rust-lang.org/nomicon/exotic-sizes.html#dynamically-sized-types-dsts)
/// section of the Rustonomicon for more details.
#[repr(transparent)]
pub(crate) struct DynamicCollection<V: Key> {
    _value_type: PhantomData<V>,
    data: [u8],
}

impl<V: Key> core::fmt::Debug for DynamicCollection<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DynamicCollection")
            .field("data", &&self.data)
            .finish()
    }
}

impl<V: Key> Value for &DynamicCollection<V> {
    type SelfType<'a>
        = &'a DynamicCollection<V>
    where
        Self: 'a;
    type AsBytes<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> &'a DynamicCollection<V>
    where
        Self: 'a,
    {
        DynamicCollection::new(data)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> &'a [u8]
    where
        Self: 'b,
    {
        &value.data
    }

    fn type_name() -> TypeName {
        TypeName::internal("redb::DynamicCollection")
    }
}

impl<V: Key> DynamicCollection<V> {
    pub(crate) fn new(data: &[u8]) -> &Self {
        unsafe { &*(core::ptr::from_ref::<[u8]>(data) as *const DynamicCollection<V>) }
    }

    pub(crate) fn collection_type(&self) -> DynamicCollectionType {
        DynamicCollectionType::from(self.data[0])
    }

    pub(crate) fn as_inline(&self) -> &[u8] {
        debug_assert!(matches!(self.collection_type(), Inline));
        &self.data[1..]
    }

    /// Given the byte range of a serialized inline-variant collection within a larger
    /// buffer, returns the sub-range that holds the inline leaf data (i.e. what
    /// `as_inline` would return if the collection were deserialized).
    pub(crate) fn inline_range_within(collection_range: Range<usize>) -> Range<usize> {
        // `as_inline` skips the one-byte type tag at `data[0]`.
        (collection_range.start + 1)..collection_range.end
    }

    pub(crate) fn as_subtree(&self) -> Result<BtreeHeader> {
        let malformed = || crate::StorageError::Corrupted("Corrupted multimap subtree".to_string());
        if self.data.len() != 1 + BtreeHeader::serialized_size() || self.data[0] != 3 {
            return Err(malformed());
        }
        BtreeHeader::from_le_bytes(self.data[1..].try_into().map_err(|_| malformed())?)
    }

    pub(crate) fn get_num_values(&self) -> Result<u64> {
        Ok(match self.collection_type() {
            Inline => {
                let leaf_data = self.as_inline();
                let accessor =
                    LeafAccessor::new(leaf_data, V::fixed_width(), <() as Value>::fixed_width());
                accessor.num_pairs() as u64
            }
            SubtreeV2 => self.as_subtree()?.length,
        })
    }

    pub(crate) fn make_inline_data(data: &[u8]) -> Vec<u8> {
        let mut result = vec![Inline.into()];
        result.extend_from_slice(data);

        result
    }

    pub(crate) fn make_subtree_data(header: BtreeHeader) -> Vec<u8> {
        let mut result = vec![SubtreeV2.into()];
        result.extend_from_slice(&header.to_le_bytes());
        result
    }

    pub(crate) fn fixed_width_with(_value_width: Option<usize>) -> Option<usize> {
        None
    }
}

#[repr(transparent)]
struct UntypedDynamicCollection {
    data: [u8],
}

impl UntypedDynamicCollection {
    pub(crate) fn fixed_width_with(_value_width: Option<usize>) -> Option<usize> {
        None
    }

    fn new(data: &[u8]) -> &Self {
        unsafe { &*(core::ptr::from_ref::<[u8]>(data) as *const UntypedDynamicCollection) }
    }

    fn make_subtree_data(header: BtreeHeader) -> Vec<u8> {
        let mut result = vec![SubtreeV2.into()];
        result.extend_from_slice(&header.to_le_bytes());
        result
    }

    fn from_bytes(data: &[u8]) -> &Self {
        Self::new(data)
    }

    fn collection_type(&self) -> DynamicCollectionType {
        DynamicCollectionType::from(self.data[0])
    }

    fn as_inline(&self) -> &[u8] {
        debug_assert!(matches!(self.collection_type(), Inline));
        &self.data[1..]
    }

    fn as_subtree(&self) -> Result<BtreeHeader> {
        let malformed = || crate::StorageError::Corrupted("Corrupted multimap subtree".to_string());
        if self.data.len() != 1 + BtreeHeader::serialized_size() || self.data[0] != 3 {
            return Err(malformed());
        }
        BtreeHeader::from_le_bytes(self.data[1..].try_into().map_err(|_| malformed())?)
    }
}

#[cfg(test)]
mod canonical_root_tests {
    use super::*;
    #[test]
    fn typed_and_untyped_subtrees_share_the_only_canonical_root_decoder() {
        for order in 0..=20 {
            let header = BtreeHeader::new(PageNumber::new(7, 0, order), 23, 31);
            let bytes = DynamicCollection::<u64>::make_subtree_data(header);
            assert_eq!(
                DynamicCollection::<u64>::new(&bytes).as_subtree().unwrap(),
                header
            );
            assert_eq!(
                UntypedDynamicCollection::new(&bytes).as_subtree().unwrap(),
                header
            );
            for bit in (40..59).chain((20 - u32::from(order))..20) {
                let mut bad = bytes.clone();
                bad[1 + bit as usize / 8] |= 1 << (bit % 8);
                assert!(matches!(
                    DynamicCollection::<u64>::new(&bad).as_subtree(),
                    Err(crate::StorageError::Corrupted(_))
                ));
                assert!(matches!(
                    UntypedDynamicCollection::new(&bad).as_subtree(),
                    Err(crate::StorageError::Corrupted(_))
                ));
                assert!(
                    DynamicCollection::<u64>::new(&bad)
                        .get_num_values()
                        .is_err()
                );
            }
            for length in 0..bytes.len() {
                assert!(
                    DynamicCollection::<u64>::new(&bytes[..length])
                        .as_subtree()
                        .is_err()
                );
                assert!(
                    UntypedDynamicCollection::new(&bytes[..length])
                        .as_subtree()
                        .is_err()
                );
            }
        }
    }
}
