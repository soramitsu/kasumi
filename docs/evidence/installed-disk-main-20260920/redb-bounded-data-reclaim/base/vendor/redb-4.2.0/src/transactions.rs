#[cfg(all(not(redb_no_std), panic = "unwind"))]
#[path = "retained_transaction.rs"]
mod retained_transaction;
#[cfg(all(not(redb_no_std), panic = "unwind"))]
pub use retained_transaction::{
    RetainedWriteTransaction, TerminalObservation, WriteTerminalError, WriteTerminalOperation,
    WriteTerminalReport, WriteTerminalSettlement,
};

use crate::db::TransactionGuard;
use crate::error::CommitError;
use crate::multimap_table::ReadOnlyUntypedMultimapTable;
use crate::sealed::Sealed;
use crate::sync::Mutex;
use crate::table::ReadOnlyUntypedTable;
use crate::transaction_tracker::{SavepointId, TransactionId, TransactionTracker};
#[cfg(all(debug_assertions, not(redb_no_std)))]
use crate::tree_store::PageNumberHashSet;
use crate::tree_store::{
    AllocationPolicy, Btree, BtreeHeader, BtreeMut, InternalTableDefinition, MAX_PAIR_LENGTH,
    MAX_VALUE_LENGTH, Page, PageAllocator, PageHint, PageListMut, PageNumber, PageNumberHashMap,
    PageResolver, PageTracker, SerializedSavepoint, ShrinkPolicy, TableTree, TableTreeMut,
    TableType, TransactionalMemory,
};
use crate::types::{Key, Value};
use crate::{
    AccessGuard, AccessGuardMutInPlace, ExtractIf, MultimapTable, MultimapTableDefinition,
    MultimapTableHandle, MutInPlaceValue, Range, ReadOnlyMultimapTable, ReadOnlyTable, Result,
    Savepoint, SavepointError, StorageError, Table, TableDefinition, TableError, TableHandle,
    TransactionError, TypeName, UntypedMultimapTableHandle, UntypedTableHandle,
};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::cmp::min;
use core::fmt::{Debug, Display, Formatter};
use core::marker::PhantomData;
use core::mem;
use core::mem::size_of;
use core::ops::{RangeBounds, RangeFull};
use core::panic;
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "logging")]
use log::debug;

const MAX_PAGES_PER_COMPACTION: usize = 64;
const NEXT_SAVEPOINT_TABLE: SystemTableDefinition<(), SavepointId> =
    SystemTableDefinition::new("next_savepoint_id");
pub(crate) const SAVEPOINT_TABLE: SystemTableDefinition<SavepointId, SerializedSavepoint> =
    SystemTableDefinition::new("persistent_savepoints");
// Pages that were allocated in the data tree by a given transaction. Only updated when a savepoint
// exists
pub(crate) const DATA_ALLOCATED_TABLE: SystemTableDefinition<
    TransactionIdWithPagination,
    PageList,
> = SystemTableDefinition::new("data_pages_allocated");
// Pages in the data tree that are in the pending free state: i.e., they are unreachable from the
// root as of the given transaction.
pub(crate) const DATA_FREED_TABLE: SystemTableDefinition<TransactionIdWithPagination, PageList> =
    SystemTableDefinition::new("data_pages_unreachable");
// Pages in the system tree that are in the pending free state: i.e., they are unreachable from the
// root as of the given transaction.
pub(crate) const SYSTEM_FREED_TABLE: SystemTableDefinition<TransactionIdWithPagination, PageList> =
    SystemTableDefinition::new("system_pages_unreachable");
// The allocator state table is stored in the system table tree, but it's accessed using
// raw btree operations rather than open_system_table(), so there's no SystemTableDefinition
pub(crate) const ALLOCATOR_STATE_TABLE_NAME: &str = "allocator_state";
pub(crate) type AllocatorStateTree = Btree<AllocatorStateKey, &'static [u8]>;
pub(crate) type AllocatorStateTreeMut = BtreeMut<AllocatorStateKey, &'static [u8]>;
pub(crate) type SystemFreedTree = BtreeMut<TransactionIdWithPagination, PageList<'static>>;

// Format:
// 2 bytes: length
// length * size_of(PageNumber): array of page numbers
#[derive(Debug)]
pub(crate) struct PageList<'a> {
    data: &'a [u8],
}

#[derive(Clone, Copy)]
pub(crate) enum PageListKind {
    Data,
    System,
}
impl PageListKind {
    pub(crate) const fn capacity(self) -> usize {
        match self {
            Self::Data => 400,
            Self::System => 200,
        }
    }
}

struct ValidatedPageListRange {
    definition: SystemTableDefinition<'static, TransactionIdWithPagination, PageList<'static>>,
    kind: PageListKind,
    free_until: TransactionId,
    root: Option<BtreeHeader>,
}

pub(crate) struct CheckedPageList<'a> {
    data: &'a [u8],
    len: usize,
}
impl<'a> PageList<'a> {
    fn required_bytes(len: usize) -> usize {
        2 + PageNumber::serialized_size() * len
    }

    pub(crate) fn checked(self, kind: PageListKind) -> Result<CheckedPageList<'a>> {
        let capacity = kind.capacity();
        if self.data.len() != Self::required_bytes(capacity) {
            return Err(StorageError::InvalidPageList);
        }
        let len = usize::from(u16::from_le_bytes(self.data[..2].try_into().unwrap()));
        if len == 0 || len > capacity {
            return Err(StorageError::InvalidPageList);
        }
        // The writers reserve a complete fixed-size record but only initialize
        // the used entries. Unused padding is not a second supported format.
        Ok(CheckedPageList {
            data: self.data,
            len,
        })
    }
}
impl CheckedPageList<'_> {
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn get(&self, index: usize) -> PageNumber {
        assert!(index < self.len);
        let start = size_of::<u16>() + PageNumber::serialized_size() * index;
        PageNumber::from_le_bytes(
            self.data[start..(start + PageNumber::serialized_size())]
                .try_into()
                .unwrap(),
        )
    }
}

impl Value for PageList<'_> {
    type SelfType<'a>
        = PageList<'a>
    where
        Self: 'a;
    type AsBytes<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        PageList { data }
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> &'b [u8]
    where
        Self: 'b,
    {
        value.data
    }

    fn type_name() -> TypeName {
        TypeName::internal("redb::PageList")
    }
}

impl MutInPlaceValue for PageList<'_> {
    type BaseRefType = PageListMut;

    fn initialize(data: &mut [u8]) {
        assert!(data.len() >= 8);
        // Set the length to zero
        data[..8].fill(0);
    }

    fn from_bytes_mut(data: &mut [u8]) -> &mut Self::BaseRefType {
        unsafe { &mut *(core::ptr::from_mut::<[u8]>(data) as *mut PageListMut) }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TransactionIdWithPagination {
    pub(crate) transaction_id: u64,
    pub(crate) pagination_id: u64,
}

impl Value for TransactionIdWithPagination {
    type SelfType<'a>
        = TransactionIdWithPagination
    where
        Self: 'a;
    type AsBytes<'a>
        = [u8; 2 * size_of::<u64>()]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        Some(2 * size_of::<u64>())
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self
    where
        Self: 'a,
    {
        let transaction_id = u64::from_le_bytes(data[..size_of::<u64>()].try_into().unwrap());
        let pagination_id = u64::from_le_bytes(data[size_of::<u64>()..].try_into().unwrap());
        Self {
            transaction_id,
            pagination_id,
        }
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> [u8; 2 * size_of::<u64>()]
    where
        Self: 'b,
    {
        let mut result = [0u8; 2 * size_of::<u64>()];
        result[..size_of::<u64>()].copy_from_slice(&value.transaction_id.to_le_bytes());
        result[size_of::<u64>()..].copy_from_slice(&value.pagination_id.to_le_bytes());
        result
    }

    fn type_name() -> TypeName {
        TypeName::internal("redb::TransactionIdWithPagination")
    }
}

impl Key for TransactionIdWithPagination {
    fn compare(data1: &[u8], data2: &[u8]) -> core::cmp::Ordering {
        let value1 = Self::from_bytes(data1);
        let value2 = Self::from_bytes(data2);

        match value1.transaction_id.cmp(&value2.transaction_id) {
            core::cmp::Ordering::Greater => core::cmp::Ordering::Greater,
            core::cmp::Ordering::Equal => value1.pagination_id.cmp(&value2.pagination_id),
            core::cmp::Ordering::Less => core::cmp::Ordering::Less,
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub(crate) enum AllocatorStateKey {
    Deprecated,
    Region(u32),
    RegionTracker,
    TransactionId,
}

impl Value for AllocatorStateKey {
    type SelfType<'a> = Self;
    type AsBytes<'a> = [u8; 1 + size_of::<u32>()];

    fn fixed_width() -> Option<usize> {
        Some(1 + size_of::<u32>())
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        match data[0] {
            // 0, 1, 2 were used in redb 2.x and have a different format
            0..=2 => Self::Deprecated,
            3 => Self::Region(u32::from_le_bytes(data[1..].try_into().unwrap())),
            4 => Self::RegionTracker,
            5 => Self::TransactionId,
            _ => unreachable!(),
        }
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        let mut result = Self::AsBytes::default();
        match value {
            Self::Region(region) => {
                result[0] = 3;
                result[1..].copy_from_slice(&u32::to_le_bytes(*region));
            }
            Self::RegionTracker => {
                result[0] = 4;
            }
            Self::TransactionId => {
                result[0] = 5;
            }
            AllocatorStateKey::Deprecated => {
                result[0] = 0;
            }
        }

        result
    }

    fn type_name() -> TypeName {
        TypeName::internal("redb::AllocatorStateKey")
    }
}

impl Key for AllocatorStateKey {
    fn compare(data1: &[u8], data2: &[u8]) -> core::cmp::Ordering {
        Self::from_bytes(data1).cmp(&Self::from_bytes(data2))
    }
}

pub struct SystemTableDefinition<'a, K: Key + 'static, V: Value + 'static> {
    name: &'a str,
    _key_type: PhantomData<K>,
    _value_type: PhantomData<V>,
}

impl<'a, K: Key + 'static, V: Value + 'static> SystemTableDefinition<'a, K, V> {
    pub const fn new(name: &'a str) -> Self {
        assert!(!name.is_empty());
        Self {
            name,
            _key_type: PhantomData,
            _value_type: PhantomData,
        }
    }
}

impl<K: Key + 'static, V: Value + 'static> TableHandle for SystemTableDefinition<'_, K, V> {
    fn name(&self) -> &str {
        self.name
    }
}

impl<K: Key, V: Value> Sealed for SystemTableDefinition<'_, K, V> {}

impl<K: Key + 'static, V: Value + 'static> Clone for SystemTableDefinition<'_, K, V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: Key + 'static, V: Value + 'static> Copy for SystemTableDefinition<'_, K, V> {}

impl<K: Key + 'static, V: Value + 'static> Display for SystemTableDefinition<'_, K, V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}<{}, {}>",
            self.name,
            K::type_name().name(),
            V::type_name().name()
        )
    }
}

/// Informational storage stats about the database
#[derive(Debug)]
pub struct DatabaseStats {
    pub(crate) tree_height: u32,
    pub(crate) allocated_pages: u64,
    pub(crate) leaf_pages: u64,
    pub(crate) branch_pages: u64,
    pub(crate) stored_leaf_bytes: u64,
    pub(crate) metadata_bytes: u64,
    pub(crate) fragmented_bytes: u64,
    pub(crate) page_size: usize,
}

impl DatabaseStats {
    /// Maximum traversal distance to reach the deepest (key, value) pair, across all tables
    pub fn tree_height(&self) -> u32 {
        self.tree_height
    }

    /// Number of pages allocated
    pub fn allocated_pages(&self) -> u64 {
        self.allocated_pages
    }

    /// Number of leaf pages that store user data
    pub fn leaf_pages(&self) -> u64 {
        self.leaf_pages
    }

    /// Number of branch pages in btrees that store user data
    pub fn branch_pages(&self) -> u64 {
        self.branch_pages
    }

    /// Number of bytes consumed by keys and values that have been inserted.
    /// Does not include indexing overhead
    pub fn stored_bytes(&self) -> u64 {
        self.stored_leaf_bytes
    }

    /// Number of bytes consumed by keys in internal branch pages, plus other metadata
    pub fn metadata_bytes(&self) -> u64 {
        self.metadata_bytes
    }

    /// Number of bytes consumed by fragmentation, both in data pages and internal metadata tables
    pub fn fragmented_bytes(&self) -> u64 {
        self.fragmented_bytes
    }

    /// Number of bytes per page
    pub fn page_size(&self) -> usize {
        self.page_size
    }
}

// Like a Table but only one may be open at a time to avoid possible races
pub struct SystemTable<'s, K: Key + 'static, V: Value + 'static> {
    name: String,
    namespace: &'s mut SystemNamespace,
    tree: BtreeMut<K, V>,
    transaction_guard: Arc<TransactionGuard>,
}

impl<'s, K: Key + 'static, V: Value + 'static> SystemTable<'s, K, V> {
    fn new(
        name: &str,
        table_root: Option<BtreeHeader>,
        freed_pages: Arc<Mutex<Vec<PageNumber>>>,
        guard: Arc<TransactionGuard>,
        page_allocator: PageAllocator,
        namespace: &'s mut SystemNamespace,
    ) -> SystemTable<'s, K, V> {
        // No need to track allocations in the system tree. Savepoint restoration only relies on
        // freeing in the data tree
        let ignore = Arc::new(PageTracker::ignore());
        SystemTable {
            name: name.to_string(),
            namespace,
            tree: BtreeMut::new(
                table_root,
                guard.clone(),
                page_allocator,
                freed_pages,
                ignore,
            ),
            transaction_guard: guard,
        }
    }

    fn get<'a>(&self, key: impl Borrow<K::SelfType<'a>>) -> Result<Option<AccessGuard<'_, V>>>
    where
        K: 'a,
    {
        self.tree.get(key.borrow())
    }

    fn range<'a, KR>(&self, range: impl RangeBounds<KR> + 'a) -> Result<Range<'_, K, V>>
    where
        K: 'a,
        KR: Borrow<K::SelfType<'a>> + 'a,
    {
        self.tree
            .range(&range)
            .map(|x| Range::new(x, self.transaction_guard.clone()))
    }

    pub fn extract_from_if<'a, KR, F: for<'f> FnMut(K::SelfType<'f>, V::SelfType<'f>) -> bool>(
        &mut self,
        range: impl RangeBounds<KR> + 'a,
        predicate: F,
    ) -> Result<ExtractIf<'_, K, V, F>>
    where
        KR: Borrow<K::SelfType<'a>> + 'a,
    {
        self.tree
            .extract_from_if(&range, predicate)
            .map(|inner| ExtractIf::new(inner, None))
    }

    pub fn insert<'k, 'v>(
        &mut self,
        key: impl Borrow<K::SelfType<'k>>,
        value: impl Borrow<V::SelfType<'v>>,
    ) -> Result<Option<AccessGuard<'_, V>>> {
        let value_len = V::as_bytes(value.borrow()).as_ref().len();
        if value_len > MAX_VALUE_LENGTH {
            return Err(StorageError::ValueTooLarge(value_len));
        }
        let key_len = K::as_bytes(key.borrow()).as_ref().len();
        if key_len > MAX_VALUE_LENGTH {
            return Err(StorageError::ValueTooLarge(key_len));
        }
        if value_len + key_len > MAX_PAIR_LENGTH {
            return Err(StorageError::ValueTooLarge(value_len + key_len));
        }
        self.tree.insert(key.borrow(), value.borrow())
    }

    pub fn remove<'a>(
        &mut self,
        key: impl Borrow<K::SelfType<'a>>,
    ) -> Result<Option<AccessGuard<'_, V>>>
    where
        K: 'a,
    {
        self.tree.remove(key.borrow())
    }
}

impl<K: Key + 'static, V: MutInPlaceValue + 'static> SystemTable<'_, K, V> {
    pub fn insert_reserve<'a>(
        &mut self,
        key: impl Borrow<K::SelfType<'a>>,
        value_length: usize,
    ) -> Result<AccessGuardMutInPlace<'_, V>> {
        if value_length > MAX_VALUE_LENGTH {
            return Err(StorageError::ValueTooLarge(value_length));
        }
        let key_len = K::as_bytes(key.borrow()).as_ref().len();
        if key_len > MAX_VALUE_LENGTH {
            return Err(StorageError::ValueTooLarge(key_len));
        }
        if value_length + key_len > MAX_PAIR_LENGTH {
            return Err(StorageError::ValueTooLarge(value_length + key_len));
        }
        self.tree.insert_reserve(key.borrow(), value_length)
    }
}

impl<K: Key + 'static, V: Value + 'static> Drop for SystemTable<'_, K, V> {
    fn drop(&mut self) {
        self.namespace.close_table(
            &self.name,
            &self.tree,
            self.tree.get_root().map(|x| x.length).unwrap_or_default(),
        );
    }
}

impl SystemTable<'_, TransactionIdWithPagination, PageList<'static>> {
    fn validate_page_lists(
        &self,
        range: impl RangeBounds<TransactionIdWithPagination>,
        kind: PageListKind,
    ) -> Result {
        for entry in self.range(range)? {
            let (_, pages) = entry?;
            pages.value().checked(kind)?;
        }
        Ok(())
    }
}

struct SystemNamespace {
    table_tree: TableTreeMut,
    freed_pages: Arc<Mutex<Vec<PageNumber>>>,
    transaction_guard: Arc<TransactionGuard>,
}

impl SystemNamespace {
    fn new(
        root_page: Option<BtreeHeader>,
        guard: Arc<TransactionGuard>,
        page_allocator: PageAllocator,
    ) -> Self {
        // No need to track allocations in the system tree. Savepoint restoration only relies on
        // freeing in the data tree
        let ignore = Arc::new(PageTracker::ignore());
        let freed_pages = Arc::new(Mutex::new(vec![]));
        Self {
            table_tree: TableTreeMut::new(
                root_page,
                guard.clone(),
                page_allocator,
                freed_pages.clone(),
                ignore,
            ),
            freed_pages,
            transaction_guard: guard.clone(),
        }
    }

    fn system_freed_pages(&self) -> Arc<Mutex<Vec<PageNumber>>> {
        self.freed_pages.clone()
    }

    fn open_system_table<'s, K: Key + 'static, V: Value + 'static>(
        &'s mut self,
        transaction: &WriteTransaction,
        definition: SystemTableDefinition<K, V>,
    ) -> Result<SystemTable<'s, K, V>> {
        let (root, _) = self
            .table_tree
            .get_or_create_table::<K, V>(definition.name(), TableType::Normal)
            .map_err(|e| {
                e.into_storage_error_or_corrupted("Internal error. System table is corrupted")
            })?;
        self.table_tree
            .clear_pending_table_update(definition.name());
        transaction.dirty.store(true, Ordering::Release);

        let page_allocator = self.table_tree.page_allocator().clone();
        Ok(SystemTable::new(
            definition.name(),
            root,
            self.freed_pages.clone(),
            self.transaction_guard.clone(),
            page_allocator,
            self,
        ))
    }

    fn get_system_table_root<K: Key + 'static, V: Value + 'static>(
        &self,
        definition: SystemTableDefinition<K, V>,
    ) -> Result<Option<BtreeHeader>> {
        let table = self
            .table_tree
            .get_table::<K, V>(definition.name(), TableType::Normal)
            .map_err(|e| {
                e.into_storage_error_or_corrupted("Internal error. System table is corrupted")
            })?;
        Ok(table.and_then(|definition| match definition {
            InternalTableDefinition::Normal { table_root, .. } => table_root,
            InternalTableDefinition::Multimap { .. } => unreachable!(),
        }))
    }

    fn close_table<K: Key + 'static, V: Value + 'static>(
        &mut self,
        name: &str,
        table: &BtreeMut<K, V>,
        length: u64,
    ) {
        self.table_tree
            .stage_update_table_root(name, table.get_root(), length);
    }
}

struct TableNamespace {
    open_tables: BTreeMap<String, &'static panic::Location<'static>>,
    allocated_pages: Arc<PageTracker>,
    freed_pages: Arc<Mutex<Vec<PageNumber>>>,
    table_tree: TableTreeMut,
}

impl TableNamespace {
    fn new(
        root_page: Option<BtreeHeader>,
        guard: Arc<TransactionGuard>,
        page_allocator: PageAllocator,
    ) -> Self {
        let allocated = Arc::new(PageTracker::new_tracking());
        let freed_pages = Arc::new(Mutex::new(vec![]));
        let table_tree = TableTreeMut::new(
            root_page,
            guard,
            page_allocator,
            // Committed pages which are no longer reachable and will be queued for free'ing
            // These are separated from the system freed pages
            freed_pages.clone(),
            allocated.clone(),
        );
        Self {
            open_tables: BTreeMap::default(),
            table_tree,
            freed_pages,
            allocated_pages: allocated,
        }
    }

    fn set_dirty(&mut self, transaction: &WriteTransaction) {
        transaction.dirty.store(true, Ordering::Release);
        if !transaction.transaction_tracker.any_savepoint_exists() {
            // No savepoints exist, and we don't allow savepoints to be created in a dirty transaction
            // so we can disable allocation tracking now
            self.allocated_pages.disable();
        }
    }

    fn set_root(&mut self, root: Option<BtreeHeader>) {
        assert!(self.open_tables.is_empty());
        self.table_tree.set_root(root);
    }

    #[track_caller]
    fn inner_open<K: Key + 'static, V: Value + 'static>(
        &mut self,
        name: &str,
        table_type: TableType,
    ) -> Result<(Option<BtreeHeader>, u64), TableError> {
        if let Some(location) = self.open_tables.get(name) {
            return Err(TableError::TableAlreadyOpen(name.to_string(), location));
        }

        let root = self
            .table_tree
            .get_or_create_table::<K, V>(name, table_type)?;
        self.table_tree.clear_pending_table_update(name);
        self.open_tables
            .insert(name.to_string(), panic::Location::caller());

        Ok(root)
    }

    #[track_caller]
    pub fn open_multimap_table<'txn, K: Key + 'static, V: Key + 'static>(
        &mut self,
        transaction: &'txn WriteTransaction,
        definition: MultimapTableDefinition<K, V>,
    ) -> Result<MultimapTable<'txn, K, V>, TableError> {
        #[cfg(feature = "logging")]
        debug!("Opening multimap table: {definition}");
        let (root, length) = self.inner_open::<K, V>(definition.name(), TableType::Multimap)?;
        self.set_dirty(transaction);

        Ok(MultimapTable::new(
            definition.name(),
            root,
            length,
            self.freed_pages.clone(),
            self.allocated_pages.clone(),
            self.table_tree.page_allocator().clone(),
            transaction,
        ))
    }

    #[track_caller]
    pub fn open_table<'txn, K: Key + 'static, V: Value + 'static>(
        &mut self,
        transaction: &'txn WriteTransaction,
        definition: TableDefinition<K, V>,
    ) -> Result<Table<'txn, K, V>, TableError> {
        #[cfg(feature = "logging")]
        debug!("Opening table: {definition}");
        let (root, _) = self.inner_open::<K, V>(definition.name(), TableType::Normal)?;
        self.set_dirty(transaction);

        Ok(Table::new(
            definition.name(),
            root,
            self.freed_pages.clone(),
            self.allocated_pages.clone(),
            self.table_tree.page_allocator().clone(),
            transaction,
        ))
    }

    #[track_caller]
    fn inner_rename(
        &mut self,
        name: &str,
        new_name: &str,
        table_type: TableType,
    ) -> Result<(), TableError> {
        if let Some(location) = self.open_tables.get(name) {
            return Err(TableError::TableAlreadyOpen(name.to_string(), location));
        }

        self.table_tree.rename_table(name, new_name, table_type)
    }

    #[track_caller]
    fn rename_table(
        &mut self,
        transaction: &WriteTransaction,
        name: &str,
        new_name: &str,
    ) -> Result<(), TableError> {
        #[cfg(feature = "logging")]
        debug!("Renaming table: {name} to {new_name}");
        self.set_dirty(transaction);
        self.inner_rename(name, new_name, TableType::Normal)
    }

    #[track_caller]
    fn rename_multimap_table(
        &mut self,
        transaction: &WriteTransaction,
        name: &str,
        new_name: &str,
    ) -> Result<(), TableError> {
        #[cfg(feature = "logging")]
        debug!("Renaming multimap table: {name} to {new_name}");
        self.set_dirty(transaction);
        self.inner_rename(name, new_name, TableType::Multimap)
    }

    #[track_caller]
    fn inner_delete(&mut self, name: &str, table_type: TableType) -> Result<bool, TableError> {
        if let Some(location) = self.open_tables.get(name) {
            return Err(TableError::TableAlreadyOpen(name.to_string(), location));
        }

        self.table_tree.delete_table(name, table_type)
    }

    #[track_caller]
    fn delete_table(
        &mut self,
        transaction: &WriteTransaction,
        name: &str,
    ) -> Result<bool, TableError> {
        #[cfg(feature = "logging")]
        debug!("Deleting table: {name}");
        self.set_dirty(transaction);
        self.inner_delete(name, TableType::Normal)
    }

    #[track_caller]
    fn delete_multimap_table(
        &mut self,
        transaction: &WriteTransaction,
        name: &str,
    ) -> Result<bool, TableError> {
        #[cfg(feature = "logging")]
        debug!("Deleting multimap table: {name}");
        self.set_dirty(transaction);
        self.inner_delete(name, TableType::Multimap)
    }

    pub(crate) fn close_table<K: Key + 'static, V: Value + 'static>(
        &mut self,
        name: &str,
        table: &BtreeMut<K, V>,
        length: u64,
    ) {
        self.open_tables.remove(name).unwrap();
        self.table_tree
            .stage_update_table_root(name, table.get_root(), length);
    }

    pub(crate) fn close_table_without_update(&mut self, name: &str) {
        self.open_tables.remove(name).unwrap();
    }
}

// Transaction-local savepoint lifecycle state.
#[derive(Default)]
struct SavepointTransactionState {
    created_persistent: BTreeSet<(SavepointId, TransactionId)>,
    deleted_persistent: Vec<(SavepointId, TransactionId)>,
    invalidated: BTreeSet<SavepointId>,
}

impl SavepointTransactionState {
    fn record_created(&mut self, id: SavepointId, transaction_id: TransactionId) {
        self.created_persistent.insert((id, transaction_id));
    }

    fn record_deleted(&mut self, id: SavepointId, transaction_id: TransactionId) {
        self.deleted_persistent.push((id, transaction_id));
    }

    fn record_invalidated(&mut self, ids: impl IntoIterator<Item = SavepointId>) {
        self.invalidated.extend(ids);
    }

    fn is_invalidated(&self, id: SavepointId) -> bool {
        self.invalidated.contains(&id)
    }

    // Persistent savepoints whose deletion is staged in this transaction. They are still
    // present in the shared tracker until apply_on_commit() runs.
    fn pending_deleted_ids(&self) -> BTreeSet<SavepointId> {
        self.deleted_persistent.iter().map(|(id, _)| *id).collect()
    }

    fn apply_on_commit(&mut self, tracker: &TransactionTracker) {
        // Persistent savepoints whose on-disk entry was deleted: release their
        // tracker refcount now that the deletion is durable.
        for (savepoint, transaction) in self.deleted_persistent.drain(..) {
            tracker.deallocate_savepoint(savepoint, transaction);
        }
        // Savepoints that restore_savepoint() invalidated: remove them from the
        // shared valid_savepoints map. For persistent savepoints,
        // deallocate_savepoint above has already removed them; for ephemeral,
        // the user's Savepoint handle still owns the live_read_transactions
        // refcount and will release it on drop.
        tracker.invalidate_savepoints(core::mem::take(&mut self.invalidated));
        // Persistent savepoints created during this transaction stay live:
        // drop them from our bookkeeping without releasing tracker state.
        self.created_persistent.clear();
    }

    fn apply_on_abort(&mut self, tracker: &TransactionTracker) {
        // Persistent savepoints created during this transaction: their
        // on-disk entries will be rolled back by rollback_uncommitted_writes(),
        // but the shared tracker registration must be released explicitly.
        for (savepoint, transaction) in mem::take(&mut self.created_persistent) {
            tracker.deallocate_savepoint(savepoint, transaction);
        }
        // Deleted-persistent entries will be rolled back on disk, so the
        // tracker state must NOT be released (it is still valid).
        self.deleted_persistent.clear();
        // Invalidations were only staged in this struct and never touched the
        // shared tracker, so dropping them is sufficient.
        self.invalidated.clear();
    }
}

// Discards the in-memory allocator state on drop, unless disarmed. An incomplete commit may
// have returned pages to the allocator that the durable roots still reference through the
// freed tables; such an allocator state must never be used, or persisted by a clean
// shutdown, again.
struct AllocatorStateLatch {
    mem: Option<Arc<TransactionalMemory>>,
}

impl AllocatorStateLatch {
    fn arm(mem: Arc<TransactionalMemory>) -> Self {
        Self { mem: Some(mem) }
    }

    fn disarm(mut self) {
        self.mem = None;
    }
}

impl Drop for AllocatorStateLatch {
    fn drop(&mut self) {
        if let Some(mem) = self.mem.take() {
            mem.invalidate_allocator_state();
        }
    }
}

/// A read/write transaction
///
/// Only a single [`WriteTransaction`] may exist at a time
///
/// A live [`WriteTransaction`] keeps the database open: if the [`Database`](crate::Database) is
/// dropped while this transaction is live, the transaction remains usable and the database
/// closes when the transaction commits, aborts, or is dropped
pub struct WriteTransaction {
    transaction_tracker: Arc<TransactionTracker>,
    mem: Arc<TransactionalMemory>,
    transaction_id: TransactionId,
    tables: Mutex<TableNamespace>,
    system_tables: Mutex<SystemNamespace>,
    completed: bool,
    deferred_reclaim: Vec<PageNumber>,
    user_tables_closed: bool,
    dirty: AtomicBool,
    poisoned: AtomicBool,
    shrink_policy: ShrinkPolicy,
    // All transaction-local savepoint lifecycle state. See
    // `SavepointTransactionState` for the commit/abort contract.
    savepoint_state: Mutex<SavepointTransactionState>,
    // Release the writer only after table/savepoint and deferred-page backing.
    transaction_guard: Arc<TransactionGuard>,
}

impl WriteTransaction {
    pub(crate) fn new(
        guard: TransactionGuard,
        transaction_tracker: Arc<TransactionTracker>,
        mem: Arc<TransactionalMemory>,
        allocation_policy: AllocationPolicy,
    ) -> Result<Self> {
        let transaction_id = guard.id();
        let guard = Arc::new(guard);

        let root_page = mem.get_data_root();
        let system_page = mem.get_system_root();

        let page_allocator = PageAllocator::new(mem.clone(), allocation_policy);
        let tables = TableNamespace::new(root_page, guard.clone(), page_allocator.clone());
        let system_tables = SystemNamespace::new(system_page, guard.clone(), page_allocator);
        let tables = Mutex::new(tables);
        let system_tables = Mutex::new(system_tables);
        drop(tables.lock().unwrap());
        drop(system_tables.lock().unwrap());
        let savepoint_state = Mutex::new(SavepointTransactionState::default());
        // Some platforms lazily allocate the native mutex on its first lock.
        drop(savepoint_state.lock().unwrap());

        Ok(Self {
            transaction_tracker,
            mem: mem.clone(),
            transaction_guard: guard.clone(),
            transaction_id,
            tables,
            system_tables,
            completed: false,
            deferred_reclaim: Vec::new(),
            user_tables_closed: false,
            dirty: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            shrink_policy: ShrinkPolicy::Default,
            savepoint_state,
        })
    }

    // Repair recomputes root lengths without publishing a partially prepared
    // header. Its roots then use the normal admitted commit protocol.
    pub(crate) fn set_repaired_roots(&mut self, roots: [Option<BtreeHeader>; 2]) {
        self.tables.lock().unwrap().table_tree.set_root(roots[0]);
        self.system_tables
            .lock()
            .unwrap()
            .table_tree
            .set_root(roots[1]);
    }

    pub(crate) fn set_shrink_policy(&mut self, shrink_policy: ShrinkPolicy) {
        self.shrink_policy = shrink_policy;
    }

    pub(crate) fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    // A PageAllocator for this transaction. All clones share the same
    // allocated-since-commit set so they agree on which pages this
    // transaction has allocated.
    fn page_allocator(&self) -> PageAllocator {
        self.tables
            .lock()
            .unwrap()
            .table_tree
            .page_allocator()
            .clone()
    }

    fn read_existing_system_table<K: Key + 'static, V: Value + 'static, T>(
        &self,
        definition: SystemTableDefinition<K, V>,
        read: impl FnOnce(&Btree<K, V>) -> Result<T>,
    ) -> Result<Option<T>> {
        let system_tables = self.system_tables.lock().unwrap();
        let Some(root) = system_tables.get_system_table_root(definition)? else {
            return Ok(None);
        };
        let table = Btree::new(
            Some(root),
            PageHint::None,
            self.transaction_guard.clone(),
            PageResolver::new(self.mem.clone()),
        )?;
        read(&table).map(Some)
    }

    #[cfg(all(debug_assertions, not(redb_no_std)))]
    pub fn print_allocated_page_debug(&self) {
        let mut all_allocated = PageNumberHashSet::from_iter(self.mem.all_allocated_pages());

        self.mem.debug_check_allocator_consistency();

        let mut table_pages = vec![];
        self.tables
            .lock()
            .unwrap()
            .table_tree
            .visit_all_pages(|path| {
                table_pages.push(path.page_number());
                Ok(())
            })
            .unwrap();
        println!("Tables");
        for p in table_pages {
            assert!(all_allocated.remove(&p));
            println!("{p:?}");
        }

        let mut system_table_pages = vec![];
        self.system_tables
            .lock()
            .unwrap()
            .table_tree
            .visit_all_pages(|path| {
                system_table_pages.push(path.page_number());
                Ok(())
            })
            .unwrap();
        println!("System tables");
        for p in system_table_pages {
            assert!(all_allocated.remove(&p));
            println!("{p:?}");
        }

        {
            println!("Pending free (in data freed table)");
            let mut system_tables = self.system_tables.lock().unwrap();
            let data_freed = system_tables
                .open_system_table(self, DATA_FREED_TABLE)
                .unwrap();
            for entry in data_freed.range::<TransactionIdWithPagination>(..).unwrap() {
                let (_, entry) = entry.unwrap();
                let value = entry.value().checked(PageListKind::Data).unwrap();
                for i in 0..value.len() {
                    let p = value.get(i);
                    assert!(all_allocated.remove(&p));
                    println!("{p:?}");
                }
            }
        }
        {
            println!("Pending free (in system freed table)");
            let mut system_tables = self.system_tables.lock().unwrap();
            let system_freed = system_tables
                .open_system_table(self, SYSTEM_FREED_TABLE)
                .unwrap();
            for entry in system_freed
                .range::<TransactionIdWithPagination>(..)
                .unwrap()
            {
                let (_, entry) = entry.unwrap();
                let value = entry.value().checked(PageListKind::System).unwrap();
                for i in 0..value.len() {
                    let p = value.get(i);
                    assert!(all_allocated.remove(&p));
                    println!("{p:?}");
                }
            }
        }
        {
            let tables = self.tables.lock().unwrap();
            let pages = tables.freed_pages.lock().unwrap();
            if !pages.is_empty() {
                println!("Pages in in-memory data freed_pages");
                for p in pages.iter() {
                    println!("{p:?}");
                    assert!(all_allocated.remove(p));
                }
            }
        }
        {
            let system_tables = self.system_tables.lock().unwrap();
            let pages = system_tables.freed_pages.lock().unwrap();
            if !pages.is_empty() {
                println!("Pages in in-memory system freed_pages");
                for p in pages.iter() {
                    println!("{p:?}");
                    assert!(all_allocated.remove(p));
                }
            }
        }
        if !all_allocated.is_empty() {
            println!("Leaked pages");
            for p in all_allocated {
                println!("{p:?}");
            }
        }
    }

    /// Creates a snapshot of the current database state, which can be used to rollback the database.
    /// This savepoint will exist until it is deleted with `[delete_savepoint()]`.
    ///
    /// Note that while a savepoint exists, pages that become unused after it was created are not freed.
    /// Therefore, the lifetime of a savepoint should be minimized.
    ///
    /// Returns `[SavepointError::InvalidSavepoint`], if the transaction is "dirty" (any tables have been opened),
    pub fn persistent_savepoint(&self) -> Result<u64, SavepointError> {
        let mut savepoint = self.ephemeral_savepoint()?;

        let mut system_tables = self.system_tables.lock().unwrap();

        let mut next_table = system_tables.open_system_table(self, NEXT_SAVEPOINT_TABLE)?;
        next_table.insert((), savepoint.get_id().next())?;
        drop(next_table);

        let mut savepoint_table = system_tables.open_system_table(self, SAVEPOINT_TABLE)?;
        savepoint_table.insert(
            savepoint.get_id(),
            SerializedSavepoint::from_savepoint(&savepoint),
        )?;

        savepoint.set_persistent();
        self.transaction_tracker
            .mark_savepoint_persistent(savepoint.get_id());

        self.savepoint_state
            .lock()
            .unwrap()
            .record_created(savepoint.get_id(), savepoint.get_transaction_id());

        Ok(savepoint.get_id().0)
    }

    pub(crate) fn transaction_guard(&self) -> Arc<TransactionGuard> {
        self.transaction_guard.clone()
    }

    pub(crate) fn next_persistent_savepoint_id(&self) -> Result<Option<SavepointId>> {
        let Some(value) = self.read_existing_system_table(NEXT_SAVEPOINT_TABLE, |next_table| {
            let value = next_table.get(&())?;
            Ok(value.map(|next_id| next_id.value()))
        })?
        else {
            return Ok(None);
        };
        Ok(value)
    }

    /// Get a persistent savepoint given its id
    pub fn get_persistent_savepoint(&self, id: u64) -> Result<Savepoint, SavepointError> {
        let Some(value) = self.read_existing_system_table(SAVEPOINT_TABLE, |table| {
            let value = table.get(&SavepointId(id))?;
            value
                .map(|x| x.value().to_savepoint(self.transaction_tracker.clone()))
                .transpose()
        })?
        else {
            return Err(SavepointError::InvalidSavepoint);
        };
        value.ok_or(SavepointError::InvalidSavepoint)
    }

    /// Delete the given persistent savepoint.
    ///
    /// Note that if the transaction is `abort()`'ed this deletion will be rolled back.
    ///
    /// Returns `true` if the savepoint existed
    pub fn delete_persistent_savepoint(&self, id: u64) -> Result<bool, SavepointError> {
        let mut system_tables = self.system_tables.lock().unwrap();
        if system_tables
            .get_system_table_root(SAVEPOINT_TABLE)?
            .is_none()
        {
            return Ok(false);
        }
        let mut table = system_tables.open_system_table(self, SAVEPOINT_TABLE)?;
        // Parse before removing, so that a corrupted record errors out without staging any change
        let savepoint = if let Some(serialized) = table.get(SavepointId(id))? {
            serialized
                .value()
                .to_savepoint(self.transaction_tracker.clone())?
        } else {
            return Ok(false);
        };
        table.remove(SavepointId(id))?;
        self.savepoint_state
            .lock()
            .unwrap()
            .record_deleted(savepoint.get_id(), savepoint.get_transaction_id());
        Ok(true)
    }

    /// List all persistent savepoints
    pub fn list_persistent_savepoints(&self) -> Result<impl Iterator<Item = u64>> {
        let Some(savepoints) = self.read_existing_system_table(SAVEPOINT_TABLE, |table| {
            let mut savepoints = vec![];
            for savepoint in table.range::<RangeFull, SavepointId>(&..)? {
                savepoints.push(savepoint?.key().0);
            }
            Ok(savepoints)
        })?
        else {
            return Ok(vec![].into_iter());
        };
        Ok(savepoints.into_iter())
    }

    fn allocate_savepoint(&self) -> Result<(SavepointId, TransactionId)> {
        let transaction_id = self
            .transaction_tracker
            .register_read_transaction(&self.mem)?;
        let id = self.transaction_tracker.allocate_savepoint(transaction_id);
        Ok((id, transaction_id))
    }

    /// Creates a snapshot of the current database state, which can be used to rollback the database
    ///
    /// This savepoint will be freed as soon as the returned `[Savepoint]` is dropped.
    ///
    /// Returns `[SavepointError::InvalidSavepoint`], if the transaction is "dirty" (any tables have been opened)
    pub fn ephemeral_savepoint(&self) -> Result<Savepoint, SavepointError> {
        // Serialize the dirty check and savepoint registration against
        // `TableNamespace::set_dirty()`, which runs under the same tables lock. Without this,
        // a concurrent first table-open (legal since `WriteTransaction: Sync`) can read the
        // dirty flag and `any_savepoint_exists()` in between, observe no savepoint, and disable
        // allocation tracking -- leaving a live savepoint with tracking `Ignore`d. A later
        // `restore_savepoint()` would then fail to free this transaction's pages, leaking them
        // (reclaimed only by a full repair).
        let (id, transaction_id) = {
            let _tables = self.tables.lock().unwrap();
            if self.dirty.load(Ordering::Acquire) {
                return Err(SavepointError::InvalidSavepoint);
            }
            self.allocate_savepoint()?
        };
        #[cfg(feature = "logging")]
        debug!("Creating savepoint id={id:?}, txn_id={transaction_id:?}");

        let root = self.mem.get_data_root();
        let savepoint = Savepoint::new_ephemeral(
            &self.mem,
            self.transaction_tracker.clone(),
            id,
            transaction_id,
            root,
        );

        Ok(savepoint)
    }

    /// Restore the state of the database to the given [`Savepoint`]
    ///
    /// Calling this method invalidates all [`Savepoint`]s created after savepoint
    pub fn restore_savepoint(&mut self, savepoint: &Savepoint) -> Result<(), SavepointError> {
        // Reject a Savepoint that is from a different Database
        if core::ptr::from_ref(self.transaction_tracker.as_ref()) != savepoint.db_address() {
            return Err(SavepointError::InvalidSavepoint);
        }

        if !self
            .transaction_tracker
            .is_valid_savepoint(savepoint.get_id())
            || self
                .savepoint_state
                .lock()
                .unwrap()
                .is_invalidated(savepoint.get_id())
        {
            return Err(SavepointError::InvalidSavepoint);
        }

        #[cfg(feature = "logging")]
        debug!(
            "Beginning savepoint restore (id={:?}) in transaction id={:?}",
            savepoint.get_id(),
            self.transaction_id
        );
        // Restoring a savepoint that reverted a file format or checksum type change could corrupt
        // the database
        assert_eq!(self.mem.get_version(), savepoint.get_version());
        self.dirty.store(true, Ordering::Release);

        // Restoring a savepoint needs to accomplish the following:
        // 1) restore the table tree. This is trivial, since we have the old root
        // 1a) we also filter the freed tree to remove any pages referenced by the old root
        // 2) free all pages that were allocated since the savepoint and are unreachable
        //    from the restored table tree root. Here we diff the reachable pages from the old
        //    and new roots
        // 3) update the system tree to remove invalid persistent savepoints.

        // 1) restore the table tree
        {
            self.tables
                .lock()
                .unwrap()
                .set_root(savepoint.get_user_root());
        }

        // 1a) purge all transactions that happened after the savepoint from the data freed tree
        let txn_id = savepoint.get_transaction_id().next().raw_id();
        {
            let lower = TransactionIdWithPagination {
                transaction_id: txn_id,
                pagination_id: 0,
            };
            let mut system_tables = self.system_tables.lock().unwrap();
            let mut data_freed = system_tables.open_system_table(self, DATA_FREED_TABLE)?;
            let mut drain = || -> Result<(), StorageError> {
                data_freed.validate_page_lists(lower.., PageListKind::Data)?;
                let mut iter = data_freed.extract_from_if(lower.., |_, _| true)?;
                for entry in &mut iter {
                    entry?;
                }
                // Defensive: exhaustion has already closed the iterator and
                // surfaced any finalization error through the loop; this only
                // keeps errors from being swallowed if the loop ever gains an
                // early exit.
                iter.close()
            };
            let result = drain();
            if result.is_err() {
                // The table tree root was already restored above, so a partial
                // purge must not be committed. System-table extract iterators
                // carry no poison target, so poison the transaction directly.
                self.poison();
            }
            result?;
            // No need to process the system freed table, because it only rolls forward
        }

        // 2) queue all pages that became unreachable
        {
            let tables = self.tables.lock().unwrap();
            let page_allocator = tables.table_tree.page_allocator();
            for page in tables.allocated_pages.reset() {
                debug_assert!(page_allocator.uncommitted(page));
                debug_assert!(self.mem.is_allocated(page));
                page_allocator.free(page, &PageTracker::ignore());
            }
            let mut data_freed_pages = tables.freed_pages.lock().unwrap();
            data_freed_pages.clear();
            let mut system_tables = self.system_tables.lock().unwrap();
            let data_allocated = system_tables.open_system_table(self, DATA_ALLOCATED_TABLE)?;
            let lower = TransactionIdWithPagination {
                transaction_id: txn_id,
                pagination_id: 0,
            };
            for entry in data_allocated.range(lower..)? {
                let (_, value) = entry?;
                let pages = value.value().checked(PageListKind::Data)?;
                for i in 0..pages.len() {
                    data_freed_pages.push(pages.get(i));
                }
            }
            // These are tracked in memory rather than in DATA_ALLOCATED_TABLE. We don't remove
            // them from the map here: if this transaction aborts, the in-memory map must still
            // reflect the full history. durable_commit() will empty the map.
        }

        // 3) Mark all savepoints newer than the restored one as invalidated for this
        // transaction, to prevent the user from later trying to restore a savepoint
        // "on another timeline". The invalidation is purely per-transaction state -
        // the shared `valid_savepoints` map is only updated if/when commit_inner()
        // runs, so an abort implicitly reverts the invalidation by dropping this set.
        let invalidated = self
            .transaction_tracker
            .list_savepoints_after(savepoint.get_id());
        self.savepoint_state
            .lock()
            .unwrap()
            .record_invalidated(invalidated);
        for persistent_savepoint in self.list_persistent_savepoints()? {
            if persistent_savepoint > savepoint.get_id().0 {
                self.delete_persistent_savepoint(persistent_savepoint)?;
            }
        }

        Ok(())
    }

    /// Open the given table
    ///
    /// The table will be created if it does not exist
    #[track_caller]
    pub fn open_table<'txn, K: Key + 'static, V: Value + 'static>(
        &'txn self,
        definition: TableDefinition<K, V>,
    ) -> Result<Table<'txn, K, V>, TableError> {
        self.tables.lock().unwrap().open_table(self, definition)
    }

    /// Open the given table
    ///
    /// The table will be created if it does not exist
    #[track_caller]
    pub fn open_multimap_table<'txn, K: Key + 'static, V: Key + 'static>(
        &'txn self,
        definition: MultimapTableDefinition<K, V>,
    ) -> Result<MultimapTable<'txn, K, V>, TableError> {
        self.tables
            .lock()
            .unwrap()
            .open_multimap_table(self, definition)
    }

    pub(crate) fn close_table<K: Key + 'static, V: Value + 'static>(
        &self,
        name: &str,
        table: &BtreeMut<K, V>,
        length: u64,
    ) {
        let mut tables = self.tables.lock().unwrap();
        if self.is_poisoned() {
            tables.close_table_without_update(name);
        } else {
            tables.close_table(name, table, length);
        }
    }

    /// Rename the given table
    pub fn rename_table(
        &self,
        definition: impl TableHandle,
        new_name: impl TableHandle,
    ) -> Result<(), TableError> {
        let name = definition.name().to_string();
        // Drop the definition so that callers can pass in a `Table` to rename, without getting a TableAlreadyOpen error
        drop(definition);
        self.tables
            .lock()
            .unwrap()
            .rename_table(self, &name, new_name.name())
    }

    /// Rename the given multimap table
    pub fn rename_multimap_table(
        &self,
        definition: impl MultimapTableHandle,
        new_name: impl MultimapTableHandle,
    ) -> Result<(), TableError> {
        let name = definition.name().to_string();
        // Drop the definition so that callers can pass in a `MultimapTable` to rename, without getting a TableAlreadyOpen error
        drop(definition);
        self.tables
            .lock()
            .unwrap()
            .rename_multimap_table(self, &name, new_name.name())
    }

    /// Delete the given table
    ///
    /// Returns a bool indicating whether the table existed
    pub fn delete_table(&self, definition: impl TableHandle) -> Result<bool, TableError> {
        let name = definition.name().to_string();
        // Drop the definition so that callers can pass in a `Table` or `MultimapTable` to delete, without getting a TableAlreadyOpen error
        drop(definition);
        self.tables.lock().unwrap().delete_table(self, &name)
    }

    /// Delete the given table
    ///
    /// Returns a bool indicating whether the table existed
    pub fn delete_multimap_table(
        &self,
        definition: impl MultimapTableHandle,
    ) -> Result<bool, TableError> {
        let name = definition.name().to_string();
        // Drop the definition so that callers can pass in a `Table` or `MultimapTable` to delete, without getting a TableAlreadyOpen error
        drop(definition);
        self.tables
            .lock()
            .unwrap()
            .delete_multimap_table(self, &name)
    }

    /// List all the tables
    pub fn list_tables(&self) -> Result<impl Iterator<Item = UntypedTableHandle> + '_> {
        self.tables
            .lock()
            .unwrap()
            .table_tree
            .list_tables(TableType::Normal)
            .map(|x| x.into_iter().map(UntypedTableHandle::new))
    }

    /// List all the multimap tables
    pub fn list_multimap_tables(
        &self,
    ) -> Result<impl Iterator<Item = UntypedMultimapTableHandle> + '_> {
        self.tables
            .lock()
            .unwrap()
            .table_tree
            .list_tables(TableType::Multimap)
            .map(|x| x.into_iter().map(UntypedMultimapTableHandle::new))
    }

    /// Commit the transaction
    ///
    /// All writes performed in this transaction will be visible to future transactions, and are
    /// immediately durable with payload and repair metadata prepared before publication.
    ///
    /// Returns [`CommitError::TransactionPoisoned`] if a previous operation panicked and left the
    /// transaction unable to commit. In that case the transaction is rolled back and the database
    /// remains usable.
    ///
    /// [`StorageError::CapacityDenied`] means preparation was refused before publication.
    /// The whole transaction is rolled back, retained extents stay charged, and the owner
    /// remains usable unless rollback encounters a physical failure.
    ///
    /// On other errors the commit did not complete cleanly: the transaction's changes are
    /// applied atomically -- fully or not at all -- but may already have become durable, so they
    /// must not be assumed rolled back. The database refuses further write transactions; closing
    /// and reopening it repairs any internal state left by the failed commit.
    pub fn commit(mut self) -> Result<(), CommitError> {
        // Set completed flag first, so that we don't go through the abort() path on drop, if this fails
        self.completed = true;
        if let Some(error) = self.mem.capacity_error() {
            self.abort_inner()?;
            return Err(error.into());
        }
        if self.is_poisoned() {
            self.abort_inner()?;
            return Err(CommitError::TransactionPoisoned);
        }
        self.commit_inner()
    }

    fn commit_inner(&mut self) -> Result<(), CommitError> {
        // Covers both the error and the panic-unwind path. Without an allocator state,
        // begin_write() refuses new write transactions and the next open repairs.
        let latch = AllocatorStateLatch::arm(self.mem.clone());
        let result = self.commit_inner_helper();
        if matches!(
            result,
            Err(CommitError::Storage(
                StorageError::CapacityDenied | StorageError::CacheCapacityDenied
            ))
        ) {
            // Preparation never releases committed pages, and has not published
            // a winner. All newly allocated user/system pages still belong to
            // this transaction's shared allocator and can be rolled back.
            self.abort_inner()?;
            latch.disarm();
        } else if result.is_ok() {
            latch.disarm();
        }
        result
    }

    fn commit_inner_helper(&mut self) -> Result<(), CommitError> {
        self.user_tables_closed = true;
        let (user_root, allocated_pages, data_freed) =
            self.tables.lock().unwrap().table_tree.flush_and_close()?;

        self.store_data_freed_pages(data_freed)?;
        let allocated_pages: Vec<PageNumber> = allocated_pages.into_iter().collect();
        self.durable_commit(user_root, allocated_pages)?;

        assert!(
            self.system_tables
                .lock()
                .unwrap()
                .system_freed_pages()
                .lock()
                .unwrap()
                .is_empty()
        );
        assert!(
            self.tables
                .lock()
                .unwrap()
                .freed_pages
                .lock()
                .unwrap()
                .is_empty()
        );

        Ok(())
    }

    fn apply_savepoint_state_on_commit(&self) {
        self.savepoint_state
            .lock()
            .unwrap()
            .apply_on_commit(&self.transaction_tracker);
    }

    fn store_data_freed_pages(&self, freed_pages: Vec<PageNumber>) -> Result<bool> {
        let stored_pages = !freed_pages.is_empty();
        // Open the table even when there is nothing to store: creating it lazily later would put
        // its metadata pages outside the baseline state that the initial cleanup commit captures.
        self.store_data_freed_pages_for(self.transaction_id, freed_pages)?;
        Ok(stored_pages)
    }

    fn store_data_freed_pages_for(
        &self,
        transaction_id: TransactionId,
        mut freed_pages: Vec<PageNumber>,
    ) -> Result {
        let mut system_tables = self.system_tables.lock().unwrap();
        let mut freed_table = system_tables.open_system_table(self, DATA_FREED_TABLE)?;
        let mut pagination_counter = 0;
        #[cfg(debug_assertions)]
        let page_allocator = self.page_allocator();
        while !freed_pages.is_empty() {
            let chunk_size = PageListKind::Data.capacity();
            let buffer_size = PageList::required_bytes(chunk_size);
            let key = TransactionIdWithPagination {
                transaction_id: transaction_id.raw_id(),
                pagination_id: pagination_counter,
            };
            let mut access_guard = freed_table.insert_reserve(&key, buffer_size)?;

            let len = freed_pages.len();
            access_guard.as_mut().clear();
            for page in freed_pages.drain(len - min(len, chunk_size)..) {
                // Make sure that the page is currently allocated
                debug_assert!(
                    self.mem.is_allocated(page),
                    "Page is not allocated: {page:?}"
                );
                #[cfg(debug_assertions)]
                debug_assert!(
                    !page_allocator.uncommitted(page),
                    "Page is uncommitted: {page:?}"
                );
                access_guard.as_mut().push_back(page);
            }

            pagination_counter += 1;
        }

        Ok(())
    }

    // Keep allocation records only while a surviving savepoint can use them.
    // Deferred reclamation is represented in the prepared allocator snapshot.
    fn flush_data_allocated_pages(&self, data_allocated_pages: Vec<PageNumber>) -> Result<u64> {
        // Catch scenarios like a page getting allocated and then deallocated within the same
        // transaction, but errantly left in the allocated pages list.
        #[cfg(debug_assertions)]
        {
            let page_allocator = self.page_allocator();
            for page in &data_allocated_pages {
                debug_assert!(
                    self.mem.is_allocated(*page),
                    "Page is not allocated: {page:?}"
                );
                debug_assert!(
                    page_allocator.uncommitted(*page),
                    "Page is committed: {page:?}"
                );
            }
        }

        let mut system_tables = self.system_tables.lock().unwrap();
        let mut allocated_table = system_tables.open_system_table(self, DATA_ALLOCATED_TABLE)?;
        Self::write_allocated_pages_entry(
            &mut allocated_table,
            self.transaction_id,
            data_allocated_pages,
        )?;

        // Purge any transactions that are no longer referenced. The horizon must reflect the
        // savepoints that will exist after this commit: savepoints deleted in this transaction
        // are still in the tracker (they are removed post-commit), but the pages they pinned
        // may be reclaimed after publication, and DATA_ALLOCATED_TABLE must never name a
        // page that is no longer allocated.
        let deleted_savepoints = self.savepoint_state.lock().unwrap().pending_deleted_ids();
        let oldest = self
            .transaction_tracker
            .oldest_savepoint_excluding(&deleted_savepoints)
            .map_or(u64::MAX, |(_, x)| x.raw_id());
        let key = TransactionIdWithPagination {
            transaction_id: oldest,
            pagination_id: 0,
        };
        allocated_table.validate_page_lists(..key, PageListKind::Data)?;
        let mut iter = allocated_table.extract_from_if(..key, |_, _| true)?;
        let result = (|| {
            for entry in &mut iter {
                entry?;
            }
            Ok(())
        })();
        self.finish_page_list_extraction(iter, result)?;

        Ok(oldest)
    }

    fn write_allocated_pages_entry(
        allocated_table: &mut SystemTable<'_, TransactionIdWithPagination, PageList<'static>>,
        transaction_id: TransactionId,
        mut pages: Vec<PageNumber>,
    ) -> Result {
        let mut pagination_counter = 0;
        while !pages.is_empty() {
            let chunk_size = PageListKind::Data.capacity();
            let buffer_size = PageList::required_bytes(chunk_size);
            let key = TransactionIdWithPagination {
                transaction_id: transaction_id.raw_id(),
                pagination_id: pagination_counter,
            };
            let mut access_guard = allocated_table.insert_reserve(&key, buffer_size)?;

            let len = pages.len();
            access_guard.as_mut().clear();
            for page in pages.drain(len - min(len, chunk_size)..) {
                access_guard.as_mut().push_back(page);
            }

            pagination_counter += 1;
        }
        Ok(())
    }

    /// Abort the transaction
    ///
    /// All writes performed in this transaction will be rolled back
    pub fn abort(mut self) -> Result {
        // Set completed flag first, so that we don't go through the abort() path on drop, if this fails
        self.completed = true;
        self.abort_inner()
    }

    fn abort_inner(&mut self) -> Result {
        let mut tables = self.tables.lock().unwrap();
        if self.user_tables_closed {
            tables.table_tree.discard_root_updates();
        } else {
            tables.table_tree.clear_root_updates_and_close();
            self.user_tables_closed = true;
        }
        drop(tables);
        // Release all transaction-local savepoint state. The on-disk mutations
        // (SAVEPOINT_TABLE / NEXT_SAVEPOINT_TABLE) are reverted by the
        // `PageAllocator::rollback_all` call below; `apply_on_abort` handles
        // the in-memory `TransactionTracker` state that rollback cannot see.
        self.savepoint_state
            .lock()
            .unwrap()
            .apply_on_abort(&self.transaction_tracker);
        self.mem.check_io_errors()?;
        self.page_allocator().rollback_all();
        self.deferred_reclaim.clear();
        self.mem.settle_growth()?;
        Ok(())
    }

    pub(crate) fn durable_commit(
        &mut self,
        user_root: Option<BtreeHeader>,
        allocated_pages: Vec<PageNumber>,
    ) -> Result {
        let free_until_transaction = self
            .transaction_tracker
            .oldest_live_read_transaction()
            .map_or(self.transaction_id, |x| x.next());
        self.process_freed_pages(free_until_transaction)?;
        // Prepare allocation records before constructing the repair snapshot.
        self.flush_data_allocated_pages(allocated_pages)?;

        let mut system_tables = self.system_tables.lock().unwrap();
        let system_freed_pages = system_tables.system_freed_pages();
        let system_root = {
            let system_tree = system_tables.table_tree.flush_table_root_updates()?;
            system_tree
                .delete_table(ALLOCATOR_STATE_TABLE_NAME, TableType::Normal)
                .map_err(|e| e.into_storage_error_or_corrupted("Unexpected TableError"))?;

            {
                system_tree.create_table_and_flush_table_root(
                    ALLOCATOR_STATE_TABLE_NAME,
                    |system_tree_ref, tree: &mut AllocatorStateTreeMut| {
                        loop {
                            let num_regions = self
                                .mem
                                .reserve_allocator_state(tree, self.transaction_id)?;

                            // The allocator snapshot must match the committed system root. Pages
                            // freed while building that root stay allocated in the snapshot and are
                            // recorded in SYSTEM_FREED_TABLE before the allocator state is saved.
                            Self::store_system_freed_pages(
                                system_tree_ref,
                                self.transaction_id,
                                system_freed_pages.clone(),
                            )?;

                            if self.mem.try_save_allocator_state(
                                tree,
                                num_regions,
                                &self.deferred_reclaim,
                            )? {
                                return Ok(());
                            }

                            // Clear out the table before retrying, just in case the number of regions
                            // has somehow shrunk. Don't use retain_in() for this, since it doesn't
                            // free the pages immediately -- we need to reuse those pages to guarantee
                            // that our retry loop will eventually terminate
                            while let Some(guards) = tree.last()? {
                                let key = guards.0.value();
                                drop(guards);
                                tree.remove(&key)?;
                            }
                        }
                    },
                )?;
            }

            system_tree.finalize_dirty_checksums()?
        };

        let page_allocator = self.page_allocator();
        self.mem.commit(
            user_root,
            system_root,
            self.transaction_id,
            self.shrink_policy,
        )?;
        for page in self.deferred_reclaim.drain(..) {
            page_allocator.free(page, &PageTracker::ignore());
        }
        // All of this transaction's allocations are durable; discard the per-txn tracker.
        page_allocator.discard_committed_allocations();

        // Immediately free the pages that were freed from the system-tree. These are only
        // accessed by write transactions, so it's safe to free them as soon as the commit is done.
        for page in system_freed_pages.lock().unwrap().drain(..) {
            page_allocator.free(page, &PageTracker::ignore());
        }

        drop(system_tables);

        self.apply_savepoint_state_on_commit();

        Ok(())
    }

    // Relocate pages to lower number regions/pages
    // Returns true if a page(s) was moved
    pub(crate) fn compact_pages(
        &mut self,
        max_relocation_bytes: core::num::NonZeroUsize,
    ) -> Result<bool> {
        let mut bytes_remaining = max_relocation_bytes.get() as u64;
        let mut progress = false;

        // Retain a small, fixed number of candidate paths.
        let mut highest_pages = BTreeMap::new();
        let mut tables = self.tables.lock().unwrap();
        let table_tree = &mut tables.table_tree;
        table_tree.highest_index_pages(MAX_PAGES_PER_COMPACTION, &mut highest_pages)?;
        let mut system_tables = self.system_tables.lock().unwrap();
        let system_table_tree = &mut system_tables.table_tree;
        system_table_tree.highest_index_pages(MAX_PAGES_PER_COMPACTION, &mut highest_pages)?;

        let page_allocator = table_tree.page_allocator().clone();

        // Calculate how many of them can be relocated to lower pages, starting from the last page
        let mut relocation_map = PageNumberHashMap::default();
        for path in highest_pages.into_values().rev() {
            if relocation_map.contains_key(&path.page_number()) {
                continue;
            }
            let mut required_bytes = path
                .page_number()
                .page_size_bytes(self.mem.get_page_size().try_into().unwrap());
            for parent in path.parents() {
                if !relocation_map.contains_key(parent) {
                    required_bytes = required_bytes.saturating_add(
                        parent.page_size_bytes(self.mem.get_page_size().try_into().unwrap()),
                    );
                }
            }
            // Reserve the old and new page buffers together before either is read.
            required_bytes = required_bytes.saturating_mul(2);
            if required_bytes > bytes_remaining {
                continue;
            }
            bytes_remaining -= required_bytes;
            let old_page = page_allocator.get_page(path.page_number(), PageHint::None)?;
            let mut new_page =
                page_allocator.allocate_lowest(old_page.memory().len(), &PageTracker::ignore())?;
            let new_page_number = new_page.get_page_number();
            // We have to copy at least the page type into the new page.
            // Otherwise its cache priority will be calculated incorrectly
            new_page.memory_mut()[0] = old_page.memory()[0];
            drop(new_page);
            // We're able to move this to a lower page, so insert it and rewrite all its parents
            if new_page_number < path.page_number() {
                relocation_map.insert(path.page_number(), new_page_number);
                for parent in path.parents() {
                    if relocation_map.contains_key(parent) {
                        continue;
                    }
                    let old_parent = page_allocator.get_page(*parent, PageHint::None)?;
                    let mut new_page = page_allocator
                        .allocate_lowest(old_parent.memory().len(), &PageTracker::ignore())?;
                    let new_page_number = new_page.get_page_number();
                    // We have to copy at least the page type into the new page.
                    // Otherwise its cache priority will be calculated incorrectly
                    new_page.memory_mut()[0] = old_parent.memory()[0];
                    drop(new_page);
                    relocation_map.insert(*parent, new_page_number);
                }
            } else {
                page_allocator.free(new_page_number, &PageTracker::ignore());
                break;
            }
        }

        if !relocation_map.is_empty() {
            progress = true;
        }

        table_tree.relocate_tables(&relocation_map)?;
        system_table_tree.relocate_tables(&relocation_map)?;

        Ok(progress)
    }

    // NOTE: must be called before store_system_freed_pages() during commit, since this can create
    // more pages freed by the current transaction
    fn process_freed_pages(&mut self, free_until: TransactionId) -> Result {
        // We assume below that PageNumber is length 8
        assert_eq!(PageNumber::serialized_size(), 8);

        let mut deferred = Vec::new();
        let mut free_page = |page| {
            deferred.push(page);
        };

        {
            let mut system_tables = self.system_tables.lock().unwrap();
            // Validate BOTH selected ranges before either tree is mutated.
            // Otherwise a malformed system record could be discovered only
            // after valid data records had already been removed.
            let plans = (|| {
                Ok([
                    self.validate_freed_page_range(
                        &mut system_tables,
                        DATA_FREED_TABLE,
                        PageListKind::Data,
                        free_until,
                    )?,
                    self.validate_freed_page_range(
                        &mut system_tables,
                        SYSTEM_FREED_TABLE,
                        PageListKind::System,
                        free_until,
                    )?,
                ])
            })();
            let plans = match plans {
                Ok(plans) => plans,
                Err(error) => {
                    self.poison();
                    return Err(error);
                }
            };
            for plan in plans {
                self.extract_freed_pages(&mut system_tables, plan, &mut free_page)?;
            }
        }
        self.deferred_reclaim.extend(deferred);

        Ok(())
    }

    fn validate_freed_page_range(
        &self,
        system_tables: &mut SystemNamespace,
        definition: SystemTableDefinition<'static, TransactionIdWithPagination, PageList<'static>>,
        kind: PageListKind,
        free_until: TransactionId,
    ) -> Result<ValidatedPageListRange> {
        let root = system_tables.get_system_table_root(definition)?;
        if root.is_some() {
            let table = system_tables.open_system_table(self, definition)?;
            let key = TransactionIdWithPagination {
                transaction_id: free_until.raw_id(),
                pagination_id: 0,
            };
            table.validate_page_lists(..key, kind)?;
        }
        Ok(ValidatedPageListRange {
            definition,
            kind,
            free_until,
            root,
        })
    }

    fn extract_freed_pages(
        &self,
        system_tables: &mut SystemNamespace,
        plan: ValidatedPageListRange,
        mut process_page: impl FnMut(PageNumber),
    ) -> Result<()> {
        if system_tables.get_system_table_root(plan.definition)? != plan.root {
            self.poison();
            return Err(StorageError::InvalidPageList);
        }
        if plan.root.is_none() {
            return Ok(());
        }
        let mut freed = system_tables.open_system_table(self, plan.definition)?;
        let key = TransactionIdWithPagination {
            transaction_id: plan.free_until.raw_id(),
            pagination_id: 0,
        };
        let kind = plan.kind;
        let mut iter = freed.extract_from_if(..key, |_, _| true)?;
        let result = (|| {
            for entry in &mut iter {
                let (_, page_list) = entry?;
                let page_list = page_list.value().checked(kind)?;
                for i in 0..page_list.len() {
                    process_page(page_list.get(i));
                }
            }
            Ok(())
        })();
        self.finish_page_list_extraction(iter, result)
    }

    // Explicit close remains mandatory even if this loop later stops at a
    // bounded prefix. System-table iterators carry no automatic poison target.
    // Preserve the first iteration failure; close after it may only re-raise
    // PreviousIo. A new close failure after successful iteration is returned
    // unchanged, and neither failure permits this transaction to publish.
    fn finish_page_list_extraction<F>(
        &self,
        iter: ExtractIf<'_, TransactionIdWithPagination, PageList<'static>, F>,
        result: Result,
    ) -> Result
    where
        F: for<'f> FnMut(TransactionIdWithPagination, PageList<'f>) -> bool,
    {
        let closed = iter.close();
        let result = match result {
            Err(original) => Err(original),
            Ok(()) => closed,
        };
        if result.is_err() {
            self.poison();
        }
        result
    }

    fn store_system_freed_pages(
        system_tree: &mut TableTreeMut,
        transaction_id: TransactionId,
        system_freed_pages: Arc<Mutex<Vec<PageNumber>>>,
    ) -> Result<bool> {
        assert_eq!(PageNumber::serialized_size(), 8); // We assume below that PageNumber is length 8
        if system_freed_pages.lock().unwrap().is_empty() {
            return Ok(false);
        }
        let mut stored_pages = false;

        system_tree.open_table_and_flush_table_root(
            SYSTEM_FREED_TABLE.name(),
            |system_freed_tree: &mut SystemFreedTree| {
                let mut pagination_id =
                    Self::next_system_freed_pagination_id(system_freed_tree, transaction_id)?;
                while !system_freed_pages.lock().unwrap().is_empty() {
                    let chunk_size = PageListKind::System.capacity();
                    let buffer_size = PageList::required_bytes(chunk_size);
                    let key = TransactionIdWithPagination {
                        transaction_id: transaction_id.raw_id(),
                        pagination_id,
                    };
                    let mut access_guard = system_freed_tree.insert_reserve(&key, buffer_size)?;

                    let mut freed_pages = system_freed_pages.lock().unwrap();
                    let len = freed_pages.len();
                    access_guard.as_mut().clear();
                    for page in freed_pages.drain(len - min(len, chunk_size)..) {
                        access_guard.as_mut().push_back(page);
                        stored_pages = true;
                    }
                    drop(access_guard);

                    pagination_id += 1;
                }
                Ok(())
            },
        )?;

        Ok(stored_pages)
    }

    fn next_system_freed_pagination_id(
        system_freed_tree: &SystemFreedTree,
        transaction_id: TransactionId,
    ) -> Result<u64> {
        let first_key = TransactionIdWithPagination {
            transaction_id: transaction_id.raw_id(),
            pagination_id: 0,
        };
        let next_transaction_key = TransactionIdWithPagination {
            transaction_id: transaction_id.next().raw_id(),
            pagination_id: 0,
        };
        let transaction_range = first_key..next_transaction_key;
        let mut existing_entries = system_freed_tree.range(&transaction_range)?;
        Ok(existing_entries
            .next_back()
            .transpose()?
            .map_or(0, |entry| entry.key().pagination_id + 1))
    }

    /// Retrieves information about storage usage in the database
    ///
    /// Tables currently open in this transaction are reported as of the start of the
    /// transaction; their modifications are reflected once the handle is dropped.
    pub fn stats(&self) -> Result<DatabaseStats> {
        let tables = self.tables.lock().unwrap();
        let table_tree = &tables.table_tree;
        let data_tree_stats = table_tree.stats()?;

        let system_tables = self.system_tables.lock().unwrap();
        let system_table_tree = &system_tables.table_tree;
        let system_tree_stats = system_table_tree.stats()?;

        let total_metadata_bytes = data_tree_stats.metadata_bytes()
            + system_tree_stats.metadata_bytes
            + system_tree_stats.stored_leaf_bytes;
        let total_fragmented = data_tree_stats.fragmented_bytes()
            + system_tree_stats.fragmented_bytes
            + self.mem.count_free_pages()? * (self.mem.get_page_size() as u64);

        Ok(DatabaseStats {
            tree_height: data_tree_stats.tree_height(),
            allocated_pages: self.mem.count_allocated_pages()?,
            leaf_pages: data_tree_stats.leaf_pages(),
            branch_pages: data_tree_stats.branch_pages(),
            stored_leaf_bytes: data_tree_stats.stored_bytes(),
            metadata_bytes: total_metadata_bytes,
            fragmented_bytes: total_fragmented,
            page_size: self.mem.get_page_size(),
        })
    }

    #[allow(dead_code)]
    #[cfg(not(redb_no_std))]
    pub(crate) fn print_debug(&self) -> Result {
        // Flush any pending updates to make sure we get the latest root
        let mut tables = self.tables.lock().unwrap();
        if let Some(page) = tables
            .table_tree
            .flush_table_root_updates()
            .unwrap()
            .finalize_dirty_checksums()
            .unwrap()
        {
            eprintln!("Master tree:");
            let master_tree: Btree<&str, InternalTableDefinition> = Btree::new(
                Some(page),
                PageHint::None,
                self.transaction_guard.clone(),
                PageResolver::new(self.mem.clone()),
            )?;
            master_tree.print_debug(true)?;
        }

        // Flush any pending updates to make sure we get the latest root
        let mut system_tables = self.system_tables.lock().unwrap();
        if let Some(page) = system_tables
            .table_tree
            .flush_table_root_updates()
            .unwrap()
            .finalize_dirty_checksums()
            .unwrap()
        {
            eprintln!("System tree:");
            let master_tree: Btree<&str, InternalTableDefinition> = Btree::new(
                Some(page),
                PageHint::None,
                self.transaction_guard.clone(),
                PageResolver::new(self.mem.clone()),
            )?;
            master_tree.print_debug(true)?;
        }

        Ok(())
    }
}

impl Drop for WriteTransaction {
    fn drop(&mut self) {
        if !self.completed && !crate::panicking() && !self.mem.storage_failure() {
            let _ = self.abort_inner();
        } else if !self.completed && self.mem.storage_failure() {
            self.tables
                .lock()
                .unwrap()
                .table_tree
                .clear_root_updates_and_close();
        }
    }
}

/// A read-only transaction
///
/// Read-only transactions may exist concurrently with writes
pub struct ReadTransaction {
    mem: Arc<TransactionalMemory>,
    tree: TableTree,
}

impl ReadTransaction {
    pub(crate) fn new(
        mem: Arc<TransactionalMemory>,
        guard: TransactionGuard,
    ) -> Result<Self, TransactionError> {
        let root_page = mem.get_data_root();
        let guard = Arc::new(guard);
        let resolver = PageResolver::new(mem.clone());
        Ok(Self {
            mem,
            tree: TableTree::new(root_page, PageHint::Clean, guard, resolver)
                .map_err(TransactionError::Storage)?,
        })
    }

    /// Open the given table
    pub fn open_table<K: Key + 'static, V: Value + 'static>(
        &self,
        definition: TableDefinition<K, V>,
    ) -> Result<ReadOnlyTable<K, V>, TableError> {
        let header = self
            .tree
            .get_table::<K, V>(definition.name(), TableType::Normal)?
            .ok_or_else(|| TableError::TableDoesNotExist(definition.name().to_string()))?;

        match header {
            InternalTableDefinition::Normal { table_root, .. } => Ok(ReadOnlyTable::new(
                definition.name().to_string(),
                table_root,
                PageHint::Clean,
                self.tree.transaction_guard().clone(),
                PageResolver::new(self.mem.clone()),
            )?),
            InternalTableDefinition::Multimap { .. } => unreachable!(),
        }
    }

    /// Open the given table without a type
    pub fn open_untyped_table(
        &self,
        handle: impl TableHandle,
    ) -> Result<ReadOnlyUntypedTable, TableError> {
        let name = handle.name();
        let header = self
            .tree
            .get_table_untyped(name, TableType::Normal)?
            .ok_or_else(|| TableError::TableDoesNotExist(name.to_string()))?;

        match header {
            InternalTableDefinition::Normal {
                table_root,
                fixed_key_size,
                fixed_value_size,
                ..
            } => Ok(ReadOnlyUntypedTable::new(
                name,
                table_root,
                PageHint::Clean,
                fixed_key_size,
                fixed_value_size,
                PageResolver::new(self.mem.clone()),
            )),
            InternalTableDefinition::Multimap { .. } => unreachable!(),
        }
    }

    /// Open the given table
    pub fn open_multimap_table<K: Key + 'static, V: Key + 'static>(
        &self,
        definition: MultimapTableDefinition<K, V>,
    ) -> Result<ReadOnlyMultimapTable<K, V>, TableError> {
        let header = self
            .tree
            .get_table::<K, V>(definition.name(), TableType::Multimap)?
            .ok_or_else(|| TableError::TableDoesNotExist(definition.name().to_string()))?;

        match header {
            InternalTableDefinition::Normal { .. } => unreachable!(),
            InternalTableDefinition::Multimap {
                table_root,
                table_length,
                ..
            } => Ok(ReadOnlyMultimapTable::new(
                definition.name(),
                table_root,
                table_length,
                PageHint::Clean,
                self.tree.transaction_guard().clone(),
                PageResolver::new(self.mem.clone()),
            )?),
        }
    }

    /// Open the given table without a type
    pub fn open_untyped_multimap_table(
        &self,
        handle: impl MultimapTableHandle,
    ) -> Result<ReadOnlyUntypedMultimapTable, TableError> {
        let name = handle.name();
        let header = self
            .tree
            .get_table_untyped(name, TableType::Multimap)?
            .ok_or_else(|| TableError::TableDoesNotExist(name.to_string()))?;

        match header {
            InternalTableDefinition::Normal { .. } => unreachable!(),
            InternalTableDefinition::Multimap {
                table_root,
                table_length,
                fixed_key_size,
                fixed_value_size,
                ..
            } => Ok(ReadOnlyUntypedMultimapTable::new(
                name,
                table_root,
                table_length,
                PageHint::Clean,
                fixed_key_size,
                fixed_value_size,
                PageResolver::new(self.mem.clone()),
            )),
        }
    }

    /// List all the tables
    pub fn list_tables(&self) -> Result<impl Iterator<Item = UntypedTableHandle>> {
        self.tree
            .list_tables(TableType::Normal)
            .map(|x| x.into_iter().map(UntypedTableHandle::new))
    }

    /// List all the multimap tables
    pub fn list_multimap_tables(&self) -> Result<impl Iterator<Item = UntypedMultimapTableHandle>> {
        self.tree
            .list_tables(TableType::Multimap)
            .map(|x| x.into_iter().map(UntypedMultimapTableHandle::new))
    }

    /// Close the transaction
    ///
    /// Transactions are automatically closed when they and all objects referencing them have been dropped,
    /// so this method does not normally need to be called.
    /// This method can be used to ensure that there are no outstanding objects remaining.
    ///
    /// Returns `ReadTransactionStillInUse` error if a table or other object retrieved from the transaction still references this transaction
    pub fn close(self) -> Result<(), TransactionError> {
        if Arc::strong_count(self.tree.transaction_guard()) > 1 {
            return Err(TransactionError::ReadTransactionStillInUse(Box::new(self)));
        }
        // No-op, just drop ourself
        Ok(())
    }
}

impl Debug for ReadTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("ReadTransaction")
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "experimental-api-5")]
    use crate::ReadableTable;
    use crate::{Database, ReadableDatabase, StorageError, TableDefinition, TransactionError};

    const X: TableDefinition<&str, &str> = TableDefinition::new("x");
    const BIG_VALUE: TableDefinition<u64, &[u8]> = TableDefinition::new("big_value");

    // A commit that stops part way may leave pages returned to the allocator while the durable
    // freed tables still reference them, so commit_inner() discards the allocator state unless
    // it completes. Verify the resulting contract: writes are refused, reads keep working, the
    // shutdown is not recorded as clean, and reopening repairs the database.
    #[test]
    fn discarded_allocator_state_poisons_database() {
        let tmpfile = crate::create_tempfile();
        let db = Database::create(tmpfile.path(), crate::test_admission()).unwrap();

        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(X).unwrap();
            for i in 0..100u32 {
                table.insert(format!("key{i}").as_str(), "value").unwrap();
            }
        }
        txn.commit().unwrap();

        // Leave freed-table entries pending, so the repair below must handle them
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(X).unwrap();
            for i in 0..50u32 {
                table.remove(format!("key{i}").as_str()).unwrap();
            }
        }
        txn.commit().unwrap();

        // The state a failed commit leaves behind
        db.get_memory().invalidate_allocator_state();

        // Twice: a refused attempt must release the write slot
        for _ in 0..2 {
            match db.begin_write() {
                Err(TransactionError::Storage(StorageError::Corrupted(_))) => {}
                Err(err) => panic!("unexpected error: {err}"),
                Ok(_) => panic!("begin_write() must fail"),
            }
        }

        // Reads still work and see the last committed state
        {
            let read_txn = db.begin_read().unwrap();
            let table = read_txn.open_table(X).unwrap();
            assert!(table.get("key0").unwrap().is_none());
            assert_eq!(table.get("key99").unwrap().unwrap().value(), "value");
        }

        // Closing must not record a clean shutdown, so reopening repairs the database
        drop(db);
        let mut db = Database::open(tmpfile.path(), crate::test_admission()).unwrap();
        assert!(db.check_integrity().unwrap());
        {
            let read_txn = db.begin_read().unwrap();
            let table = read_txn.open_table(X).unwrap();
            assert_eq!(table.get("key99").unwrap().unwrap().value(), "value");
        }

        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(X).unwrap();
            table.insert("after-repair", "value").unwrap();
        }
        txn.commit().unwrap();
    }

    #[test]
    fn transaction_id_persistence() {
        let tmpfile = crate::create_tempfile();
        let db = Database::create(tmpfile.path(), crate::test_admission()).unwrap();
        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(X).unwrap();
            table.insert("hello", "world").unwrap();
        }
        let first_txn_id = write_txn.transaction_id;
        write_txn.commit().unwrap();
        drop(db);

        let db2 = Database::create(tmpfile.path(), crate::test_admission()).unwrap();
        let write_txn = db2.begin_write().unwrap();
        assert!(write_txn.transaction_id > first_txn_id);
    }

    #[test]
    fn committed_deletion_has_no_allocating_epilogue() {
        let tmpfile = crate::create_tempfile();
        let db = Database::create(tmpfile.path(), crate::test_admission()).unwrap();
        let value = vec![0; 512 * 1024];

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(BIG_VALUE).unwrap();
            table.insert(0, value.as_slice()).unwrap();
        }
        write_txn.commit().unwrap();

        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(BIG_VALUE).unwrap();
            table.remove(0).unwrap();
        }
        let remove_txn_id = write_txn.transaction_id;
        write_txn.commit().unwrap();

        let write_txn = db.begin_write().unwrap();
        assert_eq!(write_txn.transaction_id, remove_txn_id.next());
    }
}

#[cfg(all(test, not(redb_no_std), panic = "unwind"))]
#[path = "page_list_tests.rs"]
mod page_list_tests;
