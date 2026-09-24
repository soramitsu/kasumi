use crate::io;
use crate::sync::Mutex;
use crate::transaction_tracker::TransactionId;
use crate::transactions::{AllocatorStateKey, AllocatorStateTree, AllocatorStateTreeMut};
use crate::tree_store::btree_base::{BtreeHeader, Checksum};
use crate::tree_store::page_store::base::{MAX_PAGE_INDEX, PageHint};
use crate::tree_store::page_store::buddy_allocator::BuddyAllocator;
use crate::tree_store::page_store::cached_file::PagedCachedFile;
use crate::tree_store::page_store::fast_hash::{PageNumberHashMap, PageNumberHashSet};
use crate::tree_store::page_store::header::{
    DB_HEADER_SIZE, DatabaseHeader, MAGICNUMBER, TransactionHeader, UnrepairedDatabaseHeader,
};
use crate::tree_store::page_store::layout::DatabaseLayout;
use crate::tree_store::page_store::region::{Allocators, RegionTracker};
use crate::tree_store::page_store::{PageImpl, PageMut, hash128_with_seed};
use crate::tree_store::{Page, PageNumber, PageTracker};
use crate::{CacheStats, StorageBackend};
use crate::{DatabaseError, Result, StorageError};
use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::{max, min};
use core::convert::TryInto;
use core::marker::PhantomData;
use core::mem;

// Canonical format4 never contains obsolete region headers.
const NO_HEADER: u32 = 0;

// Regions have a maximum size of 4GiB. A `4GiB - overhead` value is the largest that can be represented,
// because the leaf node format uses 32bit offsets
const MAX_USABLE_REGION_SPACE: u64 = 4 * 1024 * 1024 * 1024;
// A region holds at most `MAX_PAGE_INDEX + 1` pages (the page index within a region is 20 bits),
// so the largest buddy-allocator order any region can have is log2(MAX_PAGE_INDEX + 1).
// `u32::ilog2` is always <= 31, so the cast to u8 is lossless.
#[allow(clippy::cast_possible_truncation)]
pub(crate) const MAX_MAX_PAGE_ORDER: u8 = (MAX_PAGE_INDEX + 1).ilog2() as u8;
pub(super) const MIN_USABLE_PAGES: u32 = 10;
const MIN_DESIRED_USABLE_BYTES: u64 = 1024 * 1024;

pub(super) const INITIAL_REGIONS: u32 = 1000; // Enough for a 4TiB database

// The sole canonical format: data deferred frees use fixed PageList records;
// obsolete system pages are excluded from the prepared winning allocator and
// returned to the live allocator only after that header is durable. Formats
// 1, 2 and 3 are rejected; no upgrade or historical-system-table decoder exists.
pub(crate) const FILE_FORMAT_VERSION4: u8 = 4;

#[derive(Copy, Clone)]
pub(crate) enum ShrinkPolicy {
    // Try to shrink the file by the default amount
    Default,
    // Try to shrink the file by the maximum amount
    Maximum,
}

/// Controls how `allocate()` picks a free page.
#[derive(Copy, Clone)]
pub(crate) enum AllocationPolicy {
    /// Find a free block at the requested order, or recursively split from a
    /// higher order. Cheaper than `Lowest`, but after `grow()` has appended
    /// buddy-aligned free blocks at high page indices this can allocate at
    /// high absolute pages.
    Default,
    /// Pick the lowest-page-number allocation across all orders. More
    /// expensive, but keeps trailing pages free so `try_shrink()` can
    /// reclaim recently-grown space.
    Lowest,
}

/// Read-only view over `TransactionalMemory` exposing only the methods that
/// btree read paths and stats helpers need. Cheap to clone -- a single
/// `Arc<TransactionalMemory>` bump.
///
/// Construct one from `PageAllocator::resolver()` (write-transaction context)
/// or `PageResolver::new(mem)` (read-transaction context). Read-only btree
/// types accept `PageResolver` rather than `Arc<TransactionalMemory>` so that
/// they cannot be used to bypass `PageAllocator`'s allocation tracking.
#[derive(Clone)]
pub(crate) struct PageResolver {
    mem: Arc<TransactionalMemory>,
}

impl PageResolver {
    pub(crate) fn new(mem: Arc<TransactionalMemory>) -> Self {
        Self { mem }
    }

    pub(crate) fn get_page(&self, page_number: PageNumber, hint: PageHint) -> Result<PageImpl> {
        self.mem.get_page(page_number, hint)
    }

    pub(crate) fn count_allocated_pages(&self) -> Result<u64> {
        self.mem.count_allocated_pages()
    }
}

// Shards for `UncommittedPages`, padded to a cache line: the contention being removed is cores
// handing one lock's line back and forth, worst between cores in different L3 domains, which
// shards sharing a line would reintroduce.
const UNCOMMITTED_SHARDS: usize = 64;

#[repr(align(64))]
struct UncommittedShard(Mutex<PageNumberHashSet>);

/// The pages a write transaction has allocated since its last commit, which `uncommitted()`
/// answers from and rollback frees. Every allocation, free and `uncommitted()` check consults it,
/// and it can never be switched off, so it is sharded by page to keep concurrent writers -- tables
/// of one transaction may be written from different threads -- off a single lock.
struct UncommittedPages {
    shards: Vec<UncommittedShard>,
}

impl UncommittedPages {
    fn new() -> Self {
        Self {
            shards: (0..UNCOMMITTED_SHARDS)
                .map(|_| {
                    let shard = UncommittedShard(Mutex::new(PageNumberHashSet::default()));
                    // Some platforms allocate the OS lock lazily. Materialize it
                    // while preparing the transaction, never after publication.
                    drop(shard.0.lock().unwrap());
                    shard
                })
                .collect(),
        }
    }

    fn shard(&self, page: PageNumber) -> &Mutex<PageNumberHashSet> {
        &self.shards[page.page_index as usize % UNCOMMITTED_SHARDS].0
    }

    fn insert(&self, page: PageNumber) {
        assert!(self.shard(page).lock().unwrap().insert(page));
    }

    /// Removes `page` if present. Returns whether it was in the set.
    fn remove(&self, page: PageNumber) -> bool {
        self.shard(page).lock().unwrap().remove(&page)
    }

    fn contains(&self, page: PageNumber) -> bool {
        self.shard(page).lock().unwrap().contains(&page)
    }
}

/// Per-write-transaction handle through which btree mutation code allocates
/// and frees pages. Bundles the shared `TransactionalMemory` with the write
/// transaction's `AllocationPolicy`.
#[derive(Clone)]
pub(crate) struct PageAllocator {
    mem: Arc<TransactionalMemory>,
    policy: AllocationPolicy,
    allocated_since_commit: Arc<UncommittedPages>,
}

impl PageAllocator {
    pub(crate) fn new(mem: Arc<TransactionalMemory>, policy: AllocationPolicy) -> Self {
        Self {
            mem,
            policy,
            allocated_since_commit: Arc::new(UncommittedPages::new()),
        }
    }

    /// Returns a `PageResolver` for constructing read-only views of this transaction's pages.
    pub(crate) fn resolver(&self) -> PageResolver {
        PageResolver::new(self.mem.clone())
    }

    pub(crate) fn discard_committed_allocations(&self) {
        for shard in &self.allocated_since_commit.shards {
            shard.0.lock().unwrap().clear();
        }
    }

    /// Reverses every allocation made since the last commit: drains the
    /// allocated-since-commit set and frees each page.
    pub(crate) fn rollback_all(&self) {
        self.mem.debug_assert_no_dirty_pages();
        for shard in &self.allocated_since_commit.shards {
            let drained = mem::take(&mut *shard.0.lock().unwrap());
            for page in drained {
                self.mem.free(page, &PageTracker::ignore());
            }
        }
    }

    pub(crate) fn allocate<'a>(&self, size: usize, allocated: &PageTracker) -> Result<PageMut<'a>> {
        self.mem.check_transaction_admission()?;
        let page = match self.policy {
            AllocationPolicy::Default => self.mem.allocate(size, allocated)?,
            AllocationPolicy::Lowest => self.mem.allocate_lowest(size, allocated)?,
        };
        self.allocated_since_commit.insert(page.get_page_number());
        Ok(page)
    }

    // Always allocates at the lowest free page, ignoring `self.policy`. Used
    // by compaction's probe loop where the point is specifically to test
    // whether a page can land below its current position.
    pub(crate) fn allocate_lowest<'a>(
        &self,
        size: usize,
        allocated: &PageTracker,
    ) -> Result<PageMut<'a>> {
        self.mem.check_transaction_admission()?;
        let page = self.mem.allocate_lowest(size, allocated)?;
        self.allocated_since_commit.insert(page.get_page_number());
        Ok(page)
    }

    pub(crate) fn free(&self, page: PageNumber, allocated: &PageTracker) {
        self.allocated_since_commit.remove(page);
        self.mem.free(page, allocated);
    }

    pub(crate) fn free_if_uncommitted(&self, page: PageNumber, allocated: &PageTracker) -> bool {
        if self.allocated_since_commit.remove(page) {
            self.mem.free(page, allocated);
            true
        } else {
            false
        }
    }

    // Frees the page immediately if it was allocated in this transaction;
    // otherwise defers it to `freed` for release at commit.
    pub(crate) fn conditional_free(
        &self,
        page: PageNumber,
        allocated: &PageTracker,
        freed: &mut Vec<PageNumber>,
    ) {
        if !self.free_if_uncommitted(page, allocated) {
            freed.push(page);
        }
    }

    pub(crate) fn uncommitted(&self, page: PageNumber) -> bool {
        self.allocated_since_commit.contains(page)
    }

    pub(crate) fn get_page(&self, page_number: PageNumber, hint: PageHint) -> Result<PageImpl> {
        self.mem.get_page(page_number, hint)
    }

    pub(crate) fn get_page_mut<'a>(&self, page_number: PageNumber) -> Result<PageMut<'a>> {
        self.mem.get_page_mut(page_number)
    }

    pub(crate) fn get_page_size(&self) -> usize {
        self.mem.get_page_size()
    }
}

fn ceil_log2(x: usize) -> u8 {
    if x.is_power_of_two() {
        x.trailing_zeros().try_into().unwrap()
    } else {
        x.next_power_of_two().trailing_zeros().try_into().unwrap()
    }
}

pub(crate) fn xxh3_checksum(data: &[u8]) -> Checksum {
    hash128_with_seed(data, 0)
}

struct InMemoryState {
    header: DatabaseHeader,
    // None until the Database finishes loading allocator state from disk or rebuilding it via
    // repair.
    allocators: Option<Allocators>,
}

impl InMemoryState {
    fn new(header: DatabaseHeader) -> Self {
        Self {
            header,
            allocators: None,
        }
    }

    fn allocators(&self) -> &Allocators {
        self.allocators
            .as_ref()
            .expect("allocators have not been loaded yet")
    }

    fn allocators_mut(&mut self) -> &mut Allocators {
        self.allocators
            .as_mut()
            .expect("allocators have not been loaded yet")
    }

    fn get_region(&self, region: u32) -> &BuddyAllocator {
        &self.allocators().region_allocators[region as usize]
    }

    fn get_region_mut(&mut self, region: u32) -> &mut BuddyAllocator {
        &mut self.allocators_mut().region_allocators[region as usize]
    }

    fn get_region_tracker_mut(&mut self) -> &mut RegionTracker {
        &mut self.allocators_mut().region_tracker
    }

    fn latest_slot(&self) -> &TransactionHeader {
        self.header.primary_slot()
    }
}

pub(crate) struct TransactionalMemory {
    opened_unclean: bool,
    storage: PagedCachedFile,
    state: Mutex<InMemoryState>,
    // The number of PageMut which are outstanding
    #[cfg(debug_assertions)]
    open_dirty_pages: Arc<Mutex<PageNumberHashSet>>,
    // Reference counts of PageImpls that are outstanding
    #[cfg(debug_assertions)]
    read_page_ref_counts: Arc<Mutex<PageNumberHashMap<u64>>>,
    // Set of all allocated pages for debugging assertions
    #[cfg(debug_assertions)]
    allocated_pages: Arc<Mutex<PageNumberHashSet>>,
    page_size: u32,
    // We store these separately from the layout because they're static, and accessed on the get_page()
    // code path where there is no locking
    region_size: u64,
    region_header_with_padding_size: u64,
}

/// Partial opening resources remain in this slot through every fallible call.
/// Its caller observes outcomes and must retain the slot on uncertain close.
pub(crate) struct TransactionalMemoryOpening {
    file: Option<Box<dyn StorageBackend>>,
    storage: Option<PagedCachedFile>,
}
impl TransactionalMemoryOpening {
    pub(crate) fn new(file: Box<dyn StorageBackend>) -> Self {
        Self {
            file: Some(file),
            storage: None,
        }
    }
    pub(crate) fn initialize(
        &mut self,
        admission: Arc<dyn crate::StorageAdmission>,
        allow_initialize: bool,
        page_size: usize,
        requested_region_size: Option<u64>,
        cache_size: usize,
    ) -> Result<TransactionalMemory, DatabaseError> {
        assert!(self.storage.is_none());
        assert!(page_size.is_power_of_two() && page_size >= DB_HEADER_SIZE);
        let region_size = requested_region_size.unwrap_or(MAX_USABLE_REGION_SPACE);
        assert!(
            min(
                region_size,
                (u64::from(MAX_PAGE_INDEX) + 1) * page_size as u64
            )
            .is_power_of_two()
        );
        admission.check_owner().map_err(StorageError::from)?;
        self.storage = Some(PagedCachedFile::new_retained(
            &mut self.file,
            admission,
            page_size as u64,
            cache_size,
        )?);
        TransactionalMemory::initialize_retained_storage(
            &mut self.storage,
            allow_initialize,
            page_size,
            requested_region_size,
        )
    }
    #[cfg(all(not(redb_no_std), panic = "unwind"))]
    pub(crate) fn abandon(&self) -> Result {
        if let Some(storage) = &self.storage {
            storage.close()
        } else if let Some(file) = &self.file {
            file.close().map_err(StorageError::Io)
        } else {
            // A fully constructed memory owner has already taken the cache.
            unreachable!("partial close requires an actual opening resource")
        }
    }
}

impl TransactionalMemory {
    pub(crate) fn opened_unclean(&self) -> bool {
        self.opened_unclean
    }
    pub(crate) fn begin_transaction(&self) {
        self.storage.begin_transaction();
    }
    pub(crate) fn capacity_error(&self) -> Option<StorageError> {
        self.storage.capacity_error()
    }
    #[cfg(test)]
    pub(crate) fn set_write_entry_capacity_for_test(&self, capacity: usize) {
        self.storage.set_write_entry_capacity_for_test(capacity);
    }
    pub(crate) fn check_transaction_admission(&self) -> Result {
        self.check_io_errors()?;
        self.capacity_error().map_or(Ok(()), Err)
    }
    pub(crate) fn settle_growth(&self) -> Result {
        self.storage.settle_growth()
    }
    pub(crate) fn abandon(&self) -> Result {
        self.storage.close()
    }

    pub(crate) fn new(
        file: Box<dyn StorageBackend>,
        admission: Arc<dyn crate::StorageAdmission>,
        allow_initialize: bool,
        page_size: usize,
        requested_region_size: Option<u64>,
        cache_size: usize,
    ) -> Result<Self, DatabaseError> {
        let mut opening = TransactionalMemoryOpening::new(file);
        opening.initialize(
            admission,
            allow_initialize,
            page_size,
            requested_region_size,
            cache_size,
        )
    }

    fn initialize_retained_storage(
        storage_owner: &mut Option<PagedCachedFile>,
        allow_initialize: bool,
        page_size: usize,
        requested_region_size: Option<u64>,
    ) -> Result<Self, DatabaseError> {
        assert!(page_size.is_power_of_two() && page_size >= DB_HEADER_SIZE);
        let region_size = requested_region_size.unwrap_or(MAX_USABLE_REGION_SPACE);
        let region_size = min(
            region_size,
            (u64::from(MAX_PAGE_INDEX) + 1) * page_size as u64,
        );
        assert!(region_size.is_power_of_two());
        let storage = storage_owner.as_ref().expect("prepared cache retained");
        let initial_storage_len = storage.raw_file_len()?;

        let magic_number: [u8; MAGICNUMBER.len()] =
            if initial_storage_len >= MAGICNUMBER.len() as u64 {
                storage
                    .read_direct(0, MAGICNUMBER.len())?
                    .try_into()
                    .unwrap()
            } else {
                [0; MAGICNUMBER.len()]
            };

        if initial_storage_len > 0 {
            // File already exists check that the magic number matches
            if magic_number != MAGICNUMBER {
                return Err(StorageError::Io(io::invalid_data(
                    "Not a redb database: magic number mismatch",
                ))
                .into());
            }
        } else {
            // File is empty, check that we're allowed to initialize a new database (i.e. the caller is Database::create() and not open())
            if !allow_initialize {
                return Err(StorageError::Io(io::invalid_data(
                    "Database file is empty and creating a new database was not requested",
                ))
                .into());
            }
        }

        if magic_number != MAGICNUMBER {
            let region_tracker_required_bytes =
                RegionTracker::new(INITIAL_REGIONS, MAX_MAX_PAGE_ORDER + 1)
                    .to_vec()
                    .len();

            // Make sure that there is enough room to allocate the region tracker into a page
            let size: u64 = max(
                MIN_DESIRED_USABLE_BYTES,
                page_size as u64 * u64::from(MIN_USABLE_PAGES),
            );
            let tracker_space =
                (page_size * region_tracker_required_bytes.div_ceil(page_size)) as u64;
            let starting_size = size + tracker_space;

            let page_capacity = (region_size / u64::try_from(page_size).unwrap())
                .try_into()
                .unwrap();
            let layout = DatabaseLayout::calculate(
                starting_size,
                page_capacity,
                NO_HEADER,
                page_size.try_into().unwrap(),
            );

            {
                let file_len = storage.raw_file_len()?;

                if file_len < layout.len() {
                    storage.resize(layout.len())?;
                }
            }

            let mut header = DatabaseHeader::new(layout, TransactionId::new(0));

            header.recovery_required = false;
            storage
                .write(0, DB_HEADER_SIZE, true)?
                .mem_mut()
                .copy_from_slice(&header.to_bytes(false));

            storage.flush()?;
            // Write the magic number only after the data structure is initialized and written to disk
            // to ensure that it's crash safe
            storage
                .write(0, DB_HEADER_SIZE, true)?
                .mem_mut()
                .copy_from_slice(&header.to_bytes(true));
            storage.flush()?;
        }
        let header_bytes = storage.read_direct(0, DB_HEADER_SIZE)?;
        let unrepaired =
            UnrepairedDatabaseHeader::from_bytes(&header_bytes, page_size.try_into().unwrap())?;
        let file_len = storage.raw_file_len()?;
        let needs_recovery = unrepaired.recovery_required(file_len);
        let (header, _) = unrepaired.finalize(file_len)?;
        // Normalize only in memory here. Database validates the sole canonical
        // system namespace before repair/begin_writable may rewrite this header.

        let layout = header.layout();
        assert_eq!(layout.len(), storage.raw_file_len()?);
        let region_size = layout.full_region_layout().len();
        let region_header_size = layout.full_region_layout().data_section().start;
        let state = Mutex::new(InMemoryState::new(header));

        assert!(page_size >= DB_HEADER_SIZE);

        #[cfg(debug_assertions)]
        let open_dirty_pages = Arc::new(Mutex::new(PageNumberHashSet::default()));
        #[cfg(debug_assertions)]
        let read_page_ref_counts = Arc::new(Mutex::new(PageNumberHashMap::default()));
        #[cfg(debug_assertions)]
        let allocated_pages = Arc::new(Mutex::new(PageNumberHashSet::default()));
        let page_size = u32::try_from(page_size).unwrap();

        Ok(Self {
            opened_unclean: needs_recovery,
            state,
            #[cfg(debug_assertions)]
            open_dirty_pages,
            #[cfg(debug_assertions)]
            read_page_ref_counts,
            #[cfg(debug_assertions)]
            allocated_pages,
            page_size,
            region_size,
            region_header_with_padding_size: region_header_size,
            // No fallible operation or external callback follows this transfer.
            storage: storage_owner.take().expect("prepared cache retained"),
        })
    }

    // An order read from a corrupted file would otherwise size a multi-terabyte read buffer, whose
    // failed allocation aborts the process instead of returning an error.
    fn check_page_order(page: PageNumber) -> Result<()> {
        if page.page_order > MAX_MAX_PAGE_ORDER {
            return Err(StorageError::Corrupted(format!(
                "Page {page:?} has order greater than the maximum of {MAX_MAX_PAGE_ORDER}"
            )));
        }
        Ok(())
    }

    pub(crate) fn cache_stats(&self) -> CacheStats {
        self.storage.cache_stats()
    }

    pub(crate) fn check_io_errors(&self) -> Result {
        self.storage.check_io_errors()
    }

    // Panics in debug builds if any `PageMut` handed out by `get_page_mut` or
    // `allocate*` has not yet been dropped. Intended as a precondition for
    // commit/abort paths, which assume no mutable page references remain.
    pub(crate) fn debug_assert_no_dirty_pages(&self) {
        #[cfg(debug_assertions)]
        {
            let dirty_pages = self.open_dirty_pages.lock().unwrap();
            debug_assert!(
                dirty_pages.is_empty(),
                "Dirty pages outstanding: {dirty_pages:?}"
            );
        }
    }

    #[cfg(debug_assertions)]
    pub(crate) fn mark_debug_allocated_page(&self, page: PageNumber) {
        assert!(self.allocated_pages.lock().unwrap().insert(page));
    }

    #[cfg(debug_assertions)]
    #[cfg_attr(redb_no_std, expect(dead_code))]
    pub(crate) fn all_allocated_pages(&self) -> Vec<PageNumber> {
        self.allocated_pages
            .lock()
            .unwrap()
            .iter()
            .copied()
            .collect()
    }

    #[cfg(debug_assertions)]
    #[cfg_attr(redb_no_std, expect(dead_code))]
    pub(crate) fn debug_check_allocator_consistency(&self) {
        let state = self.state.lock().unwrap();
        let allocators = state.allocators();
        let mut region_pages = vec![vec![]; allocators.region_allocators.len()];
        for p in self.allocated_pages.lock().unwrap().iter() {
            region_pages[p.region as usize].push(*p);
        }
        for (i, allocator) in allocators.region_allocators.iter().enumerate() {
            allocator.check_allocated_pages(i.try_into().unwrap(), &region_pages[i]);
        }
    }

    pub(crate) fn clear_read_cache(&self) {
        self.storage.invalidate_cache_all();
    }

    pub(crate) fn clear_cache_and_reload(&mut self) -> Result<bool, DatabaseError> {
        // The in-memory state is being discarded for the on-disk state, so buffered writes --
        // which can only belong to the discarded state -- are dropped rather than written out;
        // after an external truncation, writing them could even fail beyond the end of the file.
        // Both caches are cleared before the fallible sync, so an early error return cannot
        // leave cached pages that disagree with the file.
        self.storage.discard_write_buffer();
        self.storage.invalidate_cache_all();
        self.storage.sync_file()?;

        let header_bytes = self.storage.read_direct(0, DB_HEADER_SIZE)?;
        let unrepaired = UnrepairedDatabaseHeader::from_bytes(&header_bytes, self.page_size)?;
        let (header, was_clean) = unrepaired.finalize(self.storage.raw_file_len()?)?;
        // Integrity validation must reject obsolete namespaces before any
        // normalization write. Its successful repair path publishes this state.

        {
            let mut state = self.state.lock().unwrap();
            state.header = header;
            // Drop the previous allocator state -- it described the layout that was in memory
            // before the reload. The caller is required to repopulate it (via reset_allocator_state or
            // load_allocator_state) before any allocation/free path runs.
            state.allocators = None;
        }
        // Reloading from disk discards in-memory roots, so drop volatile allocation state
        // that belonged only to those roots.

        Ok(was_clean)
    }

    pub(crate) fn begin_writable(&self) -> Result {
        let mut state = self.state.lock().unwrap();
        assert!(!state.header.recovery_required);
        state.header.recovery_required = true;
        self.write_header(&state.header)?;
        self.storage.flush()
    }

    pub(crate) fn allocator_hash(&self) -> u128 {
        self.state.lock().unwrap().allocators().xxh3_hash()
    }

    // Reports whether the backend has seen an I/O failure in this process.
    // Callers use this to skip cleanup that would do further I/O after a
    // previous storage error (e.g. WriteTransaction::drop).
    pub(crate) fn storage_failure(&self) -> bool {
        self.storage.check_io_errors().is_err()
    }

    // Replaces the in-memory allocator state with a fresh, empty one sized to the current
    // layout. The caller is responsible for repopulating it by marking reachable pages allocated.
    pub(crate) fn reset_allocator_state(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.allocators = Some(Allocators::new(state.header.layout()));
        #[cfg(debug_assertions)]
        self.allocated_pages.lock().unwrap().clear();

        Ok(())
    }

    // Discards an allocator state that no longer describes the file. Callers that allocate or free
    // must check for one first, since those paths have no way to work without it.
    //
    // Runs during panic unwinding, so it must tolerate poisoned locks rather than double-panic.
    // The poison is deliberately left set: subsequent lock users fail rather than trusting state
    // touched by a panicking thread.
    pub(crate) fn invalidate_allocator_state(&self) {
        self.state
            .lock()
            .unwrap_or_else(crate::sync::PoisonError::into_inner)
            .allocators = None;
        #[cfg(debug_assertions)]
        self.allocated_pages
            .lock()
            .unwrap_or_else(crate::sync::PoisonError::into_inner)
            .clear();
    }

    pub(crate) fn allocator_state_loaded(&self) -> bool {
        self.state.lock().unwrap().allocators.is_some()
    }

    // The freed tables name pages that no page walk ever reads, so this is the only place those
    // page numbers are validated.
    pub(crate) fn mark_page_allocated(&self, page_number: PageNumber) -> Result<()> {
        Self::check_page_order(page_number)?;
        let mut state = self.state.lock()?;
        // Unlike the read path, this is only reached while rebuilding the allocator state, and the
        // state lock is already held, so validating against the layout costs nothing here
        let layout = state.header.layout();
        if page_number.region >= layout.num_regions() {
            return Err(StorageError::Corrupted(format!(
                "Page {page_number:?} is in region {}, but the database has {} region(s)",
                page_number.region,
                layout.num_regions()
            )));
        }
        let region_pages = u64::from(layout.region_layout(page_number.region).num_pages());
        // Cannot overflow: page_index is at most 2^32, and the order was bounded above
        let end_page = (u64::from(page_number.page_index) + 1) << page_number.page_order;
        if end_page > region_pages {
            return Err(StorageError::Corrupted(format!(
                "Page {page_number:?} extends past the end of its region, which has {region_pages} pages"
            )));
        }

        let allocator = state.get_region_mut(page_number.region);
        if !allocator.record_alloc(page_number.page_index, page_number.page_order) {
            return Err(StorageError::Corrupted(format!(
                "Page {page_number:?} overlaps a page that is already allocated"
            )));
        }
        #[cfg(debug_assertions)]
        assert!(self.allocated_pages.lock().unwrap().insert(page_number));

        Ok(())
    }

    fn write_header(&self, header: &DatabaseHeader) -> Result {
        self.storage
            .write(0, DB_HEADER_SIZE, true)?
            .mem_mut()
            .copy_from_slice(&header.to_bytes(true));

        Ok(())
    }

    // Durably clears the recovery flag, marking the repair as complete.
    pub(crate) fn clear_recovery_required(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.header.recovery_required = false;
        self.write_header(&state.header)?;
        self.storage.flush()?;
        Ok(())
    }

    pub(crate) fn reserve_allocator_state(
        &self,
        tree: &mut AllocatorStateTreeMut,
        transaction_id: TransactionId,
    ) -> Result<u32> {
        let state = self.state.lock().unwrap();
        let layout = state.header.layout();
        let num_regions = layout.num_regions();
        let allocators = state.allocators();
        // Check every encoded length before changing the allocator-state tree.
        // This retains only the existing per-region scalar inventory, never
        // serialized bitmap/allocator copies merely to measure their lengths.
        let invalid_geometry = || {
            StorageError::Corrupted("Allocator encoded length overflow or invalid geometry".into())
        };
        if u32::try_from(allocators.region_allocators.len()).ok() != Some(num_regions) {
            return Err(invalid_geometry());
        }
        let region_tracker_len = allocators
            .region_tracker
            .checked_encoded_len()
            .ok_or_else(invalid_geometry)?;
        let region_lens: Vec<usize> = allocators
            .region_allocators
            .iter()
            .map(BuddyAllocator::checked_encoded_len)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(invalid_geometry)?;
        drop(state);

        for i in 0..num_regions {
            let region_bytes_len = region_lens[i as usize];
            tree.insert(
                &AllocatorStateKey::Region(i),
                &vec![0; region_bytes_len].as_ref(),
            )?;
        }

        tree.insert(
            &AllocatorStateKey::RegionTracker,
            &vec![0; region_tracker_len].as_ref(),
        )?;

        tree.insert(
            &AllocatorStateKey::TransactionId,
            &transaction_id.raw_id().to_le_bytes().as_ref(),
        )?;

        Ok(num_regions)
    }

    // Returns true on success, or false if the number of regions has changed
    pub(crate) fn try_save_allocator_state(
        &self,
        tree: &mut AllocatorStateTreeMut,
        num_regions: u32,
        deferred_reclaim: &[PageNumber],
        current_system_reclaim: &[PageNumber],
    ) -> Result<bool> {
        // Has the number of regions changed since reserve_allocator_state() was called?
        let state = self.state.lock().unwrap();
        if num_regions != state.header.layout().num_regions() {
            return Ok(false);
        }

        // Prepare the allocator that the winning root will own without returning
        // old-root pages to the live allocator before publication.
        let current = state.allocators();
        let mut allocators = Allocators {
            region_tracker: RegionTracker::from_bytes(&current.region_tracker.to_vec()),
            region_allocators: current
                .region_allocators
                .iter()
                .map(|region| BuddyAllocator::from_bytes(&region.to_vec()))
                .collect(),
        };
        // Neither slice is returned to the live allocator here. Current system
        // pages are writer-private, and the caller guarantees no system-tree
        // allocation/free after this snapshot completes. The winning header
        // therefore names this prepared allocator; failure preserves old-root
        // ownership and the existing retained transaction collections.
        for page in deferred_reclaim.iter().chain(current_system_reclaim) {
            let order = allocators.region_allocators[page.region as usize]
                .free(page.page_index, page.page_order);
            allocators.region_tracker.mark_free(order, page.region);
        }
        for i in 0..num_regions {
            let region_bytes = &allocators.region_allocators[i as usize].to_vec();
            if tree
                .get(&AllocatorStateKey::Region(i))?
                .unwrap()
                .value()
                .len()
                < region_bytes.len()
            {
                // The allocator state grew too much since we reserved space
                return Ok(false);
            }
            tree.insert_inplace(&AllocatorStateKey::Region(i), &region_bytes.as_ref())?;
        }

        let region_tracker_bytes = allocators.region_tracker.to_vec();
        if tree
            .get(&AllocatorStateKey::RegionTracker)?
            .unwrap()
            .value()
            .len()
            < region_tracker_bytes.len()
        {
            // The allocator state grew too much since we reserved space
            return Ok(false);
        }
        tree.insert_inplace(
            &AllocatorStateKey::RegionTracker,
            &region_tracker_bytes.as_ref(),
        )?;

        Ok(true)
    }

    // Returns true if the allocator state table is up to date, or false if it's stale
    pub(crate) fn is_valid_allocator_state(&self, tree: &AllocatorStateTree) -> Result<bool> {
        // A snapshot belongs to exactly one winning transaction. A stale snapshot
        // requires rebuilding ownership from that root before any allocation.
        let Some(value) = tree.get(&AllocatorStateKey::TransactionId)? else {
            return Ok(false);
        };
        let transaction_id =
            TransactionId::new(u64::from_le_bytes(value.value().try_into().map_err(
                |_| StorageError::Corrupted("Invalid allocator-state transaction stamp".into()),
            )?));

        Ok(transaction_id == self.get_last_committed_transaction_id()?)
    }

    pub(crate) fn load_allocator_state(&self, tree: &AllocatorStateTree) -> Result {
        assert!(self.is_valid_allocator_state(tree)?);

        // Load the allocator state
        let mut region_allocators = vec![];
        for region in
            tree.range(&(AllocatorStateKey::Region(0)..=AllocatorStateKey::Region(u32::MAX)))?
        {
            region_allocators.push(BuddyAllocator::from_bytes(region?.value()));
        }

        let region_tracker = RegionTracker::from_bytes(
            tree.get(&AllocatorStateKey::RegionTracker)?
                .unwrap()
                .value(),
        );

        let mut state = self.state.lock().unwrap();
        state.allocators = Some(Allocators {
            region_tracker,
            region_allocators,
        });

        // Resize the allocators to match the current file size
        let layout = state.header.layout();
        state.allocators_mut().resize_to(layout);
        drop(state);

        self.state.lock().unwrap().header.recovery_required = false;

        Ok(())
    }

    #[cfg_attr(not(debug_assertions), expect(unused_variables))]
    pub(crate) fn is_allocated(&self, page: PageNumber) -> bool {
        #[cfg(debug_assertions)]
        {
            let allocated = self.allocated_pages.lock().unwrap();
            allocated.contains(&page)
        }
        #[cfg(not(debug_assertions))]
        {
            unreachable!()
        }
    }

    // Commit all outstanding changes and make them visible as the primary
    pub(crate) fn commit(
        &self,
        data_root: Option<BtreeHeader>,
        system_root: Option<BtreeHeader>,
        transaction_id: TransactionId,
        shrink_policy: ShrinkPolicy,
    ) -> Result {
        // All mutable pages must be dropped, this ensures that when a transaction completes
        // no more writes can happen to the pages it allocated. Thus it is safe to make them visible
        // to future read transactions
        self.debug_assert_no_dirty_pages();
        self.storage.check_io_errors()?;

        let mut state = self.state.lock().unwrap();
        // Trim surplus file space, before finalizing the commit
        let shrunk = Self::try_shrink(&mut state, matches!(shrink_policy, ShrinkPolicy::Maximum))?;
        // Copy the header so that we can release the state lock, while we flush the file
        let mut header = state.header.clone();
        drop(state);

        let old_transaction_id = header.secondary_slot().transaction_id;
        header.write_secondary_slot(transaction_id, data_root, system_root);

        let prepared_header = header.to_bytes(true);
        header.swap_primary_slot();
        let winning_header = header.to_bytes(true);
        // Payload/cache bookkeeping can allocate; finish it before either header.
        self.storage.prepare_publication();
        self.storage.flush()?;
        self.storage.settle_growth()?;
        self.storage.write_header_direct(&prepared_header)?;
        self.storage.sync_file()?;
        self.storage.write_header_direct(&winning_header)?;
        self.storage.sync_file()?;

        if shrunk {
            self.storage.resize(header.layout().len())?;
            self.storage.sync_file()?;
        }
        // Everything this stood in for is now durable: durable_commit() flushed the allocation
        // records to DATA_ALLOCATED_TABLE before reaching here.

        let mut state = self.state.lock().unwrap();
        assert_eq!(
            state.header.secondary_slot().transaction_id,
            old_transaction_id
        );
        state.header = header;
        drop(state);

        Ok(())
    }

    pub(crate) fn get_page(&self, page_number: PageNumber, hint: PageHint) -> Result<PageImpl> {
        Self::check_page_order(page_number)?;
        let range = page_number.address_range(
            self.page_size.into(),
            self.region_size,
            self.region_header_with_padding_size,
            self.page_size,
        );
        let len: usize = (range.end - range.start).try_into().unwrap();
        let mem = self.storage.read(range.start, len, hint)?;

        // We must not retrieve an immutable reference to a page which already has a mutable ref to it
        #[cfg(debug_assertions)]
        {
            let dirty_pages = self.open_dirty_pages.lock().unwrap();
            debug_assert!(!dirty_pages.contains(&page_number), "{page_number:?}");
            *(self
                .read_page_ref_counts
                .lock()
                .unwrap()
                .entry(page_number)
                .or_default()) += 1;
            drop(dirty_pages);
        }

        Ok(PageImpl {
            mem,
            page_number,
            #[cfg(debug_assertions)]
            open_pages: self.read_page_ref_counts.clone(),
        })
    }

    // NOTE: the caller must ensure that the read cache has been invalidated or stale reads my occur
    pub(crate) fn get_page_mut<'txn>(&self, page_number: PageNumber) -> Result<PageMut<'txn>> {
        Self::check_page_order(page_number)?;
        #[cfg(debug_assertions)]
        {
            assert!(
                !self
                    .read_page_ref_counts
                    .lock()
                    .unwrap()
                    .contains_key(&page_number)
            );
            assert!(!self.open_dirty_pages.lock().unwrap().contains(&page_number));
        }

        let address_range = page_number.address_range(
            self.page_size.into(),
            self.region_size,
            self.region_header_with_padding_size,
            self.page_size,
        );
        let len: usize = (address_range.end - address_range.start)
            .try_into()
            .unwrap();
        let mem = self.storage.write(address_range.start, len, false)?;

        #[cfg(debug_assertions)]
        {
            assert!(self.open_dirty_pages.lock().unwrap().insert(page_number));
        }

        Ok(PageMut {
            mem,
            page_number,
            _lifetime: PhantomData,
            #[cfg(debug_assertions)]
            open_pages: self.open_dirty_pages.clone(),
        })
    }

    pub(crate) fn get_version(&self) -> u8 {
        let state = self.state.lock().unwrap();
        state.latest_slot().version
    }

    pub(crate) fn get_data_root(&self) -> Option<BtreeHeader> {
        let state = self.state.lock().unwrap();
        state.latest_slot().user_root
    }

    pub(crate) fn get_system_root(&self) -> Option<BtreeHeader> {
        let state = self.state.lock().unwrap();
        state.latest_slot().system_root
    }

    pub(crate) fn get_last_committed_transaction_id(&self) -> Result<TransactionId> {
        let state = self.state.lock()?;
        Ok(state.latest_slot().transaction_id)
    }

    pub(crate) fn free(&self, page: PageNumber, allocated: &PageTracker) {
        self.free_helper(page, allocated);
    }

    fn free_helper(&self, page: PageNumber, allocated: &PageTracker) {
        #[cfg(debug_assertions)]
        {
            assert!(
                !self
                    .read_page_ref_counts
                    .lock()
                    .unwrap()
                    .contains_key(&page)
            );
            assert!(self.allocated_pages.lock().unwrap().remove(&page));
            assert!(!self.open_dirty_pages.lock().unwrap().contains(&page));
        }
        allocated.remove(page);
        let mut state = self.state.lock().unwrap();
        let region_index = page.region;
        // Free in the regional allocator. free() returns the order of the resulting block, which is
        // larger than page_order when buddies merged.
        let freed_order = state
            .get_region_mut(region_index)
            .free(page.page_index, page.page_order);
        // Mark the region free at the merged order, not just page_order: leaving the tracker's
        // higher-order bits stale after a merge would hide the reclaimed space from find_free.
        state
            .get_region_tracker_mut()
            .mark_free(freed_order, region_index);

        let address_range = page.address_range(
            self.page_size.into(),
            self.region_size,
            self.region_header_with_padding_size,
            self.page_size,
        );
        let len: usize = (address_range.end - address_range.start)
            .try_into()
            .unwrap();
        self.storage.invalidate_cache(address_range.start, len);
        self.storage.cancel_pending_write(address_range.start, len);
    }

    pub(crate) fn allocate_helper<'txn>(
        &self,
        allocation_size: usize,
        lowest: bool,
    ) -> Result<PageMut<'txn>> {
        let required_pages = allocation_size.div_ceil(self.get_page_size());
        let required_order = ceil_log2(required_pages);

        let mut state = self.state.lock().unwrap();

        let page_number = if let Some(page_number) =
            Self::allocate_helper_retry(&mut state, required_order, lowest)?
        {
            page_number
        } else {
            self.grow(&mut state, required_order)?;
            Self::allocate_helper_retry(&mut state, required_order, lowest)?.unwrap()
        };

        #[cfg(debug_assertions)]
        {
            assert!(self.allocated_pages.lock().unwrap().insert(page_number));
            assert!(
                !self
                    .read_page_ref_counts
                    .lock()
                    .unwrap()
                    .contains_key(&page_number),
                "Allocated a page that is still referenced! {page_number:?}"
            );
            assert!(!self.open_dirty_pages.lock().unwrap().contains(&page_number));
        }

        let address_range = page_number.address_range(
            self.page_size.into(),
            self.region_size,
            self.region_header_with_padding_size,
            self.page_size,
        );
        let len: usize = (address_range.end - address_range.start)
            .try_into()
            .unwrap();

        #[allow(unused_mut)]
        let mut mem = match self.storage.write(address_range.start, len, true) {
            Ok(page) => page,
            Err(StorageError::CacheCapacityDenied) => {
                // The cache has not created a buffer or changed this candidate's
                // cache state. It is not yet in PageTracker/UncommittedPages.
                // Undo exactly its allocation while retaining any independently
                // admitted file growth and layout until the real abort settles.
                #[cfg(debug_assertions)]
                {
                    assert!(self.allocated_pages.lock().unwrap().remove(&page_number));
                    assert!(!self.open_dirty_pages.lock().unwrap().contains(&page_number));
                }
                let freed_order = state
                    .get_region_mut(page_number.region)
                    .free(page_number.page_index, page_number.page_order);
                state
                    .get_region_tracker_mut()
                    .mark_free(freed_order, page_number.region);
                return Err(StorageError::CacheCapacityDenied);
            }
            Err(error) => return Err(error),
        };
        debug_assert!(mem.mem().len() >= allocation_size);

        #[cfg(debug_assertions)]
        {
            assert!(self.open_dirty_pages.lock().unwrap().insert(page_number));

            // Poison the memory in debug mode to help detect uninitialized reads
            mem.mem_mut().fill(0xFF);
        }

        Ok(PageMut {
            mem,
            page_number,
            _lifetime: PhantomData,
            #[cfg(debug_assertions)]
            open_pages: self.open_dirty_pages.clone(),
        })
    }

    fn allocate_helper_retry(
        state: &mut InMemoryState,
        required_order: u8,
        lowest: bool,
    ) -> Result<Option<PageNumber>> {
        loop {
            let Some(candidate_region) = state.get_region_tracker_mut().find_free(required_order)
            else {
                return Ok(None);
            };
            let region = state.get_region_mut(candidate_region);
            let r = if lowest {
                region.alloc_lowest(required_order)
            } else {
                region.alloc(required_order)
            };
            if let Some(page) = r {
                return Ok(Some(PageNumber::new(
                    candidate_region,
                    page,
                    required_order,
                )));
            }
            // Mark the region, if it's full
            state
                .get_region_tracker_mut()
                .mark_full(required_order, candidate_region);
        }
    }

    fn try_shrink(state: &mut InMemoryState, force: bool) -> Result<bool> {
        let layout = state.header.layout();
        let last_region_index = layout.num_regions() - 1;
        let last_allocator = state.get_region(last_region_index);
        let trailing_free = last_allocator.trailing_free_pages();
        let last_allocator_len = last_allocator.len();
        if trailing_free == 0 {
            return Ok(false);
        }
        if trailing_free < last_allocator_len / 2 && !force {
            return Ok(false);
        }
        let reduce_by = if layout.num_regions() > 1 && trailing_free == last_allocator_len {
            trailing_free
        } else if force {
            // Do not shrink the database to zero size
            min(last_allocator_len - 1, trailing_free)
        } else {
            trailing_free / 2
        };

        let mut new_layout = layout;
        new_layout.reduce_last_region(reduce_by);
        state.allocators_mut().resize_to(new_layout);
        assert!(new_layout.len() <= layout.len());
        state.header.set_layout(new_layout);

        Ok(true)
    }

    fn grow(&self, state: &mut InMemoryState, required_order_allocation: u8) -> Result<()> {
        let layout = state.header.layout();
        let required_growth =
            2u64.pow(required_order_allocation.into()) * u64::from(state.header.page_size());
        let max_region_size = u64::from(state.header.layout().full_region_layout().num_pages())
            * u64::from(state.header.page_size());
        let next_desired_size = if layout.num_full_regions() > 0 {
            if let Some(trailing) = layout.trailing_region_layout() {
                if 2 * required_growth < max_region_size - trailing.usable_bytes() {
                    // Fill out the trailing region
                    layout.usable_bytes() + (max_region_size - trailing.usable_bytes())
                } else {
                    // Fill out trailing & Grow by 1 region
                    layout.usable_bytes() + 2 * max_region_size - trailing.usable_bytes()
                }
            } else {
                // Grow by 1 region
                layout.usable_bytes() + max_region_size
            }
        } else {
            max(
                layout.usable_bytes() * 2,
                layout.usable_bytes() + required_growth * 2,
            )
        };
        let new_layout = DatabaseLayout::calculate(
            next_desired_size,
            state.header.layout().full_region_layout().num_pages(),
            state
                .header
                .layout()
                .full_region_layout()
                .get_header_pages(),
            self.page_size,
        );
        assert!(new_layout.len() >= layout.len());

        self.storage.resize(new_layout.len())?;
        // Make the larger file durable before its layout can reach the on-disk header. A
        // subsequent commit writes this layout into the header, whose layout fields are shared by
        // both commit slots; if a crash persisted that header but not the file extension, every
        // open would fail with "File truncated below stored layout" even though the previous
        // durable state was intact. This mirrors the shrink path, which reduces the file only
        // after the smaller layout is durable.
        self.storage.sync_file()?;

        state.allocators_mut().resize_to(new_layout);
        state.header.set_layout(new_layout);
        Ok(())
    }

    fn allocate<'txn>(
        &self,
        allocation_size: usize,
        allocated: &PageTracker,
    ) -> Result<PageMut<'txn>> {
        let result = self.allocate_helper(allocation_size, false);
        if let Ok(ref page) = result {
            allocated.insert(page.get_page_number());
        }
        result
    }

    fn allocate_lowest<'txn>(
        &self,
        allocation_size: usize,
        allocated: &PageTracker,
    ) -> Result<PageMut<'txn>> {
        let result = self.allocate_helper(allocation_size, true);
        if let Ok(ref page) = result {
            allocated.insert(page.get_page_number());
        }
        result
    }

    pub(crate) fn count_allocated_pages(&self) -> Result<u64> {
        let state = self.state.lock().unwrap();
        let mut count = 0u64;
        for i in 0..state.header.layout().num_regions() {
            count += u64::from(state.get_region(i).count_allocated_pages());
        }

        Ok(count)
    }

    pub(crate) fn count_free_pages(&self) -> Result<u64> {
        let state = self.state.lock().unwrap();
        let mut count = 0u64;
        for i in 0..state.header.layout().num_regions() {
            count += u64::from(state.get_region(i).count_free_pages());
        }

        Ok(count)
    }

    pub(crate) fn get_page_size(&self) -> usize {
        self.page_size.try_into().unwrap()
    }

    pub(crate) fn prepare_close(&self) -> Result {
        self.flush_shutdown_header()
            .and_then(|()| self.settle_growth())
    }

    pub(crate) fn close(&self) -> Result {
        let shutdown_result = self.prepare_close();
        // The backend's close() contract guarantees it is called exactly once, so it must be
        // called even if the shutdown writes above failed
        let close_result = self.storage.close();
        shutdown_result.and(close_result)
    }

    fn flush_shutdown_header(&self) -> Result {
        if self.storage.check_io_errors().is_ok() && !crate::panicking() {
            let mut state = self.state.lock()?;
            // Clearing the flag asserts that this process left the file consistent, which requires
            // an allocator state describing what it wrote. Without one there is nothing to assert.
            if state.allocators.is_some() {
                // Preserve a new physical failure; a failed flush cannot be
                // replaced by the subsequent already-fenced settlement error.
                self.storage.flush()?;
                state.header.recovery_required = false;
                self.write_header(&state.header)?;
                self.storage.flush()?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::tree_store::page_store::page_manager::INITIAL_REGIONS;
    use crate::{Database, TableDefinition};

    // Test that the region tracker expansion code works, by adding more data than fits into the initial max regions
    #[test]
    fn out_of_regions() {
        let tmpfile = crate::create_tempfile();
        let table_definition: TableDefinition<u32, &[u8]> = TableDefinition::new("x");
        let page_size = 1024;
        let big_value = vec![0u8; 5 * page_size];

        let db = Database::builder(crate::test_admission())
            .set_region_size((8 * page_size).try_into().unwrap())
            .set_page_size(page_size)
            .create(tmpfile.path())
            .unwrap();

        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(table_definition).unwrap();
            for i in 0..=INITIAL_REGIONS {
                table.insert(&i, big_value.as_slice()).unwrap();
            }
        }
        txn.commit().unwrap();
        drop(db);

        let mut db = Database::builder(crate::test_admission())
            .set_region_size((8 * page_size).try_into().unwrap())
            .set_page_size(page_size)
            .open(tmpfile.path())
            .unwrap();
        assert!(db.check_integrity().unwrap());
    }

    // Make sure the database remains consistent after a panic
    #[test]
    #[cfg(panic = "unwind")]
    fn panic() {
        let tmpfile = crate::create_tempfile();
        let table_definition: TableDefinition<u32, &[u8]> = TableDefinition::new("x");

        let _ = std::panic::catch_unwind(|| {
            let db = Database::create(&tmpfile, crate::test_admission()).unwrap();
            let txn = db.begin_write().unwrap();
            txn.open_table(table_definition).unwrap();
            panic!();
        });

        let mut db = Database::open(tmpfile, crate::test_admission()).unwrap();
        assert!(db.check_integrity().unwrap());
    }

    // A panic raised while the state mutex is held (e.g. an allocator assertion) poisons it.
    // invalidate_allocator_state() runs while unwinding from such a panic, so it must recover
    // the lock rather than double-panic; the poison itself is left set.
    #[test]
    #[cfg(panic = "unwind")]
    fn invalidate_allocator_state_tolerates_poison() {
        use super::TransactionalMemory;
        use crate::tree_store::InMemoryBackend;

        let mem = TransactionalMemory::new(
            Box::new(InMemoryBackend::new()),
            crate::test_admission(),
            true,
            4096,
            None,
            0,
        )
        .unwrap();
        mem.reset_allocator_state().unwrap();

        std::thread::scope(|s| {
            let result = s
                .spawn(|| {
                    let _guard = mem.state.lock().unwrap();
                    panic!("poison the state mutex");
                })
                .join();
            assert!(result.is_err());
        });
        assert!(mem.state.is_poisoned());

        // Must not panic, despite the poisoned lock
        mem.invalidate_allocator_state();

        // The poison stays set, so later accesses fail rather than trust the state
        assert!(mem.state.is_poisoned());
        assert!(mem.get_last_committed_transaction_id().is_err());
    }

    // Rebuilding the allocator state feeds mark_page_allocated() page numbers straight out of the
    // freed tables, which no page walk ever reads. A corrupted entry has to be reported rather than
    // indexing the region allocators, tripping the bitmap's bounds assertion, or walking the buddy
    // allocator past its maximum order. See https://github.com/cberner/redb/issues/1333
    #[test]
    fn mark_page_allocated_rejects_corrupt_page_numbers() {
        use super::{MAX_PAGE_INDEX, TransactionalMemory};
        use crate::StorageError;
        use crate::tree_store::page_store::base::MAX_REGIONS;
        use crate::tree_store::{InMemoryBackend, PageNumber};

        let page_size = 4096;
        let mem = TransactionalMemory::new(
            Box::new(InMemoryBackend::new()),
            crate::test_admission(),
            true,
            page_size,
            Some(64 * page_size as u64),
            0,
        )
        .unwrap();
        mem.reset_allocator_state().unwrap();

        let corrupt = [
            // Past the end of the layout, which would index the region allocators out of bounds
            PageNumber::new(MAX_REGIONS - 1, 0, 0),
            // Past the end of its region, which the bitmap asserts on
            PageNumber::new(0, MAX_PAGE_INDEX, 0),
            // An order no region can have
            PageNumber::from_le_bytes((31u64 << 59).to_le_bytes()),
        ];
        for page in corrupt {
            assert!(
                matches!(
                    mem.mark_page_allocated(page),
                    Err(StorageError::Corrupted(_))
                ),
                "{page:?} was not rejected"
            );
        }

        // Naming the same page twice walks the allocator up past its maximum order looking for a
        // parent to split
        mem.mark_page_allocated(PageNumber::new(0, 0, 0)).unwrap();
        assert!(matches!(
            mem.mark_page_allocated(PageNumber::new(0, 0, 0)),
            Err(StorageError::Corrupted(_))
        ));
    }

    // A page order read from a corrupted file can be far larger than any real page, which the read
    // path would use to size its buffer.
    #[test]
    fn oversized_page_order_is_rejected() {
        use super::TransactionalMemory;
        use crate::StorageError;
        use crate::tree_store::page_store::base::PageHint;
        use crate::tree_store::{InMemoryBackend, Page, PageNumber, PageTracker};

        let page_size = 4096;
        let mem = TransactionalMemory::new(
            Box::new(InMemoryBackend::new()),
            crate::test_admission(),
            true,
            page_size,
            Some(64 * page_size as u64),
            0,
        )
        .unwrap();
        mem.reset_allocator_state().unwrap();

        let valid = mem.allocate_helper(1, false).unwrap();
        let valid_page = valid.get_page_number();
        drop(valid);

        // order = 31, which would be read as a 2^31 page (8TiB) allocation
        let bad_order = PageNumber::from_le_bytes((31u64 << 59).to_le_bytes());

        assert!(matches!(
            mem.get_page(bad_order, PageHint::None),
            Err(StorageError::Corrupted(_))
        ));
        assert!(matches!(
            mem.mark_page_allocated(bad_order),
            Err(StorageError::Corrupted(_))
        ));
        mem.get_page(valid_page, PageHint::None).unwrap();

        mem.free(valid_page, &PageTracker::ignore());
    }

    // Freeing pages that buddy-merge into a higher order must re-mark the region tracker at the
    // merged order. Otherwise the tracker stays marked full at that order, find_free skips the
    // region even though a free block exists, and the file grows (and compact() stalls) instead of
    // reusing the space.
    #[test]
    fn free_merge_remarks_region_tracker() {
        use super::TransactionalMemory;
        use crate::tree_store::{InMemoryBackend, Page, PageTracker};

        // Small pages and regions keep the reproduction cheap to set up.
        let page_size = 128 * 1024;
        let region_size = 16 * page_size as u64;
        let mem = TransactionalMemory::new(
            Box::new(InMemoryBackend::new()),
            crate::test_admission(),
            true,
            page_size,
            Some(region_size),
            0,
        )
        .unwrap();
        mem.reset_allocator_state().unwrap();

        let ignore = PageTracker::ignore();

        // Fill region 0 with order-0 pages. The allocation that spills past region 0 fails on it
        // first, which marks region 0 full at every order.
        let mut region0_pages = vec![];
        loop {
            let page = mem.allocate_helper(1, false).unwrap();
            let number = page.get_page_number();
            drop(page);
            if number.region == 0 {
                region0_pages.push(number);
            } else {
                // First page past region 0: it has done its job of forcing region 0 full. Give it
                // back so the spilled-into region is left entirely free.
                mem.free(number, &ignore);
                break;
            }
        }
        assert!(
            region0_pages.len() >= 2,
            "test needs at least two pages in region 0, got {}",
            region0_pages.len()
        );

        // Free everything in region 0. The order-0 pages buddy-merge back into larger blocks, so
        // region 0 regains free space above order 0.
        for page in region0_pages {
            mem.free(page, &ignore);
        }

        // An order-1 allocation must reuse region 0's merged free block. Before the fix the tracker
        // still marked region 0 full above order 0, so find_free skipped it and this landed in a
        // higher region.
        let reused = mem.allocate_helper(2 * page_size, false).unwrap();
        assert_eq!(
            reused.get_page_number().region,
            0,
            "order-1 allocation should reuse the merged free block in region 0"
        );
    }
}
