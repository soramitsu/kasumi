use crate::sync::Mutex;
use crate::tree_store::page_store::cached_file::WritablePage;
#[cfg(debug_assertions)]
use crate::tree_store::page_store::fast_hash::PageNumberHashMap;
use crate::tree_store::page_store::fast_hash::PageNumberHashSet;
use crate::tree_store::page_store::page_manager::MAX_MAX_PAGE_ORDER;
use crate::{Result, StorageError};
use alloc::string::ToString;
use alloc::sync::Arc;
use core::cmp::Ordering;
use core::fmt::{Debug, Formatter};
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;
use core::mem;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

pub(crate) const MAX_VALUE_LENGTH: usize = 3 * 1024 * 1024 * 1024;
pub(crate) const MAX_PAIR_LENGTH: usize = 3 * 1024 * 1024 * 1024 + 768 * 1024 * 1024;
pub(crate) const MAX_PAGE_INDEX: u32 = 0x000F_FFFF;
pub(crate) const MAX_REGIONS: u32 = 0x0010_0000;

// On-disk format is:
// TODO: consider implementing an optimization in which we store the number of order-0 pages that
// are actually used, in these reserved bits, so that the reads to the PagedCachedFile layer can avoid
// reading all the zeros at the end of the page.
// lowest 20bits: page index within the region. Only the lowest `20 - order_exponent` bits may be read.
// The remaining bits and bits 40..59 are reserved and must be zero.
// second 20bits: region number
// 19bits: reserved
// highest 5bits: page order exponent
//
// Assuming a reasonable page size, like 4kiB, this allows for 4kiB * 2^20 * 2^20 = 4PiB of usable space
#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) struct PageNumber {
    region: u32,
    page_index: u32,
    page_order: u8,
}

impl Hash for PageNumber {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut temp = u64::from(self.page_index);
        temp |= u64::from(self.region) << 20;
        temp |= u64::from(self.page_order) << 59;
        state.write_u64(temp);
    }
}

// PageNumbers are ordered as determined by their starting address in the database file
impl Ord for PageNumber {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.region.cmp(&other.region) {
            Ordering::Less => Ordering::Less,
            Ordering::Equal => {
                let self_order0 = self.page_index * 2u32.pow(self.page_order.into());
                let other_order0 = other.page_index * 2u32.pow(other.page_order.into());
                assert!(
                    self_order0 != other_order0 || self.page_order == other.page_order,
                    "{self:?} overlaps {other:?}, but is not equal"
                );
                self_order0.cmp(&other_order0)
            }
            Ordering::Greater => Ordering::Greater,
        }
    }
}

impl PartialOrd for PageNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PageNumber {
    pub(crate) const fn serialized_size() -> usize {
        8
    }

    pub(crate) const fn new(region: u32, page_index: u32, page_order: u8) -> Self {
        assert!(region < MAX_REGIONS);
        assert!(page_order <= MAX_MAX_PAGE_ORDER);
        assert!(page_index <= MAX_PAGE_INDEX >> page_order);
        Self {
            region,
            page_index,
            page_order,
        }
    }

    pub(crate) fn to_le_bytes(self) -> [u8; 8] {
        let mut temp = u64::from(self.page_index);
        temp |= u64::from(self.region) << 20;
        temp |= u64::from(self.page_order) << 59;
        temp.to_le_bytes()
    }

    // This is the sole raw decoder. A PageNumber always carries the canonical
    // representation proof, including when it reaches an infallible free path.
    pub(crate) fn from_le_bytes(bytes: [u8; 8]) -> Result<Self> {
        let raw = u64::from_le_bytes(bytes);
        let order = (raw >> 59) as u8;
        let index =
            u32::try_from(raw & u64::from(MAX_PAGE_INDEX)).expect("masked page index fits in u32");
        if order > MAX_MAX_PAGE_ORDER
            || raw & (0x7_FFFF_u64 << 40) != 0
            || index > MAX_PAGE_INDEX >> order
        {
            return Err(StorageError::Corrupted(
                "Noncanonical page number".to_string(),
            ));
        }
        Ok(Self::new(((raw >> 20) & 0xF_FFFF) as u32, index, order))
    }

    pub(crate) const fn region(self) -> u32 {
        self.region
    }
    pub(crate) const fn page_index(self) -> u32 {
        self.page_index
    }
    pub(crate) const fn page_order(self) -> u8 {
        self.page_order
    }

    #[cfg(test)]
    pub(crate) fn to_order0(self) -> Vec<PageNumber> {
        let mut pages = vec![self];
        loop {
            let mut progress = false;
            let mut new_pages = vec![];
            for page in pages {
                if page.page_order == 0 {
                    new_pages.push(page);
                } else {
                    progress = true;
                    new_pages.push(PageNumber::new(
                        page.region,
                        page.page_index * 2,
                        page.page_order - 1,
                    ));
                    new_pages.push(PageNumber::new(
                        page.region,
                        page.page_index * 2 + 1,
                        page.page_order - 1,
                    ));
                }
            }
            pages = new_pages;
            if !progress {
                break;
            }
        }

        pages
    }

    pub(crate) fn address_range(
        &self,
        data_section_offset: u64,
        region_size: u64,
        region_pages_start: u64,
        page_size: u32,
    ) -> Range<u64> {
        let regional_start =
            region_pages_start + u64::from(self.page_index) * self.page_size_bytes(page_size);
        debug_assert!(regional_start < region_size);
        let region_base = u64::from(self.region) * region_size;
        let start = data_section_offset + region_base + regional_start;
        let end = start + self.page_size_bytes(page_size);
        start..end
    }

    pub(crate) fn page_size_bytes(&self, page_size: u32) -> u64 {
        let pages = 1u64 << self.page_order;
        pages * u64::from(page_size)
    }
}

impl Debug for PageNumber {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "r{}.{}/{}",
            self.region, self.page_index, self.page_order
        )
    }
}

pub(crate) trait Page {
    fn memory(&self) -> &[u8];

    fn get_page_number(&self) -> PageNumber;
}

pub struct PageImpl {
    pub(super) mem: Arc<[u8]>,
    pub(super) page_number: PageNumber,
    #[cfg(debug_assertions)]
    pub(super) open_pages: Arc<Mutex<PageNumberHashMap<u64>>>,
}

impl PageImpl {
    pub(crate) fn to_arc(&self) -> Arc<[u8]> {
        self.mem.clone()
    }
}

impl Debug for PageImpl {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("PageImpl: page_number={:?}", self.page_number))
    }
}

#[cfg(debug_assertions)]
impl Drop for PageImpl {
    fn drop(&mut self) {
        let mut open_pages = self.open_pages.lock().unwrap();
        let value = open_pages.get_mut(&self.page_number).unwrap();
        assert!(*value > 0);
        *value -= 1;
        if *value == 0 {
            open_pages.remove(&self.page_number);
        }
    }
}

impl Page for PageImpl {
    fn memory(&self) -> &[u8] {
        self.mem.as_ref()
    }

    fn get_page_number(&self) -> PageNumber {
        self.page_number
    }
}

impl Clone for PageImpl {
    fn clone(&self) -> Self {
        #[cfg(debug_assertions)]
        {
            *self
                .open_pages
                .lock()
                .unwrap()
                .get_mut(&self.page_number)
                .unwrap() += 1;
        }
        Self {
            mem: self.mem.clone(),
            page_number: self.page_number,
            #[cfg(debug_assertions)]
            open_pages: self.open_pages.clone(),
        }
    }
}

// The lifetime should be bound to the lifetime of the transaction in which this page was opened.
// It is used in the Drop impl to ensure that the page is dropped before the transaction is committed.
pub(crate) struct PageMut<'txn> {
    pub(super) mem: WritablePage,
    pub(super) page_number: PageNumber,
    pub(super) _lifetime: PhantomData<&'txn ()>,
    #[cfg(debug_assertions)]
    pub(super) open_pages: Arc<Mutex<PageNumberHashSet>>,
}

impl PageMut<'_> {
    pub(crate) fn memory_mut(&mut self) -> &mut [u8] {
        self.mem.mem_mut()
    }
}

impl Page for PageMut<'_> {
    fn memory(&self) -> &[u8] {
        self.mem.mem()
    }

    fn get_page_number(&self) -> PageNumber {
        self.page_number
    }
}

impl Drop for PageMut<'_> {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        assert!(self.open_pages.lock().unwrap().remove(&self.page_number));
    }
}

#[derive(Copy, Clone)]
pub(crate) enum PageHint {
    None,
    // Not dirtied by the in-progress write transaction. May still be in the write buffer, if a
    // non-durable commit left committed pages there.
    Clean,
}

enum PageTrackerPolicy {
    Ignore,
    Track(PageNumberHashSet),
    Closed,
}

impl PageTrackerPolicy {
    pub(crate) fn new_tracking() -> Self {
        PageTrackerPolicy::Track(PageNumberHashSet::default())
    }

    pub(crate) fn is_empty(&self) -> bool {
        match self {
            PageTrackerPolicy::Ignore | PageTrackerPolicy::Closed => true,
            PageTrackerPolicy::Track(x) => x.is_empty(),
        }
    }

    pub(super) fn remove(&mut self, page: PageNumber) {
        match self {
            PageTrackerPolicy::Ignore => {}
            PageTrackerPolicy::Track(x) => {
                assert!(x.remove(&page));
            }
            PageTrackerPolicy::Closed => {
                panic!("Page tracker is closed");
            }
        }
    }

    pub(super) fn insert(&mut self, page: PageNumber) {
        match self {
            PageTrackerPolicy::Ignore => {}
            PageTrackerPolicy::Track(x) => {
                assert!(x.insert(page));
            }
            PageTrackerPolicy::Closed => {
                panic!("Page tracker is closed");
            }
        }
    }

    pub(crate) fn close(&mut self) -> PageNumberHashSet {
        let old = mem::replace(self, PageTrackerPolicy::Closed);
        match old {
            PageTrackerPolicy::Ignore => PageNumberHashSet::default(),
            PageTrackerPolicy::Track(x) => x,
            PageTrackerPolicy::Closed => {
                panic!("Page tracker is closed");
            }
        }
    }

    pub(crate) fn reset(&mut self) -> PageNumberHashSet {
        if matches!(self, PageTrackerPolicy::Ignore) {
            return PageNumberHashSet::default();
        }
        let old = mem::replace(self, PageTrackerPolicy::Track(PageNumberHashSet::default()));
        match old {
            PageTrackerPolicy::Ignore => PageNumberHashSet::default(),
            PageTrackerPolicy::Track(x) => x,
            PageTrackerPolicy::Closed => {
                panic!("Page tracker is closed");
            }
        }
    }
}

/// The pages a write transaction has allocated, shared by all of its tables.
///
/// Only savepoint restore needs this set, so a transaction with no savepoint tracks nothing.
/// That is the common case, and tables of one transaction may be written from different threads,
/// so it must not cost a lock on every allocation: `tracking` is checked first, and the mutex is
/// touched only while tracking is on. The flag is relaxed because nothing is ordered against it --
/// a writer that misses a concurrent `disable()` merely records a page into a set that is about to
/// be discarded, and one that sees it early skips a page nothing will read.
pub(crate) struct PageTracker {
    tracking: AtomicBool,
    policy: Mutex<PageTrackerPolicy>,
}

impl PageTracker {
    pub(crate) fn new_tracking() -> Self {
        let policy = Mutex::new(PageTrackerPolicy::new_tracking());
        // A first native mutex lock may allocate; close/drop must not be first.
        drop(policy.lock().unwrap());
        Self {
            tracking: AtomicBool::new(true),
            policy,
        }
    }

    pub(crate) fn ignore() -> Self {
        Self {
            tracking: AtomicBool::new(false),
            policy: Mutex::new(PageTrackerPolicy::Ignore),
        }
    }

    pub(crate) fn closed() -> Self {
        let policy = Mutex::new(PageTrackerPolicy::Closed);
        drop(policy.lock().unwrap());
        Self {
            tracking: AtomicBool::new(true),
            policy,
        }
    }

    fn tracking(&self) -> bool {
        self.tracking.load(AtomicOrdering::Relaxed)
    }

    /// Stops tracking, discarding what was recorded. Called once no savepoint can observe the
    /// pages, after which the tracker never tracks again for the rest of the transaction:
    /// `reset()` leaves `Ignore` alone, and `close()` only moves to the poisoned `Closed` state.
    pub(crate) fn disable(&self) {
        *self.policy.lock().unwrap() = PageTrackerPolicy::Ignore;
        self.tracking.store(false, AtomicOrdering::Relaxed);
    }

    pub(crate) fn insert(&self, page: PageNumber) {
        if self.tracking() {
            self.policy.lock().unwrap().insert(page);
        }
    }

    pub(crate) fn remove(&self, page: PageNumber) {
        if self.tracking() {
            self.policy.lock().unwrap().remove(page);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        !self.tracking() || self.policy.lock().unwrap().is_empty()
    }

    // Leaves the tracker in the `Closed` state, where any further use panics. `tracking` stays
    // set so that those uses reach the policy rather than being skipped.
    pub(crate) fn close(&self) -> Result<PageNumberHashSet> {
        self.tracking.store(true, AtomicOrdering::Relaxed);
        Ok(self.policy.lock()?.close())
    }

    pub(crate) fn reset(&self) -> PageNumberHashSet {
        self.policy.lock().unwrap().reset()
    }
}

#[cfg(test)]
mod test {
    use crate::tree_store::PageNumber;

    #[test]
    fn last_page() {
        let region_data_size = 2u64.pow(32);
        let page_size = 4096;
        let pages_per_region = region_data_size / page_size;
        let region_header_size = 2u64.pow(16);
        let last_page_index = pages_per_region - 1;
        let page_number = PageNumber::new(1, last_page_index.try_into().unwrap(), 0);
        page_number.address_range(
            4096,
            region_data_size + region_header_size,
            region_header_size,
            page_size.try_into().unwrap(),
        );
    }

    #[test]
    fn reserved_bits() {
        let page_number = PageNumber::new(0, 0, 12);
        let mut bytes = page_number.to_le_bytes();
        bytes[1] = 0xFF;
        let page_number2 = PageNumber::from_le_bytes(bytes);
        assert!(matches!(
            page_number2,
            Err(crate::StorageError::Corrupted(_))
        ));
    }

    #[test]
    fn canonical_page_number_preserves_all_orders_and_rejects_each_alias_bit() {
        use super::{MAX_PAGE_INDEX, MAX_REGIONS};
        use crate::tree_store::page_store::page_manager::MAX_MAX_PAGE_ORDER;
        for order in 0..=MAX_MAX_PAGE_ORDER {
            let max_index = MAX_PAGE_INDEX >> order;
            for region in [0, 1, MAX_REGIONS - 1] {
                for index in [0, max_index / 2, max_index] {
                    let page = PageNumber::new(region, index, order);
                    let bytes = page.to_le_bytes();
                    let (decoded, allocations) = crate::admission::observe_test_allocations(|| {
                        PageNumber::from_le_bytes(bytes)
                    });
                    assert_eq!(allocations, 0);
                    let decoded = decoded.unwrap();
                    assert_eq!(decoded, page);
                    assert_eq!(decoded.to_le_bytes(), bytes);
                    let raw = u64::from_le_bytes(bytes);
                    let mut combined = raw;
                    for bit in (40..59).chain((20 - u32::from(order))..20) {
                        let alias = raw | (1_u64 << bit);
                        assert!(matches!(
                            PageNumber::from_le_bytes(alias.to_le_bytes()),
                            Err(crate::StorageError::Corrupted(_))
                        ));
                        combined |= 1_u64 << bit;
                    }
                    assert!(PageNumber::from_le_bytes(combined.to_le_bytes()).is_err());
                }
            }
        }
        for order in 21_u64..32 {
            assert!(PageNumber::from_le_bytes((order << 59).to_le_bytes()).is_err());
        }
    }

    #[test]
    fn canonical_page_number_accepts_actual_buddy_producers_after_resize_and_free() {
        use super::{MAX_PAGE_INDEX, MAX_REGIONS};
        use crate::tree_store::page_store::buddy_allocator::BuddyAllocator;
        let capacity = MAX_PAGE_INDEX + 1;
        let mut allocator = BuddyAllocator::new(capacity, capacity);
        for size in [capacity, capacity / 2, capacity] {
            allocator.resize(size);
            let max_order = u8::try_from(size.ilog2()).unwrap();
            for order in 0..=max_order {
                let index = allocator.alloc(order).unwrap();
                for region in [0, 1, MAX_REGIONS - 1] {
                    let page = PageNumber::new(region, index, order);
                    assert_eq!(PageNumber::from_le_bytes(page.to_le_bytes()).unwrap(), page);
                }
                allocator.free(index, order);
            }
        }
    }
}
