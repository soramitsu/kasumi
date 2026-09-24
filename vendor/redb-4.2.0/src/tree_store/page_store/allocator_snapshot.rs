//! Borrowed validation of the sole allocator snapshot representation.
//! No decoded allocator or serialized copy is allocated by these checks.
use super::base::MAX_REGIONS;
use super::layout::DatabaseLayout;
use super::page_manager::{INITIAL_REGIONS, MAX_MAX_PAGE_ORDER};
use crate::transaction_tracker::TransactionId;
use crate::transactions::AllocatorStateKey;
use crate::{Result, StorageError};

const ORDERS: usize = MAX_MAX_PAGE_ORDER as usize + 1;
// A region and the region inventory each contain at most 2^20 entries.
const BITMAP_HEIGHT: usize = 4;

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn usize_at(bytes: &[u8], offset: usize) -> Option<usize> {
    usize::try_from(u32_at(bytes, offset)?).ok()
}
fn malformed() -> StorageError {
    StorageError::Corrupted("Invalid canonical allocator snapshot payload or layout".into())
}
fn height_for_capacity(mut capacity: u32) -> usize {
    let mut height = 1;
    while capacity > 64 {
        capacity = capacity.div_ceil(64);
        height += 1;
    }
    height
}

#[derive(Clone, Copy)]
struct Level<'a> {
    words: &'a [u8],
    len: u32,
}
impl<'a> Level<'a> {
    fn checked(bytes: &'a [u8], expected_len: u32) -> Option<Self> {
        if u32_at(bytes, 0)? != expected_len {
            return None;
        }
        let words = usize::try_from(expected_len.div_ceil(64)).ok()?;
        if bytes.len() != 4_usize.checked_add(words.checked_mul(8)?)? {
            return None;
        }
        let level = Self {
            words: bytes.get(4..)?,
            len: expected_len,
        };
        // The actual allocator producers start full, change only logical bits,
        // and record removed extents allocated before shrinking buddy bitmaps.
        // Generic U64GroupedBitmap::resize alone does not establish this rule.
        // The canonical tracker never shrinks its bitmap length. Both producers
        // therefore keep non-logical bits of their last serialized word full.
        if !expected_len.is_multiple_of(64) {
            let last = level.word(words - 1);
            let logical = (1_u64 << (expected_len % 64)) - 1;
            if last | logical != u64::MAX {
                return None;
            }
        }
        Some(level)
    }
    fn word(self, index: usize) -> u64 {
        // The view's exact logical word count was checked before construction.
        let start = index * 8;
        u64::from_le_bytes(self.words[start..start + 8].try_into().unwrap())
    }
    fn get(self, index: u32) -> bool {
        debug_assert!(index < self.len);
        self.word(index as usize / 64) & (1_u64 << (index % 64)) != 0
    }
    fn all_full_from(self, start: u32) -> bool {
        if start >= self.len {
            return true;
        }
        let first = start as usize / 64;
        let mask = u64::MAX << (start % 64);
        self.word(first) & mask == mask
            && ((first + 1)..self.words.len() / 8).all(|index| self.word(index) == u64::MAX)
    }
}

#[derive(Clone, Copy)]
struct Bitmap<'a> {
    leaf: Level<'a>,
}
impl<'a> Bitmap<'a> {
    fn checked(bytes: &'a [u8], len: u32, capacity: u32) -> Option<Self> {
        if len > capacity {
            return None;
        }
        let height = height_for_capacity(capacity);
        if height > BITMAP_HEIGHT || usize_at(bytes, 0)? != height {
            return None;
        }
        let mut lengths = [0; BITMAP_HEIGHT];
        let mut level_len = len;
        for length in lengths[..height].iter_mut().rev() {
            *length = level_len;
            level_len = level_len.div_ceil(64);
        }
        let mut start = 4_usize.checked_add(height.checked_mul(4)?)?;
        let mut previous: Option<Level<'a>> = None;
        for (index, &length) in lengths[..height].iter().enumerate() {
            let end = usize_at(bytes, 4 + index * 4)?;
            let level = Level::checked(bytes.get(start..end)?, length)?;
            if let Some(parent) = previous {
                for word in 0..level.words.len() / 8 {
                    if parent.get(u32::try_from(word).ok()?) != (level.word(word) == u64::MAX) {
                        return None;
                    }
                }
            }
            previous = Some(level);
            start = end;
        }
        if start != bytes.len() {
            return None;
        }
        Some(Self { leaf: previous? })
    }
}

struct Buddy<'a> {
    orders: [Option<Bitmap<'a>>; ORDERS],
    len: u32,
    max_order: u8,
}
impl<'a> Buddy<'a> {
    fn checked(bytes: &'a [u8], capacity: u32) -> Option<Self> {
        if capacity == 0 || capacity > (1 << MAX_MAX_PAGE_ORDER) {
            return None;
        }
        let max_order = u8::try_from(capacity.ilog2()).ok()?;
        if *bytes.first()? != max_order || bytes.get(1..4)? != [0; 3] {
            return None;
        }
        let len = u32_at(bytes, 4)?;
        if len == 0 || len > capacity {
            return None;
        }
        let mut orders = [None; ORDERS];
        let mut start = 8 + (usize::from(max_order) + 1) * 4;
        for order in 0..=max_order {
            let end = usize_at(bytes, 8 + usize::from(order) * 4)?;
            orders[usize::from(order)] = Some(Bitmap::checked(
                bytes.get(start..end)?,
                len >> order,
                capacity >> order,
            )?);
            start = end;
        }
        if start != bytes.len() {
            return None;
        }
        let buddy = Self {
            orders,
            len,
            max_order,
        };
        // Each free block has exactly one order. Two free buddies must already
        // have merged, and no free ancestor may overlap any free descendant.
        for order in 0..=max_order {
            let leaf = buddy.bitmap(order).leaf;
            for word in 0..leaf.words.len() / 8 {
                let mut free = !leaf.word(word);
                while free != 0 {
                    let index = u32::try_from(word).ok()? * 64 + free.trailing_zeros();
                    if order < max_order {
                        let sibling = index ^ 1;
                        if sibling < leaf.len && !leaf.get(sibling) {
                            return None;
                        }
                    }
                    for ancestor in order + 1..=max_order {
                        let parent_index = index >> (ancestor - order);
                        let parent = buddy.bitmap(ancestor).leaf;
                        if parent_index < parent.len && !parent.get(parent_index) {
                            return None;
                        }
                    }
                    free &= free - 1;
                }
            }
        }
        Some(buddy)
    }
    fn bitmap(&self, order: u8) -> Bitmap<'a> {
        self.orders[usize::from(order)].unwrap()
    }
    fn suffix_free(&self, mut start: u32) -> bool {
        while start < self.len {
            let mut end = None;
            for order in 0..=self.max_order {
                let index = start >> order;
                let leaf = self.bitmap(order).leaf;
                if index < leaf.len && !leaf.get(index) {
                    end = Some((index + 1) << order);
                    break;
                }
            }
            let Some(next) = end else {
                return false;
            };
            start = next;
        }
        true
    }
}

fn tracker_checked(bytes: &[u8], regions: u32) -> Option<()> {
    if usize_at(bytes, 0)? != ORDERS {
        return None;
    }
    let mut start = 4 + ORDERS * 4;
    let mut tracker_len = None;
    for order in 0..ORDERS {
        let end = start.checked_add(usize_at(bytes, 4 + order * 4)?)?;
        let bitmap_bytes = bytes.get(start..end)?;
        // The final layer length is itself checked below against the full
        // nested shape; reading it here neither allocates nor follows a pointer.
        let height = height_for_capacity(MAX_REGIONS);
        if usize_at(bitmap_bytes, 0)? != height {
            return None;
        }
        let leaf_start = if height == 1 {
            8
        } else {
            usize_at(bitmap_bytes, 4 + (height - 2) * 4)?
        };
        let len = u32_at(bitmap_bytes, leaf_start)?;
        if len < INITIAL_REGIONS.max(regions) || len > MAX_REGIONS {
            return None;
        }
        if tracker_len.is_some_and(|previous| previous != len) {
            return None;
        }
        tracker_len = Some(len);
        let bitmap = Bitmap::checked(bitmap_bytes, len, MAX_REGIONS)?;
        // An optimistic free marker may name an existing region even when that
        // order is actually full. It must never name an absent region.
        if !bitmap.leaf.all_full_from(regions) {
            return None;
        }
        start = end;
    }
    (start == bytes.len()).then_some(())
}

/// Incremental validation while the raw tree visits canonical records in order.
/// This owns only scalar geometry; every payload view dies with its page borrow.
pub(crate) struct AllocatorSnapshotValidation {
    layout: DatabaseLayout,
    winner: TransactionId,
    regions: u32,
    last_region_pages: Option<u32>,
    tracker: bool,
    transaction: Option<TransactionId>,
    contraction_is_free: bool,
}
impl AllocatorSnapshotValidation {
    pub(super) fn new(layout: DatabaseLayout, winner: TransactionId) -> Self {
        Self {
            layout,
            winner,
            regions: 0,
            last_region_pages: None,
            tracker: false,
            transaction: None,
            contraction_is_free: true,
        }
    }
    pub(crate) fn record(&mut self, key: AllocatorStateKey, value: &[u8]) -> Result {
        let capacity = self.layout.full_region_layout().num_pages();
        match key {
            AllocatorStateKey::Region(index) => {
                if self.tracker
                    || self.transaction.is_some()
                    || index != self.regions
                    || index >= MAX_REGIONS
                    || self
                        .last_region_pages
                        .is_some_and(|pages| pages != capacity)
                {
                    return Err(malformed());
                }
                let buddy = Buddy::checked(value, capacity).ok_or_else(malformed)?;
                let retained_pages = if index < self.layout.num_regions() {
                    self.layout.region_layout(index).num_pages()
                } else {
                    0
                };
                self.contraction_is_free &= buddy.suffix_free(retained_pages);
                self.last_region_pages = Some(buddy.len);
                self.regions += 1;
            }
            AllocatorStateKey::RegionTracker => {
                if self.regions == 0 || self.tracker || self.transaction.is_some() {
                    return Err(malformed());
                }
                tracker_checked(value, self.regions).ok_or_else(malformed)?;
                self.tracker = true;
            }
            AllocatorStateKey::TransactionId => {
                if !self.tracker || self.transaction.is_some() {
                    return Err(malformed());
                }
                self.transaction = Some(TransactionId::new(u64::from_le_bytes(
                    value.try_into().map_err(|_| malformed())?,
                )));
            }
        }
        Ok(())
    }
    pub(crate) fn finish(self) -> Result {
        // No snapshot is a supported repair trigger. A nonempty snapshot must
        // contain its complete canonical record set even when its stamp is stale.
        if self.regions == 0 && !self.tracker && self.transaction.is_none() {
            return Ok(());
        }
        let transaction = self.transaction.ok_or_else(malformed)?;
        if !self.tracker || transaction == self.winner && !self.contraction_is_free {
            return Err(malformed());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::observe_test_allocations;
    use crate::tree_store::page_store::buddy_allocator::BuddyAllocator;
    use crate::tree_store::page_store::layout::RegionLayout;
    use crate::tree_store::page_store::region::{Allocators, RegionTracker};
    use alloc::vec;
    use alloc::vec::Vec;

    fn verify_buddy(allocator: &BuddyAllocator, capacity: u32) {
        let bytes = allocator.to_vec();
        let (result, allocations) = observe_test_allocations(|| Buddy::checked(&bytes, capacity));
        assert_eq!(allocations, 0);
        assert!(
            result.is_some(),
            "capacity={capacity}, len={}",
            allocator.len()
        );
        let decoded = BuddyAllocator::from_bytes(&bytes);
        assert_eq!(decoded.to_vec(), bytes);
        assert_eq!(decoded.xxh3_hash(), allocator.xxh3_hash());
    }

    #[test]
    fn checked_buddy_payload_accepts_actual_producers_for_all_orders_and_resizes() {
        for max_order in 0..=MAX_MAX_PAGE_ORDER {
            let capacity = 1 << max_order;
            for initial in [1, 17, 65, 4097, capacity] {
                let mut allocator = BuddyAllocator::new(initial.min(capacity), capacity);
                verify_buddy(&allocator, capacity);
                let mut pages = Vec::new();
                for order in 0..=max_order {
                    if let Some(page) = allocator.alloc(order) {
                        pages.push((page, order));
                    }
                }
                verify_buddy(&allocator, capacity);
                for &(page, order) in pages.iter().rev() {
                    allocator.free(page, order);
                }
                verify_buddy(&allocator, capacity);
                allocator.resize(capacity);
                verify_buddy(&allocator, capacity);
                for size in [capacity.min(4097), capacity.min(65), capacity.min(17), 1] {
                    allocator.resize(size);
                    verify_buddy(&allocator, capacity);
                }
                allocator.resize(capacity);
                verify_buddy(&allocator, capacity);
            }
        }
    }

    fn layout(regions: u32, trailing_pages: u32, capacity: u32) -> DatabaseLayout {
        DatabaseLayout::new(
            regions - 1,
            RegionLayout::new(capacity, 0, 4096),
            Some(RegionLayout::new(trailing_pages, 0, 4096)),
        )
    }
    fn validate_snapshot(
        allocators: &Allocators,
        current: DatabaseLayout,
        stamp: TransactionId,
        winner: TransactionId,
    ) -> Result {
        let regions: Vec<_> = allocators
            .region_allocators
            .iter()
            .map(BuddyAllocator::to_vec)
            .collect();
        let tracker = allocators.region_tracker.to_vec();
        let stamp = stamp.raw_id().to_le_bytes();
        let (result, allocations) = observe_test_allocations(|| {
            let mut validation = AllocatorSnapshotValidation::new(current, winner);
            for (index, region) in regions.iter().enumerate() {
                validation.record(
                    AllocatorStateKey::Region(u32::try_from(index).unwrap()),
                    region,
                )?;
            }
            validation.record(AllocatorStateKey::RegionTracker, &tracker)?;
            validation.record(AllocatorStateKey::TransactionId, &stamp)?;
            validation.finish()
        });
        if result.is_ok() {
            assert_eq!(allocations, 0);
        }
        result
    }

    #[test]
    fn snapshot_validation_accepts_canonical_shrink_extension_and_retained_tracker_capacity() {
        let winner = TransactionId::new(11);
        let original = layout(2, 65, 128);
        let mut allocators = Allocators::new(original);
        validate_snapshot(&allocators, original, winner, winner).unwrap();
        // The snapshot is saved before commit's last-region shrink.
        validate_snapshot(&allocators, layout(2, 17, 128), winner, winner).unwrap();
        validate_snapshot(&allocators, layout(1, 128, 128), winner, winner).unwrap();
        // A physical extension can precede publication of the enlarged snapshot.
        validate_snapshot(&allocators, layout(3, 65, 128), winner, winner).unwrap();
        allocators.resize_to(layout(1001, 17, 128));
        validate_snapshot(&allocators, layout(1001, 17, 128), winner, winner).unwrap();
        allocators.resize_to(layout(1, 65, 128));
        validate_snapshot(&allocators, layout(1, 65, 128), winner, winner).unwrap();
        allocators.resize_to(layout(2, 65, 128));
        validate_snapshot(&allocators, layout(2, 65, 128), winner, winner).unwrap();
    }

    #[test]
    fn snapshot_current_winner_cannot_discard_allocated_suffix_but_stale_snapshot_can_repair() {
        let winner = TransactionId::new(11);
        let mut allocators = Allocators::new(layout(2, 65, 128));
        assert!(allocators.region_allocators[1].record_alloc(64, 0));
        assert!(matches!(
            validate_snapshot(&allocators, layout(2, 17, 128), winner, winner),
            Err(StorageError::Corrupted(_))
        ));
        validate_snapshot(
            &allocators,
            layout(2, 17, 128),
            TransactionId::new(10),
            winner,
        )
        .unwrap();
        assert!(matches!(
            validate_snapshot(&allocators, layout(1, 128, 128), winner, winner),
            Err(StorageError::Corrupted(_))
        ));
    }

    #[test]
    fn checked_snapshot_rejects_missing_out_of_sequence_and_partial_interior_regions() {
        let winner = TransactionId::new(11);
        let current = layout(2, 65, 128);
        let bytes = BuddyAllocator::new(65, 128).to_vec();
        let mut validation = AllocatorSnapshotValidation::new(current, winner);
        assert!(
            validation
                .record(AllocatorStateKey::Region(1), &bytes)
                .is_err()
        );
        let mut validation = AllocatorSnapshotValidation::new(current, winner);
        validation
            .record(AllocatorStateKey::Region(0), &bytes)
            .unwrap();
        assert!(
            validation
                .record(AllocatorStateKey::Region(1), &bytes)
                .is_err()
        );
        assert!(validation.finish().is_err());
        let mut validation = AllocatorSnapshotValidation::new(current, winner);
        assert!(
            validation
                .record(AllocatorStateKey::TransactionId, &[0; 8])
                .is_err()
        );
        let mut validation = AllocatorSnapshotValidation::new(current, winner);
        assert!(
            validation
                .record(AllocatorStateKey::RegionTracker, &[0; 8])
                .is_err()
        );
        AllocatorSnapshotValidation::new(current, winner)
            .finish()
            .unwrap();
    }

    #[test]
    fn checked_buddy_payload_rejects_truncation_offsets_dimensions_and_inconsistent_free_bits() {
        let bytes = BuddyAllocator::new(65, 128).to_vec();
        for end in 0..bytes.len() {
            let (result, allocations) =
                observe_test_allocations(|| Buddy::checked(&bytes[..end], 128));
            assert_eq!(allocations, 0);
            assert!(result.is_none(), "accepted truncation at {end}");
        }
        for (offset, replacement) in [(0, 255), (1, 1), (4, 0), (8, 0)] {
            let mut bad = bytes.clone();
            bad[offset] = replacement;
            assert!(
                Buddy::checked(&bad, 128).is_none(),
                "accepted field offset {offset}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Buddy::checked(&trailing, 128).is_none());
        let mut bad = bytes.clone();
        bad[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Buddy::checked(&bad, 128).is_none());
        let first_bitmap = 8 + (usize::from(bytes[0]) + 1) * 4;
        let mut bad = bytes.clone();
        bad[first_bitmap..first_bitmap + 4].copy_from_slice(&0_u32.to_le_bytes());
        assert!(Buddy::checked(&bad, 128).is_none());

        // A one-page region has one bitmap, one leaf word, and no summary layer.
        let mut padding = BuddyAllocator::new(1, 1).to_vec();
        *padding.last_mut().unwrap() = 0;
        assert!(Buddy::checked(&padding, 1).is_none());
        // In a two-page allocator the root free block covers both pages. A free
        // order-0 bit would overlap it, even when the bitmap itself is well formed.
        let mut overlap = BuddyAllocator::new(2, 2).to_vec();
        let order0 = 8 + 2 * 4;
        let leaf_word = order0 + 8 + 4;
        overlap[leaf_word] &= !1;
        assert!(Buddy::checked(&overlap, 2).is_none());
        // A free child word cannot have a full summary bit.
        let mut summary = bytes.clone();
        let first_level = first_bitmap + 4 + 2 * 4;
        summary[first_level + 4] |= 2;
        assert!(Buddy::checked(&summary, 128).is_none());
    }

    #[test]
    fn checked_tracker_accepts_actual_region_boundaries_and_rejects_absent_free_regions() {
        for regions in [INITIAL_REGIONS, 4096, 4097, MAX_REGIONS] {
            let mut tracker = RegionTracker::new(regions, MAX_MAX_PAGE_ORDER + 1);
            tracker.mark_free(0, 0);
            tracker.mark_free(MAX_MAX_PAGE_ORDER, regions - 1);
            let bytes = tracker.to_vec();
            let (valid, allocations) =
                observe_test_allocations(|| tracker_checked(&bytes, regions));
            assert_eq!(allocations, 0);
            assert_eq!(valid, Some(()));
            assert!(tracker_checked(&bytes, regions - 1).is_none());
            for end in [0, 3, 4, 4 + ORDERS * 4, bytes.len() - 1] {
                assert!(tracker_checked(&bytes[..end], regions).is_none());
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(tracker_checked(&trailing, regions).is_none());
        }
        let mut tracker = RegionTracker::new(INITIAL_REGIONS, MAX_MAX_PAGE_ORDER + 1);
        tracker.mark_free(0, 1);
        assert!(tracker_checked(&tracker.to_vec(), 1).is_none());
        let mut wrong_orders = tracker.to_vec();
        wrong_orders[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(tracker_checked(&wrong_orders, 2).is_none());
        let empty: Vec<u8> = vec![];
        assert!(tracker_checked(&empty, 0).is_none());
    }
}
