use crate::tree_store::page_store::base::MAX_REGIONS;
use crate::tree_store::page_store::bitmap::{
    AllocatorEncodingError, BtreeBitmap, check_encoding_buffer,
};
use crate::tree_store::page_store::buddy_allocator::BuddyAllocator;
use crate::tree_store::page_store::layout::DatabaseLayout;
use crate::tree_store::page_store::page_manager::{INITIAL_REGIONS, MAX_MAX_PAGE_ORDER};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::{self, max};
use core::mem::size_of;

// Unlike bitmap/buddy metadata, this header stores individual u32 lengths,
// not absolute end offsets. The aggregate only needs to fit usize.
fn checked_length_encoded_len(
    prefix_bytes: usize,
    mut children: impl ExactSizeIterator<Item = Option<usize>>,
) -> Option<usize> {
    u32::try_from(children.len()).ok()?;
    let metadata = children.len().checked_mul(size_of::<u32>())?;
    let header = prefix_bytes.checked_add(metadata)?;
    children.try_fold(header, |total, child| {
        let len = child?;
        u32::try_from(len).ok()?;
        total.checked_add(len)
    })
}

// Tracks the page orders that MAY BE free in each region. This data structure is optimistic, so
// a region may not actually have a page free for a given order
pub(crate) struct RegionTracker {
    order_trackers: Vec<BtreeBitmap>,
}

impl RegionTracker {
    pub(crate) fn new(regions: u32, orders: u8) -> Self {
        let mut data = vec![];
        for _ in 0..orders {
            data.push(BtreeBitmap::new_padded(regions, regions, MAX_REGIONS));
        }
        Self {
            order_trackers: data,
        }
    }

    // Format:
    // num_orders: u32 number of order allocators
    // allocator_lens: u32 length of each allocator
    // data: BtreeBitmap data for each order
    /// Exact serialized length without creating any order bitmap image.
    pub(super) fn checked_encoded_len(&self) -> Option<usize> {
        checked_length_encoded_len(
            size_of::<u32>(),
            self.order_trackers
                .iter()
                .map(BtreeBitmap::checked_encoded_len),
        )
    }

    /// Encode exactly the current canonical tracker into caller-owned backing.
    /// All nested geometry and output-length checks precede the first write.
    // The complete preflight checks each stored u32 field before any write;
    // the immutable borrow preserves those checked values throughout encoding.
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn encode_into(&self, output: &mut [u8]) -> Result<(), AllocatorEncodingError> {
        check_encoding_buffer(self.checked_encoded_len(), output.len())?;
        let header_len = size_of::<u32>() + self.order_trackers.len() * size_of::<u32>();
        let (header, mut remaining) = output.split_at_mut(header_len);
        header[..size_of::<u32>()]
            .copy_from_slice(&(self.order_trackers.len() as u32).to_le_bytes());
        for (length, bitmap) in header[size_of::<u32>()..]
            .chunks_exact_mut(size_of::<u32>())
            .zip(&self.order_trackers)
        {
            let written = bitmap.write_encoded_validated(remaining);
            length.copy_from_slice(&(written as u32).to_le_bytes());
            remaining = &mut remaining[written..];
        }
        Ok(())
    }

    pub(super) fn to_vec(&self) -> Vec<u8> {
        // The existing infallible internal API rejects invalid geometry before
        // allocating output. The checked caller-buffer API returns a scalar error.
        let Some(encoded_len) = self.checked_encoded_len() else {
            panic!("Invalid region tracker encoding geometry");
        };
        let mut result = vec![0; encoded_len];
        if let Err(error) = self.encode_into(&mut result) {
            panic!("Validated region tracker encoding failed: {error:?}");
        }
        result
    }

    #[cfg(test)]
    pub(super) fn reference_to_vec(&self) -> Vec<u8> {
        let mut result = vec![];
        let orders: u32 = self.order_trackers.len().try_into().unwrap();
        let allocator_lens: Vec<u32> = self
            .order_trackers
            .iter()
            .map(|x| x.reference_to_vec().len().try_into().unwrap())
            .collect();
        result.extend(orders.to_le_bytes());
        for allocator_len in allocator_lens {
            result.extend(allocator_len.to_le_bytes());
        }
        for order in &self.order_trackers {
            result.extend(&order.reference_to_vec());
        }
        result
    }

    pub(super) fn from_bytes(page: &[u8]) -> Self {
        let orders = u32::from_le_bytes(page[..size_of::<u32>()].try_into().unwrap());
        let mut start = size_of::<u32>();
        let mut allocator_lens = vec![];
        for _ in 0..orders {
            let allocator_len =
                u32::from_le_bytes(page[start..start + size_of::<u32>()].try_into().unwrap())
                    as usize;
            allocator_lens.push(allocator_len);
            start += size_of::<u32>();
        }
        let mut data = vec![];
        for allocator_len in allocator_lens {
            data.push(BtreeBitmap::from_bytes(
                &page[start..(start + allocator_len)],
            ));
            start += allocator_len;
        }

        Self {
            order_trackers: data,
        }
    }

    pub(crate) fn find_free(&self, order: u8) -> Option<u32> {
        self.order_trackers[order as usize].find_first_unset()
    }

    pub(crate) fn mark_free(&mut self, order: u8, region: u32) {
        let order: usize = order.into();
        for i in 0..=order {
            self.order_trackers[i].clear(region);
        }
    }

    pub(crate) fn mark_full(&mut self, order: u8, region: u32) {
        let order: usize = order.into();
        assert!(order < self.order_trackers.len());
        for i in order..self.order_trackers.len() {
            self.order_trackers[i].set(region);
        }
    }

    fn resize(&mut self, new_capacity: u32) {
        for order in &mut self.order_trackers {
            order.resize(new_capacity, true);
        }
    }

    fn len(&self) -> u32 {
        self.order_trackers[0].len()
    }
}

pub(super) struct Allocators {
    pub(super) region_tracker: RegionTracker,
    pub(super) region_allocators: Vec<BuddyAllocator>,
}

impl Allocators {
    pub(super) fn new(layout: DatabaseLayout) -> Self {
        let mut region_allocators = vec![];
        let initial_regions = max(INITIAL_REGIONS, layout.num_regions());
        let mut region_tracker = RegionTracker::new(initial_regions, MAX_MAX_PAGE_ORDER + 1);
        for i in 0..layout.num_regions() {
            let region_layout = layout.region_layout(i);
            let allocator = BuddyAllocator::new(
                region_layout.num_pages(),
                layout.full_region_layout().num_pages(),
            );
            let max_order = allocator.get_max_order();
            region_tracker.mark_free(max_order, i);
            region_allocators.push(allocator);
        }

        Self {
            region_tracker,
            region_allocators,
        }
    }

    pub(crate) fn xxh3_hash(&self) -> u128 {
        // Ignore the region tracker because it is an optimistic cache, and so may not match
        // between repairs of the allocators
        let mut result = 0;
        for allocator in &self.region_allocators {
            result ^= allocator.xxh3_hash();
        }
        result
    }

    pub(super) fn resize_to(&mut self, new_layout: DatabaseLayout) {
        let shrink = match (new_layout.num_regions() as usize).cmp(&self.region_allocators.len()) {
            cmp::Ordering::Less => true,
            cmp::Ordering::Equal => {
                let allocator = self.region_allocators.last().unwrap();
                let last_region = new_layout
                    .trailing_region_layout()
                    .unwrap_or_else(|| new_layout.full_region_layout());
                match last_region.num_pages().cmp(&allocator.len()) {
                    cmp::Ordering::Less => true,
                    cmp::Ordering::Equal => {
                        // No-op
                        return;
                    }
                    cmp::Ordering::Greater => false,
                }
            }
            cmp::Ordering::Greater => false,
        };

        if shrink {
            // Drop all regions that were removed
            for i in new_layout.num_regions()..(self.region_allocators.len().try_into().unwrap()) {
                self.region_tracker.mark_full(0, i);
            }
            self.region_allocators
                .drain((new_layout.num_regions() as usize)..);

            // Resize the last region
            let last_region = new_layout
                .trailing_region_layout()
                .unwrap_or_else(|| new_layout.full_region_layout());
            let allocator = self.region_allocators.last_mut().unwrap();
            if allocator.len() > last_region.num_pages() {
                allocator.resize(last_region.num_pages());
            }
        } else {
            let old_num_regions = self.region_allocators.len();
            for i in 0..new_layout.num_regions() {
                let new_region = new_layout.region_layout(i);
                if (i as usize) < old_num_regions {
                    let allocator = &mut self.region_allocators[i as usize];
                    assert!(new_region.num_pages() >= allocator.len());
                    if new_region.num_pages() != allocator.len() {
                        allocator.resize(new_region.num_pages());
                        let highest_free = allocator.highest_free_order().unwrap();
                        self.region_tracker.mark_free(highest_free, i);
                    }
                } else {
                    // brand new region
                    let allocator = BuddyAllocator::new(
                        new_region.num_pages(),
                        new_layout.full_region_layout().num_pages(),
                    );
                    let highest_free = allocator.highest_free_order().unwrap();
                    if i >= self.region_tracker.len() {
                        self.region_tracker.resize(i + 1);
                    }
                    self.region_tracker.mark_free(highest_free, i);
                    self.region_allocators.push(allocator);
                }
            }
        }
    }
}

#[cfg(test)]
mod encoding_tests {
    use super::RegionTracker;
    use crate::admission::observe_test_allocations;
    use crate::tree_store::page_store::base::MAX_REGIONS;
    use crate::tree_store::page_store::page_manager::{INITIAL_REGIONS, MAX_MAX_PAGE_ORDER};

    #[test]
    fn in_place_tracker_encoding_matches_original_bytes_at_region_boundaries() {
        use crate::tree_store::page_store::bitmap::assert_inplace_encoding_matches;

        for orders in [1, 2, 7, MAX_MAX_PAGE_ORDER + 1] {
            for regions in [
                0,
                1,
                63,
                64,
                65,
                INITIAL_REGIONS - 1,
                INITIAL_REGIONS,
                INITIAL_REGIONS + 1,
                4097,
                MAX_REGIONS,
            ] {
                let mut tracker = RegionTracker::new(regions, orders);
                if regions > 0 {
                    tracker.mark_free(orders - 1, regions - 1);
                    tracker.mark_full(0, 0);
                }
                let expected = tracker.reference_to_vec();
                assert_inplace_encoding_matches(
                    &expected,
                    |output| tracker.encode_into(output),
                    || tracker.to_vec(),
                );
                assert_eq!(RegionTracker::from_bytes(&expected).to_vec(), expected);
            }
        }
        let mut tracker = RegionTracker::new(4097, MAX_MAX_PAGE_ORDER + 1);
        for regions in [65, 0, 64, INITIAL_REGIONS, 4097] {
            tracker.resize(regions);
            assert_inplace_encoding_matches(
                &tracker.reference_to_vec(),
                |output| tracker.encode_into(output),
                || tracker.to_vec(),
            );
        }
    }

    #[test]
    fn in_place_tracker_encoding_rejects_child_geometry_before_writing() {
        use crate::tree_store::page_store::bitmap::{
            BtreeBitmap, assert_invalid_encoding_is_unchanged,
        };

        let malformed = [
            1_u32.to_le_bytes(),
            12_u32.to_le_bytes(),
            65_u32.to_le_bytes(),
        ]
        .concat();
        let tracker = RegionTracker {
            order_trackers: vec![BtreeBitmap::from_bytes(&malformed)],
        };
        assert_invalid_encoding_is_unchanged(|output| tracker.encode_into(output));
    }

    #[test]
    fn checked_tracker_length_arithmetic_handles_field_and_total_limits() {
        use super::checked_length_encoded_len;
        use core::iter::{empty, once, repeat_n};

        let (outcomes, allocations) = observe_test_allocations(|| {
            [
                checked_length_encoded_len(4, empty()),
                checked_length_encoded_len(4, once(Some(u32::MAX as usize))),
                checked_length_encoded_len(usize::MAX, once(Some(0))),
                checked_length_encoded_len(usize::MAX - 8, once(Some(5))),
                checked_length_encoded_len(4, once(Some(usize::MAX))),
                checked_length_encoded_len(4, once(None)),
                checked_length_encoded_len(4, repeat_n(Some(0), usize::MAX)),
            ]
        });
        assert_eq!(allocations, 0);
        // A valid individual length may put the aggregate past u32::MAX on
        // wider targets; only the child length is an on-disk u32 field.
        let largest_child = (u32::MAX as usize).checked_add(8);
        assert_eq!(
            outcomes,
            [Some(4), largest_child, None, None, None, None, None]
        );
    }

    #[test]
    fn checked_tracker_lengths_match_bytes_at_region_and_order_boundaries() {
        for orders in [1, 2, 7, MAX_MAX_PAGE_ORDER + 1] {
            for regions in [
                0,
                1,
                63,
                64,
                65,
                INITIAL_REGIONS - 1,
                INITIAL_REGIONS,
                INITIAL_REGIONS + 1,
                4097,
                MAX_REGIONS,
            ] {
                let mut tracker = RegionTracker::new(regions, orders);
                if regions > 0 {
                    tracker.mark_free(orders - 1, regions - 1);
                }
                let bytes = tracker.to_vec();
                let (planned, allocations) =
                    observe_test_allocations(|| tracker.checked_encoded_len());
                assert_eq!(planned, Some(bytes.len()));
                assert_eq!(allocations, 0);
                assert_eq!(tracker.to_vec(), bytes);
                assert_eq!(
                    RegionTracker::from_bytes(&bytes).checked_encoded_len(),
                    planned
                );
            }
        }
        let mut tracker = RegionTracker::new(4097, MAX_MAX_PAGE_ORDER + 1);
        for regions in [65, 0, 64, INITIAL_REGIONS, 4097] {
            tracker.resize(regions);
            let bytes = tracker.to_vec();
            let (planned, allocations) = observe_test_allocations(|| tracker.checked_encoded_len());
            assert_eq!(planned, Some(bytes.len()));
            assert_eq!(allocations, 0);
        }
    }
}
