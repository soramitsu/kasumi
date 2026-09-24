from pathlib import Path
P=Path('target/installed-disk-validation/redb-allocator-in-place-encoding/proposed/vendor/redb-4.2.0/src/tree_store/page_store')
p=P/'bitmap.rs';s=p.read_text();anchor='''#[cfg(test)]
mod test {''';assert s.count(anchor)==1
helper='''#[cfg(test)]
pub(super) fn assert_inplace_encoding_matches(
    expected: &[u8],
    encode: impl Fn(&mut [u8]) -> Result<(), AllocatorEncodingError>,
    collect: impl FnOnce() -> Vec<u8>,
) {
    use crate::admission::observe_test_allocations;

    let mut guarded = vec![0xa5; expected.len() + 8];
    let (result, allocations) =
        observe_test_allocations(|| encode(&mut guarded[4..4 + expected.len()]));
    assert_eq!(result, Ok(()));
    assert_eq!(allocations, 0);
    assert_eq!(&guarded[4..4 + expected.len()], expected);
    assert_eq!(&guarded[..4], &[0xa5; 4]);
    assert_eq!(&guarded[4 + expected.len()..], &[0xa5; 4]);

    for size in [0, expected.len() - 1, expected.len() + 1] {
        let mut destination = vec![0xa5; size];
        let (result, allocations) = observe_test_allocations(|| encode(&mut destination));
        assert_eq!(result, Err(AllocatorEncodingError::WrongBufferLength));
        assert_eq!(allocations, 0);
        assert!(destination.iter().all(|byte| *byte == 0xa5));
    }

    let (bytes, allocations) = observe_test_allocations(collect);
    assert_eq!(allocations, 1);
    assert_eq!(bytes, expected);
}

#[cfg(test)]
pub(super) fn assert_invalid_encoding_is_unchanged(
    encode: impl Fn(&mut [u8]) -> Result<(), AllocatorEncodingError>,
) {
    let mut destination = [0xa5; 128];
    let (result, allocations) =
        crate::admission::observe_test_allocations(|| encode(&mut destination));
    assert_eq!(result, Err(AllocatorEncodingError::InvalidGeometry));
    assert_eq!(allocations, 0);
    assert_eq!(destination, [0xa5; 128]);
}

'''
s=s.replace(anchor,helper+anchor,1)
anchor='''    #[test]
    fn checked_encoded_lengths_match_serializers_without_allocating() {''';assert s.count(anchor)==1
new='''    #[test]
    fn in_place_grouped_encoding_matches_original_bytes_without_allocation() {
        use super::{U64GroupedBitmap, assert_inplace_encoding_matches};

        for len in [0, 1, 63, 64, 65, 4095, 4096, 4097, 65_537] {
            let mut bitmap = U64GroupedBitmap::new_full(len, len + 127);
            if len > 0 {
                bitmap.clear(0);
                bitmap.clear(len - 1);
            }
            let checksum = bitmap.xxh3_hash();
            assert_inplace_encoding_matches(
                &bitmap.reference_to_vec(),
                |output| bitmap.encode_into(output),
                || bitmap.to_vec(),
            );
            assert_eq!(bitmap.xxh3_hash(), checksum);
        }
    }

    #[test]
    fn in_place_bitmap_encoding_matches_original_bytes_across_resize() {
        use super::assert_inplace_encoding_matches;

        let mut bitmap = BtreeBitmap::new_padded(65_537, 65_537, 1 << 20);
        for len in [65_537, 4097, 65, 0, 1, 63, 64, 4095, 4096, 65_537] {
            bitmap.resize(len, true);
            if len > 0 {
                bitmap.clear(0);
                bitmap.clear(len - 1);
            }
            let checksum = bitmap.xxh3_hash();
            let expected = bitmap.reference_to_vec();
            assert_inplace_encoding_matches(
                &expected,
                |output| bitmap.encode_into(output),
                || bitmap.to_vec(),
            );
            assert_eq!(bitmap.xxh3_hash(), checksum);
            assert_eq!(BtreeBitmap::from_bytes(&expected).to_vec(), expected);
        }
    }

    #[test]
    fn in_place_bitmap_encoding_rejects_geometry_before_writing() {
        use super::{U64GroupedBitmap, assert_invalid_encoding_is_unchanged};

        let grouped = U64GroupedBitmap {
            len: 65,
            data: vec![u64::MAX],
        };
        assert_invalid_encoding_is_unchanged(|output| grouped.encode_into(output));
        let bitmap = BtreeBitmap {
            heights: vec![grouped],
        };
        assert_invalid_encoding_is_unchanged(|output| bitmap.encode_into(output));
    }

'''
s=s.replace(anchor,new+anchor,1);p.write_text(s)
p=P/'buddy_allocator.rs';s=p.read_text();anchor='''    #[test]
    fn checked_encoded_lengths_cover_all_supported_orders_and_mutations() {''';assert s.count(anchor)==1
new='''    #[test]
    fn in_place_buddy_encoding_matches_original_bytes_at_all_supported_orders() {
        use crate::tree_store::page_store::bitmap::assert_inplace_encoding_matches;
        use crate::tree_store::page_store::page_manager::MAX_MAX_PAGE_ORDER;

        for max_order in 0..=MAX_MAX_PAGE_ORDER {
            let capacity = 1_u32 << max_order;
            for pages in [0, 1, capacity / 2, capacity.saturating_sub(1), capacity] {
                let mut allocator = BuddyAllocator::new(pages, capacity);
                if pages > 0 {
                    allocator.alloc(0).unwrap();
                }
                let checksum = allocator.xxh3_hash();
                let expected = allocator.reference_to_vec();
                assert_inplace_encoding_matches(
                    &expected,
                    |output| allocator.encode_into(output),
                    || allocator.to_vec(),
                );
                assert_eq!(allocator.xxh3_hash(), checksum);
                assert_eq!(BuddyAllocator::from_bytes(&expected).to_vec(), expected);
            }
        }
        let mut allocator = BuddyAllocator::new(64, 4096);
        for pages in [65, 4096, 127, 1, 64] {
            allocator.resize(pages);
            assert_inplace_encoding_matches(
                &allocator.reference_to_vec(),
                |output| allocator.encode_into(output),
                || allocator.to_vec(),
            );
        }
    }

    #[test]
    fn in_place_buddy_encoding_rejects_geometry_before_writing() {
        use crate::tree_store::page_store::bitmap::{
            BtreeBitmap, assert_invalid_encoding_is_unchanged,
        };

        let mut missing_order = BuddyAllocator::new(64, 4096);
        missing_order.free.pop();
        assert_invalid_encoding_is_unchanged(|output| missing_order.encode_into(output));

        // A canonical bitmap header with a logical word count beyond its
        // backing. The preflight must reach the child before writing our header.
        let malformed = [1_u32.to_le_bytes(), 12_u32.to_le_bytes(), 65_u32.to_le_bytes()].concat();
        let mut missing_backing = BuddyAllocator::new(64, 4096);
        missing_backing.free[0] = BtreeBitmap::from_bytes(&malformed);
        assert_invalid_encoding_is_unchanged(|output| missing_backing.encode_into(output));
    }

'''
s=s.replace(anchor,new+anchor,1);p.write_text(s)
p=P/'region.rs';s=p.read_text();anchor='''    #[test]
    fn checked_tracker_length_arithmetic_handles_field_and_total_limits() {''';assert s.count(anchor)==1
new='''    #[test]
    fn in_place_tracker_encoding_matches_original_bytes_at_region_boundaries() {
        use crate::tree_store::page_store::bitmap::assert_inplace_encoding_matches;

        for orders in [1, 2, 7, MAX_MAX_PAGE_ORDER + 1] {
            for regions in [0, 1, 63, 64, 65, INITIAL_REGIONS - 1, INITIAL_REGIONS, INITIAL_REGIONS + 1, 4097, MAX_REGIONS] {
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

        let malformed = [1_u32.to_le_bytes(), 12_u32.to_le_bytes(), 65_u32.to_le_bytes()].concat();
        let tracker = RegionTracker {
            order_trackers: vec![BtreeBitmap::from_bytes(&malformed)],
        };
        assert_invalid_encoding_is_unchanged(|output| tracker.encode_into(output));
    }

'''
s=s.replace(anchor,new+anchor,1);p.write_text(s)
print('Prepared seven new tests; no execution')
