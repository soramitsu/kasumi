//! Conservative allocation-layout envelope of both live allocator copies.
use crate::{geometry::{Heap, exact_array, vector}, layouts::*};
pub const PAGE: usize = 4096;
pub const REGION_PAGES: usize = 1 << 20;
pub const ORDERS: usize = 21;

#[derive(Clone, Copy, Debug)]
pub struct Shape {
    pub heap: Heap,
    pub encoded: usize,
    pub serialization_peak: Heap,
}

pub fn bitmap(mut n: usize, mut q: usize) -> Option<Shape> {
    let mut levels = 0usize;
    let mut heap = Heap::default();
    let mut serialized_levels = Heap::default();
    let mut encoded = 4usize;
    loop {
        levels = levels.checked_add(1)?;
        let words = n.div_ceil(64);
        heap = heap.add(vector::<u64>(words, false)?)?;
        let level_bytes = words.checked_mul(8)?.checked_add(4)?;
        serialized_levels = serialized_levels.add(exact_array::<u8>(level_bytes)?)?;
        encoded = encoded.checked_add(4)?.checked_add(level_bytes)?;
        if q <= 64 { break; }
        n = n.div_ceil(64);
        q = q.div_ceil(64);
    }
    heap = heap.add(vector::<U64GroupedBitmap>(levels, false)?)?;
    // Bitmap::to_vec retains all level images while the result grows. Count
    // both old and new result allocations; all Vec headers remain resident.
    let serialization_peak = serialized_levels
        .add(vector::<Vec<u8>>(levels, false)?)?
        .add(vector::<u8>(encoded, true)?)?;
    Some(Shape { heap, encoded, serialization_peak })
}

pub fn buddy(pages: usize) -> Option<Shape> {
    if pages > REGION_PAGES { return None; }
    let mut heap = vector::<BtreeBitmap>(ORDERS, false)?;
    let mut encoded = 8usize.checked_add(4usize.checked_mul(ORDERS)?)?;
    let mut serialized = vector::<Vec<u8>>(ORDERS, false)?;
    let mut nested = Heap::default();
    for order in 0..ORDERS {
        let bitmap = bitmap(pages >> order, REGION_PAGES >> order)?;
        heap = heap.add(bitmap.heap)?;
        encoded = encoded.checked_add(bitmap.encoded)?;
        // Completed bitmap images retain amortized Vec capacity.
        serialized = serialized.add(vector::<u8>(bitmap.encoded, false)?)?;
        nested.bytes = nested.bytes.max(bitmap.serialization_peak.bytes);
        nested.allocations = nested.allocations.max(bitmap.serialization_peak.allocations);
    }
    // Holding every finished bitmap image plus the largest nested temporary
    // overcounts its finished slot, intentionally. Final buddy image uses
    // exact with_capacity and does not reallocate.
    let serialization_peak = serialized.add(nested)?.add(exact_array::<u8>(encoded)?)?;
    Some(Shape { heap, encoded, serialization_peak })
}

pub fn tracker(regions: usize) -> Option<Shape> {
    let bitmap = bitmap(regions.max(1000), REGION_PAGES)?;
    let heap = vector::<BtreeBitmap>(ORDERS, false)?.add(bitmap.heap.times(ORDERS)?)?;
    let encoded = 4usize.checked_add(4usize.checked_mul(ORDERS)?)?
        .checked_add(bitmap.encoded.checked_mul(ORDERS)?)?;
    let serialization_peak = vector::<u32>(ORDERS, false)?
        .add(bitmap.serialization_peak)?
        .add(vector::<u8>(encoded, true)?)?;
    Some(Shape { heap, encoded, serialization_peak })
}

#[derive(Debug)]
pub struct AllocatorEnvelope {
    pub base_pages: usize,
    pub regions: usize,
    pub resident: Heap,
    /// Resident + prepared commit copy + largest serialized working set +
    /// preallocated zero-image + region-length inventory. Deliberately counts
    /// mutually exclusive reserve/save temporaries together, never just bytes.
    pub simultaneous_commit: Heap,
    pub largest_region_image: usize,
    pub tracker_image: usize,
}
pub fn allocators(disk: usize) -> Option<AllocatorEnvelope> {
    let n = disk.div_ceil(PAGE);
    if n == 0 || n > REGION_PAGES.checked_mul(REGION_PAGES)? { return None; }
    let regions = n.div_ceil(REGION_PAGES);
    let tracker = tracker(regions)?;
    let mut resident = vector::<BuddyAllocator>(regions, false)?.add(tracker.heap)?;
    let mut serialization = tracker.serialization_peak;
    let mut largest_region_image = 0;
    for region in 0..regions {
        let shape = buddy(n.saturating_sub(region * REGION_PAGES).min(REGION_PAGES))?;
        resident = resident.add(shape.heap)?;
        serialization.bytes = serialization.bytes.max(shape.serialization_peak.bytes);
        serialization.allocations = serialization.allocations.max(shape.serialization_peak.allocations);
        largest_region_image = largest_region_image.max(shape.encoded);
    }
    let simultaneous_commit = resident.times(2)?
        .add(serialization)?
        .add(exact_array::<u8>(largest_region_image.max(tracker.encoded))?)?
        .add(vector::<usize>(regions, false)?)?;
    Some(AllocatorEnvelope { base_pages:n, regions, resident, simultaneous_commit,
        largest_region_image, tracker_image:tracker.encoded })
}
