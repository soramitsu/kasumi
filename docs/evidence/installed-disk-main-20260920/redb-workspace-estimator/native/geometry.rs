//! Requested-allocation geometry for the pinned std implementation.
//! This module is a proposal component, NOT a complete redb admission estimate.
use std::alloc::Layout;
use std::mem::{align_of, size_of};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Heap {
    pub bytes: usize,
    pub allocations: usize,
}
impl Heap {
    pub fn add(self, other: Self) -> Option<Self> {
        Some(Self {
            bytes: self.bytes.checked_add(other.bytes)?,
            allocations: self.allocations.checked_add(other.allocations)?,
        })
    }
    pub fn times(self, n: usize) -> Option<Self> {
        Some(Self {
            bytes: self.bytes.checked_mul(n)?,
            allocations: self.allocations.checked_mul(n)?,
        })
    }
    pub fn charge(self, per_allocation_allowance: usize) -> Option<usize> {
        self.bytes.checked_add(self.allocations.checked_mul(per_allocation_allowance)?)
    }
}

pub fn block(bytes: usize) -> Option<Heap> {
    if bytes > isize::MAX as usize { return None; }
    Some(Heap { bytes, allocations: usize::from(bytes != 0) })
}

pub fn exact_array<T>(count: usize) -> Option<Heap> {
    block(Layout::array::<T>(count).ok()?.size())
}

/// All reserve/with_capacity requests, including speculative reserve calls,
/// must be at most `maximum_requested_elements`. This is NOT just max len.
pub fn vector<T>(maximum_requested_elements: usize, reallocating: bool) -> Option<Heap> {
    if size_of::<T>() == 0 || maximum_requested_elements == 0 { return Some(Heap::default()); }
    let minimum = if size_of::<T>() == 1 { 8 } else if size_of::<T>() <= 1024 { 4 } else { 1 };
    let cap = maximum_requested_elements.checked_mul(2)?.max(minimum);
    exact_array::<T>(cap)?.times(if reallocating { 2 } else { 1 })
}

/// Exact ArcInner allocation shape, with padding for the true T alignment.
pub fn arc<T>() -> Option<Heap> {
    let layout = Layout::array::<usize>(2).ok()?.extend(Layout::new::<T>()).ok()?.0.pad_to_align();
    block(layout.size())
}

pub fn arc_bytes(count: usize) -> Option<Heap> {
    let layout = Layout::array::<usize>(2).ok()?.extend(Layout::array::<u8>(count).ok()?).ok()?.0.pad_to_align();
    block(layout.size())
}

/// Pinned hashbrown 0.17.1. `maximum_entries` also bounds every reserve request.
/// Tombstone churn may grow at >half full despite low len, hence 2*m.
pub fn hash<T>(maximum_entries: usize, group_width: usize, reallocating: bool) -> Option<Heap> {
    if maximum_entries == 0 { return Some(Heap::default()); }
    if !matches!(group_width, 8 | 16) { return None; }
    let cap = maximum_entries.checked_mul(2)?;
    let buckets = if cap < 15 {
        let minimum = match (group_width, size_of::<T>()) {
            (16, 0..=1) => 14,
            (16, 2..=3) | (8, 0..=1) => 7,
            _ => 3,
        };
        let cap = cap.max(minimum);
        if cap < 4 { 4 } else if cap < 8 { 8 } else { 16 }
    } else {
        (cap.checked_mul(8)? / 7).checked_next_power_of_two()?
    };
    let align = align_of::<T>().max(group_width);
    let data = size_of::<T>().checked_mul(buckets)?;
    let offset = data.checked_add(align - 1)? & !(align - 1);
    let bytes = offset.checked_add(buckets)?.checked_add(group_width)?;
    Layout::from_size_align(bytes, align).ok()?;
    block(bytes)?.times(if reallocating { 2 } else { 1 })
}

/// Layout upper bound for the pinned BTree node fields, independent of repr(Rust)
/// field reordering. An internal node includes 12 child pointers. All fields
/// have alignment <= max(pointer,K,V), so adding one alignment unit per field
/// conservatively covers every possible padding hole.
pub fn btree_node<K, V>() -> Option<Heap> {
    let alignment = align_of::<K>().max(align_of::<V>()).max(align_of::<usize>());
    let bytes = size_of::<usize>().checked_add(4)?
        .checked_add(11usize.checked_mul(size_of::<K>().checked_add(size_of::<V>())?)?)?
        .checked_add(12usize.checked_mul(size_of::<usize>())?)?
        .checked_add(7usize.checked_mul(alignment - 1)?)?;
    block(bytes.checked_add(alignment - 1)? & !(alignment - 1))
}

/// Each stable nonempty node owns at least one entry; add one root and one
/// split sibling per possible ancestor while an insertion is in progress.
pub fn btree<K, V>(maximum_entries: usize) -> Option<Heap> {
    if maximum_entries == 0 { return Some(Heap::default()); }
    let height = usize::BITS as usize - maximum_entries.leading_zeros() as usize;
    btree_node::<K, V>()?.times(maximum_entries.checked_add(height)?.checked_add(1)?)
}
