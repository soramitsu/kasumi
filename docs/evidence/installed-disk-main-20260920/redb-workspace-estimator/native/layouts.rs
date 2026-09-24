#![allow(dead_code)]
use std::sync::{Arc,Mutex};
use std::collections::HashMap;
pub struct PageNumber {
    pub region: u32,
    pub page_index: u32,
    pub page_order: u8,
}
pub struct BtreeBitmap {
    heights: Vec<U64GroupedBitmap>,
}
pub struct U64GroupedBitmap {
    len: u32,
    data: Vec<u64>,
}
pub struct BuddyAllocator {
    free: Vec<BtreeBitmap>,
    len: u32,
    max_order: u8,
}
pub struct RegionTracker {
    order_trackers: Vec<BtreeBitmap>,
}
pub struct Allocators {
    pub region_tracker: RegionTracker,
    pub region_allocators: Vec<BuddyAllocator>,
}
pub struct PageImpl {
    pub mem: Arc<[u8]>,
    pub page_number: PageNumber,
    #[cfg(debug_assertions)]
    pub open_pages: Arc<Mutex<HashMap<PageNumber,u64>>>,
}
pub type Checksum=u128;
pub struct BtreeHeader {
    pub root: PageNumber,
    pub checksum: Checksum,
    pub length: u64,
}
