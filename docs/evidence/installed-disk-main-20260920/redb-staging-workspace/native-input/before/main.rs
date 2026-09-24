extern crate alloc;
mod tree_store {
 #[derive(Hash,Eq,PartialEq)] pub struct PageNumber(u64);
 pub mod page_store {
  pub mod fast_hash { include!("/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/redb-staging-workspace/native-input/vendor/redb-4.2.0/src/tree_store/page_store/fast_hash.rs"); }
  pub mod lru_cache { include!("/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/redb-staging-workspace/native-input/before/lru_cache.rs"); }
 }
}
thread_local! {
    static OBSERVING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
struct Observed;
#[global_allocator]
static ALLOCATOR: Observed = Observed;
fn allocation() {
    let _ = OBSERVING.try_with(|active| if active.get() {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
    });
}
unsafe impl std::alloc::GlobalAlloc for Observed {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        allocation();
        unsafe { std::alloc::System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        allocation();
        unsafe { std::alloc::System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        allocation();
        unsafe { std::alloc::System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}
#[test]
fn exact_removal_path_performs_no_heap_allocation() {
    let mut cache = tree_store::page_store::lru_cache::LRUCache::new();
    for key in 0..256 { cache.insert(key, key); }
    ALLOCATIONS.with(|count| count.set(0));
    OBSERVING.with(|active| active.set(true));
    let mut sum = 0;
    for key in 0..256 { sum += cache.remove(key).unwrap(); }
    OBSERVING.with(|active| active.set(false));
    let allocations = ALLOCATIONS.with(std::cell::Cell::get);
    assert_eq!(sum, 255 * 256 / 2);
    assert_eq!(allocations, 0);
    assert_eq!(cache.len(), 0);
}
