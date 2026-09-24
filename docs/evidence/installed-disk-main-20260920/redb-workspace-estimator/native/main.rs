#![allow(dead_code)]
mod geometry;
mod layouts;
mod allocator;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::mem::{align_of, size_of};
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::AtomicBool;
use layouts::*;

#[derive(Clone, Copy, Default, Debug)]
struct Stats { active:bool, live:usize, peak:usize, blocks:usize, peak_blocks:usize, largest:usize }
thread_local! { static STATS:Cell<Stats> = const { Cell::new(Stats {active:false,live:0,peak:0,blocks:0,peak_blocks:0,largest:0}) }; }
struct Observe;
fn add(size:usize) {
    let _ = STATS.try_with(|s| { let mut v=s.get(); if v.active { v.live+=size;v.blocks+=1;v.peak=v.peak.max(v.live);v.peak_blocks=v.peak_blocks.max(v.blocks);v.largest=v.largest.max(size);s.set(v); } });
}
fn sub(size:usize) {
    let _ = STATS.try_with(|s| { let mut v=s.get(); if v.active { v.live-=size;v.blocks-=1;s.set(v); } });
}
unsafe impl GlobalAlloc for Observe {
    unsafe fn alloc(&self,l:Layout)->*mut u8 { let p=unsafe{System.alloc(l)}; if !p.is_null(){add(l.size())} p }
    unsafe fn alloc_zeroed(&self,l:Layout)->*mut u8 { let p=unsafe{System.alloc_zeroed(l)};if !p.is_null(){add(l.size())}p }
    unsafe fn dealloc(&self,p:*mut u8,l:Layout){unsafe{System.dealloc(p,l)};sub(l.size())}
    unsafe fn realloc(&self,p:*mut u8,l:Layout,n:usize)->*mut u8 { let q=unsafe{System.realloc(p,l,n)};if !q.is_null(){add(n);sub(l.size())}q }
}
#[global_allocator] static ALLOC:Observe=Observe;
fn measure(f:impl FnOnce())->Stats {
    STATS.with(|s|s.set(Stats{active:true,..Stats::default()}));
    f();
    STATS.with(|s|{let v=s.get();s.set(Stats::default());assert_eq!(v.live,0);assert_eq!(v.blocks,0);v})
}

#[test]
fn vectors_cover_requested_capacity_and_reallocation() {
    for n in [1,3,4,7,8,15,16,31,257,4097] {
        let observed=measure(||{let mut v=Vec::<u64>::new();for x in 0..n{v.push(x as u64)}});
        assert!(observed.peak<=geometry::vector::<u64>(n,true).unwrap().bytes);
        let observed=measure(||{let mut v=VecDeque::<u64>::new();for x in 0..n{v.push_front(x as u64)}});
        assert!(observed.peak<=geometry::vector::<u64>(n,true).unwrap().bytes);
    }
}

#[test]
fn hash_churn_stays_within_source_derived_peak() {
    for n in [1,3,7,14,28,56,112,257,4097] {
        let observed=measure(||{
            let mut m=HashMap::<u64,u64>::new();
            for x in 0..n {m.insert(x as u64,x as u64);}
            for x in 0..n*50 {m.remove(&(x as u64));m.insert((x+n) as u64,x as u64);}
        });
        assert!(observed.peak<=geometry::hash::<(u64,u64)>(n,8,true).unwrap().bytes);
    }
}

#[test]
fn btree_node_bound_covers_split_overlap() {
    for n in [1,11,12,64,256,1024] {
        let observed=measure(||{let mut m=BTreeMap::<u64,[u8;32]>::new();for x in 0..n {m.insert(x as u64,[0;32]);}});
        let estimate=geometry::btree::<u64,[u8;32]>(n).unwrap();
        assert!(observed.peak<=estimate.bytes);
        assert!(observed.peak_blocks<=estimate.allocations);
    }
}

#[test]
fn arcs_use_actual_alignment_and_keep_weak_backing() {
    #[repr(align(64))] struct Aligned([u8;7]);
    let mut peak=0;
    let observed=measure(|| {let a=Arc::new(Aligned([0;7]));let weak=Arc::downgrade(&a);drop(a);peak=STATS.with(|s|s.get().live);drop(weak);});
    assert_eq!(peak,geometry::arc::<Aligned>().unwrap().bytes);
    assert_eq!(observed.peak,peak);
    let observed=measure(||{let a=Arc::<[u8]>::new_uninit_slice(65576);drop(a);});
    assert_eq!(observed.peak,geometry::arc_bytes(65576).unwrap().bytes);
}

#[test]
fn arithmetic_rejects_overflow() {
    assert!(geometry::hash::<(u64,u64)>(usize::MAX,8,true).is_none());
    assert!(geometry::vector::<u64>(usize::MAX,true).is_none());
    assert!(geometry::btree::<u64,u64>(usize::MAX).is_none());
    assert!(allocator::allocators(0).is_none());
    assert!(allocator::allocators(usize::MAX).is_none());
}

#[test]
fn print_exact_layout_and_allocator_components() {
    macro_rules! p {($t:ty)=>{println!("layout {} size={} align={}",stringify!($t),size_of::<$t>(),align_of::<$t>());}}
    p!(PageNumber);p!(BtreeBitmap);p!(U64GroupedBitmap);p!(BuddyAllocator);p!(RegionTracker);p!(Allocators);p!(PageImpl);p!(BtreeHeader);
    p!((u64,(Arc<[u8]>,AtomicBool)));p!((u64,(Option<Arc<[u8]>>,AtomicBool)));p!((PageNumber,u64));p!((usize,PageNumber,u128));p!(Option<(usize,PageNumber,u128)>);
    p!(Mutex<()>);p!(RwLock<()>);
    for payload in [64usize<<20, 3usize<<29] {
        let disk=payload.checked_mul(8).unwrap().checked_add(64<<20).unwrap();
        println!("allocator payload={payload} disk={disk} {:?}",allocator::allocators(disk).unwrap());
    }
    let mutex=measure(||{let m=Mutex::new(());drop(m.lock().unwrap());drop(m);});
    let rwlock=measure(||{let m=RwLock::new(());drop(m.write().unwrap());drop(m);});
    println!("native_lock_requests mutex={mutex:?} rwlock={rwlock:?}");
}
