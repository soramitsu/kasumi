//! Narrow allocation refusal and actual post-deallocation observations. These
//! hooks allocate no storage and run only in the native library test binary.
use super::*;
use crate::tables::read_fork_tests::AllocationRefusal;
use std::cell::Cell;
use std::mem::{align_of, size_of};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::{Arc, Barrier};
use std::thread;

thread_local! {
    static LAST_DEALLOCATED: Cell<usize> = const { Cell::new(0) };
    static DEALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// The real global allocator calls this only after System.dealloc returns.
// No payload, provider callback or primitive allocation path is substituted.
pub(crate) fn note_deallocation(pointer: *mut u8) {
    let _ = LAST_DEALLOCATED.try_with(|last| last.set(pointer as usize));
    let _ = DEALLOCATIONS.try_with(|count| count.set(count.get().wrapping_add(1)));
}

struct DropProbe {
    control: usize,
    drops: Arc<AtomicUsize>,
    panic: Option<Box<usize>>,
}
impl Drop for DropProbe {
    fn drop(&mut self) {
        LAST_DEALLOCATED.with(|last| {
            assert_eq!(last.get(), self.control, "actual control retired first");
        });
        self.drops.fetch_add(1, Ordering::AcqRel);
        if let Some(original) = self.panic.take() {
            resume_unwind(original);
        }
    }
}

fn probe(drops: &Arc<AtomicUsize>, panic: Option<Box<usize>>) -> NativeOwnedArc<DropProbe> {
    let mut owner = NativeOwnedArc::try_allocate()
        .unwrap()
        .initialize(DropProbe {
            control: 0,
            drops: drops.clone(),
            panic,
        });
    let control = owner.pointer.as_ptr() as usize;
    owner.get_mut().unwrap().control = control;
    owner
}

#[test]
fn pending_allocation_retires_control_without_touching_uninitialized_payload() {
    let drops = Arc::new(AtomicUsize::new(0));
    let before = DEALLOCATIONS.with(Cell::get);
    let pending = NativeOwnedArc::<DropProbe>::try_allocate().unwrap();
    let address = pending.pointer.as_ptr() as usize;
    let strong = unsafe { &*strong_pointer(pending.pointer) };
    assert_eq!(strong.load(Ordering::Relaxed), 1);
    drop(pending);
    assert_eq!(DEALLOCATIONS.with(Cell::get), before + 1);
    assert_eq!(LAST_DEALLOCATED.with(Cell::get), address);
    assert_eq!(drops.load(Ordering::Acquire), 0);
}

#[test]
fn allocation_refusal_keeps_original_payload_in_caller() {
    let drops = Arc::new(AtomicUsize::new(0));
    let original = DropProbe {
        control: 0,
        drops: drops.clone(),
        panic: None,
    };
    let before = DEALLOCATIONS.with(Cell::get);
    let denied = AllocationRefusal::arm(NativeOwnedArc::<DropProbe>::allocation_layout().unwrap());
    let error = match NativeOwnedArc::<DropProbe>::try_allocate() {
        Ok(_) => panic!("the exact control allocation must be refused"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    denied.assert_denied();
    assert_eq!(drops.load(Ordering::Acquire), 0);
    assert_eq!(DEALLOCATIONS.with(Cell::get), before);
    let mut owner = NativeOwnedArc::try_allocate().unwrap().initialize(original);
    let address = owner.pointer.as_ptr() as usize;
    owner.get_mut().unwrap().control = address;
    drop(owner);
    assert_eq!(drops.load(Ordering::Acquire), 1);
}

#[test]
fn closed_alias_refusal_preserves_owner_and_unique_mutation() {
    let mut owner = NativeOwnedArc::try_allocate().unwrap().initialize(7_usize);
    let alias = owner.clone();
    assert!(NativeOwnedArc::ptr_eq(&owner, &alias));
    assert_eq!(NativeOwnedArc::strong_count(&owner), 2);
    assert!(owner.get_mut().is_none());
    owner = match owner.try_unwrap() {
        Ok(_) => panic!("the original alias still owns the payload"),
        Err(original) => original,
    };
    assert!(NativeOwnedArc::ptr_eq(&owner, &alias));
    assert_eq!(*owner, 7);
    drop(alias);
    *owner.get_mut().unwrap() = 11;
    assert_eq!(NativeOwnedArc::strong_count(&owner), 1);
    let value = match owner.try_unwrap() {
        Ok(value) => value,
        Err(_) => panic!("the original unique owner must unwrap"),
    };
    assert_eq!(value, 11);
}

#[test]
fn unwrap_deallocates_control_before_original_payload_handoff() {
    let drops = Arc::new(AtomicUsize::new(0));
    let owner = probe(&drops, None);
    let address = owner.pointer.as_ptr() as usize;
    let value = match owner.try_unwrap() {
        Ok(value) => value,
        Err(_) => panic!("the original unique owner must unwrap"),
    };
    assert_eq!(LAST_DEALLOCATED.with(Cell::get), address);
    assert_eq!(drops.load(Ordering::Acquire), 0);
    drop(value);
    assert_eq!(drops.load(Ordering::Acquire), 1);
}

#[test]
fn simultaneous_final_alias_drops_retire_original_payload_once() {
    const ALIASES: usize = 8;
    let drops = Arc::new(AtomicUsize::new(0));
    let owner = probe(&drops, None);
    let barrier = Arc::new(Barrier::new(ALIASES + 1));
    let mut workers = Vec::new();
    for _ in 0..ALIASES {
        let alias = owner.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            drop(alias);
        }));
    }
    assert_eq!(NativeOwnedArc::strong_count(&owner), ALIASES + 1);
    drop(owner);
    barrier.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(drops.load(Ordering::Acquire), 1);
}

#[test]
fn original_payload_panic_occurs_after_control_deallocation() {
    let drops = Arc::new(AtomicUsize::new(0));
    let original = Box::new(0x00C1_05ED_usize);
    let identity = original.as_ref() as *const usize as usize;
    let owner = probe(&drops, Some(original));
    let panic = catch_unwind(AssertUnwindSafe(|| drop(owner))).unwrap_err();
    assert_eq!(drops.load(Ordering::Acquire), 1);
    assert_eq!(
        panic.downcast_ref::<usize>().unwrap() as *const usize as usize,
        identity,
    );
}

#[repr(align(4096))]
struct OverAligned([u8; 1]);

#[repr(align(4096))]
struct OverAlignedZero;

fn assert_layout<T>() {
    let layout = NativeOwnedArc::<T>::allocation_layout().unwrap();
    assert!(layout.size() > 0);
    assert!(layout.size() <= size_of::<T>() + 2 * size_of::<usize>());
    assert!(layout.align() >= align_of::<T>());
    assert_eq!(size_of::<NativeOwnedArc<T>>(), size_of::<*mut ()>());
    assert_eq!(align_of::<NativeOwnedArc<T>>(), align_of::<*mut ()>());
    assert_eq!(
        size_of::<NativeOwnedArcAllocation<T>>(),
        size_of::<*mut ()>()
    );
    assert_eq!(
        align_of::<NativeOwnedArcAllocation<T>>(),
        align_of::<*mut ()>()
    );
    let pending = NativeOwnedArc::<T>::try_allocate().unwrap();
    assert_eq!(pending.pointer.as_ptr() as usize % align_of::<T>(), 0);
    let strong = strong_pointer(pending.pointer);
    assert_eq!(strong as usize % align_of::<AtomicUsize>(), 0);
    drop(pending);
}

#[test]
fn zero_sized_and_overaligned_layouts_fit_existing_control_quote() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NativeOwnedArc<OverAligned>>();
    assert_send_sync::<NativeOwnedArcAllocation<OverAligned>>();
    assert_layout::<()>();
    assert_layout::<u8>();
    assert_layout::<[u8; 9]>();
    assert_layout::<OverAligned>();
    assert_layout::<OverAlignedZero>();
    let value = NativeOwnedArc::try_allocate()
        .unwrap()
        .initialize(OverAligned([73]));
    assert_eq!(value.0[0], 73);
    drop(value);
    let zero = NativeOwnedArc::try_allocate()
        .unwrap()
        .initialize(OverAlignedZero);
    drop(zero);
}
