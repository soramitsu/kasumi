//! Private shared owners whose control allocation retires before the payload.

use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};
use std::io;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::ops::Deref;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering, fence};

/// A sized owner with no weak or raw owning escape. The caller must acquire
/// admission for the payload, strong control and allocator allowance before
/// allocating. The payload occupies the allocation base; the strong count is
/// appended at its independently aligned offset.
pub(crate) struct NativeOwnedArc<T> {
    pointer: NonNull<T>,
    _payload: PhantomData<T>,
}

/// One allocated control whose payload has not been initialized. This owns no
/// grant or callback; abandonment deallocates only the actual empty backing.
pub(crate) struct NativeOwnedArcAllocation<T> {
    pointer: NonNull<T>,
    _payload: PhantomData<T>,
}

// Shared payload access and cross-thread final destruction require both bounds,
// exactly as for a closed strong Arc. The count is the only shared mutation.
unsafe impl<T: Send + Sync> Send for NativeOwnedArc<T> {}
unsafe impl<T: Send + Sync> Sync for NativeOwnedArc<T> {}
// The pending allocation has no initialized T and cannot be cloned or expose
// a payload. Sending it only transfers the exclusive control owner.
unsafe impl<T: Send> Send for NativeOwnedArcAllocation<T> {}
// Shared pending access exposes neither T nor mutable control. Initialization
// consumes the unique owner, and Drop also requires that exclusive ownership.
unsafe impl<T: Send + Sync> Sync for NativeOwnedArcAllocation<T> {}

fn control_layout<T>() -> io::Result<(Layout, usize)> {
    // Do not pad this layout to its alignment: for an over-aligned T, trailing
    // padding would exceed the existing two-word control quote. Layout::extend
    // checks overflow, aligns the count, and leaves T aligned at offset zero.
    Layout::new::<T>()
        .extend(Layout::new::<AtomicUsize>())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn strong_pointer<T>(pointer: NonNull<T>) -> *mut AtomicUsize {
    let (_, offset) = control_layout::<T>().expect("original native control layout");
    // SAFETY: every pointer comes from allocation of exactly control_layout<T>.
    // Its appended atomic was initialized before either owning wrapper existed.
    unsafe { pointer.cast::<u8>().as_ptr().add(offset).cast() }
}

unsafe fn deallocate_control<T>(pointer: NonNull<T>) {
    let (layout, _) = control_layout::<T>().expect("original native control layout");
    // SAFETY: the caller is the sole control owner; any initialized payload has
    // already been moved out. This is the exact, unpadded allocation layout.
    unsafe { dealloc(pointer.cast::<u8>().as_ptr(), layout) };
}

unsafe fn take_and_deallocate<T>(pointer: NonNull<T>) -> T {
    // SAFETY: a successful unique-count transition grants exclusive ownership
    // of the initialized payload, and no alias can subsequently access it.
    let value = unsafe { pointer.as_ptr().read() };
    // The original payload and any grant it holds live outside this backing
    // before its actual control is deallocated. No payload callback runs here.
    unsafe { deallocate_control(pointer) };
    value
}

impl<T> NativeOwnedArc<T> {
    pub(crate) fn allocation_layout() -> io::Result<Layout> {
        control_layout::<T>().map(|(layout, _)| layout)
    }

    pub(crate) fn try_allocate() -> io::Result<NativeOwnedArcAllocation<T>> {
        let (layout, offset) = control_layout::<T>()?;
        // SAFETY: checked layout is nonzero because it contains the count.
        let actual = unsafe { alloc(layout) };
        let pointer =
            NonNull::new(actual).ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))?;
        // SAFETY: this offset is within the allocated layout, correctly aligned
        // for AtomicUsize, and disjoint from all nonzero payload bytes. T remains
        // untouched, including when it is zero sized or over-aligned.
        unsafe {
            pointer
                .as_ptr()
                .add(offset)
                .cast::<AtomicUsize>()
                .write(AtomicUsize::new(1));
        }
        Ok(NativeOwnedArcAllocation {
            pointer: pointer.cast(),
            _payload: PhantomData,
        })
    }

    pub(crate) fn new(value: T) -> Self {
        let layout =
            Self::allocation_layout().unwrap_or_else(|_| handle_alloc_error(Layout::new::<T>()));
        match Self::try_allocate() {
            Ok(allocation) => allocation.initialize(value),
            Err(_) => handle_alloc_error(layout),
        }
    }

    pub(crate) fn as_ref(&self) -> &T {
        // SAFETY: only initialize produces this wrapper; this live strong alias
        // keeps its payload initialized and get_mut excludes all other aliases.
        unsafe { self.pointer.as_ref() }
    }

    pub(crate) fn ptr_eq(left: &Self, right: &Self) -> bool {
        left.pointer == right.pointer
    }

    pub(crate) fn strong_count(&self) -> usize {
        // SAFETY: a live strong alias keeps the initialized count allocated.
        unsafe { &*strong_pointer(self.pointer) }.load(Ordering::Relaxed)
    }

    /// Exclusive access gates a consuming operation; it does not prove that
    /// either the payload or its allocation has been retired.
    pub(crate) fn get_mut(&mut self) -> Option<&mut T> {
        // SAFETY: the count is initialized and this alias cannot concurrently
        // clone through &mut self. With no weak aliases, a count of one means no
        // other alias can create a reference. Acquire observes prior releases.
        let strong = unsafe { &*strong_pointer(self.pointer) };
        if strong.load(Ordering::Acquire) == 1 {
            Some(unsafe { self.pointer.as_mut() })
        } else {
            None
        }
    }

    /// On success the actual closed control is deallocated before handoff of
    /// the original payload. Refusal returns the unchanged owning alias.
    pub(crate) fn try_unwrap(self) -> Result<T, Self> {
        let this = ManuallyDrop::new(self);
        // SAFETY: this still owns a live strong alias. Suppressing its Drop
        // prevents a second decrement after taking unique ownership.
        let strong = unsafe { &*strong_pointer(this.pointer) };
        if strong
            .compare_exchange(1, 0, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Ok(unsafe { take_and_deallocate(this.pointer) })
        } else {
            Err(ManuallyDrop::into_inner(this))
        }
    }
}

impl<T> NativeOwnedArcAllocation<T> {
    pub(crate) fn initialize(self, value: T) -> NativeOwnedArc<T> {
        let this = ManuallyDrop::new(self);
        // SAFETY: the pending owner exclusively owns an aligned uninitialized
        // T slot. Writing it cannot invoke a payload destructor or callback.
        unsafe { this.pointer.as_ptr().write(value) };
        NativeOwnedArc {
            pointer: this.pointer,
            _payload: PhantomData,
        }
    }
}

impl<T> Drop for NativeOwnedArcAllocation<T> {
    fn drop(&mut self) {
        // SAFETY: this nonclone owner never initialized its payload. The atomic
        // requires no destructor, and no strong payload alias exists.
        unsafe { deallocate_control(self.pointer) };
    }
}

impl<T> Clone for NativeOwnedArc<T> {
    fn clone(&self) -> Self {
        // SAFETY: self owns a live alias throughout incrementing the count.
        let strong = unsafe { &*strong_pointer(self.pointer) };
        let mut count = strong.load(Ordering::Relaxed);
        loop {
            // Abort before incrementing an exhausted count. No wrapping count
            // can produce premature destruction, even if aliases are leaked.
            if count >= isize::MAX as usize {
                std::process::abort();
            }
            match strong.compare_exchange_weak(
                count,
                count + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => count = actual,
            }
        }
        Self {
            pointer: self.pointer,
            _payload: PhantomData,
        }
    }
}

impl<T> Deref for NativeOwnedArc<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.as_ref()
    }
}

impl<T> Drop for NativeOwnedArc<T> {
    fn drop(&mut self) {
        // SAFETY: this owns one live strong reference. After decrementing,
        // losing aliases never touch the allocation again. The unique final
        // alias acquires all preceding releases before moving the payload.
        let strong = unsafe { &*strong_pointer(self.pointer) };
        if strong.fetch_sub(1, Ordering::Release) == 1 {
            fence(Ordering::Acquire);
            // Exactly one alias takes and deallocates the control. The payload
            // callback, including panic, happens afterward on the moved value.
            drop(unsafe { take_and_deallocate(self.pointer) });
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativeOwnedArc<()>>() == std::mem::size_of::<*mut ()>());
    assert!(std::mem::align_of::<NativeOwnedArc<()>>() == std::mem::align_of::<*mut ()>());
    assert!(std::mem::size_of::<NativeOwnedArcAllocation<()>>() == std::mem::size_of::<*mut ()>());
    assert!(
        std::mem::align_of::<NativeOwnedArcAllocation<()>>() == std::mem::align_of::<*mut ()>()
    );
};

#[cfg(test)]
#[path = "native_owned_arc/allocation_tests.rs"]
pub(crate) mod allocation_tests;
