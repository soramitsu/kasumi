//! Closed sharing of a producer's original, previously funded budget payload.
use std::{
    alloc::{Layout, LayoutError},
    fmt, io,
    marker::PhantomData,
    ptr::NonNull,
    sync::Arc,
};

struct Operations {
    clone: unsafe fn(NonNull<()>),
    retire: unsafe fn(NonNull<()>),
}

struct Typed<T>(PhantomData<T>);
impl<T: Send + Sync + 'static> Typed<T> {
    const OPERATIONS: Operations = Operations {
        clone: clone::<T>,
        retire: retire::<T>,
    };
}

struct Strong {
    payload: NonNull<()>,
    operations: &'static Operations,
}

/// Shares one original budget payload without an opaque Arc adapter.
///
/// The trusted installer must fund `allocation_layout::<T>()` and all payload
/// backing before calling `new`. This handle grants no bytes or admission
/// authority. It closes only its own control's retirement: every alias uses
/// typed `Arc::into_inner`, so the final control is deallocated before `T` is
/// dropped. A nested `T` retains its own independent custody requirements.
/// Production installers move their actual reservation or a closed owner here;
/// wrapping an existing opaque Arc does not establish recursive refund order.
///
/// No weak alias, raw Arc, payload access, or caller-supplied retirement callback
/// is available. Cloning keeps this same original control without allocating.
///
/// ```compile_fail
/// use kasumi_types::SharedBudgetCharge;
/// let charge = SharedBudgetCharge::new(());
/// let weak = std::sync::Arc::downgrade(&charge);
/// ```
pub struct SharedBudgetCharge {
    inner: Option<Strong>,
}

impl SharedBudgetCharge {
    /// The actual sized Arc header and payload layout, before allocation.
    /// Allocator/provider allowances remain part of the installer's quote.
    pub fn allocation_layout<T: Send + Sync + 'static>() -> Result<Layout, LayoutError> {
        Layout::array::<usize>(2)
            .and_then(|header| header.extend(Layout::new::<T>()))
            .map(|(layout, _)| layout.pad_to_align())
    }

    /// Quote this one actual control with an allocator size-class allowance.
    /// A producer may use its own larger allocation allowance instead.
    pub fn required_bytes<T: Send + Sync + 'static>() -> io::Result<u64> {
        Self::allocation_layout::<T>()
            .ok()
            .and_then(|layout| layout.size().checked_next_power_of_two())
            .and_then(|bytes| bytes.checked_add(64))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }

    /// Move the already funded original payload into its only new control.
    pub fn new<T: Send + Sync + 'static>(original: T) -> Self {
        let payload = Arc::into_raw(Arc::new(original)).cast_mut().cast::<()>();
        Self {
            inner: Some(Strong {
                payload: NonNull::new(payload).expect("Arc allocation is nonnull"),
                operations: &Typed::<T>::OPERATIONS,
            }),
        }
    }

    /// Whether two closed aliases retain the exact same original control.
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        this.strong().payload == other.strong().payload
    }

    fn strong(&self) -> &Strong {
        self.inner.as_ref().expect("live shared budget charge")
    }
}

impl Clone for SharedBudgetCharge {
    fn clone(&self) -> Self {
        let original = self.strong();
        // SAFETY: the private pointer and operations are installed together by
        // new::<T>. This live handle retains one strong alias throughout clone.
        unsafe { (original.operations.clone)(original.payload) };
        Self {
            inner: Some(Strong {
                payload: original.payload,
                operations: original.operations,
            }),
        }
    }
}

impl Drop for SharedBudgetCharge {
    fn drop(&mut self) {
        let original = self.inner.take().expect("live shared budget charge");
        // SAFETY: each private pointer represents exactly one typed Arc strong
        // alias. Taking it prevents replay if the original payload Drop panics.
        unsafe { (original.operations.retire)(original.payload) };
    }
}

impl fmt::Debug for SharedBudgetCharge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedBudgetCharge")
    }
}

// SAFETY: only new::<T: Send + Sync> creates pointers/operations. No borrowed
// payload access or weak/raw ownership escapes, and Arc serializes final drop.
unsafe impl Send for SharedBudgetCharge {}
// SAFETY: shared methods only clone/compare live atomic strong aliases.
unsafe impl Sync for SharedBudgetCharge {}

unsafe fn clone<T: Send + Sync + 'static>(payload: NonNull<()>) {
    // SAFETY: the matching live typed alias supplies this original Arc pointer.
    unsafe { Arc::<T>::increment_strong_count(payload.as_ptr().cast::<T>()) };
}

unsafe fn retire<T: Send + Sync + 'static>(payload: NonNull<()>) {
    // SAFETY: private ownership transfers exactly one original typed strong
    // alias. No other method constructs an Arc or releases this alias.
    let original = unsafe { Arc::<T>::from_raw(payload.as_ptr().cast::<T>()) };
    // With no Weak capability, into_inner retires the final actual control
    // before returning its original payload, even under concurrent final drops.
    drop(Arc::into_inner(original));
}

#[cfg(test)]
#[path = "shared_budget_charge_tests.rs"]
mod tests;
