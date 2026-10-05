//! Fixed admission-error seats funded by the original snapshot root grant.
use kasumi_store::{ScratchAdmissionSlot, ScratchCreationFailure, ScratchOperationFailure};
use kasumi_types::SharedBudgetCharge;
use std::{
    alloc::Layout,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

struct Seat {
    claimed: AtomicBool,
    original: ScratchAdmissionSlot,
}
struct Inner {
    seats: Vec<Seat>,
    sealed: AtomicBool,
    // Every seat and alias also retains this exact original root authority.
    _charge: SharedBudgetCharge,
}

/// No weak/raw alias or owning backing can escape this closed control.
pub(crate) struct ScratchFailureInventory {
    inner: Option<Arc<Inner>>,
}

#[derive(Debug)]
pub(crate) enum ScratchInventoryRefusal {
    Occupied(ScratchCreationFailure),
    Busy,
    Sealed,
}

/// One constructor job claims one empty seat before any constructor effects.
/// It does not serialize the independently admitted jobs on other seats.
pub(crate) struct ScratchFailureGuard {
    inventory: ScratchFailureInventory,
    index: usize,
}

fn overflow() -> io::Error {
    io::ErrorKind::InvalidInput.into()
}
fn allocation_bytes(layout: Layout) -> io::Result<u64> {
    let bytes = layout
        .size()
        .checked_next_power_of_two()
        .and_then(|bytes| bytes.checked_add(64))
        .ok_or_else(overflow)?;
    u64::try_from(bytes).map_err(|_| overflow())
}
fn control_layout() -> io::Result<Layout> {
    Layout::array::<usize>(2)
        .map_err(|_| overflow())?
        .extend(Layout::new::<Inner>())
        .map(|(layout, _)| layout.pad_to_align())
        .map_err(|_| overflow())
}

impl ScratchFailureInventory {
    /// Pure quote of the actual seat Vec, closed Arc control and every concrete
    /// Store admission slot. The installer funds all of it before construction.
    pub(crate) fn required_bytes(capacity: usize) -> io::Result<u64> {
        if capacity == 0 {
            return Err(overflow());
        }
        let seats = allocation_bytes(Layout::array::<Seat>(capacity).map_err(|_| overflow())?)?;
        let slots = ScratchAdmissionSlot::required_bytes()?
            .checked_mul(u64::try_from(capacity).map_err(|_| overflow())?)
            .ok_or_else(overflow)?;
        allocation_bytes(control_layout()?)?
            .checked_add(seats)
            .and_then(|bytes| bytes.checked_add(slots))
            .ok_or_else(overflow)
    }

    pub(crate) fn new(capacity: usize, charge: SharedBudgetCharge) -> io::Result<Self> {
        Self::required_bytes(capacity)?;
        let mut seats = Vec::new();
        seats
            .try_reserve_exact(capacity)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        for _ in 0..capacity {
            seats.push(Seat {
                claimed: AtomicBool::new(false),
                original: ScratchAdmissionSlot::new(charge.clone()),
            });
        }
        Ok(Self {
            inner: Some(Arc::new(Inner {
                seats,
                sealed: AtomicBool::new(false),
                _charge: charge,
            })),
        })
    }

    fn inner(&self) -> &Inner {
        self.inner
            .as_deref()
            .expect("live scratch failure inventory")
    }
    pub(crate) fn capacity(&self) -> usize {
        self.inner().seats.len()
    }
    pub(crate) fn occupied(&self) -> bool {
        self.inner()
            .seats
            .iter()
            .any(|seat| seat.original.occupied())
    }
    pub(crate) fn active(&self) -> bool {
        self.inner()
            .seats
            .iter()
            .any(|seat| seat.claimed.load(Ordering::SeqCst))
    }
    pub(crate) fn retirement_blocked(&self) -> bool {
        self.active() || self.occupied()
    }
    /// The parent fences before examining active claims. Sequential ordering
    /// makes a racing new claim either visible to that check or refused by its
    /// second sealed check, before any constructor body can start.
    pub(crate) fn seal(&self) {
        self.inner().sealed.store(true, Ordering::SeqCst);
    }
    pub(crate) fn original_failure(&self, index: usize) -> Option<ScratchCreationFailure> {
        self.inner().seats.get(index)?.original.original_failure()
    }

    pub(crate) fn acquire(&self) -> Result<ScratchFailureGuard, ScratchInventoryRefusal> {
        if self.inner().sealed.load(Ordering::SeqCst) {
            return Err(ScratchInventoryRefusal::Sealed);
        }
        for (index, seat) in self.inner().seats.iter().enumerate() {
            if seat.original.occupied()
                || seat
                    .claimed
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
            {
                continue;
            }
            // A previous job publishes its original before releasing its seat.
            if self.inner().sealed.load(Ordering::SeqCst) {
                seat.claimed.store(false, Ordering::SeqCst);
                return Err(ScratchInventoryRefusal::Sealed);
            }
            if seat.original.occupied() {
                seat.claimed.store(false, Ordering::SeqCst);
                continue;
            }
            return Ok(ScratchFailureGuard {
                inventory: self.clone(),
                index,
            });
        }
        if self.inner().sealed.load(Ordering::SeqCst) {
            return Err(ScratchInventoryRefusal::Sealed);
        }
        for seat in &self.inner().seats {
            if let Some(original) = seat.original.original_failure() {
                return Err(ScratchInventoryRefusal::Occupied(original));
            }
        }
        Err(ScratchInventoryRefusal::Busy)
    }
}

impl Clone for ScratchFailureInventory {
    fn clone(&self) -> Self {
        Self {
            inner: Some(self.inner.as_ref().expect("live inventory").clone()),
        }
    }
}
impl Drop for ScratchFailureInventory {
    fn drop(&mut self) {
        let Some(control) = self.inner.take() else {
            return;
        };
        if let Some(inner) = Arc::into_inner(control) {
            // Occupied originals remain sticky even when a foreign future and
            // its facade disappear. Drop does not prove their retirement.
            if inner.seats.iter().any(|seat| seat.original.occupied()) {
                std::mem::forget(inner);
            } else {
                // into_inner positively frees the actual private control before
                // retiring seat backing and the original root charge.
                drop(inner);
            }
        }
    }
}

impl ScratchFailureGuard {
    #[cfg(test)]
    pub(crate) fn index(&self) -> usize {
        self.index
    }
    /// Publish the original bare admission failure into this previously empty
    /// seat before its claim is released. Registered failures pass unchanged.
    pub(crate) fn capture_result<T>(
        self,
        result: Result<T, ScratchOperationFailure>,
    ) -> Result<T, ScratchOperationFailure> {
        match result {
            Err(ScratchOperationFailure::Creation(original)) => {
                let original = match self.inventory.inner().seats[self.index]
                    .original
                    .capture(original)
                {
                    Ok(original) | Err(original) => original,
                };
                Err(ScratchOperationFailure::Creation(original))
            }
            result => result,
        }
    }
}
impl Drop for ScratchFailureGuard {
    fn drop(&mut self) {
        self.inventory.inner().seats[self.index]
            .claimed
            .store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
#[path = "scratch_failure_inventory_tests.rs"]
mod tests;
