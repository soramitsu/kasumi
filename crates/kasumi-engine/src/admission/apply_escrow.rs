//! Native KV capacity for one committed apply, admitted before consensus.
//!
//! The command's own registered reads (such as mutation receipt lookups), the
//! Entry sink's planner reader, the queued source reader, the publication write
//! and the selected capture all take native leases through `reserve_installed`.
//! Their ordinary Resident rule (a free ledger slot, the byte cap and the RSS
//! high-water mark, but not the ordinary protection) is shared with all native
//! Resident traffic, so concurrent readers, maintenance or RSS pressure could
//! refuse them after commitment and close the tenant. A local proposer instead
//! admits this escrow under that same rule before it proposes; the applying
//! thread then draws its native leases from it.
use super::{MemoryCore, Reservation};
use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
};

/// One pre-admitted charge. Unspent bytes return when the apply ends; leases
/// that outlive it (the selected reader) keep exactly their own bytes charged
/// until the last one is released, which also releases the ledger slot.
pub(crate) struct ApplyEscrow {
    memory: Arc<MemoryCore>,
    state: Mutex<State>,
}
struct State {
    reservation: Option<Reservation>,
    capacity: u64,
    used: u64,
    open: bool,
    #[cfg(test)]
    peak: u64,
}
struct Credit {
    escrow: Arc<ApplyEscrow>,
    bytes: u64,
}
// MemoryCore::reserve_installed budgets a Reservation-sized opaque token.
const _: () = assert!(std::mem::size_of::<Credit>() <= std::mem::size_of::<Reservation>());

thread_local! {
    static ACTIVE: RefCell<Option<Arc<ApplyEscrow>>> = const { RefCell::new(None) };
    #[cfg(test)]
    static LAST_PEAK: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Held by the applying thread for exactly one committed entry. It is never
/// carried across an await or into another thread.
pub(crate) struct ApplyScope {
    previous: Option<Arc<ApplyEscrow>>,
    escrow: Arc<ApplyEscrow>,
}
impl Drop for ApplyScope {
    fn drop(&mut self) {
        ACTIVE.with(|active| {
            active.replace(self.previous.take());
        });
        self.escrow.close();
    }
}

impl ApplyEscrow {
    /// One committed ordinary apply measures about 2.6 MiB of native leases,
    /// dominated by the 2 MiB control-record point workspace (the writer and
    /// decoder format limit), plus the planner, queued source and capture
    /// readers and the publication write. The rest leaves room for inline
    /// compaction; a larger apply admits its excess as before.
    pub(crate) const BYTES: u64 = 8 << 20;

    /// Admitted under the ordinary native Resident rule that applies to the
    /// leases it funds; a refusal proposes nothing.
    pub(crate) fn admit(memory: &Arc<MemoryCore>) -> kasumi_types::Result<Arc<Self>> {
        let reservation = memory.reserve_resident(Self::BYTES)?;
        Ok(Arc::new(Self {
            memory: memory.clone(),
            state: Mutex::new(State {
                reservation: Some(reservation),
                capacity: Self::BYTES,
                used: 0,
                open: true,
                #[cfg(test)]
                peak: 0,
            }),
        }))
    }

    pub(crate) fn enter(self: Arc<Self>) -> ApplyScope {
        let previous = ACTIVE.with(|active| active.replace(Some(self.clone())));
        ApplyScope {
            previous,
            escrow: self,
        }
    }

    pub(super) fn current_for(memory: &Arc<MemoryCore>) -> Option<Arc<Self>> {
        ACTIVE.with(|active| {
            active
                .borrow()
                .as_ref()
                .filter(|escrow| Arc::ptr_eq(&escrow.memory, memory))
                .cloned()
        })
    }

    /// None when the scope has ended or the bytes exceed what remains.
    pub(super) fn reserve(self: &Arc<Self>, bytes: u64) -> Option<kasumi_store::DiskMemoryLease> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let used = state.used.checked_add(bytes)?;
        if !state.open || used > state.capacity {
            return None;
        }
        state.used = used;
        #[cfg(test)]
        {
            state.peak = state.peak.max(used);
        }
        Some(kasumi_store::DiskMemoryLease::new(Credit {
            escrow: self.clone(),
            bytes,
        }))
    }

    fn close(&self) {
        let retired = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.open = false;
            #[cfg(test)]
            LAST_PEAK.set(Some(state.peak));
            Self::shrink(&mut state)
        };
        drop(retired);
    }
    /// Peak native bytes of the last committed apply that ended on this thread.
    #[cfg(test)]
    pub(crate) fn take_last_peak_for_test() -> Option<u64> {
        LAST_PEAK.take()
    }

    // The escrow charge never exceeds the bytes its live leases still spend.
    fn shrink(state: &mut State) -> Option<Reservation> {
        state.capacity = state.used;
        if state.used == 0 {
            return state.reservation.take();
        }
        if let Some(reservation) = state.reservation.as_mut() {
            reservation.retain(state.used);
        }
        None
    }
}
impl Drop for Credit {
    fn drop(&mut self) {
        let retired = {
            let mut state = self.escrow.state.lock().unwrap_or_else(|p| p.into_inner());
            state.used -= self.bytes;
            if state.open {
                None
            } else {
                ApplyEscrow::shrink(&mut state)
            }
        };
        drop(retired);
    }
}
