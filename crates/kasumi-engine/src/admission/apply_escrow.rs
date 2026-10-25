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
pub(crate) struct Credit {
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
    /// compaction. Document capacity is added explicitly before proposal.
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

    /// Grow only while owned by the proposer, before an applying scope can
    /// spend it. A refusal therefore accepts no write.
    pub(crate) fn admit_document_capacity(&self, document_bytes: u64) -> kasumi_types::Result<()> {
        let required = Self::BYTES.checked_add(document_bytes).ok_or_else(|| {
            kasumi_types::Error::new(
                kasumi_types::ErrorCode::ResourceExhausted,
                "document proposal workspace overflow",
            )
        })?;
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if !state.open || state.used != 0 {
            return Err(kasumi_types::Error::new(
                kasumi_types::ErrorCode::Unavailable,
                "document admission after apply began",
            ));
        }
        if required > state.capacity {
            let extra = required - state.capacity;
            state
                .reservation
                .as_mut()
                .expect("unspent original escrow")
                .reserve_additional(extra)?;
            state.capacity = required;
        } else if required < state.capacity {
            state
                .reservation
                .as_mut()
                .expect("unspent original escrow")
                .retain(required);
            state.capacity = required;
        }
        Ok(())
    }

    pub(crate) fn enter(self: Arc<Self>) -> ApplyScope {
        let previous = ACTIVE.with(|active| active.replace(Some(self.clone())));
        ApplyScope {
            previous,
            escrow: self,
        }
    }

    pub(crate) fn current_for(memory: &Arc<MemoryCore>) -> Option<Arc<Self>> {
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

/// A real document workspace. During committed apply it spends only the exact
/// pre-proposal escrow; ordinary readers retain the normal document-origin grant.
pub(crate) enum DocumentWorkspace {
    Ordinary(Reservation),
    Committed(Credit),
    Read(super::document_read_scope::ReadCredit),
}
pub(crate) trait RetainedWorkspace: kasumi_query::QueryWorkspace {
    fn retain(&mut self, bytes: u64);
}
impl RetainedWorkspace for Reservation {
    fn retain(&mut self, bytes: u64) {
        Reservation::retain(self, bytes);
    }
}
impl DocumentWorkspace {
    pub(crate) fn new(node: &Arc<super::NodeAdmission>, bytes: u64) -> kasumi_types::Result<Self> {
        if let Some(escrow) = ApplyEscrow::current_for(node.memory()) {
            let mut credit = Credit { escrow, bytes: 0 };
            credit.resize(bytes)?;
            return Ok(Self::Committed(credit));
        }
        if let Some(budget) = super::DocumentReadBudget::current_for(node.memory()) {
            return budget.credit(bytes).map(Self::Read);
        }
        node.reserve_document_source(bytes).map(Self::Ordinary)
    }
}
impl kasumi_query::QueryWorkspace for DocumentWorkspace {
    fn ensure_peak(&mut self, bytes: u64) -> kasumi_types::Result<()> {
        match self {
            Self::Ordinary(grant) => kasumi_query::QueryWorkspace::ensure_peak(grant, bytes),
            Self::Committed(credit) if bytes > credit.bytes => credit.resize(bytes),
            Self::Committed(_) => Ok(()),
            Self::Read(credit) if bytes > credit.bytes() => credit.resize(bytes),
            Self::Read(_) => Ok(()),
        }
    }
}
impl RetainedWorkspace for DocumentWorkspace {
    fn retain(&mut self, bytes: u64) {
        match self {
            Self::Ordinary(grant) => grant.retain(bytes),
            Self::Committed(credit) => credit
                .resize(bytes.min(credit.bytes))
                .expect("shrinking admitted document credit"),
            Self::Read(credit) => credit
                .resize(bytes.min(credit.bytes()))
                .expect("shrinking admitted read document credit"),
        }
    }
}
impl Credit {
    fn resize(&mut self, bytes: u64) -> kasumi_types::Result<()> {
        let mut state = self.escrow.state.lock().unwrap_or_else(|p| p.into_inner());
        let used = state
            .used
            .checked_sub(self.bytes)
            .and_then(|used| used.checked_add(bytes))
            .ok_or_else(|| {
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::ResourceExhausted,
                    "committed document workspace overflow",
                )
            })?;
        if bytes > self.bytes && (!state.open || used > state.capacity) {
            return Err(kasumi_types::Error::new(
                kasumi_types::ErrorCode::ResourceExhausted,
                "committed document workspace exceeds pre-admitted capacity",
            ));
        }
        self.bytes = bytes;
        state.used = used;
        #[cfg(test)]
        {
            state.peak = state.peak.max(used);
        }
        let retired = if state.open {
            None
        } else {
            ApplyEscrow::shrink(&mut state)
        };
        drop(state);
        drop(retired);
        Ok(())
    }
}

#[cfg(test)]
mod document_tests {
    use super::*;
    use kasumi_query::QueryWorkspace;
    use kasumi_store::NodeDiskMemoryAdmission;

    #[test]
    fn committed_document_credit_and_native_exhaustion_never_fall_back_to_fresh_admission() {
        let node = super::super::NodeAdmission::with_fixed_memory(
            super::super::AdmissionConfig::default(),
            2 << 30,
            0,
        )
        .unwrap();
        let baseline = node.snapshot().reserved_bytes;
        let escrow = ApplyEscrow::admit(node.memory()).unwrap();
        let mut document;
        {
            let _scope = escrow.clone().enter();
            document = DocumentWorkspace::new(&node, ApplyEscrow::BYTES).unwrap();
            // The governor still has ordinary capacity; only this accepted
            // entry's exact prepaid balance is exhausted.
            assert!(node.reserve_resident(1).is_ok());
            assert!(node.memory().clone().reserve_installed(1).is_err());
            assert!(node.memory().clone().reserve_document_decode(1).is_err());
            assert!(document.ensure_peak(ApplyEscrow::BYTES + 1).is_err());
            document.retain(4096);
        }
        // Its real retained owner can outlive apply; no spent bytes disappear
        // while the decoded owner remains alive.
        assert!(node.snapshot().reserved_bytes >= 4096);
        document.retain(2048);
        drop(document);
        drop(escrow);
        assert_eq!(node.snapshot().reserved_bytes, baseline);
    }

    #[test]
    fn unspent_document_proposal_capacity_tracks_the_next_request_without_retaining_its_peak() {
        let node = super::super::NodeAdmission::with_fixed_memory(
            super::super::AdmissionConfig::default(),
            2 << 30,
            0,
        )
        .unwrap();
        let escrow = ApplyEscrow::admit(node.memory()).unwrap();
        let base = node.snapshot().reserved_bytes;
        escrow.admit_document_capacity(12 << 20).unwrap();
        assert_eq!(node.snapshot().reserved_bytes, base + (12 << 20));
        escrow.admit_document_capacity(0).unwrap();
        assert_eq!(node.snapshot().reserved_bytes, base);
    }
}
