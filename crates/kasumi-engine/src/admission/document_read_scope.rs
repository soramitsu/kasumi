//! Synchronous document loans spend an explicit slice of a read workflow's
//! existing grant. This never grants committed-apply or native write authority.
use super::{MemoryCore, NodeAdmission, Reservation};
use kasumi_types::{Error, ErrorCode, Result};
use std::{
    cell::RefCell,
    marker::PhantomData,
    rc::Rc,
    sync::{Arc, Mutex},
};

pub(crate) struct DocumentReadBudget {
    memory: Arc<MemoryCore>,
    state: Mutex<State>,
    // Exact original grant survives all decoded loans, including failed work.
    _reservation: Arc<Reservation>,
}
struct State {
    capacity: u64,
    used: u64,
    entered: bool,
    open: bool,
}
pub(crate) struct ReadCredit {
    budget: Arc<DocumentReadBudget>,
    bytes: u64,
}
const _: () = assert!(std::mem::size_of::<ReadCredit>() <= std::mem::size_of::<Reservation>());

thread_local! {
    static ACTIVE: RefCell<Option<Arc<DocumentReadBudget>>> = const { RefCell::new(None) };
}

pub(crate) struct DocumentReadScope {
    previous: Option<Arc<DocumentReadBudget>>,
    budget: Arc<DocumentReadBudget>,
    // Never transfer thread-local authority across an await/thread boundary.
    _thread: PhantomData<Rc<()>>,
}
impl Drop for DocumentReadScope {
    fn drop(&mut self) {
        ACTIVE.with(|active| {
            active.replace(self.previous.take());
        });
        self.budget
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .open = false;
    }
}
impl DocumentReadBudget {
    // Covers this Arc, mutex/state, and the stream's scope handle. Allocation
    // happens only after its bytes are part of the caller's actual grant.
    pub(crate) const CONTROL_BYTES: u64 = 1024;

    pub(crate) fn bind(
        node: &Arc<NodeAdmission>,
        reservation: Reservation,
        other_work_bytes: u64,
        capacity: u64,
    ) -> Result<Arc<Self>> {
        Self::bind_shared(node, Arc::new(reservation), other_work_bytes, capacity)
    }

    /// The ledger grants exactly one document partition per original charge.
    /// Other workflow aliases retain ownership only; they cannot resize or
    /// create another partition until this budget and its last loan retire.
    pub(crate) fn bind_shared(
        node: &Arc<NodeAdmission>,
        reservation: Arc<Reservation>,
        other_work_bytes: u64,
        capacity: u64,
    ) -> Result<Arc<Self>> {
        if !Arc::ptr_eq(&reservation.core, node.memory()) {
            return Err(Error::new(
                ErrorCode::Conflict,
                "document read grant belongs to another memory core",
            ));
        }
        let required = other_work_bytes
            .checked_add(capacity)
            .and_then(|bytes| bytes.checked_add(Self::CONTROL_BYTES))
            .ok_or_else(|| {
                Error::new(ErrorCode::ResourceExhausted, "document read grant overflow")
            })?;
        {
            let mut state = reservation
                .core
                .data
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let charge = state
                .charge_mut(reservation.slot, reservation.id)
                .ok_or_else(|| {
                    Error::new(ErrorCode::Unavailable, "document read grant is absent")
                })?;
            if charge.bytes < required {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "document read grant does not cover its separate work slices",
                ));
            }
            if charge.document_partition {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "document read grant already partitioned",
                ));
            }
            charge.document_partition = true;
        }
        Ok(Arc::new(Self {
            memory: node.memory().clone(),
            state: Mutex::new(State {
                capacity,
                used: 0,
                entered: false,
                open: true,
            }),
            _reservation: reservation,
        }))
    }
    pub(crate) fn reservation(&self) -> Arc<Reservation> {
        self._reservation.clone()
    }
    pub(crate) fn enter(self: Arc<Self>) -> Result<DocumentReadScope> {
        {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.entered || !state.open {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    "document read budget already entered",
                ));
            }
            state.entered = true;
        }
        let previous = ACTIVE.with(|active| active.replace(Some(self.clone())));
        Ok(DocumentReadScope {
            previous,
            budget: self,
            _thread: PhantomData,
        })
    }
    pub(crate) fn current_for(memory: &Arc<MemoryCore>) -> Option<Arc<Self>> {
        ACTIVE.with(|active| {
            active
                .borrow()
                .as_ref()
                .filter(|budget| Arc::ptr_eq(&budget.memory, memory))
                .cloned()
        })
    }
    pub(super) fn credit(self: &Arc<Self>, bytes: u64) -> Result<ReadCredit> {
        let mut credit = ReadCredit {
            budget: self.clone(),
            bytes: 0,
        };
        credit.resize(bytes)?;
        Ok(credit)
    }
    pub(super) fn reserve(self: &Arc<Self>, bytes: u64) -> Result<kasumi_store::DiskMemoryLease> {
        Ok(kasumi_store::DiskMemoryLease::new(self.credit(bytes)?))
    }
}
impl Drop for DocumentReadBudget {
    fn drop(&mut self) {
        let mut state = self
            .memory
            .data
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(charge) = state.charge_mut(self._reservation.slot, self._reservation.id) {
            charge.document_partition = false;
        }
    }
}
impl ReadCredit {
    pub(super) fn resize(&mut self, bytes: u64) -> Result<()> {
        let mut state = self.budget.state.lock().unwrap_or_else(|p| p.into_inner());
        let used = state
            .used
            .checked_sub(self.bytes)
            .and_then(|used| used.checked_add(bytes))
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "document read credit overflow",
                )
            })?;
        if bytes > self.bytes && (!state.open || used > state.capacity) {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "document read exceeds its admitted source capacity",
            ));
        }
        self.bytes = bytes;
        state.used = used;
        Ok(())
    }
    pub(super) fn bytes(&self) -> u64 {
        self.bytes
    }
}
impl Drop for ReadCredit {
    fn drop(&mut self) {
        let mut state = self.budget.state.lock().unwrap_or_else(|p| p.into_inner());
        state.used -= self.bytes;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{AdmissionConfig, DocumentWorkspace, RetainedWorkspace};
    use kasumi_query::QueryWorkspace;
    use kasumi_store::NodeDiskMemoryAdmission;

    fn node() -> Arc<NodeAdmission> {
        NodeAdmission::with_fixed_memory(AdmissionConfig::default(), 2 << 30, 0).unwrap()
    }
    #[test]
    fn document_read_scope_spends_only_its_slice_and_keeps_original_grant_with_last_loan() {
        let node = node();
        let baseline = node.snapshot();
        let charge = node
            .reserve(16_384 + DocumentReadBudget::CONTROL_BYTES, None)
            .unwrap();
        let budget = DocumentReadBudget::bind(&node, charge, 8192, 8192).unwrap();
        let weak = Arc::downgrade(&budget.reservation());
        let mut document;
        let decode_bytes = MemoryCore::required_installed_reservation_bytes(1024).unwrap();
        let retained = 8192 - decode_bytes;
        {
            let _scope = budget.clone().enter().unwrap();
            document = DocumentWorkspace::new(&node, 8192).unwrap();
            assert!(node.reserve_resident(1).is_ok());
            assert!(document.ensure_peak(8193).is_err());
            assert!(node.memory().clone().reserve_document_decode(1).is_err());
            document.retain(retained);
            let decoded = node.memory().clone().reserve_document_decode(1024).unwrap();
            drop(decoded);
        }
        assert!(budget.clone().enter().is_err());
        drop(budget);
        assert!(weak.upgrade().is_some());
        assert!(document.ensure_peak(retained + 1).is_err());
        drop(document);
        assert!(weak.upgrade().is_none());
        assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
        assert_eq!(
            node.snapshot().live_reservations,
            baseline.live_reservations
        );
    }
    #[test]
    fn document_read_scope_rejects_unfunded_or_foreign_grants_and_never_lends_to_another_core() {
        let node = node();
        let foreign = self::node();
        assert!(
            DocumentReadBudget::bind(&foreign, node.reserve(8192, None).unwrap(), 0, 1024).is_err()
        );
        assert!(
            DocumentReadBudget::bind(&node, node.reserve(8192, None).unwrap(), 8192, 1).is_err()
        );
        let budget =
            DocumentReadBudget::bind(&node, node.reserve(8192, None).unwrap(), 0, 4096).unwrap();
        let _scope = budget.enter().unwrap();
        let before = foreign.snapshot();
        let ordinary = DocumentWorkspace::new(&foreign, 128).unwrap();
        assert_eq!(
            foreign.snapshot().live_reservations,
            before.live_reservations + 1
        );
        drop(ordinary);
        assert_eq!(foreign.snapshot().reserved_bytes, before.reserved_bytes);
    }

    #[test]
    fn shared_document_partition_blocks_handoff_until_cancelled_loans_retire() {
        let node = node();
        let before = node.snapshot();
        let cancellation = kasumi_query::QueryCancellation::default();
        let grant = Arc::new(node.reserve(32_768, Some(cancellation.clone())).unwrap());
        let budget = DocumentReadBudget::bind_shared(&node, grant.clone(), 8192, 16_384).unwrap();
        assert!(DocumentReadBudget::bind_shared(&node, grant.clone(), 8192, 16_384).is_err());
        assert!(grant.handoff_workspace(&node, 1).is_err());
        let loan;
        {
            let _scope = budget.clone().enter().unwrap();
            loan = node.memory().clone().reserve_document_decode(4096).unwrap();
            cancellation.cancel();
            // Cancellation ends work; it cannot refund memory still owned by a
            // decoded result or original native failure.
            assert!(grant.handoff_workspace(&node, 1).is_err());
        }
        drop(budget);
        assert!(grant.handoff_workspace(&node, 1).is_err());
        assert!(DocumentReadBudget::bind_shared(&node, grant.clone(), 8192, 16_384).is_err());
        drop(loan);
        grant.handoff_workspace(&node, 1).unwrap();
        drop(grant);
        assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, before.live_reservations);
    }
}
