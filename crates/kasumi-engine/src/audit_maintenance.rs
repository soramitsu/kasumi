//! One reserved archive workspace and native escrow per node, shared by every tenant.
use crate::admission::{MemoryCore, NodeAdmission, OrdinaryProtection, Reservation};
use kasumi_types::{AuditRetentionBudget, Error, ErrorCode, Result};
use std::{
    cell::RefCell,
    io,
    sync::{Arc, LazyLock, Mutex, Weak},
};

/// Preparation retains its lane until the proposed command resolves. Applying
/// replicas use a separate lane so a proposal can never wait on its own permit.
pub(crate) struct NodeAuditMaintenance {
    pub(crate) preparation: Arc<tokio::sync::Semaphore>,
    pub(crate) applying: Mutex<()>,
    memory: Arc<MemoryCore>,
    native_used: Mutex<u64>,
    _native_escrow: Reservation,
    _ordinary_protection: OrdinaryProtection,
}

thread_local! {
    static ACTIVE_AUDIT: RefCell<Option<Arc<NodeAuditMaintenance>>> = const { RefCell::new(None) };
}

pub(crate) struct AuditScope(Option<Arc<NodeAuditMaintenance>>);
impl Drop for AuditScope {
    fn drop(&mut self) {
        ACTIVE_AUDIT.with(|active| {
            active.replace(self.0.take());
        });
    }
}

struct NativeCredit {
    pool: Arc<NodeAuditMaintenance>,
    bytes: u64,
}
// MemoryCore::reserve_installed budgets a Reservation-sized opaque token.
const _: () = assert!(std::mem::size_of::<NativeCredit>() <= std::mem::size_of::<Reservation>());
impl Drop for NativeCredit {
    fn drop(&mut self) {
        let mut used = self
            .pool
            .native_used
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        *used -= self.bytes;
    }
}

static POOLS: LazyLock<Mutex<std::collections::HashMap<usize, Weak<NodeAuditMaintenance>>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

impl NodeAuditMaintenance {
    pub(crate) const WORKSPACE_BYTES: u64 = 2 * AuditRetentionBudget::MAINTENANCE_BYTES;
    pub(crate) const RESIDENT_SLOTS: usize = 4;

    pub(crate) fn install(admission: &Arc<NodeAdmission>) -> Result<Arc<Self>> {
        let mut pools = POOLS.lock().map_err(|_| {
            Error::new(
                ErrorCode::Unavailable,
                "audit maintenance ownership unavailable",
            )
        })?;
        pools.retain(|_, pool| pool.strong_count() > 0);
        let key = Arc::as_ptr(admission.memory()) as usize;
        if let Some(pool) = pools.get(&key).and_then(Weak::upgrade) {
            return Ok(pool);
        }
        // Native KV leases suballocate from this charged escrow without taking
        // more ledger slots. Its exact MemoryCore identity is checked per call.
        let escrow = admission.reserve_audit_escrow(Self::WORKSPACE_BYTES)?;
        // Keep a separate free workspace for Raft publication and bounded
        // archive allocations. Ordinary Operation charges cannot spend it;
        // unscoped native Resident traffic still shares this free capacity.
        let protection = admission
            .memory()
            .protect_ordinary(Self::WORKSPACE_BYTES, Self::RESIDENT_SLOTS)?;
        let pool = Arc::new(Self {
            preparation: Arc::new(tokio::sync::Semaphore::new(1)),
            applying: Mutex::new(()),
            memory: admission.memory().clone(),
            native_used: Mutex::new(0),
            _native_escrow: escrow,
            _ordinary_protection: protection,
        });
        pools.insert(key, Arc::downgrade(&pool));
        Ok(pool)
    }

    /// The guard is used only around synchronous audit preparation or apply.
    /// It is never carried across an await or into another thread.
    pub(crate) fn enter_scope(self: &Arc<Self>) -> AuditScope {
        let previous = ACTIVE_AUDIT.with(|active| active.replace(Some(self.clone())));
        AuditScope(previous)
    }

    pub(crate) fn current_for(memory: &Arc<MemoryCore>) -> Option<Arc<Self>> {
        ACTIVE_AUDIT.with(|active| {
            active
                .borrow()
                .as_ref()
                .filter(|pool| Arc::ptr_eq(&pool.memory, memory))
                .cloned()
        })
    }

    pub(crate) fn reserve_native(
        self: &Arc<Self>,
        bytes: u64,
    ) -> io::Result<kasumi_store::DiskMemoryLease> {
        let mut used = self.native_used.lock().map_err(|_| io::ErrorKind::Other)?;
        let next = used.checked_add(bytes).ok_or(io::ErrorKind::OutOfMemory)?;
        if next > Self::WORKSPACE_BYTES {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        *used = next;
        drop(used);
        Ok(kasumi_store::DiskMemoryLease::new(NativeCredit {
            pool: self.clone(),
            bytes,
        }))
    }
}

/// Process counters. Durable archive totals and backlog are in the tenant's
/// authenticated AuditRetentionState, not reconstructed from these counters.
#[derive(Clone, Debug, serde::Serialize)]
pub struct AuditMaintenanceStatus {
    pub failures: u64,
    pub committed_segments: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::AdmissionConfig;
    use kasumi_store::NodeDiskMemoryAdmission;

    #[test]
    fn resident_saturation_cannot_spend_scoped_native_escrow() {
        let total = NodeAuditMaintenance::WORKSPACE_BYTES * 4;
        let admission = NodeAdmission::with_fixed_memory(
            AdmissionConfig {
                max_inflight_bytes: Some(total),
                ..Default::default()
            },
            2 << 30,
            0,
        )
        .unwrap();
        let pool = NodeAuditMaintenance::install(&admission).unwrap();
        let ordinary = admission
            .reserve_resident(total - admission.snapshot().reserved_bytes)
            .unwrap();
        assert!(admission.reserve(1, None).is_err());
        assert!(admission.reserve_resident(1).is_err());
        assert!(admission.memory().clone().reserve_installed(4096).is_err());
        // This proves the synchronous prep/apply KV lease path only. Raft's
        // asynchronous proposal and log writes use ordinary Resident admission.
        let baseline = admission.snapshot();
        let native = {
            let _scope = pool.enter_scope();
            admission.memory().clone().reserve_installed(4096).unwrap()
        };
        assert_eq!(
            admission.snapshot().live_reservations,
            baseline.live_reservations
        );
        assert_eq!(admission.snapshot().reserved_bytes, baseline.reserved_bytes);
        assert!(admission.memory().clone().reserve_installed(4096).is_err());
        drop(native);
        assert_eq!(*pool.native_used.lock().unwrap(), 0);
        drop(ordinary);
        drop(pool);
        let remaining = total - admission.snapshot().reserved_bytes;
        assert!(admission.reserve(remaining, None).is_ok());
    }

    #[tokio::test]
    async fn tenants_share_capacity_and_retained_workers_keep_it_owned() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let first = NodeAuditMaintenance::install(&admission).unwrap();
        let second = NodeAuditMaintenance::install(&admission).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(
            crate::test_utils::reserved_payload_bytes(&admission),
            NodeAuditMaintenance::WORKSPACE_BYTES
        );
        assert_eq!(admission.snapshot().inflight_operations, 0);
        let permit = first.preparation.clone().acquire_owned().await.unwrap();
        assert!(second.preparation.try_acquire().is_err());
        // Applying must remain available while a proposal owns preparation.
        drop(second.applying.try_lock().unwrap());
        let worker = first.clone();
        drop(first);
        drop(second);
        assert_eq!(
            crate::test_utils::reserved_payload_bytes(&admission),
            NodeAuditMaintenance::WORKSPACE_BYTES
        );
        drop(permit);
        drop(worker);
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), 0);
    }

    #[test]
    fn facades_sharing_memory_share_one_pool_and_preparation_lane() {
        let first_admission = NodeAdmission::new(Default::default()).unwrap();
        let second_admission =
            NodeAdmission::from_memory(first_admission.memory().clone()).unwrap();
        let baseline = first_admission.snapshot().reserved_bytes;

        let first = NodeAuditMaintenance::install(&first_admission).unwrap();
        assert_eq!(
            first_admission.snapshot().reserved_bytes,
            baseline + NodeAuditMaintenance::WORKSPACE_BYTES
        );
        let second = NodeAuditMaintenance::install(&second_admission).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(
            second_admission.snapshot().reserved_bytes,
            baseline + NodeAuditMaintenance::WORKSPACE_BYTES
        );

        let permit = first.preparation.try_acquire().unwrap();
        assert!(second.preparation.try_acquire().is_err());
        drop(permit);
    }

    #[test]
    fn operation_reservations_leave_four_slots_for_raft_resident_work() {
        let admission = NodeAdmission::with_fixed_memory(
            AdmissionConfig {
                max_inflight_bytes: Some(512 << 20),
                max_reservations: 8,
                ..Default::default()
            },
            2 << 30,
            0,
        )
        .unwrap();
        let pool = NodeAuditMaintenance::install(&admission).unwrap();
        let ordinary = admission.reserve(0, None).unwrap();
        assert!(admission.reserve(0, None).is_err());
        let resident: Vec<_> = (0..NodeAuditMaintenance::RESIDENT_SLOTS)
            .map(|_| admission.reserve_resident(1).unwrap())
            .collect();
        assert!(admission.reserve_resident(0).is_err());
        let native = {
            let _scope = pool.enter_scope();
            (0..16)
                .map(|_| admission.memory().clone().reserve_installed(0).unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(admission.snapshot().live_reservations, 8);
        drop(native);
        drop(resident);
        drop(ordinary);
        drop(pool);
        assert!(admission.reserve(0, None).is_ok());
    }

    #[test]
    fn retained_ordinary_charge_cannot_grow_into_audit_headroom() {
        let total = NodeAuditMaintenance::WORKSPACE_BYTES * 4;
        let admission = NodeAdmission::with_fixed_memory(
            AdmissionConfig {
                max_inflight_bytes: Some(total),
                ..Default::default()
            },
            2 << 30,
            0,
        )
        .unwrap();
        let pool = NodeAuditMaintenance::install(&admission).unwrap();
        let mut retained = admission.reserve(1, None).unwrap();
        retained.retain_workspace();
        let ordinary = admission
            .reserve(
                total - admission.snapshot().reserved_bytes - NodeAuditMaintenance::WORKSPACE_BYTES,
                None,
            )
            .unwrap();
        assert!(retained.reserve_additional(1).is_err());
        assert!(retained.handoff_workspace(&admission, 2).is_err());
        drop(ordinary);
        drop(pool);
    }
}
