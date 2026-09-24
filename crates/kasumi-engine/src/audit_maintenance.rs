//! One reserved archive workspace per node, shared by every tenant.
use crate::admission::{NodeAdmission, OrdinaryProtection, Reservation};
use kasumi_types::{AuditRetentionBudget, Error, ErrorCode, Result};
use std::sync::{Arc, LazyLock, Mutex, Weak};

/// Preparation retains its lane until the proposed command resolves. Applying
/// replicas use a separate lane so a proposal can never wait on its own permit.
pub(crate) struct NodeAuditMaintenance {
    pub(crate) preparation: Arc<tokio::sync::Semaphore>,
    pub(crate) applying: Mutex<()>,
    _workspace: Reservation,
    _ordinary_protection: OrdinaryProtection,
}

static POOLS: LazyLock<Mutex<std::collections::HashMap<usize, Weak<NodeAuditMaintenance>>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

impl NodeAuditMaintenance {
    pub(crate) const WORKSPACE_BYTES: u64 = 2 * AuditRetentionBudget::MAINTENANCE_BYTES;

    pub(crate) fn install(admission: &Arc<NodeAdmission>) -> Result<Arc<Self>> {
        let mut pools = POOLS.lock().map_err(|_| {
            Error::new(
                ErrorCode::Unavailable,
                "audit maintenance ownership unavailable",
            )
        })?;
        pools.retain(|_, pool| pool.strong_count() > 0);
        let key = Arc::as_ptr(admission) as usize;
        if let Some(pool) = pools.get(&key).and_then(Weak::upgrade) {
            return Ok(pool);
        }
        let mut workspace = admission.reserve(Self::WORKSPACE_BYTES, None)?;
        workspace.retain_workspace();
        // The workspace charge alone would let ordinary requests reserve the
        // final byte. Keep equivalent headroom for native KV's transient write
        // staging and index leases when the archive worker runs later.
        let protection = admission.memory().protect_ordinary(Self::WORKSPACE_BYTES)?;
        let pool = Arc::new(Self {
            preparation: Arc::new(tokio::sync::Semaphore::new(1)),
            applying: Mutex::new(()),
            _workspace: workspace,
            _ordinary_protection: protection,
        });
        pools.insert(key, Arc::downgrade(&pool));
        Ok(pool)
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

    #[test]
    fn ordinary_saturation_keeps_admitted_resident_headroom_until_pool_drops() {
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
            .reserve(
                total - admission.snapshot().reserved_bytes - NodeAuditMaintenance::WORKSPACE_BYTES,
                None,
            )
            .unwrap();
        assert!(admission.reserve(1, None).is_err());
        let resident = admission.reserve_resident(4096).unwrap();
        assert!(admission.reserve(1, None).is_err());
        drop(resident);
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
}
