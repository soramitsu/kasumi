//! Mandatory lower-layer resident charge ownership, independent of a facade.
use super::{MemoryCore, Reservation, allocation_bytes};
use std::{io, sync::Arc};

impl MemoryCore {
    /// Bind an engine owner to the exact lower-layer governor before any work.
    pub(crate) fn require_store_memory(
        self: &Arc<Self>,
        store: &kasumi_store::TenantStore,
    ) -> anyhow::Result<()> {
        let expected: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = self.clone();
        anyhow::ensure!(
            Arc::ptr_eq(&expected, store.persistent_disk().memory())
                && Arc::ptr_eq(&expected, store.scratch_disk().memory()),
            "engine and physical storage memory owners differ"
        );
        Ok(())
    }

    /// Disk workspace plus this provider's real opaque lease allocation.
    /// This checked planning helper allocates neither workspace nor a charge.
    pub fn required_installed_reservation_bytes(workspace: u64) -> anyhow::Result<u64> {
        workspace
            .checked_add(allocation_bytes::<Reservation>(1)?)
            .ok_or_else(|| anyhow::anyhow!("installed reservation workspace overflow"))
    }
}
impl kasumi_store::NodeDiskMemoryAdmission for MemoryCore {
    fn reserve_installed(self: Arc<Self>, workspace: u64) -> io::Result<Box<dyn Send + Sync>> {
        let bytes =
            Self::required_installed_reservation_bytes(workspace).map_err(io::Error::other)?;
        // Admission covers the opaque box before allocating it. The actual
        // Reservation keeps the shared core alive until this box is destroyed.
        let charge = self.reserve_resident(bytes).map_err(io::Error::other)?;
        Ok(Box::new(charge))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{AdmissionConfig, NodeAdmission};
    use kasumi_store::NodeDiskMemoryAdmission;

    #[test]
    fn installed_box_stays_charged_after_facade_drop_with_operation_slots_full() {
        let node =
            NodeAdmission::with_fixed_memory(AdmissionConfig::default(), 2 << 30, 0).unwrap();
        let core = node.memory().clone();
        let baseline = core.snapshot();
        let operations: Vec<_> = (0..64).map(|_| node.reserve(0, None).unwrap()).collect();
        assert!(node.reserve(0, None).is_err());
        let required = MemoryCore::required_installed_reservation_bytes(1234).unwrap();
        let installed = core.clone().reserve_installed(1234).unwrap();
        assert_eq!(core.snapshot().inflight_operations, 64);
        assert_eq!(core.snapshot().resident_reserved_bytes, required);
        assert_eq!(
            core.snapshot().reserved_bytes,
            baseline.reserved_bytes + required
        );
        drop(operations);
        drop(node);
        assert_eq!(core.snapshot().inflight_operations, 0);
        assert_eq!(core.snapshot().resident_reserved_bytes, required);
        let retained = Arc::downgrade(&core);
        drop(core);
        assert!(retained.upgrade().is_some());
        drop(installed);
        assert!(retained.upgrade().is_none());
    }

    #[test]
    fn lease_overhead_is_admitted_before_boxing_and_denial_preserves_counters() {
        let mut config = AdmissionConfig::default();
        let baseline = NodeAdmission::required_bookkeeping_bytes(&config).unwrap();
        let required = MemoryCore::required_installed_reservation_bytes(1234).unwrap();
        assert!(required > 1234);
        config.max_inflight_bytes = Some(baseline + required - 1);
        let node = NodeAdmission::with_fixed_memory(config, 2 << 30, 0).unwrap();
        let before = node.snapshot();
        assert!(node.memory().clone().reserve_installed(1234).is_err());
        let after = node.snapshot();
        assert_eq!(after.reserved_bytes, before.reserved_bytes);
        assert_eq!(after.live_reservations, before.live_reservations);
        assert_eq!(after.inflight_operations, 0);
        assert!(MemoryCore::required_installed_reservation_bytes(u64::MAX).is_err());
    }
}
