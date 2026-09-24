//! Mandatory lower-layer resident charge ownership, independent of a facade.
use super::{ALLOCATION_ALLOWANCE, ChargeKind, MemoryCore, Reservation, ReserveKindError};
use std::{io, sync::Arc};

impl MemoryCore {
    fn installed_reservation_bytes(workspace: u64) -> Option<u64> {
        workspace.checked_add(
            u64::try_from(std::mem::size_of::<Reservation>())
                .ok()?
                .checked_add(ALLOCATION_ALLOWANCE)?,
        )
    }
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
        Self::installed_reservation_bytes(workspace)
            .ok_or_else(|| anyhow::anyhow!("installed reservation workspace overflow"))
    }
}
impl kasumi_store::NodeDiskMemoryAdmission for MemoryCore {
    fn storage_census(&self) -> &kasumi_store::StorageCensus {
        &self.storage_census
    }
    fn reserve_installed(
        self: Arc<Self>,
        workspace: u64,
    ) -> io::Result<kasumi_store::DiskMemoryLease> {
        let bytes =
            Self::installed_reservation_bytes(workspace).ok_or(io::ErrorKind::OutOfMemory)?;
        // Admission covers the opaque box before allocating it. The actual
        // Reservation keeps the shared core alive until its actual box is destroyed
        // and only then releases the resident byte/slot credit.
        let charge = self
            .reserve_kind_raw(bytes, None, ChargeKind::Resident)
            .map_err(|error| match error {
                ReserveKindError::Exhausted => io::ErrorKind::OutOfMemory,
                ReserveKindError::IdentifierExhausted => io::ErrorKind::Other,
            })?;
        Ok(kasumi_store::DiskMemoryLease::new(charge))
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
        assert_eq!(
            node.memory()
                .clone()
                .reserve_installed(1234)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::OutOfMemory,
        );
        let after = node.snapshot();
        assert_eq!(after.reserved_bytes, before.reserved_bytes);
        assert_eq!(after.live_reservations, before.live_reservations);
        assert_eq!(after.inflight_operations, 0);
        assert!(MemoryCore::required_installed_reservation_bytes(u64::MAX).is_err());
    }
    #[test]
    fn installed_storage_census_is_fixed_precharged_and_matches_the_exact_core() {
        let config = AdmissionConfig::default();
        let required =
            kasumi_store::StorageCensus::required_bytes(config.max_reservations).unwrap();
        let node = NodeAdmission::with_fixed_memory(config.clone(), 2 << 30, 0).unwrap();
        let core = node.memory();
        let provider: Arc<dyn NodeDiskMemoryAdmission> = core.clone();
        assert!(std::ptr::eq(
            core.storage_census(),
            provider.storage_census()
        ));
        assert_eq!(
            provider.storage_census().snapshot().capacity,
            config.max_reservations
        );
        assert!(core.snapshot().reserved_bytes >= required);
        assert_eq!(provider.storage_census().snapshot().databases, 0);
        assert_eq!(provider.storage_census().snapshot().writers, 0);
        assert!(provider.storage_census().bind_provider(&provider).is_err());
        let mut too_small = config;
        too_small.max_inflight_bytes =
            Some(MemoryCore::required_bookkeeping_bytes(&too_small).unwrap() - 1);
        assert!(NodeAdmission::with_fixed_memory(too_small, 2 << 30, 0).is_err());
    }
}
