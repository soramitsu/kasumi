//! Mandatory lower-layer resident charge ownership, independent of a facade.
use super::{ALLOCATION_ALLOWANCE, ChargeKind, MemoryCore, Reservation, ReserveKindError};
use std::{io, sync::Arc};

#[cfg(test)]
#[path = "../native_cache_admission_tests.rs"]
mod native_cache_admission_tests;

#[cfg(test)]
#[path = "../native_constructor_admission_tests.rs"]
mod native_constructor_admission_tests;

/// One concrete proposal reservation shared with accepted encoded input.
/// This closes its actual sized control without erasing a raw Arc/Reservation.
/// The initial producer quotes this control before new; every alias retires
/// through into_inner. The inline parking_lot mutex has no lazy native backing.
struct ProposalBudgetState {
    input_installed: bool,
    // LAST: the inline input disposition precedes the actual original grant.
    original: Reservation,
}
pub(crate) struct ProposalBudget(Option<Arc<parking_lot::Mutex<ProposalBudgetState>>>);
impl ProposalBudget {
    pub(crate) fn required_bytes() -> io::Result<u64> {
        kasumi_types::SharedBudgetCharge::required_bytes::<parking_lot::Mutex<ProposalBudgetState>>(
        )
    }
    pub(crate) fn new(original: Reservation) -> Self {
        Self(Some(Arc::new(parking_lot::Mutex::new(
            ProposalBudgetState {
                input_installed: false,
                original,
            },
        ))))
    }
    fn original(&self) -> &parking_lot::Mutex<ProposalBudgetState> {
        self.0.as_deref().expect("live original proposal budget")
    }
    pub(crate) fn reserve_additional(&self, bytes: u64) -> kasumi_types::Result<()> {
        let mut state = self.original().lock();
        if state.input_installed {
            return Err(kasumi_types::Error::new(
                kasumi_types::ErrorCode::Unavailable,
                "accepted input budget cannot grow",
            ));
        }
        state.original.reserve_additional(bytes)
    }
    #[cfg(test)]
    pub(crate) fn allocation_address(&self) -> usize {
        std::ptr::from_ref(self.original()) as usize
    }
    pub(crate) fn retain_workspace(&self) {
        self.original().lock().original.retain_workspace();
    }
}
impl Clone for ProposalBudget {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl Drop for ProposalBudget {
    fn drop(&mut self) {
        drop(Arc::into_inner(
            self.0.take().expect("live original proposal budget"),
        ));
    }
}

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

    /// Pre-submission transfer of one original proposal reservation. The same
    /// actual provider and live ledger slot are checked before Box/control work.
    /// The minimum includes exact encoded backing and, when prepared, only the
    /// known mutation change-tree recipe. Other semantic apply workspace is not
    /// certified by the old proposal estimate or by an opaque input alias.
    pub(crate) fn bind_application_input(
        self: &Arc<Self>,
        original: &ProposalBudget,
        install: &mut kasumi_raft::ApplicationInputInstall,
    ) -> Result<(), kasumi_raft::InputBindingError> {
        use kasumi_raft::InputBindingError;
        let provider: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = self.clone();
        let mut original_state = original.original().lock();
        if original_state.input_installed {
            return Err(InputBindingError::Repeated);
        }
        let reservation = &original_state.original;
        if !Arc::ptr_eq(self, &reservation.core) {
            return Err(InputBindingError::Foreign);
        }
        let permit = install.try_bind(&provider)?;
        let required = permit
            .requirements()
            .with_token::<ProposalBudget>()
            .map_err(|_| InputBindingError::Insufficient)?;
        {
            let state = self.data.state.lock().unwrap_or_else(|p| p.into_inner());
            let charge = state
                .charge(reservation.slot, reservation.id)
                .ok_or(InputBindingError::Missing)?;
            let required = required
                .checked_add(
                    ProposalBudget::required_bytes()
                        .map_err(|_| InputBindingError::Insufficient)?,
                )
                .ok_or(InputBindingError::Insufficient)?;
            if charge.bytes < required {
                return Err(InputBindingError::Insufficient);
            }
        }
        // The actual original budget is shared by closed controls; producer
        // work/response and accepted encoded input cannot refund one another's
        // charge early. Cloning allocates no new grant or control.
        original_state.input_installed = true;
        permit.bind(original.clone());
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
    fn install_native_constructor(
        self: Arc<Self>,
        install: &mut kasumi_store::NativeConstructorInstall<'_>,
    ) -> io::Result<()> {
        let provider: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = self.clone();
        let permit = install
            .try_begin_bind(provider)
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        let bytes = Self::installed_reservation_bytes(permit.request_bytes())
            .ok_or(io::ErrorKind::OutOfMemory)?;
        // Native construction is ordinary resident work, including during an
        // audit scope. Admit the concrete Reservation allocation before binding
        // its original token into the caller-owned constructor receiver.
        let charge = match self.reserve_kind_raw(
            bytes,
            None,
            ChargeKind::Resident,
            super::ChargeOrigin::OtherOrdinary,
        ) {
            Ok(charge) => charge,
            Err(ReserveKindError::Exhausted) => {
                return Err(permit.refuse_capacity(io::ErrorKind::OutOfMemory.into()));
            }
            Err(ReserveKindError::IdentifierExhausted | ReserveKindError::Missing) => {
                return Err(io::ErrorKind::Other.into());
            }
        };
        permit.bind(charge);
        Ok(())
    }

    fn install_source_metadata(
        self: Arc<Self>,
        install: &mut kasumi_store::SourceMetadataInstall<'_>,
    ) -> io::Result<()> {
        let provider: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = self.clone();
        let permit = install
            .try_begin_bind(provider)
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        let bytes = Self::installed_reservation_bytes(permit.request_bytes())
            .ok_or(io::ErrorKind::OutOfMemory)?;
        // The exact constructor, including History, is ordinary source work.
        // Publication lanes are standing reservations acquired ahead of work;
        // this does not borrow audit TLS or bypass cache/ordinary headroom.
        let charge = match self.reserve_kind_raw(
            bytes,
            None,
            ChargeKind::Resident,
            super::ChargeOrigin::DocumentSource,
        ) {
            Ok(charge) => charge,
            Err(ReserveKindError::Exhausted) => {
                return Err(permit.refuse_capacity(io::ErrorKind::OutOfMemory.into()));
            }
            Err(ReserveKindError::IdentifierExhausted | ReserveKindError::Missing) => {
                return Err(io::ErrorKind::Other.into());
            }
        };
        #[cfg(test)]
        super::installed_drop_probe::observe(&charge);
        permit.bind(charge);
        Ok(())
    }

    fn quote_installed(&self, workspace: u64) -> io::Result<u64> {
        Self::installed_reservation_bytes(workspace)
            .ok_or_else(|| io::ErrorKind::OutOfMemory.into())
    }

    fn storage_census(&self) -> &kasumi_store::StorageCensus {
        &self.storage_census
    }
    fn reserve_installed(
        self: Arc<Self>,
        workspace: u64,
    ) -> io::Result<kasumi_store::DiskMemoryLease> {
        let bytes =
            Self::installed_reservation_bytes(workspace).ok_or(io::ErrorKind::OutOfMemory)?;
        if let Some(pool) = crate::audit_maintenance::NodeAuditMaintenance::current_for(&self) {
            return pool.reserve_native(bytes);
        }
        // Admission covers the opaque box before allocating it. The actual
        // Reservation keeps the shared core alive until its actual box is destroyed
        // and only then releases the resident byte/slot credit.
        let charge = self
            .reserve_kind_raw(
                bytes,
                None,
                ChargeKind::Resident,
                super::ChargeOrigin::OtherOrdinary,
            )
            .map_err(|error| match error {
                ReserveKindError::Exhausted => io::ErrorKind::OutOfMemory,
                ReserveKindError::IdentifierExhausted | ReserveKindError::Missing => {
                    io::ErrorKind::Other
                }
            })?;
        #[cfg(test)]
        super::installed_drop_probe::observe(&charge);
        Ok(kasumi_store::DiskMemoryLease::new(charge))
    }

    fn quote_cache_memory(&self, credit_bytes: u64) -> io::Result<kasumi_kv::CacheMemoryQuote> {
        let overhead = Self::installed_reservation_bytes(0).ok_or(io::ErrorKind::OutOfMemory)?;
        kasumi_kv::CacheMemoryQuote::new(credit_bytes, overhead)
            .ok_or_else(|| io::ErrorKind::OutOfMemory.into())
    }

    fn reserve_cache_memory(
        self: Arc<Self>,
        credit_bytes: u64,
    ) -> io::Result<kasumi_kv::CacheMemoryLease> {
        let quote = self.quote_cache_memory(credit_bytes)?;
        // Deliberately bypass ACTIVE_AUDIT: optional retention and temporary
        // rehash custody must not strand protected maintenance escrow.
        let charge = self
            .reserve_kind_raw(
                quote.charged_bytes(),
                None,
                ChargeKind::Resident,
                super::ChargeOrigin::NativeCache,
            )
            .map_err(|error| match error {
                ReserveKindError::Exhausted => io::ErrorKind::OutOfMemory,
                ReserveKindError::IdentifierExhausted | ReserveKindError::Missing => {
                    io::ErrorKind::Other
                }
            })?;
        Ok(kasumi_kv::CacheMemoryLease::new(quote, charge))
    }
}

impl kasumi_kv::CacheMemoryReservation for Reservation {
    fn try_grow(&mut self, additional_bytes: u64) -> Result<(), kasumi_kv::AdmissionError> {
        self.reserve_additional_raw(additional_bytes)
            .map_err(|error| match error {
                ReserveKindError::Exhausted => kasumi_kv::AdmissionError::CapacityDenied,
                ReserveKindError::IdentifierExhausted | ReserveKindError::Missing => {
                    kasumi_kv::AdmissionError::OwnerFailed
                }
            })
    }

    fn retain_charge(&mut self, charged_bytes: u64) {
        self.retain(charged_bytes);
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

    fn cache_policy() -> AdmissionConfig {
        AdmissionConfig {
            max_inflight_bytes: Some(16 << 20),
            max_reservations: 16,
            cache_work_reserve_bytes: Some(4 << 20),
            cache_work_reserve_slots: Some(4),
            ..Default::default()
        }
    }

    #[test]
    fn cache_credit_grows_in_one_slot_and_retains_its_exact_core() {
        let node = NodeAdmission::with_fixed_memory(cache_policy(), 2 << 30, 0).unwrap();
        let core = node.memory().clone();
        let baseline = core.snapshot();
        let quote = core.quote_cache_memory(1024).unwrap();
        assert_eq!(
            quote.charged_bytes(),
            MemoryCore::required_installed_reservation_bytes(1024).unwrap()
        );
        let mut cache = core.clone().reserve_cache_memory(1024).unwrap();
        let next = core.data.state.lock().unwrap().next;
        cache.try_grow_to(1 << 20).unwrap();
        assert_eq!(core.data.state.lock().unwrap().next, next);
        assert_eq!(
            core.snapshot().live_reservations,
            baseline.live_reservations + 1
        );
        assert_eq!(
            core.snapshot().reserved_bytes,
            baseline.reserved_bytes + cache.quote().charged_bytes()
        );
        let before = core.snapshot();
        assert_eq!(
            cache.try_grow_to(u64::MAX),
            Err(kasumi_kv::AdmissionError::CapacityDenied)
        );
        assert_eq!(core.snapshot().reserved_bytes, before.reserved_bytes);
        assert!(cache.shrink_to(123));
        assert_eq!(
            core.snapshot().reserved_bytes,
            baseline.reserved_bytes + quote.overhead_bytes() + 123
        );
        drop(node);
        let retained = Arc::downgrade(&core);
        drop(core);
        assert!(retained.upgrade().is_some());
        drop(cache);
        assert!(retained.upgrade().is_none());
    }

    #[test]
    fn cache_growth_leaves_byte_headroom_and_cleanup_never_readmits() {
        let policy = cache_policy();
        let total = policy.max_inflight_bytes.unwrap();
        let reserve = policy.cache_work_reserve_bytes.unwrap();
        let node = NodeAdmission::with_fixed_memory(policy, 2 << 30, 0).unwrap();
        let core = node.memory().clone();
        let baseline = core.snapshot();
        let overhead = core.quote_cache_memory(0).unwrap().overhead_bytes();
        let credit = total - baseline.reserved_bytes - reserve - overhead;
        let mut cache = core.clone().reserve_cache_memory(credit).unwrap();
        let before = core.snapshot();
        assert_eq!(before.reserved_bytes, total - reserve);
        assert_eq!(
            cache.try_grow_to(credit + 1),
            Err(kasumi_kv::AdmissionError::CapacityDenied)
        );
        assert_eq!(core.snapshot().reserved_bytes, before.reserved_bytes);
        let work = core.clone().reserve_installed(reserve - overhead).unwrap();
        assert_eq!(core.snapshot().reserved_bytes, total);
        core.data.state.lock().unwrap().pressured = true;
        assert!(cache.shrink_to(0));
        assert_eq!(cache.quote().charged_bytes(), overhead);
        drop(cache);
        drop(work);
        assert_eq!(core.snapshot().reserved_bytes, baseline.reserved_bytes);
        assert_eq!(
            core.snapshot().live_reservations,
            baseline.live_reservations
        );
    }

    #[test]
    fn cache_respects_slot_headroom_on_acquisition_and_growth() {
        let policy = cache_policy();
        let reserve = policy.cache_work_reserve_slots.unwrap();
        let limit = policy.max_reservations;
        let node = NodeAdmission::with_fixed_memory(policy, 2 << 30, 0).unwrap();
        let core = node.memory().clone();
        let mut cache = core.clone().reserve_cache_memory(1).unwrap();
        let mut work = Vec::new();
        while core.snapshot().live_reservations < limit - reserve {
            work.push(core.clone().reserve_installed(0).unwrap());
        }
        cache.try_grow_to(2).unwrap();
        assert_eq!(
            core.clone().reserve_cache_memory(0).err().unwrap().kind(),
            io::ErrorKind::OutOfMemory
        );
        work.push(core.clone().reserve_installed(0).unwrap());
        let before = core.snapshot();
        assert_eq!(
            cache.try_grow_to(3),
            Err(kasumi_kv::AdmissionError::CapacityDenied)
        );
        assert_eq!(core.snapshot().reserved_bytes, before.reserved_bytes);
        while core.snapshot().live_reservations < limit {
            work.push(core.clone().reserve_installed(0).unwrap());
        }
        assert!(cache.shrink_to(0));
        drop(cache);
        drop(work);
    }

    #[test]
    fn cache_preserves_audit_protection_and_never_uses_scoped_escrow() {
        // Admit both the 128 MiB audit escrow and its independent 128 MiB
        // required-work protection, plus bookkeeping and optional cache room.
        let node = NodeAdmission::with_fixed_memory(
            AdmissionConfig {
                max_inflight_bytes: Some(512 << 20),
                ..AdmissionConfig::default()
            },
            2 << 30,
            0,
        )
        .unwrap();
        let core = node.memory().clone();
        let pool = crate::audit_maintenance::NodeAuditMaintenance::install(&node).unwrap();
        let baseline = core.snapshot();
        let (reserve, _) = core.data.config.cache_work_headroom(core.data.max_bytes);
        let protected = core.data.state.lock().unwrap().ordinary_protected;
        let overhead = core.quote_cache_memory(0).unwrap().overhead_bytes();
        let credit = core.data.max_bytes - baseline.reserved_bytes - reserve - protected - overhead;
        let scope = pool.enter_scope();
        let mut cache = core.clone().reserve_cache_memory(credit).unwrap();
        assert_eq!(
            core.snapshot().live_reservations,
            baseline.live_reservations + 1
        );
        assert_eq!(
            core.snapshot().reserved_bytes,
            baseline.reserved_bytes + cache.quote().charged_bytes()
        );
        let work = core.clone().reserve_installed(1024).unwrap();
        assert_eq!(
            core.snapshot().live_reservations,
            baseline.live_reservations + 1
        );
        assert_eq!(
            cache.try_grow_to(credit + 1),
            Err(kasumi_kv::AdmissionError::CapacityDenied)
        );
        drop(work);
        drop(scope);
        drop(cache);
        assert_eq!(core.snapshot().reserved_bytes, baseline.reserved_bytes);
    }

    #[test]
    fn headroom_may_disable_caching_without_disabling_required_work() {
        let mut policy = cache_policy();
        policy.cache_work_reserve_slots = Some(policy.max_reservations);
        let node = NodeAdmission::with_fixed_memory(policy, 2 << 30, 0).unwrap();
        let core = node.memory().clone();
        assert_eq!(
            core.clone().reserve_cache_memory(0).err().unwrap().kind(),
            io::ErrorKind::OutOfMemory
        );
        let work = core.reserve_installed(1024).unwrap();
        drop(work);
    }

    #[test]
    fn cache_work_reserves_reject_zero_and_values_above_installed_capacity() {
        let valid = cache_policy();
        for bytes in [0, valid.max_inflight_bytes.unwrap() + 1] {
            let mut policy = valid.clone();
            policy.cache_work_reserve_bytes = Some(bytes);
            assert!(
                NodeAdmission::with_fixed_memory(policy, 2 << 30, 0).is_err(),
                "accepted invalid cache byte reserve {bytes}"
            );
        }
        for slots in [0, valid.max_reservations + 1] {
            let mut policy = valid.clone();
            policy.cache_work_reserve_slots = Some(slots);
            assert!(
                NodeAdmission::with_fixed_memory(policy, 2 << 30, 0).is_err(),
                "accepted invalid cache slot reserve {slots}"
            );
        }
    }

    #[test]
    fn default_cache_work_reserves_follow_resolved_capacity_and_caps() {
        let small = AdmissionConfig {
            cache_work_reserve_bytes: None,
            cache_work_reserve_slots: None,
            ..cache_policy()
        };
        for (policy, expected_total, expected_headroom) in [
            (small, 16 << 20, (4 << 20, 4)),
            (AdmissionConfig::default(), 256 << 20, (64 << 20, 64)),
        ] {
            assert_eq!(policy.cache_work_reserve_bytes, None);
            assert_eq!(policy.cache_work_reserve_slots, None);
            // Fixed 2 GiB capacity resolves default high water to 1 GiB and
            // default total admission to one quarter of that high water.
            let node = NodeAdmission::with_fixed_memory(policy, 2 << 30, 0).unwrap();
            let core = node.memory();
            assert_eq!(core.data.max_bytes, expected_total);
            assert_eq!(
                core.data.config.cache_work_headroom(core.data.max_bytes),
                expected_headroom
            );
            let before = core.snapshot();
            let cache = core.clone().reserve_cache_memory(0).unwrap();
            assert_eq!(
                core.snapshot().reserved_bytes,
                before.reserved_bytes + cache.quote().charged_bytes()
            );
            drop(cache);
            assert_eq!(core.snapshot().reserved_bytes, before.reserved_bytes);
        }
    }

    #[test]
    fn full_byte_work_reserve_disables_cache_but_preserves_required_capacity() {
        let mut policy = cache_policy();
        let total = policy.max_inflight_bytes.unwrap();
        policy.cache_work_reserve_bytes = Some(total);
        let node = NodeAdmission::with_fixed_memory(policy, 2 << 30, 0).unwrap();
        let core = node.memory().clone();
        let before = core.snapshot();
        let next_id = core.data.state.lock().unwrap().next;
        assert_eq!(
            core.clone().reserve_cache_memory(0).err().unwrap().kind(),
            io::ErrorKind::OutOfMemory
        );
        assert_eq!(core.snapshot().reserved_bytes, before.reserved_bytes);
        assert_eq!(core.snapshot().live_reservations, before.live_reservations);
        assert_eq!(core.data.state.lock().unwrap().next, next_id);

        // Spend the exact remaining ordinary budget, including its concrete
        // lease overhead. The cache-only reserve must not reduce this path.
        let overhead = MemoryCore::required_installed_reservation_bytes(0).unwrap();
        let workspace = total - before.reserved_bytes - overhead;
        let work = core.clone().reserve_installed(workspace).unwrap();
        assert_eq!(core.snapshot().reserved_bytes, total);
        assert_eq!(
            core.snapshot().live_reservations,
            before.live_reservations + 1
        );
        drop(work);
        assert_eq!(core.snapshot().reserved_bytes, before.reserved_bytes);
        assert_eq!(core.snapshot().live_reservations, before.live_reservations);
    }
}

#[cfg(test)]
#[path = "../accepted_input_admission_tests.rs"]
mod accepted_input_admission_tests;
