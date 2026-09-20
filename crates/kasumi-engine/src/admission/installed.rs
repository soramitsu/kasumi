//! The installed process has one RSS source and one aggregate reservation core.
use super::{AdmissionConfig, MemoryCore};
use std::sync::Arc;

// Inline parking_lot initialization and try_lock do not allocate a parked waiter
// before the first core's bookkeeping admission. Contention is a bounded denial.
struct Registry(parking_lot::Mutex<Option<Arc<MemoryCore>>>);
impl Registry {
    const fn new() -> Self {
        Self(parking_lot::Mutex::new(None))
    }
    fn select(&self, config: AdmissionConfig) -> anyhow::Result<Arc<MemoryCore>> {
        config.validate()?;
        let mut installed = self
            .0
            .try_lock()
            .ok_or_else(|| anyhow::anyhow!("installed memory admission selection is busy"))?;
        if let Some(core) = installed.as_ref() {
            core.require_policy(&config)?;
            anyhow::ensure!(
                !core
                    .data
                    .sampler_failed
                    .load(std::sync::atomic::Ordering::Acquire),
                "installed memory sampler failed; retained core cannot be replaced"
            );
            return Ok(core.clone());
        }
        let core = MemoryCore::new(config)?;
        *installed = Some(core.clone());
        Ok(core)
    }
}

pub(super) fn select(config: AdmissionConfig) -> anyhow::Result<Arc<MemoryCore>> {
    static INSTALLED: Registry = Registry::new();
    INSTALLED.select(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::NodeAdmission;

    #[tokio::test]
    async fn retained_registry_reuses_core_across_sealed_runtime_facades() {
        let registry = Registry::new();
        let policy = AdmissionConfig::default();
        let core = registry.select(policy.clone()).unwrap();
        let first = NodeAdmission::from_memory(core.clone()).unwrap();
        let resident = first.reserve_resident(1234).unwrap();
        first.drain_snapshot_startups().await.unwrap();
        assert!(first.snapshot_buffer_owner().is_err());
        let next_core = registry.select(policy.clone()).unwrap();
        assert!(Arc::ptr_eq(&core, &next_core));
        let next = NodeAdmission::from_memory(next_core).unwrap();
        assert!(first.shares_memory(&next));
        assert!(!Arc::ptr_eq(&first, &next));
        let buffer = next.snapshot_buffer_owner().unwrap();
        drop(buffer);
        drop(first);
        assert_eq!(next.snapshot().resident_reserved_bytes, 1234);
        drop(resident);
        assert_eq!(next.snapshot().resident_reserved_bytes, 0);
        next.drain_snapshot_startups().await.unwrap();
        drop(next);
        let identity = Arc::downgrade(&core);
        drop(core);
        let reopened = registry.select(policy).unwrap();
        assert!(Arc::ptr_eq(&identity.upgrade().unwrap(), &reopened));
    }

    #[test]
    fn conflicting_policy_never_replaces_or_charges_the_retained_core() {
        let registry = Registry::new();
        let policy = AdmissionConfig::default();
        let core = registry.select(policy.clone()).unwrap();
        let before = core.snapshot();
        let variants: [fn(&mut AdmissionConfig); 9] = [
            |v| v.high_water_bytes = Some(1 << 20),
            |v| v.low_water_bytes = Some(1),
            |v| v.max_inflight_bytes = Some(1 << 20),
            |v| v.max_inflight_operations += 1,
            |v| v.max_reservations += 1,
            |v| v.max_snapshot_startups += 1,
            |v| v.max_startup_scopes += 1,
            |v| v.sample_interval_ms += 1,
            |v| v.max_sample_age_ms += 1,
        ];
        for change in variants {
            let mut incompatible = policy.clone();
            change(&mut incompatible);
            let error = registry.select(incompatible).err().unwrap();
            assert!(error.to_string().contains("policy differs"));
            assert_eq!(core.snapshot().reserved_bytes, before.reserved_bytes);
            assert_eq!(core.snapshot().live_reservations, before.live_reservations);
            assert!(Arc::ptr_eq(
                &core,
                &registry.select(policy.clone()).unwrap()
            ));
        }
    }

    #[test]
    fn failed_sampler_denies_reuse_and_keeps_original_core_and_panic() {
        use super::super::{MemorySource, SystemLeaseClock};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::{Duration, Instant};
        struct Probe(AtomicUsize);
        impl MemorySource for Probe {
            fn resident_bytes(&self) -> anyhow::Result<u64> {
                if self.0.fetch_add(1, Ordering::SeqCst) == 1 {
                    std::panic::panic_any(0x751_u64);
                }
                Ok(0)
            }
        }
        let config = AdmissionConfig {
            sample_interval_ms: 10,
            ..Default::default()
        };
        let mut core = MemoryCore::create(
            config.clone(),
            1 << 30,
            Arc::new(Probe(AtomicUsize::new(0))),
            Arc::new(SystemLeaseClock),
        )
        .unwrap();
        Arc::get_mut(&mut core).unwrap().start_sampler().unwrap();
        let registry = Registry::new();
        *registry.0.lock() = Some(core.clone());
        let deadline = Instant::now() + Duration::from_secs(2);
        while !core.sampler.as_ref().unwrap().is_finished() {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        let baseline = core.snapshot().reserved_bytes;
        for _ in 0..2 {
            let error = registry.select(config.clone()).err().unwrap();
            assert!(error.to_string().contains("sampler failed"));
            assert!(Arc::ptr_eq(registry.0.lock().as_ref().unwrap(), &core));
            assert_eq!(core.snapshot().reserved_bytes, baseline);
            assert!(NodeAdmission::from_memory(core.clone()).is_err());
        }
        drop(registry.0.lock().take());
        let panic = Arc::get_mut(&mut core)
            .unwrap()
            .sampler
            .take()
            .unwrap()
            .join()
            .unwrap_err();
        assert_eq!(panic.downcast_ref::<u64>(), Some(&0x751));
    }

    #[test]
    fn concurrent_selection_is_denied_without_publishing_an_independent_core() {
        let registry = Registry::new();
        let held = registry.0.lock();
        let error = registry.select(AdmissionConfig::default()).err().unwrap();
        assert!(error.to_string().contains("selection is busy"));
        assert!(held.is_none());
        drop(held);
        assert!(registry.select(AdmissionConfig::default()).is_ok());
    }
}
