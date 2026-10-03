use super::*;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

// Cache-only witness: the enclosing native caller tests prove actual output
// admission. Here any temporary CachedBytes workspace request is a failure.
struct NoWorkspace(Arc<Admission>);
impl StorageAdmission for NoWorkspace {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.0.check_owner()
    }
    fn reserve_workspace(&self, _: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        panic!("read-into requested a temporary cache workspace")
    }
    fn quote_cache_memory(&self, bytes: u64) -> Result<crate::CacheMemoryQuote, AdmissionError> {
        self.0.quote_cache_memory(bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, AdmissionError> {
        self.0.clone().reserve_cache_memory(bytes)
    }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        self.0.check_owner()
    }
    fn owner_failed(&self) {
        self.0.owner_failed();
    }
}

fn cache(limit: u64, provider_limit: u64) -> (NativeCache<u64>, Arc<Admission>) {
    let admission = Admission::new(provider_limit);
    (
        NativeCache::new(
            CacheConfig { byte_limit: limit },
            Arc::new(NoWorkspace(admission.clone())),
        ),
        admission,
    )
}

#[test]
fn read_into_retains_fitting_miss_and_trains_hit_without_touching_destination() {
    let (mut cache, admission) = cache(1 << 20, u64::MAX);
    let mut destination = [0xc3; 1024];
    let first = cache
        .load_or_read_into(7, &mut destination, |bytes| {
            bytes.fill(0x71);
            Ok::<_, ()>(())
        })
        .unwrap()
        .unwrap();
    assert_eq!(first.as_bytes(), &[0x71; 1024]);
    assert_eq!(destination, [0xc3; 1024]);
    let before = admission.used();
    let second = cache
        .load_or_read_into(7, &mut destination, |_| -> Result<(), ()> {
            panic!("hot value reached loader")
        })
        .unwrap()
        .unwrap();
    assert!(CachedBytes::ptr_eq(&first, &second));
    assert_eq!(destination, [0xc3; 1024]);
    assert_eq!(admission.used(), before);
    assert_eq!(cache.frequency(7), 2);
    let stats = cache.stats();
    assert_eq!(
        (stats.hits, stats.misses, stats.loads, stats.uncached_loads),
        (1, 1, 1, 0)
    );
    cache.clear();
    // clear releases lookup ownership; the live cache can still retain idle
    // aggregate credit. Retire it before testing the final output-only tail.
    drop(cache);
    assert_guard_only_pool(&admission, &first);
    let retained = admission.used();
    assert!(retained > 0);
    drop(first);
    assert_eq!(admission.used(), retained);
    assert_eq!(second.as_bytes(), &[0x71; 1024]);
    drop(second);
    assert_eq!(admission.used(), 0);
}

#[test]
fn read_into_local_and_provider_capacity_refusal_fill_only_existing_destination() {
    for (limit, provider_limit) in [(0, u64::MAX), (1, u64::MAX), (1 << 20, 0)] {
        let (mut cache, admission) = cache(limit, provider_limit);
        let mut destination = [0; 1024];
        let calls = Cell::new(0);
        assert!(
            cache
                .load_or_read_into(8, &mut destination, |bytes| {
                    calls.set(calls.get() + 1);
                    bytes.fill(0x82);
                    Ok::<_, ()>(())
                })
                .unwrap()
                .is_none()
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(destination, [0x82; 1024]);
        let stats = cache.stats();
        assert_eq!(
            (stats.hits, stats.misses, stats.loads, stats.uncached_loads),
            (0, 1, 1, 1)
        );
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.cached_bytes + stats.pinned_bytes, 0);
        cache.clear();
        assert_eq!(admission.used(), 0);
    }
    // Preserve a real existing pool/slot directory, then refuse payload growth
    // rather than initial metadata. The large value fits the local cache cap.
    let (mut cache, admission) = cache(1 << 20, u64::MAX);
    drop(
        cache
            .load_or_read_into(1, &mut [0; 64], |out| {
                out.fill(1);
                Ok::<_, ()>(())
            })
            .unwrap(),
    );
    let retained = admission.used();
    admission.limit.store(retained, Ordering::Release);
    let mut destination = vec![0; 128 << 10];
    assert!(
        cache
            .load_or_read_into(2, &mut destination, |out| {
                out.fill(2);
                Ok::<_, ()>(())
            })
            .unwrap()
            .is_none()
    );
    assert!(destination.iter().all(|byte| *byte == 2));
    assert_eq!(cache.stats().entries, 1);
    assert!(cache.peek(1).is_some());
    assert_eq!(cache.stats().uncached_loads, 1);
    assert_eq!(admission.used(), retained);
    cache.clear();
    assert_eq!(admission.used(), 0);
}

#[test]
fn read_into_loader_original_and_capacity_are_never_retried_or_counted_successful() {
    for limit in [0, 1 << 20] {
        let (mut cache, admission) = cache(limit, u64::MAX);
        let mut destination = [0; 512];
        let calls = Cell::new(0);
        let original = Arc::new(());
        let result = cache.load_or_read_into(10, &mut destination, |_| {
            calls.set(calls.get() + 1);
            Err(original.clone())
        });
        match result {
            Err(CacheLoadError::Load(found)) => assert!(Arc::ptr_eq(&original, &found)),
            _ => panic!("loader original changed"),
        }
        assert_eq!(calls.get(), 1);
        let result = cache.load_or_read_into(11, &mut destination, |_| {
            calls.set(calls.get() + 1);
            Err(crate::CoreError::CapacityDenied)
        });
        assert!(matches!(
            result,
            Err(CacheLoadError::Load(crate::CoreError::CapacityDenied))
        ));
        assert_eq!(calls.get(), 2);
        let stats = cache.stats();
        assert_eq!(
            (
                stats.misses,
                stats.loads,
                stats.uncached_loads,
                stats.entries
            ),
            (2, 0, 0, 0)
        );
        assert_eq!(stats.cached_bytes + stats.pinned_bytes, 0);
        cache.clear();
        assert_eq!(admission.used(), 0);
    }
}

#[test]
fn read_into_owner_failures_and_postload_expiry_never_become_optional_misses() {
    for phase in 0..4 {
        let (mut cache, admission) = cache(1 << 20, u64::MAX);
        match phase {
            0 => admission.failed.store(true, Ordering::Release),
            1 => admission.fail_next_quote.store(true, Ordering::Release),
            2 => admission.fail_next_reserve.store(true, Ordering::Release),
            _ => {}
        }
        let mut destination = [0; 512];
        let calls = Cell::new(0);
        let result = cache.load_or_read_into(12, &mut destination, |bytes| {
            calls.set(calls.get() + 1);
            assert_eq!(phase, 3);
            bytes.fill(9);
            admission.failed.store(true, Ordering::Release);
            Ok::<_, ()>(())
        });
        assert!(matches!(
            result,
            Err(CacheLoadError::Admission(AdmissionError::OwnerFailed))
        ));
        assert_eq!(calls.get(), usize::from(phase == 3));
        let stats = cache.stats();
        assert_eq!(
            (stats.loads, stats.uncached_loads, stats.entries),
            (0, 0, 0)
        );
        assert_eq!(stats.cached_bytes + stats.pinned_bytes, 0);
        cache.clear();
        assert_eq!(admission.used(), 0);
    }
    // A direct (unretained) successful loader also requires a positive postcheck.
    let (mut cache, admission) = cache(0, u64::MAX);
    let result = cache.load_or_read_into(13, &mut [0; 1], |_| {
        admission.failed.store(true, Ordering::Release);
        Ok::<_, ()>(())
    });
    assert!(matches!(
        result,
        Err(CacheLoadError::Admission(AdmissionError::OwnerFailed))
    ));
    assert_eq!((cache.stats().loads, cache.stats().uncached_loads), (0, 0));
}

#[test]
fn read_into_panicking_loader_releases_optional_payload_credit_without_retry() {
    for limit in [0, 1 << 20] {
        let (mut cache, admission) = cache(limit, u64::MAX);
        let original = Arc::new(17usize);
        let calls = Cell::new(0);
        let result = catch_unwind(AssertUnwindSafe(|| {
            cache.load_or_read_into(14, &mut [0; 512], |_| -> Result<(), ()> {
                calls.set(calls.get() + 1);
                std::panic::panic_any(original.clone())
            })
        }));
        let Err(panic) = result else {
            panic!("loader panic was swallowed")
        };
        assert!(Arc::ptr_eq(
            panic.downcast_ref::<Arc<usize>>().unwrap(),
            &original
        ));
        assert_eq!(calls.get(), 1);
        let stats = cache.stats();
        assert_eq!(
            (stats.loads, stats.uncached_loads, stats.entries),
            (0, 0, 0)
        );
        assert_eq!(stats.cached_bytes + stats.pinned_bytes, 0);
        cache.clear();
        assert_eq!(admission.used(), 0);
    }
}

#[test]
fn read_into_publication_refusal_does_not_train_policy_or_enter_loader() {
    let (mut cache, admission) = cache(1 << 20, u64::MAX);
    cache.begin_publication_candidates().unwrap();
    let before = cache.stats();
    let result = cache.load_or_read_into(15, &mut [0; 512], |_| -> Result<(), ()> {
        panic!("publication refusal reached loader")
    });
    assert!(matches!(
        result,
        Err(CacheLoadError::Admission(AdmissionError::OwnerFailed))
    ));
    assert_eq!(cache.stats(), before);
    assert_eq!(cache.frequency(15), 0);
    cache.clear_publication_candidates().unwrap();
    cache.clear();
    assert_eq!(admission.used(), 0);
}

#[test]
fn read_into_disabled_retention_allocates_no_second_value_owner() {
    let (mut cache, admission) = cache(0, u64::MAX);
    let mut destination = [0u8; 8192];
    // Reuse the KV binary's actual System allocator observer. The stack
    // destination and cache/provider exist before this window.
    let allocation = crate::snapshot_pins::allocation_tests::AllocationCount::start();
    let value = cache
        .load_or_read_into(16, &mut destination, |out| {
            out.fill(0x16);
            Ok::<_, ()>(())
        })
        .unwrap();
    let count = allocation.count();
    drop(allocation);
    assert!(value.is_none());
    assert_eq!(count, 0);
    assert_eq!(destination, [0x16; 8192]);
    assert_eq!(admission.used(), 0);
}
