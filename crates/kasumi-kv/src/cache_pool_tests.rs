use super::*;
use crate::{CacheMemoryLease, CacheMemoryQuote, CacheMemoryReservation, OwnerFailed};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64};

struct Governor {
    used: AtomicU64,
    limit: AtomicU64,
    slots: AtomicUsize,
    peak_slots: AtomicUsize,
    slot_limit: usize,
    reservations: AtomicUsize,
    reservation_attempts: AtomicUsize,
    expire_at_refusal: AtomicUsize,
    growths: AtomicUsize,
    refusals: AtomicUsize,
    checks: AtomicUsize,
    failed: AtomicBool,
    refuse_growth_once: AtomicBool,
    release_on_growth: Mutex<Option<CachedBytes>>,
}

struct Reservation {
    governor: Arc<Governor>,
    bytes: u64,
}

impl Governor {
    fn new(limit: u64, slot_limit: usize) -> Arc<Self> {
        Arc::new(Self {
            used: AtomicU64::new(0),
            limit: AtomicU64::new(limit),
            slots: AtomicUsize::new(0),
            peak_slots: AtomicUsize::new(0),
            slot_limit,
            reservations: AtomicUsize::new(0),
            reservation_attempts: AtomicUsize::new(0),
            expire_at_refusal: AtomicUsize::new(0),
            growths: AtomicUsize::new(0),
            refusals: AtomicUsize::new(0),
            checks: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            refuse_growth_once: AtomicBool::new(false),
            release_on_growth: Mutex::new(None),
        })
    }

    fn add_bytes(&self, bytes: u64) -> Result<(), AdmissionError> {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|&total| total <= self.limit.load(Ordering::Acquire))
            })
            .map_err(|_| self.refused())?;
        Ok(())
    }

    fn refused(&self) -> AdmissionError {
        let count = self.refusals.fetch_add(1, Ordering::AcqRel) + 1;
        if self.expire_at_refusal.load(Ordering::Acquire) == count {
            self.failed.store(true, Ordering::Release);
        }
        AdmissionError::CapacityDenied
    }

    fn reserve(self: Arc<Self>, bytes: u64) -> Result<Reservation, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        self.slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |slots| {
                (slots < self.slot_limit).then_some(slots + 1)
            })
            .map_err(|_| AdmissionError::CapacityDenied)?;
        if let Err(error) = self.add_bytes(bytes) {
            self.slots.fetch_sub(1, Ordering::AcqRel);
            return Err(error);
        }
        self.peak_slots
            .fetch_max(self.slots.load(Ordering::Acquire), Ordering::AcqRel);
        self.reservations.fetch_add(1, Ordering::AcqRel);
        Ok(Reservation {
            governor: self,
            bytes,
        })
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.governor.used.fetch_sub(self.bytes, Ordering::AcqRel);
        self.governor.slots.fetch_sub(1, Ordering::AcqRel);
    }
}

impl CacheMemoryReservation for Reservation {
    fn try_grow(&mut self, bytes: u64) -> Result<(), AdmissionError> {
        self.governor.growths.fetch_add(1, Ordering::AcqRel);
        let released = self.governor.release_on_growth.lock().unwrap().take();
        drop(released);
        if self
            .governor
            .refuse_growth_once
            .swap(false, Ordering::AcqRel)
        {
            return Err(self.governor.refused());
        }
        self.governor.add_bytes(bytes)?;
        self.bytes += bytes;
        Ok(())
    }

    fn retain_charge(&mut self, bytes: u64) {
        assert!(bytes <= self.bytes);
        self.governor
            .used
            .fetch_sub(self.bytes - bytes, Ordering::AcqRel);
        self.bytes = bytes;
    }
}

impl StorageAdmission for Governor {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.checks.fetch_add(1, Ordering::AcqRel);
        if self.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }

    fn reserve_workspace(&self, _: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        // These fixtures exercise retained credit only. An unexpected bypass
        // must fail visibly instead of masking a failure of full residency.
        Err(AdmissionError::CapacityDenied)
    }

    fn quote_cache_memory(&self, credit: u64) -> Result<CacheMemoryQuote, AdmissionError> {
        CacheMemoryQuote::new(
            credit,
            size_of::<Reservation>() as u64 + ALLOCATION_ALLOWANCE,
        )
        .ok_or(AdmissionError::CapacityDenied)
    }

    fn reserve_cache_memory(
        self: Arc<Self>,
        credit: u64,
    ) -> Result<CacheMemoryLease, AdmissionError> {
        self.reservation_attempts.fetch_add(1, Ordering::AcqRel);
        let quote = self.quote_cache_memory(credit)?;
        let token = self.reserve(quote.charged_bytes())?;
        Ok(CacheMemoryLease::new(quote, token))
    }

    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }
}

fn retain(cache: &mut NativeCache, key: u64, len: usize) -> CachedBytes {
    cache
        .load_if_fits(key, len, |bytes| {
            bytes.fill(key as u8);
            Ok::<_, ()>(())
        })
        .unwrap()
        .expect("fixture value must remain resident")
}

#[test]
fn more_than_sixteen_thousand_values_share_one_reservation_and_two_overlap_slots() {
    const COUNT: u64 = 16_385;
    let governor = Governor::new(32 << 20, 2);
    let mut cache = NativeCache::new(
        CacheConfig {
            byte_limit: 16 << 20,
        },
        governor.clone(),
    );
    for key in 0..COUNT {
        drop(retain(&mut cache, key, 32));
        assert_eq!(governor.slots.load(Ordering::Acquire), 1);
    }
    let stats = cache.stats();
    assert_eq!(stats.entries, COUNT as usize);
    assert_eq!(stats.evictions, 0);
    assert_eq!(stats.resident_bytes, governor.used.load(Ordering::Acquire));
    assert_eq!(
        stats.admitted_credit_bytes,
        stats.allocated_bytes + stats.unused_credit_bytes
    );
    assert_eq!(
        stats.resident_bytes,
        stats.admitted_credit_bytes + stats.provider_overhead_bytes
    );
    assert!(stats.unused_credit_bytes < 64 << 10);
    assert!(stats.provider_overhead_bytes > 0);
    assert_eq!(governor.peak_slots.load(Ordering::Acquire), 2);
    assert!(governor.reservations.load(Ordering::Acquire) < 32);
    for key in 0..COUNT {
        assert_eq!(
            cache
                .load_if_fits(key, 32, |_| Err::<(), _>("unexpected read"))
                .unwrap()
                .unwrap()
                .as_bytes(),
            &[key as u8; 32]
        );
    }
    cache.clear();
    assert_eq!(governor.used.load(Ordering::Acquire), 0);
    assert_eq!(governor.slots.load(Ordering::Acquire), 0);
}

#[test]
fn aliases_and_cross_thread_last_guard_keep_pool_custody_after_cache_close() {
    let governor = Governor::new(4 << 20, 2);
    let mut cache = NativeCache::new(
        CacheConfig {
            byte_limit: 2 << 20,
        },
        governor.clone(),
    );
    let value = retain(&mut cache, 7, 128 << 10);
    for key in 10..100 {
        assert!(cache.alias_if_fits(7, key).unwrap());
        assert!(CachedBytes::ptr_eq(&value, &cache.peek(key).unwrap()));
    }
    assert_eq!(cache.stats().cached_bytes, value.charged_bytes());
    assert_eq!(governor.slots.load(Ordering::Acquire), 1);
    cache.clear();
    assert_eq!(cache.stats().pinned_bytes, value.charged_bytes());
    drop(cache);
    assert!(governor.used.load(Ordering::Acquire) >= value.charged_bytes());
    governor.failed.store(true, Ordering::Release);
    let checks = governor.checks.load(Ordering::Acquire);
    std::thread::spawn(move || {
        assert_eq!(value.as_bytes(), vec![7; 128 << 10]);
        drop(value);
    })
    .join()
    .unwrap();
    assert_eq!(governor.used.load(Ordering::Acquire), 0);
    assert_eq!(governor.slots.load(Ordering::Acquire), 0);
    assert_eq!(governor.checks.load(Ordering::Acquire), checks);
}

#[test]
fn rounded_admission_falls_back_to_exact_fit_without_reporting_provider_refusal() {
    let governor = Governor::new(24 << 10, 2);
    let mut cache = NativeCache::new(
        CacheConfig {
            byte_limit: 128 << 10,
        },
        governor.clone(),
    );
    drop(retain(&mut cache, 1, 8192));
    assert!(governor.refusals.load(Ordering::Acquire) > 0);
    assert!(!cache.take_maintenance_provider_refusal());
    assert_eq!(cache.maintenance_provider_denials(), 0);
    assert_eq!(
        cache.stats().admitted_credit_bytes,
        cache.stats().allocated_bytes
    );
    assert_eq!(cache.stats().entries, 1);
    assert_eq!(governor.slots.load(Ordering::Acquire), 1);
    drop(cache);
    assert_eq!(governor.used.load(Ordering::Acquire), 0);
}

#[test]
fn growth_refusal_can_release_this_pools_last_guard_without_reentering_its_lock() {
    let governor = Governor::new(1 << 20, 2);
    let mut cache = NativeCache::new(
        CacheConfig {
            byte_limit: 512 << 10,
        },
        governor.clone(),
    );
    let old = retain(&mut cache, 1, 48 << 10);
    assert!(cache.remove(1));
    let charged = governor.used.load(Ordering::Acquire);
    governor.limit.store(charged, Ordering::Release);
    *governor.release_on_growth.lock().unwrap() = Some(old);
    governor.refuse_growth_once.store(true, Ordering::Release);
    // The rounded request needs growth while the guard is alive. Its denial
    // callback retires the old payload, making the exact retry fit old credit.
    drop(retain(&mut cache, 2, 48 << 10));
    assert!(governor.refusals.load(Ordering::Acquire) > 0);
    assert_eq!(cache.stats().pinned_bytes, 0);
    assert_eq!(cache.stats().entries, 1);
    assert!(!cache.take_maintenance_provider_refusal());
    drop(cache);
    assert_eq!(governor.used.load(Ordering::Acquire), 0);
}

#[test]
fn tiny_budget_increases_keep_one_live_provider_slot_and_expired_credit_is_not_reused() {
    let governor = Governor::new(4 << 20, 2);
    let mut cache = NativeCache::new(
        CacheConfig {
            byte_limit: 16 << 10,
        },
        governor.clone(),
    );
    drop(retain(&mut cache, 0, 1024));
    for key in 1..96 {
        cache.set_byte_limit((16 + key * 2) << 10).unwrap();
        drop(retain(&mut cache, key, 1024));
        assert_eq!(governor.slots.load(Ordering::Acquire), 1);
    }
    let stats = cache.stats();
    governor.failed.store(true, Ordering::Release);
    for (key, len) in [(0, 1024), (1000, 1), (1001, 256 << 10)] {
        assert!(matches!(
            cache.load_if_fits(key, len, |_| Ok::<_, ()>(())),
            Err(CacheLoadError::Admission(AdmissionError::OwnerFailed))
        ));
    }
    assert_eq!(cache.stats(), stats);
    let checks = governor.checks.load(Ordering::Acquire);
    drop(cache);
    assert_eq!(governor.used.load(Ordering::Acquire), 0);
    assert_eq!(governor.checks.load(Ordering::Acquire), checks);
}

#[test]
fn metadata_exchange_rollback_keeps_credit_after_concurrent_payload_retirement() {
    let governor = Governor::new(1 << 20, 2);
    let owner: Arc<dyn StorageAdmission> = governor.clone();
    let pool = pool::Pool::new(&owner, 512, 512 << 10).unwrap_or_else(|_| panic!("pool"));
    let mut metadata = pool
        .borrow(owner.as_ref(), 32 << 10, false)
        .unwrap_or_else(|_| panic!("metadata"));
    let payload = pool
        .borrow(owner.as_ref(), 8 << 10, true)
        .unwrap_or_else(|_| panic!("payload"));
    let exchange = metadata
        .exchange(owner.as_ref(), 1024)
        .unwrap_or_else(|_| panic!("exchange"));
    drop(payload);
    assert!(pool.stats().credit >= 512 + (32 << 10));
    drop(exchange);
    assert_eq!(pool.stats().used, 512 + (32 << 10));
    let exchange = metadata
        .exchange(owner.as_ref(), 1024)
        .unwrap_or_else(|_| panic!("retry"));
    exchange.commit();
    assert_eq!(pool.stats().used, 1536);
    drop(metadata);
    drop(pool);
    assert_eq!(governor.used.load(Ordering::Acquire), 0);
}

#[test]
fn rejected_limit_keeps_guard_charge_and_restores_the_previous_borrow_limit() {
    let governor = Governor::new(1 << 20, 2);
    let original_limit = 128 << 10;
    let mut cache = NativeCache::new(
        CacheConfig {
            byte_limit: original_limit,
        },
        governor.clone(),
    );
    let guard = retain(&mut cache, 1, 48 << 10);
    assert_eq!(cache.set_byte_limit(0), Err(AdmissionError::CapacityDenied));
    assert_eq!(cache.config().byte_limit, original_limit);
    assert_eq!(cache.stats().pinned_bytes, guard.charged_bytes());
    assert!(governor.used.load(Ordering::Acquire) >= guard.charged_bytes());
    // Both old reader-owned bytes and the new current payload fit the original
    // configuration. A refused shrink must not leave a hidden zero pool limit.
    drop(retain(&mut cache, 2, 48 << 10));
    assert_eq!(cache.stats().entries, 1);
    assert!(cache.stats().resident_bytes <= original_limit);
    drop(guard);
    cache.set_byte_limit(0).unwrap();
    assert_eq!(governor.used.load(Ordering::Acquire), 0);
}

#[test]
fn reservation_refusal_expiry_fences_before_fallback_or_optional_pressure() {
    // A refusal can expire the owner on an already exact request, before a
    // fitting fallback, or during that fallback. All three are owner failures.
    for (exact_request, expiry_at) in [(true, 1), (false, 1), (false, 2)] {
        let governor = Governor::new(u64::MAX, 2);
        let control = 4096;
        let exact_charge = governor
            .quote_cache_memory(control)
            .unwrap()
            .charged_bytes();
        let limit = if exact_request { exact_charge } else { 1 << 20 };
        governor.limit.store(
            if exact_request || expiry_at == 2 {
                0
            } else {
                exact_charge
            },
            Ordering::Release,
        );
        governor
            .expire_at_refusal
            .store(expiry_at, Ordering::Release);
        let admission: Arc<dyn StorageAdmission> = governor.clone();
        assert!(matches!(
            pool::Pool::new(&admission, control, limit),
            Err(pool::BorrowError::Provider(AdmissionError::OwnerFailed))
        ));
        assert_eq!(governor.refusals.load(Ordering::Acquire), expiry_at);
        assert_eq!(
            governor.reservation_attempts.load(Ordering::Acquire),
            expiry_at
        );
        assert_eq!(governor.used.load(Ordering::Acquire), 0);
        assert_eq!(governor.slots.load(Ordering::Acquire), 0);
    }
}

#[test]
fn growth_refusal_expiry_preserves_existing_custody_and_never_becomes_pressure() {
    for (exact_request, expiry_at) in [(true, 1), (false, 1), (false, 2)] {
        let governor = Governor::new(u64::MAX, 2);
        let mut cache = NativeCache::new(
            CacheConfig {
                byte_limit: 1 << 20,
            },
            governor.clone(),
        );
        let guard = retain(&mut cache, 1, 48 << 10);
        let needed_credit =
            cache.stats().allocated_bytes + CachedBytes::charge_for_len(32 << 10).unwrap();
        let exact_charge = governor
            .quote_cache_memory(needed_credit)
            .unwrap()
            .charged_bytes();
        if exact_request {
            cache.set_byte_limit(exact_charge).unwrap();
        }
        let before = cache.stats();
        let growths = governor.growths.load(Ordering::Acquire);
        let attempts = governor.reservation_attempts.load(Ordering::Acquire);
        governor.limit.store(
            if exact_request || expiry_at == 2 {
                before.resident_bytes
            } else {
                exact_charge
            },
            Ordering::Release,
        );
        governor
            .expire_at_refusal
            .store(expiry_at, Ordering::Release);
        assert!(matches!(
            cache.load_if_fits(2, 32 << 10, |_| -> Result<(), ()> {
                panic!("expired owner entered payload loader")
            }),
            Err(CacheLoadError::Admission(AdmissionError::OwnerFailed))
        ));
        assert_eq!(governor.refusals.load(Ordering::Acquire), expiry_at);
        assert_eq!(
            governor.growths.load(Ordering::Acquire) - growths,
            expiry_at
        );
        assert_eq!(
            governor.reservation_attempts.load(Ordering::Acquire),
            attempts
        );
        assert_eq!(cache.stats(), before);
        assert_eq!(governor.used.load(Ordering::Acquire), before.resident_bytes);
        assert!(!cache.take_maintenance_provider_refusal());
        assert!(CachedBytes::ptr_eq(&guard, &cache.peek(1).unwrap()));
        assert_eq!(guard.as_bytes(), &[1; 48 << 10]);
        let checks = governor.checks.load(Ordering::Acquire);
        drop(cache);
        drop(guard);
        assert_eq!(governor.checks.load(Ordering::Acquire), checks);
        assert_eq!(governor.used.load(Ordering::Acquire), 0);
        assert_eq!(governor.slots.load(Ordering::Acquire), 0);
    }
}

#[test]
fn metadata_overlap_refusal_expiry_is_never_hidden_as_optional_pressure() {
    for operation in 0..3 {
        let governor = Governor::new(u64::MAX, 2);
        let mut cache = NativeCache::new(
            CacheConfig {
                byte_limit: 1 << 20,
            },
            governor.clone(),
        );
        for key in 0..17 {
            drop(retain(&mut cache, key, 64));
        }
        let guard = cache.peek(0).unwrap();
        for key in 1..17 {
            assert!(cache.remove(key));
        }
        let before = cache.stats();
        let previous_limit = cache.config.byte_limit;
        let previous_capacity = cache.slots.len();
        assert!(previous_capacity > MIN_SLOTS);
        let exact_credit = NativeCache::<u64>::metadata_base_charge()
            + NativeCache::<u64>::slots_charge(MIN_SLOTS).unwrap()
            + guard.charged_bytes();
        let smaller_limit = governor
            .quote_cache_memory(exact_credit)
            .unwrap()
            .charged_bytes();
        // set_byte_limit trims slack before asking for temporary custody; deny
        // even that smaller intermediate charge, without invalidating any
        // already admitted bytes. Every case must enter this exact refusal.
        governor.limit.store(0, Ordering::Release);
        governor.expire_at_refusal.store(1, Ordering::Release);
        let attempts = governor.reservation_attempts.load(Ordering::Acquire);
        let result = match operation {
            0 => cache.trim_metadata(),
            1 => cache.trim_metadata_for_warm(),
            2 => cache.set_byte_limit(smaller_limit),
            _ => unreachable!(),
        };
        assert_eq!(result, Err(AdmissionError::OwnerFailed));
        assert_eq!(governor.refusals.load(Ordering::Acquire), 1);
        assert_eq!(
            governor.reservation_attempts.load(Ordering::Acquire),
            attempts + 1
        );
        assert_eq!(cache.config.byte_limit, previous_limit);
        assert_eq!(cache.slots.len(), previous_capacity);
        let after = cache.stats();
        assert_eq!(after.entries, before.entries);
        assert_eq!(after.allocated_bytes, before.allocated_bytes);
        assert_eq!(after.cached_bytes, before.cached_bytes);
        assert_eq!(after.pinned_bytes, before.pinned_bytes);
        assert_eq!(after.resident_bytes, governor.used.load(Ordering::Acquire));
        assert!(!cache.take_maintenance_provider_refusal());
        assert!(CachedBytes::ptr_eq(&guard, &cache.peek(0).unwrap()));
        let checks = governor.checks.load(Ordering::Acquire);
        drop(cache);
        drop(guard);
        assert_eq!(governor.checks.load(Ordering::Acquire), checks);
        assert_eq!(governor.used.load(Ordering::Acquire), 0);
        assert_eq!(governor.slots.load(Ordering::Acquire), 0);
    }
}
