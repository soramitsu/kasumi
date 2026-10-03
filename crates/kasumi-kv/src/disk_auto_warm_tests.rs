use super::*;
use crate::core::CacheWarmupState;

fn fixture(bytes: usize, limit: u64) -> (DiskState, Arc<Reads>, Arc<Admission>) {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(16 << 20);
    let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", vec![1; bytes]),
            Operation::put("accounts", b"b", vec![2; bytes]),
        ])
        .unwrap();
    state
        .configure_cache(CacheConfig { byte_limit: limit })
        .unwrap();
    (state, reads, admission)
}

fn finish(state: &mut DiskState) -> CacheWarmup {
    for _ in 0..1024 {
        let progress = state.warm_if_needed(7).unwrap();
        if progress.complete
            || state.warm_status().unwrap().state == CacheWarmupState::CapacityLimited
        {
            return progress;
        }
    }
    panic!("automatic warm-up did not reach a bounded terminal attempt");
}

fn assert_parked(state: &mut DiskState, reads: &Reads, admission: &Admission) {
    let io = reads.count();
    let calls = admission.calls.load(Ordering::Acquire);
    let before = state.warm_status().unwrap();
    for _ in 0..12 {
        let progress = state.warm_if_needed(64).unwrap();
        assert_eq!(progress.work, 0);
        assert_eq!(progress.complete, before.complete);
        assert_eq!(state.warm_status().unwrap(), before);
    }
    assert_eq!(reads.count(), io);
    assert_eq!(admission.calls.load(Ordering::Acquire), calls);
}

#[test]
fn cold_reopen_completes_despite_current_reader_churn_and_parks_without_io_or_admission() {
    let (state, reads, _) = fixture(8192, 128 << 10);
    drop(state);
    let reads = Reads::new(reads.group.crash());
    let admission = Admission::new(16 << 20);
    let mut state = DiskState::open(
        reads.clone(),
        admission.clone(),
        GROUP,
        CacheConfig {
            byte_limit: 128 << 10,
        },
    )
    .unwrap();
    assert_eq!(state.cache_stats().unwrap().entries, 0);
    let mut total = 0;
    loop {
        let first = state.snapshot().unwrap();
        let second = state.snapshot().unwrap();
        drop(first);
        let progress = state.warm_if_needed(1).unwrap();
        total += progress.work;
        drop(second);
        assert!(total < 128, "current-reader churn restarted the pass");
        if progress.complete {
            assert!(progress.fully_resident);
            break;
        }
    }
    assert_eq!(state.warm_status().unwrap().cumulative_work, total as u64);
    assert_parked(&mut state, &reads, &admission);
    let current = state.snapshot().unwrap();
    let before = reads.count();
    assert_eq!(value(&mut state, &current, b"a").unwrap(), vec![1; 8192]);
    assert_eq!(value(&mut state, &current, b"b").unwrap(), vec![2; 8192]);
    assert_eq!(reads.count(), before);
}

#[test]
fn unchanged_oversized_attempt_and_pure_growth_stay_parked_until_budget_grows() {
    let (mut state, reads, admission) = fixture(96 << 10, 160 << 10);
    let progress = finish(&mut state);
    assert!(progress.complete && !progress.fully_resident);
    let status = state.warm_status().unwrap();
    assert_eq!(status.state, CacheWarmupState::CapacityLimited);
    assert!(!status.provider_limited);
    assert_parked(&mut state, &reads, &admission);
    state
        .commit(&[Operation::put("accounts", b"c", vec![3; 4096])])
        .unwrap();
    assert_eq!(
        state.warm_status().unwrap().attempt_generation,
        status.attempt_generation
    );
    assert_parked(&mut state, &reads, &admission);
    state
        .configure_cache(CacheConfig {
            byte_limit: 512 << 10,
        })
        .unwrap();
    assert_eq!(
        state.warm_status().unwrap().state,
        CacheWarmupState::Pending
    );
    assert!(finish(&mut state).fully_resident);
    assert_parked(&mut state, &reads, &admission);
}

#[test]
fn shorter_replacement_and_real_delete_request_a_fitting_pass() {
    for delete in [false, true] {
        let (mut state, _, _) = fixture(96 << 10, 160 << 10);
        assert!(!finish(&mut state).fully_resident);
        let operation = if delete {
            Operation::delete("accounts", b"a")
        } else {
            Operation::put("accounts", b"a", vec![9; 4096])
        };
        state.commit(&[operation]).unwrap();
        assert_eq!(
            state.warm_status().unwrap().state,
            CacheWarmupState::Pending
        );
        assert!(finish(&mut state).fully_resident);
    }
}

#[test]
fn historical_root_retires_only_after_its_last_independent_pin_and_clone() {
    let (mut state, reads, admission) = fixture(64 << 10, 192 << 10);
    let old = state.snapshot().unwrap();
    let independent = state.snapshot().unwrap();
    let clone = old.clone();
    state
        .commit(&[Operation::put("accounts", b"a", vec![9; 64 << 10])])
        .unwrap();
    assert!(!finish(&mut state).fully_resident);
    drop(old);
    drop(independent);
    assert_parked(&mut state, &reads, &admission);
    drop(clone);
    assert_eq!(
        state.warm_status().unwrap().state,
        CacheWarmupState::Pending
    );
    assert!(finish(&mut state).fully_resident);
}

#[test]
fn pin_acquired_after_parking_is_tracked_when_publication_makes_it_historical() {
    let (mut state, reads, admission) = fixture(96 << 10, 160 << 10);
    assert!(!finish(&mut state).fully_resident);
    let pin = state.snapshot().unwrap();
    state
        .commit(&[Operation::put("accounts", b"c", vec![3; 4096])])
        .unwrap();
    assert_parked(&mut state, &reads, &admission);
    drop(pin);
    assert_eq!(
        state.warm_status().unwrap().state,
        CacheWarmupState::Pending
    );
    assert!(finish(&mut state).work > 0);
    assert_parked(&mut state, &reads, &admission);
}

#[test]
fn released_output_guard_capacity_requests_retry_without_a_snapshot_retirement() {
    let (mut state, reads, admission) = fixture(64 << 10, 192 << 10);
    let old = state.snapshot().unwrap();
    let guard = state
        .get(&old, "accounts", b"a", usize::MAX)
        .unwrap()
        .unwrap();
    drop(old);
    state
        .commit(&[Operation::put("accounts", b"a", vec![9; 64 << 10])])
        .unwrap();
    assert!(!finish(&mut state).fully_resident);
    assert_eq!(
        state.cache_stats().unwrap().pinned_bytes,
        guard.charged_bytes()
    );
    assert_parked(&mut state, &reads, &admission);
    drop(guard);
    assert_eq!(
        state.warm_status().unwrap().state,
        CacheWarmupState::Pending
    );
    assert!(finish(&mut state).fully_resident);
}

#[test]
fn denied_cache_disable_invalidates_residency_after_releasing_lookup_ownership() {
    let (mut state, _, _) = fixture(8192, 128 << 10);
    assert!(finish(&mut state).fully_resident);
    let pin = state.snapshot().unwrap();
    let payload = state
        .get(&pin, "accounts", b"a", usize::MAX)
        .unwrap()
        .unwrap();
    assert!(matches!(
        state.configure_cache(CacheConfig { byte_limit: 0 }),
        Err(CoreError::CapacityDenied)
    ));
    assert_eq!(
        state.warm_status().unwrap().state,
        CacheWarmupState::Pending
    );
    assert!(!state.is_fenced());
    drop(payload);
    drop(pin);
    assert!(finish(&mut state).fully_resident);
}

#[test]
fn required_workspace_denial_retries_bounded_work_until_capacity_returns() {
    let (mut state, reads, admission) = fixture(8192, 128 << 10);
    admission.limit.store(0, Ordering::Release);
    let denied = state.warm_if_needed(7).unwrap();
    assert!(!denied.complete && !denied.fully_resident);
    assert!(!state.is_fenced());
    let status = state.warm_status().unwrap();
    assert_eq!(status.state, CacheWarmupState::CapacityLimited);
    assert!(status.provider_limited);
    let io = reads.count();
    let calls = admission.calls.load(Ordering::Acquire);
    for _ in 0..3 {
        let progress = state.warm_if_needed(7).unwrap();
        assert_eq!(progress.work, 0);
        assert!(!progress.complete);
    }
    assert_eq!(reads.count(), io);
    assert_eq!(admission.calls.load(Ordering::Acquire), calls + 3);
    admission.limit.store(16 << 20, Ordering::Release);
    assert!(finish(&mut state).fully_resident);
}

#[test]
fn disabled_cache_is_idle_and_manual_warming_keeps_its_explicit_restart_semantics() {
    let (mut state, reads, admission) = fixture(8192, 0);
    let before = reads.count();
    let disabled = state.warm_if_needed(64).unwrap();
    assert_eq!(disabled.work, 0);
    assert!(disabled.complete && !disabled.fully_resident);
    assert_eq!(
        state.warm_status().unwrap().state,
        CacheWarmupState::Disabled
    );
    assert_eq!(reads.count(), before);
    assert_parked(&mut state, &reads, &admission);
    state
        .configure_cache(CacheConfig {
            byte_limit: 128 << 10,
        })
        .unwrap();
    assert!(finish(&mut state).fully_resident);
    assert!(state.warm(1).unwrap().work > 0);
    assert!(warm_all(&mut state).fully_resident);
    assert_parked(&mut state, &reads, &admission);
    admission.owner_failed();
    assert!(matches!(
        state.warm_if_needed(1),
        Err(CoreError::OwnerFailed)
    ));
    assert!(matches!(state.warm_status(), Err(CoreError::OwnerFailed)));
    assert!(matches!(
        state.request_warm_retry(),
        Err(CoreError::OwnerFailed)
    ));
}

struct PayloadGate {
    inner: Arc<Admission>,
    deny: AtomicU64,
    deny_cache_growth: AtomicBool,
    denied: AtomicUsize,
    requested: AtomicU64,
}

impl StorageAdmission for PayloadGate {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.inner.check_owner()
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        self.requested.store(bytes, Ordering::Release);
        let deny = self.deny.load(Ordering::Acquire);
        if deny != 0 && (deny == u64::MAX || bytes == deny) {
            self.denied.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
        }
        self.inner.reserve_workspace(bytes)
    }
    fn reserve_growth(&self, before: u64, after: u64) -> Result<(), AdmissionError> {
        self.inner.reserve_growth(before, after)
    }
    fn settle_growth(&self, bytes: u64) -> Result<(), OwnerFailed> {
        self.inner.settle_growth(bytes)
    }
    fn owner_failed(&self) {
        self.inner.owner_failed();
    }

    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> Result<crate::CacheMemoryQuote, crate::AdmissionError> {
        crate::cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, crate::AdmissionError> {
        crate::cache_test::reserve(self, bytes)
    }
}
impl crate::cache_test::Provider for PayloadGate {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
        self.requested.store(bytes, Ordering::Release);
        let deny = self.deny.load(Ordering::Acquire);
        if (!first && self.deny_cache_growth.load(Ordering::Acquire))
            || (deny != 0 && (deny == u64::MAX || bytes == deny))
        {
            self.denied.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
        }
        crate::cache_test::Provider::acquire_cache(self.inner.as_ref(), bytes, first)
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        let _ = (bytes, last);
        crate::cache_test::Provider::release_cache(self.inner.as_ref(), bytes, last);
    }
}

#[test]
fn optional_provider_denial_retries_only_the_refused_item_without_losing_early_release() {
    // The page/table prefix fits the first aggregate credit chunk. This row
    // must grow it, so refusal covers both rounded and exact growth attempts.
    const VALUE_BYTES: usize = 96 << 10;
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(16 << 20);
    let gate = Arc::new(PayloadGate {
        inner: admission.clone(),
        deny: AtomicU64::new(0),
        deny_cache_growth: AtomicBool::new(false),
        denied: AtomicUsize::new(0),
        requested: AtomicU64::new(0),
    });
    let mut state = DiskState::create(reads.clone(), gate.clone(), GROUP, LARGE_CACHE).unwrap();
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", vec![1; VALUE_BYTES]),
        ])
        .unwrap();
    state
        .configure_cache(CacheConfig { byte_limit: 0 })
        .unwrap();
    state.configure_cache(LARGE_CACHE).unwrap();
    gate.deny_cache_growth.store(true, Ordering::Release);
    let progress = finish(&mut state);
    assert!(!progress.complete && !progress.fully_resident);
    assert_eq!(gate.denied.load(Ordering::Acquire), 2);
    assert!(!state.is_fenced());
    let status = state.warm_status().unwrap();
    assert_eq!(status.state, CacheWarmupState::CapacityLimited);
    assert!(status.provider_limited);
    let io = reads.count();
    let denied = gate.denied.load(Ordering::Acquire);
    for _ in 0..3 {
        let progress = state.warm_if_needed(64).unwrap();
        assert_eq!(
            progress.work, 1,
            "refused row restarted the completed prefix"
        );
        assert!(!progress.complete);
    }
    assert_eq!(gate.denied.load(Ordering::Acquire), denied + 6);
    assert_eq!(
        reads.count(),
        io,
        "refused payload was read before admission"
    );
    gate.deny_cache_growth.store(false, Ordering::Release);
    assert!(finish(&mut state).fully_resident);
    assert!(!state.warm_status().unwrap().provider_limited);
    let pin = state.snapshot().unwrap();
    let io = reads.count();
    assert_eq!(value(&mut state, &pin, b"a").unwrap(), vec![1; VALUE_BYTES]);
    assert_eq!(reads.count(), io);
    assert!(!state.is_fenced());
}

#[test]
fn refused_metadata_shrink_retries_at_prune_end_then_restores_a_fitting_union() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(16 << 20);
    let gate = Arc::new(PayloadGate {
        inner: admission.clone(),
        deny: AtomicU64::new(0),
        deny_cache_growth: AtomicBool::new(false),
        denied: AtomicUsize::new(0),
        requested: AtomicU64::new(0),
    });
    let mut state = DiskState::create(reads.clone(), gate.clone(), GROUP, LARGE_CACHE).unwrap();
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", vec![1; 64 << 10]),
            Operation::put("accounts", b"b", vec![2; 64 << 10]),
        ])
        .unwrap();
    assert!(finish(&mut state).fully_resident);
    let fitting = state.cache_stats().unwrap();
    let fitting_limit = fitting.allocated_bytes + fitting.provider_overhead_bytes;
    let row_identity = |state: &DiskState, key: &[u8]| {
        let Some(DirectoryValue::Row { value, .. }) =
            DirectoryReader::new(state.arena.as_ref(), state.owner.admission.clone())
                .get(state.selected, DirectoryKey::row("accounts", key))
                .unwrap()
        else {
            panic!("fixture row missing");
        };
        NativeIdentity::value(GROUP, value, "accounts", key).unwrap()
    };
    let a = row_identity(&state, b"a");
    let b = row_identity(&state, b"b");
    let b_charge = state.cache.lock().unwrap().peek(b).unwrap().charged_bytes();
    state
        .commit(
            &(0..32)
                .map(|key| Operation::put("accounts", [0, key], [key]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let old = state.snapshot().unwrap();
    state
        .commit(
            &(0..32)
                .map(|key| Operation::delete("accounts", [0, key]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
    drop(old);
    assert_eq!(state.selected.height, 1);
    let reference = state.selected.page.unwrap();
    let page = NativeIdentity::Page {
        group_id: GROUP,
        arena_id: reference.arena_id,
        page_index: reference.page_index,
        sha256: reference.sha256,
    };
    // Reproduce the end of a legitimate prune without trimming its grown
    // backing. Remove one current value too, so excess metadata is the only
    // difference between the exact fitting budget and the required refill.
    let mut cache = state.cache.lock().unwrap();
    let mut cursor = crate::cache::CacheCursor::default();
    loop {
        let step = cache.candidate_step(&mut cursor, 1).unwrap();
        if let Some(candidate) = step.candidate
            && candidate.key != a
            && candidate.key != page
        {
            assert!(cache.remove_candidate(&mut cursor, &candidate).unwrap());
        }
        if step.complete {
            break;
        }
    }
    let excess = cache.stats();
    assert_eq!(excess.entries, 2);
    assert!(excess.metadata_bytes > fitting.metadata_bytes);
    let excess_required = excess.allocated_bytes + excess.provider_overhead_bytes;
    assert!(excess_required <= fitting_limit);
    assert!(excess_required + b_charge > fitting_limit);
    // Probe the actual optional publication-trim reservation. Refusal must
    // leave valid backing; the warm-only trim will retry this exact size.
    gate.deny.store(u64::MAX, Ordering::Release);
    cache.trim_metadata().unwrap();
    let trim_charge = gate.requested.load(Ordering::Acquire);
    assert_eq!(cache.stats(), excess);
    gate.deny.store(trim_charge, Ordering::Release);
    drop(cache);
    state
        .configure_cache(CacheConfig {
            byte_limit: fitting_limit,
        })
        .unwrap();
    let progress = finish(&mut state);
    assert!(!progress.complete && !progress.fully_resident);
    assert!(state.warm_status().unwrap().provider_limited);
    assert!(!state.is_fenced());
    let denied = gate.denied.load(Ordering::Acquire);
    let io = reads.count();
    for _ in 0..3 {
        let progress = state.warm_if_needed(64).unwrap();
        assert_eq!(progress.work, 1, "metadata retry rescanned cache slots");
        assert!(!progress.complete);
    }
    assert_eq!(gate.denied.load(Ordering::Acquire), denied + 3);
    assert_eq!(reads.count(), io);
    gate.deny.store(0, Ordering::Release);
    assert!(finish(&mut state).fully_resident);
    assert_eq!(state.cache_stats().unwrap().resident_bytes, fitting_limit);
    assert!(!state.warm_status().unwrap().provider_limited);
    assert_parked(&mut state, &reads, &admission);
    let pin = state.snapshot().unwrap();
    let io = reads.count();
    assert_eq!(value(&mut state, &pin, b"a").unwrap(), vec![1; 64 << 10]);
    assert_eq!(value(&mut state, &pin, b"b").unwrap(), vec![2; 64 << 10]);
    assert_eq!(reads.count(), io);
}

mod pin_release_during_pass {
    include!("disk_warm_pin_retry_tests.rs");
}
