use super::*;

fn roll_arena(state: &mut DiskState) {
    state.arena = Arc::new(
        DirectoryArenaBackend::new(
            state.owner.backend.clone(),
            state.owner.clone(),
            state.owner.admission.clone(),
            GROUP,
        )
        .unwrap(),
    );
    state.pages = CachedDirectoryBackend::with_shared_cache(
        state.arena.clone(),
        state.owner.admission.clone(),
        GROUP,
        state.cache.clone(),
    );
}

fn begin() -> (InMemoryGroup, Arc<Admission>, DiskState) {
    let group = InMemoryGroup::new();
    let admission = Admission::new(8 << 20);
    let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
    state.writer = SegmentWriter::new(GROUP).with_capacity(1024);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"k", b"old"),
        ])
        .unwrap();
    (group, admission, state)
}

fn replace_twice(state: &mut DiskState) {
    roll_arena(state);
    let capacity = state.writer.position().unwrap().offset + 1;
    let writer = std::mem::replace(&mut state.writer, SegmentWriter::new(GROUP));
    state.writer = writer.with_capacity(capacity);
    state
        .commit(&[Operation::put("accounts", b"k", b"middle")])
        .unwrap();
    roll_arena(state);
    let capacity = state.writer.position().unwrap().offset + 1;
    let writer = std::mem::replace(&mut state.writer, SegmentWriter::new(GROUP));
    state.writer = writer.with_capacity(capacity);
    state
        .commit(&[Operation::put("accounts", b"k", b"current")])
        .unwrap();
    assert!(
        state
            .owner
            .lock()
            .unwrap()
            .directory()
            .unwrap()
            .start
            .position
            .segment_id
            > 1
    );
}

fn reclaim_all(state: &mut DiskState, churn: bool) -> usize {
    let mut reclaimed = 0;
    for _ in 0..20_000 {
        if churn {
            drop(state.snapshot().unwrap());
        }
        let progress = state.reclaim_step(3).unwrap();
        assert!(progress.work <= 3);
        reclaimed += progress.reclaimed;
        if progress.complete {
            return reclaimed;
        }
    }
    panic!("bounded reclamation did not finish");
}

#[test]
fn reclaim_keeps_snapshot_files_until_last_clone_and_output_charge_until_last_guard() {
    let (group, admission, mut state) = begin();
    let old = state.snapshot().unwrap();
    let clone = old.clone();
    let output = state.get(&old, "accounts", b"k", 99).unwrap().unwrap();
    replace_twice(&mut state);
    let current = state.snapshot().unwrap();
    assert!(reclaim_all(&mut state, false) >= 1);
    assert!(group.exists(GroupFile::directory(1)).unwrap());
    assert!(!group.exists(GroupFile::directory(2)).unwrap());
    assert!(group.exists(GroupFile::segment(1)).unwrap());
    assert_eq!(value(&mut state, &old, b"k").unwrap(), b"old");
    assert_eq!(value(&mut state, &current, b"k").unwrap(), b"current");
    drop(old);
    assert_eq!(reclaim_all(&mut state, false), 0);
    drop(clone);
    assert!(reclaim_all(&mut state, false) >= 2);
    assert!(!group.exists(GroupFile::directory(1)).unwrap());
    assert!(!group.exists(GroupFile::segment(1)).unwrap());
    assert_eq!(output.as_bytes(), b"old");
    assert!(state.cache_stats().unwrap().pinned_bytes >= output.charged_bytes());
    drop(output);
    assert_eq!(state.cache_stats().unwrap().pinned_bytes, 0);
    drop(current);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
    let mut reopened =
        DiskState::open(Arc::new(group.crash()), admission, GROUP, LARGE_CACHE).unwrap();
    let pin = reopened.snapshot().unwrap();
    assert_eq!(value(&mut reopened, &pin, b"k").unwrap(), b"current");
}

#[test]
fn short_lived_current_readers_do_not_starve_reclamation() {
    let (group, _, mut state) = begin();
    replace_twice(&mut state);
    assert!(reclaim_all(&mut state, true) >= 3);
    assert!(!group.exists(GroupFile::segment(1)).unwrap());
    assert!(!group.exists(GroupFile::directory(1)).unwrap());
}

#[test]
fn more_files_than_one_garbage_batch_are_reclaimed_with_bounded_admission() {
    let group = InMemoryGroup::new();
    let admission = Admission::new(3 << 20);
    let mut state = create(
        Arc::new(group.clone()),
        admission.clone(),
        CacheConfig {
            byte_limit: 48 << 10,
        },
    );
    state.writer = SegmentWriter::new(GROUP).with_capacity(1024);
    state
        .commit(&[Operation::create_table("accounts")])
        .unwrap();
    for version in 0..140u8 {
        roll_arena(&mut state);
        state
            .commit(&[Operation::put("accounts", b"k", [version])])
            .unwrap();
    }
    let current = state.snapshot().unwrap();
    let count = reclaim_all(&mut state, true);
    assert!(count > crate::root::MAX_GARBAGE);
    assert_eq!(value(&mut state, &current, b"k").unwrap(), [139]);
    assert!(admission.peak.load(Ordering::Acquire) <= 3 << 20);
    assert!(state.owner.lock().unwrap().garbage().is_empty());
    drop(current);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn changed_commit_cancels_scan_before_any_old_proof_can_publish() {
    let (group, _, mut state) = begin();
    replace_twice(&mut state);
    assert!(!state.reclaim_step(1).unwrap().complete);
    let old_generation = state.owner.lock().unwrap().generation();
    state
        .commit(&[Operation::put("accounts", b"new-key", b"new-value")])
        .unwrap();
    assert!(state.owner.lock().unwrap().generation() > old_generation);
    reclaim_all(&mut state, false);
    let current = state.snapshot().unwrap();
    assert_eq!(
        value(&mut state, &current, b"new-key").unwrap(),
        b"new-value"
    );
    assert_eq!(value(&mut state, &current, b"k").unwrap(), b"current");
    assert!(!group.exists(GroupFile::directory(1)).unwrap());
}

#[test]
fn denial_before_scan_is_retryable_and_releases_scratch() {
    let (_, admission, mut state) = begin();
    replace_twice(&mut state);
    let before = admission.used.load(Ordering::Acquire);
    admission.deny_nth(1);
    assert!(matches!(
        state.reclaim_step(4),
        Err(CoreError::CapacityDenied)
    ));
    assert!(!state.is_fenced());
    assert_eq!(admission.used.load(Ordering::Acquire), before);
    assert!(reclaim_all(&mut state, false) >= 3);
}

fn recorded(
    group: InMemoryGroup,
    admission: Arc<Admission>,
    mut state: DiskState,
) -> (InMemoryGroup, Arc<Admission>, DiskState) {
    replace_twice(&mut state);
    for _ in 0..1000 {
        state.reclaim_step(1).unwrap();
        if !state.owner.lock().unwrap().garbage().is_empty() {
            return (group, admission, state);
        }
    }
    panic!("garbage publication was not reached");
}

#[test]
fn failure_at_each_unlink_and_forget_effect_reopens_without_losing_selected_data() {
    for op in [
        GroupOp::Unlink,
        GroupOp::SyncNames,
        GroupOp::RootWrite,
        GroupOp::RootSync,
    ] {
        for nth in 1..=2 {
            for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
                let (group, admission, state) = begin();
                let (group, admission, mut state) = recorded(group, admission, state);
                let garbage = state.owner.lock().unwrap().garbage().to_vec();
                group.fail(op, nth, timing);
                let outcome = state.reclaim_step(3);
                if outcome.is_err() {
                    assert!(state.is_fenced());
                }
                drop(state);
                let restarted = group.crash();
                let mut state =
                    DiskState::open(Arc::new(restarted.clone()), admission, GROUP, LARGE_CACHE)
                        .unwrap_or_else(|error| panic!("{op:?}/{nth}/{timing:?}: {error}"));
                let pin = state.snapshot().unwrap();
                assert_eq!(value(&mut state, &pin, b"k").unwrap(), b"current");
                assert!(state.owner.lock().unwrap().garbage().is_empty());
                for file in garbage {
                    assert!(!restarted.exists(file).unwrap());
                }
            }
        }
    }
}

#[test]
fn restart_rejects_checksum_valid_garbage_that_contains_reachable_child_pages() {
    let group = InMemoryGroup::new();
    let admission = Admission::new(8 << 20);
    let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
    let mut ops = vec![Operation::create_table("accounts")];
    for key in 1..=4u8 {
        ops.push(Operation::put("accounts", vec![key; MAX_KEY_BYTES], [key]));
    }
    state.commit(&ops).unwrap();
    assert!(state.selected.height > 1);
    roll_arena(&mut state);
    state
        .commit(&[Operation::put(
            "accounts",
            vec![1; MAX_KEY_BYTES],
            b"updated",
        )])
        .unwrap();
    assert_eq!(state.selected.page.unwrap().arena_id, 2);
    let forged = state
        .owner
        .lock()
        .unwrap()
        .with_damaged_garbage(vec![GroupFile::directory(1)]);
    let bytes = forged.encode().unwrap();
    group.write_root(RootSlot::A, &bytes).unwrap();
    group.write_root(RootSlot::B, &bytes).unwrap();
    group.sync_root().unwrap();
    drop(state);
    let restarted = group.crash();
    let error = match DiskState::open(Arc::new(restarted.clone()), admission, GROUP, LARGE_CACHE) {
        Ok(_) => panic!("reachable garbage was accepted"),
        Err(error) => error,
    };
    assert!(matches!(error, CoreError::Corrupt(_)), "{error}");
    assert!(restarted.exists(GroupFile::directory(1)).unwrap());
}

struct FailOnce {
    inner: Arc<Admission>,
    fail_reservation: AtomicBool,
}

impl StorageAdmission for FailOnce {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.inner.check_owner()
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        if self.fail_reservation.swap(false, Ordering::AcqRel) {
            return Err(AdmissionError::OwnerFailed);
        }
        self.inner.reserve_workspace(bytes)
    }
    fn reserve_growth(&self, current: u64, requested: u64) -> Result<(), AdmissionError> {
        self.inner.reserve_growth(current, requested)
    }
    fn settle_growth(&self, actual: u64) -> Result<(), OwnerFailed> {
        self.inner.settle_growth(actual)
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
impl crate::cache_test::Provider for FailOnce {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
        let _ = first;
        if self.fail_reservation.swap(false, Ordering::AcqRel) {
            return Err(AdmissionError::OwnerFailed);
        }
        crate::cache_test::Provider::acquire_cache(self.inner.as_ref(), bytes, first)
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        let _ = (bytes, last);
        crate::cache_test::Provider::release_cache(self.inner.as_ref(), bytes, last);
    }
}

#[test]
fn snapshot_reservation_owner_failure_fences_later_writes_even_if_checks_recover() {
    let admission = Arc::new(FailOnce {
        inner: Admission::new(8 << 20),
        fail_reservation: AtomicBool::new(false),
    });
    let mut state = DiskState::create(
        Arc::new(InMemoryGroup::new()),
        admission.clone(),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    admission.fail_reservation.store(true, Ordering::Release);
    assert!(matches!(state.snapshot(), Err(CoreError::OwnerFailed)));
    assert!(admission.check_owner().is_ok());
    assert!(state.is_fenced());
    assert!(matches!(
        state.commit(&[Operation::create_table("accounts")]),
        Err(CoreError::OwnerFailed)
    ));
}
