use super::*;
use crate::root::CompactionPhase;

const ONE: MaintenanceBudget = MaintenanceBudget {
    units: 1,
    mutations: 1,
};

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
    replace_arena(state, None);
    let capacity = state.writer.position().unwrap().offset + 1;
    let writer = std::mem::replace(&mut state.writer, SegmentWriter::new(GROUP));
    state.writer = writer.with_capacity(capacity);
    state
        .commit(&[Operation::put("accounts", b"k", b"middle")])
        .unwrap();
    replace_arena(state, None);
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

/// One complete cycle with three-unit steps; returns the reclaimed files.
fn reclaim_all(state: &mut DiskState, churn: bool) -> u64 {
    let start = record(state);
    state.request_compaction().unwrap();
    let mut reclaimed = 0;
    for _ in 0..20_000 {
        if churn {
            drop(state.snapshot().unwrap());
        }
        let progress = step(state, STEP);
        reclaimed += progress.reclaimed_files;
        let now = record(state);
        if now.phase() == CompactionPhase::Idle
            && (start.phase() != CompactionPhase::Idle || now.cycle() > start.cycle())
        {
            return reclaimed;
        }
    }
    panic!("bounded reclamation did not finish");
}

/// Present segment and directory files, as the census would count them.
fn present(group: &InMemoryGroup) -> Vec<GroupFile> {
    let mut files = Vec::new();
    group
        .visit_entries(&mut |name| {
            if let Some(file) = name.to_str().and_then(GroupFile::parse_name) {
                files.push(file);
            }
            Ok(())
        })
        .unwrap();
    files.sort_unstable();
    files
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
        replace_arena(&mut state, None);
        state
            .commit(&[Operation::put("accounts", b"k", [version])])
            .unwrap();
    }
    let current = state.snapshot().unwrap();
    let count = reclaim_all(&mut state, true);
    assert!(count > crate::root::MAX_GARBAGE as u64);
    assert_eq!(value(&mut state, &current, b"k").unwrap(), [139]);
    assert!(admission.peak.load(Ordering::Acquire) <= 3 << 20);
    assert!(state.owner.lock().unwrap().garbage().is_empty());
    assert_eq!(
        state
            .maintenance_status()
            .unwrap()
            .reclaim_invalidations_total,
        0
    );
    drop(current);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn reclaiming_completes_with_one_unit_steps_alternating_foreground_commits() {
    // More than MAX_GARBAGE old arenas and segments: several cohorts. Every
    // maintenance unit is followed by a successful foreground commit, which
    // installs a new root generation; nothing restarts and nothing is
    // invalidated.
    let group = InMemoryGroup::new();
    let admission = Admission::new(8 << 20);
    let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
    state.writer = SegmentWriter::new(GROUP).with_capacity(1024);
    state
        .commit(&[Operation::create_table("accounts")])
        .unwrap();
    for version in 0..150u16 {
        replace_arena(&mut state, None);
        state
            .commit(&[Operation::put(
                "accounts",
                (version % 7).to_be_bytes(),
                version.to_be_bytes(),
            )])
            .unwrap();
    }
    // Later foreground commits share one segment.
    let writer = std::mem::replace(&mut state.writer, SegmentWriter::new(GROUP));
    state.writer = writer.with_capacity(crate::segment::SEGMENT_BYTES);
    let before = present(&group).len();
    assert!(before > crate::root::MAX_GARBAGE + 16, "{before}");
    drive_through(&mut state, CompactionPhase::Evacuating, STEP);
    assert_eq!(phase(&state), CompactionPhase::Reclaiming);
    let cutoff = record(&state);
    let mut commits = 0u16;
    let mut reclaimed = 0;
    let mut last_cursor = None;
    while phase(&state) == CompactionPhase::Reclaiming {
        let progress = step(&mut state, ONE);
        assert!(progress.units <= 1);
        reclaimed += progress.reclaimed_files;
        // The cycle cursor never moves back.
        let cursor = state.reclaim.cycle_cursor_for_test();
        if let (Some((last_segment, last_arena)), Some((segment, arena))) = (last_cursor, cursor) {
            assert!(segment >= last_segment && arena >= last_arena);
        }
        last_cursor = cursor.or(last_cursor);
        state
            .commit(&[Operation::put(
                "accounts",
                (commits % 7).to_be_bytes(),
                b"foreground",
            )])
            .unwrap();
        commits += 1;
        assert!(commits < 20_000, "reclamation did not complete");
    }
    assert_eq!(phase(&state), CompactionPhase::Packing);
    let status = state.maintenance_status().unwrap();
    assert_eq!(status.reclaim_invalidations_total, 0);
    assert!(reclaimed > crate::root::MAX_GARBAGE as u64, "{reclaimed}");
    // No pin exists: every file at or below the frozen cutoffs is gone.
    for file in present(&group) {
        let cutoff = match file.kind {
            crate::group::FileKind::Segment => cutoff.cutoff_segment(),
            _ => cutoff.cutoff_arena(),
        };
        assert!(file.id > cutoff, "{file:?} survived");
    }
    let pin = state.snapshot().unwrap();
    for key in 0..7u16 {
        assert_eq!(
            value(&mut state, &pin, &key.to_be_bytes()).unwrap(),
            b"foreground"
        );
    }
    drop(pin);
    drive_cycle(&mut state, STEP);
}

#[test]
fn denial_before_scan_is_retryable_and_releases_scratch() {
    let (_, admission, mut state) = begin();
    replace_twice(&mut state);
    drive_through(&mut state, CompactionPhase::Evacuating, STEP);
    assert_eq!(phase(&state), CompactionPhase::Reclaiming);
    let before = admission.used.load(Ordering::Acquire);
    // The census allocates nothing; the first admission is the cohort's.
    admission.deny_nth(1);
    let mut deferred = None;
    for _ in 0..1000 {
        let progress = state.maintenance_step(ONE).unwrap();
        if progress.deferred.is_some() {
            deferred = progress.deferred;
            break;
        }
    }
    assert_eq!(deferred, Some(MaintenanceDeferral::Capacity));
    assert_eq!(admission.refused_calls.load(Ordering::Acquire), 1);
    assert!(!state.is_fenced());
    assert!(state.reclaim.cohort_stage_for_test().is_none());
    assert_eq!(admission.used.load(Ordering::Acquire), before);
    assert!(reclaim_all(&mut state, false) >= 3);
}

/// Reach the point where a sealed cohort has recorded its garbage.
fn recorded(
    group: InMemoryGroup,
    admission: Arc<Admission>,
    mut state: DiskState,
) -> (InMemoryGroup, Arc<Admission>, DiskState) {
    replace_twice(&mut state);
    state.request_compaction().unwrap();
    for _ in 0..1000 {
        step(&mut state, ONE);
        if !state.owner.lock().unwrap().garbage().is_empty() {
            return (group, admission, state);
        }
    }
    panic!("garbage publication was not reached");
}

#[test]
fn failure_at_each_retire_unlink_syncnames_forget_effect_with_interleaved_commits_reopens() {
    for interleave in [false, true] {
        for op in [
            GroupOp::Unlink,
            GroupOp::SyncNames,
            GroupOp::RootWrite,
            GroupOp::RootSync,
        ] {
            for nth in 1..=3 {
                for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
                    let case = format!("{interleave} {op:?}/{nth}/{timing:?}");
                    let (group, admission, state) = begin();
                    let (group, admission, mut state) = recorded(group, admission, state);
                    let garbage = state.owner.lock().unwrap().garbage().to_vec();
                    group.fail(op, nth, timing);
                    for round in 0..8u8 {
                        if interleave
                            && let Err(error) =
                                state.commit(&[Operation::put("accounts", b"interleaved", [round])])
                        {
                            assert!(state.is_fenced(), "{case}: {error:?}");
                            break;
                        }
                        match state.maintenance_step(ONE) {
                            Ok(progress) => assert_eq!(progress.deferred, None, "{case}"),
                            Err(error) => {
                                assert!(state.is_fenced(), "{case}: {error:?}");
                                break;
                            }
                        }
                    }
                    drop(state);
                    let restarted = group.crash();
                    let mut state =
                        DiskState::open(Arc::new(restarted.clone()), admission, GROUP, LARGE_CACHE)
                            .unwrap_or_else(|error| panic!("{case}: {error:?}"));
                    let pin = state.snapshot().unwrap();
                    assert_eq!(value(&mut state, &pin, b"k").unwrap(), b"current", "{case}");
                    // Reopen re-proved and drained every recorded file.
                    assert!(state.owner.lock().unwrap().garbage().is_empty(), "{case}");
                    for file in &garbage {
                        assert!(!restarted.exists(*file).unwrap(), "{case}: {file:?}");
                    }
                    drop(pin);
                    if phase(&state) != CompactionPhase::Idle {
                        drive_cycle(&mut state, STEP);
                    }
                    assert_eq!(phase(&state), CompactionPhase::Idle, "{case}");
                }
            }
        }
    }
}

#[test]
fn allocation_publications_and_commits_between_retire_unlink_and_forget() {
    // Arena and segment rolls (allocation publications) and foreground
    // commits land between the retirement publication and each unlink and
    // forget; the certified chain keeps the proof valid throughout.
    let (group, admission, state) = begin();
    let (group, _admission, mut state) = recorded(group, admission, state);
    let garbage = state.owner.lock().unwrap().garbage().to_vec();
    assert!(!garbage.is_empty());
    let mut rounds = 0u8;
    while !state.owner.lock().unwrap().garbage().is_empty() {
        replace_arena(&mut state, None);
        let capacity = state.writer.position().unwrap().offset + 1;
        let writer = std::mem::replace(&mut state.writer, SegmentWriter::new(GROUP));
        state.writer = writer.with_capacity(capacity);
        state
            .commit(&[Operation::put("accounts", b"between", [rounds])])
            .unwrap();
        step(&mut state, ONE);
        rounds += 1;
        assert!(rounds < 100);
    }
    assert!(rounds as usize >= garbage.len());
    for file in &garbage {
        assert!(!group.exists(*file).unwrap(), "{file:?}");
    }
    assert_eq!(
        state
            .maintenance_status()
            .unwrap()
            .reclaim_invalidations_total,
        0
    );
    let pin = state.snapshot().unwrap();
    assert_eq!(value(&mut state, &pin, b"k").unwrap(), b"current");
    assert_eq!(value(&mut state, &pin, b"between").unwrap(), [rounds - 1]);
}

#[test]
fn uncertified_install_or_unstamped_pin_invalidates_cohort_and_unlinks_nothing() {
    for fault in ["install", "pin"] {
        let (group, admission, mut state) = begin();
        // A root no live pin holds when the cohort starts.
        let historical = state.selected;
        replace_twice(&mut state);
        drive_through(&mut state, CompactionPhase::Evacuating, STEP);
        // Step until a cohort is walking or walked, before it records.
        state.request_compaction().unwrap();
        while state
            .reclaim
            .cohort_stage_for_test()
            .is_none_or(|stage| stage == crate::reclaim::CohortStage::Collecting)
        {
            step(&mut state, ONE);
        }
        let files = present(&group);
        let mut stray = None;
        match fault {
            // The chain sees an install whose predecessor it never
            // certified: as if a root had been selected outside the funnel.
            "install" => state.reclaim.break_chain_for_test(),
            // A pin at a historical root the cohort never walked or stamped,
            // as an acquisition outside the funnel would create.
            _ => {
                assert_ne!(historical, state.selected);
                stray = Some(state.pins.acquire(historical).unwrap());
            }
        }
        let mut invalidated = false;
        for _ in 0..1000 {
            step(&mut state, ONE);
            if state
                .maintenance_status()
                .unwrap()
                .reclaim_invalidations_total
                > 0
            {
                invalidated = true;
                break;
            }
            assert!(state.owner.lock().unwrap().garbage().is_empty(), "{fault}");
        }
        assert!(invalidated, "{fault}");
        // Nothing was retired or unlinked by the invalidated cohort.
        assert!(state.owner.lock().unwrap().garbage().is_empty(), "{fault}");
        for file in files {
            assert!(group.exists(file).unwrap(), "{fault}: {file:?}");
        }
        drop(stray);
        drop(state);
        // A reopened owner reclaims normally.
        let restarted = group.crash();
        let mut reopened =
            DiskState::open(Arc::new(restarted.clone()), admission, GROUP, LARGE_CACHE).unwrap();
        drive_cycle(&mut reopened, STEP);
        assert!(
            !restarted.exists(GroupFile::directory(2)).unwrap(),
            "{fault}"
        );
        assert!(!restarted.exists(GroupFile::segment(2)).unwrap(), "{fault}");
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
    replace_arena(&mut state, None);
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
    assert!(
        matches!(
            error.original_error().unwrap().rejected_cause(),
            Some(crate::CoreErrorCause::Corrupt(_))
        ),
        "{error:?}"
    );
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
    assert!(
        matches!(&(state.snapshot()), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
    assert!(admission.check_owner().is_ok());
    assert!(state.is_fenced());
    assert!(
        matches!(&(state.commit(&[Operation::create_table("accounts")])), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
}

mod pins {
    include!("disk_reclaim_pin_tests.rs");
}
