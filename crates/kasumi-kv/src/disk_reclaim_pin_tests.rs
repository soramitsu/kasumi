// Included beneath disk_state::tests::disk_reclaim: pins taken during a cohort,
// and captured pins retired while the cohort still walks them.

use super::*;

#[test]
fn pins_at_intermediate_roots_stay_readable_with_all_256_slots_and_are_reclaimed_next_cycle() {
    let (group, admission, mut state) = begin();
    replace_twice(&mut state);
    drive_through(&mut state, CompactionPhase::Evacuating, STEP);
    assert_eq!(phase(&state), CompactionPhase::Reclaiming);
    // Between reclamation items, each intermediate root gets its own arena
    // and a pin until every registry slot is taken.
    let mut pins = Vec::new();
    let mut arenas = Vec::new();
    let mut version = 0u16;
    let mut full = false;
    while phase(&state) == CompactionPhase::Reclaiming {
        step(&mut state, ONE);
        for _ in 0..16 {
            if full {
                break;
            }
            replace_arena(&mut state, None);
            state
                .commit(&[Operation::put("accounts", b"k", version.to_be_bytes())])
                .unwrap();
            match state.snapshot() {
                Ok(pin) => {
                    arenas.push(pin.root().page.unwrap().arena_id);
                    pins.push((pin, version));
                }
                Err(error) => {
                    assert!(error.is_capacity_denied(), "{error:?}");
                    full = true;
                }
            }
            version += 1;
        }
    }
    assert!(full, "fixture must fill every pin slot during reclamation");
    assert_eq!(pins.len(), MAX_PINNED_ROOTS);
    let status = state.maintenance_status().unwrap();
    assert_eq!(status.reclaim_invalidations_total, 0);
    assert!(status.reclaimed_files_total >= 2);
    for (pin, version) in &pins {
        assert_eq!(
            value(&mut state, pin, b"k").unwrap(),
            version.to_be_bytes(),
            "pinned intermediate root lost a file"
        );
    }
    drive_cycle(&mut state, STEP);
    for &arena in &arenas {
        assert!(group.exists(GroupFile::directory(arena)).unwrap());
    }
    let current_arena = state.selected.page.unwrap().arena_id;
    drop(pins);
    // The next cycle's cutoffs cover those arenas; nothing pins them now.
    seal_files(&mut state);
    drive_cycle(&mut state, STEP);
    let mut reclaimed = 0;
    for &arena in &arenas {
        if arena != current_arena && !group.exists(GroupFile::directory(arena)).unwrap() {
            reclaimed += 1;
        }
    }
    assert!(reclaimed >= arenas.len() - 1, "{reclaimed} of {}", arenas.len());
    let pin = state.snapshot().unwrap();
    assert_eq!(
        value(&mut state, &pin, b"k").unwrap(),
        (version - 1).to_be_bytes()
    );
    drop(pin);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn retiring_all_captured_pins_mid_walk_keeps_sources_readable_through_drain() {
    let (group, _admission, mut state) = begin();
    let first = state.snapshot().unwrap();
    replace_twice(&mut state);
    let second = state.snapshot().unwrap();
    let copy = first.clone();
    drive_through(&mut state, CompactionPhase::Evacuating, STEP);
    state.request_compaction().unwrap();
    // Stop once the cohort captured both pins and is walking them.
    while state.reclaim.cohort_stage_for_test() != Some(crate::reclaim::CohortStage::Walking) {
        step(&mut state, ONE);
    }
    step(&mut state, ONE);
    drop((first, second, copy));
    // The walk keeps reading the captured roots' pages and the cohort keeps
    // every file a captured root referenced; nothing fails or is lost.
    while phase(&state) == CompactionPhase::Reclaiming {
        step(&mut state, ONE);
    }
    assert!(group.exists(GroupFile::directory(1)).unwrap());
    assert!(group.exists(GroupFile::segment(1)).unwrap());
    assert_eq!(state.maintenance_status().unwrap().reclaim_invalidations_total, 0);
    let pin = state.snapshot().unwrap();
    assert_eq!(value(&mut state, &pin, b"k").unwrap(), b"current");
    drop(pin);
    drive_cycle(&mut state, STEP);
    // The next cycle frees them.
    drive_cycle(&mut state, STEP);
    assert!(!group.exists(GroupFile::directory(1)).unwrap());
    assert!(!group.exists(GroupFile::segment(1)).unwrap());
}

/// The first version's files, which only a pin taken before it was replaced
/// still reaches once a cycle has evacuated the current root.
const KEPT: [GroupFile; 2] = [GroupFile::directory(1), GroupFile::segment(1)];

/// One completed cycle that kept `KEPT` only for the returned pin.
fn kept_for_old_pin() -> (InMemoryGroup, Arc<Admission>, DiskState, SnapshotPin) {
    let (group, admission, mut state) = begin();
    let old = state.snapshot().unwrap();
    replace_twice(&mut state);
    assert!(reclaim_all(&mut state, false) >= 1);
    for file in KEPT {
        assert!(group.exists(file).unwrap(), "{file:?}");
    }
    assert_eq!(
        state.maintenance_status().unwrap().snapshot_retained_files,
        KEPT.len() as u64
    );
    (group, admission, state, old)
}

/// Step until nothing is due and no round can run; returns the files
/// reclaimed on the way.
fn settle(state: &mut DiskState) -> u64 {
    let mut reclaimed = 0;
    for _ in 0..20_000 {
        let progress = step(state, STEP);
        reclaimed += progress.reclaimed_files;
        if progress.idle {
            return reclaimed;
        }
    }
    panic!("maintenance did not settle");
}

#[test]
fn idle_round_waits_only_for_pins_older_than_the_evacuation() {
    let (group, _admission, mut state, old) = kept_for_old_pin();
    let cycle = record(&state).cycle();
    let (_, evacuated) = state.reclaim.owed_round_for_test().expect("owed round");
    assert!(old.root().generation < evacuated);
    // A pin of the current root reaches nothing below the cycle's limits
    // and does not hold the round back; the older pin does.
    let current = state.snapshot().unwrap();
    assert!(current.root().generation >= evacuated);
    assert_eq!(settle(&mut state), 0);
    assert!(!state.round_active());
    for file in KEPT {
        assert!(group.exists(file).unwrap(), "{file:?}");
    }
    drop(old);
    assert_eq!(settle(&mut state), KEPT.len() as u64);
    for file in KEPT {
        assert!(!group.exists(file).unwrap(), "{file:?}");
    }
    assert_eq!(
        (phase(&state), record(&state).cycle()),
        (CompactionPhase::Idle, cycle)
    );
    assert!(state.reclaim.owed_round_for_test().is_none());
    let status = state.maintenance_status().unwrap();
    assert_eq!(
        (
            status.snapshot_retained_files,
            status.reclaim_invalidations_total
        ),
        (0, 0)
    );
    assert_eq!(value(&mut state, &current, b"k").unwrap(), b"current");
}

#[test]
fn idle_round_under_commits_and_new_pins_unlinks_only_unreachable_files() {
    let (group, _admission, mut state, old) = kept_for_old_pin();
    let cycle = record(&state).cycle();
    drop(old);
    // One unit per step; a commit, sometimes in a fresh arena, and a pin of
    // its root between steps, so each cohort item meets a new installation.
    let mut pins = Vec::new();
    let mut version = 0u16;
    let mut reclaimed = 0;
    while state.round_active()
        || state.reclaim.owed_round_for_test().is_some()
        || KEPT.iter().any(|file| group.exists(*file).unwrap())
    {
        reclaimed += step(&mut state, ONE).reclaimed_files;
        if version.is_multiple_of(3) {
            replace_arena(&mut state, None);
        }
        state
            .commit(&[Operation::put("accounts", b"k", version.to_be_bytes())])
            .unwrap();
        pins.push((state.snapshot().unwrap(), version));
        version += 1;
        assert!(version < 200, "the round did not finish");
    }
    assert_eq!(reclaimed, KEPT.len() as u64);
    assert_eq!(record(&state).cycle(), cycle);
    assert_eq!(
        state
            .maintenance_status()
            .unwrap()
            .reclaim_invalidations_total,
        0
    );
    for (pin, version) in &pins {
        assert_eq!(
            value(&mut state, pin, b"k").unwrap(),
            version.to_be_bytes(),
            "pin of version {version}"
        );
    }
}

#[test]
fn rounds_and_cycles_never_overlap() {
    // An owed round that its pin still holds back is dropped when a cycle
    // begins; that cycle's reclamation covers the same files.
    let (group, _admission, mut state, old) = kept_for_old_pin();
    let cycle = record(&state).cycle();
    state.request_compaction().unwrap();
    step(&mut state, ONE);
    assert_eq!(
        (phase(&state), record(&state).cycle()),
        (CompactionPhase::Evacuating, cycle + 1)
    );
    assert!(state.reclaim.owed_round_for_test().is_none());
    drop(old);
    drive_cycle(&mut state, STEP);
    for file in KEPT {
        assert!(!group.exists(file).unwrap(), "{file:?}");
    }

    // An active round finishes before a requested cycle may begin.
    let (group, _admission, mut state, old) = kept_for_old_pin();
    let cycle = record(&state).cycle();
    drop(old);
    while state.reclaim.cohort_stage_for_test().is_none() {
        step(&mut state, ONE);
    }
    state.request_compaction().unwrap();
    while state.round_active() {
        step(&mut state, ONE);
        assert_eq!(
            (phase(&state), record(&state).cycle()),
            (CompactionPhase::Idle, cycle)
        );
    }
    for file in KEPT {
        assert!(!group.exists(file).unwrap(), "{file:?}");
    }
    assert!(step(&mut state, ONE).phase_changed);
    assert_eq!(phase(&state), CompactionPhase::Evacuating);
}

#[test]
fn failure_at_each_round_effect_reopens_and_reclaims() {
    for op in [
        GroupOp::RootWrite,
        GroupOp::RootSync,
        GroupOp::Unlink,
        GroupOp::SyncNames,
    ] {
        for nth in 1..=3 {
            for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
                let case = format!("{op:?}/{nth}/{timing:?}");
                let (group, admission, mut state, old) = kept_for_old_pin();
                drop(old);
                group.fail(op, nth, timing);
                for _ in 0..64 {
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
                settle(&mut state);
                assert!(state.owner.lock().unwrap().garbage().is_empty(), "{case}");
                for file in KEPT {
                    assert!(!restarted.exists(file).unwrap(), "{case}: {file:?}");
                }
                let pin = state.snapshot().unwrap();
                assert_eq!(value(&mut state, &pin, b"k").unwrap(), b"current", "{case}");
            }
        }
    }
}

fn reopened(group: &mut InMemoryGroup, admission: &Arc<Admission>, state: DiskState) -> DiskState {
    drop(state);
    *group = group.crash();
    DiskState::open(
        Arc::new(group.clone()),
        admission.clone(),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap()
}

#[test]
fn reopen_arms_a_round_only_after_a_completed_reclamation() {
    let (mut group, admission, state) = begin();
    // Nothing compacted yet, so nothing was kept for pins.
    let mut state = reopened(&mut group, &admission, state);
    assert!(!state.round_active());
    replace_twice(&mut state);
    state.request_compaction().unwrap();
    for (target, armed) in [
        (CompactionPhase::Evacuating, false),
        (CompactionPhase::Reclaiming, false),
        (CompactionPhase::Packing, true),
        (CompactionPhase::Idle, true),
    ] {
        while phase(&state) != target {
            step(&mut state, ONE);
        }
        state = reopened(&mut group, &admission, state);
        assert_eq!(
            (phase(&state), state.round_active()),
            (target, armed),
            "{target:?}"
        );
    }
    assert_eq!(record(&state).cycle(), 1);
    settle(&mut state);
    assert!(!state.round_active());
    let pin = state.snapshot().unwrap();
    assert_eq!(value(&mut state, &pin, b"k").unwrap(), b"current");
}
