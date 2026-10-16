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
