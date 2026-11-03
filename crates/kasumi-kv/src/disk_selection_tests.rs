// Included beneath disk_state::tests: selective evacuation. A cycle keeps
// nearly full old segments in place and empties the rest; reclamation's
// reachability proof keeps whatever any root still references.

use super::*;
use crate::directory::DirectoryWalker;
use crate::group::FileKind;
use crate::root::CompactionPhase;
use compaction::SelectionForTest;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

/// Large enough that whole commits of rows fill a segment nearly full, and
/// rows that make several directory leaves.
const CAPACITY: u64 = 128 << 10;
const ARENA_PAGES: u64 = 16;
const VALUE: usize = 200;
const ROWS_PER_COMMIT: u32 = 10;
/// The segment whose rows are mostly overwritten.
const SPARSE: u64 = 3;
const PERCENT: u32 = 25;
const ONE: MaintenanceBudget = MaintenanceBudget {
    units: 1,
    mutations: 1,
};

type Selected = Option<(u64, SelectionForTest)>;

/// The cycle, surveyed and kept segments of a surveyed selection.
fn surveyed(selected: Selected) -> (u64, Vec<u64>, Vec<u64>) {
    match selected.expect("a selection") {
        (cycle, SelectionForTest::Surveyed { surveyed, kept }) => (cycle, surveyed, kept),
        other => panic!("not a surveyed selection: {other:?}"),
    }
}

fn geometry(state: &mut DiskState, percent: u32) {
    geometry_with_capacity(state, percent, CAPACITY);
}

fn geometry_with_capacity(state: &mut DiskState, percent: u32, capacity: u64) {
    let writer = std::mem::replace(&mut state.writer, SegmentWriter::new(GROUP));
    state.writer = writer.with_capacity(capacity);
    replace_arena(state, Some(ARENA_PAGES));
    state
        .configure_maintenance(MaintenancePolicy {
            retained_garbage_percent: percent,
            ..MaintenancePolicy::default()
        })
        .unwrap();
}

fn reopen(
    state: DiskState,
    group: &InMemoryGroup,
    admission: &Arc<Admission>,
    percent: u32,
) -> (InMemoryGroup, DiskState) {
    drop(state);
    let group = group.crash();
    let mut state = DiskState::open(
        Arc::new(group.clone()),
        admission.clone(),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    geometry(&mut state, percent);
    (group, state)
}

fn put_rows(state: &mut DiskState, model: &mut BTreeMap<u32, Vec<u8>>, keys: &[u32], fill: u8) {
    for chunk in keys.chunks(ROWS_PER_COMMIT as usize) {
        let operations: Vec<_> = chunk
            .iter()
            .map(|&key| {
                let value = vec![fill ^ key as u8; VALUE];
                model.insert(key, value.clone());
                Operation::put("accounts", key.to_be_bytes(), value)
            })
            .collect();
        state.commit(&operations).unwrap();
    }
}

fn active_segment(state: &DiskState) -> u64 {
    state.writer.position().unwrap().segment_id
}

/// Fresh rows until the writer rolls past the segment it is in.
fn fill_segment(state: &mut DiskState, model: &mut BTreeMap<u32, Vec<u8>>, next: &mut u32) {
    let active = active_segment(state);
    while active_segment(state) == active {
        let keys: Vec<u32> = (*next..*next + ROWS_PER_COMMIT).collect();
        *next += ROWS_PER_COMMIT;
        put_rows(state, model, &keys, 0x11);
    }
}

fn located(state: &DiskState, key: u32) -> ValueLocation {
    let Some(DirectoryValue::Row { value, .. }) =
        DirectoryReader::new(state.arena.as_ref(), state.owner.admission.clone())
            .get(
                state.selected,
                DirectoryKey::row("accounts", &key.to_be_bytes()),
            )
            .unwrap()
    else {
        panic!("missing row {key}");
    };
    value
}

fn locations(state: &DiskState, model: &BTreeMap<u32, Vec<u8>>) -> BTreeMap<u32, ValueLocation> {
    model
        .keys()
        .map(|&key| (key, located(state, key)))
        .collect()
}

fn check_model(state: &mut DiskState, model: &BTreeMap<u32, Vec<u8>>) {
    let pin = state.snapshot().unwrap();
    for (key, expected) in model {
        assert_eq!(
            value(state, &pin, &key.to_be_bytes()).as_ref(),
            Some(expected),
            "{key}"
        );
    }
}

/// The segment ids each leaf of `root` names, in walk order, and every file
/// it reaches. Independent of the survey: it only shares the walker.
fn walk(state: &DiskState, root: DirectoryRoot) -> (Vec<BTreeSet<u64>>, BTreeSet<GroupFile>) {
    let leaves = RefCell::new(Vec::<BTreeSet<u64>>::new());
    let files = RefCell::new(BTreeSet::new());
    let mut walker = DirectoryWalker::new(root, state.owner.admission.clone()).unwrap();
    loop {
        let progress = walker
            .step(
                state.arena.as_ref(),
                256,
                |page| {
                    files
                        .borrow_mut()
                        .insert(GroupFile::directory(page.arena_id));
                    leaves.borrow_mut().push(BTreeSet::new());
                    Ok(())
                },
                |value| {
                    files
                        .borrow_mut()
                        .insert(GroupFile::segment(value.segment_id));
                    leaves
                        .borrow_mut()
                        .last_mut()
                        .expect("values follow their page")
                        .insert(value.segment_id);
                    Ok(())
                },
            )
            .unwrap();
        if progress.complete {
            break;
        }
    }
    let leaves = leaves
        .into_inner()
        .into_iter()
        .filter(|segments| !segments.is_empty())
        .collect();
    (leaves, files.into_inner())
}

fn present(group: &InMemoryGroup) -> BTreeSet<GroupFile> {
    let mut files = BTreeSet::new();
    group
        .visit_entries(&mut |name| {
            if let Some(file) = name.to_str().and_then(GroupFile::parse_name) {
                files.insert(file);
            }
            Ok(())
        })
        .unwrap();
    files
}

/// Every file `root` reaches is present, and every old file is present only
/// if it is reached: reclamation unlinked exactly the unreachable ones.
fn check_reclaimed(state: &DiskState, group: &InMemoryGroup, cutoff: (u64, u64)) {
    let (_, reached) = walk(state, state.selected);
    let present = present(group);
    for file in &reached {
        assert!(present.contains(file), "{file:?} is reached but missing");
    }
    for file in &present {
        let old = match file.kind {
            FileKind::Segment => file.id <= cutoff.0,
            FileKind::Directory => file.id <= cutoff.1,
        };
        assert!(
            !old || reached.contains(file),
            "{file:?} is unreachable but kept"
        );
    }
}

/// Run the active cycle, or request one and run it, to Idle. Returns the
/// last selection it observed and the totals.
fn run_cycle(state: &mut DiskState, budget: MaintenanceBudget) -> (Selected, CycleTotals) {
    let start = record(state);
    state.request_compaction().unwrap();
    let mut selected = None;
    let mut totals = CycleTotals::default();
    for _ in 0..200_000 {
        let progress = step(state, budget);
        totals.add(&progress, &state.compact.stats);
        if let Some(observed) = state.compact.selection_for_test() {
            selected = Some(observed);
        }
        let now = record(state);
        if now.phase() == CompactionPhase::Idle
            && (start.phase() != CompactionPhase::Idle || now.cycle() > start.cycle())
        {
            return (selected, totals);
        }
    }
    panic!("bounded compaction did not finish");
}

struct Fixture {
    group: InMemoryGroup,
    admission: Arc<Admission>,
    state: DiskState,
    model: BTreeMap<u32, Vec<u8>>,
}

/// Five nearly full segments of rows, then most rows of segment `SPARSE`
/// overwritten, then fresh rows until the overwrites are sealed in a nearly
/// full segment of their own and the writer has moved on once more.
fn fixture(percent: u32) -> Fixture {
    let group = InMemoryGroup::new();
    let admission = Admission::new(64 << 20);
    let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
    geometry(&mut state, percent);
    let mut model = BTreeMap::new();
    let mut next = 0;
    state
        .commit(&[Operation::create_table("accounts")])
        .unwrap();
    while active_segment(&state) <= 5 {
        fill_segment(&mut state, &mut model, &mut next);
    }
    let sparse: Vec<u32> = model
        .keys()
        .copied()
        .filter(|&key| located(&state, key).segment_id == SPARSE)
        .collect();
    assert!(sparse.len() > 50, "{}", sparse.len());
    let overwritten: Vec<u32> = sparse
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, _)| index % 5 != 0)
        .map(|(_, key)| key)
        .collect();
    put_rows(&mut state, &mut model, &overwritten, 0x77);
    let overwrites = active_segment(&state);
    fill_segment(&mut state, &mut model, &mut next);
    assert_eq!(active_segment(&state), overwrites + 1);
    Fixture {
        group,
        admission,
        state,
        model,
    }
}

#[test]
fn selection_rule_is_exact_and_independent_of_survey_order() {
    const C: u64 = 1000;
    let segments = [
        (1u64, 950u64),
        (2, 400),
        (3, 900),
        (4, 500),
        (5, 960),
        (6, 880),
        (7, 990),
    ];
    let choose = |order: &[(u64, u64)], percent: u32, cutoff: u64| {
        let mut live = order.to_vec();
        let (kept, garbage) = compaction::keep_segments(&mut live, C, percent, cutoff);
        let kept_ids: Vec<u64> = live[live.len() - kept..]
            .iter()
            .map(|&(id, _)| id)
            .collect();
        (kept_ids, garbage)
    };
    // At most half live is always emptied; the rest keep 320 of garbage,
    // within 25% of 5580 live.
    assert_eq!(choose(&segments, 25, 7), (vec![1, 3, 5, 6, 7], 320));
    // 5% allows 279: the emptiest candidate, 6, goes first.
    assert_eq!(choose(&segments, 5, 7), (vec![1, 3, 5, 7], 200));
    // 1% allows 55: 6, 3 and 1 go, emptiest first.
    assert_eq!(choose(&segments, 1, 7), (vec![5, 7], 50));
    // Equal live bytes: the lower identifier goes first.
    let tied = [(8u64, 900u64), (3, 900), (9, 990)];
    assert_eq!(choose(&tied, 7, 9), (vec![8, 9], 110));
    // Any survey order, and a second computation, choose the same.
    let mut reordered = segments;
    for rotation in 0..segments.len() {
        reordered.rotate_left(1);
        assert_eq!(
            choose(&reordered, 25, 7),
            choose(&segments, 25, 7),
            "{rotation}"
        );
        reordered.reverse();
        assert_eq!(
            choose(&reordered, 5, 7),
            choose(&segments, 5, 7),
            "{rotation}"
        );
    }
    // Kept segments span at most 8 identifiers per surveyed segment: 1 is
    // emptied, 100 and 101 stay.
    let sparse = [(1u64, 990u64), (100, 990), (101, 990)];
    assert_eq!(choose(&sparse, 25, 101), (vec![100, 101], 20));
    // Nothing live: nothing to keep.
    assert_eq!(choose(&[], 25, 7), (Vec::new(), 0));
}

#[test]
fn mostly_live_store_relocates_only_the_sparse_segment() {
    let Fixture {
        group,
        admission: _admission,
        mut state,
        model,
        ..
    } = fixture(PERCENT);
    let cutoff = state.owner.lock().unwrap().compaction_cutoffs();
    assert_eq!(cutoff.0, active_segment(&state) - 1);
    // Premises, measured as the survey counts: the sparse segment is at most
    // half live, every other old one at least 84%, and the newest above the
    // cutoff holds live rows too.
    let before = locations(&state, &model);
    let mut live = BTreeMap::<u64, u64>::new();
    let mut sparse_bytes = 0u64;
    for location in before.values() {
        *live.entry(location.segment_id).or_default() +=
            u64::from(location.len) + segment::VALUE_RECORD_OVERHEAD_BYTES;
        if location.segment_id == SPARSE {
            sparse_bytes += u64::from(location.len);
        }
    }
    assert!(live.contains_key(&(cutoff.0 + 1)), "{live:?}");
    live.retain(|&id, _| id <= cutoff.0);
    assert_eq!(
        live.keys().copied().collect::<Vec<_>>(),
        (1..=cutoff.0).collect::<Vec<_>>()
    );
    for (&id, &bytes) in &live {
        if id == SPARSE {
            assert!(2 * bytes <= CAPACITY, "{id}: {bytes}");
        } else {
            assert!(100 * bytes >= 84 * CAPACITY, "{id}: {bytes}");
        }
    }
    // One leaf names a value of the sparse segment and of a kept one.
    let (leaves, _) = walk(&state, state.selected);
    assert!(
        leaves
            .iter()
            .any(|segments| segments.contains(&SPARSE) && segments.len() > 1),
        "{leaves:?}"
    );
    let (selected, totals) = run_cycle(&mut state, STEP);
    let kept: Vec<u64> = (1..=cutoff.0).filter(|&id| id != SPARSE).collect();
    let (cycle, surveyed, kept_observed) = self::surveyed(selected);
    assert_eq!(cycle, 1);
    // Ids above the cutoff are not surveyed.
    assert_eq!(surveyed, (1..=cutoff.0).collect::<Vec<_>>());
    assert_eq!(kept_observed, kept);
    // Exactly the sparse segment's live values were copied.
    assert_eq!(totals.relocated, sparse_bytes);
    let after = locations(&state, &model);
    for (key, location) in &before {
        if location.segment_id == SPARSE {
            assert!(after[key].segment_id > cutoff.0, "{key}");
        } else {
            assert_eq!(after[key], *location, "{key}");
        }
    }
    assert!(!group.exists(GroupFile::segment(SPARSE)).unwrap());
    for &id in &kept {
        assert!(group.exists(GroupFile::segment(id)).unwrap(), "{id}");
    }
    check_reclaimed(&state, &group, cutoff);
    assert!(state.owner.lock().unwrap().garbage().is_empty());
    let status = state.maintenance_status().unwrap();
    assert_eq!(status.relocated_bytes_total, sparse_bytes);
    assert_eq!(
        (
            status.evacuation_surveyed_segments,
            status.evacuation_kept_segments
        ),
        (surveyed.len() as u64, kept.len() as u64)
    );
    let total: u64 = live.values().sum();
    assert!(status.evacuation_kept_garbage_bytes * 100 <= total * u64::from(PERCENT));
    assert_eq!(status.evacuation_survey_fallbacks_total, 0);
    check_model(&mut state, &model);
    // No new garbage: the next cycle keeps every old segment and rewrites
    // only the old arenas.
    let cutoff = state.owner.lock().unwrap().compaction_cutoffs();
    let (selected, totals) = run_cycle(&mut state, STEP);
    let (_, surveyed, kept_observed) = self::surveyed(selected);
    assert_eq!(surveyed, kept_observed);
    assert_eq!(totals.relocated, 0);
    assert!(totals.maintenance_commits > 0 && totals.directory_pages_written > 0);
    assert_eq!(locations(&state, &model), after);
    for &id in &kept {
        assert!(group.exists(GroupFile::segment(id)).unwrap(), "{id}");
    }
    check_reclaimed(&state, &group, cutoff);
    check_model(&mut state, &model);
}

#[test]
fn reopen_after_every_publication_and_mid_survey_selects_the_same_segments() {
    let (expected, expected_relocated) = {
        let mut fixture = fixture(PERCENT);
        let (selected, totals) = run_cycle(&mut fixture.state, ONE);
        (selected.expect("a selection"), totals.relocated)
    };
    assert!(expected_relocated > 0);
    let Fixture {
        mut group,
        admission,
        mut state,
        model,
        ..
    } = fixture(PERCENT);
    let cutoff = state.owner.lock().unwrap().compaction_cutoffs();
    state.request_compaction().unwrap();
    assert!(step(&mut state, ONE).phase_changed);
    let cycle = record(&state).cycle();
    let mut relocated = 0;
    let mut selections = 0;
    let mut survey_reopens = 0;
    for _ in 0..100_000 {
        let progress = step(&mut state, ONE);
        relocated += progress.relocated_bytes;
        if let Some(observed) = state.compact.selection_for_test() {
            assert_eq!(observed, expected);
            selections += 1;
        }
        let now = record(&state);
        if now.phase() == CompactionPhase::Idle {
            assert_eq!(now.cycle(), cycle);
            break;
        }
        // Reopen after every publication, and in the middle of the first
        // surveys; the last attempts survey to the end.
        let surveying = state.compact.surveying_for_test();
        if progress.mutations != 0 || (surveying && survey_reopens < 3) {
            survey_reopens += usize::from(surveying);
            (group, state) = reopen(state, &group, &admission, PERCENT);
            // Every reachable file survived the crash.
            check_reclaimed_reachable(&state, &group);
        }
    }
    assert_eq!(phase(&state), CompactionPhase::Idle);
    assert_eq!(survey_reopens, 3);
    assert!(selections > 1);
    assert_eq!(relocated, expected_relocated);
    assert!(state.owner.lock().unwrap().garbage().is_empty());
    check_reclaimed(&state, &group, cutoff);
    assert!(!group.exists(GroupFile::segment(SPARSE)).unwrap());
    let (_, _, kept) = surveyed(Some(expected));
    for &id in &kept {
        assert!(group.exists(GroupFile::segment(id)).unwrap(), "{id}");
    }
    check_model(&mut state, &model);
}

fn check_reclaimed_reachable(state: &DiskState, group: &InMemoryGroup) {
    let (_, reached) = walk(state, state.selected);
    let present = present(group);
    for file in &reached {
        assert!(present.contains(file), "{file:?} is reached but missing");
    }
}

/// Evacuate with `first` until the first relocation commit, reopen with
/// `then`, and finish: whatever the two policies select, only unreachable
/// files go and every value reads back.
fn resume_with_other_policy(first: u32, then: u32) -> (Selected, CycleTotals) {
    let Fixture {
        group,
        admission,
        mut state,
        model,
        ..
    } = fixture(first);
    let cutoff = state.owner.lock().unwrap().compaction_cutoffs();
    state.request_compaction().unwrap();
    loop {
        let progress = step(&mut state, ONE);
        if progress.relocated_bytes != 0 {
            break;
        }
        assert_ne!(phase(&state), CompactionPhase::Reclaiming);
    }
    assert_eq!(phase(&state), CompactionPhase::Evacuating);
    let (group, mut state) = reopen(state, &group, &admission, then);
    let finished = run_cycle(&mut state, STEP);
    assert!(state.owner.lock().unwrap().garbage().is_empty());
    check_reclaimed(&state, &group, cutoff);
    check_model(&mut state, &model);
    finished
}

#[test]
fn legacy_policy_resumes_a_selective_evacuation() {
    // An older binary, or the legacy policy, relocates every old value from
    // the persisted ordinal on.
    let (selected, totals) = resume_with_other_policy(PERCENT, 0);
    assert_eq!(selected, Some((1, SelectionForTest::RelocateAll)));
    assert!(totals.relocated > 0);
}

#[test]
fn selective_policy_resumes_a_legacy_evacuation() {
    let (selected, _) = resume_with_other_policy(0, PERCENT);
    let (cycle, surveyed, kept) = self::surveyed(selected);
    assert_eq!(cycle, 1);
    assert!(!surveyed.is_empty() && !kept.is_empty());
    assert!(!kept.contains(&SPARSE));
}

/// Every old segment survives an arena-only cycle with its values in place,
/// and every old arena is gone.
fn check_arena_only(
    state: &DiskState,
    group: &InMemoryGroup,
    cutoff: (u64, u64),
    before: &BTreeMap<u32, ValueLocation>,
    model: &BTreeMap<u32, Vec<u8>>,
) {
    assert_eq!(&locations(state, model), before);
    for location in before.values() {
        assert!(
            group
                .exists(GroupFile::segment(location.segment_id))
                .unwrap()
        );
    }
    check_reclaimed(state, group, cutoff);
    for file in present(group) {
        if file.kind == FileKind::Directory {
            assert!(file.id > cutoff.1, "{file:?} is an old arena");
        }
    }
}

#[test]
fn refused_survey_admission_falls_back_to_an_arena_only_cycle() {
    let Fixture {
        group,
        admission,
        mut state,
        model,
        ..
    } = fixture(PERCENT);
    let cutoff = state.owner.lock().unwrap().compaction_cutoffs();
    let before = locations(&state, &model);
    state.request_compaction().unwrap();
    assert!(step(&mut state, ONE).phase_changed);
    for attempt in 0..compaction::SURVEY_ATTEMPTS {
        admission.deny_nth(1);
        let progress = state.maintenance_step(ONE).unwrap();
        assert_eq!(
            progress.deferred,
            Some(MaintenanceDeferral::Capacity),
            "{attempt}"
        );
        assert!(!state.compact.surveying_for_test());
        assert!(state.compact.selection_for_test().is_none());
        // A request clears the capacity backoff.
        state.request_compaction().unwrap();
    }
    // The cycle keeps every old segment in place and rewrites old arenas.
    let (selected, totals) = run_cycle(&mut state, STEP);
    assert_eq!(selected, Some((1, SelectionForTest::KeepAll)));
    assert_eq!(totals.relocated, 0);
    assert!(totals.maintenance_commits > 0);
    check_arena_only(&state, &group, cutoff, &before, &model);
    let status = state.maintenance_status().unwrap();
    assert_eq!(status.evacuation_survey_fallbacks_total, 1);
    assert_eq!(
        (
            status.evacuation_surveyed_segments,
            status.evacuation_kept_segments
        ),
        (0, 0)
    );
    check_model(&mut state, &model);
    // The next cycle surveys again and empties the sparse segment.
    let (selected, totals) = run_cycle(&mut state, STEP);
    let (_, _, kept) = surveyed(selected);
    assert!(!kept.contains(&SPARSE));
    assert!(totals.relocated > 0);
    assert!(!group.exists(GroupFile::segment(SPARSE)).unwrap());
    check_model(&mut state, &model);
}

#[test]
fn owed_round_keeps_segments_the_current_root_still_references() {
    // A pin taken before the cycle holds an overwritten value of a kept
    // segment. The kept segment stays referenced by the current root and a
    // pin of it; the round the old pin owes frees only what it alone held.
    let Fixture {
        group,
        admission: _admission,
        mut state,
        mut model,
        ..
    } = fixture(PERCENT);
    // Overwrite one row of each kept segment and pin the old versions.
    let old = state.snapshot().unwrap();
    let old_model = model.clone();
    let cutoff = state.owner.lock().unwrap().compaction_cutoffs();
    let mut probes = BTreeMap::new();
    for &key in old_model.keys() {
        let segment = located(&state, key).segment_id;
        if segment <= cutoff.0 && segment != SPARSE {
            probes.entry(segment).or_insert(key);
        }
    }
    let keys: Vec<u32> = probes.values().copied().collect();
    put_rows(&mut state, &mut model, &keys, 0x99);
    // The overwrites go to the newest segment, above the cutoff, and do not
    // change what the next cycle keeps.
    let (selected, _) = run_cycle(&mut state, STEP);
    let (_, _, kept) = surveyed(selected);
    assert!(!kept.is_empty());
    assert!(!kept.contains(&SPARSE));
    // The sparse segment's evacuated rows are held only by the old pin.
    assert!(group.exists(GroupFile::segment(SPARSE)).unwrap());
    let (_, evacuated) = state.reclaim.owed_round_for_test().expect("owed round");
    assert!(old.root().generation < evacuated);
    let current = state.snapshot().unwrap();
    let mut settled = 0;
    while !step(&mut state, STEP).idle {
        settled += 1;
        assert!(settled < 20_000);
    }
    assert!(group.exists(GroupFile::segment(SPARSE)).unwrap());
    // The old pin still reads every version it was taken at.
    for (key, expected) in &old_model {
        assert_eq!(
            value(&mut state, &old, &key.to_be_bytes()).as_ref(),
            Some(expected),
            "{key}"
        );
    }
    drop(old);
    while state.round_active() || state.reclaim.owed_round_for_test().is_some() {
        step(&mut state, STEP);
        settled += 1;
        assert!(settled < 40_000);
    }
    assert!(!group.exists(GroupFile::segment(SPARSE)).unwrap());
    // Kept segments survive: the current root and its pin reach them.
    for &id in &kept {
        assert!(group.exists(GroupFile::segment(id)).unwrap(), "{id}");
    }
    check_reclaimed_reachable(&state, &group);
    for (key, expected) in &model {
        assert_eq!(
            value(&mut state, &current, &key.to_be_bytes()).as_ref(),
            Some(expected),
            "{key}"
        );
    }
    assert_eq!(
        state
            .maintenance_status()
            .unwrap()
            .reclaim_invalidations_total,
        0
    );
}

/// Segments of exactly three commits of ten rows: nearly full, 87% live as
/// the survey counts, so many fit in a fast test.
const DENSE_CAPACITY: u64 = crate::segment::SEGMENT_HEADER_BYTES + 3 * DENSE_BATCH + 100;
/// One commit of ten rows: their put records and the commit record.
const DENSE_BATCH: u64 = 10 * (36 + 16 + 8 + 4 + VALUE as u64) + 204;

/// `segments` dense old segments, after a table-only first one. Of every
/// tenth, four rows in five are overwritten; then fresh rows seal the
/// segment holding the overwrites. Returns the sparse segments too.
fn many_segments(segments: u64) -> (Fixture, Vec<u64>) {
    let group = InMemoryGroup::new();
    let admission = Admission::new(64 << 20);
    let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
    geometry_with_capacity(&mut state, PERCENT, DENSE_CAPACITY);
    let mut model = BTreeMap::new();
    let mut next = 0;
    state
        .commit(&[Operation::create_table("accounts")])
        .unwrap();
    // Rolls the segment too; geometry is applied again for the new arena.
    seal_files(&mut state);
    geometry_with_capacity(&mut state, PERCENT, DENSE_CAPACITY);
    while active_segment(&state) <= segments + 1 {
        fill_segment(&mut state, &mut model, &mut next);
    }
    let sparse: Vec<u64> = (12..=segments + 1).step_by(10).collect();
    let overwritten: Vec<u32> = model
        .keys()
        .copied()
        .filter(|&key| sparse.contains(&located(&state, key).segment_id))
        .filter(|key| key % 5 != 0)
        .collect();
    put_rows(&mut state, &mut model, &overwritten, 0x77);
    fill_segment(&mut state, &mut model, &mut next);
    (
        Fixture {
            group,
            admission,
            state,
            model,
        },
        sparse,
    )
}

/// The survey selection the rule makes for these premises: every segment
/// more than half live but `sparse`, whose kept garbage is within the
/// policy and whose span is within the rule.
fn premises(
    state: &DiskState,
    model: &BTreeMap<u32, Vec<u8>>,
    sparse: &[u64],
) -> (BTreeMap<u64, u64>, u64) {
    let cutoff = state.owner.lock().unwrap().compaction_cutoffs().0;
    let mut live = BTreeMap::<u64, u64>::new();
    let mut sparse_bytes = 0;
    for location in locations(state, model).values() {
        if location.segment_id <= cutoff {
            *live.entry(location.segment_id).or_default() +=
                u64::from(location.len) + segment::VALUE_RECORD_OVERHEAD_BYTES;
            if sparse.contains(&location.segment_id) {
                sparse_bytes += u64::from(location.len);
            }
        }
    }
    let total: u64 = live.values().sum();
    let mut kept_garbage = 0;
    for (&id, &bytes) in &live {
        if sparse.contains(&id) {
            assert!(2 * bytes <= DENSE_CAPACITY, "{id}: {bytes}");
        } else {
            assert!(2 * bytes > DENSE_CAPACITY, "{id}: {bytes}");
            kept_garbage += DENSE_CAPACITY - bytes;
        }
    }
    assert!(kept_garbage * 100 <= total * u64::from(PERCENT));
    let oldest = live
        .keys()
        .find(|id| !sparse.contains(id))
        .copied()
        .unwrap();
    assert!(cutoff - oldest < 8 * live.len() as u64);
    (live, sparse_bytes)
}

#[test]
fn survey_of_more_segments_than_its_first_map_grows_and_keeps_the_dense_ones() {
    let (fixture, sparse) = many_segments(80);
    let Fixture {
        group,
        admission: _admission,
        mut state,
        model,
    } = fixture;
    let cutoff = state.owner.lock().unwrap().compaction_cutoffs();
    let (live, sparse_bytes) = premises(&state, &model, &sparse);
    assert!(live.len() > 64, "{}", live.len());
    let before = locations(&state, &model);
    let (selected, totals) = run_cycle(&mut state, STEP);
    let (_, surveyed, kept) = surveyed(selected);
    assert_eq!(surveyed, live.keys().copied().collect::<Vec<_>>());
    let expected: Vec<u64> = live
        .keys()
        .copied()
        .filter(|id| !sparse.contains(id))
        .collect();
    assert_eq!(kept, expected);
    assert_eq!(totals.relocated, sparse_bytes);
    for (key, location) in &before {
        if !sparse.contains(&location.segment_id) {
            assert_eq!(located(&state, *key), *location, "{key}");
        }
    }
    for &id in &sparse {
        assert!(!group.exists(GroupFile::segment(id)).unwrap(), "{id}");
    }
    check_reclaimed(&state, &group, cutoff);
    check_model(&mut state, &model);
}

#[test]
fn refusal_in_the_middle_of_a_survey_restarts_it() {
    // Measure where the map grows past its first capacity, mid-walk, and
    // which reservations that step makes.
    let (dry, _) = many_segments(80);
    let Fixture {
        admission,
        mut state,
        ..
    } = dry;
    state.request_compaction().unwrap();
    assert!(step(&mut state, ONE).phase_changed);
    let mut growth = None;
    let mut steps = 0;
    let expected = loop {
        let before = state.compact.survey_segments_for_test().unwrap_or(0);
        let calls = admission.calls.load(Ordering::Acquire);
        step(&mut state, ONE);
        steps += 1;
        let after = state.compact.survey_segments_for_test();
        if before <= 64 && after.is_some_and(|after| after > 64) {
            growth = Some((steps, admission.calls.load(Ordering::Acquire) - calls));
        }
        if let Some(selection) = state.compact.selection_for_test() {
            break selection;
        }
    };
    let (growth_step, reservations) = growth.expect("the map grew during the survey");
    assert!(growth_step > 1, "the growth is not the survey's first step");
    assert_eq!(
        reservations, 1,
        "only the doubled map is admitted in that step"
    );
    drop(state);

    let (fixture, sparse) = many_segments(80);
    let Fixture {
        group,
        admission,
        mut state,
        model,
    } = fixture;
    let cutoff = state.owner.lock().unwrap().compaction_cutoffs();
    state.request_compaction().unwrap();
    assert!(step(&mut state, ONE).phase_changed);
    for _ in 1..growth_step {
        step(&mut state, ONE);
    }
    let walked = state.compact.survey_segments_for_test().unwrap();
    assert!(walked > 0 && walked <= 64, "{walked}");
    admission.deny_nth(1);
    let progress = state.maintenance_step(ONE).unwrap();
    assert_eq!(progress.deferred, Some(MaintenanceDeferral::Capacity));
    assert_eq!(admission.refused_calls.load(Ordering::Acquire), 1);
    assert!(!state.compact.surveying_for_test());
    assert!(state.compact.selection_for_test().is_none());
    // The retry walks again from the start and selects the same segments.
    let (selected, _) = run_cycle(&mut state, STEP);
    assert_eq!(selected, Some(expected));
    let (_, _, kept) = surveyed(selected);
    assert!(sparse.iter().all(|id| !kept.contains(id)));
    assert_eq!(
        state
            .maintenance_status()
            .unwrap()
            .evacuation_survey_fallbacks_total,
        0
    );
    for &id in &sparse {
        assert!(!group.exists(GroupFile::segment(id)).unwrap(), "{id}");
    }
    check_reclaimed(&state, &group, cutoff);
    check_model(&mut state, &model);
}

#[test]
fn survey_beyond_its_segment_bound_keeps_every_old_segment() {
    let (fixture, _) = many_segments(40);
    let Fixture {
        group,
        admission: _admission,
        mut state,
        model,
    } = fixture;
    let cutoff = state.owner.lock().unwrap().compaction_cutoffs();
    let before = locations(&state, &model);
    // A store with more old segments than the bound: the walk stops at the
    // first segment past it, with no refusal and no retry.
    state.compact.bound_survey_for_test(16);
    let (selected, totals) = run_cycle(&mut state, ONE);
    assert_eq!(selected, Some((1, SelectionForTest::KeepAll)));
    assert_eq!(totals.relocated, 0);
    let status = state.maintenance_status().unwrap();
    assert_eq!(status.evacuation_survey_fallbacks_total, 1);
    assert_eq!(status.capacity_deferrals_total, 0);
    check_arena_only(&state, &group, cutoff, &before, &model);
    check_model(&mut state, &model);
}

/// A dense old segment, then hot keys rewritten until the writer reaches
/// segment `last`: the segments between hold no live value. Returns the dense
/// segment and its live value bytes.
fn dense_then_churn(last: u64) -> (Fixture, u64, u64) {
    let group = InMemoryGroup::new();
    let admission = Admission::new(64 << 20);
    let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
    geometry_with_capacity(&mut state, PERCENT, DENSE_CAPACITY);
    let mut model = BTreeMap::new();
    let mut next = 0;
    state
        .commit(&[Operation::create_table("accounts")])
        .unwrap();
    seal_files(&mut state);
    geometry_with_capacity(&mut state, PERCENT, DENSE_CAPACITY);
    let dense = active_segment(&state);
    fill_segment(&mut state, &mut model, &mut next);
    let dense_bytes = locations(&state, &model)
        .values()
        .filter(|location| location.segment_id == dense)
        .map(|location| u64::from(location.len))
        .sum();
    let hot: Vec<u32> = (100_000..100_000 + ROWS_PER_COMMIT).collect();
    let mut round = 0u8;
    while active_segment(&state) < last {
        put_rows(&mut state, &mut model, &hot, round);
        round = round.wrapping_add(1);
    }
    fill_segment(&mut state, &mut model, &mut next);
    (
        Fixture {
            group,
            admission,
            state,
            model,
        },
        dense,
        dense_bytes,
    )
}

#[test]
fn kept_segments_spanning_too_many_identifiers_are_emptied() {
    // Few segments stay live over a wide identifier range: the span rule
    // empties the dense old one that the garbage bound alone would keep.
    let (fixture, dense, dense_bytes) = dense_then_churn(40);
    let Fixture {
        group,
        admission: _admission,
        mut state,
        model,
    } = fixture;
    let cutoff = state.owner.lock().unwrap().compaction_cutoffs();
    let (selected, totals) = run_cycle(&mut state, STEP);
    let (_, surveyed, kept) = surveyed(selected);
    assert!(
        surveyed.contains(&dense) && surveyed.len() <= 4,
        "{surveyed:?}"
    );
    assert!(cutoff.0 - dense + 1 > 8 * surveyed.len() as u64);
    assert!(!kept.is_empty() && !kept.contains(&dense), "{kept:?}");
    assert!(totals.relocated >= dense_bytes);
    assert!(!group.exists(GroupFile::segment(dense)).unwrap());
    check_reclaimed(&state, &group, cutoff);
    check_model(&mut state, &model);

    // Within the span, the same dense segment is kept in place.
    let (fixture, dense, _) = dense_then_churn(12);
    let Fixture {
        group,
        admission: _admission,
        mut state,
        model,
    } = fixture;
    let cutoff = state.owner.lock().unwrap().compaction_cutoffs();
    let (selected, _) = run_cycle(&mut state, STEP);
    let (_, surveyed, kept) = self::surveyed(selected);
    assert!(cutoff.0 - dense < 8 * surveyed.len() as u64);
    assert!(kept.contains(&dense), "{kept:?}");
    assert!(group.exists(GroupFile::segment(dense)).unwrap());
    check_reclaimed(&state, &group, cutoff);
    check_model(&mut state, &model);
}
