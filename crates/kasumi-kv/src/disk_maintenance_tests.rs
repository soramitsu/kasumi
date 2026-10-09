// Included beneath disk_state::tests: whole-machine behavior of the persisted
// compaction cycle under steady writes, pins, crash loops and random
// interleavings, with small file geometry.

use super::*;
use crate::directory::DirectoryWalker;
use crate::group::FileKind;
use crate::root::CompactionPhase;
use std::collections::BTreeMap;

const SEGMENT_CAPACITY: u64 = 16 << 10;
const ARENA_PAGES: u64 = 16;
const ARENA_CAPACITY: u64 =
    crate::arena::HEADER_BYTES as u64 + ARENA_PAGES * crate::directory::DIRECTORY_PAGE_BYTES as u64;

fn policy() -> MaintenancePolicy {
    MaintenancePolicy {
        growth_percent: 200,
        slack_bytes: 256 << 10,
        slack_files: 8,
        ..MaintenancePolicy::default()
    }
}

/// Small files: frequent segment and arena rolls.
fn geometry(state: &mut DiskState) {
    let writer = std::mem::replace(&mut state.writer, SegmentWriter::new(GROUP));
    state.writer = writer.with_capacity(SEGMENT_CAPACITY);
    replace_arena(state, Some(ARENA_PAGES));
    state.configure_maintenance(policy()).unwrap();
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Usage {
    segment_files: u64,
    segment_bytes: u64,
    arena_files: u64,
    arena_bytes: u64,
}

impl Usage {
    fn files(&self) -> u64 {
        self.segment_files + self.arena_files
    }
    fn bytes(&self) -> u64 {
        self.segment_bytes + self.arena_bytes
    }
    fn max(self, other: Self) -> Self {
        Self {
            segment_files: self.segment_files.max(other.segment_files),
            segment_bytes: self.segment_bytes.max(other.segment_bytes),
            arena_files: self.arena_files.max(other.arena_files),
            arena_bytes: self.arena_bytes.max(other.arena_bytes),
        }
    }
}

fn usage(group: &InMemoryGroup) -> Usage {
    let mut files = Vec::new();
    group
        .visit_entries(&mut |name| {
            if let Some(file) = name.to_str().and_then(GroupFile::parse_name) {
                files.push(file);
            }
            Ok(())
        })
        .unwrap();
    let mut usage = Usage::default();
    for file in files {
        let len = group.len(file).unwrap();
        match file.kind {
            FileKind::Segment => {
                usage.segment_files += 1;
                usage.segment_bytes += len;
            }
            FileKind::Directory => {
                usage.arena_files += 1;
                usage.arena_bytes += len;
            }
            FileKind::Checkpoint => {}
        }
    }
    usage
}

fn cold_rows(state: &mut DiskState, model: &mut BTreeMap<u32, Vec<u8>>, count: u32) {
    state
        .commit(&[Operation::create_table("accounts")])
        .unwrap();
    for chunk in (0..count).collect::<Vec<_>>().chunks(100) {
        let operations: Vec<_> = chunk
            .iter()
            .map(|&key| {
                let value = vec![key as u8; 32];
                model.insert(key, value.clone());
                Operation::put("accounts", key.to_be_bytes(), value)
            })
            .collect();
        state.commit(&operations).unwrap();
    }
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

/// Inline-only driver: one policy-budget step before every commit, as
/// `Database::begin_write` does. Returns the usage after each commit.
fn steady_stream(pins_every: Option<usize>) {
    let group = InMemoryGroup::new();
    let admission = Admission::new(64 << 20);
    // Without a value cache each commit skips publication proofs; the
    // maintenance machine is the subject here, not cache residency.
    let mut state = create(
        Arc::new(group.clone()),
        admission,
        CacheConfig { byte_limit: 0 },
    );
    geometry(&mut state);
    let mut model = BTreeMap::new();
    cold_rows(&mut state, &mut model, 2000);
    assert!(state.selected.height >= 2);
    let commits = 20_000usize;
    let mut window = Usage::default();
    let mut tail = Usage::default();
    let mut live_pins: std::collections::VecDeque<(usize, SnapshotPin)> = Default::default();
    let budget = state.inline_maintenance_budget();
    for index in 0..commits {
        let progress = state.maintenance_step(budget).unwrap();
        assert_eq!(progress.deferred, None, "commit {index}");
        let key = (index % 16) as u32 * 97;
        let value = (index as u32).to_be_bytes().repeat(8);
        state
            .commit(&[Operation::put("accounts", key.to_be_bytes(), value.clone())])
            .unwrap();
        model.insert(key, value);
        if let Some(every) = pins_every {
            if index % every == 0 {
                live_pins.push_back((index, state.snapshot().unwrap()));
            }
            // Bounded lifetime: every pin is dropped 4 * every commits later.
            while live_pins
                .front()
                .is_some_and(|(taken, _)| index - taken >= 4 * every)
            {
                live_pins.pop_front();
            }
        }
        let now = usage(&group);
        if index % 2000 == 0 {
            let status = state.maintenance_status().unwrap();
            eprintln!(
                "steady_stream commit={index} files={} bytes={} phase={:?} cycles={} reclaimed={}",
                now.files(),
                now.bytes(),
                status.phase,
                status.cycles_completed,
                status.reclaimed_files_total
            );
        }
        if (commits / 4..commits / 2).contains(&index) {
            window = window.max(now);
        } else if index >= commits / 2 {
            tail = tail.max(now);
        }
    }
    drop(live_pins);
    let status = state.maintenance_status().unwrap();
    eprintln!(
        "steady_stream pins={pins_every:?} window={window:?} tail={tail:?} cycles={} reclaimed_files={} invalidations={} deferrals={}",
        status.cycles_completed,
        status.reclaimed_files_total,
        status.reclaim_invalidations_total,
        status.capacity_deferrals_total + status.rejected_deferrals_total,
    );
    assert!(status.cycles_completed >= 2, "{status:?}");
    assert!(status.reclaimed_files_total > 0);
    assert!(
        tail.files() <= window.files() + 2,
        "files grew: window {window:?} tail {tail:?}"
    );
    assert!(
        tail.bytes() <= window.bytes() + SEGMENT_CAPACITY + ARENA_CAPACITY,
        "bytes grew: window {window:?} tail {tail:?}"
    );
    check_model(&mut state, &model);
}

#[test]
fn steady_commit_stream_plateaus() {
    steady_stream(None);
}

#[test]
fn steady_stream_with_bounded_lifetime_pins_plateaus() {
    steady_stream(Some(97));
}

#[test]
fn crash_loop_reopen_stays_bounded() {
    let admission = Admission::new(64 << 20);
    let mut group = InMemoryGroup::new();
    let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
    geometry(&mut state);
    let mut model = BTreeMap::new();
    cold_rows(&mut state, &mut model, 400);
    let live_value_bytes = 400 * 32;
    let mut relocated = 0u64;
    let mut peak = Usage::default();
    let mut later_peak = Usage::default();
    let opens = 120;
    for open in 0..opens {
        for commit in 0..3u32 {
            let key = (open as u32 * 3 + commit) % 400;
            let value = vec![(open % 251) as u8; 32];
            state
                .commit(&[Operation::put("accounts", key.to_be_bytes(), value.clone())])
                .unwrap();
            model.insert(key, value);
        }
        // The node worker's per-lifetime share, capped at a fixed unit total.
        let mut units = 0;
        while units < 4096 {
            let progress = state
                .maintenance_step(MaintenanceBudget {
                    units: 512,
                    mutations: 1,
                })
                .unwrap();
            assert_eq!(progress.deferred, None);
            relocated += progress.relocated_bytes;
            units += progress.units.max(1);
            if progress.idle {
                break;
            }
        }
        let now = usage(&group);
        if open < opens / 2 {
            peak = peak.max(now);
        } else {
            later_peak = later_peak.max(now);
        }
        drop(state);
        group = group.crash();
        state = DiskState::open(
            Arc::new(group.clone()),
            admission.clone(),
            GROUP,
            LARGE_CACHE,
        )
        .unwrap();
        geometry(&mut state);
    }
    let cycles = record(&state).cycle();
    eprintln!(
        "crash_loop opens={opens} cycles={cycles} relocated={relocated} peak={peak:?} later={later_peak:?}"
    );
    assert!(cycles >= 2, "crash loop never completed compaction cycles");
    // Each cycle relocates each old live value at most once; a reopen never
    // restarts a cycle's evacuation from the beginning.
    assert!(
        relocated <= cycles * live_value_bytes as u64,
        "relocated {relocated} over {cycles} cycles of {live_value_bytes}"
    );
    assert!(
        later_peak.files() <= peak.files() + 2,
        "files grew across reopens: {peak:?} then {later_peak:?}"
    );
    assert!(later_peak.bytes() <= peak.bytes() + SEGMENT_CAPACITY + ARENA_CAPACITY);
    // Finishing the active cycle leaves the store Idle with no garbage.
    drive_cycle(&mut state, STEP);
    assert_eq!(phase(&state), CompactionPhase::Idle);
    assert!(state.owner.lock().unwrap().garbage().is_empty());
    check_model(&mut state, &model);
}

#[test]
fn completed_cycle_baseline_prevents_new_cycle_after_reopen() {
    let admission = Admission::new(64 << 20);
    let group = InMemoryGroup::new();
    let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
    geometry(&mut state);
    let mut model = BTreeMap::new();
    cold_rows(&mut state, &mut model, 1000);
    let budget = MaintenanceBudget {
        units: 64,
        mutations: 1,
    };
    // Threshold-driven cycles until one completes.
    let mut steps = 0;
    while state.maintenance_status().unwrap().cycles_completed == 0 {
        let progress = step(&mut state, budget);
        if progress.idle {
            let value = vec![steps as u8];
            state
                .commit(&[Operation::put(
                    "accounts",
                    7u32.to_be_bytes(),
                    value.clone(),
                )])
                .unwrap();
            model.insert(7, value);
        }
        steps += 1;
        assert!(steps < 50_000);
    }
    let completed = record(&state);
    assert_eq!(completed.phase(), CompactionPhase::Idle);
    assert!(completed.baseline_bytes() > 0 && completed.baseline_files() > 0);
    // Measure, then show nothing is due.
    loop {
        if step(&mut state, budget).idle {
            break;
        }
    }
    let status = state.maintenance_status().unwrap();
    assert!(status.measured);
    assert!(status.segment_bytes + status.arena_bytes < status.trigger_bytes);
    drop(state);
    let mut reopened = DiskState::open(
        Arc::new(group.crash()),
        admission.clone(),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    reopened.configure_maintenance(policy()).unwrap();
    assert_eq!(record(&reopened), completed);
    for _ in 0..10_000 {
        let progress = step(&mut reopened, budget);
        assert_eq!(
            record(&reopened).cycle(),
            completed.cycle(),
            "reopen began a cycle"
        );
        if progress.idle {
            break;
        }
    }
    let status = reopened.maintenance_status().unwrap();
    assert!(status.measured);
    assert_eq!(status.baseline_bytes, completed.baseline_bytes());
    assert_eq!(
        status.trigger_bytes,
        policy().trigger_bytes(completed.baseline_bytes())
    );
    // Growth past the persisted thresholds begins the next cycle.
    let mut grown = 0u32;
    while record(&reopened).cycle() == completed.cycle() {
        reopened
            .commit(&[Operation::put(
                "accounts",
                (5000 + grown).to_be_bytes(),
                vec![1; 512],
            )])
            .unwrap();
        model.insert(5000 + grown, vec![1; 512]);
        step(&mut reopened, budget);
        grown += 1;
        assert!(grown < 20_000);
    }
    check_model(&mut reopened, &model);
}

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Files reachable from each root walked so far. A root and its pages are
/// immutable, so a root's reachable set never changes once walked.
#[derive(Default)]
struct Reachable(Vec<(DirectoryRoot, Vec<GroupFile>)>);

impl Reachable {
    /// Every file reachable from `root` exists in `group`. The first visit
    /// walks the root (each page read is verified); later visits recheck the
    /// existence of the same files.
    fn assert_present(&mut self, state: &DiskState, group: &InMemoryGroup, root: DirectoryRoot) {
        let index = match self.0.iter().position(|(walked, _)| *walked == root) {
            Some(index) => index,
            None => {
                let files = std::cell::RefCell::new(std::collections::BTreeSet::new());
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
                                Ok(())
                            },
                            |value| {
                                files
                                    .borrow_mut()
                                    .insert(GroupFile::segment(value.segment_id));
                                Ok(())
                            },
                        )
                        .unwrap();
                    if progress.complete {
                        break;
                    }
                }
                self.0
                    .push((root, files.into_inner().into_iter().collect()));
                self.0.len() - 1
            }
        };
        for file in &self.0[index].1 {
            assert!(
                group.exists(*file).unwrap(),
                "{file:?} of {root:?} is missing"
            );
        }
    }

    /// Forget roots that are neither current nor pinned any more.
    fn retain(&mut self, live: &[DirectoryRoot]) {
        self.0.retain(|(root, _)| live.contains(root));
    }
}

#[test]
fn randomized_model_interleavings_preserve_reachability() {
    for seed in [0x5eed_0001u64, 0x5eed_0002, 0x5eed_0003] {
        let mut rng = seed;
        let admission = Admission::new(64 << 20);
        let mut group = InMemoryGroup::new();
        let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
        geometry(&mut state);
        let mut model: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        state
            .commit(&[Operation::create_table("accounts")])
            .unwrap();
        let mut pins: Vec<(SnapshotPin, BTreeMap<u32, Vec<u8>>)> = Vec::new();
        let mut reachable = Reachable::default();
        for iteration in 0..700 {
            match splitmix(&mut rng) % 100 {
                0..=44 => {
                    let mut operations = Vec::new();
                    for _ in 0..1 + splitmix(&mut rng) % 6 {
                        let key = (splitmix(&mut rng) % 300) as u32;
                        if splitmix(&mut rng) % 4 == 0 {
                            model.remove(&key);
                            operations.push(Operation::delete("accounts", key.to_be_bytes()));
                        } else {
                            let len = 1 + (splitmix(&mut rng) % 600) as usize;
                            let value = vec![(iteration % 251) as u8; len];
                            model.insert(key, value.clone());
                            operations.push(Operation::put("accounts", key.to_be_bytes(), value));
                        }
                    }
                    state.commit(&operations).unwrap();
                }
                45..=74 => {
                    let budget = MaintenanceBudget {
                        units: 1 + (splitmix(&mut rng) % 64) as usize,
                        mutations: (splitmix(&mut rng) % 3) as usize,
                    };
                    if splitmix(&mut rng) % 8 == 0 {
                        state.request_compaction().unwrap();
                    }
                    let progress = state.maintenance_step(budget).unwrap();
                    assert_eq!(progress.deferred, None, "{seed:x}/{iteration}");
                }
                75..=84 => {
                    if pins.len() < 8 {
                        pins.push((state.snapshot().unwrap(), model.clone()));
                    }
                }
                85..=89 => {
                    if let Some(index) = (!pins.is_empty())
                        .then(|| (splitmix(&mut rng) % pins.len() as u64) as usize)
                    {
                        let (pin, expected) = &pins[index];
                        let copy = (pin.clone(), expected.clone());
                        pins.push(copy);
                    }
                }
                90..=96 => {
                    if !pins.is_empty() {
                        let index = (splitmix(&mut rng) % pins.len() as u64) as usize;
                        pins.swap_remove(index);
                    }
                }
                _ => {
                    pins.clear();
                    drop(state);
                    group = group.crash();
                    state = DiskState::open(
                        Arc::new(group.clone()),
                        admission.clone(),
                        GROUP,
                        LARGE_CACHE,
                    )
                    .unwrap_or_else(|error| panic!("{seed:x}/{iteration}: {error:?}"));
                    geometry(&mut state);
                }
            }
            // Oracle: the current root, every live pin and the replay anchor
            // reach only present files, and every pin still reads its model.
            reachable.assert_present(&state, &group, state.selected);
            for (pin, _) in &pins {
                reachable.assert_present(&state, &group, pin.root());
            }
            let live: Vec<_> = std::iter::once(state.selected)
                .chain(pins.iter().map(|(pin, _)| pin.root()))
                .collect();
            reachable.retain(&live);
            if let Some(commit) = state.owner.lock().unwrap().directory() {
                assert!(
                    group
                        .exists(GroupFile::segment(commit.start.position.segment_id))
                        .unwrap()
                );
            }
            if iteration % 25 == 0 {
                for (pin, expected) in &pins {
                    for (key, bytes) in expected {
                        assert_eq!(
                            state
                                .get(pin, "accounts", &key.to_be_bytes(), usize::MAX)
                                .unwrap()
                                .map(|value| value.as_bytes().to_vec())
                                .as_ref(),
                            Some(bytes),
                            "{seed:x}/{iteration}"
                        );
                    }
                }
                check_model(&mut state, &model);
            }
        }
        let status = state.maintenance_status().unwrap();
        eprintln!("randomized seed={seed:x} status={status:?}");
        assert_eq!(status.reclaim_invalidations_total, 0);
        pins.clear();
        drive_cycle(&mut state, STEP);
        check_model(&mut state, &model);
        assert!(record(&state).cycle() >= 1);
    }
}
