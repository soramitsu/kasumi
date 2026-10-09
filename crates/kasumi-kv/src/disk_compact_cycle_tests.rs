// Included beneath disk_state::tests::disk_compact: the persisted cycle, its
// cursors across reopen, phase publication faults and reserved batch space.

use super::*;
use crate::group::{ExistingFileSpace, FileKind, FileSpaceRange, TransactionSpacePlan};
use std::sync::Mutex as StdMutex;

fn rows(state: &mut DiskState, count: u32, bytes: usize) {
    let mut operations = vec![Operation::create_table("accounts")];
    for key in 0..count {
        operations.push(Operation::put(
            "accounts",
            key.to_be_bytes(),
            vec![key as u8; bytes],
        ));
    }
    state.commit(&operations).unwrap();
}

fn reopen(group: &InMemoryGroup, admission: &Arc<Admission>) -> (InMemoryGroup, DiskState) {
    let restarted = group.crash();
    let state = DiskState::open(
        Arc::new(restarted.clone()),
        admission.clone(),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    (restarted, state)
}

#[test]
fn evacuation_cursor_rides_installs_and_resumes_after_reopen_without_recopy() {
    let admission = Admission::new(16 << 20);
    let mut group = InMemoryGroup::new();
    let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
    rows(&mut state, 1200, 64);
    seal_files(&mut state);
    let old_bytes = 1200 * 64;
    state.request_compaction().unwrap();
    assert!(step(&mut state, ONE).phase_changed);
    let mut relocated = 0;
    let mut reopens = 0;
    let mut extra = 0u32;
    loop {
        for _ in 0..2 {
            relocated += step(&mut state, ONE).relocated_bytes;
        }
        if phase(&state) != CompactionPhase::Evacuating {
            break;
        }
        // A foreground install carries the in-memory cursor even when the
        // last maintenance item was a skip without a commit.
        state
            .commit(&[Operation::put(
                "accounts",
                (5000 + extra).to_be_bytes(),
                b"fresh",
            )])
            .unwrap();
        extra += 1;
        let persisted = record(&state);
        assert_eq!(persisted.phase(), CompactionPhase::Evacuating);
        assert!(!persisted.cursor().is_none());
        drop(state);
        (group, state) = reopen(&group, &admission);
        reopens += 1;
        assert_eq!(record(&state), persisted);
        // The 1 MiB-after-open trigger is gone: reopen resumes, never restarts.
        assert_eq!(record(&state).cycle(), 1);
    }
    assert!(reopens >= 2, "fixture must reopen mid-evacuation");
    assert_eq!(relocated, old_bytes, "a reopen re-copied relocated values");
    drive_cycle(&mut state, STEP);
    assert_eq!(record(&state).cycle(), 1);
    let pin = state.snapshot().unwrap();
    for key in [0u32, 599, 1199] {
        assert_eq!(
            state
                .get(&pin, "accounts", &key.to_be_bytes(), 64)
                .unwrap()
                .unwrap()
                .as_bytes(),
            vec![key as u8; 64]
        );
    }
    for key in 0..extra {
        assert_eq!(
            value(&mut state, &pin, &(5000 + key).to_be_bytes()).unwrap(),
            b"fresh"
        );
    }
}

/// The step index (1-based, `ONE` budget) at which `target` is entered.
fn transition_step(target: CompactionPhase, fixture: &dyn Fn() -> (InMemoryGroup, DiskState)) -> usize {
    let (_, mut state) = fixture();
    state.request_compaction().unwrap();
    for index in 1..=20_000 {
        let before = phase(&state);
        step(&mut state, ONE);
        if before != target && phase(&state) == target {
            return index;
        }
    }
    panic!("transition to {target:?} was not reached");
}

#[test]
fn phase_publication_faults_reopen_to_old_or_new_phase() {
    let admission = Admission::new(16 << 20);
    let fixture = || {
        let group = InMemoryGroup::new();
        let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
        rows(&mut state, 300, 48);
        let deletes: Vec<_> = (0..300u32)
            .filter(|key| key % 3 != 0)
            .map(|key| Operation::delete("accounts", key.to_be_bytes()))
            .collect();
        state.commit(&deletes).unwrap();
        seal_files(&mut state);
        (group, state)
    };
    let transitions = [
        (CompactionPhase::Idle, CompactionPhase::Evacuating),
        (CompactionPhase::Evacuating, CompactionPhase::Reclaiming),
        (CompactionPhase::Reclaiming, CompactionPhase::Packing),
        (CompactionPhase::Packing, CompactionPhase::Idle),
    ];
    for (from, to) in transitions {
        let at = transition_step(to, &fixture);
        for (op, nth, timing, torn) in [
            (GroupOp::RootWrite, 1, FaultTiming::BeforeEffect, false),
            (GroupOp::RootWrite, 2, FaultTiming::BeforeEffect, false),
            (GroupOp::RootWrite, 1, FaultTiming::AfterEffect, false),
            (GroupOp::RootSync, 1, FaultTiming::BeforeEffect, false),
            (GroupOp::RootSync, 1, FaultTiming::AfterEffect, false),
            (GroupOp::RootSync, 2, FaultTiming::BeforeEffect, false),
            (GroupOp::RootSync, 2, FaultTiming::AfterEffect, false),
            // The first slot write is torn on the medium.
            (GroupOp::RootSync, 1, FaultTiming::BeforeEffect, true),
        ] {
            let case = format!("{from:?}->{to:?} {op:?}/{nth}/{timing:?} torn={torn}");
            let (group, mut state) = fixture();
            state.request_compaction().unwrap();
            for _ in 1..at {
                step(&mut state, ONE);
            }
            assert_eq!(phase(&state), from, "{case}");
            let generation = state.owner.lock().unwrap().generation();
            group.fail(op, nth, timing);
            let result = state.maintenance_step(ONE);
            assert!(result.is_err(), "{case}: {result:?}");
            assert!(state.is_fenced(), "{case}");
            drop(state);
            let restarted = if torn {
                group.crash_torn_root(crate::root::RootSlot::for_generation(generation + 1), 100)
            } else {
                group.crash()
            };
            let mut reopened =
                DiskState::open(Arc::new(restarted), admission.clone(), GROUP, LARGE_CACHE)
                    .unwrap_or_else(|error| panic!("{case}: {error:?}"));
            let reopened_phase = phase(&reopened);
            assert!(
                reopened_phase == from || reopened_phase == to,
                "{case}: {reopened_phase:?}"
            );
            if torn {
                assert_eq!(reopened_phase, from, "{case}");
            }
            let pin = reopened.snapshot().unwrap();
            for key in [0u32, 3, 150, 297] {
                assert_eq!(
                    reopened
                        .get(&pin, "accounts", &key.to_be_bytes(), 48)
                        .unwrap()
                        .unwrap()
                        .as_bytes(),
                    vec![key as u8; 48],
                    "{case}"
                );
            }
            assert_eq!(value(&mut reopened, &pin, &1u32.to_be_bytes()), None);
            drop(pin);
            if reopened_phase != CompactionPhase::Idle {
                drive_cycle(&mut reopened, STEP);
            }
            assert_eq!(phase(&reopened), CompactionPhase::Idle, "{case}");
            assert!(reopened.owner.lock().unwrap().garbage().is_empty());
        }
    }
}

/// Mirrors the installed store's in-transaction enforcement: every create,
/// growth and write must lie inside the reserved plan, and no file effect may
/// happen outside a reserved transaction once armed.
#[derive(Default)]
struct PlanState {
    armed: bool,
    deny: bool,
    plan: Option<TransactionSpacePlan>,
    created: [u64; 2],
    grown: [u64; 2],
    reservations: usize,
    transaction_creates: [usize; 2],
    violations: Vec<String>,
    effects: usize,
}

struct PlanChecked {
    group: InMemoryGroup,
    state: StdMutex<PlanState>,
}

impl PlanChecked {
    fn new(group: InMemoryGroup) -> Arc<Self> {
        Arc::new(Self {
            group,
            state: StdMutex::new(PlanState::default()),
        })
    }

    fn index(file: GroupFile) -> Option<usize> {
        match file.kind {
            FileKind::Segment => Some(0),
            FileKind::Directory => Some(1),
            FileKind::Checkpoint => None,
        }
    }

    fn range(plan: &TransactionSpacePlan, index: usize) -> FileSpaceRange {
        if index == 0 {
            plan.new_segments
        } else {
            plan.new_directories
        }
    }

    fn existing(plan: &TransactionSpacePlan, file: GroupFile) -> Option<ExistingFileSpace> {
        plan.segment
            .into_iter()
            .chain(plan.directory)
            .find(|existing| existing.file == file)
    }

    fn check_extent(&self, file: GroupFile, end: u64) {
        let mut state = self.state.lock().unwrap();
        if !state.armed {
            return;
        }
        state.effects += 1;
        let Some(plan) = state.plan else {
            state
                .violations
                .push(format!("{file:?} grew to {end} outside a reserved transaction"));
            return;
        };
        let Some(index) = Self::index(file) else {
            state.violations.push(format!("{file:?} is not a planned kind"));
            return;
        };
        if let Some(existing) = Self::existing(&plan, file) {
            if end > existing.maximum_len {
                state.violations.push(format!(
                    "{file:?} grew to {end} beyond its planned {}",
                    existing.maximum_len
                ));
            }
            return;
        }
        let range = Self::range(&plan, index);
        let current = self.group.len(file).unwrap_or(0);
        match range.maximum_len(file.id) {
            Some(limit) if file.id - range.first_id < state.created[index] && end <= limit => {
                state.grown[index] += end.saturating_sub(current);
                let grown = state.grown[index];
                if grown > range.total_len {
                    state.violations.push(format!(
                        "new {file:?} growth {grown} exceeds planned total {}",
                        range.total_len
                    ));
                }
            }
            _ => state
                .violations
                .push(format!("{file:?} grew to {end} outside its plan {range:?}")),
        }
    }
}

impl SegmentGroupBackend for PlanChecked {
    fn reserve_transaction(
        &self,
        plan: &TransactionSpacePlan,
    ) -> std::result::Result<(), crate::TransactionReserveError> {
        let mut state = self.state.lock().unwrap();
        if state.deny {
            return Err(crate::TransactionReserveError::CapacityDenied);
        }
        self.group.reserve_transaction(plan)?;
        state.plan = Some(*plan);
        state.created = [0; 2];
        state.grown = [0; 2];
        state.reservations += 1;
        Ok(())
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.group.finish_transaction(group_id, batch_seq)?;
        self.state.lock().unwrap().plan = None;
        Ok(())
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.group.cancel_transaction(group_id, batch_seq)?;
        self.state.lock().unwrap().plan = None;
        Ok(())
    }
    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.group.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.group.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.group.sync_root()
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.group.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.group.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        {
            let mut state = self.state.lock().unwrap();
            if state.armed {
                state.effects += 1;
                match (state.plan, Self::index(file)) {
                    (Some(plan), Some(index)) => {
                        let range = Self::range(&plan, index);
                        if range.first_id + state.created[index] == file.id
                            && state.created[index] < range.count
                        {
                            state.created[index] += 1;
                            state.transaction_creates[index] += 1;
                        } else {
                            state
                                .violations
                                .push(format!("{file:?} created outside {range:?}"));
                        }
                    }
                    _ => state
                        .violations
                        .push(format!("{file:?} created outside a reserved transaction")),
                }
            }
        }
        self.group.create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.group.len(file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.group.read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.check_extent(file, at + bytes.len() as u64);
        self.group.write(file, at, bytes)
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.check_extent(file, length);
        self.group.set_len(file, length)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.group.sync(file)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        let state = self.state.lock().unwrap();
        if state.armed && state.plan.is_some() {
            drop(state);
            self.state
                .lock()
                .unwrap()
                .violations
                .push(format!("{file:?} unlinked inside a transaction"));
        } else {
            drop(state);
        }
        self.group.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.group.sync_names()
    }
    fn close(&self) -> BackendCloseOutcome {
        self.group.close()
    }
}

#[test]
fn maintenance_batch_space_plan_bounds_actual_writes() {
    let checked = PlanChecked::new(InMemoryGroup::new());
    let admission = Admission::new(48 << 20);
    let mut state = create(checked.clone(), admission, LARGE_CACHE);
    // Small files force segment and arena rolls inside maintenance batches.
    state.writer = SegmentWriter::new(GROUP).with_capacity(24 << 10);
    replace_arena(&mut state, Some(3));
    let table = "t".repeat(MAX_TABLE_BYTES);
    let key = |index: u16| {
        let mut key = vec![0x5a; MAX_KEY_BYTES];
        key[..2].copy_from_slice(&index.to_be_bytes());
        key
    };
    state
        .commit(&[Operation::create_table(table.as_str())])
        .unwrap();
    for index in 0..40u16 {
        state
            .commit(&[Operation::put(table.as_str(), key(index), vec![index as u8; 700])])
            .unwrap();
    }
    let deletes: Vec<_> = (0..40u16)
        .filter(|index| index % 4 != 0)
        .map(|index| Operation::delete(table.as_str(), key(index)))
        .collect();
    state.commit(&deletes).unwrap();
    seal_files(&mut state);
    checked.state.lock().unwrap().armed = true;
    let totals = drive_cycle(
        &mut state,
        MaintenanceBudget {
            units: 4,
            mutations: 1,
        },
    );
    // Foreground writes stay inside their own plans too.
    state
        .commit(&[Operation::put(table.as_str(), key(1), vec![9; 700])])
        .unwrap();
    let observed = checked.state.lock().unwrap();
    assert!(observed.violations.is_empty(), "{:#?}", observed.violations);
    assert!(totals.maintenance_commits > 0 && totals.relocated > 0);
    assert!(totals.density_commits > 0, "{totals:?}");
    assert!(
        observed.reservations > totals.maintenance_commits,
        "every maintenance batch and the foreground write reserve"
    );
    assert!(
        observed.transaction_creates[0] > 0 && observed.transaction_creates[1] > 0,
        "fixture must roll both kinds inside reserved batches: {:?}",
        observed.transaction_creates
    );
    assert!(observed.effects > 0);
    drop(observed);
    let pin = state.snapshot().unwrap();
    for index in (0..40u16).step_by(4) {
        assert_eq!(
            state
                .get(&pin, &table, &key(index), 700)
                .unwrap()
                .unwrap()
                .as_bytes(),
            vec![index as u8; 700]
        );
    }
}

#[test]
fn reserve_transaction_capacity_denial_defers_without_effect_or_fence() {
    let group = InMemoryGroup::new();
    let checked = PlanChecked::new(group.clone());
    let admission = Admission::new(16 << 20);
    let mut state = create(checked.clone(), admission, LARGE_CACHE);
    rows(&mut state, 200, 32);
    seal_files(&mut state);
    state.request_compaction().unwrap();
    step(&mut state, ONE);
    assert_eq!(phase(&state), CompactionPhase::Evacuating);
    let generation = state.owner.lock().unwrap().generation();
    let root = state.selected;
    {
        let mut observed = checked.state.lock().unwrap();
        observed.armed = true;
        observed.deny = true;
    }
    let progress = state.maintenance_step(ONE).unwrap();
    assert_eq!(progress.deferred, Some(MaintenanceDeferral::Capacity));
    assert_eq!(progress.mutations, 0);
    assert!(!state.is_fenced());
    assert_eq!(state.owner.lock().unwrap().generation(), generation);
    assert_eq!(state.selected, root);
    assert_eq!(checked.state.lock().unwrap().effects, 0);
    let status = state.maintenance_status().unwrap();
    assert_eq!(status.capacity_deferrals_total, 1);
    assert_eq!(status.last_deferral, Some(MaintenanceDeferral::Capacity));
    // Within the backoff the step does no work at all.
    let skipped = state.maintenance_step(ONE).unwrap();
    assert_eq!((skipped.units, skipped.mutations), (0, 0));
    assert_eq!(skipped.deferred, Some(MaintenanceDeferral::Capacity));
    // A foreground write is refused by the same denial, without fencing.
    assert!(
        state
            .commit(&[Operation::put("accounts", b"x", b"y")])
            .is_err_and(|error| error.is_capacity_denied())
    );
    assert!(!state.is_fenced());
    checked.state.lock().unwrap().deny = false;
    let totals = drive_cycle(&mut state, STEP);
    assert_eq!(totals.relocated, 200 * 32);
    assert_eq!(state.maintenance_status().unwrap().last_deferral, None);
    drop(state);
    let reopened = DiskState::open(
        Arc::new(group.crash()),
        Admission::new(16 << 20),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    assert_eq!(phase(&reopened), CompactionPhase::Idle);
}
