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
fn frozen_worklist_ordinals_finish_across_long_key_churn_and_every_step_reopen() {
    // Includes skip-only evacuation after replacing every original row. Each
    // successful step must persist progress even without a later data commit.
    for replace_originals in [false, true] {
        let admission = Admission::new(32 << 20);
        let mut group = InMemoryGroup::new();
        let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
        let table = "t".repeat(crate::core::MAX_TABLE_BYTES);
        let key = |number: u16| {
            let mut bytes = vec![b'k'; crate::core::MAX_KEY_BYTES];
            bytes[crate::core::MAX_KEY_BYTES - 2..].copy_from_slice(&number.to_be_bytes());
            bytes
        };
        let mut expected = std::collections::BTreeMap::new();
        let mut operations = vec![Operation::create_table(table.as_str())];
        for number in 0..24u16 {
            let bytes = key(number * 2);
            let value = vec![number as u8; 32];
            operations.push(Operation::put(
                table.as_str(),
                bytes.as_slice(),
                value.as_slice(),
            ));
            expected.insert(bytes, value);
        }
        state.commit(&operations).unwrap();
        seal_files(&mut state);
        state.request_compaction().unwrap();
        assert!(step(&mut state, ONE).phase_changed);
        let source = record(&state).evacuation_source().unwrap();
        assert_eq!(source.entries, 25);
        if replace_originals {
            let updates: Vec<_> = expected
                .keys()
                .map(|key| Operation::put(table.as_str(), key.as_slice(), b"new"))
                .collect();
            state.commit(&updates).unwrap();
            expected
                .values_mut()
                .for_each(|value| *value = b"new".to_vec());
        }
        let mut previous = 0;
        for turn in 0..=source.entries {
            // Insert within the original range and append more long keys than
            // a one-unit current-tree scan can consume. The worklist is fixed.
            let mut changes = Vec::new();
            for number in [
                turn as u16 * 2 + 1,
                1000 + turn as u16 * 4,
                1001 + turn as u16 * 4,
                1002 + turn as u16 * 4,
                1003 + turn as u16 * 4,
            ] {
                let bytes = key(number);
                changes.push(Operation::put(table.as_str(), bytes.as_slice(), b"fresh"));
                expected.insert(bytes, b"fresh".to_vec());
            }
            if turn.is_multiple_of(3) {
                let deleted = key(46 - (turn as u16 % 12) * 2);
                changes.push(Operation::delete(table.as_str(), deleted.as_slice()));
                expected.remove(&deleted);
            }
            state.commit(&changes).unwrap();
            step(&mut state, ONE);
            let persisted = record(&state);
            if persisted.phase() == CompactionPhase::Evacuating {
                let next = persisted.cursor().ordinal().unwrap();
                assert!(next > previous && next <= source.entries);
                assert_eq!(persisted.evacuation_source(), Some(source));
                previous = next;
            }
            // No intervening foreground publication can hide volatile-only
            // progress. All keys share a prefix much longer than 1536 bytes.
            drop(state);
            (group, state) = reopen(&group, &admission);
            assert_eq!(record(&state), persisted);
            if phase(&state) != CompactionPhase::Evacuating {
                break;
            }
        }
        assert_eq!(phase(&state), CompactionPhase::Reclaiming);
        assert_eq!(record(&state).evacuation_source(), None);
        drive_cycle(&mut state, STEP);
        let pin = state.snapshot().unwrap();
        for (key, expected) in expected {
            assert_eq!(
                state
                    .get(&pin, &table, &key, 32)
                    .unwrap()
                    .unwrap()
                    .as_bytes(),
                expected
            );
        }
    }
}

#[test]
fn evacuation_cursor_survives_foreground_installs_and_reopen_without_recopy() {
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
        // Foreground installs must preserve the exact durable ordinal,
        // including the progress of a preceding skip-only publication.
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

#[test]
fn skip_only_cursor_publication_faults_reopen_at_old_or_new_ordinal() {
    let admission = Admission::new(8 << 20);
    for (op, nth, timing, torn) in [
        (GroupOp::RootWrite, 1, FaultTiming::BeforeEffect, false),
        (GroupOp::RootWrite, 1, FaultTiming::AfterEffect, false),
        (GroupOp::RootWrite, 2, FaultTiming::BeforeEffect, false),
        (GroupOp::RootWrite, 2, FaultTiming::AfterEffect, false),
        (GroupOp::RootSync, 1, FaultTiming::BeforeEffect, false),
        (GroupOp::RootSync, 1, FaultTiming::AfterEffect, false),
        (GroupOp::RootSync, 2, FaultTiming::BeforeEffect, false),
        (GroupOp::RootSync, 2, FaultTiming::AfterEffect, false),
        (GroupOp::RootSync, 1, FaultTiming::BeforeEffect, true),
    ] {
        let case = format!("{op:?}/{nth}/{timing:?} torn={torn}");
        let group = InMemoryGroup::new();
        let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
        rows(&mut state, 20, 32);
        seal_files(&mut state);
        state.request_compaction().unwrap();
        assert!(step(&mut state, ONE).phase_changed);
        let source = record(&state).evacuation_source().unwrap();
        assert_eq!(source.entries, 21);
        let updates: Vec<_> = (0..20u32)
            .map(|key| Operation::put("accounts", key.to_be_bytes(), b"fresh"))
            .collect();
        state.commit(&updates).unwrap();
        assert_eq!(record(&state).cursor().ordinal(), Some(0));
        let selected = state.selected;
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
        let durable = record(&reopened);
        assert_eq!(durable.phase(), CompactionPhase::Evacuating, "{case}");
        assert_eq!(durable.evacuation_source(), Some(source), "{case}");
        assert_eq!(reopened.selected, selected, "{case}");
        let ordinal = durable.cursor().ordinal().unwrap();
        assert!(
            ordinal == 0 || ordinal == source.entries,
            "{case}: {ordinal}"
        );
        if torn {
            assert_eq!(ordinal, 0, "{case}");
        }
        // A successful retry publishes the skip, or observes the already
        // published ordinal. Neither outcome rewrites or restores old values.
        for _ in 0..2 {
            if phase(&reopened) != CompactionPhase::Evacuating {
                break;
            }
            let progress = step(&mut reopened, ONE);
            assert_eq!(progress.relocated_bytes, 0, "{case}");
            assert_eq!(reopened.compact.stats.maintenance_commits, 0, "{case}");
        }
        assert_eq!(phase(&reopened), CompactionPhase::Reclaiming, "{case}");
        drive_cycle(&mut reopened, STEP);
        let pin = reopened.snapshot().unwrap();
        for key in 0..20u32 {
            assert_eq!(
                value(&mut reopened, &pin, &key.to_be_bytes()).unwrap(),
                b"fresh",
                "{case}"
            );
        }
    }
}

#[test]
fn packing_finishes_across_every_step_reopen_with_long_shared_prefixes() {
    let admission = Admission::new(32 << 20);
    let mut group = InMemoryGroup::new();
    let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
    let table = "t".repeat(crate::core::MAX_TABLE_BYTES);
    let key = |number: u16| {
        let mut key = vec![b'k'; crate::core::MAX_KEY_BYTES];
        key[crate::core::MAX_KEY_BYTES - 2..].copy_from_slice(&number.to_be_bytes());
        key
    };
    let mut operations = vec![Operation::create_table(table.as_str())];
    for number in 0..24u16 {
        operations.push(Operation::put(table.as_str(), key(number), b"old"));
    }
    state.commit(&operations).unwrap();
    seal_files(&mut state);
    state.request_compaction().unwrap();
    for _ in 0..2000 {
        if phase(&state) == CompactionPhase::Packing {
            break;
        }
        step(&mut state, ONE);
    }
    assert_eq!(phase(&state), CompactionPhase::Packing);
    let cap = (state.selected.entries + 64) * u64::from(state.selected.height) + 1;
    let mut saw_skip = false;
    let mut updated = [false; 24];
    for turn in 0..cap {
        // A foreground commit must preserve all of the durable work budget.
        let before = record(&state);
        state
            .commit(&[Operation::put(
                table.as_str(),
                key((turn % 24) as u16),
                b"new",
            )])
            .unwrap();
        updated[(turn % 24) as usize] = true;
        assert_eq!(record(&state), before);
        let progress = step(&mut state, ONE);
        assert_eq!(progress.mutations, 1);
        saw_skip |= state.compact.stats.maintenance_commits == 0 && !progress.phase_changed;
        let persisted = record(&state);
        if persisted.phase() == CompactionPhase::Packing {
            assert!(persisted.level() >= before.level());
            if persisted.level() == before.level() && before.packing_remaining() != 0 {
                assert!(persisted.packing_remaining() < before.packing_remaining());
            }
        }
        drop(state);
        (group, state) = reopen(&group, &admission);
        assert_eq!(record(&state), persisted);
        if phase(&state) == CompactionPhase::Idle {
            break;
        }
    }
    assert_eq!(phase(&state), CompactionPhase::Idle);
    assert!(saw_skip, "fixture must exercise durable skip-only progress");
    let pin = state.snapshot().unwrap();
    for number in 0..24u16 {
        let value = state.get(&pin, &table, &key(number), 3).unwrap().unwrap();
        assert_eq!(
            value.as_bytes(),
            if updated[number as usize] {
                b"new"
            } else {
                b"old"
            }
        );
    }
}

#[test]
fn packing_skip_publication_faults_reopen_at_old_or_new_checkpoint() {
    for (op, nth, timing, torn) in [
        (GroupOp::RootWrite, 1, FaultTiming::BeforeEffect, false),
        (GroupOp::RootWrite, 1, FaultTiming::AfterEffect, false),
        (GroupOp::RootWrite, 2, FaultTiming::BeforeEffect, false),
        (GroupOp::RootWrite, 2, FaultTiming::AfterEffect, false),
        (GroupOp::RootSync, 1, FaultTiming::BeforeEffect, false),
        (GroupOp::RootSync, 1, FaultTiming::AfterEffect, false),
        (GroupOp::RootSync, 2, FaultTiming::BeforeEffect, false),
        (GroupOp::RootSync, 2, FaultTiming::AfterEffect, false),
        (GroupOp::RootSync, 1, FaultTiming::BeforeEffect, true),
    ] {
        let case = format!("{op:?}/{nth}/{timing:?} torn={torn}");
        let admission = Admission::new(8 << 20);
        let group = InMemoryGroup::new();
        let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
        rows(&mut state, 20, 32);
        seal_files(&mut state);
        state.request_compaction().unwrap();
        for _ in 0..2000 {
            if phase(&state) == CompactionPhase::Packing {
                break;
            }
            step(&mut state, ONE);
        }
        assert_eq!(phase(&state), CompactionPhase::Packing);
        assert_eq!(state.selected.height, 1);
        let before = record(&state);
        let selected = state.selected;
        let generation = state.owner.lock().unwrap().generation();
        group.fail(op, nth, timing);
        assert!(state.maintenance_step(ONE).is_err(), "{case}");
        assert!(state.is_fenced(), "{case}");
        drop(state);
        let restarted = if torn {
            group.crash_torn_root(crate::root::RootSlot::for_generation(generation + 1), 100)
        } else {
            group.crash()
        };
        let mut state =
            DiskState::open(Arc::new(restarted), admission, GROUP, LARGE_CACHE).unwrap();
        assert_eq!(state.selected, selected, "{case}");
        let after = record(&state);
        assert_eq!(after.phase(), CompactionPhase::Packing, "{case}");
        assert!(
            after == before
                || (after.level() == 1
                    && after.packing_remaining() == 0
                    && after.cursor().is_none()),
            "{case}"
        );
        if torn {
            assert_eq!(after, before, "{case}");
        }
        drive_cycle(&mut state, STEP);
        let pin = state.snapshot().unwrap();
        for key in 0..20u32 {
            assert_eq!(
                state
                    .get(&pin, "accounts", &key.to_be_bytes(), 32)
                    .unwrap()
                    .unwrap()
                    .as_bytes(),
                vec![key as u8; 32],
                "{case}"
            );
        }
    }
}

/// The step index (1-based, `ONE` budget) at which `target` is entered.
fn transition_step(
    target: CompactionPhase,
    fixture: &dyn Fn() -> (InMemoryGroup, DiskState),
) -> usize {
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
            state.violations.push(format!(
                "{file:?} grew to {end} outside a reserved transaction"
            ));
            return;
        };
        let Some(index) = Self::index(file) else {
            state
                .violations
                .push(format!("{file:?} is not a planned kind"));
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
            .commit(&[Operation::put(
                table.as_str(),
                key(index),
                vec![index as u8; 700],
            )])
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
