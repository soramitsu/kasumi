use super::*;
use crate::directory::DirectoryCursor;

/// Finish the single density pass after a foreground change: it never
/// restarts, never repeats evacuation, and reaches Idle.
fn finish_density_after_foreground_change(state: &mut DiskState) {
    for _ in 0..20_000 {
        let progress = step(state, ONE);
        assert!(progress.units <= 1);
        assert_eq!(progress.relocated_bytes, 0, "density retried value evacuation");
        assert_eq!(state.compact.stats.entries, 0);
        assert_eq!(state.compact.stats.copied_bytes, 0);
        if phase(state) == CompactionPhase::Idle {
            assert!(progress.phase_changed);
            return;
        }
        assert_eq!(phase(state), CompactionPhase::Packing);
    }
    panic!("density did not finish after the foreground change");
}

#[test]
fn deleting_the_exact_pending_density_row_reselects_its_successor() {
    let admission = Admission::new(12 << 20);
    let mut state = create(
        Arc::new(InMemoryGroup::new()),
        admission.clone(),
        LARGE_CACHE,
    );
    let original = populate_sparse_directory(&mut state, 48);
    evacuate_all(&mut state);

    // Predict each continuation through the public plan boundary. Initial
    // merges retain the table marker; wait for a dense left output whose
    // continuation is a row that the foreground writer can delete.
    let mut lower = None;
    let mut pending = None;
    for _ in 0..48 {
        let key = lower
            .as_ref()
            .map_or(DirectoryKey::table("\0"), DirectoryCursor::key);
        let plan = DirectoryReader::new(state.arena.as_ref(), state.owner.admission.clone())
            .pack_after(state.selected, 0, key)
            .unwrap()
            .unwrap();
        assert!(plan.references().1.is_some());
        let needs_pack = plan.needs_pack();
        let next = plan.into_next().expect("nonterminal pair has a cursor");
        // Copy the exact post-publication key before doing this density step.
        let row = next
            .key()
            .row
            .map(|key| (next.key().table.to_owned(), key.to_vec()));
        step(&mut state, ONE);
        let stats = state.compact.stats;
        assert_eq!(stats.density_pairs, 1);
        assert_eq!(stats.density_commits, usize::from(needs_pack));
        assert_eq!(phase(&state), CompactionPhase::Packing);
        assert_eq!(stats.copied_bytes, 0);
        // The install persisted exactly this continuation as its lower bound.
        if needs_pack {
            let persisted = record(&state);
            assert_eq!(persisted.level(), 0);
            assert_eq!(
                *persisted.cursor(),
                crate::root::CompactionCursor::lower_bound(next.key()).unwrap()
            );
        }
        if row.is_some() {
            pending = row;
            break;
        }
        lower = Some(next);
    }
    drop(lower);
    let (table, pending) = pending.expect("sparse tree reaches a row continuation");
    assert_eq!(table, "accounts");
    let deleted = u16::from_be_bytes(pending[..2].try_into().unwrap());
    assert!(deleted > 0 && deleted < 48 && deleted % 2 == 0);
    assert_eq!(pending, long_key(deleted));

    let before_delete = state.snapshot().unwrap();
    let surviving_version = location(&state, before_delete.root(), &long_key(0)).0;
    assert_eq!(
        value(&mut state, &before_delete, &pending).unwrap(),
        deleted.to_be_bytes()
    );
    state
        .commit(&[Operation::delete(table.as_str(), pending.clone())])
        .unwrap();
    let modified = state.snapshot().unwrap();
    assert_eq!(value(&mut state, &modified, &pending), None);

    finish_density_after_foreground_change(&mut state);
    let current = state.snapshot().unwrap();
    assert_eq!(current.root().entries, modified.root().entries);
    assert_eq!(
        location(&state, current.root(), &long_key(0)).0,
        surviving_version
    );
    for index in 0..48u16 {
        let key = long_key(index);
        assert_eq!(
            value(&mut state, &original, &key).unwrap(),
            index.to_be_bytes()
        );
        assert_eq!(
            value(&mut state, &before_delete, &key),
            (index % 2 == 0).then(|| index.to_be_bytes().to_vec())
        );
        for pin in [&modified, &current] {
            assert_eq!(
                value(&mut state, pin, &key),
                (index % 2 == 0 && index != deleted).then(|| index.to_be_bytes().to_vec())
            );
        }
    }
    drop((original, before_delete, modified, current));
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn foreground_root_collapse_reselects_density_without_repeating_evacuation() {
    let admission = Admission::new(12 << 20);
    let mut state = create(
        Arc::new(InMemoryGroup::new()),
        admission.clone(),
        LARGE_CACHE,
    );
    let original = populate_sparse_directory(&mut state, 48);
    evacuate_all(&mut state);
    step(&mut state, ONE);
    assert_eq!(state.compact.stats.density_commits, 1);
    assert_eq!(phase(&state), CompactionPhase::Packing);
    let before_collapse = state.snapshot().unwrap();
    assert!(before_collapse.root().height >= 3);
    let surviving_version = location(&state, before_collapse.root(), &long_key(0)).0;

    let deletes: Vec<_> = (2..48u16)
        .step_by(2)
        .map(|index| Operation::delete("accounts", long_key(index)))
        .collect();
    state.commit(&deletes).unwrap();
    let collapsed = state.snapshot().unwrap();
    assert_eq!(collapsed.root().height, 1);
    assert_eq!(collapsed.root().entries, 2);
    assert!(collapsed.root().height < before_collapse.root().height);

    finish_density_after_foreground_change(&mut state);
    let current = state.snapshot().unwrap();
    assert_eq!(current.root().height, 1);
    assert_eq!(current.root().entries, 2);
    assert_eq!(
        location(&state, current.root(), &long_key(0)).0,
        surviving_version
    );
    for index in 0..48u16 {
        let key = long_key(index);
        assert_eq!(
            value(&mut state, &original, &key).unwrap(),
            index.to_be_bytes()
        );
        assert_eq!(
            value(&mut state, &before_collapse, &key),
            (index % 2 == 0).then(|| index.to_be_bytes().to_vec())
        );
        for pin in [&collapsed, &current] {
            assert_eq!(
                value(&mut state, pin, &key),
                (index == 0).then(|| index.to_be_bytes().to_vec())
            );
        }
    }
    drop((original, before_collapse, collapsed, current));
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}
