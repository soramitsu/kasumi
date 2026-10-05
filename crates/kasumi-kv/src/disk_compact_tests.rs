use super::*;
use crate::directory::DirectoryWalker;

mod density_edges {
    include!("disk_density_tests.rs");
}

fn compact_all(state: &mut DiskState) -> (usize, u64) {
    let mut reclaimed = 0;
    let mut copied = 0;
    for _ in 0..20_000 {
        let progress = state.compact_step(3).unwrap();
        assert!(progress.work <= 3);
        reclaimed += progress.reclaimed;
        copied += progress.copied_bytes;
        if progress.complete {
            return (reclaimed, copied);
        }
    }
    panic!("compaction did not finish");
}

fn location(state: &DiskState, root: DirectoryRoot, key: &[u8]) -> (u64, ValueLocation) {
    let Some(DirectoryValue::Row { batch_seq, value }) =
        DirectoryReader::new(state.arena.as_ref(), state.owner.admission.clone())
            .get(root, DirectoryKey::row("accounts", key))
            .unwrap()
    else {
        panic!("missing row");
    };
    (batch_seq, value)
}

fn reachable_pages(state: &DiskState, root: DirectoryRoot) -> usize {
    let mut walker = DirectoryWalker::new(root, state.owner.admission.clone()).unwrap();
    let mut pages = 0;
    loop {
        let progress = walker
            .step(
                state.arena.as_ref(),
                64,
                |_| {
                    pages += 1;
                    Ok(())
                },
                |_| Ok(()),
            )
            .unwrap();
        if progress.complete {
            return pages;
        }
    }
}

fn long_key(index: u16) -> Vec<u8> {
    let mut key = vec![0; MAX_KEY_BYTES];
    key[..2].copy_from_slice(&index.to_be_bytes());
    key
}

fn populate_sparse_directory(state: &mut DiskState, count: u16) -> SnapshotPin {
    let mut operations = vec![Operation::create_table("accounts")];
    for index in 0..count {
        operations.push(Operation::put(
            "accounts",
            long_key(index),
            index.to_be_bytes(),
        ));
    }
    state.commit(&operations).unwrap();
    let original = state.snapshot().unwrap();
    let deletes: Vec<_> = (0..count)
        .filter(|index| index % 2 != 0)
        .map(|index| Operation::delete("accounts", long_key(index)))
        .collect();
    state.commit(&deletes).unwrap();
    original
}

fn evacuate_all(state: &mut DiskState) {
    for _ in 0..20000 {
        let progress = state.compact_step(1).unwrap();
        assert_eq!(progress.density_commits, 0);
        if progress.evacuated {
            return;
        }
    }
    panic!("evacuation did not finish");
}

#[test]
fn density_packs_sparse_internal_levels_and_preserves_pinned_versions() {
    let admission = Admission::new(12 << 20);
    let group = InMemoryGroup::new();
    let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
    let original = populate_sparse_directory(&mut state, 48);
    let sparse = state.snapshot().unwrap();
    assert!(sparse.root().height >= 3);
    let sparse_pages = reachable_pages(&state, sparse.root());
    let version = location(&state, sparse.root(), &long_key(0)).0;
    let mut commits = 0;
    let mut complete = false;
    for _ in 0..20000 {
        let progress = state.compact_step(2).unwrap();
        commits += progress.density_commits;
        if progress.complete {
            assert!(progress.density_complete);
            complete = true;
            break;
        }
    }
    assert!(complete);
    assert!(commits > 0);
    let current = state.snapshot().unwrap();
    let packed_pages = reachable_pages(&state, current.root());
    assert!(packed_pages < sparse_pages);
    assert_eq!(current.root().entries, sparse.root().entries);
    assert_eq!(location(&state, current.root(), &long_key(0)).0, version);
    for index in 0..48u16 {
        let key = long_key(index);
        assert_eq!(
            value(&mut state, &original, &key).unwrap(),
            index.to_be_bytes()
        );
        for pin in [&sparse, &current] {
            let found = value(&mut state, pin, &key);
            assert_eq!(
                found,
                (index % 2 == 0).then(|| index.to_be_bytes().to_vec())
            );
        }
    }
    let final_root = current.root();
    drop(original);
    drop(sparse);
    drop(current);
    compact_all(&mut state);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
    let mut reopened = DiskState::open(
        Arc::new(group.crash()),
        admission.clone(),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    assert_eq!(reopened.selected, final_root);
    let root = reopened.snapshot().unwrap();
    assert_eq!(
        value(&mut reopened, &root, &long_key(46)).unwrap(),
        46u16.to_be_bytes()
    );
    assert_eq!(value(&mut reopened, &root, &long_key(47)), None);
    drop(root);
    drop(reopened);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn foreground_changes_restart_only_density_before_a_clean_completion() {
    let admission = Admission::new(12 << 20);
    let mut state = create(
        Arc::new(InMemoryGroup::new()),
        admission.clone(),
        LARGE_CACHE,
    );
    let original = populate_sparse_directory(&mut state, 24);
    evacuate_all(&mut state);
    let first = state.compact_step(1).unwrap();
    assert_eq!(first.density_commits, 1);
    assert!(!first.density_complete);
    state
        .commit(&[
            Operation::put("accounts", long_key(0), b"changed"),
            Operation::delete("accounts", long_key(2)),
            Operation::put("accounts", long_key(1), b"inserted"),
        ])
        .unwrap();
    let modified = state.snapshot().unwrap();
    let version = location(&state, modified.root(), &long_key(0)).0;
    let mut restarts = 0;
    let mut complete = false;
    for _ in 0..20000 {
        let progress = state.compact_step(1).unwrap();
        assert!(progress.evacuated);
        assert_eq!(progress.copied_bytes, 0, "density retried value evacuation");
        restarts += progress.density_restarts;
        if progress.complete {
            assert!(progress.density_complete);
            complete = true;
            break;
        }
    }
    assert!(complete);
    assert_eq!(restarts, 1);
    let current = state.snapshot().unwrap();
    for pin in [&modified, &current] {
        assert_eq!(value(&mut state, pin, &long_key(0)).unwrap(), b"changed");
        assert_eq!(value(&mut state, pin, &long_key(1)).unwrap(), b"inserted");
        assert_eq!(value(&mut state, pin, &long_key(2)), None);
    }
    assert_eq!(
        value(&mut state, &original, &long_key(0)).unwrap(),
        0u16.to_be_bytes()
    );
    assert_eq!(
        value(&mut state, &original, &long_key(2)).unwrap(),
        2u16.to_be_bytes()
    );
    assert_eq!(location(&state, current.root(), &long_key(0)).0, version);
    drop(original);
    drop(modified);
    drop(current);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn density_publication_effect_failures_reopen_at_an_unchanged_logical_snapshot() {
    for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
        for operation in [
            GroupOp::Write,
            GroupOp::Sync,
            GroupOp::RootWrite,
            GroupOp::RootSync,
        ] {
            let mut failures = 0;
            let mut exhausted = false;
            for nth in 1..=32 {
                let group = InMemoryGroup::new();
                let admission = Admission::new(12 << 20);
                let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
                drop(populate_sparse_directory(&mut state, 12));
                evacuate_all(&mut state);
                let expected: Vec<_> = (0..12u16)
                    .step_by(2)
                    .map(|index| (index, location(&state, state.selected, &long_key(index))))
                    .collect();
                group.fail(operation, nth, timing);
                let result = state.compact_step(1);
                match &result {
                    Ok(progress) => {
                        assert_eq!(progress.density_commits, 1);
                        exhausted = true;
                    }
                    Err(_) => {
                        failures += 1;
                        assert!(
                            state.is_fenced(),
                            "{operation:?} {timing:?} {nth}: {result:?}"
                        );
                    }
                }
                drop(state);
                assert_eq!(admission.used.load(Ordering::Acquire), 0);
                let mut reopened = DiskState::open(
                    Arc::new(group.crash()),
                    admission.clone(),
                    GROUP,
                    LARGE_CACHE,
                )
                .unwrap_or_else(|error| {
                    panic!("{operation:?} {timing:?} {nth}: {error:?}; density {result:?}")
                });
                let current = reopened.snapshot().unwrap();
                for (index, physical) in expected {
                    let key = long_key(index);
                    assert_eq!(location(&reopened, current.root(), &key), physical);
                    assert_eq!(
                        value(&mut reopened, &current, &key).unwrap(),
                        index.to_be_bytes()
                    );
                    assert_eq!(value(&mut reopened, &current, &long_key(index + 1)), None);
                }
                drop(current);
                drop(reopened);
                assert_eq!(admission.used.load(Ordering::Acquire), 0);
                if exhausted {
                    break;
                }
            }
            assert!(failures > 0, "unexercised {operation:?} {timing:?}");
            assert!(
                exhausted,
                "fault matrix did not reach all {operation:?} {timing:?} effects"
            );
        }
    }
}

#[test]
fn density_admission_denial_keeps_the_cursor_retryable_and_releases_workspace() {
    // Discover every actual request in the successful production path. Deny
    // each position independently, including optional cache retention; the
    // complete request set must be hit without fencing or losing the cursor.
    // Warming runs after durable publication and may refuse its workspace too.
    let admission = Admission::new(12 << 20);
    let mut baseline = create(
        Arc::new(InMemoryGroup::new()),
        admission.clone(),
        LARGE_CACHE,
    );
    drop(populate_sparse_directory(&mut baseline, 12));
    evacuate_all(&mut baseline);
    let calls = admission.calls.load(Ordering::Acquire);
    assert_eq!(baseline.compact_step(1).unwrap().density_commits, 1);
    let requests = admission.calls.load(Ordering::Acquire) - calls;
    assert!(requests > 0);
    drop(baseline);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);

    let mut denials = 0;
    for nth in 1..=requests {
        let admission = Admission::new(12 << 20);
        let mut state = create(
            Arc::new(InMemoryGroup::new()),
            admission.clone(),
            LARGE_CACHE,
        );
        drop(populate_sparse_directory(&mut state, 12));
        evacuate_all(&mut state);
        let generation = state.selected.generation;
        let physical = location(&state, state.selected, &long_key(0));
        admission.deny_nth(nth);
        match state.compact_step(1) {
            Err(error) if error.is_capacity_denied() => {
                denials += 1;
                assert!(!state.is_fenced(), "reservation {nth}");
                assert_eq!(state.selected.generation, generation, "reservation {nth}");
            }
            Ok(progress) => assert_eq!(progress.density_commits, 1),
            Err(error) => panic!("reservation {nth}: {error}"),
        }
        assert_eq!(
            admission.refused_calls.load(Ordering::Acquire),
            1,
            "request {nth} was not actually refused"
        );
        admission.deny_at.store(usize::MAX, Ordering::Release);
        assert_eq!(compact_all(&mut state).1, 0, "retry repeated evacuation");
        let current = state.snapshot().unwrap();
        assert_eq!(location(&state, current.root(), &long_key(0)), physical);
        assert_eq!(
            value(&mut state, &current, &long_key(0)).unwrap(),
            0u16.to_be_bytes()
        );
        drop(current);
        drop(state);
        assert_eq!(
            admission.used.load(Ordering::Acquire),
            0,
            "reservation {nth}"
        );
    }
    assert!(denials > 0, "preparation refusals must reach the caller");
    assert!(
        denials < requests,
        "optional postcommit warming must remain retryable"
    );
}

#[test]
fn density_with_long_keys_and_large_disk_values_fits_fixed_native_workspace() {
    // The caller inputs and disk stand-in are outside this native ledger.
    // Twelve MiB of values exceed the three MiB storage workspace allowance.
    let group = InMemoryGroup::new();
    let admission = Admission::new(3 << 20);
    let config = CacheConfig { byte_limit: 0 };
    let mut state = create(Arc::new(group.clone()), admission.clone(), config);
    let size = 1 << 20;
    let mut operations = vec![Operation::create_table("accounts")];
    for index in 0..12u16 {
        operations.push(Operation::put(
            "accounts",
            long_key(index),
            vec![index as u8; size],
        ));
    }
    state.commit(&operations).unwrap();
    drop(operations);
    let old = state.snapshot().unwrap();
    let deletes: Vec<_> = (1..12u16)
        .step_by(2)
        .map(|index| Operation::delete("accounts", long_key(index)))
        .collect();
    state.commit(&deletes).unwrap();
    drop(deletes);
    let mut density_commits = 0;
    let mut complete = false;
    for _ in 0..20000 {
        let progress = state.compact_step(2).unwrap();
        density_commits += progress.density_commits;
        if progress.complete {
            complete = true;
            break;
        }
    }
    assert!(complete);
    assert!(density_commits > 0);
    let current = state.snapshot().unwrap();
    for (pin, index) in [(&old, 1u16), (&current, 10)] {
        let output = state
            .get(pin, "accounts", &long_key(index), size)
            .unwrap()
            .unwrap();
        assert_eq!(output.as_bytes().len(), size);
        assert!(output.as_bytes().iter().all(|&byte| byte == index as u8));
    }
    assert!(admission.peak.load(Ordering::Acquire) <= 3 << 20);
    drop(old);
    drop(current);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
    let reopened =
        DiskState::open(Arc::new(group.crash()), admission.clone(), GROUP, config).unwrap();
    assert_eq!(reopened.selected.entries, 7);
    drop(reopened);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn compaction_preserves_versions_pins_and_fitting_hot_values_through_reclamation() {
    let group = InMemoryGroup::new();
    let reads = Reads::new(group.clone());
    let admission = Admission::new(8 << 20);
    let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", b"one"),
            Operation::put("accounts", b"b", b"two"),
        ])
        .unwrap();
    let old = state.snapshot().unwrap();
    let (version, old_location) = location(&state, old.root(), b"a");
    let output = state.get(&old, "accounts", b"a", 99).unwrap().unwrap();
    let old_arena = old.root().page.unwrap().arena_id;
    assert_eq!(compact_all(&mut state).1, 6);
    let current = state.snapshot().unwrap();
    let (new_version, new_location) = location(&state, current.root(), b"a");
    assert_eq!(new_version, version);
    assert!(new_location.segment_id > old_location.segment_id);
    assert!(current.root().page.unwrap().arena_id > old_arena);
    assert!(group.exists(GroupFile::directory(old_arena)).unwrap());
    assert!(
        group
            .exists(GroupFile::segment(old_location.segment_id))
            .unwrap()
    );
    let before = reads.count();
    for root in [&old, &current] {
        assert_eq!(value(&mut state, root, b"a").unwrap(), b"one");
        assert_eq!(value(&mut state, root, b"b").unwrap(), b"two");
    }
    assert_eq!(
        reads.count(),
        before,
        "fitting versions lost cache residency"
    );
    drop(old);
    assert!(compact_all(&mut state).0 >= 2);
    assert!(!group.exists(GroupFile::directory(old_arena)).unwrap());
    assert!(
        !group
            .exists(GroupFile::segment(old_location.segment_id))
            .unwrap()
    );
    assert_eq!(output.as_bytes(), b"one");
    let before = reads.count();
    assert_eq!(value(&mut state, &current, b"a").unwrap(), b"one");
    assert_eq!(reads.count(), before);
    drop(current);
    drop(state);
    assert!(admission.used.load(Ordering::Acquire) > 0);
    drop(output);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
    let mut reopened =
        DiskState::open(Arc::new(group.crash()), admission, GROUP, LARGE_CACHE).unwrap();
    let root = reopened.snapshot().unwrap();
    assert_eq!(value(&mut reopened, &root, b"b").unwrap(), b"two");
}

#[test]
fn relocated_snapshot_aliases_keep_one_fitting_payload_resident() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(8 << 20);
    let config = CacheConfig {
        byte_limit: 700 << 10,
    };
    let size = 512 << 10;
    // Both snapshot identities and their directory pages fit, but two
    // independent copies of this immutable value cannot fit in the cache.
    assert!(2 * size as u64 > config.byte_limit);
    let mut state = create(reads.clone(), admission.clone(), config);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"shared", vec![37; size]),
        ])
        .unwrap();
    let old = state.snapshot().unwrap();
    let original = state
        .get(&old, "accounts", b"shared", size)
        .unwrap()
        .unwrap();
    assert_eq!(compact_all(&mut state).1, size as u64);
    let current = state.snapshot().unwrap();
    let before = reads.count();
    let previous = state
        .get(&old, "accounts", b"shared", size)
        .unwrap()
        .unwrap();
    let relocated = state
        .get(&current, "accounts", b"shared", size)
        .unwrap()
        .unwrap();
    assert!(CachedBytes::ptr_eq(&original, &previous));
    assert!(CachedBytes::ptr_eq(&original, &relocated));
    assert_eq!(
        reads.count(),
        before,
        "fitting snapshot lookup went to disk"
    );
    let stats = state.cache_stats().unwrap();
    assert_eq!(stats.evictions, 0);
    assert_eq!(stats.pinned_bytes, 0);
    assert!(stats.resident_bytes <= config.byte_limit);
    drop(previous);
    drop(old);
    assert!(compact_all(&mut state).0 >= 2);
    assert_eq!(state.cache_stats().unwrap().pinned_bytes, 0);
    let before = reads.count();
    let surviving = state
        .get(&current, "accounts", b"shared", size)
        .unwrap()
        .unwrap();
    assert!(CachedBytes::ptr_eq(&original, &surviving));
    assert_eq!(reads.count(), before);
    drop(surviving);
    drop(current);
    drop(state);
    assert!(admission.used.load(Ordering::Acquire) > 0);
    assert!(original.as_bytes().iter().all(|&byte| byte == 37));
    drop(original);
    drop(relocated);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn foreground_changes_around_compaction_cursor_never_reintroduce_old_files() {
    let admission = Admission::new(8 << 20);
    let mut state = create(
        Arc::new(InMemoryGroup::new()),
        admission.clone(),
        LARGE_CACHE,
    );
    let mut ops = vec![Operation::create_table("accounts")];
    for key in 500..1000u16 {
        ops.push(Operation::put(
            "accounts",
            key.to_be_bytes(),
            key.to_be_bytes(),
        ));
    }
    state.commit(&ops).unwrap();
    let old = state.snapshot().unwrap();
    let cutoff_segment = state.owner.bounds().unwrap().last_segment_id;
    let cutoff_arena = state.owner.lock().unwrap().last_directory_id();
    let first = state.compact_step(3).unwrap();
    assert!(first.entries > 2 && first.entries < 500);
    assert_eq!(first.maintenance_commits, 1);
    state
        .commit(&[
            Operation::put("accounts", 0u16.to_be_bytes(), 90u16.to_be_bytes()),
            Operation::put("accounts", 501u16.to_be_bytes(), 91u16.to_be_bytes()),
            Operation::put("accounts", 998u16.to_be_bytes(), 95u16.to_be_bytes()),
            Operation::delete("accounts", 997u16.to_be_bytes()),
        ])
        .unwrap();
    compact_all(&mut state);
    let current = state.snapshot().unwrap();
    for (key, expected) in [(0u16, 90u16), (501, 91), (998, 95), (999, 999)] {
        assert_eq!(
            value(&mut state, &current, &key.to_be_bytes()).unwrap(),
            expected.to_be_bytes()
        );
    }
    assert_eq!(value(&mut state, &current, &997u16.to_be_bytes()), None);
    assert_eq!(
        value(&mut state, &old, &501u16.to_be_bytes()).unwrap(),
        501u16.to_be_bytes()
    );
    assert_eq!(
        value(&mut state, &old, &997u16.to_be_bytes()).unwrap(),
        997u16.to_be_bytes()
    );
    let mut walker = DirectoryWalker::new(current.root(), admission.clone()).unwrap();
    loop {
        let progress = walker
            .step(
                state.arena.as_ref(),
                2,
                |page| {
                    assert!(page.arena_id > cutoff_arena);
                    Ok(())
                },
                |value| {
                    assert!(value.segment_id > cutoff_segment);
                    Ok(())
                },
            )
            .unwrap();
        if progress.complete {
            break;
        }
    }
    drop(walker);
    drop(old);
    drop(current);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn relocation_and_unknown_publication_recover_a_value_larger_than_native_workspace() {
    let group = InMemoryGroup::new();
    let admission = Admission::new(64 << 20);
    let config = CacheConfig { byte_limit: 0 };
    let mut state = create(Arc::new(group.clone()), admission.clone(), config);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"large", vec![73; 6 << 20]),
        ])
        .unwrap();
    let original = location(&state, state.selected, b"large");
    admission.limit.store(3 << 20, Ordering::Release);
    admission
        .peak
        .store(admission.used.load(Ordering::Acquire), Ordering::Release);
    assert_eq!(state.compact_step(2).unwrap().entries, 0);
    group.fail(GroupOp::RootWrite, 1, FaultTiming::BeforeEffect);
    let result = state.compact_step(1);
    assert!(
        matches!(&(result), Err(native_error) if native_error.is_unknown_commit()),
        "{result:?}"
    );
    assert!(state.is_fenced());
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
    let reopened =
        DiskState::open(Arc::new(group.crash()), admission.clone(), GROUP, config).unwrap();
    let relocated = location(&reopened, reopened.selected, b"large");
    assert_eq!(relocated.0, original.0);
    assert!(relocated.1.segment_id > original.1.segment_id);
    assert_eq!(relocated.1.len, original.1.len);
    assert_eq!(relocated.1.crc, original.1.crc);
    let mut buffer = [0; 4096];
    for offset in (0..relocated.1.len as u64).step_by(buffer.len()) {
        reopened
            .owner
            .backend
            .read(
                GroupFile::segment(relocated.1.segment_id),
                relocated.1.offset + offset,
                &mut buffer,
            )
            .unwrap();
        assert!(buffer.iter().all(|byte| *byte == 73));
    }
    assert!(admission.peak.load(Ordering::Acquire) <= 3 << 20);
    drop(reopened);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn compaction_effect_failures_reopen_without_changing_logical_values() {
    for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
        for op in [
            GroupOp::Create,
            GroupOp::Write,
            GroupOp::Sync,
            GroupOp::SyncNames,
            GroupOp::RootWrite,
            GroupOp::RootSync,
            GroupOp::Unlink,
        ] {
            for nth in 1..=96 {
                let group = InMemoryGroup::new();
                let admission = Admission::new(8 << 20);
                let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
                state
                    .commit(&[
                        Operation::create_table("accounts"),
                        Operation::put("accounts", b"a", b"unchanged"),
                        Operation::put("accounts", b"b", b"second"),
                        Operation::put("accounts", b"c", b"third"),
                    ])
                    .unwrap();
                let version = location(&state, state.selected, b"a").0;
                group.fail(op, nth, timing);
                let result: Result<(), CoreError> = (|| {
                    for _ in 0..1000 {
                        if state.compact_step(4)?.complete {
                            return Ok(());
                        }
                    }
                    panic!("compaction did not finish");
                })();
                if result.is_err() {
                    assert!(state.is_fenced(), "{op:?} {timing:?} {nth}: {result:?}");
                }
                drop(state);
                let mut reopened =
                    DiskState::open(Arc::new(group.crash()), admission, GROUP, LARGE_CACHE)
                        .unwrap_or_else(|error| {
                            panic!("{op:?} {timing:?} {nth}: {error:?}; compact {result:?}")
                        });
                let root = reopened.snapshot().unwrap();
                assert_eq!(value(&mut reopened, &root, b"a").unwrap(), b"unchanged");
                assert_eq!(location(&reopened, root.root(), b"a").0, version);
                for (key, expected) in [(b"b", b"second".as_slice()), (b"c", b"third".as_slice())] {
                    assert_eq!(value(&mut reopened, &root, key).unwrap(), expected);
                    assert_eq!(location(&reopened, root.root(), key).0, version);
                }
                if result.is_ok() {
                    break;
                }
                assert!(nth < 96, "unbounded maintenance effects");
            }
        }
    }
}

#[test]
fn compaction_admission_denial_is_retryable_without_skipping_a_key() {
    let mut denials = 0;
    for nth in 1..=32 {
        let admission = Admission::new(8 << 20);
        let mut state = create(
            Arc::new(InMemoryGroup::new()),
            admission.clone(),
            LARGE_CACHE,
        );
        state
            .commit(&[
                Operation::create_table("accounts"),
                Operation::put("accounts", b"a", b"bytes"),
            ])
            .unwrap();
        state.compact_step(2).unwrap();
        let generation = state.selected.generation;
        admission.deny_nth(nth);
        let result = state.compact_step(1);
        let copied = match result {
            Err(error) if error.is_capacity_denied() => {
                denials += 1;
                assert!(!state.is_fenced(), "reservation {nth}");
                assert_eq!(state.selected.generation, generation, "reservation {nth}");
                0
            }
            Ok(progress) => progress.copied_bytes,
            Err(error) => panic!("reservation {nth}: {error}"),
        };
        // A denial beyond this operation must not arm a later unrelated step.
        admission.deny_at.store(usize::MAX, Ordering::Release);
        assert_eq!(copied + compact_all(&mut state).1, 5, "reservation {nth}");
        let current = state.snapshot().unwrap();
        assert_eq!(value(&mut state, &current, b"a").unwrap(), b"bytes");
        drop(current);
        drop(state);
        assert_eq!(
            admission.used.load(Ordering::Acquire),
            0,
            "reservation {nth}"
        );
    }
    assert!(
        denials > 5,
        "did not cover private directory construction denials"
    );
}

#[test]
fn evacuation_batches_write_one_path_per_leaf_and_density_packs_the_result() {
    let admission = Admission::new(8 << 20);
    let mut state = create(
        Arc::new(InMemoryGroup::new()),
        admission.clone(),
        LARGE_CACHE,
    );
    let mut operations = vec![Operation::create_table("accounts")];
    for key in 0..1200u32 {
        operations.push(Operation::put(
            "accounts",
            key.to_be_bytes(),
            key.to_be_bytes(),
        ));
    }
    state.commit(&operations).unwrap();
    drop(operations);
    let old = state.snapshot().unwrap();
    let root = old.root();
    assert!(root.height >= 2);
    let reader = DirectoryReader::new(state.arena.as_ref(), admission.clone());
    let mut after: Option<DirectoryRecord> = None;
    let mut leaves = 0;
    loop {
        let (lower, exclusive) = after
            .as_ref()
            .map_or((DirectoryKey::table("\0"), false), |record| {
                (record.key(), true)
            });
        let Some(leaf) = reader.leaf_after(root, lower, exclusive).unwrap() else {
            break;
        };
        after = Some(leaf.owned_record(leaf.len() - 1).unwrap());
        leaves += 1;
    }
    drop(after);
    let old_pages = reachable_pages(&state, root);
    let before = state.arena.stats().unwrap();
    let mut commits = 0;
    let mut pages = 0;
    let mut entries = 0;
    let mut copied = 0;
    let mut complete = false;
    for _ in 0..10000 {
        let progress = state.compact_step(1).unwrap();
        assert!(progress.work <= 1);
        commits += progress.maintenance_commits;
        pages += progress.directory_pages_written;
        entries += progress.entries;
        copied += progress.copied_bytes;
        assert_eq!(progress.density_commits, 0);
        if progress.evacuated {
            complete = true;
            break;
        }
    }
    assert!(complete, "bounded evacuation did not finish");
    let after = state.arena.stats().unwrap();
    eprintln!(
        "evacuation_leaf_batch rows=1200 height={} leaves={} commits={} directory_pages_written={} prior_per_record_path_pages={} copied_value_bytes={}",
        root.height,
        leaves,
        commits,
        pages,
        1201 * u64::from(root.height),
        copied,
    );
    assert_eq!(commits, leaves);
    assert_eq!(pages, leaves as u64 * u64::from(root.height));
    assert_eq!(pages, after.pages_written - before.pages_written);
    assert!(
        commits < 1200 / 50,
        "one publication per row survived batching"
    );
    assert_eq!(entries, 1201);
    assert_eq!(copied, 1200 * 4);
    let before_density = state.arena.stats().unwrap();
    let mut density_commits = 0;
    let mut density_complete = false;
    for _ in 0..20000 {
        let progress = state.compact_step(3).unwrap();
        assert!(progress.evacuated);
        assert_eq!(progress.copied_bytes, 0);
        density_commits += progress.density_commits;
        if progress.complete {
            assert!(progress.density_complete);
            density_complete = true;
            break;
        }
    }
    assert!(density_complete);
    assert!(density_commits > 0);
    let after_density = state.arena.stats().unwrap();
    let packed_pages = reachable_pages(&state, state.selected);
    assert!(packed_pages < old_pages);
    eprintln!(
        "density rows=1200 old_live_pages={} new_live_pages={} commits={} directory_pages_written={}",
        old_pages,
        packed_pages,
        density_commits,
        after_density.pages_written - before_density.pages_written,
    );
    let current = state.snapshot().unwrap();
    for key in [0u32, 119, 501, 1199] {
        for snapshot in [&old, &current] {
            assert_eq!(
                value(&mut state, snapshot, &key.to_be_bytes()).unwrap(),
                key.to_be_bytes()
            );
        }
    }
    drop(old);
    drop(current);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn value_byte_target_splits_one_leaf_and_foreground_changes_keep_the_cursor_sound() {
    let admission = Admission::new(16 << 20);
    let mut state = create(
        Arc::new(InMemoryGroup::new()),
        admission.clone(),
        CacheConfig {
            byte_limit: 48 << 10,
        },
    );
    let size = 600 << 10;
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", vec![1; size]),
            Operation::put("accounts", b"b", vec![2; size]),
            Operation::put("accounts", b"c", vec![3; size]),
        ])
        .unwrap();
    let old = state.snapshot().unwrap();
    state.compact_step(2).unwrap();
    let first = state.compact_step(1).unwrap();
    assert_eq!(first.copied_bytes, size as u64);
    assert_eq!(first.entries, 2); // table marker and first row
    assert_eq!(first.maintenance_commits, 1);
    state
        .commit(&[
            Operation::put("accounts", b"a", b"new-a"),
            Operation::put("accounts", b"b", b"new-b"),
            Operation::put("accounts", b"aa", b"new-aa"),
        ])
        .unwrap();
    assert_eq!(compact_all(&mut state).1, size as u64); // only c still has an old address
    let current = state.snapshot().unwrap();
    for (key, expected) in [
        (b"a".as_slice(), b"new-a".as_slice()),
        (b"aa", b"new-aa"),
        (b"b", b"new-b"),
    ] {
        assert_eq!(value(&mut state, &current, key).unwrap(), expected);
    }
    for (key, byte) in [(b"a", 1), (b"b", 2), (b"c", 3)] {
        let bytes = state.get(&old, "accounts", key, size).unwrap().unwrap();
        assert_eq!(bytes.as_bytes().len(), size);
        assert!(bytes.as_bytes().iter().all(|found| *found == byte));
    }
    assert!(state.cache_stats().unwrap().resident_bytes <= 48 << 10);
}

#[test]
fn a_fresh_leaf_with_no_old_locations_is_skipped_without_a_commit() {
    let admission = Admission::new(8 << 20);
    let mut state = create(Arc::new(InMemoryGroup::new()), admission, LARGE_CACHE);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", b"old"),
        ])
        .unwrap();
    state.compact_step(2).unwrap();
    state
        .commit(&[Operation::put("accounts", b"a", b"new")])
        .unwrap();
    let root = state.selected;
    let progress = state.compact_step(1).unwrap();
    assert_eq!(progress.skipped_leaves, 1);
    assert_eq!(progress.entries, 2);
    assert_eq!(progress.maintenance_commits, 0);
    assert_eq!(progress.copied_bytes, 0);
    assert_eq!(progress.directory_pages_written, 0);
    assert_eq!(state.selected, root);
    compact_all(&mut state);
    let pin = state.snapshot().unwrap();
    assert_eq!(value(&mut state, &pin, b"a").unwrap(), b"new");
}

#[test]
fn table_only_leaf_uses_one_directory_marker_and_preserves_birth_versions() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(8 << 20);
    let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::create_table("empty"),
        ])
        .unwrap();
    let old = state.snapshot().unwrap();
    state.compact_step(2).unwrap();
    let progress = state.compact_step(1).unwrap();
    assert_eq!(progress.entries, 2);
    assert_eq!(progress.maintenance_commits, 1);
    assert_eq!(progress.directory_pages_written, 1);
    assert_eq!(progress.copied_bytes, 0);
    let current = state.snapshot().unwrap();
    let reader = DirectoryReader::new(state.arena.as_ref(), admission);
    for table in ["accounts", "empty"] {
        assert_eq!(
            reader.get(old.root(), DirectoryKey::table(table)).unwrap(),
            reader
                .get(current.root(), DirectoryKey::table(table))
                .unwrap()
        );
    }
    let before = reads.count();
    for pin in [&old, &current] {
        for table in ["accounts", "empty"] {
            assert!(state.table_exists(pin, table).unwrap());
        }
    }
    assert_eq!(reads.count(), before);
}

#[test]
fn regular_large_write_and_leaf_relocation_fit_fixed_native_workspace() {
    // Caller input and this disk stand-in are outside the native admission
    // ledger; this verifies storage workspace, not total process RSS.
    let group = InMemoryGroup::new();
    let admission = Admission::new(3 << 20);
    let config = CacheConfig { byte_limit: 0 };
    let mut state = create(Arc::new(group.clone()), admission.clone(), config);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"large", vec![39; 6 << 20]),
        ])
        .unwrap();
    let original = location(&state, state.selected, b"large");
    assert_eq!(compact_all(&mut state).1, 6 << 20);
    let relocated = location(&state, state.selected, b"large");
    assert_eq!(original.0, relocated.0);
    assert_eq!(original.1.len, relocated.1.len);
    assert_eq!(original.1.crc, relocated.1.crc);
    assert!(relocated.1.segment_id > original.1.segment_id);
    assert!(admission.peak.load(Ordering::Acquire) <= 3 << 20);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
    let reopened =
        DiskState::open(Arc::new(group.crash()), admission.clone(), GROUP, config).unwrap();
    assert_eq!(location(&reopened, reopened.selected, b"large"), relocated);
    drop(reopened);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}
mod residency_edges {
    include!("disk_residency_tests.rs");
}
