use super::*;

fn row_identity(state: &DiskState, root: DirectoryRoot, key: &[u8]) -> NativeIdentity {
    let Some(DirectoryValue::Row { value, .. }) =
        DirectoryReader::new(state.arena.as_ref(), state.owner.admission.clone())
            .get(root, DirectoryKey::row("accounts", key))
            .unwrap()
    else {
        panic!("fixture row is absent");
    };
    NativeIdentity::value(GROUP, value, "accounts", key).unwrap()
}

fn resident(state: &DiskState, identity: NativeIdentity) -> bool {
    state.cache.lock().unwrap().peek(identity).is_some()
}

fn policy_counters(stats: CacheStats) -> [u64; 5] {
    [
        stats.hits,
        stats.misses,
        stats.loads,
        stats.uncached_loads,
        stats.evictions,
    ]
}

/// No fixture mutates cache membership between steps except warm-up itself.
/// Each allocated slot includes a complete NativeIdentity, so the admitted
/// metadata bounds the initial slot count without exposing the cache layout.
/// Pruning can revisit at most one slot per removed entry. Refill needs one
/// unit per record, root ending and phase transition. Duplicate current-root
/// pins need at most one additional transition, regardless of reader churn.
fn warm_one_bound(state: &DiskState, historical: &[DirectoryRoot]) -> usize {
    let stats = state.cache_stats().unwrap();
    let slots = stats.metadata_bytes as usize / std::mem::size_of::<NativeIdentity>() + 1;
    let records = state.selected.entries as usize
        + historical
            .iter()
            .map(|root| root.entries as usize)
            .sum::<usize>();
    slots + stats.entries + records + historical.len() + 5
}

fn finish_one_at_a_time(
    state: &mut DiskState,
    historical: &[DirectoryRoot],
    churn_current_readers: bool,
) -> CacheWarmup {
    let bound = warm_one_bound(state, historical);
    let policy = policy_counters(state.cache_stats().unwrap());
    for step in 0..bound {
        // Independent acquisitions change pin tokens/epochs and alternate the
        // presence of the current root in captures; clones alone would not.
        let readers = if churn_current_readers && step % 2 == 0 {
            Some((state.snapshot().unwrap(), state.snapshot().unwrap()))
        } else {
            None
        };
        let progress = state.warm(1).unwrap();
        assert!(progress.work <= 1);
        drop(readers);
        assert_eq!(policy_counters(state.cache_stats().unwrap()), policy);
        if progress.complete {
            return progress;
        }
    }
    panic!("warm-up exceeded the fixture's {bound}-unit finite bound");
}

fn puts(count: u8, version: u8, bytes: usize) -> Vec<Operation> {
    (0..count)
        .map(|key| Operation::put("accounts", [key], vec![version ^ key; bytes]))
        .collect()
}

#[test]
fn overwrite_delete_history_is_pruned_and_pin_drop_or_budget_growth_restores_residency() {
    const COUNT: u8 = 8;
    const BYTES: usize = 32 << 10;
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(8 << 20);
    let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
    let mut operations = vec![Operation::create_table("accounts")];
    operations.extend(puts(COUNT, 10, BYTES));
    state.commit(&operations).unwrap();
    let old = state.snapshot().unwrap();
    let original: Vec<_> = (0..COUNT)
        .map(|key| row_identity(&state, old.root(), &[key]))
        .collect();
    state.commit(&puts(COUNT, 20, BYTES)).unwrap();
    let intermediate_pin = state.snapshot().unwrap();
    let intermediate: Vec<_> = (0..COUNT)
        .map(|key| row_identity(&state, state.selected, &[key]))
        .collect();
    state.commit(&puts(COUNT, 30, BYTES)).unwrap();
    let latest_pin = state.snapshot().unwrap();
    let latest: Vec<_> = (0..COUNT)
        .map(|key| row_identity(&state, state.selected, &[key]))
        .collect();
    state
        .commit(
            &(COUNT / 2..COUNT)
                .map(|key| Operation::delete("accounts", [key]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let current = state.snapshot().unwrap();
    for identity in original.iter().chain(&intermediate).chain(&latest) {
        assert!(resident(&state, *identity));
    }
    // Foreground publication now prunes unpinned overwritten versions. Keep
    // these roots live through the writes, then exercise explicit warm-up's
    // independent responsibility to retire history after its last pin drops.
    drop(intermediate_pin);
    drop(latest_pin);
    let before = state.cache_stats().unwrap();
    assert_eq!(before.evictions, 0);
    assert!(finish_one_at_a_time(&mut state, &[old.root()], false).fully_resident);
    assert!(state.cache_stats().unwrap().cached_bytes < before.cached_bytes);
    for key in 0..COUNT {
        assert!(resident(&state, original[key as usize]));
        assert!(!resident(&state, intermediate[key as usize]));
        assert_eq!(resident(&state, latest[key as usize]), key < COUNT / 2);
    }
    let before_reads = reads.count();
    for key in 0..COUNT {
        assert_eq!(value(&mut state, &old, &[key]), Some(vec![10 ^ key; BYTES]));
        assert_eq!(
            value(&mut state, &current, &[key]),
            (key < COUNT / 2).then(|| vec![30 ^ key; BYTES])
        );
    }
    assert_eq!(reads.count(), before_reads);

    let small = CacheConfig {
        byte_limit: 256 << 10,
    };
    state.configure_cache(small).unwrap();
    assert!(!finish_one_at_a_time(&mut state, &[old.root()], false).fully_resident);
    assert!(state.cache_stats().unwrap().resident_bytes <= small.byte_limit);
    // Growing the budget must refill both roots, including values displaced
    // by the earlier explicit budget reduction.
    state
        .configure_cache(CacheConfig {
            byte_limit: 600 << 10,
        })
        .unwrap();
    assert!(finish_one_at_a_time(&mut state, &[old.root()], false).fully_resident);
    let before_reads = reads.count();
    for key in 0..COUNT {
        assert!(value(&mut state, &old, &[key]).is_some());
        assert_eq!(
            value(&mut state, &current, &[key]).is_some(),
            key < COUNT / 2
        );
    }
    assert_eq!(reads.count(), before_reads);

    state.configure_cache(small).unwrap();
    assert!(!finish_one_at_a_time(&mut state, &[old.root()], false).fully_resident);
    drop(old);
    assert!(finish_one_at_a_time(&mut state, &[], false).fully_resident);
    for identity in original {
        assert!(!resident(&state, identity));
    }
    let before_reads = reads.count();
    for key in 0..COUNT / 2 {
        assert_eq!(
            value(&mut state, &current, &[key]),
            Some(vec![30 ^ key; BYTES])
        );
    }
    assert_eq!(reads.count(), before_reads);
    assert!(state.cache_stats().unwrap().resident_bytes <= small.byte_limit);
    drop(current);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn independent_current_reader_churn_cannot_restart_a_stable_warm_pass() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(8 << 20);
    let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
    let mut operations = vec![Operation::create_table("accounts")];
    operations.extend(puts(24, 17, 4096));
    state.commit(&operations).unwrap();
    let historical = state.snapshot().unwrap();
    state.commit(&puts(24, 39, 4096)).unwrap();
    // The complete cache starts cold so progress must include actual refill,
    // not merely an already-resident membership pass.
    state.pages.clear().unwrap();
    assert_eq!(state.cache_stats().unwrap().entries, 0);
    let before_reads = reads.count();
    assert!(finish_one_at_a_time(&mut state, &[historical.root()], true).fully_resident);
    assert!(reads.count() > before_reads);
    let current = state.snapshot().unwrap();
    let before_reads = reads.count();
    for key in 0..24 {
        assert_eq!(
            value(&mut state, &historical, &[key]),
            Some(vec![17 ^ key; 4096])
        );
        assert_eq!(
            value(&mut state, &current, &[key]),
            Some(vec![39 ^ key; 4096])
        );
    }
    assert_eq!(reads.count(), before_reads);
    drop((historical, current));
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

fn finish_compact(state: &mut DiskState) {
    for _ in 0..4096 {
        let progress = state.compact_step(8).unwrap();
        assert!(progress.work <= 8);
        if progress.complete {
            return;
        }
    }
    panic!("small relocation fixture did not complete compaction");
}

#[test]
fn obsolete_relocation_alias_is_removed_without_copying_or_releasing_live_payload() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(8 << 20);
    let mut state = create(
        reads.clone(),
        admission.clone(),
        CacheConfig {
            byte_limit: 512 << 10,
        },
    );
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"shared", vec![71; 128 << 10]),
        ])
        .unwrap();
    let old = state.snapshot().unwrap();
    let old_identity = row_identity(&state, old.root(), b"shared");
    let output = state
        .get(&old, "accounts", b"shared", usize::MAX)
        .unwrap()
        .unwrap();
    finish_compact(&mut state);
    let current = state.snapshot().unwrap();
    let new_identity = row_identity(&state, current.root(), b"shared");
    assert_ne!(old_identity, new_identity);
    {
        let cache = state.cache.lock().unwrap();
        assert!(CachedBytes::ptr_eq(
            &output,
            &cache.peek(old_identity).unwrap()
        ));
        assert!(CachedBytes::ptr_eq(
            &output,
            &cache.peek(new_identity).unwrap()
        ));
    }
    let NativeIdentity::Value { segment_id, .. } = old_identity else {
        unreachable!();
    };
    assert!(reads.group.exists(GroupFile::segment(segment_id)).unwrap());
    drop(old);
    assert!(finish_one_at_a_time(&mut state, &[], false).fully_resident);
    assert!(!resident(&state, old_identity));
    assert!(resident(&state, new_identity));
    // Warm-up proves individual identities obsolete without waiting for a
    // whole source segment to be unlinked by a later reclamation cycle.
    assert!(reads.group.exists(GroupFile::segment(segment_id)).unwrap());
    assert_eq!(state.cache_stats().unwrap().pinned_bytes, 0);
    let before_reads = reads.count();
    let current_output = state
        .get(&current, "accounts", b"shared", usize::MAX)
        .unwrap()
        .unwrap();
    assert!(CachedBytes::ptr_eq(&output, &current_output));
    assert_eq!(reads.count(), before_reads);
    drop((output, current_output, current));
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn cold_refill_shares_relocated_snapshot_versions_when_only_one_payload_fits() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(8 << 20);
    let config = CacheConfig {
        byte_limit: 700 << 10,
    };
    let bytes = 512 << 10;
    assert!(2 * bytes as u64 > config.byte_limit);
    let mut state = create(reads.clone(), admission.clone(), config);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"shared", vec![87; bytes]),
        ])
        .unwrap();
    let old = state.snapshot().unwrap();
    let old_identity = row_identity(&state, old.root(), b"shared");
    finish_compact(&mut state);
    let current = state.snapshot().unwrap();
    let current_identity = row_identity(&state, current.root(), b"shared");
    assert_ne!(old_identity, current_identity);
    state.pages.clear().unwrap();
    assert_eq!(state.cache_stats().unwrap().resident_bytes, 0);
    let before_reads = reads.count();
    assert!(finish_one_at_a_time(&mut state, &[old.root()], true).fully_resident);
    assert!(reads.count() > before_reads);
    assert!(state.cache_stats().unwrap().resident_bytes <= config.byte_limit);
    let before_reads = reads.count();
    let previous = state
        .get(&old, "accounts", b"shared", bytes)
        .unwrap()
        .unwrap();
    let latest = state
        .get(&current, "accounts", b"shared", bytes)
        .unwrap()
        .unwrap();
    assert_eq!(reads.count(), before_reads);
    assert!(CachedBytes::ptr_eq(&previous, &latest));
    assert_eq!(latest.as_bytes(), vec![87; bytes]);
    assert_eq!(state.cache_stats().unwrap().pinned_bytes, 0);
    drop((old, current, previous, latest));
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

fn finish_reclaim(state: &mut DiskState) -> usize {
    let mut reclaimed = 0;
    for _ in 0..4096 {
        let progress = state.reclaim_step(8).unwrap();
        assert!(progress.work <= 8);
        reclaimed += progress.reclaimed;
        if progress.complete {
            return reclaimed;
        }
    }
    panic!("small retired-root fixture did not complete reclamation");
}

#[test]
fn vanished_pin_and_reclaimed_files_reset_warm_before_any_stale_root_read() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(8 << 20);
    let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
    let mut operations = vec![Operation::create_table("accounts")];
    operations.extend(puts(6, 11, 4096));
    state.commit(&operations).unwrap();
    let old = state.snapshot().unwrap();
    let old_arena = old.root().page.unwrap().arena_id;
    let NativeIdentity::Value {
        segment_id: old_segment,
        ..
    } = row_identity(&state, old.root(), &[0])
    else {
        unreachable!();
    };
    state
        .writer
        .force_roll(state.owner.backend.as_ref(), &mut Roll(state.owner.clone()))
        .unwrap();
    state.arena.force_roll().unwrap();
    state.commit(&puts(6, 22, 4096)).unwrap();
    let selected = state.selected;
    assert_ne!(selected.page.unwrap().arena_id, old_arena);
    assert!(!state.warm(1).unwrap().complete);
    // The preceding warm call retained a capture containing the old root.
    // Captures are deliberately not pins, so physical GC may now unlink it.
    drop(old);
    assert!(finish_reclaim(&mut state) >= 2);
    assert!(!reads.group.exists(GroupFile::directory(old_arena)).unwrap());
    assert!(!reads.group.exists(GroupFile::segment(old_segment)).unwrap());
    assert_eq!(state.selected, selected);
    assert!(finish_one_at_a_time(&mut state, &[], true).fully_resident);
    assert!(!state.is_fenced());
    let current = state.snapshot().unwrap();
    let before_reads = reads.count();
    for key in 0..6 {
        assert_eq!(
            value(&mut state, &current, &[key]),
            Some(vec![22 ^ key; 4096])
        );
    }
    assert_eq!(reads.count(), before_reads);
    drop(current);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn pruning_a_dead_lookup_keeps_its_returned_output_charged_until_last_guard() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(8 << 20);
    let mut state = create(
        reads.clone(),
        admission.clone(),
        CacheConfig {
            byte_limit: 512 << 10,
        },
    );
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"held", vec![3; 128 << 10]),
        ])
        .unwrap();
    let old = state.snapshot().unwrap();
    let identity = row_identity(&state, old.root(), b"held");
    let output = state
        .get(&old, "accounts", b"held", usize::MAX)
        .unwrap()
        .unwrap();
    let clone = output.clone();
    state
        .commit(&[Operation::put("accounts", b"held", vec![8; 128 << 10])])
        .unwrap();
    drop(old);
    assert!(resident(&state, identity));
    assert_eq!(state.cache_stats().unwrap().pinned_bytes, 0);
    assert!(finish_one_at_a_time(&mut state, &[], false).fully_resident);
    assert!(!resident(&state, identity));
    let charge = output.charged_bytes();
    let before = admission.used.load(Ordering::Acquire);
    let stats = state.cache_stats().unwrap();
    assert_eq!(stats.pinned_bytes, charge);
    assert_eq!(
        stats.resident_bytes,
        stats.cached_bytes
            + stats.pinned_bytes
            + stats.metadata_bytes
            + stats.unused_credit_bytes
            + stats.provider_overhead_bytes
    );
    assert_eq!(output.as_bytes(), vec![3; 128 << 10]);
    drop(output);
    assert_eq!(state.cache_stats().unwrap().pinned_bytes, charge);
    assert_eq!(admission.used.load(Ordering::Acquire), before);
    drop(clone);
    let after = state.cache_stats().unwrap();
    assert_eq!(after.pinned_bytes, 0);
    assert_eq!(after.allocated_bytes, stats.allocated_bytes - charge);
    assert_eq!(
        after.resident_bytes,
        after.cached_bytes
            + after.metadata_bytes
            + after.unused_credit_bytes
            + after.provider_overhead_bytes
    );
    assert_eq!(
        before - admission.used.load(Ordering::Acquire),
        stats.resident_bytes - after.resident_bytes
    );
    let current = state.snapshot().unwrap();
    let before_reads = reads.count();
    assert_eq!(
        value(&mut state, &current, b"held"),
        Some(vec![8; 128 << 10])
    );
    assert_eq!(reads.count(), before_reads);
    drop(current);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn compact_value_locator_does_not_expand_native_cache_identity_slots() {
    #[allow(dead_code)]
    enum BeforeValueLocator {
        Page {
            group_id: [u8; 16],
            arena_id: u64,
            page_index: u64,
            sha256: [u8; 32],
        },
        Value {
            group_id: [u8; 16],
            segment_id: u64,
            offset: u64,
            len: u32,
            crc: u32,
        },
    }
    assert_eq!(
        std::mem::size_of::<NativeIdentity>(),
        std::mem::size_of::<BeforeValueLocator>()
    );
    assert_eq!(
        std::mem::align_of::<NativeIdentity>(),
        std::mem::align_of::<BeforeValueLocator>()
    );
}
