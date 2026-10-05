// Foreground publication must preserve full residency without an explicit
// warm-up after the mutation. Test input/output collections are fixture memory.
use super::*;

fn resident_fixture() -> (DiskState, Arc<Reads>, Arc<Admission>) {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(16 << 20);
    let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", vec![1; 8192]),
            Operation::put("accounts", b"b", vec![2; 8192]),
            Operation::put("accounts", b"hot", vec![3; 8192]),
        ])
        .unwrap();
    assert!(warm_all(&mut state).fully_resident);
    (state, reads, admission)
}

fn assert_resident_rows(
    state: &mut DiskState,
    reads: &Reads,
    pin: &SnapshotPin,
    rows: &[(&[u8], u8)],
) {
    let before = reads.count();
    for &(key, byte) in rows {
        let found = state.get(pin, "accounts", key, 8192).unwrap().unwrap();
        assert_eq!(found.as_bytes(), vec![byte; 8192]);
    }
    assert_eq!(
        reads.count(),
        before,
        "fitting publication left cold data/pages"
    );
}

#[test]
fn replacement_delete_and_repeated_put_preserve_exact_fit_without_warmup() {
    let (mut state, reads, _) = resident_fixture();
    let before = state.cache_stats().unwrap();
    state
        .configure_cache(CacheConfig {
            byte_limit: before.allocated_bytes + before.provider_overhead_bytes,
        })
        .unwrap();
    let before = state.cache_stats().unwrap();
    assert_eq!(before.entries, 4);
    assert_eq!(before.unused_credit_bytes, 0);
    state
        .commit(&[
            Operation::put("accounts", b"b", vec![7; 8192]),
            Operation::delete("accounts", b"b"),
            Operation::put("accounts", b"b", vec![8; 8192]),
            Operation::delete("accounts", b"a"),
            Operation::put("accounts", b"d", vec![4; 8192]),
        ])
        .unwrap();
    let current = state.snapshot().unwrap();
    assert_resident_rows(
        &mut state,
        &reads,
        &current,
        &[(b"b", 8), (b"d", 4), (b"hot", 3)],
    );
    let count = reads.count();
    assert!(
        state
            .get(&current, "accounts", b"a", 8192)
            .unwrap()
            .is_none()
    );
    assert_eq!(reads.count(), count);
    let after = state.cache_stats().unwrap();
    assert_eq!(after.entries, before.entries);
    assert_eq!(after.evictions, before.evictions);
    assert_eq!(after.resident_bytes, before.resident_bytes);
}

#[test]
fn pinned_old_root_and_replacement_remain_resident_when_the_union_fits() {
    let (mut state, reads, _) = resident_fixture();
    let old = state.snapshot().unwrap();
    let payload = state.get(&old, "accounts", b"a", 8192).unwrap().unwrap();
    let value_charge = payload.charged_bytes();
    drop(payload);
    let before = state.cache_stats().unwrap();
    let page_charge = before.cached_bytes - 3 * value_charge;
    let bound =
        before.allocated_bytes + before.provider_overhead_bytes + page_charge + value_charge;
    state
        .configure_cache(CacheConfig { byte_limit: bound })
        .unwrap();
    state
        .commit(&[Operation::put("accounts", b"a", vec![9; 8192])])
        .unwrap();
    let current = state.snapshot().unwrap();
    assert_resident_rows(
        &mut state,
        &reads,
        &old,
        &[(b"a", 1), (b"b", 2), (b"hot", 3)],
    );
    assert_resident_rows(
        &mut state,
        &reads,
        &current,
        &[(b"a", 9), (b"b", 2), (b"hot", 3)],
    );
    let after = state.cache_stats().unwrap();
    assert_eq!(after.evictions, before.evictions);
    assert_eq!(after.resident_bytes, bound);
}

#[test]
fn pressured_commit_preserves_old_snapshot_and_final_batch_visibility_across_reopen() {
    let (mut state, reads, admission) = resident_fixture();
    let old = state.snapshot().unwrap();
    let before = state.cache_stats().unwrap();
    state
        .configure_cache(CacheConfig {
            byte_limit: before.allocated_bytes + before.provider_overhead_bytes,
        })
        .unwrap();
    let before = state.cache_stats().unwrap();
    state
        .commit(&[
            Operation::put("accounts", b"a", vec![7; 8192]),
            Operation::put("accounts", b"a", vec![8; 8192]),
            Operation::put("accounts", b"b", vec![9; 8192]),
            Operation::delete("accounts", b"b"),
            Operation::put("accounts", b"temporary", vec![4; 8192]),
            Operation::delete("accounts", b"temporary"),
        ])
        .unwrap();
    let selected = state.selected;
    let after = state.cache_stats().unwrap();
    assert_eq!(after.entries, before.entries);
    assert_eq!(after.evictions, before.evictions);
    assert_eq!(after.resident_bytes, before.resident_bytes);
    assert!(!state.is_fenced());
    assert_resident_rows(
        &mut state,
        &reads,
        &old,
        &[(b"a", 1), (b"b", 2), (b"hot", 3)],
    );
    let current = state.snapshot().unwrap();
    assert_eq!(value(&mut state, &current, b"a").unwrap(), vec![8; 8192]);
    assert!(value(&mut state, &current, b"b").is_none());
    assert!(value(&mut state, &current, b"temporary").is_none());
    assert_eq!(value(&mut state, &current, b"hot").unwrap(), vec![3; 8192]);
    drop((old, current));
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
    let mut reopened =
        DiskState::open(Arc::new(reads.group.crash()), admission, GROUP, LARGE_CACHE).unwrap();
    assert_eq!(reopened.selected, selected);
    let current = reopened.snapshot().unwrap();
    assert_eq!(value(&mut reopened, &current, b"a").unwrap(), vec![8; 8192]);
    assert!(value(&mut reopened, &current, b"b").is_none());
    assert!(value(&mut reopened, &current, b"temporary").is_none());
    assert_eq!(
        value(&mut reopened, &current, b"hot").unwrap(),
        vec![3; 8192]
    );
}

#[test]
fn retired_lookup_preserves_returned_payload_charge_until_last_guard_drops() {
    let (mut state, reads, _) = resident_fixture();
    let old = state.snapshot().unwrap();
    let payload = state.get(&old, "accounts", b"a", 8192).unwrap().unwrap();
    drop(old);
    let before = state.cache_stats().unwrap();
    state
        .configure_cache(CacheConfig {
            byte_limit: before.resident_bytes + payload.charged_bytes(),
        })
        .unwrap();
    state
        .commit(&[Operation::put("accounts", b"a", vec![9; 8192])])
        .unwrap();
    let current = state.snapshot().unwrap();
    assert_resident_rows(
        &mut state,
        &reads,
        &current,
        &[(b"a", 9), (b"b", 2), (b"hot", 3)],
    );
    assert_eq!(payload.as_bytes(), vec![1; 8192]);
    assert_eq!(
        state.cache_stats().unwrap().pinned_bytes,
        payload.charged_bytes()
    );
    drop(payload);
    assert_eq!(state.cache_stats().unwrap().pinned_bytes, 0);
    assert_eq!(
        state.cache_stats().unwrap().resident_bytes,
        before.resident_bytes
    );
}

#[test]
fn publication_proof_preflight_denials_leave_cache_and_root_unchanged() {
    let (state, _, admission) = resident_fixture();
    let before = admission.calls.load(Ordering::Acquire);
    drop(state.prepare_cache_publication().unwrap());
    let reservations = admission.calls.load(Ordering::Acquire) - before;
    assert_eq!(reservations, 2, "snapshot capture and complete proof owner");
    drop(state);
    for nth in 1..=reservations {
        let (mut state, _, admission) = resident_fixture();
        let selected = state.selected;
        let cache = format!("{:?}", state.cache_stats().unwrap());
        let position = state.committed_position().unwrap();
        // Values, rollback/edit scratch and the admitted directory writer
        // precede the exact capture/proof constructors under test.
        admission.deny_nth(3 + nth);
        assert!(
            matches!(&(state.commit(&[Operation::put("accounts", b"a", vec![9; 8192])])), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
        );
        admission.deny_at.store(usize::MAX, Ordering::Release);
        assert!(!state.is_fenced());
        assert_eq!(state.selected, selected);
        assert_eq!(state.committed_position().unwrap(), position);
        assert_eq!(format!("{:?}", state.cache_stats().unwrap()), cache);
        state
            .commit(&[Operation::put("accounts", b"a", vec![9; 8192])])
            .unwrap();
    }
}

#[test]
fn corrupted_publication_candidate_fences_after_durable_commit_and_reopens_new_version() {
    let (mut state, reads, _) = resident_fixture();
    let location = match DirectoryReader::new(state.arena.as_ref(), state.owner.admission.clone())
        .get(state.selected, DirectoryKey::row("accounts", b"a"))
        .unwrap()
        .unwrap()
    {
        DirectoryValue::Row { value, .. } => value,
        _ => unreachable!(),
    };
    let identity = NativeIdentity::value(GROUP, location, "accounts", b"a").unwrap();
    {
        let mut cache = state.cache.lock().unwrap();
        cache.clear();
        drop(
            cache
                .load(identity, 8192, |out| {
                    out.fill(5);
                    Ok::<_, CoreError>(())
                })
                .unwrap(),
        );
    }
    assert!(
        matches!(&(state.commit(&[Operation::put("accounts", b"a", vec![9; 8192])])), Err(native_error) if native_error.is_unknown_commit())
    );
    assert!(state.is_fenced());
    drop(state);
    let mut reopened = DiskState::open(
        Arc::new(reads.group.crash()),
        Admission::new(16 << 20),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    let current = reopened.snapshot().unwrap();
    assert_eq!(value(&mut reopened, &current, b"a").unwrap(), vec![9; 8192]);
    assert_eq!(
        value(&mut reopened, &current, b"hot").unwrap(),
        vec![3; 8192]
    );
}

fn separator_key(index: u16) -> Vec<u8> {
    let mut key = vec![0; MAX_KEY_BYTES];
    key[..2].copy_from_slice(&index.to_be_bytes());
    key
}

fn separator_fixture() -> (DiskState, Arc<Reads>) {
    let reads = Reads::new(InMemoryGroup::new());
    let mut state = create(reads.clone(), Admission::new(16 << 20), LARGE_CACHE);
    let mut operations = vec![Operation::create_table("accounts")];
    operations.extend(
        (0..24u16).map(|index| {
            Operation::put("accounts", separator_key(index * 10), index.to_be_bytes())
        }),
    );
    state.commit(&operations).unwrap();
    assert!(warm_all(&mut state).fully_resident);
    (state, reads)
}

#[test]
fn changed_separator_tracks_redirected_path_and_root_collapse_without_warmup() {
    let (mut reference, _) = separator_fixture();
    let initial = reference.cache_stats().unwrap().resident_bytes;
    let reader = DirectoryReader::new(reference.arena.as_ref(), reference.owner.admission.clone());
    // Select a nonfirst leaf with two surviving row separators. Removing its
    // minimum sends an intermediate insertion to the original left neighbor.
    let minimum = (1..24u16)
        .map(|index| index * 10)
        .find(|&index| {
            let key = separator_key(index);
            let leaf = reader
                .leaf_after(
                    reference.selected,
                    DirectoryKey::row("accounts", &key),
                    false,
                )
                .unwrap()
                .unwrap();
            let rows: Vec<_> = leaf
                .records()
                .filter_map(|(key, _)| key.row)
                .map(|key| u16::from_be_bytes(key[..2].try_into().unwrap()))
                .collect();
            rows.len() >= 2 && rows[0] == index
        })
        .expect("fixture needs an internal separator with a successor");
    let gap = minimum + 5;
    let original_right = reader
        .leaf_after(
            reference.selected,
            DirectoryKey::row("accounts", &separator_key(minimum)),
            false,
        )
        .unwrap()
        .unwrap()
        .reference();
    let original_left = reader
        .leaf_after(
            reference.selected,
            DirectoryKey::row("accounts", &separator_key(minimum - 10)),
            false,
        )
        .unwrap()
        .unwrap()
        .reference();
    assert_ne!(original_left, original_right);
    let changes = [
        Operation::delete("accounts", separator_key(minimum)),
        Operation::put("accounts", separator_key(gap), b"replacement"),
    ];
    reference.commit(&changes).unwrap();
    assert!(warm_all(&mut reference).fully_resident);
    let bound = initial.max(reference.cache_stats().unwrap().resident_bytes);
    drop(reference);

    let (mut state, reads) = separator_fixture();
    state
        .configure_cache(CacheConfig { byte_limit: bound })
        .unwrap();
    let evictions = state.cache_stats().unwrap().evictions;
    state.commit(&changes).unwrap();
    let current = state.snapshot().unwrap();
    let before = reads.count();
    for index in 0..24u16 {
        let key = separator_key(index * 10);
        let found = state.get(&current, "accounts", &key, 32).unwrap();
        if index * 10 == minimum {
            assert!(found.is_none());
        } else {
            assert_eq!(found.unwrap().as_bytes(), index.to_be_bytes());
        }
    }
    assert_eq!(
        state
            .get(&current, "accounts", &separator_key(gap), 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"replacement"
    );
    assert_eq!(
        reads.count(),
        before,
        "redirected original path blocked fitting data"
    );
    assert_eq!(state.cache_stats().unwrap().evictions, evictions);
    assert!(state.cache_stats().unwrap().resident_bytes <= bound);
    drop(current);

    let mut deletes: Vec<_> = (1..24u16)
        .filter(|index| index * 10 != minimum)
        .map(|index| Operation::delete("accounts", separator_key(index * 10)))
        .collect();
    deletes.push(Operation::delete("accounts", separator_key(gap)));
    state.commit(&deletes).unwrap();
    assert_eq!(state.selected.height, 1);
    let current = state.snapshot().unwrap();
    let before = reads.count();
    assert_eq!(
        state
            .get(&current, "accounts", &separator_key(0), 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        0u16.to_be_bytes()
    );
    assert_eq!(reads.count(), before);
    assert_eq!(state.cache_stats().unwrap().entries, 2);
    assert_eq!(state.cache_stats().unwrap().evictions, evictions);
}
