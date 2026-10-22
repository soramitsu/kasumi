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

fn reconcile_retained_identities(state: &mut DiskState) -> Result<(), CoreError> {
    let mut publication = state.prepare_cache_publication()?.unwrap();
    state.reconcile_publication(&mut publication)
}

#[test]
fn unchanged_pinned_root_avoids_repeated_deferred_identity_reads() {
    let (mut state, reads, _) = resident_fixture();
    let old = state.snapshot().unwrap();
    state
        .commit(&[Operation::put("accounts", b"a", vec![7; 8192])])
        .unwrap();
    let count = state.auto_warm.deferred.len();
    assert!(count >= 2, "fixture must defer a page and a value");
    // With no prior positive proof, the original full directory/segment
    // check still runs. The next pass has the same roots and payloads.
    for index in 0..count {
        let mut identity = state.auto_warm.deferred.get(index);
        identity.witness = None;
        state.auto_warm.deferred.set(index, identity);
    }
    let before = reads.count();
    reconcile_retained_identities(&mut state).unwrap();
    assert!(
        reads.count() > before,
        "first proof must inspect original storage"
    );
    let before = reads.count();
    let accounting = state.cache_stats().unwrap();
    for _ in 0..16 {
        reconcile_retained_identities(&mut state).unwrap();
    }
    assert_eq!(
        reads.count(),
        before,
        "unchanged pinned identities were rescanned"
    );
    assert_eq!(state.auto_warm.deferred.len(), count);
    assert_eq!(state.cache_stats().unwrap(), accounting);
    assert_eq!(value(&mut state, &old, b"a").unwrap(), vec![1; 8192]);
    // Once the exact old root leaves, its superseded identities need no read,
    // even if a current snapshot occupies the freed registry slot.
    drop(old);
    let current = state.snapshot().unwrap();
    let before = reads.count();
    reconcile_retained_identities(&mut state).unwrap();
    assert_eq!(reads.count(), before);
    assert_eq!(state.auto_warm.deferred.len(), 0);
    assert_eq!(value(&mut state, &current, b"a").unwrap(), vec![7; 8192]);
}

#[test]
fn replaced_cached_payload_cannot_reuse_a_pinned_root_witness() {
    assert_replaced_payload_is_reproved(false);
}

#[test]
fn replaced_cached_payload_cannot_reuse_a_released_root_witness() {
    assert_replaced_payload_is_reproved(true);
}

fn assert_replaced_payload_is_reproved(release_root: bool) {
    let (mut state, _, _) = resident_fixture();
    let old = state.snapshot().unwrap();
    state
        .commit(&[Operation::put("accounts", b"a", vec![7; 8192])])
        .unwrap();
    let identity = (0..state.auto_warm.deferred.len())
        .map(|index| state.auto_warm.deferred.get(index))
        .find(|identity| matches!(identity.key, NativeIdentity::Value { .. }))
        .unwrap();
    {
        let mut cache = state.cache.lock().unwrap();
        let candidate = cache.candidate(identity.key).unwrap().unwrap();
        let mut corrupt = candidate.bytes.as_bytes().to_vec();
        corrupt[0] ^= 1;
        drop(candidate);
        cache.remove(identity.key);
        cache
            .load(identity.key, corrupt.len(), |out| {
                out.copy_from_slice(&corrupt);
                Ok::<_, CoreError>(())
            })
            .unwrap();
        assert_ne!(
            cache.candidate(identity.key).unwrap().unwrap().incarnation,
            identity.incarnation,
        );
    }
    let _old = if release_root {
        drop(old);
        assert!(state.pins.capture().unwrap().roots().is_empty());
        None
    } else {
        Some(old)
    };
    assert!(matches!(
        reconcile_retained_identities(&mut state)
            .unwrap_err()
            .rejected_cause(),
        Some(crate::CoreErrorCause::Corrupt(_))
    ));
    assert!(state.cache.lock().unwrap().contains(identity.key));
}

#[test]
fn deferred_identity_without_a_witness_requires_a_full_proof_after_pin_release() {
    let proofs = || super::super::publication::DEFERRED_PROOFS.with(std::cell::Cell::get);
    let (mut state, reads, _) = resident_fixture();
    let old = state.snapshot().unwrap();
    state
        .commit(&[Operation::put("accounts", b"a", vec![7; 8192])])
        .unwrap();
    let count = state.auto_warm.deferred.len();
    assert!(count >= 2, "fixture must defer a page and a value");
    for index in 0..count {
        // A refused proof keeps the candidate but clears its entire witness,
        // including the generation bound that could bypass subsequent reads.
        let mut identity = state.auto_warm.deferred.get(index);
        identity.witness = None;
        state.auto_warm.deferred.set(index, identity);
    }
    drop(old);
    assert!(state.pins.capture().unwrap().roots().is_empty());
    let before_reads = reads.count();
    let before_proofs = proofs();
    reconcile_retained_identities(&mut state).unwrap();
    assert!(reads.count() > before_reads);
    assert_eq!(proofs(), before_proofs + count);
    assert_eq!(state.auto_warm.deferred.len(), 0);
}

#[test]
fn pinned_root_witness_never_masks_owner_failure() {
    let (mut state, _, admission) = resident_fixture();
    let _old = state.snapshot().unwrap();
    state
        .commit(&[Operation::put("accounts", b"a", vec![7; 8192])])
        .unwrap();
    assert!(state.auto_warm.deferred.len() > 0);
    let mut publication = state.prepare_cache_publication().unwrap().unwrap();
    admission.owner_failed();
    assert!(matches!(
        state
            .reconcile_publication(&mut publication)
            .unwrap_err()
            .rejected_cause(),
        Some(crate::CoreErrorCause::OwnerFailed)
    ));
}

#[test]
fn deferred_root_witnesses_reject_foreign_capture_and_proof_owners() {
    let (mut state, _, _) = resident_fixture();
    let _old = state.snapshot().unwrap();
    state
        .commit(&[Operation::put("accounts", b"a", vec![7; 8192])])
        .unwrap();
    let (foreign, _, _) = resident_fixture();
    let count = state.auto_warm.deferred.len();
    let mut publication = state.prepare_cache_publication().unwrap().unwrap();
    publication.replace_capture_for_test(foreign.pins.capture().unwrap());
    assert!(matches!(
        state
            .reconcile_publication(&mut publication)
            .unwrap_err()
            .rejected_cause(),
        Some(crate::CoreErrorCause::InvalidInput(_))
    ));
    drop(publication);
    assert_eq!(state.auto_warm.deferred.len(), count);
    let mut publication = state.prepare_cache_publication().unwrap().unwrap();
    publication.proof =
        crate::disk_state::warming::CachedIdentityProofWorkspace::new(&foreign.owner.admission)
            .unwrap();
    assert!(matches!(
        state
            .reconcile_publication(&mut publication)
            .unwrap_err()
            .rejected_cause(),
        Some(crate::CoreErrorCause::InvalidInput(_))
    ));
    assert_eq!(state.auto_warm.deferred.len(), count);
}

#[test]
fn deferred_witness_root_compares_the_complete_root_not_just_generation() {
    let (mut state, reads, _) = resident_fixture();
    let old = state.snapshot().unwrap();
    state
        .commit(&[Operation::put("accounts", b"a", vec![7; 8192])])
        .unwrap();
    let count = state.auto_warm.deferred.len();
    for index in 0..count {
        let mut identity = state.auto_warm.deferred.get(index);
        let witness = identity.witness.as_mut().unwrap();
        let mut different_root = witness.root;
        different_root.page.as_mut().unwrap().sha256[0] ^= 1;
        assert_eq!(different_root.generation, old.root().generation);
        witness.root = different_root;
        state.auto_warm.deferred.set(index, identity);
    }
    let before = reads.count();
    reconcile_retained_identities(&mut state).unwrap();
    assert!(
        reads.count() > before,
        "different root digest reused an old witness"
    );
    for index in 0..count {
        assert_eq!(
            state.auto_warm.deferred.get(index).witness.unwrap().root,
            old.root()
        );
    }
}

#[test]
fn retired_witness_rechecks_other_pins_before_removing_a_shared_identity() {
    let (mut state, _, _) = resident_fixture();
    let first = state.snapshot().unwrap();
    state
        .commit(&[Operation::put("accounts", b"b", vec![8; 8192])])
        .unwrap();
    let second = state.snapshot().unwrap();
    state
        .commit(&[Operation::put("accounts", b"a", vec![7; 8192])])
        .unwrap();
    let shared = (0..state.auto_warm.deferred.len())
        .map(|index| state.auto_warm.deferred.get(index))
        .find(|identity| {
            matches!(identity.key, NativeIdentity::Value { .. })
                && identity.witness.unwrap().root == first.root()
                && state
                    .cache
                    .lock()
                    .unwrap()
                    .candidate(identity.key)
                    .unwrap()
                    .unwrap()
                    .bytes
                    .as_bytes()
                    == [1; 8192]
        })
        .unwrap();
    drop(first);
    reconcile_retained_identities(&mut state).unwrap();
    let witness = (0..state.auto_warm.deferred.len())
        .map(|index| state.auto_warm.deferred.get(index))
        .find(|identity| identity.key == shared.key)
        .unwrap();
    assert_eq!(witness.witness.unwrap().root, second.root());
    assert_eq!(
        witness.witness.unwrap().superseded,
        shared.witness.unwrap().superseded,
        "handoff must preserve the original negative reachability proof"
    );
    assert_eq!(value(&mut state, &second, b"a").unwrap(), vec![1; 8192]);
    drop(second);
    reconcile_retained_identities(&mut state).unwrap();
    assert!(!state.cache.lock().unwrap().contains(shared.key));
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
fn identities_kept_for_a_released_pin_leave_at_the_next_publication() {
    let (mut state, reads, _) = resident_fixture();
    let before = state.cache_stats().unwrap();
    // A reader keeps the first root pinned across two publications.
    let old = state.snapshot().unwrap();
    state
        .commit(&[Operation::put("accounts", b"a", vec![7; 8192])])
        .unwrap();
    state
        .commit(&[Operation::put("accounts", b"b", vec![8; 8192])])
        .unwrap();
    // While pinned, the replaced page and values stay resident for it.
    assert_resident_rows(
        &mut state,
        &reads,
        &old,
        &[(b"a", 1), (b"b", 2), (b"hot", 3)],
    );
    let pinned = state.cache_stats().unwrap();
    assert_eq!(pinned.entries, before.entries + 3);
    drop(old);
    // No root reaches them once the pin is gone; the next publication's
    // proof removes them. Nothing waits for a warm pass.
    state
        .commit(&[Operation::put("accounts", b"hot", vec![9; 8192])])
        .unwrap();
    let after = state.cache_stats().unwrap();
    assert_eq!(after.entries, before.entries);
    assert_eq!(after.cached_bytes, before.cached_bytes);
    assert_eq!(after.evictions, pinned.evictions);
    let current = state.snapshot().unwrap();
    assert_resident_rows(
        &mut state,
        &reads,
        &current,
        &[(b"a", 7), (b"b", 8), (b"hot", 9)],
    );
}

#[test]
fn rewrites_under_the_installed_pin_keep_cache_entries_bounded() {
    let (mut state, _, _) = resident_fixture();
    // The engine pins its installed root while the next entry applies, then
    // installs the published root and releases the replaced one.
    let mut installed = state.snapshot().unwrap();
    let mut entries = Vec::new();
    for round in 0..16u8 {
        state
            .commit(&[Operation::put("accounts", b"a", vec![round; 8192])])
            .unwrap();
        installed = state.snapshot().unwrap();
        let stats = state.cache_stats().unwrap();
        assert_eq!(stats.evictions, 0);
        entries.push(stats.entries);
    }
    drop(installed);
    // Each round keeps only the path the previous round replaced.
    assert!(
        entries[1..].iter().all(|&count| count == entries[1]),
        "superseded identities accumulated: {entries:?}"
    );
}

#[test]
fn identities_a_still_captured_pin_reaches_need_no_repeated_proof() {
    let proofs = || super::super::publication::DEFERRED_PROOFS.with(std::cell::Cell::get);
    let (mut state, _, _) = resident_fixture();
    // A reader keeps the first root pinned across many publications.
    let old = state.snapshot().unwrap();
    state
        .commit(&[Operation::put("accounts", b"a", vec![7; 8192])])
        .unwrap();
    let before = proofs();
    for round in 0..8u8 {
        state
            .commit(&[Operation::put("accounts", b"hot", vec![round; 8192])])
            .unwrap();
    }
    // That root still reaches every identity kept for it, so no publication
    // walks the directory to prove them again while it stays captured.
    let held = state.auto_warm.deferred.len();
    assert!(held > 0);
    assert!(
        (0..held).all(|index| {
            state.auto_warm.deferred.get(index).witness.unwrap().root == old.root()
        })
    );
    assert_eq!(proofs(), before);
    drop(old);
    // No captured root is older than the roots that superseded them, so the
    // next publication removes them all without walking them again.
    state
        .commit(&[Operation::put("accounts", b"b", vec![9; 8192])])
        .unwrap();
    assert_eq!(proofs(), before);
    assert_eq!(state.auto_warm.deferred.len(), 0);
}

#[test]
fn identities_the_installed_pin_kept_leave_without_a_second_walk() {
    let proofs = || super::super::publication::DEFERRED_PROOFS.with(std::cell::Cell::get);
    let (mut state, _, _) = resident_fixture();
    // The engine pins its installed root while the next entry applies, then
    // installs the published root and releases the replaced one.
    let mut installed = state.snapshot().unwrap();
    let before = proofs();
    let mut held = Vec::new();
    for round in 0..16u8 {
        state
            .commit(&[Operation::put("accounts", b"a", vec![round; 8192])])
            .unwrap();
        // Only what this publication replaced stays, kept for the installed
        // root; what the previous one kept left once its root was released.
        let deferred = state.auto_warm.deferred.len();
        assert!(deferred > 0);
        assert!((0..deferred).all(|index| {
            state.auto_warm.deferred.get(index).witness.unwrap().root == installed.root()
        }));
        held.push(deferred);
        installed = state.snapshot().unwrap();
    }
    assert!(
        held[1..].iter().all(|&count| count == held[1]),
        "deferred identities accumulated: {held:?}"
    );
    // None of them was walked a second time.
    assert_eq!(proofs(), before);
    drop(installed);
    state
        .commit(&[Operation::put("accounts", b"b", vec![9; 8192])])
        .unwrap();
    assert_eq!(state.auto_warm.deferred.len(), 0);
    assert_eq!(proofs(), before);
}

#[test]
fn a_released_root_hands_its_identities_to_an_older_pin_that_still_reaches_them() {
    let proofs = || super::super::publication::DEFERRED_PROOFS.with(std::cell::Cell::get);
    let (mut state, reads, _) = resident_fixture();
    // Two readers pin consecutive roots; both reach the original "a" row.
    let older = state.snapshot().unwrap();
    state
        .commit(&[Operation::put("accounts", b"b", vec![8; 8192])])
        .unwrap();
    let newer = state.snapshot().unwrap();
    state
        .commit(&[Operation::put("accounts", b"a", vec![9; 8192])])
        .unwrap();
    let deferred = |state: &DiskState| {
        (0..state.auto_warm.deferred.len())
            .map(|index| state.auto_warm.deferred.get(index))
            .collect::<Vec<_>>()
    };
    let kept = deferred(&state);
    assert!(kept.iter().all(|identity| {
        let root = identity.witness.unwrap().root;
        root == older.root() || root == newer.root()
    }));
    // Releasing the first root leaves the newer pin as the only older root
    // that can still reach what the "a" rewrite superseded: those are walked
    // once under it and stay. What the "b" rewrite superseded before the newer
    // root existed needs no walk; nothing captured is older than it.
    let walked = kept
        .iter()
        .filter(|identity| {
            let witness = identity.witness.unwrap();
            witness.root == older.root() && witness.superseded > newer.root().generation
        })
        .count();
    assert!(walked > 0);
    let before = proofs();
    drop(older);
    state
        .commit(&[Operation::put("accounts", b"hot", vec![7; 8192])])
        .unwrap();
    assert_eq!(proofs(), before + walked);
    let kept = deferred(&state);
    assert!(!kept.is_empty());
    assert!(
        kept.iter()
            .all(|identity| identity.witness.unwrap().root == newer.root())
    );
    assert_resident_rows(
        &mut state,
        &reads,
        &newer,
        &[(b"a", 1), (b"b", 8), (b"hot", 3)],
    );
    drop(newer);
    state
        .commit(&[Operation::put("accounts", b"hot", vec![6; 8192])])
        .unwrap();
    assert_eq!(proofs(), before + walked);
    assert_eq!(state.auto_warm.deferred.len(), 0);
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
