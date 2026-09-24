use super::*;
use std::hash::BuildHasher;

fn key_in_group<V>(map: &Map<V>, start: &mut u64, home: u64) -> Identity {
    // limit40 yields64 physical buckets on both supported group widths.
    loop {
        *start += 1;
        let key = Identity(17, *start);
        if map.entries.hasher().hash_one(key) & 63 == home {
            return key;
        }
    }
}
fn clustered<V>(mut value: impl FnMut(u64) -> V) -> (Banks<V>, [Identity; 40], u64)
where
    V: Clone,
{
    let mut banks = Banks::new(40).unwrap();
    let mut keys = [Identity(0, 0); 40];
    let mut start = 0;
    for (index, key) in keys.iter_mut().enumerate() {
        *key = key_in_group(&banks.active, &mut start, 0);
        banks.try_reserve(1).unwrap();
        banks.insert(*key, value(index as u64));
    }
    assert_eq!(banks.active.entries.capacity(), 56);
    (banks, keys, start)
}

#[test]
fn empty_tombstones_require_drain_not_clear_and_reset_does_not_allocate() {
    let (mut banks, keys, _) = clustered(|n| n);
    for key in keys {
        banks.remove(&key).unwrap();
    }
    assert_eq!(banks.len(), 0);
    let depleted = banks.active.entries.capacity();
    assert!(depleted < 56, "fixture must retain real deleted buckets");
    banks.active.entries.clear();
    assert_eq!(
        banks.active.entries.capacity(),
        depleted,
        "pinned clear skips empty control reset"
    );
    let ((), allocations) = crate::allocation_tests::measure(|| banks.clear());
    assert_eq!(allocations, 0);
    assert_eq!(banks.active.entries.capacity(), 56);
    assert_eq!(banks.spare.entries.capacity(), 56);
}
#[test]
fn absent_insertion_rebuilds_before_effect_without_any_new_allocation() {
    let (mut banks, keys, mut start) = clustered(|n| n);
    for key in &keys[..20] {
        banks.remove(key).unwrap();
    }
    let ((), allocations) = crate::allocation_tests::measure(|| {
        for n in 0..20 {
            // The opposite initially empty group consumes real growth_left
            // while deleted controls remain in the old cluster.
            let key = key_in_group(&banks.active, &mut start, 32);
            banks.try_reserve(1).unwrap();
            assert!(banks.insert(key, 100 + n).is_none());
        }
    });
    assert_eq!(allocations, 0);
    assert!(banks.rebuilds > 0);
    assert_eq!(banks.len(), 40);
    assert!(banks.try_reserve(1).is_err());
    for (index, key) in keys[20..].iter().enumerate() {
        assert_eq!(banks.get(key), Some(&(index as u64 + 20)));
    }
}
#[test]
fn occupied_replacement_at_zero_growth_does_not_call_hashmap_insert() {
    let (mut banks, keys, mut start) = clustered(|n| n);
    for key in &keys[..20] {
        banks.remove(key).unwrap();
    }
    while banks.active.entries.capacity() > banks.len() {
        let key = key_in_group(&banks.active, &mut start, 32);
        if banks.len() == 40 {
            panic!("fixture did not exhaust growth before logical capacity");
        }
        banks.active.insert(key, 777);
    }
    assert!(banks.len() < 40);
    let (old, allocations) = crate::allocation_tests::measure(|| banks.insert(keys[20], 999));
    assert_eq!(old, Some(20));
    assert_eq!(allocations, 0);
    assert_eq!(banks.get(&keys[20]), Some(&999));
}
#[test]
fn panic_during_spare_copy_preserves_complete_published_active_map() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Value(u64, Arc<AtomicUsize>);
    impl Clone for Value {
        fn clone(&self) -> Self {
            let count = self.1.fetch_add(1, Ordering::SeqCst);
            assert_ne!(count, 2, "injected third-copy failure");
            Self(self.0, self.1.clone())
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let (mut banks, keys, mut start) = clustered(|n| Value(n, calls.clone()));
    for key in &keys[..20] {
        banks.remove(key).unwrap();
    }
    while banks.active.entries.capacity() > banks.len() {
        let key = key_in_group(&banks.active, &mut start, 32);
        assert!(banks.len() < 40);
        banks.active.insert(key, Value(777, calls.clone()));
    }
    let before = banks.iter().map(|(k, v)| (*k, v.0)).collect::<Vec<_>>();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| banks.try_reserve(1)));
    assert!(result.is_err());
    assert_eq!(banks.len(), before.len());
    for (key, value) in &before {
        assert_eq!(banks.get(key).unwrap().0, *value);
    }
    assert_eq!(
        banks.spare.len(),
        0,
        "partial copied ownership retires before unwind escapes"
    );
    banks.cancel_stage();
    assert_eq!(banks.spare.len(), 0);
    banks.try_reserve(1).unwrap();
    for (key, value) in &before {
        assert_eq!(banks.get(key).unwrap().0, *value);
    }
}
#[test]
fn smaller_census_stage_preserves_full_retained_quota_after_swap_and_cancel() {
    let mut banks = Banks::<u64>::new(18).unwrap();
    banks.try_reserve(1).unwrap();
    banks.insert(Identity(1, 99), 99);
    {
        let stage = banks.stage(10).unwrap();
        for n in 0..10 {
            stage.try_reserve(1).unwrap();
            stage.insert(Identity(2, n), n);
        }
        assert!(stage.try_reserve(1).is_err());
    }
    assert_eq!(banks.get(&Identity(1, 99)), Some(&99));
    banks.cancel_stage();
    assert_eq!(banks.len(), 1);
    assert_eq!(banks.spare.len(), 0);
    {
        let stage = banks.stage(10).unwrap();
        for n in 0..10 {
            stage.try_reserve(1).unwrap();
            stage.insert(Identity(2, n), n);
        }
    }
    let ((), allocations) = crate::allocation_tests::measure(|| {
        banks.commit_stage();
        for n in 10..18 {
            banks.try_reserve(1).unwrap();
            banks.insert(Identity(2, n), n);
        }
    });
    assert_eq!(allocations, 0);
    assert_eq!(banks.len(), 18);
    assert!(banks.try_reserve(1).is_err());
    assert!(banks.get(&Identity(1, 99)).is_none());
}
#[test]
fn pinned_requested_bytes_cover_exact_two_bank_allocations_without_growth_factor() {
    // Warm the per-thread hash seed before observing table allocations.
    drop(Banks::<u64>::new(1).unwrap());
    for limit in [1, 3, 4, 7, 8, 14, 15, 40, 256, 4096] {
        let (banks, allocations, bytes) =
            crate::allocation_tests::measure_requested(|| Banks::<u64>::new(limit).unwrap());
        assert_eq!(allocations, 2, "each fixed bank has one backing allocation");
        assert!((bytes as u64) <= 2 * bank_bytes::<u64>(limit).unwrap());
        assert!(banks.active.entries.capacity() >= limit);
        let ((), retirements, retired_bytes) =
            crate::allocation_tests::measure_retired(|| drop(banks));
        assert_eq!(retirements, 2);
        assert_eq!(retired_bytes, bytes);
    }
    assert!(bank_bytes::<u64>(usize::MAX).is_err());
    assert!(Banks::<u64>::new(usize::MAX).is_err());
}

#[test]
fn repeated_churn_retains_every_logical_slot_without_allocating_or_reducing_limits() {
    let (mut banks, mut keys, mut start) = clustered(|n| n);
    let ((), allocations) = crate::allocation_tests::measure(|| {
        for round in 0..4000usize {
            let slot = round % keys.len();
            banks.remove(&keys[slot]).unwrap();
            let next = key_in_group(&banks.active, &mut start, (round as u64) % 64);
            banks.try_reserve(1).unwrap();
            assert!(banks.insert(next, round as u64).is_none());
            keys[slot] = next;
            assert_eq!(banks.len(), 40);
        }
    });
    assert_eq!(allocations, 0);
    for key in keys {
        assert!(banks.contains_key(&key));
    }
}

#[test]
fn failed_and_cancelled_real_census_preserve_old_enrollment_then_publish_complete_candidate() {
    use super::super::{CensusCancellation, NodeDisk, NodeDiskPhase};
    use crate::test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry};
    use std::os::unix::fs::PermissionsExt;
    let root = private_tempdir().unwrap();
    let config = NodeDisk::fixture_config(root.path().join("anchor")).unwrap();
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = retry_disk_registry(|| {
        NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap();
    let before = disk.snapshot();
    let before_entries = disk
        .lock_state()
        .accounted
        .iter()
        .map(|(k, v)| (*k, *v))
        .collect::<Vec<_>>();
    let bad = root.path().join("bad");
    crate::private_files::create(&bad, b"new").unwrap();
    std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    {
        let state = disk.lock_state();
        assert_eq!(state.phase, NodeDiskPhase::Failed);
        assert_eq!(state.accounted.len(), before_entries.len());
        assert_eq!(state.accounted.spare.len(), 0);
        for (key, value) in &before_entries {
            assert_eq!(state.accounted.get(key), Some(value));
        }
        assert_eq!(state.bytes, before.charged_bytes);
        assert_eq!(state.pending, before.pending_bytes);
    }
    std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cancel = CensusCancellation::default();
    cancel
        .cancel_at
        .store(2, std::sync::atomic::Ordering::Relaxed);
    assert!(disk.reconcile(&cancel).is_err());
    assert!(
        cancel
            .checkpoints
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 2
    );
    {
        let state = disk.lock_state();
        assert_eq!(state.accounted.spare.len(), 0);
        for (key, value) in &before_entries {
            assert_eq!(state.accounted.get(key), Some(value));
        }
    }
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().persistent_files, 1);
    assert!(disk.lock_state().accounted.spare.entries.capacity() >= 32769);
    assert_eq!(disk.lock_state().accounted.active.limit, 32769);
}

#[test]
fn native_entry_geometry_preserves_original_million_entry_and_handle_policy() {
    use super::super::{AccountedInode, DirectoryPolicy, NodeDisk, NodeDiskConfig};
    use std::{
        collections::BTreeMap,
        mem::{align_of, size_of},
        path::PathBuf,
        sync::Weak,
    };
    let config = NodeDiskConfig {
        roots: BTreeMap::from([("data".into(), PathBuf::from("/var/lib/kasumi/data"))]),
        max_bytes: 64 << 30,
        maintenance_reserve_bytes: 8 << 30,
        min_free_bytes: 0,
        max_open_files: 4096,
        max_open_directories: 4096,
        directory_policy: DirectoryPolicy::new(1 << 20, 32768).unwrap(),
        max_census_entries: 1_000_000,
        max_depth: 64,
        max_name_bytes: 255,
    };
    let (retained, census) = super::super::ledger::map_limits(&config).unwrap();
    assert_eq!((retained, census), (2_000_001, 1_000_001));
    let banks = 2 * bank_bytes::<AccountedInode>(retained).unwrap();
    let live = 2 * bank_bytes::<Weak<super::super::file::FileOwner>>(4096).unwrap();
    println!(
        "inode_pair_size={} inode_pair_align={} live_pair_size={} live_pair_align={} inode_two_banks_requested={} live_two_banks_requested={} cfg_test_owner={} physical_allocator_RSS_fit=UNQUALIFIED",
        size_of::<(Identity, AccountedInode)>(),
        align_of::<(Identity, AccountedInode)>(),
        size_of::<(Identity, Weak<super::super::file::FileOwner>)>(),
        align_of::<(Identity, Weak<super::super::file::FileOwner>)>(),
        banks,
        live,
        NodeDisk::required_metadata_bytes(&config).unwrap()
    );
}

#[test]
fn rebuilt_weak_registry_retires_duplicates_before_actual_last_weak_allocation_destruction() {
    use std::sync::Arc;
    let (owner, allocations, owner_bytes) =
        crate::allocation_tests::measure_requested(|| Arc::new(7u64));
    assert_eq!(allocations, 1);
    let (mut banks, keys, mut start) = clustered(|_| Arc::downgrade(&owner));
    for key in &keys[..20] {
        drop(banks.remove(key).unwrap());
    }
    while banks.active.entries.capacity() > banks.len() {
        let key = key_in_group(&banks.active, &mut start, 32);
        assert!(banks.len() < 40);
        banks.active.insert(key, Arc::downgrade(&owner));
    }
    let ((), allocations) = crate::allocation_tests::measure(|| banks.try_reserve(1).unwrap());
    assert_eq!(allocations, 0);
    assert_eq!(banks.rebuilds, 1);
    assert_eq!(
        Arc::weak_count(&owner),
        banks.len(),
        "rebuilt spare must not retain duplicate Weak ownership"
    );
    let ((), retirements, _) = crate::allocation_tests::measure_retired(|| drop(owner));
    assert_eq!(
        retirements, 0,
        "registered Weak values still retain Arc backing"
    );
    let last = banks.remove(&keys[20]).unwrap();
    assert!(last.upgrade().is_none());
    let ((), retirements, _) = crate::allocation_tests::measure_retired(|| banks.clear());
    assert_eq!(
        retirements, 0,
        "one extracted registration still owns the control block"
    );
    let ((), retirements, bytes) = crate::allocation_tests::measure_retired(|| drop(last));
    assert_eq!(
        retirements, 1,
        "the actual last Weak must destroy its allocation before caller credit"
    );
    assert_eq!(bytes, owner_bytes);
}
