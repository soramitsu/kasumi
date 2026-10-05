use super::*;
use crate::{
    CensusCancellation,
    test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry},
};
use std::path::Path;

fn fixture(
    files: u64,
    descriptors: u32,
) -> (tempfile::TempDir, Arc<NodeDisk>, Arc<TestDiskMemory>) {
    let directory = private_tempdir().unwrap();
    let mut config = NodeDisk::fixture_config(directory.path().join("unused")).unwrap();
    config.max_persistent_files = files;
    config.max_open_files = descriptors;
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = retry_disk_registry(|| {
        NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default())
    })
    .unwrap();
    (directory, disk, memory)
}
fn ceiling(disk: &NodeDisk, bytes: u64) -> u64 {
    super::super::file_ceiling(bytes, disk.unit, disk.config.file_allocation_policy).unwrap()
}

#[test]
fn complete_atomic_quota_denial_and_pristine_cancel_leave_no_physical_effect() {
    let (directory, disk, _) = fixture(2, 1);
    let root = disk.open_directory("fixture", Path::new("")).unwrap();
    let parent = root.verified_identity().unwrap();
    let bytes = ceiling(&disk, 8192);
    let before = disk.snapshot();
    *disk.available_override.lock().unwrap() =
        Some(before.filesystem_pending_bytes + before.filesystem_min_free_bytes + bytes - 1);
    assert_eq!(
        disk.reserve_transaction_space(parent, bytes, 1, 1, 0)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::StorageFull
    );
    let after = disk.snapshot();
    assert_eq!(after.charged_bytes, before.charged_bytes);
    assert_eq!(after.pending_bytes, before.pending_bytes);
    assert_eq!(after.phase, NodeDiskPhase::Open);
    assert_eq!(disk.lock_state().transaction_witnesses, 0);
    *disk.available_override.lock().unwrap() =
        Some(before.filesystem_pending_bytes + before.filesystem_min_free_bytes + bytes);
    let mut claim = disk
        .reserve_transaction_space(parent, bytes, 1, 1, 0)
        .unwrap();
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes + bytes);
    assert_eq!(
        disk.create_file("fixture", Path::new("unrelated"), DiskWork::Foreground)
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    claim.cancel().unwrap();
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(disk.lock_state().transaction_descriptors, 0);
    assert!(!directory.path().join("unrelated").exists());
    drop(claim);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    *disk.available_override.lock().unwrap() = None;
}

#[test]
fn descriptor_rights_recycle_across_more_files_than_the_peak_without_readmission() {
    let (_directory, disk, memory) = fixture(3, 1);
    let root = disk.open_directory("fixture", Path::new("")).unwrap();
    let before = disk.snapshot();
    let bytes = 3 * ceiling(&disk, 4096);
    let mut claim = disk
        .reserve_transaction_space(root.verified_identity().unwrap(), bytes, 3, 1, 0)
        .unwrap();
    let attempts = memory.snapshot().attempts;
    let charged = disk.snapshot().charged_bytes;
    for name in ["one", "two", "three"] {
        let mut file = disk
            .open_transaction_file(&mut claim, "fixture", Path::new(name), true)
            .unwrap();
        assert_eq!(disk.snapshot().open_files, 1);
        file.reserve_transaction_growth(&mut claim, 0, 4096)
            .unwrap();
        assert_eq!(disk.snapshot().charged_bytes, charged);
        file.write_all_at(&[7; 4096], 0).unwrap();
        file.settle_growth(4096).unwrap();
        assert!(matches!(
            file.close_attested(),
            super::super::NodeDiskCloseOutcome::Entered(Ok(()))
        ));
        claim.descriptor_closed().unwrap();
        assert_eq!(disk.snapshot().open_files, 0);
        assert_eq!(disk.lock_state().transaction_descriptors, 1);
        assert!(
            disk.open_file("fixture", Path::new(name)).is_err(),
            "unrelated reopen cannot spend the promised slot"
        );
    }
    assert_eq!(memory.snapshot().attempts, attempts);
    assert_eq!(
        disk.snapshot().persistent_files,
        before.persistent_files + 3
    );
    assert!(claim.cancel().is_err());
    claim.finish().unwrap();
    assert_eq!(disk.lock_state().transaction_descriptors, 0);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes + bytes);
    let mut file = disk.open_file("fixture", Path::new("one")).unwrap();
    let mut value = [0; 4096];
    file.read_exact_at(&mut value, 0).unwrap();
    assert_eq!(value, [7; 4096]);
    assert!(matches!(
        file.close_attested(),
        super::super::NodeDiskCloseOutcome::Entered(Ok(()))
    ));
}

#[test]
fn growth_transfers_to_the_exact_existing_file_without_double_charge() {
    let (_directory, disk, _) = fixture(1, 1);
    let root = disk.open_directory("fixture", Path::new("")).unwrap();
    let mut file = disk
        .create_file("fixture", Path::new("existing"), DiskWork::Foreground)
        .unwrap();
    file.settle_growth(0).unwrap();
    let delta = file.transaction_growth_quote(0, 8192).unwrap();
    let before = disk.snapshot();
    let mut claim = disk
        .reserve_transaction_space(root.verified_identity().unwrap(), delta, 0, 1, 1)
        .unwrap();
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes + delta);
    file.reserve_transaction_growth(&mut claim, 0, 4096)
        .unwrap();
    file.write_all_at(&[3; 4096], 0).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes + delta);
    file.settle_growth(4096).unwrap();
    claim.finish().unwrap();
    assert_eq!(
        disk.snapshot().charged_bytes,
        before.charged_bytes + ceiling(&disk, 4096) - ceiling(&disk, 0)
    );
    assert!(matches!(
        file.close_attested(),
        super::super::NodeDiskCloseOutcome::Entered(Ok(()))
    ));
}

#[test]
fn zero_file_claim_is_exclusive_and_unrelated_parent_claims_can_coexist() {
    let (_directory, disk, _) = fixture(2, 2);
    let root = disk.open_directory("fixture", Path::new("")).unwrap();
    let first = root.create_child(c"a", DiskWork::Foreground).unwrap();
    let second = root.create_child(c"b", DiskWork::Foreground).unwrap();
    let mut a = disk
        .reserve_transaction_space(first.verified_identity().unwrap(), 0, 0, 1, 0)
        .unwrap();
    assert_eq!(
        disk.reserve_transaction_space(first.verified_identity().unwrap(), 0, 0, 1, 0)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let mut b = disk
        .reserve_transaction_space(second.verified_identity().unwrap(), 0, 0, 1, 0)
        .unwrap();
    assert_eq!(disk.lock_state().transaction_witnesses, 2);
    assert_eq!(disk.lock_state().transaction_descriptors, 2);
    a.cancel().unwrap();
    b.cancel().unwrap();
    assert_eq!(disk.lock_state().transaction_witnesses, 0);
}

#[test]
fn abandoned_effect_keeps_unassigned_bytes_until_real_owner_drain_and_census() {
    let (_directory, disk, _) = fixture(2, 1);
    let root = disk.open_directory("fixture", Path::new("")).unwrap();
    let before = disk.snapshot();
    let bytes = 2 * ceiling(&disk, 4096);
    let mut claim = disk
        .reserve_transaction_space(root.verified_identity().unwrap(), bytes, 2, 1, 0)
        .unwrap();
    let mut file = disk
        .open_transaction_file(&mut claim, "fixture", Path::new("one"), true)
        .unwrap();
    file.reserve_transaction_growth(&mut claim, 0, 4096)
        .unwrap();
    file.write_all_at(&[1; 4096], 0).unwrap();
    file.settle_growth(4096).unwrap();
    assert!(claim.cancel().is_err());
    assert!(matches!(
        file.close_attested(),
        super::super::NodeDiskCloseOutcome::Entered(Ok(()))
    ));
    claim.descriptor_closed().unwrap();
    assert!(
        disk.reconcile(&CensusCancellation::default()).is_err(),
        "live witness prevents census refund"
    );
    drop(claim);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes + bytes);
    assert_eq!(disk.lock_state().transaction_witnesses, 0);
    drop(root);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(
        disk.snapshot().charged_bytes,
        before.charged_bytes + ceiling(&disk, 4096)
    );
    assert_eq!(disk.lock_state().transaction_files, 0);
    assert_eq!(disk.lock_state().transaction_descriptors, 0);
}

#[test]
fn range_rounding_quote_covers_individual_rounding_and_standing_allocations() {
    let (_directory, disk, _) = fixture(8, 1);
    for lengths in [[1, disk.unit - 1], [disk.unit, disk.unit], [3, 5]] {
        let range = kasumi_kv::FileSpaceRange {
            first_id: 1,
            count: 2,
            minimum_len: 1,
            full_len: lengths[0].max(lengths[1]),
            last_len: lengths[1],
            total_len: lengths.iter().sum(),
        };
        let quote = disk.transaction_range_bytes(&range, 4096).unwrap();
        let actual = lengths
            .iter()
            .map(|length| ceiling(&disk, length + 4096))
            .sum::<u64>();
        assert!(quote >= actual);
        assert!(quote - actual <= disk.unit);
    }
}

#[test]
fn panic_after_entered_work_cannot_refund_the_unassigned_part_of_the_claim() {
    let (_directory, disk, memory) = fixture(2, 1);
    let root = disk.open_directory("fixture", Path::new("")).unwrap();
    let before = disk.snapshot();
    let bytes = 2 * ceiling(&disk, 4096);
    let attempts = memory.snapshot().attempts;
    let original = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut claim = disk
            .reserve_transaction_space(root.verified_identity().unwrap(), bytes, 2, 1, 0)
            .unwrap();
        let mut file = disk
            .open_transaction_file(&mut claim, "fixture", Path::new("one"), true)
            .unwrap();
        file.reserve_transaction_growth(&mut claim, 0, 4096)
            .unwrap();
        file.write_all_at(&[1; 4096], 0).unwrap();
        file.settle_growth(4096).unwrap();
        assert!(matches!(
            file.close_attested(),
            super::super::NodeDiskCloseOutcome::Entered(Ok(()))
        ));
        claim.descriptor_closed().unwrap();
        std::panic::panic_any("original transaction caller panic");
    }))
    .unwrap_err();
    assert_eq!(
        original.downcast_ref::<&'static str>(),
        Some(&"original transaction caller panic")
    );
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes + bytes);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(memory.snapshot().attempts, attempts);
    drop(root);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(
        disk.snapshot().charged_bytes,
        before.charged_bytes + ceiling(&disk, 4096)
    );
    assert_eq!(
        original.downcast_ref::<&'static str>(),
        Some(&"original transaction caller panic")
    );
}

#[test]
fn actual_create_parent_sync_failure_retains_claim_and_native_original_custody() {
    let (_directory, disk, _) = fixture(2, 1);
    let root = disk.open_directory("fixture", Path::new("")).unwrap();
    let before = disk.snapshot();
    let bytes = 2 * ceiling(&disk, 4096);
    let mut claim = disk
        .reserve_transaction_space(root.verified_identity().unwrap(), bytes, 2, 1, 0)
        .unwrap();
    disk.namespace_failure.store(
        super::super::file::NamespaceFailure::CreateParentSync as u8,
        std::sync::atomic::Ordering::Relaxed,
    );
    let original = disk
        .open_transaction_file(&mut claim, "fixture", Path::new("one"), true)
        .unwrap_err();
    assert_eq!(original.kind(), io::ErrorKind::Other);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes + bytes);
    assert!(disk.snapshot().retained_file_attempts > 0);
    assert!(claim.cancel().is_err());
    assert!(claim.finish().is_err());
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    drop(claim);
    drop(root);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(original.kind(), io::ErrorKind::Other);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().retained_file_attempts, 0);
}

#[test]
fn claimed_namespace_consumption_does_not_repeat_foreground_or_floor_admission() {
    let (_directory, disk, memory) = fixture(3, 2);
    let root = disk.open_directory("fixture", Path::new("")).unwrap();
    let mut claim = disk
        .reserve_transaction_space(
            root.verified_identity().unwrap(),
            ceiling(&disk, 4096),
            1,
            1,
            0,
        )
        .unwrap();
    let attempts = memory.snapshot().attempts;
    // The existing promise was accepted before this changed observation. Only
    // an ordinary new request performs a new floor decision; actual I/O and
    // owner-health failures would still retain the claimed operation as unknown.
    *disk.available_override.lock().unwrap() = Some(0);
    assert_eq!(
        disk.create_file("fixture", Path::new("ordinary"), DiskWork::Foreground)
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    let mut file = disk
        .open_transaction_file(&mut claim, "fixture", Path::new("claimed"), true)
        .unwrap();
    file.reserve_transaction_growth(&mut claim, 0, 4096)
        .unwrap();
    file.write_all_at(&[4; 4096], 0).unwrap();
    file.settle_growth(4096).unwrap();
    claim.finish().unwrap();
    assert_eq!(memory.snapshot().attempts, attempts);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    *disk.available_override.lock().unwrap() = None;
    assert!(matches!(
        file.close_attested(),
        super::super::NodeDiskCloseOutcome::Entered(Ok(()))
    ));
}

#[test]
fn active_claim_prevents_removal_of_its_empty_parent_even_with_zero_files() {
    for files in [0, 1] {
        let (directory, disk, _) = fixture(2, 1);
        let root = disk.open_directory("fixture", Path::new("")).unwrap();
        let child = root.create_child(c"claimed", DiskWork::Foreground).unwrap();
        let identity = child.verified_identity().unwrap();
        let mut claim = disk
            .reserve_transaction_space(identity, files * ceiling(&disk, 4096), files, 1, 0)
            .unwrap();
        let before = disk.snapshot();
        let generation = disk.lock_state().namespace_generation;
        assert_eq!(
            child.remove_if_empty().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(directory.path().join("claimed").is_dir());
        assert_eq!(disk.lock_state().namespace_generation, generation);
        assert_eq!(disk.lock_state().transaction_witnesses, 1);
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
        assert!(claim.pristine());

        claim.cancel().unwrap();
        assert_eq!(disk.lock_state().transaction_witnesses, 0);
        let child = disk
            .open_directory("fixture", Path::new("claimed"))
            .unwrap();
        assert_eq!(child.verified_identity().unwrap(), identity);
        child.remove_if_empty().unwrap();
        assert!(!directory.path().join("claimed").exists());
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    }
}
