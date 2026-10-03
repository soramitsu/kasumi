use super::*;
use crate::{
    NodeDiskMemoryAdmission, NodeDiskPhase,
    test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry},
};
use kasumi_kv::{Core, FileSpaceRange, TransactionReserveError, TransactionSpacePlan};

const ID: Uuid = Uuid::from_u128(0x11eebbaaddcc112211eebbaaddcc1122);
const GROUP: [u8; 16] = [0x61; 16];
fn fixture() -> (
    tempfile::TempDir,
    Arc<TestDiskMemory>,
    Arc<NodeDisk>,
    Arc<NodeSegmentGroup>,
    Core,
) {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("group");
    let memory = TestDiskMemory::new(256 << 20, 64);
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let group = NodeSegmentGroup::retained_prepared(&path, ID, disk.clone(), 1);
    group.acquire_prepared(&NodeOpeningMode::Create).unwrap();
    let core = Core::create_with_backend(
        group.clone(),
        group.clone(),
        GROUP,
        kasumi_kv::CacheConfig::default(),
    )
    .unwrap();
    group.publish_ready().unwrap();
    (directory, memory, disk, group, core)
}
fn plan(count: u64) -> TransactionSpacePlan {
    TransactionSpacePlan {
        group_id: GROUP,
        root_generation: 1,
        batch_seq: 1,
        segment: None,
        directory: None,
        new_segments: FileSpaceRange {
            first_id: 1,
            count,
            minimum_len: 64,
            full_len: 128,
            last_len: 128,
            total_len: count * 128,
        },
        new_directories: FileSpaceRange::default(),
    }
}
fn retire_failed(group: &NodeSegmentGroup, disk: &NodeDisk) {
    let outcome = group.close();
    assert_eq!(
        outcome.native_disposition(),
        BackendNativeDisposition::Drained
    );
    if outcome.into_result().is_err() {
        let witness = group.failed_close_witness().unwrap();
        assert!(group.transfer_failed(&witness).unwrap());
    }
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
}

fn root_images(group: &NodeSegmentGroup) -> [[u8; ROOT_SLOT_BYTES]; 2] {
    let mut images = [[0; ROOT_SLOT_BYTES]; 2];
    group.read_root(RootSlot::A, &mut images[0]).unwrap();
    group.read_root(RootSlot::B, &mut images[1]).unwrap();
    images
}

#[test]
fn claim_transfers_actual_group_files_through_one_descriptor_cache_without_new_admission() {
    let (_directory, memory, disk, group, core) = fixture();
    let before = disk.snapshot();
    let plan = plan(3);
    group.reserve_transaction(&plan).unwrap();
    let promised = disk.snapshot().charged_bytes;
    let attempts = memory.snapshot().attempts;
    for id in 1..=3 {
        let file = GroupFile::segment(id);
        group.create(file).unwrap();
        group.write(file, 0, &[id as u8; 128]).unwrap();
        group.sync(file).unwrap();
        assert!(disk.snapshot().charged_bytes <= promised);
        assert_eq!(group.cached_files(), 1);
        assert_eq!(disk.snapshot().open_files, before.open_files + 1);
    }
    assert_eq!(memory.snapshot().attempts, attempts);
    assert!(group.cancel_transaction(GROUP, 1).is_err());
    group.finish_transaction(GROUP, 1).unwrap();
    assert_eq!(memory.snapshot().attempts, attempts);
    assert_eq!(
        disk.snapshot().persistent_files,
        before.persistent_files + 3
    );
    assert!(disk.snapshot().charged_bytes <= promised);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    for id in 1..=3 {
        let mut bytes = [0; 128];
        group.read(GroupFile::segment(id), 0, &mut bytes).unwrap();
        assert_eq!(bytes, [id as u8; 128]);
    }
    assert!(core.close().into_result().is_ok());
}

#[test]
fn metadata_shortage_precedes_root_or_file_effects_and_targeted_retry_works() {
    let (_directory, memory, disk, group, core) = fixture();
    let images = root_images(&group);
    let before = disk.snapshot();
    // Saturate actual metadata registrations; limits are unchanged. The first
    // failed request is the concrete root-image validation workspace grant.
    let mut held = Vec::new();
    while memory.snapshot().live_reservations < 64 {
        held.push(memory.clone().reserve_installed(1).unwrap());
    }
    let attempts = memory.snapshot().attempts;
    assert!(matches!(
        group.reserve_transaction(&plan(1)),
        Err(TransactionReserveError::CapacityDenied)
    ));
    assert_eq!(memory.snapshot().attempts, attempts + 1);
    assert_eq!(root_images(&group), images);
    assert!(!group.exists(GroupFile::segment(1)).unwrap());
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    drop(held);
    group.reserve_transaction(&plan(1)).unwrap();
    group.cancel_transaction(GROUP, 1).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert!(core.close().into_result().is_ok());
}

#[test]
fn stale_generation_foreign_incarnation_and_wrong_terminal_identity_are_rejected() {
    let (_directory, _memory, disk, group, core) = fixture();
    let before = disk.snapshot();
    let mut stale = plan(1);
    stale.root_generation += 1;
    assert!(matches!(
        group.reserve_transaction(&stale),
        Err(TransactionReserveError::Failed(_))
    ));
    stale = plan(1);
    stale.group_id[0] ^= 1;
    assert!(matches!(
        group.reserve_transaction(&stale),
        Err(TransactionReserveError::Failed(_))
    ));
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    group.reserve_transaction(&plan(1)).unwrap();
    assert!(group.finish_transaction(GROUP, 2).is_err());
    assert!(group.cancel_transaction([0; 16], 1).is_err());
    assert!(group.reserve_transaction(&plan(1)).is_err());
    group.cancel_transaction(GROUP, 1).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert!(core.close().into_result().is_ok());
}

#[test]
fn incomplete_envelope_or_native_minimum_cannot_finish_and_refund_a_claim() {
    for written in [0, 1] {
        let (_directory, _memory, disk, group, _core) = fixture();
        group.reserve_transaction(&plan(2)).unwrap();
        let promised = disk.snapshot().charged_bytes;
        group.create(GroupFile::segment(1)).unwrap();
        if written != 0 {
            group.write(GroupFile::segment(1), 0, &[9]).unwrap();
        }
        let error = group.finish_transaction(GROUP, 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
        assert_eq!(disk.snapshot().charged_bytes, promised);
        assert!(group.state.read().open().unwrap().transaction.is_some());
        assert!(group.cancel_transaction(GROUP, 1).is_err());
        // Existing failed-group descriptor custody is the only cleanup path.
        // Close must never turn the retained physical promise into a refund.
        let _outcome = group.close();
        assert_eq!(disk.snapshot().charged_bytes, promised);
        retire_failed(&group, &disk);
    }
}

#[test]
fn plan_overrun_keeps_original_promise_and_forbids_any_retry_effect() {
    let (_directory, _memory, disk, group, _core) = fixture();
    let mut bounded = plan(2);
    bounded.new_segments.total_len = 192;
    group.reserve_transaction(&bounded).unwrap();
    let promised = disk.snapshot().charged_bytes;
    group.create(GroupFile::segment(1)).unwrap();
    group.write(GroupFile::segment(1), 0, &[1; 128]).unwrap();
    group.create(GroupFile::segment(2)).unwrap();
    let original = group
        .write(GroupFile::segment(2), 0, &[2; 128])
        .unwrap_err();
    assert_eq!(original.kind(), io::ErrorKind::InvalidData);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().charged_bytes, promised);
    assert!(group.finish_transaction(GROUP, 1).is_err());
    assert!(group.write(GroupFile::segment(2), 0, &[2; 64]).is_err());
    let _outcome = group.close();
    assert_eq!(disk.snapshot().charged_bytes, promised);
    retire_failed(&group, &disk);
}

#[test]
fn caller_lowered_native_minimum_is_refused_before_root_or_file_effects() {
    let (_directory, memory, disk, group, core) = fixture();
    let images = root_images(&group);
    let before = disk.snapshot();
    let resident = memory.snapshot();
    let mut malformed = plan(1);
    // Scalar shape alone accepts this. The canonical native validator must
    // reject a caller attempting to turn one byte into a complete segment.
    malformed.new_segments.minimum_len = 1;
    malformed.validate().unwrap();
    let failure = group.reserve_transaction(&malformed).unwrap_err();
    assert!(matches!(failure, TransactionReserveError::Failed(_)));
    assert_eq!(root_images(&group), images);
    assert!(!group.exists(GroupFile::segment(1)).unwrap());
    assert!(group.state.read().open().unwrap().transaction.is_none());
    let after = disk.snapshot();
    assert_eq!(after.phase, NodeDiskPhase::Open);
    assert_eq!(after.charged_bytes, before.charged_bytes);
    assert_eq!(after.persistent_files, before.persistent_files);
    assert_eq!(after.open_files, before.open_files);
    assert_eq!(memory.snapshot().used_bytes, resident.used_bytes);
    group.check_owner().unwrap();
    // The malformed request neither installed a claim nor poisoned admission.
    group.reserve_transaction(&plan(1)).unwrap();
    group.cancel_transaction(GROUP, 1).unwrap();
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert!(core.close().into_result().is_ok());
}

#[test]
fn protected_root_corruption_fences_the_owner_and_retains_the_native_source() {
    let (_directory, _memory, disk, group, _core) = fixture();
    let corrupt = [0xff; ROOT_SLOT_BYTES];
    group.write_root(RootSlot::A, &corrupt).unwrap();
    group.write_root(RootSlot::B, &corrupt).unwrap();
    group.sync_root().unwrap();
    assert_eq!(root_images(&group), [corrupt; 2]);
    let before = disk.snapshot();
    assert_eq!(before.phase, NodeDiskPhase::Open);
    assert!(!group.failed.load(Ordering::Acquire));

    let original = match group.reserve_transaction(&plan(1)) {
        Err(TransactionReserveError::Failed(error)) => error,
        outcome => panic!("actual corrupt root must retain a native failure: {outcome:?}"),
    };
    let native = || {
        original
            .get_ref()
            .unwrap()
            .downcast_ref::<kasumi_kv::CoreError>()
    };
    assert!(matches!(
        native(),
        Some(kasumi_kv::CoreError::Corrupt("no intact root slot"))
    ));
    assert!(group.failed.load(Ordering::Acquire));
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert!(group.state.read().open().unwrap().transaction.is_none());
    assert!(group.create(GroupFile::segment(1)).is_err());
    assert!(
        group
            .write_root(RootSlot::A, &[0; ROOT_SLOT_BYTES])
            .is_err()
    );
    assert!(group.reserve_transaction(&plan(1)).is_err());

    retire_failed(&group, &disk);
    assert!(matches!(
        native(),
        Some(kasumi_kv::CoreError::Corrupt("no intact root slot"))
    ));
}

#[test]
fn namespace_epoch_exhaustion_refuses_the_whole_range_before_claim_admission() {
    let (_directory, memory, disk, group, core) = fixture();
    let images = root_images(&group);
    let before = disk.snapshot();
    let attempts = memory.snapshot().attempts;
    {
        let mut guard = group.state.write();
        let (resources, _) = guard.open_mut().unwrap();
        resources.namespace_epoch = u64::MAX - 1;
    }
    assert!(matches!(
        group.reserve_transaction(&plan(2)),
        Err(TransactionReserveError::CapacityDenied)
    ));
    assert_eq!(memory.snapshot().attempts, attempts);
    assert_eq!(root_images(&group), images);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert!(!group.failed.load(Ordering::Acquire));
    assert!(group.state.read().open().unwrap().transaction.is_none());
    assert!(!group.exists(GroupFile::segment(1)).unwrap());
    assert!(!group.exists(GroupFile::segment(2)).unwrap());

    // One remaining epoch is sufficient for exactly one real file. This also
    // proves the rejected range left no stale claim or unhealthy owner.
    group.reserve_transaction(&plan(1)).unwrap();
    group.create(GroupFile::segment(1)).unwrap();
    group.write(GroupFile::segment(1), 0, &[1; 128]).unwrap();
    group.finish_transaction(GROUP, 1).unwrap();
    assert_eq!(group.state.read().open().unwrap().namespace_epoch, u64::MAX);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert!(core.close().into_result().is_ok());
}
