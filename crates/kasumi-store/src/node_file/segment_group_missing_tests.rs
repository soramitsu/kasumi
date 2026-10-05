//! A missing enrolled group must pass through its actual physical owner.
use super::*;
use crate::{
    NodeDiskMemoryAdmission, NodeDiskPhase, NodeStore, RegisteredNodeOpening, ScratchDisk,
    test_utils::{TestDiskMemory, node_storage_config, private_tempdir, retry_disk_registry},
};
use kasumi_kv::DatabaseOpenSettlement;
use kasumi_types::drain::{DrainCompletion, DrainIssueRef};
use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
};

const JOURNAL_ID: Uuid = Uuid::from_u128(0x7c42_9a3d_0f75_4c46_8f02_24be_ee5c_4031);
const TARGET_ID: Uuid = Uuid::from_u128(0x632a_b270_202e_41c2_923f_0d52_4371_9dc7);

#[tokio::test]
async fn missing_enrolled_group_fences_shared_owner_and_preserves_independent_close_original() {
    let directory = private_tempdir().unwrap();
    let scratch_directory = private_tempdir().unwrap();
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let journal_path = directory.path().join("journal.kv");
    let target_path = directory.path().join("target.kv");
    let disk =
        retry_disk_registry(|| NodeDisk::fixture_for_path(&journal_path, memory.clone())).unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let journal = NodeStore::create_new(
        &journal_path,
        JOURNAL_ID,
        disk.clone(),
        scratch.clone(),
        node_storage_config(),
    )
    .unwrap();
    let target = NodeStore::create_new(
        &target_path,
        TARGET_ID,
        disk.clone(),
        scratch.clone(),
        node_storage_config(),
    )
    .unwrap();
    target.shutdown().await.unwrap();
    drop(target);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    let registered = memory.storage_census().snapshot().databases;
    std::fs::remove_dir_all(&target_path).unwrap();
    let missing = NodeStore::open_existing(
        &target_path,
        TARGET_ID,
        disk.clone(),
        scratch,
        node_storage_config(),
    )
    .err()
    .expect("replay must refuse the removed enrolled group");
    assert!(!target_path.exists());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    assert_eq!(memory.storage_census().snapshot().databases, registered + 1);
    drop(missing);

    let opening_id = journal.registered_opening_id().unwrap();
    let first = journal.shutdown().await.unwrap_err();
    assert_eq!(first.completion(), DrainCompletion::Retained);
    let original = first
        .issues()
        .iter()
        .find(|issue| issue.component() == "node database")
        .expect("independent journal must retain its real failed physical close");
    assert_eq!(
        original.error().to_string(),
        format!("registered node opening {opening_id:?} close settled DrainedWithFailure")
    );
    let retained = RegisteredNodeOpening::retained(memory, opening_id).unwrap();
    assert_eq!(
        retained.report().engine().settlement(),
        DatabaseOpenSettlement::DrainedWithFailure
    );
    let repeated = journal.shutdown().await.unwrap_err();
    assert!(
        repeated
            .issues()
            .iter()
            .any(|again| DrainIssueRef::ptr_eq(again, original))
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
}

#[tokio::test]
async fn unknown_absent_group_refuses_without_fencing_or_creating_and_sibling_closes_cleanly() {
    let directory = private_tempdir().unwrap();
    let scratch_directory = private_tempdir().unwrap();
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let journal_path = directory.path().join("journal.kv");
    let absent_path = directory.path().join("unknown.kv");
    let disk =
        retry_disk_registry(|| NodeDisk::fixture_for_path(&journal_path, memory.clone())).unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory);
    let journal = NodeStore::create_new(
        &journal_path,
        JOURNAL_ID,
        disk.clone(),
        scratch.clone(),
        node_storage_config(),
    )
    .unwrap();
    let missing = NodeStore::open_existing(
        &absent_path,
        TARGET_ID,
        disk.clone(),
        scratch,
        node_storage_config(),
    )
    .err()
    .expect("unknown absence cannot authorize creation");
    assert!(!absent_path.exists());
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    drop(missing);
    journal.shutdown().await.unwrap();
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
}

#[test]
fn present_single_file_is_strictly_rejected_before_directory_owner_dispatch() {
    let directory = private_tempdir().unwrap();
    let path = directory.path().join("single-file.kv");
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .unwrap()
        .write_all(b"unsupported single-file payload")
        .unwrap();
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let (root, relative) = disk.binding(&path).unwrap();
    let before_lookup = memory.snapshot();
    let (kind, allocations) =
        crate::allocation_tests::measure(|| disk.enrolled_name_kind(root, relative));
    assert_eq!(kind.unwrap(), Some(NodeDiskEntryKind::File));
    assert_eq!(allocations, 0, "enrolled kind lookup allocated backing");
    assert_eq!(memory.snapshot(), before_lookup);
    let group = NodeSegmentGroup::retained_prepared(&path, TARGET_ID, disk.clone(), 8);
    let error = group
        .acquire_prepared(&NodeOpeningMode::Existing)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("single-file node format is unsupported")
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().open_directories, 0);
    group.close().into_result().unwrap();
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"unsupported single-file payload"
    );
}

#[derive(Clone, Copy)]
enum Replacement {
    File,
    Symlink,
}

async fn directory_replacement_fences_canonical_owner(replacement: Replacement) {
    let directory = private_tempdir().unwrap();
    let scratch_directory = private_tempdir().unwrap();
    let outside = private_tempdir().unwrap();
    let path = directory.path().join("target.kv");
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    let node = NodeStore::create_new(
        &path,
        TARGET_ID,
        disk.clone(),
        ScratchDisk::fixture(scratch_directory.path(), memory.clone()),
        node_storage_config(),
    )
    .unwrap();
    node.shutdown().await.unwrap();
    drop(node);
    let (root, relative) = disk.binding(&path).unwrap();
    let before_lookup = memory.snapshot();
    let (kind, allocations) =
        crate::allocation_tests::measure(|| disk.enrolled_name_kind(root, relative));
    assert_eq!(kind.unwrap(), Some(NodeDiskEntryKind::Directory));
    assert_eq!(allocations, 0);
    assert_eq!(memory.snapshot(), before_lookup);
    std::fs::remove_dir_all(&path).unwrap();
    match replacement {
        Replacement::File => std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap()
            .write_all(b"replacement is not a native directory")
            .unwrap(),
        Replacement::Symlink => std::os::unix::fs::symlink(outside.path(), &path).unwrap(),
    }
    // Prove that intact ancestry alone remains healthy; the observed mismatch
    // is this exact enrolled final name's kind, not another changed parent.
    let parent = disk
        .open_directory(root, relative.parent().unwrap_or(Path::new("")))
        .unwrap();
    parent.verified_identity().unwrap();
    drop(parent);
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Open);
    let group = NodeSegmentGroup::retained_prepared(&path, TARGET_ID, disk.clone(), 8);
    let error = group
        .acquire_prepared(&NodeOpeningMode::Existing)
        .unwrap_err();
    assert!(
        !error
            .to_string()
            .contains("single-file node format is unsupported")
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    group.close().into_result().unwrap();
}

#[tokio::test]
async fn enrolled_native_directory_replaced_with_private_file_fences_actual_owner() {
    directory_replacement_fences_canonical_owner(Replacement::File).await;
}

#[tokio::test]
async fn enrolled_native_directory_replaced_with_symlink_fences_actual_owner() {
    directory_replacement_fences_canonical_owner(Replacement::Symlink).await;
}

#[test]
fn unsupported_file_under_replaced_enrolled_ancestor_cannot_skip_actual_validation() {
    let directory = private_tempdir().unwrap();
    let outside = private_tempdir().unwrap();
    let nested = directory.path().join("nested");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&nested)
        .unwrap();
    let path = nested.join("legacy.kv");
    let write_legacy = || {
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap()
            .write_all(b"unsupported single-file payload")
            .unwrap()
    };
    write_legacy();
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
    std::fs::rename(&nested, outside.path().join("original-nested")).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&nested)
        .unwrap();
    write_legacy();
    let group = NodeSegmentGroup::retained_prepared(&path, TARGET_ID, disk.clone(), 8);
    let error = group
        .acquire_prepared(&NodeOpeningMode::Existing)
        .unwrap_err();
    assert!(
        !error
            .to_string()
            .contains("single-file node format is unsupported")
    );
    assert_eq!(disk.snapshot().phase, NodeDiskPhase::Failed);
    group.close().into_result().unwrap();
}
