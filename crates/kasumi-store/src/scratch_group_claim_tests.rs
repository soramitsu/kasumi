use super::*;
use crate::{
    NodeDiskMemoryAdmission,
    test_utils::{TestDiskMemory, private_tempdir},
};
const GROUP: [u8; 16] = [137; 16];
fn fixture() -> (
    tempfile::TempDir,
    Arc<ScratchDisk>,
    Arc<TestDiskMemory>,
    Arc<Owner>,
    Backend,
    kasumi_kv::Database,
) {
    let directory = private_tempdir().unwrap();
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let owner = Owner::new(&disk, 8 << 20).unwrap();
    let backend = Backend(owner.clone());
    // Actual native creation publishes the initial selected root. The claim
    // validator must authenticate that stored root rather than bypassing it.
    let database = kasumi_kv::Database::builder(
        owner.clone(),
        GROUP,
        kasumi_kv::CacheConfig { byte_limit: 0 },
    )
    .create_with_backend(backend.clone())
    .unwrap();
    (directory, disk, memory, owner, backend, database)
}
fn plan() -> TransactionSpacePlan {
    TransactionSpacePlan {
        group_id: GROUP,
        root_generation: 1,
        batch_seq: 1,
        segment: None,
        directory: None,
        new_segments: FileSpaceRange {
            first_id: 1,
            count: 2,
            minimum_len: 64,
            full_len: 100_000,
            last_len: 100_000,
            total_len: 100_000,
        },
        new_directories: FileSpaceRange::default(),
    }
}
fn close(database: kasumi_kv::Database, disk: &ScratchDisk) {
    let result = database.close_native();
    assert_eq!(
        result.native_disposition(),
        BackendNativeDisposition::Drained
    );
    result.into_result().unwrap();
    drop(database);
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
}
#[test]
fn scratch_claim_pristine_cancel_returns_aggregate_and_prepared_memory_without_file_effects() {
    let (_directory, disk, memory, owner, backend, database) = fixture();
    let before = disk.snapshot();
    let before_memory = memory.snapshot();
    let mut root = [0; ROOT_SLOT_BYTES];
    backend.read_root(RootSlot::A, &mut root).unwrap();
    backend.reserve_transaction(&plan()).unwrap();
    assert_eq!(disk.snapshot().live_files, before.live_files);
    assert!(disk.snapshot().charged_bytes > before.charged_bytes);
    assert!(memory.snapshot().used_bytes > before_memory.used_bytes);
    assert!(
        owner
            .state
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .transaction
            .is_some()
    );
    backend.cancel_transaction(GROUP, 1).unwrap();
    assert_eq!(disk.snapshot().live_files, before.live_files);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(
        disk.snapshot().filesystem_pending_bytes,
        before.filesystem_pending_bytes
    );
    assert_eq!(memory.snapshot().used_bytes, before_memory.used_bytes);
    let mut after = [0; ROOT_SLOT_BYTES];
    backend.read_root(RootSlot::A, &mut after).unwrap();
    assert_eq!(after, root);
    assert!(!backend.exists(GroupFile::segment(1)).unwrap());
    close(database, &disk);
}
#[test]
fn scratch_claim_consumes_real_quota_without_readmission_and_finishes_complete_private_prefix() {
    let (_directory, disk, memory, _owner, backend, database) = fixture();
    let before = disk.snapshot().charged_bytes;
    backend.reserve_transaction(&plan()).unwrap();
    let promised = disk.snapshot().charged_bytes;
    // A simultaneous owner consumes all unassigned quota. Claimed writes must
    // transfer existing rights, not attempt a second capacity reservation.
    let mut competitor = disk
        .reserve_transaction_space((16 << 20) - promised, 0)
        .unwrap();
    let attempts = memory.snapshot().attempts;
    backend.create(GroupFile::segment(1)).unwrap();
    backend
        .write(GroupFile::segment(1), 0, &[7; 65_537])
        .unwrap();
    backend.sync(GroupFile::segment(1)).unwrap();
    assert_eq!(memory.snapshot().attempts, attempts);
    assert_eq!(disk.snapshot().charged_bytes, 16 << 20);
    backend.finish_transaction(GROUP, 1).unwrap();
    assert!(!backend.exists(GroupFile::segment(2)).unwrap());
    assert!(disk.snapshot().charged_bytes < 16 << 20);
    competitor.finish().unwrap();
    assert!(disk.snapshot().charged_bytes > before);
    let mut bytes = [0; 65_537];
    backend.read(GroupFile::segment(1), 0, &mut bytes).unwrap();
    assert_eq!(bytes, [7; 65_537]);
    close(database, &disk);
}
#[test]
fn scratch_claim_capacity_denial_is_before_namespace_or_root_mutation() {
    let (_directory, disk, memory, owner, backend, database) = fixture();
    let before = disk.snapshot();
    let mut impossible = plan();
    impossible.new_segments.count = MAX_FILES as u64 + 1;
    impossible.new_segments.total_len = impossible.new_segments.count * 100_000;
    assert!(matches!(
        backend.reserve_transaction(&impossible),
        Err(TransactionReserveError::CapacityDenied)
    ));
    let mut occupied = Vec::new();
    while let Ok(lease) = memory.clone().reserve_installed(0) {
        occupied.push(lease);
    }
    assert!(matches!(
        backend.reserve_transaction(&plan()),
        Err(TransactionReserveError::CapacityDenied)
    ));
    drop(occupied);
    assert!(
        owner
            .state
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .transaction
            .is_none()
    );
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().live_files, before.live_files);
    owner.check_owner().unwrap();
    close(database, &disk);
}
#[test]
fn scratch_claim_partial_native_acquisition_retains_exact_error_descriptor_and_all_rights() {
    let (directory, disk, _memory, owner, backend, database) = fixture();
    backend.reserve_transaction(&plan()).unwrap();
    #[derive(Debug)]
    struct NativeMarker;
    impl std::fmt::Display for NativeMarker {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("native acquisition marker")
        }
    }
    impl std::error::Error for NativeMarker {}
    let original = io::Error::other(NativeMarker);
    let address = original.get_ref().unwrap() as *const _ as *const () as usize;
    {
        let mut guard = owner.state.lock().unwrap();
        guard
            .as_mut()
            .unwrap()
            .transaction
            .as_mut()
            .unwrap()
            .prepared[0]
            .as_mut()
            .unwrap()
            .spool
            .fail_after_open(original);
    }
    let before = disk.snapshot();
    let error = backend.create(GroupFile::segment(1)).unwrap_err();
    assert_eq!(
        error.get_ref().unwrap() as *const _ as *const () as usize,
        address
    );
    assert!(matches!(
        owner.reserve_workspace(1),
        Err(AdmissionError::OwnerFailed)
    ));
    {
        let guard = owner.state.lock().unwrap();
        let state = guard.as_ref().unwrap();
        assert!(state.failed);
        assert!(
            state.transaction.as_ref().unwrap().prepared[0]
                .as_ref()
                .unwrap()
                .spool
                .acquired()
        );
    }
    assert_eq!(disk.snapshot().live_files, before.live_files + 1);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    for _ in 0..2 {
        assert!(backend.cancel_transaction(GROUP, 1).is_err());
        assert!(backend.finish_transaction(GROUP, 1).is_err());
        assert_eq!(
            backend.close().native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    }
    // This deliberately uncertain acquisition has no disposal proof. Preserve
    // its original diagnostic, exact named descriptor and private directory.
    std::mem::forget((directory, owner, backend, database, error));
}
#[test]
fn scratch_claim_does_not_finish_an_empty_created_file_below_its_promised_minimum() {
    let (directory, disk, _memory, owner, backend, database) = fixture();
    backend.reserve_transaction(&plan()).unwrap();
    backend.create(GroupFile::segment(1)).unwrap();
    let charged = disk.snapshot().charged_bytes;
    assert_eq!(
        backend.finish_transaction(GROUP, 1).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert_eq!(
        backend.close().native_disposition(),
        BackendNativeDisposition::Retained
    );
    std::mem::forget((directory, owner, backend, database));
}

#[test]
fn scratch_claim_wrong_native_header_minimum_fails_before_effects() {
    let (_directory, disk, _memory, owner, backend, database) = fixture();
    let before = disk.snapshot();
    let mut malformed = plan();
    malformed.new_segments.minimum_len = 1;
    let error = backend.reserve_transaction(&malformed).unwrap_err();
    assert!(matches!(error, TransactionReserveError::Failed(_)));
    assert_eq!(disk.snapshot().live_files, before.live_files);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    let guard = owner.state.lock().unwrap();
    let state = guard.as_ref().unwrap();
    assert!(state.transaction.is_none());
    assert_eq!(state.namespace_epoch, 0);
    drop(guard);
    // Pure malformed-plan rejection does not fence the otherwise healthy
    // storage owner. A correct subsequent claim can still reserve and cancel.
    owner.check_owner().unwrap();
    backend.reserve_transaction(&plan()).unwrap();
    backend.cancel_transaction(GROUP, 1).unwrap();
    close(database, &disk);
}

#[test]
fn scratch_claim_corrupt_protected_roots_fence_the_real_owner_and_keep_original_core_error() {
    let (directory, disk, _memory, owner, backend, database) = fixture();
    // Real encrypted root writes preserve spool authenticity but destroy the
    // native mirrored root encoding. The canonical decoder observes corruption.
    for slot in [RootSlot::A, RootSlot::B] {
        backend.write_root(slot, &[0x7b; ROOT_SLOT_BYTES]).unwrap();
    }
    backend.sync_root().unwrap();
    let before = disk.snapshot();
    let error = backend.reserve_transaction(&plan()).unwrap_err();
    let TransactionReserveError::Failed(original) = &error else {
        panic!("corruption is never a capacity refusal");
    };
    assert!(matches!(
        original
            .get_ref()
            .and_then(|source| source.downcast_ref::<kasumi_kv::CoreError>()),
        Some(kasumi_kv::CoreError::Corrupt(_))
    ));
    let guard = owner.state.lock().unwrap();
    let state = guard.as_ref().unwrap();
    assert!(state.failed);
    assert!(state.transaction.is_none());
    assert_eq!(state.namespace_epoch, 0);
    drop(guard);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().live_files, before.live_files);
    assert!(owner.check_owner().is_err());
    assert!(!disk.snapshot().filesystem_admission_ready);
    // Failed physical ownership cannot be retired as a healthy close proof.
    std::mem::forget((directory, owner, backend, database, error));
}

#[test]
fn scratch_claim_reuses_completed_root_validation_slot_before_preparing_files() {
    let (_directory, disk, memory, owner, backend, database) = fixture();
    let mut root = [0; ROOT_SLOT_BYTES];
    backend.read_root(RootSlot::A, &mut root).unwrap();
    // Keep all unrelated owners live. Exactly the two requested file-buffer
    // grants fit; root-validation scratch must be retired before those grants.
    let mut occupied = Vec::new();
    while let Ok(lease) = memory.clone().reserve_installed(0) {
        occupied.push(lease);
    }
    drop(occupied.pop().unwrap());
    drop(occupied.pop().unwrap());
    let before = disk.snapshot();
    let before_memory = memory.snapshot();
    backend.reserve_transaction(&plan()).unwrap();
    let claimed = memory.snapshot();
    assert_eq!(
        claimed.live_reservations,
        before_memory.live_reservations + 2
    );
    assert_eq!(
        claimed.used_bytes,
        before_memory.used_bytes
            + 2 * TestDiskMemory::required_reservation_bytes(FILE_MEMORY_BYTES).unwrap()
    );
    assert_eq!(disk.snapshot().live_files, before.live_files);
    assert!(disk.snapshot().charged_bytes > before.charged_bytes);
    backend.cancel_transaction(GROUP, 1).unwrap();
    assert_eq!(memory.snapshot().used_bytes, before_memory.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        before_memory.live_reservations
    );
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(
        disk.snapshot().filesystem_pending_bytes,
        before.filesystem_pending_bytes
    );

    // One remaining slot is still insufficient. A partial preparation must
    // return its first file grant without publishing a claim or native file.
    let one_slot = memory.clone().reserve_installed(0).unwrap();
    let one_free = memory.snapshot();
    assert!(matches!(
        backend.reserve_transaction(&plan()),
        Err(TransactionReserveError::CapacityDenied)
    ));
    assert_eq!(memory.snapshot().used_bytes, one_free.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        one_free.live_reservations
    );
    assert_eq!(disk.snapshot().live_files, before.live_files);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(
        disk.snapshot().filesystem_pending_bytes,
        before.filesystem_pending_bytes
    );
    assert!(
        owner
            .state
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .transaction
            .is_none()
    );
    let mut after = [0; ROOT_SLOT_BYTES];
    backend.read_root(RootSlot::A, &mut after).unwrap();
    assert_eq!(after, root);
    owner.check_owner().unwrap();
    drop(one_slot);
    drop(occupied);
    close(database, &disk);
}
