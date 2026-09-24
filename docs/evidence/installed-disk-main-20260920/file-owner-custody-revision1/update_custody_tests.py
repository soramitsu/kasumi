from pathlib import Path
r=Path('target/installed-disk-validation/file-owner-custody-revision1/proposed/crates/kasumi-store/src/node_disk')
p=r/'tests.rs';s=p.read_text()
s=s.replace('''fn clean(disk: &Arc<NodeDisk>, names: &[&str]) {
    assert_eq!(disk.snapshot().open_files, 0);
    disk.reconcile(&CensusCancellation::default()).unwrap();''','''fn clean(disk: &Arc<NodeDisk>, names: &[&str]) {
    {
        let state = disk.lock_state();
        assert_eq!(state.open_files, state.file_custody.internal_owners(), "all external file owners drained");
    }
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(disk.snapshot().retained_file_attempts, 0);''')
def edit(name, transform):
    global s
    a=s.index('fn '+name+'('); b=s.find('\n#[test]',a)
    if b<0: b=len(s)
    old=s[a:b]; new=transform(old); assert new!=old,name
    s=s[:a]+new+s[b:]
for name in ['live_shrink_failure_retains_charges_through_drop_and_fences_shared_device','uncertain_envelope_parent_sync_preserves_charges_through_close_and_census','post_rename_failures_keep_the_charge_and_return_without_allocating','post_reclaim_failures_keep_credit_until_actual_drain_and_census_without_allocating','publication_replaced_private_source_ancestor_fences_before_rename']:
    edit(name,lambda f:f.replace('snapshot().open_files, 0','snapshot().open_files, 1').replace('snapshot.open_files, 0','snapshot.open_files, 1'))
# A failed publication retains the source registration; failed create has no published owner.
edit('missing_enrolled_target_cannot_be_recreated_or_published_over',lambda f:f.replace('disk.snapshot().open_files, 0','disk.snapshot().open_files, u32::from(publish)'))
# Preserve both the successful backing-before-credit barrier and failed retained-backing barrier.
def reclaim(f):
    f=f.replace('stage: file::CloseStage::ResourcesClosed,','stage: if fail { file::CloseStage::ResourcesRetained } else { file::CloseStage::ResourcesClosed },')
    f=f.replace('''        // Resources are gone, but the exact Weak allocation/registration and
        // device promises still belong to this serialized reclaim transition.''','''        // Success physically retires metadata before credit. Failure keeps
        // that same metadata and original outcome under the admitted owner.
        // Both retain the exact Weak registration and serialized promises.''')
    f=f.replace('assert_eq!(after.open_files, 0);','assert_eq!(after.open_files, u32::from(fail));')
    f=f.replace('assert!(disk.lock_state().live.is_empty());','assert_eq!(disk.lock_state().live.is_empty(), !fail);')
    f=f.replace('''        disk.reconcile(&CensusCancellation::default()).unwrap();''','''        disk.reconcile(&CensusCancellation::default()).unwrap();
        assert_eq!(disk.snapshot().open_files, 0);
        assert!(disk.lock_state().live.is_empty());
        assert_eq!(disk.snapshot().retained_file_attempts, 0);''')
    return f
edit('reclaim_retires_parent_metadata_and_weak_backing_before_releasing_promises',reclaim)
s+='''
#[test]
fn file_preparation_unknown_native_close_retains_slot_and_never_retries_descriptor() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config.clone(), memory);
    let before = disk.snapshot();
    let prepared = disk.prepare_file("data", Path::new("absent"), Some(DiskWork::Foreground)).unwrap();
    let descriptor = prepared.parent_descriptor();
    native_file::fail_next_close(libc::EIO);
    let attempts = native_file::close_attempts();
    let ((), allocations) = crate::allocation_tests::measure(|| drop(prepared));
    assert_eq!(allocations, 0);
    assert_eq!(native_file::close_attempts(), attempts + 1);
    let snapshot = disk.snapshot();
    assert_eq!(snapshot.phase, NodeDiskPhase::Failed);
    assert_eq!(snapshot.retained_file_attempts, 1);
    assert_eq!(snapshot.uncertain_file_close, Some((descriptor, libc::EIO)));
    assert_eq!(snapshot.charged_bytes, before.charged_bytes);
    assert_eq!(snapshot.pending_bytes, before.pending_bytes);
    assert_eq!(snapshot.persistent_files, 0);
    assert!(!config.roots["data"].join("absent").exists());
    for _ in 0..2 {
        assert!(disk.pause().is_err());
        assert!(disk.reconcile(&CensusCancellation::default()).is_err());
        assert_eq!(native_file::close_attempts(), attempts + 1, "uncertain integer must never be retried");
        assert_eq!(disk.snapshot().uncertain_file_close, Some((descriptor, libc::EIO)));
        assert_eq!(disk.snapshot().retained_file_attempts, 1);
    }
}

#[test]
fn failed_file_creation_keeps_original_outcome_backing_until_accepted_census() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    let disk = open(config, memory);
    let prepared = disk.prepare_file("data", Path::new("created"), Some(DiskWork::Foreground)).unwrap();
    disk.namespace_failure.store(file::NamespaceFailure::CreateFileSync as u8, Ordering::Relaxed);
    assert_eq!(prepared.execute().unwrap_err().kind(), io::ErrorKind::Other);
    let address = disk.lock_state().file_custody.first_error_address().unwrap();
    assert_eq!(disk.snapshot().retained_file_attempts, 1);
    let cancelled = CensusCancellation::default();
    cancelled.cancel();
    assert!(disk.reconcile(&cancelled).is_err());
    assert_eq!(disk.lock_state().file_custody.first_error_address(), Some(address));
    assert_eq!(disk.snapshot().retained_file_attempts, 1);
    disk.reconcile(&CensusCancellation::default()).unwrap();
    assert_eq!(disk.snapshot().retained_file_attempts, 0);
    assert_eq!(disk.lock_state().file_custody.first_error_address(), None);
    clean(&disk, &["created"]);
}

#[test]
fn file_verification_walk_close_failure_keeps_registered_custody_after_owner_drop() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let (_directory, config) = installation();
    crate::private_files::create_directory(&config.roots["data"].join("child")).unwrap();
    seed(&config, "child/file", 32 << 10);
    let disk = open(config, memory);
    let file = disk.open_file("data", Path::new("child/file")).unwrap();
    let before = disk.snapshot();
    native_file::fail_next_close(libc::EIO);
    let (result, allocations) = crate::allocation_tests::measure(|| file.check_owner());
    assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EIO));
    assert_eq!(allocations, 0);
    let ((), allocations) = crate::allocation_tests::measure(|| drop(file));
    assert_eq!(allocations, 0);
    let after = disk.snapshot();
    assert_eq!(after.open_files, 1);
    assert_eq!(after.retained_file_attempts, 1);
    assert_eq!(after.charged_bytes, before.charged_bytes);
    assert_eq!(after.pending_bytes, before.pending_bytes);
    assert_eq!(after.uncertain_file_close.unwrap().1, libc::EIO);
    let attempts = native_file::close_attempts();
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    assert_eq!(native_file::close_attempts(), attempts);
    assert_eq!(disk.snapshot().open_files, 1);
    assert!(!disk.lock_state().live.is_empty());
}
'''
p.write_text(s)
