use super::*;
use kasumi_engine::{SECURITY_TENANT, SecurityAudit};
use kasumi_store::{NodeStore, StorageAccess, TenantStore, WriteOp};
use std::sync::Arc;

#[test]
fn request_only_old_governors_keep_their_released_facade_capacity() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let persistent = crate::persistent_disk::fixture_config(&directory.path().join("persistent"));
    let original = AdmissionConfig::default();
    let plan = budget(&original, 3, 3, 7, &persistent, &[]).unwrap();
    let total = original.resolved_fixture_total_bytes().unwrap();
    let full = NodeAdmission::required_bookkeeping_bytes(&original).unwrap();
    let core = MemoryCore::required_bookkeeping_bytes(&original).unwrap();
    assert_eq!(
        plan.original_payload,
        6 * (total - full) + 3 * (total - core)
    );
    // Treating all nine original owners as live facades would silently remove
    // this exact capacity from the three request-only governor budgets.
    assert_eq!(
        plan.original_payload - 9 * (total - full),
        3 * (full - core)
    );
    assert_eq!(plan.policy.high_water_bytes, original.high_water_bytes);
    assert_eq!(plan.policy.low_water_bytes, original.low_water_bytes);
    assert_eq!(plan.policy.sample_interval_ms, original.sample_interval_ms);
    assert_eq!(plan.policy.max_sample_age_ms, original.max_sample_age_ms);
    assert_eq!(
        plan.policy.max_snapshot_startups,
        original.max_snapshot_startups
    );
    assert_eq!(
        plan.policy.max_inflight_operations,
        9 * original.max_inflight_operations
    );
    assert_eq!(plan.policy.max_reservations, 9 * original.max_reservations);
    assert_eq!(
        plan.policy.max_startup_scopes,
        9 * original.max_startup_scopes
    );
}

#[test]
fn duplicate_owners_and_excess_rss_are_rejected_before_disk_installation() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let persistent = crate::persistent_disk::fixture_config(&directory.path().join("persistent"));
    let scratch = ScratchDiskConfig {
        directory: directory.path().join("scratch"),
        max_bytes: 256 << 30,
        min_free_bytes: 0,
    };
    let error = budget(
        &AdmissionConfig::default(),
        2,
        0,
        2,
        &persistent,
        &[scratch.clone(), scratch.clone()],
    )
    .err()
    .unwrap();
    assert!(
        error
            .to_string()
            .contains("duplicate fixture scratch owner")
    );
    assert!(!scratch.directory.exists());
    let small_rss = AdmissionConfig {
        high_water_bytes: Some(128 << 20),
        low_water_bytes: Some(112 << 20),
        ..Default::default()
    };
    let error = budget(&small_rss, 3, 3, 7, &persistent, &[]).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("invalid resolved admission budgets")
    );
    assert!(
        budget(
            &AdmissionConfig::default(),
            usize::MAX,
            1,
            usize::MAX,
            &persistent,
            &[]
        )
        .is_err()
    );
}

#[tokio::test]
async fn shared_physical_owner_keeps_facade_shutdown_and_replacement_independent() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let scratch_template = ScratchDiskConfig {
        directory: directory.path().join("unused-template"),
        max_bytes: 256 << 30,
        min_free_bytes: 0,
    };
    let cluster = ClusterStorage::prepare(
        directory.path(),
        2,
        false,
        &AdmissionConfig::default(),
        &scratch_template,
    )
    .unwrap();
    let storage = &cluster.storage;
    let disk = storage.open_persistent(&cluster.persistent).unwrap();
    let scratch_a = storage.open_scratch(&cluster.data_scratch[0]).unwrap();
    let scratch_b = storage.open_scratch(&cluster.data_scratch[1]).unwrap();
    let installed = storage.memory().snapshot().reserved_bytes;
    assert!(Arc::ptr_eq(
        &disk,
        &storage.open_persistent(&cluster.persistent).unwrap()
    ));
    assert!(Arc::ptr_eq(
        &scratch_a,
        &storage.open_scratch(&cluster.data_scratch[0]).unwrap()
    ));
    assert!(Arc::ptr_eq(
        &scratch_b,
        &storage.open_scratch(&cluster.data_scratch[1]).unwrap()
    ));
    assert_eq!(storage.memory().snapshot().reserved_bytes, installed);
    let first = storage.facade(storage.policy()).unwrap();
    let second = storage.facade(storage.policy()).unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert!(Arc::ptr_eq(first.memory(), second.memory()));
    let root = cluster.persistent.roots.values().next().unwrap();
    let a_root = root.join("node-a");
    let b_root = root.join("node-b");
    let _a_directory =
        crate::persistent_disk::open_or_create_directory(&cluster.persistent, &disk, &a_root)
            .unwrap();
    let _b_directory =
        crate::persistent_disk::open_or_create_directory(&cluster.persistent, &disk, &b_root)
            .unwrap();
    let a_id = uuid::Uuid::new_v4();
    let b_id = uuid::Uuid::new_v4();
    let a = NodeStore::create_new(
        a_root.join("node.kv"),
        a_id,
        disk.clone(),
        scratch_a.clone(),
    )
    .unwrap();
    let b = NodeStore::create_new(
        b_root.join("node.kv"),
        b_id,
        disk.clone(),
        scratch_b.clone(),
    )
    .unwrap();
    let provider = Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([3; 32]));
    let a_store = TenantStore::initialize_catalog(
        a.clone(),
        SECURITY_TENANT.into(),
        provider.clone(),
        StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    let b_store = TenantStore::initialize_catalog(
        b.clone(),
        SECURITY_TENANT.into(),
        provider.clone(),
        StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    let a_audit =
        SecurityAudit::initialize(a_store.clone(), Default::default(), first.clone()).unwrap();
    let b_audit =
        SecurityAudit::initialize(b_store.clone(), Default::default(), second.clone()).unwrap();
    assert!(Arc::ptr_eq(a_audit.admission(), &first));
    assert!(Arc::ptr_eq(b_audit.admission(), &second));
    first.drain_snapshot_startups().await.unwrap();
    a_audit.shutdown().await.unwrap();
    a.shutdown().await.unwrap();
    assert!(first.snapshot_buffer_owner().is_err());
    assert!(
        a_store
            .write_batch(&[WriteOp::put("probe", b"closed", b"x")])
            .is_err()
    );
    b_store
        .write_batch(&[WriteOp::put("probe", b"live", b"first")])
        .unwrap();
    assert_eq!(
        b_store.get("probe", b"live").unwrap().as_deref(),
        Some(b"first".as_slice())
    );
    // Drop closed audit/store owners but deliberately retain the sealed facade.
    // Its base stays charged while a third facade overlaps; this checks ownership,
    // not the full two-node payload maximum during that extra observer lifetime.
    drop(a_audit);
    drop(a_store);
    drop(a);
    let replacement = storage.facade(storage.policy()).unwrap();
    assert!(!Arc::ptr_eq(&first, &replacement));
    assert!(Arc::ptr_eq(replacement.memory(), second.memory()));
    let reopened = NodeStore::open_existing(
        a_root.join("node.kv"),
        a_id,
        disk.clone(),
        scratch_a.clone(),
    )
    .unwrap();
    let reopened_store = TenantStore::open_existing(
        reopened.clone(),
        SECURITY_TENANT.into(),
        provider,
        StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    let reopened_audit = SecurityAudit::open(
        reopened_store.clone(),
        Default::default(),
        replacement.clone(),
    )
    .unwrap();
    first.drain_snapshot_startups().await.unwrap();
    let owner = second.snapshot_buffer_owner().unwrap();
    drop(owner);
    let replacement_owner = replacement.snapshot_buffer_owner().unwrap();
    drop(replacement_owner);
    b_store
        .write_batch(&[WriteOp::put("probe", b"live", b"after-replacement")])
        .unwrap();
    reopened_store
        .write_batch(&[WriteOp::put("probe", b"replacement", b"usable")])
        .unwrap();
    assert_eq!(
        b_store.get("probe", b"live").unwrap().as_deref(),
        Some(b"after-replacement".as_slice())
    );
    replacement.drain_snapshot_startups().await.unwrap();
    reopened_audit.shutdown().await.unwrap();
    reopened.shutdown().await.unwrap();
    second.drain_snapshot_startups().await.unwrap();
    b_audit.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
    let before_reuse = storage.memory().snapshot().reserved_bytes;
    assert!(Arc::ptr_eq(
        &disk,
        &storage.open_persistent(&cluster.persistent).unwrap()
    ));
    assert!(Arc::ptr_eq(
        &scratch_a,
        &storage.open_scratch(&cluster.data_scratch[0]).unwrap()
    ));
    assert_eq!(storage.memory().snapshot().reserved_bytes, before_reuse);
}
