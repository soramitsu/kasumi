use super::*;
use crate::admission::{AdmissionConfig, NodeAdmission};
use kasumi_store::{
    TenantStore,
    test_utils::{LocalKeyProvider, NODE_STORE_ID},
};

#[test]
fn audit_maintenance_requires_installed_storage_before_reserving_a_pool() -> anyhow::Result<()> {
    let admission = NodeAdmission::with_fixed_memory(Default::default(), 2 << 30, 0)?;
    let engine = TenantEngine::new(
        "maintenance".into(),
        "initial".into(),
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: [Action::Admin].into_iter().collect(),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )?;
    let before = admission.snapshot();
    let error = engine.install_audit_maintenance(&admission).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(error.message, "install storage before audit maintenance");
    assert!(engine.audit_maintenance.lock().unwrap().is_none());
    let after = admission.snapshot();
    assert_eq!(after.reserved_bytes, before.reserved_bytes);
    assert_eq!(after.live_reservations, before.live_reservations);
    assert_eq!(after.inflight_operations, before.inflight_operations);
    Ok(())
}

#[tokio::test]
async fn audit_maintenance_rejects_foreign_equal_policy_core_and_keeps_exact_pool()
-> anyhow::Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let (persistent, scratch) = crate::test_utils::fixture_disk_configs(directory.path())?;
    let config = AdmissionConfig {
        max_inflight_bytes: Some(
            (256_u64 << 20)
                .checked_add(crate::test_utils::isolated_disk_metadata_bytes(
                    &persistent,
                    &scratch,
                )?)
                .ok_or_else(|| anyhow::anyhow!("fixture metadata budget overflow"))?,
        ),
        ..Default::default()
    };
    let admission = NodeAdmission::with_fixed_memory(config.clone(), 2 << 30, 0)?;
    let foreign = NodeAdmission::with_fixed_memory(config.clone(), 2 << 30, 0)?;
    admission.memory().require_policy(&config)?;
    foreign.memory().require_policy(&config)?;
    assert!(!admission.shares_memory(&foreign));
    let physical = crate::test_utils::FixtureStorage::with_admission(
        &persistent,
        &scratch,
        admission.clone(),
    )?;
    let node = physical.create_new(directory.path().join("persistent/node.redb"), NODE_STORE_ID)?;
    let store = TenantStore::initialize_catalog_fixture(
        node.clone(),
        "maintenance".into(),
        Arc::new(LocalKeyProvider::new([189; 32])),
    )
    .await?;
    node.drain_initializers().await?;
    let engine = TenantEngine::new(
        "maintenance".into(),
        "initial".into(),
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: [Action::Admin].into_iter().collect(),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )?;
    engine.install_storage_access(&store)?;
    let before = admission.snapshot();
    let foreign_before = foreign.snapshot();
    let disk_before = physical.persistent.snapshot();
    let error = engine.install_audit_maintenance(&foreign).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(
        error.message,
        "audit maintenance and physical storage memory owners differ"
    );
    assert!(engine.audit_maintenance.lock().unwrap().is_none());
    for (owner, prior) in [(&admission, before.clone()), (&foreign, foreign_before)] {
        let after = owner.snapshot();
        assert_eq!(after.reserved_bytes, prior.reserved_bytes);
        assert_eq!(after.live_reservations, prior.live_reservations);
        assert_eq!(after.inflight_operations, prior.inflight_operations);
    }
    let disk_after = physical.persistent.snapshot();
    assert_eq!(disk_after.phase, kasumi_store::NodeDiskPhase::Open);
    assert_eq!(disk_after.open_files, disk_before.open_files);
    assert_eq!(disk_after.charged_bytes, disk_before.charged_bytes);
    assert_eq!(disk_after.pending_bytes, disk_before.pending_bytes);

    engine.install_audit_maintenance(&admission)?;
    let installed = engine.audit_maintenance.lock().unwrap().clone().unwrap();
    assert_eq!(
        admission.snapshot().reserved_bytes,
        before.reserved_bytes + crate::audit_maintenance::NodeAuditMaintenance::WORKSPACE_BYTES
    );
    engine.install_audit_maintenance(&admission)?;
    assert!(Arc::ptr_eq(
        &installed,
        engine.audit_maintenance.lock().unwrap().as_ref().unwrap()
    ));
    assert_eq!(
        admission.snapshot().reserved_bytes,
        before.reserved_bytes + crate::audit_maintenance::NodeAuditMaintenance::WORKSPACE_BYTES
    );
    drop(installed);
    drop(engine);
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);
    store.shutdown().await?;
    admission.drain_snapshot_startups().await?;
    foreign.drain_snapshot_startups().await?;
    node.shutdown().await?;
    Ok(())
}
