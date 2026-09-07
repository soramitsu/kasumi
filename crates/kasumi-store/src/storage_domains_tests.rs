use super::*;
use crate::test_utils::{FaultBackend, LocalKeyProvider, ManualClock};

async fn installed(node: Arc<NodeStore>) -> Result<Arc<TenantStorageSet>> {
    let app = TenantStore::open_fixture_with_clock(
        node.clone(),
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([11; 32])),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let custody = TenantStore::open_fixture_with_clock(
        node,
        CustodyStore::catalog_name("tenant"),
        Arc::new(LocalKeyProvider::new([12; 32])),
        Arc::new(ManualClock::new()),
    )
    .await?;
    TenantStorageSet::install(app, custody)
}

#[tokio::test]
async fn domains_require_distinct_actual_wrapping_policies_and_same_node() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let node = NodeStore::open(dir.path().join("same.redb"))?;
    let provider = Arc::new(LocalKeyProvider::new([1; 32]));
    let app = TenantStore::open_fixture(node.clone(), "tenant".into(), provider.clone()).await?;
    let control =
        TenantStore::open_fixture(node, CustodyStore::catalog_name("tenant"), provider).await?;
    assert!(TenantStorageSet::install(app.clone(), control.clone()).is_err());
    assert!(control.get(BINDING_NS, BINDING_KEY)?.is_none());
    let other = TenantStore::open_fixture(
        NodeStore::open(dir.path().join("other.redb"))?,
        CustodyStore::catalog_name("tenant"),
        Arc::new(LocalKeyProvider::new([2; 32])),
    )
    .await?;
    assert!(TenantStorageSet::install(app, other).is_err());
    let reserved = NodeStore::open(dir.path().join("reserved.redb"))?;
    assert!(
        TenantStorageSet::open_fixture(
            reserved.clone(),
            "kasumi.custody/tenant".into(),
            Arc::new(LocalKeyProvider::new([3; 32])),
            Arc::new(LocalKeyProvider::new([4; 32]))
        )
        .await
        .is_err()
    );
    assert!(
        reserved.catalog("kasumi.custody/tenant")?.is_none(),
        "reserved namespace must fail before opening either key domain"
    );
    Ok(())
}

#[tokio::test]
async fn control_reopens_without_any_application_key_probe_after_revocation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("revoked.redb");
    let app_provider = Arc::new(LocalKeyProvider::new([11; 32]));
    let control_provider = Arc::new(LocalKeyProvider::new([12; 32]));
    let node = NodeStore::open(&path)?;
    let stores = TenantStorageSet::open_fixture(
        node.clone(),
        "tenant".into(),
        app_provider.clone(),
        control_provider.clone(),
    )
    .await?;
    stores.write_batch(
        &[WriteOp::put("payload", b"secret", b"municipal-data")],
        &[WriteOp::put("control", b"position", b"exact-commit")],
    )?;
    let binding = stores.custody().binding().clone();
    app_provider.revoke();
    assert!(stores.application().refresh_lease().await.is_err());
    let probes = app_provider.probe_count();
    assert!(
        stores
            .write_batch(&[], &[WriteOp::put("control", b"position", b"bad")])
            .is_err()
    );
    assert_eq!(
        stores
            .custody()
            .store()
            .get("control", b"position")?
            .unwrap(),
        b"exact-commit"
    );
    stores.application().shutdown().await;
    stores.custody().store().shutdown().await;
    drop(stores);
    drop(node);
    let reopened =
        CustodyStore::open(NodeStore::open(&path)?, "tenant".into(), control_provider).await?;
    assert_eq!(reopened.binding(), &binding);
    assert_eq!(
        reopened.store().get("control", b"position")?.unwrap(),
        b"exact-commit"
    );
    assert_eq!(app_provider.probe_count(), probes);
    reopened.store().shutdown().await;
    Ok(())
}

#[tokio::test]
async fn every_interrupted_domain_transaction_recovers_whole_old_or_whole_new() -> Result<()> {
    let original = FaultBackend::new();
    let stores = installed(NodeStore::open_with_backend(original.clone())?).await?;
    stores.write_batch(
        &[WriteOp::put("data", b"entry", b"old")],
        &[WriteOp::put("control", b"entry", b"old")],
    )?;
    let starting = original.crash();
    drop(stores);
    let mut successes = 0;
    let mut failures = 0;
    for failure in 0..40 {
        let disk = starting.crash();
        let stores = installed(NodeStore::open_with_backend(disk.clone())?).await?;
        disk.fail_after(failure);
        let result = stores.write_batch(
            &[WriteOp::put("data", b"entry", b"new")],
            &[WriteOp::put("control", b"entry", b"new")],
        );
        let crashed = disk.crash();
        disk.disarm();
        drop(stores);
        let reopened = installed(NodeStore::open_with_backend(crashed)?).await?;
        let data = reopened.application().get("data", b"entry")?.unwrap();
        let control = reopened
            .custody()
            .store()
            .get("control", b"entry")?
            .unwrap();
        assert_eq!(data, control, "split transaction after failure {failure}");
        assert!(data == b"old" || data == b"new");
        if result.is_ok() {
            successes += 1;
            assert_eq!(data, b"new");
        } else {
            failures += 1;
        }
    }
    assert!(successes > 0 && failures > 0);
    Ok(())
}

#[tokio::test]
async fn post_commit_domain_expiry_reports_uncertainty_and_retains_complete_write() -> Result<()> {
    let disk = FaultBackend::new();
    let node = NodeStore::open_with_backend(disk.clone())?;
    let clock = Arc::new(ManualClock::new());
    let app = TenantStore::open_fixture_with_clock(
        node.clone(),
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([11; 32])),
        clock.clone(),
    )
    .await?;
    let custody = TenantStore::open_fixture_with_clock(
        node,
        CustodyStore::catalog_name("tenant"),
        Arc::new(LocalKeyProvider::new([12; 32])),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let stores = TenantStorageSet::install(app, custody)?;
    disk.advance_clock_on_next_sync(clock, MAX_KEY_LEASE);
    let error = stores
        .write_batch(
            &[WriteOp::put("data", b"entry", b"new")],
            &[WriteOp::put("control", b"entry", b"new")],
        )
        .unwrap_err();
    assert!(error.to_string().contains("outcome unknown"));
    assert!(stores.application().check_access().is_err());
    let recovered = disk.crash();
    drop(stores);
    let reopened = installed(NodeStore::open_with_backend(recovered)?).await?;
    assert_eq!(
        reopened.application().get("data", b"entry")?.unwrap(),
        b"new"
    );
    assert_eq!(
        reopened
            .custody()
            .store()
            .get("control", b"entry")?
            .unwrap(),
        b"new"
    );
    Ok(())
}

#[tokio::test]
async fn combined_quota_and_substituted_catalog_binding_fail_before_publication() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let node = NodeStore::open(dir.path().join("binding.redb"))?;
    let stores = installed(node.clone()).await?;
    let ops = vec![WriteOp::put("data", b"entry", b"a"); 32769];
    assert!(stores.write_batch(&ops, &ops).is_err());
    assert!(stores.application().get("data", b"entry")?.is_none());
    let mut catalog = node.catalog("tenant")?.unwrap();
    catalog.catalog_id = Uuid::new_v4();
    node.save_catalog("tenant", &catalog)?;
    let result =
        CustodyStore::from_installed(node, "tenant".into(), stores.custody().store().clone());
    assert!(result.is_err());
    Ok(())
}
