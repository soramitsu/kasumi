use super::*;
use crate::test_utils::{FaultBackend, LocalKeyProvider, ManualClock};

async fn initialize_pair_fixture(node: Arc<NodeStore>) -> Result<Arc<TenantStorageSet>> {
    let app = TenantStore::initialize_catalog_fixture_with_clock(
        node.clone(),
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([11; 32])),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let custody = TenantStore::initialize_catalog_fixture_with_clock(
        node,
        CustodyStore::catalog_name("tenant"),
        Arc::new(LocalKeyProvider::new([12; 32])),
        Arc::new(ManualClock::new()),
    )
    .await?;
    TenantStorageSet::install(app, custody)
}

async fn existing_pair_fixture(node: Arc<NodeStore>) -> Result<Arc<TenantStorageSet>> {
    let application = Arc::new(LocalKeyProvider::new([11; 32]));
    let custody = Arc::new(LocalKeyProvider::new([12; 32]));
    let app = TenantStore::open_existing_fixture_with_clock(
        node.clone(),
        "tenant".into(),
        application.clone(),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let control = TenantStore::open_existing_fixture_with_clock(
        node.clone(),
        CustodyStore::catalog_name("tenant"),
        custody.clone(),
        Arc::new(ManualClock::new()),
    )
    .await?;
    let result = TenantStorageSet::open_existing(
        node.clone(),
        "tenant".into(),
        application,
        custody,
        StorageAccess::fixture(),
    )
    .await;
    if result.is_err() {
        app.shutdown().await.unwrap();
        control.shutdown().await.unwrap();
        node.drain_initializers().await?;
    }
    result
}

#[tokio::test]
async fn domains_require_distinct_actual_wrapping_policies_and_same_node() -> Result<()> {
    let dir = crate::test_utils::private_tempdir()?;
    let node = NodeStore::create_new_fixture(
        dir.path().join("same.redb"),
        crate::test_utils::NODE_STORE_ID,
        crate::ScratchDisk::fixture(),
    )?;
    let provider = Arc::new(LocalKeyProvider::new([1; 32]));
    let app =
        TenantStore::initialize_catalog_fixture(node.clone(), "tenant".into(), provider.clone())
            .await?;
    let control = TenantStore::initialize_catalog_fixture(
        node,
        CustodyStore::catalog_name("tenant"),
        provider,
    )
    .await?;
    assert!(TenantStorageSet::install(app.clone(), control.clone()).is_err());
    assert!(control.get(BINDING_NS, BINDING_KEY)?.is_none());
    let other = TenantStore::initialize_catalog_fixture(
        NodeStore::create_new_fixture(
            dir.path().join("other.redb"),
            crate::test_utils::NODE_STORE_ID,
            crate::ScratchDisk::fixture(),
        )?,
        CustodyStore::catalog_name("tenant"),
        Arc::new(LocalKeyProvider::new([2; 32])),
    )
    .await?;
    assert!(TenantStorageSet::install(app, other).is_err());
    let reserved = NodeStore::create_new_fixture(
        dir.path().join("reserved.redb"),
        crate::test_utils::NODE_STORE_ID,
        crate::ScratchDisk::fixture(),
    )?;
    assert!(
        TenantStorageSet::initialize_catalogs_fixture(
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
    let dir = crate::test_utils::private_tempdir()?;
    let path = dir.path().join("revoked.redb");
    let app_provider = Arc::new(LocalKeyProvider::new([11; 32]));
    let control_provider = Arc::new(LocalKeyProvider::new([12; 32]));
    let node = NodeStore::create_new_fixture(
        &path,
        crate::test_utils::NODE_STORE_ID,
        crate::ScratchDisk::fixture(),
    )?;
    let stores = TenantStorageSet::initialize_catalogs_fixture(
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
    stores.shutdown().await.unwrap();
    drop(stores);
    drop(node);
    let reopened = CustodyStore::open(
        NodeStore::open_existing_fixture(
            &path,
            crate::test_utils::NODE_STORE_ID,
            crate::ScratchDisk::fixture(),
        )?,
        "tenant".into(),
        control_provider,
    )
    .await?;
    assert_eq!(reopened.binding(), &binding);
    assert_eq!(
        reopened.store().get("control", b"position")?.unwrap(),
        b"exact-commit"
    );
    assert_eq!(app_provider.probe_count(), probes);
    reopened.store().shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn every_interrupted_domain_transaction_recovers_whole_old_or_whole_new() -> Result<()> {
    let original = FaultBackend::new();
    let stores = initialize_pair_fixture(NodeStore::open_with_backend(
        original.clone(),
        crate::test_utils::storage_admission(),
        crate::ScratchDisk::fixture(),
    )?)
    .await?;
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
        let stores = existing_pair_fixture(NodeStore::open_with_backend(
            disk.clone(),
            crate::test_utils::storage_admission(),
            crate::ScratchDisk::fixture(),
        )?)
        .await?;
        disk.fail_after(failure);
        let result = stores.write_batch(
            &[WriteOp::put("data", b"entry", b"new")],
            &[WriteOp::put("control", b"entry", b"new")],
        );
        let crashed = disk.crash();
        disk.disarm();
        drop(stores);
        let reopened = existing_pair_fixture(NodeStore::open_with_backend(
            crashed,
            crate::test_utils::storage_admission(),
            crate::ScratchDisk::fixture(),
        )?)
        .await?;
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
    let node = NodeStore::open_with_backend(
        disk.clone(),
        crate::test_utils::storage_admission(),
        crate::ScratchDisk::fixture(),
    )?;
    let clock = Arc::new(ManualClock::new());
    let app = TenantStore::initialize_catalog_fixture_with_clock(
        node.clone(),
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([11; 32])),
        clock.clone(),
    )
    .await?;
    let custody = TenantStore::initialize_catalog_fixture_with_clock(
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
    let reopened = existing_pair_fixture(NodeStore::open_with_backend(
        recovered,
        crate::test_utils::storage_admission(),
        crate::ScratchDisk::fixture(),
    )?)
    .await?;
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
    let dir = crate::test_utils::private_tempdir()?;
    let node = NodeStore::create_new_fixture(
        dir.path().join("binding.redb"),
        crate::test_utils::NODE_STORE_ID,
        crate::ScratchDisk::fixture(),
    )?;
    let stores = initialize_pair_fixture(node.clone()).await?;
    let ops = vec![WriteOp::put("data", b"entry", b"a"); 32769];
    assert!(stores.write_batch(&ops, &ops).is_err());
    assert!(stores.application().get("data", b"entry")?.is_none());
    let mut catalog = node.catalog("tenant")?.unwrap();
    catalog.catalog_id = Uuid::new_v4();
    node.save_catalog("tenant", &catalog)?;
    let result = CustodyStore::open(
        node.clone(),
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([12; 32])),
    )
    .await;
    assert!(result.is_err());
    node.drain_initializers().await?;
    stores.check_access()?;
    stores.shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn initial_state_rejects_unknown_records_in_either_complete_domain() -> Result<()> {
    let directory = crate::test_utils::private_tempdir()?;
    for custody in [false, true] {
        let node = NodeStore::create_new_fixture(
            directory.path().join(format!("unknown-{custody}.redb")),
            crate::test_utils::NODE_STORE_ID,
            ScratchDisk::fixture(),
        )?;
        let stores = initialize_pair_fixture(node).await?;
        let domain = if custody {
            stores.custody().store()
        } else {
            stores.application()
        };
        domain.write_batch(&[WriteOp::put(
            "unsupported.application.v99",
            b"retained",
            b"never-overwrite",
        )])?;
        assert!(
            stores
                .initialize_state(
                    &[WriteOp::put("genesis", b"head", b"new")],
                    &[WriteOp::put("genesis", b"head", b"new")],
                )
                .is_err()
        );
        assert_eq!(
            domain
                .get("unsupported.application.v99", b"retained")?
                .unwrap(),
            b"never-overwrite"
        );
        assert!(stores.application().get("genesis", b"head")?.is_none());
        assert!(stores.custody().store().get("genesis", b"head")?.is_none());
        stores.shutdown().await.unwrap();
    }
    Ok(())
}

#[tokio::test]
async fn initial_state_checks_and_joint_publication_have_one_concurrent_winner() -> Result<()> {
    let directory = crate::test_utils::private_tempdir()?;
    let stores = initialize_pair_fixture(NodeStore::create_new_fixture(
        directory.path().join("first-publication.redb"),
        crate::test_utils::NODE_STORE_ID,
        ScratchDisk::fixture(),
    )?)
    .await?;
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            barrier.wait();
            stores.initialize_state(
                &[WriteOp::put("genesis", b"head", b"left")],
                &[WriteOp::put("genesis", b"head", b"left")],
            )
        });
        let right = scope.spawn(|| {
            barrier.wait();
            stores.initialize_state(
                &[WriteOp::put("genesis", b"head", b"right")],
                &[WriteOp::put("genesis", b"head", b"right")],
            )
        });
        (left.join().unwrap(), right.join().unwrap())
    });
    assert_ne!(results.0.is_ok(), results.1.is_ok());
    let expected = if results.0.is_ok() {
        b"left".as_slice()
    } else {
        b"right".as_slice()
    };
    assert_eq!(
        stores.application().get("genesis", b"head")?.unwrap(),
        expected
    );
    assert_eq!(
        stores.custody().store().get("genesis", b"head")?.unwrap(),
        expected
    );
    assert!(
        stores
            .initialize_state(
                &[WriteOp::put("genesis", b"head", expected)],
                &[WriteOp::put("genesis", b"head", expected)],
            )
            .is_err(),
        "even exact initialization replay is existing state, not permission to publish genesis"
    );
    stores.shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn initial_state_requires_the_exact_retained_custody_binding() -> Result<()> {
    let directory = crate::test_utils::private_tempdir()?;
    for missing in [false, true] {
        let stores = initialize_pair_fixture(NodeStore::create_new_fixture(
            directory.path().join(format!("binding-{missing}.redb")),
            crate::test_utils::NODE_STORE_ID,
            ScratchDisk::fixture(),
        )?)
        .await?;
        let damage = if missing {
            WriteOp::delete(BINDING_NS, BINDING_KEY)
        } else {
            WriteOp::put(BINDING_NS, BINDING_KEY, b"unrelated")
        };
        stores.custody().store().write_batch(&[damage])?;
        let before = stores.custody().store().get(BINDING_NS, BINDING_KEY)?;
        assert!(
            stores
                .initialize_state(
                    &[WriteOp::put("genesis", b"head", b"new")],
                    &[WriteOp::put("genesis", b"head", b"new")],
                )
                .is_err()
        );
        assert_eq!(
            stores.custody().store().get(BINDING_NS, BINDING_KEY)?,
            before
        );
        assert!(stores.application().get("genesis", b"head")?.is_none());
        stores.shutdown().await.unwrap();
    }
    Ok(())
}

#[tokio::test]
async fn initial_state_rejects_delete_only_publications_without_consuming_initialization()
-> Result<()> {
    let directory = crate::test_utils::private_tempdir()?;
    let stores = initialize_pair_fixture(NodeStore::create_new_fixture(
        directory.path().join("empty-initialization.redb"),
        crate::test_utils::NODE_STORE_ID,
        ScratchDisk::fixture(),
    )?)
    .await?;
    let put = [WriteOp::put("genesis", b"head", b"initial")];
    let delete = [WriteOp::delete("genesis", b"head")];
    for (app, custody) in [(&delete, &delete), (&delete, &put), (&put, &delete)] {
        assert!(stores.initialize_state(app, custody).is_err());
        assert!(stores.application().get("genesis", b"head")?.is_none());
        assert!(stores.custody().store().get("genesis", b"head")?.is_none());
    }
    stores.initialize_state(&put, &put)?;
    assert_eq!(
        stores.application().get("genesis", b"head")?.unwrap(),
        b"initial"
    );
    assert_eq!(
        stores.custody().store().get("genesis", b"head")?.unwrap(),
        b"initial"
    );
    stores.shutdown().await.unwrap();
    Ok(())
}
