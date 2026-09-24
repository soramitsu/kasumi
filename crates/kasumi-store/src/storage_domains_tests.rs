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
async fn catalog_presence_classification_requires_both_domains() -> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir()?;
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = crate::test_utils::private_tempdir()?;
    let absent = NodeStore::create_new_fixture(
        directory.path().join("absent.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )?;
    assert!(!TenantStorageSet::catalogs_installed(&absent, "tenant")?);
    absent.shutdown().await.unwrap();

    for (index, name) in ["tenant".to_owned(), CustodyStore::catalog_name("tenant")]
        .into_iter()
        .enumerate()
    {
        let node = NodeStore::create_new_fixture(
            directory.path().join(format!("partial-{index}.kv")),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )?;
        let store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            name,
            Arc::new(LocalKeyProvider::new([11 + index as u8; 32])),
        )
        .await?;
        assert!(
            format!(
                "{:#}",
                TenantStorageSet::catalogs_installed(&node, "tenant").unwrap_err()
            )
            .contains("partially installed")
        );
        store.shutdown().await.unwrap();
        node.shutdown().await.unwrap();
    }

    let node = NodeStore::create_new_fixture(
        directory.path().join("complete.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory,
        fixture_scratch,
    )?;
    let stores = TenantStorageSet::initialize_catalogs_fixture(
        node.clone(),
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([21; 32])),
        Arc::new(LocalKeyProvider::new([22; 32])),
    )
    .await?;
    assert!(TenantStorageSet::catalogs_installed(&node, "tenant")?);
    stores.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn domains_require_distinct_actual_wrapping_policies_and_same_node() -> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let dir = crate::test_utils::private_tempdir()?;
    let node = NodeStore::create_new_fixture(
        dir.path().join("same.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
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
            dir.path().join("other.kv"),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )?,
        CustodyStore::catalog_name("tenant"),
        Arc::new(LocalKeyProvider::new([2; 32])),
    )
    .await?;
    assert!(TenantStorageSet::install(app, other).is_err());
    let reserved = NodeStore::create_new_fixture(
        dir.path().join("reserved.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
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
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let dir = crate::test_utils::private_tempdir()?;
    let path = dir.path().join("revoked.kv");
    let app_provider = Arc::new(LocalKeyProvider::new([11; 32]));
    let control_provider = Arc::new(LocalKeyProvider::new([12; 32]));
    let node = NodeStore::create_new_fixture(
        &path,
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
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
            fixture_memory.clone(),
            fixture_scratch.clone(),
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
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let original = FaultBackend::new();
    let stores = initialize_pair_fixture(NodeStore::open_with_backend(
        original.clone(),
        crate::test_utils::storage_admission(),
        fixture_scratch.clone(),
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
            fixture_scratch.clone(),
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
            fixture_scratch.clone(),
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
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let disk = FaultBackend::new();
    let node = NodeStore::open_with_backend(
        disk.clone(),
        crate::test_utils::storage_admission(),
        fixture_scratch.clone(),
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
        fixture_scratch.clone(),
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
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let dir = crate::test_utils::private_tempdir()?;
    let node = NodeStore::create_new_fixture(
        dir.path().join("binding.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
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
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = crate::test_utils::private_tempdir()?;
    for custody in [false, true] {
        let node = NodeStore::create_new_fixture(
            directory.path().join(format!("unknown-{custody}.kv")),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
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
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = crate::test_utils::private_tempdir()?;
    let stores = initialize_pair_fixture(NodeStore::create_new_fixture(
        directory.path().join("first-publication.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
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
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = crate::test_utils::private_tempdir()?;
    for missing in [false, true] {
        let stores = initialize_pair_fixture(NodeStore::create_new_fixture(
            directory.path().join(format!("binding-{missing}.kv")),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
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
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = crate::test_utils::private_tempdir()?;
    let stores = initialize_pair_fixture(NodeStore::create_new_fixture(
        directory.path().join("empty-initialization.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
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

#[tokio::test]
async fn paired_deployment_read_checks_domains_and_charge() -> Result<()> {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir()?;
    let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let directory = crate::test_utils::private_tempdir()?;
    let stores = initialize_pair_fixture(NodeStore::create_new_fixture(
        directory.path().join("deployment-pair.kv"),
        crate::test_utils::NODE_STORE_ID,
        memory.clone(),
        scratch,
    )?)
    .await?;
    assert!(stores.deployment_binding()?.is_none());

    // The pair must admit a deployment value larger than a single read page
    // while respecting the exact current paired writer limit.
    let binding = vec![b'x'; (1 << 20) + 1];
    assert!(binding.len() <= MAX_DEPLOYMENT_BINDING_BYTES);
    let put = WriteOp::put(DEPLOYMENT_NS, DEPLOYMENT_KEY, binding.clone());
    let writes = [put];
    stores.write_batch(&writes, &writes)?;
    drop(stores.deployment_binding()?.expect("paired binding"));
    let before = memory.snapshot().used_bytes;
    let admitted = stores.deployment_binding()?.expect("paired binding");
    assert_eq!(admitted.as_bytes(), binding);
    assert!(memory.snapshot().used_bytes > before);
    drop(admitted);
    assert_eq!(memory.snapshot().used_bytes, before);

    stores.write_batch(
        &[WriteOp::put(DEPLOYMENT_NS, DEPLOYMENT_KEY, b"different")],
        &[],
    )?;
    assert_eq!(
        stores
            .deployment_binding()
            .err()
            .expect("divergent pair must fail")
            .to_string(),
        "deployment binding differs across domains"
    );
    stores.write_batch(
        &[WriteOp::put(DEPLOYMENT_NS, DEPLOYMENT_KEY, binding.clone())],
        &[WriteOp::delete(DEPLOYMENT_NS, DEPLOYMENT_KEY)],
    )?;
    assert_eq!(
        stores
            .deployment_binding()
            .err()
            .expect("one-domain binding must fail")
            .to_string(),
        "required deployment binding is absent from one domain"
    );
    stores.write_batch(
        &[],
        &[WriteOp::put(DEPLOYMENT_NS, DEPLOYMENT_KEY, binding.clone())],
    )?;
    assert_eq!(
        stores
            .deployment_binding()?
            .expect("restored pair")
            .as_bytes(),
        binding
    );
    stores.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn custody_deployment_read_retains_writer_bounded_charge_without_application() -> Result<()> {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir()?;
    let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let directory = crate::test_utils::private_tempdir()?;
    let stores = initialize_pair_fixture(NodeStore::create_new_fixture(
        directory.path().join("custody-deployment.kv"),
        crate::test_utils::NODE_STORE_ID,
        memory.clone(),
        scratch,
    )?)
    .await?;
    assert!(stores.custody().deployment_binding()?.is_none());

    let binding = vec![b'x'; (1 << 20) + 1];
    assert!(binding.len() <= MAX_DEPLOYMENT_BINDING_BYTES);
    let put = WriteOp::put(DEPLOYMENT_NS, DEPLOYMENT_KEY, binding.clone());
    stores.write_batch(std::slice::from_ref(&put), std::slice::from_ref(&put))?;
    let before = memory.snapshot().used_bytes;
    let admitted = stores
        .custody()
        .deployment_binding()?
        .expect("custody deployment binding");
    assert_eq!(admitted.as_bytes(), binding);
    assert!(memory.snapshot().used_bytes > before);
    drop(admitted);
    assert_eq!(memory.snapshot().used_bytes, before);

    // The retired reader is allowed to retain custody alone. An application
    // row cannot substitute for the independently encrypted custody value.
    stores.write_batch(&[WriteOp::delete(DEPLOYMENT_NS, DEPLOYMENT_KEY)], &[])?;
    let retained = stores
        .custody()
        .deployment_binding()?
        .expect("retained custody deployment binding");
    assert_eq!(retained.as_bytes(), binding);
    drop(retained);
    stores.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn paired_deployment_read_accepts_exact_current_writer_boundary() -> Result<()> {
    let memory = crate::test_utils::TestDiskMemory::new(1 << 30, 4096);
    let scratch_directory = crate::test_utils::private_tempdir()?;
    let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let directory = crate::test_utils::private_tempdir()?;
    let stores = initialize_pair_fixture(NodeStore::create_new_fixture(
        directory.path().join("deployment-boundary.kv"),
        crate::test_utils::NODE_STORE_ID,
        memory,
        scratch,
    )?)
    .await?;
    let exact = vec![b'x'; MAX_DEPLOYMENT_BINDING_BYTES];
    let put = WriteOp::put(DEPLOYMENT_NS, DEPLOYMENT_KEY, exact);
    let writes = [put];
    stores.write_batch(&writes, &writes)?;
    let admitted = stores.deployment_binding()?.expect("exact writer boundary");
    assert_eq!(admitted.as_bytes().len(), MAX_DEPLOYMENT_BINDING_BYTES);
    assert!(admitted.as_bytes().iter().all(|byte| *byte == b'x'));
    drop(admitted);

    let over = vec![b'y'; MAX_DEPLOYMENT_BINDING_BYTES + 1];
    let put = WriteOp::put(DEPLOYMENT_NS, DEPLOYMENT_KEY, over);
    let writes = [put];
    assert_eq!(
        stores
            .write_batch(&writes, &writes)
            .expect_err("one byte above paired writer boundary")
            .to_string(),
        "batch exceeds 64 MiB"
    );
    let retained = stores.deployment_binding()?.expect("original exact pair");
    assert_eq!(retained.as_bytes().len(), MAX_DEPLOYMENT_BINDING_BYTES);
    assert!(retained.as_bytes().iter().all(|byte| *byte == b'x'));
    drop(retained);
    stores.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn paired_deployment_read_rejects_oversized_envelope_before_key_id_parse() -> Result<()> {
    let memory = crate::test_utils::TestDiskMemory::new(1 << 30, 4096);
    let scratch_directory = crate::test_utils::private_tempdir()?;
    let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let directory = crate::test_utils::private_tempdir()?;
    let stores = initialize_pair_fixture(NodeStore::create_new_fixture(
        directory.path().join("deployment-oversized-envelope.kv"),
        crate::test_utils::NODE_STORE_ID,
        memory.clone(),
        scratch,
    )?)
    .await?;
    let application = stores.application();
    let disk_key = {
        let state = application.state.read();
        record_key(
            application.tenant(),
            DEPLOYMENT_NS,
            DEPLOYMENT_KEY,
            state.keys.get(INDEX_KEY).context("index key missing")?,
        )
    };
    // The four-byte prefix makes the entire remaining envelope a malformed,
    // non-UTF-8 key ID. The whole-envelope bound must win before that parse.
    let mut oversized = vec![0xff; MAX_DEPLOYMENT_ENVELOPE_BYTES + 1];
    let id_len = u32::try_from(oversized.len() - 4)?;
    oversized[..4].copy_from_slice(&id_len.to_be_bytes());
    let tx = application.node.db.begin_write()?;
    tx.open_table(RECORDS)?
        .insert(disk_key.as_slice(), oversized.as_slice())?;
    tx.commit()?;
    let before = memory.snapshot().used_bytes;
    assert_eq!(
        stores
            .deployment_binding()
            .err()
            .expect("oversized encrypted envelope")
            .to_string(),
        "encrypted deployment envelope exceeds read budget"
    );
    assert_eq!(memory.snapshot().used_bytes, before);
    let tx = application.node.db.begin_read()?;
    let table = tx.open_table(RECORDS)?;
    assert_eq!(
        table
            .get(disk_key.as_slice())?
            .expect("original malformed row")
            .value(),
        oversized.as_slice(),
        "failed read must not repair the encrypted row"
    );
    drop(table);
    drop(tx);
    stores.shutdown().await?;
    Ok(())
}
