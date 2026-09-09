#[tokio::test]
async fn panicked_cold_preparation_drains_actual_nodes_stores_and_partial_runtime() -> Result<()> {
    let _gate = LIFECYCLE_GATE.lock().await;
    let directory = tempfile::tempdir()?;
    let installed =
        crate::standalone::initialize(&directory.path().join("installed"), "acme").await?;
    let mut config = RuntimeConfig::load(&installed.configuration)?;
    let [mcp, native, admin] = listening_addresses();
    config.mcp.listen = mcp;
    config.native.listen = native;
    config.admin.listen = admin;
    config.mcp.protocol = McpConfig::new(format!("https://localhost:{}/mcp", mcp.port()))?;
    for phase in ["data-security", "data-database", "data-runtime"] {
        let fault = crate::startup_preparation::install(config.database_id, phase);
        let error =
            tokio::time::timeout(Duration::from_secs(10), NodeRuntime::open(config.clone()))
                .await?
                .err()
                .context("injected preparation panic unexpectedly succeeded")?;
        assert!(
            error
                .downcast_ref::<crate::startup_preparation::PreparationPanic>()
                .is_some()
        );
        drop(fault);
        NodeRuntime::drain_startups().await?;
        // The same physical installation and its encrypted catalog must be usable
        // immediately, including after a complete Control database was retained.
        let lock = crate::standalone::claim(&config)?;
        let node = NodeStore::open_existing(
            &config.database_path,
            config.database_id,
            kasumi_store::ScratchDisk::open(config.scratch_disk.clone())?,
        )?;
        let store = TenantStore::open_existing(
            node.clone(),
            SECURITY_TENANT.into(),
            config.security_audit.keys.provider(Arc::new(file_secret))?,
            kasumi_store::StorageAccess::security_audit(),
        )
        .await?;
        assert!(store.get("security.audit.meta", b"head")?.is_some());
        store.shutdown().await.unwrap();
        node.drain_initializers().await?;
        drop(store);
        drop(node);
        drop(lock);
        let mut runtime = NodeRuntime::open(config.clone()).await?;
        runtime.shutdown().await?;
        drop(runtime);
    }
    Ok(())
}

#[tokio::test]
async fn rejected_cold_audit_open_drains_storage_and_releases_the_standalone_installation()
-> Result<()> {
    let _gate = LIFECYCLE_GATE.lock().await;
    let directory = tempfile::tempdir()?;
    let installed =
        crate::standalone::initialize(&directory.path().join("installed"), "acme").await?;
    let mut config = RuntimeConfig::load(&installed.configuration)?;
    // This case never serves or publishes topology. Reserve distinct test socket
    // endpoints so an unrelated operator listener cannot hide the audit failure.
    let [mcp, native, admin] = listening_addresses();
    config.mcp.listen = mcp;
    config.native.listen = native;
    config.admin.listen = admin;
    config.mcp.protocol = McpConfig::new(format!("https://localhost:{}/mcp", mcp.port()))?;
    let scratch = kasumi_store::ScratchDisk::open(config.scratch_disk.clone())?;
    let node =
        NodeStore::open_existing(&config.database_path, config.database_id, scratch.clone())?;
    let store = TenantStore::open_existing(
        node.clone(),
        SECURITY_TENANT.into(),
        config.security_audit.keys.provider(Arc::new(file_secret))?,
        kasumi_store::StorageAccess::security_audit(),
    )
    .await?;
    store.write_batch(&[kasumi_store::WriteOp::delete(
        "security.audit.meta",
        b"head",
    )])?;
    store.shutdown().await.unwrap();
    drop(store);
    drop(node);
    for _ in 0..2 {
        let error = NodeRuntime::open(config.clone())
            .await
            .err()
            .context("missing audit head was accepted")?;
        assert!(format!("{error:#}").contains("audit"));
        NodeRuntime::drain_startups().await?;
        let owner = crate::standalone::claim(&config)?;
        let node =
            NodeStore::open_existing(&config.database_path, config.database_id, scratch.clone())?;
        let store = TenantStore::open_existing(
            node.clone(),
            SECURITY_TENANT.into(),
            config.security_audit.keys.provider(Arc::new(file_secret))?,
            kasumi_store::StorageAccess::security_audit(),
        )
        .await?;
        assert!(store.get("security.audit.meta", b"head")?.is_none());
        store.shutdown().await.unwrap();
        drop(store);
        drop(node);
        drop(owner);
    }
    Ok(())
}

#[tokio::test]
async fn completed_runtime_shutdown_failure_retains_diagnostic_and_installation_lock() -> Result<()>
{
    let _gate = LIFECYCLE_GATE.lock().await;
    let directory = tempfile::tempdir()?;
    let installed =
        crate::standalone::initialize(&directory.path().join("installed"), "acme").await?;
    let mut config = RuntimeConfig::load(&installed.configuration)?;
    let [mcp, native, admin] = listening_addresses();
    config.mcp.listen = mcp;
    config.native.listen = native;
    config.admin.listen = admin;
    config.mcp.protocol = McpConfig::new(format!("https://localhost:{}/mcp", mcp.port()))?;
    let mut runtime = NodeRuntime::open(config.clone()).await?;
    runtime.audit.seal();
    let first = runtime.shutdown().await.unwrap_err();
    assert_eq!(
        first.completion(),
        kasumi_types::drain::DrainCompletion::Complete
    );
    assert!(
        runtime.closed,
        "complete failure did not mark actual drain completion"
    );
    assert!(crate::standalone::claim(&config).is_err());
    // Repeated shutdown preserves every exact diagnostic and does not submit
    // the stopping audit again. The installation remains owned until drop.
    let second = runtime.shutdown().await.unwrap_err();
    assert_eq!(
        second.completion(),
        kasumi_types::drain::DrainCompletion::Complete
    );
    assert_eq!(first.issues().len(), second.issues().len());
    assert!(!first.issues().is_empty());
    assert!(
        first
            .issues()
            .iter()
            .zip(second.issues())
            .all(|(a, b)| Arc::ptr_eq(a, b))
    );
    assert!(crate::standalone::claim(&config).is_err());
    drop(runtime);
    NodeRuntime::drain_startups().await?;
    let owner = crate::standalone::claim(&config)?;
    drop(owner);
    Ok(())
}
