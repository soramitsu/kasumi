//! Offline production-purpose provisioning and strict reopen regressions.
use super::*;
use kasumi_engine::control::ControlPlane;
use kasumi_store::TenantStorageSet;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initialization_provisions_control_topology_and_application_before_completion_marker()
-> Result<()> {
    let root = tempfile::tempdir()?;
    let installed = initialize(&root.path().join("database"), "documents").await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let (lock, node, audit, credentials) = operator_state(&config).await?;
    let control = operator_control(&config, node.clone(), audit.clone()).await?;
    let plane = ControlPlane::new(control.clone())?;
    let context = crate::runtime::configured_control_context(&config.control)?;
    plane.require_initialized(&context).await?;
    let topology = plane
        .topology(&context)
        .await?
        .context("initialized topology missing")?;
    ensure!(
        topology.topology == initial_topology(&config)?,
        "initial topology differs"
    );
    let tenant = &config.tenants[0];
    let TenantServingConfig::Standalone { installation_id } = tenant.serving else {
        unreachable!()
    };
    let incarnation = Uuid::parse_str(tenant.incarnation.as_deref().unwrap())?;
    let source = Arc::new(crate::runtime::file_secret);
    let stores = TenantStorageSet::open_existing(
        node.clone(),
        tenant.tenant.clone(),
        tenant.keys.provider(source.clone())?,
        tenant.custody_keys.provider(source)?,
        StorageAccess::standalone(installation_id, &tenant.tenant, incarnation)?,
    )
    .await?;
    config.install_tenant_audit_archive(stores.application(), None)?;
    let application =
        kasumi_engine::open_existing_local(stores.clone(), audit.clone(), incarnation).await?;
    let generation = application.engine().generation()?;
    ensure!(
        generation.state.incarnation == incarnation.to_string()
            && generation.state.collections.is_empty(),
        "initial application identity or schema differs"
    );
    drop(generation);
    let marker: Installation = serde_json::from_slice(&private_files::read(
        &config
            .database_path
            .parent()
            .unwrap()
            .join("installation.json"),
        16 << 10,
    )?)?;
    ensure!(
        marker.format == 2
            && marker.control_incarnation.to_string()
                == config.control.incarnation.clone().unwrap(),
        "completed installation identity differs"
    );
    application.shutdown().await?;
    drop(application);
    stores.application().shutdown().await;
    stores.custody().store().shutdown().await;
    drop(stores);
    drop(plane);
    control.shutdown().await?;
    drop(control);
    drop(credentials);
    audit.shutdown().await;
    drop(audit);
    drop(node);
    drop(lock);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_profile_publication_drains_owners_and_never_marks_partial_installation_complete()
-> Result<()> {
    let root = tempfile::tempdir()?;
    let directory = root.path().join("database");
    let result = initialize_owned(
        &directory,
        "documents",
        InitializationOptions {
            obstruct_profile_publication: true,
        },
    )
    .await;
    ensure!(
        result.is_err(),
        "injected exclusive profile publication unexpectedly succeeded"
    );
    ensure!(
        !directory.join("kasumi.json").exists()
            && !directory.join("data/installation.json").exists(),
        "failed initialization published a completion artifact"
    );
    let _lock = private_files::ExclusiveLock::acquire(&directory.join("data/installation.lock"))?;
    let node = NodeStore::open_existing(
        directory.join("data/node.redb"),
        kasumi_store::ScratchDisk::fixture(),
    )?;
    drop(node);
    ensure!(
        initialize(&directory, "documents").await.is_err(),
        "init adopted an incomplete existing directory"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopped_operator_reopen_never_recreates_missing_control_bootstrap() -> Result<()> {
    let root = tempfile::tempdir()?;
    let installed = initialize(&root.path().join("database"), "documents").await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let (_lock, node, audit, credentials) = operator_state(&config).await?;
    let source = Arc::new(crate::runtime::file_secret);
    let stores = TenantStorageSet::open_existing(
        node.clone(),
        crate::runtime::CONTROL_TENANT.into(),
        config.control.keys.provider(source.clone())?,
        config.control.custody_keys.provider(source)?,
        StorageAccess::node_control(),
    )
    .await?;
    stores
        .application()
        .write_batch(&[kasumi_store::WriteOp::delete(
            "engine.bootstrap",
            b"manifest",
        )])?;
    let retained = stores
        .custody()
        .store()
        .get("raft.meta", b"application_bootstrap_sha256")?;
    // Keep the exact opened catalogs while the strict bootstrap rejects; no new
    // policy, identity, bootstrap manifest or custody commitment may be installed.
    ensure!(
        kasumi_engine::open_existing_local(
            stores.clone(),
            audit.clone(),
            Uuid::parse_str(config.control.incarnation.as_deref().unwrap())?
        )
        .await
        .is_err(),
        "missing bootstrap reopened"
    );
    ensure!(
        stores
            .application()
            .get("engine.bootstrap", b"manifest")?
            .is_none(),
        "bootstrap was recreated"
    );
    ensure!(
        stores
            .custody()
            .store()
            .get("raft.meta", b"application_bootstrap_sha256")?
            == retained,
        "failed reopen rewrote custody commitment"
    );
    stores.application().shutdown().await;
    stores.custody().store().shutdown().await;
    drop(stores);
    drop(credentials);
    audit.shutdown().await;
    Ok(())
}
