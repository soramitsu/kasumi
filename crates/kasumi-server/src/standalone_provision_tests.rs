//! Offline production-purpose provisioning and strict reopen regressions.
use super::*;
use kasumi_engine::control::ControlPlane;
use kasumi_store::TenantStorageSet;

#[test]
fn initialization_provisions_control_topology_and_application_before_completion_marker()
-> Result<()> {
    ownership_tests::run_large_fixture(
        "standalone initial-provisioning fixture",
        initialization_provisions_control_topology_and_application_before_completion_marker_impl,
    )
}

async fn initialization_provisions_control_topology_and_application_before_completion_marker_impl()
-> Result<()> {
    let root = kasumi_store::test_utils::private_tempdir()?;
    let (installed, storage) = crate::runtime_storage_fixtures::initialize_standalone(
        &root.path().join("database"),
        "documents",
    )
    .await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let mut substituted = config.clone();
    substituted.database_id = Uuid::new_v4();
    ensure!(
        OperatorState::open(&substituted, storage.clone())
            .await
            .is_err(),
        "different configured physical database identity was accepted"
    );
    substituted = config.clone();
    substituted.control.incarnation = Some(Uuid::new_v4().to_string());
    ensure!(
        OperatorState::open(&substituted, storage.clone())
            .await
            .is_err(),
        "different configured immutable Control identity was accepted"
    );
    let mut owner = OperatorState::open(&config, storage.clone()).await?;
    let node = owner.node.clone();
    let audit = owner.audit.clone();
    let control = owner.control().await?;
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
        marker.format == 4
            && marker.origin_node_id == STANDALONE_ORIGIN_NODE_ID
            && marker.database_id == config.database_id
            && marker.control_incarnation.to_string()
                == config.control.incarnation.clone().unwrap(),
        "completed installation identity differs"
    );
    application.shutdown().await?;
    drop(application);
    stores.shutdown().await.unwrap();
    drop(stores);
    drop(plane);
    control.shutdown().await?;
    drop(control);
    audit.shutdown().await.unwrap();
    drop(audit);
    drop(node);
    owner.finish(Ok(())).await?;
    Ok(())
}

#[test]
fn failed_profile_publication_drains_owners_and_never_marks_partial_installation_complete()
-> Result<()> {
    ownership_tests::run_large_fixture(
        "standalone failed-profile-publication fixture",
        failed_profile_publication_drains_owners_and_never_marks_partial_installation_complete_impl,
    )
}

async fn failed_profile_publication_drains_owners_and_never_marks_partial_installation_complete_impl()
-> Result<()> {
    let root = kasumi_store::test_utils::private_tempdir()?;
    let directory = root.path().join("database");
    let storage =
        crate::runtime_storage_fixtures::standalone_storage(&directory, Default::default())?;
    let result = initialize_owned(
        &directory,
        "documents",
        kasumi_store::DirectoryPolicy::fixture(),
        StandaloneNetwork::fixture(),
        InitializationOptions {
            obstruct_profile_publication: true,
            ..Default::default()
        },
        storage.clone(),
    )
    .await;
    ensure!(
        result.is_err(),
        "injected exclusive profile publication unexpectedly succeeded"
    );
    ensure!(
        private_files::read(&directory.join("profiles/control.token"), 16)?.as_slice()
            == b"blocked",
        "initialization failed before the injected profile-publication obstruction"
    );
    ensure!(
        !directory.join("kasumi.json").exists()
            && !directory.join("data/installation.json").exists(),
        "failed initialization published a completion artifact"
    );
    // The installer and NodeDisk fixture bind the canonical installed root.
    // macOS TempDir may retain /var while that root is /private/var.
    let directory = std::fs::canonicalize(&directory)?;
    let (persistent, scratch) = crate::runtime_storage_fixtures::standalone_disks(&directory)?;
    let disk = storage.open_persistent(&persistent)?;
    let lock = directory.join("data/installation.lock");
    let (root, relative) = persistent.binding(&lock)?;
    let _lock = disk.open_file(root, relative)?;
    let prepared: Installation = serde_json::from_slice(&private_files::read(
        &directory.join("data/initialization.json"),
        16 << 10,
    )?)?;
    let node = NodeStore::open_existing(
        directory.join("data/node.redb"),
        prepared.database_id,
        disk,
        storage.open_scratch(&scratch)?,
    )?;
    node.shutdown().await?;
    drop(node);
    ensure!(
        initialize_with_storage(
            &directory,
            "documents",
            kasumi_store::DirectoryPolicy::fixture(),
            StandaloneNetwork::fixture(),
            storage
        )
        .await
        .is_err(),
        "init adopted an incomplete existing directory"
    );
    Ok(())
}

#[test]
fn stopped_operator_reopen_never_recreates_missing_control_bootstrap() -> Result<()> {
    ownership_tests::run_large_fixture(
        "standalone missing-Control-bootstrap fixture",
        stopped_operator_reopen_never_recreates_missing_control_bootstrap_impl,
    )
}

async fn stopped_operator_reopen_never_recreates_missing_control_bootstrap_impl() -> Result<()> {
    let root = kasumi_store::test_utils::private_tempdir()?;
    let (installed, storage) = crate::runtime_storage_fixtures::initialize_standalone(
        &root.path().join("database"),
        "documents",
    )
    .await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let mut owner = OperatorState::open(&config, storage.clone()).await?;
    let node = owner.node.clone();
    let audit = owner.audit.clone();
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
    stores.shutdown().await.unwrap();
    drop(stores);
    audit.shutdown().await.unwrap();
    drop(audit);
    drop(node);
    owner.finish(Ok(())).await?;
    Ok(())
}
