use super::*;
use crate::runtime::{
    KeyProviderSettings, MutualTlsEndpoint, ReplicaConfig, ReplicationConfig, TlsFiles,
};
use kasumi_store::{NodeStore, StorageAccess, TenantStorageSet, TenantStore};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};
use tokio::sync::Notify;

#[derive(Default)]
struct Pause {
    entered: Notify,
    release: Notify,
}
fn pauses() -> &'static Mutex<BTreeMap<PathBuf, Arc<Pause>>> {
    static PAUSES: OnceLock<Mutex<BTreeMap<PathBuf, Arc<Pause>>>> = OnceLock::new();
    PAUSES.get_or_init(Default::default)
}
struct Release(Arc<Pause>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release.notify_one();
    }
}
pub(crate) async fn checkpoint(path: &Path) -> Result<()> {
    let pause = pauses().lock().unwrap().remove(path);
    if let Some(pause) = pause {
        pause.entered.notify_one();
        pause.release.notified().await;
        anyhow::bail!("injected error after actual Control genesis publication");
    }
    Ok(())
}

fn config(root: &Path) -> Result<(RuntimeConfig, crate::runtime_memory::RuntimeStorage)> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    let mut config =
        crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
    config.admission = Default::default();
    config.persistent_disk = crate::persistent_disk::fixture_config(&root.join("data"));
    config.database_path = root.join("data/node.redb");
    config.database_id = uuid::Uuid::new_v4();
    config.scratch_disk.directory = root.join("scratch");
    config.scratch_disk.min_free_bytes = 0;
    config.serving_authorities.clear();
    config.signer_verifier = None;
    config.control.lifecycle = None;
    config.backup_destinations.clear();
    config.tenant_audit_archives.clear();
    config.security_audit.archive = None;
    config.tenants[0].serving = crate::serving_runtime::TenantServingConfig::LocalFixture;
    for (index, keys) in std::iter::once(&mut config.security_audit.keys)
        .chain([&mut config.control.keys, &mut config.control.custody_keys])
        .chain(
            config
                .tenants
                .iter_mut()
                .flat_map(|tenant| [&mut tenant.keys, &mut tenant.custody_keys]),
        )
        .enumerate()
    {
        let path = root.join(format!("key-{index}.json"));
        kasumi_store::FileKeyProvider::initialize(&path, &format!("test-{index}"))?;
        *keys = KeyProviderSettings::File { path };
    }
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()])?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
    ];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let key = rcgen::KeyPair::generate()?;
    let certificate = params.self_signed(&key)?;
    let tls = TlsFiles {
        certificate: root.join("tls.pem"),
        private_key: root.join("tls.key"),
    };
    std::fs::write(&tls.certificate, certificate.pem())?;
    std::fs::write(&tls.private_key, key.serialize_pem())?;
    std::fs::set_permissions(&tls.private_key, std::fs::Permissions::from_mode(0o600))?;
    config.mcp.tls = tls.clone();
    config.native.tls = tls.clone();
    config.admin.tls = tls.clone();
    config.native.client_ca = tls.certificate.clone();
    config.admin.client_ca = tls.certificate.clone();
    let actual_pin = hex::encode(tls.load()?.certificate_pin());
    config.replication = Some(ReplicationConfig {
        node_id: 1,
        initial_voters: BTreeSet::from([1, 2, 3]),
        listener: MutualTlsEndpoint {
            listen: "127.0.0.1:49543".parse()?,
            tls: tls.clone(),
            client_ca: tls.certificate.clone(),
        },
        peers: (1..=3)
            .map(|id| ReplicaConfig {
                node_id: id,
                endpoint: format!("https://localhost:{}", 49542 + id),
                failure_domain: format!("zone-{id}"),
                certificate_pins: vec![if id == 1 {
                    actual_pin.clone()
                } else {
                    format!("{id:064x}")
                }],
            })
            .collect(),
    });
    config.validate()?;
    let storage = crate::runtime_storage_fixtures::configure(&mut config)?;
    Ok((config, storage))
}

async fn existing(
    config: &RuntimeConfig,
    storage: &crate::runtime_memory::RuntimeStorage,
) -> Result<(Arc<NodeStore>, Arc<TenantStore>)> {
    let node = NodeStore::open_existing(
        &config.database_path,
        config.database_id,
        storage.open_persistent(&config.persistent_disk)?,
        storage.open_scratch(&config.scratch_disk)?,
    )?;
    let security = TenantStore::open_existing(
        node.clone(),
        kasumi_engine::SECURITY_TENANT.into(),
        config
            .security_audit
            .keys
            .provider(Arc::new(crate::runtime::file_secret))?,
        StorageAccess::security_audit(),
    )
    .await?;
    Ok((node, security))
}

#[tokio::test]
async fn cancelled_ha_genesis_retains_actual_node_and_error_until_acknowledged_drain() -> Result<()>
{
    use std::{future::Future, task::Poll};
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let (config, storage) = config(directory.path())?;
    let pause = Arc::new(Pause::default());
    let _release = Release(pause.clone());
    pauses()
        .lock()
        .unwrap()
        .insert(config.database_path.clone(), pause.clone());
    let mut opening = Box::pin(crate::data_node_enrollment::initialize_with_storage(
        config.clone(),
        storage.clone(),
    ));
    std::future::poll_fn(|cx| {
        assert!(opening.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(10), pause.entered.notified()).await?;
    drop(opening);
    assert!(
        NodeStore::open_existing(
            &config.database_path,
            config.database_id,
            storage.open_persistent(&config.persistent_disk)?,
            storage.open_scratch(&config.scratch_disk)?
        )
        .is_err()
    );
    let mut drain = Box::pin(crate::runtime::NodeRuntime::drain_startups());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(drain);
    assert!(
        NodeStore::open_existing(
            &config.database_path,
            config.database_id,
            storage.open_persistent(&config.persistent_disk)?,
            storage.open_scratch(&config.scratch_disk)?
        )
        .is_err()
    );
    let mut drain = Box::pin(crate::runtime::NodeRuntime::drain_startups());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    pause.release.notify_one();
    let error = tokio::time::timeout(std::time::Duration::from_secs(10), drain)
        .await?
        .unwrap_err();
    assert!(format!("{error:#}").contains("actual Control genesis"));
    let (node, security) = existing(&config, &storage).await?;
    assert!(
        crate::node_enrollment::require_complete(
            &security,
            config.database_id,
            crate::node_enrollment::Kind::Data
        )
        .is_err()
    );
    let stores = TenantStorageSet::open_existing(
        node.clone(),
        crate::runtime::CONTROL_TENANT.into(),
        config
            .control
            .keys
            .provider(Arc::new(crate::runtime::file_secret))?,
        config
            .control
            .custody_keys
            .provider(Arc::new(crate::runtime::file_secret))?,
        StorageAccess::node_control(),
    )
    .await?;
    let (_, installed): (String, ReplicatedBootstrap) = serde_json::from_slice(
        &stores
            .application()
            .get("engine.deployment", b"mode")?
            .unwrap(),
    )?;
    assert!(matches!(installed.genesis, ReplicatedGenesis::Control(_)));
    assert!(
        stores
            .application()
            .get("engine.bootstrap", b"manifest")?
            .is_some()
    );
    stores.shutdown().await?;
    security.shutdown().await?;
    node.drain_initializers().await?;
    Ok(())
}

#[tokio::test]
async fn failed_control_genesis_drains_actual_pair_before_returning_enrollment_error() -> Result<()>
{
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let (mut config, storage) = config(directory.path())?;
    config.control.initial_limits.max_document_bytes = 1;
    config.validate()?;
    let error =
        crate::data_node_enrollment::initialize_with_storage(config.clone(), storage.clone())
            .await
            .unwrap_err();
    assert!(format!("{error:#}").contains("Control genesis exceeds"));
    let (node, security) = existing(&config, &storage).await?;
    assert!(
        crate::node_enrollment::require_complete(
            &security,
            config.database_id,
            crate::node_enrollment::Kind::Data
        )
        .is_err()
    );
    let stores = TenantStorageSet::open_existing(
        node.clone(),
        crate::runtime::CONTROL_TENANT.into(),
        config
            .control
            .keys
            .provider(Arc::new(crate::runtime::file_secret))?,
        config
            .control
            .custody_keys
            .provider(Arc::new(crate::runtime::file_secret))?,
        StorageAccess::node_control(),
    )
    .await?;
    assert!(
        stores
            .application()
            .get("engine.bootstrap", b"manifest")?
            .is_none()
    );
    stores.shutdown().await?;
    security.shutdown().await?;
    node.drain_initializers().await?;
    Ok(())
}

#[tokio::test]
async fn panicked_ha_enrollment_drains_nested_node_audit_pair_and_database_owners() -> Result<()> {
    for (index, phase) in [
        "node-provision-node",
        "node-provision-store",
        "node-provision-audit",
        "ha-enrollment-node",
        "ha-control-pair",
        "ha-control-database",
    ]
    .into_iter()
    .enumerate()
    {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (config, storage) = config(directory.path())?;
        let fault = crate::startup_preparation::install(config.database_id, phase);
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            crate::data_node_enrollment::initialize_with_storage(config.clone(), storage.clone()),
        )
        .await?
        .unwrap_err();
        assert!(
            error
                .downcast_ref::<crate::startup_preparation::PreparationPanic>()
                .is_some(),
            "{error:#}"
        );
        drop(fault);
        crate::runtime::NodeRuntime::drain_startups().await?;
        let node = NodeStore::open_existing(
            &config.database_path,
            config.database_id,
            storage.open_persistent(&config.persistent_disk)?,
            storage.open_scratch(&config.scratch_disk)?,
        )?;
        if index > 0 {
            let security = TenantStore::open_existing(
                node.clone(),
                kasumi_engine::SECURITY_TENANT.into(),
                config
                    .security_audit
                    .keys
                    .provider(Arc::new(crate::runtime::file_secret))?,
                StorageAccess::security_audit(),
            )
            .await?;
            assert_eq!(
                security.get("security.audit.meta", b"head")?.is_some(),
                index >= 2
            );
            assert!(
                crate::node_enrollment::require_complete(
                    &security,
                    config.database_id,
                    crate::node_enrollment::Kind::Data
                )
                .is_err()
            );
            if index >= 4 {
                let stores = TenantStorageSet::open_existing(
                    node.clone(),
                    crate::runtime::CONTROL_TENANT.into(),
                    config
                        .control
                        .keys
                        .provider(Arc::new(crate::runtime::file_secret))?,
                    config
                        .control
                        .custody_keys
                        .provider(Arc::new(crate::runtime::file_secret))?,
                    StorageAccess::node_control(),
                )
                .await?;
                assert_eq!(
                    stores
                        .application()
                        .get("engine.bootstrap", b"manifest")?
                        .is_some(),
                    index == 5
                );
                stores.shutdown().await?;
            }
            security.shutdown().await?;
        }
        node.drain_initializers().await?;
    }
    Ok(())
}
