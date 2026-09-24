//! Secure, exclusive first-release standalone installation and operator tools.
#[path = "standalone_tenant_staging.rs"]
mod tenant_staging;
use crate::{
    auth::{AuthConfig, AuthKeySource},
    local_auth::{LocalCredentials, initialize_signer},
    runtime::{DeploymentMode, KeyProviderSettings, RuntimeConfig, TlsFiles, example_config},
    serving_runtime::TenantServingConfig,
};
use anyhow::{Context, Result, ensure};
use kasumi_client::{ProfileAuthorityEndpoint, ProfileTlsFiles};
use kasumi_store::{
    DiskWork, FileKeyProvider, NodeDisk, NodeDiskConfig, NodeDiskFile, NodeStore, StorageAccess,
    TenantStore, private_files,
};
use kasumi_types::{
    Action, CreateCredential, CredentialResource, Grant, Policy, TrustVerifierIdentity,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
#[cfg(test)]
pub(crate) use tenant_staging::stage_tenant_with_storage;
pub use tenant_staging::{StageTenantRequest, StagedTenant, stage_tenant, tenant_stage_status};
use uuid::Uuid;

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installation {
    format: u32,
    installation_id: Uuid,
    origin_node_id: u64,
    control_incarnation: Uuid,
    database_id: Uuid,
    database_path: PathBuf,
}

const STANDALONE_ORIGIN_NODE_ID: u64 = 1;

/// Verified installed identity held together with the exact enrolled disk and
/// its exclusive lock. A configured path or tenant UUID cannot construct this.
pub(crate) struct InstalledStandaloneOwner {
    identity: TrustVerifierIdentity,
    disk: Arc<NodeDisk>,
    lock: NodeDiskFile,
}
impl InstalledStandaloneOwner {
    pub(crate) fn identity_for(&self, disk: &Arc<NodeDisk>) -> Result<TrustVerifierIdentity> {
        ensure!(
            Arc::ptr_eq(&self.disk, disk),
            "standalone installed owner belongs to another physical disk"
        );
        ensure!(
            self.lock.observed_len()? == 0,
            "standalone installation lock changed"
        );
        Ok(self.identity.clone())
    }
}

/// Listener identity selected before immutable standalone Control genesis.
/// Generated certificates and client profiles are valid for localhost only.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandaloneNetwork {
    pub mcp_listen: SocketAddr,
    pub mcp_public_url: String,
    pub native_listen: SocketAddr,
    pub admin_listen: SocketAddr,
}

impl StandaloneNetwork {
    pub fn validate(&self) -> Result<()> {
        let listeners = [self.mcp_listen, self.native_listen, self.admin_listen];
        ensure!(
            listeners.iter().all(|address| {
                address.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                    && address.port() > 0
            }) && listeners[0] != listeners[1]
                && listeners[0] != listeners[2]
                && listeners[1] != listeners[2],
            "standalone listeners require distinct IPv4 loopback addresses and nonzero ports"
        );
        let url = url::Url::parse(&self.mcp_public_url)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str() == Some("localhost")
                && self.mcp_public_url
                    == format!("https://localhost:{}/mcp", self.mcp_listen.port())
                && url.path() == "/mcp"
                && url.query().is_none()
                && url.fragment().is_none()
                && url.username().is_empty()
                && url.password().is_none(),
            "standalone MCP public URL must be https://localhost:<mcp-listen-port>/mcp"
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        Self {
            mcp_listen: "127.0.0.1:9443".parse().unwrap(),
            mcp_public_url: "https://localhost:9443/mcp".into(),
            native_listen: "127.0.0.1:9444".parse().unwrap(),
            admin_listen: "127.0.0.1:9445".parse().unwrap(),
        }
    }
}

pub(crate) fn requires_provisioned(config: &RuntimeConfig) -> bool {
    if config.mode != DeploymentMode::Standalone {
        return false;
    }
    #[cfg(any(test, feature = "test-utils"))]
    if config
        .tenants
        .iter()
        .all(|tenant| matches!(tenant.serving, TenantServingConfig::LocalFixture))
    {
        return false;
    }
    true
}

/// Resolve only the caller's explicit installed root; never enroll a parent.
pub(crate) fn open_installed_file(
    config: &NodeDiskConfig,
    disk: &Arc<NodeDisk>,
    path: &Path,
) -> Result<NodeDiskFile> {
    let (root, relative) = config.binding(path)?;
    Ok(disk.open_file(root, relative)?)
}

pub(crate) fn create_installed_file(
    config: &NodeDiskConfig,
    disk: &Arc<NodeDisk>,
    path: &Path,
    bytes: &[u8],
    maximum: usize,
) -> Result<NodeDiskFile> {
    ensure!(
        bytes.len() <= maximum,
        "installed record exceeds size limit"
    );
    let (root, relative) = config.binding(path)?;
    let file = disk.create_file(root, relative, DiskWork::Foreground)?;
    file.reserve_growth(0, bytes.len() as u64, DiskWork::Foreground)?;
    file.write_all_at(bytes, 0)?;
    file.sync_all_and_parent()?;
    Ok(file)
}

pub(crate) fn read_installed_file(file: &NodeDiskFile, maximum: usize) -> Result<Vec<u8>> {
    let length = file.observed_len()?;
    ensure!(
        length <= maximum as u64,
        "installed record exceeds size limit"
    );
    let mut bytes = vec![0; usize::try_from(length)?];
    file.read_exact_at(&mut bytes, 0)?;
    Ok(bytes)
}

/// The marker binds physical standalone ownership to this configured database.
/// A process retains the returned lock until every serving/storage owner drains.
pub(crate) fn claim(
    config: &RuntimeConfig,
    disk: &Arc<NodeDisk>,
) -> Result<Option<Arc<InstalledStandaloneOwner>>> {
    if config.mode != DeploymentMode::Standalone {
        return Ok(None);
    }
    #[cfg(any(test, feature = "test-utils"))]
    if config
        .tenants
        .iter()
        .all(|tenant| matches!(tenant.serving, TenantServingConfig::LocalFixture))
    {
        return Ok(None);
    }
    let directory = config
        .database_path
        .parent()
        .context("standalone database has no parent")?;
    // Ordinary startup requires the original enrolled lock inode. A missing
    // lock is an incomplete installation, never permission to create one.
    let lock = open_installed_file(
        &config.persistent_disk,
        disk,
        &directory.join("installation.lock"),
    )?;
    ensure!(
        lock.observed_len()? == 0,
        "installation lock contains unexpected data"
    );
    let installed: Installation = serde_json::from_slice(&read_installed_file(
        &open_installed_file(
            &config.persistent_disk,
            disk,
            &directory.join("installation.json"),
        )?,
        16 << 10,
    )?)?;
    let prepared: Installation = serde_json::from_slice(&read_installed_file(
        &open_installed_file(
            &config.persistent_disk,
            disk,
            &directory.join("initialization.json"),
        )?,
        16 << 10,
    )?)?;
    ensure!(
        prepared == installed
            && installed.format == 4
            && installed.origin_node_id == STANDALONE_ORIGIN_NODE_ID
            && installed.database_id == config.database_id
            && !installed.database_id.is_nil()
            && installed.database_path == config.database_path
            && !installed.installation_id.is_nil()
            && !installed.control_incarnation.is_nil()
            && config.control.incarnation.as_deref()
                == Some(installed.control_incarnation.to_string().as_str()),
        "standalone installation binding differs"
    );
    ensure!(config.tenants.iter().all(|tenant| matches!(tenant.serving, TenantServingConfig::Standalone { installation_id } if installation_id == installed.installation_id)), "standalone installation identity differs");
    let identity = TrustVerifierIdentity {
        installation_id: installed.installation_id,
        node_id: installed.origin_node_id,
    };
    identity.validate()?;
    Ok(Some(Arc::new(InstalledStandaloneOwner {
        identity,
        disk: disk.clone(),
        lock,
    })))
}

pub(crate) fn installation_root(config: &RuntimeConfig) -> Result<&Path> {
    let root = config
        .database_path
        .parent()
        .and_then(Path::parent)
        .context("standalone installation root is missing")?;
    private_files::check_directory(root)?;
    Ok(root)
}

pub use kasumi_client::ClientProfile;

impl From<TlsFiles> for ProfileTlsFiles {
    fn from(files: TlsFiles) -> Self {
        Self {
            certificate: files.certificate,
            private_key: files.private_key,
        }
    }
}

impl From<ProfileTlsFiles> for TlsFiles {
    fn from(files: ProfileTlsFiles) -> Self {
        Self {
            certificate: files.certificate,
            private_key: files.private_key,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct InitializedInstallation {
    pub configuration: PathBuf,
    pub control_profile: PathBuf,
    pub tenant_profile: PathBuf,
}

#[path = "standalone_operator.rs"]
mod operator;
pub(crate) use operator::OperatorState;

/// Join local initialization, recovery and key-maintenance operations after
/// admission has stopped. Completed replies contain no storage owners.
pub async fn drain_operations() -> Result<()> {
    crate::startup_owner::drain(crate::startup_owner::Kind::LocalOperator).await
}

fn operator_event(
    request_id: &str,
    outcome: kasumi_engine::SecurityOutcome,
) -> kasumi_engine::SecurityEvent {
    kasumi_engine::SecurityEvent {
        kind: kasumi_engine::SecurityEventKind::KeyAdministration,
        principal: Some("offline-operator".into()),
        tenant: None,
        request_id: request_id.into(),
        outcome,
    }
}

pub(crate) fn offline_context(
    database: &kasumi_engine::Database,
) -> Result<kasumi_types::RequestContext> {
    let generation = database.engine().generation()?;
    let principal = generation
        .state
        .policy
        .grants
        .iter()
        .find(|grant| grant.collection.is_none() && grant.actions.contains(&Action::Admin))
        .context("installed administrator is missing")?
        .principal
        .clone();
    Ok(kasumi_types::RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal,
        tenant: generation.state.tenant.clone(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        request_id: Uuid::new_v4().to_string(),
    })
}

type OperatorTenants = (
    Vec<crate::runtime::TenantConfig>,
    std::collections::BTreeMap<String, Arc<NodeStore>>,
);

/// Resolve operational generations without rewriting immutable installation settings.
async fn operator_tenants(
    config: &RuntimeConfig,
    store: &TenantStore,
    owner: &OperatorState,
) -> Result<OperatorTenants> {
    let control = owner.control().await?;
    let plane = kasumi_engine::control::ControlPlane::new(control.clone())?;
    let topology = plane
        .topology(&offline_context(&control)?)
        .await?
        .context("installed Control topology is missing")?
        .topology;
    for tenant in topology.tenants.keys() {
        ensure!(
            config.tenants.iter().any(|entry| &entry.tenant == tenant),
            "routed tenant is not configured"
        );
        let enrolled = crate::node_enrollment::tenant_record(store, tenant)?
            .context("routed tenant has no local enrollment")?;
        ensure!(
            enrolled.stage == crate::node_enrollment::Stage::Prepared,
            "routed tenant enrollment is incomplete"
        );
    }
    let mut tenants = Vec::new();
    for tenant in &config.tenants {
        if let Some(record) = crate::node_enrollment::tenant_record(store, &tenant.tenant)?
            && record.stage == crate::node_enrollment::Stage::Prepared
        {
            ensure!(
                tenant
                    .incarnation
                    .as_deref()
                    .map(Uuid::parse_str)
                    .transpose()?
                    == Some(record.incarnation),
                "operator tenant differs from original enrollment"
            );
            tenants.push(tenant.clone());
        }
    }
    let mut nodes = std::collections::BTreeMap::new();
    for tenant in &mut tenants {
        let selected =
            match crate::local_recovery::active_generation(config, store, &tenant.tenant)? {
                Some(active) => {
                    tenant.incarnation = Some(active.incarnation.to_string());
                    NodeStore::open_existing(
                        active.directory.join("node.redb"),
                        active.database_id(config, &tenant.tenant)?,
                        owner.node.persistent_disk().clone(),
                        owner.node.scratch_disk().clone(),
                    )?
                }
                None => owner.node.clone(),
            };
        if let Some(route) = topology.tenants.get(&tenant.tenant) {
            ensure!(
                tenant.incarnation.as_deref() == Some(route.incarnation.as_str()),
                "routed tenant differs from its selected operator generation"
            );
        }
        owner.retain_node(selected.clone());
        nodes.insert(tenant.tenant.clone(), selected);
    }
    Ok((tenants, nodes))
}

/// Recovers credentials for the current policy's explicitly retained administrator.
/// Policy validation requires such an administrator, even when every token is
/// lost or expired. No policy bypass is installed in the running server.
pub async fn recover_administrator(configuration: &Path, output: &Path) -> Result<Vec<PathBuf>> {
    let config = RuntimeConfig::load(configuration)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    recover_administrator_with_storage(configuration, output, storage).await
}

pub(crate) async fn recover_administrator_with_storage(
    configuration: &Path,
    output: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<Vec<PathBuf>> {
    let configuration = configuration.to_owned();
    let output = output.to_owned();
    operator::run(
        async move { recover_administrator_owned(&configuration, &output, storage).await },
    )
    .await
}

async fn recover_administrator_owned(
    configuration: &Path,
    output: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<Vec<PathBuf>> {
    let mut config = RuntimeConfig::load(configuration)?;
    let mut owner = OperatorState::open(&config, storage).await?;
    let result = async {
        let node = owner.node.clone();
        let audit = owner.audit.clone();
        let credentials = owner.credentials.clone();
        crate::local_recovery::require_runtime_ready(audit.store())?;
        let (effective_tenants, generation_nodes) =
            operator_tenants(&config, audit.store(), &owner).await?;
        private_files::create_directory(output)?;
        let operation_id = Uuid::new_v4().to_string();
        audit
            .record(operator_event(
                &operation_id,
                kasumi_engine::SecurityOutcome::Started,
            ))
            .await?;
        let root = installation_root(&config)?;
        let source_profile = ClientProfile::load(&root.join("profiles/control.json"))?;
        let mut recovered = Vec::new();
        let mut recovered_control_principal = None;
        for (
            _name,
            tenant,
            _policy,
            _limits,
            incarnation,
            application,
            custody,
            access,
            resource,
        ) in std::iter::once((
            "control",
            crate::runtime::CONTROL_TENANT,
            &config.control.initial_policy,
            &config.control.initial_limits,
            config
                .control
                .incarnation
                .as_deref()
                .context("control incarnation missing")?,
            &config.control.keys,
            &config.control.custody_keys,
            StorageAccess::node_control(),
            CredentialResource::Control {
                incarnation: Uuid::parse_str(
                    config
                        .control
                        .incarnation
                        .as_deref()
                        .context("control incarnation missing")?,
                )?,
            },
        ))
        .chain(effective_tenants.iter().map(|tenant| {
            let TenantServingConfig::Standalone { installation_id } = tenant.serving else {
                unreachable!("claim validated standalone")
            };
            let incarnation = tenant
                .incarnation
                .as_deref()
                .expect("validated incarnation");
            let uuid = Uuid::parse_str(incarnation).expect("validated incarnation");
            (
                tenant.tenant.as_str(),
                tenant.tenant.as_str(),
                &tenant.initial_policy,
                &tenant.initial_limits,
                incarnation,
                &tenant.keys,
                &tenant.custody_keys,
                StorageAccess::standalone(installation_id, &tenant.tenant, uuid)
                    .expect("validated standalone"),
                CredentialResource::Database { incarnation: uuid },
            )
        })) {
            let database = if tenant == crate::runtime::CONTROL_TENANT {
                owner.control().await?
            } else {
                let source = Arc::new(crate::runtime::file_secret);
                let stores = kasumi_store::TenantStorageSet::open_existing(
                    generation_nodes
                        .get(tenant)
                        .cloned()
                        .unwrap_or_else(|| node.clone()),
                    tenant.into(),
                    application.provider(source.clone())?,
                    custody.provider(source)?,
                    access,
                )
                .await?;
                owner.retain_stores(&stores);
                config.install_tenant_audit_archive(stores.application(), None)?;
                let database = kasumi_engine::open_existing_local(
                    stores,
                    audit.clone(),
                    Uuid::parse_str(incarnation)?,
                )
                .await?;
                owner.retain_database(database.clone());
                database
            };
            let generation = database.engine().generation()?;
            let principal = generation
                .state
                .policy
                .grants
                .iter()
                .find(|grant| grant.collection.is_none() && grant.actions.contains(&Action::Admin))
                .context("installed administrator is missing")?
                .principal
                .clone();
            if tenant == crate::runtime::CONTROL_TENANT {
                recovered_control_principal = Some(principal.clone());
            }
            let issued = credentials.create(
                CreateCredential {
                    family_id: Uuid::new_v4(),
                    principal: principal.clone(),
                    tenant: tenant.into(),
                    resource: resource.clone(),
                    scopes: BTreeSet::from([
                        Action::Read,
                        Action::Write,
                        Action::Admin,
                        Action::Audit,
                    ]),
                    lifetime_seconds: 3600,
                },
                "offline-administrator-recovery",
            )?;
            let name = if tenant == crate::runtime::CONTROL_TENANT {
                "control".to_owned()
            } else {
                format!("database-{incarnation}")
            };
            let token_path = output.join(format!("{name}.token"));
            private_files::create(&token_path, issued.token.as_bytes())?;
            let profile = ClientProfile {
                tenant: tenant.into(),
                principal,
                resource,
                family_id: issued.family_id,
                bearer_file: token_path,
                ..source_profile.clone()
            };
            let profile_path = output.join(format!("{name}.json"));
            private_files::create(&profile_path, &serde_json::to_vec_pretty(&profile)?)?;
            recovered.push(profile_path);
            drop(generation);
            database.shutdown().await?;
        }
        config.control.startup_principal = recovered_control_principal;
        private_files::replace(configuration, &serde_json::to_vec_pretty(&config)?)?;
        audit
            .record(operator_event(
                &operation_id,
                kasumi_engine::SecurityOutcome::Succeeded,
            ))
            .await?;

        Ok(recovered)
    }
    .await;
    owner.finish(result).await
}

pub async fn rotate_wrapping_keys(configuration: &Path) -> Result<()> {
    let config = RuntimeConfig::load(configuration)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    rotate_wrapping_keys_with_storage(configuration, storage).await
}

pub(crate) async fn rotate_wrapping_keys_with_storage(
    configuration: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<()> {
    let configuration = configuration.to_owned();
    operator::run(async move { rotate_wrapping_keys_owned(&configuration, storage).await }).await
}

async fn rotate_wrapping_keys_owned(
    configuration: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<()> {
    let config = RuntimeConfig::load(configuration)?;
    let mut owner = OperatorState::open(&config, storage).await?;
    let result = async {
        let node = owner.node.clone();
        let audit = owner.audit.clone();
        crate::local_recovery::require_runtime_ready(audit.store())?;
        let (effective_tenants, generation_nodes) =
            operator_tenants(&config, audit.store(), &owner).await?;
        let operation = Uuid::new_v4().to_string();
        audit
            .record(operator_event(
                &operation,
                kasumi_engine::SecurityOutcome::Started,
            ))
            .await?;
        for settings in [
            &config.security_audit.keys,
            &config.control.keys,
            &config.control.custody_keys,
        ]
        .into_iter()
        .chain(
            effective_tenants
                .iter()
                .flat_map(|tenant| [&tenant.keys, &tenant.custody_keys]),
        ) {
            let KeyProviderSettings::File { path } = settings else {
                anyhow::bail!("local wrapping rotation requires file keyrings");
            };
            FileKeyProvider::open(path)?.rotate()?;
        }
        audit.store().rewrap_keys().await?;
        for (tenant, application, custody, access) in std::iter::once((
            crate::runtime::CONTROL_TENANT,
            &config.control.keys,
            &config.control.custody_keys,
            StorageAccess::node_control(),
        ))
        .chain(effective_tenants.iter().map(|tenant| {
            let TenantServingConfig::Standalone { installation_id } = tenant.serving else {
                unreachable!("claim validated standalone")
            };
            (
                tenant.tenant.as_str(),
                &tenant.keys,
                &tenant.custody_keys,
                StorageAccess::standalone(
                    installation_id,
                    &tenant.tenant,
                    Uuid::parse_str(
                        tenant
                            .incarnation
                            .as_deref()
                            .expect("validated incarnation"),
                    )
                    .expect("validated incarnation"),
                )
                .expect("validated standalone"),
            )
        })) {
            let source = Arc::new(crate::runtime::file_secret);
            let stores = kasumi_store::TenantStorageSet::open_existing(
                generation_nodes
                    .get(tenant)
                    .cloned()
                    .unwrap_or_else(|| node.clone()),
                tenant.into(),
                application.provider(source.clone())?,
                custody.provider(source)?,
                access,
            )
            .await?;
            owner.retain_stores(&stores);
            config.install_tenant_audit_archive(stores.application(), None)?;
            stores.application().rewrap_keys().await?;
            stores.custody().store().rewrap_keys().await?;
        }
        audit
            .record(operator_event(
                &operation,
                kasumi_engine::SecurityOutcome::Succeeded,
            ))
            .await?;

        Ok(())
    }
    .await;
    owner.finish(result).await
}

pub async fn rotate_signing_key(configuration: &Path) -> Result<u64> {
    let config = RuntimeConfig::load(configuration)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    rotate_signing_key_with_storage(configuration, storage).await
}

pub(crate) async fn rotate_signing_key_with_storage(
    configuration: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<u64> {
    let configuration = configuration.to_owned();
    operator::run(async move { rotate_signing_key_owned(&configuration, storage).await }).await
}

async fn rotate_signing_key_owned(
    configuration: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<u64> {
    let config = RuntimeConfig::load(configuration)?;
    let mut owner = OperatorState::open(&config, storage).await?;
    let result = async {
        let audit = owner.audit.clone();
        let operation = Uuid::new_v4().to_string();
        audit
            .record(operator_event(
                &operation,
                kasumi_engine::SecurityOutcome::Started,
            ))
            .await?;
        let AuthKeySource::Local { signer_file } = &config.auth.source else {
            unreachable!("operator state validated local issuer")
        };
        let generation = crate::local_auth::rotate_signer(signer_file)?;
        audit
            .record(operator_event(
                &operation,
                kasumi_engine::SecurityOutcome::Succeeded,
            ))
            .await?;

        Ok(generation)
    }
    .await;
    owner.finish(result).await
}

/// Offline certificate/key replacement keeps the installed CA identity. Local
/// generated profiles are updated to the exact new native/admin leaf pins.
pub async fn rotate_certificates(configuration: &Path) -> Result<serde_json::Value> {
    let config = RuntimeConfig::load(configuration)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    rotate_certificates_with_storage(configuration, storage).await
}

pub(crate) async fn rotate_certificates_with_storage(
    configuration: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<serde_json::Value> {
    let configuration = configuration.to_owned();
    operator::run(async move { rotate_certificates_owned(&configuration, storage).await }).await
}

async fn rotate_certificates_owned(
    configuration: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<serde_json::Value> {
    let config = RuntimeConfig::load(configuration)?;
    let mut owner = OperatorState::open(&config, storage).await?;
    let result = async {
        let audit = owner.audit.clone();
        crate::local_recovery::require_runtime_ready(audit.store())?;
        let operation = Uuid::new_v4().to_string();
        audit
            .record(operator_event(
                &operation,
                kasumi_engine::SecurityOutcome::Started,
            ))
            .await?;
        let result = async {
            let root = installation_root(&config)?;
            let ca_key_pem = private_files::read(&root.join("operator/ca-key.pem"), 1 << 20)?;
            let ca_pem = private_files::read(&root.join("tls/ca.pem"), 1 << 20)?;
            // Rustls checks the certificate's public key against the private key before
            // any leaf is generated or replaced. Parsing two PEM files is insufficient.
            let ca_identity = kasumi_transport::TlsIdentity::from_pem(&ca_pem, &ca_key_pem)?;
            kasumi_transport::server_config(
                &ca_identity,
                kasumi_transport::ClientAuthentication::OAuth,
            )?;
            let ca_key = rcgen::KeyPair::from_pem(std::str::from_utf8(&ca_key_pem)?)?;
            let issuer = rcgen::Issuer::from_ca_cert_pem(std::str::from_utf8(&ca_pem)?, &ca_key)?;
            let client = TlsFiles {
                certificate: root.join("profiles/client.pem"),
                private_key: root.join("profiles/client-key.pem"),
            };
            let old_admin_pin = hex::encode(config.admin.tls.load()?.certificate_pin());
            let mut replacements = Vec::with_capacity(4);
            for (name, files, client_auth) in [
                ("mcp", &config.mcp.tls, false),
                ("native", &config.native.tls, false),
                ("admin", &config.admin.tls, false),
                ("client", &client, true),
            ] {
                let key = rcgen::KeyPair::generate()?;
                let mut parameters = parameters(name, 365)?;
                parameters.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
                parameters.extended_key_usages = vec![if client_auth {
                    rcgen::ExtendedKeyUsagePurpose::ClientAuth
                } else {
                    rcgen::ExtendedKeyUsagePurpose::ServerAuth
                }];
                let certificate = parameters.signed_by(&key, &issuer)?;
                let key_pem = zeroize::Zeroizing::new(key.serialize_pem());
                let certificate_pem = certificate.pem();
                let identity = kasumi_transport::TlsIdentity::from_pem(
                    certificate_pem.as_bytes(),
                    key_pem.as_bytes(),
                )?;
                kasumi_transport::server_config(
                    &identity,
                    kasumi_transport::ClientAuthentication::OAuth,
                )?;
                replacements.push((files.clone(), key_pem, certificate_pem));
            }
            for (files, key_pem, certificate_pem) in replacements {
                private_files::replace(&files.private_key, key_pem.as_bytes())?;
                private_files::replace(&files.certificate, certificate_pem.as_bytes())?;
            }
            let native_pin = hex::encode(config.native.tls.load()?.certificate_pin());
            let admin_pin = hex::encode(config.admin.tls.load()?.certificate_pin());
            let control = owner.control().await?;
            let control_result = async {
                let context = offline_context(&control)?;
                let plane = kasumi_engine::control::ControlPlane::new(control.clone())?;
                plane.require_initialized(&context).await?;
                {
                    let mut topology = plane
                        .topology(&context)
                        .await?
                        .context("installed Control topology is missing")?;
                    let node = topology
                        .topology
                        .nodes
                        .get_mut(&1)
                        .context("standalone control node is missing")?;
                    node.certificate_pins =
                        BTreeSet::from([hex::encode(config.mcp.tls.load()?.certificate_pin())]);
                    plane
                        .replace_topology(
                            context,
                            topology.topology,
                            kasumi_types::Precondition::Version(topology.version),
                            format!("certificate-rotation-{operation}"),
                        )
                        .await?;
                }
                Ok::<_, anyhow::Error>(())
            }
            .await;
            control.shutdown().await?;
            control_result?;
            for entry in std::fs::read_dir(root.join("profiles"))? {
                let path = entry?.path();
                if path
                    .extension()
                    .is_some_and(|extension| extension == "json")
                    && let Ok(mut profile) = ClientProfile::load(&path)
                {
                    profile.native_certificate_pin = native_pin.clone();
                    for member in profile.administrative_members.values_mut() {
                        if member.certificate_pins.remove(&old_admin_pin) {
                            member.certificate_pins.insert(admin_pin.clone());
                        }
                    }
                    private_files::replace(&path, &serde_json::to_vec_pretty(&profile)?)?;
                }
            }
            Ok::<_, anyhow::Error>(serde_json::json!({
                "native_certificate_pin": native_pin,
                "admin_certificate_pin": admin_pin,
            }))
        }
        .await;
        let recorded = audit
            .record(operator_event(
                &operation,
                if result.is_ok() {
                    kasumi_engine::SecurityOutcome::Succeeded
                } else {
                    kasumi_engine::SecurityOutcome::Failed
                },
            ))
            .await;

        recorded?;
        result
    }
    .await;
    owner.finish(result).await
}

pub async fn backup_operator_keys(configuration: &Path, output: &Path) -> Result<()> {
    let config = RuntimeConfig::load(configuration)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    backup_operator_keys_with_storage(configuration, output, storage).await
}

pub(crate) async fn backup_operator_keys_with_storage(
    configuration: &Path,
    output: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<()> {
    let configuration = configuration.to_owned();
    let output = output.to_owned();
    operator::run(async move { backup_operator_keys_owned(&configuration, &output, storage).await })
        .await
}

async fn backup_operator_keys_owned(
    configuration: &Path,
    output: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<()> {
    let config = RuntimeConfig::load(configuration)?;
    let mut owner = OperatorState::open(&config, storage).await?;
    let result = async {
        let audit = owner.audit.clone();
        let operation = Uuid::new_v4().to_string();
        audit
            .record(operator_event(
                &operation,
                kasumi_engine::SecurityOutcome::Started,
            ))
            .await?;
        let result = crate::standalone_key_backup::create(&config, output);
        if let Err(error) = result {
            let _ = audit
                .record(operator_event(
                    &operation,
                    kasumi_engine::SecurityOutcome::Failed,
                ))
                .await;

            return Err(error);
        }
        audit
            .record(operator_event(
                &operation,
                kasumi_engine::SecurityOutcome::Succeeded,
            ))
            .await?;

        Ok(())
    }
    .await;
    owner.finish(result).await
}

/// Creates an exclusive private directory. Failure leaves a visibly incomplete
/// private installation; it never overwrites or adopts an existing directory.
pub async fn initialize(
    directory: &Path,
    tenant: &str,
    directory_policy: kasumi_store::DirectoryPolicy,
    network: StandaloneNetwork,
) -> Result<InitializedInstallation> {
    network.validate()?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(
        &example_config(directory_policy)?.admission,
    )?;
    initialize_with_storage(directory, tenant, directory_policy, network, storage).await
}

pub(crate) async fn initialize_with_storage(
    directory: &Path,
    tenant: &str,
    directory_policy: kasumi_store::DirectoryPolicy,
    network: StandaloneNetwork,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<InitializedInstallation> {
    directory_policy.validate()?;
    network.validate()?;
    // The owned operation retains its exclusive lock and drains every database
    // even if the CLI invocation loses its reply. Installation completion is a
    // durable marker written only after those owners have drained.
    let directory = directory.to_owned();
    let tenant = tenant.to_owned();
    operator::run(async move {
        initialize_owned(
            &directory,
            &tenant,
            directory_policy,
            network,
            InitializationOptions::default(),
            storage,
        )
        .await
    })
    .await
}
/// Install a real external tenant-audit destination before the placement
/// identity is persisted. Used by the protected outage observation fixture.
#[cfg(test)]
pub(crate) async fn initialize_with_storage_and_tenant_archive(
    directory: &Path,
    tenant: &str,
    storage: crate::runtime_memory::RuntimeStorage,
    archive: crate::audit_destination::AuditDestinationConfig,
) -> Result<InitializedInstallation> {
    let directory_policy = kasumi_store::DirectoryPolicy::fixture();
    let network = StandaloneNetwork::fixture();
    directory_policy.validate()?;
    network.validate()?;
    let directory = directory.to_owned();
    let tenant = tenant.to_owned();
    operator::run(async move {
        initialize_owned(
            &directory,
            &tenant,
            directory_policy,
            network,
            InitializationOptions {
                tenant_audit_archive: Some(archive),
                ..Default::default()
            },
            storage,
        )
        .await
    })
    .await
}
/// Install actual encrypted local groups in one owned offline initialization.
/// This fixture exercises the production catalog and topology path, not a
/// synthetic readiness cache or absent-route count.
#[cfg(test)]
pub(crate) async fn initialize_many_with_storage(
    directory: &Path,
    tenant_count: usize,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<InitializedInstallation> {
    ensure!(
        (1..=10_000).contains(&tenant_count),
        "fixture tenant count is invalid"
    );
    let directory = directory.to_owned();
    operator::run(async move {
        initialize_owned(
            &directory,
            "healthy-000",
            kasumi_store::DirectoryPolicy::fixture(),
            StandaloneNetwork::fixture(),
            InitializationOptions {
                extra_tenants: tenant_count - 1,
                ..Default::default()
            },
            storage,
        )
        .await
    })
    .await
}
#[derive(Default)]
struct InitializationOptions {
    #[cfg(test)]
    obstruct_profile_publication: bool,
    #[cfg(test)]
    extra_tenants: usize,
    #[cfg(test)]
    tenant_audit_archive: Option<crate::audit_destination::AuditDestinationConfig>,
}
async fn initialize_owned(
    directory: &Path,
    tenant: &str,
    directory_policy: kasumi_store::DirectoryPolicy,
    network: StandaloneNetwork,
    options: InitializationOptions,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<InitializedInstallation> {
    #[cfg(not(test))]
    let _ = options;
    kasumi_types::validate_name(tenant)?;
    ensure!(
        !tenant.starts_with("kasumi.") && !tenant.starts_with("__kasumi_"),
        "reserved tenant name"
    );
    ensure!(
        directory.is_absolute(),
        "installation directory must be absolute"
    );
    let mut config = example_config(directory_policy)?;
    config.admission = storage.policy().clone();
    let admission = storage.facade(&config.admission)?;
    let mut pending = crate::startup_resources::Resources::default();
    pending.owned_admissions.push(admission.clone());
    private_files::create_directory(directory)?;
    let directory = std::fs::canonicalize(directory)?;
    for name in ["data", "operator", "tls", "profiles", "backups"] {
        private_files::create_directory(&directory.join(name))?;
    }
    let data = directory.join("data");
    let operator = directory.join("operator");
    let tls = directory.join("tls");
    let profiles = directory.join("profiles");
    // Root directory creation remains the explicit installer boundary. Directory
    // mutation/accounting below those roots still needs its own NodeDisk API.
    let persistent_config = storage.new_installation_disk_config(
        BTreeMap::from([
            ("data".into(), data.clone()),
            ("backups".into(), directory.join("backups")),
        ]),
        directory_policy,
    )?;
    let persistent_disk = crate::persistent_disk::open(&persistent_config, &storage)?;
    pending.standalone_lock = Some(create_installed_file(
        &persistent_config,
        &persistent_disk,
        &data.join("installation.lock"),
        &[],
        0,
    )?);
    let prepared = async {
        let installation_id = Uuid::new_v4();
        let control_incarnation = Uuid::new_v4();
        let tenant_incarnation = Uuid::new_v4();
        let database_path = data.join("node.redb");
        let installation = Installation {
            format: 4,
            installation_id,
            origin_node_id: STANDALONE_ORIGIN_NODE_ID,
            control_incarnation,
            database_id: Uuid::new_v4(),
            database_path: database_path.clone(),
        };
        // Freeze physical ownership before the database inode may be created. The
        // separate completion marker never authorizes adoption of an interrupted init.
        create_installed_file(
            &persistent_config,
            &persistent_disk,
            &data.join("initialization.json"),
            &serde_json::to_vec(&installation)?,
            16 << 10,
        )?;

        for domain in [
            "application",
            "custody",
            "control",
            "control-custody",
            "security",
        ] {
            FileKeyProvider::initialize(&operator.join(format!("{domain}-keys.json")), domain)?;
        }
        let signer = operator.join("signers.json");
        initialize_signer(&signer)?;
        let (ca, ca_key) = generate_ca()?;
        private_files::create(
            &operator.join("ca-key.pem"),
            ca_key.serialize_pem().as_bytes(),
        )?;
        private_files::create(&tls.join("ca.pem"), ca.pem().as_bytes())?;
        let mut identities = std::collections::BTreeMap::new();
        for name in ["mcp", "native", "admin"] {
            identities.insert(name, generate_identity(&tls, name, &ca, &ca_key, false)?);
        }
        let client_identity = generate_identity(&profiles, "client", &ca, &ca_key, true)?;
        let native_pin = hex::encode(identities["native"].load()?.certificate_pin());
        let admin_pin = hex::encode(identities["admin"].load()?.certificate_pin());
        let policy = Policy {
            grants: vec![Grant {
                principal: "administrator".into(),
                collection: None,
                actions: BTreeSet::from([
                    Action::Read,
                    Action::Write,
                    Action::Admin,
                    Action::Audit,
                ]),
            }],
            strict_read_audit: false,
        };
        let provider = |domain: &str| KeyProviderSettings::File {
            path: operator.join(format!("{domain}-keys.json")),
        };
        config.mode = DeploymentMode::Standalone;
        config.serving_authorities.clear();
        config.signer_verifier = None;
        config.replication = None;
        config.database_path = database_path.clone();
        config.database_id = installation.database_id;
        config.scratch_disk.directory = directory.join("scratch");
        config.persistent_disk = persistent_config.clone();
        config.backup_destinations = std::collections::BTreeMap::from([(
            "local".into(),
            crate::administration::DestinationConfig::Filesystem {
                directory: directory.join("backups"),
                max_bytes: kasumi_store::MAX_BACKUP_BUNDLE_BYTES,
            },
        )]);
        config.auth = AuthConfig {
            issuer: format!("https://localhost/kasumi/{installation_id}"),
            audience: format!("https://localhost/kasumi/{installation_id}/api"),
            source: AuthKeySource::Local {
                signer_file: signer.clone(),
            },
            algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
            access_token_types: BTreeSet::from(["at+jwt".into()]),
        };
        config.mcp.listen = network.mcp_listen;
        config.mcp.tls = identities["mcp"].clone();
        config.mcp.protocol = crate::mcp::McpConfig::new(network.mcp_public_url.clone())?;
        config.native.listen = network.native_listen;
        config.native.tls = identities["native"].clone();
        config.native.client_ca = tls.join("ca.pem");
        config.admin.listen = network.admin_listen;
        config.admin.tls = identities["admin"].clone();
        config.admin.client_ca = tls.join("ca.pem");
        config.control.keys = provider("control");
        config.control.custody_keys = provider("control-custody");
        config.control.initial_policy = policy.clone();
        config.control.incarnation = Some(control_incarnation.to_string());
        config.security_audit.keys = provider("security");
        config.tenants[0].tenant = tenant.into();
        config.tenants[0].serving = TenantServingConfig::Standalone { installation_id };
        config.tenants[0].keys = provider("application");
        config.tenants[0].custody_keys = provider("custody");
        config.tenants[0].initial_policy = policy;
        config.tenants[0].incarnation = Some(tenant_incarnation.to_string());
        #[cfg(test)]
        if let Some(archive) = &options.tenant_audit_archive {
            config
                .tenant_audit_archives
                .insert(tenant.into(), archive.clone());
        }
        #[cfg(test)]
        for index in 1..=options.extra_tenants {
            let name = format!("healthy-{index:03}");
            let application = format!("{name}-application");
            let custody = format!("{name}-custody");
            FileKeyProvider::initialize(
                &operator.join(format!("{application}-keys.json")),
                &application,
            )?;
            FileKeyProvider::initialize(&operator.join(format!("{custody}-keys.json")), &custody)?;
            let mut extra = config.tenants[0].clone();
            extra.tenant = name;
            extra.keys = provider(&application);
            extra.custody_keys = provider(&custody);
            extra.incarnation = Some(Uuid::new_v4().to_string());
            config.tenants.push(extra);
        }
        config.validate()?;
        let node = NodeStore::create_new(
            &database_path,
            installation.database_id,
            persistent_disk.clone(),
            storage.open_scratch(&config.scratch_disk)?,
        )?;
        pending.owned_nodes.push(node.clone());
        #[cfg(test)]
        ownership_tests::checkpoint(&database_path, "initialize-node").await?;
        let security_store = TenantStore::initialize_catalog(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            config
                .security_audit
                .keys
                .provider(Arc::new(crate::runtime::file_secret))?,
            StorageAccess::security_audit(),
        )
        .await?;
        pending.stores.push(security_store.clone());
        let audit = config
            .security_audit
            .initialize(security_store.clone(), admission)?;
        pending.audits.push(audit.clone());
        #[cfg(test)]
        ownership_tests::checkpoint(&database_path, "initialize-audit").await?;
        provision_databases(&config, node.clone(), audit.clone()).await?;
        let result = async {
            #[cfg(test)]
            if options.obstruct_profile_publication {
                // Inject a real exclusive-file publication failure after every
                // database has been initialized and drained.
                private_files::create(&profiles.join("control.token"), b"blocked")?;
            }
            let credentials = LocalCredentials::open(
                security_store.clone(),
                signer,
                config.auth.issuer.clone(),
                config.auth.audience.clone(),
            )?;
            for (name, tenant, resource) in [
                (
                    "control",
                    crate::runtime::CONTROL_TENANT,
                    CredentialResource::Control {
                        incarnation: control_incarnation,
                    },
                ),
                (
                    "default",
                    tenant,
                    CredentialResource::Database {
                        incarnation: tenant_incarnation,
                    },
                ),
            ] {
                let issued = credentials.create(
                    CreateCredential {
                        family_id: Uuid::new_v4(),
                        principal: "administrator".into(),
                        tenant: tenant.into(),
                        resource: resource.clone(),
                        scopes: BTreeSet::from([
                            Action::Read,
                            Action::Write,
                            Action::Admin,
                            Action::Audit,
                        ]),
                        lifetime_seconds: 3600,
                    },
                    "initializer",
                )?;
                let bearer_file = profiles.join(format!("{name}.token"));
                private_files::create(&bearer_file, issued.token.as_bytes())?;
                let profile = ClientProfile {
                    format: 2,
                    family_id: issued.family_id,
                    tenant: tenant.into(),
                    principal: "administrator".into(),
                    resource,
                    native_endpoint: format!("https://localhost:{}", network.native_listen.port()),
                    administrative_members: BTreeMap::from([(
                        1,
                        ProfileAuthorityEndpoint {
                            endpoint: format!("https://localhost:{}", network.admin_listen.port()),
                            certificate_pins: BTreeSet::from([admin_pin.clone()]),
                        },
                    )]),
                    mcp_endpoint: network.mcp_public_url.clone(),
                    identity: client_identity.clone().into(),
                    server_ca: tls.join("ca.pem"),
                    native_certificate_pin: native_pin.clone(),
                    bearer_file,
                };
                private_files::create(
                    &profiles.join(format!("{name}.json")),
                    &serde_json::to_vec_pretty(&profile)?,
                )?;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;

        result?;
        drop(audit);
        drop(security_store);
        drop(node);
        Ok::<_, anyhow::Error>((config, installation))
    }
    .await;
    let (config, installation) = operator::finish_resources(&mut pending, prepared).await?;
    // Drop every drained resource before publication, retaining the exclusive lock.
    pending.databases.clear();
    pending.audits.clear();
    pending.stores.clear();
    pending.owned_nodes.clear();
    pending.borrowed_nodes.clear();
    pending.owned_admissions.clear();
    let configuration = directory.join("kasumi.json");
    private_files::create(&configuration, &serde_json::to_vec_pretty(&config)?)?;
    create_installed_file(
        &persistent_config,
        &persistent_disk,
        &data.join("installation.json"),
        &serde_json::to_vec(&installation)?,
        16 << 10,
    )?;
    Ok(InitializedInstallation {
        configuration,
        control_profile: profiles.join("control.json"),
        tenant_profile: profiles.join("default.json"),
    })
}

#[cfg(test)]
pub(crate) async fn configure_test_topology(
    config: &RuntimeConfig,
    storage: crate::runtime_memory::RuntimeStorage,
) {
    // Tests allocate fresh private listener ports after init. Change the already
    // installed topology with an explicit stopped-operator CAS, never restart genesis.
    let mut owner = OperatorState::open(config, storage).await.unwrap();
    let database = owner.control().await.unwrap();
    let plane = kasumi_engine::control::ControlPlane::new(database.clone()).unwrap();
    let context = crate::runtime::configured_control_context(&config.control).unwrap();
    let current = plane.topology(&context).await.unwrap().unwrap();
    let mut topology = current.topology;
    topology.nodes = initial_topology(config).unwrap().nodes;
    plane
        .replace_topology(
            context,
            topology,
            kasumi_types::Precondition::Version(current.version),
            Uuid::new_v4().to_string(),
        )
        .await
        .unwrap();
    drop(plane);
    database.shutdown().await.unwrap();
    drop(database);
    owner.finish(Ok(())).await.unwrap();
}

fn initial_topology(config: &RuntimeConfig) -> Result<kasumi_engine::control::ControlTopology> {
    use kasumi_engine::control::{ControlNode, ControlTopology, DeploymentMode, TenantRoute};
    let topology = ControlTopology {
        nodes: std::collections::BTreeMap::from([(
            1,
            ControlNode {
                endpoint: url::Url::parse(&config.mcp.protocol.public_url)?
                    .origin()
                    .ascii_serialization(),
                failure_domain: "local".into(),
                certificate_pins: BTreeSet::from([hex::encode(
                    config.mcp.tls.load()?.certificate_pin(),
                )]),
            },
        )]),
        tenants: config
            .tenants
            .iter()
            .map(|tenant| {
                Ok((
                    tenant.tenant.clone(),
                    TenantRoute {
                        incarnation: tenant
                            .incarnation
                            .clone()
                            .context("standalone incarnation missing")?,
                        mode: DeploymentMode::Local,
                        voters: BTreeSet::from([1]),
                    },
                ))
            })
            .collect::<Result<_>>()?,
    };
    topology.validate()?;
    Ok(topology)
}

async fn provision_databases(
    config: &RuntimeConfig,
    node: Arc<NodeStore>,
    audit: Arc<kasumi_engine::SecurityAudit>,
) -> Result<()> {
    config.validate_selected_key_domains(&config.tenants.iter().collect::<Vec<_>>())?;
    let enrollment = crate::node_enrollment::Enrollment::begin(
        audit.store(),
        &crate::node_enrollment::Input::Data {
            configuration: Box::new(config.clone()),
        },
    )?;
    for (tenant, policy, limits, incarnation, application, custody, access) in std::iter::once((
        crate::runtime::CONTROL_TENANT,
        &config.control.initial_policy,
        &config.control.initial_limits,
        config
            .control
            .incarnation
            .as_deref()
            .context("Control incarnation missing")?,
        &config.control.keys,
        &config.control.custody_keys,
        StorageAccess::node_control(),
    ))
    .chain(config.tenants.iter().map(|tenant| {
        let TenantServingConfig::Standalone { installation_id } = tenant.serving else {
            unreachable!("validated standalone initialization")
        };
        let incarnation = tenant
            .incarnation
            .as_deref()
            .expect("validated standalone incarnation");
        (
            tenant.tenant.as_str(),
            &tenant.initial_policy,
            &tenant.initial_limits,
            incarnation,
            &tenant.keys,
            &tenant.custody_keys,
            StorageAccess::standalone(
                installation_id,
                &tenant.tenant,
                Uuid::parse_str(incarnation).expect("validated incarnation"),
            )
            .expect("validated standalone"),
        )
    })) {
        let mut pending = crate::startup_resources::Resources::default();
        pending.borrowed_nodes.push(node.clone());
        let configured = async {
            let source = Arc::new(crate::runtime::file_secret);
            let stores = kasumi_store::TenantStorageSet::initialize_catalogs(
                node.clone(),
                tenant.into(),
                application.provider(source.clone())?,
                custody.provider(source)?,
                access,
            )
            .await?;
            pending.stores.push(stores.application().clone());
            pending.stores.push(stores.custody().store().clone());
            config.install_tenant_audit_archive(stores.application(), None)?;
            let database = kasumi_engine::open_local_with_incarnation(
                stores.clone(),
                policy.clone(),
                limits.clone(),
                audit.clone(),
                Uuid::parse_str(incarnation)?,
            )
            .await?;
            pending.databases.push(database.clone());
            if tenant == crate::runtime::CONTROL_TENANT {
                let plane = kasumi_engine::control::ControlPlane::new(database)?;
                let context = crate::runtime::configured_control_context(&config.control)?;
                plane.initialize(context.clone()).await?;
                plane
                    .replace_topology(
                        context,
                        initial_topology(config)?,
                        kasumi_types::Precondition::Absent,
                        "standalone-initial-topology".into(),
                    )
                    .await?;
            }
            crate::runtime::persisted_bootstrap_fingerprint(stores.application())
        }
        .await;
        let drained = crate::startup_owner::finish(&mut pending).await;
        let fingerprint = match (configured, drained) {
            (Err(error), Err(drain)) => {
                return Err(error.context(drain));
            }
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(drain)) => return Err(drain.into()),
            (Ok(fingerprint), Ok(())) => fingerprint,
        };
        if tenant != crate::runtime::CONTROL_TENANT {
            enrollment.record_genesis_tenant(
                audit.store(),
                tenant,
                Uuid::parse_str(incarnation)?,
                fingerprint,
            )?;
        }
    }
    enrollment.complete(audit.store())
}

fn parameters(name: &str, days: i64) -> Result<rcgen::CertificateParams> {
    let mut parameters =
        rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])?;
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    parameters.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    parameters.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);
    Ok(parameters)
}
fn generate_ca() -> Result<(rcgen::Certificate, rcgen::KeyPair)> {
    let mut parameters = parameters("Kasumi local installation CA", 3650)?;
    parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    parameters.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let key = rcgen::KeyPair::generate()?;
    Ok((parameters.self_signed(&key)?, key))
}
fn generate_identity(
    directory: &Path,
    name: &str,
    ca: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
    client: bool,
) -> Result<TlsFiles> {
    let mut parameters = parameters(name, 365)?;
    parameters.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![if client {
        rcgen::ExtendedKeyUsagePurpose::ClientAuth
    } else {
        rcgen::ExtendedKeyUsagePurpose::ServerAuth
    }];
    let key = rcgen::KeyPair::generate()?;
    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca.pem(), ca_key)?;
    let certificate = parameters.signed_by(&key, &issuer)?;
    let files = TlsFiles {
        certificate: directory.join(format!("{name}.pem")),
        private_key: directory.join(format!("{name}-key.pem")),
    };
    private_files::create(&files.certificate, certificate.pem().as_bytes())?;
    private_files::create(&files.private_key, key.serialize_pem().as_bytes())?;
    Ok(files)
}

#[cfg(test)]
#[path = "standalone_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "standalone_tenant_enrollment_tests.rs"]
mod tenant_enrollment_tests;

#[cfg(test)]
#[path = "standalone_backup_cli_tests.rs"]
mod backup_cli_tests;

#[cfg(test)]
#[path = "standalone_provision_tests.rs"]
mod provision_tests;

#[cfg(test)]
#[path = "standalone_operator_tests.rs"]
pub(crate) mod ownership_tests;

#[cfg(test)]
#[path = "standalone_storage_tests.rs"]
mod storage_tests;
