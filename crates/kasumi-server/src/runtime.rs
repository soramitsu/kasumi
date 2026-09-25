//! Operator-controlled startup and shutdown. Configuration contains credential
//! references, never plaintext tokens. A mode is explicit and durably bound by
//! the engine; a partition never changes its voter count.

use crate::{
    api::DatabaseRegistry,
    auth::{AuthConfig, Authenticator},
    cluster::{ClusterNetwork, PeerConfig, PeerLimits},
    mcp::McpConfig,
    rpc::{NativeAdmin, NativeData},
    tls::{self, ListenerLimits},
};
use anyhow::{Context, Result, ensure};
use kasumi_engine::{Database, ReplicaPlacement, ReplicatedBootstrap};
use kasumi_store::{NodeStore, TenantStorageSet, TenantStore, TransitConfig, TransitKeyProvider};
use kasumi_transport::{CertificatePin, ClientAuthentication, TlsIdentity};
#[cfg(test)]
use kasumi_types::Precondition;
use kasumi_types::{Action, Grant, Limits, Policy, RequestContext};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::sync::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use kasumi_engine::{
    SECURITY_TENANT, SecurityAudit, SecurityEvent, SecurityEventKind, SecurityOutcome,
    TransportAuditMetadata,
};
pub const CONTROL_TENANT: &str = "__kasumi_control";
const MAX_CONFIG_BYTES: usize = 2 << 20;
const MAX_PEM_BYTES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    Standalone,
    Replicated,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpEndpoint {
    pub listen: SocketAddr,
    pub tls: TlsFiles,
    pub protocol: McpConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutualTlsEndpoint {
    pub listen: SocketAddr,
    pub tls: TlsFiles,
    pub client_ca: PathBuf,
}

/// Separate named wrapping key for each tenant and for service-security records.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitSettings {
    pub endpoint: String,
    pub mount: String,
    pub key_name: String,
    pub token_file: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub ca_certificate: Option<PathBuf>,
    #[serde(default)]
    pub derived: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyProviderSettings {
    Transit(TransitSettings),
    File { path: PathBuf },
}
impl KeyProviderSettings {
    pub(crate) fn validate(&self) -> Result<String> {
        match self {
            Self::Transit(settings) => settings.validate(),
            Self::File { path } => {
                ensure!(path.is_absolute(), "file keyring path must be absolute");
                Ok(format!("file:{}", path.display()))
            }
        }
    }
    pub(crate) fn provider(
        &self,
        source: crate::serving_runtime::CredentialSource,
    ) -> Result<Arc<dyn kasumi_store::KeyProvider>> {
        match self {
            Self::Transit(settings) => Ok(settings.provider_with_source(source)?),
            Self::File { path } => Ok(Arc::new(kasumi_store::FileKeyProvider::open(path)?)),
        }
    }
    pub fn transit_mut(&mut self) -> Result<&mut TransitSettings> {
        match self {
            Self::Transit(settings) => Ok(settings),
            _ => anyhow::bail!("key provider is not Transit"),
        }
    }
    pub(crate) fn identity_descriptor(&self) -> Result<serde_json::Value> {
        Ok(match self {
            Self::File { path } => {
                serde_json::json!({"kind":"file", "identity":kasumi_store::FileKeyProvider::open(path)?.key_ref()})
            }
            Self::Transit(settings) => {
                serde_json::json!({"kind":"transit", "endpoint":settings.endpoint,"mount":settings.mount,"key_name":settings.key_name,"namespace":settings.namespace,"derived":settings.derived})
            }
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfig {
    pub tenant: String,
    pub serving: crate::serving_runtime::TenantServingConfig,
    pub keys: KeyProviderSettings,
    pub custody_keys: KeyProviderSettings,
    pub initial_policy: Policy,
    #[serde(default)]
    pub initial_limits: Limits,
    /// Fixed and identical across replicas; local creation generates its own UUID.
    #[serde(default)]
    pub incarnation: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlConfig {
    /// Explicit installed closed lifecycle protocol; absence disables this service.
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    pub lifecycle: Option<crate::lifecycle_runtime::LifecycleRuntimeConfig>,
    /// Select an already-authorized operator independently of the immutable genesis policy.
    #[serde(default)]
    pub startup_principal: Option<String>,
    pub keys: KeyProviderSettings,
    pub custody_keys: KeyProviderSettings,
    pub initial_policy: Policy,
    #[serde(default)]
    pub initial_limits: Limits,
    #[serde(default)]
    pub incarnation: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditConfig {
    pub keys: KeyProviderSettings,
    pub retention: kasumi_types::AuditRetentionBudget,
    #[serde(default)]
    pub archive: Option<crate::audit_destination::AuditDestinationConfig>,
}

impl SecurityAuditConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        self.retention.validate()?;
        if let Some(archive) = &self.archive {
            archive.validate()?;
        }
        Ok(())
    }

    fn destination(
        &self,
        store: &kasumi_store::TenantStore,
    ) -> Result<Arc<dyn kasumi_store::AuditArchiveDestination>> {
        self.validate()?;
        Ok(match &self.archive {
            None => Arc::new(kasumi_store::FilesystemAuditArchive::open(
                store.durable_directory()?.join("audit-archives"),
                store.persistent_disk().clone(),
            )?) as Arc<dyn kasumi_store::AuditArchiveDestination>,
            Some(config) => config.open(store.persistent_disk().clone())?,
        })
    }

    pub(crate) fn initialize(
        &self,
        store: Arc<kasumi_store::TenantStore>,
        admission: Arc<kasumi_engine::admission::NodeAdmission>,
    ) -> Result<Arc<SecurityAudit>> {
        let archive = self.destination(&store)?;
        SecurityAudit::initialize_with_archive(store, self.retention.clone(), archive, admission)
    }

    pub(crate) fn open(
        &self,
        store: Arc<kasumi_store::TenantStore>,
        admission: Arc<kasumi_engine::admission::NodeAdmission>,
    ) -> Result<Arc<SecurityAudit>> {
        let archive = self.destination(&store)?;
        SecurityAudit::open_with_archive(store, self.retention.clone(), archive, admission)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaConfig {
    pub node_id: u64,
    pub endpoint: String,
    pub certificate_pins: Vec<String>,
    pub failure_domain: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicationConfig {
    /// Explicit original voter identities, retained when the peer pool grows.
    pub initial_voters: BTreeSet<u64>,
    pub node_id: u64,
    pub listener: MutualTlsEndpoint,
    pub peers: Vec<ReplicaConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Installed external archive overrides by tenant, including __kasumi_control.
    /// An empty map selects each store's private durable filesystem cache.
    pub tenant_audit_archives: BTreeMap<String, crate::audit_destination::AuditDestinationConfig>,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    pub target_recovery: Option<crate::target_runtime_config::TargetRecoveryConfig>,
    pub serving_authorities: BTreeMap<String, crate::serving_runtime::ServingAuthorityConfig>,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    pub signer_verifier: Option<crate::signer_runtime::SignerVerifierConfig>,
    pub admission: kasumi_engine::admission::AdmissionConfig,
    #[serde(default)]
    pub backup_destinations: BTreeMap<String, crate::administration::DestinationConfig>,
    pub format: u32,
    pub mode: DeploymentMode,
    pub database_path: PathBuf,
    pub database_id: Uuid,
    pub persistent_disk: kasumi_store::NodeDiskConfig,
    pub scratch_disk: kasumi_store::ScratchDiskConfig,
    pub auth: AuthConfig,
    pub mcp: McpEndpoint,
    pub native: MutualTlsEndpoint,
    pub admin: MutualTlsEndpoint,
    pub control: ControlConfig,
    pub security_audit: SecurityAuditConfig,
    pub tenants: Vec<TenantConfig>,
    #[serde(default)]
    pub replication: Option<ReplicationConfig>,
}

impl RuntimeConfig {
    /// Explicit first HA node enrollment. All local catalogs and immutable
    /// genesis are installed under the original captured serving grants.
    pub async fn provision_node(&self) -> Result<()> {
        crate::data_node_enrollment::initialize(self.clone()).await
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = read_bounded(path.as_ref(), MAX_CONFIG_BYTES)?;
        let config: Self =
            serde_json::from_slice(&bytes).context("invalid runtime configuration JSON")?;
        config.validate()?;
        Ok(config)
    }

    /// Structural/security validation performs no filesystem writes, KMS calls,
    /// environment-secret reads, or network requests.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.format == 1, "unsupported runtime configuration format");
        absolute(&self.database_path)?;
        ensure!(
            !self.database_id.is_nil(),
            "installed node database identity is nil"
        );
        self.admission.validate()?;
        self.scratch_disk.validate()?;
        self.validate_persistent_disk()?;
        for (tenant, archive) in &self.tenant_audit_archives {
            kasumi_types::validate_name(tenant)?;
            ensure!(
                tenant != SECURITY_TENANT && !tenant.starts_with("kasumi.custody/"),
                "service security and custody use their own archive configuration"
            );
            archive.validate()?;
        }
        if let Some(target) = &self.target_recovery {
            target.validate(self)?;
        }
        ensure!(
            self.serving_authorities.is_empty() == self.signer_verifier.is_none(),
            "serving authorities require explicit local durable verifier state"
        );
        if let Some(verifier) = &self.signer_verifier {
            verifier.validate()?;
            ensure!(
                Some(verifier.identity.node_id) == self.replication.as_ref().map(|r| r.node_id)
                    && verifier.database_path != self.database_path,
                "serving verifier physical identity differs"
            );
        }
        for (name, authority) in &self.serving_authorities {
            kasumi_types::validate_name(name)?;
            authority.validate()?;
        }
        for (name, destination) in &self.backup_destinations {
            kasumi_types::validate_name(name)?;
            destination.validate()?;
        }
        Authenticator::new(self.auth.clone())?;
        ensure!(
            !matches!(self.auth.source, crate::auth::AuthKeySource::Local { .. })
                || self.mode == DeploymentMode::Standalone,
            "local credential storage requires standalone mode"
        );
        let mut addresses = BTreeSet::new();
        for address in [self.mcp.listen, self.native.listen, self.admin.listen] {
            ensure!(
                address.port() > 0 && addresses.insert(address),
                "listeners need distinct explicit ports/addresses"
            );
        }
        self.mcp.tls.validate()?;
        self.native.validate()?;
        self.admin.validate()?;
        // Building a router validates protocol origins/hosts without opening it.
        let _ = crate::mcp::router(
            self.mcp.protocol.clone(),
            DatabaseRegistry::default(),
            Authenticator::new(self.auth.clone())?,
        )?;
        ensure!(
            (!self.tenants.is_empty() || self.target_recovery.is_some())
                && self.tenants.len() <= 10_000,
            "configure 1–10000 tenants"
        );
        self.security_audit.validate()?;
        let mut key_refs = BTreeSet::new();
        for transit in std::iter::once(&self.security_audit.keys)
            .chain([&self.control.keys, &self.control.custody_keys])
            .chain(self.signer_verifier.iter().map(|verifier| &verifier.keys))
            .chain(
                self.tenants
                    .iter()
                    .flat_map(|tenant| [&tenant.keys, &tenant.custody_keys]),
            )
        {
            ensure!(
                key_refs.insert(transit.validate()?),
                "application, custody, control, security, and signer trust domains require distinct wrapping keys"
            );
        }
        validate_initial_policy(&self.control.initial_policy)?;
        configured_control_context(&self.control)?;
        if let Some(lifecycle) = &self.control.lifecycle {
            lifecycle.validate(self.mode, self.control.incarnation.as_deref())?;
            if let Some(recovery) = &lifecycle.recovery {
                recovery.validate(self)?;
            }
        }
        let mut tenants = BTreeSet::new();
        let mut standalone_installation = None;
        for tenant in &self.tenants {
            match &tenant.serving {
                crate::serving_runtime::TenantServingConfig::Standalone { installation_id } => {
                    ensure!(
                        self.mode == DeploymentMode::Standalone && !installation_id.is_nil(),
                        "standalone serving requires explicit installation identity and standalone mode"
                    );
                    ensure!(
                        standalone_installation.is_none_or(|id| id == *installation_id),
                        "standalone tenants belong to different installations"
                    );
                    standalone_installation = Some(*installation_id);
                    ensure!(
                        !uuid::Uuid::parse_str(
                            tenant
                                .incarnation
                                .as_deref()
                                .context("standalone incarnation missing")?
                        )?
                        .is_nil(),
                        "standalone incarnation cannot be nil"
                    );
                }
                crate::serving_runtime::TenantServingConfig::Independent { authority } => {
                    ensure!(
                        self.mode == DeploymentMode::Replicated
                            && self.serving_authorities.contains_key(authority),
                        "tenant requires an installed independent authority and replicated data storage"
                    );
                }
                #[cfg(any(test, feature = "test-utils"))]
                crate::serving_runtime::TenantServingConfig::LocalFixture => {}
            }
            kasumi_types::validate_name(&tenant.tenant)?;
            ensure!(
                !tenant.tenant.starts_with("__kasumi_")
                    && !tenant.tenant.starts_with("kasumi.custody/")
                    && tenants.insert(&tenant.tenant),
                "duplicate or reserved tenant name"
            );
            validate_initial_policy(&tenant.initial_policy)?;
            // Reuse the engine's actual policy/quota validation.
            kasumi_engine::TenantEngine::new(
                tenant.tenant.clone(),
                uuid::Uuid::nil().to_string(),
                tenant.initial_policy.clone(),
                tenant.initial_limits.clone(),
            )?;
        }
        kasumi_engine::TenantEngine::new(
            CONTROL_TENANT.into(),
            uuid::Uuid::nil().to_string(),
            self.control.initial_policy.clone(),
            self.control.initial_limits.clone(),
        )?;
        match self.mode {
            DeploymentMode::Standalone => {
                ensure!(
                    self.replication.is_none(),
                    "local mode cannot contain replicated bootstrap configuration"
                );
                for incarnation in std::iter::once(&self.control.incarnation)
                    .chain(self.tenants.iter().map(|t| &t.incarnation))
                    .flatten()
                {
                    ensure!(
                        !uuid::Uuid::parse_str(incarnation)?.is_nil(),
                        "nil local incarnation"
                    );
                }
            }
            DeploymentMode::Replicated => {
                let replication = self
                    .replication
                    .as_ref()
                    .context("replicated mode requires explicit peer configuration")?;
                replication.validate()?;
                ensure!(
                    addresses.insert(replication.listener.listen),
                    "cluster listener must be separate from data/admin listeners"
                );
                self.bootstrap(
                    &self.control.initial_policy,
                    &self.control.initial_limits,
                    self.control.incarnation.as_deref(),
                )?
                .context("replicated bootstrap missing")?
                .validate()?;
                for tenant in &self.tenants {
                    self.bootstrap(
                        &tenant.initial_policy,
                        &tenant.initial_limits,
                        tenant.incarnation.as_deref(),
                    )?
                    .context("replicated bootstrap missing")?
                    .validate()?;
                    kasumi_types::validate_name(&format!(
                        "{}/{}",
                        tenant.tenant,
                        tenant.incarnation.as_deref().unwrap()
                    ))?;
                }
            }
        }
        Ok(())
    }

    /// Compare actual provider identities only for domains selected by explicit
    /// creation or the authenticated installed-tenant ledger. Staged templates
    /// must not load file keyrings during general configuration validation.
    pub(crate) fn validate_selected_key_domains(&self, tenants: &[&TenantConfig]) -> Result<()> {
        let mut identities = BTreeSet::new();
        for settings in std::iter::once(&self.security_audit.keys)
            .chain([&self.control.keys, &self.control.custody_keys])
            .chain(self.signer_verifier.iter().map(|verifier| &verifier.keys))
            .chain(
                tenants
                    .iter()
                    .flat_map(|tenant| [&tenant.keys, &tenant.custody_keys]),
            )
        {
            ensure!(
                identities.insert(serde_json::to_string(&settings.identity_descriptor()?)?),
                "installed key domains share a wrapping identity"
            );
        }
        Ok(())
    }

    pub(crate) fn bootstrap(
        &self,
        policy: &Policy,
        limits: &Limits,
        incarnation: Option<&str>,
    ) -> Result<Option<ReplicatedBootstrap>> {
        if self.mode == DeploymentMode::Standalone {
            return Ok(None);
        }
        let replication = self
            .replication
            .as_ref()
            .context("replication configuration missing")?;
        Ok(Some(ReplicatedBootstrap {
            genesis: kasumi_engine::ReplicatedGenesis::Application,
            incarnation: incarnation
                .context("replicated tenant/control incarnation missing")?
                .into(),
            initial_policy: policy.clone(),
            initial_limits: limits.clone(),
            voters: replication
                .peers
                .iter()
                .filter(|peer| {
                    replication
                        .voters()
                        .expect("validated voters")
                        .contains(&peer.node_id)
                })
                .map(|peer| {
                    (
                        peer.node_id,
                        ReplicaPlacement {
                            address: peer.endpoint.clone(),
                            failure_domain: peer.failure_domain.clone(),
                        },
                    )
                })
                .collect(),
        }))
    }
}

fn validate_initial_policy(policy: &Policy) -> Result<()> {
    ensure!(
        policy
            .grants
            .iter()
            .any(|grant| grant.collection.is_none() && grant.actions.contains(&Action::Admin)),
        "initial policy needs an explicitly named tenant administrator"
    );
    Ok(())
}

impl TlsFiles {
    pub(crate) fn validate(&self) -> Result<()> {
        absolute(&self.certificate)?;
        absolute(&self.private_key)?;
        Ok(())
    }
    pub(crate) fn load(&self) -> Result<TlsIdentity> {
        self.validate()?;
        let cert = read_bounded(&self.certificate, MAX_PEM_BYTES)?;
        let key = read_private_file(&self.private_key, MAX_PEM_BYTES)?;
        TlsIdentity::from_pem(&cert, &key)
    }
}
impl MutualTlsEndpoint {
    pub(crate) fn validate(&self) -> Result<()> {
        self.tls.validate()?;
        absolute(&self.client_ca)?;
        ensure!(
            self.listen.port() > 0,
            "listener needs an explicit nonzero port"
        );
        Ok(())
    }
    pub(crate) fn load(&self) -> Result<Arc<rustls::ServerConfig>> {
        let identity = self.tls.load()?;
        let ca = read_bounded(&self.client_ca, MAX_PEM_BYTES)?;
        kasumi_transport::server_config(
            &identity,
            ClientAuthentication::Required {
                trusted_ca_pem: &ca,
            },
        )
    }
}
impl TransitSettings {
    pub(crate) fn validate(&self) -> Result<String> {
        let url = origin(&self.endpoint)?;
        credential_path(&self.token_file)?;
        ensure!(
            valid_transit_path(&self.mount)
                && valid_transit_path(&self.key_name)
                && !self.key_name.contains('/'),
            "invalid Transit mount or key name"
        );
        if let Some(namespace) = &self.namespace {
            ensure!(valid_transit_path(namespace), "invalid Transit namespace");
        }
        if let Some(ca) = &self.ca_certificate {
            absolute(ca)?;
        }
        Ok(format!(
            "{}|{}|{}|{}",
            url,
            self.namespace.as_deref().unwrap_or(""),
            self.mount,
            self.key_name
        ))
    }
    pub(crate) fn provider_with_source(
        &self,
        source: crate::serving_runtime::CredentialSource,
    ) -> Result<Arc<TransitKeyProvider>> {
        self.validate()?;
        let path = self.token_file.clone();
        Ok(Arc::new(TransitKeyProvider::new(TransitConfig {
            endpoint: self.endpoint.clone(),
            mount: self.mount.clone(),
            key_name: self.key_name.clone(),
            credential: Arc::new(move || source(&path)),
            namespace: self.namespace.clone(),
            derived: self.derived,
            ca_pem: self
                .ca_certificate
                .as_ref()
                .map(|path| read_bounded(path, MAX_PEM_BYTES))
                .transpose()?,
        })?))
    }
}
impl ReplicationConfig {
    pub(crate) fn control_nodes(
        &self,
    ) -> Result<BTreeMap<u64, kasumi_engine::control::ControlNode>> {
        self.peers
            .iter()
            .map(|peer| {
                Ok((
                    peer.node_id,
                    kasumi_engine::control::ControlNode {
                        endpoint: origin(&peer.endpoint)?.origin().ascii_serialization(),
                        failure_domain: peer.failure_domain.clone(),
                        certificate_pins: peer
                            .certificate_pins
                            .iter()
                            .map(|pin| pin.to_ascii_lowercase())
                            .collect(),
                    },
                ))
            })
            .collect()
    }

    pub(crate) fn voters(&self) -> Result<BTreeSet<u64>> {
        ensure!(
            self.initial_voters.len() == 3
                && self
                    .initial_voters
                    .iter()
                    .all(|id| self.peers.iter().any(|p| p.node_id == *id)),
            "initial_voters must explicitly name exactly three configured original voters"
        );
        Ok(self.initial_voters.clone())
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.listener.validate()?;
        ensure!(
            self.node_id > 0 && (3..=64).contains(&self.peers.len()),
            "replicated runtime requires 3 to 64 explicitly configured peers"
        );
        let mut ids = BTreeSet::new();
        let voters = self.voters()?;
        let mut domains = BTreeSet::new();
        let mut pins = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for peer in &self.peers {
            ensure!(
                peer.node_id > 0 && ids.insert(peer.node_id),
                "duplicate or invalid replica node ID"
            );
            kasumi_types::validate_name(&peer.failure_domain)?;
            ensure!(
                !voters.contains(&peer.node_id) || domains.insert(&peer.failure_domain),
                "replicas require independent failure domains"
            );
            ensure!(
                endpoints.insert(origin(&peer.endpoint)?.to_string()),
                "replicas require distinct endpoints"
            );
            ensure!(
                !peer.certificate_pins.is_empty(),
                "replica certificate pins missing"
            );
            for pin in &peer.certificate_pins {
                ensure!(
                    pins.insert(parse_certificate_pin(pin)?),
                    "certificate cannot identify multiple replicas"
                );
            }
        }
        ensure!(
            ids.contains(&self.node_id),
            "local replica is absent from configured voters"
        );
        Ok(())
    }
}

fn absolute(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "configuration paths must be absolute");
    Ok(())
}
pub(crate) fn valid_transit_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        })
}
pub(crate) fn origin(value: &str) -> Result<url::Url> {
    let url = url::Url::parse(value)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "endpoint must be an HTTPS origin without credentials, path, query, or fragment"
    );
    Ok(url)
}
pub(crate) fn credential_path(value: &str) -> Result<()> {
    ensure!(
        Path::new(value).is_absolute(),
        "credential file path must be absolute"
    );
    Ok(())
}
pub(crate) fn file_secret(path: &str) -> Result<Zeroizing<String>> {
    kasumi_transport::credentials::token(&kasumi_transport::credentials::FileCredentialSource::new(
        path,
    )?)
}
pub(crate) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    ensure!(
        file.metadata()?.len() <= limit as u64,
        "configuration/certificate file exceeds byte limit"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "configuration/certificate file exceeds byte limit"
    );
    Ok(bytes)
}
pub(crate) fn read_private_file(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    kasumi_store::private_files::read(path, limit)
        .with_context(|| format!("opening private key {}", path.display()))
}

pub fn parse_certificate_pin(value: &str) -> Result<CertificatePin> {
    ensure!(
        value.len() == 64,
        "certificate pin must be a 64-digit SHA-256 hex digest"
    );
    let mut bytes = [0; 32];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte: u8| {
            (byte as char)
                .to_digit(16)
                .map(|digit| digit as u8)
                .context("invalid certificate pin hex")
        };
        bytes[i] = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(bytes)
}

#[async_trait::async_trait]
impl tls::TlsHandshakeAudit for SecurityAudit {
    async fn record(&self, event: &tls::TlsHandshakeEvent) -> Result<()> {
        let success = matches!(event.outcome, tls::TlsHandshakeOutcome::Accepted);
        let entry = SecurityEvent {
            kind: if success {
                SecurityEventKind::TransportAuthenticated
            } else {
                SecurityEventKind::TransportDenied
            },
            principal: None,
            tenant: None,
            request_id: event.connection_id.clone(),
            outcome: if success {
                SecurityOutcome::Succeeded
            } else {
                SecurityOutcome::Denied
            },
        };
        let transport = TransportAuditMetadata {
            peer_address: event.peer_address,
            certificate_pin: event.certificate_pin.as_ref().map(format_certificate_pin),
            observed_at_ms: event.timestamp_ms,
        };
        self.record_transport(entry, Some(transport)).await
    }
}

#[async_trait::async_trait]
impl crate::auth::RequestAuditSink for SecurityAudit {
    async fn record(&self, event: crate::auth::RequestAuditEvent) -> kasumi_types::Result<()> {
        use crate::auth::RequestAuditKind as Kind;
        let success = matches!(event.kind, Kind::AuthenticationSucceeded);
        let kind = match event.kind {
            Kind::AuthenticationSucceeded => SecurityEventKind::AuthenticationSucceeded,
            Kind::AuthenticationDenied => SecurityEventKind::AuthenticationDenied,
            Kind::AccessDenied => SecurityEventKind::AccessDenied,
            Kind::TenantSealed => SecurityEventKind::TenantSealed,
        };
        let entry = SecurityEvent {
            kind,
            principal: event.principal,
            tenant: event.tenant,
            request_id: event.request_id,
            outcome: if success {
                SecurityOutcome::Succeeded
            } else {
                SecurityOutcome::Denied
            },
        };
        SecurityAudit::record(self, entry).await.map_err(|_| {
            kasumi_types::Error::new(
                kasumi_types::ErrorCode::AuditUnavailable,
                "durable service audit unavailable",
            )
        })
    }
}

fn format_certificate_pin(pin: &CertificatePin) -> String {
    pin.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct OpenedTenant {
    database: Arc<Database>,
    store: Arc<TenantStore>,
    bootstrap: Option<ReplicatedBootstrap>,
}
struct OpenedCustody {
    tenant: String,
    incarnation: String,
    source: kasumi_engine::InstalledRetirementSource,
    store: Arc<kasumi_store::CustodyStore>,
}
struct BoundListener {
    listener: TcpListener,
    tls: kasumi_transport::ReloadableServerConfig,
    router: axum::Router,
}

/// Retain every installed listener's nested inventory separately from its task.
/// Cooperative shutdown and abnormal listener exit both join connections and
/// Hyper stream tasks before releasing the runtime's physical ownership.
pub(crate) struct ServingTasks {
    pub(crate) listeners: JoinSet<Result<()>>,
    maintenance: JoinSet<Result<()>>,
    data_stop: watch::Sender<bool>,
    pub(crate) cluster_stop: watch::Sender<bool>,
    report: kasumi_types::drain::DrainReport,
    failed_tasks: BTreeMap<tokio::task::Id, usize>,
    listener_inventories: Vec<Arc<tls::ListenerInventory>>,
}

impl ServingTasks {
    pub(crate) fn new() -> Self {
        Self {
            listeners: JoinSet::new(),
            maintenance: JoinSet::new(),
            data_stop: watch::channel(false).0,
            cluster_stop: watch::channel(false).0,
            report: Default::default(),
            failed_tasks: BTreeMap::new(),
            listener_inventories: Vec::new(),
        }
    }

    pub(crate) fn spawn_listener(&mut self, listener: tls::ServingListener) {
        // Retain nested connection/HTTP2 inventories before dispatch. Aborting
        // or panicking this listener handle cannot drop those actual owners.
        self.listener_inventories.push(listener.inventory());
        self.listeners.spawn(listener);
    }

    /// Initialization can wait indefinitely for other voters. Keep observing
    /// its required listener while waiting, so a failed listener enters the
    /// same retained cleanup path as a failure after startup. Only pass work
    /// whose cancellation already leaves its owners in the runtime inventory.
    async fn wait_for_startup<T, S>(
        &mut self,
        operation: impl std::future::Future<Output = Result<T>>,
        shutdown: impl std::future::Future<Output = S>,
    ) -> Result<Option<T>> {
        tokio::select! {
            biased;
            _ = shutdown => Ok(None),
            result = self.listeners.join_next(), if !self.listeners.is_empty() => {
                match result {
                    Some(Ok(Err(error))) => Err(error),
                    Some(Err(error)) => Err(error.into()),
                    _ => Err(anyhow::anyhow!("required listener stopped during startup")),
                }
            },
            result = operation => result.map(Some),
        }
    }

    pub(crate) async fn shutdown(&mut self) -> kasumi_types::drain::DrainResult {
        self.data_stop.send_replace(true);
        self.cluster_stop.send_replace(true);
        // Reconciliation may be rebuilding an admitted tenant and own Raft or
        // storage workers. Signal its loop and join the current operation before
        // taking the final generation inventory; cancellation could detach work.
        for (component, tasks) in [
            ("serving maintenance", &mut self.maintenance),
            ("serving listener", &mut self.listeners),
        ] {
            while let Some(result) = tasks.join_next_with_id().await {
                let failed = match result {
                    Ok((_, Ok(()))) => None,
                    Ok((id, Err(error))) => Some((id, error)),
                    Err(error) => Some((error.id(), error.into())),
                };
                if let Some((id, error)) = failed {
                    // Each installed task contributes at most one slot. Keep
                    // the actual outcome before awaiting another task, so a
                    // cancelled drain cannot forget a completed failure.
                    let next = self.failed_tasks.len();
                    let slot = *self.failed_tasks.entry(id).or_insert(next);
                    self.report.record(component, slot, error);
                }
            }
        }
        for inventory in &self.listener_inventories {
            if let Err(failure) = inventory.drain().await {
                self.report.merge(&failure);
            }
        }
        self.report.complete()
    }
}

// Tasks precede the runtime: its exclusive installation lock outlives every
// listener and maintenance owner even if the composite is unexpectedly dropped.
struct NodeServing {
    tasks: ServingTasks,
    report: kasumi_types::drain::DrainReport,
    runtime: NodeRuntime,
}
impl crate::serving_owner::Owner for NodeServing {
    fn run<'a>(
        &'a mut self,
        shutdown: &'a mut crate::serving_owner::Shutdown,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.runtime.serve_owned(&mut self.tasks, shutdown))
    }
    fn close(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kasumi_types::drain::DrainResult> + Send + '_>,
    > {
        Box::pin(async move {
            self.runtime
                .telemetry
                .set_lifecycle(crate::observability::Lifecycle::Draining);
            for lease in &self.runtime.serving_leases {
                lease.close();
            }
            #[cfg(test)]
            crate::startup_preparation::failure_checkpoint(self.runtime.config.database_id).await;
            let mut retained = None;
            crate::runtime_drain::observe(
                &mut self.report,
                &mut retained,
                self.tasks.shutdown().await,
            );
            // The runtime owns the physical databases. Listener tasks must
            // actually drain before those databases may release their files.
            if retained.is_none() {
                crate::runtime_drain::observe(
                    &mut self.report,
                    &mut retained,
                    self.runtime.shutdown().await,
                );
            }
            self.report.outcome(retained)
        })
    }
}

#[cfg(test)]
#[path = "serving_task_drain_tests.rs"]
mod serving_task_drain_tests;

pub struct NodeRuntime {
    serving_registration: Option<crate::serving_owner::Registration>,
    startup_drain: kasumi_types::drain::DrainReport,
    telemetry: Arc<crate::observability::Telemetry>,
    config: RuntimeConfig,
    signer_verifier: Option<Arc<crate::signer_runtime::InstalledSignerVerifier>>,
    authority_trusts: BTreeMap<String, kasumi_serving::AuthorityTrust>,
    serving_leases: Vec<Arc<crate::serving_runtime::RuntimeLease>>,
    registry: DatabaseRegistry,
    tenants: Vec<OpenedTenant>,
    custody_sources: Vec<OpenedCustody>,
    unavailable_sources: BTreeMap<String, String>,
    control: OpenedTenant,
    audit: Arc<SecurityAudit>,
    data_listeners: Vec<BoundListener>,
    cluster_listener: Option<BoundListener>,
    cluster: Option<Arc<ClusterNetwork>>,
    local_certificate_pin: CertificatePin,
    closed: bool,
    stopping_audit_started: bool,
    stopping_audit_observed: bool,
    administration: Option<Arc<crate::administration::Administration>>,
    target_recovery: Option<Arc<crate::target_runtime::TargetRecoveryRuntime>>,
    shutdown_runtime: tokio::runtime::Handle,
    tls_reload: Option<crate::tls_reload::RuntimeTlsReload>,
    // Scope-owned cached stores observed during startup, including custody probes.
    startup_stores: Vec<Arc<TenantStore>>,
    owned_nodes: Vec<Arc<NodeStore>>,
    #[cfg(test)]
    audit_release_gate: Arc<tokio::sync::Mutex<Option<crate::rpc::AuditReleaseGate>>>,
    // The installation lock outlives every retained resource-bearing field.
    _standalone_owner: Option<Arc<crate::standalone::InstalledStandaloneOwner>>,
}

impl NodeRuntime {
    pub fn tls_reload_handle(&self) -> Result<crate::tls_reload::RuntimeTlsReload> {
        self.tls_reload
            .clone()
            .context("listener TLS reload is not initialized")
    }

    pub async fn open(config: RuntimeConfig) -> Result<Self> {
        Self::open_using(config, file_secret).await
    }

    async fn open_using(
        config: RuntimeConfig,
        credential: impl Fn(&str) -> Result<Zeroizing<String>> + Send + Sync + 'static,
    ) -> Result<Self> {
        config.validate()?;
        let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
        Self::open_using_storage(config, credential, storage).await
    }

    pub(crate) async fn open_using_storage(
        config: RuntimeConfig,
        credential: impl Fn(&str) -> Result<Zeroizing<String>> + Send + Sync + 'static,
        storage: crate::runtime_memory::RuntimeStorage,
    ) -> Result<Self> {
        storage.require_policy(&config.admission)?;
        crate::startup_owner::open(
            crate::startup_owner::Kind::Data,
            Self::open_owned(config, Arc::new(credential), storage),
        )
        .await
    }

    /// Join cancelled/incomplete opens after stopping new startup admission.
    /// Runtimes already handed to their callers retain their ordinary ownership.
    pub async fn drain_startups() -> Result<()> {
        crate::startup_owner::drain(crate::startup_owner::Kind::Data).await
    }

    async fn open_owned(
        config: RuntimeConfig,
        credential: crate::serving_runtime::CredentialSource,
        storage: crate::runtime_memory::RuntimeStorage,
    ) -> Result<Self> {
        let mut pending = crate::startup_resources::Resources::default();
        let mut retained_runtime: Option<Self> = None;
        let outcome = crate::startup_preparation::capture("data runtime", async {
        config.validate()?;
        let admission = storage.facade(&config.admission)?;
        pending.owned_admissions.push(admission.clone());
        let persistent_disk = crate::persistent_disk::open(&config.persistent_disk, &storage)?;
        pending.standalone_owner = crate::standalone::claim(&config, &persistent_disk)?;
        let scratch_disk = storage.open_scratch(&config.scratch_disk)?;
        let signer_verifier = if let Some(verifier) = &config.signer_verifier {
            let mut domains = BTreeMap::new();
            for authority in config.serving_authorities.values() {
                for partition in authority.manifest.partitions.keys() {
                    let domain = authority.manifest.signing_domain(*partition)?;
                    domains.insert(domain.digest()?, domain);
                }
            }
            Some(
                verifier
                    .open(domains, credential.clone(), persistent_disk.clone(), scratch_disk.clone(), admission.clone())
                    .await?,
            )
        } else {
            None
        };
        if let Some(verifier) = &signer_verifier { pending.verifiers.push(verifier.clone()); }
        let authority_trusts = config
            .serving_authorities
            .iter()
            .map(|(alias, configured)| {
                Ok((
                    alias.clone(),
                    signer_verifier
                        .as_ref()
                        .context("local signer verifier absent")?
                        .trust(configured.manifest.clone())?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let lifecycle_signer = config
            .control
            .lifecycle
            .as_ref()
            .map(|settings| settings.signer())
            .transpose()?;
        let auth = Authenticator::new(config.auth.clone())?;
        let registry = DatabaseRegistry::default();
        registry.set_approved_nodes(
            config
                .replication
                .as_ref()
                .map(|r| r.peers.iter().map(|p| p.node_id).collect())
                .unwrap_or_else(|| BTreeSet::from([1])),
        )?;
        let destinations = config
            .backup_destinations
            .iter()
            .map(|(name, destination)| Ok((name.clone(), destination.open(persistent_disk.clone())?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        // Validate all TLS/credential material and bind all sockets before a
        // durable bootstrap can be created. No listener serves until `serve`.
        let mcp_identity = config.mcp.tls.load()?;
        let local_certificate_pin = mcp_identity.certificate_pin();
        let mcp_tls = kasumi_transport::ReloadableServerConfig::new(
            kasumi_transport::server_config(&mcp_identity, ClientAuthentication::OAuth)?,
        );
        let native_tls = kasumi_transport::ReloadableServerConfig::new(config.native.load()?);
        let admin_tls = kasumi_transport::ReloadableServerConfig::new(config.admin.load()?);
        let control_provider = config.control.keys.provider(credential.clone())?;
        let control_custody_provider = config.control.custody_keys.provider(credential.clone())?;
        let security_provider = config.security_audit.keys.provider(credential.clone())?;
        let mcp_socket = TcpListener::bind(config.mcp.listen).await?;
        let native_socket = TcpListener::bind(config.native.listen).await?;
        let admin_socket = TcpListener::bind(config.admin.listen).await?;
        let (cluster, cluster_listener) = if let Some(replication) = &config.replication {
            let identity = replication.listener.tls.load()?;
            let ca = read_bounded(&replication.listener.client_ca, MAX_PEM_BYTES)?;
            let peers = replication
                .peers
                .iter()
                .map(|peer| {
                    Ok(PeerConfig {
                        node_id: peer.node_id,
                        endpoint: peer.endpoint.clone(),
                        certificate_pins: peer
                            .certificate_pins
                            .iter()
                            .map(|pin| parse_certificate_pin(pin))
                            .collect::<Result<_>>()?,
                    })
                })
                .collect::<Result<_>>()?;
            let network = ClusterNetwork::new(
                replication.node_id,
                &identity,
                &ca,
                peers,
                PeerLimits::default(),
            )?;
            let listener = BoundListener {
                listener: TcpListener::bind(replication.listener.listen).await?,
                tls: network.server_tls().into(),
                router: network.router(),
            };
            (Some(network), Some(listener))
        } else {
            (None, None)
        };
        let node = NodeStore::open_existing(
            &config.database_path,
            config.database_id,
            persistent_disk.clone(),
            scratch_disk.clone(),
        )?;
        pending.owned_nodes.push(node.clone());
        let security_store = TenantStore::open_existing(
            node.clone(),
            SECURITY_TENANT.into(),
            security_provider,
            kasumi_store::StorageAccess::security_audit(),
        )
        .await?;
        pending.stores.push(security_store.clone());
        #[cfg(test)]
        crate::startup_preparation::checkpoint(config.database_id, "data-security");
        if config.mode == DeploymentMode::Standalone
            && let Err(error) = crate::local_recovery::require_runtime_ready(&security_store)
        {
            return Err(error);
        }
        if crate::node_enrollment::required(&config) {
            crate::node_enrollment::require_complete(
                &security_store,
                config.database_id,
                crate::node_enrollment::Kind::Data,
            )?;
        }
        let enrollment_required = crate::node_enrollment::required(&config);
        let selected_tenants = config.tenants.iter().map(|tenant| {
            let installed = if enrollment_required {
                crate::node_enrollment::tenant_record(&security_store, &tenant.tenant)?.is_some_and(|record| record.stage == crate::node_enrollment::Stage::Prepared)
            } else {
                TenantStorageSet::catalogs_installed(&node, &tenant.tenant)?
            };
            Ok(installed.then_some(tenant))
        }).collect::<Result<Vec<_>>>()?.into_iter().flatten().collect::<Vec<_>>();
        config.validate_selected_key_domains(&selected_tenants)?;
        let audit = config
            .security_audit
            .open(security_store, admission.clone())?;
        pending.audits.push(audit.clone());
        auth.install_audit(audit.clone())?;
        if let crate::auth::AuthKeySource::Local { signer_file } = &config.auth.source {
            auth.install_local_credentials(crate::local_auth::LocalCredentials::open(
                audit.store().clone(),
                signer_file.clone(),
                config.auth.issuer.clone(),
                config.auth.audience.clone(),
            )?)?;
        }
        if let Some(cluster) = &cluster {
            cluster.install_audit(audit.clone())?;
        }
        let control = async {
            let control_stores = TenantStorageSet::open_existing(
                node.clone(),
                CONTROL_TENANT.into(),
                control_provider.clone(),
                control_custody_provider.clone(),
                kasumi_store::StorageAccess::node_control(),
            )
            .await?;
            pending.stores.push(control_stores.application().clone());
            pending.stores.push(control_stores.custody().store().clone());
            let expected_fingerprint = if config.mode == DeploymentMode::Replicated {
                let enrolled = crate::node_enrollment::tenant_record(audit.store(), CONTROL_TENANT)?
                    .context("Control enrollment receipt is missing")?;
                Some(enrolled.bootstrap_sha256.context("Control enrollment fingerprint is missing")?)
            } else {
                None
            };
            Self::open_database(
                &config,
                control_stores,
                config.control.initial_policy.clone(),
                config.control.initial_limits.clone(),
                config.control.incarnation.as_deref(),
                expected_fingerprint.as_deref(),
                cluster.as_ref(),
                audit.clone(),
                &mut pending,
            )
            .await
        }
        .await;
        let control = match control {
            Ok(control) => control,
            Err(error) => return Err(error),
        };
        let serving_registration = crate::serving_owner::Registration::new(crate::serving_owner::Kind::Data, config.database_id, audit.admission())?;
        retained_runtime = Some(Self {
            serving_registration: Some(serving_registration),
            telemetry: crate::observability::Telemetry::new(),
            _standalone_owner: None,
            owned_nodes: pending.owned_nodes.clone(),
            startup_stores: pending.stores.iter().filter(|store| store.tenant() != SECURITY_TENANT).cloned().collect(),
            config: config.clone(),
            signer_verifier,
            authority_trusts,
            serving_leases: Vec::new(),
            registry: registry.clone(),
            tenants: Vec::new(),
            custody_sources: Vec::new(),
            unavailable_sources: BTreeMap::new(),
            control,
            audit,
            data_listeners: Vec::new(),
            cluster_listener,
            cluster,
            local_certificate_pin,
            closed: false,
            stopping_audit_started: false,
            stopping_audit_observed: false,
            startup_drain: Default::default(),
            #[cfg(test)]
            audit_release_gate: Arc::new(tokio::sync::Mutex::new(None)),
            administration: None,
            target_recovery: None,
            shutdown_runtime: tokio::runtime::Handle::current(),
            tls_reload: None,
        });
        let runtime = retained_runtime.as_mut().expect("runtime owner just retained");
        #[cfg(test)]
        crate::startup_preparation::checkpoint(config.database_id, "data-runtime");
        let result = async {
            let mut managed = vec![crate::administration::ManagedTenant {
                database: runtime.control.database.clone(),
                store: runtime.control.store.clone(),
                bootstrap: runtime.control.bootstrap.clone(),
                lease: None,
            }];
            for configured_tenant in &config.tenants {
                if !selected_tenants.iter().any(|tenant| tenant.tenant == configured_tenant.tenant) {
                    let state = runtime.control.database.engine().generation()?;
                    if let Some(document) = state.state.collections.get("topology").and_then(|collection| collection.documents.get("current")) {
                        let topology: kasumi_engine::control::ControlTopology = serde_json::from_value(document.body.clone())?;
                        ensure!(!topology.tenants.contains_key(&configured_tenant.tenant), "routed tenant has no completed local catalog or enrollment");
                    }
                    // Configuration may stage a tenant, but cannot make an
                    // absent installation eligible for provider or grant work.
                    continue;
                }
                if enrollment_required {
                    let enrolled = crate::node_enrollment::tenant_record(runtime.audit.store(), &configured_tenant.tenant)?.context("completed tenant enrollment disappeared during startup")?;
                    ensure!(enrolled.stage == crate::node_enrollment::Stage::Prepared, "completed tenant enrollment changed during startup");
                    ensure!(configured_tenant.incarnation.as_deref().map(uuid::Uuid::parse_str).transpose()? == Some(enrolled.incarnation), "configured enrolled tenant incarnation differs");
                }
                let active = if config.mode == DeploymentMode::Standalone {
                    crate::local_recovery::active_generation(&config, runtime.audit.store(), &configured_tenant.tenant)?
                } else { None };
                let mut tenant = configured_tenant.clone();
                let tenant_node = match &active {
                    Some(active) => {
                        tenant.incarnation = Some(active.incarnation.to_string());
                        NodeStore::open_existing(active.directory.join("node.kv"), active.database_id(&config, &tenant.tenant)?, persistent_disk.clone(), scratch_disk.clone())?
                    }
                    None => node.clone(),
                };
                if active.is_some() {
                    pending.owned_nodes.push(tenant_node.clone());
                    runtime.owned_nodes.push(tenant_node.clone());
                    #[cfg(test)]
                    crate::startup_preparation::checkpoint(config.database_id, "data-active-node");
                }
                let custody_provider = tenant.custody_keys.provider(credential.clone())?;
                if kasumi_store::CustodyStore::catalog_installed(&tenant_node, &tenant.tenant)? {
                    let custody_store = kasumi_store::CustodyStore::open(tenant_node.clone(), tenant.tenant.clone(), custody_provider.clone()).await?;
                    runtime.startup_stores.push(custody_store.store().clone());
                    if let Some(control) = kasumi_raft::ControlLog::installed(custody_store.clone())? {
                        let incarnation = control.group().strip_prefix(&format!("{}/", tenant.tenant)).context("installed source group differs")?.to_owned();
                        if let Some(expected) = &tenant.incarnation { ensure!(*expected == incarnation, "configured source incarnation differs"); }
                        let recovered = tokio::task::spawn_blocking(move || control.recover_retired()).await?;
                        if !matches!(recovered, Ok(false)) {
                            let source = if recovered.is_ok() {
                                match open_retired_source(&config, custody_store.clone(), runtime.cluster.as_ref(), runtime.audit.clone(), admission.clone()).await {
                                    Ok(custody) => kasumi_engine::InstalledRetirementSource::RetiredCustody(custody),
                                    Err(_) => kasumi_engine::InstalledRetirementSource::RecoveringControl { tenant: tenant.tenant.clone(), source_incarnation: incarnation.clone() },
                                }
                            } else { kasumi_engine::InstalledRetirementSource::RecoveringControl { tenant: tenant.tenant.clone(), source_incarnation: incarnation.clone() } };
                            runtime.custody_sources.push(OpenedCustody { tenant: tenant.tenant.clone(), incarnation, source: source.clone(), store: custody_store });
                            registry.install_retirement_source(source)?;
                            continue;
                        }
                    }
                }
                let incarnation = match &tenant.serving {
                    crate::serving_runtime::TenantServingConfig::Standalone { .. } => uuid::Uuid::parse_str(tenant.incarnation.as_deref().context("installed standalone incarnation is required")?)?,
                    crate::serving_runtime::TenantServingConfig::Independent { .. } => uuid::Uuid::parse_str(tenant.incarnation.as_deref().context("installed incarnation is required")?)?,
                    #[cfg(any(test, feature = "test-utils"))]
                    crate::serving_runtime::TenantServingConfig::LocalFixture => tenant.incarnation.as_deref().map(uuid::Uuid::parse_str).transpose()?.unwrap_or_else(uuid::Uuid::new_v4),
                };
                let access = crate::serving_runtime::acquire_tenant_access(&config, &runtime.authority_trusts, credential.clone(), &tenant.tenant, incarnation, kasumi_serving::LeasePurpose::Serving).await;
                let (storage_access, lease) = match access {
                    Ok(access) => access,
                    Err(_) => {
                        registry.install_retirement_source(kasumi_engine::InstalledRetirementSource::RecoveringControl { tenant: tenant.tenant.clone(), source_incarnation: incarnation.to_string() })?;
                        runtime.unavailable_sources.insert(tenant.tenant.clone(), incarnation.to_string());
                        continue;
                    }
                };
                if let Some(lease) = &lease {
                    // Retain even a partially opened tenant's worker until the
                    // runtime's error/shutdown path drains its actual owner.
                    runtime.serving_leases.push(lease.clone());
                }
                // The application provider is constructed only after the closed
                // control route is excluded and an issuer capability is live.
                let provider = tenant.keys.provider(credential.clone())?;
                let stores = TenantStorageSet::open_existing(tenant_node.clone(), tenant.tenant.clone(),
                    provider.clone(), custody_provider.clone(), storage_access).await?;
                runtime.startup_stores.push(stores.application().clone());
                runtime.startup_stores.push(stores.custody().store().clone());
                let expected_fingerprint = if crate::node_enrollment::required(&config) && active.is_none() {
                    let enrolled = crate::node_enrollment::tenant_record(runtime.audit.store(), &tenant.tenant)?.context("enrollment disappeared during startup")?;
                    if config.mode == DeploymentMode::Replicated {
                        Some(enrolled.bootstrap_sha256.context("enrollment fingerprint is missing")?)
                    } else {
                        ensure!(enrolled.bootstrap_sha256.as_ref() == Some(&persisted_bootstrap_fingerprint(stores.application())?),
                            "installed bootstrap differs from its enrollment receipt");
                        None
                    }
                } else {
                    None
                };
                let opened = Self::open_database(
                    &config,
                    stores,
                    tenant.initial_policy.clone(),
                    tenant.initial_limits.clone(),
                    tenant.incarnation.as_deref(),
                    expected_fingerprint.as_deref(),
                    runtime.cluster.as_ref(),
                    runtime.audit.clone(),
                    &mut pending,
                )
                .await?;
                if let Some(active) = active {
                    let generation = opened.database.engine().generation()?;
                    if generation.state.restored_from.as_ref() != Some(&active.checkpoint) || generation.state.pending_restore.is_some() {
                        anyhow::bail!("active standalone generation is incomplete or differs from its committed checkpoint");
                    }
                }
                managed.push(crate::administration::ManagedTenant {
                    database: opened.database.clone(),
                    store: opened.store.clone(),
                    bootstrap: opened.bootstrap.clone(),
                    lease,
                });
                runtime.tenants.push(opened);
            }
            if config.target_recovery.is_some() {
                runtime.target_recovery=Some(crate::target_runtime::TargetRecoveryRuntime::open(config.clone(),runtime.authority_trusts.clone(),credential.clone(),admission.clone(),runtime.audit.clone(),runtime.cluster.clone().context("target requires installed cluster")?,destinations.clone(),registry.clone()).await?);
            }
            let administration = crate::administration::Administration::new(
                config.clone(),
                runtime.authority_trusts.clone(),
                node.clone(),
                registry.clone(),
                runtime.control.database.clone(),
                runtime.audit.clone(),
                runtime.cluster.clone(),
                managed,
                destinations,
                admission.clone(),
                credential.clone(),
            )?;
            runtime.administration = Some(administration.clone());
            if let Some(network) = &runtime.cluster {
                let provider: Arc<dyn crate::cluster::EnrollmentReadinessProvider> =
                    administration.clone();
                network.install_enrollment_readiness(Arc::downgrade(&provider))?;
            }
            let mcp =
                crate::mcp::router(config.mcp.protocol.clone(), registry.clone(), auth.clone())?;
            let native = tonic::service::Routes::new(
                NativeData::new(registry.clone(), auth.clone()).service(),
            )
            .into_axum_router();
            let mut native_admin = NativeAdmin::new(registry.clone(), auth.clone()).with_management(administration.clone()).with_telemetry(runtime.telemetry.clone());
            if let Some(verifier) = &runtime.signer_verifier {
                native_admin = native_admin.with_control_signer(crate::control_signer_runtime::ControlSignerRuntime::new(
                    config.replication.as_ref().context("remote signer requires installed replication")?.node_id,
                    runtime.control.database.clone(), verifier.clone(), config.serving_authorities.clone(),
                    runtime.authority_trusts.clone(), config.admin.tls.clone(), credential.clone(),
                )?);
            }
            #[cfg(test)]
            { runtime.audit_release_gate = native_admin.audit_release_gate(); }
            let mut admin = tonic::service::Routes::new(native_admin.service());
            if let Some(signer) = lifecycle_signer {
                if config.control.lifecycle.as_ref().is_some_and(|lifecycle| lifecycle.recovery.is_some()) {
                    let coordinator = crate::recovery_runtime::ControlRecoveryCoordinator::new(&config, runtime.control.database.clone(), signer.clone(), runtime.authority_trusts.clone())?;
                    admin = admin.add_service(crate::rpc::NativeRecoveryControl::new(coordinator, auth.clone()).service());
                }
                admin = admin.add_service(crate::rpc::NativeLifecycleControl::new(runtime.control.database.clone(), signer, auth.clone())?.service());
            }
            if let Some(target)=&runtime.target_recovery {admin=admin.add_service(crate::rpc::NativeTargetRecovery::new(target.clone(),auth.clone()).service());}
            let admin = admin.into_axum_router().merge(crate::observability::router(auth.clone(), administration, runtime.telemetry.clone()));
            runtime.tls_reload = Some(crate::tls_reload::RuntimeTlsReload::new(
                vec![
                    (crate::tls_reload::ListenerSource::OAuth(config.mcp.tls.clone()), mcp_tls.clone()),
                    (crate::tls_reload::ListenerSource::Mutual(config.native.clone()), native_tls.clone()),
                    (crate::tls_reload::ListenerSource::Mutual(config.admin.clone()), admin_tls.clone()),
                ],
                if config.replication.is_none() { Some((runtime.control.database.clone(), configured_control_context(&config.control)?)) } else { None },
                runtime.audit.clone(),
            ));
            runtime.data_listeners = vec![
                BoundListener {
                    listener: mcp_socket,
                    tls: mcp_tls,
                    router: mcp,
                },
                BoundListener {
                    listener: native_socket,
                    tls: native_tls,
                    router: native,
                },
                BoundListener {
                    listener: admin_socket,
                    tls: admin_tls,
                    router: admin,
                },
            ];
            Ok::<_, anyhow::Error>(())
        }
        .await;
        result?;
        Ok(())
        }).await;
        match outcome {
            Ok(()) => {
                let mut runtime = retained_runtime
                    .take()
                    .expect("successful preparation retained its runtime");
                runtime._standalone_owner = pending.standalone_owner.take();
                Ok(runtime)
            }
            Err(mut error) => {
                #[cfg(test)]
                crate::startup_preparation::failure_checkpoint(config.database_id).await;
                if let Some(runtime) = retained_runtime.as_mut()
                    && let Err(cleanup) = crate::startup_owner::finish(runtime).await
                {
                    error = error.context(cleanup);
                }
                if let Err(cleanup) = crate::startup_owner::finish(&mut pending).await {
                    error = error.context(cleanup);
                }
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn enrollment_for_test(
        &self,
        tenant: &str,
    ) -> Result<Option<(Uuid, crate::node_enrollment::Stage)>> {
        Ok(
            crate::node_enrollment::tenant_record(self.audit.store(), tenant)?
                .map(|record| (record.incarnation, record.stage)),
        )
    }
    #[cfg(test)]
    pub(crate) fn administration_for_enrollment_test(
        &self,
    ) -> Arc<crate::administration::Administration> {
        self.administration
            .as_ref()
            .expect("installed test Administration")
            .clone()
    }
    #[allow(clippy::too_many_arguments)]
    async fn open_database(
        config: &RuntimeConfig,
        stores: Arc<TenantStorageSet>,
        policy: Policy,
        limits: Limits,
        installed_incarnation: Option<&str>,
        expected_replicated_fingerprint: Option<&str>,
        cluster: Option<&Arc<ClusterNetwork>>,
        audit: Arc<SecurityAudit>,
        pending: &mut crate::startup_resources::Resources,
    ) -> Result<OpenedTenant> {
        async {
            let store = stores.application().clone();
            config.install_tenant_audit_archive(&store, None)?;
            let mut bootstrap = None;
            let database = if config.mode == DeploymentMode::Replicated {
                let replication = config
                    .replication
                    .as_ref()
                    .context("replication configuration missing")?;
                let network = cluster.context("cluster transport missing")?;
                let opened = kasumi_engine::open_existing_replicated(
                    replication.node_id,
                    stores.clone(),
                    uuid::Uuid::parse_str(
                        installed_incarnation
                            .context("installed replicated incarnation is missing")?,
                    )?,
                    network.clone(),
                    kasumi_raft::server_config(),
                    audit,
                )
                .await?;
                pending.databases.push(opened.database.clone());
                let fingerprint = opened_replicated_bootstrap_fingerprint(store.tenant(), &opened)?;
                if let Some(expected) = expected_replicated_fingerprint {
                    ensure!(
                        fingerprint == expected,
                        "installed bootstrap differs from its enrollment receipt"
                    );
                }
                #[cfg(test)]
                crate::startup_preparation::checkpoint(config.database_id, "data-database");
                let group = format!("{}/{}", store.tenant(), opened.bootstrap.incarnation);
                let bootstrap_store = store.clone();
                network.register_group_with_bootstrap(
                    group,
                    opened.database.raft_group().raft().clone(),
                    replication.peers.iter().map(|peer| peer.node_id).collect(),
                    fingerprint,
                    Arc::new(move || bootstrap_store.check_access()),
                )?;
                bootstrap = Some(opened.bootstrap);
                opened.database
            } else if crate::standalone::requires_provisioned(config) {
                kasumi_engine::open_existing_local(
                    stores,
                    audit,
                    uuid::Uuid::parse_str(
                        installed_incarnation.context("installed local incarnation is missing")?,
                    )?,
                )
                .await?
            } else {
                match installed_incarnation {
                    Some(incarnation) => {
                        kasumi_engine::open_local_with_incarnation(
                            stores,
                            policy,
                            limits,
                            audit,
                            uuid::Uuid::parse_str(incarnation)?,
                        )
                        .await?
                    }
                    None => kasumi_engine::open_local(stores, policy, limits, audit).await?,
                }
            };
            if config.mode != DeploymentMode::Replicated {
                pending.databases.push(database.clone());
                #[cfg(test)]
                crate::startup_preparation::checkpoint(config.database_id, "data-database");
            }
            Ok(OpenedTenant {
                database,
                store,
                bootstrap,
            })
        }
        .await
    }

    pub fn registry(&self) -> &DatabaseRegistry {
        &self.registry
    }
    pub fn control_database(&self) -> &Arc<Database> {
        &self.control.database
    }
    pub fn security_audit(&self) -> &Arc<SecurityAudit> {
        &self.audit
    }

    async fn initialize_original(&self, tenant: &OpenedTenant) -> Result<()> {
        let Some(bootstrap) = &tenant.bootstrap else {
            return Ok(());
        };
        let network = self
            .cluster
            .as_ref()
            .context("cluster transport unavailable")?;
        let local = self
            .config
            .replication
            .as_ref()
            .context("replication missing")?
            .node_id;
        // Prospective learners must be explicitly caught up by an operator.
        if !bootstrap.voters.contains_key(&local) {
            return Ok(());
        }
        if tenant.database.raft_group().raft().is_initialized().await? {
            return Ok(());
        }
        let group = format!("{}/{}", tenant.store.tenant(), bootstrap.incarnation);
        let expected = network.bootstrap_fingerprint(local, &group).await?;
        loop {
            tenant.store.check_access()?;
            let mut ready = true;
            for voter in bootstrap.voters.keys() {
                match network.bootstrap_fingerprint(*voter, &group).await {
                    Ok(actual) => ensure!(
                        actual == expected,
                        "replicated bootstrap mismatch for {group} on voter {voter}"
                    ),
                    Err(_) => {
                        ready = false;
                        break;
                    }
                }
            }
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if Some(&local) == bootstrap.voters.keys().next() {
            kasumi_engine::initialize_replicated(&tenant.database, bootstrap).await?;
        }
        Ok(())
    }

    /// TLS listeners start together. Raft groups remain unavailable until their
    /// configured quorum is elected; initial membership never shrinks on failure.
    pub fn serve(
        mut self,
        shutdown: watch::Receiver<bool>,
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'static {
        let registration = self
            .serving_registration
            .take()
            .expect("opened runtime has one serving registration");
        crate::serving_owner::serve(
            crate::serving_owner::Kind::Data,
            registration,
            NodeServing {
                tasks: ServingTasks::new(),
                report: Default::default(),
                runtime: self,
            },
            shutdown,
        )
    }

    /// Stop opening new instances before joining all retained serving owners.
    pub async fn drain_serving() -> Result<()> {
        crate::serving_owner::drain(crate::serving_owner::Kind::Data).await
    }

    async fn serve_owned(
        &mut self,
        tasks: &mut ServingTasks,
        shutdown: &mut crate::serving_owner::Shutdown,
    ) -> Result<()> {
        #[cfg(test)]
        crate::startup_preparation::checkpoint(self.config.database_id, "data-serving");
        if shutdown.requested() {
            return Ok(());
        }
        if let Some(listener) = self.cluster_listener.take() {
            tasks.spawn_listener(tls::serve_tls(
                listener.listener,
                listener.tls,
                listener.router,
                ListenerLimits::default(),
                self.audit.clone(),
                tasks.cluster_stop.subscribe(),
            ));
        }
        let startup = async {
            if tasks
                .wait_for_startup(self.initialize_original(&self.control), shutdown.changed())
                .await?
                .is_none()
            {
                return Ok(false);
            }
            if !tasks
                .wait_for_startup(self.publish_control(), shutdown.changed())
                .await?
                .unwrap_or(false)
            {
                return Ok(false);
            }
            if let Some(manager) = &self.administration {
                let topology = manager.committed_topology()?;
                for tenant in &self.tenants {
                    // Configuration may contain staged tenants. Only a durable
                    // route authorizes starting its original group automatically.
                    if topology.tenants.contains_key(tenant.store.tenant())
                        && tasks
                            .wait_for_startup(self.initialize_original(tenant), shutdown.changed())
                            .await?
                            .is_none()
                    {
                        return Ok(false);
                    }
                }
                manager.reconcile().await?;
            }
            self.audit
                .record(lifecycle(SecurityEventKind::NodeStarted))
                .await?;
            Ok::<_, anyhow::Error>(true)
        }
        .await;
        if !startup? {
            return Ok(());
        }
        self.telemetry
            .set_lifecycle(crate::observability::Lifecycle::Serving);
        for listener in self.data_listeners.drain(..) {
            tasks.spawn_listener(tls::serve_tls(
                listener.listener,
                listener.tls,
                listener.router,
                ListenerLimits::default(),
                self.audit.clone(),
                tasks.data_stop.subscribe(),
            ));
        }
        if let Some(manager) = self.administration.clone() {
            tasks
                .maintenance
                .spawn(manager.clone().probe_readiness(tasks.data_stop.subscribe()));
            let mut stop = tasks.data_stop.subscribe();
            tasks.maintenance.spawn(async move { loop { tokio::select! { _=stop.changed()=>return Ok(()), _=tokio::time::sleep(Duration::from_millis(250))=>{ if manager.reconcile().await.is_err() { tracing::warn!("serving reconciliation unavailable; will retry"); } } } } });
        }
        if shutdown.requested() {
            Ok(())
        } else {
            tokio::select! {
                _=shutdown.changed()=>Ok(()),
                result=tasks.listeners.join_next()=> match result { Some(Ok(Err(error)))=>Err(error),Some(Err(error))=>Err(error.into()),_=>Err(anyhow::anyhow!("required listener stopped unexpectedly")) },
                result=tasks.maintenance.join_next(), if !tasks.maintenance.is_empty()=> match result { Some(Ok(Err(error)))=>Err(error),Some(Err(error))=>Err(error.into()),_=>Err(anyhow::anyhow!("required reconciliation stopped unexpectedly")) },
            }
        }
    }

    fn expected_topology(&self) -> Result<kasumi_engine::control::ControlTopology> {
        use kasumi_engine::control::{
            ControlNode, ControlTopology, DeploymentMode as Mode, TenantRoute,
        };
        let (nodes, voters, mode) = if let Some(replication) = &self.config.replication {
            (
                replication.control_nodes()?,
                replication.voters()?,
                Mode::Replicated,
            )
        } else {
            let url = url::Url::parse(&self.config.mcp.protocol.public_url)?;
            (
                BTreeMap::from([(
                    1,
                    ControlNode {
                        endpoint: url.origin().ascii_serialization(),
                        failure_domain: "local".into(),
                        certificate_pins: BTreeSet::from([format_certificate_pin(
                            &self.local_certificate_pin,
                        )]),
                    },
                )]),
                BTreeSet::from([1]),
                Mode::Local,
            )
        };
        let tenants = self
            .tenants
            .iter()
            .map(|tenant| {
                Ok((
                    tenant.store.tenant().into(),
                    TenantRoute {
                        incarnation: tenant
                            .database
                            .engine()
                            .generation()?
                            .state
                            .incarnation
                            .clone(),
                        mode: mode.clone(),
                        voters: voters.clone(),
                    },
                ))
            })
            .collect::<Result<_>>()?;
        let mut tenants: BTreeMap<String, TenantRoute> = tenants;
        for source in &self.custody_sources {
            tenants.insert(
                source.tenant.clone(),
                TenantRoute {
                    incarnation: source.incarnation.clone(),
                    mode: mode.clone(),
                    voters: voters.clone(),
                },
            );
        }
        for (tenant, incarnation) in &self.unavailable_sources {
            tenants.insert(
                tenant.clone(),
                TenantRoute {
                    incarnation: incarnation.clone(),
                    mode: mode.clone(),
                    voters: voters.clone(),
                },
            );
        }
        let topology = ControlTopology { nodes, tenants };
        topology.validate()?;
        Ok(topology)
    }

    async fn publish_control(&self) -> Result<bool> {
        use kasumi_engine::control::ControlPlane;
        let plane = ControlPlane::new(self.control.database.clone())?;
        let context = configured_control_context(&self.config.control)?;
        let expected = self.expected_topology()?;
        loop {
            self.control.store.check_access()?;
            self.control
                .database
                .engine()
                .authorize(&context, None, Action::Admin)?;
            let metrics = self
                .control
                .database
                .raft_group()
                .raft()
                .metrics()
                .borrow()
                .clone();
            if metrics.current_leader == Some(metrics.id) {
                let result = async {
                    plane.require_initialized(&context).await?;
                    let current = plane
                        .topology(&context)
                        .await?
                        .context("installed Control topology is missing")?;
                    validate_configured_topology(&current.topology, &expected)?;
                    crate::lifecycle_runtime::require_applied(
                        &self.control.database.engine().generation()?.state,
                        self.config.control.lifecycle.as_ref(),
                    )?;
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                match result {
                    Ok(()) => return Ok(true),
                    Err(error)
                        if error
                            .downcast_ref::<kasumi_types::Error>()
                            .is_some_and(|error| {
                                matches!(
                                    error.code,
                                    kasumi_types::ErrorCode::Unavailable
                                        | kasumi_types::ErrorCode::AuditUnavailable
                                        | kasumi_types::ErrorCode::UnknownOutcome
                                        | kasumi_types::ErrorCode::Conflict
                                )
                            }) => {}
                    Err(error) => return Err(error),
                }
            } else if metrics.current_leader.is_some() && metrics.last_applied.is_some() {
                // Genesis alone does not establish readiness. A follower must
                // observe an actual leader and applied Raft state, then validate
                // its own current Control state. This is not a quorum read.
                let generation = self.control.database.engine().generation()?;
                let current = ControlPlane::applied_topology(&generation.state)?;
                validate_configured_topology(&current.topology, &expected)?;
                crate::lifecycle_runtime::require_applied(
                    &generation.state,
                    self.config.control.lifecycle.as_ref(),
                )?;
                return Ok(true);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn shutdown(&mut self) -> kasumi_types::drain::DrainResult {
        use crate::runtime_drain::observe;
        if self.closed {
            return self.startup_drain.complete();
        }
        self.telemetry
            .set_lifecycle(crate::observability::Lifecycle::Draining);
        let mut retained = None;
        for lease in &self.serving_leases {
            lease.close();
        }
        observe(
            &mut self.startup_drain,
            &mut retained,
            crate::target_runtime::shutdown_target(&mut self.target_recovery).await,
        );
        if !self.stopping_audit_started {
            self.stopping_audit_started = true;
            let audit = self
                .audit
                .record(lifecycle(SecurityEventKind::NodeStopping))
                .await;
            self.stopping_audit_observed = true;
            if let Err(error) = audit {
                self.startup_drain.record("stopping audit", 0, error);
            }
        } else if !self.stopping_audit_observed {
            self.stopping_audit_observed = true;
            self.startup_drain.record(
                "stopping audit",
                0,
                anyhow::anyhow!(
                    "stopping audit outcome was not observed before shutdown cancellation"
                ),
            );
        }
        for lease in &self.serving_leases {
            observe(
                &mut self.startup_drain,
                &mut retained,
                lease.shutdown().await,
            );
        }
        if let Some(manager) = &self.administration {
            observe(
                &mut self.startup_drain,
                &mut retained,
                manager.shutdown().await,
            );
        }
        for (index, tenant) in std::iter::once(&self.control)
            .chain(self.tenants.iter())
            .enumerate()
        {
            if let Err(error) = self.registry.remove(tenant.store.tenant()) {
                retained = Some(kasumi_types::drain::DrainFailure::retained(
                    self.startup_drain
                        .record("serving route removal", index, error.into()),
                ));
            }
            if let (Some(cluster), Some(bootstrap)) = (&self.cluster, &tenant.bootstrap)
                && let Err(error) = cluster.unregister_group(&format!(
                    "{}/{}",
                    tenant.store.tenant(),
                    bootstrap.incarnation
                ))
            {
                retained = Some(kasumi_types::drain::DrainFailure::retained(
                    self.startup_drain
                        .record("serving group removal", index, error),
                ));
            }
            observe(
                &mut self.startup_drain,
                &mut retained,
                tenant.database.shutdown().await,
            );
        }
        for (index, source) in self.custody_sources.iter().enumerate() {
            if let Some(cluster) = &self.cluster
                && let Err(error) =
                    cluster.unregister_group(&format!("{}/{}", source.tenant, source.incarnation))
            {
                retained = Some(kasumi_types::drain::DrainFailure::retained(
                    self.startup_drain
                        .record("custody group removal", index, error),
                ));
            }
            if let kasumi_engine::InstalledRetirementSource::RetiredCustody(custody) =
                &source.source
            {
                observe(
                    &mut self.startup_drain,
                    &mut retained,
                    custody.shutdown().await,
                );
            } else {
                observe(
                    &mut self.startup_drain,
                    &mut retained,
                    source.store.store().shutdown().await,
                );
            }
        }
        observe(
            &mut self.startup_drain,
            &mut retained,
            self.audit.admission().drain_snapshot_startups().await,
        );
        // A readiness timeout/stop retains its actual SDK query independently
        // of the maintenance waiter. Only positively drained tenant/Control
        // cores may release a query or caught-panic reservation.
        if retained.is_none()
            && let Some(manager) = &self.administration
        {
            observe(
                &mut self.startup_drain,
                &mut retained,
                manager.readiness.probe.drain_after_group_shutdown().await,
            );
        }
        for store in &self.startup_stores {
            observe(
                &mut self.startup_drain,
                &mut retained,
                store.shutdown().await,
            );
        }
        observe(
            &mut self.startup_drain,
            &mut retained,
            self.audit.shutdown().await,
        );
        if let Some(verifier) = &self.signer_verifier {
            observe(
                &mut self.startup_drain,
                &mut retained,
                verifier.shutdown().await,
            );
        }
        if retained.is_none() {
            for node in &self.owned_nodes {
                observe(
                    &mut self.startup_drain,
                    &mut retained,
                    node.shutdown().await,
                );
            }
        }
        if retained.is_none() {
            self.closed = true;
            self.telemetry
                .set_lifecycle(crate::observability::Lifecycle::Closed);
        }
        self.startup_drain.outcome(retained)
    }
}
/// Read the exact durable manifest digest for enrollment and transport.
/// Startup may call this before engine open; transport registration waits for
/// open to verify the immutable chunks and paired deployment binding.
pub(crate) fn persisted_bootstrap_fingerprint(store: &TenantStore) -> Result<String> {
    let tenant = store.tenant();
    let binding = store
        .get("engine.deployment", b"mode")?
        .context("immutable deployment binding missing")?;
    let digest = kasumi_engine::persisted_bootstrap_digest(store)?;
    initial_bootstrap_fingerprint(tenant, &binding, &digest)
}

/// Replicated enrollment hashes the same admitted two-domain binding that the
/// engine opens. A one-sided or divergent installation cannot receive a
/// bootstrap fingerprint from a single application row.
pub(crate) fn persisted_replicated_bootstrap_fingerprint(
    stores: &TenantStorageSet,
) -> Result<String> {
    let view = stores.read_view()?;
    let binding = view
        .deployment_binding()?
        .context("immutable replicated deployment binding missing")?;
    let store = stores.application();
    let digest = kasumi_engine::persisted_bootstrap_digest_at(&view)?;
    initial_bootstrap_fingerprint(store.tenant(), binding.as_bytes(), &digest)
}

/// Hash only the identity that engine actually verified while its pinned view
/// was live; callers use this value for receipt comparison and registration.
pub(crate) fn opened_replicated_bootstrap_fingerprint(
    tenant: &str,
    opened: &kasumi_engine::OpenedReplica,
) -> Result<String> {
    initial_bootstrap_fingerprint(
        tenant,
        opened.verified_binding(),
        opened.verified_snapshot_sha256(),
    )
}

/// A retired source no longer has an application provider. The custody commit
/// retains the exact initial application digest beside the deployment binding.
fn decode_retired_custody_bootstrap_digest(bytes: &[u8]) -> Result<String> {
    let digest: String = serde_json::from_slice(bytes)?;
    ensure!(
        serde_json::to_vec(&digest)? == bytes,
        "noncanonical retired custody bootstrap digest"
    );
    Ok(digest)
}

fn retired_custody_bootstrap_fingerprint(
    custody: &kasumi_store::CustodyStore,
    binding: &[u8],
) -> Result<String> {
    let store = custody.store();
    store.check_access()?;
    let digest = decode_retired_custody_bootstrap_digest(
        &store
            .get_bounded("raft.meta", b"application_bootstrap_sha256", 256)?
            .context("retired custody bootstrap digest missing")?,
    )?;
    initial_bootstrap_fingerprint(custody.binding().tenant(), binding, &digest)
}

fn initial_bootstrap_fingerprint(tenant: &str, binding: &[u8], digest: &str) -> Result<String> {
    use sha2::{Digest, Sha256};
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid bootstrap digest"
    );
    let mut hash = Sha256::new();
    hash.update(b"kasumi-initial-bootstrap-v1\0");
    hash.update((tenant.len() as u64).to_be_bytes());
    hash.update(tenant.as_bytes());
    hash.update((binding.len() as u64).to_be_bytes());
    hash.update(binding);
    hash.update(digest.as_bytes());
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Approved durable nodes/routes must remain supported. Extra configuration is
/// only a staging pool; it never grants a route or rewrites existing placement.
fn validate_configured_topology(
    durable: &kasumi_engine::control::ControlTopology,
    configured: &kasumi_engine::control::ControlTopology,
) -> Result<()> {
    ensure!(
        durable
            .nodes
            .iter()
            .all(|(id, node)| configured.nodes.get(id) == Some(node)),
        "configured node identity differs from approved control metadata"
    );
    ensure!(
        durable
            .tenants
            .keys()
            .all(|name| configured.tenants.contains_key(name)),
        "durably routed tenant is missing from configuration"
    );
    Ok(())
}

impl Drop for NodeRuntime {
    fn drop(&mut self) {
        if !self.closed {
            // Application and audit admission close immediately. A retained
            // target may still have a Raft writer in its own generation store.
            for tenant in std::iter::once(&self.control).chain(self.tenants.iter()) {
                tenant.database.seal_admission();
                tenant.database.engine().seal();
                tenant.store.seal();
            }
            self.audit.seal();
            if let Some(target) = self.target_recovery.take() {
                target.seal_admission();
                self.shutdown_runtime.spawn(async move {
                    let mut reported_retention = false;
                    loop {
                        match target.shutdown().await {
                            Ok(()) => break,
                            Err(failure)
                                if failure.completion()
                                    == kasumi_types::drain::DrainCompletion::Retained =>
                            {
                                if !reported_retention {
                                    tracing::error!(%failure, "abandoned target runtime drain retained");
                                    reported_retention = true;
                                }
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                            Err(failure) => {
                                tracing::error!(%failure, "abandoned target runtime drain failed");
                                break;
                            }
                        }
                    }
                });
            }
        }
    }
}
fn lifecycle(kind: SecurityEventKind) -> SecurityEvent {
    SecurityEvent {
        kind,
        principal: None,
        tenant: None,
        request_id: uuid::Uuid::new_v4().to_string(),
        outcome: SecurityOutcome::Succeeded,
    }
}

pub(crate) fn configured_control_context(config: &ControlConfig) -> Result<RequestContext> {
    let mut context = control_context(&config.initial_policy)?;
    if let Some(principal) = &config.startup_principal {
        kasumi_types::validate_name(principal)?;
        context.principal = principal.clone();
    }
    Ok(context)
}

pub(crate) fn control_context(policy: &Policy) -> Result<RequestContext> {
    let grant=policy.grants.iter().find(|grant|grant.collection.is_none() && [Action::Admin,Action::Read,Action::Write].iter().all(|action|grant.actions.contains(action)))
        .context("control bootstrap needs one explicitly named operator with read/write/admin permissions")?;
    Ok(RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: grant.principal.clone(),
        tenant: CONTROL_TENANT.into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        request_id: uuid::Uuid::new_v4().to_string(),
    })
}

/// Credential-free operator example, also emitted by `kasumid example-config`.
pub fn example_config(directory_policy: kasumi_store::DirectoryPolicy) -> Result<RuntimeConfig> {
    directory_policy.validate()?;
    let tls = || TlsFiles {
        certificate: "/etc/kasumi/server.pem".into(),
        private_key: "/etc/kasumi/server-key.pem".into(),
    };
    let mutual = |port| MutualTlsEndpoint {
        listen: format!("127.0.0.1:{port}").parse().unwrap(),
        tls: tls(),
        client_ca: "/etc/kasumi/operator-ca.pem".into(),
    };
    let transit = |key: &str, variable: &str| {
        KeyProviderSettings::Transit(TransitSettings {
            endpoint: "https://openbao.example".into(),
            mount: "transit".into(),
            key_name: key.into(),
            token_file: format!("/etc/kasumi/credentials/{variable}"),
            namespace: None,
            ca_certificate: None,
            derived: false,
        })
    };
    let policy = |principal: &str| Policy {
        grants: vec![Grant {
            principal: principal.into(),
            collection: None,
            actions: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        }],
        strict_read_audit: false,
    };
    Ok(RuntimeConfig {
        persistent_disk: crate::persistent_disk::initial_config(
            BTreeMap::from([
                ("data".into(), "/var/lib/kasumi/data".into()),
                ("verifier".into(), "/var/lib/kasumi/verifier".into()),
                ("targets".into(), "/var/lib/kasumi/targets".into()),
                ("archives".into(), "/var/lib/kasumi/archives".into()),
                ("backups".into(), "/var/lib/kasumi/backups".into()),
            ]),
            directory_policy,
        )?,
        scratch_disk: kasumi_store::ScratchDiskConfig {
            directory: "/var/lib/kasumi/scratch".into(),
            max_bytes: 64 << 30,
            min_free_bytes: 256 << 20,
        },
        tenant_audit_archives: BTreeMap::new(),
        signer_verifier: Some(crate::signer_runtime::SignerVerifierConfig {
            max_background_workers: 64,
            identity: kasumi_serving::TrustVerifierIdentity {
                installation_id: uuid::Uuid::from_u128(7),
                node_id: 1,
            },
            database_path: PathBuf::from("/var/lib/kasumi/verifier/trust.kv"),
            keys: transit("signer-trust", "SIGNER_TRUST_TOKEN"),
        }),
        target_recovery: None,
        serving_authorities: BTreeMap::from([(
            "storage-fence".into(),
            crate::serving_runtime::ServingAuthorityConfig {
                manifest: kasumi_serving::AuthorityManifest {
                    lifecycle_controls: std::collections::BTreeMap::new(),
                    authority_id: uuid::Uuid::from_u128(1),
                    max_lease_ms: 10_000,
                    clock_rate_error_ppm: 1000,
                    partitions: BTreeMap::from([(
                        0,
                        kasumi_serving::AuthorityPartition {
                            group: "storage-authority-0".into(),
                            public_key: "01".repeat(32),
                        },
                    )]),
                },
                endpoints: BTreeMap::from([(
                    0,
                    BTreeMap::from([(
                        1,
                        crate::serving_runtime::AuthorityEndpoint {
                            endpoint: "https://authority.example:9544".into(),
                            certificate_pins: BTreeSet::from(["02".repeat(32)]),
                        },
                    )]),
                )]),
                tls: TlsFiles {
                    certificate: "/etc/kasumi/node-authority.pem".into(),
                    private_key: "/etc/kasumi/node-authority-key.pem".into(),
                },
                server_ca: "/etc/kasumi/authority-ca.pem".into(),
                bearer_files: BTreeMap::from([(
                    0,
                    "/etc/kasumi/credentials/authority-0-token".into(),
                )]),
                principal: "storage-node-1".into(),
            },
        )]),
        format: 1,
        admission: kasumi_engine::admission::AdmissionConfig {
            max_inflight_bytes: Some(2 << 30),
            ..Default::default()
        },
        backup_destinations: BTreeMap::new(),
        mode: DeploymentMode::Replicated,
        database_path: "/var/lib/kasumi/data/node.kv".into(),
        database_id: Uuid::new_v4(),
        auth: AuthConfig {
            issuer: "https://identity.example".into(),
            audience: "https://kasumi.example/mcp".into(),
            source: crate::auth::AuthKeySource::ExternalOAuth {
                jwks_uri: "https://identity.example/.well-known/jwks.json".into(),
                trusted_ca_pem: None,
            },
            algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
            access_token_types: BTreeSet::from(["at+jwt".into()]),
        },
        mcp: McpEndpoint {
            listen: "127.0.0.1:9443".parse().unwrap(),
            tls: tls(),
            protocol: McpConfig::new("https://kasumi.example/mcp".into()).unwrap(),
        },
        native: mutual(9444),
        admin: mutual(9445),
        control: ControlConfig {
            lifecycle: None,
            startup_principal: None,
            keys: transit("kasumi-control", "KASUMI_CONTROL_TRANSIT_TOKEN"),
            custody_keys: transit(
                "kasumi-control-custody",
                "KASUMI_CONTROL_CUSTODY_TRANSIT_TOKEN",
            ),
            initial_policy: policy("operator"),
            initial_limits: Limits::default(),
            incarnation: Some(uuid::Uuid::from_u128(2).to_string()),
        },
        security_audit: SecurityAuditConfig {
            keys: transit("kasumi-node-security", "KASUMI_SECURITY_TRANSIT_TOKEN"),
            retention: kasumi_types::AuditRetentionBudget::default(),
            archive: None,
        },
        tenants: vec![TenantConfig {
            tenant: "acme".into(),
            serving: crate::serving_runtime::TenantServingConfig::Independent {
                authority: "storage-fence".into(),
            },
            keys: transit("acme-wrapping-key", "KASUMI_ACME_TRANSIT_TOKEN"),
            custody_keys: transit("acme-custody-key", "KASUMI_ACME_CUSTODY_TRANSIT_TOKEN"),
            initial_policy: policy("acme-admin"),
            initial_limits: Limits::default(),
            incarnation: Some(uuid::Uuid::from_u128(3).to_string()),
        }],
        replication: Some(ReplicationConfig {
            initial_voters: BTreeSet::from([1, 2, 3]),
            node_id: 1,
            listener: mutual(9446),
            peers: (1..=3)
                .map(|id| ReplicaConfig {
                    node_id: id,
                    endpoint: format!("https://node-{id}.example:9446"),
                    certificate_pins: vec![format!("{id:064x}")],
                    failure_domain: format!("zone-{id}"),
                })
                .collect(),
        }),
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminClientConfig {
    pub endpoint: String,
    pub identity: TlsFiles,
    pub server_ca: PathBuf,
    pub server_certificate_pins: Vec<String>,
    pub token_file: String,
}
impl AdminClientConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let config: Self = serde_json::from_slice(&read_bounded(path.as_ref(), MAX_CONFIG_BYTES)?)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        origin(&self.endpoint)?;
        self.identity.validate()?;
        absolute(&self.server_ca)?;
        credential_path(&self.token_file)?;
        ensure!(
            !self.server_certificate_pins.is_empty(),
            "admin server certificate pins missing"
        );
        for pin in &self.server_certificate_pins {
            parse_certificate_pin(pin)?;
        }
        Ok(())
    }
    pub async fn connect(
        &self,
    ) -> Result<(
        crate::rpc::proto::kasumi_admin_client::KasumiAdminClient<tonic::transport::Channel>,
        tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
    )> {
        self.validate()?;
        let identity = self.identity.load()?;
        let ca = read_bounded(&self.server_ca, MAX_PEM_BYTES)?;
        let pins = self
            .server_certificate_pins
            .iter()
            .map(|pin| parse_certificate_pin(pin))
            .collect::<Result<_>>()?;
        let secret = file_secret(&self.token_file)?;
        ensure!(
            !secret.contains(char::is_whitespace),
            "admin token must not contain whitespace"
        );
        let authorization = Zeroizing::new(format!("Bearer {}", secret.as_str()));
        let mut authorization: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
            authorization.parse()?;
        authorization.set_sensitive(true);
        let channel = kasumi_transport::grpc_channel(&self.endpoint, &identity, &ca, pins).await?;
        Ok((
            crate::rpc::proto::kasumi_admin_client::KasumiAdminClient::new(channel),
            authorization,
        ))
    }
}

#[cfg(test)]
fn fixture_config() -> RuntimeConfig {
    let mut config = example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
    // Keep the original fixture policy; the new-install generator's explicit
    // 2 GiB total is not a test workload budget increase.
    config.admission = kasumi_engine::admission::AdmissionConfig::default();
    config.mode = DeploymentMode::Standalone;
    config.replication = None;
    config.control.incarnation = None;
    config.serving_authorities.clear();
    config.signer_verifier = None;
    for tenant in &mut config.tenants {
        tenant.serving = crate::serving_runtime::TenantServingConfig::LocalFixture;
        tenant.incarnation = None;
    }
    config
}

#[cfg(test)]
// A fixture must explicitly enroll its node file once. Runtime restarts only
// open the retained configured identity and never create missing files.
async fn create_fixture_node(
    config: &RuntimeConfig,
    storage: &crate::runtime_memory::RuntimeStorage,
) {
    let admission = storage.facade(&config.admission).unwrap();
    let node = NodeStore::create_new(
        &config.database_path,
        config.database_id,
        storage.open_persistent(&config.persistent_disk).unwrap(),
        storage.open_scratch(&config.scratch_disk).unwrap(),
    )
    .unwrap();
    let credential: crate::serving_runtime::CredentialSource =
        Arc::new(|_| Ok(Zeroizing::new("test-runtime-token".into())));
    let provider = config
        .security_audit
        .keys
        .provider(credential.clone())
        .unwrap();
    let store = TenantStore::initialize_catalog(
        node.clone(),
        SECURITY_TENANT.into(),
        provider,
        kasumi_store::StorageAccess::security_audit(),
    )
    .await
    .unwrap();
    let audit = config
        .security_audit
        .initialize(store.clone(), admission.clone())
        .unwrap();
    let provisioned = if config.mode == DeploymentMode::Replicated {
        crate::data_node_enrollment::provision(config, node.clone(), audit.clone(), credential)
            .await
    } else {
        provision_local_fixture_domains(config, node.clone(), audit.clone(), credential).await
    };
    admission.drain_snapshot_startups().await.unwrap();
    audit.shutdown().await.unwrap();
    store.shutdown().await.unwrap();
    drop(audit);
    drop(store);
    node.shutdown().await.unwrap();
    drop(node);
    provisioned.unwrap();
}

#[cfg(test)]
async fn provision_local_fixture_domains(
    config: &RuntimeConfig,
    node: Arc<NodeStore>,
    audit: Arc<SecurityAudit>,
    credential: crate::serving_runtime::CredentialSource,
) -> Result<()> {
    let mut pending = crate::startup_resources::Resources::default();
    pending.borrowed_nodes.push(node.clone());
    let mut control = None;
    let mut routes = BTreeMap::new();
    let outcome = crate::startup_preparation::capture("local fixture enrollment", async {
        let entries = std::iter::once((
            CONTROL_TENANT,
            &config.control.initial_policy,
            &config.control.initial_limits,
            &config.control.keys,
            &config.control.custody_keys,
            config.control.incarnation.as_deref(),
            kasumi_store::StorageAccess::node_control(),
        ))
        .chain(config.tenants.iter().map(|tenant| {
            (
                tenant.tenant.as_str(),
                &tenant.initial_policy,
                &tenant.initial_limits,
                &tenant.keys,
                &tenant.custody_keys,
                tenant.incarnation.as_deref(),
                kasumi_store::StorageAccess::fixture(),
            )
        }));
        for (tenant, policy, limits, application, custody, incarnation, access) in entries {
            let stores = TenantStorageSet::initialize_catalogs(
                node.clone(),
                tenant.into(),
                application.provider(credential.clone())?,
                custody.provider(credential.clone())?,
                access,
            )
            .await?;
            pending.stores.push(stores.application().clone());
            pending.stores.push(stores.custody().store().clone());
            let opened = match incarnation {
                Some(incarnation) => {
                    kasumi_engine::open_local_with_incarnation(
                        stores.clone(),
                        policy.clone(),
                        limits.clone(),
                        audit.clone(),
                        uuid::Uuid::parse_str(incarnation)?,
                    )
                    .await
                }
                None => {
                    kasumi_engine::open_local(
                        stores.clone(),
                        policy.clone(),
                        limits.clone(),
                        audit.clone(),
                    )
                    .await
                }
            };
            let database = opened?;
            pending.databases.push(database.clone());
            if tenant == CONTROL_TENANT {
                control = Some(database);
            } else {
                routes.insert(
                    tenant.to_owned(),
                    kasumi_engine::control::TenantRoute {
                        incarnation: database.engine().generation()?.state.incarnation.clone(),
                        mode: kasumi_engine::control::DeploymentMode::Local,
                        voters: BTreeSet::from([1]),
                    },
                );
            }
        }
        let plane =
            kasumi_engine::control::ControlPlane::new(control.context("fixture Control missing")?)?;
        let context = configured_control_context(&config.control)?;
        plane.initialize(context.clone()).await?;
        plane
            .replace_topology(
                context,
                kasumi_engine::control::ControlTopology {
                    nodes: BTreeMap::from([(
                        1,
                        kasumi_engine::control::ControlNode {
                            endpoint: url::Url::parse(&config.mcp.protocol.public_url)?
                                .origin()
                                .ascii_serialization(),
                            failure_domain: "local".into(),
                            certificate_pins: BTreeSet::from([format_certificate_pin(
                                &config.mcp.tls.load()?.certificate_pin(),
                            )]),
                        },
                    )]),
                    tenants: routes,
                },
                Precondition::Absent,
                "fixture-installation-topology".into(),
            )
            .await?;
        Ok::<_, anyhow::Error>(())
    })
    .await;
    let drained = crate::startup_owner::finish(&mut pending).await;
    match (outcome, drained) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(drain)) => Err(drain.into()),
        (Err(error), Err(drain)) => Err(error.context(drain)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_store::test_utils::{LocalKeyProvider, ManualClock};

    #[test]
    fn retired_custody_bootstrap_digest_requires_current_writer_bytes() -> Result<()> {
        let digest = "a".repeat(64);
        let canonical = serde_json::to_vec(&digest)?;
        assert_eq!(decode_retired_custody_bootstrap_digest(&canonical)?, digest);
        let mut alternate = vec![b' '];
        alternate.extend_from_slice(&canonical);
        assert_eq!(
            serde_json::from_slice::<String>(&alternate)?,
            serde_json::from_slice::<String>(&canonical)?
        );
        assert!(decode_retired_custody_bootstrap_digest(&alternate).is_err());
        assert_eq!(decode_retired_custody_bootstrap_digest(&canonical)?, digest);
        Ok(())
    }

    #[tokio::test]
    async fn paired_replicated_fingerprint_preserves_installed_custody_binding() -> Result<()> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let physical =
            crate::runtime_storage_fixtures::physical(directory.path(), Default::default())?;
        let node = physical.create_new(
            directory.path().join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )?;
        let stores = TenantStorageSet::initialize_catalogs_fixture(
            node.clone(),
            "acme".into(),
            Arc::new(LocalKeyProvider::new([34; 32])),
            Arc::new(LocalKeyProvider::new([35; 32])),
        )
        .await?;
        let config = example_config(kasumi_store::DirectoryPolicy::fixture())?;
        let tenant = &config.tenants[0];
        let bootstrap = config
            .bootstrap(
                &tenant.initial_policy,
                &tenant.initial_limits,
                tenant.incarnation.as_deref(),
            )?
            .context("replicated fixture bootstrap missing")?;
        let binding = serde_json::to_vec(&("replicated", &bootstrap))?;
        let digest = "a".repeat(64);
        let manifest =
            format!(r#"{{"format":2,"bytes":1,"chunks":1,"digest":"{digest}"}}"#).into_bytes();
        let [node_id, group] =
            kasumi_raft::initial_storage_identity(1, &format!("acme/{}", bootstrap.incarnation))?;
        stores.write_batch(
            &[
                kasumi_store::WriteOp::put("engine.deployment", b"mode", binding.as_slice()),
                kasumi_store::WriteOp::put("engine.bootstrap", b"manifest", manifest.as_slice()),
            ],
            &[
                kasumi_store::WriteOp::put("engine.deployment", b"mode", binding.as_slice()),
                kasumi_store::WriteOp::put(
                    "raft.meta",
                    b"application_bootstrap_sha256",
                    serde_json::to_vec(&digest)?,
                ),
                node_id,
                group,
            ],
        )?;
        let expected = initial_bootstrap_fingerprint("acme", &binding, &digest)?;
        assert_eq!(
            persisted_replicated_bootstrap_fingerprint(&stores)?,
            expected
        );

        assert!(
            stores
                .custody()
                .store()
                .write_batch(&[kasumi_store::WriteOp::delete("engine.deployment", b"mode")])
                .is_err()
        );

        let mut substituted = bootstrap;
        substituted.incarnation = Uuid::new_v4().to_string();
        let different_binding = serde_json::to_vec(&("replicated", &substituted))?;
        assert!(
            stores
                .custody()
                .store()
                .write_batch(&[kasumi_store::WriteOp::put(
                    "engine.deployment",
                    b"mode",
                    different_binding,
                )])
                .is_err()
        );
        assert_eq!(
            persisted_replicated_bootstrap_fingerprint(&stores)?,
            expected
        );
        assert_eq!(
            persisted_bootstrap_fingerprint(stores.application())?,
            expected
        );
        assert_eq!(
            stores.application().get("engine.deployment", b"mode")?,
            Some(binding)
        );
        assert_eq!(
            stores.application().get("engine.bootstrap", b"manifest")?,
            Some(manifest)
        );
        stores.shutdown().await?;
        node.drain_initializers().await?;
        node.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn persisted_bootstrap_fingerprint_requires_current_bounded_manifest() -> Result<()> {
        let digest = "a".repeat(64);
        let canonical =
            format!(r#"{{"format":2,"bytes":1,"chunks":1,"digest":"{digest}"}}"#).into_bytes();
        let expected = initial_bootstrap_fingerprint("acme", b"local-v1", &digest)?;
        let mut alternate = vec![b' '];
        alternate.extend_from_slice(&canonical);
        assert!(serde_json::from_slice::<serde_json::Value>(&alternate).is_ok());
        let oversized = vec![b' '; 257];
        for (manifest, valid) in [(canonical, true), (alternate, false), (oversized, false)] {
            // Each case is an initial publication. A malformed authenticated
            // first manifest tests the reader without replacing a bound row.
            let directory = kasumi_store::test_utils::private_tempdir()?;
            let physical =
                crate::runtime_storage_fixtures::physical(directory.path(), Default::default())?;
            let node = physical.create_new(
                directory.path().join("persistent/node.kv"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )?;
            let stores = TenantStorageSet::initialize_catalogs_fixture(
                node.clone(),
                "acme".into(),
                Arc::new(LocalKeyProvider::new([34; 32])),
                Arc::new(LocalKeyProvider::new([35; 32])),
            )
            .await?;
            let [node_id, group] =
                kasumi_raft::initial_storage_identity(1, "acme/fingerprint-fixture")?;
            stores.write_batch(
                &[
                    kasumi_store::WriteOp::put("engine.deployment", b"mode", b"local-v1"),
                    kasumi_store::WriteOp::put(
                        "engine.bootstrap",
                        b"manifest",
                        manifest.as_slice(),
                    ),
                ],
                &[
                    kasumi_store::WriteOp::put("engine.deployment", b"mode", b"local-v1"),
                    kasumi_store::WriteOp::put(
                        "raft.meta",
                        b"application_bootstrap_sha256",
                        serde_json::to_vec(&digest)?,
                    ),
                    node_id,
                    group,
                ],
            )?;
            let fingerprint = persisted_bootstrap_fingerprint(stores.application());
            if valid {
                assert_eq!(fingerprint?, expected);
            } else if manifest.len() > 256 {
                let failure = fingerprint
                    .unwrap_err()
                    .downcast::<kasumi_store::TenantPointReadFailure>()?;
                assert_eq!(failure.stage(), "record bytes");
                let reader = failure.into_reader();
                assert_eq!(reader.phase(), kasumi_store::NodeReadPhase::Failed);
                assert_eq!(reader.finish(), kasumi_store::NodeReadPhase::Finished);
                assert_eq!(
                    reader.retire(),
                    kasumi_store::StorageCensusDisposition::Retired
                );
            } else {
                assert!(fingerprint.is_err());
            }
            assert_eq!(
                stores.application().get("engine.bootstrap", b"manifest")?,
                Some(manifest)
            );
            stores.shutdown().await?;
            node.shutdown().await?;
        }
        Ok(())
    }

    #[test]
    fn runtime_config_requires_explicit_admission() {
        let mut encoded =
            serde_json::to_value(example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap())
                .unwrap();
        let decoded: RuntimeConfig = serde_json::from_value(encoded.clone()).unwrap();
        decoded.validate().unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
        encoded.as_object_mut().unwrap().remove("admission");
        let error = serde_json::from_value::<RuntimeConfig>(encoded)
            .err()
            .unwrap();
        assert!(error.to_string().contains("missing field `admission`"));
    }

    #[test]
    fn operator_example_is_valid_secret_free_and_rejects_inline_credentials() {
        let config = example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
        config.validate().unwrap();
        let mut value = serde_json::to_value(&config).unwrap();
        assert!(value["tenants"][0]["keys"].get("token").is_none());
        value["tenants"][0]["keys"]["token"] = serde_json::json!("must-not-be-accepted");
        assert!(serde_json::from_value::<RuntimeConfig>(value).is_err());
    }

    #[test]
    fn rejects_shared_wrapping_keys_reserved_tenants_and_ambiguous_listeners() {
        let mut config = fixture_config();
        config.control.keys = config.tenants[0].keys.clone();
        assert!(config.validate().is_err());
        let mut config = fixture_config();
        config.tenants[0].custody_keys = config.tenants[0].keys.clone();
        assert!(config.validate().is_err());
        let mut config = fixture_config();
        config.control.custody_keys = config.tenants[0].custody_keys.clone();
        assert!(config.validate().is_err());
        let mut config = fixture_config();
        config.security_audit.keys = config.tenants[0].keys.clone();
        assert!(config.validate().is_err());
        let mut config = fixture_config();
        config.tenants[0].tenant = CONTROL_TENANT.into();
        assert!(config.validate().is_err());
        let mut config = fixture_config();
        config.tenants[0].tenant = "kasumi.custody/other".into();
        assert!(config.validate().is_err());
        let mut config = fixture_config();
        config.tenants.push(config.tenants[0].clone());
        assert!(config.validate().is_err());
        let mut config = fixture_config();
        config.admin.listen = config.mcp.listen;
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_cleartext_credential_urls_ambient_variable_names_and_missing_administrators() {
        let mut config = fixture_config();
        config.tenants[0].keys.transit_mut().unwrap().endpoint = "http://localhost:8200".into();
        assert!(config.validate().is_err());
        let mut config = fixture_config();
        config.tenants[0].keys.transit_mut().unwrap().endpoint =
            "https://user:password@localhost".into();
        assert!(config.validate().is_err());
        let mut config = fixture_config();
        config.tenants[0].keys.transit_mut().unwrap().token_file = "HOME".into();
        assert!(config.validate().is_err());
        let mut config = fixture_config();
        config.tenants[0].keys.transit_mut().unwrap().key_name = "../different-key".into();
        assert!(config.validate().is_err());
        let mut config = fixture_config();
        config.tenants[0].initial_policy = Policy::default();
        assert!(config.validate().is_err());
        let mut config = fixture_config();
        config.control.initial_policy.grants[0].actions = BTreeSet::from([Action::Admin]);
        assert!(config.validate().is_err());
        let mut config = fixture_config();
        config.admin.tls.private_key = "relative-key.pem".into();
        assert!(config.validate().is_err());
    }

    fn replicated() -> RuntimeConfig {
        let mut config = fixture_config();
        config.mode = DeploymentMode::Replicated;
        config.control.incarnation = Some(uuid::Uuid::new_v4().to_string());
        config.tenants[0].incarnation = Some(uuid::Uuid::new_v4().to_string());
        let mut listener = config.admin.clone();
        listener.listen = "127.0.0.1:9446".parse().unwrap();
        config.replication = Some(ReplicationConfig {
            initial_voters: BTreeSet::from([1, 2, 3]),
            node_id: 1,
            listener,
            peers: (1..=3)
                .map(|id| ReplicaConfig {
                    node_id: id,
                    endpoint: format!("https://node-{id}.example:9446"),
                    certificate_pins: vec![format!("{id:064x}")],
                    failure_domain: format!("zone-{id}"),
                })
                .collect(),
        });
        config
    }

    #[test]
    fn replication_requires_explicit_original_voters_when_decoding_and_validating() {
        let original = replicated().replication.unwrap();
        let mut encoded = serde_json::to_value(&original).unwrap();
        encoded.as_object_mut().unwrap().remove("initial_voters");
        assert!(serde_json::from_value::<ReplicationConfig>(encoded.clone()).is_err());
        encoded["initial_voters"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<ReplicationConfig>(encoded.clone()).is_err());
        encoded["initial_voters"] = serde_json::json!([]);
        let empty: ReplicationConfig = serde_json::from_value(encoded).unwrap();
        assert!(empty.voters().is_err());
        assert!(empty.validate().is_err());
        let mut expanded = original;
        expanded.peers.push(ReplicaConfig {
            node_id: 4,
            endpoint: "https://node-4.example:9446".into(),
            certificate_pins: vec![format!("{:064x}", 4)],
            failure_domain: "zone-4".into(),
        });
        expanded.node_id = 4;
        expanded.validate().unwrap();
        assert_eq!(expanded.voters().unwrap(), BTreeSet::from([1, 2, 3]));
        for invalid in [
            BTreeSet::new(),
            BTreeSet::from([1, 2]),
            BTreeSet::from([1, 2, 5]),
            BTreeSet::from([1, 2, 3, 4]),
        ] {
            expanded.initial_voters = invalid;
            assert!(expanded.validate().is_err());
        }
    }

    #[test]
    fn replication_is_explicit_three_voters_with_unique_pins_and_domains() {
        replicated().validate().unwrap();
        let mut config = fixture_config();
        config.mode = DeploymentMode::Replicated;
        assert!(config.validate().is_err());
        let mut config = replicated();
        config.mode = DeploymentMode::Standalone;
        assert!(config.validate().is_err());
        let mut config = replicated();
        config.replication.as_mut().unwrap().peers.pop();
        assert!(config.validate().is_err());
        let mut config = replicated();
        config.replication.as_mut().unwrap().peers[1].failure_domain = "zone-1".into();
        assert!(config.validate().is_err());
        let mut config = replicated();
        config.replication.as_mut().unwrap().peers[1].certificate_pins =
            vec![format!("{:064x}", 1)];
        assert!(config.validate().is_err());
        let mut config = replicated();
        config.tenants[0].incarnation = None;
        assert!(config.validate().is_err());
        let mut config = replicated();
        config.replication.as_mut().unwrap().node_id = 4;
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn service_audit_survives_reopen_and_tenant_sealing_and_fails_closed_at_quota() {
        let dir = kasumi_store::test_utils::private_tempdir().unwrap();
        let physical =
            crate::runtime_storage_fixtures::physical(dir.path(), Default::default()).unwrap();
        let path = dir.path().join("persistent/node.kv");
        let node = physical
            .create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        let keys = Arc::new(LocalKeyProvider::new([33; 32]));
        let clock = Arc::new(ManualClock::new());
        let service = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            SECURITY_TENANT.into(),
            keys.clone(),
            clock.clone(),
        )
        .await
        .unwrap();
        let tenant = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            "acme".into(),
            Arc::new(LocalKeyProvider::new([34; 32])),
            clock.clone(),
        )
        .await
        .unwrap();
        let audit = SecurityAudit::initialize(
            service.clone(),
            kasumi_types::AuditRetentionBudget::default(),
            physical.admission.clone(),
        )
        .unwrap();
        audit
            .record(lifecycle(SecurityEventKind::NodeStarted))
            .await
            .unwrap();
        tenant.seal();
        audit
            .record(SecurityEvent {
                kind: SecurityEventKind::TenantSealed,
                principal: Some("principal".into()),
                tenant: Some("acme".into()),
                request_id: uuid::Uuid::new_v4().to_string(),
                outcome: SecurityOutcome::Denied,
            })
            .await
            .unwrap();
        assert_eq!(service.scan("security.audit").unwrap().len(), 2);
        assert!(
            audit
                .record(lifecycle(SecurityEventKind::NodeStopping))
                .await
                .is_ok()
        );
        audit.shutdown().await.unwrap();
        drop(audit);
        drop(service);
        drop(tenant);
        node.shutdown().await.unwrap();
        let node = physical
            .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        let service = TenantStore::open_existing_fixture_with_clock(
            node.clone(),
            SECURITY_TENANT.into(),
            keys,
            clock,
        )
        .await
        .unwrap();
        let audit = SecurityAudit::open(
            service.clone(),
            kasumi_types::AuditRetentionBudget::default(),
            physical.admission.clone(),
        )
        .unwrap();
        assert!(
            audit
                .record(lifecycle(SecurityEventKind::NodeStarted))
                .await
                .is_ok()
        );
        assert_eq!(service.scan("security.audit").unwrap().len(), 4);
        audit.shutdown().await.unwrap();
        node.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_key_file_permissions_are_checked_on_opened_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = kasumi_store::test_utils::private_tempdir().unwrap();
        let path = dir.path().join("key.pem");
        std::fs::write(&path, b"test private material").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_file(&path, 1024).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            &*read_private_file(&path, 1024).unwrap(),
            b"test private material"
        );
        assert!(read_private_file(&path, 4).is_err());
        let link = dir.path().join("linked-key.pem");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_private_file(&link, 1024).is_err());
        let directory = dir.path().join("directory-key.pem");
        kasumi_store::private_files::create_directory(&directory).unwrap();
        assert!(read_private_file(&directory, 1024).is_err());
    }

    #[test]
    fn staged_topology_permits_supersets_but_rejects_changed_pins_and_removed_routes() {
        use kasumi_engine::control::{
            ControlNode, ControlTopology, DeploymentMode as Mode, TenantRoute,
        };
        let node = ControlNode {
            endpoint: "https://node-1.example".into(),
            failure_domain: "zone-1".into(),
            certificate_pins: BTreeSet::from(["ab".repeat(32)]),
        };
        let durable = ControlTopology {
            nodes: BTreeMap::from([(1, node.clone())]),
            tenants: BTreeMap::from([(
                "acme".into(),
                TenantRoute {
                    incarnation: uuid::Uuid::new_v4().to_string(),
                    mode: Mode::Local,
                    voters: BTreeSet::from([1]),
                },
            )]),
        };
        let mut configured = durable.clone();
        configured.nodes.insert(
            2,
            ControlNode {
                endpoint: "https://node-2.example".into(),
                failure_domain: "zone-2".into(),
                certificate_pins: BTreeSet::from(["cd".repeat(32)]),
            },
        );
        configured
            .tenants
            .insert("beta".into(), durable.tenants["acme"].clone());
        validate_configured_topology(&durable, &configured).unwrap();
        let mut changed = configured.clone();
        changed.nodes.get_mut(&1).unwrap().certificate_pins = BTreeSet::from(["ef".repeat(32)]);
        assert!(validate_configured_topology(&durable, &changed).is_err());
        let mut changed = configured.clone();
        changed.nodes.get_mut(&1).unwrap().failure_domain = "different-zone".into();
        assert!(validate_configured_topology(&durable, &changed).is_err());
        configured.tenants.remove("acme");
        assert!(validate_configured_topology(&durable, &configured).is_err());
        assert!(serde_json::from_value::<crate::administration::ManagementCommand>(serde_json::json!({"operation":"prepare_tenant","tenant":"beta","key_name":"caller-key"})).is_err());
    }

    #[test]
    fn replicated_control_origin_identity_matches_genesis_for_root_url_forms() {
        for trailing_slash in [false, true] {
            let mut config = example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
            if trailing_slash {
                for peer in &mut config.replication.as_mut().unwrap().peers {
                    peer.endpoint.push('/');
                }
            }
            let bootstrap = crate::control_genesis::bootstrap(&config).unwrap();
            let kasumi_engine::ReplicatedGenesis::Control(genesis) = bootstrap.genesis else {
                panic!("replicated Control enrollment lost its genesis");
            };
            for (id, node) in &genesis.topology.nodes {
                assert_eq!(node.endpoint, format!("https://node-{id}.example:9446"));
            }
            let configured = kasumi_engine::control::ControlTopology {
                nodes: config
                    .replication
                    .as_ref()
                    .unwrap()
                    .control_nodes()
                    .unwrap(),
                tenants: genesis.topology.tenants.clone(),
            };
            validate_configured_topology(&genesis.topology, &configured).unwrap();
            let mut substituted = configured;
            substituted.nodes.get_mut(&2).unwrap().endpoint =
                "https://different-node.example:9446".into();
            assert!(validate_configured_topology(&genesis.topology, &substituted).is_err());
        }
    }

    #[test]
    fn admin_client_requires_https_server_pin_and_runtime_token_reference() {
        let config = AdminClientConfig {
            endpoint: "https://localhost:9445".into(),
            identity: TlsFiles {
                certificate: "/cert.pem".into(),
                private_key: "/key.pem".into(),
            },
            server_ca: "/ca.pem".into(),
            server_certificate_pins: vec!["ab".repeat(32)],
            token_file: "/etc/kasumi/credentials/admin-token".into(),
        };
        config.validate().unwrap();
        let mut bad = config.clone();
        bad.endpoint = "http://localhost:9445".into();
        assert!(bad.validate().is_err());
        let mut bad = config.clone();
        bad.server_certificate_pins.clear();
        assert!(bad.validate().is_err());
        let mut bad = config;
        bad.token_file = "inline-token-value".into();
        assert!(bad.validate().is_err());
    }
}

#[cfg(test)]
mod lifecycle_tests {
    // Each fixture runs real replicas concurrently. Serialize separate fixtures
    // so unrelated storage/TLS bootstrap storms do not consume their test deadlines.
    static LIFECYCLE_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    use super::*;
    use axum::{
        Json, Router,
        extract::{Path as AxumPath, State},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
    };
    use base64::{Engine, engine::general_purpose::STANDARD};
    use kasumi_store::{KeyProvider, WrappedKey, test_utils::LocalKeyProvider};
    use kasumi_types::{CollectionDefinition, Mutation, MutationBatch, Operation};
    use sha2::{Digest, Sha256};

    #[derive(Default)]
    struct TransitFixture {
        keys: Mutex<BTreeMap<String, Arc<LocalKeyProvider>>>,
    }
    async fn transit(
        State(fixture): State<Arc<TransitFixture>>,
        AxumPath(operation): AxumPath<String>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Response {
        if headers
            .get("x-vault-token")
            .is_none_or(|value| value != "test-runtime-token")
        {
            return StatusCode::FORBIDDEN.into_response();
        }
        let (operation, key_name) = operation.rsplit_once('/').unwrap();
        let key = fixture
            .keys
            .lock()
            .unwrap()
            .entry(key_name.into())
            .or_insert_with(|| Arc::new(LocalKeyProvider::new(Sha256::digest(key_name).into())))
            .clone();
        match operation {
            "datakey/plaintext" => {
                let generated = key.generate_key(key_name).await.unwrap();
                Json(serde_json::json!({"data":{"plaintext":STANDARD.encode(generated.plaintext.as_bytes()),"ciphertext":format!("vault:v{}:{}",generated.wrapped.version,generated.wrapped.ciphertext)}})).into_response()
            }
            "rewrap" => {
                Json(serde_json::json!({"data":{"ciphertext":body["ciphertext"]}})).into_response()
            }
            "decrypt" => {
                let ciphertext = body["ciphertext"].as_str().unwrap();
                let rest = ciphertext.strip_prefix("vault:v").unwrap();
                let (version, ciphertext) = rest.split_once(':').unwrap();
                let wrapped = WrappedKey {
                    provider: "test-only".into(),
                    key_ref: key.key_ref().into(),
                    ciphertext: ciphertext.into(),
                    version: version.parse().unwrap(),
                    context: Some(key_name.into()),
                };
                match key.unwrap_key(key_name,&wrapped).await {
                    Ok(plaintext)=>Json(serde_json::json!({"data":{"plaintext":STANDARD.encode(plaintext.as_bytes())}})).into_response(),
                    Err(_)=>StatusCode::FORBIDDEN.into_response(),
                }
            }
            _ => StatusCode::NOT_FOUND.into_response(),
        }
    }
    struct FixtureAudit;
    #[async_trait::async_trait]
    impl tls::TlsHandshakeAudit for FixtureAudit {
        async fn record(&self, _: &tls::TlsHandshakeEvent) -> Result<()> {
            Ok(())
        }
    }

    fn certificate_files(dir: &Path) -> (TlsFiles, Vec<u8>) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let files = TlsFiles {
            certificate: dir.join("server.pem"),
            private_key: dir.join("server-key.pem"),
        };
        let pem = cert.pem().into_bytes();
        std::fs::write(&files.certificate, &pem).unwrap();
        std::fs::write(&files.private_key, signing_key.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&files.private_key, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        (files, pem)
    }
    fn listening_addresses() -> [SocketAddr; 3] {
        let listeners = (0..3)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect::<Vec<_>>();
        std::array::from_fn(|index| listeners[index].local_addr().unwrap())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn startup_and_serving_drains_finish_live_tls_requests_before_reopening_node() {
        use std::{
            future::{Future, poll_fn},
            task::Poll,
        };

        struct PausedRequest {
            node: Arc<NodeStore>,
            entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
            release: Arc<tokio::sync::Notify>,
        }
        async fn paused(State(state): State<Arc<PausedRequest>>) -> &'static str {
            state
                .entered
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            state.release.notified().await;
            // Keep the real node owner across the pending HTTP request.
            assert!(Arc::strong_count(&state.node) > 0);
            state.node.shutdown().await.unwrap();
            "finished"
        }

        // Startup failure/cancellation drain only the cluster listener; ordinary
        // serving shutdown also drains data listeners and joins reconciliation.
        for startup in [true, false] {
            let directory = kasumi_store::test_utils::private_tempdir().unwrap();
            let physical =
                crate::runtime_storage_fixtures::physical(directory.path(), Default::default())
                    .unwrap();
            let path = directory.path().join("persistent/listener.kv");
            let node = physical
                .create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)
                .unwrap();
            let weak = Arc::downgrade(&node);
            let (files, pem) = certificate_files(directory.path());
            let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!(
                "https://localhost:{}/pause",
                socket.local_addr().unwrap().port()
            );
            let (entered, ready) = tokio::sync::oneshot::channel();
            let release = Arc::new(tokio::sync::Notify::new());
            let state = Arc::new(PausedRequest {
                node: node.clone(),
                entered: Mutex::new(Some(entered)),
                release: release.clone(),
            });
            let router = Router::new()
                .route("/pause", post(paused))
                .with_state(state);
            let mut tasks = ServingTasks::new();
            if !startup {
                let owner = node.clone();
                let mut maintenance_stop = tasks.data_stop.subscribe();
                let (started, running) = tokio::sync::oneshot::channel();
                tasks.maintenance.spawn(async move {
                    let _owner = owner;
                    let _ = started.send(());
                    let _ = maintenance_stop.changed().await;
                    Ok(())
                });
                running.await.unwrap();
            }
            drop(node);
            let notices = if startup {
                tasks.cluster_stop.subscribe()
            } else {
                tasks.data_stop.subscribe()
            };
            tasks.spawn_listener(tls::serve_tls(
                socket,
                kasumi_transport::server_config(
                    &files.load().unwrap(),
                    ClientAuthentication::OAuth,
                )
                .unwrap(),
                router,
                ListenerLimits::default(),
                Arc::new(FixtureAudit),
                notices.clone(),
            ));
            let client = reqwest::Client::builder()
                .no_proxy()
                .http1_only()
                .add_root_certificate(reqwest::Certificate::from_pem(&pem).unwrap())
                .build()
                .unwrap();
            let response = tokio::spawn(async move {
                client
                    .post(endpoint)
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap()
            });
            tokio::time::timeout(Duration::from_secs(10), ready)
                .await
                .unwrap()
                .unwrap();
            let mut draining = Box::pin(tasks.shutdown());
            assert!(poll_fn(|cx| Poll::Ready(draining.as_mut().poll(cx).is_pending())).await);
            assert!(*notices.borrow());
            assert!(
                weak.upgrade().is_some(),
                "the live request must still own the node"
            );
            release.notify_one();
            tokio::time::timeout(Duration::from_secs(10), draining)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.await.unwrap(), "finished");
            drop(tasks);
            assert!(
                weak.upgrade().is_none(),
                "listener or request retained the node after drain"
            );
            // No delay or lock retry after the same drain used by every serve exit.
            physical
                .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
                .unwrap()
                .shutdown()
                .await
                .unwrap();
        }
    }

    fn replica_diagnostics(databases: &[Arc<kasumi_engine::Database>]) -> String {
        databases
            .iter()
            .map(|database| {
                format!(
                    "{:?}",
                    database.raft_group().raft().metrics().borrow().clone()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    async fn quorum_ready_leader(databases: &[Arc<kasumi_engine::Database>], stage: &str) -> usize {
        let mut last_barrier = "no leader observed".to_owned();
        let result=tokio::time::timeout(Duration::from_secs(20),async {
            loop {
                for (index,database) in databases.iter().enumerate() {
                    database.raft_group().check_access().expect("fixture replica must remain available");
                    let before=database.raft_group().raft().metrics().borrow().clone();
                    if before.current_leader!=Some(before.id) { continue; }
                    let result=tokio::time::timeout(Duration::from_secs(5),database.raft_group().raft().ensure_linearizable()).await;
                    match result {
                        Ok(Ok(read_log))=>{
                            database.raft_group().check_access().unwrap();
                            let after=database.raft_group().raft().metrics().borrow().clone();
                            if after.current_leader==Some(after.id) && after.current_term==before.current_term && after.last_applied>=read_log {
                                return index;
                            }
                            last_barrier=format!("node {} changed leadership or application after successful barrier: {before:?} -> {after:?}",index+1);
                        }
                        Ok(Err(error))=>{
                            assert!(error.api_error().is_some(),"fatal readiness failure at {stage}: {error:?}\n{}",replica_diagnostics(databases));
                            // The only nonfatal errors here are ForwardToLeader
                            // and QuorumNotEnough. Retain the actual Raft error,
                            // rather than the public API's redacted Unavailable.
                            last_barrier=format!("node {} barrier={error:?} before={before:?}",index+1);
                        }
                        Err(error)=>last_barrier=format!("node {} barrier deadline={error:?} before={before:?}",index+1),
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await;
        result.unwrap_or_else(|_| {
            panic!(
                "{stage}: no quorum-ready leader; last {last_barrier}\n{}",
                replica_diagnostics(databases)
            )
        })
    }
    /// Use only for idempotent restore stages and reads. A successful readiness
    /// check is not a leadership lease; the following operation may still lose
    /// quorum/leadership and must resolve against the current committed state.
    async fn on_quorum_leader<T, F, Fut>(
        databases: &[Arc<kasumi_engine::Database>],
        stage: &str,
        mut operation: F,
    ) -> (usize, T)
    where
        F: FnMut(usize) -> Fut,
        Fut: std::future::Future<Output = kasumi_types::Result<T>>,
    {
        let mut last_error = "operation not attempted".to_owned();
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let index = quorum_ready_leader(databases, stage).await;
                match operation(index).await {
                    Ok(value) => return (index, value),
                    Err(error)
                        if matches!(
                            error.code,
                            kasumi_types::ErrorCode::Unavailable
                                | kasumi_types::ErrorCode::UnknownOutcome
                        ) =>
                    {
                        last_error = format!("node {}: {error:?}", index + 1);
                    }
                    Err(error) => panic!(
                        "unexpected {stage} failure: {error:?}\n{}",
                        replica_diagnostics(databases)
                    ),
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        result.unwrap_or_else(|_| {
            panic!(
                "{stage} did not resolve after quorum/leadership changes; {last_error}\n{}",
                replica_diagnostics(databases)
            )
        })
    }

    fn staged_config(base: &TenantConfig, tenant: &str, incarnation: String) -> TenantConfig {
        let mut next = base.clone();
        next.tenant = tenant.into();
        next.incarnation = Some(incarnation);
        next.keys.transit_mut().unwrap().key_name = format!("{tenant}-wrapping-key");
        next.custody_keys.transit_mut().unwrap().key_name = format!("{tenant}-custody-key");
        next.initial_policy.grants = vec![Grant {
            principal: format!("{tenant}-admin"),
            collection: None,
            actions: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        }];
        next
    }

    async fn elect_control_member_for_local_preparation(
        controls: &[Arc<kasumi_engine::Database>],
        index: usize,
    ) {
        let control = &controls[index];
        let mut last = "election not attempted".to_owned();
        let elected = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                control.raft_group().check_access().unwrap();
                let before = control.raft_group().raft().metrics().borrow().clone();
                if before.current_leader == Some(before.id) {
                    match tokio::time::timeout(
                        Duration::from_secs(5),
                        control.raft_group().linearizable_barrier(),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            let after = control.raft_group().raft().metrics().borrow().clone();
                            if after.current_leader == Some(after.id)
                                && after.current_term == before.current_term
                            {
                                return;
                            }
                            last = format!(
                                "leadership changed after barrier: {before:?} -> {after:?}"
                            );
                        }
                        Ok(Err(error)) => last = format!("local barrier failed: {error:#}"),
                        Err(error) => last = format!("local barrier timed out: {error:?}"),
                    }
                } else {
                    control.raft_group().raft().trigger().elect().await.unwrap();
                    last = format!("requested election from {before:?}");
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        })
        .await;
        assert!(
            elected.is_ok(),
            "Control member {} could not establish its local preparation quorum: {last}; {}",
            index + 1,
            replica_diagnostics(controls)
        );
    }

    async fn exercise_provisioning(
        managers: &[Arc<crate::administration::Administration>],
        controls: &[Arc<kasumi_engine::Database>],
        registries: &[DatabaseRegistry],
        operator: RequestContext,
    ) {
        use crate::administration::ManagementCommand as M;
        let tenant = "beta";
        let beta = RequestContext {
            tenant: tenant.into(),
            principal: "beta-admin".into(),
            ..operator.clone()
        };
        for (manager, registry) in managers.iter().zip(registries) {
            assert!(registry.database(&beta).is_err());
            assert!(manager.prepare(beta.clone(), M::Status {}).is_err());
            assert!(
                manager
                    .execute_for_test(
                        beta.clone(),
                        M::ApproveTenant {
                            tenant: tenant.into()
                        }
                    )
                    .await
                    .is_err()
            );
            assert!(
                manager
                    .execute_for_test(
                        RequestContext {
                            principal: "not-an-operator".into(),
                            ..operator.clone()
                        },
                        M::PrepareTenant {
                            tenant: tenant.into()
                        }
                    )
                    .await
                    .is_err()
            );
            assert!(
                manager
                    .execute_for_test(
                        operator.clone(),
                        M::PrepareTenant {
                            tenant: tenant.into()
                        }
                    )
                    .await
                    .is_err()
            );
        }
        let mut approval_errors = vec!["not attempted".to_owned(); managers.len()];
        let approved = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                for (index, (manager, control)) in managers.iter().zip(controls).enumerate() {
                    let metrics = control.raft_group().raft().metrics().borrow().clone();
                    if metrics.current_leader == Some(metrics.id) {
                        approval_errors[index] = "leader approval attempt in flight".to_owned();
                        match crate::api::mutation_release(
                            manager
                                .execute_for_test(
                                    operator.clone(),
                                    M::ApproveTenant {
                                        tenant: tenant.into(),
                                    },
                                )
                                .await,
                        ) {
                            Ok(_) => return,
                            Err(error) => {
                                approval_errors[index] = format!("{error:#}");
                                if !matches!(
                                    error.code,
                                    kasumi_types::ErrorCode::Unavailable
                                        | kasumi_types::ErrorCode::UnknownOutcome
                                ) {
                                    panic!(
                                        "configured tenant approval failed: {error:#}; Control={}",
                                        replica_diagnostics(controls)
                                    );
                                }
                                let ready =
                                    quorum_ready_leader(controls, "resolve tenant approval").await;
                                match managers[ready].exact_enrollment_approved_for_test(tenant) {
                                    Ok(Some(true)) => return,
                                    Ok(Some(false)) => {
                                        panic!(
                                            "committed tenant approval differs from configuration"
                                        )
                                    }
                                    Ok(None) => {}
                                    Err(read_error) => {
                                        approval_errors[ready] =
                                            format!("approval resolution failed: {read_error:#}");
                                    }
                                }
                            }
                        }
                    } else {
                        approval_errors[index] = format!(
                            "not leader; leader={:?} state={:?}",
                            metrics.current_leader, metrics.state
                        );
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        approved.unwrap_or_else(|_| {
            let controls = controls
                .iter()
                .map(|control| {
                    let metrics = control.raft_group().raft().metrics().borrow().clone();
                    format!(
                        "node={} leader={:?} state={:?} term={} applied={:?}",
                        metrics.id,
                        metrics.current_leader,
                        metrics.state,
                        metrics.current_term,
                        metrics.last_applied
                    )
                })
                .collect::<Vec<_>>();
            panic!(
                "configured tenant approval timed out: last errors={approval_errors:?}; Control={controls:?}"
            )
        });
        // Neither control approval nor one prepared replica publishes data.
        assert!(
            managers[0]
                .execute_for_test(
                    operator.clone(),
                    M::InitializeTenant {
                        tenant: tenant.into()
                    }
                )
                .await
                .is_err()
        );
        for (index, manager) in managers.iter().enumerate() {
            // Preparation is local to each replica, while its administration
            // authorization requires a fresh quorum on that replica's Control
            // group. Elect each member before preparing its own tenant state.
            elect_control_member_for_local_preparation(controls, index).await;
            let mut last_error = "prepare not attempted".to_owned();
            let prepared = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    match manager
                        .execute_for_test(
                            operator.clone(),
                            M::PrepareTenant {
                                tenant: tenant.into(),
                            },
                        )
                        .await
                    {
                        Ok(_) => break,
                        Err(error) => last_error = format!("{error:#}"),
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await;
            prepared.unwrap_or_else(|_| {
                panic!(
                    "configured tenant preparation timed out on manager {}: {}; Control metrics={:?}",
                    index + 1,
                    last_error,
                    controls[index].raft_group().raft().metrics().borrow().clone()
                )
            });
            assert!(registries[index].database(&beta).is_err());
            if index == 0 && managers.len() > 1 {
                assert!(
                    manager
                        .execute_for_test(
                            operator.clone(),
                            M::InitializeTenant {
                                tenant: tenant.into()
                            }
                        )
                        .await
                        .is_err()
                );
            }
        }
        // Initialization is restricted to the lowest configured data voter.
        // It also needs that node's Control administration barrier.
        elect_control_member_for_local_preparation(controls, 0).await;
        managers[0]
            .execute_for_test(
                operator.clone(),
                M::InitializeTenant {
                    tenant: tenant.into(),
                },
            )
            .await
            .unwrap();
        for registry in registries {
            assert!(registry.database(&beta).is_err());
        }
        for manager in managers {
            assert!(
                manager
                    .execute_for_test(
                        operator.clone(),
                        M::ActivateTenant {
                            tenant: tenant.into(),
                            expected_topology_version: 0
                        }
                    )
                    .await
                    .is_err()
            );
        }
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                for (manager, control) in managers.iter().zip(controls) {
                    let metrics = control.raft_group().raft().metrics().borrow().clone();
                    if metrics.current_leader == Some(metrics.id) {
                        let topology = kasumi_engine::control::ControlPlane::new(control.clone())
                            .unwrap()
                            .topology(&operator)
                            .await;
                        if let Ok(Some(topology)) = topology
                            && manager
                                .execute_for_test(
                                    operator.clone(),
                                    M::ActivateTenant {
                                        tenant: tenant.into(),
                                        expected_topology_version: topology.version,
                                    },
                                )
                                .await
                                .is_ok()
                        {
                            return;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while registries
                .iter()
                .any(|registry| registry.database(&beta).is_err())
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        for registry in registries {
            let db = registry.database(&beta).unwrap();
            db.engine().authorize(&beta, None, Action::Admin).unwrap();
            // Routing approval does not copy the operator's control grant into a tenant.
            assert!(
                db.engine()
                    .authorize(
                        &RequestContext {
                            tenant: tenant.into(),
                            ..operator.clone()
                        },
                        None,
                        Action::Admin
                    )
                    .is_err()
            );
        }
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                for registry in registries {
                    let db = registry.database(&beta).unwrap();
                    if db
                        .administer(
                            beta.clone(),
                            Operation::CreateCollection(CollectionDefinition {
                                retention_class:
                                    kasumi_types::CollectionRetentionClass::Operational,
                                write_mode: kasumi_types::CollectionWriteMode::Mutable,
                                name: "onboarded".into(),
                                schema: serde_json::json!({"type":"object"}),
                                indexes: vec![],
                                strict_read_audit: false,
                            }),
                        )
                        .await
                        .is_ok()
                    {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }

    include!("runtime_custody_tests.rs");
    include!("runtime_serving_tests.rs");
    include!("runtime_startup_tests.rs");
    include!("runtime_mcp_tests.rs");

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn local_runtime_opens_real_transit_tls_publishes_control_serves_and_reopens_durable_state()
     {
        let dir = kasumi_store::test_utils::private_tempdir().unwrap();
        let (files, pem) = certificate_files(dir.path());
        let mock_socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let transit_endpoint = format!(
            "https://localhost:{}",
            mock_socket.local_addr().unwrap().port()
        );
        let router = Router::new()
            .route("/v1/transit/{*operation}", post(transit))
            .with_state(Arc::new(TransitFixture::default()));
        let (mock_stop, mock_shutdown) = watch::channel(false);
        let mock = tokio::spawn(tls::serve_tls(
            mock_socket,
            kasumi_transport::server_config(&files.load().unwrap(), ClientAuthentication::OAuth)
                .unwrap(),
            router,
            ListenerLimits::default(),
            Arc::new(FixtureAudit),
            mock_shutdown,
        ));
        let mut config = fixture_config();
        config.persistent_disk = crate::persistent_disk::fixture_config(&dir.path().join("data"));
        config.database_path = dir.path().join("data/node.kv");
        config.scratch_disk.directory = dir.path().join("scratch");
        config.mcp.tls = files.clone();
        config.native.tls = files.clone();
        config.admin.tls = files.clone();
        config.native.client_ca = files.certificate.clone();
        config.admin.client_ca = files.certificate.clone();
        let [mcp, native, admin] = listening_addresses();
        config.mcp.listen = mcp;
        config.native.listen = native;
        config.admin.listen = admin;
        config.mcp.protocol =
            McpConfig::new(format!("https://localhost:{}/mcp", mcp.port())).unwrap();
        for transit in [
            &mut config.control.keys,
            &mut config.control.custody_keys,
            &mut config.security_audit.keys,
        ]
        .into_iter()
        .chain(
            config
                .tenants
                .iter_mut()
                .flat_map(|tenant| [&mut tenant.keys, &mut tenant.custody_keys]),
        ) {
            let transit = transit.transit_mut().unwrap();
            transit.endpoint = transit_endpoint.clone();
            transit.ca_certificate = Some(files.certificate.clone());
        }
        let context = RequestContext {
            authorization: kasumi_types::RequestAuthorization::service_identity(),
            principal: "acme-admin".into(),
            tenant: "acme".into(),
            scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
            request_id: uuid::Uuid::new_v4().to_string(),
        };
        let client = reqwest::Client::builder()
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .add_root_certificate(reqwest::Certificate::from_pem(&pem).unwrap())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        config.backup_destinations.insert(
            "primary".into(),
            crate::administration::DestinationConfig::Filesystem {
                directory: dir.path().join("data/backups"),
                max_bytes: 32 << 20,
            },
        );
        // Preserve this fixture's former backup work budget alongside the
        // charged audit KV escrow and its equal protected maintenance lane.
        let former_total = config.admission.resolved_fixture_total_bytes().unwrap();
        config.admission.max_inflight_bytes = Some(
            former_total
                .checked_add(4 * kasumi_types::AuditRetentionBudget::MAINTENANCE_BYTES)
                .unwrap(),
        );
        let storage = crate::runtime_storage_fixtures::configure(&mut config).unwrap();
        create_fixture_node(&config, &storage).await;
        let mut incarnation = None;
        for round in 0..3 {
            let runtime = NodeRuntime::open_using_storage(
                config.clone(),
                |_| Ok(Zeroizing::new("test-runtime-token".into())),
                storage.clone(),
            )
            .await
            .unwrap();
            let registry = runtime.registry().clone();
            let manager = runtime.administration.clone().unwrap();
            let audit = runtime.security_audit().clone();
            let (stop, shutdown) = watch::channel(false);
            let serving = tokio::spawn(runtime.serve(shutdown));
            let database = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let Ok(database) = registry.database(&context)
                        && !database.engine().generation().unwrap().state.retired
                    {
                        break database;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            let operator = configured_control_context(&config.control).unwrap();
            let control = manager.authorized_database(&operator).await.unwrap();
            if round > 0 {
                // This low-level LocalFixture has no production enrollment
                // ledger. A configured template stays staged across restarts;
                // production standalone onboarding has its own installed test.
                let beta = RequestContext {
                    tenant: "beta".into(),
                    principal: "beta-admin".into(),
                    ..operator.clone()
                };
                assert!(registry.database(&beta).is_err());
                assert!(
                    !manager
                        .committed_topology()
                        .unwrap()
                        .tenants
                        .contains_key("beta")
                );
            }
            let control_limits = control.engine().generation().unwrap().state.limits.clone();
            control
                .administer(operator.clone(), Operation::SetLimits(control_limits))
                .await
                .unwrap();
            assert!(registry.database(&operator).is_err());
            assert!(
                manager
                    .authorized_database(&RequestContext {
                        principal: "denied-operator".into(),
                        ..operator.clone()
                    })
                    .await
                    .is_err()
            );
            assert!(
                manager
                    .authorized_database(&RequestContext {
                        tenant: SECURITY_TENANT.into(),
                        ..operator
                    })
                    .await
                    .is_err()
            );
            let current = database
                .engine()
                .generation()
                .unwrap()
                .state
                .incarnation
                .clone();
            if round == 0 {
                incarnation = Some(current);
                database
                    .administer(
                        context.clone(),
                        Operation::CreateCollection(CollectionDefinition {
                            retention_class: kasumi_types::CollectionRetentionClass::Operational,
                            write_mode: kasumi_types::CollectionWriteMode::Mutable,
                            name: "docs".into(),
                            schema: serde_json::json!({"type":"object"}),
                            indexes: Vec::new(),
                            strict_read_audit: false,
                        }),
                    )
                    .await
                    .unwrap();
                database
                    .mutate(
                        context.clone(),
                        MutationBatch {
                            read_set: Vec::new(),
                            idempotency_key: "runtime-persistence".into(),
                            operations: vec![Mutation::Put {
                                collection: "docs".into(),
                                id: "first".into(),
                                body: serde_json::json!({"exact":9007199254740993u64}),
                                expected: Precondition::Absent,
                            }],
                        },
                    )
                    .await
                    .unwrap();
            } else {
                assert_eq!(incarnation, Some(current));
            }
            assert_eq!(
                database.get(&context, "docs", "first").await.unwrap().body["exact"],
                serde_json::json!(9007199254740993u64)
            );
            let attacker = RequestContext {
                principal: "config-change-must-not-grant".into(),
                ..context.clone()
            };
            assert!(database.get(&attacker, "docs", "first").await.is_err());
            let metadata = client
                .get(format!(
                    "https://localhost:{}/.well-known/oauth-protected-resource/mcp",
                    mcp.port()
                ))
                .send()
                .await
                .unwrap();
            assert_eq!(metadata.status(), StatusCode::OK);
            let denied = client
                .post(format!("https://localhost:{}/mcp", mcp.port()))
                .json(&serde_json::json!({"jsonrpc":"2.0","method":"initialize","id":1}))
                .send()
                .await
                .unwrap();
            assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
            let records = audit.store().scan("security.audit").unwrap();
            assert!(records.iter().any(|(_, bytes)| {
                serde_json::from_slice::<serde_json::Value>(bytes).unwrap()["event"]["kind"]
                    == "transport_authenticated"
            }));
            assert!(records.iter().any(|(_, bytes)| {
                serde_json::from_slice::<serde_json::Value>(bytes).unwrap()["event"]["kind"]
                    == "authentication_denied"
            }));
            if round == 0 {
                use crate::administration::ManagementCommand as M;
                database
                    .administer(context.clone(), Operation::Suspend(true))
                    .await
                    .unwrap();
                let backup = manager
                    .execute_for_test(
                        context.clone(),
                        M::Backup {
                            session_id: uuid::Uuid::new_v4(),
                            destination: "primary".into(),
                        },
                    )
                    .await
                    .unwrap();
                let backup_id =
                    uuid::Uuid::parse_str(backup["backup_id"].as_str().unwrap()).unwrap();
                manager
                    .execute_for_test(context.clone(), M::RotateDataKey)
                    .await
                    .unwrap();
                manager
                    .execute_for_test(context.clone(), M::RewrapKeys)
                    .await
                    .unwrap();
                database
                    .verify_backup_checkpoint_named(context.clone(), "primary", backup_id)
                    .await
                    .unwrap();
                assert!(
                    serde_json::from_value::<M>(serde_json::json!({
                        "operation": "prepare_restore",
                        "destination": "primary",
                        "backup_id": backup_id,
                        "incarnation": uuid::Uuid::new_v4()
                    }))
                    .is_err(),
                    "removed management recovery must be rejected at decoding"
                );
                database
                    .administer(context.clone(), Operation::Suspend(false))
                    .await
                    .unwrap();
                assert_eq!(
                    database.get(&context, "docs", "first").await.unwrap().body["exact"],
                    serde_json::json!(9007199254740993u64)
                );
            }
            if round == 1 {
                use crate::administration::ManagementCommand as M;
                let invocation = manager.prepare(context.clone(), M::Status {}).unwrap();
                let fence = invocation.response_fence().unwrap();
                let _encoded = serde_json::to_vec(&invocation.execute().await.unwrap()).unwrap();
                let policy = database.engine().generation().unwrap().state.policy.clone();
                let mut changed = policy.clone();
                changed
                    .grants
                    .retain(|grant| grant.principal != context.principal);
                changed.grants.push(Grant {
                    principal: "replacement-admin".into(),
                    collection: None,
                    actions: BTreeSet::from([Action::Admin]),
                });
                database
                    .administer(context.clone(), Operation::SetPolicy(changed))
                    .await
                    .unwrap();
                assert_eq!(
                    fence.check_release().unwrap_err().code,
                    kasumi_types::ErrorCode::Conflict
                );
                assert!(manager.prepare(context.clone(), M::Status {}).is_err());
                database
                    .administer(
                        RequestContext {
                            principal: "replacement-admin".into(),
                            ..context.clone()
                        },
                        Operation::SetPolicy(policy),
                    )
                    .await
                    .unwrap();
            }
            if round == 0 {
                let mut policy = control.engine().generation().unwrap().state.policy.clone();
                policy.grants.push(Grant {
                    principal: "rotated-startup-operator".into(),
                    collection: None,
                    actions: BTreeSet::from([
                        Action::Read,
                        Action::Write,
                        Action::Admin,
                        Action::Audit,
                    ]),
                });
                control
                    .administer(
                        configured_control_context(&config.control).unwrap(),
                        Operation::SetPolicy(policy),
                    )
                    .await
                    .unwrap();
                config.control.startup_principal = Some("rotated-startup-operator".into());
            } else {
                assert_eq!(
                    configured_control_context(&config.control)
                        .unwrap()
                        .principal,
                    "rotated-startup-operator"
                );
            }
            stop.send_replace(true);
            tokio::time::timeout(Duration::from_secs(15), serving)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(database.engine().generation().is_err());
            drop(database);
            drop(registry);
            drop(audit);
            if round == 0 {
                let staged =
                    staged_config(&config.tenants[0], "beta", uuid::Uuid::new_v4().to_string());
                config.tenants.push(staged);
            }
            config.tenants[0].initial_policy.grants.push(Grant {
                principal: "config-change-must-not-grant".into(),
                collection: None,
                actions: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
            });
        }
        mock_stop.send_replace(true);
        mock.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn three_runtime_nodes_replicate_with_control_quorum_over_audited_pinned_mtls() {
        replicated_runtime_fixture(false, None).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn three_runtime_nodes_report_committed_recovery_prepare_over_protected_tls() {
        replicated_runtime_fixture_inner(false, None, false, true).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn runtime_catches_up_spare_and_replaces_three_voters_through_admin_control() {
        replicated_runtime_fixture(true, None).await;
    }
    #[derive(Clone, Copy)]
    enum BootstrapFault {
        ControlPolicy,
        TenantLimits,
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn initial_control_bootstrap_rejects_mismatched_policy_and_raft_traffic() {
        replicated_runtime_fixture(false, Some(BootstrapFault::ControlPolicy)).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn initial_tenant_bootstrap_rejects_mismatched_limits_and_raft_traffic() {
        replicated_runtime_fixture(false, Some(BootstrapFault::TenantLimits)).await;
    }
    mod recovery_fixture {
        include!("runtime_recovery_tests.rs");
    }

    // Construct large fixture futures in separate frames and keep callers small.
    fn replicated_runtime_fixture(
        with_spare: bool,
        bootstrap_fault: Option<BootstrapFault>,
    ) -> impl std::future::Future<Output = ()> {
        Box::pin(replicated_runtime_fixture_inner(
            with_spare,
            bootstrap_fault,
            false,
            false,
        ))
    }

    fn open_replicated_fixture_node(
        config: RuntimeConfig,
        credential: impl Fn(&str) -> Result<Zeroizing<String>> + Send + Sync + 'static,
        storage: crate::runtime_memory::RuntimeStorage,
    ) -> impl std::future::Future<Output = Result<NodeRuntime>> {
        Box::pin(NodeRuntime::open_using_storage(config, credential, storage))
    }

    // Construct operation futures outside the enclosing fixture poll frame.
    fn fixture_operation<F: std::future::Future>(
        make: impl FnOnce() -> F,
    ) -> impl std::future::Future<Output = F::Output> {
        Box::pin(make())
    }

    async fn replicated_runtime_fixture_inner(
        with_spare: bool,
        bootstrap_fault: Option<BootstrapFault>,
        fenced_source: bool,
        protected_prepare_only: bool,
    ) {
        #[cfg(test)]
        let fixture_started = std::time::Instant::now();
        macro_rules! fixture_stage {
            ($($arg:tt)*) => {
                #[cfg(test)]
                eprintln!(
                    "[replicated fixture +{:?}] {}",
                    fixture_started.elapsed(),
                    format_args!($($arg)*)
                );
            };
        }
        fixture_stage!("waiting for lifecycle gate");
        let _fixture = LIFECYCLE_GATE.lock().await;
        fixture_stage!("acquired lifecycle gate");
        let canonical = !with_spare && bootstrap_fault.is_none();
        assert!(!protected_prepare_only || (canonical && !fenced_source));
        let recovery_credentials = recovery_fixture::Credentials::new();
        let recovery_jwks = recovery_credentials.jwks.clone();
        let node_count = if with_spare { 4 } else { 3 };
        let dir = kasumi_store::test_utils::private_tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let template = fixture_config();
        let cluster_storage = crate::runtime_cluster_storage::ClusterStorage::prepare(
            dir.path(),
            node_count,
            canonical,
            &template.admission,
            &template.scratch_disk,
        )
        .unwrap();
        fixture_stage!("prepared cluster storage");
        let storage = cluster_storage.storage.clone();
        let (mock_files, _) = certificate_files(dir.path());
        fixture_stage!("binding mock KMS listener");
        let mock_socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        fixture_stage!("bound mock KMS listener");
        let kms_endpoint = format!(
            "https://localhost:{}",
            mock_socket.local_addr().unwrap().port()
        );
        let (mock_stop, mock_shutdown) = watch::channel(false);
        let mock = tokio::spawn(tls::serve_tls(
            mock_socket,
            kasumi_transport::server_config(
                &mock_files.load().unwrap(),
                ClientAuthentication::OAuth,
            )
            .unwrap(),
            Router::new()
                .route("/v1/transit/{*operation}", post(transit))
                .route(
                    "/recovery-jwks",
                    axum::routing::get(move || {
                        let jwks = recovery_jwks.clone();
                        async move { Json(jwks) }
                    }),
                )
                .with_state(Arc::new(TransitFixture::default())),
            ListenerLimits::default(),
            Arc::new(FixtureAudit),
            mock_shutdown,
        ));

        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let ca_path = dir.path().join("cluster-ca.pem");
        std::fs::write(&ca_path, ca_cert.pem()).unwrap();
        let reserved = (0..node_count * 4)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect::<Vec<_>>();
        let addresses = reserved
            .iter()
            .map(|listener| listener.local_addr().unwrap())
            .collect::<Vec<_>>();
        let mut files = Vec::new();
        let mut peers = Vec::new();
        for node in 0..node_count {
            let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
            params.extended_key_usages = vec![
                rcgen::ExtendedKeyUsagePurpose::ServerAuth,
                rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            ];
            params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = params.signed_by(&key, &issuer).unwrap();
            let identity = TlsFiles {
                certificate: dir.path().join(format!("node{node}.pem")),
                private_key: dir.path().join(format!("node{node}-key.pem")),
            };
            std::fs::write(&identity.certificate, cert.pem()).unwrap();
            std::fs::write(&identity.private_key, key.serialize_pem()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &identity.private_key,
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            peers.push(ReplicaConfig {
                node_id: node as u64 + 1,
                endpoint: format!("https://localhost:{}", addresses[node * 4 + 3].port()),
                certificate_pins: vec![format_certificate_pin(
                    &identity.load().unwrap().certificate_pin(),
                )],
                failure_domain: format!("zone-{node}"),
            });
            files.push(identity);
        }
        fixture_stage!("generated {node_count} node identities");
        let incarnation = uuid::Uuid::new_v4().to_string();
        let control_incarnation = uuid::Uuid::new_v4().to_string();
        let mut recovery = if canonical {
            fixture_stage!("creating recovery fixture");
            Some(
                recovery_fixture::Fixture::new(
                    dir.path(),
                    recovery_credentials,
                    &files,
                    ca_path.clone(),
                    Uuid::parse_str(&incarnation).unwrap(),
                    Uuid::parse_str(&control_incarnation).unwrap(),
                    &kms_endpoint,
                    &mock_files.certificate,
                    &cluster_storage,
                    fenced_source,
                )
                .await,
            )
        } else {
            None
        };
        fixture_stage!("recovery fixture ready");
        let mut configurations = Vec::new();
        for node in 0..node_count {
            fixture_stage!("configuring node {node}");
            let mut config = fixture_config();
            config.mode = DeploymentMode::Replicated;
            // All old per-node policies are identical; differing policies need
            // an explicit shared-budget design, not silent homogenization.
            assert_eq!(config.admission, template.admission);
            config.admission = storage.policy().clone();
            config.persistent_disk = cluster_storage.persistent.clone();
            config.database_path = dir.path().join(format!("persistent/node{node}.kv"));
            config.scratch_disk = cluster_storage.data_scratch[node].clone();
            config.mcp.tls = files[node].clone();
            config.native.tls = files[node].clone();
            config.admin.tls = files[node].clone();
            config.mcp.listen = addresses[node * 4];
            config.native.listen = addresses[node * 4 + 1];
            config.admin.listen = addresses[node * 4 + 2];
            config.mcp.protocol = McpConfig::new(format!(
                "https://localhost:{}/mcp",
                config.mcp.listen.port()
            ))
            .unwrap();
            config.native.client_ca = ca_path.clone();
            config.admin.client_ca = ca_path.clone();
            config.replication = Some(ReplicationConfig {
                initial_voters: BTreeSet::from([1, 2, 3]),
                node_id: node as u64 + 1,
                listener: MutualTlsEndpoint {
                    listen: addresses[node * 4 + 3],
                    tls: files[node].clone(),
                    client_ca: ca_path.clone(),
                },
                peers: peers.clone(),
            });
            config.tenants[0].incarnation = Some(incarnation.clone());
            config.control.incarnation = Some(control_incarnation.clone());
            config.security_audit.keys.transit_mut().unwrap().key_name =
                format!("node{node}-security");
            for settings in [
                &mut config.control.keys,
                &mut config.control.custody_keys,
                &mut config.security_audit.keys,
            ]
            .into_iter()
            .chain(
                config
                    .tenants
                    .iter_mut()
                    .flat_map(|tenant| [&mut tenant.keys, &mut tenant.custody_keys]),
            ) {
                let settings = settings.transit_mut().unwrap();
                settings.endpoint = kms_endpoint.clone();
                settings.ca_certificate = Some(mock_files.certificate.clone());
            }
            config.backup_destinations.insert(
                "primary".into(),
                crate::administration::DestinationConfig::Filesystem {
                    directory: dir.path().join("persistent/backups"),
                    max_bytes: 32 << 20,
                },
            );
            if node == 2 {
                match bootstrap_fault {
                    Some(BootstrapFault::ControlPolicy) => {
                        config.control.initial_policy.grants.push(Grant {
                            principal: "unexpected-bootstrap-principal".into(),
                            collection: None,
                            actions: BTreeSet::from([Action::Read]),
                        })
                    }
                    Some(BootstrapFault::TenantLimits) => {
                        config.tenants[0].initial_limits.max_documents -= 1
                    }
                    None => {}
                }
            }
            if let Some(recovery) = &recovery {
                fixture_stage!("node {node}: configuring recovery credentials");
                fixture_operation(|| recovery.configure(&mut config, node)).await;
                fixture_stage!("node {node}: recovery credentials configured");
                if fenced_source && node == 0 {
                    // Keep a distinct application credential path so a failed
                    // key-provider construction is observable on the reopen.
                    let application = config.tenants[0].keys.transit_mut().unwrap();
                    let original = std::fs::read(&application.token_file).unwrap();
                    let path = dir.path().join("fenced-application.token");
                    kasumi_store::private_files::publish(&path, &original).unwrap();
                    application.token_file = path.to_str().unwrap().into();
                }
                fixture_stage!("node {node}: enrolling storage");
                fixture_operation(|| {
                    crate::data_node_enrollment::initialize_with_storage(
                        config.clone(),
                        storage.clone(),
                    )
                })
                .await
                .unwrap();
                fixture_stage!("node {node}: storage enrolled");
            } else {
                fixture_stage!("node {node}: creating fixture storage");
                create_fixture_node(&config, &storage).await;
                fixture_stage!("node {node}: fixture storage created");
            }
            configurations.push(config);
        }
        fixture_stage!("all node configurations ready");
        drop(reserved);
        if fenced_source {
            // All three data nodes have completed explicit enrollment while
            // the real issuer was available. Its original grant was acquired
            // with Serving purpose and used to initialize the tenant catalogs.
            let recovery = recovery.as_mut().unwrap();
            fixture_operation(|| recovery.shutdown_issuer()).await;
            let mut config = configurations.remove(0);
            assert!(matches!(
                &config.tenants[0].serving,
                crate::serving_runtime::TenantServingConfig::Independent { .. }
            ));
            let application_token = config.tenants[0]
                .keys
                .transit_mut()
                .unwrap()
                .token_file
                .clone();
            let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed = probes.clone();
            let mut runtime = open_replicated_fixture_node(
                config.clone(),
                move |name| {
                    if name == application_token {
                        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        anyhow::bail!("application key is independently unavailable");
                    }
                    Ok(Zeroizing::new("test-runtime-token".into()))
                },
                storage.clone(),
            )
            .await
            .unwrap();
            let grant_bytes = runtime
                .audit
                .store()
                .get_bounded("node.enrollment", b"grant/acme", 64 << 10)
                .unwrap()
                .unwrap();
            let grant: kasumi_serving::SignedLease = serde_json::from_slice(&grant_bytes).unwrap();
            assert_eq!(
                grant.claims.request.purpose,
                kasumi_serving::LeasePurpose::Serving
            );
            assert_eq!(
                grant.claims.authority_id,
                config.serving_authorities["issuer"].manifest.authority_id
            );
            assert_eq!(probes.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert!(runtime.tenants.is_empty());
            assert!(runtime.administration.is_some());
            assert_eq!(
                runtime.unavailable_sources.get("acme"),
                config.tenants[0].incarnation.as_ref()
            );
            let topology = runtime.expected_topology().unwrap();
            assert_eq!(
                topology.tenants["acme"].incarnation,
                config.tenants[0].incarnation.as_ref().unwrap().as_str()
            );
            assert_eq!(
                runtime
                    .control_database()
                    .engine()
                    .generation()
                    .unwrap()
                    .state
                    .tenant,
                CONTROL_TENANT
            );
            assert_eq!(runtime.data_listeners.len(), 3);
            runtime.shutdown().await.unwrap();
            mock_stop.send_replace(true);
            mock.await.unwrap().unwrap();
            return;
        }
        let context = RequestContext {
            authorization: kasumi_types::RequestAuthorization::service_identity(),
            principal: "acme-admin".into(),
            tenant: "acme".into(),
            scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
            request_id: uuid::Uuid::new_v4().to_string(),
        };
        let context = if let Some(recovery) = &recovery {
            fixture_stage!("creating recovery request context");
            fixture_operation(|| recovery.context(false)).await
        } else {
            context
        };
        fixture_stage!("request context ready");
        if let Some(fault) = bootstrap_fault {
            let mut runtimes = Vec::new();
            let mut servers = Vec::new();
            let (stop, shutdown) = watch::channel(false);
            for config in configurations {
                let mut runtime = open_replicated_fixture_node(
                    config,
                    |_| Ok(Zeroizing::new("test-runtime-token".into())),
                    storage.clone(),
                )
                .await
                .unwrap();
                let listener = runtime.cluster_listener.take().unwrap();
                servers.push(tokio::spawn(tls::serve_tls(
                    listener.listener,
                    listener.tls,
                    listener.router,
                    ListenerLimits::default(),
                    runtime.audit.clone(),
                    shutdown.clone(),
                )));
                runtimes.push(runtime);
            }
            fn selected(runtime: &NodeRuntime, fault: BootstrapFault) -> &OpenedTenant {
                match fault {
                    BootstrapFault::ControlPolicy => &runtime.control,
                    BootstrapFault::TenantLimits => &runtime.tenants[0],
                }
            }
            for runtime in &runtimes {
                let error = tokio::time::timeout(
                    Duration::from_secs(10),
                    runtime.initialize_original(selected(runtime, fault)),
                )
                .await
                .unwrap()
                .unwrap_err();
                assert!(error.to_string().contains("bootstrap mismatch"), "{error}");
                assert!(
                    selected(runtime, fault)
                        .database
                        .raft_group()
                        .raft()
                        .metrics()
                        .borrow()
                        .membership_config
                        .membership()
                        .get_joint_config()
                        .is_empty()
                );
            }
            // A fresh mismatched follower also rejects traffic from an already
            // configured peer before persistence or application; skipping a
            // startup comparison during recovery cannot bypass this fence.
            let target = selected(&runtimes[2], fault);
            let before = target
                .database
                .raft_group()
                .raft()
                .metrics()
                .borrow()
                .current_term;
            let group = format!(
                "{}/{}",
                target.store.tenant(),
                target.bootstrap.as_ref().unwrap().incarnation
            );
            let request:kasumi_raft::RpcRequest=serde_json::from_value(serde_json::json!({"rpc":"vote","payload":{
                "vote":{"leader_id":{"term":99,"node_id":1},"committed":false},"last_log_id":null
            }})).unwrap();
            assert!(
                kasumi_raft::RaftTransport::send(
                    runtimes[0].cluster.as_ref().unwrap().as_ref(),
                    &group,
                    1,
                    3,
                    &kasumi_raft::BasicNode::new("https://ignored.invalid"),
                    request
                )
                .await
                .is_err()
            );
            assert_eq!(
                target
                    .database
                    .raft_group()
                    .raft()
                    .metrics()
                    .borrow()
                    .current_term,
                before
            );
            for runtime in &mut runtimes {
                runtime.shutdown().await.unwrap();
            }
            stop.send_replace(true);
            for server in servers {
                server.await.unwrap().unwrap();
            }
            mock_stop.send_replace(true);
            mock.await.unwrap().unwrap();
            return;
        }
        let mut stops = Vec::new();
        let mut tasks = Vec::new();
        let mut registries = Vec::new();
        let mut managers = Vec::new();
        let mut controls = Vec::new();
        let mut cluster_networks = Vec::new();
        let mut recovery_handles = Vec::new();
        let mut first_facades = Vec::new();
        for (node, config) in configurations.iter().cloned().enumerate() {
            fixture_stage!("node {node}: opening runtime");
            let runtime = open_replicated_fixture_node(
                config,
                move |path| {
                    if canonical {
                        file_secret(path)
                    } else {
                        Ok(Zeroizing::new("test-runtime-token".into()))
                    }
                },
                storage.clone(),
            )
            .await
            .unwrap();
            fixture_stage!("node {node}: runtime opened");
            assert!(Arc::ptr_eq(
                runtime.audit.admission().memory(),
                storage.memory()
            ));
            assert!(first_facades.iter().all(
                |facade: &std::sync::Weak<kasumi_engine::admission::NodeAdmission>| !Arc::ptr_eq(
                    &facade.upgrade().unwrap(),
                    runtime.audit.admission()
                )
            ));
            first_facades.push(Arc::downgrade(runtime.audit.admission()));
            recovery_handles.push(recovery_fixture::Handles::capture(&runtime));
            registries.push(runtime.registry.clone());
            managers.push(runtime.administration.clone().unwrap());
            controls.push(runtime.control.database.clone());
            cluster_networks.push(runtime.cluster.clone().unwrap());
            let (stop, shutdown) = watch::channel(false);
            stops.push(stop);
            tasks.push(tokio::spawn(runtime.serve(shutdown)));
            fixture_stage!("node {node}: server spawned");
        }
        if with_spare {
            let control_leader = tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    for (index, control) in controls.iter().enumerate().take(3) {
                        let metrics = control.raft_group().raft().metrics().borrow().clone();
                        if metrics.current_leader == Some(metrics.id)
                            && control
                                .engine()
                                .generation()
                                .unwrap()
                                .state
                                .collections
                                .get("topology")
                                .is_some_and(|c| c.documents.contains_key("current"))
                        {
                            return index;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            let _ = control_leader;
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    for (index, control) in controls.iter().enumerate().take(3) {
                        let metrics = control.raft_group().raft().metrics().borrow().clone();
                        if metrics.current_leader == Some(metrics.id)
                            && managers[index]
                                .execute_for_test(
                                    control_context(&fixture_config().control.initial_policy)
                                        .unwrap(),
                                    crate::administration::ManagementCommand::AddLearner {
                                        node_id: 4,
                                    },
                                )
                                .await
                                .is_ok()
                        {
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            })
            .await
            .unwrap();
        }
        fixture_stage!("waiting for tenant registries");
        let databases = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                let databases = registries
                    .iter()
                    .take(3)
                    .map(|registry| registry.database(&context))
                    .collect::<kasumi_types::Result<Vec<_>>>();
                if let Ok(databases) = databases {
                    break databases;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        let databases = match databases {
            Ok(databases) => databases,
            Err(elapsed) => {
                let errors = registries
                    .iter()
                    .take(3)
                    .map(|registry| registry.database(&context).map(|_| ()))
                    .collect::<Vec<_>>();
                let metrics = controls
                    .iter()
                    .map(|control| control.raft_group().raft().metrics().borrow().clone())
                    .collect::<Vec<_>>();
                let access = controls
                    .iter()
                    .map(|control| {
                        let group = control.raft_group();
                        let stores = group.storage_domains();
                        (
                            stores
                                .application()
                                .check_access()
                                .map_err(|e| e.to_string()),
                            stores
                                .custody()
                                .store()
                                .check_access()
                                .map_err(|e| e.to_string()),
                            group.check_access().map_err(|e| e.to_string()),
                        )
                    })
                    .collect::<Vec<_>>();
                let control_group = format!("{CONTROL_TENANT}/{control_incarnation}");
                // Every probe has its own bound, so a failed peer cannot hide
                // the other routes. All probes run only after the original wait
                // has failed and cannot make this fixture pass.
                let bootstrap = tokio::join!(
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        cluster_networks[0].bootstrap_fingerprint(1, &control_group)
                    ),
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        cluster_networks[1].bootstrap_fingerprint(2, &control_group)
                    ),
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        cluster_networks[2].bootstrap_fingerprint(3, &control_group)
                    ),
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        cluster_networks[0].bootstrap_fingerprint(2, &control_group)
                    ),
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        cluster_networks[1].bootstrap_fingerprint(1, &control_group)
                    ),
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        cluster_networks[2].bootstrap_fingerprint(1, &control_group)
                    ),
                );
                let transport_free = cluster_networks
                    .iter()
                    .map(|network| network.fixture_transport_free_slots())
                    .collect::<Vec<_>>();
                let disk = controls[0]
                    .raft_group()
                    .storage_domains()
                    .application()
                    .persistent_disk()
                    .snapshot();
                let mut finished_tasks = Vec::new();
                for (index, task) in tasks.iter_mut().enumerate() {
                    if task.is_finished() {
                        finished_tasks.push((index, task.await));
                    }
                }
                panic!(
                    "tenant registry readiness timed out: {elapsed:?}; registry errors: {errors:?}; control metrics: {metrics:?}; access (application, custody, raft): {access:?}; bootstrap probes (1->1, 2->2, 3->3, 1->2, 2->1, 3->1): {bootstrap:?}; transport free slots (incoming, outgoing): {transport_free:?}; shared disk: {disk:?}; finished server tasks: {finished_tasks:?}"
                );
            }
        };
        fixture_stage!("tenant registries ready");
        fixture_stage!("waiting for data leader");
        let leader = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                for (i, database) in databases.iter().enumerate() {
                    if database
                        .raft_group()
                        .raft()
                        .metrics()
                        .borrow()
                        .current_leader
                        == Some(i as u64 + 1)
                    {
                        return i;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        fixture_stage!("data leader selected: node {leader}");
        fixture_stage!("creating docs collection");
        let creation = fixture_operation(|| {
            databases[leader].administer(
                context.clone(),
                Operation::CreateCollection(CollectionDefinition {
                    retention_class: kasumi_types::CollectionRetentionClass::Operational,
                    write_mode: kasumi_types::CollectionWriteMode::Mutable,
                    name: "docs".into(),
                    schema: serde_json::json!({"type":"object"}),
                    indexes: Vec::new(),
                    strict_read_audit: false,
                }),
            )
        })
        .await;
        if let Err(error) = creation {
            let data_metrics = databases
                .iter()
                .map(|database| database.raft_group().raft().metrics().borrow().clone())
                .collect::<Vec<_>>();
            let control_metrics = controls
                .iter()
                .map(|control| control.raft_group().raft().metrics().borrow().clone())
                .collect::<Vec<_>>();
            let data_access = databases
                .iter()
                .map(|database| {
                    let group = database.raft_group();
                    let stores = group.storage_domains();
                    (
                        stores
                            .application()
                            .check_access()
                            .map_err(|e| e.to_string()),
                        stores
                            .custody()
                            .store()
                            .check_access()
                            .map_err(|e| e.to_string()),
                        group.check_access().map_err(|e| e.to_string()),
                    )
                })
                .collect::<Vec<_>>();
            let applied_docs = databases
                .iter()
                .map(|database| {
                    database.engine().generation().map(|generation| {
                        (
                            generation.state.revision,
                            generation.state.collections.contains_key("docs"),
                        )
                    })
                })
                .collect::<Vec<_>>();
            let data_group = format!("{}/{incarnation}", context.tenant);
            let bootstrap = tokio::join!(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    cluster_networks[0].bootstrap_fingerprint(1, &data_group)
                ),
                tokio::time::timeout(
                    Duration::from_secs(2),
                    cluster_networks[1].bootstrap_fingerprint(2, &data_group)
                ),
                tokio::time::timeout(
                    Duration::from_secs(2),
                    cluster_networks[2].bootstrap_fingerprint(3, &data_group)
                ),
                tokio::time::timeout(
                    Duration::from_secs(2),
                    cluster_networks[0].bootstrap_fingerprint(2, &data_group)
                ),
                tokio::time::timeout(
                    Duration::from_secs(2),
                    cluster_networks[1].bootstrap_fingerprint(1, &data_group)
                ),
                tokio::time::timeout(
                    Duration::from_secs(2),
                    cluster_networks[2].bootstrap_fingerprint(1, &data_group)
                ),
            );
            let transport_free = cluster_networks
                .iter()
                .map(|network| network.fixture_transport_free_slots())
                .collect::<Vec<_>>();
            let disk = databases[0]
                .raft_group()
                .storage_domains()
                .application()
                .persistent_disk()
                .snapshot();
            panic!(
                "initial tenant CreateCollection failed: {error:?}; selected leader: {leader}; data metrics: {data_metrics:?}; control metrics: {control_metrics:?}; data access (application, custody, raft): {data_access:?}; applied docs (revision, exists): {applied_docs:?}; bootstrap probes (1->1, 2->2, 3->3, 1->2, 2->1, 3->1): {bootstrap:?}; transport free slots (incoming, outgoing): {transport_free:?}; shared disk: {disk:?}"
            );
        }
        fixture_stage!("docs collection created");
        let batch = MutationBatch {
            read_set: Vec::new(),
            idempotency_key: "replicated-runtime".into(),
            operations: vec![Mutation::Put {
                collection: "docs".into(),
                id: "a".into(),
                body: serde_json::json!({"durable":true}),
                expected: Precondition::Absent,
            }],
        };
        fixture_stage!("writing initial document");
        let write =
            fixture_operation(|| databases[leader].mutate(context.clone(), batch.clone())).await;
        match write {
            Ok(_) => {}
            Err(error) if error.code == kasumi_types::ErrorCode::UnknownOutcome => {
                // A timed-out proposal remains owned. Only a linearizable,
                // positive receipt for the exact original batch can resolve it.
                let expected_digest = batch.digest().unwrap();
                tokio::time::timeout(Duration::from_secs(40), async {
                    loop {
                        for database in &databases {
                            if let Ok(Some(receipt)) = database
                                .operation_receipt(&context, &batch.idempotency_key)
                                .await
                            {
                                assert_eq!(receipt.request_digest, expected_digest);
                                assert_eq!(
                                    receipt.scope,
                                    kasumi_types::MutationReceiptScope {
                                        tenant: context.tenant.clone(),
                                        incarnation: incarnation.clone(),
                                        principal: context.principal.clone(),
                                    }
                                );
                                receipt.outcome.unwrap();
                                return;
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                })
                .await
                .unwrap_or_else(|_| {
                    let metrics = databases
                        .iter()
                        .map(|database| database.raft_group().raft().metrics().borrow().clone())
                        .collect::<Vec<_>>();
                    panic!(
                        "exact initial mutation receipt absent after UnknownOutcome: {error:?}; metrics={metrics:?}"
                    )
                });
            }
            Err(error) => panic!("initial tenant mutation failed: {error:?}"),
        }
        fixture_stage!("initial document write resolved");
        fixture_stage!("waiting for document replication");
        let replication = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if databases.iter().all(|database| {
                    database
                        .engine()
                        .generation()
                        .unwrap()
                        .state
                        .collections
                        .get("docs")
                        .is_some_and(|collection| collection.documents.contains_key("a"))
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        if let Err(elapsed) = replication {
            let data_metrics = databases
                .iter()
                .map(|database| database.raft_group().raft().metrics().borrow().clone())
                .collect::<Vec<_>>();
            let control_metrics = controls
                .iter()
                .map(|control| control.raft_group().raft().metrics().borrow().clone())
                .collect::<Vec<_>>();
            let registered = registries
                .iter()
                .map(|registry| {
                    registry
                        .database(&context)
                        .map(|database| database.raft_group().raft().metrics().borrow().clone())
                })
                .collect::<Vec<_>>();
            let data_access = databases
                .iter()
                .map(|database| {
                    let group = database.raft_group();
                    let stores = group.storage_domains();
                    (
                        stores
                            .application()
                            .check_access()
                            .map_err(|e| e.to_string()),
                        stores
                            .custody()
                            .store()
                            .check_access()
                            .map_err(|e| e.to_string()),
                        group.check_access().map_err(|e| e.to_string()),
                    )
                })
                .collect::<Vec<_>>();
            let applied_docs =
                databases
                    .iter()
                    .map(|database| {
                        database.engine().generation().map(|generation| {
                            (
                                generation.state.revision,
                                generation.state.collections.get("docs").is_some_and(
                                    |collection| collection.documents.contains_key("a"),
                                ),
                            )
                        })
                    })
                    .collect::<Vec<_>>();
            let data_group = format!("{}/{incarnation}", context.tenant);
            // The original 20-second condition has already failed. Each route
            // probe is independently bounded and cannot satisfy it afterward.
            let bootstrap = tokio::join!(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    cluster_networks[0].bootstrap_fingerprint(1, &data_group)
                ),
                tokio::time::timeout(
                    Duration::from_secs(2),
                    cluster_networks[1].bootstrap_fingerprint(2, &data_group)
                ),
                tokio::time::timeout(
                    Duration::from_secs(2),
                    cluster_networks[2].bootstrap_fingerprint(3, &data_group)
                ),
                tokio::time::timeout(
                    Duration::from_secs(2),
                    cluster_networks[0].bootstrap_fingerprint(2, &data_group)
                ),
                tokio::time::timeout(
                    Duration::from_secs(2),
                    cluster_networks[1].bootstrap_fingerprint(1, &data_group)
                ),
                tokio::time::timeout(
                    Duration::from_secs(2),
                    cluster_networks[2].bootstrap_fingerprint(1, &data_group)
                ),
            );
            let transport_free = cluster_networks
                .iter()
                .map(|network| network.fixture_transport_free_slots())
                .collect::<Vec<_>>();
            let disk = databases[0]
                .raft_group()
                .storage_domains()
                .application()
                .persistent_disk()
                .snapshot();
            panic!(
                "replicated document application timed out: {elapsed:?}; original selected leader: {leader}; data metrics: {data_metrics:?}; control metrics: {control_metrics:?}; current registry routes: {registered:?}; data access (application, custody, raft): {data_access:?}; applied docs (revision, exists): {applied_docs:?}; bootstrap probes (1->1, 2->2, 3->3, 1->2, 2->1, 3->1): {bootstrap:?}; transport free slots (incoming, outgoing): {transport_free:?}; shared disk: {disk:?}"
            );
        }
        fixture_stage!("document replicated");
        use crate::administration::ManagementCommand as M;
        if with_spare {
            managers[leader]
                .execute_for_test(context.clone(), M::AddLearner { node_id: 4 })
                .await
                .unwrap();
            let final_voters = BTreeSet::from([1, 2, 4]);
            assert!(
                managers[leader]
                    .execute_for_test(
                        context.clone(),
                        M::ChangeMembership {
                            voters: BTreeSet::from([1, 2])
                        }
                    )
                    .await
                    .is_err()
            );
            // Replacing voter 3 may remove the serving leader. Resolve the
            // applied membership after an uncertain response before retrying.
            let mut last_membership_error = String::from("no membership call attempted");
            let membership_result = tokio::time::timeout(Duration::from_secs(45), async {
                loop {
                    for (manager, registry) in managers.iter().zip(&registries) {
                        let Ok(database) = registry.database(&context) else {
                            continue;
                        };
                        let metrics = database.raft_group().raft().metrics().borrow().clone();
                        if metrics.current_leader != Some(metrics.id) {
                            continue;
                        }
                        let membership = &metrics.membership_config;
                        let configs = membership.membership().get_joint_config();
                        if configs.len() == 1
                            && configs[0] == final_voters
                            && membership.log_id().is_some()
                            && metrics.last_applied >= *membership.log_id()
                        {
                            return;
                        }
                        if let Err(error) = manager
                            .execute_for_test(
                                context.clone(),
                                M::ChangeMembership {
                                    voters: final_voters.clone(),
                                },
                            )
                            .await
                        {
                            last_membership_error = format!("node {}: {error:#}", metrics.id);
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await;
            if let Err(elapsed) = membership_result {
                let data_metrics = registries
                    .iter()
                    .map(|registry| {
                        registry
                            .database(&context)
                            .map(|database| database.raft_group().raft().metrics().borrow().clone())
                    })
                    .collect::<Vec<_>>();
                let control_metrics = controls
                    .iter()
                    .map(|control| control.raft_group().raft().metrics().borrow().clone())
                    .collect::<Vec<_>>();
                panic!(
                    "membership replacement timed out: {elapsed:?}; last command error: {last_membership_error}; data metrics: {data_metrics:?}; control metrics: {control_metrics:?}"
                );
            }
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    for (manager, control) in managers.iter().zip(&controls) {
                        let metrics = control.raft_group().raft().metrics().borrow().clone();
                        if metrics.current_leader == Some(metrics.id)
                            && manager
                                .execute_for_test(
                                    context.clone(),
                                    M::PublishMembership {
                                        voters: final_voters.clone(),
                                    },
                                )
                                .await
                                .is_ok()
                        {
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            tokio::time::timeout(Duration::from_secs(45), async {
                loop {
                    for (index, control) in controls.iter().enumerate() {
                        let metrics = control.raft_group().raft().metrics().borrow().clone();
                        if metrics.current_leader == Some(metrics.id)
                            && managers[index]
                                .execute_for_test(
                                    control_context(&fixture_config().control.initial_policy)
                                        .unwrap(),
                                    M::ChangeMembership {
                                        voters: final_voters.clone(),
                                    },
                                )
                                .await
                                .is_ok()
                        {
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            })
            .await
            .unwrap();
            let recovered = tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    for index in [0, 1, 3] {
                        if let Ok(db) = registries[index].database(&context)
                            && let Ok(doc) = db.get(&context, "docs", "a").await
                        {
                            return doc;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(recovered.body["durable"], serde_json::json!(true));
            for stop in &stops {
                stop.send_replace(true);
            }
            for task in tasks {
                tokio::time::timeout(Duration::from_secs(15), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            }
            mock_stop.send_replace(true);
            mock.await.unwrap().unwrap();
            return;
        }
        fixture_stage!("suspending source database");
        fixture_operation(|| {
            databases[leader].administer(context.clone(), Operation::Suspend(true))
        })
        .await
        .unwrap();
        fixture_stage!("source suspend accepted");
        fixture_stage!("starting backup");
        let backup = managers[leader]
            .execute_for_test(
                context.clone(),
                M::Backup {
                    session_id: uuid::Uuid::new_v4(),
                    destination: "primary".into(),
                },
            )
            .await
            .unwrap();
        fixture_stage!("backup command completed");
        let backup_id = uuid::Uuid::parse_str(backup["backup_id"].as_str().unwrap()).unwrap();
        fixture_stage!("waiting for suspend replication");
        tokio::time::timeout(Duration::from_secs(20), async {
            while !databases
                .iter()
                .all(|db| db.engine().generation().unwrap().state.suspended)
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        fixture_stage!("suspend replicated");
        let source_incarnation = Uuid::parse_str(
            &databases[leader]
                .engine()
                .generation()
                .unwrap()
                .state
                .incarnation,
        )
        .unwrap();
        let source_context = context.clone();
        let data_metrics_before_verification = databases
            .iter()
            .map(|database| database.raft_group().raft().metrics().borrow().clone())
            .collect::<Vec<_>>();
        fixture_stage!("verifying backup checkpoint");
        let checkpoint_result = fixture_operation(|| {
            databases[leader].verify_backup_checkpoint_named(context.clone(), "primary", backup_id)
        })
        .await;
        fixture_stage!("backup checkpoint verification returned");
        let checkpoint = match checkpoint_result {
            Ok(proof) => proof.checkpoint().clone(),
            Err(error) => {
                // The verification may already have proposed a maintenance
                // audit. Observe only after the original call failed; never
                // retry it or infer rollback from a leader redirect.
                let data_metrics = databases
                    .iter()
                    .map(|database| database.raft_group().raft().metrics().borrow().clone())
                    .collect::<Vec<_>>();
                let control_metrics = controls
                    .iter()
                    .map(|control| control.raft_group().raft().metrics().borrow().clone())
                    .collect::<Vec<_>>();
                let data_access = databases
                    .iter()
                    .map(|database| {
                        let group = database.raft_group();
                        let stores = group.storage_domains();
                        (
                            stores
                                .application()
                                .check_access()
                                .map_err(|e| e.to_string()),
                            stores
                                .custody()
                                .store()
                                .check_access()
                                .map_err(|e| e.to_string()),
                            group.check_access().map_err(|e| e.to_string()),
                        )
                    })
                    .collect::<Vec<_>>();
                let applied = databases
                    .iter()
                    .map(|database| {
                        database.engine().generation().map(|generation| {
                            let verification_audit = generation
                                .state
                                .audits
                                .iter()
                                .filter(|event| {
                                    event.action == "backup_verification"
                                        && event.request_id == context.request_id
                                })
                                .last()
                                .map(|event| {
                                    (
                                        event.event_id.clone(),
                                        event.data_revision,
                                        event.outcome.clone(),
                                    )
                                });
                            (
                                generation.state.revision,
                                generation.state.suspended,
                                verification_audit,
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                let transport_free = cluster_networks
                    .iter()
                    .map(|network| network.fixture_transport_free_slots())
                    .collect::<Vec<_>>();
                let disk = databases[0]
                    .raft_group()
                    .storage_domains()
                    .application()
                    .persistent_disk()
                    .snapshot();
                panic!(
                    "backup checkpoint verification failed: {error:?}; original selected leader: {leader}; backup ID: {backup_id}; data metrics before verification: {data_metrics_before_verification:?}; data metrics after failure: {data_metrics:?}; control metrics: {control_metrics:?}; data access (application, custody, raft): {data_access:?}; applied (revision, suspended, last matching verification audit): {applied:?}; transport free slots (incoming, outgoing): {transport_free:?}; shared disk: {disk:?}"
                );
            }
        };
        let recovery = recovery.as_mut().unwrap();
        let incarnation = recovery.target;
        fixture_stage!("installing recovery targets");
        recovery
            .install_targets(
                &configurations,
                &recovery_handles,
                &controls,
                &databases[leader],
                checkpoint,
            )
            .await;
        fixture_stage!("recovery targets installed");
        if protected_prepare_only {
            // A separate installed three-node point-status acceptance case:
            // observe a committed Prepare before any target Execute. Keep the
            // full terminal recovery test independent of G09's current block.
            fixture_stage!("checking protected Prepare status");
            fixture_operation(|| recovery.assert_protected_prepare_status(&configurations)).await;
            fixture_stage!("protected Prepare status checked");
            fixture_operation(|| recovery.close_targets()).await;
            for stop in &stops {
                stop.send_replace(true);
            }
            for task in tasks {
                tokio::time::timeout(Duration::from_secs(15), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            }
            drop(databases);
            recovery_handles.clear();
            cluster_networks.clear();
            managers.clear();
            controls.clear();
            registries.clear();
            assert!(
                first_facades
                    .iter()
                    .all(|facade| facade.upgrade().is_none())
            );
            first_facades.clear();
            fixture_operation(|| recovery.shutdown_issuer()).await;
            mock_stop.send_replace(true);
            mock.await.unwrap().unwrap();
            return;
        }
        {
            let source_status = managers[leader]
                .prepare(source_context.clone(), M::Status {})
                .unwrap();
            let source_release = source_status.response_fence().unwrap();
            fixture_stage!("executing retained source status");
            let retained_source_response =
                fixture_operation(|| source_status.execute()).await.unwrap();
            fixture_stage!("retained source status completed");
            assert_eq!(
                retained_source_response["incarnation"],
                databases[leader]
                    .engine()
                    .generation()
                    .unwrap()
                    .state
                    .incarnation
            );
            source_release.check_release().unwrap();
            fixture_stage!("starting recovery");
            fixture_operation(|| recovery.recover(&cluster_networks)).await;
            fixture_stage!("recovery completed");
            fixture_operation(|| recovery.assert_protected_status(&configurations)).await;
            // Keep the exact pre-activation database selection and request clock.
            // Target activation never upgrades this original source response fence.
            assert!(source_release.check_release().is_err());
        }
        // The planned coordinator must retain actual source custody retirement,
        // independently from the issuer's fencing and the target activation.
        tokio::time::timeout(Duration::from_secs(20), async {
            while !databases.iter().all(|db| {
                kasumi_raft::ControlLog::installed(
                    db.raft_group().storage_domains().custody().clone(),
                )
                .ok()
                .flatten()
                .is_some_and(|control| control.is_retired().unwrap_or(false))
            }) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let context = fixture_operation(|| recovery.context(true)).await;
        tokio::time::timeout(Duration::from_secs(20), async {
            while !registries.iter().all(|registry| {
                registry
                    .database(&context)
                    .ok()
                    .and_then(|database| database.engine().generation().ok())
                    .is_some_and(|generation| {
                        generation.state.incarnation == incarnation.to_string()
                    })
            }) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let restored_databases = fixture_operation(|| recovery.databases()).await;
        let activation_facts = restored_databases
            .iter()
            .map(|database| {
                let generation = database.engine().generation().unwrap();
                let execution = generation
                    .state
                    .target_lifecycle
                    .get(&generation.state.incarnation)
                    .cloned()
                    .unwrap();
                assert_eq!(
                    execution.origin.materialization.request.source_incarnation,
                    source_incarnation
                );
                assert!(execution.completion.is_some() && execution.activation.is_some());
                execution
            })
            .collect::<Vec<_>>();
        for manager in &managers {
            let status = manager
                .execute_for_test(context.clone(), M::Status {})
                .await
                .unwrap();
            assert_eq!(status["incarnation"], incarnation.to_string());
            assert!(status["pending_restore"].is_null());
            assert_eq!(status["observation"], "local_committed_state");
            assert!(
                manager
                    .prepare(source_context.clone(), M::Status {})
                    .is_err()
            );
        }
        let (resumed_leader, ()) = fixture_operation(|| {
            on_quorum_leader(&restored_databases, "resume restored tenant", |index| {
                let context = context.clone();
                let restored = &restored_databases[index];
                async move {
                    // Resolve an uncertain resume from quorum-committed state before
                    // issuing another administrative operation.
                    if restored.engine().generation()?.state.suspended {
                        restored
                            .administer(context, Operation::Suspend(false))
                            .await?;
                    }
                    Ok(())
                }
            })
        })
        .await;
        let restored = registries[resumed_leader].database(&context).unwrap();
        let (_, document) = fixture_operation(|| {
            on_quorum_leader(&restored_databases, "read restored document", |index| {
                restored_databases[index].get(&context, "docs", "a")
            })
        })
        .await;
        assert_eq!(document.body["durable"], serde_json::json!(true));
        assert!(
            databases[leader]
                .get(&source_context, "docs", "a")
                .await
                .is_err()
        );
        for registry in &registries {
            assert!(registry.database(&source_context).is_err());
        }
        drop(restored);
        drop(restored_databases);
        let target_drain_failures = fixture_operation(|| recovery.drain_targets()).await;
        // The terminal three-node recovery has already proved every voter
        // confirmed and the restored document is readable. A final
        // confirmation may still leave one timed-out call response in local
        // custody; require its exact shutdown diagnostic. Other fixture modes
        // and all other shutdown issues remain failures.
        assert!(
            target_drain_failures.len() <= usize::from(canonical),
            "unexpected target drain failures: {target_drain_failures:?}"
        );
        for (index, failure) in &target_drain_failures {
            assert!(*index < 3, "unexpected target drain node: {failure:?}");
            assert_eq!(
                failure.completion(),
                kasumi_types::drain::DrainCompletion::Complete,
                "target drain retained an owner: {failure:?}"
            );
            assert_eq!(
                failure.issues().len(),
                1,
                "target drain issues: {failure:?}"
            );
            let issue = &failure.issues()[0];
            assert_eq!(issue.component(), "abandoned target call");
            assert_eq!(
                issue.error().to_string(),
                "backup verification deadline expired",
                "unexpected abandoned target call: {failure:?}"
            );
        }
        for stop in &stops {
            stop.send_replace(true);
        }
        for task in tasks {
            tokio::time::timeout(Duration::from_secs(15), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        for database in databases {
            assert!(database.engine().generation().is_err());
        }
        recovery_handles.clear();
        cluster_networks.clear();
        managers.clear();
        controls.clear();
        registries.clear();
        assert!(
            first_facades
                .iter()
                .all(|facade| facade.upgrade().is_none()),
            "the first runtime facade generation remains physically retained"
        );
        first_facades.clear();
        // Reopening from original operator bootstrap must follow the durable
        // replacement route, never silently resurrect the retired source.
        let mut second_tasks = Vec::new();
        let mut second_stops = Vec::new();
        let mut second_registries = Vec::new();
        let beta_incarnation = uuid::Uuid::new_v4().to_string();
        let mismatched_incarnation = uuid::Uuid::new_v4().to_string();
        let mut second_managers = Vec::new();
        let mut second_controls = Vec::new();
        let mut second_recovery_handles = Vec::new();
        fixture_operation(|| {
            recovery.enroll_tenant("beta", Uuid::parse_str(&beta_incarnation).unwrap())
        })
        .await;
        fixture_operation(|| {
            recovery.enroll_tenant(
                "mismatched",
                Uuid::parse_str(&mismatched_incarnation).unwrap(),
            )
        })
        .await;
        // This remains a release assertion, not an ignored case: strict startup
        // must support explicit dormant tenant enrollment before these new
        // catalogs can be opened. The production enrollment path is a remaining
        // prerequisite; this fixture must never recreate missing catalogs itself.
        for (index, mut config) in configurations.into_iter().enumerate() {
            config
                .replication
                .as_mut()
                .unwrap()
                .peers
                .push(ReplicaConfig {
                    node_id: 44,
                    endpoint: "https://localhost:1".into(),
                    certificate_pins: vec!["ab".repeat(32)],
                    failure_domain: "approved-future-zone".into(),
                });
            config.tenants.push(staged_config(
                &config.tenants[0],
                "beta",
                beta_incarnation.clone(),
            ));
            let mut mismatched = staged_config(
                &config.tenants[0],
                "mismatched",
                mismatched_incarnation.clone(),
            );
            if index == 2 {
                mismatched.initial_limits.max_documents -= 1;
            }
            config.tenants.push(mismatched);
            let runtime = open_replicated_fixture_node(config, file_secret, storage.clone())
                .await
                .unwrap();
            for tenant in ["beta", "mismatched"] {
                assert!(
                    crate::node_enrollment::tenant_record(runtime.audit.store(), tenant)
                        .unwrap()
                        .is_none()
                );
                assert!(
                    !kasumi_store::CustodyStore::catalog_installed(
                        &runtime
                            .administration
                            .as_ref()
                            .unwrap()
                            .node_for_enrollment_test(),
                        tenant
                    )
                    .unwrap()
                );
            }
            second_recovery_handles.push(recovery_fixture::Handles::capture(&runtime));
            second_registries.push(runtime.registry.clone());
            second_managers.push(runtime.administration.clone().unwrap());
            second_controls.push(runtime.control.database.clone());
            let (stop, shutdown) = watch::channel(false);
            second_stops.push(stop);
            second_tasks.push(tokio::spawn(runtime.serve(shutdown)));
        }
        fixture_operation(|| recovery.reopen_targets(&second_recovery_handles)).await;
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                for task in &mut second_tasks {
                    if task.is_finished() {
                        panic!("restarted runtime exited: {:?}", task.await);
                    }
                }
                let mut ready = true;
                for registry in &second_registries {
                    ready &= registry.database(&context).is_ok_and(|db| {
                        db.engine()
                            .generation()
                            .is_ok_and(|g| g.state.incarnation == incarnation.to_string())
                    });
                }
                if ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .unwrap();
        for (index, registry) in second_registries.iter().enumerate() {
            assert!(registry.database(&source_context).is_err());
            let database = registry.database(&context).unwrap();
            assert_eq!(
                database
                    .engine()
                    .generation()
                    .unwrap()
                    .state
                    .target_lifecycle
                    .get(&incarnation.to_string()),
                Some(&activation_facts[index])
            );
            let status = second_managers[index]
                .execute_for_test(context.clone(), M::Status {})
                .await
                .unwrap();
            assert_eq!(status["incarnation"], incarnation.to_string());
            assert!(status["pending_restore"].is_null());
        }
        let recovered = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                for registry in &second_registries {
                    let db = registry.database(&context).unwrap();
                    if let Ok(doc) = db.get(&context, "docs", "a").await {
                        return doc;
                    }
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(recovered.body["durable"], serde_json::json!(true));
        let operator = control_context(&fixture_config().control.initial_policy).unwrap();
        assert!(
            second_managers[0]
                .execute_for_test(
                    context.clone(),
                    M::ApprovePeerPool {
                        expected_topology_version: 0
                    }
                )
                .await
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                for (manager, control) in second_managers.iter().zip(&second_controls) {
                    let metrics = control.raft_group().raft().metrics().borrow().clone();
                    if metrics.current_leader == Some(metrics.id)
                        && let Ok(Some(topology)) =
                            kasumi_engine::control::ControlPlane::new(control.clone())
                                .unwrap()
                                .topology(&operator)
                                .await
                    {
                        if topology.topology.nodes.contains_key(&44) {
                            return;
                        }
                        assert!(
                            manager
                                .execute_for_test(
                                    operator.clone(),
                                    M::ApprovePeerPool {
                                        expected_topology_version: 0
                                    }
                                )
                                .await
                                .is_err()
                        );
                        if manager
                            .execute_for_test(
                                operator.clone(),
                                M::ApprovePeerPool {
                                    expected_topology_version: topology.version,
                                },
                            )
                            .await
                            .is_ok()
                        {
                            return;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        fixture_operation(|| {
            exercise_provisioning(
                &second_managers,
                &second_controls,
                &second_registries,
                operator.clone(),
            )
        })
        .await;
        // Approving one replica's immutable configuration cannot authorize a
        // differently configured voter or create a partial two-voter group.
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                for (manager, control) in second_managers.iter().zip(&second_controls) {
                    let metrics = control.raft_group().raft().metrics().borrow().clone();
                    if metrics.current_leader == Some(metrics.id)
                        && manager
                            .execute_for_test(
                                operator.clone(),
                                M::ApproveTenant {
                                    tenant: "mismatched".into(),
                                },
                            )
                            .await
                            .is_ok()
                    {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut rejected = 0;
        for manager in &second_managers {
            if manager
                .execute_for_test(
                    operator.clone(),
                    M::PrepareTenant {
                        tenant: "mismatched".into(),
                    },
                )
                .await
                .is_err()
            {
                rejected += 1;
            }
        }
        assert!(rejected > 0);
        assert!(
            second_managers[0]
                .execute_for_test(
                    operator.clone(),
                    M::InitializeTenant {
                        tenant: "mismatched".into()
                    }
                )
                .await
                .is_err()
        );
        for registry in &second_registries {
            assert!(
                registry
                    .database(&RequestContext {
                        tenant: "mismatched".into(),
                        ..operator.clone()
                    })
                    .is_err()
            );
            assert!(registry.database(&context).is_ok());
        }
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                for registry in &second_registries {
                    if let Ok(document) = registry
                        .database(&context)
                        .unwrap()
                        .get(&context, "docs", "a")
                        .await
                    {
                        assert_eq!(document.body["durable"], serde_json::json!(true));
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        fixture_operation(|| recovery.close_targets()).await;
        for stop in &second_stops {
            stop.send_replace(true);
        }
        for task in second_tasks {
            tokio::time::timeout(Duration::from_secs(15), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        second_recovery_handles.clear();
        // Release the issuer only after every source/target renewal owner drains.
        // Its retained activation is reused on restart, never synthesized again.
        fixture_operation(|| recovery.shutdown_issuer()).await;
        mock_stop.send_replace(true);
        mock.await.unwrap().unwrap();
    }
}

/// Open only the installed source's original consensus identity. The persisted
/// deployment binding prevents configuration from downgrading replication.
pub(crate) async fn open_retired_source(
    config: &RuntimeConfig,
    store: Arc<kasumi_store::CustodyStore>,
    cluster: Option<&Arc<ClusterNetwork>>,
    audit: Arc<SecurityAudit>,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
) -> Result<Arc<kasumi_engine::RetiredCustody>> {
    // Every production caller runs inside an already retained startup or
    // reconciliation task. Keep this nested inventory outside the caught future;
    // never register a task in its parent's global startup registry.
    let mut pending = crate::startup_resources::Resources::default();
    let outcome = crate::startup_preparation::capture("retired custody", async {
        let snapshot_limit = if store.binding().tenant() == CONTROL_TENANT {
            config.control.initial_limits.max_snapshot_bytes
        } else {
            config
                .tenants
                .iter()
                .find(|tenant| tenant.tenant == store.binding().tenant())
                .context("retired source lacks installed capacity settings")?
                .initial_limits
                .max_snapshot_bytes
        };
        let control = kasumi_raft::ControlLog::installed(store.clone())?
            .context("installed custody consensus absent")?;
        let group = control.group().to_owned();
        let id = control.node_id();
        let binding = store
            .store()
            .get("engine.deployment", b"mode")?
            .context("custody deployment binding absent")?;
        if let Some(replication) = &config.replication {
            let (mode, bootstrap): (String, ReplicatedBootstrap) =
                serde_json::from_slice(&binding)?;
            bootstrap.validate()?;
            ensure!(
                mode == "replicated"
                    && id == replication.node_id
                    && group == format!("{}/{}", store.binding().tenant(), bootstrap.incarnation),
                "custody deployment differs from installed replication"
            );
            let network = cluster.context("custody peer transport absent")?;
            let fingerprint = retired_custody_bootstrap_fingerprint(&store, &binding)?;
            let access = store.store().clone();
            let custody = kasumi_engine::RetiredCustody::open_replicated(
                store,
                id,
                group.clone(),
                network.clone(),
                kasumi_raft::RaftGroupConfig {
                    raft: kasumi_raft::server_config(),
                    limits: kasumi_raft::RaftLimits {
                        max_snapshot_bytes: snapshot_limit,
                    },
                },
                admission,
                audit,
            )
            .await?;
            pending.custodies.push(custody.clone());
            #[cfg(test)]
            {
                crate::startup_preparation::checkpoint(config.database_id, "retired-custody-owner");
                retired_source_tests::after_open(config.database_id, &custody).await?;
            }
            network.register_group_with_bootstrap(
                group,
                custody
                    .raft_group()
                    .context("closed custody group absent")?
                    .raft()
                    .clone(),
                replication.peers.iter().map(|peer| peer.node_id).collect(),
                fingerprint,
                Arc::new(move || access.check_access()),
            )?;
            Ok(custody)
        } else {
            ensure!(
                binding == b"local-v1" && id == 1,
                "replicated custody cannot use local transport"
            );
            let router = Arc::new(kasumi_raft::InProcessRouter::default());
            let custody = kasumi_engine::RetiredCustody::open_replicated(
                store,
                id,
                group.clone(),
                router.clone(),
                kasumi_raft::RaftGroupConfig {
                    raft: kasumi_raft::Config::default(),
                    limits: kasumi_raft::RaftLimits {
                        max_snapshot_bytes: snapshot_limit,
                    },
                },
                admission,
                audit,
            )
            .await?;
            pending.custodies.push(custody.clone());
            #[cfg(test)]
            {
                crate::startup_preparation::checkpoint(config.database_id, "retired-custody-owner");
                retired_source_tests::after_open(config.database_id, &custody).await?;
            }
            router.register(
                group,
                id,
                custody
                    .raft_group()
                    .context("closed custody group absent")?
                    .raft()
                    .clone(),
            );
            Ok(custody)
        }
    })
    .await;
    match outcome {
        Ok(custody) => Ok(custody),
        Err(error) => {
            // Returning an error permits callers to publish RecoveringControl.
            // This must wait for Complete, including retained-child retries.
            match crate::startup_owner::finish(&mut pending).await {
                Ok(()) => Err(error),
                Err(drain) => Err(error.context(drain)),
            }
        }
    }
}

#[cfg(test)]
#[path = "runtime_retired_source_tests.rs"]
mod retired_source_tests;

#[cfg(test)]
#[path = "runtime_audit_tests.rs"]
mod audit_tests;

#[cfg(test)]
#[path = "runtime_observability_tests.rs"]
mod observability_tests;

impl crate::startup_owner::Runtime for NodeRuntime {
    fn close(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kasumi_types::drain::DrainResult> + Send + '_>,
    > {
        Box::pin(NodeRuntime::shutdown(self))
    }
}
