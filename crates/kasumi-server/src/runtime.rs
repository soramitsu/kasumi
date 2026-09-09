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
use kasumi_types::{Action, Grant, Limits, Policy, Precondition, RequestContext};
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
            Self::File { path } => Ok(kasumi_store::FileKeyProvider::open(path)?.key_ref().into()),
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
            )?) as Arc<dyn kasumi_store::AuditArchiveDestination>,
            Some(config) => config.open()?,
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
    #[serde(default)]
    pub initial_voters: BTreeSet<u64>,
    pub node_id: u64,
    pub listener: MutualTlsEndpoint,
    pub peers: Vec<ReplicaConfig>,
}

fn default_prepared_limit() -> usize {
    2
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
    #[serde(default = "default_prepared_limit")]
    pub max_prepared_generations_per_tenant: usize,
    #[serde(default)]
    pub admission: kasumi_engine::admission::AdmissionConfig,
    #[serde(default)]
    pub backup_destinations: BTreeMap<String, crate::administration::DestinationConfig>,
    pub format: u32,
    pub mode: DeploymentMode,
    pub database_path: PathBuf,
    pub database_id: Uuid,
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
    /// Explicit node and service-audit enrollment for HA. Application and
    /// Control catalogs/bootstrap require their own installation operation.
    pub async fn provision_node_file(&self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.mode == DeploymentMode::Replicated,
            "standalone installation requires kasumid init"
        );
        crate::node_provision::create(
            &self.database_path,
            self.database_id,
            &self.scratch_disk,
            &self.security_audit,
            kasumi_engine::admission::NodeAdmission::new(self.admission.clone())?,
        )
        .await
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
        ensure!(
            (1..=16).contains(&self.max_prepared_generations_per_tenant),
            "prepared generation limit must be 1..16"
        );
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
    pub(crate) fn voters(&self) -> Result<BTreeSet<u64>> {
        let voters = if self.initial_voters.is_empty() && self.peers.len() == 3 {
            self.peers.iter().map(|p| p.node_id).collect()
        } else {
            self.initial_voters.clone()
        };
        ensure!(
            voters.len() == 3
                && voters
                    .iter()
                    .all(|id| self.peers.iter().any(|p| p.node_id == *id)),
            "initial membership requires exactly three configured voters"
        );
        Ok(voters)
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

/// Listeners own their connection tasks. They must receive shutdown and finish
/// their own bounded connection drain, including while startup is incomplete.
/// Canceling an outer listener task would detach those nested owners instead.
struct ServingTasks {
    listeners: JoinSet<Result<()>>,
    maintenance: JoinSet<Result<()>>,
    data_stop: watch::Sender<bool>,
    cluster_stop: watch::Sender<bool>,
}

impl ServingTasks {
    fn new() -> Self {
        Self {
            listeners: JoinSet::new(),
            maintenance: JoinSet::new(),
            data_stop: watch::channel(false).0,
            cluster_stop: watch::channel(false).0,
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.data_stop.send_replace(true);
        self.cluster_stop.send_replace(true);
        // Reconciliation may be rebuilding an admitted tenant and own Raft or
        // storage workers. Signal its loop and join the current operation before
        // taking the final generation inventory; cancellation could detach work.
        let mut failure = None;
        while let Some(result) = self.maintenance.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Err(error) if error.is_cancelled() => {}
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Err(error) => {
                    failure.get_or_insert(error.into());
                }
            }
        }
        while let Some(result) = self.listeners.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Err(error) => {
                    failure.get_or_insert(error.into());
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

pub struct NodeRuntime {
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
    administration: Option<Arc<crate::administration::Administration>>,
    target_recovery: Option<Arc<crate::target_runtime::TargetRecoveryRuntime>>,
    tls_reload: Option<crate::tls_reload::RuntimeTlsReload>,
    _standalone_lock: Option<kasumi_store::private_files::ExclusiveLock>,
    #[cfg(test)]
    audit_release_gate: Arc<tokio::sync::Mutex<Option<crate::rpc::AuditReleaseGate>>>,
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
        let standalone_lock = crate::standalone::claim(&config)?;
        let existing_standalone = standalone_lock.is_some();
        let scratch_disk = kasumi_store::ScratchDisk::open(config.scratch_disk.clone())?;
        let credential = Arc::new(credential);
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
                    .open(domains, credential.clone(), scratch_disk.clone())
                    .await?,
            )
        } else {
            None
        };
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
        let admission = kasumi_engine::admission::NodeAdmission::new(config.admission.clone())?;
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
            .map(|(name, destination)| Ok((name.clone(), destination.open()?)))
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
            scratch_disk.clone(),
        )?;
        let security_store = TenantStore::open_existing(
            node.clone(),
            SECURITY_TENANT.into(),
            security_provider,
            kasumi_store::StorageAccess::security_audit(),
        )
        .await?;
        if config.mode == DeploymentMode::Standalone
            && let Err(error) = crate::local_recovery::require_runtime_ready(&security_store)
        {
            security_store.shutdown().await;
            return Err(error);
        }
        let audit = config
            .security_audit
            .open(security_store, admission.clone())?;
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
            let control_stores = if existing_standalone {
                TenantStorageSet::open_existing(
                    node.clone(),
                    CONTROL_TENANT.into(),
                    control_provider.clone(),
                    control_custody_provider.clone(),
                    kasumi_store::StorageAccess::node_control(),
                )
                .await?
            } else {
                TenantStorageSet::open(
                    node.clone(),
                    CONTROL_TENANT.into(),
                    control_provider.clone(),
                    control_custody_provider.clone(),
                    kasumi_store::StorageAccess::node_control(),
                )
                .await?
            };
            let control_bootstrap = config.bootstrap(
                &config.control.initial_policy,
                &config.control.initial_limits,
                config.control.incarnation.as_deref(),
            )?;
            Self::open_database(
                &config,
                control_stores,
                config.control.initial_policy.clone(),
                config.control.initial_limits.clone(),
                control_bootstrap,
                config.control.incarnation.as_deref(),
                cluster.as_ref(),
                audit.clone(),
            )
            .await
        }
        .await;
        let control = match control {
            Ok(control) => control,
            Err(error) => {
                audit.shutdown().await;
                return Err(error);
            }
        };
        control.database.install_admission(admission.clone())?;
        let mut runtime = Self {
            telemetry: crate::observability::Telemetry::new(),
            _standalone_lock: standalone_lock,
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
            #[cfg(test)]
            audit_release_gate: Arc::new(tokio::sync::Mutex::new(None)),
            administration: None,
            target_recovery: None,
            tls_reload: None,
        };
        let result = async {
            let mut managed = vec![crate::administration::ManagedTenant {
                database: runtime.control.database.clone(),
                store: runtime.control.store.clone(),
                provider: control_provider,
                custody_provider: control_custody_provider,
                bootstrap: runtime.control.bootstrap.clone(),
                descriptor: None,
                lease: None,
            }];
            for configured_tenant in &config.tenants {
                let active = if config.mode == DeploymentMode::Standalone {
                    crate::local_recovery::active_generation(&config, runtime.audit.store(), &configured_tenant.tenant)?
                } else { None };
                let mut tenant = configured_tenant.clone();
                let tenant_node = match &active {
                    Some(active) => {
                        tenant.incarnation = Some(active.incarnation.to_string());
                        NodeStore::open_existing(active.directory.join("node.redb"), active.database_id(&config, &tenant.tenant)?, scratch_disk.clone())?
                    }
                    None => node.clone(),
                };
                let custody_provider = tenant.custody_keys.provider(credential.clone())?;
                if kasumi_store::CustodyStore::catalog_installed(&tenant_node, &tenant.tenant)? {
                    let custody_store = kasumi_store::CustodyStore::open(tenant_node.clone(), tenant.tenant.clone(), custody_provider.clone()).await?;
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
                            registry.install_retirement_source(source.clone())?;
                            runtime.custody_sources.push(OpenedCustody { tenant: tenant.tenant.clone(), incarnation, source, store: custody_store });
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
                let stores = if existing_standalone {
                    TenantStorageSet::open_existing(tenant_node.clone(), tenant.tenant.clone(),
                        provider.clone(), custody_provider.clone(), storage_access).await?
                } else {
                    TenantStorageSet::open(tenant_node.clone(), tenant.tenant.clone(),
                        provider.clone(), custody_provider.clone(), storage_access).await?
                };
                let bootstrap = config.bootstrap(
                    &tenant.initial_policy,
                    &tenant.initial_limits,
                    tenant.incarnation.as_deref(),
                )?;
                let opened = Self::open_database(
                    &config,
                    stores,
                    tenant.initial_policy.clone(),
                    tenant.initial_limits.clone(),
                    bootstrap,
                    tenant.incarnation.as_deref(),
                    runtime.cluster.as_ref(),
                    runtime.audit.clone(),
                )
                .await?;
                if let Some(active) = active {
                    let generation = opened.database.engine().generation()?;
                    if generation.state.restored_from.as_ref() != Some(&active.checkpoint) || generation.state.pending_restore.is_some() {
                        opened.database.shutdown().await?;
                        anyhow::bail!("active standalone generation is incomplete or differs from its committed checkpoint");
                    }
                }
                opened.database.install_admission(admission.clone())?;
                managed.push(crate::administration::ManagedTenant {
                    database: opened.database.clone(),
                    store: opened.store.clone(),
                    provider,
                    custody_provider,
                    bootstrap: opened.bootstrap.clone(),
                    descriptor: None,
                    lease,
                });
                runtime.tenants.push(opened);
            }
            let provider_factories = config.tenants.iter().map(|tenant| {
                let application = tenant.keys.clone();
                let custody = tenant.custody_keys.clone();
                let credential = credential.clone();
                let factory: crate::administration::ProviderFactory = Arc::new(move || {
                    let application: Arc<dyn kasumi_store::KeyProvider> = application.provider(credential.clone())?;
                    let custody: Arc<dyn kasumi_store::KeyProvider> = custody.provider(credential.clone())?;
                    Ok((application, custody))
                });
                (tenant.tenant.clone(), factory)
            }).collect();
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
                provider_factories,
                credential.clone(),
            )?;
            if let Some(network) = &runtime.cluster {
                let provider: Arc<dyn crate::cluster::RestoreReadinessProvider> =
                    administration.clone();
                network.install_restore_readiness(Arc::downgrade(&provider))?;
            }
            runtime.administration = Some(administration.clone());
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
        if let Err(error) = result {
            let _ = runtime.shutdown().await;
            return Err(error);
        }
        Ok(runtime)
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_database(
        config: &RuntimeConfig,
        stores: Arc<TenantStorageSet>,
        policy: Policy,
        limits: Limits,
        bootstrap: Option<ReplicatedBootstrap>,
        installed_incarnation: Option<&str>,
        cluster: Option<&Arc<ClusterNetwork>>,
        audit: Arc<SecurityAudit>,
    ) -> Result<OpenedTenant> {
        let retained_stores = stores.clone();
        let opened = async {
            let store = stores.application().clone();
            config.install_tenant_audit_archive(&store, None)?;
            let database = if let Some(bootstrap) = &bootstrap {
                let replication = config
                    .replication
                    .as_ref()
                    .context("replication configuration missing")?;
                let network = cluster.context("cluster transport missing")?;
                let database = kasumi_engine::open_replicated(
                    replication.node_id,
                    stores.clone(),
                    bootstrap,
                    network.clone(),
                    kasumi_raft::server_config(),
                    audit,
                )
                .await?;
                let group = format!("{}/{}", store.tenant(), bootstrap.incarnation);
                let fingerprint = persisted_bootstrap_fingerprint(&store)?;
                let bootstrap_store = store.clone();
                if let Err(error) = network.register_group_with_bootstrap(
                    group,
                    database.raft_group().raft().clone(),
                    replication.peers.iter().map(|peer| peer.node_id).collect(),
                    fingerprint,
                    Arc::new(move || bootstrap_store.check_access()),
                ) {
                    let _ = database.shutdown().await;
                    return Err(error);
                }
                database
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
            Ok(OpenedTenant {
                database,
                store,
                bootstrap,
            })
        }
        .await;
        if opened.is_err() {
            retained_stores.application().shutdown().await;
            retained_stores.custody().store().shutdown().await;
        }
        opened
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
    pub async fn serve(mut self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        if *shutdown.borrow() {
            return self.shutdown().await;
        }
        let mut tasks = ServingTasks::new();
        if let Some(listener) = self.cluster_listener.take() {
            tasks.listeners.spawn(tls::serve_tls(
                listener.listener,
                listener.tls,
                listener.router,
                ListenerLimits::default(),
                self.audit.clone(),
                tasks.cluster_stop.subscribe(),
            ));
        }
        let startup=async {
            tokio::select! { result=self.initialize_original(&self.control)=>result?, _=shutdown.changed()=>return Ok(false) };
            let ready=tokio::select! { result=self.publish_control()=>result?, _=shutdown.changed()=>false };
            if !ready { return Ok(false); }
            if let Some(manager)=&self.administration {
                let topology = manager.committed_topology()?;
                for tenant in &self.tenants {
                    // Configuration may contain staged tenants. Only a durable
                    // route authorizes starting its original group automatically.
                    if topology.tenants.contains_key(tenant.store.tenant()) {
                        tokio::select! { result=self.initialize_original(tenant)=>result?, _=shutdown.changed()=>return Ok(false) };
                    }
                }
                manager.reconcile().await?;
            }
            self.audit.record(lifecycle(SecurityEventKind::NodeStarted)).await?;
            Ok::<_,anyhow::Error>(true)
        }.await;
        if let Err(error) = startup {
            let _ = tasks.shutdown().await;
            let _ = self.shutdown().await;
            return Err(error);
        }
        if matches!(startup, Ok(false)) {
            let drain = tasks.shutdown().await;
            let cleanup = self.shutdown().await;
            return drain.and(cleanup);
        }
        self.telemetry
            .set_lifecycle(crate::observability::Lifecycle::Serving);
        for listener in self.data_listeners.drain(..) {
            tasks.listeners.spawn(tls::serve_tls(
                listener.listener,
                listener.tls,
                listener.router,
                ListenerLimits::default(),
                self.audit.clone(),
                tasks.data_stop.subscribe(),
            ));
        }
        if let Some(manager) = self.administration.clone() {
            let mut stop = tasks.data_stop.subscribe();
            tasks.maintenance.spawn(async move { loop { tokio::select! { _=stop.changed()=>return Ok(()), _=tokio::time::sleep(Duration::from_millis(250))=>{ if manager.reconcile().await.is_err() { tracing::warn!("serving reconciliation unavailable; will retry"); } } } } });
        }
        let result = if *shutdown.borrow() {
            Ok(())
        } else {
            tokio::select! {
                _=shutdown.changed()=>Ok(()),
                result=tasks.listeners.join_next()=> match result { Some(Ok(Err(error)))=>Err(error),Some(Err(error))=>Err(error.into()),_=>Err(anyhow::anyhow!("required listener stopped unexpectedly")) },
                result=tasks.maintenance.join_next(), if !tasks.maintenance.is_empty()=> match result { Some(Ok(Err(error)))=>Err(error),Some(Err(error))=>Err(error.into()),_=>Err(anyhow::anyhow!("required reconciliation stopped unexpectedly")) },
            }
        };
        self.telemetry
            .set_lifecycle(crate::observability::Lifecycle::Draining);
        let drain = tasks.shutdown().await;
        let cleanup = self.shutdown().await;
        result.and(drain).and(cleanup)
    }

    fn expected_topology(&self) -> Result<kasumi_engine::control::ControlTopology> {
        use kasumi_engine::control::{
            ControlNode, ControlTopology, DeploymentMode as Mode, TenantRoute,
        };
        let (nodes, voters, mode) = if let Some(replication) = &self.config.replication {
            (
                replication
                    .peers
                    .iter()
                    .map(|peer| {
                        (
                            peer.node_id,
                            ControlNode {
                                endpoint: origin(&peer.endpoint)
                                    .expect("validated endpoint")
                                    .to_string(),
                                failure_domain: peer.failure_domain.clone(),
                                certificate_pins: peer
                                    .certificate_pins
                                    .iter()
                                    .map(|pin| pin.to_ascii_lowercase())
                                    .collect(),
                            },
                        )
                    })
                    .collect(),
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
        use kasumi_engine::control::{ControlPlane, ControlTopology};
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
                    if self._standalone_lock.is_some() {
                        plane.require_initialized(&context).await?;
                    } else {
                        plane.initialize(context.clone()).await?;
                    }
                    if let Some(current) = plane.topology(&context).await? {
                        validate_configured_topology(&current.topology, &expected)?;
                    } else {
                        ensure!(
                            self._standalone_lock.is_none(),
                            "provisioned standalone topology is missing"
                        );
                        plane
                            .replace_topology(
                                context.clone(),
                                expected.clone(),
                                Precondition::Absent,
                                "runtime-topology-bootstrap".into(),
                            )
                            .await?;
                    }
                    crate::lifecycle_runtime::publish(
                        &self.control.database,
                        &context,
                        self.config.control.lifecycle.as_ref(),
                    )
                    .await?;
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
            } else {
                // A follower may activate its data endpoint only after its own
                // committed control state has applied the expected signed topology.
                // It never manufactures a quorum read or initializes membership.
                let generation = self.control.database.engine().generation()?;
                if let Some(document) = generation
                    .state
                    .collections
                    .get("topology")
                    .and_then(|collection| collection.documents.get("current"))
                {
                    let current: ControlTopology = serde_json::from_value(document.body.clone())?;
                    current.validate()?;
                    validate_configured_topology(&current, &expected)?;
                    if crate::lifecycle_runtime::applied(
                        &generation.state,
                        self.config.control.lifecycle.as_ref(),
                    )? {
                        return Ok(true);
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        if !self.closed {
            self.telemetry
                .set_lifecycle(crate::observability::Lifecycle::Draining);
        }
        crate::target_runtime::shutdown_target(&mut self.target_recovery).await?;
        if self.closed {
            return Ok(());
        }
        let audit = self
            .audit
            .record(lifecycle(SecurityEventKind::NodeStopping))
            .await;
        let mut failure = audit.err();
        for lease in &self.serving_leases {
            lease.close();
        }
        for lease in &self.serving_leases {
            if let Err(error) = lease.shutdown().await {
                failure.get_or_insert(error);
            }
        }
        if let Some(manager) = &self.administration {
            manager.shutdown().await;
        }
        for tenant in std::iter::once(&self.control).chain(self.tenants.iter()) {
            let _ = self.registry.remove(tenant.store.tenant());
            if let (Some(cluster), Some(bootstrap)) = (&self.cluster, &tenant.bootstrap) {
                let _ = cluster.unregister_group(&format!(
                    "{}/{}",
                    tenant.store.tenant(),
                    bootstrap.incarnation
                ));
            }
            if let Err(error) = tenant.database.shutdown().await {
                failure.get_or_insert(error);
            }
        }
        for source in &self.custody_sources {
            if let Some(cluster) = &self.cluster {
                let _ =
                    cluster.unregister_group(&format!("{}/{}", source.tenant, source.incarnation));
            }
            if let kasumi_engine::InstalledRetirementSource::RetiredCustody(custody) =
                &source.source
            {
                if let Err(error) = custody.shutdown().await {
                    failure.get_or_insert(error);
                }
            } else {
                source.store.store().shutdown().await;
            }
        }
        self.audit.shutdown().await;
        if let Some(verifier) = &self.signer_verifier {
            verifier.shutdown().await;
        }
        self.closed = true;
        self.telemetry
            .set_lifecycle(crate::observability::Lifecycle::Closed);
        failure.map_or(Ok(()), Err)
    }
}
/// Called only after engine open has verified immutable bootstrap chunks against
/// this authenticated manifest. Bind the actual initial snapshot as well as its
/// deployment policy/membership, including restored documents and receipts.
pub(crate) fn persisted_bootstrap_fingerprint(store: &TenantStore) -> Result<String> {
    use sha2::{Digest, Sha256};
    let tenant = store.tenant();
    let binding = store
        .get("engine.deployment", b"mode")?
        .context("immutable deployment binding missing")?;
    let manifest: serde_json::Value = serde_json::from_slice(
        &store
            .get("engine.bootstrap", b"manifest")?
            .context("immutable bootstrap manifest missing")?,
    )?;
    let digest = manifest
        .get("digest")
        .and_then(|value| value.as_str())
        .context("bootstrap digest missing")?;
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
    hash.update(&binding);
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
        // Cancellation still closes key access. The explicit async path additionally
        // waits for Raft tasks and records graceful termination durably.
        if !self.closed {
            for tenant in std::iter::once(&self.control).chain(self.tenants.iter()) {
                tenant.database.engine().seal();
                tenant.store.seal();
            }
            self.audit.seal();
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
pub fn example_config() -> RuntimeConfig {
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
    RuntimeConfig {
        scratch_disk: kasumi_store::ScratchDiskConfig {
            directory: "/var/lib/kasumi/scratch".into(),
            max_bytes: 64 << 30,
            min_free_bytes: 256 << 20,
        },
        tenant_audit_archives: BTreeMap::new(),
        signer_verifier: Some(crate::signer_runtime::SignerVerifierConfig {
            identity: kasumi_serving::TrustVerifierIdentity {
                installation_id: uuid::Uuid::from_u128(7),
                node_id: 1,
            },
            database_path: PathBuf::from("/var/lib/kasumi/verifier/trust.redb"),
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
        max_prepared_generations_per_tenant: default_prepared_limit(),
        admission: kasumi_engine::admission::AdmissionConfig::default(),
        backup_destinations: BTreeMap::new(),
        mode: DeploymentMode::Replicated,
        database_path: "/var/lib/kasumi/node.redb".into(),
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
    }
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
    let mut config = example_config();
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
mod tests {
    use super::*;
    use kasumi_store::test_utils::{LocalKeyProvider, ManualClock};

    // A fixture must explicitly enroll its node file once. Runtime restarts only
    // open the retained configured identity and never create missing files.
    fn create_fixture_node(config: &RuntimeConfig) {
        drop(
            NodeStore::create_new(
                &config.database_path,
                config.database_id,
                kasumi_store::ScratchDisk::open(config.scratch_disk.clone()).unwrap(),
            )
            .unwrap(),
        );
    }

    #[test]
    fn operator_example_is_valid_secret_free_and_rejects_inline_credentials() {
        let config = example_config();
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
            initial_voters: BTreeSet::new(),
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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.redb");
        let node = NodeStore::create_new(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let keys = Arc::new(LocalKeyProvider::new([33; 32]));
        let clock = Arc::new(ManualClock::new());
        let service = TenantStore::open_fixture_with_clock(
            node.clone(),
            SECURITY_TENANT.into(),
            keys.clone(),
            clock.clone(),
        )
        .await
        .unwrap();
        let tenant = TenantStore::open_fixture_with_clock(
            node,
            "acme".into(),
            Arc::new(LocalKeyProvider::new([34; 32])),
            clock.clone(),
        )
        .await
        .unwrap();
        let audit = SecurityAudit::open(
            service.clone(),
            kasumi_types::AuditRetentionBudget::default(),
            kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
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
        audit.shutdown().await;
        drop(audit);
        drop(service);
        drop(tenant);
        let service = TenantStore::open_fixture_with_clock(
            NodeStore::open_existing(
                &path,
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )
            .unwrap(),
            SECURITY_TENANT.into(),
            keys,
            clock,
        )
        .await
        .unwrap();
        let audit = SecurityAudit::open(
            service.clone(),
            kasumi_types::AuditRetentionBudget::default(),
            kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
        )
        .unwrap();
        assert!(
            audit
                .record(lifecycle(SecurityEventKind::NodeStarted))
                .await
                .is_ok()
        );
        assert_eq!(service.scan("security.audit").unwrap().len(), 4);
    }

    #[cfg(unix)]
    #[test]
    fn private_key_file_permissions_are_checked_on_opened_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
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
    // so unrelated redb/TLS bootstrap storms do not consume their test deadlines.
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
            "finished"
        }

        // Startup failure/cancellation drain only the cluster listener; ordinary
        // serving shutdown also drains data listeners and joins reconciliation.
        for startup in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("listener.redb");
            let node = NodeStore::create_new(
                &path,
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )
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
            tasks.listeners.spawn(tls::serve_tls(
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
            drop(
                NodeStore::open_existing(
                    &path,
                    kasumi_store::test_utils::NODE_STORE_ID,
                    kasumi_store::ScratchDisk::fixture(),
                )
                .unwrap(),
            );
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
            assert!(manager.authorized_database(&beta).await.is_err());
            assert!(
                manager
                    .execute(
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
                    .execute(
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
                    .execute(
                        operator.clone(),
                        M::PrepareTenant {
                            tenant: tenant.into()
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
                    if metrics.current_leader == Some(metrics.id)
                        && manager
                            .execute(
                                operator.clone(),
                                M::ApproveTenant {
                                    tenant: tenant.into(),
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
        // Neither control approval nor one prepared replica publishes data.
        assert!(
            managers[0]
                .execute(
                    operator.clone(),
                    M::InitializeTenant {
                        tenant: tenant.into()
                    }
                )
                .await
                .is_err()
        );
        for (index, manager) in managers.iter().enumerate() {
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if manager
                        .execute(
                            operator.clone(),
                            M::PrepareTenant {
                                tenant: tenant.into(),
                            },
                        )
                        .await
                        .is_ok()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            assert!(registries[index].database(&beta).is_err());
            if index == 0 && managers.len() > 1 {
                assert!(
                    manager
                        .execute(
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
        managers[0]
            .execute(
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
                    .execute(
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
                                .execute(
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn local_runtime_opens_real_transit_tls_publishes_control_serves_and_reopens_durable_state()
     {
        let dir = tempfile::tempdir().unwrap();
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
        config.database_path = dir.path().join("node.redb");
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
                directory: dir.path().join("backups"),
                max_bytes: 32 << 20,
            },
        );
        create_fixture_node(&config);
        let mut incarnation = None;
        for round in 0..3 {
            let runtime = NodeRuntime::open_using(config.clone(), |_| {
                Ok(Zeroizing::new("test-runtime-token".into()))
            })
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
            if round == 1 {
                exercise_provisioning(
                    std::slice::from_ref(&manager),
                    std::slice::from_ref(&control),
                    std::slice::from_ref(&registry),
                    operator.clone(),
                )
                .await;
                // The already serving tenant remains usable during onboarding.
                assert!(database.get(&context, "docs", "first").await.is_ok());
            } else if round == 2 {
                let beta = RequestContext {
                    tenant: "beta".into(),
                    principal: "beta-admin".into(),
                    ..operator.clone()
                };
                let added = registry.database(&beta).unwrap();
                assert!(
                    added
                        .engine()
                        .generation()
                        .unwrap()
                        .state
                        .collections
                        .contains_key("onboarded")
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
                    .execute(
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
                    .execute(context.clone(), M::RotateDataKey)
                    .await
                    .unwrap();
                manager
                    .execute(context.clone(), M::RewrapKeys)
                    .await
                    .unwrap();
                database
                    .verify_backup_checkpoint_named(context.clone(), "primary", backup_id)
                    .await
                    .unwrap();
                let error = manager
                    .execute(
                        context.clone(),
                        M::PrepareRestore {
                            destination: "primary".into(),
                            backup_id,
                            incarnation: uuid::Uuid::new_v4(),
                        },
                    )
                    .await
                    .unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("stopped-installation local recovery coordinator")
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
                let command = M::Status { incarnation: None };
                let fence = manager.response_fence(&context, &command).unwrap();
                let _encoded =
                    serde_json::to_vec(&manager.execute(context.clone(), command).await.unwrap())
                        .unwrap();
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
                    kasumi_types::ErrorCode::Forbidden
                );
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
                let mut staged =
                    staged_config(&config.tenants[0], "beta", uuid::Uuid::new_v4().to_string());
                staged.incarnation = None;
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
    async fn replicated_runtime_fixture(with_spare: bool, bootstrap_fault: Option<BootstrapFault>) {
        let _fixture = LIFECYCLE_GATE.lock().await;
        let node_count = if with_spare { 4 } else { 3 };
        let dir = tempfile::tempdir().unwrap();
        let (mock_files, _) = certificate_files(dir.path());
        let mock_socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
        let incarnation = uuid::Uuid::new_v4().to_string();
        let control_incarnation = uuid::Uuid::new_v4().to_string();
        let mut configurations = Vec::new();
        for node in 0..node_count {
            let mut config = fixture_config();
            config.mode = DeploymentMode::Replicated;
            config.database_path = dir.path().join(format!("node{node}.redb"));
            config.scratch_disk.directory = dir.path().join(format!("scratch-{node}"));
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
                    directory: dir.path().join("backups"),
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
            create_fixture_node(&config);
            configurations.push(config);
        }
        drop(reserved);
        let context = RequestContext {
            authorization: kasumi_types::RequestAuthorization::service_identity(),
            principal: "acme-admin".into(),
            tenant: "acme".into(),
            scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
            request_id: uuid::Uuid::new_v4().to_string(),
        };
        if let Some(fault) = bootstrap_fault {
            let mut runtimes = Vec::new();
            let mut servers = Vec::new();
            let (stop, shutdown) = watch::channel(false);
            for config in configurations {
                let mut runtime = NodeRuntime::open_using(config, |_| {
                    Ok(Zeroizing::new("test-runtime-token".into()))
                })
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
        for config in configurations.iter().cloned() {
            let runtime = NodeRuntime::open_using(config, |_| {
                Ok(Zeroizing::new("test-runtime-token".into()))
            })
            .await
            .unwrap();
            registries.push(runtime.registry.clone());
            managers.push(runtime.administration.clone().unwrap());
            controls.push(runtime.control.database.clone());
            cluster_networks.push(runtime.cluster.clone().unwrap());
            let (stop, shutdown) = watch::channel(false);
            stops.push(stop);
            tasks.push(tokio::spawn(runtime.serve(shutdown)));
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
                                .execute(
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
        .await
        .unwrap();
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
        databases[leader]
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
        databases[leader]
            .mutate(
                context.clone(),
                MutationBatch {
                    read_set: Vec::new(),
                    idempotency_key: "replicated-runtime".into(),
                    operations: vec![Mutation::Put {
                        collection: "docs".into(),
                        id: "a".into(),
                        body: serde_json::json!({"durable":true}),
                        expected: Precondition::Absent,
                    }],
                },
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
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
        .await
        .unwrap();
        use crate::administration::ManagementCommand as M;
        if with_spare {
            managers[leader]
                .execute(context.clone(), M::AddLearner { node_id: 4 })
                .await
                .unwrap();
            let final_voters = BTreeSet::from([1, 2, 4]);
            assert!(
                managers[leader]
                    .execute(
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
            tokio::time::timeout(Duration::from_secs(45), async {
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
                        let _ = manager
                            .execute(
                                context.clone(),
                                M::ChangeMembership {
                                    voters: final_voters.clone(),
                                },
                            )
                            .await;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    for (manager, control) in managers.iter().zip(&controls) {
                        let metrics = control.raft_group().raft().metrics().borrow().clone();
                        if metrics.current_leader == Some(metrics.id)
                            && manager
                                .execute(
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
                                .execute(
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
        databases[leader]
            .administer(context.clone(), Operation::Suspend(true))
            .await
            .unwrap();
        let backup = managers[leader]
            .execute(
                context.clone(),
                M::Backup {
                    session_id: uuid::Uuid::new_v4(),
                    destination: "primary".into(),
                },
            )
            .await
            .unwrap();
        let backup_id = uuid::Uuid::parse_str(backup["backup_id"].as_str().unwrap()).unwrap();
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
        let incarnation = uuid::Uuid::new_v4();
        let source = databases[leader]
            .engine()
            .generation()
            .unwrap()
            .state
            .incarnation
            .clone();
        let retirement_request = kasumi_types::RetireSourceRequest {
            retirement_id: "replicated-restore".into(),
            expected_source_incarnation: source.clone(),
            target_incarnation: incarnation.to_string(),
            destination: "primary".into(),
            not_after_ms: u64::MAX,
            checkpoint: databases[leader]
                .verify_backup_checkpoint_named(context.clone(), "primary", backup_id)
                .await
                .unwrap()
                .checkpoint()
                .clone(),
        };
        managers[0]
            .execute(
                context.clone(),
                M::PrepareRestore {
                    destination: "primary".into(),
                    backup_id,
                    incarnation,
                },
            )
            .await
            .unwrap_or_else(|error| panic!(
                "first replicated PrepareRestore failed: {error:#}; admission after failure={:?}; destination chunk limit={:?}; source limits={:?}",
                managers[0].security_audit().admission().snapshot(),
                configurations[0].backup_destinations.get("primary").map(|destination| match destination {
                    crate::administration::DestinationConfig::Filesystem { max_bytes, .. }
                    | crate::administration::DestinationConfig::S3 { max_bytes, .. } => *max_bytes,
                }),
                databases[0].engine().generation().map(|generation| generation.state.limits.clone()),
            ));
        // A single prepared replica cannot start a replacement quorum.
        assert!(
            managers[0]
                .execute(context.clone(), M::InitializeRestore { incarnation })
                .await
                .is_err()
        );
        for manager in &managers[1..] {
            manager
                .execute(
                    context.clone(),
                    M::PrepareRestore {
                        destination: "primary".into(),
                        backup_id,
                        incarnation,
                    },
                )
                .await
                .unwrap();
        }
        managers[0]
            .execute(context.clone(), M::InitializeRestore { incarnation })
            .await
            .unwrap();
        let restored_databases = managers
            .iter()
            .map(|manager| manager.test_generation(&context.tenant, &incarnation.to_string()))
            .collect::<Vec<_>>();
        let target_leader = quorum_ready_leader(&restored_databases, "new restore election").await;
        let group = format!("{}/{}", context.tenant, incarnation);
        // A leader hint remains visible when this group loses quorum. Refusal
        // must preserve the pending restore; other tenant/control groups keep
        // their authenticated peer permissions and continue normally.
        cluster_networks[target_leader]
            .set_group_allowed_peers(&group, BTreeSet::from([target_leader as u64 + 1]))
            .unwrap();
        let before = restored_databases[target_leader]
            .engine()
            .generation()
            .unwrap()
            .state
            .pending_restore
            .clone();
        assert!(before.is_some());
        let blocked_barrier = restored_databases[target_leader]
            .raft_group()
            .raft()
            .ensure_linearizable()
            .await
            .unwrap_err();
        assert!(
            blocked_barrier.api_error().is_some(),
            "unexpected fatal barrier: {blocked_barrier:?}"
        );
        eprintln!("intentional restore quorum loss: {blocked_barrier:?}");
        let hint = managers[target_leader]
            .execute(
                context.clone(),
                M::Status {
                    incarnation: Some(incarnation),
                },
            )
            .await
            .unwrap();
        assert_eq!(hint["leader"].as_u64(), Some(target_leader as u64 + 1));
        assert_eq!(
            hint["observation"],
            serde_json::json!("local_committed_state")
        );
        let denied = managers[target_leader]
            .execute(context.clone(), M::CompleteRestore { incarnation })
            .await
            .unwrap_err();
        assert_eq!(denied.code, kasumi_types::ErrorCode::Unavailable);
        assert_eq!(
            serde_json::to_value(
                &restored_databases[target_leader]
                    .engine()
                    .generation()
                    .unwrap()
                    .state
                    .pending_restore
            )
            .unwrap(),
            serde_json::to_value(&before).unwrap()
        );
        cluster_networks[target_leader]
            .set_group_allowed_peers(&group, BTreeSet::from([1, 2, 3]))
            .unwrap();
        on_quorum_leader(
            &restored_databases,
            "complete restored generation",
            |index| managers[index].execute(context.clone(), M::CompleteRestore { incarnation }),
        )
        .await;
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let mut ready = true;
                for manager in &managers {
                    let status = manager
                        .execute(
                            context.clone(),
                            M::Status {
                                incarnation: Some(incarnation),
                            },
                        )
                        .await
                        .unwrap();
                    ready &= status["pending_restore"].is_null();
                }
                if ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                for manager in &managers {
                    // The original group can hand off to closed custody after
                    // an uncertain acknowledgement; retry through installed
                    // authority instead of polling the discarded warm handle.
                    if manager
                        .execute(
                            context.clone(),
                            M::RetireSource {
                                request: retirement_request.clone(),
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
        on_quorum_leader(&controls, "activate restored route", |index| {
            managers[index].execute(
                context.clone(),
                M::ActivateRestore {
                    incarnation,
                    retirement: retirement_request.reference().unwrap(),
                },
            )
        })
        .await;
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
        let (resumed_leader, ()) =
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
            .await;
        let restored = registries[resumed_leader].database(&context).unwrap();
        let (_, document) =
            on_quorum_leader(&restored_databases, "read restored document", |index| {
                restored_databases[index].get(&context, "docs", "a")
            })
            .await;
        assert_eq!(document.body["durable"], serde_json::json!(true));
        assert!(databases[leader].get(&context, "docs", "a").await.is_err());
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
        drop(restored);
        drop(restored_databases);
        cluster_networks.clear();
        managers.clear();
        controls.clear();
        registries.clear();
        // Reopening from original operator bootstrap must follow the durable
        // replacement route, never silently resurrect the retired source.
        let mut second_tasks = Vec::new();
        let mut second_stops = Vec::new();
        let mut second_registries = Vec::new();
        let beta_incarnation = uuid::Uuid::new_v4().to_string();
        let mismatched_incarnation = uuid::Uuid::new_v4().to_string();
        let mut second_managers = Vec::new();
        let mut second_controls = Vec::new();
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
            let runtime = NodeRuntime::open_using(config, |_| {
                Ok(Zeroizing::new("test-runtime-token".into()))
            })
            .await
            .unwrap();
            second_registries.push(runtime.registry.clone());
            second_managers.push(runtime.administration.clone().unwrap());
            second_controls.push(runtime.control.database.clone());
            let (stop, shutdown) = watch::channel(false);
            second_stops.push(stop);
            second_tasks.push(tokio::spawn(runtime.serve(shutdown)));
        }
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
                .execute(
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
                                .execute(
                                    operator.clone(),
                                    M::ApprovePeerPool {
                                        expected_topology_version: 0
                                    }
                                )
                                .await
                                .is_err()
                        );
                        if manager
                            .execute(
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
        exercise_provisioning(
            &second_managers,
            &second_controls,
            &second_registries,
            operator.clone(),
        )
        .await;
        // Approving one replica's immutable configuration cannot authorize a
        // differently configured voter or create a partial two-voter group.
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                for (manager, control) in second_managers.iter().zip(&second_controls) {
                    let metrics = control.raft_group().raft().metrics().borrow().clone();
                    if metrics.current_leader == Some(metrics.id)
                        && manager
                            .execute(
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
                .execute(
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
                .execute(
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
        let (mode, bootstrap): (String, ReplicatedBootstrap) = serde_json::from_slice(&binding)?;
        bootstrap.validate()?;
        ensure!(
            mode == "replicated"
                && id == replication.node_id
                && group == format!("{}/{}", store.binding().tenant(), bootstrap.incarnation),
            "custody deployment differs from installed replication"
        );
        let network = cluster.context("custody peer transport absent")?;
        let custody = kasumi_engine::RetiredCustody::open_replicated(
            store,
            id,
            group.clone(),
            network.clone(),
            kasumi_raft::CustodyRaftConfig {
                raft: kasumi_raft::server_config(),
                limits: kasumi_raft::RaftLimits {
                    max_snapshot_bytes: snapshot_limit,
                },
            },
            admission,
            audit,
        )
        .await?;
        if let Err(error) = network.register_group(
            group,
            custody
                .raft_group()
                .context("closed custody group absent")?
                .raft()
                .clone(),
            replication.peers.iter().map(|peer| peer.node_id).collect(),
        ) {
            let _ = custody.shutdown().await;
            return Err(error);
        }
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
            kasumi_raft::CustodyRaftConfig {
                raft: kasumi_raft::Config::default(),
                limits: kasumi_raft::RaftLimits {
                    max_snapshot_bytes: snapshot_limit,
                },
            },
            admission,
            audit,
        )
        .await?;
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
}

#[cfg(test)]
#[path = "runtime_audit_tests.rs"]
mod audit_tests;

#[cfg(test)]
#[path = "runtime_observability_tests.rs"]
mod observability_tests;
