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
use kasumi_store::{NodeStore, TenantStore, TransitConfig, TransitKeyProvider};
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
    Local,
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
    pub token_env: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub ca_certificate: Option<PathBuf>,
    #[serde(default)]
    pub derived: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfig {
    pub tenant: String,
    pub transit: TransitSettings,
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
    /// Select an already-authorized operator independently of the immutable genesis policy.
    #[serde(default)]
    pub startup_principal: Option<String>,
    pub transit: TransitSettings,
    pub initial_policy: Policy,
    #[serde(default)]
    pub initial_limits: Limits,
    #[serde(default)]
    pub incarnation: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAuditConfig {
    pub transit: TransitSettings,
    pub max_records: u64,
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
    #[serde(default = "default_prepared_limit")]
    pub max_prepared_generations_per_tenant: usize,
    #[serde(default)]
    pub admission: kasumi_engine::admission::AdmissionConfig,
    #[serde(default)]
    pub backup_destinations: BTreeMap<String, crate::administration::DestinationConfig>,
    pub format: u32,
    pub mode: DeploymentMode,
    pub database_path: PathBuf,
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
        self.admission.validate()?;
        ensure!(
            (1..=16).contains(&self.max_prepared_generations_per_tenant),
            "prepared generation limit must be 1..16"
        );
        for (name, destination) in &self.backup_destinations {
            kasumi_types::validate_name(name)?;
            destination.validate()?;
        }
        Authenticator::new(self.auth.clone())?;
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
            !self.tenants.is_empty() && self.tenants.len() <= 10_000,
            "configure 1–10000 tenants"
        );
        ensure!(
            self.security_audit.max_records > 0,
            "security audit retention quota must be positive"
        );
        let mut key_refs = BTreeSet::new();
        for transit in std::iter::once(&self.security_audit.transit)
            .chain(std::iter::once(&self.control.transit))
            .chain(self.tenants.iter().map(|tenant| &tenant.transit))
        {
            ensure!(
                key_refs.insert(transit.validate()?),
                "tenant, control, and security stores require distinct Transit wrapping keys"
            );
        }
        validate_initial_policy(&self.control.initial_policy)?;
        configured_control_context(&self.control)?;
        let mut tenants = BTreeSet::new();
        for tenant in &self.tenants {
            kasumi_types::validate_name(&tenant.tenant)?;
            ensure!(
                !tenant.tenant.starts_with("__kasumi_") && tenants.insert(&tenant.tenant),
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
            DeploymentMode::Local => {
                ensure!(
                    self.replication.is_none()
                        && self.control.incarnation.is_none()
                        && self
                            .tenants
                            .iter()
                            .all(|tenant| tenant.incarnation.is_none()),
                    "local mode cannot contain replicated bootstrap configuration"
                );
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
        if self.mode == DeploymentMode::Local {
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
    fn validate(&self) -> Result<()> {
        absolute(&self.certificate)?;
        absolute(&self.private_key)?;
        Ok(())
    }
    fn load(&self) -> Result<TlsIdentity> {
        self.validate()?;
        let cert = read_bounded(&self.certificate, MAX_PEM_BYTES)?;
        let key = read_private_file(&self.private_key, MAX_PEM_BYTES)?;
        TlsIdentity::from_pem(&cert, &key)
    }
}
impl MutualTlsEndpoint {
    fn validate(&self) -> Result<()> {
        self.tls.validate()?;
        absolute(&self.client_ca)?;
        ensure!(
            self.listen.port() > 0,
            "listener needs an explicit nonzero port"
        );
        Ok(())
    }
    fn load(&self) -> Result<Arc<rustls::ServerConfig>> {
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
    fn validate(&self) -> Result<String> {
        let url = origin(&self.endpoint)?;
        environment_name(&self.token_env)?;
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
    fn provider_with_secret(
        &self,
        mut token: Zeroizing<String>,
    ) -> Result<Arc<TransitKeyProvider>> {
        self.validate()?;
        Ok(Arc::new(TransitKeyProvider::new(TransitConfig {
            endpoint: self.endpoint.clone(),
            mount: self.mount.clone(),
            key_name: self.key_name.clone(),
            token: std::mem::take(&mut *token),
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
    fn validate(&self) -> Result<()> {
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
pub(crate) fn environment_name(value: &str) -> Result<()> {
    ensure!(
        value.starts_with("KASUMI_")
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'),
        "credentials require a KASUMI_ uppercase environment-variable reference"
    );
    Ok(())
}
fn environment_secret(name: &str) -> Result<Zeroizing<String>> {
    environment_name(name)?;
    let secret = Zeroizing::new(
        std::env::var(name)
            .map_err(|_| anyhow::anyhow!("required credential variable {name} is unavailable"))?,
    );
    ensure!(
        !secret.is_empty() && secret.len() <= 16 << 10 && !secret.chars().any(char::is_control),
        "credential variable {name} is empty or malformed"
    );
    Ok(secret)
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
fn read_private_file(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening private key {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            file.metadata()?.permissions().mode() & 0o077 == 0,
            "private key must not be readable or writable by group/other users"
        );
    }
    ensure!(
        file.metadata()?.len() <= limit as u64,
        "private key file exceeds byte limit"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "private key file exceeds byte limit");
    Ok(bytes)
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
struct BoundListener {
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
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
        // Reconciliation must stop before taking the final generation inventory.
        // It has no nested listener tasks, so aborting and joining it is safe.
        self.maintenance.abort_all();
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
    config: RuntimeConfig,
    registry: DatabaseRegistry,
    tenants: Vec<OpenedTenant>,
    control: OpenedTenant,
    audit: Arc<SecurityAudit>,
    data_listeners: Vec<BoundListener>,
    cluster_listener: Option<BoundListener>,
    cluster: Option<Arc<ClusterNetwork>>,
    local_certificate_pin: CertificatePin,
    closed: bool,
    administration: Option<Arc<crate::administration::Administration>>,
}

impl NodeRuntime {
    pub async fn open(config: RuntimeConfig) -> Result<Self> {
        Self::open_using(config, environment_secret).await
    }

    async fn open_using(
        config: RuntimeConfig,
        credential: impl Fn(&str) -> Result<Zeroizing<String>>,
    ) -> Result<Self> {
        config.validate()?;
        let admission = kasumi_engine::admission::NodeAdmission::new(config.admission.clone())?;
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
            .map(|(name, destination)| Ok((name.clone(), destination.open(&credential)?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        // Validate all TLS/credential material and bind all sockets before a
        // durable bootstrap can be created. No listener serves until `serve`.
        let mcp_identity = config.mcp.tls.load()?;
        let local_certificate_pin = mcp_identity.certificate_pin();
        let mcp_tls = kasumi_transport::server_config(&mcp_identity, ClientAuthentication::OAuth)?;
        let native_tls = config.native.load()?;
        let admin_tls = config.admin.load()?;
        let mut providers = Vec::new();
        for tenant in &config.tenants {
            providers.push(
                tenant
                    .transit
                    .provider_with_secret(credential(&tenant.transit.token_env)?)?,
            );
        }
        let control_provider = config
            .control
            .transit
            .provider_with_secret(credential(&config.control.transit.token_env)?)?;
        let security_provider = config
            .security_audit
            .transit
            .provider_with_secret(credential(&config.security_audit.transit.token_env)?)?;
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
                tls: network.server_tls(),
                router: network.router(),
            };
            (Some(network), Some(listener))
        } else {
            (None, None)
        };
        let node = NodeStore::open(&config.database_path)?;
        let security_store =
            TenantStore::open(node.clone(), SECURITY_TENANT.into(), security_provider).await?;
        let audit = SecurityAudit::open(security_store, config.security_audit.max_records)?;
        auth.install_audit(audit.clone())?;
        if let Some(cluster) = &cluster {
            cluster.install_audit(audit.clone())?;
        }
        let control_store = TenantStore::open(
            node.clone(),
            CONTROL_TENANT.into(),
            control_provider.clone(),
        )
        .await?;
        let control_bootstrap = config.bootstrap(
            &config.control.initial_policy,
            &config.control.initial_limits,
            config.control.incarnation.as_deref(),
        )?;
        let control = Self::open_database(
            &config,
            control_store,
            config.control.initial_policy.clone(),
            config.control.initial_limits.clone(),
            control_bootstrap,
            cluster.as_ref(),
            audit.clone(),
        )
        .await?;
        control.database.install_admission(admission.clone())?;
        let mut runtime = Self {
            config: config.clone(),
            registry: registry.clone(),
            tenants: Vec::new(),
            control,
            audit,
            data_listeners: Vec::new(),
            cluster_listener,
            cluster,
            local_certificate_pin,
            closed: false,
            administration: None,
        };
        let result = async {
            let mut managed = vec![crate::administration::ManagedTenant {
                database: runtime.control.database.clone(),
                store: runtime.control.store.clone(),
                provider: control_provider,
                bootstrap: runtime.control.bootstrap.clone(),
                descriptor: None,
            }];
            for (tenant, provider) in config.tenants.iter().zip(providers) {
                let store =
                    TenantStore::open(node.clone(), tenant.tenant.clone(), provider.clone())
                        .await?;
                let bootstrap = config.bootstrap(
                    &tenant.initial_policy,
                    &tenant.initial_limits,
                    tenant.incarnation.as_deref(),
                )?;
                let opened = Self::open_database(
                    &config,
                    store,
                    tenant.initial_policy.clone(),
                    tenant.initial_limits.clone(),
                    bootstrap,
                    runtime.cluster.as_ref(),
                    runtime.audit.clone(),
                )
                .await?;
                opened.database.install_admission(admission.clone())?;
                managed.push(crate::administration::ManagedTenant {
                    database: opened.database.clone(),
                    store: opened.store.clone(),
                    provider,
                    bootstrap: opened.bootstrap.clone(),
                    descriptor: None,
                });
                runtime.tenants.push(opened);
            }
            let administration = crate::administration::Administration::new(
                config.clone(),
                registry.clone(),
                runtime.control.database.clone(),
                runtime.audit.clone(),
                runtime.cluster.clone(),
                managed,
                destinations,
                admission.clone(),
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
            let admin = tonic::service::Routes::new(
                NativeAdmin::new(registry.clone(), auth)
                    .with_management(administration)
                    .service(),
            )
            .into_axum_router();
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

    async fn open_database(
        config: &RuntimeConfig,
        store: Arc<TenantStore>,
        policy: Policy,
        limits: Limits,
        bootstrap: Option<ReplicatedBootstrap>,
        cluster: Option<&Arc<ClusterNetwork>>,
        audit: Arc<SecurityAudit>,
    ) -> Result<OpenedTenant> {
        let database = if let Some(bootstrap) = &bootstrap {
            let replication = config
                .replication
                .as_ref()
                .context("replication configuration missing")?;
            let network = cluster.context("cluster transport missing")?;
            let database = kasumi_engine::open_replicated(
                replication.node_id,
                store.clone(),
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
        } else {
            kasumi_engine::open_local(store.clone(), policy, limits, audit).await?
        };
        Ok(OpenedTenant {
            database,
            store,
            bootstrap,
        })
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
            tasks.maintenance.spawn(async move { loop { tokio::select! { _=stop.changed()=>return Ok(()), _=tokio::time::sleep(Duration::from_millis(250))=>{ manager.reconcile().await?; } } } });
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
                    plane.initialize(context.clone()).await?;
                    if let Some(current) = plane.topology(&context).await? {
                        validate_configured_topology(&current.topology, &expected)?;
                    } else {
                        plane
                            .replace_topology(
                                context.clone(),
                                expected.clone(),
                                Precondition::Absent,
                                "runtime-topology-bootstrap".into(),
                            )
                            .await?;
                    }
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
                    return Ok(true);
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        let audit = self
            .audit
            .record(lifecycle(SecurityEventKind::NodeStopping))
            .await;
        let mut failure = audit.err();
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
        self.audit.shutdown().await;
        self.closed = true;
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
    let transit = |key: &str, variable: &str| TransitSettings {
        endpoint: "https://openbao.example".into(),
        mount: "transit".into(),
        key_name: key.into(),
        token_env: variable.into(),
        namespace: None,
        ca_certificate: None,
        derived: false,
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
        format: 1,
        max_prepared_generations_per_tenant: default_prepared_limit(),
        admission: kasumi_engine::admission::AdmissionConfig::default(),
        backup_destinations: BTreeMap::new(),
        mode: DeploymentMode::Local,
        database_path: "/var/lib/kasumi/node.redb".into(),
        auth: AuthConfig {
            jwks_trusted_ca_pem: None,
            issuer: "https://identity.example".into(),
            audience: "https://kasumi.example/mcp".into(),
            jwks_uri: "https://identity.example/.well-known/jwks.json".into(),
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
            startup_principal: None,
            transit: transit("kasumi-control", "KASUMI_CONTROL_TRANSIT_TOKEN"),
            initial_policy: policy("operator"),
            initial_limits: Limits::default(),
            incarnation: None,
        },
        security_audit: SecurityAuditConfig {
            transit: transit("kasumi-node-security", "KASUMI_SECURITY_TRANSIT_TOKEN"),
            max_records: 1_000_000,
        },
        tenants: vec![TenantConfig {
            tenant: "acme".into(),
            transit: transit("acme-wrapping-key", "KASUMI_ACME_TRANSIT_TOKEN"),
            initial_policy: policy("acme-admin"),
            initial_limits: Limits::default(),
            incarnation: None,
        }],
        replication: None,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminClientConfig {
    pub endpoint: String,
    pub identity: TlsFiles,
    pub server_ca: PathBuf,
    pub server_certificate_pins: Vec<String>,
    pub token_env: String,
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
        environment_name(&self.token_env)?;
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
        let secret = environment_secret(&self.token_env)?;
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
mod tests {
    use super::*;
    use kasumi_store::test_utils::{LocalKeyProvider, ManualClock};

    #[test]
    fn operator_example_is_valid_secret_free_and_rejects_inline_credentials() {
        let config = example_config();
        config.validate().unwrap();
        let mut value = serde_json::to_value(&config).unwrap();
        assert!(value["tenants"][0]["transit"].get("token").is_none());
        value["tenants"][0]["transit"]["token"] = serde_json::json!("must-not-be-accepted");
        assert!(serde_json::from_value::<RuntimeConfig>(value).is_err());
    }

    #[test]
    fn rejects_shared_wrapping_keys_reserved_tenants_and_ambiguous_listeners() {
        let mut config = example_config();
        config.control.transit = config.tenants[0].transit.clone();
        assert!(config.validate().is_err());
        let mut config = example_config();
        config.security_audit.transit = config.tenants[0].transit.clone();
        assert!(config.validate().is_err());
        let mut config = example_config();
        config.tenants[0].tenant = CONTROL_TENANT.into();
        assert!(config.validate().is_err());
        let mut config = example_config();
        config.tenants.push(config.tenants[0].clone());
        assert!(config.validate().is_err());
        let mut config = example_config();
        config.admin.listen = config.mcp.listen;
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_cleartext_credential_urls_ambient_variable_names_and_missing_administrators() {
        let mut config = example_config();
        config.tenants[0].transit.endpoint = "http://localhost:8200".into();
        assert!(config.validate().is_err());
        let mut config = example_config();
        config.tenants[0].transit.endpoint = "https://user:password@localhost".into();
        assert!(config.validate().is_err());
        let mut config = example_config();
        config.tenants[0].transit.token_env = "HOME".into();
        assert!(config.validate().is_err());
        let mut config = example_config();
        config.tenants[0].transit.key_name = "../different-key".into();
        assert!(config.validate().is_err());
        let mut config = example_config();
        config.tenants[0].initial_policy = Policy::default();
        assert!(config.validate().is_err());
        let mut config = example_config();
        config.control.initial_policy.grants[0].actions = BTreeSet::from([Action::Admin]);
        assert!(config.validate().is_err());
        let mut config = example_config();
        config.admin.tls.private_key = "relative-key.pem".into();
        assert!(config.validate().is_err());
    }

    fn replicated() -> RuntimeConfig {
        let mut config = example_config();
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
        let mut config = example_config();
        config.mode = DeploymentMode::Replicated;
        assert!(config.validate().is_err());
        let mut config = replicated();
        config.mode = DeploymentMode::Local;
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
        let node = NodeStore::open(&path).unwrap();
        let keys = Arc::new(LocalKeyProvider::new([33; 32]));
        let clock = Arc::new(ManualClock::new());
        let service = TenantStore::open_with_clock(
            node.clone(),
            SECURITY_TENANT.into(),
            keys.clone(),
            clock.clone(),
        )
        .await
        .unwrap();
        let tenant = TenantStore::open_with_clock(
            node,
            "acme".into(),
            Arc::new(LocalKeyProvider::new([34; 32])),
            clock.clone(),
        )
        .await
        .unwrap();
        let audit = SecurityAudit::open(service.clone(), 2).unwrap();
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
                .is_err()
        );
        drop(audit);
        drop(service);
        drop(tenant);
        let service = TenantStore::open_with_clock(
            NodeStore::open(&path).unwrap(),
            SECURITY_TENANT.into(),
            keys,
            clock,
        )
        .await
        .unwrap();
        let audit = SecurityAudit::open(service.clone(), 2).unwrap();
        assert!(
            audit
                .record(lifecycle(SecurityEventKind::NodeStarted))
                .await
                .is_err()
        );
        assert_eq!(service.scan("security.audit").unwrap().len(), 2);
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
            token_env: "KASUMI_ADMIN_ACCESS_TOKEN".into(),
        };
        config.validate().unwrap();
        let mut bad = config.clone();
        bad.endpoint = "http://localhost:9445".into();
        assert!(bad.validate().is_err());
        let mut bad = config.clone();
        bad.server_certificate_pins.clear();
        assert!(bad.validate().is_err());
        let mut bad = config;
        bad.token_env = "inline-token-value".into();
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
                    key_ref: "local-test-key".into(),
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
            let node = NodeStore::open(&path).unwrap();
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
                let (started, running) = tokio::sync::oneshot::channel();
                tasks.maintenance.spawn(async move {
                    let _owner = owner;
                    let _ = started.send(());
                    std::future::pending::<Result<()>>().await
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
            drop(NodeStore::open(&path).unwrap());
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
        next.transit.key_name = format!("{tenant}-wrapping-key");
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
        let mut config = example_config();
        config.database_path = dir.path().join("node.redb");
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
        for transit in std::iter::once(&mut config.control.transit)
            .chain(std::iter::once(&mut config.security_audit.transit))
            .chain(config.tenants.iter_mut().map(|tenant| &mut tenant.transit))
        {
            transit.endpoint = transit_endpoint.clone();
            transit.ca_certificate = Some(files.certificate.clone());
        }
        let context = RequestContext {
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
                // The already serving restored tenant remains usable during onboarding.
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
                let backup = manager
                    .execute(
                        context.clone(),
                        M::Backup {
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
                    .administer(context.clone(), Operation::Suspend(true))
                    .await
                    .unwrap();
                let restored = uuid::Uuid::new_v4();
                let source = database
                    .engine()
                    .generation()
                    .unwrap()
                    .state
                    .incarnation
                    .clone();
                manager
                    .execute(
                        context.clone(),
                        M::PrepareRestore {
                            destination: "primary".into(),
                            backup_id,
                            incarnation: restored,
                        },
                    )
                    .await
                    .unwrap();
                // A generation cannot be activated until the source is permanently fenced.
                assert!(
                    manager
                        .execute(
                            context.clone(),
                            M::ActivateRestore {
                                incarnation: restored,
                                expected_source: source.clone()
                            }
                        )
                        .await
                        .is_err()
                );
                manager
                    .execute(
                        context.clone(),
                        M::RetireSource {
                            incarnation: restored,
                        },
                    )
                    .await
                    .unwrap();
                assert!(
                    database
                        .administer(context.clone(), Operation::Suspend(false))
                        .await
                        .is_err()
                );
                let activation = M::ActivateRestore {
                    incarnation: restored,
                    expected_source: source,
                };
                let activation_fence = manager.response_fence(&context, &activation).unwrap();
                let old_source_fence = manager
                    .response_fence(&context, &M::Status { incarnation: None })
                    .unwrap();
                let activated = manager.execute(context.clone(), activation).await.unwrap();
                let _encoded = serde_json::to_vec(&activated).unwrap();
                activation_fence.check_release().unwrap();
                assert!(old_source_fence.check_release().is_err());
                let active = registry.database(&context).unwrap();
                assert!(active.engine().generation().unwrap().state.suspended);
                active
                    .administer(context.clone(), Operation::Suspend(false))
                    .await
                    .unwrap();
                assert_eq!(
                    active.get(&context, "docs", "first").await.unwrap().body["exact"],
                    serde_json::json!(9007199254740993u64)
                );
                incarnation = Some(restored.to_string());
                assert!(database.get(&context, "docs", "first").await.is_err());
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
            let mut config = example_config();
            config.mode = DeploymentMode::Replicated;
            config.database_path = dir.path().join(format!("node{node}.redb"));
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
            config.security_audit.transit.key_name = format!("node{node}-security");
            for settings in std::iter::once(&mut config.control.transit)
                .chain(std::iter::once(&mut config.security_audit.transit))
                .chain(config.tenants.iter_mut().map(|tenant| &mut tenant.transit))
            {
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
            configurations.push(config);
        }
        drop(reserved);
        let context = RequestContext {
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
                                    control_context(&example_config().control.initial_policy)
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
                                    control_context(&example_config().control.initial_policy)
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
        let backup = managers[leader]
            .execute(
                context.clone(),
                M::Backup {
                    destination: "primary".into(),
                },
            )
            .await
            .unwrap();
        let backup_id = uuid::Uuid::parse_str(backup["backup_id"].as_str().unwrap()).unwrap();
        databases[leader]
            .administer(context.clone(), Operation::Suspend(true))
            .await
            .unwrap();
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
            .unwrap();
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
                for (manager, database) in managers.iter().zip(&databases) {
                    let metrics = database.raft_group().raft().metrics().borrow().clone();
                    if metrics.current_leader == Some(metrics.id)
                        && manager
                            .execute(context.clone(), M::RetireSource { incarnation })
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
            while !databases
                .iter()
                .all(|db| db.engine().generation().unwrap().state.retired)
            {
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
                    expected_source: source.clone(),
                },
            )
        })
        .await;
        tokio::time::timeout(Duration::from_secs(20), async {
            while !registries.iter().all(|registry| {
                registry
                    .database(&context)
                    .unwrap()
                    .engine()
                    .generation()
                    .unwrap()
                    .state
                    .incarnation
                    == incarnation.to_string()
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
        let operator = control_context(&example_config().control.initial_policy).unwrap();
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
