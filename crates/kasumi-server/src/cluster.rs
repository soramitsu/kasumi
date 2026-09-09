//! Authenticated, bounded Raft HTTP transport. Endpoints are operator configured;
//! BasicNode addresses received through membership/logs are never network inputs.
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, OnceLock, RwLock},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use kasumi_raft::{
    BasicNode, Raft, RaftTransport, RpcPayloadTooLarge, RpcRequest, RpcResponse, dispatch_rpc,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::auth::{RequestAuditEvent, RequestAuditKind, RequestAuditSink};
use crate::tls::AuthenticatedTlsPeer;
use kasumi_transport::{
    CertificatePin, ClientAuthentication, TlsIdentity, peer_client_config, server_config,
};

const RPC_PATH: &str = "/internal/raft";
const ENROLLMENT_PATH: &str = "/internal/enrollment-readiness";
const MAINTENANCE_PATH: &str = "/internal/authority-maintenance-readiness";
const BOOTSTRAP_PATH: &str = "/internal/bootstrap-readiness";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentReadiness {
    pub bootstrap_sha256: String,
    pub initialized: bool,
    pub revision: u64,
}
pub trait EnrollmentReadinessProvider: Send + Sync {
    fn readiness(&self, group: &str) -> Result<EnrollmentReadiness>;
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadinessRequest {
    group: String,
    source: u64,
    target: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaintenanceReadinessRequest {
    group: String,
    source: u64,
    target: u64,
    bootstrap_sha256: String,
    required_state_bytes: u64,
    command: kasumi_serving::AuthorityMaintenanceCommand,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaintenanceReadinessResponse {
    node_id: u64,
    bootstrap_sha256: String,
    required_state_bytes: u64,
    command_sha256: String,
}

#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub node_id: u64,
    /// HTTPS origin from operator configuration. No paths, queries, credentials,
    /// fragments, redirects, or BasicNode fallback addresses are accepted.
    pub endpoint: String,
    /// Multiple pins permit an explicit overlap window during certificate rotation.
    pub certificate_pins: BTreeSet<CertificatePin>,
}

#[derive(Clone, Debug)]
pub struct PeerLimits {
    pub max_rpc_bytes: usize,
    pub max_inflight_requests: usize,
    pub request_timeout: Duration,
}

impl Default for PeerLimits {
    fn default() -> Self {
        Self {
            // An 8 MiB application command can expand to ~32 MiB in the JSON
            // byte-array RPC envelope. Oversized multi-entry appends shrink.
            max_rpc_bytes: 40 * 1024 * 1024,
            max_inflight_requests: 64,
            request_timeout: Duration::from_secs(30),
        }
    }
}

struct PeerClient {
    endpoint: reqwest::Url,
    client: reqwest::Client,
}
type BootstrapAccess = Arc<dyn Fn() -> Result<()> + Send + Sync>;
struct BootstrapFence {
    sha256: String,
    access: BootstrapAccess,
}
type PeerAccessFence = Arc<dyn Fn(u64) -> Result<()> + Send + Sync>;
struct GroupRoute {
    raft: Raft,
    allowed_peers: BTreeSet<u64>,
    bootstrap: Option<BootstrapFence>,
    peer_fence: Option<PeerAccessFence>,
}

pub struct ClusterNetwork {
    local_node_id: u64,
    clients: BTreeMap<u64, PeerClient>,
    certificate_nodes: BTreeMap<CertificatePin, u64>,
    groups: RwLock<BTreeMap<String, GroupRoute>>,
    server_tls: Arc<rustls::ServerConfig>,
    incoming: Arc<Semaphore>,
    outgoing: Arc<Semaphore>,
    limits: PeerLimits,
    audit: OnceLock<Arc<dyn RequestAuditSink>>,
    readiness: OnceLock<std::sync::Weak<dyn EnrollmentReadinessProvider>>,
    maintenance: OnceLock<std::sync::Weak<kasumi_authority::IndependentAuthority>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerRequest {
    group: String,
    source: u64,
    target: u64,
    request: RpcRequest,
    #[serde(default)]
    bootstrap_sha256: Option<String>,
}

fn encode_bounded(value: &impl Serialize, limit: usize) -> Result<Vec<u8>> {
    struct BoundedBytes {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl std::io::Write for BoundedBytes {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.bytes.len().saturating_add(bytes.len()) > self.limit {
                return Err(std::io::Error::other(
                    "raft message exceeds transport byte limit",
                ));
            }
            self.bytes
                .try_reserve(bytes.len())
                .map_err(std::io::Error::other)?;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = BoundedBytes {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut output, value)?;
    Ok(output.bytes)
}

impl ClusterNetwork {
    pub fn new(
        local_node_id: u64,
        identity: &TlsIdentity,
        trusted_ca_pem: &[u8],
        peers: Vec<PeerConfig>,
        limits: PeerLimits,
    ) -> Result<Arc<Self>> {
        ensure!(
            limits.max_rpc_bytes > 0
                && limits.max_inflight_requests > 0
                && !limits.request_timeout.is_zero(),
            "invalid peer limits"
        );
        let mut clients = BTreeMap::new();
        let mut certificate_nodes = BTreeMap::new();
        let mut local_certificate_bound = false;
        for peer in peers {
            let mut endpoint = reqwest::Url::parse(&peer.endpoint)?;
            ensure!(
                endpoint.scheme() == "https"
                    && endpoint.host_str().is_some()
                    && endpoint.username().is_empty()
                    && endpoint.password().is_none()
                    && endpoint.query().is_none()
                    && endpoint.fragment().is_none()
                    && matches!(endpoint.path(), "" | "/"),
                "cluster peer must be an HTTPS origin"
            );
            ensure!(
                !clients.contains_key(&peer.node_id) && !peer.certificate_pins.is_empty(),
                "duplicate peer or missing certificate pins"
            );
            for pin in &peer.certificate_pins {
                ensure!(
                    certificate_nodes.insert(*pin, peer.node_id).is_none(),
                    "a certificate may identify only one cluster node"
                );
            }
            if peer.node_id == local_node_id {
                local_certificate_bound =
                    peer.certificate_pins.contains(&identity.certificate_pin());
            }
            endpoint.set_path(RPC_PATH);
            let config = peer_client_config(identity, trusted_ca_pem, peer.certificate_pins)?;
            let client = reqwest::Client::builder()
                .use_preconfigured_tls(config)
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(3))
                .timeout(limits.request_timeout)
                .pool_idle_timeout(Duration::from_secs(30))
                .pool_max_idle_per_host(4)
                .build()?;
            clients.insert(peer.node_id, PeerClient { endpoint, client });
        }
        ensure!(
            local_certificate_bound,
            "local node identity is not bound to its configured certificate"
        );
        Ok(Arc::new(Self {
            local_node_id,
            clients,
            certificate_nodes,
            groups: RwLock::new(BTreeMap::new()),
            server_tls: server_config(identity, ClientAuthentication::Required { trusted_ca_pem })?,
            incoming: Arc::new(Semaphore::new(limits.max_inflight_requests)),
            outgoing: Arc::new(Semaphore::new(limits.max_inflight_requests)),
            limits,
            audit: OnceLock::new(),
            readiness: OnceLock::new(),
            maintenance: OnceLock::new(),
        }))
    }

    /// Mandatory before receiving peer requests. Missing audit configuration
    /// makes the endpoint unavailable; the sink cannot be replaced in place.
    pub fn install_audit(&self, audit: Arc<dyn RequestAuditSink>) -> Result<()> {
        self.audit
            .set(audit)
            .map_err(|_| anyhow::anyhow!("cluster audit sink already installed"))
    }

    async fn denied(&self, source: Option<u64>, group: &str) -> Response {
        let known_group = self
            .groups
            .read()
            .ok()
            .and_then(|groups| groups.contains_key(group).then(|| group.to_owned()));
        if let Some(audit) = self.audit.get() {
            let _ = audit
                .record(RequestAuditEvent {
                    kind: RequestAuditKind::AccessDenied,
                    principal: source.map(|source| format!("peer:{source}")),
                    tenant: known_group,
                    request_id: uuid::Uuid::new_v4().to_string(),
                })
                .await;
        }
        StatusCode::FORBIDDEN.into_response()
    }

    pub fn install_enrollment_readiness(
        &self,
        provider: std::sync::Weak<dyn EnrollmentReadinessProvider>,
    ) -> Result<()> {
        self.readiness
            .set(provider)
            .map_err(|_| anyhow::anyhow!("restore readiness already installed"))
    }
    pub fn install_authority_maintenance(
        &self,
        provider: std::sync::Weak<kasumi_authority::IndependentAuthority>,
    ) -> Result<()> {
        self.maintenance
            .set(provider)
            .map_err(|_| anyhow::anyhow!("authority maintenance provider already installed"))
    }
    pub async fn bootstrap_fingerprint(&self, peer_id: u64, group: &str) -> Result<String> {
        self.authorize(group, peer_id)?;
        if peer_id == self.local_node_id {
            return self
                .fingerprint(group)?
                .context("bootstrap fingerprint unavailable");
        }
        self.fetch_readiness(peer_id, group, BOOTSTRAP_PATH).await
    }
    fn fingerprint(&self, group: &str) -> Result<Option<String>> {
        let groups = self
            .groups
            .read()
            .map_err(|_| anyhow::anyhow!("cluster routes unavailable"))?;
        let route = groups.get(group).context("group is unavailable")?;
        if let Some(bootstrap) = &route.bootstrap {
            (bootstrap.access)()?;
            Ok(Some(bootstrap.sha256.clone()))
        } else {
            Ok(None)
        }
    }
    pub async fn enrollment_readiness(
        &self,
        peer_id: u64,
        group: &str,
    ) -> Result<EnrollmentReadiness> {
        self.authorize(group, peer_id)?;
        if peer_id == self.local_node_id {
            return self
                .readiness
                .get()
                .and_then(|p| p.upgrade())
                .context("readiness unavailable")?
                .readiness(group);
        }
        self.fetch_readiness(peer_id, group, ENROLLMENT_PATH).await
    }
    async fn fetch_readiness<T: serde::de::DeserializeOwned>(
        &self,
        peer_id: u64,
        group: &str,
        path: &str,
    ) -> Result<T> {
        let _permit = self
            .outgoing
            .clone()
            .try_acquire_owned()
            .context("cluster transport busy")?;
        let peer = self.clients.get(&peer_id).context("peer not configured")?;
        let mut endpoint = peer.endpoint.clone();
        endpoint.set_path(path);
        let mut response = peer
            .client
            .post(endpoint)
            .json(&ReadinessRequest {
                group: group.into(),
                source: self.local_node_id,
                target: peer_id,
            })
            .send()
            .await
            .context("restore readiness peer unavailable")?;
        ensure!(response.status().is_success(), "restore readiness rejected");
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len().saturating_add(chunk.len()) <= 4096,
                "readiness response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).context("invalid readiness response")
    }

    pub fn server_tls(&self) -> Arc<rustls::ServerConfig> {
        self.server_tls.clone()
    }

    /// Called by trusted node administration before initializing a new group.
    /// allowed_peers includes voters and explicitly approved prospective learners.
    pub fn register_group(
        &self,
        group: String,
        raft: Raft,
        allowed_peers: BTreeSet<u64>,
    ) -> Result<()> {
        self.register(group, raft, allowed_peers, None)
    }
    pub fn register_group_with_bootstrap(
        &self,
        group: String,
        raft: Raft,
        allowed_peers: BTreeSet<u64>,
        sha256: String,
        access: BootstrapAccess,
    ) -> Result<()> {
        ensure!(
            sha256.len() == 64
                && sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid bootstrap fingerprint"
        );
        access()?;
        self.register(
            group,
            raft,
            allowed_peers,
            Some(BootstrapFence { sha256, access }),
        )
    }
    fn register(
        &self,
        group: String,
        raft: Raft,
        allowed_peers: BTreeSet<u64>,
        bootstrap: Option<BootstrapFence>,
    ) -> Result<()> {
        kasumi_types::validate_name(&group).map_err(|_| anyhow::anyhow!("invalid group name"))?;
        ensure!(
            raft.metrics().borrow().id == self.local_node_id,
            "group belongs to another node"
        );
        ensure!(
            allowed_peers.contains(&self.local_node_id)
                && allowed_peers.iter().all(|id| self.clients.contains_key(id)),
            "group references an unconfigured peer"
        );
        let mut groups = self
            .groups
            .write()
            .map_err(|_| anyhow::anyhow!("cluster routes unavailable"))?;
        ensure!(!groups.contains_key(&group), "group already registered");
        groups.insert(
            group,
            GroupRoute {
                raft,
                allowed_peers,
                bootstrap,
                peer_fence: None,
            },
        );
        Ok(())
    }

    pub fn unregister_group(&self, group: &str) -> Result<()> {
        self.groups
            .write()
            .map_err(|_| anyhow::anyhow!("cluster routes unavailable"))?
            .remove(group);
        Ok(())
    }

    /// Trusted control-plane admission update for an already registered group.
    /// This does not change Raft membership. Approve prospective learners before
    /// adding them, and remove retired peers only after membership commits.
    pub fn set_group_allowed_peers(&self, group: &str, peers: BTreeSet<u64>) -> Result<()> {
        ensure!(
            peers.contains(&self.local_node_id)
                && peers.iter().all(|id| self.clients.contains_key(id)),
            "group references an unconfigured peer"
        );
        let mut groups = self
            .groups
            .write()
            .map_err(|_| anyhow::anyhow!("cluster routes unavailable"))?;
        groups
            .get_mut(group)
            .context("group is unavailable")?
            .allowed_peers = peers;
        Ok(())
    }

    /// Install a durable membership/revocation check in addition to static pins.
    pub fn install_group_peer_fence(&self, group: &str, fence: PeerAccessFence) -> Result<()> {
        let mut groups = self
            .groups
            .write()
            .map_err(|_| anyhow::anyhow!("cluster routes unavailable"))?;
        let route = groups.get_mut(group).context("group is unavailable")?;
        ensure!(
            route.peer_fence.is_none(),
            "group peer fence already installed"
        );
        route.peer_fence = Some(fence);
        Ok(())
    }

    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route(RPC_PATH, post(receive))
            .route(ENROLLMENT_PATH, post(receive_readiness))
            .route(BOOTSTRAP_PATH, post(receive_bootstrap))
            .route(MAINTENANCE_PATH, post(receive_maintenance))
            .layer(DefaultBodyLimit::max(self.limits.max_rpc_bytes))
            .layer(middleware::from_fn_with_state(self.clone(), bound_request))
            .with_state(self.clone())
    }

    fn authorize(&self, group: &str, peer: u64) -> Result<Raft> {
        let groups = self
            .groups
            .read()
            .map_err(|_| anyhow::anyhow!("cluster routes unavailable"))?;
        let route = groups.get(group).context("group is unavailable")?;
        ensure!(
            route.allowed_peers.contains(&peer),
            "peer is not authorized for this group"
        );
        if let Some(fence) = &route.peer_fence {
            fence(peer)?;
        }
        Ok(route.raft.clone())
    }
}

fn candidate(request: &RpcRequest) -> Option<u64> {
    match request {
        RpcRequest::Append(request) => request.vote.leader_id.voted_for(),
        RpcRequest::Vote(request) => request.vote.leader_id.voted_for(),
        RpcRequest::Snapshot(request) => request.vote.leader_id.voted_for(),
    }
}

fn smaller_append(request: &RpcRequest) -> Option<RpcPayloadTooLarge> {
    match request {
        RpcRequest::Append(request) if request.entries.len() > 1 => Some(RpcPayloadTooLarge {
            max_entries: (request.entries.len() as u64 / 2).max(1),
        }),
        _ => None,
    }
}

async fn bound_request(
    State(network): State<Arc<ClusterNetwork>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Ok(_permit) = network.incoming.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match tokio::time::timeout(network.limits.request_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}

async fn receive(
    State(network): State<Arc<ClusterNetwork>>,
    Extension(peer): Extension<AuthenticatedTlsPeer>,
    Json(message): Json<PeerRequest>,
) -> Response {
    if network.audit.get().is_none() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let source = peer
        .certificate_pin()
        .and_then(|pin| network.certificate_nodes.get(&pin).copied());
    if source != Some(message.source)
        || message.target != network.local_node_id
        || candidate(&message.request) != source
    {
        return network.denied(source, &message.group).await;
    }
    let Ok(raft) = network.authorize(&message.group, message.source) else {
        return network.denied(source, &message.group).await;
    };
    match network.fingerprint(&message.group) {
        Ok(expected) if expected == message.bootstrap_sha256 => {}
        _ => return network.denied(source, &message.group).await,
    }
    let response = dispatch_rpc(&raft, message.request).await;
    match encode_bounded(&response, network.limits.max_rpc_bytes) {
        Ok(bytes) => ([("content-type", "application/json")], bytes).into_response(),
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn receive_bootstrap(
    State(network): State<Arc<ClusterNetwork>>,
    Extension(peer): Extension<AuthenticatedTlsPeer>,
    Json(message): Json<ReadinessRequest>,
) -> Response {
    let Some(audit) = network.audit.get() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let source = peer
        .certificate_pin()
        .and_then(|pin| network.certificate_nodes.get(&pin).copied());
    if source != Some(message.source)
        || message.target != network.local_node_id
        || network.authorize(&message.group, message.source).is_err()
    {
        return network.denied(source, &message.group).await;
    }
    if audit
        .record(RequestAuditEvent {
            kind: RequestAuditKind::AuthenticationSucceeded,
            principal: Some(format!("peer:{}", message.source)),
            tenant: Some(message.group.clone()),
            request_id: uuid::Uuid::new_v4().to_string(),
        })
        .await
        .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Ok(Some(hash)) = network.fingerprint(&message.group) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(bytes) = encode_bounded(&hash, 4096) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if network.fingerprint(&message.group).is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    ([("content-type", "application/json")], bytes).into_response()
}

async fn receive_readiness(
    State(network): State<Arc<ClusterNetwork>>,
    Extension(peer): Extension<AuthenticatedTlsPeer>,
    Json(message): Json<ReadinessRequest>,
) -> Response {
    let Some(audit) = network.audit.get() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let source = peer
        .certificate_pin()
        .and_then(|pin| network.certificate_nodes.get(&pin).copied());
    if source != Some(message.source)
        || message.target != network.local_node_id
        || network.authorize(&message.group, message.source).is_err()
    {
        return network.denied(source, &message.group).await;
    }
    if audit
        .record(RequestAuditEvent {
            kind: RequestAuditKind::AuthenticationSucceeded,
            principal: Some(format!("peer:{}", message.source)),
            tenant: Some(message.group.clone()),
            request_id: uuid::Uuid::new_v4().to_string(),
        })
        .await
        .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Some(provider) = network.readiness.get().and_then(|p| p.upgrade()) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match provider.readiness(&message.group) {
        Ok(status) => Json(status).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[async_trait]
impl RaftTransport for ClusterNetwork {
    async fn send(
        &self,
        group: &str,
        source: u64,
        target: u64,
        _node: &BasicNode,
        request: RpcRequest,
    ) -> Result<RpcResponse> {
        ensure!(
            source == self.local_node_id && candidate(&request) == Some(source),
            "RPC source is not this authenticated node"
        );
        self.authorize(group, target)?;
        let peer = self
            .clients
            .get(&target)
            .context("unconfigured cluster peer")?;
        let _permit = self
            .outgoing
            .clone()
            .try_acquire_owned()
            .context("cluster transport is busy")?;
        let message = PeerRequest {
            group: group.into(),
            source,
            target,
            request,
            bootstrap_sha256: self.fingerprint(group)?,
        };
        let hint = smaller_append(&message.request);
        let bytes = encode_bounded(&message, self.limits.max_rpc_bytes)
            .map_err(|error| hint.clone().map_or(error, anyhow::Error::new))?;
        drop(message);
        let mut response = peer
            .client
            .post(peer.endpoint.clone())
            .header("content-type", "application/json")
            .body(bytes)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("authenticated cluster RPC failed"))?;
        if response.status() == reqwest::StatusCode::PAYLOAD_TOO_LARGE
            && let Some(hint) = hint
        {
            return Err(hint.into());
        }
        ensure!(
            response.status().is_success(),
            "cluster RPC rejected (HTTP {})",
            response.status().as_u16()
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("reading cluster response failed"))?
        {
            ensure!(
                bytes.len().saturating_add(chunk.len()) <= self.limits.max_rpc_bytes,
                "raft response exceeds transport byte limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).context("invalid cluster RPC response")
    }
}

#[async_trait]
impl kasumi_authority::AuthorityMaintenanceTransport for ClusterNetwork {
    async fn check_ready(
        &self,
        node_id: u64,
        bootstrap_sha256: &str,
        required_state_bytes: u64,
        command: &kasumi_serving::AuthorityMaintenanceCommand,
    ) -> Result<()> {
        let authority = self
            .maintenance
            .get()
            .and_then(|p| p.upgrade())
            .context("authority maintenance unavailable")?;
        authority.check_maintenance_ready(bootstrap_sha256, required_state_bytes, command)?;
        if node_id == self.local_node_id {
            return Ok(());
        }
        let group = &authority.installation().manifest.partitions
            [&authority.installation().partition]
            .group;
        // A prospective learner is not yet operationally admitted. This endpoint
        // only reserves installed resources; it cannot send Raft messages or grant leases.
        {
            let groups = self
                .groups
                .read()
                .map_err(|_| anyhow::anyhow!("cluster routes unavailable"))?;
            ensure!(
                groups
                    .get(group)
                    .is_some_and(|route| route.allowed_peers.contains(&node_id)),
                "maintenance peer is not installed"
            );
        }
        let _permit = self
            .outgoing
            .clone()
            .try_acquire_owned()
            .context("cluster transport busy")?;
        let peer = self
            .clients
            .get(&node_id)
            .context("maintenance peer is not installed")?;
        let mut endpoint = peer.endpoint.clone();
        endpoint.set_path(MAINTENANCE_PATH);
        let bytes = encode_bounded(
            &MaintenanceReadinessRequest {
                group: group.clone(),
                source: self.local_node_id,
                target: node_id,
                bootstrap_sha256: bootstrap_sha256.into(),
                required_state_bytes,
                command: command.clone(),
            },
            64 << 10,
        )?;
        let mut response = peer
            .client
            .post(endpoint)
            .header("content-type", "application/json")
            .body(bytes)
            .send()
            .await
            .context("authority maintenance peer unavailable")?;
        ensure!(
            response.status().is_success(),
            "authority maintenance peer rejected readiness"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len().saturating_add(chunk.len()) <= 4096,
                "maintenance readiness response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let response: MaintenanceReadinessResponse = serde_json::from_slice(&bytes)?;
        ensure!(
            response.node_id == node_id
                && response.bootstrap_sha256 == bootstrap_sha256
                && response.required_state_bytes == required_state_bytes
                && response.command_sha256 == command.digest()?,
            "maintenance peer response identity differs"
        );
        Ok(())
    }
}
async fn receive_maintenance(
    State(network): State<Arc<ClusterNetwork>>,
    Extension(peer): Extension<AuthenticatedTlsPeer>,
    Json(message): Json<MaintenanceReadinessRequest>,
) -> Response {
    let Some(audit) = network.audit.get() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let source = peer
        .certificate_pin()
        .and_then(|pin| network.certificate_nodes.get(&pin).copied());
    if source != Some(message.source)
        || message.target != network.local_node_id
        || network.authorize(&message.group, message.source).is_err()
    {
        return network.denied(source, &message.group).await;
    }
    let Some(authority) = network.maintenance.get().and_then(|p| p.upgrade()) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let installed = authority.installation();
    if installed.manifest.partitions[&installed.partition].group != message.group
        || authority
            .check_maintenance_ready(
                &message.bootstrap_sha256,
                message.required_state_bytes,
                &message.command,
            )
            .is_err()
    {
        return network.denied(source, &message.group).await;
    }
    if audit
        .record(RequestAuditEvent {
            kind: RequestAuditKind::AuthenticationSucceeded,
            principal: Some(format!("peer:{}", message.source)),
            tenant: Some(message.group.clone()),
            request_id: message.command.operation_id.to_string(),
        })
        .await
        .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Ok(command_sha256) = message.command.digest() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let response = MaintenanceReadinessResponse {
        node_id: network.local_node_id,
        bootstrap_sha256: message.bootstrap_sha256.clone(),
        required_state_bytes: message.required_state_bytes,
        command_sha256,
    };
    if authority
        .check_maintenance_ready(
            &message.bootstrap_sha256,
            message.required_state_bytes,
            &message.command,
        )
        .is_err()
        || network.authorize(&message.group, message.source).is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Json(response).into_response()
}

#[cfg(test)]
#[path = "authority_maintenance_tls_tests.rs"]
mod maintenance_tests;
