//! A data-only node reaches its dedicated Control quorum only through installed,
//! pinned mTLS routes to the Control voters' administrative listeners. It
//! admits only topology observations that the installed Control root signed for
//! this node's own request, client certificate and credential digest. A reply
//! never adds a route, member, endpoint or trust anchor.
//!
//! Outage: startup waits (cancellably) for the first verified observation;
//! afterwards serving keeps the newest verified topology and route changes wait
//! for Control. Protected observations stay available and report the access
//! state. Admission: every observation reserves its bounded response and decode
//! workspace from node admission before dispatch, and the retained topology
//! keeps a resident charge. Shutdown: `close` refuses new observations and
//! cancels the one in flight; `drain` joins every registered observation and
//! then drops the installed routes, before the runtime releases node storage.
use crate::{
    runtime::{CONTROL_TENANT, DeploymentMode, RuntimeConfig, TlsFiles, credential_path},
    serving_runtime::AuthorityEndpoint,
};
use anyhow::{Context, Result, ensure};
use kasumi_client::{ClientError, KasumiLifecyclePool};
use kasumi_engine::{
    admission::{NodeAdmission, Reservation},
    control::{ControlTopology, TenantRoute},
};
use kasumi_types::{
    Action, ControlSigningRoot, MAX_CONTROL_TOPOLOGY_BYTES, MAX_CONTROL_TOPOLOGY_LIFETIME_MS,
    RequestContext,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};

#[cfg(test)]
#[path = "remote_control_tests.rs"]
mod tests;

/// Response, decode and verification workspace of one observation. The client
/// refuses a reply above `MAX_CONTROL_TOPOLOGY_BYTES`; the remaining charge
/// covers its decoded form and the signed digest input.
const OBSERVATION_CHARGE: u64 = 3 * MAX_CONTROL_TOPOLOGY_BYTES as u64;
/// First retry delay after a failed observation; it doubles up to the
/// installed refresh interval.
const FIRST_RETRY: Duration = Duration::from_millis(250);

/// Installed routes from a data-only node to its dedicated Control quorum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteControlConfig {
    /// The dedicated Control's installed lifecycle signing root. Its
    /// incarnation identifies the only Control this node accepts.
    pub root: ControlSigningRoot,
    /// The Control voters' administrative listeners, keyed by Control node ID.
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
    pub endpoints: BTreeMap<u64, AuthorityEndpoint>,
    /// This node's own client identity at those listeners.
    pub tls: TlsFiles,
    /// The CA that issued the Control listeners' certificates.
    pub server_ca: PathBuf,
    /// The routing principal named by the Control credential in `bearer_file`.
    pub principal: String,
    /// A Control credential with `read` scope and a committed `topology`
    /// grant, renewed by atomic rename. Its plaintext is never configured.
    pub bearer_file: String,
    /// Control principals admitted to this node's protected observations.
    pub observers: BTreeSet<String>,
    pub refresh_interval_ms: u64,
    pub request_timeout_ms: u64,
}

impl RemoteControlConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        self.root.validate()?;
        crate::installed_clients::validate(&self.endpoints)?;
        self.tls.validate()?;
        ensure!(
            self.server_ca.is_absolute(),
            "remote Control CA path must be absolute"
        );
        kasumi_types::validate_name(&self.principal)?;
        credential_path(&self.bearer_file)?;
        ensure!(
            (1..=64).contains(&self.observers.len()),
            "remote Control access needs one to 64 protected observer principals"
        );
        for observer in &self.observers {
            kasumi_types::validate_name(observer)?;
        }
        ensure!(
            (1_000..=600_000).contains(&self.refresh_interval_ms)
                && (1_000..=60_000).contains(&self.request_timeout_ms),
            "remote Control refresh or request timeout outside bounds"
        );
        Ok(())
    }
}

/// Node-level checks of a data-only installation. Control and data member IDs,
/// endpoints and certificate pins stay separate, as in the shared routing
/// catalog that the dedicated Control enrolled.
pub(crate) fn validate_data_only(
    config: &RuntimeConfig,
    remote: &RemoteControlConfig,
) -> Result<()> {
    remote.validate()?;
    ensure!(
        config.mode == DeploymentMode::Replicated
            && config.control.is_none()
            && !config.tenants.is_empty()
            && config.target_recovery.is_none(),
        "remote Control access requires a replicated data-only node with local tenants"
    );
    let replication = config
        .replication
        .as_ref()
        .context("data-only node requires its data replication roster")?;
    let mut origins = BTreeSet::new();
    let mut pins = BTreeSet::new();
    for peer in &replication.peers {
        origins.insert(
            crate::runtime::origin(&peer.endpoint)?
                .origin()
                .ascii_serialization(),
        );
        pins.extend(peer.certificate_pins.iter().cloned());
    }
    for (id, member) in &remote.endpoints {
        ensure!(
            !replication.peers.iter().any(|peer| peer.node_id == *id)
                && !origins.contains(
                    &crate::runtime::origin(&member.endpoint)?
                        .origin()
                        .ascii_serialization()
                )
                && member.certificate_pins.is_disjoint(&pins),
            "remote Control reuses a data node ID, endpoint or certificate pin"
        );
    }
    Ok(())
}

/// One verified observation, retained as the node's routing source.
pub(crate) struct RemoteTopology {
    pub version: u64,
    pub topology: ControlTopology,
    pub policy_epoch: u64,
    pub revision: u64,
    pub term: u64,
    pub leader: u64,
    pub voters: BTreeSet<u64>,
    digest: [u8; 32],
    _resident: Reservation,
}
impl RemoteTopology {
    /// Routes whose voters include `node`, in tenant order.
    pub(crate) fn local_routes(&self, node: u64) -> impl Iterator<Item = (&String, &TenantRoute)> {
        self.topology
            .tenants
            .iter()
            .filter(move |(_, route)| route.voters.contains(&node))
    }
}

/// Fixed classes; no peer-controlled text leaves this boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Unreachable,
    Denied,
    InvalidResponse,
    Expired,
    Regressed,
    Inconsistent,
    Admission,
    Closed,
}
impl Failure {
    pub(crate) fn class(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::Denied => "denied",
            Self::InvalidResponse => "invalid_response",
            Self::Expired => "expired",
            Self::Regressed => "regressed",
            Self::Inconsistent => "inconsistent",
            Self::Admission => "admission",
            Self::Closed => "closed",
        }
    }
    /// The installed pool reports unreachable members as transport statuses.
    /// A verification failure of an actual reply (signature, root, request or
    /// caller binding, deadline) arrives as a checked client error instead.
    fn of(error: &ClientError) -> Self {
        let denied = |code: tonic::Code| {
            matches!(
                code,
                tonic::Code::PermissionDenied | tonic::Code::Unauthenticated
            )
        };
        match error {
            ClientError::Authorization => Self::Denied,
            ClientError::Transport(status) if denied(status.code()) => Self::Denied,
            ClientError::DecodeRejected { code, .. } if denied(*code) => Self::Denied,
            ClientError::Transport(_) => Self::Unreachable,
            _ => Self::InvalidResponse,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "remote Control observation failed: {}",
            self.class()
        )
    }
}
impl std::error::Error for Failure {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccessState {
    /// No observation has been verified yet.
    Connecting,
    /// The newest observation attempt succeeded.
    Current,
    /// The newest attempt failed; serving keeps the last verified topology.
    Unavailable,
    /// Shutdown refused further observations.
    Closed,
}

/// The protected diagnostic of a data-only node's Control dependency.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct RemoteControlStatus {
    pub state: AccessState,
    pub control_incarnation: uuid::Uuid,
    pub topology_version: Option<u64>,
    pub control_revision: Option<u64>,
    pub control_term: Option<u64>,
    pub control_leader: Option<u64>,
    pub verified_age_seconds: Option<f64>,
    pub consecutive_failures: u32,
    pub last_failure: Option<&'static str>,
}

struct State {
    state: AccessState,
    current: Option<(Arc<RemoteTopology>, Instant)>,
    consecutive_failures: u32,
    last_failure: Option<Failure>,
}

/// Registered observations; shutdown seals the fence and joins them.
#[derive(Default)]
struct Fence {
    state: Mutex<(bool, usize)>,
    idle: tokio::sync::Notify,
}
struct Registration<'a>(&'a Fence);
impl Fence {
    fn begin(&self) -> Option<Registration<'_>> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.0 {
            return None;
        }
        state.1 += 1;
        Some(Registration(self))
    }
    fn seal(&self) {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).0 = true;
    }
    fn active(&self) -> usize {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).1
    }
    async fn drain(&self) {
        loop {
            let idle = self.idle.notified();
            tokio::pin!(idle);
            idle.as_mut().enable();
            if self.active() == 0 {
                return;
            }
            idle.await;
        }
    }
}
impl Drop for Registration<'_> {
    fn drop(&mut self) {
        self.0.state.lock().unwrap_or_else(|p| p.into_inner()).1 -= 1;
        self.0.idle.notify_waiters();
    }
}

/// The single client boundary between a data-only node and its remote Control.
pub(crate) struct RemoteControl {
    root: ControlSigningRoot,
    principal: String,
    observers: BTreeSet<String>,
    refresh: Duration,
    timeout: Duration,
    admission: Arc<NodeAdmission>,
    // One observation at a time. Taking the pool drops its installed routes
    // and aborts any connection still being established for a later attempt.
    pool: tokio::sync::Mutex<Option<KasumiLifecyclePool>>,
    fence: Fence,
    closed: watch::Sender<bool>,
    state: Mutex<State>,
    verified: watch::Sender<u64>,
}

impl RemoteControl {
    /// Load the installed identity, CA and credential route. No network I/O.
    pub(crate) fn open(
        config: &RemoteControlConfig,
        admission: Arc<NodeAdmission>,
    ) -> Result<Arc<Self>> {
        config.validate()?;
        let connections = crate::installed_clients::connections(
            &config.endpoints,
            &config.tls,
            &config.server_ca,
        )?;
        let trust = kasumi_serving::ControlTrust::install(config.root.clone())?;
        let credential: Arc<dyn kasumi_transport::credentials::CredentialSource> = Arc::new(
            kasumi_transport::credentials::FileCredentialSource::new(&config.bearer_file)?,
        );
        let pool = KasumiLifecyclePool::new(connections, trust, credential)?;
        Ok(Arc::new(Self {
            root: config.root.clone(),
            principal: config.principal.clone(),
            observers: config.observers.clone(),
            refresh: Duration::from_millis(config.refresh_interval_ms),
            timeout: Duration::from_millis(config.request_timeout_ms),
            admission,
            pool: tokio::sync::Mutex::new(Some(pool)),
            fence: Fence::default(),
            closed: watch::channel(false).0,
            state: Mutex::new(State {
                state: AccessState::Connecting,
                current: None,
                consecutive_failures: 0,
                last_failure: None,
            }),
            verified: watch::channel(0).0,
        }))
    }

    pub(crate) fn control_incarnation(&self) -> uuid::Uuid {
        self.root.control_incarnation
    }

    /// The newest verified topology, retained across a Control outage.
    pub(crate) fn topology(&self) -> kasumi_types::Result<Arc<RemoteTopology>> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .current
            .as_ref()
            .map(|(topology, _)| topology.clone())
            .ok_or_else(|| {
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Unavailable,
                    "remote Control topology has not been verified",
                )
            })
    }

    pub(crate) fn status(&self) -> RemoteControlStatus {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let current = state.current.as_ref();
        RemoteControlStatus {
            state: state.state,
            control_incarnation: self.root.control_incarnation,
            topology_version: current.map(|(t, _)| t.version),
            control_revision: current.map(|(t, _)| t.revision),
            control_term: current.map(|(t, _)| t.term),
            control_leader: current.map(|(t, _)| t.leader),
            verified_age_seconds: current.map(|(_, at)| at.elapsed().as_secs_f64()),
            consecutive_failures: state.consecutive_failures,
            last_failure: state.last_failure.map(Failure::class),
        }
    }

    /// Protected observations on a data-only node: a live Control credential
    /// for this exact Control incarnation, issued to an installed observer.
    pub(crate) fn authorize_observer(&self, context: &RequestContext) -> kasumi_types::Result<()> {
        context.authorization.check_live()?;
        context
            .authorization
            .require_control(&self.root.control_incarnation.to_string())?;
        if context.tenant != CONTROL_TENANT
            || !self.observers.contains(&context.principal)
            || !(context.scopes.contains(&Action::Read) || context.scopes.contains(&Action::Admin))
        {
            return Err(kasumi_types::Error::new(
                kasumi_types::ErrorCode::Forbidden,
                "protected observation requires an installed remote Control observer",
            ));
        }
        Ok(())
    }

    /// Perform one authenticated observation and retain it if it is newer.
    pub(crate) async fn refresh(&self) -> Result<Arc<RemoteTopology>, Failure> {
        let _registration = self.fence.begin().ok_or(Failure::Closed)?;
        let result = self.observe().await;
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if *self.closed.borrow() {
            state.state = AccessState::Closed;
            return Err(Failure::Closed);
        }
        match &result {
            Ok(_) => {
                state.state = AccessState::Current;
                state.consecutive_failures = 0;
                state.last_failure = None;
            }
            Err(Failure::Closed) => state.state = AccessState::Closed,
            Err(failure) => {
                if state.state != AccessState::Closed {
                    state.state = if state.current.is_some() {
                        AccessState::Unavailable
                    } else {
                        AccessState::Connecting
                    };
                }
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                state.last_failure = Some(*failure);
            }
        }
        result
    }

    async fn observe(&self) -> Result<Arc<RemoteTopology>, Failure> {
        let mut closed = self.closed.subscribe();
        if *closed.borrow_and_update() {
            return Err(Failure::Closed);
        }
        let _workspace = self
            .admission
            .reserve(OBSERVATION_CHARGE, None)
            .map_err(|_| Failure::Admission)?;
        let observed = {
            let mut pool = self.pool.lock().await;
            let pool = pool.as_mut().ok_or(Failure::Closed)?;
            tokio::select! {
                biased;
                _ = closed.wait_for(|closed| *closed) => return Err(Failure::Closed),
                observed = pool.observe_topology(
                    &self.principal,
                    MAX_CONTROL_TOPOLOGY_LIFETIME_MS,
                    self.timeout,
                ) => observed.map_err(|error| Failure::of(&error))?,
            }
        };
        let observation = observed.observation().map_err(|_| Failure::Expired)?;
        if observation.root != self.root {
            return Err(Failure::InvalidResponse);
        }
        let encoded =
            serde_json::to_vec(&observation.topology).map_err(|_| Failure::InvalidResponse)?;
        let retained = kasumi_engine::admission::json_decode_workspace(&encoded)
            .map_err(|_| Failure::InvalidResponse)?
            .max(encoded.len() as u64);
        let retained = retained
            .checked_add((observation.voters.len() as u64).saturating_mul(128))
            .and_then(|n| n.checked_add(std::mem::size_of::<RemoteTopology>() as u64 + 64))
            .ok_or(Failure::Admission)?;
        let resident = self
            .admission
            .reserve_resident(retained)
            .map_err(|_| Failure::Admission)?;
        let topology = Arc::new(RemoteTopology {
            version: observation.topology.version,
            topology: observation.topology.topology.clone(),
            policy_epoch: observation.policy_epoch,
            revision: observation.revision,
            term: observation.term,
            leader: observation.leader_node_id,
            voters: observation.voters.clone(),
            digest: Sha256::digest(&encoded).into(),
            _resident: resident,
        });
        drop(observed);
        self.admit(topology)
    }

    fn admit(&self, topology: Arc<RemoteTopology>) -> Result<Arc<RemoteTopology>, Failure> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if *self.closed.borrow() {
            return Err(Failure::Closed);
        }
        if let Some((current, _)) = &state.current {
            // A quorum read never moves a committed version backward, and one
            // version names exactly one committed topology.
            if topology.version < current.version
                || topology.revision < current.revision
                || topology.term < current.term
                || topology.policy_epoch < current.policy_epoch
            {
                return Err(Failure::Regressed);
            }
            if (topology.version == current.version && topology.digest != current.digest)
                || (topology.term == current.term && topology.leader != current.leader)
                || (topology.revision == current.revision
                    && (topology.version != current.version
                        || topology.voters != current.voters
                        || topology.policy_epoch != current.policy_epoch))
            {
                return Err(Failure::Inconsistent);
            }
        }
        let version = topology.version;
        state.current = Some((topology.clone(), Instant::now()));
        drop(state);
        self.verified.send_replace(version);
        Ok(topology)
    }

    /// Startup: wait for the first verified topology. Failures retry with a
    /// bounded backoff; the caller cancels this through its shutdown branch.
    pub(crate) async fn wait_verified(&self) -> Result<Arc<RemoteTopology>> {
        let mut delay = FIRST_RETRY;
        loop {
            match self.refresh().await {
                Ok(topology) => return Ok(topology),
                Err(Failure::Closed) => return Err(Failure::Closed.into()),
                Err(failure) => {
                    crate::startup_progress::phase(
                        "waiting for the remote Control topology",
                        failure.class(),
                    );
                }
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(self.refresh);
        }
    }

    /// The serving task inventory owns this loop. Each observation is awaited
    /// inline; stopping never drops an unobserved spawned request.
    pub(crate) async fn refresh_while_serving(
        self: Arc<Self>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut delay = self.refresh;
        loop {
            if *stop.borrow() {
                break;
            }
            tokio::select! {
                _ = stop.changed() => break,
                _ = tokio::time::sleep(delay) => {}
            }
            if *stop.borrow() {
                break;
            }
            delay = match self.refresh().await {
                Ok(_) => self.refresh,
                Err(Failure::Closed) => break,
                Err(failure) => {
                    tracing::warn!(
                        event = "remote_control_unavailable",
                        failure = failure.class(),
                        "remote Control observation failed; serving keeps the last verified topology"
                    );
                    FIRST_RETRY.max(delay / 2).min(self.refresh)
                }
            };
        }
        Ok(())
    }

    /// Refuse new observations and cancel the one in flight.
    pub(crate) fn close(&self) {
        self.fence.seal();
        self.closed.send_replace(true);
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.state = AccessState::Closed;
    }

    /// Join every registered observation, then drop the installed routes.
    pub(crate) async fn drain(&self) {
        self.close();
        self.fence.drain().await;
        drop(self.pool.lock().await.take());
        // The retained topology's charge returns with its owner.
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .current
            .take();
    }

    #[cfg(test)]
    pub(crate) fn active_observations(&self) -> usize {
        self.fence.active()
    }

    #[cfg(test)]
    pub(crate) fn subscribe_verified(&self) -> watch::Receiver<u64> {
        self.verified.subscribe()
    }
}
