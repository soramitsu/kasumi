use crate::state::{Backend, PreparedCommand, PreparedOperation};
use crate::{
    AuthorityBootstrap, AuthorityInstallation, AuthorityMaintenanceTransport, AuthorityNodeSettings,
};
use anyhow::{Context, ensure};
use kasumi_clock::{EpochClock, LeaseClock};
use kasumi_raft::{BasicNode, Config, RaftGroup, RaftTransport};
use kasumi_serving::*;
use kasumi_store::TenantStorageSet;
use kasumi_types::drain::{DrainCompletion, DrainFailure, DrainReport, DrainResult};
use kasumi_types::{Error, ErrorCode, RequestContext, Result};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::sync::{OwnedRwLockReadGuard, OwnedSemaphorePermit, RwLock, Semaphore};
use uuid::Uuid;
#[path = "lifecycle_service.rs"]
mod lifecycle_service;
#[path = "maintenance_service.rs"]
mod maintenance_service;
#[path = "request_jobs.rs"]
mod request_jobs;
use request_jobs::RequestJobs;
pub use request_jobs::{AUTHORITY_REQUEST_SLOTS, authority_request_metadata_bytes};
#[path = "target_stop_service.rs"]
mod target_stop_service;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg_attr(test, track_caller)]
fn unavailable(_cause: impl std::fmt::Display) -> Error {
    #[cfg(test)]
    eprintln!(
        "AUTHORITY_UNAVAILABLE at {}: {}",
        std::panic::Location::caller(),
        _cause
    );
    Error::new(
        ErrorCode::Unavailable,
        "independent authority is unavailable",
    )
}
#[cfg_attr(test, track_caller)]
fn unknown(_cause: impl std::fmt::Display) -> Error {
    #[cfg(test)]
    eprintln!(
        "AUTHORITY_UNKNOWN at {}: {}",
        std::panic::Location::caller(),
        _cause
    );
    Error::new(
        ErrorCode::UnknownOutcome,
        "authority acknowledgement unavailable; resolve the exact permanent command identity",
    )
}
struct Drain {
    term: u64,
    started: Duration,
    last: Duration,
}
#[derive(Default)]
struct AuthorityShutdown {
    report: DrainReport,
    // A later opaque success cannot establish that a prior uncertain OpenRaft
    // census has resolved. Keep the original retained owner diagnostic.
    raft_unresolved: Option<DrainFailure>,
}

// Capacity and lifetime move together from admission through the returned
// response fence. Closing admission does not release an existing owner.
struct RequestPermit {
    _capacity: OwnedSemaphorePermit,
    _owner: OwnedRwLockReadGuard<()>,
}

/// Node credential constructed at the authenticated transport boundary. Raw
/// request metadata cannot supply the peer certificate or a live credential.
pub struct AuthenticatedNode {
    context: RequestContext,
    certificate_sha256: String,
}
impl AuthenticatedNode {
    /// Trusted server adapter only: `certificate_sha256` must come from the
    /// completed mTLS handshake, never the request. Deserialization is absent.
    pub fn from_verified_transport(
        context: RequestContext,
        certificate_sha256: String,
    ) -> Result<Self> {
        context.authorization.check_live()?;
        if context.authorization.expires_at_ms().is_none() {
            return Err(Error::new(
                ErrorCode::Unauthorized,
                "serving lease needs a verified expiring credential",
            ));
        }
        kasumi_types::validate_sha256(&certificate_sha256)?;
        Ok(Self {
            context,
            certificate_sha256,
        })
    }
}

pub struct AuthorityResponseFence {
    authority: Arc<IndependentAuthority>,
    signer: Arc<AuthoritySigner>,
    context: RequestContext,
    policy_epoch: Option<u64>,
    lease: Option<LeaseRequest>,
    lifecycle_lease: Option<LifecycleLeaseRequest>,
    term: u64,
    _permit: RequestPermit,
}
impl AuthorityResponseFence {
    pub async fn release(&self) -> Result<()> {
        if self.authority.barrier(&self.context).await? != self.term {
            return Err(unavailable("authority term changed before release"));
        }
        self.check()
    }
    pub fn check(&self) -> Result<()> {
        self.authority.check_open()?;
        self.context.authorization.check_live()?;
        self.authority.check_active_signer(&self.signer)?;
        if self.lease.is_some() || self.lifecycle_lease.is_some() {
            self.authority.check_issuance_signer(&self.signer)?;
        }
        self.authority.group.check_access().map_err(unavailable)?;
        self.authority
            .check_installed_configuration()
            .map_err(unavailable)?;
        if self.authority.term() != self.term {
            return Err(unavailable("authority term changed"));
        }
        if let Some(epoch) = self.policy_epoch
            && self.authority.backend.authorize_admin(&self.context)? != epoch
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "authority policy changed before acknowledgement",
            ));
        }
        if let Some(request) = &self.lease {
            self.authority
                .backend
                .lease_view(request)
                .map_err(unavailable)?;
        }
        if let Some(request) = &self.lifecycle_lease {
            let view = self
                .authority
                .backend
                .lifecycle_lease_view(request)
                .map_err(unavailable)?;
            if self.authority.clock.now_ms().map_err(unavailable)?
                >= view.commitment.intent.original_credential_expires_at_ms
            {
                return Err(Error::new(
                    ErrorCode::Unauthorized,
                    "original control credential expired before release",
                ));
            }
        }
        self.authority.check_open()
    }
}

pub struct IndependentAuthority {
    group: RaftGroup,
    backend: Arc<Backend>,
    signer: std::sync::RwLock<Arc<AuthoritySigner>>,
    clock: Arc<EpochClock>,
    elapsed: Arc<dyn LeaseClock>,
    proposal: tokio::sync::Mutex<()>,
    requests: Arc<Semaphore>,
    request_owners: Arc<RwLock<()>>,
    request_jobs: RequestJobs,
    shutdown_report: tokio::sync::Mutex<AuthorityShutdown>,
    drains: Mutex<BTreeMap<String, Drain>>,
    settings: AuthorityNodeSettings,
    local_node_id: u64,
    voters: BTreeMap<u64, BasicNode>,
    bootstrap: AuthorityBootstrap,
    bootstrap_digest: String,
    maintenance_transport: OnceLock<Arc<dyn AuthorityMaintenanceTransport>>,
    signer_publication_transport: OnceLock<Arc<dyn SignerPublicationTransport>>,
}
impl IndependentAuthority {
    /// Explicit first enrollment under exclusive installation ownership. This
    /// synchronous operation atomically publishes both authenticated domain
    /// identities, original genesis, local physical identity and resource floor.
    /// Existing, partial and unrelated state is never adopted or overwritten.
    pub fn initialize_storage(
        stores: &TenantStorageSet,
        installation: &AuthorityInstallation,
        bootstrap: &AuthorityBootstrap,
        verifier: &TrustVerifierIdentity,
    ) -> anyhow::Result<()> {
        crate::bootstrap::initialize(stores, installation, bootstrap, verifier)
    }

    pub fn bootstrap(&self) -> &AuthorityBootstrap {
        &self.bootstrap
    }
    /// The authority is an explicitly installed three-voter trust root. It has
    /// no local/downgrade opener and never uses a municipality data group.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_existing_replicated(
        stores: Arc<TenantStorageSet>,
        installation: AuthorityInstallation,
        signer: Arc<AuthoritySigner>,
        node_id: u64,
        settings: AuthorityNodeSettings,
        transport: Arc<dyn RaftTransport>,
        config: Config,
        request_budget: BackgroundWorkBudget,
        snapshot_buffers: Arc<kasumi_raft::SnapshotBufferOwner>,
    ) -> anyhow::Result<Arc<Self>> {
        Self::open_existing_with_clock(
            stores,
            installation,
            signer,
            node_id,
            settings,
            transport,
            config,
            request_budget,
            snapshot_buffers,
            EpochClock::system()?,
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn open_existing_with_clock(
        stores: Arc<TenantStorageSet>,
        installation: AuthorityInstallation,
        signer: Arc<AuthoritySigner>,
        node_id: u64,
        settings: AuthorityNodeSettings,
        transport: Arc<dyn RaftTransport>,
        config: Config,
        request_budget: BackgroundWorkBudget,
        snapshot_buffers: Arc<kasumi_raft::SnapshotBufferOwner>,
        clock: Arc<EpochClock>,
    ) -> anyhow::Result<Arc<Self>> {
        installation.validate()?;
        settings.validate(node_id)?;
        let request_jobs = RequestJobs::new(request_budget)?;
        ensure!(
            settings.installed_members[&node_id].verifier == signer.verifier_identity()?,
            "operational signer physical verifier differs from installed authority member"
        );
        let installed =
            crate::bootstrap::load(&stores, &installation, &signer.verifier_identity()?)?;
        let bootstrap = installed.bootstrap;
        let voters = bootstrap.voters();
        let partition = installation
            .manifest
            .partitions
            .get(&installation.partition)
            .context("partition absent")?;
        ensure!(
            signer.certificate().identity.domain
                == installation
                    .manifest
                    .signing_domain(installation.partition)?,
            "installed operational signer differs from authority installation root"
        );
        ensure!(
            signer.certificate().identity.generation != 1
                || *signer.certificate() == bootstrap.initial_signer_certificate,
            "generation-one signer differs from immutable bootstrap certificate"
        );
        signer.check()?;
        ensure!(
            settings.resource_budget_bytes >= installed.resource_floor,
            "authority resource budget is below its durably acknowledged maintenance floor"
        );
        let backend = Backend::open_existing(
            stores.application().clone(),
            installation.clone(),
            &bootstrap,
            settings.resource_budget_bytes,
        )?;
        let current = backend.operational_configuration()?;
        ensure!(
            current.capacity.max_state_bytes <= settings.resource_budget_bytes,
            "configured authority node resources cannot fit current durable capacity"
        );
        for (id, member) in current.membership.members {
            ensure!(
                settings.installed_members.get(&id) == Some(&member),
                "installed peer trust differs from committed authority membership"
            );
        }
        let bootstrap_digest = digest(&(
            "kasumi.authority-bootstrap.v1",
            &installation,
            &installed.binding,
        ))?;
        let group = RaftGroup::open(
            node_id,
            partition.group.clone(),
            stores,
            backend.clone(),
            transport,
            kasumi_raft::RaftGroupConfig {
                raft: config,
                limits: kasumi_raft::RaftLimits::default(),
            },
            snapshot_buffers,
        )
        .await?;
        Ok(Arc::new(Self {
            group,
            backend,
            signer: std::sync::RwLock::new(signer),
            elapsed: clock.elapsed_clock(),
            clock,
            proposal: tokio::sync::Mutex::new(()),
            requests: Arc::new(Semaphore::new(AUTHORITY_REQUEST_SLOTS)),
            request_owners: Arc::new(RwLock::new(())),
            request_jobs,
            shutdown_report: Default::default(),
            drains: Mutex::new(BTreeMap::new()),
            settings,
            local_node_id: node_id,
            voters,
            bootstrap,
            maintenance_transport: OnceLock::new(),
            signer_publication_transport: OnceLock::new(),
            bootstrap_digest,
        }))
    }
    pub fn bootstrap_digest(&self) -> &str {
        &self.bootstrap_digest
    }
    /// Trusted bootstrap orchestration invokes this only after authenticated
    /// peer fingerprints agree. Other voters never manufacture local membership.
    pub async fn initialize(&self) -> anyhow::Result<()> {
        let _permit = self.permit()?;
        if self.group.raft().metrics().borrow().id
            == *self
                .voters
                .first_key_value()
                .context("authority voters absent")?
                .0
            && !self.group.raft().is_initialized().await?
        {
            self.check_open()?;
            self.backend.require_genesis(&self.bootstrap)?;
            self.group.initialize(self.voters.clone()).await?;
        }
        self.check_open()?;
        Ok(())
    }
    pub fn raft_group(&self) -> &RaftGroup {
        &self.group
    }
    pub fn installation(&self) -> &AuthorityInstallation {
        self.backend.installation()
    }
    fn term(&self) -> u64 {
        self.group.raft().metrics().borrow().current_term
    }
    fn check_open(&self) -> Result<()> {
        self.request_jobs.observe(&self.requests);
        if self.requests.is_closed() {
            return Err(unavailable("independent authority is shutting down"));
        }
        Ok(())
    }
    fn permit(&self) -> Result<RequestPermit> {
        self.check_open()?;
        let capacity = self
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::Closed => {
                    unavailable("authority request admission closed")
                }
                tokio::sync::TryAcquireError::NoPermits => Error::new(
                    ErrorCode::ResourceExhausted,
                    "independent authority request limit reached",
                ),
            })?;
        let owner = self.operation_owner()?;
        Ok(RequestPermit {
            _capacity: capacity,
            _owner: owner,
        })
    }
    // Synchronous pinned peer/installation callbacks have no public response
    // fence. Track their work without consuming native request capacity: Raft
    // traffic must still progress when every public request slot is occupied.
    fn operation_owner(&self) -> Result<OwnedRwLockReadGuard<()>> {
        self.check_open()?;
        let owner = self
            .request_owners
            .clone()
            .try_read_owned()
            .map_err(unavailable)?;
        // Shutdown can close admission between the two synchronous acquisitions.
        // Such a contender must release both guards without becoming admitted.
        self.check_open()?;
        Ok(owner)
    }
    async fn barrier(&self, context: &RequestContext) -> Result<u64> {
        self.check_open()?;
        context.authorization.check_live()?;
        self.check_installed_configuration().map_err(unavailable)?;
        self.group
            .linearizable_barrier()
            .await
            .map_err(unavailable)?;
        context.authorization.check_live()?;
        self.check_open()?;
        Ok(self.term())
    }
    /// Bound the acknowledgement owner after dispatch. OpenRaft still owns any
    /// submitted entry and its storage work; dropping this wait neither rolls
    /// back the entry nor releases the group's tracked storage ownership. An
    /// uncertain caller resolves the same permanent command or phase identity.
    async fn write_proposal(&self, command: Vec<u8>, term: u64) -> Result<Vec<u8>> {
        self.check_open()?;
        let mut metrics = self.group.raft().metrics();
        let response = self.group.write(command);
        tokio::pin!(response);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let current = metrics.borrow().clone();
                if current.current_term != term
                    || current.current_leader != Some(self.local_node_id)
                    || current.running_state.is_err()
                {
                    #[cfg(any(test, feature = "test-utils"))]
                    eprintln!(
                        "AUTHORITY_PROPOSAL_ROUTE: local={} admitted_term={term} current={current:?}",
                        self.local_node_id
                    );
                    return Err(unknown("authority proposal leader changed"));
                }
                tokio::select! {
                    result = &mut response => return result.map_err(unknown),
                    changed = metrics.changed() => {
                        changed.map_err(unknown)?;
                    }
                }
            }
        })
        .await
        .map_err(unknown)?
    }
    fn route(&self, tenant: &str) -> Result<()> {
        if self
            .installation()
            .manifest
            .partition(tenant)
            .map_err(unavailable)?
            != self.installation().partition
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "tenant routed to another authority partition",
            ));
        }
        Ok(())
    }
    fn check_active_signer(&self, signer: &AuthoritySigner) -> Result<()> {
        signer.check().map_err(unavailable)?;
        if self.backend.signing_head().map_err(unavailable)?.active != *signer.certificate() {
            return Err(unavailable(
                "operational signer differs from replicated current generation",
            ));
        }
        Ok(())
    }
    fn check_issuance_signer(&self, signer: &AuthoritySigner) -> Result<()> {
        self.check_active_signer(signer)?;
        if self
            .backend
            .signing_head()
            .map_err(unavailable)?
            .staged
            .is_some()
        {
            return Err(unavailable(
                "signer rotation froze new old-generation lease admissions",
            ));
        }
        Ok(())
    }
    fn request_signer(&self) -> Result<Arc<AuthoritySigner>> {
        // Capture identity only. An admitted administrative effect can commit
        // while its old signer is sealed; signing and release then return an
        // unknown outcome for exact recovery through current administration.
        Ok(self.signer.read().map_err(unavailable)?.clone())
    }
    fn fence(
        self: &Arc<Self>,
        permit: RequestPermit,
        signer: Arc<AuthoritySigner>,
        context: RequestContext,
        policy_epoch: Option<u64>,
        lease: Option<LeaseRequest>,
        term: u64,
    ) -> AuthorityResponseFence {
        AuthorityResponseFence {
            authority: self.clone(),
            signer,
            context,
            policy_epoch,
            lease,
            lifecycle_lease: None,
            term,
            _permit: permit,
        }
    }
    pub async fn discover(
        self: &Arc<Self>,
        caller: AuthenticatedNode,
        request: LeaseDiscovery,
    ) -> Result<(ServingIdentity, AuthorityResponseFence)> {
        let permit = self.permit()?;
        let signer = self.request_signer()?;
        request
            .validate()
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid lease discovery"))?;
        self.route(&request.tenant)?;
        let context = caller.context;
        context.authorization.require_authority(
            self.installation().manifest.authority_id,
            self.installation().partition,
        )?;
        if context.tenant != self.installation().tenant()
            || !context.scopes.contains(&kasumi_types::Action::Read)
            || context.principal != request.node.principal
            || caller.certificate_sha256 != request.node.certificate_sha256
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "discovery credential or peer differs",
            ));
        }
        let term = self.barrier(&context).await?;
        let identity = self.backend.discover(&request).map_err(|_| {
            Error::new(
                ErrorCode::Forbidden,
                "requested incarnation is not available to this node",
            )
        })?;
        // This private observation is only a final current-state fence. It is
        // never signed or returned as a lease and creates no client clock anchor.
        let observation = LeaseRequest {
            manifest_digest: self.installation().manifest.digest().map_err(unavailable)?,
            identity: identity.clone(),
            boot_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            purpose: request.purpose,
        };
        if self.barrier(&context).await? != term {
            return Err(unavailable("discovery term changed"));
        }
        let fence = self.fence(
            permit,
            signer.clone(),
            context,
            None,
            Some(observation),
            term,
        );
        fence.check()?;
        Ok((identity, fence))
    }
    pub async fn acquire(
        self: &Arc<Self>,
        caller: AuthenticatedNode,
        request: LeaseRequest,
    ) -> Result<(SignedLease, AuthorityResponseFence)> {
        let permit = self.permit()?;
        let signer = self.request_signer()?;
        request
            .validate()
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid lease request"))?;
        self.route(&request.identity.tenant)?;
        let context = caller.context;
        context.authorization.require_authority(
            self.installation().manifest.authority_id,
            self.installation().partition,
        )?;
        if context.tenant != self.installation().tenant()
            || !context.scopes.contains(&kasumi_types::Action::Read)
            || context.principal != request.identity.node.principal
            || caller.certificate_sha256 != request.identity.node.certificate_sha256
            || request.manifest_digest
                != self.installation().manifest.digest().map_err(unavailable)?
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "lease credential, peer or installation binding differs",
            ));
        }
        let term = self.barrier(&context).await?;
        let (record, revision) = self
            .backend
            .lease_view(&request)
            .map_err(|_| Error::new(ErrorCode::Forbidden, "incarnation or node is fenced"))?;
        let now = self.clock.now_ms().map_err(unavailable)?;
        context.authorization.check_live()?;
        context.authorization.check_admitted_at(now)?;
        let max = self.installation().manifest.max_lease_ms;
        let remaining = context
            .authorization
            .expires_at_ms()
            .and_then(|expiry| expiry.checked_sub(now))
            .filter(|value| *value > 0)
            .ok_or_else(|| Error::new(ErrorCode::Unauthorized, "lease credential expired"))?;
        self.check_issuance_signer(&signer)?;
        let signed = signer
            .sign_lease(LeaseClaims {
                request: request.clone(),
                authority_id: self.installation().manifest.authority_id,
                partition: self.installation().partition,
                authority_term: term,
                authority_revision: revision,
                lifetime_ms: max,
                credential_lifetime_ms: max.min(remaining),
                activation_digest: record.activation_digest,
                recovery_checkpoint: record.recovery_checkpoint,
            })
            .map_err(unavailable)?;
        if self.barrier(&context).await? != term {
            return Err(unavailable("lease term changed"));
        }
        let fence = self.fence(permit, signer.clone(), context, None, Some(request), term);
        fence.check()?;
        Ok((signed, fence))
    }
    /// Reads are current-authorized observations, not new permanent command IDs.
    pub async fn receipt(
        self: &Arc<Self>,
        context: RequestContext,
        tenant: &str,
        command_id: Uuid,
    ) -> Result<(Option<SignedAuthorityReceipt>, AuthorityResponseFence)> {
        let permit = self.permit()?;
        let signer = self.request_signer()?;
        self.route(tenant)?;
        let term = self.barrier(&context).await?;
        let epoch = self.backend.authorize_admin(&context)?;
        let receipt = self
            .backend
            .receipt(tenant, command_id)
            .map_err(unavailable)?
            .map(|receipt| signer.sign_receipt(receipt).map_err(unavailable))
            .transpose()?;
        if self.barrier(&context).await? != term {
            return Err(unavailable("receipt term changed"));
        }
        let fence = self.fence(permit, signer.clone(), context, Some(epoch), None, term);
        fence.check()?;
        Ok((receipt, fence))
    }
    pub async fn execute(
        self: &Arc<Self>,
        context: RequestContext,
        command: AuthorityCommand,
    ) -> Result<(SignedAuthorityReceipt, AuthorityResponseFence)> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let permit = self.permit()?;
        let signer = self.request_signer()?;
        command
            .validate()
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid authority command"))?;
        self.route(&command.tenant)?;
        self.barrier(&context).await?;
        self.backend.authorize_admin(&context)?;
        // Own the permit until consensus and release actually finish, including
        // when the caller drops this future or receives an unknown outcome.
        let service = self.clone();
        self.accepted_request(deadline, async move {
            service
                .execute_owned(permit, signer, context, command)
                .await
        })
        .await
    }
    async fn execute_owned(
        self: Arc<Self>,
        permit: RequestPermit,
        signer: Arc<AuthoritySigner>,
        context: RequestContext,
        command: AuthorityCommand,
    ) -> Result<(SignedAuthorityReceipt, AuthorityResponseFence)> {
        let _gate = self.proposal.lock().await;
        let term = self.barrier(&context).await?;
        let epoch = self.backend.authorize_admin(&context)?;
        if let Some(retained) = self
            .backend
            .receipt(&command.tenant, command.command_id)
            .map_err(unavailable)?
        {
            if retained.command_digest != command.digest().map_err(unavailable)? {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "permanent command identity differs",
                ));
            }
            return self
                .release(permit, signer.clone(), context, retained, epoch, term)
                .await;
        }
        let drained_fence = match &command.action {
            AuthorityAction::Activate {
                fence_id,
                fence_digest,
                ..
            }
            | AuthorityAction::ActivateCommitted {
                fence_id,
                fence_digest,
                ..
            } => {
                let record = self
                    .backend
                    .tenant_record(&command.tenant)
                    .map_err(unavailable)?
                    .ok_or_else(|| Error::new(ErrorCode::Conflict, "source is not enrolled"))?;
                let fence = record.fence.ok_or_else(|| {
                    Error::new(ErrorCode::Conflict, "source lacks an authoritative fence")
                })?;
                if fence.command.command_id != *fence_id
                    || fence.digest().map_err(unavailable)? != *fence_digest
                {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "exact source fence differs",
                    ));
                }
                self.require_drain(fence_digest, term)?;
                Some(fence_digest.clone())
            }
            _ => None,
        };
        let admitted_at_ms = self.clock.now_ms().map_err(unavailable)?;
        context.authorization.check_live()?;
        context.authorization.check_admitted_at(admitted_at_ms)?;
        if admitted_at_ms > command.not_after_ms || epoch != command.expected_policy_epoch {
            return Err(Error::new(
                ErrorCode::Conflict,
                "authority command expired or policy changed",
            ));
        }
        // Drain witnesses are checked again at the serialized admission point;
        // no wait or caller-controlled timestamp is replicated as authority.
        if let Some(fence_digest) = &drained_fence {
            self.require_drain(fence_digest, term)?;
        }
        let prepared = PreparedCommand {
            context: context.clone(),
            command,
            admitted_at_ms,
            authority_term: term,
            drained_fence,
        };
        let bytes = self
            .write_proposal(
                serde_json::to_vec(&PreparedOperation::Administrative(Box::new(prepared)))
                    .map_err(unavailable)?,
                term,
            )
            .await?;
        let receipt: Result<AuthorityReceipt> = serde_json::from_slice(&bytes).map_err(unknown)?;
        self.release(permit, signer.clone(), context, receipt?, epoch, term)
            .await
            .map_err(unknown)
    }
    fn require_drain(&self, digest: &str, term: u64) -> Result<()> {
        let mut drains = self.drains.lock().map_err(unavailable)?;
        require_drain_witness(
            &mut drains,
            digest,
            term,
            self.elapsed.now(),
            Duration::from_millis(
                self.installation()
                    .manifest
                    .drain_ms()
                    .expect("validated immutable clock rate bound"),
            ),
            10_000,
        )?;
        if self.term() != term {
            return Err(unavailable("drain authority term changed"));
        }
        Ok(())
    }
    async fn release(
        self: &Arc<Self>,
        permit: RequestPermit,
        signer: Arc<AuthoritySigner>,
        context: RequestContext,
        receipt: AuthorityReceipt,
        epoch: u64,
        term: u64,
    ) -> Result<(SignedAuthorityReceipt, AuthorityResponseFence)> {
        if self.barrier(&context).await? != term {
            return Err(unavailable("authority response term changed"));
        }
        let fence = self.fence(permit, signer.clone(), context, Some(epoch), None, term);
        fence.check()?;
        let signed = signer.sign_receipt(receipt).map_err(unavailable)?;
        fence.check()?;
        Ok((signed, fence))
    }
    /// Close admission and response release synchronously before listener drain.
    pub fn close_admission(&self) {
        self.request_jobs.close(&self.requests);
    }
    pub async fn shutdown(&self) -> DrainResult {
        self.close_admission();
        let mut shutdown = self.shutdown_report.lock().await;
        let mut retained = None;
        // Join children before taking the owner writer: their live request
        // permits and undelivered response fences can hold its read guards.
        if let Err(failure) = self.request_jobs.drain(&self.requests).await {
            shutdown.report.merge(&failure);
            if failure.completion() == DrainCompletion::Retained {
                retained = Some(failure);
            }
        }
        if retained.is_some() {
            return shutdown.report.outcome(retained);
        }
        // Never hold proposal while draining admitted jobs. Cancelling this
        // waiter leaves every original request/response read owner installed.
        let _owners = self.request_owners.write().await;
        let _gate = self.proposal.lock().await;
        shutdown.raft_unresolved = match self.group.shutdown().await {
            Ok(()) => None,
            Err(failure) => {
                shutdown.report.merge(&failure);
                (failure.completion() == DrainCompletion::Retained).then_some(failure)
            }
        };
        shutdown
            .report
            .outcome(retained.or_else(|| shutdown.raft_unresolved.clone()))
    }
}

/// Eviction only removes a completed observation. Its permanent stop remains in
/// replicated state, and requesting an evicted witness starts a full new wait.
fn require_drain_witness(
    drains: &mut BTreeMap<String, Drain>,
    digest: &str,
    term: u64,
    now: Duration,
    required: Duration,
    capacity: usize,
) -> Result<()> {
    drains.retain(|_, drain| drain.term == term);
    // Reset all observations on regression before choosing an eviction; an
    // unobserved backwards jump cannot preserve a previously completed witness.
    for drain in drains.values_mut() {
        if now < drain.last {
            drain.started = now;
        }
        drain.last = now;
    }
    if !drains.contains_key(digest) && drains.len() >= capacity {
        let evict = drains.iter().find_map(|(key, drain)| {
            now.checked_sub(drain.started)
                .filter(|elapsed| *elapsed >= required)
                .map(|_| key.clone())
        });
        if let Some(key) = evict {
            drains.remove(&key);
        } else {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "active authority drain witness limit reached",
            ));
        }
    }
    let drain = drains.entry(digest.to_owned()).or_insert(Drain {
        term,
        started: now,
        last: now,
    });
    if now
        .checked_sub(drain.started)
        .is_none_or(|elapsed| elapsed < required)
    {
        return Err(Error::new(
            ErrorCode::Unavailable,
            "exact fence drain has not completed; retry the same identity",
        ));
    }
    Ok(())
}

#[path = "signer_administration.rs"]
mod signer_administration;
pub use signer_administration::{AuthorityAdministrativeFence, CommittedSignerDirective};

#[path = "signing_administration.rs"]
mod signing_administration;
pub use signing_administration::AuthoritySigningResponseFence;
#[path = "control_signer_service.rs"]
mod control_signer_service;
pub use control_signer_service::ControlSignerObservationFence;
#[path = "signer_coverage_service.rs"]
mod signer_coverage_service;
pub use signer_coverage_service::{SignerCoverageFence, SignerPublicationTransport};
