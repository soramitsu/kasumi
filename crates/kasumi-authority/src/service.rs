use crate::state::{Backend, PreparedCommand, PreparedOperation};
use crate::{AuthorityInstallation, AuthorityMaintenanceTransport, AuthorityNodeSettings};
use anyhow::{Context, ensure};
use kasumi_clock::{EpochClock, LeaseClock};
use kasumi_raft::{BasicNode, Config, RaftGroup, RaftTransport};
use kasumi_serving::*;
use kasumi_store::TenantStorageSet;
use kasumi_types::{Error, ErrorCode, RequestContext, Result};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;
#[path = "lifecycle_service.rs"]
mod lifecycle_service;
#[path = "maintenance_service.rs"]
mod maintenance_service;
#[path = "target_stop_service.rs"]
mod target_stop_service;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

fn unavailable(_: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::Unavailable,
        "independent authority is unavailable",
    )
}
fn unknown(_: impl std::fmt::Display) -> Error {
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
}
impl AuthorityResponseFence {
    pub async fn release(&self) -> Result<()> {
        if self.authority.barrier(&self.context).await? != self.term {
            return Err(unavailable("authority term changed before release"));
        }
        self.check()
    }
    pub fn check(&self) -> Result<()> {
        self.context.authorization.check_live()?;
        self.signer.check().map_err(unavailable)?;
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
        Ok(())
    }
}

pub struct IndependentAuthority {
    group: RaftGroup,
    backend: Arc<Backend>,
    signer: Arc<AuthoritySigner>,
    clock: Arc<EpochClock>,
    elapsed: Arc<dyn LeaseClock>,
    proposal: tokio::sync::Mutex<()>,
    requests: Arc<Semaphore>,
    drains: Mutex<BTreeMap<String, Drain>>,
    settings: AuthorityNodeSettings,
    local_node_id: u64,
    voters: BTreeMap<u64, BasicNode>,
    bootstrap_digest: String,
    maintenance_transport: OnceLock<Arc<dyn AuthorityMaintenanceTransport>>,
}
impl IndependentAuthority {
    /// The authority is an explicitly installed three-voter trust root. It has
    /// no local/downgrade opener and never uses a municipality data group.
    pub async fn open_replicated(
        stores: Arc<TenantStorageSet>,
        installation: AuthorityInstallation,
        signer: Arc<AuthoritySigner>,
        node_id: u64,
        settings: AuthorityNodeSettings,
        transport: Arc<dyn RaftTransport>,
        config: Config,
    ) -> anyhow::Result<Arc<Self>> {
        Self::open_with_clock(
            stores,
            installation,
            signer,
            node_id,
            settings,
            transport,
            config,
            EpochClock::system()?,
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn open_with_clock(
        stores: Arc<TenantStorageSet>,
        installation: AuthorityInstallation,
        signer: Arc<AuthoritySigner>,
        node_id: u64,
        settings: AuthorityNodeSettings,
        transport: Arc<dyn RaftTransport>,
        config: Config,
        clock: Arc<EpochClock>,
    ) -> anyhow::Result<Arc<Self>> {
        installation.validate()?;
        settings.validate(node_id)?;
        let voters = settings.bootstrap.voters();
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
        signer.check()?;
        let binding = serde_json::to_vec(&(
            "kasumi.independent-authority.v2",
            &installation,
            &settings.bootstrap,
        ))?;
        match stores
            .application()
            .get("authority.installation", b"binding")?
        {
            Some(bytes) => ensure!(bytes == binding, "authority voters or installation changed"),
            None => stores
                .application()
                .write_batch(&[kasumi_store::WriteOp::put(
                    "authority.installation",
                    b"binding",
                    binding.clone(),
                )])?,
        }
        let local_binding = serde_json::to_vec(&("kasumi.authority-member.v1", node_id))?;
        match stores
            .application()
            .get("authority.installation", b"local-member")?
        {
            Some(bytes) => ensure!(
                bytes == local_binding,
                "authority storage cannot reopen under another member identity"
            ),
            None => stores
                .application()
                .write_batch(&[kasumi_store::WriteOp::put(
                    "authority.installation",
                    b"local-member",
                    local_binding,
                )])?,
        }
        let required_bytes = stores
            .application()
            .get_bounded("authority.installation", b"resource-floor", 32)?
            .map(|bytes| serde_json::from_slice::<u64>(&bytes))
            .transpose()?
            .unwrap_or(settings.bootstrap.capacity.max_state_bytes);
        ensure!(
            settings.resource_budget_bytes >= required_bytes,
            "authority resource budget is below its durably acknowledged maintenance floor"
        );
        let backend = Backend::install(
            stores.application().clone(),
            installation.clone(),
            &settings,
        )?;
        ensure!(
            backend
                .operational_configuration()?
                .capacity
                .max_state_bytes
                <= settings.resource_budget_bytes,
            "configured authority node resources cannot fit current durable capacity"
        );
        for (id, member) in backend.operational_configuration()?.membership.members {
            ensure!(
                settings.installed_members.get(&id) == Some(&member),
                "installed peer trust differs from committed authority membership"
            );
        }
        let group = RaftGroup::open(
            node_id,
            partition.group.clone(),
            stores,
            backend.clone(),
            transport,
            config,
        )
        .await?;
        Ok(Arc::new(Self {
            group,
            backend,
            signer,
            elapsed: clock.elapsed_clock(),
            clock,
            proposal: tokio::sync::Mutex::new(()),
            requests: Arc::new(Semaphore::new(32)),
            drains: Mutex::new(BTreeMap::new()),
            settings,
            local_node_id: node_id,
            voters,
            maintenance_transport: OnceLock::new(),
            bootstrap_digest: digest(&("kasumi.authority-bootstrap.v1", &installation, &binding))?,
        }))
    }
    pub fn bootstrap_digest(&self) -> &str {
        &self.bootstrap_digest
    }
    /// Trusted bootstrap orchestration invokes this only after authenticated
    /// peer fingerprints agree. Other voters never manufacture local membership.
    pub async fn initialize(&self) -> anyhow::Result<()> {
        if self.group.raft().metrics().borrow().id
            == *self
                .voters
                .first_key_value()
                .context("authority voters absent")?
                .0
            && !self.group.raft().is_initialized().await?
        {
            self.group.initialize(self.voters.clone()).await?;
        }
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
    fn permit(&self) -> Result<OwnedSemaphorePermit> {
        self.requests.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "independent authority request limit reached",
            )
        })
    }
    async fn barrier(&self, context: &RequestContext) -> Result<u64> {
        context.authorization.check_live()?;
        self.check_installed_configuration().map_err(unavailable)?;
        self.group
            .linearizable_barrier()
            .await
            .map_err(unavailable)?;
        context.authorization.check_live()?;
        Ok(self.term())
    }
    /// Bound the acknowledgement owner after dispatch. OpenRaft still owns any
    /// submitted entry and its storage work; dropping this wait neither rolls
    /// back the entry nor releases the group's tracked storage ownership. An
    /// uncertain caller resolves the same permanent command or phase identity.
    async fn write_proposal(&self, command: Vec<u8>, term: u64) -> Result<Vec<u8>> {
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
    fn fence(
        self: &Arc<Self>,
        context: RequestContext,
        policy_epoch: Option<u64>,
        lease: Option<LeaseRequest>,
        term: u64,
    ) -> AuthorityResponseFence {
        AuthorityResponseFence {
            authority: self.clone(),
            signer: self.signer.clone(),
            context,
            policy_epoch,
            lease,
            lifecycle_lease: None,
            term,
        }
    }
    pub async fn discover(
        self: &Arc<Self>,
        caller: AuthenticatedNode,
        request: LeaseDiscovery,
    ) -> Result<(ServingIdentity, AuthorityResponseFence)> {
        let _permit = self.permit()?;
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
        let fence = self.fence(context, None, Some(observation), term);
        fence.check()?;
        Ok((identity, fence))
    }
    pub async fn acquire(
        self: &Arc<Self>,
        caller: AuthenticatedNode,
        request: LeaseRequest,
    ) -> Result<(SignedLease, AuthorityResponseFence)> {
        let _permit = self.permit()?;
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
        let signed = self
            .signer
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
        let fence = self.fence(context, None, Some(request), term);
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
        let _permit = self.permit()?;
        self.route(tenant)?;
        let term = self.barrier(&context).await?;
        let epoch = self.backend.authorize_admin(&context)?;
        let receipt = self
            .backend
            .receipt(tenant, command_id)
            .map_err(unavailable)?
            .map(|receipt| self.signer.sign_receipt(receipt).map_err(unavailable))
            .transpose()?;
        if self.barrier(&context).await? != term {
            return Err(unavailable("receipt term changed"));
        }
        let fence = self.fence(context, Some(epoch), None, term);
        fence.check()?;
        Ok((receipt, fence))
    }
    pub async fn execute(
        self: &Arc<Self>,
        context: RequestContext,
        command: AuthorityCommand,
    ) -> Result<(SignedAuthorityReceipt, AuthorityResponseFence)> {
        let permit = self.permit()?;
        command
            .validate()
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid authority command"))?;
        self.route(&command.tenant)?;
        self.barrier(&context).await?;
        self.backend.authorize_admin(&context)?;
        // Own the permit until consensus and release actually finish, including
        // when the caller drops this future or receives an unknown outcome.
        let service = self.clone();
        let job = tokio::spawn(async move {
            let _permit = permit;
            service.execute_owned(context, command).await
        });
        tokio::time::timeout(Duration::from_secs(5), job)
            .await
            .map_err(unknown)?
            .map_err(unknown)?
    }
    async fn execute_owned(
        self: Arc<Self>,
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
            return self.release(context, retained, epoch, term, false).await;
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
        self.release(context, receipt?, epoch, term, true).await
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
        context: RequestContext,
        receipt: AuthorityReceipt,
        epoch: u64,
        term: u64,
        accepted: bool,
    ) -> Result<(SignedAuthorityReceipt, AuthorityResponseFence)> {
        let result = async {
            if self.barrier(&context).await? != term {
                return Err(unavailable("authority response term changed"));
            }
            let fence = self.fence(context, Some(epoch), None, term);
            fence.check()?;
            let signed = self.signer.sign_receipt(receipt).map_err(unavailable)?;
            fence.check()?;
            Ok((signed, fence))
        }
        .await;
        if accepted {
            result.map_err(unknown)
        } else {
            result
        }
    }
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.requests.close();
        let _gate = self.proposal.lock().await;
        self.group.shutdown().await
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
