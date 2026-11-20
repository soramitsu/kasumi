//! A pending backup authority is created only by an authorized live source.
//! Its wire reference must be resolved at that original physical member.
use super::*;
use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
};
pub type RemoteBackupFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub trait RemoteBackupTransport: Send + Sync {
    fn control_incarnation(&self) -> uuid::Uuid;
    fn execute<'a>(
        &'a self,
        source: Arc<BackupSourceCapability>,
        action: RemoteBackupAction,
    ) -> RemoteBackupFuture<'a, Option<RemoteBackupRecord>>;
    fn inventory<'a>(
        &'a self,
        _source: Arc<BackupSourceCapability>,
        _read: BackupInventoryRead,
    ) -> RemoteBackupFuture<'a, BackupInventoryPage> {
        Box::pin(async { Err(unavailable()) })
    }
}
pub trait RemoteBackupSourceVerifier: Send + Sync {
    fn confirm<'a>(
        &'a self,
        source: &'a RemoteBackupChallenge,
        actor: &'a RequestContext,
        peer: &'a str,
    ) -> RemoteBackupFuture<'a, RemoteBackupConfirmation>;
}

pub struct BackupSourceCapability {
    restore_session: Option<uuid::Uuid>,
    reference: RemoteBackupReference,
    group: RaftGroup,
    engine: Arc<TenantEngine>,
    store: Arc<TenantStore>,
    work: Arc<WorkFence>,
    context: RequestContext,
    epoch: u64,
    active: AtomicBool,
    deadline: tokio::time::Instant,
}
/// The physical callback owns its source and quorum registration through
/// encoding. The wire observation alone cannot perform its release check.
pub struct VerifiedBackupSource {
    observation: RemoteBackupConfirmation,
    source: Arc<BackupSourceCapability>,
    quorum: SourceQuorum,
    cancellation: QueryCancellation,
    _cancel: CancelOnDrop,
    _registration: WorkRegistration,
}
impl VerifiedBackupSource {
    pub fn observation(&self) -> &RemoteBackupConfirmation {
        &self.observation
    }
    pub fn release(&self) -> Result<()> {
        self.cancellation.check()?;
        self.quorum.check()?;
        self.source.live()
    }
}

impl BackupSourceCapability {
    pub fn reference(&self) -> &RemoteBackupReference {
        &self.reference
    }
    fn close(&self) {
        self.active.store(false, Ordering::Release);
    }
    fn live(&self) -> Result<()> {
        if !self.active.load(Ordering::Acquire) || tokio::time::Instant::now() >= self.deadline {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "backup source capability expired or closed",
            ));
        }
        self.store
            .check_access()
            .map_err(|e| unavailable().with_physical_source(e))?;
        self.engine
            .authorize_release(&self.context, None, Action::Admin, self.epoch)?;
        let state = self.engine.generation()?;
        if state.state.retired || state.incarnation() != self.reference.source_incarnation {
            return Err(wrong_owner());
        }
        Ok(())
    }
    pub async fn confirm(
        self: &Arc<Self>,
        challenge: &RemoteBackupChallenge,
    ) -> Result<VerifiedBackupSource> {
        if self.reference != challenge.reference || challenge.challenge.is_nil() {
            return Err(wrong_owner());
        }
        self.live()?;
        let cancellation = QueryCancellation::default();
        let _registration = self.work.begin(cancellation.clone())?;
        let _cancel = CancelOnDrop(cancellation.clone());
        let quorum = SourceQuorum::observe(&self.group)
            .await?
            .ok_or_else(unavailable)?;
        let metrics = self.group.metrics();
        let membership = metrics.membership_config.membership();
        let [voters] = membership.get_joint_config().as_slice() else {
            return Err(unavailable());
        };
        let purpose = self.store.storage_access().purpose();
        let kasumi_store::StoragePurpose::Serving { identity, .. } = purpose else {
            return Err(wrong_owner());
        };
        if identity.node.node_id != self.reference.source_node
            || identity.tenant != self.reference.tenant
            || identity.incarnation.to_string() != self.reference.source_incarnation
        {
            return Err(wrong_owner());
        }
        let confirmation = RemoteBackupConfirmation {
            original: challenge.clone(),
            restore_source_incarnation: match self.restore_session {
                Some(id) => self
                    .engine
                    .generation()?
                    .state
                    .restore_lineage
                    .iter()
                    .find(|link| link.checkpoint.backup_id == id)
                    .map(|link| link.checkpoint.source_incarnation.clone()),
                None => None,
            },
            policy_epoch: self.epoch,
            purpose_sha256: staged_digest(purpose)?.0,
            source_certificate_sha256: identity.node.certificate_sha256.clone(),
            term: quorum.term,
            leader: quorum.leader,
            committed_term: quorum.observed.leader_id.term,
            committed_index: quorum.observed.index,
            membership_term: quorum.membership.leader_id.term,
            membership_index: quorum.membership.index,
            voters: voters.clone(),
        };
        confirmation.validate()?;
        let selected = VerifiedBackupSource {
            observation: confirmation,
            source: self.clone(),
            quorum,
            cancellation,
            _registration,
            _cancel,
        };
        selected.release()?;
        Ok(selected)
    }
}
struct ActiveSource(Arc<BackupSourceCapability>);
impl Drop for ActiveSource {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl Database {
    pub fn install_remote_backup_transport(
        &self,
        transport: Arc<dyn RemoteBackupTransport>,
    ) -> Result<()> {
        if self.backup_control.get().is_some()
            || self.group.is_local()
            || !matches!(
                self.store.storage_access().purpose(),
                kasumi_store::StoragePurpose::Serving { .. }
            )
        {
            return Err(wrong_owner());
        }
        if !Arc::ptr_eq(
            self.remote_backup.get_or_init(|| transport.clone()),
            &transport,
        ) {
            return Err(wrong_owner());
        }
        Ok(())
    }
    pub fn install_remote_backup_verifier(
        &self,
        verifier: Arc<dyn RemoteBackupSourceVerifier>,
    ) -> Result<()> {
        if self.store.tenant() != crate::control::CONTROL_TENANT || self.group.is_local() {
            return Err(wrong_owner());
        }
        if !Arc::ptr_eq(
            self.remote_backup_verifier.get_or_init(|| verifier.clone()),
            &verifier,
        ) {
            return Err(wrong_owner());
        }
        Ok(())
    }

    fn backup_source_capability(
        &self,
        transport: &Arc<dyn RemoteBackupTransport>,
        context: &RequestContext,
        session: uuid::Uuid,
        action_sha256: String,
        restore_session: Option<uuid::Uuid>,
    ) -> Result<ActiveSource> {
        self.access()?;
        self.engine.authorize(context, None, Action::Admin)?;
        let generation = self.engine.generation()?;
        let reference = RemoteBackupReference {
            nonce: uuid::Uuid::new_v4(),
            control_incarnation: transport.control_incarnation(),
            source_node: self.group.node_id(),
            tenant: context.tenant.clone(),
            source_incarnation: generation.incarnation().into(),
            session,
            action_sha256,
        };
        reference.validate()?;
        let cap = ActiveSource(Arc::new(BackupSourceCapability {
            restore_session,
            reference,
            group: self.group.clone(),
            engine: self.engine.clone(),
            store: self.store.clone(),
            work: self.work.clone(),
            context: context.clone(),
            epoch: generation.state.policy_epoch,
            active: AtomicBool::new(true),
            deadline: tokio::time::Instant::now() + Duration::from_secs(30),
        }));
        cap.0.live()?;
        Ok(cap)
    }

    pub(in crate::service) async fn remote_inventory_page(
        &self,
        transport: &Arc<dyn RemoteBackupTransport>,
        context: &RequestContext,
        read: BackupInventoryRead,
    ) -> Result<BackupInventoryPage> {
        let fence = self.response_fence(context)?;
        let cap =
            self.backup_source_capability(transport, context, read.scan, read.digest()?, None)?;
        let command = BackupInventoryCommand {
            reference: cap.0.reference.clone(),
            read: read.clone(),
        };
        let page = transport.inventory(cap.0.clone(), read).await?;
        page.validate(&command)?;
        cap.0.live()?;
        fence.check()?;
        Ok(page)
    }

    pub(super) async fn remote_backup_action(
        &self,
        transport: &Arc<dyn RemoteBackupTransport>,
        context: &RequestContext,
        action: RemoteBackupAction,
    ) -> Result<Option<RemoteBackupRecord>> {
        let fence = self.response_fence(context)?;
        action.validate()?;
        let cap = self.backup_source_capability(
            transport,
            context,
            action.session(),
            staged_digest(&action)?.0,
            Some(action.session()),
        )?;
        let observed = transport.execute(cap.0.clone(), action).await?;
        if let Some(record) = &observed {
            record.validate()?;
            if record.record.claim.session_id != cap.0.reference.session
                || record.record.claim.tenant != context.tenant
            {
                return Err(wrong_owner());
            }
        }
        cap.0.live()?;
        fence.check()?;
        Ok(observed)
    }

    pub(super) fn authorize_remote_backup(
        &self,
        actor: &RequestContext,
        epoch: Option<u64>,
    ) -> Result<()> {
        actor.authorization.check_live()?;
        let generation = self.engine.generation()?;
        crate::state::backup_claim::authorize_delegation(&generation.state, actor)?;
        if epoch.is_some_and(|epoch| epoch != generation.state.policy_epoch) {
            return Err(wrong_owner());
        }
        Ok(())
    }
    fn remote_backup_route(
        &self,
        actor: &RequestContext,
        peer: &str,
        confirmation: &RemoteBackupConfirmation,
    ) -> Result<(u64, u64)> {
        self.access()?;
        let selected = self.engine.generation()?;
        let state = &selected.state;
        actor.authorization.require_control(&state.incarnation)?;
        self.authorize_remote_backup(actor, None)?;
        let origin = &confirmation.original.reference;
        if actor.tenant != crate::control::CONTROL_TENANT
            || origin.control_incarnation.to_string() != state.incarnation
            || state.retired
            || state.suspended
            || state
                .lifecycle_control
                .as_ref()
                .is_none_or(|c| c.retired || c.pending_change.is_some())
            || confirmation.source_certificate_sha256 != peer
        {
            return Err(wrong_owner());
        }
        let version = crate::state::backup_claim::route_version(&selected, confirmation)
            .map_err(document_load_error)?
            .ok_or_else(wrong_owner)?;
        Ok((state.policy_epoch, version))
    }
}

impl Database {
    fn require_backup_leader(&self) -> Result<()> {
        if self.group.metrics().current_leader != Some(self.group.node_id()) {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "backup binding requires the current Control leader",
            ));
        }
        Ok(())
    }
    async fn confirm_backup_reference(
        &self,
        verifier: &dyn RemoteBackupSourceVerifier,
        actor: &RequestContext,
        peer: &str,
        reference: &RemoteBackupReference,
    ) -> Result<RemoteBackupConfirmation> {
        let challenge = RemoteBackupChallenge {
            reference: reference.clone(),
            challenge: uuid::Uuid::new_v4(),
        };
        let confirmation = verifier.confirm(&challenge, actor, peer).await?;
        confirmation.validate()?;
        if confirmation.original != challenge {
            return Err(wrong_owner());
        }
        Ok(confirmation)
    }
    async fn confirm_remote_source(
        &self,
        verifier: &dyn RemoteBackupSourceVerifier,
        actor: &RequestContext,
        peer: &str,
        command: &RemoteBackupCommand,
    ) -> Result<(RemoteBackupConfirmation, u64, u64)> {
        let confirmation = self
            .confirm_backup_reference(verifier, actor, peer, &command.reference)
            .await?;
        if let RemoteBackupAction::Claim { claim } = &command.action
            && claim.source_purpose_sha256 != confirmation.purpose_sha256
        {
            return Err(wrong_owner());
        }
        let (epoch, version) = self.remote_backup_route(actor, peer, &confirmation)?;
        Ok((confirmation, epoch, version))
    }

    /// Only a dedicated Control with an enrolled source callback transport may
    /// execute this command. The incoming body alone cannot yield a claim.
    pub async fn execute_remote_backup(
        self: &Arc<Self>,
        actor: RequestContext,
        peer: String,
        command: RemoteBackupCommand,
    ) -> Result<crate::AdmittedOutput<Option<RemoteBackupRecord>>> {
        let result = self
            .execute_remote_backup_inner(&actor, &peer, command)
            .await;
        self.audit_result(&actor, result).await
    }
    async fn execute_remote_backup_inner(
        self: &Arc<Self>,
        actor: &RequestContext,
        peer: &str,
        command: RemoteBackupCommand,
    ) -> Result<crate::AdmittedOutput<Option<RemoteBackupRecord>>> {
        self.access()?;
        actor
            .authorization
            .require_control(&self.engine.generation()?.state.incarnation)?;
        self.authorize_remote_backup(actor, None)?;
        validate_sha256(peer)?;
        command.validate()?;
        let verifier = self
            .remote_backup_verifier
            .get()
            .cloned()
            .ok_or_else(unavailable)?;
        let token = QueryCancellation::default();
        let _cancel = CancelOnDrop(token.clone());
        let read_job = self.work.begin(token.clone())?;
        let mut reply_workspace = self
            .admission()
            .reserve_waiting(3 * MAX_REMOTE_BACKUP_BYTES as u64, Some(token.clone()))?;
        if !matches!(command.action, RemoteBackupAction::Read { .. }) {
            self.require_backup_leader()?;
        }
        self.control_binding_barrier().await?;
        let (initial, epoch, version) = self
            .confirm_remote_source(verifier.as_ref(), actor, peer, &command)
            .await?;
        if !matches!(command.action, RemoteBackupAction::Read { .. }) {
            let db = self.clone();
            let grant = actor.clone();
            let peer = peer.to_owned();
            let original = command.clone();
            let admitted = initial.clone();
            let source = verifier.clone();
            let owned = self.work.begin(token.clone())?;
            let workspace = self
                .admission()
                .reserve_waiting(3 * MAX_REMOTE_BACKUP_BYTES as u64, Some(token.clone()))?;
            self.proposals.prepare(self.admission())?;
            let proposal = self.proposals.start_task(async move {
                let _held = (owned, workspace);
                let _gate = db.proposal_gate.lock().await;
                // A caller refusal or failed physical write is an ordinary
                // result of this retained child. A failed child itself closes
                // the proposal registry, so do not turn either into a panic
                // or outer worker error.
                let submitted: Result<Result<()>> = async {
                    token.check()?;
                    db.require_backup_leader()?;
                    db.control_binding_barrier().await?;
                    let (fresh, current_epoch, current_version) = db
                        .confirm_remote_source(source.as_ref(), &grant, &peer, &original)
                        .await?;
                    if current_epoch != epoch
                        || current_version != version
                        || !same_authority(&admitted, &fresh)
                    {
                        return Err(wrong_owner());
                    }
                    token.check()?;
                    db.access()?;
                    db.authorize_remote_backup(&grant, Some(epoch))?;
                    let (claim, terminal) = match original.action {
                        RemoteBackupAction::Claim { claim } => (claim, None),
                        RemoteBackupAction::Decide { claim, terminal } => (claim, Some(*terminal)),
                        RemoteBackupAction::Read { .. } => return Err(wrong_owner()),
                    };
                    db.engine.admit_publication()?;
                    let record = crate::state::backup_claim::ClaimCommand {
                        timestamp_ms: now_ms()?,
                        epoch,
                        context: grant,
                        remote_source: Some(Box::new(crate::state::backup_claim::Delegation {
                            confirmation: fresh,
                            topology_version: version,
                        })),
                        claim,
                        terminal,
                    };
                    db.require_backup_leader()?;
                    let result = db
                        .group
                        .write(kasumi_raft::ApplicationProposal::generated(
                            record.encode().map_err(|e| {
                                Error::new(ErrorCode::InvalidArgument, "invalid backup claim")
                                    .with_physical_source(e)
                            })?,
                        ))
                        .await
                        .map_err(|e| {
                            Error::new(
                                ErrorCode::UnknownOutcome,
                                "backup binding write requires resolution",
                            )
                            .with_physical_source(e)
                        })?;
                    serde_json::from_slice::<Result<()>>(&result).map_err(|e| {
                        Error::new(ErrorCode::Corruption, "invalid applied backup outcome")
                            .with_physical_source(e.into())
                    })
                }
                .await;
                Ok(submitted)
            })?;
            if let Err(error) = proposal.wait(Duration::from_secs(30)).await??
                && error.code != ErrorCode::Conflict
            {
                return Err(error);
            }
        }
        let selected = self
            .control_binding_point_for(actor, command.reference.session, true)
            .await?;
        let (released, current_epoch, current_version) = self
            .confirm_remote_source(verifier.as_ref(), actor, peer, &command)
            .await?;
        if epoch != current_epoch
            || version != current_version
            || !same_authority(&initial, &released)
            || selected.as_ref().is_some_and(|entry| {
                entry.record.claim.tenant != command.reference.tenant
                    || (entry.record.claim.source_incarnation
                        != command.reference.source_incarnation
                        && released.restore_source_incarnation.as_ref()
                            != Some(&entry.record.claim.source_incarnation))
            })
        {
            return Err(wrong_owner());
        }
        if !matches!(command.action, RemoteBackupAction::Read { .. }) && selected.is_none() {
            return Err(wrong_owner());
        }
        self.authorize_remote_backup(actor, Some(epoch))?;
        drop(read_job);
        reply_workspace.retain_workspace();
        Ok(crate::AdmittedOutput::new(
            selected,
            Arc::new(reply_workspace),
        ))
    }
}
fn same_authority(one: &RemoteBackupConfirmation, two: &RemoteBackupConfirmation) -> bool {
    one.original.reference == two.original.reference
        && one.policy_epoch == two.policy_epoch
        && one.restore_source_incarnation == two.restore_source_incarnation
        && one.purpose_sha256 == two.purpose_sha256
        && one.source_certificate_sha256 == two.source_certificate_sha256
        && one.term == two.term
        && one.leader == two.leader
        && one.membership_term == two.membership_term
        && one.membership_index == two.membership_index
        && one.voters == two.voters
        && two.committed_index >= one.committed_index
}

#[path = "remote_backup_inventory_control.rs"]
mod inventory;
