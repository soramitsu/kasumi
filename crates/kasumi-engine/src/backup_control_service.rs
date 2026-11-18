//! Only the installed source can prepare a claim. The Control command is private
//! and its point row is read back under a quorum barrier before external writes.
use super::*;
use kasumi_store::{AdmittedBackupBundle, VerifiedBackupSession};

pub(super) struct BackupControl {
    control: std::sync::Weak<Database>,
    operator: RequestContext,
}

fn unavailable() -> Error {
    Error::new(ErrorCode::Unavailable, "backup Control owner unavailable")
}

fn wrong_owner() -> Error {
    Error::new(
        ErrorCode::Conflict,
        "backup session belongs to a different source or destination",
    )
}

impl Database {
    /// Install the opened Control owner and its live operator. A restarted
    /// source must install its own handle before starting new sessions.
    pub fn install_backup_control(
        &self,
        control: &Arc<Database>,
        operator: &RequestContext,
    ) -> Result<()> {
        let generation = control.engine.generation()?;
        if !Arc::ptr_eq(&self.security_audit, &control.security_audit)
            || generation.tenant() != crate::control::CONTROL_TENANT
            || operator.tenant != crate::control::CONTROL_TENANT
        {
            return Err(wrong_owner());
        }
        operator.authorization.check_live()?;
        let installed = self.backup_control.get_or_init(|| BackupControl {
            control: Arc::downgrade(control),
            operator: operator.clone(),
        });
        if !installed.control.ptr_eq(&Arc::downgrade(control))
            || installed.operator.principal != operator.principal
        {
            return Err(wrong_owner());
        }
        Ok(())
    }

    fn backup_authority(&self) -> Result<Option<(Arc<Database>, RequestContext)>> {
        match self.backup_control.get() {
            Some(binding) => Ok(Some((
                binding.control.upgrade().ok_or_else(unavailable)?,
                binding.operator.clone(),
            ))),
            None if self.store.storage_access().purpose().is_local_fixture() => Ok(None),
            None => Err(unavailable()),
        }
    }

    async fn control_binding_point(
        &self,
        operator: &RequestContext,
        id: uuid::Uuid,
    ) -> Result<Option<BackupBindingRecord>> {
        self.engine.authorize(operator, None, Action::Admin)?;
        let fence = self.response_fence(operator)?;
        let token = QueryCancellation::default();
        let _cancel = CancelOnDrop(token.clone());
        let registration = self.work.begin(token.clone())?;
        let reservation = self.admission().reserve(8 << 20, Some(token.clone()))?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        let value = reservation
            .retained_read(token, move |_workspace, token| {
                let _registration = registration;
                token.check()?;
                generation
                    .backup_bindings
                    .get(id)
                    .map(|row| row.map(|row| row.record))
                    .map_err(|_| {
                        Error::new(ErrorCode::Corruption, "Control backup binding read failed")
                    })
            })
            .await?;
        fence.check()?;
        Ok(value)
    }

    pub(super) async fn backup_owner(
        &self,
        context: &RequestContext,
        destination: &dyn BackupDestination,
        id: uuid::Uuid,
    ) -> Result<Option<BackupBindingRecord>> {
        self.engine.authorize(context, None, Action::Admin)?;
        let fence = self.response_fence(context)?;
        let Some((control, operator)) = self.backup_authority()? else {
            return Ok(None);
        };
        let Some(record) = control.control_binding_point(&operator, id).await? else {
            return Ok(None);
        };
        let generation = self.engine.generation()?;
        if record.claim.tenant != context.tenant
            || (record.claim.source_incarnation != generation.incarnation()
                && !generation.state.restore_lineage.iter().any(|link| {
                    link.checkpoint.backup_id == id
                        && link.checkpoint.source_incarnation == record.claim.source_incarnation
                }))
        {
            return Err(wrong_owner());
        }
        if destination
            .verified_namespace_binding()
            .await
            .map_err(|_| unavailable())?
            != record.claim.namespace_binding
        {
            return Err(wrong_owner());
        }
        fence.check()?;
        Ok(Some(record))
    }

    pub(super) async fn require_backup_effect(
        &self,
        context: &RequestContext,
        destination: &dyn BackupDestination,
        session: &VerifiedBackupSession,
    ) -> Result<()> {
        if let Some(row) = self
            .backup_owner(context, destination, session.intent().session_id)
            .await?
        {
            if row.claim.intent_ciphertext_sha256 == session.intent_ciphertext_sha256()
                && row.claim.source_incarnation == self.engine.generation()?.incarnation()
            {
                return Ok(());
            }
        } else if self.store.storage_access().purpose().is_local_fixture()
            && self.backup_control.get().is_none()
        {
            return Ok(());
        }
        Err(wrong_owner())
    }

    pub(super) async fn claim_backup_intent(
        &self,
        context: &RequestContext,
        destination: &dyn BackupDestination,
        intent: &BackupSessionIntent,
        captured: &crate::Generation,
        alias: Option<&str>,
    ) -> Result<AdmittedBackupBundle> {
        intent.validate()?;
        if intent.tenant != captured.tenant()
            || intent.source_incarnation != captured.incarnation()
            || intent.revision != captured.state.revision
            || intent.principal != context.principal
            || intent.request_id != context.request_id
            || captured.state.retired
        {
            return Err(wrong_owner());
        }
        let epoch = captured.state.policy_epoch;
        self.engine
            .authorize_release(context, None, Action::Admin, epoch)?;
        let encrypt = || {
            self.store
                .encrypt_session_record(intent.revision, intent)
                .map_err(|_| Error::new(ErrorCode::Unavailable, "backup intent encryption failed"))
        };
        let Some((control, mut operator)) = self.backup_authority()? else {
            return encrypt();
        };
        let prior = self
            .backup_owner(context, destination, intent.session_id)
            .await?;
        let row = if let Some(row) = prior {
            row
        } else {
            let namespace_binding = destination
                .verified_namespace_binding()
                .await
                .map_err(|_| unavailable())?;
            let bytes = encrypt()?;
            let claim = BackupBindingClaim {
                session_id: intent.session_id,
                tenant: intent.tenant.clone(),
                source_incarnation: intent.source_incarnation.clone(),
                revision: intent.revision,
                source_purpose_sha256: staged_digest(self.store.storage_access().purpose())?.0,
                namespace_binding,
                binding_nonce: uuid::Uuid::new_v4(),
                principal: context.principal.clone(),
                request_id: context.request_id.clone(),
                destination_alias: alias.map(str::to_owned),
                command_id: uuid::Uuid::new_v4(),
                intent_ciphertext_sha256: hex::encode(Sha256::digest(bytes.as_bytes())),
                intent_ciphertext: bytes.as_bytes().to_vec(),
            };
            claim.validate()?;
            operator.request_id = claim.command_id.to_string();
            let cancellation = QueryCancellation::default();
            let source_work = self.work.begin(cancellation.clone())?;
            let control_work = control.work.begin(cancellation.clone())?;
            let reservation = control
                .admission()
                .reserve(16 << 20, Some(cancellation.clone()))?;
            let control_epoch = control.engine.generation()?.state.policy_epoch;
            let engine = self.engine.clone();
            let store = self.store.clone();
            let actor = context.clone();
            let db = control.clone();
            control.proposals.prepare(control.admission())?;
            let proposal = control.proposals.start_task(async move {
                let _owners = (source_work, control_work, reservation);
                let _gate = db.proposal_gate.lock().await;
                let preflight = || -> Result<()> {
                    cancellation.check()?;
                    store.check_access().map_err(|_| unavailable())?;
                    engine.authorize_release(&actor, None, Action::Admin, epoch)?;
                    db.access()?;
                    db.engine
                        .authorize_release(&operator, None, Action::Admin, control_epoch)?;
                    db.engine.admit_publication()
                };
                if let Err(denied) = preflight() {
                    return Ok(Err(denied));
                }
                let command = crate::state::backup_claim::ClaimCommand {
                    timestamp_ms: now_ms()?,
                    epoch: control_epoch,
                    context: operator,
                    claim,
                };
                let bytes = db
                    .group
                    .write(kasumi_raft::ApplicationProposal::generated(
                        command.encode()?,
                    ))
                    .await?;
                Ok(serde_json::from_slice::<Result<()>>(&bytes)?)
            })?;
            let result = proposal.wait(Duration::from_secs(30)).await?;
            if let Err(error) = result
                && error.code != ErrorCode::Conflict
            {
                return Err(error);
            }
            self.backup_owner(context, destination, intent.session_id)
                .await?
                .ok_or_else(unavailable)?
        };
        // A concurrent winner or a lost reply can be retried only for the exact
        // captured state and caller. Keep the first randomized ciphertext.
        if row.claim.revision != intent.revision
            || row.claim.principal != intent.principal
            || row.claim.request_id != intent.request_id
            || row.claim.source_incarnation != intent.source_incarnation
        {
            return Err(wrong_owner());
        }
        self.store
            .bound_backup_intent(&row)
            .map_err(|_| unavailable())
    }
}
