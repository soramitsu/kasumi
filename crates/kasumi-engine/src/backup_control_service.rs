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

/// Position at which the data group confirmed this source's authority. This
/// is independent of the original application's snapshot revision and of the
/// subsequent Control log entry. A caller cannot deserialize this evidence.
struct SourceQuorum {
    group: RaftGroup,
    term: u64,
    leader: u64,
    membership: kasumi_raft::LogId<u64>,
    observed: kasumi_raft::LogId<u64>,
}

impl SourceQuorum {
    fn changed() -> Error {
        Error::new(
            ErrorCode::Unavailable,
            "backup source quorum or membership changed",
        )
    }

    async fn observe(group: &RaftGroup) -> Result<Option<Self>> {
        if group.is_local() {
            return Ok(None);
        }
        let first = group.metrics();
        let observed = group
            .observation_barrier()
            .await
            .map_err(|cause| Self::changed().with_physical_source(cause))?
            .ok_or_else(Self::changed)?;
        let position = Self {
            group: group.clone(),
            term: first.current_term,
            leader: first.current_leader.ok_or_else(Self::changed)?,
            membership: (*first.membership_config.log_id()).ok_or_else(Self::changed)?,
            observed,
        };
        position.check()?;
        Ok(Some(position))
    }

    fn check(&self) -> Result<()> {
        let current = self.group.metrics();
        if current.current_term != self.term
            || current.current_leader != Some(self.leader)
            || self.observed.index < self.membership.index
            || current.membership_config.log_id() != &Some(self.membership)
            || current
                .membership_config
                .membership()
                .get_node(&current.id)
                .is_none()
            || !current
                .membership_config
                .membership()
                .voter_ids()
                .any(|id| id == self.leader)
            || current
                .last_applied
                .is_none_or(|id| id < self.observed || id < self.membership)
        {
            return Err(Self::changed());
        }
        Ok(())
    }
}

pub(super) struct SelectedBackup {
    pub record: BackupBindingRecord,
    pub terminal: Option<BackupBindingTerminal>,
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

    pub(super) fn backup_authority(&self) -> Result<Option<(Arc<Database>, RequestContext)>> {
        match self.backup_control.get() {
            Some(binding) => Ok(Some((
                binding.control.upgrade().ok_or_else(unavailable)?,
                binding.operator.clone(),
            ))),
            None if self.store.storage_access().purpose().is_local_fixture() => Ok(None),
            None => Err(unavailable()),
        }
    }

    /// A data leader may hold a follower of its installed Control group.
    /// Read binding records only after that member applies the current leader's
    /// authenticated quorum index. Mutations still pass through proposal admission.
    pub(super) async fn control_binding_barrier(&self) -> Result<()> {
        self.access()?;
        self.group.observation_barrier().await.map_err(|original| {
            Error::new(
                ErrorCode::Unavailable,
                "Control backup binding quorum unavailable",
            )
            .with_physical_source(original)
        })?;
        self.access()
    }

    async fn control_binding_point(
        &self,
        operator: &RequestContext,
        id: uuid::Uuid,
    ) -> Result<Option<SelectedBackup>> {
        self.engine.authorize(operator, None, Action::Admin)?;
        let fence = self.response_fence(operator)?;
        let token = QueryCancellation::default();
        let _cancel = CancelOnDrop(token.clone());
        let registration = self.work.begin(token.clone())?;
        let reservation = self.admission().reserve(8 << 20, Some(token.clone()))?;
        self.control_binding_barrier().await?;
        let generation = self.engine.generation()?;
        let value = reservation
            .retained_read(token, move |_workspace, token| {
                let _registration = registration;
                token.check()?;
                let read = || -> anyhow::Result<_> {
                    let claim = generation.backup_bindings.get(id)?;
                    let terminal = generation.backup_bindings.terminal(id)?;
                    Ok(claim.map(|row| SelectedBackup {
                        record: row.record,
                        terminal: terminal.and_then(|t| t.terminal),
                    }))
                };
                read().map_err(|original| {
                    Error::new(ErrorCode::Corruption, "Control backup binding read failed")
                        .with_physical_source(original)
                })
            })
            .await?;
        fence.check()?;
        Ok(value)
    }

    pub(super) async fn selected_backup(
        &self,
        context: &RequestContext,
        destination: &dyn BackupDestination,
        id: uuid::Uuid,
    ) -> Result<Option<SelectedBackup>> {
        self.engine.authorize(context, None, Action::Admin)?;
        let fence = self.response_fence(context)?;
        let Some((control, operator)) = self.backup_authority()? else {
            return Ok(None);
        };
        let Some(selected) = control.control_binding_point(&operator, id).await? else {
            return Ok(None);
        };
        let record = &selected.record;
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
            .map_err(|original| unavailable().with_physical_source(original))?
            != record.claim.namespace_binding
        {
            return Err(wrong_owner());
        }
        fence.check()?;
        Ok(Some(selected))
    }

    pub(super) async fn backup_owner(
        &self,
        context: &RequestContext,
        destination: &dyn BackupDestination,
        id: uuid::Uuid,
    ) -> Result<Option<BackupBindingRecord>> {
        Ok(self
            .selected_backup(context, destination, id)
            .await?
            .map(|selected| selected.record))
    }

    /// A committed Control row can survive a failed source dispatch. Replaying
    /// its original ciphertext still requires a live source quorum before the
    /// first external create, including when invoked through Abort.
    pub(super) async fn original_backup_intent_for_effect(
        &self,
        context: &RequestContext,
        row: &BackupBindingRecord,
    ) -> Result<AdmittedBackupBundle> {
        let fence = self.response_fence(context)?;
        self.engine.authorize(context, None, Action::Admin)?;
        if row.claim.tenant != context.tenant
            || row.claim.source_incarnation != self.engine.generation()?.incarnation()
        {
            return Err(wrong_owner());
        }
        let source = SourceQuorum::observe(&self.group).await?;
        let bytes = self
            .store
            .bound_backup_intent(row)
            .map_err(|original| unavailable().with_physical_source(original))?;
        if let Some(source) = source {
            source.check()?;
        }
        fence.check()?;
        Ok(bytes)
    }

    pub(super) async fn require_backup_effect(
        &self,
        context: &RequestContext,
        destination: &dyn BackupDestination,
        session: &VerifiedBackupSession,
    ) -> Result<()> {
        let fence = self.response_fence(context)?;
        if let Some(row) = self
            .backup_owner(context, destination, session.intent().session_id)
            .await?
        {
            if row.claim.intent_ciphertext_sha256 == session.intent_ciphertext_sha256()
                && row.claim.source_incarnation == self.engine.generation()?.incarnation()
            {
                let _source = SourceQuorum::observe(&self.group).await?;
                return fence.check();
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
        // The intent carries this store's key catalog, and every later object
        // of the session a catalog that is no older. Refuse a session whose
        // catalog still names a version that a key retirement fenced.
        self.require_unfenced_catalog(&captured.state.key_retirements)?;
        let encrypt = || {
            self.store
                .encrypt_session_record(intent.revision, intent)
                .map_err(|original| {
                    Error::new(ErrorCode::Unavailable, "backup intent encryption failed")
                        .with_physical_source(original)
                })
        };
        let Some((control, operator)) = self.backup_authority()? else {
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
                .map_err(|original| unavailable().with_physical_source(original))?;
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
            self.propose_backup_binding(context, epoch, control, operator, claim, None)
                .await?;
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
        self.original_backup_intent_for_effect(context, &row).await
    }
    async fn propose_backup_binding(
        &self,
        context: &RequestContext,
        epoch: u64,
        control: Arc<Database>,
        mut operator: RequestContext,
        claim: BackupBindingClaim,
        terminal: Option<BackupBindingTerminal>,
    ) -> Result<()> {
        operator.request_id = if terminal.is_some() {
            uuid::Uuid::new_v4().to_string()
        } else {
            claim.command_id.to_string()
        };
        let cancellation = QueryCancellation::default();
        let source_work = self.work.begin(cancellation.clone())?;
        let control_work = control.work.begin(cancellation.clone())?;
        let source_quorum = SourceQuorum::observe(&self.group).await?;
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
                if let Some(source) = &source_quorum {
                    source.check()?;
                }
                store
                    .check_access()
                    .map_err(|original| unavailable().with_physical_source(original))?;
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
                terminal,
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
        Ok(())
    }

    /// Select the encrypted winner in Control before creating the remote
    /// terminal object. Concurrent Abort and Complete callers read one winner.
    pub(super) async fn select_backup_terminal(
        &self,
        context: &RequestContext,
        destination: &dyn BackupDestination,
        session: &VerifiedBackupSession,
        proposed: &BackupSessionOutcome,
    ) -> Result<AdmittedBackupBundle> {
        let epoch = self.engine.generation()?.state.policy_epoch;
        self.require_backup_effect(context, destination, session)
            .await?;
        let encrypt = || self.store.encrypt_backup_session_outcome(session, proposed);
        let Some((control, operator)) = self.backup_authority()? else {
            return encrypt()
                .await
                .map_err(super::backup_sessions::storage_error);
        };
        let id = session.intent().session_id;
        let mut selected = self
            .selected_backup(context, destination, id)
            .await?
            .ok_or_else(wrong_owner)?;
        if selected.terminal.is_none() {
            let bytes = encrypt()
                .await
                .map_err(super::backup_sessions::storage_error)?;
            let terminal = BackupBindingTerminal {
                outcome: proposed.clone(),
                ciphertext_sha256: hex::encode(Sha256::digest(bytes.as_bytes())),
                ciphertext: bytes.as_bytes().to_vec(),
            };
            terminal.validate(&selected.record.claim)?;
            self.propose_backup_binding(
                context,
                epoch,
                control,
                operator,
                selected.record.claim,
                Some(terminal),
            )
            .await?;
            selected = self
                .selected_backup(context, destination, id)
                .await?
                .ok_or_else(wrong_owner)?;
        }
        let decision = selected.terminal.ok_or_else(unavailable)?;
        self.store
            .bound_backup_terminal(&selected.record, &decision)
            .map_err(super::backup_sessions::storage_error)
    }
}
