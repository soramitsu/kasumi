use super::*;
use kasumi_types::{
    CommittedControlChange, CommittedControlIntent, SignedControlChange, SignedControlIntent,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use uuid::Uuid;

/// An installed private key can sign only an engine-created, freshly checked
/// committed observation. No public constructor accepts a committed-state DTO.
pub struct LifecycleSigner {
    root: ControlSigningRoot,
    key: Ed25519KeyPair,
}
impl LifecycleSigner {
    pub fn from_pkcs8(root: ControlSigningRoot, bytes: &[u8]) -> anyhow::Result<Self> {
        root.validate()?;
        let key = Ed25519KeyPair::from_pkcs8(bytes)
            .map_err(|_| anyhow::anyhow!("invalid installed control signer"))?;
        anyhow::ensure!(
            hex::encode(key.public_key().as_ref()) == root.public_key,
            "installed control signing identity differs"
        );
        Ok(Self { root, key })
    }
    pub fn root(&self) -> &ControlSigningRoot {
        &self.root
    }
    pub async fn sign_intent(
        &self,
        proof: &VerifiedLifecycleIntent,
    ) -> Result<SignedControlIntent> {
        proof.release().await?;
        if self.root != proof.observation.installation.root {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "installed lifecycle signer differs",
            ));
        }
        let native = &proof.observation;
        let observation = ControlIntentCommitment {
            intent: native.intent.clone(),
            root: native.installation.root.clone(),
            authority_partition: native
                .installation
                .partitions
                .get(&native.intent.request.authority_partition)
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::Corruption,
                        "installed lifecycle partition absent",
                    )
                })?
                .clone(),
            partition_set_sha256: staged_digest(&native.installation.partitions)?.0,
            observed_policy_epoch: native.observed_policy_epoch,
            observed_revision: native.observed_revision,
            observed_term: native.observed_term,
        };
        let signature = hex::encode(
            self.key
                .sign(
                    &serde_json::to_vec(&("kasumi.committed-control-intent.v1", &observation))
                        .map_err(encoding)?,
                )
                .as_ref(),
        );
        let signed = SignedControlIntent {
            observation,
            signature,
        };
        proof.release().await?;
        Ok(signed)
    }
    pub async fn sign_change(
        &self,
        proof: &VerifiedLifecycleChange,
        partition_key: &str,
    ) -> Result<SignedControlChange> {
        proof.release().await?;
        if self.root != proof.observation.change.installation.root {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "installed lifecycle signer differs",
            ));
        }
        let native = &proof.observation;
        let partition = native
            .change
            .installation
            .partitions
            .get(partition_key)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "authority partition is outside the pinned control change",
                )
            })?;
        let observation = ControlChangeCommitment {
            root: native.change.installation.root.clone(),
            stop: kasumi_serving::control_stop_for(&native.change, partition).map_err(encoding)?,
            accepted_revision: native.change.accepted_revision,
            observed_policy_epoch: native.observed_policy_epoch,
            observed_revision: native.observed_revision,
            observed_term: native.observed_term,
        };
        let signature = hex::encode(
            self.key
                .sign(
                    &serde_json::to_vec(&("kasumi.committed-control-change.v1", &observation))
                        .map_err(encoding)?,
                )
                .as_ref(),
        );
        let signed = SignedControlChange {
            observation,
            signature,
        };
        proof.release().await?;
        Ok(signed)
    }
}
fn encoding(_: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Corruption, "lifecycle control encoding failed")
}
fn unknown(_: Error) -> Error {
    Error::new(
        ErrorCode::UnknownOutcome,
        "control effect may be committed; resolve its exact permanent identity with current authority",
    )
}

pub struct VerifiedLifecycleIntent {
    database: Arc<Database>,
    context: RequestContext,
    observation: CommittedControlIntent,
    _reservation: Reservation,
}
impl VerifiedLifecycleIntent {
    pub fn observation(&self) -> &CommittedControlIntent {
        &self.observation
    }
    pub async fn release(&self) -> Result<()> {
        self.database
            .check_lifecycle_intent(&self.context, &self.observation)
            .await
    }
}
pub struct VerifiedLifecycleChange {
    database: Arc<Database>,
    context: RequestContext,
    observation: CommittedControlChange,
    _reservation: Reservation,
}
impl VerifiedLifecycleChange {
    pub fn observation(&self) -> &CommittedControlChange {
        &self.observation
    }
    pub async fn release(&self) -> Result<()> {
        self.database
            .check_lifecycle_change(&self.context, &self.observation)
            .await
    }
}

impl Database {
    pub async fn lifecycle_control(
        &self,
        context: RequestContext,
        request: LifecycleControlCommand,
    ) -> Result<WriteReceipt> {
        self.administer(context, Operation::LifecycleControl(request))
            .await
    }
    pub(super) fn lifecycle_write_release(&self, context: &RequestContext) -> Result<()> {
        self.access().map_err(unknown)?;
        self.engine
            .authorize(context, None, Action::Admin)
            .map_err(unknown)
    }
    pub(super) async fn lifecycle_barrier(&self, context: &RequestContext) -> Result<u64> {
        context.authorization.check_live()?;
        self.access()?;
        self.engine.authorize(context, None, Action::Admin)?;
        let state = self.engine.generation()?;
        if state.state.tenant != "__kasumi_control" {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "installed control namespace required",
            ));
        }
        context
            .authorization
            .require_control(&state.state.incarnation)?;
        drop(state);
        self.barrier().await?;
        let metrics = self.group.raft().metrics().borrow().clone();
        if metrics.membership_config.membership().voter_ids().count() < 3
            || metrics.current_term == 0
        {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "lifecycle commitments require an actual replicated control quorum",
            ));
        }
        context.authorization.check_live()?;
        self.engine.authorize(context, None, Action::Admin)?;
        Ok(metrics.current_term)
    }
    pub(super) fn lifecycle_now(&self) -> Result<u64> {
        self.command_clock
            .lock()
            .map_err(|_| {
                Error::new(
                    ErrorCode::Unavailable,
                    "trusted lifecycle clock unavailable",
                )
            })?
            .now_ms()
    }
    pub(super) async fn control_observation_audit(
        &self,
        context: &RequestContext,
        id: Uuid,
        digest: String,
        revision: u64,
        epoch: u64,
    ) -> Result<()> {
        let incarnation = self.engine.generation()?.state.incarnation.clone();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.security_audit.record(SecurityEvent {
                kind: SecurityEventKind::ControlCommitmentObserved {
                    control_incarnation: incarnation,
                    command_id: id.to_string(),
                    commitment_sha256: digest,
                    control_policy_epoch: epoch,
                    committed_revision: revision,
                },
                principal: Some(context.principal.clone()),
                tenant: Some(context.tenant.clone()),
                request_id: context.request_id.clone(),
                outcome: SecurityOutcome::Succeeded,
            }),
        )
        .await
        .map_err(|_| {
            Error::new(
                ErrorCode::AuditUnavailable,
                "control commitment audit deadline elapsed",
            )
        })?
        .map_err(|_| {
            Error::new(
                ErrorCode::AuditUnavailable,
                "control commitment audit unavailable",
            )
        })
    }
    pub async fn observe_lifecycle_intent(
        self: &Arc<Self>,
        context: RequestContext,
        id: Uuid,
    ) -> Result<VerifiedLifecycleIntent> {
        let cancellation = QueryCancellation::default();
        let _work = self.work.begin(cancellation.clone())?;
        let _slot = self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "control observation concurrency limit",
            )
        })?;
        let mut reservation = self
            .admission()
            .reserve((MAX_LIFECYCLE_STATE_BYTES * 2) as u64, None)?;
        let term = self.lifecycle_barrier(&context).await?;
        let state = self.engine.generation()?;
        let control = state
            .state
            .lifecycle_control
            .as_ref()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "lifecycle control absent"))?;
        let intent = control
            .intents
            .get(&id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "lifecycle intent absent"))?;
        let observation = CommittedControlIntent {
            intent,
            installation: control.installation.clone(),
            observed_policy_epoch: state.state.policy_epoch,
            observed_revision: state.state.revision,
            observed_term: term,
        };
        drop(state);
        self.check_lifecycle_intent(&context, &observation).await?;
        self.control_observation_audit(
            &context,
            id,
            observation.intent.request_sha256.clone(),
            observation.intent.revision,
            observation.observed_policy_epoch,
        )
        .await?;
        self.check_lifecycle_intent(&context, &observation).await?;
        cancellation.check()?;
        reservation.retain_workspace();
        Ok(VerifiedLifecycleIntent {
            database: self.clone(),
            context,
            observation,
            _reservation: reservation,
        })
    }
    async fn check_lifecycle_intent(
        &self,
        context: &RequestContext,
        observation: &CommittedControlIntent,
    ) -> Result<()> {
        if self.lifecycle_barrier(context).await? != observation.observed_term {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "control observation quorum term changed",
            ));
        }
        let state = self.engine.generation()?;
        let control = state
            .state
            .lifecycle_control
            .as_ref()
            .ok_or_else(|| Error::new(ErrorCode::Conflict, "control installation absent"))?;
        if control.retired
            || control.pending_change.is_some()
            || control.installation != observation.installation
            || state.state.policy_epoch != observation.observed_policy_epoch
            || state.state.policy_epoch != observation.intent.request.expected_policy_epoch
            || control.intents.get(&observation.intent.request.command_id)
                != Some(&observation.intent)
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "committed control intent is no longer eligible for grant issuance",
            ));
        }
        if self.lifecycle_now()? >= observation.intent.original_credential_expires_at_ms {
            return Err(Error::new(
                ErrorCode::Unauthorized,
                "original lifecycle authorization expired",
            ));
        }
        context.authorization.check_live()?;
        self.engine.authorize_release(
            context,
            None,
            Action::Admin,
            observation.observed_policy_epoch,
        )
    }
    pub async fn observe_lifecycle_change(
        self: &Arc<Self>,
        context: RequestContext,
        id: Uuid,
    ) -> Result<VerifiedLifecycleChange> {
        let cancellation = QueryCancellation::default();
        let _work = self.work.begin(cancellation.clone())?;
        let _slot = self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "control observation concurrency limit",
            )
        })?;
        let mut reservation = self
            .admission()
            .reserve((MAX_LIFECYCLE_STATE_BYTES * 2) as u64, None)?;
        let term = self.lifecycle_barrier(&context).await?;
        let state = self.engine.generation()?;
        let control = state
            .state
            .lifecycle_control
            .as_ref()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "lifecycle control absent"))?;
        let change = control
            .changes
            .get(&id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "control change absent"))?;
        let observation = CommittedControlChange {
            change,
            observed_policy_epoch: state.state.policy_epoch,
            observed_revision: state.state.revision,
            observed_term: term,
        };
        drop(state);
        self.check_lifecycle_change(&context, &observation).await?;
        self.control_observation_audit(
            &context,
            id,
            observation.change.request_sha256.clone(),
            observation.change.accepted_revision,
            observation.observed_policy_epoch,
        )
        .await?;
        self.check_lifecycle_change(&context, &observation).await?;
        cancellation.check()?;
        reservation.retain_workspace();
        Ok(VerifiedLifecycleChange {
            database: self.clone(),
            context,
            observation,
            _reservation: reservation,
        })
    }
    async fn check_lifecycle_change(
        &self,
        context: &RequestContext,
        observation: &CommittedControlChange,
    ) -> Result<()> {
        if self.lifecycle_barrier(context).await? != observation.observed_term {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "control change quorum term changed",
            ));
        }
        let state = self.engine.generation()?;
        let control = state
            .state
            .lifecycle_control
            .as_ref()
            .ok_or_else(|| Error::new(ErrorCode::Conflict, "control installation absent"))?;
        if control.retired
            || control.pending_change != Some(observation.change.request.command_id)
            || state.state.policy_epoch != observation.observed_policy_epoch
            || control.installation != observation.change.installation
            || control
                .changes
                .get(&observation.change.request.command_id)
                .is_none_or(|actual| {
                    staged_digest(actual).ok() != staged_digest(&observation.change).ok()
                })
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "exact pending control change differs",
            ));
        }
        context.authorization.check_live()?;
        self.engine.authorize_release(
            context,
            None,
            Action::Admin,
            observation.observed_policy_epoch,
        )
    }
}

impl Database {
    pub async fn read_lifecycle_status(
        &self,
        context: &RequestContext,
        request: ReadLifecycleStatus,
    ) -> Result<LifecycleStatus> {
        let cancellation = QueryCancellation::default();
        let _work = self.work.begin(cancellation.clone())?;
        let _slot = self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "control status concurrency limit",
            )
        })?;
        let _reservation = self
            .admission()
            .reserve((MAX_LIFECYCLE_STATE_BYTES * 2) as u64, None)?;
        let term = self.lifecycle_barrier(context).await?;
        let state = self.engine.generation()?;
        let command = lifecycle_status_command(&state.state, &request)?;
        let status = LifecycleStatus {
            request,
            policy_epoch: state.state.policy_epoch,
            observed_revision: state.state.revision,
            observed_term: term,
            retired: state
                .state
                .lifecycle_control
                .as_ref()
                .expect("validated installation")
                .retired,
            command,
        };
        drop(state);
        self.control_observation_audit(
            context,
            status.request.command_id,
            staged_digest(&status.command)?.0,
            status.observed_revision,
            status.policy_epoch,
        )
        .await?;
        self.check_lifecycle_status_release(context, &status)
            .await?;
        cancellation.check()?;
        Ok(status)
    }
    pub async fn check_lifecycle_status_release(
        &self,
        context: &RequestContext,
        status: &LifecycleStatus,
    ) -> Result<()> {
        if self.lifecycle_barrier(context).await? != status.observed_term {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "control status quorum term changed",
            ));
        }
        let state = self.engine.generation()?;
        let command = lifecycle_status_command(&state.state, &status.request)?;
        if state.state.policy_epoch != status.policy_epoch
            || state
                .state
                .lifecycle_control
                .as_ref()
                .expect("validated installation")
                .retired
                != status.retired
            || staged_digest(&command)? != staged_digest(&status.command)?
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "current control status changed before release",
            ));
        }
        context.authorization.check_live()?;
        self.engine
            .authorize_release(context, None, Action::Admin, status.policy_epoch)
    }
}
fn lifecycle_status_command(
    state: &TenantState,
    request: &ReadLifecycleStatus,
) -> Result<Option<LifecycleCommandStatus>> {
    if request.command_id.is_nil() || request.expected_incarnation.to_string() != state.incarnation
    {
        return Err(Error::new(
            ErrorCode::Conflict,
            "control status identity differs",
        ));
    }
    let control = state
        .lifecycle_control
        .as_ref()
        .ok_or_else(|| Error::new(ErrorCode::NotFound, "lifecycle control absent"))?;
    if let Some(intent) = control.intents.get(&request.command_id) {
        return Ok(Some(LifecycleCommandStatus::Intent(Box::new(
            intent.clone(),
        ))));
    }
    if let Some(change) = control.changes.get(&request.command_id) {
        return Ok(Some(LifecycleCommandStatus::PolicyChange(Box::new(
            change.clone(),
        ))));
    }
    if control.installation_command_id == request.command_id {
        return Ok(Some(LifecycleCommandStatus::Installation {
            command_id: request.command_id,
            installation: control.installation.clone(),
            revision: control.installation_revision,
        }));
    }
    Ok(None)
}
