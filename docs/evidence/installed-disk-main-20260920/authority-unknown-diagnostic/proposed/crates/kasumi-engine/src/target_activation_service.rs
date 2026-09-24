use super::*;
use crate::state::target::{MAX_COMMAND_BYTES, TargetCommand, TargetOutcome};
use crate::{TargetOperation, target_invocation::TargetReleaseFence};
use kasumi_serving::{AuthorityAction, SignedAuthorityReceipt};

pub struct VerifiedTargetActivation {
    local_expected: Option<Box<SignedTargetActivation>>,
    database: Arc<Database>,
    observation: TargetActivationObservation,
    release: TargetReleaseFence,
}
impl VerifiedTargetActivation {
    pub fn fact(&self) -> &TargetActivationFact {
        &self.observation.activation
    }
    pub fn observation(&self) -> &TargetActivationObservation {
        &self.observation
    }
    pub async fn release(&self, operation: &TargetOperation) -> Result<()> {
        self.release.check(operation).map_err(unknown)?;
        let current = if let Some(expected) = &self.local_expected {
            self.database
                .local_target_activation_observation(operation, expected)
                .map_err(unknown)?
        } else {
            self.database
                .target_activation_observation(operation)
                .await
                .map_err(unknown)?
        };
        if current.completion != self.observation.completion
            || current.activation != self.observation.activation
            || current.observed_term != self.observation.observed_term
            || current.observer_node_id != self.observation.observer_node_id
            || current.observed_revision < self.observation.observed_revision
        {
            return Err(unknown("target activation observation changed"));
        }
        self.release.check(operation).map_err(unknown)
    }
}
impl Database {
    fn target_activation_access(&self, operation: &TargetOperation) -> Result<()> {
        operation.check().map_err(denied)?;
        self.materialization_access()?;
        operation
            .invocation()
            .check_target(&self.store, LifecyclePhase::Activate)?;
        let generation = self.engine.generation()?;
        let entry = generation
            .state
            .target_lifecycle
            .get(&generation.state.incarnation)
            .ok_or_else(|| denied("native target origin missing"))?;
        let lease = operation.invocation().gate().current().map_err(denied)?;
        entry
            .origin
            .accepts_phase(&lease.commitment().intent, LifecyclePhase::Activate)?;
        Ok(())
    }
    async fn target_activation_observation(
        &self,
        operation: &TargetOperation,
    ) -> Result<TargetActivationObservation> {
        self.target_activation_access(operation)?;
        operation
            .run(self.group.linearizable_barrier())
            .await
            .map_err(denied)?;
        self.target_activation_access(operation)?;
        let metrics = self.group.raft().metrics().borrow().clone();
        let generation = self.engine.generation()?;
        let entry = generation
            .state
            .target_lifecycle
            .get(&generation.state.incarnation)
            .ok_or_else(|| denied("target origin absent"))?;
        let fact = entry
            .activation
            .as_ref()
            .ok_or_else(|| Error::new(ErrorCode::Conflict, "target activation not committed"))?;
        let current = operation.invocation().gate().current().map_err(denied)?;
        if metrics.current_leader != Some(metrics.id)
            || metrics.current_term == 0
            || current.commitment().intent.request.phase_input_sha256
                != fact.intent.request.phase_input_sha256
            || metrics.membership_config.membership().get_joint_config()
                != &vec![entry.origin.input.voters.keys().copied().collect()]
        {
            return Err(denied(
                "current activation quorum or exact phase input differs",
            ));
        }
        let result = TargetActivationObservation {
            completion: entry
                .completion
                .clone()
                .ok_or_else(|| denied("completion missing"))?,
            activation: fact.clone(),
            observer_node_id: metrics.id,
            observed_revision: generation.state.revision,
            observed_term: metrics.current_term,
        };
        result.validate()?;
        self.target_activation_access(operation)?;
        Ok(result)
    }
    pub async fn activate_target(
        self: &Arc<Self>,
        operation: &TargetOperation,
        activation: SignedAuthorityReceipt,
    ) -> Result<VerifiedTargetActivation> {
        self.target_activation_access(operation)?;
        let lease = operation.invocation().gate().current().map_err(denied)?;
        lease
            .authority()
            .verify_activation(activation.clone())
            .map_err(denied)?;
        let AuthorityAction::ActivateCommitted {
            fence_id,
            fence_digest,
            target,
            control,
        } = &activation.receipt.command.action
        else {
            return Err(denied("closed issuer winner required"));
        };
        let generation = self.engine.generation()?;
        let entry = generation
            .state
            .target_lifecycle
            .get(&generation.state.incarnation)
            .ok_or_else(|| denied("target origin absent"))?;
        let completed = entry
            .completion
            .as_ref()
            .ok_or_else(|| Error::new(ErrorCode::Conflict, "target completion missing"))?;
        if completed != control.completion.fact() {
            return Err(Error::new(
                ErrorCode::Conflict,
                "issuer completion differs from actual target",
            ));
        }
        let input = kasumi_serving::ActivateTargetInput {
            fence_id: *fence_id,
            fence_digest: fence_digest.clone(),
            target: target.clone(),
            completion_sha256: completed.digest()?,
        };
        if input.digest().map_err(denied)? != lease.commitment().intent.request.phase_input_sha256 {
            return Err(Error::new(
                ErrorCode::Conflict,
                "activation phase input differs",
            ));
        }
        let digest = activation.receipt.digest().map_err(denied)?;
        let existing = entry.activation.clone();
        drop(generation);
        if let Some(existing) = existing {
            if existing.issuer_receipt_sha256 != digest {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "target has another issuer winner",
                ));
            }
        } else {
            let reservation = self.admission().reserve(
                (MAX_COMMAND_BYTES * 4 + (16 << 20)) as u64,
                Some(operation.token.clone()),
            )?;
            let registration = self.work.begin(operation.token.clone())?;
            let worker = ActivationProposal {
                database: self.clone(),
                operation: operation.clone(),
                activation,
                input_sha256: input.digest().map_err(denied)?,
                _reservation: reservation,
                _registration: registration,
            };
            let task = tokio::spawn(worker.run());
            operation
                .run(async { task.await? })
                .await
                .map_err(unknown)??;
        }
        self.observe_target_activation(operation)
            .await
            .map_err(unknown)
    }
    pub async fn observe_target_activation(
        self: &Arc<Self>,
        operation: &TargetOperation,
    ) -> Result<VerifiedTargetActivation> {
        let observation = self.target_activation_observation(operation).await?;
        let proof = VerifiedTargetActivation {
            local_expected: None,
            database: self.clone(),
            observation,
            release: operation.release_fence(),
        };
        proof.release(operation).await?;
        Ok(proof)
    }
}
struct ActivationProposal {
    database: Arc<Database>,
    operation: TargetOperation,
    activation: SignedAuthorityReceipt,
    input_sha256: String,
    _reservation: Reservation,
    _registration: WorkRegistration,
}
impl ActivationProposal {
    async fn run(self) -> anyhow::Result<Result<TargetActivationFact>> {
        let _guard = self
            .operation
            .run(async { Ok(self.database.proposal_gate.clone().lock_owned().await) })
            .await?;
        if let Err(error) = self.database.target_activation_access(&self.operation) {
            return Ok(Err(error));
        }
        let now = self
            .operation
            .invocation()
            .gate()
            .admission_time_ms()
            .map_err(denied)?;
        let authorization =
            self.operation
                .prepare(LifecyclePhase::Activate, &self.input_sha256, now)?;
        let command = TargetCommand::Activate {
            authorization,
            activation: Box::new(self.activation.clone()),
        };
        let bytes = self.database.group.write(command.encode()?).await?;
        let result = match serde_json::from_slice::<Result<TargetOutcome>>(&bytes)? {
            Ok(TargetOutcome::Activated(fact)) => Ok(*fact),
            Ok(_) => Err(unknown("target response kind differs")),
            Err(error) => Err(error),
        };
        if result.is_ok() {
            self.database
                .target_activation_access(&self.operation)
                .map_err(unknown)?;
        }
        Ok(result)
    }
}
#[cfg_attr(any(test, feature = "test-utils"), track_caller)]
fn denied(_cause: impl std::fmt::Display) -> Error {
    #[cfg(any(test, feature = "test-utils"))]
    eprintln!(
        "TARGET_ACTIVATION_DENIED at {}: {}",
        std::panic::Location::caller(),
        _cause
    );
    Error::new(
        ErrorCode::Unauthorized,
        "original target activation authority unavailable",
    )
}
#[cfg_attr(any(test, feature = "test-utils"), track_caller)]
fn unknown(_cause: impl std::fmt::Display) -> Error {
    #[cfg(any(test, feature = "test-utils"))]
    eprintln!(
        "TARGET_ACTIVATION_UNKNOWN at {}: {}",
        std::panic::Location::caller(),
        _cause
    );
    Error::new(
        ErrorCode::UnknownOutcome,
        "target activation acknowledgement unresolved; recover exact issuer winner and phase",
    )
}

impl Database {
    fn local_target_activation_observation(
        &self,
        operation: &TargetOperation,
        expected: &SignedTargetActivation,
    ) -> Result<TargetActivationObservation> {
        self.target_activation_access(operation)?;
        kasumi_serving::verify_target_activation(&expected.observation.completion.origin, expected)
            .map_err(denied)?;
        let generation = self.engine.generation()?;
        let entry = generation
            .state
            .target_lifecycle
            .get(&generation.state.incarnation)
            .ok_or_else(|| denied("local target origin absent"))?;
        if entry.completion.as_ref() != Some(&expected.observation.completion)
            || entry.activation.as_ref() != Some(&expected.observation.activation)
        {
            return Err(unknown("exact activation not present in local replay"));
        }
        let fact = entry.activation.as_ref().expect("checked activation");
        let lease = operation.invocation().gate().current().map_err(denied)?;
        if lease.commitment().intent.request.phase_input_sha256
            != fact.intent.request.phase_input_sha256
        {
            return Err(denied("local confirmation phase differs"));
        }
        let covered = self
            .group
            .confirm_local_application(&fact.position)
            .map_err(unknown)?;
        let membership = covered.membership().membership();
        if membership.get_joint_config()
            != &vec![entry.origin.input.voters.keys().copied().collect()]
            || membership.nodes().count() != entry.origin.input.voters.len()
            || membership.nodes().any(|(id, node)| {
                entry
                    .origin
                    .input
                    .voters
                    .get(id)
                    .is_none_or(|peer| peer.endpoint != node.addr)
            })
            || generation.state.revision
                > entry
                    .origin
                    .materialization
                    .request
                    .checkpoint
                    .revision
                    .checked_add(1)
                    .and_then(|base| base.checked_add(covered.index()))
                    .ok_or_else(|| unknown("revision overflow"))?
        {
            return Err(unknown(
                "actual local persisted membership/application differs",
            ));
        }
        let observation = TargetActivationObservation {
            completion: expected.observation.completion.clone(),
            activation: fact.clone(),
            observer_node_id: self.group.raft().metrics().borrow().id,
            observed_revision: generation.state.revision,
            observed_term: covered.term(),
        };
        observation.validate()?;
        drop(generation);
        self.target_activation_access(operation)?;
        Ok(observation)
    }
    /// Metadata only: a foreign signature must match this voter's actual
    /// persisted application. This never proposes or authorizes activation.
    pub async fn confirm_target_activation(
        self: &Arc<Self>,
        operation: &TargetOperation,
        expected: SignedTargetActivation,
    ) -> Result<VerifiedTargetActivation> {
        let observation = self.local_target_activation_observation(operation, &expected)?;
        let proof = VerifiedTargetActivation {
            database: self.clone(),
            observation,
            release: operation.release_fence(),
            local_expected: Some(Box::new(expected)),
        };
        proof.release(operation).await?;
        Ok(proof)
    }
}
