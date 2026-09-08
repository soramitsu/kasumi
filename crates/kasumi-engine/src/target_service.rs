use super::*;
use crate::state::target::{MAX_COMMAND_BYTES, TargetCommand, TargetOutcome};
use crate::{TargetOperation, target_invocation::TargetReleaseFence};

/// Only an actual target quorum can create this observation. It keeps the exact
/// original operation release fence and cannot be reconstructed from wire data.
pub struct VerifiedTargetCompletion {
    database: Arc<Database>,
    observation: TargetCompletionObservation,
    release: TargetReleaseFence,
}
impl VerifiedTargetCompletion {
    pub fn observation(&self) -> &TargetCompletionObservation {
        &self.observation
    }
    pub async fn release(&self, operation: &TargetOperation) -> Result<()> {
        self.release.check(operation).map_err(unknown)?;
        let fresh = self
            .database
            .target_observation(operation)
            .await
            .map_err(unknown)?;
        if fresh.fact != self.observation.fact
            || fresh.observer_node_id != self.observation.observer_node_id
            || fresh.observed_term != self.observation.observed_term
            || fresh.observed_revision < self.observation.observed_revision
        {
            return Err(unknown(
                "target completion authority changed during release",
            ));
        }
        self.release.check(operation).map_err(unknown)
    }
}
impl Database {
    fn target_access(&self, operation: &TargetOperation) -> Result<()> {
        operation.check().map_err(denied)?;
        self.materialization_access()?;
        operation
            .invocation()
            .check_target(&self.store, LifecyclePhase::Complete)?;
        let generation = self.engine.generation()?;
        let entry = generation
            .state
            .target_lifecycle
            .get(&generation.state.incarnation)
            .ok_or_else(|| denied("native target origin missing"))?;
        let lease = operation.invocation().gate().current().map_err(denied)?;
        entry
            .origin
            .accepts_phase(&lease.commitment().intent, LifecyclePhase::Complete)?;
        Ok(())
    }
    async fn target_observation(
        &self,
        operation: &TargetOperation,
    ) -> Result<TargetCompletionObservation> {
        self.target_access(operation)?;
        operation
            .run(self.group.linearizable_barrier())
            .await
            .map_err(denied)?;
        self.target_access(operation)?;
        let metrics = self.group.raft().metrics().borrow().clone();
        let generation = self.engine.generation()?;
        let entry = generation
            .state
            .target_lifecycle
            .get(&generation.state.incarnation)
            .ok_or_else(|| denied("native target origin missing"))?;
        let fact = entry
            .completion
            .as_ref()
            .ok_or_else(|| Error::new(ErrorCode::Conflict, "target completion not committed"))?;
        let lease = operation.invocation().gate().current().map_err(denied)?;
        if fact.completion_intent != lease.commitment().intent
            || metrics.current_leader != Some(metrics.id)
            || metrics.current_term < fact.term
            || metrics.membership_config.membership().get_joint_config()
                != &vec![fact.origin.input.voters.keys().copied().collect()]
        {
            return Err(denied("current target completion quorum or phase differs"));
        }
        let observation = TargetCompletionObservation {
            fact: fact.clone(),
            observer_node_id: metrics.id,
            observed_revision: generation.state.revision,
            observed_term: metrics.current_term,
        };
        observation.validate()?;
        self.target_access(operation)?;
        Ok(observation)
    }
    pub async fn complete_target(
        self: &Arc<Self>,
        operation: &TargetOperation,
        input: TargetQuorumInput,
    ) -> Result<VerifiedTargetCompletion> {
        self.target_access(operation)?;
        let generation = self.engine.generation()?;
        let entry = generation
            .state
            .target_lifecycle
            .get(&generation.state.incarnation)
            .ok_or_else(|| denied("native target origin missing"))?;
        if input.origin_sha256 != entry.origin.digest()? {
            return Err(Error::new(
                ErrorCode::Conflict,
                "target input origin differs",
            ));
        }
        kasumi_serving::verify_target_materializations(&entry.origin, &input.materialized)
            .map_err(denied)?;
        let input_digest = input.digest()?;
        let lease = operation.invocation().gate().current().map_err(denied)?;
        if lease.commitment().intent.request.phase_input_sha256 != input_digest {
            return Err(Error::new(
                ErrorCode::Conflict,
                "target input differs from committed phase",
            ));
        }
        let existing = entry.completion.clone();
        drop(generation);
        if let Some(existing) = existing {
            if existing.completion_intent != lease.commitment().intent
                || existing.materialized != input.materialized
            {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "target completed under another identity",
                ));
            }
        } else {
            let reservation = self.admission().reserve(
                (MAX_COMMAND_BYTES * 4 + (16 << 20)) as u64,
                Some(operation.token.clone()),
            )?;
            let registration = self.work.begin(operation.token.clone())?;
            let worker = TargetProposal {
                database: self.clone(),
                operation: operation.clone(),
                input,
                _reservation: reservation,
                _registration: registration,
            };
            let task = tokio::spawn(worker.run());
            let result = operation
                .run(async { task.await? })
                .await
                .map_err(unknown)?;
            result?;
        }
        let observation = self.target_observation(operation).await.map_err(unknown)?;
        let proof = VerifiedTargetCompletion {
            database: self.clone(),
            observation,
            release: operation.release_fence(),
        };
        proof.release(operation).await?;
        Ok(proof)
    }
    /// Fresh recovery re-observes the committed fact under this original phase;
    /// it does not revive an earlier operation's deadline or response fence.
    pub async fn observe_target_completion(
        self: &Arc<Self>,
        operation: &TargetOperation,
    ) -> Result<VerifiedTargetCompletion> {
        let observation = self.target_observation(operation).await?;
        let proof = VerifiedTargetCompletion {
            database: self.clone(),
            observation,
            release: operation.release_fence(),
        };
        proof.release(operation).await?;
        Ok(proof)
    }
}
struct TargetProposal {
    database: Arc<Database>,
    operation: TargetOperation,
    input: TargetQuorumInput,
    _reservation: Reservation,
    _registration: WorkRegistration,
}
impl TargetProposal {
    async fn run(self) -> anyhow::Result<Result<TargetCompletionFact>> {
        let _guard = self
            .operation
            .run(async { Ok(self.database.proposal_gate.clone().lock_owned().await) })
            .await?;
        if let Err(error) = self.database.target_access(&self.operation) {
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
                .prepare(LifecyclePhase::Complete, &self.input.digest()?, now)?;
        let command = TargetCommand::Complete {
            authorization,
            input: self.input.clone(),
        };
        // Ownership of the serialized gate, original work and byte reservation
        // survives caller cancellation until actual consensus processing ends.
        let bytes = self.database.group.write(command.encode()?).await?;
        let result = match serde_json::from_slice::<Result<TargetOutcome>>(&bytes)? {
            Ok(TargetOutcome::Completed(fact)) => Ok(*fact),
            Ok(_) => Err(unknown("target response kind differs")),
            Err(error) => Err(error),
        };
        if result.is_ok() {
            self.database
                .target_access(&self.operation)
                .map_err(unknown)?;
        }
        Ok(result)
    }
}
fn denied(_: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::Unauthorized,
        "original target authority unavailable",
    )
}
fn unknown(_: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::UnknownOutcome,
        "target effect or acknowledgement unresolved; recover the exact permanent phase",
    )
}
