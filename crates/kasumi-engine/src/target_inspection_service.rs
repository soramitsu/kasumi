//! Metadata-only recovery under a fresh independently committed InspectTarget
//! phase. No original mutation capability is reconstructed from this proof.
use super::*;
use crate::{TargetOperation, target_invocation::TargetReleaseFence};

pub struct VerifiedTargetInspection {
    local_expected: Option<Box<SignedTargetInspection>>,
    database: Arc<Database>,
    observation: TargetInspectionObservation,
    release: TargetReleaseFence,
}
impl VerifiedTargetInspection {
    pub fn observation(&self) -> &TargetInspectionObservation {
        &self.observation
    }
    pub async fn release(&self, operation: &TargetOperation) -> Result<()> {
        self.release.check(operation).map_err(denied)?;
        let fresh = if let Some(expected) = &self.local_expected {
            self.database.local_target_inspection(operation, expected)?
        } else {
            self.database
                .target_inspection(operation, &self.observation.input)
                .await?
        };
        if fresh.completion != self.observation.completion
            || fresh.activation != self.observation.activation
            || fresh.inspection_intent != self.observation.inspection_intent
            || fresh.observer_node_id != self.observation.observer_node_id
            || fresh.observed_term != self.observation.observed_term
            || fresh.observed_revision < self.observation.observed_revision
        {
            return Err(denied("target observation changed during release"));
        }
        self.release.check(operation).map_err(denied)
    }
}
impl Database {
    fn inspection_access(
        &self,
        operation: &TargetOperation,
        input: &TargetInspectionInput,
    ) -> Result<()> {
        operation.check().map_err(denied)?;
        self.materialization_access()?;
        operation
            .invocation()
            .check_target(&self.store, LifecyclePhase::InspectTarget)?;
        let generation = self.engine.generation()?;
        let entry = generation
            .state
            .target_lifecycle
            .get(&generation.state.incarnation)
            .ok_or_else(|| denied("native target origin missing"))?;
        let lease = operation.invocation().gate().current().map_err(denied)?;
        input.validate(&entry.origin, &lease.commitment().intent)?;
        kasumi_serving::verify_target_materializations(&entry.origin, &input.quorum.materialized)
            .map_err(denied)?;
        Ok(())
    }
    async fn target_inspection(
        &self,
        operation: &TargetOperation,
        input: &TargetInspectionInput,
    ) -> Result<TargetInspectionObservation> {
        self.inspection_access(operation, input)?;
        operation
            .run(self.group.linearizable_barrier())
            .await
            .map_err(denied)?;
        self.inspection_access(operation, input)?;
        let metrics = self.group.raft().metrics().borrow().clone();
        let generation = self.engine.generation()?;
        let entry = generation
            .state
            .target_lifecycle
            .get(&generation.state.incarnation)
            .ok_or_else(|| denied("native target origin missing"))?;
        let completion = entry.completion.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::UnknownOutcome,
                "original completion not observed; absence is not a stop proof",
            )
        })?;
        if metrics.current_leader != Some(metrics.id)
            || metrics.membership_config.membership().get_joint_config()
                != &vec![entry.origin.input.voters.keys().copied().collect()]
            || metrics.membership_config.membership().nodes().count()
                != entry.origin.input.voters.len()
            || !metrics
                .membership_config
                .membership()
                .nodes()
                .all(|(id, node)| {
                    entry
                        .origin
                        .input
                        .voters
                        .get(id)
                        .is_some_and(|peer| peer.endpoint == node.addr)
                })
        {
            return Err(denied("current target quorum differs"));
        }
        let lease = operation.invocation().gate().current().map_err(denied)?;
        let observation = TargetInspectionObservation {
            input: input.clone(),
            inspection_intent: lease.commitment().intent.clone(),
            completion: completion.clone(),
            activation: entry.activation.clone(),
            observer_node_id: metrics.id,
            observed_revision: generation.state.revision,
            observed_term: metrics.current_term,
        };
        observation.validate()?;
        drop(generation);
        self.inspection_access(operation, input)?;
        Ok(observation)
    }
    /// An existing target group may replay previously accepted consensus work;
    /// this method never proposes a payload, membership or lifecycle command.
    pub async fn inspect_target(
        self: &Arc<Self>,
        operation: &TargetOperation,
        input: TargetInspectionInput,
    ) -> Result<VerifiedTargetInspection> {
        let observation = self.target_inspection(operation, &input).await?;
        let proof = VerifiedTargetInspection {
            local_expected: None,
            database: self.clone(),
            observation,
            release: operation.release_fence(),
        };
        proof.release(operation).await?;
        Ok(proof)
    }
}
fn denied(_: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::Unauthorized,
        "current target inspection authority unavailable",
    )
}

impl Database {
    fn local_target_inspection(
        &self,
        operation: &TargetOperation,
        expected: &SignedTargetInspection,
    ) -> Result<TargetInspectionObservation> {
        self.inspection_access(operation, &expected.observation.input)?;
        kasumi_serving::verify_target_inspection(&expected.observation.input, expected)
            .map_err(denied)?;
        let generation = self.engine.generation()?;
        let entry = generation
            .state
            .target_lifecycle
            .get(&generation.state.incarnation)
            .ok_or_else(|| denied("target origin absent"))?;
        let activation = entry.activation.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::UnknownOutcome,
                "local target activation not observed",
            )
        })?;
        let lease = operation.invocation().gate().current().map_err(denied)?;
        if expected.observation.inspection_intent != lease.commitment().intent
            || expected.observation.input.original_phase != activation.intent
            || expected.observation.completion
                != *entry
                    .completion
                    .as_ref()
                    .ok_or_else(|| denied("local completion absent"))?
            || expected.observation.activation.as_ref() != Some(activation)
        {
            return Err(denied(
                "exact foreign inspection differs from local activation or phase",
            ));
        }
        let covered = self
            .group
            .confirm_local_application(&activation.position)
            .map_err(denied)?;
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
                    .ok_or_else(|| denied("revision overflow"))?
        {
            return Err(denied("local persisted inspection coverage differs"));
        }
        let observation = TargetInspectionObservation {
            input: expected.observation.input.clone(),
            inspection_intent: lease.commitment().intent.clone(),
            completion: expected.observation.completion.clone(),
            activation: Some(activation.clone()),
            observer_node_id: self.group.raft().metrics().borrow().id,
            observed_revision: generation.state.revision,
            observed_term: covered.term(),
        };
        observation.validate()?;
        drop(generation);
        self.inspection_access(operation, &observation.input)?;
        Ok(observation)
    }
    /// A fresh metadata-only phase may confirm the exact foreign observation
    /// only after this voter's own committed log replay contains the activation.
    pub async fn confirm_target_inspection(
        self: &Arc<Self>,
        operation: &TargetOperation,
        expected: SignedTargetInspection,
    ) -> Result<VerifiedTargetInspection> {
        let observation = self.local_target_inspection(operation, &expected)?;
        let proof = VerifiedTargetInspection {
            database: self.clone(),
            observation,
            release: operation.release_fence(),
            local_expected: Some(Box::new(expected)),
        };
        proof.release(operation).await?;
        Ok(proof)
    }
}
