//! Read-only observation under a new explicit phase and actual reopened quorum.
//! This proof never carries or reconstructs the original Start/Initialize permit.
use super::*;
use crate::{TargetJournal, TargetOperation, target_invocation::TargetReleaseFence};
use kasumi_serving::VerifiedControlIntent;

pub struct VerifiedTargetInitialMembershipStatus {
    database: Arc<Database>,
    journal: Arc<TargetJournal>,
    control: VerifiedControlIntent,
    observation: TargetInitialMembershipStatusObservation,
    release: TargetReleaseFence,
    _reservation: Reservation,
}
impl VerifiedTargetInitialMembershipStatus {
    pub fn observation(&self) -> &TargetInitialMembershipStatusObservation {
        &self.observation
    }
    pub async fn release(
        &self,
        operation: &TargetOperation,
    ) -> std::result::Result<(), crate::SnapshotFailure> {
        self.release.check(operation).map_err(unknown)?;
        let fresh = self
            .database
            .observe_initial_membership(
                operation,
                &self.journal,
                &self.control,
                &self.observation.input,
            )
            .await?;
        if fresh.association_position != self.observation.association_position
            || fresh.association != self.observation.association
            || fresh.input != self.observation.input
            || fresh.status_intent != self.observation.status_intent
            || fresh.first_fact_sha256 != self.observation.first_fact_sha256
            || fresh.first_log_index != self.observation.first_log_index
            || fresh.observer_node_id != self.observation.observer_node_id
            || fresh.observed_term != self.observation.observed_term
            || fresh.applied_log_index < self.observation.applied_log_index
            || fresh.committed_log_index < self.observation.committed_log_index
        {
            return Err(unknown("initial membership inspection changed before release").into());
        }
        self.release
            .check(operation)
            .map_err(|error| unknown(error).into())
    }
}
impl Database {
    fn initial_inspection_context(
        &self,
        operation: &TargetOperation,
        journal: &TargetJournal,
        control: &VerifiedControlIntent,
        input: &TargetInitialMembershipStatusInput,
    ) -> Result<LifecycleIntent> {
        self.target_phase_access(operation, LifecyclePhase::InspectInitialMembership)?;
        let intent = operation
            .invocation()
            .gate()
            .current()
            .map_err(denied)?
            .commitment()
            .intent
            .clone();
        if control.observation().intent != intent {
            return Err(denied(
                "initial inspection current Control identity differs",
            ));
        }
        let generation = self.engine.generation()?;
        let origin = &generation
            .state
            .target_lifecycle
            .get(&generation.state.incarnation)
            .ok_or_else(|| denied("initial inspection target origin absent"))?
            .origin;
        input.validate(origin, &intent)?;
        kasumi_serving::verify_target_materializations(origin, &input.quorum.materialized)
            .map_err(denied)?;
        journal
            .authenticate_initial_inspection_start(control, input, self.stores())
            .map_err(unknown)?;
        Ok(intent)
    }
    async fn observe_initial_membership(
        self: &Arc<Self>,
        operation: &TargetOperation,
        journal: &TargetJournal,
        control: &VerifiedControlIntent,
        input: &TargetInitialMembershipStatusInput,
    ) -> std::result::Result<TargetInitialMembershipStatusObservation, crate::SnapshotFailure> {
        let intent = self.initial_inspection_context(operation, journal, control, input)?;
        let voters = input
            .quorum
            .materialized
            .values()
            .next()
            .ok_or_else(|| denied("initial inspection materializations absent"))?
            .fact
            .origin
            .input
            .voters
            .clone();
        // A decoded row cannot take this path without an actual independently
        // opened replica, current phase gates and a fresh current-term barrier.
        operation
            .run(self.group.linearizable_barrier())
            .await
            .map_err(unknown)?;
        let metrics = self.group.raft().metrics().borrow().clone();
        let membership = metrics.membership_config.membership();
        if !voters.contains_key(&metrics.id)
            || metrics.current_leader != Some(metrics.id)
            || membership.get_joint_config() != &vec![voters.keys().copied().collect()]
            || membership.nodes().count() != voters.len()
            || membership
                .nodes()
                .any(|(id, node)| voters.get(id).is_none_or(|peer| peer.endpoint != node.addr))
        {
            return Err(unknown(
                "initial inspection requires installed actual current quorum leader",
            )
            .into());
        }
        let history = journal
            .resolve_initial_inspection_start_history(control, input, self.stores())
            .map_err(history_unknown)?;
        let local = &history;
        let committed = kasumi_raft::read_initialization_association(self.stores())
            .map_err(unknown)?
            .ok_or_else(|| {
                unknown("first membership has no committed original initialization cause")
            })?;
        let association = committed.signed;
        association
            .association
            .matches_inspection(input)
            .map_err(unknown)?;
        if association.association.control_root != control.observation().root
            || local.first_log_id().index != committed.position.index
        {
            return Err(
                unknown("current quorum cause differs from original installed history").into(),
            );
        }
        let observation = TargetInitialMembershipStatusObservation {
            association,
            association_position: committed.position,
            input: input.clone(),
            status_intent: intent,
            first_fact_sha256: local.first_fact_sha256().into(),
            first_log_index: local.first_log_id().index,
            applied_log_index: local.applied_log_id().index,
            committed_log_index: local.committed_log_id().index,
            observer_node_id: metrics.id,
            observed_term: metrics.current_term,
        };
        observation.validate()?;
        self.target_phase_access(operation, LifecyclePhase::InspectInitialMembership)?;
        Ok(observation)
    }
    pub async fn inspect_initial_membership(
        self: &Arc<Self>,
        operation: &TargetOperation,
        journal: Arc<TargetJournal>,
        control: VerifiedControlIntent,
        input: TargetInitialMembershipStatusInput,
    ) -> std::result::Result<VerifiedTargetInitialMembershipStatus, crate::SnapshotFailure> {
        let reservation = self
            .admission()
            .reserve(4 << 20, Some(operation.token.clone()))?;
        let observation = self
            .observe_initial_membership(operation, &journal, &control, &input)
            .await?;
        let proof = VerifiedTargetInitialMembershipStatus {
            database: self.clone(),
            journal,
            control,
            observation,
            release: operation.release_fence(),
            _reservation: reservation,
        };
        proof.release(operation).await?;
        Ok(proof)
    }
}
fn unknown(_: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::UnknownOutcome,
        "initial membership inspection is not positively resolved",
    )
}
fn history_unknown(original: crate::SnapshotFailure) -> crate::SnapshotFailure {
    match original {
        crate::SnapshotFailure::Operation(original) => unknown(original).into(),
        original => original,
    }
}
fn denied(_: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::Forbidden,
        "initial membership inspection authority unavailable",
    )
}
