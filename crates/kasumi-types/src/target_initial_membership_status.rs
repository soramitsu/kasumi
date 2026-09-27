//! Fresh read-only authority over an exact accepted initial membership attempt.
//! Historical records describe the old effect; none can recreate its execution owner.
use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInitialMembershipStatusInput {
    pub original_intent: LifecycleIntent,
    pub quorum: TargetQuorumInput,
    #[serde(deserialize_with = "crate::deserialize_u64_map")]
    pub starts: BTreeMap<u64, RecoveryPhaseRecord>,
    pub initialize: RecoveryPhaseRecord,
}
impl TargetInitialMembershipStatusInput {
    pub fn quorum(&self) -> &TargetQuorumInput {
        &self.quorum
    }
    pub fn node_id(&self) -> Result<u64> {
        match &self.initialize.input {
            RecoveryDispatch::Target { node_id, .. } => Ok(*node_id),
            _ => Err(invalid("initial membership status lacks target dispatch")),
        }
    }
    pub fn identity(&self) -> Result<TargetInitialDispatchIdentity> {
        Self::dispatch_identity(&self.initialize)
    }
    pub fn dispatch_identity(phase: &RecoveryPhaseRecord) -> Result<TargetInitialDispatchIdentity> {
        let marker = phase
            .effect_attempts
            .get(&RecoveryEffect::TargetCommand)
            .ok_or_else(|| invalid("initial membership status lacks accepted effect marker"))?;
        Ok(TargetInitialDispatchIdentity {
            operation_id: phase.operation_id,
            phase_id: phase.phase_id,
            attempt_id: marker.attempt_id,
            input_sha256: phase.input_sha256.clone(),
        })
    }
    /// Explicit immutable admission projection. Resolution is checked separately;
    /// stripping it does not create a current Control or execution capability.
    pub fn accepted_phase(phase: &RecoveryPhaseRecord) -> Result<RecoveryPhaseRecord> {
        phase.validate()?;
        let mut accepted = phase.clone();
        accepted.outcome = None;
        accepted.resolved_revision = None;
        accepted.validate()?;
        Ok(accepted)
    }
    pub fn digest(&self) -> Result<String> {
        let node = self.node_id()?;
        let RecoveryDispatch::Target { request, .. } = &self.initialize.input else {
            unreachable!()
        };
        require(
            matches!(&request.step, TargetRuntimeStep::Initialize(q) if q == &self.quorum),
            "initial membership status changed original Initialize input",
        )?;
        require(
            self.initialize.outcome.is_none() && self.initialize.resolved_revision.is_none(),
            "initial membership status must retain the unresolved original Initialize",
        )?;
        self.identity()?
            .validate_marked_intent(node, request, &self.original_intent, &self.initialize)
            .map_err(|_| invalid("initial membership status changed original Initialize marker"))?;
        require(
            self.starts.len() == 3
                && self
                    .starts
                    .keys()
                    .eq(self.original_intent.request.target_nodes.keys())
                && self.starts.keys().next() == Some(&node),
            "initial membership status lacks exact original voters",
        )?;
        for (start_node, start) in &self.starts {
            let RecoveryDispatch::Target {
                node_id,
                request: start_request,
            } = &start.input
            else {
                return Err(invalid("initial membership status Start route differs"));
            };
            require(
                start
                    .resolved_revision
                    .is_some_and(|revision| revision < self.initialize.prepared_revision)
                    && *node_id == *start_node
                    && start.operation_id == self.initialize.operation_id
                    && start.sequence < self.initialize.sequence
                    && start.phase_id != self.initialize.phase_id
                    && matches!(&start_request.step, TargetRuntimeStep::Start(TargetReplicaInput::Quorum(q)) if q == &self.quorum),
                "initial membership status changed original Start input",
            )?;
            require(
                matches!(&start.outcome, Some(RecoveryDispatchOutcome::Target(response))
                if response.node_id == *start_node && response.command_id == start_request.command_id
                    && matches!(&response.outcome, TargetRuntimeOutcome::Started{origin_sha256} if origin_sha256 == &self.quorum.origin_sha256)),
                "initial membership status lacks positive original Start",
            )?;
            Self::dispatch_identity(start)?
                .validate_marked_intent(
                    *start_node,
                    start_request,
                    &self.original_intent,
                    &Self::accepted_phase(start)?,
                )
                .map_err(|_| invalid("initial membership status changed original Start marker"))?;
            require(
                Self::dispatch_identity(start)?.attempt_id != self.identity()?.attempt_id,
                "initial membership status reuses Start attempt for Initialize",
            )?;
        }
        require(
            staged_digest(self)?.1 <= 256 << 10,
            "initial membership status exceeds bounded input",
        )?;
        Ok(staged_digest(&("kasumi.target-initial-membership-status-input.v1", self))?.0)
    }
    pub fn validate(&self, origin: &TargetOrigin, current: &LifecycleIntent) -> Result<()> {
        origin.accepts_phase(&self.original_intent, LifecyclePhase::Initialize)?;
        origin.accepts_phase(current, LifecyclePhase::InspectInitialMembership)?;
        let RecoveryDispatch::Target { request, .. } = &self.initialize.input else {
            return Err(invalid("initial membership status lacks original request"));
        };
        require(
            self.quorum.origin_sha256 == origin.digest()?
                && current.control_incarnation == self.original_intent.control_incarnation
                && current.revision
                    > self
                        .initialize
                        .effect_attempts
                        .get(&RecoveryEffect::TargetCommand)
                        .ok_or_else(|| invalid("initial membership status marker absent"))?
                        .begun_revision
                && current.revision > self.initialize.prepared_revision
                && current.revision > self.original_intent.revision
                && current.request.command_id != self.original_intent.request.command_id
                && current.accepted_at_ms >= request.not_after_ms
                && current.request.phase_input_sha256 == self.digest()?,
            "initial membership status requires a later exact current Control phase",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInitialMembershipStatusObservation {
    pub association: SignedTargetInitializationAssociation,
    pub association_position: TargetInitialMembershipPosition,
    pub input: TargetInitialMembershipStatusInput,
    pub status_intent: LifecycleIntent,
    pub first_fact_sha256: String,
    pub first_log_index: u64,
    pub applied_log_index: u64,
    pub committed_log_index: u64,
    pub observer_node_id: u64,
    pub observed_term: u64,
}
impl TargetInitialMembershipStatusObservation {
    pub fn origin(&self) -> Result<&TargetOrigin> {
        self.input
            .quorum
            .materialized
            .values()
            .next()
            .map(|m| &m.fact.origin)
            .ok_or_else(|| invalid("initial membership status materializations absent"))
    }
    pub fn validate(&self) -> Result<()> {
        self.input.validate(self.origin()?, &self.status_intent)?;
        validate_sha256(&self.first_fact_sha256)?;
        self.association
            .association
            .matches_inspection(&self.input)?;
        self.association_position.validate()?;
        require(
            self.association_position.index == self.first_log_index
                && self.association_position.index <= self.applied_log_index
                && self.association_position.command_sha256 == staged_digest(&self.association)?.0
                && self.input.starts.contains_key(&self.observer_node_id)
                && self.observed_term > 0
                && self.first_log_index <= self.applied_log_index
                && self.applied_log_index <= self.committed_log_index,
            "initial membership status lacks exact associated current quorum history",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTargetInitialMembershipStatus {
    pub observation: TargetInitialMembershipStatusObservation,
    pub signature: String,
}
fn invalid(message: &str) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}
fn require(value: bool, message: &str) -> Result<()> {
    if value { Ok(()) } else { Err(invalid(message)) }
}
