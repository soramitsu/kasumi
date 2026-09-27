//! Original execution cause retained by consensus. These historical bytes grant
//! neither Initialize execution authority nor a current inspection capability.
use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInitializationAssociation {
    pub control_root: ControlSigningRoot,
    pub original_intent: LifecycleIntent,
    pub quorum: TargetQuorumInput,
    pub start: RecoveryPhaseRecord,
    pub initialize: RecoveryPhaseRecord,
}
impl TargetInitializationAssociation {
    pub fn origin(&self) -> Result<&TargetOrigin> {
        self.quorum
            .materialized
            .values()
            .next()
            .map(|m| &m.fact.origin)
            .ok_or_else(|| invalid("initialization cause materializations absent"))
    }
    pub fn node_id(&self) -> Result<u64> {
        match &self.initialize.input {
            RecoveryDispatch::Target { node_id, .. } => Ok(*node_id),
            _ => Err(invalid("initialization cause lacks original target")),
        }
    }
    pub fn validate(&self) -> Result<()> {
        self.control_root.validate()?;
        let origin = self.origin()?;
        origin.accepts_phase(&self.original_intent, LifecyclePhase::Initialize)?;
        let node = self.node_id()?;
        require(
            self.control_root.control_incarnation == self.original_intent.control_incarnation
                && self.quorum.origin_sha256 == origin.digest()?
                && self.original_intent.request.target_nodes.keys().next() == Some(&node)
                && self.quorum.materialized.len() == 3
                && self.quorum.materialized.keys().eq(self
                    .original_intent
                    .request
                    .target_nodes
                    .keys()),
            "initialization cause installed identity differs",
        )?;
        for (phase, initialize) in [(&self.start, false), (&self.initialize, true)] {
            let RecoveryDispatch::Target { node_id, request } = &phase.input else {
                return Err(invalid("initialization cause dispatch absent"));
            };
            require(
                *node_id == node
                    && if initialize {
                        matches!(&request.step, TargetRuntimeStep::Initialize(q) if q == &self.quorum)
                    } else {
                        matches!(&request.step, TargetRuntimeStep::Start(TargetReplicaInput::Quorum(q)) if q == &self.quorum)
                    },
                "initialization cause packet differs",
            )?;
            TargetInitialMembershipStatusInput::dispatch_identity(phase)?
                .validate_marked_intent(node, request, &self.original_intent, phase)
                .map_err(|_| invalid("initialization cause accepted marker differs"))?;
        }
        let start = TargetInitialMembershipStatusInput::dispatch_identity(&self.start)?;
        let initialize = TargetInitialMembershipStatusInput::dispatch_identity(&self.initialize)?;
        require(
            start.operation_id == initialize.operation_id
                && start.phase_id != initialize.phase_id
                && start.attempt_id != initialize.attempt_id
                && self.start.sequence < self.initialize.sequence
                && self.start.effect_attempts[&RecoveryEffect::TargetCommand].begun_revision
                    < self.initialize.prepared_revision
                && staged_digest(self)?.1 <= 256 << 10,
            "initialization cause order, identity or bound differs",
        )
    }
    pub fn matches_inspection(&self, input: &TargetInitialMembershipStatusInput) -> Result<()> {
        self.validate()?;
        input.digest()?;
        let start = input
            .starts
            .get(&self.node_id()?)
            .ok_or_else(|| invalid("inspection lacks original designated Start"))?;
        require(
            self.original_intent == input.original_intent
                && self.quorum == input.quorum
                && self.initialize == input.initialize
                && self.start == TargetInitialMembershipStatusInput::accepted_phase(start)?,
            "inspection original accepted history differs from committed cause",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTargetInitializationAssociation {
    pub association: TargetInitializationAssociation,
    pub signature: String,
}
fn invalid(message: &str) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}
fn require(value: bool, message: &str) -> Result<()> {
    if value { Ok(()) } else { Err(invalid(message)) }
}

/// Actual position of the original membership entry. OpenRaft assigns the
/// protocol's zero log identity; no caller chooses an application position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInitialMembershipPosition {
    pub index: u64,
    pub term: u64,
    pub leader_node_id: u64,
    pub command_sha256: String,
}
impl TargetInitialMembershipPosition {
    pub fn validate(&self) -> Result<()> {
        require(
            self.index == 0 && self.term == 0 && self.leader_node_id == 0,
            "initial membership position is not the protocol's first entry",
        )?;
        validate_sha256(&self.command_sha256)
    }
}
