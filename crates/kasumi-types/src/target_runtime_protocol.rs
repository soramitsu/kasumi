//! Native target request routing contains only installed semantic identifiers.
use crate::authority_protocol::protocol_digest as digest;
use crate::*;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Native Execute carries this outside the frozen RecoveryDispatch input:
/// BeginEffect assigns the attempt ID only after that input is committed.
/// These bytes are a claim for a later installed-Control read, not authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInitialDispatchIdentity {
    pub operation_id: Uuid,
    pub phase_id: Uuid,
    pub attempt_id: Uuid,
    pub input_sha256: String,
}

impl TargetInitialDispatchIdentity {
    pub fn validate_for(&self, node_id: u64, request: &TargetRuntimeRequest) -> Result<()> {
        ensure!(
            matches!(
                &request.step,
                TargetRuntimeStep::Start(TargetReplicaInput::Quorum(_))
                    | TargetRuntimeStep::Initialize(_)
            ),
            "initial target identity requires first-membership step"
        );
        ensure!(
            node_id != 0
                && !self.operation_id.is_nil()
                && !self.phase_id.is_nil()
                && !self.attempt_id.is_nil(),
            "initial target dispatch identity is incomplete"
        );
        validate_sha256(&self.input_sha256)?;
        ensure!(
            self.input_sha256
                == staged_digest(&RecoveryDispatch::Target {
                    node_id,
                    request: Box::new(request.clone()),
                })?
                .0,
            "initial target dispatch differs from frozen target input"
        );
        Ok(())
    }

    /// Compare bytes returned by a fresh installed-Control ReadPhase to the
    /// signed lifecycle intent and exact native packet. The caller must own
    /// that authenticated read; this structural check grants no child ticket.
    pub fn validate_marked_phase(
        &self,
        installed_root: &ControlSigningRoot,
        node_id: u64,
        request: &TargetRuntimeRequest,
        lifecycle: &LifecycleIntent,
        phase: &RecoveryPhaseRecord,
    ) -> Result<()> {
        self.validate_for(node_id, request)?;
        installed_root.validate()?;
        lifecycle.request.validate()?;
        phase.validate()?;
        let RecoveryDispatch::Target {
            node_id: marked_node,
            request: marked_request,
        } = &phase.input
        else {
            anyhow::bail!("marked recovery phase is not a target dispatch")
        };
        let marker = phase
            .effect_attempts
            .get(&RecoveryEffect::TargetCommand)
            .context("marked recovery phase lacks TargetCommand attempt")?;
        let quorum = match &request.step {
            TargetRuntimeStep::Start(TargetReplicaInput::Quorum(input))
            | TargetRuntimeStep::Initialize(input) => input,
            _ => anyhow::bail!("marked recovery phase is not first membership"),
        };
        ensure!(
            phase.operation_id == self.operation_id
                && phase.phase_id == self.phase_id
                && phase.phase == RecoveryPhase::Initialize
                && phase.outcome.is_none()
                && phase.resolved_revision.is_none()
                && phase.input_sha256 == self.input_sha256
                && *marked_node == node_id
                && **marked_request == *request
                && marker.attempt_id == self.attempt_id
                && marker.input_sha256 == self.input_sha256
                && marker.begun_revision > phase.prepared_revision
                && phase.principal == lifecycle.original_principal
                && lifecycle.control_incarnation == installed_root.control_incarnation
                && lifecycle.request.phase == LifecyclePhase::Initialize
                && lifecycle.request.command_id == request.command_id
                && lifecycle.request.tenant == request.tenant
                && lifecycle.request.target_nodes.contains_key(&node_id)
                && lifecycle.request.phase_input_sha256 == quorum.digest()?
                && lifecycle.request_sha256 == staged_digest(&lifecycle.request)?.0
                && lifecycle.installation_generation > 0
                && lifecycle.revision > 0
                && lifecycle.accepted_at_ms < lifecycle.original_credential_expires_at_ms
                && lifecycle.accepted_at_ms <= phase.admitted_at_ms
                && request.not_after_ms <= phase.original_credential_expires_at_ms
                && (!matches!(&request.step, TargetRuntimeStep::Initialize(_))
                    || (phase.sequence > 1 && phase.previous_phase.is_some())),
            "marked recovery phase differs from exact first-membership dispatch or lifecycle intent"
        );
        Ok(())
    }
}

/// Required first-release wire envelope. A missing `initial_dispatch` is an
/// old contract, even for a noninitial step; those packets send explicit null.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetExecuteRequest {
    pub request: TargetRuntimeRequest,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub initial_dispatch: Option<TargetInitialDispatchIdentity>,
}

/// Status-only lookup of one previously accepted first-membership dispatch.
/// The claimed incarnation selects an already owned target store; it grants no
/// Execute permission and is checked against fresh Control and local history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInitialMembershipHistoryRequest {
    pub target_incarnation: Uuid,
    pub request: TargetRuntimeRequest,
    pub identity: TargetInitialDispatchIdentity,
}

/// Status for an exact previously accepted Start packet. This cannot select
/// Initialize or authorize a new/replacement child after shutdown or restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInitialStartRequest {
    pub target_incarnation: Uuid,
    pub request: TargetRuntimeRequest,
    pub identity: TargetInitialDispatchIdentity,
}
impl TargetInitialStartRequest {
    pub fn validate_for_node(&self, node_id: u64) -> Result<()> {
        ensure!(
            !self.target_incarnation.is_nil(),
            "Start target incarnation absent"
        );
        ensure!(
            matches!(
                self.request.step,
                TargetRuntimeStep::Start(TargetReplicaInput::Quorum(_))
            ),
            "Start status requires the original Start packet"
        );
        self.identity.validate_for(node_id, &self.request)?;
        ensure!(
            serde_json::to_vec(self)?.len() <= 512 << 10,
            "Start query exceeds bound"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInitialStartStatus {
    pub contract: String,
    pub target_incarnation: Uuid,
    pub node_id: u64,
    pub identity: TargetInitialDispatchIdentity,
    pub origin_sha256: String,
}
impl TargetInitialStartStatus {
    pub const CONTRACT: &'static str = "kasumi.initial-start-status.v1";
    pub fn validate_for(&self, query: &TargetInitialStartRequest, node_id: u64) -> Result<()> {
        query.validate_for_node(node_id)?;
        let TargetRuntimeStep::Start(TargetReplicaInput::Quorum(input)) = &query.request.step
        else {
            anyhow::bail!("Start status input differs")
        };
        ensure!(
            self.contract == Self::CONTRACT
                && self.node_id == node_id
                && self.target_incarnation == query.target_incarnation
                && self.identity == query.identity
                && self.origin_sha256 == input.origin_sha256,
            "Start status differs from exact query"
        );
        Ok(())
    }
}

impl TargetInitialMembershipHistoryRequest {
    pub fn validate_for_node(&self, node_id: u64) -> Result<()> {
        ensure!(
            !self.target_incarnation.is_nil(),
            "historical target incarnation absent"
        );
        self.identity.validate_for(node_id, &self.request)?;
        ensure!(
            serde_json::to_vec(self)?.len() <= 512 << 10,
            "historical target query exceeds bound"
        );
        Ok(())
    }
}

/// A current receiver observation of retained history only. It does not
/// authorize child startup, a new dispatch, or a current Raft quorum claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInitialMembershipHistoryStatus {
    pub contract: String,
    pub target_incarnation: Uuid,
    pub identity: TargetInitialDispatchIdentity,
    pub first_log_index: u64,
    pub applied_log_index: u64,
    pub committed_log_index: u64,
}

impl TargetInitialMembershipHistoryStatus {
    pub const CONTRACT: &'static str = "kasumi.initial-membership-history.v1";

    pub fn validate_for(&self, query: &TargetInitialMembershipHistoryRequest) -> Result<()> {
        ensure!(
            self.contract == Self::CONTRACT
                && self.target_incarnation == query.target_incarnation
                && self.identity == query.identity
                && self.first_log_index <= self.applied_log_index
                && self.first_log_index <= self.committed_log_index,
            "historical first-membership status differs from exact query"
        );
        Ok(())
    }
}

impl TargetExecuteRequest {
    pub fn validate_for_node(&self, node_id: u64) -> Result<()> {
        ensure!(node_id != 0, "native target node identity is absent");
        self.request.validate()?;
        let first_membership = matches!(
            &self.request.step,
            TargetRuntimeStep::Start(TargetReplicaInput::Quorum(_))
                | TargetRuntimeStep::Initialize(_)
        );
        ensure!(
            first_membership == self.initial_dispatch.is_some(),
            "initial target dispatch identity and step differ"
        );
        if let Some(identity) = &self.initial_dispatch {
            identity.validate_for(node_id, &self.request)?;
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= 512 << 10,
            "native target execute envelope exceeds bound"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRuntimeRequest {
    pub tenant: String,
    pub command_id: Uuid,
    /// Absolute original dispatch cap, retained across endpoint retries.
    pub not_after_ms: u64,
    pub step: TargetRuntimeStep,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TargetRuntimeStep {
    Materialize(TargetMaterializationInput),
    ResumeMaterialization(Box<TargetOrigin>),
    Start(TargetReplicaInput),
    Initialize(TargetQuorumInput),
    Complete(TargetCompletionInput),
    PrepareComplete(TargetCompletionInput),
    ResolveComplete(Box<TargetCompletionResolutionInput>),
    MaintainBudget {
        quorum: TargetQuorumInput,
        input: TargetResolutionBudgetInput,
    },
    /// Open one voter under the exact independently committed issuer winner.
    /// This does not propose or confirm target activation.
    StartActivation {
        quorum: TargetQuorumInput,
        issuer_command_id: Uuid,
    },
    Activate {
        quorum: TargetQuorumInput,
        issuer_command_id: Uuid,
    },
    ConfirmActivation(Box<SignedTargetActivation>),
    ConfirmInspection(Box<SignedTargetInspection>),
    Inspect(Box<TargetInspectionInput>),
    InspectCompletionAttempt(Box<TargetCompletionAttemptStatusInput>),
    InspectCompletionResolution(Box<TargetCompletionTerminalStatusInput>),
    Stop(TargetStopReference),
}
impl TargetRuntimeRequest {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.tenant)?;
        ensure!(
            !self.command_id.is_nil()
                && self.not_after_ms > 0
                && serde_json::to_vec(self)?.len() <= 256 << 10,
            "target runtime request exceeds bounds"
        );
        match &self.step {
            TargetRuntimeStep::Materialize(input) => {
                input.digest()?;
            }
            TargetRuntimeStep::ResumeMaterialization(origin) => {
                origin.resume_digest()?;
            }
            TargetRuntimeStep::Start(input) => {
                input.quorum().digest()?;
            }
            TargetRuntimeStep::Initialize(input) => {
                input.digest()?;
            }
            TargetRuntimeStep::Complete(input) | TargetRuntimeStep::PrepareComplete(input) => {
                input.digest()?;
            }
            TargetRuntimeStep::ResolveComplete(input) => {
                input.digest()?;
            }
            TargetRuntimeStep::MaintainBudget { quorum, input } => {
                quorum.digest()?;
                input.digest()?;
            }
            TargetRuntimeStep::StartActivation {
                quorum,
                issuer_command_id,
            }
            | TargetRuntimeStep::Activate {
                quorum,
                issuer_command_id,
            } => {
                quorum.digest()?;
                ensure!(
                    !issuer_command_id.is_nil(),
                    "missing issuer winner identity"
                );
            }
            TargetRuntimeStep::ConfirmActivation(signed) => {
                signed.observation.validate()?;
            }
            TargetRuntimeStep::ConfirmInspection(signed) => {
                signed.observation.validate()?;
            }
            TargetRuntimeStep::Inspect(input) => {
                input.digest()?;
            }
            TargetRuntimeStep::InspectCompletionAttempt(input) => {
                input.digest()?;
            }
            TargetRuntimeStep::InspectCompletionResolution(input) => {
                input.digest()?;
            }
            TargetRuntimeStep::Stop(reference) => {
                reference.validate()?;
                ensure!(reference.tenant == self.tenant, "target stop route differs");
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRuntimeResponse {
    pub command_id: Uuid,
    pub node_id: u64,
    pub outcome: TargetRuntimeOutcome,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TargetRuntimeOutcome {
    Materialized(Box<SignedTargetMaterialization>),
    /// Local Raft owner exists under the live exact phase. This is not a
    /// completion or membership proof and cannot authorize issuer activation.
    Started {
        origin_sha256: String,
    },
    Initialized {
        origin_sha256: String,
    },
    Completed(Box<SignedTargetCompletion>),
    /// A positive capacity reservation, never a completion/activation proof.
    PreparedCompletion(Box<SignedTargetCompletionAttempt>),
    ResolvedCompletion(Box<SignedTargetCompletionResolution>),
    ResolutionBudget(Box<SignedTargetResolutionBudget>),
    Activated(Box<SignedTargetActivation>),
    Inspected(Box<SignedTargetInspection>),
    CompletionAttemptStatus(Box<SignedTargetCompletionAttemptStatus>),
    CompletionTerminalStatus(Box<SignedTargetCompletionTerminalStatus>),
    Stopped(Box<SignedLocalTargetCleanup>),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalTargetCleanupFact {
    pub intent: LifecycleIntent,
    pub node_id: u64,
    pub stopped: SignedTargetStop,
    pub stop_receipt_sha256: String,
    pub observed_at_ms: u64,
}
impl LocalTargetCleanupFact {
    pub fn validate(&self) -> Result<()> {
        self.intent.request.validate()?;
        self.stopped.observation.reference.validate()?;
        validate_sha256(&self.stop_receipt_sha256)?;
        let i = &self.intent.request;
        ensure!(
            i.phase == LifecyclePhase::StopLocal
                && i.tenant == self.stopped.observation.reference.tenant
                && i.target_nodes.contains_key(&self.node_id)
                && i.phase_input_sha256
                    == digest(&(
                        "kasumi.stop-local-target-input.v1",
                        &self.stopped.observation.reference
                    ))?
                && self.observed_at_ms >= self.intent.accepted_at_ms
                && self.observed_at_ms < self.intent.original_credential_expires_at_ms,
            "local target cleanup fact differs"
        );
        let AuthorityOutcome::TargetStopped {
            source_incarnation,
            source_epoch,
            target,
        } = &self.stopped.observation.stop.outcome
        else {
            anyhow::bail!("cleanup lacks permanent incarnation stop")
        };
        ensure!(
            *source_incarnation == i.source_incarnation
                && *source_epoch == i.source_authority_epoch
                && target.incarnation == i.target_incarnation
                && target.checkpoint == i.checkpoint
                && self.stop_receipt_sha256 == self.stopped.observation.stop.digest()?,
            "cleanup stop binding differs"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLocalTargetCleanup {
    pub fact: LocalTargetCleanupFact,
    pub signature: String,
}

#[cfg(test)]
mod execute_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn initial() -> TargetExecuteRequest {
        let request = TargetRuntimeRequest {
            tenant: "target".into(),
            command_id: Uuid::from_u128(101),
            not_after_ms: 500,
            step: TargetRuntimeStep::Start(TargetReplicaInput::Quorum(TargetQuorumInput {
                origin_sha256: "11".repeat(32),
                materialized: BTreeMap::new(),
            })),
        };
        let input_sha256 = staged_digest(&RecoveryDispatch::Target {
            node_id: 1,
            request: Box::new(request.clone()),
        })
        .unwrap()
        .0;
        TargetExecuteRequest {
            request,
            initial_dispatch: Some(TargetInitialDispatchIdentity {
                operation_id: Uuid::from_u128(201),
                phase_id: Uuid::from_u128(301),
                attempt_id: Uuid::from_u128(401),
                input_sha256,
            }),
        }
    }

    #[test]
    fn exact_initial_execute_envelope_is_outside_frozen_input() {
        let envelope = initial();
        envelope.validate_for_node(1).unwrap();
        let bytes = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(
            serde_json::from_slice::<TargetExecuteRequest>(&bytes).unwrap(),
            envelope
        );
        assert!(envelope.validate_for_node(2).is_err());
        let mut wrong = envelope.clone();
        wrong.initial_dispatch.as_mut().unwrap().attempt_id = Uuid::nil();
        assert!(wrong.validate_for_node(1).is_err());
        let mut wrong = envelope.clone();
        wrong.initial_dispatch.as_mut().unwrap().input_sha256 = "ff".repeat(32);
        assert!(wrong.validate_for_node(1).is_err());
        let mut absent = envelope.clone();
        absent.initial_dispatch = None;
        assert!(absent.validate_for_node(1).is_err());
    }

    #[test]
    fn first_release_execute_wire_rejects_missing_and_extra_identity_fields() {
        let envelope = initial();
        assert!(
            serde_json::from_value::<TargetExecuteRequest>(
                serde_json::to_value(&envelope.request).unwrap()
            )
            .is_err()
        );
        let mut value = serde_json::to_value(&envelope).unwrap();
        value.as_object_mut().unwrap().remove("initial_dispatch");
        assert!(serde_json::from_value::<TargetExecuteRequest>(value).is_err());
        let mut value = serde_json::to_value(&envelope).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("legacy".into(), true.into());
        assert!(serde_json::from_value::<TargetExecuteRequest>(value).is_err());
        let mut value = serde_json::to_value(&envelope).unwrap();
        value["initial_dispatch"]
            .as_object_mut()
            .unwrap()
            .remove("attempt_id");
        assert!(serde_json::from_value::<TargetExecuteRequest>(value).is_err());
        let mut value = serde_json::to_value(&envelope).unwrap();
        value["initial_dispatch"]
            .as_object_mut()
            .unwrap()
            .insert("untrusted_grant".into(), true.into());
        assert!(serde_json::from_value::<TargetExecuteRequest>(value).is_err());
        // Other phases have an explicit null; omission is never a decoder shim.
        let mut other = envelope.clone();
        other.request.step = TargetRuntimeStep::Materialize(TargetMaterializationInput {
            destination_alias: "archive".into(),
            backup_id: Uuid::from_u128(501),
            source_purpose_sha256: "22".repeat(32),
            target_incarnation: Uuid::from_u128(601),
            voters: BTreeMap::new(),
        });
        other.initial_dispatch = None;
        other.validate_for_node(1).unwrap();
        other.initial_dispatch = envelope.initial_dispatch.clone();
        assert!(other.validate_for_node(1).is_err());
        other.initial_dispatch = None;
        assert!(
            serde_json::to_string(&other)
                .unwrap()
                .contains("\"initial_dispatch\":null")
        );
    }
}
