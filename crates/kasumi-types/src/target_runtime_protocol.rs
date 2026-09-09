//! Native target request routing contains only installed semantic identifiers.
use crate::authority_protocol::protocol_digest as digest;
use crate::*;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
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
