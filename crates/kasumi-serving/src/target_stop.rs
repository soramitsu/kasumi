//! Permanent target closure and a separately signed completed drain observation.
//! An immediate stop receipt cannot construct a drained-target proof.
use crate::*;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetStopReference {
    pub tenant: String,
    pub command_id: Uuid,
    pub receipt_digest: String,
}
impl TargetStopReference {
    pub fn validate(&self) -> Result<()> {
        kasumi_types::validate_name(&self.tenant)?;
        kasumi_types::validate_sha256(&self.receipt_digest)?;
        ensure!(!self.command_id.is_nil(), "nil target stop command");
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetStopObservation {
    pub reference: TargetStopReference,
    /// Actual first permanent incarnation stop, even if reference names an
    /// exact later administrative replay command.
    pub stop: AuthorityReceipt,
    pub observed_term: u64,
    pub observed_revision: u64,
    pub drain_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTargetStop {
    pub observation: TargetStopObservation,
    pub signature: String,
}
/// Irrevocable completed drain evidence, not a data or lifecycle lease. Local
/// jobs/storage must still close and drain before physical cleanup is claimed.
/// ```compile_fail
/// let _: kasumi_serving::VerifiedTargetStop=serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedTargetStop {
    signed: SignedTargetStop,
}
impl VerifiedTargetStop {
    pub fn observation(&self) -> &TargetStopObservation {
        &self.signed.observation
    }
    pub fn reference(&self) -> &TargetStopReference {
        &self.signed.observation.reference
    }
    pub fn target(&self) -> &RecoveryTarget {
        match &self.signed.observation.stop.outcome {
            AuthorityOutcome::TargetStopped { target, .. } => target,
            _ => unreachable!("verified stop"),
        }
    }
    pub(crate) fn verified(signed: SignedTargetStop) -> Self {
        Self { signed }
    }
}
