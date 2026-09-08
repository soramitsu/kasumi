//! Permanent target closure and a separately signed completed drain observation.
//! An immediate stop receipt cannot construct a drained-target proof.
use crate::*;

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
    pub fn signed(&self) -> &SignedTargetStop {
        &self.signed
    }
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
