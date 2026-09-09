//! A fresh, read-only Control phase can recover positive original preparation
//! evidence. The original dispatch deadline never becomes live authorization.
use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompletionAttemptStatusInput {
    pub original_intent: LifecycleIntent,
    pub original_input: TargetCompletionInput,
    pub original_dispatch_not_after_ms: u64,
}
impl TargetCompletionAttemptStatusInput {
    pub fn digest(&self) -> Result<String> {
        self.original_intent.request.validate()?;
        require(
            self.original_intent.request.phase == LifecyclePhase::Complete
                && self.original_intent.request_sha256
                    == staged_digest(&self.original_intent.request)?.0
                && self.original_intent.request.phase_input_sha256
                    == self.original_input.digest()?
                && self.original_dispatch_not_after_ms > self.original_intent.accepted_at_ms
                && self.original_dispatch_not_after_ms
                    <= self.original_intent.original_credential_expires_at_ms,
            "preparation status changed original intent, input or dispatch cap",
        )?;
        bounded(self)?;
        Ok(staged_digest(&("kasumi.target-completion-attempt-status-input.v1", self))?.0)
    }
    pub fn validate(&self, origin: &TargetOrigin, current: &LifecycleIntent) -> Result<()> {
        self.original_input
            .validate(origin, &self.original_intent)?;
        origin.accepts_phase(current, LifecyclePhase::InspectCompletionAttempt)?;
        require(
            current.control_incarnation == self.original_intent.control_incarnation
                && current.revision > self.original_intent.revision
                && current.request.command_id != self.original_intent.request.command_id
                && current.request.phase_input_sha256 == self.digest()?
                && current.request_sha256 == staged_digest(&current.request)?.0
                && current.accepted_at_ms < current.original_credential_expires_at_ms,
            "preparation status requires a distinct exact current Control phase",
        )
    }
    pub fn matches(&self, attempt: &TargetCompletionAttempt) -> Result<()> {
        attempt.validate()?;
        require(
            attempt.intent == self.original_intent
                && attempt.input == self.original_input
                && attempt.dispatch_not_after_ms == self.original_dispatch_not_after_ms,
            "preparation status substituted the original applying attempt",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompletionAttemptStatusObservation {
    pub input: TargetCompletionAttemptStatusInput,
    pub status_intent: LifecycleIntent,
    pub attempt: TargetCompletionAttempt,
    pub observer_node_id: u64,
    pub observed_revision: u64,
    pub observed_term: u64,
}
impl TargetCompletionAttemptStatusObservation {
    pub fn validate(&self) -> Result<()> {
        self.input
            .validate(&self.attempt.origin, &self.status_intent)?;
        self.input.matches(&self.attempt)?;
        require(
            self.attempt
                .origin
                .input
                .voters
                .contains_key(&self.observer_node_id)
                && self.observed_revision >= self.attempt.revision
                && self.observed_term >= self.attempt.position.term,
            "preparation status is not an actual current target observation",
        )?;
        bounded(self)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTargetCompletionAttemptStatus {
    pub observation: TargetCompletionAttemptStatusObservation,
    pub signature: String,
}
fn bounded(value: &impl Serialize) -> Result<()> {
    require(
        staged_digest(value)?.1 <= MAX_TARGET_COMPLETION_RECORD_BYTES as usize,
        "preparation status exceeds its bounded record budget",
    )
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::new(ErrorCode::InvalidArgument, message))
    }
}
