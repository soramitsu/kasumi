//! A fresh read-only observation of one exact original Resolve outcome. It
//! cannot seal an absent record or grant a replacement resolver deadline.
use crate::*;
use serde::{Deserialize, Serialize};

/// A bounded terminal fact plus its exact original and current Control inputs.
pub const MAX_TARGET_COMPLETION_TERMINAL_STATUS_BYTES: u64 = MAX_TARGET_COMPLETION_RECORD_BYTES * 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompletionTerminalStatusInput {
    pub original_intent: LifecycleIntent,
    pub original_input: TargetCompletionResolutionInput,
    pub original_dispatch_not_after_ms: u64,
}
impl TargetCompletionTerminalStatusInput {
    pub fn digest(&self) -> Result<String> {
        self.original_input
            .validate(&self.original_input.attempt.origin, &self.original_intent)?;
        require(
            self.original_dispatch_not_after_ms > self.original_intent.accepted_at_ms
                && self.original_dispatch_not_after_ms
                    <= self.original_intent.original_credential_expires_at_ms,
            "terminal status changed original resolver dispatch cap",
        )?;
        bounded(self)?;
        Ok(staged_digest(&("kasumi.target-completion-terminal-status-input.v1", self))?.0)
    }
    pub fn validate(&self, origin: &TargetOrigin, current: &LifecycleIntent) -> Result<()> {
        origin.accepts_phase(current, LifecyclePhase::InspectCompletionResolution)?;
        require(
            self.original_input.attempt.origin == *origin
                && current.control_incarnation == self.original_intent.control_incarnation
                && current.revision > self.original_intent.revision
                && current.request.command_id != self.original_intent.request.command_id
                && current.request.phase_input_sha256 == self.digest()?
                && current.request_sha256 == staged_digest(&current.request)?.0
                && current.accepted_at_ms < current.original_credential_expires_at_ms,
            "terminal status requires an exact later current Control phase",
        )
    }
    pub fn matches(&self, fact: &TargetCompletionResolutionFact) -> Result<()> {
        fact.validate()?;
        require(
            fact.resolution_intent == self.original_intent
                && fact.input == self.original_input
                && fact.dispatch_not_after_ms == self.original_dispatch_not_after_ms,
            "terminal status substituted the original resolver or applying fact",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompletionTerminalStatusObservation {
    pub input: TargetCompletionTerminalStatusInput,
    pub status_intent: LifecycleIntent,
    pub fact: TargetCompletionResolutionFact,
    pub observer_node_id: u64,
    pub observed_revision: u64,
    pub observed_term: u64,
}
impl TargetCompletionTerminalStatusObservation {
    pub fn validate(&self) -> Result<()> {
        self.input
            .validate(&self.fact.input.attempt.origin, &self.status_intent)?;
        self.input.matches(&self.fact)?;
        require(
            self.fact
                .input
                .attempt
                .origin
                .input
                .voters
                .contains_key(&self.observer_node_id)
                && self.observed_revision >= self.fact.revision
                && self.observed_term >= self.fact.position.term,
            "terminal status is not a current quorum observation of its original fact",
        )?;
        bounded(self)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTargetCompletionTerminalStatus {
    pub observation: TargetCompletionTerminalStatusObservation,
    pub signature: String,
}
fn bounded(value: &impl Serialize) -> Result<()> {
    require(
        staged_digest(value)?.1 <= MAX_TARGET_COMPLETION_TERMINAL_STATUS_BYTES as usize,
        "terminal status exceeds bounded record work",
    )
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::new(ErrorCode::InvalidArgument, message))
    }
}
