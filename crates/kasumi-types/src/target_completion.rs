//! Exact completion attempts and ordered terminal resolution. Wire records are
//! historical evidence only; live admission requires the installed target owner.
use crate::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_TARGET_COMPLETION_RECORD_BYTES: u64 = 256 << 10;
/// A terminal fact contains the prepared attempt, at most one committed fact
/// derived from it, and one new Control intent. Bound those inputs before
/// reserving capacity, so expiration cannot leave an unencodable terminal.
pub const MAX_TARGET_COMPLETION_ATTEMPT_BYTES: u64 = 64 << 10;
const MAX_TARGET_COMPLETION_INTENT_BYTES: u64 = 16 << 10;
/// PrepareComplete reserves a bounded terminal row with its point/ordinal
/// indexes and framing, plus the eventual completion fact, before dispatch.
pub const TARGET_COMPLETION_RESERVE_BYTES: u64 = MAX_TARGET_COMPLETION_RECORD_BYTES * 3;
/// Complete and its terminal resolver each retain one hot audit event. This
/// reservation is separate from the terminal table's expandable byte budget.
pub const TARGET_COMPLETION_AUDIT_RESERVE_BYTES: u64 = 2 * MAX_AUDIT_EVENT_BYTES as u64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompletionResolutionReference {
    pub origin_sha256: String,
    pub control_incarnation: Uuid,
    pub original_command_id: Uuid,
    pub resolution_command_id: Uuid,
    pub resolution_control_revision: u64,
    pub fact_sha256: String,
}
impl TargetCompletionResolutionReference {
    pub fn validate(&self) -> Result<()> {
        validate_sha256(&self.origin_sha256)?;
        validate_sha256(&self.fact_sha256)?;
        require(
            !self.control_incarnation.is_nil()
                && !self.original_command_id.is_nil()
                && !self.resolution_command_id.is_nil()
                && self.original_command_id != self.resolution_command_id
                && self.resolution_control_revision > 0,
            "invalid exact completion resolution reference",
        )
    }
}

/// A successor names the exact sealed predecessor. A missing receipt or an
/// unrelated target's terminal record cannot populate this reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompletionInput {
    pub quorum: TargetQuorumInput,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub predecessor: Option<TargetCompletionResolutionReference>,
}
impl TargetCompletionInput {
    pub fn digest(&self) -> Result<String> {
        Ok(staged_digest(&("kasumi.target-completion-input.v1", self))?.0)
    }
    pub fn validate(&self, origin: &TargetOrigin, intent: &LifecycleIntent) -> Result<()> {
        exact_phase(origin, intent, LifecyclePhase::Complete)?;
        require(
            self.quorum.origin_sha256 == origin.digest()?
                && intent.request.phase_input_sha256 == self.digest()?,
            "completion input differs from its exact Control phase",
        )?;
        if let Some(predecessor) = &self.predecessor {
            predecessor.validate()?;
            require(
                predecessor.origin_sha256 == self.quorum.origin_sha256
                    && predecessor.control_incarnation == intent.control_incarnation
                    && predecessor.original_command_id != intent.request.command_id
                    && predecessor.resolution_command_id != intent.request.command_id
                    && predecessor.resolution_control_revision < intent.revision,
                "completion successor differs from sealed target or Control order",
            )?;
        }
        bounded(self)
    }
}

/// This bounded resident fact is created by target Raft before Complete is
/// dispatched. Its original cap and reservation are never refreshed by retry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompletionAttempt {
    pub origin: TargetOrigin,
    pub input: TargetCompletionInput,
    pub intent: LifecycleIntent,
    pub dispatch_not_after_ms: u64,
    pub admitted_at_ms: u64,
    pub revision: u64,
    pub position: TargetCommitPosition,
    pub reserved_terminal_bytes: u64,
    pub reserved_audit_bytes: u64,
}
impl TargetCompletionAttempt {
    pub fn validate(&self) -> Result<()> {
        self.input.validate(&self.origin, &self.intent)?;
        position(&self.origin, &self.position, self.revision)?;
        require(
            self.admitted_at_ms >= self.intent.accepted_at_ms
                && self.admitted_at_ms < self.dispatch_not_after_ms
                && self.dispatch_not_after_ms <= self.intent.original_credential_expires_at_ms
                && self.reserved_terminal_bytes == TARGET_COMPLETION_RESERVE_BYTES
                && self.reserved_audit_bytes == TARGET_COMPLETION_AUDIT_RESERVE_BYTES,
            "completion preparation changed original admission or terminal reservation",
        )?;
        bounded_to(self, MAX_TARGET_COMPLETION_ATTEMPT_BYTES)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(staged_digest(&("kasumi.prepared-target-completion.v1", self))?.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompletionAttemptObservation {
    pub attempt: TargetCompletionAttempt,
    pub observer_node_id: u64,
    pub observed_revision: u64,
    pub observed_term: u64,
}
impl TargetCompletionAttemptObservation {
    pub fn validate(&self) -> Result<()> {
        self.attempt.validate()?;
        require(
            self.attempt
                .origin
                .input
                .voters
                .contains_key(&self.observer_node_id)
                && self.observed_revision >= self.attempt.revision
                && self.observed_term >= self.attempt.position.term,
            "completion preparation observation differs from current target quorum",
        )?;
        bounded(self)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTargetCompletionAttempt {
    pub observation: TargetCompletionAttemptObservation,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompletionResolutionInput {
    pub attempt: Box<TargetCompletionAttempt>,
}
impl TargetCompletionResolutionInput {
    pub fn digest(&self) -> Result<String> {
        self.attempt.validate()?;
        Ok(staged_digest(&("kasumi.resolve-target-completion-input.v1", self))?.0)
    }
    pub fn validate(&self, origin: &TargetOrigin, intent: &LifecycleIntent) -> Result<()> {
        self.attempt.validate()?;
        exact_phase(origin, intent, LifecyclePhase::ResolveComplete)?;
        require(
            self.attempt.origin == *origin
                && self.attempt.intent.control_incarnation == intent.control_incarnation
                && self.attempt.intent.revision < intent.revision
                && self.attempt.intent.request.command_id != intent.request.command_id
                && intent.request.phase_input_sha256 == self.digest()?,
            "resolution changed exact original target attempt or Control order",
        )?;
        bounded(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "fact",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum TargetCompletionTerminal {
    Committed(Box<TargetCompletionFact>),
    /// An actual ordered target transition permanently made this exact original
    /// attempt inapplicable before any successor could be admitted.
    Sealed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompletionResolutionFact {
    pub input: TargetCompletionResolutionInput,
    pub resolution_intent: LifecycleIntent,
    pub admitted_at_ms: u64,
    pub dispatch_not_after_ms: u64,
    pub revision: u64,
    pub position: TargetCommitPosition,
    pub terminal: TargetCompletionTerminal,
}
impl TargetCompletionResolutionFact {
    pub fn validate(&self) -> Result<()> {
        let attempt = &self.input.attempt;
        self.input
            .validate(&attempt.origin, &self.resolution_intent)?;
        position(&attempt.origin, &self.position, self.revision)?;
        require(
            self.revision > attempt.revision
                && self.admitted_at_ms >= self.resolution_intent.accepted_at_ms
                && self.admitted_at_ms < self.dispatch_not_after_ms
                && self.dispatch_not_after_ms
                    <= self.resolution_intent.original_credential_expires_at_ms,
            "terminal resolution predates its attempt or extends original authority",
        )?;
        if matches!(self.terminal, TargetCompletionTerminal::Sealed) {
            require(
                self.admitted_at_ms >= attempt.dispatch_not_after_ms,
                "negative resolution cannot seal an unexpired original dispatch",
            )?;
        }
        if let TargetCompletionTerminal::Committed(completion) = &self.terminal {
            completion.validate()?;
            require(
                completion.origin == attempt.origin
                    && completion.completion_intent == attempt.intent
                    && completion.materialized == attempt.input.quorum.materialized
                    && completion.predecessor == attempt.input.predecessor
                    && completion.revision > attempt.revision
                    && completion.revision < self.revision
                    && completion.admitted_at_ms < attempt.dispatch_not_after_ms,
                "committed resolution substituted the exact original completion",
            )?;
        }
        bounded(self)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(staged_digest(&("kasumi.target-completion-resolution.v1", self))?.0)
    }
    pub fn sealed_reference(&self) -> Result<TargetCompletionResolutionReference> {
        self.validate()?;
        require(
            matches!(self.terminal, TargetCompletionTerminal::Sealed),
            "committed completion cannot authorize a successor",
        )?;
        Ok(TargetCompletionResolutionReference {
            origin_sha256: self.input.attempt.origin.digest()?,
            control_incarnation: self.resolution_intent.control_incarnation,
            original_command_id: self.input.attempt.intent.request.command_id,
            resolution_command_id: self.resolution_intent.request.command_id,
            resolution_control_revision: self.resolution_intent.revision,
            fact_sha256: self.digest()?,
        })
    }
}

/// Fresh observation may resolve an old terminal command. It retains the old
/// fact; its new live phase never rewrites that fact's deadline or identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompletionResolutionObservation {
    pub fact: TargetCompletionResolutionFact,
    pub observation_intent: LifecycleIntent,
    pub observer_node_id: u64,
    pub observed_revision: u64,
    pub observed_term: u64,
}
impl TargetCompletionResolutionObservation {
    pub fn validate(&self) -> Result<()> {
        self.fact.validate()?;
        let origin = &self.fact.input.attempt.origin;
        self.fact.input.validate(origin, &self.observation_intent)?;
        require(
            ((self.observation_intent.request.command_id
                == self.fact.resolution_intent.request.command_id
                && self.observation_intent == self.fact.resolution_intent)
                || (self.observation_intent.request.command_id
                    != self.fact.resolution_intent.request.command_id
                    && self.observation_intent.revision > self.fact.resolution_intent.revision))
                && origin.input.voters.contains_key(&self.observer_node_id)
                && self.observed_revision >= self.fact.revision
                && self.observed_term >= self.fact.position.term,
            "terminal observation differs from exact retained resolution or current quorum",
        )?;
        bounded(self)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTargetCompletionResolution {
    pub observation: TargetCompletionResolutionObservation,
    pub signature: String,
}

/// Only the current target's active attempt and last exact sealed predecessor
/// remain resident. Permanent facts live in the selected encrypted row prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompletionHead {
    pub origin_sha256: String,
    pub control_incarnation: Uuid,
    pub initial_budget_bytes: u64,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub budget_operation_id: Option<Uuid>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub predecessor: Option<TargetCompletionResolutionReference>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub active: Option<Box<TargetCompletionAttempt>>,
}
impl TargetCompletionHead {
    pub fn empty(origin: &TargetOrigin, initial_budget_bytes: u64) -> Result<Self> {
        let head = Self {
            origin_sha256: origin.digest()?,
            control_incarnation: origin.materialization.control_incarnation,
            initial_budget_bytes,
            budget_operation_id: None,
            predecessor: None,
            active: None,
        };
        head.validate(origin)?;
        Ok(head)
    }
    pub fn validate(&self, origin: &TargetOrigin) -> Result<()> {
        require(
            self.origin_sha256 == origin.digest()?
                && self.control_incarnation == origin.materialization.control_incarnation
                && self.initial_budget_bytes >= TARGET_COMPLETION_RESERVE_BYTES
                && self.budget_operation_id.is_none_or(|id| !id.is_nil()),
            "completion head belongs to another physical target or Control incarnation",
        )?;
        if let Some(predecessor) = &self.predecessor {
            predecessor.validate()?;
            require(
                predecessor.origin_sha256 == self.origin_sha256
                    && predecessor.control_incarnation == self.control_incarnation,
                "completion head substituted its exact sealed predecessor",
            )?;
        }
        if let Some(active) = &self.active {
            active.validate()?;
            require(
                active.origin == *origin && active.input.predecessor == self.predecessor,
                "active completion did not reserve against the current exact seal",
            )?;
        }
        bounded(self)
    }
}

/// A budget change is an explicit current-Control target maintenance effect.
/// Data commands cannot widen this budget, and replay returns its old outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetResolutionBudgetInput {
    pub operation_id: Uuid,
    pub origin_sha256: String,
    pub expected_bytes: u64,
    pub maximum_bytes: u64,
}
impl TargetResolutionBudgetInput {
    pub fn digest(&self) -> Result<String> {
        validate_sha256(&self.origin_sha256)?;
        require(
            !self.operation_id.is_nil()
                && self.expected_bytes >= TARGET_COMPLETION_RESERVE_BYTES
                && self.maximum_bytes >= TARGET_COMPLETION_RESERVE_BYTES,
            "target metadata budget cannot preserve an attempt terminal reserve",
        )?;
        Ok(staged_digest(&("kasumi.target-resolution-budget-input.v1", self))?.0)
    }
    pub fn validate(&self, origin: &TargetOrigin, intent: &LifecycleIntent) -> Result<()> {
        exact_phase(origin, intent, LifecyclePhase::MaintainTarget)?;
        require(
            self.origin_sha256 == origin.digest()?
                && intent.request.phase_input_sha256 == self.digest()?,
            "target budget maintenance changed installation or Control commitment",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetResolutionBudgetFact {
    pub origin: TargetOrigin,
    pub input: TargetResolutionBudgetInput,
    pub intent: LifecycleIntent,
    pub admitted_at_ms: u64,
    pub dispatch_not_after_ms: u64,
    pub revision: u64,
    pub position: TargetCommitPosition,
}
impl TargetResolutionBudgetFact {
    pub fn validate(&self) -> Result<()> {
        self.input.validate(&self.origin, &self.intent)?;
        position(&self.origin, &self.position, self.revision)?;
        require(
            self.admitted_at_ms >= self.intent.accepted_at_ms
                && self.admitted_at_ms < self.dispatch_not_after_ms
                && self.dispatch_not_after_ms <= self.intent.original_credential_expires_at_ms,
            "target budget maintenance exceeded its original authorization",
        )?;
        bounded(self)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(staged_digest(&("kasumi.target-resolution-budget-fact.v1", self))?.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetResolutionBudgetObservation {
    pub fact: TargetResolutionBudgetFact,
    pub observation_intent: LifecycleIntent,
    pub observer_node_id: u64,
    pub observed_revision: u64,
    pub observed_term: u64,
}
impl TargetResolutionBudgetObservation {
    pub fn validate(&self) -> Result<()> {
        self.fact.validate()?;
        self.fact
            .input
            .validate(&self.fact.origin, &self.observation_intent)?;
        require(
            ((self.observation_intent.request.command_id == self.fact.intent.request.command_id
                && self.observation_intent == self.fact.intent)
                || (self.observation_intent.request.command_id
                    != self.fact.intent.request.command_id
                    && self.observation_intent.revision > self.fact.intent.revision))
                && self
                    .fact
                    .origin
                    .input
                    .voters
                    .contains_key(&self.observer_node_id)
                && self.observed_revision >= self.fact.revision
                && self.observed_term >= self.fact.position.term,
            "target budget observation changed its exact permanent effect or quorum",
        )?;
        bounded(self)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTargetResolutionBudget {
    pub observation: TargetResolutionBudgetObservation,
    pub signature: String,
}

/// The resident selector for an encrypted immutable target-resolution prefix.
/// A physical row beyond this exact count/root is not committed evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetResolutionPrefixHead {
    pub origin_incarnation: String,
    pub count: u64,
    pub encoded_bytes: u64,
    pub sha256: String,
}
impl TargetResolutionPrefixHead {
    pub fn validate(&self, tenant: &str) -> Result<()> {
        validate_sha256(&self.sha256)?;
        let empty = Self::empty(tenant, &self.origin_incarnation)?;
        require(
            (self.count == 0 && *self == empty)
                || (self.count > 0 && self.encoded_bytes >= self.count),
            "target resolution prefix count, bytes or empty root differs",
        )
    }
    pub fn empty(tenant: &str, origin_incarnation: &str) -> Result<Self> {
        validate_name(tenant)?;
        validate_name(origin_incarnation)?;
        Ok(Self {
            origin_incarnation: origin_incarnation.into(),
            count: 0,
            encoded_bytes: 0,
            sha256: staged_digest(&(
                "kasumi.target-resolution-prefix.v1",
                tenant,
                origin_incarnation,
            ))?
            .0,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "fact",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum TargetResolutionRecord {
    Completion(Box<TargetCompletionResolutionFact>),
    Budget(Box<TargetResolutionBudgetFact>),
}
impl TargetResolutionRecord {
    pub fn key(&self) -> String {
        match self {
            Self::Completion(fact) => format!(
                "completion/{}/{}",
                fact.input.attempt.origin.input.target_incarnation,
                fact.input.attempt.intent.request.command_id
            ),
            Self::Budget(fact) => format!(
                "budget/{}/{}",
                fact.origin.input.target_incarnation, fact.input.operation_id
            ),
        }
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Completion(fact) => fact.validate()?,
            Self::Budget(fact) => fact.validate()?,
        }
        bounded(self)
    }
    pub fn origin(&self) -> &TargetOrigin {
        match self {
            Self::Completion(fact) => &fact.input.attempt.origin,
            Self::Budget(fact) => &fact.origin,
        }
    }
    pub fn position(&self) -> &TargetCommitPosition {
        match self {
            Self::Completion(fact) => &fact.position,
            Self::Budget(fact) => &fact.position,
        }
    }
    pub fn revision(&self) -> u64 {
        match self {
            Self::Completion(fact) => fact.revision,
            Self::Budget(fact) => fact.revision,
        }
    }
}

fn exact_phase(
    origin: &TargetOrigin,
    intent: &LifecycleIntent,
    phase: LifecyclePhase,
) -> Result<()> {
    origin.accepts_phase(intent, phase)?;
    validate_name(&intent.original_principal)?;
    bounded_to(intent, MAX_TARGET_COMPLETION_INTENT_BYTES)?;
    require(
        intent.request.installation_sha256 == origin.materialization.request.installation_sha256
            && intent.request.authority_partition
                == origin.materialization.request.authority_partition
            && intent.revision > origin.materialization.revision,
        "target completion phase changed immutable Control installation or order",
    )
}
fn position(origin: &TargetOrigin, position: &TargetCommitPosition, revision: u64) -> Result<()> {
    position.validate()?;
    require(
        origin.input.voters.contains_key(&position.leader_node_id)
            && origin
                .materialization
                .request
                .checkpoint
                .revision
                .checked_add(1)
                .and_then(|base| base.checked_add(position.index))
                == Some(revision),
        "completion position differs from actual target generation",
    )
}
fn bounded(value: &impl Serialize) -> Result<()> {
    bounded_to(value, MAX_TARGET_COMPLETION_RECORD_BYTES)
}
fn bounded_to(value: &impl Serialize, maximum: u64) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "completion record encoding failed",
        )
    })?;
    require(
        u64::try_from(bytes.len()).is_ok_and(|length| length <= maximum),
        "completion record exceeds bounded canonical format",
    )
}
fn require(value: bool, message: &str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(Error::new(ErrorCode::InvalidArgument, message))
    }
}
