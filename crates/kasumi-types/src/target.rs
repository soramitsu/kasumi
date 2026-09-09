//! Bounded native target facts. These records never create execution authority;
//! native verifiers retain their original Control invocation and issuer gate.
use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const MAX_TARGET_HISTORY: usize = 1024;
pub const MAX_TARGET_HISTORY_BYTES: usize = 8 << 20;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetPeer {
    pub endpoint: String,
    pub failure_domain: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetMaterializationInput {
    pub destination_alias: String,
    pub backup_id: Uuid,
    pub source_purpose_sha256: String,
    pub target_incarnation: Uuid,
    #[serde(deserialize_with = "crate::deserialize_u64_map")]
    pub voters: BTreeMap<u64, TargetPeer>,
}
impl TargetMaterializationInput {
    pub fn validate(&self, intent: &LifecycleIntent) -> Result<()> {
        validate_sha256(&self.source_purpose_sha256)?;
        validate_name(&self.destination_alias)?;
        let request = &intent.request;
        require(
            request.phase == LifecyclePhase::Materialize
                && self.backup_id == request.checkpoint.backup_id
                && self.target_incarnation == request.target_incarnation
                && self.voters.len() == 3
                && self.voters.keys().eq(request.target_nodes.keys())
                && self.digest()? == request.phase_input_sha256,
            "materialization differs from exact committed phase",
        )?;
        let mut domains = BTreeSet::new();
        for (id, peer) in &self.voters {
            require(
                *id > 0
                    && !peer.endpoint.is_empty()
                    && peer.endpoint.len() <= 2048
                    && domains.insert(&peer.failure_domain),
                "invalid target placement or failure domains",
            )?;
            validate_name(&peer.failure_domain)?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        Ok(staged_digest(&("kasumi.materialize-target-input.v1", self))?.0)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetOrigin {
    pub authority_manifest_sha256: String,
    pub materialization: LifecycleIntent,
    pub input: TargetMaterializationInput,
}
impl TargetOrigin {
    pub fn resume_digest(&self) -> Result<String> {
        self.validate()?;
        Ok(staged_digest(&("kasumi.resume-target-materialization.v1", self))?.0)
    }
    pub fn validate(&self) -> Result<()> {
        validate_sha256(&self.authority_manifest_sha256)?;
        self.materialization.request.validate()?;
        self.input.validate(&self.materialization)?;
        require(
            self.materialization.request_sha256 == staged_digest(&self.materialization.request)?.0
                && self.materialization.accepted_at_ms
                    < self.materialization.original_credential_expires_at_ms,
            "target original commitment differs",
        )
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(staged_digest(&("kasumi.target-origin.v1", self))?.0)
    }
    pub fn accepts_phase(&self, intent: &LifecycleIntent, phase: LifecyclePhase) -> Result<()> {
        self.validate()?;
        intent.request.validate()?;
        let old = &self.materialization.request;
        let new = &intent.request;
        require(
            new.phase == phase
                && new.tenant == old.tenant
                && new.source_incarnation == old.source_incarnation
                && new.source_authority_epoch == old.source_authority_epoch
                && new.target_incarnation == old.target_incarnation
                && new.checkpoint == old.checkpoint
                && new.target_nodes == old.target_nodes
                && intent.control_incarnation == self.materialization.control_incarnation
                && intent.request_sha256 == staged_digest(new)?.0
                && intent.accepted_at_ms < intent.original_credential_expires_at_ms,
            "target phase origin differs",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetMaterializationFact {
    pub origin: TargetOrigin,
    pub node_id: u64,
    pub bootstrap_sha256: String,
    pub revision_base: u64,
}
impl TargetMaterializationFact {
    pub fn validate(&self) -> Result<()> {
        self.origin.validate()?;
        validate_sha256(&self.bootstrap_sha256)?;
        require(
            self.origin.input.voters.contains_key(&self.node_id)
                && self.revision_base
                    == self
                        .origin
                        .materialization
                        .request
                        .checkpoint
                        .revision
                        .checked_add(1)
                        .ok_or_else(|| invalid("target revision exhausted"))?,
            "materialized target node or revision differs",
        )
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(staged_digest(&("kasumi.materialized-target.v1", self))?.0)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTargetMaterialization {
    pub fact: TargetMaterializationFact,
    pub signature: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetQuorumInput {
    pub origin_sha256: String,
    #[serde(deserialize_with = "crate::deserialize_u64_map")]
    pub materialized: BTreeMap<u64, SignedTargetMaterialization>,
}
impl TargetQuorumInput {
    pub fn digest(&self) -> Result<String> {
        Ok(staged_digest(&("kasumi.target-quorum-input.v1", self))?.0)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompletionFact {
    pub origin: TargetOrigin,
    #[serde(deserialize_with = "crate::deserialize_u64_map")]
    pub materialized: BTreeMap<u64, SignedTargetMaterialization>,
    pub completion_intent: LifecycleIntent,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub predecessor: Option<TargetCompletionResolutionReference>,
    pub admitted_at_ms: u64,
    pub revision: u64,
    pub term: u64,
    pub leader_node_id: u64,
    pub bootstrap_sha256: String,
}
impl TargetCompletionFact {
    pub fn validate(&self) -> Result<()> {
        self.origin
            .accepts_phase(&self.completion_intent, LifecyclePhase::Complete)?;
        validate_sha256(&self.bootstrap_sha256)?;
        TargetCompletionInput {
            quorum: TargetQuorumInput {
                origin_sha256: self.origin.digest()?,
                materialized: self.materialized.clone(),
            },
            predecessor: self.predecessor.clone(),
        }
        .validate(&self.origin, &self.completion_intent)?;
        require(
            self.term > 0
                && self.origin.input.voters.contains_key(&self.leader_node_id)
                && self.revision > self.origin.materialization.request.checkpoint.revision
                && self.admitted_at_ms >= self.completion_intent.accepted_at_ms
                && self.admitted_at_ms < self.completion_intent.original_credential_expires_at_ms,
            "target completion fact differs",
        )?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(staged_digest(&("kasumi.completed-target.v1", self))?.0)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompletionObservation {
    pub fact: TargetCompletionFact,
    pub observer_node_id: u64,
    pub observed_revision: u64,
    pub observed_term: u64,
}
impl TargetCompletionObservation {
    pub fn validate(&self) -> Result<()> {
        self.fact.validate()?;
        require(
            self.fact
                .origin
                .input
                .voters
                .contains_key(&self.observer_node_id)
                && self.observed_revision >= self.fact.revision
                && self.observed_term >= self.fact.term,
            "completion observation predates its committed fact or names another target",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTargetCompletion {
    pub observation: TargetCompletionObservation,
    pub signature: String,
}
/// An original signed completion or a fresh signed observation of that exact
/// committed fact. The inspection branch never renews the original mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "proof",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CommittedCompletion {
    Original(Box<SignedTargetCompletion>),
    Resolved(Box<SignedTargetInspection>),
}
impl CommittedCompletion {
    pub fn fact(&self) -> &TargetCompletionFact {
        match self {
            Self::Original(signed) => &signed.observation.fact,
            Self::Resolved(signed) => &signed.observation.completion,
        }
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Original(signed) => signed.observation.validate(),
            Self::Resolved(signed) => {
                signed.observation.validate()?;
                require(
                    signed.observation.input.original_phase.request.phase
                        == LifecyclePhase::Complete,
                    "completion resolution must name the exact original Complete phase",
                )
            }
        }
    }
}
fn require(value: bool, message: &str) -> Result<()> {
    if value { Ok(()) } else { Err(invalid(message)) }
}
fn invalid(message: &str) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}
/// Exact adapter-assigned committed application position. Request bodies do
/// not choose these fields; deterministic target apply records them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCommitPosition {
    pub index: u64,
    pub term: u64,
    pub leader_node_id: u64,
    pub command_sha256: String,
}
impl TargetCommitPosition {
    pub fn validate(&self) -> Result<()> {
        require(
            self.index > 0 && self.term > 0 && self.leader_node_id > 0,
            "target commit position invalid",
        )?;
        validate_sha256(&self.command_sha256)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetActivationFact {
    pub position: TargetCommitPosition,
    pub intent: LifecycleIntent,
    pub issuer_receipt_sha256: String,
    pub completion_sha256: String,
    pub admitted_at_ms: u64,
    pub revision: u64,
}
/// State-machine facts are retained across later restore hops. Each destination
/// adds one fresh origin; no prior execution identity or source row is rewritten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetExecutionState {
    pub origin: TargetOrigin,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub completion: Option<TargetCompletionFact>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub activation: Option<TargetActivationFact>,
}
impl TargetExecutionState {
    pub fn validate(&self) -> Result<()> {
        self.origin.validate()?;
        if let Some(completion) = &self.completion {
            completion.validate()?;
            require(
                completion.origin == self.origin,
                "completion changed target origin",
            )?;
        }
        if let Some(activation) = &self.activation {
            let completion = self
                .completion
                .as_ref()
                .ok_or_else(|| invalid("activation predates target completion"))?;
            self.origin
                .accepts_phase(&activation.intent, LifecyclePhase::Activate)?;
            validate_sha256(&activation.issuer_receipt_sha256)?;
            activation.position.validate()?;
            require(
                self.origin
                    .materialization
                    .request
                    .checkpoint
                    .revision
                    .checked_add(1)
                    .and_then(|base| base.checked_add(activation.position.index))
                    == Some(activation.revision)
                    && self
                        .origin
                        .input
                        .voters
                        .contains_key(&activation.position.leader_node_id),
                "target activation position differs from actual revision or membership",
            )?;
            require(
                activation.completion_sha256 == completion.digest()?
                    && activation.revision > completion.revision
                    && activation.admitted_at_ms >= activation.intent.accepted_at_ms
                    && activation.admitted_at_ms
                        < activation.intent.original_credential_expires_at_ms,
                "activation changed completed target or original deadline",
            )?;
        }
        Ok(())
    }
}
pub fn validate_target_history(state: &TenantState) -> Result<()> {
    require(
        state.target_lifecycle.len() <= MAX_TARGET_HISTORY
            && serde_json::to_vec(&state.target_lifecycle)
                .map_err(|_| invalid("target history encoding failed"))?
                .len()
                <= MAX_TARGET_HISTORY_BYTES,
        "target lifecycle history limit exceeded",
    )?;
    for (id, entry) in &state.target_lifecycle {
        entry.validate()?;
        let origin = &entry.origin.materialization.request;
        require(
            *id == origin.target_incarnation.to_string()
                && origin.tenant == state.tenant
                && state.restore_lineage.iter().any(|link| {
                    link.target_incarnation == *id && link.checkpoint == origin.checkpoint
                }),
            "target history differs from immutable restoration lineage",
        )?;
        if let Some(completed) = &entry.completion {
            require(
                completed.revision <= state.revision,
                "target completion exceeds current revision",
            )?;
        }
        if let Some(activated) = &entry.activation {
            require(
                activated.revision <= state.revision,
                "target activation exceeds current revision",
            )?;
        }
    }
    if let Some(current) = state.target_lifecycle.get(&state.incarnation) {
        require(
            state.restored_from.as_ref()
                == Some(&current.origin.materialization.request.checkpoint),
            "current target origin differs",
        )?;
        require(
            current.completion.is_none() == state.pending_restore.is_some(),
            "target completion and restore marker disagree",
        )?;
        require(
            current.activation.is_some() || state.suspended,
            "incomplete lifecycle target must be suspended",
        )?;
    }
    Ok(())
}

/// Fresh inspection binds the exact original committed phase. A missing fact is
/// an unresolved outcome; this reference is never a mutation or stop authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInspectionInput {
    pub quorum: TargetQuorumInput,
    pub original_phase: LifecycleIntent,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub predecessor: Option<TargetCompletionResolutionReference>,
}
impl TargetInspectionInput {
    pub fn validate(&self, origin: &TargetOrigin, inspection: &LifecycleIntent) -> Result<()> {
        origin.accepts_phase(inspection, LifecyclePhase::InspectTarget)?;
        require(
            matches!(
                self.original_phase.request.phase,
                LifecyclePhase::Complete | LifecyclePhase::Activate
            ),
            "inspection must name an original completion or activation",
        )?;
        origin.accepts_phase(&self.original_phase, self.original_phase.request.phase)?;
        require(
            self.quorum.origin_sha256 == origin.digest()?
                && inspection.request.phase_input_sha256 == self.digest()?,
            "inspection differs from exact original target input",
        )?;
        if self.original_phase.request.phase == LifecyclePhase::Complete {
            TargetCompletionInput {
                quorum: self.quorum.clone(),
                predecessor: self.predecessor.clone(),
            }
            .validate(origin, &self.original_phase)?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        Ok(staged_digest(&("kasumi.target-inspection-input.v1", self))?.0)
    }
}
/// Startup always states whether it admits a finite mutation phase or only a
/// fresh metadata observation. There is no optional authority fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TargetReplicaInput {
    Quorum(TargetQuorumInput),
    Completion(TargetCompletionInput),
    CompletionResolution(Box<crate::TargetCompletionResolutionInput>),
    ResolutionBudget {
        quorum: TargetQuorumInput,
        input: crate::TargetResolutionBudgetInput,
    },
    Inspection(Box<TargetInspectionInput>),
}
impl TargetReplicaInput {
    pub fn quorum(&self) -> &TargetQuorumInput {
        match self {
            Self::Quorum(value) => value,
            Self::Completion(value) => &value.quorum,
            Self::CompletionResolution(value) => &value.attempt.input.quorum,
            Self::ResolutionBudget { quorum, .. } => quorum,
            Self::Inspection(value) => &value.quorum,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInspectionObservation {
    pub input: TargetInspectionInput,
    pub inspection_intent: LifecycleIntent,
    pub completion: TargetCompletionFact,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub activation: Option<TargetActivationFact>,
    pub observer_node_id: u64,
    pub observed_revision: u64,
    pub observed_term: u64,
}
impl TargetInspectionObservation {
    pub fn validate(&self) -> Result<()> {
        self.completion.validate()?;
        let origin = &self.completion.origin;
        self.input.validate(origin, &self.inspection_intent)?;
        TargetExecutionState {
            origin: origin.clone(),
            completion: Some(self.completion.clone()),
            activation: self.activation.clone(),
        }
        .validate()?;
        let original = match self.input.original_phase.request.phase {
            LifecyclePhase::Complete => &self.completion.completion_intent,
            LifecyclePhase::Activate => {
                &self
                    .activation
                    .as_ref()
                    .ok_or_else(|| invalid("original target activation not committed"))?
                    .intent
            }
            _ => return Err(invalid("unsupported original inspection phase")),
        };
        require(
            *original == self.input.original_phase
                && self.input.quorum.materialized == self.completion.materialized
                && self.input.predecessor == self.completion.predecessor
                && origin.input.voters.contains_key(&self.observer_node_id)
                && self.observed_term >= self.completion.term
                && self.observed_revision >= self.completion.revision
                && self
                    .activation
                    .as_ref()
                    .is_none_or(|fact| self.observed_revision >= fact.revision),
            "inspection differs from the actual committed original phase",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTargetInspection {
    pub observation: TargetInspectionObservation,
    pub signature: String,
}

/// Configured permanent per-node metadata budget, separate from application quotas.
/// Record counts never expire or impose a fixed installation lifetime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetJournalLimits {
    pub max_metadata_bytes: u64,
}
impl TargetJournalLimits {
    pub fn validate(&self) -> Result<()> {
        require(
            self.max_metadata_bytes >= 262_144,
            "target journal byte budget cannot hold its metadata record",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetActivationObservation {
    pub completion: TargetCompletionFact,
    pub activation: TargetActivationFact,
    pub observer_node_id: u64,
    pub observed_revision: u64,
    pub observed_term: u64,
}
impl TargetActivationObservation {
    pub fn validate(&self) -> Result<()> {
        TargetExecutionState {
            origin: self.completion.origin.clone(),
            completion: Some(self.completion.clone()),
            activation: Some(self.activation.clone()),
        }
        .validate()?;
        require(
            self.completion
                .origin
                .input
                .voters
                .contains_key(&self.observer_node_id)
                && self.observed_term > 0
                && self.observed_revision >= self.activation.revision,
            "activation observer differs",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTargetActivation {
    pub observation: TargetActivationObservation,
    pub signature: String,
}

#[cfg(test)]
mod journal_limit_tests {
    use super::*;
    #[test]
    fn target_metadata_capacity_has_no_lifetime_count_or_aggregate_format_ceiling() {
        let limits: TargetJournalLimits = serde_json::from_value(serde_json::json!({
            "max_metadata_bytes": 1u64 << 40,
        }))
        .unwrap();
        limits.validate().unwrap();
        for field in ["max_intents", "max_generation_records"] {
            let mut obsolete = serde_json::to_value(&limits).unwrap();
            obsolete[field] = 100_000.into();
            assert!(serde_json::from_value::<TargetJournalLimits>(obsolete).is_err());
        }
        assert!(
            TargetJournalLimits {
                max_metadata_bytes: 262_143
            }
            .validate()
            .is_err()
        );
    }
}
