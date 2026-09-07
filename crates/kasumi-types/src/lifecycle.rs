//! Closed lifecycle control commitments. Serialized records are facts, never
//! live execution grants; cryptographic verification is a separate boundary.
use crate::{
    Error, ErrorCode, FullBackupCheckpoint, Policy, Result, validate_name, validate_sha256,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const MAX_CONTROL_PARTITIONS: usize = 1024;
pub const MAX_LIFECYCLE_STATE_BYTES: usize = 8 << 20;
pub const MAX_LIFECYCLE_INTENTS: usize = 10_000;
pub const MAX_CONTROL_CHANGES: usize = 1024;

fn invalid(message: &str) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSigningRoot {
    pub control_incarnation: Uuid,
    pub public_key: String,
}
impl ControlSigningRoot {
    pub fn validate(&self) -> Result<()> {
        require(
            !self.control_incarnation.is_nil(),
            "nil control incarnation",
        )?;
        validate_sha256(&self.public_key)
    }
}

/// Exact exhaustive issuer configuration. Keys are canonical authority UUID and
/// partition, so aliases cannot disguise omitted or duplicate partitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlAuthorityPartition {
    pub authority_id: Uuid,
    pub manifest_sha256: String,
    pub partition: u16,
    pub signing_public_key: String,
    pub maximum_lifetime_ms: u64,
    pub drain_ms: u64,
}
impl ControlAuthorityPartition {
    pub fn key(&self) -> String {
        format!("{}/{}", self.authority_id, self.partition)
    }
    pub fn validate(&self) -> Result<()> {
        require(
            !self.authority_id.is_nil() && self.partition < 1024,
            "invalid control authority partition",
        )?;
        validate_sha256(&self.manifest_sha256)?;
        validate_sha256(&self.signing_public_key)?;
        require(
            (100..=60_000).contains(&self.maximum_lifetime_ms)
                && self.drain_ms >= self.maximum_lifetime_ms
                && self.drain_ms <= 61_213,
            "invalid immutable authority drain bound",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleInstallation {
    pub root: ControlSigningRoot,
    pub generation: u64,
    pub partitions: BTreeMap<String, ControlAuthorityPartition>,
    pub max_intents: usize,
    pub max_changes: usize,
    pub max_state_bytes: usize,
}
impl LifecycleInstallation {
    pub fn validate(&self) -> Result<()> {
        self.root.validate()?;
        require(
            self.generation > 0
                && !self.partitions.is_empty()
                && self.partitions.len() <= MAX_CONTROL_PARTITIONS,
            "invalid lifecycle installation generation or partition count",
        )?;
        for (key, partition) in &self.partitions {
            partition.validate()?;
            require(
                *key == partition.key(),
                "noncanonical control partition key",
            )?;
        }
        require(
            (1..=MAX_LIFECYCLE_INTENTS).contains(&self.max_intents)
                && (1..=MAX_CONTROL_CHANGES).contains(&self.max_changes)
                && (8192..=MAX_LIFECYCLE_STATE_BYTES).contains(&self.max_state_bytes),
            "lifecycle quota exceeds hard bounds",
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecyclePhase {
    Materialize,
    Initialize,
    Complete,
    Activate,
    StopLocal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleNode {
    pub node_id: u64,
    pub principal: String,
    pub certificate_sha256: String,
}
impl LifecycleNode {
    pub fn validate(&self) -> Result<()> {
        require(self.node_id > 0, "zero lifecycle node")?;
        validate_name(&self.principal)?;
        validate_sha256(&self.certificate_sha256)
    }
}

/// Caller request identity excludes the original credential cap: the engine
/// derives and retains that once from the first admitted verified invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitLifecycleIntent {
    pub command_id: Uuid,
    pub expected_policy_epoch: u64,
    pub installation_sha256: String,
    pub authority_partition: String,
    pub tenant: String,
    pub source_incarnation: Uuid,
    pub source_authority_epoch: u64,
    pub target_incarnation: Uuid,
    pub checkpoint: FullBackupCheckpoint,
    pub target_nodes: BTreeMap<u64, LifecycleNode>,
    pub phase: LifecyclePhase,
    pub phase_input_sha256: String,
}
impl CommitLifecycleIntent {
    pub fn validate(&self) -> Result<()> {
        require(
            !self.command_id.is_nil()
                && !self.source_incarnation.is_nil()
                && !self.target_incarnation.is_nil()
                && self.target_incarnation != self.source_incarnation
                && self.source_authority_epoch > 0
                && self.source_authority_epoch < u64::MAX,
            "invalid lifecycle identity",
        )?;
        validate_name(&self.tenant)?;
        require(
            !self.tenant.starts_with("kasumi.") && !self.tenant.starts_with("__kasumi_"),
            "lifecycle target cannot be a control namespace",
        )?;
        validate_sha256(&self.installation_sha256)?;
        validate_sha256(&self.phase_input_sha256)?;
        self.checkpoint.validate()?;
        require(
            self.checkpoint.tenant == self.tenant
                && self.checkpoint.source_incarnation == self.source_incarnation.to_string(),
            "lifecycle checkpoint source differs",
        )?;
        require(
            (3..=9).contains(&self.target_nodes.len()),
            "lifecycle target requires 3..9 nodes",
        )?;
        let mut credentials = BTreeSet::new();
        for (id, node) in &self.target_nodes {
            node.validate()?;
            require(
                *id == node.node_id
                    && credentials.insert((&node.principal, &node.certificate_sha256)),
                "duplicate lifecycle node credential",
            )?;
        }
        require(
            self.authority_partition.len() <= 64,
            "control partition key too long",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleIntent {
    pub request: CommitLifecycleIntent,
    pub request_sha256: String,
    pub control_incarnation: Uuid,
    pub installation_generation: u64,
    pub original_principal: String,
    pub original_credential_expires_at_ms: u64,
    pub accepted_at_ms: u64,
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginControlPolicyChange {
    pub command_id: Uuid,
    pub expected_policy_epoch: u64,
    pub installation_sha256: String,
    pub candidate: ControlPolicyCandidate,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPolicyCandidate {
    pub policy: Policy,
    /// Retirement closes future lifecycle intent signing permanently. It never
    /// reopens tenant storage or retires a municipality on the caller's behalf.
    pub retire_control: bool,
}
impl BeginControlPolicyChange {
    pub fn validate(&self) -> Result<()> {
        require(!self.command_id.is_nil(), "nil control change identity")?;
        validate_sha256(&self.installation_sha256)?;
        require(
            self.candidate.policy.grants.len() <= 4096
                && self
                    .candidate
                    .policy
                    .grants
                    .iter()
                    .any(|g| g.collection.is_none() && g.actions.contains(&crate::Action::Admin)),
            "control policy needs a bounded administrator set",
        )?;
        for grant in &self.candidate.policy.grants {
            validate_name(&grant.principal)?;
            if let Some(collection) = &grant.collection {
                validate_name(collection)?;
            }
            require(!grant.actions.is_empty(), "empty control policy grant")?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPolicyChange {
    pub request: BeginControlPolicyChange,
    pub request_sha256: String,
    pub control_incarnation: Uuid,
    pub installation: LifecycleInstallation,
    pub original_principal: String,
    pub accepted_at_ms: u64,
    pub accepted_revision: u64,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub completed_revision: Option<u64>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub completion_stops: Option<BTreeMap<String, SignedControlEpochStop>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlEpochStop {
    pub control_incarnation: Uuid,
    pub control_policy_epoch: u64,
    pub installation_sha256: String,
    pub installation_generation: u64,
    pub change_id: Uuid,
    pub change_sha256: String,
    pub authority_partition: ControlAuthorityPartition,
    pub partition_set_sha256: String,
}
impl ControlEpochStop {
    pub fn validate(&self) -> Result<()> {
        require(
            !self.control_incarnation.is_nil()
                && !self.change_id.is_nil()
                && self.installation_generation > 0,
            "invalid control epoch stop identity",
        )?;
        validate_sha256(&self.installation_sha256)?;
        validate_sha256(&self.change_sha256)?;
        validate_sha256(&self.partition_set_sha256)?;
        self.authority_partition.validate()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlEpochStopObservation {
    pub stop: ControlEpochStop,
    pub accepted_revision: u64,
    pub accepted_term: u64,
    pub observed_revision: u64,
    pub observed_term: u64,
    pub drain_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedControlEpochStop {
    pub observation: ControlEpochStopObservation,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteControlPolicyChange {
    pub command_id: Uuid,
    pub change_sha256: String,
    pub stops: BTreeMap<String, SignedControlEpochStop>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LifecycleControlCommand {
    Install {
        command_id: Uuid,
        installation: LifecycleInstallation,
    },
    CommitIntent(Box<CommitLifecycleIntent>),
    BeginPolicyChange(BeginControlPolicyChange),
    CompletePolicyChange(CompleteControlPolicyChange),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleControlState {
    pub installation: LifecycleInstallation,
    pub installation_command_id: Uuid,
    pub installation_revision: u64,
    pub installation_policy_epoch: u64,
    pub installation_policy: Policy,
    pub retired: bool,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub pending_change: Option<Uuid>,
    pub intents: BTreeMap<Uuid, LifecycleIntent>,
    pub changes: BTreeMap<Uuid, ControlPolicyChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedControlIntent {
    pub intent: LifecycleIntent,
    pub installation: LifecycleInstallation,
    pub observed_policy_epoch: u64,
    pub observed_revision: u64,
    pub observed_term: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedControlIntent {
    pub observation: ControlIntentCommitment,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedControlChange {
    pub change: ControlPolicyChange,
    pub observed_policy_epoch: u64,
    pub observed_revision: u64,
    pub observed_term: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedControlChange {
    pub observation: ControlChangeCommitment,
    pub signature: String,
}

/// Compact signed projection of an actual control observation. The complete
/// installation stays in the control group; each issuer receives its own exact
/// partition and a commitment to the exhaustive installed set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlIntentCommitment {
    pub intent: LifecycleIntent,
    pub root: ControlSigningRoot,
    pub authority_partition: ControlAuthorityPartition,
    pub partition_set_sha256: String,
    pub observed_policy_epoch: u64,
    pub observed_revision: u64,
    pub observed_term: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlChangeCommitment {
    pub root: ControlSigningRoot,
    pub stop: ControlEpochStop,
    pub accepted_revision: u64,
    pub observed_policy_epoch: u64,
    pub observed_revision: u64,
    pub observed_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadLifecycleStatus {
    pub command_id: Uuid,
    pub expected_incarnation: Uuid,
}
/// Recovery metadata only. This cannot construct an execution or issuer proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LifecycleCommandStatus {
    Installation {
        command_id: Uuid,
        installation: LifecycleInstallation,
        revision: u64,
    },
    Intent(Box<LifecycleIntent>),
    PolicyChange(Box<ControlPolicyChange>),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStatus {
    pub request: ReadLifecycleStatus,
    pub policy_epoch: u64,
    pub observed_revision: u64,
    pub observed_term: u64,
    pub retired: bool,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub command: Option<LifecycleCommandStatus>,
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    #[test]
    fn lifecycle_status_requires_explicit_nullable_outcome() {
        let status = LifecycleStatus {
            request: ReadLifecycleStatus {
                command_id: Uuid::new_v4(),
                expected_incarnation: Uuid::new_v4(),
            },
            policy_epoch: 1,
            observed_revision: 2,
            observed_term: 1,
            retired: false,
            command: None,
        };
        let mut value = serde_json::to_value(&status).unwrap();
        assert!(serde_json::from_value::<LifecycleStatus>(value.clone()).is_ok());
        value.as_object_mut().unwrap().remove("command");
        assert!(serde_json::from_value::<LifecycleStatus>(value).is_err());
    }
}
