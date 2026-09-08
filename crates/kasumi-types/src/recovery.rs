//! Durable Control recovery identities and bounded, independently retained phase
//! records. Serialized observations are history; they never create a live grant.
use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const MAX_RECOVERY_RECORD_BYTES: usize = 1 << 20;
pub const MAX_RECOVERY_START_BYTES: usize = 64 << 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoverySourceMode {
    Planned {
        retirement: Box<RetireSourceRequest>,
    },
    /// Requires the complete installed issuer drain. This mode cannot produce
    /// an independently verified planned-retirement observation.
    SourceUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryStart {
    pub operation_id: Uuid,
    pub tenant: String,
    pub source_incarnation: Uuid,
    pub source_authority_epoch: u64,
    pub target_incarnation: Uuid,
    pub checkpoint: FullBackupCheckpoint,
    pub source_purpose_sha256: String,
    pub source_mode: RecoverySourceMode,
    pub installation_sha256: String,
    pub expected_policy_epoch: u64,
    pub authority_partition: String,
    /// Exact installed endpoints, trust, and independently bound credential
    /// sources are selected by this digest, never supplied as request URLs.
    pub dispatch_configuration_sha256: String,
    #[serde(deserialize_with = "crate::deserialize_u64_map")]
    pub target_nodes: BTreeMap<u64, LifecycleNode>,
    pub materialization: TargetMaterializationInput,
    pub phase_timeout_ms: u64,
}
impl RecoveryStart {
    pub fn validate(&self) -> Result<()> {
        require_recovery(!self.operation_id.is_nil(), "nil recovery operation")?;
        validate_sha256(&self.source_purpose_sha256)?;
        validate_sha256(&self.dispatch_configuration_sha256)?;
        require_recovery(
            (1..=600_000).contains(&self.phase_timeout_ms),
            "recovery phase timeout exceeds work bounds",
        )?;
        let intent = CommitLifecycleIntent {
            command_id: self.operation_id,
            expected_policy_epoch: self.expected_policy_epoch,
            installation_sha256: self.installation_sha256.clone(),
            authority_partition: self.authority_partition.clone(),
            tenant: self.tenant.clone(),
            source_incarnation: self.source_incarnation,
            source_authority_epoch: self.source_authority_epoch,
            target_incarnation: self.target_incarnation,
            checkpoint: self.checkpoint.clone(),
            target_nodes: self.target_nodes.clone(),
            phase: LifecyclePhase::Materialize,
            phase_input_sha256: self.materialization.digest()?,
            resume_origin: None,
        };
        intent.validate()?;
        require_recovery(
            self.materialization.backup_id == self.checkpoint.backup_id
                && self.materialization.source_purpose_sha256 == self.source_purpose_sha256
                && self.materialization.target_incarnation == self.target_incarnation
                && self.target_nodes.len() == 3
                && self
                    .materialization
                    .voters
                    .keys()
                    .eq(self.target_nodes.keys()),
            "recovery placement differs from exact three-voter materialization",
        )?;
        let mut domains = std::collections::BTreeSet::new();
        validate_name(&self.materialization.destination_alias)?;
        for peer in self.materialization.voters.values() {
            validate_name(&peer.failure_domain)?;
            require_recovery(
                !peer.endpoint.is_empty()
                    && peer.endpoint.len() <= 2048
                    && domains.insert(&peer.failure_domain),
                "recovery placement or failure domains differ",
            )?;
        }
        if let RecoverySourceMode::Planned { retirement } = &self.source_mode {
            retirement.validate()?;
            require_recovery(
                retirement.expected_source_incarnation == self.source_incarnation.to_string()
                    && retirement.target_incarnation == self.target_incarnation.to_string()
                    && retirement.checkpoint == self.checkpoint
                    && retirement.destination == self.materialization.destination_alias,
                "planned recovery retirement differs from the frozen source and target",
            )?;
        }
        bounded_recovery(self, MAX_RECOVERY_START_BYTES)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(staged_digest(&("kasumi.control-recovery-start.v1", self))?.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPhase {
    Prepare,
    Materialize,
    Initialize,
    Complete,
    RetireSource,
    FenceSource,
    Activate,
    Confirm,
    Publish,
    Finished,
    StopActivation,
    StopTarget,
    Cleanup,
    Stopped,
}
impl RecoveryPhase {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Finished | Self::Stopped)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryVoterProgress {
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub materialization: Option<Uuid>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub started: Option<Uuid>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub confirmation: Option<Uuid>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub cleanup: Option<Uuid>,
}

/// The bounded head holds only point references. Complete signed inputs and
/// outcomes remain in separate immutable phase records across later retries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRecord {
    pub request: RecoveryStart,
    pub request_sha256: String,
    pub original_principal: String,
    pub created_revision: u64,
    pub updated_revision: u64,
    pub phase: RecoveryPhase,
    pub next_phase_sequence: u64,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub pending_phase: Option<Uuid>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub last_phase: Option<Uuid>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub issuer_preparation: Option<Uuid>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub initialization: Option<Uuid>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub completion: Option<Uuid>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub retirement: Option<Uuid>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub source_fence: Option<Uuid>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub activation: Option<Uuid>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub route_publication: Option<Uuid>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub stop_request: Option<Uuid>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub target_stop: Option<Uuid>,
    #[serde(deserialize_with = "crate::deserialize_u64_map")]
    pub voters: BTreeMap<u64, RecoveryVoterProgress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRouteChange {
    pub expected_topology_version: u64,
    pub expected_source_incarnation: Uuid,
    pub target_incarnation: Uuid,
    pub target_voters: std::collections::BTreeSet<u64>,
}

/// One exact remote command or local replicated transition, frozen before any
/// dispatch. Credential bytes are absent; the installed credential source is
/// resolved independently for the selected resource at invocation time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "input",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RecoveryDispatch {
    Authority(Box<AuthorityCommand>),
    ControlIntent(Box<CommitLifecycleIntent>),
    Target {
        node_id: u64,
        request: Box<TargetRuntimeRequest>,
    },
    RetireSource(RetireSourceRequest),
    ObserveSourceRetirement(RetirementRef),
    PublishRoute(RecoveryRouteChange),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "outcome",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RecoveryDispatchOutcome {
    Authority(Box<SignedAuthorityReceipt>),
    ControlIntent(Box<LifecycleIntent>),
    Target(Box<TargetRuntimeResponse>),
    SourceRetired(Box<RetirementReceipt>),
    RoutePublished { revision: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPhaseRecord {
    pub operation_id: Uuid,
    pub phase_id: Uuid,
    pub sequence: u64,
    pub phase: RecoveryPhase,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub previous_phase: Option<Uuid>,
    pub input: RecoveryDispatch,
    pub input_sha256: String,
    pub principal: String,
    pub admitted_at_ms: u64,
    pub original_credential_expires_at_ms: u64,
    pub prepared_revision: u64,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub outcome: Option<RecoveryDispatchOutcome>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub resolved_revision: Option<u64>,
}
impl RecoveryPhaseRecord {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.principal)?;
        require_recovery(
            !self.operation_id.is_nil()
                && !self.phase_id.is_nil()
                && self.sequence > 0
                && self.prepared_revision > 0
                && self.admitted_at_ms < self.original_credential_expires_at_ms
                && self
                    .previous_phase
                    .is_none_or(|id| !id.is_nil() && id != self.phase_id)
                && self.input_sha256 == staged_digest(&self.input)?.0
                && self.outcome.is_some() == self.resolved_revision.is_some()
                && self
                    .resolved_revision
                    .is_none_or(|revision| revision >= self.prepared_revision),
            "recovery phase identity, deadline, or durable outcome differs",
        )?;
        bounded_recovery(self, MAX_RECOVERY_RECORD_BYTES)
    }
}
impl RecoveryRecord {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        validate_name(&self.original_principal)?;
        require_recovery(
            self.request_sha256 == self.request.digest()?
                && self.created_revision > 0
                && self.updated_revision >= self.created_revision
                && self.next_phase_sequence > 0
                && self.voters.keys().eq(self.request.target_nodes.keys())
                && (!self.phase.terminal() || self.pending_phase.is_none()),
            "recovery head identity, placement, or durable position differs",
        )?;
        if self.activation.is_some() {
            require_recovery(
                matches!(
                    self.phase,
                    RecoveryPhase::Activate
                        | RecoveryPhase::Confirm
                        | RecoveryPhase::Publish
                        | RecoveryPhase::Finished
                ),
                "committed recovery activation proceeds forward",
            )?;
        }
        if self.phase == RecoveryPhase::Finished {
            require_recovery(
                self.activation.is_some()
                    && self.route_publication.is_some()
                    && self
                        .voters
                        .values()
                        .all(|voter| voter.confirmation.is_some()),
                "finished recovery lacks activation, confirmations, or route publication",
            )?;
        }
        if self.phase == RecoveryPhase::Stopped {
            require_recovery(
                self.activation.is_none()
                    && self.target_stop.is_some()
                    && self.voters.values().all(|voter| voter.cleanup.is_some()),
                "stopped recovery lacks permanent target stop or physical cleanup",
            )?;
        }
        bounded_recovery(self, MAX_RECOVERY_RECORD_BYTES)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryControlState {
    pub operations: imbl::OrdMap<String, RecoveryRecord>,
    pub phases: imbl::OrdMap<String, RecoveryPhaseRecord>,
    /// Permanent target incarnation identity, retained after physical cleanup.
    pub targets: imbl::OrdMap<String, Uuid>,
}
impl RecoveryControlState {
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty() && self.phases.is_empty() && self.targets.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RecoveryControlCommand {
    Start(Box<RecoveryStart>),
    Stop {
        operation_id: Uuid,
        command_id: Uuid,
    },
}

fn require_recovery(condition: bool, message: &str) -> Result<()> {
    if !condition {
        return Err(Error::new(ErrorCode::InvalidArgument, message));
    }
    Ok(())
}
fn bounded_recovery<T: Serialize>(value: &T, limit: usize) -> Result<()> {
    require_recovery(
        staged_digest(value)?.1 <= limit,
        "recovery record exceeds its work limit",
    )
}
