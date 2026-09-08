//! Canonical transport-independent issuer commands and signed historical facts.
//! Validation preserves exact identities; these DTOs never grant live authority.
use crate::*;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub(crate) fn protocol_digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(crate::staged_digest(value)?.0)
}
use protocol_digest as digest;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "intent_id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LifecycleAuthorityIdentity {
    Intent(Uuid),
    EpochStop,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleAuthorityReference {
    pub control_incarnation: Uuid,
    pub control_policy_epoch: u64,
    pub identity: LifecycleAuthorityIdentity,
}
impl LifecycleAuthorityReference {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.control_incarnation.is_nil(),
            "nil issuer control reference"
        );
        if let LifecycleAuthorityIdentity::Intent(id) = self.identity {
            ensure!(!id.is_nil(), "nil control intent reference");
        }
        Ok(())
    }
    pub fn key(&self) -> Result<String> {
        self.validate()?;
        Ok(match self.identity {
            LifecycleAuthorityIdentity::Intent(id) => format!(
                "lc/i/{}/{}/{id}",
                self.control_incarnation, self.control_policy_epoch
            ),
            LifecycleAuthorityIdentity::EpochStop => format!(
                "lc/e/{}/{}",
                self.control_incarnation, self.control_policy_epoch
            ),
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTarget {
    pub incarnation: Uuid,
    pub nodes: BTreeSet<NodeIdentity>,
    pub checkpoint: FullBackupCheckpoint,
}
impl RecoveryTarget {
    pub fn validate(&self, tenant: &str, source: Uuid) -> Result<()> {
        self.checkpoint.validate()?;
        ensure!(
            !self.incarnation.is_nil() && self.incarnation != source,
            "invalid replacement incarnation"
        );
        ensure!(
            self.checkpoint.tenant == tenant
                && self.checkpoint.source_incarnation == source.to_string(),
            "replacement backup source differs"
        );
        validate_nodes(&self.nodes)
    }
}
pub fn validate_nodes(nodes: &BTreeSet<NodeIdentity>) -> Result<()> {
    ensure!(
        (3..=9).contains(&nodes.len()),
        "serving incarnation requires 3..9 nodes"
    );
    let mut ids = BTreeSet::new();
    let mut credentials = BTreeSet::new();
    for node in nodes {
        node.validate()?;
        ensure!(
            ids.insert(node.node_id)
                && credentials.insert((&node.principal, &node.certificate_sha256)),
            "duplicate node or credential"
        );
    }
    Ok(())
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCommand {
    pub tenant: String,
    pub command_id: Uuid,
    pub expected_policy_epoch: u64,
    pub not_after_ms: u64,
    pub action: AuthorityAction,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityAction {
    Enroll {
        incarnation: Uuid,
        nodes: BTreeSet<NodeIdentity>,
    },
    Fence {
        incarnation: Uuid,
        authority_epoch: u64,
    },
    PrepareTarget {
        source_incarnation: Uuid,
        source_epoch: u64,
        target: RecoveryTarget,
    },
    Activate {
        fence_id: Uuid,
        fence_digest: String,
        target: RecoveryTarget,
    },
    /// Activation under an installed committed Control phase. The immutable
    /// reference is part of the permanent command identity.
    ActivateCommitted {
        fence_id: Uuid,
        fence_digest: String,
        target: RecoveryTarget,
        control: CommittedActivation,
    },
    /// Exact original activation identity is permanently stopped if unaccepted.
    /// A previously committed activation remains the original successful result.
    StopActivation {
        original: Box<AuthorityCommand>,
    },
    /// Permanent incarnation closure, including preparations not received yet.
    StopTarget {
        source_incarnation: Uuid,
        source_epoch: u64,
        target: RecoveryTarget,
    },
    ReplaceAdministrators {
        administrators: BTreeSet<String>,
    },
}
impl AuthorityCommand {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.tenant)?;
        ensure!(
            !self.command_id.is_nil() && self.expected_policy_epoch > 0 && self.not_after_ms > 0,
            "invalid authority command identity"
        );
        match &self.action {
            AuthorityAction::Enroll { incarnation, nodes } => {
                ensure!(!incarnation.is_nil(), "nil incarnation");
                validate_nodes(nodes)?;
            }
            AuthorityAction::Fence {
                incarnation,
                authority_epoch,
            } => {
                ensure!(
                    !incarnation.is_nil() && *authority_epoch > 0,
                    "invalid fence identity"
                );
            }
            AuthorityAction::PrepareTarget {
                source_incarnation,
                source_epoch,
                target,
            }
            | AuthorityAction::StopTarget {
                source_incarnation,
                source_epoch,
                target,
            } => {
                ensure!(
                    !source_incarnation.is_nil() && *source_epoch > 0 && *source_epoch < u64::MAX,
                    "invalid preparation source epoch"
                );
                target.validate(&self.tenant, *source_incarnation)?;
            }
            AuthorityAction::Activate {
                fence_id,
                fence_digest,
                target,
            }
            | AuthorityAction::ActivateCommitted {
                fence_id,
                fence_digest,
                target,
                ..
            } => {
                ensure!(!fence_id.is_nil(), "nil fence identity");
                validate_sha256(fence_digest)?;
                let source = Uuid::parse_str(&target.checkpoint.source_incarnation)?;
                target.validate(&self.tenant, source)?;
            }
            AuthorityAction::StopActivation { original } => {
                ensure!(
                    matches!(
                        original.action,
                        AuthorityAction::Activate { .. }
                            | AuthorityAction::ActivateCommitted { .. }
                    ) && original.tenant == self.tenant
                        && original.command_id != self.command_id,
                    "invalid original activation stop"
                );
                original.validate()?;
            }
            AuthorityAction::ReplaceAdministrators { administrators } => {
                ensure!(
                    !administrators.is_empty() && administrators.len() <= 64,
                    "invalid authority administrators"
                );
                for principal in administrators {
                    validate_name(principal)?;
                }
            }
        }
        if let AuthorityAction::ActivateCommitted { control, .. } = &self.action {
            control.validate()?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(&("kasumi.authority-command.v1", self))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityReceipt {
    pub authority_id: Uuid,
    pub manifest_digest: String,
    pub partition: u16,
    pub command: AuthorityCommand,
    pub command_digest: String,
    pub principal: String,
    pub term: u64,
    pub revision: u64,
    /// Actual trusted ordered admission, never a caller supplied timestamp.
    pub admitted_at_ms: u64,
    pub outcome: AuthorityOutcome,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityOutcome {
    Enrolled {
        incarnation: Uuid,
        authority_epoch: u64,
    },
    Fenced {
        incarnation: Uuid,
        authority_epoch: u64,
    },
    TargetPrepared {
        target: RecoveryTarget,
        authority_epoch: u64,
    },
    Activated {
        target: RecoveryTarget,
        authority_epoch: u64,
    },
    TargetStopped {
        source_incarnation: Uuid,
        source_epoch: u64,
        target: RecoveryTarget,
    },
    TargetAlreadyActivated {
        original: Box<AuthorityReceipt>,
    },
    ActivationStopped {
        original_digest: String,
    },
    AdministratorsReplaced {
        policy_epoch: u64,
    },
    Rejected {
        code: crate::ErrorCode,
        message: String,
    },
    ActivationResolved {
        original: Box<AuthorityReceipt>,
    },
}
impl AuthorityReceipt {
    pub fn digest(&self) -> Result<String> {
        digest(&("kasumi.authority-receipt.v1", self))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorityReceipt {
    pub receipt: AuthorityReceipt,
    pub signature: crate::GenerationSignature,
}

/// An accepted issuer intent reference is durable identity, not a live grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedActivation {
    pub completion: Box<crate::SignedTargetCompletion>,
    pub reference: crate::LifecycleAuthorityReference,
    pub intent_sha256: String,
}
impl CommittedActivation {
    pub fn validate(&self) -> Result<()> {
        self.completion.observation.validate()?;
        validate_sha256(
            &self
                .completion
                .observation
                .fact
                .origin
                .authority_manifest_sha256,
        )?;
        self.reference.validate()?;
        ensure!(
            matches!(
                self.reference.identity,
                crate::LifecycleAuthorityIdentity::Intent(_)
            ),
            "activation requires an exact intent identity"
        );
        validate_sha256(&self.intent_sha256)?;
        Ok(())
    }
}
/// Stable exact phase input. The accepted Control intent names this digest;
/// issuer invocation credentials and fresh observations cannot change it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateTargetInput {
    pub completion_sha256: String,
    pub fence_id: Uuid,
    pub fence_digest: String,
    pub target: RecoveryTarget,
}
impl ActivateTargetInput {
    pub fn digest(&self) -> Result<String> {
        validate_sha256(&self.completion_sha256)?;
        ensure!(!self.fence_id.is_nil(), "nil activation source fence");
        validate_sha256(&self.fence_digest)?;
        self.target.validate(
            &self.target.checkpoint.tenant,
            Uuid::parse_str(&self.target.checkpoint.source_incarnation)?,
        )?;
        digest(&("kasumi.activate-target-input.v1", self))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetStopReference {
    pub tenant: String,
    pub command_id: Uuid,
    pub receipt_digest: String,
}
impl TargetStopReference {
    pub fn validate(&self) -> Result<()> {
        crate::validate_name(&self.tenant)?;
        crate::validate_sha256(&self.receipt_digest)?;
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
    pub signature: crate::GenerationSignature,
}

impl LifecycleAuthorityReference {
    pub fn epoch_stop(&self) -> Self {
        Self {
            identity: LifecycleAuthorityIdentity::EpochStop,
            ..self.clone()
        }
    }
    pub fn epoch_key(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "lc/a/{}/{}",
            self.control_incarnation, self.control_policy_epoch
        ))
    }
}
