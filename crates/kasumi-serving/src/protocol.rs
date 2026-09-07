use anyhow::{Result, ensure};
use kasumi_types::{FullBackupCheckpoint, validate_name, validate_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

/// Immutable operator installation. Partition routing and lease lifetime cannot
/// change under an old grant. A different installation needs a distinct drain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityManifest {
    pub authority_id: Uuid,
    /// Fixed bounded Control roots. Empty explicitly disables lifecycle grants.
    pub lifecycle_controls: BTreeMap<Uuid, String>,
    pub partitions: BTreeMap<u16, AuthorityPartition>,
    pub max_lease_ms: u64,
    /// Installed bound on each participating suspend-aware clock's rate error.
    /// Zero describes exact logical-clock fixtures, not a hardware guarantee.
    pub clock_rate_error_ppm: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityPartition {
    pub group: String,
    pub public_key: String,
}
impl AuthorityManifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.authority_id.is_nil(), "nil authority identity");
        ensure!(
            self.lifecycle_controls.len() <= 1024,
            "too many installed lifecycle control roots"
        );
        for (incarnation, key) in &self.lifecycle_controls {
            ensure!(!incarnation.is_nil(), "nil installed control identity");
            validate_sha256(key)?;
        }
        ensure!(
            self.clock_rate_error_ppm <= 10_000,
            "clock rate error exceeds supported 1% bound"
        );
        ensure!(
            (100..=60_000).contains(&self.max_lease_ms),
            "lease lifetime outside hard bounds"
        );
        ensure!(
            self.partitions.len().is_power_of_two() && self.partitions.len() <= 1024,
            "invalid partition count"
        );
        let mut groups = BTreeSet::new();
        for (index, partition) in &self.partitions {
            ensure!(
                usize::from(*index) < self.partitions.len(),
                "noncontiguous partitions"
            );
            validate_name(&partition.group)?;
            ensure!(groups.insert(&partition.group), "duplicate partition group");
            validate_sha256(&partition.public_key)?;
        }
        Ok(())
    }
    pub fn partition(&self, tenant: &str) -> Result<u16> {
        self.validate()?;
        validate_name(tenant)?;
        let hash = Sha256::digest(tenant.as_bytes());
        Ok(u16::from_be_bytes([hash[0], hash[1]]) & (self.partitions.len() as u16 - 1))
    }
    pub fn digest(&self) -> Result<String> {
        digest(&("kasumi.authority-installation.v1", self))
    }
    /// Slowest allowed client versus fastest allowed issuer, rounded upward.
    /// This rate bound is immutable alongside every still-outstanding grant.
    pub fn drain_ms(&self) -> Result<u64> {
        self.validate()?;
        let numerator = self.max_lease_ms * (1_000_000 + self.clock_rate_error_ppm);
        Ok(numerator.div_ceil(1_000_000 - self.clock_rate_error_ppm))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeIdentity {
    pub node_id: u64,
    pub principal: String,
    /// SHA-256 of the actual authenticated mTLS leaf DER, never body metadata.
    pub certificate_sha256: String,
}
impl NodeIdentity {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.node_id > 0, "zero node identity");
        validate_name(&self.principal)?;
        validate_sha256(&self.certificate_sha256)?;
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingIdentity {
    pub tenant: String,
    pub incarnation: Uuid,
    pub authority_epoch: u64,
    pub node: NodeIdentity,
}
impl ServingIdentity {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.tenant)?;
        self.node.validate()?;
        ensure!(
            !self.incarnation.is_nil() && self.authority_epoch > 0,
            "invalid incarnation or epoch"
        );
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequest {
    pub manifest_digest: String,
    pub identity: ServingIdentity,
    pub boot_id: Uuid,
    pub attempt_id: Uuid,
    pub purpose: LeasePurpose,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeasePurpose {
    Serving,
    RestorePreparation,
}
/// Authenticated discovery of the exact requested incarnation. The returned
/// epoch is routing information only; it cannot open storage or anchor a lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseDiscovery {
    pub tenant: String,
    pub incarnation: Uuid,
    pub node: NodeIdentity,
    pub purpose: LeasePurpose,
}
impl LeaseDiscovery {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.tenant)?;
        self.node.validate()?;
        ensure!(!self.incarnation.is_nil(), "nil discovery incarnation");
        Ok(())
    }
}
impl LeaseRequest {
    pub fn validate(&self) -> Result<()> {
        validate_sha256(&self.manifest_digest)?;
        self.identity.validate()?;
        ensure!(
            !self.boot_id.is_nil() && !self.attempt_id.is_nil(),
            "nil lease acquisition identity"
        );
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseClaims {
    pub request: LeaseRequest,
    pub authority_id: Uuid,
    pub partition: u16,
    pub authority_term: u64,
    pub authority_revision: u64,
    pub lifetime_ms: u64,
    /// Credential lifetime remaining at the issuer's trusted admission, capped
    /// by max_lease_ms. Anchoring before request makes network delay conservative.
    pub credential_lifetime_ms: u64,
    pub activation_digest: String,
    pub recovery_checkpoint: Option<FullBackupCheckpoint>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLease {
    pub claims: LeaseClaims,
    pub signature: String,
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
            } => {
                ensure!(!fence_id.is_nil(), "nil fence identity");
                validate_sha256(fence_digest)?;
                let source = Uuid::parse_str(&target.checkpoint.source_incarnation)?;
                target.validate(&self.tenant, source)?;
            }
            AuthorityAction::StopActivation { original } => {
                ensure!(
                    matches!(original.action, AuthorityAction::Activate { .. })
                        && original.tenant == self.tenant
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
        code: kasumi_types::ErrorCode,
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
    pub signature: String,
}
