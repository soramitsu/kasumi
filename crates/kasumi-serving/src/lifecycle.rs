//! Compact permanent issuer commands; original control authorization and fresh
//! issuer invocation authority have distinct identities and lifetimes.
use crate::*;
use anyhow::{Result, ensure};
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "proof",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LifecycleAuthorityRequest {
    AcceptIntent(Box<SignedControlIntent>),
    StopEpoch(Box<SignedControlChange>),
}
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
impl LifecycleAuthorityRequest {
    pub fn reference(&self) -> LifecycleAuthorityReference {
        match self {
            Self::AcceptIntent(signed) => LifecycleAuthorityReference {
                control_incarnation: signed.observation.intent.control_incarnation,
                control_policy_epoch: signed.observation.intent.request.expected_policy_epoch,
                identity: LifecycleAuthorityIdentity::Intent(
                    signed.observation.intent.request.command_id,
                ),
            },
            Self::StopEpoch(signed) => LifecycleAuthorityReference {
                control_incarnation: signed.observation.stop.control_incarnation,
                control_policy_epoch: signed.observation.stop.control_policy_epoch,
                identity: LifecycleAuthorityIdentity::EpochStop,
            },
        }
    }
    /// Fresh quorum observation positions and signatures are verification input,
    /// not a replacement immutable command identity. Every attempt still verifies
    /// the complete installed signature before lookup/release.
    pub fn digest(&self) -> Result<String> {
        match self {
            Self::AcceptIntent(signed) => digest(&(
                "kasumi.issuer-control-intent.v1",
                &signed.observation.intent,
                &signed.observation.root,
                &signed.observation.authority_partition,
                &signed.observation.partition_set_sha256,
            )),
            Self::StopEpoch(signed) => digest(&(
                "kasumi.issuer-control-stop.v1",
                &signed.observation.root,
                &signed.observation.stop,
            )),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleAuthorityReceipt {
    pub authority_id: Uuid,
    pub authority_manifest_sha256: String,
    pub partition: u16,
    pub reference: LifecycleAuthorityReference,
    pub request: LifecycleAuthorityRequest,
    pub request_sha256: String,
    pub original_principal: String,
    pub accepted_revision: u64,
    pub accepted_term: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleLeaseRequest {
    pub authority_manifest_sha256: String,
    pub reference: LifecycleAuthorityReference,
    pub intent_sha256: String,
    pub target_node: NodeIdentity,
    pub boot_id: Uuid,
    pub attempt_id: Uuid,
}
impl LifecycleLeaseRequest {
    pub fn validate(&self) -> Result<()> {
        self.reference.validate()?;
        ensure!(
            matches!(
                self.reference.identity,
                LifecycleAuthorityIdentity::Intent(_)
            ) && !self.boot_id.is_nil()
                && !self.attempt_id.is_nil(),
            "invalid phase acquisition identity"
        );
        self.target_node.validate()?;
        validate_sha256(&self.authority_manifest_sha256)?;
        validate_sha256(&self.intent_sha256)?;
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleLeaseClaims {
    pub request: LifecycleLeaseRequest,
    pub commitment: ControlIntentCommitment,
    pub authority_id: Uuid,
    pub partition: u16,
    pub authority_term: u64,
    pub authority_revision: u64,
    /// The issuer's actual current incarnation role. Cleanup has no application
    /// authority; inspection may use the exact prepared or activated role.
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    pub application_purpose: Option<LeasePurpose>,
    pub lifetime_ms: u64,
    /// Remaining actual node JWT AND original committed Control JWT at issuer
    /// admission, capped by the immutable maximum and anchored before dispatch.
    pub credential_lifetime_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLifecycleLease {
    pub claims: LifecycleLeaseClaims,
    pub signature: String,
}

impl AuthorityManifest {
    pub fn control_partition(&self, partition: u16) -> Result<ControlAuthorityPartition> {
        self.validate()?;
        let installed = self
            .partitions
            .get(&partition)
            .ok_or_else(|| anyhow::anyhow!("unknown lifecycle issuer partition"))?;
        Ok(ControlAuthorityPartition {
            authority_id: self.authority_id,
            manifest_sha256: self.digest()?,
            partition,
            signing_public_key: installed.public_key.clone(),
            maximum_lifetime_ms: self.max_lease_ms,
            drain_ms: self.drain_ms()?,
        })
    }
    /// Verifies installed cryptographic origin on every attempt, including exact
    /// replay. The returned immutable facts cannot create a live target grant.
    pub fn verify_lifecycle_request(
        &self,
        partition: u16,
        request: &LifecycleAuthorityRequest,
    ) -> Result<()> {
        let reference = request.reference();
        reference.validate()?;
        let root = ControlSigningRoot {
            control_incarnation: reference.control_incarnation,
            public_key: self
                .lifecycle_controls
                .get(&reference.control_incarnation)
                .ok_or_else(|| anyhow::anyhow!("control root not installed"))?
                .clone(),
        };
        let trust = ControlTrust::install(root)?;
        let expected = self.control_partition(partition)?;
        match request {
            LifecycleAuthorityRequest::AcceptIntent(signed) => {
                let proof = trust.verify_intent(signed)?;
                let obs = proof.observation();
                ensure!(
                    obs.authority_partition == expected
                        && self.partition(&obs.intent.request.tenant)? == partition,
                    "control intent issuer routing differs"
                );
            }
            LifecycleAuthorityRequest::StopEpoch(signed) => {
                let proof = trust.verify_change(signed)?;
                ensure!(
                    proof.observation().stop.authority_partition == expected,
                    "control epoch stop issuer differs"
                );
            }
        }
        Ok(())
    }
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
impl LifecycleAuthorityReceipt {
    pub fn validate(&self, manifest: &AuthorityManifest, partition: u16) -> Result<()> {
        manifest.verify_lifecycle_request(partition, &self.request)?;
        validate_name(&self.original_principal)?;
        ensure!(
            self.authority_id == manifest.authority_id
                && self.authority_manifest_sha256 == manifest.digest()?
                && self.partition == partition
                && self.reference == self.request.reference()
                && self.request_sha256 == self.request.digest()?
                && self.accepted_revision > 0
                && self.accepted_term > 0,
            "lifecycle issuer receipt binding differs"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLifecycleAuthorityReceipt {
    pub receipt: LifecycleAuthorityReceipt,
    pub signature: String,
}
