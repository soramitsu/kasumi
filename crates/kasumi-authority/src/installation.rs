use anyhow::{Result, ensure};
use kasumi_serving::{
    AuthorityCapacity, AuthorityManifest, AuthorityMembership, SigningCertificate,
    SigningCertificateVerification,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Permanent authority storage and proof identity. Operational membership,
/// administrators and byte capacities are replicated state, not this identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityInstallation {
    pub manifest: AuthorityManifest,
    pub partition: u16,
}
impl AuthorityInstallation {
    pub fn validate(&self) -> Result<()> {
        self.manifest.validate()?;
        ensure!(
            self.manifest.partitions.contains_key(&self.partition),
            "unknown installed authority partition"
        );
        Ok(())
    }
    pub fn tenant(&self) -> String {
        format!(
            "kasumi.authority.{}.{}",
            self.manifest.authority_id, self.partition
        )
    }
}

/// The original bootstrap remains explicit for a fresh replacement member. Once
/// installed it never overwrites current policy, capacities or membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBootstrap {
    pub initial_signer_certificate: SigningCertificate,
    pub administrators: BTreeSet<String>,
    pub capacity: AuthorityCapacity,
    pub membership: AuthorityMembership,
}
impl AuthorityBootstrap {
    pub fn validate(&self) -> Result<()> {
        self.initial_signer_certificate
            .verify(&self.initial_signer_certificate.identity.domain)?;
        ensure!(
            self.initial_signer_certificate.identity.generation == 1,
            "bootstrap signer generation must be one"
        );
        ensure!(
            !self.administrators.is_empty() && self.administrators.len() <= 64,
            "invalid initial authority administrators"
        );
        for principal in &self.administrators {
            kasumi_types::validate_name(principal)?;
        }
        self.capacity.validate()?;
        self.membership.validate()?;
        ensure!(
            self.membership.members.len() == 3,
            "bootstrap contains only its original three voters; enroll learners through maintenance"
        );
        Ok(())
    }
    pub fn voters(&self) -> BTreeMap<u64, kasumi_raft::BasicNode> {
        self.membership
            .voters
            .iter()
            .map(|id| {
                (
                    *id,
                    kasumi_raft::BasicNode::new(self.membership.members[id].endpoint.clone()),
                )
            })
            .collect()
    }
}

/// Installed node resources and approved transport pool may change between
/// starts. They never change the durable bootstrap or an accepted operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityNodeSettings {
    pub bootstrap: AuthorityBootstrap,
    pub resource_budget_bytes: u64,
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
    pub installed_members: BTreeMap<u64, kasumi_serving::AuthorityMember>,
}
impl AuthorityNodeSettings {
    pub fn validate(&self, node_id: u64) -> Result<()> {
        self.bootstrap.validate()?;
        ensure!(
            node_id > 0 && self.installed_members.contains_key(&node_id),
            "local authority node is absent from installed transport pool"
        );
        ensure!(
            self.resource_budget_bytes >= self.bootstrap.capacity.max_state_bytes
                && self.resource_budget_bytes <= (u64::MAX - (64 << 20)) / 8,
            "authority node resources cannot fit its bootstrap capacity"
        );
        for (id, member) in &self.bootstrap.membership.members {
            ensure!(
                self.installed_members.get(id) == Some(member),
                "installed original authority member differs from bootstrap"
            );
        }
        AuthorityMembership {
            voters: self.bootstrap.membership.voters.clone(),
            members: self.installed_members.clone(),
        }
        .validate()?;
        Ok(())
    }
}

/// Implemented by the installed, authenticated peer transport. Callers cannot
/// supply serialized readiness evidence to authorize a resource or trust change.
/// Successful acknowledgements durably reserve the required local resource floor.
#[async_trait::async_trait]
pub trait AuthorityMaintenanceTransport: Send + Sync {
    async fn check_ready(
        &self,
        node_id: u64,
        bootstrap_sha256: &str,
        required_state_bytes: u64,
        command: &kasumi_serving::AuthorityMaintenanceCommand,
    ) -> Result<()>;
}
