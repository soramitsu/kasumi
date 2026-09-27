//! Signed routing reads are observations, never tenant or issuer execution grants.
use crate::{control_topology::VersionedTopology, *};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const MAX_CONTROL_TOPOLOGY_LIFETIME_MS: u64 = 5_000;
pub const MAX_CONTROL_TOPOLOGY_BYTES: usize = 8 << 20;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadControlTopology {
    pub request_id: Uuid,
    pub control_incarnation: Uuid,
    pub maximum_lifetime_ms: u64,
}
impl ReadControlTopology {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.request_id.is_nil()
                && !self.control_incarnation.is_nil()
                && (1..=MAX_CONTROL_TOPOLOGY_LIFETIME_MS).contains(&self.maximum_lifetime_ms),
            "invalid Control topology read identity or lifetime"
        );
        Ok(())
    }
}

/// Derived at the native authentication boundary. The credential digest binds
/// the exact verified bearer without retaining or exposing its plaintext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlTopologyCaller {
    pub principal: String,
    pub certificate_sha256: String,
    pub credential_sha256: String,
}
impl ControlTopologyCaller {
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_name(&self.principal)?;
        validate_sha256(&self.certificate_sha256)?;
        validate_sha256(&self.credential_sha256)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlTopologyObservation {
    pub request: ReadControlTopology,
    pub root: ControlSigningRoot,
    pub caller: ControlTopologyCaller,
    pub policy_epoch: u64,
    pub revision: u64,
    pub term: u64,
    pub leader_node_id: u64,
    pub voters: BTreeSet<u64>,
    pub topology: VersionedTopology,
    pub admitted_at_ms: u64,
    pub not_after_ms: u64,
}
impl ControlTopologyObservation {
    pub fn validate(&self) -> anyhow::Result<()> {
        self.request.validate()?;
        self.root.validate()?;
        self.caller.validate()?;
        self.topology.topology.validate()?;
        anyhow::ensure!(
            self.request.control_incarnation == self.root.control_incarnation
                && self.policy_epoch > 0
                && self.revision > 0
                && self.term > 0
                && self.voters.len() == 3
                && !self.voters.contains(&0)
                && self.voters.contains(&self.leader_node_id)
                && self.topology.version > 0
                && self.admitted_at_ms < self.not_after_ms
                && self.not_after_ms - self.admitted_at_ms <= self.request.maximum_lifetime_ms,
            "invalid current Control topology observation"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedControlTopology {
    pub observation: ControlTopologyObservation,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseControlTopology {
    pub request_id: Uuid,
    pub original: SignedControlTopology,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlTopologyRelease {
    pub request_id: Uuid,
    pub original_sha256: String,
    pub revision: u64,
    /// The original deadline is copied exactly, never renewed by release.
    pub not_after_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedControlTopologyRelease {
    pub release: ControlTopologyRelease,
    pub signature: String,
}
