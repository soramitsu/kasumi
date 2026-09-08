//! Durable authority maintenance identities. Starting and resuming an operation
//! preserve its original command; status never substitutes a new membership.
use anyhow::{Result, ensure};
use kasumi_types::{ErrorCode, validate_name, validate_sha256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityMember {
    pub endpoint: String,
    pub failure_domain: String,
    pub certificate_pins: BTreeSet<String>,
}
impl AuthorityMember {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.endpoint.len() <= 2048,
            "authority endpoint exceeds its byte limit"
        );
        let endpoint = url::Url::parse(&self.endpoint)?;
        ensure!(
            endpoint.scheme() == "https"
                && endpoint.host_str().is_some()
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.path() == "/"
                && endpoint.query().is_none()
                && endpoint.fragment().is_none(),
            "authority member endpoint must be an installed HTTPS origin"
        );
        validate_name(&self.failure_domain)?;
        ensure!(
            (1..=8).contains(&self.certificate_pins.len()),
            "authority member requires bounded explicit certificate pins"
        );
        for pin in &self.certificate_pins {
            validate_sha256(pin)?;
            ensure!(
                *pin == pin.to_ascii_lowercase(),
                "authority member pins must be canonical lowercase digests"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCapacity {
    pub max_tenants: u64,
    /// Includes permanent receipts and member-revocation identities. Counts have
    /// no lifetime ceiling; admission uses the expandable encrypted byte budget.
    pub max_state_bytes: u64,
    /// Ordinary commands cannot consume the reserve required for maintenance,
    /// revocation and durable completion of an already accepted operation.
    pub maintenance_reserve_bytes: u64,
}
impl AuthorityCapacity {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.max_tenants > 0
                && self.maintenance_reserve_bytes >= 1 << 20
                && self.maintenance_reserve_bytes < self.max_state_bytes,
            "authority capacity must retain at least one MiB of maintenance reserve"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityMembership {
    pub voters: BTreeSet<u64>,
    /// Live members only. Permanent revoked member identities are point-addressed
    /// records, and cannot be reused merely by removing them from this map.
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
    pub members: BTreeMap<u64, AuthorityMember>,
}
impl AuthorityMembership {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (3..=64).contains(&self.members.len()) && !self.members.contains_key(&0),
            "authority requires three to 64 installed live members"
        );
        ensure!(
            self.voters.len() == 3 && self.voters.iter().all(|id| self.members.contains_key(id)),
            "authority membership requires exactly three installed voters"
        );
        let mut domains = BTreeSet::new();
        let mut origins = BTreeSet::new();
        let mut pins = BTreeSet::new();
        for (id, member) in &self.members {
            member.validate()?;
            ensure!(
                !self.voters.contains(id) || domains.insert(&member.failure_domain),
                "authority voters require independent failure domains"
            );
            ensure!(
                origins.insert(url::Url::parse(&member.endpoint)?.to_string()),
                "authority members require distinct endpoints"
            );
            ensure!(
                member.certificate_pins.iter().all(|pin| pins.insert(pin)),
                "authority certificate cannot identify multiple members"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityMaintenanceAction {
    EnrollLearner {
        node_id: u64,
        member: AuthorityMember,
    },
    ReplaceVoters {
        voters: BTreeSet<u64>,
    },
    RevokeMember {
        node_id: u64,
    },
    SetCapacity {
        capacity: AuthorityCapacity,
    },
}
impl AuthorityMaintenanceAction {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::EnrollLearner { node_id, member } => {
                ensure!(*node_id > 0, "authority member ID cannot be zero");
                member.validate()?;
            }
            Self::ReplaceVoters { voters } => ensure!(
                voters.len() == 3 && !voters.contains(&0),
                "authority replacement needs exactly three nonzero voters"
            ),
            Self::RevokeMember { node_id } => {
                ensure!(*node_id > 0, "authority member ID cannot be zero")
            }
            Self::SetCapacity { capacity } => capacity.validate()?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityMaintenanceCommand {
    pub operation_id: Uuid,
    pub expected_policy_epoch: u64,
    pub expected_operational_revision: u64,
    /// Latest initial admission. An accepted operation resumes with its original
    /// input after fresh current-admin authorization, without rewriting this time.
    pub not_after_ms: u64,
    pub action: AuthorityMaintenanceAction,
}
impl AuthorityMaintenanceCommand {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.operation_id.is_nil() && self.expected_policy_epoch > 0 && self.not_after_ms > 0,
            "invalid authority maintenance identity or admission deadline"
        );
        self.action.validate()
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        crate::digest(&("kasumi.authority-maintenance-command.v1", self))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityMaintenanceRequest {
    Configuration,
    Start {
        command: AuthorityMaintenanceCommand,
    },
    Resume {
        operation_id: Uuid,
    },
    Status {
        operation_id: Uuid,
    },
    Stop {
        operation_id: Uuid,
    },
}
impl AuthorityMaintenanceRequest {
    pub fn operation_id(&self) -> Option<Uuid> {
        match self {
            Self::Configuration => None,
            Self::Start { command } => Some(command.operation_id),
            Self::Resume { operation_id }
            | Self::Status { operation_id }
            | Self::Stop { operation_id } => Some(*operation_id),
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.operation_id().is_none_or(|id| !id.is_nil()),
            "maintenance operation ID cannot be nil"
        );
        if let Self::Start { command } = self {
            command.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityMaintenancePhase {
    Prepared,
    /// Persisted before dispatch. Cancellation cannot pretend this phase has no
    /// side effects; uncertain membership changes must resolve and proceed.
    Dispatched,
    /// Revocation is committed; the complete issuer interval must elapse before
    /// reporting that the removed identity has drained.
    Draining,
    Completed,
    Stopped,
    Rejected {
        code: ErrorCode,
        message: String,
    },
}
impl AuthorityMaintenancePhase {
    pub fn terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Stopped | Self::Rejected { .. }
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityMaintenanceStatus {
    pub command: AuthorityMaintenanceCommand,
    pub command_sha256: String,
    pub admitted_principal: String,
    pub admitted_revision: u64,
    pub progress_revision: u64,
    pub phase: AuthorityMaintenancePhase,
}
impl AuthorityMaintenanceStatus {
    pub fn validate(&self) -> Result<()> {
        self.command.validate()?;
        validate_name(&self.admitted_principal)?;
        ensure!(
            self.command.digest()? == self.command_sha256
                && self.admitted_revision > 0
                && self.progress_revision >= self.admitted_revision,
            "invalid maintenance command commitment or position"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityOperationalConfiguration {
    pub policy_epoch: u64,
    pub revision: u64,
    pub membership: AuthorityMembership,
    pub capacity: AuthorityCapacity,
    pub pending_operation: Option<Uuid>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityMaintenanceResponse {
    Configuration {
        configuration: AuthorityOperationalConfiguration,
    },
    Operation {
        status: AuthorityMaintenanceStatus,
    },
}
