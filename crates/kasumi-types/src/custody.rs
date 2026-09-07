//! Closed administration of one permanently retired source. These wire records
//! cannot enable serving or construct a current-authority retirement proof.
use crate::{Error, ErrorCode, Result, RetirementRef, validate_name, validate_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Dedicated custody budgets, independent of the frozen application limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustodyLimits {
    pub max_commands: usize,
    pub max_audit_records: usize,
    pub max_state_bytes: usize,
}
impl Default for CustodyLimits {
    fn default() -> Self {
        Self {
            max_commands: 1024,
            max_audit_records: 2048,
            max_state_bytes: 1 << 20,
        }
    }
}
impl CustodyLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_commands == 0
            || self.max_commands > 4096
            || self.max_audit_records == 0
            || self.max_audit_records > 8192
            || !(4096..=1 << 20).contains(&self.max_state_bytes)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid custody limits",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "action",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CustodyAction {
    ReplaceAdministrators(BTreeSet<String>),
    SetLimits(CustodyLimits),
}

/// The entire request is the permanent command identity. Authentication and
/// trusted admission time are supplied separately by the native boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustodyRequest {
    pub retirement: RetirementRef,
    pub command_id: String,
    pub expected_policy_epoch: u64,
    pub not_after_ms: u64,
    pub action: CustodyAction,
}
impl CustodyRequest {
    pub fn validate(&self) -> Result<()> {
        self.retirement.validate()?;
        validate_name(&self.command_id)?;
        if self.expected_policy_epoch == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "custody epoch is zero",
            ));
        }
        match &self.action {
            CustodyAction::ReplaceAdministrators(principals) => {
                validate_custody_administrators(principals)
            }
            CustodyAction::SetLimits(limits) => limits.validate(),
        }
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(&("kasumi.retirement-custody-command.v1", self)).map_err(|_| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "custody request encoding failed",
                )
            })?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

pub fn validate_custody_administrators(principals: &BTreeSet<String>) -> Result<()> {
    if principals.is_empty() || principals.len() > 1024 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "custody requires 1..1024 administrators",
        ));
    }
    for principal in principals {
        validate_name(principal)?;
    }
    Ok(())
}

/// Immutable accepted outcome. It carries no renewable credential, quorum or
/// serving authority. A current source custodian must authorize every readback.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustodyReceipt {
    pub command_id: String,
    pub request_digest: String,
    pub principal: String,
    pub revision: u64,
    pub admitted_at_ms: u64,
    pub previous_policy_epoch: u64,
    pub policy_epoch: u64,
    pub outcome: Result<()>,
}
impl CustodyReceipt {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.command_id)?;
        validate_name(&self.principal)?;
        validate_sha256(&self.request_digest)?;
        if self.revision == 0
            || self.previous_policy_epoch == 0
            || self.policy_epoch < self.previous_policy_epoch
            || self.policy_epoch > self.previous_policy_epoch.saturating_add(1)
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "custody receipt position differs",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustodyStatus {
    pub retirement: RetirementRef,
    pub revision: u64,
    pub policy_epoch: u64,
    pub administrators: BTreeSet<String>,
    pub limits: CustodyLimits,
}
