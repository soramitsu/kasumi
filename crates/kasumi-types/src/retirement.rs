//! Planned retirement observations and exact request identity. These are wire
//! records, never constructors for a verified engine or SDK proof.
use crate::{
    Error, ErrorCode, FullBackupCheckpoint, Result, staged_digest, validate_name, validate_sha256,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetireSourceRequest {
    pub retirement_id: String,
    pub expected_source_incarnation: String,
    pub target_incarnation: String,
    pub checkpoint: FullBackupCheckpoint,
    pub destination: String,
    pub not_after_ms: u64,
}
impl RetireSourceRequest {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.retirement_id)?;
        validate_name(&self.expected_source_incarnation)?;
        validate_name(&self.destination)?;
        self.checkpoint.validate()?;
        let target = uuid::Uuid::parse_str(&self.target_incarnation).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "retirement target must be a UUID incarnation",
            )
        })?;
        if target.is_nil()
            || target.to_string() != self.target_incarnation
            || self.target_incarnation == self.expected_source_incarnation
            || self.checkpoint.source_incarnation != self.expected_source_incarnation
            || self.not_after_ms == 0
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "retirement source, target or deadline binding differs",
            ));
        }
        Ok(())
    }
    pub fn reference(&self) -> Result<RetirementRef> {
        self.validate()?;
        Ok(RetirementRef {
            source_incarnation: self.expected_source_incarnation.clone(),
            retirement_id: self.retirement_id.clone(),
            request_digest: staged_digest(&("kasumi.planned-retirement.v1", self))?.0,
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetirementRef {
    pub source_incarnation: String,
    pub retirement_id: String,
    pub request_digest: String,
}
impl RetirementRef {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.source_incarnation)?;
        validate_name(&self.retirement_id)?;
        validate_sha256(&self.request_digest)
    }
}

/// Historical accepted outcome, not a serving lease or proof constructor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetirementReceipt {
    pub tenant: String,
    pub principal: String,
    pub retirement_id: String,
    pub request_digest: String,
    pub source_incarnation: String,
    pub target_incarnation: String,
    pub revision: u64,
    pub policy_epoch: u64,
    pub admitted_at_ms: u64,
    pub checkpoint: FullBackupCheckpoint,
    /// Digest of all application payload/definition/epoch dependencies and
    /// retained command identities checked during ordered retirement.
    pub closure_digest: String,
}
impl RetirementReceipt {
    pub fn validate(&self) -> Result<()> {
        for name in [
            &self.tenant,
            &self.principal,
            &self.retirement_id,
            &self.source_incarnation,
        ] {
            validate_name(name)?;
        }
        validate_sha256(&self.request_digest)?;
        validate_sha256(&self.closure_digest)?;
        self.checkpoint.validate()?;
        let target = uuid::Uuid::parse_str(&self.target_incarnation)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "retirement target is invalid"))?;
        if target.is_nil()
            || target.to_string() != self.target_incarnation
            || self.tenant != self.checkpoint.tenant
            || self.source_incarnation != self.checkpoint.source_incarnation
            || self.source_incarnation == self.target_incarnation
            || self.revision <= self.checkpoint.revision
            || self.policy_epoch == 0
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "retirement receipt binding differs",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredRetirement {
    pub request: RetireSourceRequest,
    pub principal: String,
    pub request_digest: String,
    pub accepted_revision: u64,
    pub outcome: Result<RetirementReceipt>,
}

/// Exact accepted outcome for recovery discovery. This observation does not
/// construct a verified retirement proof in the engine or native SDK.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetirementStatus {
    pub tenant: String,
    pub principal: String,
    pub reference: RetirementRef,
    pub accepted_revision: u64,
    pub outcome: Result<RetirementReceipt>,
}

/// Internal replicated preparation. Public administrative mutation endpoints
/// must reject this operation; only complete backup graph verification creates
/// it. The serialized leader checks the current closure and fills observation
/// while retaining its ordered proposal gate until consensus resolves.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRetirement {
    pub request: RetireSourceRequest,
    pub verified_closure_digest: String,
    pub observation: Option<RetirementObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementObservation {
    pub revision: u64,
    pub closure_digest: String,
}
