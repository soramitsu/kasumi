//! Transport observations about a complete authenticated backup. These records
//! are not authority: verified proof wrappers belong to the engine and secure SDK.
use crate::{Error, ErrorCode, Result, validate_name, validate_sha256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FullBackupCheckpoint {
    pub tenant: String,
    pub source_incarnation: String,
    pub revision: u64,
    pub resident_sha256: String,
    pub backup_id: uuid::Uuid,
    pub manifest_ciphertext_sha256: String,
    pub key_lineage_digest: String,
}
impl FullBackupCheckpoint {
    /// Checks wire shape only; it does not authenticate a checkpoint.
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.tenant)?;
        validate_name(&self.source_incarnation)?;
        validate_sha256(&self.resident_sha256)?;
        validate_sha256(&self.manifest_ciphertext_sha256)?;
        validate_sha256(&self.key_lineage_digest)?;
        if self.backup_id.is_nil() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "nil backup checkpoint identity",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBackupCheckpoint {
    pub destination: String,
    pub session_id: uuid::Uuid,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyBackupCheckpoint {
    pub destination: String,
    pub backup_id: uuid::Uuid,
}

/// One durable identity is chosen before the first object is uploaded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupSessionIntent {
    pub session_id: uuid::Uuid,
    pub tenant: String,
    pub source_incarnation: String,
    pub revision: u64,
    pub principal: String,
    pub request_id: String,
}
impl BackupSessionIntent {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.tenant)?;
        validate_name(&self.source_incarnation)?;
        validate_name(&self.principal)?;
        if self.session_id.is_nil() || self.request_id.len() > 1024 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid backup session intent",
            ));
        }
        Ok(())
    }
}
/// Exactly one create-only outcome can win. It is never a cleanup target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupSessionOutcome {
    Complete {
        intent_ciphertext_sha256: String,
        checkpoint: FullBackupCheckpoint,
    },
    Aborted {
        intent_ciphertext_sha256: String,
        session_id: uuid::Uuid,
        principal: String,
        reason: String,
    },
}
impl BackupSessionOutcome {
    pub fn validate(&self, intent: &BackupSessionIntent, digest: &str) -> Result<()> {
        intent.validate()?;
        validate_sha256(digest)?;
        let actual = match self {
            Self::Complete {
                intent_ciphertext_sha256,
                checkpoint,
            } => {
                checkpoint.validate()?;
                if checkpoint.backup_id != intent.session_id
                    || checkpoint.tenant != intent.tenant
                    || checkpoint.source_incarnation != intent.source_incarnation
                    || checkpoint.revision != intent.revision
                {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "completed backup differs from session intent",
                    ));
                }
                intent_ciphertext_sha256
            }
            Self::Aborted {
                intent_ciphertext_sha256,
                session_id,
                principal,
                reason,
            } => {
                validate_name(principal)?;
                if *session_id != intent.session_id || reason.is_empty() || reason.len() > 1024 {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "aborted backup differs from session intent",
                    ));
                }
                intent_ciphertext_sha256
            }
        };
        if actual != digest {
            return Err(Error::new(
                ErrorCode::Corruption,
                "backup outcome intent digest differs",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSessionRequest {
    pub destination: String,
    pub session_id: uuid::Uuid,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortBackupSession {
    pub destination: String,
    pub session_id: uuid::Uuid,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupBackupSession {
    pub destination: String,
    pub session_id: uuid::Uuid,
    pub max_objects: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSessionStatus {
    pub intent: BackupSessionIntent,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub outcome: Option<BackupSessionOutcome>,
    pub source_purpose_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCleanupResult {
    pub session_id: uuid::Uuid,
    pub deleted_objects: u64,
    pub more_objects_observed: bool,
}
