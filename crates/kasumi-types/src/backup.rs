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
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyBackupCheckpoint {
    pub destination: String,
    pub backup_id: uuid::Uuid,
}
