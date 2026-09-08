//! Canonical signing wire records. Deserialization does not verify a signature
//! or grant authority to change a verifier's current accepted generation.
use crate::{Error, ErrorCode, Result, validate_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningDomain {
    pub authority_id: Uuid,
    pub partition: u16,
    pub manifest_sha256: String,
    pub root_public_key: String,
    pub retirement_drain_ms: u64,
}
impl SigningDomain {
    pub fn validate(&self) -> Result<()> {
        if self.authority_id.is_nil() || self.partition >= 1024 {
            return Err(invalid("invalid signing authority or partition"));
        }
        validate_sha256(&self.manifest_sha256)?;
        validate_sha256(&self.root_public_key)?;
        if !(100..=125_000).contains(&self.retirement_drain_ms) {
            return Err(invalid("invalid installed signer retirement interval"));
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(&("kasumi.signing-domain.v1", self))
            .map_err(|_| invalid("signing domain encoding failed"))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningGeneration {
    pub domain: SigningDomain,
    pub generation: u64,
    pub public_key: String,
}
impl SigningGeneration {
    pub fn validate(&self) -> Result<()> {
        self.domain.validate()?;
        if self.generation == 0 {
            return Err(invalid("zero signing generation"));
        }
        validate_sha256(&self.public_key)?;
        if self.public_key == self.domain.root_public_key {
            return Err(invalid(
                "operational signer must be separate from the installation root",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningCertificate {
    pub identity: SigningGeneration,
    pub root_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationSignature {
    pub certificate: SigningCertificate,
    pub signature: String,
}

fn invalid(message: &str) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}
