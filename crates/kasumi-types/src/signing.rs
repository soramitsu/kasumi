//! Canonical signing wire records. Deserialization does not verify a signature
//! or grant authority to change a verifier's current accepted generation.
use crate::{Error, ErrorCode, Result, validate_name, validate_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Immutable physical verifier installation, separate from a tenant, authority
/// generation, operational membership or renewable transport certificate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustVerifierIdentity {
    pub installation_id: Uuid,
    pub node_id: u64,
}
impl TrustVerifierIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.installation_id.is_nil() || self.node_id == 0 {
            return Err(invalid("invalid local verifier identity"));
        }
        Ok(())
    }
    pub fn tenant(&self) -> String {
        format!("kasumi.trust.{}.{}", self.installation_id, self.node_id)
    }
}

/// Exact enrolled HA node, including the physical live verifier installation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeIdentity {
    pub node_id: u64,
    pub verifier: TrustVerifierIdentity,
    pub principal: String,
    /// SHA-256 of the actual authenticated mTLS leaf DER, never body metadata.
    pub certificate_sha256: String,
}
impl NodeIdentity {
    pub fn validate(&self) -> Result<()> {
        self.verifier.validate()?;
        if self.node_id != self.verifier.node_id {
            return Err(invalid("physical verifier node differs"));
        }
        validate_name(&self.principal)?;
        validate_sha256(&self.certificate_sha256)
    }
}

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
