//! Historical signing certificates deliberately carry no live authorization.
use anyhow::{Context, Result, ensure};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
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
        ensure!(
            !self.authority_id.is_nil() && self.partition < 1024,
            "invalid signing authority or partition"
        );
        kasumi_types::validate_sha256(&self.manifest_sha256)?;
        kasumi_types::validate_sha256(&self.root_public_key)?;
        ensure!(
            (100..=125_000).contains(&self.retirement_drain_ms),
            "invalid installed signer retirement interval"
        );
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        crate::digest(&("kasumi.signing-domain.v1", self))
    }
}
impl crate::AuthorityManifest {
    pub fn signing_domain(&self, partition: u16) -> Result<SigningDomain> {
        self.validate()?;
        Ok(SigningDomain {
            authority_id: self.authority_id,
            partition,
            manifest_sha256: self.digest()?,
            root_public_key: self
                .partitions
                .get(&partition)
                .context("unknown authority partition")?
                .public_key
                .clone(),
            retirement_drain_ms: self.drain_ms()?,
        })
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
    fn validate(&self) -> Result<()> {
        self.domain.validate()?;
        ensure!(self.generation > 0, "zero signing generation");
        kasumi_types::validate_sha256(&self.public_key)?;
        ensure!(
            self.public_key != self.domain.root_public_key,
            "operational signer must be separate from the installation root"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningCertificate {
    pub identity: SigningGeneration,
    pub root_signature: String,
}
impl SigningCertificate {
    pub fn verify(&self, installed: &SigningDomain) -> Result<()> {
        installed.validate()?;
        self.identity.validate()?;
        ensure!(
            self.identity.domain == *installed,
            "signing installation differs"
        );
        verify_signature(
            &installed.root_public_key,
            &serde_json::to_vec(&("kasumi.signing-certificate.v1", &self.identity))?,
            &self.root_signature,
        )
    }
    pub fn digest(&self) -> Result<String> {
        self.verify(&self.identity.domain)?;
        crate::digest(&("kasumi.signing-certificate-digest.v1", self))
    }
}

/// Operator-held installation root. Runtime generation keys cannot issue roots
/// or manufacture certificates for another operational generation.
pub struct InstallationSigningRoot {
    domain: SigningDomain,
    key: Ed25519KeyPair,
}
impl InstallationSigningRoot {
    pub fn from_pkcs8(domain: SigningDomain, bytes: &[u8]) -> Result<Self> {
        domain.validate()?;
        let key = decode_key(bytes)?;
        ensure!(
            hex::encode(key.public_key().as_ref()) == domain.root_public_key,
            "installation root key differs"
        );
        Ok(Self { domain, key })
    }
    pub fn certify(&self, generation: u64, public_key: String) -> Result<SigningCertificate> {
        let identity = SigningGeneration {
            domain: self.domain.clone(),
            generation,
            public_key,
        };
        identity.validate()?;
        let bytes = serde_json::to_vec(&("kasumi.signing-certificate.v1", &identity))?;
        Ok(SigningCertificate {
            identity,
            root_signature: hex::encode(self.key.sign(&bytes).as_ref()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationSignature {
    pub certificate: SigningCertificate,
    pub signature: String,
}
pub struct GenerationSigner {
    certificate: SigningCertificate,
    key: Ed25519KeyPair,
}
impl GenerationSigner {
    pub fn from_pkcs8(certificate: SigningCertificate, bytes: &[u8]) -> Result<Self> {
        certificate.verify(&certificate.identity.domain)?;
        let key = decode_key(bytes)?;
        ensure!(
            hex::encode(key.public_key().as_ref()) == certificate.identity.public_key,
            "operational signing key differs from certificate"
        );
        Ok(Self { certificate, key })
    }
    pub fn certificate(&self) -> &SigningCertificate {
        &self.certificate
    }
    pub fn sign<T: Serialize>(&self, purpose: &str, value: &T) -> Result<GenerationSignature> {
        let bytes = signed_bytes(&self.certificate, purpose, value)?;
        Ok(GenerationSignature {
            certificate: self.certificate.clone(),
            signature: hex::encode(self.key.sign(&bytes).as_ref()),
        })
    }
}

/// Verification of retained evidence returns no gate, activation permit, or
/// authority to mutate a verifier's current trust record.
#[derive(Clone)]
pub struct HistoricalSigningTrust(SigningDomain);
impl HistoricalSigningTrust {
    pub fn install(domain: SigningDomain) -> Result<Self> {
        domain.validate()?;
        Ok(Self(domain))
    }
    pub fn domain(&self) -> &SigningDomain {
        &self.0
    }
    pub fn verify<T: Serialize>(
        &self,
        purpose: &str,
        value: &T,
        signed: &GenerationSignature,
    ) -> Result<()> {
        signed.certificate.verify(&self.0)?;
        verify_signature(
            &signed.certificate.identity.public_key,
            &signed_bytes(&signed.certificate, purpose, value)?,
            &signed.signature,
        )
    }
}
fn signed_bytes<T: Serialize>(
    certificate: &SigningCertificate,
    purpose: &str,
    value: &T,
) -> Result<Vec<u8>> {
    kasumi_types::validate_name(purpose)?;
    serde_json::to_vec(&(
        "kasumi.generation-signature.v1",
        certificate.digest()?,
        purpose,
        value,
    ))
    .map_err(Into::into)
}
fn decode_key(bytes: &[u8]) -> Result<Ed25519KeyPair> {
    Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| anyhow::anyhow!("invalid installed Ed25519 key"))
}
fn verify_signature(key: &str, bytes: &[u8], signature: &str) -> Result<()> {
    ensure!(
        signature.len() == 128
            && signature
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "generation signatures require canonical lowercase hex"
    );
    let signature = hex::decode(signature)?;
    UnparsedPublicKey::new(&ED25519, hex::decode(key)?)
        .verify(bytes, &signature)
        .map_err(|_| anyhow::anyhow!("generation signature invalid"))
}
