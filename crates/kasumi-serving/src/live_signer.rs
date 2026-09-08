//! Issuing a signature requires the same exact durable generation accepted by
//! the local verifier. This does not replace command authorization or deadlines.
use crate::{
    GenerationSignature, GenerationSigner, LiveSignerTrust, SignerGenerationFence,
    SigningCertificate,
};
use anyhow::{Result, ensure};
use serde::Serialize;
use std::sync::Arc;

pub struct LiveGenerationSigner {
    signer: GenerationSigner,
    trust: Arc<LiveSignerTrust>,
}
impl LiveGenerationSigner {
    /// Installed key material is usable only after this exact certificate has
    /// become the durable current generation. Staging alone cannot start issuance.
    pub fn install(signer: GenerationSigner, trust: Arc<LiveSignerTrust>) -> Result<Self> {
        let owner = Self { signer, trust };
        owner.check()?;
        Ok(owner)
    }
    pub fn certificate(&self) -> &SigningCertificate {
        self.signer.certificate()
    }
    pub fn verifier_identity(&self) -> Result<crate::TrustVerifierIdentity> {
        self.check()?;
        Ok(self.trust.current()?.verifier)
    }
    pub fn same_verifier_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.trust, &other.trust)
    }
    pub fn check(&self) -> Result<()> {
        ensure!(
            self.trust.current()?.active == *self.signer.certificate(),
            "installed signer is not the exact active generation"
        );
        Ok(())
    }
    /// Retain the returned guard through adapter encoding and check it at the
    /// response release boundary, together with original invocation authority.
    pub fn sign<T: Serialize>(&self, purpose: &str, value: &T) -> Result<LiveGenerationSignature> {
        self.check()?;
        let signature = self.signer.sign(purpose, value)?;
        let fence = self.trust.verify_live(purpose, value, &signature)?;
        let output = LiveGenerationSignature { signature, fence };
        output.check()?;
        Ok(output)
    }
}

/// No deserializer or public constructor. Signature bytes remain historical
/// evidence; this separately retained guard proves current local acceptance.
pub struct LiveGenerationSignature {
    signature: GenerationSignature,
    fence: SignerGenerationFence,
}
impl LiveGenerationSignature {
    pub fn signature(&self) -> &GenerationSignature {
        &self.signature
    }
    pub fn check(&self) -> Result<()> {
        self.fence.check()
    }
}
