use crate::*;
use anyhow::{Context, Result, ensure};
use kasumi_clock::{LeaseClock, SystemLeaseClock};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

/// Explicit installed secret. No deserializer, Debug output or request endpoint
/// accepts an issuer key. The corresponding public key is fixed in the manifest.
pub struct AuthoritySigner(Ed25519KeyPair);
impl AuthoritySigner {
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| {
            anyhow::anyhow!("invalid installed authority signing key")
        })?))
    }
    pub fn public_key(&self) -> String {
        hex::encode(self.0.public_key().as_ref())
    }
    pub fn sign_lease(&self, claims: LeaseClaims) -> Result<SignedLease> {
        let bytes = serde_json::to_vec(&("kasumi.serving-lease.v1", &claims))?;
        Ok(SignedLease {
            claims,
            signature: hex::encode(self.0.sign(&bytes).as_ref()),
        })
    }
    pub fn sign_receipt(&self, receipt: AuthorityReceipt) -> Result<SignedAuthorityReceipt> {
        let bytes = serde_json::to_vec(&("kasumi.authority-proof.v1", &receipt))?;
        Ok(SignedAuthorityReceipt {
            receipt,
            signature: hex::encode(self.0.sign(&bytes).as_ref()),
        })
    }
}

#[derive(Clone)]
pub struct AuthorityTrust {
    manifest: Arc<AuthorityManifest>,
    digest: String,
}
impl AuthorityTrust {
    pub fn install(manifest: AuthorityManifest) -> Result<Self> {
        manifest.validate()?;
        let digest = manifest.digest()?;
        Ok(Self {
            manifest: Arc::new(manifest),
            digest,
        })
    }
    pub fn manifest(&self) -> &AuthorityManifest {
        &self.manifest
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    fn verify<T: serde::Serialize>(
        &self,
        partition: u16,
        domain: &str,
        value: &T,
        signature: &str,
    ) -> Result<()> {
        let key = &self
            .manifest
            .partitions
            .get(&partition)
            .context("unknown authority partition")?
            .public_key;
        let bytes = serde_json::to_vec(&(domain, value))?;
        let signature = hex::decode(signature)?;
        ensure!(signature.len() == 64, "invalid authority signature length");
        UnparsedPublicKey::new(&ED25519, hex::decode(key)?)
            .verify(&bytes, &signature)
            .map_err(|_| anyhow::anyhow!("authority signature invalid"))
    }
    pub fn verify_activation(&self, signed: SignedAuthorityReceipt) -> Result<VerifiedActivation> {
        self.verify_receipt(&signed)?;
        let receipt = &signed.receipt;
        match (&receipt.command.action, &receipt.outcome) {
            (
                AuthorityAction::Activate {
                    target: requested, ..
                },
                AuthorityOutcome::Activated {
                    target,
                    authority_epoch,
                },
            ) => {
                ensure!(
                    target == requested && *authority_epoch > 1,
                    "activation outcome differs"
                );
            }
            _ => anyhow::bail!("authority receipt is not an activation"),
        }
        Ok(VerifiedActivation { signed })
    }
    /// Validate immutable wire evidence against the installed issuer. This
    /// creates no live authority and does not assert current administrator access.
    pub fn verify_receipt(&self, signed: &SignedAuthorityReceipt) -> Result<()> {
        let receipt = &signed.receipt;
        receipt.command.validate()?;
        ensure!(
            receipt.authority_id == self.manifest.authority_id
                && receipt.manifest_digest == self.digest
                && receipt.partition == self.manifest.partition(&receipt.command.tenant)?
                && receipt.revision > 0,
            "activation authority binding differs"
        );
        ensure!(
            receipt.command.digest()? == receipt.command_digest,
            "activation command digest differs"
        );
        self.verify(
            receipt.partition,
            "kasumi.authority-proof.v1",
            receipt,
            &signed.signature,
        )
    }
}

/// Process-scoped identity; cannot be loaded from a persisted boot UUID.
#[derive(Clone)]
pub struct ServingBoot {
    pub(crate) id: Uuid,
    pub(crate) identity: ServingIdentity,
    pub(crate) trust: AuthorityTrust,
    pub(crate) clock: Arc<dyn LeaseClock>,
    last_seen: Arc<Mutex<Option<Duration>>>,
    purpose: LeasePurpose,
}
impl ServingBoot {
    pub fn new(trust: AuthorityTrust, identity: ServingIdentity) -> Result<Self> {
        Self::with_clock(trust, identity, Arc::new(SystemLeaseClock))
    }
    fn with_clock(
        trust: AuthorityTrust,
        identity: ServingIdentity,
        clock: Arc<dyn LeaseClock>,
    ) -> Result<Self> {
        identity.validate()?;
        let initial = clock.now();
        Ok(Self {
            id: Uuid::new_v4(),
            identity,
            trust,
            clock,
            last_seen: Arc::new(Mutex::new(Some(initial))),
            purpose: LeasePurpose::Serving,
        })
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_test_clock(
        trust: AuthorityTrust,
        identity: ServingIdentity,
        clock: Arc<dyn LeaseClock>,
    ) -> Result<Self> {
        Self::with_clock(trust, identity, clock)
    }
    pub fn identity(&self) -> &ServingIdentity {
        &self.identity
    }
    pub fn authority(&self) -> &AuthorityTrust {
        &self.trust
    }
    pub fn for_restore_preparation(mut self) -> Self {
        self.purpose = LeasePurpose::RestorePreparation;
        self
    }
    /// Same process clock/boot, but each serving request gets a new attempt
    /// nonce. Only the issuer's active-incarnation response can promote access.
    pub fn for_serving(mut self) -> Self {
        self.purpose = LeasePurpose::Serving;
        self
    }
    pub(crate) fn now(&self) -> Result<Duration> {
        let mut last = self
            .last_seen
            .lock()
            .map_err(|_| anyhow::anyhow!("serving clock poisoned"))?;
        let now = self.clock.now();
        if last.is_none_or(|previous| now < previous) {
            *last = None;
            anyhow::bail!("serving elapsed clock regressed; restart requires fresh authority");
        }
        *last = Some(now);
        Ok(now)
    }
    /// Called before the first network dispatch. Retrying the same attempt must
    /// reuse this object; a new attempt cannot accept an earlier signed response.
    pub fn begin_acquisition(&self) -> Result<LeaseAttempt> {
        let start = self.now()?;
        let request = LeaseRequest {
            manifest_digest: self.trust.digest.clone(),
            identity: self.identity.clone(),
            boot_id: self.id,
            attempt_id: Uuid::new_v4(),
            purpose: self.purpose,
        };
        Ok(LeaseAttempt {
            boot: self.clone(),
            start,
            request,
        })
    }
}

/// No Deserialize or public constructor. Clones retain the exact original clock
/// anchor, boot and attempt nonce and therefore cannot extend a grant.
#[derive(Clone)]
pub struct LeaseAttempt {
    boot: ServingBoot,
    start: Duration,
    request: LeaseRequest,
}
impl LeaseAttempt {
    pub fn request(&self) -> &LeaseRequest {
        &self.request
    }
    pub fn verify(&self, signed: SignedLease) -> Result<VerifiedLease> {
        let claims = &signed.claims;
        let trust = &self.boot.trust;
        ensure!(
            claims.request == self.request
                && claims.authority_id == trust.manifest.authority_id
                && claims.partition == trust.manifest.partition(&self.request.identity.tenant)?
                && claims.lifetime_ms == trust.manifest.max_lease_ms
                && claims.credential_lifetime_ms > 0
                && claims.credential_lifetime_ms <= claims.lifetime_ms
                && claims.authority_revision > 0,
            "lease receiver, attempt, installation or lifetime differs"
        );
        kasumi_types::validate_sha256(&claims.activation_digest)?;
        if let Some(checkpoint) = &claims.recovery_checkpoint {
            checkpoint.validate()?;
            ensure!(
                checkpoint.tenant == claims.request.identity.tenant
                    && checkpoint.source_incarnation
                        != claims.request.identity.incarnation.to_string(),
                "lease recovery checkpoint differs"
            );
        }
        ensure!(
            (claims.request.identity.authority_epoch == 1) == claims.recovery_checkpoint.is_none(),
            "lease activation origin absent or unexpected"
        );
        trust.verify(
            claims.partition,
            "kasumi.serving-lease.v1",
            claims,
            &signed.signature,
        )?;
        let deadline = self
            .start
            .checked_add(Duration::from_millis(claims.credential_lifetime_ms))
            .context("serving deadline overflow")?;
        let proof = VerifiedLease {
            boot: self.boot.clone(),
            start: self.start,
            deadline,
            signed,
        };
        proof.check()?;
        Ok(proof)
    }
}

#[derive(Clone)]
pub struct VerifiedLease {
    pub(crate) boot: ServingBoot,
    pub(crate) start: Duration,
    pub(crate) deadline: Duration,
    pub(crate) signed: SignedLease,
}
impl VerifiedLease {
    pub fn identity(&self) -> &ServingIdentity {
        &self.signed.claims.request.identity
    }
    pub fn activation_digest(&self) -> &str {
        &self.signed.claims.activation_digest
    }
    pub fn check(&self) -> Result<()> {
        ensure!(self.boot.now()? < self.deadline, "serving grant expired");
        Ok(())
    }
}
/// Immutable signed evidence of an accepted replacement; it is not a renewable
/// serving lease. Materialization still requires a fresh matching lease.
#[derive(Clone)]
pub struct VerifiedActivation {
    signed: SignedAuthorityReceipt,
}
impl VerifiedActivation {
    pub fn receipt(&self) -> &AuthorityReceipt {
        &self.signed.receipt
    }
    pub fn digest(&self) -> Result<String> {
        self.signed.receipt.digest()
    }
}
