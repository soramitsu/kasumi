use crate::*;
use anyhow::{Context, Result, ensure};
use kasumi_clock::{LeaseClock, SystemLeaseClock};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

/// Operational signing owner. The installation root is never a runtime issuer.
pub struct AuthoritySigner(LiveGenerationSigner);
impl AuthoritySigner {
    pub fn new(owner: LiveGenerationSigner) -> Self {
        Self(owner)
    }
    pub fn certificate(&self) -> &SigningCertificate {
        self.0.certificate()
    }
    pub fn verifier_identity(&self) -> Result<TrustVerifierIdentity> {
        self.0.verifier_identity()
    }
    pub fn same_verifier_owner(&self, other: &Self) -> bool {
        self.0.same_verifier_owner(&other.0)
    }
    pub fn check(&self) -> Result<()> {
        self.0.check()
    }
    fn sign<T: serde::Serialize>(&self, purpose: &str, value: &T) -> Result<GenerationSignature> {
        let signed = self.0.sign(purpose, value)?;
        let wire = signed.signature().clone();
        signed.check()?;
        Ok(wire)
    }
    pub fn sign_lifecycle_receipt(
        &self,
        receipt: LifecycleAuthorityReceipt,
    ) -> Result<SignedLifecycleAuthorityReceipt> {
        let signature = self.sign("kasumi.issuer-control-receipt.v1", &receipt)?;
        Ok(SignedLifecycleAuthorityReceipt { receipt, signature })
    }
    pub fn sign_control_epoch_stop(
        &self,
        observation: kasumi_types::ControlEpochStopObservation,
    ) -> Result<kasumi_types::SignedControlEpochStop> {
        let signature = self.sign("kasumi.control-epoch-drained.v1", &observation)?;
        Ok(kasumi_types::SignedControlEpochStop {
            observation,
            signature,
        })
    }
    pub fn sign_lifecycle_lease(
        &self,
        claims: LifecycleLeaseClaims,
    ) -> Result<SignedLifecycleLease> {
        let signature = self.sign("kasumi.lifecycle-lease.v1", &claims)?;
        Ok(SignedLifecycleLease { claims, signature })
    }
    pub fn sign_lease(&self, claims: LeaseClaims) -> Result<SignedLease> {
        let signature = self.sign("kasumi.serving-lease.v1", &claims)?;
        Ok(SignedLease { claims, signature })
    }
    pub fn sign_target_stop(&self, observation: TargetStopObservation) -> Result<SignedTargetStop> {
        let signature = self.sign("kasumi.target-stop-drained.v1", &observation)?;
        Ok(SignedTargetStop {
            observation,
            signature,
        })
    }
    pub fn sign_receipt(&self, receipt: AuthorityReceipt) -> Result<SignedAuthorityReceipt> {
        let signature = self.sign("kasumi.authority-proof.v1", &receipt)?;
        Ok(SignedAuthorityReceipt { receipt, signature })
    }
}

#[derive(Clone)]
pub struct AuthorityTrust {
    manifest: Arc<AuthorityManifest>,
    digest: String,
    live: std::collections::BTreeMap<u16, Arc<LiveSignerTrust>>,
}
impl AuthorityTrust {
    /// Bind local background ownership to this exact installed partition owner.
    pub fn start_background_work(
        &self,
        partition: u16,
        install: impl FnOnce() -> Arc<dyn crate::LiveTrustBackgroundWork>,
    ) -> Result<()> {
        self.require_live_partition(partition)?
            .start_background_work(install)
    }
    pub fn install(manifest: AuthorityManifest) -> Result<Self> {
        manifest.validate()?;
        let digest = manifest.digest()?;
        Ok(Self {
            manifest: Arc::new(manifest),
            digest,
            live: Default::default(),
        })
    }
    /// Attach exact durable local owners. Installation-root verification alone
    /// cannot construct a serving or lifecycle lease.
    pub fn with_live_verifiers(
        mut self,
        live: std::collections::BTreeMap<u16, Arc<LiveSignerTrust>>,
    ) -> Result<Self> {
        ensure!(
            live.keys().eq(self.manifest.partitions.keys()),
            "exact complete local signer verifier set required"
        );
        let mut verifier = None;
        for (partition, owner) in &live {
            let current = owner.current()?;
            ensure!(
                current.active.identity.domain == self.manifest.signing_domain(*partition)?,
                "live verifier belongs to another installation"
            );
            ensure!(
                verifier
                    .as_ref()
                    .is_none_or(|identity| *identity == current.verifier),
                "authority partitions cannot mix physical verifier installations"
            );
            verifier = Some(current.verifier);
        }
        self.live = live;
        Ok(self)
    }
    pub fn verifier_identity(&self) -> Result<TrustVerifierIdentity> {
        let mut identity = None;
        for partition in self.manifest.partitions.keys() {
            let current = self.require_live_partition(*partition)?.current()?.verifier;
            ensure!(
                identity
                    .as_ref()
                    .is_none_or(|identity| *identity == current),
                "live physical verifier identity changed"
            );
            identity = Some(current);
        }
        identity.context("current durable verifier identity unavailable")
    }
    pub(crate) fn require_live_partition(&self, partition: u16) -> Result<&Arc<LiveSignerTrust>> {
        let owner = self
            .live
            .get(&partition)
            .context("current durable live signer verifier is not installed")?;
        owner.current()?;
        Ok(owner)
    }
    pub(crate) fn verify_live<T: serde::Serialize>(
        &self,
        partition: u16,
        purpose: &str,
        value: &T,
        signature: &GenerationSignature,
    ) -> Result<SignerGenerationFence> {
        self.require_live_partition(partition)?
            .verify_live(purpose, value, signature)
    }
    pub fn manifest(&self) -> &AuthorityManifest {
        &self.manifest
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn verify<T: serde::Serialize>(
        &self,
        partition: u16,
        domain: &str,
        value: &T,
        signature: &GenerationSignature,
    ) -> Result<()> {
        HistoricalSigningTrust::install(self.manifest.signing_domain(partition)?)?
            .verify(domain, value, signature)
    }
    pub fn verify_target_stop(
        &self,
        signed: SignedTargetStop,
        expected: &TargetStopReference,
    ) -> Result<VerifiedTargetStop> {
        let observation = &signed.observation;
        let receipt = &observation.stop;
        expected.validate()?;
        receipt.command.validate()?;
        ensure!(
            observation.reference == *expected
                && receipt.command.tenant == expected.tenant
                && receipt.authority_id == self.manifest.authority_id
                && receipt.manifest_digest == self.digest
                && receipt.partition == self.manifest.partition(&expected.tenant)?
                && receipt.revision > 0
                && receipt.command_digest == receipt.command.digest()?
                && observation.observed_revision >= receipt.revision
                && observation.observed_term >= receipt.term
                && observation.drain_ms == self.manifest.drain_ms()?,
            "target stop proof binding differs"
        );
        ensure!(
            matches!((&receipt.command.action,&receipt.outcome),
            (AuthorityAction::StopTarget {source_incarnation,source_epoch,target},AuthorityOutcome::TargetStopped {source_incarnation:actual_source,source_epoch:actual_epoch,target:actual}) if source_incarnation==actual_source && source_epoch==actual_epoch && target==actual),
            "target stop outcome differs"
        );
        self.verify(
            receipt.partition,
            "kasumi.target-stop-drained.v1",
            observation,
            &signed.signature,
        )?;
        Ok(VerifiedTargetStop::verified(signed))
    }
    pub fn verify_activation(&self, signed: SignedAuthorityReceipt) -> Result<VerifiedActivation> {
        self.verify_receipt(&signed)?;
        let receipt = &signed.receipt;
        match (&receipt.command.action, &receipt.outcome) {
            (
                AuthorityAction::Activate {
                    target: requested, ..
                }
                | AuthorityAction::ActivateCommitted {
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
        ensure!(
            identity.node.verifier == trust.verifier_identity()?,
            "serving boot physical verifier differs from installed live owner"
        );
        trust.require_live_partition(trust.manifest.partition(&identity.tenant)?)?;
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
        let signer = trust.verify_live(
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
            signer,
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
    signer: SignerGenerationFence,
}
impl VerifiedLease {
    /// Exact immutable signed input retained by an explicitly authorized local
    /// enrollment. This historical evidence does not create a new live grant.
    pub fn signed(&self) -> &SignedLease {
        &self.signed
    }
    pub fn identity(&self) -> &ServingIdentity {
        &self.signed.claims.request.identity
    }
    pub fn activation_digest(&self) -> &str {
        &self.signed.claims.activation_digest
    }
    /// Remaining verified authority on the original suspend-aware boot clock.
    pub fn remaining(&self) -> Result<Duration> {
        self.signer.check()?;
        let now = self.boot.now()?;
        ensure!(now < self.deadline, "serving grant expired");
        Ok(self.deadline - now)
    }
    pub fn check(&self) -> Result<()> {
        self.signer.check()?;
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
