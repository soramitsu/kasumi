//! Live phase capabilities retain a pre-dispatch suspend-aware anchor. Wire
//! signatures prove immutable issuer facts; decoding cannot create elapsed time.
use crate::*;
use anyhow::{Context, Result, ensure};
use kasumi_clock::{LeaseClock, SystemLeaseClock};
use kasumi_types::{ControlIntentCommitment, ControlSigningRoot};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

impl AuthorityTrust {
    pub fn verify_lifecycle_receipt(
        &self,
        signed: &SignedLifecycleAuthorityReceipt,
        expected: &LifecycleAuthorityReference,
    ) -> Result<()> {
        signed
            .receipt
            .validate(self.manifest(), signed.receipt.partition)?;
        ensure!(
            signed.receipt.reference == *expected,
            "issuer lifecycle receipt reference differs"
        );
        self.verify(
            signed.receipt.partition,
            "kasumi.issuer-control-receipt.v1",
            &signed.receipt,
            &signed.signature,
        )
    }
    /// Immutable verification for deterministic replica checks. This cannot
    /// construct a live gate or renew a phase from a serialized record.
    pub fn verify_lifecycle_claims(&self, signed: &SignedLifecycleLease) -> Result<()> {
        let c = &signed.claims;
        c.request.validate()?;
        let i = &c.commitment.intent;
        i.request.validate()?;
        let root = ControlSigningRoot {
            control_incarnation: i.control_incarnation,
            public_key: self
                .manifest()
                .lifecycle_controls
                .get(&i.control_incarnation)
                .context("control root not installed")?
                .clone(),
        };
        let reference = LifecycleAuthorityReference {
            control_incarnation: i.control_incarnation,
            control_policy_epoch: i.request.expected_policy_epoch,
            identity: LifecycleAuthorityIdentity::Intent(i.request.command_id),
        };
        let partition = self.manifest().partition(&i.request.tenant)?;
        ensure!(
            c.authority_id == self.manifest().authority_id
                && c.partition == partition
                && c.request.authority_manifest_sha256 == self.digest()
                && c.request.reference == reference
                && c.commitment.root == root
                && c.commitment.authority_partition
                    == self.manifest().control_partition(partition)?
                && i.request.authority_partition == c.commitment.authority_partition.key()
                && i.request_sha256 == digest(&i.request)?
                && c.commitment.observed_policy_epoch == i.request.expected_policy_epoch
                && c.commitment.observed_revision >= i.revision
                && c.commitment.observed_term > 0
                && i.revision > 0
                && i.installation_generation > 0
                && i.accepted_at_ms < i.original_credential_expires_at_ms
                && c.authority_revision > 0
                && c.authority_term > 0
                && c.lifetime_ms == self.manifest().max_lease_ms
                && c.credential_lifetime_ms > 0
                && c.credential_lifetime_ms <= c.lifetime_ms,
            "phase capability installation, commitment or lifetime differs"
        );
        kasumi_types::validate_name(&i.original_principal)?;
        kasumi_types::validate_sha256(&c.commitment.partition_set_sha256)?;
        let identity =
            LifecycleAuthorityRequest::AcceptIntent(Box::new(kasumi_types::SignedControlIntent {
                observation: c.commitment.clone(),
                signature: String::new(),
            }));
        ensure!(
            identity.digest()? == c.request.intent_sha256,
            "phase capability intent digest differs"
        );
        let node = i
            .request
            .target_nodes
            .get(&c.request.target_node.node_id)
            .context("phase target node not approved")?;
        ensure!(
            node.principal == c.request.target_node.principal
                && node.certificate_sha256 == c.request.target_node.certificate_sha256,
            "phase capability target credential differs"
        );
        self.verify(partition, "kasumi.lifecycle-lease.v1", c, &signed.signature)
    }
}
#[derive(Clone)]
pub struct LifecycleBoot {
    trust: AuthorityTrust,
    node: NodeIdentity,
    boot_id: Uuid,
    clock: Arc<dyn LeaseClock>,
    last: Arc<Mutex<Option<Duration>>>,
}
impl LifecycleBoot {
    pub fn new(trust: AuthorityTrust, node: NodeIdentity) -> Result<Self> {
        Self::with_clock(trust, node, Arc::new(SystemLeaseClock))
    }
    pub fn with_clock(
        trust: AuthorityTrust,
        node: NodeIdentity,
        clock: Arc<dyn LeaseClock>,
    ) -> Result<Self> {
        node.validate()?;
        let now = clock.now();
        Ok(Self {
            trust,
            node,
            boot_id: Uuid::new_v4(),
            clock,
            last: Arc::new(Mutex::new(Some(now))),
        })
    }
    fn now(&self) -> Result<Duration> {
        let mut previous = self
            .last
            .lock()
            .map_err(|_| anyhow::anyhow!("phase clock poisoned"))?;
        let now = self.clock.now();
        if previous.is_none_or(|value| now < value) {
            *previous = None;
            anyhow::bail!("phase elapsed clock regressed; original boot closed");
        }
        *previous = Some(now);
        Ok(now)
    }
    pub fn begin(&self, intent: &VerifiedControlIntent) -> Result<LifecycleAttempt> {
        let request = LifecycleAuthorityRequest::AcceptIntent(Box::new(intent.signed().clone()));
        let partition = self
            .trust
            .manifest()
            .partition(&intent.observation().intent.request.tenant)?;
        self.trust
            .manifest()
            .verify_lifecycle_request(partition, &request)?;
        let node = intent
            .observation()
            .intent
            .request
            .target_nodes
            .get(&self.node.node_id)
            .context("phase target node not approved")?;
        ensure!(
            node.principal == self.node.principal
                && node.certificate_sha256 == self.node.certificate_sha256,
            "phase target credential differs"
        );
        Ok(LifecycleAttempt {
            boot: self.clone(),
            start: self.now()?,
            request: LifecycleLeaseRequest {
                authority_manifest_sha256: self.trust.digest().to_owned(),
                reference: request.reference(),
                intent_sha256: request.digest()?,
                target_node: self.node.clone(),
                boot_id: self.boot_id,
                attempt_id: Uuid::new_v4(),
            },
        })
    }
}
#[derive(Clone)]
pub struct LifecycleAttempt {
    boot: LifecycleBoot,
    start: Duration,
    request: LifecycleLeaseRequest,
}
impl LifecycleAttempt {
    pub fn request(&self) -> &LifecycleLeaseRequest {
        &self.request
    }
    pub fn verify(&self, signed: SignedLifecycleLease) -> Result<VerifiedLifecycleLease> {
        self.boot.trust.verify_lifecycle_claims(&signed)?;
        ensure!(
            signed.claims.request == self.request,
            "phase response from another attempt or boot"
        );
        let deadline = self
            .start
            .checked_add(Duration::from_millis(signed.claims.credential_lifetime_ms))
            .context("phase deadline overflow")?;
        let proof = VerifiedLifecycleLease {
            boot: self.boot.clone(),
            deadline,
            signed,
        };
        proof.check()?;
        Ok(proof)
    }
}
#[derive(Clone)]
pub struct VerifiedLifecycleLease {
    boot: LifecycleBoot,
    deadline: Duration,
    signed: SignedLifecycleLease,
}
impl VerifiedLifecycleLease {
    pub fn check(&self) -> Result<()> {
        ensure!(self.boot.now()? < self.deadline, "phase grant expired");
        Ok(())
    }
    pub fn commitment(&self) -> &ControlIntentCommitment {
        &self.signed.claims.commitment
    }
    pub fn signed(&self) -> &SignedLifecycleLease {
        &self.signed
    }
}
