//! Independently keyed evidence of an actual local committed activation. This
//! never reconstructs a live phase or serving lease from retained metadata.
use super::*;
use crate::{TargetSigner, VerifiedTargetActivation, VerifiedTargetInspection};
use kasumi_serving::{
    AuthorityManifest, AuthorityTrust, LeasePurpose, ServingGate, SignedLifecycleLease,
};
use kasumi_types::{
    SignedTargetActivation, SignedTargetInspection, TargetActivationFact, TargetCompletionFact,
    TargetExecutionState,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Observation {
    Activated(Box<SignedTargetActivation>),
    Inspected(Box<SignedTargetInspection>),
}
impl Observation {
    fn facts(&self) -> Result<(&TargetCompletionFact, &TargetActivationFact)> {
        match self {
            Self::Activated(s) => Ok((&s.observation.completion, &s.observation.activation)),
            Self::Inspected(s) => Ok((
                &s.observation.completion,
                s.observation
                    .activation
                    .as_ref()
                    .context("inspection did not observe activation")?,
            )),
        }
    }
    fn node(&self) -> u64 {
        match self {
            Self::Activated(s) => s.observation.observer_node_id,
            Self::Inspected(s) => s.observation.observer_node_id,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActivationProjection {
    intent: TargetJournalIntent,
    authority: AuthorityManifest,
    original_lease: SignedLifecycleLease,
    observation: Observation,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServingCandidate {
    tenant: String,
    incarnation: Uuid,
    source_epoch: u64,
    projection_sha256: String,
}
/// Opaque, journal-bound historical evidence. Every application opener must
/// still require a fresh exact ServingGate and validate actual local state.
/// There is intentionally no Deserialize or constructor from wire observations.
pub struct VerifiedTargetServingProjection {
    journal: Arc<TargetJournal>,
    record: ActivationProjection,
}
impl VerifiedTargetServingProjection {
    pub fn tenant(&self) -> &str {
        &self.record.intent.intent.request.tenant
    }
    pub fn target_incarnation(&self) -> Uuid {
        self.record.intent.intent.request.target_incarnation
    }
    pub fn execution(&self) -> Result<TargetExecutionState> {
        let (completed, activated) = self.record.observation.facts()?;
        Ok(TargetExecutionState {
            origin: completed.origin.clone(),
            completion: Some(completed.clone()),
            activation: Some(activated.clone()),
        })
    }
    /// Checks only current exposure eligibility. Historical original phase
    /// expiry is preserved in the record and is never turned into a live grant.
    pub fn check(&self, gate: &ServingGate) -> Result<()> {
        gate.check()?;
        ensure!(!gate.is_prepared()?, "prepared target cannot serve data");
        let r = &self.record.intent.intent.request;
        let identity = gate.identity();
        ensure!(
            gate.authority_digest() == self.record.authority.digest()?
                && identity.tenant == r.tenant
                && identity.incarnation == r.target_incarnation
                && identity.authority_epoch
                    == r.source_authority_epoch
                        .checked_add(1)
                        .context("target epoch exhausted")?
                && identity.node == self.journal.installed.node
                && gate.recovery_checkpoint()?.as_ref() == Some(&r.checkpoint)
                && gate.activation_digest()?
                    == self.record.observation.facts()?.1.issuer_receipt_sha256,
            "fresh serving authority differs from exact committed target"
        );
        let _workspace = self
            .journal
            .admission
            .reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .journal
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let key = activation_key(&r.tenant, r.target_incarnation);
        let bytes = self
            .journal
            .store
            .get_bounded(NS, &key, MAX_RECORD)?
            .context("activation projection disappeared")?;
        let current = self.journal.validate_projection_record(&key, &bytes)?;
        ensure!(
            serde_json::to_vec(&current)? == serde_json::to_vec(&self.record)?,
            "immutable activation projection changed"
        );
        self.journal
            .require_unstopped(&r.tenant, r.target_incarnation)?;
        gate.check()
    }
    pub fn storage_access(&self, gate: Arc<ServingGate>) -> Result<kasumi_store::StorageAccess> {
        self.check(&gate)?;
        kasumi_store::StorageAccess::serving(gate)
    }
}
impl TargetJournal {
    fn require_unstopped(&self, tenant: &str, incarnation: Uuid) -> Result<()> {
        ensure!(
            self.store
                .get_bounded(NS, &stop_key(tenant, incarnation), MAX_RECORD)?
                .is_none(),
            "target incarnation permanently stopped locally"
        );
        Ok(())
    }
    pub(super) fn decode_projection_record(
        &self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<ActivationProjection> {
        ensure!(
            bytes.len() <= MAX_RECORD - 4096,
            "activation projection exceeds reservation"
        );
        let p: ActivationProjection = serde_json::from_slice(bytes)?;
        self.validate_intent(&p.intent)?;
        let i = &p.intent.intent;
        ensure!(
            key == activation_key(&i.request.tenant, i.request.target_incarnation),
            "activation projection key differs"
        );
        let trust = AuthorityTrust::install(p.authority.clone())?;
        trust.verify_lifecycle_claims(&p.original_lease)?;
        let claims = &p.original_lease.claims;
        ensure!(
            claims.commitment.root == self.installed.root
                && claims.commitment.intent == *i
                && claims.commitment.authority_partition == p.intent.authority_partition
                && claims.commitment.partition_set_sha256 == p.intent.partition_set_sha256
                && claims.request.target_node == self.installed.node
                && claims.application_purpose == Some(LeasePurpose::Serving)
                && p.observation.node() == self.installed.node.node_id,
            "activation projection original issuer/control/node differs"
        );
        let (completion, activation) = p.observation.facts()?;
        match &p.observation {
            Observation::Activated(s) => {
                kasumi_serving::verify_target_activation(&completion.origin, s)?;
                completion
                    .origin
                    .accepts_phase(i, LifecyclePhase::Activate)?;
                ensure!(
                    i.request.phase_input_sha256 == activation.intent.request.phase_input_sha256,
                    "activation projection original effect differs"
                );
            }
            Observation::Inspected(s) => {
                kasumi_serving::verify_target_inspection(&s.observation.input, s)?;
                ensure!(
                    s.observation.inspection_intent == *i
                        && s.observation.input.original_phase == activation.intent,
                    "serving recovery must inspect exact original activation"
                );
            }
        }
        Ok(p)
    }
    pub(super) fn validate_projection_record(
        &self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<ActivationProjection> {
        let p = self.decode_projection_record(key, bytes)?;
        let i = &p.intent.intent;
        let binding = GenerationBinding::from_intent(&p.intent);
        let generation = self
            .store
            .get_bounded(
                NS,
                &generation_key(&binding.tenant, binding.target_incarnation),
                MAX_RECORD,
            )?
            .context("projection generation reservation missing")?;
        ensure!(
            serde_json::from_slice::<GenerationBinding>(&generation)? == binding,
            "projection generation binding changed"
        );
        let retained = self
            .store
            .get_bounded(NS, &intent_key(i.request.command_id), MAX_RECORD)?
            .context("projection original phase reservation missing")?;
        ensure!(
            serde_json::from_slice::<TargetJournalIntent>(&retained)? == p.intent,
            "projection original intent differs"
        );
        Ok(p)
    }
    fn publish_projection(
        self: &Arc<Self>,
        op: &TargetOperation,
        observation: Observation,
    ) -> Result<VerifiedTargetServingProjection> {
        let _workspace = self
            .admission
            .reserve((MAX_RECORD * 8) as u64, Some(op.token.clone()))?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let intent = self.intent(op)?;
        let lease = op.invocation().gate().current()?;
        let r = &intent.intent.request;
        self.require_unstopped(&r.tenant, r.target_incarnation)?;
        let key = activation_key(&r.tenant, r.target_incarnation);
        let record = ActivationProjection {
            intent,
            authority: lease.authority().manifest().clone(),
            original_lease: lease.signed().clone(),
            observation,
        };
        let bytes = serde_json::to_vec(&record)?;
        self.validate_projection_record(&key, &bytes)?;
        let record = if let Some(old) = self.store.get_bounded(NS, &key, MAX_RECORD)? {
            let old = self.validate_projection_record(&key, &old)?;
            ensure!(
                old.observation.facts()? == record.observation.facts()?,
                "target has another committed activation"
            );
            old
        } else {
            // Capacity was charged before physical effects, distinct from stop
            // headroom. Publication does not spend another command identity.
            self.metadata()?;
            op.check()?;
            let r = &record.intent.intent.request;
            let candidate = ServingCandidate {
                tenant: r.tenant.clone(),
                incarnation: r.target_incarnation,
                source_epoch: r.source_authority_epoch,
                projection_sha256: kasumi_serving::digest(&record)?,
            };
            let candidate_key = candidate_key(&r.tenant);
            if let Some(old) = self.store.get_bounded(NS, &candidate_key, 4096)? {
                let old = self.decode_serving_candidate(&candidate_key, &old)?;
                ensure!(
                    old.source_epoch < candidate.source_epoch || old == candidate,
                    "serving candidate cannot replace a newer or same-epoch incarnation"
                );
            }
            let candidate_bytes = serde_json::to_vec(&candidate)?;
            ensure!(
                candidate_bytes.len() <= 4096,
                "serving candidate exceeds reserved metadata"
            );
            self.store
                .write_batch(&[
                    WriteOp::put(NS, key.as_slice(), bytes),
                    WriteOp::put(NS, candidate_key, candidate_bytes),
                ])
                .map_err(journal_unknown)?;
            record
        };
        op.check().map_err(journal_unknown)?;
        Ok(VerifiedTargetServingProjection {
            journal: self.clone(),
            record,
        })
    }
    pub async fn record_activation(
        self: &Arc<Self>,
        op: &TargetOperation,
        proof: &VerifiedTargetActivation,
        signer: &TargetSigner,
    ) -> Result<VerifiedTargetServingProjection> {
        let signed = signer.sign_activated(proof, op).await?;
        let projection = self.publish_projection(op, Observation::Activated(Box::new(signed)))?;
        proof.release(op).await.map_err(journal_unknown)?;
        Ok(projection)
    }
    pub async fn record_inspected_activation(
        self: &Arc<Self>,
        op: &TargetOperation,
        proof: &VerifiedTargetInspection,
        signer: &TargetSigner,
    ) -> Result<VerifiedTargetServingProjection> {
        let signed = signer.sign_inspection(proof, op).await?;
        let projection = self.publish_projection(op, Observation::Inspected(Box::new(signed)))?;
        proof.release(op).await.map_err(journal_unknown)?;
        Ok(projection)
    }
    pub(super) fn decode_serving_candidate(
        &self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<ServingCandidate> {
        ensure!(
            bytes.len() <= 4096,
            "serving candidate exceeds reserved metadata"
        );
        let c: ServingCandidate = serde_json::from_slice(bytes)?;
        kasumi_types::validate_name(&c.tenant)?;
        kasumi_types::validate_sha256(&c.projection_sha256)?;
        ensure!(
            !c.incarnation.is_nil() && c.source_epoch > 0 && key == candidate_key(&c.tenant),
            "serving candidate identity differs"
        );
        Ok(c)
    }
    /// Bounded point discovery per installed tenant, independent of retained
    /// historical generation count. A candidate is only a hint until a fresh
    /// exact issuer ServingGate and actual local state are checked.
    pub fn serving_candidate(self: &Arc<Self>, tenant: &str) -> Result<Option<Uuid>> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let key = candidate_key(tenant);
        let Some(bytes) = self.store.get_bounded(NS, &key, 4096)? else {
            return Ok(None);
        };
        let c = self.decode_serving_candidate(&key, &bytes)?;
        if self
            .store
            .get_bounded(NS, &stop_key(tenant, c.incarnation), MAX_RECORD)?
            .is_some()
        {
            return Ok(None);
        }
        let key = activation_key(tenant, c.incarnation);
        let projection = self
            .store
            .get_bounded(NS, &key, MAX_RECORD)?
            .context("candidate activation projection absent")?;
        let record = self.validate_projection_record(&key, &projection)?;
        ensure!(
            kasumi_serving::digest(&record)? == c.projection_sha256
                && record.intent.intent.request.source_authority_epoch == c.source_epoch,
            "candidate substituted activation projection"
        );
        Ok(Some(c.incarnation))
    }
    /// Installed startup discovery reads only independently encrypted metadata.
    /// Absence is non-serving and cannot be converted into an implicit restore.
    pub fn serving_projection(
        self: &Arc<Self>,
        tenant: &str,
        incarnation: Uuid,
    ) -> Result<Option<VerifiedTargetServingProjection>> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        self.require_unstopped(tenant, incarnation)?;
        let key = activation_key(tenant, incarnation);
        let Some(bytes) = self.store.get_bounded(NS, &key, MAX_RECORD)? else {
            return Ok(None);
        };
        let record = self.validate_projection_record(&key, &bytes)?;
        Ok(Some(VerifiedTargetServingProjection {
            journal: self.clone(),
            record,
        }))
    }
}
fn activation_key(tenant: &str, incarnation: Uuid) -> Vec<u8> {
    format!("activation/{tenant}/{incarnation}").into_bytes()
}

fn candidate_key(tenant: &str) -> Vec<u8> {
    format!("serving/{tenant}").into_bytes()
}
