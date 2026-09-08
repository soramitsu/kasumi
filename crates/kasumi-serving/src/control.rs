//! Installed cryptographic control commitments. Verifiers never infer quorum
//! from a supplied DTO; signatures come from the closed native control signer.
use crate::digest;
use anyhow::{Result, ensure};
use kasumi_types::*;
use ring::signature::{ED25519, UnparsedPublicKey};
use std::collections::BTreeMap;

fn verify<T: serde::Serialize>(key: &str, domain: &str, value: &T, signature: &str) -> Result<()> {
    validate_sha256(key)?;
    let signature = hex::decode(signature)?;
    ensure!(signature.len() == 64, "invalid control signature length");
    UnparsedPublicKey::new(&ED25519, hex::decode(key)?)
        .verify(&serde_json::to_vec(&(domain, value))?, &signature)
        .map_err(|_| anyhow::anyhow!("control signature invalid"))
}

pub fn control_stop_for(
    change: &ControlPolicyChange,
    partition: &ControlAuthorityPartition,
) -> Result<ControlEpochStop> {
    change.request.validate()?;
    change.installation.validate()?;
    ensure!(
        change.request_sha256 == digest(&change.request)?
            && change.request.installation_sha256 == digest(&change.installation)?
            && change.installation.partitions.get(&partition.key()) == Some(partition),
        "control change or installed partition differs"
    );
    Ok(ControlEpochStop {
        control_incarnation: change.control_incarnation,
        control_policy_epoch: change.request.expected_policy_epoch,
        installation_sha256: change.request.installation_sha256.clone(),
        installation_generation: change.installation.generation,
        change_id: change.request.command_id,
        change_sha256: change.request_sha256.clone(),
        authority_partition: partition.clone(),
        partition_set_sha256: digest(&change.installation.partitions)?,
    })
}

#[derive(Debug, Clone)]
pub struct VerifiedControlEpochStop {
    observation: ControlEpochStopObservation,
}
impl VerifiedControlEpochStop {
    pub fn observation(&self) -> &ControlEpochStopObservation {
        &self.observation
    }
}

pub fn verify_control_epoch_stop(
    expected: &ControlEpochStop,
    signed: &SignedControlEpochStop,
) -> Result<VerifiedControlEpochStop> {
    expected.validate()?;
    let observation = &signed.observation;
    ensure!(
        observation.stop == *expected
            && observation.accepted_revision > 0
            && observation.accepted_term > 0
            && observation.observed_revision >= observation.accepted_revision
            && observation.observed_term >= observation.accepted_term
            && observation.drain_ms == expected.authority_partition.drain_ms,
        "control stop proof identity or drain differs"
    );
    let partition = &expected.authority_partition;
    crate::HistoricalSigningTrust::install(crate::SigningDomain {
        authority_id: partition.authority_id,
        partition: partition.partition,
        manifest_sha256: partition.manifest_sha256.clone(),
        root_public_key: partition.signing_public_key.clone(),
        retirement_drain_ms: partition.drain_ms,
    })?
    .verify(
        "kasumi.control-epoch-drained.v1",
        observation,
        &signed.signature,
    )?;
    Ok(VerifiedControlEpochStop {
        observation: observation.clone(),
    })
}

pub fn verify_control_epoch_stops(
    change: &ControlPolicyChange,
    stops: &BTreeMap<String, SignedControlEpochStop>,
) -> Result<()> {
    ensure!(
        stops.len() == change.installation.partitions.len(),
        "exhaustive control stop partition set missing"
    );
    for (key, partition) in &change.installation.partitions {
        let expected = control_stop_for(change, partition)?;
        verify_control_epoch_stop(
            &expected,
            stops
                .get(key)
                .ok_or_else(|| anyhow::anyhow!("installed authority stop absent"))?,
        )?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct VerifiedControlIntent {
    observation: ControlIntentCommitment,
    signed: SignedControlIntent,
}
impl VerifiedControlIntent {
    pub fn signed(&self) -> &SignedControlIntent {
        &self.signed
    }
    pub fn observation(&self) -> &ControlIntentCommitment {
        &self.observation
    }
}
#[derive(Debug, Clone)]
pub struct VerifiedControlChange {
    observation: ControlChangeCommitment,
    signed: SignedControlChange,
}
impl VerifiedControlChange {
    pub fn signed(&self) -> &SignedControlChange {
        &self.signed
    }
    pub fn observation(&self) -> &ControlChangeCommitment {
        &self.observation
    }
}
#[derive(Clone)]
pub struct ControlTrust {
    root: ControlSigningRoot,
}
impl ControlTrust {
    pub fn install(root: ControlSigningRoot) -> Result<Self> {
        root.validate()?;
        Ok(Self { root })
    }
    pub fn root(&self) -> &ControlSigningRoot {
        &self.root
    }
    pub fn verify_intent(&self, signed: &SignedControlIntent) -> Result<VerifiedControlIntent> {
        let observation = &signed.observation;
        let intent = &observation.intent;
        intent.request.validate()?;
        observation.root.validate()?;
        observation.authority_partition.validate()?;
        validate_sha256(&observation.partition_set_sha256)?;
        ensure!(
            observation.root == self.root
                && intent.control_incarnation == self.root.control_incarnation
                && intent.installation_generation > 0
                && intent.request_sha256 == digest(&intent.request)?
                && observation.observed_policy_epoch == intent.request.expected_policy_epoch
                && observation.observed_revision >= intent.revision
                && intent.revision > 0
                && observation.observed_term > 0
                && intent.accepted_at_ms < intent.original_credential_expires_at_ms
                && observation.authority_partition.key() == intent.request.authority_partition,
            "committed control intent identity differs"
        );
        validate_name(&intent.original_principal)?;
        verify(
            &self.root.public_key,
            "kasumi.committed-control-intent.v1",
            observation,
            &signed.signature,
        )?;
        Ok(VerifiedControlIntent {
            observation: observation.clone(),
            signed: signed.clone(),
        })
    }
    pub fn verify_change(&self, signed: &SignedControlChange) -> Result<VerifiedControlChange> {
        let observation = &signed.observation;
        observation.root.validate()?;
        observation.stop.validate()?;
        ensure!(
            observation.root == self.root
                && observation.stop.control_incarnation == self.root.control_incarnation
                && observation.observed_policy_epoch == observation.stop.control_policy_epoch
                && observation.accepted_revision > 0
                && observation.observed_revision >= observation.accepted_revision
                && observation.observed_term > 0,
            "committed control change identity differs"
        );
        verify(
            &self.root.public_key,
            "kasumi.committed-control-change.v1",
            observation,
            &signed.signature,
        )?;
        Ok(VerifiedControlChange {
            observation: observation.clone(),
            signed: signed.clone(),
        })
    }
}
