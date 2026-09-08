//! Immutable target attestations. Signatures prove exact native facts, never a
//! current serving lease. Expected origin must come from the installed command.
use anyhow::{Result, ensure};
use kasumi_types::{SignedTargetCompletion, SignedTargetMaterialization, TargetOrigin};
use ring::signature;
use std::collections::BTreeMap;

fn verify<T: serde::Serialize>(key: &str, domain: &str, value: &T, signed: &str) -> Result<()> {
    let public = hex::decode(key)?;
    let signature = hex::decode(signed)?;
    signature::UnparsedPublicKey::new(&signature::ED25519, public)
        .verify(&serde_json::to_vec(&(domain, value))?, &signature)
        .map_err(|_| anyhow::anyhow!("installed target attestation signature invalid"))
}
/// Check the exhaustive three original materializations before creating initial
/// membership. Repeating a DTO or one node's signature cannot fill another slot.
pub fn verify_target_materializations(
    expected: &TargetOrigin,
    facts: &BTreeMap<u64, SignedTargetMaterialization>,
) -> Result<String> {
    expected.validate()?;
    ensure!(
        facts.len() == 3 && facts.keys().eq(expected.input.voters.keys()),
        "complete installed target materialization set required"
    );
    let mut bootstrap = None;
    for (node, signed) in facts {
        signed.fact.validate()?;
        ensure!(
            signed.fact.origin == *expected && signed.fact.node_id == *node,
            "target materialization origin or node differs"
        );
        if let Some(hash) = bootstrap {
            ensure!(
                hash == signed.fact.bootstrap_sha256,
                "target bootstrap bytes disagree"
            );
        } else {
            bootstrap = Some(signed.fact.bootstrap_sha256.as_str());
        }
        let installed = expected
            .materialization
            .request
            .target_nodes
            .get(node)
            .ok_or_else(|| anyhow::anyhow!("target signer not installed"))?;
        verify(
            &installed.attestation_public_key,
            "kasumi.materialized-target.v1",
            &signed.fact,
            &signed.signature,
        )?;
    }
    Ok(bootstrap.expect("three checked materializations").into())
}
#[derive(Clone)]
pub struct AuthenticatedTargetCompletion {
    signed: SignedTargetCompletion,
}
impl AuthenticatedTargetCompletion {
    pub fn signed(&self) -> &SignedTargetCompletion {
        &self.signed
    }
}
/// Permanent completion fact only. Issuer target/epoch stops and fresh phase
/// grants must still independently permit any activation or cleanup effect.
pub fn verify_target_completion(
    expected: &TargetOrigin,
    signed: &SignedTargetCompletion,
) -> Result<AuthenticatedTargetCompletion> {
    signed.observation.validate()?;
    ensure!(
        signed.observation.fact.origin == *expected,
        "completed target origin differs"
    );
    let bootstrap =
        verify_target_materializations(expected, &signed.observation.fact.materialized)?;
    ensure!(
        bootstrap == signed.observation.fact.bootstrap_sha256,
        "completion bootstrap differs from prepared replicas"
    );
    let installed = expected
        .materialization
        .request
        .target_nodes
        .get(&signed.observation.observer_node_id)
        .ok_or_else(|| anyhow::anyhow!("completion signer not installed"))?;
    verify(
        &installed.attestation_public_key,
        "kasumi.completed-target-observation.v1",
        &signed.observation,
        &signed.signature,
    )?;
    Ok(AuthenticatedTargetCompletion {
        signed: signed.clone(),
    })
}

#[derive(Clone)]
pub struct AuthenticatedTargetInspection {
    signed: kasumi_types::SignedTargetInspection,
}
impl AuthenticatedTargetInspection {
    pub fn signed(&self) -> &kasumi_types::SignedTargetInspection {
        &self.signed
    }
}
/// Historical metadata only, with a separate signature domain and proof type.
/// No conversion into a completion, activation, stop or renewable lease exists.
pub fn verify_target_inspection(
    expected: &kasumi_types::TargetInspectionInput,
    signed: &kasumi_types::SignedTargetInspection,
) -> Result<AuthenticatedTargetInspection> {
    signed.observation.validate()?;
    ensure!(
        signed.observation.input == *expected,
        "target inspection identity differs"
    );
    let origin = &signed.observation.completion.origin;
    let bootstrap = verify_target_materializations(origin, &expected.quorum.materialized)?;
    ensure!(
        bootstrap == signed.observation.completion.bootstrap_sha256,
        "inspected target bootstrap differs"
    );
    let installed = origin
        .materialization
        .request
        .target_nodes
        .get(&signed.observation.observer_node_id)
        .ok_or_else(|| anyhow::anyhow!("inspection signer not installed"))?;
    verify(
        &installed.attestation_public_key,
        "kasumi.inspected-target-observation.v1",
        &signed.observation,
        &signed.signature,
    )?;
    Ok(AuthenticatedTargetInspection {
        signed: signed.clone(),
    })
}

#[derive(Clone)]
pub struct AuthenticatedTargetActivation {
    signed: kasumi_types::SignedTargetActivation,
}
impl AuthenticatedTargetActivation {
    pub fn signed(&self) -> &kasumi_types::SignedTargetActivation {
        &self.signed
    }
}
pub fn verify_target_activation(
    expected: &TargetOrigin,
    signed: &kasumi_types::SignedTargetActivation,
) -> Result<AuthenticatedTargetActivation> {
    signed.observation.validate()?;
    ensure!(
        signed.observation.completion.origin == *expected,
        "activated target origin differs"
    );
    verify_target_materializations(expected, &signed.observation.completion.materialized)?;
    let node = expected
        .materialization
        .request
        .target_nodes
        .get(&signed.observation.observer_node_id)
        .ok_or_else(|| anyhow::anyhow!("activation signer not installed"))?;
    verify(
        &node.attestation_public_key,
        "kasumi.activated-target-observation.v1",
        &signed.observation,
        &signed.signature,
    )?;
    Ok(AuthenticatedTargetActivation {
        signed: signed.clone(),
    })
}

pub fn verify_target_materialization(
    expected: &TargetOrigin,
    node_id: u64,
    signed: &kasumi_types::SignedTargetMaterialization,
) -> Result<()> {
    signed.fact.validate()?;
    ensure!(
        signed.fact.origin == *expected && signed.fact.node_id == node_id,
        "materialization identity differs"
    );
    let node = expected
        .materialization
        .request
        .target_nodes
        .get(&node_id)
        .ok_or_else(|| anyhow::anyhow!("materialization signer missing"))?;
    verify(
        &node.attestation_public_key,
        "kasumi.materialized-target.v1",
        &signed.fact,
        &signed.signature,
    )
}
pub fn verify_local_target_cleanup(
    trust: &crate::AuthorityTrust,
    expected: &kasumi_types::LifecycleIntent,
    node_id: u64,
    signed: &crate::SignedLocalTargetCleanup,
) -> Result<()> {
    signed.fact.validate()?;
    ensure!(
        signed.fact.intent == *expected && signed.fact.node_id == node_id,
        "local cleanup identity differs"
    );
    ensure!(
        expected.request.authority_partition
            == trust
                .manifest()
                .control_partition(trust.manifest().partition(&expected.request.tenant)?)?
                .key(),
        "cleanup issuer differs"
    );
    trust.verify_target_stop(
        signed.fact.stopped.clone(),
        &signed.fact.stopped.observation.reference,
    )?;
    let node = expected
        .request
        .target_nodes
        .get(&node_id)
        .ok_or_else(|| anyhow::anyhow!("cleanup signer missing"))?;
    verify(
        &node.attestation_public_key,
        "kasumi.local-target-cleanup.v1",
        &signed.fact,
        &signed.signature,
    )
}
