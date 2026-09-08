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

/// Authenticate a permanent completion through its original observation or a
/// separately signed inspection of the exact original fact. This proof grants
/// neither mutation authority nor a renewed original phase deadline.
pub fn verify_committed_completion(
    expected: &TargetOrigin,
    proof: &kasumi_types::CommittedCompletion,
) -> Result<()> {
    proof.validate()?;
    ensure!(
        proof.fact().origin == *expected,
        "resolved completion origin differs"
    );
    match proof {
        kasumi_types::CommittedCompletion::Original(signed) => {
            verify_target_completion(expected, signed)?;
        }
        kasumi_types::CommittedCompletion::Resolved(signed) => {
            verify_target_inspection(&signed.observation.input, signed)?;
        }
    }
    Ok(())
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
/// An explicit CommittedCompletion::Resolved may consume a positive original
/// completion observation. It never converts the signature or creates a lease.
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

/// Verify retained physical cleanup against the exact committed issuer
/// partition. This returns historical evidence only and cannot create a lease
/// or a live cleanup capability from a Control journal record.
pub fn verify_local_target_cleanup_history(
    partition: &kasumi_types::ControlAuthorityPartition,
    expected: &kasumi_types::LifecycleIntent,
    node_id: u64,
    reference: &crate::TargetStopReference,
    signed: &crate::SignedLocalTargetCleanup,
) -> Result<()> {
    use kasumi_types::{AuthorityAction, AuthorityOutcome, SigningDomain};
    partition.validate()?;
    signed.fact.validate()?;
    reference.validate()?;
    let observation = &signed.fact.stopped.observation;
    let receipt = &observation.stop;
    receipt.command.validate()?;
    ensure!(
        signed.fact.intent == *expected
            && signed.fact.node_id == node_id
            && observation.reference == *reference
            && expected.request.authority_partition == partition.key()
            && receipt.command.tenant == expected.request.tenant
            && receipt.authority_id == partition.authority_id
            && receipt.manifest_digest == partition.manifest_sha256
            && receipt.partition == partition.partition
            && receipt.revision > 0
            && receipt.term > 0
            && receipt.command_digest == receipt.command.digest()?
            && observation.observed_revision >= receipt.revision
            && observation.observed_term >= receipt.term
            && observation.drain_ms == partition.drain_ms,
        "retained physical cleanup issuer, original phase, or complete drain differs"
    );
    ensure!(
        matches!((&receipt.command.action,&receipt.outcome),
        (AuthorityAction::StopTarget {source_incarnation,source_epoch,target},AuthorityOutcome::TargetStopped {source_incarnation:actual_source,source_epoch:actual_epoch,target:actual})
        if source_incarnation==actual_source && source_epoch==actual_epoch && target==actual
            && target.nodes == expected.request.target_nodes.values().map(|node| kasumi_types::NodeIdentity {
                node_id: node.node_id, verifier: node.verifier.clone(), principal: node.principal.clone(), certificate_sha256: node.certificate_sha256.clone()
            }).collect()),
        "retained cleanup lacks exact permanent target stop"
    );
    crate::HistoricalSigningTrust::install(SigningDomain {
        authority_id: partition.authority_id,
        partition: partition.partition,
        manifest_sha256: partition.manifest_sha256.clone(),
        root_public_key: partition.signing_public_key.clone(),
        retirement_drain_ms: partition.drain_ms,
    })?
    .verify(
        "kasumi.target-stop-drained.v1",
        observation,
        &signed.fact.stopped.signature,
    )?;
    let node = expected
        .request
        .target_nodes
        .get(&node_id)
        .ok_or_else(|| anyhow::anyhow!("retained cleanup target signer absent"))?;
    verify(
        &node.attestation_public_key,
        "kasumi.local-target-cleanup.v1",
        &signed.fact,
        &signed.signature,
    )
}

#[derive(Clone)]
pub struct AuthenticatedTargetCompletionAttempt {
    signed: kasumi_types::SignedTargetCompletionAttempt,
}
impl AuthenticatedTargetCompletionAttempt {
    pub fn signed(&self) -> &kasumi_types::SignedTargetCompletionAttempt {
        &self.signed
    }
}
/// Authenticate a committed original capacity reservation. This historical
/// proof does not extend its dispatch cap or authorize a target phase.
pub fn verify_target_completion_attempt(
    expected: &TargetOrigin,
    signed: &kasumi_types::SignedTargetCompletionAttempt,
) -> Result<AuthenticatedTargetCompletionAttempt> {
    signed.observation.validate()?;
    let attempt = &signed.observation.attempt;
    ensure!(
        attempt.origin == *expected,
        "prepared completion target differs"
    );
    verify_target_materializations(expected, &attempt.input.quorum.materialized)?;
    let installed = expected
        .materialization
        .request
        .target_nodes
        .get(&signed.observation.observer_node_id)
        .ok_or_else(|| anyhow::anyhow!("prepared completion observer is not installed"))?;
    verify(
        &installed.attestation_public_key,
        "kasumi.prepared-target-completion-observation.v1",
        &signed.observation,
        &signed.signature,
    )?;
    Ok(AuthenticatedTargetCompletionAttempt {
        signed: signed.clone(),
    })
}

#[derive(Clone)]
pub struct AuthenticatedTargetCompletionResolution {
    signed: kasumi_types::SignedTargetCompletionResolution,
}
impl AuthenticatedTargetCompletionResolution {
    pub fn signed(&self) -> &kasumi_types::SignedTargetCompletionResolution {
        &self.signed
    }
}
/// A sealed outcome proves an actual permanent target transition over one
/// exact prepared attempt. Missing facts never enter this proof type. Current
/// Control and issuer admission are independently required for a successor.
pub fn verify_target_completion_resolution(
    expected: &TargetOrigin,
    signed: &kasumi_types::SignedTargetCompletionResolution,
) -> Result<AuthenticatedTargetCompletionResolution> {
    signed.observation.validate()?;
    let fact = &signed.observation.fact;
    ensure!(
        fact.input.attempt.origin == *expected,
        "resolved completion target differs"
    );
    let bootstrap =
        verify_target_materializations(expected, &fact.input.attempt.input.quorum.materialized)?;
    if let kasumi_types::TargetCompletionTerminal::Committed(completion) = &fact.terminal {
        ensure!(
            completion.bootstrap_sha256 == bootstrap,
            "resolved committed completion changed its prepared bootstrap"
        );
    }
    let installed = expected
        .materialization
        .request
        .target_nodes
        .get(&signed.observation.observer_node_id)
        .ok_or_else(|| anyhow::anyhow!("terminal completion observer is not installed"))?;
    verify(
        &installed.attestation_public_key,
        "kasumi.resolved-target-completion-observation.v1",
        &signed.observation,
        &signed.signature,
    )?;
    Ok(AuthenticatedTargetCompletionResolution {
        signed: signed.clone(),
    })
}

#[derive(Clone)]
pub struct AuthenticatedTargetResolutionBudget {
    signed: kasumi_types::SignedTargetResolutionBudget,
}
impl AuthenticatedTargetResolutionBudget {
    pub fn signed(&self) -> &kasumi_types::SignedTargetResolutionBudget {
        &self.signed
    }
}
/// Exact permanent maintenance outcome only. Re-observing an old increase does
/// not reapply that increase or overwrite a later authorized budget change.
pub fn verify_target_resolution_budget(
    expected: &TargetOrigin,
    signed: &kasumi_types::SignedTargetResolutionBudget,
) -> Result<AuthenticatedTargetResolutionBudget> {
    signed.observation.validate()?;
    ensure!(
        signed.observation.fact.origin == *expected,
        "target budget origin differs"
    );
    let installed = expected
        .materialization
        .request
        .target_nodes
        .get(&signed.observation.observer_node_id)
        .ok_or_else(|| anyhow::anyhow!("target budget observer is not installed"))?;
    verify(
        &installed.attestation_public_key,
        "kasumi.target-resolution-budget-observation.v1",
        &signed.observation,
        &signed.signature,
    )?;
    Ok(AuthenticatedTargetResolutionBudget {
        signed: signed.clone(),
    })
}
