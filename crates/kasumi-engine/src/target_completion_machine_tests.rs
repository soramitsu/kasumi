//! Pure ordered-transition regressions. These fixtures supply synthetic Raft
//! positions; native authorization and prefix publication are tested separately.
use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::BTreeMap;
use uuid::Uuid;

fn key(node: u64) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[u8::try_from(node).unwrap(); 32]).unwrap()
}
fn sign(value: &impl serde::Serialize, domain: &str, node: u64) -> String {
    hex::encode(
        key(node)
            .sign(&serde_json::to_vec(&(domain, value)).unwrap())
            .as_ref(),
    )
}
pub(crate) fn origin() -> TargetOrigin {
    let source = Uuid::from_u128(1);
    let target = Uuid::from_u128(2);
    let checkpoint = FullBackupCheckpoint {
        tenant: "documents".into(),
        source_incarnation: source.to_string(),
        revision: 10,
        resident_sha256: "11".repeat(32),
        backup_id: Uuid::from_u128(4),
        manifest_ciphertext_sha256: "22".repeat(32),
        key_lineage_digest: "33".repeat(32),
    };
    let input = TargetMaterializationInput {
        destination_alias: "backup".into(),
        backup_id: checkpoint.backup_id,
        source_purpose_sha256: "44".repeat(32),
        target_incarnation: target,
        voters: (1..=3)
            .map(|id| {
                (
                    id,
                    TargetPeer {
                        endpoint: format!("https://target-{id}:7400"),
                        failure_domain: format!("zone-{id}"),
                    },
                )
            })
            .collect(),
    };
    let request = CommitLifecycleIntent {
        command_id: Uuid::from_u128(5),
        expected_policy_epoch: 1,
        installation_sha256: "55".repeat(32),
        authority_partition: "authority/0".into(),
        tenant: checkpoint.tenant.clone(),
        source_incarnation: source,
        source_authority_epoch: 1,
        target_incarnation: target,
        checkpoint,
        target_nodes: (1..=3)
            .map(|id| {
                (
                    id,
                    LifecycleNode {
                        node_id: id,
                        verifier: TrustVerifierIdentity {
                            installation_id: Uuid::from_u128(100 + u128::from(id)),
                            node_id: id,
                        },
                        principal: format!("target-{id}"),
                        certificate_sha256: format!("{id:064x}"),
                        attestation_public_key: hex::encode(key(id).public_key().as_ref()),
                    },
                )
            })
            .collect(),
        phase: LifecyclePhase::Materialize,
        phase_input_sha256: input.digest().unwrap(),
        resume_origin: None,
    };
    let materialization = LifecycleIntent {
        request_sha256: staged_digest(&request).unwrap().0,
        request,
        control_incarnation: Uuid::from_u128(3),
        installation_generation: 1,
        original_principal: "operator".into(),
        original_credential_expires_at_ms: 1_000,
        accepted_at_ms: 100,
        revision: 2,
    };
    let value = TargetOrigin {
        authority_manifest_sha256: "66".repeat(32),
        materialization,
        input,
    };
    value.validate().unwrap();
    value
}
fn intent(
    origin: &TargetOrigin,
    phase: LifecyclePhase,
    input: String,
    revision: u64,
    accepted: u64,
    expires: u64,
) -> LifecycleIntent {
    let mut value = origin.materialization.clone();
    value.request.command_id = Uuid::from_u128(1_000 + u128::from(revision));
    value.request.phase = phase;
    value.request.phase_input_sha256 = input;
    value.request_sha256 = staged_digest(&value.request).unwrap().0;
    value.revision = revision;
    value.accepted_at_ms = accepted;
    value.original_credential_expires_at_ms = expires;
    value
}
fn position(index: u64) -> TargetCommitPosition {
    TargetCommitPosition {
        index,
        term: 1,
        leader_node_id: 1,
        command_sha256: format!("{index:064x}"),
    }
}
pub(crate) fn attempt(
    origin: &TargetOrigin,
    predecessor: Option<TargetCompletionResolutionReference>,
    control_revision: u64,
    index: u64,
    accepted: u64,
    cap: u64,
) -> TargetCompletionAttempt {
    let quorum = TargetQuorumInput {
        origin_sha256: origin.digest().unwrap(),
        materialized: (1..=3)
            .map(|node_id| {
                let fact = TargetMaterializationFact {
                    origin: origin.clone(),
                    node_id,
                    bootstrap_sha256: "77".repeat(32),
                    revision_base: origin.materialization.request.checkpoint.revision + 1,
                };
                (
                    node_id,
                    SignedTargetMaterialization {
                        signature: sign(&fact, "kasumi.materialized-target.v1", node_id),
                        fact,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
    };
    let input = TargetCompletionInput {
        quorum,
        predecessor,
    };
    let value = TargetCompletionAttempt {
        intent: intent(
            origin,
            LifecyclePhase::Complete,
            input.digest().unwrap(),
            control_revision,
            accepted,
            cap + 100,
        ),
        origin: origin.clone(),
        input,
        dispatch_not_after_ms: cap,
        admitted_at_ms: accepted + 10,
        revision: origin.materialization.request.checkpoint.revision + 1 + index,
        position: position(index),
        reserved_terminal_bytes: TARGET_COMPLETION_RESERVE_BYTES,
        reserved_audit_bytes: TARGET_COMPLETION_AUDIT_RESERVE_BYTES,
    };
    value.validate().unwrap();
    value
}
pub(crate) fn resolution(
    original: &TargetCompletionAttempt,
    control_revision: u64,
) -> (TargetCompletionResolutionInput, LifecycleIntent) {
    let input = TargetCompletionResolutionInput {
        attempt: Box::new(original.clone()),
    };
    let under = intent(
        &original.origin,
        LifecyclePhase::ResolveComplete,
        input.digest().unwrap(),
        control_revision,
        450,
        1_000,
    );
    (input, under)
}
pub(crate) fn applied(intent: LifecycleIntent, admitted_at_ms: u64, index: u64) -> ResolutionApply {
    ResolutionApply {
        intent,
        admitted_at_ms,
        dispatch_not_after_ms: 900,
        revision: 11 + index,
        position: position(index),
    }
}
fn completion(original: &TargetCompletionAttempt) -> TargetCompletionFact {
    let fact = TargetCompletionFact {
        origin: original.origin.clone(),
        materialized: original.input.quorum.materialized.clone(),
        completion_intent: original.intent.clone(),
        predecessor: original.input.predecessor.clone(),
        admitted_at_ms: original.dispatch_not_after_ms - 1,
        revision: original.revision + 1,
        term: original.position.term,
        leader_node_id: original.position.leader_node_id,
        bootstrap_sha256: "77".repeat(32),
    };
    fact.validate().unwrap();
    fact
}
fn machine<'a>(
    origin: &'a TargetOrigin,
    head: &'a mut TargetCompletionHead,
    completion: Option<&'a TargetCompletionFact>,
) -> CompletionMachine<'a> {
    CompletionMachine {
        origin,
        head,
        completion,
        terminal_bytes: 0,
        maximum_bytes: TARGET_COMPLETION_RESERVE_BYTES,
    }
}

#[test]
fn exact_preparation_replays_after_completion_without_replacing_its_reservation() {
    let origin = origin();
    let original = attempt(&origin, None, 3, 1, 200, 500);
    let mut head = TargetCompletionHead::empty(&origin).unwrap();
    machine(&origin, &mut head, None)
        .prepare(original.clone(), None, None)
        .unwrap();
    let completed = completion(&original);
    let mut replay = original.clone();
    replay.position = position(4);
    replay.revision += 3;
    replay.admitted_at_ms += 20;
    let retained = machine(&origin, &mut head, Some(&completed))
        .prepare(replay, None, None)
        .unwrap();
    assert_eq!(retained, original);
    assert_eq!(head.active.as_deref(), Some(&original));
}

#[test]
fn only_an_expired_exact_prepared_attempt_can_be_sealed() {
    let origin = origin();
    let original = attempt(&origin, None, 3, 1, 200, 500);
    let (input, under) = resolution(&original, 4);
    let mut head = TargetCompletionHead::empty(&origin).unwrap();
    assert!(
        machine(&origin, &mut head, None)
            .resolve(input.clone(), applied(under.clone(), 500, 3), None)
            .is_err()
    );
    assert!(head.active.is_none());
    assert!(head.predecessor.is_none());
    machine(&origin, &mut head, None)
        .prepare(original.clone(), None, None)
        .unwrap();
    let before = head.clone();
    assert!(
        machine(&origin, &mut head, None)
            .resolve(input.clone(), applied(under.clone(), 499, 3), None)
            .is_err()
    );
    assert_eq!(head, before);
    let sealed = machine(&origin, &mut head, None)
        .resolve(input, applied(under, 500, 3), None)
        .unwrap();
    assert!(matches!(sealed.terminal, TargetCompletionTerminal::Sealed));
    assert!(head.active.is_none());
    assert_eq!(head.predecessor, Some(sealed.sealed_reference().unwrap()));
}

#[test]
fn sealed_predecessor_orders_successor_and_rejects_a_late_original_complete() {
    let origin = origin();
    let original = attempt(&origin, None, 3, 1, 200, 500);
    let mut head = TargetCompletionHead::empty(&origin).unwrap();
    machine(&origin, &mut head, None)
        .prepare(original.clone(), None, None)
        .unwrap();
    let (input, under) = resolution(&original, 4);
    let sealed = machine(&origin, &mut head, None)
        .resolve(input, applied(under, 500, 3), None)
        .unwrap();
    let successor = attempt(
        &origin,
        Some(sealed.sealed_reference().unwrap()),
        5,
        4,
        600,
        900,
    );
    let mut unlinked = successor.clone();
    unlinked.input.predecessor = None;
    unlinked.intent.request.phase_input_sha256 = unlinked.input.digest().unwrap();
    unlinked.intent.request_sha256 = staged_digest(&unlinked.intent.request).unwrap().0;
    assert!(
        machine(&origin, &mut head, None)
            .prepare(unlinked, None, None)
            .is_err()
    );
    assert!(
        machine(&origin, &mut head, None)
            .prepare(successor.clone(), None, None)
            .is_err()
    );
    let mut unordered = successor.clone();
    unordered.revision = sealed.revision;
    unordered.position = sealed.position.clone();
    assert!(
        machine(&origin, &mut head, None)
            .prepare(unordered, Some(&sealed), None)
            .is_err()
    );
    machine(&origin, &mut head, None)
        .prepare(successor.clone(), Some(&sealed), None)
        .unwrap();
    // Even an old command authorized before expiration cannot cross the
    // predecessor transition in the same actual target Raft apply stream.
    assert!(
        machine(&origin, &mut head, None)
            .require_active(
                &original.intent,
                &original.input,
                original.dispatch_not_after_ms,
                Some(&sealed)
            )
            .is_err()
    );
    assert!(
        machine(&origin, &mut head, None)
            .require_active(
                &original.intent,
                &original.input,
                original.dispatch_not_after_ms,
                None
            )
            .is_err()
    );
    assert_eq!(
        machine(&origin, &mut head, None)
            .require_active(
                &successor.intent,
                &successor.input,
                successor.dispatch_not_after_ms,
                None
            )
            .unwrap(),
        &successor
    );
    // An old Prepare receipt remains resolvable without resurrecting it.
    assert_eq!(
        machine(&origin, &mut head, None)
            .prepare(original.clone(), None, Some(&sealed))
            .unwrap(),
        original
    );
    assert_eq!(head.active.as_deref(), Some(&successor));
}

#[test]
fn committed_original_resolves_positively_and_cannot_authorize_a_successor() {
    let origin = origin();
    let original = attempt(&origin, None, 3, 1, 200, 500);
    let mut head = TargetCompletionHead::empty(&origin).unwrap();
    machine(&origin, &mut head, None)
        .prepare(original.clone(), None, None)
        .unwrap();
    let completed = completion(&original);
    let (input, under) = resolution(&original, 4);
    let fact = machine(&origin, &mut head, Some(&completed))
        .resolve(input.clone(), applied(under.clone(), 500, 3), None)
        .unwrap();
    assert_eq!(
        fact.terminal,
        TargetCompletionTerminal::Committed(Box::new(completed.clone()))
    );
    assert!(fact.sealed_reference().is_err());
    assert!(head.active.is_none());
    assert!(head.predecessor.is_none());
    let next = attempt(&origin, None, 5, 4, 600, 900);
    assert!(
        machine(&origin, &mut head, Some(&completed))
            .prepare(next, None, None)
            .is_err()
    );
    let mut fresh = under.clone();
    fresh.request.command_id = Uuid::from_u128(2_000);
    fresh.request_sha256 = staged_digest(&fresh.request).unwrap().0;
    assert!(
        machine(&origin, &mut head, Some(&completed))
            .resolve(input.clone(), applied(fresh.clone(), 700, 4), Some(&fact))
            .is_err()
    );
    fresh.revision += 1;
    let observed = machine(&origin, &mut head, Some(&completed))
        .resolve(input, applied(fresh.clone(), 700, 4), Some(&fact))
        .unwrap();
    assert_eq!(observed, fact);
    let observation = TargetCompletionResolutionObservation {
        fact: observed,
        observation_intent: fresh,
        observer_node_id: 1,
        observed_revision: 15,
        observed_term: 1,
    };
    observation.validate().unwrap();
    let mut duplicate_revision = observation.clone();
    duplicate_revision.observation_intent.revision = under.revision;
    assert!(duplicate_revision.validate().is_err());
}

#[test]
fn preparation_reserves_terminal_capacity_and_resolution_does_not_reacquire_it() {
    let origin = origin();
    let original = attempt(&origin, None, 3, 1, 200, 500);
    let mut head = TargetCompletionHead::empty(&origin).unwrap();
    let mut value = machine(&origin, &mut head, None);
    value.terminal_bytes = 1;
    assert_eq!(
        value
            .prepare(original.clone(), None, None)
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    value.maximum_bytes = u64::MAX;
    value.terminal_bytes = u64::MAX;
    assert_eq!(
        value
            .prepare(original.clone(), None, None)
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    value.terminal_bytes = u64::MAX - TARGET_COMPLETION_RESERVE_BYTES;
    value.prepare(original.clone(), None, None).unwrap();
    let (input, under) = resolution(&original, 4);
    // The head already owns the full terminal reserve. The resolver consumes
    // that reserve even though no unreserved capacity remains.
    value.resolve(input, applied(under, 500, 3), None).unwrap();
    assert!(value.head.active.is_none());
}

#[test]
fn target_budget_changes_preserve_reserves_and_replay_the_first_outcome() {
    let origin = origin();
    let original = attempt(&origin, None, 3, 1, 200, 500);
    let mut head = TargetCompletionHead::empty(&origin).unwrap();
    machine(&origin, &mut head, None)
        .prepare(original, None, None)
        .unwrap();
    let input = TargetResolutionBudgetInput {
        operation_id: Uuid::from_u128(3_000),
        origin_sha256: origin.digest().unwrap(),
        expected_bytes: TARGET_COMPLETION_RESERVE_BYTES,
        maximum_bytes: TARGET_COMPLETION_RESERVE_BYTES * 2,
    };
    let proposed = TargetResolutionBudgetFact {
        intent: intent(
            &origin,
            LifecyclePhase::MaintainTarget,
            input.digest().unwrap(),
            4,
            300,
            1_000,
        ),
        origin: origin.clone(),
        input,
        admitted_at_ms: 350,
        dispatch_not_after_ms: 900,
        revision: 13,
        position: position(2),
    };
    let value = machine(&origin, &mut head, None);
    let transition = value
        .maintain_budget(proposed.clone(), TARGET_COMPLETION_RESERVE_BYTES, None)
        .unwrap();
    assert!(transition.changed);
    assert_eq!(transition.fact, proposed);
    let mut too_small = proposed.clone();
    too_small.input.maximum_bytes = TARGET_COMPLETION_RESERVE_BYTES;
    too_small.intent.request.phase_input_sha256 = too_small.input.digest().unwrap();
    too_small.intent.request_sha256 = staged_digest(&too_small.intent.request).unwrap().0;
    assert_eq!(
        value
            .maintain_budget(too_small, TARGET_COMPLETION_RESERVE_BYTES, None)
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    let mut stale = proposed.clone();
    stale.input.expected_bytes += 1;
    stale.intent.request.phase_input_sha256 = stale.input.digest().unwrap();
    stale.intent.request_sha256 = staged_digest(&stale.intent.request).unwrap().0;
    assert_eq!(
        value
            .maintain_budget(stale, TARGET_COMPLETION_RESERVE_BYTES, None)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    // A later authorized change may have altered the operational budget.
    // Resolving this exact earlier operation returns its first immutable fact.
    let mut changed_budget = value;
    changed_budget.maximum_bytes = TARGET_COMPLETION_RESERVE_BYTES * 4;
    let mut fresh = proposed.clone();
    fresh.intent.request.command_id = Uuid::from_u128(4_000);
    fresh.intent.revision += 1;
    fresh.intent.request_sha256 = staged_digest(&fresh.intent.request).unwrap().0;
    fresh.revision += 1;
    fresh.position.index += 1;
    let result = changed_budget
        .maintain_budget(fresh, TARGET_COMPLETION_RESERVE_BYTES, Some(&proposed))
        .unwrap();
    assert!(!result.changed);
    assert_eq!(result.fact, proposed);
}

#[test]
fn reservation_shape_and_explicit_predecessor_are_canonical() {
    let origin = origin();
    let original = attempt(&origin, None, 3, 1, 200, 500);
    let mut value = serde_json::to_value(&original).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("reserved_audit_bytes");
    assert!(serde_json::from_value::<TargetCompletionAttempt>(value).is_err());
    let mut value = serde_json::to_value(&original.input).unwrap();
    value.as_object_mut().unwrap().remove("predecessor");
    assert!(serde_json::from_value::<TargetCompletionInput>(value).is_err());
    let mut undersized = original.clone();
    undersized.reserved_terminal_bytes -= 1;
    assert!(undersized.validate().is_err());
    let mut oversized = original;
    oversized
        .input
        .quorum
        .materialized
        .get_mut(&1)
        .unwrap()
        .signature = "x".repeat(64 << 10);
    oversized.intent.request.phase_input_sha256 = oversized.input.digest().unwrap();
    oversized.intent.request_sha256 = staged_digest(&oversized.intent.request).unwrap().0;
    assert!(oversized.validate().is_err());
}

#[test]
fn terminal_proof_binds_original_target_order_and_distinct_signature_purpose() {
    let origin = origin();
    let original = attempt(&origin, None, 3, 1, 200, 500);
    let prepared = TargetCompletionAttemptObservation {
        attempt: original.clone(),
        observer_node_id: 1,
        observed_revision: original.revision,
        observed_term: 1,
    };
    let signed = SignedTargetCompletionAttempt {
        signature: sign(
            &prepared,
            "kasumi.prepared-target-completion-observation.v1",
            1,
        ),
        observation: prepared,
    };
    kasumi_serving::verify_target_completion_attempt(&origin, &signed).unwrap();
    let mut head = TargetCompletionHead::empty(&origin).unwrap();
    machine(&origin, &mut head, None)
        .prepare(original.clone(), None, None)
        .unwrap();
    let (input, under) = resolution(&original, 4);
    let fact = machine(&origin, &mut head, None)
        .resolve(input, applied(under.clone(), 500, 3), None)
        .unwrap();
    let observation = TargetCompletionResolutionObservation {
        fact,
        observation_intent: under,
        observer_node_id: 1,
        observed_revision: 14,
        observed_term: 1,
    };
    let mut terminal = SignedTargetCompletionResolution {
        signature: sign(
            &observation,
            "kasumi.resolved-target-completion-observation.v1",
            1,
        ),
        observation,
    };
    kasumi_serving::verify_target_completion_resolution(&origin, &terminal).unwrap();
    let original_signature = terminal.signature.clone();
    terminal.signature = sign(
        &terminal.observation,
        "kasumi.completed-target-observation.v1",
        1,
    );
    assert!(kasumi_serving::verify_target_completion_resolution(&origin, &terminal).is_err());
    terminal.signature = original_signature;
    let mut wrong_target = origin.clone();
    wrong_target.input.target_incarnation = Uuid::from_u128(9_000);
    wrong_target.materialization.request.target_incarnation = wrong_target.input.target_incarnation;
    wrong_target.materialization.request.phase_input_sha256 = wrong_target.input.digest().unwrap();
    wrong_target.materialization.request_sha256 =
        staged_digest(&wrong_target.materialization.request)
            .unwrap()
            .0;
    wrong_target.validate().unwrap();
    assert!(kasumi_serving::verify_target_completion_resolution(&wrong_target, &terminal).is_err());
    // Even a consistently re-signed different observation cannot appear at
    // the first terminal's authoritative Control revision.
    terminal.observation.observation_intent.request.command_id = Uuid::from_u128(9_001);
    terminal.observation.observation_intent.request_sha256 =
        staged_digest(&terminal.observation.observation_intent.request)
            .unwrap()
            .0;
    terminal.signature = sign(
        &terminal.observation,
        "kasumi.resolved-target-completion-observation.v1",
        1,
    );
    assert!(kasumi_serving::verify_target_completion_resolution(&origin, &terminal).is_err());
    terminal.observation.observation_intent.revision += 1;
    terminal.signature = sign(
        &terminal.observation,
        "kasumi.resolved-target-completion-observation.v1",
        1,
    );
    kasumi_serving::verify_target_completion_resolution(&origin, &terminal).unwrap();
}
