use crate::target_completion_machine::tests as fixture;
use kasumi_types::*;

fn observation() -> TargetCompletionAttemptStatusObservation {
    let origin = fixture::origin();
    let attempt = fixture::attempt(&origin, None, 3, 1, 200, 500);
    let input = TargetCompletionAttemptStatusInput {
        original_intent: attempt.intent.clone(),
        original_input: attempt.input.clone(),
        original_dispatch_not_after_ms: attempt.dispatch_not_after_ms,
    };
    let status_intent = fixture::intent(
        &origin,
        LifecyclePhase::InspectCompletionAttempt,
        input.digest().unwrap(),
        5,
        1000,
        2000,
    );
    TargetCompletionAttemptStatusObservation {
        input,
        status_intent,
        attempt,
        observer_node_id: 1,
        observed_revision: 20,
        observed_term: 1,
    }
}
fn signed(
    observation: TargetCompletionAttemptStatusObservation,
) -> SignedTargetCompletionAttemptStatus {
    let signature = fixture::sign(
        &observation,
        "kasumi.target-completion-attempt-status-observation.v1",
        1,
    );
    SignedTargetCompletionAttemptStatus {
        observation,
        signature,
    }
}
#[test]
fn fresh_status_preserves_expired_original_scope_position_and_dispatch_cap() {
    let observation = observation();
    assert!(
        observation.status_intent.accepted_at_ms
            > observation.attempt.intent.original_credential_expires_at_ms
    );
    observation.validate().unwrap();
    let proof = signed(observation.clone());
    let verified =
        kasumi_serving::verify_target_completion_attempt_status(&observation.input, &proof)
            .unwrap();
    assert_eq!(verified.signed().observation.attempt, observation.attempt);
    assert_eq!(
        verified.signed().observation.attempt.dispatch_not_after_ms,
        500
    );
    assert_eq!(verified.signed().observation.attempt.position.index, 1);
    // A later status cap does not update either of the original deadlines.
    assert_eq!(
        verified
            .signed()
            .observation
            .attempt
            .intent
            .original_credential_expires_at_ms,
        600
    );
}
#[test]
fn status_requires_distinct_later_control_identity_and_exact_original_attempt() {
    let original = observation();
    let mut changed = original.clone();
    changed.status_intent.revision = changed.attempt.intent.revision;
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed.status_intent.request.command_id = changed.attempt.intent.request.command_id;
    changed.status_intent.request_sha256 = staged_digest(&changed.status_intent.request).unwrap().0;
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed.attempt.dispatch_not_after_ms -= 1;
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed.attempt.intent.original_principal = "another-operator".into();
    assert!(changed.validate().is_err());
    let mut changed = original.clone();
    changed.status_intent.control_incarnation = uuid::Uuid::from_u128(333);
    assert!(changed.validate().is_err());
    let mut changed = original;
    changed.observed_revision = changed.attempt.revision - 1;
    assert!(changed.validate().is_err());
}
#[test]
fn status_signature_domain_and_expected_input_cannot_be_substituted() {
    let original = observation();
    let mut proof = signed(original.clone());
    proof.signature = fixture::sign(
        &original,
        "kasumi.prepared-target-completion-observation.v1",
        1,
    );
    assert!(
        kasumi_serving::verify_target_completion_attempt_status(&original.input, &proof).is_err()
    );
    let proof = signed(original.clone());
    let mut other = original.input;
    other.original_dispatch_not_after_ms -= 1;
    assert!(kasumi_serving::verify_target_completion_attempt_status(&other, &proof).is_err());
    // There is deliberately no absent/negative observation variant.
    assert!(
        serde_json::from_value::<TargetCompletionAttemptStatusObservation>(
            serde_json::json!({"absent":true})
        )
        .is_err()
    );
}
