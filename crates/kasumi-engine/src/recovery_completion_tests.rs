use super::*;
use crate::target_completion_machine::tests as fixture;

#[test]
fn retained_complete_input_requires_explicit_canonical_predecessor() {
    let origin = fixture::origin();
    let original = fixture::attempt(&origin, None, 10, 1, 200, 500);
    assert!(original.input.predecessor.is_none());
    validate_original_intent(&origin, &original.input, &original.intent).unwrap();

    let mut quorum_only = original.intent.clone();
    quorum_only.request.phase_input_sha256 = original.input.quorum.digest().unwrap();
    quorum_only.request_sha256 = staged_digest(&quorum_only.request).unwrap().0;
    assert!(validate_original_intent(&origin, &original.input, &quorum_only).is_err());

    let mut substituted = original.input.clone();
    substituted.predecessor = Some(TargetCompletionResolutionReference {
        origin_sha256: origin.digest().unwrap(),
        control_incarnation: original.intent.control_incarnation,
        original_command_id: Uuid::from_u128(910),
        resolution_command_id: Uuid::from_u128(911),
        resolution_control_revision: 9,
        fact_sha256: "88".repeat(32),
    });
    let mut substituted_intent = original.intent.clone();
    substituted_intent.request.phase_input_sha256 = substituted.digest().unwrap();
    substituted_intent.request_sha256 = staged_digest(&substituted_intent.request).unwrap().0;
    // This input is structurally valid for its substituted intent, but is not
    // the coordinator's original canonical input with predecessor None.
    substituted.validate(&origin, &substituted_intent).unwrap();
    assert!(validate_original_intent(&origin, &original.input, &substituted_intent).is_err());
    assert!(validate_original_intent(&origin, &substituted, &original.intent).is_err());
}
