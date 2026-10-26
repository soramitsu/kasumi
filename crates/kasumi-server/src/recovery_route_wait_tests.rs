//! Route fallback keeps its finite ceiling while later healthy replies retain
//! the same allowance, bounded by the original command/credential time left.
use super::*;

fn quorum() -> TargetQuorumInput {
    // Timing selection examines only the typed step. Dispatch admission remains
    // responsible for validating this payload before any network work.
    TargetQuorumInput {
        origin_sha256: String::new(),
        materialized: BTreeMap::new(),
    }
}

fn completion() -> TargetRuntimeStep {
    TargetRuntimeStep::Complete(TargetCompletionInput {
        quorum: quorum(),
        predecessor: None,
    })
}

#[test]
fn later_routes_keep_the_same_ceiling_as_time_is_consumed() {
    let configured = Duration::from_secs(120);
    for seconds in [120, 96, 72, 48, 24] {
        assert_eq!(
            target_route_wait(
                RecoveryPhase::Complete,
                &completion(),
                configured,
                Duration::from_secs(seconds),
            ),
            Duration::from_secs(24),
        );
    }
}

#[tokio::test]
async fn healthy_later_route_keeps_time_for_its_reply_after_prior_route_cost() {
    let configured = Duration::from_secs(1);
    let remaining = Duration::from_millis(300);
    let wait = target_route_wait(
        RecoveryPhase::Complete,
        &completion(),
        configured,
        remaining,
    );
    let response_cost = Duration::from_millis(100);
    assert!(response_cost > remaining / 5);
    assert!(response_cost < wait);
    let response = tokio::time::timeout(wait, async {
        tokio::time::sleep(response_cost).await;
        "positively observed reply"
    })
    .await
    .expect("an earlier route must not repeatedly divide a healthy reply's allowance");
    assert_eq!(response, "positively observed reply");
}

#[tokio::test]
async fn stalled_route_yields_to_fallback_after_one_configured_slice() {
    let configured = Duration::from_millis(100);
    let remaining = Duration::from_millis(80);
    let wait = target_route_wait(
        RecoveryPhase::Complete,
        &completion(),
        configured,
        remaining,
    );
    assert_eq!(wait, Duration::from_millis(20));
    assert!(
        tokio::time::timeout(wait, std::future::pending::<()>())
            .await
            .is_err()
    );
    // Connection and dispatch are still enclosed by this same timeout. A
    // connected peer that never replies cannot consume the remaining phase.
    let fallback = tokio::time::timeout(wait, async { "next installed route" })
        .await
        .unwrap();
    assert_eq!(fallback, "next installed route");
}

#[tokio::test]
async fn final_route_cannot_wait_past_remaining_absolute_authority() {
    let configured = Duration::from_secs(1);
    let remaining = Duration::from_millis(20);
    let wait = target_route_wait(
        RecoveryPhase::Complete,
        &completion(),
        configured,
        remaining,
    );
    assert_eq!(wait, remaining);
    assert!(
        tokio::time::timeout(wait, std::future::pending::<()>())
            .await
            .is_err()
    );
    assert_eq!(
        target_route_wait(
            RecoveryPhase::Complete,
            &completion(),
            configured,
            Duration::ZERO,
        ),
        Duration::ZERO,
    );
}

#[test]
fn other_steps_keep_the_existing_full_remaining_allowance() {
    let configured = Duration::from_secs(1);
    let remaining = Duration::from_millis(300);
    for (phase, step) in [
        (
            RecoveryPhase::Initialize,
            TargetRuntimeStep::Start(TargetReplicaInput::Quorum(quorum())),
        ),
        (
            RecoveryPhase::Initialize,
            TargetRuntimeStep::Initialize(quorum()),
        ),
        (RecoveryPhase::Initialize, completion()),
        (
            RecoveryPhase::Complete,
            TargetRuntimeStep::Initialize(quorum()),
        ),
    ] {
        assert_eq!(
            target_route_wait(phase, &step, configured, remaining),
            remaining
        );
    }
}
