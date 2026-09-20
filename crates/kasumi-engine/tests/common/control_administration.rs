use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

struct Revocation(AtomicBool);
impl CredentialLiveness for Revocation {
    fn check(&self) -> Result<()> {
        if self.0.load(Ordering::SeqCst) {
            Err(Error::new(
                ErrorCode::Unauthorized,
                "fixture credential revoked",
            ))
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn current_control_administration_retains_exact_resource_revocation_and_original_lifetime() {
    let mut fixture = Fixture::new().await;
    let database = fixture.leader().await;
    let partition = fixture
        .installation
        .partitions
        .values()
        .next()
        .unwrap()
        .clone();
    let original = fixture.context("owner");
    let revoked = Arc::new(Revocation(AtomicBool::new(false)));
    let now = kasumi_clock::EpochClock::system()
        .unwrap()
        .observe()
        .unwrap();
    let mut context = original.clone();
    context.authorization = RequestAuthorization::from_verified_credential_with_liveness(
        now.utc_ms() + 60_000,
        &now,
        CredentialResource::Control {
            incarnation: fixture.installation.root.control_incarnation,
        },
        revoked.clone(),
    )
    .unwrap();
    let fence = database
        .authorize_control_administration(context.clone(), partition.clone())
        .await
        .unwrap();
    assert_eq!(fence.installation(), &fixture.installation);
    assert_eq!(fence.partition(), &partition);
    assert_eq!(
        fence.members().collect::<BTreeSet<_>>(),
        BTreeSet::from([1, 2, 3])
    );
    assert_eq!(
        fence.voters().collect::<BTreeSet<_>>(),
        BTreeSet::from([1, 2, 3])
    );
    assert!(
        fence
            .context()
            .authorization
            .same_live_invocation(&context.authorization)
    );
    fence.release().await.unwrap();

    let replayed: RequestContext =
        serde_json::from_value(serde_json::to_value(&context).unwrap()).unwrap();
    assert!(
        database
            .authorize_control_administration(replayed, partition.clone())
            .await
            .is_err()
    );
    let mut wrong = fixture.context("owner");
    wrong.authorization = RequestAuthorization::from_verified_credential(
        now.utc_ms() + 60_000,
        &now,
        CredentialResource::Control {
            incarnation: Uuid::new_v4(),
        },
    )
    .unwrap();
    assert!(
        database
            .authorize_control_administration(wrong, partition.clone())
            .await
            .is_err()
    );
    assert!(
        database
            .authorize_control_administration(fixture.context("outsider"), partition.clone())
            .await
            .is_err()
    );
    let mut changed = partition.clone();
    changed.signing_public_key = "93".repeat(32);
    assert!(
        database
            .authorize_control_administration(original, changed)
            .await
            .is_err()
    );

    revoked.0.store(true, Ordering::SeqCst);
    assert!(fence.check().is_err());
    assert!(fence.release().await.is_err());
    drop(fence);

    let finite = fixture.context_for("owner", 2000);
    let expired = database
        .authorize_control_administration(finite, partition.clone())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert!(expired.check().is_err());
    let renewed = database
        .authorize_control_administration(fixture.context("owner"), partition)
        .await
        .unwrap();
    renewed.release().await.unwrap();
    assert!(
        expired.release().await.is_err(),
        "a new credential cannot replace an existing fence's anchor"
    );
    drop(expired);
    drop(renewed);
    drop(database);
    fixture.close().await;
}

#[tokio::test]
async fn current_control_administration_pins_actual_membership_and_pending_policy_across_restart() {
    let mut fixture = Fixture::new().await;
    let database = fixture.leader().await;
    let partition = fixture
        .installation
        .partitions
        .values()
        .next()
        .unwrap()
        .clone();
    let original = database
        .authorize_control_administration(fixture.context("owner"), partition.clone())
        .await
        .unwrap();
    database
        .raft_group()
        .raft()
        .add_learner(4, kasumi_raft::BasicNode::new("node-4"), false)
        .await
        .unwrap();
    assert!(
        original.check().is_err(),
        "learner admission changes exact verifier coverage"
    );
    let current = database
        .authorize_control_administration(fixture.context("owner"), partition.clone())
        .await
        .unwrap();
    assert_eq!(
        current.members().collect::<BTreeSet<_>>(),
        BTreeSet::from([1, 2, 3, 4])
    );
    assert_eq!(
        current.voters().collect::<BTreeSet<_>>(),
        BTreeSet::from([1, 2, 3])
    );
    current.release().await.unwrap();
    let epoch = database.engine().generation().unwrap().state.policy_epoch;
    database
        .lifecycle_control(
            fixture.context("owner"),
            LifecycleControlCommand::BeginPolicyChange(fixture.change(epoch)),
        )
        .await
        .unwrap();
    assert!(current.check().is_err());
    assert!(
        database
            .authorize_control_administration(fixture.context("owner"), partition.clone())
            .await
            .is_err()
    );
    drop(original);
    drop(current);
    drop(database);
    fixture.close().await;
    fixture.open(false).await;
    let database = fixture.leader().await;
    assert!(
        database
            .authorize_control_administration(fixture.context("owner"), partition)
            .await
            .is_err(),
        "reopening cannot bypass the retained pending Control change"
    );
    drop(database);
    fixture.close().await;
}

#[tokio::test]
async fn current_control_administration_cannot_release_through_a_cached_leader_after_quorum_loss() {
    let mut fixture = Fixture::new().await;
    let database = fixture.leader().await;
    let partition = fixture
        .installation
        .partitions
        .values()
        .next()
        .unwrap()
        .clone();
    let fence = database
        .authorize_control_administration(fixture.context("owner"), partition.clone())
        .await
        .unwrap();
    let group = format!("__kasumi_control/{}", fixture.bootstrap.incarnation);
    fixture.router.isolate(&group, fence.local_node_id(), true);
    assert!(
        tokio::time::timeout(Duration::from_secs(6), fence.release())
            .await
            .unwrap()
            .is_err()
    );
    fixture.router.isolate(&group, fence.local_node_id(), false);
    let current = fixture.leader().await;
    let admitted = current
        .authorize_control_administration(fixture.context("owner"), partition)
        .await
        .unwrap();
    admitted.release().await.unwrap();
    assert!(
        fence.check().is_err(),
        "new quorum authority cannot replace the original observed term"
    );
    fixture
        .router
        .isolate(&group, admitted.local_node_id(), true);
    {
        let mut pending = Box::pin(admitted.release());
        tokio::select! {
            biased;
            outcome = &mut pending => assert!(outcome.is_err()),
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(
        admitted.check().is_err(),
        "cancelled current-quorum release permanently closes its original observation"
    );
    fixture
        .router
        .isolate(&group, admitted.local_node_id(), false);
    drop(fence);
    drop(admitted);
    drop(current);
    drop(database);
    fixture.close().await;
}
