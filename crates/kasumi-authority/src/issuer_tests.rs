//! Reducer/lease fixtures explicitly sign immutable Control commitments. The
//! native end-to-end test separately proves actual control-quorum signing.
use super::*;
use kasumi_types::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
struct ControlFixture {
    root: ControlSigningRoot,
    key: Ed25519KeyPair,
}
impl ControlFixture {
    fn new() -> Self {
        let bytes = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap();
        Self {
            root: ControlSigningRoot {
                control_incarnation: Uuid::new_v4(),
                public_key: hex::encode(key.public_key().as_ref()),
            },
            key,
        }
    }
    async fn issuer(&self, max: u64) -> Fixture {
        Fixture::with_controls(
            max,
            BTreeMap::from([(self.root.control_incarnation, self.root.public_key.clone())]),
        )
        .await
    }
    fn intent(&self, f: &Fixture, t: &RecoveryTarget, expiry: u64) -> SignedControlIntent {
        let request = CommitLifecycleIntent {
            command_id: Uuid::new_v4(),
            expected_policy_epoch: 1,
            installation_sha256: "ab".repeat(32),
            authority_partition: f.installation.manifest.control_partition(0).unwrap().key(),
            tenant: "city".into(),
            source_incarnation: Uuid::parse_str(&t.checkpoint.source_incarnation).unwrap(),
            source_authority_epoch: 1,
            target_incarnation: t.incarnation,
            checkpoint: t.checkpoint.clone(),
            target_nodes: t
                .nodes
                .iter()
                .map(|n| {
                    (
                        n.node_id,
                        LifecycleNode {
                            node_id: n.node_id,
                            principal: n.principal.clone(),
                            certificate_sha256: n.certificate_sha256.clone(),
                        },
                    )
                })
                .collect(),
            phase: LifecyclePhase::Materialize,
            phase_input_sha256: "cd".repeat(32),
        };
        let mut signed = SignedControlIntent {
            observation: ControlIntentCommitment {
                intent: LifecycleIntent {
                    control_incarnation: self.root.control_incarnation,
                    installation_generation: 1,
                    request_sha256: digest(&request).unwrap(),
                    request,
                    original_principal: "control-admin".into(),
                    original_credential_expires_at_ms: expiry,
                    accepted_at_ms: 1_000_000,
                    revision: 2,
                },
                root: self.root.clone(),
                authority_partition: f.installation.manifest.control_partition(0).unwrap(),
                partition_set_sha256: "ef".repeat(32),
                observed_policy_epoch: 1,
                observed_revision: 2,
                observed_term: 1,
            },
            signature: String::new(),
        };
        self.sign_intent(&mut signed);
        signed
    }
    fn sign_intent(&self, signed: &mut SignedControlIntent) {
        signed.signature = hex::encode(
            self.key
                .sign(
                    &serde_json::to_vec(&(
                        "kasumi.committed-control-intent.v1",
                        &signed.observation,
                    ))
                    .unwrap(),
                )
                .as_ref(),
        );
    }
    fn stop(&self, signed: &SignedControlIntent) -> SignedControlChange {
        let obs = &signed.observation;
        let observation = ControlChangeCommitment {
            root: self.root.clone(),
            stop: ControlEpochStop {
                control_incarnation: self.root.control_incarnation,
                control_policy_epoch: 1,
                installation_sha256: obs.intent.request.installation_sha256.clone(),
                installation_generation: 1,
                change_id: Uuid::new_v4(),
                change_sha256: "12".repeat(32),
                authority_partition: obs.authority_partition.clone(),
                partition_set_sha256: obs.partition_set_sha256.clone(),
            },
            accepted_revision: 3,
            observed_policy_epoch: 1,
            observed_revision: 3,
            observed_term: 1,
        };
        let signature = hex::encode(
            self.key
                .sign(
                    &serde_json::to_vec(&("kasumi.committed-control-change.v1", &observation))
                        .unwrap(),
                )
                .as_ref(),
        );
        SignedControlChange {
            observation,
            signature,
        }
    }
}
fn request(s: &SignedControlIntent) -> LifecycleAuthorityRequest {
    LifecycleAuthorityRequest::AcceptIntent(Box::new(s.clone()))
}
fn node(f: &Fixture) -> AuthenticatedNode {
    AuthenticatedNode::from_verified_transport(
        f.context("node-1"),
        nodes().first().unwrap().certificate_sha256.clone(),
    )
    .unwrap()
}
async fn prepared(f: &Fixture, service: &Arc<IndependentAuthority>) -> RecoveryTarget {
    let source = f.enroll(service).await;
    let target = target(source);
    service
        .execute(
            f.context("operator"),
            f.command(AuthorityAction::PrepareTarget {
                source_incarnation: source,
                source_epoch: 1,
                target: target.clone(),
            }),
        )
        .await
        .unwrap();
    target
}
#[tokio::test]
async fn control_epoch_stop_preserves_exact_identity_replay_and_restarts_full_drain() {
    let control = ControlFixture::new();
    let mut f = control.issuer(100).await;
    let service = f.leader().await;
    let t = prepared(&f, &service).await;
    let signed = control.intent(&f, &t, 1_050_000);
    let original = request(&signed);
    drop(service);
    let (service, accepted) = accepted_on_current_leader(&f, original.clone()).await;
    service
        .backend
        .lifecycle_receipt(&original.reference())
        .unwrap()
        .unwrap();
    let mut refresh = signed.clone();
    refresh.observation.observed_revision = 10;
    control.sign_intent(&mut refresh);
    let replay = service
        .execute_lifecycle(f.context("operator"), request(&refresh))
        .await
        .unwrap()
        .0;
    assert_eq!(
        replay.receipt.accepted_revision,
        accepted.receipt.accepted_revision
    );
    refresh.signature = "00".repeat(64);
    assert!(
        service
            .execute_lifecycle(f.context("operator"), request(&refresh))
            .await
            .is_err()
    );
    let mut changed = signed.clone();
    changed.observation.intent.original_credential_expires_at_ms += 1;
    control.sign_intent(&mut changed);
    assert_eq!(
        service
            .execute_lifecycle(f.context("operator"), request(&changed))
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );
    let proof = ControlTrust::install(control.root.clone())
        .unwrap()
        .verify_intent(&signed)
        .unwrap();
    let boot = LifecycleBoot::with_clock(
        AuthorityTrust::install(f.installation.manifest.clone()).unwrap(),
        nodes().first().unwrap().clone(),
        f.clock.clone(),
    )
    .unwrap();
    let attempt = boot.begin(&proof).unwrap();
    service
        .backend
        .lifecycle_lease_view(attempt.request())
        .unwrap();
    let (lease, fence) = service
        .acquire_lifecycle(node(&f), attempt.request().clone())
        .await
        .unwrap();
    let lease = attempt.verify(lease).unwrap();
    fence.release().await.unwrap();
    let stop = control.stop(&signed);
    let stopped = LifecycleAuthorityRequest::StopEpoch(Box::new(stop.clone()));
    service
        .execute_lifecycle(f.context("operator"), stopped.clone())
        .await
        .unwrap();
    assert!(fence.release().await.is_err());
    assert!(
        service
            .acquire_lifecycle(node(&f), boot.begin(&proof).unwrap().request().clone())
            .await
            .is_err()
    );
    assert!(
        service
            .verify_control_stop(f.context("operator"), stopped.reference())
            .await
            .is_err()
    );
    f.clock.0.store(999, Ordering::SeqCst);
    assert!(
        service
            .verify_control_stop(f.context("operator"), stopped.reference())
            .await
            .is_err()
    );
    f.clock.0.store(1000, Ordering::SeqCst);
    assert!(lease.check().is_err());
    let (drained, _) = service
        .verify_control_stop(f.context("operator"), stopped.reference())
        .await
        .unwrap();
    verify_control_epoch_stop(&stop.observation.stop, &drained).unwrap();
    use kasumi_raft::StateMachineBackend;
    let snapshot = service.backend.snapshot().unwrap();
    service.backend.validate_snapshot(&snapshot.data).unwrap();
    drop(fence);
    drop(service);
    f.reopen().await;
    let service = f.leader().await;
    assert!(
        service
            .verify_control_stop(f.context("operator"), stopped.reference())
            .await
            .is_err()
    );
    f.clock.0.store(1999, Ordering::SeqCst);
    assert!(
        service
            .verify_control_stop(f.context("operator"), stopped.reference())
            .await
            .is_err()
    );
    f.clock.0.store(2000, Ordering::SeqCst);
    service
        .verify_control_stop(f.context("operator"), stopped.reference())
        .await
        .unwrap();
    let retained = service
        .read_lifecycle_receipt(f.context("operator"), original.reference())
        .await
        .unwrap()
        .0
        .unwrap();
    assert_eq!(
        retained.receipt.accepted_revision,
        accepted.receipt.accepted_revision
    );
    let late = control.intent(&f, &t, 1_050_000);
    assert_eq!(
        service
            .execute_lifecycle(f.context("operator"), request(&late))
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );
    f.close().await;
}
#[tokio::test]
async fn control_stop_before_intent_and_reserved_capacity_defeat_late_publication() {
    let c = ControlFixture::new();
    let f = c.issuer(2).await;
    let service = f.leader().await;
    let signed = c.intent(&f, &target(Uuid::new_v4()), 1_050_000);
    service
        .execute_lifecycle(f.context("operator"), request(&signed))
        .await
        .unwrap();
    let next = c.intent(&f, &target(Uuid::new_v4()), 1_050_000);
    assert_eq!(
        service
            .execute_lifecycle(f.context("operator"), request(&next))
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::ResourceExhausted
    );
    let stop = LifecycleAuthorityRequest::StopEpoch(Box::new(c.stop(&signed)));
    service
        .execute_lifecycle(f.context("operator"), stop)
        .await
        .unwrap();
    f.close().await;
    let f = c.issuer(20).await;
    let service = f.leader().await;
    let signed = c.intent(&f, &target(Uuid::new_v4()), 1_050_000);
    service
        .execute_lifecycle(
            f.context("operator"),
            LifecycleAuthorityRequest::StopEpoch(Box::new(c.stop(&signed))),
        )
        .await
        .unwrap();
    assert_eq!(
        service
            .execute_lifecycle(f.context("operator"), request(&signed))
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );
    assert!(
        service
            .read_lifecycle_receipt(f.context("operator"), request(&signed).reference())
            .await
            .unwrap()
            .0
            .is_none()
    );
    f.close().await;
}
#[tokio::test]
async fn lifecycle_original_deadline_survives_queued_acceptance_delayed_reply_and_clock_regression()
{
    let c = ControlFixture::new();
    let f = c.issuer(100).await;
    let service = f.leader().await;
    let t = prepared(&f, &service).await;
    let signed = c.intent(&f, &t, 1_000_500);
    let proof = ControlTrust::install(c.root.clone())
        .unwrap()
        .verify_intent(&signed)
        .unwrap();
    drop(service);
    let (service, _) = accepted_on_current_leader(&f, request(&signed)).await;
    let boot = LifecycleBoot::with_clock(
        AuthorityTrust::install(f.installation.manifest.clone()).unwrap(),
        nodes().first().unwrap().clone(),
        f.clock.clone(),
    )
    .unwrap();
    let attempt = boot.begin(&proof).unwrap();
    service
        .backend
        .lifecycle_lease_view(attempt.request())
        .unwrap();
    let (response, _) = service
        .acquire_lifecycle(node(&f), attempt.request().clone())
        .await
        .unwrap();
    assert_eq!(response.claims.credential_lifetime_ms, 500);
    let held = attempt.verify(response.clone()).unwrap();
    f.clock.0.store(500, Ordering::SeqCst);
    assert!(attempt.clone().verify(response.clone()).is_err());
    assert!(held.check().is_err());
    assert!(boot.begin(&proof).unwrap().verify(response).is_err());
    assert!(
        service
            .acquire_lifecycle(node(&f), boot.begin(&proof).unwrap().request().clone())
            .await
            .is_err()
    );
    let queued = c.intent(&f, &t, 1_000_600);
    let gate = service.proposal.lock().await;
    let task = {
        let service = service.clone();
        let ctx = f.context("operator");
        let request = request(&queued);
        tokio::spawn(async move { service.execute_lifecycle(ctx, request).await })
    };
    tokio::task::yield_now().await;
    f.clock.0.store(600, Ordering::SeqCst);
    drop(gate);
    assert_eq!(
        task.await.unwrap().err().unwrap().code,
        ErrorCode::Unauthorized
    );
    assert!(
        service
            .read_lifecycle_receipt(f.context("operator"), request(&queued).reference())
            .await
            .unwrap()
            .0
            .is_none()
    );
    f.clock.0.store(400, Ordering::SeqCst);
    assert!(held.check().is_err());
    f.clock.0.store(700, Ordering::SeqCst);
    assert!(boot.begin(&proof).is_err());
    f.close().await;
}

#[tokio::test]
async fn lifecycle_byte_exhaustion_preserves_reserved_epoch_stop_and_exact_snapshot_history() {
    let c = ControlFixture::new();
    let f = Fixture::with_control_capacity(
        100,
        BTreeMap::from([(c.root.control_incarnation, c.root.public_key.clone())]),
        (256 << 10) + 16000,
    )
    .await;
    let service = f.leader().await;
    let t = target(Uuid::new_v4());
    let first = c.intent(&f, &t, 1_050_000);
    service
        .execute_lifecycle(f.context("operator"), request(&first))
        .await
        .unwrap();
    let mut exhausted = false;
    for _ in 0..20 {
        let next = c.intent(&f, &t, 1_050_000);
        match service
            .execute_lifecycle(f.context("operator"), request(&next))
            .await
        {
            Ok(_) => {}
            Err(error) => {
                assert_eq!(error.code, ErrorCode::ResourceExhausted);
                exhausted = true;
                break;
            }
        }
    }
    assert!(
        exhausted,
        "small byte budget must exhaust before count quota"
    );
    let stop = LifecycleAuthorityRequest::StopEpoch(Box::new(c.stop(&first)));
    service
        .execute_lifecycle(f.context("operator"), stop.clone())
        .await
        .unwrap();
    use kasumi_raft::StateMachineBackend;
    let snapshot = service.backend.snapshot().unwrap();
    service.backend.validate_snapshot(&snapshot.data).unwrap();
    let mut modified: serde_json::Value = serde_json::from_slice(&snapshot.data).unwrap();
    let key = stop.reference().key().unwrap();
    modified["records"][&key]["record"]["original_principal"] =
        serde_json::json!("substituted-admin");
    assert!(
        service
            .backend
            .restore(&serde_json::to_vec(&modified).unwrap())
            .is_err()
    );
    let retained = service
        .read_lifecycle_receipt(f.context("operator"), stop.reference())
        .await
        .unwrap()
        .0
        .unwrap();
    assert_eq!(retained.receipt.original_principal, "operator");
    f.close().await;
}

// Test helper for initial setup, not production retry policy. Preserve the
// original verified invocation and permanent command identity across uncertainty.
async fn accepted_on_current_leader(
    f: &Fixture,
    request: LifecycleAuthorityRequest,
) -> (Arc<IndependentAuthority>, SignedLifecycleAuthorityReceipt) {
    let context = f.context("operator");
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let service = f.leader().await;
            match service
                .execute_lifecycle(context.clone(), request.clone())
                .await
            {
                Ok((receipt, fence)) => {
                    if fence.release().await.is_ok() {
                        return (service, receipt);
                    }
                }
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::Unavailable | ErrorCode::UnknownOutcome
                    ) => {}
                Err(error) => panic!("definitive setup rejection: {error:?}"),
            }
            // A retry uses the same exact original command. No absent/read error
            // is interpreted as a stop or rollback of a possibly committed result.
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("bounded setup recovery did not obtain current-quorum receipt")
}
