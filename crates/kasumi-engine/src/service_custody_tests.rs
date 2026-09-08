async fn credential_custody_fixture() -> (CredentialFixture, Arc<RetiredCustody>, RetirementRef) {
    let fixture = CredentialFixture::new().await;
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            fixture._directory.path().join("custody-backup"),
            32 << 20,
        )
        .unwrap(),
    );
    fixture
        .db
        .install_archive_destination("custody-approved".into(), destination.clone())
        .unwrap();
    let checkpoint = fixture
        .db
        .backup_checkpoint(fixture.context.clone(), destination.as_ref(), uuid::Uuid::new_v4())
        .await
        .unwrap();
    let request = RetireSourceRequest {
        retirement_id: "credential-custody".into(),
        expected_source_incarnation: checkpoint.source_incarnation().into(),
        target_incarnation: uuid::Uuid::new_v4().to_string(),
        checkpoint: checkpoint.checkpoint().clone(),
        destination: "custody-approved".into(),
        not_after_ms: u64::MAX,
    };
    fixture
        .db
        .retire_source(fixture.context.clone(), request.clone())
        .await
        .unwrap();
    let custody = fixture.db.retired_custody().unwrap();
    (fixture, custody, request.reference().unwrap())
}
fn credential_custody_rotation(reference: &RetirementRef, id: &str, epoch: u64) -> CustodyRequest {
    CustodyRequest {
        retirement: reference.clone(),
        command_id: id.into(),
        expected_policy_epoch: epoch,
        not_after_ms: u64::MAX,
        action: CustodyAction::ReplaceAdministrators(BTreeSet::from([
            "owner".into(),
            "custodian".into(),
        ])),
    }
}

#[tokio::test]
async fn queued_custody_credentials_expire_without_accepting_a_permanent_identity() {
    let (fixture, custody, reference) = credential_custody_fixture().await;
    for (epoch, cancel) in [(1, false), (2, true)] {
        let clock = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
        let context = fixture.credential(clock.clone());
        let request = credential_custody_rotation(
            &reference,
            if cancel {
                "cancelled-custody"
            } else {
                "queued-custody"
            },
            epoch,
        );
        let gate = fixture.db.proposal_gate.lock().await;
        let mut queued = Box::pin(custody.execute(context, request.clone()));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(queued.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        clock.0.store(1000, Ordering::SeqCst);
        if cancel {
            drop(queued);
            drop(gate);
            fixture.db.work.drain().await;
        } else {
            drop(gate);
            assert_eq!(queued.await.unwrap_err().code, ErrorCode::Unauthorized);
        }
        assert_eq!(
            fixture
                .db
                .raft_group()
                .custody_view()
                .unwrap()
                .policy_epoch(),
            epoch
        );
        // A genuine first accepted attempt still succeeds; expiry cannot leave
        // a hidden failed identity that would supersede this exact request.
        custody
            .execute(fixture.context.clone(), request)
            .await
            .unwrap()
            .outcome
            .unwrap();
    }
    drop(custody);
    fixture.close().await;
}

struct CustodyCommitObservedClock(RaftGroup);
impl LeaseClock for CustodyCommitObservedClock {
    fn now(&self) -> Duration {
        Duration::from_millis(
            if self
                .0
                .custody_view()
                .is_ok_and(|view| view.policy_epoch() > 1)
            {
                1000
            } else {
                0
            },
        )
    }
}
#[tokio::test]
async fn committed_custody_with_expired_ack_recovers_only_with_fresh_authority() {
    let (fixture, custody, reference) = credential_custody_fixture().await;
    let context = fixture.credential(Arc::new(CustodyCommitObservedClock(
        fixture.db.raft_group().clone(),
    )));
    let request = credential_custody_rotation(&reference, "committed-custody", 1);
    assert_eq!(
        custody
            .execute(context.clone(), request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::UnknownOutcome
    );
    assert!(custody.response_fence(&context).is_err());
    assert_eq!(
        custody
            .verify_retirement_receipt(context, &reference)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Unauthorized
    );
    let receipt = custody
        .execute(fixture.context.clone(), request.clone())
        .await
        .unwrap();
    receipt.outcome.clone().unwrap();
    assert_eq!(
        custody
            .execute(fixture.context.clone(), request)
            .await
            .unwrap(),
        receipt
    );
    drop(custody);
    fixture.close().await;
}

#[tokio::test]
async fn custody_observations_preserve_mutation_capacity_and_exhaustion_can_expand() {
    let (fixture, custody, reference) = credential_custody_fixture().await;
    let bounded = CustodyRequest {
        retirement: reference.clone(),
        command_id: "bounded-custody".into(),
        expected_policy_epoch: 1,
        not_after_ms: u64::MAX,
        action: CustodyAction::SetLimits(CustodyLimits {
            max_commands: 1,
            max_audit_records: 1,
            max_state_bytes: 4096,
        }),
    };
    custody
        .execute(fixture.context.clone(), bounded)
        .await
        .unwrap()
        .outcome
        .unwrap();
    let before = fixture.db.raft_group().custody_view().unwrap().revision();
    for _ in 0..20 {
        custody.status(&fixture.context, &reference).await.unwrap();
        custody
            .verify_retirement_receipt(fixture.context.clone(), &reference)
            .await
            .unwrap();
    }
    assert_eq!(
        fixture.db.raft_group().custody_view().unwrap().revision(),
        before
    );
    let observations = fixture
        .audit
        .store()
        .scan("security.audit")
        .unwrap()
        .into_iter()
        .filter_map(|(_, bytes)| {
            let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            (record["event"]["kind"]["retirement_observed"]["custody_policy_epoch"] == 2)
                .then_some(record)
        })
        .collect::<Vec<_>>();
    assert_eq!(observations.len(), 40);
    for record in observations {
        let observation = &record["event"]["kind"]["retirement_observed"];
        assert_eq!(
            observation["source_incarnation"],
            reference.source_incarnation
        );
        assert_eq!(observation["retirement_id"], reference.retirement_id);
        assert_eq!(observation["request_digest"], reference.request_digest);
        assert_eq!(observation["custody_policy_epoch"], 2);
        assert_eq!(record["event"]["principal"], fixture.context.principal);
    }
    let rotation = credential_custody_rotation(&reference, "after-full-budget", 2);
    assert_eq!(
        custody
            .execute(fixture.context.clone(), rotation)
            .await
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    let expansion = CustodyRequest {
        retirement: reference.clone(),
        command_id: "expand-full-custody".into(),
        expected_policy_epoch: 2,
        not_after_ms: u64::MAX,
        action: CustodyAction::SetLimits(CustodyLimits {
            max_commands: 4,
            max_audit_records: 4,
            max_state_bytes: 16384,
        }),
    };
    custody
        .execute(fixture.context.clone(), expansion)
        .await
        .unwrap()
        .outcome
        .unwrap();
    custody
        .execute(
            fixture.context.clone(),
            credential_custody_rotation(&reference, "after-expansion", 3),
        )
        .await
        .unwrap()
        .outcome
        .unwrap();
    assert_eq!(
        custody
            .status(&fixture.context, &reference)
            .await
            .unwrap()
            .policy_epoch,
        4
    );
    // An unavailable durable observation audit must not release a fresh proof.
    fixture.audit.store().seal();
    assert!(
        custody
            .verify_retirement_receipt(fixture.context.clone(), &reference)
            .await
            .is_err()
    );
    drop(custody);
    fixture.close().await;
}
