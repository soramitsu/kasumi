async fn retirement_input(
    fixture: &CredentialFixture,
    id: &str,
    deadline: u64,
) -> PreparedRetirement {
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            fixture._directory.path().join(id),
            16 << 20,
        )
        .unwrap(),
    );
    fixture
        .db
        .install_archive_destination(id.into(), destination.clone())
        .unwrap();
    let checkpoint = fixture
        .db
        .backup_checkpoint(fixture.context.clone(), destination.as_ref())
        .await
        .unwrap();
    let request = RetireSourceRequest {
        retirement_id: id.into(),
        expected_source_incarnation: checkpoint.source_incarnation().into(),
        target_incarnation: uuid::Uuid::new_v4().to_string(),
        checkpoint: checkpoint.checkpoint().clone(),
        destination: id.into(),
        not_after_ms: deadline,
    };
    let verified_closure_digest = fixture
        .db
        .verified_retirement_closure(
            &fixture.context,
            destination.as_ref(),
            request.checkpoint.clone(),
        )
        .await
        .unwrap();
    PreparedRetirement {
        request,
        verified_closure_digest,
        observation: None,
    }
}

#[tokio::test]
async fn queued_retirement_uses_trusted_admission_deadline_and_cancellation_keeps_exact_outcome() {
    for (cancel, expired) in [(false, true), (true, true), (true, false)] {
        let fixture = CredentialFixture::new().await;
        let clock = Arc::new(ControlledCommandClock(std::sync::atomic::AtomicU64::new(
            1000,
        )));
        *fixture.db.command_clock.lock().unwrap() = clock.clone();
        let prepared = retirement_input(&fixture, "queued-retirement", 1000).await;
        let reference = prepared.request.reference().unwrap();
        let gate = fixture.db.proposal_gate.lock().await;
        let mut pending = Box::pin(
            fixture
                .db
                .submit(fixture.context.clone(), Operation::RetireSource(prepared)),
        );
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        if expired {
            clock.0.store(1001, Ordering::SeqCst);
        }
        if cancel {
            drop(pending);
            drop(gate);
            fixture.db.work.drain().await;
        } else {
            drop(gate);
            assert_eq!(pending.await.unwrap_err().code, ErrorCode::Conflict);
        }
        let status = fixture
            .db
            .retirement_status(&fixture.context, &reference)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.outcome.is_err(), expired);
        assert_eq!(
            fixture.db.engine.generation().unwrap().state.retired,
            !expired
        );
        if !expired {
            clock.0.store(10_000, Ordering::SeqCst);
            let proof = fixture
                .db
                .verify_retirement_receipt(fixture.context.clone(), &reference)
                .await
                .unwrap();
            assert_eq!(proof.receipt().admitted_at_ms, 1000);
        }
        fixture.close().await;
    }
}

#[tokio::test]
async fn queued_expired_credential_cannot_accept_retirement_or_its_id() {
    let fixture = CredentialFixture::new().await;
    let prepared = retirement_input(&fixture, "credential-retirement", u64::MAX).await;
    let reference = prepared.request.reference().unwrap();
    let clock = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
    let context = fixture.credential(clock.clone());
    let gate = fixture.db.proposal_gate.lock().await;
    let mut pending = Box::pin(
        fixture
            .db
            .submit(context, Operation::RetireSource(prepared)),
    );
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    clock.0.store(1000, Ordering::SeqCst);
    drop(pending);
    drop(gate);
    fixture.db.work.drain().await;
    assert!(
        fixture
            .db
            .retirement_status(&fixture.context, &reference)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!fixture.db.engine.generation().unwrap().state.retired);
    fixture.close().await;
}

struct RetirementObservedClock(std::sync::Weak<TenantEngine>);
impl LeaseClock for RetirementObservedClock {
    fn now(&self) -> Duration {
        let retired = self
            .0
            .upgrade()
            .and_then(|engine| engine.generation().ok())
            .is_some_and(|generation| generation.state.retired);
        Duration::from_millis(if retired { 1000 } else { 0 })
    }
}
#[tokio::test]
async fn committed_retirement_with_expired_reply_has_fresh_authorized_receipt_recovery() {
    let fixture = CredentialFixture::new().await;
    let prepared = retirement_input(&fixture, "uncertain-retirement", u64::MAX).await;
    let reference = prepared.request.reference().unwrap();
    let credential = fixture.credential(Arc::new(RetirementObservedClock(Arc::downgrade(
        &fixture.db.engine,
    ))));
    assert_eq!(
        fixture
            .db
            .retire_source(credential.clone(), prepared.request)
            .await
            .unwrap_err()
            .code,
        ErrorCode::UnknownOutcome
    );
    assert_eq!(
        fixture
            .db
            .verify_retirement_receipt(credential, &reference)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Unauthorized
    );
    let proof = fixture
        .db
        .verify_retirement_receipt(fixture.context.clone(), &reference)
        .await
        .unwrap();
    assert_eq!(proof.receipt().retirement_id, "uncertain-retirement");
    assert_eq!(
        fixture
            .db
            .engine
            .generation()
            .unwrap()
            .state
            .retirements
            .len(),
        1
    );
    fixture.close().await;
}

#[tokio::test]
async fn generic_administration_cannot_inject_a_claimed_retirement_preparation() {
    let fixture = CredentialFixture::new().await;
    let prepared = retirement_input(&fixture, "forged-preparation", u64::MAX).await;
    for operation in [
        Operation::RetireSource(prepared.clone()),
        Operation::AbortRetirement(prepared.request),
    ] {
        assert_eq!(
            fixture
                .db
                .administer(fixture.context.clone(), operation)
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    assert!(
        fixture
            .db
            .engine
            .generation()
            .unwrap()
            .state
            .retirements
            .is_empty()
    );
    fixture.close().await;
}
