#[tokio::test]
async fn cancelled_submit_keeps_actual_proposal_until_original_identity_is_resolvable() {
    let fixture = CredentialFixture::new().await;
    let gate = fixture.db.proposal_gate.lock().await;
    let batch = credential_batch("cancelled-owned-proposal");
    let mut request = Box::pin(fixture.db.mutate(fixture.context.clone(), batch.clone()));
    std::future::poll_fn(|cx| {
        assert!(request.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(request);
    let held = fixture.db.admission().snapshot();
    assert!(held.inflight_operations > 0);
    let mut work = Box::pin(fixture.db.work.drain());
    std::future::poll_fn(|cx| {
        assert!(work.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(gate);
    tokio::time::timeout(Duration::from_secs(5), work)
        .await
        .unwrap();
    let original = fixture
        .db
        .operation_receipt(&fixture.context, &batch.idempotency_key)
        .await
        .unwrap()
        .unwrap()
        .outcome
        .unwrap();
    assert_eq!(
        fixture
            .db
            .mutate(fixture.context.clone(), batch)
            .await
            .unwrap(),
        original
    );
    assert_eq!(
        fixture
            .db
            .get(&fixture.context, "docs", "cancelled-owned-proposal")
            .await
            .unwrap()
            .body,
        json!({"value":7})
    );
    fixture.close().await;
}

#[tokio::test]
async fn cancelled_database_shutdown_joins_actual_proposal_panic_before_raft_shutdown() {
    struct PanickingProposalClock;
    impl CommandClock for PanickingProposalClock {
        fn now_ms(&self) -> Result<u64> {
            panic!("actual proposal admission clock panic")
        }
    }
    let fixture = CredentialFixture::new().await;
    *fixture.db.command_clock.lock().unwrap() = Arc::new(PanickingProposalClock);
    let gate = fixture.db.proposal_gate.lock().await;
    let mut request = Box::pin(
        fixture
            .db
            .mutate(fixture.context.clone(), credential_batch("proposal-panic")),
    );
    std::future::poll_fn(|cx| {
        assert!(request.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(request);
    let mut drain = Box::pin(fixture.db.shutdown());
    tokio::time::timeout(
        Duration::from_secs(5),
        std::future::poll_fn(|cx| {
            assert!(drain.as_mut().poll(cx).is_pending());
            if fixture.db.proposals.check().is_err() {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }),
    )
    .await
    .unwrap();
    drop(drain);
    // The cancelled waiter cannot stop the live Raft group while its admitted
    // proposal still owns the ordering gate and original command workspace.
    assert!(fixture.db.group.check_access().is_ok());
    drop(gate);
    let failed = tokio::time::timeout(Duration::from_secs(5), fixture.db.shutdown())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failed.completion(), DrainCompletion::Complete);
    let actual = failed
        .issues()
        .iter()
        .find(|issue| issue.component() == "background worker")
        .unwrap();
    assert!(
        actual
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_panic()
    );
    let repeated = fixture.db.shutdown().await.unwrap_err();
    assert!(
        repeated
            .issues()
            .iter()
            .any(|issue| Arc::ptr_eq(actual, issue))
    );
    fixture.audit.shutdown().await.unwrap();
}
