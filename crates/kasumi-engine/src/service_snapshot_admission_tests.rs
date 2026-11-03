fn snapshot_admission_request(id: &str) -> ReadSnapshotRequest {
    ReadSnapshotRequest {
        documents: vec![DocumentKey {
            collection: "docs".into(),
            id: id.into(),
        }],
        queries: vec![],
        time_bounds: None,
    }
}

#[tokio::test]
async fn snapshot_admission_queues_input_without_workspace_and_selects_fresh_generation() {
    let fixture = CredentialFixture::new().await;
    let request = snapshot_admission_request("after-wait");
    let workspace = snapshot_workspace(
        &fixture.db.engine.generation().unwrap().state.limits,
        &request,
    )
    .unwrap();
    let slots = fixture.db.query_slots.clone();
    let held = slots.clone().acquire_many_owned(4).await.unwrap();
    let before = fixture.db.admission().snapshot();
    let mut waiting: Vec<_> = (0..8)
        .map(|_| Box::pin(fixture.db.read_snapshot(&fixture.context, request.clone())))
        .collect();
    std::future::poll_fn(|cx| {
        for read in &mut waiting {
            assert!(read.as_mut().poll(cx).is_pending());
        }
        Poll::Ready(())
    })
    .await;
    let queued = fixture.db.admission().snapshot();
    assert_eq!(queued.inflight_operations, before.inflight_operations);
    assert_eq!(queued.live_reservations, before.live_reservations + 8);
    assert!(queued.reserved_bytes - before.reserved_bytes < workspace / 10);
    fixture
        .db
        .mutate(fixture.context.clone(), credential_batch("after-wait"))
        .await
        .unwrap();
    let revision = fixture.db.engine.generation().unwrap().state.revision;
    drop(held);
    for read in waiting {
        let output = read.await.unwrap();
        assert_eq!(output.revision, revision);
        assert_eq!(
            output.documents[0].document.as_ref().unwrap().body,
            json!({"value":7})
        );
    }
    assert_eq!(slots.available_permits(), 4);
    fixture.close().await;
}

#[tokio::test]
async fn snapshot_admission_rechecks_policy_and_original_credential_after_wait() {
    for expire_credential in [false, true] {
        let fixture = CredentialFixture::new().await;
        let clock = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
        let context = fixture.credential(clock.clone());
        let slots = fixture.db.query_slots.clone();
        let held = slots.clone().acquire_many_owned(4).await.unwrap();
        let mut waiting = Box::pin(
            fixture
                .db
                .read_snapshot(&context, snapshot_admission_request("a")),
        );
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        if expire_credential {
            clock.0.store(1000, Ordering::SeqCst);
        } else {
            let mut policy = fixture.db.engine.generation().unwrap().state.policy.clone();
            for grant in &mut policy.grants {
                grant.actions.remove(&Action::Read);
            }
            fixture
                .db
                .administer(fixture.context.clone(), Operation::SetPolicy(policy))
                .await
                .unwrap();
        }
        drop(held);
        let error = waiting.await.unwrap_err();
        assert!(matches!(
            error.code,
            ErrorCode::Unauthorized | ErrorCode::Forbidden
        ));
        assert_eq!(slots.available_permits(), 4);
        fixture.close().await;
    }
}

#[tokio::test]
async fn snapshot_admission_caller_drop_retires_queued_input_without_consuming_a_worker() {
    let fixture = CredentialFixture::new().await;
    let slots = fixture.db.query_slots.clone();
    let held = slots.clone().acquire_many_owned(4).await.unwrap();
    let before = fixture.db.admission().snapshot();
    let mut waiting = Box::pin(
        fixture
            .db
            .read_snapshot(&fixture.context, snapshot_admission_request("a")),
    );
    std::future::poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(fixture.db.admission().snapshot().reserved_bytes > before.reserved_bytes);
    drop(waiting);
    fixture.db.work.drain().await;
    assert_eq!(
        fixture.db.admission().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.db.admission().snapshot().live_reservations,
        before.live_reservations
    );
    assert_eq!(slots.available_permits(), 0);
    drop(held);
    assert_eq!(slots.available_permits(), 4);
    fixture.close().await;
}

#[tokio::test]
async fn snapshot_admission_deadline_includes_queue_and_strict_audit_without_holding_workers() {
    let fixture = snapshot_audit_fixture().await;
    let slots = fixture.db.query_slots.clone();
    let held = slots.clone().acquire_many_owned(4).await.unwrap();
    let gate = fixture.db.proposal_gate.lock().await;
    let mut waiting = Box::pin(
        fixture
            .db
            .read_snapshot(&fixture.context, snapshot_audit_request()),
    );
    std::future::poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    // Spend most of the one native-read deadline in the worker queue. The
    // blocked strict audit must consume its remainder, not start a new timer.
    tokio::time::sleep(kasumi_store::NATIVE_READ_TIMEOUT - Duration::from_secs(2)).await;
    drop(held);
    // The FIFO semaphore has assigned one permit to this queued read even
    // before it is polled again, so a fast blocking worker cannot hide entry.
    assert_eq!(slots.available_permits(), 3);
    tokio::time::timeout(
        Duration::from_secs(1),
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            if slots.available_permits() == 4 {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }),
    )
    .await
    .unwrap();
    // The worker has released all four permits while the strict audit waits.
    assert_eq!(slots.available_permits(), 4);
    let error = tokio::time::timeout(Duration::from_secs(3), waiting)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    drop(gate);
    assert!(
        fixture
            .db
            .engine
            .generation()
            .unwrap()
            .state
            .audits
            .iter()
            .all(|event| event.action != "read")
    );
    fixture.close().await;
}
