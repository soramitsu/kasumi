fn guarded_request(fixture: &CredentialFixture, id: &str, deadline: u64) -> StopStagedTransaction {
    let current = fixture.db.engine.generation().unwrap();
    let chunk = StagedChunk {
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: id.into(),
            expected: Precondition::Absent,
            body: json!({"value": id}),
        }],
    };
    StopStagedTransaction {
        original: BeginStagedTransaction {
            transaction_id: id.into(),
            manifest: StagedManifest::from_chunks(&[chunk]).unwrap(),
            ttl_ms: 60_000,
        },
        admission: vec![
            ReadAssertion::Snapshot {
                incarnation: current.state.incarnation.clone(),
                policy_epoch: current.state.policy_epoch,
                schema_epoch: current.state.schema_epoch,
            },
            ReadAssertion::Before {
                not_after_ms: deadline,
            },
            ReadAssertion::Document {
                collection: "docs".into(),
                id: "guard".into(),
                expected: current.state.collections["docs"]
                    .documents
                    .get("guard")
                    .map_or(ReadPrecondition::Absent, |document| {
                        ReadPrecondition::Version(document.version)
                    }),
            },
        ],
    }
}

#[tokio::test]
async fn guarded_stop_queued_deadline_and_cancellation_leave_only_actual_durable_outcomes() {
    let fixture = CredentialFixture::new().await;
    let base = now_ms().unwrap();
    let clock = Arc::new(ControlledCommandClock(std::sync::atomic::AtomicU64::new(
        base,
    )));
    *fixture.db.command_clock.lock().unwrap() = clock.clone();
    for (id, cancel, expired) in [
        ("expired", false, true),
        ("canceled-expired", true, true),
        ("canceled-valid", true, false),
    ] {
        clock.0.store(base, Ordering::SeqCst);
        let request = guarded_request(&fixture, id, base + 10);
        let reference = request.original.reference().unwrap();
        let gate = fixture.db.proposal_gate.lock().await;
        let mut pending = Box::pin(
            fixture
                .db
                .stop_staged_transaction(fixture.context.clone(), request),
        );
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        clock
            .0
            .store(base + if expired { 11 } else { 10 }, Ordering::SeqCst);
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
            .staged_transaction_status(&fixture.context, &reference)
            .await;
        if expired {
            assert_eq!(status.unwrap_err().code, ErrorCode::NotFound);
        } else {
            assert!(matches!(
                status.unwrap().outcome,
                StagedOutcome::Aborted { .. }
            ));
        }
    }
    fixture.close().await;
}

#[tokio::test]
async fn queued_stop_checks_authority_after_an_earlier_ordered_write() {
    let fixture = CredentialFixture::new().await;
    let request = guarded_request(&fixture, "queued-authority", now_ms().unwrap() + 60_000);
    let reference = request.original.reference().unwrap();
    let gate = fixture.db.proposal_gate.lock().await;
    let mut change = Box::pin(
        fixture
            .db
            .mutate(fixture.context.clone(), credential_batch("guard")),
    );
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(change.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    // Poll the already spawned proposal before admitting the second request;
    // Tokio's mutex preserves the queue's acquisition order.
    tokio::task::yield_now().await;
    let mut stop = Box::pin(
        fixture
            .db
            .stop_staged_transaction(fixture.context.clone(), request),
    );
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(stop.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(gate);
    change.await.unwrap();
    assert_eq!(stop.await.unwrap_err().code, ErrorCode::Conflict);
    assert_eq!(
        fixture
            .db
            .staged_transaction_status(&fixture.context, &reference)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    fixture.close().await;
}

#[tokio::test]
async fn accepted_stop_release_failure_is_unknown_and_reopen_recovers_exact_tombstone() {
    let fixture = CredentialFixture::new().await;
    let request = guarded_request(&fixture, "release-closed", now_ms().unwrap() + 60_000);
    let reference = request.original.reference().unwrap();
    let status = fixture
        .db
        .stop_staged_transaction(fixture.context.clone(), request.clone())
        .await
        .unwrap();
    let receipt = match &status.outcome {
        StagedOutcome::Aborted { receipt } => receipt.clone(),
        other => panic!("unexpected: {other:?}"),
    };
    // Exercise the exact post-Raft acknowledgement boundary with an actual
    // accepted result. Shutdown occurs before those pending result bytes release.
    let pending_bytes = serde_json::to_vec(&Ok::<_, Error>(receipt)).unwrap();
    fixture.db.shutdown().await.unwrap();
    assert_eq!(
        fixture
            .db
            .release_submitted_response(&fixture.context, &pending_bytes)
            .await
            .unwrap_err()
            .code,
        ErrorCode::UnknownOutcome
    );
    let rejection = serde_json::to_vec(&Err::<WriteReceipt, _>(Error::new(
        ErrorCode::Conflict,
        "ordered rejection",
    )))
    .unwrap();
    assert_eq!(
        fixture
            .db
            .release_submitted_response(&fixture.context, &rejection)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let CredentialFixture {
        _directory: directory,
        db,
        audit,
        context,
    } = fixture;
    audit.shutdown().await;
    drop(db);
    drop(audit);
    let node = NodeStore::open(directory.path().join("node.redb")).unwrap();
    let provider = Arc::new(LocalKeyProvider::new([0x97; 32]));
    let audit = SecurityAudit::open(
        TenantStore::open(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            provider.clone(),
        )
        .await
        .unwrap(),
        100_000,
    )
    .unwrap();
    let application = TenantStore::open(node, context.tenant.clone(), provider)
        .await
        .unwrap();
    let stores = kasumi_store::test_utils::with_custody(
        application,
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await
    .unwrap();
    let db = crate::open_local(
        stores,
        Policy {
            grants: vec![Grant {
                principal: context.principal.clone(),
                collection: None,
                actions: context.scopes.clone(),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        db.stop_staged_transaction(context.clone(), request)
            .await
            .unwrap()
            .outcome,
        status.outcome
    );
    assert!(
        db.finalize_staged_transaction(context, reference)
            .await
            .is_err()
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await;
}

#[tokio::test]
async fn retained_stop_response_fence_expires_without_changing_permanent_outcome() {
    let fixture = CredentialFixture::new().await;
    let base = now_ms().unwrap();
    let clock = Arc::new(ControlledCommandClock(std::sync::atomic::AtomicU64::new(
        base,
    )));
    *fixture.db.command_clock.lock().unwrap() = clock.clone();
    let request = guarded_request(&fixture, "expired-response", base + 10);
    let fence = fixture
        .db
        .staged_stop_response_fence(&fixture.context, &request)
        .unwrap();
    let accepted = fixture
        .db
        .stop_staged_transaction(fixture.context.clone(), request.clone())
        .await
        .unwrap();
    let _encoded = serde_json::to_vec(&accepted).unwrap();
    clock.0.store(base + 11, Ordering::SeqCst);
    assert_eq!(fence.check().unwrap_err().code, ErrorCode::Conflict);
    drop(fence);
    let mut fresh = request;
    fresh.admission = guarded_request(&fixture, "expired-response", base + 100).admission;
    assert_eq!(
        fixture
            .db
            .stop_staged_transaction(fixture.context.clone(), fresh)
            .await
            .unwrap()
            .outcome,
        accepted.outcome
    );
    fixture.close().await;
}

#[tokio::test]
async fn queued_stop_credential_expiry_never_accepts_missing_identity() {
    let fixture = CredentialFixture::new().await;
    let elapsed = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
    let context = fixture.credential(elapsed.clone());
    let request = guarded_request(
        &fixture,
        "expired-credential-stop",
        now_ms().unwrap() + 60_000,
    );
    let reference = request.original.reference().unwrap();
    let gate = fixture.db.proposal_gate.lock().await;
    let mut pending = Box::pin(fixture.db.stop_staged_transaction(context, request));
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    elapsed.0.store(1000, Ordering::SeqCst);
    drop(gate);
    assert_eq!(pending.await.unwrap_err().code, ErrorCode::Unauthorized);
    assert_eq!(
        fixture
            .db
            .staged_transaction_status(&fixture.context, &reference)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    fixture.close().await;
}
