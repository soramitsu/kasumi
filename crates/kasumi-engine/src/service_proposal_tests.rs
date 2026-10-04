fn merge_patch_workspace_fixture() -> (TenantState, RequestContext) {
    let context = RequestContext::trusted(
        "patch-workspace",
        "owner",
        [Action::Read, Action::Write, Action::Admin],
    );
    let state = TenantEngine::new(
        context.tenant.clone(),
        "incarnation".into(),
        Policy {
            grants: vec![Grant {
                principal: context.principal.clone(),
                collection: None,
                actions: context.scopes.clone(),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )
    .unwrap()
    .generation()
    .unwrap()
    .state
    .clone();
    (state, context)
}

#[test]
fn merge_patch_proposal_workspace_covers_limits_raised_while_queued() {
    let (mut state, context) = merge_patch_workspace_fixture();
    state.limits.max_document_bytes = 4096;
    state.limits.max_batch_bytes = 4096;
    let patch = Operation::Mutate(MutationBatch::new().patch("docs", "a", json!({})));
    assert_eq!(
        merge_patch_proposal_workspace(&patch, &state, &state, &context).unwrap(),
        3 << 20
    );
    let mut many = MutationBatch::new();
    for index in 0..256 {
        many = many.patch("docs", index.to_string(), json!({}));
    }
    assert_eq!(
        merge_patch_proposal_workspace(&Operation::Mutate(many), &state, &state, &context).unwrap(),
        3 * (8 << 20)
    );
    let put = Operation::Mutate(MutationBatch::new().upsert("docs", "a", json!({})));
    assert_eq!(
        merge_patch_proposal_workspace(&put, &state, &state, &context).unwrap(),
        0
    );
}

#[test]
fn staged_merge_patch_workspace_matches_live_chunks_to_the_header_read() {
    let (state, context) = merge_patch_workspace_fixture();
    for patches in [false, true] {
        let mut current = state.clone();
        let chunk = StagedChunk {
            read_set: vec![],
            operations: (0..100)
                .map(|index| {
                    if patches {
                        Mutation::patch("docs", index.to_string(), json!({}), Precondition::Any)
                    } else {
                        Mutation::put("docs", index.to_string(), json!({}), Precondition::Any)
                    }
                })
                .collect(),
        };
        let manifest = StagedManifest::from_chunks(std::slice::from_ref(&chunk)).unwrap();
        let stage = StagedTransaction {
            scope: StagedTransactionScope {
                tenant: context.tenant.clone(),
                incarnation: current.incarnation.clone(),
                principal: context.principal.clone(),
            },
            transaction_id: "stage".into(),
            manifest_digest: staged_digest(&manifest).unwrap().0,
            manifest,
            chunks: BTreeMap::from([(0, Arc::new(chunk))]),
            stored_chunk_bytes: 0,
            uploaded_payload_bytes: 0,
            uploaded_operations: 100,
            uploaded_read_assertions: 0,
            expires_at_ms: Some(u64::MAX),
            ttl_ms: 60_000,
            outcome: StagedOutcome::Uploading,
        };
        let reference = stage.status().transaction;
        let key = crate::state::staging::identity(&context.principal, "stage").unwrap();
        current.staged_transactions.insert(key.clone(), stage);
        // read_staged_identity strips chunks from its admitted header view.
        let mut header = current.clone();
        header
            .staged_transactions
            .get_mut(&key)
            .unwrap()
            .chunks
            .clear();
        let operation = Operation::FinalizeStaged(reference);
        assert_eq!(
            merge_patch_proposal_workspace(&operation, &header, &current, &context).unwrap(),
            if patches { 3 * (64 << 20) } else { 0 }
        );
        // Missing chunks could be uploaded before ordered finalization, so
        // even a currently empty header must reserve the declared envelope.
        assert_eq!(
            merge_patch_proposal_workspace(&operation, &header, &header, &context).unwrap(),
            3 * (64 << 20)
        );
        header.staged_transactions.get_mut(&key).unwrap().outcome = StagedOutcome::Finished {
            outcome: Ok(WriteReceipt {
                revision: 1,
                versions: BTreeMap::new(),
            }),
        };
        assert_eq!(
            merge_patch_proposal_workspace(&operation, &header, &current, &context).unwrap(),
            0,
            "terminal replay copies no source documents"
        );
    }
}

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
            .expect("document exists")
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
            .any(|issue| kasumi_types::drain::DrainIssueRef::ptr_eq(actual, issue))
    );
    fixture.audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn actual_raft_leadership_redirect_does_not_poison_proposal_custody() {
    let fixture = CredentialFixture::new().await;
    let raft = fixture.db.group.raft();
    raft.runtime_config().elect(false);
    let gate = fixture.db.proposal_gate.lock().await;
    let batch = credential_batch("leadership-change-proposal");
    let mut request = Box::pin(fixture.db.mutate(fixture.context.clone(), batch.clone()));
    std::future::poll_fn(|cx| {
        assert!(request.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;

    // Exercise the real OpenRaft write path after its original leader observes
    // a higher committed vote. Disable automatic elections until the response
    // is observed; the retained request is already admitted behind the gate.
    let metrics = raft.metrics().borrow().clone();
    raft.append_entries(openraft::raft::AppendEntriesRequest {
        vote: openraft::Vote::new_committed(metrics.current_term + 1, 2),
        prev_log_id: metrics.last_applied,
        entries: vec![],
        leader_commit: metrics.last_applied,
    })
    .await
    .unwrap();
    raft.wait(Some(Duration::from_secs(5)))
        .current_leader(2, "proposal fixture observed a new leader")
        .await
        .unwrap();
    drop(gate);
    assert_eq!(request.await.unwrap_err().code, ErrorCode::UnknownOutcome);
    fixture.db.proposals.check().unwrap();
    fixture.db.check_serving().unwrap();

    // The one-voter fixture can elect itself again. The original identity has
    // no accepted receipt and may now be retried without recreating Database.
    raft.trigger().elect().await.unwrap();
    raft.wait(Some(Duration::from_secs(5)))
        .current_leader(1, "proposal fixture recovered its leader")
        .await
        .unwrap();
    assert!(
        fixture
            .db
            .operation_receipt(&fixture.context, &batch.idempotency_key)
            .await
            .unwrap()
            .is_none()
    );
    let receipt = fixture
        .db
        .mutate(fixture.context.clone(), batch.clone())
        .await
        .unwrap();
    assert_eq!(
        fixture
            .db
            .mutate(fixture.context.clone(), batch)
            .await
            .unwrap(),
        receipt
    );
    fixture.close().await;
}

#[tokio::test]
async fn retirement_workspace_rejection_is_definite_and_does_not_poison_custody() {
    let fixture = CredentialFixture::new().await;
    let prepared = retirement_input(&fixture, "retirement-workspace-pressure", u64::MAX).await;
    let reference = prepared.request.reference().unwrap();
    let gate = fixture.db.proposal_gate.lock().await;
    let mut request = Box::pin(
        fixture
            .db
            .submit(fixture.context.clone(), Operation::RetireSource(prepared)),
    );
    std::future::poll_fn(|cx| {
        assert!(request.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    // Fill the original governor's finite operation slots after outer command
    // admission. The actual closure workspace reservation must reject in run.
    let mut pressure = Vec::new();
    loop {
        match fixture.db.admission().reserve(0, None) {
            Ok(reservation) => pressure.push(reservation),
            Err(error) => {
                assert_eq!(error.code, ErrorCode::ResourceExhausted);
                break;
            }
        }
    }
    drop(gate);
    assert_eq!(
        request.await.unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    fixture.db.proposals.check().unwrap();
    fixture.db.check_serving().unwrap();
    drop(pressure);
    assert!(
        fixture
            .db
            .retirement_status(&fixture.context, &reference)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!fixture.db.engine.generation().unwrap().state.retired);
    fixture
        .db
        .mutate(
            fixture.context.clone(),
            credential_batch("after-workspace-rejection"),
        )
        .await
        .unwrap();
    fixture.close().await;
}
