#[tokio::test]
async fn permanent_receipt_public_retry_survives_expiry_era_and_lowered_batch_limits() {
    let fixture = CredentialFixture::new().await;
    let db = &fixture.db;
    let context = &fixture.context;
    let base = now_ms().unwrap();
    let clock = Arc::new(ControlledCommandClock(std::sync::atomic::AtomicU64::new(
        base,
    )));
    *db.command_clock.lock().unwrap() = clock.clone();
    let original = MutationBatch {
        idempotency_key: "original".into(),
        read_set: vec![],
        operations: (0..8)
            .map(|i| Mutation::Put {
                collection: "docs".into(),
                id: format!("row-{i}"),
                body: json!({"value": "x".repeat(32 << 10)}),
                expected: Precondition::Absent,
            })
            .collect(),
    };
    let committed = db.mutate(context.clone(), original.clone()).await.unwrap();
    let original_head = db
        .engine
        .generation()
        .unwrap()
        .state
        .mutation_receipt_head
        .clone();
    let mut limits = db.engine.generation().unwrap().state.limits.clone();
    limits.max_document_bytes = 64 << 10;
    limits.max_batch_bytes = 64 << 10;
    limits.max_batch_operations = 1;
    db.administer(context.clone(), Operation::SetLimits(limits))
        .await
        .unwrap();
    clock.0.store(base + 86_401_000, Ordering::SeqCst);
    assert_eq!(
        db.mutate(context.clone(), original.clone()).await.unwrap(),
        committed
    );
    assert_eq!(
        db.engine.generation().unwrap().state.mutation_receipt_head,
        original_head
    );
    assert_eq!(db.engine.generation().unwrap().state.document_count, 8);
    let lookup = db
        .operation_receipt(context, "original")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lookup.outcome, Ok(committed.clone()));
    assert_eq!(lookup.request_digest, original.digest().unwrap());

    let mut new_identity = original.clone();
    new_identity.idempotency_key = "new-identity".into();
    let rejected = db
        .mutate(context.clone(), new_identity.clone())
        .await
        .unwrap_err();
    assert_eq!(rejected.code, ErrorCode::ResourceExhausted);
    assert_eq!(db.engine.generation().unwrap().state.document_count, 8);
    assert_eq!(
        db.engine
            .generation()
            .unwrap()
            .state
            .mutation_receipt_head
            .count,
        2
    );
    let mut expanded = db.engine.generation().unwrap().state.limits.clone();
    expanded.max_batch_bytes = 2 << 20;
    expanded.max_batch_operations = 256;
    db.administer(context.clone(), Operation::SetLimits(expanded))
        .await
        .unwrap();
    // Re-evaluation would now reach the absent-document precondition. The
    // retained batch-budget failure remains the exact immutable outcome.
    assert_eq!(
        db.mutate(context.clone(), new_identity).await.unwrap_err(),
        rejected
    );
    let mut substituted = original;
    substituted.operations.pop();
    assert_eq!(
        db.mutate(context.clone(), substituted)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        db.engine
            .generation()
            .unwrap()
            .state
            .mutation_receipt_head
            .count,
        2
    );
    fixture.close().await;
}
