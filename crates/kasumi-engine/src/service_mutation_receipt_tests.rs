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

fn receipt_audit_batch(collections: &[&str]) -> MutationBatch {
    MutationBatch {
        idempotency_key: "receipt-audit-original".into(),
        read_set: vec![],
        operations: collections
            .iter()
            .map(|collection| Mutation::Put {
                collection: (*collection).into(),
                id: "original".into(),
                body: json!({"value":7}),
                expected: Precondition::Absent,
            })
            .collect(),
    }
}

#[tokio::test]
async fn receipt_audit_batches_strict_collections_without_changing_original_receipt() {
    let fixture = snapshot_audit_fixture().await;
    let batch = receipt_audit_batch(&["first", "docs", "second"]);
    let committed = fixture
        .db
        .mutate(fixture.context.clone(), batch.clone())
        .await
        .unwrap();
    let (revision, count, head, incarnation) = {
        let generation = fixture.db.engine.generation().unwrap();
        (
            generation.state.revision,
            generation.state.audits.len(),
            generation.state.mutation_receipt_head.clone(),
            generation.state.incarnation.clone(),
        )
    };
    let receipt = fixture
        .db
        .operation_receipt(&fixture.context, &batch.idempotency_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.scope,
        MutationReceiptScope {
            tenant: fixture.context.tenant.clone(),
            incarnation,
            principal: fixture.context.principal.clone(),
        }
    );
    assert_eq!(receipt.request_digest, batch.digest().unwrap());
    assert_eq!(receipt.outcome, Ok(committed));
    let generation = fixture.db.engine.generation().unwrap();
    assert_eq!(
        generation.state.revision,
        revision + 1,
        "one receipt observation writes one bounded audit command"
    );
    assert_eq!(generation.state.mutation_receipt_head, head);
    let events: Vec<_> = generation.state.audits.iter().skip(count).collect();
    assert_eq!(events.len(), 2);
    assert_eq!(
        events
            .iter()
            .map(|event| event.collection.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    assert_ne!(events[0].event_id, events[1].event_id);
    for event in events {
        assert_eq!(event.action, "receipt");
        assert_eq!(event.outcome, "authorized_release");
        assert_eq!(event.principal, fixture.context.principal);
        assert_eq!(event.request_id, fixture.context.request_id);
        assert_eq!(event.data_revision, Some(revision));
    }
    drop(generation);
    fixture.close().await;
}

#[tokio::test]
async fn receipt_audit_preserves_unrestricted_and_missing_receipt_behavior() {
    let fixture = CredentialFixture::new().await;
    let batch = receipt_audit_batch(&["docs"]);
    fixture
        .db
        .mutate(fixture.context.clone(), batch.clone())
        .await
        .unwrap();
    let revision = fixture.db.engine.generation().unwrap().state.revision;
    assert!(
        fixture
            .db
            .operation_receipt(&fixture.context, &batch.idempotency_key)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        fixture
            .db
            .operation_receipt(&fixture.context, "missing")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture.db.engine.generation().unwrap().state.revision,
        revision
    );

    let mut policy = fixture.db.engine.generation().unwrap().state.policy.clone();
    policy.strict_read_audit = true;
    fixture
        .db
        .administer(fixture.context.clone(), Operation::SetPolicy(policy))
        .await
        .unwrap();
    let revision = fixture.db.engine.generation().unwrap().state.revision;
    assert!(
        fixture
            .db
            .operation_receipt(&fixture.context, &batch.idempotency_key)
            .await
            .unwrap()
            .is_some()
    );
    {
        let generation = fixture.db.engine.generation().unwrap();
        assert_eq!(generation.state.revision, revision + 1);
        let event = generation.state.audits.back().unwrap();
        assert_eq!(event.collection.as_deref(), Some("docs"));
        assert_eq!(event.action, "receipt");
        assert_eq!(event.data_revision, Some(revision));
    }
    assert!(
        fixture
            .db
            .operation_receipt(&fixture.context, "missing")
            .await
            .unwrap()
            .is_none()
    );
    {
        let generation = fixture.db.engine.generation().unwrap();
        assert_eq!(generation.state.revision, revision + 2);
        let event = generation.state.audits.back().unwrap();
        assert!(event.collection.is_none());
        assert_eq!(event.action, "receipt");
        assert_eq!(event.data_revision, Some(revision + 1));
    }
    fixture.close().await;
}

#[tokio::test]
async fn receipt_audit_splits_129_collections_at_existing_128_event_bound() {
    let fixture = CredentialFixture::new().await;
    let mut limits = fixture.db.engine.generation().unwrap().state.limits.clone();
    limits.max_collections = 256;
    fixture
        .db
        .administer(fixture.context.clone(), Operation::SetLimits(limits))
        .await
        .unwrap();
    let names: Vec<_> = (0..129).map(|i| format!("receipt-{i:03}")).collect();
    for (index, chunk) in names.chunks(MAX_SCHEMA_CHANGESET_COLLECTIONS).enumerate() {
        let generation = fixture.db.engine.generation().unwrap();
        let request = SchemaChangeSet {
            activation_id: format!("receipt-schema-{index}"),
            expected_incarnation: generation.state.incarnation.clone(),
            expected_schema_epoch: generation.state.schema_epoch,
            read_set: vec![],
            changes: chunk
                .iter()
                .map(|name| SchemaChange::Create {
                    definition: CollectionDefinition {
                        name: name.clone(),
                        write_mode: CollectionWriteMode::Mutable,
                        retention_class: CollectionRetentionClass::Operational,
                        schema: json!({"type":"object"}),
                        indexes: vec![],
                        strict_read_audit: true,
                    },
                })
                .collect(),
        };
        drop(generation);
        fixture
            .db
            .activate_schema(fixture.context.clone(), request)
            .await
            .unwrap();
    }
    let batch = receipt_audit_batch(&names.iter().map(String::as_str).collect::<Vec<_>>());
    let committed = fixture
        .db
        .mutate(fixture.context.clone(), batch.clone())
        .await
        .unwrap();
    let (revision, count) = {
        let generation = fixture.db.engine.generation().unwrap();
        (generation.state.revision, generation.state.audits.len())
    };
    let receipt = fixture
        .db
        .operation_receipt(&fixture.context, &batch.idempotency_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.outcome, Ok(committed));
    assert_eq!(receipt.request_digest, batch.digest().unwrap());
    let generation = fixture.db.engine.generation().unwrap();
    assert_eq!(generation.state.revision, revision + 2);
    let events: Vec<_> = generation.state.audits.iter().skip(count).collect();
    assert_eq!(events.len(), names.len());
    assert_eq!(
        events
            .iter()
            .map(|event| event.collection.as_ref().unwrap())
            .collect::<Vec<_>>(),
        names.iter().collect::<Vec<_>>()
    );
    assert!(events.iter().all(|event| event.action == "receipt"
        && event.data_revision == Some(revision)
        && event.request_id == fixture.context.request_id));
    drop(generation);
    fixture.close().await;
}

#[tokio::test]
async fn receipt_audit_long_original_names_survive_lowered_command_bytes() {
    let fixture = CredentialFixture::new().await;
    let mut context = fixture.context.clone();
    context.principal = "p".repeat(256);
    let mut policy = fixture.db.engine.generation().unwrap().state.policy.clone();
    policy.grants.push(Grant {
        principal: context.principal.clone(),
        collection: None,
        actions: context.scopes.clone(),
    });
    fixture
        .db
        .administer(fixture.context.clone(), Operation::SetPolicy(policy))
        .await
        .unwrap();
    let mut limits = fixture.db.engine.generation().unwrap().state.limits.clone();
    limits.max_collections = 256;
    fixture
        .db
        .administer(
            fixture.context.clone(),
            Operation::SetLimits(limits.clone()),
        )
        .await
        .unwrap();
    let names: Vec<_> = (0..128)
        .map(|i| format!("c{i:03}{}", "x".repeat(252)))
        .collect();
    let generation = fixture.db.engine.generation().unwrap();
    let request = SchemaChangeSet {
        activation_id: "long-receipt-names".into(),
        expected_incarnation: generation.state.incarnation.clone(),
        expected_schema_epoch: generation.state.schema_epoch,
        read_set: vec![],
        changes: names
            .iter()
            .map(|name| SchemaChange::Create {
                definition: CollectionDefinition {
                    name: name.clone(),
                    write_mode: CollectionWriteMode::Mutable,
                    retention_class: CollectionRetentionClass::Operational,
                    schema: json!({"type":"object"}),
                    indexes: vec![],
                    strict_read_audit: true,
                },
            })
            .collect(),
    };
    drop(generation);
    fixture
        .db
        .activate_schema(fixture.context.clone(), request)
        .await
        .unwrap();
    let batch = receipt_audit_batch(&names.iter().map(String::as_str).collect::<Vec<_>>());
    let committed = fixture
        .db
        .mutate(context.clone(), batch.clone())
        .await
        .unwrap();
    limits.max_document_bytes = 1024;
    limits.max_batch_bytes = 1024;
    fixture
        .db
        .administer(fixture.context.clone(), Operation::SetLimits(limits))
        .await
        .unwrap();
    let (revision, count, head) = {
        let generation = fixture.db.engine.generation().unwrap();
        (
            generation.state.revision,
            generation.state.audits.len(),
            generation.state.mutation_receipt_head.clone(),
        )
    };
    let receipt = fixture
        .db
        .operation_receipt(&context, &batch.idempotency_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.scope.principal, context.principal);
    assert_eq!(receipt.request_digest, batch.digest().unwrap());
    assert_eq!(receipt.outcome, Ok(committed));
    let generation = fixture.db.engine.generation().unwrap();
    assert_eq!(
        generation.state.revision,
        revision + 2,
        "byte limit splits fewer than 128 events"
    );
    assert_eq!(generation.state.mutation_receipt_head, head);
    let events: Vec<_> = generation.state.audits.iter().skip(count).collect();
    assert_eq!(events.len(), names.len());
    assert_eq!(
        events
            .iter()
            .map(|event| event.collection.as_ref().unwrap())
            .collect::<Vec<_>>(),
        names.iter().collect::<Vec<_>>()
    );
    assert!(
        events
            .iter()
            .all(|event| event.principal == context.principal
                && event.action == "receipt"
                && event.data_revision == Some(revision))
    );
    drop(generation);
    fixture.close().await;
}

#[tokio::test]
async fn receipt_audit_policy_change_while_queued_refuses_the_complete_observation() {
    let fixture = snapshot_audit_fixture().await;
    let batch = receipt_audit_batch(&["first", "docs", "second"]);
    fixture
        .db
        .mutate(fixture.context.clone(), batch.clone())
        .await
        .unwrap();
    // The strict collections remain allowed. Only the non-strict collection is
    // revoked, so a durable audit cannot substitute for the final release fence.
    let policy = Policy {
        grants: ["first", "second"]
            .into_iter()
            .map(|collection| Grant {
                principal: fixture.context.principal.clone(),
                collection: Some(collection.into()),
                actions: fixture.context.scopes.clone(),
            })
            .chain(std::iter::once(Grant {
                principal: "fixture-administrator".into(),
                collection: None,
                actions: BTreeSet::from([Action::Admin]),
            }))
            .collect(),
        strict_read_audit: false,
    };
    let gate = fixture.db.proposal_gate.lock().await;
    let mut policy_change = Box::pin(
        fixture
            .db
            .administer(fixture.context.clone(), Operation::SetPolicy(policy)),
    );
    fixture
        .db
        .proposals
        .wait_for_admission(policy_change.as_mut())
        .await;
    // The single-thread test runtime polls the registered policy child into the
    // held FIFO gate before the later receipt audit is registered.
    tokio::task::yield_now().await;
    let mut pending = Box::pin(
        fixture
            .db
            .operation_receipt(&fixture.context, &batch.idempotency_key),
    );
    fixture
        .db
        .proposals
        .wait_for_admission(pending.as_mut())
        .await;
    drop(gate);
    let (changed, observed) = tokio::join!(policy_change, pending);
    changed.unwrap();
    assert_eq!(observed.unwrap_err().code, ErrorCode::Forbidden);
    let generation = fixture.db.engine.generation().unwrap();
    assert_eq!(
        generation
            .state
            .audits
            .iter()
            .filter(|event| event.action == "receipt")
            .count(),
        2,
        "the strict audit commits but does not release the forbidden non-strict collection"
    );
    drop(generation);
    fixture.close().await;
}

struct ReceiptAuditRevocation(std::sync::Weak<TenantEngine>);
impl kasumi_types::CredentialLiveness for ReceiptAuditRevocation {
    fn check(&self) -> Result<()> {
        if self
            .0
            .upgrade()
            .and_then(|engine| engine.generation().ok())
            .is_some_and(|generation| {
                generation
                    .state
                    .audits
                    .iter()
                    .any(|event| event.action == "receipt")
            })
        {
            Err(Error::new(
                ErrorCode::Unauthorized,
                "original credential revoked",
            ))
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn receipt_audit_committed_batch_never_releases_after_original_credential_revocation() {
    let fixture = snapshot_audit_fixture().await;
    let batch = receipt_audit_batch(&["first", "docs", "second"]);
    fixture
        .db
        .mutate(fixture.context.clone(), batch.clone())
        .await
        .unwrap();
    let observation = kasumi_clock::EpochClock::system()
        .unwrap()
        .observe()
        .unwrap();
    let incarnation =
        uuid::Uuid::parse_str(&fixture.db.engine.generation().unwrap().state.incarnation).unwrap();
    let context = RequestContext {
        authorization: RequestAuthorization::from_verified_credential_with_liveness(
            observation.utc_ms() + 60_000,
            &observation,
            CredentialResource::Database { incarnation },
            Arc::new(ReceiptAuditRevocation(Arc::downgrade(&fixture.db.engine))),
        )
        .unwrap(),
        ..fixture.context.clone()
    };
    assert_eq!(
        fixture
            .db
            .operation_receipt(&context, &batch.idempotency_key)
            .await
            .unwrap_err()
            .code,
        ErrorCode::AuditUnavailable
    );
    let generation = fixture.db.engine.generation().unwrap();
    assert_eq!(
        generation
            .state
            .audits
            .iter()
            .filter(|event| event.action == "receipt")
            .count(),
        2
    );
    drop(generation);
    fixture.close().await;
}

#[tokio::test]
async fn receipt_audit_capacity_failure_releases_no_observation_or_partial_audit() {
    let fixture = snapshot_audit_fixture().await;
    let batch = receipt_audit_batch(&["first", "docs", "second"]);
    fixture
        .db
        .mutate(fixture.context.clone(), batch.clone())
        .await
        .unwrap();
    let count = fixture.db.engine.generation().unwrap().state.audits.len();
    let gate = fixture.db.proposal_gate.lock().await;
    let mut blockers = Vec::new();
    for index in 0..32 {
        let mut pending = Box::pin(fixture.db.mutate(
            fixture.context.clone(),
            credential_batch(&format!("receipt-audit-blocker-{index}")),
        ));
        fixture
            .db
            .proposals
            .wait_for_admission(pending.as_mut())
            .await;
        blockers.push(pending);
    }
    assert_eq!(fixture.db.fixture_running_proposals(), 32);
    let error = fixture
        .db
        .operation_receipt(&fixture.context, &batch.idempotency_key)
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert_eq!(
        fixture.db.engine.generation().unwrap().state.audits.len(),
        count
    );
    drop(blockers);
    drop(gate);
    fixture.db.work.drain().await;
    fixture.close().await;
}
