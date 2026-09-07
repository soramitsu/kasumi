#[tokio::test]
async fn canceled_queued_schema_activation_finishes_once_and_checks_receipt_release_authority() {
    let root = tempfile::tempdir().unwrap();
    let node = NodeStore::open(root.path().join("node.redb")).unwrap();
    let audit_store = TenantStore::open_fixture(
        node.clone(),
        crate::SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([0x91; 32])),
    )
    .await
    .unwrap();
    let audit = SecurityAudit::open(audit_store, 100_000).unwrap();
    let store = TenantStore::open_fixture(
        node,
        "schema-cancel".into(),
        Arc::new(LocalKeyProvider::new([0x92; 32])),
    )
    .await
    .unwrap();
    let context = RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        tenant: "schema-cancel".into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "cancel-schema".into(),
    };
    let policy = Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: context.scopes.clone(),
        }],
        strict_read_audit: false,
    };
    let db = crate::open_local(
        kasumi_store::test_utils::with_custody(
            store,
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        policy.clone(),
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    let request = SchemaChangeSet {
        activation_id: "cancel".into(),
        expected_incarnation: db.engine.generation().unwrap().state.incarnation.clone(),
        expected_schema_epoch: 0,
        read_set: vec![],
        changes: ["journal", "balances"]
            .map(|name| SchemaChange::Create {
                definition: CollectionDefinition {
                    name: name.into(),
                    write_mode: CollectionWriteMode::Mutable,
                    retention_class: CollectionRetentionClass::Operational,
                    schema: json!({"type":"object"}),
                    indexes: vec![],
                    strict_read_audit: false,
                },
            })
            .into(),
    };
    let reference = request.reference().unwrap();
    let gate = db.proposal_gate.lock().await;
    let mut pending = Box::pin(db.activate_schema(context.clone(), request.clone()));
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(pending);
    assert!(db.engine.generation().unwrap().state.collections.is_empty());
    drop(gate);
    db.work.drain().await;
    let status = db
        .schema_activation_status(
            &context,
            &ReadSchemaActivation {
                reference: reference.clone(),
                read_set: vec![],
            },
        )
        .await
        .unwrap();
    let receipt = status.outcome.unwrap();
    assert_eq!(
        db.activate_schema(context.clone(), request.clone())
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(db.engine.generation().unwrap().state.schema_epoch, 1);
    let fence = db
        .schema_activation_response_fence(&context, &request)
        .unwrap();
    let mut replacement = policy;
    replacement.grants[0].principal = "replacement".into();
    db.administer(context.clone(), Operation::SetPolicy(replacement))
        .await
        .unwrap();
    assert_eq!(fence.check().unwrap_err().code, ErrorCode::Conflict);
    assert!(
        db.schema_activation_response_fence(&context, &request)
            .is_err()
    );
    drop(fence);
    db.shutdown().await.unwrap();
    audit.shutdown().await;
}

#[tokio::test]
async fn schema_original_deadline_and_current_lookup_dependencies_survive_until_encoded_release() {
    let fixture = CredentialFixture::new().await;
    let base = now_ms().unwrap();
    let clock = Arc::new(ControlledCommandClock(std::sync::atomic::AtomicU64::new(
        base,
    )));
    *fixture.db.command_clock.lock().unwrap() = clock.clone();
    let before = fixture.db.engine.generation().unwrap();
    let request = SchemaChangeSet {
        activation_id: "deadline-install".into(),
        expected_incarnation: before.state.incarnation.clone(),
        expected_schema_epoch: before.state.schema_epoch,
        read_set: vec![
            ReadAssertion::Snapshot {
                incarnation: before.state.incarnation.clone(),
                schema_epoch: before.state.schema_epoch,
                policy_epoch: before.state.policy_epoch,
            },
            ReadAssertion::Before {
                not_after_ms: base + 10,
            },
        ],
        changes: vec![SchemaChange::Create {
            definition: CollectionDefinition {
                name: "journal".into(),
                write_mode: CollectionWriteMode::AppendOnly,
                retention_class: CollectionRetentionClass::Operational,
                schema: json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: true,
            },
        }],
    };
    let receipt = fixture
        .db
        .activate_schema(fixture.context.clone(), request.clone())
        .await
        .unwrap();
    let release = fixture
        .db
        .schema_activation_response_fence(&fixture.context, &request)
        .unwrap();
    clock.0.store(base + 11, Ordering::SeqCst);
    assert_eq!(release.check().unwrap_err().code, ErrorCode::Conflict);
    drop(release);
    assert_eq!(
        fixture
            .db
            .activate_schema(fixture.context.clone(), request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::UnknownOutcome
    );
    let current = fixture.db.engine.generation().unwrap();
    let lookup = ReadSchemaActivation {
        reference: request.reference().unwrap(),
        read_set: vec![
            ReadAssertion::Snapshot {
                incarnation: current.state.incarnation.clone(),
                schema_epoch: current.state.schema_epoch,
                policy_epoch: current.state.policy_epoch,
            },
            ReadAssertion::Before {
                not_after_ms: base + 100,
            },
            ReadAssertion::Document {
                collection: "docs".into(),
                id: "guard".into(),
                expected: ReadPrecondition::Absent,
            },
        ],
    };
    assert_eq!(
        fixture
            .db
            .schema_activation_status(&fixture.context, &lookup)
            .await
            .unwrap()
            .outcome
            .unwrap(),
        receipt
    );
    let expiring_lookup = ReadSchemaActivation {
        reference: lookup.reference.clone(),
        read_set: vec![ReadAssertion::Before {
            not_after_ms: base + 12,
        }],
    };
    let expiring_release = fixture
        .db
        .schema_status_response_fence(&fixture.context, &expiring_lookup)
        .unwrap();
    clock.0.store(base + 13, Ordering::SeqCst);
    assert_eq!(
        expiring_release.check().unwrap_err().code,
        ErrorCode::Conflict
    );
    assert_eq!(
        fixture
            .db
            .schema_activation_status(&fixture.context, &expiring_lookup)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    drop(expiring_release);
    let release = fixture
        .db
        .schema_status_response_fence(&fixture.context, &lookup)
        .unwrap();
    fixture
        .db
        .mutate(
            fixture.context.clone(),
            MutationBatch {
                idempotency_key: "advance-guard".into(),
                read_set: vec![],
                operations: vec![Mutation::Put {
                    collection: "docs".into(),
                    id: "guard".into(),
                    expected: Precondition::Absent,
                    body: json!({"phase":"resumed"}),
                }],
            },
        )
        .await
        .unwrap();
    assert_eq!(release.check().unwrap_err().code, ErrorCode::Conflict);
    assert_eq!(
        fixture
            .db
            .schema_activation_status(&fixture.context, &lookup)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    drop(release);
    let fresh = ReadSchemaActivation {
        reference: request.reference().unwrap(),
        read_set: vec![],
    };
    assert_eq!(
        fixture
            .db
            .schema_activation_status(&fixture.context, &fresh)
            .await
            .unwrap()
            .outcome
            .unwrap(),
        receipt
    );
    fixture.close().await;
}

#[tokio::test]
async fn queued_schema_before_expiry_rejects_all_definitions_and_retains_original_failure() {
    let fixture = CredentialFixture::new().await;
    let base = now_ms().unwrap();
    let clock = Arc::new(ControlledCommandClock(std::sync::atomic::AtomicU64::new(
        base,
    )));
    *fixture.db.command_clock.lock().unwrap() = clock.clone();
    let before = fixture.db.engine.generation().unwrap();
    let request = SchemaChangeSet {
        activation_id: "queued-schema-expired".into(),
        expected_incarnation: before.state.incarnation.clone(),
        expected_schema_epoch: before.state.schema_epoch,
        read_set: vec![ReadAssertion::Before {
            not_after_ms: base + 10,
        }],
        changes: ["journal", "balances"]
            .map(|name| SchemaChange::Create {
                definition: CollectionDefinition {
                    name: name.into(),
                    write_mode: CollectionWriteMode::AppendOnly,
                    retention_class: CollectionRetentionClass::Operational,
                    schema: json!({"type":"object"}),
                    indexes: vec![],
                    strict_read_audit: true,
                },
            })
            .into(),
    };
    let gate = fixture.db.proposal_gate.lock().await;
    let mut pending = Box::pin(
        fixture
            .db
            .activate_schema(fixture.context.clone(), request.clone()),
    );
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    clock.0.store(base + 11, Ordering::SeqCst);
    drop(gate);
    assert_eq!(pending.await.unwrap_err().code, ErrorCode::Conflict);
    let current = fixture.db.engine.generation().unwrap();
    assert_eq!(current.state.schema_epoch, before.state.schema_epoch);
    assert!(!current.state.collections.contains_key("journal"));
    assert!(!current.state.collections.contains_key("balances"));
    let lookup = ReadSchemaActivation {
        reference: request.reference().unwrap(),
        read_set: vec![],
    };
    assert_eq!(
        fixture
            .db
            .schema_activation_status(&fixture.context, &lookup)
            .await
            .unwrap()
            .outcome
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    fixture.close().await;
}
