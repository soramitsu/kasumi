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
        .schema_activation_status(&context, &reference)
        .await
        .unwrap();
    let receipt = status.outcome.unwrap();
    assert_eq!(
        db.activate_schema(context.clone(), request).await.unwrap(),
        receipt
    );
    assert_eq!(db.engine.generation().unwrap().state.schema_epoch, 1);
    let fence = db
        .schema_activation_response_fence(&context, &reference)
        .unwrap();
    let mut replacement = policy;
    replacement.grants[0].principal = "replacement".into();
    db.administer(context.clone(), Operation::SetPolicy(replacement))
        .await
        .unwrap();
    assert_eq!(fence.check().unwrap_err().code, ErrorCode::Conflict);
    assert!(
        db.schema_activation_response_fence(&context, &reference)
            .is_err()
    );
    drop(fence);
    db.shutdown().await.unwrap();
    audit.shutdown().await;
}
