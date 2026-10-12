async fn snapshot_audit_fixture() -> CredentialFixture {
    let fixture = CredentialFixture::new().await;
    for name in ["first", "second"] {
        fixture
            .db
            .administer(
                fixture.context.clone(),
                Operation::CreateCollection(CollectionDefinition {
                    name: name.into(),
                    write_mode: CollectionWriteMode::Mutable,
                    retention_class: CollectionRetentionClass::Operational,
                    schema: json!({"type":"object"}),
                    indexes: vec![],
                    strict_read_audit: true,
                }),
            )
            .await
            .unwrap();
    }
    fixture
}

fn snapshot_audit_request() -> ReadSnapshotRequest {
    ReadSnapshotRequest {
        documents: ["first", "second", "docs"]
            .into_iter()
            .map(|name| DocumentKey {
                collection: name.into(),
                id: "missing".into(),
            })
            .collect(),
        queries: vec![],
        time_bounds: None,
    }
}

#[tokio::test]
async fn snapshot_audit_batches_every_strict_collection_in_one_durable_revision() {
    let fixture = snapshot_audit_fixture().await;
    let (revision, count) = {
        let generation = fixture.db.engine.generation().unwrap();
        (generation.state.revision, generation.state.audits.len())
    };
    let snapshot = fixture
        .db
        .read_snapshot(&fixture.context, snapshot_audit_request())
        .await
        .unwrap();
    assert_eq!(snapshot.revision, revision);
    assert_eq!(snapshot.documents.len(), 3);
    assert!(snapshot.documents.iter().all(|row| row.document.is_none()));
    let generation = fixture.db.engine.generation().unwrap();
    assert_eq!(
        generation.state.revision,
        revision + 1,
        "strict collection audits share one ordered command"
    );
    let events: Vec<_> = generation.state.audits.iter().skip(count).collect();
    assert_eq!(events.len(), 2);
    assert_eq!(
        events
            .iter()
            .map(|e| e.collection.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    for event in events {
        assert_eq!(event.action, "read");
        assert_eq!(event.outcome, "authorized_release");
        assert_eq!(event.principal, fixture.context.principal);
        assert_eq!(event.request_id, fixture.context.request_id);
        assert_eq!(event.data_revision, Some(revision));
    }
    drop((generation, snapshot));
    fixture.close().await;
}

#[tokio::test]
async fn snapshot_audit_includes_tenant_strict_collections_and_leaves_unrestricted_reads_unmodified()
 {
    let fixture = CredentialFixture::new().await;
    let request = ReadSnapshotRequest {
        documents: vec![DocumentKey {
            collection: "docs".into(),
            id: "missing".into(),
        }],
        queries: vec![],
        time_bounds: None,
    };
    let revision = fixture.db.engine.generation().unwrap().state.revision;
    drop(
        fixture
            .db
            .read_snapshot(&fixture.context, request.clone())
            .await
            .unwrap(),
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
    drop(
        fixture
            .db
            .read_snapshot(&fixture.context, request)
            .await
            .unwrap(),
    );
    let generation = fixture.db.engine.generation().unwrap();
    assert_eq!(generation.state.revision, revision + 1);
    assert_eq!(
        generation
            .state
            .audits
            .back()
            .unwrap()
            .collection
            .as_deref(),
        Some("docs")
    );
    drop(generation);
    fixture.close().await;
}

struct SnapshotAuditExpiryClock(std::sync::Weak<TenantEngine>);
impl LeaseClock for SnapshotAuditExpiryClock {
    fn now(&self) -> Duration {
        let committed = self
            .0
            .upgrade()
            .and_then(|engine| engine.generation().ok())
            .is_some_and(|generation| {
                generation
                    .state
                    .audits
                    .iter()
                    .any(|event| event.action == "read")
            });
        Duration::from_millis(if committed { 1000 } else { 0 })
    }
}

#[tokio::test]
async fn snapshot_audit_committed_batch_does_not_release_after_original_credential_expires() {
    let fixture = snapshot_audit_fixture().await;
    let context = fixture.credential(Arc::new(SnapshotAuditExpiryClock(Arc::downgrade(
        &fixture.db.engine,
    ))));
    let error = fixture
        .db
        .read_snapshot(&context, snapshot_audit_request())
        .await
        .unwrap_err();
    assert!(matches!(
        error.code,
        ErrorCode::Forbidden | ErrorCode::AuditUnavailable
    ));
    let generation = fixture.db.engine.generation().unwrap();
    let events: Vec<_> = generation
        .state
        .audits
        .iter()
        .filter(|event| event.action == "read")
        .collect();
    assert_eq!(
        events.len(),
        2,
        "audit remains durable even when the response is refused"
    );
    drop(generation);
    fixture.close().await;
}

#[tokio::test]
async fn snapshot_audit_rejects_any_unauthorized_collection_before_auditing_or_releasing() {
    let fixture = snapshot_audit_fixture().await;
    let mut context = fixture.context.clone();
    context.principal = "partial-reader".into();
    let mut policy = fixture.db.engine.generation().unwrap().state.policy.clone();
    policy
        .grants
        .extend(["first", "docs"].into_iter().map(|name| Grant {
            principal: context.principal.clone(),
            collection: Some(name.into()),
            actions: BTreeSet::from([Action::Read]),
        }));
    fixture
        .db
        .administer(fixture.context.clone(), Operation::SetPolicy(policy))
        .await
        .unwrap();
    let count = fixture.db.engine.generation().unwrap().state.audits.len();
    assert_eq!(
        fixture
            .db
            .read_snapshot(&context, snapshot_audit_request())
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        fixture.db.engine.generation().unwrap().state.audits.len(),
        count
    );
    fixture.close().await;
}
