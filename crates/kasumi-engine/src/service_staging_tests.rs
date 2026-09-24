#[tokio::test]
async fn queued_staged_finalize_checks_fresh_time_and_canceled_callers_keep_durable_outcomes() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let (persistent_config, scratch_config) =
        crate::test_utils::fixture_disk_configs(directory.path()).unwrap();
    let storage = crate::test_utils::FixtureStorage::open(
        &persistent_config,
        &scratch_config,
        Default::default(),
    )
    .unwrap();
    let node = storage
        .create_new(
            directory.path().join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let audit_store = TenantStore::initialize_catalog_fixture(
        node.clone(),
        crate::SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([0xA7; 32])),
    )
    .await
    .unwrap();
    let node_admission = storage.admission.clone();
    let audit = SecurityAudit::initialize(
        audit_store,
        kasumi_types::AuditRetentionBudget::default(),
        node_admission.clone(),
    )
    .unwrap();
    let context = RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        tenant: "stage-time".into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        request_id: "stage-time".into(),
    };
    let store = TenantStore::initialize_catalog_fixture(
        node,
        context.tenant.clone(),
        Arc::new(LocalKeyProvider::new([0xC7; 32])),
    )
    .await
    .unwrap();
    let db = crate::test_utils::open_fixture(
        kasumi_store::test_utils::initialize_custody_fixture(
            store,
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
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
    db.administer(
        context.clone(),
        Operation::CreateCollection(CollectionDefinition {
            retention_class: kasumi_types::CollectionRetentionClass::Operational,
            name: "docs".into(),
            schema: json!({"type":"object"}),
            indexes: vec![],
            strict_read_audit: false,
            write_mode: CollectionWriteMode::Mutable,
        }),
    )
    .await
    .unwrap();
    let base = now_ms().unwrap();
    let clock = Arc::new(ControlledCommandClock(std::sync::atomic::AtomicU64::new(
        base,
    )));
    *db.command_clock.lock().unwrap() = clock.clone();
    for (id, canceled) in [("expired", false), ("canceled", true)] {
        clock.0.store(base, Ordering::SeqCst);
        let chunk = StagedChunk {
            read_set: vec![ReadAssertion::Before {
                not_after_ms: base + 100,
            }],
            operations: vec![Mutation::Put {
                collection: "docs".into(),
                id: id.into(),
                expected: Precondition::Absent,
                body: json!({"value":id}),
            }],
        };
        let manifest = StagedManifest::from_chunks(std::slice::from_ref(&chunk)).unwrap();
        let reference = StagedTransactionRef {
            scope: kasumi_types::StagedTransactionScope {
                tenant: context.tenant.clone(),
                principal: context.principal.clone(),
                incarnation: db.engine().generation().unwrap().state.incarnation.clone(),
            },
            transaction_id: id.into(),
            manifest_digest: staged_digest(&manifest).unwrap().0,
        };
        db.begin_staged_transaction(
            context.clone(),
            BeginStagedTransaction {
                scope: reference.scope.clone(),
                transaction_id: id.into(),
                manifest,
                ttl_ms: 60_000,
            },
        )
        .await
        .unwrap();
        db.append_staged_chunk(
            context.clone(),
            AppendStagedChunk {
                transaction: reference.clone(),
                index: 0,
                chunk,
            },
        )
        .await
        .unwrap();
        let gate = db.proposal_gate.lock().await;
        let mut pending =
            Box::pin(db.finalize_staged_transaction(context.clone(), reference.clone()));
        db.proposals.wait_for_admission(pending.as_mut()).await;
        if canceled {
            drop(pending);
            clock.0.store(base + 99, Ordering::SeqCst);
            drop(gate);
            db.work.drain().await;
            let status = db
                .staged_transaction_status(&context, &reference)
                .await
                .unwrap();
            let receipt = status.outcome.resolved().unwrap().unwrap();
            assert_eq!(
                db.get(&context, "docs", id).await.unwrap().version,
                receipt.revision
            );
            clock.0.store(base + 172_800_000, Ordering::SeqCst);
            assert_eq!(
                db.finalize_staged_transaction(context.clone(), reference)
                    .await
                    .unwrap(),
                receipt
            );
        } else {
            clock.0.store(base + 101, Ordering::SeqCst);
            drop(gate);
            assert_eq!(pending.await.unwrap_err().code, ErrorCode::Conflict);
            assert_eq!(
                db.get(&context, "docs", id).await.unwrap_err().code,
                ErrorCode::NotFound
            );
            assert_eq!(
                db.staged_transaction_status(&context, &reference)
                    .await
                    .unwrap()
                    .outcome
                    .resolved()
                    .unwrap()
                    .unwrap_err()
                    .code,
                ErrorCode::Conflict
            );
        }
    }
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}
