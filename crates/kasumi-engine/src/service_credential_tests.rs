struct CredentialFixture {
    _directory: tempfile::TempDir,
    db: Arc<Database>,
    audit: Arc<SecurityAudit>,
    context: RequestContext,
}
impl CredentialFixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let node = NodeStore::open(directory.path().join("node.redb")).unwrap();
        let provider = Arc::new(LocalKeyProvider::new([0x97; 32]));
        let audit_store = TenantStore::open_fixture(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            provider.clone(),
        )
        .await
        .unwrap();
        let audit = SecurityAudit::open(audit_store, 100_000).unwrap();
        let context = RequestContext {
            authorization: RequestAuthorization::service_identity(),
            tenant: "credential-expiry".into(),
            principal: "owner".into(),
            scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
            request_id: "expiry-test".into(),
        };
        let store = TenantStore::open_fixture(node, context.tenant.clone(), provider)
            .await
            .unwrap();
        let policy = Policy {
            grants: vec![Grant {
                principal: context.principal.clone(),
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
            policy,
            Limits::default(),
            audit.clone(),
        )
        .await
        .unwrap();
        db.install_admission(NodeAdmission::new(AdmissionConfig::default()).unwrap())
            .unwrap();
        db.administer(
            context.clone(),
            Operation::CreateCollection(CollectionDefinition {
                name: "docs".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
        Self {
            _directory: directory,
            db,
            audit,
            context,
        }
    }
    async fn close(self) {
        self.db.shutdown().await.unwrap();
        self.audit.shutdown().await;
    }
    fn credential(&self, clock: Arc<dyn LeaseClock>) -> RequestContext {
        let epoch =
            kasumi_clock::EpochClock::new(clock, Arc::new(kasumi_clock::SystemWallClock)).unwrap();
        let observation = epoch.observe().unwrap();
        RequestContext {
            authorization: RequestAuthorization::from_verified_credential(
                observation.utc_ms() + 1000,
                &observation,
            )
            .unwrap(),
            ..self.context.clone()
        }
    }
}
struct CredentialClock(std::sync::atomic::AtomicU64);
impl LeaseClock for CredentialClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::SeqCst))
    }
}
fn credential_batch(id: &str) -> MutationBatch {
    MutationBatch {
        idempotency_key: id.into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: id.into(),
            body: json!({"value":7}),
            expected: Precondition::Absent,
        }],
    }
}

#[test]
fn replicated_credential_admission_uses_only_captured_time_after_local_expiry() {
    struct Wall;
    impl kasumi_clock::WallClock for Wall {
        fn now_ms(&self) -> anyhow::Result<u64> {
            Ok(1000)
        }
    }
    let elapsed = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
    let epoch = kasumi_clock::EpochClock::new(elapsed.clone(), Arc::new(Wall)).unwrap();
    let context = RequestContext {
        authorization: RequestAuthorization::from_verified_credential(
            2000,
            &epoch.observe().unwrap(),
        )
        .unwrap(),
        tenant: "replica".into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Admin, Action::Write]),
        request_id: "deterministic".into(),
    };
    let policy = Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: context.scopes.clone(),
        }],
        strict_read_audit: false,
    };
    let first = TenantEngine::new(
        "replica".into(),
        "same-incarnation".into(),
        policy.clone(),
        Limits::default(),
    )
    .unwrap();
    let second = TenantEngine::new(
        "replica".into(),
        "same-incarnation".into(),
        policy,
        Limits::default(),
    )
    .unwrap();
    let command = Command {
        context,
        timestamp_ms: 1999,
        operation: Operation::CreateCollection(CollectionDefinition {
            name: "docs".into(),
            write_mode: CollectionWriteMode::Mutable,
            retention_class: CollectionRetentionClass::Operational,
            schema: json!({"type":"object"}),
            indexes: vec![],
            strict_read_audit: false,
        }),
    };
    let encoded = serde_json::to_vec(&command).unwrap();
    elapsed.0.store(1000, Ordering::SeqCst);
    assert!(command.context.authorization.check_live().is_err());
    for replica in [&first, &second] {
        // Actual log deserialization deliberately removes all local live proof.
        replica
            .apply_command(1, serde_json::from_slice(&encoded).unwrap())
            .unwrap()
            .unwrap();
        let late = Command {
            context: serde_json::from_slice::<Command>(&encoded).unwrap().context,
            timestamp_ms: 2000,
            operation: Operation::Mutate(credential_batch("late")),
        };
        assert_eq!(
            replica.apply_command(2, late).unwrap().unwrap_err().code,
            ErrorCode::Unauthorized
        );
        assert!(
            replica.generation().unwrap().state.collections["docs"]
                .documents
                .is_empty()
        );
        assert!(replica.generation().unwrap().state.receipts.is_empty());
    }
    assert_eq!(first.snapshot().unwrap(), second.snapshot().unwrap());
}

#[tokio::test]
async fn expired_queued_and_canceled_credentials_accept_no_effect_or_identity() {
    let fixture = CredentialFixture::new().await;
    for cancel in [false, true] {
        let id = if cancel { "canceled" } else { "queued" };
        let clock = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
        let context = fixture.credential(clock.clone());
        let gate = fixture.db.proposal_gate.lock().await;
        let mut queued = Box::pin(fixture.db.mutate(context, credential_batch(id)));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(queued.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        clock.0.store(1000, Ordering::SeqCst);
        if cancel {
            drop(queued);
            drop(gate);
            fixture.db.work.drain().await;
        } else {
            drop(gate);
            assert_eq!(queued.await.unwrap_err().code, ErrorCode::Unauthorized);
        }
        assert_eq!(
            fixture
                .db
                .get(&fixture.context, "docs", id)
                .await
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
        assert!(
            fixture
                .db
                .operation_receipt(&fixture.context, id)
                .await
                .unwrap()
                .is_none()
        );
        let receipt = fixture
            .db
            .mutate(fixture.context.clone(), credential_batch(id))
            .await
            .unwrap();
        assert_eq!(
            fixture
                .db
                .mutate(fixture.context.clone(), credential_batch(id))
                .await
                .unwrap(),
            receipt
        );
    }
    fixture.close().await;
}

// Observe actual materialization to advance time deterministically between the
// committed effect and its acknowledgement; no timing race or fake database.
struct CommitObservedClock(std::sync::Weak<TenantEngine>);
impl LeaseClock for CommitObservedClock {
    fn now(&self) -> Duration {
        let committed = self
            .0
            .upgrade()
            .and_then(|engine| engine.generation().ok())
            .is_some_and(|generation| {
                generation.state.collections["docs"]
                    .documents
                    .contains_key("committed")
            });
        Duration::from_millis(if committed { 1000 } else { 0 })
    }
}
#[tokio::test]
async fn committed_effect_with_expired_ack_is_resolved_by_fresh_credential() {
    let fixture = CredentialFixture::new().await;
    let context = fixture.credential(Arc::new(CommitObservedClock(Arc::downgrade(
        &fixture.db.engine,
    ))));
    let error = fixture
        .db
        .mutate(context.clone(), credential_batch("committed"))
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::UnknownOutcome);
    assert_eq!(
        fixture
            .db
            .get(&context, "docs", "committed")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Unauthorized
    );
    let receipt = fixture
        .db
        .operation_receipt(&fixture.context, "committed")
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let document = fixture
        .db
        .get(&fixture.context, "docs", "committed")
        .await
        .unwrap();
    assert_eq!(document.version, receipt.revision);
    assert_eq!(
        fixture
            .db
            .mutate(fixture.context.clone(), credential_batch("committed"))
            .await
            .unwrap(),
        receipt
    );
    fixture.close().await;
}

#[tokio::test]
async fn serialized_authorization_never_becomes_fresh_service_or_credential_authority() {
    let fixture = CredentialFixture::new().await;
    let clock = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
    for context in [fixture.context.clone(), fixture.credential(clock)] {
        let replicated: RequestContext =
            serde_json::from_slice(&serde_json::to_vec(&context).unwrap()).unwrap();
        assert_eq!(
            fixture
                .db
                .mutate(replicated.clone(), credential_batch("replicated"))
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
        assert_eq!(
            fixture
                .db
                .get(&replicated, "docs", "replicated")
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
        assert_eq!(
            fixture.db.response_fence(&replicated).err().unwrap().code,
            ErrorCode::Unauthorized
        );
    }
    assert!(
        fixture
            .db
            .operation_receipt(&fixture.context, "replicated")
            .await
            .unwrap()
            .is_none()
    );
    fixture.close().await;
}

struct CredentialPausedDestination {
    inner: Arc<kasumi_store::FilesystemBackupDestination>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl BackupDestination for CredentialPausedDestination {
    async fn put(&self, id: uuid::Uuid, bytes: Vec<u8>) -> anyhow::Result<()> {
        self.inner.put(id, bytes).await
    }
    async fn get(&self, id: uuid::Uuid, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
        self.entered.notify_one();
        self.release.notified().await;
        self.inner.get(id, max_bytes).await
    }
}
#[tokio::test]
async fn long_backup_verification_and_encoded_read_recheck_original_credential() {
    let fixture = CredentialFixture::new().await;
    fixture
        .db
        .mutate(fixture.context.clone(), credential_batch("read"))
        .await
        .unwrap();
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            fixture._directory.path().join("backups"),
            32 << 20,
        )
        .unwrap(),
    );
    let proof = fixture
        .db
        .backup_checkpoint(fixture.context.clone(), destination.as_ref())
        .await
        .unwrap();
    let paused = CredentialPausedDestination {
        inner: destination,
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    };
    let clock = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
    let context = fixture.credential(clock.clone());
    let fence = fixture.db.response_fence(&context).unwrap();
    let _encoded =
        serde_json::to_vec(&fixture.db.get(&context, "docs", "read").await.unwrap()).unwrap();
    let verify = fixture
        .db
        .verify_backup_checkpoint(context, &paused, proof.backup_id());
    let advance = async {
        paused.entered.notified().await;
        clock.0.store(1000, Ordering::SeqCst);
        paused.release.notify_one();
    };
    let (result, ()) = tokio::join!(verify, advance);
    assert_eq!(result.unwrap_err().code, ErrorCode::Unauthorized);
    assert_eq!(fence.check().unwrap_err().code, ErrorCode::Unauthorized);
    drop(fence);
    // Creation can have already published immutable encrypted objects when its
    // credential expires; suppress the proof and report uncertainty.
    let clock = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
    let create = fixture
        .db
        .backup_checkpoint(fixture.credential(clock.clone()), &paused);
    let advance = async {
        paused.entered.notified().await;
        clock.0.store(1000, Ordering::SeqCst);
        paused.release.notify_one();
    };
    let (result, ()) = tokio::join!(create, advance);
    assert_eq!(result.unwrap_err().code, ErrorCode::UnknownOutcome);
    fixture.close().await;
}
