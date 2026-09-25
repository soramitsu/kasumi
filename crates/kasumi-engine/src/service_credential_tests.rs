struct CredentialFixture {
    storage: crate::test_utils::FixtureStorage,
    node: Arc<kasumi_store::NodeStore>,
    db: Arc<Database>,
    audit: Arc<SecurityAudit>,
    context: RequestContext,
    _directory: tempfile::TempDir,
}
impl CredentialFixture {
    async fn new() -> Self {
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
        let provider = Arc::new(LocalKeyProvider::new([0x97; 32]));
        let audit_store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            provider.clone(),
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
            authorization: RequestAuthorization::service_identity(),
            tenant: "credential-expiry".into(),
            principal: "owner".into(),
            scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
            request_id: "expiry-test".into(),
        };
        let store = TenantStore::initialize_catalog_fixture(node.clone(), context.tenant.clone(), provider)
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
        let db = crate::test_utils::open_fixture(
            kasumi_store::test_utils::initialize_custody_fixture(
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
            storage,
            node,
            db,
            audit,
            context,
        }
    }
    async fn close(self) {
        self.db.shutdown().await.unwrap();
        self.audit.shutdown().await.unwrap();
        self.node.shutdown().await.unwrap();
    }
    fn credential(&self, clock: Arc<dyn LeaseClock>) -> RequestContext {
        self.credential_with_validity(clock, 1000)
    }
    fn credential_with_validity(
        &self,
        clock: Arc<dyn LeaseClock>,
        validity_ms: u64,
    ) -> RequestContext {
        let epoch =
            kasumi_clock::EpochClock::new(clock, Arc::new(kasumi_clock::SystemWallClock)).unwrap();
        let observation = epoch.observe().unwrap();
        let generation = self.db.engine().generation().unwrap();
        let incarnation = uuid::Uuid::parse_str(&generation.state.incarnation).unwrap();
        let resource = if generation.state.retired {
            CredentialResource::Custody { incarnation }
        } else {
            CredentialResource::Database { incarnation }
        };
        RequestContext {
            authorization: RequestAuthorization::from_verified_credential(
                observation.utc_ms() + validity_ms,
                &observation,
                resource,
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

#[tokio::test]
async fn owned_response_fence_retains_workspace_and_original_credential_after_adapter_return() {
    let fixture = CredentialFixture::new().await;
    let clock = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
    let context = fixture.credential(clock.clone());
    let before = fixture.db.admission().snapshot();
    let owners = Arc::strong_count(&fixture.db);
    let fence = {
        let adapter_database = fixture.db.clone();
        adapter_database.owned_response_fence(&context).unwrap()
    };
    assert_eq!(Arc::strong_count(&fixture.db), owners + 1);
    let retained = fixture.db.admission().snapshot();
    assert!(retained.reserved_bytes > before.reserved_bytes);
    assert_eq!(retained.inflight_operations, before.inflight_operations);
    fence.check().unwrap();

    // A later adapter invocation may obtain fresh authority. The retained body
    // still belongs to the first invocation and must keep its original expiry.
    clock.0.store(1000, Ordering::SeqCst);
    let renewed = fixture.credential(clock);
    renewed.authorization.check_live().unwrap();
    assert_eq!(fence.check().unwrap_err().code, ErrorCode::Unauthorized);
    assert_eq!(
        fixture.db.admission().snapshot().reserved_bytes,
        retained.reserved_bytes
    );
    drop(fence);
    assert_eq!(Arc::strong_count(&fixture.db), owners);
    assert_eq!(
        fixture.db.admission().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    fixture.close().await;
}

#[test]
fn replicated_credential_admission_uses_only_captured_time_after_local_expiry() {
    let scratch = crate::codec_fixture::ScratchScope::new(
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
    )
    .unwrap();
    let disk = &scratch.disk;
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
            CredentialResource::Database {
                incarnation: uuid::Uuid::from_u128(1),
            },
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
        uuid::Uuid::from_u128(1).to_string(),
        policy.clone(),
        Limits::default(),
    )
    .unwrap();
    let second = TenantEngine::new(
        "replica".into(),
        uuid::Uuid::from_u128(1).to_string(),
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
            .apply_command(disk, 1, serde_json::from_slice(&encoded).unwrap())
            .unwrap()
            .unwrap();
        let late = Command {
            context: serde_json::from_slice::<Command>(&encoded).unwrap().context,
            timestamp_ms: 2000,
            operation: Operation::Mutate(credential_batch("late")),
        };
        assert_eq!(
            replica
                .apply_command(disk, 2, late)
                .unwrap()
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
        assert!(
            replica.generation().unwrap().state.collections["docs"]
                .documents
                .is_empty()
        );
        assert_eq!(
            replica
                .generation()
                .unwrap()
                .state
                .mutation_receipt_head
                .count,
            0
        );
    }
    assert_eq!(
        first.logical_snapshot(disk).unwrap(),
        second.logical_snapshot(disk).unwrap()
    );
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
        .outcome
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
    async fn session_put(
        &self,
        session: uuid::Uuid,
        slot: kasumi_store::BackupSessionSlot,
        bytes: kasumi_store::BackupUpload,
    ) -> anyhow::Result<()> {
        kasumi_store::BackupDestination::session_put(self.inner.as_ref(), session, slot, bytes)
            .await
    }
    async fn session_get(
        &self,
        session: uuid::Uuid,
        slot: kasumi_store::BackupSessionSlot,
        limit: usize,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        if matches!(slot, kasumi_store::BackupSessionSlot::Object(_)) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        kasumi_store::BackupDestination::session_get(self.inner.as_ref(), session, slot, limit)
            .await
    }

    async fn put(&self, id: uuid::Uuid, bytes: kasumi_store::BackupUpload) -> anyhow::Result<()> {
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
    const LONG_BACKUP_CREDENTIAL_MS: u64 = 600_000;
    let fixture = CredentialFixture::new().await;
    fixture
        .db
        .mutate(fixture.context.clone(), credential_batch("read"))
        .await
        .unwrap();
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            fixture._directory.path().join("persistent/backups"),
            32 << 20,
            fixture.storage.persistent.clone(),
        )
        .unwrap(),
    );
    let proof = fixture
        .db
        .backup_checkpoint(
            fixture.context.clone(),
            destination.as_ref(),
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap();
    let paused = CredentialPausedDestination {
        inner: destination,
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    };
    let clock = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
    let context = fixture.credential_with_validity(clock.clone(), LONG_BACKUP_CREDENTIAL_MS);
    let fence = fixture.db.response_fence(&context).unwrap();
    let _encoded =
        serde_json::to_vec(&fixture.db.get(&context, "docs", "read").await.unwrap()).unwrap();
    let result = {
        let mut verify = std::pin::pin!(fixture.db.verify_backup_checkpoint(
            context,
            &paused,
            proof.backup_id(),
        ));
        tokio::select! {
            biased;
            result = &mut verify => match result {
                Ok(_) => panic!("backup verification succeeded before reading a paused object"),
                Err(error) => panic!("backup verification failed before reading a paused object: {error:?}"),
            },
            reached = tokio::time::timeout(Duration::from_secs(360), paused.entered.notified()) => {
                reached.expect("backup verification did not read a paused object within 360 seconds");
            },
        }
        clock.0.store(LONG_BACKUP_CREDENTIAL_MS, Ordering::SeqCst);
        paused.release.notify_one();
        verify.await
    };
    assert_eq!(result.unwrap_err().code, ErrorCode::Unauthorized);
    assert_eq!(fence.check().unwrap_err().code, ErrorCode::Unauthorized);
    drop(fence);
    // Creation can have already published immutable encrypted objects when its
    // credential expires; suppress the proof and report uncertainty.
    let clock = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
    let result = {
        let mut create = std::pin::pin!(fixture.db.backup_checkpoint(
            fixture.credential_with_validity(clock.clone(), LONG_BACKUP_CREDENTIAL_MS),
            &paused,
            uuid::Uuid::new_v4(),
        ));
        tokio::select! {
            biased;
            result = &mut create => match result {
                Ok(_) => panic!("backup creation succeeded before reading a paused object"),
                Err(error) => panic!("backup creation failed before reading a paused object: {error:?}"),
            },
            reached = tokio::time::timeout(Duration::from_secs(360), paused.entered.notified()) => {
                reached.expect("backup creation did not read a paused object within 360 seconds");
            },
        }
        clock.0.store(LONG_BACKUP_CREDENTIAL_MS, Ordering::SeqCst);
        paused.release.notify_one();
        create.await
    };
    assert_eq!(result.unwrap_err().code, ErrorCode::UnknownOutcome);
    fixture.close().await;
}

struct LineageAuditClock(std::sync::Weak<TenantEngine>);
impl LeaseClock for LineageAuditClock {
    fn now(&self) -> Duration {
        let observed = self
            .0
            .upgrade()
            .and_then(|engine| engine.generation().ok())
            .is_some_and(|g| g.state.audits.iter().any(|a| a.action == "restore_lineage"));
        Duration::from_millis(if observed { 1000 } else { 0 })
    }
}
#[tokio::test]
async fn lineage_read_keeps_original_expiry_and_current_collection_policy_at_release() {
    let fixture = CredentialFixture::new().await;
    let mut definition = fixture.db.engine().generation().unwrap().state.collections["docs"]
        .definition
        .clone();
    definition.strict_read_audit = true;
    fixture
        .db
        .administer(
            fixture.context.clone(),
            Operation::ReplaceCollection(definition),
        )
        .await
        .unwrap();
    let request = ReadRestoreLineage {
        expected_incarnation: fixture
            .db
            .engine()
            .generation()
            .unwrap()
            .state
            .incarnation
            .clone(),
        collection: "docs".into(),
    };
    let context = fixture.credential(Arc::new(LineageAuditClock(Arc::downgrade(
        &fixture.db.engine,
    ))));
    assert_eq!(
        fixture
            .db
            .read_restore_lineage(&context, request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::AuditUnavailable
    );
    assert!(
        fixture
            .db
            .engine()
            .generation()
            .unwrap()
            .state
            .audits
            .iter()
            .any(|a| a.action == "restore_lineage")
    );
    let clock = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
    let fresh = fixture.credential(clock.clone());
    let proof = fixture
        .db
        .read_restore_lineage(&fresh, request)
        .await
        .unwrap();
    assert!(proof.links().is_empty());
    clock.0.store(1000, Ordering::SeqCst);
    assert_eq!(
        fixture
            .db
            .check_restore_lineage_release(&fresh, &proof)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Unauthorized
    );
    fixture
        .db
        .administer(
            fixture.context.clone(),
            Operation::SetPolicy(Policy {
                grants: vec![Grant {
                    principal: "successor".into(),
                    collection: None,
                    actions: BTreeSet::from([Action::Admin]),
                }],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    assert!(
        fixture
            .db
            .check_restore_lineage_release(&fixture.context, &proof)
            .await
            .is_err()
    );
    fixture.close().await;
}
