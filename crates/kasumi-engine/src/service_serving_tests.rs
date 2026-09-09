// The issuer reducer and pinned native issuer have separate actual-quorum tests.
// This fixture signs real opaque capabilities to isolate the encrypted engine's
// queue, materialization and release boundaries under a deterministic clock.
struct ServingFixture {
    directory: tempfile::TempDir,
    databases: Vec<Arc<Database>>,
    audits: Vec<Arc<SecurityAudit>>,
    signer: Arc<kasumi_serving::AuthoritySigner>,
    signing: kasumi_serving::test_utils::FixtureAuthority,
    manifest: kasumi_serving::AuthorityManifest,
    bootstrap: crate::ReplicatedBootstrap,
    clock: Arc<CredentialClock>,
    router: Arc<kasumi_raft::InProcessRouter>,
    context: RequestContext,
}
impl ServingFixture {
    async fn new() -> Self {
        let keys =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap();
        let root =
            kasumi_serving::test_utils::FixtureSigningRoot::from_pkcs8(keys.as_ref()).unwrap();
        let manifest = kasumi_serving::AuthorityManifest {
            lifecycle_controls: std::collections::BTreeMap::new(),
            authority_id: uuid::Uuid::new_v4(),
            max_lease_ms: 1000,
            clock_rate_error_ppm: 0,
            partitions: BTreeMap::from([(
                0,
                kasumi_serving::AuthorityPartition {
                    group: "independent-fixture-issuer".into(),
                    public_key: root.public_key(),
                },
            )]),
        };
        let signing = root.install(manifest.clone(), 0).unwrap();
        let signer = signing.signer.clone();
        let context = RequestContext {
            tenant: "serving-expiry".into(),
            principal: "owner".into(),
            request_id: "serving-test".into(),
            authorization: RequestAuthorization::service_identity(),
            scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        };
        let bootstrap = crate::ReplicatedBootstrap {
            genesis: crate::ReplicatedGenesis::Application,
            incarnation: uuid::Uuid::new_v4().to_string(),
            initial_policy: Policy {
                grants: vec![Grant {
                    principal: context.principal.clone(),
                    collection: None,
                    actions: context.scopes.clone(),
                }],
                strict_read_audit: false,
            },
            initial_limits: Limits::default(),
            voters: (1..=3)
                .map(|id| {
                    (
                        id,
                        crate::ReplicaPlacement {
                            address: format!("node-{id}"),
                            failure_domain: format!("zone-{id}"),
                        },
                    )
                })
                .collect(),
        };
        let mut fixture = Self {
            directory: tempfile::tempdir().unwrap(),
            databases: vec![],
            audits: vec![],
            signer,
            signing,
            manifest,
            bootstrap,
            clock: Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0))),
            router: Arc::new(kasumi_raft::InProcessRouter::default()),
            context,
        };
        fixture.open(true).await;
        crate::initialize_replicated(&fixture.databases[0], &fixture.bootstrap)
            .await
            .unwrap();
        let leader = fixture.leader().await;
        leader
            .administer(
                fixture.context.clone(),
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
        fixture
    }
    async fn open(&mut self, create: bool) {
        let group = format!("{}/{}", self.context.tenant, self.bootstrap.incarnation);
        for id in 1..=3 {
            let boot = kasumi_serving::ServingBoot::with_test_clock(
                self.signing
                    .for_verifier(kasumi_serving::test_utils::fixture_verifier(id))
                    .unwrap()
                    .trust,
                kasumi_serving::ServingIdentity {
                    tenant: self.context.tenant.clone(),
                    incarnation: uuid::Uuid::parse_str(&self.bootstrap.incarnation).unwrap(),
                    authority_epoch: 1,
                    node: kasumi_serving::NodeIdentity {
                        node_id: id,
                        verifier: kasumi_serving::test_utils::fixture_verifier(id),
                        principal: format!("node-{id}"),
                        certificate_sha256: format!("{id:064x}"),
                    },
                },
                self.clock.clone(),
            )
            .unwrap();
            let attempt = boot.begin_acquisition().unwrap();
            let lease = attempt
                .verify(
                    self.signer
                        .sign_lease(kasumi_serving::LeaseClaims {
                            request: attempt.request().clone(),
                            authority_id: self.manifest.authority_id,
                            partition: 0,
                            authority_term: 1,
                            authority_revision: 1,
                            lifetime_ms: 1000,
                            credential_lifetime_ms: 1000,
                            activation_digest: "a".repeat(64),
                            recovery_checkpoint: None,
                        })
                        .unwrap(),
                )
                .unwrap();
            let gate = kasumi_serving::ServingGate::new(lease).unwrap();
            let node = (if create {
                NodeStore::create_new(
                    self.directory.path().join(format!("node-{id}.redb")),
                    kasumi_store::test_utils::NODE_STORE_ID,
                    kasumi_store::ScratchDisk::fixture(),
                )
            } else {
                NodeStore::open_existing(
                    self.directory.path().join(format!("node-{id}.redb")),
                    kasumi_store::test_utils::NODE_STORE_ID,
                    kasumi_store::ScratchDisk::fixture(),
                )
            })
            .unwrap();
            let audit_store = (if create {
                TenantStore::initialize_catalog(
                    node.clone(),
                    crate::SECURITY_TENANT.into(),
                    Arc::new(LocalKeyProvider::new([id as u8 + 20; 32])),
                    kasumi_store::StorageAccess::security_audit(),
                )
                .await
            } else {
                TenantStore::open_existing(
                    node.clone(),
                    crate::SECURITY_TENANT.into(),
                    Arc::new(LocalKeyProvider::new([id as u8 + 20; 32])),
                    kasumi_store::StorageAccess::security_audit(),
                )
                .await
            })
            .unwrap();
            // Each simulated data node has the same independent governor used
            // by a real NodeRuntime, including its maintenance reservation.
            let admission = crate::admission::NodeAdmission::new(Default::default()).unwrap();
            let archive = Arc::new(
                kasumi_store::FilesystemAuditArchive::open(
                    audit_store
                        .durable_directory()
                        .unwrap()
                        .join("audit-archives"),
                )
                .unwrap(),
            );
            let audit = (if create {
                SecurityAudit::initialize_with_archive
            } else {
                SecurityAudit::open_with_archive
            })(
                audit_store,
                kasumi_types::AuditRetentionBudget::default(),
                archive,
                admission.clone(),
            )
            .unwrap();
            let stores = if create {
                kasumi_store::TenantStorageSet::initialize_catalogs(
                    node,
                    self.context.tenant.clone(),
                    Arc::new(LocalKeyProvider::new([id as u8; 32])),
                    Arc::new(LocalKeyProvider::new([id as u8 + 10; 32])),
                    kasumi_store::StorageAccess::serving(gate).unwrap(),
                )
                .await
            } else {
                kasumi_store::TenantStorageSet::open_existing(
                    node,
                    self.context.tenant.clone(),
                    Arc::new(LocalKeyProvider::new([id as u8; 32])),
                    Arc::new(LocalKeyProvider::new([id as u8 + 10; 32])),
                    kasumi_store::StorageAccess::serving(gate).unwrap(),
                )
                .await
            }
            .unwrap();
            let db = crate::open_replicated(
                id,
                stores,
                &self.bootstrap,
                self.router.clone(),
                kasumi_raft::Config {
                    heartbeat_interval: 30,
                    election_timeout_min: 100,
                    election_timeout_max: 180,
                    ..Default::default()
                },
                audit.clone(),
            )
            .await
            .unwrap();
            db.install_admission(admission).unwrap();
            self.router
                .register(group.clone(), id, db.raft_group().raft().clone());
            self.databases.push(db);
            self.audits.push(audit);
        }
    }
    async fn leader(&self) -> Arc<Database> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                for db in &self.databases {
                    let metrics = db.group.raft().metrics().borrow().clone();
                    if metrics.current_leader == Some(metrics.id)
                        && db.group.linearizable_barrier().await.is_ok()
                    {
                        return db.clone();
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }
    async fn drain(&mut self) {
        for db in &self.databases {
            db.shutdown().await.unwrap();
        }
        for audit in &self.audits {
            audit.shutdown().await;
        }
        self.databases.clear();
        self.audits.clear();
        self.router = Arc::new(kasumi_raft::InProcessRouter::default());
    }
    async fn reopen(&mut self) {
        self.drain().await;
        self.open(false).await;
        self.leader().await;
    }
}

#[tokio::test]
async fn serving_expiry_rejects_queued_effect_and_late_read_or_committed_ack_then_reopens_exactly()
{
    let mut fixture = ServingFixture::new().await;
    let db = fixture.leader().await;
    let gate = db.proposal_gate.lock().await;
    let mut queued = Box::pin(db.mutate(fixture.context.clone(), credential_batch("queued")));
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(queued.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    fixture.clock.0.store(1000, Ordering::SeqCst);
    drop(gate);
    assert!(queued.await.is_err());
    drop(db);
    fixture.reopen().await;
    let db = fixture.leader().await;
    assert!(
        db.operation_receipt(&fixture.context, "queued")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db.get(&fixture.context, "docs", "queued")
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    let accepted = db
        .mutate(fixture.context.clone(), credential_batch("accepted"))
        .await
        .unwrap();
    let encoded = serde_json::to_vec(&Ok::<_, Error>(accepted.clone())).unwrap();
    let response = db.response_fence(&fixture.context).unwrap();
    let read = db.get(&fixture.context, "docs", "accepted").await.unwrap();
    assert_eq!(read.version, accepted.revision);
    fixture.clock.0.store(2000, Ordering::SeqCst);
    assert_eq!(response.check().unwrap_err().code, ErrorCode::Sealed);
    assert_eq!(
        db.release_submitted_response(&fixture.context, &encoded)
            .await
            .unwrap_err()
            .code,
        ErrorCode::UnknownOutcome
    );
    assert!(db.get(&fixture.context, "docs", "accepted").await.is_err());
    drop(response);
    drop(db);
    fixture.reopen().await;
    let db = fixture.leader().await;
    assert_eq!(
        db.mutate(fixture.context.clone(), credential_batch("accepted"))
            .await
            .unwrap(),
        accepted
    );
    drop(db);
    fixture.drain().await;
}

#[tokio::test]
async fn serving_expiry_suppresses_long_backup_verification_and_post_publication_proof() {
    let mut fixture = ServingFixture::new().await;
    let db = fixture.leader().await;
    db.mutate(fixture.context.clone(), credential_batch("read"))
        .await
        .unwrap();
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            fixture.directory.path().join("backups"),
            32 << 20,
        )
        .unwrap(),
    );
    let proof = db
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
    let result = expire_paused_backup(
        db.verify_backup_checkpoint(fixture.context.clone(), &paused, proof.backup_id()),
        &paused,
        &fixture.clock,
        1000,
    )
    .await;
    let result = match result {
        Ok((true, result)) => result,
        other => {
            drop(db);
            fixture.drain().await;
            panic!("verification pause failed: {other:?}");
        }
    };
    assert!(result.is_err());
    drop(db);
    fixture.reopen().await;
    let mut expired = false;
    for _ in 0..3 {
        let db = fixture.leader().await;
        let session_id = uuid::Uuid::new_v4();
        let result = expire_paused_backup(
            db.backup_checkpoint(fixture.context.clone(), &paused, session_id),
            &paused,
            &fixture.clock,
            2000,
        )
        .await;
        match result {
            Ok((true, result)) => {
                assert_eq!(result.unwrap_err().code, ErrorCode::UnknownOutcome);
                expired = true;
                break;
            }
            Ok((false, Err(error))) if error.code == ErrorCode::UnknownOutcome => {
                // An election can interrupt the pre-upload audit proposal. Settle
                // that exact admitted session before attempting another capture.
                // This fixture gives replicas independent wrapping keys, so its
                // original publisher must regain leadership to audit the abort.
                db.work.drain().await;
                db.install_archive_destination("expiry-abort".into(), paused.inner.clone())
                    .unwrap();
                let mut aborted = false;
                for _ in 0..3 {
                    db.group.raft().trigger().elect().await.unwrap();
                    tokio::time::timeout(Duration::from_secs(10), async {
                        while db.barrier().await.is_err() {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    })
                    .await
                    .unwrap();
                    let session = db
                        .backup_session(&fixture.context, paused.inner.as_ref(), session_id)
                        .await
                        .unwrap()
                        .expect("admitted session must remain visible");
                    if matches!(
                        session.outcome(),
                        Some(BackupSessionOutcome::Aborted { .. })
                    ) {
                        aborted = true;
                        break;
                    }
                    assert!(
                        session.outcome().is_none(),
                        "unexpired attempt unexpectedly completed"
                    );
                    let _outcome = db
                        .abort_backup_session(
                            fixture.context.clone(),
                            AbortBackupSession {
                                destination: "expiry-abort".into(),
                                session_id,
                                reason: "settle interrupted expiry fixture preparation".into(),
                            },
                        )
                        .await;
                    let session = db
                        .backup_session(&fixture.context, paused.inner.as_ref(), session_id)
                        .await
                        .unwrap()
                        .expect("abort must retain its session tombstone");
                    if matches!(
                        session.outcome(),
                        Some(BackupSessionOutcome::Aborted { .. })
                    ) {
                        aborted = true;
                        break;
                    }
                }
                assert!(
                    aborted,
                    "original backup session did not reach permanent abort"
                );
            }
            other => {
                drop(db);
                fixture.drain().await;
                panic!("creation pause failed: {other:?}");
            }
        }
    }
    fixture.drain().await;
    assert!(
        expired,
        "elections repeatedly prevented the controlled expiry attempt"
    );
}

// A failed operation must not leave the companion pause waiter pending forever.
// Returning drops the request future; the caller drains its owned workers before
// reporting any diagnostic. Serving expiry and capacity are unchanged.
async fn expire_paused_backup<T: std::fmt::Debug>(
    operation: impl std::future::Future<Output = Result<T>>,
    paused: &CredentialPausedDestination,
    clock: &CredentialClock,
    expires_at: u64,
) -> std::result::Result<(bool, Result<T>), String> {
    let mut operation = Box::pin(operation);
    tokio::select! {
        result = &mut operation => return Ok((false, result)),
        _ = paused.entered.notified() => {},
        _ = tokio::time::sleep(Duration::from_secs(10)) => return Err("operation never reached paused dependency read".into()),
    }
    clock.0.store(expires_at, Ordering::SeqCst);
    paused.release.notify_one();
    tokio::time::timeout(Duration::from_secs(10), operation)
        .await
        .map(|result| (true, result))
        .map_err(|_| "operation did not exit after serving expiry".into())
}
