// The issuer reducer and pinned native issuer have separate actual-quorum tests.
// This fixture signs real opaque capabilities to isolate the encrypted engine's
// queue, materialization and release boundaries under a deterministic clock.
struct ServingFixture {
    storage: Vec<crate::test_utils::FixtureStorage>,
    nodes: Vec<Arc<kasumi_store::NodeStore>>,
    databases: Vec<Arc<Database>>,
    audits: Vec<Arc<SecurityAudit>>,
    signer: Arc<kasumi_serving::AuthoritySigner>,
    signing: kasumi_serving::test_utils::FixtureAuthority,
    manifest: kasumi_serving::AuthorityManifest,
    bootstrap: crate::ReplicatedBootstrap,
    clock: Arc<CredentialClock>,
    router: Arc<kasumi_raft::InProcessRouter>,
    context: RequestContext,
    directory: tempfile::TempDir,
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
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let storage = (1..=3)
            .map(|id| {
                let root = directory.path().join(format!("node-{id}"));
                kasumi_store::private_files::create_directory(&root).unwrap();
                let (persistent, scratch) = crate::test_utils::fixture_disk_configs(&root).unwrap();
                crate::test_utils::FixtureStorage::open(&persistent, &scratch, Default::default())
                    .unwrap()
            })
            .collect();
        let mut fixture = Self {
            directory,
            storage,
            nodes: vec![],
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
        let leader = fixture.leader("initial bootstrap").await;
        fixture.disable_automatic_elections();
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
            let storage = &self.storage[id as usize - 1];
            let path = self
                .directory
                .path()
                .join(format!("node-{id}/persistent/node.kv"));
            let node = (if create {
                storage.create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)
            } else {
                storage.open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
            })
            .unwrap();
            self.nodes.push(node.clone());
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
            let admission = storage.admission.clone();
            let archive = Arc::new(
                kasumi_store::FilesystemAuditArchive::open(
                    audit_store
                        .durable_directory()
                        .unwrap()
                        .join("audit-archives"),
                    storage.persistent.clone(),
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
                kasumi_raft::server_config(),
                audit.clone(),
            )
            .await
            .unwrap();
            self.router
                .register(group.clone(), id, db.raft_group().raft().clone());
            self.databases.push(db);
            self.audits.push(audit);
        }
    }
    fn disable_automatic_elections(&self) {
        // Credential-expiry checks own the leadership timeline. Keep the
        // serving fixture on its ready leader while storage and backup work
        // run; bootstrap and reopening still elect before this call.
        for db in &self.databases {
            db.group.raft().runtime_config().elect(false);
        }
    }
    async fn leader(&self, phase: &str) -> Arc<Database> {
        let mut last_barrier_error = None;
        let selected = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                for db in &self.databases {
                    let metrics = db.group.raft().metrics().borrow().clone();
                    if metrics.current_leader == Some(metrics.id) {
                        match db.group.linearizable_barrier().await {
                            Ok(_) => return db.clone(),
                            Err(error) => {
                                last_barrier_error = Some(format!(
                                    "node={} term={}: {error:#}",
                                    metrics.id, metrics.current_term
                                ));
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        match selected {
            Ok(db) => db,
            Err(_) => {
                let nodes = self
                    .databases
                    .iter()
                    .map(|db| {
                        let metrics = db.group.raft().metrics().borrow().clone();
                        format!("running={:?}; {metrics}", metrics.running_state)
                    })
                    .collect::<Vec<_>>();
                panic!(
                    "serving fixture leader timed out in {phase}; last_barrier_error={last_barrier_error:?}; nodes={nodes:?}"
                );
            }
        }
    }
    async fn drain(&mut self) {
        for db in &self.databases {
            db.shutdown().await.unwrap();
        }
        for audit in &self.audits {
            audit.shutdown().await.unwrap();
        }
        self.databases.clear();
        self.audits.clear();
        for node in self.nodes.drain(..) {
            node.shutdown().await.unwrap();
        }
        self.router = Arc::new(kasumi_raft::InProcessRouter::default());
    }
    async fn drain_after_expiry(&mut self) {
        use kasumi_types::drain::DrainCompletion;
        for db in &self.databases {
            assert!(
                db.group.check_access().is_err(),
                "fixture lease must be expired"
            );
            if let Err(failure) = db.shutdown().await {
                assert_eq!(failure.completion(), DrainCompletion::Complete);
                assert_eq!(failure.issues().len(), 1, "{failure:?}");
                for issue in failure.issues() {
                    assert_eq!(issue.component(), "OpenRaft runtime");
                    assert_eq!(issue.instance(), 0);
                    let original = issue.error()
                        .downcast_ref::<openraft::error::ShutdownError<u64, tokio::task::JoinError>>()
                        .expect("expired storage must retain the original OpenRaft failure");
                    assert!(original.core_join_error().is_none(), "{original:?}");
                    assert!(original.ticker().is_none(), "{original:?}");
                    assert!(original.snapshot_builder().is_none(), "{original:?}");
                    assert!(original.auxiliary().is_empty(), "{original:?}");
                    assert!(original.incoming_snapshot().is_none(), "{original:?}");
                    let mut observed = 0;
                    if let Some(core) = original.core() {
                        let openraft::error::Fatal::StorageError(error) = core else {
                            panic!("unexpected expired core failure: {core:?}");
                        };
                        assert!(is_serving_expiry_write(error), "{error:?}");
                        observed += 1;
                    }
                    if let Some(worker) = original.state_machine() {
                        let error = worker.storage_error().expect("original storage error");
                        assert!(is_serving_expiry_write(error), "{error:?}");
                        observed += 1;
                    }
                    for replication in original.replications() {
                        assert!(replication.owner_id > 0, "{replication:?}");
                        assert!((1..=3).contains(&replication.target), "{replication:?}");
                        assert!(replication.snapshot.is_none(), "{replication:?}");
                        let error = replication
                            .stream
                            .as_ref()
                            .and_then(|stream| stream.storage_error())
                            .expect("original replication storage error");
                        assert!(is_serving_expiry_write(error), "{error:?}");
                        observed += 1;
                    }
                    assert!(observed > 0, "no original expiry failure: {original:?}");
                }
                let repeated = db.shutdown().await.unwrap_err();
                assert_eq!(repeated.completion(), DrainCompletion::Complete);
                assert_eq!(repeated.issues().len(), failure.issues().len());
                for issue in failure.issues() {
                    assert!(
                        repeated
                            .issues()
                            .iter()
                            .any(|next| Arc::ptr_eq(issue, next))
                    );
                }
            }
        }
        for audit in &self.audits {
            audit.shutdown().await.unwrap();
        }
        self.databases.clear();
        self.audits.clear();
        for node in self.nodes.drain(..) {
            node.shutdown().await.unwrap();
        }
        self.router = Arc::new(kasumi_raft::InProcessRouter::default());
    }
    async fn reopen(&mut self, phase: &str) {
        self.drain_after_expiry().await;
        self.open(false).await;
        self.leader(phase).await;
        self.disable_automatic_elections();
    }
}

fn is_serving_expiry_write(error: &openraft::StorageError<u64>) -> bool {
    if !matches!(error, openraft::StorageError::IO { .. }) {
        return false;
    }
    [
        "tenant is sealed: key-access lease unavailable or expired",
        "domain transaction committed; access expired before acknowledgment; outcome unknown",
        "batch committed but key access was lost before acknowledgment; outcome unknown",
        "Corruption: batch committed but key access was lost before acknowledgment; outcome unknown",
    ]
    .into_iter()
    .any(|message| {
        let expected = openraft::StorageError::<u64>::from_io_error(
            openraft::ErrorSubject::Store,
            openraft::ErrorVerb::Write,
            std::io::Error::other(message),
        );
        error.to_string() == expected.to_string()
    })
}

#[test]
fn serving_expiry_drain_rejects_unrelated_storage_causes() {
    use openraft::{ErrorSubject, ErrorVerb, StorageError};
    let closed =
        "domain transaction committed; access expired before acknowledgment; outcome unknown";
    let committed =
        "batch committed but key access was lost before acknowledgment; outcome unknown";
    let wrapped_committed = "Corruption: batch committed but key access was lost before acknowledgment; outcome unknown";
    for (subject, verb, message, expected) in [
        (ErrorSubject::Store, ErrorVerb::Write, closed, true),
        (ErrorSubject::Store, ErrorVerb::Read, closed, false),
        (ErrorSubject::Vote, ErrorVerb::Write, closed, false),
        (ErrorSubject::Store, ErrorVerb::Write, committed, true),
        (
            ErrorSubject::Store,
            ErrorVerb::Write,
            wrapped_committed,
            true,
        ),
        (
            ErrorSubject::Store,
            ErrorVerb::Read,
            wrapped_committed,
            false,
        ),
        (
            ErrorSubject::Vote,
            ErrorVerb::Write,
            wrapped_committed,
            false,
        ),
        (
            ErrorSubject::Store,
            ErrorVerb::Write,
            "Corruption: batch committed but key access was lost before acknowledgment",
            false,
        ),
        (
            ErrorSubject::Store,
            ErrorVerb::Write,
            "unrelated I/O failure",
            false,
        ),
        (
            ErrorSubject::Store,
            ErrorVerb::Write,
            "unrelated access expired before acknowledgment",
            false,
        ),
    ] {
        let error = StorageError::from_io_error(subject, verb, std::io::Error::other(message));
        assert_eq!(is_serving_expiry_write(&error), expected, "{error:?}");
    }
}

#[tokio::test]
async fn serving_expiry_rejects_queued_effect_and_late_read_or_committed_ack_then_reopens_exactly()
{
    let mut fixture = ServingFixture::new().await;
    let db = fixture.leader("queued-effect initial").await;
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
    fixture.reopen("queued-effect first reopen").await;
    let db = fixture.leader("queued-effect first reopen").await;
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
    fixture.reopen("queued-effect second reopen").await;
    let db = fixture.leader("queued-effect second reopen").await;
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
    let db = fixture.leader("backup-expiry initial").await;
    db.mutate(fixture.context.clone(), credential_batch("read"))
        .await
        .unwrap();
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            db.store.durable_directory().unwrap().join("backups"),
            32 << 20,
            db.store.persistent_disk().clone(),
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
    fixture.reopen("backup-expiry reopen").await;
    let mut expired = false;
    for attempt in 0..3 {
        let phase = format!("backup-expiry capture attempt {}", attempt + 1);
        let db = fixture.leader(&phase).await;
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
    if expired {
        fixture.drain_after_expiry().await;
    } else {
        fixture.drain().await;
    }
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
