#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn fenced_source_startup_keeps_control_handle_without_constructing_application_provider() {
    // The canonical fixture first enrolls the Independent tenant against its
    // live three-voter issuer. Only the subsequent reopen fences that issuer.
    Box::pin(replicated_runtime_fixture_inner(
        false, None, true, false, false,
    ))
    .await;
}

/// One standalone node using a real transit TLS key service. The application
/// credential can be withdrawn so a closed tenant cannot reopen until restored.
struct OriginalServingFixture {
    config: RuntimeConfig,
    storage: crate::runtime_memory::RuntimeStorage,
    public_dir: PathBuf,
    available: Arc<std::sync::atomic::AtomicBool>,
    runtime: NodeRuntime,
    mock_stop: watch::Sender<bool>,
    mock: tokio::task::JoinHandle<Result<()>>,
}

impl OriginalServingFixture {
    async fn open(dir: &Path) -> Self {
        let (files, _) = certificate_files(dir);
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("https://localhost:{}", socket.local_addr().unwrap().port());
        let (mock_stop, mock_stopped) = watch::channel(false);
        let mock = tokio::spawn(tls::serve_tls(
            socket,
            kasumi_transport::server_config(&files.load().unwrap(), ClientAuthentication::OAuth)
                .unwrap(),
            Router::new()
                .route("/v1/transit/{*operation}", post(transit))
                .with_state(Arc::new(TransitFixture::default())),
            ListenerLimits::default(),
            Arc::new(FixtureAudit),
            mock_stopped,
        ));
        let public_dir = dir.join("public");
        std::fs::create_dir(&public_dir).unwrap();
        let (public_files, _) = certificate_files(&public_dir);
        let mut config = fixture_config();
        config.persistent_disk = crate::persistent_disk::fixture_config(&dir.join("data"));
        config.database_path = dir.join("data/node.kv");
        config.scratch_disk.directory = dir.join("scratch");
        config.mcp.tls = public_files.clone();
        config.native.tls = public_files.clone();
        config.admin.tls = public_files.clone();
        config.native.client_ca = files.certificate.clone();
        config.admin.client_ca = files.certificate.clone();
        let [mcp, native, admin] = listening_addresses();
        config.mcp.listen = mcp;
        config.native.listen = native;
        config.admin.listen = admin;
        config.mcp.protocol =
            McpConfig::new(format!("https://localhost:{}/mcp", mcp.port())).unwrap();
        for settings in [
            &mut config.control.keys,
            &mut config.control.custody_keys,
            &mut config.security_audit.keys,
        ]
        .into_iter()
        .chain(
            config
                .tenants
                .iter_mut()
                .flat_map(|tenant| [&mut tenant.keys, &mut tenant.custody_keys]),
        ) {
            let settings = settings.transit_mut().unwrap();
            settings.endpoint = endpoint.clone();
            settings.ca_certificate = Some(files.certificate.clone());
        }
        let application_file = config.tenants[0]
            .keys
            .transit_mut()
            .unwrap()
            .token_file
            .clone();
        let available = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let credential_available = available.clone();
        let storage = crate::runtime_storage_fixtures::configure(&mut config).unwrap();
        create_fixture_node(&config, &storage).await;
        let runtime = NodeRuntime::open_using_storage(
            config.clone(),
            move |path| {
                anyhow::ensure!(
                    path != application_file
                        || credential_available.load(std::sync::atomic::Ordering::Acquire),
                    "application credential temporarily unavailable"
                );
                Ok(Zeroizing::new("test-runtime-token".into()))
            },
            storage.clone(),
        )
        .await
        .unwrap();
        Self {
            config,
            storage,
            public_dir,
            available,
            runtime,
            mock_stop,
            mock,
        }
    }
}

fn original_admin_context() -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        tenant: "acme".into(),
        principal: "acme-admin".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "fresh-admission".into(),
    }
}

/// A live native database credential bound to one exact incarnation.
fn database_credential(context: &RequestContext, incarnation: Uuid) -> RequestContext {
    let observation = kasumi_clock::EpochClock::system()
        .unwrap()
        .observe()
        .unwrap();
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::from_verified_credential(
            observation.utc_ms() + 60_000,
            &observation,
            kasumi_types::CredentialResource::Database { incarnation },
        )
        .unwrap(),
        ..context.clone()
    }
}

async fn wait_routed(registry: &crate::api::DatabaseRegistry, context: &RequestContext) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if registry.database(context).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

/// Bounded wait for a serving generation distinct from the retained closed one.
async fn wait_fresh(
    registry: &crate::api::DatabaseRegistry,
    context: &RequestContext,
    retained: &Arc<Database>,
) -> Arc<Database> {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(database) = registry.database(context)
                && !Arc::ptr_eq(&database, retained)
                && database.check_serving().is_ok()
            {
                break database;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("fresh original generation serves within the bounded deadline")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_tenant_reopens_after_key_outage_without_reviving_retained_handles() {
    let _gate = LIFECYCLE_GATE.lock().await;
    let dir = kasumi_store::test_utils::private_tempdir().unwrap();
    let OriginalServingFixture {
        config,
        storage,
        public_dir,
        available,
        runtime,
        mock_stop,
        mock,
    } = OriginalServingFixture::open(dir.path()).await;
    let reload = runtime.tls_reload_handle().unwrap();
    let retained = runtime.tenants[0].database.clone();
    let retained_store = runtime.tenants[0].store.clone();
    let registry = runtime.registry().clone();
    let manager = runtime.administration.clone().unwrap();
    let context = original_admin_context();
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(runtime.serve(stopped));
    wait_routed(&registry, &context).await;
    retained
        .administer(
            context.clone(),
            Operation::SetLimits(kasumi_types::Limits::default()),
        )
        .await
        .unwrap();
    let expected = retained.engine().generation().unwrap().state.revision;
    available.store(false, std::sync::atomic::Ordering::Release);
    retained_store.seal();
    manager.reconcile().await.unwrap();
    assert!(retained.check_serving().is_err());
    assert!(registry.database(&context).is_err());
    available.store(true, std::sync::atomic::Ordering::Release);
    let fresh = wait_fresh(&registry, &context, &retained).await;
    assert_eq!(
        fresh.engine().generation().unwrap().state.revision,
        expected
    );
    assert!(
        retained
            .administer(
                context,
                Operation::SetLimits(kasumi_types::Limits::default())
            )
            .await
            .is_err()
    );
    retained.shutdown().await.unwrap();
    fresh.check_serving().unwrap();
    // A hot MCP certificate change is committed to local Control metadata before
    // listeners publish it, so restarting under the new installed files agrees.
    let (replacement, _) = certificate_files(&public_dir);
    assert_eq!(reload.reload().await.unwrap(), vec![2, 2, 2]);
    assert_eq!(
        manager.committed_topology().unwrap().nodes[&1].certificate_pins,
        BTreeSet::from([format_certificate_pin(
            &replacement.load().unwrap().certificate_pin()
        )])
    );
    stop.send_replace(true);
    task.await.unwrap().unwrap();
    drop((reload, retained, retained_store, fresh, registry, manager));
    let mut reopened = NodeRuntime::open_using_storage(
        config,
        |_| Ok(Zeroizing::new("test-runtime-token".into())),
        storage.clone(),
    )
    .await
    .unwrap();
    assert!(reopened.publish_control().await.unwrap());
    reopened.shutdown().await.unwrap();
    mock_stop.send_replace(true);
    mock.await.unwrap().unwrap();
}

/// Closure causes whose drain completes while recording the failed owner's
/// issues. Before fresh admission ignored that sticky evidence, each of these
/// kept an installed original tenant closed until the daemon restarted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OriginalClosure {
    SealDuringProposal,
    FailedProposalChild,
    RaftCoreFatal,
}

async fn original_tenant_reopens_after(closure: OriginalClosure) {
    use std::sync::atomic::Ordering;
    let _gate = LIFECYCLE_GATE.lock().await;
    let dir = kasumi_store::test_utils::private_tempdir().unwrap();
    let OriginalServingFixture {
        config,
        storage,
        available,
        runtime,
        mock_stop,
        mock,
        ..
    } = OriginalServingFixture::open(dir.path()).await;
    let retained = runtime.tenants[0].database.clone();
    let retained_store = runtime.tenants[0].store.clone();
    let registry = runtime.registry().clone();
    let manager = runtime.administration.clone().unwrap();
    let context = original_admin_context();
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(runtime.serve(stopped));
    wait_routed(&registry, &context).await;
    retained
        .administer(context.clone(), Operation::SetLimits(Limits::default()))
        .await
        .unwrap();
    let (expected, incarnation) = {
        let generation = retained.engine().generation().unwrap();
        (
            generation.state.revision,
            generation.state.incarnation.clone(),
        )
    };
    // Fresh admission cannot open storage until the closure has been drained.
    available.store(false, Ordering::Release);
    let (causes, component): (&[&str], &str) = match closure {
        OriginalClosure::SealDuringProposal => {
            // Hold the actual Raft core so one admitted write stays in flight
            // while its tenant key lease is sealed beneath it.
            let (release, blocked) = std::sync::mpsc::channel::<()>();
            let (entered, core_blocked) = tokio::sync::oneshot::channel::<()>();
            retained.raft_group().raft().external_request(move |_| {
                let _ = entered.send(());
                let _ = blocked.recv();
            });
            core_blocked.await.unwrap();
            let writer = {
                let database = retained.clone();
                let context = context.clone();
                tokio::spawn(async move {
                    database
                        .administer(context, Operation::SetLimits(Limits::default()))
                        .await
                })
            };
            tokio::time::timeout(Duration::from_secs(10), async {
                while retained.fixture_running_proposals() == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            retained_store.seal();
            release.send(()).unwrap();
            let outcome = tokio::time::timeout(Duration::from_secs(15), writer)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                outcome.unwrap_err().code,
                kasumi_types::ErrorCode::UnknownOutcome
            );
            (
                &["key_lease_sealed", "proposal_work_closed"],
                "background work result",
            )
        }
        OriginalClosure::FailedProposalChild => {
            let failed = retained.fixture_fail_admitted_proposal().await.unwrap_err();
            assert_eq!(failed.code, kasumi_types::ErrorCode::UnknownOutcome);
            (&["proposal_work_closed"], "background work result")
        }
        OriginalClosure::RaftCoreFatal => {
            retained
                .raft_group()
                .raft()
                .external_request(|_| panic!("fixture Raft core fatal"));
            tokio::time::timeout(Duration::from_secs(10), async {
                while retained.check_serving().is_ok() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            (
                &["raft_core_failed", "proposal_work_closed"],
                "OpenRaft runtime",
            )
        }
    };
    manager.reconcile().await.unwrap();
    assert!(retained.check_serving().is_err());
    // The drained owner left the generation registry; only fixed classes and
    // the pending admission record remain until a fresh generation serves.
    assert!(!manager.test_has_generation("acme", &incarnation));
    let pending = manager
        .pending_admission("acme", &incarnation)
        .expect("closed original awaits fresh admission");
    assert!(
        causes.contains(&pending.closure_cause),
        "{closure:?}: {}",
        pending.closure_cause
    );
    assert!(
        pending.drained_with_issues.contains(component),
        "{closure:?}: {:?}",
        pending.drained_with_issues
    );
    assert!(pending.failed_attempts >= 1);
    // A closed original is a retryable outage for its own credentials, not an
    // authorization denial; other incarnations stay Forbidden.
    let bound = database_credential(&context, Uuid::parse_str(&incarnation).unwrap());
    for caller in [&context, &bound] {
        assert_eq!(
            registry.database(caller).err().unwrap().code,
            kasumi_types::ErrorCode::Unavailable
        );
    }
    let other = database_credential(&context, Uuid::new_v4());
    assert_eq!(
        registry.database(&other).err().unwrap().code,
        kasumi_types::ErrorCode::Forbidden
    );
    available.store(true, Ordering::Release);
    let fresh = wait_fresh(&registry, &context, &retained).await;
    assert_eq!(
        fresh.engine().generation().unwrap().state.revision,
        expected
    );
    assert!(manager.pending_admission("acme", &incarnation).is_none());
    assert!(Arc::ptr_eq(&registry.database(&bound).unwrap(), &fresh));
    // A routed generation rejects another incarnation's credential as before.
    assert_eq!(
        registry.database(&other).err().unwrap().code,
        kasumi_types::ErrorCode::Unauthorized
    );
    // Retained handles never serve again; their sticky report stays complete.
    assert!(
        retained
            .administer(context.clone(), Operation::SetLimits(Limits::default()))
            .await
            .is_err()
    );
    assert_eq!(
        retained.shutdown().await.unwrap_err().completion(),
        kasumi_types::drain::DrainCompletion::Complete
    );
    fresh
        .administer(context.clone(), Operation::SetLimits(Limits::default()))
        .await
        .unwrap();
    assert_eq!(
        fresh.engine().generation().unwrap().state.revision,
        expected + 1
    );
    // Daemon shutdown drains only the fresh owner and completes cleanly.
    stop.send_replace(true);
    task.await.unwrap().unwrap();
    drop((retained, retained_store, fresh, registry, manager));
    let mut reopened = NodeRuntime::open_using_storage(
        config,
        |_| Ok(Zeroizing::new("test-runtime-token".into())),
        storage.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.tenants[0]
            .database
            .engine()
            .generation()
            .unwrap()
            .state
            .revision,
        expected + 1
    );
    reopened.shutdown().await.unwrap();
    mock_stop.send_replace(true);
    mock.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_tenant_reopens_after_store_seal_during_inflight_proposal() {
    original_tenant_reopens_after(OriginalClosure::SealDuringProposal).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_tenant_reopens_after_failed_proposal_child() {
    original_tenant_reopens_after(OriginalClosure::FailedProposalChild).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_tenant_reopens_after_raft_core_fatal() {
    original_tenant_reopens_after(OriginalClosure::RaftCoreFatal).await;
}
