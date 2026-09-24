#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn fenced_source_startup_keeps_control_handle_without_constructing_application_provider() {
    // The canonical fixture first enrolls the Independent tenant against its
    // live three-voter issuer. Only the subsequent reopen fences that issuer.
    Box::pin(replicated_runtime_fixture_inner(false, None, true, false)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_tenant_reopens_after_key_outage_without_reviving_retained_handles() {
    let _gate = LIFECYCLE_GATE.lock().await;
    let dir = kasumi_store::test_utils::private_tempdir().unwrap();
    let (files, _) = certificate_files(dir.path());
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
    let public_dir = dir.path().join("public");
    std::fs::create_dir(&public_dir).unwrap();
    let (public_files, _) = certificate_files(&public_dir);
    let mut config = fixture_config();
    config.persistent_disk = crate::persistent_disk::fixture_config(&dir.path().join("data"));
    config.database_path = dir.path().join("data/node.kv");
    config.scratch_disk.directory = dir.path().join("scratch");
    config.mcp.tls = public_files.clone();
    config.native.tls = public_files.clone();
    config.admin.tls = public_files.clone();
    config.native.client_ca = files.certificate.clone();
    config.admin.client_ca = files.certificate.clone();
    let [mcp, native, admin] = listening_addresses();
    config.mcp.listen = mcp;
    config.native.listen = native;
    config.admin.listen = admin;
    config.mcp.protocol = McpConfig::new(format!("https://localhost:{}/mcp", mcp.port())).unwrap();
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
    let reload = runtime.tls_reload_handle().unwrap();
    let retained = runtime.tenants[0].database.clone();
    let retained_store = runtime.tenants[0].store.clone();
    let registry = runtime.registry().clone();
    let manager = runtime.administration.clone().unwrap();
    let context = RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        tenant: "acme".into(),
        principal: "acme-admin".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "fresh-admission".into(),
    };
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(runtime.serve(stopped));
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if registry.database(&context).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
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
    let fresh = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(database) = registry.database(&context)
                && !Arc::ptr_eq(&database, &retained)
                && database.check_serving().is_ok()
            {
                break database;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
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
