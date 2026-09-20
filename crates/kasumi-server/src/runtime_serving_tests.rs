#[tokio::test]
async fn fenced_source_startup_keeps_control_handle_without_constructing_application_provider() {
    let _gate = LIFECYCLE_GATE.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let (files, _) = certificate_files(dir.path());
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://localhost:{}", socket.local_addr().unwrap().port());
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(tls::serve_tls(
        socket,
        kasumi_transport::server_config(&files.load().unwrap(), ClientAuthentication::OAuth)
            .unwrap(),
        Router::new()
            .route("/v1/transit/{*operation}", post(transit))
            .with_state(Arc::new(TransitFixture::default())),
        ListenerLimits::default(),
        Arc::new(FixtureAudit),
        stopped,
    ));
    let mut config = example_config();
    config.database_path = dir.path().join("node.redb");
    config.scratch_disk.directory = dir.path().join("scratch");
    config.mcp.tls = files.clone();
    config.native.tls = files.clone();
    config.admin.tls = files.clone();
    config.native.client_ca = files.certificate.clone();
    config.admin.client_ca = files.certificate.clone();
    let [mcp, native, admin] = listening_addresses();
    config.mcp.listen = mcp;
    config.native.listen = native;
    config.admin.listen = admin;
    config.mcp.protocol = McpConfig::new(format!("https://localhost:{}/mcp", mcp.port())).unwrap();
    let cluster = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let cluster_address = cluster.local_addr().unwrap();
    drop(cluster);
    let replication = config.replication.as_mut().unwrap();
    replication.listener = MutualTlsEndpoint {
        listen: cluster_address,
        tls: files.clone(),
        client_ca: files.certificate.clone(),
    };
    replication.peers[0].endpoint = format!("https://localhost:{}", cluster_address.port());
    replication.peers[0].certificate_pins = vec![format_certificate_pin(
        &files.load().unwrap().certificate_pin(),
    )];
    for setting in [
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
        let setting = setting.transit_mut().unwrap();
        setting.endpoint = endpoint.clone();
        setting.ca_certificate = Some(files.certificate.clone());
    }
    let unavailable = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable_address = unavailable.local_addr().unwrap();
    drop(unavailable);
    let authority = config.serving_authorities.get_mut("storage-fence").unwrap();
    authority.tls = files.clone();
    authority.server_ca = files.certificate.clone();
    authority
        .endpoints
        .get_mut(&0)
        .unwrap()
        .get_mut(&1)
        .unwrap()
        .endpoint = format!("https://localhost:{}", unavailable_address.port());
    // Even an unavailable authority requires explicit current local trust;
    // startup must not manufacture it from the root manifest or a wire reply.
    let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    authority
        .manifest
        .partitions
        .get_mut(&0)
        .unwrap()
        .public_key = hex::encode(root_key.public_key_raw());
    let root = kasumi_serving::InstallationSigningRoot::from_pkcs8(
        authority.manifest.signing_domain(0).unwrap(),
        &root_key.serialize_der(),
    )
    .unwrap();
    let operational = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let trust_directory = dir.path().join("signer-verifier");
    kasumi_store::private_files::create_directory(&trust_directory).unwrap();
    let wrapping = trust_directory.join("keys.json");
    kasumi_store::FileKeyProvider::initialize(&wrapping, "runtime-verifier").unwrap();
    let verifier = config.signer_verifier.as_mut().unwrap();
    verifier.database_path = trust_directory.join("trust.redb");
    verifier.keys = KeyProviderSettings::File { path: wrapping };
    crate::signer_runtime::InitializeSignerVerifier {
        admission: Default::default(),
        scratch_disk: config.scratch_disk.clone(),
        verifier: verifier.clone(),
        initial_certificates: vec![
            root.certify(1, hex::encode(operational.public_key_raw()))
                .unwrap(),
        ],
    }
    .initialize()
    .await
    .unwrap();
    let application_token = config.tenants[0]
        .keys
        .transit_mut()
        .unwrap()
        .token_file
        .clone();
    let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = probes.clone();
    create_fixture_node(&config).await;
    let mut runtime = NodeRuntime::open_using(config.clone(), move |name| {
        if name == application_token {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            anyhow::bail!("application key is independently unavailable");
        }
        Ok(Zeroizing::new("test-runtime-token".into()))
    })
    .await
    .unwrap();
    assert_eq!(probes.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(runtime.tenants.is_empty());
    assert!(runtime.administration.is_some());
    assert_eq!(
        runtime.unavailable_sources.get("acme"),
        config.tenants[0].incarnation.as_ref()
    );
    let topology = runtime.expected_topology().unwrap();
    assert_eq!(
        topology.tenants["acme"].incarnation,
        config.tenants[0].incarnation.as_ref().unwrap().as_str()
    );
    assert_eq!(
        runtime
            .control_database()
            .engine()
            .generation()
            .unwrap()
            .state
            .tenant,
        CONTROL_TENANT
    );
    assert_eq!(runtime.data_listeners.len(), 3);
    // This fixture proves closed startup and retained listeners/control storage.
    // Serving control quorum itself is covered by the real three-node runtime suite.
    runtime.shutdown().await.unwrap();
    stop.send_replace(true);
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_tenant_reopens_after_key_outage_without_reviving_retained_handles() {
    let _gate = LIFECYCLE_GATE.lock().await;
    let dir = tempfile::tempdir().unwrap();
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
    config.database_path = dir.path().join("node.redb");
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
    create_fixture_node(&config).await;
    let runtime = NodeRuntime::open_using(config.clone(), move |path| {
        anyhow::ensure!(
            path != application_file
                || credential_available.load(std::sync::atomic::Ordering::Acquire),
            "application credential temporarily unavailable"
        );
        Ok(Zeroizing::new("test-runtime-token".into()))
    })
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
    let mut reopened =
        NodeRuntime::open_using(config, |_| Ok(Zeroizing::new("test-runtime-token".into())))
            .await
            .unwrap();
    assert!(reopened.publish_control().await.unwrap());
    reopened.shutdown().await.unwrap();
    mock_stop.send_replace(true);
    mock.await.unwrap().unwrap();
}
