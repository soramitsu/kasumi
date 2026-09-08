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
        &mut config.control.transit,
        &mut config.control.custody_transit,
        &mut config.security_audit.transit,
    ]
    .into_iter()
    .chain(
        config
            .tenants
            .iter_mut()
            .flat_map(|tenant| [&mut tenant.transit, &mut tenant.custody_transit]),
    ) {
        setting.endpoint = endpoint.clone();
        setting.ca_certificate = Some(files.certificate.clone());
    }
    let unavailable = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable_address = unavailable.local_addr().unwrap();
    drop(unavailable);
    let authority = config.serving_authorities.get_mut("storage-fence").unwrap();
    authority.tls = files.clone();
    authority.server_ca = files.certificate.clone();
    authority.endpoints.get_mut(&0).unwrap().get_mut(&1).unwrap().endpoint =
        format!("https://localhost:{}", unavailable_address.port());
    let application_token = config.tenants[0].transit.token_file.clone();
    let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = probes.clone();
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
