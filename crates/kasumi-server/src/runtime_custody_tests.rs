#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retired_runtime_reopens_current_custody_without_constructing_application_provider() {
    let _gate = LIFECYCLE_GATE.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let (files, _) = certificate_files(dir.path());
    let mock_socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "https://localhost:{}",
        mock_socket.local_addr().unwrap().port()
    );
    let keys = Arc::new(TransitFixture::default());
    let router = Router::new()
        .route("/v1/transit/{*operation}", post(transit))
        .with_state(keys.clone());
    let (mock_stop, mock_shutdown) = watch::channel(false);
    let mock = tokio::spawn(tls::serve_tls(
        mock_socket,
        kasumi_transport::server_config(&files.load().unwrap(), ClientAuthentication::OAuth)
            .unwrap(),
        router,
        ListenerLimits::default(),
        Arc::new(FixtureAudit),
        mock_shutdown,
    ));
    let mut config = fixture_config();
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
    for transit in [
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
        let transit = transit.transit_mut().unwrap();
            transit.endpoint = endpoint.clone();
        transit.ca_certificate = Some(files.certificate.clone());
    }
    let context = RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: "acme-admin".into(),
        tenant: "acme".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "custody-native-restart".into(),
    };
    let mut runtime = NodeRuntime::open_using(config.clone(), |_| {
        Ok(Zeroizing::new("test-runtime-token".into()))
    })
    .await
    .unwrap();
    let db = runtime.tenants[0].database.clone();
    db.administer(
        context.clone(),
        Operation::CreateCollection(CollectionDefinition {
            name: "municipal-payload".into(),
            schema: serde_json::json!({"type":"object"}),
            indexes: vec![],
            strict_read_audit: false,
            write_mode: kasumi_types::CollectionWriteMode::Mutable,
            retention_class: kasumi_types::CollectionRetentionClass::Operational,
        }),
    )
    .await
    .unwrap();
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(dir.path().join("backup"), 32 << 20)
            .unwrap(),
    );
    db.install_archive_destination("approved".into(), destination.clone())
        .unwrap();
    let checkpoint = db
        .backup_checkpoint(context.clone(), destination.as_ref(), uuid::Uuid::new_v4())
        .await
        .unwrap();
    let request = kasumi_types::RetireSourceRequest {
        retirement_id: "cold-retirement".into(),
        expected_source_incarnation: checkpoint.source_incarnation().into(),
        target_incarnation: uuid::Uuid::new_v4().to_string(),
        checkpoint: checkpoint.checkpoint().clone(),
        destination: "approved".into(),
        not_after_ms: u64::MAX,
    };
    let proof = db
        .retire_source(context.clone(), request.clone())
        .await
        .unwrap();
    let rotation = kasumi_types::CustodyRequest {
        retirement: request.reference().unwrap(),
        command_id: "cold-rotation".into(),
        expected_policy_epoch: 1,
        not_after_ms: u64::MAX,
        action: kasumi_types::CustodyAction::ReplaceAdministrators(BTreeSet::from([
            "current-custodian".into(),
        ])),
    };
    assert_eq!(
        db.retired_custody()
            .unwrap()
            .execute(context.clone(), rotation.clone())
            .await
            .unwrap_err()
            .code,
        kasumi_types::ErrorCode::UnknownOutcome
    );
    let original_receipt = proof.receipt().clone();
    let reference = request.reference().unwrap();
    drop(proof);
    drop(db);
    runtime.shutdown().await.unwrap();
    drop(runtime);
    let old_key = keys
        .keys
        .lock()
        .unwrap()
        .get(&config.tenants[0].keys.transit_mut().unwrap().key_name)
        .unwrap()
        .clone();
    old_key.revoke();
    let probes = old_key.probe_count();
    let forbidden_credential = config.tenants[0].keys.transit_mut().unwrap().token_file.clone();
    let mut runtime = NodeRuntime::open_using(config, move |name| {
        anyhow::ensure!(
            name != forbidden_credential,
            "retired application credential must not be requested"
        );
        Ok(Zeroizing::new("test-runtime-token".into()))
    })
    .await
    .unwrap();
    assert!(
        runtime.tenants.is_empty(),
        "closed startup cannot materialize municipality state"
    );
    assert!(runtime.registry.database(&context).is_err());
    let installed = runtime
        .registry
        .retirement_source(&context, &reference.source_incarnation)
        .unwrap();
    let kasumi_engine::InstalledRetirementSource::RetiredCustody(custody) = installed else {
        panic!("installed current custody route required")
    };
    custody
        .raft_group()
        .unwrap()
        .raft()
        .wait(Some(Duration::from_secs(10)))
        .current_leader(1, "cold custody leader")
        .await
        .unwrap();
    assert!(
        custody
            .verify_retirement_receipt(context.clone(), &reference)
            .await
            .is_err()
    );
    let custodian = RequestContext {
        principal: "current-custodian".into(),
        ..context
    };
    let replay = custody.execute(custodian.clone(), rotation).await.unwrap();
    assert_eq!(replay.principal, "acme-admin");
    replay.outcome.unwrap();
    let recovered = custody
        .verify_retirement_receipt(custodian, &reference)
        .await
        .unwrap();
    assert_eq!(recovered.receipt(), &original_receipt);
    assert_eq!(
        old_key.probe_count(),
        probes,
        "custody recovery cannot access the unavailable application key"
    );
    runtime.shutdown().await.unwrap();
    drop(runtime);
    mock_stop.send(true).unwrap();
    mock.await.unwrap().unwrap();
}
