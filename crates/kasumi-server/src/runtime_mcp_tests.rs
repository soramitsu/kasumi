use crate::standalone::ClientProfile;
use kasumi_client::KasumiAdminClient;
use kasumi_store::private_files;
use kasumi_types::{CreateCredential, RenewCredential};
use serde_json::{Value, json};
use uuid::Uuid;

fn g07_mcp_call(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
    id: u64,
    name: &str,
    arguments: Value,
) -> reqwest::RequestBuilder {
    client
        .post(endpoint)
        .bearer_auth(token)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "g07-installed-tls", "version": "1"},
                    "io.modelcontextprotocol/clientCapabilities": {}
                },
                "name": name,
                "arguments": arguments
            }
        }))
}

#[test]
fn installed_mcp_mutation_release_keeps_original_deadline_and_receipt() {
    // The installed runtime, TLS listener, admin client and response fence
    // retain a large async frame. Run the same assertions on an explicit stack.
    std::thread::Builder::new()
        .name("installed MCP response-fence fixture".into())
        .stack_size(16 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(
                    installed_mcp_mutation_release_keeps_original_deadline_and_receipt_impl(),
                ));
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn installed_mcp_mutation_release_keeps_original_deadline_and_receipt_impl() {
    let _serial = LIFECYCLE_GATE.lock().await;
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
        &directory.path().join("kasumi"),
        "tenant-a",
    )
    .await
    .unwrap();
    let mut config = RuntimeConfig::load(&installation.configuration).unwrap();
    let mut control = ClientProfile::load(&installation.control_profile).unwrap();
    let tenant = ClientProfile::load(&installation.tenant_profile).unwrap();
    let listeners = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    config.mcp.listen = listeners[0].local_addr().unwrap();
    config.native.listen = listeners[1].local_addr().unwrap();
    config.admin.listen = listeners[2].local_addr().unwrap();
    config.mcp.protocol = McpConfig::new(format!(
        "https://localhost:{}/mcp",
        config.mcp.listen.port()
    ))
    .unwrap();
    let gate = crate::mcp::ReleaseGate::new();
    *config.mcp.protocol.release_gate.lock().unwrap() = Some(gate.clone());
    control.administrative_members.get_mut(&1).unwrap().endpoint =
        format!("https://localhost:{}", config.admin.listen.port());
    private_files::replace(
        &installation.control_profile,
        &serde_json::to_vec(&control).unwrap(),
    )
    .unwrap();
    crate::standalone::configure_test_topology(&config, storage.clone()).await;
    drop(listeners);

    let runtime =
        NodeRuntime::open_using_storage(config.clone(), crate::runtime::file_secret, storage)
            .await
            .unwrap();
    let registry = runtime.registry().clone();
    let service = RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: "administrator".into(),
        tenant: "tenant-a".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "g07-installed-mcp-resolution".into(),
    };
    let (stop, shutdown) = watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    let database = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(database) = registry.database(&service)
                && database.check_serving().is_ok()
            {
                break database;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    database
        .administer(
            service.clone(),
            Operation::CreateCollection(CollectionDefinition {
                name: "docs".into(),
                write_mode: kasumi_types::CollectionWriteMode::Mutable,
                retention_class: kasumi_types::CollectionRetentionClass::Operational,
                schema: json!({"type":"object"}),
                indexes: Vec::new(),
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    let mut admin = KasumiAdminClient::connect(&control.connection(true).unwrap())
        .await
        .unwrap();
    let short = admin
        .create_credential(
            &control.bearer().unwrap(),
            &CreateCredential {
                family_id: Uuid::new_v4(),
                principal: "administrator".into(),
                tenant: "tenant-a".into(),
                resource: tenant.resource.clone(),
                scopes: BTreeSet::from([Action::Read, Action::Write]),
                lifetime_seconds: 12,
            },
        )
        .await
        .unwrap();
    let client = reqwest::Client::builder()
        .https_only(true)
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .max_tls_version(reqwest::tls::Version::TLS_1_3)
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(
                &private_files::read(&tenant.server_ca, 1 << 20).unwrap(),
            )
            .unwrap(),
        )
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let endpoint = config.mcp.protocol.public_url.clone();
    let key = format!("g07-installed-{}", Uuid::new_v4());
    let batch = json!({
        "idempotency_key": key.clone(),
        "read_set": [],
        "operations": [{
            "op": "put", "collection": "docs", "id": "one",
            "body": {"retained": true}, "expected": {"kind": "absent"}
        }]
    });
    let _: MutationBatch = serde_json::from_value(batch.clone()).unwrap();
    let request = g07_mcp_call(
        &client,
        &endpoint,
        &short.token,
        1,
        "kasumi_mutate",
        batch.clone(),
    );
    let pending = tokio::spawn(async move { request.send().await.unwrap() });
    gate.entered().await;
    assert!(
        !pending.is_finished(),
        "terminal MCP response escaped its release gate"
    );
    let receipt = database
        .operation_receipt(&service, &key)
        .await
        .unwrap()
        .expect("mutation committed before terminal response release");
    assert!(receipt.outcome.is_ok());

    tokio::time::sleep(Duration::from_secs(4)).await;
    let renewed = admin
        .renew_credential(
            &short.token,
            &RenewCredential {
                family_id: short.family_id,
                renewal_id: Uuid::new_v4(),
            },
        )
        .await
        .unwrap();
    assert!(renewed.expires_at_ms > short.expires_at_ms);
    let now = kasumi_clock::EpochClock::system()
        .unwrap()
        .now_ms()
        .unwrap();
    assert!(now < short.expires_at_ms);
    tokio::time::sleep(Duration::from_millis(short.expires_at_ms - now + 100)).await;
    assert!(
        kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            < renewed.expires_at_ms,
        "renewed credential expired before the original request was released"
    );
    gate.release();
    let response = pending.await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"error":"UNKNOWN_OUTCOME"})
    );

    let response = g07_mcp_call(
        &client,
        &endpoint,
        &renewed.token,
        2,
        "kasumi_receipt",
        json!({"idempotency_key": key}),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let reply = response.json::<Value>().await.unwrap();
    assert_eq!(
        reply["result"]["structuredContent"],
        serde_json::to_value(&receipt).unwrap()
    );
    let response = g07_mcp_call(
        &client,
        &endpoint,
        &renewed.token,
        3,
        "kasumi_mutate",
        batch,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let reply = response.json::<Value>().await.unwrap();
    assert_eq!(
        reply["result"]["structuredContent"],
        serde_json::to_value(receipt.outcome.unwrap()).unwrap()
    );
    assert_eq!(
        database.get(&service, "docs", "one").await.unwrap().body,
        json!({"retained": true})
    );

    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(30), serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
