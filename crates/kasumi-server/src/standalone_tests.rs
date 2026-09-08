use super::*;
use crate::runtime::NodeRuntime;
use kasumi_types::{
    CollectionDefinition, CollectionRetentionClass, CollectionWriteMode, Mutation, MutationBatch,
    Operation, Precondition, RequestAuthorization, RequestContext,
};

fn context(tenant: &str) -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "administrator".into(),
        tenant: tenant.into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        request_id: Uuid::new_v4().to_string(),
    }
}

#[tokio::test]
async fn initialized_standalone_serves_native_mcp_and_durable_credential_lifecycle() {
    let root = tempfile::tempdir().unwrap();
    let installation = initialize(&root.path().join("kasumi"), "tenant-a")
        .await
        .unwrap();
    assert!(
        initialize(&root.path().join("kasumi"), "tenant-a")
            .await
            .is_err()
    );
    let mut config = RuntimeConfig::load(&installation.configuration).unwrap();
    let mut control = ClientProfile::load(&installation.control_profile).unwrap();
    let mut tenant = ClientProfile::load(&installation.tenant_profile).unwrap();
    let listeners = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let addresses = listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap())
        .collect::<Vec<_>>();
    config.mcp.listen = addresses[0];
    config.native.listen = addresses[1];
    config.admin.listen = addresses[2];
    config.mcp.protocol =
        crate::mcp::McpConfig::new(format!("https://localhost:{}/mcp", addresses[0].port()))
            .unwrap();
    for profile in [&mut control, &mut tenant] {
        profile.mcp_endpoint = config.mcp.protocol.public_url.clone();
        profile.native_endpoint = format!("https://localhost:{}", addresses[1].port());
        profile.admin_endpoint = format!("https://localhost:{}", addresses[2].port());
    }
    private_files::replace(
        &installation.control_profile,
        &serde_json::to_vec_pretty(&control).unwrap(),
    )
    .unwrap();
    private_files::replace(
        &installation.tenant_profile,
        &serde_json::to_vec_pretty(&tenant).unwrap(),
    )
    .unwrap();
    drop(listeners);
    let runtime = NodeRuntime::open(config.clone()).await.unwrap();
    assert!(NodeRuntime::open(config.clone()).await.is_err());
    let registry = runtime.registry().clone();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while registry.database(&context("tenant-a")).is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    registry
        .database(&context("tenant-a"))
        .unwrap()
        .administer(
            context("tenant-a"),
            Operation::CreateCollection(CollectionDefinition {
                name: "docs".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    let mut data = kasumi_client::KasumiClient::connect(&tenant.connection(false).unwrap())
        .await
        .unwrap();
    let mut admin = kasumi_client::KasumiAdminClient::connect(&control.connection(true).unwrap())
        .await
        .unwrap();
    let bearer = tenant.bearer().unwrap();
    let mutation = MutationBatch {
        idempotency_key: Uuid::new_v4().to_string(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: "first".into(),
            body: serde_json::json!({"message":"encrypted standalone document"}),
            expected: Precondition::Absent,
        }],
    };
    data.mutate(&bearer, &mutation).await.unwrap();
    assert!(
        data.mutate(&control.bearer().unwrap(), &mutation)
            .await
            .is_err()
    );
    let http = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&tenant.server_ca).unwrap()).unwrap(),
        )
        .build()
        .unwrap();
    let metadata_url = format!(
        "https://localhost:{}/.well-known/oauth-protected-resource/mcp",
        addresses[0].port()
    );
    let metadata = http.get(metadata_url).send().await.unwrap();
    assert!(metadata.status().is_success());
    assert!(
        metadata
            .json::<serde_json::Value>()
            .await
            .unwrap()
            .get("authorization_servers")
            .is_none()
    );
    let mcp = http.post(&tenant.mcp_endpoint).bearer_auth(bearer.as_str()).header("accept", "application/json, text/event-stream").header("mcp-protocol-version", "2026-07-28").header("mcp-method", "tools/call").header("mcp-name", "kasumi_get")
        .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"standalone-tests","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}},"name":"kasumi_get","arguments":{"collection":"docs","id":"first"}}}))
        .send().await.unwrap();
    assert!(mcp.status().is_success(), "{}", mcp.status());
    assert!(
        mcp.text()
            .await
            .unwrap()
            .contains("encrypted standalone document")
    );
    assert!(http.get(&tenant.native_endpoint).send().await.is_err()); // native TLS requires a client certificate
    let renewal = kasumi_types::RenewCredential {
        family_id: tenant.family_id,
        renewal_id: Uuid::new_v4(),
    };
    let renewed = admin.renew_credential(&bearer, &renewal).await.unwrap();
    assert_eq!(
        admin
            .renew_credential(&bearer, &renewal)
            .await
            .unwrap()
            .token,
        renewed.token
    );
    let new_request = CreateCredential {
        family_id: Uuid::new_v4(),
        principal: "administrator".into(),
        tenant: tenant.tenant.clone(),
        resource: tenant.resource.clone(),
        scopes: BTreeSet::from([Action::Read]),
        lifetime_seconds: 3600,
    };
    let restricted = admin
        .create_credential(&control.bearer().unwrap(), &new_request)
        .await
        .unwrap();
    let request_file = installation
        .configuration
        .parent()
        .unwrap()
        .join("profiles/create.json");
    let output_profile = installation
        .configuration
        .parent()
        .unwrap()
        .join("profiles/reader.json");
    private_files::create(&request_file, &serde_json::to_vec(&new_request).unwrap()).unwrap();
    let command = vec![
        "credential".into(),
        "create".into(),
        installation.control_profile.to_string_lossy().into_owned(),
        request_file.to_string_lossy().into_owned(),
        output_profile.to_string_lossy().into_owned(),
    ];
    crate::standalone_cli::command(&command).await.unwrap();
    crate::standalone_cli::command(&command).await.unwrap();
    assert_eq!(
        ClientProfile::load(&output_profile)
            .unwrap()
            .bearer()
            .unwrap()
            .as_str(),
        restricted.token
    );
    crate::standalone_cli::command(&[
        "credential".into(),
        "renew".into(),
        installation.tenant_profile.to_string_lossy().into_owned(),
    ])
    .await
    .unwrap();
    assert!(data.mutate(&restricted.token, &mutation).await.is_err());
    assert!(
        admin
            .create_credential(
                &bearer,
                &CreateCredential {
                    family_id: Uuid::new_v4(),
                    ..new_request.clone()
                }
            )
            .await
            .is_err()
    );
    let reference = kasumi_types::CredentialReference {
        family_id: tenant.family_id,
    };
    admin
        .revoke_credential(&control.bearer().unwrap(), &reference)
        .await
        .unwrap();
    assert!(data.mutate(&renewed.token, &mutation).await.is_err());
    stop.send_replace(true);
    serving.await.unwrap().unwrap();
    drop(data);
    drop(admin);
    drop(registry);
    let reopened = NodeRuntime::open(config).await.unwrap();
    let reopened_registry = reopened.registry().clone();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(reopened.serve(shutdown));
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while reopened_registry.database(&context("tenant-a")).is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        reopened_registry
            .database(&context("tenant-a"))
            .unwrap()
            .engine()
            .generation()
            .unwrap()
            .state
            .collections["docs"]
            .documents
            .contains_key("first")
    );
    stop.send_replace(true);
    serving.await.unwrap().unwrap();
}

#[tokio::test]
async fn offline_maintenance_and_administrator_recovery_require_exclusive_ownership() {
    let root = tempfile::tempdir().unwrap();
    let installation = initialize(&root.path().join("kasumi"), "tenant")
        .await
        .unwrap();
    let mut config = RuntimeConfig::load(&installation.configuration).unwrap();
    let listeners = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    config.mcp.listen = listeners[0].local_addr().unwrap();
    config.native.listen = listeners[1].local_addr().unwrap();
    config.admin.listen = listeners[2].local_addr().unwrap();
    config.mcp.protocol = crate::mcp::McpConfig::new(format!(
        "https://localhost:{}/mcp",
        config.mcp.listen.port()
    ))
    .unwrap();
    private_files::replace(
        &installation.configuration,
        &serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();
    for path in [&installation.control_profile, &installation.tenant_profile] {
        let mut profile = ClientProfile::load(path).unwrap();
        profile.mcp_endpoint = config.mcp.protocol.public_url.clone();
        profile.native_endpoint = format!("https://localhost:{}", config.native.listen.port());
        profile.admin_endpoint = format!("https://localhost:{}", config.admin.listen.port());
        private_files::replace(path, &serde_json::to_vec_pretty(&profile).unwrap()).unwrap();
    }
    drop(listeners);
    let runtime = NodeRuntime::open(config.clone()).await.unwrap();
    let registry = runtime.registry().clone();
    let control = runtime.control_database().clone();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while registry.database(&context("tenant")).is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    control
        .administer(
            context(crate::runtime::CONTROL_TENANT),
            Operation::SetPolicy(Policy {
                grants: vec![Grant {
                    principal: "next-operator".into(),
                    collection: None,
                    actions: BTreeSet::from([
                        Action::Read,
                        Action::Write,
                        Action::Admin,
                        Action::Audit,
                    ]),
                }],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    assert!(
        recover_administrator(
            &installation.configuration,
            &root.path().join("should-not-exist")
        )
        .await
        .is_err()
    );
    assert!(!root.path().join("should-not-exist").exists());
    assert!(
        rotate_wrapping_keys(&installation.configuration)
            .await
            .is_err()
    );
    stop.send_replace(true);
    serving.await.unwrap().unwrap();
    drop(control);
    drop(registry);
    rotate_wrapping_keys(&installation.configuration)
        .await
        .unwrap();
    assert_eq!(
        rotate_signing_key(&installation.configuration)
            .await
            .unwrap(),
        2
    );
    let old_profile = ClientProfile::load(&installation.control_profile).unwrap();
    let old_client_certificate = std::fs::read(&old_profile.identity.certificate).unwrap();
    rotate_certificates(&installation.configuration)
        .await
        .unwrap();
    let updated = ClientProfile::load(&installation.control_profile).unwrap();
    assert_ne!(
        old_client_certificate,
        std::fs::read(&updated.identity.certificate).unwrap()
    );
    assert_ne!(
        old_profile.admin_certificate_pin,
        updated.admin_certificate_pin
    );
    backup_operator_keys(
        &installation.configuration,
        &root.path().join("operator-backup"),
    )
    .await
    .unwrap();
    assert!(
        root.path()
            .join("operator-backup/security-keys.json")
            .exists()
    );
    let profiles =
        recover_administrator(&installation.configuration, &root.path().join("recovered"))
            .await
            .unwrap();
    assert_eq!(profiles.len(), 2);
    let recovered_control = profiles
        .iter()
        .map(|path| ClientProfile::load(path).unwrap())
        .find(|profile| profile.tenant == crate::runtime::CONTROL_TENANT)
        .unwrap();
    for profile in profiles {
        assert!(
            !ClientProfile::load(&profile)
                .unwrap()
                .bearer()
                .unwrap()
                .is_empty()
        );
    }
    let recovered_config = RuntimeConfig::load(&installation.configuration).unwrap();
    assert_eq!(
        recovered_config.control.startup_principal.as_deref(),
        Some("next-operator")
    );
    let runtime = NodeRuntime::open(recovered_config).await.unwrap();
    let registry = runtime.registry().clone();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while registry.database(&context("tenant")).is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let mut client =
        kasumi_client::KasumiAdminClient::connect(&recovered_control.connection(true).unwrap())
            .await
            .unwrap();
    let status = client
        .credential_status(
            &recovered_control.bearer().unwrap(),
            &kasumi_types::CredentialReference {
                family_id: recovered_control.family_id,
            },
        )
        .await
        .unwrap();
    assert!(status.revoked_at_ms.is_none());
    stop.send_replace(true);
    serving.await.unwrap().unwrap();
}
