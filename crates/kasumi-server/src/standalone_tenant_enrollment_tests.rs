use super::*;
use crate::{administration::ManagementCommand, runtime::NodeRuntime};
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

async fn manage(profile: &ClientProfile, command: ManagementCommand) -> Result<()> {
    let connection = crate::runtime::AdminClientConfig {
        endpoint: profile.admin_endpoint.clone(),
        identity: profile.identity.clone(),
        server_ca: profile.server_ca.clone(),
        server_certificate_pins: vec![profile.admin_certificate_pin.clone()],
        token_file: profile.bearer_file.to_string_lossy().into_owned(),
    };
    let (mut client, authorization) = connection.connect().await?;
    let mut request = tonic::Request::new(crate::rpc::proto::ManagementRequest {
        command_json: serde_json::to_vec(&command)?,
    });
    request
        .metadata_mut()
        .insert("authorization", authorization);
    request.set_timeout(std::time::Duration::from_secs(60));
    let response = client.manage(request).await?.into_inner();
    let _: serde_json::Value = serde_json::from_slice(&response.result_json)?;
    Ok(())
}
async fn installation() -> Result<(
    tempfile::TempDir,
    InitializedInstallation,
    StageTenantRequest,
)> {
    let root = tempfile::tempdir()?;
    let installed = initialize(&root.path().join("installed"), "tenant-a").await?;
    let mut config = RuntimeConfig::load(&installed.configuration)?;
    let listeners = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0"))
        .collect::<std::io::Result<Vec<_>>>()?;
    config.mcp.listen = listeners[0].local_addr()?;
    config.native.listen = listeners[1].local_addr()?;
    config.admin.listen = listeners[2].local_addr()?;
    config.mcp.protocol = crate::mcp::McpConfig::new(format!(
        "https://localhost:{}/mcp",
        config.mcp.listen.port()
    ))?;
    for path in [&installed.control_profile, &installed.tenant_profile] {
        let mut profile = ClientProfile::load(path)?;
        profile.mcp_endpoint = config.mcp.protocol.public_url.clone();
        profile.native_endpoint = format!("https://localhost:{}", config.native.listen.port());
        profile.admin_endpoint = format!("https://localhost:{}", config.admin.listen.port());
        private_files::replace(path, &serde_json::to_vec_pretty(&profile)?)?;
    }
    configure_test_topology(&config).await;
    private_files::replace(
        &installed.configuration,
        &serde_json::to_vec_pretty(&config)?,
    )?;
    drop(listeners);
    let request = StageTenantRequest {
        operation_id: Uuid::new_v4(),
        tenant: "tenant-b".into(),
        incarnation: Uuid::new_v4(),
        initial_policy: config.tenants[0].initial_policy.clone(),
        initial_limits: config.tenants[0].initial_limits.clone(),
    };
    stage_tenant(&installed.configuration, request.clone()).await?;
    Ok((root, installed, request))
}

#[tokio::test]
async fn unrecorded_standalone_template_never_opens_missing_keyrings_or_catalogs() -> Result<()> {
    let (_root, installed, request) = installation().await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let staged = config
        .tenants
        .iter()
        .find(|entry| entry.tenant == request.tenant)
        .unwrap();
    let KeyProviderSettings::File { path } = &staged.keys else {
        unreachable!()
    };
    let original = private_files::read(path, 1 << 20)?;
    std::fs::remove_file(path)?;
    private_files::sync_parent(path)?;
    let mut runtime = NodeRuntime::open(config.clone()).await?;
    let manager = runtime.administration_for_enrollment_test();
    assert!(runtime.enrollment_for_test(&request.tenant)?.is_none());
    assert!(!kasumi_store::CustodyStore::catalog_installed(
        &manager.node_for_enrollment_test(),
        &request.tenant
    )?);
    assert!(
        runtime
            .registry()
            .database(&context(&request.tenant))
            .is_err()
    );
    runtime.shutdown().await?;
    drop(manager);
    drop(runtime);
    // Installed maintenance also selects only required, completed ledger rows.
    rotate_wrapping_keys(&installed.configuration).await?;
    assert!(!path.exists());
    private_files::create(path, &original)?;
    Ok(())
}

#[tokio::test]
async fn explicitly_enrolled_standalone_tenant_requires_bound_profile_and_survives_restart()
-> Result<()> {
    let (_root, installed, staged) = installation().await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let control_profile = ClientProfile::load(&installed.control_profile)?;
    let original_profile = ClientProfile::load(&installed.tenant_profile)?;
    let runtime = NodeRuntime::open(config.clone()).await?;
    let manager = runtime.administration_for_enrollment_test();
    let registry = runtime.registry().clone();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    assert!(registry.database(&context(&staged.tenant)).is_err());
    let control = context(crate::runtime::CONTROL_TENANT);
    for command in [
        ManagementCommand::ApproveTenant {
            tenant: staged.tenant.clone(),
        },
        ManagementCommand::PrepareTenant {
            tenant: staged.tenant.clone(),
        },
        ManagementCommand::InitializeTenant {
            tenant: staged.tenant.clone(),
        },
    ] {
        manage(&control_profile, command).await?;
    }
    assert!(registry.database(&context(&staged.tenant)).is_err());
    let state = registry.database(&control)?.engine().generation()?;
    let version = state.state.collections["topology"].documents["current"].version;
    manage(
        &control_profile,
        ManagementCommand::ActivateTenant {
            tenant: staged.tenant.clone(),
            expected_topology_version: version,
        },
    )
    .await?;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while registry.database(&context(&staged.tenant)).is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?;
    let database = registry.database(&context(&staged.tenant))?;
    assert_eq!(
        database.engine().generation()?.state.incarnation,
        staged.incarnation.to_string()
    );
    database
        .administer(
            context(&staged.tenant),
            Operation::CreateCollection(CollectionDefinition {
                name: "docs".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await?;
    let mut admin =
        kasumi_client::KasumiAdminClient::connect(&control_profile.connection(true)?).await?;
    let credential = CreateCredential {
        family_id: Uuid::new_v4(),
        principal: "administrator".into(),
        tenant: staged.tenant.clone(),
        resource: CredentialResource::Database {
            incarnation: staged.incarnation,
        },
        scopes: BTreeSet::from([Action::Read, Action::Write]),
        lifetime_seconds: 3600,
    };
    let wrong = CreateCredential {
        family_id: Uuid::new_v4(),
        resource: CredentialResource::Database {
            incarnation: Uuid::new_v4(),
        },
        ..credential.clone()
    };
    assert!(
        admin
            .create_credential(&control_profile.bearer()?, &wrong)
            .await
            .is_err()
    );
    let request_file = installation_root(&config)?.join("profiles/tenant-b-request.json");
    let output = installation_root(&config)?.join("profiles/tenant-b.json");
    private_files::create(&request_file, &serde_json::to_vec(&credential)?)?;
    crate::standalone_cli::command(&[
        "credential".into(),
        "create".into(),
        installed.control_profile.to_string_lossy().into_owned(),
        request_file.to_string_lossy().into_owned(),
        output.to_string_lossy().into_owned(),
    ])
    .await?;
    let profile = ClientProfile::load(&output)?;
    assert_eq!(
        profile.resource,
        CredentialResource::Database {
            incarnation: staged.incarnation
        }
    );
    let mut client = kasumi_client::KasumiClient::connect(&profile.connection(false)?).await?;
    let mutation = MutationBatch {
        idempotency_key: Uuid::new_v4().to_string(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: "first".into(),
            body: serde_json::json!({"message":"explicit standalone enrollment"}),
            expected: Precondition::Absent,
        }],
    };
    assert!(
        client
            .mutate(&control_profile.bearer()?, &mutation)
            .await
            .is_err()
    );
    client.mutate(&profile.bearer()?, &mutation).await?;
    // A profile for another tenant is bound to its own resource, not this one.
    assert_ne!(original_profile.resource, profile.resource);
    let http = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            &profile.server_ca,
        )?)?)
        .build()?;
    let mcp = http.post(&profile.mcp_endpoint).bearer_auth(profile.bearer()?.as_str()).header("accept", "application/json, text/event-stream").header("mcp-protocol-version", "2026-07-28").header("mcp-method", "tools/call").header("mcp-name", "kasumi_get").json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"tenant-enrollment-tests","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}},"name":"kasumi_get","arguments":{"collection":"docs","id":"first"}}})).send().await?;
    assert!(mcp.status().is_success());
    assert!(mcp.text().await?.contains("explicit standalone enrollment"));
    let status = admin
        .credential_status(
            &control_profile.bearer()?,
            &kasumi_types::CredentialReference {
                family_id: credential.family_id,
            },
        )
        .await?;
    assert_eq!(status.specification.family_id, credential.family_id);
    drop(database);
    drop(manager);
    drop(state);
    drop(client);
    drop(admin);
    stop.send_replace(true);
    serving.await??;
    drop(registry);
    let mut reopened = NodeRuntime::open(config.clone()).await?;
    let record = reopened.enrollment_for_test(&staged.tenant)?.unwrap();
    assert_eq!(
        record,
        (staged.incarnation, crate::node_enrollment::Stage::Prepared)
    );
    let owner = reopened
        .administration_for_enrollment_test()
        .test_generation(&staged.tenant, &staged.incarnation.to_string());
    assert!(
        owner.engine().generation()?.state.collections["docs"]
            .documents
            .contains_key("first")
    );
    drop(owner);
    reopened.shutdown().await?;
    drop(reopened);
    // A later tenant is not part of immutable genesis. Its routed enrollment
    // row must still be required by every stopped maintenance selector.
    let mut maintenance = OperatorState::open(&config).await?;
    let ledger_key = format!("tenant/{}", staged.tenant);
    let saved = maintenance
        .audit
        .store()
        .get("node.enrollment", ledger_key.as_bytes())?
        .unwrap();
    maintenance
        .audit
        .store()
        .write_batch(&[kasumi_store::WriteOp::delete(
            "node.enrollment",
            ledger_key.as_bytes(),
        )])?;
    maintenance.finish(Ok(())).await?;
    drop(maintenance);
    let KeyProviderSettings::File {
        path: control_keyring,
    } = &config.control.keys
    else {
        unreachable!()
    };
    let before = private_files::read(control_keyring, 1 << 20)?;
    assert!(
        rotate_wrapping_keys(&installed.configuration)
            .await
            .is_err()
    );
    assert_eq!(
        private_files::read(control_keyring, 1 << 20)?.as_slice(),
        before.as_slice()
    );
    let recovery_output = installation_root(&config)?.join("must-not-create-profile");
    assert!(
        recover_administrator(&installed.configuration, &recovery_output)
            .await
            .is_err()
    );
    assert!(!recovery_output.exists());
    let mut maintenance = OperatorState::open(&config).await?;
    maintenance
        .audit
        .store()
        .write_batch(&[kasumi_store::WriteOp::put(
            "node.enrollment",
            ledger_key.as_bytes(),
            saved,
        )])?;
    maintenance.finish(Ok(())).await?;
    Ok(())
}
