use super::*;
use crate::runtime::NodeRuntime;
use kasumi_types::*;

fn context() -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "administrator".into(),
        tenant: "tenant-a".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        request_id: Uuid::new_v4().to_string(),
    }
}

#[tokio::test]
async fn backup_cli_persists_session_before_connect_and_resolves_original_completion() {
    let directory = tempfile::tempdir().unwrap();
    let installation = initialize(&directory.path().join("kasumi"), "tenant-a")
        .await
        .unwrap();
    let mut config = RuntimeConfig::load(&installation.configuration).unwrap();
    let mut profile = ClientProfile::load(&installation.tenant_profile).unwrap();
    let mut control = ClientProfile::load(&installation.control_profile).unwrap();
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
    for selected in [&mut profile, &mut control] {
        selected.native_endpoint = format!("https://localhost:{}", config.native.listen.port());
        selected.admin_endpoint = format!("https://localhost:{}", config.admin.listen.port());
        selected.mcp_endpoint = config.mcp.protocol.public_url.clone();
    }
    private_files::replace(
        &installation.tenant_profile,
        &serde_json::to_vec(&profile).unwrap(),
    )
    .unwrap();
    private_files::replace(
        &installation.control_profile,
        &serde_json::to_vec(&control).unwrap(),
    )
    .unwrap();
    crate::standalone::configure_test_topology(&config).await;
    drop(listeners);
    let output = installation
        .tenant_profile
        .with_file_name("backup-checkpoint.json");
    let create = vec![
        "backup".into(),
        "create".into(),
        installation.tenant_profile.display().to_string(),
        "local".into(),
        output.display().to_string(),
    ];
    // The transport cannot connect, but the operation identity is already durable.
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            crate::standalone_cli::command(&create)
        )
        .await
        .unwrap()
        .is_err()
    );
    assert!(!output.exists());
    let journal = output.with_extension("backup-attempt.json");
    let original = private_files::read(&journal, 128 << 10).unwrap();
    let persisted: serde_json::Value = serde_json::from_slice(&original).unwrap();
    let session_id = Uuid::parse_str(persisted["session_id"].as_str().unwrap()).unwrap();
    assert!(!session_id.is_nil());

    let runtime = NodeRuntime::open(config.clone()).await.unwrap();
    let registry = runtime.registry().clone();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while registry.database(&context()).is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    registry
        .database(&context())
        .unwrap()
        .administer(
            context(),
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
    let mut data = kasumi_client::KasumiClient::connect(&profile.connection(false).unwrap())
        .await
        .unwrap();
    let write = |id: &str| MutationBatch {
        idempotency_key: Uuid::new_v4().to_string(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: id.into(),
            body: serde_json::json!({"body":"encrypted original backup data"}),
            expected: Precondition::Absent,
        }],
    };
    data.mutate(&profile.bearer().unwrap(), &write("before"))
        .await
        .unwrap();
    assert!(crate::standalone_cli::command(&create).await.unwrap());
    assert_eq!(private_files::read(&journal, 128 << 10).unwrap(), original);
    let checkpoint_bytes = private_files::read(&output, 128 << 10).unwrap();
    let checkpoint: FullBackupCheckpoint = serde_json::from_slice(&checkpoint_bytes).unwrap();
    assert_eq!(checkpoint.backup_id, session_id);
    let later = data
        .mutate(&profile.bearer().unwrap(), &write("after"))
        .await
        .unwrap();
    assert!(later.revision > checkpoint.revision);
    assert!(crate::standalone_cli::command(&create).await.unwrap());
    assert_eq!(
        private_files::read(&output, 128 << 10).unwrap(),
        checkpoint_bytes
    );
    let base = |action: &str| {
        vec![
            "backup".into(),
            action.into(),
            installation.tenant_profile.display().to_string(),
            "local".into(),
            session_id.to_string(),
        ]
    };
    assert!(
        crate::standalone_cli::command(&base("status"))
            .await
            .unwrap()
    );
    assert!(
        crate::standalone_cli::command(&base("verify"))
            .await
            .unwrap()
    );
    // An abort attempt must report the existing completion, and completed
    // dependency graphs cannot become cleanup targets.
    let mut abort = base("abort");
    abort.push("operator-test".into());
    assert!(crate::standalone_cli::command(&abort).await.unwrap());
    let mut cleanup = base("cleanup");
    cleanup.push("256".into());
    assert!(crate::standalone_cli::command(&cleanup).await.is_err());
    assert_eq!(
        private_files::read(&output, 128 << 10).unwrap(),
        checkpoint_bytes
    );
    assert!(
        crate::standalone_cli::command(&base("verify"))
            .await
            .unwrap()
    );
    let mut changed = create.clone();
    changed[3] = "different-destination".into();
    assert!(crate::standalone_cli::command(&changed).await.is_err());

    // A fresh authorized credential may resolve the same original session after
    // its old family is revoked; the operation identity and source stay fixed.
    let mut admin = kasumi_client::KasumiAdminClient::connect(&control.connection(true).unwrap())
        .await
        .unwrap();
    let replacement = admin
        .create_credential(
            &control.bearer().unwrap(),
            &CreateCredential {
                family_id: Uuid::new_v4(),
                principal: "administrator".into(),
                tenant: profile.tenant.clone(),
                resource: profile.resource.clone(),
                scopes: BTreeSet::from([Action::Admin]),
                lifetime_seconds: 3600,
            },
        )
        .await
        .unwrap();
    admin
        .revoke_credential(
            &control.bearer().unwrap(),
            &CredentialReference {
                family_id: profile.family_id,
            },
        )
        .await
        .unwrap();
    private_files::replace(&profile.bearer_file, replacement.token.as_bytes()).unwrap();
    profile.family_id = replacement.family_id;
    private_files::replace(
        &installation.tenant_profile,
        &serde_json::to_vec(&profile).unwrap(),
    )
    .unwrap();
    assert!(crate::standalone_cli::command(&create).await.unwrap());
    assert_eq!(
        private_files::read(&output, 128 << 10).unwrap(),
        checkpoint_bytes
    );
    assert_eq!(private_files::read(&journal, 128 << 10).unwrap(), original);
    stop.send(true).unwrap();
    serving.await.unwrap().unwrap();
}
