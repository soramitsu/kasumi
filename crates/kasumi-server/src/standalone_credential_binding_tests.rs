use super::*;
use crate::runtime::{AdminClientConfig, NodeRuntime};
use kasumi_types::{
    CollectionDefinition, CollectionRetentionClass, CollectionWriteMode, Mutation, MutationBatch,
    Precondition, RequestAuthorization, RequestContext,
};

fn service_context(tenant: &str) -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: ADMINISTRATOR_PRINCIPAL.into(),
        tenant: tenant.into(),
        scopes: tenant_operator_actions(),
        request_id: Uuid::new_v4().to_string(),
    }
}

fn put(id: &str) -> MutationBatch {
    MutationBatch {
        idempotency_key: Uuid::new_v4().to_string(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: id.into(),
            body: serde_json::json!({"id": id}),
            expected: Precondition::Absent,
        }],
    }
}

fn unauthenticated<T: std::fmt::Debug>(result: Result<T, kasumi_client::ClientError>) {
    match result {
        Err(kasumi_client::ClientError::Transport(status)) => {
            assert_eq!(status.code(), tonic::Code::Unauthenticated, "{status:?}")
        }
        other => panic!("expected an authentication refusal, got {other:?}"),
    }
}

fn pin_of(profile: &ClientProfile) -> String {
    hex::encode(profile.identity.load().unwrap().certificate_pin())
}

/// One MCP `kasumi_get` of docs/first with `token`, and its HTTP status.
async fn mcp_get(profile: &ClientProfile, token: &str) -> reqwest::StatusCode {
    let http = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&profile.server_ca).unwrap()).unwrap(),
        )
        .build()
        .unwrap();
    http.post(&profile.mcp_endpoint)
        .bearer_auth(token)
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "kasumi_get")
        .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"binding-tests","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}},"name":"kasumi_get","arguments":{"collection":"docs","id":"first"}}}))
        .send()
        .await
        .unwrap()
        .status()
}

/// Serve the installation and check that each native credential works only
/// from its own profile's certificate and never on MCP, that the MCP
/// credential works only on MCP, and that `refused` tokens no longer
/// authenticate at all.
async fn check_binding(
    installation: &InitializedInstallation,
    storage: &crate::runtime_memory::RuntimeStorage,
    refused: &[String],
) -> Result<()> {
    let config =
        crate::runtime_storage_fixtures::retarget_standalone(installation, storage).await?;
    let application = ClientProfile::load(&installation.tenant_profile)?;
    let operator = ClientProfile::load(&installation.operator_profile)?;
    let control = ClientProfile::load(&installation.control_profile)?;
    let mcp = ClientProfile::load(&installation.mcp_profile)?;
    let runtime =
        NodeRuntime::open_using_storage(config, crate::runtime::file_secret, storage.clone())
            .await?;
    let registry = runtime.registry().clone();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while registry
            .database(&service_context(&operator.tenant))
            .is_err()
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?;
    let checked = async {
        // The operator's bound token over its own certificate administers.
        let (mut client, authorization) = AdminClientConfig::from_profile(&operator)?
            .connect()
            .await?;
        let mut request = tonic::Request::new(crate::rpc::proto::CollectionDefinitionRequest {
            definition_json: serde_json::to_vec(&CollectionDefinition {
                name: "docs".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type": "object"}),
                indexes: vec![],
                strict_read_audit: false,
            })?,
        });
        request
            .metadata_mut()
            .insert("authorization", authorization);
        client.create_collection(request).await?;
        // The application's writes from its own certificate succeed, and its
        // token is refused over the operator's, equally admitted, certificate.
        let mut data =
            kasumi_client::KasumiClient::connect(&application.connection(false)?).await?;
        data.mutate(&application.bearer()?, &put("first")).await?;
        let mut elsewhere = kasumi_client::KasumiClient::connect(
            &ClientProfile {
                identity: operator.identity.clone(),
                ..application.clone()
            }
            .connection(false)?,
        )
        .await?;
        unauthenticated(
            elsewhere
                .mutate(&application.bearer()?, &put("second"))
                .await,
        );
        // MCP takes only the MCP credential, and the native listener refuses it.
        assert_eq!(
            mcp_get(&application, &mcp.bearer()?).await,
            reqwest::StatusCode::OK
        );
        for native in [&application, &operator, &control] {
            assert_eq!(
                mcp_get(&application, &native.bearer()?).await,
                reqwest::StatusCode::UNAUTHORIZED
            );
        }
        unauthenticated(data.mutate(&mcp.bearer()?, &put("third")).await);
        // The protected observation routes check the binding too.
        let (status, _) = AdminClientConfig::from_profile(&control)?
            .observe("/metrics")
            .await?;
        assert_eq!(status, 200);
        let (status, _) = AdminClientConfig::from_profile(&ClientProfile {
            identity: application.identity.clone(),
            ..control.clone()
        })?
        .observe("/metrics")
        .await?;
        assert_eq!(status, 401);
        for token in refused {
            unauthenticated(data.mutate(token, &put("refused")).await);
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    stop.send(true)?;
    serving.await??;
    checked
}

#[test]
fn a_new_installation_binds_native_credentials_and_separates_mcp() -> Result<()> {
    super::super::ownership_tests::run_large_fixture("certificate binding", || async {
        let root = kasumi_store::test_utils::private_tempdir()?;
        let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
            &root.path().join("kasumi"),
            "tenant",
        )
        .await?;
        let config = RuntimeConfig::load(&installation.configuration)?;
        assert!(config.auth.require_certificate_binding);
        assert!(config.auth.mcp_audience.is_some());
        // Each native family is bound to its own profile's certificate; the
        // MCP family is unbound and for the MCP audience.
        let mut owner = OperatorState::open(&config, storage.clone()).await?;
        for path in [
            &installation.control_profile,
            &installation.tenant_profile,
            &installation.operator_profile,
        ] {
            let profile = ClientProfile::load(path)?;
            let family = owner.credentials.status(profile.family_id)?.specification;
            assert_eq!(family.client_certificate_sha256, Some(pin_of(&profile)));
            assert_eq!(family.audience, CredentialAudience::Native);
        }
        let mcp = ClientProfile::load(&installation.mcp_profile)?;
        let family = owner.credentials.status(mcp.family_id)?.specification;
        assert_eq!(family.client_certificate_sha256, None);
        assert_eq!(family.audience, CredentialAudience::Mcp);
        owner.finish(Ok(())).await?;
        drop(owner);
        check_binding(&installation, &storage, &[]).await?;
        // The installation has nothing to migrate.
        let report =
            bind_credentials_with_storage(&installation.configuration, storage.clone()).await?;
        assert!(!report.bound && report.profiles.is_empty());
        Ok(())
    })
}

#[test]
fn credential_commands_bind_named_certificates_and_renew_mcp_through_control() -> Result<()> {
    super::super::ownership_tests::run_large_fixture("binding credential commands", || async {
        let root = kasumi_store::test_utils::private_tempdir()?;
        let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
            &root.path().join("kasumi"),
            "tenant",
        )
        .await?;
        let config =
            crate::runtime_storage_fixtures::retarget_standalone(&installation, &storage).await?;
        let application = ClientProfile::load(&installation.tenant_profile)?;
        let runtime =
            NodeRuntime::open_using_storage(config, crate::runtime::file_secret, storage.clone())
                .await?;
        let registry = runtime.registry().clone();
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        let serving = tokio::spawn(runtime.serve(shutdown));
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while registry
                .database(&service_context(&application.tenant))
                .is_err()
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await?;
        let checked = async {
            let text = |path: &Path| path.to_string_lossy().into_owned();
            let directory = installation.tenant_profile.parent().context("profiles")?;
            // An MCP credential cannot renew itself; the Control profile renews it.
            let mcp = ClientProfile::load(&installation.mcp_profile)?;
            let before = mcp.bearer()?;
            assert!(
                crate::standalone_cli::command(&[
                    "credential".into(),
                    "renew".into(),
                    text(&installation.mcp_profile),
                ])
                .await
                .is_err()
            );
            crate::standalone_cli::command(&[
                "credential".into(),
                "renew".into(),
                text(&installation.mcp_profile),
                text(&installation.control_profile),
            ])
            .await?;
            assert_ne!(mcp.bearer()?.as_str(), before.as_str());
            // A native credential must name its certificate on this installation.
            let request = CreateCredential {
                family_id: Uuid::new_v4(),
                principal: APPLICATION_PRINCIPAL.into(),
                tenant: application.tenant.clone(),
                resource: application.resource.clone(),
                scopes: BTreeSet::from([Action::Read]),
                lifetime_seconds: 3600,
                client_certificate_sha256: None,
                audience: CredentialAudience::Native,
            };
            let request_path = directory.join("reader-request.json");
            private_files::create(&request_path, &serde_json::to_vec(&request)?)?;
            let output = directory.join("reader.json");
            let create = |identity: &[String]| {
                let mut arguments = vec![
                    "credential".into(),
                    "create".into(),
                    text(&installation.control_profile),
                    text(&request_path),
                    text(&output),
                ];
                arguments.extend_from_slice(identity);
                arguments
            };
            let refused = crate::standalone_cli::command(&create(&[]))
                .await
                .unwrap_err();
            assert!(
                format!("{refused:#}").contains("client certificate"),
                "{refused:#}"
            );
            std::fs::remove_file(directory.join("reader.create.json"))?;
            crate::standalone_cli::command(&create(&[
                text(&application.identity.certificate),
                text(&application.identity.private_key),
            ]))
            .await?;
            let reader = ClientProfile::load(&output)?;
            assert_eq!(
                reader.identity.certificate,
                application.identity.certificate
            );
            let mut admin = kasumi_client::KasumiAdminClient::connect(
                &ClientProfile::load(&installation.control_profile)?.connection(true)?,
            )
            .await?;
            let status = admin
                .credential_status(
                    &ClientProfile::load(&installation.control_profile)?.bearer()?,
                    &kasumi_types::CredentialReference {
                        family_id: reader.family_id,
                    },
                )
                .await?;
            assert_eq!(
                status.specification.client_certificate_sha256,
                Some(pin_of(&application))
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        stop.send(true)?;
        serving.await??;
        checked
    })
}

/// Rewrite a new installation into the layout every installation had before
/// certificate binding: unbound native families, no MCP audience or profile,
/// and no binding requirement. Returns the replaced tokens.
async fn install_pre_binding_layout(
    installation: &InitializedInstallation,
    storage: &crate::runtime_memory::RuntimeStorage,
) -> Result<Vec<String>> {
    let mut config = RuntimeConfig::load(&installation.configuration)?;
    let mut owner = OperatorState::open(&config, storage.clone()).await?;
    let result = async {
        let mut tokens = Vec::new();
        for path in [
            &installation.control_profile,
            &installation.tenant_profile,
            &installation.operator_profile,
        ] {
            let profile = ClientProfile::load(path)?;
            let mut specification = owner.credentials.status(profile.family_id)?.specification;
            owner.credentials.revoke(profile.family_id, "fixture")?;
            specification.family_id = Uuid::new_v4();
            specification.client_certificate_sha256 = None;
            let issued = owner.credentials.create(specification, "initializer")?;
            private_files::replace(&profile.bearer_file, issued.token.as_bytes())?;
            private_files::replace(
                path,
                &serde_json::to_vec_pretty(&ClientProfile {
                    family_id: issued.family_id,
                    ..profile
                })?,
            )?;
            tokens.push(issued.token);
        }
        let mcp = ClientProfile::load(&installation.mcp_profile)?;
        owner.credentials.revoke(mcp.family_id, "fixture")?;
        std::fs::remove_file(&mcp.bearer_file)?;
        std::fs::remove_file(&installation.mcp_profile)?;
        Ok(tokens)
    }
    .await;
    let tokens = owner.finish(result).await?;
    config.auth.mcp_audience = None;
    config.auth.require_certificate_binding = false;
    private_files::replace(
        &installation.configuration,
        &serde_json::to_vec_pretty(&config)?,
    )?;
    Ok(tokens)
}

#[test]
fn bind_credentials_rebinds_every_profile_once_and_finishes_after_an_interruption() -> Result<()> {
    super::super::ownership_tests::run_large_fixture("certificate binding migration", || async {
        let root = kasumi_store::test_utils::private_tempdir()?;
        let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
            &root.path().join("kasumi"),
            "tenant",
        )
        .await?;
        let unbound = install_pre_binding_layout(&installation, &storage).await?;
        let directory = installation.tenant_profile.parent().context("profiles")?;
        let journal_path = directory.join("credential-binding.json");
        // A running watcher stops the migration before anything changes.
        let watcher =
            private_files::ExclusiveLock::acquire(&directory.join("operator.watch.lock"))?;
        assert!(
            bind_credentials_with_storage(&installation.configuration, storage.clone())
                .await
                .is_err()
        );
        drop(watcher);
        // Interrupt the run after every profile is rebound, before the MCP
        // credential is published.
        std::fs::create_dir(directory.join("mcp.token"))?;
        assert!(
            bind_credentials_with_storage(&installation.configuration, storage.clone())
                .await
                .is_err()
        );
        let journal: Journal =
            serde_json::from_slice(&private_files::read(&journal_path, MAX_JOURNAL)?)?;
        assert_eq!(
            journal
                .profiles
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["control.json", "default.json", "operator.json"]
        );
        std::fs::remove_dir(directory.join("mcp.token"))?;
        let report =
            bind_credentials_with_storage(&installation.configuration, storage.clone()).await?;
        assert!(report.bound && !journal_path.exists());
        assert_eq!(report.mcp_audience, Some(journal.mcp_audience.clone()));
        let config = RuntimeConfig::load(&installation.configuration)?;
        assert!(config.auth.require_certificate_binding);
        assert_eq!(config.auth.mcp_audience, Some(journal.mcp_audience.clone()));
        let mut owner = OperatorState::open(&config, storage.clone()).await?;
        let checked = async {
            for (name, replacement) in &journal.profiles {
                let profile = ClientProfile::load(&directory.join(name))?;
                // The rerun finished with the families the first run journaled.
                assert_eq!(profile.family_id, replacement.family);
                assert_eq!(report.profiles[name], replacement.replaced);
                let family = owner.credentials.status(replacement.family)?;
                assert_eq!(
                    family.specification.client_certificate_sha256,
                    Some(pin_of(&profile))
                );
                assert!(
                    owner
                        .credentials
                        .status(replacement.replaced)?
                        .revoked_at_ms
                        .is_some()
                );
            }
            let mcp = ClientProfile::load(&installation.mcp_profile)?;
            assert_eq!(mcp.family_id, journal.mcp_family);
            let family = owner.credentials.status(mcp.family_id)?.specification;
            assert_eq!(family.audience, CredentialAudience::Mcp);
            assert_eq!(family.client_certificate_sha256, None);
            Ok::<_, anyhow::Error>(())
        }
        .await;
        owner.finish(checked).await?;
        drop(owner);
        // A bound installation has nothing left to migrate.
        let again =
            bind_credentials_with_storage(&installation.configuration, storage.clone()).await?;
        assert!(!again.bound);
        check_binding(&installation, &storage, &unbound).await
    })
}
