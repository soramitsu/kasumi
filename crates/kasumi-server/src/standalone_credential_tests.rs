//! A new installation's credential layout: each native profile has only its
//! own authority, and its family is bound to that profile's certificate; MCP
//! has its own unbound credential and audience.
use super::*;
use crate::runtime::{AdminClientConfig, NodeRuntime};
use kasumi_types::{
    CollectionDefinition, CollectionRetentionClass, CollectionWriteMode, Mutation, MutationBatch,
    Precondition, ReadAssertion, RequestAuthorization, RequestContext, SchemaChange,
    SchemaChangeSet,
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

fn profiles(installation: &InitializedInstallation) -> [&Path; 3] {
    [
        &installation.control_profile,
        &installation.tenant_profile,
        &installation.operator_profile,
    ]
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

fn collection(name: &str) -> CollectionDefinition {
    CollectionDefinition {
        name: name.into(),
        write_mode: CollectionWriteMode::Mutable,
        retention_class: CollectionRetentionClass::Operational,
        schema: serde_json::json!({"type": "object"}),
        indexes: vec![],
        strict_read_audit: false,
    }
}

/// Create a collection through the administrative listener, as
/// `kasumictl --profile <profile> create-collection` does.
async fn create_collection(profile: &Path, name: &str) -> Result<(), tonic::Status> {
    let (mut client, authorization) =
        AdminClientConfig::from_profile(&ClientProfile::load(profile).unwrap())
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut request = tonic::Request::new(crate::rpc::proto::CollectionDefinitionRequest {
        definition_json: serde_json::to_vec(&collection(name)).unwrap(),
    });
    request
        .metadata_mut()
        .insert("authorization", authorization);
    client.create_collection(request).await.map(|_| ())
}

fn denied<T: std::fmt::Debug>(result: Result<T, kasumi_client::ClientError>) {
    match result {
        Err(kasumi_client::ClientError::Transport(status)) => {
            assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status:?}")
        }
        other => panic!("expected a permission denial, got {other:?}"),
    }
}

/// Serve the installation and check that the application reads and writes
/// documents and renews itself but cannot administer or audit, and that the
/// tenant operator administers, activates schema with read assertions and
/// cannot write documents.
async fn check_profile_authority(
    installation: &InitializedInstallation,
    storage: &crate::runtime_memory::RuntimeStorage,
) -> Result<()> {
    let config =
        crate::runtime_storage_fixtures::retarget_standalone(installation, storage).await?;
    let application = ClientProfile::load(&installation.tenant_profile)?;
    let operator = ClientProfile::load(&installation.operator_profile)?;
    let control = ClientProfile::load(&installation.control_profile)?;
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
        // Only the operator administers the tenant.
        assert_eq!(
            create_collection(&installation.tenant_profile, "docs")
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        create_collection(&installation.operator_profile, "docs")
            .await
            .unwrap();
        // Only the application writes documents.
        let mut data =
            kasumi_client::KasumiClient::connect(&application.connection(false)?).await?;
        data.mutate(&application.bearer()?, &put("first")).await?;
        let mut operator_data =
            kasumi_client::KasumiClient::connect(&operator.connection(false)?).await?;
        denied(
            operator_data
                .mutate(&operator.bearer()?, &put("second"))
                .await,
        );
        // The operator's schema activation asserts a collection it reads; the
        // application cannot activate schema at all.
        let database = registry.database(&service_context(&operator.tenant))?;
        let generation = database.engine().generation()?;
        let activation = SchemaChangeSet {
            activation_id: "operator-schema".into(),
            expected_incarnation: generation.state.incarnation.clone(),
            expected_schema_epoch: generation.state.schema_epoch,
            read_set: vec![ReadAssertion::Collection {
                collection: "docs".into(),
                data_epoch: generation.state.collections["docs"].data_epoch,
            }],
            changes: vec![SchemaChange::Create {
                definition: collection("journal"),
            }],
        };
        drop(generation);
        drop(database);
        let mut application_admin =
            kasumi_client::KasumiAdminClient::connect(&application.connection(true)?).await?;
        denied(
            application_admin
                .activate_schema(&application.bearer()?, &activation)
                .await,
        );
        let mut operator_admin =
            kasumi_client::KasumiAdminClient::connect(&operator.connection(true)?).await?;
        operator_admin
            .activate_schema(&operator.bearer()?, &activation)
            .await?;
        // Neither tenant credential reads the service audit or administers
        // credentials; the application still renews itself.
        for (admin, profile) in [
            (&mut application_admin, &application),
            (&mut operator_admin, &operator),
        ] {
            assert!(
                admin
                    .security_audit_status(&profile.bearer()?)
                    .await
                    .is_err()
            );
            assert!(
                admin
                    .create_credential(
                        &profile.bearer()?,
                        &CreateCredential {
                            family_id: Uuid::new_v4(),
                            principal: APPLICATION_PRINCIPAL.into(),
                            tenant: profile.tenant.clone(),
                            resource: profile.resource.clone(),
                            scopes: all_actions(),
                            lifetime_seconds: 3600,
                            client_certificate_sha256: None,
                            audience: Default::default(),
                        },
                    )
                    .await
                    .is_err()
            );
        }
        application_admin
            .renew_credential(
                &application.bearer()?,
                &kasumi_types::RenewCredential {
                    family_id: application.family_id,
                    renewal_id: Uuid::new_v4(),
                },
            )
            .await?;
        let mut control_admin =
            kasumi_client::KasumiAdminClient::connect(&control.connection(true)?).await?;
        control_admin
            .security_audit_status(&control.bearer()?)
            .await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    stop.send(true)?;
    serving.await??;
    checked
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
        .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"credential-tests","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}},"name":"kasumi_get","arguments":{"collection":"docs","id":"first"}}}))
        .send()
        .await
        .unwrap()
        .status()
}

/// Serve the installation and check that each native credential works only
/// from its own profile's certificate and never on MCP, and that the MCP
/// credential works only on MCP.
async fn check_binding(
    installation: &InitializedInstallation,
    storage: &crate::runtime_memory::RuntimeStorage,
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
        Ok::<_, anyhow::Error>(())
    }
    .await;
    stop.send(true)?;
    serving.await??;
    checked
}

#[test]
fn a_new_installation_gives_each_profile_only_its_own_authority() -> Result<()> {
    super::ownership_tests::run_large_fixture("split credential authority", || async {
        let root = kasumi_store::test_utils::private_tempdir()?;
        let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
            &root.path().join("kasumi"),
            "tenant",
        )
        .await?;
        let config = RuntimeConfig::load(&installation.configuration)?;
        assert_eq!(
            serde_json::to_value(&config.tenants[0].initial_policy)?,
            serde_json::to_value(tenant_policy())?
        );
        let expected = [
            (ADMINISTRATOR_PRINCIPAL, all_actions(), "control-client.pem"),
            (APPLICATION_PRINCIPAL, application_actions(), "client.pem"),
            (
                ADMINISTRATOR_PRINCIPAL,
                tenant_operator_actions(),
                "operator-client.pem",
            ),
        ];
        let mut owner = OperatorState::open(&config, storage.clone()).await?;
        let mut certificates = BTreeSet::new();
        for (path, (principal, scopes, certificate)) in
            profiles(&installation).into_iter().zip(expected)
        {
            let profile = ClientProfile::load(path)?;
            let family = owner.credentials.status(profile.family_id)?.specification;
            assert_eq!(
                (family.principal.as_str(), &family.scopes),
                (principal, &scopes)
            );
            assert_eq!(profile.principal, principal);
            assert_eq!(
                profile.identity.certificate.file_name(),
                Some(std::ffi::OsStr::new(certificate))
            );
            certificates.insert(TlsFiles::from(profile.identity).load()?.certificate_pin());
        }
        assert_eq!(
            certificates.len(),
            3,
            "each profile has its own certificate"
        );
        owner.finish(Ok(())).await?;
        drop(owner);
        check_profile_authority(&installation, &storage).await
    })
}

#[test]
fn a_new_installation_binds_native_credentials_and_separates_mcp() -> Result<()> {
    super::ownership_tests::run_large_fixture("certificate binding", || async {
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
        check_binding(&installation, &storage).await
    })
}

#[test]
fn credential_commands_bind_named_certificates_and_renew_mcp_through_control() -> Result<()> {
    super::ownership_tests::run_large_fixture("binding credential commands", || async {
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
