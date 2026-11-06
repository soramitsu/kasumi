use super::*;
use crate::runtime::{AdminClientConfig, NodeRuntime};
use kasumi_types::{
    CollectionDefinition, CollectionRetentionClass, CollectionWriteMode, Mutation, MutationBatch,
    Precondition, ReadAssertion, RequestAuthorization, RequestContext, SchemaChange,
    SchemaChangeSet,
};

#[test]
fn the_split_policy_removes_only_tenant_wide_administrator_write() -> Result<()> {
    let legacy = Policy {
        grants: vec![
            Grant {
                principal: ADMINISTRATOR_PRINCIPAL.into(),
                collection: None,
                actions: all_actions(),
            },
            Grant {
                principal: ADMINISTRATOR_PRINCIPAL.into(),
                collection: Some("ledger".into()),
                actions: BTreeSet::from([Action::Write]),
            },
            Grant {
                principal: "reporting".into(),
                collection: None,
                actions: BTreeSet::from([Action::Read]),
            },
        ],
        strict_read_audit: true,
    };
    let split = split_policy(&legacy)?;
    assert_eq!(
        serde_json::to_value(&split)?,
        serde_json::json!({
            "grants": [
                {"principal": "administrator", "collection": null, "actions": ["read", "admin", "audit"]},
                {"principal": "administrator", "collection": "ledger", "actions": ["write"]},
                {"principal": "reporting", "collection": null, "actions": ["read"]},
                {"principal": "application", "collection": null, "actions": ["read", "write"]},
            ],
            "strict_read_audit": true,
        })
    );
    // Repeating the split, or splitting a new installation's policy, changes nothing.
    for policy in [split, tenant_policy()] {
        assert_eq!(
            serde_json::to_value(split_policy(&policy)?)?,
            serde_json::to_value(&policy)?
        );
    }
    let mut conflicting = legacy;
    conflicting.grants.push(Grant {
        principal: APPLICATION_PRINCIPAL.into(),
        collection: None,
        actions: all_actions(),
    });
    assert!(split_policy(&conflicting).is_err());
    Ok(())
}

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
/// documents and renews itself but cannot administer or audit; that the
/// tenant operator administers, activates schema with read assertions and
/// cannot write documents; and that `refused`, the replaced family's last
/// token, if any, no longer authenticates.
async fn check_profile_authority(
    installation: &InitializedInstallation,
    storage: &crate::runtime_memory::RuntimeStorage,
    refused: Option<&str>,
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
        if let Some(refused) = refused {
            match data.mutate(refused, &put("third")).await {
                Err(kasumi_client::ClientError::Transport(status)) => {
                    assert_eq!(status.code(), tonic::Code::Unauthenticated, "{status:?}")
                }
                other => panic!("the replaced family still authenticates: {other:?}"),
            }
        }
        // The operator's schema activation asserts a collection it reads; the
        // application cannot activate schema at all.
        let database = registry.database(&service_context(&operator.tenant))?;
        let generation = database.engine().generation()?;
        let activation = SchemaChangeSet {
            activation_id: "split-operator-schema".into(),
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

#[test]
fn a_new_installation_gives_each_profile_only_its_own_authority() -> Result<()> {
    super::super::ownership_tests::run_large_fixture("split credential authority", || async {
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
        // The installation has nothing to split.
        let report =
            split_credentials_with_storage(&installation.configuration, storage.clone()).await?;
        assert!(!report.split && report.revoked_family.is_none());
        check_profile_authority(&installation, &storage, None).await
    })
}

/// Rewrite a new installation into the layout every installation had before
/// the split: `default.json` is the tenant administrator with every scope,
/// the tenant policy has no application, and every profile shares
/// `profiles/client.pem`. Returns the legacy family and its token.
async fn install_pre_split_layout(
    installation: &InitializedInstallation,
    storage: &crate::runtime_memory::RuntimeStorage,
) -> Result<(Uuid, String)> {
    let config = RuntimeConfig::load(&installation.configuration)?;
    let mut owner = OperatorState::open(&config, storage.clone()).await?;
    let result = async {
        let application = ClientProfile::load(&installation.tenant_profile)?;
        let database =
            open_tenant(&config, &owner, &application.tenant, &application.resource).await?;
        let policy = async {
            database
                .administer(
                    offline_context(&database)?,
                    kasumi_types::Operation::SetPolicy(Policy {
                        grants: vec![Grant {
                            principal: ADMINISTRATOR_PRINCIPAL.into(),
                            collection: None,
                            actions: all_actions(),
                        }],
                        strict_read_audit: false,
                    }),
                )
                .await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        database.shutdown().await?;
        policy?;
        let legacy = owner.credentials.create(
            CreateCredential {
                family_id: Uuid::new_v4(),
                principal: ADMINISTRATOR_PRINCIPAL.into(),
                tenant: application.tenant.clone(),
                resource: application.resource.clone(),
                scopes: all_actions(),
                lifetime_seconds: 3600,
            },
            "initializer",
        )?;
        owner.credentials.revoke(application.family_id, "fixture")?;
        private_files::replace(&application.bearer_file, legacy.token.as_bytes())?;
        let legacy_profile = ClientProfile {
            family_id: legacy.family_id,
            principal: ADMINISTRATOR_PRINCIPAL.into(),
            ..application.clone()
        };
        private_files::replace(
            &installation.tenant_profile,
            &serde_json::to_vec_pretty(&legacy_profile)?,
        )?;
        let mut control = ClientProfile::load(&installation.control_profile)?;
        control.identity = application.identity.clone();
        private_files::replace(
            &installation.control_profile,
            &serde_json::to_vec_pretty(&control)?,
        )?;
        let operator = ClientProfile::load(&installation.operator_profile)?;
        owner.credentials.revoke(operator.family_id, "fixture")?;
        let directory = installation.operator_profile.parent().context("profiles")?;
        for name in [
            "operator.json",
            "operator.token",
            "operator-client.pem",
            "operator-client-key.pem",
            "control-client.pem",
            "control-client-key.pem",
        ] {
            std::fs::remove_file(directory.join(name))?;
        }
        // A watcher stopped before the migration left its renewal identity.
        private_files::create(
            &application.bearer_file.with_extension("renewal.json"),
            &serde_json::to_vec(&kasumi_types::RenewCredential {
                family_id: legacy.family_id,
                renewal_id: Uuid::new_v4(),
            })?,
        )?;
        Ok((legacy.family_id, legacy.token))
    }
    .await;
    owner.finish(result).await
}

#[test]
fn a_pre_split_installation_is_split_once_and_finishes_after_an_interruption() -> Result<()> {
    super::super::ownership_tests::run_large_fixture("pre-split credential migration", || async {
        let root = kasumi_store::test_utils::private_tempdir()?;
        let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
            &root.path().join("kasumi"),
            "tenant",
        )
        .await?;
        let (legacy_family, legacy_token) =
            install_pre_split_layout(&installation, &storage).await?;
        let directory = installation.tenant_profile.parent().context("profiles")?;
        let journal_path = directory.join("credential-split.json");
        let renewal = directory.join("default.renewal.json");
        assert!(renewal.exists());
        // A running watcher of the replaced profile stops the migration.
        let watcher = private_files::ExclusiveLock::acquire(&directory.join("default.watch.lock"))?;
        assert!(
            split_credentials_with_storage(&installation.configuration, storage.clone())
                .await
                .is_err()
        );
        assert!(!journal_path.exists());
        drop(watcher);
        // Interrupt the first run after the new families and operator profile
        // exist, before the application's profile is replaced.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &installation.control_profile,
                std::fs::Permissions::from_mode(0o640),
            )?;
        }
        assert!(
            split_credentials_with_storage(&installation.configuration, storage.clone())
                .await
                .is_err()
        );
        let journal: Journal =
            serde_json::from_slice(&private_files::read(&journal_path, MAX_JOURNAL)?)?;
        assert_eq!(journal.legacy_family, legacy_family);
        assert_eq!(
            ClientProfile::load(&installation.operator_profile)?.family_id,
            journal.operator_family
        );
        assert_eq!(
            ClientProfile::load(&installation.tenant_profile)?.family_id,
            legacy_family
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &installation.control_profile,
                std::fs::Permissions::from_mode(0o600),
            )?;
        }
        let operator_certificate = std::fs::read(directory.join("operator-client.pem"))?;
        let report =
            split_credentials_with_storage(&installation.configuration, storage.clone()).await?;
        assert!(report.split);
        assert_eq!(report.revoked_family, Some(legacy_family));
        assert!(!journal_path.exists() && !renewal.exists());
        // The rerun finished the same split with the same families and certificate.
        assert_eq!(
            std::fs::read(directory.join("operator-client.pem"))?,
            operator_certificate
        );
        let application = ClientProfile::load(&installation.tenant_profile)?;
        let operator = ClientProfile::load(&installation.operator_profile)?;
        let control = ClientProfile::load(&installation.control_profile)?;
        assert_eq!(
            (application.family_id, application.principal.as_str()),
            (journal.application_family, APPLICATION_PRINCIPAL)
        );
        assert_eq!(
            (operator.family_id, operator.principal.as_str()),
            (journal.operator_family, ADMINISTRATOR_PRINCIPAL)
        );
        assert_eq!(
            application.identity.certificate,
            directory.join("client.pem")
        );
        assert_eq!(
            operator.identity.certificate,
            directory.join("operator-client.pem")
        );
        assert_eq!(
            control.identity.certificate,
            directory.join("control-client.pem")
        );
        let config = RuntimeConfig::load(&installation.configuration)?;
        let mut owner = OperatorState::open(&config, storage.clone()).await?;
        let checked = async {
            assert!(
                owner
                    .credentials
                    .status(legacy_family)?
                    .revoked_at_ms
                    .is_some()
            );
            for (profile, scopes) in [
                (&application, application_actions()),
                (&operator, tenant_operator_actions()),
            ] {
                let status = owner.credentials.status(profile.family_id)?;
                assert!(status.revoked_at_ms.is_none());
                assert_eq!(status.specification.scopes, scopes);
            }
            let database =
                open_tenant(&config, &owner, &application.tenant, &application.resource).await?;
            let policy = database.engine().generation()?.policy().clone();
            database.shutdown().await?;
            assert_eq!(
                serde_json::to_value(&policy)?,
                serde_json::to_value(tenant_policy())?
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        owner.finish(checked).await?;
        drop(owner);
        // A split installation has nothing left to split.
        let bytes = profiles(&installation).map(|path| std::fs::read(path).unwrap());
        let again =
            split_credentials_with_storage(&installation.configuration, storage.clone()).await?;
        assert!(!again.split);
        assert_eq!(
            profiles(&installation).map(|path| std::fs::read(path).unwrap()),
            bytes
        );
        check_profile_authority(&installation, &storage, Some(&legacy_token)).await
    })
}
