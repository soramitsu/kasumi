use super::*;
use crate::standalone::ClientProfile;
use kasumi_client::{ClientError, KasumiAdminClient};
use kasumi_store::private_files;
use kasumi_types::*;
use uuid::Uuid;

fn denied(error: ClientError) {
    let ClientError::Transport(error) = error else {
        panic!("expected a transport denial: {error}")
    };
    assert!(
        matches!(
            error.code(),
            tonic::Code::PermissionDenied
                | tonic::Code::Unauthenticated
                | tonic::Code::DeadlineExceeded
        ),
        "{error}"
    );
}
async fn append(audit: &SecurityAudit, count: usize) {
    for index in 0..count {
        audit
            .record(SecurityEvent {
                kind: SecurityEventKind::Administration,
                principal: Some("administrator".into()),
                tenant: Some(CONTROL_TENANT.into()),
                request_id: format!("audit-test-{index}-{}", "a".repeat(200)),
                outcome: SecurityOutcome::Succeeded,
            })
            .await
            .unwrap();
        if index % 64 == 0 {
            audit.maintain().await.unwrap();
        }
    }
    audit.maintain().await.unwrap();
}
async fn gate(
    holder: &Arc<tokio::sync::Mutex<Option<crate::rpc::AuditReleaseGate>>>,
) -> crate::rpc::AuditReleaseGate {
    let gate = crate::rpc::AuditReleaseGate {
        entered: Arc::new(tokio::sync::Notify::new()),
        release: Arc::new(tokio::sync::Notify::new()),
    };
    *holder.lock().await = Some(gate.clone());
    gate
}
async fn entered(gate: &crate::rpc::AuditReleaseGate) {
    tokio::time::timeout(Duration::from_secs(10), gate.entered.notified())
        .await
        .unwrap();
}

#[test]
fn audit_native_tls_fixed_history_and_original_authorization_release() {
    // This aggregate fixture retains TLS, native clients, archived audit pages,
    // and authorization-release futures. Isolate its frame from libtest's stack.
    std::thread::Builder::new()
        .name("audit native TLS aggregate fixture".into())
        .stack_size(16 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(
                    audit_native_tls_fixed_history_and_original_authorization_release_impl(),
                ));
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn audit_native_tls_fixed_history_and_original_authorization_release_impl() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
        &directory.path().join("kasumi"),
        "tenant-a",
    )
    .await
    .unwrap();
    let mut config = RuntimeConfig::load(&installation.configuration).unwrap();
    config.security_audit.retention.hot_bytes = 128 << 10;
    let mut control = ClientProfile::load(&installation.control_profile).unwrap();
    let mut tenant = ClientProfile::load(&installation.tenant_profile).unwrap();
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
    for profile in [&mut control, &mut tenant] {
        profile.mcp_endpoint = config.mcp.protocol.public_url.clone();
        profile.native_endpoint = format!("https://localhost:{}", config.native.listen.port());
        profile.administrative_members.get_mut(&1).unwrap().endpoint =
            format!("https://localhost:{}", config.admin.listen.port());
    }
    private_files::replace(
        &installation.control_profile,
        &serde_json::to_vec(&control).unwrap(),
    )
    .unwrap();
    crate::standalone::configure_test_topology(&config, storage.clone()).await;
    drop(listeners);
    let runtime = NodeRuntime::open_using_storage(
        config.clone(),
        crate::runtime::file_secret,
        storage.clone(),
    )
    .await
    .unwrap();
    let audit = runtime.audit.clone();
    let database = runtime.control.database.clone();
    let release = runtime.audit_release_gate.clone();
    let (stop, shutdown) = watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    let mut admin = KasumiAdminClient::connect(&control.connection(true).unwrap())
        .await
        .unwrap();
    let operator = control.bearer().unwrap();
    // Tenant administrators and Control read-only or ungranted principals cannot
    // use this service route, even with valid TLS and exact resource credentials.
    denied(
        admin
            .security_audit_status(&tenant.bearer().unwrap())
            .await
            .unwrap_err(),
    );
    for (principal, scopes) in [
        ("administrator", BTreeSet::from([Action::Read])),
        ("ungranted", BTreeSet::from([Action::Admin])),
    ] {
        let issued = admin
            .create_credential(
                &operator,
                &CreateCredential {
                    family_id: Uuid::new_v4(),
                    principal: principal.into(),
                    tenant: CONTROL_TENANT.into(),
                    resource: control.resource.clone(),
                    scopes,
                    lifetime_seconds: 3600,
                },
            )
            .await
            .unwrap();
        denied(
            admin
                .security_audit_status(&issued.token)
                .await
                .unwrap_err(),
        );
    }
    append(&audit, 40).await;
    let decode_resources = kasumi_client::ClientResources::new(512 << 20, 4).unwrap();
    let decode_options = || kasumi_client::JsonReadOptions {
        resources: decode_resources.clone(),
        limits: kasumi_client::ClientDecodeLimits {
            max_request_bytes: 64 << 10,
            max_wire_bytes: 2 << 20,
            max_json_bytes: 1 << 20,
            max_decoded_bytes: 64 << 20,
            max_rows: 1024,
            ..Default::default()
        },
        deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(30),
    };
    let first = admin
        .export_security_audit(
            &operator,
            &SecurityAuditExportRequest {
                cursor: None,
                limit: 2,
            },
            &decode_options(),
        )
        .await
        .unwrap();
    assert_eq!(first.next_sequence, 2);
    let end = first.through_sequence;
    let stream = first.stream_id;
    append(&audit, 750).await;
    let status = admin.security_audit_status(&operator).await.unwrap();
    assert!(status.position.pruned_before > end);
    assert!(status.archive_segments > 1);
    let mut cursor = first.cursor();
    let mut sequences = first
        .records
        .iter()
        .map(|value| value["sequence"].as_u64().unwrap())
        .collect::<Vec<_>>();
    while let Some(next) = cursor {
        let page = admin
            .export_security_audit(
                &operator,
                &SecurityAuditExportRequest {
                    cursor: Some(next),
                    limit: 1024,
                },
                &decode_options(),
            )
            .await
            .unwrap();
        assert_eq!(page.stream_id, stream);
        assert_eq!(page.through_sequence, end);
        assert!(serde_json::to_vec(&*page).unwrap().len() <= MAX_SECURITY_AUDIT_PAGE_BYTES);
        sequences.extend(
            page.records
                .iter()
                .map(|value| value["sequence"].as_u64().unwrap()),
        );
        cursor = page.cursor();
    }
    assert_eq!(sequences, (0..end).collect::<Vec<_>>());
    let archives = admin
        .security_audit_archives(
            &operator,
            &SecurityAuditArchivePageRequest {
                cursor: None,
                limit: 1,
            },
        )
        .await
        .unwrap();
    let pinned_archive_count = archives.through_index;
    let reference = archives.archives[0].clone();
    let mut changed_snapshot = archives.cursor().unwrap();
    changed_snapshot.snapshot_head.as_mut().unwrap().object_id = Uuid::new_v4();
    changed_snapshot.validate().unwrap();
    let error = admin
        .security_audit_archives(
            &operator,
            &SecurityAuditArchivePageRequest {
                cursor: Some(changed_snapshot),
                limit: 1,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, ClientError::Transport(status) if status.code() == tonic::Code::InvalidArgument)
    );
    let mut changed_boundary = archives.cursor().unwrap();
    changed_boundary.previous.as_mut().unwrap().object_id = Uuid::new_v4();
    changed_boundary.validate().unwrap();
    let error = admin
        .security_audit_archives(
            &operator,
            &SecurityAuditArchivePageRequest {
                cursor: Some(changed_boundary),
                limit: 1,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, ClientError::Transport(status) if status.code() == tonic::Code::InvalidArgument)
    );
    append(&audit, 350).await;
    let next = admin
        .security_audit_archives(
            &operator,
            &SecurityAuditArchivePageRequest {
                cursor: archives.cursor(),
                limit: 256,
            },
        )
        .await
        .unwrap();
    assert_eq!(next.through_index, pinned_archive_count);
    assert_eq!(next.next_index, pinned_archive_count);
    let verified = admin
        .verify_security_audit_archive(
            &operator,
            &SecurityAuditVerifyRequest {
                stream_id: stream,
                index: 0,
            },
        )
        .await
        .unwrap();
    assert_eq!(verified.observation().archive, reference);
    assert!(
        admin
            .verify_security_audit_archive(
                &operator,
                &SecurityAuditVerifyRequest {
                    stream_id: Uuid::new_v4(),
                    index: 0
                }
            )
            .await
            .is_err()
    );

    // CLI saves an exact initial cursor before dispatch and publishes a private
    // bounded page. Repeating a published path or changing its inputs is rejected.
    let request = installation
        .control_profile
        .with_file_name("audit-request.json");
    let output = installation
        .control_profile
        .with_file_name("audit-page.json");
    private_files::create(&request, br#"{"cursor":null,"limit":8}"#).unwrap();
    let arguments = vec![
        "audit".into(),
        "export".into(),
        installation.control_profile.display().to_string(),
        request.display().to_string(),
        output.display().to_string(),
    ];
    assert!(crate::standalone_cli::command(&arguments).await.unwrap());
    let page: SecurityAuditPage = serde_json::from_slice(
        &private_files::read(&output, MAX_SECURITY_AUDIT_PAGE_BYTES).unwrap(),
    )
    .unwrap();
    assert_eq!(page.records.len(), 8);
    let original_attempt = private_files::read(
        &output.with_extension("audit-attempt.json"),
        MAX_SECURITY_AUDIT_PAGE_BYTES,
    )
    .unwrap();
    assert!(crate::standalone_cli::command(&arguments).await.is_err());
    assert_eq!(
        private_files::read(
            &output.with_extension("audit-attempt.json"),
            MAX_SECURITY_AUDIT_PAGE_BYTES
        )
        .unwrap(),
        original_attempt
    );

    // Cancel after the server encoded a page. The CLI retains the exact cursor,
    // so fresh authentication on retry cannot advance the historical boundary.
    let retry_input = installation
        .control_profile
        .with_file_name("audit-retry-request.json");
    let retry_output = installation
        .control_profile
        .with_file_name("audit-retry-page.json");
    let retry_request = SecurityAuditExportRequest {
        cursor: Some(SecurityAuditCursor {
            stream_id: stream,
            next_sequence: 0,
            through_sequence: page.through_sequence,
        }),
        limit: 8,
    };
    private_files::create(&retry_input, &serde_json::to_vec(&retry_request).unwrap()).unwrap();
    let retry_arguments = vec![
        "audit".into(),
        "export".into(),
        installation.control_profile.display().to_string(),
        retry_input.display().to_string(),
        retry_output.display().to_string(),
    ];
    let cancellation_gate = gate(&release).await;
    let arguments = retry_arguments.clone();
    let cancelled = tokio::spawn(async move { crate::standalone_cli::command(&arguments).await });
    entered(&cancellation_gate).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    cancellation_gate.release.notify_one();
    assert!(!retry_output.exists());
    append(&audit, 50).await;
    assert!(
        crate::standalone_cli::command(&retry_arguments)
            .await
            .unwrap()
    );
    let retried: SecurityAuditPage = serde_json::from_slice(
        &private_files::read(&retry_output, MAX_SECURITY_AUDIT_PAGE_BYTES).unwrap(),
    )
    .unwrap();
    assert_eq!(retried.through_sequence, page.through_sequence);
    assert_eq!(retried.stream_id, stream);

    let create = |seconds| CreateCredential {
        family_id: Uuid::new_v4(),
        principal: "administrator".into(),
        tenant: CONTROL_TENANT.into(),
        resource: control.resource.clone(),
        scopes: BTreeSet::from([Action::Admin]),
        lifetime_seconds: seconds,
    };
    let revoked = admin
        .create_credential(&operator, &create(3600))
        .await
        .unwrap();
    let revoke_gate = gate(&release).await;
    let mut request_client = admin.clone();
    let token = revoked.token.clone();
    let request = tokio::spawn(async move { request_client.security_audit_status(&token).await });
    entered(&revoke_gate).await;
    admin
        .revoke_credential(
            &operator,
            &CredentialReference {
                family_id: revoked.family_id,
            },
        )
        .await
        .unwrap();
    revoke_gate.release.notify_one();
    denied(request.await.unwrap().unwrap_err());

    let short = admin
        .create_credential(&operator, &create(4))
        .await
        .unwrap();
    let expiry_gate = gate(&release).await;
    let mut request_client = admin.clone();
    let token = short.token.clone();
    let request = tokio::spawn(async move { request_client.security_audit_status(&token).await });
    entered(&expiry_gate).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
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
    tokio::time::sleep(Duration::from_millis(
        short.expires_at_ms.saturating_sub(now) + 50,
    ))
    .await;
    expiry_gate.release.notify_one();
    denied(request.await.unwrap().unwrap_err());
    admin.security_audit_status(&renewed.token).await.unwrap();

    let mut replacement_specification = create(3600);
    replacement_specification.principal = "replacement-administrator".into();
    let replacement = admin
        .create_credential(&operator, &replacement_specification)
        .await
        .unwrap();
    let policy_gate = gate(&release).await;
    let mut request_client = admin.clone();
    let token = operator.to_string();
    let request = tokio::spawn(async move { request_client.security_audit_status(&token).await });
    entered(&policy_gate).await;
    database
        .administer(
            configured_control_context(&config.control).unwrap(),
            Operation::SetPolicy(Policy {
                grants: vec![Grant {
                    principal: "replacement-administrator".into(),
                    collection: None,
                    actions: BTreeSet::from([Action::Admin]),
                }],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    policy_gate.release.notify_one();
    denied(request.await.unwrap().unwrap_err());
    // Service-audit encryption authority is independently fenced at handoff,
    // even when the Control administrator and Control storage remain valid.
    let storage_gate = gate(&release).await;
    let mut request_client = admin.clone();
    let token = replacement.token;
    let request = tokio::spawn(async move { request_client.security_audit_status(&token).await });
    entered(&storage_gate).await;
    audit.seal();
    storage_gate.release.notify_one();
    let ClientError::Transport(error) = request.await.unwrap().unwrap_err() else {
        panic!("expected a fenced native response")
    };
    // Local credential liveness also depends on the now-sealed revocation table.
    assert_eq!(error.code(), tonic::Code::Unauthenticated);
    stop.send(true).unwrap();
    // Shutdown still drains every owner and reports the injected audit closure.
    assert!(serving.await.unwrap().is_err());
}
