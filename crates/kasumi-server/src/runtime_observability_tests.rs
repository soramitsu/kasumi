use super::*;
use crate::{
    observability::{Lifecycle, Telemetry},
    standalone::ClientProfile,
};
use kasumi_client::KasumiAdminClient;
use kasumi_store::private_files;
use kasumi_types::*;
use uuid::Uuid;

fn http(profile: &ClientProfile, identity: bool) -> reqwest::Client {
    let mut client = reqwest::Client::builder()
        .https_only(true)
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .max_tls_version(reqwest::tls::Version::TLS_1_3)
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(
                &private_files::read(&profile.server_ca, 1 << 20).unwrap(),
            )
            .unwrap(),
        )
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15));
    if identity {
        let mut pem = private_files::read(&profile.identity.certificate, 1 << 20).unwrap();
        pem.extend_from_slice(
            &private_files::read(&profile.identity.private_key, 1 << 20).unwrap(),
        );
        client = client.identity(reqwest::Identity::from_pem(&pem).unwrap());
    }
    client.build().unwrap()
}
async fn gate(telemetry: &Arc<Telemetry>) -> crate::rpc::AuditReleaseGate {
    let gate = crate::rpc::AuditReleaseGate {
        entered: Arc::new(tokio::sync::Notify::new()),
        release: Arc::new(tokio::sync::Notify::new()),
    };
    *telemetry.release_gate.lock().await = Some(gate.clone());
    gate
}
async fn entered(gate: &crate::rpc::AuditReleaseGate) {
    tokio::time::timeout(Duration::from_secs(10), gate.entered.notified())
        .await
        .unwrap();
}
fn request(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
) -> tokio::task::JoinHandle<reqwest::Response> {
    let request = client.get(endpoint).bearer_auth(token);
    tokio::spawn(async move { request.send().await.unwrap() })
}
async fn ready_response(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
) -> reqwest::Response {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let response = client
                .get(endpoint)
                .bearer_auth(token)
                .send()
                .await
                .unwrap();
            if response.status().as_u16() == 200 {
                return response;
            }
            assert_eq!(response.status().as_u16(), 503);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap()
}
async fn withheld(request: tokio::task::JoinHandle<reqwest::Response>, status: u16) {
    let response = request.await.unwrap();
    assert_eq!(response.status().as_u16(), status);
    assert_eq!(
        response.text().await.unwrap(),
        "protected node observation unavailable\n"
    );
}

async fn unavailable_tenant_ready(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
) -> serde_json::Value {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let response = client
                .get(endpoint)
                .bearer_auth(token)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), 503);
            let body = response.text().await.unwrap();
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
                assert_eq!(value["ready"], false);
                if value["groups"]
                    .as_array()
                    .is_some_and(|groups| groups.iter().any(|group| group["tenant"] == "tenant-a"))
                {
                    return value;
                }
            } else {
                assert_eq!(body, "protected node observation unavailable\n");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap()
}

async fn unavailable_tenant_metrics(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
) -> String {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let response = client
                .get(endpoint)
                .bearer_auth(token)
                .send()
                .await
                .unwrap();
            let status = response.status().as_u16();
            let body = response.text().await.unwrap();
            if status == 200 {
                assert!(body.contains("kasumi_ready 0\n"));
                if body.contains("kasumi_local_group_store_available{tenant=\"tenant-a\"} 0\n") {
                    return body;
                }
            } else {
                assert_eq!(status, 503);
                assert_eq!(body, "protected node observation unavailable\n");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap()
}

#[test]
fn protected_observability_tls_reports_actual_state_and_fences_release() {
    // The installed TLS, Raft and archive-worker fixture exceeds libtest's
    // default stack while retaining its async request and response owners.
    std::thread::Builder::new()
        .name("protected observability TLS fixture".into())
        .stack_size(16 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(
                    protected_observability_tls_reports_actual_state_and_fences_release_impl(),
                ));
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn protected_observability_tls_reports_actual_state_and_fences_release_impl() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
        &directory.path().join("kasumi"),
        "tenant-a",
    )
    .await
    .unwrap();
    let mut config = RuntimeConfig::load(&installation.configuration).unwrap();
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
    crate::standalone::configure_test_topology(&config, storage.clone()).await;
    drop(listeners);
    let runtime = NodeRuntime::open_using_storage(
        config.clone(),
        crate::runtime::file_secret,
        storage.clone(),
    )
    .await
    .unwrap();
    let telemetry = runtime.telemetry.clone();
    let management = runtime.administration.as_ref().unwrap().clone();
    let registry = runtime.registry.clone();
    assert_eq!(telemetry.lifecycle(), Lifecycle::Starting);
    let database = runtime.control.database.clone();
    let tenant_database = runtime.tenants[0].database.clone();
    let application = runtime.tenants[0].store.clone();
    let (stop, shutdown) = watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    let mut admin = KasumiAdminClient::connect(&control.connection(true).unwrap())
        .await
        .unwrap();
    let operator = control.bearer().unwrap();
    let client = http(&control, true);
    let metrics = format!(
        "{}/metrics",
        control.administrative_member().unwrap().endpoint
    );
    let ready = format!(
        "{}/ready",
        control.administrative_member().unwrap().endpoint
    );
    let health = format!(
        "{}/health",
        control.administrative_member().unwrap().endpoint
    );
    let recovery = format!(
        "{}/recovery/{}",
        control.administrative_member().unwrap().endpoint,
        Uuid::new_v4()
    );
    let malformed_recovery = format!(
        "{}/recovery/not-a-uuid",
        control.administrative_member().unwrap().endpoint
    );
    let no_identity = http(&control, false);
    assert!(
        no_identity
            .get(&metrics)
            .bearer_auth(&*operator)
            .send()
            .await
            .is_err()
    );
    assert_eq!(
        client.get(&metrics).send().await.unwrap().status().as_u16(),
        401
    );
    assert_eq!(
        client
            .get(&metrics)
            .bearer_auth(&*tenant.bearer().unwrap())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        client
            .get(&metrics)
            .bearer_auth(&*operator)
            .header("authorization", "Bearer duplicate")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );
    let response = ready_response(&client, &ready, &operator).await;
    assert_eq!(response.headers()["cache-control"], "no-store");
    let value: serde_json::Value = response.json().await.unwrap();
    assert_eq!(value["ready"], true);
    assert!(
        no_identity
            .get(&recovery)
            .bearer_auth(&*operator)
            .send()
            .await
            .is_err()
    );
    assert_eq!(
        client
            .get(&recovery)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );
    assert_eq!(
        client
            .get(&recovery)
            .bearer_auth(&*tenant.bearer().unwrap())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        client
            .get(&malformed_recovery)
            .bearer_auth(&*operator)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        400
    );
    // Standalone has no three-voter Control quorum for a durable recovery read.
    let unavailable = client
        .get(&recovery)
        .bearer_auth(&*operator)
        .send()
        .await
        .unwrap();
    assert_eq!(unavailable.status().as_u16(), 503);
    assert_eq!(unavailable.headers()["cache-control"], "no-store");
    assert_eq!(
        unavailable.text().await.unwrap(),
        "protected node observation unavailable\n"
    );
    assert_eq!(value["readiness_coverage"]["expected_groups"], 2);
    assert_eq!(value["readiness_coverage"]["examined_groups"], 2);
    assert_eq!(value["readiness_coverage"]["healthy_groups"], 2);
    assert_eq!(value["readiness_coverage"]["complete"], true);
    assert_eq!(value["readiness_coverage"]["fresh"], true);
    assert_eq!(value["readiness_coverage"]["detail_limit"], 128);
    assert_eq!(value["standalone_recovery_pending"], false);
    assert_eq!(value["backup_requests"]["create"]["inflight"], 0);
    assert_eq!(
        value["service_audit"]["retention"]["archive_backlog_bytes"],
        0
    );
    let tenant_group = value["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["tenant"] == "tenant-a")
        .unwrap();
    assert_eq!(tenant_group["retention"]["archive_backlog_bytes"], 0);
    assert_eq!(tenant_group["audit_maintenance"]["failures"], 0);
    assert_eq!(tenant_group["audit_maintenance"]["committed_segments"], 0);
    assert!(
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .all(|group| group["capacity"]["logical_budget_bytes"].as_u64().unwrap() > 0)
    );
    assert!(
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .all(|group| group["quorum"] == true && group["authority_remaining_seconds"].is_null())
    );
    let text = client
        .get(&metrics)
        .bearer_auth(&*operator)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(text.contains("kasumi_ready 1\n") && text.contains("kasumi_service_audit_hot_bytes "));
    assert!(text.contains("kasumi_local_group_audit_hot_bytes{tenant=\"tenant-a\"}"));
    assert!(text.contains("kasumi_service_audit_archive_backlog_bytes 0\n"));
    assert!(
        text.contains("kasumi_local_group_audit_archive_backlog_bytes{tenant=\"tenant-a\"} 0\n")
    );
    assert!(
        text.contains(
            "kasumi_local_group_audit_maintenance_failures_total{tenant=\"tenant-a\"} 0\n"
        )
    );
    assert!(text.contains(
        "kasumi_local_group_audit_maintenance_committed_segments_total{tenant=\"tenant-a\"} 0\n"
    ));
    assert!(
        !text.contains("authority_remaining_seconds")
            && !text.contains("backup_sessions_completed")
    );
    assert!(!text.contains(&*operator) && !text.contains("administrator"));

    // Force a real tenant archive through the installed worker, then observe
    // its process counter through both protected surfaces.
    let context = crate::standalone::offline_context(&tenant_database).unwrap();
    let mut limits = tenant_database
        .engine()
        .generation()
        .unwrap()
        .state
        .limits
        .clone();
    limits.audit_retention.hot_bytes = 128 << 10;
    tenant_database
        .administer(context.clone(), Operation::SetLimits(limits))
        .await
        .unwrap();
    for index in 0..50 {
        let revision = tenant_database
            .engine()
            .generation()
            .unwrap()
            .state
            .revision;
        let command = Command {
            context: context.clone(),
            timestamp_ms: 1_000,
            operation: Operation::Audit(AuditEvent {
                event_id: format!("observability-{index}:{}", "x".repeat(2_000)),
                principal: context.principal.clone(),
                action: "read".into(),
                request_id: context.request_id.clone(),
                timestamp_ms: 1_000,
                data_revision: Some(revision),
                outcome: "authorized_release".into(),
                collection: None,
            }),
        };
        let response = tenant_database
            .raft_group()
            .write(serde_json::to_vec(&command).unwrap())
            .await
            .unwrap();
        serde_json::from_slice::<kasumi_types::Result<WriteReceipt>>(&response)
            .unwrap()
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        while tenant_database
            .audit_maintenance_status()
            .unwrap()
            .committed_segments
            == 0
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let value: serde_json::Value = ready_response(&client, &ready, &operator)
        .await
        .json()
        .await
        .unwrap();
    let tenant_group = value["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["tenant"] == "tenant-a")
        .unwrap();
    assert!(
        tenant_group["audit_maintenance"]["committed_segments"]
            .as_u64()
            .unwrap()
            > 0
    );
    let response = client
        .get(&metrics)
        .bearer_auth(&*operator)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let text = response.text().await.unwrap();
    let committed = text
        .lines()
        .find_map(|line| {
            line.strip_prefix(
                "kasumi_local_group_audit_maintenance_committed_segments_total{tenant=\"tenant-a\"} ",
            )
        })
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(committed > 0);

    assert_eq!(
        client
            .get(&health)
            .bearer_auth(&*operator)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // Invalidate a held response through a real committed membership append.
    // Control topology and data routing are unchanged, so their epochs alone
    // would incorrectly release the old observation.
    let original = management.readiness_epoch().unwrap();
    let hold = gate(&telemetry).await;
    let pending = request(&client, &ready, &operator);
    entered(&hold).await;
    database
        .raft_group()
        .raft()
        .add_learner(2, kasumi_raft::BasicNode::new("127.0.0.1:9"), false)
        .await
        .unwrap();
    let changed = management.readiness_epoch().unwrap();
    assert_eq!(changed.topology_version, original.topology_version);
    assert_eq!(changed.installed_routes, original.installed_routes);
    assert!(changed.actual_membership > original.actual_membership);
    hold.release.notify_one();
    withheld(pending, 503).await;
    ready_response(&client, &ready, &operator).await;

    // A complete quorum probe cannot certify a different committed voter set.
    let group = database.raft_group();
    assert!(
        !group
            .readiness_probe(1, Some(BTreeSet::from([2])))
            .await
            .unwrap()
    );

    // Reinstalling the same physical route still invalidates the original
    // response; a newer successful sweep must not repair an older release token.
    let hold = gate(&telemetry).await;
    let pending = request(&client, &ready, &operator);
    entered(&hold).await;
    let removed = registry.remove("tenant-a").unwrap().unwrap();
    registry.insert(removed).unwrap();
    ready_response(&client, &ready, &operator).await;
    hold.release.notify_one();
    withheld(pending, 503).await;

    // These counters describe actual adapter responses, not permanent outcomes.
    assert!(
        admin
            .verify_backup_checkpoint(
                "bad-token",
                &VerifyBackupCheckpoint {
                    destination: "local".into(),
                    backup_id: Uuid::new_v4()
                }
            )
            .await
            .is_err()
    );
    let text = client
        .get(&metrics)
        .bearer_auth(&*operator)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(text.contains(
        "kasumi_backup_requests_total{operation=\"verify\",outcome=\"returned_denied\"} 1\n"
    ));

    let create = |seconds, principal: &str, scopes| CreateCredential {
        family_id: Uuid::new_v4(),
        principal: principal.into(),
        tenant: CONTROL_TENANT.into(),
        resource: control.resource.clone(),
        scopes,
        lifetime_seconds: seconds,
    };
    let reader = admin
        .create_credential(
            &operator,
            &create(3600, "administrator", BTreeSet::from([Action::Read])),
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .get(&ready)
            .bearer_auth(&reader.token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );

    let revoked = admin
        .create_credential(
            &operator,
            &create(3600, "administrator", BTreeSet::from([Action::Admin])),
        )
        .await
        .unwrap();
    let hold = gate(&telemetry).await;
    let pending = request(&client, &metrics, &revoked.token);
    entered(&hold).await;
    admin
        .revoke_credential(
            &operator,
            &CredentialReference {
                family_id: revoked.family_id,
            },
        )
        .await
        .unwrap();
    hold.release.notify_one();
    withheld(pending, 401).await;

    let short = admin
        .create_credential(
            &operator,
            &create(4, "administrator", BTreeSet::from([Action::Admin])),
        )
        .await
        .unwrap();
    let hold = gate(&telemetry).await;
    let pending = request(&client, &metrics, &short.token);
    entered(&hold).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
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
    hold.release.notify_one();
    withheld(pending, 401).await;
    assert_eq!(
        client
            .get(&ready)
            .bearer_auth(&renewed.token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    let hold = gate(&telemetry).await;
    let pending = request(&client, &metrics, &operator);
    entered(&hold).await;
    telemetry.set_lifecycle(Lifecycle::Draining);
    hold.release.notify_one();
    withheld(pending, 503).await;
    assert_eq!(
        client
            .get(&ready)
            .bearer_auth(&*operator)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        503
    );
    telemetry.set_lifecycle(Lifecycle::Serving);

    // An already encoded observation must not survive closure of a data store.
    let hold = gate(&telemetry).await;
    let pending = request(&client, &metrics, &operator);
    entered(&hold).await;
    application.seal();
    hold.release.notify_one();
    withheld(pending, 503).await;
    // A failed sweep invalidates the previous complete page immediately. While
    // its replacement is in progress, the bounded diagnostic page can contain
    // Control but not yet the sealed tenant. Every observed response must stay
    // unavailable; require the tenant row once a sweep has reached it.
    let value = unavailable_tenant_ready(&client, &ready, &operator).await;
    let data = value["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["tenant"] == "tenant-a")
        .unwrap();
    assert_eq!(data["store_available"], false);
    assert!(data["retention"].is_null());
    assert!(data["audit_maintenance"].is_null());
    assert!(data["capacity"].is_null());
    let text = unavailable_tenant_metrics(&client, &metrics, &operator).await;
    assert!(
        !text.contains("kasumi_local_group_audit_maintenance_failures_total{tenant=\"tenant-a\"}")
    );
    assert!(!text.contains(
        "kasumi_local_group_audit_maintenance_committed_segments_total{tenant=\"tenant-a\"}"
    ));

    // Exercise the actual background sweep beyond the diagnostic page. Every
    // locally assigned missing group must be counted, including the final row.
    let plane = kasumi_engine::control::ControlPlane::new(database.clone()).unwrap();
    let context = configured_control_context(&config.control).unwrap();
    let mut topology = plane.topology(&context).await.unwrap().unwrap();
    for index in 0..129 {
        topology.topology.tenants.insert(
            format!("missing-{index:03}"),
            kasumi_engine::control::TenantRoute {
                incarnation: Uuid::new_v4().to_string(),
                mode: kasumi_engine::control::DeploymentMode::Local,
                voters: BTreeSet::from([1]),
            },
        );
    }
    plane
        .replace_topology(
            context,
            topology.topology,
            Precondition::Version(topology.version),
            "readiness-whole-coverage".into(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let coverage = management.readiness.snapshot(
                management.readiness_epoch().unwrap(),
                tokio::time::Instant::now(),
            );
            if coverage.status.complete {
                assert_eq!(coverage.status.expected_groups, Some(131));
                assert_eq!(coverage.status.examined_groups, 131);
                assert_eq!(coverage.details.len(), 128);
                assert!(!coverage.status.ready());
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();

    let hold = gate(&telemetry).await;
    let pending = request(&client, &metrics, &operator);
    entered(&hold).await;
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
    hold.release.notify_one();
    withheld(pending, 403).await;
    let last_epoch = management.readiness_epoch().unwrap();
    stop.send(true).unwrap();
    serving.await.unwrap().unwrap();
    assert_eq!(telemetry.lifecycle(), Lifecycle::Closed);
    let drained = management
        .readiness
        .snapshot(last_epoch, tokio::time::Instant::now());
    assert!(!drained.status.complete && drained.token.is_none());
}

#[test]
fn protected_tls_reports_real_archive_outage_and_due_backlog() {
    std::thread::Builder::new()
        .name("protected archive outage observation".into())
        .stack_size(16 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(protected_archive_outage_and_due_backlog()));
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn protected_archive_outage_and_due_backlog() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let root = directory.path().join("archive-outage");
    let storage = crate::runtime_storage_fixtures::standalone_storage(
        &root,
        kasumi_engine::admission::AdmissionConfig::default(),
    )
    .unwrap();
    // The installed S3 destination keeps its exact namespace binding, but a
    // missing credential bundle makes actual external publication fail before
    // a prune proposal. This does not fail or replace the local NodeDisk.
    let missing_credentials = directory.path().join("missing-s3-credentials.json");
    assert!(!missing_credentials.exists());
    let installation = crate::standalone::initialize_with_storage_and_tenant_archive(
        &root,
        "tenant-a",
        storage.clone(),
        crate::audit_destination::AuditDestinationConfig::S3 {
            endpoint: "https://localhost:1".into(),
            region: "test".into(),
            bucket: "tenant-audit".into(),
            prefix: "outage".into(),
            credentials_file: missing_credentials,
            ca_certificate: None,
        },
    )
    .await
    .unwrap();
    let mut config = RuntimeConfig::load(&installation.configuration).unwrap();
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
    crate::standalone::configure_test_topology(&config, storage.clone()).await;
    drop(listeners);
    let runtime = NodeRuntime::open_using_storage(config, crate::runtime::file_secret, storage)
        .await
        .unwrap();
    let tenant_database = runtime.tenants[0].database.clone();
    let (stop, shutdown) = watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    let client = http(&control, true);
    let operator = control.bearer().unwrap();
    let ready = format!(
        "{}/ready",
        control.administrative_member().unwrap().endpoint
    );
    let metrics = format!(
        "{}/metrics",
        control.administrative_member().unwrap().endpoint
    );
    assert_eq!(
        client
            .get(&metrics)
            .bearer_auth(&*tenant.bearer().unwrap())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );

    let context = crate::standalone::offline_context(&tenant_database).unwrap();
    let mut limits = tenant_database
        .engine()
        .generation()
        .unwrap()
        .state
        .limits
        .clone();
    limits.audit_retention.hot_bytes = 128 << 10;
    tenant_database
        .administer(context.clone(), Operation::SetLimits(limits))
        .await
        .unwrap();
    for index in 0..50 {
        let revision = tenant_database
            .engine()
            .generation()
            .unwrap()
            .state
            .revision;
        let command = Command {
            context: context.clone(),
            timestamp_ms: 1_000,
            operation: Operation::Audit(AuditEvent {
                event_id: format!("outage-{index}:{}", "x".repeat(2_000)),
                principal: context.principal.clone(),
                action: "read".into(),
                request_id: context.request_id.clone(),
                timestamp_ms: 1_000,
                data_revision: Some(revision),
                outcome: "authorized_release".into(),
                collection: None,
            }),
        };
        let response = tenant_database
            .raft_group()
            .write(serde_json::to_vec(&command).unwrap())
            .await
            .unwrap();
        serde_json::from_slice::<kasumi_types::Result<WriteReceipt>>(&response)
            .unwrap()
            .unwrap();
    }
    let before = tenant_database.engine().generation().unwrap();
    assert!(
        before.state.audit_retention.hot_bytes >= before.state.limits.audit_retention.starts_at()
    );
    assert_eq!(before.state.audit_retention.archive_segments, 0);
    tokio::time::timeout(Duration::from_secs(10), async {
        while tenant_database.audit_maintenance_status().unwrap().failures == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let after = tenant_database.engine().generation().unwrap();
    assert_eq!(after.state.revision, before.state.revision);
    assert_eq!(after.state.audit_retention, before.state.audit_retention);
    drop(after);
    drop(before);

    let value: serde_json::Value = ready_response(&client, &ready, &operator)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(value["ready"], true);
    let group = value["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["tenant"] == "tenant-a")
        .unwrap();
    let due = group["retention"]["archive_backlog_bytes"]
        .as_u64()
        .unwrap();
    let hot = group["retention"]["hot_bytes"].as_u64().unwrap();
    let target = group["retention"]["hot_budget_bytes"].as_u64().unwrap() / 2;
    assert!(due > 0);
    assert_eq!(due, hot - target);
    let failures = group["audit_maintenance"]["failures"].as_u64().unwrap();
    assert!(failures > 0);
    assert_eq!(group["audit_maintenance"]["committed_segments"], 0);
    let service_due = value["service_audit"]["retention"]["archive_backlog_bytes"]
        .as_u64()
        .unwrap();

    let response = client
        .get(&metrics)
        .bearer_auth(&*operator)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let text = response.text().await.unwrap();
    assert!(text.contains("kasumi_ready 1\n"));
    assert!(text.contains(&format!(
        "kasumi_local_group_audit_archive_backlog_bytes{{tenant=\"tenant-a\"}} {due}\n"
    )));
    let reported_failures = text
        .lines()
        .find_map(|line| {
            line.strip_prefix(
                "kasumi_local_group_audit_maintenance_failures_total{tenant=\"tenant-a\"} ",
            )
        })
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(reported_failures >= failures);
    assert!(text.contains(&format!(
        "kasumi_service_audit_archive_backlog_bytes {service_due}\n"
    )));

    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(30), serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[test]
fn protected_tls_certifies_all_129_installed_healthy_groups_and_fences_membership_change() {
    std::thread::Builder::new()
        .name("129 installed readiness groups".into())
        .stack_size(16 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(installed_healthy_group_coverage()));
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn installed_healthy_group_coverage() {
    const TENANTS: usize = 128;
    const GROUPS: usize = TENANTS + 1; // Control is a separately probed group.
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let root = directory.path().join("many-healthy-groups");
    // The generic one-tenant fixture resolves to at most 512 MiB of work
    // capacity. This installed 129-group case uses the example installation's
    // explicit 2 GiB total and one retained snapshot-startup slot per actual
    // Control/tenant group. Other host, operation and file limits are unchanged.
    let storage = crate::runtime_storage_fixtures::standalone_storage(
        &root,
        kasumi_engine::admission::AdmissionConfig {
            max_inflight_bytes: Some(2 << 30),
            max_snapshot_startups: GROUPS,
            ..Default::default()
        },
    )
    .unwrap();
    let installation =
        crate::standalone::initialize_many_with_storage(&root, TENANTS, storage.clone())
            .await
            .unwrap();
    let mut config = RuntimeConfig::load(&installation.configuration).unwrap();
    assert_eq!(config.tenants.len(), TENANTS);
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
    control.mcp_endpoint = config.mcp.protocol.public_url.clone();
    control.native_endpoint = format!("https://localhost:{}", config.native.listen.port());
    control.administrative_members.get_mut(&1).unwrap().endpoint =
        format!("https://localhost:{}", config.admin.listen.port());
    crate::standalone::configure_test_topology(&config, storage.clone()).await;
    drop(listeners);

    let memory = storage.memory().clone();
    let policy = storage.policy().clone();
    let runtime = NodeRuntime::open_using_storage(
        config.clone(),
        crate::runtime::file_secret,
        storage,
    )
    .await
    .unwrap_or_else(|error| {
        panic!(
            "installed 129-group runtime open failed: {error:?}; policy={policy:?}; admission={:?}",
            memory.snapshot()
        )
    });
    assert_eq!(runtime.tenants.len(), TENANTS);
    let management = runtime.administration.as_ref().unwrap().clone();
    let telemetry = runtime.telemetry.clone();
    let registry = runtime.registry.clone();
    let last = runtime
        .tenants
        .iter()
        .find(|tenant| tenant.store.tenant() == "healthy-127")
        .unwrap();
    let last_store = last.store.clone();
    let last = last.database.clone();
    let (stop, shutdown) = watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    let sweep_wait_started = tokio::time::Instant::now();
    let client = http(&control, true);
    let operator = control.bearer().unwrap();
    let endpoint = control.administrative_member().unwrap().endpoint.clone();
    let ready = format!("{endpoint}/ready");
    let metrics = format!("{endpoint}/metrics");

    async fn healthy(
        client: &reqwest::Client,
        ready: &str,
        operator: &str,
        management: &Arc<crate::administration::Administration>,
    ) -> serde_json::Value {
        let response = tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                let epoch = management.readiness_epoch().unwrap();
                let coverage = management
                    .readiness
                    .snapshot(epoch, tokio::time::Instant::now());
                if coverage.status.ready() {
                    match client.get(ready).bearer_auth(operator).send().await {
                        Ok(response) if response.status().as_u16() == 200 => break response,
                        Ok(response) => assert_eq!(response.status().as_u16(), 503),
                        Err(_) => {} // Listener startup is owned by the serving task.
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            let status = management.readiness.snapshot(
                management.readiness_epoch().unwrap(),
                tokio::time::Instant::now(),
            );
            panic!(
                "installed 129-group readiness timed out: {}",
                serde_json::to_string(&status.status).unwrap()
            )
        });
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body = response.bytes().await.unwrap();
        assert!(
            body.len() <= (1 << 20),
            "diagnostic response exceeded 1 MiB"
        );
        serde_json::from_slice(&body).unwrap()
    }

    let value = healthy(&client, &ready, &operator, &management).await;
    // Serving reconciliation publishes committed routes before readiness can
    // certify them; an opened runtime intentionally has no data routes yet.
    for tenant in &config.tenants {
        assert!(
            registry
                .installed_generation(&tenant.tenant, tenant.incarnation.as_deref().unwrap())
                .unwrap()
                .is_some(),
            "installed route absent after healthy certificate: {}",
            tenant.tenant
        );
    }
    eprintln!(
        "installed healthy coverage: groups={GROUPS}, wait_ms={}, oldest_probe_age_s={}, admission_reserved_bytes={}, admission_resident_bytes={}, persistent_charged_bytes={}",
        sweep_wait_started.elapsed().as_millis(),
        value["readiness_coverage"]["oldest_probe_age_seconds"],
        value["admission"]["reserved_bytes"],
        value["admission"]["resident_bytes"],
        value["persistent_disk"]["charged_bytes"],
    );
    assert_eq!(value["ready"], true);
    assert_eq!(value["readiness_coverage"]["expected_groups"], GROUPS);
    assert_eq!(value["readiness_coverage"]["examined_groups"], GROUPS);
    assert_eq!(value["readiness_coverage"]["healthy_groups"], GROUPS);
    assert_eq!(value["readiness_coverage"]["complete"], true);
    assert_eq!(value["readiness_coverage"]["fresh"], true);
    assert_eq!(value["readiness_coverage"]["detail_limit"], 128);
    assert!(
        value["readiness_coverage"]["oldest_probe_age_seconds"]
            .as_f64()
            .unwrap()
            < 30.0
    );
    let details = value["groups"].as_array().unwrap();
    assert_eq!(details.len(), 128);
    assert!(!details.iter().any(|group| group["tenant"] == "healthy-127"));
    assert!(
        details
            .iter()
            .all(|group| group["store_available"] == true && group["quorum"] == true)
    );
    assert_eq!(value["admission"]["sample_usable"], true);
    assert_eq!(value["admission"]["pressured"], false);
    assert!(
        value["admission"]["reserved_bytes"].as_u64().unwrap()
            <= value["admission"]["high_water_bytes"].as_u64().unwrap()
    );
    assert!(
        value["persistent_disk"]["charged_bytes"].as_u64().unwrap()
            <= value["persistent_disk"]["max_bytes"].as_u64().unwrap()
    );
    let text = client
        .get(&metrics)
        .bearer_auth(&*operator)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for expected in [
        "kasumi_ready 1\n",
        "kasumi_readiness_groups_expected 129\n",
        "kasumi_readiness_groups_examined 129\n",
        "kasumi_readiness_groups_healthy 129\n",
        "kasumi_local_group_details 128\n",
    ] {
        assert!(text.contains(expected), "metric absent: {expected}");
    }

    // Change the actual Raft membership of a group outside the diagnostic page.
    // A previously encoded healthy response must not pass its release fence.
    let original = management.readiness_epoch().unwrap();
    let hold = gate(&telemetry).await;
    let pending = request(&client, &ready, &operator);
    entered(&hold).await;
    let held_coverage = management
        .readiness
        .snapshot(original, tokio::time::Instant::now());
    assert!(
        held_coverage.status.ready() && held_coverage.token.is_some(),
        "held response did not start with a fresh complete healthy certificate"
    );
    last.raft_group()
        .raft()
        .add_learner(2, kasumi_raft::BasicNode::new("127.0.0.1:9"), false)
        .await
        .unwrap();
    let changed = management.readiness_epoch().unwrap();
    assert_eq!(changed.topology_version, original.topology_version);
    assert_eq!(changed.installed_routes, original.installed_routes);
    assert!(changed.actual_membership > original.actual_membership);
    hold.release.notify_one();
    withheld(pending, 503).await;
    let refreshed = healthy(&client, &ready, &operator, &management).await;
    assert_eq!(refreshed["ready"], true);
    assert_eq!(
        refreshed["readiness_coverage"]["membership_epoch"],
        serde_json::to_value(changed).unwrap()
    );
    assert_eq!(refreshed["readiness_coverage"]["expected_groups"], GROUPS);
    assert_eq!(refreshed["readiness_coverage"]["examined_groups"], GROUPS);
    assert_eq!(refreshed["readiness_coverage"]["healthy_groups"], GROUPS);
    assert_eq!(refreshed["readiness_coverage"]["complete"], true);
    assert_eq!(refreshed["readiness_coverage"]["fresh"], true);

    // The only failed group is beyond the bounded detail page. Its actual
    // installed store failure still revokes whole-node readiness.
    last_store.seal();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let epoch = management.readiness_epoch().unwrap();
            let coverage = management
                .readiness
                .snapshot(epoch, tokio::time::Instant::now());
            if coverage.status.complete && coverage.status.healthy_groups == GROUPS - 1 {
                assert_eq!(coverage.status.expected_groups, Some(GROUPS));
                assert_eq!(coverage.status.examined_groups, GROUPS);
                assert_eq!(coverage.details.len(), 128);
                assert!(coverage.details.iter().all(|sample| sample.quorum));
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let response = client
        .get(&ready)
        .bearer_auth(&*operator)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 503);
    let failed: serde_json::Value = response.json().await.unwrap();
    assert_eq!(failed["ready"], false);
    assert_eq!(failed["readiness_coverage"]["healthy_groups"], GROUPS - 1);
    assert_eq!(failed["groups"].as_array().unwrap().len(), 128);
    stop.send(true).unwrap();
    serving.await.unwrap().unwrap();
}
