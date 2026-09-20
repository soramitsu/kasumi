use super::*;
use crate::{
    observability::{Lifecycle, Telemetry},
    standalone::{ClientProfile, initialize},
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

#[tokio::test]
async fn protected_observability_tls_reports_actual_state_and_fences_release() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let installation = initialize(&directory.path().join("kasumi"), "tenant-a")
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
    crate::standalone::configure_test_topology(&config).await;
    drop(listeners);
    let runtime = NodeRuntime::open(config.clone()).await.unwrap();
    let telemetry = runtime.telemetry.clone();
    let management = runtime.administration.as_ref().unwrap().clone();
    let registry = runtime.registry.clone();
    assert_eq!(telemetry.lifecycle(), Lifecycle::Starting);
    let database = runtime.control.database.clone();
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
    assert_eq!(value["readiness_coverage"]["expected_groups"], 2);
    assert_eq!(value["readiness_coverage"]["examined_groups"], 2);
    assert_eq!(value["readiness_coverage"]["healthy_groups"], 2);
    assert_eq!(value["readiness_coverage"]["complete"], true);
    assert_eq!(value["readiness_coverage"]["fresh"], true);
    assert_eq!(value["readiness_coverage"]["detail_limit"], 128);
    assert_eq!(value["standalone_recovery_pending"], false);
    assert_eq!(value["backup_requests"]["create"]["inflight"], 0);
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
    assert!(
        !text.contains("authority_remaining_seconds")
            && !text.contains("tenant_audit_maintenance_failures")
            && !text.contains("backup_sessions_completed")
    );
    assert!(!text.contains(&*operator) && !text.contains("administrator"));
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
    let response = client
        .get(&ready)
        .bearer_auth(&*operator)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 503);
    let value: serde_json::Value = response.json().await.unwrap();
    let data = value["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["tenant"] == "tenant-a")
        .unwrap();
    assert_eq!(data["store_available"], false);
    assert!(data["retention"].is_null());
    assert!(data["capacity"].is_null());

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
