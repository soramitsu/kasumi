use super::*;
use crate::{
    remote_backup::{
        BackupAccess, BackupSources, ControlVerifier, DataTransport, Endpoint, SourceRoute,
    },
    runtime::TlsFiles,
    serving_runtime::AuthorityEndpoint,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use kasumi_client::{KasumiAdminClient, KasumiClientConfig};
use kasumi_engine::{
    BackupSourceCapability, Database, RemoteBackupFuture, RemoteBackupSourceVerifier,
    RemoteBackupTransport, ReplicaPlacement, ReplicatedBootstrap, ReplicatedGenesis,
};
use kasumi_serving::{AuthorityManifest, ServingBoot, ServingGate, ServingIdentity};
use kasumi_store::{
    BackupDestination, StorageAccess, TenantStorageSet, TenantStore, private_files,
    test_utils::LocalKeyProvider,
};
use kasumi_types::*;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;

// Keep the original component-stage refusal in the native fixture receipt.
// Production adapters continue to apply their public response redaction.
struct SourceTrace(Arc<DataTransport>);
impl RemoteBackupTransport for SourceTrace {
    fn control_incarnation(&self) -> Uuid {
        self.0.control_incarnation()
    }
    fn execute<'a>(
        &'a self,
        source: Arc<BackupSourceCapability>,
        action: RemoteBackupAction,
    ) -> RemoteBackupFuture<'a, Option<RemoteBackupRecord>> {
        Box::pin(async move {
            let kind = match &action {
                RemoteBackupAction::Read { .. } => "read",
                RemoteBackupAction::Claim { .. } => "claim",
                RemoteBackupAction::Decide { .. } => "decide",
            };
            let result = self.0.execute(source, action).await;
            eprintln!(
                "dedicated backup source {kind} returned {}",
                match &result {
                    Ok(Some(_)) => "selected".into(),
                    Ok(None) => "absent".into(),
                    Err(e) => format!("{:#}", anyhow::Error::from(e.clone())),
                }
            );
            result
        })
    }
}
struct ControlTrace(Arc<ControlVerifier>);
impl RemoteBackupSourceVerifier for ControlTrace {
    fn confirm<'a>(
        &'a self,
        source: &'a RemoteBackupChallenge,
        actor: &'a RequestContext,
        peer: &'a str,
    ) -> RemoteBackupFuture<'a, RemoteBackupConfirmation> {
        Box::pin(async move {
            let result = self.0.confirm(source, actor, peer).await;
            eprintln!(
                "dedicated backup callback returned {}",
                match &result {
                    Ok(confirmation) => format!(
                        "committed {}/{}",
                        confirmation.committed_term, confirmation.committed_index
                    ),
                    Err(e) => format!("{:#}", anyhow::Error::from(e.clone())),
                }
            );
            result
        })
    }
}

struct FixtureClock;
impl kasumi_clock::LeaseClock for FixtureClock {
    fn now(&self) -> Duration {
        Duration::ZERO
    }
}
struct ListenerAudit;
#[async_trait::async_trait]
impl crate::tls::TlsHandshakeAudit for ListenerAudit {
    async fn record(&self, _: &crate::tls::TlsHandshakeEvent) -> anyhow::Result<()> {
        Ok(())
    }
}

struct Identities {
    ca: PathBuf,
    files: Vec<TlsFiles>,
}
impl Identities {
    fn create(dir: &Path) -> Self {
        use rcgen::*;
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().unwrap();
        let ca = dir.join("ca.crt");
        private_files::create(&ca, params.self_signed(&key).unwrap().pem().as_bytes()).unwrap();
        let issuer = Issuer::new(params, key);
        let files = (0..11)
            .map(|i| {
                let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
                params.extended_key_usages = vec![
                    ExtendedKeyUsagePurpose::ClientAuth,
                    ExtendedKeyUsagePurpose::ServerAuth,
                ];
                params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
                let key = KeyPair::generate().unwrap();
                let files = TlsFiles {
                    certificate: dir.join(format!("identity-{i}.crt")),
                    private_key: dir.join(format!("identity-{i}.key")),
                };
                private_files::create(
                    &files.certificate,
                    params.signed_by(&key, &issuer).unwrap().pem().as_bytes(),
                )
                .unwrap();
                private_files::create(&files.private_key, key.serialize_pem().as_bytes()).unwrap();
                files
            })
            .collect();
        Self { ca, files }
    }
    fn pin(&self, id: usize) -> String {
        hex::encode(self.files[id].load().unwrap().certificate_pin())
    }
}
fn voters(ids: std::ops::RangeInclusive<u64>) -> BTreeMap<u64, ReplicaPlacement> {
    ids.map(|id| {
        (
            id,
            ReplicaPlacement {
                address: format!("https://member-{id}.example"),
                failure_domain: format!("zone-{id}"),
            },
        )
    })
    .collect()
}
async fn leader(nodes: &[Arc<Database>]) -> Arc<Database> {
    tokio::time::timeout(crate::runtime_storage_fixtures::LIVENESS, async {
        loop {
            for node in nodes {
                let group = node.raft_group();
                if group.metrics().current_leader == Some(group.node_id())
                    && group.linearizable_barrier().await.is_ok()
                {
                    return node.clone();
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("actual elected leader")
}
fn listen(socket: &tokio::net::TcpListener, pin: String) -> AuthorityEndpoint {
    AuthorityEndpoint {
        endpoint: format!("https://localhost:{}", socket.local_addr().unwrap().port()),
        certificate_pins: BTreeSet::from([pin]),
    }
}
fn write_token(path: &Path, token: &str) {
    let pending = path.with_extension(Uuid::new_v4().to_string());
    private_files::create(&pending, token.as_bytes()).unwrap();
    std::fs::rename(pending, path).unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dedicated_backup_transport_rechecks_both_quorums_and_original_after_lost_control_reply() {
    let dir = kasumi_store::test_utils::private_tempdir().unwrap();
    let ids = Identities::create(dir.path());
    let data_inc = Uuid::new_v4();
    let control_inc = Uuid::new_v4();
    let tenant = "separate-source";
    let rootkey = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let root = ControlSigningRoot {
        control_incarnation: control_inc,
        public_key: hex::encode(rootkey.public_key_raw()),
    };
    let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let signing =
        kasumi_serving::test_utils::FixtureSigningRoot::from_pkcs8(&issuer_key.serialize_der())
            .unwrap();
    let manifest = AuthorityManifest {
        authority_id: Uuid::new_v4(),
        lifecycle_controls: BTreeMap::from([(control_inc, root.public_key.clone())]),
        partitions: BTreeMap::from([(
            0,
            kasumi_serving::AuthorityPartition {
                group: "separate-issuer".into(),
                public_key: signing.public_key(),
            },
        )]),
        max_lease_ms: 1000,
        clock_rate_error_ppm: 0,
    };
    let partition = manifest.control_partition(0).unwrap();
    let signing = signing.install(manifest.clone(), 0).unwrap();
    let data_voters = voters(1..=3);
    let control_voters = voters(4..=6);
    let topology = kasumi_engine::control::ControlTopology {
        nodes: data_voters
            .iter()
            .chain(&control_voters)
            .map(|(id, v)| {
                (
                    *id,
                    kasumi_engine::control::ControlNode {
                        endpoint: v.address.clone(),
                        failure_domain: v.failure_domain.clone(),
                        certificate_pins: if *id <= 3 {
                            BTreeSet::from([ids.pin(*id as usize), ids.pin(*id as usize + 7)])
                        } else {
                            BTreeSet::from([ids.pin(*id as usize)])
                        },
                    },
                )
            })
            .collect(),
        tenants: BTreeMap::from([(
            tenant.into(),
            kasumi_engine::control::TenantRoute {
                incarnation: data_inc.to_string(),
                mode: kasumi_engine::control::DeploymentMode::Replicated,
                voters: BTreeSet::from([1, 2, 3]),
            },
        )]),
    };
    let mut grants: Vec<_> = (1..=3)
        .map(|i| Grant {
            principal: format!("writer-{i}"),
            collection: Some(BACKUP_DELEGATION_COLLECTION.into()),
            actions: BTreeSet::from([Action::Write]),
        })
        .collect();
    grants.push(Grant {
        principal: "router".into(),
        collection: Some("topology".into()),
        actions: BTreeSet::from([Action::Read]),
    });
    grants.push(Grant {
        principal: "operator".into(),
        collection: None,
        actions: BTreeSet::from([Action::Admin, Action::Write, Action::Read]),
    });
    let policy = Policy {
        grants,
        strict_read_audit: false,
    };
    let data_config = ReplicatedBootstrap {
        incarnation: data_inc.to_string(),
        genesis: ReplicatedGenesis::Application,
        initial_policy: policy.clone(),
        initial_limits: Limits::default(),
        voters: data_voters,
    };
    let control_config = ReplicatedBootstrap {
        incarnation: control_inc.to_string(),
        genesis: ReplicatedGenesis::Control(kasumi_engine::ControlGenesis {
            topology: topology.clone(),
            lifecycle: kasumi_engine::ControlLifecycleGenesis::Installed {
                command_id: Uuid::new_v4(),
                installation: LifecycleInstallation {
                    root: root.clone(),
                    generation: 1,
                    partitions: BTreeMap::from([(partition.key(), partition)]),
                    max_intents: 100,
                    max_changes: 10,
                    max_state_bytes: 1 << 20,
                },
            },
        }),
        initial_policy: policy,
        initial_limits: Limits::default(),
        voters: control_voters,
    };
    let router = Arc::new(kasumi_raft::InProcessRouter::default());
    let mut data = vec![];
    let mut controls = vec![];
    let mut stores = vec![];
    let mut audits = vec![];
    let mut physicals = vec![];
    for id in 1..=6 {
        let base = dir.path().join(format!("member-{id}"));
        private_files::create_directory(&base).unwrap();
        let (persistent, scratch) = kasumi_engine::test_utils::fixture_disk_configs(&base).unwrap();
        // Exercise the admission policy generated for an actual installation,
        // including its native audit escrow, protected lane, and disk leases.
        let policy = crate::runtime::generated_admission(&persistent, &scratch).unwrap();
        eprintln!(
            "dedicated backup member {id} generated admission bytes {:?}",
            policy.max_inflight_bytes
        );
        let admission = kasumi_engine::admission::NodeAdmission::new_fixture(policy).unwrap();
        let disks = kasumi_engine::test_utils::FixtureStorage::with_admission(
            &persistent,
            &scratch,
            admission,
        )
        .unwrap();
        let node = disks
            .create_new(base.join("persistent/node.kv"), Uuid::new_v4())
            .unwrap();
        let sec = TenantStore::initialize_catalog(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([80 + id as u8; 32])),
            StorageAccess::security_audit(),
        )
        .await
        .unwrap();
        let audit = kasumi_engine::SecurityAudit::initialize(
            sec,
            Default::default(),
            disks.admission.clone(),
        )
        .unwrap();
        let (bootstrap, name, access) = if id <= 3 {
            let verifier = kasumi_serving::test_utils::fixture_verifier(id);
            let boot = ServingBoot::with_test_clock(
                signing.for_verifier(verifier.clone()).unwrap().trust,
                ServingIdentity {
                    tenant: tenant.into(),
                    incarnation: data_inc,
                    authority_epoch: 1,
                    node: kasumi_serving::NodeIdentity {
                        node_id: id,
                        verifier,
                        principal: format!("writer-{id}"),
                        certificate_sha256: ids.pin(id as usize),
                    },
                },
                Arc::new(FixtureClock),
            )
            .unwrap();
            let attempt = boot.begin_acquisition().unwrap();
            let signed = signing
                .signer
                .sign_lease(kasumi_serving::LeaseClaims {
                    request: attempt.request().clone(),
                    authority_id: manifest.authority_id,
                    partition: 0,
                    authority_term: 1,
                    authority_revision: 1,
                    lifetime_ms: 1000,
                    credential_lifetime_ms: 1000,
                    activation_digest: "a".repeat(64),
                    recovery_checkpoint: None,
                })
                .unwrap();
            (
                &data_config,
                tenant,
                StorageAccess::serving(ServingGate::new(attempt.verify(signed).unwrap()).unwrap())
                    .unwrap(),
            )
        } else {
            (
                &control_config,
                crate::runtime::CONTROL_TENANT,
                StorageAccess::node_control(),
            )
        };
        let pair = TenantStorageSet::initialize_catalogs(
            node.clone(),
            name.into(),
            Arc::new(LocalKeyProvider::new([id as u8; 32])),
            Arc::new(LocalKeyProvider::new([10 + id as u8; 32])),
            access,
        )
        .await
        .unwrap();
        kasumi_engine::test_utils::install_local_replica_audit_placement(pair.application())
            .unwrap();
        let db = kasumi_engine::open_replicated(
            id,
            pair,
            bootstrap,
            router.clone(),
            kasumi_raft::server_config(),
            audit.clone(),
        )
        .await
        .unwrap();
        router.register(
            format!("{name}/{}", bootstrap.incarnation),
            id,
            db.raft_group().raft().clone(),
        );
        if id <= 3 {
            data.push(db);
        } else {
            controls.push(db);
        }
        stores.push(node);
        audits.push(audit);
        physicals.push(disks);
    }
    kasumi_engine::initialize_replicated(&data[0], &data_config)
        .await
        .unwrap();
    kasumi_engine::initialize_replicated(&controls[0], &control_config)
        .await
        .unwrap();
    let (source, control) = tokio::join!(leader(&data), leader(&controls));
    for db in data.iter().chain(&controls) {
        db.raft_group().raft().runtime_config().elect(false);
    }
    let source_id = source.raft_group().node_id();
    let control_id = control.raft_group().node_id();
    let source_index = source_id as usize - 1;
    let control_index = control_id as usize - 1;
    let data_socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let data_route = listen(&data_socket, ids.pin(source_id as usize));
    let control_route = listen(&control_socket, ids.pin(control_id as usize));
    let jwt = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let keys:jsonwebtoken::jwk::JwkSet=serde_json::from_value(json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"backup","x":URL_SAFE_NO_PAD.encode(jwt.public_key_raw())}]})).unwrap();
    let acl = crate::auth::AuthConfig {
        issuer: "https://identity.example".into(),
        audience: "https://control.example".into(),
        source: crate::auth::AuthKeySource::ExternalOAuth {
            jwks_uri: "https://identity.example/keys".into(),
            trusted_ca_pem: None,
        },
        algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
        access_token_types: BTreeSet::from(["at+jwt".into()]),
        mcp_audience: None,
        require_certificate_binding: false,
    };
    let make_token = |principal: &str, name: &str, kind: &str, incarnation: Uuid, scope: &str| {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some("backup".into());
        header.typ = Some("at+jwt".into());
        let now = kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            / 1000;
        jsonwebtoken::encode(&header,&json!({"sub":principal,"tenant":name,"kasumi_resource":{"kind":kind,"incarnation":incarnation},"scope":scope,
            "iss":"https://identity.example","aud":"https://control.example","exp":now+600}),&jsonwebtoken::EncodingKey::from_ed_pem(jwt.serialize_pem().as_bytes()).unwrap()).unwrap()
    };
    let routing_token = make_token(
        "router",
        crate::runtime::CONTROL_TENANT,
        "control",
        control_inc,
        "kasumi:read",
    );
    let writer_name = format!("writer-{source_id}");
    let writer = make_token(
        &writer_name,
        crate::runtime::CONTROL_TENANT,
        "control",
        control_inc,
        "kasumi:write",
    );
    let callback = make_token(
        "recheck",
        crate::runtime::CONTROL_TENANT,
        "control",
        control_inc,
        "kasumi:read",
    );
    let operator = make_token("operator", tenant, "database", data_inc, "kasumi:admin");
    let writer_path = dir.path().join("write.token");
    let callback_path = dir.path().join("callback.token");
    let observer_path = dir.path().join("read.token");
    write_token(&observer_path, &routing_token);
    write_token(&writer_path, &writer);
    write_token(&callback_path, &callback);
    let access = BackupAccess {
        tls: ids.files[source_id as usize].clone(),
        bearer_file: writer_path.display().to_string(),
        principal: writer_name.clone(),
        source_certificate_pins: topology.nodes[&source_id].certificate_pins.clone(),
        callback_principal: "recheck".into(),
        callback_certificate_pins: BTreeSet::from([ids.pin(7)]),
    };
    let remote = crate::remote_control::RemoteControlConfig {
        root,
        backup: Some(access.clone()),
        endpoints: BTreeMap::from([(control_id, control_route.clone())]),
        tls: ids.files[0].clone(),
        principal: "router".into(),
        server_ca: ids.ca.clone(),
        bearer_file: observer_path.display().to_string(),
        observers: BTreeSet::from(["observer".into()]),
        refresh_interval_ms: 1000,
        request_timeout_ms: 5000,
    };
    let enrollment = BackupSources {
        tls: ids.files[7].clone(),
        server_ca: ids.ca.clone(),
        bearer_file: callback_path.display().to_string(),
        callback_principal: "recheck".into(),
        members: BTreeMap::from([(
            source_id,
            SourceRoute {
                admin: data_route.clone(),
                writer_principal: writer_name,
                source_certificate_pins: topology.nodes[&source_id].certificate_pins.clone(),
            },
        )]),
    };
    enrollment.validate(&topology).unwrap();
    // Both enrolled writer leaves can open an installed client. Each actual
    // request must additionally match the live data lease and Control roster.
    let mut refreshed = access.clone();
    refreshed.tls = ids.files[source_id as usize + 7].clone();
    DataTransport::open(
        &remote,
        &refreshed,
        physicals[source_index].admission.clone(),
    )
    .unwrap();
    refreshed.tls = ids.files[0].clone();
    assert!(
        DataTransport::open(
            &remote,
            &refreshed,
            physicals[source_index].admission.clone()
        )
        .is_err()
    );
    let data_endpoint =
        DataTransport::open(&remote, &access, physicals[source_index].admission.clone()).unwrap();
    source
        .install_remote_backup_transport(Arc::new(SourceTrace(data_endpoint.clone())))
        .unwrap();
    control
        .install_remote_backup_verifier(Arc::new(ControlTrace(
            ControlVerifier::open(&enrollment, &physicals[control_index].admission).unwrap(),
        )))
        .unwrap();
    let directory = dir
        .path()
        .join(format!("member-{source_id}/persistent/external"));
    let dest = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            &directory,
            32 << 20,
            physicals[source_index].persistent.clone(),
        )
        .unwrap(),
    );
    source
        .install_archive_destination("approved".into(), dest.clone())
        .unwrap();
    let registry = DatabaseRegistry::default();
    registry.insert(source.clone()).unwrap();
    let auth = Authenticator::with_test_keys(acl.clone(), keys.clone()).await;
    auth.install_audit(audits[source_index].clone()).unwrap();
    let control_auth = Authenticator::with_test_keys(acl, keys).await;
    control_auth
        .install_audit(audits[control_index].clone())
        .unwrap();
    let failed = |i: usize, participant: &str| {
        crate::administration::OriginalRecoveries::new(
            &physicals[i].admission,
            crate::administration::OriginalRecoveryParticipants::one(participant),
        )
        .unwrap()
    };
    let data_failures = failed(source_index, tenant);
    let original_failures = || {
        (0..physicals[source_index]
            .admission
            .policy()
            .max_inflight_operations)
            .filter_map(|index| {
                data_failures.with_rpc_original(index, |original| {
                    if let Some(cause) = original.operation_error() {
                        return anyhow::Error::from(cause.clone())
                            .chain()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(" -> ");
                    }
                    if let Some(cause) = original.source_error() {
                        return format!("{cause:#}");
                    }
                    original.to_string()
                })
            })
            .collect::<Vec<_>>()
    };
    let mut data_admin = NativeAdmin::new(registry, auth.clone(), data_failures.clone());
    data_admin.backup = Some(Endpoint::Source(data_endpoint));
    let mut control_admin = NativeAdmin::new(
        DatabaseRegistry::default(),
        control_auth.clone(),
        failed(control_index, crate::runtime::CONTROL_TENANT),
    );
    control_admin.backup = Some(Endpoint::Control(control.clone()));
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let ca = std::fs::read(&ids.ca).unwrap();
    let serve = |socket, id: usize, routes: axum::Router| {
        tokio::spawn(crate::tls::serve_tls(
            socket,
            kasumi_transport::server_config(
                &ids.files[id].load().unwrap(),
                kasumi_transport::ClientAuthentication::Required {
                    trusted_ca_pem: &ca,
                },
            )
            .unwrap(),
            routes,
            Default::default(),
            Arc::new(ListenerAudit),
            stopped.clone(),
        ))
    };
    let native = |admin: NativeAdmin, auth: Arc<Authenticator>, i: usize| {
        tonic::service::Routes::new(admin.service())
            .into_axum_router()
            .layer(axum::middleware::from_fn_with_state(
                crate::request_admission::RequestAdmission::native(
                    physicals[i].admission.clone(),
                    auth,
                ),
                crate::request_admission::admit,
            ))
    };
    let serving = serve(
        data_socket,
        source_id as usize,
        native(data_admin, auth, source_index),
    );
    let original = Arc::new(Mutex::new(None));
    let cut = Arc::new(AtomicBool::new(true));
    let fault = axum::middleware::from_fn({
        let original = original.clone();
        let cut = cut.clone();
        move |request: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| {
            let original = original.clone();
            let cut = cut.clone();
            async move {
                if request.uri().path() != "/kasumi.v1.KasumiAdmin/ExchangeBackupBinding" {
                    return next.run(request).await;
                }
                let (parts, body) = request.into_parts();
                let bytes = axum::body::to_bytes(body, MAX_REMOTE_BACKUP_BYTES + 1024)
                    .await
                    .unwrap();
                let envelope =
                    <proto::PrivateReadJsonRequest as prost::Message>::decode(&bytes[5..]).unwrap();
                let command: RemoteBackupCommand =
                    serde_json::from_slice(&envelope.request_json).unwrap();
                let claim = matches!(command.action, RemoteBackupAction::Claim { .. });
                let response = next
                    .run(axum::http::Request::from_parts(
                        parts,
                        axum::body::Body::from(bytes),
                    ))
                    .await;
                if let Some(grpc) = response.headers().get("grpc-status") {
                    eprintln!(
                        "dedicated backup Control status {:?} {:?}",
                        grpc,
                        response.headers().get("grpc-message")
                    );
                }
                if claim
                    && response.status().is_success()
                    && response.headers().get("grpc-status").is_none()
                    && cut.swap(false, Ordering::SeqCst)
                {
                    let reply =
                        axum::body::to_bytes(response.into_body(), MAX_REMOTE_BACKUP_BYTES + 1024)
                            .await
                            .unwrap();
                    assert!(reply.len() > 5, "Control did not return its committed row");
                    let wire =
                        <proto::PrivateReadJsonResponse as prost::Message>::decode(&reply[5..])
                            .unwrap();
                    let record =
                        serde_json::from_slice::<Option<RemoteBackupRecord>>(&wire.response_json)
                            .unwrap()
                            .unwrap();
                    *original.lock().unwrap() = Some((command, record));
                    return axum::http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .header("grpc-status", "14")
                        .body(axum::body::Body::empty())
                        .unwrap();
                }
                response
            }
        }
    });
    let confirming = serve(
        control_socket,
        control_id as usize,
        native(control_admin, control_auth, control_index).layer(fault),
    );
    let config = |route: &AuthorityEndpoint, id: usize| KasumiClientConfig {
        endpoint: route.endpoint.clone(),
        identity: ids.files[id].load().unwrap(),
        trusted_ca_pem: ca.clone(),
        server_certificate_pins: route
            .certificate_pins
            .iter()
            .map(|v| crate::runtime::parse_certificate_pin(v).unwrap())
            .collect(),
    };
    let mut admin = KasumiAdminClient::connect(&config(&data_route, 0))
        .await
        .unwrap();
    let session = Uuid::new_v4();
    let request = CreateBackupCheckpoint {
        session_id: session,
        destination: "approved".into(),
    };
    let status = BackupSessionRequest {
        session_id: session,
        destination: "approved".into(),
    };
    let exists = || dest.session_get(session, kasumi_store::BackupSessionSlot::Intent, 1 << 20);
    write_token(&writer_path, &routing_token);
    assert_eq!(
        admin
            .create_backup_checkpoint(&operator, &request)
            .await
            .unwrap_err()
            .code(),
        Some(ErrorCode::Forbidden),
        "{:?}",
        original_failures()
    );
    assert!(exists().await.unwrap().is_none());
    write_token(&writer_path, &writer);
    write_token(&callback_path, &routing_token);
    assert_eq!(
        admin
            .create_backup_checkpoint(&operator, &request)
            .await
            .unwrap_err()
            .code(),
        Some(ErrorCode::Forbidden),
        "{:?}",
        original_failures()
    );
    assert!(exists().await.unwrap().is_none());
    write_token(&callback_path, &callback);
    let empty = admin
        .backup_session_status(&operator, &status)
        .await
        .unwrap_err();
    assert_eq!(empty.code(), Some(ErrorCode::NotFound), "{empty}");
    let lost = admin
        .create_backup_checkpoint(&operator, &request)
        .await
        .unwrap_err();
    eprintln!("dedicated backup create after fault: {lost}");
    assert!(exists().await.unwrap().is_none());
    let (command, committed) = original.lock().unwrap().clone().unwrap_or_else(|| {
        panic!(
            "lost after a real Control commit: {:?}",
            original_failures()
        )
    });
    let mut control_client =
        KasumiAdminClient::connect(&config(&control_route, source_id as usize))
            .await
            .unwrap();
    assert_eq!(
        control_client
            .exchange_backup_binding(&writer, &command)
            .await
            .unwrap_err()
            .code(),
        Some(ErrorCode::Forbidden)
    );
    let complete = admin
        .create_backup_checkpoint(&operator, &request)
        .await
        .unwrap();
    assert_eq!(
        exists().await.unwrap().unwrap(),
        committed.record.claim.intent_ciphertext
    );
    let duplicate = admin
        .create_backup_checkpoint(&operator, &request)
        .await
        .unwrap();
    assert_eq!(complete.checkpoint(), duplicate.checkpoint());
    let observation = admin
        .backup_session_status(&operator, &status)
        .await
        .unwrap();
    assert_eq!(observation.intent.session_id, session);
    let cleanup = admin
        .cleanup_backup_session(
            &operator,
            &CleanupBackupSession {
                destination: "approved".into(),
                session_id: session,
                max_objects: 3,
            },
        )
        .await;
    assert!(
        cleanup.is_err(),
        "completed backup cannot be cleaned as failed"
    );
    let aborted_id = Uuid::new_v4();
    cut.store(true, Ordering::SeqCst);
    let unpublished = CreateBackupCheckpoint {
        session_id: aborted_id,
        destination: "approved".into(),
    };
    assert!(
        admin
            .create_backup_checkpoint(&operator, &unpublished)
            .await
            .is_err()
    );
    assert!(
        dest.session_get(aborted_id, kasumi_store::BackupSessionSlot::Intent, 1 << 20)
            .await
            .unwrap()
            .is_none()
    );
    let abort = AbortBackupSession {
        destination: "approved".into(),
        session_id: aborted_id,
        reason: "operator cancellation".into(),
    };
    let aborted = admin.abort_backup_session(&operator, &abort).await.unwrap();
    assert!(
        matches!(aborted.outcome,Some(BackupSessionOutcome::Aborted{ref reason,..}) if reason=="operator cancellation")
    );
    assert_eq!(
        abort.session_id,
        admin
            .abort_backup_session(&operator, &abort)
            .await
            .unwrap()
            .intent
            .session_id
    );
    let cleanup = admin
        .cleanup_backup_session(
            &operator,
            &CleanupBackupSession {
                destination: "approved".into(),
                session_id: aborted_id,
                max_objects: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(cleanup.session_id, aborted_id);
    // A live transport token and unchanged member pin cannot restore a
    // revoked tenant administrator. Only the replacement administrator may
    // restore that committed application policy.
    let source_operator = RequestContext::trusted(tenant, "operator", [Action::Admin]);
    let replacement = RequestContext::trusted(tenant, "replacement", [Action::Admin]);
    let mut changed = data_config.initial_policy.clone();
    changed.grants.retain(|g| g.principal != "operator");
    changed.grants.push(Grant {
        principal: "replacement".into(),
        collection: None,
        actions: BTreeSet::from([Action::Admin]),
    });
    source
        .administer(source_operator, Operation::SetPolicy(changed))
        .await
        .unwrap();
    let refused = CreateBackupCheckpoint {
        destination: "approved".into(),
        session_id: Uuid::new_v4(),
    };
    assert_eq!(
        admin
            .create_backup_checkpoint(&operator, &refused)
            .await
            .unwrap_err()
            .code(),
        Some(ErrorCode::Forbidden)
    );
    assert!(
        dest.session_get(
            refused.session_id,
            kasumi_store::BackupSessionSlot::Intent,
            1 << 20
        )
        .await
        .unwrap()
        .is_none()
    );
    source
        .administer(
            replacement,
            Operation::SetPolicy(data_config.initial_policy.clone()),
        )
        .await
        .unwrap();

    // Closed Control changes policy through its lifecycle command. Beginning
    // the real transition immediately closes backup authority while issuer
    // drain and completion are outstanding.
    let mut revoked = control_config.initial_policy.clone();
    revoked
        .grants
        .retain(|g| g.collection.as_deref() != Some(BACKUP_DELEGATION_COLLECTION));
    let ReplicatedGenesis::Control(genesis) = &control_config.genesis else {
        unreachable!()
    };
    let kasumi_engine::ControlLifecycleGenesis::Installed { installation, .. } = &genesis.lifecycle
    else {
        unreachable!()
    };
    let control_operator =
        RequestContext::trusted(crate::runtime::CONTROL_TENANT, "operator", [Action::Admin]);
    control
        .lifecycle_control(
            control_operator,
            LifecycleControlCommand::BeginPolicyChange(BeginControlPolicyChange {
                command_id: Uuid::new_v4(),
                expected_policy_epoch: 1,
                installation_sha256: kasumi_serving::digest(installation).unwrap(),
                candidate: ControlPolicyCandidate {
                    policy: revoked,
                    retire_control: false,
                },
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        admin
            .create_backup_checkpoint(&operator, &refused)
            .await
            .unwrap_err()
            .code(),
        Some(ErrorCode::UnknownOutcome),
        "{:?}",
        original_failures()
    );
    // Read the same already-resolved session through the native status route.
    // This non-mutating observation can report the original policy refusal.
    assert_eq!(
        admin
            .backup_session_status(&operator, &status)
            .await
            .unwrap_err()
            .code(),
        Some(ErrorCode::Conflict)
    );
    assert!(
        dest.session_get(
            refused.session_id,
            kasumi_store::BackupSessionSlot::Intent,
            1 << 20
        )
        .await
        .unwrap()
        .is_none()
    );
    drop(admin);
    drop(control_client);
    stop.send(true).unwrap();
    serving.await.unwrap().unwrap();
    confirming.await.unwrap().unwrap();
    for node in data.iter().chain(&controls) {
        node.shutdown().await.unwrap();
    }
    for audit in audits {
        audit.shutdown().await.unwrap();
    }
    for node in stores {
        node.shutdown().await.unwrap();
    }
}
