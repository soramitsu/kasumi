// Actual installed issuer, Control dispatch, and target owners for the runtime
// TLS fixture. Signed receipts below come only from real replicated services.
use super::*;
use crate::{
    recovery_runtime::{
        ControlRecoveryCoordinator, RecoveryMember, RecoveryRoute, RecoveryRuntimeConfig,
    },
    serving_runtime::{AuthorityEndpoint, ServingAuthorityConfig, TenantServingConfig},
    target_runtime::TargetRecoveryRuntime,
    target_runtime_config::{
        TargetBackupSource, TargetRecoveryConfig, TargetRunnerLimits, TargetTenantTemplate,
    },
};
use anyhow::Result;
use kasumi_serving::{AuthorityManifest, AuthorityPartition, NodeIdentity};
use kasumi_store::private_files;
use kasumi_types::*;

const OPERATOR: &str = "operator";

// Bounded test diagnostics retain semantic counters and error classes only.
// They neither renew a dispatch nor retain a database, task or credential.
fn recovery_step_error(error: &kasumi_client::ClientError) -> String {
    use kasumi_client::ClientError;
    match error {
        ClientError::Transport(status) => format!(
            "{:?}: {}",
            status.code(),
            status.message().chars().take(384).collect::<String>()
        ),
        ClientError::DecodeRejected { code, reason } => format!("decode {code:?}: {reason}"),
        ClientError::InvalidResponse(reason) => format!("invalid response: {reason}"),
        ClientError::Connection(_) => "connection".into(),
        ClientError::Json(_) => "json".into(),
        ClientError::Authorization => "authorization".into(),
        ClientError::RequestTooLarge => "request too large".into(),
    }
}
// Failure-only metadata from existing owners. Weak references cannot keep a
// retired source or Control owner alive, and this performs no RPC or retry.
fn recovery_database_progress(owner: &std::sync::Weak<kasumi_engine::Database>) -> String {
    let Some(database) = owner.upgrade() else {
        return "owner dropped".into();
    };
    let metrics = database.raft_group().raft().metrics().borrow().clone();
    let running = format!("{:?}", metrics.running_state)
        .chars()
        .take(512)
        .collect::<String>();
    let state = match database.engine().generation() {
        Ok(generation) => format!(
            "revision={} retired={}",
            generation.state.revision, generation.state.retired
        ),
        Err(error) => format!("unavailable {:?}", error.code),
    };
    format!(
        "node={} state={:?} term={} leader={:?} running={} last_log={:?} applied={:?} snapshot={:?} quorum_ack_ms={:?} engine={}",
        metrics.id,
        metrics.state,
        metrics.current_term,
        metrics.current_leader,
        running,
        metrics.last_log_index,
        metrics.last_applied,
        metrics.snapshot,
        metrics.millis_since_quorum_ack,
        state
    )
}
fn recovery_progress(record: &RecoveryRecord) -> String {
    format!(
        "phase={:?} revision={} next={} pending={:?} last={:?} initialized={} completion_intent={:?} predecessor={:?} prepared={:?} prepare_attempt={:?} complete_attempt={:?} resolve_attempt={:?} terminal={:?} completion={:?} activated={} routed={} voters={:?}",
        record.phase,
        record.updated_revision,
        record.next_phase_sequence,
        record.pending_phase,
        record.last_phase,
        record.initialization.is_some(),
        record.completion_intent,
        record.completion_predecessor,
        record.completion_preparation,
        record.completion_preparation_attempt,
        record.completion_attempt,
        record.completion_resolution_attempt,
        record.completion_terminal,
        record.completion,
        record.activation.is_some(),
        record.route_publication.is_some(),
        record
            .voters
            .iter()
            .take(3)
            .map(|(node, voter)| (
                *node,
                voter.materialization.is_some(),
                voter.started.is_some(),
                voter.confirmation.is_some()
            ))
            .collect::<Vec<_>>()
    )
}
fn recovery_target_step(step: &TargetRuntimeStep) -> &'static str {
    match step {
        TargetRuntimeStep::Materialize(_) => "Materialize",
        TargetRuntimeStep::ResumeMaterialization(_) => "ResumeMaterialization",
        TargetRuntimeStep::Start(_) => "Start",
        TargetRuntimeStep::Initialize(_) => "Initialize",
        TargetRuntimeStep::Complete(_) => "Complete",
        TargetRuntimeStep::PrepareComplete(_) => "PrepareComplete",
        TargetRuntimeStep::ResolveComplete(_) => "ResolveComplete",
        TargetRuntimeStep::MaintainBudget { .. } => "MaintainBudget",
        TargetRuntimeStep::StartActivation { .. } => "StartActivation",
        TargetRuntimeStep::Activate { .. } => "Activate",
        TargetRuntimeStep::ConfirmActivation(_) => "ConfirmActivation",
        TargetRuntimeStep::ConfirmInspection(_) => "ConfirmInspection",
        TargetRuntimeStep::Inspect(_) => "Inspect",
        TargetRuntimeStep::InspectCompletionAttempt(_) => "InspectCompletionAttempt",
        TargetRuntimeStep::InspectCompletionResolution(_) => "InspectCompletionResolution",
        TargetRuntimeStep::Stop(_) => "Stop",
    }
}

pub(super) struct Credentials {
    key: rcgen::KeyPair,
    pub jwks: serde_json::Value,
}
impl Credentials {
    pub fn new() -> Self {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let jwks = serde_json::json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"runtime-recovery","x":URL_SAFE_NO_PAD.encode(key.public_key_raw())}]});
        Self { key, jwks }
    }
    fn token(&self, principal: &str, tenant: &str, resource: CredentialResource) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some("runtime-recovery".into());
        header.typ = Some("at+jwt".into());
        let now = kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap()
            / 1000;
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "sub":principal,"tenant":tenant,"kasumi_resource":resource,
                "scope":"kasumi:admin kasumi:read kasumi:write kasumi:audit",
                "iss":"https://runtime-identity.example","aud":"https://runtime.example",
                "exp":now+3600
            }),
            &jsonwebtoken::EncodingKey::from_ed_pem(self.key.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap()
    }
}

pub(super) struct Handles {
    registry: DatabaseRegistry,
    cluster: Arc<ClusterNetwork>,
    audit: Arc<SecurityAudit>,
    trusts: BTreeMap<String, kasumi_serving::AuthorityTrust>,
}
impl Handles {
    pub fn capture(runtime: &NodeRuntime) -> Self {
        Self {
            registry: runtime.registry.clone(),
            cluster: runtime.cluster.clone().unwrap(),
            audit: runtime.audit.clone(),
            trusts: runtime.authority_trusts.clone(),
        }
    }
}

pub(super) struct Fixture {
    directory: PathBuf,
    credentials: Credentials,
    auth: AuthConfig,
    files: Vec<TlsFiles>,
    ca: PathBuf,
    root: ControlSigningRoot,
    installation: LifecycleInstallation,
    install_command: Uuid,
    manifest: AuthorityManifest,
    signing: kasumi_serving::test_utils::FixtureAuthority,
    endpoints: BTreeMap<u64, AuthorityEndpoint>,
    issuers: Vec<Arc<kasumi_authority::IndependentAuthority>>,
    issuer_stores: Vec<Arc<TenantStorageSet>>,
    issuer_nodes: Vec<Arc<NodeStore>>,
    storage: crate::runtime_memory::RuntimeStorage,
    issuer_audits: Vec<Arc<SecurityAudit>>,
    issuer_networks: Vec<Arc<ClusterNetwork>>,
    issuer_stops: Vec<watch::Sender<bool>>,
    issuer_tasks: Vec<tokio::task::JoinHandle<Result<()>>>,
    verifier_ids: Vec<kasumi_serving::TrustVerifierIdentity>,
    source: Uuid,
    pub target: Uuid,
    pub source_token: String,
    pub target_token: String,
    control_token: String,
    target_configs: Vec<RuntimeConfig>,
    targets: Vec<Arc<TargetRecoveryRuntime>>,
    target_stops: Vec<watch::Sender<bool>>,
    target_tasks: Vec<tokio::task::JoinHandle<Result<()>>>,
    native_addresses: Vec<std::net::SocketAddr>,
    control_stops: Vec<watch::Sender<bool>>,
    control_tasks: Vec<tokio::task::JoinHandle<Result<()>>>,
    control_observers: Vec<std::sync::Weak<kasumi_engine::Database>>,
    source_observer: std::sync::Weak<kasumi_engine::Database>,
    control_dispatch_node: u64,
    request: Option<RecoveryStart>,
}
impl Fixture {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        directory: &std::path::Path,
        credentials: Credentials,
        files: &[TlsFiles],
        ca: PathBuf,
        source: Uuid,
        control: Uuid,
        kms: &str,
        kms_certificate: &std::path::Path,
        cluster: &crate::runtime_cluster_storage::ClusterStorage,
        fenced_source: bool,
    ) -> impl std::future::Future<Output = Self> {
        Box::pin(async move {
            let directory = directory.join("canonical-recovery");
            assert!(
                directory.is_dir(),
                "shared fixture roots must precede census"
            );
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let root = ControlSigningRoot {
                control_incarnation: control,
                public_key: hex::encode(key.public_key_raw()),
            };
            private_files::publish(&directory.join("control.pk8"), &key.serialize_der()).unwrap();
            let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let signing_root = kasumi_serving::test_utils::FixtureSigningRoot::from_pkcs8(
                &issuer_key.serialize_der(),
            )
            .unwrap();
            let manifest = AuthorityManifest {
                authority_id: Uuid::new_v4(),
                lifecycle_controls: BTreeMap::from([(control, root.public_key.clone())]),
                partitions: BTreeMap::from([(
                    0,
                    AuthorityPartition {
                        group: "runtime-issuer".into(),
                        public_key: signing_root.public_key(),
                    },
                )]),
                max_lease_ms: 10_000,
                clock_rate_error_ppm: 0,
            };
            let signing = signing_root.install(manifest.clone(), 0).unwrap();
            let partition = manifest.control_partition(0).unwrap();
            let installation = LifecycleInstallation {
                root: root.clone(),
                generation: 1,
                partitions: BTreeMap::from([(partition.key(), partition)]),
                max_intents: 1000,
                max_changes: 64,
                max_state_bytes: 8 << 20,
            };
            let auth = AuthConfig {
                issuer: "https://runtime-identity.example".into(),
                audience: "https://runtime.example".into(),
                source: crate::auth::AuthKeySource::ExternalOAuth {
                    jwks_uri: format!("{kms}/recovery-jwks"),
                    trusted_ca_pem: Some(std::fs::read_to_string(kms_certificate).unwrap()),
                },
                algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
                access_token_types: BTreeSet::from(["at+jwt".into()]),
            };
            let target = Uuid::new_v4();
            let source_token = credentials.token(
                "acme-admin",
                "acme",
                CredentialResource::Database {
                    incarnation: source,
                },
            );
            let target_token = credentials.token(
                "acme-admin",
                "acme",
                CredentialResource::Database {
                    incarnation: target,
                },
            );
            let control_token = credentials.token(
                OPERATOR,
                CONTROL_TENANT,
                CredentialResource::Control {
                    incarnation: control,
                },
            );
            for (name, value) in [
                ("source.jwt", source_token.clone()),
                ("target.jwt", target_token.clone()),
                ("control.jwt", control_token.clone()),
                (
                    "custody.jwt",
                    credentials.token(
                        "acme-admin",
                        "acme",
                        CredentialResource::Custody {
                            incarnation: source,
                        },
                    ),
                ),
                (
                    "issuer-admin.jwt",
                    credentials.token(
                        OPERATOR,
                        &format!("kasumi.authority.{}.0", manifest.authority_id),
                        CredentialResource::Authority {
                            authority_id: manifest.authority_id,
                            partition: 0,
                        },
                    ),
                ),
                ("transit.token", "test-runtime-token".into()),
            ] {
                private_files::publish(&directory.join(name), value.as_bytes()).unwrap();
            }
            let mut sockets = Vec::new();
            for _ in 0..3 {
                sockets.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
            }
            let endpoints: BTreeMap<_, _> = sockets
                .iter()
                .enumerate()
                .map(|(index, socket)| {
                    (
                        (index + 1) as u64,
                        AuthorityEndpoint {
                            endpoint: format!(
                                "https://localhost:{}",
                                socket.local_addr().unwrap().port()
                            ),
                            certificate_pins: BTreeSet::from([hex::encode(
                                files[index].load().unwrap().certificate_pin(),
                            )]),
                        },
                    )
                })
                .collect();
            let authority_install = kasumi_authority::AuthorityInstallation {
                manifest: manifest.clone(),
                partition: 0,
            };
            // Issuer physical identities are separate from source/target verifiers.
            let authority_ids = (1..=3)
                .map(|node_id| kasumi_serving::TrustVerifierIdentity {
                    installation_id: Uuid::new_v4(),
                    node_id,
                })
                .collect::<Vec<_>>();
            let members = endpoints
                .iter()
                .map(|(id, endpoint)| {
                    (
                        *id,
                        kasumi_serving::AuthorityMember {
                            verifier: authority_ids[*id as usize - 1].clone(),
                            endpoint: endpoint.endpoint.clone(),
                            failure_domain: format!("issuer-zone-{id}"),
                            certificate_pins: endpoint.certificate_pins.clone(),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let bootstrap = kasumi_authority::AuthorityBootstrap {
                initial_signer_certificate: signing.signer.certificate().clone(),
                administrators: BTreeSet::from([OPERATOR.into()]),
                capacity: kasumi_serving::AuthorityCapacity {
                    max_tenants: 100,
                    max_state_bytes: 16 << 20,
                    maintenance_reserve_bytes: 1 << 20,
                },
                membership: kasumi_serving::AuthorityMembership {
                    voters: BTreeSet::from([1, 2, 3]),
                    members: members.clone(),
                },
            };
            let mut issuers = Vec::new();
            let mut issuer_stores = Vec::new();
            let mut issuer_nodes = Vec::new();
            let mut issuer_audits = Vec::new();
            let mut issuer_networks = Vec::new();
            let mut issuer_stops = Vec::new();
            let mut issuer_tasks = Vec::new();
            for (index, socket) in sockets.into_iter().enumerate() {
                let id = (index + 1) as u64;
                let admission = cluster.storage.facade(cluster.storage.policy()).unwrap();
                let disk = cluster
                    .storage
                    .open_persistent(&cluster.persistent)
                    .unwrap();
                let audit_node = NodeStore::create_new(
                    directory.join(format!("persistent/issuer-audit-{id}.kv")),
                    Uuid::new_v4(),
                    disk.clone(),
                    cluster
                        .storage
                        .open_scratch(&cluster.issuer_scratch[index][0])
                        .unwrap(),
                )
                .unwrap();
                issuer_nodes.push(audit_node.clone());
                let audit = SecurityAudit::initialize(
                    TenantStore::initialize_catalog_fixture(
                        audit_node,
                        kasumi_engine::SECURITY_TENANT.into(),
                        Arc::new(LocalKeyProvider::new([0xA0 + id as u8; 32])),
                    )
                    .await
                    .unwrap(),
                    AuditRetentionBudget {
                        hot_bytes: 64 << 20,
                        archive_bytes: 64 << 30,
                    },
                    admission.clone(),
                )
                .unwrap();
                let node = NodeStore::create_new(
                    directory.join(format!("persistent/issuer-{id}.kv")),
                    Uuid::new_v4(),
                    disk,
                    cluster
                        .storage
                        .open_scratch(&cluster.issuer_scratch[index][1])
                        .unwrap(),
                )
                .unwrap();
                issuer_nodes.push(node.clone());
                let stores = TenantStorageSet::initialize_catalogs(
                    node,
                    authority_install.tenant(),
                    Arc::new(LocalKeyProvider::new([40 + id as u8; 32])),
                    Arc::new(LocalKeyProvider::new([50 + id as u8; 32])),
                    kasumi_store::StorageAccess::independent_authority(&manifest, 0).unwrap(),
                )
                .await
                .unwrap();
                kasumi_authority::IndependentAuthority::initialize_storage(
                    &stores,
                    &authority_install,
                    &bootstrap,
                    &authority_ids[index],
                )
                .unwrap();
                let network = ClusterNetwork::new(
                    id,
                    &files[index].load().unwrap(),
                    &std::fs::read(&ca).unwrap(),
                    endpoints
                        .iter()
                        .map(|(node_id, endpoint)| crate::cluster::PeerConfig {
                            node_id: *node_id,
                            endpoint: endpoint.endpoint.clone(),
                            certificate_pins: endpoint
                                .certificate_pins
                                .iter()
                                .map(|pin| parse_certificate_pin(pin).unwrap())
                                .collect(),
                        })
                        .collect(),
                    crate::cluster::PeerLimits::default(),
                )
                .unwrap();
                network.install_audit(audit.clone()).unwrap();
                let authority = kasumi_authority::IndependentAuthority::open_existing_replicated(
                    stores.clone(),
                    authority_install.clone(),
                    signing
                        .for_verifier(authority_ids[index].clone())
                        .unwrap()
                        .signer,
                    id,
                    kasumi_authority::AuthorityNodeSettings {
                        resource_budget_bytes: 16 << 20,
                        installed_members: members.clone(),
                    },
                    network.clone(),
                    kasumi_raft::server_config(),
                    crate::authority_runtime::request_budget(&admission).unwrap(),
                    admission.snapshot_buffer_owner().unwrap(),
                )
                .await
                .unwrap();
                network
                    .register_group(
                        "runtime-issuer".into(),
                        authority.raft_group().raft().clone(),
                        BTreeSet::from([1, 2, 3]),
                    )
                    .unwrap();
                let authenticator = crate::auth::Authenticator::with_test_keys(
                    auth.clone(),
                    serde_json::from_value(credentials.jwks.clone()).unwrap(),
                )
                .await;
                authenticator.install_audit(audit.clone()).unwrap();
                let router = network.router().merge(
                    tonic::service::Routes::new(
                        crate::rpc::NativeAuthority::new(authority.clone(), authenticator)
                            .service(),
                    )
                    .into_axum_router(),
                );
                let (stop, stopped) = watch::channel(false);
                // The fenced-source test isolates startup after real signed issuer
                // enrollment. Audited issuer HA remains a separate release gate;
                // every other canonical recovery case uses the durable sink.
                let handshake_audit: Arc<dyn tls::TlsHandshakeAudit> = if fenced_source {
                    Arc::new(FixtureAudit)
                } else {
                    audit.clone()
                };
                issuer_tasks.push(tokio::spawn(tls::serve_tls(
                    socket,
                    network.server_tls(),
                    router,
                    ListenerLimits::default(),
                    handshake_audit,
                    stopped,
                )));
                issuer_stops.push(stop);
                issuer_networks.push(network);
                issuer_stores.push(stores);
                issuer_audits.push(audit);
                issuers.push(authority);
            }
            issuers[0].initialize().await.unwrap();
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    for issuer in &issuers {
                        let metrics = issuer.raft_group().raft().metrics().borrow().clone();
                        if metrics.current_leader == Some(metrics.id)
                            && matches!(
                                tokio::time::timeout(
                                    Duration::from_secs(2),
                                    issuer.raft_group().linearizable_barrier(),
                                )
                                .await,
                                Ok(Ok(_))
                            )
                        {
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                let progress = issuers
                    .iter()
                    .map(|issuer| {
                        let metrics = issuer.raft_group().raft().metrics().borrow().clone();
                        format!(
                            "id={} leader={:?} term={} state={:?} applied={:?} running={:?}",
                            metrics.id,
                            metrics.current_leader,
                            metrics.current_term,
                            metrics.state,
                            metrics.last_applied,
                            metrics.running_state,
                        )
                    })
                    .collect::<Vec<_>>();
                let audits = issuer_audits
                    .iter()
                    .map(|audit| audit.status().map_err(|error| error.to_string()))
                    .collect::<Vec<_>>();
                let transport_free = issuer_networks
                    .iter()
                    .map(|network| network.fixture_transport_free_slots())
                    .collect::<Vec<_>>();
                let listener_finished = issuer_tasks
                    .iter()
                    .map(|task| task.is_finished())
                    .collect::<Vec<_>>();
                panic!(
                    "issuer quorum did not become linearizable: {progress:?}; audit_status={audits:?}; transport_free={transport_free:?}; listener_finished={listener_finished:?}"
                )
            });
            let verifier_ids = (1..=3)
                .map(|node_id| kasumi_serving::TrustVerifierIdentity {
                    installation_id: Uuid::new_v4(),
                    node_id,
                })
                .collect();
            let mut result = Self {
                directory,
                credentials,
                auth,
                files: files.to_vec(),
                ca,
                root,
                installation,
                install_command: Uuid::new_v4(),
                manifest,
                signing,
                endpoints,
                issuers,
                issuer_stores,
                issuer_nodes,
                storage: cluster.storage.clone(),
                issuer_audits,
                issuer_networks,
                issuer_stops,
                issuer_tasks,
                verifier_ids,
                source,
                target,
                source_token,
                target_token,
                control_token,
                target_configs: Vec::new(),
                targets: Vec::new(),
                target_stops: Vec::new(),
                target_tasks: Vec::new(),
                native_addresses: Vec::new(),
                control_stops: Vec::new(),
                control_tasks: Vec::new(),
                control_observers: Vec::new(),
                source_observer: std::sync::Weak::new(),
                control_dispatch_node: 0,
                request: None,
            };
            result.enroll_tenant("acme", source).await;
            result
        })
    }
    fn path(&self, name: &str) -> String {
        self.directory.join(name).display().to_string()
    }
    fn node(&self, index: usize) -> NodeIdentity {
        NodeIdentity {
            node_id: (index + 1) as u64,
            verifier: self.verifier_ids[index].clone(),
            principal: format!("runtime-node-{}", index + 1),
            certificate_sha256: hex::encode(self.files[index].load().unwrap().certificate_pin()),
        }
    }
    pub async fn enroll_tenant(&mut self, tenant: &str, incarnation: Uuid) {
        let request = kasumi_serving::AuthorityCommand {
            tenant: tenant.into(),
            command_id: Uuid::new_v4(),
            expected_policy_epoch: 1,
            not_after_ms: kasumi_clock::EpochClock::system()
                .unwrap()
                .now_ms()
                .unwrap()
                + 60_000,
            action: kasumi_serving::AuthorityAction::Enroll {
                incarnation,
                nodes: (0..3).map(|index| self.node(index)).collect(),
            },
        };
        let config = self.authority(0);
        let endpoints = config.endpoints[&0]
            .iter()
            .map(|(id, endpoint)| {
                (
                    *id,
                    kasumi_client::KasumiClientConfig {
                        endpoint: endpoint.endpoint.clone(),
                        identity: config.tls.load().unwrap(),
                        trusted_ca_pem: std::fs::read(&self.ca).unwrap(),
                        server_certificate_pins: endpoint
                            .certificate_pins
                            .iter()
                            .map(|pin| parse_certificate_pin(pin).unwrap())
                            .collect(),
                    },
                )
            })
            .collect();
        let mut pool = kasumi_client::KasumiAuthorityPool::new(
            endpoints,
            self.signing.trust.clone(),
            Arc::new(
                kasumi_transport::credentials::FileCredentialSource::new(
                    self.path("issuer-admin.jwt"),
                )
                .unwrap(),
            ),
        )
        .unwrap();
        let receipt = pool
            .execute(&request, Duration::from_secs(30))
            .await
            .unwrap();
        assert!(
            !matches!(
                receipt.receipt.outcome,
                kasumi_serving::AuthorityOutcome::Rejected { .. }
            ),
            "{:?}",
            receipt.receipt
        );
    }
    fn authority(&self, index: usize) -> ServingAuthorityConfig {
        ServingAuthorityConfig {
            manifest: self.manifest.clone(),
            endpoints: BTreeMap::from([(0, self.endpoints.clone())]),
            tls: self.files[index].clone(),
            server_ca: self.ca.clone(),
            bearer_files: BTreeMap::from([(0, self.path(&format!("node-{}.jwt", index + 1)))]),
            principal: self.node(index).principal,
        }
    }
    pub async fn configure(&self, config: &mut RuntimeConfig, index: usize) {
        config.auth = self.auth.clone();
        config.control.lifecycle = Some(crate::lifecycle_runtime::LifecycleRuntimeConfig {
            command_id: self.install_command,
            installation: self.installation.clone(),
            signing_key: self.directory.join("control.pk8"),
            recovery: None,
        });
        assert!(
            config
                .control
                .initial_policy
                .grants
                .iter()
                .any(|grant| grant.principal == OPERATOR)
        );
        let token = self.credentials.token(
            &self.node(index).principal,
            &format!("kasumi.authority.{}.0", self.manifest.authority_id),
            CredentialResource::Authority {
                authority_id: self.manifest.authority_id,
                partition: 0,
            },
        );
        private_files::publish(
            &self.directory.join(format!("node-{}.jwt", index + 1)),
            token.as_bytes(),
        )
        .unwrap();
        for keys in [
            &mut config.control.keys,
            &mut config.control.custody_keys,
            &mut config.security_audit.keys,
        ]
        .into_iter()
        .chain(
            config
                .tenants
                .iter_mut()
                .flat_map(|tenant| [&mut tenant.keys, &mut tenant.custody_keys]),
        ) {
            keys.transit_mut().unwrap().token_file = self.path("transit.token");
        }
        let mut keys = config.control.keys.clone();
        keys.transit_mut().unwrap().key_name = format!("verifier-{}", index + 1);
        let verifier = crate::signer_runtime::SignerVerifierConfig {
            max_background_workers: 64,
            identity: self.verifier_ids[index].clone(),
            database_path: self
                .directory
                .join(format!("persistent/verifier-{}/trust.kv", index + 1)),
            keys,
        };
        let verifier_root = verifier.database_path.parent().unwrap();
        private_files::check_directory(verifier_root).unwrap();
        crate::signer_runtime::InitializeSignerVerifier {
            admission: config.admission.clone(),
            persistent_disk: config.persistent_disk.clone(),
            scratch_disk: config.scratch_disk.clone(),
            verifier: verifier.clone(),
            initial_certificates: vec![self.signing.signer.certificate().clone()],
        }
        .initialize_with_storage(self.storage.clone())
        .await
        .unwrap_or_else(|error| panic!("signer verifier fixture initialization failed: {error:?}"));
        config.signer_verifier = Some(verifier);
        config.serving_authorities = BTreeMap::from([("issuer".into(), self.authority(index))]);
        config.tenants[0].serving = TenantServingConfig::Independent {
            authority: "issuer".into(),
        };
    }
    pub async fn context(&self, target: bool) -> RequestContext {
        let auth = crate::auth::Authenticator::with_test_keys(
            self.auth.clone(),
            serde_json::from_value(self.credentials.jwks.clone()).unwrap(),
        )
        .await;
        auth.install_audit(self.issuer_audits[0].clone()).unwrap();
        auth.authenticate(&format!(
            "Bearer {}",
            if target {
                &self.target_token
            } else {
                &self.source_token
            }
        ))
        .await
        .unwrap()
    }
}

impl Fixture {
    fn admin(&self, endpoint: String, server: usize, credential: &str) -> AdminClientConfig {
        AdminClientConfig {
            endpoint,
            identity: self.files[0].clone(),
            server_ca: self.ca.clone(),
            server_certificate_pins: vec![hex::encode(
                self.files[server].load().unwrap().certificate_pin(),
            )],
            token_file: self.path(credential),
        }
    }
    async fn authenticator(&self, audit: Arc<SecurityAudit>) -> Arc<crate::auth::Authenticator> {
        let auth = crate::auth::Authenticator::with_test_keys(
            self.auth.clone(),
            serde_json::from_value(self.credentials.jwks.clone()).unwrap(),
        )
        .await;
        auth.install_audit(audit).unwrap();
        auth
    }
    pub fn install_targets(
        &mut self,
        configurations: &[RuntimeConfig],
        handles: &[Handles],
        controls: &[Arc<kasumi_engine::Database>],
        source: &Arc<kasumi_engine::Database>,
        checkpoint: FullBackupCheckpoint,
    ) -> impl std::future::Future<Output = ()> {
        Box::pin(async move {
            let control_leader = quorum_ready_leader(controls, "canonical Control dispatch").await;
            assert_eq!(controls.len(), 3);
            self.control_observers = controls.iter().map(Arc::downgrade).collect();
            self.source_observer = Arc::downgrade(source);
            self.control_dispatch_node = controls[control_leader]
                .raft_group()
                .raft()
                .metrics()
                .borrow()
                .id;
            let mut control_sockets = Vec::new();
            let mut control_endpoints = BTreeMap::new();
            for index in 0..controls.len() {
                let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
                control_endpoints.insert(
                    index as u64 + 1,
                    AuthorityEndpoint {
                        endpoint: format!(
                            "https://localhost:{}",
                            socket.local_addr().unwrap().port()
                        ),
                        certificate_pins: BTreeSet::from([hex::encode(
                            self.files[index].load().unwrap().certificate_pin(),
                        )]),
                    },
                );
                control_sockets.push(socket);
            }
            let mut sockets = Vec::new();
            for _ in 0..3 {
                sockets.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
            }
            self.native_addresses = sockets
                .iter()
                .map(|socket| socket.local_addr().unwrap())
                .collect();
            let mut nodes = BTreeMap::new();
            for (index, base) in configurations.iter().enumerate() {
                let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
                let attestation = self.directory.join(format!("target-{}.pk8", index + 1));
                private_files::publish(&attestation, &key.serialize_der()).unwrap();
                let node = self.node(index);
                nodes.insert(
                    node.node_id,
                    LifecycleNode {
                        node_id: node.node_id,
                        verifier: node.verifier.clone(),
                        principal: node.principal.clone(),
                        certificate_sha256: node.certificate_sha256.clone(),
                        attestation_public_key: hex::encode(key.public_key_raw()),
                    },
                );
                let mut config = base.clone();
                let target_key = |name: &str| {
                    let mut key = base.tenants[0].keys.clone();
                    key.transit_mut().unwrap().key_name = format!("target-{}-{name}", index + 1);
                    key
                };
                config.target_recovery = Some(TargetRecoveryConfig {
                    control_root: self.root.clone(),
                    control_endpoints: control_endpoints.clone(),
                    control_tls: self.files[index].clone(),
                    control_ca: self.ca.clone(),
                    node,
                    attestation_key: attestation,
                    issuer_admin_bearer_file: BTreeMap::from([(
                        self.manifest.authority_id,
                        self.path("issuer-admin.jwt"),
                    )]),
                    journal_path: self
                        .directory
                        .join(format!("persistent/target-journal-{}.kv", index + 1)),
                    journal_keys: target_key("journal"),
                    generation_root: self
                        .directory
                        .join(format!("persistent/target-generations-{}", index + 1)),
                    tenants: BTreeMap::from([(
                        "acme".into(),
                        TargetTenantTemplate {
                            authority: "issuer".into(),
                            application_keys: target_key("application"),
                            custody_keys: target_key("custody"),
                            source_backups: BTreeMap::from([(
                                self.source,
                                TargetBackupSource {
                                    destination_alias: "primary".into(),
                                    keys: base.tenants[0].keys.clone(),
                                },
                            )]),
                        },
                    )]),
                    limits: TargetRunnerLimits {
                        journal: TargetJournalLimits {
                            max_metadata_bytes: 32 << 20,
                        },
                        max_live_generations: 4,
                        operation_timeout_ms: 60_000,
                    },
                });
                crate::target_journal_installation::initialize_with_storage(
                    config.clone(),
                    self.storage.clone(),
                )
                .await
                .unwrap();
                self.target_configs.push(config);
            }
            let source_purpose = kasumi_types::staged_digest(
                source
                    .raft_group()
                    .storage_domains()
                    .application()
                    .storage_access()
                    .purpose(),
            )
            .unwrap()
            .0;
            let source_gate = source
                .raft_group()
                .storage_domains()
                .application()
                .storage_access()
                .serving_gate()
                .unwrap();
            source_gate.check().unwrap();
            let materialization = TargetMaterializationInput {
                destination_alias: "primary".into(),
                backup_id: checkpoint.backup_id,
                source_purpose_sha256: source_purpose.clone(),
                target_incarnation: self.target,
                voters: configurations[0]
                    .replication
                    .as_ref()
                    .unwrap()
                    .peers
                    .iter()
                    .map(|peer| {
                        (
                            peer.node_id,
                            TargetPeer {
                                endpoint: peer.endpoint.clone(),
                                failure_domain: peer.failure_domain.clone(),
                            },
                        )
                    })
                    .collect(),
            };
            let route = RecoveryRoute {
                tenant: "acme".into(),
                source_incarnation: self.source,
                source_purpose_sha256: source_purpose.clone(),
                authority: "issuer".into(),
                issuer_admin_bearer_file: self.path("issuer-admin.jwt"),
                targets: nodes
                    .iter()
                    .map(|(id, node)| {
                        (
                            *id,
                            RecoveryMember {
                                node: node.clone(),
                                replication: materialization.voters[id].clone(),
                                client: self.admin(
                                    format!(
                                        "https://localhost:{}",
                                        self.native_addresses[*id as usize - 1].port()
                                    ),
                                    *id as usize - 1,
                                    "control.jwt",
                                ),
                            },
                        )
                    })
                    .collect(),
                source: Some(crate::recovery_runtime::RecoverySource {
                    members: configurations
                        .iter()
                        .enumerate()
                        .map(|(index, config)| {
                            (
                                index as u64 + 1,
                                AuthorityEndpoint {
                                    endpoint: format!(
                                        "https://localhost:{}",
                                        config.admin.listen.port()
                                    ),
                                    certificate_pins: BTreeSet::from([hex::encode(
                                        self.files[index].load().unwrap().certificate_pin(),
                                    )]),
                                },
                            )
                        })
                        .collect(),
                    identity: self.files[0].clone(),
                    server_ca: self.ca.clone(),
                    token_file: self.path("source.jwt"),
                }),
                source_custody: Some(crate::recovery_runtime::RecoverySource {
                    members: configurations
                        .iter()
                        .enumerate()
                        .map(|(index, config)| {
                            (
                                index as u64 + 1,
                                AuthorityEndpoint {
                                    endpoint: format!(
                                        "https://localhost:{}",
                                        config.admin.listen.port()
                                    ),
                                    certificate_pins: BTreeSet::from([hex::encode(
                                        self.files[index].load().unwrap().certificate_pin(),
                                    )]),
                                },
                            )
                        })
                        .collect(),
                    identity: self.files[0].clone(),
                    server_ca: self.ca.clone(),
                    token_file: self.path("custody.jwt"),
                }),
            };
            self.request = Some(RecoveryStart {
                operation_id: Uuid::new_v4(),
                tenant: "acme".into(),
                source_incarnation: self.source,
                source_authority_epoch: source_gate.identity().authority_epoch,
                target_incarnation: self.target,
                checkpoint,
                source_purpose_sha256: source_purpose,
                source_mode: RecoverySourceMode::Planned {
                    retirement_id: "replicated-restore".into(),
                    source_backup_destination: "primary".into(),
                },
                installation_sha256: kasumi_serving::digest(&self.installation).unwrap(),
                expected_policy_epoch: controls[control_leader]
                    .engine()
                    .generation()
                    .unwrap()
                    .state
                    .policy_epoch,
                authority_policy_epoch: 1,
                authority_partition: self.manifest.control_partition(0).unwrap().key(),
                dispatch_configuration_sha256: route
                    .digest(&configurations[control_leader].serving_authorities["issuer"])
                    .unwrap(),
                target_nodes: nodes,
                materialization,
                phase_timeout_ms: 60_000,
            });
            for (index, socket) in control_sockets.into_iter().enumerate() {
                let mut config = configurations[index].clone();
                config.control.lifecycle.as_mut().unwrap().recovery = Some(RecoveryRuntimeConfig {
                    routes: BTreeMap::from([("planned".into(), route.clone())]),
                });
                self.start_control(
                    socket,
                    config,
                    controls[index].clone(),
                    &handles[index],
                    index,
                )
                .await;
            }
            self.open_targets(handles, sockets).await;
        })
    }
    async fn start_control(
        &mut self,
        socket: TcpListener,
        config: RuntimeConfig,
        control: Arc<kasumi_engine::Database>,
        handles: &Handles,
        certificate: usize,
    ) {
        let signer = config.control.lifecycle.as_ref().unwrap().signer().unwrap();
        let auth = self.authenticator(handles.audit.clone()).await;
        let lifecycle =
            crate::rpc::NativeLifecycleControl::new(control.clone(), signer.clone(), auth.clone())
                .unwrap();
        let coordinator =
            ControlRecoveryCoordinator::new(&config, control, signer, handles.trusts.clone())
                .unwrap();
        let router = tonic::service::Routes::new(lifecycle.service())
            .add_service(crate::rpc::NativeRecoveryControl::new(coordinator, auth).service())
            .into_axum_router();
        let (stop, stopped) = watch::channel(false);
        self.control_tasks.push(tokio::spawn(tls::serve_tls(
            socket,
            kasumi_transport::server_config(
                &self.files[certificate].load().unwrap(),
                ClientAuthentication::Required {
                    trusted_ca_pem: &std::fs::read(&self.ca).unwrap(),
                },
            )
            .unwrap(),
            router,
            ListenerLimits::default(),
            handles.audit.clone(),
            stopped,
        )));
        self.control_stops.push(stop);
    }
    async fn open_targets(&mut self, handles: &[Handles], sockets: Vec<TcpListener>) {
        for (index, socket) in sockets.into_iter().enumerate() {
            let config = &self.target_configs[index];
            let target = TargetRecoveryRuntime::open(
                config.clone(),
                handles[index].trusts.clone(),
                Arc::new(file_secret),
                handles[index].audit.admission().clone(),
                handles[index].audit.clone(),
                handles[index].cluster.clone(),
                config
                    .backup_destinations
                    .iter()
                    .map(|(alias, destination)| {
                        (
                            alias.clone(),
                            destination
                                .open(handles[index].audit.store().persistent_disk().clone())
                                .unwrap(),
                        )
                    })
                    .collect(),
                handles[index].registry.clone(),
            )
            .await
            .unwrap();
            let router = tonic::service::Routes::new(
                crate::rpc::NativeTargetRecovery::new(
                    target.clone(),
                    self.authenticator(handles[index].audit.clone()).await,
                )
                .service(),
            )
            .into_axum_router();
            let (stop, stopped) = watch::channel(false);
            self.target_tasks.push(tokio::spawn(tls::serve_tls(
                socket,
                kasumi_transport::server_config(
                    &self.files[index].load().unwrap(),
                    ClientAuthentication::Required {
                        trusted_ca_pem: &std::fs::read(&self.ca).unwrap(),
                    },
                )
                .unwrap(),
                router,
                ListenerLimits::default(),
                handles[index].audit.clone(),
                stopped,
            )));
            self.target_stops.push(stop);
            self.targets.push(target);
        }
    }
    async fn client(&self) -> kasumi_client::KasumiRecoveryPool {
        self.client_with_credential(&self.control_token)
    }
    /// Commit a real Control Start and observe its initial durable phase before
    /// any target effect is dispatched. This positive point read does not claim
    /// that the target has initialized or the recovery has finished.
    pub async fn assert_protected_prepare_status(&self, configurations: &[RuntimeConfig]) {
        let request = self.request.as_ref().unwrap();
        let mut native = self.client().await;
        let expected = match native.start(request, Duration::from_secs(5)).await {
            Ok(record) => record,
            Err(_) => self.status(&mut native, "protected Start outcome").await,
        };
        assert_eq!(expected.request, *request);
        assert_eq!(expected.phase, RecoveryPhase::Prepare);
        assert!(expected.pending_phase.is_none());
        self.assert_protected_status_record(configurations, &expected)
            .await;
    }
    /// Drive installed Control/issuer/target services through one actual
    /// Start, discard its original reply, and resolve only its retained owner.
    pub async fn assert_initial_start_lost_reply_status(&self) {
        let request = self.request.as_ref().unwrap();
        let mut control = self.client().await;
        if control
            .start(request, Duration::from_secs(5))
            .await
            .is_err()
        {
            self.status(&mut control, "initial Start operation readback")
                .await;
        }
        tokio::time::timeout(Duration::from_secs(180), async {
            for _ in 0..64 {
                let before = self.status(&mut control, "initial Start progress").await;
                if let Some(phase_id) = before.pending_phase {
                    let phase = control.read_phase(&RecoveryPhaseRequest {
                        operation_id: request.operation_id, phase_id,
                    }, Duration::from_secs(5)).await.unwrap();
                    if let RecoveryDispatch::Target { node_id, request: original } = &phase.input
                        && matches!(original.step, TargetRuntimeStep::Start(TargetReplicaInput::Quorum(_))) {
                        let receiver = self.targets.iter().find(|target| target.node_id() == *node_id).unwrap();
                        receiver.test_lose_next_initial_start_reply();
                        assert!(self.step(&mut control).await.is_err(), "fixture must lose the real first Start reply");
                        let marked = control.read_phase(&RecoveryPhaseRequest {
                            operation_id: request.operation_id, phase_id,
                        }, Duration::from_secs(5)).await.unwrap();
                        assert!(marked.outcome.is_none());
                        let attempt = marked.effect_attempts.get(&RecoveryEffect::TargetCommand).unwrap();
                        let identity = TargetInitialDispatchIdentity {
                            operation_id: marked.operation_id, phase_id: marked.phase_id,
                            attempt_id: attempt.attempt_id, input_sha256: marked.input_sha256.clone(),
                        };
                        assert!(receiver.test_has_replica("acme", self.target).await,
                            "lost Start reply must retain the actual prebound Raft owner");
                        assert_eq!(receiver.test_initial_dispatch_status(&identity, original).unwrap(),
                            kasumi_engine::InitialDispatchStatus::AcceptedOnly);
                        assert_eq!(receiver.test_owned_custody_group("acme", self.target).await.unwrap(),
                            Some(Some(format!("acme/{}", self.target))));
                        let query = TargetInitialStartRequest {
                            target_incarnation: self.target, request: (**original).clone(), identity: identity.clone(),
                        };
                        let index = *node_id as usize - 1;
                        let connection = kasumi_client::KasumiClientConfig {
                            endpoint: format!("https://localhost:{}", self.native_addresses[index].port()),
                            identity: self.files[0].load().unwrap(),
                            trusted_ca_pem: read_bounded(&self.ca, 1 << 20).unwrap(),
                            server_certificate_pins: BTreeSet::from([self.files[index].load().unwrap().certificate_pin()]),
                        };
                        let mut target = kasumi_client::KasumiTargetClient::connect(&connection,
                            kasumi_serving::ControlTrust::install(self.root.clone()).unwrap(),
                            kasumi_serving::AuthorityTrust::install(self.manifest.clone()).unwrap(), *node_id,
                        ).await.unwrap();
                        let before_reads = receiver.test_marked_first_membership_reads();
                        let status = target.read_initial_start(&self.control_token, &query).await
                            .expect("lost Start reply must resolve over pinned mTLS while original child is live");
                        status.validate_for(&query, *node_id).unwrap();
                        assert!(receiver.test_marked_first_membership_reads() >= before_reads + 3,
                            "Start RPC must refresh Control at admission and both release fences");
                        let unauthorized_reads = receiver.test_marked_first_membership_reads();
                        assert!(target.read_initial_start(&self.source_token, &query).await.is_err());
                        assert_eq!(receiver.test_marked_first_membership_reads(), unauthorized_reads,
                            "source token must fail before Control reads");
                        let mut substituted = query.clone();
                        substituted.identity.attempt_id = Uuid::new_v4();
                        assert!(target.read_initial_start(&self.control_token, &substituted).await.is_err());
                        let history = TargetInitialMembershipHistoryRequest {
                            target_incarnation: self.target, request: (**original).clone(), identity: identity.clone(),
                        };
                        assert!(target.read_initial_membership_history(&self.control_token, &history).await.is_err(),
                            "owned Start is not committed/applied first membership");
                        let authenticator = self.authenticator(self.issuer_audits[0].clone()).await;
                        let context = authenticator.authenticate(&format!("Bearer {}", self.control_token)).await.unwrap();
                        let retry = receiver.execute(context, zeroize::Zeroizing::new(self.control_token.clone()),
                            TargetExecuteRequest { request: (**original).clone(), initial_dispatch: Some(identity.clone()) },
                        ).await;
                        let error = retry.err().expect("replayed Execute must not issue another child");
                        assert!(format!("{error:#}").contains("status-only"), "{error:#}");

                        // The next coordinator attempt consumes the protected
                        // status. The committed attempt ID remains unchanged.
                        self.step(&mut control).await.expect("coordinator must resolve retained Start without Execute");
                        let resolved = control.read_phase(&RecoveryPhaseRequest {
                            operation_id: request.operation_id, phase_id,
                        }, Duration::from_secs(5)).await.unwrap();
                        assert_eq!(resolved.effect_attempts, marked.effect_attempts);
                        assert!(matches!(resolved.outcome, Some(RecoveryDispatchOutcome::Target(ref response))
                            if matches!(response.outcome, TargetRuntimeOutcome::Started { .. })));
                        assert!(resolved.resolved_revision.is_some());
                        assert!(target.read_initial_start(&self.control_token, &query).await.is_err(),
                            "resolved Control phase cannot be normalized into current Start authority");
                        assert!(receiver.test_has_replica("acme", self.target).await);
                        for other in self.targets.iter().filter(|other| other.node_id() != *node_id) {
                            assert!(!other.test_has_replica("acme", self.target).await,
                                "status continuation must not construct another target child");
                        }
                        self.assert_initialize_lost_reply_status(&mut control).await;
                        return;
                    }
                }
                let _ = self.step(&mut control).await;
            }
            panic!("initial Start was not reached in 64 exact phases");
        }).await.expect("installed lost-Start fixture exceeded its deadline");
    }
    async fn assert_initialize_lost_reply_status(
        &self,
        control: &mut kasumi_client::KasumiRecoveryPool,
    ) {
        let operation = self.request.as_ref().unwrap().operation_id;
        for _ in 0..16 {
            let before = self.status(control, "Initialize progress").await;
            if let Some(phase_id) = before.pending_phase {
                let phase = control
                    .read_phase(
                        &RecoveryPhaseRequest {
                            operation_id: operation,
                            phase_id,
                        },
                        Duration::from_secs(5),
                    )
                    .await
                    .unwrap();
                if let RecoveryDispatch::Target { node_id, request } = &phase.input
                    && matches!(request.step, TargetRuntimeStep::Initialize(_))
                {
                    let receiver = self
                        .targets
                        .iter()
                        .find(|target| target.node_id() == *node_id)
                        .unwrap();
                    let original_start = receiver
                        .test_owned_start_identity("acme", self.target)
                        .await
                        .unwrap();
                    for target in &self.targets {
                        assert!(
                            target.test_has_replica("acme", self.target).await,
                            "all original voters must be owned before Initialize"
                        );
                    }
                    receiver.test_lose_next_initialize_reply();
                    assert!(
                        self.step(control).await.is_err(),
                        "fixture must discard actual Initialize reply"
                    );
                    let marked = control
                        .read_phase(
                            &RecoveryPhaseRequest {
                                operation_id: operation,
                                phase_id,
                            },
                            Duration::from_secs(5),
                        )
                        .await
                        .unwrap();
                    assert!(marked.outcome.is_none());
                    let attempt = marked
                        .effect_attempts
                        .get(&RecoveryEffect::TargetCommand)
                        .unwrap();
                    let identity = TargetInitialDispatchIdentity {
                        operation_id: operation,
                        phase_id,
                        attempt_id: attempt.attempt_id,
                        input_sha256: marked.input_sha256.clone(),
                    };
                    assert_eq!(identity.operation_id, original_start.operation_id);
                    assert_ne!(identity.phase_id, original_start.phase_id);
                    assert_ne!(identity.attempt_id, original_start.attempt_id);
                    assert_eq!(
                        receiver
                            .test_owned_start_identity("acme", self.target)
                            .await
                            .unwrap(),
                        original_start,
                        "Initialize must preserve original Start prebind"
                    );
                    let index = *node_id as usize - 1;
                    let connection = kasumi_client::KasumiClientConfig {
                        endpoint: format!(
                            "https://localhost:{}",
                            self.native_addresses[index].port()
                        ),
                        identity: self.files[0].load().unwrap(),
                        trusted_ca_pem: read_bounded(&self.ca, 1 << 20).unwrap(),
                        server_certificate_pins: BTreeSet::from([self.files[index]
                            .load()
                            .unwrap()
                            .certificate_pin()]),
                    };
                    let mut target = kasumi_client::KasumiTargetClient::connect(
                        &connection,
                        kasumi_serving::ControlTrust::install(self.root.clone()).unwrap(),
                        kasumi_serving::AuthorityTrust::install(self.manifest.clone()).unwrap(),
                        *node_id,
                    )
                    .await
                    .unwrap();
                    let query = TargetInitialMembershipHistoryRequest {
                        target_incarnation: self.target,
                        request: (**request).clone(),
                        identity: identity.clone(),
                    };
                    let reads = receiver.test_marked_first_membership_reads();
                    let status = target
                        .read_initial_membership_history(&self.control_token, &query)
                        .await
                        .expect(
                            "lost Initialize reply must prove real committed/applied membership",
                        );
                    status.validate_for(&query).unwrap();
                    assert!(receiver.test_marked_first_membership_reads() >= reads + 3);
                    assert!(
                        target
                            .read_initial_membership_history(&self.source_token, &query)
                            .await
                            .is_err()
                    );
                    let mut substituted = query.clone();
                    substituted.identity.attempt_id = Uuid::new_v4();
                    assert!(
                        target
                            .read_initial_membership_history(&self.control_token, &substituted)
                            .await
                            .is_err()
                    );
                    let start_query = TargetInitialStartRequest {
                        target_incarnation: self.target,
                        request: (**request).clone(),
                        identity: identity.clone(),
                    };
                    assert!(
                        target
                            .read_initial_start(&self.control_token, &start_query)
                            .await
                            .is_err()
                    );
                    let authenticator = self.authenticator(self.issuer_audits[0].clone()).await;
                    let context = authenticator
                        .authenticate(&format!("Bearer {}", self.control_token))
                        .await
                        .unwrap();
                    let retry = receiver
                        .execute(
                            context,
                            zeroize::Zeroizing::new(self.control_token.clone()),
                            TargetExecuteRequest {
                                request: (**request).clone(),
                                initial_dispatch: Some(identity.clone()),
                            },
                        )
                        .await;
                    let error = retry
                        .err()
                        .expect("accepted Initialize Execute must remain one use");
                    assert!(format!("{error:#}").contains("status-only"), "{error:#}");
                    self.step(control).await.expect(
                        "coordinator must resolve Initialize from exact retained membership",
                    );
                    let resolved = control
                        .read_phase(
                            &RecoveryPhaseRequest {
                                operation_id: operation,
                                phase_id,
                            },
                            Duration::from_secs(5),
                        )
                        .await
                        .unwrap();
                    assert_eq!(resolved.effect_attempts, marked.effect_attempts);
                    assert!(
                        matches!(resolved.outcome, Some(RecoveryDispatchOutcome::Target(ref response))
                        if matches!(response.outcome, TargetRuntimeOutcome::Initialized { .. }))
                    );
                    assert!(resolved.resolved_revision.is_some());
                    assert!(
                        target
                            .read_initial_membership_history(&self.control_token, &query)
                            .await
                            .is_err(),
                        "resolved Initialize phase is not new authority"
                    );
                    return;
                }
            }
            let _ = self.step(control).await;
        }
        panic!("Initialize was not reached in 16 exact phases");
    }
    /// Query the actual NodeRuntime protected listener after the same operation
    /// has reached a durable terminal phase through the native coordinator.
    pub async fn assert_protected_status(&self, configurations: &[RuntimeConfig]) {
        let mut native = self.client().await;
        let expected = self.status(&mut native, "protected terminal phase").await;
        assert_eq!(expected.phase, RecoveryPhase::Finished);
        self.assert_protected_status_record(configurations, &expected)
            .await;
    }
    async fn assert_protected_status_record(
        &self,
        configurations: &[RuntimeConfig],
        expected: &RecoveryRecord,
    ) {
        let operation_id = self.request.as_ref().unwrap().operation_id;
        let controls = self
            .control_observers
            .iter()
            .map(|owner| owner.upgrade().expect("live installed Control owner"))
            .collect::<Vec<_>>();
        assert_eq!(controls.len(), configurations.len());
        // The recovery fixture deliberately fails over Control after Start.
        // The saved dispatch node is not necessarily the current read leader.
        let index = quorum_ready_leader(&controls, "protected recovery status").await;
        assert_eq!(
            controls[index].raft_group().raft().metrics().borrow().id as usize,
            index + 1
        );
        drop(controls);
        let endpoint = format!(
            "https://localhost:{}/recovery/{operation_id}",
            configurations[index].admin.listen.port()
        );
        let absent = format!(
            "https://localhost:{}/recovery/{}",
            configurations[index].admin.listen.port(),
            Uuid::new_v4()
        );
        let mut identity = read_bounded(&self.files[0].certificate, 1 << 20).unwrap();
        identity
            .extend_from_slice(&private_files::read(&self.files[0].private_key, 1 << 20).unwrap());
        let client = reqwest::Client::builder()
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .max_tls_version(reqwest::tls::Version::TLS_1_3)
            .tls_built_in_root_certs(false)
            .add_root_certificate(
                reqwest::Certificate::from_pem(&read_bounded(&self.ca, 1 << 20).unwrap()).unwrap(),
            )
            .identity(reqwest::Identity::from_pem(&identity).unwrap())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(25))
            .build()
            .unwrap();
        let response = client
            .get(&endpoint)
            .bearer_auth(&self.control_token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let value: serde_json::Value = response.json().await.unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        assert_eq!(value["operation_id"], operation_id.to_string());
        assert_eq!(
            value["phase"],
            serde_json::to_value(expected.phase).unwrap()
        );
        assert_eq!(value["updated_revision"], expected.updated_revision);
        assert_eq!(value["phase_pending"], expected.pending_phase.is_some());
        assert_eq!(value["terminal"], expected.phase.terminal());
        let missing = client
            .get(&absent)
            .bearer_auth(&self.control_token)
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status().as_u16(), 404);
        assert_eq!(missing.headers()["cache-control"], "no-store");
        assert_eq!(
            missing.text().await.unwrap(),
            "protected node observation unavailable\n"
        );
    }
    fn client_with_credential(&self, token: &str) -> kasumi_client::KasumiRecoveryPool {
        let installed = self.target_configs[0].target_recovery.as_ref().unwrap();
        let token = zeroize::Zeroizing::new(token.to_owned());
        kasumi_client::KasumiRecoveryPool::new(
            installed.control_connections().unwrap(),
            Arc::new(move || Ok(token.clone())),
        )
        .unwrap()
    }
    fn control_failure_context(&self) -> String {
        let controls = self
            .control_observers
            .iter()
            .take(3)
            .map(recovery_database_progress)
            .collect::<Vec<_>>();
        format!(
            "dispatch_node={} controls={controls:?} source={}",
            self.control_dispatch_node,
            recovery_database_progress(&self.source_observer)
        )
    }
    async fn status(
        &self,
        client: &mut kasumi_client::KasumiRecoveryPool,
        context: &str,
    ) -> RecoveryRecord {
        client
            .status(
                &RecoveryStatusRequest {
                    operation_id: self.request.as_ref().unwrap().operation_id,
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "Control recovery status read failed: {}; {context}; {}",
                    recovery_step_error(&error),
                    self.control_failure_context()
                )
            })
    }
    async fn step(
        &self,
        client: &mut kasumi_client::KasumiRecoveryPool,
    ) -> std::result::Result<RecoveryRecord, kasumi_client::ClientError> {
        client
            .resume(
                &RecoveryResume {
                    operation_id: self.request.as_ref().unwrap().operation_id,
                    max_steps: 1,
                },
                Duration::from_secs(60),
            )
            .await
    }
    async fn assert_control_member_failover(
        &self,
        client: &mut kasumi_client::KasumiRecoveryPool,
        networks: &[Arc<ClusterNetwork>],
    ) {
        let controls = self
            .control_observers
            .iter()
            .map(|weak| weak.upgrade().expect("live Control owner"))
            .collect::<Vec<_>>();
        assert_eq!(controls.len(), 3);
        let leader =
            quorum_ready_leader(&controls, "Control before installed-member failover").await;
        let group = format!("__kasumi_control/{}", self.root.control_incarnation);
        networks[leader]
            .set_test_group_isolated(&group, true)
            .unwrap();
        // OpenRaft waits for the old leader lease and its randomized election
        // timeout. Require an actual, linearizable replacement among the two
        // survivors before starting the original five-second client deadline.
        let survivors = controls
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != leader)
            .map(|(_, database)| Arc::clone(database))
            .collect::<Vec<_>>();
        let replacement =
            quorum_ready_leader(&survivors, "Control after installed-member isolation").await;
        let replacement_node = survivors[replacement]
            .raft_group()
            .raft()
            .metrics()
            .borrow()
            .id;
        let original = self.request.as_ref().unwrap();
        let observed = client
            .status(
                &RecoveryStatusRequest {
                    operation_id: original.operation_id,
                },
                Duration::from_secs(5),
            )
            .await;
        networks[leader]
            .set_test_group_isolated(&group, false)
            .unwrap();
        let observed = observed.unwrap_or_else(|error| {
            panic!(
                "installed Control quorum must remain readable after replacement election: {}; replacement node={replacement_node}; {}",
                recovery_step_error(&error),
                self.control_failure_context()
            )
        });
        assert_eq!(observed.request, *original);
        // Physical owners remain with the fixture. Release these observations before target draining.
        drop(survivors);
        drop(controls);
    }
    pub async fn recover(&self, networks: &[Arc<ClusterNetwork>]) {
        let request = self.request.as_ref().unwrap();
        let mut client = self.client().await;
        // Independently bound source and target credentials cannot administer Control.
        assert!(
            self.client_with_credential(&self.source_token)
                .start(request, Duration::from_secs(5))
                .await
                .is_err()
        );
        assert!(
            self.client_with_credential(&self.target_token)
                .start(request, Duration::from_secs(5))
                .await
                .is_err()
        );
        let started = client.start(request, Duration::from_secs(5)).await.unwrap();
        assert_eq!(started.request, *request);
        assert_eq!(
            client
                .start(request, Duration::from_secs(5))
                .await
                .unwrap()
                .request,
            *request
        );
        self.assert_control_member_failover(&mut client, networks)
            .await;
        let mut observed_one_materialization = false;
        let mut isolated = false;
        let mut restored = false;
        let mut progress = std::collections::VecDeque::with_capacity(8);
        let mut dispatches = std::collections::VecDeque::with_capacity(8);
        let mut last_pending = None;
        let mut last_step = String::from("not dispatched");
        let mut steps = 0_u64;
        let completed = tokio::time::timeout(Duration::from_secs(240), async {
            loop {
                let context = format!("stage=progress materialized_one={observed_one_materialization} isolated={isolated} restored={restored} steps={steps}; last_step={last_step}; last_eight_heads={progress:?}");
                let before = self.status(&mut client, &context).await;
                last_pending = before.pending_phase;
                let observation = recovery_progress(&before);
                if progress.back() != Some(&observation) {
                    if progress.len() == 8 { progress.pop_front(); }
                    progress.push_back(observation);
                }
                let prepared_count = before
                    .voters
                    .values()
                    .filter(|voter| voter.materialization.is_some())
                    .count();
                if prepared_count == 1 {
                    observed_one_materialization = true;
                    assert_eq!(before.phase, RecoveryPhase::Materialize);
                    assert!(
                        before.initialization.is_none(),
                        "a single prepared target cannot initialize the group"
                    );
                }
                if before.initialization.is_some() {
                    assert_eq!(prepared_count, 3);
                }
                if before.phase == RecoveryPhase::Complete && !isolated {
                    let mut databases = Vec::new();
                    for target in &self.targets {
                        if let Some(database) =
                            target.test_owned_database("acme", self.target).await
                        {
                            databases.push(database);
                        }
                    }
                    if databases.len() == 3 {
                        let leader = quorum_ready_leader(
                            &databases,
                            "canonical target before completion isolation",
                        )
                        .await;
                        let pending = databases
                            .iter()
                            .map(|db| {
                                db.engine()
                                    .generation()
                                    .unwrap()
                                    .state
                                    .pending_restore
                                    .clone()
                            })
                            .collect::<Vec<_>>();
                        assert!(pending.iter().all(Option::is_some));
                        let mut drained = Vec::new();
                        for target in &self.targets {
                            drained.push(target.test_restore_drain_observer("acme", self.target)
                                .await.expect("existing target drain observer"));
                        }
                        let group = format!("acme/{}", self.target);
                        // Completion preparation drains and reopens actual target
                        // owners. Keep this transport partition across route changes.
                        for network in networks {
                            network.set_test_group_isolated(&group, true).unwrap();
                        }
                        let error = databases[leader]
                            .raft_group()
                            .raft()
                            .ensure_linearizable()
                            .await
                            .unwrap_err();
                        assert!(
                            error.api_error().is_some(),
                            "isolation became a fatal storage error: {error:?}"
                        );
                        // Phase transitions drain their actual owners. The test
                        // must release these borrowed Arcs before dispatching one.
                        drop(databases);
                        // An uncertain target dispatch may return an error or a
                        // committed retry admission. Retain the original unresolved
                        // phase in either case, never the newly prepared successor.
                        let (failed, pending_id, phase) = tokio::time::timeout(Duration::from_secs(45), async {
                            loop {
                                let context = format!("stage=isolated-before-dispatch steps={steps}; last_step={last_step}; last_eight_heads={progress:?}");
                                let before_dispatch = self.status(&mut client, &context).await;
                                let response = self.step(&mut client).await;
                                let outcome = match &response {
                                    Ok(record) => recovery_progress(record),
                                    Err(error) => recovery_step_error(error),
                                };
                                let context = format!("stage=isolated-after-dispatch before={}; response={outcome}; last_eight_heads={progress:?}", recovery_progress(&before_dispatch));
                                let after_dispatch = self.status(&mut client, &context).await;
                                if let Some(original_id) = before_dispatch.pending_phase {
                                    let original = client.read_phase(

                                        &RecoveryPhaseRequest {
                                            operation_id: request.operation_id,
                                            phase_id: original_id,
                                        }, Duration::from_secs(5)).await.unwrap();
                                    if original.outcome.is_none()
                                        && (response.is_err()
                                            || after_dispatch.pending_phase != Some(original_id))
                                    {
                                        assert!(matches!(original.input, RecoveryDispatch::Target { .. }));
                                        break (after_dispatch, original_id, original);
                                    }
                                }
                            }
                        })
                        .await
                        .unwrap();
                        assert_eq!(failed.phase, RecoveryPhase::Complete);
                        assert!(failed.completion.is_none());
                        assert!(phase.outcome.is_none());
                        assert!(matches!(phase.input, RecoveryDispatch::Target { .. }));
                        for ((target, expected), drained) in self.targets.iter().zip(&pending).zip(&drained) {
                            let observed = if let Some(database) = target.test_owned_database("acme", self.target).await {
                                if let Err(error) = database.engine().generation() {
                                    assert_eq!(error.code, kasumi_types::ErrorCode::Sealed);
                                }
                                database.engine().fixture_pending_restore()
                                    .or_else(|_| database.engine().fixture_pending_restore_at_seal())
                                    .expect("actual owned target marker")
                            } else {
                                // The target can remove its fully drained generation.
                                // This observer retains only metadata captured under
                                // the actual engine seal fence, never physical owners.
                                drained.marker().expect("actual removed target seal marker")
                            };
                            assert_eq!(serde_json::to_value(&observed).unwrap(),
                                serde_json::to_value(expected).unwrap());
                        }
                        for network in networks {
                            network.set_test_group_isolated(&group, false).unwrap();
                        }
                        assert_eq!(
                            client
                                .read_phase(

                                    &RecoveryPhaseRequest {
                                        operation_id: request.operation_id,
                                        phase_id: pending_id
                                    }, Duration::from_secs(5))
                                .await
                                .unwrap(),
                            phase
                        );
                        isolated = true;
                    }
                }
                if before.phase == RecoveryPhase::Finished {
                    assert!(before.retirement.is_some());
                    assert!(before.source_fence.is_some());
                    assert!(before.activation.is_some());
                    assert!(before.route_publication.is_some());
                    assert!(before.voters.values().all(|v| v.confirmation.is_some()));
                    restored = true;
                    break;
                }
                steps = steps.saturating_add(1);
                last_step = "dispatch pending".into();
                last_step = match self.step(&mut client).await {
                    Ok(record) => recovery_progress(&record),
                    Err(error) => recovery_step_error(&error),
                };
                if dispatches.len() == 8 {
                    dispatches.pop_front();
                }
                dispatches.push_back(last_step.clone());
            }
        })
        .await;
        if let Err(error) = completed {
            // The original 240-second success deadline has already failed.
            // A bounded immutable point read diagnoses that failed attempt;
            // its result can never change failure into success.
            let pending = if let Some(phase_id) = last_pending {
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    client.read_phase(
                        &RecoveryPhaseRequest {
                            operation_id: request.operation_id,
                            phase_id,
                        },
                        Duration::from_secs(5),
                    ),
                )
                .await
                {
                    Ok(Ok(phase)) => match &phase.input {
                        RecoveryDispatch::Target { node_id, request } => format!(
                            "phase={phase_id} sequence={} node={node_id} step={} original_deadline={} outcome={}",
                            phase.sequence,
                            recovery_target_step(&request.step),
                            request.not_after_ms,
                            phase.outcome.is_some()
                        ),
                        _ => format!(
                            "phase={phase_id} sequence={} control_phase={:?} non_target=true outcome={}",
                            phase.sequence,
                            phase.phase,
                            phase.outcome.is_some()
                        ),
                    },
                    Ok(Err(error)) => recovery_step_error(&error),
                    Err(_) => "pending phase diagnostic read elapsed".into(),
                }
            } else {
                "no pending phase in last observed head".into()
            };
            panic!(
                "recovery success deadline elapsed: {error:?}; materialized_one={observed_one_materialization} isolated={isolated} restored={restored} steps={steps}; last_step={last_step}; pending={pending}; last_eight_heads={progress:?}; last_eight_dispatches={dispatches:?}; {}",
                self.control_failure_context()
            );
        }
        assert!(observed_one_materialization && isolated && restored);
    }
    pub async fn databases(&self) -> Vec<Arc<kasumi_engine::Database>> {
        let mut databases = Vec::new();
        for target in &self.targets {
            databases.push(
                target
                    .test_owned_database("acme", self.target)
                    .await
                    .unwrap(),
            );
        }
        databases
    }
    pub async fn close_targets(&mut self) {
        for stop in &self.target_stops {
            stop.send_replace(true);
        }
        for task in self.target_tasks.drain(..) {
            tokio::time::timeout(Duration::from_secs(15), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        self.target_stops.clear();
        for target in &self.targets {
            target.shutdown().await.unwrap();
        }
        self.targets.clear();
        for stop in self.control_stops.drain(..) {
            stop.send_replace(true);
        }
        for task in self.control_tasks.drain(..) {
            tokio::time::timeout(Duration::from_secs(15), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }
    pub async fn reopen_targets(&mut self, handles: &[Handles]) {
        // Activated ordinary serving uses the retained journal projection and a
        // fresh issuer boot. Reopening never creates another target activation.
        let mut sockets = Vec::new();
        for address in &self.native_addresses {
            sockets.push(TcpListener::bind(address).await.unwrap());
        }
        self.open_targets(handles, sockets).await;
    }
    pub async fn shutdown_issuer(&mut self) {
        self.close_targets().await;
        for stop in &self.issuer_stops {
            stop.send_replace(true);
        }
        for task in self.issuer_tasks.drain(..) {
            tokio::time::timeout(Duration::from_secs(15), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        for network in &self.issuer_networks {
            network.unregister_group("runtime-issuer").unwrap();
        }
        for issuer in &self.issuers {
            issuer.shutdown().await.unwrap();
        }
        self.issuers.clear();
        self.issuer_networks.clear();
        for audit in &self.issuer_audits {
            audit.admission().drain_snapshot_startups().await.unwrap();
        }
        for stores in self.issuer_stores.drain(..) {
            stores.shutdown().await.unwrap();
        }
        for audit in self.issuer_audits.drain(..) {
            audit.shutdown().await.unwrap();
        }
        for node in self.issuer_nodes.drain(..) {
            node.shutdown().await.unwrap();
        }
    }
}
