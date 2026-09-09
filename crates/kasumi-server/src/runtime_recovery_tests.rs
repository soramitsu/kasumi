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
    control_stop: Option<watch::Sender<bool>>,
    control_task: Option<tokio::task::JoinHandle<Result<()>>>,
    request: Option<RecoveryStart>,
}
impl Fixture {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        directory: &std::path::Path,
        credentials: Credentials,
        files: &[TlsFiles],
        ca: PathBuf,
        source: Uuid,
        control: Uuid,
        kms: &str,
        kms_certificate: &std::path::Path,
    ) -> Self {
        let directory = directory.join("canonical-recovery");
        private_files::create_directory(&directory).unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let root = ControlSigningRoot {
            control_incarnation: control,
            public_key: hex::encode(key.public_key_raw()),
        };
        private_files::publish(&directory.join("control.pk8"), &key.serialize_der()).unwrap();
        let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let signing_root =
            kasumi_serving::test_utils::FixtureSigningRoot::from_pkcs8(&issuer_key.serialize_der())
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
        let mut issuer_networks = Vec::new();
        let mut issuer_stops = Vec::new();
        let mut issuer_tasks = Vec::new();
        for (index, socket) in sockets.into_iter().enumerate() {
            let id = (index + 1) as u64;
            let stores = TenantStorageSet::initialize_catalogs(
                NodeStore::create_new(
                    directory.join(format!("issuer-{id}.redb")),
                    Uuid::new_v4(),
                    kasumi_store::ScratchDisk::fixture(),
                )
                .unwrap(),
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
            network.install_audit(Arc::new(FixtureAudit)).unwrap();
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
            authenticator.install_audit(Arc::new(FixtureAudit)).unwrap();
            let router = network.router().merge(
                tonic::service::Routes::new(
                    crate::rpc::NativeAuthority::new(authority.clone(), authenticator).service(),
                )
                .into_axum_router(),
            );
            let (stop, stopped) = watch::channel(false);
            issuer_tasks.push(tokio::spawn(tls::serve_tls(
                socket,
                network.server_tls(),
                router,
                ListenerLimits::default(),
                Arc::new(FixtureAudit),
                stopped,
            )));
            issuer_stops.push(stop);
            issuer_networks.push(network);
            issuer_stores.push(stores);
            issuers.push(authority);
        }
        issuers[0].initialize().await.unwrap();
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
            control_stop: None,
            control_task: None,
            request: None,
        };
        result.enroll_tenant("acme", source).await;
        result
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
            identity: self.verifier_ids[index].clone(),
            database_path: self
                .directory
                .join(format!("verifier-{}/trust.redb", index + 1)),
            keys,
        };
        crate::signer_runtime::InitializeSignerVerifier {
            scratch_disk: config.scratch_disk.clone(),
            verifier: verifier.clone(),
            initial_certificates: vec![self.signing.signer.certificate().clone()],
        }
        .initialize()
        .await
        .unwrap();
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
        auth.install_audit(Arc::new(FixtureAudit)).unwrap();
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
    pub async fn install_targets(
        &mut self,
        configurations: &[RuntimeConfig],
        handles: &[Handles],
        controls: &[Arc<kasumi_engine::Database>],
        source: &Arc<kasumi_engine::Database>,
        checkpoint: FullBackupCheckpoint,
    ) {
        let control_leader = quorum_ready_leader(controls, "canonical Control dispatch").await;
        let source_leader = source.raft_group().raft().metrics().borrow().id as usize - 1;
        let control_socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_address = control_socket.local_addr().unwrap();
        let control_endpoint = format!("https://localhost:{}", control_address.port());
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
                control_endpoint: AuthorityEndpoint {
                    endpoint: control_endpoint.clone(),
                    certificate_pins: BTreeSet::from([hex::encode(
                        self.files[control_leader].load().unwrap().certificate_pin(),
                    )]),
                },
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
                    .join(format!("target-journal-{}.redb", index + 1)),
                journal_keys: target_key("journal"),
                generation_root: self
                    .directory
                    .join(format!("target-generations-{}", index + 1)),
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
            crate::target_journal_installation::initialize(config.clone())
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
            source: Some(self.admin(
                format!(
                    "https://localhost:{}",
                    configurations[source_leader].admin.listen.port()
                ),
                source_leader,
                "source.jwt",
            )),
            source_custody: Some(self.admin(
                format!(
                    "https://localhost:{}",
                    configurations[source_leader].admin.listen.port()
                ),
                source_leader,
                "custody.jwt",
            )),
        };
        let mut coordinator_config = configurations[control_leader].clone();
        coordinator_config
            .control
            .lifecycle
            .as_mut()
            .unwrap()
            .recovery = Some(RecoveryRuntimeConfig {
            routes: BTreeMap::from([("planned".into(), route.clone())]),
        });
        self.request = Some(RecoveryStart {
            operation_id: Uuid::new_v4(),
            tenant: "acme".into(),
            source_incarnation: self.source,
            source_authority_epoch: source.engine().generation().unwrap().state.authority_epoch,
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
                .digest(&coordinator_config.serving_authorities["issuer"])
                .unwrap(),
            target_nodes: nodes,
            materialization,
            phase_timeout_ms: 60_000,
        });
        self.start_control(
            control_socket,
            coordinator_config,
            controls[control_leader].clone(),
            &handles[control_leader],
            control_leader,
        )
        .await;
        self.open_targets(handles, sockets).await;
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
        self.control_task = Some(tokio::spawn(tls::serve_tls(
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
        self.control_stop = Some(stop);
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
                    .map(|(alias, destination)| (alias.clone(), destination.open().unwrap()))
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
    async fn client(&self) -> kasumi_client::KasumiRecoveryClient {
        let installed = self.target_configs[0].target_recovery.as_ref().unwrap();
        kasumi_client::KasumiRecoveryClient::connect(&installed.control_connection().unwrap())
            .await
            .unwrap()
    }
    async fn status(&self, client: &mut kasumi_client::KasumiRecoveryClient) -> RecoveryRecord {
        client
            .status(
                &self.control_token,
                &RecoveryStatusRequest {
                    operation_id: self.request.as_ref().unwrap().operation_id,
                },
            )
            .await
            .unwrap()
    }
    async fn step(
        &self,
        client: &mut kasumi_client::KasumiRecoveryClient,
    ) -> std::result::Result<RecoveryRecord, kasumi_client::ClientError> {
        client
            .resume(
                &self.control_token,
                &RecoveryResume {
                    operation_id: self.request.as_ref().unwrap().operation_id,
                    max_steps: 1,
                },
            )
            .await
    }
    pub async fn recover(&self, networks: &[Arc<ClusterNetwork>]) {
        let request = self.request.as_ref().unwrap();
        let mut client = self.client().await;
        // Independently bound source and target credentials cannot administer Control.
        assert!(client.start(&self.source_token, request).await.is_err());
        assert!(client.start(&self.target_token, request).await.is_err());
        let started = client.start(&self.control_token, request).await.unwrap();
        assert_eq!(started.request, *request);
        assert_eq!(
            client
                .start(&self.control_token, request)
                .await
                .unwrap()
                .request,
            *request
        );
        let mut observed_one_materialization = false;
        let mut isolated = false;
        let mut restored = false;
        tokio::time::timeout(Duration::from_secs(240), async {
            loop {
                let before = self.status(&mut client).await;
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
                        let group = format!("acme/{}", self.target);
                        for (index, network) in networks.iter().enumerate() {
                            network
                                .set_group_allowed_peers(&group, BTreeSet::from([index as u64 + 1]))
                                .unwrap();
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
                        // Prepare/observe operations may still succeed. Dispatch until
                        // an actual target operation fails, then retain its exact ID.
                        let failed = tokio::time::timeout(Duration::from_secs(45), async {
                            loop {
                                if self.step(&mut client).await.is_err() {
                                    break self.status(&mut client).await;
                                }
                            }
                        })
                        .await
                        .unwrap();
                        assert_eq!(failed.phase, RecoveryPhase::Complete);
                        assert!(failed.completion.is_none());
                        let pending_id = failed
                            .pending_phase
                            .expect("failed dispatch must retain its prepared identity");
                        let phase = client
                            .read_phase(
                                &self.control_token,
                                &RecoveryPhaseRequest {
                                    operation_id: request.operation_id,
                                    phase_id: pending_id,
                                },
                            )
                            .await
                            .unwrap();
                        assert!(phase.outcome.is_none());
                        assert!(matches!(phase.input, RecoveryDispatch::Target { .. }));
                        for (target, expected) in self.targets.iter().zip(&pending) {
                            let database = target
                                .test_owned_database("acme", self.target)
                                .await
                                .expect("failed quorum operation lost its retained target owner");
                            assert_eq!(
                                database
                                    .engine()
                                    .generation()
                                    .unwrap()
                                    .state
                                    .pending_restore,
                                *expected
                            );
                        }
                        for network in networks {
                            network
                                .set_group_allowed_peers(&group, BTreeSet::from([1, 2, 3]))
                                .unwrap();
                        }
                        assert_eq!(
                            client
                                .read_phase(
                                    &self.control_token,
                                    &RecoveryPhaseRequest {
                                        operation_id: request.operation_id,
                                        phase_id: pending_id
                                    }
                                )
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
                let _ = self.step(&mut client).await;
            }
        })
        .await
        .unwrap();
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
        if let Some(stop) = self.control_stop.take() {
            stop.send_replace(true);
        }
        if let Some(task) = self.control_task.take() {
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
        for stores in self.issuer_stores.drain(..) {
            stores.application().shutdown().await;
            stores.custody().store().shutdown().await;
        }
    }
}
