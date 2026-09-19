use super::*;
use crate::{
    auth::{AuthConfig, AuthKeySource},
    runtime::{
        KeyProviderSettings, MutualTlsEndpoint, ReplicaConfig, ReplicationConfig,
        SecurityAuditConfig, TlsFiles,
    },
    signer_runtime::{InitializeSignerVerifier, OperationalSignerConfig, SignerVerifierConfig},
};
use kasumi_serving::{
    AuthorityCapacity, AuthorityManifest, AuthorityMember, AuthorityMembership, AuthorityPartition,
    InstallationSigningRoot, TrustVerifierIdentity,
};
use kasumi_store::{NodeStore, ScratchDisk, TenantStore, private_files};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::{Condvar, Mutex, OnceLock},
    task::Poll,
    time::Duration,
};
use tokio::sync::Notify;
use uuid::Uuid;

struct Fixture {
    _directory: tempfile::TempDir,
    config: AuthorityRuntimeConfig,
}
impl Fixture {
    async fn new() -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        let keys = |name: &str| -> Result<KeyProviderSettings> {
            let path = root.join(format!("{name}.json"));
            kasumi_store::FileKeyProvider::initialize(&path, name)?;
            Ok(KeyProviderSettings::File { path })
        };
        let mut parameters = rcgen::CertificateParams::new(vec!["localhost".into()])?;
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
        ];
        parameters.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = rcgen::KeyPair::generate()?;
        let certificate = parameters.self_signed(&key)?;
        let tls = TlsFiles {
            certificate: root.join("tls.pem"),
            private_key: root.join("tls.key"),
        };
        private_files::create(&tls.certificate, certificate.pem().as_bytes())?;
        private_files::create(&tls.private_key, key.serialize_pem().as_bytes())?;
        let pin = hex::encode(tls.load()?.certificate_pin());
        let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let manifest = AuthorityManifest {
            authority_id: Uuid::new_v4(),
            partitions: BTreeMap::from([(
                0,
                AuthorityPartition {
                    group: "authority-0".into(),
                    public_key: hex::encode(root_key.public_key_raw()),
                },
            )]),
            lifecycle_controls: BTreeMap::new(),
            max_lease_ms: 1000,
            clock_rate_error_ppm: 0,
        };
        let signer = InstallationSigningRoot::from_pkcs8(
            manifest.signing_domain(0)?,
            &root_key.serialize_der(),
        )?;
        let operational_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let operational = OperationalSignerConfig {
            certificate: signer.certify(1, hex::encode(operational_key.public_key_raw()))?,
            key_file: root.join("operational.pk8"),
        };
        private_files::create(&operational.key_file, &operational_key.serialize_der())?;
        let operational_signer_file = root.join("operational.json");
        private_files::create(&operational_signer_file, &serde_json::to_vec(&operational)?)?;
        let installed_verifiers: BTreeMap<_, _> = (1..=3)
            .map(|node_id| {
                (
                    node_id,
                    TrustVerifierIdentity {
                        installation_id: Uuid::new_v4(),
                        node_id,
                    },
                )
            })
            .collect();
        let peers: Vec<_> = (1..=3)
            .map(|node_id| ReplicaConfig {
                node_id,
                endpoint: format!("https://localhost:{}", 49542 + node_id),
                failure_domain: format!("authority-zone-{node_id}"),
                certificate_pins: vec![if node_id == 1 {
                    pin.clone()
                } else {
                    format!("{node_id:064x}")
                }],
            })
            .collect();
        let scratch_disk = kasumi_store::ScratchDiskConfig {
            directory: root.join("scratch"),
            max_bytes: 64 << 20,
            min_free_bytes: 0,
        };
        let signer_verifier = SignerVerifierConfig {
            identity: installed_verifiers[&1].clone(),
            database_path: root.join("verifier.redb"),
            keys: keys("verifier")?,
            max_background_workers: 64,
        };
        InitializeSignerVerifier {
            admission: Default::default(),
            scratch_disk: scratch_disk.clone(),
            verifier: signer_verifier.clone(),
            initial_certificates: vec![operational.certificate.clone()],
        }
        .initialize()
        .await?;
        let config = AuthorityRuntimeConfig {
            installation: kasumi_authority::AuthorityInstallation {
                manifest,
                partition: 0,
            },
            bootstrap: kasumi_authority::AuthorityBootstrap {
                initial_signer_certificate: operational.certificate,
                administrators: BTreeSet::from(["operator".into()]),
                capacity: AuthorityCapacity {
                    max_tenants: 100,
                    max_state_bytes: 64 << 20,
                    maintenance_reserve_bytes: 1 << 20,
                },
                membership: AuthorityMembership {
                    voters: BTreeSet::from([1, 2, 3]),
                    members: peers
                        .iter()
                        .map(|peer| {
                            (
                                peer.node_id,
                                AuthorityMember {
                                    verifier: installed_verifiers[&peer.node_id].clone(),
                                    endpoint: peer.endpoint.clone(),
                                    failure_domain: peer.failure_domain.clone(),
                                    certificate_pins: peer
                                        .certificate_pins
                                        .iter()
                                        .cloned()
                                        .collect(),
                                },
                            )
                        })
                        .collect(),
                },
            },
            resource_budget_bytes: 128 << 20,
            admission: Default::default(),
            database_path: root.join("authority.redb"),
            database_id: Uuid::new_v4(),
            scratch_disk,
            operational_signer_file,
            signer_verifier,
            signer_publications: None,
            installed_verifiers,
            keys: keys("application")?,
            custody_keys: keys("custody")?,
            security_audit: SecurityAuditConfig {
                keys: keys("security")?,
                retention: Default::default(),
                archive: None,
            },
            auth: AuthConfig {
                issuer: "https://issuer.example".into(),
                audience: "https://authority.example".into(),
                source: AuthKeySource::ExternalOAuth {
                    jwks_uri: "https://issuer.example/jwks".into(),
                    trusted_ca_pem: None,
                },
                algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
                access_token_types: BTreeSet::from(["at+jwt".into()]),
            },
            native: MutualTlsEndpoint {
                listen: "127.0.0.1:49540".parse()?,
                tls: tls.clone(),
                client_ca: tls.certificate.clone(),
            },
            replication: ReplicationConfig {
                node_id: 1,
                initial_voters: BTreeSet::from([1, 2, 3]),
                listener: MutualTlsEndpoint {
                    listen: "127.0.0.1:49543".parse()?,
                    tls: tls.clone(),
                    client_ca: tls.certificate.clone(),
                },
                peers,
            },
        };
        config.validate()?;
        config.bootstrap.validate()?;
        Ok(Self {
            _directory: directory,
            config,
        })
    }
    fn node(&self) -> Result<Arc<NodeStore>> {
        NodeStore::open_existing(
            &self.config.database_path,
            self.config.database_id,
            ScratchDisk::open(self.config.scratch_disk.clone())?,
        )
    }
    async fn verifier(&self) -> Result<Arc<crate::signer_runtime::InstalledSignerVerifier>> {
        let domain = self.config.installation.manifest.signing_domain(0)?;
        self.config
            .signer_verifier
            .open(
                BTreeMap::from([(domain.digest()?, domain)]),
                Arc::new(crate::runtime::file_secret),
                ScratchDisk::open(self.config.scratch_disk.clone())?,
                kasumi_engine::admission::NodeAdmission::new(Default::default())?,
            )
            .await
    }
    async fn verify_retained_state(&self, pair: bool, genesis: bool, complete: bool) -> Result<()> {
        let node = self.node()?;
        let security = TenantStore::open_existing(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            self.config
                .security_audit
                .keys
                .provider(Arc::new(crate::runtime::file_secret))?,
            StorageAccess::security_audit(),
        )
        .await?;
        assert_eq!(
            crate::node_enrollment::require_complete(
                &security,
                self.config.database_id,
                crate::node_enrollment::Kind::Authority,
            )
            .is_ok(),
            complete
        );
        if pair {
            let pair = TenantStorageSet::open_existing(
                node.clone(),
                self.config.installation.tenant(),
                self.config
                    .keys
                    .provider(Arc::new(crate::runtime::file_secret))?,
                self.config
                    .custody_keys
                    .provider(Arc::new(crate::runtime::file_secret))?,
                StorageAccess::independent_authority(&self.config.installation.manifest, 0)?,
            )
            .await?;
            let application = pair
                .application()
                .get("authority.installation", b"binding")?;
            let custody = pair
                .custody()
                .store()
                .get("authority.installation", b"binding")?;
            assert_eq!(application, custody, "genesis publication must be atomic");
            assert_eq!(application.is_some(), genesis);
            pair.shutdown().await?;
            drop(pair);
        }
        security.shutdown().await?;
        drop(security);
        node.drain_initializers().await?;
        drop(node);
        let verifier = self.verifier().await?;
        verifier.shutdown().await?;
        Ok(())
    }
}

#[derive(Default)]
struct BlockingPause {
    entered: Notify,
    released: Mutex<bool>,
    changed: Condvar,
}
fn blocking_pauses() -> &'static Mutex<BTreeMap<Uuid, Arc<BlockingPause>>> {
    static PAUSES: OnceLock<Mutex<BTreeMap<Uuid, Arc<BlockingPause>>>> = OnceLock::new();
    PAUSES.get_or_init(Default::default)
}
struct BlockingGuard(Uuid, Arc<BlockingPause>);
impl BlockingGuard {
    fn install(id: Uuid) -> Self {
        let pause = Arc::new(BlockingPause::default());
        assert!(
            blocking_pauses()
                .lock()
                .unwrap()
                .insert(id, pause.clone())
                .is_none()
        );
        Self(id, pause)
    }
    fn release(&self) {
        *self.1.released.lock().unwrap() = true;
        self.1.changed.notify_all();
    }
}
impl Drop for BlockingGuard {
    fn drop(&mut self) {
        blocking_pauses().lock().unwrap().remove(&self.0);
        self.release();
    }
}
pub(super) fn blocking_checkpoint(id: Uuid) {
    let pause = blocking_pauses().lock().unwrap().remove(&id);
    if let Some(pause) = pause {
        pause.entered.notify_one();
        let (released, _) = pause
            .changed
            .wait_timeout_while(
                pause.released.lock().unwrap(),
                Duration::from_secs(20),
                |released| !*released,
            )
            .unwrap();
        let finished = *released;
        drop(released);
        assert!(finished, "authority genesis test release deadline exceeded");
        std::panic::panic_any("original authority genesis blocking panic");
    }
}

#[tokio::test]
async fn authority_enrollment_panics_drain_owned_nodes_verifier_and_both_domains() -> Result<()> {
    for (phase, pair, genesis, complete) in [
        ("authority-enrollment-node", false, false, false),
        ("authority-enrollment-verifier", false, false, false),
        ("authority-enrollment-pair", true, false, false),
        ("authority-enrollment-genesis", true, true, false),
        ("authority-enrollment-complete", true, true, true),
    ] {
        let fixture = Fixture::new().await?;
        let _fault = crate::startup_preparation::install(fixture.config.database_id, phase);
        let error = tokio::time::timeout(Duration::from_secs(10), fixture.config.provision_node())
            .await?
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<crate::startup_preparation::PreparationPanic>()
                .is_some(),
            "{phase}: {error:#}"
        );
        fixture
            .verify_retained_state(pair, genesis, complete)
            .await?;
        let before = std::fs::read(&fixture.config.database_path)?;
        assert!(fixture.config.provision_node().await.is_err());
        assert_eq!(
            std::fs::read(&fixture.config.database_path)?,
            before,
            "rejected reenrollment cannot replace partial or complete state"
        );
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_authority_enrollment_joins_dispatched_genesis_and_preserves_both_panics()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let id = fixture.config.database_id;
    let registry = crate::startup_owner::TestRegistry::default();
    let blocking = BlockingGuard::install(id);
    let _fault = crate::startup_preparation::install(id, "authority-enrollment-genesis-dispatched");
    let pause = crate::startup_preparation::pause_failure(id);
    let mut enrolling = Box::pin(registry.open(initialize_owned(fixture.config.clone())));
    std::future::poll_fn(|cx| {
        assert!(enrolling.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    tokio::time::timeout(Duration::from_secs(10), pause.entered()).await?;
    tokio::time::timeout(Duration::from_secs(10), blocking.1.entered.notified()).await?;
    drop(enrolling);
    assert!(fixture.node().is_err());
    assert!(fixture.verifier().await.is_err());
    let mut drain = Box::pin(registry.drain());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(drain);
    // The cleanup path has left the preparation pause and now must join its
    // original blocking child, which still owns the actual encrypted pair.
    pause.release();
    tokio::task::yield_now().await;
    let mut drain = Box::pin(registry.drain());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(fixture.node().is_err());
    assert!(fixture.verifier().await.is_err());
    drop(drain);
    blocking.release();
    let error = tokio::time::timeout(Duration::from_secs(10), registry.drain())
        .await?
        .unwrap_err();
    assert!(
        error
            .downcast_ref::<crate::startup_preparation::PreparationPanic>()
            .is_some()
    );
    let report = error
        .downcast_ref::<kasumi_types::drain::DrainFailure>()
        .unwrap();
    let issue = report
        .issues()
        .iter()
        .find(|issue| issue.component() == "authority enrollment genesis")
        .expect("the original blocking outcome is retained alongside the preparation failure");
    let child = issue
        .error()
        .downcast_ref::<tokio::task::JoinError>()
        .unwrap();
    assert!(child.is_panic());
    fixture.verify_retained_state(true, false, false).await?;
    registry.drain().await?;
    Ok(())
}
