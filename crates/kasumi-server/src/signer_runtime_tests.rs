use super::*;
use kasumi_store::FileKeyProvider;
use std::future::Future;
use uuid::Uuid;

struct Fixture {
    _directory: tempfile::TempDir,
    input: InitializeSignerVerifier,
    manifest: AuthorityManifest,
    root: InstallationSigningRoot,
    operational: OperationalSignerConfig,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let keys = directory.path().join("wrapping.json");
        FileKeyProvider::initialize(&keys, "signer-verifier").unwrap();
        let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
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
        let root = InstallationSigningRoot::from_pkcs8(
            manifest.signing_domain(0).unwrap(),
            &root_key.serialize_der(),
        )
        .unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let certificate = root.certify(1, hex::encode(key.public_key_raw())).unwrap();
        let key_file = directory.path().join("operational.pk8");
        private_files::create(&key_file, &key.serialize_der()).unwrap();
        Self {
            input: InitializeSignerVerifier {
                scratch_disk: kasumi_store::ScratchDiskConfig {
                    directory: directory.path().join("scratch"),
                    max_bytes: 64 << 30,
                    min_free_bytes: 256 << 20,
                },
                verifier: SignerVerifierConfig {
                    identity: TrustVerifierIdentity {
                        installation_id: Uuid::new_v4(),
                        node_id: 1,
                    },
                    database_path: directory.path().join("trust.redb"),
                    keys: KeyProviderSettings::File { path: keys },
                },
                initial_certificates: vec![certificate.clone()],
            },
            operational: OperationalSignerConfig {
                certificate,
                key_file,
            },
            manifest,
            root,
            _directory: directory,
        }
    }
    async fn open(&self) -> Result<Arc<InstalledSignerVerifier>> {
        let domain = self.manifest.signing_domain(0)?;
        self.input
            .verifier
            .open(
                BTreeMap::from([(domain.digest()?, domain)]),
                Arc::new(file_secret),
                kasumi_store::ScratchDisk::open(self.input.scratch_disk.clone())?,
            )
            .await
    }
    fn paused_lease(
        &self,
        installed: &InstalledSignerVerifier,
    ) -> (
        Arc<crate::serving_runtime::RuntimeLease>,
        Arc<crate::runtime_worker::WorkerPause>,
    ) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let pem = certificate.pem().into_bytes();
        let tls =
            kasumi_transport::TlsIdentity::from_pem(&pem, key.serialize_pem().as_bytes()).unwrap();
        let trust = installed.trust(self.manifest.clone()).unwrap();
        let boot = ServingBoot::with_test_clock(
            trust.clone(),
            ServingIdentity {
                tenant: "city".into(),
                incarnation: Uuid::new_v4(),
                authority_epoch: 1,
                node: NodeIdentity {
                    node_id: 1,
                    verifier: self.input.verifier.identity.clone(),
                    principal: "data-1".into(),
                    certificate_sha256: hex::encode(tls.certificate_pin()),
                },
            },
            Arc::new(kasumi_store::test_utils::ManualClock::new()),
        )
        .unwrap();
        let attempt = boot.begin_acquisition().unwrap();
        let signed = self
            .operational
            .open(installed)
            .unwrap()
            .sign_lease(kasumi_serving::LeaseClaims {
                request: attempt.request().clone(),
                authority_id: self.manifest.authority_id,
                partition: 0,
                authority_term: 1,
                authority_revision: 1,
                lifetime_ms: 1000,
                credential_lifetime_ms: 1000,
                activation_digest: "ab".repeat(32),
                recovery_checkpoint: None,
            })
            .unwrap();
        let gate = kasumi_serving::ServingGate::new(attempt.verify(signed).unwrap()).unwrap();
        let client = kasumi_client::KasumiAuthorityPool::new(
            BTreeMap::from([(
                1,
                kasumi_client::KasumiClientConfig {
                    endpoint: "https://localhost:9".into(),
                    server_certificate_pins: std::collections::BTreeSet::from([
                        tls.certificate_pin()
                    ]),
                    identity: tls,
                    trusted_ca_pem: pem,
                },
            )]),
            trust,
            Arc::new(|| Ok(zeroize::Zeroizing::new("fixture".into()))),
        )
        .unwrap();
        crate::serving_runtime::RuntimeLease::paused_renewal(boot, client, gate).unwrap()
    }
}

#[tokio::test]
async fn renewal_shutdown_keeps_its_handle_through_cancelled_join_and_verifier_reopen() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let f = Fixture::new();
        f.input.initialize().await.unwrap();
        let installed = f.open().await.unwrap();
        let (lease, pause) = f.paused_lease(&installed);
        let weak_lease = Arc::downgrade(&lease);
        pause.entered.notified().await;
        let mut first = Box::pin(lease.shutdown());
        std::future::poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(first);
        assert!(lease.gate().check().is_err());
        let mut retry = Box::pin(lease.shutdown());
        std::future::poll_fn(|cx| {
            assert!(retry.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        pause.release.notify_one();
        retry.await.unwrap();
        drop(lease);
        assert!(weak_lease.upgrade().is_none());
        installed.shutdown().await;
        drop(installed);
        let reopened = f.open().await.unwrap();
        reopened.shutdown().await;
    })
    .await
    .expect("shutdown ownership fixture timed out");
}

#[tokio::test]
async fn verifier_shutdown_joins_renewal_after_setup_owner_is_dropped() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let f = Fixture::new();
        f.input.initialize().await.unwrap();
        let installed = f.open().await.unwrap();
        let (lease, pause) = f.paused_lease(&installed);
        let weak_lease = Arc::downgrade(&lease);
        pause.entered.notified().await;
        drop(lease); // A failed or cancelled setup no longer owns this lease.
        assert!(weak_lease.upgrade().is_some());
        let mut first = Box::pin(installed.shutdown());
        std::future::poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(first);
        let owner = installed
            .owner(&f.manifest.signing_domain(0).unwrap())
            .unwrap();
        assert!(
            owner
                .start_background_work(|| panic!("closed verifier spawned a late worker"))
                .is_err()
        );
        drop(owner);
        let mut retry = Box::pin(installed.shutdown());
        std::future::poll_fn(|cx| {
            assert!(retry.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        pause.release.notify_one();
        retry.await;
        assert!(weak_lease.upgrade().is_none());
        drop(installed);
        let reopened = f.open().await.unwrap();
        reopened.shutdown().await;
    })
    .await
    .expect("shutdown ownership fixture timed out");
}

#[tokio::test]
async fn explicit_encrypted_verifier_initialization_never_bootstraps_runtime_trust() {
    let f = Fixture::new();
    assert!(f.open().await.is_err());
    assert!(!f.input.verifier.database_path.exists());
    private_files::create(&f.input.verifier.database_path, b"").unwrap();
    assert!(f.open().await.is_err());
    assert_eq!(
        std::fs::metadata(&f.input.verifier.database_path)
            .unwrap()
            .len(),
        0
    );
    std::fs::remove_file(&f.input.verifier.database_path).unwrap();
    f.input.initialize().await.unwrap();
    f.input.initialize().await.unwrap();
    let installed = f.open().await.unwrap();
    assert!(f.open().await.is_err(), "exclusive metadata ownership");
    let signer = f.operational.open(&installed).unwrap();
    signer.check().unwrap();
    let identity = ServingIdentity {
        tenant: "city".into(),
        incarnation: Uuid::new_v4(),
        authority_epoch: 1,
        node: NodeIdentity {
            node_id: 1,
            verifier: f.input.verifier.identity.clone(),
            principal: "data-1".into(),
            certificate_sha256: "ab".repeat(32),
        },
    };
    let trust = installed.trust(f.manifest.clone()).unwrap();
    ServingBoot::new(trust, identity).unwrap();
    let mut staged = f.operational.clone();
    staged.certificate = f
        .root
        .certify(
            2,
            hex::encode(
                rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
                    .unwrap()
                    .public_key_raw(),
            ),
        )
        .unwrap();
    assert!(staged.open(&installed).is_err());
    let mut forged = f.operational.clone();
    forged.certificate.root_signature = "00".repeat(64);
    assert!(forged.open(&installed).is_err());
    installed.shutdown().await;
    assert!(signer.check().is_err());
    drop(signer);
    drop(installed);
    let reopened = f.open().await.unwrap();
    f.operational.open(&reopened).unwrap().check().unwrap();
    reopened.shutdown().await;
}

#[tokio::test]
async fn partial_initializer_resumes_only_exact_initial_heads_and_rejects_corruption() {
    let f = Fixture::new();
    let store = f
        .input
        .verifier
        .store(
            Arc::new(file_secret),
            true,
            kasumi_store::ScratchDisk::fixture(),
        )
        .await
        .unwrap();
    store
        .initialize_live_signer_trust(
            &f.input.verifier.identity,
            f.operational.certificate.clone(),
            Arc::new(ScopedSignerAdministrator::default()),
        )
        .unwrap();
    store.shutdown().await;
    drop(store);
    assert!(f.open().await.is_err());
    f.input.initialize().await.unwrap();
    let installed = f.open().await.unwrap();
    installed.shutdown().await;
    drop(installed);
    let store = f
        .input
        .verifier
        .store(
            Arc::new(file_secret),
            true,
            kasumi_store::ScratchDisk::fixture(),
        )
        .await
        .unwrap();
    let digest = f.manifest.signing_domain(0).unwrap().digest().unwrap();
    store
        .write_batch(&[WriteOp::put(
            "live.signer.trust",
            digest.as_bytes(),
            b"corrupt".to_vec(),
        )])
        .unwrap();
    store.shutdown().await;
    drop(store);
    assert!(f.open().await.is_err());
    // A completion marker is not permission to reseed a damaged durable head.
    assert!(f.input.initialize().await.is_err());
    let store = f
        .input
        .verifier
        .store(
            Arc::new(file_secret),
            true,
            kasumi_store::ScratchDisk::fixture(),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .get("live.signer.trust", digest.as_bytes())
            .unwrap()
            .unwrap(),
        b"corrupt"
    );
    store.shutdown().await;
}

#[tokio::test]
async fn initialization_rejects_noninitial_and_mismatched_domains_without_publishing() {
    let mut f = Fixture::new();
    let next_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let next = f
        .root
        .certify(2, hex::encode(next_key.public_key_raw()))
        .unwrap();
    f.input.initial_certificates = vec![next];
    assert!(f.input.initialize().await.is_err());
    assert!(!f.input.verifier.database_path.exists());
    f.input.initial_certificates = vec![f.operational.certificate.clone(); 2];
    assert!(f.input.initialize().await.is_err());
    assert!(!f.input.verifier.database_path.exists());
    f.input.initial_certificates.truncate(1);
    f.input.initialize().await.unwrap();
    let domain = f.manifest.signing_domain(0).unwrap();
    assert!(
        f.input
            .verifier
            .open(
                BTreeMap::new(),
                Arc::new(file_secret),
                kasumi_store::ScratchDisk::fixture()
            )
            .await
            .is_err()
    );
    let mut other_identity = f.input.verifier.clone();
    other_identity.identity.node_id = 2;
    assert!(
        other_identity
            .open(
                BTreeMap::from([(domain.digest().unwrap(), domain)]),
                Arc::new(file_secret),
                kasumi_store::ScratchDisk::fixture()
            )
            .await
            .is_err()
    );
    let installed = f.open().await.unwrap();
    let owner = installed
        .owner(&f.manifest.signing_domain(0).unwrap())
        .unwrap();
    let clock = kasumi_clock::EpochClock::system().unwrap();
    let context = kasumi_types::RequestContext {
        tenant: f.input.verifier.identity.tenant(),
        principal: "operator".into(),
        request_id: Uuid::new_v4().to_string(),
        scopes: std::collections::BTreeSet::from([kasumi_types::Action::Admin]),
        authorization: kasumi_types::RequestAuthorization::from_verified_credential(
            clock.now_ms().unwrap() + 60_000,
            &clock.observe().unwrap(),
            kasumi_types::CredentialResource::Authority {
                authority_id: f.manifest.authority_id,
                partition: 0,
            },
        )
        .unwrap(),
    };
    assert!(
        owner
            .administer(
                &context,
                SignerTrustCommand {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 0,
                    not_after_ms: u64::MAX,
                    action: SignerTrustAction::Stage {
                        certificate: f
                            .root
                            .certify(2, hex::encode(next_key.public_key_raw()))
                            .unwrap()
                    },
                }
            )
            .is_err(),
        "production maintenance requires the current coordinator"
    );
    installed.shutdown().await;
}

#[tokio::test]
async fn operational_source_is_private_bounded_and_cannot_substitute_installed_trust() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    f.input.initialize().await.unwrap();
    let installed = f.open().await.unwrap();
    let domain = f.manifest.signing_domain(0).unwrap();
    let path = f._directory.path().join("current.json");
    let bytes = serde_json::to_vec(&f.operational).unwrap();
    private_files::create(&path, &bytes).unwrap();
    let retained = OperationalSignerConfig::load(&path, &domain)
        .unwrap()
        .open(&installed)
        .unwrap();
    assert!(OperationalSignerConfig::load(Path::new("relative.json"), &domain).is_err());
    let link = f._directory.path().join("alias.json");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(OperationalSignerConfig::load(&link, &domain).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(OperationalSignerConfig::load(&path, &domain).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    private_files::replace(&path, &vec![b' '; (128 << 10) + 1]).unwrap();
    assert!(OperationalSignerConfig::load(&path, &domain).is_err());
    let mut forged = f.operational.clone();
    forged.certificate.root_signature = "00".repeat(64);
    private_files::replace(&path, &serde_json::to_vec(&forged).unwrap()).unwrap();
    assert!(OperationalSignerConfig::load(&path, &domain).is_err());
    retained.check().unwrap();
    private_files::replace(&path, &bytes).unwrap();
    installed.shutdown().await;
    assert!(retained.check().is_err());
    drop(installed);
    assert!(
        f.open().await.is_err(),
        "retained metadata owners must drain before reopening"
    );
    drop(retained);
    let reopened = f.open().await.unwrap();
    OperationalSignerConfig::load(&path, &domain)
        .unwrap()
        .open(&reopened)
        .unwrap()
        .check()
        .unwrap();
    reopened.shutdown().await;
}
