use super::*;
use kasumi_store::FileKeyProvider;
use std::future::Future;
use uuid::Uuid;

#[tokio::test]
async fn complete_domain_worker_budget_is_reserved_before_verifier_storage_open() {
    let fixture = Fixture::with_policy(kasumi_engine::admission::AdmissionConfig {
        max_inflight_operations: 1,
        ..Default::default()
    });
    fixture.initialize().await.unwrap();
    let before = std::fs::read(&fixture.input.verifier.database_path).unwrap();
    // Reuse the exact installed disk/core identity. A real resident reservation
    // leaves the original 1024-byte rejection boundary without spending the
    // only operation slot or substituting another governor.
    let persistent = fixture.persistent().unwrap();
    let scratch = fixture.scratch().unwrap();
    let admission = fixture.admission().unwrap();
    let baseline = admission.snapshot().reserved_bytes;
    let cap = fixture.input.admission.max_inflight_bytes.unwrap();
    let held = admission
        .reserve_resident(
            cap.checked_sub(baseline)
                .unwrap()
                .checked_sub(1024)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(cap - admission.snapshot().reserved_bytes, 1024);
    assert_eq!(admission.snapshot().inflight_operations, 0);
    let domain = fixture.manifest.signing_domain(0).unwrap();
    assert!(
        fixture
            .input
            .verifier
            .open(
                BTreeMap::from([(domain.digest().unwrap(), domain)]),
                Arc::new(file_secret),
                persistent.clone(),
                scratch.clone(),
                admission.clone(),
            )
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(&fixture.input.verifier.database_path).unwrap(),
        before
    );
    assert_eq!(cap - admission.snapshot().reserved_bytes, 1024);
    drop(held);
    assert_eq!(admission.snapshot().reserved_bytes, baseline);
    let domain = fixture.manifest.signing_domain(0).unwrap();
    let opened = fixture
        .input
        .verifier
        .open(
            BTreeMap::from([(domain.digest().unwrap(), domain)]),
            Arc::new(file_secret),
            persistent.clone(),
            scratch.clone(),
            admission.clone(),
        )
        .await
        .unwrap();
    let expected =
        BackgroundWorkBudget::required_bytes(fixture.input.verifier.max_background_workers, 1)
            .unwrap();
    // The opened native KV store also retains a charged resident index.
    let opened_reserved = admission.snapshot().reserved_bytes;
    assert!(opened_reserved >= baseline + expected);
    assert_eq!(admission.snapshot().inflight_operations, 0);
    // Installed metadata must leave the sole operation slot usable.
    let request = admission.reserve(1, None).unwrap();
    assert_eq!(admission.snapshot().inflight_operations, 1);
    drop(request);
    opened.shutdown().await.unwrap();
    let shut_down_reserved = admission.snapshot().reserved_bytes;
    assert!((baseline + expected..=opened_reserved).contains(&shut_down_reserved));
    drop(opened);
    assert_eq!(admission.snapshot().reserved_bytes, baseline);
}

#[tokio::test]
async fn checked_replicated_installation_identity_requires_its_live_exact_disk() {
    let fixture = Fixture::new();
    fixture.initialize().await.unwrap();
    let disk = fixture.persistent().unwrap();
    let installed = fixture.open().await.unwrap();
    assert_eq!(
        installed.identity_for(&disk).unwrap(),
        fixture.input.verifier.identity
    );
    let other = Fixture::new();
    assert!(
        installed
            .identity_for(&other.persistent().unwrap())
            .is_err()
    );
    installed.shutdown().await.unwrap();
    assert!(installed.identity_for(&disk).is_err());
}

struct Fixture {
    storage: crate::runtime_memory::RuntimeStorage,
    _directory: tempfile::TempDir,
    input: InitializeSignerVerifier,
    manifest: AuthorityManifest,
    root: InstallationSigningRoot,
    operational: OperationalSignerConfig,
}
impl Fixture {
    fn new() -> Self {
        Self::with_policy(kasumi_engine::admission::AdmissionConfig::default())
    }
    fn with_policy(policy: kasumi_engine::admission::AdmissionConfig) -> Self {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
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
        let persistent_disk =
            crate::persistent_disk::fixture_config(&directory.path().join("data"));
        let scratch_disk = kasumi_store::ScratchDiskConfig {
            directory: directory.path().join("scratch"),
            max_bytes: 64 << 30,
            min_free_bytes: 256 << 20,
        };
        let storage = crate::runtime_memory::RuntimeStorage::isolated_fixture(
            policy,
            &persistent_disk,
            &scratch_disk,
        )
        .unwrap();
        Self {
            input: InitializeSignerVerifier {
                admission: storage.policy().clone(),
                persistent_disk,
                scratch_disk,
                verifier: SignerVerifierConfig {
                    max_background_workers: 64,
                    identity: TrustVerifierIdentity {
                        installation_id: Uuid::new_v4(),
                        node_id: 1,
                    },
                    database_path: directory.path().join("data/trust.kv"),
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
            storage,
            _directory: directory,
        }
    }
    async fn initialize(&self) -> Result<()> {
        self.input
            .initialize_with_storage(self.storage.clone())
            .await
    }
    fn persistent(&self) -> Result<Arc<kasumi_store::NodeDisk>> {
        self.storage.open_persistent(&self.input.persistent_disk)
    }
    fn scratch(&self) -> Result<Arc<kasumi_store::ScratchDisk>> {
        self.storage.open_scratch(&self.input.scratch_disk)
    }
    fn admission(&self) -> Result<Arc<kasumi_engine::admission::NodeAdmission>> {
        self.storage.facade(&self.input.admission)
    }
    async fn open(&self) -> Result<Arc<InstalledSignerVerifier>> {
        let domain = self.manifest.signing_domain(0)?;
        self.input
            .verifier
            .open(
                BTreeMap::from([(domain.digest()?, domain)]),
                Arc::new(file_secret),
                self.persistent().unwrap(),
                self.scratch()?,
                self.admission()?,
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
        f.initialize().await.unwrap();
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
        installed.shutdown().await.unwrap();
        drop(installed);
        let reopened = f.open().await.unwrap();
        reopened.shutdown().await.unwrap();
    })
    .await
    .expect("shutdown ownership fixture timed out");
}

#[tokio::test]
async fn verifier_shutdown_joins_renewal_after_setup_owner_is_dropped() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let f = Fixture::new();
        f.initialize().await.unwrap();
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
                .start_background_work(Arc::new(BackgroundWork::default()), async {
                    panic!("closed verifier spawned a late worker")
                })
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
        retry.await.unwrap();
        assert!(weak_lease.upgrade().is_none());
        drop(installed);
        let reopened = f.open().await.unwrap();
        reopened.shutdown().await.unwrap();
    })
    .await
    .expect("shutdown ownership fixture timed out");
}

#[tokio::test]
async fn explicit_encrypted_verifier_initialization_never_bootstraps_runtime_trust() {
    let f = Fixture::new();
    assert!(f.open().await.is_err());
    assert!(!f.input.verifier.database_path.exists());
    // Enroll the intentionally empty fixture inode through its exact owner.
    // Runtime rejects the missing node envelope without a raw namespace change
    // that would independently fence the installed physical census.
    let disk = f.persistent().unwrap();
    let (root, relative) = f
        .input
        .persistent_disk
        .binding(&f.input.verifier.database_path)
        .unwrap();
    let empty = disk
        .create_file(root, relative, kasumi_store::DiskWork::Foreground)
        .unwrap();
    drop(empty);
    assert!(f.open().await.is_err());
    assert_eq!(disk.snapshot().phase, kasumi_store::NodeDiskPhase::Open);
    assert_eq!(
        std::fs::metadata(&f.input.verifier.database_path)
            .unwrap()
            .len(),
        0
    );
    let empty = disk.open_file(root, relative).unwrap();
    disk.delete_file(empty).unwrap();
    f.initialize().await.unwrap();
    assert!(f.initialize().await.is_err(), "installation cannot repeat");
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
    installed.shutdown().await.unwrap();
    assert!(signer.check().is_err());
    drop(signer);
    drop(installed);
    let reopened = f.open().await.unwrap();
    f.operational.open(&reopened).unwrap().check().unwrap();
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn completed_verifier_installation_requires_current_writer_bytes_without_repair() -> Result<()>
{
    let fixture = Fixture::new();
    fixture.initialize().await?;
    let (node, store) = fixture
        .input
        .verifier
        .store(
            Arc::new(file_secret),
            false,
            fixture.persistent()?,
            fixture.scratch()?,
        )
        .await?;
    let canonical = store
        .get_bounded(NS, b"installation", 256 << 10)?
        .expect("current writer must publish verifier installation");
    let installed: VerifierInstallation = serde_json::from_slice(&canonical)?;
    assert!(serde_json::to_vec(&installed)?.as_slice() == canonical.as_slice());
    let mut alternate = canonical.clone();
    alternate.push(b' ');
    assert!(serde_json::from_slice::<VerifierInstallation>(&alternate)? == installed);
    store.write_batch(&[WriteOp::put(NS, b"installation", alternate.as_slice())])?;
    store.shutdown().await?;
    node.shutdown().await?;
    drop(store);
    drop(node);

    let error = fixture
        .open()
        .await
        .err()
        .expect("alternate verifier installation accepted");
    assert!(
        format!("{error:#}").contains("noncanonical signer verifier installation"),
        "{error:#}"
    );
    assert!(
        fixture.initialize().await.is_err(),
        "existing verifier was reseeded"
    );
    let (node, store) = fixture
        .input
        .verifier
        .store(
            Arc::new(file_secret),
            false,
            fixture.persistent()?,
            fixture.scratch()?,
        )
        .await?;
    assert!(
        store.get_bounded(NS, b"installation", 256 << 10)? == Some(alternate),
        "failed startup repaired the verifier installation"
    );
    store.write_batch(&[WriteOp::put(NS, b"installation", canonical.as_slice())])?;
    store.shutdown().await?;
    node.shutdown().await?;
    drop(store);
    drop(node);

    let reopened = fixture.open().await?;
    fixture.operational.open(&reopened)?.check()?;
    reopened.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn partial_verifier_is_never_adopted_and_corrupt_complete_head_is_never_reseeded() {
    let f = Fixture::new();
    let (node, store) = f
        .input
        .verifier
        .store(
            Arc::new(file_secret),
            true,
            f.persistent().unwrap(),
            f.scratch().unwrap(),
        )
        .await
        .unwrap();
    store
        .initialize_live_signer_trust(
            &f.input.verifier.identity,
            f.operational.certificate.clone(),
            Arc::new(ScopedSignerAdministrator::default()),
            BackgroundWorkBudget::new(64, Arc::new(())).unwrap(),
        )
        .unwrap();
    let digest = f.manifest.signing_domain(0).unwrap().digest().unwrap();
    let retained = store
        .get("live.signer.trust", digest.as_bytes())
        .unwrap()
        .unwrap();
    assert!(store.get(NS, b"installation").unwrap().is_none());
    store.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    drop(node);
    drop(store);
    assert!(f.open().await.is_err());
    assert!(
        f.initialize().await.is_err(),
        "partial installation cannot be adopted"
    );
    let (node, store) = f
        .input
        .verifier
        .store(
            Arc::new(file_secret),
            false,
            f.persistent().unwrap(),
            f.scratch().unwrap(),
        )
        .await
        .unwrap();
    assert!(store.get(NS, b"installation").unwrap().is_none());
    assert_eq!(
        store
            .get("live.signer.trust", digest.as_bytes())
            .unwrap()
            .unwrap(),
        retained
    );
    store.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    drop(node);
    drop(store);

    // Independently completed installation: corruption must not reseed its head.
    let f = Fixture::new();
    f.initialize().await.unwrap();
    let (node, store) = f
        .input
        .verifier
        .store(
            Arc::new(file_secret),
            false,
            f.persistent().unwrap(),
            f.scratch().unwrap(),
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
    store.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    drop(node);
    drop(store);
    assert!(f.open().await.is_err());
    // A completion marker is not permission to reseed a damaged durable head.
    assert!(f.initialize().await.is_err());
    let (node, store) = f
        .input
        .verifier
        .store(
            Arc::new(file_secret),
            false,
            f.persistent().unwrap(),
            f.scratch().unwrap(),
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
    store.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    drop(node);
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
    assert!(f.initialize().await.is_err());
    assert!(!f.input.verifier.database_path.exists());
    f.input.initial_certificates = vec![f.operational.certificate.clone(); 2];
    assert!(f.initialize().await.is_err());
    assert!(!f.input.verifier.database_path.exists());
    f.input.initial_certificates.truncate(1);
    f.initialize().await.unwrap();
    let domain = f.manifest.signing_domain(0).unwrap();
    assert!(
        f.input
            .verifier
            .open(
                BTreeMap::new(),
                Arc::new(file_secret),
                f.persistent().unwrap(),
                f.scratch().unwrap(),
                f.admission().unwrap(),
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
                f.persistent().unwrap(),
                f.scratch().unwrap(),
                f.admission().unwrap(),
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
    installed.shutdown().await.unwrap();
}

#[tokio::test]
async fn operational_source_is_private_bounded_and_cannot_substitute_installed_trust() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    f.initialize().await.unwrap();
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
    installed.shutdown().await.unwrap();
    assert!(retained.check().is_err());
    // Actual shutdown closed the physical node and sealed every old trust
    // facade. Keeping either old Arc alive cannot revive it or block a fresh
    // owner after that positive drain proof.
    let reopened = f.open().await.unwrap();
    let fresh = OperationalSignerConfig::load(&path, &domain)
        .unwrap()
        .open(&reopened)
        .unwrap();
    fresh.check().unwrap();
    installed.shutdown().await.unwrap();
    assert!(retained.check().is_err());
    fresh.check().unwrap();
    drop(installed);
    drop(retained);
    reopened.shutdown().await.unwrap();
    assert!(fresh.check().is_err());
}

#[tokio::test]
async fn panicked_verifier_initialization_drains_each_acquired_encrypted_owner() -> Result<()> {
    for phase in [
        "verifier-storage-node",
        "verifier-storage-catalog",
        "verifier-installation-store",
        "verifier-installation-domains",
        "verifier-installation-complete",
    ] {
        let fixture = Fixture::new();
        let id = kasumi_store::node_store_ids::signer_verifier(&fixture.input.verifier.identity)?;
        let _fault = crate::startup_preparation::install(id, phase);
        let error = tokio::time::timeout(std::time::Duration::from_secs(10), fixture.initialize())
            .await?
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<crate::startup_preparation::PreparationPanic>()
                .is_some(),
            "{phase}: {error:#}"
        );
        let node = NodeStore::open_existing(
            &fixture.input.verifier.database_path,
            id,
            fixture.persistent().unwrap(),
            fixture.scratch()?,
        )?;
        if phase != "verifier-storage-node" {
            let store = TenantStore::open_existing(
                node.clone(),
                fixture.input.verifier.identity.tenant(),
                fixture
                    .input
                    .verifier
                    .keys
                    .provider(Arc::new(file_secret))?,
                StorageAccess::live_signer_trust(fixture.input.verifier.identity.clone())?,
            )
            .await?;
            let complete = store.get(NS, b"installation")?.is_some();
            assert_eq!(complete, phase == "verifier-installation-complete");
            let domain = fixture.manifest.signing_domain(0)?.digest()?;
            assert_eq!(
                store.get("live.signer.trust", domain.as_bytes())?.is_some(),
                matches!(
                    phase,
                    "verifier-installation-domains" | "verifier-installation-complete"
                )
            );
            store.shutdown().await?;
            drop(store);
        }
        node.drain_initializers().await?;
        node.shutdown().await?;
        drop(node);
        let before = std::fs::read(&fixture.input.verifier.database_path)?;
        assert!(fixture.initialize().await.is_err());
        assert_eq!(
            std::fs::read(&fixture.input.verifier.database_path)?,
            before
        );
        if phase == "verifier-installation-complete" {
            let installed = fixture.open().await?;
            fixture.operational.open(&installed)?.check()?;
            installed.shutdown().await?;
        } else {
            assert!(
                fixture.open().await.is_err(),
                "partial trust cannot be resumed"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_verifier_initialization_retains_physical_owner_and_unclaimed_panic() -> Result<()>
{
    use std::task::Poll;
    for phase in ["verifier-storage-catalog", "verifier-installation-complete"] {
        let fixture = Fixture::new();
        let registry = crate::startup_owner::TestRegistry::default();
        let id = kasumi_store::node_store_ids::signer_verifier(&fixture.input.verifier.identity)?;
        let _fault = crate::startup_preparation::install(id, phase);
        // This guard releases the retained operation even if an assertion fails.
        let pause = crate::startup_preparation::pause_failure(id);
        let mut initialize = Box::pin(
            registry.open(
                fixture
                    .input
                    .clone()
                    .initialize_owned(fixture.storage.clone()),
            ),
        );
        std::future::poll_fn(|cx| {
            assert!(initialize.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::timeout(std::time::Duration::from_secs(10), pause.entered()).await?;
        drop(initialize);
        let reopen = || {
            NodeStore::open_existing(
                &fixture.input.verifier.database_path,
                id,
                fixture.persistent().unwrap(),
                fixture.scratch()?,
            )
        };
        assert!(
            reopen().is_err(),
            "{phase}: caller cancellation lost ownership"
        );
        let mut drain = Box::pin(registry.drain());
        std::future::poll_fn(|cx| {
            assert!(drain.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(drain);
        assert!(reopen().is_err(), "{phase}: cancelled drain lost ownership");
        let mut drain = Box::pin(registry.drain());
        std::future::poll_fn(|cx| {
            assert!(drain.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        pause.release();
        let error = tokio::time::timeout(std::time::Duration::from_secs(10), drain)
            .await?
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<crate::startup_preparation::PreparationPanic>()
                .is_some(),
            "original unclaimed panic must survive both cancellations: {error:#}"
        );
        let node = reopen()?;
        node.drain_initializers().await?;
        node.shutdown().await?;
        drop(node);
        registry.drain().await?;
        if phase == "verifier-installation-complete" {
            let installed = fixture.open().await?;
            fixture.operational.open(&installed)?.check()?;
            installed.shutdown().await?;
        } else {
            assert!(
                fixture.open().await.is_err(),
                "partial trust cannot be resumed"
            );
        }
    }
    Ok(())
}
