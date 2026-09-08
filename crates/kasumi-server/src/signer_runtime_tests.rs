use super::*;
use kasumi_store::FileKeyProvider;
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
            )
            .await
    }
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
        .store(Arc::new(file_secret), true)
        .await
        .unwrap();
    store
        .initialize_live_signer_trust(
            &f.input.verifier.identity,
            f.operational.certificate.clone(),
            Arc::new(MaintenanceClosed),
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
        .store(Arc::new(file_secret), true)
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
        .store(Arc::new(file_secret), true)
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
            .open(BTreeMap::new(), Arc::new(file_secret))
            .await
            .is_err()
    );
    let mut other_identity = f.input.verifier.clone();
    other_identity.identity.node_id = 2;
    assert!(
        other_identity
            .open(
                BTreeMap::from([(domain.digest().unwrap(), domain)]),
                Arc::new(file_secret)
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
