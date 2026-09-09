use super::*;
use kasumi_store::WriteOp;

type RetainedRows = Vec<Vec<(Vec<u8>, Vec<u8>)>>;

struct InstalledFixture {
    directory: tempfile::TempDir,
    stores: Arc<TenantStorageSet>,
    installation: AuthorityInstallation,
    bootstrap: crate::AuthorityBootstrap,
    settings: AuthorityNodeSettings,
    signing: kasumi_serving::test_utils::FixtureAuthority,
}
impl InstalledFixture {
    async fn new() -> anyhow::Result<Self> {
        let directory = tempfile::tempdir()?;
        let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("fixture root generation failed"))?;
        let root = kasumi_serving::test_utils::FixtureSigningRoot::from_pkcs8(key.as_ref())?;
        let installation = AuthorityInstallation {
            manifest: AuthorityManifest {
                lifecycle_controls: BTreeMap::new(),
                authority_id: Uuid::new_v4(),
                max_lease_ms: 1000,
                clock_rate_error_ppm: 0,
                partitions: BTreeMap::from([(
                    0,
                    AuthorityPartition {
                        group: "strict-authority".into(),
                        public_key: root.public_key(),
                    },
                )]),
            },
            partition: 0,
        };
        let signing = root.install(installation.manifest.clone(), 0)?;
        let (bootstrap, settings) = test_settings(4 << 20, signing.signer.certificate().clone());
        let node = NodeStore::create_new(
            directory.path().join("authority.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )?;
        let stores = TenantStorageSet::initialize_catalogs(
            node,
            installation.tenant(),
            Arc::new(LocalKeyProvider::new([31; 32])),
            Arc::new(LocalKeyProvider::new([32; 32])),
            kasumi_store::StorageAccess::independent_authority(&installation.manifest, 0)?,
        )
        .await?;
        Ok(Self {
            directory,
            stores,
            installation,
            bootstrap,
            settings,
            signing,
        })
    }
    fn initialize(&self) -> anyhow::Result<()> {
        IndependentAuthority::initialize_storage(
            &self.stores,
            &self.installation,
            &self.bootstrap,
            &self.settings.installed_members[&1].verifier,
        )
    }
    async fn open(&self) -> anyhow::Result<Arc<IndependentAuthority>> {
        self.open_as(
            self.installation.clone(),
            self.signing.signer.clone(),
            self.settings.clone(),
        )
        .await
    }
    async fn open_as(
        &self,
        installation: AuthorityInstallation,
        signer: Arc<AuthoritySigner>,
        settings: AuthorityNodeSettings,
    ) -> anyhow::Result<Arc<IndependentAuthority>> {
        IndependentAuthority::open_existing_with_clock(
            self.stores.clone(),
            installation,
            signer,
            1,
            settings,
            Arc::new(InProcessRouter::default()),
            Config::default(),
            EpochClock::system()?,
        )
        .await
    }
    fn retained(&self) -> anyhow::Result<RetainedRows> {
        let mut values = Vec::new();
        for store in [self.stores.application(), self.stores.custody().store()] {
            for namespace in [
                "authority.installation",
                "kasumi.independent-authority",
                "raft.meta",
                "raft.headers",
                "raft.log",
                "raft.snapshot",
            ] {
                values.push(store.scan(namespace)?);
            }
        }
        Ok(values)
    }
    async fn reject(&self) -> anyhow::Result<()> {
        self.reject_as(
            self.installation.clone(),
            self.signing.signer.clone(),
            self.settings.clone(),
        )
        .await
    }
    async fn reject_as(
        &self,
        installation: AuthorityInstallation,
        signer: Arc<AuthoritySigner>,
        settings: AuthorityNodeSettings,
    ) -> anyhow::Result<()> {
        let before = self.retained()?;
        let outcome = self.open_as(installation, signer, settings).await;
        if let Ok(service) = &outcome {
            service.shutdown().await?;
        }
        assert!(
            outcome.is_err(),
            "strict existing authority unexpectedly opened"
        );
        assert_eq!(
            self.retained()?,
            before,
            "rejected restart changed durable rows"
        );
        Ok(())
    }
    async fn close(&self) {
        self.stores.application().shutdown().await;
        self.stores.custody().store().shutdown().await;
    }
    async fn reopen(self) -> anyhow::Result<Self> {
        self.close().await;
        let Self {
            directory,
            stores,
            installation,
            bootstrap,
            settings,
            signing,
        } = self;
        drop(stores);
        let node = NodeStore::open_existing(
            directory.path().join("authority.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )?;
        let stores = TenantStorageSet::open_existing(
            node,
            installation.tenant(),
            Arc::new(LocalKeyProvider::new([31; 32])),
            Arc::new(LocalKeyProvider::new([32; 32])),
            kasumi_store::StorageAccess::independent_authority(&installation.manifest, 0)?,
        )
        .await?;
        Ok(Self {
            directory,
            stores,
            installation,
            bootstrap,
            settings,
            signing,
        })
    }
}

#[tokio::test]
async fn strict_authority_requires_every_published_head_without_recreating_it() -> anyhow::Result<()>
{
    let fixture = InstalledFixture::new().await?;
    fixture.reject().await?;
    fixture.initialize()?;
    for (custody, namespace, key) in [
        (false, "authority.installation", b"binding".as_slice()),
        (true, "authority.installation", b"binding".as_slice()),
        (false, "authority.installation", b"local-member".as_slice()),
        (true, "authority.installation", b"local-member".as_slice()),
        (
            false,
            "authority.installation",
            b"resource-floor".as_slice(),
        ),
        (false, "kasumi.independent-authority", b"meta".as_slice()),
        (true, "raft.meta", b"node_id".as_slice()),
        (true, "raft.meta", b"group".as_slice()),
    ] {
        let store = if custody {
            fixture.stores.custody().store()
        } else {
            fixture.stores.application()
        };
        let original = store.get(namespace, key)?.unwrap();
        store.write_batch(&[WriteOp::delete(namespace, key)])?;
        fixture.reject().await?;
        let before = fixture.retained()?;
        assert!(
            fixture.initialize().is_err(),
            "partial installation cannot initialize again"
        );
        assert_eq!(fixture.retained()?, before);
        store.write_batch(&[WriteOp::put(namespace, key, original)])?;
    }
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn strict_authority_rejects_corrupt_and_unsupported_genesis_without_replacement()
-> anyhow::Result<()> {
    let fixture = InstalledFixture::new().await?;
    fixture.initialize()?;
    let original = fixture
        .stores
        .application()
        .get("authority.installation", b"binding")?
        .unwrap();
    for bytes in [
        b"not-json".as_slice(),
        br#"{"kind":"local"}"#.as_slice(),
        br#"["kasumi.independent-authority.v2",{},{}]"#.as_slice(),
    ] {
        fixture.stores.write_batch(
            &[WriteOp::put("authority.installation", b"binding", bytes)],
            &[WriteOp::put("authority.installation", b"binding", bytes)],
        )?;
        fixture.reject().await?;
    }
    fixture.stores.write_batch(
        &[WriteOp::put(
            "authority.installation",
            b"binding",
            original.clone(),
        )],
        &[WriteOp::put("authority.installation", b"binding", original)],
    )?;
    let original = fixture
        .stores
        .application()
        .get("kasumi.independent-authority", b"meta")?
        .unwrap();
    fixture.stores.application().write_batch(&[WriteOp::put(
        "kasumi.independent-authority",
        b"meta",
        b"not-json",
    )])?;
    fixture.reject().await?;
    fixture.stores.application().write_batch(&[WriteOp::put(
        "kasumi.independent-authority",
        b"meta",
        original,
    )])?;
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn strict_authority_binds_immutable_installation_and_physical_verifier() -> anyhow::Result<()>
{
    let fixture = InstalledFixture::new().await?;
    fixture.initialize()?;
    let before = fixture.retained()?;
    let mut installation = fixture.installation.clone();
    installation.manifest.authority_id = Uuid::new_v4();
    fixture
        .reject_as(
            installation,
            fixture.signing.signer.clone(),
            fixture.settings.clone(),
        )
        .await?;
    let mut verifier = fixture.settings.installed_members[&1].verifier.clone();
    verifier.installation_id = Uuid::new_v4();
    let signer = fixture.signing.for_verifier(verifier.clone())?.signer;
    let mut settings = fixture.settings.clone();
    settings.installed_members.get_mut(&1).unwrap().verifier = verifier;
    fixture
        .reject_as(fixture.installation.clone(), signer, settings)
        .await?;
    assert_eq!(fixture.retained()?, before);
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn strict_authority_reopens_original_genesis_after_complete_owner_drain() -> anyhow::Result<()>
{
    let fixture = InstalledFixture::new().await?;
    fixture.initialize()?;
    let service = fixture.open().await?;
    assert_eq!(service.bootstrap(), &fixture.bootstrap);
    let digest = service.bootstrap_digest().to_owned();
    service.shutdown().await?;
    drop(service);
    let fixture = fixture.reopen().await?;
    let mut duplicate = fixture.settings.clone();
    let alias = format!("{}/", duplicate.installed_members[&1].endpoint);
    duplicate.installed_members.get_mut(&4).unwrap().endpoint = alias;
    assert!(
        duplicate.validate(1).is_err(),
        "normalized endpoint aliases must remain duplicate identities"
    );
    let mut settings = fixture.settings.clone();
    settings.resource_budget_bytes += 1 << 20;
    // An approved endpoint for a not-yet-enrolled learner is operational input;
    // it must not be confused with the authenticated original three voters.
    settings.installed_members.get_mut(&4).unwrap().endpoint =
        "https://replacement-four.test".into();
    let service = fixture
        .open_as(
            fixture.installation.clone(),
            fixture.signing.signer.clone(),
            settings,
        )
        .await?;
    assert_eq!(service.bootstrap(), &fixture.bootstrap);
    assert_eq!(service.bootstrap_digest(), digest);
    assert!(fixture.initialize().is_err());
    service.shutdown().await?;
    drop(service);
    fixture.close().await;
    Ok(())
}
