use super::*;
use kasumi_store::WriteOp;

type RetainedRows = Vec<Vec<(Vec<u8>, Vec<u8>)>>;

struct InstalledFixture {
    physical: PhysicalFixture,
    stores: Arc<TenantStorageSet>,
    installation: AuthorityInstallation,
    bootstrap: crate::AuthorityBootstrap,
    settings: AuthorityNodeSettings,
    signing: kasumi_serving::test_utils::FixtureAuthority,
}
impl InstalledFixture {
    async fn new() -> anyhow::Result<Self> {
        let physical = PhysicalFixture::new()?;
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
        let node = physical.create_new(
            physical.path("authority.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
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
            physical,
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
            request_budget(&self.physical.admission),
            self.physical.admission.snapshot_buffer_owner().unwrap(),
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
        self.stores.shutdown().await.unwrap();
    }
    async fn reopen(self) -> anyhow::Result<Self> {
        self.close().await;
        let Self {
            physical,
            stores,
            installation,
            bootstrap,
            settings,
            signing,
        } = self;
        drop(stores);
        let node = physical.open_existing(
            physical.path("authority.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
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
            physical,
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
async fn strict_authority_rejects_alternate_installation_bytes_and_restores_writer_rows()
-> anyhow::Result<()> {
    let fixture = InstalledFixture::new().await?;
    fixture.initialize()?;
    let verifier = &fixture.settings.installed_members[&1].verifier;
    for (key, diagnostic, paired) in [
        (
            b"binding".as_slice(),
            "noncanonical authority installation descriptor",
            true,
        ),
        (
            b"local-member".as_slice(),
            "noncanonical authority local member",
            true,
        ),
        (
            b"resource-floor".as_slice(),
            "noncanonical authority resource floor",
            false,
        ),
    ] {
        let original = fixture
            .stores
            .application()
            .get("authority.installation", key)?
            .unwrap();
        assert_eq!(
            fixture
                .stores
                .custody()
                .store()
                .get("authority.installation", key)?,
            paired.then(|| original.clone())
        );
        let write = |bytes: &[u8]| -> anyhow::Result<()> {
            if paired {
                fixture.stores.write_batch(
                    &[WriteOp::put("authority.installation", key, bytes)],
                    &[WriteOp::put("authority.installation", key, bytes)],
                )?;
            } else {
                fixture.stores.application().write_batch(&[WriteOp::put(
                    "authority.installation",
                    key,
                    bytes,
                )])?;
            }
            Ok(())
        };
        let mut alternate = original.clone();
        alternate.push(b' ');
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&alternate)?,
            serde_json::from_slice::<serde_json::Value>(&original)?
        );
        write(&alternate)?;
        let Err(error) = crate::bootstrap::load(&fixture.stores, &fixture.installation, verifier)
        else {
            panic!("equivalent alternate bytes must fail");
        };
        assert!(format!("{error:#}").contains(diagnostic), "{error:#}");
        fixture.reject().await?;
        write(&original)?;
        let restored = crate::bootstrap::load(&fixture.stores, &fixture.installation, verifier)?;
        assert_eq!(
            restored.binding,
            fixture
                .stores
                .application()
                .get("authority.installation", b"binding")?
                .unwrap()
        );
    }
    let service = fixture.open().await?;
    assert_eq!(service.bootstrap(), &fixture.bootstrap);
    service.shutdown().await?;
    drop(service);
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

#[tokio::test]
async fn live_maintenance_resource_floor_rejects_alternate_bytes_and_accepts_restored_writer_bytes()
-> anyhow::Result<()> {
    let fixture = InstalledFixture::new().await?;
    fixture.initialize()?;
    let service = fixture.open().await?;
    let original = fixture
        .stores
        .application()
        .get("authority.installation", b"resource-floor")?
        .unwrap();
    let mut alternate = original.clone();
    alternate.push(b' ');
    assert_eq!(
        serde_json::from_slice::<u64>(&alternate)?,
        serde_json::from_slice::<u64>(&original)?
    );
    fixture.stores.application().write_batch(&[WriteOp::put(
        "authority.installation",
        b"resource-floor",
        alternate.as_slice(),
    )])?;
    let Err(error) = service.backend.reserve_node_resources(0) else {
        panic!("live maintenance accepted alternate resource-floor bytes");
    };
    assert!(
        format!("{error:#}").contains("noncanonical authority resource floor"),
        "{error:#}"
    );
    assert_eq!(
        fixture
            .stores
            .application()
            .get("authority.installation", b"resource-floor")?,
        Some(alternate)
    );
    fixture.stores.application().write_batch(&[WriteOp::put(
        "authority.installation",
        b"resource-floor",
        original.as_slice(),
    )])?;
    service.backend.reserve_node_resources(0)?;
    assert_eq!(
        fixture
            .stores
            .application()
            .get("authority.installation", b"resource-floor")?,
        Some(original)
    );
    service.shutdown().await?;
    drop(service);
    fixture.close().await;
    Ok(())
}
