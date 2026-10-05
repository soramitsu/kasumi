use super::*;
use kasumi_store::WriteOp;

type RetainedRows = Vec<kasumi_store::PlaintextScan>;

/// Copies used to alter authenticated fixture rows own their installed credit
/// through the production writer. The operation's buffers retire first.
pub(super) struct AdmittedFixturePut {
    operation: WriteOp,
    _charge: kasumi_store::DiskMemoryLease,
}
impl AdmittedFixturePut {
    fn prepare(
        store: &kasumi_store::TenantStore,
        namespace: &str,
        key: &[u8],
        value_len: usize,
        fill: impl FnOnce(&mut Vec<u8>),
    ) -> anyhow::Result<Self> {
        // Each actual buffer has a checked allocator allowance; the installed
        // provider separately accounts for its opaque reservation token.
        const ALLOCATION_ALLOWANCE: usize = 4096;
        let namespace_bound = namespace
            .len()
            .checked_add(ALLOCATION_ALLOWANCE)
            .ok_or_else(|| anyhow::anyhow!("fixture namespace allocation overflow"))?;
        let key_bound = key
            .len()
            .checked_add(ALLOCATION_ALLOWANCE)
            .ok_or_else(|| anyhow::anyhow!("fixture key allocation overflow"))?;
        let value_bound = value_len
            .checked_add(ALLOCATION_ALLOWANCE)
            .ok_or_else(|| anyhow::anyhow!("fixture value allocation overflow"))?;
        let admitted = namespace_bound
            .checked_add(key_bound)
            .and_then(|bytes| bytes.checked_add(value_bound))
            .ok_or_else(|| anyhow::anyhow!("fixture write allocation overflow"))?;
        let charge = store
            .plaintext_memory_owner()
            .clone()
            .reserve_installed(u64::try_from(admitted)?)?;
        let mut namespace_buffer = String::new();
        namespace_buffer.try_reserve_exact(namespace.len())?;
        anyhow::ensure!(
            namespace_buffer.capacity() <= namespace_bound,
            "fixture namespace allocation exceeded admission"
        );
        namespace_buffer.push_str(namespace);
        let mut key_buffer = Vec::new();
        key_buffer.try_reserve_exact(key.len())?;
        anyhow::ensure!(
            key_buffer.capacity() <= key_bound,
            "fixture key allocation exceeded admission"
        );
        key_buffer.extend_from_slice(key);
        let mut value_buffer = Vec::new();
        value_buffer.try_reserve_exact(value_len)?;
        anyhow::ensure!(
            value_buffer.capacity() <= value_bound,
            "fixture value allocation exceeded admission"
        );
        fill(&mut value_buffer);
        anyhow::ensure!(
            value_buffer.len() == value_len && value_buffer.capacity() <= value_bound,
            "fixture value construction exceeded admission"
        );
        Ok(Self {
            operation: WriteOp::put(namespace_buffer, key_buffer, value_buffer),
            _charge: charge,
        })
    }
    pub(super) fn copy(
        store: &kasumi_store::TenantStore,
        namespace: &str,
        key: &[u8],
        value: &[u8],
    ) -> anyhow::Result<Self> {
        Self::with_suffix(store, namespace, key, value, &[])
    }
    pub(super) fn with_suffix(
        store: &kasumi_store::TenantStore,
        namespace: &str,
        key: &[u8],
        prefix: &[u8],
        suffix: &[u8],
    ) -> anyhow::Result<Self> {
        let value_len = prefix
            .len()
            .checked_add(suffix.len())
            .ok_or_else(|| anyhow::anyhow!("fixture value length overflow"))?;
        Self::prepare(store, namespace, key, value_len, |value| {
            value.extend_from_slice(prefix);
            value.extend_from_slice(suffix);
        })
    }
    pub(super) fn replace(
        store: &kasumi_store::TenantStore,
        namespace: &str,
        key: &[u8],
        source: &[u8],
        needle: &str,
        replacement: &str,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(!needle.is_empty(), "fixture replacement needle is empty");
        let source = std::str::from_utf8(source)?;
        let matches = source.match_indices(needle).count();
        let removed = matches
            .checked_mul(needle.len())
            .ok_or_else(|| anyhow::anyhow!("fixture replacement length overflow"))?;
        let added = matches
            .checked_mul(replacement.len())
            .ok_or_else(|| anyhow::anyhow!("fixture replacement length overflow"))?;
        let value_len = source
            .len()
            .checked_sub(removed)
            .and_then(|bytes| bytes.checked_add(added))
            .ok_or_else(|| anyhow::anyhow!("fixture replacement length overflow"))?;
        Self::prepare(store, namespace, key, value_len, |value| {
            let mut start = 0;
            for (index, _) in source.match_indices(needle) {
                value.extend_from_slice(&source.as_bytes()[start..index]);
                value.extend_from_slice(replacement.as_bytes());
                start = index + needle.len();
            }
            value.extend_from_slice(&source.as_bytes()[start..]);
        })
    }
    pub(super) fn operations(&self) -> &[WriteOp] {
        std::slice::from_ref(&self.operation)
    }
    pub(super) fn value(&self) -> &[u8] {
        let WriteOp::Put { value, .. } = &self.operation else {
            unreachable!("fixture owner contains only Put")
        };
        value
    }
}

struct InstalledFixture {
    physical: PhysicalFixture,
    stores: Arc<TenantStorageSet>,
    node: NodeStore,
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
        let node = physical
            .create_new(
                physical.path("authority.kv"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .expect("bounded installed authority fixture must create its original node");
        let stores = TenantStorageSet::initialize_catalogs(
            node.clone(),
            installation.tenant(),
            Arc::new(LocalKeyProvider::new([31; 32])),
            Arc::new(LocalKeyProvider::new([32; 32])),
            kasumi_store::StorageAccess::independent_authority(&installation.manifest, 0)?,
        )
        .await?;
        Ok(Self {
            physical,
            stores,
            node,
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
    async fn open(
        &self,
    ) -> std::result::Result<Arc<IndependentAuthority>, kasumi_store::ScratchOperationFailure> {
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
    ) -> std::result::Result<Arc<IndependentAuthority>, kasumi_store::ScratchOperationFailure> {
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
        self.node.shutdown().await.unwrap();
    }
    async fn reopen(self) -> anyhow::Result<Self> {
        self.close().await;
        let Self {
            physical,
            stores,
            node,
            installation,
            bootstrap,
            settings,
            signing,
        } = self;
        drop(stores);
        drop(node);
        let node = physical
            .open_existing(
                physical.path("authority.kv"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .expect("positively drained authority fixture must reopen its original node");
        let stores = TenantStorageSet::open_existing(
            node.clone(),
            installation.tenant(),
            Arc::new(LocalKeyProvider::new([31; 32])),
            Arc::new(LocalKeyProvider::new([32; 32])),
            kasumi_store::StorageAccess::independent_authority(&installation.manifest, 0)?,
        )
        .await?;
        Ok(Self {
            physical,
            stores,
            node,
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
        let inject = |operation| {
            if custody {
                kasumi_store::test_utils::inject_authenticated_rows_below_facade(
                    fixture.stores.as_ref(),
                    &[],
                    &[operation],
                )
            } else {
                kasumi_store::test_utils::inject_authenticated_rows_below_facade(
                    fixture.stores.as_ref(),
                    &[operation],
                    &[],
                )
            }
        };
        let original = store.get(namespace, key)?.unwrap();
        inject(WriteOp::delete(namespace, key))?;
        fixture.reject().await?;
        let before = fixture.retained()?;
        assert!(
            fixture.initialize().is_err(),
            "partial installation cannot initialize again"
        );
        assert_eq!(fixture.retained()?, before);
        let restoration = AdmittedFixturePut::copy(store, namespace, key, original.as_bytes())?;
        let operations = restoration.operations();
        if custody {
            kasumi_store::test_utils::inject_authenticated_rows_below_facade(
                fixture.stores.as_ref(),
                &[],
                operations,
            )?;
        } else {
            kasumi_store::test_utils::inject_authenticated_rows_below_facade(
                fixture.stores.as_ref(),
                operations,
                &[],
            )?;
        }
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
    let restoration = AdmittedFixturePut::copy(
        fixture.stores.application(),
        "authority.installation",
        b"binding",
        original.as_bytes(),
    )?;
    fixture
        .stores
        .write_batch(restoration.operations(), restoration.operations())?;
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
    let restoration = AdmittedFixturePut::copy(
        fixture.stores.application(),
        "kasumi.independent-authority",
        b"meta",
        original.as_bytes(),
    )?;
    fixture
        .stores
        .application()
        .write_batch(restoration.operations())?;
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn strict_authority_rejects_alternate_installation_bytes_and_restores_writer_rows()
-> FixtureResult<()> {
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
                .get("authority.installation", key)?
                .as_deref(),
            paired.then_some(original.as_bytes())
        );
        let write = |operation: &AdmittedFixturePut| -> anyhow::Result<()> {
            if paired {
                fixture
                    .stores
                    .write_batch(operation.operations(), operation.operations())?;
            } else {
                fixture
                    .stores
                    .application()
                    .write_batch(operation.operations())?;
            }
            Ok(())
        };
        let alternate = AdmittedFixturePut::with_suffix(
            fixture.stores.application(),
            "authority.installation",
            key,
            original.as_bytes(),
            b" ",
        )?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(alternate.value())?,
            serde_json::from_slice::<serde_json::Value>(&original)?
        );
        write(&alternate)?;
        let Err(error) = crate::bootstrap::load(&fixture.stores, &fixture.installation, verifier)
        else {
            panic!("equivalent alternate bytes must fail");
        };
        assert!(format!("{error:#}").contains(diagnostic), "{error:#}");
        fixture.reject().await?;
        let restoration = AdmittedFixturePut::copy(
            fixture.stores.application(),
            "authority.installation",
            key,
            original.as_bytes(),
        )?;
        write(&restoration)?;
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
async fn strict_authority_reopens_original_genesis_after_complete_owner_drain() -> FixtureResult<()>
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
-> FixtureResult<()> {
    let fixture = InstalledFixture::new().await?;
    fixture.initialize()?;
    let service = fixture.open().await?;
    let original = fixture
        .stores
        .application()
        .get("authority.installation", b"resource-floor")?
        .unwrap();
    let alternate = AdmittedFixturePut::with_suffix(
        fixture.stores.application(),
        "authority.installation",
        b"resource-floor",
        original.as_bytes(),
        b" ",
    )?;
    assert_eq!(
        serde_json::from_slice::<u64>(alternate.value())?,
        serde_json::from_slice::<u64>(&original)?
    );
    fixture
        .stores
        .application()
        .write_batch(alternate.operations())?;
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
            .get("authority.installation", b"resource-floor")?
            .as_deref(),
        Some(alternate.value())
    );
    let restoration = AdmittedFixturePut::copy(
        fixture.stores.application(),
        "authority.installation",
        b"resource-floor",
        original.as_bytes(),
    )?;
    fixture
        .stores
        .application()
        .write_batch(restoration.operations())?;
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
