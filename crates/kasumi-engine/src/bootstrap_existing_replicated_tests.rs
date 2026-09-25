use super::*;
use kasumi_raft::InProcessRouter;
use kasumi_store::{NodeStore, test_utils::LocalKeyProvider};
use std::time::Duration;

const NODE_STORE_ID: uuid::Uuid = uuid::Uuid::from_u128(0xa1f9_93e5_2727_480a_9e7c_6e39_eb51_5f01);

struct Replica {
    storage: crate::test_utils::FixtureStorage,
    node: Arc<NodeStore>,
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
    directory: tempfile::TempDir,
}
impl Replica {
    async fn new() -> anyhow::Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (persistent_config, scratch_config) =
            crate::test_utils::fixture_disk_configs(directory.path())?;
        // Keep the 128 MiB ordinary margin available alongside the installed
        // security audit and maintenance owners. Add the physical metadata.
        let config = crate::admission::AdmissionConfig {
            max_inflight_bytes: Some(
                (384_u64 << 20)
                    .checked_add(crate::test_utils::isolated_disk_metadata_bytes(
                        &persistent_config,
                        &scratch_config,
                    )?)
                    .ok_or_else(|| anyhow::anyhow!("fixture metadata budget overflow"))?,
            ),
            ..Default::default()
        };
        let admission = crate::admission::NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
        let storage = crate::test_utils::FixtureStorage::with_admission(
            &persistent_config,
            &scratch_config,
            admission.clone(),
        )?;
        let node =
            storage.create_new(directory.path().join("persistent/node.kv"), NODE_STORE_ID)?;
        let stores = TenantStorageSet::initialize_catalogs_fixture(
            node.clone(),
            "replica".into(),
            Arc::new(LocalKeyProvider::new([31; 32])),
            Arc::new(LocalKeyProvider::new([32; 32])),
        )
        .await?;
        let audit = Self::audit(node.clone(), false, storage.admission.clone()).await?;
        Ok(Self {
            directory,
            storage,
            node,
            stores,
            audit,
        })
    }
    async fn existing(
        (directory, storage): (tempfile::TempDir, crate::test_utils::FixtureStorage),
    ) -> anyhow::Result<Self> {
        let node =
            storage.open_existing(directory.path().join("persistent/node.kv"), NODE_STORE_ID)?;
        let stores = TenantStorageSet::open_existing_fixture(
            node.clone(),
            "replica".into(),
            Arc::new(LocalKeyProvider::new([31; 32])),
            Arc::new(LocalKeyProvider::new([32; 32])),
        )
        .await?;
        let audit = Self::audit(node.clone(), true, storage.admission.clone()).await?;
        Ok(Self {
            directory,
            storage,
            node,
            stores,
            audit,
        })
    }
    async fn audit(
        node: Arc<NodeStore>,
        existing: bool,
        admission: Arc<crate::admission::NodeAdmission>,
    ) -> anyhow::Result<Arc<SecurityAudit>> {
        let provider = Arc::new(LocalKeyProvider::new([33; 32]));
        let store = if existing {
            TenantStore::open_existing_fixture(node, crate::SECURITY_TENANT.into(), provider)
                .await?
        } else {
            TenantStore::initialize_catalog_fixture(node, crate::SECURITY_TENANT.into(), provider)
                .await?
        };
        if existing {
            SecurityAudit::open(store, Default::default(), admission)
        } else {
            SecurityAudit::initialize(store, Default::default(), admission)
        }
    }
    async fn close(self) -> (tempfile::TempDir, crate::test_utils::FixtureStorage) {
        self.stores.shutdown().await.unwrap();
        self.audit.shutdown().await.unwrap();
        self.node.shutdown().await.unwrap();
        let Self {
            directory,
            storage,
            stores,
            audit,
            node,
        } = self;
        drop(stores);
        drop(audit);
        drop(node);
        (directory, storage)
    }
    fn seed(
        &self,
        installed: &ReplicatedBootstrap,
        actual_incarnation: &str,
    ) -> anyhow::Result<()> {
        bind_deployment(
            &self.stores,
            &serde_json::to_vec(&("replicated", installed))?,
        )?;
        persist_new(&self.stores, &self.image(installed, actual_incarnation)?)
    }
    fn image(
        &self,
        installed: &ReplicatedBootstrap,
        actual_incarnation: &str,
    ) -> anyhow::Result<SnapshotImage> {
        let engine = TenantEngine::new(
            "replica".into(),
            actual_incarnation.into(),
            installed.initial_policy.clone(),
            installed.initial_limits.clone(),
        )?;
        Ok(engine.logical_snapshot(self.node.scratch_disk())?)
    }
    fn first_publish_image(
        &self,
        image: &SnapshotImage,
        manifest_bytes: Vec<u8>,
        custody_digest: &str,
        incarnation: &str,
        first_chunk: Option<Vec<u8>>,
        omit_first_chunk: bool,
    ) -> anyhow::Result<()> {
        let mut reader = image.reader();
        let chunks = image.len().div_ceil(CHUNK as u64);
        for index in 0..chunks {
            let mut chunk =
                vec![0; (image.len() - index * CHUNK as u64).min(CHUNK as u64) as usize];
            reader.read_exact(&mut chunk)?;
            if index == 0 {
                if omit_first_chunk {
                    continue;
                }
                chunk = first_chunk.clone().unwrap_or(chunk);
            }
            self.stores.application().write_batch(&[WriteOp::put(
                NS,
                index.to_be_bytes(),
                chunk,
            )])?;
        }
        let [node_id, group] = kasumi_raft::initial_storage_identity(
            1,
            &format!("{}/{}", self.stores.application().tenant(), incarnation),
        )?;
        self.stores.write_batch(
            &[WriteOp::put(NS, b"manifest", manifest_bytes)],
            &[
                WriteOp::put(
                    "raft.meta",
                    b"application_bootstrap_sha256",
                    serde_json::to_vec(custody_digest)?,
                ),
                node_id,
                group,
            ],
        )
    }
    async fn reject(
        &self,
        node_id: u64,
        expected_incarnation: uuid::Uuid,
        expected: &str,
    ) -> anyhow::Result<()> {
        let before = retained(&self.stores)?;
        let error = open_existing_replicated(
            node_id,
            self.stores.clone(),
            expected_incarnation,
            Arc::new(InProcessRouter::default()),
            raft_config(),
            self.audit.clone(),
        )
        .await
        .err()
        .expect("invalid existing replica must fail");
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert_eq!(retained(&self.stores)?, before);
        Ok(())
    }
}

fn manifest_for(image: &SnapshotImage) -> Manifest {
    Manifest {
        format: 2,
        bytes: image.len(),
        chunks: image.len().div_ceil(CHUNK as u64),
        digest: image.sha256().to_owned(),
    }
}

async fn reject_first_installed_descriptor(
    installed: &ReplicatedBootstrap,
    bytes: &[u8],
    diagnostic: &str,
) -> anyhow::Result<()> {
    let fixture = Replica::new().await?;
    fixture.stores.write_batch(
        &[WriteOp::put("engine.deployment", b"mode", bytes)],
        &[WriteOp::put("engine.deployment", b"mode", bytes)],
    )?;
    let image = fixture.image(installed, &installed.incarnation)?;
    persist_new(&fixture.stores, &image)?;
    fixture
        .reject(
            1,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            diagnostic,
        )
        .await?;
    drop(image);
    drop(fixture.close().await);
    Ok(())
}

fn bootstrap() -> ReplicatedBootstrap {
    ReplicatedBootstrap {
        genesis: crate::ReplicatedGenesis::Application,
        incarnation: uuid::Uuid::new_v4().to_string(),
        initial_policy: Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: BTreeSet::from([Action::Admin]),
            }],
            strict_read_audit: false,
        },
        initial_limits: Limits::default(),
        voters: (1..=3)
            .map(|id| {
                (
                    id,
                    ReplicaPlacement {
                        address: format!("replica-{id}"),
                        failure_domain: format!("zone-{id}"),
                    },
                )
            })
            .collect(),
    }
}
fn raft_config() -> Config {
    Config {
        election_timeout_min: 200,
        election_timeout_max: 400,
        heartbeat_interval: 50,
        ..Default::default()
    }
}
fn retained(stores: &TenantStorageSet) -> anyhow::Result<String> {
    let mut digest = Sha256::new();
    for (index, store) in [stores.application(), stores.custody().store()]
        .into_iter()
        .enumerate()
    {
        digest.update((index as u64).to_be_bytes());
        for namespace in [
            NS,
            "engine.deployment",
            "engine.audit.placement",
            "raft.meta",
            "raft.headers",
        ] {
            digest.update(namespace.as_bytes());
            store.visit(namespace, 16 << 20, |key, value| {
                digest.update((key.len() as u64).to_be_bytes());
                digest.update(key);
                digest.update((value.len() as u64).to_be_bytes());
                digest.update(value);
                Ok(())
            })?;
        }
    }
    Ok(hex::encode(digest.finalize()))
}

#[tokio::test]
async fn installed_raft_identity_uses_the_bootstrap_view_generation() -> anyhow::Result<()> {
    let fixture = Replica::new().await?;
    let custody = fixture.stores.custody().store();
    fixture.stores.write_batch(
        &[],
        &[
            WriteOp::put("raft.meta", b"node_id", b"1"),
            WriteOp::put("raft.meta", b"group", b"\"replica/first\""),
        ],
    )?;
    let view = fixture.stores.read_view()?;
    assert!(
        custody
            .write_batch(&[
                WriteOp::put("raft.meta", b"node_id", b"2"),
                WriteOp::put("raft.meta", b"group", b"\"replica/second\""),
            ])
            .is_err()
    );
    assert_eq!(
        kasumi_raft::ControlLog::installed_identity_at(&view)?,
        Some((1, "replica/first".into()))
    );
    drop(view);
    assert_eq!(
        kasumi_raft::ControlLog::installed_identity_at(&fixture.stores.read_view()?)?,
        Some((1, "replica/first".into()))
    );
    drop(fixture.close().await);
    Ok(())
}

#[tokio::test]
async fn physical_a_to_b_generation_keeps_pinned_bootstrap_and_reopens_only_b() -> anyhow::Result<()>
{
    use kasumi_store::test_utils::inject_authenticated_rows_below_facade;

    let fixture = Replica::new().await?;
    let installed_a = bootstrap();
    fixture.seed(&installed_a, &installed_a.incarnation)?;
    let old = fixture.stores.read_view()?;
    let image_a = load_at(&old, fixture.node.scratch_disk())?.expect("A image");
    validate_bootstrap_control_at(&old, &image_a)?;
    assert_eq!(
        kasumi_raft::ControlLog::installed_identity_at(&old)?,
        Some((1, format!("replica/{}", installed_a.incarnation)))
    );

    let installed_b = bootstrap();
    let image_b = fixture.image(&installed_b, &installed_b.incarnation)?;
    assert_ne!(image_a.sha256(), image_b.sha256());
    let binding_b = serde_json::to_vec(&("replicated", &installed_b))?;
    let mut application_b = vec![WriteOp::put(
        "engine.deployment",
        b"mode",
        binding_b.clone(),
    )];
    let mut reader = image_b.reader();
    for index in 0..image_b.len().div_ceil(CHUNK as u64) {
        let mut chunk = vec![0; (image_b.len() - index * CHUNK as u64).min(CHUNK as u64) as usize];
        reader.read_exact(&mut chunk)?;
        application_b.push(WriteOp::put(NS, index.to_be_bytes(), chunk));
    }
    application_b.push(WriteOp::put(
        NS,
        b"manifest",
        serde_json::to_vec(&manifest_for(&image_b))?,
    ));
    let custody_b = [
        WriteOp::put("engine.deployment", b"mode", binding_b),
        WriteOp::put(
            "raft.meta",
            b"application_bootstrap_sha256",
            serde_json::to_vec(image_b.sha256())?,
        ),
        WriteOp::put("raft.meta", b"node_id", serde_json::to_vec(&2_u64)?),
        WriteOp::put(
            "raft.meta",
            b"group",
            serde_json::to_vec(&format!("replica/{}", installed_b.incarnation))?,
        ),
    ];
    assert!(
        fixture
            .stores
            .write_batch(&application_b, &custody_b)
            .is_err()
    );
    inject_authenticated_rows_below_facade(&fixture.stores, &application_b, &custody_b)?;

    // The old view still sees only A, including its independently encrypted
    // descriptor, manifest/chunks, digest, and Raft node/group rows.
    assert_eq!(
        installed_replicated_bootstrap(&old, uuid::Uuid::parse_str(&installed_a.incarnation)?)?
            .0
            .incarnation,
        installed_a.incarnation
    );
    let pinned_image = load_at(&old, fixture.node.scratch_disk())?.expect("pinned A image");
    assert_eq!(pinned_image.sha256(), image_a.sha256());
    validate_bootstrap_control_at(&old, &pinned_image)?;
    assert_eq!(
        kasumi_raft::ControlLog::installed_identity_at(&old)?,
        Some((1, format!("replica/{}", installed_a.incarnation)))
    );
    let newer = fixture.stores.read_view()?;
    assert_eq!(
        installed_replicated_bootstrap(&newer, uuid::Uuid::parse_str(&installed_b.incarnation)?)?
            .0
            .incarnation,
        installed_b.incarnation
    );
    let new_image = load_at(&newer, fixture.node.scratch_disk())?.expect("B image");
    assert_eq!(new_image.sha256(), image_b.sha256());
    validate_bootstrap_control_at(&newer, &new_image)?;
    assert_eq!(
        kasumi_raft::ControlLog::installed_identity_at(&newer)?,
        Some((2, format!("replica/{}", installed_b.incarnation)))
    );
    drop((old, newer, image_a, image_b, pinned_image, new_image));

    let reopened = Replica::existing(fixture.close().await).await?;
    reopened
        .reject(
            1,
            uuid::Uuid::parse_str(&installed_a.incarnation)?,
            "installed replicated genesis differs from expected incarnation",
        )
        .await?;
    let opened = open_existing_replicated(
        2,
        reopened.stores.clone(),
        uuid::Uuid::parse_str(&installed_b.incarnation)?,
        Arc::new(InProcessRouter::default()),
        raft_config(),
        reopened.audit.clone(),
    )
    .await?;
    assert_eq!(opened.bootstrap.incarnation, installed_b.incarnation);
    assert_eq!(opened.database.raft_group().raft().metrics().borrow().id, 2);
    opened.database.shutdown().await?;
    drop(opened.database);
    drop(reopened.close().await);
    Ok(())
}

#[tokio::test]
async fn one_sided_physical_identity_fault_after_pin_rejects_existing_reopen() -> anyhow::Result<()>
{
    use kasumi_store::test_utils::inject_authenticated_rows_below_facade;

    for case in 0..3 {
        let fixture = Replica::new().await?;
        let installed = bootstrap();
        fixture.seed(&installed, &installed.incarnation)?;
        let old = fixture.stores.read_view()?;
        let image = load_at(&old, fixture.node.scratch_disk())?.expect("installed image");
        let expected_identity = Some((1, format!("replica/{}", installed.incarnation)));
        let (application_fault, custody_fault, diagnostic) = match case {
            0 => (
                vec![],
                vec![WriteOp::put(
                    "raft.meta",
                    b"node_id",
                    serde_json::to_vec(&2_u64)?,
                )],
                "consensus identity differs",
            ),
            1 => (
                vec![],
                vec![WriteOp::delete("raft.meta", b"group")],
                "installed consensus identity is incomplete",
            ),
            _ => (
                vec![],
                vec![WriteOp::put(
                    "raft.meta",
                    b"application_bootstrap_sha256",
                    serde_json::to_vec("wrong")?,
                )],
                "application bootstrap/control identity differs",
            ),
        };
        assert!(
            fixture
                .stores
                .write_batch(&application_fault, &custody_fault)
                .is_err()
        );
        inject_authenticated_rows_below_facade(
            &fixture.stores,
            &application_fault,
            &custody_fault,
        )?;

        let old_image = load_at(&old, fixture.node.scratch_disk())?.expect("pinned A image");
        assert_eq!(old_image.sha256(), image.sha256());
        validate_bootstrap_control_at(&old, &old_image)?;
        assert_eq!(
            kasumi_raft::ControlLog::installed_identity_at(&old)?,
            expected_identity
        );
        let current = fixture.stores.read_view()?;
        if case == 1 {
            assert!(kasumi_raft::ControlLog::installed_identity_at(&current).is_err());
        } else if case == 0 {
            assert_eq!(
                kasumi_raft::ControlLog::installed_identity_at(&current)?,
                Some((2, format!("replica/{}", installed.incarnation)))
            );
        } else {
            assert!(validate_bootstrap_control_at(&current, &image).is_err());
        }
        drop((old, current, old_image, image));
        let reopened = Replica::existing(fixture.close().await).await?;
        reopened
            .reject(
                1,
                uuid::Uuid::parse_str(&installed.incarnation)?,
                diagnostic,
            )
            .await?;
        drop(reopened.close().await);
    }
    Ok(())
}

#[tokio::test]
async fn existing_replica_never_creates_missing_bootstrap_or_changes_consensus_identity()
-> anyhow::Result<()> {
    let fixture = Replica::new().await?;
    let installed = bootstrap();
    fixture
        .reject(
            1,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            "required deployment binding",
        )
        .await?;
    bind_deployment(
        &fixture.stores,
        &serde_json::to_vec(&("replicated", &installed))?,
    )?;
    fixture
        .reject(
            1,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            "replicated bootstrap is not initialized",
        )
        .await?;
    fixture.seed(&installed, &installed.incarnation)?;
    assert_eq!(
        kasumi_raft::ControlLog::installed_identity_at(&fixture.stores.read_view()?)?,
        Some((1, format!("replica/{}", installed.incarnation)))
    );
    assert!(
        fixture
            .stores
            .write_batch(&[], &[WriteOp::put("raft.meta", b"node_id", b"1")])
            .is_err()
    );
    fixture.stores.write_batch(
        &[],
        &[
            WriteOp::put("raft.meta", b"node_id", b"1"),
            WriteOp::put(
                "raft.meta",
                b"group",
                serde_json::to_vec(&format!("replica/{}", installed.incarnation))?,
            ),
        ],
    )?;
    fixture
        .reject(
            2,
            uuid::Uuid::parse_str(&installed.incarnation)?,
            "consensus identity differs",
        )
        .await?;
    assert!(
        fixture
            .stores
            .custody()
            .store()
            .write_batch(&[WriteOp::put("raft.meta", b"group", b"\"another/group\"",)])
            .is_err()
    );
    drop(fixture.close().await);
    Ok(())
}

#[tokio::test]
async fn existing_replica_rejects_corrupt_manifest_body_and_authenticated_incarnation()
-> anyhow::Result<()> {
    let installed = bootstrap();
    let expected = uuid::Uuid::parse_str(&installed.incarnation)?;
    for case in 0..5 {
        let fixture = Replica::new().await?;
        let binding = serde_json::to_vec(&("replicated", &installed))?;
        bind_deployment(&fixture.stores, &binding)?;
        let image = fixture.image(&installed, &installed.incarnation)?;
        let mut manifest = manifest_for(&image);
        if case == 0 {
            manifest.format = 99;
        }
        let manifest_bytes = if case == 1 {
            b"{".to_vec()
        } else {
            serde_json::to_vec(&manifest)?
        };
        let mut first_chunk = None;
        if case == 3 {
            let mut reader = image.reader();
            let mut corrupt = vec![0; image.len().min(CHUNK as u64) as usize];
            reader.read_exact(&mut corrupt)?;
            corrupt[0] ^= 1;
            first_chunk = Some(corrupt);
        }
        fixture.first_publish_image(
            &image,
            manifest_bytes,
            if case == 4 { "wrong" } else { image.sha256() },
            &installed.incarnation,
            first_chunk,
            case == 2,
        )?;
        let diagnostic = match case {
            0 => "invalid bootstrap manifest",
            1 => "EOF",
            2 => "incomplete bootstrap",
            3 => "bootstrap digest mismatch",
            4 => "bootstrap/control identity differs",
            _ => unreachable!(),
        };
        fixture.reject(1, expected, diagnostic).await?;
        drop(image);
        drop(fixture.close().await);
    }
    let fixture = Replica::new().await?;
    fixture.seed(&installed, &uuid::Uuid::new_v4().to_string())?;
    fixture
        .reject(1, expected, "replicated incarnation differs from bootstrap")
        .await?;
    drop(fixture.close().await);
    Ok(())
}

#[tokio::test]
async fn paired_bootstrap_guard_rejects_orphan_divergence_and_reader_rejects_alternate_bytes()
-> anyhow::Result<()> {
    let fixture = Replica::new().await?;
    let descriptor = bootstrap();
    let expected = uuid::Uuid::parse_str(&descriptor.incarnation)?;
    let binding = serde_json::to_vec(&("replicated", &descriptor))?;
    let pristine = retained(&fixture.stores)?;
    // One-sided initial publication is forbidden by the writable facade.
    assert!(
        fixture
            .stores
            .custody()
            .store()
            .write_batch(&[WriteOp::put(
                "engine.deployment",
                b"mode",
                binding.as_slice()
            )])
            .is_err()
    );
    assert!(
        fixture
            .stores
            .application()
            .write_batch(&[WriteOp::put(
                "engine.deployment",
                b"mode",
                binding.as_slice()
            )])
            .is_err()
    );
    assert!(
        fixture
            .stores
            .write_batch(
                &[WriteOp::put(
                    "engine.deployment",
                    b"mode",
                    binding.as_slice()
                )],
                &[WriteOp::put("engine.deployment", b"mode", b"local-v1")],
            )
            .is_err()
    );
    assert_eq!(retained(&fixture.stores)?, pristine);
    drop(fixture.close().await);

    let fixture = Replica::new().await?;
    let mut alternate = binding.clone();
    alternate.push(b' ');
    fixture.stores.write_batch(
        &[WriteOp::put(
            "engine.deployment",
            b"mode",
            alternate.as_slice(),
        )],
        &[WriteOp::put(
            "engine.deployment",
            b"mode",
            alternate.as_slice(),
        )],
    )?;
    let noncanonical = retained(&fixture.stores)?;
    let error = match installed_replicated_bootstrap(&fixture.stores.read_view()?, expected) {
        Ok(_) => panic!("equal alternate bytes must fail"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("trailing deployment bytes"));
    assert_eq!(retained(&fixture.stores)?, noncanonical);
    drop(fixture.close().await);
    Ok(())
}

#[tokio::test]
async fn existing_replica_validates_authenticated_genesis_tag_domains_and_descriptor()
-> anyhow::Result<()> {
    let fixture = Replica::new().await?;
    let installed = bootstrap();
    let expected = uuid::Uuid::parse_str(&installed.incarnation)?;
    fixture.seed(&installed, &installed.incarnation)?;
    fixture
        .reject(1, uuid::Uuid::nil(), "nil expected replicated incarnation")
        .await?;
    fixture
        .reject(1, uuid::Uuid::new_v4(), "differs from expected incarnation")
        .await?;
    let binding = serde_json::to_vec(&("replicated", &installed))?;
    let (restored, restored_binding) =
        installed_replicated_bootstrap(&fixture.stores.read_view()?, expected)?;
    assert_eq!(serde_json::to_vec(&("replicated", &restored))?, binding);
    assert_eq!(restored_binding.as_bytes(), binding);
    // An installed descriptor cannot be changed through a live custody
    // facade. A physically altered copy needs a separate offline fault test.
    assert!(
        fixture
            .stores
            .custody()
            .store()
            .write_batch(&[WriteOp::put("engine.deployment", b"mode", b"other")])
            .is_err()
    );
    assert!(
        fixture
            .stores
            .custody()
            .store()
            .write_batch(&[WriteOp::delete("engine.deployment", b"mode")])
            .is_err()
    );
    drop(fixture.close().await);

    reject_first_installed_descriptor(
        &installed,
        &serde_json::to_vec(&("local", &installed))?,
        "unsupported deployment field or enum",
    )
    .await?;
    reject_first_installed_descriptor(&installed, b"{", "unexpected deployment token").await?;
    let canonical = std::str::from_utf8(&binding)?;
    reject_first_installed_descriptor(
        &installed,
        canonical.replace("\"1\":", "\"01\":").as_bytes(),
        "invalid numeric map key",
    )
    .await?;

    for field in 0..5 {
        let mut invalid = installed.clone();
        let diagnostic = match field {
            0 => {
                invalid.incarnation = uuid::Uuid::nil().to_string();
                "nil replicated incarnation"
            }
            1 => {
                invalid.voters.remove(&3);
                "exactly three initial voters"
            }
            2 => {
                invalid.voters.get_mut(&2).unwrap().failure_domain = "zone-1".into();
                "independent failure domains"
            }
            3 => {
                invalid.initial_policy.grants.clear();
                "tenant needs an administrator"
            }
            4 => {
                invalid.initial_limits.history.max_feed_events = 0;
                "invalid history resource limits"
            }
            _ => unreachable!(),
        };
        reject_first_installed_descriptor(
            &installed,
            &serde_json::to_vec(&("replicated", &invalid))?,
            diagnostic,
        )
        .await?;
    }
    let mut whitespace = binding.clone();
    whitespace.push(b' ');
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&whitespace)?,
        serde_json::from_slice::<serde_json::Value>(&binding)?
    );
    reject_first_installed_descriptor(&installed, &whitespace, "trailing deployment bytes").await?;
    let mut altered = installed.clone();
    altered.initial_policy.strict_read_audit = !altered.initial_policy.strict_read_audit;
    reject_first_installed_descriptor(
        &installed,
        &serde_json::to_vec(&("replicated", &altered))?,
        "initial policy differs from bootstrap image",
    )
    .await?;
    altered = installed.clone();
    altered.initial_limits.max_documents += 1;
    reject_first_installed_descriptor(
        &installed,
        &serde_json::to_vec(&("replicated", &altered))?,
        "initial limits differ from bootstrap image",
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn target_deployment_requires_paired_current_writer_bytes() -> anyhow::Result<()> {
    let fixture = Replica::new().await?;
    let installed = bootstrap();
    let binding = serde_json::to_vec(&("replicated", &installed))?;
    bind_deployment(&fixture.stores, &binding)?;
    let decoded = decode_current_target_deployment(&fixture.stores)?;
    assert_eq!(serde_json::to_vec(&("replicated", &decoded))?, binding);

    let mut alternate = binding.clone();
    alternate.push(b' ');
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&alternate)?,
        serde_json::from_slice::<serde_json::Value>(&binding)?
    );
    let before = retained(&fixture.stores)?;
    assert!(
        fixture
            .stores
            .application()
            .write_batch(&[WriteOp::put(
                "engine.deployment",
                b"mode",
                alternate.as_slice()
            )])
            .is_err()
    );
    assert!(
        fixture
            .stores
            .write_batch(
                &[WriteOp::put(
                    "engine.deployment",
                    b"mode",
                    alternate.as_slice()
                )],
                &[WriteOp::put(
                    "engine.deployment",
                    b"mode",
                    binding.as_slice()
                )],
            )
            .is_err()
    );
    assert_eq!(retained(&fixture.stores)?, before);
    drop(fixture.close().await);

    let fixture = Replica::new().await?;
    fixture.stores.write_batch(
        &[WriteOp::put(
            "engine.deployment",
            b"mode",
            alternate.as_slice(),
        )],
        &[WriteOp::put(
            "engine.deployment",
            b"mode",
            alternate.as_slice(),
        )],
    )?;
    let before = retained(&fixture.stores)?;
    let Err(error) = decode_current_target_deployment(&fixture.stores) else {
        panic!("target reader accepted equivalent alternate deployment bytes");
    };
    assert!(
        format!("{error:#}").contains("trailing deployment bytes"),
        "{error:#}"
    );
    assert_eq!(retained(&fixture.stores)?, before);
    drop(fixture.close().await);
    Ok(())
}

#[tokio::test]
async fn target_deployment_accepts_valid_writer_bytes_above_legacy_cap() -> anyhow::Result<()> {
    let fixture = Replica::new().await?;
    let mut installed = bootstrap();
    installed
        .initial_policy
        .grants
        .extend((0..4095).map(|id| Grant {
            principal: format!("member-{id:04}-{}", "x".repeat(128)),
            collection: None,
            actions: BTreeSet::from([Action::Read]),
        }));
    installed.validate()?;
    let binding = serde_json::to_vec(&("replicated", &installed))?;
    assert!(binding.len() > 256 << 10);
    assert!(binding.len() <= kasumi_store::MAX_DEPLOYMENT_BINDING_BYTES);
    bind_deployment(&fixture.stores, &binding)?;
    let decoded = decode_current_target_deployment(&fixture.stores)?;
    assert_eq!(serde_json::to_vec(&("replicated", &decoded))?, binding);
    drop(fixture.close().await);
    Ok(())
}

async fn leader(nodes: &BTreeMap<u64, Arc<Database>>) -> anyhow::Result<u64> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for (&id, node) in nodes {
                if node.raft_group().raft().metrics().borrow().current_leader == Some(id)
                    && matches!(
                        tokio::time::timeout(
                            Duration::from_millis(200),
                            node.raft_group().linearizable_barrier()
                        )
                        .await,
                        Ok(Ok(_))
                    )
                {
                    return id;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?)
}

#[tokio::test]
async fn initialize_replicated_keeps_custody_binding_before_membership() -> anyhow::Result<()> {
    let fixture = Replica::new().await?;
    let installed = bootstrap();
    let router = Arc::new(InProcessRouter::default());
    let database = fixtures::open_fixture_replicated(
        1,
        fixture.stores.clone(),
        &installed,
        router,
        raft_config(),
        fixture.audit.clone(),
    )
    .await?;
    assert!(!database.raft_group().raft().is_initialized().await?);
    let before = retained(&fixture.stores)?;
    assert!(
        fixture
            .stores
            .custody()
            .store()
            .write_batch(&[WriteOp::delete("engine.deployment", b"mode")])
            .is_err()
    );
    assert_eq!(retained(&fixture.stores)?, before);
    assert!(!database.raft_group().raft().is_initialized().await?);
    initialize_replicated(&database, &installed).await?;
    assert!(database.raft_group().raft().is_initialized().await?);
    database.shutdown().await?;
    drop(database);
    drop(fixture.close().await);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_replicas_replay_committed_state_and_membership_after_full_close()
-> anyhow::Result<()> {
    let installed = bootstrap();
    let group = format!("replica/{}", installed.incarnation);
    let router = Arc::new(InProcessRouter::default());
    let mut fixtures = BTreeMap::new();
    let mut nodes = BTreeMap::new();
    for id in 1..=4 {
        let fixture = Replica::new().await?;
        let database = fixtures::open_fixture_replicated(
            id,
            fixture.stores.clone(),
            &installed,
            router.clone(),
            raft_config(),
            fixture.audit.clone(),
        )
        .await?;
        router.register(group.clone(), id, database.raft_group().raft().clone());
        nodes.insert(id, database);
        fixtures.insert(id, fixture);
    }
    initialize_replicated(&nodes[&1], &installed).await?;
    let first = leader(&nodes).await?;
    nodes[&first]
        .administer(
            RequestContext {
                authorization: RequestAuthorization::service_identity(),
                tenant: "replica".into(),
                principal: "owner".into(),
                scopes: BTreeSet::from([Action::Admin]),
                request_id: "strict-replica".into(),
            },
            Operation::CreateCollection(CollectionDefinition {
                name: "retained".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await?;
    let revision = nodes[&first].engine().generation()?.state.revision;
    nodes[&first]
        .raft_group()
        .add_learner(4, BasicNode::new("relocated-4"))
        .await?;
    // Keep the current leader in the replacement voter set, avoiding an
    // intentionally ambiguous leader-removal response in this reopen fixture.
    let removed = (1..=3).find(|id| *id != first).unwrap();
    let voters = (1..=4).filter(|id| *id != removed).collect::<BTreeSet<_>>();
    nodes[&first]
        .raft_group()
        .change_membership(voters.clone())
        .await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if voters.iter().all(|id| {
                let node = &nodes[id];
                node.engine()
                    .generation()
                    .is_ok_and(|generation| generation.state.revision == revision)
                    && node
                        .raft_group()
                        .raft()
                        .metrics()
                        .borrow()
                        .membership_config
                        .membership()
                        .voter_ids()
                        .collect::<BTreeSet<_>>()
                        == voters
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    for (&id, node) in &nodes {
        router.unregister(&group, id);
        node.shutdown().await?;
    }
    nodes.clear();
    let mut directories = BTreeMap::new();
    for (id, fixture) in fixtures {
        directories.insert(id, fixture.close().await);
    }
    let mut reopened = BTreeMap::new();
    for (id, directory) in directories {
        if id == removed {
            drop(directory);
            continue;
        }
        let fixture = Replica::existing(directory).await?;
        let pinned = fixture.stores.read_view()?;
        let installed_identity = Some((id, group.clone()));
        assert_eq!(
            kasumi_raft::ControlLog::installed_identity_at(&pinned)?,
            installed_identity
        );
        let custody = fixture.stores.custody().store();
        assert!(
            custody
                .write_batch(&[WriteOp::put(
                    "raft.meta",
                    b"node_id",
                    serde_json::to_vec(&(id + 10))?,
                )])
                .is_err()
        );
        assert!(
            custody
                .write_batch(&[WriteOp::put(
                    "raft.meta",
                    b"group",
                    serde_json::to_vec(&format!("{group}/other"))?,
                )])
                .is_err()
        );
        assert_eq!(
            kasumi_raft::ControlLog::installed_identity_at(&fixture.stores.read_view()?)?,
            installed_identity
        );
        drop(pinned);
        let opened = open_existing_replicated(
            id,
            fixture.stores.clone(),
            uuid::Uuid::parse_str(&installed.incarnation)?,
            router.clone(),
            raft_config(),
            fixture.audit.clone(),
        )
        .await?;
        assert_eq!(
            serde_json::to_vec(&opened.bootstrap)?,
            serde_json::to_vec(&installed)?
        );
        let binding = serde_json::to_vec(&("replicated", &installed))?;
        require_deployment(&fixture.stores, &binding)?;
        assert_eq!(opened.verified_binding(), binding);
        assert_eq!(
            opened.verified_snapshot_sha256(),
            persisted_bootstrap_digest_at(&fixture.stores.read_view()?)?
        );
        let database = opened.database;
        assert_eq!(database.raft_group().raft().metrics().borrow().id, id);
        // This is a no-op for recovered membership, even at an original voter.
        initialize_replicated(&database, &opened.bootstrap).await?;
        let generation = database.engine().generation()?;
        assert_eq!(generation.state.incarnation, installed.incarnation);
        assert_eq!(generation.state.revision, revision);
        assert!(generation.state.collections.contains_key("retained"));
        let metrics = database.raft_group().raft().metrics().borrow().clone();
        assert_eq!(
            metrics
                .membership_config
                .membership()
                .voter_ids()
                .collect::<Vec<_>>(),
            voters.iter().copied().collect::<Vec<_>>()
        );
        assert_eq!(
            metrics
                .membership_config
                .membership()
                .get_node(&4)
                .unwrap()
                .addr,
            "relocated-4"
        );
        router.register(group.clone(), id, database.raft_group().raft().clone());
        nodes.insert(id, database);
        reopened.insert(id, fixture);
    }
    leader(&nodes).await?;
    for (&id, node) in &nodes {
        router.unregister(&group, id);
        node.shutdown().await?;
    }
    nodes.clear();
    for (_, fixture) in reopened {
        drop(fixture.close().await);
    }
    Ok(())
}
