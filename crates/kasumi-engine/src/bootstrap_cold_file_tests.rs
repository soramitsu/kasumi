use super::*;
use kasumi_raft::InProcessRouter;
use kasumi_store::{NodeStore, test_utils::LocalKeyProvider};
use std::{path::Path, process::Command};

const NODE_STORE_ID: uuid::Uuid = uuid::Uuid::from_u128(0xa1f9_93e5_2727_480a_9e7c_6e39_eb51_5f01);
const CHILD_STAGE: &str = "KASUMI_G01_COLD_FILE_STAGE";
const CHILD_ROOT: &str = "KASUMI_G01_COLD_FILE_ROOT";
const TEST_NAME: &str =
    "bootstrap::cold_file_tests::stopped_process_raw_file_rollback_selects_a_generation";

struct ProcessFixture {
    _storage: crate::test_utils::FixtureStorage,
    node: Arc<NodeStore>,
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
}
impl ProcessFixture {
    async fn open(root: &Path, create: bool) -> anyhow::Result<Self> {
        let (persistent, scratch) = if create {
            crate::test_utils::fixture_disk_configs(root)?
        } else {
            (
                kasumi_store::NodeDisk::fixture_config(root.join("persistent/node.kv"))?,
                kasumi_store::ScratchDiskConfig {
                    directory: root.join("scratch"),
                    max_bytes: 256 << 30,
                    min_free_bytes: 0,
                },
            )
        };
        let config = crate::admission::AdmissionConfig {
            max_inflight_bytes: Some(
                (384_u64 << 20)
                    .checked_add(crate::test_utils::isolated_disk_metadata_bytes(
                        &persistent,
                        &scratch,
                    )?)
                    .ok_or_else(|| anyhow::anyhow!("fixture metadata budget overflow"))?,
            ),
            ..Default::default()
        };
        let admission = crate::admission::NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
        let storage = crate::test_utils::FixtureStorage::with_admission(
            &persistent,
            &scratch,
            admission.clone(),
        )?;
        let path = root.join("persistent/node.kv");
        let node = if create {
            storage.create_new(path, NODE_STORE_ID)?
        } else {
            storage.open_existing(path, NODE_STORE_ID)?
        };
        let application = Arc::new(LocalKeyProvider::new([31; 32]));
        let custody = Arc::new(LocalKeyProvider::new([32; 32]));
        let stores = if create {
            TenantStorageSet::initialize_catalogs_fixture(
                node.clone(),
                "replica".into(),
                application,
                custody,
            )
            .await?
        } else {
            TenantStorageSet::open_existing_fixture(
                node.clone(),
                "replica".into(),
                application,
                custody,
            )
            .await?
        };
        let audit_provider = Arc::new(LocalKeyProvider::new([33; 32]));
        let audit_store = if create {
            TenantStore::initialize_catalog_fixture(
                node.clone(),
                crate::SECURITY_TENANT.into(),
                audit_provider,
            )
            .await?
        } else {
            TenantStore::open_existing_fixture(
                node.clone(),
                crate::SECURITY_TENANT.into(),
                audit_provider,
            )
            .await?
        };
        let audit = if create {
            SecurityAudit::initialize(audit_store, Default::default(), admission)?
        } else {
            SecurityAudit::open(audit_store, Default::default(), admission)?
        };
        Ok(Self {
            _storage: storage,
            node,
            stores,
            audit,
        })
    }

    async fn close(self) {
        self.stores.shutdown().await.unwrap();
        self.audit.shutdown().await.unwrap();
        self.node.shutdown().await.unwrap();
    }
}

fn descriptor(incarnation: uuid::Uuid) -> ReplicatedBootstrap {
    ReplicatedBootstrap {
        genesis: ReplicatedGenesis::Application,
        incarnation: incarnation.to_string(),
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

fn raw_digest(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 << 10];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn read_descriptor(root: &Path, name: &str) -> anyhow::Result<ReplicatedBootstrap> {
    Ok(serde_json::from_slice(&std::fs::read(root.join(name))?)?)
}

async fn child(root: &Path, stage: &str) -> anyhow::Result<()> {
    let a = read_descriptor(root, "a.json")?;
    let b = read_descriptor(root, "b.json")?;
    match stage {
        "seed-a" => {
            let fixture = ProcessFixture::open(root, true).await?;
            bind_deployment(&fixture.stores, &serde_json::to_vec(&("replicated", &a))?)?;
            let image = TenantEngine::new(
                "replica".into(),
                a.incarnation.clone(),
                a.initial_policy.clone(),
                a.initial_limits.clone(),
            )?
            .logical_snapshot(fixture.node.scratch_disk())?;
            persist_new(&fixture.stores, &image)?;
            drop(image);
            fixture.close().await;
        }
        "install-b" => {
            use kasumi_store::test_utils::inject_authenticated_rows_below_facade;
            let fixture = ProcessFixture::open(root, false).await?;
            let image = TenantEngine::new(
                "replica".into(),
                b.incarnation.clone(),
                b.initial_policy.clone(),
                b.initial_limits.clone(),
            )?
            .logical_snapshot(fixture.node.scratch_disk())?;
            let binding = serde_json::to_vec(&("replicated", &b))?;
            let mut application = vec![WriteOp::put("engine.deployment", b"mode", binding.clone())];
            let mut reader = image.reader();
            for index in 0..image.len().div_ceil(CHUNK as u64) {
                let mut chunk =
                    vec![0; (image.len() - index * CHUNK as u64).min(CHUNK as u64) as usize];
                reader.read_exact(&mut chunk)?;
                application.push(WriteOp::put(NS, index.to_be_bytes(), chunk));
            }
            let manifest = Manifest {
                format: 2,
                bytes: image.len(),
                chunks: image.len().div_ceil(CHUNK as u64),
                digest: image.sha256().to_owned(),
            };
            application.push(WriteOp::put(
                NS,
                b"manifest",
                serde_json::to_vec(&manifest)?,
            ));
            let custody = [
                WriteOp::put("engine.deployment", b"mode", binding),
                WriteOp::put(
                    "raft.meta",
                    b"application_bootstrap_sha256",
                    serde_json::to_vec(image.sha256())?,
                ),
                WriteOp::put("raft.meta", b"node_id", serde_json::to_vec(&2_u64)?),
                WriteOp::put(
                    "raft.meta",
                    b"group",
                    serde_json::to_vec(&format!("replica/{}", b.incarnation))?,
                ),
            ];
            assert!(fixture.stores.write_batch(&application, &custody).is_err());
            inject_authenticated_rows_below_facade(&fixture.stores, &application, &custody)?;
            drop(image);
            fixture.close().await;
        }
        "probe-b" | "probe-rollback-a" => {
            let fixture = ProcessFixture::open(root, false).await?;
            let (selected, rejected, node_id) = if stage == "probe-b" {
                (&b, &a, 2)
            } else {
                (&a, &b, 1)
            };
            let view = fixture.stores.read_view()?;
            let (installed, _) = installed_replicated_bootstrap(
                &view,
                uuid::Uuid::parse_str(&selected.incarnation)?,
            )?;
            assert_eq!(installed.incarnation, selected.incarnation);
            let image = load_at(&view, fixture.node.scratch_disk())?.expect("raw generation image");
            validate_bootstrap_control_at(&view, &image)?;
            assert_eq!(
                kasumi_raft::ControlLog::installed_identity_at(&view)?,
                Some((node_id, format!("replica/{}", selected.incarnation)))
            );
            drop((view, image));
            let rejected_open = open_existing_replicated(
                node_id,
                fixture.stores.clone(),
                uuid::Uuid::parse_str(&rejected.incarnation)?,
                Arc::new(InProcessRouter::default()),
                Config::default(),
                fixture.audit.clone(),
            )
            .await;
            let error = rejected_open
                .err()
                .expect("other generation must not reopen");
            assert!(
                format!("{error:#}")
                    .contains("installed replicated genesis differs from expected incarnation")
            );
            let opened = open_existing_replicated(
                node_id,
                fixture.stores.clone(),
                uuid::Uuid::parse_str(&selected.incarnation)?,
                Arc::new(InProcessRouter::default()),
                Config::default(),
                fixture.audit.clone(),
            )
            .await?;
            assert_eq!(opened.bootstrap.incarnation, selected.incarnation);
            assert_eq!(
                opened.database.raft_group().raft().metrics().borrow().id,
                node_id
            );
            opened.database.shutdown().await?;
            drop(opened);
            fixture.close().await;
        }
        _ => anyhow::bail!("unknown raw generation child stage"),
    }
    Ok(())
}

fn run_child(root: &Path, stage: &str) -> anyhow::Result<()> {
    let output = Command::new(std::env::current_exe()?)
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env(CHILD_STAGE, stage)
        .env(CHILD_ROOT, root)
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "raw generation child {stage} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    anyhow::ensure!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "raw generation child {stage} did not run the selected test"
    );
    eprintln!("raw generation child {stage}: passed");
    Ok(())
}

#[tokio::test]
async fn stopped_process_raw_file_rollback_selects_a_generation() -> anyhow::Result<()> {
    if let Ok(stage) = std::env::var(CHILD_STAGE) {
        let root = std::path::PathBuf::from(std::env::var(CHILD_ROOT)?);
        return child(&root, &stage).await;
    }
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let root = directory.path();
    let a = descriptor(uuid::Uuid::new_v4());
    let b = descriptor(uuid::Uuid::new_v4());
    assert_ne!(a.incarnation, b.incarnation);
    std::fs::write(root.join("a.json"), serde_json::to_vec(&a)?)?;
    std::fs::write(root.join("b.json"), serde_json::to_vec(&b)?)?;
    run_child(root, "seed-a")?;
    let installed = root.join("persistent/node.kv");
    let raw_a = root.join("generation-a.kv");
    let raw_b = root.join("generation-b.kv");
    std::fs::copy(&installed, &raw_a)?;
    let digest_a = raw_digest(&raw_a)?;
    assert_eq!(raw_digest(&installed)?, digest_a);
    run_child(root, "install-b")?;
    std::fs::copy(&installed, &raw_b)?;
    let digest_b = raw_digest(&raw_b)?;
    assert_ne!(digest_a, digest_b);
    assert_eq!(raw_digest(&installed)?, digest_b);
    run_child(root, "probe-b")?;
    let served_b_digest = raw_digest(&installed)?;
    assert_ne!(served_b_digest, digest_a);
    // The B process has exited. Substitute the exact prior raw file while no
    // Kasumi process holds the database, then start a fresh process on that path.
    std::fs::copy(&raw_a, &installed)?;
    assert_eq!(raw_digest(&installed)?, digest_a);
    run_child(root, "probe-rollback-a")?;
    eprintln!(
        "cold raw generations: A={digest_a} B={digest_b} B-after-serving={served_b_digest}; rollback accepted A"
    );
    Ok(())
}
