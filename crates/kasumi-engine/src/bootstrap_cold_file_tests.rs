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
    node: NodeStore,
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
}
impl ProcessFixture {
    async fn open(root: &Path, create: bool) -> crate::test_fixture_failure::FixtureResult<Self> {
        let (persistent, scratch) = if create {
            crate::test_utils::fixture_disk_configs(root)?
        } else {
            (
                kasumi_store::NodeDisk::fixture_config(root.join("persistent/node.kv"))?,
                kasumi_store::ScratchDiskConfig {
                    directory: root.join("scratch"),
                    max_bytes: 256 << 30,
                    min_free_bytes: 0,
                    native_cache_bytes: 8 << 20,
                },
            )
        };
        // The child must be able to start the selected native replica after
        // verifying its cold files. Use the same constructor plan as the other
        // positive replica fixtures: actual fixed owners and protected floors
        // plus the independently declared workload. The legacy 384 MiB total
        // remains an explicit negative in replica_budget.
        let config = super::existing_replicated_tests::replica_budget::planned_config(
            &persistent,
            &scratch,
        )?;
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
        // Like a production installer, select the audit placement before any open.
        crate::test_utils::install_fixture_audit_placement(stores.application())?;
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

fn read_descriptor(root: &Path, name: &str) -> anyhow::Result<ReplicatedBootstrap> {
    Ok(serde_json::from_slice(&std::fs::read(root.join(name))?)?)
}

async fn child(root: &Path, stage: &str) -> crate::test_fixture_failure::FixtureResult<()> {
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
            let manifest = ApplicationBootstrapManifest {
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
                uuid::Uuid::parse_str(&selected.incarnation).map_err(anyhow::Error::from)?,
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
                uuid::Uuid::parse_str(&rejected.incarnation).map_err(anyhow::Error::from)?,
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
                uuid::Uuid::parse_str(&selected.incarnation).map_err(anyhow::Error::from)?,
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
        _ => return Err(anyhow::anyhow!("unknown raw generation child stage").into()),
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
async fn stopped_process_raw_file_rollback_selects_a_generation()
-> crate::test_fixture_failure::FixtureResult<()> {
    if let Ok(stage) = std::env::var(CHILD_STAGE) {
        let root =
            std::path::PathBuf::from(std::env::var(CHILD_ROOT).map_err(anyhow::Error::from)?);
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
    // Child processes have stopped and own no live admission in this parent.
    // The offline fixture explicitly admits every complete member inventory.
    let memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> =
        kasumi_store::test_utils::TestDiskMemory::new(1 << 20, 64);
    use kasumi_store::test_utils::{
        capture_native_group_image, copy_closed_native_group, restore_closed_native_group,
    };
    copy_closed_native_group(&installed, &raw_a, memory.clone())?;
    let image_a = capture_native_group_image(&raw_a, memory.clone())?;
    let digest_a = hex::encode(image_a.sha256());
    assert_eq!(
        capture_native_group_image(&installed, memory.clone())?,
        image_a
    );
    run_child(root, "install-b")?;
    copy_closed_native_group(&installed, &raw_b, memory.clone())?;
    let image_b = capture_native_group_image(&raw_b, memory.clone())?;
    let digest_b = hex::encode(image_b.sha256());
    assert_ne!(image_a, image_b);
    assert_eq!(
        capture_native_group_image(&installed, memory.clone())?,
        image_b
    );
    run_child(root, "probe-b")?;
    let served_b_image = capture_native_group_image(&installed, memory.clone())?;
    let served_b_digest = hex::encode(served_b_image.sha256());
    assert_ne!(served_b_image, image_a);
    // The B process has exited. Restore every member of the exact prior native
    // group in place, preserving the enrolled directory/root identities, then
    // start a fresh process on that path.
    restore_closed_native_group(&raw_a, &installed, memory.clone())?;
    assert_eq!(capture_native_group_image(&installed, memory)?, image_a);
    run_child(root, "probe-rollback-a")?;
    eprintln!(
        "cold raw generations: A={digest_a} B={digest_b} B-after-serving={served_b_digest}; rollback accepted A"
    );
    Ok(())
}
