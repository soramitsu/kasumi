//! The one-time ROOT003 upgrade against a real stopped standalone installation.
use super::*;
use crate::runtime::NodeRuntime;
use crate::standalone::OperatorState;
use kasumi_types::{
    Action, CollectionDefinition, CollectionRetentionClass, CollectionWriteMode, Mutation,
    MutationBatch, Operation, Precondition, QueryRequest, RequestAuthorization, RequestContext,
};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::time::{Duration, Instant};

const TENANT: &str = "tenant-a";
const SLOT_A: usize = 4096;
const SLOT_B: usize = 8192;
const CHECKSUM_AT: usize = 4092;

fn context() -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "administrator".into(),
        tenant: TENANT.into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        request_id: Uuid::new_v4().to_string(),
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    configuration: PathBuf,
    config: RuntimeConfig,
    storage: crate::runtime_memory::RuntimeStorage,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let root = kasumi_store::test_utils::private_tempdir()?;
        let directory = std::fs::canonicalize(root.path())?.join("kasumi");
        let (installed, storage) = tokio::spawn(async move {
            crate::runtime_storage_fixtures::initialize_standalone(&directory, TENANT).await
        })
        .await??;
        let mut config = RuntimeConfig::load(&installed.configuration)?;
        let listeners = (0..3)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0"))
            .collect::<std::io::Result<Vec<_>>>()?;
        config.mcp.listen = listeners[0].local_addr()?;
        config.native.listen = listeners[1].local_addr()?;
        config.admin.listen = listeners[2].local_addr()?;
        config.mcp.protocol = crate::mcp::McpConfig::new(format!(
            "https://localhost:{}/mcp",
            config.mcp.listen.port()
        ))?;
        private_files::replace(
            &installed.configuration,
            &serde_json::to_vec_pretty(&config)?,
        )?;
        crate::standalone::configure_test_topology(&config, storage.clone()).await;
        drop(listeners);
        Ok(Self {
            _root: root,
            configuration: installed.configuration,
            config,
            storage,
        })
    }

    fn data(&self) -> &Path {
        self.config.database_path.parent().unwrap()
    }

    fn root_file(&self) -> PathBuf {
        self.config.database_path.join("root.kvroot")
    }

    fn save_directory(&self, name: &str) -> PathBuf {
        self.data().parent().unwrap().join(name)
    }

    async fn upgrade(&self, save: &Path) -> Result<serde_json::Value> {
        super::upgrade_storage_root_with_storage(&self.configuration, save, self.storage.clone())
            .await
    }

    async fn serve(&self) -> Result<Serving> {
        let runtime = NodeRuntime::open_using_storage(
            self.config.clone(),
            crate::runtime::file_secret,
            self.storage.clone(),
        )
        .await?;
        let registry = runtime.registry().clone();
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        let serving = tokio::spawn(runtime.serve(shutdown));
        tokio::time::timeout(Duration::from_secs(10), async {
            while registry.database(&context()).is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        Ok(Serving {
            stop,
            serving,
            registry,
        })
    }
}

struct Serving {
    stop: tokio::sync::watch::Sender<bool>,
    serving: tokio::task::JoinHandle<Result<()>>,
    registry: crate::api::DatabaseRegistry,
}

impl Serving {
    fn database(&self) -> Arc<kasumi_engine::Database> {
        self.registry.database(&context()).unwrap()
    }

    async fn stop(self) -> Result<()> {
        self.stop.send_replace(true);
        self.serving.await??;
        drop(self.registry);
        Ok(())
    }
}

fn id(index: usize) -> String {
    format!("doc-{index:02}")
}

async fn write_documents(
    database: &kasumi_engine::Database,
) -> Result<BTreeMap<String, serde_json::Value>> {
    database
        .administer(
            context(),
            Operation::CreateCollection(CollectionDefinition {
                name: "docs".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await?;
    let mut expected = BTreeMap::new();
    let batch = |operations| MutationBatch {
        idempotency_key: Uuid::new_v4().to_string(),
        read_set: vec![],
        operations,
    };
    for chunk in 0..3 {
        let mut operations = Vec::new();
        for index in chunk * 8..(chunk + 1) * 8 {
            let body = serde_json::json!({"index": index, "value": "written by the ROOT003 build"});
            expected.insert(id(index), body.clone());
            operations.push(Mutation::Put {
                collection: "docs".into(),
                id: id(index),
                body,
                expected: Precondition::Absent,
            });
        }
        database.mutate(context(), batch(operations)).await?;
    }
    let mut operations = Vec::new();
    for index in 0..4 {
        let body = serde_json::json!({"index": index, "value": "replaced"});
        expected.insert(id(index), body.clone());
        operations.push(Mutation::Put {
            collection: "docs".into(),
            id: id(index),
            body,
            expected: Precondition::Any,
        });
    }
    for index in [22, 23] {
        expected.remove(&id(index));
        operations.push(Mutation::Delete {
            collection: "docs".into(),
            id: id(index),
            expected: Precondition::Any,
        });
    }
    database.mutate(context(), batch(operations)).await?;
    assert_eq!(expected.len(), 22);
    Ok(expected)
}

/// Every document by point read, and the collection's count by query.
async fn read_documents(
    database: &kasumi_engine::Database,
) -> Result<BTreeMap<String, serde_json::Value>> {
    let mut documents = BTreeMap::new();
    for index in 0..24 {
        if let Some(document) = database.get(&context(), "docs", &id(index)).await? {
            documents.insert(id(index), document.body.clone());
        }
    }
    let query: QueryRequest = serde_json::from_value(
        serde_json::json!({"collection": "docs", "allow_scan": true, "limit": 100}),
    )?;
    let rows = database.query(&context(), query).await?;
    let queried: BTreeMap<_, _> = rows
        .rows
        .iter()
        .map(|row| (row.id.clone(), row.body.clone()))
        .collect();
    assert_eq!(queried, documents);
    Ok(documents)
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn reseal(image: &mut [u8], slot: usize) {
    let checksum = crc32c(&image[slot..slot + CHECKSUM_AT]);
    image[slot + CHECKSUM_AT..slot + 4096].copy_from_slice(&checksum.to_le_bytes());
}

/// The root image a master-era `KASUMI-KVROOT003` build writes for the same
/// superblocks: the current bytes of a never-compacted root with magic byte
/// 15 `'3'` and the CRC-32C over that (checked in `kasumi_kv` against the
/// ported master codec).
pub(crate) fn spelled_root003(fresh: &[u8]) -> Vec<u8> {
    let mut image = fresh.to_vec();
    for slot in [SLOT_A, SLOT_B] {
        assert_eq!(&image[slot..slot + 16], b"KASUMI-KVROOT005");
        assert!(
            image[slot + 2384..slot + CHECKSUM_AT]
                .iter()
                .all(|&byte| byte == 0),
            "the fixture already ran a compaction cycle"
        );
        image[slot + 15] = b'3';
        reseal(&mut image, slot);
    }
    image
}

/// Replace the root's bytes in place, as a crash or the media would.
pub(crate) fn put(path: &Path, image: &[u8]) {
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.write_all_at(image, 0).unwrap();
    file.sync_all().unwrap();
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn group_files(path: &Path) -> BTreeSet<String> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".kvseg") || name.ends_with(".kvdir"))
        .collect()
}

fn single_root(summary: &serde_json::Value) -> &serde_json::Value {
    let roots = summary["roots"].as_array().unwrap();
    assert_eq!(roots.len(), 1, "{summary:#}");
    &roots[0]
}

/// Run a refused upgrade: the root and the save directory stay untouched.
async fn refused(fixture: &Fixture, save: &Path, expected: &str) {
    let root = fixture.root_file();
    let before = std::fs::read(&root).unwrap();
    let saved_before = save.exists().then(|| file_names(save));
    let error = fixture.upgrade(save).await.unwrap_err();
    assert!(format!("{error:#}").contains(expected), "{error:#}");
    assert_eq!(std::fs::read(&root).unwrap(), before);
    assert_eq!(save.exists().then(|| file_names(save)), saved_before);
}

fn file_names(path: &Path) -> BTreeSet<String> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect()
}

#[test]
fn root003_installation_upgrades_in_place_and_serves_the_same_documents() -> Result<()> {
    crate::standalone::ownership_tests::run_large_fixture(
        "storage root upgrade fixture",
        root003_installation_upgrades_in_place_impl,
    )
}

async fn root003_installation_upgrades_in_place_impl() -> Result<()> {
    // Operators and runtimes publish through the process-wide startup
    // registries this fixture drains; serialize with every other drainer.
    let _serial = crate::standalone::ownership_tests::drain_serial()
        .lock()
        .await;
    let fixture = Fixture::new().await?;
    let serving = fixture.serve().await?;
    let written = write_documents(&serving.database()).await?;
    assert_eq!(read_documents(&serving.database()).await?, written);
    serving.stop().await?;

    let root = fixture.root_file();
    let inode = std::fs::metadata(&root)?.ino();
    let fresh = std::fs::read(&root)?;
    assert_eq!(fresh.len(), 12288);
    let generation = u64::from_le_bytes(fresh[SLOT_A + 40..SLOT_A + 48].try_into()?);
    let files = group_files(&fixture.config.database_path);

    // A ROOT005 installation is already current: nothing is written, not
    // even the save directory.
    let unused = fixture.save_directory("unused-save");
    let summary = fixture.upgrade(&unused).await?;
    let current = single_root(&summary);
    assert_eq!(current["outcome"], "already ROOT005");
    assert_eq!(current["slots_changed"], serde_json::json!([]));
    assert_eq!(current["saved_copy"], serde_json::Value::Null);
    assert_eq!(current["generation"], generation);
    assert!(!unused.exists());
    assert_eq!(std::fs::read(&root)?, fresh);

    // The installation as a master-era build left it. (Reopen refuses it:
    // `kasumi_kv`'s upgrade tests prove that against the strict decoder.)
    let master = spelled_root003(&fresh);
    put(&root, &master);

    // Refusals before any write.
    let save = fixture.save_directory("root-upgrade-save");
    let mut envelope = master.clone();
    envelope[20] ^= 1;
    put(&root, &envelope);
    refused(&fixture, &save, "envelope is invalid").await;
    let mut compaction = master.clone();
    compaction[SLOT_A + 3000] = 1;
    reseal(&mut compaction, SLOT_A);
    put(&root, &compaction);
    refused(&fixture, &save, "nonzero compaction region").await;
    put(&root, &master);
    refused(
        &fixture,
        &fixture.data().join("save"),
        "inside installed storage",
    )
    .await;
    refused(&fixture, Path::new("relative-save"), "absolute path").await;
    private_files::create_directory(&save)?;
    let collision = save.join("node.kv.root.kvroot");
    let mut other = master.clone();
    other[SLOT_B + 100] ^= 1;
    private_files::create(&collision, &other)?;
    refused(&fixture, &save, "holds a different copy").await;
    assert_eq!(std::fs::read(&collision)?, other);
    std::fs::remove_file(&collision)?;

    // A run interrupted after its first slot write resumes from the copy it
    // saved; the result is exactly the bytes the current encoder wrote.
    let mut interrupted = master.clone();
    interrupted[SLOT_B..].copy_from_slice(&fresh[SLOT_B..]);
    put(&root, &interrupted);
    private_files::create(&collision, &master)?;
    let summary = fixture.upgrade(&save).await?;
    let resumed = single_root(&summary);
    assert_eq!(resumed["outcome"], "resumed", "{summary:#}");
    assert_eq!(resumed["slots_changed"], serde_json::json!(["A"]));
    assert_eq!(resumed["saved_copy"]["state"], "matches");
    assert_eq!(std::fs::read(&root)?, fresh);
    assert_eq!(std::fs::read(&collision)?, master);

    // A torn final write and a fresh save directory: the torn image is
    // saved as found and the upgrade still completes from the slots alone.
    let mut torn = interrupted.clone();
    torn[SLOT_A + 15] = b'5';
    put(&root, &torn);
    let torn_save = fixture.save_directory("torn-save");
    let summary = fixture.upgrade(&torn_save).await?;
    let resumed = single_root(&summary);
    assert_eq!(resumed["outcome"], "resumed", "{summary:#}");
    assert_eq!(resumed["slots_changed"], serde_json::json!(["A"]));
    assert_eq!(resumed["saved_copy"]["state"], "written");
    assert_eq!(std::fs::read(torn_save.join("node.kv.root.kvroot"))?, torn);
    assert_eq!(std::fs::read(&root)?, fresh);

    // A torn ROOT003 slot gets the new magic and stays torn.
    let mut torn_slot = master.clone();
    torn_slot[SLOT_B + 100] ^= 1;
    put(&root, &torn_slot);
    let torn_slot_save = fixture.save_directory("torn-slot-save");
    let summary = fixture.upgrade(&torn_slot_save).await?;
    let upgraded = single_root(&summary);
    assert_eq!(upgraded["outcome"], "upgraded", "{summary:#}");
    assert_eq!(
        upgraded["slots"],
        serde_json::json!({"A": "upgraded", "B": "invalid_rewritten"})
    );
    assert_eq!(upgraded["slots_changed"], serde_json::json!(["B", "A"]));
    assert_eq!(upgraded["mirrored"], false);
    let image = std::fs::read(&root)?;
    assert_eq!(image[..SLOT_B], fresh[..SLOT_B]);
    let mut expected_b = torn_slot[SLOT_B..].to_vec();
    expected_b[15] = b'5';
    assert_eq!(image[SLOT_B..], expected_b[..]);

    // The upgrade itself, from the installation a master-era build left.
    put(&root, &master);
    let save = fixture.save_directory("final-save");
    let summary = fixture.upgrade(&save).await?;
    assert_eq!(summary["format"], "kasumi.storage-root-upgrade.v1");
    assert_eq!(summary["save_directory"], serde_json::json!(save));
    let upgraded = single_root(&summary);
    let copy = save.join("node.kv.root.kvroot");
    assert_eq!(
        *upgraded,
        serde_json::json!({
            "path": root,
            "outcome": "upgraded",
            "envelope": "ready",
            "slots": {"A": "upgraded", "B": "upgraded"},
            "slots_changed": ["B", "A"],
            "generation": generation,
            "selected_slot": "A",
            "mirrored": true,
            "sha256_before": sha256(&master),
            "sha256_after": sha256(&fresh),
            "saved_copy": {"path": copy, "state": "written"},
        })
    );
    assert_eq!(std::fs::read(&root)?, fresh);
    assert_eq!(std::fs::metadata(&root)?.ino(), inode);
    assert_eq!(group_files(&fixture.config.database_path), files);
    assert_eq!(std::fs::read(&copy)?, master);
    assert_eq!((mode(&save), mode(&copy)), (0o700, 0o600));
    // A second run is a no-op.
    let summary = fixture.upgrade(&save).await?;
    let again = single_root(&summary);
    assert_eq!(again["outcome"], "already ROOT005");
    assert_eq!(again["slots_changed"], serde_json::json!([]));
    assert_eq!(again["saved_copy"]["state"], "matches");
    assert_eq!(again["sha256_before"], again["sha256_after"]);
    assert_eq!(std::fs::read(&root)?, fresh);

    // The upgraded installation serves the same documents, and the upgrade
    // is refused while it does.
    let serving = fixture.serve().await?;
    assert_eq!(read_documents(&serving.database()).await?, written);
    let error = fixture.upgrade(&save).await.unwrap_err();
    assert!(!format!("{error:#}").is_empty());
    serving.stop().await?;

    // Compaction and reclaim run and unlink files the master-era build wrote.
    let mut owner = OperatorState::open(&fixture.config, fixture.storage.clone()).await?;
    let node = owner.node.clone();
    // The node worker runs one bounded maintenance step per iteration.
    node.prepare_cache_warming().await?;
    node.activate_cache_warming()?;
    node.request_storage_compaction()?;
    let started = Instant::now();
    let status = loop {
        let status = node.storage_maintenance_status()?;
        if status.cycle >= 1 && status.phase == kasumi_store::StorageCompactionPhase::Idle {
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "compaction did not finish: {status:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(status.garbage_files, 0, "{status:?}");
    assert!(status.reclaimed_files_total >= 1, "{status:?}");
    drop(node);
    owner.finish(Ok(())).await?;
    // The operator holds the installation lock until it is dropped.
    drop(owner);
    let remaining = group_files(&fixture.config.database_path);
    assert!(
        files.iter().any(|file| !remaining.contains(file)),
        "no file the master-era build wrote was reclaimed: {files:?} -> {remaining:?}"
    );
    assert!(
        !fixture
            .config
            .database_path
            .join("0000000000000001.kvdir")
            .exists()
    );
    let serving = fixture.serve().await?;
    assert_eq!(read_documents(&serving.database()).await?, written);
    serving.stop().await?;
    // Once later builds have written their own roots, the saved copy is stale
    // and the upgrade still has nothing to do.
    let summary = fixture.upgrade(&save).await?;
    let later = single_root(&summary);
    assert_eq!(later["outcome"], "already ROOT005");
    assert_eq!(later["saved_copy"]["state"], "stale");
    crate::standalone::drain_operations().await?;
    NodeRuntime::drain_startups().await?;
    Ok(())
}
