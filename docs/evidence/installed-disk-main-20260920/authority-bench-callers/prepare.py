from pathlib import Path
import shutil
root=Path('/Users/mtakemiya/dev/kasumi'); out=root/'target/installed-disk-validation/authority-bench-callers'; base=out/'before'; prop=out/'proposed'
files=['crates/kasumi-authority/Cargo.toml','crates/kasumi-authority/src/tests.rs','crates/kasumi-authority/src/maintenance_tests.rs','crates/kasumi-authority/src/bootstrap_open_tests.rs','crates/kasumi-authority/src/request_drain_tests.rs','crates/kasumi-authority/src/activation_gate_tests.rs','crates/kasumi-authority/src/target_materialization_tests.rs','crates/kasumi-authority/src/target_serving_tests.rs','crates/kasumi-bench/Cargo.toml','crates/kasumi-bench/src/main.rs','crates/kasumi-bench/src/bin/loopback.rs']
for f in files:
 for tree in [base,prop]:
  dest=tree/f; dest.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(root/f,dest)
def edit(f, old,new,count=None):
 p=prop/f; s=p.read_text(); n=s.count(old)
 assert n and (count is None or n>=count),(f,n,old[:120]); p.write_text(s.replace(old,new) if count is None else s.replace(old,new,count))
a='crates/kasumi-authority/src/'; b='crates/kasumi-bench/'
edit('crates/kasumi-authority/Cargo.toml','kasumi-engine.workspace = true','kasumi-engine = { workspace = true, features = ["test-utils"] }')
edit(b+'Cargo.toml','"kasumi-store/test-utils"]','"kasumi-store/test-utils", "kasumi-engine/test-utils"]',1)
old='''fn request_budget() -> BackgroundWorkBudget {
    static ADMISSION: OnceLock<Arc<kasumi_engine::admission::NodeAdmission>> = OnceLock::new();
    let admission = ADMISSION
        .get_or_init(|| kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap());
    let bytes = authority_request_metadata_bytes().unwrap();
    let mut charge = admission.reserve(bytes, None).unwrap();
    charge.retain(bytes);
    BackgroundWorkBudget::new(AUTHORITY_REQUEST_SLOTS, Arc::new(charge)).unwrap()
}
'''
new='''/// One modeled physical process. The caller retains both private directories
/// and the same admitted disk owners through every file close/reopen.
struct PhysicalFixture {
    storage: kasumi_engine::test_utils::FixtureStorage,
    directory: tempfile::TempDir,
    _scratch_directory: tempfile::TempDir,
}
impl std::ops::Deref for PhysicalFixture {
    type Target = kasumi_engine::test_utils::FixtureStorage;
    fn deref(&self) -> &Self::Target {
        &self.storage
    }
}
impl PhysicalFixture {
    fn new() -> anyhow::Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let scratch_directory = kasumi_store::test_utils::private_tempdir()?;
        let persistent = kasumi_store::NodeDisk::fixture_config(directory.path().join("node.redb"))?;
        let scratch = kasumi_store::ScratchDiskConfig {
            directory: scratch_directory.path().to_owned(),
            max_bytes: 256 << 30,
            min_free_bytes: 0,
        };
        let storage = kasumi_engine::test_utils::FixtureStorage::open(
            &persistent, &scratch, Default::default(),
        )?;
        Ok(Self { storage, directory, _scratch_directory: scratch_directory })
    }
    fn path(&self, name: impl AsRef<std::path::Path>) -> std::path::PathBuf {
        self.directory.path().join(name)
    }
}

fn request_budget(admission: &Arc<kasumi_engine::admission::NodeAdmission>) -> BackgroundWorkBudget {
    let bytes = authority_request_metadata_bytes().unwrap();
    let charge = admission.memory().reserve_resident(bytes).unwrap();
    BackgroundWorkBudget::new(AUTHORITY_REQUEST_SLOTS, Arc::new(charge)).unwrap()
}
'''
edit(a+'tests.rs',old,new,1)
edit(a+'tests.rs','    _dir: tempfile::TempDir,','    physical: BTreeMap<u64, PhysicalFixture>,',1)
edit(a+'tests.rs','        let dir = kasumi_store::test_utils::private_tempdir().unwrap();\n','',1)
edit(a+'tests.rs','        let mut stores = Vec::new();\n        for id in 1..=3 {','        let mut stores = Vec::new();\n        let mut physical = BTreeMap::new();\n        for id in 1..=3 {\n            let storage = PhysicalFixture::new().unwrap();',1)
edit(a+'tests.rs','''NodeStore::create_new_fixture(
                dir.path().join(format!("authority-{id}.redb")),
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )''','''storage.create_new(
                storage.path(format!("authority-{id}.redb")),
                kasumi_store::test_utils::NODE_STORE_ID,
            )''',1)
edit(a+'tests.rs','                request_budget(),\n                kasumi_raft::SnapshotBufferOwner::fixture(),','                request_budget(&storage.admission),\n                storage.admission.snapshot_buffer_owner().unwrap(),',1)
edit(a+'tests.rs','            stores.push(store);','            stores.push(store);\n            physical.insert(id, storage);',1)
edit(a+'tests.rs','            _dir: dir,','            physical,',1)
edit(a+'tests.rs','''NodeStore::open_existing_fixture(
                self._dir.path().join(format!("authority-{id}.redb")),
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )''','''self.physical[&id].open_existing(
                self.physical[&id].path(format!("authority-{id}.redb")),
                kasumi_store::test_utils::NODE_STORE_ID,
            )''',1)
edit(a+'tests.rs','                request_budget(),\n                kasumi_raft::SnapshotBufferOwner::fixture(),','                request_budget(&self.physical[&id].admission),\n                self.physical[&id].admission.snapshot_buffer_owner().unwrap(),',1)
edit(a+'tests.rs','    let path = fixture._dir.path().join("separate-municipality.redb");','    let storage = PhysicalFixture::new().unwrap();\n    let path = storage.path("separate-municipality.redb");')
for op in ['create_new','open_existing']:
 edit(a+'tests.rs',f'''NodeStore::{op}_fixture(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )''',f'''storage.{op}(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
    )''',1)
# Authority member addition and negative open tests bind the real store's facade.
edit(a+'maintenance_tests.rs','        let id = 4;','        let id = 4;\n        let storage = PhysicalFixture::new().unwrap();',1)
edit(a+'maintenance_tests.rs','''NodeStore::create_new_fixture(
                self._dir.path().join("authority-4.redb"),
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )''','''storage.create_new(
                storage.path("authority-4.redb"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )''',1)
edit(a+'maintenance_tests.rs','            request_budget(),\n            kasumi_raft::SnapshotBufferOwner::fixture(),','            request_budget(&storage.admission),\n            storage.admission.snapshot_buffer_owner().unwrap(),',1)
edit(a+'maintenance_tests.rs','        self.stores.push(stores);','        self.stores.push(stores);\n        self.physical.insert(id, storage);',1)
edit(a+'maintenance_tests.rs','        request_budget(),\n        kasumi_raft::SnapshotBufferOwner::fixture(),','        request_budget(&fixture.physical[&1].admission),\n        fixture.physical[&1].admission.snapshot_buffer_owner().unwrap(),',3)
# Strict bootstrap fixture keeps physical ownership through its consuming reopen.
edit(a+'bootstrap_open_tests.rs','    directory: tempfile::TempDir,','    physical: PhysicalFixture,',1)
edit(a+'bootstrap_open_tests.rs','        let directory = kasumi_store::test_utils::private_tempdir()?;','        let physical = PhysicalFixture::new()?;',1)
for op in ['create_new','open_existing']:
 edit(a+'bootstrap_open_tests.rs',f'''NodeStore::{op}_fixture(
            directory.path().join("authority.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )''',f'''physical.{op}(
            physical.path("authority.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )''',1)
edit(a+'bootstrap_open_tests.rs','            directory,','            physical,',3)
edit(a+'bootstrap_open_tests.rs','            request_budget(),\n            kasumi_raft::SnapshotBufferOwner::fixture(),','            request_budget(&self.physical.admission),\n            self.physical.admission.snapshot_buffer_owner().unwrap(),',1)
# Independent request-job tests have their own explicit admission, not a global core.
edit(a+'request_drain_tests.rs','    let mut charge = admission.reserve(bytes, None).unwrap();\n    charge.retain(bytes);','    let baseline = admission.snapshot().reserved_bytes;\n    let charge = admission.memory().reserve_resident(bytes).unwrap();',1)
edit(a+'request_drain_tests.rs','assert_eq!(admission.snapshot().reserved_bytes, bytes);','assert_eq!(admission.snapshot().reserved_bytes, baseline + bytes);',2)
edit(a+'request_drain_tests.rs','assert_eq!(admission.snapshot().reserved_bytes, 0);','assert_eq!(admission.snapshot().reserved_bytes, baseline);',1)
edit(a+'request_drain_tests.rs','    let jobs = RequestJobs::new(request_budget()).unwrap();','    let admission = kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap();\n    let jobs = RequestJobs::new(request_budget(&admission)).unwrap();',1)
edit(a+'activation_gate_tests.rs','''    let node_store = NodeStore::create_new_fixture(
        f._dir.path().join("actual-target.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )''','''    let storage = PhysicalFixture::new().unwrap();
    let node_store = storage.create_new(
        storage.path("actual-target.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
    )''',1)
# Materialization: source and every target are separate modeled physical processes.
f=a+'target_materialization_tests.rs'
edit(f,'    admissions: BTreeMap<u64, Arc<kasumi_engine::admission::NodeAdmission>>,','    physical: BTreeMap<u64, PhysicalFixture>,\n    _source_physical: PhysicalFixture,',1)
edit(f,'''        let node = NodeStore::create_new_fixture(
            issuer._dir.path().join("source.redb"),
            Uuid::new_v4(),
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let source_admission =
            kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap();''','''        let source_physical = PhysicalFixture::new().unwrap();
        let node = source_physical.create_new(
            source_physical.path("source.redb"), Uuid::new_v4(),
        ).unwrap();
        let source_admission = source_physical.admission.clone();''',1)
# The existing admitted root owns backup objects too; no extra fixture root/lease.
edit(f,'FilesystemBackupDestination::new_fixture(issuer._dir.path().join("backups"), 16 << 20)','FilesystemBackupDestination::new(source_physical.path("backups"), 16 << 20, source_physical.persistent.clone())',1)
edit(f,'''            admissions: (1..=3)
                .map(|id| {
                    (
                        id,
                        kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
                    )
                })
                .collect(),''','''            physical: (1..=3)
                .map(|id| (id, PhysicalFixture::new().unwrap()))
                .collect(),
            _source_physical: source_physical,''',1)
edit(f,'self.admissions[&id]','self.physical[&id].admission')
edit(f,'f.admissions[&projected_node_id]','f.physical[&projected_node_id].admission')
edit(f,'f.admissions[&1]','f.physical[&1].admission')
edit(f,'self.issuer._dir.path().join(format!("target-{id}.redb"))','self.physical[&id].path(format!("target-{id}.redb"))',1)
for op in ['create_new','open_existing']:
 edit(f,f'''NodeStore::{op}_fixture(
                    path,
                    node_store_id,
                    kasumi_store::ScratchDisk::fixture(),
                )''',f'''self.physical[&id].{op}(path, node_store_id)''',1)
edit(f,'f.issuer._dir.path().join("activation-journal.redb")','f.physical[&selected.id].path("activation-journal.redb")',1)
for op in ['create_new','open_existing']:
 edit(f,f'''NodeStore::{op}_fixture(
            &journal_path,
            journal_file_id,
            kasumi_store::ScratchDisk::fixture(),
        )''',f'''f.physical[&projected_node_id].{op}(&journal_path, journal_file_id)''',1)
for leaf in ['independent-target-journal.redb','file-intent-target.redb','target-1.redb','creation-outcome-journal.redb','creation-outcome-target.redb']:
 edit(f,f'f.issuer._dir.path().join("{leaf}")',f'f.physical[&1].path("{leaf}")',1)
edit(f,'NodeStore::create_new_fixture(&path, file_id, kasumi_store::ScratchDisk::fixture())','f.physical[&1].create_new(&path, file_id)',1)
edit(f,'NodeStore::open_existing_fixture(path, file_id, kasumi_store::ScratchDisk::fixture())','f.physical[&1].open_existing(path, file_id)',1)
edit(f,'NodeStore::create_new_fixture(\n        &file_path,\n        Uuid::new_v4(),\n        kasumi_store::ScratchDisk::fixture(),\n    )','f.physical[&1].create_new(&file_path, Uuid::new_v4())',1)
edit(f,'let node = NodeStore::create_new_fixture(\n        &journal_path,','let node = f.physical[&1].create_new(\n        &journal_path,',1)
edit(f,'        kasumi_store::ScratchDisk::fixture(),\n    )','    )',1)
edit(f,'kasumi_store::ScratchDisk::fixture()','f.physical[&1].scratch.clone()')
# Serving journals use the target physical owner, which already contains its generation.
f=a+'target_serving_tests.rs'
edit(f,'''    f.issuer
        ._dir
        .path()
        .join(format!("serving-journal-{id}.redb"))''','''    f.physical[&id].path(format!("serving-journal-{id}.redb"))''',1)
for op in ['create_new','open_existing']:
 edit(f,f'NodeStore::{op}_fixture(path, file_id, kasumi_store::ScratchDisk::fixture())',f'f.physical[&id].{op}(path, file_id)',1)
edit(f,'f.admissions[&id]','f.physical[&id].admission')
edit(f,'f.issuer._dir.path().join("activation-journal.redb")','f.physical[&id].path("activation-journal.redb")',1)
edit(f,'NodeStore::open_existing_fixture(\n            f.issuer._dir.path().join(format!("target-{id}.redb")),','f.physical[&id].open_existing(\n            f.physical[&id].path(format!("target-{id}.redb")),',1)
edit(f,'            kasumi_store::ScratchDisk::fixture(),\n','',1)
print('authority prepared')
# The embedded benchmark models multiple facades in one physical process.
f=b+'src/main.rs'
edit(f,'struct Databases {','''/// Retained for the entire benchmark case, including close/reopen. Replicas
/// share the original ONE scratch quota. Distinct runtime facades share the
/// aggregate of their original payload allowances; RSS ceilings are unchanged.
struct BenchmarkStorage {
    storage: kasumi_engine::test_utils::FixtureStorage,
    admissions: Vec<Arc<kasumi_engine::admission::NodeAdmission>>,
    root: PathBuf,
}
impl BenchmarkStorage {
    fn open(root: &Path, replicas: usize) -> Result<Self> {
        use kasumi_engine::admission::{AdmissionConfig, MemoryCore, NodeAdmission};
        let data = root.join("persistent");
        kasumi_store::private_files::create_directory(&data)?;
        let persistent = kasumi_store::NodeDisk::fixture_config(data.join("node.redb"))?;
        let scratch = kasumi_store::ScratchDiskConfig {
            directory: root.join("scratch"),
            max_bytes: 64 << 30,
            min_free_bytes: 256 << 20,
        };
        let original = AdmissionConfig::default();
        let payload = original.resolved_fixture_total_bytes()?
            .checked_sub(NodeAdmission::required_bookkeeping_bytes(&original)?)
            .context("original benchmark policy cannot fund its bookkeeping")?;
        let replicas_u64 = u64::try_from(replicas).context("replica count exceeds u64")?;
        let mut config = original.clone();
        config.max_inflight_operations = original.max_inflight_operations.checked_mul(replicas)
            .context("benchmark operation-slot count overflow")?;
        config.max_reservations = original.max_reservations.checked_mul(replicas)
            .context("benchmark reservation-slot count overflow")?;
        config.max_startup_scopes = original.max_startup_scopes.checked_mul(replicas)
            .context("benchmark startup-scope count overflow")?;
        let core = MemoryCore::required_bookkeeping_bytes(&config)?;
        let facade = NodeAdmission::required_bookkeeping_bytes(&config)?
            .checked_sub(core).context("benchmark facade bookkeeping underflow")?;
        let metadata = kasumi_engine::test_utils::isolated_disk_metadata_bytes(&persistent, &scratch)?;
        config.max_inflight_bytes = Some(payload.checked_mul(replicas_u64)
            .and_then(|n| n.checked_add(core))
            .and_then(|n| facade.checked_mul(replicas_u64).and_then(|f| n.checked_add(f)))
            .and_then(|n| n.checked_add(metadata))
            .context("benchmark aggregate admission capacity overflow")?);
        config.validate()?;
        let first = NodeAdmission::new(config)?;
        let mut admissions = Vec::with_capacity(replicas);
        admissions.push(first.clone());
        for _ in 1..replicas {
            admissions.push(NodeAdmission::from_memory(first.memory().clone())?);
        }
        let storage = kasumi_engine::test_utils::FixtureStorage::with_admission(
            &persistent, &scratch, first,
        )?;
        Ok(Self { storage, admissions, root: data })
    }
    fn path(&self, replica: usize) -> PathBuf {
        self.root.join(format!("replica-{replica}.redb"))
    }
}

struct Databases {''',1)
edit(f,'        path: &Path,\n        tenants: usize,','        physical: &BenchmarkStorage,\n        tenants: usize,',1)
start='''        let scratch_disk = kasumi_store::ScratchDisk::open(kasumi_store::ScratchDiskConfig {
            directory: path.join("scratch"),
            max_bytes: 64 << 30,
            min_free_bytes: 256 << 20,
        })?;'''
edit(f,start,'        ensure!(physical.admissions.len() == replicas, "benchmark physical replica count changed");',1)
for op in ['create_new','open_existing']:
 edit(f,f'''NodeStore::{op}_fixture(
                        path.join(format!("replica-{{replica}}.redb")),
                        kasumi_store::test_utils::NODE_STORE_ID,
                        scratch_disk.clone(),
                    )''',f'''physical.storage.{op}(
                        physical.path(replica),
                        kasumi_store::test_utils::NODE_STORE_ID,
                    )''',1)
edit(f,'        for node in &nodes {','        for (replica, node) in nodes.iter().enumerate() {',1)
edit(f,'kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),','physical.admissions[replica].clone(),',1)
edit(f,'        self.audits.clear();\n        self.nodes.clear();','''        self.audits.clear();
        for node in &self.nodes {
            if let Err(failure) = node.shutdown().await {
                report.merge(&failure);
            }
        }
        self.nodes.clear();''',1)
edit(f,'    let opened = Instant::now();\n    let databases = Databases::open(\n        directory.path(),','    let opened = Instant::now();\n    let physical = BenchmarkStorage::open(directory.path(), if replicated { 3 } else { 1 })?;\n    let databases = Databases::open(\n        &physical,',1)
edit(f,'    let databases = Databases::open(\n        directory.path(),','    let databases = Databases::open(\n        &physical,',1)
edit(f,'        let databases = Databases::open(dir.path(), 1, 1, 4, false, None, true)','        let physical = BenchmarkStorage::open(dir.path(), 1).unwrap();\n        let databases = Databases::open(&physical, 1, 1, 4, false, None, true)',1)
# Production loopback subprocess uses the unchanged installed disk policy and
# the new-install explicit memory policy from example_config, with private roots.
f=b+'src/bin/loopback.rs'
edit(f,'    config.database_path = path.join("node.redb");','''    let persistent = path.join("persistent");
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&persistent)?;
    }
    config.persistent_disk.roots = std::collections::BTreeMap::from([
        ("data".into(), persistent.clone()),
    ]);
    config.database_path = persistent.join("node.redb");''',1)
print('bench prepared')
