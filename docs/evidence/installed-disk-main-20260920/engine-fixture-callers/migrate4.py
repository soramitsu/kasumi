exec(open('target/installed-disk-validation/engine-fixture-callers/migrate.py').read().split('for name,root')[0])
def jobs(s):
 s=s.replace('let path = directory.path().join("audit.redb");',default_setup('directory','        ')+'let path = directory.path().join("persistent/audit.redb");')
 s=re.sub(r'NodeStore::(create_new|open_existing)_fixture\(\s*&path,\s*kasumi_store::test_utils::NODE_STORE_ID,\s*kasumi_store::ScratchDisk::fixture\(\),?\s*\)',lambda m:f'storage.{m[1]}(&path, kasumi_store::test_utils::NODE_STORE_ID)',s)
 s=s.replace('crate::admission::NodeAdmission::new(Default::default()).unwrap()', 'storage.admission.clone()')
 s=s.replace('''FilesystemAuditArchive::open_fixture(
                directory.path().join("archives"),''','''FilesystemAuditArchive::open(
                directory.path().join("persistent/archives"), storage.persistent.clone(),''')
 return s
edit('security_audit_jobs.rs',jobs)
def workers(s):
 s=s.replace('NodeStore, ScratchDisk,','NodeStore,')
 s=s.replace('directory: tempfile::TempDir,','directory: tempfile::TempDir,\n    storage: crate::test_utils::FixtureStorage,',1)
 start=s.index('    async fn new(');end=s.index('        let store =',start)
 s=s[:start]+'''    async fn new(name: &str) -> anyhow::Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (persistent, scratch) = crate::test_utils::fixture_disk_configs(directory.path())?;
        let storage = crate::test_utils::FixtureStorage::open(&persistent, &scratch, Default::default())?;
        Self::on_disk(directory, storage, name).await
    }
    async fn on_disk(directory: tempfile::TempDir, storage: crate::test_utils::FixtureStorage, name: &str) -> anyhow::Result<Self> {
        let admission = storage.admission.clone();
        let path = directory.path().join("persistent/node.redb");
        let node = storage.create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)?;
'''+s[end:]
 s=s.replace('''            directory,
            path,''','''            directory,
            storage,
            path,''')
 s=re.sub(r'NodeStore::open_existing_fixture\(\s*&self.path,\s*kasumi_store::test_utils::NODE_STORE_ID,\s*ScratchDisk::fixture\(\),?\s*\)', 'self.storage.open_existing(&self.path, kasumi_store::test_utils::NODE_STORE_ID)',s)
 s=s.replace('Fixture::new(NodeAdmission::new(Default::default())?, "tenant")', 'Fixture::new("tenant")')
 s=s.replace('''    let admission = NodeAdmission::new(Default::default())?;
    let blocked = Fixture::new(admission.clone(), "blocked").await?;''','''    let blocked_directory = kasumi_store::test_utils::private_tempdir()?;
    let waiting_directory = kasumi_store::test_utils::private_tempdir()?;
    let (blocked_persistent, blocked_scratch) = crate::test_utils::fixture_disk_configs(blocked_directory.path())?;
    let (waiting_persistent, waiting_scratch) = crate::test_utils::fixture_disk_configs(waiting_directory.path())?;
    // One original operation allowance, plus both actual isolated installations.
    let config = crate::test_utils::isolated_disk_config_with_metadata(Default::default(), &blocked_persistent, &blocked_scratch)?;
    let config = crate::test_utils::isolated_disk_config_with_metadata(config, &waiting_persistent, &waiting_scratch)?;
    let admission = NodeAdmission::new(config)?;
    let blocked_storage = crate::test_utils::FixtureStorage::with_admission(&blocked_persistent, &blocked_scratch, admission.clone())?;
    let waiting_storage = crate::test_utils::FixtureStorage::with_admission(&waiting_persistent, &waiting_scratch, admission)?;
    let blocked = Fixture::on_disk(blocked_directory, blocked_storage, "blocked").await?;''')
 s=s.replace('Fixture::new(admission, "waiting")','Fixture::on_disk(waiting_directory, waiting_storage, "waiting")')
 return s
edit('database_worker_outcome_tests.rs',workers)
def genesis(s):
 s=s.replace('let disk = kasumi_store::ScratchDisk::fixture();','''let scratch = crate::codec_fixture::ScratchScope::new(kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32)).unwrap();
    let disk = scratch.disk.clone();''')
 s=s.replace('async fn audit(node: Arc<NodeStore>)', 'async fn audit(node: Arc<NodeStore>, admission: Arc<crate::admission::NodeAdmission>)')
 s=s.replace('crate::admission::NodeAdmission::with_fixed_memory(Default::default(), 2 << 30, 0)?,','admission,')
 s=s.replace('audit(node.clone())','audit(node.clone(), storage.admission.clone())')
 # Each test selects its governor before disks. Two physical files within one installation reuse both disks.
 s=s.replace('''    let directory = kasumi_store::test_utils::private_tempdir()?;
    let node =''','''    let directory = kasumi_store::test_utils::private_tempdir()?;
    let (persistent, scratch) = crate::test_utils::fixture_disk_configs(directory.path())?;
    let config = crate::test_utils::isolated_disk_config_with_metadata(Default::default(), &persistent, &scratch)?;
    let admission = crate::admission::NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
    let storage = crate::test_utils::FixtureStorage::with_admission(&persistent, &scratch, admission)?;
    let node =''')
 s=re.sub(r'NodeStore::create_new_fixture\(\s*directory.path\(\).join\("([^\"]+)"\),\s*uuid::Uuid::new_v4\(\),\s*kasumi_store::ScratchDisk::fixture\(\),\s*\)',lambda m:f'storage.create_new(directory.path().join("persistent/{m[1]}"), uuid::Uuid::new_v4())',s)
 return s
edit('bootstrap_control_genesis_tests.rs',genesis)
def tenant_audit(s):
 s=s.replace('''        let node = NodeStore::create_new_fixture(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )''','''        let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32);
        kasumi_store::private_files::create_directory(&directory.path().join("persistent")).unwrap();
        let disk = kasumi_store::ScratchDisk::fixture(directory.path().join("scratch"), memory.clone());
        let node = NodeStore::create_new_fixture(
            directory.path().join("persistent/node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            memory,
            disk,
        )''')
 s=s.replace('FilesystemAuditArchive::open_fixture(directory.path().join("tenant-audit-archives"))','FilesystemAuditArchive::open(directory.path().join("persistent/tenant-audit-archives"), store.persistent_disk().clone())')
 s=s.replace('FilesystemAuditArchive::open_fixture(directory.path().join("external"))','FilesystemAuditArchive::open(directory.path().join("persistent/external"), store.persistent_disk().clone())')
 s=s.replace('.apply_command(\n                    revision,','.apply_command(\n                    store.scratch_disk(),\n                    revision,')
 s=s.replace('''        drop(engine);
        drop(store);

        let node''','''        drop(engine);
        let disk = store.scratch_disk().clone();
        let persistent = store.persistent_disk().clone();
        drop(store);

        let node''')
 s=s.replace('''NodeStore::open_existing_fixture(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),''','''NodeStore::open_existing(
            directory.path().join("persistent/node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            persistent,
            disk,''')
 s=s.replace('''FilesystemAuditArchive::open_fixture(
                        directory.path().join("tenant-audit-archives"),''','''FilesystemAuditArchive::open(
                        directory.path().join("persistent/tenant-audit-archives"), store.persistent_disk().clone(),''')
 return s
edit('tenant_audit.rs',tenant_audit)
