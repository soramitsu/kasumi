exec(open('target/installed-disk-validation/engine-fixture-callers/migrate.py').read().split('for name,root')[0])
for name in ['mutation_apply_tests.rs','lease_retention_tests.rs']:
 edit(name,lambda s:s.replace('TestDiskMemory::new(64 << 20, 32).unwrap()', 'TestDiskMemory::new(64 << 20, 32)'))
def synth(s):
 old='''        let archive = Arc::new(
            kasumi_store::FilesystemAuditArchive::open_fixture(directory.path().join("archive"))
                .unwrap(),
        );
        let admission = crate::admission::NodeAdmission::new(Default::default()).unwrap();'''
 assert old in s
 s=s.replace(old,'''        '''+default_setup('directory','        ')+'''let archive = Arc::new(kasumi_store::FilesystemAuditArchive::open(directory.path().join("persistent/archive"), storage.persistent.clone()).unwrap());
        let admission = storage.admission.clone();''')
 s=s.replace('NodeStore::open_with_backend(', 'NodeStore::open_fixture_backend_on_disk(')
 s=s.replace('''                kasumi_store::ScratchDisk::fixture(),''','''                storage.persistent.clone(),
                storage.scratch.clone(),''')
 return s
edit('security_audit.rs',synth)
def bootstrap_fixture(s):
 old='''let node = NodeStore::create_new_fixture(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let admission = NodeAdmission::new(Default::default()).unwrap();'''
 assert old in s
 s=s.replace(old,default_setup('directory','        ')+'''let node = storage.create_new(directory.path().join("persistent/node.redb"), kasumi_store::test_utils::NODE_STORE_ID).unwrap();
        let admission = storage.admission.clone();''')
 return s
edit('bootstrap_fixtures.rs',bootstrap_fixture)
def startup(s):
 s=s.replace('''    let config = AdmissionConfig::default();''','''    let directory = kasumi_store::test_utils::private_tempdir()?;
    let (persistent_config, scratch_config) = crate::test_utils::fixture_disk_configs(directory.path())?;
    let metadata_bytes = crate::test_utils::isolated_disk_metadata_bytes(&persistent_config, &scratch_config)?;
    let config = crate::test_utils::isolated_disk_config_with_metadata(AdmissionConfig::default(), &persistent_config, &scratch_config)?;''')
 s=s.replace('''    let core = admission.memory().clone();''','''    let storage = crate::test_utils::FixtureStorage::with_admission(&persistent_config, &scratch_config, admission.clone())?;
    let core = admission.memory().clone();''')
 s=s.replace('''    let directory = kasumi_store::test_utils::private_tempdir()?;
    let stores''','''    let stores''')
 s=re.sub(r'kasumi_store::NodeStore::create_new_fixture\(\s*directory.path\(\).join\("cancelled-node-startup.redb"\),\s*kasumi_store::test_utils::NODE_STORE_ID,\s*kasumi_store::ScratchDisk::fixture\(\),\s*\)', 'storage.create_new(directory.path().join("persistent/cancelled-node-startup.redb"), kasumi_store::test_utils::NODE_STORE_ID)',s)
 s=s.replace('assert_eq!(pending.resident_reserved_bytes, owner_bytes);','assert_eq!(pending.resident_reserved_bytes, metadata_bytes + owner_bytes);')
 s=s.replace('assert_eq!(completed.resident_reserved_bytes, 0);','assert_eq!(completed.resident_reserved_bytes, metadata_bytes);')
 s=s.replace('''    drop(admission);
    assert!''','''    drop(storage);
    drop(admission);
    assert!''')
 s=s.replace('core.snapshot().reserved_bytes, core_base','core.snapshot().reserved_bytes, core_base + metadata_bytes')
 return s
edit('admission_startup_tests.rs',startup)
def maintenance(s):
 pat=r'let path = directory.path\(\).join\("node.redb"\);\s*let node = NodeStore::create_new_fixture\(\s*&path,\s*kasumi_store::test_utils::NODE_STORE_ID,\s*kasumi_store::ScratchDisk::fixture\(\),\s*\)\s*.unwrap\(\);'
 s=re.sub(pat,default_setup('directory','            ')+'''let path = directory.path().join("persistent/node.redb");
            let node = storage.create_new(&path, kasumi_store::test_utils::NODE_STORE_ID).unwrap();''',s)
 s=s.replace('let admission = NodeAdmission::new(Default::default()).unwrap();','let admission = storage.admission.clone();')
 s=re.sub(r'NodeStore::open_existing_fixture\(\s*&path,\s*kasumi_store::test_utils::NODE_STORE_ID,\s*kasumi_store::ScratchDisk::fixture\(\),\s*\)', 'storage.open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)',s)
 start=s.index('        let node = NodeStore::create_new_fixture(',s.index('async fn worker_drains_hot_history'))
 end=s.index('        let store = TenantStore',start)
 s=s[:start]+'''        let (persistent_config, scratch_config) = crate::test_utils::fixture_disk_configs(directory.path()).unwrap();
        let metadata_bytes = crate::test_utils::isolated_disk_metadata_bytes(&persistent_config, &scratch_config).unwrap();
        let config = crate::test_utils::admission_config_with_bookkeeping(crate::admission::AdmissionConfig { max_inflight_bytes: Some(512 << 20), ..Default::default() }).unwrap();
        let storage = crate::test_utils::FixtureStorage::open(&persistent_config, &scratch_config, config).unwrap();
        let admission = storage.admission.clone();
        let node = storage.create_new(directory.path().join("persistent/node.redb"), kasumi_store::test_utils::NODE_STORE_ID).unwrap();
'''+s[end:]
 s=s.replace('FilesystemAuditArchive::open_fixture(directory.path().join("external"))', 'FilesystemAuditArchive::open(directory.path().join("persistent/external"), storage.persistent.clone())')
 s=s.replace('''FilesystemAuditArchive::open_fixture(
                        directory.path().join("tenant-audit-archives"),''','''FilesystemAuditArchive::open(
                        directory.path().join("persistent/tenant-audit-archives"),
                        storage.persistent.clone(),''')
 s=s.replace('(512 << 20) - crate::test_utils::reserved_payload_bytes(&admission)','(512 << 20) + metadata_bytes - crate::test_utils::reserved_payload_bytes(&admission)')
 s=s.replace('''            kasumi_raft::SnapshotBufferOwner::required_bytes''','''            metadata_bytes + kasumi_raft::SnapshotBufferOwner::required_bytes''')
 s=s.replace('assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), 0);','assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), metadata_bytes);')
 return s
edit('audit_maintenance_service.rs',maintenance)
def serving(s):
 s=s.replace('directory: tempfile::TempDir,','directory: tempfile::TempDir,\n    storage: Vec<crate::test_utils::FixtureStorage>,',1)
 s=s.replace('''        let mut fixture = Self {
            directory: kasumi_store::test_utils::private_tempdir().unwrap(),''','''        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let storage = (1..=3).map(|id| {
            let root = directory.path().join(format!("node-{id}"));
            kasumi_store::private_files::create_directory(&root).unwrap();
            let (persistent, scratch) = crate::test_utils::fixture_disk_configs(&root).unwrap();
            crate::test_utils::FixtureStorage::open(&persistent, &scratch, Default::default()).unwrap()
        }).collect();
        let mut fixture = Self {
            directory,
            storage,''')
 start=s.index('            let node = (if create {');end=s.index('            let audit_store =',start)
 s=s[:start]+'''            let storage = &self.storage[id as usize - 1];
            let path = self.directory.path().join(format!("node-{id}/persistent/node.redb"));
            let node = (if create {
                storage.create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)
            } else {
                storage.open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
            }).unwrap();
'''+s[end:]
 s=s.replace('crate::admission::NodeAdmission::new(Default::default()).unwrap()', 'storage.admission.clone()')
 s=s.replace('FilesystemAuditArchive::open_fixture(', 'FilesystemAuditArchive::open(')
 s=s.replace('''.join("audit-archives"),
                )''','''.join("audit-archives"),
                    storage.persistent.clone(),
                )''')
 s=s.replace('FilesystemBackupDestination::new_fixture(', 'FilesystemBackupDestination::new(')
 s=s.replace('''fixture.directory.path().join("backups"),
            32 << 20,''','''db.store.durable_directory().unwrap().join("backups"),
            32 << 20,
            db.store.persistent_disk().clone(),''')
 return s
edit('service_serving_tests.rs',serving)
