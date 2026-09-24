exec(open('target/installed-disk-validation/engine-fixture-callers/migrate.py').read().split('for name,root')[0])
def fixed_setup(indent='        '):
 return '''let (persistent_config, scratch_config) = crate::test_utils::fixture_disk_configs(directory.path())?;
'''+indent+'''let config = crate::test_utils::isolated_disk_config_with_metadata(Default::default(), &persistent_config, &scratch_config)?;
'''+indent+'''let admission = crate::admission::NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
'''+indent+'''let storage = crate::test_utils::FixtureStorage::with_admission(&persistent_config, &scratch_config, admission.clone())?;
'''+indent

def existing(s):
 s=s.replace('directory: tempfile::TempDir,','directory: tempfile::TempDir,\n    storage: crate::test_utils::FixtureStorage,',1)
 s=re.sub(r'let node = NodeStore::create_new_fixture\(\s*directory.path\(\).join\("node.redb"\),\s*kasumi_store::test_utils::NODE_STORE_ID,\s*kasumi_store::ScratchDisk::fixture\(\),\s*\)\?;',fixed_setup()+'let node = storage.create_new(directory.path().join("persistent/node.redb"), kasumi_store::test_utils::NODE_STORE_ID)?;',s)
 s=s.replace('''        let admission =
            crate::admission::NodeAdmission::with_fixed_memory(Default::default(), 2 << 30, 0)?;
''','')
 s=s.replace('''            directory,
            node,''','''            directory,
            storage,
            node,''')
 s=s.replace('''        directory,
        node,''','''        directory,
        storage,
        node,''')
 s=re.sub(r'NodeStore::open_existing_fixture\(\s*directory.path\(\).join\("node.redb"\),\s*kasumi_store::test_utils::NODE_STORE_ID,\s*kasumi_store::ScratchDisk::fixture\(\),\s*\)', 'storage.open_existing(directory.path().join("persistent/node.redb"), kasumi_store::test_utils::NODE_STORE_ID)',s)
 s=s.replace('crate::admission::NodeAdmission::with_fixed_memory(Default::default(), 2 << 30, 0)?,','storage.admission.clone(),')
 return s
edit('bootstrap_existing_tests.rs',existing)
def replicated(s):
 s=s.replace('directory: tempfile::TempDir,','directory: tempfile::TempDir,\n    storage: crate::test_utils::FixtureStorage,',1)
 s=re.sub(r'let node = NodeStore::create_new_fixture\(\s*directory.path\(\).join\("node.redb"\),\s*NODE_STORE_ID,\s*kasumi_store::ScratchDisk::fixture\(\),\s*\)\?;',fixed_setup()+'let node = storage.create_new(directory.path().join("persistent/node.redb"), NODE_STORE_ID)?;',s)
 s=s.replace('async fn existing(directory: tempfile::TempDir)', 'async fn existing((directory, storage): (tempfile::TempDir, crate::test_utils::FixtureStorage))')
 s=re.sub(r'NodeStore::open_existing_fixture\(\s*directory.path\(\).join\("node.redb"\),\s*NODE_STORE_ID,\s*kasumi_store::ScratchDisk::fixture\(\),\s*\)', 'storage.open_existing(directory.path().join("persistent/node.redb"), NODE_STORE_ID)',s)
 s=s.replace('Self::audit(node.clone(), false)', 'Self::audit(node.clone(), false, storage.admission.clone())').replace('Self::audit(node.clone(), true)', 'Self::audit(node.clone(), true, storage.admission.clone())')
 s=s.replace('async fn audit(node: Arc<NodeStore>, existing: bool)', 'async fn audit(node: Arc<NodeStore>, existing: bool, admission: Arc<crate::admission::NodeAdmission>)')
 s=s.replace('''        let admission =
            crate::admission::NodeAdmission::with_fixed_memory(Default::default(), 2 << 30, 0)?;
''','')
 s=s.replace('''            directory,
            node,''','''            directory,
            storage,
            node,''')
 s=s.replace('''            directory,
            stores,''','''            directory,
            storage,
            stores,''')
 s=s.replace('async fn close(self) -> tempfile::TempDir', 'async fn close(self) -> (tempfile::TempDir, crate::test_utils::FixtureStorage)')
 s=s.replace('''        directory
    }
    fn seed''','''        (directory, storage)
    }
    fn seed''')
 return s
edit('bootstrap_existing_replicated_tests.rs',replicated)
def journal(s):
 s=s.replace('NodeStore, ScratchDisk, ', 'NodeStore, ')
 s=s.replace('directory: tempfile::TempDir,','directory: tempfile::TempDir,\n    storage: crate::test_utils::FixtureStorage,',1)
 s=re.sub(r'let node = NodeStore::create_new_fixture\(\s*directory.path\(\).join\("journal.redb"\),\s*id,\s*ScratchDisk::fixture\(\),\s*\)\?;',fixed_setup()+'let node = storage.create_new(directory.path().join("persistent/journal.redb"), id)?;',s)
 s=s.replace('''            directory,
            id,''','''            directory,
            storage,
            id,''')
 s=re.sub(r'admission: crate::admission::NodeAdmission::with_fixed_memory\(\s*Default::default\(\),\s*2 << 30,\s*0,\s*\)\?,','admission,',s)
 s=s.replace('''        directory,
        id,''','''        directory,
        storage,
        id,''')
 s=s.replace('directory.path().join("journal.redb")', 'directory.path().join("persistent/journal.redb")')
 s=s.replace('NodeStore::open_existing_fixture(&path, Uuid::new_v4(), ScratchDisk::fixture())', 'storage.open_existing(&path, Uuid::new_v4())')
 s=s.replace('NodeStore::open_existing_fixture(&path, id, ScratchDisk::fixture())', 'storage.open_existing(&path, id)')
 return s
edit('target_journal_open_tests.rs',journal)
def security_existing(s):
 s=s.replace('NodeStore, ScratchDisk, ', '')
 s=s.replace('disk: Arc<ScratchDisk>,','storage: crate::test_utils::FixtureStorage,\n    metadata_bytes: u64,')
 s=s.replace('''        Ok(Self {''',fixed_setup()+'''let metadata_bytes = crate::test_utils::isolated_disk_metadata_bytes(&persistent_config, &scratch_config)?;
        Ok(Self {''',1)
 s=s.replace('path: private.join("node.redb"),','path: directory.path().join("persistent/node.redb"),')
 # Evaluate path before moving directory.
 s=s.replace('''            _directory: directory,
            path: directory.path().join("persistent/node.redb"),''','''            path: directory.path().join("persistent/node.redb"),
            _directory: directory,''')
 s=s.replace('''            disk: ScratchDisk::fixture(),
            admission: NodeAdmission::with_fixed_memory(Default::default(), 2 << 30, 0)?,''','''            storage,
            metadata_bytes,
            admission,''')
 s=s.replace('NodeStore::create_new_fixture(&self.path, self.id, self.disk.clone())','self.storage.create_new(&self.path, self.id)').replace('NodeStore::open_existing_fixture(&self.path, self.id, self.disk.clone())','self.storage.open_existing(&self.path, self.id)')
 s=re.sub(r'(reserved_payload_bytes\(&installation.admission\),\s*)0',r'\1installation.metadata_bytes',s)
 return s
edit('security_audit_existing_tests.rs',security_existing)
def retention(s):
 s=s.replace('''let path = directory.path().join("security.redb");
        let persistent = kasumi_store::NodeDisk::fixture_for_path(&path).unwrap();''',default_setup('directory','        ')+'''let path = directory.path().join("persistent/security.redb");
        let persistent = storage.persistent.clone();''')
 s=s.replace('directory.path().join("archives")','directory.path().join("persistent/archives")')
 s=s.replace('crate::admission::NodeAdmission::new(Default::default()).unwrap()','storage.admission.clone()')
 s=re.sub(r'NodeStore::(create_new|open_existing)_fixture\(\s*&path,\s*kasumi_store::test_utils::NODE_STORE_ID,\s*kasumi_store::ScratchDisk::fixture\(\),\s*\)',lambda m:f'storage.{m[1]}(&path, kasumi_store::test_utils::NODE_STORE_ID)',s)
 return s
edit('security_audit_retention.rs',retention)
