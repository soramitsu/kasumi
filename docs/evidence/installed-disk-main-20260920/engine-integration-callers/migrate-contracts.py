from pathlib import Path
import re
out=Path('target/installed-disk-validation/engine-integration-callers/proposed/crates/kasumi-engine/tests')
p=out/'common/mod.rs';s=p.read_text();s=s.replace('    pub fn new(\n        tenant: String,','    pub fn new(\n        memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,\n        tenant: String,')
s=s.replace('        let memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);\n','')
p.write_text(s)
for name in ['contracts','schema_activation','staged_transactions','snapshot_budget']:
 p=out/(name+'.rs');s=p.read_text().replace('FixtureEngine::new(', 'FixtureEngine::new(kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32), ');p.write_text(s)
p=out/'contracts.rs';s=p.read_text()
s=s.replace('    tempfile::TempDir,\n    Arc<Database>,','    tempfile::TempDir,\n    common::PhysicalFixture,\n    Arc<Database>,',1)
s=s.replace('    (dir, db, key, store, audit)','    (dir, physical, db, key, store, audit)')
s=re.sub(r'let \((_[a-z_]+), (.*?)\) = database\(',r'let (\1, _physical, \2) = database(',s)
# Three fresh real installations; each has an explicitly retained physicalscope.
pattern=r'    let node = NodeStore::create_new_fixture\(\n        ([^\n]+),\n        kasumi_store::test_utils::NODE_STORE_ID,\n        kasumi_store::ScratchDisk::fixture\(\),\n    \)'
s,n=re.subn(pattern,lambda m:f'    let physical = common::PhysicalFixture::new(&{m[1]}, Default::default());\n    let node = physical.storage.create_new({m[1]}, kasumi_store::test_utils::NODE_STORE_ID)',s);assert n==3,n
# Parent of the killed worker is a fresh real process/census, separate from the
# child process's prior installed owner; the test keeps the same durable bytes.
s=s.replace('    let node = NodeStore::open_existing_fixture(\n        dir.path().join("node.redb"),\n        kasumi_store::test_utils::NODE_STORE_ID,\n        kasumi_store::ScratchDisk::fixture(),\n    )','    let physical = common::PhysicalFixture::new(&dir.path().join("node.redb"), Default::default());\n    let node = physical.storage.open_existing(dir.path().join("node.redb"), kasumi_store::test_utils::NODE_STORE_ID)')
s=s.replace('common::security_audit(node.clone())','common::security_audit(node.clone(), physical.storage.admission.clone())').replace('common::existing_security_audit(node.clone())','common::existing_security_audit(node.clone(), physical.storage.admission.clone())')
# Synthetic audit fault has a real metadata owner, admitted before redb work.
s=s.replace('    let backend = kasumi_store::test_utils::FaultBackend::new();\n    let node = NodeStore::open_with_backend(', '    let audit_directory = kasumi_store::test_utils::private_tempdir().unwrap();\n    let physical = common::PhysicalFixture::new(&audit_directory.path().join("synthetic-owner"), Default::default());\n    let backend = kasumi_store::test_utils::FaultBackend::new();\n    let node = NodeStore::open_fixture_backend_on_disk(')
s=s.replace('        kasumi_store::test_utils::storage_admission(),\n        kasumi_store::ScratchDisk::fixture(),','        kasumi_store::test_utils::storage_admission(),\n        physical.storage.persistent.clone(),\n        physical.storage.scratch.clone(),')
s=s.replace('    .unwrap();\n    let audit_directory = kasumi_store::test_utils::private_tempdir().unwrap();\n    let audit_store', '    .unwrap();\n    let audit_store')
s=s.replace('audit_directory.path().join("archive"),\n            )','audit_directory.path().join("archive"),\n                physical.storage.admission.memory().clone(),\n            )')
s=s.replace('kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),','physical.storage.admission.clone(),')
# Filesystem backup is a namespace on source's existing physical root; there is
# no unrelated governor or extra unseen owner. Source scope persists to end.
s=s.replace('    let backup_dir = kasumi_store::test_utils::private_tempdir().unwrap();\n','')
s=s.replace('kasumi_store::FilesystemBackupDestination::new_fixture(backup_dir.path(), 16 << 20)', 'kasumi_store::FilesystemBackupDestination::new_fixture(_source_dir.path().join("backups"), 16 << 20, source_audit.admission().memory().clone())')
p.write_text(s)
p=out/'shutdown.rs';s=p.read_text();s=s.replace('    let provider =', '    let physical = common::PhysicalFixture::new(&path, Default::default());\n    let provider =',1)
s=re.sub(r'NodeStore::(create_new|open_existing)_fixture\(\s*&path,\s*kasumi_store::test_utils::NODE_STORE_ID,\s*kasumi_store::ScratchDisk::fixture\(\),?\s*\)',r'physical.storage.\1(&path, kasumi_store::test_utils::NODE_STORE_ID)',s)
s=s.replace('common::security_audit(node.clone())','common::security_audit(node.clone(), physical.storage.admission.clone())').replace('common::existing_security_audit(node.clone())','common::existing_security_audit(node.clone(), physical.storage.admission.clone())')
s=s.replace('        drop(node);','        node.shutdown().await.unwrap();\n        drop(node);').replace('        drop(reopened);','        reopened.shutdown().await.unwrap();\n        drop(reopened);')
s=s.replace('NodeStore, TenantStore','TenantStore');p.write_text(s)
