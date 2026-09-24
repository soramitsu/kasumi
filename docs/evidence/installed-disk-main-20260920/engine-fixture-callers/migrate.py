from pathlib import Path
import re
P=Path('target/installed-disk-validation/engine-fixture-callers/proposed/crates/kasumi-engine/src')
def edit(name, fn):
 p=P/name;s=p.read_text();p.write_text(fn(s))
def default_setup(root,indent='    '):
 return f'''let (persistent_config, scratch_config) = crate::test_utils::fixture_disk_configs({root}.path()).unwrap();
{indent}let storage = crate::test_utils::FixtureStorage::open(&persistent_config, &scratch_config, Default::default()).unwrap();
{indent}'''
for name,root in [('service_schema_tests.rs','root'),('service_staging_tests.rs','directory'),('service_credential_tests.rs','directory')]:
 def change(s):
  s=re.sub(r'let node = NodeStore::create_new_fixture\(\s*'+root+r'\.path\(\)\.join\("node.redb"\),\s*kasumi_store::test_utils::NODE_STORE_ID,\s*kasumi_store::ScratchDisk::fixture\(\),\s*\)\s*\.unwrap\(\);',default_setup(root)+f'let node = storage.create_new({root}.path().join("persistent/node.redb"), kasumi_store::test_utils::NODE_STORE_ID).unwrap();',s)
  s=s.replace('NodeAdmission::new(AdmissionConfig::default()).unwrap()','storage.admission.clone()')
  if name=='service_credential_tests.rs':
   s=s.replace('_directory: tempfile::TempDir,','_directory: tempfile::TempDir,\n    storage: crate::test_utils::FixtureStorage,')
   s=s.replace('_directory: directory,','_directory: directory,\n            storage,')
   s=s.replace('&kasumi_store::ScratchDisk::fixture()', 'fixture.db.store.scratch_disk()')
  return s
 edit(name,change)
# The four CredentialFixture destinations use the already admitted persistent root.
for name in ['service_custody_tests.rs','service_retirement_tests.rs','service_credential_tests.rs']:
 def change(s):
  s=s.replace('FilesystemBackupDestination::new_fixture(', 'FilesystemBackupDestination::new(')
  s=re.sub(r'fixture\._directory\.path\(\)\.join\("([^\"]+)"\),(\s*[^\n]+,)',r'fixture._directory.path().join("persistent/\1"),\2\n            fixture.storage.persistent.clone(),',s)
  return s
 edit(name,change)
# Reopen the exact credential installation.
def stopped(s):
 s=s.replace('_directory: directory,\n        db,','_directory: directory,\n        storage,\n        db,')
 s=re.sub(r'NodeStore::open_existing_fixture\(\s*directory\.path\(\)\.join\("node.redb"\),\s*kasumi_store::test_utils::NODE_STORE_ID,\s*kasumi_store::ScratchDisk::fixture\(\),\s*\)', 'storage.open_existing(directory.path().join("persistent/node.redb"), kasumi_store::test_utils::NODE_STORE_ID)',s)
 s=s.replace('crate::admission::NodeAdmission::new(Default::default()).unwrap()', 'storage.admission.clone()')
 return s
edit('service_staged_stop_tests.rs',stopped)
# Default admitted node fixtures whose path is declared directly in the test.
for name in ['security_audit.rs','security_audit_jobs.rs']:
 def change(s):
  pat=r'let path = directory\.path\(\)\.join\("([^\"]+)"\);\s*let node = NodeStore::create_new_fixture\(\s*&path,\s*kasumi_store::test_utils::NODE_STORE_ID,\s*kasumi_store::ScratchDisk::fixture\(\),\s*\)\s*\.unwrap\(\);'
  s=re.sub(pat,lambda m:default_setup('directory','        ')+f'let path = directory.path().join("persistent/{m[1]}");\n        let node = storage.create_new(&path, kasumi_store::test_utils::NODE_STORE_ID).unwrap();',s)
  # Only the default constructors within tests now containing `storage` are changed; synthetic final test kept separately.
  chunks=s.split('    #[tokio::test]')
  for i,c in enumerate(chunks):
   if 'let storage = crate::test_utils::FixtureStorage::open' not in c: continue
   c=c.replace('crate::admission::NodeAdmission::new(Default::default()).unwrap()', 'storage.admission.clone()')
   c=re.sub(r'NodeStore::open_existing_fixture\(\s*&path,\s*kasumi_store::test_utils::NODE_STORE_ID,\s*kasumi_store::ScratchDisk::fixture\(\),?\s*\)', 'storage.open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)',c)
   c=c.replace('FilesystemAuditArchive::open_fixture(\n                directory.path().join("archives"),\n            )','FilesystemAuditArchive::open(\n                directory.path().join("persistent/archives"), storage.persistent.clone(),\n            )')
   chunks[i]=c
  return '    #[tokio::test]'.join(chunks)
 edit(name,change)
def audit_destination(s):
 return s.replace('FilesystemAuditArchive::open_fixture(\n            store.durable_directory().unwrap().join("audit-archives"),','FilesystemAuditArchive::open(\n            store.durable_directory().unwrap().join("audit-archives"),\n            store.persistent_disk().clone(),')
edit('security_audit.rs',audit_destination)
def service(s):
 old='''let node = NodeStore::create_new_fixture(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();'''
 assert old in s
 s=s.replace(old,default_setup('directory','        ')+'''let node = storage.create_new(directory.path().join("persistent/node.redb"), kasumi_store::test_utils::NODE_STORE_ID).unwrap();''')
 # Exactly this test's inline audit argument.
 s=s.replace('crate::admission::NodeAdmission::new(Default::default()).unwrap(),','storage.admission.clone(),')
 return s
edit('service.rs',service)
