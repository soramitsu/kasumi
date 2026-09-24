from pathlib import Path
import re
root=Path.cwd(); out=root/'target/installed-disk-validation/engine-integration-callers/proposed/crates/kasumi-engine/tests'
p=out/'common/mod.rs'; s=p.read_text()
start=s.index('/// The node\'s service security ledger')
end=s.index('#[allow(dead_code)]\npub fn local_restore_request')
s=s[:start]+'''/// Explicit physical fixture lifetime. The caller retains the persistent
/// parent; this value retains the separate private scratch directory and the
/// original owners through shutdown and reopen.
#[allow(dead_code)]
pub struct PhysicalFixture {
    pub storage: kasumi_engine::test_utils::FixtureStorage,
    _scratch_directory: tempfile::TempDir,
}
#[allow(dead_code)]
impl PhysicalFixture {
    pub fn new(path: &std::path::Path, config: kasumi_engine::admission::AdmissionConfig) -> Self {
        let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let persistent = kasumi_store::NodeDisk::fixture_config(path).unwrap();
        let scratch = kasumi_store::ScratchDiskConfig {
            directory: scratch_directory.path().to_owned(),
            max_bytes: 256 << 30,
            min_free_bytes: 0,
        };
        let storage = kasumi_engine::test_utils::FixtureStorage::open(&persistent, &scratch, config).unwrap();
        Self { storage, _scratch_directory: scratch_directory }
    }
}

/// The exact runtime facade is required before the service ledger can open.
#[allow(dead_code)]
pub async fn security_audit(
    node: Arc<NodeStore>,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
) -> Arc<SecurityAudit> {
    let store = TenantStore::initialize_catalog_fixture(
        node,
        SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([0xA7; 32])),
    ).await.unwrap();
    SecurityAudit::initialize(store, kasumi_types::AuditRetentionBudget::default(), admission).unwrap()
}

/// Reopen a previously initialized ledger under its exact physical memory core.
#[allow(dead_code)]
pub async fn existing_security_audit(
    node: Arc<NodeStore>,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
) -> Arc<SecurityAudit> {
    let store = TenantStore::open_existing_fixture(
        node,
        SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([0xA7; 32])),
    ).await.unwrap();
    SecurityAudit::open(store, kasumi_types::AuditRetentionBudget::default(), admission).unwrap()
}

'''+s[end:]
p.write_text(s)
# Independent one-installation test scopes retain both directories until all
# local engine/audit/store values are dropped; no reopen creates new owners.
for name in ['concurrent_pagination','control','ordered_seek','restore_deadline']:
    p=out/(name+'.rs'); s=p.read_text()
    pattern=r'    let node = NodeStore::create_new_fixture\(\n        ([^\n]+),\n        kasumi_store::test_utils::NODE_STORE_ID,\n        kasumi_store::ScratchDisk::fixture\(\),\n    \)\n    \.unwrap\(\);'
    def replace(m):
        path=m.group(1)
        return f'''    let physical = common::PhysicalFixture::new(&{path}, Default::default());
    let node = physical.storage.create_new(
        {path}, kasumi_store::test_utils::NODE_STORE_ID,
    ).unwrap();'''
    s,n=re.subn(pattern,replace,s); assert n==1,(name,n)
    s=s.replace('common::security_audit(node.clone())','common::security_audit(node.clone(), physical.storage.admission.clone())')
    # NodeStore is now constructed through the retained explicit fixture scope.
    s=s.replace('BackupDestination, NodeStore, TenantStore','BackupDestination, TenantStore').replace('NodeStore, TenantStore','TenantStore')
    p.write_text(s)
# The response test preserves its single execution slot, now on the storage core.
p=out/'response_release.rs'; s=p.read_text()
start=s.index('    let node = NodeStore::create_new_fixture('); end=s.index('    let audit =',start)
s=s[:start]+'''    let physical = common::PhysicalFixture::new(
        &directory.path().join("node.redb"),
        kasumi_engine::admission::AdmissionConfig {
            max_inflight_operations: 1,
            ..Default::default()
        },
    );
    let node = physical.storage.create_new(directory.path().join("node.redb"), kasumi_store::test_utils::NODE_STORE_ID).unwrap();
    let admission = physical.storage.admission.clone();
'''+s[end:]
s=s.replace('common::security_audit_with_admission(', 'common::security_audit(').replace('NodeStore, TenantStore','TenantStore')
p.write_text(s)
# Clock fixtures each retain their actual memory/storage through all epoch tests.
p=out/'fixture_epoch_clock.rs'; s=p.read_text()
if 'mod common;' not in s: s='mod common;\n'+s
pattern=r'    let node = NodeStore::create_new_fixture\(\n        directory.path\(\).join\("node.redb"\),\n        kasumi_store::test_utils::NODE_STORE_ID,\n        kasumi_store::ScratchDisk::fixture\(\),\n    \)\n    \.unwrap\(\);\n    let admission = NodeAdmission::new\(Default::default\(\)\).unwrap\(\);'
replace='''    let physical = common::PhysicalFixture::new(&directory.path().join("node.redb"), Default::default());
    let node = physical.storage.create_new(directory.path().join("node.redb"), kasumi_store::test_utils::NODE_STORE_ID).unwrap();
    let admission = physical.storage.admission.clone();'''
s,n=re.subn(pattern,replace,s); assert n==3,n
# Different facade test specifically rejects facade identity even when memory
# identity agrees; the new facade is small and charged on the existing core.
s=s.replace('NodeAdmission::new(Default::default()).unwrap(),\n        epoch,','NodeAdmission::from_memory(physical.storage.admission.memory().clone()).unwrap(),\n        epoch,')
p.write_text(s)
