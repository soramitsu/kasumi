from pathlib import Path
import re
out=Path('target/installed-disk-validation/engine-integration-callers/proposed/crates/kasumi-engine/tests')
p=out/'common/mod.rs';s=p.read_text()
s+='''

/// Pure ordered-apply fixture with an explicit bounded scratch owner. The
/// engine and every retained generation drop before the enclosing private
/// directory; these fixtures do not construct serving or Raft capabilities.
#[allow(dead_code)]
pub struct FixtureEngine {
    engine: kasumi_engine::TenantEngine,
    pub disk: Arc<kasumi_store::ScratchDisk>,
    _directory: tempfile::TempDir,
}
#[allow(dead_code)]
impl FixtureEngine {
    pub fn new(tenant: String, incarnation: String, policy: kasumi_types::Policy, limits: kasumi_types::Limits) -> kasumi_types::Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let disk = kasumi_store::ScratchDisk::fixture(directory.path(), memory);
        let engine = kasumi_engine::TenantEngine::new(tenant, incarnation, policy, limits)?;
        Ok(Self { engine, disk, _directory: directory })
    }
}
impl std::ops::Deref for FixtureEngine {
    type Target = kasumi_engine::TenantEngine;
    fn deref(&self) -> &Self::Target { &self.engine }
}
'''
p.write_text(s)
for name in ['contracts','schema_activation','staged_transactions','snapshot_budget']:
    p=out/(name+'.rs');s=p.read_text()
    # This type is used only by ordered-apply fixtures in these four files.
    s=s.replace('use kasumi_engine::{Database, TenantEngine};','use kasumi_engine::Database;\nuse common::FixtureEngine;')
    s=s.replace('use kasumi_engine::{Database, SecurityAudit, TenantEngine};','use kasumi_engine::{Database, SecurityAudit};\nuse common::FixtureEngine;')
    s=s.replace('use kasumi_engine::TenantEngine;','mod common;\nuse common::FixtureEngine;')
    s=s.replace('TenantEngine','FixtureEngine')
    if 'use common::FixtureEngine;' not in s:
        # Accommodate the schema file's own import shape; detect duplicates in review.
        s=s.replace('use kasumi_engine::{', 'use common::FixtureEngine;\nuse kasumi_engine::{',1).replace(', FixtureEngine}', '}').replace('FixtureEngine, ', '')
    s,n=re.subn(r'(\b\w+)(\s*)\.apply_command\(',lambda m:m[1]+m[2]+'.apply_command(&'+m[1]+'.disk, ',s)
    s=re.sub(r'(\b\w+)(\s*)\.fixture_snapshot\(\)',lambda m:m[1]+m[2]+'.fixture_snapshot(&'+m[1]+'.disk)',s)
    # Disk origin in every corruption encoding is the corresponding pure
    # fixture scope, retained for the complete candidate/restore lifetime.
    if name=='contracts':
        s=s.replace('encode_snapshot_candidate(&corrupt,','encode_snapshot_candidate(&db.disk, &corrupt,')
    if name=='staged_transactions':
        s=s.replace('encode_snapshot_candidate(&corrupt,','encode_snapshot_candidate(&db.disk, &corrupt,')
    if name=='schema_activation':
        s=s.replace('encode_snapshot_candidate(&state,','encode_snapshot_candidate(&db.disk, &state,')
    if name=='snapshot_budget':
        for state in ['after','before']:s=s.replace('encode_snapshot_candidate(&'+state+',','encode_snapshot_candidate(&source.disk, &'+state+',')
        s=s.replace('encode_snapshot_candidate(&state,','encode_snapshot_candidate(&db.disk, &state,')
    p.write_text(s)
    print(name,'apply calls',n)
