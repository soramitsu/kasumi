from pathlib import Path
import re
root=Path(__file__).parent/'proposed/crates/kasumi-raft'
for p in root.rglob('*.rs'):
 s=p.read_text();rel=str(p.relative_to(root))
 # This was a draft-only unused declaration introduced by a broad initial scan.
 s=s.replace('async fn install(machine: &mut StateMachine, image: &SnapshotEnvelope) -> Result<()> {\n    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);','async fn install(machine: &mut StateMachine, image: &SnapshotEnvelope) -> Result<()> {')
 s=s.replace('disk_memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission>', 'fixture_scratch: Arc<kasumi_store::ScratchDisk>')
 s=s.replace('kasumi_store::ScratchDisk::fixture(disk_memory.clone())','fixture_scratch.clone()')
 s=s.replace('kasumi_store::ScratchDisk::fixture(codec_memory.clone())','codec_scratch.clone()')
 s=s.replace('let codec_memory = disk_memory.clone();','let codec_scratch = fixture_scratch.clone();')
 s=s.replace('disk_memory.clone()', 'fixture_scratch.clone()')
 # Explicit physical-file metadata admission uses this very scratch owner's core.
 s=re.sub(r'(NODE_STORE_ID,\s*)fixture_scratch.clone\(\),(\s*)fixture_scratch.clone\(\)',r'\1fixture_scratch.memory().clone(),\2fixture_scratch.clone()',s)
 # Trusted tests own their private directory outside the process-static disk.
 s=re.sub(r'(?m)^(\s*)let disk_memory = kasumi_store::test_utils::TestDiskMemory::new\(256 << 20, 4096\);',lambda m:m[0]+'\n'+m[1].split('\n')[-1]+'let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();\n'+m[1].split('\n')[-1]+'let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);',s)
 if rel=='tests/cluster.rs':
  s=s.replace('    nodes: BTreeMap<u64, Node>,\n}', '    nodes: BTreeMap<u64, Node>,\n    _scratch_directory: TempDir,\n}')
  s=s.replace('    async fn new() -> Result<Self> {\n        let mut cluster = Self {\n            disk_memory: kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096),','''    async fn new() -> Result<Self> {
        let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_directory = kasumi_store::test_utils::private_tempdir()?;
        let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
        let mut cluster = Self {
            fixture_scratch,
            _scratch_directory: scratch_directory,''')
 if rel=='tests/read_barrier.rs':
  s=s.replace('    stores: Vec<Arc<TenantStorageSet>>,\n}', '    stores: Vec<Arc<TenantStorageSet>>,\n    _scratch_directory: tempfile::TempDir,\n}')
  s=s.replace('''        Ok(Self {
''','''        Ok(Self {
            _scratch_directory: scratch_directory,
''')
 if rel=='tests/storage_conformance.rs':
  s=s.replace('struct Builder;','''struct Builder;
struct StoreScope {
    _directory: TempDir,
    _scratch_directory: TempDir,
}''')
  s=s.replace('StoreBuilder<TypeConfig, LogStore, StateMachine, TempDir>', 'StoreBuilder<TypeConfig, LogStore, StateMachine, StoreScope>')
  s=s.replace('Result<(TempDir, LogStore, StateMachine), StorageError<u64>>','Result<(StoreScope, LogStore, StateMachine), StorageError<u64>>')
  s=s.replace('anyhow::Ok((dir, log, machine))','anyhow::Ok((StoreScope { _directory: dir, _scratch_directory: scratch_directory }, log, machine))')
 p.write_text(s)
