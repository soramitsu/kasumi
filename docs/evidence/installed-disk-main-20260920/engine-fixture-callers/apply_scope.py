from pathlib import Path
import json,hashlib,re
D=Path('target/installed-disk-validation/engine-fixture-callers'); P=D/'proposed/crates/kasumi-engine/src'
for name in ['lease_retention_tests.rs']:
 rel='crates/kasumi-engine/src/'+name;b=Path(rel).read_bytes(); (P/name).write_bytes(b);(D/'before'/rel).write_bytes(b)
 inv=json.loads((D/'inventory.json').read_text());inv['files'].append(dict(path=rel,base=rel,before_sha256=hashlib.sha256(b).hexdigest()));(D/'inventory.json').write_text(json.dumps(inv,indent=2)+'\n')
for name in ['mutation_receipt.rs','staged_terminal.rs']:
 p=P/name;s=p.read_text().replace('fn fixture_owner(&self, state: &TenantState)', 'fn fixture_owner(&self, disk: &Arc<ScratchDisk>, state: &TenantState)').replace('&ScratchDisk::fixture(),','disk,');p.write_text(s)
p=P/'state.rs';s=p.read_text()
s=s.replace('impl kasumi_raft::StateMachineBackend for TenantEngine {','''enum ApplyScope {
    Committed,
    #[cfg(any(test, feature = "test-utils"))]
    Fixture(Arc<kasumi_store::ScratchDisk>),
}

impl kasumi_raft::StateMachineBackend for TenantEngine {''',1)
s=s.replace('self.apply_command_ordered(revision, command, applied)?','self.apply_command_ordered(revision, command, applied, ApplyScope::Committed)?')
s=s.replace('pub fn apply_command(&self, revision: u64, command: Command)', 'pub fn apply_command(&self, disk: &Arc<kasumi_store::ScratchDisk>, revision: u64, command: Command)')
s=s.replace('self.apply_command_ordered(revision, command, applied)\n','self.apply_command_ordered(revision, command, applied, ApplyScope::Fixture(disk.clone()))\n')
s=s.replace('''        applied: crate::staged_terminal::AppliedIdentity,
    ) -> Result<Result<WriteReceipt>>''','''        applied: crate::staged_terminal::AppliedIdentity,
        scope: ApplyScope,
    ) -> Result<Result<WriteReceipt>>''')
s=s.replace('self.apply_mutation_ordered(&previous, &command, batch, &applied)','self.apply_mutation_ordered(&previous, &command, batch, &applied, &scope)')
start=s.index('        let terminal_owner = previous.terminals.clone();',s.index('fn apply_command_ordered'))
end=s.index('        let mut next =',start)
s=s[:start]+'''        let terminal_owner = match &scope {
            ApplyScope::Committed => previous.terminals.clone(),
            #[cfg(any(test, feature = "test-utils"))]
            ApplyScope::Fixture(disk) => previous.terminals.fixture_owner(disk, &previous.state).map_err(terminal_error)?,
        };
'''+s[end:]
p.write_text(s)
p=P/'mutation_apply.rs';s=p.read_text().replace('''        applied: &crate::staged_terminal::AppliedIdentity,
    ) -> Result<Result<WriteReceipt>>''','''        applied: &crate::staged_terminal::AppliedIdentity,
        scope: &ApplyScope,
    ) -> Result<Result<WriteReceipt>>''')
start=s.index('        let owner = previous.receipts.clone();');end=s.index('        let mut baseline =',start)
s=s[:start]+'''        let owner = match scope {
            ApplyScope::Committed => previous.receipts.clone(),
            #[cfg(any(test, feature = "test-utils"))]
            ApplyScope::Fixture(disk) => previous.receipts.fixture_owner(disk, state).map_err(terminal_error)?,
        };
'''+s[end:];p.write_text(s)
# Real CredentialFixture retains exact store disk; restored in-memory replica uses same explicit disk.
p=P/'service_credential_tests.rs';s=p.read_text().replace('.apply_command(1,', '.apply_command(fixture.db.store.scratch_disk(), 1,').replace('replica.apply_command(2,', 'replica.apply_command(fixture.db.store.scratch_disk(), 2,');p.write_text(s)
# Pure in-memory reducer fixtures own a bounded scratch context through their actual retained histories.
wrapper='''struct CodecFixture {
    engine: TenantEngine,
    disk: Arc<kasumi_store::ScratchDisk>,
    _directory: tempfile::TempDir,
}
impl std::ops::Deref for CodecFixture {
    type Target = TenantEngine;
    fn deref(&self) -> &Self::Target { &self.engine }
}
'''
for name,signature,endmark in [('mutation_apply_tests.rs','fn engine(max_snapshot_bytes: u64) -> TenantEngine {','fn batch('),('lease_retention_tests.rs','fn fixture(count: usize, body_bytes: usize, budget: usize) -> TenantEngine {','fn install(')]:
 p=P/name;s=p.read_text();s=s.replace(signature,wrapper+signature.replace('-> TenantEngine','-> CodecFixture')+'''
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32).unwrap();
    let disk = kasumi_store::ScratchDisk::fixture(directory.path().join("scratch"), memory);
''')
 first=s.index('    engine\n}',s.index('struct CodecFixture'));s=s[:first]+'''    CodecFixture { engine, disk, _directory: directory }
}'''+s[first+len('    engine\n}'):]
 if name=='mutation_apply_tests.rs':
  s=s.replace('.apply_command(\n            1,','.apply_command(\n            &disk,\n            1,')
  s=s.replace('fn apply(engine: &TenantEngine,', 'fn apply(engine: &CodecFixture,')
  s=s.replace('.apply_command(revision,', '.apply_command(&engine.disk, revision,')
  s=s.replace('.fixture_snapshot()', '.fixture_snapshot(&engine.disk)')
  s=s.replace('let disk = kasumi_store::ScratchDisk::fixture();', 'let disk = source.disk.clone();')
 else:
  s=s.replace('fn write(engine: &TenantEngine,', 'fn write(engine: &CodecFixture,')
  s=s.replace('.apply_command(\n            revision,','.apply_command(\n            &engine.disk,\n            revision,')
 p.write_text(s)
