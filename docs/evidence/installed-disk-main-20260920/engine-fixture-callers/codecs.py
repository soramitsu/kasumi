from pathlib import Path
import json,hashlib,re
D=Path('target/installed-disk-validation/engine-fixture-callers');P=D/'proposed/crates/kasumi-engine/src'
def enroll(name,new=None):
 rel='crates/kasumi-engine/src/'+name;b=Path(rel).read_bytes() if Path(rel).exists() else b'';(D/'before'/rel).write_bytes(b)
 (P/name).write_bytes(b if new is None else new.encode())
 inv=json.loads((D/'inventory.json').read_text());inv['files'].append(dict(path=rel,base=rel,before_sha256=hashlib.sha256(b).hexdigest(),new_file=not Path(rel).exists()));(D/'inventory.json').write_text(json.dumps(inv,indent=2)+'\n')
enroll('codec_fixture.rs','''//! Private codec-test scope. Callers select and retain their explicit bounded governor.
use std::sync::Arc;
pub(crate) struct ScratchScope {
    pub(crate) disk: Arc<kasumi_store::ScratchDisk>,
    _directory: tempfile::TempDir,
}
impl ScratchScope {
    pub(crate) fn new(memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission>) -> anyhow::Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let disk = kasumi_store::ScratchDisk::fixture(directory.path().join("scratch"), memory);
        Ok(Self { disk, _directory: directory })
    }
}
''')
enroll('lib.rs');p=P/'lib.rs';s=p.read_text();s+='\n#[cfg(test)]\nmod codec_fixture;\n';p.write_text(s)
setup='''let scratch = crate::codec_fixture::ScratchScope::new(kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32)).unwrap();
    let disk = &scratch.disk;'''
def edit(name,fn):p=P/name;p.write_text(fn(p.read_text()))
# Pure durable stores keep their same explicit provider and scratch until reopened views finish.
for name in ['mutation_receipt_tests.rs','staged_terminal_tests.rs','target_resolution_tests.rs']:
 def change(s):
  old='''    let node = NodeStore::create_new_fixture(
        directory.path().join("node.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        ScratchDisk::fixture(),
    )'''
  assert old in s
  s=s.replace(old,'''    let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32);
    kasumi_store::private_files::create_directory(&directory.path().join("persistent")).unwrap();
    let disk = ScratchDisk::fixture(directory.path().join("scratch"), memory.clone());
    let node = NodeStore::create_new_fixture(
        directory.path().join("persistent/node.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        memory,
        disk,
    )''')
  s=s.replace('directory.path().join("node.redb")','directory.path().join("persistent/node.redb")')
  s=s.replace('''        kasumi_store::test_utils::NODE_STORE_ID,
        disk,
    )''','''        kasumi_store::test_utils::NODE_STORE_ID,
        disk.memory().clone(),
        disk,
    )''')
  # Add a scope only to standalone tests that had their own unowned scratch.
  parts=re.split(r'(?=\#\[test\]\n)',s)
  for i,c in enumerate(parts):
   if 'ScratchDisk::fixture()' in c:
    c=c.replace('() {','() {\n    '+setup,1)
    c=c.replace('&ScratchDisk::fixture()', 'disk')
   parts[i]=c
  return ''.join(parts)
 edit(name,change)
# Explicit scope through helpers returning an image or proof.
for name in ['snapshot_validation.rs','snapshot_recovery_tests.rs']:
 def change(s):
  start=s.index('#[cfg(test)]') if name=='snapshot_validation.rs' else 0
  prefix,s=s[:start],s[start:]
  funcs=['image','indexed','proof','encoded','verify'] if name=='snapshot_validation.rs' else ['image']
  for fn in funcs:
   s=re.sub(r'(?<![\w.])'+fn+r'\(',fn+'(disk, ',s)
   s=s.replace('fn '+fn+'(disk, ','fn '+fn+'(disk: &Arc<kasumi_store::ScratchDisk>, ')
  s=re.sub(r'(#\[test\]\n\s*fn [^(]+\(\) \{)',lambda m:m[0]+'\n        '+setup,s)
  s=s.replace('&kasumi_store::ScratchDisk::fixture()', 'disk')
  s=s.replace('            let disk = kasumi_store::ScratchDisk::fixture();\n','')
  # Local disk is already a borrowed Arc in proof.
  s=s.replace('SnapshotImage::capture(&disk,','SnapshotImage::capture(disk,').replace('EncryptedTable::new(&disk,','EncryptedTable::new(disk,')
  return prefix+s
 edit(name,change)
edit('snapshot_literal_tests.rs',lambda s:s.replace('let disk = kasumi_store::ScratchDisk::fixture();',setup).replace('SnapshotImage::capture(&disk,','SnapshotImage::capture(disk,'))
edit('snapshot_codec.rs',lambda s:s.replace('''    fn read(reader: &mut dyn Read) -> anyhow::Result<TenantState> {
        Ok(super::read(&kasumi_store::ScratchDisk::fixture(), reader)?.state)''','''    fn read(reader: &mut dyn Read) -> anyhow::Result<TenantState> {
        '''+setup+'''
        Ok(super::read(disk, reader)?.state)'''))
def recovery(s):
 start=s.index('fn linked_completion_history_roundtrips');a=s[:start];s=s[start:]
 s=s.replace('() {','() {\n    '+setup,1)
 s=re.sub(r'(?<![\w.])image\(', 'image(disk, ',s).replace('fn image(disk, ','fn image(disk: &Arc<kasumi_store::ScratchDisk>, ')
 s=s.replace('&kasumi_store::ScratchDisk::fixture()', 'disk')
 return a+s
edit('recovery_receiver_tests.rs',recovery)
def staging(s):
 s=s.replace('fn permanent_staged_point_capacity_transfers_to_outcome_and_can_expand_without_identity_reuse() {','fn permanent_staged_point_capacity_transfers_to_outcome_and_can_expand_without_identity_reuse() {\n    '+setup)
 s=s.replace('persist_terminal_overlay(&','persist_terminal_overlay(disk, &')
 s=s.replace('fn persist_terminal_overlay(\n','fn persist_terminal_overlay(\n    disk: &Arc<kasumi_store::ScratchDisk>,\n')
 s=s.replace('.fixture_owner(previous)', '.fixture_owner(disk, previous)')
 return s
edit('staging_capacity_tests.rs',staging)
def state(s):
 start=s.index('mod restore_budget_tests');a=s[:start];s=s[start:]
 s=s.replace('fn restored_identity_metadata_is_validated_before_bootstrap_persistence() {','fn restored_identity_metadata_is_validated_before_bootstrap_persistence() {\n        '+setup)
 s=s.replace('.apply_command(\n', '.apply_command(\n                disk,\n')
 s=s.replace('encode_snapshot_candidate(&','encode_snapshot_candidate(disk, &')
 return a+s
edit('state.rs',state)
