from pathlib import Path
import shutil,re
root=Path('/Users/mtakemiya/dev/kasumi'); out=root/'target/installed-disk-validation/engine-integration-store-agent'; base=out/'before'; prop=out/'proposed'; incoming=root/'target/installed-disk-validation/engine-integration-callers/proposed'
files=['backup_checkpoint','embedded_audit','retirement','lifecycle','replicated']; relbase=Path('crates/kasumi-engine/tests')
for f in files:
 rel=relbase/(f+'.rs')
 for tree in [base,prop]:
  p=tree/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(incoming/rel,p)
def edit(f,old,new,n=None):
 p=prop/relbase/(f+'.rs');s=p.read_text();c=s.count(old);assert c and(n is None or c>=n),(f,c,old[:90]);p.write_text(s.replace(old,new) if n is None else s.replace(old,new,n))
def transform_calls(f,fn,callback):
 p=prop/relbase/(f+'.rs');s=p.read_text();matches=list(re.finditer(re.escape(fn)+r'\(',s))
 for m in reversed(matches):
  start=m.end();i=start;level=0;quote=False;escape=False;args=[];last=start
  while i<len(s):
   c=s[i]
   if quote:
    if escape:escape=False
    elif c=='\\':escape=True
    elif c=='"':quote=False
   elif c=='"':quote=True
   elif c in '([{':level+=1
   elif c in ')]}':
    if level==0:break
    level-=1
   elif c==',' and level==0:args.append(s[last:i].strip());last=i+1
   i+=1
  if s[last:i].strip():args.append(s[last:i].strip())
  replacement=callback(args,m.start(),s)
  s=s[:m.start()]+replacement+s[i+1:]
 p.write_text(s)
def node_calls(f,owner):
 for op in ['create_new','open_existing']:
  transform_calls(f,'NodeStore::'+op+'_fixture',lambda a,pos,s: owner(a,pos,s)+'.storage.'+op+'('+', '.join(a[:2])+')')
# Retirement one real installed owner survives every destructuring/reopen.
f='retirement'
edit(f,'    directory: tempfile::TempDir,','    directory: tempfile::TempDir,\n    physical: common::PhysicalFixture,',1)
edit(f,'        let directory = kasumi_store::test_utils::private_tempdir().unwrap();','        let directory = kasumi_store::test_utils::private_tempdir().unwrap();\n        let physical = common::PhysicalFixture::new(&directory.path().join("node.redb"), Default::default());',1)
edit(f,'            directory,','            directory,\n            physical,',1)
edit(f,'        directory,\n        db,','        directory,\n        physical,\n        db,',3)
node_calls(f,lambda a,pos,s:'physical')
edit(f,'common::security_audit(node.clone())','common::security_audit(node.clone(), physical.storage.admission.clone())',1)
edit(f,'common::existing_security_audit(node.clone())','common::existing_security_audit(node.clone(), physical.storage.admission.clone())',2)
transform_calls(f,'FilesystemBackupDestination::new_fixture',lambda a,pos,s:'FilesystemBackupDestination::new('+', '.join(a)+', physical.storage.persistent.clone())')
# Embedded service fixture explicitly receives its physical admission.
f='embedded_audit'
edit(f,'    audit_provider: Arc<LocalKeyProvider>,','    audit_provider: Arc<LocalKeyProvider>,\n    admission: Arc<kasumi_engine::admission::NodeAdmission>,',1)
edit(f,'kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),','admission,',1)
edit(f,'    let path = dir.path().join("node.redb");','    let path = dir.path().join("node.redb");\n    let physical = common::PhysicalFixture::new(&path, Default::default());',2)
edit(f,'fixture(node.clone(), provider, service_provider.clone())','fixture(node.clone(), provider, service_provider.clone(), physical.storage.admission.clone())',1)
edit(f,'            service_provider.clone(),','            service_provider.clone(),\n            physical.storage.admission.clone(),',1)
# Source and target originally used independent admissions; keep them in sibling roots.
edit(f,'    let source_node = NodeStore::create_new_fixture(','    let source_root = dir.path().join("source");\n    kasumi_store::private_files::create_directory(&source_root).unwrap();\n    let source_physical = common::PhysicalFixture::new(&source_root.join("source.redb"), Default::default());\n    let source_node = NodeStore::create_new_fixture(',1)
edit(f,'dir.path().join("source.redb")','source_root.join("source.redb")',1)
edit(f,'        Arc::new(LocalKeyProvider::new([52; 32])),','        Arc::new(LocalKeyProvider::new([52; 32])),\n        source_physical.storage.admission.clone(),',1)
edit(f,'    let target_path = dir.path().join("target.redb");','    let target_root = dir.path().join("target");\n    kasumi_store::private_files::create_directory(&target_root).unwrap();\n    let target_path = target_root.join("target.redb");\n    let target_physical = common::PhysicalFixture::new(&target_path, Default::default());',1)
edit(f,'kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),','target_physical.storage.admission.clone(),',1)
node_calls(f,lambda a,pos,s:'source_physical' if 'source_root' in a[0] else ('target_physical' if 'target_path' in a[0] else 'physical'))
def embeddedbackup(a,pos,s):
 if 'standalone_restore_denials' in s[:pos]:return 'FilesystemBackupDestination::new(source_root.join("backups"), '+a[1]+', source_physical.storage.persistent.clone())'
 return 'FilesystemBackupDestination::new('+', '.join(a)+', physical.storage.persistent.clone())'
transform_calls(f,'FilesystemBackupDestination::new_fixture',embeddedbackup)
# Lifecycle replicas have different physical roots and retained admissions.
f='lifecycle'
edit(f,'    router: Arc<InProcessRouter>,','    physical: BTreeMap<u64, common::PhysicalFixture>,\n    router: Arc<InProcessRouter>,',1)
edit(f,'        let mut result = Self {','''        let physical = (1..=3).map(|id| {
            let directory = root.path().join(id.to_string());
            kasumi_store::private_files::create_directory(&directory).unwrap();
            (id, common::PhysicalFixture::new(&directory.join("node.redb"), Default::default()))
        }).collect();
        let mut result = Self {''',1)
edit(f,'            root,\n            router:','            root,\n            physical,\n            router:',1)
edit(f,'self.root.path().join(format!("{id}.redb"))','self.root.path().join(id.to_string()).join("node.redb")',2)
node_calls(f,lambda a,pos,s:'self.physical[&id]')
for fn in ['security_audit','existing_security_audit']:
 edit(f,'common::'+fn+'(node.clone())','common::'+fn+'(node.clone(), self.physical[&id].storage.admission.clone())',1)
edit(f,'.fixture_snapshot()','.fixture_snapshot(db.raft_group().storage_domains().application().scratch_disk())')
edit(f,'encode_snapshot_candidate(&state, 64 << 20)','encode_snapshot_candidate(db.raft_group().storage_domains().application().scratch_disk(), &state, 64 << 20)',1)
# Replicated integration helpers never infer a governor from a file path.
f='replicated'
edit(f,'async fn store(\n    path: &std::path::Path,','async fn store(\n    physical: &common::PhysicalFixture,\n    path: &std::path::Path,',1)
node_calls(f,lambda a,pos,s:'physical')
for fn in ['security_audit','existing_security_audit']:
 edit(f,'common::'+fn+'(node.clone())','common::'+fn+'(node.clone(), physical.storage.admission.clone())',1)
# One explicit helper creates directories only, before the mandatory admission/disk opening.
edit(f,'async fn store(','''fn replica_fixture(root: &std::path::Path, name: &str) -> common::PhysicalFixture {
    let directory = root.join(name);
    kasumi_store::private_files::create_directory(&directory).unwrap();
    common::PhysicalFixture::new(&directory.join("node.redb"), Default::default())
}
async fn store(''',1)
edit(f,'    let root = kasumi_store::test_utils::private_tempdir().unwrap();','    let root = kasumi_store::test_utils::private_tempdir().unwrap();\n    let physical: BTreeMap<_, _> = (1..=3).map(|id| (id, replica_fixture(root.path(), &id.to_string()))).collect();',1)
for create in ['true','false']:
 edit(f,f'store(&root.path().join(format!("{{id}}.redb")), {create})',f'store(&physical[&id], &root.path().join(id.to_string()).join("node.redb"), {create})',1)
edit(f,'    let (store, audit) = store(&root.path().join("local.redb"), true).await;','    let physical = replica_fixture(root.path(), "local");\n    let (store, audit) = store(&physical, &root.path().join("local/node.redb"), true).await;',1)
edit(f,'    let (source_store, source_audit) = store(&root.path().join("source.redb"), true).await;','''    let source_physical = replica_fixture(root.path(), "source");
    let physical: BTreeMap<_, _> = (1..=3).map(|id| (id, replica_fixture(root.path(), &format!("restored-{id}")))).collect();
    let (source_store, source_audit) = store(&source_physical, &root.path().join("source/node.redb"), true).await;''',1)
for create in ['true','false']:
 edit(f,f'store(&root.path().join(format!("restored-{{id}}.redb")), {create})',f'store(&physical[&id], &root.path().join(format!("restored-{{id}}/node.redb")), {create})',1)
edit(f,'root.path().join("backups")','root.path().join("source/backups")',1)
edit(f,'root.path().join("cold")','root.path().join("source/cold")',1)
transform_calls(f,'kasumi_store::FilesystemBackupDestination::new_fixture',lambda a,pos,s:'kasumi_store::FilesystemBackupDestination::new('+', '.join(a)+', source_physical.storage.persistent.clone())')
# Exact workspace regressions keep the old payload cap and subtract real disk
# metadata from payload assertions, not from production counters.
f='backup_checkpoint'
edit(f,'    directory: tempfile::TempDir,','    directory: tempfile::TempDir,\n    physical: common::PhysicalFixture,\n    disk_metadata_bytes: u64,',1)
edit(f,'    fn production_payload_baseline(&self) -> u64 {','''    fn reserved_payload(&self) -> u64 {
        reserved_payload_bytes(self.audit.admission()).checked_sub(self.disk_metadata_bytes)
            .expect("actual installed disk metadata remains charged")
    }
    fn production_payload_baseline(&self) -> u64 {''',1)
edit(f,'let bytes = reserved_payload_bytes(self.audit.admission());','let bytes = self.reserved_payload();',1)
edit(f,'reserved_payload_bytes(fixture.audit.admission())','fixture.reserved_payload()')
edit(f,'reserved_payload_bytes(&admission)','fixture.reserved_payload()')
edit(f,'        let directory = kasumi_store::test_utils::private_tempdir().unwrap();','''        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let config = kasumi_engine::test_utils::admission_config_with_bookkeeping(config).unwrap();
        let physical = common::PhysicalFixture::new(&directory.path().join("node.redb"), config);
        let admission = physical.storage.admission.clone();
        let disk_metadata_bytes = reserved_payload_bytes(&admission);''',1)
edit(f,'''        let admission = kasumi_engine::admission::NodeAdmission::new(
            kasumi_engine::test_utils::admission_config_with_bookkeeping(config).unwrap(),
        )
        .unwrap();
''','',1)
edit(f,'common::security_audit_with_admission','common::security_audit')
edit(f,'            directory,\n            db,','            directory,\n            physical,\n            disk_metadata_bytes,\n            db,',1)
edit(f,'        directory,\n        db,','        directory,\n        physical,\n        db,',1)
# New independent restore targets retain their exact governors across restart.
edit(f,'    let target_directory = kasumi_store::test_utils::private_tempdir().unwrap();','    let target_directory = kasumi_store::test_utils::private_tempdir().unwrap();\n    let target_physical = common::PhysicalFixture::new(&target_directory.path().join("target.redb"), Default::default());',1)
edit(f,'    let wrong_directory = kasumi_store::test_utils::private_tempdir().unwrap();','    let wrong_directory = kasumi_store::test_utils::private_tempdir().unwrap();\n    let wrong_physical = common::PhysicalFixture::new(&wrong_directory.path().join("wrong.redb"), Default::default());',1)
def backup_owner(a,pos,s):
 path=a[0]
 if 'fixture.directory' in path:return 'fixture.physical'
 if 'target_directory' in path:return 'target_physical'
 if 'wrong_directory' in path:return 'wrong_physical'
 return 'physical'
node_calls(f,backup_owner)
edit(f,'common::existing_security_audit(node.clone())','common::existing_security_audit(node.clone(), physical.storage.admission.clone())',1)
edit(f,'common::security_audit(node.clone()).await','common::security_audit(node.clone(), target_physical.storage.admission.clone()).await',1)
edit(f,'common::security_audit(wrong_node.clone()).await','common::security_audit(wrong_node.clone(), wrong_physical.storage.admission.clone()).await',1)
edit(f,'common::existing_security_audit(node.clone())','common::existing_security_audit(node.clone(), target_physical.storage.admission.clone())',1)
transform_calls(f,'FilesystemBackupDestination::new_fixture',lambda a,pos,s:'FilesystemBackupDestination::new('+', '.join(a)+', physical.storage.persistent.clone())')
transform_calls(f,'NodeStore::open_with_backend',lambda a,pos,s:'NodeStore::open_fixture_backend_on_disk('+', '.join(a[:2])+', fixture.physical.storage.persistent.clone(), '+a[2]+')')
edit(f,'.fixture_snapshot()','.fixture_snapshot(fixture.store.scratch_disk())')
edit(f,'kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),','target_physical.storage.admission.clone(),',2)
# External cache deletion is performed only after actual node shutdown, then a
# fresh census of that same stopped physical owner precedes cold recovery.
edit(f,'    let target = TenantStore::initialize_catalog_fixture(\n        node,\n        "checkpoint".into(),','    let target = TenantStore::initialize_catalog_fixture(\n        node,\n        "checkpoint".into(),',1) # owner cloning below restricted to target physical block
p=prop/relbase/(f+'.rs');s=p.read_text();mark=s.index('let target_physical =');start=s.index('    let target = TenantStore::initialize_catalog_fixture(\n        node,',mark);s=s[:start]+s[start:].replace('    let target = TenantStore::initialize_catalog_fixture(\n        node,','    let target = TenantStore::initialize_catalog_fixture(\n        node.clone(),',1);s=s.replace('    drop(target_audit);\n    let cache_path =','    drop(target_audit);\n    node.shutdown().await.unwrap();\n    drop(node);\n    assert_eq!(target_physical.storage.persistent.snapshot().open_files, 0);\n    let cache_path =',1);s=s.replace('    std::fs::remove_file(&cache_path).unwrap();','''    std::fs::remove_file(&cache_path).unwrap();
    target_physical.storage.persistent.pause().unwrap();
    target_physical.storage.persistent.reconcile(&kasumi_store::CensusCancellation::default()).unwrap();''',1);p.write_text(s)
print('five integrations prepared')
