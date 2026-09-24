from pathlib import Path
import re
out=Path('target/installed-disk-validation/engine-integration-callers/proposed/crates/kasumi-engine/tests')
# Add mandatory final argument to the unconverted filesystem backup fixture
# calls in the four root-owned files, preserving exact root/object byte bounds.
for name in ['history','guarded_staging','schema_activation']:
 p=out/(name+'.rs');s=p.read_text()
 # Enroll root before first destination opens. The destination's namespace is
 # already beneath this physical owner, so there is no extra metadata lease.
 if name=='history':
  for function,file in [('archived_prefixes_keep_logical_reads_unique_indexes_and_dedup_after_restart','node.redb'),('chunked_full_backup_restores_cold_history_and_permanent_identity_without_source_objects','source.redb')]:
   start=s.index('async fn '+function+'('); end=s.find('\n#[',start)
   if end<0:end=len(s)
   block=s[start:end]
   m=re.search(r'    let physical =\s*common::PhysicalFixture::new\(&root.path\(\).join\("'+re.escape(file)+r'"\), Default::default\(\)\);\n',block)
   assert m,(function,block[:200])
   declaration=m.group(0);block=block[:m.start()]+block[m.end():]
   marker='    let root = kasumi_store::test_utils::private_tempdir().unwrap();\n'
   block=block.replace(marker,marker+declaration,1)
   s=s[:start]+block+s[end:]
  # These are exact existing-file reopen phases, not fresh catalog creation.
  s,n=re.subn(r'(drop\(db\);\n    drop\(audit\);\n    let \(db, audit\) = open\(\n        &physical,\n        &root.path\(\).join\("node.redb"\),\n        Limits::default\(\),\n        )true',r'\1false',s)
  assert n==2,n
  s=s.replace('NodeStore::create_new_fixture(\n            root.path().join(format!("{suffix}.redb")),\n            kasumi_store::test_utils::NODE_STORE_ID,\n            kasumi_store::ScratchDisk::fixture(),\n        )','physical.storage.create_new(root.path().join(format!("{suffix}.redb")), kasumi_store::test_utils::NODE_STORE_ID)')
  s=s.replace('NodeStore, TenantStore','TenantStore')
 positions=[]
 needle='FilesystemBackupDestination::new_fixture('
 at=0
 while (a:=s.find(needle,at))>=0:
  start=a+len(needle);depth=1;i=start;quote=None;escape=False
  while depth:
   ch=s[i]
   if quote:
    if escape:escape=False
    elif ch=='\\':escape=True
    elif ch==quote:quote=None
   elif ch=='"':quote=ch
   elif ch=='(':depth+=1
   elif ch==')':depth-=1
   i+=1
  body=s[start:i-1].rstrip()
  positions.append((start,i-1,body+('' if body.endswith(',') else ',')+' physical.storage.admission.memory().clone(),'))
  at=i
 for a,b,r in reversed(positions):s=s[:a]+r+s[b:]
 p.write_text(s)
