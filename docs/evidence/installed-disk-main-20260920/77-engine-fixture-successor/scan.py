from pathlib import Path
import re,json
D=Path('target/installed-disk-validation/77-engine-fixture-successor');P=D/'proposed'
expected={'ScratchDisk::fixture':2,'ScratchDisk::open_fixture':2,'ScratchDisk::open':2,'NodeDisk::fixture_for_path':2,'NodeDisk::open_fixture':3,'NodeStore::create_new_fixture':4,'NodeStore::open_existing_fixture':4,'NodeStore::initialize_owned_empty_fixture':5,'NodeStore::claim_cleanup_fixture':3,'NodeStore::open_fixture_backend_on_disk':4,'FilesystemBackupDestination::new':3,'FilesystemBackupDestination::new_fixture':3,'FilesystemAuditArchive::open':2,'FilesystemAuditArchive::open_fixture':2}
rows=[]
def arity(s,start):
 stack=[')'];commas=0;has=False;i=start;quoted=False;escape=False
 while stack:
  c=s[i]
  if quoted:
   if escape:escape=False
   elif c=='\\':escape=True
   elif c=='"':quoted=False
  elif c=='"':quoted=True;has=True
  elif s[i:i+2]=='//':
   i=s.find('\n',i)
  elif c in '([{':stack.append({'(':')','[':']','{':'}'}[c]);has=True
  elif c in ')]}':
   assert stack.pop()==c
   if not stack:break
   has=True
  elif c==',' and len(stack)==1:commas+=1;has=False
  elif not c.isspace():has=True
  i+=1
 return commas+int(has)
for f in Path('crates/kasumi-engine/src').rglob('*.rs'):
 s=(P/f).read_text() if (P/f).exists() else f.read_text()
 for name,n in expected.items():
  for m in re.finditer(r'\b'+re.escape(name)+r'\s*\(',s):
   found=arity(s,m.end());rows.append(dict(path=str(f),line=s.count('\n',0,m.start())+1,call=name,expected=n,observed=found))
fail=[x for x in rows if x['expected']!=x['observed']]
(D/'constructor-arity-inventory.json').write_text(json.dumps(dict(status='SOURCE_OVERLAY_TEXT_SCAN_NOT_TYPECHECK',calls=rows,mismatches=fail),indent=2)+'\n')
print('calls',len(rows),'mismatches',fail)
