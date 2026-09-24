from pathlib import Path
import re,json
root=Path(__file__).parent/'proposed'
expected={
 'ScratchDisk::fixture':2,'ScratchDisk::isolated_fixture':3,
 'ScratchDisk::open':2,'ScratchDisk::open_fixture':2,
 'NodeDisk::open':3,'NodeDisk::open_fixture':3,'NodeDisk::fixture_for_path':2,
 'NodeStore::create_new_fixture':4,'NodeStore::open_existing_fixture':4,
 'NodeStore::initialize_owned_empty_fixture':5,'NodeStore::claim_cleanup_fixture':3,
 'FilesystemAuditArchive::open_fixture':2,'FilesystemBackupDestination::new_fixture':3,
}
def arguments(s,start):
 stack=['('];quote=False;esc=False;commas=0;begin=start+1
 for i in range(begin,len(s)):
  c=s[i]
  if quote:
   if esc:esc=False
   elif c=='\\':esc=True
   elif c=='"':quote=False
   continue
  if c=='"':quote=True;continue
  if c in '([{':stack.append(c)
  elif c in ')]}':
   stack.pop()
   if not stack:
    raw=s[begin:i].strip()
    return 0 if not raw else commas+(not raw.endswith(','))
  elif c==',' and len(stack)==1:commas+=1
 raise ValueError(start)
rows=[];bad=[]
for p in root.rglob('*.rs'):
 s=p.read_text()
 for name,n in expected.items():
  for m in re.finditer(re.escape(name)+r'\(',s):
   actual=arguments(s,m.end()-1);row={'path':str(p.relative_to(root)),'line':s[:m.start()].count('\n')+1,'constructor':name,'arity':actual}
   rows.append(row)
   if actual!=n:bad.append(row)
r={'revision':2,'calls':len(rows),'failures':bad};(root.parent/'revision2-arity-audit.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2));assert not bad
