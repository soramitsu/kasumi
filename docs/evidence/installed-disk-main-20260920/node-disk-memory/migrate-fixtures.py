from pathlib import Path
import re,shutil,json
ROOT=Path.cwd();OUT=ROOT/'target/installed-disk-validation/node-disk-memory'
def mask(s):
 out=list(s);i=0;n=len(s)
 while i<n:
  start=i
  if s.startswith('//',i):
   i=s.find('\n',i)
   if i<0:i=n
  elif s.startswith('/*',i):
   depth=1;i+=2
   while i<n and depth:
    if s.startswith('/*',i):depth+=1;i+=2
    elif s.startswith('*/',i):depth-=1;i+=2
    else:i+=1
  elif (r:=re.match(r'(?:br|r)(#+)?"',s[i:])):
   end='"'+(r.group(1) or '');i=s.find(end,i+r.end());i=n if i<0 else i+len(end)
  elif s[i]=='"':
   i+=1
   while i<n:
    if s[i]=='\\':i+=2
    elif s[i]=='"':i+=1;break
    else:i+=1
  elif s[i]=="'" and (r:=re.match(r"'(?:\\.|[^'\n])'",s[i:])):i+=r.end()
  else:i+=1;continue
  for k in range(start,i):
   if out[k]!='\n':out[k]=' '
 return ''.join(out)
def close(m,start):
 pairs={'(':')','[':']','{':'}'};want=[pairs[m[start]]]
 for i in range(start+1,len(m)):
  if m[i] in pairs:want.append(pairs[m[i]])
  elif m[i] in ')]}':
   assert m[i]==want[-1],(m[i],want[-1],start,i)
   want.pop()
   if not want:return i
 raise ValueError(start)
def args(m,start,end):
 points=[];i=start+1;begin=i
 while i<end:
  if m[i] in '([{':i=close(m,i)+1
  elif m[i]==',':
   if m[begin:i].strip():points.append((begin,i))
   begin=i+1;i+=1
  else:i+=1
 if m[begin:end].strip():points.append((begin,end))
 return points
callrx=re.compile(r'\b(ScratchDisk::(?:fixture|isolated_fixture)|NodeStore::(?:create_new_fixture|open_existing_fixture|initialize_owned_empty_fixture|claim_cleanup_fixture)|FilesystemAuditArchive::open_fixture|FilesystemBackupDestination::new_fixture)\s*\(')
report=[]
for src in sorted((ROOT/'crates/kasumi-store').rglob('*.rs')):
 path=src.relative_to(ROOT)
 if str(path) in ['crates/kasumi-store/src/test_utils.rs','crates/kasumi-store/src/node_disk/tests.rs','crates/kasumi-store/src/scratch_disk.rs']:continue
 s=src.read_text();m=mask(s);calls=list(callrx.finditer(m))
 if not calls:continue
 funcs=[]
 for f in re.finditer(r'\bfn\s+(\w+)\s*(?:<[^{}]*?>\s*)?\(',m):
  par=m.index('(',f.start());endpar=close(m,par);body=m.find('{',endpar)
  semicolon=m.find(';',endpar)
  if body<0 or 0<=semicolon<body:continue
  funcs.append((f.start(),body,close(m,body),f.group(1)))
 edits=[];owners={}
 for c in calls:
  f=max((f for f in funcs if f[1]<c.start()<f[2]),key=lambda f:f[1]);owners[f[1]]=f
  a=c.end()-1;b=close(m,a);aa=args(m,a,b);name=c.group(1)
  if name.startswith('NodeStore::') and not name.endswith('claim_cleanup_fixture'):
   pos=aa[-1][0]
   while s[pos].isspace():pos+=1
   edits.append((pos,'fixture_memory.clone(), '))
  else:
   pos=b
   while s[pos-1].isspace():pos-=1
   separator='' if not aa else ' ' if s[pos-1]==',' else ', '
   edits.append((pos,separator+'fixture_memory.clone()'+(',' if aa and s[pos-1]==',' else '')))
 prefix='kasumi_store' if '/tests/' in str(path) and not '/src/' in str(path) else 'crate'
 for body,f in owners.items():
  indent=re.match(r'\s*',s[s.rfind('\n',0,f[0])+1:]).group().replace('\n','')+'    '
  edits.append((body+1,f'\n{indent}let fixture_memory = {prefix}::test_utils::TestDiskMemory::new(256 << 20, 4096);'))
 for pos,text in sorted(edits,reverse=True):s=s[:pos]+text+s[pos:]
 dst=OUT/'proposed'/path;base=OUT/'base'/path;dst.parent.mkdir(parents=True,exist_ok=True);base.parent.mkdir(parents=True,exist_ok=True)
 assert not dst.exists(),path
 shutil.copy2(src,base);dst.write_text(s)
 report.append({'path':str(path),'functions':[f[3] for f in owners.values()],'calls':len(calls)})
(OUT/'fixture-migration-inventory.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'files':len(report),'calls':sum(r['calls'] for r in report)}))
