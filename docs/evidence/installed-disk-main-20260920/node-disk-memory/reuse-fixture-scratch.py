from pathlib import Path
import re
root=Path(__file__).parent/'proposed/crates/kasumi-store'
helper_files={
 'src/tests.rs':('fixture',),
 'src/backup_sessions.rs':('fixture',),
 'src/audit_archive.rs':('store',),
 'src/single_catalog/tests.rs':('node',),
 'src/storage_domains/catalog_initialization/tests.rs':('node',),
}
def end_paren(s,start):
 n=0
 for i in range(start,len(s)):
  if s[i]=='(':n+=1
  elif s[i]==')':
   n-=1
   if not n:return i
 raise ValueError(start)
for p in root.rglob('*.rs'):
 rel=str(p.relative_to(root));s=p.read_text()
 if rel in ('src/scratch_disk.rs','src/disk_memory.rs','src/test_utils.rs'):continue
 if not re.search(r'(?:crate::|kasumi_store::)?ScratchDisk::fixture\(fixture_memory\.clone\(\)\)',s):continue
 # Private test helper must receive the actual installed scratch owner, not
 # construct a new hidden directory at every simulated backend reopen.
 for helper in helper_files.get(rel,()):
  m=re.search(r'\bfn '+helper+r'\(',s); assert m,(rel,helper)
  e=end_paren(s,m.end()-1)
  args=s[m.end():e];assert 'fixture_memory:' in args
  args=args.rstrip()+ '\n    fixture_scratch: std::sync::Arc<crate::ScratchDisk>,\n'
  s=s[:m.end()]+args+s[e:]
  edits=[]
  for c in re.finditer(r'(?<![:\w])'+helper+r'\(',s):
   if re.search(r'fn\s*$',s[max(0,c.start()-4):c.start()]):continue
   e=end_paren(s,c.end()-1);edits.append(e)
  for e in reversed(edits):s=s[:e]+', fixture_scratch.clone()'+s[e:]
 s=re.sub(r'(?:crate::|kasumi_store::)?ScratchDisk::fixture\(fixture_memory\.clone\(\)\)', 'fixture_scratch.clone()',s)
 # Existing local governors own all default scratch directories in this test.
 # Insert only for blocks that actually need a local owner (helper parameters
 # above satisfy their own bodies).
 matches=list(re.finditer(r'(?m)^(\s*)let fixture_memory\s*=\s*[^;]+;',s))
 for i,m in reversed(list(enumerate(matches))):
  end=matches[i+1].start() if i+1<len(matches) else len(s)
  body=s[m.end():end]
  if 'fixture_scratch.clone()' not in body:continue
  indent=m[1].split('\n')[-1]
  prefix='kasumi_store::' if rel.startswith('tests/') else 'crate::'
  s=s[:m.end()]+'\n'+indent+'let fixture_scratch = '+prefix+'ScratchDisk::fixture(fixture_memory.clone());'+s[m.end():]
 p.write_text(s)
