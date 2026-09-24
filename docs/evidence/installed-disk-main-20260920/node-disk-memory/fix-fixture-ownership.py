from pathlib import Path
import re
exec(Path('target/installed-disk-validation/node-disk-memory/migrate-fixtures.py').read_text().split('callrx=')[0])
def append_calls(s,name):
 m=mask(s);edits=[];bodies=set()
 funcs=[]
 for f in re.finditer(r'\bfn\s+(\w+)\s*\(',m):
  par=m.index('(',f.start());endpar=close(m,par);body=m.find('{',endpar);semi=m.find(';',endpar)
  if body<0 or 0<=semi<body:continue
  funcs.append((body,close(m,body)))
 for c in re.finditer(r'(?<![\w.:])'+re.escape(name)+r'\s*\(',m):
  if m[max(0,c.start()-3):c.start()]=='fn ':continue
  start=c.end()-1;end=close(m,start);aa=args(m,start,end)
  body,endbody=max((f for f in funcs if f[0]<start<f[1]),key=lambda f:f[0])
  bodies.add((body,endbody));edits.append((end,(', ' if aa else '')+'fixture_memory.clone()'))
 for body,endbody in bodies:
  if not re.search(r'let\s+fixture_memory\s*=',s[body:endbody]):edits.append((body+1,'\n    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);'))
 for pos,text in sorted(edits,reverse=True):s=s[:pos]+text+s[pos:]
 return s
p=OUT/'proposed/crates/kasumi-store/src/node_file/tests.rs';s=p.read_text()
s=s.replace('fn create_node(path: &Path, id: Uuid)', 'fn create_node(path: &Path, id: Uuid, fixture_memory: Arc<dyn crate::NodeDiskMemoryAdmission>)').replace('fn open_node(path: &Path, id: Uuid)', 'fn open_node(path: &Path, id: Uuid, fixture_memory: Arc<dyn crate::NodeDiskMemoryAdmission>)').replace('NodeDisk::fixture_for_path(path)', 'NodeDisk::fixture_for_path(path, fixture_memory)')
s=append_calls(s,'create_node');s=append_calls(s,'open_node');p.write_text(s)
for path,name,needle,replacement in [
 ('src/tests.rs','fixture','async fn fixture()','async fn fixture(fixture_memory: Arc<dyn crate::NodeDiskMemoryAdmission>)'),
 ('src/backup_sessions.rs','fixture','async fn fixture()','async fn fixture(fixture_memory: Arc<dyn crate::NodeDiskMemoryAdmission>)'),
 ('src/single_catalog/tests.rs','node','fn node()','fn node(fixture_memory: Arc<dyn crate::NodeDiskMemoryAdmission>)'),
 ('src/storage_domains/catalog_initialization/tests.rs','node','fn node()','fn node(fixture_memory: Arc<dyn crate::NodeDiskMemoryAdmission>)'),
 ('src/audit_archive.rs','store','async fn store(directory: &Path, create: bool)','async fn store(directory: &Path, create: bool, fixture_memory: Arc<dyn crate::NodeDiskMemoryAdmission>)'),
]:
 p=OUT/'proposed/crates/kasumi-store'/path;s=p.read_text();assert needle in s,path;s=s.replace(needle,replacement,1)
 start=s.index(replacement);body=s.index('{',start)
 line='\n'+re.match(r'\s*',s[body+1:]).group().split('\n')[-1]+'let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);'
 # The inserted declaration is the first line of this helper body.
 m=re.match(r'\s*let fixture_memory = crate::test_utils::TestDiskMemory::new\(256 << 20, 4096\);',s[body+1:]);assert m,path;s=s[:body+1]+s[body+1+m.end():]
 s=append_calls(s,name);p.write_text(s)
# The two explicit scratch configurations use the same fixture core as their node.
for path in ['src/tests.rs','src/node_file/tests.rs']:
 p=OUT/'proposed/crates/kasumi-store'/path;s=p.read_text();m=mask(s);edits=[]
 for c in re.finditer(r'ScratchDisk::open\s*\(',m):
  start=c.end()-1;end=close(m,start)
  edits.extend([(c.start(),start+1,'ScratchDisk::open_fixture(&'),(end,end,', fixture_memory.clone()')])
 for a,b,t in sorted(edits,reverse=True):s=s[:a]+t+s[b:]
 p.write_text(s)
