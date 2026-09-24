from pathlib import Path
import re
root=Path(__file__).parent/'proposed'/'crates/kasumi-raft'
memory_type='Arc<dyn kasumi_store::NodeDiskMemoryAdmission>'
declaration='    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);'
def end_paren(text,start):
 level=0; quote=None;escape=False
 for i in range(start,len(text)):
  c=text[i]
  if quote:
   if escape:escape=False
   elif c=='\\':escape=True
   elif c==quote:quote=None
  elif c=='"':quote=c
  elif c=='(':level+=1
  elif c==')':
   level-=1
   if level==0:return i
 raise ValueError(start)
def addarg(text,pattern,arg):
 edits=[]
 for m in re.finditer(pattern,text):
  if re.search(r'fn\s+$',text[max(0,m.start()-4):m.start()]):continue
  e=end_paren(text,m.end()-1)
  edits.append((e,', '+arg))
 for e,v in reversed(edits):text=text[:e]+v+text[e:]
 return text

def inject_top_functions(text):
 starts=list(re.finditer(r'(?m)^async fn (\w+)\([^)]*\)(?:\s*->[^\{]+)?\s*\{',text))
 edits=[]
 for idx,m in enumerate(starts):
  body=text[m.end():starts[idx+1].start() if idx+1<len(starts) else len(text)]
  if m[1] in ('new_fault_store','existing_fault_store','open','accepted_snapshot'):continue
  if 'let disk_memory =' in body:continue
  if any(s in body for s in ['ScratchDisk::fixture()', 'common::store(', 'new_fault_store(', 'existing_fault_store(', 'envelope(', 'image(', 'open(seed.', 'open(disk.']):
   edits.append(m.end())
 for i in reversed(edits):text=text[:i]+'\n'+declaration+text[i:]
 return text
for path in root.rglob('*.rs'):
 text=path.read_text();name=path.name
 if name!='snapshot_custody_tests.rs':text=inject_top_functions(text)
 if name=='tests.rs':
  text=text.replace('async fn new_fault_store(disk: FaultBackend)',f'async fn new_fault_store(disk: FaultBackend, disk_memory: {memory_type})')
  text=text.replace('async fn existing_fault_store(disk: FaultBackend)',f'async fn existing_fault_store(disk: FaultBackend, disk_memory: {memory_type})')
  text=text.replace('fn envelope(bytes: Vec<u8>)',f'fn envelope(bytes: Vec<u8>, disk_memory: {memory_type})')
  text=text.replace('async fn open(path: &std::path::Path, create: bool)',f'async fn open(path: &std::path::Path, create: bool, disk_memory: {memory_type})')
  text=addarg(text,r'(?<![:\w])open\(', 'disk_memory.clone()')
 if name=='joint_publication_tests.rs':
  text=text.replace('fn image(tag: u8, index: u64)',f'fn image(tag: u8, index: u64, disk_memory: {memory_type})')
  text=text.replace('    create: bool,\n)',f'    create: bool,\n    disk_memory: {memory_type},\n)')
  text=addarg(text,r'(?<![:\w])image\(', 'disk_memory.clone()')
  text=addarg(text,r'(?<![:\w])open\(', 'disk_memory.clone()')
 if name=='mod.rs':
  text=text.replace('pub async fn store(path: &Path, create: bool)',f'pub async fn store(path: &Path, create: bool, disk_memory: {memory_type})')
 if name=='cluster.rs':
  text=text.replace('struct Cluster {\n','struct Cluster {\n    disk_memory: '+memory_type+',\n')
  text=text.replace('        let mut cluster = Self {\n','        let mut cluster = Self {\n            disk_memory: kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096),\n')
  text=addarg(text,r'common::store\(', 'disk_memory.clone()')
  text=text.replace('format!("node-{id}.redb")), create, disk_memory.clone()', 'format!("node-{id}.redb")), create, self.disk_memory.clone()')
 if name=='read_barrier.rs':
  text=text.replace('    async fn new() -> Result<Self> {','    async fn new() -> Result<Self> {\n    '+declaration)
 if name=='storage_conformance.rs':
  text=text.replace('        async {\n            let dir =','        async {\n        '+declaration+'\n            let dir =')
  text=text.replace('async fn open(disk: FaultBackend, create: bool)',f'async fn open(disk: FaultBackend, create: bool, disk_memory: {memory_type})')
  text=addarg(text,r'(?<![:\w])open\(', 'disk_memory.clone()')
 if name!='cluster.rs':text=addarg(text,r'common::store\(', 'disk_memory.clone()')
 text=addarg(text,r'(?<![:\w])(?:new_fault_store|existing_fault_store|envelope)\(', 'disk_memory.clone()')
 text=text.replace('kasumi_store::ScratchDisk::fixture()', 'kasumi_store::ScratchDisk::fixture(disk_memory.clone())')
 # NodeStore physical constructors gain memory before the existing scratch owner.
 for m in list(re.finditer(r'(?:kasumi_store::)?NodeStore::(?:create_new_fixture|open_existing_fixture)\(',text))[::-1]:
  e=end_paren(text,m.end()-1)
  old=text[m.end():e]
  assert old.count('NODE_STORE_ID,')==1
  new=old.replace('NODE_STORE_ID,','NODE_STORE_ID,\n            disk_memory.clone(),')
  text=text[:m.end()]+new+text[e:]
 path.write_text(text)
