from pathlib import Path
import re
exec(Path('target/installed-disk-validation/node-disk-memory/migrate-fixtures.py').read_text().split('callrx=')[0])
p=OUT/'proposed/crates/kasumi-store/src/node_disk/tests.rs';s=p.read_text();a=s.index('fn open(');b=close(mask(s),s.index('{',a))+1;s=s[:a]+'''fn open(config: NodeDiskConfig, memory: Arc<dyn NodeDiskMemoryAdmission>) -> Arc<NodeDisk> {
    NodeDisk::open_fixture(&config, memory, &CensusCancellation::default()).unwrap()
}'''+s[b:]
m=mask(s);edits=[]
for c in re.finditer(r'(?<![\w.:])open\s*\(',m):
 if m[max(0,c.start()-3):c.start()]=='fn ':continue
 start=c.end()-1;end=close(m,start);aa=args(m,start,end);assert len(aa)==1
 edits.append((end,end,', fixture_memory.clone()'))
for c in re.finditer(r'NodeDisk::(open|open_inner)\s*\(',m):
 start=c.end()-1;end=close(m,start);aa=args(m,start,end)
 config=s[aa[0][0]:aa[0][1]].strip();config=config.removesuffix('.clone()');cancel=s[aa[1][0]:aa[1][1]].strip()
 if c.group(1)=='open_inner':text=f'NodeDisk::open_fixture(&{config}, fixture_memory.clone(), {cancel})'
 else:text=f'NodeDisk::open(&{config}, fixture_memory.clone(), {cancel})'
 edits.append((c.start(),end+1,text))
for f in re.finditer(r'#\[test\]\s*fn\s+\w+\([^)]*\)[^{]*\{',m):
 edits.append((f.end(),f.end(),'\n    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);'))
for a,b,text in sorted(edits,reverse=True):s=s[:a]+text+s[b:]
p.write_text(s)
