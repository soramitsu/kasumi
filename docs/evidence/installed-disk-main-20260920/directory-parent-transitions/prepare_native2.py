from pathlib import Path
import shutil,json
r=Path.cwd();p=r/'target/installed-disk-validation/directory-parent-transitions';old=p/'native-01';d=p/'native-02';d.mkdir()
shutil.copytree(old/'deps',d/'deps')
for rel in ('driver.rs','disk_memory.rs','device_disk.rs','selected.json','copied-dependencies.json','run.py'):
 (d/rel).write_text((old/rel).read_text().replace('/native-01/','/native-02/'))
for name in ['subtle','zeroize','hybrid_array','rand_chacha','ppv_lite86','const_oid']:
 for f in (r/'target/debug/deps').glob('lib'+name+'-*'):
  if f.suffix in ('.rlib','.dylib'):shutil.copyfile(f,d/'deps'/f.name)
s=p/'proposed/crates/kasumi-store/src';(d/'node_disk.rs').write_bytes((s/'node_disk.rs').read_bytes());shutil.copytree(s/'node_disk',d/'node_disk')
q=d/'driver.rs';v=q.read_text();v=v.replace(f'#[path = {json.dumps(str(s/"node_disk.rs"))}] mod node_disk;','mod node_disk;');q.write_text(v)
q=d/'run.py';v=q.read_text().replace("(pkg/'proposed',p/'deps')","(pkg/'proposed',p/'deps',p/'node_disk')").replace("'driver.rs','disk_memory.rs'","'node_disk.rs','driver.rs','disk_memory.rs'");q.write_text(v)
