from pathlib import Path
import json,shutil,os
r=Path.cwd();p=r/'target/installed-disk-validation/directory-parent-transitions';o=p/'native-04';d=p/'native-05';d.mkdir();shutil.copytree(o/'deps',d/'deps',copy_function=os.link);shutil.copytree(o/'node_disk',d/'node_disk')
for n in ('private_files.rs','node_disk.rs','driver.rs','disk_memory.rs','device_disk.rs','selected.json','copied-dependencies.json','run.py'):(d/n).write_text((o/n).read_text().replace('/native-04/','/native-05/'))
index={}
for f in (r/'target/debug/.fingerprint').glob('*/lib-*.json'):
 name=f.stem.removeprefix('lib-');index.setdefault(name,set()).update(x[1] for x in json.loads(f.read_text())['deps'] if x[1]!='build_script_build')
names={'anyhow','serde','uuid','libc','sha2','parking_lot','zeroize','tempfile'};pending=list(names)
while pending:
 for dep in index.get(pending.pop(),set()):
  if dep not in names:names.add(dep);pending.append(dep)
new=[]
for name in names:
 for f in (r/'target/debug/deps').glob('lib'+name+'-*'):
  if f.suffix in ('.rlib','.dylib') and not (d/'deps'/f.name).exists():shutil.copyfile(f,d/'deps'/f.name);new.append(f.name)
(d/'dependency-closure.json').write_text(json.dumps({'names':sorted(names),'added':sorted(new)},indent=2)+'\n');print('closure',len(names),'added',len(new))
