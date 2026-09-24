from pathlib import Path
import shutil,json
r=Path.cwd();p=r/'target/installed-disk-validation/directory-parent-transitions';old=p/'native-02';d=p/'native-03';d.mkdir()
for folder in ('deps','node_disk'):shutil.copytree(old/folder,d/folder)
for rel in ('node_disk.rs','driver.rs','disk_memory.rs','device_disk.rs','selected.json','copied-dependencies.json','run.py'):
 (d/rel).write_text((old/rel).read_text().replace('/native-02/','/native-03/'))
selected=json.loads((d/'selected.json').read_text())
for name in ['tempfile','rustix','errno','fastrand','once_cell']:
 choices=[f for f in (r/'target/debug/deps').glob('lib'+name+'-*') if f.suffix in ('.rlib','.dylib')]
 for f in choices:shutil.copyfile(f,d/'deps'/f.name)
 libs=[f for f in choices if f.suffix=='.rlib']
 if libs:selected[name]=str(d/'deps'/max(libs,key=lambda f:f.stat().st_mtime_ns).name)
selected['zeroize']=str(max((d/'deps').glob('libzeroize-*.rlib'),key=lambda f:f.stat().st_mtime_ns))
(d/'selected.json').write_text(json.dumps(selected,indent=2)+'\n')
(d/'private_files.rs').write_bytes((r/'crates/kasumi-store/src/private_files.rs').read_bytes())
q=d/'driver.rs';q.write_text(q.read_text().replace('mod node_disk;','mod node_disk;\nmod private_files;'))
q=d/'run.py';q.write_text(q.read_text().replace("'node_disk.rs','driver.rs'","'private_files.rs','node_disk.rs','driver.rs'").replace("'sha2','parking_lot')","'sha2','parking_lot','zeroize','tempfile')"))
