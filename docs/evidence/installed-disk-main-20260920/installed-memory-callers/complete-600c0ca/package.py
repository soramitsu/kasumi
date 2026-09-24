from pathlib import Path
import subprocess,hashlib,json,difflib
root=Path.cwd();base=root/'target/installed-disk-validation/installed-memory-callers/complete-600c0ca';proposed=base/'proposed';files=[];patch=[]
for p in sorted(proposed.rglob('*')):
 if not p.is_file():continue
 rel=p.relative_to(proposed);actual=root/rel;before=actual.read_bytes() if actual.exists() else b'';after=p.read_bytes()
 if before==after:continue
 if p.suffix=='.rs':
  result=subprocess.run(['/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustfmt','--edition','2024','--emit','stdout','--config','skip_children=true'],input=after,capture_output=True)
  if result.returncode:raise RuntimeError(str(rel)+': '+result.stderr.decode())
  after=result.stdout;p.write_bytes(after)
 files.append({'path':str(rel),'before_sha256':hashlib.sha256(before).hexdigest() if actual.exists() else None,'after_sha256':hashlib.sha256(after).hexdigest()})
 patch.extend(difflib.unified_diff(before.decode().splitlines(True),after.decode().splitlines(True),fromfile='a/'+str(rel) if actual.exists() else '/dev/null',tofile='b/'+str(rel)))
payload=''.join(patch).encode();(base/'server.patch').write_bytes(payload)
manifest={'status':'Proposed only; uncompiled; source unchanged','base_commit':'600c0ca2b2c4c22b89b44ccd932eca02272c70f1','patch_sha256':hashlib.sha256(payload).hexdigest(),'files':files};(base/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
result=subprocess.run(['git','apply','--check',str(base/'server.patch')],capture_output=True,text=True);print(result.stdout+result.stderr);assert result.returncode==0
print(len(files),'files',manifest['patch_sha256'])
