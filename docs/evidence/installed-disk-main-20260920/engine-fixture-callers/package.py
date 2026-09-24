from pathlib import Path
import subprocess,json,hashlib,difflib
D=Path('target/installed-disk-validation/engine-fixture-callers');P=D/'proposed';rows=json.loads((D/'inventory.json').read_text())['files'];diff=[];manifest=[];formatted=[]
sha=lambda b:hashlib.sha256(b).hexdigest()
for r in rows:
 rel=r['path'];p=P/rel;b=(D/'before'/rel).read_bytes()
 expected=Path(r['base']).read_bytes() if Path(r['base']).exists() else b''
 assert expected==b,(rel,'baseline changed')
 run=subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true','--emit','stdout'],input=p.read_bytes(),capture_output=True)
 assert run.returncode==0,(rel,run.stderr.decode())
 p.write_bytes(run.stdout);s=run.stdout;formatted.append(rel)
 if b==s:continue
 manifest.append(dict(path=rel,base=r['base'],before_sha256=sha(b),proposed_sha256=sha(s),new_file=r.get('new_file',False)))
 diff.append('diff --git a/'+rel+' b/'+rel+'\n')
 if r.get('new_file'):diff.append('new file mode 100644\n')
 diff.extend(difflib.unified_diff(b.decode().splitlines(True),s.decode().splitlines(True),fromfile='/dev/null' if r.get('new_file') else 'a/'+rel,tofile='b/'+rel,n=3))
(D/'callers.patch').write_text(''.join(diff));patchsha=sha((D/'callers.patch').read_bytes())
(D/'manifest.json').write_text(json.dumps(dict(status='FROZEN_TARGET_ONLY_UNCOMPILED',source_head='600c0ca2b2c4c22b89b44ccd932eca02272c70f1',patch_sha256=patchsha,files=manifest),indent=2)+'\n')
V=D/'virtual-check'
for r in manifest:
 if r['new_file']:continue
 dst=V/r['path'];dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes((D/'before'/r['path']).read_bytes())
# New paths must not preexist for the target-only application.
for r in manifest:
 if r['new_file'] and (V/r['path']).exists():(V/r['path']).unlink()
cmd=['git','apply','--unsafe-paths','--directory='+str(V)]
check=subprocess.run(cmd+['--check',str(D/'callers.patch')],capture_output=True,text=True)
assert check.returncode==0,check.stderr
apply=subprocess.run(cmd+[str(D/'callers.patch')],capture_output=True,text=True)
assert apply.returncode==0,apply.stderr
for r in manifest:assert sha((V/r['path']).read_bytes())==r['proposed_sha256'],r['path']
(D/'validation.json').write_text(json.dumps(dict(patch_sha256=patchsha,rustfmt_stdin_pass=formatted,virtual_apply_check_exit=check.returncode,virtual_apply_exit=apply.returncode,all_proposed_hashes_match=True,no_rust_build=True,actual_source_unchanged=True),indent=2)+'\n')
(D/'paths.txt').write_text(''.join(r['path']+'\n' for r in manifest))
print(len(manifest),patchsha)
