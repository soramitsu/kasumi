from pathlib import Path
import difflib,json,hashlib,subprocess
root=Path('/Users/mtakemiya/dev/kasumi')
out=root/'target/installed-disk-validation/88-engine-causal-fixtures'
sha=lambda b:hashlib.sha256(b).hexdigest()
files=[]
all_patch=''
core_patch=''
schema_patch=''
for base in sorted((out/'base').rglob('*.rs')):
    name=str(base.relative_to(out/'base'))
    proposed=out/'proposed'/name
    old,new=base.read_bytes(),proposed.read_bytes()
    assert (root/name).read_bytes()==old, f'actual changed: {name}'
    patch=''.join(difflib.unified_diff(old.decode().splitlines(True),new.decode().splitlines(True),fromfile='a/'+name,tofile='b/'+name))
    all_patch+=patch
    if name.endswith('/schema_activation.rs'):schema_patch+=patch
    else:core_patch+=patch
    files.append({'path':name,'base_sha256':sha(old),'proposed_sha256':sha(new)})
artifacts={}
for name,body in [('corrections.patch',all_patch),('history-lifecycle-recovery.patch',core_patch),('schema-generation-release.patch',schema_patch)]:
    (out/name).write_text(body)
    artifacts[name]=sha(body.encode())
checks=[]
commands=[['git','apply','--check',str(out/'corrections.patch')],['git','apply','--numstat',str(out/'corrections.patch')],['/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustfmt','--check','--edition','2024','--config','skip_children=true']+[str(out/'proposed'/f['path']) for f in files]]
for i,args in enumerate(commands):
    result=subprocess.run(args,cwd=root,text=True,capture_output=True)
    (out/f'check-{i}.stdout').write_text(result.stdout)
    (out/f'check-{i}.stderr').write_text(result.stderr)
    checks.append({'command':args,'exit_code':result.returncode,'stdout_sha256':sha(result.stdout.encode()),'stderr_sha256':sha(result.stderr.encode())})
    assert result.returncode==0,(args,result.stderr)
(out/'manifest.json').write_text(json.dumps({'branch':subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip(),'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'scope':'target-only source proposal; no Cargo/builds','files':files,'patches':artifacts},indent=2)+'\n')
(out/'static-checks.json').write_text(json.dumps({'checks':checks,'actual_source_matches_base':True,'tests_run':False,'cargo_run':False},indent=2)+'\n')
print(json.dumps({'patches':artifacts,'files':files},indent=2))
print((out/'check-1.stdout').read_text())
