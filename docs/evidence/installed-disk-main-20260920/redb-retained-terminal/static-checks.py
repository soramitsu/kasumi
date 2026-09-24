from pathlib import Path
import hashlib, json, subprocess
root=Path('/Users/mtakemiya/dev/kasumi')
pkg=root/'target/installed-disk-validation/redb-retained-terminal'
m=json.loads((pkg/'manifest.json').read_text())
checks=[]
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
for f in m['files']:
 p=root/f['path']
 actual=hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
 assert actual==f['base_sha256'],f['path']
 assert hashlib.sha256((pkg/'proposed'/f['path']).read_bytes()).hexdigest()==f['proposed_sha256']
assert hashlib.sha256((pkg/'terminal.patch').read_bytes()).hexdigest()==m['patch_sha256']
commands=[['git','apply','--check',str(pkg/'terminal.patch')],['/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustfmt','--edition','2024','--config','skip_children=true','--check',*[str(pkg/'proposed'/f['path']) for f in m['files']]]]
for i,command in enumerate(commands):
 r=subprocess.run(command,cwd=root,text=True,capture_output=True)
 (pkg/f'check-{i}.stdout').write_text(r.stdout)
 (pkg/f'check-{i}.stderr').write_text(r.stderr)
 checks.append({'argv':command,'returncode':r.returncode})
 assert r.returncode==0
checks={'status':'STATIC_CHECKS_ONLY','base_unchanged':True,'actual_source_edited':False,'cargo_compiled_or_tested':False,'commands':checks}
(pkg/'static-checks.json').write_text(json.dumps(checks,indent=2)+'\n')
print(json.dumps({'patch':m['patch_sha256'],'files':len(m['files']),'prepared_tests':m['prepared_tests'],'checks':[c['returncode'] for c in checks['commands']]}))
