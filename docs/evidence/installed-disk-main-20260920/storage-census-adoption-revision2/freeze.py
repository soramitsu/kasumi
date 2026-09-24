from pathlib import Path
import hashlib, difflib, json, subprocess
r=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
files=[];patch=[]
for p in sorted((r/'proposed').rglob('*.rs')):
 rel=p.relative_to(r/'proposed');b=r/'base'/rel;live=Path('/Users/mtakemiya/dev/kasumi')/rel
 before=b.read_text() if b.exists() else ''
 after=p.read_text()
 if before==after: continue
 if b.exists(): assert live.read_bytes()==b.read_bytes(),str(rel)
 else: assert not live.exists(),str(rel)
 files.append({'path':str(rel),'before':sha(b) if b.exists() else None,'after':sha(p)})
 patch.append(f'diff --git a/{rel} b/{rel}\n')
 if not b.exists(): patch.append('new file mode 100644\n')
 patch.extend(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile=f'a/{rel}' if b.exists() else '/dev/null',tofile=f'b/{rel}'))
(r/'adoption.patch').write_text(''.join(patch))
result=subprocess.run(['git','apply','--check',str(r/'adoption.patch')],cwd='/Users/mtakemiya/dev/kasumi',text=True,capture_output=True)
(r/'apply-check.stdout').write_text(result.stdout);(r/'apply-check.stderr').write_text(result.stderr)
manifest={'schema':'kasumi-target-storage-census-adoption-v2','root':'/Users/mtakemiya/dev/kasumi','branch':subprocess.check_output(['git','branch','--show-current'],text=True).strip(),'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'files':files,'patch_sha256':sha(r/'adoption.patch'),'apply_check_exit':result.returncode,'target_rustfmt_exit':0,'new_tests':18,'cargo_dispatched':False,'native_tests_dispatched':False,'production_callers_migrated':False,'complete_workspace_bound':False,'readme_sha256':sha(r/'README.md')}
(r/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'files':len(files),'patch_sha256':sha(r/'adoption.patch'),'manifest_sha256':sha(r/'manifest.json'),'apply_check_exit':result.returncode,'stderr':result.stderr[:1500]}))
