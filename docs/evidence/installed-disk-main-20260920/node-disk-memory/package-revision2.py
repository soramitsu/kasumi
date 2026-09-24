from pathlib import Path
import difflib,hashlib,json,re,subprocess
p=Path(__file__).parent
sha=lambda b:hashlib.sha256(b).hexdigest()
r=subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',*[str(f) for f in (p/'proposed').rglob('*.rs')]],capture_output=True,text=True)
(p/'revision2-format-output.txt').write_text(r.stdout+r.stderr);assert r.returncode==0
old=json.loads((p/'revisions/v1/manifest.json').read_text());files=[];patch=[];followup=[];count=0
for e in old['files']:
 rel=Path(e['path']);base=(p/'base'/rel).read_bytes() if e['before_sha256'] else b''
 actual=rel.read_bytes() if rel.exists() else b'';assert actual==base,str(rel)
 after=(p/'proposed'/rel).read_bytes();inter=(p/'revisions/v1/proposed'/rel).read_bytes()
 if base==after:continue
 patch.extend(difflib.unified_diff(base.decode().splitlines(True),after.decode().splitlines(True),fromfile='a/'+str(rel) if base else '/dev/null',tofile='b/'+str(rel)))
 followup.extend(difflib.unified_diff(inter.decode().splitlines(True),after.decode().splitlines(True),fromfile='a/'+str(rel),tofile='b/'+str(rel)))
 oldnames=set(re.findall(rb'\bfn (\w+)\(',base));newtests=[]
 for m in re.finditer(rb'#\[(?:tokio::)?test(?:\([^\]]*\))?\]\s*(?:#\[[^\]]*\]\s*)*(?:async )?fn (\w+)',after):
  if m[1] not in oldnames:newtests.append(m[1].decode())
 count+=len(newtests)
 files.append({'path':str(rel),'before_sha256':sha(base) if base else None,'revision1_sha256':sha(inter),'proposed_sha256':sha(after),'new_test_functions':newtests})
patch=''.join(patch);followup=''.join(followup)
(p/'metadata.patch').write_text(patch);(p/'revision2-followup.patch').write_text(followup)
check=subprocess.run(['git','apply','--check',str(p/'metadata.patch')],capture_output=True,text=True)
(p/'patch-check.txt').write_text(check.stdout+check.stderr+f'exit_code={check.returncode}\n');assert check.returncode==0
manifest={**old,'revision':2,'patch_sha256':sha(patch.encode()),'revision1_patch_sha256':old['patch_sha256'],'revision2_followup_sha256':sha(followup.encode()),'files':files,'new_test_count':count,'scratch_lifetime':'Strong installed owner and all leases retained until process exit; external Weak remains funded. Per-file charges release independently. Fixture directory cleanup belongs to mandatory caller scope.','rustfmt':'passed revision2 target-only','patch_check_exit_code':0,'cargo_runs':[]}
(p/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(p/'paths.txt').write_text(''.join(f['path']+'\n' for f in files))
print(json.dumps({'complete_sha':manifest['patch_sha256'],'followup_sha':manifest['revision2_followup_sha256'],'files':len(files),'new_tests':count,'diff_lines':len(patch.splitlines())},indent=2))
