from pathlib import Path
import difflib,hashlib,json,re,subprocess
p=Path(__file__).parent;a=p.parent/'pure-codec-store-agent'
sha=lambda b:hashlib.sha256(b).hexdigest()
first=json.loads((a/'manifest.json').read_text());firstpaths={e['path']:e for e in first['files']}
r=subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',*[str(f) for f in (p/'proposed').rglob('*.rs')]],capture_output=True,text=True)
(p/'format-output.txt').write_text(r.stdout+r.stderr);assert r.returncode==0
files=[];follow=[];combined=[]
for f in sorted((p/'base').rglob('*.rs')):
 rel=f.relative_to(p/'base');mid=f.read_bytes();after=(p/'proposed'/rel).read_bytes();actual=Path(rel).read_bytes()
 if str(rel) in firstpaths:
  assert sha(actual)==firstpaths[str(rel)]['before_sha256'],str(rel)
  assert sha(mid)==firstpaths[str(rel)]['proposed_sha256'],str(rel)
 else:assert mid==actual,str(rel)
 assert not re.search(rb'ScratchDisk::fixture\(\)',after),str(rel)
 tests=lambda b:len(re.findall(rb'#\[(?:tokio::)?test(?:\(|\])',b))
 assert tests(actual)==tests(after),str(rel)
 if actual==after:continue
 files.append({'path':str(rel),'actual_before_sha256':sha(actual),'after_first_layer_sha256':sha(mid),'proposed_sha256':sha(after),'stacked':str(rel) in firstpaths,'scratch_calls':after.count(b'ScratchDisk::fixture('),'test_attributes':tests(after)})
 if mid!=after:follow.extend(difflib.unified_diff(mid.decode().splitlines(True),after.decode().splitlines(True),fromfile='a/'+str(rel),tofile='b/'+str(rel)))
 combined.extend(difflib.unified_diff(actual.decode().splitlines(True),after.decode().splitlines(True),fromfile='a/'+str(rel),tofile='b/'+str(rel)))
follow=''.join(follow);combined=''.join(combined)
(p/'followup.patch').write_text(follow);(p/'combined-raft-callers.patch').write_text(combined)
check=subprocess.run(['git','apply','--check',str(p/'combined-raft-callers.patch')],capture_output=True,text=True)
(p/'patch-check.txt').write_text(check.stdout+check.stderr+f'exit_code={check.returncode}\n');assert check.returncode==0
manifest={'status':'PREPARED_UNAPPLIED_UNCOMPILED','repository':str(Path.cwd()),'branch':'master','combined_patch_sha256':sha(combined.encode()),'followup_patch_sha256':sha(follow.encode()),'first_layer_sha256':first['patch_sha256'],'store_revision2_sha256':'10ebc1c6ee2a0df7c65b67302757b537ddedcb000008ea5391a82d030fab5259','files':files,'rustfmt':'passed target-only','patch_check_exit_code':0,'actual_source_unchanged':True,'cargo_runs':[],'application':'Apply combined-raft-callers.patch directly to current actual source OR first layer callers.patch then followup.patch. Never apply both combined and first layer.','scope':'All current Raft scratch/physical-disk fixture constructor callers and helper dependencies; engine/server/authority/client/bench remain separate.'}
(p/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(p/'paths.txt').write_text(''.join(e['path']+'\n' for e in files))
print(json.dumps({'combined_sha':manifest['combined_patch_sha256'],'followup_sha':manifest['followup_patch_sha256'],'files':len(files),'diff_lines':len(combined.splitlines()),'scratch_owners':sum(e['scratch_calls'] for e in files)},indent=2))
