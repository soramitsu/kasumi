from pathlib import Path
import difflib,hashlib,json,shutil,subprocess
r=Path.cwd();p=r/'target/installed-disk-validation/directory-fixed-maps';prior=r/'target/installed-disk-validation/directory-cursor'
assert subprocess.check_output(['git','branch','--show-current'],text=True).strip()=='master'
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
assert sha(prior/'cumulative.patch')=='1e01ebae6ec21036854a4f82050eb96ba0a4681fc07a2d4563150e3d61bcfaca'
shutil.copytree(prior/'cumulative-proposed',p/'cumulative-proposed');shutil.copytree(prior/'cumulative-base',p/'cumulative-base')
for f in (p/'proposed').rglob('*'):
 if f.is_file():q=p/'cumulative-proposed'/f.relative_to(p/'proposed');q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,q)
rel=Path('crates/kasumi-store/src/allocation_tests.rs');q=p/'cumulative-base'/rel;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p/'base'/rel,q)
def patch(base,proposed,name):
 chunks=[];files=[]
 for f in sorted(proposed.rglob('*')):
  if not f.is_file():continue
  rel=f.relative_to(proposed);old=base/rel;a=old.read_text().splitlines(keepends=True) if old.exists() else [];b=f.read_text().splitlines(keepends=True)
  if a==b:continue
  files.append(str(rel));chunks.append(f'diff --git a/{rel} b/{rel}\n')
  if not old.exists():chunks.append('new file mode 100644\n')
  chunks.extend(difflib.unified_diff(a,b,fromfile=f'a/{rel}' if old.exists() else '/dev/null',tofile=f'b/{rel}'))
 (p/name).write_text(''.join(chunks));return {'sha256':sha(p/name),'files':files}
patches={'fixed-maps.patch':patch(p/'base',p/'proposed','fixed-maps.patch'),'cumulative.patch':patch(p/'cumulative-base',p/'cumulative-proposed','cumulative.patch')}
manifest={'status':'frozen target-only code; NOT MERGE READY, NOT production qualified','root':str(r),'branch':'master','head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'dependency':{'patch':str(prior/'cumulative.patch'),'sha256':sha(prior/'cumulative.patch')},'patches':patches,'files':{}}
for f in sorted((p/'cumulative-proposed').rglob('*')):
 if not f.is_file():continue
 rel=f.relative_to(p/'cumulative-proposed');actual=r/rel;cb=p/'cumulative-base'/rel;baseline=p/'base'/rel
 manifest['files'][str(rel)]={'successor_changed':(p/'proposed'/rel).exists() and (not baseline.exists() or sha(baseline)!=sha(f)),'successor_base_sha256':sha(baseline) if baseline.exists() else None,'cumulative_base_sha256':sha(cb) if cb.exists() else None,'current_actual_sha256':sha(actual) if actual.exists() else None,'proposed_sha256':sha(f)}
manifest['current_source_matches_cumulative_base']=all(v['cumulative_base_sha256']==v['current_actual_sha256'] for v in manifest['files'].values())
(p/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'patches':{k:{'sha256':v['sha256'],'files':len(v['files'])} for k,v in patches.items()},'manifest_sha256':sha(p/'manifest.json'),'current_source_matches_cumulative_base':manifest['current_source_matches_cumulative_base']},indent=2))
