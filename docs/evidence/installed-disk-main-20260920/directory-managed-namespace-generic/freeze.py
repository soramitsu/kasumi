from pathlib import Path
import json,hashlib,difflib,subprocess,shutil
r=Path.cwd();p=r/'target/installed-disk-validation/directory-managed-namespace-generic';dependency=r/'target/installed-disk-validation/directory-managed-namespace'
def digest(b):return hashlib.sha256(b).hexdigest()
base_mismatches=[]
for f in (p/'base').rglob('*'):
 if f.is_file():
  relative=f.relative_to(p/'base');dep=dependency/'cumulative-proposed'/relative
  if not dep.exists() or f.read_bytes()!=dep.read_bytes():base_mismatches.append(str(relative))
assert not base_mismatches,base_mismatches
for f in (p/'proposed').rglob('*'):
 if f.is_file():
  d=p/'cumulative-proposed'/f.relative_to(p/'proposed');d.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,d)
def make(kind):
 base=p/('base' if kind=='successor' else 'cumulative-base');proposed=p/('proposed' if kind=='successor' else 'cumulative-proposed');paths=sorted(set(f.relative_to(base) for f in base.rglob('*') if f.is_file())|set(f.relative_to(proposed) for f in proposed.rglob('*') if f.is_file()));pieces=[];records=[]
 for relative in paths:
  bf=base/relative;af=proposed/relative;before=bf.read_bytes() if bf.exists() else b'';after=af.read_bytes() if af.exists() else b''
  if before==after:continue
  pieces.extend(difflib.unified_diff(before.decode().splitlines(True),after.decode().splitlines(True),fromfile='a/'+str(relative) if bf.exists() else '/dev/null',tofile='b/'+str(relative) if af.exists() else '/dev/null'))
  records.append({'path':str(relative),'base_sha256':digest(before) if bf.exists() else None,'proposed_sha256':digest(after) if af.exists() else None})
 patch=''.join(pieces).encode();pf=p/(kind+'.patch');pf.write_bytes(patch)
 # Exactly known baseline tree, no actual checkout mutation.
 check=p/('apply-check-'+kind);assert not check.exists();shutil.copytree(base,check)
 q=subprocess.run(['git','apply','--check',str(pf)],cwd=check,capture_output=True,text=True);assert q.returncode==0,q.stderr
 q=subprocess.run(['git','apply',str(pf)],cwd=check,capture_output=True,text=True);assert q.returncode==0,q.stderr
 for item in records:
  f=check/item['path'];assert digest(f.read_bytes())==item['proposed_sha256']
 return {'patch':pf.name,'sha256':digest(patch),'files':records,'apply_check':'PASS exact baseline/proposed bytes'}
manifest={'status':'TARGET_ONLY_GENERIC_CORRECTION_NATIVE49PASS_UNAPPLIED','branch':subprocess.check_output(['git','branch','--show-current'],text=True).strip(),'root':str(r),'dependency':json.loads((p/'dependency.json').read_text()),'successor':make('successor'),'cumulative':make('cumulative'),'native':{'result':'49 PASS/0 FAIL/5 filtered; complete prior47 plus two generic acquisition tests','results_sha256':digest((p/'native-01/results.json').read_bytes()),'groups':[14226,14227,14239,14257,14261],'all_groups_drained':True,'inputs_unchanged':1731,'limits':'original120seconds perphase'}}
(p/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps({'manifest_sha256':digest((p/'manifest.json').read_bytes()),'successor_sha256':manifest['successor']['sha256'],'successor_files':len(manifest['successor']['files']),'cumulative_sha256':manifest['cumulative']['sha256'],'cumulative_files':len(manifest['cumulative']['files'])},indent=2))
