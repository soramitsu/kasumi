from pathlib import Path
import subprocess,json,os,hashlib
root=Path('/Users/mtakemiya/dev/kasumi'); stage=root/'target/installed-disk-validation'; os.chdir(root)
head='600c0ca2b2c4c22b89b44ccd932eca02272c70f1'
assert subprocess.check_output(['git','branch','--show-current'],text=True).strip()=='master'
assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==head
assert not subprocess.check_output(['git','status','--porcelain'],text=True)
index=stage/'installed-memory-assembly.index'; env={**os.environ,'GIT_INDEX_FILE':str(index)}
items=[('engine-fixture-callers/callers.patch','b9b8ad4c271feaa26adb69c043e185e57bab193b9d5e292bb47ec6e8475c2a65'),('installed-memory-review-corrections/pause-before-offline-mutation.patch','f8bec7aa2a549eff1f84f88ccb806a517be7f6e8e3f0861f8546efba79a6810c')]
receipt=json.loads((stage/'installed-memory-assembly.json').read_text())
for path,expected in items:
 p=stage/path;actual=hashlib.sha256(p.read_bytes()).hexdigest();assert actual==expected,(path,actual)
 r=subprocess.run(['git','apply','--cached',str(p)],env=env,capture_output=True,text=True)
 receipt['packages'].append({'path':path,'sha256':actual,'status':r.returncode,'stderr':r.stderr})
 assert r.returncode==0,(path,r.stderr)
combined=subprocess.check_output(['git','diff','--cached','--binary','HEAD'],env=env)
patch=stage/'installed-memory-combined.patch';patch.write_bytes(combined)
receipt.update(status='TARGET_ONLY_COMPLETE_UNCOMPILED',head=head,patch_sha256=hashlib.sha256(combined).hexdigest())
files=[]
for name in subprocess.check_output(['git','diff','--cached','--name-only','HEAD'],env=env,text=True).splitlines():
 p=root/name
 files.append({'path':name,'before_sha256':hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None,'proposed_sha256':hashlib.sha256(subprocess.check_output(['git','show',':'+name],env=env)).hexdigest()})
receipt['files']=files
(stage/'installed-memory-combined.manifest.json').write_text(json.dumps(receipt,indent=2)+'\n')
subprocess.run(['git','apply','--check',str(patch)],check=True)
print(json.dumps({'status':receipt['status'],'files':len(files),'patch_sha256':receipt['patch_sha256']}))
