from pathlib import Path
import hashlib,json,subprocess
root=Path.cwd();base=root/'target/installed-disk-validation/database-construction'
m=json.loads((base/'manifest.json').read_text())
guards=root/'target/installed-disk-validation/installed-memory-engine-guards/proposed'
tree=base/'validation-tree'; results=[]
for item in m['files']:
 rel=item['path']; dest=tree/rel
 dest.parent.mkdir(parents=True,exist_ok=True)
 if item['before_sha256'] is None:
  if dest.exists():dest.unlink()
  continue
 source=(guards/rel) if item['baseline'].startswith('corrected guards') else root/rel
 data=source.read_bytes();assert hashlib.sha256(data).hexdigest()==item['before_sha256'],rel
 dest.write_bytes(data)
args=['git','apply','--directory',str(tree.relative_to(root))]
patch=str((base/'construction.patch').relative_to(root))
check=subprocess.run(args+['--check',patch],capture_output=True,text=True)
assert check.returncode==0,check.stderr
apply=subprocess.run(args+[patch],capture_output=True,text=True)
assert apply.returncode==0,apply.stderr
for item in m['files']:
 data=(tree/item['path']).read_bytes(); got=hashlib.sha256(data).hexdigest()
 assert got==item['proposed_sha256'],item['path']
 results.append({'path':item['path'],'virtual_result_sha256':got})
receipt={'status':'TARGET_ONLY_VIRTUAL_APPLY_AND_FORMAT_VALIDATED_NOT_COMPILED','patch_sha256':m['patch_sha256'],'check_exit_code':check.returncode,'apply_exit_code':apply.returncode,'files':results}
(base/'validation.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(receipt['patch_sha256'],len(results),'virtual apply verified')
