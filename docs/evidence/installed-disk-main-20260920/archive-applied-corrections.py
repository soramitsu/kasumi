from pathlib import Path
import hashlib,json,subprocess
root=Path('/Users/mtakemiya/dev/kasumi')
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
source=root/'target/installed-disk-validation'; destination=root/'docs/evidence/installed-disk-main-20260920'
manifest_path=destination/'raw-sha256.json';manifest=json.loads(manifest_path.read_text()); previous=len(manifest)
for name,digest in manifest.items():assert hashlib.sha256((destination/name).read_bytes()).hexdigest()==digest,name
files={source/'archive-applied-corrections.py',source/'91-corrections-applied.json',source/'91-additional-fixtures-applied.json'}
for name in ['authority-lint-corrections','file-owner-retirement','89-audit-metadata-fixture','89-tenant-audit-policy-fixture','89-bootstrap-audit-fixtures','assembly-metadata-custody']:
 for p in (source/name).iterdir():
  if p.is_file() and p.suffix in {'.py','.json','.md','.patch','.txt','.rs','.log'}:files.add(p)
for p in (source/'assembly-metadata-python-01').rglob('*'):
 if p.is_file():files.add(p)
for p in sorted(files):
 relative=p.relative_to(source);data=p.read_bytes();digest=hashlib.sha256(data).hexdigest();target=destination/relative
 if target.exists():assert target.read_bytes()==data,str(relative)
 else:target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
 if str(relative) in manifest:assert manifest[str(relative)]==digest,str(relative)
 else:manifest[str(relative)]=digest
manifest_path.write_text(json.dumps(dict(sorted(manifest.items())),indent=2)+'\n')
for name,digest in manifest.items():assert hashlib.sha256((destination/name).read_bytes()).hexdigest()==digest,name
print(json.dumps({'previous_entries_verified':previous,'entries_verified':len(manifest),'new_package_and_python_files':len(files)}))
