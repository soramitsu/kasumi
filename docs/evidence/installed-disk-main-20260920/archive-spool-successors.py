"""Archive frozen borrowed-spool and diagnostic successors without replacing history."""
from pathlib import Path
import hashlib,json,subprocess
root=Path('/Users/mtakemiya/dev/kasumi')
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
source=root/'target/installed-disk-validation'
destination=root/'docs/evidence/installed-disk-main-20260920'
manifest_path=destination/'raw-sha256.json'
manifest=json.loads(manifest_path.read_text()); previous=len(manifest)
for name,digest in manifest.items():
 assert hashlib.sha256((destination/name).read_bytes()).hexdigest()==digest,name
files={Path(__file__).resolve(),source/'114-corrections-applied.json'}
for name in ['retained-spool-close','114-successor-corrections','114-spool-module-order','redb-workspace-estimator','109-stopped-epoch-bounded-resolution-candidate','retained-transaction-disposal']:
 files.update(p for p in (source/name).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
attempts=[]
for number in range(114,120):
 receipt=source/f'{number}-result.json'
 if not receipt.exists(): continue
 record=json.loads(receipt.read_text()); assert record['drained'] and record['cwd']==str(root),receipt
 attempts.append(number); files.add(source/f'run{number}.py')
 files.update(p for p in source.glob(f'{number}-*') if p.is_file())
omitted=[]
for path in sorted(files):
 assert not path.is_symlink(),path
 relative=path.relative_to(source); data=path.read_bytes(); digest=hashlib.sha256(data).hexdigest()
 if data[:4] in (b'\xcf\xfa\xed\xfe',b'\xce\xfa\xed\xfe',b'\x7fELF',b'\xca\xfe\xba\xbe'):
  omitted.append({'path':str(relative),'bytes':len(data),'sha256':digest,'reason':'Native development executable retained under target; source, receipts and exact digest archived.'}); continue
 target=destination/relative
 if target.exists(): assert target.read_bytes()==data,str(relative)
 else: target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(data)
 if str(relative) in manifest: assert manifest[str(relative)]==digest,str(relative)
 else: manifest[str(relative)]=digest
name='spool-successors-probe-binary-omissions.json'; data=(json.dumps(omitted,indent=2)+'\n').encode(); target=destination/name
if target.exists(): assert target.read_bytes()==data
else: target.write_bytes(data)
manifest[name]=hashlib.sha256(data).hexdigest()
manifest_path.write_text(json.dumps(dict(sorted(manifest.items())),indent=2)+'\n')
for name,digest in manifest.items(): assert hashlib.sha256((destination/name).read_bytes()).hexdigest()==digest,name
print(json.dumps({'previous_entries_verified':previous,'entries_verified':len(manifest),'completed_attempts_archived':attempts,'probe_binaries_retained_only_in_target':len(omitted)}))
