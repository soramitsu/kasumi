from pathlib import Path
import gzip,hashlib,json,stat,sys
base=Path(__file__).resolve().parent
manifest=json.loads((base/'archive-manifest.json').read_text())
sha=lambda b:hashlib.sha256(b).hexdigest()
expected={e['archive_path'] for e in manifest['files']}|{'archive-manifest.json'}
actual={str(p.relative_to(base)) for p in base.rglob('*') if p.is_file()}
assert actual==expected,('archive path mismatch',actual^expected)
for entry in manifest['files']:
 p=base/entry['archive_path'];assert not p.is_symlink();data=p.read_bytes()
 assert len(data)==entry['archive_bytes'] and sha(data)==entry['archive_sha256'],str(p)
 raw=gzip.decompress(data) if entry['encoding']=='gzip' else data
 assert len(raw)==entry['source_bytes'] and sha(raw)==entry['source_sha256'],str(p)
args=sys.argv[1:];assert args in [[],['--live-base'],['--live-proposed']],args
if args:
 candidate=json.loads((base/'candidate/manifest.json').read_text());root=Path(candidate['root']);key='before' if args==['--live-base'] else 'after'
 for entry in candidate['files']:
  p=root/entry['path'];assert (sha(p.read_bytes()) if p.exists() else None)==entry[key],str(p)
  if p.exists():assert oct(stat.S_IMODE(p.stat().st_mode))==entry[key+'_mode'],str(p)
print(json.dumps({'archive_files_verified':len(manifest['files']),'live_check':args[0] if args else None,'status':'PASS'}))
