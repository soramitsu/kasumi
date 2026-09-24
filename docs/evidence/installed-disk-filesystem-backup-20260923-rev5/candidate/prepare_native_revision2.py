"""Freeze an exact target assembly after root selects applied or frozen revision6.
This script copies and verifies source only; it never dispatches Cargo/native code.
"""
from pathlib import Path
import hashlib,json,shutil,subprocess,sys,stat
root=Path('/Users/mtakemiya/dev/kasumi')
pkg=Path(__file__).resolve().parent
base=root/'target/installed-disk-validation/storage-namespace-custody-integration-revision6'
out=pkg/'native-02';assembly=out/'assembly'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sys.argv[1:] in [['actual'],['frozen']]
mode=sys.argv[1]
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
assert not assembly.exists() and not (out/'preflight.json').exists() and not (out/'cargo-target').exists()
assert sha(pkg/'manifest.json')=='7b10428c0b5cea9eba7b03ac57ca3ba1e86eb32fbacbbf50b03d8123420c908a'
assert sha(base/'manifest.json')=='b2d6f9f980a55d0e1a688093cf2deb64269878005ff78e15f394af8341b336e5'
m=json.loads((pkg/'manifest.json').read_text());b=json.loads((base/'manifest.json').read_text())
selected={f['path']:f for f in b['files']}
for f in b['files']:
 actual=root/f['path'];current=sha(actual) if actual.exists() else None
 assert current==f['after' if mode=='actual' else 'before'],(f['path'],current)
 assert sha(base/'proposed'/f['path'])==f['after']
def source_record(path):
 return {'sha256':sha(path),'bytes':path.stat().st_size,'mode':oct(stat.S_IMODE(path.stat().st_mode))}
def exact_nonselected_sources(expected,actual,selected):
 return {p:v for p,v in expected.items() if p not in selected}=={p:v for p,v in actual.items() if p not in selected}
def source_set(base):
 paths=[p for component in ['crates','vendor','tests'] for p in (base/component).rglob('*') if p.is_file()]
 paths += [base/name for name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']]
 return {str(p.relative_to(base)):source_record(p) for p in paths}
expected_sources=source_set(base/'assembly');actual_sources=source_set(root)
assert exact_nonselected_sources(expected_sources,actual_sources,selected),'outside-composition source path/hash/mode/Cargo drift'
for f in b['files']:
 actual=root/f['path']
 if actual.exists():
  assert oct(stat.S_IMODE(actual.stat().st_mode))==f['after_mode' if mode=='actual' else 'before_mode']
assembly.mkdir()
for component in ['crates','vendor','tests','docs','scripts']:
 shutil.copytree(root/component,assembly/component)
for name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']:
 shutil.copyfile(root/name,assembly/name)
if mode=='frozen':
 for f in b['files']:
  target=assembly/f['path'];target.parent.mkdir(parents=True,exist_ok=True)
  shutil.copyfile(base/'proposed'/f['path'],target)
for f in b['files']:assert sha(assembly/f['path'])==f['after']
for f in m['changes']:
 target=assembly/f['path'];actual=sha(target) if target.exists() else None
 assert actual==f['before_sha256']
 target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pkg/'proposed'/f['path'],target)
 assert sha(target)==f['after_sha256']
bindings=[]
for tree in [assembly,pkg/'base',pkg/'proposed',base/'proposed']:
 for p in sorted(tree.rglob('*')):
  if p.is_file():bindings.append({'path':str(p.relative_to(root)),'sha256':sha(p),'bytes':p.stat().st_size,'mode':oct(stat.S_IMODE(p.stat().st_mode))})
for p in [pkg/'manifest.json',pkg/'adoption.patch',pkg/'expected-store-tests.json',base/'manifest.json',base/'combined.patch',base/'expected-store-tests.json']:
 bindings.append({'path':str(p.relative_to(root)),'sha256':sha(p),'bytes':p.stat().st_size,'mode':oct(stat.S_IMODE(p.stat().st_mode))})
for f in b['files']:
 p=root/f['path']
 if p.exists():bindings.append({'path':str(p.relative_to(root)),'sha256':sha(p),'bytes':p.stat().st_size,'mode':oct(stat.S_IMODE(p.stat().st_mode))})
preflight={'status':'FROZEN_SOURCE_ASSEMBLY_NO_NATIVE_DISPATCH','root':str(root),'branch':'master','actual_base_mode':mode,'integration_manifest_sha256':sha(base/'manifest.json'),'adoption_manifest_sha256':sha(pkg/'manifest.json'),'expected_store_count':345,'cohort_bound_seconds':1200,'source_set_sha256':hashlib.sha256(json.dumps(actual_sources,sort_keys=True).encode()).hexdigest(),'source_set':actual_sources,'input_bindings':bindings}
(out/'preflight.json').write_text(json.dumps(preflight,indent=2)+'\n')
print(json.dumps({'assembly':str(assembly),'mode':mode,'bindings':len(bindings),'preflight_sha256':sha(out/'preflight.json')}))
