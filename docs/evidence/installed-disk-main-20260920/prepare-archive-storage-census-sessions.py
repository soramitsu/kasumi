"""Freeze only completed prerequisite packages; never traverse Cargo assemblies."""
from pathlib import Path
import hashlib,json
ROOT=Path('/Users/mtakemiya/dev/kasumi'); SOURCE=ROOT/'target/installed-disk-validation'
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''): h.update(b)
 return h.hexdigest()
def encoded(v): return (json.dumps(v,indent=2,sort_keys=True)+'\n').encode()
files=set(); packages=[]; controls={}; terminals={}
def add(p):
 assert p.is_file() and not p.is_symlink(),str(p)
 assert p.resolve().is_relative_to(SOURCE)
 files.add(p)
def tree(p):
 for f in p.rglob('*'):
  if f.is_file(): add(f)
def top(p):
 for f in p.iterdir():
  if f.is_file(): add(f)
def package(name):
 p=SOURCE/name; packages.append(name); return p
for name in ['storage-census-adoption','storage-census-adoption-revision2','storage-census-adoption-revision3']:
 p=package(name); top(p)
 for sub in ['base','proposed']: tree(p/sub)
 controls[name+'/manifest.json']=digest(p/'manifest.json')
 for native in sorted(p.glob('native-*')):
  assert (native/'result.json').is_file(),native
  result=json.loads((native/'result.json').read_text()); results=json.loads((native/'results.json').read_text())
  assert result['source_unchanged'],native
  assert all(x.get('drained',x.get('process_group_drained')) is True for x in results),native
  terminals[str(native.relative_to(SOURCE))]={'result_sha256':digest(native/'result.json'),'results_sha256':digest(native/'results.json'),'source_unchanged':True,'all_process_groups_drained':True,'all_passed':result['all_passed']}
  top(native) # Executable bytes are hashed, then omitted by the archiver.
p=package('backup-namespace-admission'); top(p)
for sub in ['base','proposed','format-01-before','format-02-before','format-03-before','candidate-02-apply-check','candidate-03-apply-check']:
 if (p/sub).is_dir(): tree(p/sub)
for native in sorted(p.glob('native-*')):
 top(native)
 for sub in ['node_disk','proposal-at-run']:
  if (native/sub).is_dir(): tree(native/sub)
 if (native/'results.json').exists():
  results=json.loads((native/'results.json').read_text()); drain=json.loads((native/'terminal-drain.json').read_text())
  assert all(x['process_group_drained'] for x in results),native
  assert json.loads((native/'before.json').read_text())==json.loads((native/'after.json').read_text()),native
  terminals[str(native.relative_to(SOURCE))]={'results_sha256':digest(native/'results.json'),'drain_sha256':digest(native/'terminal-drain.json'),'source_unchanged':True,'all_process_groups_drained':True,'all_passed':all(x['exit_code']==0 for x in results)}
 else: assert (native/'preparation-failure.json').is_file(),native
for name in ['candidate-02.json','candidate-03.json']: controls[str((p/name).relative_to(SOURCE))]=digest(p/name)
p=package('backup-namespace-admission-revision4'); raw=json.loads((p/'raw-manifest.json').read_text())
for n,v in raw.items():
 f=p/n; assert f.stat().st_size==v['bytes'] and digest(f)==v['sha256'],n; add(f)
add(p/'raw-manifest.json'); controls[str((p/'raw-manifest.json').relative_to(SOURCE))]=digest(p/'raw-manifest.json')
native=p/'native-01'; results=json.loads((native/'results.json').read_text()); assert all(x['exit_code']==0 and x['process_group_drained'] for x in results)
assert json.loads((native/'before.json').read_text())==json.loads((native/'after.json').read_text())
terminals[str(native.relative_to(SOURCE))]={'results_sha256':digest(native/'results.json'),'drain_sha256':digest(native/'terminal-drain.json'),'source_unchanged':True,'all_process_groups_drained':True,'all_passed':True}
for name in ['storage-census-adoption-independent-review','storage-census-adoption-revision2-independent-review','backup-namespace-claim-path-design-review','backup-namespace-admission-revision4-independent-review','backup-namespace-session-root-review','redb-canonical-page-number-audit']:
 p=package(name);tree(p)
 for name2 in ['receipt.json','manifest.json']:
  if (p/name2).exists(): controls[str((p/name2).relative_to(SOURCE))]=digest(p/name2)
add(Path(__file__).resolve())
inputs={'package_roots':packages,'controls':controls,'terminal_runs':{},'candidate_terminal_runs':terminals,'files':{str(p.relative_to(SOURCE)):{'sha256':digest(p),'bytes':p.stat().st_size} for p in sorted(files)},'selection_policy':'Frozen package source/readback/receipts only; no Cargo assembly or dependency cache traversal. Preparation, compile, stale-executable, runtime and parser failures preserved.'}
out=SOURCE/'archive-storage-census-sessions';out.mkdir(exist_ok=False);(out/'inputs.json').write_bytes(encoded(inputs));input_sha=digest(out/'inputs.json')
script=(SOURCE/'archive-provenance-successors.py').read_text()
script=script.replace('current dependency provenance evidence','storage census and session prerequisite evidence').replace('Run165 are included only with pinned terminal/drained receipts.','Candidate runs are included only after terminal and drain verification.')
script=script.replace('archive-provenance-successors','archive-storage-census-sessions').replace('3f953010e0fe1f2adb84ad5e7cc72c56cfdccc380deba1e0dd8ba85202e3c0bf',input_sha).replace('4980','5160').replace('2470453a84a8b6f20efeef67eb750c60e3a1cd321f8df7ebd5036db0bb5aa827','c5920b77dfc114a8047329ca47b3d47829a1d1dc6e355663acd9fd0816f03c68').replace('provenance-native-binary-omissions','storage-census-sessions-native-binary-omissions').replace('provenance-append-receipts','storage-census-sessions-append-receipts')
script=script.replace("'terminal_runs_selected': sorted(selected_terminals)}","'terminal_runs_selected': sorted(selected_terminals), 'candidate_terminal_runs': inputs['candidate_terminal_runs']}")
path=SOURCE/'archive-storage-census-sessions.py'
with path.open('x') as f:f.write(script)
print(json.dumps({'files':len(files),'packages':len(packages),'candidate_runs':len(terminals),'inputs_sha256':input_sha,'script_sha256':digest(path)}))
