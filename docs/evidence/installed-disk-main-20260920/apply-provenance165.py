from pathlib import Path
import hashlib,json,stat,subprocess
ROOT=Path('/Users/mtakemiya/dev/kasumi');OUT=ROOT/'target/installed-disk-validation';PKG=OUT/'redb-current-provenance-checkpoint'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def check(p,r):
 assert not p.is_symlink() and p.is_file(),str(p)
 assert sha(p)==r['sha256'] and p.stat().st_size==r['bytes'] and oct(stat.S_IMODE(p.stat().st_mode))==r['mode'],str(p)
def new_file(p,source):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(source.read_bytes())
 p.chmod(stat.S_IMODE(source.stat().st_mode))
 assert p.read_bytes()==source.read_bytes()
assert subprocess.check_output(['git','branch','--show-current'],cwd=ROOT,text=True).strip()=='master'
assert sha(PKG/'manifest.json')=='eb2b072c7b173833e4444aa03793da260926d1be747090edfae36e94853ebb35'
m=json.loads((PKG/'manifest.json').read_text());old_path=ROOT/'vendor/patch-manifest.json';old_bytes=old_path.read_bytes()
assert sha(old_path)==m['original_manifest_sha256'];old=json.loads(old_bytes);proposed=PKG/'proposed';new=json.loads((proposed/'vendor/patch-manifest.json').read_text())
assert len(old['inventories'])==len(new['inventories'])
for a,b in zip(old['inventories'],new['inventories']):
 if a!=b:
  assert a['path']==b['path']=='vendor/redb-4.2.0'
  assert {k:v for k,v in a.items() if k not in ['files','review']}=={k:v for k,v in b.items() if k not in ['files','review']}
assert old['format']==new['format']==2
assert set(old['support_files'])==set(new['support_files'])
assert [k for k in old['support_files'] if old['support_files'][k]!=new['support_files'][k]]==['README.md']
for name,r in m['source_checkpoint'].items():check(ROOT/'vendor/redb-4.2.0'/name,r)
for name,r in m['proposed_installation_artifacts'].items():check(proposed/name,r)
for name,r in m['preparation_and_verification_artifacts'].items():check(PKG/name,r)
for name,r in new['support_files'].items():check(ROOT/'vendor'/name,r)
evidence=Path('docs/evidence/redb-current-source-20260922');d=json.loads((proposed/evidence/'provenance.json').read_text());original_path=ROOT/d['checkpoint']['original_provenance']['path'];original=json.loads(original_path.read_text())
assert sha(original_path)==m['original_provenance_sha256']
for k in ['published_crate_sha256','published_crate_url','upstream_commit','companion_archive_sha256','companion_archive_url']:assert original[k]==d[k]
assert sorted(f['path'] for f in original['files'] if f['fork_sha256'] is None)==sorted(f['path'] for f in d['files'] if f['fork_sha256'] is None)
bindings=json.loads((proposed/evidence/'evidence-bindings.json').read_text());ids=set()
for b in bindings['bindings']:
 assert b['id'] not in ids;ids.add(b['id'])
 p=proposed/b['path'];source=ROOT/b['original_repository_path'];assert sha(p)==sha(source)==b['sha256'] and p.stat().st_size==source.stat().st_size==b['bytes']
assert len(ids)==134
for t in bindings['tests']:
 if t['attempt'] in [162,163,164]:
  assert not t['current_redb_source_different'] and not [x for x in t['not_in_gate_source_inventory'] if x.endswith('.rs')]
  assert t['result']['exit_code']==0 and t['result']['drained'] and t['result']['inventoried_source_unchanged']
subprocess.run(['git','apply','--check',str(PKG/'policy-update.patch')],cwd=ROOT,check=True)
review=OUT/'redb-current-provenance-root-review';review.mkdir(exist_ok=False)
text='''# Root adoption review of the current redb inventory

Approved as an exact current-source inventory checkpoint, not final release acceptance. The root independently verified all 109 current file hashes, lengths and modes; 111 provenance rows preserve the two original removals; original published and companion identities remain intact. The policy changes only the redb inventory/provenance binding and vendor README support hash. The checker, other five source inventories, package roster and three other support records remain unchanged.

All 134 copied historical/gate bindings match their repository sources exactly. Historical patches and scoped reviews are partial history, not a claimed complete transformation chain. Current Rust/Cargo inputs exactly match completed 162/163/164 unit, strict vendor lint and public integration runs, with unchanged source and actual drain. Earlier differing gate inputs are explicitly labeled. Root also read the current canonical-format/integration fixture diffs and original checked-backend correction: these retain malformed-input rejection, exact original errors and unchanged-file assertions. They introduce no reader fallback or relaxed workload.

Root authored and reviewed the current vendor README, KASUMI_PATCH and CHANGELOG wording. They distinguish the original import from selected current source, record canonical format 4 and retained outcomes, and state the unfinished production adoption/resource and upstream workflow gates. The proposal metadata remains immutable; this receipt supplies its subsequent adoption decision. Frozen candidate source verification uses the exact unchanged checker and retains three negative rejection cases. Actual Cargo selection verification follows as run 165; no passing result is claimed here.

Complete ownership correspondence, production census/caller adoption, protected maintenance, memory/workspace, unavailable upstream gates and final native release qualification remain open. This inventory checkpoint closes none of G01-G14.
'''
(review/'review.md').write_text(text)
receipt={'status':'approved-current-source-inventory-checkpoint-not-release-acceptance','root':str(ROOT),'branch':'master','candidate_manifest_sha256':sha(PKG/'manifest.json'),'policy_patch_sha256':sha(PKG/'policy-update.patch'),'old_policy_sha256':sha(old_path),'new_policy_sha256':sha(proposed/'vendor/patch-manifest.json'),'provenance_sha256':sha(proposed/evidence/'provenance.json'),'review_sha256':sha(review/'review.md'),'current_files_verified':109,'evidence_bindings_verified':134,'checker_changed':False,'cargo_selection_validation':'run165 pending'}
(review/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
assert not (ROOT/evidence).exists()
for name,r in m['proposed_installation_artifacts'].items():
 if name=='vendor/patch-manifest.json':continue
 assert Path(name).is_relative_to(evidence)
 new_file(ROOT/name,proposed/name);check(ROOT/name,r)
new_file(ROOT/evidence/'root-adoption-review.md',review/'review.md');new_file(ROOT/evidence/'root-adoption-receipt.json',review/'receipt.json')
assert old_path.read_bytes()==old_bytes
subprocess.run(['git','apply',str(PKG/'policy-update.patch')],cwd=ROOT,check=True)
assert sha(old_path)==m['candidate_manifest_sha256']
for name,r in m['source_checkpoint'].items():check(ROOT/'vendor/redb-4.2.0'/name,r)
assert sha(original_path)==m['original_provenance_sha256']
new_file(OUT/'165-original-vendor-policy.json',PKG/'verification-original-manifest.json') if (PKG/'verification-original-manifest.json').exists() else (OUT/'165-original-vendor-policy.json').write_bytes(old_bytes)
(OUT/'165-provenance-applied.json').write_text(json.dumps({**receipt,'review_receipt_sha256':sha(review/'receipt.json'),'installed_evidence_files':141,'actual_source_unchanged':True},indent=2)+'\n')
print(json.dumps({'installed_evidence_files':141,'policy_sha256':sha(old_path),'review_receipt_sha256':sha(review/'receipt.json'),'applied_receipt_sha256':sha(OUT/'165-provenance-applied.json')}))
