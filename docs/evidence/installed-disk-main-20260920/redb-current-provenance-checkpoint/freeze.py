from pathlib import Path
import copy,datetime,difflib,hashlib,json,os,stat
ROOT=Path('/Users/mtakemiya/dev/kasumi');PKG=ROOT/'target/installed-disk-validation/redb-current-provenance-checkpoint';EVIDENCE=Path('docs/evidence/redb-current-source-20260922')
assert Path.cwd()==ROOT and (ROOT/'.git/HEAD').read_text().strip()=='ref: refs/heads/master'
assert not (PKG/'manifest.json').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text())
def rec(p):
 s=p.lstat();assert stat.S_ISREG(s.st_mode),str(p)
 return {'sha256':sha(p),'bytes':s.st_size,'mode':oct(stat.S_IMODE(s.st_mode))}
def inventory(p):
 out={};pending=[p]
 while pending:
  for e in os.scandir(pending.pop()):
   f=Path(e.path);s=e.stat(follow_symlinks=False)
   if stat.S_ISDIR(s.st_mode):pending.append(f)
   else:out[f.relative_to(p).as_posix()]=rec(f)
 return dict(sorted(out.items()))
prep=read(PKG/'preparation.json');current_vendor=inventory(ROOT/'vendor');assert current_vendor==prep['current_vendor']
original_path=ROOT/'docs/evidence/redb-canonical-20260920/provenance.json';original=read(original_path);assert sha(original_path)==prep['original_provenance_sha256'];assert sha(ROOT/'vendor/patch-manifest.json')==prep['original_manifest_sha256']
policy=read(PKG/'proposed/vendor/patch-manifest.json');original_policy=read(ROOT/'vendor/patch-manifest.json');new_inventory=next(x for x in policy['inventories'] if x['path']=='vendor/redb-4.2.0');old_inventory=next(x for x in original_policy['inventories'] if x['path']=='vendor/redb-4.2.0')
reconstructed=copy.deepcopy(policy);reconstructed['inventories']=[old_inventory if x['path']=='vendor/redb-4.2.0' else x for x in reconstructed['inventories']];reconstructed['support_files']['README.md']=original_policy['support_files']['README.md'];assert reconstructed==original_policy
assert {k:v for k,v in new_inventory.items() if k not in {'review','files'}}=={k:v for k,v in old_inventory.items() if k not in {'review','files'}}
current=inventory(ROOT/'vendor/redb-4.2.0');assert len(current)==109 and current==inventory(PKG/'current-source') and current==new_inventory['files'];assert policy['support_files']['README.md']==rec(ROOT/'vendor/README.md')
provenance_path=PKG/'proposed'/EVIDENCE/'provenance.json';provenance=read(provenance_path);assert {k:v for k,v in provenance.items() if k not in {'files','checkpoint'}}=={k:v for k,v in original.items() if k!='files'}
assert new_inventory['review']=={'kind':'redb-provenance','path':str(EVIDENCE/'provenance.json'),'sha256':sha(provenance_path)}
assert len(provenance['files'])==111
rows={x['path']:x for x in provenance['files']};original_rows={x['path']:x for x in original['files']}
for name,row in original_rows.items():
 assert rows[name]['prior_canonical_fork_sha256']==row['fork_sha256']
 for key in ['published_sha256','upstream_companion_sha256']:
  assert rows[name].get(key)==row.get(key)
for name,record in current.items():assert {'sha256':rows[name]['fork_sha256'],'bytes':rows[name]['fork_bytes'],'mode':rows[name]['fork_mode']}==record
removed=sorted(x['path'] for x in provenance['files'] if x['fork_sha256'] is None);assert removed==sorted(x['path'] for x in original['files'] if x['fork_sha256'] is None)
for key in ['source_inventory','changes_since_import','review_and_test_bindings']:
 item=provenance['checkpoint'][key];assert sha(PKG/'proposed'/item['path'])==item['sha256']
bindings=read(PKG/'proposed'/EVIDENCE/'evidence-bindings.json');assert len(bindings['bindings'])==134
for item in bindings['bindings']:
 assert sha(PKG/'proposed'/item['path'])==item['sha256']==sha(ROOT/item['original_repository_path'])
 assert (PKG/'proposed'/item['path']).stat().st_size==item['bytes']
for run in [162,163,164]:
 test=next(t for t in bindings['tests'] if t['attempt']==run);assert test['result']['exit_code']==0 and test['result']['drained'] and test['result']['inventoried_source_unchanged']
 assert not test['current_redb_source_different'];assert all(not name.endswith('.rs') for name in test['not_in_gate_source_inventory'])
verification=read(PKG/'final-verification.json');assert verification['status']=='EXACT_UNMODIFIED_VERIFY_SOURCES_PASS_NO_CARGO';assert verification['candidate_manifest_sha256']==sha(PKG/'proposed/vendor/patch-manifest.json');assert verification['checker_sha256']==sha(ROOT/'scripts/check_dependency_patches.py');assert not verification['cargo_metadata_or_selection_run'];assert all(x['rejected'] for x in verification['negative_checks'])
patch=''.join(difflib.unified_diff((ROOT/'vendor/patch-manifest.json').read_text().splitlines(keepends=True),(PKG/'proposed/vendor/patch-manifest.json').read_text().splitlines(keepends=True),fromfile='a/vendor/patch-manifest.json',tofile='b/vendor/patch-manifest.json'));(PKG/'policy-update.patch').write_text(patch)
artifacts=inventory(PKG/'proposed');support={name:rec(PKG/name) for name in ['README.md','prepare.py','bind_archived_test_history.py','verify_candidate.py','verify_final_candidate.py','freeze.py','preparation.json','verification.json','final-verification.json','redb-inventory-candidate.json','vendor-support-candidate.json','policy-update.patch']}
manifest={'status':'FROZEN_TARGET_ONLY_CURRENT_SOURCE_CHECKPOINT_PENDING_ROOT_REVIEW_NOT_RELEASE_ACCEPTANCE','repository':str(ROOT),'branch':'master','frozen_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'original_manifest_sha256':prep['original_manifest_sha256'],'original_provenance_sha256':prep['original_provenance_sha256'],'candidate_manifest_sha256':sha(PKG/'proposed/vendor/patch-manifest.json'),'provenance_sha256':sha(provenance_path),'policy_patch_sha256':sha(PKG/'policy-update.patch'),'current_source_files':len(current),'provenance_rows':len(rows),'original_removals_preserved':removed,'evidence_bindings':len(bindings['bindings']),'proposed_installation_artifacts':artifacts,'preparation_and_verification_artifacts':support,'installation_scope':['Add exact proposed/docs/evidence/redb-current-source-20260922 evidence files.','Replace only redb inventory/review and vendor README support record in vendor/patch-manifest.json.'],'scratch_excluded_from_installation':['current-source','verification-root'],'source_checkpoint':current,'policy_scope_assertion':'All other inventory fields, inventory roots, support records and policy fields remain byte-equivalent after JSON parsing.','no_actual_source_manifest_checker_mutation':True,'no_cargo_native_or_formatter_execution':True,'historical_scope':'Exact archived patch and review bindings provide partial historical coverage; no complete transformation chain or blanket current-source review is asserted.','current_component_gates':[162,163,164],'current_documentation_requiring_root_adoption_review':['vendor/redb-4.2.0/CHANGELOG.md','vendor/redb-4.2.0/KASUMI_PATCH.md','vendor/README.md'],'verification':verification['status'],'release_acceptance':False}
assert inventory(ROOT/'vendor')==current_vendor and sha(original_path)==prep['original_provenance_sha256'] and sha(ROOT/'scripts/check_dependency_patches.py')==verification['checker_sha256']
(PKG/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'manifest_sha256':sha(PKG/'manifest.json'),'policy_patch_sha256':manifest['policy_patch_sha256'],'candidate_manifest_sha256':manifest['candidate_manifest_sha256'],'provenance_sha256':manifest['provenance_sha256'],'proposed_artifact_count':len(artifacts),'evidence_binding_count':len(bindings['bindings']),'source_unchanged':True},indent=2))
