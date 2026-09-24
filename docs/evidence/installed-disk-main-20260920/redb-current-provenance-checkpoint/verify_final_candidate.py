from pathlib import Path
import copy,hashlib,importlib.util,json,shutil,sys
sys.dont_write_bytecode=True
ROOT=Path('/Users/mtakemiya/dev/kasumi');PKG=ROOT/'target/installed-disk-validation/redb-current-provenance-checkpoint';OVERLAY=PKG/'verification-root'
assert Path.cwd()==ROOT and (ROOT/'.git/HEAD').read_text().strip()=='ref: refs/heads/master'
assert sys.version_info >= (3,11)
sha=lambda b:hashlib.sha256(b).hexdigest()
preparation=json.loads((PKG/'preparation.json').read_text());original_manifest=(ROOT/'vendor/patch-manifest.json').read_bytes();original_checker=(ROOT/'scripts/check_dependency_patches.py').read_bytes()
assert sha(original_manifest)==preparation['original_manifest_sha256']
assert OVERLAY.is_dir()
assert (PKG/'verification.json').is_file()
for p in (PKG/'proposed').rglob('*'):
    if p.is_file():
        out=OVERLAY/p.relative_to(PKG/'proposed');out.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,out)
# Existing policy references remain in the proposed complete manifest. Retain
# only the exact files its unmodified source verifier reads, without Cargo.
old=json.loads(original_manifest)
for inventory in old['inventories']:
    review=inventory.get('review')
    if review:
        for key in ['path','inventory_path']:
            if key in review:
                rel=review[key];out=OVERLAY/rel;out.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/rel,out)
spec=importlib.util.spec_from_file_location('current_exact_dependency_checker',ROOT/'scripts/check_dependency_patches.py');checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
packages=checker.verify_sources(OVERLAY)
assert len(packages)==7
new=json.loads((PKG/'redb-inventory-candidate.json').read_text())
negative=[]
def rejected(label,operation):
    try:operation()
    except ValueError as error:negative.append({'case':label,'rejected':True,'message':str(error)})
    else:raise AssertionError(label+' did not reject')
bad=copy.deepcopy(new);bad['review']=next(i['review'] for i in old['inventories'] if i['path']=='vendor/redb-4.2.0')
rejected('current109_inventory_with_original97_provenance',lambda:checker.verify_review(OVERLAY,bad))
bad=copy.deepcopy(new);bad['files'].pop('src/tree_store/page_store/allocator_snapshot.rs')
rejected('omit_added_payload_source_from_current_reviewed_inventory',lambda:checker.verify_review(OVERLAY,bad))
bad=copy.deepcopy(new['files']['Cargo.toml']);bad['mode']='0o755'
rejected('changed_file_mode_is_not_accepted',lambda:checker.check_file(OVERLAY/'vendor/redb-4.2.0/Cargo.toml',bad))
assert (ROOT/'vendor/patch-manifest.json').read_bytes()==original_manifest and (ROOT/'scripts/check_dependency_patches.py').read_bytes()==original_checker
report={'status':'EXACT_UNMODIFIED_VERIFY_SOURCES_PASS_NO_CARGO','python_version':sys.version,'python_executable':sys.executable,'checker_path':'scripts/check_dependency_patches.py','checker_sha256':sha(original_checker),'candidate_manifest_sha256':sha((PKG/'proposed/vendor/patch-manifest.json').read_bytes()),'packages':packages,'negative_checks':negative,'source_root':str(OVERLAY),'actual_manifest_unchanged':True,'actual_checker_unchanged':True,'cargo_metadata_or_selection_run':False,'verifier_policy_changed':False}
(PKG/'final-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'selected_package_records':len(packages),'negative_checks':negative},indent=2))
