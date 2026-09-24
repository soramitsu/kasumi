from pathlib import Path
import datetime,hashlib,json,os,stat,sys
ROOT=Path('/Users/mtakemiya/dev/kasumi');OUT=ROOT/'target/installed-disk-validation/vendor-inventory-drift'
assert Path.cwd()==ROOT and (ROOT/'.git/HEAD').read_text().strip()=='ref: refs/heads/master'
sha=lambda b:hashlib.sha256(b).hexdigest()
def record(path):
    observed=path.lstat()
    if not stat.S_ISREG(observed.st_mode):
        return {'special_mode':oct(observed.st_mode)}
    return {'sha256':sha(path.read_bytes()),'bytes':observed.st_size,'mode':oct(stat.S_IMODE(observed.st_mode))}
def scan(directory):
    files={};special=[];pending=[directory]
    while pending:
        current=pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                path=Path(entry.path);relative=path.relative_to(directory).as_posix();mode=entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):pending.append(path)
                elif stat.S_ISREG(mode):files[relative]=record(path)
                else:special.append({'path':relative,'mode':oct(mode)})
    return files,special
manifest_path=ROOT/'vendor/patch-manifest.json';manifest_bytes=manifest_path.read_bytes();manifest=json.loads(manifest_bytes)
source_path=ROOT/'docs/evidence/installed-disk-main-20260920/161-source-after.json';source_bytes=source_path.read_bytes();source=json.loads(source_bytes)
result_path=ROOT/'docs/evidence/installed-disk-main-20260920/161-result.json';result_bytes=result_path.read_bytes()
next_source_path=ROOT/'target/installed-disk-validation/162-source-before.json';next_source_bytes=next_source_path.read_bytes();next_source=json.loads(next_source_bytes)
payload_path=ROOT/'target/installed-disk-validation/redb-allocator-payload-shapes/manifest.json';payload_bytes=payload_path.read_bytes();payload=json.loads(payload_bytes);payload_files={x['path']:x['proposed_sha256'] for x in payload['files']}
applied_path=ROOT/'target/installed-disk-validation/162-allocator-payload-shapes-applied.json';applied_bytes=applied_path.read_bytes()
next_result_path=ROOT/'target/installed-disk-validation/162-result.json';next_result_bytes=next_result_path.read_bytes();next_result=json.loads(next_result_bytes)
assert next_result['exit_code']==0 and next_result['drained'] and next_result['inventoried_source_unchanged']
observed_before,special_before=scan(ROOT/'vendor');expected={'patch-manifest.json'};inventories=[]
for inv in manifest['inventories']:
    prefix=Path(inv['path']).relative_to('vendor').as_posix()+'/'
    actual={p[len(prefix):]:v for p,v in observed_before.items() if p.startswith(prefix)};wanted=inv['files'];changed=[];extra=[]
    for name in sorted(set(wanted)&set(actual)):
        if wanted[name]!=actual[name]:
            full=inv['path']+'/'+name
            classification='applied_payload_candidate_exactly_matches_frozen_patch_and_passed_run162_input' if payload_files.get(full)==actual[name]['sha256'] and next_source.get(full)==actual[name]['sha256'] else 'applied_release_code_exactly_matches_preserved_run161_source' if source.get(full)==actual[name]['sha256'] else 'disposition_document_update_after_run162' if name=='CHANGELOG.md' else 'disposition_document_update_after_run161' if name=='KASUMI_PATCH.md' else 'unexplained_drift'
            changed.append({'path':name,'expected':wanted[name],'actual':actual[name],'differences':[k for k in ('sha256','bytes','mode') if wanted[name][k]!=actual[name][k]],'classification':classification,'matches_run161':source.get(full)==actual[name]['sha256'],'matches_run162_input':next_source.get(full)==actual[name]['sha256'],'matches_frozen_payload_patch':payload_files.get(full)==actual[name]['sha256']})
    for name in sorted(set(actual)-set(wanted)):
        full=inv['path']+'/'+name
        extra.append({'path':name,'actual':actual[name],'classification':'applied_payload_addition_exactly_matches_frozen_patch_and_passed_run162_input' if payload_files.get(full)==actual[name]['sha256'] and next_source.get(full)==actual[name]['sha256'] else 'applied_release_addition_exactly_matches_preserved_run161_source' if source.get(full)==actual[name]['sha256'] else 'unexplained_unexpected_file','matches_run161':source.get(full)==actual[name]['sha256'],'matches_run162_input':next_source.get(full)==actual[name]['sha256'],'matches_frozen_payload_patch':payload_files.get(full)==actual[name]['sha256']})
    review=inv.get('review');review_audit=None
    if review:
        evidence=(ROOT/review['path']).read_bytes();e=json.loads(evidence);review_audit={'record':review,'evidence_sha256_actual':sha(evidence),'evidence_hash_matches':sha(evidence)==review['sha256']}
        if review['kind']=='redb-provenance':
            original={x['path']:x['fork_sha256'] for x in e['files'] if x['fork_sha256'] is not None}
            review_audit['manifest_matches_original_review']={p:x['sha256'] for p,x in wanted.items()}==original and inv['published_crate_sha256']==e['published_crate_sha256']
        else:
            evidence2=(ROOT/review['inventory_path']).read_bytes();items=json.loads(evidence2);original={x['path']:{k:x[k] for k in ('sha256','bytes','mode')} for x in items}
            review_audit['inventory_sha256_actual']=sha(evidence2);review_audit['inventory_hash_matches']=sha(evidence2)==review['inventory_sha256'];review_audit['manifest_matches_original_review']=wanted==original and e['source_inventory_sha256']==review['inventory_sha256'] and e['source_files']==len(items) and e['source_bytes']==sum(x['bytes'] for x in items) and str(Path(review['path']).parent/e['source_inventory'])==review['inventory_path']
    inventories.append({'path':inv['path'],'packages':inv['packages'],'expected_count':len(wanted),'actual_count':len(actual),'changed':changed,'missing':sorted(set(wanted)-set(actual)),'unexpected':extra,'review':review_audit})
    expected.update(prefix+name for name in wanted)
support=[]
for name,wanted in manifest['support_files'].items():
    actual=observed_before.get(name);support.append({'path':'vendor/'+name,'expected':wanted,'actual':actual,'matches':actual==wanted});expected.add(name)
observed_after,special_after=scan(ROOT/'vendor')
assert observed_before==observed_after and special_before==special_after,'vendor changed during final audit'
assert manifest_path.read_bytes()==manifest_bytes and source_path.read_bytes()==source_bytes and result_path.read_bytes()==result_bytes
assert next_source_path.read_bytes()==next_source_bytes and payload_path.read_bytes()==payload_bytes and applied_path.read_bytes()==applied_bytes and next_result_path.read_bytes()==next_result_bytes
report={'status':'read_only_inventory_audit_no_release_manifest_update_no_Cargo','root':str(ROOT),'branch':'master','time_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'python_version':sys.version,'manifest_sha256':sha(manifest_bytes),'checker_sha256':sha((ROOT/'scripts/check_dependency_patches.py').read_bytes()),'run161_source_path':str(source_path.relative_to(ROOT)),'run161_source_sha256':sha(source_bytes),'run161_result_path':str(result_path.relative_to(ROOT)),'run161_result_sha256':sha(result_bytes),'run162_source_path':str(next_source_path.relative_to(ROOT)),'run162_source_sha256':sha(next_source_bytes),'payload_manifest_sha256':sha(payload_bytes),'payload_patch_sha256':payload['patch_sha256'],'payload_applied_receipt_sha256':sha(applied_bytes),'run162_result_status':'completed exit0; source unchanged and process group drained per preserved result','run162_result_path':str(next_result_path.relative_to(ROOT)),'run162_result_sha256':sha(next_result_bytes),'inventories':inventories,'vendor_support_files':support,'vendor_missing':sorted(expected-set(observed_before)),'vendor_unexpected':sorted(set(observed_before)-expected),'vendor_special':special_before,'vendor_stable_across_final_scan':True,'checker_execution':'not executed: its normal entry point invokes Cargo metadata; audited source inventory logic with Python only','selection_verification':'Cargo resolver selection not evaluated in this inventory-only audit','notes':['Thirty earlier redb Rust/source test differences still exactly match preserved run161 bytes; five payload files match the frozen applied patch and run162 input inventory.','KASUMI_PATCH.md and vendor/README.md are intentional completed disposition documentation updates reported by parent; CHANGELOG.md adds three release-note bullets after run162; final double-scan is stable.','vendor/README.md now explicitly identifies the original 97-file import and the need to refresh inventory for later source; its recorded support hash is stale.','Original redb provenance and OpenRaft checkpoint/inventory still exactly match their manifest review references.']}
(OUT/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'report_sha256':sha((OUT/'report.json').read_bytes()),'inventories':[{'path':i['path'],'changed':len(i['changed']),'missing':len(i['missing']),'unexpected':len(i['unexpected'])} for i in inventories],'support_matches':all(x['matches'] for x in support),'special':len(special_before)},indent=2))
