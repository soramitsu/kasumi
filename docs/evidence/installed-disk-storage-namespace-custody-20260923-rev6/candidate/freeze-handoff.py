from pathlib import Path
import datetime,gzip,hashlib,json,re,subprocess
root=Path('/Users/mtakemiya/dev/kasumi'); area=root/'target/installed-disk-validation'; pkg=area/'storage-namespace-custody-integration-revision6'; native=pkg/'native-01'; fmt=pkg/'format-01'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text())
def write_new(p,d):
 with p.open('x') as f:json.dump(d,f,indent=2);f.write('\n')
def bind(p):return {'path':str(p),'sha256':sha(p),'bytes':p.stat().st_size}
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
m=read(pkg/'manifest.json');results=read(native/'results.json');nr=read(native/'result.json');fr=read(fmt/'result.json')
assert nr['all_passed'] and fr['all_passed'] and nr['source_unchanged'] and fr['source_unchanged']
assert len(results)==19 and nr['cohort_elapsed_seconds']<1200 and fr['elapsed_seconds']<120
for r in results+[fr]:assert r['exit_code']==0 and not r['timeout'] and not r['signals'] and r['drained'] and not r['remaining_processes']
assert read(native/'source-before.json')==read(native/'source-after.json')
assert read(fmt/'source-before.json')==read(fmt/'source-after.json')
for path,entry in read(fmt/'source-after.json').items():assert sha(Path(path))==entry['sha256'],path
for f in m['files']:
 for where,key in [(root,'before'),(pkg/'proposed','after'),(pkg/'apply-readback','after'),(pkg/'assembly','after')]:
  path=where/f['path']; assert (sha(path) if path.exists() else None)==f[key],str(path)
inv=read(native/'store-inventory-proof.json'); assert inv['required_count']==inv['actual_count']==338 and not inv['missing'] and not inv['extra']
store_summary=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', (native/'store-full.log').read_text())
assert store_summary[-1]==('336','0','2','0','0')
for r in results:
 if r['name'].startswith('focused-'):assert re.search(r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 337 filtered out;',Path(r['log']).read_text())
binary=read(native/'store-binary-provenance.json');assert not binary['selected']['fresh'];assert sha(Path(binary['retained_path']))==binary['sha256']
groups={92304,fr['pgid']}|{r['pgid'] for r in results}; ps=subprocess.check_output(['ps','-axo','pid=,ppid=,pgid=,stat=,command='],text=True)
left=[s for s in ps.splitlines() if len(s.split())>=3 and int(s.split()[2]) in groups];assert not left,left
subprocess.run(['git','apply','--check',str(pkg/'combined.patch')],cwd=root,check=True)
terminal={'schema':'kasumi-composed-candidate-terminal-drain-v1','checked_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'groups':sorted(groups),'remaining_processes':left,'native':bind(native/'result.json'),'format':bind(fmt/'result.json'),'all_source_bindings_rehashed':3700,'actual_bases_verified':75,'proposed_readback_assembly_hashes_verified':75,'patch_apply_check_exit':0,'binary':bind(Path(binary['retained_path']))}
write_new(pkg/'terminal-drain.json',terminal)
reviews=[
'storage-namespace-custody-rev6-root-review/receipt.json',
'storage-namespace-custody-rev5-root-review/receipt.json',
'storage-namespace-custody-rev4-root-review/receipt.json',
'storage-namespace-custody-rev3-root-review/receipt.json',
'storage-namespace-custody-root-review/receipt.json',
'storage-namespace-custody-overlap-managed-review/receipt.json',
'storage-namespace-custody-overlap-managed-review/revision2-receipt.json',
'storage-custody-revision3-lint-independent-review/receipt.json',
'file-explicit-close-managed-review/receipt.json',
'file-explicit-close-revision5-composition-review/receipt.json',
'file-explicit-close-revision5-composition-review/inventory-readback.json',
'audit-archive-custody-fixture-opening-review/receipt.json',
'combined-store-runner-and-revision6-independent-review/initial-review.json',
'combined-store-runner-and-revision6-independent-review/revision3-review.json']
for name in reviews:assert (area/name).exists(),name
prior=area/'storage-and-namespace-integration-revision6';priorinv=read(prior/'native-full-store/source-after.json');python_bindings=[]
for rel in ['scripts/small_native_smoke.py','scripts/test_small_native_smoke.py']:
 found=[(p,x) for p,x in priorinv.items() if p.endswith('/'+rel) and '/assembly/' in p]
 if found:
  oldpath,entry=found[0];new=pkg/'assembly'/rel;assert sha(new)==entry['sha256'];python_bindings.append({'path':rel,'prior_qualified_path':oldpath,'sha256':entry['sha256'],'current_candidate':str(new)})
receipt={'schema':'kasumi-composed-storage-namespace-custody-qualification-v1','status':'QUALIFIED_PREREQUISITE_READY_FOR_ROOT_APPLICATION','root':str(root),'branch':'master','head':m['head'],'source_file_count':75,'patch':bind(pkg/'combined.patch'),'manifest':bind(pkg/'manifest.json'),'apply_readback':bind(pkg/'apply-readback.json'),'changed_paths':bind(pkg/'changed-paths.json'),'native':nr,'format':fr,'store_tests':{'inventory':338,'passed':336,'failed':0,'existing_ignored':2,'filtered':0,'focused_exact_cases_passed':14},'binary':binary,'native_results':bind(native/'results.json'),'terminal_drain':bind(pkg/'terminal-drain.json'),'reviews':[bind(area/n) for n in reviews],'prior_python_validation':{'status':'INHERITED_SOURCE_IDENTICAL_NOT_RERUN','qualified_package':str(prior),'smoke_tests_log':bind(prior/'native-full-store/smoke-script-tests.log'),'bindings':python_bindings},'application':{'actual_Rust_Cargo_source_modified':False,'authorized_next_actor':'root','patch_apply_check_exit':0,'requires_exact_before_hashes':True},'remaining_gaps':read(pkg/'integration-gaps.json')['gaps'],'scope':'Workspace check/lint, store unit cohort and formatting qualify this 75-file prerequisite. No claim that G02 caller migration, failed-owner recovery, release contract, full workspace runtime or memory/RSS bounds are complete. Frozen manifests retain pre-run pending text; this receipt records subsequent qualification without rewriting them.'}
write_new(pkg/'qualification-receipt.json',receipt)
print(json.dumps({'terminal_drain':bind(pkg/'terminal-drain.json'),'qualification':bind(pkg/'qualification-receipt.json'),'python_bindings':python_bindings},indent=2))
