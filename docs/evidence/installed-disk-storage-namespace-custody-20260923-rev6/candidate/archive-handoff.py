from pathlib import Path
import gzip,hashlib,json
root=Path('/Users/mtakemiya/dev/kasumi');area=root/'target/installed-disk-validation';pkg=area/'storage-namespace-custody-integration-revision6';out=root/'docs/evidence/installed-disk-storage-namespace-custody-20260923-rev6'
sha=lambda b:hashlib.sha256(b).hexdigest()
def read(p):return json.loads(p.read_text())
assert not out.exists(),out
out.mkdir(parents=True)
entries=[]
def add(src,rel=None):
 assert src.is_file(),src
 rel=rel or str(src.relative_to(area));raw=src.read_bytes();compressed=len(raw)>65536 and src.suffix in ['.json','.log','.patch','.txt'];target=out/(rel+('.gz' if compressed else ''));target.parent.mkdir(parents=True,exist_ok=True)
 data=gzip.compress(raw,compresslevel=9,mtime=0) if compressed else raw
 with target.open('xb') as f:f.write(data)
 entries.append({'archive_path':str(target.relative_to(out)),'archive_sha256':sha(data),'archive_bytes':len(data),'encoding':'gzip' if compressed else 'identity','source_path':str(src),'source_sha256':sha(raw),'source_bytes':len(raw)})
def generated(rel,data):
 raw=data.encode();target=out/rel;target.parent.mkdir(parents=True,exist_ok=True)
 with target.open('xb') as f:f.write(raw)
 entries.append({'archive_path':rel,'archive_sha256':sha(raw),'archive_bytes':len(raw),'encoding':'identity','source_path':None,'source_sha256':sha(raw),'source_bytes':len(raw)})
def tops(folder,prefix):
 for p in sorted(folder.iterdir()):
  if p.is_file() and p.name!='store-test-binary':add(p,prefix+'/'+p.name)
# Exact candidate and complete native/format evidence; executable bytes stay retained in target.
for p in sorted(pkg.iterdir()):
 if p.is_file():add(p,'candidate/'+p.name)
tops(pkg/'native-01','native-01');tops(pkg/'format-01','format-01')
# All source-reviewed lineage manifests plus exact supplied patches, including failed predecessors.
manifest=read(pkg/'manifest.json')
for inp in manifest['inputs']:
 p=Path(inp['path']);assert sha(p.read_bytes())==inp['sha256'];base='lineage/'+str(p.parent.relative_to(area));add(p,base+'/manifest.json')
 for q in sorted(p.parent.glob('*.patch')):add(q,base+'/'+q.name)
# Original failure trials remain failed, with complete logs/selection/inventory/process provenance.
failures=[]
for rev in [2,3,4,5]:
 name='storage-namespace-custody-integration-revision'+str(rev);trial=area/name;receipt=area/(name+'-native01-failure-receipt.json')
 assert receipt.exists();add(receipt,'failed-trials/revision'+str(rev)+'/failure-receipt.json');tops(trial/'native-01','failed-trials/revision'+str(rev)+'/native-01')
 failures.append({'revision':rev,'manifest_path':str(trial/'manifest.json'),'manifest_sha256':sha((trial/'manifest.json').read_bytes()),'failure_receipt_sha256':sha(receipt.read_bytes()),'native_result_sha256':sha((trial/'native-01/result.json').read_bytes()),'status':'FAILED_PRESERVED_NOT_ACCEPTANCE'})
tops(area/'storage-namespace-custody-integration-revision5/format-diagnostic-01','failed-trials/revision5/format-diagnostic-01')
generated('failed-trials/index.json',json.dumps({'trials':failures,'revision5_format':'Diagnostic only on failed revision5; final format acceptance is current format-01.'},indent=2)+'\n')
# Independent reviews; their scoped statements and historical pending text remain byte-exact.
q=read(pkg/'qualification-receipt.json')
review_paths={Path(x['path']) for x in q['reviews']}
extra=area/'storage-namespace-custody-rev6-native-independent-review/receipt.json'
assert extra.exists(),extra
review_paths.add(extra)
for p in sorted(review_paths):add(p,'reviews/'+str(p.relative_to(area)))
# Prior 17-test Python validation binds unchanged scripts, with its original conservative runner acceptance.
prior=area/'storage-and-namespace-integration-revision6'
for n in ['qualification-receipt.json','workspace-qualification-receipt.json','HANDOFF.md']:
 add(prior/n,'inherited-python/'+n)
for n in ['smoke-script-tests.log','smoke-script-tests-processes.json','python-version.log','python-version-processes.json','results.json','result.json','source-before.json','source-after.json','conservative-terminal-acceptance.json']:
 add(prior/'native-full-store'/n,'inherited-python/native-full-store/'+n)
readme='''# Storage, namespace and file custody prerequisite — revision 6

This immutable bundle qualifies the cumulative 75-file candidate for application to the exact recorded master bases. It does not complete the first release or G02. Actual Rust/Cargo source was unchanged during qualification and archive creation; root owns application.

The exact candidate passed all 19 native stages in 482.655 seconds under the original 1200-second bound: offline locked full-workspace all-target/all-feature check and strict Clippy, compilation of the store tests, exact 338-name inventory, all 14 focused regressions, and the unfiltered store suite (336 passed, zero failed, two existing ignored, zero filtered). Final workspace formatting passed separately in 2.362 seconds under a 120-second bound. All 3697 native and 3700 format source bindings remained unchanged. All owned process groups drained without timeouts or cleanup signals. The assembly-selected binary was freshly built and its retained hash stayed unchanged.

The two ignored cases are preserved original exclusions from direct execution in the main test harness: the externally configured MinIO live case and the crash-child subprocess helper. The latter can be invoked by its owning parent regression; the ignored count itself is not an execution claim. Check and Clippy cover the full workspace; runtime qualification here covers the store library only. The prior 17 Python smoke-script tests are inherited evidence bound to identical script bytes, not a new run on this candidate.

`candidate/qualification-receipt.json` and `native-01/results.json` are the terminal evidence. Original frozen manifests and review receipts retain their historical pending/failure wording. The terminal receipt supersedes only the pending runtime status of this exact candidate; it does not expand any review's scope. Revisions 2–5 remain failed and preserved in `failed-trials`, including revision 4's four failures and revision 5's two failures. Revision 5's format diagnostic is not final acceptance.

`archive-manifest.json` binds every payload, original absolute path, original SHA-256, stored SHA-256 and encoding. Large text files use deterministic gzip with mtime zero; decompress before applying the patch. The original retained executable remains under `target`, with its exact path, SHA-256, size, selection and before/after execution records preserved here. Executable bytes and build caches are deliberately omitted from this compact archive.

Verify the archive with `python3 verify.py`. Use `python3 verify.py --live-base` before applying, or `python3 verify.py --live-proposed` after root's application. These optional checks compare all 75 recorded paths and modes; the verifier never mutates source. The exact cumulative patch hash is 791f80c362c9ee0c317e0a46a4fedb26054e50a274aad0e735641e339737f2c9 and candidate manifest hash is b2d6f9f980a55d0e1a688093cf2deb64269878005ff78e15f394af8341b336e5.

Mandatory production StorageCensus and retained-opening caller migration, verified failed-owner disposal and original-outcome acknowledgement/recovery, original error/panic allocation backing, complete memory/RSS admission, configured-root/directory custody and supported-filesystem physical bounds remain open. In particular, legacy consuming NodeDatabase close can report Complete while physical FileOwner custody is retained. Indefinite retention is not release acceptance. See `candidate/integration-gaps.json` and the terminal qualification receipt. No compatibility or fallback path is introduced by this package.
'''
generated('README.md',readme)
verifier='''from pathlib import Path
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
'''
generated('verify.py',verifier)
archive={'schema':'kasumi-immutable-evidence-archive-v1','qualified_candidate_manifest_sha256':sha((pkg/'manifest.json').read_bytes()),'qualification_receipt_sha256':sha((pkg/'qualification-receipt.json').read_bytes()),'root':str(root),'branch':'master','status':'QUALIFIED_PREREQUISITE_NOT_RELEASE_ACCEPTANCE','files':sorted(entries,key=lambda e:e['archive_path']),'unarchived_binary':read(pkg/'native-01/store-binary-provenance.json'),'source_bundles_preserved':True,'archive_manifest_self_excluded':True}
with (out/'archive-manifest.json').open('x') as f:json.dump(archive,f,indent=2);f.write('\n')
print(json.dumps({'path':str(out),'archive_manifest_sha256':sha((out/'archive-manifest.json').read_bytes()),'payload_count':len(entries),'stored_bytes':sum(e['archive_bytes'] for e in entries),'source_bytes':sum(e['source_bytes'] for e in entries)},indent=2))
