from pathlib import Path
import gzip,hashlib,json,shutil,stat,subprocess
root=Path('/Users/mtakemiya/dev/kasumi');pkg=root/'target/installed-disk-validation/filesystem-backup-admission-revision5';native=pkg/'native-02';fmt=pkg/'format-02'
archive=root/'docs/evidence/installed-disk-filesystem-backup-20260923-rev5'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
record=lambda p:{'sha256':sha(p),'bytes':p.stat().st_size,'mode':oct(stat.S_IMODE(p.stat().st_mode))}
result=json.loads((native/'result.json').read_text());stages=json.loads((native/'results.json').read_text());format_result=json.loads((fmt/'result.json').read_text());preflight=json.loads((native/'preflight.json').read_text())
assert result['all_passed'] and result['source_unchanged'] and result['binary_unchanged'] and result['compiled_artifacts_unchanged']
assert format_result['passed'] and len(stages)==5
assert stages[-1]['runtime_summary']==['343','0','2','0','0']
assert all(s['drained'] and not s['timeout'] and not s['signals'] for s in stages)
pgs=[s['pgid'] for s in stages]+[format_result['pgid']]
remaining=[]
for line in subprocess.check_output(['ps','-axo','pid=,ppid=,pgid=,command='],text=True).splitlines():
 x=line.split(None,3)
 if len(x)==4 and int(x[2]) in pgs:remaining.append(line)
assert not remaining,remaining
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
paths=[p for component in ['crates','vendor','tests'] for p in (root/component).rglob('*') if p.is_file()]+[root/n for n in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']]
actual={str(p.relative_to(root)):record(p) for p in paths}
assert actual==preflight['source_set'],'actual source changed since qualified preparation'
man=json.loads((pkg/'manifest.json').read_text());base=[]
for f in man['changes']:
 p=root/f['path'];current=sha(p) if p.exists() else None
 assert current==f['before_sha256'],f['path']
 assert sha(pkg/'proposed'/f['path'])==f['after_sha256']
 assert sha(native/'assembly'/f['path'])==f['after_sha256']
 base.append({'path':f['path'],'actual_before_sha256':current,'qualified_after_sha256':f['after_sha256']})
receipt={'status':'QUALIFIED THREE-FILE BACKUP CANDIDATE; NOT YET APPLIED; NOT RELEASE ACCEPTED','root':str(root),'branch':'master','head':head,'patch_sha256':sha(pkg/'adoption.patch'),'manifest_sha256':sha(pkg/'manifest.json'),'integration_manifest_sha256':preflight['integration_manifest_sha256'],'native_result_sha256':sha(native/'result.json'),'native_results_sha256':sha(native/'results.json'),'format_result_sha256':sha(fmt/'result.json'),'preflight_sha256':sha(native/'preflight.json'),'test_inventory':345,'passed':343,'failed':0,'ignored':2,'filtered':0,'native_elapsed_seconds':result['cohort_elapsed_seconds'],'native_bound_seconds':1200,'native_input_count':result['source_count'],'compiled_artifact_count':result['compiled_artifact_count'],'binary':result['compiled_binary'],'process_groups':pgs,'all_groups_absent':True,'actual_source_files':len(actual),'actual_source_set_unchanged':True,'actual_backup_bases':base,'format_preparation_failure_preserved':'format-01/preparation-failure.json','scope_limits':['Compiled dependency artifact bindings are not a complete external registry-source or full toolchain component inventory.','Two inherited tests remain ignored; no test was filtered or removed.','Opaque outcomes, whole-call workers/stacks/ciphertext, cache/RSS and complete constructor adoption remain separate open G02 requirements.','Configured-root/inherited directory closure and supported-filesystem physical bounds remain open.','The exact frozen candidate includes applied storage revision6 and these three backup files; it excludes ongoing failed-opening recovery and unapplied PageNumber migration.']}
(pkg/'terminal-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
archive.mkdir(parents=True,exist_ok=False)
records=[]
def add(src,relative):
 data=src.read_bytes();compress=len(data)>65536
 dst=archive/(relative+('.gz' if compress else ''));dst.parent.mkdir(parents=True,exist_ok=True)
 if compress:dst.write_bytes(gzip.compress(data,mtime=0))
 else:shutil.copy2(src,dst)
 records.append({'path':str(dst.relative_to(archive)),**record(dst),'source':str(src.relative_to(root)),'uncompressed_sha256':hashlib.sha256(data).hexdigest(),'uncompressed_bytes':len(data),'compression':'gzip' if compress else None})
for name in ['adoption.patch','manifest.json','expected-store-tests.json','qualification-plan.json','apply-readback.json','HANDOFF.md','runner-lineage.json','prepare_native_revision2.py','check_runner_gates_revision2.py','terminal-receipt.json','freeze_evidence.py']:
 add(pkg/name,'candidate/'+name)
for side in ['base','proposed']:
 for p in sorted((pkg/side).rglob('*')):
  if p.is_file():add(p,str(p.relative_to(pkg)))
for folder in ['native-02','format-01','format-02']:
 for p in sorted((pkg/folder).iterdir()):
  if p.is_file() and p.name not in ['store-test-binary','active.json']:
   add(p,folder+'/'+p.name)
for name in ['filesystem-backup-rev3-root-review/receipt.json','filesystem-backup-revision4-runner-independent-review/receipt.json','filesystem-backup-revision4-runner-independent-review/native-02/receipt.json','actual-application-storage-rev6/receipt.json']:
 add(root/'target/installed-disk-validation'/name,'reviews/'+name)
readme='''# Filesystem backup admission qualification

The exact three-file proposal is qualified against storage integration revision6 applied to master at the HEAD recorded in candidate/terminal-receipt.json. It has not been applied by this bundle and is not release acceptance.

Full workspace check and strict Clippy passed. The retained store binary listed exactly 345 expected tests, then passed all 343 runnable cases with the two inherited ignores and zero filtering. All five stages completed in 577.767 seconds within the original 1200-second bound. All 14,963 source/tool records and 1,112 compiled artifact bindings stayed unchanged. A separate pinned-toolchain full-workspace formatting check passed; its 14,966 inputs and store binary stayed unchanged. Every recorded process group was independently absent at bundle freeze.

The full native logs and inventories are included, with deterministic gzip for larger files. manifest.json binds the compressed bytes and the exact original uncompressed hash/size. The 54,831,152-byte executable remains in the target package and is represented here by its original compilation and dispatch hashes. External registry source trees and all toolchain components were not inventoried; compiled artifact stability is the narrower supported claim.

format-01 is a preserved source-inventory preparation failure: no native child was dispatched. format-02 explicitly includes both runner scripts and passes. The previously reviewed runner preparation failure and its corrected provenance gates are also retained. No failed trial was relabeled or overwritten.

The backup change admits the full pending inode/extent before creation, claims its physical name through classification and publication, preserves the original inode, and refuses existing pending/published names. Whole-call worker/ciphertext/stack and opaque outcome/cache/RSS admission, configured-root and inherited directory close, supported-filesystem bounds, and full registered constructor adoption remain open. The ongoing failed-opening recovery and PageNumber proposals are excluded from this candidate.
'''
(archive/'README.md').write_text(readme)
records.append({'path':'README.md',**record(archive/'README.md'),'source':None})
for f in records:
 p=archive/f['path'];assert sha(p)==f['sha256']
 if f.get('compression')=='gzip':
  data=gzip.decompress(p.read_bytes());assert len(data)==f['uncompressed_bytes'] and hashlib.sha256(data).hexdigest()==f['uncompressed_sha256']
manifest={'root':str(root),'status':receipt['status'],'payloads':records,'count':len(records),'terminal_receipt_sha256':sha(pkg/'terminal-receipt.json')}
(archive/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
# Re-read actual source after all additive evidence writes.
paths=[p for component in ['crates','vendor','tests'] for p in (root/component).rglob('*') if p.is_file()]+[root/n for n in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']]
assert {str(p.relative_to(root)):record(p) for p in paths}==preflight['source_set']
print(json.dumps({'archive':str(archive),'payloads':len(records),'manifest_sha256':sha(archive/'manifest.json'),'terminal_receipt_sha256':sha(pkg/'terminal-receipt.json'),'actual_source_files':len(actual),'process_groups_drained':pgs},indent=2))
