from pathlib import Path
import copy,datetime,difflib,hashlib,json,os,re,shutil,stat,sys
ROOT=Path('/Users/mtakemiya/dev/kasumi');PKG=ROOT/'target/installed-disk-validation/redb-current-provenance-checkpoint';EVIDENCE=Path('docs/evidence/redb-current-source-20260922');DEST=PKG/'proposed'/EVIDENCE
assert Path.cwd()==ROOT and (ROOT/'.git/HEAD').read_text().strip()=='ref: refs/heads/master'
assert not (PKG/'manifest.json').exists()
sha=lambda b:hashlib.sha256(b).hexdigest()
def write_json(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2)+'\n')
def rec(path):
    s=path.lstat();assert stat.S_ISREG(s.st_mode),str(path)
    return {'sha256':sha(path.read_bytes()),'bytes':s.st_size,'mode':oct(stat.S_IMODE(s.st_mode))}
def inventory(directory):
    items={};pending=[directory]
    while pending:
        current=pending.pop()
        for entry in os.scandir(current):
            p=Path(entry.path);s=entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(s.st_mode):pending.append(p)
            else:items[p.relative_to(directory).as_posix()]=rec(p)
    return dict(sorted(items.items()))
original_path=Path('docs/evidence/redb-canonical-20260920/provenance.json');original_bytes=(ROOT/original_path).read_bytes();original=json.loads(original_bytes)
manifest_bytes=(ROOT/'vendor/patch-manifest.json').read_bytes();manifest=json.loads(manifest_bytes);old_inventory=next(x for x in manifest['inventories'] if x['path']=='vendor/redb-4.2.0');original_files={x['path']:x for x in original['files']}
assert old_inventory['review']=={'kind':'redb-provenance','path':str(original_path),'sha256':sha(original_bytes)}
current=inventory(ROOT/'vendor/redb-4.2.0');vendor_before=inventory(ROOT/'vendor');assert len(current)==109
support_updates={name:rec(ROOT/'vendor'/name) for name,expected in manifest['support_files'].items() if rec(ROOT/'vendor'/name)!=expected}
assert set(support_updates)=={'README.md'}
DEST.mkdir(parents=True,exist_ok=True)
# Retain a complete current source snapshot in the target package for independent
# readback. It is not installed in vendor or added to the future docs evidence.
for name,record in current.items():
    out=PKG/'current-source'/name;out.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/'vendor/redb-4.2.0'/name,out);assert rec(out)==record
bindings=[];path_bindings={}
def bind(source,category,bundle):
    raw=(ROOT/source).read_bytes();relative=Path('bindings')/bundle/Path(source).name;out=DEST/relative;out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(raw)
    item={'id':str(relative),'original_repository_path':str(source),'path':str(EVIDENCE/relative),'sha256':sha(raw),'bytes':len(raw),'category':category};bindings.append(item)
    if str(source).endswith('.patch'):
        for file in re.findall(r'^\+\+\+ b/vendor/redb-4\.2\.0/(.+)$',raw.decode(),re.M):path_bindings.setdefault(file,[]).append(item['id'])
    return item
for file in ['provenance.json','published-to-fork.patch','README.md','owned-verification.json','owned-evidence.json']:
    bind(original_path.parent/file,'immutable_original_import_evidence','canonical-import')
packages=['redb-retained-terminal','redb-retained-database-close-revision2','redb-page-list-prerequisites','redb-page-list-key-copy-followup','redb-bounded-data-reclaim','redb-bounded-allocation-purge','redb-fixed-cache-capacity-revision2','redb-fixed-cache-clean-close-followup','redb-fixed-cache-metadata-components','redb-allocator-encoded-lengths','redb-allocator-in-place-encoding','retained-opening-owner-revision3','redb-canonical-allocator-keys-opening-composed','redb-allocator-payload-shapes']
reviews=['redb-retained-terminal-independent-review','redb-retained-database-close-revision2-authority-review','redb-page-list-prerequisites-root-review','redb-page-list-prerequisites-authority-review','redb-bounded-data-reclaim-root-review','redb-bounded-allocation-purge-independent-review','redb-fixed-cache-capacity-revision2-authority-review','redb-allocator-encoded-lengths-root-review','redb-allocator-in-place-independent-review','retained-opening-owner-revision2-independent-review','redb-canonical-allocator-keys-root-review','redb-allocator-payload-shapes-root-review']
for name in packages+reviews:
    directory=ROOT/'target/installed-disk-validation'/name
    for p in sorted(directory.iterdir()):
        if p.is_file() and (p.suffix in {'.patch','.md'} or p.name in {'manifest.json','receipt.json','evidence.json','source-checks.json'}):
            bind(p.relative_to(ROOT),'historical_scoped_patch_or_review',name)
for name in ['156-retained-opening-applied.json','157-canonical-allocator-keys-applied.json','162-allocator-payload-shapes-applied.json']:
    bind(Path('target/installed-disk-validation')/name,'root_applied_patch_receipt','applied-receipts')
tests=[]
for run in [157,158,159,160,161,162,163,164]:
    base=ROOT/'target/installed-disk-validation';result_path=base/(str(run)+'-result.json');result=json.loads(result_path.read_text());assert result['exit_code']==0 and result['drained'] and result['inventoried_source_unchanged']
    artifacts=[]
    for p in sorted(base.glob(str(run)+'-*')):
        if p.is_file() and (p.name.endswith('-result.json') or p.name.endswith('-source-before.json') or p.name.endswith('-source-after.json') or p.suffix=='.log' or p.name.endswith('-phases.json')):
            artifacts.append(bind(p.relative_to(ROOT),'completed_source_specific_component_gate','run-'+str(run)))
    before=json.loads((base/(str(run)+'-source-before.json')).read_text());after=json.loads((base/(str(run)+'-source-after.json')).read_text());assert before==after
    tests.append({'attempt':run,'result':result,'artifacts':[x['id'] for x in artifacts],'current_redb_source_matches':sorted(name for name,v in current.items() if before.get('vendor/redb-4.2.0/'+name)==v['sha256']),'current_redb_source_different':sorted(name for name,v in current.items() if 'vendor/redb-4.2.0/'+name in before and before['vendor/redb-4.2.0/'+name]!=v['sha256']),'not_in_gate_source_inventory':sorted(name for name in current if 'vendor/redb-4.2.0/'+name not in before)})
# Only current source tests/Clippy are source-equivalent. Earlier passing attempts
# are preserved as historical evidence, never promoted to current-source passes.
assert not tests[-1]['current_redb_source_different'] and not tests[-2]['current_redb_source_different']
entries=[];changes=[]
for name in sorted(set(original_files)|set(current)):
    prior=original_files.get(name);now=current.get(name);entry=copy.deepcopy(prior) if prior else {'path':name,'published_sha256':None}
    entry['prior_canonical_fork_sha256']=prior['fork_sha256'] if prior else None
    entry['fork_sha256']=now['sha256'] if now else None;entry['fork_bytes']=now['bytes'] if now else None;entry['fork_mode']=now['mode'] if now else None
    entry['status']='removed' if now is None else 'added' if entry['published_sha256'] is None else 'unchanged' if entry['published_sha256']==now['sha256'] else 'modified'
    changed=entry['fork_sha256']!=entry['prior_canonical_fork_sha256'];entry['checkpoint_change']='unchanged' if not changed else 'removed' if now is None else 'added' if not prior or prior['fork_sha256'] is None else 'modified'
    entry['review_history_bindings']=sorted(set(path_bindings.get(name,[]))) if changed else ['bindings/canonical-import/provenance.json']
    if changed:
        entry['current_source_gate_binding']='run-162-and-run-163-and-run-164' if name.endswith('.rs') else 'root-reviewed-disposition-documents-pending-checkpoint-review'
        changes.append({'path':name,'prior':old_inventory['files'].get(name),'current':now,'classification':entry['checkpoint_change'],'review_history_bindings':entry['review_history_bindings']})
    entries.append(entry)
assert sum(x['fork_sha256'] is not None for x in entries)==109 and len(entries)==111
source_inventory=[{'path':name,**value} for name,value in current.items()];write_json(DEST/'source-inventory.json',source_inventory);write_json(DEST/'changes-since-import.json',changes);write_json(DEST/'evidence-bindings.json',{'status':'review-history-and-component-tests-not-release-acceptance','bindings':bindings,'tests':tests})
provenance={k:v for k,v in original.items() if k!='files'}
provenance['checkpoint']={'status':'proposed-current-source-checkpoint-pending-root-review-not-release-acceptance','repository':'/Users/mtakemiya/dev/kasumi','branch':'master','created_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'original_provenance':{'path':str(original_path),'sha256':sha(original_bytes)},'source_inventory':{'path':str(EVIDENCE/'source-inventory.json'),'sha256':sha((DEST/'source-inventory.json').read_bytes()),'files':len(current),'bytes':sum(v['bytes'] for v in current.values())},'changes_since_import':{'path':str(EVIDENCE/'changes-since-import.json'),'sha256':sha((DEST/'changes-since-import.json').read_bytes())},'review_and_test_bindings':{'path':str(EVIDENCE/'evidence-bindings.json'),'sha256':sha((DEST/'evidence-bindings.json').read_bytes())},'limitations':['Historical review receipts approve their own scoped patches, not the entire current checkpoint.','Current source has run162 unit, run163 strict vendor Clippy and run164 ten-target public integration passes; these component results are not release acceptance.','Mandatory production custody/census, exact maintenance reserve, complete ownership correspondence and total memory remain open.','Upstream container, audit and fuzz workflows are not passed; this is not release acceptance.']}
provenance['files']=entries;write_json(DEST/'provenance.json',provenance)
new_inventory=copy.deepcopy(old_inventory);new_inventory['files']=current;new_inventory['review']={'kind':'redb-provenance','path':str(EVIDENCE/'provenance.json'),'sha256':sha((DEST/'provenance.json').read_bytes())};write_json(PKG/'redb-inventory-candidate.json',new_inventory);write_json(PKG/'vendor-support-candidate.json',support_updates)
new_manifest=copy.deepcopy(manifest);new_manifest['inventories']=[new_inventory if x['path']=='vendor/redb-4.2.0' else x for x in manifest['inventories']];new_manifest['support_files'].update(support_updates);write_json(PKG/'proposed/vendor/patch-manifest.json',new_manifest)
assert inventory(ROOT/'vendor')==vendor_before and (ROOT/'vendor/patch-manifest.json').read_bytes()==manifest_bytes and (ROOT/original_path).read_bytes()==original_bytes
write_json(PKG/'preparation.json',{'status':'target-only-provenance-inventory-candidate','original_manifest_sha256':sha(manifest_bytes),'original_provenance_sha256':sha(original_bytes),'current_vendor':vendor_before,'files':len(current),'provenance_rows':len(entries),'changes':len(changes),'bindings':len(bindings),'candidate_manifest_sha256':sha((PKG/'proposed/vendor/patch-manifest.json').read_bytes()),'provenance_sha256':sha((DEST/'provenance.json').read_bytes()),'no_actual_source_or_manifest_mutation':True})
print(json.dumps({'files':len(current),'provenance_rows':len(entries),'changed_or_added_since_import':len(changes),'evidence_bindings':len(bindings),'provenance_sha256':sha((DEST/'provenance.json').read_bytes())},indent=2))
