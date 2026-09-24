from pathlib import Path
import datetime,difflib,hashlib,json,re,subprocess
ROOT=Path('/Users/mtakemiya/dev/kasumi')
PKG=ROOT/'target/installed-disk-validation/redb-allocator-encoded-lengths'
assert Path.cwd().resolve()==ROOT
assert subprocess.check_output(['git','branch','--show-current'],text=True).strip()=='master'
assert not (PKG/'manifest.json').exists(), 'Package already frozen'
sha=lambda data:hashlib.sha256(data).hexdigest()
def bodies(source,name):
    result=[]
    for match in re.finditer(r'\bfn '+name+r'\s*\(',source):
        begin=source.index('{',match.end());depth=1;end=begin+1
        while depth:
            depth+=int(source[end]=='{')-int(source[end]=='}');end+=1
        result.append(source[match.start():end].encode())
    return result
rows=[];patch=[];preservation=[]
for base in sorted((PKG/'base').rglob('*.rs')):
    rel=base.relative_to(PKG/'base');proposed=PKG/'proposed'/rel;actual=ROOT/rel
    before=base.read_bytes();after=proposed.read_bytes()
    assert actual.read_bytes()==before, str(rel)+' base drift'
    rows.append({'path':str(rel),'base_sha256':sha(before),'proposed_sha256':sha(after),'base_bytes':len(before),'proposed_bytes':len(after)})
    patch.extend(difflib.unified_diff(before.decode().splitlines(keepends=True),after.decode().splitlines(keepends=True),fromfile='a/'+str(rel),tofile='b/'+str(rel)))
    for name in ['to_vec','from_bytes']:
        old=bodies(before.decode(),name);new=bodies(after.decode(),name)
        assert old==new, str(rel)+' changed '+name
        if old:
            preservation.append({'path':str(rel),'function':name,'body_sha256':[sha(x) for x in old],'unchanged':True})
patch_bytes=''.join(patch).encode();(PKG/'encoded-lengths.patch').write_bytes(patch_bytes)
checks=[]
rustfmt='/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustfmt'
for label,argv in [('target-rustfmt-check',[rustfmt,'--check','--edition','2024']+[str(PKG/'proposed'/x['path']) for x in rows]),('git-apply-check',['git','apply','--check',str(PKG/'encoded-lengths.patch')])]:
    proc=subprocess.run(argv,capture_output=True,text=True)
    (PKG/(label+'.log')).write_text(proc.stdout+proc.stderr)
    checks.append({'name':label,'argv':argv,'exit_code':proc.returncode,'log':label+'.log','log_sha256':sha((proc.stdout+proc.stderr).encode())})
    assert proc.returncode==0, label+' failed'
for row in rows:
    assert sha((ROOT/row['path']).read_bytes())==row['base_sha256'], row['path']+' changed during static validation'
design_paths=[
 'target/installed-disk-validation/redb-bounded-allocation-purge/README.md',
 'target/installed-disk-validation/redb-bounded-data-reclaim/README.md',
 'target/installed-disk-validation/redb-staging-workspace/workspace-derivation.md',
 'target/installed-disk-validation/redb-workspace-estimator/README.md',
 'vendor/redb-4.2.0/src/admission.rs',
 'vendor/redb-4.2.0/src/tree_store/page_store/base.rs',
 'vendor/redb-4.2.0/src/tree_store/page_store/layout.rs',
]
tests=[]
for row in rows:
    text=(PKG/'proposed'/row['path']).read_text()
    for name in re.findall(r'#\[test\]\s*fn (checked_\w+)\(',text):
        tests.append({'path':row['path'],'name':name,'status':'prepared-unexecuted'})
assert len(tests)==7, tests
manifest={
 'status':'target-only-not-applied-not-compiled-not-tested',
 'created_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'root':str(ROOT),'branch':'master','head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
 'files':rows,'patch':'encoded-lengths.patch','patch_sha256':sha(patch_bytes),
 'serializer_and_decoder_preservation':preservation,'prepared_tests':tests,'static_checks':checks,
 'supporting_source_and_design':[{'path':p,'sha256':sha((ROOT/p).read_bytes())} for p in design_paths],
 'readme_sha256':sha((PKG/'README.md').read_bytes()),
 'freeze_script_sha256':sha((PKG/'freeze.py').read_bytes()),
 'actual_source_unchanged_for_all_four_files':True,
 'limitations':['Existing per-region scalar Vec and corruption error backing remain allocating','Actual serializer buffers and full prepared allocator copy remain unchanged','Complete COW/workspace and RSS bounds remain open','Protected maintenance free-page and extension capacity remain open','No Cargo or native test executed'],
}
(PKG/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'package':str(PKG),'patch_sha256':sha(patch_bytes),'manifest_sha256':sha((PKG/'manifest.json').read_bytes()),'files':len(rows),'tests_prepared_unexecuted':len(tests),'static_checks':[(x['name'],x['exit_code']) for x in checks]},indent=2))
