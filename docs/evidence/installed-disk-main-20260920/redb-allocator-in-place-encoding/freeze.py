from pathlib import Path
import datetime,difflib,hashlib,json,re,subprocess
ROOT=Path('/Users/mtakemiya/dev/kasumi')
PKG=ROOT/'target/installed-disk-validation/redb-allocator-in-place-encoding'
PREREQ=ROOT/'target/installed-disk-validation/redb-allocator-encoded-lengths'
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
        result.append(source[match.start():end])
    return result
norm=lambda source:re.sub(r'\s+','',source)
assert sha((PREREQ/'encoded-lengths.patch').read_bytes())=='055fc2a64f3477a0dc6d6e5a1a086afbf2f5df521ebd863936b60c82bf46a7d3'
assert sha((PREREQ/'manifest.json').read_bytes())=='4c29b812846a4e39b09f58eba58b27d7b52c1c3b31c7d67cf37f98a2f58a37e7'
rows=[];patch=[];preservation=[];references=[];tests=[]
for base in sorted((PKG/'base').rglob('*.rs')):
    rel=base.relative_to(PKG/'base');proposed=PKG/'proposed'/rel;actual=ROOT/rel
    before=base.read_bytes();after=proposed.read_bytes()
    assert (PREREQ/'proposed'/rel).read_bytes()==before, str(rel)+' prerequisite mismatch'
    assert actual.read_bytes()==before, str(rel)+' live base drift'
    rows.append({'path':str(rel),'base_sha256':sha(before),'proposed_sha256':sha(after),'base_bytes':len(before),'proposed_bytes':len(after)})
    patch.extend(difflib.unified_diff(before.decode().splitlines(keepends=True),after.decode().splitlines(keepends=True),fromfile='a/'+str(rel),tofile='b/'+str(rel)))
    for name in ['from_bytes','xxh3_hash','checked_encoded_len','checked_offset_encoded_len','checked_length_encoded_len']:
        old=bodies(before.decode(),name);new=bodies(after.decode(),name)
        assert old==new, str(rel)+' changed '+name
        if old:
            preservation.append({'path':str(rel),'function':name,'body_sha256':[sha(x.encode()) for x in old],'unchanged':True})
    old=bodies(before.decode(),'to_vec');refs=bodies(after.decode(),'reference_to_vec')
    assert len(old)==len(refs),(rel,'reference count')
    for i,(original,reference) in enumerate(zip(old,refs)):
        restored=reference.replace('reference_to_vec','to_vec')
        assert norm(original)==norm(restored),(rel,'reference tokens differ',i)
        references.append({'path':str(rel),'ordinal':i,'original_body_sha256':sha(original.encode()),'reference_body_sha256':sha(reference.encode()),'normalized_original_tokens_sha256':sha(norm(original).encode()),'only_names_and_format_differ':True})
    for name in re.findall(r'#\[test\]\s*fn (in_place_\w+)\(',after.decode()):
        tests.append({'path':str(rel),'name':name,'status':'prepared-unexecuted'})
assert len(rows)==3 and len(tests)==7
patch_bytes=''.join(patch).encode();(PKG/'encoding.patch').write_bytes(patch_bytes)
checks=[]
rustfmt='/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustfmt'
for label,argv in [('target-rustfmt-check',[rustfmt,'--check','--edition','2024']+[str(PKG/'proposed'/x['path']) for x in rows]),('git-apply-check',['git','apply','--check',str(PKG/'encoding.patch')])]:
    proc=subprocess.run(argv,capture_output=True,text=True)
    (PKG/(label+'.log')).write_text(proc.stdout+proc.stderr)
    checks.append({'name':label,'argv':argv,'exit_code':proc.returncode,'log':label+'.log','log_sha256':sha((proc.stdout+proc.stderr).encode())})
    assert proc.returncode==0,label+' failed'
for row in rows:
    assert sha((ROOT/row['path']).read_bytes())==row['base_sha256'],row['path']+' changed during static validation'
support=['vendor/redb-4.2.0/src/lib.rs','vendor/redb-4.2.0/src/tree_store/page_store/page_manager.rs','vendor/redb-4.2.0/src/admission.rs','target/installed-disk-validation/redb-bounded-allocation-purge/README.md']
manifest={
 'status':'target-only-not-applied-not-compiled-not-tested',
 'created_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'root':str(ROOT),'branch':'master','head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
 'prerequisite':{'package':str(PREREQ.relative_to(ROOT)),'patch_sha256':sha((PREREQ/'encoded-lengths.patch').read_bytes()),'manifest_sha256':sha((PREREQ/'manifest.json').read_bytes())},
 'files':rows,'patch':'encoding.patch','patch_sha256':sha(patch_bytes),
 'unchanged_helpers_decoders_checksums':preservation,'original_reference_serializer_equivalence':references,
 'prepared_tests':tests,'static_checks':checks,
 'supporting_sources':[{'path':p,'sha256':sha((ROOT/p).read_bytes())} for p in support],
 'readme_sha256':sha((PKG/'README.md').read_bytes()),
 'preparation_scripts':[{'path':p,'sha256':sha((PKG/p).read_bytes())} for p in ['implement.py','add-tests.py','freeze.py']],
 'actual_source_unchanged_for_all_three_files':True,
 'limitations':['Existing infallible internal to_vec panic boundary retained','Final output and full prepared allocator decoding/copy remain','Complete COW/workspace and RSS bounds remain open','Protected maintenance allocator-page and extension capacity remain open','No Cargo or native test executed']
}
(PKG/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'package':str(PKG),'patch_sha256':sha(patch_bytes),'manifest_sha256':sha((PKG/'manifest.json').read_bytes()),'files':len(rows),'tests_prepared_unexecuted':len(tests),'static_checks':[(x['name'],x['exit_code']) for x in checks]},indent=2))
