from pathlib import Path
import datetime,difflib,hashlib,json,re,subprocess
ROOT=Path('/Users/mtakemiya/dev/kasumi');PKG=ROOT/'target/installed-disk-validation/redb-canonical-allocator-keys'
assert Path.cwd().resolve()==ROOT
assert subprocess.check_output(['git','branch','--show-current'],text=True).strip()=='master'
assert not (PKG/'manifest.json').exists()
sha=lambda b:hashlib.sha256(b).hexdigest()
rows=[];patch=[];tests=[]
for proposed in sorted((PKG/'proposed').rglob('*.rs')):
 rel=proposed.relative_to(PKG/'proposed');base=PKG/'base'/rel;actual=ROOT/rel
 old=base.read_bytes() if base.exists() else b'';new=proposed.read_bytes()
 if base.exists(): assert actual.read_bytes()==old,str(rel)+' live base drift'
 else: assert not actual.exists(),str(rel)+' new source already exists'
 rows.append({'path':str(rel),'base_sha256':sha(old) if base.exists() else None,'proposed_sha256':sha(new),'base_bytes':len(old),'proposed_bytes':len(new)})
 patch.extend(difflib.unified_diff(old.decode().splitlines(keepends=True),new.decode().splitlines(keepends=True),fromfile='a/'+str(rel) if base.exists() else '/dev/null',tofile='b/'+str(rel)))
 if rel.name in ['allocator_state.rs','allocator_state_key_tests.rs']:
  tests.extend({'path':str(rel),'name':name,'status':'prepared-unexecuted'} for name in re.findall(r'#\[test\]\s*fn (\w+)\(',new.decode()))
assert len(rows)==6 and len(tests)==7
source=(PKG/'proposed/vendor/redb-4.2.0/src/transactions.rs').read_text()
assert 'Deprecated' not in source
assert '0..=2 =>' not in source
patch_bytes=''.join(patch).encode();(PKG/'canonical-keys.patch').write_bytes(patch_bytes)
checks=[];rustfmt='/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustfmt'
for label,argv in [('target-rustfmt-check',[rustfmt,'--check','--edition','2024','--config','skip_children=true']+[str(PKG/'proposed'/r['path']) for r in rows]),('git-apply-check',['git','apply','--check',str(PKG/'canonical-keys.patch')])]:
 proc=subprocess.run(argv,text=True,capture_output=True);log=proc.stdout+proc.stderr
 (PKG/(label+'.log')).write_text(log)
 checks.append({'name':label,'argv':argv,'exit_code':proc.returncode,'log_sha256':sha(log.encode())})
 assert proc.returncode==0,(label,log)
for row in rows:
 actual=ROOT/row['path']
 assert (sha(actual.read_bytes()) if actual.exists() else None)==row['base_sha256']
support=['vendor/redb-4.2.0/src/tree_store/btree.rs','vendor/redb-4.2.0/src/tree_store/btree_base.rs','vendor/redb-4.2.0/src/tree_store/table_tree.rs','vendor/redb-4.2.0/src/tree_store/page_store/base.rs','vendor/redb-4.2.0/src/tree_store/page_store/cached_file.rs','vendor/redb-4.2.0/src/types.rs','vendor/redb-4.2.0/src/error.rs','vendor/redb-4.2.0/src/page_list_tests.rs']
manifest={'status':'target-only-not-applied-not-compiled-not-tested','root':str(ROOT),'branch':'master','head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'created_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':rows,'patch':'canonical-keys.patch','patch_sha256':sha(patch_bytes),'prepared_tests':tests,'static_checks':checks,'supporting_sources':[{'path':p,'sha256':sha((ROOT/p).read_bytes())} for p in support],'readme_sha256':sha((PKG/'README.md').read_bytes()),'preparation_failures_sha256':sha((PKG/'preparation-failures.json').read_bytes()),'freeze_script_sha256':sha((PKG/'freeze.py').read_bytes()),'actual_source_unchanged':True,'remaining_limits':['Value::from_bytes remains an infallible internal interface behind mandatory input prevalidation','Buddy/tracker value payload and region-index/layout validation remain separate','Raw traversal cache/ancestor guards/stack are not total memory qualification','Opening-owner successor must compose narrow db entry-point and page_manager stamp hunks','No Cargo/native tests executed']}
(PKG/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'patch_sha256':sha(patch_bytes),'manifest_sha256':sha((PKG/'manifest.json').read_bytes()),'files':len(rows),'tests_prepared':len(tests),'static_checks':[(x['name'],x['exit_code']) for x in checks]},indent=2))
