from pathlib import Path
import datetime,difflib,hashlib,json,re,subprocess
ROOT=Path('/Users/mtakemiya/dev/kasumi');PKG=ROOT/'target/installed-disk-validation/redb-allocator-payload-shapes'
assert Path.cwd().resolve()==ROOT
assert subprocess.check_output(['git','branch','--show-current'],text=True).strip()=='master'
assert not (PKG/'manifest.json').exists()
sha=lambda b:hashlib.sha256(b).hexdigest()
rows=[];patch=[];newtests=[]
for proposed in sorted((PKG/'proposed').rglob('*.rs')):
 rel=proposed.relative_to(PKG/'proposed');base=PKG/'base'/rel;actual=ROOT/rel
 before=base.read_bytes() if base.exists() else b'';after=proposed.read_bytes()
 assert actual.exists()==base.exists(),str(rel)
 assert not actual.exists() or actual.read_bytes()==before,str(rel)+' live base drift'
 rows.append({'path':str(rel),'base_sha256':sha(before) if base.exists() else None,'proposed_sha256':sha(after),'base_bytes':len(before),'proposed_bytes':len(after)})
 patch.extend(difflib.unified_diff(before.decode().splitlines(keepends=True),after.decode().splitlines(keepends=True),fromfile='a/'+str(rel) if base.exists() else '/dev/null',tofile='b/'+str(rel)))
 oldtests=set(re.findall(r'#\[test\]\s*fn (\w+)\(',before.decode()))
 newtests.extend({'path':str(rel),'name':name,'status':'prepared-unexecuted'} for name in re.findall(r'#\[test\]\s*fn (\w+)\(',after.decode()) if name not in oldtests)
assert len(rows)==5 and len(newtests)==7
patch_bytes=''.join(patch).encode();(PKG/'payload-shapes.patch').write_bytes(patch_bytes)
checks=[];rustfmt='/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustfmt'
for label,argv in [('target-rustfmt-check',[rustfmt,'--check','--edition','2024','--config','skip_children=true']+[str(PKG/'proposed'/r['path']) for r in rows]),('git-apply-check',['git','apply','--check',str(PKG/'payload-shapes.patch')])]:
 proc=subprocess.run(argv,text=True,capture_output=True);log=proc.stdout+proc.stderr
 (PKG/(label+'.log')).write_text(log)
 checks.append({'name':label,'argv':argv,'exit_code':proc.returncode,'log_sha256':sha(log.encode())})
 assert proc.returncode==0,(label,log)
for row in rows:
 actual=ROOT/row['path'];assert (sha(actual.read_bytes()) if actual.exists() else None)==row['base_sha256']
support=['vendor/redb-4.2.0/src/tree_store/page_store/bitmap.rs','vendor/redb-4.2.0/src/tree_store/page_store/buddy_allocator.rs','vendor/redb-4.2.0/src/tree_store/page_store/region.rs','vendor/redb-4.2.0/src/tree_store/page_store/layout.rs','vendor/redb-4.2.0/src/tree_store/page_store/header.rs','vendor/redb-4.2.0/src/tree_store/btree_base.rs','vendor/redb-4.2.0/src/db.rs','vendor/redb-4.2.0/src/transactions.rs','vendor/redb-4.2.0/src/retained_opening.rs']
manifest={'status':'target-only-not-applied-not-compiled-not-tested','root':str(ROOT),'branch':'master','head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'created_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':rows,'patch':'payload-shapes.patch','patch_sha256':sha(patch_bytes),'prepared_new_tests':newtests,'strengthened_existing_test':'allocator_raw_walk_rejects_bad_branch_separator_and_cycle_without_comparison now also checks canonical misrouting separator','static_checks':checks,'supporting_sources':[{'path':p,'sha256':sha((ROOT/p).read_bytes()),'unchanged':True} for p in support],'readme_sha256':sha((PKG/'README.md').read_bytes()),'producer_invariants_sha256':sha((PKG/'producer-invariants.md').read_bytes()),'freeze_script_sha256':sha((PKG/'freeze.py').read_bytes()),'actual_source_unchanged':True,'serializers_and_decoders_unchanged':True,'remaining_limits':['Canonical producer tail invariants require prepared all-order mutation test runtime verification','Allocator ownership correspondence to reachable user/system/pending DATA pages remains separate','Pessimistic region tracker markers for existing free regions remain unchecked','PageNumber canonical representation remains separate','Raw traversal/cache/ancestor guards/decoder/workspace/native RSS are not total memory qualification','Protected maintenance pool and exact extension capability remain open','No Cargo/native tests executed']}
(PKG/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'patch_sha256':sha(patch_bytes),'manifest_sha256':sha((PKG/'manifest.json').read_bytes()),'files':len(rows),'tests_prepared':len(newtests),'static_checks':[(x['name'],x['exit_code']) for x in checks]},indent=2))
