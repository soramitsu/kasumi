from pathlib import Path
import datetime,difflib,hashlib,json,re,subprocess
ROOT=Path('/Users/mtakemiya/dev/kasumi');PKG=ROOT/'target/installed-disk-validation/redb-canonical-allocator-keys-opening-composed';OLD=ROOT/'target/installed-disk-validation/redb-canonical-allocator-keys';OPEN=ROOT/'target/installed-disk-validation/retained-opening-owner-revision3'
assert Path.cwd().resolve()==ROOT
assert subprocess.check_output(['git','branch','--show-current'],text=True).strip()=='master'
assert not (PKG/'manifest.json').exists()
sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha((OLD/'canonical-keys.patch').read_bytes())=='a61e1c3d9ac6bfef19a4f33b669d9355c59fca38af02234817244a8ad02551d4'
assert sha((OPEN/'opening.patch').read_bytes())=='a28a3b438ed3138afb1c0faec7daab045f0812800ebf696b8ce8a93d86fd3cef'
original=json.loads((OLD/'manifest.json').read_text());opening=json.loads((OPEN/'manifest.json').read_text())
rows=[];patch=[]
for row in original['files']:
 rel=row['path'];base=PKG/'base'/rel;proposed=PKG/'proposed'/rel;actual=ROOT/rel;reversed=PKG/'reverse-check'/rel
 before=base.read_bytes() if base.exists() else b'';after=proposed.read_bytes()
 assert actual.exists()==base.exists() and reversed.exists()==base.exists(),rel
 assert not actual.exists() or actual.read_bytes()==before==reversed.read_bytes(),rel
 rows.append({'path':rel,'base_sha256':sha(before) if base.exists() else None,'proposed_sha256':sha(after),'base_bytes':len(before),'proposed_bytes':len(after),'original_canonical_reverse_restores_exact_base':True})
 patch.extend(difflib.unified_diff(before.decode().splitlines(keepends=True),after.decode().splitlines(keepends=True),fromfile='a/'+rel if base.exists() else '/dev/null',tofile='b/'+rel))
patch_bytes=''.join(patch).encode();(PKG/'canonical-keys.patch').write_bytes(patch_bytes)
opening_rows=[]
for row in opening['files']:
 actual=ROOT/row['path'];assert sha(actual.read_bytes())==row['after_sha256'],row['path']
 proposed=PKG/'proposed'/row['path']
 opening_rows.append({'path':row['path'],'applied_opening_sha256':row['after_sha256'],'composed_sha256':sha(proposed.read_bytes()) if proposed.exists() else row['after_sha256'],'opening_changes_preserved':'original_canonical_reverse_restores_exact_base' if proposed.exists() else 'unchanged_file'})
checks=[];rustfmt='/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustfmt'
for label,argv in [('target-rustfmt-check',[rustfmt,'--check','--edition','2024','--config','skip_children=true']+[str(PKG/'proposed'/r['path']) for r in rows]),('git-apply-check',['git','apply','--check',str(PKG/'canonical-keys.patch')])]:
 proc=subprocess.run(argv,text=True,capture_output=True);log=proc.stdout+proc.stderr
 (PKG/(label+'.log')).write_text(log);checks.append({'name':label,'argv':argv,'exit_code':proc.returncode,'log_sha256':sha(log.encode())})
 assert proc.returncode==0,(label,log)
for row in rows:
 actual=ROOT/row['path'];assert (sha(actual.read_bytes()) if actual.exists() else None)==row['base_sha256']
manifest={'status':'target-only-composed-not-applied-not-compiled-not-tested','root':str(ROOT),'branch':'master','head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'created_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'patch_sha256':sha(patch_bytes),'files':rows,'original_canonical_patch_sha256':original['patch_sha256'],'original_canonical_manifest_sha256':sha((OLD/'manifest.json').read_bytes()),'opening_patch_sha256':opening['patch_sha256'],'opening_manifest_sha256':sha((OPEN/'manifest.json').read_bytes()),'opening_files_preserved':opening_rows,'prepared_tests':original['prepared_tests'],'static_checks':checks,'target_forward_composition_sha256':sha((PKG/'composition-apply.log').read_bytes()),'target_reverse_composition_sha256':sha((PKG/'composition-reverse.log').read_bytes()),'readme_sha256':sha((PKG/'README.md').read_bytes()),'canonical_key_scope_sha256':sha((PKG/'canonical-key-scope.md').read_bytes()),'opening_peer_review_sha256':sha((PKG/'opening-peer-review.md').read_bytes()),'freeze_script_sha256':sha((PKG/'freeze.py').read_bytes()),'actual_source_unchanged':True,'remaining_limits':original['remaining_limits'][:3]+['Branch separator correspondence to child key ranges remains separate','No Cargo/native tests executed']}
(PKG/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'patch_sha256':sha(patch_bytes),'manifest_sha256':sha((PKG/'manifest.json').read_bytes()),'files':len(rows),'opening_files_preserved':len(opening_rows),'tests_prepared':len(original['prepared_tests']),'static_checks':[(x['name'],x['exit_code']) for x in checks]},indent=2))
