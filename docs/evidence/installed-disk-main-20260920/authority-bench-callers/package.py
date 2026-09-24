from pathlib import Path
import subprocess,hashlib,json,difflib,re
root=Path('/Users/mtakemiya/dev/kasumi'); out=root/'target/installed-disk-validation/authority-bench-callers'; base=out/'before'; proposed=out/'proposed'
sha=lambda b:hashlib.sha256(b).hexdigest()
files=[]; parts=[]
for p in sorted(proposed.rglob('*')):
 if not p.is_file(): continue
 rel=p.relative_to(proposed); b=base/rel; before=b.read_bytes(); after=p.read_bytes()
 if before==after:continue
 assert (root/rel).read_bytes()==before, f'changed actual source: {rel}'
 parts.extend(difflib.unified_diff(before.decode().splitlines(True),after.decode().splitlines(True),fromfile='a/'+str(rel),tofile='b/'+str(rel)))
 files.append({'path':str(rel),'before_sha256':sha(before),'proposed_sha256':sha(after)})
patch=''.join(parts); (out/'callers.patch').write_text(patch)
manifest={'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'status':'target-only prepared; NOT applied or compiled','patch_sha256':sha(patch.encode()),'dependencies':{'store_metadata_revision2':'10ebc1c6ee2a0df7c65b67302757b537ddedcb000008ea5391a82d030fab5259','engine_fixture_helper':'e3bebad935c1fe5ddbe9a53a46fb8bbe68afe0a5b3cf99fe0439edd80535f844','installed_core_adapter':'3d70d1a2765b53ebbba062382a15b6db3bb97a82af45b47aa263124de81100cd','server_example_config':'prepared new-install explicit 2GiB policy (loopback subprocess only)'},'files':files}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(out/'paths').write_text(''.join(x['path']+'\n' for x in files))
r=subprocess.run(['git','apply','--check',str(out/'callers.patch')],cwd=root,text=True,capture_output=True)
receipt={'patch_sha256':manifest['patch_sha256'],'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'before_hashes_match':True}
(out/'patch-check.json').write_text(json.dumps(receipt,indent=2)+'\n')
assert r.returncode==0,receipt
# Verify all original test entrypoints, attributes, timeouts and numeric test
# workloads remain present; source changes in budgets are enumerated in README.
audit=[]
for x in files:
 if not x['path'].endswith('.rs'):continue
 old=(base/x['path']).read_text(); new=(proposed/x['path']).read_text()
 names=lambda s: re.findall(r'#\[(?:tokio::)?test[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:async\s+)?fn\s+(\w+)',s)
 assert names(old)==names(new),(x['path'],'test entrypoints changed')
 durations=lambda s:re.findall(r'Duration::from_(?:secs|millis)\([^\n)]*\)',s)
 assert durations(old)==durations(new),(x['path'],'durations changed')
 audit.append({'path':x['path'],'test_entrypoints':names(new),'duration_expressions_unchanged':True})
(out/'fixture-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
print(json.dumps({'sha':manifest['patch_sha256'],'files':len(files),'lines':len(patch.splitlines()),'tests':sum(len(a['test_entrypoints']) for a in audit)},indent=2))
