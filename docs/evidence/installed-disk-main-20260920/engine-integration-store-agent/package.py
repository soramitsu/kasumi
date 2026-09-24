from pathlib import Path
import hashlib,json,difflib,re,subprocess
root=Path('/Users/mtakemiya/dev/kasumi');out=root/'target/installed-disk-validation/engine-integration-store-agent';sha=lambda x:hashlib.sha256(x).hexdigest();parts=[];follow=[];files=[];audits=[]
for p in sorted((out/'proposed').rglob('*.rs')):
 rel=p.relative_to(out/'proposed');a=(root/rel).read_bytes();b=(out/'before'/rel).read_bytes();n=p.read_bytes();files.append({'path':str(rel),'actual_before_sha256':sha(a),'incoming_proposed_sha256':sha(b),'proposed_sha256':sha(n)})
 parts.extend(difflib.unified_diff(a.decode().splitlines(True),n.decode().splitlines(True),fromfile='a/'+str(rel),tofile='b/'+str(rel)))
 follow.extend(difflib.unified_diff(b.decode().splitlines(True),n.decode().splitlines(True),fromfile='a/'+str(rel),tofile='b/'+str(rel)))
 names=lambda s:re.findall(r'#\[(?:tokio::)?test[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:async\s+)?fn\s+(\w+)',s)
 durations=lambda s:re.findall(r'Duration::from_(?:secs|millis)\([^\n)]*\)',s)
 assert names(a.decode())==names(n.decode()),rel
 assert durations(a.decode())==durations(n.decode()),rel
 r=subprocess.run(['rustfmt','--check','--edition','2024','--config','skip_children=true',str(p)],capture_output=True,text=True);assert r.returncode==0,r.stderr
 audits.append({'path':str(rel),'test_entrypoints':names(n.decode()),'duration_expressions_unchanged':True,'formatted':True})
patch=''.join(parts);(out/'callers.patch').write_text(patch);(out/'incoming-followup.patch').write_text(''.join(follow));m={'status':'target-only prepared, not compiled/applied','head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'patch_sha256':sha(patch.encode()),'incoming_followup_sha256':sha(''.join(follow).encode()),'dependencies':{'store_metadata':'10ebc1c6ee2a0df7c65b67302757b537ddedcb000008ea5391a82d030fab5259','synthetic_backend_followup':'2c9971827a928bd3dd412e944f4f55df2c235e5e9edf723514d5411b2ee53b84','root_integration_common':'ec254c91921d0b33f8f11b7bd63315e225fa01cb8f3aecfdb6fbe3f557d57f83'},'files':files};(out/'manifest.json').write_text(json.dumps(m,indent=2)+'\n');(out/'paths').write_text(''.join(x['path']+'\n' for x in files));(out/'fixture-audit.json').write_text(json.dumps(audits,indent=2)+'\n')
r=subprocess.run(['git','apply','--check',str(out/'callers.patch')],cwd=root,text=True,capture_output=True);(out/'patch-check.json').write_text(json.dumps({'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr},indent=2)+'\n');assert r.returncode==0,r.stderr
print(json.dumps({'sha':m['patch_sha256'],'files':len(files),'lines':len(patch.splitlines()),'tests':sum(len(a['test_entrypoints']) for a in audits),'incoming_equals_actual':all(f['actual_before_sha256']==f['incoming_proposed_sha256'] for f in files)},indent=2))
