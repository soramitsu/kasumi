from pathlib import Path
import hashlib,json,difflib,re,subprocess
root=Path.cwd(); stage=root/'target/installed-disk-validation/engine-integration-callers'; records=json.loads((stage/'baseline.json').read_text())
held={'backup_checkpoint.rs','embedded_audit.rs','retirement.rs','lifecycle.rs','replicated.rs'}
manifest=[];patch=[];audit=[]
for record in records:
 path=record['path'];p=Path(path)
 if p.name in held:continue
 base=root/record['source']; proposed=stage/'proposed'/path
 if base.read_bytes()==proposed.read_bytes():continue
 assert hashlib.sha256(base.read_bytes()).hexdigest()==record['before_sha256']
 before=base.read_text(); after=proposed.read_text()
 # Names and original duration arguments retained; test helper APIs/layouts
 # change, not test entrypoints or timing budgets.
 tests=lambda x:re.findall(r'#\[(?:tokio::)?test(?:\([^\n]*\))?\]\s*(?:#\[[^\n]*\]\s*)*(?:async\s+)?fn\s+(\w+)',x)
 durations=lambda x:re.findall(r'Duration::from_\w+\([^)]*\)',x)
 assert tests(before)==tests(after),(path,'tests')
 assert durations(before)==durations(after),(path,'durations')
 audit.append({'path':path,'test_names':tests(after),'unchanged_duration_expressions':durations(after)})
 check=subprocess.run(['/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustfmt','--edition','2024','--config','skip_children=true','--check',str(proposed)],capture_output=True,text=True)
 assert check.returncode==0,(path,check.stdout,check.stderr)
 patch.append(''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/'+path,tofile='b/'+path)))
 manifest.append(dict(record,proposed_sha256=hashlib.sha256(proposed.read_bytes()).hexdigest()))
combined=''.join(patch);(stage/'root-callers.patch').write_text(combined)
receipt={'status':'TARGET_ONLY_UNCOMPILED_ROOT_LAYER','head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'requires':['metadata10ebc1c6','backend2c997182','adapter90015017','guards efeca43a','construction05d51188','helper e3bebad9','engine-src-required-disk-apply proposal pending'],'patch_sha256':hashlib.sha256(combined.encode()).hexdigest(),'held_files':sorted(held),'files':manifest}
(stage/'root-manifest.json').write_text(json.dumps(receipt,indent=2)+'\n');(stage/'root-fixture-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
print(json.dumps({'files':len(manifest),'patch_sha256':receipt['patch_sha256'],'tests':sum(len(a['test_names']) for a in audit),'status':receipt['status']}))
