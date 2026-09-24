from pathlib import Path
import difflib,hashlib,json,subprocess
R=Path('/Users/mtakemiya/dev/kasumi');P=R/'target/installed-disk-validation/disk-memory-lease-retirement'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
assert subprocess.check_output(['git','-C',str(R),'branch','--show-current'],text=True).strip()=='master'
patch=[];files=[]
for after in sorted((P/'proposed').rglob('*')):
 if not after.is_file():continue
 name=after.relative_to(P/'proposed').as_posix();before=P/'base'/name
 if before.exists():assert sha(R/name)==sha(before),name+' baseline changed'
 else:assert not (R/name).exists(),name+' newly exists in actual source'
 old=before.read_text() if before.exists() else '';new=after.read_text()
 if old==new:continue
 patch.extend(difflib.unified_diff(old.splitlines(keepends=True),new.splitlines(keepends=True),fromfile='a/'+name if before.exists() else '/dev/null',tofile='b/'+name))
 files.append({'path':name,'before_sha256':sha(before) if before.exists() else None,'proposed_sha256':sha(after)})
(P/'retirement.patch').write_text(''.join(patch))
check=subprocess.run(['git','-C',str(R),'apply','--check',str(P/'retirement.patch')],capture_output=True,text=True)
(P/'apply-check.json').write_text(json.dumps({'exit_code':check.returncode,'stdout':check.stdout,'stderr':check.stderr},indent=2)+'\n')
assert check.returncode==0
scopes={name:json.loads((P/name/'results.json').read_text()) for name in ['standalone-01','standalone-02','counterfactual-01']}
manifest={'status':'TARGET_ONLY_REVIEWABLE_STANDALONE_VALIDATED_NO_WORKSPACE_CARGO',
 'repository':str(R),'branch':'master','base_head':subprocess.check_output(['git','-C',str(R),'rev-parse','HEAD'],text=True).strip(),
 'patch_sha256':sha(P/'retirement.patch'),'files':files,'actual_source_modified':False,'cargo_executed':False,
 'allocation_allowance_bytes':4096,'native_opaque_inline_bytes':16,'native_opaque_alignment':8,
 'validation':scopes,'native_debug_proposed_tests':3,'native_optimized_proposed_tests':3,
 'counterfactual':json.loads((P/'counterfactual-01/counterexample.json').read_text()),
 'not_run':['Full store crate integration','Full engine crate integration','Strict workspace Clippy','Final native release qualification'],
 'format_note':'lib.rs public export was rustfmt-normalized after standalone tests; the four literal extracted/included implementation-test inputs still exactly match the final proposal.'}
for name in ['disk_memory.rs','test_utils.rs','allocation_tests.rs','disk_memory_tests.rs']:
 assert json.loads((P/'standalone-02/source-before.json').read_text())[str(P/'proposed/crates/kasumi-store/src'/name)]==sha(P/'proposed/crates/kasumi-store/src'/name)
(P/'manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
(P/'raw-sha256.json').write_text(json.dumps({str(f.relative_to(P)):sha(f) for f in sorted(P.rglob('*')) if f.is_file() and f.name!='raw-sha256.json'},indent=2,sort_keys=True)+'\n')
print(json.dumps({'files':len(files),'patch_sha256':sha(P/'retirement.patch'),'apply_check':check.returncode,'final_source_matches_test_inputs':True}))
