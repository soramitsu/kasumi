from pathlib import Path
import ast
import difflib
import hashlib
import json
import subprocess

ROOT=Path('/Users/mtakemiya/dev/kasumi')
P=ROOT/'target/installed-disk-validation/repeatable-assembly-v2'
assert subprocess.check_output(['git','-C',str(ROOT),'branch','--show-current'],text=True).strip()=='master'
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
changed=[];diff=[]
for after in sorted((P/'proposed').rglob('*')):
 if not after.is_file():continue
 name=after.relative_to(P/'proposed').as_posix();before=P/'base'/name
 old=before.read_text() if before.exists() else ''
 new=after.read_text()
 if old==new:continue
 if before.exists():assert digest(ROOT/name)==digest(before),name+' actual baseline changed'
 else:assert not (ROOT/name).exists(),name+' appeared outside proposal'
 if name.endswith('.py'):ast.parse(new,filename=name)
 diff.extend(difflib.unified_diff(old.splitlines(keepends=True),new.splitlines(keepends=True),fromfile='a/'+name if before.exists() else '/dev/null',tofile='b/'+name))
 changed.append({'path':name,'before_sha256':digest(before) if before.exists() else None,'after_sha256':digest(after)})
patch=P/'assembly.patch';patch.write_text(''.join(diff))
result=subprocess.run(['git','-C',str(ROOT),'apply','--check',str(patch)],capture_output=True,text=True)
(P/'apply-check.txt').write_text(result.stdout+result.stderr)
assert result.returncode==0
stats=[]
for name in ('python-tests-01','python-tests-02','python-tests-03'):
 d=P/name
 stats.append({'name':name,'result':json.loads((d/'unit-result.json').read_text()),'process':json.loads((d/'process.json').read_text()),
               'imported_files':len(json.loads((d/'imports-before.json').read_text())),
               'new_imports':json.loads((d/'new-imports.json').read_text())})
manifest={'schema':'kasumi-target-proposal-v1','status':'PROPOSED_REVIEW_REQUIRED_NOT_NATIVE_QUALIFIED','repository':str(ROOT),'branch':'master',
 'base_head':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),
 'patch_sha256':digest(patch),'files':changed,'validation':stats,
 'scope':'Two actual owned assembly invocations, direct native Cargo metadata, declared native dependency custody and read-only semantic adapter. DOMAIN_ADAPTERS remains empty.',
 'not_run':['Native Cargo/rustc probes','Full frozen-candidate assembly pair','Full native semantic-adapter acceptance-positive run','CI workflow execution','Cross-platform runtime/host library declarations'],
 'review_limits':['Host dependency completeness relies on retained operator inventory evidence, not universal read tracing.',
                  'Native Cargo home operational-state behavior and native library/loader inventory representation still require actual native validation.',
                  'No final acceptance registration, independent compilation, OCI/image SBOM, native release qualification or release completion.']}
(P/'manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
(P/'raw-sha256.json').write_text(json.dumps({str(f.relative_to(P)):digest(f) for f in sorted(P.rglob('*')) if f.is_file() and f.name!='raw-sha256.json'},indent=2,sort_keys=True)+'\n')
print(json.dumps({'files':len(changed),'patch_sha256':digest(patch),'tests':stats[-1]['result'],'imports':stats[-1]['imported_files'],'apply_check':result.returncode}))
