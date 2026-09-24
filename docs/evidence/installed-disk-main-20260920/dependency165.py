from pathlib import Path
import subprocess,json,sys
root=Path('/Users/mtakemiya/dev/kasumi')
commands=[
 [sys.executable,'-m','unittest','discover','-s','scripts','-p','test_check_dependency_patches.py','-v'],
 [sys.executable,'scripts/check_dependency_patches.py'],
]
results=[]
for command in commands:
 result=subprocess.run(command,cwd=root)
 results.append({'command':command,'exit_code':result.returncode})
 (root/'target/installed-disk-validation/165-dependency-phases.json').write_text(json.dumps(results,indent=2)+'\n')
 if result.returncode: raise SystemExit(result.returncode)
