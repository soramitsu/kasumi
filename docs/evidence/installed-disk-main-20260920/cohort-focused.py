from pathlib import Path
import subprocess,sys,json
root=Path('/Users/mtakemiya/dev/kasumi'); base=root/'target/installed-disk-validation'
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
for number in [20,21,22,23,24,25]:
    print(json.dumps({'dispatching':number}),flush=True)
    result=subprocess.run([sys.executable,str(base/f'test{number}.py')],cwd=root)
    receipt=json.loads((base/f'{number}-result.json').read_text())
    if result.returncode or not receipt['drained'] or not receipt['inventoried_source_unchanged']:
        print(json.dumps({'stopped_at':number,'remaining_unrun':True}),flush=True)
        raise SystemExit(result.returncode or 1)
print(json.dumps({'cohort_complete':True}),flush=True)
