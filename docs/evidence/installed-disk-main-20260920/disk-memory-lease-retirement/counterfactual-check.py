from pathlib import Path
import json,os,sys
ROOT=Path('/Users/mtakemiya/dev/kasumi');P=ROOT/'target/installed-disk-validation/disk-memory-lease-retirement';D=P/'counterfactual-01';D.mkdir(exist_ok=False)
sys.path.insert(0,str(ROOT/'scripts'))
import gate_process
from release_gate import sha256,write_json
old=(P/'standalone-02/lease-extracted.rs').read_text()
correct='''        let reservation = {
            let allocation = self;
            *allocation
        };
        drop(reservation);'''
assert old.count(correct)==1
(D/'lease-extracted.rs').write_text(old.replace(correct,'        let reservation = *self;\n        drop(reservation);'))
(D/'provider-extracted.rs').write_bytes((P/'standalone-02/provider-extracted.rs').read_bytes())
(D/'harness.rs').write_bytes((P/'standalone-02/harness.rs').read_bytes())
inputs={str(f):sha256(f) for f in D.glob('*.rs')}
inputs.update({str(P/'proposed/crates/kasumi-store/src'/n):sha256(P/'proposed/crates/kasumi-store/src'/n) for n in ['allocation_tests.rs','disk_memory_tests.rs']})
write_json(D/'source-before.json',inputs)
env=os.environ.copy();env['TMPDIR']=str(ROOT/'target/tmp');env['PYTHONDONTWRITEBYTECODE']='1'
results=[]
commands=[('compile',['/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustc','--edition=2024','--test',str(D/'harness.rs'),'-o',str(D/'tests')]),
          ('expected-rejection',[str(D/'tests'),'--exact','disk_memory::tests::installed_lease_cannot_return_bytes_or_slot_before_actual_box_deallocation','--nocapture'])]
for name,cmd in commands:
 with (D/(name+'.stdout')).open('xb') as out,(D/(name+'.stderr')).open('xb') as err:
  result=gate_process.run(cmd,ROOT,env,out,120,lambda value:write_json(D/(name+'.process.json'),value),stderr=err)
 results.append(result)
 if name=='compile' and result['exit_code']!=0:break
write_json(D/'results.json',results)
after={name:sha256(name) for name in inputs};write_json(D/'source-after.json',after)
assert inputs==after
observed=len(results)==2 and results[0]['exit_code']==0 and results[1]['process_exit_code']==101 and results[1]['cleanup']['drained'] and not results[1]['timed_out']
write_json(D/'counterexample.json',{'scope':'Intentionally incorrect named-Box retirement, no production source changes','detected_early_credit':observed,'actual_test_exit_code':results[-1]['exit_code'],'original_failed_receipt_preserved':True})
write_json(D/'raw-sha256.json',{str(f.relative_to(D)):sha256(f) for f in D.rglob('*') if f.is_file()})
print(json.dumps({'expected_rejection_observed':observed,'test_exit_code':results[-1]['exit_code']}))
raise SystemExit(0 if observed else 1)
