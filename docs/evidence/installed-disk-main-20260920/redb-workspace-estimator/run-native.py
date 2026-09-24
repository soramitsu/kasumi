from pathlib import Path
import hashlib,json,os,signal,subprocess,time
root=Path('/Users/mtakemiya/dev/kasumi')
base=root/'target/installed-disk-validation/redb-workspace-estimator'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
tracked=list((root/'vendor/redb-4.2.0/src').rglob('*.rs'))
before={str(p.relative_to(root)):sha(p) for p in tracked}
inputs={str(p.relative_to(root)):sha(p) for p in (base/'native').rglob('*.rs')}
receipts=[]
def run(name,command):
    start=time.monotonic()
    proc=subprocess.Popen(command,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    timed_out=False
    try: output,_=proc.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        timed_out=True;os.killpg(proc.pid,signal.SIGKILL);output,_=proc.communicate()
    try: os.killpg(proc.pid,0);drained=False
    except ProcessLookupError:drained=True
    log=base/(name+'.log');log.write_bytes(output)
    receipt={'name':name,'command':command,'process_group':proc.pid,'exit_code':proc.returncode,'timed_out':timed_out,'deadline_seconds':60,'elapsed_seconds':time.monotonic()-start,'process_group_drained':drained,'log_sha256':sha(log)}
    receipts.append(receipt)
    assert not timed_out and drained,receipt
    return proc.returncode
version=subprocess.check_output(['rustc','--version','--verbose'],cwd=root,text=True)
(base/'rustc-version.txt').write_text(version)
for mode in ['debug','release']:
    executable=base/('geometry-'+mode+'-tests')
    flags=[] if mode=='debug' else ['-C','opt-level=2','-C','debug-assertions=no']
    assert run('compile-'+mode,['rustc','--test','--edition=2024',str(base/'native/main.rs'),'-o',str(executable)]+flags)==0
    assert run('run-'+mode,[str(executable),'--test-threads=1','--nocapture'])==0
after={str(p.relative_to(root)):sha(p) for p in tracked}
assert before==after
result={'status':'PINNED_COLLECTION_LAYOUT_COMPONENT_TEST_ONLY_NOT_COMPLETE_REDB_ESTIMATOR','source_inputs':inputs,'actual_before_sha256':before,'actual_after_sha256':after,'actual_sources_unchanged':before==after,'rustc_version_sha256':sha(base/'rustc-version.txt'),'runs':receipts,'scope_note':'Collection formulas and exact extracted vendor field declarations only. No redb transaction execution; no total heap, malloc footprint or RSS qualification. Both debug and optimized layout probes use the same locked toolchain.'}
(base/'native-receipt.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'runs':receipts,'actual_sources_unchanged':True},indent=2))
