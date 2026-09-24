from pathlib import Path
import hashlib,json,os,signal,subprocess,time
root=Path('/Users/mtakemiya/dev/kasumi')
base=root/'target/installed-disk-validation/redb-staging-workspace'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
tracked=[root/'vendor/redb-4.2.0/src/tree_store/page_store/lru_cache.rs',root/'vendor/redb-4.2.0/src/tree_store/page_store/fast_hash.rs']
before={str(p.relative_to(root)):sha(p) for p in tracked}
inputs={str(p.relative_to(root)):sha(p) for p in (base/'native-input').rglob('*.rs')}
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
for mode in ['before','proposed']:
    executable=base/('lru-'+mode+'-tests')
    assert run('compile-'+mode,['rustc','--test','--edition=2024',str(base/'native-input'/mode/'main.rs'),'-o',str(executable)])==0
    result=run('run-'+mode,[str(executable),'--test-threads=1','--nocapture'])
    assert result==(101 if mode=='before' else 0),receipts[-1]
after={str(p.relative_to(root)):sha(p) for p in tracked}
assert before==after
result={'status':'EXTRACTED_EXACT_LRU_MODULE_TEST_ONLY_NOT_VENDOR_OR_WORKSPACE_GATE','source_inputs':inputs,'actual_before_sha256':before,'actual_after_sha256':after,'actual_sources_unchanged':before==after,'rustc_version_sha256':sha(base/'rustc-version.txt'),'runs':receipts,'scope_note':'Exact actual/proposed LRU modules and exact vendored fast_hash; unused PageNumber aliases use a stub because this isolated module only stores u64 cache keys. Native allocator test is harness-only; ordinary proposed vendor patch includes the two behavioral regressions.'}
(base/'native-receipt.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'runs':receipts,'actual_sources_unchanged':True},indent=2))
