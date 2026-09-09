import sys,os,json,hashlib,subprocess,importlib.util,time
from pathlib import Path
root=Path('/tmp/kasumi-redb-4f62863-upstream')
out=Path('/tmp/kasumi-redb-bdde797-metadata')
helper=Path('/tmp/kasumi-production-recovery-followon/scripts/gate_process.py')
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
def git(*args):return subprocess.check_output(['git',*args],cwd=root,text=True,timeout=20).strip()
def inventory():
    names=subprocess.check_output(['git','ls-files','-z'],cwd=root,timeout=20).decode().split('\0')
    return {p:sha(root/p) for p in names if p}
assert git('rev-parse','HEAD')=='bdde7978ddac88db4851cbf0c1f77f75f5778b47'
assert not git('status','--porcelain')
assert sha(helper)=='6c8b255e5a69aa8985da8d70f5baa73337bcaeac7098bd756c4d6cc6472e58de'
before=inventory()
assert not (root/'Cargo.lock').exists() and not (root/'fuzz/Cargo.lock').exists()
out.mkdir(mode=0o700)
spec=importlib.util.spec_from_file_location('gate_process',helper)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
cargo=Path(subprocess.check_output(['rustup','which','--toolchain','1.97.1','cargo'],text=True,timeout=20).strip())
env=dict(os.environ,RUSTUP_TOOLCHAIN='1.97.1',RUSTC=str(cargo.parent/'rustc'),RUSTDOC=str(cargo.parent/'rustdoc'),CARGO_BUILD_JOBS='1',CARGO_NET_OFFLINE='true',CARGO_TARGET_DIR='/tmp/kasumi-redb-metadata-no-build-target',PYTHONDONTWRITEBYTECODE='1')
record={'scope':'Offline metadata-only dependency preparation for exact complete upstream source overlay; no compiler/native/test claim. Root and fuzz graphs are independently attempted, each120s, source and helper hashes guarded, changes restricted to verification locks. A missing cached dependency remains failure.','source':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'files_before':before,'runner_sha256':sha(Path(__file__)),'helper_sha256':sha(helper),'tools':{str(p):sha(p) for p in [cargo,cargo.parent/'rustc',cargo.parent/'rustdoc']},'gates':[]}
def persist():
    (out/'evidence.json').write_text(json.dumps(record,indent=2)+'\n')
persist()
for name,manifest,lock in [('upstream','Cargo.toml','Cargo.lock'),('fuzz','fuzz/Cargo.toml','fuzz/Cargo.lock')]:
    assert inventory()==before
    command=[str(cargo),'metadata','--offline','--all-features','--format-version','1','--manifest-path',manifest]
    print('START',name,flush=True)
    gate={'name':name,'command':command,'lock_before':sha(root/lock)}
    record['gates'].append(gate);persist()
    def observe(value):gate['process_record']=value;persist()
    with (out/(name+'.log')).open('wb') as stream:
        value=mod.run(command,root,env,stream,120,observe)
    gate.update(process_record=value,log_sha256=sha(out/(name+'.log')),lock_after=sha(root/lock),source_unchanged=inventory()==before,helper_unchanged=sha(helper)==record['helper_sha256'])
    gate['status']='passed' if value['exit_code']==0 and value['cleanup']['drained'] and gate['source_unchanged'] and gate['helper_unchanged'] else 'failed'
    if (root/lock).exists():(out/(name+'-Cargo.lock')).write_bytes((root/lock).read_bytes())
    print('TERMINAL',name,gate['status'],value['cleanup'],flush=True);persist()
    if not value['cleanup']['drained'] or not gate['source_unchanged'] or not gate['helper_unchanged']:break
record['source_unchanged']=inventory()==before
record['status']='passed' if len(record['gates'])==2 and all(g['status']=='passed' for g in record['gates']) else 'failed'
record['no_target_created']=not Path(env['CARGO_TARGET_DIR']).exists()
persist()
sys.exit(0 if record['status']=='passed' and record['no_target_created'] else 1)
