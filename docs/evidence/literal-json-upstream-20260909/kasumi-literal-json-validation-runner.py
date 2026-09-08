#!/usr/bin/env python3
"""One explicitly authorized serde-only cohort; fail closed and drain each gate."""
from pathlib import Path
import datetime, hashlib, json, os, signal, subprocess, sys, time

SOURCE = Path('/tmp/kasumi-literal-json-markers').resolve()
OUTPUT = Path('/tmp/kasumi-literal-json-validation-8f4cf74')
TARGET = Path('/tmp/kasumi-literal-json-validation-target')
TOOLS = Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin')
EXPECTED = '8f4cf744248f54ca416c965e708ad9d0b6074930'

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):h.update(block)
    return h.hexdigest()

def command_output(command):
    return subprocess.check_output(command,cwd=SOURCE,text=True).strip()

def write(name,value):
    dest=OUTPUT/name; pending=dest.with_suffix(dest.suffix+'.tmp')
    with pending.open('w') as f:
        json.dump(value,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    pending.replace(dest)

def source_state():
    names=subprocess.check_output(['git','ls-files','-z'],cwd=SOURCE).decode().split('\0')
    return {'commit':command_output(['git','rev-parse','HEAD']),
            'tree':command_output(['git','rev-parse','HEAD^{tree}']),
            'status':command_output(['git','status','--porcelain']),
            'files':{p:digest(SOURCE/p) for p in names if p}}

def members(group):
    listing=subprocess.check_output(['ps','-axo','pid=,ppid=,pgid=,stat=,comm='],text=True)
    return [line.strip() for line in listing.splitlines() if len(line.split(None,4))>=5 and line.split(None,4)[2]==str(group)]

def drain(process):
    before=members(process.pid); sent=[]
    for sig,seconds in [(signal.SIGTERM,5),(signal.SIGKILL,5)]:
        if not members(process.pid):break
        try:os.killpg(process.pid,sig);sent.append(sig.name)
        except ProcessLookupError:pass
        until=time.monotonic()+seconds
        while time.monotonic()<until:
            process.poll()
            if not members(process.pid):break
            time.sleep(0.1)
    process.wait(timeout=5)
    after=members(process.pid)
    return {'group':process.pid,'before':before,'signals':sent,'after':after,'drained':not after}

def artifacts(log):
    result={};packages={}
    with log.open() as f:
        for line in f:
            try:m=json.loads(line)
            except ValueError:continue
            if not isinstance(m,dict) or m.get('reason')!='compiler-artifact':continue
            pid=m.get('package_id','unknown');packages.setdefault(pid,set()).update(m.get('features',[]))
            paths=list(m.get('filenames',[]))
            if m.get('executable'):paths.append(m['executable'])
            for name in paths:
                p=Path(name).resolve();rel=str(p.relative_to(TARGET.resolve()))
                if p.is_file():result[rel]={'sha256':digest(p),'bytes':p.stat().st_size,'package_id':pid,'target':m.get('target'),'profile':m.get('profile'),'executable':name==m.get('executable')}
    return {'files':result,'packages':{k:sorted(v) for k,v in packages.items()}}

def interrupted(sig,frame):raise InterruptedError('runner received signal '+str(sig))

for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,interrupted)
OUTPUT.mkdir(mode=0o700);TARGET.mkdir(mode=0o700)
before=source_state();assert before['commit']==EXPECTED and before['status']==''
write('source-before.json',before)
assert not (SOURCE/'target').exists(), 'source target directory already exists'
env=dict(os.environ,PATH=str(TOOLS)+os.pathsep+os.environ['PATH'],CARGO_TARGET_DIR=str(TARGET),CARGO_BUILD_JOBS='1',RUST_TEST_THREADS='1',RUSTUP_TOOLCHAIN='1.97.1',RUSTC=str(TOOLS/'rustc'),RUSTDOC=str(TOOLS/'rustdoc'),PYTHONDONTWRITEBYTECODE='1',CARGO_TERM_COLOR='never')
base=[str(TOOLS/'cargo'),'test','--manifest-path','vendor/serde_json-1.0.151/Cargo.toml','--locked','-j','1','--message-format=json-render-diagnostics']
gates=[('dependency-patches',[sys.executable,'scripts/check_dependency_patches.py'],300)]
for name,features in [('default',None),('number','arbitrary_precision'),('raw','raw_value'),('combined','arbitrary_precision,raw_value,float_roundtrip,preserve_order')]:
    gates.append(('serde-json-'+name,base+(['--features',features] if features else [])+['--','--test-threads=1'],900))
report={'schema':1,'scope':'Authorized serde-only dependency cohort; no Kasumi compilation/native acceptance','source':EXPECTED,'tree':before['tree'],'root_lock_sha256':digest(SOURCE/'Cargo.lock'),'vendor_lock_sha256':digest(SOURCE/'vendor/serde_json-1.0.151/Cargo.lock'),'runner_sha256':digest(__file__),'source_before_sha256':digest(OUTPUT/'source-before.json'),'tools':{str(p):{'sha256':digest(p),'version':command_output([str(p),'-V'])} for p in [TOOLS/'cargo',TOOLS/'rustc',TOOLS/'rustdoc',Path(sys.executable)]},'target':str(TARGET),'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'jobs':1,'test_threads':1,'gates':[],'status':'running'}
write('evidence.json',report)
try:
    for name,command,timeout in gates:
        assert source_state()==before,'frozen source changed before gate'
        print('START',name,flush=True)
        log=OUTPUT/(name+'.log');start=time.monotonic();proc=None;failure=None;expired=False
        with log.open('wb') as output:
            try:
                proc=subprocess.Popen(command,cwd=SOURCE,env=env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
                write('progress.json',{'gate':name,'pid':proc.pid,'group':proc.pid,'command':command,'timeout_seconds':timeout,'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat()})
                try:code=proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:expired=True;code=124
            except BaseException as error:
                failure=repr(error);code=125
            finally:
                cleanup=drain(proc) if proc is not None else {'drained':True,'after':[]}
                output.flush();os.fsync(output.fileno())
        after=source_state();unchanged=after==before
        observed=artifacts(log)
        entry={'name':name,'command':command,'timeout_seconds':timeout,'exit_code':code,'timed_out':expired,'exception':failure,'duration_seconds':round(time.monotonic()-start,3),'log':log.name,'log_sha256':digest(log),'process_cleanup':cleanup,'source_unchanged':unchanged,'artifacts':observed}
        report['gates'].append(entry)
        failed=code!=0 or failure is not None or not cleanup['drained'] or not unchanged
        report['status']='failed' if failed else 'running';write('evidence.json',report)
        print('TERMINAL',name,'exit',code,'drained',cleanup['drained'],'source_unchanged',unchanged,flush=True)
        if failed:break
    else:report['status']='passed'
except BaseException as error:
    report['status']='failed';report['runner_error']=repr(error)
finally:
    after=source_state();write('source-after.json',after)
    report['source_after_sha256']=digest(OUTPUT/'source-after.json');report['source_unchanged']=after==before
    if after!=before:report['status']='failed'
    report['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();write('evidence.json',report)
    write('progress.json',{'status':report['status'],'terminal':True,'gates':len(report['gates'])})
    print('COHORT',report['status'],'evidence',OUTPUT/'evidence.json',flush=True)
sys.exit(0 if report['status']=='passed' else 1)
