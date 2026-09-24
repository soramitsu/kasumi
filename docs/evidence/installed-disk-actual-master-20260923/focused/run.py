from pathlib import Path
import datetime,hashlib,json,os,signal,subprocess,sys,threading,time
root=Path('/Users/mtakemiya/dev/kasumi');out=Path(__file__).resolve().parent;tool=Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin');target=out/'cargo-target';expected=out/'expected-tests.json';application=root/'target/installed-disk-validation/actual-application-authority-route/receipt.json'
case='service::tests::permanent_target_stop_defeats_missing_and_prepared_generations_then_reopens_after_full_drain'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def record(p):return {'sha256':sha(p),'bytes':p.stat().st_size}
def save(name,obj):
 with (out/name).open('w') as f:json.dump(obj,f,indent=2);f.write('\n')
def inventory():
 paths={Path(__file__),out/'preflight.json',expected,application,root/'Cargo.toml',root/'Cargo.lock'}
 for d in ['crates','vendor','tests','scripts','.cargo']:
  if (root/d).exists():paths.update(p for p in (root/d).rglob('*') if p.is_file())
 paths.update(root.glob('rust-toolchain*'));paths.update(tool/n for n in ['cargo','rustc','rustdoc'])
 return {str(p):record(p) for p in sorted(paths)}
def rows(pg):
 result=[]
 for line in subprocess.check_output(['ps','-axo','pid=,ppid=,pgid=,command='],text=True).splitlines():
  parts=line.strip().split(None,3)
  if len(parts)==4 and int(parts[2])==pg:result.append({'pid':int(parts[0]),'ppid':int(parts[1]),'pgid':int(parts[2]),'command':parts[3]})
 return result
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
assert sha(application)=='fb981d0261bb6b88908c026b019cd3f6d8d1b76f98fbdb2a196929cf044dea53'
assert sha(root/'crates/kasumi-engine/src/service.rs')=='7c6fd2dccb2afddc0c9ffd203fab2e21b7048c0b9e1342652f03f539876bd7c0'
assert sha(root/'crates/kasumi-authority/src/target_stop_tests.rs')=='33b3a3f13eee6e1ec859a01e8977de010613fba9a25e6c8e0bc9685225d26574'
assert not target.exists();assert not (out/'source-before.json').exists();target.mkdir()
start=time.monotonic();before=inventory();save('source-before.json',before);save('launcher.json',{'pid':os.getpid(),'pgid':os.getpgrp(),'command':sys.argv,'started_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
env={**os.environ,'PATH':str(tool)+':'+os.environ['PATH'],'CARGO_TARGET_DIR':str(target),'CARGO_NET_OFFLINE':'true','CARGO_BUILD_JOBS':'2','RUST_BACKTRACE':'1','RUST_TEST_THREADS':'1','TMPDIR':str(root/'target/tmp'),'PYTHONDONTWRITEBYTECODE':'1'}
results=[];binary=None;exception=None
def phase(name,command,bound=1200):
 assert inventory()==before,'source changed before phase '+name
 assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
 remaining=1200-(time.monotonic()-start)
 if remaining<=0:raise RuntimeError('cohort deadline exhausted before dispatch')
 limit=min(bound,remaining);log=out/(name+'.log');signals=[];timed_out=False;seen={};stop=threading.Event();started=time.monotonic()
 with log.open('xb') as f:
  q=subprocess.Popen(command,cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
  active={'name':name,'pid':q.pid,'pgid':q.pid,'command':command,'cwd':str(root),'log':str(log),'bound_seconds':limit};save('active.json',active);print(json.dumps(active),flush=True)
  def monitor():
   while not stop.wait(.1):
    for row in rows(q.pid):seen[(row['pid'],row['command'])]=row
  t=threading.Thread(target=monitor,daemon=True);t.start()
  try:q.wait(timeout=limit)
  except subprocess.TimeoutExpired:
   timed_out=True;signals.append('SIGTERM');os.killpg(q.pid,signal.SIGTERM)
   try:q.wait(timeout=5)
   except subprocess.TimeoutExpired:signals.append('SIGKILL');os.killpg(q.pid,signal.SIGKILL);q.wait(timeout=5)
  cleanup=time.monotonic();left=rows(q.pid)
  if left:
   signals.append('POST_PARENT_SIGTERM');os.killpg(q.pid,signal.SIGTERM)
   deadline=time.monotonic()+5
   while rows(q.pid) and time.monotonic()<deadline:time.sleep(.05)
   if rows(q.pid):signals.append('POST_PARENT_SIGKILL');os.killpg(q.pid,signal.SIGKILL)
   deadline=time.monotonic()+5
   while rows(q.pid) and time.monotonic()<deadline:time.sleep(.05)
  left=rows(q.pid);stop.set();t.join(timeout=2)
 result={**active,'exit_code':q.returncode,'timeout':timed_out,'signals':signals,'drained':not left,'remaining_processes':left,'cleanup_seconds':time.monotonic()-cleanup,'elapsed_seconds':time.monotonic()-started,'log_sha256':sha(log)}
 save(name+'-processes.json',list(seen.values()));results.append(result);save('results.json',results);print(json.dumps(result),flush=True)
 if q.returncode!=0 or timed_out or signals or left:raise RuntimeError('phase failed: '+name)
 return log

try:
 log=phase('compile',[str(tool/'cargo'),'test','--offline','--locked','-p','kasumi-authority','--all-features','--lib','--no-run','--message-format=json'])
 artifacts=[];diagnostics=[]
 for line in log.read_text().splitlines():
  try:obj=json.loads(line)
  except ValueError:continue
  if obj.get('reason')=='compiler-artifact':artifacts.append(obj)
  elif obj.get('reason')=='compiler-message':diagnostics.append(obj)
 save('artifacts.json',artifacts);save('diagnostics.json',diagnostics)
 selected=[a for a in artifacts if a.get('executable') and a['profile']['test'] and a['target']['name']=='kasumi_authority' and a['target']['kind']==['lib'] and Path(a['manifest_path'])==root/'crates/kasumi-authority/Cargo.toml']
 assert len(selected)==1 and not selected[0]['fresh'],'exact fresh authority library executable required'
 path=Path(selected[0]['executable']);assert path.is_relative_to(target)
 binary={'path':str(path),'selection':selected[0],**record(path)};save('binary-before.json',binary)
 log=phase('inventory',[str(path),'--list','--format','terse'],60)
 names=[line[:-6] for line in log.read_text().splitlines() if line.endswith(': test')]
 assert len(names)==63 and len(set(names))==63 and set(names)==set(json.loads(expected.read_text())) and case in names
 save('test-inventory.json',{'names':names,'count':len(names),'log_sha256':sha(log),'binary_sha256':binary['sha256']})
 assert record(path)=={k:binary[k] for k in ['sha256','bytes']}
 log=phase('focused-original',[str(path),'--exact',case,'--test-threads=1','--nocapture'])
 text=log.read_text();assert 'running 1 test' in text and 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 62 filtered out;' in text
 save('focused-result.json',{'case':case,'passed':1,'failed':0,'ignored':0,'filtered_other_original_names':62,'log_sha256':sha(log),'binary_sha256':binary['sha256']})
except BaseException as error:
 exception={'type':type(error).__name__,'message':str(error)};print(json.dumps({'failure':exception}),flush=True)
finally:
 after=inventory();save('source-after.json',after);changed=[p for p in sorted(set(before)|set(after)) if before.get(p)!=after.get(p)]
 observed={'path':binary['path'],**record(Path(binary['path']))} if binary is not None else None;save('binary-after.json',observed)
 unchanged=binary is not None and all(observed[k]==binary[k] for k in ['sha256','bytes']);branch=subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()
 result={'exception':exception,'source_unchanged':not changed,'changed_inputs':changed,'source_count':len(before),'binary_unchanged':unchanged,'branch':branch,'completed_stages':len(results),'cohort_elapsed_seconds':time.monotonic()-start,'cohort_bound_seconds':1200,'all_passed':exception is None and not changed and unchanged and branch=='master' and len(results)==3 and all(x['exit_code']==0 and not x['timeout'] and not x['signals'] and x['drained'] for x in results),'results_sha256':sha(out/'results.json') if (out/'results.json').exists() else None}
 save('result.json',result);print(json.dumps(result),flush=True);sys.exit(0 if result['all_passed'] else 1)
