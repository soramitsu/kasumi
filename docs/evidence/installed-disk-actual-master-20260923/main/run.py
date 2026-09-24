from pathlib import Path
import datetime,hashlib,json,os,re,signal,subprocess,sys,threading,time
root=Path('/Users/mtakemiya/dev/kasumi');out=Path(__file__).resolve().parent;tool=Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin');target=out/'cargo-target';tmp=root/'target/tmp';expected=root/'target/installed-disk-validation/filesystem-backup-admission-revision5/expected-store-tests.json'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def record(p):return {'sha256':sha(p),'bytes':p.stat().st_size}
def save(name,obj):
 with (out/name).open('w') as f:json.dump(obj,f,indent=2);f.write('\n')
def inventory():
 paths={Path(__file__),out/'preflight.json',expected,root/'Cargo.toml',root/'Cargo.lock'}
 for d in ['crates','vendor','tests','scripts','.cargo']:
  if (root/d).exists():paths.update(p for p in (root/d).rglob('*') if p.is_file())
 paths.update(root.glob('rust-toolchain*'))
 paths.update(tool/n for n in ['cargo','rustc','cargo-clippy','clippy-driver','cargo-fmt','rustfmt','rustdoc'])
 return {str(p):record(p) for p in sorted(paths)}
def rows(pg):
 result=[]
 for line in subprocess.check_output(['ps','-axo','pid=,ppid=,pgid=,command='],text=True).splitlines():
  parts=line.strip().split(None,3)
  if len(parts)==4 and int(parts[2])==pg:result.append({'pid':int(parts[0]),'ppid':int(parts[1]),'pgid':int(parts[2]),'command':parts[3]})
 return result
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
assert not target.exists();assert not (out/'source-before.json').exists();target.mkdir();tmp.mkdir(exist_ok=True)
start=time.monotonic();before=inventory();save('source-before.json',before);save('launcher.json',{'pid':os.getpid(),'pgid':os.getpgrp(),'command':sys.argv,'started_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
env={**os.environ,'PATH':str(tool)+':'+os.environ['PATH'],'CARGO_TARGET_DIR':str(target),'CARGO_NET_OFFLINE':'true','CARGO_BUILD_JOBS':'2','RUST_BACKTRACE':'1','RUST_TEST_THREADS':'1','TMPDIR':str(tmp),'PYTHONDONTWRITEBYTECODE':'1'}
results=[];binaries=[];exception=None

def phase(name,command,bound=1200):
 remaining=3600-(time.monotonic()-start)
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

def artifacts(log):
 artifacts=[];diagnostics=[]
 for line in log.read_text().splitlines():
  try:obj=json.loads(line)
  except ValueError:continue
  if obj.get('reason')=='compiler-artifact':artifacts.append(obj)
  elif obj.get('reason')=='compiler-message':diagnostics.append(obj)
 save(log.stem+'-artifacts.json',artifacts);save(log.stem+'-diagnostics.json',diagnostics)
 return artifacts
try:
 phase('workspace-format',[str(tool/'cargo'),'fmt','--all','--','--check'],120)
 phase('vendor-format',[str(tool/'cargo'),'fmt','--manifest-path','vendor/redb-4.2.0/Cargo.toml','--all','--','--check'],120)
 base=[str(tool/'cargo')]
 log=phase('workspace-check',base+['check','--offline','--locked','--workspace','--all-targets','--all-features','--message-format=json']);artifacts(log)
 log=phase('workspace-clippy',base+['clippy','--offline','--locked','--workspace','--all-targets','--all-features','--message-format=json','--','-D','warnings']);artifacts(log)
 log=phase('workspace-tests-compile',base+['test','--offline','--locked','--workspace','--all-features','--no-run','--message-format=json'])
 selected=[a for a in artifacts(log) if a.get('executable') and a['profile']['test'] and Path(a['manifest_path']).is_relative_to(root/'crates')]
 assert selected and len({a['executable'] for a in selected})==len(selected)
 assert all(not a['fresh'] for a in selected),'unexpected reused test executable in fresh candidate target'
 for a in selected:
  p=Path(a['executable']);binaries.append({'selection':a,'path':str(p),**record(p)})
 save('test-binaries-before.json',binaries)
 expected_names=set(json.loads(expected.read_text())['expected']);assert len(expected_names)==345
 inventories=[];store_checked=False
 for i,b in enumerate(binaries):
  p=Path(b['path']);assert record(p)=={k:b[k] for k in ['sha256','bytes']}
  log=phase('inventory-'+str(i+1).zfill(2),[str(p),'--list','--format','terse'],60)
  names=[line[:-6] for line in log.read_text().splitlines() if line.endswith(': test')]
  assert len(names)==len(set(names));kind=b['selection']['target']['kind'];name=b['selection']['target']['name']
  if name=='kasumi_store' and kind==['lib']:
   assert set(names)==expected_names,('store inventory mismatch',set(names)^expected_names);store_checked=True
  inventories.append({'binary':str(p),'sha256':b['sha256'],'target':name,'kind':kind,'count':len(names),'names':names,'inventory_log':str(log),'inventory_sha256':sha(log)})
 assert store_checked;save('test-inventories.json',inventories)
 for b in binaries:assert record(Path(b['path']))=={k:b[k] for k in ['sha256','bytes']}
 log=phase('workspace-tests-full',base+['test','--offline','--locked','--workspace','--all-features','--message-format=json','--','--test-threads=1']);artifacts(log)
 text=log.read_text();missing=[b['path'] for b in binaries if Path(b['path']).name not in text];assert not missing,('missing cargo runtime dispatch log',missing)
 save('test-summaries.json',{'summaries':re.findall(r'test result: (?:ok|FAILED)\..*',text),'all_selected_binaries_in_runtime_log':True,'total_discovered_tests':sum(x['count'] for x in inventories),'runtime_binary_targets':len(binaries)})
except BaseException as error:
 exception={'type':type(error).__name__,'message':str(error)};print(json.dumps({'failure':exception}),flush=True)
finally:
 after=inventory();save('source-after.json',after)
 changed=[p for p in sorted(set(before)|set(after)) if before.get(p)!=after.get(p)]
 observed=[{'path':b['path'],**record(Path(b['path']))} for b in binaries if Path(b['path']).exists()];save('test-binaries-after.json',observed)
 binary_unchanged=all(record(Path(b['path']))=={k:b[k] for k in ['sha256','bytes']} for b in binaries)
 result={'exception':exception,'source_unchanged':not changed,'changed_inputs':changed,'source_count':len(before),'binary_unchanged':binary_unchanged,'completed_stages':len(results),'cohort_elapsed_seconds':time.monotonic()-start,'cohort_bound_seconds':3600,'per_phase_bound_seconds':1200,'all_passed':exception is None and not changed and binary_unchanged and all(r['exit_code']==0 and not r['timeout'] and not r['signals'] and r['drained'] for r in results),'results_sha256':sha(out/'results.json')}
 save('result.json',result);print(json.dumps(result),flush=True)
 sys.exit(0 if result['all_passed'] else 1)
