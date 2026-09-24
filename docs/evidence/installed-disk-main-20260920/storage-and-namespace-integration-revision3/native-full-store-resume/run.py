from pathlib import Path
import subprocess,hashlib,json,os,time,signal,threading,sys
root=Path('/Users/mtakemiya/dev/kasumi');out=Path(__file__).resolve().parent;pkg=out.parent;prior=pkg/'native-full-store';assembly=pkg/'assembly';binary=prior/'store-test-binary';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(pkg/'manifest.json')=='0e0ceb1d2fcaa3293183af8e65f1c333909996b953c7ad415f2fc27b3759d709'
assert sha(out/'inventory-reconciliation.json')=='4367b1dfc4a5215f4fd0f374769f45ca576a117880d2bb686acfa9f9da820292'
assert sha(binary)=='b5a6f147846656057c9949a1378148fa5667a53a97612471a40845f678e88bae'
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
python=Path('/Users/mtakemiya/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3');baseline=json.loads((prior/'source-after.json').read_text());extra=[binary,Path(__file__),out/'inventory-reconciliation.json',out/'census-test-correspondence.patch',prior/'store-binary-provenance.json']
def inventory():
 paths=[Path(x) for x in baseline]+extra
 paths += [p for base in [root,assembly] for name in ['crates','vendor','tests'] for p in (base/name).rglob('*') if p.is_file()]
 return {str(p):{'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(set(paths))}
before=inventory();assert all(before[p]==v for p,v in baseline.items());(out/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
env={**os.environ,'TMPDIR':str(root/'target/tmp'),'PYTHONDONTWRITEBYTECODE':'1','RUST_BACKTRACE':'1'};expected=set(json.loads((out/'inventory-reconciliation.json').read_text())['expected'])
commands=[('store-inventory',[str(binary),'--list']),('store-full',[str(binary),'--test-threads=1','--nocapture']),('python-version',[str(python),'--version']),('smoke-script-tests',[str(python),'scripts/test_small_native_smoke.py','-v'])]
results=[];deadline=time.monotonic()+1200;start_all=time.monotonic()
def group_rows(pg):
 rows=[]
 for l in subprocess.check_output(['ps','-axo','pid=,ppid=,pgid=,command='],text=True).splitlines():
  x=l.strip().split(None,3)
  if len(x)==4 and int(x[2])==pg:rows.append({'pid':int(x[0]),'ppid':int(x[1]),'pgid':int(x[2]),'command':x[3]})
 return rows
for name,command in commands:
 start=time.monotonic();timed_out=False;signals=[];logpath=out/(name+'.log');stop=threading.Event();seen={};exe_before=sha(Path(command[0]))
 with logpath.open('xb') as log:
  q=subprocess.Popen(command,cwd=assembly,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  active={'name':name,'pid':q.pid,'pgid':q.pid,'command':command,'cwd':str(assembly),'log':str(logpath),'cohort_bound_seconds':1200};(out/'active.json').write_text(json.dumps(active,indent=2)+'\n');print(json.dumps(active),flush=True)
  def monitor():
   while not stop.wait(.2):
    for row in group_rows(q.pid):seen[(row['pid'],row['command'])]=row
  t=threading.Thread(target=monitor,daemon=True);t.start()
  try:code=q.wait(timeout=max(.01,deadline-time.monotonic()))
  except subprocess.TimeoutExpired:
   timed_out=True;os.killpg(q.pid,signal.SIGTERM);signals.append('SIGTERM')
   try:code=q.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(q.pid,signal.SIGKILL);signals.append('SIGKILL');code=q.wait()
  stop.set();t.join()
 remaining=group_rows(q.pid)
 if remaining:
  os.killpg(q.pid,signal.SIGTERM);signals.append('SIGTERM-remaining');until=time.monotonic()+10
  while group_rows(q.pid) and time.monotonic()<until:time.sleep(.1)
  if group_rows(q.pid):os.killpg(q.pid,signal.SIGKILL);signals.append('SIGKILL-remaining');time.sleep(.2)
 remaining=group_rows(q.pid);exe_after=sha(Path(command[0]));(out/(name+'-processes.json')).write_text(json.dumps(list(seen.values()),indent=2)+'\n')
 result={**active,'executable_sha256_before':exe_before,'executable_sha256_after':exe_after,'exit_code':code,'timeout':timed_out,'signals':signals,'drained':not remaining,'remaining_processes':remaining,'elapsed_seconds':time.monotonic()-start,'log_sha256':sha(logpath)}
 if name=='store-inventory':
  actual=set(l.removesuffix(': test') for l in logpath.read_text().splitlines() if l.endswith(': test'));result['exact_inventory_passed']=actual==expected;result['missing']=sorted(expected-actual);result['extra']=sorted(actual-expected)
 if name=='python-version':result['expected_version']=logpath.read_text().startswith('Python 3.12.')
 results.append(result);(out/'results.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(result),flush=True)
 if code or remaining or exe_before!=exe_after or result.get('exact_inventory_passed') is False or result.get('expected_version') is False:break
after=inventory();(out/'source-after.json').write_text(json.dumps(after,indent=2)+'\n');result={'source_unchanged':before==after,'changed_inputs':[p for p in sorted(before.keys()|after.keys()) if before.get(p)!=after.get(p)],'source_count':len(before),'completed_stages':len(results),'expected_stages':len(commands),'all_passed':len(results)==len(commands) and all(r['exit_code']==0 and r['drained'] for r in results),'cohort_elapsed_seconds':time.monotonic()-start_all,'results_sha256':sha(out/'results.json')};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
print('\n'.join((out/(results[-1]['name']+'.log')).read_text(errors='replace').splitlines()[-100:]),flush=True)
sys.exit(0 if result['all_passed'] and result['source_unchanged'] else 1)
