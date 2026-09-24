from pathlib import Path
import subprocess,hashlib,json,os,time,signal,sys,threading
root=Path('/Users/mtakemiya/dev/kasumi');pkg=Path(__file__).resolve().parent.parent;out=pkg/'native-01';assembly=pkg/'assembly';target=out/'cargo-target'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert not target.exists()
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
assert sha(pkg/'manifest.json')=='0e0ceb1d2fcaa3293183af8e65f1c333909996b953c7ad415f2fc27b3759d709'
m=json.loads((pkg/'manifest.json').read_text())
for f in m['files']:
 assert sha(pkg/'proposed'/f['path'])==f['after']
 assert sha(assembly/f['path'])==f['after']
 assert (sha(root/f['path']) if (root/f['path']).exists() else None)==f['before']
toolchain=Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin')
tools=[toolchain/name for name in ['cargo','rustc','cargo-clippy','clippy-driver','rustfmt']]
def inventory():
 paths=[]
 for base in [root,assembly]:
  paths += [p for d in ['crates','vendor','tests'] for p in (base/d).rglob('*') if p.is_file()]
  paths += [base/n for n in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']]
 paths += [root/f['path'] for f in m['files'] if f['before']]
 paths += [p for p in (pkg/'proposed').rglob('*') if p.is_file()]
 paths += [pkg/n for n in ['manifest.json','combined.patch','composition.json','namespace-to-combined-overlaps.patch','census-to-combined-overlaps.patch']]
 for i in m['inputs']:
  inp=Path(i['path']);paths.append(inp); paths += [p for p in (inp.parent/'proposed').rglob('*') if p.is_file()]
 paths += tools+[Path(__file__)]
 return {str(p):{'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(set(paths))}
before=inventory();(out/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
env={**os.environ,'PATH':str(toolchain)+':'+os.environ['PATH'],'CARGO_NET_OFFLINE':'true','CARGO_TARGET_DIR':str(target),'CARGO_BUILD_JOBS':'2','TMPDIR':str(root/'target/tmp'),'RUST_BACKTRACE':'1'}
commands=[('workspace-check',[str(toolchain/'cargo'),'check','--offline','--locked','--workspace','--all-targets','--all-features','--message-format=json']),('workspace-clippy',[str(toolchain/'cargo'),'clippy','--offline','--locked','--workspace','--all-targets','--all-features','--message-format=json','--','-D','warnings'])]
commands.reverse()
results=[];cohort_start=time.monotonic();deadline=cohort_start+1200

def group_rows(pg):
 rows=[]
 for l in subprocess.check_output(['ps','-axo','pid=,ppid=,pgid=,command='],text=True).splitlines():
  x=l.strip().split(None,3)
  if len(x)==4 and int(x[2])==pg:rows.append({'pid':int(x[0]),'ppid':int(x[1]),'pgid':int(x[2]),'command':x[3]})
 return rows
for name,command in commands:
 start=time.monotonic();timed_out=False;signals=[];logpath=out/(name+'.log');stop=threading.Event();seen={}
 with logpath.open('xb') as log:
  q=subprocess.Popen(command,cwd=assembly,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  active={'name':name,'pid':q.pid,'pgid':q.pid,'command':command,'cwd':str(assembly),'log':str(logpath),'cargo_target_dir':str(target),'cohort_bound_seconds':1200,'remaining_bound_seconds':deadline-time.monotonic()};(out/'active.json').write_text(json.dumps(active,indent=2)+'\n');print(json.dumps(active),flush=True)
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
 remaining=group_rows(q.pid)
 (out/(name+'-processes.json')).write_text(json.dumps(list(seen.values()),indent=2)+'\n')
 artifacts=[];diagnostics=[]
 for line in logpath.read_text(errors='replace').splitlines():
  try:item=json.loads(line)
  except json.JSONDecodeError:continue
  if item.get('reason')=='compiler-message':diagnostics.append(item)
  if item.get('reason')!='compiler-artifact':continue
  files=[]
  for filename in item.get('filenames',[]):
   f=Path(filename)
   if f.is_file():files.append({'path':filename,'sha256':sha(f),'bytes':f.stat().st_size})
  artifacts.append({'package_id':item.get('package_id'),'target':item.get('target'),'profile':item.get('profile'),'fresh':item.get('fresh'),'files':files})
 (out/(name+'-artifacts.json')).write_text(json.dumps(artifacts,indent=2)+'\n')
 (out/(name+'-diagnostics.json')).write_text(json.dumps(diagnostics,indent=2)+'\n')
 (out/(name+'-diagnostics.txt')).write_text(''.join(i['message'].get('rendered','') for i in diagnostics))
 result={**active,'exit_code':code,'timeout':timed_out,'signals':signals,'drained':not remaining,'remaining_processes':remaining,'elapsed_seconds':time.monotonic()-start,'log_sha256':sha(logpath),'artifact_count':len(artifacts),'diagnostic_count':len(diagnostics)};results.append(result);(out/'results.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(result),flush=True)
 if code or remaining:break
after=inventory();(out/'source-after.json').write_text(json.dumps(after,indent=2)+'\n')
diffs=[p for p in sorted(before.keys()|after.keys()) if before.get(p)!=after.get(p)]
result={'source_unchanged':before==after,'changed_inputs':diffs,'source_count':len(before),'completed_stages':len(results),'expected_stages':len(commands),'all_passed':len(results)==len(commands) and all(r['exit_code']==0 and r['drained'] for r in results),'cohort_elapsed_seconds':time.monotonic()-cohort_start,'cohort_bound_seconds':1200,'results_sha256':sha(out/'results.json'),'native_runtime_tests':False,'artifact_scope':'Exact check/Clippy compiler artifacts and tool binaries; no runnable test execution.'};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
print((out/(results[-1]['name']+'-diagnostics.txt')).read_text()[-18000:],flush=True)
sys.exit(0 if result['all_passed'] and result['source_unchanged'] else 1)
