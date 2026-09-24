from pathlib import Path
import subprocess,hashlib,json,os,time,signal,sys,re,shutil,threading
root=Path('/Users/mtakemiya/dev/kasumi');pkg=Path(__file__).resolve().parent.parent;expected_manifest='93ce8996fc13e0c84d77ddf22f9b71875124286c7de12367c216eea3c0026d24';out=pkg/'native-01';assembly=pkg/'assembly';target=out/'cargo-target'
assert pkg.is_relative_to(root/'target');assert not target.exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def dispatch_budget_remaining(deadline, now):
 return max(0.0, deadline-now)
def qualified_stage(result):
 return (result['exit_code']==0 and result['drained'] and not result['timeout'] and not result['signals']
         and result['executable_before']==result['executable_after']
         and result.get('inventory_passed',True) and result.get('expected_python_3_12',True))
assert sha(pkg/'manifest.json')==expected_manifest
m=json.loads((pkg/'manifest.json').read_text())
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
for f in m['files']:
 assert sha(assembly/f['path'])==f['after']
 assert sha(pkg/'proposed'/f['path'])==f['after']
 assert (sha(root/f['path']) if (root/f['path']).exists() else None)==f['before']
toolchain=Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin')
# This target must start absent and is used only by this exact frozen candidate.
env={**os.environ,'PATH':str(toolchain)+':'+os.environ['PATH'],'CARGO_NET_OFFLINE':'true','CARGO_TARGET_DIR':str(target),'CARGO_BUILD_JOBS':'2','TMPDIR':str(root/'target/tmp'),'RUST_BACKTRACE':'1','PYTHONDONTWRITEBYTECODE':'1'}
def inventory():
 paths=[]
 for base in [root,assembly]:
  paths += [p for d in ['crates','vendor','tests'] for p in (base/d).rglob('*') if p.is_file()]
  paths += [base/n for n in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']]
 paths += [root/f['path'] for f in m['files'] if f['before']]
 paths += [assembly/f['path'] for f in m['files']]
 paths += [p for p in (pkg/'proposed').rglob('*') if p.is_file()]
 paths += [pkg/n for n in ['manifest.json','combined.patch','composition.json','expected-store-tests.json','revision6-to-combined.patch','custody-to-combined-overlaps.patch']]+[Path(__file__)]
 for item in m['inputs']:
  input_path=Path(item['path']);paths.append(input_path);paths += [f for f in (input_path.parent/'proposed').rglob('*') if f.is_file()]
 paths += [toolchain/n for n in ['cargo','rustc','cargo-clippy','clippy-driver']]
 paths += [root/'target/installed-disk-validation/storage-and-namespace-integration-revision6/native-full-store/store-inventory-proof.json',root/'target/installed-disk-validation/file-owner-custody-revision1/candidate-04/native-01/list.stdout']
 return {str(p):{'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(set(paths))}
before=inventory();(out/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
expected_record=json.loads((pkg/'expected-store-tests.json').read_text());expected=set(expected_record['expected']);assert len(expected)==331
commands=[('workspace-check',[str(toolchain/'cargo'),'check','--offline','--locked','--workspace','--all-targets','--all-features','--message-format=json']),('workspace-clippy',[str(toolchain/'cargo'),'clippy','--offline','--locked','--workspace','--all-targets','--all-features','--message-format=json','--','-D','warnings']),('compile-store',[str(toolchain/'cargo'),'test','--offline','--locked','-p','kasumi-store','--all-features','--lib','--no-run','--message-format=json']),('store-inventory',['STORE_BINARY','--list']),('store-full',['STORE_BINARY','--test-threads=1','--nocapture'])]
results=[];binary=None;dispatch_denied=None;cohort_start=time.monotonic();deadline=cohort_start+1200

def group_rows(pg):
 rows=[]
 for l in subprocess.check_output(['ps','-axo','pid=,ppid=,pgid=,command='],text=True).splitlines():
  x=l.strip().split(None,3)
  if len(x)==4 and int(x[2])==pg:rows.append({'pid':int(x[0]),'ppid':int(x[1]),'pgid':int(x[2]),'command':x[3]})
 return rows
for name,command in commands:
 if command[0]=='STORE_BINARY':command=[str(binary),*command[1:]]
 start=time.monotonic();timed_out=False;signals=[];cleanup_started=None;logpath=out/(name+'.log');stop=threading.Event();seen={}
 executable_before={'path':command[0],'sha256':sha(Path(command[0])),'bytes':Path(command[0]).stat().st_size}
 with logpath.open('xb') as log:
  if not dispatch_budget_remaining(deadline,time.monotonic()):
   dispatch_denied={'name':name,'command':command,'reason':'1200-second cohort budget exhausted before dispatch','elapsed_seconds':time.monotonic()-cohort_start}
   (out/'dispatch-denied.json').write_text(json.dumps(dispatch_denied,indent=2)+'\n');print(json.dumps(dispatch_denied),flush=True);break
  q=subprocess.Popen(command,cwd=assembly,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  active={'name':name,'pid':q.pid,'pgid':q.pid,'command':command,'cwd':str(assembly),'log':str(logpath),'remaining_bound_seconds':deadline-time.monotonic()};(out/'active.json').write_text(json.dumps(active,indent=2)+'\n');print(json.dumps(active),flush=True)
  def monitor():
   while not stop.wait(.2):
    for row in group_rows(q.pid):seen[(row['pid'],row['command'])]=row
  t=threading.Thread(target=monitor,daemon=True);t.start()
  try:code=q.wait(timeout=dispatch_budget_remaining(deadline,time.monotonic()))
  except subprocess.TimeoutExpired:
   timed_out=True;cleanup_started=time.monotonic();os.killpg(q.pid,signal.SIGTERM);signals.append('SIGTERM')
   try:code=q.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(q.pid,signal.SIGKILL);signals.append('SIGKILL');code=q.wait()
  stop.set();t.join()
 remaining=group_rows(q.pid)
 if remaining:
  if cleanup_started is None:cleanup_started=time.monotonic()
  os.killpg(q.pid,signal.SIGTERM);signals.append('SIGTERM-remaining');until=time.monotonic()+10
  while group_rows(q.pid) and time.monotonic()<until:time.sleep(.1)
  if group_rows(q.pid):os.killpg(q.pid,signal.SIGKILL);signals.append('SIGKILL-remaining');time.sleep(.2)
 remaining=group_rows(q.pid)
 (out/(name+'-processes.json')).write_text(json.dumps(list(seen.values()),indent=2)+'\n')
 executable_after={'path':command[0],'sha256':sha(Path(command[0])),'bytes':Path(command[0]).stat().st_size}
 result={**active,'executable_before':executable_before,'executable_after':executable_after,'exit_code':code,'timeout':timed_out,'signals':signals,'cleanup_grace_seconds':0.0 if cleanup_started is None else time.monotonic()-cleanup_started,'drained':not remaining,'remaining_processes':remaining,'elapsed_seconds':time.monotonic()-start,'log_sha256':sha(logpath)}
 if name in ['workspace-check','workspace-clippy','compile-store']:
  artifacts=[];chosen=[];diagnostics=[]
  for line in logpath.read_text(errors='replace').splitlines():
   try:item=json.loads(line)
   except json.JSONDecodeError:continue
   if item.get('reason')=='compiler-message':diagnostics.append(item)
   if item.get('reason')!='compiler-artifact':continue
   files=[{'path':n,'sha256':sha(Path(n)),'bytes':Path(n).stat().st_size} for n in item.get('filenames',[]) if Path(n).is_file()]
   artifacts.append({'package_id':item.get('package_id'),'target':item.get('target'),'fresh':item.get('fresh'),'files':files})
   if item.get('executable') and item['target']['name']=='kasumi_store' and item['profile']['test']:chosen.append(item)
  (out/(name+'-artifacts.json')).write_text(json.dumps(artifacts,indent=2)+'\n')
  (out/(name+'-diagnostics.json')).write_text(json.dumps(diagnostics,indent=2)+'\n')
  (out/(name+'-diagnostics.txt')).write_text(''.join(x['message'].get('rendered','') for x in diagnostics))
  if name=='compile-store' and code==0:
   assert len(chosen)==1; selected=chosen[0];assert Path(selected['target']['src_path'])==assembly/'crates/kasumi-store/src/lib.rs';assert not selected['fresh']
   binary=out/'store-test-binary';shutil.copy2(selected['executable'],binary)
   (out/'store-binary-provenance.json').write_text(json.dumps({'selected':selected,'retained_path':str(binary),'sha256':sha(binary),'bytes':binary.stat().st_size},indent=2)+'\n')
 if name=='store-inventory':
  actual=set(line.removesuffix(': test') for line in logpath.read_text().splitlines() if line.endswith(': test'));missing=sorted(expected-actual);extra=sorted(actual-expected);inventory_passed=not missing and not extra and len(actual)==331
  proof={'required_count':len(expected),'actual_count':len(actual),'missing':missing,'extra':extra,'exact_expected_inventory_present':inventory_passed,'actual':sorted(actual)};(out/'store-inventory-proof.json').write_text(json.dumps(proof,indent=2)+'\n');result['inventory_passed']=inventory_passed
 results.append(result);(out/'results.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(result),flush=True)
 if not qualified_stage(result):break
after=inventory();(out/'source-after.json').write_text(json.dumps(after,indent=2)+'\n');diffs=[p for p in sorted(before.keys()|after.keys()) if before.get(p)!=after.get(p)]
result={'source_unchanged':before==after,'changed_inputs':diffs,'source_count':len(before),'dispatch_denied':dispatch_denied,'completed_stages':len(results),'expected_stages':len(commands),'all_passed':before==after and dispatch_denied is None and len(results)==len(commands) and all(qualified_stage(r) for r in results) and time.monotonic()<=deadline,'cohort_elapsed_seconds':time.monotonic()-cohort_start,'cohort_bound_seconds':1200,'results_sha256':sha(out/'results.json') if results else None};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
if results:print('\n'.join(line[:1000] for line in (out/(results[-1]['name']+'.log')).read_text(errors='replace').splitlines()[-35:]),flush=True)
sys.exit(0 if result['all_passed'] and result['source_unchanged'] else 1)
