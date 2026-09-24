from pathlib import Path
import subprocess,json,hashlib,os,time,signal,threading,sys
root=Path('/Users/mtakemiya/dev/kasumi');out=Path(__file__).resolve().parent;pkg=out.parent;native=pkg/'native-01';assembly=pkg/'assembly';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(pkg/'manifest.json')=='64a8b440408c734c05b442aafbb9fa969862d78662178b8029a287dd66578b2e'
assert json.loads((native/'result.json').read_text())['source_unchanged'] # Diagnostic only after failed runtime qualification.
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
baseline=json.loads((native/'source-after.json').read_text());toolchain=Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin')
def inventory():
 paths=set(map(Path,baseline))|{Path(__file__)}|{toolchain/n for n in ['cargo','cargo-fmt','rustfmt']}
 for base in [root,assembly]:
  for directory in ['crates','vendor','tests']:
   actual={p for p in (base/directory).rglob('*') if p.is_file()}
   prior={Path(p) for p in baseline if Path(p).is_relative_to(base/directory)}
   assert actual==prior,(str(base/directory),'source path inventory changed')
 return {str(p):{'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(paths)}
before=inventory();assert all(before[p]==v for p,v in baseline.items());(out/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
command=[str(toolchain/'cargo'),'fmt','--all','--','--check'];env={**os.environ,'PATH':str(toolchain)+':'+os.environ['PATH'],'CARGO_NET_OFFLINE':'true','CARGO_TARGET_DIR':str(native/'cargo-target'),'TMPDIR':str(root/'target/tmp'),'PYTHONDONTWRITEBYTECODE':'1'}
def rows(pg):
 result=[]
 for line in subprocess.check_output(['ps','-axo','pid=,ppid=,pgid=,command='],text=True).splitlines():
  x=line.strip().split(None,3)
  if len(x)==4 and int(x[2])==pg:result.append({'pid':int(x[0]),'ppid':int(x[1]),'pgid':int(x[2]),'command':x[3]})
 return result
seen={};stop=threading.Event();signals=[];timed_out=False;start=time.monotonic()
with (out/'format.log').open('xb') as log:
 q=subprocess.Popen(command,cwd=assembly,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 active={'command':command,'cwd':str(assembly),'pid':q.pid,'pgid':q.pid,'log':str(out/'format.log'),'bound_seconds':120};(out/'active.json').write_text(json.dumps(active,indent=2)+'\n');print(json.dumps(active),flush=True)
 def monitor():
  while not stop.wait(.1):
   for row in rows(q.pid):seen[(row['pid'],row['command'])]=row
 t=threading.Thread(target=monitor,daemon=True);t.start()
 try:code=q.wait(timeout=120)
 except subprocess.TimeoutExpired:
  timed_out=True;os.killpg(q.pid,signal.SIGTERM);signals.append('SIGTERM')
  try:code=q.wait(timeout=10)
  except subprocess.TimeoutExpired:os.killpg(q.pid,signal.SIGKILL);signals.append('SIGKILL');code=q.wait()
 stop.set();t.join()
if rows(q.pid):
 os.killpg(q.pid,signal.SIGTERM);signals.append('SIGTERM-remaining');until=time.monotonic()+10
 while rows(q.pid) and time.monotonic()<until:time.sleep(.1)
 if rows(q.pid):os.killpg(q.pid,signal.SIGKILL);signals.append('SIGKILL-remaining');time.sleep(.2)
remaining=rows(q.pid);after=inventory();(out/'source-after.json').write_text(json.dumps(after,indent=2)+'\n');(out/'processes.json').write_text(json.dumps(list(seen.values()),indent=2)+'\n')
r={**active,'diagnostic_only':True,'final_acceptance':False,'exit_code':code,'timeout':timed_out,'signals':signals,'drained':not remaining,'remaining_processes':remaining,'source_unchanged':before==after,'source_count':len(before),'native_source_after_sha256':sha(native/'source-after.json'),'binary_sha256':sha(native/'store-test-binary'),'source_before_sha256':sha(out/'source-before.json'),'source_after_sha256':sha(out/'source-after.json'),'elapsed_seconds':time.monotonic()-start,'log_sha256':sha(out/'format.log'),'all_passed':code==0 and not timed_out and not signals and not remaining and before==after};(out/'result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r),flush=True);print((out/'format.log').read_text(),flush=True);sys.exit(0 if r['all_passed'] else 1)
