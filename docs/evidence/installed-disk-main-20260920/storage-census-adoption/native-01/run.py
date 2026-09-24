from pathlib import Path
import subprocess, shutil, hashlib, json, os, time, signal, sys
root=Path('/Users/mtakemiya/dev/kasumi'); pkg=Path(__file__).resolve().parent.parent; out=pkg/'native-01'; assembly=out/'assembly'
os.chdir(root)
assert subprocess.check_output(['git','branch','--show-current'],text=True).strip()=='master'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((pkg/'manifest.json').read_text())
assert sha(pkg/'manifest.json')=='ec860ed3dc624fb840100f75fb7681b541ae99004edda7e42ff710883730123b'
for f in manifest['files']:
 assert sha(pkg/'proposed'/f['path'])==f['after'],f['path']
 if f['before']: assert sha(root/f['path'])==f['before'],f['path']
 else: assert not (root/f['path']).exists(),f['path']
assert not assembly.exists(); assembly.mkdir()
for name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']: shutil.copy2(root/name,assembly/name)
for name in ['crates','vendor','tests']: shutil.copytree(root/name,assembly/name)
for f in manifest['files']:
 p=assembly/f['path'];p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(pkg/'proposed'/f['path'],p)
compiler=Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustc');cargo=compiler.with_name('cargo')
def inventory():
 paths=[]
 for base in [root,assembly]:
  paths += [p for d in ['crates','vendor'] for p in (base/d).rglob('*') if p.is_file() and (p.suffix=='.rs' or p.name in ['Cargo.toml','Cargo.lock'])]
  paths += [base/'Cargo.toml',base/'Cargo.lock',base/'rust-toolchain.toml']
 paths += [pkg/'manifest.json',pkg/'adoption.patch',compiler,cargo]
 paths += [p for p in (pkg/'proposed').rglob('*') if p.is_file()]
 return {str(p):{'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(set(paths))}
before=inventory();(out/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
env={**os.environ,'PATH':str(compiler.parent)+':'+os.environ['PATH'],'CARGO_NET_OFFLINE':'true','CARGO_TARGET_DIR':str(root/'target'),'CARGO_BUILD_JOBS':'2','TMPDIR':str(root/'target/tmp'),'RUST_BACKTRACE':'1'}
commands=[
 ('census',[str(cargo),'test','--offline','--locked','-p','kasumi-store','--lib','storage_census::','--','--test-threads=1','--nocapture']),
 ('opening',[str(cargo),'test','--offline','--locked','-p','kasumi-store','--lib','storage_opening::','--','--test-threads=1','--nocapture']),
 ('store-lease',[str(cargo),'test','--offline','--locked','-p','kasumi-store','--lib','disk_memory::','--','--test-threads=1','--nocapture']),
 ('engine-provider',[str(cargo),'test','--offline','--locked','-p','kasumi-engine','--lib','admission::disk_memory::','--','--test-threads=1','--nocapture'])]
results=[]
def live(pg):
 try:os.killpg(pg,0);return True
 except ProcessLookupError:return False
 except PermissionError:return any(len(x)==2 and int(x[1])==pg for l in subprocess.check_output(['ps','-axo','pid=,pgid='],text=True).splitlines() if (x:=l.split()))
for name,command in commands:
 start=time.monotonic();timed_out=False;signals=[]
 with (out/(name+'.log')).open('xb') as log:
  q=subprocess.Popen(command,cwd=assembly,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  active={'name':name,'pid':q.pid,'pgid':q.pid,'command':command,'cwd':str(assembly),'log':str(out/(name+'.log'))};(out/'active.json').write_text(json.dumps(active,indent=2)+'\n');print(json.dumps(active),flush=True)
  try:code=q.wait(timeout=900)
  except subprocess.TimeoutExpired:
   timed_out=True;os.killpg(q.pid,signal.SIGTERM);signals.append('SIGTERM')
   try:code=q.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(q.pid,signal.SIGKILL);signals.append('SIGKILL');code=q.wait()
 if live(q.pid):
  os.killpg(q.pid,signal.SIGTERM);signals.append('SIGTERM-remaining');until=time.monotonic()+10
  while live(q.pid) and time.monotonic()<until:time.sleep(.1)
  if live(q.pid):os.killpg(q.pid,signal.SIGKILL);signals.append('SIGKILL-remaining')
 result={**active,'exit_code':code,'timeout':timed_out,'signals':signals,'drained':not live(q.pid),'elapsed_seconds':time.monotonic()-start,'log_sha256':sha(out/(name+'.log'))};results.append(result);(out/'results.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(result),flush=True)
 if code or not result['drained']:break
after=inventory();(out/'source-after.json').write_text(json.dumps(after,indent=2)+'\n')
result={'source_unchanged':before==after,'completed_stages':len(results),'expected_stages':len(commands),'all_passed':len(results)==len(commands) and all(r['exit_code']==0 and r['drained'] for r in results),'results_sha256':sha(out/'results.json')};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
print('\n'.join((out/(results[-1]['name']+'.log')).read_text(errors='replace').splitlines()[-75:]),flush=True)
sys.exit(0 if result['all_passed'] and result['source_unchanged'] else 1)
