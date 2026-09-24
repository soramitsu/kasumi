from pathlib import Path
import subprocess, shutil, hashlib, json, os, time, signal, sys, re
root=Path('/Users/mtakemiya/dev/kasumi'); pkg=Path(__file__).resolve().parent.parent; out=pkg/'native-03'; assembly=out/'assembly'
os.chdir(root)
assert subprocess.check_output(['git','branch','--show-current'],text=True).strip()=='master'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((pkg/'manifest.json').read_text())
assert sha(pkg/'manifest.json')=='785269f80c8030962721109554629a1032bf7193db361b6775fb22bcec2926cf'
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
env={**os.environ,'PATH':str(compiler.parent)+':'+os.environ['PATH'],'CARGO_NET_OFFLINE':'true','CARGO_TARGET_DIR':str(out/'cargo-target'),'CARGO_BUILD_JOBS':'2','TMPDIR':str(root/'target/tmp'),'RUST_BACKTRACE':'1'}
commands=[
 ('compile-store',[str(cargo),'test','--offline','--locked','-p','kasumi-store','--lib','--no-run','--message-format=json']),
 ('store-test-inventory',['STORE_BINARY','--list']),
 ('census',['STORE_BINARY','storage_census::','--test-threads=1','--nocapture']),
 ('opening',['STORE_BINARY','storage_opening::','--test-threads=1','--nocapture']),
 ('store-lease',['STORE_BINARY','disk_memory::','--test-threads=1','--nocapture']),
 ('device-memory',['STORE_BINARY','device_disk::memory_tests::','--test-threads=1','--nocapture']),
 ('scratch-memory',['STORE_BINARY','scratch_disk::memory_tests::','--test-threads=1','--nocapture']),
 ('node-metadata-denial',['STORE_BINARY','node_disk::tests::metadata_denial','--test-threads=1','--nocapture']),
 ('node-partial-admission',['STORE_BINARY','node_disk::tests::partial_metadata_admission','--test-threads=1','--nocapture']),
 ('node-reuse',['STORE_BINARY','node_disk::tests::installed_metadata_reuse','--test-threads=1','--nocapture']),
 ('node-failed-census',['STORE_BINARY','node_disk::tests::census_failure_closes','--test-threads=1','--nocapture']),
 ('compile-engine',[str(cargo),'test','--offline','--locked','-p','kasumi-engine','--lib','--no-run','--message-format=json']),
 ('engine-test-inventory',['ENGINE_BINARY','--list']),
 ('engine-provider',['ENGINE_BINARY','admission::disk_memory::','--test-threads=1','--nocapture'])]
binaries={}
results=[]
def live(pg):
 try:os.killpg(pg,0);return True
 except ProcessLookupError:return False
 except PermissionError:return any(len(x)==2 and int(x[1])==pg for l in subprocess.check_output(['ps','-axo','pid=,pgid='],text=True).splitlines() if (x:=l.split()))
for name,command in commands:
 if command[0] in binaries: command=[binaries[command[0]],*command[1:]]
 start=time.monotonic();timed_out=False;signals=[]
 executable_before={'path':command[0],'sha256':sha(Path(command[0])),'bytes':Path(command[0]).stat().st_size}
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
 executable_after={'path':command[0],'sha256':sha(Path(command[0])),'bytes':Path(command[0]).stat().st_size}
 result={**active,'executable_before':executable_before,'executable_after':executable_after,'executable_unchanged':executable_before==executable_after,'exit_code':code,'timeout':timed_out,'signals':signals,'drained':not live(q.pid),'elapsed_seconds':time.monotonic()-start,'log_sha256':sha(out/(name+'.log'))};results.append(result);(out/'results.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(result),flush=True)
 if code or not result['drained'] or not result['executable_unchanged']:break
 if name in ['store-test-inventory','engine-test-inventory']:
  expected=[]
  sources=[('storage_census::tests::','crates/kasumi-store/src/storage_census_tests.rs'),('storage_opening::tests::','crates/kasumi-store/src/storage_opening_tests.rs')] if name=='store-test-inventory' else [('admission::disk_memory::tests::','crates/kasumi-engine/src/admission/disk_memory.rs')]
  for prefix,relative in sources:
   source=(assembly/relative).read_text()
   expected += [prefix+function for function in re.findall(r'#\[test\]\s*fn\s+(\w+)',source)]
  actual=[line.removesuffix(': test') for line in (out/(name+'.log')).read_text().splitlines() if line.endswith(': test') and any(line.startswith(prefix) for prefix,_ in sources)]
  proof={'expected':sorted(expected),'actual':sorted(actual),'matches':sorted(expected)==sorted(actual)}
  (out/(name+'-proof.json')).write_text(json.dumps(proof,indent=2)+'\n')
  if not proof['matches']:break
 if name.startswith('compile-'):
  artifacts=[];executable=None
  for line in (out/(name+'.log')).read_text(errors='replace').splitlines():
   try: item=json.loads(line)
   except json.JSONDecodeError: continue
   if item.get('reason')!='compiler-artifact': continue
   for filename in item.get('filenames',[]):
    path=Path(filename)
    if path.is_file():artifacts.append({'path':filename,'sha256':sha(path),'bytes':path.stat().st_size})
   if item.get('executable'):executable=item['executable']
  assert executable,name
  target=out/(name.removeprefix('compile-')+'-test-binary')
  shutil.copy2(executable,target)
  binaries['STORE_BINARY' if name=='compile-store' else 'ENGINE_BINARY']=str(target)
  (out/(name+'-artifacts.json')).write_text(json.dumps({'selected_artifacts_after_compile':artifacts,'selected_test_binary':{'built_path':executable,'retained_path':str(target),'sha256':sha(target),'bytes':target.stat().st_size}},indent=2)+'\n')
after=inventory();(out/'source-after.json').write_text(json.dumps(after,indent=2)+'\n')
result={'source_unchanged':before==after,'completed_stages':len(results),'expected_stages':len(commands),'all_passed':len(results)==len(commands) and all(r['exit_code']==0 and r['drained'] for r in results),'results_sha256':sha(out/'results.json')};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
print('\n'.join((out/(results[-1]['name']+'.log')).read_text(errors='replace').splitlines()[-75:]),flush=True)
sys.exit(0 if result['all_passed'] and result['source_unchanged'] else 1)
