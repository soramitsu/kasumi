from pathlib import Path
import subprocess, os, time, json, signal, hashlib
root=Path('/Users/mtakemiya/dev/kasumi'); os.chdir(root)
assert subprocess.check_output(['git','branch','--show-current'],text=True).strip()=='master'
out=root/'target/installed-disk-validation'
binary=root/'target/debug/deps/lifecycle-377b80b89ca111b0'
expected_binary='631110f244e868c72e9966ec5af1df0d484b63bb8c26ffcde3d8c00a730ec098'
def binary_digest():
 digest=hashlib.sha256()
 with binary.open('rb') as stream:
  for block in iter(lambda: stream.read(1 << 20), b''): digest.update(block)
 return digest.hexdigest()
def inventory():
 inputs=sorted(list((root/'crates').rglob('*.rs'))+list((root/'crates').rglob('Cargo.toml'))+list((root/'vendor').rglob('*.rs'))+list((root/'vendor').rglob('Cargo.toml'))+list((root/'vendor').rglob('Cargo.lock'))+[root/'Cargo.toml',root/'Cargo.lock'])
 return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}

before=inventory(); (out/'129-source-before.json').write_text(json.dumps(before,indent=2)+'\n')
command=['/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/cargo', 'test', '--offline', '--locked', '-p', 'kasumi-engine', '--all-features', '--test', 'lifecycle', '--', '--test-threads=1', '--nocapture']
env={**os.environ,'RUST_BACKTRACE':'1','PATH':'/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin:'+os.environ['PATH'],'CARGO_TARGET_DIR':str(root/'target'),'CARGO_BUILD_JOBS':'2','TMPDIR':str(root/'target/tmp')}
def run():
 binary_before=binary_digest(); assert binary_before==expected_binary, 'Lifecycle binary differs from128 static capture'
 started=time.time(); signals=[]; timeout=False
 with (out/'129-lifecycle-handoff.log').open('wb') as log:
  process=subprocess.Popen(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  print(json.dumps({'running_pid':process.pid,'deadline_seconds':1200,'log':str(out/'129-lifecycle-handoff.log')}),flush=True)
  try: rc=process.wait(timeout=1200)
  except subprocess.TimeoutExpired:
   timeout=True; os.killpg(process.pid,signal.SIGTERM); signals.append('SIGTERM')
   try: rc=process.wait(timeout=10)
   except subprocess.TimeoutExpired: os.killpg(process.pid,signal.SIGKILL); signals.append('SIGKILL'); rc=process.wait()
 def live():
  try: os.killpg(process.pid,0); return True
  except ProcessLookupError: return False
  except PermissionError:
   listing=subprocess.check_output(['ps','-axo','pid=,pgid='],text=True)
   return any(len(parts)==2 and int(parts[1])==process.pid for line in listing.splitlines() if (parts:=line.split()))
 if live():
  os.killpg(process.pid,signal.SIGTERM); signals.append('SIGTERM-remaining')
  until=time.monotonic()+10
  while live() and time.monotonic()<until: time.sleep(.1)
  if live(): os.killpg(process.pid,signal.SIGKILL); signals.append('SIGKILL-remaining')
 binary_after=binary_digest()
 after=inventory(); result={'scope':'Full original lifecycle target with bounded vote diagnostic and current-leader exact phase read; unchanged workloads/deadlines, no final acceptance','command':command,'cwd':str(root),'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'process_group':process.pid,'exit_code':rc,'timeout':timeout,'signals':signals,'drained':not live(),'elapsed_seconds':time.time()-started,'inventoried_source_unchanged':before==after,'binary_path':str(binary),'expected_binary_sha256':expected_binary,'binary_sha256_before':binary_before,'binary_sha256_after':binary_after,'binary_unchanged':binary_before==binary_after}
 (out/'129-result.json').write_text(json.dumps(result,indent=2)+'\n'); (out/'129-source-after.json').write_text(json.dumps(after,indent=2)+'\n'); print(json.dumps(result),flush=True)
 lines=(out/'129-lifecycle-handoff.log').read_text(errors='replace').splitlines(); print('\n'.join(lines[-100:]),flush=True)
 raise SystemExit(rc if before==after and binary_before==binary_after else 2)

try:
 run()
except Exception as error:
 recovery={'scope':'runner failure; no passing gate', 'error_type':type(error).__name__, 'error':str(error), 'time':time.time(), 'process_inventory':subprocess.check_output(['ps','-axo','pid,ppid,pgid,uid,state,etime,comm'],text=True)}
 (out/'129-runner-failure.json').write_text(json.dumps(recovery,indent=2)+'\n')
 (out/'129-source-after-recovery.json').write_text(json.dumps(inventory(),indent=2)+'\n')
 raise
