from pathlib import Path
import subprocess, os, time, json, signal, hashlib
root=Path('/Users/mtakemiya/dev/kasumi'); os.chdir(root)
assert subprocess.check_output(['git','branch','--show-current'],text=True).strip()=='master'
out=root/'target/installed-disk-validation'
def inventory():
 inputs=sorted(list((root/'crates').rglob('*.rs'))+list((root/'crates').rglob('Cargo.toml'))+list((root/'vendor').rglob('*.rs'))+list((root/'vendor').rglob('Cargo.toml'))+list((root/'vendor').rglob('Cargo.lock'))+[root/'Cargo.toml',root/'Cargo.lock'])
 return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}

before=inventory(); (out/'151-source-before.json').write_text(json.dumps(before,indent=2)+'\n')
command=['/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/cargo', 'test', '--offline', '--locked', '--manifest-path', 'vendor/redb-4.2.0/Cargo.toml', '--lib', '--', '--test-threads=1', '--nocapture']
env={**os.environ,'RUST_BACKTRACE':'1','PATH':'/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin:'+os.environ['PATH'],'CARGO_TARGET_DIR':str(root/'target'),'CARGO_BUILD_JOBS':'2','TMPDIR':str(root/'target/tmp')}
def run():
 started=time.time(); signals=[]; timeout=False
 with (out/'151-vendor-in-place-allocator-encoding.log').open('wb') as log:
  process=subprocess.Popen(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  print(json.dumps({'running_pid':process.pid,'deadline_seconds':1200,'log':str(out/'151-vendor-in-place-allocator-encoding.log')}),flush=True)
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
 after=inventory(); result={'scope':'Complete vendor redb library after checked one-buffer allocator encoding; no final acceptance','command':command,'cwd':str(root),'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'process_group':process.pid,'exit_code':rc,'timeout':timeout,'signals':signals,'drained':not live(),'elapsed_seconds':time.time()-started,'inventoried_source_unchanged':before==after}
 (out/'151-result.json').write_text(json.dumps(result,indent=2)+'\n'); (out/'151-source-after.json').write_text(json.dumps(after,indent=2)+'\n'); print(json.dumps(result),flush=True)
 lines=(out/'151-vendor-in-place-allocator-encoding.log').read_text(errors='replace').splitlines(); print('\n'.join(lines[-100:]),flush=True)
 raise SystemExit(rc)

try:
 run()
except Exception as error:
 recovery={'scope':'runner failure; no passing gate', 'error_type':type(error).__name__, 'error':str(error), 'time':time.time(), 'process_inventory':subprocess.check_output(['ps','-axo','pid,ppid,pgid,uid,state,etime,comm'],text=True)}
 (out/'151-runner-failure.json').write_text(json.dumps(recovery,indent=2)+'\n')
 (out/'151-source-after-recovery.json').write_text(json.dumps(inventory(),indent=2)+'\n')
 raise
