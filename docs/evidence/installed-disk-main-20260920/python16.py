from pathlib import Path
import subprocess, os, time, json, signal, hashlib
root=Path('/Users/mtakemiya/dev/kasumi'); os.chdir(root)
assert subprocess.check_output(['git','branch','--show-current'],text=True).strip()=='master'
out=root/'target/installed-disk-validation'
def inventory():
 inputs=sorted(list((root/'scripts').rglob('*.py'))+[root/'vendor/patch-manifest.json'])
 return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}

before=inventory(); (out/'16-source-before.json').write_text(json.dumps(before,indent=2)+'\n')
command=['/Users/mtakemiya/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3','-m','unittest','discover','-s','scripts','-p','test_*.py','-v']
env={**os.environ,'PATH':'/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin:'+os.environ['PATH'],'CARGO_TARGET_DIR':str(root/'target'),'CARGO_BUILD_JOBS':'2','TMPDIR':str(root/'target/tmp')}
started=time.time(); signals=[]; timeout=False
with (out/'16-python-tests.log').open('wb') as log:
 process=subprocess.Popen(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 print(json.dumps({'running_pid':process.pid,'deadline_seconds':300,'log':str(out/'16-python-tests.log')}),flush=True)
 try: rc=process.wait(timeout=300)
 except subprocess.TimeoutExpired:
  timeout=True; os.killpg(process.pid,signal.SIGTERM); signals.append('SIGTERM')
  try: rc=process.wait(timeout=10)
  except subprocess.TimeoutExpired: os.killpg(process.pid,signal.SIGKILL); signals.append('SIGKILL'); rc=process.wait()
def live():
 try: os.killpg(process.pid,0); return True
 except ProcessLookupError: return False
if live():
 os.killpg(process.pid,signal.SIGTERM); signals.append('SIGTERM-remaining')
 until=time.monotonic()+10
 while live() and time.monotonic()<until: time.sleep(.1)
 if live(): os.killpg(process.pid,signal.SIGKILL); signals.append('SIGKILL-remaining')
after=inventory(); result={'scope':'development release-tooling regression diagnostic, not final release qualification','command':command,'cwd':str(root),'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'process_group':process.pid,'exit_code':rc,'timeout':timeout,'signals':signals,'drained':not live(),'elapsed_seconds':time.time()-started,'inventoried_source_unchanged':before==after}
(out/'16-result.json').write_text(json.dumps(result,indent=2)+'\n'); (out/'16-source-after.json').write_text(json.dumps(after,indent=2)+'\n'); print(json.dumps(result),flush=True)
lines=(out/'16-python-tests.log').read_text(errors='replace').splitlines(); print('\n'.join(lines[-100:]),flush=True)
raise SystemExit(rc)
