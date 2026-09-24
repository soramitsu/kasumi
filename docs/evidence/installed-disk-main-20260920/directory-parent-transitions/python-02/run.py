from pathlib import Path
import os,json,hashlib,subprocess,time,signal
p=Path(__file__).resolve().parent;pkg=p.parent;r=Path.cwd();exe=Path('/Users/mtakemiya/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3');env={**os.environ,'TMPDIR':str(r/'target/tmp'),'PYTHONDONTWRITEBYTECODE':'1'};files=[f for f in (pkg/'proposed').rglob('*') if f.is_file()]+[p/'driver.py',p/'run.py',exe]
def inventory():return {str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
before=inventory();(p/'before.json').write_text(json.dumps(before,indent=2)+'\n');start=time.monotonic();argv=[str(exe),str(p/'driver.py')]
with (p/'stdout').open('xb') as out,(p/'stderr').open('xb') as err:
 q=subprocess.Popen(argv,cwd=r,env=env,stdout=out,stderr=err,start_new_session=True)
 try:code=q.wait(timeout=60)
 except subprocess.TimeoutExpired:os.killpg(q.pid,signal.SIGKILL);code=q.wait(timeout=5)
try:os.killpg(q.pid,0);drained=False
except ProcessLookupError:drained=True
(p/'result.json').write_text(json.dumps({'argv':argv,'cwd':str(r),'TMPDIR':env['TMPDIR'],'pid':q.pid,'pgid':q.pid,'exit_code':code,'process_group_drained':drained,'elapsed_seconds':time.monotonic()-start},indent=2)+'\n');after=inventory();(p/'after.json').write_text(json.dumps(after,indent=2)+'\n');assert before==after;print('Python',code,'drained',drained,'proposal inputs unchanged',len(before));print((p/'stdout').read_text());print((p/'stderr').read_text()[-1000:])
