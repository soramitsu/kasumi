from pathlib import Path
import json,hashlib,subprocess,shutil,time,os,signal
r=Path.cwd();p=r/'target/installed-disk-validation/directory-cursor';manifest=json.loads((p/'manifest.json').read_text());inputs=[p/'manifest.json',p/'cursor.patch',p/'cumulative.patch']+[f for folder in ('base','proposed','cumulative-base','cumulative-proposed') for f in (p/folder).rglob('*') if f.is_file()]
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def inventory():return {str(f):sha(f) for f in inputs}
before=inventory();results=[]
for name,baseline,patch in [('successor','base','cursor.patch'),('cumulative','cumulative-base','cumulative.patch')]:shutil.copytree(p/baseline,p/('apply-check-'+name))
formatter=Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustfmt')
commands=[('format',[str(formatter),'--check','--edition','2024','--config','skip_children=true',*[str(f) for f in sorted((p/'proposed').rglob('*.rs'))]])]+[(name+'-apply-check',['git','apply','--check','--directory='+str((p/('apply-check-'+name)).relative_to(r)),str(p/patch)]) for name,patch in [('successor','cursor.patch'),('cumulative','cumulative.patch')]]
for name,argv in commands:
 started=time.monotonic()
 with (p/(name+'.stdout')).open('xb') as out,(p/(name+'.stderr')).open('xb') as err:
  q=subprocess.Popen(argv,cwd=r,env={**os.environ,'TMPDIR':str(r/'target/tmp')},stdout=out,stderr=err,start_new_session=True)
  try:code=q.wait(timeout=30)
  except subprocess.TimeoutExpired:
   os.killpg(q.pid,signal.SIGKILL);code=q.wait(timeout=5)
 try:os.killpg(q.pid,0);drained=False
 except ProcessLookupError:drained=True
 results.append({'name':name,'argv':argv,'pid':q.pid,'pgid':q.pid,'exit_code':code,'drained':drained,'elapsed_seconds':time.monotonic()-started,'stdout_sha256':sha(p/(name+'.stdout')),'stderr_sha256':sha(p/(name+'.stderr'))})
after=inventory();actual_match=all((sha(r/rel) if (r/rel).exists() else None)==v['current_actual_sha256'] for rel,v in manifest['files'].items())
record={'checks':results,'inputs_before':before,'inputs_after':after,'all_frozen_inputs_unchanged':before==after,'current_source_unchanged_since_manifest':actual_match,'formatter_sha256':sha(formatter)};(p/'final-checks.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({'checks':[{k:v[k] for k in ('name','exit_code','drained')} for v in results],'frozen_inputs_unchanged':before==after,'actual_source_unchanged':actual_match},indent=2));assert before==after and actual_match and all(v['exit_code']==0 and v['drained'] for v in results)
