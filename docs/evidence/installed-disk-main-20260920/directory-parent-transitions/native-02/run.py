from pathlib import Path
import os,json,hashlib,subprocess,time,signal
p=Path(__file__).resolve().parent;pkg=p.parent;r=Path.cwd();compiler=Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustc');env={**os.environ,'TMPDIR':str(r/'target/tmp')}
inputs=[f for folder in (pkg/'proposed',p/'deps',p/'node_disk') for f in folder.rglob('*') if f.is_file()]+[p/x for x in ('node_disk.rs','driver.rs','disk_memory.rs','device_disk.rs','selected.json','copied-dependencies.json','run.py')]+[compiler]
def inventory():return {str(f):{'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'bytes':f.stat().st_size} for f in inputs}
before=inventory();(p/'before.json').write_text(json.dumps(before,indent=2)+'\n');selected=json.loads((p/'selected.json').read_text());extern=[]
for name in ('anyhow','serde','uuid','libc','sha2','parking_lot'):extern+=['--extern',name+'='+selected[name]]
commands=[('compiler',[str(compiler),'-vV']),('compile',[str(compiler),'--edition=2024','--crate-name','directory_parent_native','-L','dependency='+str(p/'deps'),*extern,str(p/'driver.rs'),'-o',str(p/'driver')]),('run',[str(p/'driver'),str(p/'state')])];results=[]
for name,argv in commands:
 start=time.monotonic();timed_out=False
 with (p/(name+'.stdout')).open('xb') as out,(p/(name+'.stderr')).open('xb') as err:
  q=subprocess.Popen(argv,cwd=r,env=env,stdout=out,stderr=err,start_new_session=True)
  try:code=q.wait(timeout=120)
  except subprocess.TimeoutExpired:
   timed_out=True;os.killpg(q.pid,signal.SIGTERM)
   try:code=q.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(q.pid,signal.SIGKILL);code=q.wait(timeout=5)
 try:os.killpg(q.pid,0);drained=False
 except ProcessLookupError:drained=True
 result={'argv':argv,'cwd':str(r),'TMPDIR':env['TMPDIR'],'timeout_seconds':120,'name':name,'pid':q.pid,'pgid':q.pid,'exit_code':code,'timed_out':timed_out,'process_group_drained':drained,'elapsed_seconds':time.monotonic()-start,'stdout_sha256':hashlib.sha256((p/(name+'.stdout')).read_bytes()).hexdigest(),'stderr_sha256':hashlib.sha256((p/(name+'.stderr')).read_bytes()).hexdigest()};results.append(result);(p/'results.json').write_text(json.dumps(results,indent=2)+'\n');print(name,code,'drained',drained,flush=True)
 if code or not drained:break
after=inventory();(p/'after.json').write_text(json.dumps(after,indent=2)+'\n');print('inputs unchanged',before==after,len(before));assert before==after
