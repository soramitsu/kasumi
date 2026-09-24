from pathlib import Path
import os,json,hashlib,subprocess,time,signal,sys
p=Path(__file__).resolve().parent;pkg=p.parent;r=Path.cwd();compiler=Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustc');env={**os.environ,'TMPDIR':str(r/'target/tmp')};selection=json.loads((p/'selection.json').read_text());deps=Path(selection['dependency_directory'])
inputs=[f for folder in (pkg/'proposed',p/'proposal-at-run',p/'node_disk',deps) for f in folder.rglob('*') if f.is_file()]+[f for f in p.iterdir() if f.suffix in ('.py','.rs','.json')]+[compiler]
inputs += [f for f in (compiler.parent.parent/'lib').rglob('*') if f.is_file() and f.suffix in ('.rlib','.rmeta','.dylib','.so','.a')]
def inventory():return {str(f):{'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'bytes':f.stat().st_size} for f in inputs}
before=inventory();(p/'before.json').write_text(json.dumps(before,indent=2)+'\n');extern=[]
for name in ('anyhow','serde','uuid','libc','sha2','parking_lot','zeroize','tempfile'):extern+=['--extern',name+'='+selection['extern'][name]]
common=[str(compiler),'--edition=2024','--crate-name','directory_cursor_native','-L','dependency='+str(deps),*extern,str(p/'driver.rs')]
commands=[('compiler',[str(compiler),'-vV']),('compile-production',common+['-o',str(p/'production')]),('compile-tests',common+['--test','-o',str(p/'tests')]),('run',[str(p/'tests'),'node_disk::directory::cursor::tests::','--nocapture','--test-threads=1'])];results=[]
for name,argv in commands:
 start=time.monotonic();timed_out=False
 with (p/(name+'.stdout')).open('xb') as out,(p/(name+'.stderr')).open('xb') as err:
  q=subprocess.Popen(argv,cwd=r,env=env,stdout=out,stderr=err,start_new_session=True)
  active={'name':name,'pid':q.pid,'pgid':q.pid,'argv':argv};(p/'active.json').write_text(json.dumps(active,indent=2)+'\n');print('START',name,'pid/pgid',q.pid,flush=True)
  try:code=q.wait(timeout=120)
  except subprocess.TimeoutExpired:
   timed_out=True;os.killpg(q.pid,signal.SIGTERM)
   try:code=q.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(q.pid,signal.SIGKILL);code=q.wait(timeout=5)
 try:os.killpg(q.pid,0);drained=False
 except ProcessLookupError:drained=True
 result={'argv':argv,'cwd':str(r),'TMPDIR':env['TMPDIR'],'timeout_seconds':120,'name':name,'pid':q.pid,'pgid':q.pid,'exit_code':code,'timed_out':timed_out,'process_group_drained':drained,'elapsed_seconds':time.monotonic()-start,'stdout_sha256':hashlib.sha256((p/(name+'.stdout')).read_bytes()).hexdigest(),'stderr_sha256':hashlib.sha256((p/(name+'.stderr')).read_bytes()).hexdigest()};results.append(result);(p/'results.json').write_text(json.dumps(results,indent=2)+'\n');print(name,code,'drained',drained,flush=True)
 if code or not drained:break
after=inventory();(p/'after.json').write_text(json.dumps(after,indent=2)+'\n');print('inputs unchanged',before==after,len(before),flush=True);assert before==after
sys.exit(0 if all(x['exit_code']==0 and x['process_group_drained'] for x in results) and len(results)==len(commands) else 1)
