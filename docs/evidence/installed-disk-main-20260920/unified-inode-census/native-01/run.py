from pathlib import Path
import os,json,hashlib,subprocess,time
p=Path(__file__).resolve().parent; package=p.parent; root=Path.cwd()
compiler=Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustc')
env=os.environ.copy();env['TMPDIR']=str(root/'target/tmp')
inputs=list((package/'proposed').rglob('*'))+[p/'ledger_tests.rs',p/'metadata_formula.rs',compiler,root/'crates/kasumi-store/src/disk_memory.rs',root/'crates/kasumi-store/src/device_disk.rs']
def inventory():return {str(f.relative_to(root)) if f.is_relative_to(root) else str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in inputs if f.is_file()}
before=inventory();(p/'before.json').write_text(json.dumps(before,indent=2)+'\n')
commands=[('compiler',[str(compiler),'-vV']),('compile-ledger-tests',[str(compiler),'--edition=2024','--test',str(p/'ledger_tests.rs'),'-o',str(p/'ledger-tests')]),('ledger-tests',[str(p/'ledger-tests'),'--test-threads=1']),('compile-formula',[str(compiler),'--edition=2024',str(p/'metadata_formula.rs'),'-o',str(p/'metadata-formula')]),('formula',[str(p/'metadata-formula')])]
results=[]
for name,argv in commands:
 start=time.time()
 with (p/(name+'.stdout')).open('wb') as out,(p/(name+'.stderr')).open('wb') as err:
  proc=subprocess.Popen(argv,cwd=root,env=env,stdout=out,stderr=err,start_new_session=True)
  pid=proc.pid;code=proc.wait()
 try:os.killpg(pid,0);drained=False
 except ProcessLookupError:drained=True
 result={'name':name,'argv':argv,'cwd':str(root),'TMPDIR':env['TMPDIR'],'pid':pid,'pgid':pid,'exit_code':code,'process_group_drained':drained,'elapsed_seconds':time.time()-start}
 results.append(result);(p/'results.json').write_text(json.dumps(results,indent=2)+'\n')
 print(name,code,'drained',drained,flush=True)
 if code or not drained:break
after=inventory();(p/'after.json').write_text(json.dumps(after,indent=2)+'\n');assert before==after
print('inputs unchanged',len(before))
