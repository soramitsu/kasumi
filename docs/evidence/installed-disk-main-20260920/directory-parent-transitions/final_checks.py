from pathlib import Path
import subprocess,json,os,hashlib,time,signal
r=Path.cwd();p=r/'target/installed-disk-validation/directory-parent-transitions';env={**os.environ,'TMPDIR':str(r/'target/tmp')};fmt='/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustfmt';files=[f for f in (p/'proposed').rglob('*') if f.is_file()]
def inv():return {str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
before=inv();results=[]
commands=[('format',[fmt,'--check','--edition','2024','--config','skip_children=true',*[str(f) for f in files if f.suffix=='.rs']]),('cumulative-apply-check',['git','apply','--check',str(p/'cumulative.patch')]),('successor-apply-check',['git','apply','--check','--directory=target/installed-disk-validation/directory-parent-transitions/base',str(p/'parent-transitions.patch')])]
for name,argv in commands:
 with (p/(name+'.stdout')).open('xb') as out,(p/(name+'.stderr')).open('xb') as err:
  q=subprocess.Popen(argv,cwd=r,env=env,stdout=out,stderr=err,start_new_session=True)
  try:code=q.wait(timeout=60)
  except subprocess.TimeoutExpired:os.killpg(q.pid,signal.SIGKILL);code=q.wait(timeout=5)
 try:os.killpg(q.pid,0);drained=False
 except ProcessLookupError:drained=True
 results.append({'name':name,'argv':argv,'cwd':str(r),'TMPDIR':env['TMPDIR'],'pid':q.pid,'pgid':q.pid,'exit_code':code,'process_group_drained':drained});print(name,code,drained)
after=inv();assert before==after
(p/'final-checks.json').write_text(json.dumps({'checks':results,'proposed_before':before,'proposed_after':after,'unchanged':before==after},indent=2)+'\n')
