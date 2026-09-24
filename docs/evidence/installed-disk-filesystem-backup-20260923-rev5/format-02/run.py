from pathlib import Path
import ast,hashlib,json,os,stat,subprocess,time,signal
root=Path('/Users/mtakemiya/dev/kasumi');pkg=root/'target/installed-disk-validation/filesystem-backup-admission-revision5';out=pkg/'native-02';format_out=pkg/'format-02';assembly=out/'assembly'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
preflight=json.loads((out/'preflight.json').read_text());toolchain=Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin')
node=next(n for n in ast.parse((out/'run.py').read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='inventory')
exec(compile(ast.Module(body=[node],type_ignores=[]),str(out/'run.py'),'exec'))
def inventory_with_format():
 result=inventory()
 for p in [Path(__file__),out/'run.py',toolchain/'rustfmt',toolchain/'cargo-fmt']:
  result[str(p)]={'sha256':sha(p),'bytes':p.stat().st_size,'mode':oct(stat.S_IMODE(p.stat().st_mode))}
 return result
before=inventory_with_format();(format_out/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
original=json.loads((out/'source-after.json').read_text());assert all(before[k]==v for k,v in original.items())
def group(pg):
 rows=[]
 for line in subprocess.check_output(['ps','-axo','pid=,ppid=,pgid=,command='],text=True).splitlines():
  x=line.split(None,3)
  if len(x)==4 and int(x[2])==pg:rows.append({'pid':int(x[0]),'ppid':int(x[1]),'pgid':int(x[2]),'command':x[3]})
 return rows
binary=out/'store-test-binary';binary_before=sha(binary);assert binary_before==json.loads((out/'store-binary-provenance.json').read_text())['sha256']
command=[str(toolchain/'cargo'),'fmt','--all','--','--check'];env={**os.environ,'PATH':str(toolchain)+':'+os.environ['PATH'],'CARGO_NET_OFFLINE':'true','CARGO_TARGET_DIR':str(format_out/'cargo-target'),'TMPDIR':str(root/'target/tmp')}
start=time.monotonic();timed_out=False;signals=[]
with (format_out/'format.log').open('xb') as log:
 child=subprocess.Popen(command,cwd=assembly,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 active={'pid':child.pid,'pgid':child.pid,'command':command,'cwd':str(assembly),'bound_seconds':120};(format_out/'active.json').write_text(json.dumps(active,indent=2)+'\n');print(json.dumps(active),flush=True)
 try:code=child.wait(timeout=120)
 except subprocess.TimeoutExpired:
  timed_out=True;os.killpg(child.pid,signal.SIGTERM);signals.append('SIGTERM')
  try:code=child.wait(timeout=3)
  except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);signals.append('SIGKILL');code=child.wait(timeout=3)
remaining=group(child.pid)
for _ in range(20):
 if not remaining:break
 time.sleep(.05);remaining=group(child.pid)
after=inventory_with_format();(format_out/'source-after.json').write_text(json.dumps(after,indent=2)+'\n')
result={**active,'exit_code':code,'timed_out':timed_out,'signals':signals,'remaining_processes':remaining,'drained':not remaining,'source_count':len(before),'source_unchanged':before==after,'binary_unchanged':binary_before==sha(binary),'elapsed_seconds':time.monotonic()-start,'log_sha256':sha(format_out/'format.log')}
result['passed']=code==0 and not timed_out and not signals and not remaining and before==after and result['binary_unchanged'] and result['elapsed_seconds']<=120
(format_out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
raise SystemExit(0 if result['passed'] else 1)
