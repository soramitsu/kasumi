import hashlib,json,os,pathlib,re,signal,subprocess,time
root=pathlib.Path('/tmp/kasumi-production-drain-validation')
out=pathlib.Path('/tmp/kasumi-combined-075e24d-types-gates')
def sh(*args):return subprocess.check_output(args,cwd=root,text=True).strip()
def sha(p):return hashlib.file_digest(open(p,'rb'),'sha256').hexdigest()
def source():return {'head':sh('git','rev-parse','HEAD'),'tree':sh('git','rev-parse','HEAD^{tree}'),'status':sh('git','status','--porcelain=v1'),'lock_sha256':sha(root/'Cargo.lock')}
before=source();assert before['head']=='075e24dc95c39be8e2c63baf63aa22aae78539ea' and not before['status']
out.mkdir(exist_ok=False)
cargo=sh('rustup','which','--toolchain','1.97.1','cargo');rustc=sh('rustup','which','--toolchain','1.97.1','rustc');rustdoc=sh('rustup','which','--toolchain','1.97.1','rustdoc')
env=os.environ.copy();env.update(RUSTUP_TOOLCHAIN='1.97.1',RUSTC=rustc,RUSTDOC=rustdoc,CARGO_TARGET_DIR='/tmp/kasumi-production-root-target',CARGO_BUILD_JOBS='1',RUST_TEST_THREADS='1');env['PATH']=str(pathlib.Path(cargo).parent)+':'+env['PATH']
record={'scope':'Combined first-release types and canonical payload tests with corrected workspace JSON dependency. Kasumi-types only; no engine/store/server/Raft or native listener/provider. Not production acceptance or capacity evidence.','source_before':before,'tools':{str(p):sha(p) for p in [cargo,rustc,rustdoc]},'runner_sha256':sha(__file__),'per_gate_timeout_seconds':300,'gates':[]}
(out/'evidence.json').write_text(json.dumps(record,indent=2))
commands=[('canonical-types',[cargo,'test','--locked','--offline','-j1','-p','kasumi-types','--test','canonical_json','--message-format=json-render-diagnostics','--','--test-threads=1'],['literal_json_has_one_explicit_byte_contract', 'mutation_replay_and_staging_manifest_are_feature_independent', 'archive_plaintext_and_document_references_share_the_same_encoding', 'schema_activation_identity_preserves_typed_field_order', 'typed_maps_and_enclosing_field_order_are_explicit', 'bounded_writer_failure_does_not_require_an_encoded_payload_copy']),('types-lib',[cargo,'test','--locked','--offline','-j1','-p','kasumi-types','--lib','--message-format=json-render-diagnostics','--','--test-threads=1'],None),('types-strict',[cargo,'clippy','--locked','--offline','-j1','-p','kasumi-types','--all-targets','--all-features','--message-format=json-render-diagnostics','--','-D','warnings'],None)]

def group_alive(pgid):
 try:os.killpg(pgid,0);return True
 except ProcessLookupError:return False

def drain_group(process):
 actions=[]
 for sig in (signal.SIGTERM,signal.SIGKILL):
  if not group_alive(process.pid):break
  try:os.killpg(process.pid,sig);actions.append(sig.name)
  except ProcessLookupError:break
  deadline=time.monotonic()+10
  while time.monotonic()<deadline:
   process.poll()
   if not group_alive(process.pid):break
   time.sleep(.05)
 process.poll()
 return {'signals':actions,'process_returncode':process.returncode,'process_group_drained':not group_alive(process.pid)}

for name,cmd,expected in commands:
 log=out/(name+'.log');start=time.monotonic();print('Running',name,flush=True)
 problem=None;cleanup=None;process=None
 with log.open('wb') as f:
  try:
   process=subprocess.Popen(cmd,cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
   code=process.wait(timeout=300)
   if group_alive(process.pid):
    problem='owned process group remained after command exit';code=1
    cleanup=drain_group(process)
   else:cleanup={'signals':[],'process_returncode':process.returncode,'process_group_drained':True}
  except BaseException as error:
   problem=type(error).__name__+': '+str(error)
   code=124 if isinstance(error,subprocess.TimeoutExpired) else 130 if isinstance(error,KeyboardInterrupt) else 1
   if process is not None:cleanup=drain_group(process)
  finally:
   f.flush();os.fsync(f.fileno())
 content=log.read_text(errors='replace');artifacts=[]
 for line in content.splitlines():
  try:item=json.loads(line)
  except ValueError:continue
  p=item.get('executable')
  if item.get('reason')=='compiler-artifact' and p and pathlib.Path(p).is_file():artifacts.append({'path':p,'sha256':sha(p),'profile':item.get('profile'),'features':item.get('features')})
 expected_ran=(expected is None or all(('test '+name+' ... ok') in content for name in expected)) and ('test' not in cmd[1:2] or re.search(r'test result: ok\. [1-9][0-9]* passed',content) is not None)
 code=code if code else (0 if expected_ran else 1)
 record['source_after']=source()
 if record['source_after']!=before:problem=(problem+'; ' if problem else '')+'source changed during gate';code=1
 if cleanup is not None and not cleanup['process_group_drained']:code=1
 record['gates'].append({'name':name,'command':cmd,'seconds':time.monotonic()-start,'process_group_id':process.pid if process else None,'process_exit_code':process.returncode if process else None,'exit_code':code,'problem':problem,'cleanup':cleanup,'required_test':expected,'required_test_passed':expected_ran,'log_sha256':sha(log),'artifacts':artifacts})
 (out/'evidence.json').write_text(json.dumps(record,indent=2));print(name,code,flush=True)
 if code:raise SystemExit(code)
